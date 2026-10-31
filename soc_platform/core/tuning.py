"""Tuning: leads adapt the platform to the situation with rules tested on past data and approved by a second lead.

A lead describes the change in words ("stop raising incidents for the scanner on scan-* hosts"). The request becomes
a **draft rule from a fixed menu**, and the platform shows what the rule would have done over the last 90 days. A
second lead approves it before it applies. The model only translates words into the menu's fields, and its draft is
checked:

* a detection must be one the platform has actually seen;
* a host or user pattern must be written in the request;
* a number must be written in the request, or the default is used.

The lead edits the draft, sees the preview and proposes it. The model never decides what is filtered.

The menu:

* ``suppress_detection`` closes new incidents made only of one detection as noise. It can be narrowed to a tool, a
  host pattern or a user pattern, and covers severities up to a cap (low by default, medium at most).
* ``noise_threshold`` sets when a detection counts as noise from analysts' decisions. The default is 80% benign
  over at least 3 decisions in 30 days, and each value is kept within bounds.
* ``raise_severity`` raises new and re-assessed incidents involving chosen hosts or users by one or two levels
  ("finance servers matter more until quarter close"). The verdict is still judged on the unraised severity.
* ``exercise`` labels incidents involving chosen hosts or users as an exercise for up to 30 days (a red-team or
  penetration test). They are investigated as usual, never suppressed, and analysts' decisions on them stay out of
  the noise statistics.
* ``phishing_autoclose`` sets the confidence at which clearly safe or spam reports close automatically, and the
  share sampled for QA. A report somebody clicked, or one a mail gateway rated worse, is never auto-closed.
* ``vuln_priority`` sets the vulnerability priority weights (CVSS, EPSS, KEV, internet exposure, asset criticality;
  they add up to 100) and the SLA days per band. A KEV-listed finding on an internet-facing asset stays P1, and every
  KEV-listed finding keeps the P1 SLA, whatever the weights.
* ``action_demote`` marks an action analysts keep rejecting in a context (an action type in a domain, optionally for
  one detection or some hosts / users) as "usually rejected here": it is still recommended and shown, labelled, and
  can never run autonomously there. Critical and deception cases are never affected.

Guardrails, in code, whatever a rule says:

* A rule never suppresses a high or critical alert, a deception alert, an exercise incident, or an alert on a host
  with a KEV-listed vulnerability.
* 1 in 10 incidents a rule would suppress stays open as a QA sample and is investigated in full (stable hash).
* An analyst who rules a suppressed or sampled case malicious or suspicious pauses the rule at once.
* Every rule expires (at most a year). A lead can revoke a rule at any time, with immediate effect.
* Proposer and approver must be different people, both with ``tune_detections`` in the rule's domain (leads, a
  person, never an API key). Every step is audited.
"""

from __future__ import annotations

import fnmatch
import hashlib
import re
from collections import Counter
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import JSON, Integer, String, select
from sqlalchemy.orm import Mapped, Session, mapped_column

from soc_platform.core.audit import AuditLog
from soc_platform.core.auth import Perm, Principal
from soc_platform.core.db import Base, BoundedText, UTCDateTime
from soc_platform.core.models import Case, CaseEntity, Disposition, Entity, utcnow
from soc_platform.core.schema import severity_rank

KINDS = ("suppress_detection", "noise_threshold", "raise_severity", "exercise", "phishing_autoclose", "vuln_priority",
         "action_demote")
KIND_LABELS = {"suppress_detection": "Suppress a detection", "noise_threshold": "Noise threshold",
               "raise_severity": "Raise attention", "exercise": "Exercise", "phishing_autoclose": "Phishing auto-close",
               "vuln_priority": "Vulnerability priority", "action_demote": "Usually rejected action"}
DOMAINS = ("incident", "phishing", "vulnerability")
# the domain a rule belongs to (whose leads may tune it); an action rule names its own
KIND_DOMAIN = {"suppress_detection": "incident", "noise_threshold": "incident", "raise_severity": "incident",
               "exercise": "incident", "phishing_autoclose": "phishing", "vuln_priority": "vulnerability",
               "action_demote": None}
SINGLETONS = ("noise_threshold", "phishing_autoclose", "vuln_priority")   # one in force: a newer one supersedes it
SUPPRESSIBLE = ("informational", "low", "medium")           # high and critical are never suppressed
DEFAULT_THRESHOLD = {"benign_percent": 80, "min_decisions": 3, "days": 30}
THRESHOLD_BOUNDS = {"benign_percent": (60, 100), "min_decisions": (2, 50), "days": (7, 180)}
EXPIRES_DEFAULT, EXPIRES_MAX = 90, 365
EXERCISE_DEFAULT, EXERCISE_MAX = 7, 30
DEFAULT_AUTOCLOSE = {"min_confidence_percent": 70, "sample_percent": 10}
AUTOCLOSE_BOUNDS = {"min_confidence_percent": (50, 95), "sample_percent": (5, 50)}
VULN_WEIGHTS = ("weight_cvss", "weight_epss", "weight_kev", "weight_exposure", "weight_criticality")
VULN_SLAS = ("sla_p1", "sla_p2", "sla_p3", "sla_p4")
DEFAULT_VULN = {"weight_cvss": 30, "weight_epss": 25, "weight_kev": 20, "weight_exposure": 10, "weight_criticality": 15,
                "sla_p1": 7, "sla_p2": 15, "sla_p3": 30, "sla_p4": 90}
VULN_BOUNDS = {**{k: (0, 60) for k in VULN_WEIGHTS},
               "sla_p1": (1, 30), "sla_p2": (1, 60), "sla_p3": (1, 180), "sla_p4": (1, 365)}
DEMOTE_MIN_DECISIONS, DEMOTE_REJECT_SHARE = 5, 0.8
QA_RATE = 0.1
PREVIEW_DAYS = 90
ALERT_KINDS = {"alert", "deception"}
_PATTERN = re.compile(r"[\w.\-*?@ ]{1,200}")
DRAFT_SYSTEM = (
    "You turn a SOC lead's request into ONE draft tuning rule from a fixed menu. Never invent values: copy host and "
    "user patterns and numbers only from the request, choose a detection only from the list given, and leave a field "
    "null when the request does not say it. Kinds: suppress_detection (close new incidents made only of one "
    "detection as noise; optional tool, host pattern, user pattern with * wildcards, max_severity informational|low|"
    "medium, expires_days); noise_threshold (when analysts' decisions make a detection noise: benign_percent, "
    "min_decisions, days, expires_days); raise_severity (incidents involving a host or user pattern count 1 or 2 "
    "levels higher: host, user, optional detection, levels, expires_days); exercise (a red-team or penetration test "
    "on a host or user pattern: host, user, optional detection, expires_days up to 30); phishing_autoclose (auto-close "
    "confidence and QA sample for reported e-mails: min_confidence_percent, sample_percent, expires_days); "
    "vuln_priority (vulnerability priority weights in percent adding up to 100 - weight_cvss, weight_epss, weight_kev, "
    "weight_exposure, weight_criticality - and SLA days per band: sla_p1, sla_p2, sla_p3, sla_p4); action_demote (an "
    "action analysts keep rejecting: action_type from the list given, domain incident|phishing|vulnerability, optional "
    "detection, host, user). Return JSON only.")


class TuningRule(Base):
    """One proposed tuning rule and its life: proposed -> active (second lead) | rejected; active -> revoked |
    paused (an analyst found a threat in what it suppressed) | superseded (a newer threshold); expiry is by date."""

    __tablename__ = "tuning_rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    kind: Mapped[str] = mapped_column(String(32))
    params: Mapped[dict[str, Any]] = mapped_column(JSON)
    status: Mapped[str] = mapped_column(String(16), default="proposed", index=True)
    reason: Mapped[str] = mapped_column(BoundedText(1000), default="")
    request_text: Mapped[str] = mapped_column(BoundedText(2000), default="")
    drafted_by: Mapped[str] = mapped_column(String(16), default="form")
    preview: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    proposed_by: Mapped[str] = mapped_column(String(256))
    decided_by: Mapped[str | None] = mapped_column(String(256), nullable=True)
    decided_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    decision_note: Mapped[str] = mapped_column(BoundedText(1000), default="")
    expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)


# ---------------------------------------------------------------------------------------------- validation


def incident_alert(title: str | None, attrs: dict[str, Any] | None) -> bool:
    """Alerts the incident workflow clusters: a user's phishing report belongs to the phishing workflow (the same
    test as ``incident.service._handled_by_phishing``)."""
    return not ((attrs or {}).get("tool") == "defender_office365" and "reported by user" in (title or "").lower())


def known_detections(session: Session) -> dict[str, int]:
    """Every incident alert title the platform has seen, with how often (the only detections a rule may name)."""
    counts: Counter[str] = Counter(t for (t, a) in session.execute(
        select(Entity.display_name, Entity.attributes).where(Entity.kind.in_(ALERT_KINDS))).all()
        if t and incident_alert(t, a))
    return dict(sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])))


def known_action_types(session: Session) -> list[str]:
    """Action types the platform has recommended (the only ones an action rule may name)."""
    from soc_platform.core.models import ActionRequest

    return sorted({a for (a,) in session.execute(select(ActionRequest.action_type).distinct()).all() if a})


def rule_domain(kind: str, params: Any = None) -> str:
    """The domain whose leads may tune this rule; an action rule names its own (unknown -> all-domain only)."""
    d = KIND_DOMAIN.get(kind) or ((params or {}).get("domain") if isinstance(params, dict) else None)
    return d if d in DOMAINS else "*"


def known_tools(session: Session) -> list[str]:
    return sorted({(a or {}).get("tool") for (a,) in session.execute(
        select(Entity.attributes).where(Entity.kind.in_(ALERT_KINDS))).all() if (a or {}).get("tool")})


def _whole(v: Any) -> int | None:
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return v
    if isinstance(v, str) and v.strip().isdigit():
        return int(v.strip())
    return None


def clean_params(session: Session, kind: str, params: Any) -> dict[str, Any]:
    """The rule's settings, checked: raises ValueError naming every problem."""
    if kind not in KINDS:
        raise ValueError(f"unknown rule kind '{kind}' ({', '.join(KINDS)})")
    problems: list[str] = [] if isinstance(params, dict) else ["the rule's settings must be an object"]
    if problems:
        raise ValueError(problems[0])
    out: dict[str, Any] = {}
    ex = kind == "exercise"
    exp_max = EXERCISE_MAX if ex else EXPIRES_MAX
    exp = _whole(params.get("expires_days") or (EXERCISE_DEFAULT if ex else EXPIRES_DEFAULT))
    if exp is None or not 1 <= exp <= exp_max:
        problems.append(f"expires_days must be a whole number of days from 1 to {exp_max}")
    out["expires_days"] = exp
    allowed = {"suppress_detection": {"detection", "tool", "host", "user", "max_severity"},
               "noise_threshold": set(THRESHOLD_BOUNDS), "raise_severity": {"detection", "tool", "host", "user", "levels"},
               "exercise": {"detection", "tool", "host", "user"}, "phishing_autoclose": set(AUTOCLOSE_BOUNDS),
               "vuln_priority": set(VULN_BOUNDS), "action_demote": {"domain", "action_type", "detection", "tool", "host", "user"}}[kind]
    allowed = allowed | {"expires_days"}
    problems += [f"unknown setting '{k}' ({', '.join(sorted(allowed))})" for k in params if k not in allowed]
    if kind == "action_demote":
        dom = params.get("domain")
        if dom not in DOMAINS:
            problems.append(f"domain must be one of {', '.join(DOMAINS)}")
        out["domain"] = dom
        act = str(params.get("action_type") or "").strip()
        if act not in known_action_types(session):
            problems.append("name an action the platform has recommended (for example endpoint.isolate)")
        out["action_type"] = act
        if params.get("detection") and dom != "incident":
            problems.append("a detection narrows incident actions only")
    if kind in ("suppress_detection", "raise_severity", "exercise", "action_demote"):
        det = str(params.get("detection") or "").strip()
        by_fold = {t.casefold(): t for t in known_detections(session)}
        if not det and kind == "suppress_detection":
            problems.append("name the detection (alert title) to suppress")
        elif det and det.casefold() not in by_fold:
            problems.append(f"no alert titled '{det[:120]}' has been seen - choose one from the list")
        out["detection"] = by_fold.get(det.casefold(), det) or None
        tool = str(params.get("tool") or "").strip() or None
        if tool and tool not in known_tools(session):
            problems.append(f"no alert from tool '{tool[:60]}' has been seen")
        out["tool"] = tool
        for k in ("host", "user"):
            v = str(params.get(k) or "").strip() or None
            if v and (not _PATTERN.fullmatch(v) or v.strip("*? ") == ""):
                problems.append(f"{k} must be a name or a pattern with * or ? (letters, digits, . - _ @), not only wildcards")
            out[k] = v
        if kind in ("raise_severity", "exercise") and not (out["host"] or out["user"]):
            problems.append("name the hosts or users it covers (a name or a pattern such as fin-*)")
    if kind == "suppress_detection":
        sev = params.get("max_severity") or "low"
        if sev not in SUPPRESSIBLE:
            problems.append(f"max_severity must be one of {', '.join(SUPPRESSIBLE)} - high and critical are never suppressed")
        out["max_severity"] = sev
    elif kind == "raise_severity":
        lv = _whole(params.get("levels") or 1)
        if lv not in (1, 2):
            problems.append("levels must be 1 or 2")
        out["levels"] = lv
    for bounds, defaults in ((THRESHOLD_BOUNDS, DEFAULT_THRESHOLD), (AUTOCLOSE_BOUNDS, DEFAULT_AUTOCLOSE),
                             (VULN_BOUNDS, DEFAULT_VULN)):
        if not set(bounds) <= allowed:
            continue
        for k, (lo, hi) in bounds.items():
            v = _whole(params.get(k, defaults[k]))
            if v is None or not lo <= v <= hi:
                problems.append(f"{k} must be a whole number from {lo} to {hi}")
            out[k] = v
    if kind == "vuln_priority" and not problems:
        total = sum(out[k] for k in VULN_WEIGHTS)
        if total != 100:
            problems.append(f"the five weights must add up to 100 (they add up to {total})")
        slas = [out[k] for k in VULN_SLAS]
        if slas != sorted(slas):
            problems.append("SLA days must not shrink from P1 to P4 (a lower priority never gets less time)")
    if kind == "action_demote":
        out.pop("tool", None)
    if problems:
        raise ValueError("; ".join(problems))
    return out


def describe(kind: str, p: dict[str, Any]) -> str:
    """The rule in one plain sentence (the console, the audit log, case summaries)."""
    if kind == "noise_threshold":
        return (f"A detection is noise when at least {p['benign_percent']}% of at least {p['min_decisions']} analyst "
                f"decisions in {p['days']} days were benign")
    if kind == "phishing_autoclose":
        return (f"Auto-close clearly safe or spam reports at {p['min_confidence_percent']}% confidence or more, "
                f"sampling {p['sample_percent']}% for QA")
    if kind == "vuln_priority":
        return (f"Vulnerability priority: CVSS {p['weight_cvss']}%, EPSS {p['weight_epss']}%, KEV {p['weight_kev']}%, "
                f"internet exposure {p['weight_exposure']}%, asset criticality {p['weight_criticality']}%; SLA "
                f"P1 {p['sla_p1']} / P2 {p['sla_p2']} / P3 {p['sla_p3']} / P4 {p['sla_p4']} days")
    where = " ".join(w for w in (f"'{p['detection']}'" if p.get("detection") else "", f"from {p['tool']}" if p.get("tool") else "",
                                 f"on hosts {p['host']}" if p.get("host") else "",
                                 f"for users {p['user']}" if p.get("user") else "") if w)
    if kind == "raise_severity":
        return f"Raise incidents {where} by {p['levels']} severity level{'s' if p['levels'] > 1 else ''}"
    if kind == "exercise":
        return f"Label incidents {where} as an exercise"
    if kind == "action_demote":
        return f"Treat {p['action_type']} on {p['domain']} cases{' ' + where if where else ''} as usually rejected"
    return f"Suppress {where} up to {p['max_severity']} severity"


# ---------------------------------------------------------------------------------------------- matching


def alert_facts(session: Session, store: Any, alerts: list[Entity]) -> dict[str, dict[str, Any]]:
    """What a rule is matched on, per alert: title, tool, severity, the hosts and users it involves."""
    out: dict[str, dict[str, Any]] = {}
    for a in alerts:
        attrs = a.attributes or {}
        hosts, users, host_ids = set(), set(), set()
        for _rel, ent in store.neighbors(a.id, kinds={"asset", "identity"}):
            ea = ent.attributes or {}
            names = {ent.display_name, ea.get("hostname"), ea.get("fqdn"), ea.get("upn"), ea.get("email")}
            names = {str(n) for n in names if n}
            if ent.kind == "asset":
                hosts |= names | {n.split(".")[0] for n in names}
                host_ids.add(ent.id)
            else:
                users |= names
        out[a.id] = {"title": a.display_name or "", "tool": attrs.get("tool"), "sev": severity_rank(attrs.get("severity")),
                     "severity": attrs.get("severity") or "low", "deception": a.kind == "deception",
                     "hosts": sorted(hosts), "users": sorted(users), "host_ids": sorted(host_ids),
                     "at": a.first_seen}
    return out


def _glob(pattern: str, names: list[str]) -> bool:
    p = pattern.casefold()
    return any(fnmatch.fnmatchcase(n.casefold(), p) for n in names)


def matches(p: dict[str, Any], f: dict[str, Any]) -> bool:
    """Does a rule's scope (detection, tool, host and user patterns - each optional except where required) cover this
    alert? For suppression the guardrails are checked after."""
    if p.get("detection") and f["title"].casefold() != str(p["detection"]).casefold():
        return False
    if p.get("tool") and f["tool"] != p["tool"]:
        return False
    if p.get("host") and not _glob(p["host"], f["hosts"]):
        return False
    return not (p.get("user") and not _glob(p["user"], f["users"]))


def kev_host_ids(store: Any, host_ids: set[str], kev_cves: set[str]) -> set[str]:
    """Hosts carrying a KEV-listed vulnerability (a guardrail: their alerts are never suppressed)."""
    out = set()
    for hid in sorted(host_ids):
        for f in store.events_for(hid, kinds={"finding"}):
            fa = f.attributes or {}
            if fa.get("kev") or (fa.get("cve") and fa["cve"] in kev_cves):
                out.add(hid)
                break
    return out


def guard(f: dict[str, Any], cap: str, kev_hosts: set[str]) -> str | None:
    """Why a guardrail keeps this alert even though a rule covers it (None = it may be suppressed)."""
    if f["deception"]:
        return "deception alert"
    if f["sev"] > SUPPRESSIBLE.index(cap) or f["sev"] > 2:
        return f"{f['severity']} severity is above the rule's cap ({cap})"
    if set(f["host_ids"]) & kev_hosts:
        return "host carries a KEV-listed vulnerability"
    return None


def qa_sampled(alert_ids: list[str]) -> bool:
    """1 in 10 suppressions stays open for review - a stable hash, so a re-run makes the same choice."""
    key = "|".join(sorted(alert_ids))
    return int(hashlib.sha256(key.encode()).hexdigest(), 16) % 1000 < int(QA_RATE * 1000)


# ---------------------------------------------------------------------------------------------- the store


class TuningStore:
    def __init__(self, session: Session) -> None:
        self.s = session
        self.audit = AuditLog(session)

    # -- reading

    def rules(self, *, limit: int = 200) -> list[TuningRule]:
        return list(self.s.execute(select(TuningRule).order_by(TuningRule.id.desc()).limit(limit)).scalars())

    def active(self, kind: str) -> list[TuningRule]:
        now = _naive(utcnow())
        rows = self.s.execute(select(TuningRule).where(TuningRule.kind == kind, TuningRule.status == "active")
                              .order_by(TuningRule.id)).scalars()
        return [r for r in rows if r.expires_at is None or _naive(r.expires_at) > now]

    def active_suppressions(self) -> list[TuningRule]:
        return self.active("suppress_detection")

    def threshold(self) -> dict[str, int]:
        rows = self.active("noise_threshold")
        return {k: rows[-1].params[k] for k in DEFAULT_THRESHOLD} if rows else dict(DEFAULT_THRESHOLD)

    def vuln_priority(self) -> dict[str, int]:
        rows = self.active("vuln_priority")
        return {k: rows[-1].params[k] for k in DEFAULT_VULN} if rows else dict(DEFAULT_VULN)

    def autoclose(self) -> dict[str, int]:
        rows = self.active("phishing_autoclose")
        return {k: rows[-1].params[k] for k in DEFAULT_AUTOCLOSE} if rows else dict(DEFAULT_AUTOCLOSE)

    def status_of(self, r: TuningRule) -> str:
        if r.status == "active" and r.expires_at is not None and _naive(r.expires_at) <= _naive(utcnow()):
            return "expired"
        return r.status

    def as_dict(self, r: TuningRule) -> dict[str, Any]:
        hits: Counter[str] = Counter()
        mark = {"suppress_detection": "tuning_rule", "raise_severity": "tuning_raise", "exercise": "exercise"}.get(r.kind)
        if mark and r.status not in ("proposed", "rejected"):
            for (attrs,) in self.s.execute(select(Case.attributes).where(Case.domain == "incident")).all():
                if (attrs or {}).get(mark) == r.id:
                    hits["qa_sample" if mark == "tuning_rule" and attrs.get("tuning_qa") else "applied"] += 1
        if r.kind == "action_demote" and r.status not in ("proposed", "rejected"):
            from soc_platform.core.models import ActionRequest

            hits["applied"] = sum(1 for (res,) in self.s.execute(
                select(ActionRequest.result).where(ActionRequest.action_type == r.params.get("action_type"))).all()
                if ((res or {}).get("tuning_demoted") or {}).get("rule") == r.id)
        return {"id": r.id, "kind": r.kind, "kind_label": KIND_LABELS[r.kind], "domain": rule_domain(r.kind, r.params),
                "params": r.params,
                "summary": describe(r.kind, r.params), "status": self.status_of(r), "reason": r.reason,
                "request_text": r.request_text, "drafted_by": r.drafted_by, "preview": r.preview,
                "proposed_by": r.proposed_by, "decided_by": r.decided_by, "decision_note": r.decision_note,
                "decided_at": r.decided_at.isoformat() if r.decided_at else None,
                "expires_at": r.expires_at.isoformat() if r.expires_at else None,
                "created_at": r.created_at.isoformat(), "applied": hits["applied"], "qa_samples": hits["qa_sample"]}

    # -- changing

    def propose(self, kind: str, params: Any, by: Principal, *, reason: str, request_text: str = "",
                drafted_by: str = "form", preview: dict[str, Any] | None = None) -> TuningRule:
        if kind not in KINDS:
            raise ValueError(f"unknown rule kind '{kind}' ({', '.join(KINDS)})")
        _may_tune(by, kind, params)
        if not (reason or "").strip():
            raise ValueError("say why the rule is needed (kept with the rule and in the audit log)")
        clean = clean_params(self.s, kind, params)
        row = TuningRule(kind=kind, params=clean, status="proposed", reason=reason.strip()[:1000],
                         request_text=(request_text or "")[:2000],
                         drafted_by=drafted_by if drafted_by in ("llm", "rules", "form") else "form",
                         preview=preview or {}, proposed_by=by.id)
        self.s.add(row)
        self.s.flush()
        self.audit.append(actor_type=by.actor_type, actor_id=by.id, event_type="tuning.proposed",
                          subject_type="tuning_rule", subject_id=str(row.id),
                          payload={"kind": kind, "rule": describe(kind, clean), "params": clean,
                                   "reason": row.reason, "drafted_by": row.drafted_by,
                                   "preview": {k: v for k, v in (preview or {}).items() if k != "examples"}})
        return row

    def _pending(self, rule_id: int, statuses: tuple[str, ...], what: str) -> TuningRule:
        row = self.s.get(TuningRule, rule_id)
        if row is None:
            raise KeyError(f"unknown tuning rule {rule_id}")
        if self.status_of(row) not in statuses:
            raise ValueError(f"rule {rule_id} is {self.status_of(row)} - it cannot be {what}")
        return row

    def approve(self, rule_id: int, by: Principal, note: str = "") -> TuningRule:
        row = self._pending(rule_id, ("proposed",), "approved")
        _may_tune(by, row.kind, row.params)
        if row.proposed_by == by.id:
            raise PermissionError("separation of duties: a second lead approves - not the one who proposed it")
        clean_params(self.s, row.kind, row.params)          # the data may have changed since it was proposed
        now = utcnow()
        if row.kind in SINGLETONS:
            for old in self.active(row.kind):
                old.status, old.decided_at = "superseded", now
        row.status, row.decided_by, row.decided_at = "active", by.id, now
        row.decision_note = (note or "")[:1000]
        row.expires_at = now + timedelta(days=int(row.params.get("expires_days") or EXPIRES_DEFAULT))
        self.audit.append(actor_type=by.actor_type, actor_id=by.id, event_type="tuning.activated",
                          subject_type="tuning_rule", subject_id=str(row.id),
                          payload={"rule": describe(row.kind, row.params), "proposed_by": row.proposed_by,
                                   "expires_at": row.expires_at.isoformat(), "note": row.decision_note})
        return row

    def reject(self, rule_id: int, by: Principal, note: str = "") -> TuningRule:
        row = self._pending(rule_id, ("proposed",), "rejected")
        _may_tune(by, row.kind, row.params)
        row.status, row.decided_by, row.decided_at, row.decision_note = "rejected", by.id, utcnow(), (note or "")[:1000]
        self.audit.append(actor_type=by.actor_type, actor_id=by.id, event_type="tuning.rejected",
                          subject_type="tuning_rule", subject_id=str(row.id), payload={"note": row.decision_note})
        return row

    def revoke(self, rule_id: int, by: Principal, note: str = "") -> TuningRule:
        """Roll a rule back at once (any lead - stopping a rule never needs a second person)."""
        row = self._pending(rule_id, ("active",), "revoked")
        _may_tune(by, row.kind, row.params)
        if not (note or "").strip():
            raise ValueError("say why the rule is revoked")
        row.status, row.decided_by, row.decided_at, row.decision_note = "revoked", by.id, utcnow(), note.strip()[:1000]
        self.audit.append(actor_type=by.actor_type, actor_id=by.id, event_type="tuning.revoked",
                          subject_type="tuning_rule", subject_id=str(row.id), payload={"note": row.decision_note})
        return row

    def pause_for_threat(self, rule_id: Any, case: Case, analyst: Principal, verdict: str) -> TuningRule | None:
        """An analyst ruled a case this rule suppressed (or sampled) a threat: the rule stops at once."""
        row = self.s.get(TuningRule, rule_id) if isinstance(rule_id, int) else None
        if row is None or row.status != "active" or row.kind != "suppress_detection":
            return None
        row.status, row.decided_by, row.decided_at = "paused", analyst.id, utcnow()
        row.decision_note = f"paused: case {case.id} was ruled {verdict}"[:1000]
        self.audit.append(actor_type=analyst.actor_type, actor_id=analyst.id, event_type="tuning.paused",
                          subject_type="tuning_rule", subject_id=str(row.id),
                          payload={"case": case.id, "analyst_verdict": verdict, "rule": describe(row.kind, row.params)})
        return row


def may_tune(by: Principal, kind: str, params: Any = None) -> bool:
    """A person with tune_detections in the rule's domain (a phishing lead tunes phishing, an incident lead incidents).
    For an action rule without params: may this person tune actions in any domain?"""
    if by.is_service or by.is_agent:
        return False
    if kind == "action_demote" and not (isinstance(params, dict) and params.get("domain")):
        return any(may_tune(by, kind, {"domain": d}) for d in DOMAINS)
    d = rule_domain(kind, params)
    return by.in_domain(d) and by.acting_in(d).can(Perm.TUNE_DETECTIONS)


def _may_tune(by: Principal, kind: str, params: Any = None) -> None:
    if not may_tune(by, kind, params):
        raise PermissionError(f"a lead with {rule_domain(kind, params)} scope (tune_detections) changes this tuning - "
                              "a person, never an API key")


# ---------------------------------------------------------------- usually rejected actions


def case_facts(session: Session, case: Case) -> dict[str, Any]:
    """A case as an action rule matches it: its detection and the names of its hosts and people."""
    hosts, users = set(), set()
    for ln in session.execute(select(CaseEntity).where(CaseEntity.case_id == case.id)).scalars():
        ent = session.get(Entity, ln.entity_id)
        if ent is None or ent.kind not in ("asset", "identity"):
            continue
        ea = ent.attributes or {}
        names = {str(n) for n in (ent.display_name, ea.get("hostname"), ea.get("fqdn"), ea.get("upn"), ea.get("email")) if n}
        if ent.kind == "asset":
            hosts |= names | {n.split(".")[0] for n in names}
        else:
            users |= names
    return {"title": (case.attributes or {}).get("detection_source") or "", "tool": None,
            "hosts": sorted(hosts), "users": sorted(users)}


def demote_rule(session: Session, case: Case | None, action_type: str, *, rules: list[TuningRule] | None = None,
                facts: dict[str, Any] | None = None) -> TuningRule | None:
    """The usually-rejected rule covering this recommendation, or None. A critical or deception case is never
    covered: whatever analysts rejected before, a serious case keeps its normal handling."""
    if case is None:
        return None
    rules = [r for r in (rules if rules is not None else TuningStore(session).active("action_demote"))
             if r.params.get("action_type") == action_type and r.params.get("domain") == case.domain]
    if not rules or case.severity == "critical" or (case.attributes or {}).get("deception"):
        return None
    facts = facts or case_facts(session, case)
    return next((r for r in rules if matches(r.params, facts)), None)


def _human_decisions(session: Session) -> list[tuple[Any, Case | None, bool]]:
    """Every action a person decided, with its case and whether it was rejected."""
    from soc_platform.core.models import ActionRequest

    rows = session.execute(select(ActionRequest).where(ActionRequest.approver.is_not(None))).scalars().all()
    cases = {c.id: c for c in session.execute(select(Case).where(
        Case.id.in_(sorted({a.case_id for a in rows if a.case_id}) or [""]))).scalars()}
    return [(a, cases.get(a.case_id), a.status == "rejected") for a in rows
            if not str(a.approver or "").startswith("agent:")]


def action_suggestions(session: Session, *, days: int = 30) -> list[dict[str, Any]]:
    """Actions analysts keep rejecting in one context (domain, action type, detection) over the last ``days`` of
    decisions (ending at the newest decision) - each a ready draft. Never applied without a second lead."""
    decided = _human_decisions(session)
    times = [_naive(a.decided_at) for a, _, _ in decided if a.decided_at]
    if not times:
        return []
    since = max(times) - timedelta(days=days)
    groups: dict[tuple[str, str, str | None], Counter[str]] = {}
    for a, case, rejected in decided:
        if not a.decided_at or _naive(a.decided_at) < since:
            continue
        det = (case.attributes or {}).get("detection_source") if case is not None and case.domain == "incident" else None
        groups.setdefault((a.domain, a.action_type, det), Counter())["rejected" if rejected else "approved"] += 1
    covered = {(r.params.get("domain"), r.params.get("action_type"), r.params.get("detection"))
               for r in TuningStore(session).active("action_demote")}
    out = []
    for (dom, act, det), c in sorted(groups.items(), key=lambda kv: (kv[0][0], kv[0][1], kv[0][2] or "")):
        n = c["rejected"] + c["approved"]
        if dom not in DOMAINS or n < DEMOTE_MIN_DECISIONS or c["rejected"] / n < DEMOTE_REJECT_SHARE:
            continue
        if (dom, act, det) in covered or (dom, act, None) in covered:
            continue
        where = f" for '{det}'" if det else ""
        out.append({"domain": dom, "action_type": act, "detection": det, "decisions": n, "rejected": c["rejected"],
                    "reject_share": round(c["rejected"] / n, 3),
                    "draft": {"kind": "action_demote", "drafted_by": "rules",
                              "params": {"domain": dom, "action_type": act, "detection": det,
                                         "expires_days": EXPIRES_DEFAULT},
                              "reason": f"Analysts rejected {c['rejected']} of {n} {act} recommendations{where} "
                                        f"in {days} days"}})
    return out


# ---------------------------------------------------------------------------------------------- preview


def preview(session: Session, store: Any, kind: str, params: Any, *, kev_cves: set[str] | None = None,
            days: int = PREVIEW_DAYS, phishing_history: list[dict[str, Any]] | None = None,
            vuln_preview: Any = None) -> dict[str, Any]:
    """What the rule would have done over the last ``days`` of alerts (ending at the newest alert, as clustering
    does), or over the reported e-mails analysed so far: every figure is counted from stored data and analysts'
    decisions."""
    from soc_platform.core.cases import detection_quality

    clean = clean_params(session, kind, params)
    if kind == "vuln_priority":
        cur = TuningStore(session).vuln_priority()
        return {"kind": kind, "summary": describe(kind, clean), "current": cur, **(vuln_preview(clean) if vuln_preview else {}),
                "note": ("A KEV-listed finding on an internet-facing asset stays P1 and every KEV-listed finding keeps "
                         "the P1 SLA, whatever the weights.")}
    if kind == "action_demote":
        return _demote_preview(session, clean, days)
    if kind == "phishing_autoclose":
        hist = phishing_history or []
        cur = TuningStore(session).autoclose()
        now_, new = autoclose_effect(hist, cur["min_confidence_percent"]), autoclose_effect(hist, clean["min_confidence_percent"])
        return {"kind": kind, "summary": describe(kind, clean), "current": cur, "reports": len(hist),
                "decided": sum(1 for h in hist if h["analyst"] in ("malicious", "suspicious", "benign")),
                "auto_closed_now": now_["closed"], "auto_closed_after": new["closed"],
                "threats_closed_now": now_["threats"], "threats_closed_after": new["threats"],
                "sampled_after": round(new["closed"] * clean["sample_percent"] / 100),
                "suggestion": autoclose_suggestion(hist, cur["min_confidence_percent"]),
                "note": "A report somebody clicked, or one a mail gateway rated worse, is never auto-closed."}
    if kind == "noise_threshold":
        cur = TuningStore(session).threshold()
        before = {d["detection"]: d for d in detection_quality(session, "incident", **_dq(cur))}
        after = {d["detection"]: d for d in detection_quality(session, "incident", **_dq(clean))}
        return {"kind": kind, "summary": describe(kind, clean), "current": cur,
                "noisy_now": sorted(before), "noisy_after": sorted(after),
                "newly_noise": [after[k] for k in sorted(set(after) - set(before))],
                "no_longer_noise": [before[k] for k in sorted(set(before) - set(after))],
                "note": "Only low and medium incidents made entirely of a noisy detection are closed as noise."}
    alerts = session.execute(select(Entity).where(Entity.kind.in_(ALERT_KINDS))).scalars().all()
    newest = max((_naive(a.first_seen) for a in alerts if a.first_seen), default=None)
    now = _naive(utcnow())
    end = min(newest, now) if newest else now
    since = end - timedelta(days=days)
    in_window = [a for a in alerts if a.first_seen and _naive(a.first_seen) >= since
                 and incident_alert(a.display_name, a.attributes)]
    det = (clean.get("detection") or "").casefold()
    facts = alert_facts(session, store, [a for a in in_window if not det or (a.display_name or "").casefold() == det])
    hit = {aid: f for aid, f in facts.items() if matches(clean, f)}
    if kind in ("raise_severity", "exercise"):
        return _scope_preview(session, kind, clean, hit, days, since, end)
    kev_hosts = kev_host_ids(store, {h for f in hit.values() for h in f["host_ids"]}, kev_cves or set())
    kept: Counter[str] = Counter()
    suppressed = []
    for aid, f in hit.items():
        why = guard(f, clean["max_severity"], kev_hosts)
        if why:
            kept[why] += 1
        else:
            suppressed.append(aid)
    # what analysts concluded about the incidents these alerts were part of
    verdicts: Counter[str] = Counter()
    threat_cases: list[str] = []
    case_of = {ln.entity_id: ln.case_id for ln in session.execute(
        select(CaseEntity).where(CaseEntity.role == "alert", CaseEntity.entity_id.in_(list(hit) or [""]))).scalars()}
    from soc_platform.core.cases import _bucket

    for cid in sorted(set(case_of.values())):
        d = session.execute(select(Disposition).where(Disposition.subject_id == cid)
                            .order_by(Disposition.created_at.desc()).limit(1)).scalars().first()
        b = _bucket(d.analyst_verdict) if d else "undecided"
        verdicts[b] += 1
        if b in ("malicious", "suspicious"):
            threat_cases.append(cid)
    sev = Counter(hit[a]["severity"] for a in suppressed)
    return {"kind": kind, "summary": describe(kind, clean), "days": days,
            "window": {"from": since.isoformat(), "to": end.isoformat()},
            "detection_alerts": len(facts), "matching_alerts": len(hit), "would_suppress": len(suppressed),
            "kept_by_guardrails": dict(sorted(kept.items())), "by_severity": dict(sorted(sev.items())),
            "hosts": len({h for a in suppressed for h in hit[a]["host_ids"]}),
            "incident_verdicts": dict(sorted(verdicts.items())), "threats_hidden": len(threat_cases),
            "threat_cases": threat_cases[:20],
            "examples": [{"title": hit[a]["title"], "severity": hit[a]["severity"],
                          "hosts": hit[a]["hosts"][:3], "users": hit[a]["users"][:3],
                          "at": hit[a]["at"].isoformat() if hit[a]["at"] else None}
                         for a in sorted(suppressed, key=lambda x: (_naive(hit[x]["at"]) if hit[x]["at"] else end, x),
                                         reverse=True)[:10]],
            "qa_rate": QA_RATE}


def _scope_preview(session: Session, kind: str, clean: dict[str, Any], hit: dict[str, dict[str, Any]], days: int,
                   since: datetime, end: datetime) -> dict[str, Any]:
    """Raise attention / exercise: the alerts and incidents in scope, and what would change for them."""
    links = session.execute(select(CaseEntity).where(CaseEntity.role == "alert",
                                                     CaseEntity.entity_id.in_(list(hit) or [""]))).scalars().all()
    cases = [c for c in (session.get(Case, cid) for cid in sorted({ln.case_id for ln in links})) if c is not None]
    out = {"kind": kind, "summary": describe(kind, clean), "days": days,
           "window": {"from": since.isoformat(), "to": end.isoformat()}, "matching_alerts": len(hit),
           "hosts": len({h for f in hit.values() for h in f["host_ids"]}),
           "users": len({u for f in hit.values() for u in f["users"] if "@" in u}), "incidents": len(cases)}
    if kind == "raise_severity":
        moves: Counter[str] = Counter()
        for c in cases:
            r = severity_rank(c.severity)
            moves[f"{c.severity} -> {SEVERITIES[min(4, r + clean['levels'])]}"] += 1 if r < 4 else 0
        out["severity_changes"] = {k: v for k, v in sorted(moves.items()) if v}
        out["note"] = ("New and re-assessed incidents in scope are raised; their verdict is still judged on the "
                       "unraised severity, and actions stay at their approval level.")
    else:
        decided = session.execute(select(Disposition).where(Disposition.subject_id.in_([c.id for c in cases] or [""]))).scalars()
        out["decisions_kept_out_of_noise_statistics"] = sum(1 for _ in decided)
        out["note"] = ("Incidents in scope are labelled [Exercise], investigated as usual and never suppressed; "
                       "analysts' decisions on them do not count towards the noise statistics.")
    return out


SEVERITIES = ("informational", "low", "medium", "high", "critical")


def _demote_preview(session: Session, clean: dict[str, Any], days: int) -> dict[str, Any]:
    """How analysts decided this action in this context over the last ``days`` (ending at the newest action)."""
    from soc_platform.core.models import ActionRequest

    rows = session.execute(select(ActionRequest).where(ActionRequest.action_type == clean["action_type"],
                                                       ActionRequest.domain == clean["domain"])).scalars().all()
    newest = max((_naive(a.created_at) for a in rows if a.created_at), default=_naive(utcnow()))
    since = newest - timedelta(days=days)
    cases = {c.id: c for c in session.execute(select(Case).where(
        Case.id.in_(sorted({a.case_id for a in rows if a.case_id}) or [""]))).scalars()}
    outcome: Counter[str] = Counter()
    for a in rows:
        case = cases.get(a.case_id)
        if not a.created_at or _naive(a.created_at) < since or case is None:
            continue
        if not matches(clean, case_facts(session, case)):
            continue
        if case.severity == "critical" or (case.attributes or {}).get("deception"):
            outcome["kept: critical or deception case"] += 1
        elif a.status == "rejected":
            outcome["rejected by an analyst"] += 1
        elif a.approver and not str(a.approver).startswith("agent:"):
            outcome["approved by an analyst"] += 1
        else:
            outcome["not decided yet"] += 1
    return {"kind": "action_demote", "summary": describe("action_demote", clean), "days": days,
            "outcomes": dict(sorted(outcome.items())), "approved_by_analysts": outcome["approved by an analyst"],
            "note": ("New recommendations in scope are still shown, labelled 'usually rejected here', and can never run "
                     "autonomously there. Critical and deception cases are not affected.")}


def autoclose_effect(history: list[dict[str, Any]], min_percent: int) -> dict[str, int]:
    """How many analysed reports a confidence would auto-close, and how many of them analysts ruled a threat."""
    closed = [h for h in history if h["verdict"] in ("safe", "spam") and h["confidence"] is not None
              and h["confidence"] * 100 >= min_percent and not h["clicked"] and not h["gateway_flagged"]]
    return {"closed": len(closed), "threats": sum(1 for h in closed if h["analyst"] in ("malicious", "suspicious"))}


MIN_DECIDED_FOR_SUGGESTION = 10


def autoclose_suggestion(history: list[dict[str, Any]], current: int) -> dict[str, Any] | None:
    """The lowest confidence (in steps of 5) at which no report an analyst ruled a threat would have been
    auto-closed - computed, never the model; None without enough analyst decisions to say."""
    decided = [h for h in history if h["analyst"] in ("malicious", "suspicious", "benign")]
    if len(decided) < MIN_DECIDED_FOR_SUGGESTION:
        return None
    lo, hi = AUTOCLOSE_BOUNDS["min_confidence_percent"]
    safe = next((p for p in range(lo, hi + 1, 5) if autoclose_effect(history, p)["threats"] == 0), None)
    if safe is None or safe == current:
        return None
    eff = autoclose_effect(history, safe)
    return {"min_confidence_percent": safe, "would_auto_close": eff["closed"], "decided": len(decided),
            "now": autoclose_effect(history, current),
            "why": (f"at {safe}% no report analysts ruled a threat would have closed; now ({current}%) "
                    f"{autoclose_effect(history, current)['threats']} would" if safe > current else
                    f"{safe}% would still close no report analysts ruled a threat, and close more reports")}


def _naive(v: datetime) -> datetime:
    return v.replace(tzinfo=None)


def _dq(t: dict[str, Any]) -> dict[str, Any]:
    return {"min_count": t["min_decisions"], "days": t["days"], "share": t["benign_percent"] / 100}


# ---------------------------------------------------------------------------------------------- drafting


def _numbers(text: str) -> set[int]:
    return {int(n) for n in re.findall(r"(?<![\w.])(\d{1,4})(?![\w.])", text)}


def _written(pattern: str, text: str) -> bool:
    """Every literal part of a pattern appears in the request (the model may add wildcards, not names)."""
    parts = [x for x in re.split(r"[*?]+", pattern.casefold()) if x.strip()]
    return bool(parts) and all(x in text.casefold() for x in parts)


def draft(session: Session, request: str, llm: Any = None, *, incident: bool = True) -> dict[str, Any]:
    """A lead's request in words -> a draft rule for them to check, preview and propose. Nothing is stored.
    ``incident=False``: the person has no incident scope, so no alert titles or tools go into the prompt."""
    from soc_platform.llm.gateway import BudgetExceeded, model_choice

    text = (request or "").strip()[:1500]
    dets = known_detections(session) if incident else {}
    tools = known_tools(session) if incident else []
    actions = known_action_types(session)
    by_fold = {t.casefold(): t for t in dets}
    notes: list[str] = []
    data: dict[str, Any] | None = None
    if llm is not None:
        listing = "\n".join(f"- {t} ({n} alerts)" for t, n in list(dets.items())[:300])
        try:
            data = llm.complete_json(
                "tuning.draft", DRAFT_SYSTEM,
                f"DETECTIONS SEEN:\n{listing}\n\nTOOLS: {', '.join(tools)}\n\nACTIONS: {', '.join(actions)}"
                f"\n\nREQUEST: {text}\n\nReturn JSON: "
                '{"kind": "suppress_detection|noise_threshold|raise_severity|exercise|phishing_autoclose", '
                '"detection": "<exact title from the list or null>", "tool": null, "host": null, "user": null, '
                '"max_severity": "low", "levels": null, "expires_days": null, "benign_percent": null, '
                '"min_decisions": null, "days": null, "min_confidence_percent": null, "sample_percent": null, '
                '"weight_cvss": null, "weight_epss": null, "weight_kev": null, "weight_exposure": null, '
                '"weight_criticality": null, "sla_p1": null, "sla_p2": null, "sla_p3": null, "sla_p4": null, '
                '"action_type": null, "domain": null, "reason": "<one line>"}', tier="small")
        except BudgetExceeded:
            data = None
        if not isinstance(data, dict):
            # refused (a usage limit, the endpoint's content filter - which blocks prompt-injection attempts) or
            # unavailable: say so, so the lead knows the draft is the platform's own reading of the words
            notes.append("the model did not answer this request (refused or unavailable) - the platform read it itself")
    nums = _numbers(text)
    if isinstance(data, dict):
        kind = model_choice(data.get("kind"), KINDS, "suppress_detection")
        out: dict[str, Any] = {"expires_days": EXERCISE_DEFAULT if kind == "exercise" else EXPIRES_DEFAULT}
        if kind == "action_demote":
            out["action_type"] = model_choice(data.get("action_type"), set(actions), None)
            out["domain"] = model_choice(data.get("domain"), set(DOMAINS), "incident")
            if data.get("action_type") and not out["action_type"]:
                notes.append("the action named is not one the platform has recommended - choose it from the list")
        if kind in ("suppress_detection", "raise_severity", "exercise", "action_demote"):
            det = data.get("detection")
            out["detection"] = by_fold.get(det.casefold()) if isinstance(det, str) else None
            if det and not out["detection"]:
                notes.append("the detection named was not one the platform has seen - choose it from the list")
            out["tool"] = model_choice(data.get("tool"), set(tools), None)
            for k in ("host", "user"):
                v = data.get(k)
                ok = isinstance(v, str) and v.strip() and _written(v, text) and _PATTERN.fullmatch(v.strip())
                out[k] = v.strip() if ok else None
                if v and not ok:
                    notes.append(f"the {k} pattern was dropped: it is not written in the request")
            if kind == "suppress_detection":
                out["max_severity"] = model_choice(data.get("max_severity"), set(SUPPRESSIBLE), "low")
            if kind == "raise_severity":
                lv = _whole(data.get("levels"))
                out["levels"] = lv if lv in (1, 2) and lv in nums else 1
        else:
            defaults = {"noise_threshold": DEFAULT_THRESHOLD, "phishing_autoclose": DEFAULT_AUTOCLOSE,
                        "vuln_priority": DEFAULT_VULN}[kind]
            for k in defaults:
                v = _whole(data.get(k))
                out[k] = v if v is not None and v in nums else defaults[k]
                if v is not None and v not in nums:
                    notes.append(f"{k} {v} is not written in the request - the default {defaults[k]} is used")
            if kind == "vuln_priority" and sum(out[k] for k in VULN_WEIGHTS) != 100:
                notes.append("the five weights must add up to 100 - adjust them before previewing")
        exp = _whole(data.get("expires_days"))
        if exp is not None and exp in nums and 1 <= exp <= (EXERCISE_MAX if kind == "exercise" else EXPIRES_MAX):
            out["expires_days"] = exp
        reason = data.get("reason") if isinstance(data.get("reason"), str) else ""
        return {"kind": kind, "params": out, "reason": (reason or text)[:300], "drafted_by": "llm",
                "notes": notes, "request": text}
    # the platform's own reading of the request (the model is off or refused)
    low = text.casefold()
    # what kind of change: read from the words around a named detection, not from its title ("Port scan from the
    # vulnerability scanner" is not a request about vulnerability priority)
    named = max((f for f in by_fold if f in low), key=len, default="")
    words = low.replace(named, " ") if named else low
    kind = ("exercise" if re.search(r"exercise|red[- ]?team|pen(etration)?[- ]?test|purple[- ]?team", words) else
            "phishing_autoclose" if re.search(r"auto[- ]?clos|phish", words) else
            "noise_threshold" if re.search(r"threshold|benign (share|percent)|decisions", words) else
            "vuln_priority" if re.search(r"vulnerab|\bsla\b|\bcvss\b|\bepss\b|patch", words) else
            "action_demote" if re.search(r"reject|stop recommending|(?:don'?t|do not|never) recommend|keeps? recommending", words) else
            "raise_severity" if re.search(r"raise|higher|more important|matter[s]? more|escalat|prioriti[sz]e|\bwatch\b.{0,80}?\bclosely", words)
            else "suppress_detection")
    out = {"expires_days": EXERCISE_DEFAULT if kind == "exercise" else EXPIRES_DEFAULT}
    m = re.search(r"(\d{1,3})\s*days?", low)
    if kind in ("suppress_detection", "raise_severity", "exercise", "action_demote"):
        hit = max((t for f, t in by_fold.items() if f in low), key=len, default=None)
        out["detection"] = hit
        if not hit and kind == "suppress_detection":
            notes.append("no detection the platform has seen is named in the request - choose it from the list")
        for g in re.findall(r"[\w.\-@]*[*?][\w.\-@*?]*", text) + re.findall(r"[\w.\-]{1,64}@[\w.\-]{1,190}", text):
            k = "user" if "@" in g else "host"
            if g.strip("*?") and not out.get(k):
                out[k] = g
        if kind in ("raise_severity", "exercise") and not (out.get("host") or out.get("user")):
            notes.append("no host or user is named - write a name or a pattern such as fin-*")
        out["tool"] = next((t for t in tools if t.casefold() in low), None)
        if kind == "suppress_detection":
            out["max_severity"] = "medium" if "medium" in low else "informational" if "informational" in low else "low"
        if kind == "raise_severity":
            out["levels"] = 2 if re.search(r"\btwo levels|\b2 levels", low) else 1
        cap = EXERCISE_MAX if kind == "exercise" else EXPIRES_MAX
        if m and 1 <= int(m.group(1)) <= cap and re.search(r"for\s+\d{1,3}\s*days?|expir|next\s+\d{1,3}\s*days?", low):
            out["expires_days"] = int(m.group(1))
    if kind == "action_demote":
        spaced = {a: a.split(".")[-1].replace("_", " ") for a in actions}
        out["action_type"] = next((a for a in actions if a.casefold() in low), None) or \
            max((a for a, words in spaced.items() if words.casefold() in low), key=lambda a: len(spaced[a]), default=None)
        out["domain"] = "phishing" if "phish" in low else "vulnerability" if "vulnerab" in low else "incident"
        if out["detection"] and out["domain"] != "incident":
            out["detection"] = None
        out.pop("tool", None)
        if not out["action_type"]:
            notes.append("no action the platform has recommended is named - choose it from the list")
    elif kind == "vuln_priority":
        for band, n in re.findall(r"\bp([1-4])\b\D{0,25}?(\d{1,3})\s*days?", low):
            out[f"sla_p{band}"] = int(n)
        words = {"cvss": "weight_cvss", "epss": "weight_epss", "kev": "weight_kev", "known[- ]exploited": "weight_kev",
                 "exposure": "weight_exposure", "internet": "weight_exposure", "criticality": "weight_criticality"}
        for w, key in words.items():
            m2 = re.search(rf"{w}\D{{0,25}}?(\d{{1,2}})\s*%", low)
            if m2 and key not in out:
                out[key] = int(m2.group(1))
        out = {**{k: v for k, v in DEFAULT_VULN.items()}, **out}
        if sum(out[k] for k in VULN_WEIGHTS) != 100:
            notes.append("the five weights must add up to 100 - adjust them before previewing")
    elif kind == "phishing_autoclose":
        pcts = [int(x) for x in re.findall(r"(\d{1,3})\s*%", low)]
        conf = next((x for x in pcts if 50 <= x <= 95), None)
        smp = re.search(r"(?:sample|check|qa)\D{0,20}(\d{1,2})\s*%|1 in (\d{1,2})", low)
        out["min_confidence_percent"] = conf or DEFAULT_AUTOCLOSE["min_confidence_percent"]
        out["sample_percent"] = (int(smp.group(1)) if smp and smp.group(1) else
                                 round(100 / int(smp.group(2))) if smp and smp.group(2) and int(smp.group(2)) > 0 else
                                 DEFAULT_AUTOCLOSE["sample_percent"])
    elif kind == "noise_threshold":
        pm = re.search(r"(\d{1,3})\s*(?:%|percent)", low)
        dm = re.search(r"(\d{1,2})\s*(?:analyst\s+)?decisions", low)
        out["benign_percent"] = int(pm.group(1)) if pm else DEFAULT_THRESHOLD["benign_percent"]
        out["min_decisions"] = int(dm.group(1)) if dm else DEFAULT_THRESHOLD["min_decisions"]
        out["days"] = int(m.group(1)) if m else DEFAULT_THRESHOLD["days"]
    return {"kind": kind, "params": out, "reason": text[:300], "drafted_by": "rules", "notes": notes, "request": text}


def suggestions(session: Session) -> list[dict[str, Any]]:
    """Detections analysts keep ruling benign that no active rule covers yet - each a ready draft. (The phishing
    auto-close suggestion comes from ``autoclose_suggestion`` with the reports' history.)"""
    from soc_platform.core.cases import detection_quality

    st = TuningStore(session)
    covered = {r.params.get("detection") for r in st.active_suppressions()}
    out = []
    for d in detection_quality(session, "incident", **_dq(st.threshold())):
        if d["detection"] in covered or d["detection"] == "unknown":
            continue
        out.append({**d, "draft": {"kind": "suppress_detection", "drafted_by": "rules",
                                   "params": {"detection": d["detection"], "max_severity": "low",
                                              "expires_days": EXPIRES_DEFAULT},
                                   "reason": d["recommendation"]}})
    return out
