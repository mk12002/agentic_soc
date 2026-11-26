"""Needs immediate attention: the few recent, serious cases nobody has started on, with why each one is urgent now.

Shown at the top of the Overview and the CISO's executive view, above everything else. Every rule is fixed code - the
model never decides what is urgent - and every reason names the record it comes from:

* an open **incident or phishing case** created within ``SOC_URGENT_WINDOW_HOURS`` (default 24), with **no owner**
  and no decision yet, that is **critical**, or **high with at least one urgency signal** on the people or hosts it
  involves (the risk engine's factors: a deception tripwire, a risky sign-in - impossible travel, an unfamiliar or
  anonymous location, with its country -, privileged credential access, a privileged account with compromise
  indicators, identity compromise after a phishing click, a click on a malicious e-mail, a malicious destination
  reached, a known-exploited vulnerability on the host, an internet-facing vulnerable host, a host without EDR);
* a **correlated finding** of an attack rule (privileged access after compromise, deception corroborated, exposed host
  under attack, phishing chain, consent after phishing, attacked host without EDR) or of critical severity, first seen
  within the window and not yet acknowledged. A finding about the same people or hosts as a listed case is added to
  that case as a reason, not shown twice.

An item leaves the strip when someone takes the case (or a lead assigns it), decides it, or acknowledges the finding -
never by being hidden. ``pickup`` measures how fast serious cases were taken over the last 30 days (detection to the
first ``case.assigned`` audit event), so the strip's effect is visible.
"""

from __future__ import annotations

import os
import statistics
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from soc_platform.core.models import AuditRecord, Case, CaseEntity, utcnow

# signal -> (label shown, ranking weight). The labels are the reasons an analyst reads first.
URGENT_SIGNALS: dict[str, tuple[str, int]] = {
    "deception_hit": ("Deception tripwire touched", 30),
    "phishing_identity_compromise": ("Account compromise indicators after a phishing click", 25),
    "privileged_user_at_risk": ("Privileged account with compromise indicators", 25),
    "privileged_credential_access": ("Privileged credentials accessed", 20),
    "risky_signin": ("Risky sign-in", 22),          # where and how the account signed in: shown before the privileged access
    "identity_risk": ("Identity risk detection", 15),
    "phishing_click": ("Clicked a malicious e-mail", 15),
    "malicious_destination_reached": ("Reached a malicious destination", 12),
    "kev_exposure": ("Known-exploited vulnerability on the host", 12),
    "internet_exposed_vulnerable": ("Internet-facing vulnerable host", 10),
    "no_edr_coverage": ("No EDR on the host", 8),
}
# which domain's data each signal is: a viewer scoped to some domains sees only those signals as reasons (the risk
# engine itself spans every domain, which is why its screens are all-domain only)
SIGNAL_DOMAIN = {"deception_hit": "incident", "privileged_user_at_risk": "incident", "privileged_credential_access": "incident",
                 "risky_signin": "incident", "identity_risk": "incident", "malicious_destination_reached": "incident",
                 "no_edr_coverage": "incident", "phishing_identity_compromise": "phishing", "phishing_click": "phishing",
                 "kev_exposure": "vulnerability", "internet_exposed_vulnerable": "vulnerability"}
# correlation rules that describe an attack in progress (the platform's own findings are not attacks)
ATTACK_RULES = {"privileged_after_compromise", "deception_corroborated", "exposed_host_under_attack",
                "phishing_compromise_chain", "consent_after_phishing", "attacked_host_without_edr"}
# findings about the platform itself (integrity, capabilities, AI integration, budgets, drift, gaps, emergency access):
# they have their own banners and notifications and are not an attack to respond to
PLATFORM_RULES = {"platform_integrity", "platform_capability", "model_drift", "control_gap", "break_glass_used",
                  "action_outcome_unknown"}


def _platform_rule(rule: str) -> bool:
    return rule in PLATFORM_RULES or rule.startswith("llm_")
SEV_WEIGHT = {"critical": 100, "high": 70}
RESPONSE_TARGET_HOURS = {"critical": 4, "high": 24}
CASE_DOMAINS = ("incident", "phishing")


def window_hours() -> int:
    try:
        return max(1, min(168, int(os.environ.get("SOC_URGENT_WINDOW_HOURS", "24"))))
    except ValueError:
        return 24


def _aware(t: datetime) -> datetime:

    return t if t.tzinfo else t.replace(tzinfo=UTC)


def _entity_factors(s: Session, entity_ids: list[str]) -> list[Any]:
    """The risk engine's factors for these people / hosts (the same figures the Intelligence screen shows)."""
    from soc_platform.intelligence.risk import RiskEngine

    eng = RiskEngine(s)
    out = []
    for eid in entity_ids:
        p = eng.profile(eid)
        if p is not None:
            out.extend((p.name, f) for f in p.factors)
    return out


def _reasons(s: Session, entity_ids: list[str], domains: Any = frozenset({"*"})) -> list[dict[str, Any]]:
    """One reason per urgency signal, naming every person / host it was seen on (a user and their laptop share most);
    for a viewer scoped to some domains, only the signals of those domains."""
    seen: dict[str, dict[str, Any]] = {}
    for who, f in sorted(_entity_factors(s, entity_ids), key=lambda x: (x[0], x[1].signal, x[1].ref)):
        if f.signal not in URGENT_SIGNALS or f.decayed <= 0:
            continue
        if "*" not in domains and SIGNAL_DOMAIN.get(f.signal) not in domains:
            continue
        label, w = URGENT_SIGNALS[f.signal]
        r = seen.setdefault(f.signal, {"signal": f.signal, "label": label, "who": "", "detail": (f.detail or "")[:200],
                                       "at": f.when, "source": f.source, "weight": w, "_who": []})
        if who not in r["_who"]:
            r["_who"].append(who)
    out = []
    for r in seen.values():
        names = r.pop("_who")
        r["who"] = ", ".join(names[:2]) + (f" +{len(names) - 2}" if len(names) > 2 else "")
        out.append(r)
    return sorted(out, key=lambda r: (-r["weight"], r["label"]))


def _in_scope(domains: Any, item_domains: list[str]) -> bool:
    if "*" in domains:
        return True
    return bool(item_domains) and bool(set(item_domains) & set(domains))


def urgent(s: Session, domains: Any, *, limit: int = 3, now: datetime | None = None) -> dict[str, Any]:
    """The items, most urgent first: at most ``limit`` shown, ``total`` waiting, plus pickup statistics."""
    from soc_platform.intelligence.models import Insight

    now = _aware(now or utcnow())
    hours = window_hours()
    since = now - timedelta(hours=hours)
    items: list[dict[str, Any]] = []

    cases = s.execute(select(Case).where(Case.domain.in_(CASE_DOMAINS), Case.status != "closed",
                                         Case.assignee.is_(None), Case.severity.in_(tuple(SEV_WEIGHT)),
                                         Case.created_at >= since).order_by(Case.created_at.desc(), Case.id)).scalars().all()
    for c in cases:
        if not _in_scope(domains, [c.domain]):
            continue
        ents = sorted(set(s.execute(select(CaseEntity.entity_id).where(CaseEntity.case_id == c.id)).scalars()))
        reasons = _reasons(s, ents, domains)
        if c.severity == "high" and not reasons:
            continue                                   # high alone is the queue's job; high + a signal is urgent
        created = _aware(c.created_at)
        due = created + timedelta(hours=RESPONSE_TARGET_HOURS[c.severity])
        items.append({"kind": "case", "id": c.id, "title": c.title, "severity": c.severity, "domain": c.domain,
                      "detected_at": created.isoformat(), "due_at": due.isoformat(), "overdue": now > due,
                      "owner": None, "reasons": reasons, "entities": ents, "link": f"#/cases/{c.id}",
                      "score": SEV_WEIGHT[c.severity] + sum(r["weight"] for r in reasons[:4])})

    # one attack story, one item: cases about the same person or host gather under the most urgent of them (the
    # others are listed as related; when the lead case is taken, the next one leads)
    items.sort(key=_order)
    stories: list[dict[str, Any]] = []
    for it in items:
        lead = next((st for st in stories if set(st["entities"]) & set(it["entities"])), None)
        if lead is None:
            it["related_cases"] = []
            stories.append(it)
            continue
        lead["entities"] = sorted(set(lead["entities"]) | set(it["entities"]))
        lead["related_cases"].append({"id": it["id"], "title": it["title"], "severity": it["severity"]})
        lead["reasons"].append({"signal": "related_case", "label": "Related case, same person or host", "who": "",
                                "detail": it["title"][:200], "at": it["detected_at"], "source": it["domain"],
                                "weight": 5})
    items = stories

    findings = s.execute(select(Insight).where(Insight.status == "new", Insight.first_seen >= since,
                                               Insight.severity.in_(tuple(SEV_WEIGHT)))
                         .order_by(Insight.first_seen.desc(), Insight.id)).scalars().all()   # fixed order on a tie
    for i in findings:
        if _platform_rule(i.rule) or not (i.rule in ATTACK_RULES or i.severity == "critical"):
            continue
        if "*" not in domains:     # correlated findings span domains (their evidence names other domains' cases):
            continue               # all-domain viewers only, as on the Intelligence screen
        # a finding joining another item is shown by its own title (a chip reading only "Correlated finding" said nothing)
        short = i.title if len(i.title) <= 90 else i.title[:89] + "…"
        reason = {"signal": f"finding:{i.rule}", "label": f"Finding: {short}", "who": "", "detail": i.title[:200],
                  "at": _aware(i.first_seen).isoformat(), "source": "correlation", "weight": 15}
        ents = set(i.entity_ids or [])
        case_refs = {str(e.get("ref")) for e in (i.evidence or []) if isinstance(e, dict) and e.get("ref")}
        host = next((it for it in items if it["kind"] == "case" and (ents & set(it["entities"]) or it["id"] in case_refs
                                                                      or case_refs & {r["id"] for r in it["related_cases"]})), None)
        if host is not None:                       # the same people / hosts or the same case: one story, one item
            host["reasons"].append(reason)
            host["score"] += reason["weight"]
            continue
        story = ("e", frozenset(ents)) if ents else ("c", frozenset(case_refs)) if case_refs else ("i", i.id)
        same = next((it for it in items if it.get("_story") == story), None)
        if same is not None:                       # several findings about one case (a supplier's payment diversion
            same["reasons"].append(reason)         # and impersonation): one item listing each
            same["score"] = max(same["score"], SEV_WEIGHT[i.severity] + 15) + 5
            continue
        first = _aware(i.first_seen)
        due = first + timedelta(hours=RESPONSE_TARGET_HOURS[i.severity])
        case_link = sorted(case_refs & set(s.execute(select(Case.id).where(Case.id.in_(case_refs))).scalars())) if case_refs else []
        items.append({"kind": "finding", "id": i.id, "title": i.title, "severity": i.severity,
                      "domain": ",".join(i.domains or []) or "cross-domain", "detected_at": first.isoformat(),
                      "due_at": due.isoformat(), "overdue": now > due, "owner": None,
                      "reasons": _reasons(s, sorted(ents))[:4], "entities": sorted(ents), "_story": story,
                      "related_cases": [],
                      "link": f"#/cases/{case_link[0]}" if case_link else "#/intelligence",
                      "score": SEV_WEIGHT[i.severity] + 15})

    items.sort(key=_order)   # most urgent, then newest
    for it in items:
        it.pop("entities", None)
        it.pop("_story", None)
        it["waiting_minutes"] = max(0, int((now - _aware(datetime.fromisoformat(it["detected_at"]))).total_seconds() // 60))
    oldest = max((it["waiting_minutes"] for it in items), default=0)
    return {"items": items[:max(0, limit)], "total": len(items), "window_hours": hours,
            "oldest_waiting_minutes": oldest, "generated_at": now.isoformat(), "pickup": pickup(s, domains, now=now)}


def _order(it: dict[str, Any]) -> tuple:
    """Most urgent first; on a tie an incident leads (the wider story), then a case before a finding, then the newest."""
    domain_rank = 0 if it["domain"] == "incident" else 1
    return (-it["score"], domain_rank, 0 if it["kind"] == "case" else 1, -_ts(it["detected_at"]), it["id"])


def _ts(iso: str) -> float:
    return _aware(datetime.fromisoformat(iso)).timestamp()


def pickup(s: Session, domains: Any, *, now: datetime | None = None, days: int = 30) -> dict[str, Any]:
    """How fast serious (critical / high) incident and phishing cases were taken: detection to first assignment."""
    now = _aware(now or utcnow())
    since = now - timedelta(days=days)
    cases = [c for c in s.execute(select(Case).where(Case.domain.in_(CASE_DOMAINS), Case.severity.in_(tuple(SEV_WEIGHT)),
                                                     Case.created_at >= since)).scalars()
             if _in_scope(domains, [c.domain])]
    if not cases:
        return {"days": days, "cases": 0, "taken": 0, "median_minutes": None}
    first: dict[str, datetime] = {}
    ids = [c.id for c in cases]
    for sid, ts in s.execute(select(AuditRecord.subject_id, AuditRecord.ts).where(
            AuditRecord.event_type == "case.assigned", AuditRecord.subject_id.in_(ids)).order_by(AuditRecord.seq)):
        first.setdefault(sid, _aware(ts))
    waits = [(first[c.id] - _aware(c.created_at)).total_seconds() / 60 for c in cases if c.id in first]
    return {"days": days, "cases": len(cases), "taken": len(waits),
            "median_minutes": round(statistics.median(waits), 1) if waits else None}
