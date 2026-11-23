"""The executive (CISO) view: the whole security picture on one screen, every figure computed from the records.

Built on what security leaders are usually asked to report (NIST CSF 2.0's functions - govern, identify, protect,
detect, respond - with time-to-respond and exposure figures), from the same calculations the other screens use, so
every number here matches the screen it links to:

* **Posture** - the Dome Score and its pillars, and its history from the daily snapshots.
* **Headline figures** for the period (7, 30 or 90 days), each against the period before it.
* **Agenda** - what needs a decision, bucketed by its real due date: *Overdue*, *Today*, *Tomorrow*, *This week*,
  *Later*. Due dates come from response targets by severity (critical 4 h, high 1 day, medium 3 days, low 7 days),
  vulnerability SLAs and CISA KEV due dates, risk acceptances and tuning rules ending, credentials expiring and tools
  that stopped delivering data. "Today" is the viewer's day (their time zone is passed in).
* **Sections** - threats and incidents, vulnerabilities and exposure, people and phishing, coverage and resilience,
  operations, governance, third parties, AI use.

Nothing here is written by a model; the optional brief (``executive.brief``) narrates these figures and cites them.

Trends that the records can rebuild (cases and findings opened and closed per day) are rebuilt for any period. The
rest (the Dome Score, SLA compliance, coverage) exists only from the first daily snapshot (``posture_snapshot``
job): the view says when that history starts rather than drawing a line it does not have.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import UTC, date, datetime, timedelta
from statistics import median
from typing import Any

from sqlalchemy import JSON, Integer, String, or_, select
from sqlalchemy.orm import Mapped, Session, mapped_column

from soc_platform.core.db import Base, UTCDateTime
from soc_platform.core.models import utcnow

PERIODS = (7, 30, 90)
# response targets by severity (hours): when an open incident or a waiting approval falls due
RESPONSE_TARGET_HOURS = {"critical": 4, "high": 24, "medium": 72, "low": 168, "informational": 168}
SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}
BUCKETS = ("overdue", "today", "tomorrow", "this_week", "later")
SNAPSHOT_FIGURES = ("dome_score", "open_incidents_critical_high", "kev_open", "open_findings", "sla_breached",
                    "sla_compliance_pct", "edr_coverage_pct", "attack_coverage_pct", "tools_unhealthy",
                    "automation_rate_pct", "pending_approvals", "open_insights_critical_high")


class PostureSnapshot(Base):
    """One row per day: the headline figures as they stood (``posture_snapshot`` job; idempotent per day)."""

    __tablename__ = "posture_snapshots"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    day: Mapped[str] = mapped_column(String(10), unique=True)      # YYYY-MM-DD (UTC)
    figures: Mapped[dict[str, Any]] = mapped_column(JSON)
    taken_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)


def _aware(dt: Any) -> datetime | None:
    if dt is None:
        return None
    if isinstance(dt, str):
        try:
            dt = datetime.fromisoformat(dt)
        except ValueError:
            return None
    if isinstance(dt, date) and not isinstance(dt, datetime):
        dt = datetime(dt.year, dt.month, dt.day, tzinfo=UTC)
    return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt


def _median_hours(pairs: list[tuple[Any, Any]]) -> float | None:
    hours = [(_aware(b) - _aware(a)).total_seconds() / 3600 for a, b in pairs if a is not None and b is not None
             and _aware(b) >= _aware(a)]
    return round(median(hours), 1) if hours else None


def _change(now: Any, before: Any, better: str) -> dict[str, Any]:
    """A figure against the period before: the direction, and whether that direction is good."""
    if not isinstance(now, (int, float)) or not isinstance(before, (int, float)):
        return {"previous": before, "delta": None, "trend": "none"}
    delta = round(now - before, 1)
    if delta == 0:
        trend = "flat"
    else:
        trend = "better" if (delta < 0) == (better == "lower") else "worse"
    return {"previous": before, "delta": delta, "trend": trend}


# ---------------------------------------------------------------------------------------------- the measures


def _measures(s: Session, registry: Any, vm: Any) -> dict[str, Any]:
    """Point-in-time figures (what a snapshot keeps): from the same functions as the screens they link to."""
    from soc_platform.api.dashboards import overview
    from soc_platform.connectors.health import HEALTHY_STATES, connector_freshness
    from soc_platform.core.models import Case
    from soc_platform.intelligence.attack_coverage import coverage
    from soc_platform.intelligence.dome_score import dome_score
    from soc_platform.intelligence.models import Insight

    dome = dome_score(s, registry)
    met = vm.metrics()
    cov = vm.coverage()
    machines = [m for m in cov["matrix"]]
    edr_gaps = len(cov["missing_edr"])
    att = coverage(s, registry.enabled_names())
    tools = [t for t in connector_freshness(s, registry) if t.get("enabled")]
    unhealthy = [t for t in tools if t.get("state") not in HEALTHY_STATES]
    ov = overview(s, frozenset({"*"}), days=30)
    open_inc = [c for c in s.execute(select(Case).where(Case.domain == "incident", Case.status != "closed")).scalars()]
    open_ins = [i for i in s.execute(select(Insight).where(Insight.status == "new")).scalars()
                if i.severity in ("critical", "high")]
    return {
        "dome": dome, "vm": met, "coverage": cov, "attack": att, "tools": tools, "unhealthy": unhealthy,
        "overview": ov, "open_incidents": open_inc, "open_insights": open_ins,
        "figures": {
            "dome_score": dome.get("score"),
            "open_incidents_critical_high": sum(1 for c in open_inc if c.severity in ("critical", "high")),
            "kev_open": met.get("kev_open", 0), "open_findings": met.get("open", 0),
            "sla_breached": met.get("sla_breached", 0),
            "sla_compliance_pct": (round(100 * (met["open"] - met["sla_breached"]) / met["open"], 1)
                                   if met.get("open") else None),
            "edr_coverage_pct": (round(100 * (len(machines) - edr_gaps) / len(machines), 1) if machines else None),
            "attack_coverage_pct": (att.get("summary") or {}).get("weighted_coverage_pct"),
            "tools_unhealthy": len(unhealthy),
            "automation_rate_pct": ov["actions"]["automation_rate_pct"],
            "pending_approvals": ov["actions"]["pending_approval"],
            "open_insights_critical_high": len(open_ins)}}


def snapshot(s: Session, registry: Any, vm: Any) -> dict[str, Any]:
    """Store today's headline figures (once per UTC day; a second run the same day updates that day's row)."""
    figures = _measures(s, registry, vm)["figures"]
    day = utcnow().date().isoformat()
    row = s.execute(select(PostureSnapshot).where(PostureSnapshot.day == day)).scalars().first()
    if row is None:
        s.add(PostureSnapshot(day=day, figures=figures))
    else:
        row.figures, row.taken_at = figures, utcnow()
    s.flush()
    return {"day": day, "figures": figures}


def _history(s: Session, since: datetime) -> list[dict[str, Any]]:
    rows = s.execute(select(PostureSnapshot).where(PostureSnapshot.day >= since.date().isoformat())
                     .order_by(PostureSnapshot.day)).scalars()
    return [{"day": r.day, **{k: (r.figures or {}).get(k) for k in SNAPSHOT_FIGURES}} for r in rows]


def _snapshot_on_or_before(s: Session, when: datetime) -> dict[str, Any] | None:
    row = s.execute(select(PostureSnapshot).where(PostureSnapshot.day <= when.date().isoformat())
                    .order_by(PostureSnapshot.day.desc()).limit(1)).scalars().first()
    return dict(row.figures or {}) if row else None


# ---------------------------------------------------------------------------------------------- the agenda


def _bucket(due: datetime, now: datetime, offset: timedelta) -> str:
    """Overdue / today / tomorrow / this week / later, in the viewer's own day (``offset`` from UTC)."""
    if due < now:
        return "overdue"
    d, today = (due + offset).date(), (now + offset).date()
    if d == today:
        return "today"
    if d == today + timedelta(days=1):
        return "tomorrow"
    if d <= today + timedelta(days=7):
        return "this_week"
    return "later"


def _agenda(s: Session, m: dict[str, Any], now: datetime, offset: timedelta) -> list[dict[str, Any]]:
    from soc_platform.core.models import ActionRequest, Case
    from soc_platform.domains.vulnerability.models import ConsolidatedFinding, VulnException, VulnIntel

    items: list[dict[str, Any]] = []

    def add(kind: str, title: str, why: str, due: datetime, severity: str, link: str, owner: str | None = None,
            ref: str = "") -> None:
        items.append({"kind": kind, "title": title, "why": why, "due": due.isoformat(), "severity": severity,
                      "link": link, "owner": owner or "unassigned", "ref": ref,
                      "bucket": _bucket(due, now, offset)})

    for c in sorted(m["open_incidents"], key=lambda c: c.id):
        if c.severity not in ("critical", "high", "medium"):
            continue
        due = _aware(c.created_at) + timedelta(hours=RESPONSE_TARGET_HOURS[c.severity])
        add("incident", f"Incident: {c.title}", f"open {c.severity} incident; response target "
            f"{RESPONSE_TARGET_HOURS[c.severity]} h from detection", due, c.severity, f"#/cases/{c.id}", c.assignee, c.id)
    pending = list(s.execute(select(ActionRequest).where(ActionRequest.status.in_(("pending_approval", "recommended"))))
                   .scalars())
    by_case: dict[str, list[Any]] = defaultdict(list)
    for a in pending:
        by_case[a.case_id or f"platform:{a.domain}"].append(a)
    cases = {c.id: c for c in s.execute(select(Case).where(Case.id.in_([k for k in by_case if k]))).scalars()}
    for key in sorted(by_case):
        acts = by_case[key]
        case = cases.get(key)
        sev = case.severity if case is not None else "medium"
        oldest = min(_aware(a.created_at) for a in acts)
        due = oldest + timedelta(hours=RESPONSE_TARGET_HOURS.get(sev, 72))
        what = case.title if case is not None else f"{key.split(':', 1)[-1]} actions"
        add("approval", f"{len(acts)} action(s) awaiting approval: {what}",
            "recommended containment or remediation waiting for a decision", due, sev,
            f"#/cases/{case.id}" if case is not None else "#/approvals", case.assignee if case else None, key)
    findings = list(s.execute(select(ConsolidatedFinding).where(
        ConsolidatedFinding.status.in_(("open", "reopened")), ConsolidatedFinding.priority_band.in_(("P1", "P2")))
    ).scalars())
    kev = {v.cve: v for v in s.execute(select(VulnIntel).where(VulnIntel.cve.in_(sorted({f.cve for f in findings}))))
           .scalars()}
    by_cve: dict[str, list[Any]] = defaultdict(list)
    for f in findings:
        by_cve[f.cve].append(f)
    for cve in sorted(by_cve):
        fs = by_cve[cve]
        dues = [_aware(f.sla_due) for f in fs if f.sla_due]
        intel = kev.get(cve)
        kev_due = _aware(intel.kev_due) if intel is not None and intel.kev and intel.kev_due else None
        if kev_due is not None:
            dues.append(kev_due)
        if not dues:
            continue
        band = min(f.priority_band for f in fs)
        why = (f"{band}; {'known exploited (CISA KEV), ' if intel is not None and intel.kev else ''}"
               f"{sum(1 for f in fs if f.internet_exposed)} internet-exposed; remediation SLA")
        teams = sorted({f.platform_team for f in fs if f.platform_team})
        add("vulnerability", f"{cve} on {len(fs)} asset(s)", why, min(dues), "critical" if band == "P1" else "high",
            f"#/vulnerabilities/{fs[0].id}" if len(fs) == 1 else "#/vulnerabilities", ", ".join(teams) or None, cve)
    horizon = now + timedelta(days=30)
    for ex in s.execute(select(VulnException).where(VulnException.status == "active")).scalars():
        exp = _aware(ex.expires_at)
        if exp is not None and exp <= horizon:
            add("risk_acceptance", "Risk acceptance ends", f"accepted by {ex.approver or 'a lead'}: renew it or fix "
                "the finding", exp, "medium", "#/vulnerabilities", ex.requested_by, ex.id)
    try:
        from soc_platform.core.tuning import TuningRule

        for r in s.execute(select(TuningRule).where(TuningRule.status == "active")).scalars():
            exp = _aware(r.expires_at)
            if exp is not None and exp <= horizon:
                add("tuning", "Tuning rule ends", "review whether it is still needed", exp, "low", "#/tuning", None,
                    str(r.id))
    except ImportError:
        pass
    for t in sorted(m["unhealthy"], key=lambda t: t["name"]):
        add("tool", f"{t.get('tool') or t['name']} is not delivering data", f"state: {t.get('state')}", now,
            "high", "#/integrations", None, t["name"])
    try:
        from soc_platform.llm.integration import IntegrationStore

        for c in IntegrationStore(s, _settings()).status()["credentials"]:
            exp = _aware(c.get("expires_at"))
            if c["set"] and exp is not None and exp <= horizon:
                add("ai_credential", f"AI provider {c['label'].lower()} expires",
                    "AI text falls back to the platform's own wording once it has", exp, "medium", "#/ai-usage",
                    c.get("set_by"), c["name"])
    except ValueError:
        pass
    for i in sorted(m["open_insights"], key=lambda i: (-i.score, i.id))[:10]:
        due = _aware(i.first_seen) + timedelta(hours=RESPONSE_TARGET_HOURS.get(i.severity, 72))
        add("finding", i.title, "correlated finding across tools", due, i.severity, "#/intelligence", None, i.id)
    items.sort(key=lambda x: (BUCKETS.index(x["bucket"]), -SEV_RANK.get(x["severity"], 0), x["due"], x["ref"]))
    return items


def _settings() -> Any:
    from soc_platform.config import get_settings

    return get_settings()


# ---------------------------------------------------------------------------------------------- the view


def _in(dt: Any, a: datetime, b: datetime) -> bool:
    d = _aware(dt)
    return d is not None and a <= d < b


def _daily(series: dict[str, Counter], since: datetime, days: int, keys: tuple[str, ...]) -> list[dict[str, Any]]:
    out = []
    for i in range(days):
        d = (since + timedelta(days=i + 1)).date().isoformat()
        out.append({"date": d, **{k: series[d].get(k, 0) for k in keys}})
    return out


def view(s: Session, registry: Any, vm: Any, *, days: int = 30, tz_offset_minutes: int = 0) -> dict[str, Any]:
    from soc_platform.core.models import AuditRecord, Case
    from soc_platform.domains.phishing.models import Submission
    from soc_platform.domains.vulnerability.models import ConsolidatedFinding
    from soc_platform.intelligence.risk import RiskEngine

    if days not in PERIODS:
        raise ValueError(f"the period is one of {', '.join(map(str, PERIODS))} days")
    if not -840 <= tz_offset_minutes <= 840:
        raise ValueError("tz_offset_minutes is between -840 and 840")
    now = utcnow()
    since, prev = now - timedelta(days=days), now - timedelta(days=2 * days)
    offset = timedelta(minutes=tz_offset_minutes)
    m = _measures(s, registry, vm)
    fig = m["figures"]
    # only what is open or inside the two periods: years of closed history are never loaded
    cases = list(s.execute(select(Case).where(or_(Case.status != "closed", Case.created_at >= prev,
                                                  Case.closed_at >= prev))).scalars())

    # -------- threats and incidents
    inc = [c for c in cases if c.domain == "incident"]

    def inc_period(a: datetime, b: datetime) -> dict[str, Any]:
        opened = [c for c in inc if _in(c.created_at, a, b)]
        closed = [c for c in inc if _in(c.closed_at, a, b)]
        return {"opened": len(opened), "closed": len(closed),
                "critical_high_opened": sum(1 for c in opened if c.severity in ("critical", "high")),
                "mttr_hours": _median_hours([(c.created_at, c.closed_at) for c in closed])}

    inc_now, inc_prev = inc_period(since, now), inc_period(prev, since)
    techniques: Counter = Counter()
    for c in inc:
        if _in(c.created_at, since, now):
            for t in (c.assessment or {}).get("mitre") or []:
                if isinstance(t, dict) and t.get("technique"):
                    techniques[str(t["technique"])] += 1
    open_inc = m["open_incidents"]
    incidents = {
        "open": len(open_inc), "open_by_severity": dict(Counter(c.severity for c in open_inc)),
        "open_unassigned": sum(1 for c in open_inc if not c.assignee),
        "period": inc_now, "previous": inc_prev,
        "techniques": [{"technique": t, "cases": n} for t, n in sorted(techniques.items(), key=lambda x: (-x[1], x[0]))[:8]],
        "most_at_risk": [{"name": p.name, "kind": p.kind, "score": p.score, "band": p.band, "link": f"#/entity/{p.entity_id}"}
                         for p in RiskEngine(s).top(None, 5)]}

    # -------- vulnerabilities and exposure
    vmm = m["vm"]
    allf = list(s.execute(select(ConsolidatedFinding).where(or_(ConsolidatedFinding.first_seen >= prev,
                                                               ConsolidatedFinding.closed_at >= prev))).scalars())

    def vm_period(a: datetime, b: datetime) -> dict[str, Any]:
        fixed = [f for f in allf if _in(f.closed_at, a, b)]
        return {"opened": sum(1 for f in allf if _in(f.first_seen, a, b)), "fixed": len(fixed),
                "fixed_within_sla": sum(1 for f in fixed if f.sla_due and _aware(f.closed_at) <= _aware(f.sla_due)),
                "mean_days_to_fix": (round(sum((_aware(f.closed_at) - _aware(f.first_seen)).total_seconds() / 86400
                                               for f in fixed) / len(fixed), 1) if fixed else None)}

    burn: dict[str, Counter] = defaultdict(Counter)
    for f in allf:
        if _in(f.first_seen, since, now):
            burn[_aware(f.first_seen).date().isoformat()]["opened"] += 1
        if _in(f.closed_at, since, now):
            burn[_aware(f.closed_at).date().isoformat()]["fixed"] += 1
    vulnerabilities = {
        "open": vmm.get("open", 0), "by_priority": vmm.get("by_priority", {}), "kev_open": vmm.get("kev_open", 0),
        "internet_exposed_open": vmm.get("internet_exposed_open", 0), "sla_breached": vmm.get("sla_breached", 0),
        "sla_compliance_pct": fig["sla_compliance_pct"], "per_team": vmm.get("per_team", {}),
        "period": vm_period(since, now), "previous": vm_period(prev, since),
        "trend": _daily(burn, since, days, ("opened", "fixed"))}

    # -------- people and phishing
    subs = list(s.execute(select(Submission).where(Submission.received_at >= prev)).scalars())
    wanted = sorted({x.case_id for x in subs if x.case_id})
    ph_cases = {c.id: c for c in s.execute(select(Case).where(Case.id.in_(wanted))).scalars()} if wanted else {}

    def ph_period(a: datetime, b: datetime) -> dict[str, Any]:
        got = [x for x in subs if _in(x.received_at, a, b)]
        clickers: Counter = Counter()
        for x in got:
            c = ph_cases.get(x.case_id or "")
            for user, imp in sorted(((c.assessment or {}).get("user_impact") or {}).get("per_user", {}).items()) if c else []:
                if isinstance(imp, dict) and imp.get("clicked"):
                    clickers[user] += 1
        verdicts = Counter(x.verdict or "pending" for x in got)
        harmful = verdicts.get("malicious", 0) + verdicts.get("suspicious", 0)
        return {"reported": len(got), "verdicts": dict(sorted(verdicts.items())),
                "harmful_share_pct": round(100 * harmful / len(got), 1) if got else None,
                "auto_closed": sum(1 for x in got if x.auto_closed), "people_who_clicked": len(clickers),
                "repeat_clickers": sorted(u for u, n in clickers.items() if n > 1),
                "reporters": len({x.reporter for x in got if x.reporter})}

    phishing = {"period": ph_period(since, now), "previous": ph_period(prev, since)}

    # -------- coverage and resilience
    att = m["attack"].get("summary") or {}
    coverage = {"edr_coverage_pct": fig["edr_coverage_pct"], "assets": m["coverage"]["assets"],
                "missing_edr": sorted(m["coverage"]["missing_edr"]), "not_in_cmdb": len(m["coverage"]["not_in_cmdb"]),
                "attack_coverage_pct": att.get("weighted_coverage_pct"),
                "priority_blind_spots": att.get("priority_blind_spots", 0),
                "single_source_priority": att.get("single_source_priority", 0),
                "tools": {"enabled": len(m["tools"]), "unhealthy": [t["name"] for t in m["unhealthy"]]}}

    # -------- operations
    ov = m["overview"]
    open_cases = [c for c in cases if c.status != "closed"]
    operations = {"automation_rate_pct": ov["actions"]["automation_rate_pct"],
                  "pending_approvals": ov["actions"]["pending_approval"],
                  "open_cases": len(open_cases), "unassigned_cases": sum(1 for c in open_cases if not c.assignee),
                  "workload": [{"analyst": a, "open_cases": n} for a, n in
                               sorted(Counter(c.assignee for c in open_cases if c.assignee).items(),
                                      key=lambda x: (-x[1], x[0]))[:10]]}

    # -------- governance
    events = Counter(e for (e,) in s.execute(select(AuditRecord.event_type).where(AuditRecord.ts >= since)).all())

    def count(*prefixes: str) -> int:
        return sum(n for e, n in events.items() if e.startswith(prefixes))

    governance = {"policy_changes": count("policy.", "dome_score.", "tuning.", "llm_policy."),
                  "access_changes": count("access.", "auth.role", "api_key."),
                  "break_glass_uses": count("auth.break_glass"),
                  "actions_approved": count("action.approved"), "actions_rejected": count("action.rejected"),
                  "audit_events": sum(events.values())}

    # -------- third parties and AI
    suppliers: list[dict[str, Any]] = []
    try:
        from soc_platform.domains.phishing.supplier import SupplierMonitor

        sup = SupplierMonitor(s).assess(days=days)
        for name, x in sorted((sup.get("suppliers") or {}).items()):
            hits = [f for f in x.get("findings") or [] if isinstance(f, dict)]
            if hits:
                suppliers.append({"supplier": name, "criticality": x.get("criticality"), "findings": len(hits),
                                  "worst": max((f.get("severity") for f in hits), key=lambda v: SEV_RANK.get(v, 0))})
    except (KeyError, ValueError):
        suppliers = []
    ai = None
    from soc_platform.llm.integration import configured

    if configured(s, _settings()):
        from soc_platform.llm.gateway import LLMGateway

        b = LLMGateway(s, _settings()).budget_status()
        ai = {"used_tokens": b["used"], "monthly_budget": b["budget"], "fraction": b["fraction"]}

    # -------- headline figures against the period before
    before = _snapshot_on_or_before(s, since) or {}
    headline = [
        {"key": "dome_score", "label": "Dome Score", "value": fig["dome_score"], "unit": "/100", "better": "higher",
         "link": "#/dome-score", **_change(fig["dome_score"], before.get("dome_score"), "higher")},
        {"key": "open_incidents_critical_high", "label": "Open critical / high incidents",
         "value": fig["open_incidents_critical_high"], "better": "lower", "link": "#/cases",
         **_change(fig["open_incidents_critical_high"], before.get("open_incidents_critical_high"), "lower")},
        {"key": "mttr_hours", "label": "Median time to resolve an incident", "value": inc_now["mttr_hours"],
         "unit": "h", "better": "lower", "link": "#/cases",
         **_change(inc_now["mttr_hours"], inc_prev["mttr_hours"], "lower")},
        {"key": "kev_open", "label": "Known-exploited vulnerabilities open", "value": fig["kev_open"],
         "better": "lower", "link": "#/vulnerabilities", **_change(fig["kev_open"], before.get("kev_open"), "lower")},
        {"key": "sla_compliance_pct", "label": "Vulnerabilities within SLA", "value": fig["sla_compliance_pct"],
         "unit": "%", "better": "higher", "link": "#/vulnerabilities",
         **_change(fig["sla_compliance_pct"], before.get("sla_compliance_pct"), "higher")},
        {"key": "people_who_clicked", "label": "People who clicked a reported phish",
         "value": phishing["period"]["people_who_clicked"], "better": "lower", "link": "#/phishing",
         **_change(phishing["period"]["people_who_clicked"], phishing["previous"]["people_who_clicked"], "lower")},
        {"key": "edr_coverage_pct", "label": "Machines with EDR", "value": fig["edr_coverage_pct"], "unit": "%",
         "better": "higher", "link": "#/coverage", **_change(fig["edr_coverage_pct"], before.get("edr_coverage_pct"),
                                                              "higher")},
        {"key": "automation_rate_pct", "label": "Actions run under policy", "value": fig["automation_rate_pct"],
         "unit": "%", "better": "higher", "link": "#/approvals",
         **_change(fig["automation_rate_pct"], before.get("automation_rate_pct"), "higher")},
    ]
    agenda = _agenda(s, m, now, offset)
    history = _history(s, since)
    first = s.execute(select(PostureSnapshot.day).order_by(PostureSnapshot.day).limit(1)).scalars().first()
    return {
        "generated_at": now.isoformat(), "period_days": days, "periods": list(PERIODS),
        "since": since.isoformat(), "tz_offset_minutes": tz_offset_minutes,
        "response_targets_hours": RESPONSE_TARGET_HOURS,
        "posture": {"score": m["dome"].get("score"), "band": m["dome"].get("band"),
                    "pillars": [{k: p.get(k) for k in ("key", "name", "score", "detail", "link", "counted")}
                                for p in m["dome"].get("pillars") or []]},
        "headline": headline,
        "agenda": {"items": agenda, "counts": {b: sum(1 for x in agenda if x["bucket"] == b) for b in BUCKETS}},
        "incidents": incidents, "vulnerabilities": vulnerabilities, "phishing": phishing, "coverage": coverage,
        "operations": operations, "governance": governance, "suppliers": suppliers, "ai": ai,
        "history": {"snapshots": history, "since": first,
                    "note": (None if first and first <= since.date().isoformat() else
                             f"posture history starts on {first}" if first else
                             "posture history starts with the first daily snapshot")},
    }


def deterministic_brief(v: dict[str, Any], ev: list[dict[str, Any]]) -> dict[str, Any]:
    """The brief the platform writes itself (no model, a model over its limit, or an answer the evidence check
    rejected): plain sentences from the same figures, each statement citing the figure it rests on."""
    by_key = {h["key"]: h for h in v["headline"]}
    cite = {e["claim"].split(":", 1)[0]: e["id"] for e in ev}
    claims = []
    score = by_key.get("dome_score", {})
    if score.get("value") is not None:
        claims.append({"text": f"Posture is {score['value']}/100 ({v['posture'].get('band') or 'no band'}).",
                       "kind": "fact", "evidence_ids": [cite.get("Dome Score", "K1")]})
    worse = [h["label"].lower() for h in v["headline"] if h.get("trend") == "worse"]
    better = [h["label"].lower() for h in v["headline"] if h.get("trend") == "better"]
    if worse or better:
        ids = [cite[h["label"]] for h in v["headline"] if h.get("trend") in ("worse", "better") and h["label"] in cite]
        text = "Against the period before, " + "; ".join(
            x for x in (f"worse: {', '.join(worse)}" if worse else "", f"better: {', '.join(better)}" if better else "") if x)
        claims.append({"text": text + ".", "kind": "fact", "evidence_ids": ids[:6] or [ev[0]["id"]]})
    c = v["agenda"]["counts"]
    agenda_id = next((e["id"] for e in ev if e["claim"].startswith("Agenda:")), ev[-1]["id"] if ev else "K1")
    claims.append({"text": f"{c['overdue']} item(s) are overdue and {c['today']} are due today.", "kind": "fact",
                   "evidence_ids": [agenda_id]})
    first = [e for e in ev if e["claim"].startswith(("overdue:", "today:"))][:3]
    for e in first:
        claims.append({"text": "Needs a decision - " + e["claim"].split(": ", 1)[-1], "kind": "fact",
                       "evidence_ids": [e["id"]]})
    summary = " ".join(x["text"] for x in claims[:3])
    return {"summary": summary, "claims": claims, "grounded": True, "insufficient_evidence": False,
            "source": "deterministic"}


def evidence(v: dict[str, Any]) -> list[dict[str, Any]]:
    """The view's figures as cited evidence for the optional written brief (the model only narrates them)."""
    out: list[dict[str, Any]] = []
    for h in v["headline"]:
        if h["value"] is None:
            continue
        prev = "" if h.get("previous") is None else f" (previous period {h['previous']}{h.get('unit', '')})"
        out.append({"id": f"K{len(out) + 1}", "claim": f"{h['label']}: {h['value']}{h.get('unit', '')}{prev}",
                    "source": "platform"})
    counts = v["agenda"]["counts"]
    out.append({"id": f"K{len(out) + 1}", "source": "platform",
                "claim": f"Agenda: {counts['overdue']} overdue, {counts['today']} due today, {counts['tomorrow']} due "
                         f"tomorrow, {counts['this_week']} due this week"})
    for x in [i for i in v["agenda"]["items"] if i["bucket"] in ("overdue", "today")][:6]:
        out.append({"id": f"K{len(out) + 1}", "source": "platform",
                    "claim": f"{x['bucket'].replace('_', ' ')}: {x['title']} ({x['severity']}; {x['why']})"})
    return out
