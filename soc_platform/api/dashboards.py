"""Dashboard read models (U07, U09, U11, U17, NFR-13): everything a SOC lead needs on one screen.

All figures are computed from the database; every tile links back to the records it counts so any
number shown to a client can be explained and drilled into.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from statistics import median
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from soc_platform.core.context_store import ContextStore
from soc_platform.core.entity_resolution import EntityResolver
from soc_platform.core.models import (ActionRequest, Case, CaseEntity, ConnectorCheckpoint, Entity, UnresolvedItem,
                                      utcnow)

# expected freshness per stream kind (NFR-13): alert streams must be near-real-time, inventories daily
FRESHNESS_HOURS = {"alerts": 1, "incidents": 1, "detections": 1, "risk_detections": 1, "email_alerts": 1,
                   "incidents_canary": 1, "secret_audits": 4, "elevation_events": 4, "vulnerabilities": 26,
                   "findings": 26, "issues": 26}
DEFAULT_FRESHNESS_HOURS = 26


def _aware(dt: datetime | None) -> datetime | None:
    return dt.replace(tzinfo=timezone.utc) if dt is not None and dt.tzinfo is None else dt


def overview(s: Session, domains: frozenset[str], *, days: int = 14) -> dict[str, Any]:
    now = utcnow()
    since = now - timedelta(days=days)
    q = select(Case)
    if "*" not in domains:
        q = q.where(Case.domain.in_(sorted(domains)))
    cases = list(s.execute(q).scalars())
    open_cases = [c for c in cases if c.status != "closed"]
    trend: dict[str, Counter] = defaultdict(Counter)
    for c in cases:
        ca = _aware(c.created_at)
        if ca >= since:
            trend[ca.date().isoformat()][c.domain] += 1
    series = [{"date": (since + timedelta(days=i + 1)).date().isoformat(),
               **{d: trend[(since + timedelta(days=i + 1)).date().isoformat()].get(d, 0)
                  for d in ("phishing", "incident", "vulnerability")}} for i in range(days)]
    ttc = [(_aware(c.closed_at) - _aware(c.created_at)).total_seconds() / 3600 for c in cases if c.closed_at]
    acts = list(s.execute(select(ActionRequest).where(ActionRequest.created_at >= since)).scalars())
    autonomous = sum(1 for a in acts if str(a.approver or "").startswith("policy:"))
    from soc_platform.intelligence.models import Insight

    ins = list(s.execute(select(Insight).where(Insight.status.in_(("new", "acknowledged")))).scalars())
    if "*" not in domains:
        ins = [i for i in ins if not i.domains or set(i.domains) & set(domains)]
    vm: dict[str, Any] = {}
    if "*" in domains or "vulnerability" in domains:
        from soc_platform.domains.vulnerability.models import CloudMisconfiguration, ConsolidatedFinding

        fs = list(s.execute(select(ConsolidatedFinding).where(ConsolidatedFinding.status.in_(("open", "reopened")))).scalars())
        vm = {"open_findings": len(fs), "by_band": dict(Counter(f.priority_band for f in fs)),
              "sla_breached": sum(1 for f in fs if f.sla_due and _aware(f.sla_due) < now),
              "internet_exposed": sum(1 for f in fs if f.internet_exposed),
              "open_misconfigurations": s.query(CloudMisconfiguration).filter(
                  CloudMisconfiguration.status.in_(("open", "routed", "reopened", "pending_validation"))).count()}
    return {
        "generated_at": now.isoformat(), "window_days": days,
        "performance": performance(s, cases),
        "cases": {"open": len(open_cases), "open_by_domain": dict(Counter(c.domain for c in open_cases)),
                  "open_by_severity": dict(Counter(c.severity for c in open_cases)),
                  "awaiting_approval": sum(1 for c in open_cases if c.status == "awaiting_approval"),
                  "median_hours_to_close": round(median(ttc), 1) if ttc else None,
                  "verdicts": dict(Counter(c.verdict or "undetermined" for c in cases if _aware(c.created_at) >= since))},
        "trend": series,
        "actions": {"in_window": len(acts), "by_status": dict(Counter(a.status for a in acts)),
                    "pending_approval": sum(1 for a in acts if a.status in {"pending_approval", "recommended"}),
                    "autonomous": autonomous,
                    "automation_rate_pct": round(100 * autonomous / len(acts), 1) if acts else 0.0},
        "insights": {"open": len(ins), "by_severity": dict(Counter(i.severity for i in ins)),
                     "top": [{"id": i.id, "title": i.title, "severity": i.severity, "rule": i.rule}
                             for i in sorted(ins, key=lambda x: -x.score)[:5]]},
        "vulnerability": vm,
        "context": {"entities": dict(s.execute(select(Entity.kind, func.count()).group_by(Entity.kind)).all()),
                    "unresolved_queue": s.query(UnresolvedItem).filter(UnresolvedItem.status == "open").count(),
                    "asset_match_rate": EntityResolver(s).match_rate("asset"),
                    "identity_match_rate": EntityResolver(s).match_rate("identity")},
    }


def _pct(xs: list[float], q: float) -> float | None:
    if not xs:
        return None
    xs = sorted(xs)
    return round(xs[min(len(xs) - 1, int(round(q * (len(xs) - 1))))], 1)


def performance(s: Session, cases: list[Case]) -> dict[str, Any]:
    """Measured enrichment latency (NFR-06, IM-T08): per domain per investigation, and per tool per lookup."""
    from soc_platform.core.models import Evidence

    per_dom: dict[str, list[float]] = defaultdict(list)
    for c in cases:
        ms = (c.completeness or {}).get("elapsed_ms")
        if isinstance(ms, (int, float)):
            per_dom[c.domain].append(float(ms))
    per_tool: dict[str, list[float]] = defaultdict(list)
    ids = [c.id for c in cases][-500:]
    if ids:
        for ev in s.execute(select(Evidence).where(Evidence.case_id.in_(ids))).scalars():
            ms = (ev.data or {}).get("elapsed_ms") if isinstance(ev.data, dict) else None
            if isinstance(ms, (int, float)):
                per_tool[ev.source_tool or "unknown"].append(float(ms))
    return {"investigation_enrichment_ms": {d: {"n": len(v), "median": _pct(v, .5), "p95": _pct(v, .95)}
                                            for d, v in per_dom.items()},
            "lookup_ms_by_tool": {t: {"n": len(v), "median": _pct(v, .5), "p95": _pct(v, .95)}
                                  for t, v in sorted(per_tool.items())}}


def connector_freshness(s: Session, registry: Any) -> list[dict[str, Any]]:
    now = utcnow()
    cps = defaultdict(list)
    for c in s.execute(select(ConnectorCheckpoint)).scalars():
        cps[c.connector].append(c)
    out = []
    for row in registry.status():
        name = row["name"]
        streams = []
        for c in cps.get(name, []):
            limit = FRESHNESS_HOURS.get(c.stream, DEFAULT_FRESHNESS_HOURS)
            age = (now - _aware(c.last_success_at)).total_seconds() / 3600 if c.last_success_at else None
            streams.append({"stream": c.stream, "last_success_at": c.last_success_at.isoformat() if c.last_success_at else None,
                            "age_hours": round(age, 2) if age is not None else None, "expected_within_hours": limit,
                            "fresh": age is not None and age <= limit, "last_error": c.last_error,
                            "ingested": c.ingested_count, "failed": c.failed_count})
        state = ("disabled" if not row["enabled"] else "misconfigured" if row.get("config_problems") else
                 "never_synced" if row.get("streams") and not streams else
                 "error" if any(x["last_error"] for x in streams) else
                 "stale" if any(not x["fresh"] for x in streams) else "healthy")
        out.append({"name": name, "tool": row.get("tool"), "category": row.get("category"), "mode": row.get("mode"),
                    "enabled": row["enabled"], "state": state, "config_problems": row.get("config_problems", []),
                    "streams": streams})
    return out


def entity_360(s: Session, eid: str) -> dict[str, Any] | None:
    """Everything known about one user or host across every tool (U07)."""
    e = s.get(Entity, eid)
    if e is None:
        return None
    st = ContextStore(s)
    from soc_platform.intelligence.models import Insight
    from soc_platform.intelligence.risk import RiskEngine

    prof = RiskEngine(s).profile(eid)
    events = [o for _, o in st.neighbors(eid) if o.kind not in {"asset", "identity", "indicator"}]
    by_tool = Counter((o.attributes or {}).get("tool") or "unknown" for o in events)
    related = defaultdict(list)
    for r, o in st.neighbors(eid):
        if o.kind in {"asset", "identity", "indicator"}:
            related[o.kind].append({"id": o.id, "name": o.display_name, "rel": r.rel_type})
    for ev in events:  # second hop: the users/hosts that share events with this entity
        for r, o in st.neighbors(ev.id):
            if o.id != eid and o.kind in {"asset", "identity"} and all(x["id"] != o.id for x in related[o.kind]):
                related[o.kind].append({"id": o.id, "name": o.display_name, "rel": f"via {ev.kind}"})
    case_ids = [ce.case_id for ce in s.execute(select(CaseEntity).where(CaseEntity.entity_id == eid)).scalars()]
    cases = [{"id": c.id, "domain": c.domain, "title": c.title, "severity": c.severity, "status": c.status,
              "verdict": c.verdict} for c in (s.get(Case, i) for i in dict.fromkeys(case_ids)) if c]
    ins = [{"id": i.id, "title": i.title, "severity": i.severity, "rule": i.rule}
           for i in s.execute(select(Insight).where(Insight.status != "dismissed")).scalars() if eid in (i.entity_ids or [])]
    vulns: list[dict[str, Any]] = []
    if e.kind == "asset":
        from soc_platform.domains.vulnerability.models import ConsolidatedFinding

        vulns = [{"cve": f.cve, "band": f.priority_band, "status": f.status, "sla_due": f.sla_due.isoformat() if f.sla_due else None,
                  "sources": sorted(f.sources or {})} for f in s.execute(select(ConsolidatedFinding).where(
                      ConsolidatedFinding.asset_id == eid)).scalars()]
    attrs = e.attributes or {}
    return {"id": e.id, "kind": e.kind, "name": e.display_name, "keys": st.keys_of(eid),
            "seen_by": sorted((attrs.get("by_tool") or {}).keys()), "attributes": {k: v for k, v in attrs.items() if k != "by_tool"},
            "per_tool": attrs.get("by_tool") or {},
            "risk": ({"score": prof.score, "band": prof.band, "dimensions": prof.dimensions,
                      "factors": [f.__dict__ for f in sorted(prof.factors, key=lambda f: -f.decayed)[:15]]} if prof else None),
            "activity_by_tool": dict(by_tool), "related": dict(related), "cases": cases, "insights": ins,
            "vulnerabilities": vulns, "timeline": st.timeline([eid])[:100]}


def prometheus(s: Session, registry: Any) -> str:
    """Prometheus text exposition (scrape with a read-only service-account key)."""
    lines: list[str] = []

    def g(name: str, help_: str, samples: list[tuple[dict[str, str], float]]) -> None:
        lines.append(f"# HELP {name} {help_}")
        lines.append(f"# TYPE {name} gauge")
        for labels, v in samples:
            lab = ",".join(f'{k}="{str(val).replace(chr(34), "")}"' for k, val in labels.items())
            lines.append(f"{name}{{{lab}}} {v}" if lab else f"{name} {v}")

    open_by = Counter((c.domain, c.severity) for c in s.execute(select(Case).where(Case.status != "closed")).scalars())
    g("soc_open_cases", "Open cases by domain and severity", [({"domain": d, "severity": sv}, n) for (d, sv), n in open_by.items()])
    acts = Counter(a.status for a in s.execute(select(ActionRequest)).scalars())
    g("soc_actions", "Action requests by status", [({"status": k}, v) for k, v in acts.items()])
    from soc_platform.intelligence.models import Insight

    ins = Counter(i.severity for i in s.execute(select(Insight).where(Insight.status.in_(("new", "acknowledged")))).scalars())
    g("soc_open_insights", "Open correlation insights by severity", [({"severity": k}, v) for k, v in ins.items()])
    g("soc_unresolved_entities", "Records awaiting analyst entity resolution",
      [({}, s.query(UnresolvedItem).filter(UnresolvedItem.status == "open").count())])
    now = utcnow()
    fr = []
    for c in s.execute(select(ConnectorCheckpoint)).scalars():
        if c.last_success_at:
            fr.append(({"connector": c.connector, "stream": c.stream}, round((now - _aware(c.last_success_at)).total_seconds(), 1)))
    g("soc_connector_last_success_age_seconds", "Seconds since the last successful sync per stream", fr)
    from soc_platform.core.access import kill_switch_on
    from soc_platform.config import get_settings

    g("soc_kill_switch", "1 when all automated actions are halted", [({}, 1.0 if kill_switch_on(s, get_settings()) else 0.0)])
    g("soc_connectors_enabled", "Enabled connectors", [({}, len(registry.enabled_names()))])
    return "\n".join(lines) + "\n"
