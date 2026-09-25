"""Platform self-check: the platform continuously proves its own numbers agree and its records are intact.

Every figure that appears on more than one surface (dashboard, approvals badge, analyst answers, briefs, reports) is
recomputed through each independent code path and compared; every stored reference is resolved; nothing that must
be unique is duplicated; the audit chain is verified. Runs as a scheduled job (``self_check``) that raises a
``platform_integrity`` finding on failure and resolves it when the platform is consistent again, and on demand via
``GET /api/v1/admin/self-check``.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from soc_platform.core.models import ActionRequest, Case, CaseEntity, Entity, Evidence, utcnow

ALL = frozenset({"*"})


def run_self_check(s: Session) -> dict[str, Any]:
    from soc_platform.api.dashboards import overview
    from soc_platform.core.audit import AuditLog
    from soc_platform.domains.phishing.models import Submission
    from soc_platform.domains.vulnerability.models import ConsolidatedFinding, RemediationCampaign
    from soc_platform.intelligence.analyst import IntelligenceAnalyst, _total
    from soc_platform.intelligence.models import Insight
    from soc_platform.reporting.builder import Ctx, src_overview

    checks: list[dict[str, Any]] = []

    def agree(name: str, **values: Any) -> None:
        ok = len({repr(v) for v in values.values()}) == 1
        checks.append({"check": name, "ok": ok, "detail": values})

    def none_of(name: str, problems: list[str]) -> None:
        checks.append({"check": name, "ok": not problems, "detail": {"count": len(problems), "examples": problems[:5]}})

    # ---- the same figure through every code path
    ov = overview(s, ALL)
    analyst = IntelligenceAnalyst(s, None)
    rep = dict(src_overview(Ctx(s, None, domains=ALL))["facts"])
    pending = s.execute(select(func.count()).select_from(ActionRequest)
                        .where(ActionRequest.status.in_(("recommended", "pending_approval")))).scalar()
    agree("actions awaiting approval", dashboard=ov["actions"]["pending_approval"], database=pending,
          analyst=_total(analyst._pending()), report=int(rep["Actions awaiting approval"]))
    open_cases = s.execute(select(func.count()).select_from(Case).where(Case.status != "closed")).scalar()
    agree("open cases", dashboard=ov["cases"]["open"], database=open_cases, report=int(rep["Open cases"]))
    open_ins = s.execute(select(func.count()).select_from(Insight).where(Insight.status.in_(("new", "acknowledged")))).scalar()
    agree("open correlated findings", dashboard=ov["insights"]["open"], database=open_ins,
          analyst=_total(analyst._list_insights()), report=int(rep["Open correlated insights"]))
    if ov.get("vulnerability"):
        open_f = s.execute(select(func.count()).select_from(ConsolidatedFinding)
                           .where(ConsolidatedFinding.status.in_(("open", "reopened")))).scalar()
        agree("open vulnerability findings", dashboard=ov["vulnerability"]["open_findings"], database=open_f)

    # ---- every stored reference resolves
    case_ids = set(s.execute(select(Case.id)).scalars())
    entity_ids = set(s.execute(select(Entity.id)).scalars())
    campaign_ids = set(s.execute(select(RemediationCampaign.id)).scalars())
    none_of("case links resolve", [f"{c}->{e}" for c, e in s.execute(select(CaseEntity.case_id, CaseEntity.entity_id))
                                   if c not in case_ids or e not in entity_ids])
    none_of("evidence belongs to a case", [e for e, c in s.execute(select(Evidence.id, Evidence.case_id)) if c not in case_ids])
    none_of("actions belong to a case or campaign",
            [a.id for a in s.execute(select(ActionRequest)).scalars()
             if (a.case_id and a.case_id not in case_ids | campaign_ids)
             or any(x not in case_ids for x in (a.result or {}).get("linked_cases", []))])
    none_of("findings reference existing campaigns",
            [f for f, c in s.execute(select(ConsolidatedFinding.id, ConsolidatedFinding.campaign_id)) if c and c not in campaign_ids])
    none_of("insights reference existing users/hosts",
            [i.id for i in s.execute(select(Insight)).scalars() if any(e not in entity_ids for e in i.entity_ids or [])])
    bad_cites = []
    for c in s.execute(select(Case)).scalars():
        idx = set((c.assessment or {}).get("evidence_index") or {})
        bad_cites += [c.id for cl in (c.assessment or {}).get("claims") or [] if idx and not set(cl.get("evidence_ids", [])) <= idx]
    none_of("every cited evidence id exists", bad_cites)

    # ---- nothing that must be unique is duplicated (re-runs must not create second copies)
    per_sub = Counter(str((c.attributes or {}).get("submission_id")) for c in s.execute(select(Case).where(Case.domain == "phishing")).scalars()
                      if (c.attributes or {}).get("submission_id"))
    none_of("one case per reported email", [k for k, n in per_sub.items() if n > 1])
    subs_with_case = {x for x in s.execute(select(Submission.case_id)).scalars() if x}
    none_of("reported emails point at existing cases", sorted(subs_with_case - case_ids))
    active = Counter(c.cve for c in s.execute(select(RemediationCampaign).where(RemediationCampaign.status != "closed")).scalars())
    overlapping = []
    for cve, n in active.items():
        if n > 1:
            owners = Counter(f.campaign_id for f in s.execute(select(ConsolidatedFinding).where(ConsolidatedFinding.cve == cve)).scalars())
            if sum(1 for cid, k in owners.items() if cid) < n:      # a campaign with no findings of its own = duplicate
                overlapping.append(cve)
    none_of("no duplicate active remediation campaigns", overlapping)

    # ---- the audit chain is intact
    v = AuditLog(s).verify()
    checks.append({"check": "audit chain verifies", "ok": bool(v.get("ok")), "detail": {k: v.get(k) for k in ("records", "first_bad_seq")}})

    return {"ok": all(c["ok"] for c in checks), "passed": sum(c["ok"] for c in checks), "total": len(checks),
            "generated_at": utcnow().isoformat(), "checks": checks}


def raise_or_resolve(s: Session, result: dict[str, Any]) -> None:
    """Keep one ``platform_integrity`` finding in step with the latest self-check."""
    from soc_platform.intelligence.correlation import _key
    from soc_platform.intelligence.models import Insight

    key = _key("platform", "integrity")
    cur = s.execute(select(Insight).where(Insight.dedupe_key == key)).scalars().first()
    failing = [c for c in result["checks"] if not c["ok"]]
    if not failing:
        if cur is not None and cur.status in {"new", "acknowledged"}:
            cur.status, cur.decided_by = "resolved", "system:self_check"
        return
    evidence = [{"ref": c["check"], "signal": "self_check_failed", "source": "platform", "summary": f"{c['check']}: {c['detail']}"[:400]}
                for c in failing]
    title = f"Platform self-check: {len(failing)} of {result['total']} checks failing"
    if cur is None:
        s.add(Insight(rule="platform_integrity", dedupe_key=key, severity="high", score=70.0, title=title, entity_ids=[], domains=[],
                      evidence=evidence, next_steps=["Open GET /api/v1/admin/self-check for the failing checks and their values",
                                                     "Investigate the data source or job that diverged, then re-run the check"],
                      requirement_refs=["NFR-13", "R02"]))
    else:
        cur.title, cur.evidence, cur.status, cur.last_seen = title, evidence, "new", utcnow()
