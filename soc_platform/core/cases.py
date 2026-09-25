"""Cases: the consolidated investigation record, recommendations and analyst decisions.

Serves IM-F05/F07/F08/F12/F15/F16 and PH-F09/F16, and the shadow-mode measurement
required by PH-T08 / NFR-15 (agreement between system verdicts and analyst dispositions).
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from soc_platform.core.actions import ActionRegistry, ActionService
from soc_platform.core.audit import AuditLog
from soc_platform.core.auth import Perm, Principal, agent_principal
from soc_platform.core.context_store import ContextStore
from soc_platform.core.models import ActionRequest, Case, CaseEntity, Disposition, Entity, Evidence, utcnow
from soc_platform.core.policy import PolicyEngine


def actions_for_case(session: Session, case_id: str) -> list[ActionRequest]:
    """A case's actions: its own, plus live actions it shares with another case (one containment approval can
    cover several cases). Used by the case page and the actions API, so both always list the same actions."""
    own = list(session.execute(select(ActionRequest).where(ActionRequest.case_id == case_id)
                               .order_by(ActionRequest.created_at)).scalars())
    # shared actions can cross domains (one isolation approval covers the phishing and the incident case). The
    # database narrows by the case id inside the JSON (ids are 32 random hex chars); Python confirms exactly.
    from sqlalchemy import String, cast

    q = select(ActionRequest).where(ActionRequest.case_id != case_id,
                                    ActionRequest.status.in_(("recommended", "pending_approval", "approved", "executed")),
                                    cast(ActionRequest.result, String).like(f"%{case_id}%"))
    shared = [a for a in session.execute(q).scalars() if case_id in (a.result or {}).get("linked_cases", [])]
    return own + shared


@dataclass
class Recommendation:
    action_type: str
    targets: list[dict[str, Any]]
    rationale: str
    evidence_ids: list[str] = field(default_factory=list)
    params: dict[str, Any] = field(default_factory=dict)
    expected_impact: str = ""
    blast_radius: str = ""
    reversible: bool = True
    priority: int = 50  # lower = more urgent; ranking is deterministic


class CaseService:
    def __init__(self, session: Session) -> None:
        self.s = session
        self.audit = AuditLog(session)
        self.store = ContextStore(session)

    # ------------------------------------------------------------------ lifecycle

    def create(self, domain: str, title: str, *, severity: str = "medium", attributes: dict[str, Any] | None = None,
               actor: str = "agent:platform", autonomy_mode: str = "shadow") -> Case:
        case = Case(domain=domain, title=title, severity=severity, attributes=attributes or {},
                    autonomy_mode=autonomy_mode)
        self.s.add(case)
        self.s.flush()
        self.audit.append(actor_type="agent" if actor.startswith("agent:") else "human", actor_id=actor,
                          event_type="case.created", subject_type="case", subject_id=case.id,
                          payload={"domain": domain, "title": title, "severity": severity})
        return case

    def link(self, case_id: str, entity_id: str, role: str = "related") -> None:
        exists = self.s.execute(select(CaseEntity).where(CaseEntity.case_id == case_id, CaseEntity.entity_id == entity_id,
                                                         CaseEntity.role == role)).scalars().first()
        if exists is None:
            self.s.add(CaseEntity(case_id=case_id, entity_id=entity_id, role=role))
            self.s.flush()

    def add_evidence(self, case_id: str, *, summary: str, source: str, dimension: str, data: dict[str, Any] | None = None,
                     entity_id: str | None = None, deep_link: str | None = None, is_inference: bool = False,
                     observed_at: datetime | None = None) -> Evidence:
        ev = Evidence(case_id=case_id, summary=summary, source_tool=source, dimension=dimension, data=data or {},
                      entity_id=entity_id, deep_link=deep_link, is_inference=is_inference, observed_at=observed_at)
        self.s.add(ev)
        self.s.flush()
        return ev

    def set_assessment(self, case: Case, *, verdict: str, severity: str, confidence: float, summary: str,
                       assessment: dict[str, Any], completeness: dict[str, Any], actor: str) -> None:
        case.verdict, case.severity, case.confidence = verdict, severity, round(float(confidence), 3)
        case.summary, case.assessment, case.completeness = summary, assessment, completeness
        case.status = "investigating" if case.status == "open" else case.status
        self.audit.append(actor_type="agent", actor_id=actor, event_type="case.assessed", subject_type="case",
                          subject_id=case.id, payload={"verdict": verdict, "severity": severity,
                                                       "confidence": case.confidence,
                                                       "claims": assessment.get("claims", []),
                                                       "unavailable_sources": completeness.get("unavailable", [])})

    # ------------------------------------------------------------------ recommendations (IM-F07, PH-F11)

    def recommend(self, case: Case, recs: list[Recommendation], registry: ActionRegistry, policy: PolicyEngine,
                  *, agent: str) -> list[ActionRequest]:
        svc = ActionService(self.s, registry, policy)
        out = []
        for r in sorted(recs, key=lambda x: x.priority):
            try:
                registry.get(r.action_type)
            except KeyError:
                # No connector can perform it: still shown to the analyst as a manual recommendation.
                self.add_evidence(case.id, summary=f"Manual action recommended: {r.action_type} - {r.rationale}",
                                  source=agent, dimension="recommendation", is_inference=True,
                                  data={"recommendation": asdict(r), "executable": False})
                continue
            req = svc.request(r.action_type, params=r.params, targets=r.targets, requested_by=agent_principal(agent),
                              case_id=case.id, domain=case.domain, rationale=r.rationale, evidence_ids=r.evidence_ids)
            req.result = {**(req.result or {}), "expected_impact": r.expected_impact, "blast_radius": r.blast_radius,
                          "reversible": r.reversible, "priority": r.priority}
            out.append(req)
        if any(a.status in ("recommended", "pending_approval") for a in out):
            case.status = "awaiting_approval"
        return out

    # ------------------------------------------------------------------ analyst decision (IM-F08)

    def decide(self, case_id: str, analyst: Principal, *, verdict: str, reasoning: str = "",
               close: bool = True) -> Disposition:
        if not analyst.can(Perm.INVESTIGATE):
            raise PermissionError("investigate permission required")
        case = self._get(case_id)
        d = Disposition(domain=case.domain, subject_type="case", subject_id=case.id, system_verdict=case.verdict,
                        system_confidence=case.confidence, analyst_verdict=verdict, analyst=analyst.id,
                        reasoning=reasoning, detection_source=(case.attributes or {}).get("detection_source"))
        self.s.add(d)
        if close:
            case.status, case.closed_at = "closed", utcnow()
        self.audit.append(actor_type="human", actor_id=analyst.id, event_type="case.disposition", subject_type="case",
                          subject_id=case.id, payload={"system_verdict": case.verdict, "analyst_verdict": verdict,
                                                       "agrees": _agrees(case.verdict, verdict), "reasoning": reasoning})
        self.s.flush()
        return d

    # ------------------------------------------------------------------ consolidated view (IM-F05, PH-F09)

    def view(self, case_id: str) -> dict[str, Any]:
        case = self._get(case_id)
        links = self.s.execute(select(CaseEntity).where(CaseEntity.case_id == case_id)).scalars().all()
        entities = []
        for ln in links:
            e = self.s.get(Entity, ln.entity_id)
            if e is None:
                continue
            attrs = dict(e.attributes or {})
            by_tool = attrs.pop("by_tool", {})
            entities.append({"id": e.id, "kind": e.kind, "role": ln.role, "name": e.display_name,
                             "attributes": attrs, "seen_by": sorted(by_tool), "confidence": e.confidence})
        evidence = self.s.execute(select(Evidence).where(Evidence.case_id == case_id)
                                  .order_by(Evidence.collected_at)).scalars().all()
        from soc_platform.core.enrichment import evidence_for_llm

        ref_of = {x["evidence_row"]: x["id"] for x in evidence_for_llm(list(evidence))}
        row_of = {v: k for k, v in ref_of.items()}
        by_dim: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for ev in evidence:
            by_dim[ev.dimension].append({"id": ev.id, "ref": ref_of.get(ev.id), "source": ev.source_tool, "summary": ev.summary,
                                         "deep_link": ev.deep_link, "type": "inference" if ev.is_inference else "fact",
                                         "observed_at": ev.observed_at.isoformat() if ev.observed_at else None})
        actions = actions_for_case(self.s, case_id)
        dispositions = self.s.execute(select(Disposition).where(Disposition.subject_id == case_id)).scalars().all()
        timeline = self.store.timeline([x["id"] for x in entities if x["kind"] in {"asset", "identity", "indicator"}])
        summaries = {ev.id: (ev.summary, ev.source_tool, ev.deep_link) for ev in evidence}
        claims = [{**c, "evidence": [{"ref": r, "id": row_of.get(r), "summary": summaries.get(row_of.get(r), ("",))[0],
                                      "source": summaries.get(row_of.get(r), ("", ""))[1]}
                                     for r in (c.get("evidence_ids") or [])]}
                  for c in (case.assessment or {}).get("claims", [])]
        return {
            "case": {"id": case.id, "domain": case.domain, "title": case.title, "status": case.status,
                     "severity": case.severity, "confidence": case.confidence, "verdict": case.verdict,
                     "summary": case.summary, "autonomy_mode": case.autonomy_mode,
                     "created_at": case.created_at.isoformat(), "attributes": case.attributes},
            "completeness": case.completeness,
            "assessment": {**(case.assessment or {}),
                           "facts": [c for c in claims if c.get("kind") == "fact"],
                           "inferences": [c for c in claims if c.get("kind") != "fact"]},
            "entities": entities,
            "timeline": timeline,
            "evidence": dict(by_dim),
            "actions": [{"id": a.id, "action_type": a.action_type, "status": a.status, "level": a.autonomy_level,
                         "targets": a.targets, "rationale": a.rationale, "policy_reasons": a.policy_reasons,
                         "evidence_ids": a.evidence_ids, "approver": a.approver,
                         "expected_impact": (a.result or {}).get("expected_impact"),
                         "blast_radius": (a.result or {}).get("blast_radius"),
                         "reversible": (a.result or {}).get("reversible"),
                         "priority": (a.result or {}).get("priority")} for a in actions],
            "dispositions": [{"analyst": d.analyst, "verdict": d.analyst_verdict, "reasoning": d.reasoning,
                              "at": d.created_at.isoformat()} for d in dispositions],
            "audit": [{"seq": r.seq, "ts": r.ts.isoformat(), "actor": f"{r.actor_type}:{r.actor_id}",
                       "event": r.event_type} for r in reversed(self.audit.query(subject_id=case_id, limit=500))],
        }

    def _get(self, case_id: str) -> Case:
        case = self.s.get(Case, case_id)
        if case is None:
            raise KeyError(f"unknown case {case_id}")
        return case


# ---------------------------------------------------------------------------- shadow-mode measurement


MALICIOUS = {"malicious", "phishing", "true_positive", "confirmed", "compromised", "high_risk"}
BENIGN = {"safe", "benign", "clean", "false_positive", "spam", "likely_safe", "no_action"}


def _bucket(v: str | None) -> str:
    x = (v or "").lower()
    if x in MALICIOUS:
        return "malicious"
    if x in BENIGN:
        return "benign"
    return "suspicious" if x else "none"


def _agrees(system: str | None, analyst: str | None) -> bool:
    return _bucket(system) == _bucket(analyst)


def agreement_report(session: Session, domain: str, *, since: datetime | None = None) -> dict[str, Any]:
    """Confusion matrix and agreement rate of system vs analyst verdicts (PH-T08, NFR-15, R14)."""
    stmt = select(Disposition).where(Disposition.domain == domain)
    if since:
        stmt = stmt.where(Disposition.created_at >= since)
    rows = session.execute(stmt).scalars().all()
    matrix: Counter[tuple[str, str]] = Counter((_bucket(d.system_verdict), _bucket(d.analyst_verdict)) for d in rows)
    n = len(rows)
    agree = sum(v for (s, a), v in matrix.items() if s == a)
    fp = matrix[("malicious", "benign")]
    fn = matrix[("benign", "malicious")]
    return {"domain": domain, "sample_size": n, "agreement_rate": round(agree / n, 4) if n else None,
            "false_positive_rate": round(fp / n, 4) if n else None, "false_negative_rate": round(fn / n, 4) if n else None,
            "confusion": {f"{s}->{a}": v for (s, a), v in sorted(matrix.items())}}


def detection_quality(session: Session, domain: str, *, min_count: int = 3, days: int = 30) -> list[dict[str, Any]]:
    """Detections consistently dispositioned as false positives -> tuning recommendations (IM-F14, U14)."""
    since = utcnow() - timedelta(days=days)
    rows = session.execute(select(Disposition).where(Disposition.domain == domain,
                                                     Disposition.created_at >= since)).scalars().all()
    per: dict[str, Counter[str]] = defaultdict(Counter)
    for d in rows:
        per[d.detection_source or "unknown"][_bucket(d.analyst_verdict)] += 1
    out = []
    for det, c in per.items():
        total = sum(c.values())
        fp = c["benign"]
        if total >= min_count and fp / total >= 0.8:
            out.append({"detection": det, "dispositions": total, "false_positive_share": round(fp / total, 3),
                        "recommendation": f"Tune or suppress '{det}': {fp}/{total} dispositions benign in {days}d"})
    return sorted(out, key=lambda x: -x["false_positive_share"])
