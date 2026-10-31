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
from soc_platform.core.models import ActionRequest, Case, CaseEntity, CaseNote, Disposition, Entity, Evidence, utcnow
from soc_platform.core.policy import PolicyEngine
from soc_platform.core.text import readable


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


def _aware(dt: datetime) -> datetime:
    from datetime import UTC

    return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt


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
        summary = readable(summary)
        same = self.s.execute(select(Evidence).where(
            Evidence.case_id == case_id, Evidence.summary == summary, Evidence.source_tool == source,
            Evidence.dimension == dimension, Evidence.entity_id.is_(None) if entity_id is None
            else Evidence.entity_id == entity_id).limit(1)).scalar()
        if same is not None:            # a reassessment re-collects what is already on the case: keep one row
            return same
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

    # ------------------------------------------------------------------ deferred narration

    def _case_hosts(self, case_id: str) -> set[str]:
        """The case's own device names, pseudonymised before a model sees them (laptop names often carry a person's
        name, and carry no domain the redactor could recognise)."""
        rows = self.s.execute(select(Entity.display_name).join(CaseEntity, CaseEntity.entity_id == Entity.id)
                              .where(CaseEntity.case_id == case_id, Entity.kind == "asset")).scalars()
        return {str(n).split(".")[0] for n in rows if n}

    @staticmethod
    def narration_request(workflow: str, question: str, ev_llm: list[dict[str, Any]], *, tier: str = "large") -> dict[str, Any]:
        """What a later model call needs: the exact evidence rows the case was assessed on (so the E-numbers match)."""
        return {"workflow": workflow, "question": question, "tier": tier, "evidence_rows": [e["evidence_row"] for e in ev_llm]}

    def pending_narration(self, domain: str, *, days: int = 7, limit: int = 200) -> list[str]:
        """Cases of ``domain`` whose written explanation is still to come (e.g. a job stopped between the two steps)."""
        rows = self.s.execute(select(Case).where(Case.domain == domain, Case.created_at >= utcnow() - timedelta(days=days))
                              .order_by(Case.created_at)).scalars()
        return [c.id for c in rows if (c.assessment or {}).get("narration_pending")][:limit]

    def narrate_pending(self, case_ids: list[str], llm: Any, *, redactor: Any = None, actor: str) -> int:
        """Write the model's explanation for cases that were committed with the deterministic one. The model calls run
        in parallel (``SOC_LLM_CONCURRENCY``); the results are applied in order, on this thread. A model answer that
        fails grounding - or no model - leaves the deterministic, cited explanation in place. Returns cases improved."""
        from soc_platform.core.enrichment import evidence_for_llm

        todo = []
        for cid in case_ids:
            case = self.s.get(Case, cid)
            req = (case.assessment or {}).get("narration_pending") if case is not None else None
            if not req:
                continue
            rows = self.s.execute(select(Evidence).where(Evidence.id.in_(req["evidence_rows"]))).scalars().all()
            todo.append((case, req, evidence_for_llm(rows), self._case_hosts(case.id)))
        if not todo:
            return 0

        def ask(item: tuple[Case, dict[str, Any], list[dict[str, Any]], set[str]]) -> dict[str, Any] | None:
            _, req, ev, hosts = item
            if llm is None:
                return None
            # one redactor per call: its token map is mutated while redacting, and the calls run in parallel - a
            # shared one could hand two people the same token and restore the wrong name into a case
            from soc_platform.llm.redaction import Redactor

            base = redactor if redactor is not None else getattr(llm, "redactor_factory", lambda: None)()
            red = Redactor(internal_domains=set(getattr(base, "internal_domains", set()) or set()),
                           known_names=set(getattr(base, "known_names", set()) or set()),
                           known_hosts=set(getattr(base, "known_hosts", set()) or set()) | hosts)
            return llm.grounded(req["workflow"], req["question"], ev, tier=req.get("tier", "large"), redactor=red)

        if llm is not None and len(todo) > 1:
            from concurrent.futures import ThreadPoolExecutor

            from soc_platform.llm.gateway import llm_concurrency

            with ThreadPoolExecutor(max_workers=llm_concurrency()) as pool:
                answers = list(pool.map(ask, todo))
        else:
            answers = [ask(t) for t in todo]
        improved = 0
        for (case, _, ev, _hosts), g in zip(todo, answers, strict=True):
            assessment = {k: v for k, v in (case.assessment or {}).items() if k != "narration_pending"}
            if g is not None and g.get("source") == "llm":
                case.summary = g["summary"]
                assessment.update({"claims": g["claims"], "insufficient_evidence": g.get("insufficient_evidence", False),
                                   "evidence_index": {e["id"]: e["evidence_row"] for e in ev}})
                improved += 1
                self.audit.append(actor_type="agent", actor_id=actor, event_type="case.narrated", subject_type="case",
                                  subject_id=case.id, payload={"claims": g["claims"]})
            case.assessment = assessment
        self.s.flush()
        return improved

    # ------------------------------------------------------------------ recommendations (IM-F07, PH-F11)

    def recommend(self, case: Case, recs: list[Recommendation], registry: ActionRegistry, policy: PolicyEngine,
                  *, agent: str, ceiling: tuple[int, str] | None = None) -> list[ActionRequest]:
        from soc_platform.core.tuning import TuningStore, case_facts, demote_rule, describe

        svc = ActionService(self.s, registry, policy)
        out = []
        demotes = TuningStore(self.s).active("action_demote")
        facts = case_facts(self.s, case) if demotes else None
        for r in sorted(recs, key=lambda x: x.priority):
            try:
                registry.get(r.action_type)
            except KeyError:
                # No connector can perform it: still shown to the analyst as a manual recommendation.
                self.add_evidence(case.id, summary=f"Manual action recommended: {r.action_type} - {r.rationale}",
                                  source=agent, dimension="recommendation", is_inference=True,
                                  data={"recommendation": asdict(r), "executable": False})
                continue
            # an action analysts keep rejecting here (a lead-approved rule): still recommended and shown, but it
            # never runs autonomously here - the policy is capped at recommend (L2)
            demoted = demote_rule(self.s, case, r.action_type, rules=demotes, facts=facts) if demotes else None
            cap = ceiling
            if demoted is not None:
                own = (2, f"usually rejected here (tuning rule #{demoted.id}): recommend only")
                cap = min((c for c in (ceiling, own) if c is not None), key=lambda c: int(c[0]))
            req = svc.request(r.action_type, params=r.params, targets=r.targets, requested_by=agent_principal(agent),
                              case_id=case.id, domain=case.domain, rationale=r.rationale, evidence_ids=r.evidence_ids,
                              ceiling=cap)
            fresh = "expected_impact" not in (req.result or {})        # created now, not an action open from before
            req.result = {**(req.result or {}), "expected_impact": r.expected_impact, "blast_radius": r.blast_radius,
                          "reversible": r.reversible, "priority": r.priority}
            # labelled only when the rule decided it (an action already open from before keeps its own decision)
            if demoted is not None and fresh:
                req.result = {**req.result, "tuning_demoted": {"rule": demoted.id,
                                                               "why": describe(demoted.kind, demoted.params)}}
                if own[1] not in (req.policy_reasons or []):        # a tool's stage capped it first: still say why
                    req.policy_reasons = [*(req.policy_reasons or []), own[1]]
            out.append(req)
        if any(a.status in ("recommended", "pending_approval") for a in out):
            case.status = "awaiting_approval"
        return out

    # ------------------------------------------------------------------ analyst decision (IM-F08)

    # ------------------------------------------------------------------ collaboration

    def assign(self, case_id: str, assignee: str | None, *, by: Principal) -> Case:
        """Give the case an owner (or none). Taking a case yourself needs ``investigate``; assigning it to someone
        else, or taking it off someone else, needs ``approve_high_impact`` (a lead)."""
        case = self._get(case_id)
        me = by.id.lower()
        target = (assignee or "").strip().lower() or None
        current = (case.assignee or "").lower() or None
        if not by.can(Perm.INVESTIGATE):
            raise PermissionError("investigate permission required")
        if (target not in (None, me) or (target is None and current not in (None, me))) and not by.can(Perm.APPROVE_HIGH_IMPACT):
            raise PermissionError("only a lead can assign a case to someone else or take it off them")
        if target is not None and ("@" not in target or len(target) > 256):
            raise ValueError("assignee must be a work e-mail address")
        case.assignee = target
        self.audit.append(actor_type=by.actor_type, actor_id=by.id, event_type="case.assigned", subject_type="case",
                          subject_id=case.id, payload={"assignee": target, "previous": current})
        self.s.flush()
        return case

    def add_note(self, case_id: str, text: str, *, by: Principal) -> CaseNote:
        text = (text or "").strip()
        if not text:
            raise ValueError("a note needs text")
        if len(text) > 4000:
            raise ValueError("a note is limited to 4,000 characters")
        if not by.can(Perm.INVESTIGATE):
            raise PermissionError("investigate permission required")
        case = self._get(case_id)
        # strictly after the case's previous note, so "newest first" holds even within one clock tick
        from sqlalchemy import func

        last = self.s.execute(select(func.max(CaseNote.created_at)).where(CaseNote.case_id == case.id)).scalar()
        at = utcnow()
        if last is not None and at <= _aware(last):
            at = _aware(last) + timedelta(microseconds=1)
        note = CaseNote(case_id=case.id, author=by.id, text=text, created_at=at)
        self.s.add(note)
        self.s.flush()
        self.audit.append(actor_type=by.actor_type, actor_id=by.id, event_type="case.note_added", subject_type="case",
                          subject_id=case.id, payload={"note": note.id, "chars": len(text)})
        return note

    def decide(self, case_id: str, analyst: Principal, *, verdict: str, reasoning: str = "",
               close: bool = True) -> Disposition:
        if not analyst.can(Perm.INVESTIGATE):
            raise PermissionError("investigate permission required")
        case = self._get(case_id)
        # an exercise's outcome says nothing about whether the detection is noise: it stays out of the statistics
        source = None if (case.attributes or {}).get("exercise") else (case.attributes or {}).get("detection_source")
        d = Disposition(domain=case.domain, subject_type="case", subject_id=case.id, system_verdict=case.verdict,
                        system_confidence=case.confidence, analyst_verdict=verdict, analyst=analyst.id,
                        reasoning=reasoning, detection_source=source)
        self.s.add(d)
        if close:
            case.status, case.closed_at = "closed", utcnow()
        self.audit.append(actor_type="human", actor_id=analyst.id, event_type="case.disposition", subject_type="case",
                          subject_id=case.id, payload={"system_verdict": case.verdict, "analyst_verdict": verdict,
                                                       "agrees": _agrees(case.verdict, verdict), "reasoning": reasoning})
        rule = (case.attributes or {}).get("tuning_rule")
        if rule is not None and _bucket(verdict) in ("malicious", "suspicious"):
            # a threat in what a tuning rule suppressed (or sampled): the rule stops at once
            from soc_platform.core.tuning import TuningStore

            TuningStore(self.s).pause_for_threat(rule, case, analyst, verdict)
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
        summaries = {ev.id: (ev.summary, ev.source_tool, ev.observed_at.isoformat() if ev.observed_at else None)
                     for ev in evidence}
        claims = [{**c, "evidence": [{"ref": r, "id": row_of.get(r), "summary": summaries.get(row_of.get(r), ("",))[0],
                                      "source": summaries.get(row_of.get(r), ("", ""))[1],
                                      "observed_at": summaries.get(row_of.get(r), ("", "", None))[2]}
                                     for r in (c.get("evidence_ids") or [])]}
                  for c in (case.assessment or {}).get("claims", [])]
        return {
            "case": {"id": case.id, "domain": case.domain, "title": case.title, "status": case.status,
                     "severity": case.severity, "confidence": case.confidence, "verdict": case.verdict,
                     "summary": case.summary, "autonomy_mode": case.autonomy_mode, "assignee": case.assignee,
                     "created_at": case.created_at.isoformat(), "attributes": case.attributes},
            "completeness": case.completeness,
            "assessment": {**(case.assessment or {}),
                           "mitre": _named_techniques((case.assessment or {}).get("mitre") or []),
                           "facts": [c for c in claims if c.get("kind") == "fact"],
                           "inferences": [c for c in claims if c.get("kind") != "fact"]},
            "entities": entities,
            "watchlists": self._watchlists(case_id),
            "timeline": timeline,
            "evidence": dict(by_dim),
            "actions": [{"id": a.id, "action_type": a.action_type, "status": a.status, "level": a.autonomy_level,
                         "targets": a.targets, "rationale": a.rationale, "policy_reasons": a.policy_reasons,
                         "evidence_ids": a.evidence_ids, "approver": a.approver,
                         "result": {"awaiting_second_approval": bool((a.result or {}).get("awaiting_second_approval"))
                                    and a.status == "pending_approval"},
                         "expected_impact": (a.result or {}).get("expected_impact"),
                         "blast_radius": (a.result or {}).get("blast_radius"),
                         "reversible": (a.result or {}).get("reversible"),
                         "priority": (a.result or {}).get("priority")} for a in actions],
            "dispositions": [{"analyst": d.analyst, "verdict": d.analyst_verdict, "reasoning": d.reasoning,
                              "at": d.created_at.isoformat()} for d in dispositions],
            "notes": [{"id": n.id, "author": n.author, "text": n.text, "at": n.created_at.isoformat()}
                      for n in self.s.execute(select(CaseNote).where(CaseNote.case_id == case_id)
                                              .order_by(CaseNote.created_at.desc(), CaseNote.id)).scalars()],
            "audit": [{"seq": r.seq, "ts": r.ts.isoformat(), "actor": f"{r.actor_type}:{r.actor_id}",
                       "event": r.event_type} for r in reversed(self.audit.query(subject_id=case_id, limit=500))],
        }

    def _watchlists(self, case_id: str) -> list[dict[str, Any]]:
        """People, hosts and indicators of this case on the block / exception list (context only: no figure,
        verdict or action depends on it)."""
        from soc_platform.config import get_settings
        from soc_platform.core.watchlists import WatchlistService

        return WatchlistService(self.s).case_matches([case_id], get_settings().org_domains).get(case_id, [])

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


def detection_quality(session: Session, domain: str, *, min_count: int = 3, days: int = 30,
                      share: float = 0.8) -> list[dict[str, Any]]:
    """Detections consistently dispositioned as false positives -> tuning recommendations (IM-F14, U14). The
    thresholds are the defaults or the noise threshold a lead set (``core/tuning.py``)."""
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
        if total >= min_count and fp / total >= share:
            out.append({"detection": det, "dispositions": total, "false_positive_share": round(fp / total, 3),
                        "recommendation": f"Tune or suppress '{det}': {fp}/{total} dispositions benign in {days}d"})
    return sorted(out, key=lambda x: -x["false_positive_share"])


def _named_techniques(mitre: list[Any]) -> list[Any]:
    """ATT&CK techniques with their names: a vendor sends the id alone (T1190), so the name comes from the
    platform's technique catalogue (the parent's name for a sub-technique the catalogue does not list)."""
    from soc_platform.intelligence.attack_coverage import TECHNIQUES  # data only; same lazy pattern as access.py

    out = []
    for m in mitre:
        if isinstance(m, dict) and not m.get("name"):
            tid = str(m.get("technique") or "")
            known = TECHNIQUES.get(tid) or TECHNIQUES.get(tid.split(".")[0])
            m = {**m, "name": known[0] if known else ""}
        out.append(m)
    return out
