"""Deep analysis: an evidence-bound senior-analyst review of an Attack Story by the governed LLM.

The model receives only the story's evidence (events S#, gaps G#, benign-explanation tests H#, reach B#, pending
actions P#, exposure X#) - never the database - and must return structured JSON:

    assessment, confidence, attacker_objective, key_findings, alternative_explanations, open_questions, priorities

Controls (in addition to the gateway's redaction, approved endpoints, model pinning, prompt log and token budget):

* every finding / objective / alternative / priority must cite evidence ids that exist; anything uncited or citing
  invented ids is dropped and **counted** so the analyst sees how much was removed
* statuses and confidence are restricted to fixed vocabularies
* priorities may only reference real pending actions (``P#``) or be marked manual - the model can never execute,
  approve or create an action
* disagreement with the deterministic assessment is flagged, not silently accepted
* results are cached on the case per story fingerprint (re-run only when the evidence changes or on request)
"""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from soc_platform.core.audit import AuditLog
from soc_platform.core.models import Case, LLMCall, utcnow
from soc_platform.intelligence.story import evidence_for_llm
from soc_platform.llm.gateway import BudgetExceeded, LLMGateway, supported_summary, unsupported_numbers
from soc_platform.llm.redaction import Redactor

SYSTEM = (
    "You are a principal incident responder reviewing a reconstructed attack for a SOC lead. Use ONLY the evidence "
    "provided; cite evidence ids (S#, G#, H#, B#, P#, X#) for every statement. Separate observed facts from your "
    "inferences. Consider benign explanations seriously and say what evidence would change your mind. Never invent "
    "hosts, users, indicators, times or counts. You cannot take actions; you may only prioritise the pending actions "
    "listed (P#) or propose manual steps. Respond with JSON only."
)
SCHEMA = (
    '{"assessment": "2-4 sentences", "confidence": "high|medium|low", '
    '"attacker_objective": {"text": "...", "evidence_ids": ["S1"]}, '
    '"key_findings": [{"text": "...", "kind": "fact|inference", "evidence_ids": ["S1"]}], '
    '"alternative_explanations": [{"hypothesis": "...", "status": "rejected|unlikely|plausible|cannot_assess", '
    '"reasoning": "...", "evidence_ids": ["H1"]}], '
    '"open_questions": [{"question": "...", "why": "...", "evidence_ids": ["G1"]}], '
    '"priorities": [{"action_ref": "P1 or manual", "text": "...", "why": "...", "evidence_ids": ["S1"]}]}'
)
STATUSES = {"rejected", "unlikely", "plausible", "cannot_assess"}
CONF = {"high", "medium", "low"}
VERDICT_CONF = {"confirmed_compromise": "high", "likely_compromise": "medium", "attempt_blocked": "medium",
                "suspicious_activity": "low", "no_attack_activity": "low"}


def _cited(item: dict[str, Any], valid: set[str]) -> list[str]:
    return [str(i) for i in (item.get("evidence_ids") or []) if str(i) in valid]


def _figures_ok(item: dict[str, Any], fields: tuple[str, ...], ids: list[str], text_by_id: dict[str, str], context: str) -> bool:
    """Every figure a statement states must appear in the evidence it cites (or the case context)."""
    support = context + " " + " ".join(text_by_id.get(i, "") for i in ids)
    return not any(unsupported_numbers(str(item.get(f, "")), support) for f in fields)


def run_deep_analysis(session: Session, story: dict[str, Any], llm: LLMGateway | None, *, actor: str,
                      force: bool = False, org_domains: list[str] | None = None) -> dict[str, Any]:
    case = session.get(Case, story["case_id"])
    if case is None:
        raise KeyError("unknown case")
    if llm is None:
        return {"available": False, "reason": "No LLM provider is configured (SOC_LLM_PROVIDER=none). The Attack Story "
                "above is complete and deterministic; configure an approved endpoint to add a deep analysis."}
    cached = (case.assessment or {}).get("deep_analysis")
    if cached and cached.get("fingerprint") == story["fingerprint"] and not force:
        return {**cached, "cached": True}

    evidence = evidence_for_llm(story)
    valid = {e["id"] for e in evidence}
    plan_ids = {e["id"]: e["action_id"] for e in evidence if e["id"].startswith("P")}
    lines = "\n".join(f"[{e['id']}] ({e['source']}) {e['claim']}" for e in evidence)
    user = (f"CASE: {story['title']}\nDETERMINISTIC ASSESSMENT: {story['assessment']['label']} "
            f"({story['assessment']['confidence']}): {story['assessment']['reason']}\n\nEVIDENCE:\n{lines}\n\n"
            f"Return JSON exactly in this shape: {SCHEMA}")
    red = Redactor(internal_domains=set(org_domains or []))
    try:
        data = llm.complete_json("intelligence.deep_analysis", SYSTEM, user, tier="large", redactor=red)
    except BudgetExceeded:
        return {"available": True, "ok": False, "reason": "Monthly LLM token budget exhausted - analysis not run."}
    if not data:
        return {"available": True, "ok": False, "reason": "The model returned no usable answer (see the LLM call log)."}

    text_by_id = {e["id"]: e["claim"] for e in evidence}
    context = f"{story['title']} {story['assessment']['label']} {story['assessment']['reason']}"
    dropped = 0
    findings = []
    for f in data.get("key_findings") or []:
        ids = _cited(f, valid) if isinstance(f, dict) else []
        if not ids or not str(f.get("text", "")).strip() or not _figures_ok(f, ("text",), ids, text_by_id, context):
            dropped += 1
            continue
        findings.append({"text": str(f["text"]).strip(), "kind": f.get("kind") if f.get("kind") in {"fact", "inference"} else "inference",
                         "evidence_ids": ids})
    alts = []
    for h in data.get("alternative_explanations") or []:
        ids = _cited(h, valid) if isinstance(h, dict) else []
        if not ids or h.get("status") not in STATUSES or not _figures_ok(h, ("hypothesis", "reasoning"), ids, text_by_id, context):
            dropped += 1
            continue
        alts.append({"hypothesis": str(h.get("hypothesis", ""))[:300], "status": h["status"],
                     "reasoning": str(h.get("reasoning", ""))[:600], "evidence_ids": ids})
    questions = [{"question": str(q.get("question", ""))[:300], "why": str(q.get("why", ""))[:400], "evidence_ids": _cited(q, valid)}
                 for q in (data.get("open_questions") or [])[:8] if isinstance(q, dict) and str(q.get("question", "")).strip()]
    priorities = []
    for p in data.get("priorities") or []:
        if not isinstance(p, dict):
            dropped += 1
            continue
        ref = str(p.get("action_ref", "")).strip()
        ids = _cited(p, valid)
        if ref != "manual" and ref not in plan_ids:
            dropped += 1          # references an action that does not exist
            continue
        if not ids or not _figures_ok(p, ("text", "why"), ids, text_by_id, context):
            dropped += 1
            continue
        priorities.append({"action_ref": ref, "action_id": plan_ids.get(ref), "text": str(p.get("text", ""))[:300],
                           "why": str(p.get("why", ""))[:500], "evidence_ids": ids})
    obj = data.get("attacker_objective") if isinstance(data.get("attacker_objective"), dict) else {}
    objective = {"text": str(obj.get("text", ""))[:400], "evidence_ids": _cited(obj, valid)} if _cited(obj, valid) else None
    if obj and objective is None:
        dropped += 1
    conf = data.get("confidence") if data.get("confidence") in CONF else "low"
    expected = VERDICT_CONF.get(story["assessment"]["verdict"], "medium")
    rank = {"low": 0, "medium": 1, "high": 2}
    disagreement = None
    if abs(rank[conf] - rank[expected]) >= 2 or (story["assessment"]["verdict"] == "no_attack_activity" and findings):
        disagreement = (f"The model's confidence ({conf}) differs markedly from the deterministic assessment "
                        f"({story['assessment']['label']}, {story['assessment']['confidence']}). Review the cited evidence.")
    assessment, removed = supported_summary(str(data.get("assessment", "")), context + " " + " ".join(text_by_id.values()))
    dropped += removed
    call = session.query(LLMCall).filter(LLMCall.workflow == "intelligence.deep_analysis").order_by(LLMCall.ts.desc()).first()
    result = {"available": True, "ok": True, "assessment": assessment[:1200], "confidence": conf,
              "attacker_objective": objective, "key_findings": findings, "alternative_explanations": alts,
              "open_questions": questions, "priorities": priorities, "dropped_statements": dropped,
              "disagreement": disagreement, "fingerprint": story["fingerprint"],
              "model": call.model if call else None, "provider": llm.provider.name,
              "generated_at": utcnow().isoformat(), "generated_by": actor, "cached": False}
    asm = dict(case.assessment or {})
    asm["deep_analysis"] = result
    case.assessment = asm
    AuditLog(session).append(actor_type="agent", actor_id="agent:deep-analysis", event_type="intelligence.deep_analysis",
                             subject_type="case", subject_id=case.id,
                             payload={"requested_by": actor, "findings": len(findings), "dropped": dropped,
                                      "model": result["model"], "disagreement": bool(disagreement)})
    session.flush()
    return result
