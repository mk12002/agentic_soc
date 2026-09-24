"""
LLM reasoner for final risk explanation (Azure OpenAI with local fallback).
"""

from __future__ import annotations

from typing import Any

import functools
import json
import re
from openai import AzureOpenAI

from soc_platform.domains.phishing.engine.configs.settings import settings
from soc_platform.domains.phishing.engine.services.logging_service import get_service_logger

logger = get_service_logger("llm_reasoner")


def _cf_agent_names(counterfactual: dict[str, Any] | None) -> list[str]:
    """Extract agent names from a counterfactual ``agents_altered`` list.

    Tolerates both the structured dict shape ``{agent_name, original_risk, attenuated_risk}`` and the
    legacy bare-string shape, so this stays correct regardless of which the engine emits.
    """
    names: list[str] = []
    for entry in ((counterfactual or {}).get("agents_altered") or []):
        if isinstance(entry, dict):
            names.append(str(entry.get("agent_name", "unknown")))
        else:
            names.append(str(entry))
    return names


def _fallback_explanation(agent_results: list[dict[str, Any]], score: float, counterfactual: dict[str, Any] | None = None) -> str:
    top = sorted(agent_results, key=lambda entry: entry.get("risk_score", 0.0), reverse=True)[:3]
    highlights = ", ".join(
        f"{entry.get('agent_name')}={entry.get('risk_score', 0.0):.2f}" for entry in top
    )
    base = (
        f"Final score {score:.2f}. Top contributing agents: {highlights}. "
        "This verdict is generated using deterministic weighting because Azure OpenAI is unavailable."
    )
    if counterfactual and counterfactual.get("is_counterfactual"):
        agents = ", ".join(_cf_agent_names(counterfactual))
        base += f" However, if {agents} were safe, the score would drop to {counterfactual.get('new_normalized_score')}."
    return base


@functools.lru_cache(maxsize=2000)
def _cached_azure_call(system_prompt: str, user_prompt: str) -> str | None:
    try:
        client = AzureOpenAI(
            api_key=settings.azure_openai_api_key,
            azure_endpoint=settings.azure_openai_endpoint,
            api_version=settings.azure_openai_api_version,
        )
        completion = client.chat.completions.create(
            model=settings.azure_openai_deployment,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0.1,
        )
        return completion.choices[0].message.content
    except Exception as exc:
        logger.warning("Azure OpenAI reasoning failed", error=str(exc))
        return None


def generate_reasoning(
    agent_results: list[dict[str, Any]], 
    normalized_score: float,
    counterfactual: dict[str, Any] | None = None
) -> str:
    if not (
        settings.azure_openai_endpoint
        and settings.azure_openai_api_key
        and settings.azure_openai_deployment
    ):
        return _fallback_explanation(agent_results, normalized_score, counterfactual)

    prompt = (
        "You are SOC reasoning engine. "
        "Given the agent outputs, explain the likely attack scenario, confidence, and final score. "
        "Keep under 120 words.\n"
        f"Agent outputs: {agent_results}\n"
        f"Preliminary score: {normalized_score:.4f}\n"
    )
    
    if counterfactual and counterfactual.get("is_counterfactual"):
        agents = ", ".join(_cf_agent_names(counterfactual))
        new_score = counterfactual.get("new_normalized_score", 0)
        prompt += (
            f"\nIMPORTANT COUNTERFACTUAL BOUNDARY: This email was blocked. "
            f"However, we calculated that if the findings from [{agents}] were neutralized "
            f"to be completely safe, the final score would drop to {new_score} and the email would have been delivered. "
            f"Be sure to explicitly mention this counterfactual in your explanation so the human analyst knows exactly what triggered the block."
        )
    
    content = _cached_azure_call("You are a cybersecurity triage analyst.", prompt)
    return content or _fallback_explanation(agent_results, normalized_score, counterfactual)


def explain_counterfactual(counterfactual: dict[str, Any]) -> str:
    if not counterfactual or not counterfactual.get("is_counterfactual"):
        return "No counterfactual scenario was applicable for this verdict."
    
    if not (settings.azure_openai_endpoint and settings.azure_openai_api_key and settings.azure_openai_deployment):
        return f"Raw Counterfactual: {counterfactual}"

    agents = ", ".join(_cf_agent_names(counterfactual))
    new_score = counterfactual.get("new_normalized_score")
    prompt = (
        f"Explain the following counterfactual logic in 1-2 clear, human-readable sentences for a SOC analyst.\n"
        f"Data: We calculated that if the findings from [{agents}] were completely safe, the final risk score would drop to {new_score} "
        f"and the email would have been delivered.\nMake it sound professional and explanatory."
    )
    
    content = _cached_azure_call("You are a cybersecurity triage analyst.", prompt)
    return content or "Counterfactual generated."


def explain_storyline(storyline: list[dict[str, Any]]) -> str:
    if not storyline:
        return "No obvious threat storyline detected."
        
    if not (settings.azure_openai_endpoint and settings.azure_openai_api_key and settings.azure_openai_deployment):
        return f"Raw Storyline: {storyline}"
        
    prompt = (
        "You are a SOC reasoning engine. Convert the following list of attack phases into a beautiful, chronological "
        "Markdown-formatted threat narrative for an analyst to read. Use clear spacing.\n"
        "CRITICAL: You MUST include a Mermaid.js directional graph (`graph TD`) mapping the attack progression conceptually. "
        "Place it inside a ```mermaid code block along with the text narrative.\n"
        f"Raw phases: {storyline}"
    )
    
    content = _cached_azure_call("You are a cybersecurity triage analyst configuring markdown narratives with diagrams.", prompt)
    return content or "Storyline generated."


# ---------------------------------------------------------------------------
# Evidence-grounded reasoning (anti-hallucination)
# ---------------------------------------------------------------------------

_GROUNDED_SYSTEM_PROMPT = (
    "You are a SOC triage analyst. You may ONLY state facts that are supported by the EVIDENCE items "
    "provided. Every claim you make MUST cite one or more evidence ids (e.g. E3). Do NOT invent details, "
    "senders, URLs, or behaviours that are not present in the evidence. If the evidence is thin, say so. "
    "Respond with STRICT JSON only, no prose outside the JSON."
)


def _parse_json_block(text: str | None) -> dict[str, Any] | None:
    """Best-effort parse of a JSON object from an LLM response (tolerates ```json fences / surrounding text)."""
    if not text:
        return None
    candidate = text.strip()
    fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", candidate, re.DOTALL)
    if fence:
        candidate = fence.group(1)
    else:
        brace = re.search(r"\{.*\}", candidate, re.DOTALL)
        if brace:
            candidate = brace.group(0)
    try:
        parsed = json.loads(candidate)
        return parsed if isinstance(parsed, dict) else None
    except (json.JSONDecodeError, ValueError):
        return None


def _validate_grounded_claims(
    claims: list[dict[str, Any]] | None,
    valid_ids: set[str],
) -> list[dict[str, Any]]:
    """Keep only claims that cite at least one real evidence id; strip unknown ids from those claims."""
    validated: list[dict[str, Any]] = []
    for claim in (claims or []):
        if not isinstance(claim, dict):
            continue
        text = str(claim.get("text", "")).strip()
        if not text:
            continue
        cited = [str(cid) for cid in (claim.get("evidence_ids") or []) if str(cid) in valid_ids]
        if not cited:
            # Unsupported claim — drop it rather than risk presenting a fabricated statement.
            continue
        validated.append({"text": text, "evidence_ids": cited})
    return validated


def _render_grounded_explanation(summary: str, claims: list[dict[str, Any]]) -> str:
    """Render validated claims into a markdown explanation with inline [E#] citations."""
    lines: list[str] = []
    if summary:
        lines.append(summary.strip())
    if claims:
        lines.append("")
        for claim in claims:
            citation = " ".join(f"[{cid}]" for cid in claim["evidence_ids"])
            lines.append(f"- {claim['text']} {citation}".rstrip())
    return "\n".join(lines).strip()


def _deterministic_grounded(
    evidence: list[dict[str, Any]],
    normalized_score: float,
    counterfactual: dict[str, Any] | None,
) -> dict[str, Any]:
    """Fallback grounded output built purely from evidence (used when Azure is unavailable or invalid)."""
    # Skip the per-agent score anchors for the headline claims; prefer concrete indicator evidence.
    signal_evidence = [e for e in evidence if e.get("type") != "agent_score"]
    chosen = signal_evidence[:6] if signal_evidence else evidence[:6]
    claims = [{"text": e["claim"], "evidence_ids": [e["id"]]} for e in chosen]
    summary = (
        f"Overall risk {normalized_score:.2f}. The verdict is supported by {len(signal_evidence)} "
        f"concrete detector signal(s) across {len({e['agent'] for e in evidence})} agent(s)."
    )
    if counterfactual and counterfactual.get("is_counterfactual"):
        names = ", ".join(_cf_agent_names(counterfactual))
        new_score = counterfactual.get("new_normalized_score")
        summary += (
            f" If {names} had not flagged this message, the score would fall to {new_score}, "
            "below the blocking threshold."
        )
    return {
        "explanation": _render_grounded_explanation(summary, claims),
        "claims": claims,
        "evidence": evidence,
        "grounded": True,
        "source": "deterministic",
    }


def generate_grounded_reasoning(
    agent_results: list[dict[str, Any]],
    normalized_score: float,
    evidence: list[dict[str, Any]],
    counterfactual: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Produce an explanation in which **every claim is traceable to a real evidence id**.

    Returns ``{explanation, claims, evidence, grounded, source}``. ``explanation`` is a markdown string
    (safe to drop into the existing ``llm_explanation`` field). Claims that do not cite valid evidence are
    discarded, so the rendered explanation cannot contain fabricated statements.
    """
    valid_ids = {str(e.get("id")) for e in (evidence or []) if e.get("id")}

    # No evidence or Azure not configured -> deterministic, still fully grounded.
    if not valid_ids or not (
        settings.azure_openai_endpoint
        and settings.azure_openai_api_key
        and settings.azure_openai_deployment
    ):
        return _deterministic_grounded(evidence, normalized_score, counterfactual)

    evidence_lines = "\n".join(
        f"{e['id']} [{e['agent']}/{e['type']}] {e['claim']}" + (f" (value: {e['raw_value']})" if e.get("raw_value") else "")
        for e in evidence
    )
    cf_line = ""
    if counterfactual and counterfactual.get("is_counterfactual"):
        cf_line = (
            f"\nCounterfactual: if [{', '.join(_cf_agent_names(counterfactual))}] were neutralized, the score "
            f"would drop to {counterfactual.get('new_normalized_score')} (below the blocking threshold). "
            "You may reference this, but only alongside the evidence ids for those agents.\n"
        )

    user_prompt = (
        f"Overall normalized risk score: {normalized_score:.4f}\n"
        f"EVIDENCE (cite by id):\n{evidence_lines}\n{cf_line}\n"
        "Return STRICT JSON of the form:\n"
        '{"summary": "<=2 sentence overview", '
        '"claims": [{"text": "specific finding", "evidence_ids": ["E1", "E2"]}]}\n'
        "Only include claims whose evidence_ids appear above."
    )

    raw = _cached_azure_call(_GROUNDED_SYSTEM_PROMPT, user_prompt)
    parsed = _parse_json_block(raw)
    if not parsed:
        logger.warning("Grounded reasoning returned unparseable output; using deterministic fallback")
        return _deterministic_grounded(evidence, normalized_score, counterfactual)

    claims = _validate_grounded_claims(parsed.get("claims"), valid_ids)
    if not claims:
        logger.warning("Grounded reasoning produced no evidence-backed claims; using deterministic fallback")
        return _deterministic_grounded(evidence, normalized_score, counterfactual)

    summary = str(parsed.get("summary", "")).strip()
    return {
        "explanation": _render_grounded_explanation(summary, claims),
        "claims": claims,
        "evidence": evidence,
        "grounded": True,
        "source": "azure_openai",
    }


# ---------------------------------------------------------------------------
# Structured analyst brief (SOC-ready, grounded in the same evidence)
# ---------------------------------------------------------------------------

# Maps evidence types to the concrete investigation step they warrant. Keeping the
# mapping explicit means every recommended step is justified by evidence that is
# actually present — no generic boilerplate that the evidence does not support.
_INVESTIGATION_STEPS: dict[str, str] = {
    "email_authentication": "Confirm SPF/DKIM/DMARC alignment for the sender domain against the purported brand.",
    "routing_forgery": "Trace the Received/ARC chain and confirm the originating relay is legitimate for this sender.",
    "domain_spoofing": "Verify the registered sender domain and compare it character-by-character with the trusted brand.",
    "brand_impersonation": "Detonate the embedded URLs in an isolated sandbox before any user is allowed to follow them.",
    "url_heuristic": "Inspect and sandbox the embedded URLs; check domain age and reputation feeds.",
    "content_pattern": "Confirm the request with the purported sender through a known-good, out-of-band channel.",
    "evasion": "Treat as a targeted attempt: the lure was crafted to bypass automated filters — escalate to a human analyst.",
    "sender_reputation": "Review historical sender reputation and prior interactions for this domain.",
    "header_anomaly": "Review the full header set for inconsistencies in routing, timing, and Reply-To alignment.",
}

_ESCALATION_BY_VERDICT: dict[str, str] = {
    "malicious": "Block/quarantine immediately and open a SOC incident; hunt for other recipients of the campaign.",
    "high_risk": "Quarantine and escalate to a SOC analyst for confirmation before release.",
    "suspicious": "Hold for analyst review; do not auto-deliver until corroborated.",
    "likely_safe": "Deliver with a caution banner; no analyst action required unless the user reports it.",
    "safe": "Deliver normally; no action required.",
}


def generate_structured_brief(
    agent_results: list[dict[str, Any]],
    normalized_score: float,
    evidence: list[dict[str, Any]],
    verdict: str,
    counterfactual: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Produce a SOC-ready analyst brief whose every field is grounded in real evidence.

    Returns ``{executive_summary, key_evidence, confidence_assessment,
    investigation_steps, false_positive_indicators, escalation_recommendation}``.
    The brief is built deterministically from the agents' own output, so it is
    faithful by construction and never depends on an LLM being available.
    """
    signal_evidence = [e for e in (evidence or []) if e.get("type") != "agent_score"]
    agents_present = {e.get("agent") for e in (evidence or [])}
    types_present = {e.get("type") for e in signal_evidence}

    # Key evidence: the concrete detector signals, each tagged with its source agent.
    key_evidence = [
        {"evidence_id": e["id"], "agent": e["agent"], "claim": e["claim"], "raw_value": e.get("raw_value")}
        for e in signal_evidence[:8]
    ]

    # Confidence assessment from agreement + the strongest agent confidence present.
    agreeing = [r for r in agent_results if float(r.get("risk_score", 0.0) or 0.0) >= 0.4]
    max_conf = max((float(r.get("confidence", 0.0) or 0.0) for r in agent_results), default=0.0)
    if len(agreeing) >= 3:
        confidence_assessment = (
            f"High — {len(agreeing)} independent agents corroborate the risk (peak agent confidence {max_conf:.2f})."
        )
    elif len(agreeing) == 2:
        confidence_assessment = f"Moderate — 2 agents agree on elevated risk (peak confidence {max_conf:.2f})."
    elif len(agreeing) == 1:
        confidence_assessment = (
            f"Low — only 1 agent flagged elevated risk (confidence {max_conf:.2f}); corroboration is weak."
        )
    else:
        confidence_assessment = "Minimal — no single agent reported elevated risk."

    # Investigation steps justified by the evidence types actually present.
    steps: list[str] = []
    for etype in types_present:
        step = _INVESTIGATION_STEPS.get(str(etype))
        if step and step not in steps:
            steps.append(step)
    if signal_evidence:
        steps.append("Search the mail flow for other recipients of the same campaign and contain as needed.")

    # False-positive indicators surfaced honestly from the evidence itself.
    fp: list[str] = []
    legitimacy_hits = [
        e for e in (evidence or [])
        if "transactional_legitimacy" in str(e.get("indicator") or "")
    ]
    if legitimacy_hits:
        fp.append("Message shows transactional-legitimacy signals (e.g. order/receipt patterns); confirm before blocking.")
    if len(agreeing) <= 1:
        fp.append("Weak corroboration — a single agent drove the score, which raises false-positive risk.")
    if 0.40 <= normalized_score <= 0.58:
        fp.append("Score sits near the suspicious/high-risk boundary; treat the verdict as provisional.")
    if not fp:
        fp.append("No strong false-positive indicators; evidence is consistent with the verdict.")

    summary = (
        f"Verdict '{verdict}' at risk {normalized_score:.2f}, supported by {len(signal_evidence)} concrete "
        f"detector signal(s) across {len(agents_present)} agent(s)."
    )
    if counterfactual and counterfactual.get("is_counterfactual"):
        summary += (
            f" Removing the findings of {', '.join(_cf_agent_names(counterfactual))} would drop the score to "
            f"{counterfactual.get('new_normalized_score')}, indicating they are the decisive signals."
        )

    return {
        "executive_summary": summary,
        "key_evidence": key_evidence,
        "confidence_assessment": confidence_assessment,
        "investigation_steps": steps,
        "false_positive_indicators": fp,
        "escalation_recommendation": _ESCALATION_BY_VERDICT.get(verdict, "Route to a SOC analyst for triage."),
        "source": "deterministic",
    }
