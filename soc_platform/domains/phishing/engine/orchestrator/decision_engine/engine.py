"""
Decision Engine for the Agentic Email Security System.

LEGACY CONVENIENCE MODULE — The production runtime uses the LangGraph
orchestrator workflow (langgraph_workflow.py) which encapsulates scoring,
correlation, counterfactual, reasoning, storyline, and action dispatch in
a unified graph.

This module is retained as a convenience wrapper for direct testing and
external callers that want a single-call decision without standing up the
full LangGraph pipeline.
"""

from typing import Any

from soc_platform.domains.phishing.engine.orchestrator.llm_reasoner import generate_reasoning
from soc_platform.domains.phishing.engine.orchestrator.scoring_engine import calculate_threat_score
from soc_platform.domains.phishing.engine.orchestrator.threat_correlation import correlate_threats
from soc_platform.domains.phishing.engine.orchestrator.counterfactual_engine import calculate_counterfactual, threshold_for_verdict
from soc_platform.domains.phishing.engine.orchestrator.storyline_engine import generate_storyline
from soc_platform.domains.phishing.engine.services.logging_service import get_service_logger

logger = get_service_logger("decision_engine")


def _contains_indicator(agent: dict[str, Any], token: str) -> bool:
    indicators = [str(item).lower() for item in (agent.get("indicators") or [])]
    return any(token in item for item in indicators)


def _has_hard_malicious_signal(agent_results: list[dict[str, Any]]) -> bool:
    for item in agent_results:
        name = str(item.get("agent_name") or "")
        risk = float(item.get("risk_score") or 0.0)

        if name in {"attachment_agent", "sandbox_agent"} and risk >= 0.75:
            return True
        if name == "threat_intel_agent" and risk >= 0.6:
            return True
        if name == "header_agent" and risk >= 0.5:
            return True
    return False


def _has_strong_transactional_legitimacy(agent_results: list[dict[str, Any]]) -> bool:
    strong_votes = 0
    for item in agent_results:
        if _contains_indicator(item, "transactional_legitimacy_profile:strong"):
            strong_votes += 1
    return strong_votes >= 2


def _has_weak_malicious_compound_warning(agent_results: list[dict[str, Any]]) -> bool:
    content = next((item for item in agent_results if str(item.get("agent_name")) == "content_agent"), None)
    header = next((item for item in agent_results if str(item.get("agent_name")) == "header_agent"), None)
    url = next((item for item in agent_results if str(item.get("agent_name")) == "url_agent"), None)
    user_behavior = next((item for item in agent_results if str(item.get("agent_name")) == "user_behavior_agent"), None)

    if not header or not user_behavior:
        return False

    header_risk = float(header.get("risk_score") or 0.0)
    content_risk = float(content.get("risk_score") or 0.0) if content is not None else 0.0
    url_risk = float(url.get("risk_score") or 0.0) if url is not None else 0.0
    user_risk = float(user_behavior.get("risk_score") or 0.0)

    header_warning = header_risk >= 0.12 and any(
        _contains_indicator(header, token)
        for token in (
            "authentication_results_missing",
            "reply_to_domain_mismatch",
            "no_auth_headers_with_domain",
            "lookalike_domain",
            "dmarc_failed",
        )
    )
    content_warning = content is not None and content_risk >= 0.05 and (
        _contains_indicator(content, "financial_signals:")
        or _contains_indicator(content, "credential_signals:")
        or _contains_indicator(content, "spam_marketing_signals:")
        or _contains_indicator(content, "long_email_body")
    )
    url_warning = url is not None and url_risk >= 0.05 and (
        _contains_indicator(url, "many_urls:")
        or _contains_indicator(url, "non_https_url")
        or _contains_indicator(url, "brand_impersonation")
        or _contains_indicator(url, "credential_bait")
    )
    user_warning = user_risk >= 0.25 and _contains_indicator(user_behavior, "unfamiliar_sender_domain")

    warning_votes = sum((header_warning, content_warning, url_warning, user_warning))
    if warning_votes < 3 or not (header_warning and user_warning):
        return False

    return True


def _has_uncertain_conflict_pattern(agent_results: list[dict[str, Any]], normalized_score: float) -> bool:
    """Identify evidence disagreement strong enough to force manual review."""
    if normalized_score >= 0.4:
        return False

    informative = [
        item
        for item in agent_results
        if float(item.get("confidence") or 0.0) >= 0.7
    ]
    if len(informative) < 3:
        return False

    scores = [float(item.get("risk_score") or 0.0) for item in informative]
    high_votes = sum(1 for score in scores if score >= 0.65)
    low_votes = sum(1 for score in scores if score <= 0.2)
    spread = max(scores) - min(scores)

    return high_votes >= 1 and low_votes >= 2 and spread >= 0.45


def _has_strong_multi_agent_malicious_consensus(agent_results: list[dict[str, Any]]) -> bool:
    """Detect when 4+ agents show strong agreement on malicious signals (0.4+)."""
    high_risk_agents = [
        item for item in agent_results
        if float(item.get("risk_score") or 0.0) >= 0.4
        and float(item.get("confidence") or 0.0) >= 0.65
    ]
    return len(high_risk_agents) >= 4



def _apply_transactional_legitimacy_override(
    verdict: str,
    actions: list[str],
    normalized_score: float,
    agent_results: list[dict[str, Any]],
) -> tuple[str, list[str], float, bool]:
    if (
        verdict in {"suspicious", "high_risk"}
        and _has_strong_transactional_legitimacy(agent_results)
        and not _has_hard_malicious_signal(agent_results)
    ):
        return "likely_safe", ["deliver_with_banner"], min(normalized_score, 0.39), True
    return verdict, actions, normalized_score, False


# Verdict bands (cutoff inclusive, highest first). Single source of truth shared by
# make_decision and the read-only what-if simulator so they can never drift apart.
VERDICT_BANDS: list[tuple[float, str, list[str]]] = [
    (0.75, "malicious", ["quarantine", "block_sender", "trigger_garuda"]),
    (0.55, "high_risk", ["quarantine", "soc_alert", "trigger_garuda"]),
    (0.40, "suspicious", ["manual_review", "soc_alert"]),
    (0.10, "likely_safe", ["deliver_with_banner"]),
    (0.00, "safe", ["deliver"]),
]

VERDICT_THRESHOLDS = {"malicious": 0.75, "high_risk": 0.55, "suspicious": 0.40, "likely_safe": 0.10}


def determine_verdict(normalized_score: float) -> tuple[str, list[str]]:
    """Map a normalized risk score to (verdict, recommended_actions) using the bands."""
    for cutoff, verdict, actions in VERDICT_BANDS:
        if normalized_score >= cutoff:
            return verdict, list(actions)
    return "safe", ["deliver"]


def simulate_verdict(agent_scores: dict[str, float]) -> dict[str, Any]:
    """
    Read-only "what-if" verdict simulation for analysts.

    Given hypothetical per-agent risk scores (e.g. from UI sliders), reproduce the
    exact scoring path — weighted fusion + correlation boost + threshold mapping —
    used by the live engine, with **no persistence and no actions**. Indicator-driven
    guardrails are intentionally not applied (sliders carry no indicators), so the
    result reflects the pure score→threshold relationship the analyst is exploring.
    """
    agent_results = [
        {
            "agent_name": str(name),
            "risk_score": max(0.0, min(1.0, float(score))),
            "confidence": 0.8,
            "indicators": [],
        }
        for name, score in (agent_scores or {}).items()
    ]
    score_data = calculate_threat_score(agent_results)
    correlation = correlate_threats(agent_results)
    normalized = round(min(1.0, score_data["overall_score"] + (0.2 * correlation["correlation_score"])), 4)
    verdict, actions = determine_verdict(normalized)
    return {
        "input_scores": {r["agent_name"]: r["risk_score"] for r in agent_results},
        "overall_risk_score": normalized,
        "verdict": verdict,
        "recommended_actions": actions,
        "thresholds": dict(VERDICT_THRESHOLDS),
        "agent_contributions": score_data.get("agent_contributions", {}),
        "correlation_score": round(float(correlation.get("correlation_score", 0.0) or 0.0), 4),
        "note": "Read-only what-if simulation reflecting the score→threshold mapping; indicator-driven guardrails are not applied.",
    }


def make_decision(agent_results: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Aggregate agent results and produce a final threat decision.

    This is a standalone convenience function that mirrors the LangGraph
    workflow logic.  For production use, prefer :class:`LangGraphOrchestrator`.

    Args:
        agent_results: List of standardized agent result dictionaries.

    Returns:
        Final decision with overall risk score, verdict, and recommended actions.
    """
    logger.info("Making decision", agent_count=len(agent_results))

    score_data = calculate_threat_score(agent_results)
    correlation = correlate_threats(agent_results)
    normalized_score = min(1.0, score_data["overall_score"] + (0.2 * correlation["correlation_score"]))

    verdict, actions = determine_verdict(normalized_score)

    verdict, actions, normalized_score, downgraded = _apply_transactional_legitimacy_override(
        verdict,
        actions,
        normalized_score,
        agent_results,
    )
    if downgraded:
        logger.info("Applied transactional legitimacy downgrade", verdict=verdict)

    # Strong multi-agent consensus escalation
    if _has_strong_multi_agent_malicious_consensus(agent_results) and normalized_score < 0.75:
        if normalized_score >= 0.5:
            # Already high_risk or suspicious with strong consensus -> escalate to malicious
            verdict = "malicious"
            actions = ["quarantine", "block_sender", "trigger_garuda"]
            normalized_score = max(normalized_score, 0.75)
            logger.info("Applied strong multi-agent consensus escalation to malicious", consensus_count=len(agent_results))
        elif normalized_score >= 0.35:
            # Suspicious with strong consensus -> escalate to high_risk
            verdict = "high_risk"
            actions = ["quarantine", "soc_alert", "trigger_garuda"]
            normalized_score = max(normalized_score, 0.55)
            logger.info("Applied strong multi-agent consensus escalation to high_risk", consensus_count=len(agent_results))

    if (
        verdict in {"safe", "likely_safe"}
        and _has_weak_malicious_compound_warning(agent_results)
        and not _has_hard_malicious_signal(agent_results)
        and not _has_strong_transactional_legitimacy(agent_results)
    ):
        verdict = "suspicious"
        actions = ["manual_review", "soc_alert"]
        normalized_score = max(normalized_score, 0.42)
        logger.info("Applied compound delivery-warning escalation", verdict=verdict)

    if verdict in {"safe", "likely_safe"} and _has_uncertain_conflict_pattern(agent_results, normalized_score):
        verdict = "suspicious"
        actions = ["manual_review"]
        normalized_score = max(normalized_score, 0.4)
        logger.info("Applied uncertain conflict guardrail", verdict=verdict)

    # Counterfactual analysis
    threshold = threshold_for_verdict(verdict)
    if threshold is not None:
        counterfactual = calculate_counterfactual(
            agent_results=agent_results,
            correlation=correlation,
            current_normalized_score=normalized_score,
            threshold=threshold,
        )
    else:
        counterfactual = {"is_counterfactual": False, "reason": "no_blocking_boundary"}

    # LLM reasoning (falls back to deterministic if Azure OpenAI is unavailable)
    llm_explanation = generate_reasoning(agent_results, normalized_score, counterfactual)

    # Threat storyline
    storyline = generate_storyline(agent_results, verdict, actions)

    decision = {
        "overall_risk_score": round(normalized_score, 4),
        "verdict": verdict,
        "recommended_actions": actions,
        "threat_level": score_data["threat_level"],
        "correlation": correlation,
        "counterfactual_result": counterfactual,
        "threat_storyline": storyline,
        "llm_explanation": llm_explanation,
        "agent_results": agent_results,
    }

    logger.info("Decision made", verdict=decision["verdict"])
    return decision
