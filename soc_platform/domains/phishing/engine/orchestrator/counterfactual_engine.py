"""
Counterfactual Engine.

Calculates the minimum perturbation required to revert a malicious decision
into a safe decision for explainability.
"""

from typing import Any
import copy

from soc_platform.domains.phishing.engine.orchestrator.scoring_engine.scorer import calculate_threat_score
from soc_platform.domains.phishing.engine.services.logging_service import get_service_logger

logger = get_service_logger("counterfactual_engine")


def _clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))


def threshold_for_verdict(verdict: str) -> float | None:
    """Return the policy boundary that must be crossed to lower the current verdict."""
    value = str(verdict or "").strip().lower()
    if value == "malicious":
        return 0.75
    if value == "high_risk":
        return 0.55
    if value == "suspicious":
        return 0.4
    if value == "likely_safe":
        return 0.1
    return None


def _attenuate_risk(risk_score: float, confidence: float) -> float:
    """Apply bounded, confidence-aware attenuation without forcing risk to zero."""
    risk = _clamp(float(risk_score or 0.0), 0.0, 1.0)
    conf = _clamp(float(confidence or 0.0), 0.0, 1.0)

    # Higher-confidence findings are harder to perturb, lower-confidence findings
    # can be attenuated more. Retain at least 20% of original risk.
    max_drop = 0.65
    confidence_factor = 1.0 - (0.5 * conf)
    applied_drop = _clamp(max_drop * confidence_factor, 0.0, max_drop)
    attenuated = risk * (1.0 - applied_drop)
    return round(max(0.2 * risk, attenuated), 4)


def calculate_counterfactual(
    agent_results: list[dict[str, Any]],
    correlation: dict[str, Any],
    current_normalized_score: float,
    threshold: float,
) -> dict[str, Any]:
    """
    Determines the minimum changes to agent scores required to bring the
    overall normalized score below the blocking threshold.
    """
    if current_normalized_score < threshold:
        logger.debug("Score already below threshold, no counterfactual needed.")
        return {
            "is_counterfactual": False,
            "threshold": threshold,
            "reason": "score_already_below_boundary",
        }

    # Get initial contributions to order by impact
    initial_score_data = calculate_threat_score(agent_results)
    contributions = initial_score_data.get("agent_contributions", {})

    sorted_agents = sorted(
        contributions.keys(),
        key=lambda x: contributions[x].get("contribution", 0.0),
        reverse=True,
    )

    corr_score = float(correlation.get("correlation_score", 0.0))
    modified_agents = []

    for agent_name in sorted_agents:
        modified_agents.append(agent_name)

        # Create perturbed results using bounded confidence-aware attenuation.
        perturbed_results = copy.deepcopy(agent_results)
        for res in perturbed_results:
            if res.get("agent_name") in modified_agents:
                res["risk_score"] = _attenuate_risk(
                    risk_score=float(res.get("risk_score", 0.0) or 0.0),
                    confidence=float(res.get("confidence", 0.0) or 0.0),
                )

        new_score_data = calculate_threat_score(perturbed_results)
        new_overall = float(new_score_data.get("overall_score", 0.0))
        new_normalized = min(1.0, new_overall + (0.2 * corr_score))

        if new_normalized < threshold:
            logger.info("Found counterfactual flip point", altered=modified_agents, new_score=new_normalized)
            # Emit structured deltas: {agent_name, original_risk, attenuated_risk}. Both the orchestrator
            # narrative (_reason_node) and the frontend counterfactual chart consume this dict shape.
            original_by_agent = {
                str(r.get("agent_name")): float(r.get("risk_score", 0.0) or 0.0) for r in agent_results
            }
            confidence_by_agent = {
                str(r.get("agent_name")): float(r.get("confidence", 0.0) or 0.0) for r in agent_results
            }
            agents_altered = [
                {
                    "agent_name": name,
                    "original_risk": round(original_by_agent.get(name, 0.0), 4),
                    "attenuated_risk": _attenuate_risk(
                        original_by_agent.get(name, 0.0),
                        confidence_by_agent.get(name, 0.0),
                    ),
                }
                for name in modified_agents
            ]
            return {
                "is_counterfactual": True,
                "agents_altered": agents_altered,
                "new_normalized_score": round(new_normalized, 4),
                "threshold": threshold,
                "perturbation_model": "bounded_confidence_attenuation",
            }

    logger.info("Could not find single-agent counterfactual flip")
    return {
        "is_counterfactual": False,
        "threshold": threshold,
        "perturbation_model": "bounded_confidence_attenuation",
        "reason": "cannot_lower_score_sufficiently",
    }
