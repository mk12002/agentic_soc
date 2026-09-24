"""
Scoring Engine for the Agentic Email Security System.

Calculates weighted threat scores from individual agent risk assessments.
"""

from typing import Any

from soc_platform.domains.phishing.engine.services.logging_service import get_service_logger

logger = get_service_logger("scoring_engine")

# Default agent weights (sum to 1.0)
DEFAULT_WEIGHTS = {
    "header_agent": 0.15,
    "content_agent": 0.20,
    "url_agent": 0.20,
    "attachment_agent": 0.15,
    "sandbox_agent": 0.10,
    "threat_intel_agent": 0.10,
    "user_behavior_agent": 0.10,
}


def calculate_threat_score(
    agent_results: list[dict[str, Any]],
    weights: dict[str, float] | None = None,
) -> dict[str, Any]:
    """
    Calculate a weighted overall threat score from agent results.

    Args:
        agent_results: List of standardized agent result dictionaries.
        weights: Optional custom weight mapping per agent.

    Returns:
        Scoring result with weighted score, per-agent contributions, and threat level.
    """
    weights = weights or DEFAULT_WEIGHTS

    logger.info("Calculating threat score", agent_count=len(agent_results))

    weighted_sum = 0.0
    contributions = {}

    for result in agent_results:
        agent_name = result.get("agent_name", "unknown")
        risk_score = result.get("risk_score", 0.0)
        weight = weights.get(agent_name, 0.0)

        contribution = risk_score * weight
        weighted_sum += contribution
        contributions[agent_name] = {
            "risk_score": risk_score,
            "weight": weight,
            "contribution": contribution,
        }

    max_single_risk = max([c["risk_score"] for c in contributions.values()] or [0.0])
    
    # Consensus amplification: when multiple agents agree, boost the score
    high_signal_agents = sum(1 for c in contributions.values() if c["risk_score"] >= 0.4)
    if high_signal_agents >= 3:
        # Multiple agents agree on significant risk - amplify the consensus signal
        consensus_boost = min(0.25, 0.08 * high_signal_agents)
        weighted_sum = min(1.0, weighted_sum + consensus_boost)
    
    # Only very strong single-agent evidence should completely override the fused score.
    if max_single_risk >= 0.80:
        weighted_sum = max(weighted_sum, max_single_risk)
    else:
        # Prevent severe dilution from safe agents. If one agent detects moderate risk,
        # the overall score should at least reflect a baseline suspicion.
        weighted_sum = max(weighted_sum, max_single_risk * 0.8)

    # Determine threat level
    if weighted_sum >= 0.8:
        threat_level = "critical"
    elif weighted_sum >= 0.6:
        threat_level = "high"
    elif weighted_sum >= 0.4:
        threat_level = "medium"
    elif weighted_sum >= 0.2:
        threat_level = "low"
    else:
        threat_level = "safe"

    score_result = {
        "overall_score": round(weighted_sum, 4),
        "threat_level": threat_level,
        "agent_contributions": contributions,
    }

    logger.info(
        "Threat score calculated",
        score=score_result["overall_score"],
        level=threat_level,
    )
    return score_result
