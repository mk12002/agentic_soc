"""
Threat Correlation Engine for the Agentic Email Security System.

Correlates findings across agents to identify coordinated attack patterns
using explicit combinatorial rules that amplify the score when multiple
high-risk agents agree on a threat vector.
"""

from __future__ import annotations

from typing import Any

from soc_platform.domains.phishing.engine.services.logging_service import get_service_logger

logger = get_service_logger("threat_correlation")

# Combinatorial correlation rules.
# Each rule: (agent_a, min_score_a, agent_b, min_score_b, score_boost, pattern_name)
_CORRELATION_RULES: list[tuple[str, float, str, float, float, str]] = [
    # Both content + URL flagged → dual-vector phishing
    ("content_agent", 0.6, "url_agent", 0.6, 0.20, "dual_vector_phishing"),
    # High content risk + suspicious header origin → social engineering
    ("content_agent", 0.7, "header_agent", 0.25, 0.15, "social_engineering_suspicious_origin"),
    # URL flagged + threat intel hit → known malicious infrastructure
    ("url_agent", 0.7, "threat_intel_agent", 0.1, 0.20, "known_malicious_infrastructure"),
    # Attachment malicious + sandbox confirms execution → confirmed malware delivery
    ("attachment_agent", 0.5, "sandbox_agent", 0.5, 0.25, "confirmed_malware_delivery"),
    # BEC pattern: financial content + unfamiliar sender behavioral risk
    ("content_agent", 0.6, "user_behavior_agent", 0.15, 0.10, "bec_financial_lure"),
]


def _get_agent_score(agent_results: list[dict[str, Any]], agent_name: str) -> float:
    for r in agent_results:
        if r.get("agent_name") == agent_name:
            return float(r.get("risk_score", 0.0))
    return 0.0


def correlate_threats(agent_results: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Correlate threat indicators across multiple agent results.

    Uses explicit combinatorial rules to produce a meaningful correlation
    score whenever two or more agents agree on a threat dimension.

    Returns:
        Correlation report with identified patterns and additive score boost.
    """
    logger.info("Correlating threats", agent_count=len(agent_results))

    patterns: list[str] = []
    rule_boosts: list[float] = []
    fired_rules: list[str] = []

    for agent_a, min_a, agent_b, min_b, boost, pattern in _CORRELATION_RULES:
        score_a = _get_agent_score(agent_results, agent_a)
        score_b = _get_agent_score(agent_results, agent_b)
        if score_a >= min_a and score_b >= min_b:
            patterns.append(pattern)
            rule_boosts.append(boost)
            fired_rules.append(f"{agent_a}+{agent_b}→{pattern}")

    # Legacy indicator-overlap check for backward compatibility
    normalized: dict[str, set[str]] = {}
    for result in agent_results:
        name = result.get("agent_name", "unknown")
        indicators = {
            str(item).split("::")[-1].split(":")[-1].strip().lower()
            for item in result.get("indicators", [])
            if str(item).strip()
        }
        normalized[name] = indicators

    overlap_counts: dict[str, int] = {}
    for indicator_set in normalized.values():
        for indicator in indicator_set:
            overlap_counts[indicator] = overlap_counts.get(indicator, 0) + 1

    correlated = [key for key, count in overlap_counts.items() if count >= 2]

    # Legacy patterns from indicator overlap
    if any("lookalike" in item or "spoof" in item for item in correlated):
        if "domain_spoofing_campaign" not in patterns:
            patterns.append("domain_spoofing_campaign")
    if any("macro" in item or "virtualalloc" in item or "risky_executable" in item for item in correlated):
        if "malware_delivery_pattern" not in patterns:
            patterns.append("malware_delivery_pattern")

    # Score: sum of triggered rule boosts (capped at 1.0)
    correlation_score = round(min(1.0, sum(rule_boosts)), 4)

    correlation = {
        "correlated_indicators": sorted(correlated),
        "attack_patterns": patterns,
        "fired_rules": fired_rules,
        "correlation_score": correlation_score,
    }

    logger.info(
        "Correlation complete",
        patterns_found=len(patterns),
        fired_rules=fired_rules,
        correlation_score=correlation_score,
    )
    return correlation
