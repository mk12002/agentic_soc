"""
Evidence provenance chain — an auditable, ordered record of how a verdict was
reached, from raw detector signals through to the final classification.

Each step records its ``impact_on_score`` (signed, where known) and the concrete
``refs`` (agent names / evidence ids / guardrail names) it derives from. The chain
is built purely from data the orchestrator already computed, so it adds zero new
inference — it simply makes the existing decision path inspectable. This directly
supports auditability requirements (e.g. GDPR Art. 22, EU AI Act Art. 14): an
analyst can see, in order, every factor that raised or lowered the score.
"""

from __future__ import annotations

from typing import Any


def _cf_names(counterfactual: dict[str, Any] | None) -> list[str]:
    names: list[str] = []
    for entry in ((counterfactual or {}).get("agents_altered") or []):
        if isinstance(entry, dict):
            names.append(str(entry.get("agent_name", "unknown")))
        else:
            names.append(str(entry))
    return names


def build_provenance_chain(
    agent_results: list[dict[str, Any]],
    score_data: dict[str, Any] | None,
    correlation: dict[str, Any] | None,
    decision_audit_trail: list[dict[str, Any]] | None,
    counterfactual: dict[str, Any] | None,
    verdict: str,
    overall_score: float,
) -> list[dict[str, Any]]:
    """Assemble the ordered provenance chain for a single analysis."""
    chain: list[dict[str, Any]] = []
    contributions = (score_data or {}).get("agent_contributions", {}) or {}

    # 1. Raw detector signals → indicators (grouped per agent, in risk order).
    ordered_agents = sorted(
        agent_results or [],
        key=lambda r: float(r.get("risk_score", 0.0) or 0.0),
        reverse=True,
    )
    for r in ordered_agents:
        indicators = [str(i) for i in (r.get("indicators", []) or [])]
        if not indicators:
            continue
        chain.append({
            "stage": "raw_signals",
            "description": f"{r.get('agent_name', 'unknown')} extracted {len(indicators)} indicator(s) from the message.",
            "impact_on_score": None,
            "refs": indicators[:8],
        })

    # 2. Per-agent risk → weighted contribution to the fused score.
    for r in ordered_agents:
        name = str(r.get("agent_name", "unknown"))
        contrib = contributions.get(name, {})
        chain.append({
            "stage": "agent_score",
            "description": (
                f"{name} scored risk {float(r.get('risk_score', 0.0) or 0.0):.2f} "
                f"(weight {float(contrib.get('weight', 0.0) or 0.0):.2f})."
            ),
            "impact_on_score": round(float(contrib.get("contribution", 0.0) or 0.0), 4),
            "refs": [name],
        })

    # 3. Cross-agent correlation boost.
    corr_score = float((correlation or {}).get("correlation_score", 0.0) or 0.0)
    if corr_score > 0.0:
        patterns = (correlation or {}).get("patterns") or (correlation or {}).get("matched_patterns") or []
        chain.append({
            "stage": "correlation_boost",
            "description": "Cross-agent correlation reinforced the verdict (multiple vectors aligned).",
            "impact_on_score": round(corr_score, 4),
            "refs": [str(p) for p in patterns][:6],
        })

    # 4. Decision guardrails that adjusted the verdict.
    for entry in (decision_audit_trail or []):
        chain.append({
            "stage": "guardrail",
            "description": str(entry.get("explanation", entry.get("guardrail", "Decision guardrail applied."))),
            "impact_on_score": None,
            "refs": [str(entry.get("guardrail", "guardrail"))],
        })

    # 5. Counterfactual boundary (which agents were decisive).
    if counterfactual and counterfactual.get("is_counterfactual"):
        names = _cf_names(counterfactual)
        new_score = counterfactual.get("new_normalized_score")
        chain.append({
            "stage": "counterfactual",
            "description": (
                f"Removing {', '.join(names) or 'the flagged agents'} would lower the score to {new_score}, "
                "so these are the decisive signals."
            ),
            "impact_on_score": None,
            "refs": names,
        })

    # 6. Final verdict.
    chain.append({
        "stage": "verdict",
        "description": f"Final verdict '{verdict}' at overall risk {float(overall_score):.2f}.",
        "impact_on_score": round(float(overall_score), 4),
        "refs": [verdict],
    })

    return chain
