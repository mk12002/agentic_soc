"""Regression tests for the counterfactual narrative (G6 bug fix).

Previously ``agents_altered`` was a list of strings while both the orchestrator narrative builder and the
frontend chart expected a list of ``{agent_name, original_risk, attenuated_risk}`` dicts, so the narrative
silently fell back to a generic message. These tests lock in the corrected dict contract.
"""

from __future__ import annotations

import soc_platform.domains.phishing.engine.orchestrator.llm_reasoner as reasoner
from soc_platform.domains.phishing.engine.orchestrator.counterfactual_engine import calculate_counterfactual


def _blocking_results():
    # Low/zero confidence keeps the findings perturbable so a counterfactual flip exists
    # (high-confidence findings are intentionally hard to attenuate, per _attenuate_risk).
    return [
        {"agent_name": "url_agent", "risk_score": 0.95},
        {"agent_name": "attachment_agent", "risk_score": 0.95},
        {"agent_name": "sandbox_agent", "risk_score": 0.90},
        {"agent_name": "content_agent", "risk_score": 0.95},
    ]


def test_engine_emits_structured_agent_deltas():
    res = calculate_counterfactual(_blocking_results(), {"correlation_score": 0.0}, 0.6125, threshold=0.6)
    assert res["is_counterfactual"] is True
    altered = res["agents_altered"]
    assert isinstance(altered, list) and altered
    for entry in altered:
        assert isinstance(entry, dict)
        assert {"agent_name", "original_risk", "attenuated_risk"} == set(entry)
        assert 0.0 <= entry["attenuated_risk"] <= entry["original_risk"] <= 1.0


def test_narrative_loop_does_not_raise_on_dict_shape():
    """Reproduce the orchestrator narrative-building loop that used to throw on string items."""
    res = calculate_counterfactual(_blocking_results(), {"correlation_score": 0.0}, 0.6125, threshold=0.6)

    parts = []
    for agent_delta in res.get("agents_altered", []):
        # This is exactly the access pattern in langgraph_workflow._reason_node.
        name = agent_delta.get("agent_name", "unknown")
        orig = float(agent_delta.get("original_risk", 0) or 0)
        new = float(agent_delta.get("attenuated_risk", 0) or 0)
        parts.append(f"{name} (risk {orig:.2f} -> {new:.2f})")

    assert parts, "narrative parts should be populated, not silently empty"
    assert all("unknown" not in p for p in parts)


def test_explain_counterfactual_offline_includes_data(monkeypatch):
    monkeypatch.setattr(reasoner.settings, "azure_openai_endpoint", None, raising=False)
    res = calculate_counterfactual(_blocking_results(), {"correlation_score": 0.0}, 0.6125, threshold=0.6)
    text = reasoner.explain_counterfactual(res)
    # Offline fallback surfaces the raw counterfactual rather than crashing.
    assert "Raw Counterfactual" in text
