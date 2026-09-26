from soc_platform.domains.phishing.engine.orchestrator.counterfactual_engine import (
    calculate_counterfactual,
    threshold_for_verdict,
)


def test_counterfactual_finding():
    # Agent results whose weighted sum crosses the 0.6 blocking threshold
    agent_results_2 = [
        {"agent_name": "url_agent", "risk_score": 0.95},          # 0.95 * 0.20 = 0.19
        {"agent_name": "attachment_agent", "risk_score": 0.95},   # 0.95 * 0.15 = 0.1425
        {"agent_name": "sandbox_agent", "risk_score": 0.90},      # 0.90 * 0.10 = 0.09
        {"agent_name": "content_agent", "risk_score": 0.95},      # 0.95 * 0.20 = 0.19
    ]
    # Sum = 0.19 + 0.1425 + 0.09 + 0.19 = 0.6125 (High Risk, Blocked)
    
    correlation = {"correlation_score": 0.0}
    current_normalized = 0.6125
    
    res = calculate_counterfactual(agent_results_2, correlation, current_normalized, threshold=0.6)
    
    assert res["is_counterfactual"] is True
    # The highest contributor is url_agent (0.19) and content_agent (0.19).
    assert res["perturbation_model"] == "bounded_confidence_attenuation"
    # agents_altered is now a list of {agent_name, original_risk, attenuated_risk} dicts
    # (the shape the orchestrator narrative and the frontend chart both consume).
    altered_names = {entry["agent_name"] for entry in res["agents_altered"]}
    assert "url_agent" in altered_names or "content_agent" in altered_names
    for entry in res["agents_altered"]:
        assert set(entry.keys()) == {"agent_name", "original_risk", "attenuated_risk"}
        assert entry["attenuated_risk"] <= entry["original_risk"]
    assert res["new_normalized_score"] < 0.6

def test_counterfactual_already_safe():
    agent_results = [
        {"agent_name": "url_agent", "risk_score": 0.1},
    ]
    res = calculate_counterfactual(agent_results, {"correlation_score": 0.0}, 0.1, threshold=0.6)
    assert res["is_counterfactual"] is False
    assert res["reason"] == "score_already_below_boundary"


def test_threshold_for_verdict_policy() -> None:
    assert threshold_for_verdict("malicious") == 0.75
    assert threshold_for_verdict("high_risk") == 0.55
    assert threshold_for_verdict("suspicious") == 0.4
    assert threshold_for_verdict("likely_safe") == 0.1
