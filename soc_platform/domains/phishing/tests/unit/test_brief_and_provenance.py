"""Tests for the structured analyst brief (#6) and evidence provenance chain (#3),
including their integration into the orchestrator reason node."""

from __future__ import annotations

from soc_platform.domains.phishing.engine.orchestrator.evidence_collector import collect_evidence
from soc_platform.domains.phishing.engine.orchestrator.llm_reasoner import generate_structured_brief
from soc_platform.domains.phishing.engine.orchestrator.provenance_chain import build_provenance_chain
from soc_platform.domains.phishing.engine.orchestrator.langgraph_workflow import LangGraphOrchestrator


AGENT_RESULTS = [
    {
        "agent_name": "header_agent",
        "risk_score": 0.85,
        "confidence": 0.82,
        "indicators": ["spf_failed", "unicode_domain_spoofing:pаypal.com->paypal.com"],
    },
    {
        "agent_name": "url_agent",
        "risk_score": 0.74,
        "confidence": 0.80,
        "indicators": ["homoglyph_attack:pаypal.com->paypal.com", "credential_bait_terms"],
    },
    {
        "agent_name": "content_agent",
        "risk_score": 0.66,
        "confidence": 0.7,
        "indicators": ["credential_signals:password,login"],
    },
]


def test_brief_is_grounded_and_complete() -> None:
    evidence = collect_evidence(AGENT_RESULTS)
    brief = generate_structured_brief(AGENT_RESULTS, 0.81, evidence, "malicious")

    assert brief["executive_summary"]
    assert brief["escalation_recommendation"]
    assert brief["confidence_assessment"].startswith("High")  # 3 agents agree
    assert brief["investigation_steps"]
    assert brief["false_positive_indicators"]

    # Every key-evidence item must reference a real collected evidence id.
    valid_ids = {e["id"] for e in evidence}
    assert brief["key_evidence"]
    for item in brief["key_evidence"]:
        assert item["evidence_id"] in valid_ids
        assert item["agent"] in {"header_agent", "url_agent", "content_agent"}


def test_brief_flags_weak_corroboration() -> None:
    single = [AGENT_RESULTS[0]]
    evidence = collect_evidence(single)
    brief = generate_structured_brief(single, 0.5, evidence, "suspicious")
    assert brief["confidence_assessment"].startswith("Low")
    assert any("Weak corroboration" in fp or "single agent" in fp.lower()
               for fp in brief["false_positive_indicators"])


def test_provenance_chain_is_ordered_and_terminates_in_verdict() -> None:
    evidence = collect_evidence(AGENT_RESULTS)  # noqa: F841 (kept for parity)
    score_data = {
        "agent_contributions": {
            "header_agent": {"risk_score": 0.85, "weight": 0.15, "contribution": 0.1275},
            "url_agent": {"risk_score": 0.74, "weight": 0.20, "contribution": 0.148},
            "content_agent": {"risk_score": 0.66, "weight": 0.20, "contribution": 0.132},
        }
    }
    chain = build_provenance_chain(
        agent_results=AGENT_RESULTS,
        score_data=score_data,
        correlation={"correlation_score": 0.2, "patterns": ["dual_vector_phishing"]},
        decision_audit_trail=[{"guardrail": "g1", "explanation": "Escalated for X."}],
        counterfactual={"is_counterfactual": True, "agents_altered": [{"agent_name": "url_agent"}],
                        "new_normalized_score": 0.3},
        verdict="malicious",
        overall_score=0.81,
    )
    stages = [step["stage"] for step in chain]
    assert stages[0] == "raw_signals"
    assert "agent_score" in stages
    assert "correlation_boost" in stages
    assert "guardrail" in stages
    assert "counterfactual" in stages
    assert stages[-1] == "verdict"
    # agent_score steps carry a concrete signed impact.
    agent_steps = [s for s in chain if s["stage"] == "agent_score"]
    assert all(isinstance(s["impact_on_score"], float) for s in agent_steps)


def test_reason_node_emits_brief_and_provenance() -> None:
    graph = LangGraphOrchestrator(save_report=lambda _i, _d: None, execute_actions=lambda _d: None)
    state = {
        "analysis_id": "brief-prov-1",
        "normalized_score": 0.81,
        "correlation": {"correlation_score": 0.2, "patterns": ["dual_vector_phishing"]},
        "verdict": "malicious",
        "recommended_actions": ["quarantine", "soc_alert"],
        "score_data": {"agent_contributions": {
            "header_agent": {"risk_score": 0.85, "weight": 0.15, "contribution": 0.1275},
        }},
        "agent_results": AGENT_RESULTS,
    }
    reason = graph._reason_node(state)
    brief = reason.get("analyst_brief")
    prov = reason.get("provenance_chain")
    assert isinstance(brief, dict) and brief.get("executive_summary")
    assert isinstance(prov, list) and prov and prov[-1]["stage"] == "verdict"
