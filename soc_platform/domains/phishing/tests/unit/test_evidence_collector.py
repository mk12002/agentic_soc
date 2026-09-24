"""Unit tests for the grounded-reasoning evidence collector."""

from __future__ import annotations

from soc_platform.domains.phishing.engine.orchestrator.evidence_collector import collect_evidence, evidence_ids


def _sample_results():
    return [
        {
            "agent_name": "content_agent",
            "risk_score": 0.82,
            "confidence": 0.7,
            "indicators": ["financial_signals:invoice,payment,wire", "click_through_language"],
        },
        {
            "agent_name": "header_agent",
            "risk_score": 0.6,
            "confidence": 0.5,
            "indicators": ["spf_failed", "lookalike_domain:paypa1.com->paypal.com"],
        },
        {
            "agent_name": "url_agent",
            "risk_score": 0.4,
            "confidence": 0.4,
            "indicators": ["brand_impersonation:microsoft"],
        },
    ]


def test_evidence_has_stable_unique_ids():
    evidence = collect_evidence(_sample_results())
    ids = [e["id"] for e in evidence]
    assert len(ids) == len(set(ids))  # unique
    assert evidence_ids(evidence) == set(ids)


def test_every_evidence_record_is_grounded_in_a_real_value():
    evidence = collect_evidence(_sample_results())
    by_indicator = {e["indicator"]: e for e in evidence if e.get("indicator")}

    # The matched financial terms must be carried through verbatim — no fabrication.
    fin = by_indicator["financial_signals:invoice,payment,wire"]
    assert fin["raw_value"] == "invoice,payment,wire"
    assert fin["type"] == "content_pattern"
    assert "invoice,payment,wire" in fin["claim"]

    # Authentication signal with no value still produces faithful evidence.
    spf = by_indicator["spf_failed"]
    assert spf["type"] == "email_authentication"
    assert spf["agent"] == "header_agent"

    # Brand impersonation carries the concrete brand token.
    brand = by_indicator["brand_impersonation:microsoft"]
    assert brand["raw_value"] == "microsoft"
    assert "microsoft" in brand["claim"]


def test_unknown_indicator_still_becomes_faithful_evidence():
    evidence = collect_evidence(
        [{"agent_name": "url_agent", "risk_score": 0.5, "confidence": 0.5, "indicators": ["some_new_signal:xyz"]}]
    )
    match = [e for e in evidence if e.get("indicator") == "some_new_signal:xyz"]
    assert match, "unknown indicator should not be dropped"
    assert match[0]["raw_value"] == "xyz"
    assert match[0]["type"] == "indicator"


def test_per_agent_score_anchor_present():
    evidence = collect_evidence(_sample_results())
    anchors = [e for e in evidence if e["type"] == "agent_score"]
    assert {a["agent"] for a in anchors} == {"content_agent", "header_agent", "url_agent"}
    # Score anchor raw_value reflects the real risk score.
    content_anchor = next(a for a in anchors if a["agent"] == "content_agent")
    assert content_anchor["raw_value"].startswith("0.82")


def test_results_ordered_by_risk_and_capped():
    evidence = collect_evidence(_sample_results(), max_items=3)
    assert len(evidence) <= 3
    # Highest-risk agent (content_agent, 0.82) appears first.
    assert evidence[0]["agent"] == "content_agent"


def test_empty_input_returns_empty():
    assert collect_evidence([]) == []
    assert evidence_ids([]) == set()
