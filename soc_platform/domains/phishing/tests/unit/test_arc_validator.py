"""Tests for ARC chain integrity and Received-hop forensics, and their
integration into the header agent and grounded evidence."""

from __future__ import annotations

from datetime import UTC, datetime

from soc_platform.domains.phishing.engine.agents.header_agent.agent import analyze as header_analyze
from soc_platform.domains.phishing.engine.agents.header_agent.arc_validator import (
    analyze_headers,
    analyze_received_hops,
    validate_arc_chain,
)
from soc_platform.domains.phishing.engine.orchestrator.evidence_collector import collect_evidence

# Pinned "now" so future-date checks are deterministic.
NOW = datetime(2026, 6, 18, 6, 0, 0, tzinfo=UTC)

CLEAN_CHAIN = [
    "from a.example by b.example; Wed, 18 Jun 2026 05:00:30 +0000",
    "from c.example by d.example; Wed, 18 Jun 2026 05:00:10 +0000",
    "from e.example by f.example; Wed, 18 Jun 2026 04:59:50 +0000",
]

# A lower (older-position) hop newer than the one above it = forged insertion.
OUT_OF_ORDER_CHAIN = [
    "from a by b; Wed, 18 Jun 2026 05:00:10 +0000",
    "from c by d; Wed, 18 Jun 2026 05:45:00 +0000",
]


def test_clean_received_chain_has_no_anomalies() -> None:
    result = analyze_received_hops(CLEAN_CHAIN, now=NOW)
    assert result["indicators"] == []
    assert result["risk_contribution"] == 0.0
    assert result["parsed_timestamps"] == 3


def test_out_of_order_received_chain_flagged() -> None:
    result = analyze_received_hops(OUT_OF_ORDER_CHAIN, now=NOW)
    assert "received_chain_out_of_order" in result["indicators"]
    assert result["risk_contribution"] > 0.0


def test_future_dated_hop_flagged() -> None:
    chain = ["from a by b; Wed, 18 Jun 2026 09:00:00 +0000"]  # 3h ahead of NOW
    result = analyze_received_hops(chain, now=NOW)
    assert "received_hop_future_dated" in result["indicators"]


def test_arc_valid_chain_not_flagged() -> None:
    arc = {
        "seal": ["i=1; cv=none; d=relay.example"],
        "message_signature": ["i=1; d=relay.example"],
        "authentication_results": ["i=1; spf=pass dkim=pass"],
    }
    result = validate_arc_chain(arc)
    assert result["present"] is True
    assert result["cv"] == "none"
    assert result["indicators"] == []


def test_arc_broken_cv_fail_flagged() -> None:
    arc = {
        "seal": ["i=1; cv=none", "i=2; cv=fail"],
        "message_signature": ["i=1", "i=2"],
        "authentication_results": ["i=1", "i=2"],
    }
    result = validate_arc_chain(arc)
    assert "arc_chain_broken:cv=fail" in result["indicators"]
    assert result["risk_contribution"] >= 0.5


def test_arc_noncontiguous_chain_flagged() -> None:
    arc = {
        "seal": ["i=1; cv=none", "i=3; cv=pass"],
        "message_signature": ["i=1", "i=3"],
        "authentication_results": ["i=1", "i=3"],
    }
    result = validate_arc_chain(arc)
    assert "arc_chain_noncontiguous" in result["indicators"]


def test_no_arc_present_is_neutral() -> None:
    assert validate_arc_chain(None)["present"] is False
    assert validate_arc_chain({})["risk_contribution"] == 0.0


def test_analyze_headers_combines_both() -> None:
    headers = {
        "received": OUT_OF_ORDER_CHAIN,
        "arc": {
            "seal": ["i=1; cv=none", "i=2; cv=fail"],
            "message_signature": ["i=1", "i=2"],
            "authentication_results": ["i=1", "i=2"],
        },
    }
    result = analyze_headers(headers, now=NOW)
    assert "received_chain_out_of_order" in result["indicators"]
    assert "arc_chain_broken:cv=fail" in result["indicators"]
    assert result["risk_contribution"] > 0.0


def test_header_agent_escalates_on_broken_arc_chain() -> None:
    payload = {
        "headers": {
            "sender": "ceo@example.com",
            "authentication_results": "spf=pass dkim=pass dmarc=pass",
            "received": CLEAN_CHAIN,
            "arc": {
                "seal": ["i=1; cv=none", "i=2; cv=fail"],
                "message_signature": ["i=1", "i=2"],
                "authentication_results": ["i=1", "i=2"],
            },
        },
        "body": {"plain": "Please action this wire."},
    }
    result = header_analyze(payload)
    indicators = [str(i) for i in result["indicators"]]
    assert any(i.startswith("arc_chain_broken") for i in indicators)
    # Broken ARC is malicious evidence, so it must raise risk above the benign floor.
    assert result["risk_score"] >= 0.4


def test_routing_forgery_becomes_grounded_evidence() -> None:
    agent_result = {
        "agent_name": "header_agent",
        "risk_score": 0.6,
        "confidence": 0.8,
        "indicators": ["arc_chain_broken:cv=fail", "received_chain_out_of_order"],
    }
    evidence = collect_evidence([agent_result])
    types = {e["type"] for e in evidence}
    assert "routing_forgery" in types
    # The concrete indicator survives into a citable claim.
    assert any("ARC chain validation failed" in e["claim"] for e in evidence)
