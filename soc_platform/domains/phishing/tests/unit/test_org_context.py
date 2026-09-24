"""Tests for organizational risk-context scoring (#14)."""

from __future__ import annotations

import pytest

from soc_platform.domains.phishing.engine.services.org_context import (
    apply_org_context,
    classify_recipient_role,
    get_recipient_risk_multiplier,
)
from soc_platform.domains.phishing.engine.orchestrator.langgraph_workflow import LangGraphOrchestrator


def test_classify_recipient_role() -> None:
    assert classify_recipient_role("cfo@acme.com") == "executive"
    assert classify_recipient_role("accounts.payable@acme.com") == "finance"
    assert classify_recipient_role("sysadmin@acme.com") == "it_admin"
    assert classify_recipient_role("jane.doe@acme.com") == "general"


def test_multiplier_picks_highest_value_target() -> None:
    info = get_recipient_risk_multiplier(["jane.doe@acme.com", "cfo@acme.com"])
    assert info["highest_role"] == "executive"
    assert info["multiplier"] > 1.0


def test_apply_org_context_raises_score_for_high_value_target() -> None:
    res = apply_org_context(0.5, ["cfo@acme.com"])
    assert res["applied"] is True
    assert res["adjusted_score"] > 0.5
    assert res["adjusted_score"] <= 1.0


def test_apply_org_context_noop_for_general_recipient() -> None:
    res = apply_org_context(0.5, ["jane.doe@acme.com"])
    assert res["applied"] is False
    assert res["adjusted_score"] == 0.5


def test_apply_org_context_noop_when_no_recipients() -> None:
    res = apply_org_context(0.7, [])
    assert res["applied"] is False
    assert res["adjusted_score"] == 0.7


def test_score_node_applies_org_context_when_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    # Patch the same settings object the workflow imports at runtime
    # (``from soc_platform.domains.phishing.engine.configs.settings import settings``), not the dual-path alias.
    from soc_platform.domains.phishing.engine.configs.settings import settings as live_settings

    monkeypatch.setattr(live_settings, "org_context_enabled", True, raising=False)
    graph = LangGraphOrchestrator(save_report=lambda _i, _d: None, execute_actions=lambda _d: None)

    agent_results = [
        {"agent_name": "content_agent", "risk_score": 0.5, "confidence": 0.8, "indicators": ["urgency_signals:urgent"]},
        {"agent_name": "url_agent", "risk_score": 0.5, "confidence": 0.8, "indicators": ["credential_bait_terms"]},
    ]
    baseline = graph._score_node({"agent_results": agent_results})["score_data"]["overall_score"]
    targeted = graph._score_node({
        "agent_results": agent_results,
        "recipients": ["cfo@acme.com"],
    })["score_data"]
    assert targeted["overall_score"] >= baseline
    assert targeted.get("org_context", {}).get("highest_role") == "executive"


def test_score_node_unchanged_when_disabled() -> None:
    # Default settings (org_context_enabled=False): recipients must not change the score.
    graph = LangGraphOrchestrator(save_report=lambda _i, _d: None, execute_actions=lambda _d: None)
    agent_results = [{"agent_name": "content_agent", "risk_score": 0.5, "confidence": 0.8, "indicators": []}]
    base = graph._score_node({"agent_results": agent_results})["score_data"]["overall_score"]
    with_recip = graph._score_node({"agent_results": agent_results, "recipients": ["cfo@acme.com"]})["score_data"]
    assert with_recip["overall_score"] == base
    assert "org_context" not in with_recip
