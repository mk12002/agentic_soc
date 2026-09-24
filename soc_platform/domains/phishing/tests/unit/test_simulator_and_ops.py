"""Tests for the read-only what-if verdict simulator (#13) and the ops
analytics endpoints (#7)."""

from __future__ import annotations

from fastapi.testclient import TestClient

from soc_platform.domains.phishing.engine.orchestrator.decision_engine.engine import (
    determine_verdict,
    simulate_verdict,
)
from soc_platform.domains.phishing.engine.api.main import app


def test_determine_verdict_bands() -> None:
    assert determine_verdict(0.9)[0] == "malicious"
    assert determine_verdict(0.6)[0] == "high_risk"
    assert determine_verdict(0.45)[0] == "suspicious"
    assert determine_verdict(0.2)[0] == "likely_safe"
    assert determine_verdict(0.0)[0] == "safe"


def test_simulate_verdict_is_monotonic_and_bounded() -> None:
    low = simulate_verdict({"content_agent": 0.05, "url_agent": 0.05})
    high = simulate_verdict({"content_agent": 0.95, "url_agent": 0.95, "attachment_agent": 0.95})
    assert 0.0 <= low["overall_risk_score"] <= 1.0
    assert high["overall_risk_score"] > low["overall_risk_score"]
    assert high["verdict"] in {"high_risk", "malicious"}
    assert set(high["thresholds"]) == {"malicious", "high_risk", "suspicious", "likely_safe"}
    # Input is clamped to [0,1].
    clamped = simulate_verdict({"url_agent": 5.0})
    assert clamped["input_scores"]["url_agent"] == 1.0


def test_simulate_verdict_endpoint() -> None:
    with TestClient(app) as client:
        resp = client.post(
            "/ops/simulate-verdict",
            json={"agent_scores": {"content_agent": 0.9, "url_agent": 0.8, "attachment_agent": 0.85}},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["verdict"] in {"high_risk", "malicious"}
        assert "thresholds" in body and "overall_risk_score" in body
        # Read-only: actions are advisory only, nothing is persisted.
        assert isinstance(body["recommended_actions"], list)


def test_ops_endpoints_registered_and_degrade_gracefully() -> None:
    # Without a live analytics DB these must return data (200) or a clean 503,
    # never an unhandled 500.
    with TestClient(app) as client:
        for path in (
            "/ops/agent-accuracy",
            "/ops/weight-recommendations",
            "/ops/drift-report",
            "/ops/feedback-summary",
        ):
            resp = client.get(path)
            assert resp.status_code in (200, 503), f"{path} -> {resp.status_code}"
