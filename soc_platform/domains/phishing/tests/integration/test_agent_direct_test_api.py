"""Tests for isolated per-agent direct testing API endpoints."""

from __future__ import annotations

from fastapi.testclient import TestClient

from soc_platform.domains.phishing.engine.api import main as api_main


def test_list_testable_agents() -> None:
    client = TestClient(api_main.app)
    resp = client.get("/agent-test/agents")

    assert resp.status_code == 200
    body = resp.json()
    assert "supported_agents" in body
    assert "header_agent" in body["supported_agents"]


def test_agent_test_examples_endpoint() -> None:
    client = TestClient(api_main.app)
    resp = client.get("/agent-test/examples")

    assert resp.status_code == 200
    body = resp.json()
    assert "examples" in body
    assert "content_agent" in body["examples"]
    assert "payload" in body["usage"]["body"]



def test_direct_agent_test_success_with_injected_analysis_id(monkeypatch) -> None:
    def _fake_analyze(payload: dict):
        assert payload.get("analysis_id")
        return {
            "agent_name": "content_agent",
            "risk_score": 0.42,
            "confidence": 0.88,
            "indicators": ["test_indicator"],
        }

    monkeypatch.setattr(api_main, "_get_agent_test_function", lambda _name: _fake_analyze)

    client = TestClient(api_main.app)
    resp = client.post(
        "/agent-test/content_agent",
        json={
            "payload": {
                "body": "urgent update your password",
                "headers": {"subject": "Important"},
            },
            "inject_analysis_id": True,
            "print_output": False,
        },
    )

    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "completed"
    assert body["agent_name"] == "content_agent"
    assert body["input_payload"]["analysis_id"].startswith("manual-agent-test-")
    assert body["output"]["risk_score"] == 0.42



def test_direct_agent_test_unsupported_agent(monkeypatch) -> None:
    from fastapi import HTTPException

    def _raise(_name: str):
        raise HTTPException(status_code=404, detail="Unsupported agent")

    monkeypatch.setattr(api_main, "_get_agent_test_function", _raise)

    client = TestClient(api_main.app)
    resp = client.post("/agent-test/nonexistent_agent", json={"payload": {}})

    assert resp.status_code == 404
