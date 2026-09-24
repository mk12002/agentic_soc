"""Tests for Garuda integration trigger and retry behavior."""

from __future__ import annotations

from typing import Any

from soc_platform.domains.phishing.engine.garuda_integration import retry_queue
from soc_platform.domains.phishing.engine.garuda_integration import bridge
from soc_platform.domains.phishing.engine.orchestrator.langgraph_workflow import LangGraphOrchestrator


def test_trigger_garuda_investigation_success(monkeypatch) -> None:
    captured: dict[str, Any] = {}

    class _FakeResponse:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, Any]:
            return {"ticket": "g-123"}

    class _FakeClient:
        def __init__(self, timeout: float):
            self.timeout = timeout

        def __enter__(self) -> "_FakeClient":
            return self

        def __exit__(self, _exc_type, _exc, _tb) -> None:
            return None

        def post(self, url: str, json: dict[str, Any]) -> _FakeResponse:
            captured["url"] = url
            captured["payload"] = json
            return _FakeResponse()

    monkeypatch.setattr(bridge.httpx, "Client", _FakeClient)

    decision = {
        "analysis_id": "a-1",
        "verdict": "malicious",
        "overall_risk_score": 0.92,
        "agent_results": [
            {"indicators": [f"ioc-{i}" for i in range(60)]},
        ],
    }

    result = bridge.trigger_garuda_investigation(decision)

    assert result["status"] == "triggered"
    assert result["response"]["ticket"] == "g-123"
    assert captured["url"].endswith("/investigate")
    assert len(captured["payload"]["iocs"]["indicators"]) == 50


def test_trigger_garuda_investigation_queues_retry_on_failure(monkeypatch) -> None:
    calls: dict[str, Any] = {}

    class _FailingClient:
        def __init__(self, timeout: float):
            self.timeout = timeout

        def __enter__(self) -> "_FailingClient":
            return self

        def __exit__(self, _exc_type, _exc, _tb) -> None:
            return None

        def post(self, _url: str, json: dict[str, Any]):
            calls["payload"] = json
            raise RuntimeError("garuda down")

    monkeypatch.setattr(bridge.httpx, "Client", _FailingClient)
    monkeypatch.setattr(
        bridge,
        "enqueue_garuda_retry",
        lambda decision, error, attempt=0: calls.update(
            {"analysis_id": decision.get("analysis_id"), "error": error, "attempt": attempt}
        )
        or True,
    )

    decision = {
        "analysis_id": "a-2",
        "verdict": "high_risk",
        "overall_risk_score": 0.81,
        "agent_results": [{"indicators": ["ioc-a"]}],
    }

    result = bridge.trigger_garuda_investigation(decision)

    assert result["status"] == "queued_retry"
    assert "queued for retry" in result["response"]["message"]
    assert calls["analysis_id"] == "a-2"
    assert calls["attempt"] == 0
    assert "garuda down" in calls["error"]


def test_orchestrator_includes_garuda_feedback_for_high_risk(monkeypatch) -> None:
    persisted: dict[str, Any] = {}

    def _save(analysis_id: str, decision: dict[str, Any]) -> None:
        persisted["analysis_id"] = analysis_id
        persisted["decision"] = decision

    monkeypatch.setattr(
        "soc_platform.domains.phishing.engine.orchestrator.langgraph_workflow.trigger_garuda_investigation",
        lambda decision: {"status": "triggered", "analysis_id": decision.get("analysis_id")},
    )
    monkeypatch.setattr(
        "soc_platform.domains.phishing.engine.orchestrator.langgraph_workflow.calculate_threat_score",
        lambda _results: {"overall_score": 0.9, "threat_level": "critical"},
    )
    monkeypatch.setattr(
        "soc_platform.domains.phishing.engine.orchestrator.langgraph_workflow.correlate_threats",
        lambda _results: {"correlation_score": 0.8, "attack_patterns": []},
    )

    graph = LangGraphOrchestrator(save_report=_save, execute_actions=lambda _decision: None)
    state = {
        "analysis_id": "a-3",
        "agent_results": [
            {
                "agent_name": "content_agent",
                "risk_score": 0.95,
                "confidence": 0.99,
                "indicators": ["credential_harvest_pattern"],
            }
        ],
    }

    final_state = graph.run(state)
    decision = final_state.get("decision", {})

    assert decision.get("analysis_id") == "a-3"
    assert float(decision.get("overall_risk_score", 0.0)) > 0.7
    assert decision.get("garuda_feedback", {}).get("status") == "triggered"
    assert persisted.get("analysis_id") == "a-3"


def test_process_garuda_retries_handles_broker_unavailable(monkeypatch) -> None:
    class _FailingMQ:
        channel = None

        def connect(self) -> None:
            raise RuntimeError("rabbitmq unavailable")

        def close(self) -> None:
            return None

    monkeypatch.setattr(retry_queue, "RabbitMQClient", _FailingMQ)

    result = retry_queue.process_garuda_retries(max_items=1)

    assert result["processed"] == 0
    assert result["succeeded"] == 0
    assert result["requeued"] == 0
    assert result["dead_lettered"] == 0
    assert "rabbitmq unavailable" in result.get("error", "")
