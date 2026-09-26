"""Mocked end-to-end operational flow validation.

Covers:
- POST /analyze-email ingestion and event publish
- Orchestrator finalization path in runner.py
- Action dispatch path in response_engine.py
- GET /reports/{analysis_id} polling behavior
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, ClassVar, Self

from fastapi.testclient import TestClient

import soc_platform.domains.phishing.engine.api.main as api_main
import soc_platform.domains.phishing.engine.garuda_integration.bridge as _garuda_bridge
import soc_platform.domains.phishing.engine.orchestrator.langgraph_workflow as _langgraph_wf
from soc_platform.domains.phishing.engine.action_layer import response_engine
from soc_platform.domains.phishing.engine.orchestrator.langgraph_workflow import LangGraphOrchestrator
from soc_platform.domains.phishing.engine.orchestrator.runner import EXPECTED_AGENTS, OrchestratorWorker


class _FakeRabbitMQClient:
    published_events: ClassVar[list[dict[str, Any]]] = []

    def connect(self) -> None:
        return None

    def publish_new_email(self, payload: dict[str, Any]) -> None:
        self.__class__.published_events.append(payload)

    def close(self) -> None:
        return None


@dataclass
class _FakeRedis:
    """Minimal Redis stub covering all methods used by OrchestratorWorker."""

    store: dict[str, str] = field(default_factory=dict)

    def get(self, key: str) -> str | None:
        return self.store.get(key)

    def set(self, key: str, value: str) -> None:
        self.store[key] = value

    def setex(self, key: str, _ttl: int, value: str) -> None:
        self.store[key] = value

    def delete(self, key: str) -> None:
        self.store.pop(key, None)

    def publish(self, channel: str, message: str) -> None:
        pass

    # Pipeline / transactional stubs (used by _merge_results WATCH/MULTI/EXEC)
    def pipeline(self) -> _FakeRedis:
        return self

    def watch(self, *keys: str) -> None:
        pass

    def multi(self) -> None:
        pass

    def execute(self) -> list[Any]:
        return [True]

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args: object) -> None:
        pass


class _FakeCursor:
    def __init__(self, report_store: dict[str, dict[str, Any]]):
        self.report_store = report_store
        self.analysis_id: str | None = None

    def execute(self, _query: str, params: tuple[Any, ...]) -> None:
        self.analysis_id = str(params[0])

    def fetchone(self) -> tuple[dict[str, Any]] | None:
        if self.analysis_id is None:
            return None
        report = self.report_store.get(self.analysis_id)
        if report is None:
            return None
        return (report,)

    def __enter__(self) -> Self:
        return self

    def __exit__(self, _exc_type, _exc, _tb) -> None:
        return None


class _FakeConnection:
    def __init__(self, report_store: dict[str, dict[str, Any]]):
        self.report_store = report_store

    def cursor(self) -> _FakeCursor:
        return _FakeCursor(self.report_store)

    def __enter__(self) -> Self:
        return self

    def __exit__(self, _exc_type, _exc, _tb) -> None:
        return None


class _TestWorker(OrchestratorWorker):
    def __init__(self) -> None:
        self.messaging = None
        self.redis_client = _FakeRedis()
        self.saved_reports: dict[str, dict[str, Any]] = {}
        self.graph = LangGraphOrchestrator(
            save_report=self._save_report,
            execute_actions=response_engine.execute_actions,
        )

    def _save_report(self, analysis_id: str, decision: dict[str, Any]) -> None:
        self.saved_reports[analysis_id] = decision

    def _report_exists(self, analysis_id: str) -> bool:
        return analysis_id in self.saved_reports


def test_operational_flow_ingest_finalize_actions_and_report_poll(monkeypatch) -> None:
    _FakeRabbitMQClient.published_events.clear()
    action_calls: list[str] = []
    
    monkeypatch.setattr(api_main, "RabbitMQClient", _FakeRabbitMQClient)
    # Updated signature: _execute_simulated_actions(self, actions, analysis_id, sender="")
    monkeypatch.setattr(
        response_engine.ResponseEngine,
        "_execute_simulated_actions",
        lambda self, actions, analysis_id, sender="": action_calls.extend(actions),
    )
    monkeypatch.setattr(response_engine.response_engine, "simulated_mode", True)
    # Stub Garuda bridge to avoid real RabbitMQ / network calls in test environment
    # Must patch both the bridge module AND the workflow module (imported with 'from X import Y')
    _garuda_stub = lambda decision: {"status": "stubbed", "response": {}}
    monkeypatch.setattr(_garuda_bridge, "trigger_garuda_investigation", _garuda_stub)
    monkeypatch.setattr(_langgraph_wf, "trigger_garuda_investigation", _garuda_stub)

    report_store: dict[str, dict[str, Any]] = {}
    # BUG-02 FIX: api_main does `from soc_platform.domains.phishing.engine.services.database import connect_database`
    # so the live name lives in api_main's namespace — patch it there.
    monkeypatch.setattr(
        api_main,
        "connect_database",
        lambda _url, **_kw: _FakeConnection(report_store),
    )

    client = TestClient(api_main.app)

    post_resp = client.post(
        "/analyze-email",
        json={
            "headers": {
                "sender": "attacker@evil.example",
                "reply_to": "ops@evil.example",
                "subject": "Urgent payroll update",
                "received": ["from bad-host by victim-mx"],
                "message_id": "<m1>",
                "authentication_results": "spf=fail; dkim=fail; dmarc=fail",
            },
            "body": "Please login now at https://evil.example/login",
            "urls": ["https://evil.example/login"],
            "attachments": [],
        },
    )

    assert post_resp.status_code == 200
    analysis_id = post_resp.json()["analysis_id"]
    assert analysis_id
    assert _FakeRabbitMQClient.published_events
    assert _FakeRabbitMQClient.published_events[0]["analysis_id"] == analysis_id

    # Report is not available before orchestrator finalization.
    pre_report = client.get(f"/reports/{analysis_id}")
    assert pre_report.status_code == 404

    worker = _TestWorker()
    for agent_name in sorted(EXPECTED_AGENTS):
        worker._handle_result(
            {
                "analysis_id": analysis_id,
                "agent_name": agent_name,
                "risk_score": 0.95,
                "confidence": 0.98,
                "indicators": ["critical_chain_detected", "credential_harvest_pattern"],
            }
        )

    assert analysis_id in worker.saved_reports
    report_store[analysis_id] = worker.saved_reports[analysis_id]

    # Poll report endpoint after finalization.
    final_report = client.get(f"/reports/{analysis_id}")
    assert final_report.status_code == 200
    body = final_report.json()
    assert body["analysis_id"] == analysis_id
    assert body["verdict"] in {"high_risk", "malicious"}

    assert "quarantine" in action_calls or "delete" in action_calls
    assert "soc_alert" in action_calls or "trigger_garuda" in action_calls or "block_sender" in action_calls
