"""Additional sandbox tests for fallback paths and uncovered execution branches."""

from __future__ import annotations

from pathlib import Path

import docker

from soc_platform.domains.phishing.engine.agents.sandbox_agent import agent as sandbox_agent
from soc_platform.domains.phishing.engine.agents.sandbox_agent.feature_extractor import extract_features


class _DummyContainer:
    def __init__(self, status: str, started_at: str | None = None, created_at: str | None = None) -> None:
        self.id = f"ctr-{status}"
        self.attrs = {
            "State": {
                "Status": status,
                "StartedAt": started_at,
            },
            "Created": created_at,
        }
        self.stopped = False
        self.removed = False

    def reload(self) -> None:
        return None

    def stop(self, timeout: int = 2) -> None:
        self.stopped = True

    def remove(self, force: bool = True) -> None:
        self.removed = True


class _DummyContainersApi:
    def __init__(self, containers: list[_DummyContainer]) -> None:
        self._containers = containers

    def list(self, all: bool = True, filters: dict | None = None) -> list[_DummyContainer]:
        return self._containers


class _DummyDockerClient:
    def __init__(self, containers: list[_DummyContainer]) -> None:
        self.containers = _DummyContainersApi(containers)


def test_cleanup_stale_containers_removes_exited_or_old() -> None:
    exited = _DummyContainer(status="exited", started_at="2026-01-01T00:00:00Z")
    old_running = _DummyContainer(status="running", started_at="2020-01-01T00:00:00Z")
    fresh_running = _DummyContainer(status="running", started_at="2999-01-01T00:00:00Z")
    client = _DummyDockerClient([exited, old_running, fresh_running])

    sandbox_agent._cleanup_stale_detonation_containers(client, stale_seconds=300)

    assert exited.stopped is True
    assert exited.removed is True
    assert old_running.stopped is True
    assert old_running.removed is True
    assert fresh_running.removed is False


def test_analyze_falls_back_when_local_docker_unavailable(monkeypatch, tmp_path: Path) -> None:
    sample = tmp_path / "invoice.exe"
    sample.write_bytes(b"MZdummy")

    monkeypatch.setattr(sandbox_agent.settings, "sandbox_local_docker_enabled", True, raising=False)
    monkeypatch.setattr(sandbox_agent.settings, "sandbox_executor_url", "", raising=False)
    monkeypatch.setattr(
        sandbox_agent.docker,
        "from_env",
        lambda: (_ for _ in ()).throw(docker.errors.DockerException("daemon unavailable")),
    )

    result = sandbox_agent.analyze({"attachments": [{"filename": sample.name, "path": str(sample)}]})

    assert result["analysis_mode"] == "fallback_static"
    assert "docker_sandbox_unavailable" in result["indicators"]
    assert result.get("operational_alert", {}).get("code") == "sandbox_backend_unavailable"


def test_analyze_executor_unavailable_during_detonation(monkeypatch, tmp_path: Path) -> None:
    sample = tmp_path / "payload.exe"
    sample.write_bytes(b"MZpayload")

    monkeypatch.setattr(sandbox_agent.settings, "sandbox_local_docker_enabled", False, raising=False)
    monkeypatch.setattr(sandbox_agent.settings, "sandbox_executor_url", "http://sandbox-executor:8099", raising=False)
    monkeypatch.setattr(
        sandbox_agent,
        "_detonate_via_executor",
        lambda _target: (_ for _ in ()).throw(OSError("executor down")),
    )

    result = sandbox_agent.analyze({"attachments": [{"filename": sample.name, "path": str(sample)}]})

    assert result["analysis_mode"] == "fallback_static"
    assert "sandbox_executor_unavailable" in result["indicators"]
    assert "soc_operational_alert:sandbox_backend_unavailable" in result["indicators"]
    assert result.get("operational_alert", {}).get("code") == "sandbox_backend_unavailable"


def test_detonate_via_executor_sends_token_and_falls_back_training_row(monkeypatch, tmp_path: Path) -> None:
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ")

    captured: dict[str, object] = {}

    class _Resp:
        @staticmethod
        def raise_for_status() -> None:
            return None

        @staticmethod
        def json() -> dict:
            return {
                "heuristic_score": 0.9,
                "indicators": ["remote_connect_detected"],
                "behavior": {
                    "exec_chain": ["/bin/sh"],
                    "remote_ips": ["8.8.8.8"],
                    "sensitive_writes": [],
                    "shell_spawned": True,
                    "network_tool_spawned": True,
                    "critical_chain_detected": True,
                },
            }

    class _Client:
        def __init__(self, timeout: float):
            captured["timeout"] = timeout

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def post(self, endpoint: str, json: dict, headers: dict):
            captured["endpoint"] = endpoint
            captured["payload"] = dict(json)
            captured["headers"] = dict(headers)
            return _Resp()

    monkeypatch.setattr(sandbox_agent, "httpx", type("_Httpx", (), {"Client": _Client}))
    monkeypatch.setattr(sandbox_agent.settings, "sandbox_executor_url", "http://sandbox-executor:8099", raising=False)
    monkeypatch.setattr(sandbox_agent.settings, "sandbox_executor_shared_token", "tok123", raising=False)
    monkeypatch.setattr(sandbox_agent.settings, "sandbox_executor_timeout_seconds", 12.0, raising=False)

    score, indicators, behavior, row = sandbox_agent._detonate_via_executor(sample)

    assert score == 0.9
    assert "remote_connect_detected" in indicators
    assert behavior["critical_chain_detected"] is True
    assert row["behavior_risk_score"] == 0.9
    assert captured["endpoint"] == "http://sandbox-executor:8099/detonate"
    assert captured["headers"] == {"x-sandbox-token": "tok123"}


def test_feature_extractor_handles_nested_and_missing_columns() -> None:
    out = extract_features(
        {
            "sandbox_features": {
                "executed": "1",
                "connect_calls": "2",
                "execve_calls": "3",
                "critical_chain_detected": "1",
            }
        }
    )

    assert out["numeric_vector"].shape == (1, 17)
    assert out["metrics"]["executed"] == 1.0
    assert out["metrics"]["connect_calls"] == 2.0
    assert out["metrics"]["critical_chain_detected"] == 1.0
