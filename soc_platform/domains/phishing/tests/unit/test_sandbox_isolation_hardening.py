"""Sandbox isolation hardening tests."""

from __future__ import annotations

from pathlib import Path

from soc_platform.domains.phishing.engine.agents.sandbox_agent import agent as sandbox_agent
from soc_platform.domains.phishing.engine.configs.settings import Settings


def test_sandbox_falls_back_when_local_docker_disabled(monkeypatch) -> None:
    monkeypatch.setattr(sandbox_agent.settings, "sandbox_local_docker_enabled", False, raising=False)
    monkeypatch.setattr(sandbox_agent.settings, "sandbox_executor_url", "", raising=False)

    # Ensure this path never attempts local Docker.
    monkeypatch.setattr(
        sandbox_agent.docker,
        "from_env",
        lambda: (_ for _ in ()).throw(AssertionError("docker.from_env should not be called")),
    )

    result = sandbox_agent.analyze(
        {
            "attachments": [
                {
                    "filename": "urgent_invoice.pdf",
                    "path": "/nonexistent/urgent_invoice.pdf",
                }
            ]
        }
    )

    assert result["agent_name"] == "sandbox_agent"
    assert "sandbox_local_docker_disabled" in result["indicators"]
    assert result["analysis_mode"] == "fallback_static"
    assert result["confidence"] <= 0.45


def test_production_warns_when_local_docker_enabled() -> None:
    prod = Settings(
        app_env="production",
        sandbox_local_docker_enabled=True,
    )
    warnings = prod.validate_production_settings()
    assert any("SANDBOX_LOCAL_DOCKER_ENABLED" in item for item in warnings)


def test_warns_when_executor_url_has_no_shared_token() -> None:
    cfg = Settings(
        app_env="development",
        sandbox_executor_url="http://sandbox-executor:8099",
        sandbox_executor_shared_token="",
    )
    warnings = cfg.validate_production_settings()
    assert any("SANDBOX_EXECUTOR_URL" in item for item in warnings)


def test_sandbox_executor_mode_uses_remote_path(monkeypatch, tmp_path: Path) -> None:
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZdummy")

    monkeypatch.setattr(sandbox_agent.settings, "sandbox_executor_url", "http://sandbox-executor:8099", raising=False)
    monkeypatch.setattr(sandbox_agent.settings, "sandbox_local_docker_enabled", False, raising=False)

    # Executor mode must not use local docker.from_env.
    monkeypatch.setattr(
        sandbox_agent.docker,
        "from_env",
        lambda: (_ for _ in ()).throw(AssertionError("docker.from_env should not be called")),
    )

    monkeypatch.setattr(
        sandbox_agent,
        "_detonate_via_executor",
        lambda _target: (0.92, ["sandbox_remote_ok"], {"remote_ips": ["1.2.3.4"]}, {"behavior_risk_score": 0.92}),
    )
    monkeypatch.setattr(
        sandbox_agent,
        "predict",
        lambda _row, model=None: {"risk_score": 0.9, "confidence": 0.9, "indicators": ["ml_high_risk"]},
    )

    result = sandbox_agent.analyze({"attachments": [{"filename": sample.name, "path": str(sample)}]})

    assert "sandbox_executor_mode" in result["indicators"]
    assert result["analysis_mode"] == "executor"
    assert result["risk_score"] >= 0.8


def test_fallback_high_static_combo_gets_suspicious_floor(monkeypatch, tmp_path: Path) -> None:
    sample = tmp_path / "urgent_payload.docm"
    sample.write_bytes((bytes(range(256)) * 16) + b"VirtualAlloc WriteProcessMemory powershell vba AutoOpen")

    monkeypatch.setattr(sandbox_agent.settings, "sandbox_local_docker_enabled", False, raising=False)
    monkeypatch.setattr(sandbox_agent.settings, "sandbox_executor_url", "", raising=False)

    result = sandbox_agent.analyze({"attachments": [{"filename": sample.name, "path": str(sample)}]})

    assert result["analysis_mode"] == "fallback_static"
    assert "fallback_static_suspicious_floor" in result["indicators"]
    assert result["risk_score"] >= 0.45
