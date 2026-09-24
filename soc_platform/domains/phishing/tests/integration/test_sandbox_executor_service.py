"""Tests for sandbox executor service authentication and path isolation."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from soc_platform.domains.phishing.engine.sandbox import executor_service


def test_executor_rejects_missing_token_when_required(monkeypatch, tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")

    monkeypatch.setattr(executor_service.settings, "sandbox_executor_shared_token", "secret-token", raising=False)
    monkeypatch.setattr(executor_service.settings, "sandbox_executor_attachment_root", str(tmp_path), raising=False)

    client = TestClient(executor_service.app)
    resp = client.post("/detonate", json={"attachment_path": str(sample)})

    assert resp.status_code == 401
    assert "Invalid sandbox executor token" in resp.text


def test_executor_rejects_path_outside_attachment_root(monkeypatch, tmp_path: Path) -> None:
    allowed_root = tmp_path / "allowed"
    allowed_root.mkdir(parents=True)

    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"payload")

    monkeypatch.setattr(executor_service.settings, "sandbox_executor_shared_token", "", raising=False)
    monkeypatch.setattr(executor_service.settings, "sandbox_executor_attachment_root", str(allowed_root), raising=False)

    client = TestClient(executor_service.app)
    resp = client.post("/detonate", json={"attachment_path": str(outside)})

    assert resp.status_code == 403
    assert "outside allowed root" in resp.text


def test_executor_rejects_prefix_bypass_path(monkeypatch, tmp_path: Path) -> None:
    allowed_root = tmp_path / "allowed"
    allowed_root.mkdir(parents=True)

    # This shares a string prefix with allowed_root but is not actually inside it.
    prefix_bypass = tmp_path / "allowed_evil"
    prefix_bypass.mkdir(parents=True)
    bypass_file = prefix_bypass / "evil.bin"
    bypass_file.write_bytes(b"payload")

    monkeypatch.setattr(executor_service.settings, "sandbox_executor_shared_token", "", raising=False)
    monkeypatch.setattr(executor_service.settings, "sandbox_executor_attachment_root", str(allowed_root), raising=False)

    client = TestClient(executor_service.app)
    resp = client.post("/detonate", json={"attachment_path": str(bypass_file)})

    assert resp.status_code == 403
    assert "outside allowed root" in resp.text


def test_executor_rejects_missing_attachment(monkeypatch, tmp_path: Path) -> None:
    missing = tmp_path / "missing.exe"

    monkeypatch.setattr(executor_service.settings, "sandbox_executor_shared_token", "", raising=False)
    monkeypatch.setattr(executor_service.settings, "sandbox_executor_attachment_root", str(tmp_path), raising=False)

    client = TestClient(executor_service.app)
    resp = client.post("/detonate", json={"attachment_path": str(missing)})

    assert resp.status_code == 404
    assert "not found" in resp.text


def test_executor_returns_detonation_payload(monkeypatch, tmp_path: Path) -> None:
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ")

    class _DummyDockerClient:
        pass

    monkeypatch.setattr(executor_service.settings, "sandbox_executor_shared_token", "abc123", raising=False)
    monkeypatch.setattr(executor_service.settings, "sandbox_executor_attachment_root", str(tmp_path), raising=False)
    monkeypatch.setattr(executor_service.docker, "from_env", lambda: _DummyDockerClient())
    monkeypatch.setattr(
        executor_service,
        "_detonate_attachment",
        lambda _client, _path: (
            0.91,
            ["remote_connect_detected", "shell_spawn_detected"],
            {"remote_ips": ["8.8.8.8"]},
            {"behavior_risk_score": 0.91, "sample_id": "runtime_x"},
        ),
    )

    client = TestClient(executor_service.app)
    resp = client.post(
        "/detonate",
        json={"attachment_path": str(sample)},
        headers={"x-sandbox-token": "abc123"},
    )

    assert resp.status_code == 200
    body = resp.json()
    assert body["heuristic_score"] == 0.91
    assert "remote_connect_detected" in body["indicators"]
    assert body["behavior"]["remote_ips"] == ["8.8.8.8"]
    assert body["training_row"]["behavior_risk_score"] == 0.91
