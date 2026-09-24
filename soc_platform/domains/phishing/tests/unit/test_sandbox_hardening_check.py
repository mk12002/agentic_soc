"""Tests for CI sandbox hardening checklist script."""

from __future__ import annotations

from pathlib import Path

from soc_platform.domains.phishing.tools.check_sandbox_hardening import run_checks


def test_hardening_fails_on_docker_sock_and_missing_executor_token(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("SANDBOX_EXECUTOR_URL", raising=False)
    monkeypatch.delenv("SANDBOX_EXECUTOR_SHARED_TOKEN", raising=False)

    (tmp_path / "docker").mkdir(parents=True)
    compose = tmp_path / "docker" / "docker-compose.yml"
    compose.write_text(
        """
services:
  sandbox_agent_service:
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
""".strip()
        + "\n",
        encoding="utf-8",
    )

    env_file = tmp_path / ".env"
    env_file.write_text("SANDBOX_EXECUTOR_URL=http://sandbox-executor:8099\n", encoding="utf-8")

    report = run_checks(
        repo_root=tmp_path,
        compose_rel="docker/docker-compose.yml",
        env_file_rel=".env",
        allow_docker_sock=False,
    )

    assert report["passed"] is False
    assert any("docker_sock_mount_detected" in item for item in report["violations"])
    assert any("sandbox_executor_missing_token" in item for item in report["violations"])


def test_hardening_passes_when_constraints_satisfied(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("SANDBOX_EXECUTOR_URL", raising=False)
    monkeypatch.delenv("SANDBOX_EXECUTOR_SHARED_TOKEN", raising=False)

    (tmp_path / "docker").mkdir(parents=True)
    compose = tmp_path / "docker" / "docker-compose.yml"
    compose.write_text(
        """
services:
  sandbox_agent_service:
    volumes:
      - ./attachments:/mnt/attachments
""".strip()
        + "\n",
        encoding="utf-8",
    )

    env_file = tmp_path / ".env"
    env_file.write_text(
        "SANDBOX_EXECUTOR_URL=http://sandbox-executor:8099\nSANDBOX_EXECUTOR_SHARED_TOKEN=abc123\n",
        encoding="utf-8",
    )

    report = run_checks(
        repo_root=tmp_path,
        compose_rel="docker/docker-compose.yml",
        env_file_rel=".env",
        allow_docker_sock=False,
    )

    assert report["passed"] is True
    assert report["violations"] == []
