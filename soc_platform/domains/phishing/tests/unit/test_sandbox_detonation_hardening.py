"""Tests for sandbox detonation container hardening behavior."""

from __future__ import annotations

from pathlib import Path

from soc_platform.domains.phishing.engine.agents.sandbox_agent import agent as sandbox_agent


class _ExecResult:
    def __init__(self, exit_code: int, output: bytes):
        self.exit_code = exit_code
        self.output = output


class _FakeContainer:
    def __init__(self) -> None:
        self.started = False
        self.stopped = False
        self.removed = False
        self.archives: list[tuple[str, bytes]] = []
        self.exec_calls: list[object] = []

    def start(self) -> None:
        self.started = True

    def exec_run(self, cmd, detach: bool = False, **kwargs):
        self.exec_calls.append(cmd)
        if isinstance(cmd, list) and cmd[:3] == ["mkdir", "-p", "/sandbox/input"]:
            return _ExecResult(0, b"")

        strace_output = (
            b'12:00:00 execve("/bin/sh", ["sh", "-c", "curl http://bad"], 0x0) = 0\n'
            b'12:00:01 execve("/usr/bin/curl", ["curl", "http://bad"], 0x0) = 0\n'
            b'12:00:02 connect(3, {sa_family=AF_INET, sin_port=htons(80), '
            b'sin_addr=inet_addr("8.8.8.8")}, 16) = 0\n'
        )
        return _ExecResult(0, strace_output)

    def put_archive(self, path: str, data: bytes) -> None:
        self.archives.append((path, data))

    def kill(self) -> None:
        return None

    def stop(self, timeout: int = 2) -> None:
        self.stopped = True

    def remove(self, force: bool = True) -> None:
        self.removed = True


class _FakeDockerClient:
    def __init__(self, fail_first_create: bool = False) -> None:
        self.container = _FakeContainer()
        self.fail_first_create = fail_first_create
        self.create_calls: list[dict] = []

        class _Images:
            @staticmethod
            def get(_image: str) -> None:
                return None

            @staticmethod
            def pull(_image: str) -> None:
                return None

        class _Containers:
            def __init__(self, outer: _FakeDockerClient) -> None:
                self.outer = outer

            def create(self, **kwargs):
                self.outer.create_calls.append(dict(kwargs))
                if self.outer.fail_first_create and len(self.outer.create_calls) == 1:
                    raise TypeError("unsupported option")
                return self.outer.container

        self.images = _Images()
        self.containers = _Containers(self)


def test_detonation_enforces_hardening_options(monkeypatch, tmp_path: Path) -> None:
    sample = tmp_path / "payload.exe"
    sample.write_bytes(b"MZ payload")
    fake_client = _FakeDockerClient()

    monkeypatch.setattr(sandbox_agent.settings, "sandbox_allow_network", False, raising=False)
    monkeypatch.setattr(sandbox_agent.settings, "sandbox_memory_limit_mb", 192, raising=False)
    monkeypatch.setattr(sandbox_agent.settings, "sandbox_pids_limit", 96, raising=False)
    monkeypatch.setattr(sandbox_agent.settings, "sandbox_non_root_user", "65534:65534", raising=False)
    monkeypatch.setattr(sandbox_agent.settings, "sandbox_timeout_seconds", 10, raising=False)
    monkeypatch.setattr(sandbox_agent, "SANDBOX_RUNTIME_CSV", tmp_path / "sandbox_behavior" / "runtime_observations.csv")

    score, indicators, behavior, training_row = sandbox_agent._detonate_attachment(fake_client, sample)

    assert score >= 0.86
    assert "remote_connect_detected" in indicators
    assert behavior["shell_spawned"] is True
    assert training_row["connect_calls"] >= 1

    kwargs = fake_client.create_calls[0]
    assert kwargs["read_only"] is True
    assert kwargs["cap_drop"] == ["ALL"]
    assert kwargs["security_opt"] == ["no-new-privileges"]
    assert kwargs["tmpfs"]["/sandbox"].startswith("rw,noexec,nosuid,nodev")
    assert kwargs["mem_limit"] == "192m"
    assert kwargs["pids_limit"] == 96
    assert kwargs["user"] == "65534:65534"
    assert kwargs["network_disabled"] is True
    assert fake_client.container.started is True
    assert fake_client.container.stopped is True
    assert fake_client.container.removed is True


def test_detonation_fails_closed_when_daemon_rejects_hardening(monkeypatch, tmp_path: Path) -> None:
    """Security fix: the old code retried WITHOUT seccomp/pids/tmpfs limits; now it refuses to detonate."""
    import pytest

    sample = tmp_path / "payload.sh"
    sample.write_text("echo hi", encoding="utf-8")
    fake_client = _FakeDockerClient(fail_first_create=True)
    monkeypatch.setattr(sandbox_agent.settings, "sandbox_allow_network", False, raising=False)
    monkeypatch.setattr(sandbox_agent.settings, "sandbox_timeout_seconds", 10, raising=False)
    with pytest.raises(sandbox_agent.SandboxHardeningError):
        sandbox_agent._detonate_attachment(fake_client, sample)
    assert len(fake_client.create_calls) == 1
    assert fake_client.container.started is False


def test_hardened_kwargs_full_isolation(monkeypatch, tmp_path: Path) -> None:
    import pytest

    sample = tmp_path / "x.sh"
    sample.write_text("id", encoding="utf-8")
    monkeypatch.setattr(sandbox_agent.settings, "sandbox_allow_network", False, raising=False)
    monkeypatch.setattr(sandbox_agent.settings, "sandbox_runtime", "runsc", raising=False)
    kw = sandbox_agent._hardened_container_kwargs("img@sha256:abc", "n", sample, "/tmp/sample.sh", "h")
    assert kw["network_mode"] == "none" and kw["ipc_mode"] == "none" and kw["runtime"] == "runsc"
    assert kw["memswap_limit"] == kw["mem_limit"] and kw["privileged"] is False and kw["init"] is True
    assert {u["Name"] for u in kw["ulimits"]} == {"nofile", "core", "fsize"}
    monkeypatch.setattr(sandbox_agent.settings, "sandbox_non_root_user", "0:0", raising=False)
    with pytest.raises(sandbox_agent.SandboxHardeningError):
        sandbox_agent._hardened_container_kwargs("img", "n", sample, "/tmp/sample.sh", "h")


def test_host_watchdog_kills_runaway_sample(monkeypatch, tmp_path: Path) -> None:
    import time as _t

    sample = tmp_path / "loop.sh"
    sample.write_text("while :; do :; done", encoding="utf-8")
    fake_client = _FakeDockerClient()
    killed = {}

    def hang(cmd, detach=False, **kw):
        _t.sleep(3)
        return _ExecResult(0, b"")

    fake_client.container.exec_run = hang
    fake_client.container.kill = lambda: killed.setdefault("yes", True)
    monkeypatch.setattr(sandbox_agent.settings, "sandbox_timeout_seconds", -4, raising=False)  # deadline = 1s
    monkeypatch.setattr(sandbox_agent, "SANDBOX_RUNTIME_CSV", tmp_path / "rt.csv")
    _score, indicators, _behavior, _ = sandbox_agent._detonate_attachment(fake_client, sample)
    assert "host_watchdog_killed_detonation" in indicators and killed.get("yes")
    assert fake_client.container.removed is True


def test_production_requires_pinned_image(monkeypatch, tmp_path: Path) -> None:
    import pytest

    sample = tmp_path / "a.sh"
    sample.write_text("id", encoding="utf-8")
    monkeypatch.setattr(sandbox_agent.settings, "app_env", "production", raising=False)
    monkeypatch.setattr(sandbox_agent.settings, "sandbox_detonation_image", "python:3.11-slim", raising=False)
    with pytest.raises(sandbox_agent.SandboxHardeningError):
        sandbox_agent._detonate_attachment(_FakeDockerClient(), sample)
