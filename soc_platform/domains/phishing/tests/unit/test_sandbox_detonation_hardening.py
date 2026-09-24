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

    def exec_run(self, cmd, detach: bool = False, **kwargs):  # noqa: ANN001
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
            def __init__(self, outer: "_FakeDockerClient") -> None:
                self.outer = outer

            def create(self, **kwargs):  # noqa: ANN003
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


def test_detonation_compat_fallback_drops_unsupported_hardening_keys(monkeypatch, tmp_path: Path) -> None:
    sample = tmp_path / "payload.sh"
    sample.write_text("echo hi", encoding="utf-8")
    fake_client = _FakeDockerClient(fail_first_create=True)

    monkeypatch.setattr(sandbox_agent.settings, "sandbox_allow_network", True, raising=False)
    monkeypatch.setattr(sandbox_agent.settings, "sandbox_timeout_seconds", 10, raising=False)
    monkeypatch.setattr(sandbox_agent, "SANDBOX_RUNTIME_CSV", tmp_path / "sandbox_behavior" / "runtime_observations.csv")

    sandbox_agent._detonate_attachment(fake_client, sample)

    assert len(fake_client.create_calls) == 2
    first_call = fake_client.create_calls[0]
    second_call = fake_client.create_calls[1]

    assert "security_opt" in first_call
    assert "pids_limit" in first_call
    assert "tmpfs" in first_call

    assert "security_opt" not in second_call
    assert "pids_limit" not in second_call
    assert "tmpfs" not in second_call
    assert "network_disabled" not in second_call
