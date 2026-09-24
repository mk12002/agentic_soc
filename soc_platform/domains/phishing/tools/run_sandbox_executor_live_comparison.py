#!/usr/bin/env python3
"""Compare sandbox-agent outputs between simulated and live executor modes."""

from __future__ import annotations
from soc_platform.domains.phishing.engine.paths import PHISHING_HOME

import json
import os
import sys
import tempfile
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO_ROOT = PHISHING_HOME
WORKSPACE_ROOT = REPO_ROOT.parent
if str(WORKSPACE_ROOT) not in sys.path:
    pass  # (package import; no sys.path hack needed)
from soc_platform.domains.phishing.engine.agents.sandbox_agent import agent as sandbox_agent


@contextmanager
def _patched_settings(**overrides: Any):
    original: dict[str, Any] = {}
    for key, value in overrides.items():
        original[key] = getattr(sandbox_agent.settings, key)
        setattr(sandbox_agent.settings, key, value)
    try:
        yield
    finally:
        for key, value in original.items():
            setattr(sandbox_agent.settings, key, value)


@contextmanager
def _patched_attr(obj: Any, name: str, replacement: Any):
    original = getattr(obj, name)
    setattr(obj, name, replacement)
    try:
        yield
    finally:
        setattr(obj, name, original)


def _make_samples(root: Path) -> dict[str, Path]:
    root.mkdir(parents=True, exist_ok=True)
    benign = root / "meeting_notes.txt"
    benign.write_bytes(b"Project planning notes and non-executable text.")

    suspicious_exe = root / "urgent_invoice.pdf.exe"
    suspicious_exe.write_bytes((bytes(range(256)) * 20) + b"VirtualAlloc WriteProcessMemory powershell")

    suspicious_docm = root / "payment_update.docm"
    suspicious_docm.write_bytes(b"VBA AutoOpen macro shell powershell payload")

    return {
        "benign": benign,
        "suspicious_exe": suspicious_exe,
        "suspicious_docm": suspicious_docm,
    }


def _run_live_case(payload: dict[str, Any], executor_url: str, token: str) -> dict[str, Any]:
    with _patched_settings(
        sandbox_local_docker_enabled=False,
        sandbox_executor_url=executor_url,
        sandbox_executor_shared_token=token,
        sandbox_executor_timeout_seconds=45.0,
    ):
        return sandbox_agent.analyze(payload)


def _run_simulated_case(payload: dict[str, Any]) -> dict[str, Any]:
    behavior = {
        "exec_chain": ["/bin/sh", "/usr/bin/curl"],
        "remote_ips": ["8.8.8.8"],
        "sensitive_writes": ["/etc/cron.d/evil"],
        "shell_spawned": True,
        "network_tool_spawned": True,
        "critical_chain_detected": True,
    }
    training_row = {
        "executed": 1,
        "return_code": 0,
        "timed_out": 0,
        "spawned_processes": 2,
        "suspicious_process_count": 2,
        "file_entropy": 7.8,
        "connect_calls": 1,
        "execve_calls": 2,
        "file_write_calls": 1,
        "sequence_length": 4,
        "sequence_process_calls": 2,
        "sequence_network_calls": 1,
        "sequence_filesystem_calls": 1,
        "sequence_registry_calls": 0,
        "sequence_memory_calls": 0,
        "critical_chain_detected": 1,
        "behavior_risk_score": 0.94,
    }

    with _patched_settings(sandbox_local_docker_enabled=False, sandbox_executor_url="http://simulated:8099"):
        with _patched_attr(
            sandbox_agent,
            "_detonate_via_executor",
            lambda _target: (0.94, ["shell_spawn_detected", "remote_connect_detected"], behavior, training_row),
        ):
            return sandbox_agent.analyze(payload)


def run(executor_url: str, token: str, attachment_root: Path) -> dict[str, Any]:
    samples = _make_samples(attachment_root)

    scenarios = [
        {
            "name": "negative_benign_text_attachment",
            "input": {"attachments": [{"filename": samples["benign"].name, "path": str(samples["benign"])}]},
        },
        {
            "name": "positive_double_extension_executable",
            "input": {"attachments": [{"filename": samples["suspicious_exe"].name, "path": str(samples["suspicious_exe"])}]},
        },
        {
            "name": "positive_macro_enabled_docm",
            "input": {"attachments": [{"filename": samples["suspicious_docm"].name, "path": str(samples["suspicious_docm"])}]},
        },
        {
            "name": "edge_budget_enforcement_multi_attach",
            "input": {
                "attachments": [
                    {"filename": samples["suspicious_exe"].name, "path": str(samples["suspicious_exe"])},
                    {"filename": samples["suspicious_docm"].name, "path": str(samples["suspicious_docm"])},
                    {"filename": samples["benign"].name, "path": str(samples["benign"])},
                ]
            },
            "settings_override": {"sandbox_max_detonations": 1},
        },
    ]

    cases: list[dict[str, Any]] = []

    for scenario in scenarios:
        payload = scenario["input"]
        overrides = scenario.get("settings_override", {})

        with _patched_settings(**overrides):
            live = _run_live_case(payload, executor_url=executor_url, token=token)
        with _patched_settings(**overrides):
            simulated = _run_simulated_case(payload)

        live_risk = float(live.get("risk_score", 0.0) or 0.0)
        sim_risk = float(simulated.get("risk_score", 0.0) or 0.0)

        cases.append(
            {
                "name": scenario["name"],
                "input": payload,
                "live_output": live,
                "simulated_output": simulated,
                "comparison": {
                    "live_risk": live_risk,
                    "simulated_risk": sim_risk,
                    "risk_delta_live_minus_simulated": round(live_risk - sim_risk, 4),
                    "live_mode": live.get("analysis_mode"),
                    "simulated_mode": simulated.get("analysis_mode"),
                    "live_indicator_sample": (live.get("indicators") or [])[:8],
                    "simulated_indicator_sample": (simulated.get("indicators") or [])[:8],
                },
            }
        )

    return {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "executor_url": executor_url,
        "case_count": len(cases),
        "cases": cases,
    }


def main() -> int:
    executor_url = os.getenv("SANDBOX_EXECUTOR_URL", "http://127.0.0.1:8099").strip()
    token = os.getenv("SANDBOX_EXECUTOR_SHARED_TOKEN", "").strip()
    attachment_root_env = os.getenv("SANDBOX_EXECUTOR_ATTACHMENT_ROOT", "").strip()

    if not token:
        print("Missing SANDBOX_EXECUTOR_SHARED_TOKEN", file=sys.stderr)
        return 2

    if attachment_root_env:
        attachment_root = Path(attachment_root_env)
        attachment_root.mkdir(parents=True, exist_ok=True)
    else:
        attachment_root = Path(tempfile.mkdtemp(prefix="sandbox_exec_compare_"))

    report = run(executor_url=executor_url, token=token, attachment_root=attachment_root)

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    report_dir = REPO_ROOT / "analysis_reports" / f"sandbox_live_vs_sim_{ts}"
    report_dir.mkdir(parents=True, exist_ok=True)
    out = report_dir / "sandbox_live_vs_sim.json"
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print(json.dumps({
        "report": str(out),
        "case_count": report["case_count"],
        "summary": [
            {
                "name": c["name"],
                "live_risk": c["comparison"]["live_risk"],
                "simulated_risk": c["comparison"]["simulated_risk"],
                "delta": c["comparison"]["risk_delta_live_minus_simulated"],
                "live_mode": c["comparison"]["live_mode"],
            }
            for c in report["cases"]
        ],
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
