#!/usr/bin/env python3
"""Run deep sandbox-agent scenario evaluation and emit structured report."""

from __future__ import annotations

import json
import sys
import tempfile
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from soc_platform.domains.phishing.engine.paths import PHISHING_HOME

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


def _write_file(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def _summarize_case(name: str, output: dict[str, Any]) -> dict[str, Any]:
    risk = float(output.get("risk_score", 0.0) or 0.0)
    mode = str(output.get("analysis_mode", "unknown"))
    indicators = output.get("indicators", []) or []

    interpretation = "benign_or_low_signal"
    if risk >= 0.8:
        interpretation = "high_risk"
    elif risk >= 0.45:
        interpretation = "suspicious"
    elif risk >= 0.2:
        interpretation = "low_moderate_signal"

    return {
        "case": name,
        "risk_score": risk,
        "analysis_mode": mode,
        "indicator_count": len(indicators),
        "top_indicators": indicators[:8],
        "interpretation": interpretation,
    }


def run() -> dict[str, Any]:
    ts = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    report_dir = REPO_ROOT / "analysis_reports" / f"sandbox_deep_eval_{ts}"
    report_dir.mkdir(parents=True, exist_ok=True)

    cases: list[dict[str, Any]] = []

    with tempfile.TemporaryDirectory(prefix="sandbox_deep_eval_") as tmp:
        tmp_path = Path(tmp)

        benign_txt = tmp_path / "meeting_notes.txt"
        _write_file(benign_txt, b"Quarterly review notes and planning details. Nothing executable.")

        suspicious_exe = tmp_path / "urgent_invoice.pdf.exe"
        exe_blob = (bytes(range(256)) * 18) + b"VirtualAlloc WriteProcessMemory CreateRemoteThread powershell"
        _write_file(suspicious_exe, exe_blob)

        macro_docm = tmp_path / "payment_update.docm"
        _write_file(macro_docm, b"VBA AutoOpen macro shell powershell payload")

        low_signal_pdf = tmp_path / "newsletter.pdf"
        _write_file(low_signal_pdf, b"Simple PDF-like content for harmless newsletter")

        # 1) Edge: no attachments
        input_payload = {"attachments": []}
        output = sandbox_agent.analyze(input_payload)
        cases.append(
            {
                "name": "edge_no_attachments",
                "description": "No attachment payload should short-circuit safely.",
                "input": input_payload,
                "output": output,
                "analysis": _summarize_case("edge_no_attachments", output),
            }
        )

        # 2) Edge: missing path
        input_payload = {"attachments": [{"filename": "missing.exe", "path": str(tmp_path / "missing.exe")}]}
        output = sandbox_agent.analyze(input_payload)
        cases.append(
            {
                "name": "edge_missing_attachment_path",
                "description": "Attachment metadata points to non-existent file.",
                "input": input_payload,
                "output": output,
                "analysis": _summarize_case("edge_missing_attachment_path", output),
            }
        )

        # 3) Negative: benign plain text
        input_payload = {"attachments": [{"filename": benign_txt.name, "path": str(benign_txt)}]}
        output = sandbox_agent.analyze(input_payload)
        cases.append(
            {
                "name": "negative_benign_text_attachment",
                "description": "Benign text document with low-risk content.",
                "input": input_payload,
                "output": output,
                "analysis": _summarize_case("negative_benign_text_attachment", output),
            }
        )

        # 4) Positive: suspicious double-extension executable with suspicious imports/high entropy
        input_payload = {"attachments": [{"filename": suspicious_exe.name, "path": str(suspicious_exe)}]}
        output = sandbox_agent.analyze(input_payload)
        cases.append(
            {
                "name": "positive_double_extension_executable",
                "description": "Double-extension executable with suspicious memory/process API strings.",
                "input": input_payload,
                "output": output,
                "analysis": _summarize_case("positive_double_extension_executable", output),
            }
        )

        # 5) Positive: macro-enabled document with VBA markers
        input_payload = {"attachments": [{"filename": macro_docm.name, "path": str(macro_docm)}]}
        output = sandbox_agent.analyze(input_payload)
        cases.append(
            {
                "name": "positive_macro_enabled_docm",
                "description": "Macro-enabled Office file with VBA/macro markers.",
                "input": input_payload,
                "output": output,
                "analysis": _summarize_case("positive_macro_enabled_docm", output),
            }
        )

        # 6) Edge: max detonation budget with multiple suspicious files
        multi_input = {
            "attachments": [
                {"filename": suspicious_exe.name, "path": str(suspicious_exe)},
                {"filename": macro_docm.name, "path": str(macro_docm)},
                {"filename": low_signal_pdf.name, "path": str(low_signal_pdf)},
            ]
        }
        with _patched_settings(sandbox_max_detonations=1):
            output = sandbox_agent.analyze(multi_input)
        cases.append(
            {
                "name": "edge_detonation_budget_enforced",
                "description": "Only top-priority attachment should be processed when budget=1.",
                "input": multi_input,
                "output": output,
                "analysis": _summarize_case("edge_detonation_budget_enforced", output),
            }
        )

        # 7) Edge: executor configured but unavailable (forced fallback path)
        unavailable_input = {"attachments": [{"filename": suspicious_exe.name, "path": str(suspicious_exe)}]}
        with (
            _patched_settings(sandbox_local_docker_enabled=False, sandbox_executor_url="http://sandbox-executor:8099"),
            _patched_attr(
                sandbox_agent,
                "_detonate_via_executor",
                lambda _target: (_ for _ in ()).throw(OSError("executor offline")),
            ),
        ):
            output = sandbox_agent.analyze(unavailable_input)
        cases.append(
            {
                "name": "edge_executor_unavailable_fallback",
                "description": "Executor detonation raises backend error and agent should degrade safely.",
                "input": unavailable_input,
                "output": output,
                "analysis": _summarize_case("edge_executor_unavailable_fallback", output),
            }
        )

        # 8) Positive: simulated executor success with rich behavior signals
        simulated_input = {"attachments": [{"filename": suspicious_exe.name, "path": str(suspicious_exe)}]}
        simulated_behavior = {
            "exec_chain": ["/bin/sh", "/usr/bin/curl"],
            "remote_ips": ["8.8.8.8"],
            "sensitive_writes": ["/etc/cron.d/evil"],
            "shell_spawned": True,
            "network_tool_spawned": True,
            "critical_chain_detected": True,
        }
        simulated_training_row = {
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

        with (
            _patched_settings(sandbox_local_docker_enabled=False, sandbox_executor_url="http://sandbox-executor:8099"),
            _patched_attr(
                sandbox_agent,
                "_detonate_via_executor",
                lambda _target: (0.94, ["shell_spawn_detected", "remote_connect_detected"], simulated_behavior, simulated_training_row),
            ),
        ):
            output = sandbox_agent.analyze(simulated_input)
        cases.append(
            {
                "name": "positive_executor_behavior_signals",
                "description": "Simulated successful executor detonation with strong malicious behavior chain.",
                "input": simulated_input,
                "output": output,
                "analysis": _summarize_case("positive_executor_behavior_signals", output),
            }
        )

    report = {
        "timestamp_utc": datetime.now(UTC).isoformat(),
        "case_count": len(cases),
        "cases": cases,
    }

    out_json = report_dir / "sandbox_deep_evaluation.json"
    out_json.write_text(json.dumps(report, indent=2), encoding="utf-8")

    concise = {
        "report": str(out_json),
        "case_count": len(cases),
        "summary": [item["analysis"] for item in cases],
    }
    print(json.dumps(concise, indent=2))
    return report


if __name__ == "__main__":
    run()
