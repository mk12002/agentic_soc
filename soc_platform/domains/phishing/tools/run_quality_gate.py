#!/usr/bin/env python3
"""Run a focused quality gate and emit a timestamped validation report.

This script improves release readiness by collecting concrete pass/fail evidence
for core integration paths instead of relying on ad-hoc local runs.
"""

from __future__ import annotations
from soc_platform.domains.phishing.engine.paths import PHISHING_HOME

import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = PHISHING_HOME
ANALYSIS_ROOT = REPO_ROOT / "analysis_reports"

TEST_GROUPS = {
    "core_orchestrator": [
        "tests/unit/test_langgraph_orchestrator.py",
        "tests/unit/test_orchestrator_partial_finalization.py",
        "tests/integration/test_operational_flow_e2e.py",
    ],
    "sandbox_safety": [
        "tests/unit/test_sandbox_agent_behavior.py",
        "tests/unit/test_sandbox_model_inference.py",
        "tests/unit/test_sandbox_isolation_hardening.py",
        "tests/integration/test_sandbox_executor_service.py",
        "tests/unit/test_sandbox_detonation_hardening.py",
        "tests/unit/test_sandbox_additional_paths.py",
        "tests/unit/test_sandbox_hardening_check.py",
    ],
    "data_and_model_smoke": [
        "tests/unit/test_content_preprocessing.py",
        "tests/unit/test_url_model_smoke.py",
        "tests/unit/test_attachment_ensemble_smoke.py",
        "tests/unit/test_threat_intel_smoke.py",
        "tests/unit/test_user_behavior_smoke.py",
    ],
    "regression_contracts": [
        "tests/unit/test_langgraph_orchestrator.py",
        "tests/unit/test_counterfactual.py",
        "tests/unit/test_storyline.py",
        "tests/unit/test_audit_reliability_metrics.py",
        "tests/unit/test_orchestrator_slo.py",
        "tests/unit/test_threat_intel_cache.py",
    ],
}

COMMAND_CHECKS = {
    "sandbox_hardening": [sys.executable, "tools/check_sandbox_hardening.py"],
    "hard_set_builder_dry_run": [sys.executable, "tools/build_hard_set_pack.py", "--per-category", "5"],
    "degraded_mode_slo": [sys.executable, "tools/run_degraded_mode_slo.py"],
}


def _run_pytest(paths: list[str]) -> dict[str, object]:
    cmd = [sys.executable, "-m", "pytest", "-q", *paths]
    started = datetime.now(timezone.utc)
    env = dict(os.environ)
    env["IOC_DB_PATH"] = str(REPO_ROOT / "data" / "ioc_store_ci.db")
    proc = subprocess.run(
        cmd,
        cwd=str(REPO_ROOT),
        text=True,
        capture_output=True,
        env=env,
        check=False,
    )
    finished = datetime.now(timezone.utc)
    return {
        "command": " ".join(cmd),
        "started_utc": started.isoformat(),
        "finished_utc": finished.isoformat(),
        "exit_code": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "passed": proc.returncode == 0,
    }


def _run_command(command: list[str]) -> dict[str, object]:
    started = datetime.now(timezone.utc)
    proc = subprocess.run(
        command,
        cwd=str(REPO_ROOT),
        text=True,
        capture_output=True,
        env=dict(os.environ),
        check=False,
    )
    finished = datetime.now(timezone.utc)
    return {
        "command": " ".join(command),
        "started_utc": started.isoformat(),
        "finished_utc": finished.isoformat(),
        "exit_code": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "passed": proc.returncode == 0,
    }


def main() -> int:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out_dir = ANALYSIS_ROOT / f"quality_gate_{ts}"
    out_dir.mkdir(parents=True, exist_ok=True)

    results: dict[str, object] = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "python": sys.executable,
        "groups": {},
    }

    overall_ok = True
    for group_name, group_tests in TEST_GROUPS.items():
        run = _run_pytest(group_tests)
        results["groups"][group_name] = run
        overall_ok = overall_ok and bool(run["passed"])

    for check_name, command in COMMAND_CHECKS.items():
        run = _run_command(command)
        results["groups"][check_name] = run
        overall_ok = overall_ok and bool(run["passed"])

    results["overall_passed"] = overall_ok

    json_path = out_dir / "quality_gate_results.json"
    md_path = out_dir / "quality_gate_summary.md"
    json_path.write_text(json.dumps(results, indent=2), encoding="utf-8")

    lines = [
        "# Quality Gate Summary",
        "",
        f"- Timestamp (UTC): `{results['timestamp_utc']}`",
        f"- Overall Passed: `{overall_ok}`",
        "",
        "## Groups",
    ]
    for group_name, run in results["groups"].items():
        status = "PASS" if run["passed"] else "FAIL"
        lines.append(f"- `{group_name}`: **{status}** (exit={run['exit_code']})")

    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"Quality gate report written to: {out_dir}")
    return 0 if overall_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
