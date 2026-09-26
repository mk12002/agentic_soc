#!/usr/bin/env python3
"""Run release-readiness checks and emit a timestamped report."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from soc_platform.domains.phishing.engine.paths import PHISHING_HOME

REPO_ROOT = PHISHING_HOME
WORKSPACE_ROOT = REPO_ROOT.parent
if str(WORKSPACE_ROOT) not in sys.path:
    pass  # (package import; no sys.path hack needed)
# Avoid container-only IOC DB defaults when running locally.
os.environ.setdefault("IOC_DB_PATH", str(REPO_ROOT / "data" / "ioc_store.db"))

from soc_platform.domains.phishing.engine.agents.threat_intel_agent.agent import get_ioc_store_status
from soc_platform.domains.phishing.engine.configs.settings import settings
from soc_platform.domains.phishing.engine.services.messaging_service import RabbitMQClient

ANALYSIS_ROOT = REPO_ROOT / "analysis_reports"


def _check_model_artifacts() -> dict[str, Any]:
    required = {
        "header": settings.header_model_path,
        "content": settings.content_model_path,
        "url": settings.url_model_path,
        "attachment": settings.attachment_model_path,
        "sandbox": settings.sandbox_model_path,
        "threat_intel": settings.threat_intel_model_path,
        "user_behavior": settings.user_behavior_model_path,
    }
    results: dict[str, dict[str, Any]] = {}
    all_ok = True
    for name, path_str in required.items():
        path = Path(path_str)
        if not path.is_absolute():
            path = REPO_ROOT.parent / path
        exists = path.exists()
        non_empty = exists and any(path.iterdir()) if exists and path.is_dir() else exists
        ok = bool(exists and non_empty)
        all_ok = all_ok and ok
        results[name] = {
            "path": str(path),
            "exists": exists,
            "non_empty": non_empty,
            "ok": ok,
        }
    return {"ok": all_ok, "details": results}


def _check_rabbitmq() -> dict[str, Any]:
    queue_names = [settings.results_queue, settings.rabbitmq_dead_letter_queue]
    client = RabbitMQClient()
    try:
        stats = client.get_multi_queue_stats(queue_names)
        return {"ok": all(item.get("exists", False) for item in stats), "queues": stats}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
    finally:
        client.close()


def _run_quality_gate() -> dict[str, Any]:
    cmd = [sys.executable, "tools/run_quality_gate.py"]
    proc = subprocess.run(
        cmd,
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        env=dict(os.environ),
        check=False,
    )
    return {
        "command": " ".join(cmd),
        "exit_code": proc.returncode,
        "passed": proc.returncode == 0,
        "stdout_tail": "\n".join(proc.stdout.splitlines()[-20:]),
        "stderr_tail": "\n".join(proc.stderr.splitlines()[-20:]),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run release-readiness checks")
    parser.add_argument(
        "--run-quality-gate",
        action="store_true",
        help="Also execute tools/run_quality_gate.py",
    )
    args = parser.parse_args()

    ts = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    out_dir = ANALYSIS_ROOT / f"release_readiness_{ts}"
    out_dir.mkdir(parents=True, exist_ok=True)

    production_warnings = settings.validate_production_settings()
    ioc_status = get_ioc_store_status()
    model_check = _check_model_artifacts()
    rabbitmq_check = _check_rabbitmq()

    report: dict[str, Any] = {
        "timestamp_utc": datetime.now(UTC).isoformat(),
        "app_env": settings.app_env,
        "production_warnings": production_warnings,
        "ioc_status": ioc_status,
        "model_artifacts": model_check,
        "rabbitmq": rabbitmq_check,
    }

    if args.run_quality_gate:
        report["quality_gate"] = _run_quality_gate()

    critical_failures = []
    if not model_check["ok"]:
        critical_failures.append("model_artifacts")
    if not rabbitmq_check["ok"]:
        critical_failures.append("rabbitmq")
    if str(ioc_status.get("health_level")) == "critical":
        critical_failures.append("ioc_health")
    if args.run_quality_gate and not bool(report["quality_gate"].get("passed")):
        critical_failures.append("quality_gate")

    report["critical_failures"] = critical_failures
    report["overall_passed"] = len(critical_failures) == 0

    json_path = out_dir / "release_readiness.json"
    md_path = out_dir / "release_readiness.md"
    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    lines = [
        "# Release Readiness",
        "",
        f"- Timestamp (UTC): `{report['timestamp_utc']}`",
        f"- Environment: `{report['app_env']}`",
        f"- Overall Passed: `{report['overall_passed']}`",
        f"- Critical Failures: `{', '.join(critical_failures) if critical_failures else 'none'}`",
        "",
        "## Checks",
        f"- Model Artifacts: `{'PASS' if model_check['ok'] else 'FAIL'}`",
        f"- RabbitMQ Reachability: `{'PASS' if rabbitmq_check['ok'] else 'FAIL'}`",
        f"- IOC Health Level: `{ioc_status.get('health_level', 'unknown')}`",
        f"- Production Warnings: `{len(production_warnings)}`",
    ]
    if args.run_quality_gate:
        lines.append(f"- Quality Gate: `{'PASS' if report['quality_gate']['passed'] else 'FAIL'}`")

    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Release-readiness report written to: {out_dir}")
    return 0 if report["overall_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
