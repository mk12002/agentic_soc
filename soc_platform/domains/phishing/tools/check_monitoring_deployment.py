#!/usr/bin/env python3
"""Confirm monitoring endpoint reachability and rule visibility."""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import UTC, datetime

import httpx

from soc_platform.domains.phishing.engine.paths import PHISHING_HOME

REPO_ROOT = PHISHING_HOME
WORKSPACE_ROOT = REPO_ROOT.parent
if str(WORKSPACE_ROOT) not in sys.path:
    pass  # (package import; no sys.path hack needed)
ANALYSIS_ROOT = REPO_ROOT / "analysis_reports"


def _default_targets(base_api: str) -> list[tuple[str, str]]:
    return [
        ("api_health", base_api.rstrip("/") + "/health"),
        ("prometheus_ready", "http://127.0.0.1:9090/-/ready"),
        ("alertmanager_ready", "http://127.0.0.1:9093/-/ready"),
    ]


def _parse_targets(raw: str) -> list[tuple[str, str]]:
    targets: list[tuple[str, str]] = []
    for item in raw.split(","):
        token = item.strip()
        if not token:
            continue
        if "=" in token:
            name, url = token.split("=", 1)
            targets.append((name.strip(), url.strip()))
        else:
            targets.append((token, token))
    return targets


def main() -> int:
    parser = argparse.ArgumentParser(description="Check monitoring deployment endpoints")
    parser.add_argument("--api-base-url", default="http://127.0.0.1:8000")
    parser.add_argument(
        "--targets",
        default=os.environ.get("MONITORING_ENDPOINTS", ""),
        help="Comma-separated list: name=url,name2=url2",
    )
    parser.add_argument("--strict", action="store_true", help="Fail if any endpoint check fails")
    args = parser.parse_args()

    ts = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    out_dir = ANALYSIS_ROOT / f"monitoring_check_{ts}"
    out_dir.mkdir(parents=True, exist_ok=True)

    targets = _parse_targets(args.targets) if args.targets else _default_targets(args.api_base_url)
    checks = []

    with httpx.Client(timeout=5.0) as client:
        for name, url in targets:
            status_code = 0
            ok = False
            error = ""
            try:
                resp = client.get(url)
                status_code = int(resp.status_code)
                ok = 200 <= status_code < 300
            except Exception as exc:
                error = str(exc)
            checks.append({"name": name, "url": url, "ok": ok, "status_code": status_code, "error": error})

    failed = [item for item in checks if not item["ok"]]
    report = {
        "timestamp_utc": datetime.now(UTC).isoformat(),
        "strict": args.strict,
        "checks": checks,
        "overall_passed": len(failed) == 0,
    }

    json_path = out_dir / "monitoring_check.json"
    md_path = out_dir / "monitoring_check.md"
    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    lines = [
        "# Monitoring Deployment Check",
        "",
        f"- Overall Passed: `{report['overall_passed']}`",
        f"- Strict Mode: `{args.strict}`",
        "",
        "## Endpoints",
    ]
    for item in checks:
        status = "PASS" if item["ok"] else "FAIL"
        lines.append(f"- `{item['name']}`: **{status}** (`{item['url']}`, status={item['status_code']})")

    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Monitoring check report written to: {out_dir}")

    if args.strict and failed:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
