#!/usr/bin/env python3
"""Run a lightweight API load benchmark and write SLA summary."""

from __future__ import annotations
from soc_platform.domains.phishing.engine.paths import PHISHING_HOME

import argparse
import asyncio
import json
import statistics
import sys
import time
from datetime import datetime, timezone

import httpx

REPO_ROOT = PHISHING_HOME
WORKSPACE_ROOT = REPO_ROOT.parent
if str(WORKSPACE_ROOT) not in sys.path:
    pass  # (package import; no sys.path hack needed)
ANALYSIS_ROOT = REPO_ROOT / "analysis_reports"


def _default_payload() -> dict[str, object]:
    return {
        "headers": {
            "sender": "alerts@example.com",
            "reply_to": "alerts@example.com",
            "subject": "Security update required",
            "received": ["from mail.example.com by mx.local"],
            "message_id": "<benchmark@example.com>",
            "authentication_results": "spf=pass dkim=pass dmarc=pass",
        },
        "body": "Please review https://example.com/security for account updates.",
        "urls": ["https://example.com/security"],
        "attachments": [],
    }


async def _worker(
    client: httpx.AsyncClient,
    url: str,
    payload: dict[str, object],
    api_key: str,
    semaphore: asyncio.Semaphore,
) -> tuple[float, int, str]:
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["X-API-Key"] = api_key

    async with semaphore:
        started = time.perf_counter()
        try:
            resp = await client.post(url, json=payload, headers=headers)
            elapsed_ms = (time.perf_counter() - started) * 1000.0
            return elapsed_ms, int(resp.status_code), ""
        except Exception as exc:
            elapsed_ms = (time.perf_counter() - started) * 1000.0
            return elapsed_ms, 0, str(exc)


def _pct(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = int(round((pct / 100.0) * (len(ordered) - 1)))
    return ordered[max(0, min(idx, len(ordered) - 1))]


async def _run(args: argparse.Namespace) -> dict[str, object]:
    endpoint = args.base_url.rstrip("/") + "/analyze-email"
    payload = _default_payload()
    semaphore = asyncio.Semaphore(max(1, args.concurrency))

    async with httpx.AsyncClient(timeout=float(args.timeout_seconds)) as client:
        tasks = [
            _worker(client, endpoint, payload, args.api_key or "", semaphore)
            for _ in range(args.requests)
        ]
        results = await asyncio.gather(*tasks)

    latencies = [row[0] for row in results]
    statuses = [row[1] for row in results]
    errors = [row[2] for row in results if row[2]]

    success = sum(1 for code in statuses if 200 <= code < 300)
    failed = len(statuses) - success

    p50 = round(_pct(latencies, 50), 2)
    p95 = round(_pct(latencies, 95), 2)
    p99 = round(_pct(latencies, 99), 2)

    avg = round(statistics.mean(latencies), 2) if latencies else 0.0
    max_v = round(max(latencies), 2) if latencies else 0.0
    min_v = round(min(latencies), 2) if latencies else 0.0

    sla_ok = (failed == 0) and (p95 <= float(args.p95_sla_ms))

    return {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "endpoint": endpoint,
        "requests": args.requests,
        "concurrency": args.concurrency,
        "success": success,
        "failed": failed,
        "status_codes": sorted(set(statuses)),
        "latency_ms": {
            "min": min_v,
            "avg": avg,
            "p50": p50,
            "p95": p95,
            "p99": p99,
            "max": max_v,
        },
        "p95_sla_ms": float(args.p95_sla_ms),
        "sla_passed": sla_ok,
        "error_samples": errors[:10],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run API benchmark against /analyze-email")
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--api-key", default="")
    parser.add_argument("--requests", type=int, default=100)
    parser.add_argument("--concurrency", type=int, default=10)
    parser.add_argument("--timeout-seconds", type=float, default=15.0)
    parser.add_argument("--p95-sla-ms", type=float, default=1200.0)
    args = parser.parse_args()

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out_dir = ANALYSIS_ROOT / f"benchmark_{ts}"
    out_dir.mkdir(parents=True, exist_ok=True)

    report = asyncio.run(_run(args))
    json_path = out_dir / "benchmark_results.json"
    md_path = out_dir / "benchmark_summary.md"

    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    lines = [
        "# API Benchmark Summary",
        "",
        f"- Endpoint: `{report['endpoint']}`",
        f"- Requests: `{report['requests']}`",
        f"- Concurrency: `{report['concurrency']}`",
        f"- Success: `{report['success']}`",
        f"- Failed: `{report['failed']}`",
        f"- P95 (ms): `{report['latency_ms']['p95']}`",
        f"- SLA (p95 <= {report['p95_sla_ms']} ms): `{report['sla_passed']}`",
    ]
    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"Benchmark report written to: {out_dir}")
    return 0 if report["sla_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
