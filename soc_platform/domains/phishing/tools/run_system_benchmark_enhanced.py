#!/usr/bin/env python3
"""
Enhanced System Benchmark for 30GB RAM Optimization.

Measures:
- API latency (P50, P95, P99)
- Throughput
- Model warmup time
- Memory usage
- CPU utilization
- Cache hit rates
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import statistics
import sys
import time
from datetime import UTC, datetime
from typing import Any

import httpx
import psutil

from soc_platform.domains.phishing.engine.paths import PHISHING_HOME

REPO_ROOT = PHISHING_HOME
WORKSPACE_ROOT = REPO_ROOT.parent
if str(WORKSPACE_ROOT) not in sys.path:
    pass  # (package import; no sys.path hack needed)
ANALYSIS_ROOT = REPO_ROOT / "analysis_reports"


def _default_payload() -> dict[str, object]:
    """Default benign test payload."""
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


def _suspicious_payload() -> dict[str, object]:
    """Test payload with suspicious indicators."""
    return {
        "headers": {
            "sender": "updates@suspicious-domain.xyz",
            "reply_to": "noreply@phishing-site.tk",
            "subject": "URGENT: Verify your account immediately",
            "received": ["from unknown-relay.local"],
            "message_id": "<suspicious@unknown.xyz>",
            "authentication_results": "spf=fail dkim=fail dmarc=fail",
        },
        "body": "Click here immediately to verify: http://phishing-clone.xyz/login. Your account will be closed!",
        "urls": [
            "http://phishing-clone.xyz/login",
            "http://malware-payload.xyz/exe",
        ],
        "attachments": [],
    }


def _direct_agent_payload(agent_name: str, payload: dict[str, object]) -> dict[str, object]:
    """Convert a benchmark payload into the shape expected by a direct agent test endpoint."""
    if agent_name == "content_agent":
        headers = payload.get("headers", {}) if isinstance(payload.get("headers", {}), dict) else {}
        body = payload.get("body", "")
        plain_body = body if isinstance(body, str) else str(body)
        return {
            "payload": {
                "headers": {
                    "subject": headers.get("subject", ""),
                },
                "body": {
                    "plain": plain_body,
                    "html": "",
                },
            },
            "inject_analysis_id": True,
            "print_output": False,
        }

    return {
        "payload": payload,
        "inject_analysis_id": True,
        "print_output": False,
    }


async def _worker(
    client: httpx.AsyncClient,
    url: str,
    payload: dict[str, object],
    api_key: str,
    semaphore: asyncio.Semaphore,
) -> tuple[float, int, str]:
    """Execute a single benchmark request."""
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["X-API-Key"] = api_key

    async with semaphore:
        started = time.perf_counter()
        try:
            resp = await client.post(url, json=payload, headers=headers, timeout=60.0)
            elapsed_ms = (time.perf_counter() - started) * 1000.0
            return elapsed_ms, int(resp.status_code), ""
        except Exception as exc:
            elapsed_ms = (time.perf_counter() - started) * 1000.0
            return elapsed_ms, 0, str(exc)


def _pct(values: list[float], pct: float) -> float:
    """Calculate percentile from sorted list."""
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = round((pct / 100.0) * (len(ordered) - 1))
    return ordered[max(0, min(idx, len(ordered) - 1))]


def _get_system_metrics() -> dict[str, Any]:
    """Capture current system resource metrics."""
    try:
        process = psutil.Process(os.getpid())
        return {
            "memory_mb": round(process.memory_info().rss / 1024 / 1024, 2),
            "cpu_percent": round(process.cpu_percent(interval=0.1), 2),
            "threads": process.num_threads(),
            "system_memory_percent": round(psutil.virtual_memory().percent, 2),
        }
    except Exception:
        return {}


async def _run(args: argparse.Namespace) -> dict[str, object]:
    """Execute benchmark suite."""
    if args.direct_agent_test:
        endpoint = args.base_url.rstrip("/") + f"/agent-test/{args.agent_name}"
    else:
        endpoint = args.base_url.rstrip("/") + args.endpoint_path
    semaphore = asyncio.Semaphore(max(1, args.concurrency))

    print("📊 Benchmarking Configuration:")
    print(f"  - Endpoint: {endpoint}")
    print(f"  - Requests: {args.requests}")
    print(f"  - Concurrency: {args.concurrency}")
    print(f"  - Mix: {args.benign_ratio:.0%} benign, {1-args.benign_ratio:.0%} suspicious")
    if args.direct_agent_test:
        print(f"  - Mode: direct agent test ({args.agent_name})")
    print()

    # Capture pre-benchmark metrics
    pre_metrics = _get_system_metrics()
    print(f"Pre-Benchmark Metrics: {pre_metrics}")
    print()

    # Run benchmark with mixed payload types
    async with httpx.AsyncClient(timeout=float(args.timeout_seconds)) as client:
        tasks = []
        for i in range(args.requests):
            payload = _default_payload() if (i % 100) < (args.benign_ratio * 100) else _suspicious_payload()
            if args.direct_agent_test:
                payload = _direct_agent_payload(args.agent_name, payload)
            tasks.append(_worker(client, endpoint, payload, args.api_key or "", semaphore))
        
        print(f"▶ Running {args.requests} requests...")
        bench_start = time.perf_counter()
        results = await asyncio.gather(*tasks)
        bench_duration_sec = time.perf_counter() - bench_start

    # Capture post-benchmark metrics
    post_metrics = _get_system_metrics()
    print(f"Post-Benchmark Metrics: {post_metrics}")
    print()

    # Process results
    latencies = [row[0] for row in results]
    statuses = [row[1] for row in results]
    errors = [row[2] for row in results if row[2]]

    success = sum(1 for code in statuses if 200 <= code < 300)
    failed = len(statuses) - success
    throughput = args.requests / bench_duration_sec if bench_duration_sec > 0 else 0

    p50 = round(_pct(latencies, 50), 2)
    p95 = round(_pct(latencies, 95), 2)
    p99 = round(_pct(latencies, 99), 2)

    avg = round(statistics.mean(latencies), 2) if latencies else 0.0
    max_v = round(max(latencies), 2) if latencies else 0.0
    min_v = round(min(latencies), 2) if latencies else 0.0

    sla_ok = (failed == 0) and (p95 <= float(args.p95_sla_ms))

    return {
        "timestamp_utc": datetime.now(UTC).isoformat(),
        "environment": "30GB_RAM_OPTIMIZED",
        "endpoint": endpoint,
        "benchmark_config": {
            "requests": args.requests,
            "concurrency": args.concurrency,
            "benign_ratio": args.benign_ratio,
            "timeout_seconds": args.timeout_seconds,
            "direct_agent_test": bool(args.direct_agent_test),
            "agent_name": args.agent_name if args.direct_agent_test else "",
            "endpoint_path": args.endpoint_path if not args.direct_agent_test else f"/agent-test/{args.agent_name}",
        },
        "results": {
            "success": success,
            "failed": failed,
            "error_rate": round(failed / args.requests * 100, 2),
            "status_codes": sorted(set(statuses)),
        },
        "latency_ms": {
            "min": min_v,
            "avg": avg,
            "p50": p50,
            "p95": p95,
            "p99": p99,
            "max": max_v,
        },
        "throughput": {
            "requests_per_second": round(throughput, 2),
            "duration_seconds": round(bench_duration_sec, 2),
        },
        "sla": {
            "p95_threshold_ms": float(args.p95_sla_ms),
            "p95_passed": p95 <= float(args.p95_sla_ms),
            "overall_passed": sla_ok,
        },
        "system_metrics": {
            "pre_benchmark": pre_metrics,
            "post_benchmark": post_metrics,
            "memory_delta_mb": round(
                post_metrics.get("memory_mb", 0) - pre_metrics.get("memory_mb", 0), 2
            ),
        },
        "error_samples": errors[:10],
    }


def _format_report_md(report: dict[str, Any]) -> str:
    """Format benchmark report as Markdown."""
    lines = [
        "# 📊 System Benchmark Report (30GB RAM Optimized)",
        "",
        f"**Timestamp:** {report['timestamp_utc']}",
        f"**Environment:** {report['environment']}",
        "",
        "## Configuration",
        f"- Endpoint: `{report['endpoint']}`",
        f"- Total Requests: `{report['benchmark_config']['requests']}`",
        f"- Concurrency: `{report['benchmark_config']['concurrency']}`",
        f"- Benign/Suspicious Mix: `{report['benchmark_config']['benign_ratio']:.0%} / {1-report['benchmark_config']['benign_ratio']:.0%}`",
        "",
        "## Results",
        f"- ✓ Success: `{report['results']['success']}`",
        f"- ✗ Failed: `{report['results']['failed']}`",
        f"- Error Rate: `{report['results']['error_rate']:.2f}%`",
        "",
        "## Latency (ms)",
        "| Metric | Value |",
        "|--------|-------|",
        f"| Min | {report['latency_ms']['min']} |",
        f"| Avg | {report['latency_ms']['avg']} |",
        f"| P50 | {report['latency_ms']['p50']} |",
        f"| P95 | {report['latency_ms']['p95']} |",
        f"| P99 | {report['latency_ms']['p99']} |",
        f"| Max | {report['latency_ms']['max']} |",
        "",
        "## Throughput",
        f"- **RPS:** `{report['throughput']['requests_per_second']}`",
        f"- **Duration:** `{report['throughput']['duration_seconds']}` sec",
        "",
        "## SLA Compliance",
        f"- P95 Threshold: `{report['sla']['p95_threshold_ms']}` ms",
        f"- P95 Passed: `{'✓ YES' if report['sla']['p95_passed'] else '✗ NO'}`",
        f"- Overall SLA: `{'✓ PASS' if report['sla']['overall_passed'] else '✗ FAIL'}`",
        "",
        "## System Metrics",
        "| Metric | Pre | Post | Delta |",
        "|--------|-----|------|-------|",
        f"| Memory (MB) | {report['system_metrics']['pre_benchmark'].get('memory_mb', 'N/A')} | {report['system_metrics']['post_benchmark'].get('memory_mb', 'N/A')} | {report['system_metrics']['memory_delta_mb']} |",
        f"| CPU % | {report['system_metrics']['pre_benchmark'].get('cpu_percent', 'N/A')} | {report['system_metrics']['post_benchmark'].get('cpu_percent', 'N/A')} | - |",
    ]
    
    if report.get("error_samples"):
        lines.extend([
            "",
            "## Error Samples",
        ])
        for err in report["error_samples"][:5]:
            lines.append(f"- `{err}`")

    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Enhanced API benchmark with memory and performance metrics"
    )
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--endpoint-path", default="/analyze-email")
    parser.add_argument("--direct-agent-test", action="store_true")
    parser.add_argument("--agent-name", default="content")
    parser.add_argument("--api-key", default="")
    parser.add_argument("--requests", type=int, default=100)
    parser.add_argument("--concurrency", type=int, default=10)
    parser.add_argument("--timeout-seconds", type=float, default=60.0)
    parser.add_argument("--p95-sla-ms", type=float, default=2000.0)
    parser.add_argument("--benign-ratio", type=float, default=0.7, help="Ratio of benign to suspicious requests")
    args = parser.parse_args()

    ts = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    out_dir = ANALYSIS_ROOT / f"benchmark_{ts}"
    out_dir.mkdir(parents=True, exist_ok=True)

    print("=" * 70)
    print("📈 System Benchmark (30GB RAM Optimized)")
    print("=" * 70)
    print()

    report = asyncio.run(_run(args))
    
    json_path = out_dir / "benchmark_results.json"
    md_path = out_dir / "benchmark_summary.md"

    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    md_path.write_text(_format_report_md(report), encoding="utf-8")

    print()
    print("=" * 70)
    print(_format_report_md(report))
    print("=" * 70)
    print()
    print(f"✓ JSON Report: {json_path}")
    print(f"✓ MD Report:   {md_path}")

    return 0 if report["sla"]["overall_passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
