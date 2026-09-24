#!/usr/bin/env python3
"""Simulate degraded orchestrator conditions and assert SLOs.

Focuses on slow/missing-agent behavior and queue-pressure finalization latency.
"""

from __future__ import annotations
from soc_platform.domains.phishing.engine.paths import PHISHING_HOME

import json
import random
import statistics
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = PHISHING_HOME
WORKSPACE_ROOT = REPO_ROOT.parent
if str(WORKSPACE_ROOT) not in sys.path:
    pass  # (package import; no sys.path hack needed)
from soc_platform.domains.phishing.engine.configs.settings import settings
from soc_platform.domains.phishing.engine.orchestrator.runner import EXPECTED_AGENTS, OrchestratorWorker

ANALYSIS_ROOT = REPO_ROOT / "analysis_reports"


def _pct(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = int(round((pct / 100.0) * (len(ordered) - 1)))
    idx = max(0, min(idx, len(ordered) - 1))
    return ordered[idx]


def _simulate_finalize_latency(total_analyses: int, seed: int = 7) -> list[float]:
    rng = random.Random(seed)
    worker = OrchestratorWorker.__new__(OrchestratorWorker)
    timeout = float(settings.orchestrator_partial_timeout_seconds)
    min_agents = int(settings.orchestrator_min_agents_for_decision)
    agents = sorted(EXPECTED_AGENTS)

    latencies: list[float] = []
    for _ in range(total_analyses):
        # 40% complete quickly, 60% partial timeout scenarios.
        complete_case = rng.random() < 0.4
        if complete_case:
            count = len(agents)
            elapsed = rng.uniform(1.0, timeout * 0.6)
        else:
            count = rng.randint(min_agents, len(agents) - 1)
            elapsed = timeout + rng.uniform(0.1, 3.0)

        subset = [{"agent_name": name, "risk_score": 0.1} for name in agents[:count]]
        should_finalize, _reason = worker._should_finalize(subset, datetime.now(timezone.utc).timestamp() - elapsed)
        if should_finalize:
            latencies.append(float(elapsed))

    return latencies


def main() -> int:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out_dir = ANALYSIS_ROOT / f"degraded_slo_{ts}"
    out_dir.mkdir(parents=True, exist_ok=True)

    latencies = _simulate_finalize_latency(total_analyses=600)
    p95 = _pct(latencies, 95)
    p99 = _pct(latencies, 99)
    timeout = float(settings.orchestrator_partial_timeout_seconds)
    max_allowed_p95 = timeout + 5.0

    report = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "orchestrator_partial_timeout_seconds": timeout,
        "samples": len(latencies),
        "latency_seconds": {
            "min": round(min(latencies), 3) if latencies else 0.0,
            "avg": round(statistics.mean(latencies), 3) if latencies else 0.0,
            "p95": round(p95, 3),
            "p99": round(p99, 3),
            "max": round(max(latencies), 3) if latencies else 0.0,
        },
        "slo": {
            "p95_max_seconds": max_allowed_p95,
            "passed": bool(p95 <= max_allowed_p95),
        },
    }

    json_path = out_dir / "degraded_mode_slo.json"
    md_path = out_dir / "degraded_mode_slo.md"
    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    lines = [
        "# Degraded Mode SLO",
        "",
        f"- Samples: `{report['samples']}`",
        f"- Timeout baseline (s): `{timeout}`",
        f"- P95 latency (s): `{report['latency_seconds']['p95']}`",
        f"- P99 latency (s): `{report['latency_seconds']['p99']}`",
        f"- SLO passed: `{report['slo']['passed']}`",
    ]
    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"SLO report written to: {out_dir}")
    return 0 if report["slo"]["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
