#!/usr/bin/env python3
"""Bootstrap runtime dependencies like queues and IOC freshness."""

from __future__ import annotations
from soc_platform.domains.phishing.engine.paths import PHISHING_HOME

import argparse
import json
import sys
from typing import Any


REPO_ROOT = PHISHING_HOME
if str(REPO_ROOT.parent) not in sys.path:
    pass  # (package import; no sys.path hack needed)
from soc_platform.domains.phishing.engine.agents.threat_intel_agent.agent import get_ioc_store_status, refresh_ioc_store
from soc_platform.domains.phishing.engine.configs.settings import settings
from soc_platform.domains.phishing.engine.services.messaging_service import RabbitMQClient


def bootstrap_runtime_state(
    *,
    declare_results_queue: bool = True,
    refresh_ioc: bool = True,
    force_ioc_refresh: bool = True,
) -> dict[str, Any]:
    """Ensure baseline runtime dependencies are ready.

    Returns a detailed status report; this function is intentionally non-throwing
    for non-critical bootstrap failures so services can still start in degraded mode.
    """
    report: dict[str, Any] = {
        "declare_results_queue": {
            "requested": bool(declare_results_queue),
            "ok": True,
            "queue": None,
        },
        "ioc_refresh": {
            "requested": bool(refresh_ioc),
            "ok": True,
            "forced": bool(force_ioc_refresh),
            "refresh": None,
            "status": None,
        },
        "overall_ok": True,
    }

    if declare_results_queue:
        mq = RabbitMQClient()
        try:
            mq.connect()
            queue_name = mq.declare_results_queue(settings.results_queue)
            report["declare_results_queue"]["queue"] = queue_name
        except Exception as exc:
            report["declare_results_queue"]["ok"] = False
            report["declare_results_queue"]["error"] = str(exc)
        finally:
            try:
                mq.close()
            except Exception:
                pass

    if refresh_ioc:
        try:
            refresh = refresh_ioc_store(force=bool(force_ioc_refresh))
            status = get_ioc_store_status()
            report["ioc_refresh"]["refresh"] = refresh
            report["ioc_refresh"]["status"] = status
            report["ioc_refresh"]["ok"] = not bool(status.get("is_stale"))
        except Exception as exc:
            report["ioc_refresh"]["ok"] = False
            report["ioc_refresh"]["error"] = str(exc)

    report["overall_ok"] = bool(report["declare_results_queue"]["ok"] and report["ioc_refresh"]["ok"])
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description="Bootstrap runtime dependencies for API/orchestrator startup")
    parser.add_argument("--skip-results-queue", action="store_true", help="Skip results queue declaration")
    parser.add_argument("--skip-ioc-refresh", action="store_true", help="Skip IOC refresh")
    parser.add_argument(
        "--ioc-non-forced",
        action="store_true",
        help="Refresh IOC in interval-aware mode instead of force refresh",
    )
    args = parser.parse_args()

    report = bootstrap_runtime_state(
        declare_results_queue=not bool(args.skip_results_queue),
        refresh_ioc=not bool(args.skip_ioc_refresh),
        force_ioc_refresh=not bool(args.ioc_non_forced),
    )
    print(json.dumps(report, indent=2))
    return 0 if bool(report.get("overall_ok")) else 1


if __name__ == "__main__":
    raise SystemExit(main())
