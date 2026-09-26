#!/usr/bin/env python3
"""Refresh local IOC store and print lifecycle health status."""

from __future__ import annotations

import argparse
import json

from soc_platform.domains.phishing.engine.paths import PHISHING_HOME

REPO_ROOT = PHISHING_HOME
# (package import; no sys.path hack needed)
from soc_platform.domains.phishing.engine.agents.threat_intel_agent.agent import get_ioc_store_status, refresh_ioc_store


def main() -> int:
    parser = argparse.ArgumentParser(description="Refresh local IOC store from curated feeds")
    parser.add_argument("--force", action="store_true", help="Force refresh regardless of refresh interval")
    args = parser.parse_args()

    refresh_result = refresh_ioc_store(force=args.force)
    status = get_ioc_store_status()

    print(json.dumps({"refresh": refresh_result, "status": status}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
