#!/usr/bin/env python3
"""Process Garuda retry queue with exponential backoff reconciliation."""

from __future__ import annotations

import argparse
import json

from soc_platform.domains.phishing.engine.paths import PHISHING_HOME

REPO_ROOT = PHISHING_HOME
# (package import; no sys.path hack needed)
from soc_platform.domains.phishing.engine.garuda_integration.retry_queue import process_garuda_retries


def main() -> int:
    parser = argparse.ArgumentParser(description="Process queued Garuda retries")
    parser.add_argument("--max-items", type=int, default=50, help="Maximum retry messages to process")
    args = parser.parse_args()

    result = process_garuda_retries(max_items=max(1, args.max_items))
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
