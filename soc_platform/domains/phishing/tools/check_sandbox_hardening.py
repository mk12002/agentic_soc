#!/usr/bin/env python3
"""Fail-fast sandbox hardening checks intended for CI and release gates."""

from __future__ import annotations

import argparse
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from soc_platform.domains.phishing.engine.paths import PHISHING_HOME

REPO_ROOT = PHISHING_HOME
def _load_dotenv(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values

    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def _compose_has_docker_sock(compose_path: Path) -> bool:
    if not compose_path.exists():
        return False
    for raw in compose_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "/var/run/docker.sock" in line:
            return True
    return False


def run_checks(
    *,
    repo_root: Path,
    compose_rel: str,
    env_file_rel: str,
    allow_docker_sock: bool,
) -> dict[str, Any]:
    compose_path = repo_root / compose_rel
    env_file = repo_root / env_file_rel

    dotenv = _load_dotenv(env_file)
    env = dict(dotenv)
    env.update({k: v for k, v in os.environ.items() if isinstance(v, str)})

    sandbox_executor_url = str(env.get("SANDBOX_EXECUTOR_URL", "")).strip()
    sandbox_executor_token = str(env.get("SANDBOX_EXECUTOR_SHARED_TOKEN", "")).strip()

    violations: list[str] = []
    checks: list[dict[str, Any]] = []

    docker_sock_mounted = _compose_has_docker_sock(compose_path)
    docker_sock_ok = allow_docker_sock or (not docker_sock_mounted)
    checks.append(
        {
            "name": "no_docker_sock_mount",
            "passed": docker_sock_ok,
            "details": {
                "compose": str(compose_path),
                "docker_sock_mounted": docker_sock_mounted,
                "allow_docker_sock": allow_docker_sock,
            },
        }
    )
    if not docker_sock_ok:
        violations.append(
            "docker_sock_mount_detected: remove /var/run/docker.sock mount for sandbox agent in hardened CI/production profiles"
        )

    token_required_ok = True
    if sandbox_executor_url and not sandbox_executor_token:
        token_required_ok = False
        violations.append(
            "sandbox_executor_missing_token: SANDBOX_EXECUTOR_URL is set but SANDBOX_EXECUTOR_SHARED_TOKEN is empty"
        )
    checks.append(
        {
            "name": "sandbox_executor_token_required_when_url_set",
            "passed": token_required_ok,
            "details": {
                "sandbox_executor_url_configured": bool(sandbox_executor_url),
                "sandbox_executor_shared_token_set": bool(sandbox_executor_token),
            },
        }
    )

    return {
        "timestamp_utc": datetime.now(UTC).isoformat(),
        "checks": checks,
        "violations": violations,
        "passed": len(violations) == 0,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run sandbox hardening checks for CI")
    parser.add_argument(
        "--compose",
        default="docker/docker-compose.yml",
        help="Compose file path relative to email_security/",
    )
    parser.add_argument(
        "--env-file",
        default=".env",
        help="Environment file path relative to email_security/",
    )
    parser.add_argument(
        "--allow-docker-sock",
        action="store_true",
        help="Allow docker.sock mount (for local/dev parity only)",
    )
    args = parser.parse_args()

    report = run_checks(
        repo_root=REPO_ROOT,
        compose_rel=str(args.compose),
        env_file_rel=str(args.env_file),
        allow_docker_sock=bool(args.allow_docker_sock),
    )
    print(json.dumps(report, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
