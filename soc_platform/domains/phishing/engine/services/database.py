"""Shared PostgreSQL connection helpers.

The application can run either from the host workspace or inside Docker.
In the host layout, Docker-only hostnames like ``database`` are not resolvable.
This helper tries the configured URL first and then a small set of sensible
fallback hostnames so report reads and writes keep working in both modes.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse, urlunparse

import psycopg2


_LOCAL_HOSTS = {"localhost", "127.0.0.1", "host.docker.internal"}
_DOCKER_HOSTS = {"database", "postgres", "db"}


@dataclass(frozen=True)
class DatabaseConnectionAttempt:
    url: str
    host: str | None


def _render_netloc(parsed, host: str) -> str:
    auth = ""
    if parsed.username:
        auth = parsed.username
        if parsed.password:
            auth += f":{parsed.password}"
        auth += "@"
    port = f":{parsed.port}" if parsed.port else ""
    return f"{auth}{host}{port}"


def _candidate_urls(database_url: str) -> list[DatabaseConnectionAttempt]:
    parsed = urlparse(database_url)
    host = parsed.hostname
    candidates: list[str] = [database_url]

    if host in _DOCKER_HOSTS:
        for alt in ("localhost", "127.0.0.1", "host.docker.internal"):
            candidates.append(urlunparse(parsed._replace(netloc=_render_netloc(parsed, alt))))
    elif host in _LOCAL_HOSTS:
        candidates.append(urlunparse(parsed._replace(netloc=_render_netloc(parsed, "database"))))

    seen: set[str] = set()
    ordered: list[DatabaseConnectionAttempt] = []
    for candidate in candidates:
        if candidate in seen:
            continue
        seen.add(candidate)
        ordered.append(DatabaseConnectionAttempt(url=candidate, host=urlparse(candidate).hostname))
    return ordered


def connect_database(
    database_url: str,
    *,
    max_retries: int = 3,
    initial_delay: float = 0.5,
    connect_timeout: int = 5,
    logger: Any | None = None,
):
    """Connect to PostgreSQL, falling back across hostnames if needed."""

    last_error: Exception | None = None
    candidates = _candidate_urls(database_url)

    for attempt in range(max_retries):
        for candidate in candidates:
            try:
                if logger is not None:
                    logger.debug(
                        "Connecting to PostgreSQL",
                        url=candidate.url,
                        attempt=attempt + 1,
                        max_retries=max_retries,
                    )
                return psycopg2.connect(candidate.url, connect_timeout=connect_timeout)
            except Exception as exc:  # pragma: no cover - runtime/network dependent
                last_error = exc
                if logger is not None:
                    logger.warning(
                        "Database connection attempt failed",
                        url=candidate.url,
                        host=candidate.host,
                        attempt=attempt + 1,
                        error=str(exc),
                    )

        if attempt < max_retries - 1:
            import time

            sleep_for = min(initial_delay * (2**attempt), 5.0)
            if logger is not None:
                logger.info("Retrying PostgreSQL connection", sleep_seconds=sleep_for)
            time.sleep(sleep_for)

    if last_error is None:
        raise psycopg2.OperationalError("Unable to establish a PostgreSQL connection")
    raise last_error