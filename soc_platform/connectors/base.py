"""Uniform connector interface (section 5.3 connector layer, NFR-14, VM-T02, IM-T02, IM-T04, R06).

A connector adapts one security tool. It implements:
  * ``streams``         - named datasets it can pull (e.g. "alerts", "vulnerabilities")
  * ``fetch_page()``    - one page of raw records for a stream from a cursor
  * ``normalize()``     - raw record -> ``NormalizedRecord`` (canonical schema)
  * ``lookup()``        - on-demand enrichment queries (per-entity, used by agents)
  * action specs        - write operations, registered separately and policy-gated

The ``SyncRunner`` handles cursor checkpointing, resumable backfill, rate-limit
budgets with exponential backoff, raw payload retention and source-vs-ingested
reconciliation counts. Replacing a tool is a connector swap, not a redesign.
"""

from __future__ import annotations

import random
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, TypeVar

from sqlalchemy.orm import Session

from soc_platform.core.context_store import ContextStore
from soc_platform.core.models import ConnectorCheckpoint, utcnow
from soc_platform.core.schema import NormalizedRecord

T = TypeVar("T")


class ConnectorError(Exception):
    pass


class RateLimited(ConnectorError):
    def __init__(self, retry_after: float | None = None) -> None:
        super().__init__(f"rate limited (retry after {retry_after})")
        self.retry_after = retry_after


class TransientError(ConnectorError):
    pass


class TokenBucket:
    """Per-tool request budget so enrichment traffic cannot degrade the source platform (IM-T04)."""

    def __init__(self, rate_per_sec: float, burst: int) -> None:
        self.rate = rate_per_sec
        self.capacity = burst
        self.tokens = float(burst)
        self.updated = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self, timeout: float = 30.0) -> bool:
        deadline = time.monotonic() + timeout
        while True:
            with self._lock:
                now = time.monotonic()
                self.tokens = min(self.capacity, self.tokens + (now - self.updated) * self.rate)
                self.updated = now
                if self.tokens >= 1:
                    self.tokens -= 1
                    return True
                wait = (1 - self.tokens) / self.rate if self.rate > 0 else timeout
            if time.monotonic() + wait > deadline:
                return False
            time.sleep(min(wait, 1.0))


def with_backoff(fn: Callable[[], T], *, retries: int = 5, base: float = 0.5, cap: float = 30.0,
                 sleep: Callable[[float], None] = time.sleep) -> T:
    """Retry transient/rate-limit errors with exponential backoff and jitter."""
    attempt = 0
    while True:
        try:
            return fn()
        except RateLimited as exc:
            delay = exc.retry_after if exc.retry_after is not None else min(cap, base * 2 ** attempt)
        except TransientError:
            delay = min(cap, base * 2 ** attempt) * (0.5 + random.random() / 2)
        attempt += 1
        if attempt > retries:
            raise ConnectorError(f"gave up after {retries} retries")
        sleep(delay)


@dataclass
class Page:
    records: list[dict[str, Any]]
    next_cursor: str | None
    source_total: int | None = None  # tool-reported total, for reconciliation where available
    has_more: bool | None = None  # defaults to "next_cursor is not None"

    @property
    def more(self) -> bool:
        return self.has_more if self.has_more is not None else self.next_cursor is not None


@dataclass
class LookupResult:
    """Result of an on-demand enrichment lookup (partial-result aware, IM-F15)."""

    source: str
    dimension: str
    ok: bool
    records: list[NormalizedRecord] = field(default_factory=list)
    summary: str = ""
    error: str | None = None
    deep_link: str | None = None
    elapsed_ms: float = 0.0
    signals: dict[str, Any] = field(default_factory=dict)  # structured facts for deterministic scoring


class BaseConnector(ABC):
    name: str = ""
    tool: str = ""
    dimension: str = "other"
    streams: tuple[str, ...] = ()
    lookups: tuple[str, ...] = ()  # e.g. ("host", "user", "ip", "domain")
    read_scopes: tuple[str, ...] = ()
    write_scopes: tuple[str, ...] = ()

    def __init__(self, *, rate_per_sec: float = 5.0, burst: int = 10) -> None:
        self.budget = TokenBucket(rate_per_sec, burst)

    # -- required ----------------------------------------------------------------------------
    @abstractmethod
    def fetch_page(self, stream: str, cursor: str | None) -> Page: ...

    @abstractmethod
    def normalize(self, stream: str, raw: dict[str, Any]) -> list[NormalizedRecord]: ...

    # -- optional ----------------------------------------------------------------------------
    def health(self) -> dict[str, Any]:
        return {"ok": True}

    def lookup(self, entity_type: str, value: str, **context: Any) -> LookupResult:
        return LookupResult(self.tool, self.dimension, False, error=f"{self.tool} has no {entity_type} lookup")

    def call(self, fn: Callable[[], T]) -> T:
        """Wrap an outbound API call with the rate-limit budget and backoff."""
        if not self.budget.acquire():
            raise RateLimited()
        return with_backoff(fn)

    def describe(self) -> dict[str, Any]:
        return {"name": self.name, "tool": self.tool, "dimension": self.dimension, "streams": list(self.streams),
                "lookups": list(self.lookups), "read_scopes": list(self.read_scopes),
                "write_scopes": list(self.write_scopes)}


@dataclass
class SyncReport:
    connector: str
    stream: str
    pages: int = 0
    source_records: int = 0
    ingested: int = 0
    failed: int = 0
    errors: list[str] = field(default_factory=list)
    cursor: str | None = None
    source_total: int | None = None

    @property
    def reconciled(self) -> bool:
        expected = self.source_total if self.source_total is not None else self.source_records
        return self.failed == 0 and self.ingested >= expected


class SyncRunner:
    """Incremental pull with checkpointing, resumable backfill and reconciliation (VM-T02)."""

    def __init__(self, session: Session, store: ContextStore) -> None:
        self.s = session
        self.store = store

    def _checkpoint(self, connector: BaseConnector, stream: str) -> ConnectorCheckpoint:
        cp = self.s.get(ConnectorCheckpoint, (connector.name, stream))
        if cp is None:
            cp = ConnectorCheckpoint(connector=connector.name, stream=stream)
            self.s.add(cp)
            self.s.flush()
        return cp

    def sync(self, connector: BaseConnector, stream: str, *, full_backfill: bool = False,
             max_pages: int = 1000) -> SyncReport:
        cp = self._checkpoint(connector, stream)
        cursor = None if full_backfill else cp.cursor
        report = SyncReport(connector.name, stream)
        cp.last_attempt_at = utcnow()
        try:
            for _ in range(max_pages):
                page = connector.call(lambda: connector.fetch_page(stream, cursor))
                report.pages += 1
                report.source_records += len(page.records)
                if page.source_total is not None:
                    report.source_total = page.source_total
                for raw in page.records:
                    try:
                        with self.s.begin_nested():
                            for rec in connector.normalize(stream, raw):
                                if rec.raw is None:
                                    rec.raw = raw
                                self.store.ingest(rec)
                        report.ingested += 1
                    except Exception as exc:  # one bad record must not stop the stream
                        report.failed += 1
                        report.errors.append(f"{type(exc).__name__}: {exc}"[:300])
                # Checkpoint after every page so an interrupted backfill resumes, not restarts.
                cursor = page.next_cursor or cursor
                cp.cursor = cursor
                self.s.flush()
                if not page.more:
                    break
            cp.last_success_at = utcnow()
            cp.last_error = None
        except Exception as exc:
            cp.last_error = f"{type(exc).__name__}: {exc}"[:1000]
            report.errors.append(cp.last_error)
        cp.source_count = (cp.source_count or 0) + report.source_records
        cp.ingested_count = (cp.ingested_count or 0) + report.ingested
        cp.failed_count = (cp.failed_count or 0) + report.failed
        report.cursor = cursor
        return report


def iter_records(records: Iterable[dict[str, Any]], page_size: int, cursor: str | None) -> Page:
    """Helper for fixture/list-backed connectors: offset cursor pagination."""
    data = list(records)
    start = int(cursor or 0)
    chunk = data[start:start + page_size]
    nxt = start + len(chunk)
    return Page(chunk, str(nxt), source_total=len(data), has_more=nxt < len(data))
