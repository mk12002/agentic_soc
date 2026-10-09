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

import logging
import os
import queue
import random
import threading
import time
from abc import ABC, abstractmethod
from collections.abc import Callable, Iterable, Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, TypeVar

from sqlalchemy.orm import Session

from soc_platform.core.context_store import ContextStore
from soc_platform.core.models import ConnectorCheckpoint, utcnow
from soc_platform.core.schema import NormalizedRecord

T = TypeVar("T")


MAX_RETRY_AFTER = 120.0   # seconds; a longer Retry-After is capped (the call is retried, then given up)
log = logging.getLogger(__name__)


def max_pages_per_sync() -> int:
    """Pages one stream may read in one sync (SOC_SYNC_MAX_PAGES). A backlog beyond it is not dropped: the stream
    keeps its continuation point and the next sync goes on from there (the report says ``truncated``)."""
    try:
        return max(1, int(os.environ.get("SOC_SYNC_MAX_PAGES", "1000")))
    except ValueError:
        return 1000


PAGE_BUFFER = 8   # pages downloaded ahead of ingestion per stream (sync_many): bounded, so memory stays flat
SYSTEMATIC_FAILURES = 20   # identical consecutive record failures that mean a systematic fault (stop retrying each)


class ConnectorError(Exception):
    pass


class RateLimited(ConnectorError):
    def __init__(self, retry_after: float | None = None) -> None:
        super().__init__(f"rate limited (retry after {retry_after})")
        self.retry_after = retry_after


class TransientError(ConnectorError):
    pass


class AuthExpired(ConnectorError):
    """401: the token was refused (expired, revoked or rotated early). The connector re-authenticates once."""


class PermissionDenied(ConnectorError):
    """403: authenticated, but the identity lacks a permission. Never retried; reported with the scopes needed."""


def _quality(connector: Any, stream: str) -> dict[str, int]:
    """Field coercions since the last sync (a connector not derived from BaseConnector has none to report)."""
    take = getattr(connector, "take_quality", None)
    return take(stream) if callable(take) else {}


def rate_share() -> int:
    """SOC_CONNECTOR_RATE_SHARE: how many processes call the tools at once (API workers + a separate scheduler).
    Each takes 1/N of every tool's request budget, so together they stay within what the vendor allows - a budget
    held in each process would otherwise be multiplied by the number of processes."""
    import os

    try:
        return max(1, min(64, int(os.environ.get("SOC_CONNECTOR_RATE_SHARE", "1") or 1)))
    except ValueError:
        return 1


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


def _sleep(seconds: float) -> None:
    """Back-off wait (module level, so a test of a long outage can make it instant)."""
    time.sleep(seconds)


def with_backoff(fn: Callable[[], T], *, retries: int = 5, base: float = 0.5, cap: float = 30.0,
                 sleep: Callable[[float], None] | None = None) -> T:
    """Retry transient/rate-limit errors with exponential backoff and jitter."""
    attempt = 0
    while True:
        try:
            return fn()
        except RateLimited as exc:
            # honour the vendor's Retry-After, but never let one answer stall a job indefinitely
            delay = min(exc.retry_after, MAX_RETRY_AFTER) if exc.retry_after is not None else min(cap, base * 2 ** attempt)
            last: Exception = exc
        except TransientError as exc:
            delay = min(cap, base * 2 ** attempt) * (0.5 + random.random() / 2)
            last = exc
        attempt += 1
        if attempt > retries:
            # keep the cause: "CERTIFICATE_VERIFY_FAILED" (TLS inspection), a DNS failure or a 503 need different fixes
            raise ConnectorError(f"gave up after {retries} retries: {type(last).__name__}: {str(last)[:300]}") from last
        (sleep or _sleep)(delay)


@dataclass
class Page:
    records: list[dict[str, Any]]
    next_cursor: str | None
    source_total: int | None = None  # tool-reported total, for reconciliation where available
    has_more: bool | None = None  # defaults to "next_cursor is not None"
    # The stream is complete and ``next_cursor`` is where the NEXT sync starts: a time watermark, or None to read the
    # stream from the beginning. Without it the last page's continuation token was kept as the resume point, so the
    # next sync re-read the last page (or failed: Graph skip tokens and Jira page tokens expire).
    reset: bool = False

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
        share = rate_share()
        self.budget = TokenBucket(rate_per_sec / share, max(1, burst // share))

    def __init_subclass__(cls, **kwargs: Any) -> None:
        """Every connector's ``normalize`` first brings the record to the stream's documented shape
        (``connectors/conform.py``): one malformed field no longer costs the whole record."""
        super().__init_subclass__(**kwargs)
        own = cls.__dict__.get("normalize")
        if own is None or getattr(own, "_soc_conformed", False):
            return

        def normalize(self, stream: str, raw: Any, _own=own):
            return _own(self, stream, self.conform(stream, raw))

        normalize._soc_conformed = True   # type: ignore[attr-defined]
        normalize.__doc__ = own.__doc__
        cls.normalize = normalize         # type: ignore[method-assign]

    def conform(self, stream: str, raw: Any) -> Any:
        from collections import Counter

        from soc_platform.connectors.conform import conform, shape_for

        if not isinstance(raw, dict):
            return raw
        shape = shape_for(self, stream)
        if shape is None:
            return raw
        notes = self.__dict__.setdefault("_soc_quality", {}).setdefault(stream, Counter())
        return conform(raw, shape, notes)

    def take_quality(self, stream: str) -> dict[str, int]:
        """Field coercions counted since the last call (path -> count), for the sync report."""
        notes = self.__dict__.get("_soc_quality", {}).pop(stream, None)
        return dict(notes.most_common(20)) if notes else {}

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
        """Wrap an outbound API call with the rate-limit budget and backoff. A refused token (401) is renewed once and
        the call repeated - in fake mode too, so the path is the one a live tenant takes."""
        if not self.budget.acquire():
            raise RateLimited()
        try:
            return with_backoff(fn)
        except AuthExpired:
            reauth = getattr(getattr(self, "http", None), "reauthenticate", None)
            if reauth is None:
                raise
            reauth()
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
    truncated: bool = False   # page limit reached with more to read: the next sync continues
    coerced: dict[str, int] = field(default_factory=dict)   # malformed fields brought to the documented shape

    @property
    def reconciled(self) -> bool:
        expected = self.source_total if self.source_total is not None else self.source_records
        return self.failed == 0 and self.ingested >= expected


class SyncRunner:
    """Incremental pull with checkpointing, resumable backfill and reconciliation (VM-T02)."""

    def __init__(self, session: Session, store: ContextStore, *, commit_pages: bool = True) -> None:
        self.s = session
        self.store = store
        # Commit after every page: an interrupted backfill then resumes from its last page instead of rolling back to
        # the start (the checkpoint used to be only flushed, so a failure at page 500 lost all 500), and a long sync
        # never holds one database transaction open - which on PostgreSQL ran out of lock memory on large streams and
        # on SQLite blocked every other writer (scheduler heartbeat, API) for the whole sync.
        self.commit_pages = commit_pages

    def _checkpoint(self, connector: BaseConnector, stream: str) -> ConnectorCheckpoint:
        cp = self.s.get(ConnectorCheckpoint, (connector.name, stream))
        if cp is None:
            cp = ConnectorCheckpoint(connector=connector.name, stream=stream)
            self.s.add(cp)
            self.s.flush()
        return cp

    @staticmethod
    def _pages(connector: BaseConnector, stream: str, cursor: str | None, max_pages: int) -> Iterator[Page]:
        """The network half of a sync: pages in cursor order (each page's cursor comes from the one before)."""
        for _ in range(max_pages):
            page = connector.call(lambda cur=cursor: connector.fetch_page(stream, cur))
            yield page
            cursor = page.next_cursor or cursor
            if not page.more:
                return

    def sync(self, connector: BaseConnector, stream: str, *, full_backfill: bool = False,
             max_pages: int | None = None, pages: Iterator[Page] | None = None) -> SyncReport:
        max_pages = max_pages or max_pages_per_sync()
        cp = self._checkpoint(connector, stream)
        cursor = None if full_backfill else cp.cursor
        report = SyncReport(connector.name, stream)
        cp.last_attempt_at = utcnow()
        last: Page | None = None
        try:
            for page in (pages if pages is not None else self._pages(connector, stream, cursor, max_pages)):
                last = page
                report.pages += 1
                report.source_records += len(page.records)
                if page.source_total is not None:
                    report.source_total = page.source_total
                self._ingest_page(connector, stream, page, report)
                # Checkpoint after every page so an interrupted backfill resumes, not restarts.
                cursor = page.next_cursor if page.reset else (page.next_cursor or cursor)
                cp.cursor = cursor
                self.s.flush()
                if self.commit_pages and not self.s.in_nested_transaction():
                    self.s.commit()
            cp.last_success_at = utcnow()
            cp.last_error = None
            if last is not None and last.more and report.pages >= max_pages:
                report.truncated = True
                log.warning("%s.%s: page limit (%d) reached with more to read; the next sync continues",
                            connector.name, stream, max_pages)
        except Exception as exc:
            cp.last_error = f"{type(exc).__name__}: {exc}"[:1000]
            report.errors.append(cp.last_error)
        cp.source_count = (cp.source_count or 0) + report.source_records
        cp.ingested_count = (cp.ingested_count or 0) + report.ingested
        cp.failed_count = (cp.failed_count or 0) + report.failed
        report.cursor = cursor
        report.coerced = _quality(connector, stream)
        if report.coerced:          # the vendor sent fields in an unexpected shape: visible, not silently absorbed
            from soc_platform.core.observability import event

            event("connector.data_quality", 30, connector=connector.name, stream=stream,
                  fields_coerced=sum(report.coerced.values()), by_field=report.coerced)
        return report

    def ingest_records(self, connector: BaseConnector, stream: str, records: list[dict[str, Any]]) -> SyncReport:
        """Records that arrive without a sync (pushed by a SIEM): the same isolation as a sync page - a malformed or
        unstorable record is refused with its reason, the rest land."""
        report = SyncReport(connector.name, stream, pages=1, source_records=len(records))
        self._ingest_page(connector, stream, Page(records, None, has_more=False), report)
        report.coerced = _quality(connector, stream)
        return report

    def _ingest_page(self, connector: BaseConnector, stream: str, page: Page, report: SyncReport) -> None:
        """Normalise every record, then store the page in ONE savepoint. Only if that fails is the page replayed record
        by record, each in its own savepoint, so one bad record is still isolated. (A savepoint per record is a
        PostgreSQL subtransaction holding a lock until the transaction ends: thousands of them exhausted the lock
        table - "out of shared memory" - on a large stream.)"""
        ready: list[tuple[dict[str, Any], list[NormalizedRecord]]] = []
        for raw in page.records:
            try:
                ready.append((raw, list(connector.normalize(stream, raw))))
            except Exception as exc:  # one bad record must not stop the stream
                report.failed += 1
                report.errors.append(f"{type(exc).__name__}: {exc}"[:300])

        def store(raw: dict[str, Any], recs: list[NormalizedRecord]) -> None:
            for rec in recs:
                if rec.raw is None:
                    rec.raw = raw
                self.store.ingest(rec)

        try:
            with self.s.begin_nested():
                for raw, recs in ready:
                    store(raw, recs)
            report.ingested += len(ready)
            return
        except Exception as exc:  # replayed below record by record; each failing record is reported there
            log.info("%s.%s: page not storable in one step (%s: %s); storing record by record",
                     connector.name, stream, type(exc).__name__, str(exc)[:200])
        same, last_error = 0, ""
        for i, (raw, recs) in enumerate(ready):
            try:
                with self.s.begin_nested():
                    store(raw, recs)
                report.ingested += 1
                same = 0
            except Exception as exc:  # one bad record must not stop the stream
                report.failed += 1
                err = f"{type(exc).__name__}: {exc}"[:300]
                report.errors.append(err)
                same = same + 1 if err.split(":")[0] == last_error.split(":")[0] else 1
                last_error = err
                if same >= SYSTEMATIC_FAILURES:
                    # every record fails the same way: a systematic fault, not a bad record. Stop opening a
                    # savepoint per record (on PostgreSQL each one holds a lock until commit; 14,000 of them ran
                    # the lock table out) and report the rest of the page as failed with that error.
                    rest = len(ready) - i - 1
                    report.failed += rest
                    log.error("%s.%s: %d records in a row failed (%s); %d more not attempted", connector.name,
                              stream, same, err, rest)
                    return

    def sync_many(self, items: list[tuple[BaseConnector, str]], *, full_backfill: bool = False,
                  max_pages: int | None = None, workers: int = 8) -> list[SyncReport]:
        """Sync several (connector, stream) pairs: every stream downloads at once, while its pages are ingested here,
        stream by stream and page by page, in the order given - the same result as calling ``sync`` for each in
        turn, in about the time of the slowest stream instead of the sum of all of them.

        Only the network half runs in threads (each connector's rate budget still applies). Ingestion stays on this
        thread and this session, which are not shared."""
        max_pages = max_pages or max_pages_per_sync()
        done = object()
        feeds: list[queue.Queue] = []
        pool = ThreadPoolExecutor(max_workers=max(1, min(workers, len(items))))

        def fetch(connector: BaseConnector, stream: str, cursor: str | None, feed: queue.Queue) -> None:
            try:
                for page in self._pages(connector, stream, cursor, max_pages):
                    feed.put(page)
            except BaseException as exc:  # handed to the ingesting thread, which records it as sync() does
                feed.put(exc)
            feed.put(done)

        for connector, stream in items:
            cp = self._checkpoint(connector, stream)
            # bounded: a fast download waits for ingestion instead of holding a whole large stream in memory
            feed: queue.Queue = queue.Queue(maxsize=PAGE_BUFFER)
            feeds.append(feed)
            pool.submit(fetch, connector, stream, None if full_backfill else cp.cursor, feed)

        finished: set[int] = set()

        def drain(feed: queue.Queue) -> Iterator[Page]:
            while True:
                item = feed.get()
                if item is done:
                    finished.add(id(feed))
                    return
                if isinstance(item, BaseException):
                    raise item
                yield item

        def discard(feed: queue.Queue) -> None:
            """Pages ingestion did not take (it stopped early): read them off so the download can finish."""
            while id(feed) not in finished:
                if feed.get() is done:
                    finished.add(id(feed))

        try:
            reports = []
            for (c, st), feed in zip(items, feeds, strict=True):
                reports.append(self.sync(c, st, full_backfill=full_backfill, max_pages=max_pages, pages=drain(feed)))
                discard(feed)
            return reports
        finally:
            for feed in feeds:                  # an unexpected error above: unblock every download before waiting
                discard(feed)
            pool.shutdown(wait=True)


def iter_records(records: Iterable[dict[str, Any]], page_size: int, cursor: str | None) -> Page:
    """Helper for fixture/list-backed connectors: offset cursor pagination."""
    data = list(records)
    start = int(cursor or 0)
    chunk = data[start:start + page_size]
    nxt = start + len(chunk)
    return Page(chunk, str(nxt), source_total=len(data), has_more=nxt < len(data))
