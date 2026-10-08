"""Helpers shared by tool connectors."""

from __future__ import annotations

import os
import re
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

from soc_platform.connectors.base import AuthExpired, BaseConnector, LookupResult, PermissionDenied
from soc_platform.connectors.http import Response, Transport
from soc_platform.core.actions import ActionSpec
from soc_platform.core.models import utcnow
from soc_platform.core.schema import NormalizedRecord


def parse_ts(v: Any) -> datetime | None:
    if v in (None, ""):
        return None
    if isinstance(v, (int, float)):
        return datetime.fromtimestamp(v / 1000 if v > 1e11 else v, tz=UTC)
    s = str(v).strip().replace("Z", "+00:00")
    if "." in s:  # trim >6 fractional digits (Graph returns 7)
        head, _, rest = s.partition(".")
        # only the digits right after the dot are the fraction: the offset that may follow (Jira "+0530") was once
        # swallowed into it, so "12:00:00.000+0530" read as 12:00 UTC
        frac = re.match(r"\d*", rest).group(0)
        tz = rest[len(frac):]
        if re.fullmatch(r"[+-]\d{4}", tz):
            tz = f"{tz[:3]}:{tz[3:]}"
        s = f"{head}.{frac[:6]}{tz}" if frac else f"{head}{tz}"
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
            try:
                dt = datetime.strptime(s[:19], fmt).replace(tzinfo=UTC)     # vendor times without offset are UTC
                break
            except ValueError:
                continue
        else:
            return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def need(rec: Any, key: str) -> Any:
    """A record's identifier. Without one a record cannot be stored or de-duplicated, so it is refused with a reason
    (one failed record in the sync report) rather than crashing on a KeyError."""
    v = rec.get(key) if isinstance(rec, dict) else None
    if v in (None, ""):
        raise ValueError(f"record without its identifier '{key}'")
    return v


def sev_from_score(score: float | None, scale: float = 10.0) -> str:
    if score is None:
        return "informational"
    x = float(score) / scale * 10.0
    if x >= 9.0:
        return "critical"
    if x >= 7.0:
        return "high"
    if x >= 4.0:
        return "medium"
    if x > 0:
        return "low"
    return "informational"


def sev_name(v: Any) -> str:
    s = str(v or "").lower()
    return {"informational": "informational", "info": "informational", "low": "low", "medium": "medium",
            "moderate": "medium", "high": "high", "critical": "critical", "severe": "critical"}.get(s, "medium" if s else "informational")


FUTURE_TOLERANCE = timedelta(hours=1)


def watermark_overlap(conn: Any) -> timedelta:
    """How far before the newest time seen the next sync asks from. Logs (sign-ins, audits, DNS) are indexed minutes
    after the event, so a record can arrive with a time older than one already read; asking exactly from the mark
    would lose it forever. Ingest is idempotent, so the overlap costs a re-read, never a duplicate."""
    v = (getattr(conn, "settings", None) or {}).get("watermark_overlap_minutes") \
        or os.environ.get("SOC_WATERMARK_OVERLAP_MINUTES", "30")
    try:
        return timedelta(minutes=max(0.0, float(v)))
    except (TypeError, ValueError):
        return timedelta(minutes=30)


class Watermark:
    """The newest change time seen while one stream is read, kept on the connector between its pages.

    ``start(cursor)`` -> the time to ask from (the mark minus the overlap; None for a full read); ``see(records,
    field)`` raises the mark; ``finish()`` -> the next sync's cursor (``since:<newest UTC time seen>``, or None when
    nothing carried a time). A time more than an hour in the future (a device with a wrong clock) is ignored: it would
    move the mark past every real record and silently stop the stream."""

    def __init__(self, overlap: timedelta = timedelta(0)) -> None:
        self.since: str | None = None
        self.best = None
        self.overlap = overlap

    @staticmethod
    def of(conn: Any, key: str) -> Watermark:
        marks = conn.__dict__.setdefault("_watermarks", {})
        wm = marks.setdefault(key, Watermark())
        wm.overlap = watermark_overlap(conn)
        return wm

    def start(self, cursor: str | None) -> str | None:
        self.since = cursor[6:] if cursor and cursor.startswith("since:") else None
        self.best = parse_ts(self.since) if self.since else None
        if self.best is None:
            return None
        return (self.best - self.overlap).astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

    def see(self, records: list[dict[str, Any]], field: str) -> None:
        limit = utcnow() + FUTURE_TOLERANCE
        for r in records:
            v = r
            for part in field.split("."):
                v = v.get(part) if isinstance(v, dict) else None
            t = parse_ts(v)
            if t is not None and t <= limit and (self.best is None or t > self.best):
                self.best = t

    def finish(self) -> str | None:
        # whole seconds, rounded down: asking ">= mark" re-reads the newest record (ingest is idempotent), never skips
        return f"since:{self.best.astimezone(UTC).strftime('%Y-%m-%dT%H:%M:%SZ')}" if self.best else None


class ToolConnector(BaseConnector):
    """A connector bound to a transport plus its settings."""

    def __init__(self, settings: dict[str, Any], transport: Transport, *, rate_per_sec: float = 5.0,
                 burst: int = 10) -> None:
        super().__init__(rate_per_sec=rate_per_sec, burst=burst)
        self.settings = settings
        self.http = transport

    def req(self, method: str, path: str, **kw: Any) -> Response:
        return self.call(lambda: self.http.request(method, path, **kw))

    def get(self, path: str, **kw: Any) -> Any:
        return self.req("GET", path, **kw).body

    def post(self, path: str, **kw: Any) -> Any:
        return self.req("POST", path, **kw).body

    def timed_lookup(self, fn: Callable[[], LookupResult]) -> LookupResult:
        t0 = time.perf_counter()
        try:
            res = fn()
        except Exception as exc:
            res = LookupResult(self.tool, self.dimension, False, error=f"{type(exc).__name__}: {exc}")
        res.elapsed_ms = round((time.perf_counter() - t0) * 1000, 1)
        return res

    health_stream: str | None = None  # stream probed by health(); default: the first pull stream

    def health(self) -> dict[str, Any]:
        """Live connectivity + permission check: authenticate and read one page of a stream."""
        stream = self.health_stream or (self.streams[0] if self.streams else None)
        out: dict[str, Any] = {"transport": type(self.http).__name__, "stream": stream}
        if stream is None:
            return out | {"ok": True, "detail": "no pull streams (push or lookup-only)"}
        t0 = time.perf_counter()
        try:
            page = self.fetch_page(stream, None)
            return out | {"ok": True, "latency_ms": round((time.perf_counter() - t0) * 1000, 1),
                          "sample_records": len(page.records), "more": page.more}
        except Exception as exc:
            res = out | {"ok": False, "latency_ms": round((time.perf_counter() - t0) * 1000, 1),
                         "error": f"{type(exc).__name__}: {_redact(str(exc))[:300]}"}
            if isinstance(exc, PermissionDenied):     # say what to grant, not just that it failed
                res |= {"missing_permission": True, "required_scopes": list(self.read_scopes)}
            elif isinstance(exc, AuthExpired):
                res |= {"auth_failed": True}
            return res


class ConnectorAction(ActionSpec):
    """ActionSpec implemented by a callable on a connector (keeps action code next to its API)."""

    def __init__(self, action_type: str, connector: ToolConnector, fn: Callable[[dict, list], dict], *,
                 description: str = "", destructive: bool = False, reverse_type: str | None = None,
                 reverse: Callable[[dict, list, dict], tuple[dict, list] | None] | None = None,
                 preconditions: Callable[[dict, list], list[str]] | None = None) -> None:
        self.action_type = action_type
        self.tool = connector.tool
        self.description = description
        self.destructive = destructive
        self.reverse_type = reverse_type
        self._fn = fn
        self._reverse = reverse
        self._pre = preconditions

    def preconditions(self, params, targets):
        return self._pre(params, targets) if self._pre else []

    def execute(self, params, targets):
        return self._fn(params, targets)

    def reverse(self, params, targets, result):
        if self._reverse:
            return self._reverse(params, targets, result)
        return (params, targets) if self.reverse_type else None


def targets_of(targets: list[dict[str, Any]], ttype: str, field: str = "id") -> list[str]:
    """Vendor-specific identifiers of targets of one type. No fallback to the generic ``id`` for vendor keys,
    so a connector never acts on a target it cannot identify (drives RoutedAction provider choice)."""
    return [str(t[field]) for t in targets if t.get("type") == ttype and t.get(field)]


def ok_lookup(conn: BaseConnector, records: list[NormalizedRecord], summary: str,
              deep_link: str | None = None, **signals: Any) -> LookupResult:
    return LookupResult(conn.tool, conn.dimension, True, records=records, summary=summary, deep_link=deep_link,
                        signals=signals)


def _redact(msg: str) -> str:
    """Strip query-string values and bearer tokens from error text before it is shown or stored."""
    msg = re.sub(r"([?&][A-Za-z0-9_.-]+=)[^&\s'\"]+", r"\1***", msg)
    return re.sub(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+", r"\1***", msg)
