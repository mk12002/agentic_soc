"""Helpers shared by tool connectors."""

from __future__ import annotations

import re
import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from soc_platform.connectors.base import BaseConnector, LookupResult
from soc_platform.connectors.http import Response, Transport
from soc_platform.core.actions import ActionSpec
from soc_platform.core.schema import NormalizedRecord


def parse_ts(v: Any) -> datetime | None:
    if v in (None, ""):
        return None
    if isinstance(v, (int, float)):
        return datetime.fromtimestamp(v / 1000 if v > 1e11 else v, tz=UTC)
    s = str(v).strip().replace("Z", "+00:00")
    if "." in s:  # trim >6 fractional digits (Graph returns 7)
        head, _, rest = s.partition(".")
        frac = "".join(c for c in rest if c.isdigit())
        tz = rest[len(frac):]
        s = f"{head}.{frac[:6]}{tz}"
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
            return out | {"ok": False, "latency_ms": round((time.perf_counter() - t0) * 1000, 1),
                          "error": f"{type(exc).__name__}: {_redact(str(exc))[:300]}"}


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
