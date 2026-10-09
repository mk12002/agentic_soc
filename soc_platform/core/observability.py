"""Diagnostics: one trace id per request or job, carried into every record it causes, and structured logs.

**Trace ids.** Every API request gets one (``X-Request-ID`` from a trusted caller if it is well-formed, else a new
one, echoed in the response). Every scheduled or replayed job run gets one (``job-<name>-...``). It is stored on the
access-log row, on every audit event, every model call and the job run it belongs to, and printed on every log line,
so one id answers "what did this request / this job do": ``GET /api/v1/admin/trace/{id}`` puts the whole story
together (request, audit events, model calls with prompts and guardrail removals, job run).

**Structured logs** (``configure_logging``; the server, scheduler and CLI call it): one line per event - JSON in
production (``SOC_LOG_FORMAT=json``, the default when ``SOC_ENVIRONMENT=prod``), readable text otherwise - to stdout
for the container platform / SIEM, and optionally to a rotating file (``SOC_LOG_FILE``). Every request, audit event,
model call, outbound call to a tool and job run is logged with its trace id. Values under keys that look like
secrets (token, secret, password, key, authorization, cookie) are masked and long values are cut, so a log line can be
shipped anywhere.

The database records stay the source of truth (the audit log is hash-chained); the log lines are for operations,
alerting and forwarding.
"""

from __future__ import annotations

import json
import logging
import os
import re
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import UTC, datetime
from typing import Any

TRACE: ContextVar[str | None] = ContextVar("soc_trace", default=None)
_TRACE_ID = re.compile(r"^[A-Za-z0-9._:-]{8,64}$")
_SENSITIVE = re.compile(r"(token|secret|password|passwd|api[_-]?key|authorization|cookie|credential|private)", re.IGNORECASE)
MAX_VALUE = 500
EVENTS = logging.getLogger("soc.events")
_CONFIGURED = "_soc_configured"


def new_trace(prefix: str = "req") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:20]}"


def accept_trace(header: str | None, prefix: str = "req") -> str:
    """A caller's request id when it is safe to reuse (no spaces, quotes or control characters), else a new one."""
    return header if header and _TRACE_ID.match(header) else new_trace(prefix)


def current_trace() -> str | None:
    return TRACE.get()


@contextmanager
def traced(trace_id: str) -> Iterator[str]:
    token = TRACE.set(trace_id)
    try:
        yield trace_id
    finally:
        TRACE.reset(token)


def scrub(value: Any, key: str = "", depth: int = 0) -> Any:
    """A copy safe to log: secrets masked by key name, long strings cut, deep or wide structures bounded."""
    if key and _SENSITIVE.search(key) and not key.endswith(("_tokens", "tokens")):
        return "***"
    if depth > 4:
        return "..."
    if isinstance(value, dict):
        return {str(k): scrub(v, str(k), depth + 1) for k, v in list(value.items())[:50]}
    if isinstance(value, (list, tuple, set)):
        return [scrub(v, key, depth + 1) for v in list(value)[:50]]
    if isinstance(value, str):
        return value if len(value) <= MAX_VALUE else value[:MAX_VALUE] + f"...[{len(value)} chars]"
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return scrub(str(value), key, depth)


def event(name: str, level: int = logging.INFO, **fields: Any) -> None:
    """One structured log line: ``name`` plus fields (scrubbed), with the current trace id."""
    if EVENTS.isEnabledFor(level):
        # stamped here, not only by the platform's handler, so any handler (a host's own, a test's) sees the trace
        EVENTS.log(level, name, extra={"soc_fields": scrub(fields), "trace_id": current_trace()})


class _TraceFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.trace_id = getattr(record, "trace_id", None) or current_trace()
        return True


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        out: dict[str, Any] = {"ts": datetime.fromtimestamp(record.created, UTC).isoformat(timespec="milliseconds"),
                               "level": record.levelname, "logger": record.name, "msg": record.getMessage()}
        if getattr(record, "trace_id", None):
            out["trace_id"] = record.trace_id
        out.update(getattr(record, "soc_fields", None) or {})
        if record.exc_info:
            out["exc"] = self.formatException(record.exc_info)[-4000:]
        return json.dumps(out, default=str, ensure_ascii=False)


class TextFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        ts = datetime.fromtimestamp(record.created, UTC).strftime("%Y-%m-%d %H:%M:%S")
        fields = getattr(record, "soc_fields", None) or {}
        kv = " ".join(f"{k}={json.dumps(v, default=str, ensure_ascii=False) if not isinstance(v, str) else v}"
                      for k, v in fields.items())
        trace = f" [{record.trace_id}]" if getattr(record, "trace_id", None) else ""
        line = f"{ts} {record.levelname:<7} {record.name}{trace} {record.getMessage()}" + (f" {kv}" if kv else "")
        if record.exc_info:
            line += "\n" + self.formatException(record.exc_info)
        return line


def configure_logging(*, force: bool = False) -> bool:
    """Set up the platform's logging once per process (idempotent). ``SOC_LOG_CONFIGURE=0`` leaves logging alone
    (tests, or a host that configures Python logging itself)."""
    root = logging.getLogger()
    if os.environ.get("SOC_LOG_CONFIGURE", "1").strip().lower() in {"0", "false", "no", "off"}:
        return False
    if getattr(root, _CONFIGURED, False) and not force:
        return False
    for h in [h for h in root.handlers if getattr(h, _CONFIGURED, False)]:
        root.removeHandler(h)
    level = getattr(logging, os.environ.get("SOC_LOG_LEVEL", "INFO").upper(), logging.INFO)
    prod = os.environ.get("SOC_ENVIRONMENT", "dev") == "prod"
    fmt_name = (os.environ.get("SOC_LOG_FORMAT") or ("json" if prod else "text")).lower()
    formatter: logging.Formatter = JsonFormatter() if fmt_name == "json" else TextFormatter()
    handlers: list[logging.Handler] = [logging.StreamHandler()]
    path = os.environ.get("SOC_LOG_FILE", "").strip()
    if path:
        from logging.handlers import RotatingFileHandler

        os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
        handlers.append(RotatingFileHandler(
            path, maxBytes=int(float(os.environ.get("SOC_LOG_FILE_MAX_MB", "50")) * 1024 * 1024),
            backupCount=int(os.environ.get("SOC_LOG_FILE_BACKUPS", "10")), encoding="utf-8"))
    for h in handlers:
        h.setFormatter(formatter)
        h.addFilter(_TraceFilter())
        setattr(h, _CONFIGURED, True)
        root.addHandler(h)
    root.setLevel(level)
    for noisy in ("httpx", "httpcore", "urllib3", "asyncio", "multipart"):   # the platform logs its own outbound calls
        logging.getLogger(noisy).setLevel(max(level, logging.WARNING))
    setattr(root, _CONFIGURED, True)
    return True
