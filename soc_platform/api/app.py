"""Platform API: one service for phishing, incident and vulnerability workflows.

Run:  uvicorn soc_platform.api.app:app --host 0.0.0.0 --port 8080
Auth: Bearer token (Entra ID access token in prod; dev HS256 token from /api/v1/dev/token in dev).
Every state change goes through the policy-gated ActionService and lands in the audit log.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, File, Header, HTTPException, Query, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from sqlalchemy.exc import DataError, OperationalError, SQLAlchemyError
from sqlalchemy.exc import TimeoutError as SQLATimeoutError
from sqlalchemy.orm import Session
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from soc_platform import __version__
from soc_platform.config import Settings, get_settings
from soc_platform.connectors.base import SyncRunner
from soc_platform.connectors.registry import ConfigError, ConnectorRegistry
from soc_platform.core.access import AccessService, kill_switch_on, permissions_matrix
from soc_platform.core.actions import ActionService
from soc_platform.core.audit import AuditLog
from soc_platform.core.auth import AuthError, Perm, Principal, issue_dev_token, principal_from_token
from soc_platform.core.cases import CaseService, agreement_report, detection_quality
from soc_platform.core.connector_config import ConfigRejected, ConfigStore, version_dict
from soc_platform.core.context_store import ContextStore
from soc_platform.core.db import get_database
from soc_platform.core.entity_resolution import EntityResolver
from soc_platform.core.models import AccessLogRecord, ActionRequest, Case, Entity, PolicyVersion, UnresolvedItem
from soc_platform.core.policy import PolicyEngine, PolicyStore
from soc_platform.llm.gateway import LLMGateway

STATIC = Path(__file__).parent / "static"
_PROD = get_settings().environment == "prod"
@asynccontextmanager
async def _lifespan(_app: FastAPI):
    """The server runs the job scheduler itself (SOC_EMBEDDED_SCHEDULER=1, the default), so one process is the whole
    platform. Deployments with a dedicated scheduler service set SOC_EMBEDDED_SCHEDULER=0; running both is also safe."""
    from soc_platform import scheduler as sched
    from soc_platform.domains.phishing.agents.analyzer import engine_enabled, warm_up_engine

    threads = int(__import__("os").environ.get("SOC_API_THREADS", "40") or 40)
    __import__("anyio").to_thread.current_default_thread_limiter().total_tokens = max(4, threads)  # request threads
    if engine_enabled():   # load the trained models in the background; the server answers meanwhile
        __import__("threading").Thread(target=warm_up_engine, name="soc-engine-warmup", daemon=True).start()
    sch = None
    if sched.enabled_embedded():
        sch = sched.Scheduler(mode="embedded")
        sch.start(start_delay=float(__import__("os").environ.get("SOC_SCHEDULER_START_DELAY", "5")))
    try:
        yield
    finally:
        if sch is not None:
            sch.shutdown()


app = FastAPI(title="Agentic SOC Platform", version=__version__, lifespan=_lifespan,
              docs_url=None if _PROD else "/docs", redoc_url=None, openapi_url=None if _PROD else "/openapi.json")
app.mount("/static", StaticFiles(directory=STATIC), name="static")

MAX_BODY_BYTES = 30 * 1024 * 1024
SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
                               "img-src 'self' data:; connect-src 'self' https://login.microsoftonline.com; "
                               "frame-ancestors 'none'; base-uri 'none'; "
                               "form-action 'self'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cache-Control": "no-store",
}


class _RateLimiter:
    """Per-client token bucket (in-process; put a gateway/WAF limit in front for multi-replica deployments)."""

    def __init__(self, rate: float = 20.0, burst: int = 120) -> None:
        import threading
        import time as _t

        self.rate, self.burst, self._t, self._lock, self._b = rate, burst, _t, threading.Lock(), {}

    def allow(self, key: str) -> bool:
        with self._lock:
            now = self._t.monotonic()
            tokens, last = self._b.get(key, (float(self.burst), now))
            tokens = min(self.burst, tokens + (now - last) * self.rate)
            ok = tokens >= 1
            self._b[key] = (tokens - 1 if ok else tokens, now)
            if len(self._b) > 50_000:
                # drop only buckets idle long enough to be full again: clearing everything let a flood of new
                # addresses reset the budget of a client that was being limited
                idle = self.burst / max(self.rate, 1e-9)
                self._b = {k: v for k, v in self._b.items() if now - v[1] < idle}
                if len(self._b) > 50_000:
                    self._b.clear()
                    self._b[key] = (tokens - 1 if ok else tokens, now)
            return ok


_limiter = _RateLimiter(float(__import__("os").environ.get("SOC_RATE_LIMIT_RPS", "20")),
                        int(__import__("os").environ.get("SOC_RATE_LIMIT_BURST", "120")))


_TRUSTED_PROXIES = {x.strip() for x in __import__("os").environ.get("SOC_TRUSTED_PROXIES", "").split(",") if x.strip()}


def _client_ip(request: Request) -> str:
    """Peer address; X-Forwarded-For is honoured only when the direct peer is a configured trusted proxy, and then
    the right-most hop that is not itself a trusted proxy is the client. Proxies *append* to the header, so its
    left-most entry is whatever the caller sent: trusting it let anyone pick their address (a fresh rate-limit
    bucket per request, or "127.0.0.1" to reach the loopback-only dev sign-in)."""
    peer = request.client.host if request.client else "unknown"
    if peer not in _TRUSTED_PROXIES:
        return peer
    hops = [h.strip() for h in ",".join(request.headers.getlist("x-forwarded-for")).split(",") if h.strip()]
    for hop in reversed(hops):
        if hop not in _TRUSTED_PROXIES:
            return hop[:64]
    return peer


def _is_https(request: Request) -> bool:
    """TLS usually ends at the reverse proxy: believe its X-Forwarded-Proto, but only from a trusted proxy."""
    if request.url.scheme == "https":
        return True
    peer = request.client.host if request.client else ""
    return peer in _TRUSTED_PROXIES and (request.headers.get("x-forwarded-proto") or "").split(",")[-1].strip() == "https"


class SecurityMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # NUL is never valid in an id, name or filter, and PostgreSQL rejects it in text: refuse it at the edge
        if "\x00" in request.url.path or b"%00" in request.scope.get("query_string", b"").lower():
            return JSONResponse({"detail": "invalid character in request"}, status_code=400)
        cl = request.headers.get("content-length")
        if cl and cl.isdigit() and int(cl) > MAX_BODY_BYTES:
            return JSONResponse({"detail": "request too large"}, status_code=413)
        client = _client_ip(request)
        if not _limiter.allow(client):
            return JSONResponse({"detail": "rate limit exceeded"}, status_code=429, headers={"Retry-After": "5"})
        t0 = __import__("time").perf_counter()
        response = await call_next(request)
        if request.url.path.startswith("/api/") or request.url.path == "/metrics":
            _log_access(request, response.status_code, (__import__("time").perf_counter() - t0) * 1000)
        for k, v in SECURITY_HEADERS.items():
            response.headers.setdefault(k, v)
        if _is_https(request):
            response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        return response


app.add_middleware(SecurityMiddleware)


@app.exception_handler(SQLATimeoutError)
async def _pool_exhausted(_request: Request, _exc: Exception) -> JSONResponse:
    """Every database connection is busy: tell the client to retry shortly instead of holding the request."""
    return JSONResponse({"detail": "the platform is busy - retry in a moment"}, status_code=503,
                        headers={"Retry-After": "2"})


@app.exception_handler(OperationalError)
async def _database_busy(_request: Request, exc: Exception) -> JSONResponse:
    """SQLite still locked after its busy timeout, or the database briefly unreachable: a retryable 503, not a 500."""
    import logging

    logging.getLogger(__name__).warning("database unavailable: %s", str(exc).splitlines()[0][:200])
    return JSONResponse({"detail": "the database is busy or unreachable - retry in a moment"}, status_code=503,
                        headers={"Retry-After": "5"})


@app.exception_handler(DataError)
async def _data_error(_request: Request, _exc: Exception) -> JSONResponse:
    """A value the database cannot store (too long, out of range, invalid text) is the caller's error, not a crash."""
    return JSONResponse({"detail": "a value in the request is invalid or too long"}, status_code=400)


class BodyLimitMiddleware:
    """Enforces MAX_BODY_BYTES on the actual byte stream (covers chunked uploads with no Content-Length)."""

    def __init__(self, app_, limit: int) -> None:
        self.app, self.limit = app_, limit

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            return await self.app(scope, receive, send)
        seen, too_big = 0, False

        async def limited():
            nonlocal seen, too_big
            msg = await receive()
            if msg.get("type") == "http.request":
                seen += len(msg.get("body") or b"")
                if seen > self.limit:
                    too_big = True
                    raise HTTPException(413, "request too large")
            return msg

        done = False

        async def send_(msg):
            nonlocal done
            if done:
                return
            if too_big and msg.get("type") == "http.response.start":  # parsers may wrap the error as 400
                msg = {**msg, "status": 413, "headers": [(b"content-type", b"application/json")]}
            elif too_big and msg.get("type") == "http.response.body":
                msg, done = {"type": "http.response.body", "body": b'{"detail":"request too large"}', "more_body": False}, True
            await send(msg)

        return await self.app(scope, limited, send_)


app.add_middleware(BodyLimitMiddleware, limit=MAX_BODY_BYTES)


class _AccessLogWriter:
    """Append-only access log without slowing requests: rows are queued and written in batches by one
    background thread (retrying while the request's own transaction still holds the database)."""

    def __init__(self) -> None:
        import queue
        import threading

        self.q: queue.Queue[tuple[Any, dict[str, Any]]] = queue.Queue(maxsize=100_000)
        self.dropped = 0
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None

    def put(self, row: dict[str, Any]) -> None:
        import queue
        import threading

        try:
            # bound to the database of the request that produced it, not whichever is current at flush time
            self.q.put_nowait((get_database(), row))
        except queue.Full:
            self.dropped += 1
            return
        with self._lock:
            if self._thread is None or not self._thread.is_alive():
                self._thread = threading.Thread(target=self._run, name="access-log", daemon=True)
                self._thread.start()

    def _run(self) -> None:
        import queue
        import time as _t

        while True:
            try:
                batch = [self.q.get(timeout=30)]
            except queue.Empty:
                return
            while len(batch) < 500:
                try:
                    batch.append(self.q.get_nowait())
                except queue.Empty:
                    break
            by_db: dict[int, tuple[Any, list[dict[str, Any]]]] = {}
            for db, row in batch:
                by_db.setdefault(id(db), (db, []))[1].append(row)
            for db, rows in by_db.values():
                for attempt in range(20):
                    try:
                        with db.session() as s:
                            s.add_all([AccessLogRecord(**r) for r in rows])
                        break
                    except Exception:  # noqa: BLE001 - database busy/unavailable: back off, never crash
                        _t.sleep(min(2.0, 0.1 * (attempt + 1)))
                else:
                    self.dropped += len(rows)
                    import logging

                    logging.getLogger(__name__).warning("access log: %d row(s) could not be written", len(rows))

    def flush(self, timeout: float = 10.0) -> None:
        import time as _t

        end = _t.monotonic() + timeout
        while not self.q.empty() and _t.monotonic() < end:
            _t.sleep(0.05)
        _t.sleep(0.1)


ACCESS_LOG = _AccessLogWriter()


def _log_access(request: Request, status: int, latency_ms: float) -> None:
    from soc_platform.core.models import utcnow

    ACCESS_LOG.put({"ts": utcnow(),
                    "principal_id": getattr(request.state, "principal_id", None),
                    "auth_method": getattr(request.state, "auth_method", None),
                    "method": request.method[:8], "path": request.url.path[:512], "status": int(status),
                    "client_ip": _client_ip(request),
                    "user_agent": (request.headers.get("user-agent") or "")[:256], "latency_ms": round(latency_ms, 1)})


# ----------------------------------------------------------------------------- dependencies


class _Registry:
    """The connector registry in force: ``config/connectors.yaml`` plus the approved console version
    (``core/connector_config.py``). The active version is re-read at most every SOC_CONFIG_RELOAD_SECONDS (5), so
    every API process and the scheduler pick an approved change up within seconds, without a restart; the process
    that approves it rebuilds at once (``cache_clear``)."""

    def __init__(self) -> None:
        import threading

        self._lock = threading.Lock()
        self.cache_clear()

    def cache_clear(self) -> None:
        self._reg: ConnectorRegistry | None = None
        self._db: Any = None
        self._version: int | None = None
        self._checked: float | None = None          # None = never checked (monotonic time can be small after boot)

    @staticmethod
    def _active_version(db: Any) -> int | None:
        from soc_platform.core.models import ConnectorConfigVersion

        try:
            with db.session() as s:
                return s.execute(select(func.max(ConnectorConfigVersion.id))
                                 .where(ConnectorConfigVersion.status == "active")).scalar()
        except SQLAlchemyError:
            return None          # no table yet (init-db not run) or the database is busy: the file alone applies

    @staticmethod
    def _build(db: Any) -> ConnectorRegistry:
        try:
            with db.session() as s:
                return ConfigStore(s).registry()
        except SQLAlchemyError:
            import logging

            logging.getLogger(__name__).warning("console configuration unreadable; using the file", exc_info=True)
            return ConnectorRegistry.from_file()

    def __call__(self) -> ConnectorRegistry:
        import os
        import time

        db, now = get_database(), time.monotonic()
        every = float(os.environ.get("SOC_CONFIG_RELOAD_SECONDS", "5") or 5)
        with self._lock:
            if (self._reg is not None and self._db is db and self._checked is not None
                    and now - self._checked < every):
                return self._reg
            version = self._active_version(db)
            self._checked = now
            if self._reg is None or self._db is not db or version != self._version:
                self._reg, self._db, self._version = self._build(db), db, version
            return self._reg


registry = _Registry()


def db_session() -> Iterator[Session]:
    """One session per request, committed when the handler returns. Always used with ``scope="function"`` so the
    commit happens *before* the response is sent: with FastAPI's default ("request") the commit ran after the reply,
    so a client could read back stale data - an upload's case was missing from the next list in 28 of 40 tries - or
    be told a write succeeded that then failed to commit."""
    with get_database().session() as s:
        yield s


def current_user(request: Request, authorization: str | None = Header(default=None),
                 x_api_key: str | None = Header(default=None), x_break_glass: str | None = Header(default=None),
                 settings: Settings = Depends(get_settings), s: Session = Depends(db_session, scope="function")) -> Principal:
    """Bearer token (Entra / dev), service-account API key, or sealed break-glass credential."""
    acc = AccessService(s, settings)
    client = _client_ip(request)
    try:
        if x_break_glass:
            p = acc.break_glass(x_break_glass, client=client, path=request.url.path)
        elif x_api_key:
            p = acc.authenticate_api_key(x_api_key.strip())
        elif authorization and authorization.lower().startswith("bearer "):
            p = acc.effective(principal_from_token(authorization.split(" ", 1)[1].strip(), settings))
        else:
            raise HTTPException(401, "authentication required (Bearer token or X-API-Key)")
    except (AuthError, PermissionError) as exc:
        s.commit()  # keep the audit trail of failed break-glass attempts
        raise HTTPException(401, str(exc)) from exc
    request.state.principal_id, request.state.auth_method = p.id, p.auth_method
    return p


def need(perm: Perm, domain: str | None = None):
    """Route guard. With a domain, the principal is handed on *as it acts in that domain* (only roles whose own
    scope covers it), so the services' own permission checks are domain-correct too."""
    def dep(p: Principal = Depends(current_user)) -> Principal:
        if not p.can(perm):
            raise HTTPException(403, p.why_not(perm))
        if not p.in_domain(domain):
            raise HTTPException(403, "cross-domain data requires all-domain access" if domain == "*"
                                else f"not authorised for {domain} data")
        acting = p.acting_in(domain)
        if not acting.can(perm):
            raise HTTPException(403, f"{perm.value} is not granted for {'all-domain' if domain == '*' else domain} data")
        return acting
    return dep


def _case_in_scope(s: Session, p: Principal, cid: str | None) -> Case | None:
    """Out-of-scope cases are reported as missing (no existence oracle)."""
    if cid is None:
        return None
    case = s.get(Case, cid)
    if case is None or not p.in_domain(case.domain):
        raise HTTPException(404, "unknown case")
    return case


def policy_engine(s: Session) -> PolicyEngine:
    return PolicyEngine(PolicyStore(s).active(), kill_switch=kill_switch_on(s, get_settings()))


def _iso(value: datetime | None) -> str | None:
    """ISO 8601 with an explicit UTC offset (models return aware UTC datetimes)."""
    return value.isoformat() if value else None


def llm(s: Session, p: Principal | None = None) -> LLMGateway | None:
    """The gateway for this request. ``p``: the person asking (analyst questions, deep analysis, reports) - their
    AI usage limits apply; omitted for scheduled and shared work (platform budgets only)."""
    st = get_settings()
    return LLMGateway(s, st, actor=p) if st.llm_provider != "none" else None


def _with_notice(out: Any, gw: LLMGateway | None) -> Any:
    """Tell the person when their answer was written without the model because of an AI usage limit."""
    if gw is not None and gw.notice and isinstance(out, dict):
        return {**out, "llm_notice": f"Written by the platform without the model: {gw.notice}."}
    return out


def _services(s: Session):
    from soc_platform.domains.incident.service import IncidentService
    from soc_platform.domains.phishing.agents.analyzer import engine_enabled
    from soc_platform.domains.phishing.service import PhishingService
    from soc_platform.domains.vulnerability.service import VulnerabilityService

    reg, pol, gw = registry(), policy_engine(s), llm(s)
    acts = reg.action_registry()
    st = get_settings()
    org = [d.strip() for d in (__import__("os").environ.get("SOC_ORG_DOMAINS", "")).split(",") if d.strip()]
    return {"incident": IncidentService(s, reg, policy=pol, llm=gw, actions=acts),
            "vulnerability": VulnerabilityService(s, reg, policy=pol, llm=gw, actions=acts),
            "phishing": PhishingService(s, reg, policy=pol, llm=gw, actions=acts, org_domains=org,
                                        use_engine=engine_enabled(),
                                        raw_dir=Path(st.raw_payload_dir) / "phishing")}


def _protected_file(path: str):
    """Serve a generated file, decrypting it if it is encrypted at rest."""
    import mimetypes

    from fastapi.responses import Response as RawResponse

    from soc_platform.core.crypto import read_protected

    name = Path(path).name
    return RawResponse(read_protected(path), media_type=mimetypes.guess_type(name)[0] or "application/octet-stream",
                       headers={"Content-Disposition": f'attachment; filename="{name}"'})


def _err(exc: Exception) -> HTTPException:
    if isinstance(exc, PermissionError):
        return HTTPException(403, str(exc))
    if isinstance(exc, KeyError):
        return HTTPException(404, str(exc))
    if isinstance(exc, (AttributeError, TypeError, NameError, IndexError, AssertionError)):
        # a bug, not a bad request: log it, and never echo interpreter internals to the caller
        import logging

        logging.getLogger(__name__).exception("request failed")
        return HTTPException(400, "the request could not be completed")
    return HTTPException(400, str(exc))


# ----------------------------------------------------------------------------- system


_CHAIN_CACHE: dict[str, Any] = {"at": None, "ok": None}   # "at" None = never verified (monotonic time can be < 300 s after boot)


@app.get("/health")
def health(s: Session = Depends(db_session, scope="function")) -> dict[str, Any]:
    now = __import__("time").monotonic()
    if _CHAIN_CACHE["at"] is None or now - _CHAIN_CACHE["at"] > 300:  # at most every 5 min; /api/v1/audit/verify on demand
        _CHAIN_CACHE.update(at=now, ok=AuditLog(s).verify()["ok"])
    return {"status": "ok", "version": __version__, "audit_chain": _CHAIN_CACHE["ok"],
            "connectors_enabled": len(registry().enabled_names()), "kill_switch": kill_switch_on(s, get_settings()),
            "scheduler": _scheduler_heartbeat(s)}


def _scheduler_heartbeat(s: Session) -> dict[str, Any]:
    """If the scheduler stops, no job runs, so nothing can fail or alert: report its heartbeat here instead."""
    from soc_platform import scheduler as sched

    return sched.status(s)


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def ui() -> HTMLResponse:
    return HTMLResponse((STATIC / "index.html").read_text(encoding="utf-8"))


@app.get("/api/v1/auth/config")
def auth_config() -> dict[str, str]:
    """What the console needs to start single sign-on (public values only: tenant, client id, scope)."""
    import os

    st = get_settings()
    if st.auth_mode != "entra":
        return {"mode": st.auth_mode}
    audience = st.entra_audience or ""
    # one app registration can be both the API (audience api://<app-id>) and the console's SPA client
    client = os.environ.get("SOC_ENTRA_SPA_CLIENT_ID") or audience.removeprefix("api://")
    return {"mode": "entra", "tenant_id": st.entra_tenant_id or "", "client_id": client,
            "scope": os.environ.get("SOC_ENTRA_SCOPE") or f"{audience}/.default"}


@app.get("/api/v1/dev/token")
def dev_token(request: Request, user: str = "analyst@acme-demo.com", roles: str = "analyst", mfa: bool = True,
              domains: str = "") -> dict[str, str]:
    st = get_settings()
    if st.auth_mode != "dev" or st.environment == "prod" or not st.dev_jwt_secret:
        raise HTTPException(404, "not available")
    remote_ok = __import__("os").environ.get("SOC_DEV_TOKENS_REMOTE", "0") == "1"
    if not remote_ok and _client_ip(request) not in {"127.0.0.1", "::1", "testclient", "localhost"}:
        raise HTTPException(404, "not available")  # dev sign-in never served to other machines by default
    return {"token": issue_dev_token(st.dev_jwt_secret, user, [r.strip() for r in roles.split(",")], mfa=mfa,
                                     domains=[d.strip() for d in domains.split(",") if d.strip()] or None)}


@app.get("/api/v1/me")
def me(p: Principal = Depends(current_user)) -> dict[str, Any]:
    return {"id": p.id, "name": p.name, "roles": sorted(r.value for r in p.roles),
            "permissions": sorted(x.value for x in Perm if p.can(x)), "domains": sorted(p.domains),
            "role_scopes": p.role_scopes(), "mfa": p.mfa, "auth_method": p.auth_method,
            "service_account": p.is_service, "break_glass": p.break_glass}


# ----------------------------------------------------------------------------- connectors


@app.get("/api/v1/connectors")
def connectors(_: Principal = Depends(need(Perm.READ))) -> list[dict[str, Any]]:
    return registry().status()


@app.post("/api/v1/connectors/{name}/sync")
def connector_sync(name: str, stream: str, full: bool = False, p: Principal = Depends(need(Perm.MANAGE_CONNECTORS)),
                   s: Session = Depends(db_session, scope="function")) -> dict[str, Any]:
    reg = registry()
    if name not in reg.manifests:
        raise HTTPException(404, "unknown connector")
    if name not in reg.enabled_names():
        raise HTTPException(409, "; ".join(reg.problems_of(name)) or f"{name} is switched off")
    try:
        conn = reg.get(name)
    except ConfigError as exc:
        raise HTTPException(409, str(exc)) from exc
    if stream not in conn.streams:
        raise HTTPException(400, f"unknown stream; available: {list(conn.streams)}")
    rep = SyncRunner(s, ContextStore(s)).sync(conn, stream, full_backfill=full)
    AuditLog(s).append(actor_type="human", actor_id=p.id, event_type="connector.sync", subject_type="connector",
                       subject_id=name, payload={"stream": stream, "ingested": rep.ingested, "failed": rep.failed})
    return rep.__dict__ | {"reconciled": rep.reconciled}


@app.post("/api/v1/connectors/{name}/test")
def connector_test(name: str, p: Principal = Depends(need(Perm.MANAGE_CONNECTORS)),
                   s: Session = Depends(db_session, scope="function")) -> dict[str, Any]:
    """Authenticate against the tool and read one page (NFR-13): proves credentials, scopes and reachability.
    The full check is the preflight (POST /api/v1/config/connectors/{name}/preflight)."""
    try:
        conn = registry().get(name)
    except KeyError:
        raise HTTPException(404, "unknown connector") from None
    except ConfigError as exc:
        return {"connector": name, "ok": False, "error": str(exc)}
    res = conn.health()
    AuditLog(s).append(actor_type="human", actor_id=p.id, event_type="connector.test", subject_type="connector",
                       subject_id=name, payload={"ok": res.get("ok"), "error": res.get("error")})
    return {"connector": name} | res


# ----------------------------------------------------------------------------- connector configuration (console)


def _config_err(exc: Exception) -> HTTPException:
    if isinstance(exc, ConfigRejected):
        return HTTPException(422, exc.detail())          # problems and preflight, so the screen can show what to fix
    return _err(exc)


class ConfigChangeBody(BaseModel):
    changes: dict[str, Any] = Field(default_factory=dict)
    lists: dict[str, Any] | None = None          # suppliers / sanctioned (a list replaces the file's; null restores it)
    note: str = Field(default="", max_length=2000)


class ReasonBody(BaseModel):
    reason: str = Field(default="", max_length=2000)


class ImportBody(BaseModel):
    yaml: str = Field(min_length=1, max_length=500_000)
    note: str = Field(default="", max_length=2000)


@app.get("/api/v1/config/connectors")
def config_view(_: Principal = Depends(need(Perm.READ_AUDIT)), s: Session = Depends(db_session, scope="function")):
    """Every connector: stage, settings (secrets only as 'set / not set' and the variable they come from), problems,
    last preflight; plus the pending changes awaiting approval."""
    return ConfigStore(s).view()


@app.post("/api/v1/config/connectors/{name}/preflight")
def config_preflight(name: str, p: Principal = Depends(need(Perm.MANAGE_CONNECTORS)),
                     s: Session = Depends(db_session, scope="function")):
    try:
        return ConfigStore(s).preflight(name, p)
    except Exception as exc:
        raise _config_err(exc) from exc


@app.post("/api/v1/config/proposals")
def config_propose(body: ConfigChangeBody, p: Principal = Depends(need(Perm.MANAGE_CONNECTORS)),
                   s: Session = Depends(db_session, scope="function")):
    try:
        return version_dict(ConfigStore(s).propose(body.changes, p, body.note, lists=body.lists))
    except ConfigRejected as exc:
        if exc.preflight:
            s.commit()      # nothing was proposed, but the preflight run and its audit entry are kept as evidence
        raise _config_err(exc) from exc
    except Exception as exc:
        raise _config_err(exc) from exc


@app.post("/api/v1/config/proposals/{vid}/approve")
def config_approve(vid: int, p: Principal = Depends(need(Perm.APPROVE_POLICY)),
                   s: Session = Depends(db_session, scope="function")):
    try:
        v = ConfigStore(s).approve(vid, p)
    except Exception as exc:
        raise _config_err(exc) from exc
    s.commit()
    registry.cache_clear()                  # this process uses it at once; the others within SOC_CONFIG_RELOAD_SECONDS
    return version_dict(v)


@app.post("/api/v1/config/proposals/{vid}/reject")
def config_reject(vid: int, body: ReasonBody, p: Principal = Depends(current_user),
                  s: Session = Depends(db_session, scope="function")):
    try:
        return version_dict(ConfigStore(s).reject(vid, p, body.reason))
    except Exception as exc:
        raise _config_err(exc) from exc


@app.post("/api/v1/config/connectors/{name}/pause")
def config_pause(name: str, body: ReasonBody, p: Principal = Depends(current_user),
                 s: Session = Depends(db_session, scope="function")):
    """Switch one tool off at once (audited; switching it back on is a normal, approved change)."""
    try:
        v = ConfigStore(s).pause(name, p, body.reason)
    except Exception as exc:
        raise _config_err(exc) from exc
    s.commit()
    registry.cache_clear()
    return version_dict(v)


@app.post("/api/v1/config/versions/{vid}/restore")
def config_restore(vid: int, body: ReasonBody, p: Principal = Depends(need(Perm.MANAGE_CONNECTORS)),
                   s: Session = Depends(db_session, scope="function")):
    try:
        return version_dict(ConfigStore(s).restore(vid, p, body.reason))
    except Exception as exc:
        raise _config_err(exc) from exc


@app.get("/api/v1/config/history")
def config_history(limit: int = Query(default=50, ge=1, le=500), _: Principal = Depends(need(Perm.READ_AUDIT)),
                   s: Session = Depends(db_session, scope="function")):
    return [version_dict(v) for v in ConfigStore(s).history(limit)]


@app.get("/api/v1/config/export")
def config_export(_: Principal = Depends(need(Perm.READ_AUDIT)), s: Session = Depends(db_session, scope="function")):
    """The configuration in force as one YAML file (secrets only as ${VAR} references) - for review, staging and
    disaster recovery; re-imported with POST /api/v1/config/import."""
    return PlainTextResponse(ConfigStore(s).export_yaml(), media_type="text/yaml",
                             headers={"Content-Disposition": 'attachment; filename="connectors.yaml"'})


@app.post("/api/v1/config/import")
def config_import(body: ImportBody, p: Principal = Depends(need(Perm.MANAGE_CONNECTORS)),
                  s: Session = Depends(db_session, scope="function")):
    try:
        return version_dict(ConfigStore(s).import_yaml(body.yaml, p, body.note))
    except Exception as exc:
        raise _config_err(exc) from exc


# ----------------------------------------------------------------------------- access management (NFR-09)


class GrantBody(BaseModel):
    principal_id: str = Field(min_length=3, max_length=256)
    role: str
    domains: list[str] = Field(default_factory=lambda: ["*"])
    days: int | None = Field(default=None, ge=1, le=366)
    reason: str = Field(min_length=3, max_length=2000)


class ApiKeyBody(BaseModel):
    name: str = Field(min_length=2, max_length=128)
    roles: list[str]
    domains: list[str] = Field(default_factory=lambda: ["*"])
    days: int = Field(default=90, ge=1, le=365)


class RevokeBody(BaseModel):
    principal_id: str
    reason: str = ""


def _access(s: Session) -> AccessService:
    return AccessService(s, get_settings())


@app.get("/api/v1/admin/permissions")
def admin_permissions(_: Principal = Depends(need(Perm.READ_AUDIT))) -> dict[str, Any]:
    return permissions_matrix()


@app.get("/api/v1/admin/roles")
def admin_roles(all: bool = False, _: Principal = Depends(need(Perm.MANAGE_ACCESS)), s: Session = Depends(db_session, scope="function")):
    return _access(s).list_grants(include_inactive=all)


@app.post("/api/v1/admin/roles")
def admin_grant(body: GrantBody, p: Principal = Depends(need(Perm.MANAGE_ACCESS)), s: Session = Depends(db_session, scope="function")):
    try:
        g = _access(s).grant(p, body.principal_id, body.role, domains=body.domains, days=body.days, reason=body.reason)
    except Exception as exc:
        raise _err(exc) from exc
    return {"id": g.id, "principal_id": g.principal_id, "role": g.role, "domains": g.domains}


@app.delete("/api/v1/admin/roles/{gid}")
def admin_revoke(gid: str, reason: str = "", p: Principal = Depends(need(Perm.MANAGE_ACCESS)),
                 s: Session = Depends(db_session, scope="function")):
    try:
        g = _access(s).revoke_grant(p, gid, reason)
    except Exception as exc:
        raise _err(exc) from exc
    return {"id": g.id, "revoked": True}


@app.get("/api/v1/admin/api-keys")
def admin_keys(_: Principal = Depends(need(Perm.MANAGE_ACCESS)), s: Session = Depends(db_session, scope="function")):
    return _access(s).list_api_keys()


@app.post("/api/v1/admin/api-keys")
def admin_key_create(body: ApiKeyBody, p: Principal = Depends(need(Perm.MANAGE_ACCESS)), s: Session = Depends(db_session, scope="function")):
    try:
        key, secret = _access(s).create_api_key(p, body.name, body.roles, domains=body.domains, days=body.days)
    except Exception as exc:
        raise _err(exc) from exc
    return {"id": key.id, "name": key.name, "roles": key.roles, "domains": key.domains,
            "expires_at": key.expires_at.isoformat(), "api_key": secret,
            "note": "Shown once. Store it in the calling system's vault; send it as the X-API-Key header."}


@app.delete("/api/v1/admin/api-keys/{kid}")
def admin_key_revoke(kid: str, p: Principal = Depends(need(Perm.MANAGE_ACCESS)), s: Session = Depends(db_session, scope="function")):
    try:
        _access(s).revoke_api_key(p, kid)
    except Exception as exc:
        raise _err(exc) from exc
    return {"id": kid, "revoked": True}


@app.post("/api/v1/admin/revoke-sessions")
def admin_revoke_sessions(body: RevokeBody, p: Principal = Depends(need(Perm.MANAGE_ACCESS)),
                          s: Session = Depends(db_session, scope="function")):
    _access(s).revoke_sessions(p, body.principal_id, body.reason)
    return {"principal_id": body.principal_id, "sessions_revoked": True}


@app.post("/api/v1/auth/logout")
def logout(p: Principal = Depends(current_user), s: Session = Depends(db_session, scope="function")) -> dict[str, Any]:
    """Revoke the presented token (its jti) server-side."""
    if p.is_service or p.break_glass or not p.token_id:
        raise HTTPException(400, "only bearer tokens with a jti can be revoked this way")
    _access(s).revoke_token(p, p.token_id)
    return {"revoked": True}


@app.get("/api/v1/admin/access-log")
def admin_access_log(principal_id: str | None = None, status_min: int = 0, limit: int = Query(200, ge=1, le=2000),
                     _: Principal = Depends(need(Perm.READ_AUDIT, "*")), s: Session = Depends(db_session, scope="function")):
    # request paths name cases and entities of every domain: all-domain readers only
    ACCESS_LOG.flush(2.0)
    q = select(AccessLogRecord).order_by(AccessLogRecord.seq.desc()).limit(limit)
    if principal_id:
        q = q.where(AccessLogRecord.principal_id == principal_id)
    if status_min:
        q = q.where(AccessLogRecord.status >= status_min)
    return [{"ts": r.ts.isoformat(), "principal_id": r.principal_id, "auth": r.auth_method, "method": r.method,
             "path": r.path, "status": r.status, "ip": r.client_ip, "latency_ms": r.latency_ms}
            for r in s.execute(q).scalars()]


@app.post("/api/v1/admin/retention/run")
def admin_retention(dry_run: bool = True, p: Principal = Depends(need(Perm.MANAGE_ACCESS)),
                    s: Session = Depends(db_session, scope="function")) -> dict[str, Any]:
    from soc_platform.core.retention import run_retention

    return run_retention(s, get_settings(), actor=p.id, dry_run=dry_run)


@app.get("/api/v1/audit/export")
def audit_export(since_seq: int = 0, p: Principal = Depends(need(Perm.EXPORT_EVIDENCE, "*")), s: Session = Depends(db_session, scope="function")):
    """JSON Lines export of the hash-chained audit log for external archiving / SIEM (NFR-04). The whole chain is
    needed to verify it, so this requires all-domain scope."""
    from fastapi.responses import PlainTextResponse

    from soc_platform.core.retention import export_audit

    AuditLog(s).append(actor_type="human", actor_id=p.id, event_type="audit.export", subject_type="audit",
                       subject_id="audit_log", payload={"since_seq": since_seq})
    body = "".join(export_audit(s, since_seq=since_seq))
    return PlainTextResponse(body, media_type="application/x-ndjson",
                             headers={"Content-Disposition": 'attachment; filename="audit_log.jsonl"'})


class PushedAlerts(BaseModel):
    alerts: list[dict[str, Any]] = Field(max_length=5000)


@app.post("/api/v1/ingest/alerts")
def ingest_alerts(body: PushedAlerts, p: Principal = Depends(need(Perm.INVESTIGATE, "incident")),
                  s: Session = Depends(db_session, scope="function")) -> dict[str, int]:
    """Push endpoint for any SIEM/SOAR (IM-T02 webhook ingestion; duplicates suppressed on replay)."""
    reg = registry()
    if "generic_siem" not in reg.enabled_names():
        raise HTTPException(409, "the generic SIEM connector is switched off or misconfigured: "
                                 + ("; ".join(reg.problems_of("generic_siem")) or "switch it on in Integrations"))
    conn = reg.get("generic_siem")
    store = ContextStore(s)
    n = 0
    for a in body.alerts:
        for rec in conn.normalize("pushed", a):
            store.ingest(rec)
            n += 1
    return {"ingested": n}


# ----------------------------------------------------------------------------- policy & kill switch


@app.get("/api/v1/policy")
def get_policy(_: Principal = Depends(need(Perm.READ)), s: Session = Depends(db_session, scope="function")) -> dict[str, Any]:
    ps = PolicyStore(s)
    return {"active_version": ps.active_version(), "document": ps.active(),
            "proposals": [{"id": v.id, "proposed_by": v.proposed_by, "status": v.status, "note": v.note}
                          for v in s.execute(select(PolicyVersion).where(PolicyVersion.status == "proposed")).scalars()]}


class PolicyProposal(BaseModel):
    document: dict[str, Any]
    note: str = ""


@app.post("/api/v1/policy/proposals")
def propose_policy(body: PolicyProposal, p: Principal = Depends(current_user), s: Session = Depends(db_session, scope="function")):
    try:
        v = PolicyStore(s).propose(body.document, p.acting_in("*"), body.note)   # policy governs every domain
    except Exception as exc:
        raise _err(exc) from exc
    return {"id": v.id, "status": v.status}


@app.post("/api/v1/policy/proposals/{vid}/approve")
def approve_policy(vid: int, p: Principal = Depends(current_user), s: Session = Depends(db_session, scope="function")):
    try:
        v = PolicyStore(s).approve(vid, p.acting_in("*"))
    except Exception as exc:
        raise _err(exc) from exc
    return {"id": v.id, "status": v.status}


@app.post("/api/v1/kill-switch")
def kill_switch(on: bool, p: Principal = Depends(need(Perm.KILL_SWITCH)), s: Session = Depends(db_session, scope="function")):
    """Durable (DB-backed) so every API replica and the scheduler stop together, and it survives restarts."""
    AccessService(s, get_settings()).set_flag(p, "kill_switch", bool(on), perm=Perm.KILL_SWITCH)
    AuditLog(s).append(actor_type="human", actor_id=p.id, event_type="policy.kill_switch", subject_type="policy",
                       subject_id="kill_switch", payload={"on": on})
    return {"kill_switch": kill_switch_on(s, get_settings())}


# ----------------------------------------------------------------------------- actions / approvals


@app.get("/api/v1/actions/catalog")
def action_catalog(_: Principal = Depends(need(Perm.READ)), s: Session = Depends(db_session, scope="function")):
    pol = policy_engine(s)
    # the level shown is the one that applies: the policy's, lowered by a tool's rollout stage (recommend -> L2)
    return [{**a, "level": min(int(pol.view(a["action_type"]).level), 4 if a["max_level"] is None else a["max_level"])}
            for a in registry().action_registry().catalog()]


@app.get("/api/v1/actions")
def list_actions(status: str | None = None, case_id: str | None = None, domain: str | None = None,
                 p: Principal = Depends(need(Perm.READ)), s: Session = Depends(db_session, scope="function")):
    if case_id:
        from soc_platform.core.cases import actions_for_case

        _case_in_scope(s, p, case_id)
        rows = [a for a in actions_for_case(s, case_id) if not status or a.status in status.split(",")]
        return [_action(a) for a in rows if "*" in p.domains or a.domain in p.domains]
    q = select(ActionRequest).order_by(ActionRequest.created_at.desc()).limit(500)
    if status:
        q = q.where(ActionRequest.status.in_(status.split(",")))
    if domain:
        q = q.where(ActionRequest.domain == domain)
    if "*" not in p.domains:
        q = q.where(ActionRequest.domain.in_(sorted(p.domains)))  # "platform" actions are cross-domain
    return [_action(a) for a in s.execute(q).scalars()]


@app.get("/api/v1/actions/summary")
def actions_summary(status: str | None = None, p: Principal = Depends(need(Perm.READ)), s: Session = Depends(db_session, scope="function")):
    """True totals behind the action list (badge and tab counts), scoped like the list."""
    from sqlalchemy import func

    q = select(ActionRequest.domain, func.count()).group_by(ActionRequest.domain)
    if status:
        q = q.where(ActionRequest.status.in_(status.split(",")))
    if "*" not in p.domains:
        q = q.where(ActionRequest.domain.in_(sorted(p.domains)))
    by = {d: n for d, n in s.execute(q).all()}
    return {"total": sum(by.values()), "by_domain": by, "list_limit": 500}


def _action(a: ActionRequest) -> dict[str, Any]:
    return {"id": a.id, "action_type": a.action_type, "status": a.status, "level": a.autonomy_level, "case_id": a.case_id,
            "domain": a.domain, "targets": a.targets, "params": a.params, "rationale": a.rationale,
            "evidence_ids": a.evidence_ids, "policy_reasons": a.policy_reasons, "requested_by": a.requested_by,
            "approver": a.approver, "result": a.result, "created_at": a.created_at.isoformat(),
            "executed_at": a.executed_at.isoformat() if a.executed_at else None}


class ActionBody(BaseModel):
    action_type: str
    targets: list[dict[str, Any]] = Field(default_factory=list)
    params: dict[str, Any] = Field(default_factory=dict)
    case_id: str | None = None
    rationale: str = ""


class Decision(BaseModel):
    note: str = ""


def _action_service(s: Session) -> ActionService:
    return ActionService(s, registry().action_registry(), policy_engine(s))


@app.post("/api/v1/actions")
def request_action(body: ActionBody, p: Principal = Depends(current_user), s: Session = Depends(db_session, scope="function")):
    case = _case_in_scope(s, p, body.case_id)
    if body.case_id is None and "*" not in p.domains:
        raise HTTPException(403, "actions outside a case require all-domain access")
    # The action belongs to its case's domain (it was recorded as "platform", so it fell outside every scoped
    # approver's queue while its requester could still self-approve it); a case-less action is platform-wide.
    domain = case.domain if case is not None else "platform"
    try:
        return _action(_action_service(s).request(body.action_type, params=body.params, targets=body.targets,
                                                  requested_by=p.acting_in(domain), case_id=body.case_id,
                                                  domain=domain, rationale=body.rationale))
    except Exception as exc:
        raise _err(exc) from exc


@app.post("/api/v1/actions/{aid}/{verb}")
def decide_action(aid: str, verb: str, body: Decision, p: Principal = Depends(current_user),
                  s: Session = Depends(db_session, scope="function")):
    svc = _action_service(s)
    ar = s.get(ActionRequest, aid)
    if ar is not None:
        _case_in_scope(s, p, ar.case_id)
        if not p.in_domain(ar.domain if ar.domain in {"phishing", "incident", "vulnerability"} else "*"):
            raise HTTPException(404, "unknown action")
    try:
        fn = {"approve": svc.approve, "reject": svc.reject, "rollback": svc.rollback}[verb]
        return _action(fn(aid, p, note=body.note))
    except KeyError as exc:
        raise HTTPException(404, str(exc)) from exc
    except Exception as exc:
        raise _err(exc) from exc


# ----------------------------------------------------------------------------- audit


@app.get("/api/v1/audit")
def audit(subject_id: str | None = None, actor_id: str | None = None, event_type: str | None = None,
          limit: int = Query(200, ge=1, le=100_000), p: Principal = Depends(need(Perm.READ_AUDIT)),
          s: Session = Depends(db_session, scope="function")):
    log = AuditLog(s)
    if "*" in p.domains:
        rows = log.query(subject_id=subject_id, actor_id=actor_id, event_type=event_type, limit=limit)
    else:  # domain-scoped readers see records about their own domains (and their own actions) only
        rows = [r for r in log.query(subject_id=subject_id, actor_id=actor_id, event_type=event_type, limit=100_000)
                if r.actor_id == p.id or _audit_domain(s, r.subject_type, r.subject_id) in p.domains][:limit]
    return [{**rec, "ts_utc": row.ts.isoformat()} for rec, row in zip(AuditLog.export(rows), rows)]


_VM_SUBJECTS = {"finding", "campaign", "misconfiguration", "plan", "action_plan", "risk_entry", "vm"}


def _audit_domain(s: Session, subject_type: str, subject_id: str) -> str | None:
    """Domain an audit record is about (None = platform-wide, visible to all-domain readers only)."""
    if subject_type == "case":
        c = s.get(Case, subject_id)
        return c.domain if c else None
    if subject_type == "action":
        a = s.get(ActionRequest, subject_id)
        return a.domain if a and a.domain in {"phishing", "incident", "vulnerability"} else None
    if subject_type == "submission":
        return "phishing"
    return "vulnerability" if subject_type in _VM_SUBJECTS else None


@app.get("/api/v1/admin/self-check")
def self_check(_: Principal = Depends(need(Perm.READ_AUDIT, "*")), s: Session = Depends(db_session, scope="function")):
    """The platform proves its own figures agree across every surface and its records are intact (see core.selfcheck)."""
    from soc_platform.core.selfcheck import run_self_check

    return run_self_check(s)


@app.get("/api/v1/admin/notifications")
def notifications(_: Principal = Depends(need(Perm.READ_AUDIT, "*")), s: Session = Depends(db_session, scope="function")):
    """Configured notification channels (kind and host only - never the webhook URL, which holds a secret) and the
    most recent deliveries."""
    from soc_platform.core import notify

    floor = next(k for k, v in notify.SEVERITY_RANK.items() if v == notify.min_severity())
    return {"channels": [c.label for c in notify.channels()], "min_severity": floor,
            "max_attempts": notify.MAX_ATTEMPTS, "recent": notify.recent(s)}


@app.post("/api/v1/admin/notifications/test")
def notifications_test(p: Principal = Depends(need(Perm.MANAGE_CONNECTORS, "*")), s: Session = Depends(db_session, scope="function")):
    """Send a test message to every configured channel now (Integrations -> Notifications -> Send test message)."""
    from soc_platform.core import notify

    if not notify.channels():
        raise HTTPException(400, "no notification channels configured (SOC_NOTIFY_WEBHOOKS)")
    results = notify.send_test(by=p.id)
    AuditLog(s).append(actor_type=p.actor_type, actor_id=p.id, event_type="notify.test", subject_type="notifications",
                       subject_id="channels", payload={"results": results})
    return {"results": results}


@app.get("/api/v1/audit/verify")
def audit_verify(_: Principal = Depends(need(Perm.READ_AUDIT)), s: Session = Depends(db_session, scope="function")):
    return AuditLog(s).verify()


# ----------------------------------------------------------------------------- entities & resolution


@app.get("/api/v1/entities/find")
def find_entity(kind: str, key: str, value: str, _: Principal = Depends(need(Perm.READ, "*")), s: Session = Depends(db_session, scope="function")):
    st = ContextStore(s)
    e = st.find(kind, key, value)
    if e is None:
        raise HTTPException(404, "not found")
    return _entity(st, e)


@app.get("/api/v1/entities/{eid}")
def get_entity(eid: str, _: Principal = Depends(need(Perm.READ, "*")), s: Session = Depends(db_session, scope="function")):
    e = s.get(Entity, eid)
    if e is None:
        raise HTTPException(404, "not found")
    return _entity(ContextStore(s), e)


def _entity(st: ContextStore, e: Entity) -> dict[str, Any]:
    return {"id": e.id, "kind": e.kind, "name": e.display_name, "attributes": e.attributes, "keys": st.keys_of(e.id),
            "related": [{"rel": r.rel_type, "id": o.id, "kind": o.kind, "name": o.display_name}
                        for r, o in st.neighbors(e.id)][:200],
            "timeline": st.timeline([e.id])}


@app.get("/api/v1/resolution/unresolved")
def unresolved(_: Principal = Depends(need(Perm.READ, "*")), s: Session = Depends(db_session, scope="function")):
    return [{"id": u.id, "kind": u.kind, "reason": u.reason, "candidates": u.candidates, "source_record": u.source_record_id}
            for u in s.execute(select(UnresolvedItem).where(UnresolvedItem.status == "open")).scalars()]


class Override(BaseModel):
    entity_id: str | None = None
    reason: str = ""


@app.post("/api/v1/resolution/{uid}/override")
def resolution_override(uid: str, body: Override, p: Principal = Depends(need(Perm.RESOLVE_ENTITIES, "*")), s: Session = Depends(db_session, scope="function")):
    try:
        rec = EntityResolver(s).override(uid, body.entity_id, p, body.reason)
    except Exception as exc:
        raise _err(exc) from exc
    return {"source_record": rec.id, "entity_id": rec.entity_id}


@app.get("/api/v1/resolution/match-rate")
def match_rate(kind: str = "asset", _: Principal = Depends(need(Perm.READ, "*")), s: Session = Depends(db_session, scope="function")):
    return EntityResolver(s).match_rate(kind)


# ----------------------------------------------------------------------------- cases (shared)


def _assignee_filter(q: Any, assignee: str | None, p: Principal) -> Any:
    """``me`` -> the caller's cases, ``unassigned`` -> cases without an owner, an address -> that person's cases."""
    if not assignee:
        return q
    if assignee == "me":
        return q.where(Case.assignee == p.id.lower())
    if assignee == "unassigned":
        return q.where(Case.assignee.is_(None))
    return q.where(Case.assignee == assignee.strip().lower())


@app.get("/api/v1/cases")
def list_cases(domain: str | None = None, status: str | None = None, assignee: str | None = Query(None, max_length=256),
               p: Principal = Depends(need(Perm.READ)), s: Session = Depends(db_session, scope="function")):
    q = select(Case).order_by(Case.created_at.desc()).limit(500)
    if domain:
        q = q.where(Case.domain == domain)
    if "*" not in p.domains:
        q = q.where(Case.domain.in_(sorted(p.domains)))
    if status:
        q = q.where(Case.status.in_(status.split(",")))
    q = _assignee_filter(q, assignee, p)
    return [{"id": c.id, "domain": c.domain, "title": c.title, "status": c.status, "severity": c.severity,
             "verdict": c.verdict, "confidence": c.confidence, "assignee": c.assignee, "created_at": _iso(c.created_at)}
            for c in s.execute(q).scalars()]


LIST_LIMIT = 500


@app.get("/api/v1/cases/summary")
def cases_summary(status: str | None = None, p: Principal = Depends(need(Perm.READ)), s: Session = Depends(db_session, scope="function")):
    """True totals behind the case list (the list itself returns the 500 most recent)."""
    from sqlalchemy import func

    q = select(Case.domain, func.count()).group_by(Case.domain)
    if "*" not in p.domains:
        q = q.where(Case.domain.in_(sorted(p.domains)))
    if status:
        q = q.where(Case.status.in_(status.split(",")))
    by = {d: n for d, n in s.execute(q).all()}

    def count(assignee: str) -> int:
        cq = select(func.count()).select_from(Case)
        if "*" not in p.domains:
            cq = cq.where(Case.domain.in_(sorted(p.domains)))
        if status:
            cq = cq.where(Case.status.in_(status.split(",")))
        return s.execute(_assignee_filter(cq, assignee, p)).scalar()

    return {"total": sum(by.values()), "by_domain": by, "mine": count("me"), "unassigned": count("unassigned"),
            "list_limit": LIST_LIMIT}


@app.get("/api/v1/search")
def search(q: str = Query(..., min_length=2, max_length=200), limit: int = Query(10, ge=1, le=50),
           p: Principal = Depends(need(Perm.READ)), s: Session = Depends(db_session, scope="function")) -> dict[str, Any]:
    """One search box over cases, people / hosts / indicators (any identifier from any tool), correlated findings and
    vulnerabilities - each group limited to what the caller may see. Matching is case-insensitive substring; the
    user's text is escaped, so it is always a literal (``%`` and ``_`` match themselves)."""
    from soc_platform.core.models import EntityKey
    from soc_platform.domains.vulnerability.models import ConsolidatedFinding
    from soc_platform.intelligence.models import Insight

    term = q.strip()
    like = "%" + term.lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"

    def has(col: Any) -> Any:
        return func.lower(col).like(like, escape="\\")

    all_domains = "*" in p.domains
    cq = select(Case).where(or_(has(Case.title), Case.id == term.lower())).order_by(Case.created_at.desc()).limit(limit)
    if not all_domains:
        cq = cq.where(Case.domain.in_(sorted(p.domains)))
    out: dict[str, Any] = {"q": term, "cases": [
        {"id": c.id, "domain": c.domain, "title": c.title, "severity": c.severity, "status": c.status,
         "assignee": c.assignee} for c in s.execute(cq).scalars()]}
    if all_domains:   # people, hosts and correlated findings span every domain
        ids = select(EntityKey.entity_id).where(has(EntityKey.key_value))
        eq = (select(Entity).where(Entity.kind.in_(("asset", "identity", "indicator")),
                                   or_(has(Entity.display_name), Entity.id.in_(ids)))
              .order_by(Entity.last_seen.desc()).limit(limit))
        out["entities"] = [{"id": e.id, "kind": e.kind, "name": e.display_name} for e in s.execute(eq).scalars()]
        iq = select(Insight).where(has(Insight.title)).order_by(Insight.last_seen.desc()).limit(limit)
        out["insights"] = [{"id": i.id, "title": i.title, "severity": i.severity, "status": i.status}
                           for i in s.execute(iq).scalars()]
    if all_domains or p.in_domain("vulnerability"):
        fq = (select(ConsolidatedFinding).where(or_(has(ConsolidatedFinding.cve), has(ConsolidatedFinding.asset_name)))
              .order_by(ConsolidatedFinding.priority_score.desc()).limit(limit))
        out["findings"] = [{"id": f.id, "cve": f.cve, "asset": f.asset_name, "priority": f.priority_band,
                            "status": f.status} for f in s.execute(fq).scalars()]
    AuditLog(s).append(actor_type=p.actor_type, actor_id=p.id, event_type="search", subject_type="search",
                       subject_id="search", payload={"chars": len(term)})
    return out


class AssignBody(BaseModel):
    assignee: str | None = Field(default=None, max_length=256)


class NoteBody(BaseModel):
    text: str = Field(min_length=1, max_length=4000)


@app.post("/api/v1/cases/{cid}/assign")
def case_assign(cid: str, body: AssignBody, p: Principal = Depends(need(Perm.INVESTIGATE)), s: Session = Depends(db_session, scope="function")):
    """Take a case, give it to someone (lead), or clear the owner (lead, or the current owner)."""
    case = _case_in_scope(s, p, cid)
    try:
        case = CaseService(s).assign(cid, body.assignee, by=p.acting_in(case.domain))
    except PermissionError as exc:
        raise HTTPException(403, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return {"id": case.id, "assignee": case.assignee}


@app.post("/api/v1/cases/{cid}/notes")
def case_note(cid: str, body: NoteBody, p: Principal = Depends(need(Perm.INVESTIGATE)), s: Session = Depends(db_session, scope="function")):
    """Append an analyst note (notes are never edited or deleted; a correction is a new note)."""
    case = _case_in_scope(s, p, cid)
    try:
        note = CaseService(s).add_note(cid, body.text, by=p.acting_in(case.domain))
    except PermissionError as exc:
        raise HTTPException(403, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return {"id": note.id, "author": note.author, "text": note.text, "at": note.created_at.isoformat()}


@app.get("/api/v1/cases/{cid}")
def get_case(cid: str, p: Principal = Depends(need(Perm.READ)), s: Session = Depends(db_session, scope="function")):
    _case_in_scope(s, p, cid)
    try:
        view = CaseService(s).view(cid)
    except KeyError as exc:
        raise HTTPException(404, str(exc)) from exc
    view["intelligence"] = _case_intelligence(s, view) if "*" in p.domains else {}
    return view


def _case_intelligence(s: Session, view: dict[str, Any]) -> dict[str, Any]:
    from soc_platform.intelligence.models import Insight
    from soc_platform.intelligence.risk import RiskEngine

    ids = {e["id"] for e in view["entities"]}
    insights = [i for i in s.execute(select(Insight).where(Insight.status != "dismissed")).scalars()
                if ids & set(i.entity_ids)]
    risk = RiskEngine(s)
    profiles = [p for e in view["entities"] if e["kind"] in {"asset", "identity"} and (p := risk.profile(e["id"]))]
    return {"insights": [{"id": i.id, "rule": i.rule, "title": i.title, "severity": i.severity,
                          "narrative": i.narrative, "next_steps": i.next_steps} for i in
                         sorted(insights, key=lambda x: -x.score)],
            "entity_risk": [{"entity_id": p.entity_id, "name": p.name, "score": p.score, "band": p.band,
                             "dimensions": p.dimensions} for p in sorted(profiles, key=lambda p: -p.score)]}


class DispositionBody(BaseModel):
    verdict: str
    reasoning: str = ""
    close: bool = True


@app.post("/api/v1/cases/{cid}/disposition")
def case_disposition(cid: str, body: DispositionBody, p: Principal = Depends(current_user), s: Session = Depends(db_session, scope="function")):
    case = _case_in_scope(s, p, cid)
    p = p.acting_in(case.domain)
    try:
        if case.domain == "phishing":
            return _services(s)["phishing"].confirm(cid, p, verdict=body.verdict, reasoning=body.reasoning)
        d = CaseService(s).decide(cid, p, verdict=body.verdict, reasoning=body.reasoning, close=body.close)
        return {"disposition": d.analyst_verdict}
    except Exception as exc:
        raise _err(exc) from exc


@app.get("/api/v1/cases/{cid}/report")
def case_report(cid: str, p: Principal = Depends(need(Perm.READ)), s: Session = Depends(db_session, scope="function")):
    _case_in_scope(s, p, cid)
    from soc_platform.reporting.reports import ReportService

    run = ReportService(s, get_settings().report_output_dir, llm=llm(s, p)).investigation_report(CaseService(s).view(cid), by=p.id)
    return _protected_file(run.path)


class BundleBody(BaseModel):
    action_ids: list[str] = Field(min_length=1, max_length=50)
    note: str = ""


@app.get("/api/v1/cases/{cid}/story")
def case_story(cid: str, p: Principal = Depends(need(Perm.READ)), s: Session = Depends(db_session, scope="function")):
    """Attack Story: cross-tool attack chain, gaps, benign explanations, blast radius, response plan."""
    from soc_platform.intelligence.story import story_for_case

    _case_in_scope(s, p, cid)
    story = story_for_case(s, cid, registry())
    if "*" not in p.domains:  # related cases from other domains are summarised, not exposed
        story["generated_from"] = [c for c in story["generated_from"] if p.in_domain((s.get(Case, c) or Case()).domain)]
    story["deep_analysis"] = ((s.get(Case, cid).assessment or {}).get("deep_analysis"))
    return story


@app.post("/api/v1/cases/{cid}/story/approve")
def story_approve(cid: str, body: BundleBody, p: Principal = Depends(need(Perm.APPROVE_ACTION)), s: Session = Depends(db_session, scope="function")):
    """Approve several response-plan actions at once. Each goes through the normal policy / four-eyes checks (and
    is judged in its own domain by ActionService)."""
    from soc_platform.intelligence.story import story_for_case

    _case_in_scope(s, p, cid)
    rows = {a["id"]: a for ph in story_for_case(s, cid, registry())["response_plan"] for a in ph["actions"] if a["approvable"]}
    svc, out = _action_service(s), []
    expanded = [x for aid in body.action_ids for x in [aid, *rows.get(aid, {}).get("duplicate_ids", [])]]
    allowed = set(rows) | {d for r in rows.values() for d in r.get("duplicate_ids", [])}
    for aid in dict.fromkeys(expanded):
        if aid not in allowed:
            out.append({"id": aid, "ok": False, "error": "not a pending action of this story"})
            continue
        ar = s.get(ActionRequest, aid)
        if not p.in_domain(ar.domain if ar.domain in {"phishing", "incident", "vulnerability"} else "*"):
            out.append({"id": aid, "ok": False, "error": "outside your data scope"})
            continue
        try:
            with s.begin_nested():
                r = svc.approve(aid, p, note=body.note or "approved from attack story")
            out.append({"id": aid, "ok": True, "status": r.status})
        except Exception as exc:  # noqa: BLE001 - reported per action
            out.append({"id": aid, "ok": False, "error": str(exc)[:200]})
    AuditLog(s).append(actor_type=p.actor_type, actor_id=p.id, event_type="story.bundle_approve", subject_type="case",
                       subject_id=cid, payload={"requested": len(body.action_ids), "approved": sum(1 for x in out if x["ok"])})
    return {"results": out, "approved": sum(1 for x in out if x["ok"])}


class DeepBody(BaseModel):
    force: bool = False


@app.post("/api/v1/cases/{cid}/deep-analysis")
def deep_analysis(cid: str, body: DeepBody | None = None, p: Principal = Depends(need(Perm.INVESTIGATE)),
                  s: Session = Depends(db_session, scope="function")):
    """Evidence-bound LLM review of the attack story (requires an approved LLM endpoint)."""
    from soc_platform.intelligence.deep_analysis import run_deep_analysis
    from soc_platform.intelligence.story import story_for_case

    case = _case_in_scope(s, p, cid)
    if not p.acting_in(case.domain).can(Perm.INVESTIGATE):
        raise HTTPException(403, f"investigate is not granted for {case.domain} data")
    story = story_for_case(s, cid, registry())
    gw = llm(s, p)
    return _with_notice(run_deep_analysis(s, story, gw, actor=p.id, force=bool(body and body.force),
                                          org_domains=get_settings().org_domains), gw)


@app.get("/api/v1/llm/status")
def llm_status(_: Principal = Depends(need(Perm.READ)), s: Session = Depends(db_session, scope="function")):
    st = get_settings()
    return {"configured": st.llm_provider != "none", "provider": st.llm_provider,
            "model_pinned": st.llm_model_version, "redaction": st.llm_redact_pii,
            "budget": LLMGateway(s, st).budget_status() if st.llm_provider != "none" else None,
            "latency": LLMGateway(s, st).latency_status() if st.llm_provider != "none" else None}


@app.get("/api/v1/metrics/shadow")
def shadow(domain: str, p: Principal = Depends(need(Perm.READ)), s: Session = Depends(db_session, scope="function")):
    if not p.in_domain(domain):
        raise HTTPException(403, f"not authorised for {domain} data")
    return {"agreement": agreement_report(s, domain), "detection_quality": detection_quality(s, domain, min_count=2)}


@app.get("/api/v1/metrics/drift")
def drift(recent_days: int = Query(7, ge=1, le=90), baseline_days: int = Query(28, ge=7, le=365),
          p: Principal = Depends(need(Perm.READ)), s: Session = Depends(db_session, scope="function")):
    """Verdict-quality drift per domain (R14, NFR-13), limited to the caller's domains."""
    from soc_platform.intelligence.drift import drift_report

    out = drift_report(s, recent_days=recent_days, baseline_days=baseline_days)
    out["domains"] = {d: v for d, v in out.get("domains", {}).items() if p.in_domain(d)}
    return out


class LlmPolicyBody(BaseModel):
    policy: dict[str, Any]
    note: str = Field(default="", max_length=2000)


@app.get("/api/v1/admin/llm/policy")
def llm_policy_get(_: Principal = Depends(need(Perm.READ_AUDIT)), s: Session = Depends(db_session, scope="function")):
    """The AI usage policy in force (budgets, per-user limits, per-feature tiers), its defaults and its history."""
    from soc_platform.llm.usage_policy import KNOWN_WORKFLOWS, ROLES, TIERS, UsagePolicyStore, defaults

    st = UsagePolicyStore(s, get_settings())
    return {"policy": st.active(), "defaults": defaults(get_settings()), "history": st.history(),
            "workflows": {k: {"default_tier": v[0], "triggered_by": v[1], "description": v[2]}
                          for k, v in KNOWN_WORKFLOWS.items()}, "roles": list(ROLES), "tiers": list(TIERS)}


@app.post("/api/v1/admin/llm/policy")
def llm_policy_set(body: LlmPolicyBody, p: Principal = Depends(need(Perm.MANAGE_ACCESS)),
                   s: Session = Depends(db_session, scope="function")):
    """Set budgets, per-user / per-role limits and per-feature model choice (administrators; audited; in force for
    the next model call, no restart)."""
    from soc_platform.llm.usage_policy import UsagePolicyStore

    try:
        row = UsagePolicyStore(s, get_settings()).save(body.policy, p, body.note)
    except Exception as exc:
        raise _err(exc) from exc
    return {"id": row.id, "policy": UsagePolicyStore(s, get_settings()).active()}


@app.get("/api/v1/admin/llm/usage")
def llm_usage(days: int = Query(30, ge=1, le=366), _: Principal = Depends(need(Perm.READ_AUDIT)),
              s: Session = Depends(db_session, scope="function")):
    """Measured use per feature and per person, cost, answer quality and speed, with a tier recommendation per
    feature computed from those figures."""
    from soc_platform.llm.usage_policy import UsagePolicyStore, usage_report

    return usage_report(s, UsagePolicyStore(s, get_settings()).active(), days=days)


@app.get("/api/v1/llm/budget")
def llm_budget(_: Principal = Depends(need(Perm.READ)), s: Session = Depends(db_session, scope="function")):
    return LLMGateway(s, get_settings()).budget_status()


# ----------------------------------------------------------------------------- phishing


@app.post("/api/v1/phishing/ingest")
def phishing_ingest(process: bool = True, p: Principal = Depends(need(Perm.INVESTIGATE, "phishing")), s: Session = Depends(db_session, scope="function")):
    svc = _services(s)["phishing"]
    subs = svc.ingest_reported()
    ids = [svc.process(sub.id, narrate=False)["case"]["id"] for sub in subs if process and sub.status == "new"]
    s.commit()                                   # cases saved first: no write lock is held while the model writes
    svc.narrate_pending(ids)                     # the model explanations for the whole batch, in parallel
    out = [svc.cases.view(cid)["case"] for cid in ids]
    if out:
        _intel(s).refresh()
    return {"submissions": [x.id for x in subs], "processed": out}


@app.post("/api/v1/phishing/submit")
async def phishing_submit(file: UploadFile = File(...), reporter: str | None = None, process: bool = True,
                          p: Principal = Depends(need(Perm.INVESTIGATE, "phishing")), s: Session = Depends(db_session, scope="function")):
    raw = await file.read(25 * 1024 * 1024 + 1)
    if len(raw) > 25 * 1024 * 1024:
        raise HTTPException(413, "message too large")
    if not raw.strip():
        raise HTTPException(400, "empty message")
    svc = _services(s)["phishing"]
    sub = svc.submit_raw(raw, source="upload", reporter=reporter or p.name)
    return svc.process(sub.id) if process and sub.status == "new" else {"submission": sub.id, "status": sub.status}


@app.get("/api/v1/phishing/suppliers")
def phishing_suppliers(days: int = Query(90, ge=1, le=730), _: Principal = Depends(need(Perm.READ, "phishing")),
                       s: Session = Depends(db_session, scope="function")):
    """Third-party / vendor email risk (U18)."""
    from soc_platform.domains.phishing.supplier import SupplierMonitor

    return SupplierMonitor(s).assess(days=days)


@app.get("/api/v1/phishing/metrics")
def phishing_metrics(_: Principal = Depends(need(Perm.READ, "phishing")), s: Session = Depends(db_session, scope="function")):
    return _services(s)["phishing"].metrics()


# ----------------------------------------------------------------------------- incident


@app.post("/api/v1/incidents/run")
def incidents_run(investigate: bool = True, p: Principal = Depends(need(Perm.INVESTIGATE, "incident")), s: Session = Depends(db_session, scope="function")):
    svc = _services(s)["incident"]
    ing = svc.ingest()
    cases = svc.cluster()
    ids = [svc.investigate(c.id, narrate=False)["case"]["id"] for c in cases if investigate and c.status != "closed"]
    s.commit()                                   # cases saved first: no write lock is held while the model writes
    svc.narrate_pending(ids)                     # the model explanations for the whole batch, in parallel
    done = [svc.cases.view(cid)["case"] for cid in ids]
    _intel(s).refresh()
    return {"ingested": ing.synced, "errors": ing.errors, "new_incidents": len(cases), "investigated": done}


@app.post("/api/v1/incidents/{cid}/investigate")
def incident_investigate(cid: str, p: Principal = Depends(need(Perm.INVESTIGATE, "incident")), s: Session = Depends(db_session, scope="function")):
    case = s.get(Case, cid)
    if case is None or case.domain != "incident":
        raise HTTPException(404, "unknown incident")
    return _services(s)["incident"].investigate(cid)


@app.get("/api/v1/incidents/handover")
def incident_handover(hours: int = Query(12, ge=1, le=24 * 90), _: Principal = Depends(need(Perm.READ, "incident")), s: Session = Depends(db_session, scope="function")):
    return _services(s)["incident"].handover(hours=hours)


# ----------------------------------------------------------------------------- vulnerability


@app.post("/api/v1/vm/refresh")
def vm_refresh(p: Principal = Depends(need(Perm.INVESTIGATE, "vulnerability")), s: Session = Depends(db_session, scope="function")):
    out = _services(s)["vulnerability"].refresh()
    out["misconfigurations"] = _misconfig(s).refresh()
    _intel(s).refresh()
    return out


def _misconfig(s: Session):
    from soc_platform.domains.vulnerability.misconfig import MisconfigurationService

    return MisconfigurationService(s, registry(), policy=policy_engine(s))


@app.get("/api/v1/vm/metrics")
def vm_metrics(_: Principal = Depends(need(Perm.READ, "vulnerability")), s: Session = Depends(db_session, scope="function")):
    return _services(s)["vulnerability"].metrics()


@app.get("/api/v1/vm/findings")
def vm_findings(priority: str | None = None, status: str = "open,reopened", _: Principal = Depends(need(Perm.READ, "vulnerability")),
                s: Session = Depends(db_session, scope="function")):
    from soc_platform.domains.vulnerability.models import ConsolidatedFinding

    q = select(ConsolidatedFinding).where(ConsolidatedFinding.status.in_(status.split(","))) \
        .order_by(ConsolidatedFinding.priority_score.desc())
    if priority:
        q = q.where(ConsolidatedFinding.priority_band.in_(priority.split(",")))
    return [{"id": f.id, "cve": f.cve, "asset": f.asset_name, "priority": f.priority_band, "score": f.priority_score,
             "factors": f.priority_factors, "status": f.status, "team": f.platform_team, "owner": f.owner,
             "sla_due": f.sla_due.isoformat() if f.sla_due else None, "sources": f.sources,
             "internet_exposed": f.internet_exposed, "campaign_id": f.campaign_id} for f in s.execute(q).scalars()]


@app.get("/api/v1/vm/affected/{cve}")
def vm_affected(cve: str, _: Principal = Depends(need(Perm.READ, "vulnerability")), s: Session = Depends(db_session, scope="function")):
    return _services(s)["vulnerability"].affected_devices(cve.upper())


class CampaignBody(BaseModel):
    cve: str
    notify_via: str = "email"
    team_contacts: dict[str, str] = Field(default_factory=dict)


@app.post("/api/v1/vm/campaigns")
def vm_campaign(body: CampaignBody, p: Principal = Depends(need(Perm.READ, "vulnerability")), s: Session = Depends(db_session, scope="function")):
    try:
        c = _services(s)["vulnerability"].create_campaign(body.cve.upper(), p, notify_via=body.notify_via,
                                                          team_contacts=body.team_contacts)
    except Exception as exc:
        raise _err(exc) from exc
    return {"campaign_id": c.id, "status": c.status}


class AckBody(BaseModel):
    committed_date: datetime
    owner: str | None = None
    dependencies: str = ""
    response: str = ""


@app.post("/api/v1/vm/plans/{pid}/acknowledge")
def vm_ack(pid: str, body: AckBody, p: Principal = Depends(need(Perm.INVESTIGATE, "vulnerability")),
           s: Session = Depends(db_session, scope="function")):
    from soc_platform.domains.vulnerability.models import ActionPlan

    if s.get(ActionPlan, pid) is None:
        raise HTTPException(404, "unknown plan")
    plan = _services(s)["vulnerability"].acknowledge(pid, p, committed_date=body.committed_date, owner=body.owner,
                                                     dependencies=body.dependencies, response=body.response)
    return {"plan_id": plan.id, "status": plan.status}


@app.post("/api/v1/vm/follow-up")
def vm_follow(p: Principal = Depends(need(Perm.INVESTIGATE, "vulnerability")), s: Session = Depends(db_session, scope="function")):
    return _services(s)["vulnerability"].follow_up()


@app.post("/api/v1/vm/campaigns/{cid}/validate")
def vm_validate(cid: str, p: Principal = Depends(need(Perm.INVESTIGATE, "vulnerability")), s: Session = Depends(db_session, scope="function")):
    from soc_platform.domains.vulnerability.models import RemediationCampaign

    if s.get(RemediationCampaign, cid) is None:
        raise HTTPException(404, "unknown campaign")
    return _services(s)["vulnerability"].validate_campaign(cid)


class ExceptionBody(BaseModel):
    finding_id: str = Field(max_length=64)
    justification: str = Field(min_length=3, max_length=4000)
    compensating_control: str = Field(default="", max_length=4000)
    days: int = Field(default=90, ge=1, le=365)   # a risk acceptance always expires, and within a year


@app.post("/api/v1/vm/exceptions")
def vm_exception(body: ExceptionBody, p: Principal = Depends(need(Perm.REQUEST_ACTION, "vulnerability")),
                 s: Session = Depends(db_session, scope="function")):
    from soc_platform.domains.vulnerability.models import ConsolidatedFinding

    if s.get(ConsolidatedFinding, body.finding_id) is None:
        raise HTTPException(404, "unknown finding")
    ex = _services(s)["vulnerability"].request_exception(body.finding_id, p, justification=body.justification,
                                                         compensating_control=body.compensating_control, days=body.days)
    return {"exception_id": ex.id, "status": ex.status}


@app.post("/api/v1/vm/exceptions/{eid}/decision")
def vm_exception_decision(eid: str, approve: bool, p: Principal = Depends(need(Perm.READ, "vulnerability")), s: Session = Depends(db_session, scope="function")):
    try:
        ex = _services(s)["vulnerability"].decide_exception(eid, p, approve=approve)
    except Exception as exc:
        raise _err(exc) from exc
    return {"exception_id": ex.id, "status": ex.status}


@app.post("/api/v1/vm/risk-register/propose")
def vm_rr(p: Principal = Depends(need(Perm.INVESTIGATE, "vulnerability")), s: Session = Depends(db_session, scope="function")):
    return [{"id": e.id, "cve": e.cve, "rating": e.rating, "risk_statement": e.risk_statement, "status": e.status}
            for e in _services(s)["vulnerability"].propose_risk_register()]


@app.post("/api/v1/vm/risk-register/{eid}/decision")
def vm_rr_decide(eid: str, approve: bool, p: Principal = Depends(need(Perm.READ, "vulnerability")), s: Session = Depends(db_session, scope="function")):
    try:
        e = _services(s)["vulnerability"].decide_risk_entry(eid, p, approve=approve)
    except Exception as exc:
        raise _err(exc) from exc
    return {"id": e.id, "status": e.status}


class QueryBody(BaseModel):
    question: str


@app.post("/api/v1/vm/query")
def vm_query(body: QueryBody, _: Principal = Depends(need(Perm.READ, "vulnerability")), s: Session = Depends(db_session, scope="function")):
    return _services(s)["vulnerability"].query(body.question)


@app.get("/api/v1/vm/new-kev")
def vm_new_kev(since: str = Query(..., description="YYYY-MM-DD"), _: Principal = Depends(need(Perm.READ, "vulnerability")),
               s: Session = Depends(db_session, scope="function")):
    return _services(s)["vulnerability"].new_cve_assessment(since=since)


@app.get("/api/v1/vm/coverage")
def vm_coverage(_: Principal = Depends(need(Perm.READ, "vulnerability")), s: Session = Depends(db_session, scope="function")):
    return _services(s)["vulnerability"].coverage()


@app.get("/api/v1/jobs")
def job_history(job: str | None = None, limit: int = Query(100, ge=1, le=1000), _: Principal = Depends(need(Perm.READ)),
                s: Session = Depends(db_session, scope="function")):
    """Scheduled job runs, retries and dead letters (VM-T11)."""
    from soc_platform import jobs

    return {"jobs": {n: {"interval_env": e, "default_seconds": d} for n, (e, d) in jobs.JOBS.items()},
            "runs": jobs.history(s, job=job, limit=limit)}


@app.post("/api/v1/jobs/{name}/run")
def job_replay(name: str, p: Principal = Depends(need(Perm.MANAGE_CONNECTORS)), s: Session = Depends(db_session, scope="function")):
    """Replay / run a job now. Jobs are idempotent, so a replay never duplicates work or actions."""
    from soc_platform import jobs

    if name not in jobs.JOBS:
        raise HTTPException(404, "unknown job")
    AuditLog(s).append(actor_type=p.actor_type, actor_id=p.id, event_type="job.replay", subject_type="job",
                       subject_id=name, payload={})
    s.commit()
    run = jobs.run_job(name, trigger=f"manual:{p.id}")
    if run is None:
        raise HTTPException(409, "job is running on another replica")
    return {"job": name, "status": run.status, "attempts": run.attempts,
            "error": (run.error or "").splitlines()[0] if run.error else None,
            "summary": run.summary}


@app.post("/api/v1/vm/tickets/sync")
def vm_ticket_sync(_: Principal = Depends(need(Perm.INVESTIGATE, "vulnerability")), s: Session = Depends(db_session, scope="function")):
    """Pull ticket state from ITSM; resolved tickets trigger closure validation (VM-T10, VM-F10)."""
    return _services(s)["vulnerability"].sync_tickets()


@app.get("/api/v1/vm/misconfigurations")
def vm_misconfigs(status: str | None = None, _: Principal = Depends(need(Perm.READ, "vulnerability")),
                  s: Session = Depends(db_session, scope="function")):
    svc = _misconfig(s)
    return {"metrics": svc.metrics(), "items": svc.list(status)}


@app.post("/api/v1/vm/misconfigurations/route")
def vm_misconfig_route(p: Principal = Depends(need(Perm.REQUEST_ACTION, "vulnerability")), s: Session = Depends(db_session, scope="function")):
    try:
        return _misconfig(s).route(p)
    except Exception as exc:
        raise _err(exc) from exc


@app.post("/api/v1/vm/misconfigurations/{mid}/{verb}")
def vm_misconfig_verb(mid: str, verb: str, note: str = "", p: Principal = Depends(need(Perm.INVESTIGATE, "vulnerability")),
                      s: Session = Depends(db_session, scope="function")):
    svc = _misconfig(s)
    try:
        if verb == "fixed":
            m = svc.mark_fixed(mid, p, note)
            return {"id": m.id, "status": m.status}
        if verb == "validate":
            return svc.validate(mid)
    except Exception as exc:
        raise _err(exc) from exc
    raise HTTPException(404, "unknown operation")


# ----------------------------------------------------------------------------- reports


REPORT_DOMAIN = {"daily_exposure": "vulnerability", "weekly_vm": "vulnerability", "weekly_mgmt": "*",
                 "compliance": "*"}


def _report_allowed(p: Principal, kind: str) -> bool:
    dom = REPORT_DOMAIN.get(kind, "*")
    if kind == "compliance" and not p.acting_in("*").can(Perm.EXPORT_EVIDENCE):
        return False
    return "*" in p.domains if dom == "*" else p.in_domain(dom)


class PlanBody(BaseModel):
    request: str = Field(min_length=3, max_length=1500)


class BuildBody(BaseModel):
    template_id: str | None = None
    spec: dict[str, Any] | None = None
    case_id: str | None = None


class SaveTemplateBody(BaseModel):
    spec: dict[str, Any]


def _custom_report_allowed(p: Principal, metrics: dict[str, Any]) -> bool:
    """A generated report may be read only by someone whose data scope covers what it was built from: every
    domain it contains, and the builder's own scope (scope-dependent sections such as the overview)."""
    if "*" in p.domains:
        return True
    needed = set(metrics.get("domains") or []) | set(metrics.get("scope") or ["*"])
    return "*" not in needed and needed <= set(p.domains)


@app.get("/api/v1/reports/templates")
def report_templates(_: Principal = Depends(need(Perm.READ)), s: Session = Depends(db_session, scope="function")):
    """Standard and saved report specifications, plus the data-source catalogue they may use."""
    from soc_platform.reporting.builder import catalogue, list_templates

    return {"templates": list_templates(s), "sources": catalogue()}


@app.post("/api/v1/reports/plan")
def report_plan(body: PlanBody, p: Principal = Depends(need(Perm.READ)), s: Session = Depends(db_session, scope="function")):
    """Turn a report described in words into a spec (catalogue sources only) for review before generating."""
    from soc_platform.reporting.builder import plan_report

    gw = llm(s, p)
    spec = _with_notice(plan_report(body.request, gw), gw)
    AuditLog(s).append(actor_type=p.actor_type, actor_id=p.id, event_type="report.planned", subject_type="report",
                       subject_id="plan", payload={"planner": spec["planner"], "sections": [x["source"] for x in spec["sections"]]})
    return spec


@app.post("/api/v1/reports/templates")
def save_report_template(body: SaveTemplateBody, p: Principal = Depends(need(Perm.READ)), s: Session = Depends(db_session, scope="function")):
    from soc_platform.reporting.builder import validate_spec
    from soc_platform.reporting.models import ReportTemplate

    try:
        spec = validate_spec(body.spec)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    t = ReportTemplate(title=spec["title"], spec=spec, created_by=p.id)
    s.add(t)
    s.flush()
    AuditLog(s).append(actor_type=p.actor_type, actor_id=p.id, event_type="report.template_saved", subject_type="report_template",
                       subject_id=t.id, payload={"title": t.title, "sections": [x["source"] for x in spec["sections"]]})
    return {"id": t.id, **spec}


@app.post("/api/v1/reports/build")
def build_custom_report(body: BuildBody, p: Principal = Depends(need(Perm.READ)), s: Session = Depends(db_session, scope="function")):
    """Generate a standard, saved or ad-hoc report: figures computed in code, narrative grounded on them."""
    from soc_platform.reporting.builder import build_report, get_template, validate_spec

    if body.template_id:
        spec = get_template(s, body.template_id)
        if spec is None:
            raise HTTPException(404, "unknown report template")
    elif body.spec:
        spec = body.spec
    else:
        raise HTTPException(422, "template_id or spec is required")
    try:
        spec = {**validate_spec(spec), "id": spec.get("id"), "planner": spec.get("planner")}
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    if spec["needs_case"]:
        if not body.case_id:
            raise HTTPException(422, "this report is about one case: case_id is required")
        _case_in_scope(s, p, body.case_id)
    denied = frozenset() if p.acting_in("*").can(Perm.EXPORT_EVIDENCE) else frozenset({"compliance"})
    gw = llm(s, p)
    r = build_report(s, registry(), spec, get_settings().report_output_dir, llm=gw, by=p.id,
                     domains=frozenset(p.domains), case_id=body.case_id, denied_sources=denied)
    return _with_notice(r, gw)


@app.post("/api/v1/reports/{kind}")
def make_report(kind: str, period_days: int = Query(90, ge=1, le=730), p: Principal = Depends(need(Perm.READ)),
                s: Session = Depends(db_session, scope="function")):
    from soc_platform.reporting.reports import ReportService

    if kind not in REPORT_DOMAIN:
        raise HTTPException(404, f"unknown report {kind}")
    if not _report_allowed(p, kind):
        raise HTTPException(403, "not authorised for this report")
    if kind == "compliance":
        from soc_platform.domains.vulnerability.models import ReportRun
        from soc_platform.reporting.compliance import build_pack

        path, ev = build_pack(s, get_settings(), get_settings().report_output_dir, period_days=period_days)
        run = ReportRun(kind="compliance", path=str(path), metrics=ev["summary"], generated_by=p.id)
        s.add(run)
        s.flush()
        AuditLog(s).append(actor_type=p.actor_type, actor_id=p.id, event_type="report.compliance_pack",
                           subject_type="report", subject_id=run.id, payload=ev["summary"])
        return {"id": run.id, "kind": run.kind, "path": run.path, "summary": ev["summary"]}
    sv = _services(s)
    rs = ReportService(s, get_settings().report_output_dir, llm=llm(s))
    fn = {"daily_exposure": lambda: rs.daily_exposure(sv["vulnerability"], by=p.id),
          "weekly_vm": lambda: rs.weekly_vm(sv["vulnerability"], by=p.id),
          "weekly_mgmt": lambda: rs.weekly_management_deck(sv["vulnerability"], sv["incident"], sv["phishing"], by=p.id)}
    if kind not in fn:
        raise HTTPException(404, f"unknown report {kind}")
    run = fn[kind]()
    return {"id": run.id, "kind": run.kind, "path": run.path}


@app.get("/api/v1/reports/{rid}/download")
def download_report(rid: str, p: Principal = Depends(need(Perm.READ)), s: Session = Depends(db_session, scope="function")):
    from soc_platform.domains.vulnerability.models import ReportRun

    run = s.get(ReportRun, rid)
    if run is None:
        raise HTTPException(404, "unknown report")
    if run.kind == "investigation":
        _case_in_scope(s, p, (run.metrics or {}).get("case_id"))
    elif run.kind.startswith("custom:"):
        if (run.metrics or {}).get("case_id"):
            _case_in_scope(s, p, run.metrics["case_id"])
        if not _custom_report_allowed(p, run.metrics or {}):
            raise HTTPException(404, "unknown report")
    elif not _report_allowed(p, run.kind):
        raise HTTPException(404, "unknown report")
    root = Path(get_settings().report_output_dir).resolve()
    if root not in Path(run.path).resolve().parents:
        raise HTTPException(404, "unknown report")
    return _protected_file(run.path)


# ----------------------------------------------------------------------------- dashboards


@app.get("/api/v1/dashboard/overview")
def dash_overview(days: int = Query(14, ge=1, le=90), p: Principal = Depends(need(Perm.READ)),
                  s: Session = Depends(db_session, scope="function")):
    from soc_platform.api.dashboards import overview

    return overview(s, p.domains, days=days)


@app.get("/api/v1/dashboard/connectors")
def dash_connectors(_: Principal = Depends(need(Perm.READ)), s: Session = Depends(db_session, scope="function")):
    from soc_platform.api.dashboards import connector_freshness

    return connector_freshness(s, registry())


@app.get("/api/v1/dashboard/attack-coverage")
def dash_attack(_: Principal = Depends(need(Perm.READ)), s: Session = Depends(db_session, scope="function")):
    from soc_platform.intelligence.attack_coverage import coverage

    return coverage(s, registry().enabled_names())


@app.get("/api/v1/dashboard/shadow-it")
def dash_shadow_it(since: str = Query("-7days", pattern=r"^-\d{1,3}(days|hours)$"),
                   _: Principal = Depends(need(Perm.READ, "incident"))):
    from soc_platform.intelligence.shadow_it import shadow_it_report

    return shadow_it_report(registry(), since=since)


@app.get("/api/v1/entities/{eid}/360")
def entity360(eid: str, p: Principal = Depends(need(Perm.READ)), s: Session = Depends(db_session, scope="function")):
    from soc_platform.api.dashboards import entity_360

    out = entity_360(s, eid)
    if out is None:
        raise HTTPException(404, "not found")
    if "*" not in p.domains:
        out["cases"] = [c for c in out["cases"] if p.in_domain(c["domain"])]
        out["insights"] = []   # correlated findings are cross-domain
        out["risk"] = None     # fused risk mixes every domain
        out["timeline"], out["related"], out["per_tool"], out["activity_by_tool"] = [], {}, {}, {}
        if not p.in_domain("vulnerability"):
            out["vulnerabilities"] = []
    return out


@app.get("/metrics", include_in_schema=False)
def metrics(_: Principal = Depends(need(Perm.READ_AUDIT, "*")), s: Session = Depends(db_session, scope="function")):
    """Prometheus scrape endpoint; authenticate with an auditor service-account key (X-API-Key)."""
    from fastapi.responses import PlainTextResponse

    from soc_platform.api.dashboards import prometheus

    return PlainTextResponse(prometheus(s, registry()), media_type="text/plain; version=0.0.4")


# ----------------------------------------------------------------------------- intelligence layer


def _intel(s: Session, gw: LLMGateway | None = None):
    from soc_platform.intelligence.analyst import IntelligenceService

    return IntelligenceService(s, gw if gw is not None else llm(s), vm=_services(s)["vulnerability"])


def _insight(i) -> dict[str, Any]:
    return {"id": i.id, "rule": i.rule, "title": i.title, "severity": i.severity, "score": i.score, "status": i.status,
            "domains": i.domains, "entity_ids": i.entity_ids, "evidence": i.evidence, "next_steps": i.next_steps,
            "narrative": i.narrative, "narrative_source": i.narrative_source, "requirements": i.requirement_refs,
            "first_seen": i.first_seen.isoformat(), "last_seen": i.last_seen.isoformat()}


@app.get("/api/v1/intelligence/insights")
def intel_insights(severity: str | None = None, status: str = "new,acknowledged", _: Principal = Depends(need(Perm.READ, "*")),
                   s: Session = Depends(db_session, scope="function")):
    from soc_platform.intelligence.models import Insight

    q = select(Insight).where(Insight.status.in_(status.split(","))).order_by(Insight.score.desc())
    if severity:
        q = q.where(Insight.severity.in_(severity.split(",")))
    return [_insight(i) for i in s.execute(q).scalars()]


@app.post("/api/v1/intelligence/refresh")
def intel_refresh(p: Principal = Depends(need(Perm.INVESTIGATE, "*")), s: Session = Depends(db_session, scope="function")):
    return {"insights": len(_intel(s).refresh())}


@app.post("/api/v1/intelligence/insights/{iid}/{verb}")
def intel_decide(iid: str, verb: str, p: Principal = Depends(need(Perm.INVESTIGATE, "*")), s: Session = Depends(db_session, scope="function")):
    from soc_platform.intelligence.models import Insight

    status = {"acknowledge": "acknowledged", "dismiss": "dismissed", "resolve": "resolved"}.get(verb)
    i = s.get(Insight, iid)
    if status is None or i is None:
        raise HTTPException(404, "unknown insight or verb")
    i.status, i.decided_by = status, p.id
    AuditLog(s).append(actor_type="human", actor_id=p.id, event_type=f"insight.{status}", subject_type="insight",
                       subject_id=iid, payload={"rule": i.rule, "title": i.title})
    return _insight(i)


@app.get("/api/v1/intelligence/risk/top")
def intel_top(kind: str | None = None, limit: int = Query(10, ge=1, le=500), _: Principal = Depends(need(Perm.READ, "*")),
              s: Session = Depends(db_session, scope="function")):
    from soc_platform.intelligence.risk import RiskEngine

    return [p.as_dict() for p in RiskEngine(s).top(kind, limit)]


@app.get("/api/v1/intelligence/entities/{eid}/risk")
def intel_entity_risk(eid: str, _: Principal = Depends(need(Perm.READ, "*")), s: Session = Depends(db_session, scope="function")):
    from soc_platform.intelligence.risk import RiskEngine

    p = RiskEngine(s).profile(eid)
    if p is None:
        raise HTTPException(404, "not a user/host entity")
    return p.as_dict()


class AskBody(BaseModel):
    question: str = Field(min_length=3, max_length=2000)


@app.post("/api/v1/intelligence/ask")
def intel_ask(body: AskBody, p: Principal = Depends(need(Perm.READ, "*")), s: Session = Depends(db_session, scope="function")):
    gw = llm(s, p)
    out = _with_notice(_intel(s, gw).analyst.ask(body.question), gw)
    AuditLog(s).append(actor_type="human", actor_id=p.id, event_type="intelligence.ask", subject_type="question",
                       subject_id="ask", payload={"question": body.question, "planner": out["planner"],
                                                  "tool_calls": out["tool_calls"]})
    return out


@app.get("/api/v1/intelligence/brief")
def intel_brief(_: Principal = Depends(need(Perm.READ, "*")), s: Session = Depends(db_session, scope="function")):
    return _intel(s).analyst.brief()
