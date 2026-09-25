"""Platform API: one service for phishing, incident and vulnerability workflows.

Run:  uvicorn soc_platform.api.app:app --host 0.0.0.0 --port 8080
Auth: Bearer token (Entra ID access token in prod; dev HS256 token from /api/v1/dev/token in dev).
Every state change goes through the policy-gated ActionService and lands in the audit log.
"""

from __future__ import annotations

from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterator

from fastapi import Depends, FastAPI, File, Header, HTTPException, Query, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from soc_platform import __version__
from soc_platform.config import Settings, get_settings
from soc_platform.connectors.base import SyncRunner
from soc_platform.connectors.registry import ConnectorRegistry
from soc_platform.core.actions import ActionService
from soc_platform.core.audit import AuditLog
from soc_platform.core.access import AccessService, kill_switch_on, permissions_matrix
from soc_platform.core.auth import AuthError, Perm, Principal, issue_dev_token, principal_from_token
from soc_platform.core.cases import CaseService, agreement_report, detection_quality
from soc_platform.core.context_store import ContextStore
from soc_platform.core.db import get_database
from soc_platform.core.entity_resolution import EntityResolver
from soc_platform.core.models import AccessLogRecord, ActionRequest, Case, Entity, PolicyVersion, UnresolvedItem
from soc_platform.core.policy import PolicyEngine, PolicyStore
from soc_platform.llm.gateway import LLMGateway

STATIC = Path(__file__).parent / "static"
_PROD = get_settings().environment == "prod"
app = FastAPI(title="CCI SOC AI & Automation Platform", version=__version__,
              docs_url=None if _PROD else "/docs", redoc_url=None, openapi_url=None if _PROD else "/openapi.json")
app.mount("/static", StaticFiles(directory=STATIC), name="static")

MAX_BODY_BYTES = 30 * 1024 * 1024
SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
                               "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; "
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
                self._b.clear()
            return ok


_limiter = _RateLimiter(float(__import__("os").environ.get("SOC_RATE_LIMIT_RPS", "20")),
                        int(__import__("os").environ.get("SOC_RATE_LIMIT_BURST", "120")))


_TRUSTED_PROXIES = {x.strip() for x in __import__("os").environ.get("SOC_TRUSTED_PROXIES", "").split(",") if x.strip()}


def _client_ip(request: Request) -> str:
    """Peer address; X-Forwarded-For is honoured only when the direct peer is a configured trusted proxy."""
    peer = request.client.host if request.client else "unknown"
    if peer in _TRUSTED_PROXIES:
        fwd = (request.headers.get("x-forwarded-for") or "").split(",")[0].strip()
        if fwd:
            return fwd
    return peer


class SecurityMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
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
        if request.url.scheme == "https":
            response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        return response


app.add_middleware(SecurityMiddleware)


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

        self.q: "queue.Queue[dict[str, Any]]" = queue.Queue(maxsize=100_000)
        self.dropped = 0
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None

    def put(self, row: dict[str, Any]) -> None:
        import queue
        import threading

        try:
            self.q.put_nowait(row)
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
            for attempt in range(20):
                try:
                    with get_database().session() as s:
                        s.add_all([AccessLogRecord(**r) for r in batch])
                    break
                except Exception:  # noqa: BLE001 - database busy/unavailable: back off, never crash
                    _t.sleep(min(2.0, 0.1 * (attempt + 1)))
            else:
                self.dropped += len(batch)

    def flush(self, timeout: float = 10.0) -> None:
        import time as _t

        end = _t.monotonic() + timeout
        while not self.q.empty() and _t.monotonic() < end:
            _t.sleep(0.05)
        _t.sleep(0.1)


ACCESS_LOG = _AccessLogWriter()


def _log_access(request: Request, status: int, latency_ms: float) -> None:
    ACCESS_LOG.put({"ts": __import__("datetime").datetime.now(__import__("datetime").timezone.utc),
                    "principal_id": getattr(request.state, "principal_id", None),
                    "auth_method": getattr(request.state, "auth_method", None),
                    "method": request.method[:8], "path": request.url.path[:512], "status": int(status),
                    "client_ip": request.client.host if request.client else None,
                    "user_agent": (request.headers.get("user-agent") or "")[:256], "latency_ms": round(latency_ms, 1)})


# ----------------------------------------------------------------------------- dependencies


@lru_cache(maxsize=1)
def registry() -> ConnectorRegistry:
    return ConnectorRegistry.from_file()


def db_session() -> Iterator[Session]:
    with get_database().session() as s:
        yield s


def current_user(request: Request, authorization: str | None = Header(default=None),
                 x_api_key: str | None = Header(default=None), x_break_glass: str | None = Header(default=None),
                 settings: Settings = Depends(get_settings), s: Session = Depends(db_session)) -> Principal:
    """Bearer token (Entra / dev), service-account API key, or sealed break-glass credential."""
    acc = AccessService(s, settings)
    client = request.client.host if request.client else "unknown"
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
    def dep(p: Principal = Depends(current_user)) -> Principal:
        if not p.can(perm):
            raise HTTPException(403, p.why_not(perm))
        if not p.in_domain(domain):
            raise HTTPException(403, "cross-domain data requires all-domain access" if domain == "*"
                                else f"not authorised for {domain} data")
        return p
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


def llm(s: Session) -> LLMGateway | None:
    st = get_settings()
    return LLMGateway(s, st) if st.llm_provider != "none" else None


def _services(s: Session):
    from soc_platform.domains.incident.service import IncidentService
    from soc_platform.domains.phishing.service import PhishingService
    from soc_platform.domains.vulnerability.service import VulnerabilityService

    reg, pol, gw = registry(), policy_engine(s), llm(s)
    acts = reg.action_registry()
    st = get_settings()
    org = [d.strip() for d in (__import__("os").environ.get("SOC_ORG_DOMAINS", "")).split(",") if d.strip()]
    return {"incident": IncidentService(s, reg, policy=pol, llm=gw, actions=acts),
            "vulnerability": VulnerabilityService(s, reg, policy=pol, llm=gw, actions=acts),
            "phishing": PhishingService(s, reg, policy=pol, llm=gw, actions=acts, org_domains=org,
                                        use_engine=__import__("os").environ.get("SOC_PHISHING_ENGINE", "0") == "1",
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
    return HTTPException(400, str(exc))


# ----------------------------------------------------------------------------- system


_CHAIN_CACHE: dict[str, Any] = {"at": 0.0, "ok": None}


@app.get("/health")
def health(s: Session = Depends(db_session)) -> dict[str, Any]:
    now = __import__("time").monotonic()
    if now - _CHAIN_CACHE["at"] > 300:  # full verification at most every 5 min; /api/v1/audit/verify is on demand
        _CHAIN_CACHE.update(at=now, ok=AuditLog(s).verify()["ok"])
    return {"status": "ok", "version": __version__, "audit_chain": _CHAIN_CACHE["ok"],
            "connectors_enabled": len(registry().enabled_names()), "kill_switch": kill_switch_on(s, get_settings())}


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def ui() -> HTMLResponse:
    return HTMLResponse((STATIC / "index.html").read_text(encoding="utf-8"))


@app.get("/api/v1/dev/token")
def dev_token(request: Request, user: str = "analyst@cci-demo.com", roles: str = "analyst", mfa: bool = True,
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
            "mfa": p.mfa, "auth_method": p.auth_method, "service_account": p.is_service, "break_glass": p.break_glass}


# ----------------------------------------------------------------------------- connectors


@app.get("/api/v1/connectors")
def connectors(_: Principal = Depends(need(Perm.READ))) -> list[dict[str, Any]]:
    return registry().status()


@app.post("/api/v1/connectors/{name}/sync")
def connector_sync(name: str, stream: str, full: bool = False, p: Principal = Depends(need(Perm.MANAGE_CONNECTORS)),
                   s: Session = Depends(db_session)) -> dict[str, Any]:
    try:
        conn = registry().get(name)
    except KeyError:
        raise HTTPException(404, "unknown connector") from None
    if stream not in conn.streams:
        raise HTTPException(400, f"unknown stream; available: {list(conn.streams)}")
    rep = SyncRunner(s, ContextStore(s)).sync(conn, stream, full_backfill=full)
    AuditLog(s).append(actor_type="human", actor_id=p.id, event_type="connector.sync", subject_type="connector",
                       subject_id=name, payload={"stream": stream, "ingested": rep.ingested, "failed": rep.failed})
    return rep.__dict__ | {"reconciled": rep.reconciled}


@app.post("/api/v1/connectors/{name}/test")
def connector_test(name: str, p: Principal = Depends(need(Perm.MANAGE_CONNECTORS)),
                   s: Session = Depends(db_session)) -> dict[str, Any]:
    """Authenticate against the tool and read one page (NFR-13): proves credentials, scopes and reachability."""
    try:
        conn = registry().get(name)
    except KeyError:
        raise HTTPException(404, "unknown connector") from None
    res = conn.health()
    AuditLog(s).append(actor_type="human", actor_id=p.id, event_type="connector.test", subject_type="connector",
                       subject_id=name, payload={"ok": res.get("ok"), "error": res.get("error")})
    return {"connector": name} | res


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
def admin_roles(all: bool = False, _: Principal = Depends(need(Perm.MANAGE_ACCESS)), s: Session = Depends(db_session)):
    return _access(s).list_grants(include_inactive=all)


@app.post("/api/v1/admin/roles")
def admin_grant(body: GrantBody, p: Principal = Depends(need(Perm.MANAGE_ACCESS)), s: Session = Depends(db_session)):
    try:
        g = _access(s).grant(p, body.principal_id, body.role, domains=body.domains, days=body.days, reason=body.reason)
    except Exception as exc:
        raise _err(exc) from exc
    return {"id": g.id, "principal_id": g.principal_id, "role": g.role, "domains": g.domains}


@app.delete("/api/v1/admin/roles/{gid}")
def admin_revoke(gid: str, reason: str = "", p: Principal = Depends(need(Perm.MANAGE_ACCESS)),
                 s: Session = Depends(db_session)):
    try:
        g = _access(s).revoke_grant(p, gid, reason)
    except Exception as exc:
        raise _err(exc) from exc
    return {"id": g.id, "revoked": True}


@app.get("/api/v1/admin/api-keys")
def admin_keys(_: Principal = Depends(need(Perm.MANAGE_ACCESS)), s: Session = Depends(db_session)):
    return _access(s).list_api_keys()


@app.post("/api/v1/admin/api-keys")
def admin_key_create(body: ApiKeyBody, p: Principal = Depends(need(Perm.MANAGE_ACCESS)), s: Session = Depends(db_session)):
    try:
        key, secret = _access(s).create_api_key(p, body.name, body.roles, domains=body.domains, days=body.days)
    except Exception as exc:
        raise _err(exc) from exc
    return {"id": key.id, "name": key.name, "roles": key.roles, "domains": key.domains,
            "expires_at": key.expires_at.isoformat(), "api_key": secret,
            "note": "Shown once. Store it in the calling system's vault; send it as the X-API-Key header."}


@app.delete("/api/v1/admin/api-keys/{kid}")
def admin_key_revoke(kid: str, p: Principal = Depends(need(Perm.MANAGE_ACCESS)), s: Session = Depends(db_session)):
    try:
        _access(s).revoke_api_key(p, kid)
    except Exception as exc:
        raise _err(exc) from exc
    return {"id": kid, "revoked": True}


@app.post("/api/v1/admin/revoke-sessions")
def admin_revoke_sessions(body: RevokeBody, p: Principal = Depends(need(Perm.MANAGE_ACCESS)),
                          s: Session = Depends(db_session)):
    _access(s).revoke_sessions(p, body.principal_id, body.reason)
    return {"principal_id": body.principal_id, "sessions_revoked": True}


@app.post("/api/v1/auth/logout")
def logout(p: Principal = Depends(current_user), s: Session = Depends(db_session)) -> dict[str, Any]:
    """Revoke the presented token (its jti) server-side."""
    if p.is_service or p.break_glass or not p.token_id:
        raise HTTPException(400, "only bearer tokens with a jti can be revoked this way")
    _access(s).revoke_token(p, p.token_id)
    return {"revoked": True}


@app.get("/api/v1/admin/access-log")
def admin_access_log(principal_id: str | None = None, status_min: int = 0, limit: int = Query(200, le=2000),
                     _: Principal = Depends(need(Perm.READ_AUDIT)), s: Session = Depends(db_session)):
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
                    s: Session = Depends(db_session)) -> dict[str, Any]:
    from soc_platform.core.retention import run_retention

    return run_retention(s, get_settings(), actor=p.id, dry_run=dry_run)


@app.get("/api/v1/audit/export")
def audit_export(since_seq: int = 0, p: Principal = Depends(need(Perm.EXPORT_EVIDENCE)), s: Session = Depends(db_session)):
    """JSON Lines export of the hash-chained audit log for external archiving / SIEM (NFR-04)."""
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
                  s: Session = Depends(db_session)) -> dict[str, int]:
    """Push endpoint for any SIEM/SOAR (IM-T02 webhook ingestion; duplicates suppressed on replay)."""
    reg = registry()
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
def get_policy(_: Principal = Depends(need(Perm.READ)), s: Session = Depends(db_session)) -> dict[str, Any]:
    ps = PolicyStore(s)
    return {"active_version": ps.active_version(), "document": ps.active(),
            "proposals": [{"id": v.id, "proposed_by": v.proposed_by, "status": v.status, "note": v.note}
                          for v in s.execute(select(PolicyVersion).where(PolicyVersion.status == "proposed")).scalars()]}


class PolicyProposal(BaseModel):
    document: dict[str, Any]
    note: str = ""


@app.post("/api/v1/policy/proposals")
def propose_policy(body: PolicyProposal, p: Principal = Depends(current_user), s: Session = Depends(db_session)):
    try:
        v = PolicyStore(s).propose(body.document, p, body.note)
    except Exception as exc:
        raise _err(exc) from exc
    return {"id": v.id, "status": v.status}


@app.post("/api/v1/policy/proposals/{vid}/approve")
def approve_policy(vid: int, p: Principal = Depends(current_user), s: Session = Depends(db_session)):
    try:
        v = PolicyStore(s).approve(vid, p)
    except Exception as exc:
        raise _err(exc) from exc
    return {"id": v.id, "status": v.status}


@app.post("/api/v1/kill-switch")
def kill_switch(on: bool, p: Principal = Depends(need(Perm.KILL_SWITCH)), s: Session = Depends(db_session)):
    """Durable (DB-backed) so every API replica and the scheduler stop together, and it survives restarts."""
    AccessService(s, get_settings()).set_flag(p, "kill_switch", bool(on), perm=Perm.KILL_SWITCH)
    AuditLog(s).append(actor_type="human", actor_id=p.id, event_type="policy.kill_switch", subject_type="policy",
                       subject_id="kill_switch", payload={"on": on})
    return {"kill_switch": kill_switch_on(s, get_settings())}


# ----------------------------------------------------------------------------- actions / approvals


@app.get("/api/v1/actions/catalog")
def action_catalog(_: Principal = Depends(need(Perm.READ)), s: Session = Depends(db_session)):
    pol = policy_engine(s)
    return [{**a, "level": int(pol.view(a["action_type"]).level)} for a in registry().action_registry().catalog()]


@app.get("/api/v1/actions")
def list_actions(status: str | None = None, case_id: str | None = None, p: Principal = Depends(need(Perm.READ)),
                 s: Session = Depends(db_session)):
    q = select(ActionRequest).order_by(ActionRequest.created_at.desc()).limit(500)
    if status:
        q = q.where(ActionRequest.status.in_(status.split(",")))
    if case_id:
        _case_in_scope(s, p, case_id)
        q = q.where(ActionRequest.case_id == case_id)
    if "*" not in p.domains:
        q = q.where(ActionRequest.domain.in_(sorted(p.domains)))  # "platform" actions are cross-domain
    return [_action(a) for a in s.execute(q).scalars()]


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
def request_action(body: ActionBody, p: Principal = Depends(current_user), s: Session = Depends(db_session)):
    _case_in_scope(s, p, body.case_id)
    if body.case_id is None and "*" not in p.domains:
        raise HTTPException(403, "actions outside a case require all-domain access")
    try:
        return _action(_action_service(s).request(body.action_type, params=body.params, targets=body.targets,
                                                  requested_by=p, case_id=body.case_id, rationale=body.rationale))
    except Exception as exc:
        raise _err(exc) from exc


@app.post("/api/v1/actions/{aid}/{verb}")
def decide_action(aid: str, verb: str, body: Decision, p: Principal = Depends(current_user),
                  s: Session = Depends(db_session)):
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
def audit(subject_id: str | None = None, actor_id: str | None = None, event_type: str | None = None, limit: int = 200,
          _: Principal = Depends(need(Perm.READ_AUDIT)), s: Session = Depends(db_session)):
    log = AuditLog(s)
    return AuditLog.export(log.query(subject_id=subject_id, actor_id=actor_id, event_type=event_type, limit=limit))


@app.get("/api/v1/audit/verify")
def audit_verify(_: Principal = Depends(need(Perm.READ_AUDIT)), s: Session = Depends(db_session)):
    return AuditLog(s).verify()


# ----------------------------------------------------------------------------- entities & resolution


@app.get("/api/v1/entities/find")
def find_entity(kind: str, key: str, value: str, _: Principal = Depends(need(Perm.READ, "*")), s: Session = Depends(db_session)):
    st = ContextStore(s)
    e = st.find(kind, key, value)
    if e is None:
        raise HTTPException(404, "not found")
    return _entity(st, e)


@app.get("/api/v1/entities/{eid}")
def get_entity(eid: str, _: Principal = Depends(need(Perm.READ, "*")), s: Session = Depends(db_session)):
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
def unresolved(_: Principal = Depends(need(Perm.READ, "*")), s: Session = Depends(db_session)):
    return [{"id": u.id, "kind": u.kind, "reason": u.reason, "candidates": u.candidates, "source_record": u.source_record_id}
            for u in s.execute(select(UnresolvedItem).where(UnresolvedItem.status == "open")).scalars()]


class Override(BaseModel):
    entity_id: str | None = None
    reason: str = ""


@app.post("/api/v1/resolution/{uid}/override")
def resolution_override(uid: str, body: Override, p: Principal = Depends(need(Perm.RESOLVE_ENTITIES, "*")), s: Session = Depends(db_session)):
    try:
        rec = EntityResolver(s).override(uid, body.entity_id, p, body.reason)
    except Exception as exc:
        raise _err(exc) from exc
    return {"source_record": rec.id, "entity_id": rec.entity_id}


@app.get("/api/v1/resolution/match-rate")
def match_rate(kind: str = "asset", _: Principal = Depends(need(Perm.READ, "*")), s: Session = Depends(db_session)):
    return EntityResolver(s).match_rate(kind)


# ----------------------------------------------------------------------------- cases (shared)


@app.get("/api/v1/cases")
def list_cases(domain: str | None = None, status: str | None = None, p: Principal = Depends(need(Perm.READ)),
               s: Session = Depends(db_session)):
    q = select(Case).order_by(Case.created_at.desc()).limit(500)
    if domain:
        q = q.where(Case.domain == domain)
    if "*" not in p.domains:
        q = q.where(Case.domain.in_(sorted(p.domains)))
    if status:
        q = q.where(Case.status.in_(status.split(",")))
    return [{"id": c.id, "domain": c.domain, "title": c.title, "status": c.status, "severity": c.severity,
             "verdict": c.verdict, "confidence": c.confidence, "created_at": c.created_at.isoformat()}
            for c in s.execute(q).scalars()]


@app.get("/api/v1/cases/{cid}")
def get_case(cid: str, p: Principal = Depends(need(Perm.READ)), s: Session = Depends(db_session)):
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
def case_disposition(cid: str, body: DispositionBody, p: Principal = Depends(current_user), s: Session = Depends(db_session)):
    case = _case_in_scope(s, p, cid)
    try:
        if case.domain == "phishing":
            return _services(s)["phishing"].confirm(cid, p, verdict=body.verdict, reasoning=body.reasoning)
        d = CaseService(s).decide(cid, p, verdict=body.verdict, reasoning=body.reasoning, close=body.close)
        return {"disposition": d.analyst_verdict}
    except Exception as exc:
        raise _err(exc) from exc


@app.get("/api/v1/cases/{cid}/report")
def case_report(cid: str, p: Principal = Depends(need(Perm.READ)), s: Session = Depends(db_session)):
    _case_in_scope(s, p, cid)
    from soc_platform.reporting.reports import ReportService

    run = ReportService(s, get_settings().report_output_dir, llm=llm(s)).investigation_report(CaseService(s).view(cid), by=p.id)
    return _protected_file(run.path)


class BundleBody(BaseModel):
    action_ids: list[str] = Field(min_length=1, max_length=50)
    note: str = ""


@app.get("/api/v1/cases/{cid}/story")
def case_story(cid: str, p: Principal = Depends(need(Perm.READ)), s: Session = Depends(db_session)):
    """Attack Story: cross-tool attack chain, gaps, benign explanations, blast radius, response plan."""
    from soc_platform.intelligence.story import story_for_case

    _case_in_scope(s, p, cid)
    story = story_for_case(s, cid, registry())
    if "*" not in p.domains:  # related cases from other domains are summarised, not exposed
        story["generated_from"] = [c for c in story["generated_from"] if p.in_domain((s.get(Case, c) or Case()).domain)]
    story["deep_analysis"] = ((s.get(Case, cid).assessment or {}).get("deep_analysis"))
    return story


@app.post("/api/v1/cases/{cid}/story/approve")
def story_approve(cid: str, body: BundleBody, p: Principal = Depends(need(Perm.APPROVE_ACTION)), s: Session = Depends(db_session)):
    """Approve several response-plan actions at once. Each goes through the normal policy / four-eyes checks."""
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
                  s: Session = Depends(db_session)):
    """Evidence-bound LLM review of the attack story (requires an approved LLM endpoint)."""
    from soc_platform.intelligence.deep_analysis import run_deep_analysis
    from soc_platform.intelligence.story import story_for_case

    _case_in_scope(s, p, cid)
    story = story_for_case(s, cid, registry())
    return run_deep_analysis(s, story, llm(s), actor=p.id, force=bool(body and body.force),
                             org_domains=get_settings().org_domains)


@app.get("/api/v1/llm/status")
def llm_status(_: Principal = Depends(need(Perm.READ)), s: Session = Depends(db_session)):
    st = get_settings()
    return {"configured": st.llm_provider != "none", "provider": st.llm_provider,
            "model_pinned": st.llm_model_version, "redaction": st.llm_redact_pii,
            "budget": LLMGateway(s, st).budget_status() if st.llm_provider != "none" else None}


@app.get("/api/v1/metrics/shadow")
def shadow(domain: str, p: Principal = Depends(need(Perm.READ)), s: Session = Depends(db_session)):
    if not p.in_domain(domain):
        raise HTTPException(403, f"not authorised for {domain} data")
    return {"agreement": agreement_report(s, domain), "detection_quality": detection_quality(s, domain, min_count=2)}


@app.get("/api/v1/metrics/drift")
def drift(recent_days: int = Query(7, ge=1, le=90), baseline_days: int = Query(28, ge=7, le=365),
          _: Principal = Depends(need(Perm.READ)), s: Session = Depends(db_session)):
    """Verdict-quality drift per domain (R14, NFR-13)."""
    from soc_platform.intelligence.drift import drift_report

    return drift_report(s, recent_days=recent_days, baseline_days=baseline_days)


@app.get("/api/v1/llm/budget")
def llm_budget(_: Principal = Depends(need(Perm.READ)), s: Session = Depends(db_session)):
    return LLMGateway(s, get_settings()).budget_status()


# ----------------------------------------------------------------------------- phishing


@app.post("/api/v1/phishing/ingest")
def phishing_ingest(process: bool = True, p: Principal = Depends(need(Perm.INVESTIGATE, "phishing")), s: Session = Depends(db_session)):
    svc = _services(s)["phishing"]
    subs = svc.ingest_reported()
    out = []
    for sub in subs:
        if process and sub.status == "new":
            out.append(svc.process(sub.id)["case"])
    if out:
        _intel(s).refresh()
    return {"submissions": [x.id for x in subs], "processed": out}


@app.post("/api/v1/phishing/submit")
async def phishing_submit(file: UploadFile = File(...), reporter: str | None = None, process: bool = True,
                          p: Principal = Depends(need(Perm.INVESTIGATE, "phishing")), s: Session = Depends(db_session)):
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
                       s: Session = Depends(db_session)):
    """Third-party / vendor email risk (U18)."""
    from soc_platform.domains.phishing.supplier import SupplierMonitor

    return SupplierMonitor(s).assess(days=days)


@app.get("/api/v1/phishing/metrics")
def phishing_metrics(_: Principal = Depends(need(Perm.READ, "phishing")), s: Session = Depends(db_session)):
    return _services(s)["phishing"].metrics()


# ----------------------------------------------------------------------------- incident


@app.post("/api/v1/incidents/run")
def incidents_run(investigate: bool = True, p: Principal = Depends(need(Perm.INVESTIGATE, "incident")), s: Session = Depends(db_session)):
    svc = _services(s)["incident"]
    ing = svc.ingest()
    cases = svc.cluster()
    done = [svc.investigate(c.id)["case"] for c in cases if investigate and c.status != "closed"]
    _intel(s).refresh()
    return {"ingested": ing.synced, "errors": ing.errors, "new_incidents": len(cases), "investigated": done}


@app.post("/api/v1/incidents/{cid}/investigate")
def incident_investigate(cid: str, p: Principal = Depends(need(Perm.INVESTIGATE, "incident")), s: Session = Depends(db_session)):
    return _services(s)["incident"].investigate(cid)


@app.get("/api/v1/incidents/handover")
def incident_handover(hours: int = 12, _: Principal = Depends(need(Perm.READ, "incident")), s: Session = Depends(db_session)):
    return _services(s)["incident"].handover(hours=hours)


# ----------------------------------------------------------------------------- vulnerability


@app.post("/api/v1/vm/refresh")
def vm_refresh(p: Principal = Depends(need(Perm.INVESTIGATE, "vulnerability")), s: Session = Depends(db_session)):
    out = _services(s)["vulnerability"].refresh()
    out["misconfigurations"] = _misconfig(s).refresh()
    _intel(s).refresh()
    return out


def _misconfig(s: Session):
    from soc_platform.domains.vulnerability.misconfig import MisconfigurationService

    return MisconfigurationService(s, registry(), policy=policy_engine(s))


@app.get("/api/v1/vm/metrics")
def vm_metrics(_: Principal = Depends(need(Perm.READ, "vulnerability")), s: Session = Depends(db_session)):
    return _services(s)["vulnerability"].metrics()


@app.get("/api/v1/vm/findings")
def vm_findings(priority: str | None = None, status: str = "open,reopened", _: Principal = Depends(need(Perm.READ, "vulnerability")),
                s: Session = Depends(db_session)):
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
def vm_affected(cve: str, _: Principal = Depends(need(Perm.READ, "vulnerability")), s: Session = Depends(db_session)):
    return _services(s)["vulnerability"].affected_devices(cve.upper())


class CampaignBody(BaseModel):
    cve: str
    notify_via: str = "email"
    team_contacts: dict[str, str] = Field(default_factory=dict)


@app.post("/api/v1/vm/campaigns")
def vm_campaign(body: CampaignBody, p: Principal = Depends(need(Perm.READ, "vulnerability")), s: Session = Depends(db_session)):
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
def vm_ack(pid: str, body: AckBody, p: Principal = Depends(need(Perm.READ, "vulnerability")), s: Session = Depends(db_session)):
    plan = _services(s)["vulnerability"].acknowledge(pid, p, committed_date=body.committed_date, owner=body.owner,
                                                     dependencies=body.dependencies, response=body.response)
    return {"plan_id": plan.id, "status": plan.status}


@app.post("/api/v1/vm/follow-up")
def vm_follow(p: Principal = Depends(need(Perm.INVESTIGATE, "vulnerability")), s: Session = Depends(db_session)):
    return _services(s)["vulnerability"].follow_up()


@app.post("/api/v1/vm/campaigns/{cid}/validate")
def vm_validate(cid: str, p: Principal = Depends(need(Perm.INVESTIGATE, "vulnerability")), s: Session = Depends(db_session)):
    return _services(s)["vulnerability"].validate_campaign(cid)


class ExceptionBody(BaseModel):
    finding_id: str
    justification: str
    compensating_control: str = ""
    days: int = 90


@app.post("/api/v1/vm/exceptions")
def vm_exception(body: ExceptionBody, p: Principal = Depends(need(Perm.READ, "vulnerability")), s: Session = Depends(db_session)):
    ex = _services(s)["vulnerability"].request_exception(body.finding_id, p, justification=body.justification,
                                                         compensating_control=body.compensating_control, days=body.days)
    return {"exception_id": ex.id, "status": ex.status}


@app.post("/api/v1/vm/exceptions/{eid}/decision")
def vm_exception_decision(eid: str, approve: bool, p: Principal = Depends(need(Perm.READ, "vulnerability")), s: Session = Depends(db_session)):
    try:
        ex = _services(s)["vulnerability"].decide_exception(eid, p, approve=approve)
    except Exception as exc:
        raise _err(exc) from exc
    return {"exception_id": ex.id, "status": ex.status}


@app.post("/api/v1/vm/risk-register/propose")
def vm_rr(p: Principal = Depends(need(Perm.INVESTIGATE, "vulnerability")), s: Session = Depends(db_session)):
    return [{"id": e.id, "cve": e.cve, "rating": e.rating, "risk_statement": e.risk_statement, "status": e.status}
            for e in _services(s)["vulnerability"].propose_risk_register()]


@app.post("/api/v1/vm/risk-register/{eid}/decision")
def vm_rr_decide(eid: str, approve: bool, p: Principal = Depends(need(Perm.READ, "vulnerability")), s: Session = Depends(db_session)):
    try:
        e = _services(s)["vulnerability"].decide_risk_entry(eid, p, approve=approve)
    except Exception as exc:
        raise _err(exc) from exc
    return {"id": e.id, "status": e.status}


class QueryBody(BaseModel):
    question: str


@app.post("/api/v1/vm/query")
def vm_query(body: QueryBody, _: Principal = Depends(need(Perm.READ, "vulnerability")), s: Session = Depends(db_session)):
    return _services(s)["vulnerability"].query(body.question)


@app.get("/api/v1/vm/new-kev")
def vm_new_kev(since: str = Query(..., description="YYYY-MM-DD"), _: Principal = Depends(need(Perm.READ, "vulnerability")),
               s: Session = Depends(db_session)):
    return _services(s)["vulnerability"].new_cve_assessment(since=since)


@app.get("/api/v1/vm/coverage")
def vm_coverage(_: Principal = Depends(need(Perm.READ, "vulnerability")), s: Session = Depends(db_session)):
    return _services(s)["vulnerability"].coverage()


@app.get("/api/v1/jobs")
def job_history(job: str | None = None, limit: int = Query(100, le=1000), _: Principal = Depends(need(Perm.READ)),
                s: Session = Depends(db_session)):
    """Scheduled job runs, retries and dead letters (VM-T11)."""
    from soc_platform import jobs

    return {"jobs": {n: {"interval_env": e, "default_seconds": d} for n, (e, d) in jobs.JOBS.items()},
            "runs": jobs.history(s, job=job, limit=limit)}


@app.post("/api/v1/jobs/{name}/run")
def job_replay(name: str, p: Principal = Depends(need(Perm.MANAGE_CONNECTORS)), s: Session = Depends(db_session)):
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
def vm_ticket_sync(_: Principal = Depends(need(Perm.INVESTIGATE, "vulnerability")), s: Session = Depends(db_session)):
    """Pull ticket state from ITSM; resolved tickets trigger closure validation (VM-T10, VM-F10)."""
    return _services(s)["vulnerability"].sync_tickets()


@app.get("/api/v1/vm/misconfigurations")
def vm_misconfigs(status: str | None = None, _: Principal = Depends(need(Perm.READ, "vulnerability")),
                  s: Session = Depends(db_session)):
    svc = _misconfig(s)
    return {"metrics": svc.metrics(), "items": svc.list(status)}


@app.post("/api/v1/vm/misconfigurations/route")
def vm_misconfig_route(p: Principal = Depends(need(Perm.REQUEST_ACTION, "vulnerability")), s: Session = Depends(db_session)):
    try:
        return _misconfig(s).route(p)
    except Exception as exc:
        raise _err(exc) from exc


@app.post("/api/v1/vm/misconfigurations/{mid}/{verb}")
def vm_misconfig_verb(mid: str, verb: str, note: str = "", p: Principal = Depends(need(Perm.INVESTIGATE, "vulnerability")),
                      s: Session = Depends(db_session)):
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
    if kind == "compliance" and not p.can(Perm.EXPORT_EVIDENCE):
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
def report_templates(_: Principal = Depends(need(Perm.READ)), s: Session = Depends(db_session)):
    """Standard and saved report specifications, plus the data-source catalogue they may use."""
    from soc_platform.reporting.builder import catalogue, list_templates

    return {"templates": list_templates(s), "sources": catalogue()}


@app.post("/api/v1/reports/plan")
def report_plan(body: PlanBody, p: Principal = Depends(need(Perm.READ)), s: Session = Depends(db_session)):
    """Turn a report described in words into a spec (catalogue sources only) for review before generating."""
    from soc_platform.reporting.builder import plan_report

    spec = plan_report(body.request, llm(s))
    AuditLog(s).append(actor_type=p.actor_type, actor_id=p.id, event_type="report.planned", subject_type="report",
                       subject_id="plan", payload={"planner": spec["planner"], "sections": [x["source"] for x in spec["sections"]]})
    return spec


@app.post("/api/v1/reports/templates")
def save_report_template(body: SaveTemplateBody, p: Principal = Depends(need(Perm.READ)), s: Session = Depends(db_session)):
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
def build_custom_report(body: BuildBody, p: Principal = Depends(need(Perm.READ)), s: Session = Depends(db_session)):
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
    denied = frozenset() if p.can(Perm.EXPORT_EVIDENCE) else frozenset({"compliance"})
    r = build_report(s, registry(), spec, get_settings().report_output_dir, llm=llm(s), by=p.id,
                     domains=frozenset(p.domains), case_id=body.case_id, denied_sources=denied)
    return r


@app.post("/api/v1/reports/{kind}")
def make_report(kind: str, period_days: int = Query(90, ge=1, le=730), p: Principal = Depends(need(Perm.READ)),
                s: Session = Depends(db_session)):
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
def download_report(rid: str, p: Principal = Depends(need(Perm.READ)), s: Session = Depends(db_session)):
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
                  s: Session = Depends(db_session)):
    from soc_platform.api.dashboards import overview

    return overview(s, p.domains, days=days)


@app.get("/api/v1/dashboard/connectors")
def dash_connectors(_: Principal = Depends(need(Perm.READ)), s: Session = Depends(db_session)):
    from soc_platform.api.dashboards import connector_freshness

    return connector_freshness(s, registry())


@app.get("/api/v1/dashboard/attack-coverage")
def dash_attack(_: Principal = Depends(need(Perm.READ)), s: Session = Depends(db_session)):
    from soc_platform.intelligence.attack_coverage import coverage

    return coverage(s, registry().enabled_names())


@app.get("/api/v1/dashboard/shadow-it")
def dash_shadow_it(since: str = Query("-7days", pattern=r"^-\d{1,3}(days|hours)$"),
                   _: Principal = Depends(need(Perm.READ, "incident"))):
    from soc_platform.intelligence.shadow_it import shadow_it_report

    return shadow_it_report(registry(), since=since)


@app.get("/api/v1/entities/{eid}/360")
def entity360(eid: str, p: Principal = Depends(need(Perm.READ)), s: Session = Depends(db_session)):
    from soc_platform.api.dashboards import entity_360

    out = entity_360(s, eid)
    if out is None:
        raise HTTPException(404, "not found")
    if "*" not in p.domains:
        out["cases"] = [c for c in out["cases"] if p.in_domain(c["domain"])]
        out["insights"] = []   # correlated findings are cross-domain
        out["risk"] = None     # fused risk mixes every domain
        out["timeline"], out["related"], out["per_tool"], out["activity_by_tool"] = [], {}, {}, {}
    return out


@app.get("/metrics", include_in_schema=False)
def metrics(_: Principal = Depends(need(Perm.READ_AUDIT)), s: Session = Depends(db_session)):
    """Prometheus scrape endpoint; authenticate with an auditor service-account key (X-API-Key)."""
    from fastapi.responses import PlainTextResponse

    from soc_platform.api.dashboards import prometheus

    return PlainTextResponse(prometheus(s, registry()), media_type="text/plain; version=0.0.4")


# ----------------------------------------------------------------------------- intelligence layer


def _intel(s: Session):
    from soc_platform.intelligence.analyst import IntelligenceService

    return IntelligenceService(s, llm(s), vm=_services(s)["vulnerability"])


def _insight(i) -> dict[str, Any]:
    return {"id": i.id, "rule": i.rule, "title": i.title, "severity": i.severity, "score": i.score, "status": i.status,
            "domains": i.domains, "entity_ids": i.entity_ids, "evidence": i.evidence, "next_steps": i.next_steps,
            "narrative": i.narrative, "narrative_source": i.narrative_source, "requirements": i.requirement_refs,
            "first_seen": i.first_seen.isoformat(), "last_seen": i.last_seen.isoformat()}


@app.get("/api/v1/intelligence/insights")
def intel_insights(severity: str | None = None, status: str = "new,acknowledged", _: Principal = Depends(need(Perm.READ, "*")),
                   s: Session = Depends(db_session)):
    from soc_platform.intelligence.models import Insight

    q = select(Insight).where(Insight.status.in_(status.split(","))).order_by(Insight.score.desc())
    if severity:
        q = q.where(Insight.severity.in_(severity.split(",")))
    return [_insight(i) for i in s.execute(q).scalars()]


@app.post("/api/v1/intelligence/refresh")
def intel_refresh(p: Principal = Depends(need(Perm.INVESTIGATE, "*")), s: Session = Depends(db_session)):
    return {"insights": len(_intel(s).refresh())}


@app.post("/api/v1/intelligence/insights/{iid}/{verb}")
def intel_decide(iid: str, verb: str, p: Principal = Depends(need(Perm.INVESTIGATE, "*")), s: Session = Depends(db_session)):
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
def intel_top(kind: str | None = None, limit: int = 10, _: Principal = Depends(need(Perm.READ, "*")),
              s: Session = Depends(db_session)):
    from soc_platform.intelligence.risk import RiskEngine

    return [p.as_dict() for p in RiskEngine(s).top(kind, limit)]


@app.get("/api/v1/intelligence/entities/{eid}/risk")
def intel_entity_risk(eid: str, _: Principal = Depends(need(Perm.READ, "*")), s: Session = Depends(db_session)):
    from soc_platform.intelligence.risk import RiskEngine

    p = RiskEngine(s).profile(eid)
    if p is None:
        raise HTTPException(404, "not a user/host entity")
    return p.as_dict()


class AskBody(BaseModel):
    question: str = Field(min_length=3, max_length=2000)


@app.post("/api/v1/intelligence/ask")
def intel_ask(body: AskBody, p: Principal = Depends(need(Perm.READ, "*")), s: Session = Depends(db_session)):
    out = _intel(s).analyst.ask(body.question)
    AuditLog(s).append(actor_type="human", actor_id=p.id, event_type="intelligence.ask", subject_type="question",
                       subject_id="ask", payload={"question": body.question, "planner": out["planner"],
                                                  "tool_calls": out["tool_calls"]})
    return out


@app.get("/api/v1/intelligence/brief")
def intel_brief(_: Principal = Depends(need(Perm.READ, "*")), s: Session = Depends(db_session)):
    return _intel(s).analyst.brief()
