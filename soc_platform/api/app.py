"""Platform API: one service for phishing, incident and vulnerability workflows.

Run:  uvicorn soc_platform.api.app:app --host 0.0.0.0 --port 8080
Auth: Bearer token (Entra ID access token in prod; dev HS256 token from /api/v1/dev/token in dev).
Every state change goes through the policy-gated ActionService and lands in the audit log.
"""

from __future__ import annotations

import copy
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterator

from fastapi import Depends, FastAPI, File, Header, HTTPException, Query, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
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
from soc_platform.core.auth import AuthError, Perm, Principal, Role, issue_dev_token, principal_from_token
from soc_platform.core.cases import CaseService, agreement_report, detection_quality
from soc_platform.core.context_store import ContextStore
from soc_platform.core.db import Database, get_database
from soc_platform.core.entity_resolution import EntityResolver
from soc_platform.core.models import ActionRequest, Case, Entity, PolicyVersion, UnresolvedItem
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


class SecurityMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        cl = request.headers.get("content-length")
        if cl and cl.isdigit() and int(cl) > MAX_BODY_BYTES:
            return JSONResponse({"detail": "request too large"}, status_code=413)
        client = request.headers.get("authorization", "")[-24:] or (request.client.host if request.client else "anon")
        if not _limiter.allow(client):
            return JSONResponse({"detail": "rate limit exceeded"}, status_code=429, headers={"Retry-After": "5"})
        response = await call_next(request)
        for k, v in SECURITY_HEADERS.items():
            response.headers.setdefault(k, v)
        if request.url.scheme == "https":
            response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        return response


app.add_middleware(SecurityMiddleware)


# ----------------------------------------------------------------------------- dependencies


@lru_cache(maxsize=1)
def registry() -> ConnectorRegistry:
    return ConnectorRegistry.from_file()


def db_session() -> Iterator[Session]:
    with get_database().session() as s:
        yield s


def current_user(authorization: str | None = Header(default=None), settings: Settings = Depends(get_settings)) -> Principal:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "bearer token required")
    try:
        return principal_from_token(authorization.split(" ", 1)[1], settings)
    except AuthError as exc:
        raise HTTPException(401, str(exc)) from exc


def need(perm: Perm):
    def dep(p: Principal = Depends(current_user)) -> Principal:
        if not p.can(perm):
            raise HTTPException(403, f"{perm.value} permission required")
        return p
    return dep


def policy_engine(s: Session) -> PolicyEngine:
    return PolicyEngine(PolicyStore(s).active(), kill_switch=get_settings().kill_switch or _KILL["on"])


def llm(s: Session) -> LLMGateway | None:
    st = get_settings()
    return LLMGateway(s, st) if st.llm_provider != "none" else None


_KILL = {"on": False}


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


def _err(exc: Exception) -> HTTPException:
    if isinstance(exc, PermissionError):
        return HTTPException(403, str(exc))
    if isinstance(exc, KeyError):
        return HTTPException(404, str(exc))
    return HTTPException(400, str(exc))


# ----------------------------------------------------------------------------- system


@app.get("/health")
def health(s: Session = Depends(db_session)) -> dict[str, Any]:
    return {"status": "ok", "version": __version__, "audit_chain": AuditLog(s).verify()["ok"],
            "connectors_enabled": len(registry().enabled_names()), "kill_switch": _KILL["on"] or get_settings().kill_switch}


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def ui() -> HTMLResponse:
    return HTMLResponse((STATIC / "index.html").read_text(encoding="utf-8"))


@app.get("/api/v1/dev/token")
def dev_token(user: str = "analyst@cci-demo.com", roles: str = "analyst") -> dict[str, str]:
    st = get_settings()
    if st.auth_mode != "dev" or st.environment == "prod" or not st.dev_jwt_secret:
        raise HTTPException(404, "not available")
    return {"token": issue_dev_token(st.dev_jwt_secret, user, [r.strip() for r in roles.split(",")])}


@app.get("/api/v1/me")
def me(p: Principal = Depends(current_user)) -> dict[str, Any]:
    return {"id": p.id, "name": p.name, "roles": sorted(r.value for r in p.roles),
            "permissions": sorted(x.value for x in Perm if p.can(x))}


# ----------------------------------------------------------------------------- connectors


@app.get("/api/v1/connectors")
def connectors(_: Principal = Depends(need(Perm.READ))) -> list[dict[str, Any]]:
    return registry().status()


@app.post("/api/v1/connectors/{name}/sync")
def connector_sync(name: str, stream: str, full: bool = False, p: Principal = Depends(need(Perm.MANAGE_CONNECTORS)),
                   s: Session = Depends(db_session)) -> dict[str, Any]:
    rep = SyncRunner(s, ContextStore(s)).sync(registry().get(name), stream, full_backfill=full)
    AuditLog(s).append(actor_type="human", actor_id=p.id, event_type="connector.sync", subject_type="connector",
                       subject_id=name, payload={"stream": stream, "ingested": rep.ingested, "failed": rep.failed})
    return rep.__dict__ | {"reconciled": rep.reconciled}


class PushedAlerts(BaseModel):
    alerts: list[dict[str, Any]]


@app.post("/api/v1/ingest/alerts")
def ingest_alerts(body: PushedAlerts, p: Principal = Depends(need(Perm.INVESTIGATE)),
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
    _KILL["on"] = on
    AuditLog(s).append(actor_type="human", actor_id=p.id, event_type="policy.kill_switch", subject_type="policy",
                       subject_id="kill_switch", payload={"on": on})
    return {"kill_switch": on}


# ----------------------------------------------------------------------------- actions / approvals


@app.get("/api/v1/actions/catalog")
def action_catalog(_: Principal = Depends(need(Perm.READ)), s: Session = Depends(db_session)):
    pol = policy_engine(s)
    return [{**a, "level": int(pol.view(a["action_type"]).level)} for a in registry().action_registry().catalog()]


@app.get("/api/v1/actions")
def list_actions(status: str | None = None, case_id: str | None = None, _: Principal = Depends(need(Perm.READ)),
                 s: Session = Depends(db_session)):
    q = select(ActionRequest).order_by(ActionRequest.created_at.desc()).limit(500)
    if status:
        q = q.where(ActionRequest.status.in_(status.split(",")))
    if case_id:
        q = q.where(ActionRequest.case_id == case_id)
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
    try:
        return _action(_action_service(s).request(body.action_type, params=body.params, targets=body.targets,
                                                  requested_by=p, case_id=body.case_id, rationale=body.rationale))
    except Exception as exc:
        raise _err(exc) from exc


@app.post("/api/v1/actions/{aid}/{verb}")
def decide_action(aid: str, verb: str, body: Decision, p: Principal = Depends(current_user),
                  s: Session = Depends(db_session)):
    svc = _action_service(s)
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
def find_entity(kind: str, key: str, value: str, _: Principal = Depends(need(Perm.READ)), s: Session = Depends(db_session)):
    st = ContextStore(s)
    e = st.find(kind, key, value)
    if e is None:
        raise HTTPException(404, "not found")
    return _entity(st, e)


@app.get("/api/v1/entities/{eid}")
def get_entity(eid: str, _: Principal = Depends(need(Perm.READ)), s: Session = Depends(db_session)):
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
def unresolved(_: Principal = Depends(need(Perm.READ)), s: Session = Depends(db_session)):
    return [{"id": u.id, "kind": u.kind, "reason": u.reason, "candidates": u.candidates, "source_record": u.source_record_id}
            for u in s.execute(select(UnresolvedItem).where(UnresolvedItem.status == "open")).scalars()]


class Override(BaseModel):
    entity_id: str | None = None
    reason: str = ""


@app.post("/api/v1/resolution/{uid}/override")
def resolution_override(uid: str, body: Override, p: Principal = Depends(current_user), s: Session = Depends(db_session)):
    try:
        rec = EntityResolver(s).override(uid, body.entity_id, p, body.reason)
    except Exception as exc:
        raise _err(exc) from exc
    return {"source_record": rec.id, "entity_id": rec.entity_id}


@app.get("/api/v1/resolution/match-rate")
def match_rate(kind: str = "asset", _: Principal = Depends(need(Perm.READ)), s: Session = Depends(db_session)):
    return EntityResolver(s).match_rate(kind)


# ----------------------------------------------------------------------------- cases (shared)


@app.get("/api/v1/cases")
def list_cases(domain: str | None = None, status: str | None = None, _: Principal = Depends(need(Perm.READ)),
               s: Session = Depends(db_session)):
    q = select(Case).order_by(Case.created_at.desc()).limit(500)
    if domain:
        q = q.where(Case.domain == domain)
    if status:
        q = q.where(Case.status.in_(status.split(",")))
    return [{"id": c.id, "domain": c.domain, "title": c.title, "status": c.status, "severity": c.severity,
             "verdict": c.verdict, "confidence": c.confidence, "created_at": c.created_at.isoformat()}
            for c in s.execute(q).scalars()]


@app.get("/api/v1/cases/{cid}")
def get_case(cid: str, _: Principal = Depends(need(Perm.READ)), s: Session = Depends(db_session)):
    try:
        view = CaseService(s).view(cid)
    except KeyError as exc:
        raise HTTPException(404, str(exc)) from exc
    view["intelligence"] = _case_intelligence(s, view)
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
    case = s.get(Case, cid)
    if case is None:
        raise HTTPException(404, "unknown case")
    try:
        if case.domain == "phishing":
            return _services(s)["phishing"].confirm(cid, p, verdict=body.verdict, reasoning=body.reasoning)
        d = CaseService(s).decide(cid, p, verdict=body.verdict, reasoning=body.reasoning, close=body.close)
        return {"disposition": d.analyst_verdict}
    except Exception as exc:
        raise _err(exc) from exc


@app.get("/api/v1/cases/{cid}/report")
def case_report(cid: str, p: Principal = Depends(need(Perm.READ)), s: Session = Depends(db_session)):
    from soc_platform.reporting.reports import ReportService

    run = ReportService(s, get_settings().report_output_dir, llm=llm(s)).investigation_report(CaseService(s).view(cid), by=p.id)
    return FileResponse(run.path, filename=Path(run.path).name)


@app.get("/api/v1/metrics/shadow")
def shadow(domain: str, _: Principal = Depends(need(Perm.READ)), s: Session = Depends(db_session)):
    return {"agreement": agreement_report(s, domain), "detection_quality": detection_quality(s, domain, min_count=2)}


@app.get("/api/v1/llm/budget")
def llm_budget(_: Principal = Depends(need(Perm.READ)), s: Session = Depends(db_session)):
    return LLMGateway(s, get_settings()).budget_status()


# ----------------------------------------------------------------------------- phishing


@app.post("/api/v1/phishing/ingest")
def phishing_ingest(process: bool = True, p: Principal = Depends(need(Perm.INVESTIGATE)), s: Session = Depends(db_session)):
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
                          p: Principal = Depends(need(Perm.INVESTIGATE)), s: Session = Depends(db_session)):
    raw = await file.read()
    if len(raw) > 25 * 1024 * 1024:
        raise HTTPException(413, "message too large")
    svc = _services(s)["phishing"]
    sub = svc.submit_raw(raw, source="upload", reporter=reporter or p.name)
    return svc.process(sub.id) if process and sub.status == "new" else {"submission": sub.id, "status": sub.status}


@app.get("/api/v1/phishing/metrics")
def phishing_metrics(_: Principal = Depends(need(Perm.READ)), s: Session = Depends(db_session)):
    return _services(s)["phishing"].metrics()


# ----------------------------------------------------------------------------- incident


@app.post("/api/v1/incidents/run")
def incidents_run(investigate: bool = True, p: Principal = Depends(need(Perm.INVESTIGATE)), s: Session = Depends(db_session)):
    svc = _services(s)["incident"]
    ing = svc.ingest()
    cases = svc.cluster()
    done = [svc.investigate(c.id)["case"] for c in cases if investigate and c.status != "closed"]
    _intel(s).refresh()
    return {"ingested": ing.synced, "errors": ing.errors, "new_incidents": len(cases), "investigated": done}


@app.post("/api/v1/incidents/{cid}/investigate")
def incident_investigate(cid: str, p: Principal = Depends(need(Perm.INVESTIGATE)), s: Session = Depends(db_session)):
    return _services(s)["incident"].investigate(cid)


@app.get("/api/v1/incidents/handover")
def incident_handover(hours: int = 12, _: Principal = Depends(need(Perm.READ)), s: Session = Depends(db_session)):
    return _services(s)["incident"].handover(hours=hours)


# ----------------------------------------------------------------------------- vulnerability


@app.post("/api/v1/vm/refresh")
def vm_refresh(p: Principal = Depends(need(Perm.INVESTIGATE)), s: Session = Depends(db_session)):
    out = _services(s)["vulnerability"].refresh()
    _intel(s).refresh()
    return out


@app.get("/api/v1/vm/metrics")
def vm_metrics(_: Principal = Depends(need(Perm.READ)), s: Session = Depends(db_session)):
    return _services(s)["vulnerability"].metrics()


@app.get("/api/v1/vm/findings")
def vm_findings(priority: str | None = None, status: str = "open,reopened", _: Principal = Depends(need(Perm.READ)),
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
def vm_affected(cve: str, _: Principal = Depends(need(Perm.READ)), s: Session = Depends(db_session)):
    return _services(s)["vulnerability"].affected_devices(cve.upper())


class CampaignBody(BaseModel):
    cve: str
    notify_via: str = "email"
    team_contacts: dict[str, str] = Field(default_factory=dict)


@app.post("/api/v1/vm/campaigns")
def vm_campaign(body: CampaignBody, p: Principal = Depends(current_user), s: Session = Depends(db_session)):
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
def vm_ack(pid: str, body: AckBody, p: Principal = Depends(current_user), s: Session = Depends(db_session)):
    plan = _services(s)["vulnerability"].acknowledge(pid, p, committed_date=body.committed_date, owner=body.owner,
                                                     dependencies=body.dependencies, response=body.response)
    return {"plan_id": plan.id, "status": plan.status}


@app.post("/api/v1/vm/follow-up")
def vm_follow(p: Principal = Depends(need(Perm.INVESTIGATE)), s: Session = Depends(db_session)):
    return _services(s)["vulnerability"].follow_up()


@app.post("/api/v1/vm/campaigns/{cid}/validate")
def vm_validate(cid: str, p: Principal = Depends(need(Perm.INVESTIGATE)), s: Session = Depends(db_session)):
    return _services(s)["vulnerability"].validate_campaign(cid)


class ExceptionBody(BaseModel):
    finding_id: str
    justification: str
    compensating_control: str = ""
    days: int = 90


@app.post("/api/v1/vm/exceptions")
def vm_exception(body: ExceptionBody, p: Principal = Depends(current_user), s: Session = Depends(db_session)):
    ex = _services(s)["vulnerability"].request_exception(body.finding_id, p, justification=body.justification,
                                                         compensating_control=body.compensating_control, days=body.days)
    return {"exception_id": ex.id, "status": ex.status}


@app.post("/api/v1/vm/exceptions/{eid}/decision")
def vm_exception_decision(eid: str, approve: bool, p: Principal = Depends(current_user), s: Session = Depends(db_session)):
    try:
        ex = _services(s)["vulnerability"].decide_exception(eid, p, approve=approve)
    except Exception as exc:
        raise _err(exc) from exc
    return {"exception_id": ex.id, "status": ex.status}


@app.post("/api/v1/vm/risk-register/propose")
def vm_rr(p: Principal = Depends(need(Perm.INVESTIGATE)), s: Session = Depends(db_session)):
    return [{"id": e.id, "cve": e.cve, "rating": e.rating, "risk_statement": e.risk_statement, "status": e.status}
            for e in _services(s)["vulnerability"].propose_risk_register()]


@app.post("/api/v1/vm/risk-register/{eid}/decision")
def vm_rr_decide(eid: str, approve: bool, p: Principal = Depends(current_user), s: Session = Depends(db_session)):
    try:
        e = _services(s)["vulnerability"].decide_risk_entry(eid, p, approve=approve)
    except Exception as exc:
        raise _err(exc) from exc
    return {"id": e.id, "status": e.status}


class QueryBody(BaseModel):
    question: str


@app.post("/api/v1/vm/query")
def vm_query(body: QueryBody, _: Principal = Depends(need(Perm.READ)), s: Session = Depends(db_session)):
    return _services(s)["vulnerability"].query(body.question)


@app.get("/api/v1/vm/new-kev")
def vm_new_kev(since: str = Query(..., description="YYYY-MM-DD"), _: Principal = Depends(need(Perm.READ)),
               s: Session = Depends(db_session)):
    return _services(s)["vulnerability"].new_cve_assessment(since=since)


@app.get("/api/v1/vm/coverage")
def vm_coverage(_: Principal = Depends(need(Perm.READ)), s: Session = Depends(db_session)):
    return _services(s)["vulnerability"].coverage()


# ----------------------------------------------------------------------------- reports


@app.post("/api/v1/reports/{kind}")
def make_report(kind: str, p: Principal = Depends(need(Perm.READ)), s: Session = Depends(db_session)):
    from soc_platform.reporting.reports import ReportService

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
def download_report(rid: str, _: Principal = Depends(need(Perm.READ)), s: Session = Depends(db_session)):
    from soc_platform.domains.vulnerability.models import ReportRun

    run = s.get(ReportRun, rid)
    if run is None:
        raise HTTPException(404, "unknown report")
    return FileResponse(run.path, filename=Path(run.path).name)


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
def intel_insights(severity: str | None = None, status: str = "new,acknowledged", _: Principal = Depends(need(Perm.READ)),
                   s: Session = Depends(db_session)):
    from soc_platform.intelligence.models import Insight

    q = select(Insight).where(Insight.status.in_(status.split(","))).order_by(Insight.score.desc())
    if severity:
        q = q.where(Insight.severity.in_(severity.split(",")))
    return [_insight(i) for i in s.execute(q).scalars()]


@app.post("/api/v1/intelligence/refresh")
def intel_refresh(p: Principal = Depends(need(Perm.INVESTIGATE)), s: Session = Depends(db_session)):
    return {"insights": len(_intel(s).refresh())}


@app.post("/api/v1/intelligence/insights/{iid}/{verb}")
def intel_decide(iid: str, verb: str, p: Principal = Depends(need(Perm.INVESTIGATE)), s: Session = Depends(db_session)):
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
def intel_top(kind: str | None = None, limit: int = 10, _: Principal = Depends(need(Perm.READ)),
              s: Session = Depends(db_session)):
    from soc_platform.intelligence.risk import RiskEngine

    return [p.as_dict() for p in RiskEngine(s).top(kind, limit)]


@app.get("/api/v1/intelligence/entities/{eid}/risk")
def intel_entity_risk(eid: str, _: Principal = Depends(need(Perm.READ)), s: Session = Depends(db_session)):
    from soc_platform.intelligence.risk import RiskEngine

    p = RiskEngine(s).profile(eid)
    if p is None:
        raise HTTPException(404, "not a user/host entity")
    return p.as_dict()


class AskBody(BaseModel):
    question: str = Field(min_length=3, max_length=2000)


@app.post("/api/v1/intelligence/ask")
def intel_ask(body: AskBody, p: Principal = Depends(need(Perm.READ)), s: Session = Depends(db_session)):
    out = _intel(s).analyst.ask(body.question)
    AuditLog(s).append(actor_type="human", actor_id=p.id, event_type="intelligence.ask", subject_type="question",
                       subject_id="ask", payload={"question": body.question, "planner": out["planner"],
                                                  "tool_calls": out["tool_calls"]})
    return out


@app.get("/api/v1/intelligence/brief")
def intel_brief(_: Principal = Depends(need(Perm.READ)), s: Session = Depends(db_session)):
    return _intel(s).analyst.brief()
