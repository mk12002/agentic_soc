"""Access control & data protection (NFR-08, NFR-09): scoped RBAC, step-up MFA, service accounts,
revocation, break-glass, durable kill switch, access log, encryption at rest, retention, audit export."""

from __future__ import annotations

import hashlib
import json
import os
from datetime import timedelta
from pathlib import Path

import pytest

from soc_platform.config import Settings
from soc_platform.core.access import AccessService, kill_switch_on
from soc_platform.core.auth import Perm, Principal, Role, issue_dev_token, principal_from_token
from soc_platform.core.db import Database

ROOT = Path(__file__).resolve().parents[2]
SECRET = "test-secret-0123456789abcdef0123456789"


def _db():
    db = Database("sqlite://")
    db.create_all()
    return db


def _st(**kw) -> Settings:
    return Settings(auth_mode="dev", dev_jwt_secret=SECRET, environment="test", **kw)


ADMIN = Principal("root.admin@cci", "Admin", frozenset({Role.ADMIN}))


# ----------------------------------------------------------------------------- principal / token rules


def test_domain_scoped_roles_from_entra_style_claims():
    import jwt

    tok = jwt.encode({"sub": "u1", "roles": ["SOC.Analyst.Phishing"], "amr": ["mfa"]}, SECRET, algorithm="HS256")
    p = principal_from_token(tok, _st())
    assert p.roles == frozenset({Role.ANALYST}) and p.domains == frozenset({"phishing"})
    assert p.in_domain("phishing") and not p.in_domain("vulnerability")
    tok = jwt.encode({"sub": "u2", "roles": ["SOC.Lead"]}, SECRET, algorithm="HS256")
    assert principal_from_token(tok, _st()).domains == frozenset({"*"})


def test_step_up_mfa_required_for_decisions_when_enforced():
    weak = principal_from_token(issue_dev_token(SECRET, "lena", ["lead"], mfa=False), _st(require_mfa=True))
    strong = principal_from_token(issue_dev_token(SECRET, "lena", ["lead"], mfa=True), _st(require_mfa=True))
    assert weak.can(Perm.INVESTIGATE) and not weak.can(Perm.APPROVE_ACTION) and not weak.can(Perm.KILL_SWITCH)
    assert "multi-factor" in weak.why_not(Perm.APPROVE_ACTION)
    assert strong.can(Perm.APPROVE_ACTION) and strong.can(Perm.APPROVE_HIGH_IMPACT)
    ctx = principal_from_token(__import__("jwt").encode({"sub": "x", "roles": ["lead"], "acrs": ["c1"]}, SECRET,
                                                        algorithm="HS256"), _st(require_mfa=True, mfa_auth_context="c1"))
    assert ctx.can(Perm.APPROVE_ACTION)


# ----------------------------------------------------------------------------- assignments / keys / revocation


def test_role_grants_are_audited_scoped_expiring_and_never_self_granted():
    db = _db()
    with db.session() as s:
        acc = AccessService(s, _st())
        with pytest.raises(PermissionError):
            acc.grant(ADMIN, ADMIN.id, "lead", reason="me")
        with pytest.raises(PermissionError):
            acc.grant(Principal("a", "a", frozenset({Role.ANALYST})), "b", "lead", reason="x")
        with pytest.raises(ValueError):
            acc.grant(ADMIN, "bob", "analyst", domains=["hr"], reason="bad domain")
        g = acc.grant(ADMIN, "bob", "analyst", domains=["vulnerability"], days=7, reason="VM rotation")
        bob = acc.effective(Principal("bob", "bob"))
        assert bob.can(Perm.INVESTIGATE) and bob.domains == frozenset({"vulnerability"})
        g.expires_at = g.granted_at - timedelta(seconds=1)
        assert not acc.effective(Principal("bob", "bob")).roles
        g2 = acc.grant(ADMIN, "bob", "analyst", reason="again")
        acc.revoke_grant(ADMIN, g2.id, "done")
        assert not acc.effective(Principal("bob", "bob")).roles
        events = {r.event_type for r in __import__("soc_platform.core.audit", fromlist=["AuditLog"]).AuditLog(s).query()}
        assert {"access.grant", "access.revoke"} <= events


def test_service_account_keys_are_hashed_expiring_and_cannot_approve():
    db = _db()
    with db.session() as s:
        acc = AccessService(s, _st())
        with pytest.raises(PermissionError):
            acc.create_api_key(ADMIN, "soar", ["lead"])            # approver roles are human-only
        with pytest.raises(ValueError):
            acc.create_api_key(ADMIN, "soar", ["analyst"], days=4000)
        key, secret = acc.create_api_key(ADMIN, "soar", ["analyst"], domains=["incident"], days=30)
        assert secret.split("_", 3)[-1] not in json.dumps(acc.list_api_keys())
        assert key.secret_sha256 == hashlib.sha256(secret.split(f"{key.id}_", 1)[1].encode()).hexdigest()
        svc = acc.authenticate_api_key(secret)
        assert svc.is_service and svc.can(Perm.INVESTIGATE) and svc.can(Perm.REQUEST_ACTION)
        assert not svc.can(Perm.APPROVE_ACTION) and svc.domains == frozenset({"incident"})
        with pytest.raises(PermissionError):
            acc.authenticate_api_key(secret[:-2] + "xx")
        acc.revoke_api_key(ADMIN, key.id)
        with pytest.raises(PermissionError):
            acc.authenticate_api_key(secret)


def test_token_and_session_revocation():
    db = _db()
    st = _st()
    with db.session() as s:
        acc = AccessService(s, st)
        p = principal_from_token(issue_dev_token(SECRET, "eve", ["analyst"]), st)
        assert acc.effective(p)
        acc.revoke_token(p, p.token_id)
        with pytest.raises(PermissionError):
            acc.effective(p)
        q = principal_from_token(issue_dev_token(SECRET, "mallory", ["analyst"]), st)
        acc.revoke_sessions(ADMIN, "mallory", "suspected compromise")
        with pytest.raises(PermissionError):
            acc.effective(q)


def test_break_glass_requires_sealed_secret_and_is_audited_and_alerted():
    from soc_platform.core.audit import AuditLog
    from soc_platform.intelligence.models import Insight

    db = _db()
    with db.session() as s:
        with pytest.raises(PermissionError):
            AccessService(s, _st()).break_glass("anything", client="1.2.3.4", path="/x")  # disabled by default
        acc = AccessService(s, _st(break_glass_sha256=hashlib.sha256(b"sealed-envelope-secret").hexdigest()))
        with pytest.raises(PermissionError):
            acc.break_glass("guess", client="1.2.3.4", path="/api/v1/kill-switch")
        p = acc.break_glass("sealed-envelope-secret", client="1.2.3.4", path="/api/v1/kill-switch")
        assert p.break_glass and p.can(Perm.KILL_SWITCH) and p.can(Perm.MANAGE_ACCESS)
        ev = [r.event_type for r in AuditLog(s).query()]
        assert "auth.break_glass_failed" in ev and "auth.break_glass_used" in ev
        assert s.query(Insight).filter(Insight.rule == "break_glass_used").count() == 1


def test_kill_switch_is_durable_and_permissioned():
    db = _db()
    with db.session() as s:
        acc = AccessService(s, _st())
        assert not kill_switch_on(s, _st())
        with pytest.raises(PermissionError):
            acc.set_flag(Principal("a", "a", frozenset({Role.ANALYST})), "kill_switch", True, perm=Perm.KILL_SWITCH)
        acc.set_flag(Principal("l", "l", frozenset({Role.LEAD})), "kill_switch", True, perm=Perm.KILL_SWITCH)
    with db.session() as s:  # new session / "another replica"
        assert kill_switch_on(s, _st())


# ----------------------------------------------------------------------------- data protection


def test_encryption_at_rest_roundtrip_rotation_and_tamper(tmp_path):
    from cryptography.fernet import Fernet

    from soc_platform.core.context_store import RawStore
    from soc_platform.core.crypto import MAGIC, DataCipher, DataProtectionError, read_protected, write_protected

    k1, k2 = Fernet.generate_key().decode(), Fernet.generate_key().decode()
    c1 = DataCipher([k1])
    p = write_protected(tmp_path / "a.eml", b"Subject: secret\r\n\r\npassword=hunter2", c1)
    assert p.read_bytes().startswith(MAGIC) and b"hunter2" not in p.read_bytes()
    assert read_protected(p, DataCipher([k2, k1])) == b"Subject: secret\r\n\r\npassword=hunter2"  # rotation
    blob = bytearray(p.read_bytes())
    blob[-5] ^= 1
    p.write_bytes(bytes(blob))
    with pytest.raises(DataProtectionError):
        read_protected(p, c1)
    rs = RawStore(tmp_path / "raw", cipher=c1)
    ref = rs.put("../../etc", "x/y", "id-1", {"token": "abc"})
    assert Path(ref).resolve().is_relative_to((tmp_path / "raw").resolve())
    assert rs.get(ref) == {"token": "abc"} and b"abc" not in Path(ref).read_bytes()
    with pytest.raises(PermissionError):
        rs.get(str(tmp_path / "a.eml"))
    with pytest.raises(DataProtectionError):
        from soc_platform.core.crypto import get_cipher

        get_cipher(Settings(environment="prod"))  # prod without a key refuses to run


def test_retention_prunes_copies_but_keeps_legal_hold_and_audits(tmp_path):
    from soc_platform.core.audit import AuditLog
    from soc_platform.core.models import AccessLogRecord, Case, LLMCall, SourceRecord, utcnow
    from soc_platform.core.retention import export_audit, run_retention
    from soc_platform.domains.phishing.models import Submission

    db = _db()
    old = utcnow() - timedelta(days=800)  # well past every cut-off (400 d is the access-log boundary itself)
    with db.session() as s:
        raw = tmp_path / "r.json"
        raw.write_text("{}")
        s.add(SourceRecord(kind="alert", tool="t", source_type="x", source_id="1", normalized={}, raw_ref=str(raw),
                           fetched_at=old, first_seen=old, last_seen=old))
        open_case = Case(domain="phishing", title="open")
        s.add(open_case)
        s.flush()
        held, gone = tmp_path / "held.eml", tmp_path / "gone.eml"
        held.write_bytes(b"x")
        gone.write_bytes(b"y")
        s.add_all([Submission(source="t", source_ref="a", raw_path=str(held), received_at=old, case_id=open_case.id,
                              mime_sha256="a"),
                   Submission(source="t", source_ref="b", raw_path=str(gone), received_at=old, mime_sha256="b")])
        s.add(LLMCall(ts=old, workflow="w", provider="p", model="m", prompt_redacted="secret prompt"))
        s.add(AccessLogRecord(ts=old, method="GET", path="/api/v1/x", status=200))
        s.flush()
        dry = run_retention(s, Settings(), dry_run=True)
        assert dry["raw_payloads"] == 1 and raw.exists()
        rep = run_retention(s, Settings())
        assert rep["raw_payloads"] == 1 and rep["emails"] == 1 and rep["emails_on_hold"] == 1, rep
        assert rep["llm_prompts"] == 1 and rep["access_log_rows"] == 1
        assert not raw.exists() and not gone.exists() and held.exists()
        assert s.query(LLMCall).one().prompt_redacted == "[purged]"
        lines = [json.loads(x) for x in export_audit(s)]
        assert lines[-1]["_verification"]["ok"] and any(x.get("event_type") == "retention.run" for x in lines[:-1])
        assert AuditLog(s).verify()["ok"]


# ----------------------------------------------------------------------------- over HTTP


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("acc")
    os.environ.update({"SOC_AUTH_MODE": "dev", "SOC_DEV_JWT_SECRET": SECRET, "SOC_ENVIRONMENT": "test",
                       "SOC_DATABASE_URL": f"sqlite:///{tmp / 'a.db'}", "SOC_REQUIRE_MFA": "1",
                       "SOC_CONNECTORS_CONFIG": str(ROOT / "config" / "connectors.yaml"),
                       "SOC_REPORT_OUTPUT_DIR": str(tmp / "reports"), "SOC_RAW_PAYLOAD_DIR": str(tmp / "raw")})
    from soc_platform.config import get_settings
    from soc_platform.core import db as dbm

    get_settings.cache_clear()
    dbm._default = None
    from fastapi.testclient import TestClient

    from soc_platform.api import app as appmod

    appmod.registry.cache_clear()
    yield TestClient(appmod.app)
    os.environ.pop("SOC_REQUIRE_MFA", None)
    get_settings.cache_clear()
    dbm._default = None


def _h(client, user, roles, mfa=True, domains=""):
    t = client.get(f"/api/v1/dev/token?user={user}&roles={roles}&mfa={str(mfa).lower()}&domains={domains}").json()["token"]
    return {"Authorization": f"Bearer {t}"}


def test_http_domain_scoping_mfa_keys_logout_access_log(client):
    vm_only = _h(client, "vic", "analyst", domains="vulnerability")
    assert client.post("/api/v1/phishing/ingest", headers=vm_only).status_code == 403
    assert client.post("/api/v1/vm/refresh", headers=vm_only).status_code == 200
    admin = _h(client, "ada", "admin")
    weak_admin = _h(client, "ada", "admin", mfa=False)
    assert client.get("/api/v1/admin/roles", headers=weak_admin).status_code == 403   # step-up
    assert client.post("/api/v1/kill-switch?on=true", headers=_h(client, "l", "lead", mfa=False)).status_code == 403
    r = client.post("/api/v1/admin/api-keys", headers=admin, json={"name": "soar", "roles": ["analyst"],
                                                                   "domains": ["incident"], "days": 30})
    assert r.status_code == 200, r.text
    key = {"X-API-Key": r.json()["api_key"]}
    me = client.get("/api/v1/me", headers=key).json()
    assert me["service_account"] and "approve_action" not in me["permissions"] and me["domains"] == ["incident"]
    assert client.post("/api/v1/incidents/run", headers=key).status_code == 200
    assert client.post("/api/v1/vm/refresh", headers=key).status_code == 403
    cases = client.get("/api/v1/cases", headers=key).json()
    assert cases and {c["domain"] for c in cases} == {"incident"}
    vm_case = next(c for c in client.get("/api/v1/cases", headers=admin).json() if c["domain"] != "incident") \
        if any(c["domain"] != "incident" for c in client.get("/api/v1/cases", headers=admin).json()) else None
    if vm_case:
        assert client.get(f"/api/v1/cases/{vm_case['id']}", headers=key).status_code == 404
    assert client.post("/api/v1/admin/roles", headers=admin, json={"principal_id": "ada", "role": "lead",
                                                                   "reason": "self"}).status_code == 403
    assert client.post("/api/v1/admin/roles", headers=admin, json={"principal_id": "vic", "role": "analyst",
                                                                   "domains": ["phishing"], "reason": "cover"}).status_code == 200
    assert client.post("/api/v1/phishing/ingest", headers=vm_only).status_code == 200  # grant widened scope
    user = _h(client, "tom", "analyst")
    assert client.post("/api/v1/auth/logout", headers=user).status_code == 200
    assert client.get("/api/v1/me", headers=user).status_code == 401
    assert client.post("/api/v1/kill-switch?on=true", headers=_h(client, "l", "lead")).json()["kill_switch"] is True
    assert client.get("/health").json()["kill_switch"] is True
    client.post("/api/v1/kill-switch?on=false", headers=_h(client, "l", "lead"))
    log = client.get("/api/v1/admin/access-log?status_min=400", headers=_h(client, "aud", "auditor")).json()
    assert any(x["path"] == "/api/v1/vm/refresh" and x["status"] == 403 and x["auth"] == "api_key" for x in log)
    exp = client.get("/api/v1/audit/export", headers=_h(client, "aud", "auditor"))
    assert exp.status_code == 200 and json.loads(exp.text.strip().splitlines()[-1])["_verification"]["ok"]
    assert client.post("/api/v1/connectors/wiz/test", headers=_h(client, "aa", "automation_admin")).json()["ok"]


def test_http_hardening_scope_body_limit_health_and_streams(client):
    """Security review fixes: cross-domain scope, stream-level body cap, cheap /health, validated inputs."""
    scoped = _h(client, "pam", "analyst", domains="phishing")
    for path in ("/api/v1/intelligence/insights", "/api/v1/intelligence/brief", "/api/v1/intelligence/risk/top"):
        assert client.get(path, headers=scoped).status_code == 403, path       # cross-domain data needs "*"
    assert client.post("/api/v1/intelligence/ask", headers=scoped, json={"question": "incidents?"}).status_code == 403
    assert client.post("/api/v1/ingest/alerts", headers=scoped, json={"alerts": []}).status_code == 403

    def big():
        for _ in range(35):
            yield b"a" * (1024 * 1024)
    full = _h(client, "lee", "lead")
    r = client.post("/api/v1/intelligence/ask", headers={**full, "Content-Type": "application/json"}, content=big())
    assert r.status_code == 413                                                # chunked, no Content-Length

    def small():
        yield b'{"question": "what is happening?"}'
    assert client.post("/api/v1/intelligence/ask", headers={**full, "Content-Type": "application/json"},
                       content=small()).status_code == 200
    assert client.get("/health").json()["audit_chain"] is True
    aa = _h(client, "ops", "automation_admin")
    assert client.post("/api/v1/connectors/wiz/sync?stream=../../etc", headers=aa).status_code == 400
    assert client.post("/api/v1/connectors/nope/sync?stream=x", headers=aa).status_code == 404


def test_rate_limit_is_per_client_not_per_token():
    from starlette.requests import Request

    from soc_platform.api.app import _client_ip, _RateLimiter

    lim = _RateLimiter(rate=0.0, burst=3)
    assert [lim.allow("10.0.0.9") for _ in range(4)] == [True, True, True, False]
    scope = {"type": "http", "headers": [(b"x-forwarded-for", b"1.2.3.4")], "client": ("10.0.0.9", 5555)}
    assert _client_ip(Request(scope)) == "10.0.0.9"        # XFF ignored unless the peer is a trusted proxy


def test_scoped_users_only_see_and_decide_their_domain_actions(client):
    lead = _h(client, "lee2", "lead")
    client.post("/api/v1/incidents/run", headers=lead)
    client.post("/api/v1/vm/refresh", headers=lead)
    client.post("/api/v1/vm/misconfigurations/route", headers=lead)
    vm_only = _h(client, "val", "lead", domains="vulnerability")
    mine = client.get("/api/v1/actions", headers=vm_only).json()
    assert mine and {a["domain"] for a in mine} == {"vulnerability"}
    other = next(a for a in client.get("/api/v1/actions?status=recommended,pending_approval", headers=lead).json()
                 if a["domain"] == "incident")
    assert client.post(f"/api/v1/actions/{other['id']}/approve", headers=vm_only, json={"note": "x"}).status_code == 404
    assert client.get("/api/v1/entities/find?kind=asset&key=fqdn&value=web01.cci-demo.com", headers=vm_only).status_code == 403
