"""HTTP-level test of the platform API: auth, RBAC, all three domains, approvals, audit, reports."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("api")
    os.environ.update({"SOC_AUTH_MODE": "dev", "SOC_DEV_JWT_SECRET": "test-secret-0123456789abcdef0123456789",
                       "SOC_DATABASE_URL": f"sqlite:///{tmp / 'api.db'}", "SOC_CONNECTORS_CONFIG": str(ROOT / "config" / "connectors.yaml"),
                       "SOC_REPORT_OUTPUT_DIR": str(tmp / "reports"), "SOC_RAW_PAYLOAD_DIR": str(tmp / "raw"),
                       "SOC_ORG_DOMAINS": "acme-demo.com", "SOC_ENVIRONMENT": "test"})
    from soc_platform.config import get_settings
    from soc_platform.core import db as dbm

    get_settings.cache_clear()
    dbm._default = None
    from fastapi.testclient import TestClient

    from soc_platform.api import app as appmod

    appmod.registry.cache_clear()
    return TestClient(appmod.app)


@pytest.fixture(scope="module")
def seeded(client):
    """Sample estate loaded once for this module, whatever order its tests run in."""
    a = tok(client, "seed", "analyst")
    return {"vm": client.post("/api/v1/vm/refresh", headers=a).json(),
            "inc": client.post("/api/v1/incidents/run", headers=a).json(),
            "ph": client.post("/api/v1/phishing/ingest", headers=a).json()}


def tok(client, user, roles):
    return {"Authorization": "Bearer " + client.get(f"/api/v1/dev/token?user={user}&roles={roles}").json()["token"]}


def test_auth_required_and_rbac(client):
    assert client.get("/api/v1/cases").status_code == 401
    assert client.get("/api/v1/cases", headers={"Authorization": "Bearer junk"}).status_code == 401
    auditor = tok(client, "audrey", "auditor")
    assert client.get("/api/v1/audit/verify", headers=auditor).json()["ok"]
    assert client.post("/api/v1/incidents/run", headers=auditor).status_code == 403
    me = client.get("/api/v1/me", headers=tok(client, "alice", "analyst")).json()
    assert "approve_action" in me["permissions"] and "approve_policy" not in me["permissions"]


def test_all_three_domains_over_http(client, seeded):
    a, lead = tok(client, "alice", "analyst"), tok(client, "lena", "lead")
    assert len(client.get("/api/v1/connectors", headers=a).json()) >= 20
    vm, inc, ph = seeded["vm"], seeded["inc"], seeded["ph"]
    assert vm["consolidation"]["consolidated"] == 6
    assert inc["new_incidents"] >= 3 and inc["investigated"]
    assert ph["processed"][0]["verdict"] == "malicious"
    cases = client.get("/api/v1/cases", headers=a).json()
    assert {c["domain"] for c in cases} >= {"incident", "phishing"}
    # upload a corpus message
    eml = ROOT / "artifacts" / "phishing" / "corpus" / "bec_ceo_fraud.eml"
    if eml.exists():
        r = client.post("/api/v1/phishing/submit", headers=a, files={"file": ("x.eml", eml.read_bytes(), "message/rfc822")})
        assert r.status_code == 200 and r.json()["case"]["verdict"] == "malicious"
    # approvals: analyst cannot approve four-eyes isolation; lead can
    pending = client.get("/api/v1/actions?status=recommended", headers=a).json()
    iso = next(x for x in pending if x["action_type"] == "endpoint.isolate")
    assert client.post(f"/api/v1/actions/{iso['id']}/approve", headers=a, json={"note": ""}).status_code == 403
    r = client.post(f"/api/v1/actions/{iso['id']}/approve", headers=lead, json={"note": "confirmed"}).json()
    assert r["status"] == "executed"
    rb = client.post(f"/api/v1/actions/{r['id']}/rollback", headers=lead, json={"note": "test"}).json()
    assert rb["status"] == "executed"
    # VM workflow
    c = client.post("/api/v1/vm/campaigns", headers=a, json={"cve": "CVE-2021-44228", "notify_via": "ticket"}).json()
    assert client.post(f"/api/v1/vm/campaigns/{c['campaign_id']}/validate", headers=a).json()["results"]
    q = client.post("/api/v1/vm/query", headers=a, json={"question": "internet exposed KEV findings"}).json()
    assert q["records"]
    assert client.get("/api/v1/vm/new-kev?since=2026-09-18", headers=a).json()[0]["exposed"]
    # decision + shadow metrics
    case_id = next(x for x in cases if x["domain"] == "incident")["id"]
    assert client.post(f"/api/v1/cases/{case_id}/disposition", headers=a,
                       json={"verdict": "true_positive", "reasoning": "ok"}).status_code == 200
    assert client.get("/api/v1/metrics/shadow?domain=incident", headers=a).json()["agreement"]["sample_size"] == 1


def test_reports_and_audit_chain(client, seeded):
    a = tok(client, "alice", "analyst")
    for kind in ("daily_exposure", "weekly_vm", "weekly_mgmt"):
        r = client.post(f"/api/v1/reports/{kind}", headers=a).json()
        d = client.get(f"/api/v1/reports/{r['id']}/download", headers=a)
        assert d.status_code == 200 and len(d.content) > 5000
    cid = client.get("/api/v1/cases?domain=phishing", headers=a).json()[0]["id"]
    assert client.get(f"/api/v1/cases/{cid}/report", headers=a).status_code == 200
    v = client.get("/api/v1/audit/verify", headers=tok(client, "audrey", "auditor")).json()
    assert v["ok"] and v["records"] >= 40


def test_policy_change_control_and_kill_switch(client):
    admin, lead = tok(client, "adam", "automation_admin"), tok(client, "lena", "lead")
    doc = client.get("/api/v1/policy", headers=lead).json()["document"]
    doc["actions"]["canary.acknowledge"] = {"level": 4}
    pid = client.post("/api/v1/policy/proposals", headers=admin, json={"document": doc, "note": "U04"}).json()["id"]
    assert client.post(f"/api/v1/policy/proposals/{pid}/approve", headers=admin).status_code == 403
    assert client.post(f"/api/v1/policy/proposals/{pid}/approve", headers=lead).json()["status"] == "active"
    assert client.post("/api/v1/kill-switch?on=true", headers=lead).json()["kill_switch"]
    assert client.get("/health").json()["kill_switch"] is True
    client.post("/api/v1/kill-switch?on=false", headers=lead)


def test_siem_push_and_ui(client):
    a = tok(client, "alice", "analyst")
    r = client.post("/api/v1/ingest/alerts", headers=a, json={"alerts": [
        {"id": "siem-1", "title": "Impossible travel", "severity": "high", "timestamp": "2026-09-20T10:00:00Z",
         "user": "jane.doe@acme-demo.com", "src_ip": "185.220.101.4", "source": "sentinel"}]}).json()
    assert r["ingested"] == 1
    assert "<title>Agentic SOC</title>" in client.get("/").text


def test_security_headers_csp_and_limits(client):
    r = client.get("/")
    assert "script-src 'self'" in r.headers["content-security-policy"] and r.headers["x-frame-options"] == "DENY"
    assert "onclick=" not in r.text and "<script>" not in r.text          # no inline script under strict CSP
    js = client.get("/static/app.js").text
    assert "onclick" not in js and "eval(" not in js and "safeUrl" in js
    big = client.post("/api/v1/ingest/alerts", headers={"content-length": str(40 * 1024 * 1024)}, content=b"{}")
    assert big.status_code == 413


def test_intelligence_endpoints(client, seeded):
    a = tok(client, "alice", "analyst")
    assert client.post("/api/v1/intelligence/refresh", headers=a).json()["insights"] > 0
    ins = client.get("/api/v1/intelligence/insights", headers=a).json()
    assert ins and ins[0]["evidence"] and ins[0]["narrative"]
    assert client.post(f"/api/v1/intelligence/insights/{ins[-1]['id']}/dismiss", headers=a).json()["status"] == "dismissed"
    top = client.get("/api/v1/intelligence/risk/top?limit=3", headers=a).json()
    assert top[0]["name"] == "jane.doe@acme-demo.com"
    r = client.post("/api/v1/intelligence/ask", headers=a, json={"question": "who is riskiest?"}).json()
    assert r["tool_calls"] and r["answer"]
    assert "Top correlated threats" in client.get("/api/v1/intelligence/brief", headers=a).json()["summary"]
    case = client.get("/api/v1/cases?domain=phishing", headers=a).json()[0]
    assert "intelligence" in client.get(f"/api/v1/cases/{case['id']}", headers=a).json()


def test_health_reports_a_stopped_scheduler(client):
    """Failure point: if the scheduler dies, no job runs - so none can fail or alert. /health watches it."""
    from datetime import timedelta

    from soc_platform.core import db as dbm
    from soc_platform.core.models import JobRun, utcnow

    with dbm.get_database().session() as s:
        s.query(JobRun).delete()
    assert client.get("/health").json()["scheduler"]["state"] == "never"
    with dbm.get_database().session() as s:
        s.add(JobRun(job="intelligence", trigger="schedule", status="ok", attempts=1, ordinal=1,
                     started_at=utcnow() - timedelta(hours=3), finished_at=utcnow() - timedelta(hours=3)))
    h = client.get("/health").json()["scheduler"]
    assert h["state"] == "stale" and h["age_seconds"] > 3600
    with dbm.get_database().session() as s:
        s.add(JobRun(job="intelligence", trigger="schedule", status="ok", attempts=1, ordinal=2, started_at=utcnow(), finished_at=utcnow()))
    assert client.get("/health").json()["scheduler"]["state"] == "running"


def test_input_postgresql_would_reject_never_crashes_a_request(client, seeded):
    """PostgreSQL (production) rejects NUL characters and over-long text where SQLite (dev) is lax."""
    lead = tok(client, "lena@acme-demo.com", "lead")
    for url in ("/api/v1/cases/%00", "/api/v1/entities/a%00b/360", "/api/v1/cases?domain=%00"):
        assert client.get(url, headers=lead).status_code == 400, url
    # a job run by someone with a long address (the run records "manual:<address>")
    long_user = "a.very.long.firstname.and.surname.for.testing@subsidiary.acme-demo.com"
    ops = tok(client, long_user, "automation_admin")
    assert client.post("/api/v1/jobs/follow_up/run", headers=ops).status_code == 200
    assert any(long_user in str(r.get("trigger")) for r in client.get("/api/v1/jobs", headers=ops).json()["runs"])
    # a reported email with an absurd subject and a NUL in it is analysed, not crashed; the subject is kept to width
    raw = (b"From: Someone <someone@example.net>\r\nTo: jane.doe@acme-demo.com\r\nSubject: " + b"Invoice " * 400
           + b"\x00tail\r\nMessage-ID: <long-subject@example.net>\r\nContent-Type: text/plain\r\n\r\nPlease see attached.\r\n")
    r = client.post("/api/v1/phishing/submit", headers=lead, files={"file": ("long.eml", raw)})
    assert r.status_code == 200, r.text[:300]
    cid = r.json().get("id") or r.json()["case"]["id"]
    case = client.get(f"/api/v1/cases/{cid}", headers=lead).json()
    case = case.get("case", case)
    assert "\x00" not in case["title"] + (case.get("summary") or "") and len(case["title"]) <= 512


def test_bounded_text_keeps_values_to_width_and_free_of_nul():
    from soc_platform.core.db import BoundedText

    t = BoundedText(10)
    assert t.process_bind_param("short", None) == "short"
    assert t.process_bind_param("x" * 25, None) == "x" * 9 + "\u2026"
    assert t.process_bind_param("a\x00b", None) == "ab" and t.process_bind_param(None, None) is None


@pytest.mark.skipif(not __import__("os").environ.get("SOC_TEST_POSTGRES"), reason="PostgreSQL only (SOC_TEST_POSTGRES)")
def test_start_up_widens_columns_an_older_schema_left_narrow():
    from sqlalchemy import inspect, text

    from soc_platform.core.db import Database

    db = Database("sqlite://")                                   # a fresh PostgreSQL database in this mode
    db.create_all()
    with db.engine.begin() as c:
        c.execute(text('ALTER TABLE job_runs ALTER COLUMN "trigger" TYPE VARCHAR(32)'))   # as an older release made it
    db.create_all()
    width = {c["name"]: getattr(c["type"], "length", None) for c in inspect(db.engine).get_columns("job_runs")}["trigger"]
    assert width == 320


def test_access_log_rows_go_to_the_database_of_their_own_request():
    """Rows are queued and written later; they must land in the database that served the request, even if the
    process's default database has changed before the background writer flushes."""
    from soc_platform.api.app import ACCESS_LOG
    from soc_platform.core import db as dbm
    from soc_platform.core.models import AccessLogRecord

    saved = dbm._default
    a, b = dbm.Database("sqlite://"), dbm.Database("sqlite://")
    a.create_all()
    b.create_all()
    try:
        dbm.set_database(a)
        ACCESS_LOG.put({"ts": __import__("soc_platform.core.models", fromlist=["x"]).utcnow(), "principal_id": "p-a",
                        "auth_method": "bearer", "method": "GET", "path": "/api/v1/me", "status": 200,
                        "client_ip": "127.0.0.1", "user_agent": "t", "latency_ms": 1.0})
        dbm.set_database(b)                                                         # switched before the flush
        ACCESS_LOG.flush()
        with a.session() as s:
            assert s.query(AccessLogRecord).filter(AccessLogRecord.principal_id == "p-a").count() == 1
        with b.session() as s:
            assert s.query(AccessLogRecord).count() == 0
    finally:
        dbm._default = saved
