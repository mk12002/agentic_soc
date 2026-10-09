"""Every request, agent call and job run is diagnosable and auditable: one trace id ties the access log, audit events,
model calls (with what the evidence check removed and why) and job runs together; every successful write is audited;
structured log lines cover requests, audit events, model calls, outbound calls to tools, jobs and CLI commands, with
secrets masked."""

from __future__ import annotations

import json
import logging

import httpx
import pytest

from soc_platform.core.observability import TRACE, accept_trace, configure_logging, event, scrub, traced

LEAD = "lena@acme-demo.com"


# ============================================================================== trace ids and log lines
def test_a_callers_request_id_is_reused_only_when_it_is_safe():
    assert accept_trace("abc-123_DEF.456") == "abc-123_DEF.456"
    for bad in (None, "", "short", "has space in it", "x" * 65, 'q"uote-12345', "line\nbreak-1234"):
        assert accept_trace(bad).startswith("req-")


def test_log_lines_mask_secrets_and_cut_long_values_but_keep_token_counts():
    s = scrub({"api_key": "k", "Authorization": "Bearer x", "client_secret": "s", "prompt_tokens": 120,
               "nested": {"password": "p", "ok": "fine"}, "text": "a" * 2000, "items": list(range(100))})
    assert s["api_key"] == s["Authorization"] == s["client_secret"] == s["nested"]["password"] == "***"
    assert s["prompt_tokens"] == 120 and s["nested"]["ok"] == "fine"
    assert s["text"].endswith("[2000 chars]") and len(s["items"]) == 50


@pytest.fixture()
def logging_on(tmp_path, monkeypatch):
    """The platform's logging, configured as the server does, into a file; restored afterwards."""
    root = logging.getLogger()
    saved = (root.level, list(root.handlers), getattr(root, "_soc_configured", False))
    log = tmp_path / "soc.log"
    for k, v in {"SOC_LOG_CONFIGURE": "1", "SOC_LOG_FORMAT": "json", "SOC_LOG_FILE": str(log),
                 "SOC_LOG_LEVEL": "INFO"}.items():
        monkeypatch.setenv(k, v)
    assert configure_logging(force=True)
    yield log
    for h in list(root.handlers):
        if getattr(h, "_soc_configured", False):
            root.removeHandler(h)
            h.close()
    root.setLevel(saved[0])
    root._soc_configured = saved[2]


def _lines(path):
    for h in logging.getLogger().handlers:
        h.flush()
    return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]


def test_structured_logs_are_json_lines_carrying_the_trace_id(logging_on):
    with traced("req-test-0001"):
        event("demo.event", api_key="secret-value", tokens=5, note="hello")
    assert not configure_logging()                                # idempotent: no second set of handlers
    line = next(x for x in _lines(logging_on) if x["msg"] == "demo.event")
    assert line["trace_id"] == "req-test-0001" and line["api_key"] == "***" and line["tokens"] == 5
    assert line["level"] == "INFO" and line["logger"] == "soc.events" and "ts" in line
    assert TRACE.get() is None                                     # the trace ends with its block


# ============================================================================== the API
@pytest.fixture()
def client(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from soc_platform.api import app as appmod
    from soc_platform.config import get_settings
    from soc_platform.core import db as dbm
    from soc_platform.core.auth import issue_dev_token

    secret = "observability-secret-0123456789abcdef01"
    for k, v in {"SOC_AUTH_MODE": "dev", "SOC_DEV_JWT_SECRET": secret, "SOC_ORG_DOMAINS": "acme-demo.com",
                 "SOC_DATABASE_URL": f"sqlite:///{(tmp_path / 'o.db').as_posix()}", "SOC_EMBEDDED_SCHEDULER": "0"}.items():
        monkeypatch.setenv(k, v)
    get_settings.cache_clear()
    dbm._default = None
    appmod.registry.cache_clear()
    dbm.get_database().create_all()
    tok = lambda u, r, d="*": {"Authorization": "Bearer " + issue_dev_token(secret, u, [r], domains=[d])}
    with TestClient(appmod.app) as c:
        yield c, tok, appmod
    get_settings.cache_clear()
    dbm._default = None
    appmod.registry.cache_clear()


def _audit(trace=None):
    from sqlalchemy import select

    from soc_platform.core import db as dbm
    from soc_platform.core.models import AuditRecord

    with dbm.get_database().session() as s:
        q = select(AuditRecord).order_by(AuditRecord.seq)
        if trace:
            q = q.where(AuditRecord.trace_id == trace)
        return [(r.event_type, r.trace_id, r.payload) for r in s.execute(q).scalars()]


def test_every_request_gets_a_trace_id_and_everything_it_causes_carries_it(client):
    c, tok, _ = client
    lead = tok(LEAD, "lead")
    r = c.post("/api/v1/cases/does-not-exist/notes", headers={**lead, "X-Request-ID": "caller-trace-0001"},
               json={"text": "x"})
    assert r.headers["X-Request-ID"] == "caller-trace-0001"
    r = c.post("/api/v1/intelligence/ask", headers=lead, json={"question": "Who is most at risk right now?"})
    trace = r.headers["X-Request-ID"]
    assert trace.startswith("req-") and [e[0] for e in _audit(trace)] == ["intelligence.ask"]
    t = c.get(f"/api/v1/admin/trace/{trace}", headers=lead).json()
    assert t["requests"][0]["path"] == "/api/v1/intelligence/ask" and t["requests"][0]["principal"] == LEAD
    assert [a["event_type"] for a in t["audit"]] == ["intelligence.ask"] and t["audit"][0]["trace_id"] == trace
    assert c.get("/api/v1/admin/trace/req-unknown-000000", headers=lead).status_code == 404
    scoped = tok("pia@acme-demo.com", "analyst", "phishing")
    assert c.get(f"/api/v1/admin/trace/{trace}", headers=scoped).status_code == 403   # spans every domain


def test_every_successful_write_is_audited_even_when_its_code_forgot(client):
    c, tok, _ = client
    lead = tok(LEAD, "lead")
    before = len(_audit())
    r = c.post("/api/v1/ingest/alerts", headers=lead, json={"alerts": [{"id": "obs-1", "title": "Test alert",
                                                                         "severity": "low"}]})
    assert r.status_code == 200
    new = _audit()[before:]
    assert [e[0] for e in new] == ["api.post"] and new[0][2]["route"] == "/api/v1/ingest/alerts"
    assert new[0][1] == r.headers["X-Request-ID"]
    assert c.post("/api/v1/ingest/alerts", headers=lead, json={"alerts": "nope"}).status_code == 422
    assert len(_audit()) == before + 1                              # a refused request changes nothing, audits nothing
    r = c.post("/api/v1/intelligence/ask", headers=lead, json={"question": "Who is most at risk right now?"})
    assert [e[0] for e in _audit(r.headers["X-Request-ID"])] == ["intelligence.ask"]   # no generic duplicate


def test_a_model_call_is_diagnosable_end_to_end(client):
    from soc_platform.core import db as dbm
    from soc_platform.llm.gateway import Completion, LLMGateway, Provider

    class Model(Provider):
        name = "fake"

        def complete(self, system, user, *, tier, max_tokens=None):
            claims = [{"text": "3 hosts reached the domain", "kind": "fact", "evidence_ids": ["E1"]},
                      {"text": "Nothing cited here", "kind": "fact", "evidence_ids": ["E9"]},
                      {"text": "777 hosts were wiped", "kind": "fact", "evidence_ids": ["E1"]}]
            return Completion(json.dumps({"summary": "ok", "claims": claims}), 100, 40, "fake-1")

    c, tok, _ = client
    lead = tok(LEAD, "lead")
    with dbm.get_database().session() as s, traced("req-llm-diag-0001"):
        from soc_platform.config import get_settings

        LLMGateway(s, get_settings(), provider=Model()).grounded(
            "incident.summary", "q", [{"id": "E1", "claim": "3 hosts reached the domain", "source": "umbrella"}])
    calls = c.get("/api/v1/admin/llm/calls?workflow=incident.*", headers=lead).json()
    assert calls[0]["trace_id"] == "req-llm-diag-0001" and calls[0]["max_tokens"] == 3_000
    assert (calls[0]["claims_kept"], calls[0]["claims_dropped"]) == (1, 2)
    d = c.get(f"/api/v1/admin/llm/calls/{calls[0]['id']}", headers=lead).json()
    reasons = {x["text"]: x["reason"] for x in d["guardrail"]["dropped"]}
    assert reasons == {"Nothing cited here": "cites no evidence that was provided",
                       "777 hosts were wiped": "states a figure its cited evidence does not contain"}
    assert "3 hosts reached the domain" in d["prompt"] and "777 hosts" in d["response"]
    t = c.get("/api/v1/admin/trace/req-llm-diag-0001", headers=lead).json()
    assert t["llm_calls"][0]["guardrail"]["kept"] == 1
    assert c.get("/api/v1/admin/llm/calls/nope", headers=lead).status_code == 404


def test_a_job_run_and_everything_it_did_share_one_trace(client, caplog):
    from soc_platform import jobs
    from soc_platform.core import db as dbm
    from soc_platform.core.audit import AuditLog

    caplog.set_level(logging.INFO, logger="soc.events")

    def body(name, s):
        AuditLog(s).append(actor_type="system", actor_id="system:test", event_type="test.event", subject_type="x",
                           subject_id="1")
        return {"done": 1}

    run = jobs.run_job("intelligence", db=dbm.get_database(), trigger="manual:test", body=body)
    assert run.trace_id.startswith("job-intelligence-")
    assert [e[0] for e in _audit(run.trace_id)] == ["test.event"]
    msgs = [r for r in caplog.records if r.name == "soc.events"]
    assert {"job.start", "job.end", "audit"} <= {r.getMessage() for r in msgs}
    assert all(r.trace_id == run.trace_id for r in msgs if r.getMessage() in ("job.start", "job.end"))
    c, tok, _ = client
    assert c.get(f"/api/v1/admin/trace/{run.trace_id}", headers=tok(LEAD, "lead")).json()["job_run"]["job"] == "intelligence"
    hist = c.get("/api/v1/jobs?limit=5", headers=tok(LEAD, "lead")).json()["runs"]
    assert hist[0]["trace_id"] == run.trace_id


def test_outbound_calls_to_tools_are_logged_without_their_query_string(caplog):
    from soc_platform.connectors.http import HttpTransport

    caplog.set_level(logging.INFO, logger="soc.events")
    t = HttpTransport("https://api.vendor.example")
    t.client = httpx.Client(transport=httpx.MockTransport(lambda req: httpx.Response(200, json={"ok": True})))
    with traced("req-outbound-0001"):
        t.request("GET", "/v1/alerts", params={"api_key": "leak-me", "since": "x"})
    rec = next(r for r in caplog.records if r.getMessage() == "connector.http")
    f = rec.soc_fields
    assert f["host"] == "api.vendor.example" and f["path"] == "/v1/alerts" and f["status"] == 200
    assert "leak-me" not in json.dumps(f) and rec.trace_id == "req-outbound-0001"


def test_cli_commands_are_logged(caplog, monkeypatch, capsys):
    from soc_platform.__main__ import main

    caplog.set_level(logging.INFO, logger="soc.events")
    monkeypatch.setenv("SOC_DEV_JWT_SECRET", "cli-secret-0123456789abcdef0123456789")
    main(["token", "lena@acme-demo.com", "lead"])
    rec = next(r for r in caplog.records if r.getMessage() == "cli.command")
    assert rec.soc_fields["command"] == "token" and rec.soc_fields["args"] == ["<value>", "<value>"]
    assert rec.trace_id.startswith("cli-token-") and capsys.readouterr().out.strip()


def test_trace_ids_do_not_change_what_the_audit_chain_proves(session):
    from soc_platform.core.audit import AuditLog

    with traced("req-chain-000001"):
        AuditLog(session).append(actor_type="human", actor_id=LEAD, event_type="test.event", subject_type="x",
                                 subject_id="1")
    AuditLog(session).append(actor_type="system", actor_id="s", event_type="test.event", subject_type="x", subject_id="2")
    assert AuditLog(session).verify()["ok"]


def test_stopping_the_server_writes_the_last_access_log_rows_first(client, monkeypatch, caplog):
    from fastapi.testclient import TestClient

    _, _, appmod = client
    flushed = []
    monkeypatch.setattr(appmod.ACCESS_LOG, "flush", lambda timeout=10.0: flushed.append(timeout))
    caplog.set_level(logging.INFO, logger="soc.events")
    with TestClient(appmod.app) as c:
        c.get("/health")
    assert flushed and any(r.getMessage() == "server.stop" for r in caplog.records)
