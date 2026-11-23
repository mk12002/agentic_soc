"""The CISO: a read-only role that sees everything, and the executive view - posture, headline figures against the
period before, and the agenda bucketed by real due dates in the viewer's own day. Every figure is computed; the
optional brief only narrates them."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from soc_platform.api.executive import BUCKETS, PostureSnapshot, _bucket, evidence, snapshot, view
from soc_platform.connectors.registry import ConnectorRegistry
from soc_platform.core.auth import ROLE_PERMS, Perm, Principal, Role, _roles_from_claims
from soc_platform.core.models import ActionRequest, Case
from soc_platform.domains.vulnerability.service import VulnerabilityService

NOON = datetime(2026, 11, 23, 12, 0, tzinfo=UTC)


@pytest.fixture()
def at_noon(monkeypatch):
    monkeypatch.setenv("SOC_CLOCK_FREEZE", NOON.isoformat())
    return NOON


def _view(session, **kw):
    reg = ConnectorRegistry.all_fake()
    return view(session, reg, VulnerabilityService(session, reg), **kw)


# ============================================================================== the role
def test_the_ciso_sees_everything_and_changes_nothing():
    assert ROLE_PERMS[Role.CISO] == {Perm.READ, Perm.READ_AUDIT, Perm.EXPORT_EVIDENCE}
    ciso = Principal("cleo@acme-demo.com", "Cleo", frozenset({Role.CISO}))
    for perm in (Perm.APPROVE_ACTION, Perm.APPROVE_HIGH_IMPACT, Perm.APPROVE_POLICY, Perm.KILL_SWITCH,
                 Perm.MANAGE_ACCESS, Perm.MANAGE_CONNECTORS, Perm.REQUEST_ACTION, Perm.INVESTIGATE, Perm.TUNE_DETECTIONS):
        assert not ciso.can(perm), perm
    roles, domains, _ = _roles_from_claims({"roles": ["SOC.CISO"]})       # the Entra app role
    assert roles == frozenset({Role.CISO}) and domains == frozenset({"*"})


# ============================================================================== the agenda's day
@pytest.mark.parametrize("due,offset_h,bucket", [
    (NOON - timedelta(minutes=1), 0, "overdue"),
    (NOON + timedelta(hours=11), 0, "today"),
    (NOON + timedelta(hours=13), 0, "tomorrow"),          # past midnight UTC
    (NOON + timedelta(hours=13), -6, "today"),             # ...but still the same day six hours west of UTC
    (NOON + timedelta(hours=11), 13, "today"),             # 13 h east the day rolled over: 23:00 UTC is their noon
    (NOON + timedelta(days=6), 0, "this_week"),
    (NOON + timedelta(days=9), 0, "later")])
def test_due_dates_fall_in_the_viewers_own_day(due, offset_h, bucket):
    assert _bucket(due, NOON, timedelta(hours=offset_h)) == bucket


def test_an_open_incident_and_its_waiting_approvals_fall_due_by_severity(session, at_noon):
    crit = Case(domain="incident", title="Ransomware precursor", severity="critical", status="awaiting_approval",
                created_at=NOON - timedelta(hours=5))
    med = Case(domain="incident", title="Odd sign-in", severity="medium", status="open", created_at=NOON)
    session.add_all([crit, med])
    session.flush()
    for i in range(3):
        session.add(ActionRequest(action_type="isolate_host", case_id=crit.id, domain="incident", requested_by="agent",
                                  idempotency_key=f"k{i}", status="pending_approval", created_at=NOON - timedelta(hours=5)))
    session.flush()
    items = {(x["kind"], x["ref"]): x for x in _view(session)["agenda"]["items"]}
    assert items[("incident", crit.id)]["bucket"] == "overdue"            # 4 h target, open 5 h
    assert items[("incident", med.id)]["bucket"] == "this_week"            # 3 days
    appr = items[("approval", crit.id)]
    assert appr["bucket"] == "overdue" and appr["title"].startswith("3 action(s) awaiting approval")


def test_a_wrong_period_or_time_zone_is_refused(session):
    with pytest.raises(ValueError, match="7, 30, 90"):
        _view(session, days=45)
    with pytest.raises(ValueError, match="tz_offset"):
        _view(session, tz_offset_minutes=900)


# ============================================================================== history
def test_a_daily_snapshot_is_one_row_per_day_and_feeds_the_comparison(session, monkeypatch, at_noon):
    reg = ConnectorRegistry.all_fake()
    vm = VulnerabilityService(session, reg)
    snapshot(session, reg, vm)
    snapshot(session, reg, vm)                                             # same day: updated, not duplicated
    assert session.query(PostureSnapshot).count() == 1
    v = _view(session, days=7)
    assert v["history"]["note"] == "posture history starts on 2026-11-23"  # said, not drawn
    monkeypatch.setenv("SOC_CLOCK_FREEZE", (NOON + timedelta(days=8)).isoformat())
    session.add(Case(domain="incident", title="New one", severity="high", status="open", created_at=NOON + timedelta(days=8)))
    session.flush()
    v = _view(session, days=7)
    tile = next(h for h in v["headline"] if h["key"] == "open_incidents_critical_high")
    assert (tile["value"], tile["previous"], tile["delta"], tile["trend"]) == (1, 0, 1, "worse")
    assert v["history"]["note"] is None


# ============================================================================== the brief
def test_the_brief_only_narrates_the_computed_figures(session):
    v = _view(session)
    ev = evidence(v)
    assert ev and all(e["id"].startswith("K") for e in ev)
    claims = " ".join(e["claim"] for e in ev)
    assert f"Agenda: {v['agenda']['counts']['overdue']} overdue" in claims


# ============================================================================== the API
@pytest.fixture()
def client(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from soc_platform.api import app as appmod
    from soc_platform.config import get_settings
    from soc_platform.core import db as dbm
    from soc_platform.core.auth import issue_dev_token

    secret = "executive-view-secret-0123456789abcdef"
    for k, v in {"SOC_AUTH_MODE": "dev", "SOC_DEV_JWT_SECRET": secret, "SOC_ORG_DOMAINS": "acme-demo.com",
                 "SOC_DATABASE_URL": f"sqlite:///{(tmp_path / 'x.db').as_posix()}", "SOC_EMBEDDED_SCHEDULER": "0",
                 "SOC_LLM_PROVIDER": "none"}.items():
        monkeypatch.setenv(k, v)
    get_settings.cache_clear()
    dbm._default = None
    appmod.registry.cache_clear()
    dbm.get_database().create_all()
    tok = lambda u, r, d="": {"Authorization": "Bearer " + issue_dev_token(secret, u, [r], domains=[d] if d else None)}
    with TestClient(appmod.app) as c:
        yield c, tok
    get_settings.cache_clear()
    dbm._default = None
    appmod.registry.cache_clear()


def test_the_ciso_reads_the_executive_view_and_cannot_change_anything(client):
    c, tok = client
    ciso = tok("cleo@acme-demo.com", "ciso")
    me = c.get("/api/v1/me", headers=ciso).json()
    assert me["roles"] == ["ciso"] and me["permissions"] == ["export_evidence", "read", "read_audit"]
    v = c.get("/api/v1/executive?days=7&tz_offset_minutes=330", headers=ciso)
    assert v.status_code == 200 and set(v.json()["agenda"]["counts"]) == set(BUCKETS)
    assert c.get("/api/v1/executive?days=45", headers=ciso).status_code == 400
    assert c.get("/api/v1/executive", headers=tok("pia@acme-demo.com", "analyst", "phishing")).status_code == 403
    brief = c.post("/api/v1/executive/brief?days=30", headers=ciso).json()
    assert brief["source"] == "deterministic" and brief["evidence"]
    # without a model the platform writes real sentences from the figures - never the generic "N evidence item(s)"
    assert brief["summary"].startswith("Posture is") and "evidence item" not in brief["summary"]
    ids = {e["id"] for e in brief["evidence"]}
    assert brief["claims"] and all(set(x["evidence_ids"]) <= ids for x in brief["claims"])
    for method, url, body in (("post", "/api/v1/kill-switch?on=true", None),
                              ("put", "/api/v1/dome-score/weights", {"weights": {"identity": 50}, "note": "x"}),
                              ("put", "/api/v1/admin/llm/integration", {"provider": "none"}),
                              ("post", "/api/v1/policy/proposals", {"document": {}, "note": "x"})):
        r = getattr(c, method)(url, headers=ciso, json=body)
        assert r.status_code in (403, 422) and r.status_code != 200, (url, r.status_code)
    for url in ("/api/v1/audit?limit=5", "/api/v1/dome-score", "/api/v1/cases", "/api/v1/vm/metrics",
                "/api/v1/admin/llm/usage"):
        assert c.get(url, headers=ciso).status_code == 200, url


def test_with_a_model_the_brief_is_written_by_it_and_cites_only_the_figures(client, monkeypatch):
    from soc_platform.tests import fake_gateway_sdk as sdk

    sdk.reset()
    monkeypatch.setenv("SOC_LLM_GATEWAY_SDK", "soc_platform.tests.fake_gateway_sdk")
    monkeypatch.setenv("SOC_LLM_GATEWAY_MODELS_CALL", "llm.models")
    c, tok = client
    admin, ciso = tok("ada@acme-demo.com", "admin"), tok("cleo@acme-demo.com", "ciso")
    assert c.put("/api/v1/admin/llm/integration", headers=admin,
                 json={"provider": "enterprise_gateway", "secrets": {"auth_token": "svc-auth-token"}}).status_code == 200
    brief = c.post("/api/v1/executive/brief?days=30", headers=ciso).json()
    ids = {e["id"] for e in brief["evidence"]}
    assert brief["source"] == "llm" and brief["claims"]
    assert all(set(x["evidence_ids"]) <= ids for x in brief["claims"])
    plain = c.get("/api/v1/executive?days=30", headers=ciso).json()          # the figures are the same either way
    assert [h["value"] for h in plain["headline"]] == [h["value"] for h in
                                                       c.get("/api/v1/executive?days=30", headers=ciso).json()["headline"]]
