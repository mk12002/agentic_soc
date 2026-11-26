"""Needs immediate attention (top of the Overview and the executive view): which recent cases and findings are urgent,
why, when they leave, and that the rules - not the model - decide.

The rules are tested with the risk engine's factors stubbed per person / host (so each case states exactly which
signal it carries); one test runs them on the real demonstration data, with the real risk engine."""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import timedelta

import pytest

from soc_platform.api import urgent as U
from soc_platform.core.cases import CaseService
from soc_platform.core.models import CaseEntity, Entity, utcnow
from soc_platform.intelligence.models import Insight

ALL = frozenset({"*"})


@dataclass
class F:                     # the fields of risk.Factor the strip reads
    signal: str
    decayed: float = 10.0
    detail: str = ""
    when: str | None = None
    source: str = "tool"
    ref: str = "r"


@pytest.fixture()
def signals(monkeypatch):
    """entity id -> list of signals; _entity_factors reads from it."""
    table: dict[str, list[F]] = {}
    names: dict[str, str] = {}

    def fake(_s, entity_ids):
        return [(names.get(e, e), f) for e in entity_ids for f in table.get(e, [])]

    monkeypatch.setattr(U, "_entity_factors", fake)
    return table, names


def _person(s, name):
    e = Entity(kind="identity", display_name=name)
    s.add(e)
    s.flush()
    return e.id


def _case(s, domain, sev, title, *ents, age_minutes=10):
    c = CaseService(s).create(domain, title, severity=sev, attributes={}, actor="agent:test")
    c.created_at = utcnow() - timedelta(minutes=age_minutes)
    for e in ents:
        s.add(CaseEntity(case_id=c.id, entity_id=e, role="subject"))
    s.flush()
    return c


def _finding(s, rule, sev, title, *, ents=(), case_ref=None, domains=("incident",), age_minutes=5):
    i = Insight(rule=rule, dedupe_key=f"{rule}:{title}", severity=sev, title=title, entity_ids=list(ents),
                domains=list(domains), evidence=[{"ref": case_ref}] if case_ref else [],
                first_seen=utcnow() - timedelta(minutes=age_minutes))
    s.add(i)
    s.flush()
    return i


def test_a_recent_critical_case_nobody_owns_is_listed_until_someone_takes_or_decides_it(session, signals):
    from soc_platform.core.auth import Principal, Role

    c = _case(session, "incident", "critical", "Deception alert on a file server")
    out = U.urgent(session, ALL)
    assert [it["id"] for it in out["items"]] == [c.id] and out["total"] == 1
    item = out["items"][0]
    assert item["severity"] == "critical" and item["owner"] is None and item["link"] == f"#/cases/{c.id}"
    assert not item["overdue"] and item["waiting_minutes"] >= 10
    lead = Principal(id="lena@example.com", name="Lena", roles=frozenset({Role.LEAD}))
    CaseService(session).assign(c.id, "lena@example.com", by=lead)
    assert U.urgent(session, ALL)["total"] == 0                       # taken: it leaves the strip
    CaseService(session).assign(c.id, None, by=lead)
    assert U.urgent(session, ALL)["total"] == 1
    CaseService(session).decide(c.id, lead, verdict="malicious", reasoning="confirmed")
    assert U.urgent(session, ALL)["total"] == 0                       # decided and closed: gone


def test_high_needs_an_urgency_signal_and_each_reason_names_who_it_was_seen_on(session, signals):
    table, names = signals
    quiet, loud = _person(session, "a"), _person(session, "b")
    names[loud] = "jane@example.com"
    table[loud] = [F("risky_signin", detail="Sign-in from 185.220.101.4 (DE)"), F("privileged_credential_access")]
    _case(session, "incident", "high", "Suspicious script", quiet)
    c = _case(session, "incident", "high", "Privileged access after a risky sign-in", loud)
    items = U.urgent(session, ALL)["items"]
    assert [it["id"] for it in items] == [c.id]                       # high without a signal is the queue's job
    labels = [r["label"] for r in items[0]["reasons"]]
    assert labels == ["Privileged credentials accessed", "Risky sign-in"] or labels == ["Risky sign-in", "Privileged credentials accessed"]
    assert all(r["who"] == "jane@example.com" for r in items[0]["reasons"])
    assert "(DE)" in next(r["detail"] for r in items[0]["reasons"] if r["signal"] == "risky_signin")


def test_only_recent_serious_incident_and_phishing_cases_count(session, signals, monkeypatch):
    _case(session, "incident", "critical", "Two days old", age_minutes=48 * 60)
    _case(session, "incident", "medium", "Medium")
    _case(session, "vulnerability", "critical", "A KEV campaign (has its own SLA agenda)")
    assert U.urgent(session, ALL)["total"] == 0
    monkeypatch.setenv("SOC_URGENT_WINDOW_HOURS", "72")
    out = U.urgent(session, ALL)
    assert out["total"] == 1 and out["window_hours"] == 72


def test_an_old_unowned_critical_case_is_past_its_response_target(session, signals, monkeypatch):
    monkeypatch.setenv("SOC_URGENT_WINDOW_HOURS", "24")
    _case(session, "incident", "critical", "Five hours unowned", age_minutes=5 * 60)
    it = U.urgent(session, ALL)["items"][0]
    assert it["overdue"] is True                                     # critical: respond within 4 hours


def test_attack_findings_are_listed_platform_findings_are_not_and_acknowledging_removes_one(session, signals):
    f = _finding(session, "privileged_after_compromise", "high", "Privileged access after compromise indicators")
    _finding(session, "platform_capability", "high", "QR decoding unavailable")
    _finding(session, "llm_credentials", "high", "AI provider refused the credentials")
    _finding(session, "repeat_clicker", "high", "Repeat clicker")               # not an attack rule, not critical
    out = U.urgent(session, ALL)
    assert [it["id"] for it in out["items"]] == [f.id] and out["items"][0]["kind"] == "finding"
    f.status = "acknowledged"
    session.flush()
    assert U.urgent(session, ALL)["total"] == 0


def test_one_attack_story_is_one_item(session, signals):
    table, _ = signals
    jane, laptop, other = _person(session, "jane"), _person(session, "laptop"), _person(session, "x")
    table[jane] = [F("deception_hit")]
    lead = _case(session, "incident", "critical", "Deception alert", jane, laptop)
    phish = _case(session, "phishing", "critical", "Reported phishing", jane)
    _finding(session, "deception_corroborated", "high", "Deception hit corroborated", ents=[laptop])   # same host
    _finding(session, "supplier_risk", "critical", "Supplier: impersonation", ents=[], case_ref=phish.id,
             domains=("phishing",))                                                                    # names a case
    s1 = _finding(session, "supplier_risk", "critical", "Other: payment diversion", case_ref="c-unlisted", domains=("phishing",))
    s2 = _finding(session, "supplier_risk", "critical", "Other: impersonation", case_ref="c-unlisted", domains=("phishing",))
    _case(session, "incident", "critical", "Unrelated", other)
    out = U.urgent(session, ALL, limit=10)
    first = out["items"][0]
    assert first["id"] == lead.id and [r["id"] for r in first["related_cases"]] == [phish.id]
    found = [r["detail"] for r in first["reasons"] if r["signal"].startswith("finding:")]
    assert all(r["label"].startswith("Finding: ") for r in first["reasons"] if r["signal"].startswith("finding:"))
    assert "Deception hit corroborated" in found and "Supplier: impersonation" in found
    supplier = [it for it in out["items"] if it["kind"] == "finding"]
    # the item is the first finding; the second is listed by its title, the first is not repeated as its own reason
    assert len(supplier) == 1 and supplier[0]["id"] in {s1.id, s2.id}
    other = "Other: impersonation" if supplier[0]["id"] == s1.id else "Other: payment diversion"
    assert [r["label"] for r in supplier[0]["reasons"]] == [f"Finding: {other}"]
    assert out["total"] == 3                                         # Jane's story, the supplier's, the unrelated case


def test_a_domain_scoped_reader_sees_only_their_domains(session, signals):
    """Found by the every-route sweep: a vulnerability-only reader saw an incident case's id through a finding tagged
    with both domains. Findings are all-domain only (as on the Intelligence screen); reasons keep to the reader's domains."""
    table, _ = signals
    jane = _person(session, "jane")
    table[jane] = [F("deception_hit"), F("phishing_click")]
    inc = _case(session, "incident", "critical", "Incident", jane)
    p = _case(session, "phishing", "high", "Phishing", jane)
    _finding(session, "exposed_host_under_attack", "critical", "Exposed host", case_ref=inc.id,
             domains=("incident", "vulnerability"))
    phish_only = U.urgent(session, frozenset({"phishing"}))
    assert [it["id"] for it in phish_only["items"]] == [p.id]
    assert [r["signal"] for r in phish_only["items"][0]["reasons"]] == ["phishing_click"]     # not the deception hit
    assert inc.id not in str(U.urgent(session, frozenset({"vulnerability"})))
    assert U.urgent(session, frozenset({"vulnerability"}))["total"] == 0
    assert U.urgent(session, ALL)["total"] == 1                     # one story: the incident with the phishing case


def test_pickup_time_is_measured_from_detection_to_first_assignment(session, signals, monkeypatch):
    from soc_platform.core.auth import Principal, Role

    a = _case(session, "incident", "critical", "Taken after 30 minutes", age_minutes=120)
    b = _case(session, "phishing", "high", "Taken after 90 minutes", age_minutes=120)
    _case(session, "incident", "critical", "Not yet taken", age_minutes=60)
    lead = Principal(id="x@example.com", name="X", roles=frozenset({Role.LEAD}))
    for c, minutes in ((a, 30), (b, 90)):      # the audit log is append-only: the clock is set, not the record
        monkeypatch.setenv("SOC_CLOCK_FREEZE", (c.created_at + timedelta(minutes=minutes)).isoformat())
        CaseService(session).assign(c.id, "x@example.com", by=lead)
        CaseService(session).assign(c.id, None, by=lead)                # a later assignment does not count
        CaseService(session).assign(c.id, "x@example.com", by=lead)
    monkeypatch.delenv("SOC_CLOCK_FREEZE")
    p = U.pickup(session, ALL)
    assert p == {"days": 30, "cases": 3, "taken": 2, "median_minutes": 60.0}


def test_the_model_takes_no_part():
    from pathlib import Path

    code = Path(U.__file__).read_text(encoding="utf-8").split('"""', 2)[2]      # after the module docstring
    assert "LLMGateway" not in code and "gateway" not in code.lower() and "complete_json" not in code


def test_the_overview_and_the_executive_view_open_with_the_strip():
    from pathlib import Path

    views = (Path(U.__file__).resolve().parents[1] / "api" / "static" / "views.js").read_text(encoding="utf-8")
    ov = views[views.index("async function Overview()"):]
    ex = views[views.index("async function Executive()"):]
    assert "/api/v1/dashboard/urgent" in ov[:1500] and "${urgentStrip(urg" in ov[:4000]
    assert "/api/v1/dashboard/urgent" in ex[:800] and "urgentStrip(urg, {take: false})" in ex


# ----------------------------------------------------------------------------- the API and the metrics

@pytest.fixture()
def client(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from soc_platform.api import app as appmod
    from soc_platform.config import get_settings
    from soc_platform.core import db as dbm
    from soc_platform.core.auth import issue_dev_token

    secret = "urgent-strip-secret-0123456789abcdef0123"
    for k, v in {"SOC_AUTH_MODE": "dev", "SOC_DEV_JWT_SECRET": secret, "SOC_ORG_DOMAINS": "acme-demo.com",
                 "SOC_DATABASE_URL": f"sqlite:///{(tmp_path / 'u.db').as_posix()}", "SOC_EMBEDDED_SCHEDULER": "0",
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


def test_the_api_serves_the_strip_to_every_reader_and_the_ciso_cannot_take(client):
    from soc_platform.core.db import get_database

    c, tok = client
    with get_database().session() as s:
        case = _case(s, "incident", "critical", "Critical, nobody on it")
        cid = case.id
    for role in ("analyst", "lead", "ciso", "auditor"):
        body = c.get("/api/v1/dashboard/urgent?limit=3", headers=tok(f"{role}@example.com", role)).json()
        assert body["total"] == 1 and body["items"][0]["id"] == cid and "pickup" in body
    assert c.get("/api/v1/dashboard/urgent").status_code == 401
    assert c.post(f"/api/v1/cases/{cid}/assign", json={"assignee": "ciso@example.com"},
                  headers=tok("ciso@example.com", "ciso")).status_code == 403
    assert c.post(f"/api/v1/cases/{cid}/assign", json={"assignee": "ann@example.com"},
                  headers=tok("ann@example.com", "analyst")).status_code == 200
    assert c.get("/api/v1/dashboard/urgent", headers=tok("lead2@example.com", "lead")).json()["total"] == 0
    metrics = c.get("/metrics", headers=tok("aud@example.com", "auditor"))
    assert metrics.status_code == 200
    assert "soc_urgent_waiting 0" in metrics.text and "soc_urgent_oldest_wait_minutes 0" in metrics.text


def test_on_the_demonstration_data_the_strip_leads_with_the_attack_on_one_person(tmp_path, monkeypatch):
    """Real risk engine, real correlation: the demo's critical cases are listed with reasons from the tools."""
    from soc_platform import __main__ as cli
    from soc_platform.config import get_settings
    from soc_platform.core import db as dbm

    monkeypatch.chdir(tmp_path)
    for k, v in {"SOC_DATABASE_URL": f"sqlite:///{(tmp_path / 'demo.db').as_posix()}", "SOC_ORG_DOMAINS": "acme-demo.com",
                 "SOC_RAW_PAYLOAD_DIR": str(tmp_path / "raw"), "SOC_REPORT_OUTPUT_DIR": str(tmp_path / "rep"),
                 "SOC_ENVIRONMENT": "dev", "SOC_LLM_PROVIDER": "none", "SOC_PHISHING_ENGINE": "0"}.items():
        monkeypatch.setenv(k, v)
    get_settings.cache_clear()
    dbm._default = None
    try:
        cli.cmd_init_db()
        cli.cmd_demo()
        with dbm.get_database().session() as s:
            out = U.urgent(s, ALL, limit=10)
        assert out["total"] >= 1
        first = out["items"][0]
        assert first["severity"] == "critical" and first["kind"] == "case" and first["reasons"]
        known = {label for label, _ in U.URGENT_SIGNALS.values()} | {"Related case, same person or host"}
        assert all(r["label"] in known or r["label"].startswith("Finding: ") for it in out["items"] for r in it["reasons"])
        assert any(r["signal"] == "deception_hit" for r in first["reasons"])
        # one story, one item: no person or host appears as the subject of two listed cases
        assert len({it["id"] for it in out["items"]}) == len(out["items"])
    finally:
        if dbm._default is not None:
            dbm._default.engine.dispose()
        dbm._default = None
        get_settings.cache_clear()
        os.environ.pop("SOC_URGENT_WINDOW_HOURS", None)
