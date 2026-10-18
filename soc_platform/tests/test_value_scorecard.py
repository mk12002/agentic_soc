"""Value scorecard: every benefit KPI the customer was promised is computed from the platform's own records (or from
time-study figures a lead enters), compared with the organisation's baseline and target, and reported - never by the
model. Seeded with controlled timestamps so each figure is exact."""

from __future__ import annotations

from datetime import timedelta

import pytest

from soc_platform.core.models import ActionRequest, Case, Disposition, Entity, utcnow
from soc_platform.reporting import value as V


def _seed(s):
    """Two reported e-mails (handled in 60 and 120 minutes, one contained after 30), two incidents (decided after 2 and
    4 hours), one remediated P1 finding (10 days), one KEV finding past SLA, four dispositions (3 agree, 1 missed)."""
    from soc_platform.domains.phishing.models import Submission
    from soc_platform.domains.vulnerability.models import ConsolidatedFinding, VulnIntel

    now = utcnow()
    t0 = now - timedelta(days=3)
    for i, minutes in enumerate((60, 120)):
        c = Case(domain="phishing", title=f"p{i}", status="closed", created_at=t0, closed_at=t0 + timedelta(minutes=minutes))
        s.add(c)
        s.flush()
        s.add(Submission(source="upload", source_ref=f"seed:{i}", received_at=t0, case_id=c.id, mime_sha256="0" * 64,
                         status="closed"))
        if i == 0:
            s.add(ActionRequest(case_id=c.id, action_type="email.campaign_purge", requested_by="t", status="executed",
                                idempotency_key=f"seed-{i}", executed_at=t0 + timedelta(minutes=30), domain="phishing"))
    for i, hours in enumerate((2, 4)):
        c = Case(domain="incident", title=f"i{i}", status="open", created_at=t0)
        s.add(c)
        s.flush()
        s.add(Disposition(domain="incident", subject_type="case", subject_id=c.id, system_verdict="malicious",
                          analyst_verdict="true_positive", analyst="a", created_at=t0 + timedelta(hours=hours)))
    s.add(Disposition(domain="phishing", subject_type="case", subject_id="x1", system_verdict="safe",
                      analyst_verdict="safe", analyst="a", created_at=now))
    s.add(Disposition(domain="phishing", subject_type="case", subject_id="x2", system_verdict="safe",
                      analyst_verdict="malicious", analyst="a", created_at=now))            # a missed threat
    host = Entity(kind="asset", display_name="srv-1")
    s.add(host)
    s.flush()
    s.add(VulnIntel(cve="CVE-2026-0001", kev=True))
    s.add(ConsolidatedFinding(asset_id=host.id, cve="CVE-2026-1000", status="remediated", priority_band="P1",
                              first_seen=now - timedelta(days=12), closed_at=now - timedelta(days=2)))
    s.add(ConsolidatedFinding(asset_id=host.id, cve="CVE-2026-0001", status="open", priority_band="P2",
                              first_seen=now - timedelta(days=40), sla_due=now - timedelta(days=1)))
    s.flush()


def _kpi(sc, kid):
    return next(k for k in sc["kpis"] if k["id"] == kid)


def test_every_kpi_is_listed_with_its_source_and_nothing_is_claimed_without_data(session):
    sc = V.scorecard(session)
    assert [k["id"] for k in sc["kpis"]] == list(V.KPIS)
    assert all(k["source"] in {"platform", "time_study", "derived"} and k["measured_from"] for k in sc["kpis"])
    assert {k["status"] for k in sc["kpis"]} <= {"no_data", "no_baseline"}
    assert _kpi(sc, "capacity_freed_pct")["current"] is None and sc["automation_gate_open"] is False


def test_platform_measured_kpis_are_exact(session):
    _seed(session)
    sc = V.scorecard(session, days=30)
    assert _kpi(sc, "phishing_handling_minutes")["current"] == 90.0                       # median of 60 and 120
    assert _kpi(sc, "phishing_containment_minutes")["current"] == 30.0
    assert _kpi(sc, "incident_decision_hours")["current"] == 3.0                          # median of 2 and 4
    assert _kpi(sc, "vuln_mttr_days")["current"] == 10.0
    assert _kpi(sc, "findings_past_sla")["current"] == 1.0                                # KEV-listed, past SLA
    agree = _kpi(sc, "analyst_agreement_pct")
    assert agree["current"] == 75.0 and agree["supporting"]["missed_threats_pct"] == 25.0
    assert agree["status"] == "not_improved" or agree["status"] == "no_baseline"
    assert sc["automation_gate_open"] is False                                             # 75 % < 90 %, misses 25 %


def test_baselines_targets_and_status_against_them(session):
    _seed(session)
    V.set_input(session, "phishing_handling_minutes", "baseline", 240, note="ServiceNow Q1", by="lena")
    V.set_input(session, "incident_decision_hours", "baseline", 4, note="ServiceNow Q1", by="lena")
    V.set_input(session, "vuln_mttr_days", "baseline", 9, note="Rapid7 history", by="lena")
    sc = V.scorecard(session)
    ph = _kpi(sc, "phishing_handling_minutes")
    assert ph["target"] == 120.0 and ph["status"] == "met" and ph["change_pct"] == -62.5   # default target: -50 %
    inc = _kpi(sc, "incident_decision_hours")
    assert inc["target"] == 2.4 and inc["status"] == "improving"                          # 3 h: better, short of -40 %
    assert _kpi(sc, "vuln_mttr_days")["status"] == "not_improved"                         # 10 d vs 9 d
    V.set_input(session, "incident_decision_hours", "target", 3, note="agreed with the SOC", by="lena")
    assert _kpi(V.scorecard(session), "incident_decision_hours")["status"] == "met"         # a lead's own target wins
    assert V.scorecard(session)["statuses"]["met"] >= 2


def test_capacity_freed_is_derived_from_time_study_effort_and_platform_volume(session):
    _seed(session)
    V.set_input(session, "phishing_effort_minutes", "baseline", 40, note="time study wk 1-2", by="lena")
    V.set_input(session, "phishing_effort_minutes", "measured", 10, note="pilot time study", by="lena")
    V.set_input(session, "report_hours_per_week", "baseline", 10, note="time study", by="lena")
    V.set_input(session, "report_hours_per_week", "measured", 3, note="pilot", by="lena")
    V.set_input(session, "tier1_hours_per_month", "baseline", 320, note="2 analysts", by="lena")
    cap = _kpi(V.scorecard(session, days=30), "capacity_freed_pct")
    # 2 e-mails a month x 30 min saved = 1 h; reports 7 h/week x 52/12 = 30.33 h; total 31.33 h of 320 h
    assert cap["supporting"]["hours_freed_per_month"] == 31.3 and cap["current"] == 9.8 and cap["status"] == "no_baseline"
    rep = _kpi(V.scorecard(session), "report_hours_per_week")
    assert rep["current"] == 3.0 and rep["status"] == "met"                               # 3 h <= 10 h x 0.3


@pytest.mark.parametrize("args, message", [
    (("nonsense", "baseline", 1), "unknown"),
    (("vuln_mttr_days", "measured", 5), "measured by the platform"),
    (("vuln_mttr_days", "guess", 5), "kind"),
    (("vuln_mttr_days", "baseline", -1), "non-negative"),
    (("capacity_freed_pct", "target", 120), "100"),
    (("vuln_mttr_days", "baseline", float("nan")), "non-negative"),
])
def test_bad_inputs_are_refused(session, args, message):
    with pytest.raises(V.ValueInputError, match=message):
        V.set_input(session, *args, note="", by="lena")


def test_a_new_value_replaces_the_old_and_every_change_is_audited(session):
    from soc_platform.core.audit import AuditLog

    V.set_input(session, "vuln_mttr_days", "baseline", 9, note="first", by="lena")
    V.set_input(session, "vuln_mttr_days", "baseline", 12, note="corrected", by="omar")
    assert V.inputs(session)["vuln_mttr_days"]["baseline"]["value"] == 12.0
    events = AuditLog(session).query(event_type="value.input_set", subject_id="vuln_mttr_days")
    assert [e.payload["previous"] for e in events] == [9.0, None]                       # newest first


def test_api_scope_permissions_and_the_board_report(tmp_path, request):
    """Domain-scoped people see their domain's KPIs only; entering figures is a lead's, human and audited; the
    board pack carries the scorecard."""
    import os

    from fastapi.testclient import TestClient

    from soc_platform.config import get_settings
    from soc_platform.core import db as dbm

    keys = {"SOC_AUTH_MODE": "dev", "SOC_DEV_JWT_SECRET": "value-test-secret-0123456789abcdef012345",
            "SOC_DATABASE_URL": f"sqlite:///{(tmp_path / 'v.db').as_posix()}", "SOC_ORG_DOMAINS": "acme-demo.com",
            "SOC_ENVIRONMENT": "test", "SOC_EMBEDDED_SCHEDULER": "0", "SOC_REPORT_OUTPUT_DIR": str(tmp_path / "rep"),
            "SOC_RAW_PAYLOAD_DIR": str(tmp_path / "raw")}
    saved, saved_db = {k: os.environ.get(k) for k in keys}, dbm._default

    def restore():
        for k, v in saved.items():
            os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)
        dbm._default = saved_db
        get_settings.cache_clear()
    request.addfinalizer(restore)
    os.environ.update(keys)
    get_settings.cache_clear()
    dbm._default = None
    from soc_platform.api import app as appmod

    appmod.registry.cache_clear()
    c = TestClient(appmod.app)

    def tok(user, roles, domains="*"):
        url = f"/api/v1/dev/token?user={user}&roles={roles}&domains={domains}"
        return {"Authorization": "Bearer " + c.get(url).json()["token"]}

    lead, analyst = tok("lena", "lead"), tok("alice", "analyst")
    vm_only = tok("vic", "analyst", "vulnerability")
    full = c.get("/api/v1/value/scorecard", headers=lead).json()
    assert [k["id"] for k in full["kpis"]] == list(V.KPIS) and full["inputs"]
    scoped = c.get("/api/v1/value/scorecard", headers=vm_only).json()
    assert {k["id"] for k in scoped["kpis"]} == {"vuln_mttr_days", "findings_past_sla", "report_hours_per_week"}
    assert scoped["inputs"] == {}
    body = {"kpi": "vuln_mttr_days", "kind": "baseline", "value": 21, "note": "Rapid7 history"}
    assert c.put("/api/v1/value/inputs", headers=analyst, json=body).status_code == 403
    assert c.put("/api/v1/value/inputs", headers=lead, json=body).status_code == 200
    assert c.put("/api/v1/value/inputs", headers=lead, json={**body, "kind": "measured"}).status_code == 400
    assert _kpi(c.get("/api/v1/value/scorecard", headers=lead).json(), "vuln_mttr_days")["baseline"] == 21.0
    b = c.post("/api/v1/reports/build", headers=lead, json={"template_id": "board_monthly"}).json()
    sec = next(x for x in b["sections"] if x["source"] == "value")
    assert dict(sec["facts"])["Period (days)"] == "30"
