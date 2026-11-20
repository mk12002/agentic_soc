"""Dome Score: CyberDome's posture figure. Each pillar is computed in code from the records and can be recomputed by
hand; the weights a lead sets decide only how much each pillar counts; every change of weights is versioned and
audited; a pillar that cannot be read never takes the score down; the console's preview saves nothing."""

from __future__ import annotations

from datetime import timedelta

import pytest

from soc_platform.connectors.registry import ConnectorRegistry
from soc_platform.core.audit import AuditLog
from soc_platform.core.auth import Principal, Role
from soc_platform.core.models import AuditRecord, Case, Entity, utcnow
from soc_platform.intelligence import dome_score as D


def _seed(s):
    """4 hosts (one with an open P1, one with an open P3, one whose P1 is remediated), 2 people, 2 cloud resources (one
    with an open high misconfiguration), 5 malicious reports (1 clicked, 1 outside the 90-day window), cases: one open
    critical, one open high, one closed critical."""
    from soc_platform.domains.phishing.models import Submission
    from soc_platform.domains.vulnerability.models import CloudMisconfiguration, ConsolidatedFinding

    now = utcnow()
    hosts = [Entity(kind="asset", display_name=f"srv-{i}") for i in range(4)]
    people = [Entity(kind="identity", display_name=f"p{i}@acme-demo.com") for i in range(2)]
    s.add_all(hosts + people)
    s.flush()
    s.add_all([ConsolidatedFinding(asset_id=hosts[0].id, cve="CVE-2026-1001", status="open", priority_band="P1"),
               ConsolidatedFinding(asset_id=hosts[1].id, cve="CVE-2026-1002", status="open", priority_band="P3"),
               ConsolidatedFinding(asset_id=hosts[2].id, cve="CVE-2026-1003", status="remediated", priority_band="P1")])
    s.add_all([CloudMisconfiguration(resource_id=hosts[3].id, rule="public bucket", severity="high", status="open"),
               CloudMisconfiguration(resource_id=hosts[2].id, rule="open port", severity="critical", status="closed")])
    for i, (clicked, age) in enumerate([(["a@acme-demo.com"], 0), ([], 1), ([], 2), ([], 30), (["b@acme-demo.com"], 200)]):
        s.add(Submission(source="upload", source_ref=f"dome:{i}", received_at=now - timedelta(days=age),
                         mime_sha256="0" * 64, status="escalated", verdict="malicious", analysis={"clicked": clicked}))
    s.add_all([Case(domain="incident", title="c1", severity="critical", status="open"),
               Case(domain="incident", title="c2", severity="high", status="awaiting_approval"),
               Case(domain="incident", title="c3", severity="critical", status="closed")])
    s.flush()


@pytest.fixture()
def reg():
    return ConnectorRegistry.from_file()


def _pillar(d, key):
    return next(p for p in d["pillars"] if p["key"] == key)


def test_each_pillar_is_the_published_count_of_the_records(session, reg):
    _seed(session)
    d = D.dome_score(session, reg)
    assert (_pillar(d, "vulnerability")["score"], _pillar(d, "vulnerability")["detail"]) == (75, "3 of 4 hosts")
    assert _pillar(d, "identity")["score"] == 100 and _pillar(d, "identity")["detail"] == "2 of 2 people"
    assert _pillar(d, "cloud")["score"] == 50                      # the closed critical does not count against
    assert _pillar(d, "email")["detail"] == "3 of 4 malicious or suspicious reports with no click"   # 200-day one out
    assert _pillar(d, "response")["score"] == 100 - D.CRITICAL_PENALTY - D.HIGH_PENALTY
    assert all(p["formula"] and p["link"].startswith("#/") and p["module"].startswith("Dome ") for p in d["pillars"])


def test_the_score_is_the_weighted_average_of_the_pillar_scores_shown(session, reg):
    _seed(session)
    d = D.dome_score(session, reg)
    used = [p for p in d["pillars"] if p["counted"]]
    assert d["score"] == round(sum(p["weight"] * p["score"] for p in used) / sum(p["weight"] for p in used))
    assert abs(sum(p["contribution"] for p in used) - d["score"]) <= 0.5 + 0.05 * len(used)
    assert d["band"] == next(b for t, b in D.BANDS if d["score"] >= t)


def test_weights_change_how_pillars_count_never_a_pillars_own_figure(session, reg):
    _seed(session)
    base = D.dome_score(session, reg)
    only_vuln = D.dome_score(session, reg, {k: (100 if k == "vulnerability" else 0) for k in D.PILLARS})
    assert only_vuln["score"] == _pillar(base, "vulnerability")["score"] == 75 and only_vuln["preview"]
    assert [p["score"] for p in only_vuln["pillars"]] == [p["score"] for p in base["pillars"]]
    no_resp = D.dome_score(session, reg, {"response": 0})
    assert not _pillar(no_resp, "response")["counted"] and _pillar(no_resp, "response")["score"] == 77


def test_a_pillar_without_data_is_left_out_and_the_others_share_its_weight():
    measured = {k: {"score": 80, "detail": "", "good": 4, "total": 5} for k in D.PILLARS}
    measured["cloud"] = {"score": None, "detail": "No cloud resources on record yet", "good": 0, "total": 0}
    measured["email"]["score"] = 20
    out = D.combine(measured, dict(D.DEFAULT_WEIGHTS))
    w = {k: v for k, v in D.DEFAULT_WEIGHTS.items() if k != "cloud"}
    assert out["score"] == round((sum(w.values()) * 80 - w["email"] * 60) / sum(w.values()))
    assert not _pillar(out, "cloud")["counted"] and abs(sum(p["share_pct"] for p in out["pillars"]) - 100) < 0.5
    assert D.combine({k: {**v, "score": None} for k, v in measured.items()}, dict(D.DEFAULT_WEIGHTS))["band"] == "no data"


@pytest.mark.parametrize("bad", [{"nope": 5}, {"identity": -1}, {"identity": 101}, {"identity": True},
                                 {"identity": 1.5}, {k: 0 for k in D.PILLARS}, ["identity"]])
def test_weights_are_whole_numbers_for_known_pillars_and_not_all_zero(session, reg, bad):
    with pytest.raises(ValueError):
        D.dome_score(session, reg, bad)


def test_only_a_person_who_is_a_lead_sets_weights_and_every_change_is_versioned_and_audited(session, reg):
    store = D.WeightStore(session)
    with pytest.raises(PermissionError):
        store.save({"identity": 50}, Principal(id="alice", name="alice", roles=frozenset({Role.ANALYST})))
    with pytest.raises(PermissionError):   # a service key never decides how the headline figure is weighted
        store.save({"identity": 50}, Principal(id="svc", name="svc", roles=frozenset({Role.LEAD}), is_service=True))
    lead = Principal(id="lena", name="lena", roles=frozenset({Role.LEAD}))
    store.save({"identity": 50, "email": 0}, lead, "board asked for identity first")
    assert store.active() == {**D.DEFAULT_WEIGHTS, "identity": 50, "email": 0}
    assert D.dome_score(session, reg)["weights_version"]["set_by"] == "lena"
    rec = session.query(AuditRecord).filter(AuditRecord.event_type == "dome_score.weights_changed").one()
    assert rec.payload["changes"] == {"identity": {"from": 20, "to": 50}, "email": {"from": 10, "to": 0}}
    assert AuditLog(session).verify()["ok"]
    store.save({}, lead, "back to the defaults")
    assert store.active() == D.DEFAULT_WEIGHTS and len(store.history()) == 2


def test_a_pillar_that_cannot_be_read_does_not_take_the_score_down(session, reg, monkeypatch):
    _seed(session)

    def broken(_s):
        raise RuntimeError("scanner table unreadable")
    monkeypatch.setattr(D, "_vulnerability", broken)
    d = D.dome_score(session, reg)
    assert _pillar(d, "vulnerability")["score"] is None and "Unavailable" in _pillar(d, "vulnerability")["detail"]
    assert d["score"] is not None and not _pillar(d, "vulnerability")["counted"]


def test_the_api_shows_the_score_to_all_domain_readers_previews_without_saving_and_lets_a_lead_save(tmp_path, request):
    import os

    from fastapi.testclient import TestClient

    from soc_platform.config import get_settings
    from soc_platform.core import db as dbm

    keys = {"SOC_AUTH_MODE": "dev", "SOC_DEV_JWT_SECRET": "dome-test-secret-0123456789abcdef0123456789",
            "SOC_DATABASE_URL": f"sqlite:///{(tmp_path / 'd.db').as_posix()}", "SOC_ORG_DOMAINS": "acme-demo.com",
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
        return {"Authorization": "Bearer " + c.get(f"/api/v1/dev/token?user={user}&roles={roles}&domains={domains}").json()["token"]}

    lead, analyst, vm_only = tok("lena", "lead"), tok("alice", "analyst"), tok("vic", "analyst", "vulnerability")
    with dbm.get_database().session() as s:
        _seed(s)
        s.commit()
    d = c.get("/api/v1/dome-score", headers=analyst).json()
    assert d["weights"] == D.DEFAULT_WEIGHTS and d["weights_version"] is None and len(d["pillars"]) == len(D.PILLARS)
    assert c.get("/api/v1/dome-score", headers=vm_only).status_code == 403         # it spans every domain
    only_vuln = {k: (100 if k == "vulnerability" else 0) for k in D.PILLARS}
    pv = c.post("/api/v1/dome-score/preview", headers=analyst, json={"weights": only_vuln}).json()
    assert pv["score"] == 75 and pv["preview"]
    assert c.get("/api/v1/dome-score/history", headers=analyst).json()["versions"] == []     # a preview saves nothing
    assert c.put("/api/v1/dome-score/weights", headers=analyst, json={"weights": only_vuln}).status_code == 403
    assert c.put("/api/v1/dome-score/weights", headers=lead, json={"weights": {"identity": 500}}).status_code == 400
    saved_r = c.put("/api/v1/dome-score/weights", headers=lead, json={"weights": only_vuln, "note": "patching first"})
    assert saved_r.status_code == 200 and saved_r.json()["score"] == 75
    after = c.get("/api/v1/dome-score", headers=analyst).json()
    assert after["weights"] == only_vuln and after["weights_version"]["note"] == "patching first"
    assert c.get("/api/v1/dome-score/history", headers=analyst).json()["versions"][0]["set_by"] == "lena"
