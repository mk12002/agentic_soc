"""Tuning: a lead's request becomes a checked draft rule, is previewed on past data, applies only after a
second lead approves it, and is held back by guardrails no rule can switch off."""

from __future__ import annotations

from collections import Counter
from datetime import timedelta

import pytest

from soc_platform.connectors.base import SyncRunner
from soc_platform.connectors.registry import ConnectorRegistry
from soc_platform.core.auth import Principal, Role
from soc_platform.core.cases import CaseService
from soc_platform.core.context_store import ContextStore
from soc_platform.core.models import AuditRecord, Case, Disposition, Entity, utcnow
from soc_platform.core.tuning import (
    DEFAULT_THRESHOLD,
    TuningRule,
    TuningStore,
    alert_facts,
    clean_params,
    draft,
    known_detections,
    preview,
    qa_sampled,
)
from soc_platform.domains.incident.service import IncidentService
from soc_platform.tests.conftest import person
from soc_platform.tests.test_watchlists import client  # noqa: F401 - the module-scoped API client fixture

LEAD1 = person("lead.one@example.com", Role.LEAD)
LEAD2 = person("lead.two@example.com", Role.LEAD)
ANALYST = person("ana@example.com", Role.ANALYST)
SERVICE_LEAD = Principal("svc", "svc", frozenset({Role.LEAD}), is_service=True)


@pytest.fixture()
def world(session):
    reg = ConnectorRegistry.all_fake()
    runner = SyncRunner(session, ContextStore(session))
    for name, stream in [("crowdstrike", "hosts"), ("defender_endpoint", "machines"), ("entra", "users"),
                         ("crowdstrike", "vulnerabilities"), ("rapid7", "findings")]:
        runner.sync(reg.get(name), stream)
    svc = IncidentService(session, reg)
    svc.ingest()
    _scanner_noise(session)
    return svc


NOISE = "Port scan from the vulnerability scanner"


def _scanner_noise(session, n=4):
    """Low-severity alerts on hosts with no known vulnerability - the noise a lead tunes away."""
    from soc_platform.core.schema import EntityRef, NormalizedRecord

    newest = max(e.first_seen for e in session.query(Entity).filter(Entity.kind == "alert"))
    store = ContextStore(session)
    for i in range(n):
        store.ingest(NormalizedRecord(
            kind="alert", tool="crowdstrike", source_type="alert", source_id=f"scan-{i}", title=NOISE, severity="low",
            observed_at=newest - timedelta(days=2 * i, hours=1),
            refs=[EntityRef(kind="asset", role="host", keys={"crowdstrike_aid": f"aid-scan-{i}"},
                            attributes={"hostname": f"scan-node-{i:02d}"})]))
    session.flush()


def _previews(session, svc, cap="medium"):
    return {d: preview(session, svc.store, "suppress_detection", {"detection": d, "max_severity": cap},
                       kev_cves=svc.kev_cves()) for d in known_detections(session)}


def _suppressible(session, svc):
    """A detection the guardrails let a rule suppress, read from the data (no sample names hard-coded)."""
    return next(d for d, pv in _previews(session, svc).items() if pv["would_suppress"])


def _activate(session, kind, params, reason="noise"):
    st = TuningStore(session)
    row = st.propose(kind, params, LEAD1, reason=reason)
    return st.approve(row.id, LEAD2)


def _alerts_of(session, case):
    from soc_platform.core.models import CaseEntity
    return [session.get(Entity, ln.entity_id) for ln in session.query(CaseEntity).filter_by(case_id=case.id, role="alert")]


# ---------------------------------------------------------------------------------------------- approval


def test_a_rule_applies_only_after_a_second_lead_approves_it(session, world):
    det = _suppressible(session, world)
    st = TuningStore(session)
    row = st.propose("suppress_detection", {"detection": det, "max_severity": "medium"}, LEAD1, reason="scanner noise")
    assert row.status == "proposed" and st.active_suppressions() == []
    with pytest.raises(PermissionError, match="second lead"):
        st.approve(row.id, LEAD1)
    st.approve(row.id, LEAD2)
    assert [r.id for r in st.active_suppressions()] == [row.id]
    assert row.expires_at is not None
    cases = world.cluster()
    tuned = [c for c in cases if c.attributes.get("tuning_rule") == row.id]
    assert tuned and all(t.title.startswith(det) for t in tuned)
    for c in tuned:   # suppressed as noise, or kept open as the QA sample - never both, never neither
        if c.attributes["tuning_qa"]:
            assert c.status != "closed" and not c.attributes["suppressed"]
        else:
            assert c.status == "closed" and c.verdict == "suppressed_noise" and f"#{row.id}" in c.summary
    events = {e.event_type for e in session.query(AuditRecord).filter_by(subject_type="tuning_rule")}
    assert {"tuning.proposed", "tuning.activated"} <= events


def test_only_leads_tune_and_never_through_an_api_key(session, world):
    det = _suppressible(session, world)
    st = TuningStore(session)
    for who in (ANALYST, SERVICE_LEAD):
        with pytest.raises(PermissionError):
            st.propose("suppress_detection", {"detection": det}, who, reason="x")
    row = st.propose("suppress_detection", {"detection": det}, LEAD1, reason="x")
    with pytest.raises(PermissionError):
        st.approve(row.id, ANALYST)
    with pytest.raises(ValueError, match="say why"):
        st.propose("suppress_detection", {"detection": det}, LEAD1, reason=" ")


def test_a_rule_names_only_detections_seen_and_never_high_severity(session, world):
    det = next(iter(known_detections(session)))
    bad = [({"detection": "Nothing like this"}, "no alert titled"),
           ({"detection": det, "max_severity": "high"}, "never suppressed"),
           ({"detection": det, "host": "*"}, "not only wildcards"),
           ({"detection": det, "host": "a;b"}, "pattern"),
           ({"detection": det, "tool": "nosuchtool"}, "no alert from tool"),
           ({"detection": det, "expires_days": 400}, "expires_days"),
           ({"detection": det, "colour": "red"}, "unknown setting")]
    for params, msg in bad:
        with pytest.raises(ValueError, match=msg):
            clean_params(session, "suppress_detection", params)
    with pytest.raises(ValueError, match="benign_percent"):
        clean_params(session, "noise_threshold", {"benign_percent": 40})
    # a title is matched whatever its case and stored as the platform wrote it
    assert clean_params(session, "suppress_detection", {"detection": det.upper()})["detection"] == det


# ---------------------------------------------------------------------------------------------- guardrails


def test_guardrails_keep_high_severity_deception_and_kev_host_alerts(session, world):
    previews = _previews(session, world)
    facts = alert_facts(session, world.store, session.query(Entity).filter(Entity.kind.in_(["alert", "deception"])).all())
    by_title = {f["title"]: f for f in facts.values()}
    for det, pv in previews.items():
        f = by_title[det]
        if f["deception"] or f["sev"] > 2:
            assert pv["would_suppress"] == 0 and pv["kept_by_guardrails"], det
    assert any("KEV" in k for pv in previews.values() for k in pv["kept_by_guardrails"])
    # rules for every detection at the highest cap: nothing high, critical or deception is closed by a rule
    for det in previews:
        _activate(session, "suppress_detection", {"detection": det, "max_severity": "medium"})
    for c in world.cluster():
        if c.attributes.get("tuning_rule"):
            assert c.severity in ("informational", "low", "medium") and not c.attributes["deception"]
            assert not any(a.kind == "deception" for a in _alerts_of(session, c))


def test_a_threat_found_in_what_a_rule_suppressed_pauses_the_rule(session, world):
    det = _suppressible(session, world)
    row = _activate(session, "suppress_detection", {"detection": det, "max_severity": "medium"})
    case = next(c for c in world.cluster() if c.attributes.get("tuning_rule") == row.id)
    CaseService(session).decide(case.id, ANALYST, verdict="true_positive", reasoning="it was real")
    assert row.status == "paused" and case.id in row.decision_note
    assert TuningStore(session).active_suppressions() == []
    assert session.query(AuditRecord).filter_by(event_type="tuning.paused", subject_id=str(row.id)).count() == 1


def test_a_benign_ruling_leaves_the_rule_running(session, world):
    det = _suppressible(session, world)
    row = _activate(session, "suppress_detection", {"detection": det, "max_severity": "medium"})
    case = next(c for c in world.cluster() if c.attributes.get("tuning_rule") == row.id)
    CaseService(session).decide(case.id, ANALYST, verdict="false_positive")
    assert row.status == "active"


def test_revoked_and_expired_rules_stop_at_once(session, world):
    det = _suppressible(session, world)
    st = TuningStore(session)
    row = _activate(session, "suppress_detection", {"detection": det})
    with pytest.raises(ValueError, match="say why"):
        st.revoke(row.id, LEAD1, "")
    st.revoke(row.id, LEAD1, "too broad")          # stopping a rule needs one lead, even its proposer
    assert st.active_suppressions() == [] and st.status_of(row) == "revoked"
    with pytest.raises(ValueError, match="cannot be revoked"):
        st.revoke(row.id, LEAD2, "again")
    other = _activate(session, "suppress_detection", {"detection": det, "expires_days": 1})
    other.expires_at = utcnow() - timedelta(minutes=1)
    assert st.active_suppressions() == [] and st.status_of(other) == "expired"
    assert not any(c.attributes.get("tuning_rule") for c in world.cluster())


def test_one_suppression_in_ten_stays_open_for_review_and_the_choice_is_stable():
    sets = [[f"alert-{i}", f"other-{i}"] for i in range(2000)]
    picked = [qa_sampled(s) for s in sets]
    assert 0.07 < sum(picked) / len(picked) < 0.13
    assert picked == [qa_sampled(list(reversed(s))) for s in sets]       # order of the alerts does not matter


# ---------------------------------------------------------------------------------------------- noise threshold


def test_the_noise_threshold_a_lead_sets_changes_what_counts_as_noise(session, world):
    det = next(iter(known_detections(session)))
    for i, verdict in enumerate(["false_positive"] * 3 + ["true_positive"]):
        session.add(Disposition(domain="incident", subject_type="case", subject_id=f"c{i}", system_verdict="x",
                                system_confidence=0.5, analyst_verdict=verdict, analyst="a", detection_source=det))
    session.flush()
    st = TuningStore(session)
    assert st.threshold() == DEFAULT_THRESHOLD                     # 3 of 4 benign = 75%: below the default 80%
    pv = preview(session, world.store, "noise_threshold", {"benign_percent": 70, "min_decisions": 4, "days": 30})
    assert det in [d["detection"] for d in pv["newly_noise"]] and det not in pv["noisy_now"]
    first = _activate(session, "noise_threshold", {"benign_percent": 70, "min_decisions": 4, "days": 30})
    assert st.threshold() == {"benign_percent": 70, "min_decisions": 4, "days": 30}
    second = _activate(session, "noise_threshold", {"benign_percent": 90, "min_decisions": 3, "days": 30})
    assert first.status == "superseded" and second.status == "active" and st.threshold()["benign_percent"] == 90


# ---------------------------------------------------------------------------------------------- drafting


class _FakeModel:
    def __init__(self, answer):
        self.answer = answer

    def complete_json(self, workflow, system, user, **kw):
        assert workflow == "tuning.draft" and "REQUEST:" in user
        return self.answer


def test_a_drafted_rule_keeps_only_what_the_request_says_and_what_the_data_holds(session, world):
    det = next(iter(known_detections(session)))
    request = f"Too much noise from {det} on the scan-* servers, mute it for 30 days"
    out = draft(session, request, _FakeModel({"kind": "suppress_detection", "detection": det.lower(), "host": "scan-*",
                                              "user": "boss@example.com", "max_severity": "critical",
                                              "expires_days": 30, "tool": ["crowdstrike"]}))
    assert out["drafted_by"] == "llm"
    p = out["params"]
    assert p["detection"] == det and p["host"] == "scan-*" and p["expires_days"] == 30
    assert p["user"] is None and any("user pattern was dropped" in n for n in out["notes"])   # not in the request
    assert p["max_severity"] == "low" and p["tool"] is None                                  # not allowed / not a word
    invented = draft(session, request, _FakeModel({"kind": "suppress_detection", "detection": "Made up alert",
                                                   "expires_days": 365}))
    assert invented["params"]["detection"] is None and invented["params"]["expires_days"] == 90
    th = draft(session, "make the noise threshold 70 percent", _FakeModel({"kind": "noise_threshold",
                                                                            "benign_percent": 70, "min_decisions": 9}))
    assert th["params"]["benign_percent"] == 70 and th["params"]["min_decisions"] == DEFAULT_THRESHOLD["min_decisions"]


def test_without_the_model_the_platform_reads_the_request_itself(session, world):
    det = next(iter(known_detections(session)))
    out = draft(session, f"suppress {det} on web* hosts, medium too, for 30 days", None)
    assert out["drafted_by"] == "rules" and out["kind"] == "suppress_detection"
    assert out["params"] == {"detection": det, "host": "web*", "tool": None, "max_severity": "medium",
                             "expires_days": 30}
    th = draft(session, "noise threshold: 85% benign over 5 decisions in 60 days", None)
    assert th["kind"] == "noise_threshold"
    assert {k: th["params"][k] for k in DEFAULT_THRESHOLD} == {"benign_percent": 85, "min_decisions": 5, "days": 60}
    assert session.query(TuningRule).count() == 0                  # a draft stores nothing


def test_suggestions_come_from_analysts_decisions_and_drop_once_a_rule_covers_them(session, world):
    from soc_platform.core.tuning import suggestions

    det = _suppressible(session, world)
    for i in range(3):
        session.add(Disposition(domain="incident", subject_type="case", subject_id=f"s{i}", system_verdict="x",
                                system_confidence=0.5, analyst_verdict="false_positive", analyst="a",
                                detection_source=det))
    session.flush()
    sug = suggestions(session)
    assert [s["detection"] for s in sug] == [det] and sug[0]["draft"]["params"]["detection"] == det
    _activate(session, "suppress_detection", sug[0]["draft"]["params"])
    assert suggestions(session) == []


def test_case_counts_follow_the_rule(session, world):
    det = _suppressible(session, world)
    row = _activate(session, "suppress_detection", {"detection": det, "max_severity": "medium"})
    world.cluster()
    d = TuningStore(session).as_dict(row)
    n = session.query(Case).filter(Case.domain == "incident").count()
    assert 1 <= d["applied"] + d["qa_samples"] <= n


def test_a_host_pattern_narrows_the_rule_to_the_hosts_it_names(session, world):
    all_hosts = preview(session, world.store, "suppress_detection", {"detection": NOISE})
    one = preview(session, world.store, "suppress_detection", {"detection": NOISE, "host": "SCAN-NODE-00*"})
    none = preview(session, world.store, "suppress_detection", {"detection": NOISE, "host": "web*"})
    assert all_hosts["would_suppress"] == 4 and one["would_suppress"] == 1 and none["matching_alerts"] == 0
    assert one["examples"][0]["hosts"][0].lower().startswith("scan-node-00")


# ---------------------------------------------------------------------------------------------- the API


def test_the_console_api_runs_the_whole_lifecycle_with_two_leads(client):  # noqa: F811 - the imported fixture
    from soc_platform.tests.test_watchlists import tok

    lead1, lead2 = tok(client, "lead.one", "lead"), tok(client, "lead.two", "lead")
    analyst = tok(client, "ana", "analyst")
    view = client.get("/api/v1/tuning", headers=analyst).json()
    det = view["detections"][0]["title"]
    assert view["threshold"] == DEFAULT_THRESHOLD and view["rules"] == []
    body = {"kind": "suppress_detection", "params": {"detection": det}, "reason": "noise"}
    for path in ("/api/v1/tuning/draft", "/api/v1/tuning/preview", "/api/v1/tuning"):
        assert client.post(path, headers=analyst, json=body | {"request": "mute " + det}).status_code == 403
    d = client.post("/api/v1/tuning/draft", headers=lead1, json={"request": f"mute {det} for 30 days"}).json()
    assert d["params"]["detection"] == det and d["params"]["expires_days"] == 30
    pv = client.post("/api/v1/tuning/preview", headers=lead1, json=body).json()
    assert pv["matching_alerts"] >= 1
    assert client.post("/api/v1/tuning/preview", headers=lead1,
                       json=body | {"params": {"detection": "No such alert"}}).status_code == 422
    rule = client.post("/api/v1/tuning", headers=lead1, json=body).json()
    assert rule["status"] == "proposed" and rule["preview"]["matching_alerts"] == pv["matching_alerts"]
    assert client.post(f"/api/v1/tuning/{rule['id']}/approve", headers=lead1, json={}).status_code == 403
    assert client.post(f"/api/v1/tuning/{rule['id']}/approve", headers=lead2, json={}).json()["status"] == "active"
    assert client.post(f"/api/v1/tuning/{rule['id']}/approve", headers=lead2, json={}).status_code == 409
    assert client.post(f"/api/v1/tuning/{rule['id']}/frobnicate", headers=lead2, json={}).status_code == 404
    assert client.post(f"/api/v1/tuning/{rule['id']}/revoke", headers=lead1, json={"note": "done"}).json()["status"] == "revoked"
    assert [r["status"] for r in client.get("/api/v1/tuning", headers=analyst).json()["rules"]] == ["revoked"]


def test_an_unknown_or_impossible_rule_id_is_not_found(client):  # noqa: F811 - the imported fixture
    from soc_platform.tests.test_watchlists import tok

    lead = tok(client, "lead.three", "lead")
    for rid in ("999999", "00000000000000000000000000000000", "-1"):
        assert client.post(f"/api/v1/tuning/{rid}/approve", headers=lead, json={}).status_code == 404


# ---------------------------------------------------------------------------------------------- raise attention


def _investigated(world, session):
    cases = world.cluster()
    return {c.id: world.investigate(c.id, narrate=False)["case"] for c in cases if c.status != "closed"}


def test_raising_attention_moves_severity_but_not_the_verdict(session, world):
    with pytest.raises(ValueError, match="hosts or users"):
        clean_params(session, "raise_severity", {"levels": 1})
    with pytest.raises(ValueError, match="levels"):
        clean_params(session, "raise_severity", {"host": "scan-*", "levels": 3})
    row = _activate(session, "raise_severity", {"host": "scan-node-0*", "levels": 1})
    views = _investigated(world, session)
    raised = [c for c in session.query(Case).filter(Case.domain == "incident")
              if (c.attributes or {}).get("tuning_raise") == row.id]
    assert raised and all(NOISE in c.title for c in raised)
    for c in raised:
        f = c.assessment["scoring"]["raised_by_tuning_rule"]
        assert f["rule"] == row.id and f["to"] == c.severity and f["from"] != f["to"]
        # judged on the unraised (low) severity: the raise alone never makes it a threat or a review item
        assert views[c.id]["verdict"] == "likely_benign"
    others = [c for c in session.query(Case).filter(Case.domain == "incident") if c not in raised]
    assert all(not (c.attributes or {}).get("tuning_raise") for c in others)
    assert TuningStore(session).as_dict(row)["applied"] == len(raised)


def test_a_revoked_raise_no_longer_applies_when_the_incident_is_reassessed(session, world):
    row = _activate(session, "raise_severity", {"host": "scan-node-0*"})
    _investigated(world, session)
    case = next(c for c in session.query(Case) if (c.attributes or {}).get("tuning_raise") == row.id)
    raised = case.severity
    TuningStore(session).revoke(row.id, LEAD1, "quarter closed")
    world.investigate(case.id, narrate=False)
    assert case.severity != raised and not case.attributes.get("tuning_raise")
    assert "raised_by_tuning_rule" not in case.assessment["scoring"]


# ---------------------------------------------------------------------------------------------- exercise


def test_an_exercise_is_labelled_never_suppressed_and_kept_out_of_the_noise_statistics(session, world):
    with pytest.raises(ValueError, match="expires_days"):
        clean_params(session, "exercise", {"host": "scan-*", "expires_days": 31})
    assert clean_params(session, "exercise", {"host": "scan-*"})["expires_days"] == 7
    _activate(session, "suppress_detection", {"detection": NOISE, "max_severity": "medium"})
    ex = _activate(session, "exercise", {"host": "scan-node-0*", "expires_days": 5})
    cases = [c for c in world.cluster() if (c.attributes or {}).get("exercise") == ex.id]
    assert cases and all(c.title.startswith("[Exercise] ") for c in cases)
    assert all(c.status != "closed" and not c.attributes.get("suppressed") and "tuning_rule" not in c.attributes
               for c in cases)
    d = CaseService(session).decide(cases[0].id, ANALYST, verdict="false_positive", reasoning="the red team")
    assert d.detection_source is None
    assert TuningStore(session).as_dict(ex)["applied"] == len(cases)


# ---------------------------------------------------------------------------------------------- phishing auto-close


def _hist(rows):
    return [{"verdict": v, "confidence": c, "clicked": k, "gateway_flagged": g, "analyst": a} for v, c, k, g, a in rows]


def test_the_auto_close_preview_counts_what_would_close_and_what_analysts_ruled_a_threat():
    from soc_platform.core.tuning import autoclose_effect

    h = _hist([("safe", 0.9, False, False, "benign"), ("safe", 0.72, False, False, "malicious"),
               ("spam", 0.65, False, False, "undecided"), ("safe", 0.95, True, False, "benign"),
               ("safe", 0.95, False, True, "benign"), ("malicious", 0.99, False, False, "malicious")])
    assert autoclose_effect(h, 70) == {"closed": 2, "threats": 1}       # clicked / gateway-flagged never close
    assert autoclose_effect(h, 60) == {"closed": 3, "threats": 1}
    assert autoclose_effect(h, 75) == {"closed": 1, "threats": 0}


def test_the_platform_suggests_the_lowest_confidence_that_would_have_missed_no_ruled_threat():
    from soc_platform.core.tuning import autoclose_suggestion

    few = _hist([("safe", 0.72, False, False, "malicious")] * 3)
    assert autoclose_suggestion(few, 70) is None                         # too few decisions to say
    h = _hist([("safe", 0.72, False, False, "malicious")] + [("safe", 0.9, False, False, "benign")] * 12)
    s = autoclose_suggestion(h, 70)
    assert s["min_confidence_percent"] == 75 and s["now"]["threats"] == 1 and s["would_auto_close"] == 12
    assert autoclose_suggestion(h, 75) is None                           # already there


def test_an_approved_auto_close_rule_is_what_the_phishing_service_uses(session):
    from soc_platform.domains.phishing.service import tuned_auto_close

    assert (tuned_auto_close(session).min_confidence, tuned_auto_close(session).sample_rate) == (0.7, 0.1)
    st = TuningStore(session)
    row = st.propose("phishing_autoclose", {"min_confidence_percent": 85, "sample_percent": 20}, LEAD1, reason="fewer")
    assert tuned_auto_close(session).min_confidence == 0.7                # not before a second lead approves
    st.approve(row.id, LEAD2)
    assert (tuned_auto_close(session).min_confidence, tuned_auto_close(session).sample_rate) == (0.85, 0.2)
    with pytest.raises(ValueError, match="min_confidence_percent"):
        clean_params(session, "phishing_autoclose", {"min_confidence_percent": 40})


def test_a_lead_tunes_only_the_domains_their_role_covers(session, world):
    incident_lead = Principal("il", "il", frozenset({Role.LEAD}), domains=frozenset({"incident"}))
    phishing_lead = Principal("pl", "pl", frozenset({Role.LEAD}), domains=frozenset({"phishing"}))
    st = TuningStore(session)
    with pytest.raises(PermissionError, match="phishing scope"):
        st.propose("phishing_autoclose", {"min_confidence_percent": 80}, incident_lead, reason="x")
    with pytest.raises(PermissionError, match="incident scope"):
        st.propose("exercise", {"host": "scan-*"}, phishing_lead, reason="x")
    row = st.propose("phishing_autoclose", {"min_confidence_percent": 80}, phishing_lead, reason="x")
    with pytest.raises(PermissionError):
        st.approve(row.id, incident_lead)
    st.approve(row.id, LEAD2)


def test_the_platform_reads_the_new_kinds_from_words_without_the_model(session, world):
    ex = draft(session, "Red-team exercise on fin-* hosts for the next 5 days", None)
    assert ex["kind"] == "exercise" and ex["params"]["host"] == "fin-*" and ex["params"]["expires_days"] == 5
    up = draft(session, "Finance servers fin-* matter more until quarter close, for 30 days", None)
    assert up["kind"] == "raise_severity" and up["params"]["host"] == "fin-*" and up["params"]["levels"] == 1
    assert up["params"]["expires_days"] == 30
    who = draft(session, "watch cfo@example.com closely, two levels", None)
    assert who["kind"] == "raise_severity" and who["params"]["user"] == "cfo@example.com" and who["params"]["levels"] == 2
    ac = draft(session, "auto-close phishing reports only at 85% confidence and check 1 in 5", None)
    assert ac["kind"] == "phishing_autoclose"
    assert {k: ac["params"][k] for k in ("min_confidence_percent", "sample_percent")} == {"min_confidence_percent": 85,
                                                                                         "sample_percent": 20}


def test_the_console_api_previews_phishing_auto_close_on_the_analysed_reports(client):  # noqa: F811 - the imported fixture
    from soc_platform.tests.test_watchlists import tok

    lead = tok(client, "lead.four", "lead")
    view = client.get("/api/v1/tuning", headers=lead).json()
    assert view["autoclose"] == {"min_confidence_percent": 70, "sample_percent": 10}
    assert set(view["may_propose"]) == {"suppress_detection", "noise_threshold", "raise_severity", "exercise",
                                        "phishing_autoclose", "vuln_priority", "action_demote"}
    pv = client.post("/api/v1/tuning/preview", headers=lead,
                     json={"kind": "phishing_autoclose", "params": {"min_confidence_percent": 95}}).json()
    assert pv["reports"] >= 1 and pv["auto_closed_after"] <= pv["auto_closed_now"]
    scoped = tok(client, "lead.five", "lead", "incident")
    assert client.post("/api/v1/tuning/preview", headers=scoped,
                       json={"kind": "phishing_autoclose", "params": {}}).status_code == 403
    assert client.get("/api/v1/tuning", headers=scoped).json()["autoclose"] is None


def test_assessing_an_incident_again_does_not_stack_boosts(session, world):
    # each assessment starts from the alerts' own severity: the KEV boost and a raise apply once, however often an
    # incident is re-assessed (re-assessment once started from the last scored severity and climbed each time)
    _activate(session, "raise_severity", {"host": "scan-node-0*"})
    first = {cid: v["severity"] for cid, v in _investigated(world, session).items()}
    again = {cid: world.investigate(cid, narrate=False)["case"]["severity"] for cid in first}
    assert again == first


def test_a_draft_says_when_the_model_did_not_answer(session, world):
    # the endpoint's content filter refuses prompt-injection attempts (seen live: HTTP 400, jailbreak detected)
    out = draft(session, f"suppress {NOISE} on scan-* hosts", _FakeModel(None))
    assert out["drafted_by"] == "rules" and out["params"]["detection"] == NOISE
    assert any("did not answer" in n for n in out["notes"])
    assert not any("did not answer" in n for n in draft(session, f"suppress {NOISE}", None)["notes"])   # model off


# ---------------------------------------------------------------------------------------------- vulnerability priority


@pytest.fixture()
def vm(session):
    from soc_platform.domains.vulnerability.service import VulnerabilityService

    svc = VulnerabilityService(session, ConnectorRegistry.all_fake())
    svc.refresh()
    return svc


CVSS_HEAVY = {"weight_cvss": 60, "weight_epss": 0, "weight_kev": 20, "weight_exposure": 10, "weight_criticality": 10,
              "sla_p1": 5, "sla_p2": 10, "sla_p3": 45, "sla_p4": 120}


def test_vulnerability_priority_weights_and_slas_are_checked(session):
    for bad, msg in [({**CVSS_HEAVY, "weight_epss": 5}, "add up to 100"),
                     ({**CVSS_HEAVY, "sla_p3": 8}, "must not shrink"),
                     ({**CVSS_HEAVY, "weight_cvss": 70, "weight_kev": 10}, "weight_cvss"),
                     ({**CVSS_HEAVY, "sla_p1": 45, "sla_p2": 45, "sla_p3": 45}, "sla_p1")]:
        with pytest.raises(ValueError, match=msg):
            clean_params(session, "vuln_priority", bad)
    assert clean_params(session, "vuln_priority", {})["weight_cvss"] == 30          # the defaults when nothing is said


def test_a_vulnerability_priority_rule_moves_bands_as_previewed_and_keeps_kev_exposed_findings_p1(session, vm):
    from soc_platform.domains.vulnerability.models import ConsolidatedFinding
    from soc_platform.domains.vulnerability.service import VulnerabilityService

    before = {f.id: (f.priority_band, f.sla_due) for f in session.query(ConsolidatedFinding)}
    assert all("weights" not in (f.priority_factors or {}) for f in session.query(ConsolidatedFinding))
    pv = preview(session, vm.store, "vuln_priority", CVSS_HEAVY, vuln_preview=vm.priority_preview)
    assert pv["findings"] == len(before) and pv["bands_now"] == dict(sorted(Counter(b for b, _ in before.values()).items()))
    row = _activate(session, "vuln_priority", CVSS_HEAVY)
    VulnerabilityService(session, ConnectorRegistry.all_fake()).prioritise()
    after = {f.id: f for f in session.query(ConsolidatedFinding)}
    moved = sum(1 for i, f in after.items() if f.priority_band != before[i][0])
    assert moved == sum(pv["moves"].values()) and moved > 0
    assert pv["bands_after"] == dict(sorted(Counter(f.priority_band for f in after.values()).items()))
    for f in after.values():
        fac = f.priority_factors
        assert fac["weights"]["cvss"] == 60
        if fac["kev"] and f.internet_exposed:
            assert f.priority_band == "P1"                                # whatever the weights
        days = 5 if fac["kev"] else {"P1": 5, "P2": 10, "P3": 45, "P4": 120}[f.priority_band]
        assert (f.sla_due.replace(tzinfo=None) - f.first_seen.replace(tzinfo=None)).days == days
    TuningStore(session).revoke(row.id, LEAD1, "back to the defaults")
    VulnerabilityService(session, ConnectorRegistry.all_fake()).prioritise()
    assert {f.id: f.priority_band for f in session.query(ConsolidatedFinding)} == {i: b for i, (b, _) in before.items()}


def test_vulnerability_priority_is_a_vulnerability_leads_rule(session):
    incident_lead = Principal("il", "il", frozenset({Role.LEAD}), domains=frozenset({"incident"}))
    vuln_lead = Principal("vl", "vl", frozenset({Role.LEAD}), domains=frozenset({"vulnerability"}))
    with pytest.raises(PermissionError, match="vulnerability scope"):
        TuningStore(session).propose("vuln_priority", CVSS_HEAVY, incident_lead, reason="x")
    TuningStore(session).propose("vuln_priority", CVSS_HEAVY, vuln_lead, reason="x")


# ---------------------------------------------------------------------------------------------- usually rejected actions


def _rejected_history(session, world, n=5, action="endpoint.isolate", verdict="rejected"):
    """Past recommendations of one action on a scanner-noise incident, decided by analysts."""
    from soc_platform.core.models import ActionRequest

    case = (next((c for c in session.query(Case).filter(Case.domain == "incident") if NOISE in c.title), None)
            or next(c for c in world.cluster() if NOISE in c.title))
    for i in range(n):
        session.add(ActionRequest(action_type=action, params={}, targets=[], case_id=case.id, domain="incident",
                                  requested_by="agent:incident", idempotency_key=f"hist-{verdict}-{n}-{i}", status=verdict,
                                  approver=f"analyst{i}@example.com", decided_at=utcnow() - timedelta(days=i)))
    session.flush()
    return case


def test_actions_analysts_keep_rejecting_become_a_suggestion(session, world):
    from soc_platform.core.tuning import action_suggestions

    _rejected_history(session, world, n=4)
    assert action_suggestions(session) == []                             # 4 decisions: too few to say
    _rejected_history(session, world, n=1, verdict="approved")
    sug = action_suggestions(session)                                    # 4 of 5 rejected: 80 % - suggested
    assert [(s["action_type"], s["rejected"], s["decisions"]) for s in sug] == [("endpoint.isolate", 4, 5)]
    from soc_platform.core.models import ActionRequest

    session.add(ActionRequest(action_type="endpoint.isolate", params={}, targets=[], case_id=None, domain="incident",
                              requested_by="agent:incident", idempotency_key="hist-extra", status="approved",
                              approver="analyst9@example.com", decided_at=utcnow()))
    session.flush()
    # a decision on another context (no case, so no detection) neither joins nor dilutes this one
    assert [(s["action_type"], s["detection"], s["rejected"], s["decisions"]) for s in action_suggestions(session)] ==         [("endpoint.isolate", NOISE, 4, 5)]


def test_a_usually_rejected_action_is_still_recommended_but_never_autonomous_and_is_labelled(session, world):
    from soc_platform.core.cases import CaseService, Recommendation
    from soc_platform.core.policy import PolicyEngine
    from soc_platform.core.tuning import action_suggestions, demote_rule

    case = _rejected_history(session, world, n=6)
    sug = action_suggestions(session)
    assert [(s["domain"], s["action_type"], s["detection"]) for s in sug] == [("incident", "endpoint.isolate", NOISE)]
    pv = preview(session, world.store, "action_demote", sug[0]["draft"]["params"])
    assert pv["outcomes"]["rejected by an analyst"] == 6 and pv["approved_by_analysts"] == 0
    row = _activate(session, "action_demote", sug[0]["draft"]["params"])
    assert action_suggestions(session) == []                             # covered now
    target = [{"type": "host", "name": "scan-node-00"}]
    recs = [Recommendation("endpoint.isolate", target, "scanner noise", params={"why": "test"})]
    req = CaseService(session).recommend(case, recs, world.actions, PolicyEngine.for_session(session), agent="incident")[0]
    assert req.status in ("recommended", "blocked") and req.autonomy_level <= 2
    assert req.result["tuning_demoted"]["rule"] == row.id
    assert any(f"tuning rule #{row.id}" in r for r in req.policy_reasons)
    # a critical case keeps its normal handling, whatever analysts rejected before
    case.severity = "critical"
    assert demote_rule(session, case, "endpoint.isolate") is None
    case.severity = "low"
    other = next(c for c in session.query(Case).filter(Case.domain == "incident") if NOISE not in c.title)
    assert demote_rule(session, other, "endpoint.isolate") is None       # another detection is not in scope
    assert TuningStore(session).as_dict(row)["applied"] == 1


def test_an_action_rule_names_an_action_the_platform_has_recommended(session, world):
    _rejected_history(session, world, n=1)
    with pytest.raises(ValueError, match="action the platform has recommended"):
        clean_params(session, "action_demote", {"domain": "incident", "action_type": "endpoint.wipe_everything"})
    with pytest.raises(ValueError, match="domain"):
        clean_params(session, "action_demote", {"domain": "finance", "action_type": "endpoint.isolate"})
    with pytest.raises(ValueError, match="incident actions only"):
        clean_params(session, "action_demote", {"domain": "phishing", "action_type": "endpoint.isolate",
                                                "detection": NOISE})
    ok = clean_params(session, "action_demote", {"domain": "incident", "action_type": "endpoint.isolate", "tool": None})
    assert "tool" not in ok


def test_the_platform_reads_vulnerability_and_action_requests_without_the_model(session, world):
    _rejected_history(session, world, n=1)
    v = draft(session, "Vulnerability SLA: P1 in 5 days, P2 in 10 days; CVSS 50% and EPSS 15%", None)
    assert v["kind"] == "vuln_priority"
    assert (v["params"]["sla_p1"], v["params"]["sla_p2"], v["params"]["weight_cvss"], v["params"]["weight_epss"]) == (5, 10, 50, 15)
    assert any("add up to 100" in n for n in v["notes"])                 # 50 + 15 + 20 + 10 + 15 = 110
    a = draft(session, "Stop recommending isolate for the scanner incidents, analysts always reject it", None)
    assert a["kind"] == "action_demote" and a["params"]["action_type"] == "endpoint.isolate"
    assert a["params"]["domain"] == "incident"
