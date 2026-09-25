"""Incident Management domain, end to end on the fixture scenario."""

from __future__ import annotations

import pytest

from soc_platform.connectors.base import SyncRunner
from soc_platform.connectors.registry import ConnectorRegistry
from soc_platform.core.actions import ActionService
from soc_platform.core.cases import CaseService, agreement_report, detection_quality
from soc_platform.core.context_store import ContextStore
from soc_platform.core.models import Case
from soc_platform.domains.incident.service import IncidentService


@pytest.fixture()
def world(session):
    reg = ConnectorRegistry.all_fake()
    runner = SyncRunner(session, ContextStore(session))
    for name, stream in [("crowdstrike", "hosts"), ("defender_endpoint", "machines"), ("entra", "users"),
                         ("crowdstrike", "vulnerabilities"), ("rapid7", "findings")]:
        runner.sync(reg.get(name), stream)
    svc = IncidentService(session, reg)
    svc.ingest()
    return reg, svc


def _jane_case(session, cases):
    return next(c for c in cases if any("PowerShell" in t for t in [c.title]) or c.attributes.get("deception")
                and c.attributes.get("alert_count", 0) > 1)


def test_alerts_from_many_tools_cluster_into_one_incident(session, world):
    reg, svc = world
    cases = svc.cluster()
    jane = max(cases, key=lambda c: c.attributes["alert_count"])
    # CrowdStrike + Defender endpoint alerts, Entra risk, Canary deception all involve Jane / her laptop
    assert jane.attributes["alert_count"] >= 4
    assert {"crowdstrike", "defender_endpoint", "entra", "canary"} <= set(jane.attributes["tools"])
    assert jane.severity == "critical" and jane.attributes["deception"]
    # unrelated web01 / db01 alerts are separate incidents
    assert len(cases) >= 3


def test_investigation_builds_consolidated_context(session, world):
    reg, svc = world
    jane = max(svc.cluster(), key=lambda c: c.attributes["alert_count"])
    view = svc.investigate(jane.id)
    dims = set(view["evidence"])
    assert {"endpoint", "identity", "privileged_access", "dns", "deception", "threat_intel", "email"} <= dims
    assert view["completeness"]["complete"] is True
    assert view["case"]["severity"] == "critical" and view["case"]["verdict"] == "true_positive"
    tech = {m["technique"] for m in view["assessment"]["mitre"]}
    assert {"T1059.001", "T1039", "T1114.003", "T1078", "T1555"} <= tech
    assert view["assessment"]["scoring"]["kev_exposure_boost"] is True
    # every claim cites evidence
    assert all(c["evidence_ids"] for c in view["assessment"]["claims"])


def test_recommendations_are_ranked_gated_and_well_formed(session, world):
    reg, svc = world
    jane = max(svc.cluster(), key=lambda c: c.attributes["alert_count"])
    view = svc.investigate(jane.id)
    acts = {a["action_type"]: a for a in view["actions"]}
    assert acts["endpoint.isolate"]["status"] == "recommended"  # L2 by default: nothing auto-executes
    iso_target = acts["endpoint.isolate"]["targets"][0]
    assert iso_target["crowdstrike_aid"] == "cs-aid-jane01" and iso_target["mde_device_id"] == "mde-jane01"
    assert acts["identity.revoke_sessions"]["targets"][0]["upn"] == "jane.doe@acme-demo.com"
    assert acts["pam.rotate_secret"]["targets"][0]["secret_id"] == "42"
    blocked = [a["targets"][0]["value"] for a in view["actions"] if a["action_type"] == "dns.block_domain"]
    assert "login.micros0ft-helpdesk.com" in blocked and all("." in b for b in blocked)
    assert all(a["evidence_ids"] or a["action_type"] == "ticket.create" for a in view["actions"])
    assert view["actions"] == sorted(view["actions"], key=lambda a: a["priority"])
    assert view["case"]["status"] == "awaiting_approval"


def test_lead_approves_isolation_and_it_reaches_the_edr(session, world, lead):
    reg, svc = world
    jane = max(svc.cluster(), key=lambda c: c.attributes["alert_count"])
    view = svc.investigate(jane.id)
    iso = next(a for a in view["actions"] if a["action_type"] == "endpoint.isolate")
    done = ActionService(session, svc.actions, svc.policy).approve(iso["id"], lead, note="confirmed compromise")
    assert done.status == "executed" and done.result["provider"] == "crowdstrike"


def test_disposition_similar_incidents_handover_and_quality(session, world, analyst):
    reg, svc = world
    cases = svc.cluster()
    for c in cases:
        svc.investigate(c.id)
    jane = max(cases, key=lambda c: c.attributes["alert_count"])
    CaseService(session).decide(jane.id, analyst, verdict="true_positive", reasoning="payload + deception + token theft")
    other = next(c for c in cases if c.id != jane.id)
    CaseService(session).decide(other.id, analyst, verdict="false_positive", reasoning="benign admin activity")
    rep = agreement_report(session, "incident")
    assert rep["sample_size"] == 2
    hand = svc.handover(hours=24 * 365 * 5)
    assert hand["closed_this_shift"] == 2 and "open_by_severity" in hand
    assert isinstance(svc.similar(jane.id), list)
    assert isinstance(detection_quality(session, "incident", min_count=1), list)


def test_noisy_detection_is_suppressed(session, world, analyst):
    reg, svc = world
    from soc_platform.core.models import Disposition

    for i in range(3):
        session.add(Disposition(domain="incident", subject_type="case", subject_id=f"x{i}", system_verdict="needs_review",
                                analyst_verdict="false_positive", analyst="alice",
                                detection_source="Unusual outbound connection from web server"))
    session.flush()
    cases = svc.cluster()
    web = next(c for c in cases if "outbound" in c.title)
    assert web.attributes["suppressed"] is True and web.status == "closed"
    assert session.get(Case, web.id).verdict == "suppressed_noise"
