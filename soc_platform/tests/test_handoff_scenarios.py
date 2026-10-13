"""The data handoff's acceptance scenarios and correlation rules (docs/DATA_HANDOFF_RECONCILIATION.md), checked on the
real pipelines. Scenarios already proven elsewhere are listed in that document with their tests; this file holds the
ones that needed their own check."""

from __future__ import annotations

import tempfile
from datetime import UTC, datetime, timedelta

from soc_platform.connectors.registry import ConnectorRegistry
from soc_platform.core.context_store import ContextStore
from soc_platform.core.models import ActionRequest, Case, CaseEntity, Entity, Evidence, UnresolvedItem
from soc_platform.core.schema import NormalizedRecord
from soc_platform.domains.incident.service import IncidentService
from soc_platform.domains.phishing.service import PhishingService

T0 = datetime(2026, 9, 20, 10, 0, tzinfo=UTC)


def _routes(conn, needle: str) -> list[dict]:
    return [r for _, rx, r in conn.http.routes if needle in rx.pattern or needle == r.get("body_contains")]


def _incidents(session, reg) -> IncidentService:
    im = IncidentService(session, reg)
    im.ingest()
    for c in im.cluster():
        if c.status != "closed":
            im.investigate(c.id)
    return im


def _asset(session, tool: str, sid: str, key: str, *, at: datetime, **attrs) -> None:
    ContextStore(session).ingest(NormalizedRecord(kind="asset", tool=tool, source_type="device", source_id=sid,
                                                  keys={key: sid}, attributes=attrs, observed_at=at))
    session.flush()


def _held_for_review(session, mde_id: str) -> None:
    """The second tool's record joined nothing: its id is on no device, and an analyst has it in the review queue."""
    store = ContextStore(session)
    assets = session.query(Entity).filter(Entity.kind == "asset").all()
    assert not [a for a in assets if store.keys_of(a.id).get("mde_device_id") == mde_id]
    assert session.query(UnresolvedItem).count() == 1


# ------------------------------------------------------------------ PHISH-01 (negative): a blocked click is no click


def test_a_blocked_click_never_counts_as_a_click_through(session):
    reg = ConnectorRegistry.all_fake()
    clicks = _routes(reg.get("defender_office365"), "UrlClickEvents | where Timestamp > ago(14d)")[0]["body"]["results"]
    blocked = sorted(c["AccountUpn"] for c in clicks if c["ActionType"] == "ClickBlocked" and not c["IsClickedThrough"])
    assert blocked, "the demo data must hold a blocked click"
    ph = PhishingService(session, reg, org_domains=["acme-demo.com"], raw_dir=tempfile.mkdtemp())
    sub = ph.ingest_reported()[0]
    ph.process(sub.id)
    case = session.query(Case).filter(Case.domain == "phishing").one()
    impact = case.assessment["user_impact"]
    for upn in blocked:
        assert upn not in impact["clicked"]
        assert impact["per_user"][upn]["click_blocked"] and not impact["per_user"][upn]["clicked"]


# ------------------------------------------------------------------ EDGE-01: tools disagree -> flagged, held for a person


def test_contradicting_edr_verdicts_are_flagged_and_every_action_waits_for_a_person(session):
    reg = ConnectorRegistry.all_fake()
    cs = reg.get("crowdstrike")
    alert = next(a for r in _routes(cs, "/alerts/entities/alerts/v2") for a in r["body"].get("resources", [])
                 if a["device"]["hostname"] == "JANE-LT01")
    alert.update(status="closed", tags=["false_positive"])           # Falcon closed it; Defender still reports it
    _incidents(session, reg)
    ent = session.query(Entity).filter(Entity.kind == "alert", Entity.display_name == alert["display_name"]).one()
    case_id = session.query(CaseEntity.case_id).filter(CaseEntity.entity_id == ent.id, CaseEntity.role == "alert").scalar()
    case = session.get(Case, case_id)
    conflict = case.assessment["verdict_conflict"]
    assert conflict and {r["tool"] for r in conflict["dismissed"]} == {"crowdstrike"}
    assert any(r["tool"] != "crowdstrike" for r in conflict["active"])
    ev = session.query(Evidence).filter(Evidence.case_id == case_id, Evidence.dimension == "verdict_conflict").one()
    assert ev.summary.startswith("Tools disagree") and "approval" in ev.summary
    actions = session.query(ActionRequest).filter(ActionRequest.case_id == case_id).all()
    assert actions and all(a.status in {"recommended", "pending_approval", "blocked"} for a in actions)
    assert all(a.autonomy_level <= 3 and any("tools disagree" in r for r in a.policy_reasons) for a in actions)


def test_the_demo_estate_has_no_verdict_conflict(session):
    _incidents(session, ConnectorRegistry.all_fake())
    assert not [c for c in session.query(Case).filter(Case.domain == "incident") if (c.assessment or {}).get("verdict_conflict")]


# ------------------------------------------------------------------ EDGE-01: a shared public IP never merges people


def test_people_sharing_a_public_ip_stay_separate(session):
    entra = ConnectorRegistry.all_fake().get("entra")
    store = ContextStore(session)
    for i, upn in enumerate(("analyst.demo@acme-demo.com", "other.demo@acme-demo.com")):
        raw = {"id": f"si-shared-{i}", "createdDateTime": f"2026-09-20T10:2{i}:00Z", "userPrincipalName": upn,
               "userId": f"u-shared-{i}", "appDisplayName": "Office", "ipAddress": "198.51.100.15",
               "status": {"errorCode": 0}, "riskLevelDuringSignIn": "none"}
        for rec in entra.normalize("signins", raw):
            store.ingest(rec)
    session.flush()
    people = [store.keys_of(e.id).get("upn") for e in session.query(Entity).filter(Entity.kind == "identity")]
    assert sorted(people) == ["analyst.demo@acme-demo.com", "other.demo@acme-demo.com"]   # two people, not one


# ------------------------------------------------------------------ device joins: never on a name or an IP alone


def test_a_device_seen_by_two_tools_joins_on_name_plus_address_at_the_same_time(session):
    """The handoff's rule for CrowdStrike device_id vs Defender DeviceId: not equivalent ids, so joined on host name plus
    inventory and time - here one unique name, the same address within the IP window and the same OS family."""
    _asset(session, "crowdstrike", "aid-demo-001", "crowdstrike_aid", at=T0, hostname="demo-laptop-01",
           os="Windows 11", ip="192.0.2.10")
    _asset(session, "defender_endpoint", "mde-demo-001", "mde_device_id", at=T0, hostname="demo-laptop-01",
           os="Windows 11", ip="192.0.2.10")
    assets = session.query(Entity).filter(Entity.kind == "asset").all()
    assert len(assets) == 1
    keys = ContextStore(session).keys_of(assets[0].id)
    assert keys["crowdstrike_aid"] == "aid-demo-001" and keys["mde_device_id"] == "mde-demo-001"   # both ids kept


def test_a_name_alone_never_joins_two_devices_it_goes_to_review(session):
    _asset(session, "crowdstrike", "aid-demo-001", "crowdstrike_aid", at=T0, hostname="demo-laptop-01", os="Windows 11")
    _asset(session, "defender_endpoint", "mde-demo-001", "mde_device_id", at=T0, hostname="demo-laptop-01",
           os="Windows 11")
    _held_for_review(session, "mde-demo-001")                 # name + OS scores 0.75: below the 0.85 auto threshold


def test_a_reused_name_and_address_at_a_different_time_go_to_review(session):
    """EDGE-02: a re-used short host name and DHCP address, ten days apart - never joined on name or IP alone."""
    _asset(session, "crowdstrike", "aid-demo-001", "crowdstrike_aid", at=T0, hostname="demo-laptop-01", ip="192.0.2.20")
    _asset(session, "defender_endpoint", "mde-demo-009", "mde_device_id", at=T0 + timedelta(days=10),
           hostname="demo-laptop-01", ip="192.0.2.20")
    _held_for_review(session, "mde-demo-009")                 # the address is outside the IP window: ignored


def test_a_reused_ip_at_a_different_time_never_joins_two_devices(session):
    _asset(session, "crowdstrike", "aid-demo-001", "crowdstrike_aid", at=T0, hostname="demo-laptop-01", ip="192.0.2.20")
    _asset(session, "crowdstrike", "aid-demo-002", "crowdstrike_aid", at=T0 + timedelta(days=10),
           hostname="demo-laptop-02", ip="192.0.2.20")
    assert session.query(Entity).filter(Entity.kind == "asset").count() == 2


# ------------------------------------------------------------------ threat indicator: hash equality, type kept


def test_one_file_hash_seen_by_two_tools_is_one_indicator_linked_to_both_alerts(session):
    from soc_platform.core.schema import EntityRef

    sha = "a" * 64
    store = ContextStore(session)
    for tool, value in (("crowdstrike", sha), ("defender_endpoint", sha.upper())):
        store.ingest(NormalizedRecord(kind="alert", tool=tool, source_type="alert", source_id=f"{tool}-alert-1",
                                      title="Synthetic suspicious execution", observed_at=T0, refs=[
                                          EntityRef(kind="indicator", role="observable", keys={"value": value},
                                                    attributes={"type": "sha256"})]))
    session.flush()
    hashes = session.query(Entity).filter(Entity.kind == "indicator").all()
    assert [h.canonical_key for h in hashes] == [f"sha256:{sha}"]     # one indicator, algorithm kept in the key
    alerts = {e.attributes.get("tool") for _, e in store.neighbors(hashes[0].id) if e.kind == "alert"}
    assert alerts == {"crowdstrike", "defender_endpoint"}


# ------------------------------------------------------------------ ticket evidence keeps the vendors' alert ids


def test_an_incident_ticket_carries_the_original_vendor_alert_ids(session):
    from soc_platform.core.models import SourceRecord

    _incidents(session, ConnectorRegistry.all_fake())
    tickets = session.query(ActionRequest).filter(ActionRequest.action_type == "ticket.create",
                                                  ActionRequest.domain == "incident").all()
    assert tickets
    known = {f"{t}:{s}" for t, s in session.query(SourceRecord.tool, SourceRecord.source_id)}   # alerts and deception hits
    for t in tickets:
        ids = t.params["source_alert_ids"]
        assert ids and set(ids) <= known                         # each is a real tool alert id, not a ticket number
        assert all(i in t.params["description"] for i in ids)


# ------------------------------------------------------------------ privileged identity: an approved admin -> person map


def test_an_admin_account_links_to_its_owner_only_through_the_approved_map(session):
    ss = ConnectorRegistry.all_fake().get("delinea_secret_server")
    ss.settings = {**ss.settings, "account_owners": '{"adm-jane": "jane.doe@acme-demo.com"}'}
    rec = {"secretAuditId": 1, "secretId": 42, "secretName": "Domain admin", "action": "CHECKOUT",
           "byUserName": "ACME\\adm-jane", "dateRecorded": "2026-09-20T10:25:00Z", "ipAddress": "192.0.2.10"}
    refs = ss.normalize("secret_audits", rec)[0].refs
    people = {r.role: r.keys for r in refs if r.kind == "identity"}
    assert people["user"] == {"sam": "adm-jane"}                         # the admin account stays its own identity
    assert people["human_owner"] == {"upn": "jane.doe@acme-demo.com"}   # and names its approved owner
    shared = ss.normalize("secret_audits", {**rec, "secretAuditId": 2, "byUserName": "ACME\\svc-backup"})[0].refs
    assert not [r for r in shared if r.role == "human_owner"]           # unmapped (shared) account: no owner guessed
    ss.settings = {k: v for k, v in ss.settings.items() if k != "account_owners"}
    assert not [r for r in ss.normalize("secret_audits", rec)[0].refs if r.role == "human_owner"]   # never from the name
