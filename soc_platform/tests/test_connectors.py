"""Every connector, end to end in fixture mode: discovery, sync -> context store, lookups, actions."""

from __future__ import annotations

import pytest

from soc_platform.connectors.base import SyncRunner
from soc_platform.connectors.registry import ConnectorRegistry, discover, interpolate
from soc_platform.core.actions import ActionService
from soc_platform.core.auth import agent_principal
from soc_platform.core.context_store import ContextStore
from soc_platform.core.entity_resolution import EntityResolver
from soc_platform.core.policy import PolicyEngine

EXPECTED = {"crowdstrike", "defender_endpoint", "defender_office365", "entra", "rapid7", "wiz", "avanan", "umbrella",
            "canary", "delinea_secret_server", "delinea_privilege_manager", "nvd", "epss", "cisa_kev", "threat_intel",
            "servicenow", "jira", "cmdb_csv", "sentinel", "generic_siem"}


@pytest.fixture(scope="module")
def reg() -> ConnectorRegistry:
    return ConnectorRegistry.all_fake()


def test_every_tool_in_the_requirements_has_a_connector():
    found = discover()
    assert EXPECTED <= set(found), EXPECTED - set(found)
    for m in found.values():
        assert m.category and m.dimension and m.description


def test_live_mode_reports_missing_config():
    reg = ConnectorRegistry({"connectors": {"crowdstrike": {"enabled": True, "mode": "live", "settings": {}}}})
    problems = reg.validate("crowdstrike")
    assert any("client_id" in p for p in problems)


def test_secret_interpolation(monkeypatch):
    monkeypatch.setenv("CS_ID", "abc")
    assert interpolate({"a": "${CS_ID}", "b": "${MISSING:-dflt}"}) == {"a": "abc", "b": "dflt"}


def test_all_streams_sync_into_context_store(session, reg):
    store = ContextStore(session)
    runner = SyncRunner(session, store)
    for name in reg.enabled_names():
        c = reg.get(name)
        for stream in c.streams:
            if name in {"nvd"}:  # feed-only stream: consumed by lookups, not stored
                continue
            rep = runner.sync(c, stream)
            assert not rep.errors, (name, stream, rep.errors[:2])
            assert rep.failed == 0, (name, stream)


def test_cross_tool_asset_resolution_collapses_same_hosts(session, reg):
    store = ContextStore(session)
    runner = SyncRunner(session, store)
    for name, stream in [("crowdstrike", "hosts"), ("defender_endpoint", "machines"), ("rapid7", "assets"),
                         ("wiz", "resources"), ("servicenow", "cmdb")]:
        runner.sync(reg.get(name), stream)
    jane = store.find("asset", "crowdstrike_aid", "cs-aid-jane01")
    assert jane is not None
    assert store.find("asset", "mde_device_id", "mde-jane01").id == jane.id          # serial / fqdn match
    web_r7 = store.find("asset", "rapid7_asset_id", "101")
    web_wiz = store.find("asset", "wiz_id", "wiz-vm-web01")
    web_mde = store.find("asset", "mde_device_id", "mde-web01")
    assert web_r7 and web_wiz and web_mde and web_r7.id == web_mde.id
    rate = EntityResolver(session).match_rate("asset")
    assert rate["match_rate"] is not None and rate["match_rate"] >= 0.8
    # 5 real hosts (+ Canary node) regardless of how many tools reported them
    assert rate["canonical_entities"] <= 8


@pytest.mark.parametrize("name,etype,value,expect", [
    ("crowdstrike", "host", "JANE-LT01", "1 Falcon host"),
    ("defender_endpoint", "host", "jane-lt01", "MDE: 1 device"),
    ("entra", "user", "jane.doe@cci-demo.com", "1 suspicious inbox rule"),
    ("umbrella", "domain", "login.micros0ft-helpdesk.com", "2 allowed"),
    ("canary", "ip", "10.20.1.15", "DECEPTION HIT"),
    ("delinea_secret_server", "user", "jane.doe@cci-demo.com", "SAP-Prod-Finance-Service"),
    ("delinea_privilege_manager", "user", "jane.doe@cci-demo.com", "1 denied"),
    ("rapid7", "host", "web01", "Rapid7: 1 asset"),
    ("wiz", "host", "web01", "internet-exposed=True"),
    ("defender_office365", "domain", "login.micros0ft-helpdesk.com", "9 message"),
    ("avanan", "email_message", "<20260920090200.1111@micros0ft-helpdesk.com>", "verdict=clean"),
    ("threat_intel", "ip", "185.220.101.4", "malicious"),
    ("threat_intel", "hash", "a3f5c0e1b2d4f6a8c0e2b4d6f8a0c2e4b6d8f0a2c4e6b8d0f2a4c6e8b0d2f4a6", "MalwareBazaar"),
    ("nvd", "cve", "CVE-2021-44228", "CVSS 10.0"),
    ("epss", "cve", "CVE-2021-44228", "EPSS 0.976"),
    ("cisa_kev", "cve", "CVE-2024-21412", "is on CISA KEV"),
    ("servicenow", "host", "web01", "Web Platform"),
    ("cmdb_csv", "host", "db01", "Windows Server Team"),
])
def test_lookups(reg, name, etype, value, expect):
    res = reg.get(name).lookup(etype, value)
    assert res.ok, res.error
    assert expect in res.summary, res.summary


def test_lookup_failure_is_reported_not_raised(reg):
    res = reg.get("crowdstrike").lookup("hash", "")  # unknown route -> error captured
    assert res.source == "crowdstrike"


def test_actions_registry_routes_endpoint_isolation(session, reg, lead):
    actions = reg.action_registry()
    catalog = {a["action_type"] for a in actions.catalog()}
    for t in ["endpoint.isolate", "endpoint.release", "identity.revoke_sessions", "identity.disable_account",
              "dns.block_domain", "email.campaign_purge", "email.restore", "indicator.block", "pam.rotate_secret",
              "ticket.create", "canary.acknowledge", "email.reporter_feedback", "endpoint.collect_forensics"]:
        assert t in catalog, t
    svc = ActionService(session, actions, PolicyEngine())
    # A Defender-only host must route to MDE, a Falcon host to CrowdStrike.
    r1 = svc.request("endpoint.isolate", targets=[{"type": "asset", "id": "db01", "mde_device_id": "mde-db01"}],
                     requested_by=agent_principal("incident"))
    done = svc.approve(r1.id, lead)
    assert done.status == "executed" and done.result["provider"] == "defender_endpoint"
    r2 = svc.request("endpoint.isolate", targets=[{"type": "asset", "id": "jane", "crowdstrike_aid": "cs-aid-jane01"}],
                     requested_by=agent_principal("incident"))
    done2 = svc.approve(r2.id, lead)
    assert done2.result["provider"] == "crowdstrike"
    rb = svc.rollback(done2.id, lead, note="test")
    assert rb.status == "executed"
    calls = reg.instance("crowdstrike").transport.calls
    assert any(c["params"] == {"action_name": "lift_containment"} for c in calls)


def test_threat_intel_fusion_attributes_every_source(reg):
    e = reg.get("threat_intel").enrich("domain", "micros0ft-helpdesk.com")
    assert e["verdict"] == "malicious"
    assert {"virustotal", "otx", "urlhaus", "threatfox"} <= set(e["sources"])


def test_registry_status_lists_everything(reg):
    rows = reg.status()
    assert {r["name"] for r in rows} >= EXPECTED
    assert all(r["health"]["ok"] for r in rows if r["enabled"])
