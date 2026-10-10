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
    ("entra", "user", "jane.doe@acme-demo.com", "1 suspicious inbox rule"),
    ("umbrella", "domain", "login.micros0ft-helpdesk.com", "2 allowed"),
    ("canary", "ip", "10.20.1.15", "DECEPTION HIT"),
    ("delinea_secret_server", "user", "jane.doe@acme-demo.com", "SAP-Prod-Finance-Service"),
    ("delinea_privilege_manager", "user", "jane.doe@acme-demo.com", "1 denied"),
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
    rows = reg.status(probe=True)
    assert {r["name"] for r in rows} >= EXPECTED
    assert all(r["health"]["ok"] for r in rows if r["enabled"])


def test_every_connector_health_probe_passes_in_fixture_mode(reg):
    for name in sorted(EXPECTED):
        h = reg.get(name).health()
        assert h["ok"], (name, h)


def test_health_probe_reports_failure_without_leaking_secrets():
    from soc_platform.connectors.http import FixtureTransport
    from soc_platform.connectors.tools._common import _redact

    reg = ConnectorRegistry.all_fake()
    conn = reg.get("rapid7")
    conn.http = FixtureTransport([{"method": "GET", "path": ".*", "status": 503}], "rapid7")
    h = conn.health()
    assert h["ok"] is False and h["error"]
    assert "k3y" not in _redact("GET https://x/api?apikey=k3y&a=1 Bearer abc.def") and "***" in _redact("?token=zz")


def test_mde_findbyip_sends_a_timestamp(reg):
    r = reg.get("defender_endpoint").lookup("ip", "10.20.1.15")
    assert r.ok and r.records, r  # fixture only answers when an ISO timestamp is present


def test_rapid7_and_wiz_cve_lookups_return_affected_assets(reg):
    r7 = reg.get("rapid7").lookup("cve", "CVE-2021-44228")
    assert r7.ok and r7.signals["affected_assets"] >= 1 and r7.records
    wz = reg.get("wiz").lookup("cve", "cve-2021-44228")
    assert wz.ok and wz.signals["findings"] == 1 and wz.signals["assets"] == ["web01"]
    assert reg.get("wiz").lookup("cve", "CVE-1999-0001").signals["findings"] == 0


def test_wiz_lookup_follows_pagination():
    from soc_platform.connectors.http import FixtureTransport

    conn = ConnectorRegistry.all_fake().get("wiz")
    node = lambda i: {"id": f"v{i}", "name": "CVE-2021-44228", "vulnerableAsset": {"name": "web01"}}
    conn.http = FixtureTransport([
        {"method": "POST", "path": "^/graphql$", "body_contains": '"after": null',
         "body": {"data": {"vulnerabilityFindings": {"nodes": [node(1)], "pageInfo": {"hasNextPage": True, "endCursor": "c2"}}}}},
        {"method": "POST", "path": "^/graphql$", "body_contains": '"after": "c2"',
         "body": {"data": {"vulnerabilityFindings": {"nodes": [node(2)], "pageInfo": {"hasNextPage": False}}}}}], "wiz")
    r = conn.lookup("host", "web01")
    assert r.signals["findings"] == 2 and r.signals["truncated"] is False


def test_jira_uses_enhanced_search_with_page_tokens():
    from soc_platform.connectors.http import FixtureTransport

    conn = ConnectorRegistry.all_fake().get("jira")
    issue = lambda i: {"id": str(i), "key": f"SEC-{i}", "fields": {"summary": "x", "status": {"name": "Done"}}}
    conn.http = FixtureTransport([
        {"method": "GET", "path": "^/rest/api/3/search/jql$", "params": {"nextPageToken": "t2"},
         "body": {"issues": [issue(2)], "isLast": True}},
        {"method": "GET", "path": "^/rest/api/3/search/jql$", "params": {"nextPageToken": "!"},
         "body": {"issues": [issue(1)], "isLast": False, "nextPageToken": "t2"}}], "jira")
    p1 = conn.fetch_page("tickets", None)
    p2 = conn.fetch_page("tickets", p1.next_cursor)
    assert [i["key"] for i in p1.records + p2.records] == ["SEC-1", "SEC-2"] and p1.more and not p2.more


def test_exchange_admin_calls_use_their_own_token_audience():
    from soc_platform.connectors.http import Response, RoutingTransport

    seen = []

    class Rec:
        def __init__(self, tag):
            self.tag = tag

        def request(self, method, path, **kw):
            seen.append((self.tag, path))
            return Response(200, {})

    rt = RoutingTransport(Rec("graph"), {"https://outlook.office365.com": Rec("exo")})
    rt.request("POST", "https://outlook.office365.com/adminapi/beta/t/InvokeCommand")
    rt.request("GET", "/v1.0/users")
    assert seen == [("exo", "https://outlook.office365.com/adminapi/beta/t/InvokeCommand"), ("graph", "/v1.0/users")]
    from soc_platform.connectors.tools import defender_office365 as mdo
    assert mdo.MANIFEST.live_transport is mdo._live


def test_entra_reports_azure_role_assignments_from_resource_manager(reg):
    """'Azure Identity & Access': who holds which Azure role, directly or through a group, on each subscription -
    read from Azure Resource Manager with its own token audience alongside Graph."""
    entra = reg.get("entra")
    bob = entra.identity_context("bob.lee@acme-demo.com")
    assert bob["azure_roles"][0]["role"] == "Owner" and bob["azure_roles"][0]["privileged"]
    assert bob["azure_privileged"] == ["Owner on Acme Production"] and bob["azure_error"] is None
    jane = entra.identity_context("jane.doe@acme-demo.com")
    assert jane["azure_roles"] == [{"role": "Contributor", "privileged": True, "subscription": "Acme Production",
                                    "scope": jane["azure_roles"][0]["scope"], "via": "group",
                                    "scope_name": "Acme Production (resourceGroups/finance-apps)"}]
    raj = entra.identity_context("raj.mehta@acme-demo.com")
    assert [r["role"] for r in raj["azure_roles"]] == ["Reader"] and raj["azure_privileged"] == []
    assert entra.identity_context("priya.nair@acme-demo.com")["azure_roles"] == []
    # the lookup an investigation uses carries it, and the ARM calls went to the Azure API paths
    look = entra.lookup("user", "bob.lee@acme-demo.com")
    assert look.ok and look.signals["azure_privileged_roles"] == ["Owner on Acme Production"]
    assert "Azure roles: Owner on Acme Production" in look.summary
    arm_calls = [c for c in entra.http.calls if c["path"].startswith("/subscriptions")]
    assert arm_calls and all(c["params"]["api-version"] for c in arm_calls)


def test_entra_identity_context_survives_azure_being_unreadable(reg, monkeypatch):
    entra = reg.get("entra")
    real_get = entra.get

    def get(path, **kw):
        if "management.azure.com" in path:
            raise PermissionError("403: the app has no Reader role on the subscriptions")
        return real_get(path, **kw)

    monkeypatch.setattr(entra, "get", get)
    ctx = entra.identity_context("jane.doe@acme-demo.com")
    assert ctx["azure_roles"] is None and "Reader role" in ctx["azure_error"]
    assert ctx["privileged_roles"] == [] and len(ctx["suspicious_inbox_rules"]) == 1          # the rest still works
    look = entra.lookup("user", "jane.doe@acme-demo.com")
    assert look.ok and "Azure role assignments unavailable" in look.summary


def test_entra_reads_only_the_configured_subscriptions_when_given(reg, monkeypatch):
    entra = reg.get("entra")
    monkeypatch.setitem(entra.settings, "azure_subscriptions", "11111111-2222-3333-4444-000000000002")
    raj = entra.identity_context("raj.mehta@acme-demo.com")
    assert [(r["role"], r["subscription"]) for r in raj["azure_roles"]] == [("Reader", "11111111-2222-3333-4444-000000000002")]
    assert entra.identity_context("bob.lee@acme-demo.com")["azure_roles"] == []    # production not configured


def test_avanan_reads_message_details_from_the_entity_not_the_event(reg):
    # HEC security events name their e-mail only by entityId; sender, recipients and subject live on the entity
    c = reg.get("avanan")
    page = c.fetch_page("security_events", None)
    [rec] = c.normalize("security_events", page.records[0])
    assert rec.severity == "low"                                  # HEC severity "2"
    assert rec.attributes["subject"] and rec.attributes["internet_message_id"]
    roles = {r.role for r in rec.refs}
    assert roles == {"sender", "recipient"}


def test_avanan_overall_verdict_is_the_worst_engine_verdict():
    from soc_platform.connectors.tools.avanan import overall_verdict
    assert overall_verdict({"ap": "clean", "av": "malicious", "dlp": None}) == "malicious"
    assert overall_verdict({"ap": "spam", "av": "clean"}) == "spam"
    assert overall_verdict({"ap": "clean", "dlp": None}) == "clean"
    assert overall_verdict({}) is None


def test_rapid7_verify_tls_false_from_the_environment_really_turns_verification_off():
    from soc_platform.connectors.tools.rapid7 import _truthy
    assert _truthy(True) and _truthy("true") and _truthy("1")
    assert not _truthy("false") and not _truthy("0") and not _truthy(False) and not _truthy(" No ")


def test_generic_siem_field_map_works_from_an_environment_variable():
    from soc_platform.connectors.tools.siem import _field_map
    assert _field_map('{"id": "alert_id", "title": "rule_name"}') == {"id": "alert_id", "title": "rule_name"}
    assert _field_map({"id": "alert_id"}) == {"id": "alert_id"} and _field_map("") == {} and _field_map(None) == {}


def test_processes_calling_a_tool_split_its_request_budget(monkeypatch):
    """Each process holds its own budget: with N of them, each takes 1/N so the vendor sees the configured rate."""
    one = ConnectorRegistry.all_fake().get("crowdstrike").budget
    monkeypatch.setenv("SOC_CONNECTOR_RATE_SHARE", "4")
    four = ConnectorRegistry.all_fake().get("crowdstrike").budget
    assert four.rate == pytest.approx(one.rate / 4) and four.capacity == max(1, one.capacity // 4)
    monkeypatch.setenv("SOC_CONNECTOR_RATE_SHARE", "many")             # unreadable: no split (and config check says so)
    assert ConnectorRegistry.all_fake().get("crowdstrike").budget.rate == pytest.approx(one.rate)


def test_microsoft_apps_can_sign_in_with_a_certificate_instead_of_a_secret(monkeypatch):
    # Security reviews commonly require certificate credentials for app registrations: the token request then carries
    # a short-lived assertion signed with the certificate's key, and no shared secret ever leaves the platform.
    import base64
    import datetime as dt
    import hashlib

    import jwt
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    from soc_platform.connectors import http as h
    from soc_platform.connectors.base import ConnectorError
    from soc_platform.connectors.tools._microsoft import mde_transport

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "soc-connector")])
    now = dt.datetime.now(dt.UTC)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(now).not_valid_after(now + dt.timedelta(days=1)).sign(key, hashes.SHA256()))
    pem = (key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
           + cert.public_bytes(serialization.Encoding.PEM)).decode()

    sent = {}

    class Reply:
        status_code = 200

        @staticmethod
        def json():
            return {"access_token": "t0k", "expires_in": 3600}

    monkeypatch.setattr(h.httpx, "post", lambda url, data=None, **kw: sent.update(url=url, form=data) or Reply())
    settings = {"tenant_id": "tid", "client_id": "cid", "client_secret": None, "client_certificate": pem}
    transport = mde_transport(settings)
    assert transport.auth.token() == "t0k"
    form = sent["form"]
    assert "client_secret" not in form and form["client_assertion_type"].endswith("jwt-bearer")
    claims = jwt.decode(form["client_assertion"], cert.public_key(), algorithms=["RS256"], audience=sent["url"])
    assert claims["iss"] == claims["sub"] == "cid" and claims["exp"] - claims["iat"] == 600
    thumb = base64.urlsafe_b64encode(hashlib.sha1(cert.public_bytes(serialization.Encoding.DER)).digest()).decode()
    assert jwt.get_unverified_header(form["client_assertion"])["x5t"] == thumb.rstrip("=")

    with pytest.raises(ConnectorError, match="client_certificate"):
        mde_transport({"tenant_id": "tid", "client_id": "cid", "client_secret": None, "client_certificate": None})
    mde_transport({"tenant_id": "tid", "client_id": "cid", "client_secret": "s3cret", "client_certificate": None})


def test_internal_indicators_are_never_sent_to_outside_reputation_services(monkeypatch):
    # An incident names internal addresses and hosts, and reported mail links to the organisation's own sites: asking
    # VirusTotal, Shodan or AbuseIPDB about them would disclose the organisation's internal structure.
    from soc_platform.config import get_settings
    from soc_platform.connectors.tools.threat_intel import internal_indicator

    org = ["acme-demo.com"]
    for t, v in [("ip", "10.20.30.40"), ("ip", "192.168.1.5"), ("ip", "127.0.0.1"), ("ip", "fe80::1"), ("ip", "fd00::7"),
                 ("domain", "web01"), ("domain", "fs01.corp"), ("domain", "acme-demo.com"),
                 ("domain", "intranet.acme-demo.com"), ("url", "https://sharepoint.acme-demo.com/x?y=1"),
                 ("url", "http://10.1.1.1/admin"), ("url", "https://[fd00::1]/")]:
        assert internal_indicator(t, v, org), (t, v)
    for t, v in [("ip", "185.220.101.4"), ("domain", "micros0ft-helpdesk.com"), ("domain", "acme-demo.com.evil.io"),
                 ("url", "https://login.micros0ft-helpdesk.com/verify"), ("hash", "a3f5c0e1")]:
        assert internal_indicator(t, v, org) is None, (t, v)

    monkeypatch.setenv("SOC_ORG_DOMAINS", "acme-demo.com")
    get_settings.cache_clear()
    try:
        ti = ConnectorRegistry.all_fake().get("threat_intel")
        asked = []
        monkeypatch.setattr(ti, "_q", lambda *a, **k: asked.append(a) or {})
        result = ti.enrich("ip", "10.0.0.5")
        assert result["verdict"] == "not_checked" and result["withheld"] and asked == []
        assert "not sent to outside sources" in ti.lookup("domain", "intranet.acme-demo.com").summary
    finally:
        get_settings.cache_clear()
