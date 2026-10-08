"""Connecting and administering tools: isolation, strict configuration, rollout stages, preflight, governed console
changes (propose -> approve -> in force without a restart), export / import, and the connector development kit.

Live stages are exercised offline: ``offline`` swaps a live connector's network transport for its vendor-shaped
fixtures (plus any faults a test injects), so the platform takes exactly the live code paths without a tenant.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from datetime import timedelta
from pathlib import Path

import pytest
import yaml

from soc_platform.connectors.config_schema import check_document, errors, load_file, load_yaml
from soc_platform.connectors.http import FixtureTransport
from soc_platform.connectors.preflight import run_preflight
from soc_platform.connectors.registry import (
    FIXTURES_DIR,
    ConfigError,
    ConnectorInstance,
    ConnectorRegistry,
    discover,
)
from soc_platform.core.auth import Principal, Role
from soc_platform.core.connector_config import ConfigRejected, ConfigStore
from soc_platform.core.models import ConnectorConfigVersion, ConnectorPreflight

ROOT = Path(__file__).resolve().parents[2]
ADMIN = Principal("ada@acme-demo.com", "Ada", frozenset({Role.AUTOMATION_ADMIN}))
LEAD = Principal("lena@acme-demo.com", "Lena", frozenset({Role.LEAD}))
LEAD2 = Principal("leo@acme-demo.com", "Leo", frozenset({Role.LEAD}))
SECRET = "S3cr3t-value-never-stored-0123456789"


def _routes(name: str) -> list[dict]:
    return json.loads((Path(FIXTURES_DIR) / f"{name}.json").read_text(encoding="utf-8"))["routes"]


@pytest.fixture()
def offline(monkeypatch):
    """Live connectors answer from their fixtures (plus ``faults[name]`` routes first) instead of the network."""
    faults: dict[str, list[dict]] = {}
    built: dict[str, FixtureTransport] = {}
    orig = ConnectorRegistry.construct

    def construct(self, name):
        if self.mode_of(name) == "fake":
            return orig(self, name)
        problems = self.validate(name)
        if problems:
            raise ConfigError("; ".join(problems))
        m = self.manifests[name]
        t = FixtureTransport(faults.get(name, []) + _routes(name), name)
        built[name] = t
        return ConnectorInstance(m, m.factory({**m.fake_settings, **self.settings_for(name)}, t), "live", t,
                                 self.stage_of(name))

    monkeypatch.setattr(ConnectorRegistry, "construct", construct)
    faults["_transports"] = built          # type: ignore[assignment]
    return faults


@pytest.fixture()
def cfg_file(tmp_path, monkeypatch):
    """A small connector configuration file for the test, and the secrets a live Umbrella needs."""
    path = tmp_path / "connectors.yaml"
    path.write_text(yaml.safe_dump({"connectors": {
        "umbrella": {"enabled": True, "mode": "fake", "settings": {"api_key": "${UMBRELLA_API_KEY}",
                                                                     "api_secret": "${UMBRELLA_API_SECRET}"}},
        "crowdstrike": {"enabled": True, "mode": "fake"},
        "entra": {"enabled": True, "mode": "fake"}}}), encoding="utf-8")
    monkeypatch.setenv("SOC_CONNECTORS_CONFIG", str(path))
    monkeypatch.setenv("UMBRELLA_API_KEY", SECRET)
    monkeypatch.setenv("UMBRELLA_API_SECRET", SECRET + "-2")
    return path


# ============================================================================== 1. one broken tool never stops the rest
def test_one_misconfigured_connector_is_isolated_and_everything_else_keeps_working():
    m = discover()
    cfg = {n: {"enabled": True, "mode": "fake"} for n in m}
    cfg["canary"] = {"enabled": True, "mode": "live", "settings": {}}          # no credentials
    reg = ConnectorRegistry({"connectors": cfg}, manifests=m)
    assert "canary" not in reg.enabled_names() and "canary" in reg.configured_names()
    acts = reg.action_registry()                                              # used to raise ConfigError here
    assert acts.catalog() and reg.with_lookup("ip") and reg.enabled()
    row = next(r for r in reg.status() if r["name"] == "canary")
    assert row["enabled"] and any("auth_token" in p for p in row["config_problems"])


def test_a_connector_that_cannot_be_built_is_isolated_with_the_reason(monkeypatch):
    m = dict(discover())
    good = m["canary"]

    def boom(settings, transport):
        raise RuntimeError("vendor SDK missing")

    from dataclasses import replace

    m["canary"] = replace(good, factory=boom)
    reg = ConnectorRegistry({"connectors": {"canary": {"mode": "fake"}, "crowdstrike": {"mode": "fake"}}}, manifests=m)
    assert [c.name for c in reg.enabled()] == ["crowdstrike"]
    assert "canary" not in reg.enabled_names()
    assert "vendor SDK missing" in reg.problems_of("canary")[0]
    with pytest.raises(ConfigError):
        reg.get("canary")


def test_a_connector_module_that_fails_to_import_is_left_out(monkeypatch):
    import pkgutil

    from soc_platform.connectors import registry as regmod

    real = pkgutil.iter_modules

    def plus_broken(path):
        yield from real(path)
        yield pkgutil.ModuleInfo(None, "zz_broken_vendor", False)

    monkeypatch.setattr(regmod.pkgutil, "iter_modules", plus_broken)
    found = regmod.discover()
    assert "crowdstrike" in found and "zz_broken_vendor" not in found


def test_a_malformed_entry_is_reported_not_silently_ignored_or_enabled():
    m = discover()
    reg = ConnectorRegistry({"connectors": {"canary": {"enabeld": False}, "epss": {"enabled": "maybe"},
                                            "nvd": {"stage": "reed"}, "cisa_kev": None}}, manifests=m)
    assert set(reg.configured_names()) == {"canary", "epss", "nvd", "cisa_kev"}
    assert reg.enabled_names() == ["cisa_kev"]                    # a bare entry is a switched-on tool in fake mode
    assert "unknown key 'enabeld'" in reg.problems_of("canary")[0]
    assert "true or false" in reg.problems_of("epss")[0] and "unknown stage" in reg.problems_of("nvd")[0]


# ============================================================================== 2. strict configuration checking
def test_every_problem_in_a_configuration_is_named_with_how_to_fix_it(monkeypatch):
    monkeypatch.delenv("WIZ_CLIENT_ID", raising=False)
    doc, _ = load_yaml("""
connectors:
  crowdstrik: {enabled: true}
  entra: {enabeld: false, stage: reed}
  umbrella:
    stage: read
    settings: {api_key: "plaintext-key", api_secret: "${UMBRELLA_API_SECRET}", dns_sync: everything, block_list: x}
  rapid7: {stage: read, settings: {console_url: "ivm-local", verify_tls: "perhaps", username: "${R7_U}", password: "${R7_P}"}}
  generic_siem: {settings: {field_map: "not json"}}
  wiz: {mode: live, stage: fake, settings: {api_url: "http://api.wiz.example"}}
  canary: {settings: {auth_token: "abc"}}
bogus_top: 1
""")
    probs = {(p.where, p.level): p for p in check_document(doc, discover())}
    text = "\n".join(str(p) for p in probs.values())
    assert "did you mean 'crowdstrike'" in probs[("crowdstrik", "error")].fix
    assert "'enabled'" in probs[("entra.enabeld", "error")].fix and "'read'" in probs[("entra.stage", "error")].fix
    assert "${UMBRELLA_API_KEY}" in probs[("umbrella.settings.api_key", "error")].fix       # a secret in clear, live
    assert probs[("canary.settings.auth_token", "warning")]                                    # in clear, fake: warned
    assert "UMBRELLA_API_SECRET" in probs[("umbrella.settings.api_secret", "error")].fix or \
        "UMBRELLA_API_SECRET" in text
    assert ("umbrella.settings.dns_sync", "error") in probs
    assert "'block_list_id'" in probs[("umbrella.settings.block_list", "error")].fix
    assert ("rapid7.settings.console_url", "error") in probs and ("rapid7.settings.verify_tls", "error") in probs
    assert "R7_U" in probs[("rapid7.settings.username", "error")].fix                         # names the variable
    assert ("generic_siem.settings.field_map", "error") in probs
    assert ("wiz", "error") in probs                                                           # mode contradicts stage
    assert ("bogus_top", "error") in probs


def test_a_yaml_syntax_error_names_its_line():
    _, probs = load_yaml("connectors:\n  entra:\n\tenabled: true\n")
    assert probs and probs[0].where.startswith("line 3") and "tabs" in probs[0].fix


def test_the_shipped_configuration_file_is_valid():
    doc, probs = load_file(ROOT / "config" / "connectors.yaml")
    assert not probs and not check_document(doc, discover())


def test_serve_refuses_a_broken_configuration_and_says_how_to_fix_it(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("connectors:\n  crowdstrik: {enabled: true}\n", encoding="utf-8")
    env = {**__import__("os").environ, "SOC_CONNECTORS_CONFIG": str(bad), "SOC_DATABASE_URL": "sqlite://"}
    for cmd in ("serve", "scheduler"):
        r = subprocess.run([sys.executable, "-m", "soc_platform", cmd], capture_output=True, text=True, env=env, check=False,
                           timeout=120, cwd=ROOT)
        assert r.returncode == 1 and "did you mean 'crowdstrike'" in r.stderr and "config check" in r.stderr, r.stderr


def test_a_live_tool_without_its_secret_does_not_stop_a_start(tmp_path, monkeypatch):
    from soc_platform.core.connector_config import startup_problems

    monkeypatch.delenv("CANARY_AUTH_TOKEN", raising=False)
    f = tmp_path / "c.yaml"
    f.write_text("connectors:\n  canary: {stage: read, settings: {domain_hash: x, auth_token: '${CANARY_AUTH_TOKEN}'}}\n",
                 encoding="utf-8")
    assert not errors(startup_problems(f))            # isolated and shown instead


def test_config_check_command_lists_problems_and_exits_non_zero(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("connectors:\n  entra: {stage: reed}\n", encoding="utf-8")
    r = subprocess.run([sys.executable, "-m", "soc_platform", "config", "check", str(bad), "--no-env"], check=False,
                       capture_output=True, text=True, timeout=120, cwd=ROOT,
                       env={**__import__("os").environ, "SOC_DATABASE_URL": "sqlite://"})
    assert r.returncode == 1 and "did you mean 'read'" in r.stdout


# ============================================================================== 3. rollout stages
def _umbrella_registry(stage: str) -> ConnectorRegistry:
    return ConnectorRegistry({"connectors": {"umbrella": {"stage": stage, "settings": {
        "api_key": "${UMBRELLA_API_KEY}", "api_secret": "${UMBRELLA_API_SECRET}"}}}}, manifests=discover())


@pytest.mark.parametrize("stage", ["record", "read"])
def test_read_only_stages_offer_no_actions(stage, cfg_file, offline):
    acts = _umbrella_registry(stage).action_registry()
    assert not [a for a in acts.catalog() if a["action_type"].startswith("dns.")]


def test_the_recommend_stage_caps_actions_at_l2_whatever_the_policy_says(session, cfg_file, offline):
    from soc_platform.core.actions import ActionService
    from soc_platform.core.policy import PolicyEngine

    acts = _umbrella_registry("recommend").action_registry()
    pol = PolicyEngine({"default_level": 2, "actions": {"dns.block_domain": {"level": 4}}})
    target = [{"type": "indicator", "indicator_type": "domain", "value": "bad.example"}]
    agent = Principal("agent:incident", "agent", is_agent=True)
    req = ActionService(session, acts, pol).request("dns.block_domain", targets=target, requested_by=agent)
    assert req.autonomy_level == 2 and req.status == "recommended" and req.executed_at is None   # L4 in policy
    assert any("Recommend stage" in r for r in req.policy_reasons)
    auto = ActionService(session, _umbrella_registry("automate").action_registry(), pol)
    assert auto.policy.decide("dns.block_domain", target, destructive=False).outcome == "execute"


def test_the_record_stage_saves_sanitised_responses(cfg_file, tmp_path, monkeypatch):
    from soc_platform.connectors.config_schema import check_entry
    from soc_platform.connectors.recording import RecordingTransport

    monkeypatch.setenv("SOC_RECORD_FIXTURES_DIR", str(tmp_path / "rec"))
    monkeypatch.delenv("SOC_RECORD_SALT", raising=False)
    monkeypatch.delenv("SOC_DATA_KEY", raising=False)
    entry = _umbrella_registry("record").config["umbrella"]
    assert any("Recording stage needs a key" in p.message for p in check_entry("umbrella", entry, discover()))
    reg = _umbrella_registry("record")
    assert "umbrella" not in reg.enabled_names() or not reg.with_stream("dns_activity")   # isolated, not crashing
    monkeypatch.setenv("SOC_DATA_KEY", "a-platform-encryption-key-for-tests")             # the salt derives from it
    assert not check_entry("umbrella", entry, discover())
    inst = _umbrella_registry("record").construct("umbrella")
    assert isinstance(inst.transport, RecordingTransport) and inst.stage == "record"
    monkeypatch.delenv("SOC_RECORD_FIXTURES_DIR")              # (set, it records every live tool, whatever its stage)
    assert not isinstance(_umbrella_registry("read").construct("umbrella").transport, RecordingTransport)


# ============================================================================== 4. preflight
def test_every_connector_passes_preflight_on_its_sample_data():
    reg = ConnectorRegistry.all_fake()
    bad = {n: r for n in reg.enabled_names() if not (r := run_preflight(reg, n))["ok"] or r["warnings"]}
    assert not bad, {n: [c for c in r["checks"] if c["status"] != "ok"] for n, r in bad.items()}


def test_preflight_names_the_missing_secret(monkeypatch):
    monkeypatch.delenv("CANARY_AUTH_TOKEN", raising=False)
    reg = ConnectorRegistry({"connectors": {"canary": {"stage": "read", "settings": {
        "domain_hash": "x", "auth_token": "${CANARY_AUTH_TOKEN}"}}}}, manifests=discover())
    r = run_preflight(reg, "canary")
    assert not r["ok"] and r["checks"][0]["check"] == "Configuration" and "CANARY_AUTH_TOKEN" in r["checks"][0]["fix"]


def _live_crowdstrike(monkeypatch) -> ConnectorRegistry:
    monkeypatch.setenv("CS_ID", "id")
    monkeypatch.setenv("CS_SECRET", "secret")
    return ConnectorRegistry({"connectors": {"crowdstrike": {"stage": "read", "settings": {
        "client_id": "${CS_ID}", "client_secret": "${CS_SECRET}"}}}}, manifests=discover())


def test_preflight_names_the_stream_and_permission_a_tool_refuses(monkeypatch, offline):
    offline["crowdstrike"] = [{"method": "GET", "path": r"^/spotlight/.*", "status": 403, "body": None}]
    r = run_preflight(_live_crowdstrike(monkeypatch), "crowdstrike")
    checks = {c["check"]: c for c in r["checks"]}
    assert not r["ok"] and checks["Sign-in"]["status"] == "ok"
    assert "vulnerabilities" in checks["Permissions"]["detail"] and "Spotlight" in checks["Permissions"]["fix"]


def test_refused_credentials_stop_the_preflight_without_hammering_the_tool(monkeypatch, offline):
    offline["crowdstrike"] = [{"method": m, "path": ".*", "status": 401, "body": None} for m in ("GET", "POST")]
    r = run_preflight(_live_crowdstrike(monkeypatch), "crowdstrike")
    signin = next(c for c in r["checks"] if c["check"] == "Sign-in")
    assert not r["ok"] and "credentials were refused" in signin["detail"]
    rows = next(c for c in r["checks"] if c["check"] == "Streams")["streams"]
    assert [x["status"] for x in rows].count("skipped") == len(rows) - 1      # stopped after the first refusal
    assert len(offline["_transports"]["crowdstrike"].calls) <= 4              # one renewal at most, no retry storm


def test_a_proxy_page_and_a_wrong_clock_are_explained(monkeypatch, offline):
    offline["crowdstrike"] = [{"method": "GET", "path": r"^/alerts/queries/.*", "status": 200,
                               "body": "<html><body>Sign in to the proxy</body></html>"}]
    r = run_preflight(_live_crowdstrike(monkeypatch), "crowdstrike")
    s = next(c for c in r["checks"] if c["check"] == "Sign-in")
    assert "proxy" in s["fix"]

    alerts = next(x for x in _routes("crowdstrike") if x["method"] == "POST" and "alerts/entities" in x["path"])
    future = json.loads(json.dumps(alerts))
    for a in future["body"]["resources"]:
        a["updated_timestamp"] = a["created_timestamp"] = "2031-01-01T00:00:00Z"
    offline["crowdstrike"] = [future]
    r = run_preflight(_live_crowdstrike(monkeypatch), "crowdstrike")
    rows = {x["stream"]: x for c in r["checks"] for x in c.get("streams", [])}
    assert r["ok"] and rows["alerts"]["status"] == "warning" and "clock" in rows["alerts"]["notes"][0]


# ============================================================================== 5. governed console changes
def _store(session) -> ConfigStore:
    return ConfigStore(session)


def test_a_change_is_proposed_by_one_person_approved_by_another_and_applies(session, cfg_file):
    st = _store(session)
    v = st.propose({"crowdstrike": {"settings": {"user_domain": "corp.example"}}}, ADMIN, "UPN suffix")
    assert v.status == "proposed" and v.changes == [{"connector": "crowdstrike", "field": "settings.user_domain",
                                                     "from": None, "to": "corp.example"}]
    with pytest.raises(PermissionError):
        st.approve(v.id, Principal(ADMIN.id, "Ada", frozenset({Role.LEAD})))       # own change
    st.approve(v.id, LEAD)
    assert st.registry().settings_for("crowdstrike")["user_domain"] == "corp.example"
    events = [r.event_type for r in session.execute(__import__("sqlalchemy").select(
        __import__("soc_platform.core.models", fromlist=["AuditRecord"]).AuditRecord)).scalars()]
    assert "connector_config.proposed" in events and "connector_config.activated" in events


def test_services_and_agents_cannot_propose_and_only_approvers_approve(session, cfg_file):
    st = _store(session)
    svc = Principal("svc", "svc", frozenset({Role.AUTOMATION_ADMIN}), is_service=True)
    with pytest.raises(PermissionError):
        st.propose({"crowdstrike": {"enabled": False}}, svc)
    v = st.propose({"crowdstrike": {"enabled": False}}, ADMIN)
    with pytest.raises(PermissionError):
        st.approve(v.id, Principal("ana@acme-demo.com", "Ana", frozenset({Role.ANALYST})))


def test_secrets_are_never_stored_only_referenced(session, cfg_file):
    st = _store(session)
    with pytest.raises(ConfigRejected) as e:
        st.propose({"umbrella": {"settings": {"api_key": "pasted-secret-value"}}}, ADMIN)
    assert "UMBRELLA_API_KEY" in e.value.problems[0].fix
    st.propose({"umbrella": {"settings": {"api_key": "${VAULT_UMBRELLA_KEY}"}}}, ADMIN)
    stored = json.dumps([r.document for r in session.execute(__import__("sqlalchemy").select(ConnectorConfigVersion)).scalars()])
    assert SECRET not in stored and "pasted-secret-value" not in stored
    assert SECRET not in st.export_yaml() and SECRET not in json.dumps(st.view(), default=str)


def test_invalid_or_empty_changes_are_refused_with_the_reason(session, cfg_file):
    st = _store(session)
    for changes, needle in [({"crowdstrik": {"enabled": False}}, "crowdstrike"),
                            ({"umbrella": {"settings": {"dns_sinc": "all"}}}, "dns_sync"),
                            ({"umbrella": {"stage": "reed"}}, "stage"),
                            ({"umbrella": {"settings": {"dns_sync": "everything"}}}, "security"),
                            ({"crowdstrike": {"enabled": True}}, "changes nothing")]:
        with pytest.raises(ConfigRejected) as e:
            st.propose(changes, ADMIN)
        assert needle in json.dumps(e.value.detail()), (changes, e.value.detail())


def test_going_live_requires_a_passing_preflight_and_approval_rechecks_it(session, cfg_file, offline, monkeypatch):
    st = _store(session)
    offline["umbrella"] = [{"method": m, "path": ".*", "status": 403, "body": None} for m in ("GET", "POST")]
    with pytest.raises(ConfigRejected) as e:
        st.propose({"umbrella": {"stage": "read"}}, ADMIN)
    assert e.value.preflight and not e.value.preflight["ok"]                    # the report, to show what to fix
    offline["umbrella"] = []
    v = st.propose({"umbrella": {"stage": "read"}}, ADMIN, "go live read-only")
    assert v.preflight["umbrella"]["verdict"].startswith("ready")
    assert session.query(ConnectorPreflight).filter_by(connector="umbrella").count() == 2
    monkeypatch.delenv("UMBRELLA_API_SECRET")                                   # the secret disappears meanwhile
    with pytest.raises(ConfigRejected):
        st.approve(v.id, LEAD)
    monkeypatch.setenv("UMBRELLA_API_SECRET", SECRET + "-2")
    monkeypatch.setenv("SOC_CLOCK_OFFSET_SECONDS", str(timedelta(days=8).total_seconds()))
    with pytest.raises(ConfigRejected, match="days old"):
        st.approve(v.id, LEAD)
    monkeypatch.delenv("SOC_CLOCK_OFFSET_SECONDS")
    st.approve(v.id, LEAD)
    assert st.registry().stage_of("umbrella") == "read"


def test_a_stale_proposal_cannot_overwrite_a_newer_approved_change(session, cfg_file):
    st = _store(session)
    a = st.propose({"crowdstrike": {"settings": {"user_domain": "a.example"}}}, ADMIN)
    b = st.propose({"crowdstrike": {"settings": {"user_domain": "b.example"}}}, ADMIN)
    st.approve(a.id, LEAD)
    with pytest.raises(ConfigRejected, match="propose it again"):
        st.approve(b.id, LEAD)


def test_pausing_is_immediate_and_resuming_needs_approval(session, cfg_file):
    st = _store(session)
    with pytest.raises(ValueError):
        st.pause("crowdstrike", ADMIN, "")                                        # a reason is required
    st.pause("crowdstrike", ADMIN, "sending malformed alerts")
    assert "crowdstrike" not in st.registry().enabled_names()
    with pytest.raises(ValueError, match="already off"):
        st.pause("crowdstrike", ADMIN, "again")
    v = st.propose({"crowdstrike": {"enabled": True}}, ADMIN, "fixed")
    assert "crowdstrike" not in st.registry().enabled_names()
    st.approve(v.id, LEAD)
    assert "crowdstrike" in st.registry().enabled_names()


def test_an_earlier_version_can_be_restored_through_approval(session, cfg_file):
    st = _store(session)
    v1 = st.propose({"crowdstrike": {"settings": {"user_domain": "one.example"}}}, ADMIN)
    st.approve(v1.id, LEAD)
    v2 = st.propose({"crowdstrike": {"settings": {"user_domain": "two.example"}}}, ADMIN)
    st.approve(v2.id, LEAD)
    r = st.restore(v1.id, ADMIN)
    assert r.kind == "restore" and r.status == "proposed"
    st.approve(r.id, LEAD2)
    assert st.registry().settings_for("crowdstrike")["user_domain"] == "one.example"


def test_export_and_import_round_trip_as_one_proposal(session, cfg_file):
    st = _store(session)
    text = st.export_yaml()
    doc = yaml.safe_load(text)
    doc["connectors"]["crowdstrike"]["settings"] = {"user_domain": "imported.example"}
    del doc["connectors"]["entra"]                                              # absent from the file: switched off
    v = st.import_yaml(yaml.safe_dump(doc), ADMIN, "staging config")
    assert v.kind == "import" and {(c["connector"], c["field"]) for c in v.changes} == {
        ("crowdstrike", "settings.user_domain"), ("entra", "enabled")}
    st.approve(v.id, LEAD)
    reg = st.registry()
    assert "entra" not in reg.enabled_names() and reg.settings_for("crowdstrike")["user_domain"] == "imported.example"
    with pytest.raises(ConfigRejected, match="nothing to import"):
        st.import_yaml(st.export_yaml(), ADMIN)
    with pytest.raises(ConfigRejected):
        st.import_yaml("connectors:\n  crowdstrik: {}\n", ADMIN)


def test_editing_an_unlisted_tool_does_not_switch_it_on(session, cfg_file):
    st = _store(session)
    v = st.propose({"canary": {"settings": {"user_domain": "x.example"}}}, ADMIN)
    st.approve(v.id, LEAD)
    assert "canary" not in st.registry().configured_names()


# ============================================================================== 6. the API and hot reload
@pytest.fixture()
def client(tmp_path, monkeypatch, cfg_file):
    from fastapi.testclient import TestClient

    from soc_platform.api import app as appmod
    from soc_platform.config import get_settings
    from soc_platform.core import db as dbm
    from soc_platform.core.auth import issue_dev_token

    secret = "admin-test-secret-0123456789abcdef0123"
    for k, v in {"SOC_AUTH_MODE": "dev", "SOC_DEV_JWT_SECRET": secret, "SOC_ORG_DOMAINS": "acme-demo.com",
                 "SOC_DATABASE_URL": f"sqlite:///{(tmp_path / 'a.db').as_posix()}", "SOC_EMBEDDED_SCHEDULER": "0",
                 "SOC_CONFIG_RELOAD_SECONDS": "0"}.items():
        monkeypatch.setenv(k, v)
    get_settings.cache_clear()
    dbm._default = None
    appmod.registry.cache_clear()
    dbm.get_database().create_all()
    tok = lambda u, r: {"Authorization": "Bearer " + issue_dev_token(secret, u, [r])}
    with TestClient(appmod.app) as c:
        yield c, tok, appmod
    get_settings.cache_clear()
    dbm._default = None
    appmod.registry.cache_clear()


def test_the_console_flow_end_to_end_through_the_api(client):
    c, tok, appmod = client
    admin, lead, analyst = tok(ADMIN.id, "automation_admin"), tok(LEAD.id, "lead"), tok("al@acme-demo.com", "analyst")
    view = c.get("/api/v1/config/connectors", headers=analyst).json()
    assert {x["name"] for x in view["connectors"]} >= {"crowdstrike", "umbrella"} and view["pending"] == []
    secret_row = next(f for x in view["connectors"] if x["name"] == "umbrella" for f in x["config"] if f["name"] == "api_key")
    assert secret_row["kind"] == "secret" and "value" not in secret_row and secret_row["env_var"] == "UMBRELLA_API_KEY"
    assert c.post("/api/v1/config/proposals", headers=analyst, json={"changes": {"entra": {"enabled": False}}}).status_code == 403
    r = c.post("/api/v1/config/proposals", headers=admin, json={"changes": {"umbrella": {"settings": {"api_key": "x1"}}}})
    assert r.status_code == 422 and r.json()["detail"]["problems"][0]["fix"]
    r = c.post("/api/v1/config/proposals", headers=admin, json={"changes": {"entra": {"enabled": False}}, "note": "n"})
    vid = r.json()["id"]
    assert c.post(f"/api/v1/config/proposals/{vid}/approve", headers=admin).status_code == 403
    assert "entra" in appmod.registry().enabled_names()
    assert c.post(f"/api/v1/config/proposals/{vid}/approve", headers=lead).status_code == 200
    assert "entra" not in appmod.registry().enabled_names()                       # in force at once, no restart
    pf = c.post("/api/v1/config/connectors/crowdstrike/preflight", headers=admin).json()
    assert pf["verdict"] == "ready" and c.get("/api/v1/config/connectors", headers=lead).json()[
        "connectors"][[x["name"] for x in view["connectors"]].index("crowdstrike")]["last_preflight"]["verdict"] == "ready"
    assert c.post("/api/v1/config/connectors/crowdstrike/pause", headers=admin, json={"reason": "noisy"}).status_code == 200
    assert c.post("/api/v1/connectors/crowdstrike/sync?stream=alerts", headers=admin).status_code == 409
    exp = c.get("/api/v1/config/export", headers=lead)
    assert exp.status_code == 200 and SECRET not in exp.text and "crowdstrike" in exp.text
    hist = c.get("/api/v1/config/history", headers=lead).json()
    assert [h["kind"] for h in hist[:2]] == ["pause", "change"]


def test_an_approved_change_reaches_another_process_without_a_restart(client):
    c, tok, appmod = client
    other = type(appmod.registry)()                       # a second API process or the scheduler
    assert "entra" in other().enabled_names()
    vid = c.post("/api/v1/config/proposals", headers=tok(ADMIN.id, "automation_admin"),
                 json={"changes": {"entra": {"enabled": False}}}).json()["id"]
    c.post(f"/api/v1/config/proposals/{vid}/approve", headers=tok(LEAD.id, "lead"))
    assert "entra" not in other().enabled_names()          # re-read (SOC_CONFIG_RELOAD_SECONDS=0 in this test)


def test_pushed_alerts_are_refused_clearly_when_the_siem_connector_is_off(client):
    c, tok, _ = client
    # cfg_file does not list generic_siem: it is off
    r = c.post("/api/v1/ingest/alerts", headers=tok(LEAD.id, "lead"), json={"alerts": [{"id": "a1"}]})
    assert r.status_code == 409 and "generic SIEM" in r.json()["detail"]


# ============================================================================== 7. the connector development kit
def _load(path: Path):
    spec = importlib.util.spec_from_file_location(path.stem, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_a_scaffolded_connector_is_valid_passes_preflight_and_survives_faults(tmp_path, monkeypatch, session):
    from soc_platform.connectors import devkit
    from soc_platform.connectors.base import SyncRunner
    from soc_platform.core.context_store import ContextStore

    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "connectors.yaml").write_text("connectors:\n", encoding="utf-8")
    files = devkit.scaffold("acme_probe", "edr", "Probe XDR", root=tmp_path)
    assert len(files) == 4 and all(f.exists() for f in files)
    mod = _load(tmp_path / "soc_platform" / "connectors" / "tools" / "acme_probe.py")
    m = mod.MANIFEST
    entry = yaml.safe_load((tmp_path / "config" / "connectors.yaml").read_text())["connectors"]["acme_probe"]
    assert not check_document({"connectors": {"acme_probe": entry}}, {"acme_probe": m})
    monkeypatch.setenv("SOC_FIXTURES_DIR", str(tmp_path / "soc_platform" / "fixtures"))
    reg = ConnectorRegistry({"connectors": {"acme_probe": {"mode": "fake"}}}, manifests={"acme_probe": m})
    assert run_preflight(reg, "acme_probe")["verdict"] == "ready"
    routes = json.loads((tmp_path / "soc_platform" / "fixtures" / "acme_probe.json").read_text())["routes"]
    throttled = m.factory(m.fake_settings, FixtureTransport(
        [{"method": "GET", "path": ".*", "status": 429, "times": 1, "headers": {"Retry-After": "0"}, "body": None}] + routes,
        "acme_probe"))
    rep = SyncRunner(session, ContextStore(session)).sync(throttled, "events")
    assert not rep.errors and rep.ingested == 2
    for rec in routes[0]["body"]["items"]:
        for k in list(rec):
            try:
                throttled.normalize("events", {x: v for x, v in rec.items() if x != k})
            except ValueError:
                assert k == "id"                          # only a record without its identifier is refused


def test_the_scaffold_refuses_bad_names_and_never_overwrites(tmp_path):
    from soc_platform.connectors import devkit

    for name, cat in (("Bad-Name", "edr"), ("ok_name", "nonsense")):
        with pytest.raises(ValueError):
            devkit.scaffold(name, cat, root=tmp_path)
    devkit.scaffold("twice", "dns", root=tmp_path, add_to_config=False)
    with pytest.raises(ValueError, match="already exists"):
        devkit.scaffold("twice", "dns", root=tmp_path, add_to_config=False)
    with pytest.raises(ValueError, match="already exists"):
        devkit.scaffold("crowdstrike", "edr")                     # a real connector name in the real tree


# ============================================================================== 8. organisation lists in the console
def test_supplier_and_sanctioned_lists_are_edited_approved_and_used_everywhere(session, cfg_file):
    from soc_platform.domains.phishing.supplier import SupplierMonitor, load_suppliers
    from soc_platform.intelligence.shadow_it import analyse

    st = _store(session)
    for bad, needle in [({"suppliers": [{"name": "X", "domains": ["not a domain"]}]}, "not a domain"),
                        ({"suppliers": [{"name": "X", "domains": ["x.com"], "criticality": "hgh"}]}, "'high'"),
                        ({"suppliers": [{"domains": ["x.com"]}]}, "needs a name"),
                        ({"sanctioned": ["sharepoint com"]}, "not a domain"),
                        ({"supliers": []}, "'suppliers'")]:
        with pytest.raises(ConfigRejected) as e:
            st.propose({}, ADMIN, lists=bad)
        assert needle in json.dumps(e.value.detail()), bad
    file_names = {s.name for s in load_suppliers(include_env=False)}
    v = st.propose({}, ADMIN, "procurement master list", lists={
        "suppliers": [{"name": "Northwind Parts", "domains": ["Northwind-Parts.example"], "criticality": "high"}],
        "sanctioned": ["dropbox.com"]})
    assert {c["field"] for c in v.changes} == {"suppliers", "sanctioned"}
    assert {s.name for s in SupplierMonitor(session).suppliers} == file_names            # not in force yet
    st.approve(v.id, LEAD)
    assert [s.domains for s in SupplierMonitor(session).suppliers] == [["northwind-parts.example"]]
    reg = st.registry()
    assert reg.lists["sanctioned"] == ["dropbox.com"]
    rows = [{"domain": "www.dropbox.com", "categories": ["File Storage"], "user": "a@acme-demo.com"}]
    assert analyse(rows, sanctioned={"dropbox.com"})["summary"]["unsanctioned_services"] == 0
    assert "Northwind Parts" in st.export_yaml()
    back = st.propose({}, ADMIN, "file list again", lists={"suppliers": None})          # None: the file's list again
    st.approve(back.id, LEAD)
    assert {s.name for s in SupplierMonitor(session).suppliers} == file_names
    assert st.registry().lists == {"sanctioned": ["dropbox.com"]}


def test_a_refused_proposal_keeps_its_preflight_as_evidence(client, offline):
    from sqlalchemy import select

    from soc_platform.core import db as dbm
    from soc_platform.core.models import AuditRecord

    c, tok, _ = client
    offline["umbrella"] = [{"method": m, "path": ".*", "status": 403, "body": None} for m in ("GET", "POST")]
    r = c.post("/api/v1/config/proposals", headers=tok(ADMIN.id, "automation_admin"),
               json={"changes": {"umbrella": {"stage": "read"}}})
    assert r.status_code == 422 and r.json()["detail"]["preflight"]["verdict"] == "not ready"
    with dbm.get_database().session() as s:
        assert s.query(ConnectorPreflight).filter_by(connector="umbrella", ok=False).count() == 1
        assert s.query(ConnectorConfigVersion).count() == 0
        assert "connector.preflight" in [a.event_type for a in s.execute(select(AuditRecord)).scalars()]
