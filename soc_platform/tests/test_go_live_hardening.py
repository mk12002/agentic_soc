"""The go-live review's fixes, each as the behaviour it guarantees: production fails closed, development sign-in
never meets a real tool, credentials and prompts go only where they are meant to, and an operator can watch the
platform from outside (docs/TEST_REPORT.md, the go-live review round)."""

from __future__ import annotations

import pytest

from soc_platform.settings_check import check_environment

PROD = {"SOC_ENVIRONMENT": "prod", "SOC_AUTH_MODE": "entra", "SOC_ENTRA_TENANT_ID": "t", "SOC_ENTRA_AUDIENCE": "a",
        "SOC_DATA_KEY": "x" * 43 + "=", "SOC_BLOB_STORE": "database", "SOC_ORG_DOMAINS": "example.com,example.onmicrosoft.com",
        "SOC_DATABASE_URL": "postgresql+psycopg2://u:p@db/soc?sslmode=verify-full&sslrootcert=system"}


def _errors(env):
    return {p.name for p in check_environment(env) if p.level == "error"}


def test_a_real_deployment_that_forgot_its_environment_is_refused():
    assert "SOC_ENVIRONMENT" in _errors({"SOC_AUTH_MODE": "entra", "SOC_ENTRA_TENANT_ID": "t", "SOC_ENTRA_AUDIENCE": "a"})
    assert "SOC_ENVIRONMENT" in _errors({"SOC_CONNECTOR_MODE": "live"})
    assert "SOC_ENVIRONMENT" not in _errors({"SOC_ENVIRONMENT": "dev", "SOC_CONNECTOR_MODE": "fake"})


def test_development_sign_in_is_refused_with_real_tools_or_a_weak_secret():
    assert "SOC_CONNECTOR_MODE" in _errors({"SOC_ENVIRONMENT": "dev", "SOC_AUTH_MODE": "dev", "SOC_CONNECTOR_MODE": "live"})
    assert "SOC_DEV_JWT_SECRET" in _errors({"SOC_ENVIRONMENT": "dev", "SOC_DEV_JWT_SECRET": "short"})
    warn = {p.name for p in check_environment({"SOC_ENVIRONMENT": "dev", "SOC_DEV_TOKENS_REMOTE": "1"})}
    assert "SOC_DEV_TOKENS_REMOTE" in warn


def test_production_needs_a_verified_database_connection_and_an_approved_https_model_endpoint():
    assert not _errors(PROD)
    assert "SOC_DATABASE_URL" in _errors({**PROD, "SOC_DATABASE_URL": "postgresql://u:p@db/soc"})          # 'prefer'
    assert "SOC_DATABASE_URL" in _errors({**PROD, "SOC_DATABASE_URL": "postgresql://u:p@db/soc?sslmode=require"})
    assert "SOC_DATABASE_URL" in _errors({**PROD, "SOC_DATABASE_URL": "sqlite:///soc.db"})
    llm = {**PROD, "SOC_LLM_PROVIDER": "azure_openai", "SOC_LLM_ENDPOINT": "https://m.example"}
    assert "SOC_LLM_APPROVED_ENDPOINTS" in _errors(llm)
    assert "SOC_LLM_ENDPOINT" in _errors({**llm, "SOC_LLM_ENDPOINT": "http://m.example",
                                          "SOC_LLM_APPROVED_ENDPOINTS": "http://m.example"})
    assert not _errors({**llm, "SOC_LLM_APPROVED_ENDPOINTS": "https://m.example"})
    no_tenant_domain = {p.name for p in check_environment({**PROD, "SOC_ORG_DOMAINS": "example.com"})}
    assert "SOC_ORG_DOMAINS" in no_tenant_domain


def test_a_mounted_secret_file_gets_the_same_check_as_the_setting(tmp_path):
    bad = tmp_path / "key"
    bad.write_text("not-a-fernet-key\n", encoding="utf-8")
    url = tmp_path / "url"
    url.write_text("postgresql://u:p@db/soc?sslmode=verify-full&sslrootcert=system\n", encoding="utf-8")
    env = {k: v for k, v in PROD.items() if k not in ("SOC_DATA_KEY", "SOC_DATABASE_URL")}
    errors = _errors({**env, "SOC_DATA_KEY_FILE": str(bad), "SOC_DATABASE_URL_FILE": str(url)})
    assert "SOC_DATA_KEY_FILE" in errors and "SOC_DATABASE_URL" not in errors          # the URL file is read


def test_development_sign_in_isolates_every_live_tool(monkeypatch):
    """However a tool is switched live (file, console, SOC_CONNECTOR_MODE), dev sign-in - where anyone who reaches
    the port can mint any role - never drives it."""
    from soc_platform.config import get_settings
    from soc_platform.connectors.registry import ConnectorRegistry

    monkeypatch.setenv("SOC_ENVIRONMENT", "dev")
    monkeypatch.setenv("SOC_AUTH_MODE", "dev")
    get_settings.cache_clear()
    try:
        reg = ConnectorRegistry({"connectors": {"nvd": {"enabled": True, "mode": "live"},
                                                "canary": {"enabled": True, "mode": "fake"}}})
        assert "nvd" not in reg.enabled_names() and "canary" in reg.enabled_names()
        assert any("Entra sign-in" in p for p in reg.problems_of("nvd"))
    finally:
        monkeypatch.undo()
        get_settings.cache_clear()


def test_prompts_go_only_to_an_approved_https_endpoint_in_production():
    from soc_platform.config import Settings
    from soc_platform.llm.gateway import check_endpoint

    with pytest.raises(ValueError):
        check_endpoint(Settings(environment="prod"), "https://anywhere.example")             # empty list: refused
    with pytest.raises(ValueError):
        check_endpoint(Settings(environment="prod", llm_approved_endpoints=["http://m.example"]), "http://m.example")
    check_endpoint(Settings(environment="prod", llm_approved_endpoints=["https://m.example/"]), "https://m.example")
    check_endpoint(Settings(environment="dev"), "http://localhost:8000")                     # local model in dev
    with pytest.raises(ValueError):
        check_endpoint(Settings(environment="dev", llm_approved_endpoints=["https://a"]), "https://b")


def test_credentials_never_follow_a_next_link_to_another_host():
    """A vendor's next link is followed with the connector's credentials only on the connector's own origin."""
    from soc_platform.connectors.base import ConnectorError
    from soc_platform.connectors.http import HttpTransport

    seen = []

    class Auth:
        def apply(self, headers, params):
            headers["Authorization"] = "Bearer secret-token"

        def invalidate(self):
            pass

    t = HttpTransport("https://graph.example.com/v1.0", Auth())
    t.client.request = lambda *a, **k: seen.append(a) or (_ for _ in ()).throw(RuntimeError("sent"))
    for evil in ("https://attacker.example/steal", "http://graph.example.com/v1.0/x", "https://graph.example.com:8443/x"):
        with pytest.raises(ConnectorError):
            t.request("GET", evil)
    assert seen == []
    with pytest.raises(RuntimeError):                                         # same origin: sent
        t.request("GET", "https://graph.example.com/v1.0/users?$skiptoken=x")
    assert seen and seen[0][1].startswith("https://graph.example.com/")


@pytest.fixture()
def api(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from soc_platform.api import app as appmod
    from soc_platform.config import get_settings
    from soc_platform.core import db as dbm
    from soc_platform.core.auth import issue_dev_token

    secret = "g" * 40
    for k, v in {"SOC_AUTH_MODE": "dev", "SOC_DEV_JWT_SECRET": secret, "SOC_ENVIRONMENT": "test",
                 "SOC_DATABASE_URL": f"sqlite:///{(tmp_path / 'g.db').as_posix()}", "SOC_LLM_PROVIDER": "none"}.items():
        monkeypatch.setenv(k, v)
    saved = dbm._default
    get_settings.cache_clear()
    dbm._default = None
    appmod.registry.cache_clear()
    try:
        with TestClient(appmod.app) as c:
            yield c, lambda user, roles: {"Authorization": "Bearer " + issue_dev_token(secret, user, roles.split(","))}
    finally:
        monkeypatch.undo()
        get_settings.cache_clear()
        dbm._default = saved
        appmod.registry.cache_clear()


def test_a_service_key_can_be_sent_as_bearer_for_scrapers_and_metrics_cover_what_alerts_watch(api):
    c, tok = api
    key = c.post("/api/v1/admin/api-keys", headers=tok("ada@example.com", "admin"),
                 json={"name": "prometheus", "roles": ["auditor"], "days": 30}).json()["api_key"]
    r = c.get("/metrics", headers={"Authorization": f"Bearer {key}"})
    assert r.status_code == 200
    for name in ("soc_scheduler_heartbeat_age_seconds", "soc_audit_chain_ok", "soc_job_failing",
                 "soc_break_glass_uses_24h", "soc_kill_switch", "soc_actions"):
        assert name in r.text, name
    assert c.get("/metrics", headers={"Authorization": "Bearer sk_soc_bogus_key"}).status_code == 401


def test_audit_verify_checks_heads_shipped_to_the_log_pipeline(tmp_path, monkeypatch, capsys):
    import json

    from soc_platform import __main__ as cli
    from soc_platform.config import get_settings
    from soc_platform.core import db as dbm
    from soc_platform.core.audit import AuditLog

    monkeypatch.setenv("SOC_DATABASE_URL", f"sqlite:///{(tmp_path / 'a.db').as_posix()}")
    saved = dbm._default
    get_settings.cache_clear()
    dbm._default = None
    try:
        with dbm.get_database().session() as s:
            for i in range(3):
                AuditLog(s).append(actor_type="system", actor_id="t", event_type="e", subject_type="t", subject_id=str(i))
        with dbm.get_database().session() as s:
            head = AuditLog(s).verify()
        cli.cmd_audit("verify", "--anchor", f"{head['head_seq']}:{head['head']}")
        assert json.loads(capsys.readouterr().out)["anchors"][0]["ok"] is True
        with pytest.raises(SystemExit):
            cli.cmd_audit("verify", "--anchor", f"{head['head_seq']}:{'0' * 64}")   # history rewritten since
    finally:
        monkeypatch.undo()
        get_settings.cache_clear()
        dbm._default = saved
