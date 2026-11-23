"""AI integration: an administrator chooses the model provider in the console (the in-house gateway's service account,
or an API key), the credentials stay write-only and encrypted, and every chosen model follows its line - a newer
version in the same generation is checked, then used; a new generation waits for an administrator; every change can
be rolled back."""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

import pytest
from cryptography.fernet import Fernet

from soc_platform.config import Settings
from soc_platform.core.auth import Principal, Role
from soc_platform.core.models import AuditRecord as AuditEvent
from soc_platform.core.models import LLMCall, utcnow
from soc_platform.intelligence.models import Insight
from soc_platform.llm import catalogue
from soc_platform.llm.gateway import LLMGateway, _Breaker
from soc_platform.llm.integration import IntegrationStore, LLMSecret, configured, connection_check, effective
from soc_platform.llm.model_lines import newest, parse
from soc_platform.llm.usage_policy import UsagePolicyStore, rule_for
from soc_platform.tests import fake_gateway_sdk as sdk

ADMIN = Principal("ada@acme-demo.com", "Ada", frozenset({Role.ADMIN}))
LEAD = Principal("lena@acme-demo.com", "Lena", frozenset({Role.LEAD}))
EVIDENCE = [{"id": "E1", "claim": "3 hosts reached the domain", "source": "umbrella"}]
TOKEN = "svc-auth-token"


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    from soc_platform.llm.providers.enterprise_gateway import EnterpriseGatewayProvider

    sdk.reset()
    EnterpriseGatewayProvider._sessions.clear()
    _Breaker.failures, _Breaker.open_until = 0, 0.0
    monkeypatch.setenv("SOC_LLM_GATEWAY_SDK", "soc_platform.tests.fake_gateway_sdk")
    monkeypatch.setenv("SOC_LLM_GATEWAY_MODELS_CALL", "llm.models")
    monkeypatch.delenv("SOC_LLM_MODELS", raising=False)
    monkeypatch.delenv("SOC_LLM_MODEL_VERSION", raising=False)
    yield
    _Breaker.failures, _Breaker.open_until = 0, 0.0


def st(**kw) -> Settings:
    return Settings(**{"data_keys": [Fernet.generate_key().decode()], "llm_monthly_token_budget": 10_000_000, **kw})


def connect(session, settings, token=TOKEN, **kw):
    return IntegrationStore(session, settings).save(provider="enterprise_gateway", endpoint=None,
                                                    secrets={"auth_token": token, "session_token": "svc-session"},
                                                    expires_at=kw.get("expires_at"), by=ADMIN, note="service account")


def insights(session, rule):
    return [i for i in session.query(Insight).all() if i.rule == rule and i.status == "new"]


# ============================================================================== names: a line and a version
@pytest.mark.parametrize("name,line,version", [
    ("GPT 6.2 Sol", "gpt sol", (6, 2)), ("GPT 6 Sol", "gpt sol", (6,)), ("GPT 6.2 Astra", "gpt astra", (6, 2)),
    ("Claude Sonnet 5.5", "claude sonnet", (5, 5)), ("Gemini 3.7 Flash", "gemini flash", (3, 7)),
    ("Grok 4.7", "grok", (4, 7)), ("gpt-4.1-mini", "gpt mini", (4, 1)), ("gpt-4.1", "gpt", (4, 1)),
    ("claude-sonnet-4-5-20250929", "claude sonnet", (4, 5)), ("claude-3-5-sonnet-20241022", "claude sonnet", (3, 5)),
    ("anthropic/claude-sonnet-4.5", "anthropic claude sonnet", (4, 5)), ("gpt-4o-2024-08-06", "gpt o", (4,)),
    ("mistral-large-2411", "mistral large", ()), ("Auto", "auto", None)])
def test_a_model_name_reads_as_a_line_and_a_version(name, line, version):
    m = parse(name)
    assert (m.line, m.version) == (line, version)


def test_only_a_newer_version_of_the_same_line_is_an_upgrade_and_a_new_generation_is_kept_apart():
    offered = ["GPT 6 Sol", "GPT 6.1 Sol", "GPT 6.2 Sol", "GPT 7 Sol", "GPT 6.3 Sol Preview", "GPT 6.9 Astra"]
    assert newest(offered, "GPT 6 Sol") == ("GPT 6.2 Sol", "GPT 7 Sol")      # preview and another variant ignored
    assert newest(list(reversed(offered)), "GPT 6 Sol") == ("GPT 6.2 Sol", "GPT 7 Sol")   # listing order is irrelevant
    assert newest(offered, "GPT 7 Sol") == (None, None)
    assert newest(offered, "GPT 6.2 Sol", allow_preview=True)[0] == "GPT 6.3 Sol Preview"
    assert newest(["claude-sonnet-4-5-20250929", "claude-sonnet-4-5-20251101"], "claude-sonnet-4-5-20250929")[0] == \
        "claude-sonnet-4-5-20251101"                                        # a newer dated build of one version
    assert newest(offered, "Auto") == (None, None)                          # an alias has no version to follow


# ============================================================================== credentials
def test_credentials_are_write_only_encrypted_and_audited_by_name_only(session):
    settings = st()
    connect(session, settings)
    row = session.get(LLMSecret, "enterprise_gateway.auth_token")
    assert row.encrypted and TOKEN not in row.sealed                       # sealed with the data key
    status = json.dumps(IntegrationStore(session, settings).status())
    assert TOKEN not in status and "svc-session" not in status              # the screen sees "set", never the value
    audit = json.dumps([e.payload for e in session.query(AuditEvent).filter_by(event_type="llm.integration_changed")])
    assert TOKEN not in audit and "auth_token replaced" in audit
    assert effective(session, settings).secrets["auth_token"] == TOKEN       # only the provider reads it


def test_only_an_administrator_chooses_the_provider_and_an_endpoint_must_be_approved(session):
    settings = st(llm_approved_endpoints=["https://llm.approved.example/v1"])
    store = IntegrationStore(session, settings)
    with pytest.raises(PermissionError):
        store.save(provider="openrouter", endpoint=None, secrets={"api_key": "k1"}, expires_at=None, by=LEAD)
    with pytest.raises(ValueError, match="approved"):            # OpenRouter's address is not on this deployment's list
        store.save(provider="openrouter", endpoint=None, secrets={"api_key": "k1"}, expires_at=None, by=ADMIN)
    with pytest.raises(ValueError, match="needs its api key"):
        store.save(provider="anthropic", endpoint=None, secrets={}, expires_at=None, by=ADMIN)
    with pytest.raises(ValueError, match="takes no credential"):
        store.save(provider="openai_compatible", endpoint="https://llm.approved.example/v1",
                   secrets={"auth_token": "x"}, expires_at=None, by=ADMIN)
    store.save(provider="openai_compatible", endpoint="https://llm.approved.example/v1", secrets={"api_key": "k2"},
               expires_at=None, by=ADMIN)
    assert effective(session, settings).endpoint == "https://llm.approved.example/v1"


def test_switching_provider_never_sends_one_vendors_key_to_another(session):
    settings = st()
    store = IntegrationStore(session, settings)
    store.save(provider="openrouter", endpoint=None, secrets={"api_key": "router-key"}, expires_at=None, by=ADMIN)
    store.save(provider="openai_compatible", endpoint="https://llm.internal.example/v1", secrets={}, expires_at=None,
               by=ADMIN)
    assert effective(session, settings).secrets == {}                         # not the router's key
    store.save(provider="openrouter", endpoint=None, secrets={}, expires_at=None, by=ADMIN)
    assert effective(session, settings).secrets == {"api_key": "router-key"}


def test_the_console_choice_wins_over_the_settings_and_off_means_off(session):
    settings = st(llm_provider="openai_compatible", llm_endpoint="https://llm.internal.example/v1")
    assert configured(session, settings) and effective(session, settings).source == "settings"
    IntegrationStore(session, settings).save(provider="none", endpoint=None, secrets={}, expires_at=None, by=ADMIN)
    assert not configured(session, settings)


# ============================================================================== the in-house gateway's SDK
def test_the_gateway_answers_through_the_service_account_with_the_platforms_grounding(session):
    settings = st()
    connect(session, settings)
    catalogue.refresh(session, settings)
    out = LLMGateway(session, settings).grounded("incident.summary", "What happened?", EVIDENCE)
    assert out["source"] == "llm" and out["claims"][0]["evidence_ids"] == ["E1"]
    call = session.query(LLMCall).filter_by(workflow="incident.summary").one()
    assert call.status == "ok" and call.provider == "enterprise_gateway" and call.prompt_tokens > 0
    assert sdk.STATE["calls"][-1]["model"] == call.requested_model


def test_an_expired_token_falls_back_to_the_platforms_text_and_tells_the_administrators(session):
    settings = st()
    connect(session, settings)
    catalogue.refresh(session, settings)
    sdk.STATE["tokens"] = set()                                             # the gateway revoked the token
    out = LLMGateway(session, settings).grounded("incident.summary", "What happened?", EVIDENCE)
    assert out["source"] == "deterministic"                                 # nothing fails
    assert session.query(LLMCall).filter_by(workflow="incident.summary").one().status == "auth_error"
    assert insights(session, "llm_credentials")[0].severity == "high"
    sdk.STATE["tokens"] = {"new-token"}
    connect(session, settings, token="new-token")
    _Breaker.failures, _Breaker.open_until = 0, 0.0
    assert connection_check(session, settings, ADMIN)["ok"]
    assert not insights(session, "llm_credentials")                         # cleared once the new token works


def test_test_connection_names_the_missing_sdk_and_its_fix(session, monkeypatch):
    settings = st()
    connect(session, settings)
    monkeypatch.setenv("SOC_LLM_GATEWAY_SDK", "not_an_installed_gateway_sdk")
    out = connection_check(session, settings, ADMIN)
    assert not out["ok"]
    step = next(x for x in out["steps"] if x["step"] == "Gateway SDK installed")
    assert not step["ok"] and "package index" in step["fix"]


def test_test_connection_walks_every_step_and_warns_when_tokens_are_estimated(session):
    settings = st()
    connect(session, settings)
    sdk.STATE["usage"] = False
    out = connection_check(session, settings, ADMIN)
    assert out["ok"], out
    assert [x["step"] for x in out["steps"]] == ["Provider chosen", "Gateway SDK installed", "Credentials entered",
                                                 "Provider starts", "Model list", "A model to test",
                                                 "Answer passes the platform's check", "Token usage reported"]
    assert out["steps"][-1]["warning"]                                    # budgets use an estimate, said so


def test_gateway_calls_overlap_on_its_event_loop(session):
    """Narratives run in parallel: the async SDK must not serialise them (counted in flight, not timed)."""
    from soc_platform.llm.providers.enterprise_gateway import EnterpriseGatewayProvider

    settings = st()
    p = EnterpriseGatewayProvider(settings, credentials={"auth_token": TOKEN})
    sdk.STATE["delay"] = 0.3
    with ThreadPoolExecutor(4) as pool:
        list(pool.map(lambda _: p.complete("sys", "[E1] (x) a", tier="small", model="GPT 6 Sol"), range(4)))
    assert sdk.STATE["max_in_flight"] >= 2 and sdk.STATE["sessions"] == 1


# ============================================================================== following a model line
def _setup(session, settings, **chosen):
    connect(session, settings)
    catalogue.refresh(session, settings)
    UsagePolicyStore(session, settings).save({"chosen_defaults": {"small": "GPT 6 Luna", "large": "GPT 6 Sol"},
                                              **chosen}, ADMIN, "baseline")


def test_a_newer_version_in_the_same_generation_is_checked_then_used_without_anyone_changing_settings(session):
    settings = st()
    _setup(session, settings)
    out = catalogue.refresh(session, settings)
    assert out["adopted"] == [{"line": "gpt sol", "from": "GPT 6 Sol", "to": "GPT 6.1 Sol"}]
    assert rule_for(UsagePolicyStore(session, settings).active(), "incident.summary", "large")["model"] == "GPT 6.1 Sol"
    sdk.STATE["models"].append("GPT 6.2 Sol")                              # the gateway publishes a new version
    catalogue.refresh(session, settings)
    pol = UsagePolicyStore(session, settings).active()
    assert rule_for(pol, "incident.summary", "large")["model"] == "GPT 6.2 Sol"
    assert rule_for(pol, "incident.summary", "large")["chosen"] == "GPT 6 Sol"     # the choice itself is unchanged
    LLMGateway(session, settings).grounded("incident.summary", "What happened?", EVIDENCE)
    assert sdk.STATE["calls"][-1]["model"] == "GPT 6.2 Sol"
    assert [e.payload["to"] for e in session.query(AuditEvent).filter_by(event_type="llm.model_adopted")] == [
        "GPT 6.1 Sol", "GPT 6.2 Sol"]
    assert {i.title for i in insights(session, "llm_adopted")} == {
        "AI model upgraded: GPT 6 Sol -> GPT 6.1 Sol (passed the platform's check)",
        "AI model upgraded: GPT 6.1 Sol -> GPT 6.2 Sol (passed the platform's check)"}


def test_refreshing_again_with_nothing_new_changes_nothing(session):
    settings = st()
    _setup(session, settings)
    catalogue.refresh(session, settings)
    before = (session.query(catalogue.LLMLineAdoption).count(), session.query(Insight).count(),
              session.query(catalogue.LLMCatalogueModel).count())
    catalogue.refresh(session, settings)
    assert (session.query(catalogue.LLMLineAdoption).count(), session.query(Insight).count(),
            session.query(catalogue.LLMCatalogueModel).count()) == before


def test_a_version_that_fails_the_check_is_not_used_and_is_not_rechecked_for_a_day(session):
    settings = st()
    sdk.STATE["bad_models"] = {"GPT 6.1 Sol"}
    _setup(session, settings)
    out = catalogue.refresh(session, settings)
    assert out["adopted"] == [] and out["failed_checks"][0]["model"] == "GPT 6.1 Sol"
    assert rule_for(UsagePolicyStore(session, settings).active(), "incident.summary", "large")["model"] == "GPT 6 Sol"
    assert "failed the platform's check" in insights(session, "llm_check_failed")[0].title
    checks = len([c for c in sdk.STATE["calls"] if c["model"] == "GPT 6.1 Sol"])
    catalogue.refresh(session, settings)
    assert len([c for c in sdk.STATE["calls"] if c["model"] == "GPT 6.1 Sol"]) == checks


def test_a_new_generation_waits_for_an_administrator_who_approves_it_after_the_check(session):
    settings = st()
    sdk.STATE["models"].append("GPT 7 Sol")
    _setup(session, settings)
    out = catalogue.refresh(session, settings)
    assert out["awaiting_approval"] == [{"line": "gpt sol", "current": "GPT 6.1 Sol", "offered": "GPT 7 Sol"}]
    assert "awaiting an administrator's approval" in insights(session, "llm_generation")[0].title
    with pytest.raises(PermissionError):
        catalogue.approve(session, settings, "gpt sol", "GPT 7 Sol", LEAD)
    catalogue.approve(session, settings, "gpt sol", "GPT 7 Sol", ADMIN)
    assert rule_for(UsagePolicyStore(session, settings).active(), "incident.summary", "large")["model"] == "GPT 7 Sol"
    assert not insights(session, "llm_generation")
    sdk.STATE["bad_models"] = {"GPT 7.1 Sol"}
    sdk.STATE["models"].append("GPT 7.1 Sol")
    catalogue.refresh(session, settings)                                    # 7.1 fails its check: stays on 7
    assert rule_for(UsagePolicyStore(session, settings).active(), "incident.summary", "large")["model"] == "GPT 7 Sol"


def test_rolling_back_returns_to_the_previous_version_and_never_adopts_the_bad_one_again(session):
    settings = st()
    _setup(session, settings)
    catalogue.refresh(session, settings)                                    # 6 -> 6.1
    catalogue.rollback(session, settings, "gpt sol", ADMIN)
    assert rule_for(UsagePolicyStore(session, settings).active(), "incident.summary", "large")["model"] == "GPT 6 Sol"
    catalogue.refresh(session, settings)
    assert rule_for(UsagePolicyStore(session, settings).active(), "incident.summary", "large")["model"] == "GPT 6 Sol"
    catalogue.unblock(session, settings, "GPT 6.1 Sol", ADMIN)
    catalogue.refresh(session, settings)
    assert rule_for(UsagePolicyStore(session, settings).active(), "incident.summary", "large")["model"] == "GPT 6.1 Sol"


def test_a_pinned_feature_and_a_pinned_line_stay_where_they_are(session, monkeypatch):
    settings = st()
    _setup(session, settings, workflows={"phishing.explanation": {"model": "GPT 6 Sol", "follow": False}})
    catalogue.refresh(session, settings)
    pol = UsagePolicyStore(session, settings).active()
    assert rule_for(pol, "phishing.explanation", "small")["model"] == "GPT 6 Sol"     # the feature is pinned
    assert rule_for(pol, "incident.summary", "large")["model"] == "GPT 6.1 Sol"       # the rest follow the line
    monkeypatch.setenv("SOC_LLM_MODEL_VERSION", "GPT 6.1 Sol")
    sdk.STATE["models"].append("GPT 6.2 Sol")
    assert catalogue.refresh(session, settings)["adopted"] == []           # a deployment pin wins


def test_with_automatic_upgrades_off_a_new_version_is_offered_for_approval(session):
    settings = st()
    _setup(session, settings, auto_upgrade=False)
    out = catalogue.refresh(session, settings)
    assert out["adopted"] == [] and out["awaiting_approval"][0]["offered"] == "GPT 6.1 Sol"
    catalogue.approve(session, settings, "gpt sol", "GPT 6.1 Sol", ADMIN)
    assert rule_for(UsagePolicyStore(session, settings).active(), "incident.summary", "large")["model"] == "GPT 6.1 Sol"


def test_a_model_being_retired_with_nothing_newer_is_raised_before_calls_fail(session):
    settings = st()
    _setup(session, settings)
    sdk.STATE["retiring"] = {"GPT 6 Luna"}
    out = catalogue.refresh(session, settings)
    assert out["retiring"] == ["GPT 6 Luna"]
    assert insights(session, "llm_retiring")[0].severity == "high"


def test_choosing_another_version_makes_it_the_one_in_use_and_saving_again_moves_nothing(session):
    settings = st()
    sdk.STATE["models"].append("GPT 6.2 Sol")
    _setup(session, settings)
    catalogue.refresh(session, settings)                                    # 6 -> 6.2
    store = UsagePolicyStore(session, settings)
    store.save({"chosen_defaults": {"small": "GPT 6 Luna", "large": "GPT 6.1 Sol"}}, ADMIN, "step back on purpose")
    assert rule_for(store.active(), "incident.summary", "large")["model"] == "GPT 6.1 Sol"
    store.save({"chosen_defaults": {"small": "GPT 6 Luna", "large": "GPT 6.1 Sol"}, "monthly_tokens": 9_000_000},
               ADMIN, "budget only")
    assert rule_for(store.active(), "incident.summary", "large")["model"] == "GPT 6.1 Sol"
    assert session.query(catalogue.LLMLineAdoption).filter_by(reason="chosen").count() == 1


def test_an_expiring_token_is_raised_before_it_expires_and_again_when_it_has(session, monkeypatch):
    settings = st()
    connect(session, settings, expires_at=utcnow() + timedelta(days=1))
    catalogue.refresh(session, settings)
    assert "expires within days" in insights(session, "llm_credential_expiry")[0].title
    monkeypatch.setenv("SOC_CLOCK_OFFSET_SECONDS", str(timedelta(days=2).total_seconds()))
    catalogue.refresh(session, settings)
    assert "expired" in insights(session, "llm_credential_expiry")[0].title


def test_an_administrator_adds_a_model_the_provider_does_not_list(session, monkeypatch):
    settings = st()
    monkeypatch.setenv("SOC_LLM_GATEWAY_MODELS_CALL", "")                  # this gateway publishes no list
    sdk.STATE["models"].append("GPT 6.1 Sol")
    connect(session, settings)
    catalogue.add_model(session, settings, "GPT 6 Sol", ADMIN)
    UsagePolicyStore(session, settings).save({"chosen_defaults": {"large": "GPT 6 Sol"}}, ADMIN, "baseline")
    catalogue.add_model(session, settings, "GPT 6.1 Sol", ADMIN)
    assert catalogue.refresh(session, settings)["adopted"][0]["to"] == "GPT 6.1 Sol"
    with pytest.raises(PermissionError):
        catalogue.add_model(session, settings, "GPT 6.2 Sol", LEAD)


# ============================================================================== OpenRouter
def test_openrouter_asks_that_no_vendor_keeps_the_prompt_and_reads_the_model_list(session, monkeypatch):
    import httpx

    seen: dict = {}

    class R:
        status_code = 200

        def __init__(self, body):
            self._b = body

        def json(self):
            return self._b

        def raise_for_status(self):
            return None

    def post(url, headers=None, json=None, **kw):
        seen.update({"url": url, "auth": headers.get("Authorization"), "body": json})
        return R({"choices": [{"message": {"content": '{"summary": "ok", "claims": []}'}}],
                  "usage": {"prompt_tokens": 5, "completion_tokens": 2}, "model": json["model"]})

    def get(url, headers=None, **kw):
        return R({"data": [{"id": "openai/gpt-5.1"}, {"id": "openai/gpt-5", "expiration_date": "2026-12-31"}]})

    monkeypatch.setattr(httpx, "post", post)
    monkeypatch.setattr(httpx, "get", get)
    settings = st()
    IntegrationStore(session, settings).save(provider="openrouter", endpoint=None, secrets={"api_key": "or-key"},
                                             expires_at=None, by=ADMIN)
    catalogue.refresh(session, settings)
    names = {m["name"]: m for m in catalogue.view(session, settings)["models"]}
    assert set(names) == {"openai/gpt-5.1", "openai/gpt-5"} and names["openai/gpt-5"]["deprecated"]
    LLMGateway(session, settings).complete_json("incident.summary", "s", "u")
    assert seen["url"] == "https://openrouter.ai/api/v1/chat/completions" and seen["auth"] == "Bearer or-key"
    assert seen["body"]["provider"] == {"data_collection": "deny"}


# ============================================================================== the API
@pytest.fixture()
def client(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from soc_platform.api import app as appmod
    from soc_platform.config import get_settings
    from soc_platform.core import db as dbm
    from soc_platform.core.auth import issue_dev_token

    secret = "llm-integration-secret-0123456789abcdef"
    for k, v in {"SOC_AUTH_MODE": "dev", "SOC_DEV_JWT_SECRET": secret, "SOC_ORG_DOMAINS": "acme-demo.com",
                 "SOC_DATABASE_URL": f"sqlite:///{(tmp_path / 'i.db').as_posix()}", "SOC_EMBEDDED_SCHEDULER": "0",
                 "SOC_DATA_KEY": Fernet.generate_key().decode(), "SOC_LLM_PROVIDER": "none"}.items():
        monkeypatch.setenv(k, v)
    get_settings.cache_clear()
    dbm._default = None
    appmod.registry.cache_clear()
    dbm.get_database().create_all()
    tok = lambda u, r: {"Authorization": "Bearer " + issue_dev_token(secret, u, [r])}
    with TestClient(appmod.app) as c:
        yield c, tok
    get_settings.cache_clear()
    dbm._default = None
    appmod.registry.cache_clear()


def test_the_api_sets_the_provider_never_returns_a_credential_and_manages_model_lines(client):
    c, tok = client
    admin, lead, auditor = tok(ADMIN.id, "admin"), tok(LEAD.id, "lead"), tok("au@acme-demo.com", "auditor")
    assert c.get("/api/v1/llm/status", headers=lead).json()["configured"] is False
    body = {"provider": "enterprise_gateway", "secrets": {"auth_token": TOKEN, "session_token": "svc-session"},
            "note": "service account"}
    assert c.put("/api/v1/admin/llm/integration", headers=lead, json=body).status_code == 403
    assert c.put("/api/v1/admin/llm/integration", headers=auditor, json=body).status_code == 403
    r = c.put("/api/v1/admin/llm/integration", headers=admin, json=body)
    assert r.status_code == 200 and TOKEN not in r.text
    got = c.get("/api/v1/admin/llm/integration", headers=auditor)
    assert got.status_code == 200 and TOKEN not in got.text and "svc-session" not in got.text
    assert [x["set"] for x in got.json()["credentials"]] == [True, True] and got.json()["gateway_sdk"]["installed"]
    assert c.get("/api/v1/llm/status", headers=lead).json() | {"configured": True} == \
        c.get("/api/v1/llm/status", headers=lead).json()
    assert c.post("/api/v1/admin/llm/integration/test", headers=admin).json()["ok"]
    cat = c.post("/api/v1/admin/llm/catalogue/refresh", headers=admin).json()["catalogue"]
    assert {m["name"] for m in cat["models"]} == {"GPT 6 Sol", "GPT 6.1 Sol", "GPT 6 Luna"}
    pol = c.get("/api/v1/admin/llm/policy", headers=auditor).json()
    doc = {**pol["policy"], "chosen_defaults": {"small": "GPT 6 Luna", "large": "GPT 6 Sol"}}
    assert c.post("/api/v1/admin/llm/policy", headers=admin, json={"policy": doc, "note": "baseline"}).status_code == 200
    sdk.STATE["models"].append("GPT 7 Sol")
    lines = {x["line"]: x for x in c.post("/api/v1/admin/llm/catalogue/refresh", headers=admin).json()["catalogue"]["lines"]}
    assert lines["gpt sol"]["in_use"] == "GPT 6.1 Sol" and lines["gpt sol"]["next_generation"] == "GPT 7 Sol"
    assert c.post("/api/v1/admin/llm/lines/approve", headers=lead,
                  json={"line": "gpt sol", "model": "GPT 7 Sol"}).status_code == 403
    after = c.post("/api/v1/admin/llm/lines/approve", headers=admin, json={"line": "gpt sol", "model": "GPT 7 Sol"})
    assert {x["line"]: x["in_use"] for x in after.json()["lines"]}["gpt sol"] == "GPT 7 Sol"
    back = c.post("/api/v1/admin/llm/lines/rollback", headers=admin, json={"line": "gpt sol"}).json()
    assert {x["line"]: x["in_use"] for x in back["lines"]}["gpt sol"] == "GPT 6.1 Sol"
    bad = c.post("/api/v1/admin/llm/lines/approve", headers=admin, json={"line": "gpt sol", "model": "GPT 7 Sol"})
    assert bad.status_code == 400 and "rolled back" in bad.json()["detail"]
    assert c.post("/api/v1/admin/llm/models/unblock", headers=admin, json={"name": "GPT 7 Sol"}).status_code == 200
    assert c.post("/api/v1/admin/llm/catalogue/models", headers=admin, json={"name": "GPT 6.5 Luna"}).status_code == 200
    hist = c.get("/api/v1/admin/llm/catalogue", headers=auditor).json()["history"]
    assert [h["reason"] for h in hist][:3] == ["rollback", "approved", "automatic"]
    trail = c.get("/api/v1/audit?limit=200", headers=auditor)
    assert trail.status_code == 200 and TOKEN not in trail.text


def test_a_deployment_can_supply_the_gateway_tokens_from_a_vault_mount(session, monkeypatch, tmp_path):
    token_file = tmp_path / "gateway-token"
    token_file.write_text(TOKEN + "\n", encoding="utf-8")
    monkeypatch.setenv("SOC_LLM_GATEWAY_AUTH_TOKEN_FILE", str(token_file))
    settings = st(llm_provider="enterprise_gateway")
    creds = IntegrationStore(session, settings).status()["credentials"]
    assert [(c["name"], c["set"], c["managed_by_deployment"]) for c in creds] == [
        ("auth_token", True, True), ("session_token", False, True)]
    catalogue.refresh(session, settings)
    out = LLMGateway(session, settings).grounded("incident.summary", "What happened?", EVIDENCE)
    assert out["source"] == "llm" and TOKEN not in json.dumps(IntegrationStore(session, settings).status())


def test_a_provider_chosen_in_the_console_never_inherits_the_settings_model_names(session, monkeypatch):
    """Regression (feature verification with a live .env): SOC_LLM_DEPLOYMENT / SOC_LLM_MODELS describe the provider
    configured in the settings; with the gateway chosen in the console, features asked it for those names, it did not
    serve them, and every call fell back to the platform's own text."""
    monkeypatch.setenv("SOC_LLM_MODELS", "gpt-4.1-mini,gpt-4.1")
    monkeypatch.setenv("SOC_LLM_DEPLOYMENT_SMALL", "gpt-4.1-nano")
    settings = st(llm_provider="azure_foundry", llm_deployment="gpt-4.1-mini")
    connect(session, settings)
    catalogue.refresh(session, settings)
    pol = UsagePolicyStore(session, settings).active()
    assert {m["name"] for m in pol["models"]} == {"GPT 6 Sol", "GPT 6.1 Sol", "GPT 6 Luna"}
    assert set(pol["default_models"].values()) <= {"GPT 6 Sol", "GPT 6.1 Sol", "GPT 6 Luna"}
    out = LLMGateway(session, settings).grounded("incident.summary", "What happened?", EVIDENCE)
    assert out["source"] == "llm"
