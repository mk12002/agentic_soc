"""AI usage policy: administrators set budgets, per-person limits and the model tier / output cap of every feature;
over any limit the platform answers without the model (never fails); the usage screen advises a tier from measured
figures."""

from __future__ import annotations

import json
from datetime import timedelta

import pytest
from sqlalchemy import inspect, text

from soc_platform.config import Settings
from soc_platform.core.auth import Principal, Role
from soc_platform.core.models import LLMCall, utcnow
from soc_platform.llm.gateway import BudgetExceeded, Completion, LLMGateway, Provider, UserLimitExceeded
from soc_platform.llm.usage_policy import UsagePolicyStore, defaults, limits_for, usage_report, validate

ADMIN = Principal("ada@acme-demo.com", "Ada", frozenset({Role.ADMIN}))
LEAD = Principal("lena@acme-demo.com", "Lena", frozenset({Role.LEAD}))
ANALYST = Principal("al@acme-demo.com", "Al", frozenset({Role.ANALYST}))
EVIDENCE = [{"id": "E1", "claim": "3 hosts reached the domain", "source": "umbrella"}]


class Model(Provider):
    """Answers with one cited claim (and optionally one the evidence does not support); records what it was asked."""

    name = "fake"

    def __init__(self, *, bad_claims: int = 0, text: str | None = None, tokens: tuple[int, int] = (100, 50)) -> None:
        self.calls: list[dict] = []
        self.bad, self.text, self.tokens = bad_claims, text, tokens

    def complete(self, system, user, *, tier, max_tokens=None):
        self.calls.append({"tier": tier, "max_tokens": max_tokens})
        claims = [{"text": "3 hosts reached the domain", "kind": "fact", "evidence_ids": ["E1"]}]
        claims += [{"text": f"99{i} hosts were wiped", "kind": "fact", "evidence_ids": ["E1"]} for i in range(self.bad)]
        body = self.text if self.text is not None else json.dumps({"summary": "3 hosts reached it.", "claims": claims})
        return Completion(body, *self.tokens, "fake-1")


class OldModel(Provider):
    """A provider written before output caps existed: it must keep working."""

    name = "old"

    def complete(self, system, user, *, tier):
        return Completion(json.dumps({"summary": "ok", "claims": []}), 10, 10, "old-1")


def settings(**kw) -> Settings:
    return Settings(llm_provider="fake", llm_monthly_token_budget=kw.pop("monthly", 1_000_000), **kw)


def gw(session, model=None, actor=None, st=None) -> LLMGateway:
    return LLMGateway(session, st or settings(), provider=model or Model(), actor=actor)


def save(session, doc, by=ADMIN, st=None):
    return UsagePolicyStore(session, st or settings()).save(doc, by, "test")


def spend(session, tokens: int, *, actor: str | None = None, ago: timedelta = timedelta(0), wf: str = "x") -> None:
    session.add(LLMCall(workflow=wf, provider="fake", model="m", prompt_redacted="", prompt_tokens=tokens,
                        completion_tokens=0, status="ok", actor=actor, ts=utcnow() - ago, tier="large"))
    session.flush()


# ============================================================================== the policy document
def test_defaults_follow_the_deployment_budget_and_cap_a_day_at_a_tenth():
    d = defaults(settings(monthly=50_000_000))
    assert d["monthly_tokens"] == 50_000_000 and d["daily_tokens"] == 5_000_000
    assert d["max_output_tokens"] == {"small": 1_500, "large": 3_000} and not validate(d)


def test_every_mistake_in_a_policy_is_named():
    probs = "\n".join(validate({"monthly_tokens": 10, "daily_tokens": 20, "alert_at": 3, "colour": "red",
                                "user_default": {"hourly_tokens": -1, "weekly": 5},
                                "roles": {"wizard": {"daily_tokens": 1}}, "users": {"bob": {"hourly_tokens": 1}},
                                "workflows": {"incident.summary": {"tier": "medium", "max_output_tokens": 50},
                                              "made.up": {"tier": "small"}},
                                "max_output_tokens": {"huge": 100}, "prices": {"small": {"input": -1}}}))
    for needle in ("unknown setting 'colour'", "daily_tokens cannot be more", "alert_at", "user_default.hourly_tokens",
                   "user_default.weekly", "roles.wizard", "users.bob", "tier must be small or large",
                   "between 200 and 16000", "workflows.made.up", "max_output_tokens.huge", "prices.small"):
        assert needle in probs, needle


def test_only_an_administrator_sets_limits_and_every_change_is_kept_and_audited(session):
    from soc_platform.core.models import AuditRecord

    for who in (LEAD, ANALYST, Principal("svc", "svc", frozenset({Role.ADMIN}), is_service=True)):
        with pytest.raises(PermissionError):
            save(session, {"daily_tokens": 1000}, by=who)
    with pytest.raises(ValueError, match="daily_tokens cannot be more"):
        save(session, {"monthly_tokens": 10, "daily_tokens": 20})
    save(session, {"daily_tokens": 1000})
    save(session, {"daily_tokens": 2000})
    st = UsagePolicyStore(session, settings())
    assert st.active()["daily_tokens"] == 2000 and [h["document"]["daily_tokens"] for h in st.history()] == [2000, 1000]
    audit = [a for a in session.query(AuditRecord).all() if a.event_type == "llm_policy.changed"]
    assert len(audit) == 2 and audit[-1].payload["changes"]["daily_tokens"] == {"from": 1000, "to": 2000}


def test_a_person_gets_their_own_limit_else_their_most_generous_role_else_everyone_s():
    pol = {**defaults(settings()), "roles": {"analyst": {"hourly_tokens": 10}, "lead": {"hourly_tokens": 50}},
           "users": {"al@acme-demo.com": {"daily_tokens": 0}}}
    assert limits_for(pol, "x@acme-demo.com", ["analyst", "lead"])["hourly_tokens"] == 50
    assert limits_for(pol, "y@acme-demo.com", [])["hourly_tokens"] == 100_000
    assert limits_for(pol, "al@acme-demo.com", ["analyst"]) == {"hourly_tokens": 100_000, "daily_tokens": 0}


# ============================================================================== routing and caps
def test_each_feature_uses_the_tier_and_answer_cap_the_policy_sets(session):
    m = Model()
    save(session, {"workflows": {"incident.summary": {"tier": "small"},
                                 "report.section.*": {"max_output_tokens": 900}}})
    g = gw(session, m)
    g.grounded("incident.summary", "q", EVIDENCE, tier="large")
    g.grounded("report.section.risk", "q", EVIDENCE, tier="large")
    g.grounded("phishing.explanation", "q", EVIDENCE, tier="small")
    assert m.calls == [{"tier": "small", "max_tokens": 1_500}, {"tier": "large", "max_tokens": 900},
                       {"tier": "small", "max_tokens": 1_500}]
    assert [c.tier for c in session.query(LLMCall).order_by(LLMCall.ts).all()] == ["small", "large", "small"]


def test_a_provider_without_an_output_cap_still_works(session):
    assert gw(session, OldModel()).complete_json("report.plan", "s", "u", tier="small") == {"summary": "ok", "claims": []}


def test_a_feature_switched_off_answers_without_the_model(session):
    m = Model()
    save(session, {"workflows": {"intelligence.answer": {"enabled": False}}})
    out = gw(session, m).grounded("intelligence.answer", "q", EVIDENCE)
    assert out["source"] == "deterministic" and not m.calls
    assert session.query(LLMCall).one().status == "disabled_by_policy"


# ============================================================================== budgets and per-person limits
def test_the_daily_cap_stops_a_burst_from_spending_the_month(session):
    save(session, {"daily_tokens": 1_000})
    spend(session, 1_000)
    spend(session, 50_000, ago=timedelta(days=2))          # yesterday's use does not count against today
    m = Model()
    with pytest.raises(BudgetExceeded):
        gw(session, m).complete_json("incident.summary", "s", "u")
    assert not m.calls and gw(session).budget_status()["daily_exceeded"]


def test_the_monthly_cap_is_the_one_the_administrator_set(session):
    save(session, {"monthly_tokens": 5_000, "daily_tokens": 0})
    spend(session, 5_000)
    assert gw(session).grounded("incident.summary", "q", EVIDENCE)["source"] == "deterministic"
    assert session.query(LLMCall).filter_by(status="budget_exceeded").count() == 1


def test_a_person_over_their_limit_gets_an_answer_without_the_model_and_is_told_why(session):
    save(session, {"user_default": {"hourly_tokens": 1_000, "daily_tokens": 5_000}})
    spend(session, 1_000, actor=ANALYST.id, ago=timedelta(minutes=10))
    m = Model()
    g = gw(session, m, actor=ANALYST)
    out = g.grounded("intelligence.answer", "q", EVIDENCE)
    assert out["source"] == "deterministic" and not m.calls
    assert "hourly AI limit (1,000 tokens)" in g.notice
    with pytest.raises(UserLimitExceeded):
        g.complete_json("intelligence.plan", "s", "u")
    assert gw(session, m, actor=LEAD).grounded("intelligence.answer", "q", EVIDENCE)["source"] == "llm"   # others fine
    assert gw(session, m).grounded("incident.summary", "q", EVIDENCE)["source"] == "llm"          # scheduled work
    spend(session, 5_000, actor=LEAD.id, ago=timedelta(hours=3))      # over the 5,000 daily limit
    lead = gw(session, m, actor=LEAD)
    lead.grounded("intelligence.answer", "q", EVIDENCE)
    assert "daily AI limit" in lead.notice


def test_zero_switches_the_model_off_for_one_person(session):
    save(session, {"users": {ANALYST.id: {"hourly_tokens": 0}}})
    g = gw(session, actor=ANALYST)
    g.grounded("intelligence.answer", "q", EVIDENCE)
    assert "not enabled for your account" in g.notice


# ============================================================================== quality signals and the usage screen
def test_statements_the_evidence_check_removes_are_counted_and_unreadable_answers_marked(session):
    gw(session, Model(bad_claims=2)).grounded("incident.summary", "q", EVIDENCE)
    gw(session, Model(text="not json at all")).grounded("incident.summary", "q", EVIDENCE)
    rows = session.query(LLMCall).order_by(LLMCall.ts).all()
    assert (rows[0].claims_kept, rows[0].claims_dropped) == (1, 2) and rows[1].status == "unparseable"


def test_the_usage_screen_advises_a_tier_from_measured_figures(session):
    pol = defaults(settings())
    pol["prices"] = {"small": {"input": 0.1, "output": 0.4}, "large": {"input": 2.0, "output": 8.0}}
    for _ in range(25):        # large tier, short clean answers -> try small
        session.add(LLMCall(workflow="incident.summary", provider="f", model="m", prompt_redacted="", status="ok",
                            prompt_tokens=800, completion_tokens=300, tier="large", claims_kept=3, claims_dropped=0))
        # small tier, answers losing a third of their statements -> use large
        session.add(LLMCall(workflow="phishing.explanation", provider="f", model="m", prompt_redacted="", status="ok",
                            prompt_tokens=500, completion_tokens=400, tier="small", claims_kept=2, claims_dropped=1))
    session.add(LLMCall(workflow="intelligence.answer", provider="f", model="m", prompt_redacted="", status="ok",
                        prompt_tokens=900, completion_tokens=200, tier="large", actor=ANALYST.id))
    session.flush()
    r = usage_report(session, {**pol, "workflows": {"phishing.explanation": {"tier": "small"}}})
    f = {x["workflow"]: x for x in r["features"]}
    assert f["incident.summary"]["advice"] == "try small" and f["phishing.explanation"]["advice"] == "use large"
    assert f["intelligence.answer"]["advice"] == "not enough data"
    assert f["incident.summary"]["cost"] == pytest.approx(25 * (800 * 2.0 + 300 * 8.0) / 1e6, abs=1e-4)
    assert f["incident.summary"]["cost_on_other_tier"] < f["incident.summary"]["cost"]
    assert f["phishing.explanation"]["claims_dropped_rate"] == pytest.approx(1 / 3, abs=1e-3)
    assert r["users"] == [{"user": ANALYST.id, "period": 1_100, "today": 1_100, "hour": 1_100, "calls": 1}]
    assert set(f) >= {"report.section.*", "intelligence.deep_analysis"}       # every feature listed, used or not


def test_a_day_over_budget_raises_a_finding_that_clears_itself(session, monkeypatch):
    from soc_platform.core.selfcheck import llm_budget_alert
    from soc_platform.intelligence.models import Insight

    st = settings()
    save(session, {"daily_tokens": 100}, st=st)
    spend(session, 200)
    llm_budget_alert(session, st)
    ins = session.query(Insight).filter(Insight.title.like("Today's AI budget%")).one()
    assert ins.status == "new"
    monkeypatch.setenv("SOC_CLOCK_OFFSET_SECONDS", str(timedelta(days=1).total_seconds()))
    llm_budget_alert(session, st)
    assert ins.status == "resolved"


def test_an_existing_database_gains_the_new_call_log_columns(tmp_path):
    from soc_platform.core.db import Database

    d = Database(f"sqlite:///{(tmp_path / 'old.db').as_posix()}")
    d.create_all()
    with d.engine.begin() as c:                    # a database from before this release
        c.execute(text("DROP INDEX ix_llm_calls_actor"))
        for col in ("tier", "actor", "claims_kept", "claims_dropped"):
            c.execute(text(f"ALTER TABLE llm_calls DROP COLUMN {col}"))
    d.create_all()
    cols = {c["name"] for c in inspect(d.engine).get_columns("llm_calls")}
    assert {"tier", "actor", "claims_kept", "claims_dropped"} <= cols
    assert "ix_llm_calls_actor" in {i["name"] for i in inspect(d.engine).get_indexes("llm_calls")}


# ============================================================================== the API
@pytest.fixture()
def client(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from soc_platform.api import app as appmod
    from soc_platform.config import get_settings
    from soc_platform.core import db as dbm
    from soc_platform.core.auth import issue_dev_token
    from soc_platform.llm import gateway

    secret = "llm-usage-secret-0123456789abcdef0123"
    for k, v in {"SOC_AUTH_MODE": "dev", "SOC_DEV_JWT_SECRET": secret, "SOC_ORG_DOMAINS": "acme-demo.com",
                 "SOC_DATABASE_URL": f"sqlite:///{(tmp_path / 'u.db').as_posix()}", "SOC_EMBEDDED_SCHEDULER": "0",
                 "SOC_LLM_PROVIDER": "openai_compatible"}.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setattr(gateway, "build_provider", lambda st: Model())
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


def test_administrators_set_the_policy_and_people_see_why_the_model_was_not_used(client):
    c, tok = client
    admin, lead, auditor = tok(ADMIN.id, "admin"), tok(LEAD.id, "lead"), tok("au@acme-demo.com", "auditor")
    pol = c.get("/api/v1/admin/llm/policy", headers=auditor).json()
    assert pol["policy"]["daily_tokens"] == pol["defaults"]["daily_tokens"] and "incident.summary" in pol["workflows"]
    assert c.get("/api/v1/admin/llm/usage", headers=auditor).status_code == 200
    body = {"policy": {**pol["policy"], "users": {LEAD.id: {"hourly_tokens": 0}}}, "note": "pilot: lead off"}
    assert c.post("/api/v1/admin/llm/policy", headers=lead, json=body).status_code == 403
    bad = c.post("/api/v1/admin/llm/policy", headers=admin, json={"policy": {"daily_tokens": -5}})
    assert bad.status_code == 400 and "daily_tokens" in bad.json()["detail"]
    assert c.post("/api/v1/admin/llm/policy", headers=admin, json=body).status_code == 200
    r = c.post("/api/v1/intelligence/ask", headers=lead, json={"question": "Who is most at risk right now?"}).json()
    assert "not enabled for your account" in r["llm_notice"] and r["answer"]
    usage = c.get("/api/v1/admin/llm/usage", headers=admin).json()
    assert sum(f["refused"] for f in usage["features"]) >= 1


def test_a_used_up_month_raises_one_finding_not_a_daily_one_too(session):
    from soc_platform.core.selfcheck import llm_budget_alert
    from soc_platform.intelligence.models import Insight

    st = settings(monthly=1_000)
    save(session, {"monthly_tokens": 1_000, "daily_tokens": 100}, st=st)
    spend(session, 2_000)
    llm_budget_alert(session, st)
    assert [i.rule for i in session.query(Insight).all() if i.status == "new"] == ["llm_budget"]


def test_a_resolved_finding_is_not_presented_as_a_current_one(session):
    from soc_platform.intelligence.analyst import IntelligenceAnalyst
    from soc_platform.intelligence.models import Insight

    session.add(Insight(rule="llm_daily_budget", dedupe_key="k1", title="cleared", severity="medium", score=40.0,
                        status="resolved", entity_ids=[], domains=[], evidence=[], next_steps=[], requirement_refs=[]))
    session.add(Insight(rule="x", dedupe_key="k2", title="current", severity="high", score=60.0, status="new",
                        entity_ids=[], domains=[], evidence=[], next_steps=[], requirement_refs=[]))
    session.flush()
    page = IntelligenceAnalyst(session, None)._list_insights()
    assert [i["title"] for i in page] == ["current"] and page.total == 1
