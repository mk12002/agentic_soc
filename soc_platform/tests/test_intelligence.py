"""Intelligence layer: entity risk, cross-domain correlation, LLM analyst (with and without a model), providers."""

from __future__ import annotations

import json
import tempfile
from types import SimpleNamespace

import pytest

from soc_platform.config import Settings
from soc_platform.connectors.registry import ConnectorRegistry
from soc_platform.domains.incident.service import IncidentService
from soc_platform.domains.phishing.service import PhishingService
from soc_platform.domains.vulnerability.service import VulnerabilityService
from soc_platform.intelligence.analyst import IntelligenceService
from soc_platform.intelligence.models import Insight
from soc_platform.llm.gateway import Completion, LLMGateway, Provider, build_provider


@pytest.fixture()
def world(session):
    reg = ConnectorRegistry.all_fake()
    vm = VulnerabilityService(session, reg)
    vm.refresh()
    im = IncidentService(session, reg)
    im.ingest()
    for c in im.cluster():
        if c.status != "closed":
            im.investigate(c.id)
    ph = PhishingService(session, reg, org_domains=["cci-demo.com"], raw_dir=tempfile.mkdtemp())
    ph.process(ph.ingest_reported()[0].id)
    return vm


def test_cross_domain_correlations(session, world):
    ins = IntelligenceService(session, vm=world).refresh()
    rules = {i.rule for i in ins}
    assert {"phishing_compromise_chain", "privileged_after_compromise", "deception_corroborated",
            "exposed_host_under_attack", "control_gap", "new_kev_exposure", "entity_risk_high"} <= rules
    chain = next(i for i in ins if i.rule == "phishing_compromise_chain")
    assert "click -> endpoint execution -> identity compromise" in chain.title and chain.severity == "critical"
    assert all(e.get("ref") for i in ins for e in i.evidence)            # every insight cites evidence
    titles = " ".join(i.title for i in ins)
    assert "FS01-Finance-Backups" not in titles                         # Canary decoy is a sensor, not an asset
    assert "web01" not in " ".join(i.title for i in ins if i.rule == "exposed_host_under_attack")  # weak alert only
    db = next(i for i in ins if i.rule == "exposed_host_under_attack" and "db01" in i.title)
    assert "exploitation attempt" in db.title                           # T1190 alert + ProxyNotShell KEV
    assert all(i.narrative for i in ins)


def test_entity_risk_is_explainable_and_ranked(session, world):
    svc = IntelligenceService(session, vm=world)
    top = svc.analyst.risk.top(limit=3)
    assert top[0].name == "jane.doe@cci-demo.com" and top[0].band == "critical"
    assert {"email", "endpoint", "identity", "privileged_access", "deception"} <= set(top[0].dimensions)
    assert all(f.ref and f.source for f in top[0].factors)


def test_dismissed_insight_stays_dismissed_unless_worse(session, world):
    svc = IntelligenceService(session, vm=world)
    first = svc.refresh()
    target = next(i for i in first if i.rule == "control_gap")
    target.status = "dismissed"
    session.flush()
    svc.refresh()
    assert session.get(Insight, target.id).status == "dismissed"
    assert session.query(Insight).count() == len(first)                  # dedupe: no duplicates on re-run


def test_ask_without_llm_uses_deterministic_planner(session, world):
    a = IntelligenceService(session, vm=world).analyst
    r = a.ask("Is jane.doe@cci-demo.com compromised?")
    assert r["planner"] == "deterministic" and {"find_entity", "entity_risk"} <= {c["tool"] for c in r["tool_calls"]}
    assert "jane.doe@cci-demo.com is at CRITICAL risk" in r["answer"] and "Recommended first step" in r["answer"]
    ids = {f"R{i + 1}" for i in range(len(r["results"]))}
    assert r["claims"] and all(set(c["evidence_ids"]) <= ids for c in r["claims"])        # every claim is cited
    assert not any("{" in c["text"] for c in r["claims"])                                  # no raw JSON shown
    r2 = a.ask("which hosts are exposed to CVE-2021-44228?")
    assert "web01" in r2["answer"]


class ScriptedLLM(Provider):
    """Plans with one real and one hallucinated tool, then answers citing one real and one fake result id."""

    name = "scripted"

    def __init__(self) -> None:
        self.prompts: list[str] = []

    def complete(self, system, user, *, tier):
        self.prompts.append(user)
        if "TOOLS:" in user:
            return Completion(json.dumps({"calls": [
                {"tool": "top_risky", "args": {"limit": 3}},
                {"tool": "drop_all_tables", "args": {}},                       # not in catalogue -> ignored
                {"tool": "list_insights", "args": {"severity": "critical"}}]}), 50, 20, "m")
        return Completion(json.dumps({"summary": "Jane is the top risk.", "claims": [
            {"text": "Jane has the highest fused risk", "kind": "fact", "evidence_ids": ["R1"]},
            {"text": "Approve every pending action now", "kind": "inference", "evidence_ids": ["R99"]}]}), 80, 30, "m")


def test_ask_with_llm_plans_only_catalogue_tools_and_is_grounded(session, world):
    IntelligenceService(session, vm=world).refresh()
    llm = ScriptedLLM()
    gw = LLMGateway(session, Settings(llm_redact_pii=True, org_domains=["cci-demo.com"]), provider=llm)
    r = IntelligenceService(session, gw, vm=world).analyst.ask("Who is most at risk right now?")
    assert r["planner"] == "llm"
    assert [c["tool"] for c in r["tool_calls"]] == ["top_risky", "list_insights"]
    assert [c["text"] for c in r["claims"]] == ["Jane has the highest fused risk"]    # uncited claim dropped
    assert "jane.doe@cci-demo.com" not in llm.prompts[-1]                            # internal users pseudonymised
    assert gw.tokens_this_month() > 0


def test_brief_covers_all_domains(session, world):
    svc = IntelligenceService(session, vm=world)
    svc.refresh()
    b = svc.analyst.brief()
    assert "Top correlated threats" in b["summary"] and "Exposure:" in b["summary"]
    assert b["facts"]["pending_approvals"] > 0


# --------------------------------------------------------------------------- providers


def test_provider_factory():
    assert build_provider(Settings(llm_provider="none")).name == "none"
    assert build_provider(Settings(llm_provider="openai_compatible", llm_endpoint="http://llm:8000",
                                   llm_deployment="m")).name == "openai_compatible"
    with pytest.raises(ValueError):
        build_provider(Settings(llm_provider="openai_compatible", llm_endpoint="http://evil",
                                llm_approved_endpoints=["http://llm:8000"]))


def _msg(text, stop="end_turn"):
    return SimpleNamespace(stop_reason=stop, model="claude-opus-5",
                           content=[SimpleNamespace(type="text", text=text)],
                           usage=SimpleNamespace(input_tokens=11, output_tokens=7))


def test_anthropic_provider(monkeypatch):
    monkeypatch.setenv("SOC_LLM_API_KEY", "test-key")
    from soc_platform.llm.providers.anthropic_provider import AnthropicProvider

    p = AnthropicProvider(Settings(llm_provider="anthropic"))
    calls = {}
    p.client = SimpleNamespace(
        beta=SimpleNamespace(messages=SimpleNamespace(create=lambda **kw: calls.setdefault("large", kw) and _msg('{"a": 1}'))),
        messages=SimpleNamespace(create=lambda **kw: calls.setdefault("small", kw) and _msg('{"b": 2}')))
    out = p.complete("sys", "user", tier="large")
    assert out.text == '{"a": 1}' and out.prompt_tokens == 11 and out.completion_tokens == 7
    assert calls["large"]["model"] == "claude-opus-5" and calls["large"]["fallbacks"] == [{"model": "claude-opus-4-8"}]
    assert "JSON object only" in calls["large"]["system"]
    assert p.complete("sys", "user", tier="small").text == '{"b": 2}' and calls["small"]["model"] == "claude-haiku-4-5"
    p.client = SimpleNamespace(beta=SimpleNamespace(messages=SimpleNamespace(create=lambda **kw: _msg("", "refusal"))))
    assert p.complete("sys", "user", tier="large") is None           # refusal -> deterministic path


def test_openai_compatible_provider(monkeypatch):
    from soc_platform.llm.providers import openai_compatible as oc

    seen = {}

    def fake_post(url, headers=None, json=None, timeout=None):
        seen.update(url=url, model=json["model"])
        return SimpleNamespace(raise_for_status=lambda: None, json=lambda: {
            "model": json["model"], "choices": [{"message": {"content": '{"ok": true}'}}],
            "usage": {"prompt_tokens": 3, "completion_tokens": 2}})

    monkeypatch.setattr(oc.httpx, "post", fake_post)
    p = oc.OpenAICompatibleProvider(Settings(llm_endpoint="http://llm:8000", llm_deployment="qwen"))
    out = p.complete("s", "u", tier="large")
    assert out.text == '{"ok": true}' and seen["url"] == "http://llm:8000/v1/chat/completions"


def test_drift_monitor_flags_agreement_drop_and_verdict_shift(session):
    from datetime import timedelta

    from soc_platform.core.models import Case, Disposition, utcnow
    from soc_platform.intelligence.drift import drift_insights, drift_report

    now = utcnow()
    for i in range(30):  # baseline: mostly malicious verdicts, analysts agree
        t = now - timedelta(days=10 + i % 20)
        session.add(Case(domain="phishing", title=f"b{i}", verdict="malicious" if i % 5 else "safe", confidence=0.9,
                         created_at=t))
        session.add(Disposition(domain="phishing", subject_type="case", subject_id=f"b{i}", created_at=t,
                                system_verdict="malicious" if i % 5 else "safe",
                                analyst_verdict="malicious" if i % 5 else "safe", analyst="a"))
    for i in range(30):  # recent: model calls most things safe, analysts disagree
        t = now - timedelta(days=i % 6)
        session.add(Case(domain="phishing", title=f"r{i}", verdict="safe", confidence=0.55, created_at=t))
        session.add(Disposition(domain="phishing", subject_type="case", subject_id=f"r{i}", created_at=t,
                                system_verdict="safe", analyst_verdict="malicious" if i % 2 else "safe", analyst="a"))
    session.flush()
    d = drift_report(session)["domains"]["phishing"]
    assert d["status"] == "drift" and d["agreement"]["baseline"] == 1.0 and d["agreement"]["recent"] == 0.5
    assert d["psi_verdicts"] > 0.2
    ins = drift_insights(session)
    assert ins and ins[0].rule == "model_drift" and "R14" in ins[0].requirement_refs
    assert drift_report(session)["domains"]["incident"]["status"] == "insufficient_data"
