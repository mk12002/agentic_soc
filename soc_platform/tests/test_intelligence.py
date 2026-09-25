"""Intelligence layer: entity risk, cross-domain correlation, LLM analyst (with and without a model), providers."""

from __future__ import annotations

import json
import re
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
    ph = PhishingService(session, reg, org_domains=["acme-demo.com"], raw_dir=tempfile.mkdtemp())
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
    assert top[0].name == "jane.doe@acme-demo.com" and top[0].band == "critical"
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
    r = a.ask("Is jane.doe@acme-demo.com compromised?")
    assert r["planner"] == "deterministic" and {"find_entity", "entity_risk"} <= {c["tool"] for c in r["tool_calls"]}
    assert "jane.doe@acme-demo.com is at CRITICAL risk" in r["answer"] and "Recommended first step" in r["answer"]
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
    gw = LLMGateway(session, Settings(llm_redact_pii=True, org_domains=["acme-demo.com"]), provider=llm)
    r = IntelligenceService(session, gw, vm=world).analyst.ask("Who is most at risk right now?")
    assert r["planner"] == "llm"
    assert [c["tool"] for c in r["tool_calls"]] == ["top_risky", "list_insights"]
    assert [c["text"] for c in r["claims"]] == ["Jane has the highest fused risk"]    # uncited claim dropped
    assert "jane.doe@acme-demo.com" not in llm.prompts[-1]                            # internal users pseudonymised
    assert gw.tokens_this_month() > 0


def test_brief_covers_all_domains(session, world):
    svc = IntelligenceService(session, vm=world)
    svc.refresh()
    b = svc.analyst.brief()
    assert "Top correlated threats" in b["summary"] and "Exposure:" in b["summary"]
    assert b["facts"]["pending_approvals"] > 0


def test_counts_are_true_totals_not_capped_lists(session, world):
    """Regression: the brief said "30 pending approvals" when 34 were open (a 30-row list was being counted)."""
    from soc_platform.core.models import ActionRequest

    for i in range(45):
        session.add(ActionRequest(action_type="ticket.create", requested_by="t", idempotency_key=f"cap-{i}", status="recommended"))
    session.flush()
    true_total = session.query(ActionRequest).filter(ActionRequest.status.in_(("recommended", "pending_approval"))).count()
    svc = IntelligenceService(session, vm=world)
    svc.refresh()
    b = svc.analyst.brief()
    assert true_total > 30 and b["facts"]["pending_approvals"] == true_total
    r = svc.analyst.ask("How many actions are waiting for approval?")
    assert f"{true_total} action(s) awaiting approval" in r["answer"]


def test_llm_narrative_rewritten_when_the_finding_changes_not_on_score_drift(session, world):
    """Regression: an insight titled 100/100 kept a narrative written when it was 94/100."""
    from soc_platform.intelligence.correlation import _basis
    from soc_platform.intelligence.models import Insight

    class Narrator(Provider):
        name = "scripted"

        def __init__(self):
            self.prompts = []

        def complete(self, system, user, *, tier):
            self.prompts.append(user)
            return Completion(json.dumps({"summary": "narrative", "claims": [{"text": "x", "kind": "fact", "evidence_ids": ["E1"]}]}),
                              10, 10, "m")

    prov = Narrator()
    svc = IntelligenceService(session, LLMGateway(session, Settings(), provider=prov), vm=world)
    ins = svc.refresh()
    assert ins and all(i.narrative_source == "llm" for i in ins)
    assert not any(re.search(r"\(\d+/100\)", p.split("EVIDENCE")[0]) for p in prov.prompts)   # no score given to the model
    n = len(prov.prompts)
    svc.refresh()
    assert len(prov.prompts) == n                                                        # unchanged findings: no new calls
    target = session.query(Insight).filter(Insight.narrative_source == "llm").first()
    target.evidence = target.evidence[:-1]                                               # the finding's substance changes
    target_basis = _basis(target)
    session.flush()
    svc.refresh()
    fresh = session.get(Insight, target.id)
    assert _basis(fresh) != target_basis and fresh.narrative_source == "llm" and len(prov.prompts) > n


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


def test_azure_foundry_provider(monkeypatch):
    from soc_platform.llm.gateway import build_provider
    from soc_platform.llm.providers import openai_compatible as oc

    seen = {}

    def fake_post(url, headers=None, json=None, timeout=None):
        seen.update(url=url, headers=headers, model=json["model"])
        return SimpleNamespace(raise_for_status=lambda: None, json=lambda: {
            "model": "gpt-4.1-mini-2025-04-14", "choices": [{"message": {"content": '{"ok": true}'}}],
            "usage": {"prompt_tokens": 3, "completion_tokens": 2}})

    monkeypatch.setattr(oc.httpx, "post", fake_post)
    base = "https://res.services.ai.azure.com/openai/v1"
    st = Settings(llm_provider="azure_foundry", llm_endpoint=base + "/", llm_deployment="gpt-4.1-mini")
    monkeypatch.delenv("SOC_LLM_API_KEY", raising=False)
    assert build_provider(st).complete("s", "u", tier="large") is None            # no key -> deterministic path
    monkeypatch.setenv("SOC_LLM_API_KEY", "k" * 32)
    p = build_provider(st)
    out = p.complete("s", "u", tier="small")
    assert p.name == "azure_foundry" and out.model.startswith("gpt-4.1-mini")
    assert seen["url"] == base + "/chat/completions" and seen["model"] == "gpt-4.1-mini"
    assert seen["headers"] == {"api-key": "k" * 32}                                  # Azure key header, not Bearer
    with pytest.raises(ValueError):
        build_provider(Settings(llm_provider="azure_foundry", llm_endpoint="https://evil.example/openai/v1",
                                llm_approved_endpoints=[base]))


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
