"""Live checks against the configured LLM endpoint (costs tokens). Run with SOC_LIVE_LLM=1.

Reads SOC_LLM_* from the environment, or from the repository's .env if they are not set there. Every call goes
through the same gateway as production: redaction, approved-endpoint allow-list, pinned model, budget, logging.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from soc_platform.config import Settings

ROOT = Path(__file__).resolve().parents[2]
pytestmark = [pytest.mark.live,
              pytest.mark.skipif(os.environ.get("SOC_LIVE_LLM") != "1", reason="set SOC_LIVE_LLM=1 for live LLM tests")]


def _llm_env() -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k.startswith("SOC_LLM_")}
    if "SOC_LLM_PROVIDER" not in env and (ROOT / ".env").is_file():
        for line in (ROOT / ".env").read_text(encoding="utf-8").splitlines():
            k, sep, v = line.partition("=")
            if sep and k.strip().startswith("SOC_LLM_"):
                env[k.strip()] = v.split(" #")[0].strip()
    return env


@pytest.fixture(scope="module")
def llm_settings():
    env = _llm_env()
    if env.get("SOC_LLM_PROVIDER", "none") == "none":
        pytest.skip("no LLM provider configured")
    for k in ("SOC_LLM_API_KEY",):                     # providers read the key through config.secret()
        if env.get(k):
            os.environ[k] = env[k]
    return Settings(llm_provider=env["SOC_LLM_PROVIDER"], llm_endpoint=env.get("SOC_LLM_ENDPOINT"),
                    llm_deployment=env.get("SOC_LLM_DEPLOYMENT"), llm_model_version=env.get("SOC_LLM_MODEL_VERSION"),
                    llm_approved_endpoints=[e.strip() for e in env.get("SOC_LLM_APPROVED_ENDPOINTS", "").split(",") if e.strip()],
                    org_domains=["acme-demo.com"], llm_redact_pii=True)


def test_provider_round_trip(llm_settings):
    from soc_platform.llm.gateway import build_provider

    out = build_provider(llm_settings).complete("You reply with JSON only.", 'Return exactly {"pong": true}.', tier="small")
    assert out is not None and json.loads(out.text).get("pong") is True
    if llm_settings.llm_model_version:
        assert llm_settings.llm_model_version in out.model                              # pinned model answered
    assert out.prompt_tokens > 0


def test_grounded_answer_is_cited_redacted_and_logged(session, llm_settings):
    from soc_platform.core.models import LLMCall
    from soc_platform.llm.gateway import LLMGateway

    gw = LLMGateway(session, llm_settings)
    ev = [{"id": "E1", "claim": "maria.okafor@acme-demo.com clicked a link to login.micros0ft-helpdesk.com at 09:05", "source": "proxy"},
          {"id": "E2", "claim": "powershell.exe on ACME-LT01 downloaded p.ps1 from the same domain at 09:07", "source": "edr"}]
    r = gw.grounded("live.test", "Was the user compromised? Answer in two short claims.", ev, tier="small")
    assert r["source"] == "llm" and r["claims"]
    assert all(set(c["evidence_ids"]) <= {"E1", "E2"} for c in r["claims"])
    call = session.query(LLMCall).filter(LLMCall.workflow == "live.test").one()
    assert "maria.okafor@acme-demo.com" not in call.prompt_redacted and call.status == "ok"


@pytest.fixture(scope="module")
def estate(llm_settings, tmp_path_factory):
    """The sample estate processed with the live LLM writing incident summaries and phishing explanations."""
    from soc_platform.connectors.registry import ConnectorRegistry
    from soc_platform.core.db import Database
    from soc_platform.domains.incident.service import IncidentService
    from soc_platform.domains.phishing.service import PhishingService
    from soc_platform.domains.vulnerability.service import VulnerabilityService
    from soc_platform.intelligence.analyst import IntelligenceService
    from soc_platform.llm.gateway import LLMGateway

    db = Database("sqlite://")
    db.create_all()
    s = db._factory()
    reg = ConnectorRegistry.all_fake()
    gw = LLMGateway(s, llm_settings)
    VulnerabilityService(s, reg, llm=gw).refresh()
    inc = IncidentService(s, reg, llm=gw)
    inc.ingest()
    for c in inc.cluster():
        inc.investigate(c.id)
    ph = PhishingService(s, reg, org_domains=["acme-demo.com"], llm=gw)
    for sub in ph.ingest_reported():
        ph.process(sub.id)
    IntelligenceService(s, gw).refresh()
    s.commit()
    yield s, reg, gw, tmp_path_factory.mktemp("reports")
    s.close()


def _calls(s, workflow_prefix):
    from soc_platform.core.models import LLMCall

    return [c for c in s.query(LLMCall).all() if c.workflow.startswith(workflow_prefix)]


def test_incident_summaries_written_by_llm_and_cited(estate):
    from soc_platform.core.models import Case

    s, *_ = estate
    calls = _calls(s, "incident.summary")
    assert calls and all(c.status == "ok" for c in calls)
    for case in s.query(Case).filter(Case.domain == "incident"):
        a = case.assessment or {}
        assert case.summary and a.get("claims"), case.title
        assert all(set(c["evidence_ids"]) <= set(a["evidence_index"]) for c in a["claims"])     # cited, valid ids


def test_phishing_explanation_written_by_llm_and_redacted(estate):
    import re

    from soc_platform.core.models import Case

    s, *_ = estate
    calls = _calls(s, "phishing.explanation")
    assert calls and all(c.status == "ok" for c in calls)
    assert not any(re.search(r"[\w.]+@acme-demo\.com", c.prompt_redacted) for c in calls)   # identities pseudonymised
    case = s.query(Case).filter(Case.domain == "phishing").first()
    assert case.verdict == "malicious" and (case.assessment or {}).get("claims")                 # verdict still from code


def test_analyst_answers_with_llm(estate):
    from soc_platform.intelligence.analyst import IntelligenceService

    s, _reg, gw, _ = estate
    r = IntelligenceService(s, gw).analyst.ask("What happened to jane.doe@acme-demo.com and what should we do first?")
    assert r["tool_calls"] and r["answer"]
    assert r.get("source") == "llm" and r["claims"]
    assert "attack_story" in [c["tool"] for c in r["tool_calls"]]


def test_deep_analysis_on_the_sample_estate(estate):
    from soc_platform.core.models import Case
    from soc_platform.intelligence.deep_analysis import run_deep_analysis
    from soc_platform.intelligence.story import evidence_for_llm, story_for_case

    s, reg, gw, _ = estate
    case = s.query(Case).filter(Case.domain == "phishing").first()
    st = story_for_case(s, case.id, reg)
    r = run_deep_analysis(s, st, gw, actor="live-test", org_domains=["acme-demo.com"])
    assert r["ok"], r
    valid = {e["id"] for e in evidence_for_llm(st)}
    assert r["key_findings"] and all(set(f["evidence_ids"]) <= valid for f in r["key_findings"])
    assert all(p["action_ref"] == "manual" or p.get("action_id") for p in r["priorities"])
    assert r["confidence"] in {"high", "medium", "low"}


def test_every_standard_report_with_llm_narrative(estate):
    import re

    from soc_platform.core.models import Case
    from soc_platform.reporting.builder import STANDARD, build_report, get_template, plan_report

    s, reg, gw, out = estate
    case = s.query(Case).filter(Case.domain == "incident", Case.severity == "critical").first()
    llm_sections = total = 0
    for tid in STANDARD:
        r = build_report(s, reg, get_template(s, tid), out, llm=gw, by="live-test", case_id=case.id)
        assert r["sections"] and not r["skipped"], tid
        for sec in r["sections"]:
            total += 1
            if sec["writer"] == "llm":
                llm_sections += 1
                cited = {int(n) for n in re.findall(r"F(\d+)", sec["narrative"])}
                assert cited and max(cited) <= len(sec["facts"]) + 20, (tid, sec["narrative"])
    assert llm_sections >= 0.8 * total, (llm_sections, total)                                   # fallback only rarely
    sp = plan_report("A one-page board brief on phishing and supplier risk this quarter, as slides", gw)
    assert sp["planner"] == "llm" and sp["format"] == "pptx" and 1 <= len(sp["sections"]) <= 4


def test_every_llm_call_succeeded_on_the_pinned_model(estate):
    from soc_platform.core.models import LLMCall

    s, *_ = estate
    calls = s.query(LLMCall).all()
    assert len(calls) >= 10
    assert {c.status for c in calls} == {"ok"}, {c.workflow: c.status for c in calls if c.status != "ok"}


def test_no_pseudonym_placeholders_reach_analysts(estate):
    """Models sometimes drop the brackets of <USER_1>; restore must still put the real identity back."""
    import re

    from soc_platform.core.models import Case
    from soc_platform.intelligence.models import Insight

    s, *_ = estate
    token = re.compile(r"\b(USER|PERSON|PHONE|ID|CARD)_\d+\b")
    texts = [i.narrative for i in s.query(Insight)] + [c.summary or "" for c in s.query(Case)]
    texts += [cl["text"] for c in s.query(Case) for cl in (c.assessment or {}).get("claims", [])]
    assert texts and not [t for t in texts if token.search(t or "")]
