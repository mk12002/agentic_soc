"""The trained ML engine (seven agents, one per e-mail component) inside the platform's phishing pipeline.

The rest of the suite runs the heuristic analyser only (conftest pins SOC_PHISHING_ENGINE=0) so it stays fast and
does not need PyTorch. These tests prove the engine and the platform work together: every agent answers, the two
opinions are fused as documented, engine status notes are not cited as evidence, and a failing engine falls back.
Tests that load the models are skipped when PyTorch / transformers are not installed.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from soc_platform.domains.phishing.agents import analyzer as az
from soc_platform.domains.phishing.agents.analyzer import AnalysisResult, CompositeAnalyzer, Signal

ROOT = Path(__file__).resolve().parents[2]
CORPUS = ROOT / "artifacts" / "phishing" / "corpus"
AGENTS = {"header_agent", "content_agent", "url_agent", "attachment_agent", "sandbox_agent", "threat_intel_agent",
          "user_behavior_agent"}
needs_models = pytest.mark.skipif(not az.EngineAnalyzer.available(), reason="PyTorch / transformers not installed")


def _result(verdict, score, signals=(), backend="heuristic"):
    return AnalysisResult(verdict, score, 0.8, list(signals), backend)


# ---------------------------------------------------------------- fusion rules (no models needed)

def test_the_most_severe_opinion_wins_and_both_are_kept():
    h = _result("suspicious", 0.4, [Signal("urgency", 0.2, "urgent wording", "content")])
    e = _result("malicious", 0.93, [Signal("dmarc_failed", 0.3, "header_agent: dmarc_failed", "header")], "engine")
    c = CompositeAnalyzer.fuse(h, e)
    assert (c.verdict, c.backend, c.score) == ("malicious", "engine+heuristic", 0.93)
    assert c.raw["engine"]["verdict"] == "malicious" and c.raw["heuristic"]["verdict"] == "suspicious"
    assert {s.name for s in c.signals} == {"urgency", "dmarc_failed"}
    safe_h, safe_e = _result("safe", 0.05), _result("safe", 0.03, backend="engine")
    assert CompositeAnalyzer.fuse(safe_h, safe_e).verdict == "safe"


def test_an_engine_only_moderate_alarm_on_an_authenticated_sender_goes_to_an_analyst():
    """The observed false positive: a legitimate vendor invoice (DMARC/DKIM pass). The heuristic had one weak signal
    it had already outweighed; the old rule required none, so the invoice was declared malicious."""
    h = _result("safe", 0.15, [Signal("lookalike_url_domain", 0.3, "link domain resembles a partner", "url"),
                               Signal("strong_authentication", -0.15, "SPF, DKIM and DMARC pass", "header")])
    moderate = CompositeAnalyzer.fuse(h, _result("malicious", 0.70, backend="engine"))
    assert moderate.verdict == "suspicious" and "downgraded to suspicious" in moderate.raw["fusion_note"]
    confident = CompositeAnalyzer.fuse(h, _result("malicious", 0.90, backend="engine"))
    assert confident.verdict == "malicious" and confident.raw["fusion_note"] is None      # high confidence stands
    unauthenticated = copy.deepcopy(h)
    unauthenticated.signals = unauthenticated.signals[:1]
    assert CompositeAnalyzer.fuse(unauthenticated, _result("malicious", 0.70, backend="engine")).verdict == "malicious"


def test_engine_status_notes_are_not_evidence():
    # every status / absence note the seven agents emitted on the corpus (listed from a real run)
    for note in ("ml_header_model_used", "urls_analyzed=2", "heuristic_risk=0.2", "ml_slm_label:Legitimate",
                 "ml_slm_confidence:0.9499", "ml_attachment_model_used_ensemble_3", "no_attachments",
                 "no_attachments_for_sandbox", "sandbox_local_docker_disabled", "abuseipdb_not_configured",
                 "external_enrichment_score=0", "external_threat_enrichment_enabled", "local_match_score=0",
                 "malwarebazaar_unauthorized", "no_local_ioc_hits", "otx_not_configured", "external_lookups_enabled",
                 "google_safe_browsing_not_configured", "urlhaus_unauthorized", "virustotal_not_configured",
                 "no_urls_detected", "missing_data:short_smtp_trace", "confidence_capped_low_evidence"):
        assert az.ENGINE_STATUS_NOTE.search(note), note
    # real findings, in either direction, stay evidence
    for evidence in ("dmarc_failed", "spf_failed", "spf=fail", "reply_to_domain_mismatch", "urgency_signals:verify",
                     "credential_signals:login", "office_macro_presence:INV-4471.docm", "ml_slm_label:Phishing",
                     "domain_signal:suspicious_tld (.top)", "unfamiliar_sender_domain", "high_subdomain_entropy",
                     "ml_user_behavior_anomaly_detected", "txn_trust:auth_all_pass", "benign_allowlist_prior:github.com"):
        assert not az.ENGINE_STATUS_NOTE.search(evidence), evidence


def test_a_failing_engine_falls_back_to_the_heuristic_and_says_why():
    class Broken:
        def analyze(self, em, raw):
            raise RuntimeError("model file missing")

    from soc_platform.domains.phishing.agents.decompose import decompose

    raw = (CORPUS / "cred_phish_lookalike.eml").read_bytes()
    heur = az.HeuristicAnalyzer(org_domains=["acme-demo.com"])
    out = CompositeAnalyzer(heur, Broken()).analyze(decompose(raw), raw)
    assert out.backend == "heuristic" and out.verdict == "malicious" and "model file missing" in out.raw["engine_error"]


def test_the_setting_auto_follows_whether_the_engine_is_installed(monkeypatch):
    monkeypatch.setattr(az, "_ENGINE_AVAILABLE", None)
    monkeypatch.setattr(az.EngineAnalyzer, "available", classmethod(lambda cls: False))
    for mode, expected in (("auto", False), ("", False), ("1", True), ("0", False), ("off", False)):
        monkeypatch.setenv("SOC_PHISHING_ENGINE", mode)
        monkeypatch.setattr(az, "_ENGINE_AVAILABLE", None)
        assert az.engine_enabled() is expected, mode
    monkeypatch.setattr(az.EngineAnalyzer, "available", classmethod(lambda cls: True))
    monkeypatch.setattr(az, "_ENGINE_AVAILABLE", None)
    monkeypatch.setenv("SOC_PHISHING_ENGINE", "auto")
    assert az.engine_enabled() is True


# ---------------------------------------------------------------- the real models inside the pipeline

@pytest.fixture(scope="module")
def engine():
    if not az.EngineAnalyzer.available():
        pytest.skip("PyTorch / transformers not installed")
    e = az.EngineAnalyzer(offline=True)
    az.warm_up_engine()                                     # loads the models once for the module
    return e


@needs_models
def test_every_agent_scores_a_reported_email_inside_the_platform_pipeline(session, tmp_path, engine):
    from soc_platform.connectors.registry import ConnectorRegistry
    from soc_platform.domains.phishing.service import PhishingService

    ph = PhishingService(session, ConnectorRegistry.all_fake(), org_domains=["acme-demo.com"], raw_dir=tmp_path,
                         use_engine=True)
    sub = ph.submit_raw((CORPUS / "cred_phish_lookalike.eml").read_bytes(), source="test")
    v = ph.process(sub.id)
    detail = v["assessment"]["backend_detail"]
    assert v["completeness"]["analysis_backend"] == "engine+heuristic"
    assert set(detail["engine"]["agent_scores"]) == AGENTS - {"sandbox_agent"}  # all six in-platform agents answered
    assert v["completeness"]["missing_agents"] == []
    assert v["case"]["verdict"] == "malicious" and detail["engine"]["verdict"] == "malicious"
    engine_signals = [s for s in v["assessment"]["signals"] if s["agent"] in {a.replace("_agent", "") for a in AGENTS}]
    assert engine_signals and not any(az.ENGINE_STATUS_NOTE.search(s["name"]) for s in engine_signals)
    # the evidence the explanation cites includes what the models found
    rows = [e for dim in v["evidence"].values() for e in dim]
    assert any(e["source"] == "phishing.header" and "dmarc" in e["summary"].lower() for e in rows)


@needs_models
def test_the_combined_analysis_misses_no_phishing_in_the_labelled_corpus(engine):
    """Measured on the built-in corpus (small and synthetic - see docs/TEST_REPORT.md for what that does and does
    not show): the combined analysis detects every malicious or suspicious message, and no legitimate message is
    declared malicious (a disputed one goes to an analyst as suspicious)."""
    from soc_platform.connectors.registry import ConnectorRegistry
    from soc_platform.domains.phishing.agents.decompose import decompose
    from soc_platform.domains.phishing.supplier import load_suppliers

    heur = az.HeuristicAnalyzer(org_domains=["acme-demo.com"], threat_intel=ConnectorRegistry.all_fake().get("threat_intel"),
                                partner_domains=[d for sup in load_suppliers() for d in sup.domains])
    combined = CompositeAnalyzer(heur, engine)
    labels = json.loads((CORPUS / "labels.json").read_text())
    got = {}
    for name, label in labels.items():
        raw = (CORPUS / f"{name}.eml").read_bytes()
        got[name] = (label, combined.analyze(decompose(raw), raw).verdict)
    missed = [n for n, (lab, v) in got.items() if lab in {"malicious", "suspicious"} and v not in {"malicious", "suspicious"}]
    wrongly_malicious = [n for n, (lab, v) in got.items() if lab in {"safe", "spam"} and v == "malicious"]
    assert missed == [] and wrongly_malicious == [], got


# ---------------------------------------------------------------- the platform's data feeding the models

def test_the_threat_intel_agent_is_fed_by_the_platforms_intel_sources():
    none = az.platform_threat_intel_result([])
    assert none["risk_score"] == 0.0 and none["indicators"] == [] and none["source"] == "platform_threat_intel"
    hit = az.platform_threat_intel_result([{"type": "domain", "value": "micros0ft-helpdesk.com", "verdict": "malicious",
                                            "sources_hit": 3}, {"type": "ip", "value": "203.0.113.9", "verdict": "clean"}])
    assert hit["risk_score"] == 1.0 and hit["indicators"] == ["ti_malicious:domain:micros0ft-helpdesk.com (3 sources)"]
    assert az.platform_threat_intel_result([{"type": "domain", "value": "x.top", "verdict": "suspicious"}])["risk_score"] == 0.45


def test_the_sandbox_agent_runs_only_with_a_detonation_host(monkeypatch):
    agents = {n: object() for n in AGENTS}
    monkeypatch.delenv("SOC_PHISHING_SANDBOX", raising=False)
    assert "sandbox_agent" not in az.EngineAnalyzer.active_agents(agents)
    assert set(az.EngineAnalyzer.active_agents(agents)) == AGENTS - {"sandbox_agent"}
    monkeypatch.setenv("SOC_PHISHING_SANDBOX", "1")
    assert "sandbox_agent" in az.EngineAnalyzer.active_agents(agents)


def test_a_models_only_alarm_needs_a_reliable_model_or_the_rules_to_agree():
    """The content and user-behaviour models were the least reliable on the labelled mail: on their own they send a
    message to an analyst; with the header, URL, attachment or threat-intel model (or the rules) agreeing it stands."""
    h = _result("safe", 0.05)
    only_weak = _result("malicious", 0.9, backend="engine")
    only_weak.raw = {"agent_scores": {"content_agent": 0.95, "user_behavior_agent": 0.9, "header_agent": 0.1, "url_agent": 0.2}}
    c = CompositeAnalyzer.fuse(h, only_weak)
    assert c.verdict == "suspicious" and "content / user-behaviour" in c.raw["fusion_note"] and c.raw["corroborated_by"] == []
    backed = _result("malicious", 0.9, backend="engine")
    backed.raw = {"agent_scores": {"content_agent": 0.95, "url_agent": 0.93}}
    c = CompositeAnalyzer.fuse(h, backed)
    assert c.verdict == "malicious" and c.raw["corroborated_by"] == ["url_agent"]
    rules_agree = CompositeAnalyzer.fuse(_result("suspicious", 0.4), only_weak)
    assert rules_agree.verdict == "malicious"                           # the rules corroborate


def test_the_behaviour_model_uses_real_history_department_and_arrival_time():
    import sqlite3

    from soc_platform.domains.phishing.engine.preprocessing.user_behavior_feature_contract import (
        extract_behavior_features,
    )

    cur = sqlite3.connect(":memory:").cursor()
    cur.execute("CREATE TABLE employees (email_address TEXT, department TEXT)")
    cur.execute("CREATE TABLE interactions (recipient_email TEXT, sender_domain TEXT, interaction_count REAL, days_since_last REAL)")
    payload = {"headers": {"sender": "billing@azure.microsoft.com", "subject": "Your invoice", "to": ["jane.doe@acme-demo.com"]}}
    defaults = dict(zip(extract_behavior_features(payload, cur)["feature_names"],
                        extract_behavior_features(payload, cur)["numeric_vector"][0], strict=True))
    assert (defaults["contact_count"], defaults["days_since_last_contact"], defaults["is_business_hours"]) == (0.0, 365.0, 1.0)
    payload["behavior_context"] = {"contact_count": 11, "days_since_last_contact": 30, "department": "Finance",
                                   "is_business_hours": False}
    real = dict(zip(extract_behavior_features(payload, cur)["feature_names"],
                    extract_behavior_features(payload, cur)["numeric_vector"][0], strict=True))
    assert (real["contact_count"], real["days_since_last_contact"], real["is_business_hours"], real["dept_risk_tier"]) == (11, 30, 0, 1.0)


def test_behaviour_context_comes_from_mail_flow_directory_and_the_date_header():
    from soc_platform.connectors.registry import ConnectorRegistry
    from soc_platform.domains.phishing.agents.decompose import decompose
    from soc_platform.domains.phishing.service import behavior_context

    reg = ConnectorRegistry.all_fake()
    invoice = decompose((CORPUS / "legit_vendor_invoice.eml").read_bytes())
    ctx = behavior_context(invoice, None, org_domains=["acme-demo.com"], registry=reg, department_of=lambda upn: "Finance")
    assert ctx["recipient"] == "jane.doe@acme-demo.com" and ctx["contact_count"] == 11 and ctx["department"] == "Finance"
    assert ctx["days_since_last_contact"] > 0 and ctx["is_business_hours"] is False       # sent on a Sunday
    lookalike = decompose((CORPUS / "cred_phish_lookalike.eml").read_bytes())
    ctx = behavior_context(lookalike, None, org_domains=["acme-demo.com"], registry=reg, department_of=lambda upn: None)
    assert ctx["contact_count"] == 0 and "days_since_last_contact" not in ctx and "department" not in ctx


@needs_models
def test_with_the_platforms_data_the_genuine_invoice_is_safe_and_phishing_still_caught(session, tmp_path, engine):
    from soc_platform.connectors.base import SyncRunner
    from soc_platform.connectors.registry import ConnectorRegistry
    from soc_platform.core.context_store import ContextStore
    from soc_platform.domains.phishing.service import PhishingService

    reg = ConnectorRegistry.all_fake()
    SyncRunner(session, ContextStore(session)).sync(reg.get("entra"), "users")          # departments from the directory
    ph = PhishingService(session, reg, org_domains=["acme-demo.com"], raw_dir=tmp_path, use_engine=True)
    invoice = ph.process(ph.submit_raw((CORPUS / "legit_vendor_invoice.eml").read_bytes(), source="test").id)
    assert invoice["case"]["verdict"] == "safe", invoice["assessment"]["backend_detail"]
    assert invoice["assessment"]["backend_detail"]["engine"]["verdict"] != "malicious"
    phish = ph.process(ph.submit_raw((CORPUS / "cred_phish_lookalike.eml").read_bytes(), source="test").id)
    assert phish["case"]["verdict"] == "malicious"
    assert "sandbox_agent" not in phish["assessment"]["backend_detail"]["engine"]["agent_scores"]
