"""Unit tests for evidence-grounded reasoning (anti-hallucination)."""

from __future__ import annotations

import soc_platform.domains.phishing.engine.orchestrator.llm_reasoner as reasoner
from soc_platform.domains.phishing.engine.orchestrator.evidence_collector import collect_evidence


def _disable_azure(monkeypatch):
    """Force the deterministic (no-Azure) grounded path so tests are hermetic."""
    monkeypatch.setattr(reasoner.settings, "azure_openai_endpoint", None, raising=False)
    monkeypatch.setattr(reasoner.settings, "azure_openai_api_key", None, raising=False)
    monkeypatch.setattr(reasoner.settings, "azure_openai_deployment", None, raising=False)


def _sample_results():
    return [
        {"agent_name": "content_agent", "risk_score": 0.82, "confidence": 0.7,
         "indicators": ["financial_signals:invoice,payment", "click_through_language"]},
        {"agent_name": "header_agent", "risk_score": 0.6, "confidence": 0.5,
         "indicators": ["spf_failed"]},
    ]


# --- claim validation -------------------------------------------------------

def test_validation_drops_claims_without_real_evidence():
    valid = {"E1", "E2", "E3"}
    claims = [
        {"text": "Real claim", "evidence_ids": ["E2"]},
        {"text": "Hallucinated claim", "evidence_ids": ["E99"]},   # invalid id -> dropped
        {"text": "No citation", "evidence_ids": []},               # no citation -> dropped
        {"text": "Mixed", "evidence_ids": ["E1", "E99"]},          # unknown id stripped, kept
        {"text": "", "evidence_ids": ["E1"]},                      # empty text -> dropped
    ]
    out = reasoner._validate_grounded_claims(claims, valid)
    texts = [c["text"] for c in out]
    assert texts == ["Real claim", "Mixed"]
    assert out[1]["evidence_ids"] == ["E1"]  # E99 stripped


# --- json parsing -----------------------------------------------------------

def test_parse_json_block_handles_fences_and_garbage():
    assert reasoner._parse_json_block('```json\n{"a": 1}\n```') == {"a": 1}
    assert reasoner._parse_json_block('prefix {"b": 2} suffix') == {"b": 2}
    assert reasoner._parse_json_block("not json at all") is None
    assert reasoner._parse_json_block(None) is None


# --- counterfactual name extraction (dict + legacy string shapes) -----------

def test_cf_agent_names_handles_dict_and_string():
    cf_dicts = {"agents_altered": [{"agent_name": "url_agent"}, {"agent_name": "content_agent"}]}
    cf_strings = {"agents_altered": ["url_agent", "content_agent"]}
    assert reasoner._cf_agent_names(cf_dicts) == ["url_agent", "content_agent"]
    assert reasoner._cf_agent_names(cf_strings) == ["url_agent", "content_agent"]
    assert reasoner._cf_agent_names({}) == []


# --- grounded reasoning end-to-end (deterministic path) ---------------------

def test_grounded_reasoning_every_claim_cites_valid_evidence(monkeypatch):
    _disable_azure(monkeypatch)
    results = _sample_results()
    evidence = collect_evidence(results)
    valid_ids = {e["id"] for e in evidence}

    out = reasoner.generate_grounded_reasoning(results, 0.71, evidence)

    assert out["grounded"] is True
    assert out["claims"], "deterministic grounding should produce claims"
    for claim in out["claims"]:
        assert claim["evidence_ids"], "every claim must cite evidence"
        assert set(claim["evidence_ids"]).issubset(valid_ids)
    # Explanation references evidence ids inline.
    assert any(c["evidence_ids"][0] in out["explanation"] for c in out["claims"])


def test_grounded_reasoning_with_no_evidence_is_safe(monkeypatch):
    _disable_azure(monkeypatch)
    out = reasoner.generate_grounded_reasoning([], 0.0, [])
    assert out["grounded"] is True
    assert out["claims"] == []
    assert isinstance(out["explanation"], str)


def test_fallback_explanation_handles_dict_agents_altered():
    # Regression: counterfactual agents_altered is now a list of dicts, not strings.
    cf = {"is_counterfactual": True,
          "agents_altered": [{"agent_name": "url_agent", "original_risk": 0.9, "attenuated_risk": 0.3}],
          "new_normalized_score": 0.4}
    text = reasoner._fallback_explanation(_sample_results(), 0.7, cf)
    assert "url_agent" in text  # name extracted from dict, no crash
