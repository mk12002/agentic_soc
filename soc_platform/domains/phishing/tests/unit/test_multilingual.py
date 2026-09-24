"""Tests for dependency-free multi-language phishing detection and its
integration into the content agent and grounded evidence."""

from __future__ import annotations

from soc_platform.domains.phishing.engine.agents.content_agent.multilingual import (
    analyze_multilingual,
    detect_language,
)
from soc_platform.domains.phishing.engine.agents.content_agent.agent import analyze as content_analyze
from soc_platform.domains.phishing.engine.orchestrator.evidence_collector import collect_evidence

SPANISH_PHISH = (
    "estimado cliente, su cuenta ha sido suspendida. verifique su cuenta e inicie "
    "sesión para confirmar su identidad. se requiere una transferencia urgente de fondos."
)
FRENCH_PHISH = (
    "cher client, votre compte est suspendu. vérifiez votre compte et confirmez "
    "votre identité immédiatement. un paiement urgent est requis."
)
ENGLISH_LEGIT = (
    "Hi team, please review the attached weekly project notes and the meeting "
    "agenda for tomorrow. Thanks and best regards, Operations."
)


def test_detect_language_basic() -> None:
    assert detect_language(SPANISH_PHISH) == "es"
    assert detect_language(FRENCH_PHISH) == "fr"
    assert detect_language(ENGLISH_LEGIT) == "en"
    assert detect_language("hola") == "unknown"  # too little signal


def test_spanish_phishing_detected_with_cross_language_flag() -> None:
    result = analyze_multilingual(SPANISH_PHISH)
    assert result["language"] == "es"
    assert result["risk_contribution"] > 0.4
    assert any(i.startswith("multilingual_financial_signals:es") for i in result["indicators"])
    assert any(i.startswith("cross_language_phishing") for i in result["indicators"])


def test_french_phishing_detected() -> None:
    result = analyze_multilingual(FRENCH_PHISH)
    assert result["language"] == "fr"
    assert any(i.startswith("multilingual_credential_signals:fr") for i in result["indicators"])
    assert "multilingual_bec_pattern:fr" in result["indicators"]


def test_english_legit_has_no_multilingual_signal() -> None:
    result = analyze_multilingual(ENGLISH_LEGIT)
    assert result["risk_contribution"] == 0.0
    assert result["indicators"] == []


def test_reported_keywords_are_actually_present() -> None:
    # Grounding: every reported keyword must literally appear in the text.
    result = analyze_multilingual(SPANISH_PHISH)
    lowered = SPANISH_PHISH.lower()
    for ind in result["indicators"]:
        if ind.startswith("multilingual_") and ":" in ind:
            sample = ind.split(":", 2)[-1]
            for kw in sample.split(","):
                assert kw in lowered, f"reported keyword not in text: {kw!r}"


def test_content_agent_flags_spanish_phishing() -> None:
    payload = {
        "headers": {"subject": "Cuenta suspendida"},
        "body": {"plain": SPANISH_PHISH},
    }
    result = content_analyze(payload)
    indicators = [str(i) for i in result["indicators"]]
    assert any(i.startswith("multilingual_") for i in indicators)
    # A multi-signal foreign BEC lure should not score as benign.
    assert result["risk_score"] >= 0.4


def test_content_agent_english_legit_not_inflated_by_multilingual() -> None:
    payload = {
        "headers": {"subject": "Weekly notes"},
        "body": {"plain": ENGLISH_LEGIT},
    }
    result = content_analyze(payload)
    indicators = [str(i) for i in result["indicators"]]
    assert not any(i.startswith("multilingual_") for i in indicators)


def test_multilingual_becomes_grounded_evidence() -> None:
    agent_result = {
        "agent_name": "content_agent",
        "risk_score": 0.7,
        "confidence": 0.8,
        "indicators": [
            "multilingual_financial_signals:es:factura,pago",
            "cross_language_phishing:es",
        ],
    }
    evidence = collect_evidence([agent_result])
    types = {e["type"] for e in evidence}
    assert "content_pattern" in types
    assert "evasion" in types
    assert any("filter-evasion" in e["claim"] for e in evidence)
