"""Tests for Unicode homoglyph / zero-width deception detection and its
integration into the URL and header agents."""

from __future__ import annotations

from soc_platform.domains.phishing.engine.agents.header_agent.agent import analyze as header_analyze
from soc_platform.domains.phishing.engine.agents.url_agent.agent import _unicode_deception_indicators
from soc_platform.domains.phishing.engine.agents.url_agent.agent import analyze as url_analyze
from soc_platform.domains.phishing.engine.utils.unicode_normalizer import (
    analyze_text,
    find_zero_width,
    is_mixed_script,
    is_punycode,
    skeleton,
)

# Cyrillic homograph of "paypal" — 'а' (U+0430) and 'р' (U+0440) are confusables.
CYRILLIC_PAYPAL = "pаypаl.com"
# Zero-width space splitting the brand keyword.
ZW_PAYPAL = "pay\u200bpal.com"


def test_skeleton_folds_cyrillic_to_ascii() -> None:
    assert skeleton(CYRILLIC_PAYPAL) == "paypal.com"
    # Pure ASCII is untouched.
    assert skeleton("paypal.com") == "paypal.com"


def test_zero_width_detection_and_stripping() -> None:
    assert find_zero_width(ZW_PAYPAL) == ["ZERO WIDTH SPACE"]
    assert skeleton(ZW_PAYPAL) == "paypal.com"
    assert find_zero_width("paypal.com") == []


def test_mixed_script_and_punycode() -> None:
    assert is_mixed_script("pаypal") is True  # Latin + Cyrillic
    assert is_mixed_script("paypal") is False
    assert is_punycode("xn--pypal-4ve.com") is True
    assert is_punycode("paypal.com") is False


def test_analyze_text_report_is_grounded() -> None:
    report = analyze_text(CYRILLIC_PAYPAL)
    assert report["has_confusables"] is True
    assert report["skeleton"] == "paypal.com"
    assert "CYRILLIC" in report["scripts"] and "LATIN" in report["scripts"]
    assert report["mixed_script"] is True
    # ASCII input produces a clean report.
    clean = analyze_text("github.com")
    assert clean["has_confusables"] is False
    assert clean["mixed_script"] is False


def test_url_agent_detects_homoglyph_brand_attack() -> None:
    # This is the case the ASCII-only brand check misses: no literal "paypal".
    indicators = _unicode_deception_indicators(f"https://{CYRILLIC_PAYPAL}/login")
    assert any(i.startswith("homoglyph_attack:") for i in indicators)
    # Mapping is grounded: shows the real original -> skeleton transformation.
    homoglyph = next(i for i in indicators if i.startswith("homoglyph_attack:"))
    assert "->paypal.com" in homoglyph


def test_url_agent_pure_ascii_has_no_unicode_indicators() -> None:
    assert _unicode_deception_indicators("https://github.com/login") == []


def test_url_agent_homoglyph_raises_overall_risk() -> None:
    result = url_analyze({"urls": [f"https://{CYRILLIC_PAYPAL}/login"]})
    assert result["risk_score"] >= 0.45
    assert any(str(i).startswith("homoglyph_attack:") for i in result["indicators"])


def test_header_agent_flags_unicode_domain_spoofing() -> None:
    payload = {
        "headers": {
            "sender": f"billing@{CYRILLIC_PAYPAL}",
            "authentication_results": "spf=pass dkim=pass dmarc=pass",
            "received": ["hop1", "hop2"],
        },
        "body": {"plain": "Please confirm your account."},
    }
    result = header_analyze(payload)
    indicators = [str(i) for i in result["indicators"]]
    assert any(i.startswith("unicode_domain_spoofing:") for i in indicators)
    assert result["risk_score"] >= 0.8


def test_header_agent_clean_domain_not_flagged() -> None:
    payload = {
        "headers": {
            "sender": "billing@paypal.com",
            "authentication_results": "spf=pass dkim=pass dmarc=pass",
            "received": ["hop1", "hop2"],
        },
        "body": {"plain": "Receipt attached."},
    }
    result = header_analyze(payload)
    indicators = [str(i) for i in result["indicators"]]
    assert not any(i.startswith("unicode_domain_spoofing:") for i in indicators)
