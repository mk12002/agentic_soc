"""Tests for the platform-enhancement fixes:

- domain validation hardening (command-injection / SSRF defense before WHOIS)
- PDF report generation (reportlab)
- STIX 2.1 and ATT&CK Navigator exports
"""

from __future__ import annotations

from unittest import mock

import pytest

# ── Domain validation (security) ──────────────────────────────────────────

@pytest.mark.parametrize(
    "domain,expected",
    [
        ("example.com", True),
        ("sub.example.co.uk", True),
        ("xn--d1acufc.xn--p1ai", True),  # IDN punycode
        ("a; rm -rf /", False),          # command injection
        ("evil.com$(whoami)", False),    # command substitution
        ("a b.com", False),              # whitespace
        ("192.168.1.1", False),          # IP literal — heuristics only
        ("-bad.com", False),
        ("", False),
    ],
)
def test_is_valid_domain(domain, expected):
    from soc_platform.domains.phishing.engine.services.domain_enrichment import is_valid_domain

    assert is_valid_domain(domain) is expected


def test_enrich_domain_never_calls_whois_on_malformed_input():
    """Malformed/unsafe domains must never reach python-whois."""
    import soc_platform.domains.phishing.engine.services.domain_enrichment as de

    with mock.patch.object(de, "_domain_cache", {}), mock.patch("whois.whois") as whois_mock:
        result = de.enrich_domain("a; rm -rf /")
    whois_mock.assert_not_called()
    assert "invalid_domain_format" in result["risk_signals"]
    assert result["whois_available"] is False


# ── PDF generation ────────────────────────────────────────────────────────

def test_build_report_pdf_returns_pdf_bytes():
    pytest.importorskip("reportlab")
    from soc_platform.domains.phishing.engine.services.pdf_report import build_report_pdf

    report = {
        "analysis_id": "test-123",
        "verdict": "malicious",
        "overall_risk_score": 0.91,
        "llm_explanation": "Phishing with <script>alert(1)</script> injection.",
        "agent_results": [
            {"agent_name": "url_agent", "risk_score": 0.88, "indicators": ["malicious_url"]},
        ],
        "attack_assessment": {
            "techniques": [
                {"technique_id": "T1566", "technique_name": "Phishing",
                 "tactic_name": "Initial Access", "confidence": 0.9},
            ]
        },
        "recommended_actions": ["quarantine", "block_sender"],
    }
    pdf = build_report_pdf(report)
    assert isinstance(pdf, bytes)
    assert pdf[:4] == b"%PDF"
    # XSS payload must not appear verbatim (it is HTML-escaped in the PDF text).
    assert b"<script>" not in pdf


def test_build_report_pdf_handles_minimal_report():
    pytest.importorskip("reportlab")
    from soc_platform.domains.phishing.engine.services.pdf_report import build_report_pdf

    pdf = build_report_pdf({})
    assert pdf[:4] == b"%PDF"


# ── STIX + Navigator exports ──────────────────────────────────────────────

def test_generate_stix_bundle_shape():
    from soc_platform.domains.phishing.engine.orchestrator.stix_generator import generate_stix_bundle

    bundle = generate_stix_bundle(
        analysis_id="a1",
        agent_results=[{"agent_name": "url_agent", "risk_score": 0.9, "indicators": ["phishing_url"]}],
        verdict="malicious",
        risk_score=0.9,
    )
    assert bundle["type"] == "bundle"
    assert isinstance(bundle.get("objects"), list) and bundle["objects"]


def test_generate_navigator_layer_shape():
    from soc_platform.domains.phishing.engine.orchestrator.attack_navigator import generate_navigator_layer

    layer = generate_navigator_layer(
        agent_results=[{"agent_name": "url_agent", "risk_score": 0.9, "indicators": ["phishing"]}],
        analysis_id="a1",
        verdict="malicious",
    )
    assert "techniques" in layer
    assert layer.get("domain") == "enterprise-attack"
