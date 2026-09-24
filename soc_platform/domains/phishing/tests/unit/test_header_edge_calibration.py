"""Regression tests for header-agent edge-case calibration."""

from __future__ import annotations

from soc_platform.domains.phishing.engine.agents.header_agent.agent import analyze


def _headers_payload(headers: dict[str, object]) -> dict[str, object]:
    return {"headers": headers}


def test_authenticated_reply_to_mismatch_is_reviewable() -> None:
    result = analyze(
        _headers_payload(
            {
                "sender": "sales@legit-vendor.com",
                "from": "Sales Team <sales@legit-vendor.com>",
                "reply_to": "invoices@totally-different-company.com",
                "authentication_results": "spf=pass; dkim=pass; dmarc=pass",
                "received": [
                    "from mail.legit-vendor.com by mx.target.com",
                    "from smtp.legit-vendor.com by mail.legit-vendor.com",
                ],
            }
        )
    )

    assert result["risk_score"] >= 0.4
    assert "reply_to_domain_mismatch" in result["indicators"]


def test_authenticated_single_hop_is_reviewable() -> None:
    result = analyze(
        _headers_payload(
            {
                "sender": "friend@gmail.com",
                "from": "friend@gmail.com",
                "reply_to": "friend@gmail.com",
                "authentication_results": "spf=pass; dkim=pass; dmarc=pass",
                "received": ["from unknown-server by mx.dest.com"],
            }
        )
    )

    assert result["risk_score"] >= 0.4
    assert "authenticated_single_hop_anomaly" in result["indicators"]


def test_normal_authenticated_multi_hop_stays_low() -> None:
    result = analyze(
        _headers_payload(
            {
                "sender": "noreply@google.com",
                "from": "Google Security <noreply@google.com>",
                "reply_to": "noreply@google.com",
                "authentication_results": "spf=pass; dkim=pass; dmarc=pass",
                "received": [
                    "from mail-wr1-f54.google.com by mx.example.com",
                    "from internal-relay.google.com by mail-wr1-f54.google.com",
                    "from smtp.google.com by internal-relay.google.com",
                ],
            }
        )
    )

    assert result["risk_score"] < 0.4


def test_sparse_header_maps_to_insufficient_evidence() -> None:
    result = analyze(
        _headers_payload(
            {
                "sender": "",
                "reply_to": "",
                "authentication_results": "",
                "received": [],
            }
        )
    )

    assert result["header_verdict"] == "insufficient_evidence"
    assert result["risk_score"] <= 0.18
    evidence = result.get("evidence_summary", {})
    assert "sender_missing" in evidence.get("missing_data_indicators", [])
    assert evidence.get("malicious_evidence_indicators", []) == []
