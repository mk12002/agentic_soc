"""Realistic smoke checks for user behavior click-risk scoring."""

from __future__ import annotations

import datetime
import types

import pytest

from soc_platform.domains.phishing.engine.agents.user_behavior_agent.agent import analyze


@pytest.mark.smoke
def test_user_behavior_smoke_risk_ordering() -> None:
    benign_payload = {
        "headers": {
            "sender": "it@company.com",
            "subject": "Weekly team sync notes",
        },
        "body": {"plain": "Please review project notes."},
        "urls": ["https://intranet.company.com/wiki"],
        "attachments": [],
        "iocs": {"domains": ["company.com"], "ips": [], "hashes": []},
    }

    phishy_payload = {
        "headers": {
            "sender": "security-alerts@company-secure-verify.com",
            "subject": "Urgent action required: verify payroll immediately",
        },
        "body": {"plain": "Verify your account now to avoid suspension."},
        "urls": ["https://company-secure-verify.com/login"],
        "attachments": [],
        "iocs": {"domains": ["company-secure-verify.com"], "ips": [], "hashes": []},
    }

    benign_result = analyze(benign_payload)
    phishy_result = analyze(phishy_payload)

    benign_risk = float(benign_result["risk_score"])
    phishy_risk = float(phishy_result["risk_score"])

    assert 0.0 <= benign_risk <= 1.0
    assert 0.0 <= phishy_risk <= 1.0
    assert phishy_risk > benign_risk
    assert any("urgency" in str(i) or "unfamiliar" in str(i) for i in phishy_result["indicators"])


@pytest.mark.smoke
def test_user_behavior_high_risk_tld_does_not_crash_and_sets_indicator(monkeypatch: pytest.MonkeyPatch) -> None:
    class _FakeWhoisModule:
        @staticmethod
        def whois(_domain: str):
            return types.SimpleNamespace(
                creation_date=datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=7)
            )

    import sys

    monkeypatch.setitem(sys.modules, "whois", _FakeWhoisModule)

    payload = {
        "headers": {
            "sender": "risk@promo-verify.xyz",
            "subject": "Urgent action required",
        },
        "body": {"plain": "Please verify immediately."},
        "urls": ["https://promo-verify.xyz/login"],
        "attachments": [],
        "iocs": {"domains": ["promo-verify.xyz"], "ips": [], "hashes": []},
    }

    result = analyze(payload)
    indicators = [str(item) for item in result["indicators"]]

    assert any(item.startswith("high_risk_tld:") for item in indicators)
    assert any(item.startswith("new_domain_age:") for item in indicators)
