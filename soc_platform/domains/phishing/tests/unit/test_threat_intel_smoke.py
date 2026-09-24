"""Smoke tests for threat-intel scoring behavior with live IOC data."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from soc_platform.domains.phishing.engine.agents.threat_intel_agent.agent import analyze, get_ioc_store_status


from soc_platform.domains.phishing.engine.configs import settings

def _find_ioc_db() -> Path:
    return Path(settings.ioc_db_path)


def _fetch_known_bad(ioc_type: str, limit: int = 2) -> list[str]:
    db_path = _find_ioc_db()
    with sqlite3.connect(str(db_path)) as conn:
        rows = conn.execute(
            "SELECT indicator FROM iocs WHERE ioc_type = ? ORDER BY updated_ts DESC LIMIT ?",
            (ioc_type, limit),
        ).fetchall()
    return [row[0] for row in rows if row and row[0]]


def _has_ioc_match(result: dict[str, object]) -> bool:
    indicators = result.get("indicators") or []
    return any(str(item).startswith("ioc_match:") for item in indicators)


@pytest.mark.smoke
def test_threat_intel_smoke_ordering_and_signal() -> None:
    # Warm and refresh the local IOC DB from feeds.
    analyze({"iocs": {}})

    bad_domains = _fetch_known_bad("domain", 2)
    bad_ips = _fetch_known_bad("ip", 2)
    if not bad_domains and not bad_ips:
        pytest.skip("No IOC records available for threat-intel smoke test")

    benign_payload = {
        "iocs": {
            "domains": ["example.com", "python.org", "w3.org"],
            "ips": ["35.190.247.0", "104.16.124.0", "13.107.42.14"],
            "hashes": [],
        }
    }

    malicious_payload = {
        "iocs": {
            "domains": bad_domains,
            "ips": bad_ips,
            "hashes": [],
        }
    }

    mixed_domains = ["cdn.stripe.com", "unpkg.com", "raw.githubusercontent.com"]
    mixed_ips = ["52.0.0.1", "54.0.0.1"]
    if bad_domains:
        mixed_domains.append(bad_domains[0])
    elif bad_ips:
        mixed_ips.append(bad_ips[0])

    mixed_payload = {
        "iocs": {
            "domains": mixed_domains,
            "ips": mixed_ips,
            "hashes": [],
        }
    }

    benign_result = analyze(benign_payload)
    malicious_result = analyze(malicious_payload)
    mixed_result = analyze(mixed_payload)
    ioc_status = get_ioc_store_status()

    benign_risk = float(benign_result["risk_score"])
    malicious_risk = float(malicious_result["risk_score"])
    mixed_risk = float(mixed_result["risk_score"])

    assert malicious_risk >= mixed_risk >= benign_risk
    assert _has_ioc_match(malicious_result)
    assert not _has_ioc_match(benign_result)
    assert ioc_status["health_level"] in {"healthy", "warning", "critical"}
    assert isinstance(ioc_status["policy_violations"], list)
