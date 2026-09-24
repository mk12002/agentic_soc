"""Live external enrichment checks.

This suite is opt-in and executes only when relevant API keys + feature flags
are configured. It validates real provider calls return well-formed tuples and
do not crash the enrichment pipeline.
"""

from __future__ import annotations

import pytest

from soc_platform.domains.phishing.engine.agents.threat_intel_agent import agent as threat_intel_agent
from soc_platform.domains.phishing.engine.agents.url_agent import agent as url_agent


def _is_enabled(flag: bool, key: str | None) -> bool:
    return bool(flag and (key or "").strip())


@pytest.mark.live
def test_url_external_live_runs_when_configured() -> None:
    settings = url_agent.settings
    enabled = any(
        (
            _is_enabled(settings.enable_google_safe_browsing_lookup, settings.google_safe_browsing_api_key),
            _is_enabled(settings.enable_virustotal_url_lookup, settings.virustotal_api_key),
            bool(settings.enable_openphish_lookup),
            bool(settings.enable_urlhaus_lookup),
        )
    )
    if not enabled:
        pytest.skip("No URL external providers configured for live checks")

    score, indicators = url_agent._external_score("https://example.com")
    assert isinstance(score, float)
    assert 0.0 <= score <= 1.0
    assert isinstance(indicators, list)


@pytest.mark.live
def test_threat_intel_external_live_runs_when_configured() -> None:
    settings = threat_intel_agent.settings
    enabled = any(
        (
            _is_enabled(settings.enable_otx_lookup, settings.otx_api_key),
            _is_enabled(settings.enable_abuseipdb_lookup, settings.abuseipdb_api_key),
            bool(settings.enable_malwarebazaar_lookup),
            _is_enabled(settings.enable_virustotal_hash_lookup, settings.virustotal_api_key),
        )
    )
    if not enabled:
        pytest.skip("No threat-intel external providers configured for live checks")

    score, indicators = threat_intel_agent._external_enrichment_score(
        {
            "domains": ["example.com"],
            "ips": ["8.8.8.8"],
            "hashes": [],
        }
    )
    assert isinstance(score, float)
    assert 0.0 <= score <= 1.0
    assert isinstance(indicators, list)
