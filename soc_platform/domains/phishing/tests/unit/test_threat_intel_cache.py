"""Tests for threat-intel external lookup cache behavior."""

from __future__ import annotations

import time

from soc_platform.domains.phishing.engine.agents.threat_intel_agent.agent import IOCStore


def test_external_cache_roundtrip(tmp_path) -> None:
    db_path = tmp_path / "ioc_cache_test.db"
    store = IOCStore(str(db_path))

    store.set_external_cache("otx", "domain:example.com", 0.73, ["otx_hit:domain:example.com"])
    cached = store.get_external_cache("otx", "domain:example.com", max_age_seconds=60)

    assert cached is not None
    score, indicators = cached
    assert score == 0.73
    assert "otx_hit:domain:example.com" in indicators


def test_external_cache_honors_age_limit(tmp_path) -> None:
    db_path = tmp_path / "ioc_cache_test.db"
    store = IOCStore(str(db_path))

    store.set_external_cache("abuseipdb", "1.2.3.4", 0.5, ["abuseipdb_high_confidence:1.2.3.4:50"])
    time.sleep(1.05)

    expired = store.get_external_cache("abuseipdb", "1.2.3.4", max_age_seconds=0)
    assert expired is None

    fallback = store.get_external_cache("abuseipdb", "1.2.3.4", max_age_seconds=None)
    assert fallback is not None
