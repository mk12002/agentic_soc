"""Unit tests for IOC health policy evaluation."""

from __future__ import annotations

from soc_platform.domains.phishing.engine.agents.threat_intel_agent import agent


def test_ioc_health_critical_when_age_missing() -> None:
    level, violations = agent._evaluate_ioc_health(None, total_iocs=200)
    assert level == "critical"
    assert any(v.startswith("ioc_refresh_never_recorded") for v in violations)


def test_ioc_health_warning_for_old_but_not_critical_age() -> None:
    warning = max(60, int(agent.settings.ioc_warning_age_seconds))
    critical = max(warning, int(agent.settings.ioc_critical_age_seconds))
    if critical <= warning + 1:
        # Degenerate configuration can collapse warning/critical into one bucket.
        return

    level, violations = agent._evaluate_ioc_health(warning + 1, total_iocs=200)
    assert level == "warning"
    assert any(v.startswith("ioc_age_exceeds_warning") for v in violations)


def test_ioc_health_critical_for_very_stale_or_empty_store() -> None:
    warning = max(60, int(agent.settings.ioc_warning_age_seconds))
    critical = max(warning, int(agent.settings.ioc_critical_age_seconds))

    level, violations = agent._evaluate_ioc_health(critical + 1, total_iocs=0)
    assert level == "critical"
    assert any(v.startswith("ioc_age_exceeds_critical") for v in violations)
    assert any(v.startswith("ioc_record_count_low") for v in violations)
