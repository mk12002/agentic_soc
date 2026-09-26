"""SLO-oriented tests for partial finalization timing behavior."""

from __future__ import annotations

from datetime import UTC, datetime

from soc_platform.domains.phishing.engine.configs.settings import settings
from soc_platform.domains.phishing.engine.orchestrator.runner import EXPECTED_AGENTS, OrchestratorWorker


def _mk_results(n: int) -> list[dict[str, object]]:
    names = sorted(EXPECTED_AGENTS)[:n]
    return [{"agent_name": name, "risk_score": 0.2} for name in names]


def test_should_not_finalize_before_timeout_with_min_agents() -> None:
    worker = OrchestratorWorker.__new__(OrchestratorWorker)
    n = int(settings.orchestrator_min_agents_for_decision)
    elapsed = max(0.0, float(settings.orchestrator_partial_timeout_seconds) - 5.0)
    first_seen = datetime.now(UTC).timestamp() - elapsed

    should_finalize, reason = worker._should_finalize(_mk_results(n), first_seen)
    assert should_finalize is False
    assert reason == "waiting"


def test_should_finalize_at_timeout_with_min_agents() -> None:
    worker = OrchestratorWorker.__new__(OrchestratorWorker)
    n = int(settings.orchestrator_min_agents_for_decision)
    elapsed = float(settings.orchestrator_partial_timeout_seconds) + 0.1
    first_seen = datetime.now(UTC).timestamp() - elapsed

    should_finalize, reason = worker._should_finalize(_mk_results(n), first_seen)
    assert should_finalize is True
    assert reason == "partial_timeout"
