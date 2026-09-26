"""Tests for orchestrator partial finalization behavior."""

from __future__ import annotations

from datetime import UTC, datetime

from soc_platform.domains.phishing.engine.configs.settings import settings
from soc_platform.domains.phishing.engine.orchestrator.runner import EXPECTED_AGENTS, OrchestratorWorker


def _mk_result(agent_name: str) -> dict[str, object]:
    return {"agent_name": agent_name, "risk_score": 0.1}


def test_should_finalize_when_complete() -> None:
    worker = OrchestratorWorker.__new__(OrchestratorWorker)
    results = [_mk_result(name) for name in EXPECTED_AGENTS]

    should_finalize, reason = worker._should_finalize(
        results,
        datetime.now(UTC).timestamp(),
    )

    assert should_finalize is True
    assert reason == "complete"


def test_should_finalize_partial_on_timeout() -> None:
    worker = OrchestratorWorker.__new__(OrchestratorWorker)
    subset = sorted(EXPECTED_AGENTS)[: settings.orchestrator_min_agents_for_decision]
    results = [_mk_result(name) for name in subset]
    first_seen = datetime.now(UTC).timestamp() - (
        settings.orchestrator_partial_timeout_seconds + 1
    )

    should_finalize, reason = worker._should_finalize(results, first_seen)

    assert should_finalize is True
    assert reason == "partial_timeout"


def test_should_wait_when_not_enough_agents() -> None:
    worker = OrchestratorWorker.__new__(OrchestratorWorker)
    results = [_mk_result("header_agent")]
    first_seen = datetime.now(UTC).timestamp() - (
        settings.orchestrator_partial_timeout_seconds + 30
    )

    should_finalize, reason = worker._should_finalize(results, first_seen)

    assert should_finalize is False
    assert reason == "waiting"
