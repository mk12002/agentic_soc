"""Consistency checks for agent wiring, scoring, and deployment config."""

from __future__ import annotations


from soc_platform.domains.phishing.engine.paths import REPO_ROOT

from soc_platform.domains.phishing.engine.agents import AGENT_REGISTRY
from soc_platform.domains.phishing.engine.agents.service_runner import AGENT_FUNCTIONS
from soc_platform.domains.phishing.engine.orchestrator.runner import EXPECTED_AGENTS
from soc_platform.domains.phishing.engine.orchestrator.scoring_engine.scorer import DEFAULT_WEIGHTS


def test_expected_agents_match_runtime_agent_functions() -> None:
    assert EXPECTED_AGENTS == set(AGENT_FUNCTIONS.keys())


def test_registry_covers_expected_agents() -> None:
    assert EXPECTED_AGENTS.issubset(set(AGENT_REGISTRY.keys()))


def test_default_weights_cover_expected_agents_and_sum_to_one() -> None:
    assert EXPECTED_AGENTS.issubset(set(DEFAULT_WEIGHTS.keys()))
    assert all(DEFAULT_WEIGHTS[name] > 0.0 for name in EXPECTED_AGENTS)
    assert abs(sum(DEFAULT_WEIGHTS.values()) - 1.0) < 1e-9


def test_compose_includes_user_behavior_service() -> None:
    compose = REPO_ROOT / "deploy" / "docker-compose.yml"
    text = compose.read_text(encoding="utf-8")

    assert "user_behavior_agent_service:" in text
    assert "AGENT_NAME: user_behavior_agent" in text
