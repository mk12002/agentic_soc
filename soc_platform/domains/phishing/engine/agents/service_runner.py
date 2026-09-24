"""
Container entrypoint for agent workers.
"""

from __future__ import annotations

import os
from typing import Any, Callable

from soc_platform.domains.phishing.engine.agents.base_agent import BaseAgent
from soc_platform.domains.phishing.engine.agents.header_agent import analyze as header_analyze
from soc_platform.domains.phishing.engine.agents.content_agent import analyze as content_analyze
from soc_platform.domains.phishing.engine.agents.url_agent import analyze as url_analyze
from soc_platform.domains.phishing.engine.agents.attachment_agent import analyze as attachment_analyze
from soc_platform.domains.phishing.engine.agents.sandbox_agent import analyze as sandbox_analyze
from soc_platform.domains.phishing.engine.agents.threat_intel_agent import analyze as threat_intel_analyze
from soc_platform.domains.phishing.engine.agents.user_behavior_agent.agent import analyze as user_behavior_analyze
from soc_platform.domains.phishing.engine.configs.settings import settings
from soc_platform.domains.phishing.engine.services.logging_service import setup_logging

AGENT_FUNCTIONS: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
    "header_agent": header_analyze,
    "content_agent": content_analyze,
    "url_agent": url_analyze,
    "attachment_agent": attachment_analyze,
    "sandbox_agent": sandbox_analyze,
    "threat_intel_agent": threat_intel_analyze,
    "user_behavior_agent": user_behavior_analyze,
}

DISABLED_AGENTS = set()


class FunctionalAgent(BaseAgent):
    """Wrap plain analyze(payload) callables into BaseAgent consumers."""

    def __init__(self, agent_name: str, fn: Callable[[dict[str, Any]], dict[str, Any]]):
        super().__init__(agent_name)
        self.fn = fn

    def analyze(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self.fn(payload)


def run() -> None:
    setup_logging(settings.log_dir, settings.app_log_level, settings.log_format)
    agent_name = os.getenv("AGENT_NAME", "").strip()
    if agent_name in DISABLED_AGENTS:
        raise ValueError(
            f"AGENT_NAME={agent_name} is explicitly disabled in the current deployment scope."
        )
    if agent_name not in AGENT_FUNCTIONS:
        raise ValueError(f"Unsupported AGENT_NAME={agent_name}. Expected one of: {sorted(AGENT_FUNCTIONS)}")

    # Pre-warm ML models before connecting to RabbitMQ to prevent heartbeat timeouts
    import importlib
    import logging
    logger = logging.getLogger(agent_name)
    try:
        model_loader_mod = importlib.import_module(f"soc_platform.domains.phishing.engine.agents.{agent_name}.model_loader")
        if hasattr(model_loader_mod, "load_model"):
            logger.info("Pre-warming ML models before connecting to RabbitMQ...")
            model_loader_mod.load_model()
            
            # Execute a full dummy payload to warm up inference paths (e.g. CUDA/C-libs)
            logger.info("Running dummy inference payload for complete warmup...")
            dummy_payload = {
                "analysis_id": "warmup-0000",
                "headers": {"sender": "warmup@example.com", "subject": "warmup"},
                "body": {"plain": "Click here to verify your account urgently.", "html": ""},
                "urls": ["http://example.com/login"],
                "attachments": [],
                "iocs": {"domains": [], "ips": [], "hashes": []}
            }
            try:
                AGENT_FUNCTIONS[agent_name](dummy_payload)
                logger.info("ML inference warmup complete.")
            except Exception as e:
                logger.warning(f"Dummy inference warmup failed (non-fatal): {e}")
    except (ModuleNotFoundError, ImportError):
        pass

    agent = FunctionalAgent(agent_name=agent_name, fn=AGENT_FUNCTIONS[agent_name])
    agent.run()


if __name__ == "__main__":
    run()
