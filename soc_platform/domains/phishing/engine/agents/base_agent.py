"""
Shared base class for all asynchronous email analysis agents.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from typing import Any

from soc_platform.domains.phishing.engine.configs.settings import settings
from soc_platform.domains.phishing.engine.services.logging_service import get_agent_logger
from soc_platform.domains.phishing.engine.services.messaging_service import RabbitMQClient


class BaseAgent(ABC):
    """Base RabbitMQ consumer for NewEmailEvent processing."""

    def __init__(self, agent_name: str):
        self.agent_name = agent_name
        self.logger = get_agent_logger(agent_name)
        self.messaging = RabbitMQClient()
        self.queue_name = f"{agent_name}.queue"

    @abstractmethod
    def analyze(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Return standardized agent result dictionary."""

    def _handle_message(self, payload: dict[str, Any]) -> None:
        analysis_id = payload.get("analysis_id")
        self.logger.info("Processing event", analysis_id=analysis_id)
        result = self.analyze(payload)
        result["analysis_id"] = analysis_id
        # Forward Graph identity fields for the action layer
        if payload.get("internet_message_id"):
            result["internet_message_id"] = payload["internet_message_id"]
        if payload.get("user_principal_name"):
            result["user_principal_name"] = payload["user_principal_name"]
        headers = payload.get("headers") or {}
        if headers.get("sender"):
            result["sender"] = headers["sender"]
        if headers.get("subject"):
            result["subject"] = headers["subject"]
        if payload.get("local_routing_path"):
            result["local_routing_path"] = payload["local_routing_path"]
        if payload.get("gdrive_file_id"):
            result["gdrive_file_id"] = payload["gdrive_file_id"]
        self.messaging.publish_to_queue(settings.results_queue, result)
        self.logger.info(
            "Published agent result",
            analysis_id=analysis_id,
            risk_score=result.get("risk_score", 0.0),
        )

    def run(self) -> None:
        import signal

        self._is_running = True

        def _on_shutdown(sig, frame):
            self.logger.info("Graceful shutdown signal received")
            self._is_running = False
            try:
                self.messaging.shutdown()
            except Exception:
                self.logger.opt(exception=True).debug("messaging shutdown failed during graceful stop")

        signal.signal(signal.SIGTERM, _on_shutdown)
        signal.signal(signal.SIGINT, _on_shutdown)

        while self._is_running:
            try:
                self.messaging.connect()
                self.messaging.declare_new_email_fanout(self.queue_name)
                self.messaging.declare_results_queue(settings.results_queue)
                self.logger.info("Agent worker started", queue=self.queue_name)
                self.messaging.consume(self.queue_name, self._handle_message)
            except Exception as exc:
                if not self._is_running:
                    break
                self.logger.exception("Agent consumer loop failed; reconnecting", error=str(exc))
                try:
                    self.messaging.close()
                except Exception:
                    self.logger.opt(exception=True).debug("messaging close failed before reconnect")
                # Exponential backoff is handled in messaging.connect(),
                # but we add a small safety sleep here as well.
                time.sleep(2)
        self.logger.info("Agent worker stopped")
