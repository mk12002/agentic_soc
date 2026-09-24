"""
Bridge module for Garuda Threat Hunting framework integration.
"""

from __future__ import annotations

from typing import Any

import httpx

from soc_platform.domains.phishing.engine.configs.settings import settings
from soc_platform.domains.phishing.engine.garuda_integration.retry_queue import enqueue_garuda_retry
from soc_platform.domains.phishing.engine.services.logging_service import get_service_logger

logger = get_service_logger("garuda_bridge")


def trigger_garuda_investigation(decision: dict[str, Any]) -> dict[str, Any]:
    """Trigger endpoint hunting workflow when risk threshold is exceeded."""
    payload = {
        "analysis_id": decision.get("analysis_id"),
        "verdict": decision.get("verdict"),
        "overall_risk_score": decision.get("overall_risk_score"),
        "iocs": {
            "indicators": [
                item
                for result in decision.get("agent_results", [])
                for item in result.get("indicators", [])
            ][:50]
        },
    }

    try:
        with httpx.Client(timeout=settings.garuda_timeout_seconds) as client:
            response = client.post(f"{settings.garuda_api_base_url}/investigate", json=payload)
            response.raise_for_status()
            body = response.json()
            logger.info("Garuda investigation triggered", analysis_id=payload["analysis_id"])
            return {
                "status": "triggered",
                "response": body,
            }
    except Exception as exc:
        logger.warning("Garuda integration unavailable", error=str(exc))
        queued = enqueue_garuda_retry(decision=decision, error=str(exc), attempt=0)
        return {
            "status": "queued_retry" if queued else "degraded",
            "response": {
                "message": (
                    "Garuda API unavailable; investigation queued for retry."
                    if queued
                    else "Garuda API unavailable; failed to queue retry."
                ),
                "error": str(exc),
            },
        }
