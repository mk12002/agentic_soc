"""
Webhook Dispatcher for the Agentic Email Security System.

Sends analysis results to external endpoints (SIEM, SOAR, Slack, Teams)
when verdicts are finalized.
"""

from __future__ import annotations
from datetime import datetime, timezone
from typing import Any, Optional
from soc_platform.domains.phishing.engine.services.logging_service import get_service_logger

logger = get_service_logger("webhook_dispatcher")


class WebhookDispatcher:
    """Dispatch analysis results to configured webhook endpoints."""

    def __init__(self):
        self._webhooks: list[dict[str, Any]] = []
        self._load_webhooks()

    def _load_webhooks(self) -> None:
        """Load webhook configurations from settings."""
        from soc_platform.domains.phishing.engine.configs.settings import settings
        # Support env-based webhook config
        webhook_urls = getattr(settings, "webhook_urls", "") or ""
        for url in webhook_urls.split(","):
            url = url.strip()
            if url:
                self._webhooks.append({
                    "url": url, "enabled": True,
                    "events": ["verdict_finalized"],
                    "format": "json",
                })

    def register_webhook(self, url: str, events: list[str] | None = None,
                         headers: dict[str, str] | None = None) -> dict[str, Any]:
        """Register a new webhook endpoint."""
        webhook = {
            "url": url,
            "enabled": True,
            "events": events or ["verdict_finalized"],
            "headers": headers or {},
            "format": "json",
            "registered_at": datetime.now(timezone.utc).isoformat(),
        }
        self._webhooks.append(webhook)
        logger.info("Webhook registered", url=url)
        return webhook

    def dispatch(self, event_type: str, payload: dict[str, Any]) -> list[dict[str, Any]]:
        """Dispatch an event to all matching webhooks."""
        results = []
        for webhook in self._webhooks:
            if not webhook.get("enabled"):
                continue
            if event_type not in webhook.get("events", []):
                continue

            result = self._send(webhook, event_type, payload)
            results.append(result)
        return results

    def _send(self, webhook: dict[str, Any], event_type: str,
              payload: dict[str, Any]) -> dict[str, Any]:
        """Send payload to a webhook endpoint."""
        url = webhook["url"]
        wrapped = {
            "event_type": event_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": "agentic-email-security",
            "data": payload,
        }

        try:
            import httpx
            headers = {"Content-Type": "application/json"}
            headers.update(webhook.get("headers", {}))

            with httpx.Client(timeout=10.0) as client:
                response = client.post(url, json=wrapped, headers=headers)

            return {
                "url": url, "status": "delivered",
                "http_status": response.status_code,
                "delivered_at": datetime.now(timezone.utc).isoformat(),
            }
        except ImportError:
            logger.debug("httpx not available, webhook skipped", url=url)
            return {"url": url, "status": "skipped", "reason": "httpx not installed"}
        except Exception as e:
            logger.warning("Webhook delivery failed", url=url, error=str(e))
            return {"url": url, "status": "failed", "error": str(e)}

    def dispatch_verdict(self, analysis_id: str, verdict: str,
                         risk_score: float, report: dict[str, Any]) -> list[dict[str, Any]]:
        """Convenience method to dispatch a verdict event."""
        payload = {
            "analysis_id": analysis_id,
            "verdict": verdict,
            "risk_score": risk_score,
            "agent_results": report.get("agent_results", []),
            "recommended_actions": report.get("recommended_actions", []),
            "llm_explanation": report.get("llm_explanation", ""),
        }
        return self.dispatch("verdict_finalized", payload)

    def list_webhooks(self) -> list[dict[str, Any]]:
        """List all registered webhooks."""
        return [
            {k: v for k, v in w.items() if k != "headers"}
            for w in self._webhooks
        ]


_dispatcher: Optional[WebhookDispatcher] = None

def get_webhook_dispatcher() -> WebhookDispatcher:
    global _dispatcher
    if _dispatcher is None:
        _dispatcher = WebhookDispatcher()
    return _dispatcher
