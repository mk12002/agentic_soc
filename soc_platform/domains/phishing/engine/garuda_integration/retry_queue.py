"""Garuda retry queue helpers with exponential backoff and reconciliation events."""

from __future__ import annotations

import json
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

from soc_platform.domains.phishing.engine.configs.settings import PROJECT_ROOT, settings
from soc_platform.domains.phishing.engine.services.logging_service import get_service_logger
from soc_platform.domains.phishing.engine.services.messaging_service import RabbitMQClient

logger = get_service_logger("garuda_retry")


def _event_log_path() -> Path:
    log_dir = Path(settings.log_dir)
    if not log_dir.is_absolute():
        log_dir = PROJECT_ROOT / log_dir
    log_dir.mkdir(parents=True, exist_ok=True)
    return log_dir / "garuda_retry_events.jsonl"


def _append_event(event: dict[str, Any]) -> None:
    payload = {
        "ts_utc": datetime.now(UTC).isoformat(),
        **event,
    }
    path = _event_log_path()
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload) + "\n")


def _next_backoff_seconds(attempt: int) -> int:
    base = max(5, int(settings.garuda_retry_base_seconds))
    cap = max(base, int(settings.garuda_retry_max_seconds))
    # Exponential backoff: base * 2^attempt, bounded by cap.
    return min(cap, base * (2 ** max(0, attempt)))


def _build_retry_payload(decision: dict[str, Any], error: str, attempt: int) -> dict[str, Any]:
    delay = _next_backoff_seconds(attempt)
    return {
        "analysis_id": decision.get("analysis_id"),
        "decision": decision,
        "attempt": int(attempt),
        "last_error": error,
        "next_retry_ts": int(time.time()) + delay,
        "created_ts": int(time.time()),
    }


def enqueue_garuda_retry(decision: dict[str, Any], error: str, attempt: int = 0) -> bool:
    """Queue a failed Garuda trigger for retry."""
    mq = RabbitMQClient()
    retry_queue = settings.garuda_retry_queue
    try:
        mq.connect()
        mq.publish_to_queue(retry_queue, _build_retry_payload(decision, error, attempt))
        _append_event(
            {
                "event": "queued",
                "analysis_id": decision.get("analysis_id"),
                "attempt": int(attempt),
                "error": error,
                "queue": retry_queue,
            }
        )
        return True
    except Exception as exc:
        logger.warning("Failed to enqueue Garuda retry", error=str(exc))
        _append_event(
            {
                "event": "queue_failed",
                "analysis_id": decision.get("analysis_id"),
                "attempt": int(attempt),
                "error": f"{error} | enqueue_error={exc}",
                "queue": retry_queue,
            }
        )
        return False
    finally:
        mq.close()


def _build_garuda_request_payload(decision: dict[str, Any]) -> dict[str, Any]:
    return {
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


def _post_to_garuda(decision: dict[str, Any]) -> dict[str, Any]:
    payload = _build_garuda_request_payload(decision)
    with httpx.Client(timeout=settings.garuda_timeout_seconds) as client:
        response = client.post(f"{settings.garuda_api_base_url}/investigate", json=payload)
        response.raise_for_status()
        body = response.json()
    return {
        "status": "triggered",
        "response": body,
    }


def process_garuda_retries(max_items: int = 25) -> dict[str, Any]:
    """Process queued Garuda retries with backoff and dead-letter fallback."""
    processed = 0
    succeeded = 0
    requeued = 0
    dead_lettered = 0

    mq = RabbitMQClient()
    retry_queue = settings.garuda_retry_queue
    dead_queue = settings.garuda_dead_letter_queue
    max_attempts = max(1, int(settings.garuda_retry_max_attempts))

    try:
        mq.connect()
        # Avoid queue argument mismatches: first check whether queues already
        # exist (passive declare). If not, create them with expected settings.
        # NOTE: pika closes the channel on a failed passive declare, so we
        # must reconnect before attempting the fallback active declare.
        try:
            mq.channel.queue_declare(queue=retry_queue, passive=True)
        except Exception:
            # Channel is now closed — reconnect to get a fresh channel
            mq.connect()
            mq.channel.queue_declare(
                queue=retry_queue,
                durable=True,
                arguments=mq._queue_arguments(),
            )

        try:
            mq.channel.queue_declare(queue=dead_queue, passive=True)
        except Exception:
            mq.connect()
            mq.channel.queue_declare(queue=dead_queue, durable=True)

        for _ in range(max_items):
            method, _properties, body = mq.channel.basic_get(queue=retry_queue, auto_ack=False)
            if not method:
                break

            processed += 1
            try:
                item = json.loads(body.decode("utf-8"))
                analysis_id = item.get("analysis_id")
                decision = item.get("decision") or {}
                attempt = int(item.get("attempt", 0))
                due_ts = int(item.get("next_retry_ts", 0))

                if int(time.time()) < due_ts:
                    # Not due yet: put it back with same payload and ack current delivery.
                    mq.publish_to_queue(retry_queue, item)
                    mq.channel.basic_ack(delivery_tag=method.delivery_tag)
                    requeued += 1
                    continue

                try:
                    result = _post_to_garuda(decision)
                    mq.channel.basic_ack(delivery_tag=method.delivery_tag)
                    succeeded += 1
                    _append_event(
                        {
                            "event": "retry_success",
                            "analysis_id": analysis_id,
                            "attempt": attempt,
                            "result": result,
                        }
                    )
                except Exception as exc:
                    next_attempt = attempt + 1
                    mq.channel.basic_ack(delivery_tag=method.delivery_tag)
                    if next_attempt < max_attempts:
                        mq.publish_to_queue(
                            retry_queue,
                            _build_retry_payload(decision, str(exc), next_attempt),
                        )
                        requeued += 1
                        _append_event(
                            {
                                "event": "retry_requeued",
                                "analysis_id": analysis_id,
                                "attempt": next_attempt,
                                "error": str(exc),
                            }
                        )
                    else:
                        mq.publish_to_queue(
                            dead_queue,
                            {
                                "analysis_id": analysis_id,
                                "decision": decision,
                                "attempt": next_attempt,
                                "last_error": str(exc),
                                "failed_ts": int(time.time()),
                            },
                        )
                        dead_lettered += 1
                        _append_event(
                            {
                                "event": "retry_dead_lettered",
                                "analysis_id": analysis_id,
                                "attempt": next_attempt,
                                "error": str(exc),
                                "dead_letter_queue": dead_queue,
                            }
                        )
            except Exception as exc:
                # Corrupt message, ack and move forward to avoid poison-loop.
                mq.channel.basic_ack(delivery_tag=method.delivery_tag)
                _append_event(
                    {
                        "event": "retry_corrupt_payload",
                        "error": str(exc),
                    }
                )

        return {
            "processed": processed,
            "succeeded": succeeded,
            "requeued": requeued,
            "dead_lettered": dead_lettered,
            "retry_queue": retry_queue,
            "dead_letter_queue": dead_queue,
        }
    except Exception as exc:
        logger.warning("Garuda retry processor unavailable", error=str(exc))
        return {
            "processed": processed,
            "succeeded": succeeded,
            "requeued": requeued,
            "dead_lettered": dead_lettered,
            "retry_queue": retry_queue,
            "dead_letter_queue": dead_queue,
            "error": str(exc),
        }
    finally:
        mq.close()
