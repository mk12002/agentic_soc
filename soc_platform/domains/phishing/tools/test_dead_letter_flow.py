#!/usr/bin/env python3
"""Operational DLQ test for RabbitMQ dead-letter routing."""

from __future__ import annotations

import json
import logging
import sys
import time
from datetime import UTC, datetime

from soc_platform.domains.phishing.engine.paths import PHISHING_HOME

REPO_ROOT = PHISHING_HOME
WORKSPACE_ROOT = REPO_ROOT.parent
if str(WORKSPACE_ROOT) not in sys.path:
    pass  # (package import; no sys.path hack needed)
from soc_platform.domains.phishing.engine.configs.settings import settings
from soc_platform.domains.phishing.engine.services.messaging_service import RabbitMQClient

ANALYSIS_ROOT = REPO_ROOT / "analysis_reports"


def main() -> int:
    ts = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    out_dir = ANALYSIS_ROOT / f"dlq_test_{ts}"
    out_dir.mkdir(parents=True, exist_ok=True)

    queue_name = f"dlq.test.queue.{ts}"
    dead_queue = settings.rabbitmq_dead_letter_queue

    report = {
        "timestamp_utc": datetime.now(UTC).isoformat(),
        "test_queue": queue_name,
        "dead_letter_queue": dead_queue,
        "published": False,
        "nacked": False,
        "dlq_received": False,
        "delivery_payload": None,
        "errors": [],
    }

    client = RabbitMQClient()
    try:
        client.channel.queue_declare(queue=queue_name, durable=False, arguments=client._queue_arguments())
        payload = {"event": "dlq_test", "timestamp": report["timestamp_utc"]}
        client.channel.basic_publish(
            exchange="",
            routing_key=queue_name,
            body=json.dumps(payload).encode("utf-8"),
        )
        report["published"] = True

        method, _properties, _body = client.channel.basic_get(queue=queue_name, auto_ack=False)
        if method is None:
            report["errors"].append("No message fetched from test queue")
        else:
            client.channel.basic_nack(delivery_tag=method.delivery_tag, requeue=False)
            report["nacked"] = True

            for _ in range(10):
                d_method, _d_props, d_body = client.channel.basic_get(queue=dead_queue, auto_ack=False)
                if d_method is not None:
                    report["dlq_received"] = True
                    report["delivery_payload"] = d_body.decode("utf-8", errors="replace")
                    client.channel.basic_ack(delivery_tag=d_method.delivery_tag)
                    break
                time.sleep(0.3)

        try:
            client.channel.queue_delete(queue=queue_name)
        except Exception:
            logging.getLogger(__name__).debug("test queue could not be deleted", exc_info=True)

    except Exception as exc:
        report["errors"].append(str(exc))
    finally:
        client.close()

    report["overall_passed"] = report["published"] and report["nacked"] and report["dlq_received"]

    json_path = out_dir / "dlq_test.json"
    md_path = out_dir / "dlq_test.md"
    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    lines = [
        "# DLQ Operational Test",
        "",
        f"- Test Queue: `{queue_name}`",
        f"- Dead-Letter Queue: `{dead_queue}`",
        f"- Published: `{report['published']}`",
        f"- Nacked: `{report['nacked']}`",
        f"- DLQ Received: `{report['dlq_received']}`",
        f"- Overall Passed: `{report['overall_passed']}`",
    ]
    if report["errors"]:
        lines.append(f"- Errors: `{'; '.join(report['errors'])}`")

    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"DLQ test report written to: {out_dir}")

    return 0 if report["overall_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
