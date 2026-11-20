"""Tool health (NFR-13): is each enabled tool configured, syncing and fresh?

One definition, read by the Integrations screen, the Dome Score's tool-health pillar and the connector report.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from soc_platform.core.models import ConnectorCheckpoint, utcnow

# expected freshness per stream kind: alert streams must be near-real-time, inventories daily
FRESHNESS_HOURS = {"alerts": 1, "incidents": 1, "detections": 1, "risk_detections": 1, "email_alerts": 1,
                   "incidents_canary": 1, "secret_audits": 4, "elevation_events": 4, "vulnerabilities": 26,
                   "findings": 26, "issues": 26}
DEFAULT_FRESHNESS_HOURS = 26
HEALTHY_STATES = ("healthy", "on_demand")      # on demand: a look-up tool with no scheduled stream


def _aware(dt: datetime | None) -> datetime | None:
    return dt.replace(tzinfo=UTC) if dt is not None and dt.tzinfo is None else dt


def connector_freshness(s: Session, registry: Any) -> list[dict[str, Any]]:
    now = utcnow()
    cps = defaultdict(list)
    for c in s.execute(select(ConnectorCheckpoint)).scalars():
        cps[c.connector].append(c)
    out = []
    for row in registry.status():
        name = row["name"]
        streams = []
        for c in cps.get(name, []):
            limit = FRESHNESS_HOURS.get(c.stream, DEFAULT_FRESHNESS_HOURS)
            age = (now - _aware(c.last_success_at)).total_seconds() / 3600 if c.last_success_at else None
            streams.append({"stream": c.stream, "last_success_at": c.last_success_at.isoformat() if c.last_success_at else None,
                            "age_hours": round(age, 2) if age is not None else None, "expected_within_hours": limit,
                            "fresh": age is not None and age <= limit, "last_error": c.last_error,
                            "ingested": c.ingested_count, "failed": c.failed_count})
        state = ("disabled" if not row["enabled"] else "misconfigured" if row.get("config_problems") else
                 "on_demand" if not streams else
                 "error" if any(x["last_error"] for x in streams) else
                 "stale" if any(not x["fresh"] for x in streams) else "healthy")
        out.append({"name": name, "tool": row.get("tool"), "category": row.get("category"), "mode": row.get("mode"),
                    "stage": row.get("stage"), "stage_label": row.get("stage_label"),
                    "enabled": row["enabled"], "state": state, "config_problems": row.get("config_problems", []),
                    "streams": streams})
    return out
