"""Outbound notifications: tell people about important findings where they already are (Teams, Slack, any webhook).

What is sent: every open finding (``Insight``) at or above ``SOC_NOTIFY_MIN_SEVERITY`` (default ``high``). That covers
the correlation rules *and* the operational alerts, which are findings too: a dead-lettered job, break-glass use, a
failing platform self-check, the LLM budget.

Rules:

* **Destinations come from configuration only** (``SOC_NOTIFY_WEBHOOKS``), never from data, and must be ``https://``
  (``http://`` only to localhost, for testing) - no request is ever made to an address taken from an e-mail or alert.
* **Each finding is sent once per channel.** An escalation to a higher severity is sent again; a finding that stays
  the same is not repeated. Delivery is recorded in ``notifications``.
* **Failures are retried** by the ``notify`` job (every minute by default) up to ``MAX_ATTEMPTS`` times, then left
  recorded as failed. A notification never blocks or fails the job that raised the finding.

Configuration: ``SOC_NOTIFY_WEBHOOKS=teams|https://…,slack|https://hooks.slack.com/…,json|https://siem.example/hook``
(or ``SOC_NOTIFY_WEBHOOKS_FILE``, a mounted vault secret - the URLs carry their own credentials) and optionally ``SOC_PUBLIC_URL`` (the console address, so a message links to the finding).
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from urllib.parse import urlparse

from sqlalchemy import Integer, String, Text, UniqueConstraint, select
from sqlalchemy.orm import Mapped, Session, mapped_column

from soc_platform.core.db import Base, UTCDateTime
from soc_platform.core.models import new_id, utcnow

log = logging.getLogger(__name__)

SEVERITY_RANK = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
MAX_ATTEMPTS = 5
KINDS = {"teams", "slack", "json"}


class Notification(Base):
    """One finding delivered (or attempted) to one channel, at one severity."""

    __tablename__ = "notifications"
    __table_args__ = (UniqueConstraint("dedupe_key", "severity", "channel", name="uq_notification"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    insight_id: Mapped[str] = mapped_column(String(32), index=True)
    dedupe_key: Mapped[str] = mapped_column(String(256), index=True)
    severity: Mapped[str] = mapped_column(String(16))
    channel: Mapped[str] = mapped_column(String(64))          # "<kind>:<host>" - never the full URL (it holds a secret)
    status: Mapped[str] = mapped_column(String(16), default="pending", index=True)   # pending | sent | failed
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    sent_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)



@dataclass(frozen=True)
class Channel:
    kind: str
    url: str

    @property
    def label(self) -> str:
        return f"{self.kind}:{urlparse(self.url).hostname or '?'}"


def channels() -> list[Channel]:
    """Configured webhooks. Invalid entries are skipped with a warning (never a crash at start-up)."""
    from soc_platform.config import secret

    out = []
    for raw in (secret("SOC_NOTIFY_WEBHOOKS") or "").split(","):
        raw = raw.strip()
        if not raw:
            continue
        kind, sep, url = raw.partition("|")
        kind, url = kind.strip().lower(), url.strip()
        u = urlparse(url)
        local = u.hostname in {"localhost", "127.0.0.1", "::1"}
        if not sep or kind not in KINDS or not u.hostname or not (u.scheme == "https" or (u.scheme == "http" and local)):
            log.warning("notify: ignoring invalid webhook entry for %r (expected kind|https://host/...)", kind or raw[:20])
            continue
        out.append(Channel(kind, url))
    return out


def min_severity() -> int:
    return SEVERITY_RANK.get((os.environ.get("SOC_NOTIFY_MIN_SEVERITY") or "high").lower(), 3)


def _link() -> str | None:
    base = (os.environ.get("SOC_PUBLIC_URL") or "").rstrip("/")
    return f"{base}/#/intelligence" if base else None


def payload(kind: str, insight: Any) -> dict[str, Any]:
    steps = [str(x) for x in (insight.next_steps or [])][:3]
    link = _link()
    head = f"[{insight.severity.upper()}] {insight.title}"
    if kind == "json":
        return {"source": "agentic-soc", "id": insight.id, "rule": insight.rule, "severity": insight.severity,
                "title": insight.title, "status": insight.status, "domains": insight.domains,
                "next_steps": steps, "first_seen": insight.first_seen.isoformat() if insight.first_seen else None,
                "link": link}
    lines = [head] + [f"- {s}" for s in steps] + ([f"Open: {link}"] if link else [])
    return {"text": "\n".join(lines)}                       # Teams incoming webhook and Slack both accept {"text": ...}


def _post(url: str, body: dict[str, Any]) -> None:
    import httpx

    r = httpx.post(url, json=body, timeout=httpx.Timeout(10.0, connect=5.0))
    if r.status_code >= 300:
        raise RuntimeError(f"webhook answered {r.status_code}")


def deliver(s: Session, *, post: Any = None) -> dict[str, int]:
    """Send what is due: new findings at or above the threshold, plus retries of earlier failures."""
    from soc_platform.intelligence.models import Insight

    post = post or _post
    chans = channels()
    counts = {"sent": 0, "failed": 0, "skipped_no_channels": 0 if chans else 1}
    if not chans:
        return counts
    floor = min_severity()
    open_insights = [i for i in s.execute(select(Insight).where(Insight.status == "new")).scalars()
                     if SEVERITY_RANK.get(i.severity, 0) >= floor]
    for insight in sorted(open_insights, key=lambda i: (-SEVERITY_RANK.get(i.severity, 0), i.first_seen or utcnow())):
        for ch in chans:
            row = s.execute(select(Notification).where(Notification.dedupe_key == insight.dedupe_key,
                                                       Notification.severity == insight.severity,
                                                       Notification.channel == ch.label)).scalars().first()
            if row is not None and (row.status == "sent" or row.attempts >= MAX_ATTEMPTS):
                continue
            if row is None:
                row = Notification(insight_id=insight.id, dedupe_key=insight.dedupe_key, severity=insight.severity,
                                   channel=ch.label)
                s.add(row)
            row.attempts = (row.attempts or 0) + 1
            try:
                post(ch.url, payload(ch.kind, insight))
                row.status, row.sent_at, row.last_error = "sent", utcnow(), None
                counts["sent"] += 1
            except Exception as exc:  # noqa: BLE001 - recorded on the row and retried next run
                row.status, row.last_error = "failed", f"{type(exc).__name__}: {exc}"[:500]
                counts["failed"] += 1
                log.warning("notify: delivery to %s failed (attempt %d): %s", ch.label, row.attempts, row.last_error)
            s.flush()
    return counts


def recent(s: Session, limit: int = 20) -> list[dict[str, Any]]:
    rows = s.execute(select(Notification).order_by(Notification.created_at.desc()).limit(limit)).scalars()
    return [{"channel": r.channel, "severity": r.severity, "status": r.status, "attempts": r.attempts,
             "error": r.last_error, "at": (r.sent_at or r.created_at).isoformat(), "insight_id": r.insight_id}
            for r in rows]

