"""
Campaign Email Clustering Service.

Detects email campaigns by tracking sender domain + subject fingerprints
in a Redis sorted set with a 1-hour TTL. When 3 or more emails from the
same sender domain arrive within 10 minutes, a campaign is flagged.

Usage (standalone, without a Redis connection):
    The detector degrades gracefully — if Redis is unavailable the check
    method returns `campaign_detected=False` rather than raising an error.
"""

from __future__ import annotations

import hashlib
import time
from datetime import UTC, datetime
from typing import Any

from soc_platform.domains.phishing.engine.services.logging_service import get_service_logger

logger = get_service_logger("campaign_detector")

# Campaign detection configuration
CAMPAIGN_WINDOW_SECONDS = 600    # 10-minute sliding window
CAMPAIGN_THRESHOLD = 3           # Number of emails to trigger campaign flag
REDIS_KEY_PREFIX = "campaign:"
REDIS_TTL_SECONDS = 3600         # 1 hour TTL on sorted sets


def domain_from_sender(sender: str) -> str:
    """Extract the domain portion of a sender address (e.g. 'a@evil.com' -> 'evil.com')."""
    if "@" not in sender:
        return ""
    return sender.split("@")[-1].strip().lower()


def _subject_fingerprint(subject: str) -> str:
    """Normalize subject line to an 8-char fingerprint for fuzzy grouping."""
    # Remove common prefixes (Re:, Fwd:, etc.) and normalize whitespace
    normalized = subject.lower().strip()
    for prefix in ("re:", "fwd:", "fw:", "reply:", "tr:"):
        if normalized.startswith(prefix):
            normalized = normalized[len(prefix):].strip()
    return hashlib.md5(normalized.encode(), usedforsecurity=False).hexdigest()[:8]


class CampaignDetector:
    """Redis-backed email campaign detector."""

    def __init__(self, redis_client: Any = None):
        self._redis = redis_client
        self._available = redis_client is not None

    def _try_connect(self) -> bool:
        """Check if the Redis client is alive."""
        try:
            self._redis.ping()
            return True
        except Exception:
            return False

    def record_and_check(
        self,
        sender_domain: str,
        subject: str,
        analysis_id: str = "",
    ) -> dict[str, Any]:
        """
        Record this email in the campaign tracker and return detection result.

        Args:
            sender_domain: Normalized sender domain (e.g. 'evil.com')
            subject: Email subject line
            analysis_id: Optional analysis UUID for deduplication

        Returns:
            Dict with keys: campaign_detected (bool), count (int), window_seconds (int)
        """
        empty_result = {
            "campaign_detected": False,
            "count": 1,
            "window_seconds": CAMPAIGN_WINDOW_SECONDS,
            "sender_domain": sender_domain,
        }

        if not self._available or not sender_domain:
            return empty_result

        if not self._try_connect():
            return empty_result

        try:
            now = time.time()
            window_start = now - CAMPAIGN_WINDOW_SECONDS

            fp = _subject_fingerprint(subject)
            key = f"{REDIS_KEY_PREFIX}{sender_domain}:{fp}"

            # Add this email's timestamp to the sorted set
            member = f"{analysis_id}:{now}"
            pipe = self._redis.pipeline()
            pipe.zadd(key, {member: now})
            # Remove entries outside the sliding window
            pipe.zremrangebyscore(key, "-inf", window_start)
            # Count emails within the window
            pipe.zcard(key)
            # Reset TTL
            pipe.expire(key, REDIS_TTL_SECONDS)
            results = pipe.execute()

            count = int(results[2])
            detected = count >= CAMPAIGN_THRESHOLD

            if detected:
                logger.warning(
                    "Campaign detected",
                    sender_domain=sender_domain,
                    subject_fingerprint=fp,
                    count=count,
                    window_seconds=CAMPAIGN_WINDOW_SECONDS,
                )

            return {
                "campaign_detected": detected,
                "count": count,
                "window_seconds": CAMPAIGN_WINDOW_SECONDS,
                "sender_domain": sender_domain,
                "subject_fingerprint": fp,
            }

        except Exception as exc:
            logger.warning("Campaign detection failed, degrading gracefully", error=str(exc))
            return empty_result

    def list_active_campaigns(self) -> list[dict[str, Any]]:
        """Scan tracked sender/subject fingerprints and return groups currently at/over threshold."""
        if not self._available or not self._try_connect():
            return []

        campaigns: list[dict[str, Any]] = []
        now = time.time()
        window_start = now - CAMPAIGN_WINDOW_SECONDS

        try:
            for raw_key in self._redis.scan_iter(match=f"{REDIS_KEY_PREFIX}*"):
                key = raw_key.decode() if isinstance(raw_key, bytes) else raw_key

                self._redis.zremrangebyscore(key, "-inf", window_start)
                members = self._redis.zrange(key, 0, -1, withscores=True)
                count = len(members)
                if count < CAMPAIGN_THRESHOLD:
                    continue

                rest = key[len(REDIS_KEY_PREFIX):]
                sender_domain, _, fingerprint = rest.rpartition(":")

                analysis_ids = []
                timestamps = []
                for member, score in members:
                    member_str = member.decode() if isinstance(member, bytes) else member
                    analysis_id, _, _ = member_str.partition(":")
                    if analysis_id:
                        analysis_ids.append(analysis_id)
                    timestamps.append(score)

                campaigns.append(
                    {
                        "sender_domain": sender_domain,
                        "subject_fingerprint": fingerprint,
                        "count": count,
                        "first_seen": datetime.fromtimestamp(min(timestamps), tz=UTC).isoformat(),
                        "last_seen": datetime.fromtimestamp(max(timestamps), tz=UTC).isoformat(),
                        "analysis_ids": analysis_ids[:20],
                    }
                )
        except Exception as exc:
            logger.warning("Failed to list active campaigns, degrading gracefully", error=str(exc))
            return []

        campaigns.sort(key=lambda c: c["count"], reverse=True)
        return campaigns


# Module-level singleton — instantiated lazily with the shared Redis client
_detector: CampaignDetector | None = None


def get_campaign_detector(redis_client: Any = None) -> CampaignDetector:
    """Return (or create) the module-level campaign detector singleton."""
    global _detector
    if _detector is None:
        _detector = CampaignDetector(redis_client=redis_client)
    return _detector
