"""
Sender Reputation Engine for the Agentic Email Security System.

Builds and maintains a sender reputation database from historical analysis
verdicts, analyst feedback, and sending patterns.
"""

from __future__ import annotations
from datetime import datetime, timezone
from typing import Any, Optional
from soc_platform.domains.phishing.engine.services.logging_service import get_service_logger

logger = get_service_logger("sender_reputation")


class SenderReputationEngine:
    """Track sender reputation from historical analysis data."""

    def __init__(self, database_url: str | None = None):
        self._database_url = database_url
        self._cache: dict[str, dict[str, Any]] = {}

    def _connect(self):
        from soc_platform.domains.phishing.engine.configs.settings import settings
        from soc_platform.domains.phishing.engine.services.database import connect_database
        return connect_database(self._database_url or settings.database_url, logger=logger)

    def ensure_table(self) -> None:
        """Create sender_reputation table if it doesn't exist."""
        try:
            with self._connect() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        CREATE TABLE IF NOT EXISTS sender_reputation (
                            sender_email TEXT PRIMARY KEY,
                            sender_domain TEXT NOT NULL,
                            total_emails INTEGER DEFAULT 0,
                            safe_count INTEGER DEFAULT 0,
                            suspicious_count INTEGER DEFAULT 0,
                            malicious_count INTEGER DEFAULT 0,
                            false_positive_count INTEGER DEFAULT 0,
                            true_positive_count INTEGER DEFAULT 0,
                            reputation_score REAL DEFAULT 0.5,
                            first_seen TIMESTAMPTZ DEFAULT NOW(),
                            last_seen TIMESTAMPTZ DEFAULT NOW(),
                            last_verdict TEXT DEFAULT '',
                            is_allowlisted BOOLEAN DEFAULT FALSE,
                            is_blocklisted BOOLEAN DEFAULT FALSE
                        )
                    """)
                conn.commit()
            logger.info("sender_reputation table ensured")
        except Exception as e:
            logger.warning("Failed to ensure sender_reputation table", error=str(e))

    def update_reputation(self, sender_email: str, verdict: str, risk_score: float) -> dict[str, Any]:
        """Update sender reputation after an analysis."""
        sender_email = sender_email.lower().strip()
        sender_domain = sender_email.split("@")[-1] if "@" in sender_email else sender_email
        now = datetime.now(timezone.utc)

        try:
            with self._connect() as conn:
                with conn.cursor() as cur:
                    # Upsert sender record
                    safe_inc = 1 if verdict in ("safe", "likely_safe") else 0
                    susp_inc = 1 if verdict == "suspicious" else 0
                    mal_inc = 1 if verdict in ("malicious", "high_risk") else 0

                    cur.execute("""
                        INSERT INTO sender_reputation
                            (sender_email, sender_domain, total_emails, safe_count,
                             suspicious_count, malicious_count, last_seen, last_verdict)
                        VALUES (%s, %s, 1, %s, %s, %s, %s, %s)
                        ON CONFLICT (sender_email) DO UPDATE SET
                            total_emails = sender_reputation.total_emails + 1,
                            safe_count = sender_reputation.safe_count + %s,
                            suspicious_count = sender_reputation.suspicious_count + %s,
                            malicious_count = sender_reputation.malicious_count + %s,
                            last_seen = %s,
                            last_verdict = %s
                    """, (sender_email, sender_domain, safe_inc, susp_inc, mal_inc, now, verdict,
                          safe_inc, susp_inc, mal_inc, now, verdict))

                    # Recalculate reputation score
                    cur.execute("""
                        UPDATE sender_reputation SET reputation_score = CASE
                            WHEN total_emails = 0 THEN 0.5
                            ELSE GREATEST(0.0, LEAST(1.0,
                                (safe_count::REAL * 1.0 + suspicious_count::REAL * 0.3 -
                                 malicious_count::REAL * 2.0 + false_positive_count::REAL * 0.5) /
                                GREATEST(1, total_emails)
                            ))
                        END
                        WHERE sender_email = %s
                    """, (sender_email,))
                conn.commit()

            return self.get_reputation(sender_email)
        except Exception as e:
            logger.warning("Failed to update sender reputation", error=str(e), sender=sender_email[:30])
            return {"sender_email": sender_email, "reputation_score": 0.5, "error": str(e)}

    def get_reputation(self, sender_email: str) -> dict[str, Any]:
        """Get reputation for a sender email address."""
        sender_email = sender_email.lower().strip()
        try:
            with self._connect() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        SELECT sender_email, sender_domain, total_emails, safe_count,
                               suspicious_count, malicious_count, false_positive_count,
                               true_positive_count, reputation_score, first_seen, last_seen,
                               last_verdict, is_allowlisted, is_blocklisted
                        FROM sender_reputation WHERE sender_email = %s
                    """, (sender_email,))
                    row = cur.fetchone()
                    if not row:
                        return {
                            "sender_email": sender_email, "status": "unknown",
                            "reputation_score": 0.5, "total_emails": 0,
                            "risk_level": "neutral",
                        }
                    return {
                        "sender_email": row[0], "sender_domain": row[1],
                        "total_emails": row[2], "safe_count": row[3],
                        "suspicious_count": row[4], "malicious_count": row[5],
                        "false_positive_count": row[6], "true_positive_count": row[7],
                        "reputation_score": round(row[8], 4),
                        "first_seen": row[9].isoformat() if row[9] else None,
                        "last_seen": row[10].isoformat() if row[10] else None,
                        "last_verdict": row[11],
                        "is_allowlisted": row[12], "is_blocklisted": row[13],
                        "risk_level": _score_to_risk(row[8]),
                        "status": "known",
                    }
        except Exception as e:
            logger.warning("Failed to get sender reputation", error=str(e))
            return {"sender_email": sender_email, "reputation_score": 0.5, "error": str(e)}

    def record_feedback(self, sender_email: str, is_false_positive: bool) -> None:
        """Record analyst feedback for reputation adjustment."""
        sender_email = sender_email.lower().strip()
        try:
            with self._connect() as conn:
                with conn.cursor() as cur:
                    col = "false_positive_count" if is_false_positive else "true_positive_count"
                    cur.execute(f"""
                        UPDATE sender_reputation SET {col} = {col} + 1
                        WHERE sender_email = %s
                    """, (sender_email,))
                conn.commit()
        except Exception as e:
            logger.warning("Failed to record feedback", error=str(e))


def _score_to_risk(score: float) -> str:
    if score >= 0.7:
        return "trusted"
    if score >= 0.4:
        return "neutral"
    if score >= 0.1:
        return "suspicious"
    return "malicious"


_engine: Optional[SenderReputationEngine] = None

def get_sender_reputation_engine() -> SenderReputationEngine:
    global _engine
    if _engine is None:
        _engine = SenderReputationEngine()
    return _engine
