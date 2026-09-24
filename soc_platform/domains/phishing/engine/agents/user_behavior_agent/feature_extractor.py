"""Feature extraction for user interaction prediction models."""

from __future__ import annotations
from soc_platform.domains.phishing.engine.paths import PHISHING_HOME

from typing import Any
import sqlite3
from pathlib import Path

from soc_platform.domains.phishing.engine.services.logging_service import get_agent_logger
from soc_platform.domains.phishing.engine.preprocessing.user_behavior_feature_contract import extract_behavior_features

logger = get_agent_logger("user_behavior_agent")

WORKSPACE_ROOT = PHISHING_HOME
_DB_PATH = WORKSPACE_ROOT / "data" / "behavior_graph.db"


def _ensure_behavior_graph_schema(conn: sqlite3.Connection) -> None:
    """Create baseline tables used by the feature contract when the DB is empty."""
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS employees (
            email_address TEXT PRIMARY KEY,
            department TEXT
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS interactions (
            recipient_email TEXT NOT NULL,
            sender_domain TEXT NOT NULL,
            interaction_count REAL NOT NULL,
            days_since_last REAL NOT NULL,
            PRIMARY KEY (recipient_email, sender_domain)
        )
        """
    )
    # Seed one neutral row so lookups have deterministic defaults in fresh setups.
    conn.execute(
        """
        INSERT OR IGNORE INTO employees (email_address, department)
        VALUES (?, ?)
        """,
        ("unknown@company.internal", "operations"),
    )
    conn.commit()

class BehaviorGraphStore:
    def __init__(self, db_path: Path = _DB_PATH):
        self.db_path = db_path
        self._conn = None
        
    def _get_cursor(self) -> sqlite3.Cursor:
        if self._conn is None:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
            _ensure_behavior_graph_schema(self._conn)
        return self._conn.cursor()
        
    def close(self):
        if self._conn:
            self._conn.close()
            self._conn = None

_STORE = BehaviorGraphStore()

def extract_features(data: dict[str, Any]) -> dict[str, Any]:
    """Bridge runtime payload to the exact deterministic contract used in offline training."""
    logger.debug("Extracting behavioral features mapping against local graph", agent="user_behavior_agent")
    
    try:
        cursor = _STORE._get_cursor()
        features = extract_behavior_features(data, cursor)
        return features
    except Exception as e:
        logger.error("Failed to extract behavior features: {}", e)
        # Fallback empty structure
        return {"numeric_vector": None, "context": {}}
