"""
Feature contract for the User Behavior ML pipeline.
Ensures zero train-serve skew by enforcing that both the offline generator
and the real-time agent use the exact same feature engineering pipeline.
"""

from typing import Any
import sqlite3
import numpy as np

URGENCY_TERMS = {"urgent", "wire", "invoice", "payment", "password", "reset", "immediately", "action"}

DEPT_RISK_MAP = {
    "finance": 1.0,
    "hr": 1.0,
    "executive": 0.9,
    "sales": 0.7,
    "marketing": 0.5,
    "operations": 0.5,
    "engineering": 0.2,
    "it": 0.1,
}

def _calculate_target_domain(email_str: str) -> str:
    parts = str(email_str).split("@")
    return parts[-1].strip().lower() if len(parts) > 1 else str(email_str).strip().lower()


def extract_behavior_features(payload: dict[str, Any], cursor: sqlite3.Cursor) -> dict[str, Any]:
    """
    Given a payload and a Live DB Connection to the Corporate Social Graph,
    extract a deterministic numpy vector for XGBoost.
    """
    # 1. Parse payload
    headers = payload.get("headers") or {}
    sender = headers.get("sender", "").lower()
    subject = headers.get("subject", "").lower()
    
    # Runtime parser stores recipients under headers.to; keep top-level `to` as backward-compatible fallback.
    recipients = (
        payload.get("to")
        or headers.get("to")
        or ["unknown@company.internal"]
    )
    recipient = recipients[0].lower() if len(recipients) > 0 else "unknown@company.internal"
    
    urls = payload.get("urls") or []

    # 2. Extract string-level metadata
    sender_domain = _calculate_target_domain(sender)
    recipient_domain = _calculate_target_domain(recipient)
    is_internal_domain = 1.0 if sender_domain == recipient_domain else 0.0
    link_count = float(len(urls))
    
    urgency_score = float(sum(1 for term in URGENCY_TERMS if term in subject))

    # 3. Query the Offline Graph Database
    # Query A: Recipient context (Department)
    dept_risk_tier = 0.5 # Default medium risk if not found
    try:
        cursor.execute("SELECT department FROM employees WHERE email_address = ?", (recipient,))
        emp_row = cursor.fetchone()
        if emp_row and emp_row[0]:
            dept_risk_tier = DEPT_RISK_MAP.get(emp_row[0].lower(), 0.5)
    except Exception:
        pass  # Failsafe if running in tests without populated tables

    # Query B: Historical Interaction Edge
    contact_count = 0.0
    days_since_last_contact = 365.0  # Default to "Never" essentially
    try:
        cursor.execute(
            "SELECT interaction_count, days_since_last FROM interactions WHERE recipient_email = ? AND sender_domain = ?",
            (recipient, sender_domain),
        )
        interact_row = cursor.fetchone()
        if interact_row:
            contact_count = float(interact_row[0])
            days_since_last_contact = float(interact_row[1])
    except Exception:
        pass

    # Basic business hour approximation (ideally passed in timestamp, but we'll mock based on existence of timestamp in headers)
    # The payload generally doesn't have an explicit arrival timestamp in the standard dict format yet, so we assume 1.0 (Day) unless specified.
    is_business_hours = 1.0 
    
    vector = np.array(
        [
            contact_count,
            days_since_last_contact,
            is_internal_domain,
            is_business_hours,
            urgency_score,
            link_count,
            dept_risk_tier,
        ],
        dtype=float,
    ).reshape(1, -1)

    return {
        "numeric_vector": vector,
        "feature_names": [
            "contact_count",
            "days_since_last_contact",
            "is_internal_domain",
            "is_business_hours",
            "urgency_score",
            "link_count",
            "dept_risk_tier",
        ],
        "context": {
            "recipient": recipient,
            "sender_domain": sender_domain,
            "is_internal_domain": is_internal_domain,
            # Backward-compatible alias for older inference code paths.
            "is_internal": is_internal_domain,
            "dept_risk_tier": dept_risk_tier,
        }
    }
