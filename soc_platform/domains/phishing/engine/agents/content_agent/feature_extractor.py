"""Feature extractor for content phishing detection models."""

from __future__ import annotations

from typing import Any

import numpy as np

from soc_platform.domains.phishing.engine.services.logging_service import get_agent_logger

logger = get_agent_logger("content_agent")

URGENCY_TERMS = ["urgent", "immediately", "action required", "asap", "suspended"]
CREDENTIAL_TERMS = ["verify", "password", "login", "confirm identity", "mfa"]
FINANCIAL_TERMS = ["invoice", "payment", "wire", "bank", "refund"]


def extract_features(data: dict[str, Any]) -> dict[str, Any]:
    """Build text and numeric vectors suitable for transformer or tabular models."""
    logger.debug("Extracting features", agent="content_agent")

    headers = data.get("headers", {}) or {}
    body = data.get("body", {}) or {}
    subject = str(headers.get("subject", "") or "")
    plain = str(body.get("plain", "") or "")
    html = str(body.get("html", "") or "")

    text = f"{subject}\n{plain}\n{html}".strip()
    lower = text.lower()
    word_count = len(lower.split())
    url_count = lower.count("http://") + lower.count("https://")
    exclamation_count = lower.count("!")

    urgency_hits = sum(1 for term in URGENCY_TERMS if term in lower)
    credential_hits = sum(1 for term in CREDENTIAL_TERMS if term in lower)
    financial_hits = sum(1 for term in FINANCIAL_TERMS if term in lower)

    numeric_vector = np.array(
        [
            word_count,
            url_count,
            exclamation_count,
            urgency_hits,
            credential_hits,
            financial_hits,
        ],
        dtype=float,
    ).reshape(1, -1)

    features = {
        "text": text,
        "numeric_vector": numeric_vector,
        "metrics": {
            "word_count": word_count,
            "url_count": url_count,
            "urgency_hits": urgency_hits,
            "credential_hits": credential_hits,
            "financial_hits": financial_hits,
        },
    }

    logger.debug("Features extracted", metric_count=len(features["metrics"]))
    return features
