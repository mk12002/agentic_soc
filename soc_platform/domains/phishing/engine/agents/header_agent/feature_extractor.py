"""
Feature extractor for the Header Analysis Agent.

Transforms raw email header data into an 8-dimensional numeric feature
vector suitable for sklearn / XGBoost model inference.
"""

from __future__ import annotations

import math
from typing import Any

import numpy as np

from soc_platform.domains.phishing.engine.services.logging_service import get_agent_logger

logger = get_agent_logger("header_agent")


def _entropy(text: str) -> float:
    """Shannon entropy of a string."""
    if not text:
        return 0.0
    probs = [text.count(char) / len(text) for char in set(text)]
    return -sum(prob * math.log(prob, 2) for prob in probs)


def _domain_from_email(address: str) -> str:
    """Extract domain from an email address."""
    if "@" not in address:
        return ""
    return address.split("@")[-1].strip().lower()


def extract_features(data: dict[str, Any]) -> dict[str, Any]:
    """
    Extract features from raw email header data.

    Features (8-dimensional vector):
        0. spf_pass        — 1.0 if SPF passed, 0.0 otherwise
        1. dkim_pass       — 1.0 if DKIM passed, 0.0 otherwise
        2. dmarc_pass      — 1.0 if DMARC passed, 0.0 otherwise
        3. sender_domain_len — length of the sender's domain
        4. display_name_mismatch — 1.0 if display name domain ≠ sender domain
        5. hop_count       — number of Received headers (SMTP hops)
        6. reply_to_mismatch — 1.0 if Reply-To domain ≠ sender domain
        7. sender_domain_entropy — Shannon entropy of sender domain string
    """
    logger.debug("Extracting features", agent="header_agent")

    headers = data.get("headers", {}) or {}
    auth = str(headers.get("authentication_results", "") or "").lower()
    sender = str(headers.get("sender", "") or "")
    from_header = str(headers.get("from", "") or "")
    reply_to = str(headers.get("reply_to", "") or "")
    received = headers.get("received", []) or []

    # Authentication results
    spf_pass = 1.0 if "spf=pass" in auth else 0.0
    dkim_pass = 1.0 if "dkim=pass" in auth else 0.0
    dmarc_pass = 1.0 if "dmarc=pass" in auth else 0.0

    # Sender domain analysis
    sender_domain = _domain_from_email(sender) or _domain_from_email(from_header)
    sender_domain_len = float(len(sender_domain))
    sender_domain_entropy = _entropy(sender_domain)

    # Display name mismatch: extract domain from the display name portion
    display_name_mismatch = 0.0
    if "<" in from_header and "@" in from_header:
        display_part = from_header.split("<")[0].strip().lower()
        if display_part:
            # Check if display name contains a different domain
            for trusted in ["microsoft", "google", "paypal", "amazon", "apple"]:
                if trusted in display_part and trusted not in sender_domain:
                    display_name_mismatch = 1.0
                    break

    # Hop count
    hop_count = float(len(received)) if isinstance(received, list) else 1.0

    # Reply-to mismatch
    reply_to_mismatch = 0.0
    if reply_to:
        reply_domain = _domain_from_email(reply_to)
        if reply_domain and sender_domain and reply_domain != sender_domain:
            reply_to_mismatch = 1.0

    numeric_vector = np.array(
        [
            spf_pass,
            dkim_pass,
            dmarc_pass,
            sender_domain_len,
            display_name_mismatch,
            hop_count,
            reply_to_mismatch,
            sender_domain_entropy,
        ],
        dtype=float,
    ).reshape(1, -1)

    features = {
        "text": f"{sender} {from_header}",
        "numeric_vector": numeric_vector,
        "metrics": {
            "spf_pass": spf_pass,
            "dkim_pass": dkim_pass,
            "dmarc_pass": dmarc_pass,
            "hop_count": hop_count,
            "reply_to_mismatch": reply_to_mismatch,
            "display_name_mismatch": display_name_mismatch,
        },
    }

    logger.debug("Features extracted", feature_count=len(features["metrics"]))
    return features
