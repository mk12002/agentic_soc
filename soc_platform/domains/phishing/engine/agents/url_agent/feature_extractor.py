"""Feature extraction for URL reputation models."""

from __future__ import annotations

from typing import Any

import numpy as np
from soc_platform.domains.phishing.engine.preprocessing.feature_pipeline import (
    URL_FEATURE_COLUMNS,
    extract_url_lexical_features,
    normalize_url,
)

from soc_platform.domains.phishing.engine.services.logging_service import get_agent_logger

logger = get_agent_logger("url_agent")


def extract_features(data: dict[str, Any]) -> dict[str, Any]:
    """Build aggregated URL lexical features for XGBoost/sklearn-style models."""
    logger.debug("Extracting features", agent="url_agent")

    urls = [str(item) for item in (data.get("urls", []) or []) if str(item).strip()][:20]
    if not urls:
        numeric_vector = np.zeros((1, len(URL_FEATURE_COLUMNS)), dtype=float)
        return {"text": "", "numeric_vector": numeric_vector, "metrics": {"url_count": 0}}

    rows: list[dict[str, float]] = []
    normalized_urls: list[str] = []

    for url in urls:
        normalized = normalize_url(url)
        if not normalized:
            continue
        normalized_urls.append(normalized)
        rows.append(extract_url_lexical_features(normalized))

    if not rows:
        numeric_vector = np.zeros((1, len(URL_FEATURE_COLUMNS)), dtype=float)
        return {"text": "", "numeric_vector": numeric_vector, "metrics": {"url_count": 0}}

    count = float(len(rows))
    feature_map = {
        key: float(sum(row[key] for row in rows) / count)
        for key in URL_FEATURE_COLUMNS
    }
    numeric_vector = np.array([feature_map[key] for key in URL_FEATURE_COLUMNS], dtype=float).reshape(1, -1)

    return {
        "text": "\n".join(normalized_urls),
        "numeric_vector": numeric_vector,
        "feature_map": feature_map,
        "metrics": {
            "url_count": len(rows),
            "avg_length": feature_map.get("url_length", 0.0),
            "avg_entropy": feature_map.get("host_entropy", 0.0),
            "suspicious_token_density": feature_map.get("suspicious_token_count", 0.0),
        },
    }
