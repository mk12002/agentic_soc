"""Feature extraction for sandbox behavior model inputs."""

from __future__ import annotations

from typing import Any

import numpy as np

from soc_platform.domains.phishing.engine.preprocessing.sandbox_feature_contract import (
    SANDBOX_NUMERIC_FEATURE_COLUMNS,
    build_numeric_feature_map,
)
from soc_platform.domains.phishing.engine.services.logging_service import get_agent_logger

logger = get_agent_logger("sandbox_agent")


def extract_features(data: dict[str, Any]) -> dict[str, Any]:
    """Convert raw sandbox-style payloads into contract-aligned numeric vectors."""
    logger.debug("Extracting features", agent="sandbox_agent")

    # `data` can already be a row-like dict (training_row/runtime_observation) or nested.
    row = data.get("sandbox_features") if isinstance(data.get("sandbox_features"), dict) else data
    feature_map = build_numeric_feature_map(row or {})
    numeric_vector = np.array(
        [[feature_map[column] for column in SANDBOX_NUMERIC_FEATURE_COLUMNS]],
        dtype=float,
    )

    features = {
        "feature_map": feature_map,
        "numeric_vector": numeric_vector,
        "metrics": {
            "executed": feature_map["executed"],
            "connect_calls": feature_map["connect_calls"],
            "execve_calls": feature_map["execve_calls"],
            "critical_chain_detected": feature_map["critical_chain_detected"],
        },
    }
    logger.debug("Features extracted", feature_count=len(feature_map))
    return features
