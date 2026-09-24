"""Inference engine for the Header Analysis Agent.

Uses ml_runtime for consistency with other agents, while supporting
the header-specific model bundle format.
"""

from __future__ import annotations

from typing import Any

from soc_platform.domains.phishing.engine.agents.ml_runtime import predict_with_model
from soc_platform.domains.phishing.engine.services.logging_service import get_agent_logger

logger = get_agent_logger("header_agent")


def predict(features: dict[str, Any], model: Any = None) -> dict[str, Any]:
    """Run inference using the agent model.

    Args:
        features: Extracted feature dictionary containing numeric_vector and feature_map.
        model: Pre-loaded model bundle (dict with 'model', 'kind', 'features' keys).

    Returns:
        Prediction result with risk_score, confidence, and indicators.
    """
    logger.debug("Running inference", agent="header_agent")
    prediction = predict_with_model(features, model, model_indicator="ml_header_model_used")
    logger.debug("Inference complete", prediction=prediction)
    return prediction
