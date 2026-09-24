"""Inference engine for URL reputation models."""

from __future__ import annotations

from typing import Any

from soc_platform.domains.phishing.engine.agents.ml_runtime import predict_with_model
from soc_platform.domains.phishing.engine.services.logging_service import get_agent_logger

logger = get_agent_logger("url_agent")


def predict(features: dict[str, Any], model: Any = None) -> dict[str, Any]:
    """Run inference for URL agent and return normalized risk output."""
    logger.debug("Running inference", agent="url_agent")
    prediction = predict_with_model(features, model, model_indicator="ml_url_model_used")
    logger.debug("Inference complete", prediction=prediction)
    return prediction
