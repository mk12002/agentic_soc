"""Inference engine for user interaction prediction models."""

from __future__ import annotations

from typing import Any
import xgboost as xgb

from soc_platform.domains.phishing.engine.services.logging_service import get_agent_logger

logger = get_agent_logger("user_behavior_agent")

def predict(features: dict[str, Any], model: xgb.XGBClassifier | None = None) -> dict[str, Any]:
    """Run inference for user-behavior model and return normalized contextual risk."""
    if model is None:
        return {"risk_score": 0.0, "confidence": 0.0, "indicators": []}

    try:
        vec = features.get("numeric_vector")
        if vec is None:
            return {"risk_score": 0.0, "confidence": 0.0, "indicators": []}

        prob = float(model.predict_proba(vec)[0, 1])

        indicators = ["ml_user_behavior_anomaly_detected"] if prob > 0.6 else []
        if features.get("context", {}).get("is_internal_domain") == 1.0 and prob > 0.8:
            indicators.append("high_confidence_internal_spoof_or_compromise")
            
        return {
            "risk_score": prob,
            "confidence": 0.85 if prob > 0.85 or prob < 0.15 else 0.60,
            "indicators": indicators
        }
    except Exception as e:
        logger.error("UBA Inference failed: {}", e)
        return {"risk_score": 0.0, "confidence": 0.0, "indicators": []}
