"""
Inference engine for the Threat Intelligence Agent.

Runs the loaded XGBoost model against extracted features to produce predictions.
"""

from typing import Any
import pandas as pd

from soc_platform.domains.phishing.engine.preprocessing.threat_intel_feature_contract import MESSAGE_FEATURE_COLUMNS, get_zero_features
from soc_platform.domains.phishing.engine.services.logging_service import get_agent_logger

logger = get_agent_logger("threat_intel_agent")


def predict(features: dict[str, Any], model: Any = None) -> dict[str, Any]:
    """
    Run inference using the agent model.

    Args:
        features: Extracted feature dictionary from extract_features_from_matches().
        model: Pre-loaded XGBClassifier object (optional).

    Returns:
        Prediction result with risk_score and confidence.
    """
    prediction = {
        "risk_score": 0.0,
        "confidence": 0.3,
        "indicators": [],
    }
    
    if not features:
        features = get_zero_features()

    if model is None:
        # Fallback to simple heuristics if model isn't built
        logger.warning("Inference missing model. Falling back to heuristic defaults.")
        ratio = features.get("overall_match_ratio", 0.0)
        prediction["risk_score"] = min(1.0, ratio * 2.5)  # E.g. 40% match = 100% risk
        prediction["confidence"] = 0.5
        return prediction

    try:
        # XGBoost requires proper 2D array or DataFrame aligned exactly to training columns
        df = pd.DataFrame([features], columns=MESSAGE_FEATURE_COLUMNS)
        
        # Binary logistic objective gives probability of class 1 (malicious)
        y_prob = float(model.predict_proba(df)[0, 1])
        
        prediction["risk_score"] = round(y_prob, 4)
        
        # Build confidence dynamically
        # High confidence if predictions are stark (near 1.0 or 0.0) and match count > 0
        matches = features.get("total_match_count", 0.0)
        prob_starkness = abs(0.5 - y_prob) * 2  # scales 0.0 -> 1.0
        
        if matches > 0 and prob_starkness > 0.8:
            prediction["confidence"] = 0.95
        elif matches > 0:
            prediction["confidence"] = 0.85
        else:
            prediction["confidence"] = 0.65
            
        logger.debug("Inference complete", risk_score=prediction["risk_score"], confidence=prediction["confidence"])
        
    except Exception as e:
        logger.error("XGBoost prediction failed: %s", e)
        # Fallback
        prediction["risk_score"] = min(1.0, features.get("overall_match_ratio", 0.0) * 2.5)
        prediction["confidence"] = 0.4

    return prediction
