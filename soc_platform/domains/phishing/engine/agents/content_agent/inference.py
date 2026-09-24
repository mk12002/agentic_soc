"""Inference engine for content phishing detection models.

Supports the tri-class SLM output:
    Label 0 = Legitimate
    Label 1 = Spam
    Label 2 = Phishing

The text preprocessing step (_compact_text) MUST mirror the exact
preprocessing applied during training so the tokenizer sees the same
distribution at inference time.
"""

from __future__ import annotations

from typing import Any

from soc_platform.domains.phishing.engine.agents.ml_runtime import clamp as _clamp
from soc_platform.domains.phishing.engine.services.logging_service import get_agent_logger

logger = get_agent_logger("content_agent")

MAX_WORDS_PER_SAMPLE = 200  # Must match training script default (30GB RAM setting)
MAX_SEQ_LEN = 128  # Must match training tokenization max_length (30GB RAM setting)





def _from_proba(value: Any) -> float:
    if isinstance(value, (list, tuple)) and value:
        return float(value[-1])
    return float(value)


def _compact_text(text: str) -> str:
    """Normalize and shorten text — identical to the training preprocessor."""
    normalized = " ".join(str(text).split())
    words = normalized.split()
    if len(words) > MAX_WORDS_PER_SAMPLE:
        words = words[:MAX_WORDS_PER_SAMPLE]
    return " ".join(words)


# Labels the SLM was trained on (must stay in sync with prepare_training_data)
_LABEL_RISK = {
    "LABEL_0": 0.0,   # Legitimate  → zero risk
    "LABEL_1": 0.65,  # Spam        → moderate risk
    "LABEL_2": 0.95,  # Phishing    → high risk
    "Legitimate": 0.0,
    "Spam": 0.65,
    "Phishing": 0.95,
}


def predict(features: dict[str, Any], model: Any = None) -> dict[str, Any]:
    """Run model inference and return normalized risk/confidence values."""
    logger.debug("Running inference", agent="content_agent")
    if not model:
        return {"risk_score": 0.0, "confidence": 0.0, "indicators": ["ml_model_unavailable"]}

    try:
        kind = model.get("kind") if isinstance(model, dict) else "sklearn_model"

        if kind == "transformer_pipeline":
            raw_text = features.get("text", "")

            # ── CRITICAL: apply the same preprocessing used during training ──
            processed_text = _compact_text(raw_text)

            output = model["model"](processed_text, truncation=True, max_length=MAX_SEQ_LEN)
            row = output[0] if output else {}
            label = str(row.get("label", ""))
            score = float(row.get("score", 0.0))

            # Map the tri-class label to a risk score
            risk = _LABEL_RISK.get(label, 0.5)
            # Scale risk by confidence (low-confidence predictions should lower risk)
            risk = risk * score

            indicators = [f"ml_slm_label:{label}", f"ml_slm_confidence:{score:.4f}"]
            return {
                "risk_score": _clamp(risk),
                "confidence": _clamp(score),
                "indicators": indicators,
                "feature_importance": {"text_transformer": 1.0},
            }

        # ── Fallback: sklearn model ──
        base_model = model.get("model") if isinstance(model, dict) else model
        vectorizer = model.get("vectorizer") if isinstance(model, dict) else None
        text = features.get("text", "")
        numeric_vector = features.get("numeric_vector")

        if vectorizer is not None:
            x = vectorizer.transform([text])
        else:
            x = numeric_vector

        if hasattr(base_model, "predict_proba"):
            proba = base_model.predict_proba(x)[0]
            risk = _from_proba(proba)
            confidence = max(float(proba.max()), 0.5)
        elif hasattr(base_model, "predict"):
            pred = base_model.predict(x)[0]
            risk = float(pred)
            confidence = 0.65
        else:
            return {"risk_score": 0.0, "confidence": 0.0, "indicators": ["ml_model_no_predict_interface"]}

        return {
            "risk_score": _clamp(risk),
            "confidence": _clamp(confidence),
            "indicators": ["ml_content_model_used"],
            "feature_importance": {"sklearn_content": 1.0},
        }
    except Exception as exc:
        logger.warning("Content model inference failed", error=str(exc))
        return {"risk_score": 0.0, "confidence": 0.0, "indicators": ["ml_inference_failed"]}
