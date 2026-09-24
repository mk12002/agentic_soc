"""Shared ML runtime helpers for agent model loading and inference."""

from __future__ import annotations
from soc_platform.domains.phishing.engine.paths import PHISHING_HOME

import pickle
import warnings
import logging
from pathlib import Path
from typing import Any

import joblib


# `src/agents/ml_runtime.py` lives under `email_security/src/agents/`, so the
# package root is two parents up.
PROJECT_ROOT = PHISHING_HOME
logger = logging.getLogger("ml_runtime")


def clamp(value: float) -> float:
    return max(0.0, min(1.0, round(float(value), 4)))


def resolve_model_path(
    model_path: str | Path,
    required_files: tuple[str, ...] | None = None,
) -> Path:
    """Resolve model directories without relying on process CWD.

    Resolution order is deterministic:
    1) Absolute path as provided.
    2) Under PROJECT_ROOT (email_security/...).
    3) Fallback to PROJECT_ROOT-relative target.
    """
    raw = Path(model_path)
    if raw.is_absolute():
        return raw

    candidates = [PROJECT_ROOT / raw]

    if required_files:
        for candidate in candidates:
            if not candidate.exists():
                continue
            if any((candidate / name).exists() for name in required_files):
                return candidate

    for candidate in candidates:
        if candidate.exists():
            return candidate

    return PROJECT_ROOT / raw


def load_model_bundle(model_path: str | Path) -> Any:
    """Load a model artifact from a model directory.

    Supported artifacts:
    - model.joblib / model.pkl containing a model or dict bundle
    - local transformer folder (config.json) for text classification
    """
    path = resolve_model_path(
        model_path,
        required_files=("model.joblib", "model.pkl", "config.json"),
    )
    if not path.exists():
        return None

    for name in ("model.joblib", "model.pkl"):
        artifact = path / name
        if not artifact.exists():
            continue

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            if artifact.suffix == ".joblib":
                loaded = joblib.load(artifact)
            else:
                with open(artifact, "rb") as handle:
                    loaded = pickle.load(handle)  # nosec B301

        mismatch_messages: dict[str, int] = {}
        for warning in caught:
            category_name = getattr(warning.category, "__name__", "")
            if category_name != "InconsistentVersionWarning":
                continue
            msg = str(warning.message)
            mismatch_messages[msg] = mismatch_messages.get(msg, 0) + 1

        for msg, count in mismatch_messages.items():
            logger.warning(
                "Model artifact loaded with sklearn version mismatch: %s (x%d) %s",
                str(artifact),
                count,
                msg,
            )

        if isinstance(loaded, dict) and "model" in loaded:
            loaded.setdefault("kind", "sklearn_bundle")
            return loaded
        return {"kind": "sklearn_model", "model": loaded}

    config_file = path / "config.json"
    if config_file.exists():
        try:
            from transformers import pipeline
        except Exception:
            return None
        pipe = pipeline(
            "text-classification",
            model=str(path),
            tokenizer=str(path),
            truncation=True,
            local_files_only=True,
        )
        return {"kind": "transformer_pipeline", "model": pipe}

    return None


def predict_with_model(features: dict[str, Any], model_bundle: Any, model_indicator: str) -> dict[str, Any]:
    """Run generic inference against loaded model bundle."""
    if not model_bundle:
        return {"risk_score": 0.0, "confidence": 0.0, "indicators": ["ml_model_unavailable"]}

    try:
        kind = model_bundle.get("kind") if isinstance(model_bundle, dict) else "sklearn_model"

        if kind == "transformer_pipeline":
            text = str(features.get("text", "") or "")
            output = model_bundle["model"](text[:4000], truncation=True)
            row = output[0] if output else {}
            label = str(row.get("label", "")).lower()
            score = float(row.get("score", 0.0))
            risk = score if any(token in label for token in ["phish", "spam", "fraud", "malicious", "1"]) else 1.0 - score
            
            return {
                "risk_score": clamp(risk),
                "confidence": clamp(score),
                "indicators": [f"ml_transformer_label:{label}"] if label else [model_indicator],
                "feature_importance": {"text_transformer": 1.0},
            }

        model = model_bundle.get("model") if isinstance(model_bundle, dict) else model_bundle
        vectorizer = model_bundle.get("vectorizer") if isinstance(model_bundle, dict) else None
        feature_names = model_bundle.get("features") if isinstance(model_bundle, dict) else None
        text = str(features.get("text", "") or "")
        numeric_vector = features.get("numeric_vector")
        feature_map = features.get("feature_map") if isinstance(features, dict) else None

        if vectorizer is not None:
            x = vectorizer.transform([text])
        elif feature_names and isinstance(feature_map, dict):
            try:
                import pandas as pd

                x = pd.DataFrame(
                    [[float(feature_map.get(name, 0.0)) for name in feature_names]],
                    columns=feature_names,
                )
            except Exception:
                x = [[float(feature_map.get(name, 0.0)) for name in feature_names]]
        elif feature_names and numeric_vector is not None:
            try:
                import pandas as pd

                x = pd.DataFrame(numeric_vector, columns=feature_names)
            except Exception:
                x = numeric_vector
        else:
            x = numeric_vector

        if x is None:
            return {"risk_score": 0.0, "confidence": 0.0, "indicators": ["ml_missing_feature_vector"]}

        # Support bagging/ensemble bundles where multiple base models vote via mean probability.
        if isinstance(model, dict) and isinstance(model.get("models"), list):
            members = model.get("models", [])
            if not members:
                return {"risk_score": 0.0, "confidence": 0.0, "indicators": ["ml_ensemble_empty"]}

            probs: list[float] = []
            for member in members:
                if hasattr(member, "predict_proba"):
                    member_proba = member.predict_proba(x)[0]
                    if hasattr(member_proba, "tolist"):
                        member_proba = member_proba.tolist()
                    probs.append(float(member_proba[-1]) if isinstance(member_proba, list) else float(member_proba))
                elif hasattr(member, "predict"):
                    probs.append(float(member.predict(x)[0]))

            if not probs:
                return {"risk_score": 0.0, "confidence": 0.0, "indicators": ["ml_ensemble_no_predict_interface"]}

            risk = sum(probs) / len(probs)
            confidence = max(risk, 1.0 - risk)
            return {
                "risk_score": clamp(risk),
                "confidence": clamp(confidence),
                "indicators": [f"{model_indicator}_ensemble_{len(probs)}"],
                "feature_importance": {},
            }

        if isinstance(model, (list, tuple)):
            probs: list[float] = []
            for member in model:
                if hasattr(member, "predict_proba"):
                    member_proba = member.predict_proba(x)[0]
                    if hasattr(member_proba, "tolist"):
                        member_proba = member_proba.tolist()
                    probs.append(float(member_proba[-1]) if isinstance(member_proba, list) else float(member_proba))
                elif hasattr(member, "predict"):
                    probs.append(float(member.predict(x)[0]))

            if not probs:
                return {"risk_score": 0.0, "confidence": 0.0, "indicators": ["ml_ensemble_no_predict_interface"]}

            risk = sum(probs) / len(probs)
            confidence = max(risk, 1.0 - risk)
            return {
                "risk_score": clamp(risk),
                "confidence": clamp(confidence),
                "indicators": [f"{model_indicator}_ensemble_{len(probs)}"],
                "feature_importance": {},
            }

        if hasattr(model, "predict_proba"):
            proba = model.predict_proba(x)[0]
            if hasattr(proba, "tolist"):
                proba = proba.tolist()
            if isinstance(proba, list):
                risk = float(proba[-1])
                confidence = max(float(max(proba)), 0.5)
            else:
                risk = float(proba)
                confidence = max(float(proba), 0.5)
        elif hasattr(model, "predict"):
            pred = model.predict(x)[0]
            risk = float(pred)
            confidence = 0.65
        else:
            return {"risk_score": 0.0, "confidence": 0.0, "indicators": ["ml_model_no_predict_interface"]}

        feature_importance = {}
        if hasattr(model, "feature_importances_") and feature_names:
            try:
                importances = model.feature_importances_
                # Support case where importances is 2D (multi-class tree)
                if len(importances.shape) > 1:
                    importances = importances.mean(axis=0)
                
                # Pair with names, sort, take top 10 non-zero
                pairs = [(name, float(imp)) for name, imp in zip(feature_names, importances) if imp > 0]
                pairs.sort(key=lambda item: item[1], reverse=True)
                feature_importance = {k: v for k, v in pairs[:10]}
            except Exception as e:
                import logging
                logging.getLogger("ml_runtime").warning(f"Failed to extract feature importance: {e}")

        return {
            "risk_score": clamp(risk),
            "confidence": clamp(confidence),
            "indicators": [model_indicator],
            "feature_importance": feature_importance,
        }
    except Exception as e:
        import logging
        import traceback
        log = logging.getLogger("ml_runtime")
        shape_info = "unknown"
        if "x" in locals() and hasattr(locals()["x"], "shape"):
            shape_info = str(locals()["x"].shape)
        elif "x" in locals() and isinstance(locals()["x"], list):
            shape_info = f"list(len={len(locals()['x'])})"
        
        err_msg = traceback.format_exc()
        log.error(f"ML inference failed: {e} | Model type: {type(model_bundle.get('model') if isinstance(model_bundle, dict) else model_bundle)} | Input shape: {shape_info}\n{err_msg}")
        return {"risk_score": 0.0, "confidence": 0.0, "indicators": ["ml_inference_failed"]}
