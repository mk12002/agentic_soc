"""Optional runtime score calibration helpers for URL-agent risk outputs."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from soc_platform.domains.phishing.engine.configs.settings import PROJECT_ROOT, settings

_CALIBRATOR_CACHE: dict[str, dict[str, Any] | None] = {}


def _clamp(value: float) -> float:
    return max(0.0, min(1.0, round(value, 4)))


def _calibrator_path() -> Path:
    configured = Path(str(settings.url_model_path or "models/url_agent")) / "risk_calibrator.joblib"
    if configured.is_absolute():
        return configured
    return PROJECT_ROOT.parent / configured


def load_calibrator() -> dict[str, Any] | None:
    path = _calibrator_path()
    key = str(path)
    if key in _CALIBRATOR_CACHE:
        return _CALIBRATOR_CACHE[key]
    if not path.exists():
        _CALIBRATOR_CACHE[key] = None
        return None

    try:
        import joblib  # type: ignore

        from soc_platform.domains.phishing.engine.integrity import verify as verify_artifact

        verify_artifact(path)
        payload = joblib.load(path)
        if not isinstance(payload, dict) or "method" not in payload or "model" not in payload:
            _CALIBRATOR_CACHE[key] = None
            return None
        _CALIBRATOR_CACHE[key] = payload
        return payload
    except Exception:
        _CALIBRATOR_CACHE[key] = None
        return None


def apply_calibration(raw_score: float) -> tuple[float, str | None]:
    payload = load_calibrator()
    if not payload:
        return _clamp(raw_score), None

    method = str(payload.get("method") or "").lower()
    model = payload.get("model")
    try:
        if method == "platt":
            calibrated = float(model.predict_proba([[float(raw_score)]])[0][1])
            return _clamp(calibrated), "platt"
        if method == "isotonic":
            calibrated = float(model.predict([float(raw_score)])[0])
            # Isotonic can become too step-like on smaller fits; smooth large jumps.
            if abs(calibrated - float(raw_score)) > 0.3:
                calibrated = (0.6 * float(raw_score)) + (0.4 * calibrated)
            return _clamp(calibrated), "isotonic"
    except Exception:
        return _clamp(raw_score), None

    return _clamp(raw_score), None
