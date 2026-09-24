from __future__ import annotations
from soc_platform.domains.phishing.engine.paths import PHISHING_HOME

import importlib.util
import sys
from pathlib import Path

import numpy as np
import pytest

REPO_ROOT = PHISHING_HOME
pass  # (package import; no sys.path hack needed)
ML_RUNTIME_PATH = Path(__file__).resolve().parents[2] / "engine" / "agents" / "ml_runtime.py"
_SPEC = importlib.util.spec_from_file_location("ml_runtime_standalone", ML_RUNTIME_PATH)
if _SPEC is None or _SPEC.loader is None:
    raise RuntimeError(f"Unable to load ml_runtime from {ML_RUNTIME_PATH}")
_MODULE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MODULE)

load_model_bundle = _MODULE.load_model_bundle
predict_with_model = _MODULE.predict_with_model


@pytest.mark.smoke
def test_attachment_ensemble_prediction_ordering() -> None:
    model_dir = REPO_ROOT.parent / "models" / "attachment_agent"
    model_bundle = load_model_bundle(model_dir)

    if not model_bundle:
        pytest.skip(f"No trained attachment model found at {model_dir}")

    threshold = 0.5
    if isinstance(model_bundle, dict):
        inner = model_bundle.get("model")
        if isinstance(inner, dict) and "threshold" in inner:
            threshold = float(inner["threshold"])

    benign_like = {
        "numeric_vector": np.array([[1.0, 0.0, 0.0, 0.0, 5.1, 0.11]], dtype=float),
        "text": "",
    }
    malware_like = {
        "numeric_vector": np.array([[1.0, 1.0, 1.0, 0.0, 7.7, 1.85]], dtype=float),
        "text": "",
    }

    benign_risk = float(predict_with_model(benign_like, model_bundle, "pytest_smoke").get("risk_score", 0.0))
    malware_risk = float(predict_with_model(malware_like, model_bundle, "pytest_smoke").get("risk_score", 0.0))

    assert malware_risk > benign_risk
    assert malware_risk >= threshold
    assert benign_risk < threshold
