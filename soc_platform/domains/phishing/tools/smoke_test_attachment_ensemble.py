#!/usr/bin/env python3
"""Smoke test for attachment ensemble predictions.

Checks whether the trained model produces lower risk for a benign-like feature
vector and higher risk for a malware-like feature vector.
"""

from __future__ import annotations
from soc_platform.domains.phishing.engine.paths import PHISHING_HOME

import importlib.util
import sys
from pathlib import Path

import numpy as np

REPO_ROOT = PHISHING_HOME
pass  # (package import; no sys.path hack needed)
ML_RUNTIME_PATH = REPO_ROOT / "agents" / "ml_runtime.py"
_SPEC = importlib.util.spec_from_file_location("ml_runtime_standalone", ML_RUNTIME_PATH)
if _SPEC is None or _SPEC.loader is None:
    raise RuntimeError(f"Unable to load ml_runtime from {ML_RUNTIME_PATH}")
_MODULE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MODULE)

load_model_bundle = _MODULE.load_model_bundle
predict_with_model = _MODULE.predict_with_model

MODEL_DIR = REPO_ROOT.parent / "models" / "attachment_agent"


def main() -> int:
    model_bundle = load_model_bundle(MODEL_DIR)
    if not model_bundle:
        print(f"ERROR: No attachment model found at {MODEL_DIR}")
        return 1

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

    benign_pred = predict_with_model(benign_like, model_bundle, "smoke_attachment")
    malware_pred = predict_with_model(malware_like, model_bundle, "smoke_attachment")

    benign_risk = float(benign_pred.get("risk_score", 0.0))
    malware_risk = float(malware_pred.get("risk_score", 0.0))

    print("Attachment Ensemble Smoke Test")
    print(f"  decision threshold={threshold:.4f}")
    print(f"  benign-like  risk={benign_risk:.4f} confidence={float(benign_pred.get('confidence', 0.0)):.4f}")
    print(f"  malware-like risk={malware_risk:.4f} confidence={float(malware_pred.get('confidence', 0.0)):.4f}")

    conditions = [
        malware_risk > benign_risk,
        malware_risk >= threshold,
        benign_risk < threshold,
    ]

    if all(conditions):
        print("SMOKE TEST PASS")
        return 0

    print("SMOKE TEST FAIL")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
