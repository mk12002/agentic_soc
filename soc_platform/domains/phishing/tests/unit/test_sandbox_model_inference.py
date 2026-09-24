"""Unit tests for sandbox model inference and loader integration."""

from __future__ import annotations

import numpy as np

from soc_platform.domains.phishing.engine.agents.sandbox_agent.inference import predict
from soc_platform.domains.phishing.engine.preprocessing.sandbox_feature_contract import SANDBOX_NUMERIC_FEATURE_COLUMNS


class _DummyModel:
    def predict_proba(self, x):
        n = len(x)
        probs = np.full((n, 2), 0.0, dtype=float)
        probs[:, 0] = 0.15
        probs[:, 1] = 0.85
        return probs


def test_predict_uses_feature_map_contract() -> None:
    model_bundle = {
        "kind": "sklearn_model",
        "model": _DummyModel(),
        "features": SANDBOX_NUMERIC_FEATURE_COLUMNS,
        "threshold": 0.5,
    }

    row = {col: 1.0 for col in SANDBOX_NUMERIC_FEATURE_COLUMNS}
    out = predict(row, model=model_bundle)

    assert out["risk_score"] > 0.8
    assert out["confidence"] > 0.5
    assert any("ml_sandbox_model_used" in item for item in out["indicators"])
