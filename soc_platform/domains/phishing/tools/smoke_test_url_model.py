#!/usr/bin/env python3
"""Smoke test for URL model quality and prediction robustness."""

from __future__ import annotations
from soc_platform.domains.phishing.engine.paths import PHISHING_HOME

import importlib.util
import sys
from pathlib import Path

REPO_ROOT = PHISHING_HOME
pass  # (package import; no sys.path hack needed)
ML_RUNTIME_PATH = REPO_ROOT / "agents" / "ml_runtime.py"
FEAT_EXTRACTOR_PATH = REPO_ROOT / "agents" / "url_agent" / "feature_extractor.py"


def _load_symbol(path: Path, symbol: str):
    spec = importlib.util.spec_from_file_location(path.stem + "_standalone", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load module: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return getattr(module, symbol)


load_model_bundle = _load_symbol(ML_RUNTIME_PATH, "load_model_bundle")
predict_with_model = _load_symbol(ML_RUNTIME_PATH, "predict_with_model")
extract_features = _load_symbol(FEAT_EXTRACTOR_PATH, "extract_features")

MODEL_DIR = REPO_ROOT.parent / "models" / "url_agent"


def _predict_risk(model_bundle, urls: list[str]) -> float:
    features = extract_features({"urls": urls})
    pred = predict_with_model(features, model_bundle, "smoke_url")
    return float(pred.get("risk_score", 0.0))


def main() -> int:
    model_bundle = load_model_bundle(MODEL_DIR)
    if not model_bundle:
        print(f"ERROR: No URL model found at {MODEL_DIR}")
        return 1

    threshold = 0.5
    if isinstance(model_bundle, dict) and "decision_threshold" in model_bundle:
        threshold = float(model_bundle["decision_threshold"])

    benign_cases = [
        ["http://google.com"],
        ["http://amazon.com"],
        ["http://wikipedia.org"],
        ["http://johnfuauto.com/"],
    ]

    malicious_cases = [
        ["http://secure-login-update-account.example.biz/verify?token=abc123&continue=bank"],
        ["http://198.51.100.42/login.php?verify=1&session=expired"],
        ["http://xn--secure-paypa1-9k2d.com/auth/signin?confirm=invoice"],
        ["http://apple-id-verify-account.example.ru/security/update?password=reset"],
    ]

    benign_scores = [_predict_risk(model_bundle, urls) for urls in benign_cases]
    malicious_scores = [_predict_risk(model_bundle, urls) for urls in malicious_cases]

    benign_mean = sum(benign_scores) / max(1, len(benign_scores))
    malicious_mean = sum(malicious_scores) / max(1, len(malicious_scores))

    benign_below = sum(score < threshold for score in benign_scores)
    malicious_above = sum(score >= threshold for score in malicious_scores)

    print("URL Model Smoke Test")
    print(f"  decision threshold={threshold:.4f}")
    for idx, score in enumerate(benign_scores):
        print(f"  benign_case_{idx} risk={score:.4f}")
    for idx, score in enumerate(malicious_scores):
        print(f"  malicious_case_{idx} risk={score:.4f}")
    print(f"  benign_mean={benign_mean:.4f} malicious_mean={malicious_mean:.4f}")

    conditions = [
        malicious_mean > benign_mean,
        (malicious_mean - benign_mean) >= 0.18,
        benign_below >= 3,
        malicious_above >= 3,
        max(malicious_scores) > min(benign_scores),
    ]

    if all(conditions):
        print("SMOKE TEST PASS")
        return 0

    print("SMOKE TEST FAIL")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
