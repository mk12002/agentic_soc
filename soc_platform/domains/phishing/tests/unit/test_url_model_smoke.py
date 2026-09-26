from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

from soc_platform.domains.phishing.engine.paths import PHISHING_HOME

REPO_ROOT = PHISHING_HOME
# (package import; no sys.path hack needed)
ML_RUNTIME_PATH = Path(__file__).resolve().parents[2] / "engine" / "agents" / "ml_runtime.py"
FEAT_EXTRACTOR_PATH = Path(__file__).resolve().parents[2] / "engine" / "agents" / "url_agent" / "feature_extractor.py"


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


@pytest.mark.smoke
def test_url_model_smoke_ordering_and_threshold() -> None:
    model_dir = REPO_ROOT.parent / "models" / "url_agent"
    model_bundle = load_model_bundle(model_dir)

    if not model_bundle:
        pytest.skip(f"No trained URL model found at {model_dir}")

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

    def predict(urls: list[str]) -> float:
        features = extract_features({"urls": urls})
        pred = predict_with_model(features, model_bundle, "pytest_url_smoke")
        return float(pred.get("risk_score", 0.0))

    benign_scores = [predict(urls) for urls in benign_cases]
    malicious_scores = [predict(urls) for urls in malicious_cases]

    benign_mean = sum(benign_scores) / len(benign_scores)
    malicious_mean = sum(malicious_scores) / len(malicious_scores)

    assert malicious_mean > benign_mean
    assert (malicious_mean - benign_mean) >= 0.18
    assert sum(score < threshold for score in benign_scores) >= 3
    assert sum(score >= threshold for score in malicious_scores) >= 3
