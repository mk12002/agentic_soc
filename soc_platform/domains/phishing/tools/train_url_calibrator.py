"""Train URL-agent probability calibrator (Platt vs Isotonic) and persist best model."""

from __future__ import annotations

import os
import sys
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

import joblib
import pandas as pd
from loguru import logger
from sklearn.isotonic import IsotonicRegression
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import brier_score_loss, log_loss
from sklearn.model_selection import train_test_split

from soc_platform.domains.phishing.engine.paths import PHISHING_HOME

SCRIPT_PATH = Path(__file__).resolve()
WORKSPACE_ROOT = SCRIPT_PATH.parents[2]
if str(WORKSPACE_ROOT) not in sys.path:
    pass  # (package import; no sys.path hack needed)
from soc_platform.domains.phishing.engine.agents.url_agent.feature_extractor import extract_features
from soc_platform.domains.phishing.engine.agents.url_agent.inference import predict
from soc_platform.domains.phishing.engine.agents.url_agent.model_loader import load_model


@dataclass
class CalibrationMetrics:
    method: str
    brier: float
    logloss: float


def _score_urls(model, urls: list[str]) -> list[float]:
    scores: list[float] = []
    for url in urls:
        features = extract_features({"urls": [url]})
        pred = predict(features, model=model)
        scores.append(float(pred.get("risk_score", 0.0) or 0.0))
    return scores


def main() -> int:
    repo_root = PHISHING_HOME
    dataset_path = repo_root / "datasets_processed" / "url_training.csv"
    out_path = repo_root / "models" / "url_agent" / "risk_calibrator.joblib"

    if not dataset_path.exists():
        raise FileNotFoundError(f"Dataset not found: {dataset_path}")

    df = pd.read_csv(dataset_path)
    # Keep runtime practical for local training runs.
    max_rows = int(os.getenv("URL_CALIBRATION_MAX_ROWS", "20000"))
    if len(df) > max_rows:
        df = df.sample(n=max_rows, random_state=42)

    logger.remove()
    logger.add(sys.stderr, level="WARNING")

    if "url" not in df.columns or "label" not in df.columns:
        raise ValueError("url_training.csv must include 'url' and 'label' columns")

    labels = df["label"].astype(int).tolist()
    urls = df["url"].astype(str).tolist()

    train_urls, val_urls, train_y, val_y = train_test_split(
        urls,
        labels,
        test_size=0.2,
        random_state=42,
        stratify=labels,
    )

    model = load_model()
    train_scores = _score_urls(model, train_urls)
    val_scores = _score_urls(model, val_urls)

    # Platt scaling (logistic calibration)
    platt = LogisticRegression(max_iter=1000)
    platt.fit([[score] for score in train_scores], train_y)
    platt_probs = [float(item[1]) for item in platt.predict_proba([[score] for score in val_scores])]
    platt_metrics = CalibrationMetrics(
        method="platt",
        brier=float(brier_score_loss(val_y, platt_probs)),
        logloss=float(log_loss(val_y, platt_probs, labels=[0, 1])),
    )

    # Isotonic regression
    iso = IsotonicRegression(out_of_bounds="clip")
    iso.fit(train_scores, train_y)
    iso_probs = [float(item) for item in iso.predict(val_scores)]
    iso_metrics = CalibrationMetrics(
        method="isotonic",
        brier=float(brier_score_loss(val_y, iso_probs)),
        logloss=float(log_loss(val_y, iso_probs, labels=[0, 1])),
    )

    chosen_method = "isotonic" if iso_metrics.brier <= platt_metrics.brier else "platt"
    chosen_model = iso if chosen_method == "isotonic" else platt

    payload = {
        "method": chosen_method,
        "model": chosen_model,
        "trained_at": datetime.now(UTC).isoformat(),
        "metrics": {
            "platt": asdict(platt_metrics),
            "isotonic": asdict(iso_metrics),
        },
    }

    out_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(payload, out_path)

    print(f"Saved URL calibrator: {out_path}")
    print(f"Selected method: {chosen_method}")
    print(f"Platt brier={platt_metrics.brier:.6f} logloss={platt_metrics.logloss:.6f}")
    print(f"Isotonic brier={iso_metrics.brier:.6f} logloss={iso_metrics.logloss:.6f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
