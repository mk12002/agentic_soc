"""
Train Attachment Malware Detection Model on EMBER 2018 features.

Pipeline:  EMBER pre-extracted PE feature vectors  →  LightGBM (or RandomForest fallback)
Input:     datasets/attachments/malware/ember_features/train_ember_2018_v2_features.parquet
Output:    models/attachment_agent/ember_model.joblib

Notes:
    - EMBER features are 2381-dimensional PE (Portable Executable) feature vectors.
    - The model trained here handles EMBER-style input directly.
    - The agent's existing 6-dim feature extractor remains for non-EMBER files;
      the model_loader and inference module already support both formats.

Usage:
    cd <repo root>
    python scripts/train_attachment_model.py
"""

from __future__ import annotations

import sys

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split

from soc_platform.domains.phishing.engine.configs.settings import settings
from soc_platform.domains.phishing.engine.paths import PHISHING_HOME

REPO_ROOT = PHISHING_HOME
# (package import; no sys.path hack needed)
DATASET_DIR = REPO_ROOT.parent / "datasets" / "attachments" / "malware" / "ember_features"
MODEL_DIR = REPO_ROOT.parent / "models" / "attachment_agent"

# Try to use LightGBM if available, fall back to RandomForest
try:
    import lightgbm as lgb
    HAS_LGBM = True
except ImportError:
    HAS_LGBM = False


def _load_ember_data(max_samples: int | None = None) -> tuple:
    """Load EMBER parquet and extract features + labels."""
    if max_samples is None:
        max_samples = max(100_000, int(settings.preprocessing_chunk_size_mb) * 1_000)

    train_path = DATASET_DIR / "train_ember_2018_v2_features.parquet"
    if not train_path.exists():
        print(f"ERROR: EMBER training data not found at {train_path}")
        sys.exit(1)

    print(f"Loading EMBER parquet from {train_path} ...")
    df = pd.read_parquet(train_path)

    # EMBER datasets typically have a 'label' column (-1 = unlabeled, 0 = benign, 1 = malware)
    if "label" not in df.columns:
        # If no label column, assume last column is the label
        label_col = df.columns[-1]
        print(f"  No 'label' column found, using '{label_col}' as label.")
    else:
        label_col = "label"

    # Drop unlabeled samples (label == -1)
    df = df[df[label_col].isin([0, 1])].copy()

    # Subsample if dataset is very large
    if len(df) > max_samples:
        df = df.sample(n=max_samples, random_state=42)
        print(f"  Subsampled to {max_samples} rows for memory efficiency.")

    y = df[label_col].astype(int)
    X = df.drop(columns=[label_col]).select_dtypes(include=[np.number])

    # Fill NaN/inf
    X = X.replace([np.inf, -np.inf], np.nan).fillna(0)

    print(f"  Feature matrix: {X.shape}")
    print(f"  Label distribution:\n{y.value_counts().to_string()}\n")
    return X, y


def main() -> None:
    X, y = _load_ember_data()

    if len(X) < 20:
        print("ERROR: Too few samples for training.")
        sys.exit(1)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    if HAS_LGBM:
        print("Training LightGBM classifier ...")
        model = lgb.LGBMClassifier(
            n_estimators=300,
            max_depth=12,
            learning_rate=0.05,
            class_weight="balanced",
            random_state=42,
            n_jobs=-1,
            verbose=-1,
        )
    else:
        print("LightGBM not available, training RandomForest (slower) ...")
        model = RandomForestClassifier(
            n_estimators=150,
            max_depth=15,
            class_weight="balanced",
            random_state=42,
            n_jobs=-1,
        )

    model.fit(X_train, y_train)

    print("\n── Test Set Evaluation ──")
    y_pred = model.predict(X_test)
    print(classification_report(y_test, y_pred))

    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    bundle = {
        "model": model,
        "kind": "sklearn_model",
        "feature_source": "ember_2018_v2",
        "n_features": X.shape[1],
    }
    # Keep this artifact separate from the production 6-feature static ensemble.
    out_path = MODEL_DIR / "ember_model.joblib"
    joblib.dump(bundle, out_path)
    print(f"\n✅ Model saved to {out_path}")
    print(f"   Feature count: {X.shape[1]}")
    print("   NOTE: Production attachment agent expects 6-feature static schema.")


if __name__ == "__main__":
    main()
