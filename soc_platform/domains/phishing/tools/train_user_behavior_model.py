#!/usr/bin/env python3
"""Train runtime-aligned User Behavior XGBoost model.

Input priority:
1) datasets_processed/user_behavior/user_behavior_training.csv
2) datasets_processed/user_behavior_training.csv (legacy schema converted when possible)

Output:
- models/user_behavior_agent/user_behavior_xgb.json
- models/user_behavior_agent/model_metrics.json
"""

from __future__ import annotations
from soc_platform.domains.phishing.engine.paths import PHISHING_HOME

import json
import sys
from pathlib import Path

import pandas as pd
import xgboost as xgb
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.model_selection import train_test_split

REPO_ROOT = PHISHING_HOME
pass  # (package import; no sys.path hack needed)
PROCESSED_DIR = REPO_ROOT.parent / "datasets_processed"
MODEL_DIR = REPO_ROOT.parent / "models" / "user_behavior_agent"

FEATURE_COLS = [
    "contact_count",
    "days_since_last_contact",
    "is_internal_domain",
    "is_business_hours",
    "urgency_score",
    "link_count",
    "dept_risk_tier",
]
LABEL_COL = "label"


def _resolve_training_csv() -> Path:
    preferred = PROCESSED_DIR / "user_behavior" / "user_behavior_training.csv"
    if preferred.exists():
        return preferred
    fallback = PROCESSED_DIR / "user_behavior_training.csv"
    if fallback.exists():
        return fallback
    return preferred


def _prepare_frame(df: pd.DataFrame) -> pd.DataFrame:
    """Normalize legacy and canonical schemas into FEATURE_COLS + label."""
    if set(FEATURE_COLS + [LABEL_COL]).issubset(df.columns):
        out = df[FEATURE_COLS + [LABEL_COL]].copy()
        out[LABEL_COL] = pd.to_numeric(out[LABEL_COL], errors="coerce")
        out = out.dropna(subset=[LABEL_COL])
        out[LABEL_COL] = out[LABEL_COL].astype(int)
        return out

    # Legacy synthetic schema conversion path.
    legacy_required = {"sender_familiarity", "subject_urgency", "link_count", "user_clicked"}
    if legacy_required.issubset(df.columns):
        out = pd.DataFrame()
        out["contact_count"] = (pd.to_numeric(df["sender_familiarity"], errors="coerce").fillna(0.0) * 100.0)
        out["days_since_last_contact"] = (1.0 - pd.to_numeric(df["sender_familiarity"], errors="coerce").fillna(0.0)) * 180.0
        out["is_internal_domain"] = pd.to_numeric(df["sender_familiarity"], errors="coerce").fillna(0.0)
        out["is_business_hours"] = 1.0
        out["urgency_score"] = pd.to_numeric(df["subject_urgency"], errors="coerce").fillna(0.0)
        out["link_count"] = pd.to_numeric(df["link_count"], errors="coerce").fillna(0.0)
        out["dept_risk_tier"] = 0.5
        out[LABEL_COL] = pd.to_numeric(df["user_clicked"], errors="coerce").fillna(0).astype(int)
        return out

    raise RuntimeError(
        "Unsupported user behavior training schema. "
        f"Need columns {FEATURE_COLS + [LABEL_COL]} or legacy {sorted(legacy_required)}."
    )


def main() -> None:
    csv_path = _resolve_training_csv()
    if not csv_path.exists():
        raise SystemExit(f"ERROR: Training data not found at {csv_path}")

    print(f"Loading training data from {csv_path} ...")
    raw_df = pd.read_csv(csv_path, low_memory=False)
    df = _prepare_frame(raw_df)

    for col in FEATURE_COLS:
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0.0)

    df = df[df[LABEL_COL].isin([0, 1])].reset_index(drop=True)
    if len(df) < 100:
        raise SystemExit(f"ERROR: Too few rows after cleanup ({len(df)}).")

    print(f"  Rows: {len(df)}")
    print(f"  Label distribution:\n{df[LABEL_COL].value_counts().to_string()}\n")

    X = df[FEATURE_COLS]
    y = df[LABEL_COL]

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y,
    )

    model = xgb.XGBClassifier(
        n_estimators=300,
        max_depth=6,
        learning_rate=0.06,
        subsample=0.9,
        colsample_bytree=0.9,
        objective="binary:logistic",
        eval_metric="auc",
        random_state=42,
        n_jobs=2,
    )
    model.fit(X_train, y_train)

    y_prob = model.predict_proba(X_test)[:, 1]
    y_pred = (y_prob >= 0.5).astype(int)
    auc = float(roc_auc_score(y_test, y_prob))
    report = classification_report(y_test, y_pred, output_dict=True, zero_division=0)

    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    model_path = MODEL_DIR / "user_behavior_xgb.json"
    model.save_model(str(model_path))

    metrics = {
        "dataset": str(csv_path),
        "rows": int(len(df)),
        "features": FEATURE_COLS,
        "auc": auc,
        "classification_report": report,
        "model_path": str(model_path),
    }
    (MODEL_DIR / "model_metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")

    print(f"AUC: {auc:.4f}")
    print(json.dumps(report, indent=2))
    print(f"Saved model: {model_path}")


if __name__ == "__main__":
    main()
