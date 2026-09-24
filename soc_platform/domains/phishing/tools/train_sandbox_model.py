#!/usr/bin/env python3
"""Train sandbox behavior model with imbalance-aware selection, rich metrics, and visual reports."""

from __future__ import annotations
from soc_platform.domains.phishing.engine.paths import PHISHING_HOME

import argparse
import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

os.environ.setdefault("OMP_NUM_THREADS", "2")
os.environ.setdefault("OPENBLAS_NUM_THREADS", "2")
os.environ.setdefault("MKL_NUM_THREADS", "2")

import joblib
import matplotlib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.inspection import permutation_importance
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    ConfusionMatrixDisplay,
    accuracy_score,
    average_precision_score,
    balanced_accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)

matplotlib.use("Agg")

REPO_ROOT = PHISHING_HOME
WORKSPACE_ROOT = REPO_ROOT.parent
pass  # (package import; no sys.path hack needed)
from soc_platform.domains.phishing.engine.preprocessing.sandbox_feature_contract import (
    SANDBOX_FEATURE_VERSION,
    SANDBOX_NUMERIC_FEATURE_COLUMNS,
)

RANDOM_STATE = 42


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


def _setup_logger(report_dir: Path) -> logging.Logger:
    logger = logging.getLogger("sandbox_model_training")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()
    fmt = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")

    file_handler = logging.FileHandler(report_dir / "training.log")
    file_handler.setFormatter(fmt)
    logger.addHandler(file_handler)

    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(fmt)
    logger.addHandler(stream_handler)
    return logger


def _class_weight_map(y: pd.Series) -> dict[int, float]:
    counts = y.value_counts().to_dict()
    total = float(len(y))
    return {
        0: total / (2.0 * max(1, counts.get(0, 0))),
        1: total / (2.0 * max(1, counts.get(1, 0))),
    }


def _calc_sample_weights(df: pd.DataFrame, y: pd.Series) -> np.ndarray:
    class_weights = _class_weight_map(y)
    source_weights = df["sample_weight"].astype(float).to_numpy() if "sample_weight" in df.columns else np.ones(len(df))
    cls_weights = np.array([class_weights[int(v)] for v in y.to_numpy()], dtype=float)
    weights = source_weights * cls_weights
    weights = weights / max(np.mean(weights), 1e-9)
    return weights


def _rebalance_training_split(train_df: pd.DataFrame, max_ratio: float) -> pd.DataFrame:
    if train_df.empty or max_ratio <= 1.0:
        return train_df

    counts = train_df["label"].value_counts()
    if len(counts) < 2:
        return train_df

    majority_label = int(counts.idxmax())
    minority_label = int(counts.idxmin())
    majority_count = int(counts.max())
    minority_count = int(counts.min())

    if minority_count <= 0 or (majority_count / minority_count) <= max_ratio:
        return train_df

    keep_majority = int(minority_count * max_ratio)
    majority_slice = train_df[train_df["label"] == majority_label].sample(
        n=keep_majority,
        random_state=RANDOM_STATE,
    )
    minority_slice = train_df[train_df["label"] == minority_label]
    balanced = pd.concat([majority_slice, minority_slice], axis=0).sample(
        frac=1.0,
        random_state=RANDOM_STATE,
    )
    return balanced.reset_index(drop=True)


def _load_dataset(path: Path) -> pd.DataFrame:
    if not path.exists():
        raise FileNotFoundError(f"Sandbox training dataset not found: {path}")

    df = pd.read_csv(path, low_memory=False)
    missing = [c for c in SANDBOX_NUMERIC_FEATURE_COLUMNS if c not in df.columns]
    if missing:
        raise RuntimeError(f"Training CSV missing required sandbox feature columns: {missing}")
    if "label" not in df.columns:
        raise RuntimeError("Training CSV missing label column.")

    df = df[df["label"].isin([0, 1])].copy()
    df[SANDBOX_NUMERIC_FEATURE_COLUMNS] = df[SANDBOX_NUMERIC_FEATURE_COLUMNS].replace([np.inf, -np.inf], np.nan).fillna(0.0)
    for col in SANDBOX_NUMERIC_FEATURE_COLUMNS:
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0.0)

    if "split" not in df.columns:
        from sklearn.model_selection import train_test_split

        train_idx, val_idx = train_test_split(df.index, test_size=0.2, random_state=RANDOM_STATE, stratify=df["label"])
        df["split"] = "train"
        df.loc[val_idx, "split"] = "val"

    return df


def _plot_class_distribution(df: pd.DataFrame, out_file: Path) -> None:
    counts = df["label"].value_counts().sort_index()
    labels = ["benign(0)", "malicious(1)"]
    vals = [int(counts.get(0, 0)), int(counts.get(1, 0))]
    fig, ax = plt.subplots(figsize=(6, 4))
    bars = ax.bar(labels, vals)
    ax.set_title("Sandbox Label Distribution")
    ax.set_ylabel("Rows")
    for bar, val in zip(bars, vals):
        ax.text(bar.get_x() + bar.get_width() / 2, val, str(val), ha="center", va="bottom")
    fig.tight_layout()
    fig.savefig(out_file, dpi=180)
    plt.close(fig)


def _plot_source_distribution(df: pd.DataFrame, out_file: Path) -> None:
    counts = df["source"].value_counts().head(12)
    fig, ax = plt.subplots(figsize=(10, 5))
    ax.bar(counts.index.astype(str), counts.values)
    ax.set_title("Sandbox Rows by Source")
    ax.set_ylabel("Rows")
    ax.tick_params(axis="x", rotation=25)
    fig.tight_layout()
    fig.savefig(out_file, dpi=180)
    plt.close(fig)


def _evaluate(y_true: np.ndarray, y_prob: np.ndarray, threshold: float) -> dict[str, float]:
    pred = (y_prob >= threshold).astype(int)
    return {
        "roc_auc": float(roc_auc_score(y_true, y_prob)),
        "pr_auc_malicious": float(average_precision_score(y_true, y_prob)),
        "pr_auc_benign": float(average_precision_score(1 - y_true, 1.0 - y_prob)),
        "accuracy": float(accuracy_score(y_true, pred)),
        "balanced_accuracy": float(balanced_accuracy_score(y_true, pred)),
        "precision": float(precision_score(y_true, pred, zero_division=0)),
        "recall": float(recall_score(y_true, pred, zero_division=0)),
        "f1": float(f1_score(y_true, pred, zero_division=0)),
        "macro_f1": float(f1_score(y_true, pred, average="macro", zero_division=0)),
    }


def _best_threshold(y_true: np.ndarray, y_prob: np.ndarray) -> tuple[float, dict[str, float], pd.DataFrame]:
    records: list[dict[str, float]] = []
    best_t = 0.5
    best_score = -1.0
    best_metrics: dict[str, float] = {}
    for t in np.linspace(0.05, 0.95, 181):
        m = _evaluate(y_true, y_prob, float(t))
        combo = 0.55 * m["balanced_accuracy"] + 0.45 * m["macro_f1"]
        records.append({"threshold": float(t), **m, "selection_score": combo})
        if combo > best_score:
            best_score = combo
            best_t = float(t)
            best_metrics = m
    return best_t, best_metrics, pd.DataFrame(records)


def _candidate_models(pos_weight: float) -> list[dict[str, Any]]:
    candidates = [
        {
            "name": "hist_gradient_boosting",
            "builder": lambda: HistGradientBoostingClassifier(
                max_iter=700,
                learning_rate=0.04,
                max_leaf_nodes=63,
                min_samples_leaf=30,
                l2_regularization=0.08,
                early_stopping=True,
                validation_fraction=0.1,
                n_iter_no_change=30,
                random_state=RANDOM_STATE,
            ),
            "uses_sample_weight": True,
        },
        {
            "name": "random_forest_balanced",
            "builder": lambda: RandomForestClassifier(
                n_estimators=500,
                max_depth=24,
                min_samples_leaf=2,
                class_weight="balanced_subsample",
                n_jobs=2,
                random_state=RANDOM_STATE,
            ),
            "uses_sample_weight": False,
        },
        {
            "name": "logistic_balanced",
            "builder": lambda: LogisticRegression(
                max_iter=1200,
                class_weight="balanced",
                solver="lbfgs",
                random_state=RANDOM_STATE,
            ),
            "uses_sample_weight": False,
        },
    ]

    try:
        from xgboost import XGBClassifier

        candidates.insert(
            0,
            {
                "name": "xgboost_weighted",
                "builder": lambda: XGBClassifier(
                    n_estimators=450,
                    max_depth=6,
                    learning_rate=0.05,
                    subsample=0.9,
                    colsample_bytree=0.8,
                    reg_lambda=1.2,
                    reg_alpha=0.1,
                    min_child_weight=3.0,
                    gamma=0.05,
                    objective="binary:logistic",
                    eval_metric="aucpr",
                    random_state=RANDOM_STATE,
                    n_jobs=2,
                    scale_pos_weight=float(pos_weight),
                ),
                "uses_sample_weight": True,
            },
        )
    except Exception:
        pass

    return candidates


def _predict_proba(model: Any, x: pd.DataFrame) -> np.ndarray:
    if hasattr(model, "predict_proba"):
        return model.predict_proba(x)[:, 1]
    if hasattr(model, "decision_function"):
        dec = model.decision_function(x)
        return 1.0 / (1.0 + np.exp(-dec))
    raise RuntimeError("Model lacks predict_proba/decision_function.")


def _plot_candidate_comparison(scores: pd.DataFrame, out_file: Path) -> None:
    fig, ax = plt.subplots(figsize=(10, 5))
    x = np.arange(len(scores))
    w = 0.25
    ax.bar(x - w, scores["val_balanced_accuracy"], width=w, label="Val Balanced Acc")
    ax.bar(x, scores["val_macro_f1"], width=w, label="Val Macro F1")
    ax.bar(x + w, scores["val_pr_auc_malicious"], width=w, label="Val PR-AUC Mal")
    ax.set_xticks(x)
    ax.set_xticklabels(scores["name"].tolist(), rotation=20)
    ax.set_ylim(0.0, 1.0)
    ax.set_title("Sandbox Candidate Model Comparison")
    ax.legend()
    fig.tight_layout()
    fig.savefig(out_file, dpi=180)
    plt.close(fig)


def _plot_roc(y_true: np.ndarray, y_prob: np.ndarray, out_file: Path) -> None:
    fpr, tpr, _ = roc_curve(y_true, y_prob)
    auc = roc_auc_score(y_true, y_prob)
    fig, ax = plt.subplots(figsize=(6, 5))
    ax.plot(fpr, tpr, label=f"ROC AUC={auc:.4f}")
    ax.plot([0, 1], [0, 1], "--", color="gray")
    ax.set_xlabel("False Positive Rate")
    ax.set_ylabel("True Positive Rate")
    ax.set_title("Sandbox ROC Curve")
    ax.legend()
    fig.tight_layout()
    fig.savefig(out_file, dpi=180)
    plt.close(fig)


def _plot_pr(y_true: np.ndarray, y_prob: np.ndarray, out_file_mal: Path, out_file_ben: Path) -> None:
    p, r, _ = precision_recall_curve(y_true, y_prob)
    ap = average_precision_score(y_true, y_prob)
    fig, ax = plt.subplots(figsize=(6, 5))
    ax.plot(r, p, label=f"AP={ap:.4f}")
    ax.set_xlabel("Recall")
    ax.set_ylabel("Precision")
    ax.set_title("PR Curve (Malicious class=1)")
    ax.legend()
    fig.tight_layout()
    fig.savefig(out_file_mal, dpi=180)
    plt.close(fig)

    p_b, r_b, _ = precision_recall_curve(1 - y_true, 1.0 - y_prob)
    ap_b = average_precision_score(1 - y_true, 1.0 - y_prob)
    fig, ax = plt.subplots(figsize=(6, 5))
    ax.plot(r_b, p_b, label=f"AP={ap_b:.4f}", color="darkorange")
    ax.set_xlabel("Recall")
    ax.set_ylabel("Precision")
    ax.set_title("PR Curve (Benign class=0)")
    ax.legend()
    fig.tight_layout()
    fig.savefig(out_file_ben, dpi=180)
    plt.close(fig)


def _plot_confusion(y_true: np.ndarray, y_pred: np.ndarray, out_file: Path) -> None:
    cm = confusion_matrix(y_true, y_pred)
    fig, ax = plt.subplots(figsize=(5, 4))
    ConfusionMatrixDisplay(cm, display_labels=["benign", "malicious"]).plot(ax=ax, cmap="Blues", values_format="d")
    ax.set_title("Confusion Matrix")
    fig.tight_layout()
    fig.savefig(out_file, dpi=180)
    plt.close(fig)


def _plot_threshold_sweep(threshold_df: pd.DataFrame, out_file: Path) -> None:
    fig, ax = plt.subplots(figsize=(8, 5))
    ax.plot(threshold_df["threshold"], threshold_df["balanced_accuracy"], label="Balanced Accuracy")
    ax.plot(threshold_df["threshold"], threshold_df["macro_f1"], label="Macro F1")
    ax.plot(threshold_df["threshold"], threshold_df["selection_score"], label="Selection Score")
    ax.set_xlabel("Threshold")
    ax.set_ylim(0.0, 1.0)
    ax.set_title("Threshold Sweep")
    ax.legend()
    fig.tight_layout()
    fig.savefig(out_file, dpi=180)
    plt.close(fig)


def _plot_score_distribution(y_true: np.ndarray, y_prob: np.ndarray, threshold: float, out_file: Path) -> None:
    fig, ax = plt.subplots(figsize=(8, 5))
    ax.hist(y_prob[y_true == 0], bins=40, alpha=0.6, label="benign", color="tab:green")
    ax.hist(y_prob[y_true == 1], bins=40, alpha=0.6, label="malicious", color="tab:red")
    ax.axvline(threshold, color="black", linestyle="--", label=f"threshold={threshold:.3f}")
    ax.set_xlabel("Predicted malicious probability")
    ax.set_ylabel("Count")
    ax.set_title("Score Distribution by Class")
    ax.legend()
    fig.tight_layout()
    fig.savefig(out_file, dpi=180)
    plt.close(fig)


def _plot_feature_importance(model: Any, x_ref: pd.DataFrame, y_ref: pd.Series, out_file: Path) -> dict[str, float]:
    importance: pd.Series
    if hasattr(model, "feature_importances_"):
        importance = pd.Series(model.feature_importances_, index=x_ref.columns)
    elif hasattr(model, "coef_"):
        coefs = np.abs(np.ravel(model.coef_))
        importance = pd.Series(coefs, index=x_ref.columns)
    else:
        perm = permutation_importance(model, x_ref, y_ref, n_repeats=5, random_state=RANDOM_STATE, n_jobs=2)
        importance = pd.Series(perm.importances_mean, index=x_ref.columns)

    importance = importance.sort_values(ascending=False)
    top = importance.head(15)

    fig, ax = plt.subplots(figsize=(8, 6))
    ax.barh(top.index[::-1], top.values[::-1])
    ax.set_title("Top Feature Importance")
    ax.set_xlabel("Importance")
    fig.tight_layout()
    fig.savefig(out_file, dpi=180)
    plt.close(fig)

    return {k: float(v) for k, v in importance.to_dict().items()}


def train(dataset_path: Path, report_dir: Path, model_dir: Path) -> dict[str, Any]:
    logger = _setup_logger(report_dir)
    logger.info("Loading sandbox training dataset", extra={"dataset": str(dataset_path)})
    df = _load_dataset(dataset_path)

    _plot_class_distribution(df, report_dir / "class_distribution.png")
    _plot_source_distribution(df, report_dir / "source_distribution.png")

    train_df = df[df["split"] == "train"].copy()
    val_df = df[df["split"] == "val"].copy()
    if train_df.empty or val_df.empty:
        raise RuntimeError("Sandbox dataset split must contain both train and val rows.")

    max_class_ratio = float(os.getenv("SANDBOX_MAX_CLASS_RATIO", "20.0"))
    train_df_before = len(train_df)
    train_df = _rebalance_training_split(train_df, max_ratio=max_class_ratio)

    x_train = train_df[SANDBOX_NUMERIC_FEATURE_COLUMNS].astype(float)
    y_train = train_df["label"].astype(int)
    x_val = val_df[SANDBOX_NUMERIC_FEATURE_COLUMNS].astype(float)
    y_val = val_df["label"].astype(int)

    sample_weights = _calc_sample_weights(train_df, y_train)
    label_counts = y_train.value_counts().to_dict()
    pos_weight = max(0.1, float(label_counts.get(0, 1)) / max(1.0, float(label_counts.get(1, 1))))

    logger.info(
        "Training setup",
        extra={
            "rows_train": int(len(train_df)),
            "rows_train_before_rebalance": int(train_df_before),
            "rows_val": int(len(val_df)),
            "class_distribution_train": {str(k): int(v) for k, v in label_counts.items()},
            "pos_weight": pos_weight,
            "max_class_ratio": max_class_ratio,
            "feature_version": SANDBOX_FEATURE_VERSION,
        },
    )

    candidates = _candidate_models(pos_weight=pos_weight)
    candidate_rows: list[dict[str, Any]] = []
    best: dict[str, Any] | None = None

    for cand in candidates:
        name = cand["name"]
        logger.info("Training candidate", extra={"candidate_name": name})
        model = cand["builder"]()

        if cand.get("uses_sample_weight", False):
            model.fit(x_train, y_train, sample_weight=sample_weights)
        else:
            model.fit(x_train, y_train)

        val_prob = _predict_proba(model, x_val)
        threshold, best_metrics, threshold_df = _best_threshold(y_val.to_numpy(), val_prob)

        selection_score = 0.55 * best_metrics["balanced_accuracy"] + 0.45 * best_metrics["macro_f1"]
        row = {
            "name": name,
            "threshold": threshold,
            "selection_score": float(selection_score),
            "val_balanced_accuracy": float(best_metrics["balanced_accuracy"]),
            "val_macro_f1": float(best_metrics["macro_f1"]),
            "val_pr_auc_malicious": float(best_metrics["pr_auc_malicious"]),
            "val_pr_auc_benign": float(best_metrics["pr_auc_benign"]),
            "val_roc_auc": float(best_metrics["roc_auc"]),
            "model": model,
            "threshold_df": threshold_df,
        }
        candidate_rows.append(row)

        logger.info(
            "Candidate validation metrics",
            extra={
                "candidate_name": name,
                "threshold": row["threshold"],
                "selection_score": row["selection_score"],
                "val_balanced_accuracy": row["val_balanced_accuracy"],
                "val_macro_f1": row["val_macro_f1"],
                "val_pr_auc_malicious": row["val_pr_auc_malicious"],
                "val_pr_auc_benign": row["val_pr_auc_benign"],
                "val_roc_auc": row["val_roc_auc"],
            },
        )

        if best is None or row["selection_score"] > best["selection_score"]:
            best = row

    assert best is not None

    scores_df = pd.DataFrame([{k: v for k, v in row.items() if k not in {"model", "threshold_df"}} for row in candidate_rows])
    scores_df.to_csv(report_dir / "candidate_scores.csv", index=False)
    _plot_candidate_comparison(scores_df, report_dir / "candidate_comparison.png")

    model = best["model"]
    threshold = float(best["threshold"])

    val_prob = _predict_proba(model, x_val)
    val_pred = (val_prob >= threshold).astype(int)
    metrics = _evaluate(y_val.to_numpy(), val_prob, threshold)

    _plot_roc(y_val.to_numpy(), val_prob, report_dir / "roc_curve.png")
    _plot_pr(y_val.to_numpy(), val_prob, report_dir / "pr_curve_malicious.png", report_dir / "pr_curve_benign.png")
    _plot_confusion(y_val.to_numpy(), val_pred, report_dir / "confusion_matrix.png")
    _plot_threshold_sweep(best["threshold_df"], report_dir / "threshold_sweep.png")
    _plot_score_distribution(y_val.to_numpy(), val_prob, threshold, report_dir / "score_distribution.png")
    feature_importance = _plot_feature_importance(model, x_val, y_val, report_dir / "feature_importance.png")

    model_dir.mkdir(parents=True, exist_ok=True)
    bundle = {
        "kind": "sklearn_model",
        "model": model,
        "features": SANDBOX_NUMERIC_FEATURE_COLUMNS,
        "threshold": threshold,
        "feature_version": SANDBOX_FEATURE_VERSION,
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "selection_metric": "0.55*balanced_accuracy + 0.45*macro_f1",
        "class_labels": {"0": "benign", "1": "malicious"},
    }
    joblib.dump(bundle, model_dir / "model.joblib")

    classification = classification_report(y_val.to_numpy(), val_pred, output_dict=True, zero_division=0)
    confusion = confusion_matrix(y_val.to_numpy(), val_pred).tolist()

    report = {
        "model_name": best["name"],
        "threshold": threshold,
        "feature_contract": {
            "version": SANDBOX_FEATURE_VERSION,
            "columns": SANDBOX_NUMERIC_FEATURE_COLUMNS,
        },
        "dataset": {
            "path": str(dataset_path),
            "rows_total": int(len(df)),
            "rows_train": int(len(train_df)),
            "rows_train_before_rebalance": int(train_df_before),
            "rows_val": int(len(val_df)),
            "max_class_ratio": max_class_ratio,
            "label_distribution_total": {str(k): int(v) for k, v in df["label"].value_counts().to_dict().items()},
            "source_distribution_total": {str(k): int(v) for k, v in df["source"].value_counts().to_dict().items()},
        },
        "metrics": metrics,
        "classification_report": classification,
        "confusion_matrix": confusion,
        "candidate_scores": scores_df.to_dict(orient="records"),
        "feature_importance": feature_importance,
        "artifacts": {
            "model": str(model_dir / "model.joblib"),
            "report_dir": str(report_dir),
        },
    }

    (model_dir / "model_metrics.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    (report_dir / "training_summary.json").write_text(json.dumps(report, indent=2), encoding="utf-8")

    logger.info(
        "Sandbox model training complete",
        extra={
            "model_name": best["name"],
            "threshold": threshold,
            "balanced_accuracy": metrics["balanced_accuracy"],
            "macro_f1": metrics["macro_f1"],
            "pr_auc_benign": metrics["pr_auc_benign"],
            "pr_auc_malicious": metrics["pr_auc_malicious"],
            "model_path": str(model_dir / "model.joblib"),
            "report_dir": str(report_dir),
        },
    )
    logger.info(
        "Sandbox artifacts generated",
        extra={
            "candidate_scores_csv": str(report_dir / "candidate_scores.csv"),
            "summary_json": str(report_dir / "training_summary.json"),
            "roc_plot": str(report_dir / "roc_curve.png"),
            "pr_malicious_plot": str(report_dir / "pr_curve_malicious.png"),
            "pr_benign_plot": str(report_dir / "pr_curve_benign.png"),
            "confusion_plot": str(report_dir / "confusion_matrix.png"),
            "feature_importance_plot": str(report_dir / "feature_importance.png"),
            "threshold_plot": str(report_dir / "threshold_sweep.png"),
            "score_distribution_plot": str(report_dir / "score_distribution.png"),
        },
    )
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description="Train sandbox behavior model with detailed reports and plots.")
    parser.add_argument(
        "--dataset",
        default=str(WORKSPACE_ROOT / "datasets_processed" / "sandbox_behavior_training.csv"),
        help="Path to sandbox_behavior_training.csv",
    )
    parser.add_argument(
        "--model-dir",
        default=str(WORKSPACE_ROOT / "models" / "sandbox_agent"),
        help="Directory where model.joblib will be written.",
    )
    parser.add_argument(
        "--report-root",
        default=str(REPO_ROOT / "analysis_reports"),
        help="Root folder for run reports/plots.",
    )
    args = parser.parse_args()

    dataset_path = Path(args.dataset)
    model_dir = Path(args.model_dir)
    report_dir = Path(args.report_root) / f"sandbox_model_train_{_stamp()}"
    report_dir.mkdir(parents=True, exist_ok=True)

    train(dataset_path=dataset_path, report_dir=report_dir, model_dir=model_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
