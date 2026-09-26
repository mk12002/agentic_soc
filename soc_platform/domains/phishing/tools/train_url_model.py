#!/usr/bin/env python3
"""Train a high-quality URL classifier with detailed audits, logs, and visual reports."""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from soc_platform.domains.phishing.engine.paths import PHISHING_HOME

# Keep CPU usage bounded for low-core machines.
os.environ["OMP_NUM_THREADS"] = "2"
os.environ["OPENBLAS_NUM_THREADS"] = "2"
os.environ["MKL_NUM_THREADS"] = "2"

import joblib
import matplotlib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.inspection import permutation_importance
from sklearn.metrics import (
    ConfusionMatrixDisplay,
    accuracy_score,
    average_precision_score,
    balanced_accuracy_score,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)
from sklearn.model_selection import train_test_split

# Non-interactive backend for headless environments.
matplotlib.use("Agg")

REPO_ROOT = PHISHING_HOME
# (package import; no sys.path hack needed)
from soc_platform.domains.phishing.engine.preprocessing.feature_pipeline import URL_FEATURE_COLUMNS

PROCESSED_DIR = REPO_ROOT.parent / "datasets_processed"
MODEL_DIR = REPO_ROOT.parent / "models" / "url_agent"
CHECKPOINT_PATH = MODEL_DIR / "model.joblib"
RUN_LOG_DIR = MODEL_DIR / "run_logs"
REPORTS_ROOT = REPO_ROOT / "analysis_reports"

RANDOM_SEED = 42


def _stamp() -> str:
    return datetime.now(UTC).strftime("%Y%m%d_%H%M%S")


def _setup_logger(report_dir: Path) -> logging.Logger:
    logger = logging.getLogger("url_model_training")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()

    formatter = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")

    file_handler = logging.FileHandler(report_dir / "training.log")
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)

    return logger


def _stratified_cap(df: pd.DataFrame, target_rows: int, seed: int) -> pd.DataFrame:
    if target_rows <= 0 or len(df) <= target_rows:
        return df

    class_counts = df["label"].value_counts()
    total = int(class_counts.sum())
    alloc = {
        int(label): max(1, round(target_rows * count / total))
        for label, count in class_counts.items()
    }

    while sum(alloc.values()) > target_rows:
        label = max(alloc, key=alloc.get)
        if alloc[label] > 1:
            alloc[label] -= 1
    while sum(alloc.values()) < target_rows:
        label = max(class_counts.index.tolist(), key=lambda value: class_counts[value])
        alloc[int(label)] += 1

    parts = []
    for label, n_rows in alloc.items():
        part = df[df["label"] == label]
        if len(part) <= n_rows:
            parts.append(part)
        else:
            parts.append(part.sample(n=n_rows, random_state=seed))
    capped = pd.concat(parts, ignore_index=True)
    return capped.sample(frac=1.0, random_state=seed).reset_index(drop=True)


def _load_dataset(csv_path: Path, chunk_size: int, max_rows: int) -> pd.DataFrame:
    chunks: list[pd.DataFrame] = []
    for chunk in pd.read_csv(csv_path, low_memory=False, chunksize=chunk_size):
        if chunk.empty:
            continue
        chunks.append(chunk)

    if not chunks:
        raise RuntimeError("No rows found in URL training CSV.")

    df = pd.concat(chunks, ignore_index=True)
    if "url" not in df.columns or "label" not in df.columns:
        raise RuntimeError("Dataset must include 'url' and 'label' columns.")

    missing = [col for col in URL_FEATURE_COLUMNS if col not in df.columns]
    if missing:
        raise RuntimeError(f"Missing required URL feature columns: {missing}")

    for col in URL_FEATURE_COLUMNS:
        df[col] = pd.to_numeric(df[col], errors="coerce")

    df[URL_FEATURE_COLUMNS] = df[URL_FEATURE_COLUMNS].replace([np.inf, -np.inf], np.nan).fillna(0.0)
    df["label"] = pd.to_numeric(df["label"], errors="coerce").fillna(-1).astype(int)
    df = df[df["label"].isin([0, 1])].reset_index(drop=True)

    if len(df) < 10000:
        raise RuntimeError(f"URL dataset too small after cleanup: {len(df)} rows")

    return _stratified_cap(df, target_rows=max_rows, seed=RANDOM_SEED)


def _dataset_audit(df: pd.DataFrame) -> dict[str, Any]:
    label_counts = df["label"].value_counts().sort_index().to_dict()
    class_ratio = float(max(label_counts.values()) / max(1, min(label_counts.values())))
    missing = {col: int(value) for col, value in df.isna().sum().to_dict().items() if int(value) > 0}
    unique_urls = int(df["url"].nunique())

    return {
        "rows": len(df),
        "columns": list(df.columns),
        "unique_urls": unique_urls,
        "duplicate_urls": int(len(df) - unique_urls),
        "label_distribution": {str(k): int(v) for k, v in label_counts.items()},
        "class_ratio_major_to_minor": class_ratio,
        "missing_values": missing,
        "feature_columns_used": URL_FEATURE_COLUMNS,
        "feature_summary": {
            col: {
                "mean": float(df[col].mean()),
                "std": float(df[col].std()),
                "p50": float(df[col].quantile(0.50)),
                "p95": float(df[col].quantile(0.95)),
                "p99": float(df[col].quantile(0.99)),
            }
            for col in URL_FEATURE_COLUMNS
        },
    }


def _build_candidates() -> list[dict[str, Any]]:
    return [
        {
            "name": "hgb_wide",
            "builder": lambda seed: HistGradientBoostingClassifier(
                max_iter=900,
                learning_rate=0.03,
                max_leaf_nodes=63,
                min_samples_leaf=30,
                l2_regularization=0.05,
                early_stopping=True,
                validation_fraction=0.1,
                n_iter_no_change=35,
                random_state=seed,
            ),
        },
        {
            "name": "hgb_fast",
            "builder": lambda seed: HistGradientBoostingClassifier(
                max_iter=650,
                learning_rate=0.05,
                max_leaf_nodes=31,
                min_samples_leaf=40,
                l2_regularization=0.10,
                early_stopping=True,
                validation_fraction=0.1,
                n_iter_no_change=30,
                random_state=seed,
            ),
        },
        {
            "name": "rf_baseline",
            "builder": lambda seed: RandomForestClassifier(
                n_estimators=300,
                max_depth=20,
                min_samples_leaf=2,
                class_weight="balanced_subsample",
                n_jobs=2,
                random_state=seed,
            ),
        },
    ]


def _find_best_threshold(y_true: pd.Series | np.ndarray, y_prob: np.ndarray) -> tuple[float, dict[str, float]]:
    y = np.asarray(y_true)
    best_t = 0.5
    best = {
        "f1": float(f1_score(y, (y_prob >= 0.5).astype(int), zero_division=0)),
        "precision": float(precision_score(y, (y_prob >= 0.5).astype(int), zero_division=0)),
        "recall": float(recall_score(y, (y_prob >= 0.5).astype(int), zero_division=0)),
    }

    for t in np.linspace(0.05, 0.95, 181):
        pred = (y_prob >= t).astype(int)
        cand = {
            "f1": float(f1_score(y, pred, zero_division=0)),
            "precision": float(precision_score(y, pred, zero_division=0)),
            "recall": float(recall_score(y, pred, zero_division=0)),
        }
        if cand["f1"] > best["f1"]:
            best_t = float(t)
            best = cand

    return best_t, best


def _plot_candidate_scores(candidate_scores: list[dict[str, Any]], out_file: Path) -> None:
    names = [item["name"] for item in candidate_scores]
    val_auc = [item["val_roc_auc"] for item in candidate_scores]
    val_ap = [item["val_pr_auc"] for item in candidate_scores]
    val_f1 = [item["val_f1"] for item in candidate_scores]

    x = np.arange(len(names))
    width = 0.26
    fig, ax = plt.subplots(figsize=(10, 5))
    ax.bar(x - width, val_auc, width=width, label="Val ROC-AUC")
    ax.bar(x, val_ap, width=width, label="Val PR-AUC")
    ax.bar(x + width, val_f1, width=width, label="Val F1")
    ax.set_xticks(x)
    ax.set_xticklabels(names)
    ax.set_ylim(0.0, 1.0)
    ax.set_ylabel("Score")
    ax.set_title("URL Candidate Model Comparison")
    ax.legend()
    fig.tight_layout()
    fig.savefig(out_file, dpi=180)
    plt.close(fig)


def _plot_confusion(cm: np.ndarray, out_file: Path) -> None:
    disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=["Benign", "Malicious"])
    fig, ax = plt.subplots(figsize=(6, 5))
    disp.plot(cmap="Blues", ax=ax, colorbar=False)
    ax.set_title("URL Model Confusion Matrix")
    fig.tight_layout()
    fig.savefig(out_file, dpi=180)
    plt.close(fig)


def _plot_roc_pr(y_test: pd.Series, y_score: np.ndarray, roc_file: Path, pr_file: Path) -> tuple[float, float]:
    roc_auc = float(roc_auc_score(y_test, y_score))
    pr_auc = float(average_precision_score(y_test, y_score))

    fpr, tpr, _ = roc_curve(y_test, y_score)
    fig, ax = plt.subplots(figsize=(7, 5))
    ax.plot(fpr, tpr, label=f"ROC AUC = {roc_auc:.4f}")
    ax.plot([0, 1], [0, 1], "k--", linewidth=1)
    ax.set_xlabel("False Positive Rate")
    ax.set_ylabel("True Positive Rate")
    ax.set_title("URL Model ROC Curve")
    ax.legend(loc="lower right")
    fig.tight_layout()
    fig.savefig(roc_file, dpi=180)
    plt.close(fig)

    p_vals, r_vals, _ = precision_recall_curve(y_test, y_score)
    fig, ax = plt.subplots(figsize=(7, 5))
    ax.plot(r_vals, p_vals, label=f"PR AUC = {pr_auc:.4f}")
    ax.set_xlabel("Recall")
    ax.set_ylabel("Precision")
    ax.set_title("URL Model Precision-Recall Curve")
    ax.legend(loc="lower left")
    fig.tight_layout()
    fig.savefig(pr_file, dpi=180)
    plt.close(fig)

    return roc_auc, pr_auc


def _plot_score_hist(y_test: pd.Series, y_score: np.ndarray, out_file: Path) -> None:
    fig, ax = plt.subplots(figsize=(7, 5))
    y_arr = np.asarray(y_test)
    ax.hist(y_score[y_arr == 0], bins=50, alpha=0.6, label="Benign", color="#4CAF50")
    ax.hist(y_score[y_arr == 1], bins=50, alpha=0.6, label="Malicious", color="#F44336")
    ax.set_xlabel("Predicted malicious probability")
    ax.set_ylabel("Count")
    ax.set_title("URL Model Score Distribution")
    ax.legend()
    fig.tight_layout()
    fig.savefig(out_file, dpi=180)
    plt.close(fig)


def _plot_threshold_sweep(y_test: pd.Series, y_score: np.ndarray, out_file: Path) -> None:
    y = np.asarray(y_test)
    thresholds = np.linspace(0.05, 0.95, 181)
    precision_vals = []
    recall_vals = []
    f1_vals = []

    for t in thresholds:
        pred = (y_score >= t).astype(int)
        precision_vals.append(precision_score(y, pred, zero_division=0))
        recall_vals.append(recall_score(y, pred, zero_division=0))
        f1_vals.append(f1_score(y, pred, zero_division=0))

    fig, ax = plt.subplots(figsize=(8, 5))
    ax.plot(thresholds, precision_vals, label="Precision")
    ax.plot(thresholds, recall_vals, label="Recall")
    ax.plot(thresholds, f1_vals, label="F1")
    ax.set_xlabel("Decision threshold")
    ax.set_ylabel("Score")
    ax.set_title("Threshold Sweep on Holdout")
    ax.legend()
    fig.tight_layout()
    fig.savefig(out_file, dpi=180)
    plt.close(fig)


def _plot_learning_curve(model: Any, out_file: Path) -> None:
    train_curve = getattr(model, "train_score_", None)
    val_curve = getattr(model, "validation_score_", None)
    if train_curve is None or val_curve is None:
        return

    train_curve = np.asarray(train_curve, dtype=float)
    val_curve = np.asarray(val_curve, dtype=float)
    rounds = np.arange(1, len(train_curve) + 1)

    fig, ax = plt.subplots(figsize=(8, 5))
    ax.plot(rounds, train_curve, label="Train score")
    ax.plot(rounds, val_curve, label="Validation score")
    ax.set_xlabel("Boosting iteration")
    ax.set_ylabel("Score")
    ax.set_title("Learning Curve (HistGradientBoosting)")
    ax.legend()
    fig.tight_layout()
    fig.savefig(out_file, dpi=180)
    plt.close(fig)


def _plot_permutation_importance(model: Any, x_ref: pd.DataFrame, y_ref: pd.Series, out_file: Path) -> list[dict[str, float]]:
    if len(x_ref) == 0:
        return []

    sample_size = min(20000, len(x_ref))
    x_sample = x_ref.sample(n=sample_size, random_state=RANDOM_SEED)
    y_sample = y_ref.loc[x_sample.index]

    result = permutation_importance(
        model,
        x_sample,
        y_sample,
        n_repeats=3,
        random_state=RANDOM_SEED,
        scoring="f1",
        n_jobs=2,
    )

    importances = pd.DataFrame(
        {
            "feature": x_ref.columns,
            "importance_mean": result.importances_mean,
            "importance_std": result.importances_std,
        }
    ).sort_values("importance_mean", ascending=False)

    top = importances.head(20)
    fig, ax = plt.subplots(figsize=(9, 7))
    ax.barh(top["feature"][::-1], top["importance_mean"][::-1], xerr=top["importance_std"][::-1])
    ax.set_title("Permutation Importance (Top 20)")
    ax.set_xlabel("Mean importance (F1 drop)")
    fig.tight_layout()
    fig.savefig(out_file, dpi=180)
    plt.close(fig)

    return [
        {
            "feature": str(row.feature),
            "importance_mean": float(row.importance_mean),
            "importance_std": float(row.importance_std),
        }
        for row in importances.itertuples()
    ]


def _is_checkpoint_compatible(model: Any, features: list[str]) -> bool:
    names = getattr(model, "feature_names_in_", None)
    if names is None:
        return False
    return list(names) == list(features)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train robust URL model with extensive logging/reporting")
    parser.add_argument("--csv-path", type=Path, default=PROCESSED_DIR / "url_training.csv")
    parser.add_argument("--chunk-size", type=int, default=int(os.getenv("URL_CSV_CHUNK_SIZE", "150000")))
    parser.add_argument("--max-train-rows", type=int, default=int(os.getenv("URL_MAX_TRAIN_ROWS", "900000")))
    parser.add_argument("--seed", type=int, default=RANDOM_SEED)
    parser.add_argument("--test-size", type=float, default=0.2)
    parser.add_argument("--val-size", type=float, default=0.1)
    parser.add_argument("--force-retrain", action="store_true", default=os.getenv("URL_FORCE_RETRAIN", "1") == "1")
    parser.add_argument("--audit-only", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    stamp = _stamp()
    report_dir = REPORTS_ROOT / f"url_model_train_{stamp}"
    report_dir.mkdir(parents=True, exist_ok=True)
    logger = _setup_logger(report_dir)

    logger.info("Starting URL model pipeline")
    logger.info("Report directory: %s", report_dir)
    logger.info("Using dataset: %s", args.csv_path)

    if not args.csv_path.exists():
        raise FileNotFoundError(f"Training data not found at {args.csv_path}")

    logger.info("Loading and validating URL dataset...")
    df = _load_dataset(args.csv_path, chunk_size=args.chunk_size, max_rows=args.max_train_rows)
    audit = _dataset_audit(df)
    (report_dir / "dataset_audit.json").write_text(json.dumps(audit, indent=2), encoding="utf-8")

    logger.info("Dataset rows: %d", audit["rows"])
    logger.info("Class distribution: %s", audit["label_distribution"])
    logger.info("Duplicate URLs: %d", audit["duplicate_urls"])

    if args.audit_only:
        logger.info("Audit-only mode complete. Exiting before training.")
        return

    X = df[URL_FEATURE_COLUMNS].astype(float)
    y = df["label"].astype(int)

    X_train_full, X_test, y_train_full, y_test = train_test_split(
        X,
        y,
        test_size=args.test_size,
        random_state=args.seed,
        stratify=y,
    )
    X_train, X_val, y_train, y_val = train_test_split(
        X_train_full,
        y_train_full,
        test_size=args.val_size,
        random_state=args.seed,
        stratify=y_train_full,
    )

    logger.info("Split sizes: train=%d val=%d test=%d", len(X_train), len(X_val), len(X_test))

    model: Any
    candidate_scores: list[dict[str, Any]] = []
    selected_candidate = ""

    if CHECKPOINT_PATH.exists() and not args.force_retrain:
        logger.info("Existing checkpoint found and force_retrain=False. Attempting evaluation-only mode.")
        bundle = joblib.load(CHECKPOINT_PATH)
        model = bundle.get("model") if isinstance(bundle, dict) else bundle
        if not _is_checkpoint_compatible(model, URL_FEATURE_COLUMNS):
            logger.info("Checkpoint feature schema is incompatible. Falling back to retraining.")
            args.force_retrain = True
        else:
            selected_candidate = "loaded_checkpoint"
            candidate_scores.append({"name": selected_candidate})

    if args.force_retrain or not selected_candidate:
        logger.info("Training candidate models...")
        candidates = _build_candidates()
        best_score = -1.0
        best_model = None

        for idx, candidate in enumerate(candidates, start=1):
            logger.info("Candidate %d/%d: %s", idx, len(candidates), candidate["name"])
            cand_model = candidate["builder"](args.seed)
            cand_model.fit(X_train, y_train)

            val_proba = cand_model.predict_proba(X_val)[:, 1]
            val_threshold, val_thr_metrics = _find_best_threshold(y_val, val_proba)
            val_pred = (val_proba >= val_threshold).astype(int)

            val_f1 = float(f1_score(y_val, val_pred, zero_division=0))
            val_auc = float(roc_auc_score(y_val, val_proba))
            val_ap = float(average_precision_score(y_val, val_proba))
            val_bacc = float(balanced_accuracy_score(y_val, val_pred))

            composite = (0.45 * val_auc) + (0.30 * val_ap) + (0.20 * val_f1) + (0.05 * val_bacc)

            row = {
                "name": candidate["name"],
                "val_threshold": float(val_threshold),
                "val_precision": float(val_thr_metrics["precision"]),
                "val_recall": float(val_thr_metrics["recall"]),
                "val_f1": val_f1,
                "val_roc_auc": val_auc,
                "val_pr_auc": val_ap,
                "val_balanced_accuracy": val_bacc,
                "composite_score": float(composite),
            }
            candidate_scores.append(row)

            logger.info(
                "%s -> threshold=%.3f f1=%.4f roc_auc=%.4f pr_auc=%.4f bacc=%.4f composite=%.4f",
                candidate["name"],
                val_threshold,
                val_f1,
                val_auc,
                val_ap,
                val_bacc,
                composite,
            )

            if composite > best_score:
                best_score = composite
                best_model = cand_model
                selected_candidate = candidate["name"]

        if best_model is None:
            raise RuntimeError("No URL model candidate could be trained.")

        model = best_model

    logger.info("Selected model: %s", selected_candidate)

    val_proba_final = model.predict_proba(X_val)[:, 1]
    decision_threshold, threshold_metrics = _find_best_threshold(y_val, val_proba_final)

    logger.info("Decision threshold from validation F1: %.4f", decision_threshold)

    y_score = model.predict_proba(X_test)[:, 1]
    y_pred = (y_score >= decision_threshold).astype(int)

    test_metrics = {
        "accuracy": float(accuracy_score(y_test, y_pred)),
        "balanced_accuracy": float(balanced_accuracy_score(y_test, y_pred)),
        "precision": float(precision_score(y_test, y_pred, zero_division=0)),
        "recall": float(recall_score(y_test, y_pred, zero_division=0)),
        "f1": float(f1_score(y_test, y_pred, zero_division=0)),
        "roc_auc": float(roc_auc_score(y_test, y_score)),
        "pr_auc": float(average_precision_score(y_test, y_score)),
    }

    logger.info("Test metrics: %s", test_metrics)

    cm = confusion_matrix(y_test, y_pred, labels=[0, 1])

    _plot_candidate_scores(candidate_scores, report_dir / "candidate_comparison.png")
    _plot_confusion(cm, report_dir / "confusion_matrix.png")
    roc_auc, pr_auc = _plot_roc_pr(y_test, y_score, report_dir / "roc_curve.png", report_dir / "precision_recall_curve.png")
    _plot_score_hist(y_test, y_score, report_dir / "score_histogram.png")
    _plot_threshold_sweep(y_test, y_score, report_dir / "threshold_sweep.png")
    _plot_learning_curve(model, report_dir / "learning_curve.png")
    feature_importance = _plot_permutation_importance(model, X_test, y_test, report_dir / "feature_importance.png")

    summary = {
        "timestamp_utc": stamp,
        "dataset": {
            "path": str(args.csv_path),
            "rows_used": len(df),
            "train_rows": len(X_train),
            "val_rows": len(X_val),
            "test_rows": len(X_test),
            "label_distribution": {str(k): int(v) for k, v in y.value_counts().to_dict().items()},
        },
        "data_audit": audit,
        "model": {
            "type": type(model).__name__,
            "selected_candidate": selected_candidate,
            "decision_threshold": float(decision_threshold),
            "candidate_scores": candidate_scores,
        },
        "validation_threshold_metrics": threshold_metrics,
        "test_metrics": test_metrics,
        "curves": {
            "roc_auc": float(roc_auc),
            "pr_auc": float(pr_auc),
        },
        "feature_importance": feature_importance,
        "artifacts": {
            "training_log": str(report_dir / "training.log"),
            "dataset_audit": str(report_dir / "dataset_audit.json"),
            "candidate_comparison": str(report_dir / "candidate_comparison.png"),
            "confusion_matrix": str(report_dir / "confusion_matrix.png"),
            "roc_curve": str(report_dir / "roc_curve.png"),
            "precision_recall_curve": str(report_dir / "precision_recall_curve.png"),
            "score_histogram": str(report_dir / "score_histogram.png"),
            "threshold_sweep": str(report_dir / "threshold_sweep.png"),
            "learning_curve": str(report_dir / "learning_curve.png"),
            "feature_importance": str(report_dir / "feature_importance.png"),
        },
    }

    (report_dir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")

    report_lines = [
        "URL Model Training Report",
        "========================",
        "",
        f"Timestamp (UTC): {stamp}",
        f"Dataset: {args.csv_path}",
        f"Rows used: {len(df)}",
        f"Selected candidate: {selected_candidate}",
        f"Decision threshold: {decision_threshold:.4f}",
        "",
        "Test metrics",
        "------------",
        f"Accuracy:          {test_metrics['accuracy']:.4f}",
        f"Balanced Accuracy: {test_metrics['balanced_accuracy']:.4f}",
        f"Precision:         {test_metrics['precision']:.4f}",
        f"Recall:            {test_metrics['recall']:.4f}",
        f"F1:                {test_metrics['f1']:.4f}",
        f"ROC AUC:           {test_metrics['roc_auc']:.4f}",
        f"PR AUC:            {test_metrics['pr_auc']:.4f}",
        "",
        f"Detailed summary: {report_dir / 'summary.json'}",
    ]
    (report_dir / "training_report.txt").write_text("\n".join(report_lines), encoding="utf-8")

    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    RUN_LOG_DIR.mkdir(parents=True, exist_ok=True)

    bundle = {
        "model": model,
        "kind": "sklearn_model",
        "features": URL_FEATURE_COLUMNS,
        "metrics": test_metrics,
        "decision_threshold": float(decision_threshold),
        "report_dir": str(report_dir),
    }
    joblib.dump(bundle, CHECKPOINT_PATH)

    (RUN_LOG_DIR / f"metrics_{stamp}.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")

    logger.info("Training complete")
    logger.info("Model saved: %s", CHECKPOINT_PATH)
    logger.info("Summary saved: %s", report_dir / "summary.json")


if __name__ == "__main__":
    main()
