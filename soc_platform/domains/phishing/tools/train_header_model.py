#!/usr/bin/env python3
"""Train Header Analysis Model with detailed logging and visual reports.

Pipeline:  8-dim header feature vector  →  HistGradientBoosting / RandomForest
Input:     datasets_processed/header_training.csv
Output:    models/header_agent/model.joblib

Features:
    spf_pass, dkim_pass, dmarc_pass, sender_domain_len,
    display_name_mismatch, hop_count, reply_to_mismatch,
    sender_domain_entropy

Usage:
    cd <repo root>
    python scripts/train_header_model.py
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from soc_platform.domains.phishing.engine.paths import PHISHING_HOME

os.environ.setdefault("OMP_NUM_THREADS", "2")
os.environ.setdefault("OPENBLAS_NUM_THREADS", "2")

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

matplotlib.use("Agg")

REPO_ROOT = PHISHING_HOME
# (package import; no sys.path hack needed)
PROCESSED_DIR = REPO_ROOT.parent / "datasets_processed"
MODEL_DIR = REPO_ROOT.parent / "models" / "header_agent"
CHECKPOINT_PATH = MODEL_DIR / "model.joblib"
RUN_LOG_DIR = MODEL_DIR / "run_logs"
REPORTS_ROOT = REPO_ROOT / "analysis_reports"

RANDOM_SEED = 42

FEATURE_COLS = [
    "spf_pass",
    "dkim_pass",
    "dmarc_pass",
    "sender_domain_len",
    "display_name_mismatch",
    "hop_count",
    "reply_to_mismatch",
    "sender_domain_entropy",
]


def _stamp() -> str:
    return datetime.now(UTC).strftime("%Y%m%d_%H%M%S")


def _setup_logger(report_dir: Path) -> logging.Logger:
    logger = logging.getLogger("header_model_training")
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


# ── Dataset ──────────────────────────────────────────────────────────────────

def _load_dataset(csv_path: Path) -> pd.DataFrame:
    df = pd.read_csv(csv_path)

    missing = [col for col in FEATURE_COLS if col not in df.columns]
    if missing:
        raise RuntimeError(f"Missing required feature columns: {missing}")
    if "label" not in df.columns:
        raise RuntimeError("Dataset must include a 'label' column.")

    for col in FEATURE_COLS:
        df[col] = pd.to_numeric(df[col], errors="coerce")

    df[FEATURE_COLS] = df[FEATURE_COLS].replace([np.inf, -np.inf], np.nan).fillna(0.0)
    df["label"] = pd.to_numeric(df["label"], errors="coerce").fillna(-1).astype(int)
    df = df[df["label"].isin([0, 1])].reset_index(drop=True)

    if len(df) < 50:
        raise RuntimeError(f"Header dataset too small after cleanup: {len(df)} rows")

    return df


def _dataset_audit(df: pd.DataFrame) -> dict[str, Any]:
    label_counts = df["label"].value_counts().sort_index().to_dict()
    class_ratio = float(max(label_counts.values()) / max(1, min(label_counts.values())))

    return {
        "rows": len(df),
        "label_distribution": {str(k): int(v) for k, v in label_counts.items()},
        "class_ratio_major_to_minor": round(class_ratio, 2),
        "feature_columns": FEATURE_COLS,
        "feature_summary": {
            col: {
                "mean": round(float(df[col].mean()), 4),
                "std": round(float(df[col].std()), 4),
                "min": round(float(df[col].min()), 4),
                "max": round(float(df[col].max()), 4),
                "p50": round(float(df[col].quantile(0.50)), 4),
                "p95": round(float(df[col].quantile(0.95)), 4),
            }
            for col in FEATURE_COLS
        },
    }


# ── Model candidates ─────────────────────────────────────────────────────────

def _build_candidates() -> list[dict[str, Any]]:
    return [
        {
            "name": "hgb_header",
            "builder": lambda seed: HistGradientBoostingClassifier(
                max_iter=500,
                learning_rate=0.05,
                max_leaf_nodes=31,
                min_samples_leaf=10,
                l2_regularization=0.1,
                early_stopping=True,
                validation_fraction=0.15,
                n_iter_no_change=25,
                random_state=seed,
            ),
        },
        {
            "name": "rf_header",
            "builder": lambda seed: RandomForestClassifier(
                n_estimators=300,
                max_depth=12,
                min_samples_leaf=3,
                class_weight="balanced",
                random_state=seed,
                n_jobs=-1,
            ),
        },
    ]


# ── Threshold sweep ──────────────────────────────────────────────────────────

def _find_best_threshold(y_true: np.ndarray, y_prob: np.ndarray) -> tuple[float, dict[str, float]]:
    y = np.asarray(y_true)
    best_t = 0.5
    best = {
        "f1": float(f1_score(y, (y_prob >= 0.5).astype(int), zero_division=0)),
        "precision": float(precision_score(y, (y_prob >= 0.5).astype(int), zero_division=0)),
        "recall": float(recall_score(y, (y_prob >= 0.5).astype(int), zero_division=0)),
    }
    for t in np.linspace(0.10, 0.90, 161):
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


# ── Visualization helpers ────────────────────────────────────────────────────

def _plot_candidate_scores(scores: list[dict[str, Any]], out_file: Path) -> None:
    names = [s["name"] for s in scores]
    roc = [s["val_roc_auc"] for s in scores]
    pr = [s["val_pr_auc"] for s in scores]
    f1 = [s["val_f1"] for s in scores]

    x = np.arange(len(names))
    width = 0.26
    fig, ax = plt.subplots(figsize=(10, 5))
    ax.bar(x - width, roc, width=width, label="Val ROC-AUC")
    ax.bar(x, pr, width=width, label="Val PR-AUC")
    ax.bar(x + width, f1, width=width, label="Val F1")
    ax.set_xticks(x)
    ax.set_xticklabels(names)
    ax.set_ylim(0.0, 1.0)
    ax.set_ylabel("Score")
    ax.set_title("Header Agent — Candidate Model Comparison")
    ax.legend()
    fig.tight_layout()
    fig.savefig(out_file, dpi=180)
    plt.close(fig)


def _plot_confusion(cm: np.ndarray, out_file: Path) -> None:
    disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=["Benign", "Phishing"])
    fig, ax = plt.subplots(figsize=(6, 5))
    disp.plot(cmap="Blues", ax=ax, colorbar=False)
    ax.set_title("Header Agent — Confusion Matrix")
    fig.tight_layout()
    fig.savefig(out_file, dpi=180)
    plt.close(fig)


def _plot_roc_pr(y_test: np.ndarray, y_score: np.ndarray, roc_file: Path, pr_file: Path) -> tuple[float, float]:
    roc_auc = float(roc_auc_score(y_test, y_score))
    pr_auc = float(average_precision_score(y_test, y_score))

    fpr, tpr, _ = roc_curve(y_test, y_score)
    fig, ax = plt.subplots(figsize=(7, 5))
    ax.plot(fpr, tpr, label=f"ROC AUC = {roc_auc:.4f}")
    ax.plot([0, 1], [0, 1], "k--", linewidth=1)
    ax.set_xlabel("False Positive Rate")
    ax.set_ylabel("True Positive Rate")
    ax.set_title("Header Agent — ROC Curve")
    ax.legend(loc="lower right")
    fig.tight_layout()
    fig.savefig(roc_file, dpi=180)
    plt.close(fig)

    p_vals, r_vals, _ = precision_recall_curve(y_test, y_score)
    fig, ax = plt.subplots(figsize=(7, 5))
    ax.plot(r_vals, p_vals, label=f"PR AUC = {pr_auc:.4f}")
    ax.set_xlabel("Recall")
    ax.set_ylabel("Precision")
    ax.set_title("Header Agent — Precision-Recall Curve")
    ax.legend(loc="lower left")
    fig.tight_layout()
    fig.savefig(pr_file, dpi=180)
    plt.close(fig)

    return roc_auc, pr_auc


def _plot_score_hist(y_test: np.ndarray, y_score: np.ndarray, out_file: Path) -> None:
    fig, ax = plt.subplots(figsize=(7, 5))
    ax.hist(y_score[y_test == 0], bins=40, alpha=0.6, label="Benign", color="#4CAF50")
    ax.hist(y_score[y_test == 1], bins=40, alpha=0.6, label="Phishing", color="#F44336")
    ax.set_xlabel("Predicted phishing probability")
    ax.set_ylabel("Count")
    ax.set_title("Header Agent — Score Distribution")
    ax.legend()
    fig.tight_layout()
    fig.savefig(out_file, dpi=180)
    plt.close(fig)


def _plot_threshold_sweep(y_test: np.ndarray, y_score: np.ndarray, out_file: Path) -> None:
    thresholds = np.linspace(0.05, 0.95, 181)
    prec_v, rec_v, f1_v = [], [], []
    for t in thresholds:
        pred = (y_score >= t).astype(int)
        prec_v.append(precision_score(y_test, pred, zero_division=0))
        rec_v.append(recall_score(y_test, pred, zero_division=0))
        f1_v.append(f1_score(y_test, pred, zero_division=0))

    fig, ax = plt.subplots(figsize=(8, 5))
    ax.plot(thresholds, prec_v, label="Precision")
    ax.plot(thresholds, rec_v, label="Recall")
    ax.plot(thresholds, f1_v, label="F1")
    ax.set_xlabel("Decision threshold")
    ax.set_ylabel("Score")
    ax.set_title("Header Agent — Threshold Sweep")
    ax.legend()
    fig.tight_layout()
    fig.savefig(out_file, dpi=180)
    plt.close(fig)


def _plot_learning_curve(model: Any, out_file: Path) -> None:
    train_curve = getattr(model, "train_score_", None)
    val_curve = getattr(model, "validation_score_", None)
    if train_curve is None or val_curve is None:
        return
    rounds = np.arange(1, len(train_curve) + 1)
    fig, ax = plt.subplots(figsize=(8, 5))
    ax.plot(rounds, np.asarray(train_curve), label="Train score")
    ax.plot(rounds, np.asarray(val_curve), label="Validation score")
    ax.set_xlabel("Boosting iteration")
    ax.set_ylabel("Score")
    ax.set_title("Header Agent — Learning Curve (HistGradientBoosting)")
    ax.legend()
    fig.tight_layout()
    fig.savefig(out_file, dpi=180)
    plt.close(fig)


def _plot_permutation_importance(model: Any, x_ref: pd.DataFrame, y_ref: np.ndarray, out_file: Path) -> list[dict[str, float]]:
    if len(x_ref) == 0:
        return []
    result = permutation_importance(
        model, x_ref, y_ref,
        n_repeats=5,
        random_state=RANDOM_SEED,
        scoring="f1",
        n_jobs=-1,
    )
    importances = pd.DataFrame({
        "feature": x_ref.columns,
        "importance_mean": result.importances_mean,
        "importance_std": result.importances_std,
    }).sort_values("importance_mean", ascending=False)

    fig, ax = plt.subplots(figsize=(9, 6))
    ax.barh(importances["feature"][::-1], importances["importance_mean"][::-1],
            xerr=importances["importance_std"][::-1])
    ax.set_title("Header Agent — Permutation Feature Importance")
    ax.set_xlabel("Mean importance (F1 drop)")
    fig.tight_layout()
    fig.savefig(out_file, dpi=180)
    plt.close(fig)

    return [
        {"feature": str(row.feature), "importance_mean": float(row.importance_mean), "importance_std": float(row.importance_std)}
        for row in importances.itertuples()
    ]


# ── Main ─────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train header analysis model with detailed reporting")
    parser.add_argument("--csv-path", type=Path, default=PROCESSED_DIR / "header_training.csv")
    parser.add_argument("--seed", type=int, default=RANDOM_SEED)
    parser.add_argument("--test-size", type=float, default=0.20)
    parser.add_argument("--val-size", type=float, default=0.15)
    parser.add_argument("--force-retrain", action="store_true", default=True)
    parser.add_argument("--audit-only", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    stamp = _stamp()
    report_dir = REPORTS_ROOT / f"header_model_train_{stamp}"
    report_dir.mkdir(parents=True, exist_ok=True)
    logger = _setup_logger(report_dir)

    logger.info("=" * 70)
    logger.info("Header Agent Model Training Pipeline")
    logger.info("=" * 70)
    logger.info("Report directory: %s", report_dir)
    logger.info("Using dataset: %s", args.csv_path)

    if not args.csv_path.exists():
        logger.error("Training data not found at %s", args.csv_path)
        logger.info("Run: python scripts/generate_synthetic_datasets.py")
        logger.info("Then: python -m preprocessing.header_preprocessing")
        sys.exit(1)

    # ── Load & audit ──
    logger.info("Loading and validating dataset ...")
    df = _load_dataset(args.csv_path)
    audit = _dataset_audit(df)
    (report_dir / "dataset_audit.json").write_text(json.dumps(audit, indent=2), encoding="utf-8")

    logger.info("Dataset rows: %d", audit["rows"])
    logger.info("Label distribution: %s", audit["label_distribution"])
    logger.info("Class ratio (major/minor): %.2f", audit["class_ratio_major_to_minor"])

    for col in FEATURE_COLS:
        stats = audit["feature_summary"][col]
        logger.info(
            "  Feature %-24s  mean=%.4f  std=%.4f  min=%.4f  max=%.4f",
            col, stats["mean"], stats["std"], stats["min"], stats["max"],
        )

    if args.audit_only:
        logger.info("Audit-only mode. Exiting before training.")
        return

    # ── Split ──
    X = df[FEATURE_COLS].astype(float)
    y = df["label"].astype(int).values

    X_train_full, X_test, y_train_full, y_test = train_test_split(
        X, y, test_size=args.test_size, random_state=args.seed, stratify=y,
    )
    X_train, X_val, y_train, y_val = train_test_split(
        X_train_full, y_train_full, test_size=args.val_size, random_state=args.seed, stratify=y_train_full,
    )

    logger.info("Split sizes: train=%d  val=%d  test=%d", len(X_train), len(X_val), len(X_test))
    logger.info("Train label dist: %s", dict(zip(*np.unique(y_train, return_counts=True))))
    logger.info("Val   label dist: %s", dict(zip(*np.unique(y_val, return_counts=True))))
    logger.info("Test  label dist: %s", dict(zip(*np.unique(y_test, return_counts=True))))

    # ── Train candidates ──
    candidates = _build_candidates()
    candidate_scores: list[dict[str, Any]] = []
    best_score = -1.0
    best_model = None
    selected_candidate = ""

    for idx, candidate in enumerate(candidates, start=1):
        logger.info("─" * 50)
        logger.info("Candidate %d/%d: %s", idx, len(candidates), candidate["name"])
        t0 = time.perf_counter()
        cand_model = candidate["builder"](args.seed)
        cand_model.fit(X_train, y_train)
        train_time = time.perf_counter() - t0

        val_proba = cand_model.predict_proba(X_val)[:, 1]
        val_threshold, val_thr_metrics = _find_best_threshold(y_val, val_proba)
        val_pred = (val_proba >= val_threshold).astype(int)

        val_f1 = float(f1_score(y_val, val_pred, zero_division=0))
        val_auc = float(roc_auc_score(y_val, val_proba))
        val_ap = float(average_precision_score(y_val, val_proba))
        val_bacc = float(balanced_accuracy_score(y_val, val_pred))

        composite = (0.40 * val_auc) + (0.30 * val_ap) + (0.25 * val_f1) + (0.05 * val_bacc)

        row = {
            "name": candidate["name"],
            "train_seconds": round(train_time, 2),
            "val_threshold": round(float(val_threshold), 4),
            "val_precision": round(float(val_thr_metrics["precision"]), 4),
            "val_recall": round(float(val_thr_metrics["recall"]), 4),
            "val_f1": round(val_f1, 4),
            "val_roc_auc": round(val_auc, 4),
            "val_pr_auc": round(val_ap, 4),
            "val_balanced_accuracy": round(val_bacc, 4),
            "composite_score": round(float(composite), 4),
        }
        candidate_scores.append(row)

        logger.info(
            "%s → trained in %.1fs | threshold=%.3f  f1=%.4f  roc_auc=%.4f  pr_auc=%.4f  bacc=%.4f  composite=%.4f",
            candidate["name"], train_time, val_threshold, val_f1, val_auc, val_ap, val_bacc, composite,
        )

        if composite > best_score:
            best_score = composite
            best_model = cand_model
            selected_candidate = candidate["name"]

    if best_model is None:
        raise RuntimeError("No candidate model could be trained.")

    model = best_model
    logger.info("─" * 50)
    logger.info("Selected model: %s (composite=%.4f)", selected_candidate, best_score)

    # ── Optimal threshold ──
    val_proba_final = model.predict_proba(X_val)[:, 1]
    decision_threshold, _ = _find_best_threshold(y_val, val_proba_final)
    logger.info("Decision threshold (from val F1): %.4f", decision_threshold)

    # ── Test evaluation ──
    logger.info("─" * 50)
    logger.info("Evaluating on held-out test set ...")
    y_score = model.predict_proba(X_test)[:, 1]
    y_pred = (y_score >= decision_threshold).astype(int)

    test_metrics = {
        "accuracy": round(float(accuracy_score(y_test, y_pred)), 4),
        "balanced_accuracy": round(float(balanced_accuracy_score(y_test, y_pred)), 4),
        "precision": round(float(precision_score(y_test, y_pred, zero_division=0)), 4),
        "recall": round(float(recall_score(y_test, y_pred, zero_division=0)), 4),
        "f1": round(float(f1_score(y_test, y_pred, zero_division=0)), 4),
        "roc_auc": round(float(roc_auc_score(y_test, y_score)), 4),
        "pr_auc": round(float(average_precision_score(y_test, y_score)), 4),
    }

    logger.info("Test Accuracy:          %.4f", test_metrics["accuracy"])
    logger.info("Test Balanced Accuracy: %.4f", test_metrics["balanced_accuracy"])
    logger.info("Test Precision:         %.4f", test_metrics["precision"])
    logger.info("Test Recall:            %.4f", test_metrics["recall"])
    logger.info("Test F1:                %.4f", test_metrics["f1"])
    logger.info("Test ROC AUC:           %.4f", test_metrics["roc_auc"])
    logger.info("Test PR AUC:            %.4f", test_metrics["pr_auc"])

    cm = confusion_matrix(y_test, y_pred, labels=[0, 1])
    logger.info("Confusion matrix:\n%s", cm)

    # ── Visual reports ──
    logger.info("Generating visual reports ...")
    _plot_candidate_scores(candidate_scores, report_dir / "candidate_comparison.png")
    _plot_confusion(cm, report_dir / "confusion_matrix.png")
    roc_auc, pr_auc = _plot_roc_pr(y_test, y_score, report_dir / "roc_curve.png", report_dir / "precision_recall_curve.png")
    _plot_score_hist(y_test, y_score, report_dir / "score_histogram.png")
    _plot_threshold_sweep(y_test, y_score, report_dir / "threshold_sweep.png")
    _plot_learning_curve(model, report_dir / "learning_curve.png")
    feature_importance = _plot_permutation_importance(model, X_test, y_test, report_dir / "feature_importance.png")

    # ── Summary JSON ──
    summary = {
        "timestamp_utc": stamp,
        "dataset": {
            "path": str(args.csv_path),
            "rows_used": len(df),
            "train_rows": len(X_train),
            "val_rows": len(X_val),
            "test_rows": len(X_test),
            "label_distribution": {str(k): int(v) for k, v in zip(*np.unique(y, return_counts=True))},
        },
        "data_audit": audit,
        "model": {
            "type": type(model).__name__,
            "selected_candidate": selected_candidate,
            "decision_threshold": float(decision_threshold),
            "candidate_scores": candidate_scores,
        },
        "test_metrics": test_metrics,
        "curves": {"roc_auc": roc_auc, "pr_auc": pr_auc},
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

    # ── Readable report ──
    report_lines = [
        "Header Agent Model Training Report",
        "===================================",
        "",
        f"Timestamp (UTC): {stamp}",
        f"Dataset: {args.csv_path}",
        f"Rows used: {len(df)}",
        f"Selected candidate: {selected_candidate}",
        f"Decision threshold: {decision_threshold:.4f}",
        "",
        "Test Metrics",
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

    # ── Save model bundle ──
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    RUN_LOG_DIR.mkdir(parents=True, exist_ok=True)

    bundle = {
        "model": model,
        "kind": "sklearn_model",
        "features": FEATURE_COLS,
        "n_features": len(FEATURE_COLS),
        "feature_source": "header_synthetic_v1",
        "metrics": test_metrics,
        "decision_threshold": float(decision_threshold),
        "report_dir": str(report_dir),
    }
    joblib.dump(bundle, CHECKPOINT_PATH)

    (RUN_LOG_DIR / f"metrics_{stamp}.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")

    logger.info("=" * 70)
    logger.info("Training complete")
    logger.info("Model saved: %s", CHECKPOINT_PATH)
    logger.info("Summary saved: %s", report_dir / "summary.json")
    logger.info("Run logs: %s", RUN_LOG_DIR / f"metrics_{stamp}.json")
    logger.info("=" * 70)


if __name__ == "__main__":
    main()
