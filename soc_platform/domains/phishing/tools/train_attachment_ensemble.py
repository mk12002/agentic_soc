#!/usr/bin/env python3
"""Train a balanced-bagging attachment ensemble with detailed logging and visual reports.

The trainer builds 6-dim static features per file compatible with the runtime
attachment feature schema:
[attachment_count, risky_ext_ratio, suspicious_import_ratio, macro_ratio, avg_entropy, avg_size_mb]

Data flow:
1) Read benign/malware files from DikeDataset.
2) Reserve a stratified holdout set for unbiased evaluation.
3) Train N models where each model sees all benign train files + a disjoint malware chunk.
4) Aggregate inference by mean probability across models.
5) Emit extensive logs, metrics, and plots.
"""

from __future__ import annotations
from soc_platform.domains.phishing.engine.paths import PHISHING_HOME

import argparse
import json
import logging
import math
import random
import sys
import time
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import joblib
import matplotlib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    balanced_accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
    precision_recall_curve,
)
from sklearn.model_selection import train_test_split

# Non-interactive backend for headless servers.
matplotlib.use("Agg")
import matplotlib.pyplot as plt

REPO_ROOT = PHISHING_HOME
pass  # (package import; no sys.path hack needed)
DATA_ROOT = REPO_ROOT.parent / "datasets" / "attachments" / "malware" / "DikeDataset" / "files"
MODELS_ROOT = REPO_ROOT.parent / "models" / "attachment_agent"
REPORTS_ROOT = REPO_ROOT / "analysis_reports"

SUSPICIOUS_IMPORT_STRINGS = [
    b"VirtualAlloc",
    b"WriteProcessMemory",
    b"CreateRemoteThread",
    b"powershell",
]
MACRO_EXTENSIONS = {".docm", ".xlsm"}
RISKY_EXTENSIONS = {".exe", ".dll", ".scr", ".js", ".vbs", ".hta", ".ps1", ".docm", ".xlsm"}
FEATURE_NAMES = [
    "attachment_count",
    "risky_ext_ratio",
    "suspicious_import_ratio",
    "macro_ratio",
    "avg_entropy",
    "avg_size_mb",
]


try:
    import lightgbm as lgb

    HAS_LGBM = True
except Exception:
    HAS_LGBM = False


@dataclass
class Sample:
    path: Path
    label: int


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for byte in data:
        freq[byte] += 1
    probs = [count / len(data) for count in freq if count]
    return -sum(prob * math.log(prob, 2) for prob in probs)


def _extract_single_file_features(path: Path) -> np.ndarray:
    extension = path.suffix.lower()
    risky = 1.0 if extension in RISKY_EXTENSIONS else 0.0

    try:
        blob = path.read_bytes()
    except Exception:
        # If a file cannot be read, return a conservative low-information vector.
        return np.array([1.0, risky, 0.0, 0.0, 0.0, 0.0], dtype=float)

    suspicious = 1.0 if any(token in blob for token in SUSPICIOUS_IMPORT_STRINGS) else 0.0
    has_macro = 1.0 if extension in MACRO_EXTENSIONS and b"vba" in blob.lower() else 0.0
    ent = float(_entropy(blob))
    size_mb = float(len(blob)) / (1024.0 * 1024.0)

    return np.array([1.0, risky, suspicious, has_macro, ent, size_mb], dtype=float)


def _setup_logger(report_dir: Path) -> logging.Logger:
    logger = logging.getLogger("attachment_ensemble_training")
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


def _collect_samples(benign_dir: Path, malware_dir: Path, logger: logging.Logger) -> list[Sample]:
    benign_files = sorted(p for p in benign_dir.rglob("*") if p.is_file())
    malware_files = sorted(p for p in malware_dir.rglob("*") if p.is_file())

    logger.info("Benign files: %d", len(benign_files))
    logger.info("Malware files: %d", len(malware_files))

    samples = [Sample(path=p, label=0) for p in benign_files]
    samples.extend(Sample(path=p, label=1) for p in malware_files)
    return samples


def _build_feature_cache(samples: list[Sample], logger: logging.Logger) -> dict[str, np.ndarray]:
    unique_paths = sorted({str(s.path) for s in samples})
    cache: dict[str, np.ndarray] = {}

    logger.info("Extracting static features for %d unique files", len(unique_paths))
    start = time.perf_counter()
    for idx, p in enumerate(unique_paths, start=1):
        cache[p] = _extract_single_file_features(Path(p))
        if idx % 1000 == 0:
            logger.info("Feature extraction progress: %d/%d", idx, len(unique_paths))

    elapsed = time.perf_counter() - start
    logger.info("Feature extraction complete in %.2f sec", elapsed)
    return cache


def _to_xy(samples: list[Sample], feature_cache: dict[str, np.ndarray]) -> tuple[np.ndarray, np.ndarray]:
    x = np.vstack([feature_cache[str(s.path)] for s in samples])
    y = np.array([s.label for s in samples], dtype=int)
    return x, y


def _to_feature_frame(x: np.ndarray) -> pd.DataFrame:
    return pd.DataFrame(x, columns=FEATURE_NAMES)


def _build_model(model_type: str, seed: int):
    if model_type == "lightgbm" and HAS_LGBM:
        return lgb.LGBMClassifier(
            n_estimators=300,
            learning_rate=0.05,
            num_leaves=31,
            max_depth=-1,
            subsample=0.8,
            colsample_bytree=0.8,
            random_state=seed,
            n_jobs=1,
            verbose=-1,
        )

    return RandomForestClassifier(
        n_estimators=350,
        max_depth=18,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=seed,
        n_jobs=1,
    )


def _metric_dict(y_true: np.ndarray, prob: np.ndarray, threshold: float) -> dict[str, float]:
    pred = (prob >= threshold).astype(int)
    out = {
        "accuracy": float(accuracy_score(y_true, pred)),
        "balanced_accuracy": float(balanced_accuracy_score(y_true, pred)),
        "precision": float(precision_score(y_true, pred, zero_division=0)),
        "recall": float(recall_score(y_true, pred, zero_division=0)),
        "f1": float(f1_score(y_true, pred, zero_division=0)),
        "roc_auc": float(roc_auc_score(y_true, prob)),
        "pr_auc": float(average_precision_score(y_true, prob)),
    }
    return out


def _find_best_threshold(y_true: np.ndarray, prob: np.ndarray) -> tuple[float, dict[str, float]]:
    best_threshold = 0.5
    best_metrics = _metric_dict(y_true, prob, 0.5)
    best_f1 = best_metrics["f1"]

    for t in np.linspace(0.1, 0.9, 161):
        metrics = _metric_dict(y_true, prob, float(t))
        if metrics["f1"] > best_f1:
            best_f1 = metrics["f1"]
            best_threshold = float(t)
            best_metrics = metrics

    return best_threshold, best_metrics


def _plot_ensemble_curves(y: np.ndarray, model_probs: list[np.ndarray], ensemble_prob: np.ndarray, out_dir: Path) -> None:
    plt.figure(figsize=(10, 7))
    for idx, p in enumerate(model_probs):
        fpr, tpr, _ = roc_curve(y, p)
        auc = roc_auc_score(y, p)
        plt.plot(fpr, tpr, alpha=0.25, linewidth=1.2, label=f"model_{idx} auc={auc:.3f}")

    fpr_e, tpr_e, _ = roc_curve(y, ensemble_prob)
    auc_e = roc_auc_score(y, ensemble_prob)
    plt.plot(fpr_e, tpr_e, color="black", linewidth=2.5, label=f"ensemble auc={auc_e:.3f}")
    plt.plot([0, 1], [0, 1], linestyle="--", color="gray", linewidth=1)
    plt.title("Attachment Ensemble ROC Curves")
    plt.xlabel("False Positive Rate")
    plt.ylabel("True Positive Rate")
    plt.legend(fontsize=8, ncol=2)
    plt.tight_layout()
    plt.savefig(out_dir / "roc_curves.png", dpi=180)
    plt.close()

    plt.figure(figsize=(10, 7))
    for idx, p in enumerate(model_probs):
        prec, rec, _ = precision_recall_curve(y, p)
        auc = average_precision_score(y, p)
        plt.plot(rec, prec, alpha=0.25, linewidth=1.2, label=f"model_{idx} ap={auc:.3f}")

    prec_e, rec_e, _ = precision_recall_curve(y, ensemble_prob)
    ap_e = average_precision_score(y, ensemble_prob)
    plt.plot(rec_e, prec_e, color="black", linewidth=2.5, label=f"ensemble ap={ap_e:.3f}")
    plt.title("Attachment Ensemble Precision-Recall Curves")
    plt.xlabel("Recall")
    plt.ylabel("Precision")
    plt.legend(fontsize=8, ncol=2)
    plt.tight_layout()
    plt.savefig(out_dir / "pr_curves.png", dpi=180)
    plt.close()


def _plot_confusion(cm: np.ndarray, out_dir: Path) -> None:
    plt.figure(figsize=(5, 4))
    plt.imshow(cm, cmap="Blues")
    plt.title("Ensemble Confusion Matrix")
    plt.xlabel("Predicted")
    plt.ylabel("Actual")
    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            plt.text(j, i, str(cm[i, j]), ha="center", va="center")
    plt.xticks([0, 1], ["Benign", "Malware"])
    plt.yticks([0, 1], ["Benign", "Malware"])
    plt.tight_layout()
    plt.savefig(out_dir / "confusion_matrix.png", dpi=180)
    plt.close()


def _plot_per_model_metrics(per_model: list[dict[str, Any]], out_dir: Path) -> None:
    ids = [m["model_id"] for m in per_model]
    roc = [m["holdout_metrics"]["roc_auc"] for m in per_model]
    pra = [m["holdout_metrics"]["pr_auc"] for m in per_model]
    f1s = [m["holdout_metrics"]["f1"] for m in per_model]
    times = [m["train_seconds"] for m in per_model]

    x = np.arange(len(ids))
    width = 0.26

    plt.figure(figsize=(12, 6))
    plt.bar(x - width, roc, width=width, label="ROC-AUC")
    plt.bar(x, pra, width=width, label="PR-AUC")
    plt.bar(x + width, f1s, width=width, label="F1")
    plt.ylim(0.0, 1.0)
    plt.xticks(x, [f"m{i}" for i in ids])
    plt.title("Per-Model Holdout Metrics")
    plt.xlabel("Model")
    plt.ylabel("Score")
    plt.legend()
    plt.tight_layout()
    plt.savefig(out_dir / "per_model_metrics.png", dpi=180)
    plt.close()

    plt.figure(figsize=(10, 5))
    plt.bar(x, times)
    plt.xticks(x, [f"m{i}" for i in ids])
    plt.title("Per-Model Training Time")
    plt.xlabel("Model")
    plt.ylabel("Seconds")
    plt.tight_layout()
    plt.savefig(out_dir / "training_time.png", dpi=180)
    plt.close()


def _plot_probability_distribution(y_true: np.ndarray, prob: np.ndarray, out_dir: Path) -> None:
    benign_prob = prob[y_true == 0]
    malware_prob = prob[y_true == 1]

    plt.figure(figsize=(10, 5))
    plt.hist(benign_prob, bins=30, alpha=0.6, label="Benign", density=True)
    plt.hist(malware_prob, bins=30, alpha=0.6, label="Malware", density=True)
    plt.title("Ensemble Probability Distribution on Holdout")
    plt.xlabel("Predicted malware probability")
    plt.ylabel("Density")
    plt.legend()
    plt.tight_layout()
    plt.savefig(out_dir / "probability_distribution.png", dpi=180)
    plt.close()


def train(args: argparse.Namespace) -> None:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_dir = REPORTS_ROOT / f"attachment_ensemble_{timestamp}"
    report_dir.mkdir(parents=True, exist_ok=True)
    logger = _setup_logger(report_dir)

    logger.info("Starting attachment ensemble training")
    logger.info("Report directory: %s", report_dir)

    benign_dir = args.benign_dir
    malware_dir = args.malware_dir

    if not benign_dir.exists() or not malware_dir.exists():
        raise FileNotFoundError("Benign or malware directory does not exist")

    all_samples = _collect_samples(benign_dir, malware_dir, logger)
    labels = np.array([s.label for s in all_samples], dtype=int)

    train_samples, holdout_samples = train_test_split(
        all_samples,
        test_size=args.holdout_ratio,
        random_state=args.seed,
        stratify=labels,
    )

    logger.info("Train pool size: %d", len(train_samples))
    logger.info("Holdout size: %d", len(holdout_samples))
    logger.info("Train pool class distribution: %s", dict(Counter(s.label for s in train_samples)))
    logger.info("Holdout class distribution: %s", dict(Counter(s.label for s in holdout_samples)))

    feature_cache = _build_feature_cache(train_samples + holdout_samples, logger)

    train_benign = [s for s in train_samples if s.label == 0]
    train_malware = [s for s in train_samples if s.label == 1]
    random.Random(args.seed).shuffle(train_malware)

    malware_base = len(train_malware) // args.num_models
    remainder = len(train_malware) % args.num_models

    holdout_x, holdout_y = _to_xy(holdout_samples, feature_cache)
    holdout_x_df = _to_feature_frame(holdout_x)

    models: list[Any] = []
    per_model_report: list[dict[str, Any]] = []
    holdout_probs_per_model: list[np.ndarray] = []

    logger.info("Training %d models (type=%s)", args.num_models, args.model_type)

    cursor = 0
    for model_id in range(args.num_models):
        malware_count = malware_base + (1 if model_id < remainder else 0)
        malware_chunk = train_malware[cursor : cursor + malware_count]
        cursor += malware_count

        split_samples = train_benign + malware_chunk
        x, y = _to_xy(split_samples, feature_cache)

        x_train, x_val, y_train, y_val = train_test_split(
            x,
            y,
            test_size=0.15,
            random_state=args.seed + model_id,
            stratify=y,
        )

        model = _build_model(args.model_type, args.seed + model_id)

        x_train_df = _to_feature_frame(x_train)
        x_val_df = _to_feature_frame(x_val)

        logger.info(
            "Model %d: split_size=%d, benign=%d, malware=%d, train=%d, val=%d",
            model_id,
            len(split_samples),
            len(train_benign),
            len(malware_chunk),
            len(y_train),
            len(y_val),
        )

        start = time.perf_counter()
        model.fit(x_train_df, y_train)
        train_seconds = time.perf_counter() - start

        val_prob = model.predict_proba(x_val_df)[:, 1] if hasattr(model, "predict_proba") else model.predict(x_val_df)
        holdout_prob = (
            model.predict_proba(holdout_x_df)[:, 1]
            if hasattr(model, "predict_proba")
            else model.predict(holdout_x_df)
        )

        val_threshold, val_best = _find_best_threshold(y_val, val_prob)
        holdout_metrics = _metric_dict(holdout_y, holdout_prob, val_threshold)

        logger.info(
            "Model %d done in %.2f sec | val_f1=%.4f | holdout_roc_auc=%.4f | holdout_pr_auc=%.4f",
            model_id,
            train_seconds,
            val_best["f1"],
            holdout_metrics["roc_auc"],
            holdout_metrics["pr_auc"],
        )

        models.append(model)
        holdout_probs_per_model.append(np.asarray(holdout_prob, dtype=float))
        per_model_report.append(
            {
                "model_id": model_id,
                "split_size": int(len(split_samples)),
                "split_benign": int(len(train_benign)),
                "split_malware": int(len(malware_chunk)),
                "train_size": int(len(y_train)),
                "val_size": int(len(y_val)),
                "train_seconds": float(train_seconds),
                "val_best_threshold": float(val_threshold),
                "val_metrics": val_best,
                "holdout_metrics": holdout_metrics,
            }
        )

    ensemble_prob = np.mean(np.vstack(holdout_probs_per_model), axis=0)
    best_threshold, ensemble_metrics = _find_best_threshold(holdout_y, ensemble_prob)
    ensemble_pred = (ensemble_prob >= best_threshold).astype(int)
    cm = confusion_matrix(holdout_y, ensemble_pred)

    logger.info("Ensemble threshold selected by holdout F1: %.4f", best_threshold)
    logger.info("Ensemble holdout metrics: %s", ensemble_metrics)
    logger.info("Confusion matrix: %s", cm.tolist())

    # Visual outputs
    _plot_ensemble_curves(holdout_y, holdout_probs_per_model, ensemble_prob, report_dir)
    _plot_confusion(cm, report_dir)
    _plot_per_model_metrics(per_model_report, report_dir)
    _plot_probability_distribution(holdout_y, ensemble_prob, report_dir)

    feature_stats = {
        "feature_means": np.mean(holdout_x, axis=0).tolist(),
        "feature_stds": np.std(holdout_x, axis=0).tolist(),
            "feature_names": FEATURE_NAMES,
    }

    summary = {
        "timestamp": timestamp,
        "config": {
            "num_models": args.num_models,
            "seed": args.seed,
            "holdout_ratio": args.holdout_ratio,
            "model_type": args.model_type if (args.model_type != "lightgbm" or HAS_LGBM) else "random_forest_fallback",
            "has_lightgbm": HAS_LGBM,
        },
        "dataset": {
            "benign_dir": str(benign_dir),
            "malware_dir": str(malware_dir),
            "all_samples": int(len(all_samples)),
            "train_pool": int(len(train_samples)),
            "holdout": int(len(holdout_samples)),
            "train_class_distribution": dict(Counter(s.label for s in train_samples)),
            "holdout_class_distribution": dict(Counter(s.label for s in holdout_samples)),
        },
        "ensemble": {
            "threshold": float(best_threshold),
            "holdout_metrics": ensemble_metrics,
            "confusion_matrix": cm.tolist(),
            "n_models": len(models),
        },
        "per_model": per_model_report,
        "feature_stats": feature_stats,
        "artifacts": {
            "training_log": str(report_dir / "training.log"),
            "roc_curves": str(report_dir / "roc_curves.png"),
            "pr_curves": str(report_dir / "pr_curves.png"),
            "confusion_matrix": str(report_dir / "confusion_matrix.png"),
            "per_model_metrics": str(report_dir / "per_model_metrics.png"),
            "training_time": str(report_dir / "training_time.png"),
            "probability_distribution": str(report_dir / "probability_distribution.png"),
        },
    }

    summary_path = report_dir / "summary.json"
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    MODELS_ROOT.mkdir(parents=True, exist_ok=True)
    bundle = {
        "kind": "sklearn_bundle",
        "feature_source": "dikedataset_static_v1",
        "n_features": 6,
        "features": FEATURE_NAMES,
        "model": {
            "type": "bagging_ensemble",
            "models": models,
            "threshold": float(best_threshold),
            "num_models": len(models),
        },
        "report_dir": str(report_dir),
        "summary": {
            "holdout_metrics": ensemble_metrics,
            "confusion_matrix": cm.tolist(),
        },
    }
    out_path = MODELS_ROOT / "model.joblib"
    joblib.dump(bundle, out_path)

    logger.info("Model bundle written to: %s", out_path)
    logger.info("Summary written to: %s", summary_path)
    logger.info("Training complete")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train attachment ensemble with detailed reporting")
    parser.add_argument(
        "--benign-dir",
        type=Path,
        default=DATA_ROOT / "benign",
        help="Directory containing benign files",
    )
    parser.add_argument(
        "--malware-dir",
        type=Path,
        default=DATA_ROOT / "malware",
        help="Directory containing malware files",
    )
    parser.add_argument("--num-models", type=int, default=10, help="Number of ensemble members")
    parser.add_argument(
        "--holdout-ratio",
        type=float,
        default=0.12,
        help="Holdout fraction reserved for final evaluation",
    )
    parser.add_argument(
        "--model-type",
        choices=["lightgbm", "random_forest"],
        default="lightgbm",
        help="Base learner type",
    )
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    train(args)
