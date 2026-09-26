"""Thorough evaluation + smoke analysis for content classification model.

Outputs under models/content_agent/run_logs/eval_<timestamp>/:
- evaluation_summary.json
- classification_report.txt
- confusion_matrix.png
- per_class_f1.png
- confidence_histogram.png
- misclassified_samples.csv
- smoke_test_detailed.csv
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_recall_fscore_support,
)
from sklearn.model_selection import train_test_split
from transformers import pipeline

from soc_platform.domains.phishing.engine.paths import PHISHING_HOME

LABEL_NAMES = {0: "Legitimate", 1: "Spam", 2: "Phishing"}


def _stamp() -> str:
    return datetime.now(UTC).strftime("%Y%m%d_%H%M%S")


def _compact_text(text: str, max_words: int = 220) -> str:
    words = " ".join(str(text).split()).split()
    if len(words) > max_words:
        words = words[:max_words]
    return " ".join(words)


def _plot_confusion(cm: np.ndarray, out_file: Path) -> None:
    labels = [LABEL_NAMES[0], LABEL_NAMES[1], LABEL_NAMES[2]]
    plt.figure(figsize=(7, 6))
    plt.imshow(cm, interpolation="nearest")
    plt.title("Confusion Matrix")
    plt.colorbar()
    ticks = np.arange(len(labels))
    plt.xticks(ticks, labels, rotation=15)
    plt.yticks(ticks, labels)

    threshold = cm.max() / 2.0 if cm.size else 0.0
    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            plt.text(
                j,
                i,
                str(cm[i, j]),
                ha="center",
                va="center",
                color="white" if cm[i, j] > threshold else "black",
            )
    plt.ylabel("True")
    plt.xlabel("Predicted")
    plt.tight_layout()
    plt.savefig(out_file)
    plt.close()


def _plot_per_class_f1(y_true: np.ndarray, y_pred: np.ndarray, out_file: Path) -> None:
    labels = [0, 1, 2]
    _, _, f1, _ = precision_recall_fscore_support(y_true, y_pred, labels=labels, zero_division=0)
    names = [LABEL_NAMES[i] for i in labels]
    plt.figure(figsize=(8, 5))
    plt.bar(names, f1)
    plt.ylim(0, 1.0)
    plt.title("Per-Class F1")
    plt.ylabel("F1")
    plt.tight_layout()
    plt.savefig(out_file)
    plt.close()


def _plot_confidence_hist(confidences: list[float], out_file: Path) -> None:
    plt.figure(figsize=(8, 5))
    plt.hist(confidences, bins=40)
    plt.title("Prediction Confidence Distribution")
    plt.xlabel("Confidence")
    plt.ylabel("Count")
    plt.tight_layout()
    plt.savefig(out_file)
    plt.close()


def _normalize_pipeline_output(raw_output: object) -> list[dict[str, object]]:
    """Normalize pipeline output to a flat list of prediction dictionaries."""
    if isinstance(raw_output, list):
        if raw_output and isinstance(raw_output[0], list):
            return [item for item in raw_output[0] if isinstance(item, dict)]
        return [item for item in raw_output if isinstance(item, dict)]
    return []


def main() -> None:
    repo_root = PHISHING_HOME
    model_dir = repo_root.parent / "models" / "content_agent"
    dataset_path = repo_root.parent / "datasets_processed" / "content_training_slm.csv"

    if not model_dir.exists():
        raise FileNotFoundError(f"Model not found: {model_dir}")
    if not dataset_path.exists():
        raise FileNotFoundError(f"Dataset not found: {dataset_path}")

    run_dir = model_dir / "run_logs" / f"eval_{_stamp()}"
    run_dir.mkdir(parents=True, exist_ok=True)

    df = pd.read_csv(dataset_path)
    df = df.dropna(subset=["text", "label"]).copy()
    df["label"] = pd.to_numeric(df["label"], errors="coerce")
    df = df.dropna(subset=["label"]).copy()
    df["label"] = df["label"].astype(int)
    df = df[df["label"].isin([0, 1, 2])].copy()
    df["text"] = df["text"].astype(str).map(_compact_text)

    _, test_df = train_test_split(
        df,
        test_size=0.2,
        random_state=42,
        stratify=df["label"],
    )

    classifier = pipeline("text-classification", model=str(model_dir), tokenizer=str(model_dir), top_k=3)

    y_true = test_df["label"].to_numpy()
    y_pred: list[int] = []
    y_conf: list[float] = []

    for text in test_df["text"].tolist():
        out = _normalize_pipeline_output(classifier(text, truncation=True, max_length=128))
        if not out:
            y_pred.append(2)
            y_conf.append(0.0)
            continue
        top = out[0]
        label_name = str(top["label"])
        if label_name.lower().startswith("label_"):
            pred = int(label_name.split("_")[-1])
        else:
            pred = {"Legitimate": 0, "Spam": 1, "Phishing": 2}.get(label_name, 2)
        y_pred.append(pred)
        y_conf.append(float(top["score"]))

    y_pred_np = np.array(y_pred)

    acc = float(accuracy_score(y_true, y_pred_np))
    f1_macro = float(f1_score(y_true, y_pred_np, average="macro"))
    prec, rec, f1_pc, support = precision_recall_fscore_support(y_true, y_pred_np, labels=[0, 1, 2], zero_division=0)

    cm = confusion_matrix(y_true, y_pred_np, labels=[0, 1, 2])
    _plot_confusion(cm, run_dir / "confusion_matrix.png")
    _plot_per_class_f1(y_true, y_pred_np, run_dir / "per_class_f1.png")
    _plot_confidence_hist(y_conf, run_dir / "confidence_histogram.png")

    report_txt = classification_report(
        y_true,
        y_pred_np,
        labels=[0, 1, 2],
        target_names=[LABEL_NAMES[0], LABEL_NAMES[1], LABEL_NAMES[2]],
        digits=4,
        zero_division=0,
    )
    (run_dir / "classification_report.txt").write_text(report_txt, encoding="utf-8")

    pred_df = test_df.copy()
    pred_df["pred_label"] = y_pred_np
    pred_df["confidence"] = y_conf
    mis = pred_df[pred_df["label"] != pred_df["pred_label"]].copy()
    mis.to_csv(run_dir / "misclassified_samples.csv", index=False)

    smoke_rows = [
        ("Legitimate", "Hi team, attached is the weekly roadmap and meeting notes for tomorrow."),
        ("Spam", "FREE OFFER!!! click now for discount coupon and unlimited rewards!!!"),
        ("Phishing", "Your account will be suspended. Verify login immediately at http://secure-update-login.com"),
        ("Legitimate", "Weekly digest: engineering updates, releases, and sprint planning summary."),
        ("Phishing", "Confirm your payroll credentials now to avoid lockout and salary delays."),
        ("Spam", "Win cash now! limited stock promo. cheap meds buy now."),
    ]

    smoke_out = []
    for expected_name, text in smoke_rows:
        out = _normalize_pipeline_output(classifier(_compact_text(text), truncation=True, max_length=128))
        top = out[0] if out else {"label": "label_2", "score": 0.0}
        raw = str(top["label"])
        if raw.lower().startswith("label_"):
            pred_id = int(raw.split("_")[-1])
            pred_name = LABEL_NAMES.get(pred_id, raw)
        else:
            pred_name = raw
        smoke_out.append(
            {
                "expected": expected_name,
                "predicted": pred_name,
                "confidence": float(top["score"]),
                "raw_label": raw,
                "text": text,
            }
        )
    smoke_df = pd.DataFrame(smoke_out)
    smoke_df.to_csv(run_dir / "smoke_test_detailed.csv", index=False)

    summary = {
        "model_dir": str(model_dir),
        "dataset_path": str(dataset_path),
        "test_samples": len(test_df),
        "accuracy": acc,
        "f1_macro": f1_macro,
        "per_class": {
            "Legitimate": {
                "precision": float(prec[0]),
                "recall": float(rec[0]),
                "f1": float(f1_pc[0]),
                "support": int(support[0]),
            },
            "Spam": {
                "precision": float(prec[1]),
                "recall": float(rec[1]),
                "f1": float(f1_pc[1]),
                "support": int(support[1]),
            },
            "Phishing": {
                "precision": float(prec[2]),
                "recall": float(rec[2]),
                "f1": float(f1_pc[2]),
                "support": int(support[2]),
            },
        },
        "avg_confidence": float(np.mean(y_conf)),
        "misclassified_count": len(mis),
    }
    (run_dir / "evaluation_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")

    print(f"Evaluation artifacts written to: {run_dir}")
    print(json.dumps(summary, indent=2))

if __name__ == "__main__":
    main()
