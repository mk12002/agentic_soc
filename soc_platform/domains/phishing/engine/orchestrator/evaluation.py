"""
Ground-truth evaluation metrics for the detection pipeline.

Turns a labeled corpus of predictions into the standard detection-quality metrics
that make accuracy *measurable and provable*: precision / recall / F1, a confusion
matrix, ROC / PR AUC, and calibration metrics (Expected Calibration Error + Brier
score). Per-agent precision/recall are also computed so weak agents are visible.

The core functions are pure and dependency-light (numpy; sklearn when available with
a numpy fallback), so they can be unit-tested on synthetic data without running the
full agent stack. ``tools/evaluate_pipeline.py`` is the thin CLI wrapper.

A ``record`` is::

    {"score": 0.0-1.0, "true_label": "phishing"|"safe"|..., "verdict": "malicious"|...,
     "agent_scores": {"url_agent": 0.8, ...}}  # verdict/agent_scores optional
"""

from __future__ import annotations

from typing import Any, Iterable

# Labels that map to the positive (malicious) class.
_POSITIVE_LABELS = {"phishing", "malicious", "spam", "bad", "bec", "malware", "positive", "1", "true"}
# Verdicts treated as a "blocked/flagged" positive prediction.
_POSITIVE_VERDICTS = {"malicious", "high_risk", "suspicious"}


def binarize_label(label: Any) -> int:
    """Map a ground-truth label to 1 (malicious) or 0 (benign)."""
    return 1 if str(label).strip().lower() in _POSITIVE_LABELS else 0


def _predicted_from_record(rec: dict[str, Any], threshold: float) -> int:
    """A record is a positive prediction if its verdict is flagged or score >= threshold."""
    verdict = str(rec.get("verdict", "")).strip().lower()
    if verdict:
        return 1 if verdict in _POSITIVE_VERDICTS else 0
    return 1 if float(rec.get("score", 0.0) or 0.0) >= threshold else 0


def confusion_counts(y_true: list[int], y_pred: list[int]) -> dict[str, int]:
    tp = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 1)
    fp = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 1)
    fn = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 0)
    tn = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 0)
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn}


def _prf(counts: dict[str, int]) -> dict[str, float]:
    tp, fp, fn, tn = counts["tp"], counts["fp"], counts["fn"], counts["tn"]
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    total = tp + fp + fn + tn
    accuracy = (tp + tn) / total if total else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    return {
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "accuracy": round(accuracy, 4),
        "false_positive_rate": round(fpr, 4),
    }


def expected_calibration_error(scores: list[float], labels: list[int], n_bins: int = 10) -> float:
    """ECE: average gap between predicted confidence and empirical accuracy per bin."""
    if not scores:
        return 0.0
    n = len(scores)
    total = 0.0
    for b in range(n_bins):
        lo, hi = b / n_bins, (b + 1) / n_bins
        # Include the right edge in the last bin.
        idx = [i for i, s in enumerate(scores) if (lo <= s < hi) or (b == n_bins - 1 and s == hi)]
        if not idx:
            continue
        avg_conf = sum(scores[i] for i in idx) / len(idx)
        avg_acc = sum(labels[i] for i in idx) / len(idx)
        total += (len(idx) / n) * abs(avg_conf - avg_acc)
    return round(total, 4)


def brier_score(scores: list[float], labels: list[int]) -> float:
    """Mean squared error between predicted probability and outcome (lower is better)."""
    if not scores:
        return 0.0
    return round(sum((s - y) ** 2 for s, y in zip(scores, labels)) / len(scores), 4)


def _auc(scores: list[float], labels: list[int]) -> dict[str, float | None]:
    """ROC and PR AUC, using sklearn when present, else returning None for unsupported cases."""
    if len(set(labels)) < 2:
        return {"roc_auc": None, "pr_auc": None}
    try:
        from sklearn.metrics import average_precision_score, roc_auc_score
        return {
            "roc_auc": round(float(roc_auc_score(labels, scores)), 4),
            "pr_auc": round(float(average_precision_score(labels, scores)), 4),
        }
    except Exception:
        return {"roc_auc": None, "pr_auc": None}


def _per_agent_metrics(records: list[dict[str, Any]], y_true: list[int], agent_threshold: float) -> dict[str, Any]:
    agents: dict[str, dict[str, int]] = {}
    for rec, t in zip(records, y_true):
        for name, score in (rec.get("agent_scores") or {}).items():
            pred = 1 if float(score) >= agent_threshold else 0
            c = agents.setdefault(name, {"tp": 0, "fp": 0, "fn": 0, "tn": 0})
            if pred and t:
                c["tp"] += 1
            elif pred and not t:
                c["fp"] += 1
            elif not pred and t:
                c["fn"] += 1
            else:
                c["tn"] += 1
    return {name: {**counts, **_prf(counts)} for name, counts in agents.items()}


def evaluate_corpus(
    records: Iterable[dict[str, Any]],
    threshold: float = 0.5,
    agent_threshold: float = 0.5,
) -> dict[str, Any]:
    """Compute the full evaluation report from labeled prediction records."""
    records = list(records)
    if not records:
        return {"status": "empty", "count": 0}

    y_true = [binarize_label(r.get("true_label")) for r in records]
    y_pred = [_predicted_from_record(r, threshold) for r in records]
    scores = [max(0.0, min(1.0, float(r.get("score", 0.0) or 0.0))) for r in records]

    counts = confusion_counts(y_true, y_pred)
    report = {
        "status": "ok",
        "count": len(records),
        "positives": sum(y_true),
        "negatives": len(y_true) - sum(y_true),
        "confusion_matrix": counts,
        "metrics": _prf(counts),
        "auc": _auc(scores, y_true),
        "calibration": {
            "expected_calibration_error": expected_calibration_error(scores, y_true),
            "brier_score": brier_score(scores, y_true),
        },
        "per_agent": _per_agent_metrics(records, y_true, agent_threshold),
        "threshold": threshold,
    }
    return report
