"""Tests for the ground-truth evaluation metrics (#4) and calibration metrics (#5)."""

from __future__ import annotations

from soc_platform.domains.phishing.engine.orchestrator.evaluation import (
    binarize_label,
    brier_score,
    confusion_counts,
    evaluate_corpus,
    expected_calibration_error,
)


def test_binarize_label() -> None:
    assert binarize_label("phishing") == 1
    assert binarize_label("Malicious") == 1
    assert binarize_label("safe") == 0
    assert binarize_label("legitimate") == 0


def test_confusion_counts_exact() -> None:
    y_true = [1, 1, 0, 0]
    y_pred = [1, 0, 1, 0]
    c = confusion_counts(y_true, y_pred)
    assert c == {"tp": 1, "fp": 1, "fn": 1, "tn": 1}


def test_perfect_classifier_metrics() -> None:
    records = [
        {"score": 0.95, "true_label": "phishing"},
        {"score": 0.90, "true_label": "malicious"},
        {"score": 0.05, "true_label": "safe"},
        {"score": 0.10, "true_label": "safe"},
    ]
    report = evaluate_corpus(records)
    m = report["metrics"]
    assert m["precision"] == 1.0
    assert m["recall"] == 1.0
    assert m["f1"] == 1.0
    assert report["confusion_matrix"] == {"tp": 2, "fp": 0, "fn": 0, "tn": 2}
    # Both classes present -> AUC computed.
    assert report["auc"]["roc_auc"] == 1.0


def test_calibration_metrics_bounds() -> None:
    # Well-calibrated extremes: confident and correct -> low ECE/Brier.
    scores = [0.99, 0.98, 0.02, 0.01]
    labels = [1, 1, 0, 0]
    assert expected_calibration_error(scores, labels) < 0.1
    assert brier_score(scores, labels) < 0.05
    # Confident but wrong -> high Brier.
    assert brier_score([0.99, 0.99], [0, 0]) > 0.9


def test_per_agent_metrics() -> None:
    records = [
        {"score": 0.8, "true_label": "phishing", "agent_scores": {"url_agent": 0.9, "header_agent": 0.2}},
        {"score": 0.1, "true_label": "safe", "agent_scores": {"url_agent": 0.1, "header_agent": 0.1}},
    ]
    report = evaluate_corpus(records)
    per_agent = report["per_agent"]
    # url_agent flagged the phishing one and stayed quiet on the safe one -> perfect here.
    assert per_agent["url_agent"]["recall"] == 1.0
    assert per_agent["url_agent"]["false_positive_rate"] == 0.0
    # header_agent missed the phishing one -> recall 0.
    assert per_agent["header_agent"]["recall"] == 0.0


def test_verdict_used_when_present() -> None:
    # Verdict overrides the score threshold for the prediction.
    records = [
        {"score": 0.3, "verdict": "malicious", "true_label": "phishing"},
        {"score": 0.6, "verdict": "safe", "true_label": "safe"},
    ]
    report = evaluate_corpus(records)
    assert report["confusion_matrix"] == {"tp": 1, "fp": 0, "fn": 0, "tn": 1}


def test_empty_corpus() -> None:
    assert evaluate_corpus([])["status"] == "empty"
