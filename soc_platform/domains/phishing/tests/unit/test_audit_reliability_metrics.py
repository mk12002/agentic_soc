"""Regression tests for audit reliability/calibration helpers."""

from __future__ import annotations

from soc_platform.domains.phishing.tools.run_eml_batch_audit import (
    _binary_reliability,
    _expected_calibration_error,
    _expected_label,
)


def test_expected_label_prefers_adjudicated_override() -> None:
    label, source = _expected_label(
        "/tmp/IEEE ICNPCV 2026 - PAYMENT REMINDER.eml",
        {"ieee icnpcv 2026 - payment reminder.eml": "benign"},
    )
    assert label == "benign"
    assert source == "adjudicated"


def test_binary_reliability_outputs_expected_fields() -> None:
    scores = [0.95, 0.9, 0.2, 0.1, 0.8, 0.3]
    labels = [1, 1, 0, 0, 1, 0]
    metrics = _binary_reliability(scores, labels)

    assert metrics["count"] == len(scores)
    assert metrics["precision"] is not None
    assert metrics["recall"] is not None
    assert metrics["f1"] is not None
    assert metrics["accuracy"] is not None
    assert metrics["brier"] is not None
    assert metrics["ece"] is not None


def test_expected_calibration_error_is_zero_for_perfect_bins() -> None:
    scores = [0.0, 0.0, 1.0, 1.0]
    labels = [0, 0, 1, 1]
    ece = _expected_calibration_error(scores, labels, bins=5)
    assert ece == 0.0
