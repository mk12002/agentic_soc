"""Tests for canonical content preprocessing output schema and label normalization."""

from __future__ import annotations

from pathlib import Path

import pandas as pd

from soc_platform.domains.phishing.engine.preprocessing.content_preprocessing import run


def test_content_preprocessing_outputs_tri_class_schema(tmp_path: Path) -> None:
    base = tmp_path / "datasets"
    legit = base / "email_content" / "legitimate"
    spam = base / "email_content" / "spam"
    phish = base / "email_content" / "phishing"

    legit.mkdir(parents=True)
    spam.mkdir(parents=True)
    phish.mkdir(parents=True)

    # Plain text corpora per class.
    (legit / "l1.txt").write_text("Hi team, attached is the meeting agenda for tomorrow.", encoding="utf-8")
    (spam / "s1.txt").write_text("FREE SHIPPING and huge discount on watches, click now.", encoding="utf-8")
    (phish / "p1.txt").write_text("Your account is suspended. Verify password immediately.", encoding="utf-8")

    # Heterogeneous CSV schema with binary labels in phishing dataset.
    pd.DataFrame(
        {
            "subject": ["Security notice", "Weekly update"],
            "body": [
                "verify your account login now",
                "project notes and schedule for this week",
            ],
            "label": [1, 0],
        }
    ).to_csv(phish / "mixed_phish.csv", index=False)

    out_dir = tmp_path / "datasets_processed"
    run(base_dir=str(base), output_dir=str(out_dir))

    slm_path = out_dir / "content_training_slm.csv"
    feat_path = out_dir / "content_training.csv"

    assert slm_path.exists()
    assert feat_path.exists()

    slm_df = pd.read_csv(slm_path)
    feature_df = pd.read_csv(feat_path)

    assert list(slm_df.columns) == ["text", "label"]
    assert set(slm_df["label"].unique().tolist()) == {0, 1, 2}

    assert {"text", "word_count", "urgency_count", "url_count", "label"}.issubset(
        set(feature_df.columns)
    )
