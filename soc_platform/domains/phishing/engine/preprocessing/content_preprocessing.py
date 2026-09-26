"""Content-agent preprocessing with canonical text/label normalization."""

from __future__ import annotations

import json
import logging
import os
import quopri
import random
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import pandas as pd

from soc_platform.domains.phishing.engine.paths import PHISHING_HOME

from .feature_pipeline import build_content_features, write_processed_dataset

RANDOM_SEED = 42
WORKSPACE_ROOT = PHISHING_HOME
TARGET_SAMPLES_PER_CLASS = int(os.getenv("CONTENT_TARGET_SAMPLES_PER_CLASS", "12000"))
MAX_SAMPLES_PER_CLASS = int(os.getenv("CONTENT_MAX_SAMPLES_PER_CLASS", "60000"))
SKIP_CSV_SOURCES = os.getenv("CONTENT_SKIP_CSV", "0") == "1"
MAX_CSV_FILES_PER_CLASS = int(os.getenv("CONTENT_MAX_CSV_FILES_PER_CLASS", "0"))
MAX_ROWS_PER_CSV = int(os.getenv("CONTENT_MAX_ROWS_PER_CSV", "0"))

# Canonical 3-class labels used by content SLM
LABEL_LEGIT = 0
LABEL_SPAM = 1
LABEL_PHISH = 2

_TEXT_COL_CANDIDATES = (
    "text_combined",
    "message",
    "body",
    "content",
    "text",
    "email",
)

_LABEL_COL_CANDIDATES = ("label", "class", "target")

_HEADER_LINE_RE = re.compile(
    r"^(Message-ID|Date|From|To|Subject|Cc|Bcc|X-.*|Mime-Version|Content-Type|Content-Transfer-Encoding|Reply-To|Return-Path|Sent):",
    re.IGNORECASE,
)
_FORWARDED_MARKER_RE = re.compile(
    r"^(-----Original Message-----|Begin forwarded message:|Forwarded by\b|FW:|FWD:)",
    re.IGNORECASE,
)
_BASE64_LINE_RE = re.compile(r"^[A-Za-z0-9+/=]{160,}$")
_QPRINT_SOFT_BREAK_RE = re.compile(r"=\r?\n")
_QPRINT_HEX_RE = re.compile(r"=([A-Fa-f0-9]{2})")


def _normalize_space(value: str) -> str:
    return " ".join(str(value).split())


def _decode_quoted_printable(text: str) -> str:
    """Decode common quoted-printable artifacts seen in legacy email corpora."""
    raw = str(text)
    if "=" not in raw:
        return raw

    # Heuristic gate: only decode if clear quoted-printable markers are present.
    if not (_QPRINT_SOFT_BREAK_RE.search(raw) or _QPRINT_HEX_RE.search(raw)):
        return raw

    try:
        return quopri.decodestring(raw.encode("utf-8", errors="ignore")).decode(
            "utf-8", errors="ignore"
        )
    except Exception:
        return raw


def _clean_email_text(raw_text: str) -> str:
    """Strip obvious RFC-822 header artifacts and forwarded quote blocks."""
    decoded = _decode_quoted_printable(raw_text)
    lines = str(decoded).splitlines()
    cleaned: list[str] = []
    in_header = True

    for line in lines:
        stripped = line.strip()

        if in_header:
            if _HEADER_LINE_RE.match(line):
                continue
            if not stripped:
                in_header = False
                continue

        if _FORWARDED_MARKER_RE.match(stripped):
            continue
        if _HEADER_LINE_RE.match(stripped):
            continue
        # Drop long base64-like lines to avoid attachment payload leakage in text data.
        if _BASE64_LINE_RE.match(stripped):
            continue

        cleaned.append(line)
        in_header = False

    result = "\n".join(cleaned).strip()
    return result if result else str(raw_text).strip()


def _looks_like_noise_blob(text: str) -> bool:
    """Guardrail to reject mostly non-natural-language payloads."""
    if not text:
        return True
    sample = text[:4000]
    if len(sample) < 20:
        return True

    printable = sum(1 for ch in sample if ch.isprintable() or ch in "\n\t\r")
    printable_ratio = printable / max(1, len(sample))
    alpha_ratio = sum(1 for ch in sample if ch.isalpha()) / max(1, len(sample))

    # If there are almost no spaces and too many symbols, this is likely payload noise.
    space_ratio = sample.count(" ") / max(1, len(sample))
    symbol_ratio = sum(1 for ch in sample if not ch.isalnum() and not ch.isspace()) / max(1, len(sample))

    return (
        printable_ratio < 0.85
        or alpha_ratio < 0.20
        or (space_ratio < 0.03 and symbol_ratio > 0.25)
    )


def _map_native_label(raw_label: Any, default_label: int) -> int | None:
    """Map heterogeneous dataset labels into canonical 0/1/2 classes.

    `default_label` reflects the parent dataset folder semantics:
      0 legitimate, 1 spam, 2 phishing.
    """
    if raw_label is None or (isinstance(raw_label, float) and pd.isna(raw_label)):
        return default_label

    token = str(raw_label).strip().lower()
    if not token:
        return default_label

    textual_map = {
        "legitimate": LABEL_LEGIT,
        "legit": LABEL_LEGIT,
        "ham": LABEL_LEGIT,
        "benign": LABEL_LEGIT,
        "normal": LABEL_LEGIT,
        "safe": LABEL_LEGIT,
        "spam": LABEL_SPAM,
        "junk": LABEL_SPAM,
        "advertisement": LABEL_SPAM,
        "phishing": LABEL_PHISH,
        "phish": LABEL_PHISH,
        "fraud": LABEL_PHISH,
        "scam": LABEL_PHISH,
    }
    if token in textual_map:
        return textual_map[token]

    try:
        n = int(float(token))
    except Exception:
        return default_label

    # Preserve explicit tri-class labels when provided.
    if n in (0, 1, 2):
        if default_label == LABEL_PHISH:
            # In phishing corpora, binary labels usually mean 1=phish, 0=benign.
            if n == 1:
                return LABEL_PHISH
            if n == 0:
                return LABEL_LEGIT
            return LABEL_PHISH
        return n

    if n <= 0:
        return LABEL_LEGIT
    return default_label


def _resolve_text_from_row(row: pd.Series) -> str:
    cols = {str(c).lower(): c for c in row.index}

    subject = ""
    if "subject" in cols:
        subject = str(row[cols["subject"]] or "").strip()

    text_body = ""
    for key in _TEXT_COL_CANDIDATES:
        if key in cols:
            value = row[cols[key]]
            if value is not None and not (isinstance(value, float) and pd.isna(value)):
                text_body = str(value)
                break

    if not text_body:
        return ""

    if subject:
        return f"Subject: {subject}\n\n{text_body}"
    return text_body


def _collect_text_files(directory: Path, default_label: int) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not directory.exists():
        return rows

    for file_path in directory.rglob("*"):
        if not file_path.is_file():
            continue
        if file_path.suffix.lower() == ".csv":
            continue
        if file_path.name.lower() == "cmds":
            continue

        try:
            raw_text = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            logging.getLogger(__name__).warning("skipping an unreadable training file", exc_info=True)
            continue

        cleaned = _clean_email_text(raw_text)
        cleaned = _normalize_space(cleaned)
        if _looks_like_noise_blob(cleaned):
            continue

        rows.append(
            {
                "content": cleaned,
                "label": default_label,
                "source": str(file_path),
                "source_name": file_path.name,
            }
        )

    return rows


def _collect_csv_rows(csv_path: Path, default_label: int) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        read_kwargs: dict[str, Any] = {
            "encoding": "utf-8",
            "on_bad_lines": "skip",
            "low_memory": False,
        }
        if MAX_ROWS_PER_CSV > 0:
            read_kwargs["nrows"] = MAX_ROWS_PER_CSV
        frame = pd.read_csv(csv_path, **read_kwargs)
    except Exception:
        return rows

    if frame.empty:
        return rows

    cols_lower = {str(c).lower(): c for c in frame.columns}
    label_col = next((cols_lower[c] for c in _LABEL_COL_CANDIDATES if c in cols_lower), None)

    for _, rec in frame.iterrows():
        text = _resolve_text_from_row(rec)
        if not text:
            continue

        cleaned = _clean_email_text(text)
        cleaned = _normalize_space(cleaned)
        if _looks_like_noise_blob(cleaned):
            continue

        native_label = rec[label_col] if label_col else None
        mapped_label = _map_native_label(native_label, default_label)
        if mapped_label is None:
            continue

        rows.append(
            {
                "content": cleaned,
                "label": int(mapped_label),
                "source": str(csv_path),
                "source_name": csv_path.name,
            }
        )

    return rows


def _balance_three_classes(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    legit = [r for r in rows if r["label"] == LABEL_LEGIT]
    spam = [r for r in rows if r["label"] == LABEL_SPAM]
    phish = [r for r in rows if r["label"] == LABEL_PHISH]

    if not legit or not spam or not phish:
        return rows

    target = max(1, min(MAX_SAMPLES_PER_CLASS, TARGET_SAMPLES_PER_CLASS))
    random.seed(RANDOM_SEED)

    def _sample_to_target(bucket: list[dict[str, Any]]) -> list[dict[str, Any]]:
        if len(bucket) >= target:
            return random.sample(bucket, target)
        # Upsample minority classes with replacement so training doesn't collapse.
        return random.choices(bucket, k=target)

    balanced = _sample_to_target(legit) + _sample_to_target(spam) + _sample_to_target(phish)
    random.shuffle(balanced)
    return balanced


def _summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    by_label = Counter(int(item.get("label", -1)) for item in rows)
    by_source = Counter(str(item.get("source_name", "unknown")) for item in rows)

    by_label_source: dict[str, dict[str, int]] = defaultdict(dict)
    for row in rows:
        label = int(row.get("label", -1))
        source_name = str(row.get("source_name", "unknown"))
        current = by_label_source.setdefault(str(label), {})
        current[source_name] = current.get(source_name, 0) + 1

    return {
        "row_count": len(rows),
        "label_distribution": {str(k): int(v) for k, v in sorted(by_label.items())},
        "top_sources": dict(by_source.most_common(25)),
        "label_source_breakdown": by_label_source,
    }


def _resolve_input_dir(path_value: str) -> Path:
    path = Path(path_value)
    if path.is_absolute():
        return path
    if path.exists():
        return path
    return WORKSPACE_ROOT / path


def _resolve_output_dir(path_value: str) -> Path:
    path = Path(path_value)
    if path.is_absolute():
        return path
    return WORKSPACE_ROOT / path


def run(base_dir: str = "datasets", output_dir: str = "datasets_processed") -> str:
    """Build content datasets with canonical schema for both SLM and tabular features."""
    base = _resolve_input_dir(base_dir)
    output = _resolve_output_dir(output_dir)
    output.mkdir(parents=True, exist_ok=True)

    content_root = base / "email_content"
    class_dirs = [
        (content_root / "legitimate", LABEL_LEGIT),
        (content_root / "spam", LABEL_SPAM),
        (content_root / "phishing", LABEL_PHISH),
    ]

    all_rows: list[dict[str, Any]] = []
    for class_dir, default_label in class_dirs:
        all_rows.extend(_collect_text_files(class_dir, default_label))
        if SKIP_CSV_SOURCES:
            continue

        csv_files = sorted(class_dir.rglob("*.csv"))
        if MAX_CSV_FILES_PER_CLASS > 0:
            csv_files = csv_files[:MAX_CSV_FILES_PER_CLASS]

        for csv_file in csv_files:
            all_rows.extend(_collect_csv_rows(csv_file, default_label))

    pre_balance_summary = _summarize(all_rows)
    all_rows = _balance_three_classes(all_rows)
    post_balance_summary = _summarize(all_rows)

    # Canonical SLM dataset expected by content model training.
    slm_df = pd.DataFrame(all_rows)
    if slm_df.empty:
        slm_df = pd.DataFrame(columns=["text", "label"])
    else:
        slm_df = slm_df[["content", "label"]].rename(columns={"content": "text"})
        slm_df = slm_df.dropna(subset=["text", "label"])
        slm_df["text"] = slm_df["text"].astype(str)
        slm_df["label"] = slm_df["label"].astype(int)
        slm_df = slm_df[slm_df["text"].str.len() >= 16].reset_index(drop=True)

    label_set = set(slm_df["label"].unique().tolist()) if not slm_df.empty else set()
    if label_set and label_set != {LABEL_LEGIT, LABEL_SPAM, LABEL_PHISH}:
        raise ValueError(
            "Content preprocessing failed tri-class guarantee. "
            f"Expected labels {{0,1,2}}, got {sorted(label_set)}"
        )

    write_processed_dataset(slm_df, output / "content_training_slm.csv")

    # Backward-compatible enriched dataset used by existing scripts.
    feature_df = build_content_features(all_rows)
    content_csv = write_processed_dataset(feature_df, output / "content_training.csv")

    audit_payload = {
        "base_dir": str(base),
        "output_dir": str(output),
        "balancing": {
            "target_samples_per_class": TARGET_SAMPLES_PER_CLASS,
            "max_samples_per_class": MAX_SAMPLES_PER_CLASS,
        },
        "ingestion_limits": {
            "skip_csv_sources": SKIP_CSV_SOURCES,
            "max_csv_files_per_class": MAX_CSV_FILES_PER_CLASS,
            "max_rows_per_csv": MAX_ROWS_PER_CSV,
        },
        "pre_balance": pre_balance_summary,
        "post_balance": post_balance_summary,
        "canonical_slm": {
            "path": str(output / "content_training_slm.csv"),
            "rows": len(slm_df),
            "columns": list(slm_df.columns),
            "label_distribution": (
                {str(k): int(v) for k, v in slm_df["label"].value_counts().to_dict().items()}
                if not slm_df.empty
                else {}
            ),
        },
    }
    (output / "content_training_audit.json").write_text(
        json.dumps(audit_payload, indent=2),
        encoding="utf-8",
    )
    return content_csv


if __name__ == "__main__":
    out = run(base_dir="datasets", output_dir="datasets_processed")
    print(out)
