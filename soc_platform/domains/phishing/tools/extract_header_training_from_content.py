#!/usr/bin/env python3
"""Build header-model training data from datasets/email_content sources.

Produces engineered header features expected by train_header_model.py:
    spf_pass, dkim_pass, dmarc_pass, sender_domain_len,
    display_name_mismatch, hop_count, reply_to_mismatch,
    sender_domain_entropy, label

Sources used:
1) Raw message files under legitimate/ and spam/ (parsed as RFC822)
2) Phishing CSV files under phishing/ (sender-based fallback features)

Notes:
- Some phishing CSVs do not include full headers (Authentication-Results/Received).
  For those rows, auth-related features default to 0 and hop_count to 1.
"""

from __future__ import annotations

import argparse
import json
import logging
import math
from datetime import UTC, datetime
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from pathlib import Path

import pandas as pd

from soc_platform.domains.phishing.engine.paths import PHISHING_HOME

WORKSPACE_ROOT = PHISHING_HOME
TRUSTED_KEYWORDS = ("microsoft", "google", "paypal", "amazon", "apple")
PHISHING_SENDER_COLUMNS = (
    "sender",
    "from",
    "from_email",
    "sender_email",
)


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    probs = [text.count(ch) / len(text) for ch in set(text)]
    return -sum(p * math.log2(p) for p in probs)


def _domain_from_address(address: str) -> str:
    parsed = parseaddr(address or "")[1]
    if "@" not in parsed:
        return ""
    return parsed.split("@", 1)[1].strip().lower()


def _display_mismatch(from_header: str, sender_domain: str) -> float:
    display_name = parseaddr(from_header or "")[0].strip().lower()
    if not display_name:
        return 0.0
    for keyword in TRUSTED_KEYWORDS:
        if keyword in display_name and keyword not in sender_domain:
            return 1.0
    return 0.0


def _build_features(
    auth_results: str,
    sender: str,
    from_header: str,
    reply_to: str,
    hop_count: int,
    label: int,
) -> dict[str, float | int]:
    auth_l = (auth_results or "").lower()
    sender_domain = _domain_from_address(sender) or _domain_from_address(from_header)
    reply_domain = _domain_from_address(reply_to)

    return {
        "spf_pass": 1.0 if "spf=pass" in auth_l else 0.0,
        "dkim_pass": 1.0 if "dkim=pass" in auth_l else 0.0,
        "dmarc_pass": 1.0 if "dmarc=pass" in auth_l else 0.0,
        "sender_domain_len": float(len(sender_domain)),
        "display_name_mismatch": _display_mismatch(from_header, sender_domain),
        "hop_count": float(max(1, hop_count)),
        "reply_to_mismatch": 1.0
        if (reply_domain and sender_domain and reply_domain != sender_domain)
        else 0.0,
        "sender_domain_entropy": float(round(_entropy(sender_domain), 4)),
        "label": int(label),
    }


def _extract_from_message_file(path: Path, label: int) -> dict[str, float | int] | None:
    try:
        blob = path.read_bytes()
    except Exception:
        return None

    try:
        msg = BytesParser(policy=policy.default).parsebytes(blob)
    except Exception:
        return None

    auth_values = msg.get_all("Authentication-Results", []) or []
    auth_results = " ".join(str(v) for v in auth_values)
    sender = str(msg.get("Sender", "") or msg.get("From", ""))
    from_header = str(msg.get("From", "") or "")
    reply_to = str(msg.get("Reply-To", "") or "")
    received = msg.get_all("Received", []) or []

    return _build_features(
        auth_results=auth_results,
        sender=sender,
        from_header=from_header,
        reply_to=reply_to,
        hop_count=len(received),
        label=label,
    )


def _sample_dataframe(df: pd.DataFrame, cap: int, seed: int) -> pd.DataFrame:
    if cap <= 0 or len(df) <= cap:
        return df
    return df.sample(n=cap, random_state=seed)


def _extract_from_phishing_csv(
    phishing_dir: Path,
    max_rows_per_csv: int,
    seed: int,
) -> list[dict[str, float | int]]:
    rows: list[dict[str, float | int]] = []

    csv_files = sorted(phishing_dir.rglob("*.csv"))
    for csv_path in csv_files:
        try:
            frame = pd.read_csv(csv_path, low_memory=False)
        except Exception:
            logging.getLogger(__name__).warning("skipping an unreadable CSV", exc_info=True)
            continue

        if frame.empty:
            continue

        sender_col = next((c for c in PHISHING_SENDER_COLUMNS if c in frame.columns), None)
        if sender_col is None:
            continue

        frame = frame[[sender_col]].dropna()
        frame = frame[frame[sender_col].astype(str).str.contains("@", na=False)]
        if frame.empty:
            continue

        frame = _sample_dataframe(frame, max_rows_per_csv, seed)

        for sender in frame[sender_col].astype(str):
            rows.append(
                _build_features(
                    auth_results="",
                    sender=sender,
                    from_header=sender,
                    reply_to="",
                    hop_count=1,
                    label=1,
                )
            )

    return rows


def _extract_from_folder(folder: Path, label: int) -> list[dict[str, float | int]]:
    rows: list[dict[str, float | int]] = []
    for file_path in folder.rglob("*"):
        if not file_path.is_file():
            continue
        item = _extract_from_message_file(file_path, label=label)
        if item is not None:
            rows.append(item)
    return rows


def _balance_binary(df: pd.DataFrame, seed: int) -> pd.DataFrame:
    if df.empty:
        return df

    counts = df["label"].value_counts().to_dict()
    if 0 not in counts or 1 not in counts:
        return df

    target = min(counts[0], counts[1])
    neg = df[df["label"] == 0].sample(n=target, random_state=seed)
    pos = df[df["label"] == 1].sample(n=target, random_state=seed)
    return pd.concat([neg, pos], axis=0).sample(frac=1.0, random_state=seed).reset_index(drop=True)


def build_dataset(
    content_dir: Path,
    output_csv: Path,
    max_rows_per_phishing_csv: int,
    seed: int,
    balance: bool,
) -> dict[str, object]:
    legitimate_dir = content_dir / "legitimate"
    spam_dir = content_dir / "spam"
    phishing_dir = content_dir / "phishing"

    legitimate_rows = _extract_from_folder(legitimate_dir, label=0) if legitimate_dir.exists() else []
    spam_rows = _extract_from_folder(spam_dir, label=1) if spam_dir.exists() else []
    phishing_rows = (
        _extract_from_phishing_csv(phishing_dir, max_rows_per_phishing_csv, seed)
        if phishing_dir.exists()
        else []
    )

    all_rows = legitimate_rows + spam_rows + phishing_rows
    frame = pd.DataFrame(all_rows)

    for col in (
        "spf_pass",
        "dkim_pass",
        "dmarc_pass",
        "sender_domain_len",
        "display_name_mismatch",
        "hop_count",
        "reply_to_mismatch",
        "sender_domain_entropy",
        "label",
    ):
        if col not in frame.columns:
            frame[col] = 0.0 if col != "label" else 0

    frame = frame[
        [
            "spf_pass",
            "dkim_pass",
            "dmarc_pass",
            "sender_domain_len",
            "display_name_mismatch",
            "hop_count",
            "reply_to_mismatch",
            "sender_domain_entropy",
            "label",
        ]
    ]

    before_balance = len(frame)
    if balance:
        frame = _balance_binary(frame, seed)

    output_csv.parent.mkdir(parents=True, exist_ok=True)
    frame.to_csv(output_csv, index=False)

    stats = {
        "timestamp": datetime.now(UTC).isoformat(),
        "content_dir": str(content_dir),
        "output_csv": str(output_csv),
        "counts": {
            "legitimate_rows": len(legitimate_rows),
            "spam_rows": len(spam_rows),
            "phishing_rows": len(phishing_rows),
            "total_before_balance": before_balance,
            "total_after_balance": len(frame),
        },
        "label_distribution": frame["label"].value_counts().to_dict(),
        "settings": {
            "max_rows_per_phishing_csv": max_rows_per_phishing_csv,
            "seed": seed,
            "balance": balance,
        },
    }

    audit_path = output_csv.with_name(output_csv.stem + "_audit.json")
    audit_path.write_text(json.dumps(stats, indent=2), encoding="utf-8")
    return stats


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Extract header training features from content datasets")
    parser.add_argument(
        "--content-dir",
        type=Path,
        default=WORKSPACE_ROOT / "datasets" / "email_content",
        help="Path to datasets/email_content directory",
    )
    parser.add_argument(
        "--output-csv",
        type=Path,
        default=WORKSPACE_ROOT / "datasets" / "email_content" / "header_training_extracted.csv",
        help="Output CSV path",
    )
    parser.add_argument(
        "--max-rows-per-phishing-csv",
        type=int,
        default=25000,
        help="Max sampled rows per phishing CSV source",
    )
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument(
        "--no-balance",
        action="store_true",
        help="Disable binary class balancing",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    stats = build_dataset(
        content_dir=args.content_dir,
        output_csv=args.output_csv,
        max_rows_per_phishing_csv=args.max_rows_per_phishing_csv,
        seed=args.seed,
        balance=not args.no_balance,
    )
    print(json.dumps(stats, indent=2))


if __name__ == "__main__":
    main()
