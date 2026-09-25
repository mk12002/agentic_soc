"""Deep EDA for processed URL training data."""

from __future__ import annotations
from soc_platform.domains.phishing.engine.paths import PHISHING_HOME

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd


REPO_ROOT = PHISHING_HOME
pass  # (package import; no sys.path hack needed)
from soc_platform.domains.phishing.engine.preprocessing.feature_pipeline import URL_FEATURE_COLUMNS

PROCESSED_CSV = REPO_ROOT.parent / "datasets_processed" / "url_training.csv"
OUTPUT_ROOT = REPO_ROOT / "analysis_reports"
MAX_PLOT_ROWS = 250000


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


def _sample_for_plot(df: pd.DataFrame, max_rows: int = MAX_PLOT_ROWS) -> pd.DataFrame:
    if len(df) <= max_rows:
        return df.copy()

    per_class = max(1, max_rows // 2)
    pieces = []
    for label in (0, 1):
        part = df[df["label"] == label]
        take = min(len(part), per_class)
        pieces.append(part.sample(n=take, random_state=42) if take > 0 else part)

    sampled = pd.concat(pieces, ignore_index=True)
    return sampled.sample(frac=1.0, random_state=42).reset_index(drop=True)


def _extract_tld(url: str) -> str:
    host = (urlsplit(str(url)).hostname or "").lower()
    if not host:
        return "unknown"
    labels = [segment for segment in host.split(".") if segment]
    if not labels:
        return "unknown"
    if len(labels) == 1:
        return labels[0]
    return labels[-1]


def _plot_class_balance(df: pd.DataFrame, out_file: Path) -> None:
    counts = df["label"].value_counts().sort_index()
    labels = ["Benign" if value == 0 else "Malicious" for value in counts.index]
    fig, ax = plt.subplots(figsize=(7, 5))
    ax.bar(labels, counts.values, color=["#4CAF50", "#F44336"])
    ax.set_title("URL Dataset Class Balance")
    ax.set_ylabel("Rows")
    fig.tight_layout()
    fig.savefig(out_file)
    plt.close(fig)


def _plot_feature_grid(df: pd.DataFrame, out_file: Path) -> None:
    selected = [
        "url_length",
        "host_length",
        "path_length",
        "special_char_count",
        "host_entropy",
        "suspicious_token_count",
    ]
    selected = [col for col in selected if col in df.columns]
    if not selected:
        return

    fig, axes = plt.subplots(2, 3, figsize=(15, 9))
    axes = axes.flatten()
    benign = df[df["label"] == 0]
    malicious = df[df["label"] == 1]

    for idx, col in enumerate(selected):
        ax = axes[idx]
        q99 = float(df[col].quantile(0.99))
        benign_vals = benign[benign[col] <= q99][col]
        malicious_vals = malicious[malicious[col] <= q99][col]
        ax.hist(benign_vals, bins=60, alpha=0.55, color="#4CAF50", label="Benign")
        ax.hist(malicious_vals, bins=60, alpha=0.55, color="#F44336", label="Malicious")
        ax.set_title(col)
        ax.legend()

    for idx in range(len(selected), len(axes)):
        axes[idx].axis("off")

    fig.suptitle("URL Feature Distributions (clipped at p99)")
    fig.tight_layout()
    fig.savefig(out_file)
    plt.close(fig)


def _plot_correlation(df: pd.DataFrame, out_file: Path) -> None:
    numeric_cols = [col for col in URL_FEATURE_COLUMNS if col in df.columns]
    if not numeric_cols:
        return

    corr = df[numeric_cols + ["label"]].corr(numeric_only=True)
    fig, ax = plt.subplots(figsize=(14, 12))
    im = ax.imshow(corr.values, cmap="coolwarm", vmin=-1, vmax=1)
    ax.set_xticks(range(len(corr.columns)))
    ax.set_yticks(range(len(corr.columns)))
    ax.set_xticklabels(corr.columns, rotation=90)
    ax.set_yticklabels(corr.columns)
    fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04)
    ax.set_title("Feature Correlation Matrix")
    fig.tight_layout()
    fig.savefig(out_file)
    plt.close(fig)


def _plot_top_tlds(df: pd.DataFrame, out_file: Path) -> None:
    benign_tlds = Counter(_extract_tld(url) for url in df[df["label"] == 0]["url"].astype(str).tolist())
    malicious_tlds = Counter(_extract_tld(url) for url in df[df["label"] == 1]["url"].astype(str).tolist())

    top = sorted(set([key for key, _ in benign_tlds.most_common(15)] + [key for key, _ in malicious_tlds.most_common(15)]))
    if not top:
        return

    benign_vals = [benign_tlds.get(tld, 0) for tld in top]
    malicious_vals = [malicious_tlds.get(tld, 0) for tld in top]

    x = np.arange(len(top))
    width = 0.4
    fig, ax = plt.subplots(figsize=(16, 6))
    ax.bar(x - width / 2, benign_vals, width=width, color="#4CAF50", label="Benign")
    ax.bar(x + width / 2, malicious_vals, width=width, color="#F44336", label="Malicious")
    ax.set_xticks(x)
    ax.set_xticklabels(top, rotation=70)
    ax.set_ylabel("Count")
    ax.set_title("Top TLD Distribution by Class")
    ax.legend()
    fig.tight_layout()
    fig.savefig(out_file)
    plt.close(fig)


def main() -> None:
    if not PROCESSED_CSV.exists():
        raise FileNotFoundError(f"URL processed dataset not found: {PROCESSED_CSV}")

    out_dir = OUTPUT_ROOT / f"url_eda_{_stamp()}"
    out_dir.mkdir(parents=True, exist_ok=True)

    df = pd.read_csv(PROCESSED_CSV, low_memory=False)
    required = {"url", "label"}
    if not required.issubset(df.columns):
        raise RuntimeError(f"Missing required columns in {PROCESSED_CSV}: {required - set(df.columns)}")

    df["label"] = pd.to_numeric(df["label"], errors="coerce").fillna(-1).astype(int)
    df = df[df["label"].isin([0, 1])].copy()

    missing_features = [col for col in URL_FEATURE_COLUMNS if col not in df.columns]
    for col in URL_FEATURE_COLUMNS:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0.0)

    plot_df = _sample_for_plot(df)

    _plot_class_balance(df, out_dir / "class_balance.png")
    _plot_feature_grid(plot_df, out_dir / "feature_distributions.png")
    _plot_correlation(plot_df, out_dir / "feature_correlation.png")
    _plot_top_tlds(df, out_dir / "top_tlds_by_class.png")

    summary = {
        "dataset_path": str(PROCESSED_CSV),
        "rows": int(len(df)),
        "unique_urls": int(df["url"].nunique()),
        "duplicate_urls": int(len(df) - df["url"].nunique()),
        "label_distribution": {str(k): int(v) for k, v in df["label"].value_counts().sort_index().to_dict().items()},
        "missing_feature_columns": missing_features,
        "missing_values": {col: int(value) for col, value in df.isna().sum().to_dict().items()},
        "numeric_feature_summary": {
            col: {
                "mean": float(df[col].mean()),
                "std": float(df[col].std()),
                "p50": float(df[col].quantile(0.50)),
                "p95": float(df[col].quantile(0.95)),
                "p99": float(df[col].quantile(0.99)),
            }
            for col in URL_FEATURE_COLUMNS
            if col in df.columns
        },
    }

    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")

    report_lines = [
        "URL Dataset EDA Summary",
        "=======================",
        "",
        f"Dataset: {PROCESSED_CSV}",
        f"Rows: {len(df):,}",
        f"Unique URLs: {df['url'].nunique():,}",
        f"Duplicate URLs: {len(df) - df['url'].nunique():,}",
        f"Label distribution: {summary['label_distribution']}",
        f"Missing feature columns: {missing_features if missing_features else 'None'}",
        "",
        "Generated plots:",
        "- class_balance.png",
        "- feature_distributions.png",
        "- feature_correlation.png",
        "- top_tlds_by_class.png",
    ]
    (out_dir / "report.txt").write_text("\n".join(report_lines), encoding="utf-8")

    print(f"URL EDA report generated at: {out_dir}")


if __name__ == "__main__":
    main()
