"""
Ground-truth evaluation harness (CLI).

Reads a labeled corpus of prediction records (JSONL) and prints/saves the standard
detection-quality report: precision/recall/F1, confusion matrix, ROC/PR AUC, and
calibration (ECE + Brier), plus per-agent metrics. The metric logic lives in
``src.orchestrator.evaluation`` so it is unit-testable without the agent stack.

Each JSONL line:
    {"score": 0.0-1.0, "true_label": "phishing"|"safe", "verdict": "malicious"|...,
     "agent_scores": {"url_agent": 0.8, ...}}

Usage:
    python -m tools.evaluate_pipeline --input corpus.jsonl --output report.json
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

# Ensure the package root is importable when run as a script.
# (package import; no sys.path hack needed)
from soc_platform.domains.phishing.engine.orchestrator.evaluation import evaluate_corpus


def load_records(path: str | Path) -> list[dict]:
    records: list[dict] = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate detection pipeline against a labeled corpus.")
    parser.add_argument("--input", required=True, help="Path to JSONL corpus of prediction records.")
    parser.add_argument("--output", help="Optional path to write the JSON report.")
    parser.add_argument("--threshold", type=float, default=0.5, help="Score threshold for the positive class.")
    args = parser.parse_args(argv)

    records = load_records(args.input)
    report = evaluate_corpus(records, threshold=args.threshold)

    text = json.dumps(report, indent=2)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
