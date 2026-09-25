#!/usr/bin/env python3
"""Validate end-to-end consistency of sandbox data, model artifacts, and production feature schema."""

from __future__ import annotations
from soc_platform.domains.phishing.engine.paths import PHISHING_HOME

import json
from datetime import datetime, timezone
from typing import Any

import joblib
import pandas as pd

REPO_ROOT = PHISHING_HOME
WORKSPACE_ROOT = REPO_ROOT.parent
pass  # (package import; no sys.path hack needed)
from soc_platform.domains.phishing.engine.preprocessing.sandbox_feature_contract import (
    SANDBOX_FEATURE_VERSION,
    SANDBOX_NUMERIC_FEATURE_COLUMNS,
)


def _ok(condition: bool, code: str, message: str, details: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "code": code,
        "status": "pass" if condition else "fail",
        "message": message,
        "details": details or {},
    }


def run_validation() -> dict[str, Any]:
    processed_dir = WORKSPACE_ROOT / "datasets_processed"
    training_csv = processed_dir / "sandbox_behavior_training.csv"
    audit_json = processed_dir / "sandbox_behavior_audit.json"
    runtime_csv = WORKSPACE_ROOT / "datasets" / "sandbox_behavior" / "runtime_observations.csv"

    model_dir = WORKSPACE_ROOT / "models" / "sandbox_agent"
    model_file = model_dir / "model.joblib"
    metrics_file = model_dir / "model_metrics.json"

    checks: list[dict[str, Any]] = []

    checks.append(_ok(training_csv.exists(), "training_csv_exists", "Processed sandbox training CSV exists."))
    checks.append(_ok(audit_json.exists(), "audit_json_exists", "Sandbox audit JSON exists."))

    if training_csv.exists():
        frame = pd.read_csv(training_csv, nrows=2000)
        missing = [col for col in SANDBOX_NUMERIC_FEATURE_COLUMNS if col not in frame.columns]
        checks.append(
            _ok(
                not missing,
                "training_has_contract_columns",
                "Training CSV includes required feature contract columns.",
                {"missing_columns": missing},
            )
        )
        checks.append(
            _ok(
                "label" in frame.columns and frame["label"].isin([0, 1]).all(),
                "training_label_binary",
                "Training labels are binary for sampled rows.",
            )
        )
        source_count = 0
        if "source" in frame.columns:
            source_col_full = pd.read_csv(training_csv, usecols=["source"], low_memory=False)
            source_count = int(source_col_full["source"].nunique())
        checks.append(
            _ok(
                source_count >= 3,
                "training_multi_source",
                "Training set includes multiple sandbox data sources.",
                {"source_count": source_count},
            )
        )

    if audit_json.exists():
        audit = json.loads(audit_json.read_text(encoding="utf-8"))
        checks.append(
            _ok(
                audit.get("feature_version") == SANDBOX_FEATURE_VERSION,
                "audit_feature_version_match",
                "Audit feature version matches current contract.",
                {
                    "audit_feature_version": audit.get("feature_version"),
                    "contract_feature_version": SANDBOX_FEATURE_VERSION,
                },
            )
        )
        checks.append(
            _ok(
                list(audit.get("feature_columns", [])) == SANDBOX_NUMERIC_FEATURE_COLUMNS,
                "audit_feature_columns_match",
                "Audit feature columns exactly match contract ordering.",
            )
        )

    if runtime_csv.exists() and runtime_csv.stat().st_size > 0:
        runtime = pd.read_csv(runtime_csv, nrows=500)
        runtime_missing = [col for col in SANDBOX_NUMERIC_FEATURE_COLUMNS if col not in runtime.columns]
        checks.append(
            _ok(
                not runtime_missing,
                "runtime_has_contract_columns",
                "Runtime observations include required feature contract columns.",
                {"missing_columns": runtime_missing},
            )
        )
    else:
        checks.append(
            _ok(
                True,
                "runtime_observations_optional",
                "Runtime observations file missing or empty; this is allowed before first detonation.",
            )
        )

    checks.append(_ok(model_file.exists(), "model_artifact_exists", "Sandbox model artifact exists."))
    checks.append(_ok(metrics_file.exists(), "model_metrics_exists", "Sandbox model metrics JSON exists."))

    if model_file.exists():
        bundle = joblib.load(model_file)
        features = list(bundle.get("features", [])) if isinstance(bundle, dict) else []
        threshold = bundle.get("threshold") if isinstance(bundle, dict) else None
        checks.append(
            _ok(
                features == SANDBOX_NUMERIC_FEATURE_COLUMNS,
                "model_feature_order_match",
                "Model bundle feature list matches contract exactly.",
                {"feature_count": len(features)},
            )
        )
        checks.append(
            _ok(
                isinstance(threshold, (int, float)) and 0.0 <= float(threshold) <= 1.0,
                "model_threshold_valid",
                "Model threshold is defined and valid in [0,1].",
                {"threshold": threshold},
            )
        )

    failures = [item for item in checks if item["status"] == "fail"]
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total_checks": len(checks),
            "passed": len(checks) - len(failures),
            "failed": len(failures),
            "status": "pass" if not failures else "fail",
        },
        "checks": checks,
    }


def main() -> int:
    report = run_validation()
    out_dir = REPO_ROOT / "analysis_reports" / f"sandbox_consistency_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / "consistency_report.json"
    out_file.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report["summary"], indent=2))
    print(str(out_file))
    return 0 if report["summary"]["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
