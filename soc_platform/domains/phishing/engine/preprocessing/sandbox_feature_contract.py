"""Shared sandbox feature contract used by training and production pipelines."""

from __future__ import annotations

from typing import Any

import pandas as pd

SANDBOX_FEATURE_VERSION = "v1"

# Numeric features expected by sandbox model training/inference.
SANDBOX_NUMERIC_FEATURE_COLUMNS = [
    "executed",
    "return_code",
    "timed_out",
    "spawned_processes",
    "suspicious_process_count",
    "file_entropy",
    "connect_calls",
    "execve_calls",
    "file_write_calls",
    "sequence_length",
    "sequence_process_calls",
    "sequence_network_calls",
    "sequence_filesystem_calls",
    "sequence_registry_calls",
    "sequence_memory_calls",
    "critical_chain_detected",
    "behavior_risk_score",
]


def _as_int(value: object, default: int = 0) -> int:
    try:
        if value is None:
            return default
        return int(float(str(value).strip()))
    except (TypeError, ValueError):
        return default


def _as_float(value: object, default: float = 0.0) -> float:
    try:
        if value is None:
            return default
        return float(str(value).strip())
    except (TypeError, ValueError):
        return default


def build_numeric_feature_map(row: dict[str, Any]) -> dict[str, float]:
    """Convert a raw sandbox row into the standard numeric feature map."""
    return {
        "executed": float(_as_int(row.get("executed"), 0)),
        "return_code": float(_as_int(row.get("return_code"), 0)),
        "timed_out": float(_as_int(row.get("timed_out"), 0)),
        "spawned_processes": float(_as_int(row.get("spawned_processes"), 0)),
        "suspicious_process_count": float(_as_int(row.get("suspicious_process_count"), 0)),
        "file_entropy": float(_as_float(row.get("file_entropy"), 0.0)),
        "connect_calls": float(_as_int(row.get("connect_calls"), 0)),
        "execve_calls": float(_as_int(row.get("execve_calls"), 0)),
        "file_write_calls": float(_as_int(row.get("file_write_calls"), 0)),
        "sequence_length": float(_as_int(row.get("sequence_length"), 0)),
        "sequence_process_calls": float(_as_int(row.get("sequence_process_calls"), 0)),
        "sequence_network_calls": float(_as_int(row.get("sequence_network_calls"), 0)),
        "sequence_filesystem_calls": float(_as_int(row.get("sequence_filesystem_calls"), 0)),
        "sequence_registry_calls": float(_as_int(row.get("sequence_registry_calls"), 0)),
        "sequence_memory_calls": float(_as_int(row.get("sequence_memory_calls"), 0)),
        "critical_chain_detected": float(_as_int(row.get("critical_chain_detected"), 0)),
        "behavior_risk_score": float(_as_float(row.get("behavior_risk_score"), 0.0)),
    }


def ensure_numeric_feature_frame(frame: pd.DataFrame) -> pd.DataFrame:
    """Add missing sandbox numeric columns and force float dtype for model readiness."""
    for col in SANDBOX_NUMERIC_FEATURE_COLUMNS:
        if col not in frame.columns:
            frame[col] = 0.0

    frame[SANDBOX_NUMERIC_FEATURE_COLUMNS] = (
        frame[SANDBOX_NUMERIC_FEATURE_COLUMNS]
        .replace([float("inf"), float("-inf")], 0.0)
        .fillna(0.0)
        .astype(float)
    )
    return frame
