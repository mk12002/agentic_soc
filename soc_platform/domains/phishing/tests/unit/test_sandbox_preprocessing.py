"""Tests for sandbox preprocessing data normalization."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pandas as pd

from soc_platform.domains.phishing.engine.preprocessing.sandbox_preprocessing import run


def test_sandbox_preprocessing_merges_sources(tmp_path: Path) -> None:
    base = tmp_path / "datasets"
    out = tmp_path / "datasets_processed"

    sandbox_dir = base / "sandbox_behavior"
    sandbox_dir.mkdir(parents=True)

    pd.DataFrame(
        [
            {
                "sample_id": "legacy_1",
                "file_extension": ".pdf",
                "executed": 1,
                "return_code": 0,
                "timed_out": 0,
                "spawned_processes": 1,
                "suspicious_process_count": 0,
                "file_entropy": 5.2,
                "label": 0,
            }
        ]
    ).to_csv(sandbox_dir / "sandbox_logs.csv", index=False)

    api_dir = sandbox_dir / "api_sequences"
    api_dir.mkdir(parents=True)
    pd.DataFrame(
        [
            {
                "sample_id": "api_1",
                "api_sequence": "CreateProcessW connect WriteFile",
                "label": "malware",
            }
        ]
    ).to_csv(api_dir / "oliveira_like.csv", index=False)

    cuckoo_dir = sandbox_dir / "cuckoo_reports"
    cuckoo_dir.mkdir(parents=True)
    report = {
        "info": {"score": 8.5},
        "target": {"file": {"name": "invoice.pdf", "entropy": 6.7}},
        "behavior": {
            "processes": [{"process_name": "invoice.pdf"}, {"process_name": "sh"}],
            "summary": {
                "connects": ["1.2.3.4"],
                "write_files": ["/tmp/a"],
                "executed_commands": ["/bin/sh -c curl http://x.y"]
            },
        },
        "network": {"hosts": ["1.2.3.4"], "http": [{"uri": "/"}]},
    }
    (cuckoo_dir / "report_1.json").write_text(json.dumps(report), encoding="utf-8")

    os.environ["SANDBOX_INCLUDE_SYNTHETIC_LOGS"] = "1"
    output_path = Path(run(base_dir=str(base), output_dir=str(out)))
    os.environ.pop("SANDBOX_INCLUDE_SYNTHETIC_LOGS", None)

    assert output_path.exists()
    frame = pd.read_csv(output_path)
    assert frame.shape[0] == 3
    assert {"sandbox_logs", "api_sequences", "cuckoo_reports"}.issubset(set(frame["source"].tolist()))
    assert {"connect_calls", "execve_calls", "file_write_calls", "label"}.issubset(set(frame.columns))

    audit_path = out / "sandbox_behavior_audit.json"
    assert audit_path.exists()


def test_runtime_observations_can_feed_training_with_pseudo_labels(tmp_path: Path) -> None:
    base = tmp_path / "datasets"
    out = tmp_path / "datasets_processed"

    api_dir = base / "sandbox_behavior" / "api_sequences"
    api_dir.mkdir(parents=True)
    pd.DataFrame(
        [
            {
                "hash": "oliveira_1",
                "t_0": 12,
                "t_1": 44,
                "malware": 1,
            }
        ]
    ).to_csv(api_dir / "dynamic_api_call_sequence_per_malware_100_0_306.csv", index=False)

    runtime_path = base / "sandbox_behavior" / "runtime_observations.csv"
    pd.DataFrame(
        [
            {
                "sample_id": "runtime_1",
                "file_extension": ".exe",
                "executed": 1,
                "return_code": 0,
                "timed_out": 0,
                "spawned_processes": 2,
                "suspicious_process_count": 2,
                "file_entropy": 6.8,
                "connect_calls": 1,
                "execve_calls": 2,
                "file_write_calls": 1,
                "sequence_length": 4,
                "sequence_process_calls": 2,
                "sequence_network_calls": 1,
                "sequence_filesystem_calls": 1,
                "sequence_registry_calls": 0,
                "sequence_memory_calls": 0,
                "critical_chain_detected": 1,
                "behavior_risk_score": 0.92,
                "pseudo_label": 1,
                "label": "",
            }
        ]
    ).to_csv(runtime_path, index=False)

    os.environ["SANDBOX_USE_PSEUDO_LABELS"] = "1"
    output_path = Path(run(base_dir=str(base), output_dir=str(out)))
    os.environ.pop("SANDBOX_USE_PSEUDO_LABELS", None)

    frame = pd.read_csv(output_path)
    runtime_rows = frame[frame["source"] == "runtime_detonation"]
    assert not runtime_rows.empty
    assert int(runtime_rows.iloc[0]["label"]) == 1
    assert {"critical_chain_detected", "behavior_risk_score"}.issubset(set(frame.columns))
