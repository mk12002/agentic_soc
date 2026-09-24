"""Sandbox behavior preprocessing for sequence and dynamic-report datasets."""

from __future__ import annotations
from soc_platform.domains.phishing.engine.paths import PHISHING_HOME

import json
import math
import os
import re
from collections import Counter
from hashlib import sha1
from pathlib import Path

import pandas as pd

from soc_platform.domains.phishing.engine.configs.settings import settings

try:
    from .sandbox_feature_contract import (
        SANDBOX_FEATURE_VERSION,
        SANDBOX_NUMERIC_FEATURE_COLUMNS,
        build_numeric_feature_map,
        ensure_numeric_feature_frame,
    )
except ImportError:
    try:
        from soc_platform.domains.phishing.engine.preprocessing.sandbox_feature_contract import (
            SANDBOX_FEATURE_VERSION,
            SANDBOX_NUMERIC_FEATURE_COLUMNS,
            build_numeric_feature_map,
            ensure_numeric_feature_frame,
        )
    except ImportError:
        from soc_platform.domains.phishing.engine.preprocessing.sandbox_feature_contract import (
            SANDBOX_FEATURE_VERSION,
            SANDBOX_NUMERIC_FEATURE_COLUMNS,
            build_numeric_feature_map,
            ensure_numeric_feature_frame,
        )

WORKSPACE_ROOT = PHISHING_HOME
SHELL_MARKERS = {"sh", "bash", "zsh", "cmd", "powershell", "pwsh", "cmd.exe"}
CSV_CHUNK_ROWS = max(10_000, int(settings.preprocessing_chunk_size_mb) * 1_000)


# Windows API ID buckets used by Oliveira-style sequence datasets.
_API_ID_TO_BUCKET: dict[int, str] = {}


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


def _read_csv_chunks(csv_path: Path, **kwargs):
    read_kwargs = {
        "low_memory": False,
        "chunksize": CSV_CHUNK_ROWS,
        **kwargs,
    }
    return pd.read_csv(csv_path, **read_kwargs)


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


def _label_to_int(value: object) -> int | None:
    if value is None:
        return None
    text = str(value).strip().lower()
    if text in {"1", "true", "malicious", "malware", "bad", "yes"}:
        return 1
    if text in {"0", "false", "benign", "good", "no"}:
        return 0
    return None


def _extract_label(row: dict[str, object], default: int = 1) -> int:
    for key in ("label", "class", "family", "is_malware", "malicious", "classification_type"):
        if key in row:
            maybe = _label_to_int(row.get(key))
            if maybe is not None:
                return maybe
    return default


def _entropy_from_tokens(tokens: list[str]) -> float:
    if not tokens:
        return 0.0
    joined = " ".join(tokens)
    counts: dict[str, int] = {}
    for ch in joined:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(joined)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 2)


def _entropy_from_bytes(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / total
        entropy -= p * math.log2(p)
    return round(entropy, 2)


def _normalize_row(row: dict[str, object], source: str, sample_id: str) -> dict[str, object]:
    normalized = {
        "sample_id": sample_id,
        "file_extension": str(row.get("file_extension") or row.get("ext") or "unknown"),
        **build_numeric_feature_map(row),
        "label": _extract_label(row),
        "source": source,
    }
    return normalized


def _load_runtime_observations(base_dir: Path, use_pseudo_labels: bool) -> list[dict[str, object]]:
    csv_path = base_dir / "sandbox_behavior" / "runtime_observations.csv"
    if not csv_path.exists() or csv_path.stat().st_size == 0:
        return []

    rows: list[dict[str, object]] = []
    for frame in _read_csv_chunks(csv_path):
        chunk = frame.fillna("")
        for idx, row in chunk.iterrows():
            row_dict = row.to_dict()
            sample_id = str(row_dict.get("sample_id") or f"runtime_{idx:07d}")

            explicit_label = _label_to_int(row_dict.get("label"))
            pseudo_label = _label_to_int(row_dict.get("pseudo_label"))
            if explicit_label is not None:
                row_dict["label"] = explicit_label
            elif use_pseudo_labels and pseudo_label is not None:
                row_dict["label"] = pseudo_label
            else:
                row_dict["label"] = -1

            rows.append(_normalize_row(row_dict, "runtime_detonation", sample_id))

    return rows


def _load_existing_sandbox_logs(base_dir: Path) -> list[dict[str, object]]:
    csv_path = base_dir / "sandbox_behavior" / "sandbox_logs.csv"
    if not csv_path.exists() or csv_path.stat().st_size == 0:
        return []

    rows: list[dict[str, object]] = []
    for frame in _read_csv_chunks(csv_path):
        for idx, row in frame.fillna("").iterrows():
            as_dict = row.to_dict()
            sample_id = str(as_dict.get("sample_id") or f"synthetic_{idx:06d}")
            rows.append(_normalize_row(as_dict, "sandbox_logs", sample_id))
    return rows


def _windows_api_id_to_bucket(call_id: int) -> str:
    if not _API_ID_TO_BUCKET:
        vocab_path = WORKSPACE_ROOT / "datasets" / "sandbox_behavior" / "avast_ctu_capev2" / "avast_vocab.json"
        if vocab_path.exists():
            try:
                vocab = json.loads(vocab_path.read_text(encoding="utf-8"))
                for api_name, api_id in vocab.items():
                    name_lower = api_name.lower()
                    if "exec" in name_lower or "process" in name_lower or "thread" in name_lower:
                        _API_ID_TO_BUCKET[api_id] = "process"
                    elif any(k in name_lower for k in ["connect", "socket", "http", "internet", "send", "recv", "bind", "accept", "ws", "url"]):
                        _API_ID_TO_BUCKET[api_id] = "network"
                    elif any(k in name_lower for k in ["file", "open", "write", "read", "dir"]):
                        _API_ID_TO_BUCKET[api_id] = "filesystem"
                    elif "reg" in name_lower:
                        _API_ID_TO_BUCKET[api_id] = "registry"
                    elif any(k in name_lower for k in ["alloc", "protect", "map", "mem"]):
                        _API_ID_TO_BUCKET[api_id] = "memory"
                    else:
                        _API_ID_TO_BUCKET[api_id] = "unknown"
            except Exception:
                pass
    return _API_ID_TO_BUCKET.get(call_id, "unknown")


def _load_oliveira_api_sequences(base_dir: Path) -> list[dict[str, object]]:
    csv_path = base_dir / "sandbox_behavior" / "api_sequences" / "dynamic_api_call_sequence_per_malware_100_0_306.csv"
    if not csv_path.exists() or csv_path.stat().st_size == 0:
        return []

    rows: list[dict[str, object]] = []
    for frame in _read_csv_chunks(csv_path):
        frame = frame.fillna(0)
        t_columns = [col for col in frame.columns if re.fullmatch(r"t_\d+", str(col))]

        for _, row in frame.iterrows():
            seq_raw = [_as_int(row.get(col), -1) for col in t_columns]
            seq = [val for val in seq_raw if val >= 0]
            dedup_seq = list(dict.fromkeys(seq))[:100]

            bucket_counts = {"process": 0, "filesystem": 0, "network": 0, "registry": 0, "memory": 0}
            for call_id in dedup_seq:
                bucket = _windows_api_id_to_bucket(call_id)
                if bucket in bucket_counts:
                    bucket_counts[bucket] += 1

            normalized = _normalize_row(
                {
                    "executed": 1,
                    "spawned_processes": bucket_counts["process"],
                    "suspicious_process_count": int(bucket_counts["network"] > 0 and bucket_counts["process"] > 0),
                    "connect_calls": bucket_counts["network"],
                    "execve_calls": bucket_counts["process"],
                    "file_write_calls": bucket_counts["filesystem"],
                    "sequence_length": len(dedup_seq),
                    "sequence_process_calls": bucket_counts["process"],
                    "sequence_network_calls": bucket_counts["network"],
                    "sequence_filesystem_calls": bucket_counts["filesystem"],
                    "sequence_registry_calls": bucket_counts["registry"],
                    "sequence_memory_calls": bucket_counts["memory"],
                    "file_entropy": _entropy_from_tokens([str(v) for v in dedup_seq]),
                    "label": _extract_label({"label": row.get("malware")}, default=1),
                },
                source="oliveira_api_sequences",
                sample_id=str(row.get("hash") or "oliveira_unknown"),
            )
            rows.append(normalized)

    return rows


def _load_generic_api_sequences(base_dir: Path) -> list[dict[str, object]]:
    api_dir = base_dir / "sandbox_behavior" / "api_sequences"
    if not api_dir.exists():
        return []

    rows: list[dict[str, object]] = []
    for file_path in sorted(api_dir.glob("*.csv")):
        if file_path.name == "dynamic_api_call_sequence_per_malware_100_0_306.csv":
            continue
        try:
            for frame in _read_csv_chunks(file_path):
                col_map = {str(c).lower(): c for c in frame.columns}
                seq_col = None
                for key in ("api_sequence", "api_calls", "sequence", "calls"):
                    if key in col_map:
                        seq_col = col_map[key]
                        break
                if seq_col is None:
                    continue

                for idx, row in frame.fillna("").iterrows():
                    tokens = [tok.strip() for tok in re.split(r"[\s,;|>]+", str(row.get(seq_col, ""))) if tok.strip()]
                    lowered = [tok.lower() for tok in tokens]

                    process_calls = sum(1 for tok in lowered if "exec" in tok or "process" in tok or "thread" in tok)
                    network_calls = sum(1 for tok in lowered if "connect" in tok or "socket" in tok or "http" in tok)
                    filesystem_calls = sum(1 for tok in lowered if "file" in tok or "open" in tok or "write" in tok)
                    registry_calls = sum(1 for tok in lowered if "reg" in tok)
                    memory_calls = sum(1 for tok in lowered if "alloc" in tok or "protect" in tok or "map" in tok)

                    normalized = _normalize_row(
                        {
                            "executed": 1,
                            "spawned_processes": max(process_calls, 1 if tokens else 0),
                            "suspicious_process_count": int(process_calls > 0 and network_calls > 0),
                            "connect_calls": network_calls,
                            "execve_calls": process_calls,
                            "file_write_calls": filesystem_calls,
                            "sequence_length": len(tokens),
                            "sequence_process_calls": process_calls,
                            "sequence_network_calls": network_calls,
                            "sequence_filesystem_calls": filesystem_calls,
                            "sequence_registry_calls": registry_calls,
                            "sequence_memory_calls": memory_calls,
                            "file_entropy": _entropy_from_tokens(tokens),
                            "label": _extract_label(row.to_dict(), default=1),
                        },
                        source="api_sequences",
                        sample_id=str(row.get("sample_id") or f"api_{file_path.stem}_{idx:06d}"),
                    )
                    rows.append(normalized)
        except Exception:
            continue

    return rows


def _load_cuckoo_reports(base_dir: Path) -> list[dict[str, object]]:
    report_dir = base_dir / "sandbox_behavior" / "cuckoo_reports"
    if not report_dir.exists():
        return []

    rows: list[dict[str, object]] = []
    for file_path in sorted(report_dir.rglob("*.json")):
        try:
            report = json.loads(file_path.read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            continue

        if not isinstance(report, dict):
            continue

        # Support both {summary: ...} and {behavior: {summary: ...}} schemas.
        summary = report.get("summary")
        if not isinstance(summary, dict):
            behavior = report.get("behavior", {}) if isinstance(report.get("behavior"), dict) else {}
            summary = behavior.get("summary", {}) if isinstance(behavior.get("summary"), dict) else {}

        network = report.get("network", {}) if isinstance(report.get("network"), dict) else {}
        info = report.get("info", {}) if isinstance(report.get("info"), dict) else {}
        target = report.get("target", {}) if isinstance(report.get("target"), dict) else {}
        file_info = target.get("file", {}) if isinstance(target.get("file"), dict) else {}

        files_touched = len(summary.get("files", []) or [])
        write_files = len(summary.get("write_files", []) or [])
        read_files = len(summary.get("read_files", []) or [])
        executed_commands = summary.get("executed_commands", []) or []
        resolved_apis = summary.get("resolved_apis", []) or []

        connect_calls = len(summary.get("connects", []) or [])
        connect_calls += len(network.get("hosts", []) or [])
        connect_calls += len(network.get("domains", []) or [])
        connect_calls += len(network.get("http", []) or [])
        connect_calls += len(network.get("tcp", []) or [])
        connect_calls += len(network.get("udp", []) or [])

        shell_flag = 1 if any(any(marker in str(cmd).lower() for marker in SHELL_MARKERS) for cmd in executed_commands) else 0
        score_val = info.get("score")
        if score_val is None:
            label = -1
        else:
            label = 1 if _as_float(score_val, 0.0) >= 6.0 else 0

        name = str(file_info.get("name") or file_path.stem)
        ext = "." + name.split(".")[-1] if "." in name else "unknown"

        normalized = _normalize_row(
            {
                "file_extension": ext,
                "executed": 1,
                "spawned_processes": max(len(executed_commands), shell_flag),
                "suspicious_process_count": shell_flag,
                "connect_calls": connect_calls,
                "execve_calls": len(executed_commands),
                "file_write_calls": write_files,
                "sequence_length": len(resolved_apis),
                "sequence_process_calls": len(executed_commands),
                "sequence_network_calls": connect_calls,
                "sequence_filesystem_calls": files_touched + read_files + write_files,
                "sequence_registry_calls": len(summary.get("keys", []) or []),
                "sequence_memory_calls": 0,
                "file_entropy": _as_float(file_info.get("entropy"), 0.0),
                "label": label,
            },
            source="cuckoo_reports",
            sample_id=f"cuckoo_{file_path.stem}",
        )
        rows.append(normalized)

    return rows


def _load_polymorphic_dynamics(base_dir: Path) -> list[dict[str, object]]:
    csv_path = base_dir / "sandbox_behavior" / "polymorphic_dynamics" / "Malware_Analysis.csv"
    if not csv_path.exists() or csv_path.stat().st_size == 0:
        return []

    rows: list[dict[str, object]] = []
    for frame in _read_csv_chunks(csv_path):
        frame = frame.fillna(0)
        for _, row in frame.iterrows():
            score = _as_float(row.get("Score"), 0.0)
            connects = _as_int(row.get("API_connect"), 0) + _as_int(row.get("API_InternetConnectA"), 0)
            exec_calls = _as_int(row.get("API_CreateProcessInternalW"), 0) + _as_int(row.get("API_CreateThread"), 0)
            file_writes = _as_int(row.get("file_written"), 0) + _as_int(row.get("API_NtWriteFile"), 0)
            reg_ops = _as_int(row.get("regkey_read"), 0) + _as_int(row.get("API_RegSetValueExA"), 0)

            normalized = _normalize_row(
                {
                    "executed": 1,
                    "spawned_processes": max(exec_calls, 1),
                    "suspicious_process_count": int(exec_calls > 2) + int(connects > 0),
                    "connect_calls": connects,
                    "execve_calls": exec_calls,
                    "file_write_calls": file_writes,
                    "sequence_length": _as_int(row.get("dll_loaded_count"), 0),
                    "sequence_process_calls": exec_calls,
                    "sequence_network_calls": connects,
                    "sequence_filesystem_calls": _as_int(row.get("file_opened"), 0) + file_writes,
                    "sequence_registry_calls": reg_ops,
                    "sequence_memory_calls": _as_int(row.get("API_NtAllocateVirtualMemory"), 0),
                    "file_entropy": _entropy_from_tokens([str(row.get("pid", "0")), str(row.get("info_id", "0"))]),
                    "label": 1 if score >= 6.0 else 0,
                },
                source="polymorphic_dynamics",
                sample_id=f"poly_{_as_int(row.get('info_id'), 0)}_{_as_int(row.get('pid'), 0)}",
            )
            rows.append(normalized)

    return rows


def _load_cic_maldroid(base_dir: Path) -> list[dict[str, object]]:
    csv_path = base_dir / "sandbox_behavior" / "cic_maldroid_2020" / "feature_vectors_syscallsbinders_frequency_5_Cat.csv"
    if not csv_path.exists() or csv_path.stat().st_size == 0:
        return []

    rows: list[dict[str, object]] = []
    for frame in _read_csv_chunks(csv_path):
        frame = frame.fillna(0)
        for idx, row in frame.iterrows():
            connects = _as_int(row.get("connect"), 0) + _as_int(row.get("socket"), 0)
            exec_calls = _as_int(row.get("execve"), 0) + _as_int(row.get("fork"), 0) + _as_int(row.get("clone"), 0)
            writes = _as_int(row.get("write"), 0) + _as_int(row.get("pwrite64"), 0)
            reg_like = _as_int(row.get("set"), 0) + _as_int(row.get("get"), 0)

            label_raw = _as_int(row.get("Class"), 0)
            label = 1 if label_raw > 0 else 0

            normalized = _normalize_row(
                {
                    "executed": 1,
                    "spawned_processes": max(exec_calls, 1),
                    "suspicious_process_count": int(exec_calls > 0 and connects > 0),
                    "connect_calls": connects,
                    "execve_calls": exec_calls,
                    "file_write_calls": writes,
                    "sequence_length": int(sum(_as_int(v, 0) for v in row.values if str(v).strip())),
                    "sequence_process_calls": exec_calls,
                    "sequence_network_calls": connects,
                    "sequence_filesystem_calls": _as_int(row.get("open"), 0) + writes,
                    "sequence_registry_calls": reg_like,
                    "sequence_memory_calls": _as_int(row.get("mmap2"), 0) + _as_int(row.get("mprotect"), 0),
                    "file_entropy": 0.0,
                    "label": label,
                },
                source="cic_maldroid_2020",
                sample_id=f"cic_{idx:07d}",
            )
            rows.append(normalized)

    return rows


def _load_avast_subset(base_dir: Path) -> list[dict[str, object]]:
    csv_path = base_dir / "sandbox_behavior" / "avast_ctu_capev2" / "avast_full_index_subset5_seed42.csv"
    if not csv_path.exists() or csv_path.stat().st_size == 0:
        return []

    rows: list[dict[str, object]] = []
    for frame in _read_csv_chunks(csv_path):
        for _, row in frame.fillna("").iterrows():
            fam = str(row.get("classification_family", "")).strip().lower()
            ctype = str(row.get("classification_type", "")).strip().lower()
            # This subset is malware-centric; keep as malicious unless explicitly benign.
            label = 0 if ctype in {"benign", "goodware"} else 1
            normalized = _normalize_row(
                {
                    "executed": 1,
                    "spawned_processes": 1,
                    "suspicious_process_count": int(ctype not in {"benign", "goodware"}),
                    "connect_calls": int(ctype in {"banker", "botnet", "backdoor"}),
                    "execve_calls": 1,
                    "file_write_calls": 1,
                    "sequence_length": _as_int(row.get("seq_length"), 0),
                    "sequence_process_calls": int(ctype not in {"benign", "goodware"}),
                    "sequence_network_calls": int(ctype in {"banker", "botnet", "backdoor"}),
                    "sequence_filesystem_calls": 1,
                    "sequence_registry_calls": int(fam in {"trickbot", "qakbot", "zeus"}),
                    "sequence_memory_calls": 1,
                    "file_entropy": 0.0,
                    "label": label,
                },
                source="avast_ctu_capev2",
                sample_id=str(row.get("sha256") or f"avast_{fam}"),
            )
            rows.append(normalized)

    return rows


def _load_local_benign_bootstrap(base_dir: Path, max_rows: int) -> list[dict[str, object]]:
    if max_rows <= 0:
        return []

    candidate_dirs = [
        base_dir / "attachments" / "benign",
        base_dir / "email_content" / "legitimate",
        base_dir / "email_content" / "spamassassin_ham",
    ]

    allowed_suffixes = {
        ".txt", ".eml", ".md", ".csv", ".json", ".html", ".htm", ".pdf",
        ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".rtf",
        ".jpg", ".jpeg", ".png", ".gif",
    }

    rows: list[dict[str, object]] = []
    seen_sample_ids: set[str] = set()

    for root in candidate_dirs:
        if not root.exists():
            continue

        for file_path in sorted(root.rglob("*")):
            if len(rows) >= max_rows:
                return rows
            if not file_path.is_file():
                continue

            suffix = file_path.suffix.lower()
            if suffix and suffix not in allowed_suffixes:
                continue

            try:
                blob = file_path.read_bytes()
            except OSError:
                continue

            if not blob:
                continue

            stable_suffix = sha1(str(file_path).encode("utf-8", errors="ignore")).hexdigest()[:12]  # nosec B324
            sample_id = f"benign_{file_path.stem}_{stable_suffix}"
            if sample_id in seen_sample_ids:
                continue
            seen_sample_ids.add(sample_id)

            entropy = _entropy_from_bytes(blob)
            size_kb = len(blob) / 1024.0

            row = _normalize_row(
                {
                    "file_extension": suffix or "unknown",
                    "executed": 0,
                    "return_code": 0,
                    "timed_out": 0,
                    "spawned_processes": 0,
                    "suspicious_process_count": 0,
                    "file_entropy": entropy,
                    "connect_calls": 0,
                    "execve_calls": 0,
                    "file_write_calls": 0,
                    # Keep mild sequence length signal from file size to avoid a completely degenerate benign cluster.
                    "sequence_length": int(min(40, max(1, size_kb // 8))),
                    "sequence_process_calls": 0,
                    "sequence_network_calls": 0,
                    "sequence_filesystem_calls": 0,
                    "sequence_registry_calls": 0,
                    "sequence_memory_calls": 0,
                    "critical_chain_detected": 0,
                    "behavior_risk_score": 0.02,
                    "label": 0,
                },
                source="local_benign_bootstrap",
                sample_id=sample_id,
            )
            rows.append(row)

    return rows


def run(base_dir: str = "datasets", output_dir: str = "datasets_processed") -> str:
    base = _resolve_input_dir(base_dir)
    output = _resolve_output_dir(output_dir)
    output.mkdir(parents=True, exist_ok=True)

    rows: list[dict[str, object]] = []

    real_rows: list[dict[str, object]] = []
    real_rows.extend(_load_oliveira_api_sequences(base))
    real_rows.extend(_load_generic_api_sequences(base))
    real_rows.extend(_load_cuckoo_reports(base))
    real_rows.extend(_load_polymorphic_dynamics(base))
    real_rows.extend(_load_cic_maldroid(base))
    real_rows.extend(_load_avast_subset(base))

    include_runtime = os.getenv("SANDBOX_INCLUDE_RUNTIME_OBSERVATIONS", "1") == "1"
    use_runtime_pseudo_labels = os.getenv("SANDBOX_USE_PSEUDO_LABELS", "0") == "1"
    include_benign_bootstrap = os.getenv("SANDBOX_ENABLE_BENIGN_BOOTSTRAP", "1") == "1"
    benign_bootstrap_max_rows = _as_int(os.getenv("SANDBOX_BENIGN_BOOTSTRAP_MAX_ROWS", "5000"), 5000)
    if include_runtime:
        real_rows.extend(_load_runtime_observations(base, use_pseudo_labels=use_runtime_pseudo_labels))

    if include_benign_bootstrap:
        real_rows.extend(_load_local_benign_bootstrap(base, max_rows=benign_bootstrap_max_rows))

    include_synthetic = os.getenv("SANDBOX_INCLUDE_SYNTHETIC_LOGS", "0") == "1"
    if include_synthetic or not real_rows:
        rows.extend(_load_existing_sandbox_logs(base))

    rows.extend(real_rows)

    if not rows:
        raise FileNotFoundError(
            "No sandbox behavior sources found. Expected at least one source under datasets/sandbox_behavior/."
        )

    frame = pd.DataFrame(rows)
    frame = frame.drop_duplicates(subset=["sample_id", "source"], keep="first")
    frame = ensure_numeric_feature_frame(frame)
    
    # Exclude unknowns
    frame = frame[frame["label"].isin([0, 1])].copy()
    frame["label"] = frame["label"].astype(int)

    # Source-stratified train/val split and weighting
    try:
        from sklearn.model_selection import train_test_split
    except ImportError:
        train_test_split = None

    frame["split"] = "train"
    val_indices = []
    
    total_len = len(frame)
    num_sources = frame["source"].nunique()
    weights = {}
    
    for source in frame["source"].unique():
        source_mask = frame["source"] == source
        source_idx = frame[source_mask].index
        
        count = len(source_idx)
        weights[source] = float(total_len) / (count * num_sources) if count > 0 else 0.0
        
        if train_test_split is not None and count > 5:
            labels = frame.loc[source_idx, "label"]
            try:
                if len(labels.unique()) > 1:
                    _, va = train_test_split(source_idx, test_size=0.2, stratify=labels, random_state=42)
                else:
                    _, va = train_test_split(source_idx, test_size=0.2, random_state=42)
                val_indices.extend(va)
            except Exception:
                pass

    frame.loc[val_indices, "split"] = "val"
    frame["sample_weight"] = frame["source"].map(weights)

    stable_columns = [
        "sample_id",
        "file_extension",
        *SANDBOX_NUMERIC_FEATURE_COLUMNS,
        "label",
        "source",
        "split",
        "sample_weight",
    ]
    frame = frame[stable_columns]

    out_csv = output / "sandbox_behavior_training.csv"
    frame.to_csv(out_csv, index=False)

    audit = {
        "rows": int(frame.shape[0]),
        "malicious": int((frame["label"] == 1).sum()),
        "benign": int((frame["label"] == 0).sum()),
        "sources": frame["source"].value_counts().to_dict(),
        "per_source_weights": weights,
        "train_set_size": int((frame["split"] == "train").sum()),
        "val_set_size": int((frame["split"] == "val").sum()),
        "output": str(out_csv),
        "include_synthetic": include_synthetic,
        "include_runtime_observations": include_runtime,
        "use_runtime_pseudo_labels": use_runtime_pseudo_labels,
        "include_benign_bootstrap": include_benign_bootstrap,
        "benign_bootstrap_max_rows": benign_bootstrap_max_rows,
        "feature_version": SANDBOX_FEATURE_VERSION,
        "feature_columns": SANDBOX_NUMERIC_FEATURE_COLUMNS,
    }
    (output / "sandbox_behavior_audit.json").write_text(json.dumps(audit, indent=2), encoding="utf-8")

    return str(out_csv)


if __name__ == "__main__":
    out = run(base_dir="datasets", output_dir="datasets_processed")
    print(out)
