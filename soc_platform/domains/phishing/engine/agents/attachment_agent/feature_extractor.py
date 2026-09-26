"""Feature extraction for attachment static-analysis models."""

from __future__ import annotations

import math
from pathlib import Path
from typing import Any

import numpy as np

from soc_platform.domains.phishing.engine.services.logging_service import get_agent_logger

logger = get_agent_logger("attachment_agent")

SUSPICIOUS_IMPORT_STRINGS = [b"VirtualAlloc", b"WriteProcessMemory", b"CreateRemoteThread", b"powershell"]
MACRO_EXTENSIONS = {".docm", ".xlsm"}
RISKY_EXTENSIONS = {".exe", ".dll", ".scr", ".js", ".vbs", ".hta", ".ps1", ".docm", ".xlsm"}


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    probs = [count / len(data) for count in freq if count]
    return -sum(prob * math.log2(prob) for prob in probs)


def extract_features(data: dict[str, Any]) -> dict[str, Any]:
    """Build aggregate features from attachment bytes and metadata."""
    logger.debug("Extracting features", agent="attachment_agent")
    attachments = data.get("attachments", []) or []

    if not attachments:
        return {"text": "", "numeric_vector": np.zeros((1, 6), dtype=float), "metrics": {"attachment_count": 0}}

    entropy_values: list[float] = []
    risky_ext_count = 0
    suspicious_import_count = 0
    macro_count = 0
    total_size = 0.0

    for attachment in attachments[:10]:
        path = Path(str(attachment.get("path", "") or ""))
        extension = path.suffix.lower()
        if extension in RISKY_EXTENSIONS:
            risky_ext_count += 1

        if not path.exists() or not path.is_file():
            continue

        blob = path.read_bytes()
        total_size += float(len(blob))
        entropy_values.append(float(_entropy(blob)))

        if any(token in blob for token in SUSPICIOUS_IMPORT_STRINGS):
            suspicious_import_count += 1
        if extension in MACRO_EXTENSIONS and b"vba" in blob.lower():
            macro_count += 1

    count = float(max(1, len(attachments[:10])))
    avg_entropy = sum(entropy_values) / max(1, len(entropy_values))
    numeric_vector = np.array(
        [
            float(len(attachments[:10])),
            risky_ext_count / count,
            suspicious_import_count / count,
            macro_count / count,
            avg_entropy,
            (total_size / count) / (1024.0 * 1024.0),
        ],
        dtype=float,
    ).reshape(1, -1)

    return {
        "text": "",
        "numeric_vector": numeric_vector,
        "metrics": {
            "attachment_count": int(count),
            "avg_entropy": avg_entropy,
            "risky_ext_ratio": risky_ext_count / count,
        },
    }
