"""Attachment-agent preprocessing (EMBER conversion/check)."""

from __future__ import annotations
from soc_platform.domains.phishing.engine.paths import PHISHING_HOME

from pathlib import Path

from .convert_ember_jsonl import convert_ember_jsonl_to_parquet

WORKSPACE_ROOT = PHISHING_HOME
def _resolve_input_dir(path_value: str) -> Path:
    path = Path(path_value)
    if path.is_absolute():
        return path
    if path.exists():
        return path
    return WORKSPACE_ROOT / path


def run(base_dir: str = "datasets", output_dir: str = "datasets_processed") -> str:
    # output_dir retained for consistent run() signature, though this step outputs parquet in-place.
    _ = output_dir
    base = _resolve_input_dir(base_dir)

    ember_dir = base / "attachments" / "malware" / "ember_features"
    target = ember_dir / "train_ember_2018_v2_features.parquet"

    if target.exists():
        return str(target)

    if (ember_dir / "train_features_0.jsonl").exists():
        try:
            convert_ember_jsonl_to_parquet(ember_dir, target)
        except Exception:
            return ""

    if target.exists():
        return str(target)
    return ""


if __name__ == "__main__":
    out = run(base_dir="datasets", output_dir="datasets_processed")
    print(out)
