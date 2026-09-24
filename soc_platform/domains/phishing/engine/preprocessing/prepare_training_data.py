"""Run all agent-specific preprocessing pipelines and emit a manifest."""

from __future__ import annotations
from soc_platform.domains.phishing.engine.paths import PHISHING_HOME

import json
from pathlib import Path

from .attachment_preprocessing import run as run_attachment_preprocessing
from .content_preprocessing import run as run_content_preprocessing
from .header_preprocessing import run as run_header_preprocessing
from .sandbox_preprocessing import run as run_sandbox_preprocessing
from .url_preprocessing import run as run_url_preprocessing

WORKSPACE_ROOT = PHISHING_HOME
def _resolve_output_dir(path_value: str) -> Path:
    path = Path(path_value)
    if path.is_absolute():
        return path
    return WORKSPACE_ROOT / path


def run(base_dir: str = "datasets", output_dir: str = "datasets_processed") -> dict[str, str]:
    output = _resolve_output_dir(output_dir)
    output.mkdir(parents=True, exist_ok=True)

    print("Extracting Content training data...")
    content_path = run_content_preprocessing(base_dir=base_dir, output_dir=output_dir)

    print("Extracting URL training data...")
    url_path = run_url_preprocessing(base_dir=base_dir, output_dir=output_dir)

    print("Extracting Header training data...")
    header_training_out = run_header_preprocessing(base_dir=base_dir, output_dir=output_dir)

    print("Checking Attachment/EMBER training data...")
    attachment_out = run_attachment_preprocessing(base_dir=base_dir, output_dir=output_dir)
    if not attachment_out:
        print("Warning: EMBER Parquet is missing, Attachment Agent cannot be trained.")

    print("Extracting Sandbox behavior training data...")
    try:
        sandbox_out = run_sandbox_preprocessing(base_dir=base_dir, output_dir=output_dir)
    except FileNotFoundError:
        sandbox_out = ""
        print("Warning: No sandbox behavior datasets found. Sandbox training data not generated.")

    report = {
        "content_training": content_path,
        "content_training_slm": str(output / "content_training_slm.csv"),
        "url_training": url_path,
        "header_training": header_training_out,
        "attachment_training_ember": attachment_out,
        "sandbox_behavior_training": sandbox_out,
    }
    (output / "training_manifest.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print("\nDataset Preprocessing Complete!")
    return report


if __name__ == "__main__":
    output = run(base_dir="datasets", output_dir="datasets_processed")
    print(json.dumps(output, indent=2))
