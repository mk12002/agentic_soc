#!/usr/bin/env python3
"""Create balanced-bagging splits for attachment malware training.

Each split reuses all benign samples and gets a disjoint chunk of malware samples.
Symlinks are used to avoid duplicating the dataset on disk.
"""

from __future__ import annotations

import argparse
import json
import random
import shutil
from pathlib import Path

from soc_platform.domains.phishing.engine.paths import PHISHING_HOME


def _gather_files(folder: Path) -> list[Path]:
    if not folder.exists():
        raise FileNotFoundError(f"Folder not found: {folder}")
    return sorted(p for p in folder.rglob("*") if p.is_file())


def _safe_link(src: Path, dst_dir: Path) -> None:
    """Link file into dst_dir, adding a numeric suffix if name conflicts."""
    dst = dst_dir / src.name
    counter = 1
    while dst.exists() or dst.is_symlink():
        dst = dst_dir / f"{src.stem}_{counter}{src.suffix}"
        counter += 1
    dst.symlink_to(src)


def create_ensemble_splits(
    benign_dir: Path,
    malware_dir: Path,
    output_dir: Path,
    num_splits: int,
    seed: int,
    force_rebuild: bool,
) -> None:
    benign_files = _gather_files(benign_dir)
    malware_files = _gather_files(malware_dir)

    print(f"Benign folder:  {benign_dir}", flush=True)
    print(f"Malware folder: {malware_dir}", flush=True)
    print(
        f"Found {len(benign_files)} benign and {len(malware_files)} malware files.",
        flush=True,
    )

    if not benign_files or not malware_files:
        raise RuntimeError("Both benign and malware folders must contain files.")

    if num_splits < 1:
        raise ValueError("num_splits must be >= 1")

    random.seed(seed)
    random.shuffle(malware_files)

    output_dir.mkdir(parents=True, exist_ok=True)
    if force_rebuild:
        for i in range(num_splits):
            split_dir = output_dir / f"split_{i}"
            if split_dir.exists():
                shutil.rmtree(split_dir)

    malware_base = len(malware_files) // num_splits
    remainder = len(malware_files) % num_splits

    print(
        f"Creating {num_splits} split(s) using symlinks in {output_dir} ...",
        flush=True,
    )

    manifest: dict[str, object] = {
        "benign_dir": str(benign_dir),
        "malware_dir": str(malware_dir),
        "output_dir": str(output_dir),
        "num_splits": num_splits,
        "seed": seed,
        "benign_total": len(benign_files),
        "malware_total": len(malware_files),
        "splits": [],
    }

    total_symlinks = 0
    malware_start = 0
    for i in range(num_splits):
        split_dir = output_dir / f"split_{i}"
        split_benign = split_dir / "benign"
        split_malware = split_dir / "malware"
        split_benign.mkdir(parents=True, exist_ok=True)
        split_malware.mkdir(parents=True, exist_ok=True)

        for b_file in benign_files:
            _safe_link(b_file, split_benign)
            total_symlinks += 1

        malware_count = malware_base + (1 if i < remainder else 0)
        malware_chunk = malware_files[malware_start : malware_start + malware_count]
        malware_start += malware_count

        for m_file in malware_chunk:
            _safe_link(m_file, split_malware)
            total_symlinks += 1

        split_meta = {
            "split": i,
            "benign": len(benign_files),
            "malware": len(malware_chunk),
            "ratio_malware_to_benign": round(len(malware_chunk) / len(benign_files), 4),
        }
        manifest["splits"].append(split_meta)
        print(
            f"Split {i}: benign={len(benign_files)}, malware={len(malware_chunk)}",
            flush=True,
        )

    manifest_path = output_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    print(f"\nDone. Created {total_symlinks} symlinks.", flush=True)
    print(f"Manifest written to: {manifest_path}", flush=True)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create balanced-bagging splits via symlinks.",
    )
    parser.add_argument(
        "--benign-dir",
        type=Path,
        default=(PHISHING_HOME / "datasets" / "attachments/malware/DikeDataset/files/benign"),
        help="Directory containing benign files.",
    )
    parser.add_argument(
        "--malware-dir",
        type=Path,
        default=(PHISHING_HOME / "datasets" / "attachments/malware/DikeDataset/files/malware"),
        help="Directory containing malware files.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=(PHISHING_HOME / "datasets_processed" / "ensemble_splits"),
        help="Where split folders are created.",
    )
    parser.add_argument(
        "--num-splits",
        type=int,
        default=10,
        help="Number of ensemble splits/models.",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed used to shuffle malware files.",
    )
    parser.add_argument(
        "--force-rebuild",
        action="store_true",
        help="Delete existing split_*/ folders before creating new splits.",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    create_ensemble_splits(
        benign_dir=args.benign_dir,
        malware_dir=args.malware_dir,
        output_dir=args.output_dir,
        num_splits=args.num_splits,
        seed=args.seed,
        force_rebuild=args.force_rebuild,
    )
