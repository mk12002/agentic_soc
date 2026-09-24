"""
Utility: Convert Parquet files to CSV using pandas.

Usage examples:
  python utils/parquet_to_csv.py --input datasets/static_analysis/ember_v2/train.parquet
  python utils/parquet_to_csv.py --input datasets/static_analysis/ember_v2 --recursive
  python utils/parquet_to_csv.py --input data.parquet --output data.csv --chunksize 200000
"""

from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd


PARQUET_ENGINE_HINT = (
    "Parquet support requires 'pyarrow' or 'fastparquet'. "
    "Install one with: pip install pyarrow"
)


def convert_file(input_path: Path, output_path: Path, chunksize: int | None = None) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        if chunksize is None:
            df = pd.read_parquet(input_path)
            df.to_csv(output_path, index=False)
            print(f"[OK] {input_path} -> {output_path} ({len(df)} rows)")
            return

        # Chunked conversion for large files
        df = pd.read_parquet(input_path)
        total_rows = len(df)
        start = 0
        first = True
        while start < total_rows:
            end = min(start + chunksize, total_rows)
            df.iloc[start:end].to_csv(output_path, mode="w" if first else "a", header=first, index=False)
            first = False
            start = end
        print(f"[OK] {input_path} -> {output_path} ({total_rows} rows, chunksize={chunksize})")
    except ImportError as exc:
        raise SystemExit(f"{PARQUET_ENGINE_HINT}\nOriginal error: {exc}") from exc


def collect_parquet_files(input_path: Path, recursive: bool) -> list[Path]:
    if input_path.is_file():
        if input_path.suffix.lower() != ".parquet":
            raise ValueError(f"Input file is not parquet: {input_path}")
        return [input_path]

    if not input_path.is_dir():
        raise FileNotFoundError(f"Input path does not exist: {input_path}")

    pattern = "**/*.parquet" if recursive else "*.parquet"
    files = sorted(input_path.glob(pattern))
    if not files:
        raise FileNotFoundError(f"No parquet files found in: {input_path}")
    return files


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Convert parquet file(s) to CSV")
    parser.add_argument("--input", required=True, help="Parquet file path or directory containing parquet files")
    parser.add_argument("--output", help="Output CSV path (valid only when input is a single parquet file)")
    parser.add_argument("--recursive", action="store_true", help="Recursively scan directories for parquet files")
    parser.add_argument("--chunksize", type=int, default=None, help="Optional chunk size for writing CSV in parts")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    input_path = Path(args.input)
    parquet_files = collect_parquet_files(input_path, recursive=args.recursive)

    if args.output and len(parquet_files) != 1:
        raise ValueError("--output can only be used when converting a single parquet file")

    for parquet_file in parquet_files:
        if args.output:
            output_candidate = Path(args.output)
            if output_candidate.exists() and output_candidate.is_dir():
                output_csv = output_candidate / f"{parquet_file.stem}.csv"
            elif output_candidate.suffix.lower() == ".csv":
                output_csv = output_candidate
            else:
                output_csv = output_candidate / f"{parquet_file.stem}.csv"
        else:
            output_csv = parquet_file.with_suffix(".csv")

        convert_file(parquet_file, output_csv, chunksize=args.chunksize)


if __name__ == "__main__":
    main()
