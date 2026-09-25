import subprocess
import sys
from pathlib import Path

import numpy as np
import pandas as pd

from soc_platform.domains.phishing.engine.configs.settings import settings

def _install_ember_module():
    """Install the official lief/ember module required to vectorize the raw JSONL."""
    try:
        import ember
        return
    except ImportError:
        print("Installing the `ember` module from elasticity repository...")
        subprocess.check_call([
            sys.executable, "-m", "pip", "install", 
            "git+https://github.com/elastic/ember.git"
        ])


def _rows_per_chunk(num_columns: int) -> int:
    chunk_mb = max(1, int(getattr(settings, "preprocessing_chunk_size_mb", 256)))
    approx_row_bytes = max(1, num_columns * np.dtype(np.float32).itemsize)
    return max(1_000, (chunk_mb * 1024 * 1024) // approx_row_bytes)


def _write_parquet_in_chunks(df: pd.DataFrame, output_parquet: Path) -> None:
    try:
        import pyarrow as pa
        import pyarrow.parquet as pq
    except Exception:
        df.to_parquet(output_parquet, engine="pyarrow", compression="snappy")
        return

    writer = None
    try:
        rows_per_chunk = _rows_per_chunk(len(df.columns) - 1)
        for start in range(0, len(df), rows_per_chunk):
            chunk = df.iloc[start : start + rows_per_chunk]
            table = pa.Table.from_pandas(chunk, preserve_index=False)
            if writer is None:
                writer = pq.ParquetWriter(output_parquet, table.schema, compression="snappy")
            writer.write_table(table)
    finally:
        if writer is not None:
            writer.close()
        
def convert_ember_jsonl_to_parquet(ember_dir: Path, output_parquet: Path):
    """
    Parses EMBER JSONL raw features, converts them to the 2381-vector space
    using the official EMBER vectorizer, and stores them in a highly-compressed Parquet.
    """
    _install_ember_module()
    import ember
    
    ember_dir_str = str(ember_dir)
    print(f"Creating vectorized features from JSONL in {ember_dir_str}...")
    
    # ember.create_vectorized_features parses JSONL and creates X_train.dat, y_train.dat
    # It takes a while and creates numpy memmaps.
    try:
        if not (ember_dir / "X_train.dat").exists():
            ember.create_vectorized_features(ember_dir_str)
    except Exception as e:
        print(f"Failed during ember.create_vectorized_features: {e}")
        raise

    print("Loading vectorized features into memory...")
    # read_vectorized_features returns X (features), y (labels)
    try:
        X_train, y_train = ember.read_vectorized_features(ember_dir_str, subset="train")
    except Exception as e:
        print(f"Failed to read vectorized features: {e}")
        # Sometimes subset="train" is not needed or it's just read_vectorized_features(ember_dir_str)
        try:
            X_train, y_train = ember.read_vectorized_features(ember_dir_str)
        except Exception as e2:
             print(f"Fallback read failed too: {e2}")
             raise

    print(f"Total shape of EMBER training data: {X_train.shape}")
    
    # Filter out unlabeled (-1)
    valid_idx = np.where(y_train != -1)[0]
    X_train = X_train[valid_idx]
    y_train = y_train[valid_idx]
    
    print(f"Shape after removing unlabeled samples: {X_train.shape}")

    # Convert to DataFrame
    print(f"Saving Parquet to {output_parquet}...")
    # Build and write the parquet file in smaller row groups to keep peak RAM lower.
    df = pd.DataFrame(X_train, dtype=np.float32)
    df["label"] = y_train.astype(np.int8)
    _write_parquet_in_chunks(df, output_parquet)
    print("EMBER Parquet conversion completed successfully!")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--dir", type=str, required=True, help="Directory containing train_features_X.jsonl")
    parser.add_argument("--out", type=str, required=True, help="Output parquet file path")
    args = parser.parse_args()
    
    convert_ember_jsonl_to_parquet(Path(args.dir), Path(args.out))
