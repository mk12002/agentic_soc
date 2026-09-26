"""URL-agent preprocessing."""

from __future__ import annotations

import json
import os
import random
from pathlib import Path
from urllib.parse import urlsplit

import pandas as pd

from soc_platform.domains.phishing.engine.paths import PHISHING_HOME

from .feature_pipeline import build_url_features, normalize_url, write_processed_dataset

RANDOM_SEED = int(os.getenv("URL_RANDOM_SEED", "42"))
TARGET_SAMPLES_PER_CLASS = int(os.getenv("URL_TARGET_SAMPLES_PER_CLASS", "500000"))
MIN_SAMPLES_PER_CLASS = int(os.getenv("URL_MIN_SAMPLES_PER_CLASS", "150000"))
MAX_SAMPLES_PER_SOURCE = int(os.getenv("URL_MAX_SAMPLES_PER_SOURCE", "800000"))
CSV_CHUNK_SIZE = int(os.getenv("URL_CSV_CHUNK_SIZE", "150000"))
BENIGN_VARIANT_RATIO = float(os.getenv("URL_BENIGN_VARIANT_RATIO", "0.35"))
WORKSPACE_ROOT = PHISHING_HOME
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


def _sample_cap(values: list[str], cap: int, rng: random.Random) -> list[str]:
    if cap <= 0 or len(values) <= cap:
        return values
    return rng.sample(values, cap)


def _extract_plain_line_urls(file_path: Path) -> list[str]:
    urls: list[str] = []
    try:
        with file_path.open("r", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                value = line.strip().strip('"').strip("'")
                if not value or value.startswith("#"):
                    continue
                urls.append(value)
    except Exception:
        return []
    return urls


def _extract_csv_column(file_path: Path, column_name: str) -> list[str]:
    urls: list[str] = []
    if not file_path.exists() or file_path.stat().st_size == 0:
        return urls
    try:
        for chunk in pd.read_csv(
            file_path,
            comment="#",
            on_bad_lines="skip",
            low_memory=False,
            chunksize=CSV_CHUNK_SIZE,
            dtype=str,
        ):
            cols = {str(c).lower(): c for c in chunk.columns}
            if column_name.lower() not in cols:
                continue
            col = cols[column_name.lower()]
            urls.extend(chunk[col].dropna().astype(str).tolist())
    except Exception:
        return urls
    return urls


def _extract_csv_index(file_path: Path, index: int) -> list[str]:
    urls: list[str] = []
    if not file_path.exists() or file_path.stat().st_size == 0:
        return urls
    try:
        for chunk in pd.read_csv(
            file_path,
            comment="#",
            on_bad_lines="skip",
            low_memory=False,
            chunksize=CSV_CHUNK_SIZE,
            header=None,
            usecols=[index],
            dtype=str,
        ):
            urls.extend(chunk.iloc[:, 0].dropna().astype(str).tolist())
    except Exception:
        return urls
    return urls


def _extract_kaggle_urls(file_path: Path, wanted_type: str) -> list[str]:
    urls: list[str] = []
    if not file_path.exists() or file_path.stat().st_size == 0:
        return urls
    wanted = wanted_type.strip().lower()
    try:
        for chunk in pd.read_csv(
            file_path,
            on_bad_lines="skip",
            low_memory=False,
            chunksize=CSV_CHUNK_SIZE,
            dtype=str,
        ):
            cols = {str(c).lower(): c for c in chunk.columns}
            if "url" not in cols or "type" not in cols:
                continue
            url_col = cols["url"]
            type_col = cols["type"]
            if wanted == "benign":
                mask = chunk[type_col].astype(str).str.lower().eq("benign")
            else:
                mask = ~chunk[type_col].astype(str).str.lower().eq("benign")
            urls.extend(chunk.loc[mask, url_col].dropna().astype(str).tolist())
    except Exception:
        return urls
    return urls


def _extract_benign_domains(file_path: Path) -> list[str]:
    domains = _extract_csv_column(file_path, "domain")
    return [f"http://{domain.strip()}" for domain in domains if str(domain).strip()]


def _extract_top1m_domains(file_path: Path) -> list[str]:
    values = _extract_csv_index(file_path, 1)
    return [f"http://{value.strip()}" for value in values if str(value).strip()]


def _extract_urlhaus_urls(file_path: Path) -> list[str]:
    # URLhaus CSV dumps have comments and no header; URL is column index 2.
    return _extract_csv_index(file_path, 2)


def _inject_benign_variants(urls: list[str], rng: random.Random) -> tuple[list[str], int]:
    if not urls or BENIGN_VARIANT_RATIO <= 0:
        return urls, 0

    updated = list(urls)
    replace_count = min(len(updated), int(len(updated) * BENIGN_VARIANT_RATIO))
    if replace_count <= 0:
        return updated, 0

    indexes = rng.sample(range(len(updated)), replace_count)
    replaced = 0
    for idx in indexes:
        host = (urlsplit(updated[idx]).hostname or "").strip().lower()
        if not host:
            continue

        variants = [
            f"https://{host}/about",
            f"https://{host}/support",
            f"https://{host}/account",
            f"https://{host}/login",
            f"https://{host}/search?q=home",
        ]
        if not host.startswith("www."):
            variants.append(f"https://www.{host}/")

        candidate = rng.choice(variants)
        normalized = normalize_url(candidate)
        if normalized:
            updated[idx] = normalized
            replaced += 1

    return updated, replaced


def _collect_source_rows(base: Path, rng: random.Random) -> tuple[list[tuple[str, int, str]], dict[str, dict[str, int | str]]]:
    source_specs = [
        {
            "name": "malicious.openphish",
            "label": 1,
            "path": base / "url_dataset" / "malicious" / "openphish_urls.csv",
            "loader": _extract_plain_line_urls,
        },
        {
            "name": "malicious.phishtank_verified_online",
            "label": 1,
            "path": base / "url_dataset" / "malicious" / "verified_online.csv",
            "loader": lambda p: _extract_csv_column(p, "url"),
        },
        {
            "name": "malicious.urlhaus_online",
            "label": 1,
            "path": base / "url_dataset" / "malicious" / "urlhaus_urls.csv",
            "loader": _extract_urlhaus_urls,
        },
        {
            "name": "malicious.urlhaus_recent",
            "label": 1,
            "path": base / "url_dataset" / "malicious" / "urlhaus_recent.csv",
            "loader": _extract_urlhaus_urls,
        },
        {
            "name": "malicious.kaggle_non_benign",
            "label": 1,
            "path": base / "url_dataset" / "malicious_phish.csv",
            "loader": lambda p: _extract_kaggle_urls(p, "malicious"),
        },
        {
            "name": "malicious.threat_intel_feed",
            "label": 1,
            "path": base / "threat_intelligence" / "urls" / "malicious_urls.csv",
            "loader": lambda p: _extract_csv_column(p, "url"),
        },
        {
            "name": "malicious.threat_intel_urlhaus",
            "label": 1,
            "path": base / "threat_intelligence" / "urls" / "urlhaus_urls.csv",
            "loader": _extract_urlhaus_urls,
        },
        {
            "name": "benign.top_1m",
            "label": 0,
            "path": base / "url_dataset" / "benign" / "top-1m.csv",
            "loader": _extract_top1m_domains,
        },
        {
            "name": "benign.majestic_million",
            "label": 0,
            "path": base / "url_dataset" / "benign" / "majestic_million.csv",
            "loader": _extract_benign_domains,
        },
        {
            "name": "benign.kaggle_benign",
            "label": 0,
            "path": base / "url_dataset" / "malicious_phish.csv",
            "loader": lambda p: _extract_kaggle_urls(p, "benign"),
        },
        {
            "name": "benign.custom_list",
            "label": 0,
            "path": base / "url_dataset" / "benign" / "benign_urls.csv",
            "loader": _extract_plain_line_urls,
        },
    ]

    rows: list[tuple[str, int, str]] = []
    audit_sources: dict[str, dict[str, int | str]] = {}

    for spec in source_specs:
        file_path = spec["path"]
        source_name = str(spec["name"])
        label = int(spec["label"])
        if not file_path.exists() or file_path.stat().st_size == 0:
            audit_sources[source_name] = {
                "path": str(file_path),
                "label": label,
                "raw_count": 0,
                "after_cap": 0,
                "normalized_valid": 0,
                "unique_normalized": 0,
            }
            continue

        extracted = spec["loader"](file_path)
        raw_count = len(extracted)
        capped = _sample_cap(extracted, MAX_SAMPLES_PER_SOURCE, rng)

        normalized = [normalize_url(url) for url in capped]
        valid_urls = [url for url in normalized if url]
        unique_urls = sorted(set(valid_urls))

        rows.extend((url, label, source_name) for url in unique_urls)
        audit_sources[source_name] = {
            "path": str(file_path),
            "label": label,
            "raw_count": raw_count,
            "after_cap": len(capped),
            "normalized_valid": len(valid_urls),
            "unique_normalized": len(unique_urls),
        }

    return rows, audit_sources


def run(base_dir: str = "datasets", output_dir: str = "datasets_processed") -> str:
    base = _resolve_input_dir(base_dir)
    output = _resolve_output_dir(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    rng = random.Random(RANDOM_SEED)

    source_rows, source_audit = _collect_source_rows(base, rng)
    if not source_rows:
        raise RuntimeError("No URL rows extracted from raw datasets.")

    label_map: dict[str, int] = {}
    conflict_count = 0
    for url, label, _source in source_rows:
        previous = label_map.get(url)
        if previous is None:
            label_map[url] = label
            continue
        if previous != label:
            conflict_count += 1
            # Conservative precedence: if any source marks a URL malicious, keep malicious.
            if label == 1:
                label_map[url] = 1

    malicious = [url for url, label in label_map.items() if label == 1]
    benign = [url for url, label in label_map.items() if label == 0]

    if not benign or not malicious:
        raise RuntimeError(
            f"URL preprocessing requires both classes. benign={len(benign)} malicious={len(malicious)}"
        )

    target = min(len(benign), len(malicious))
    if TARGET_SAMPLES_PER_CLASS > 0:
        target = min(target, TARGET_SAMPLES_PER_CLASS)
    if target < MIN_SAMPLES_PER_CLASS:
        raise RuntimeError(
            "Not enough balanced URL samples after normalization and dedup. "
            f"target={target}, required_min={MIN_SAMPLES_PER_CLASS}."
        )

    benign_sample = rng.sample(benign, target)
    benign_sample, benign_variant_replacements = _inject_benign_variants(benign_sample, rng)
    malicious_sample = rng.sample(malicious, target)

    url_df = pd.concat(
        [
            build_url_features(malicious_sample, label=1),
            build_url_features(benign_sample, label=0),
        ],
        ignore_index=True,
    )
    url_df = url_df.sample(frac=1.0, random_state=RANDOM_SEED).reset_index(drop=True)

    output_csv = write_processed_dataset(url_df, output / "url_training.csv")
    audit_payload = {
        "config": {
            "random_seed": RANDOM_SEED,
            "target_samples_per_class": TARGET_SAMPLES_PER_CLASS,
            "min_samples_per_class": MIN_SAMPLES_PER_CLASS,
            "max_samples_per_source": MAX_SAMPLES_PER_SOURCE,
            "csv_chunk_size": CSV_CHUNK_SIZE,
            "benign_variant_ratio": BENIGN_VARIANT_RATIO,
        },
        "source_audit": source_audit,
        "merged": {
            "total_unique_urls": len(label_map),
            "malicious_unique": len(malicious),
            "benign_unique": len(benign),
            "label_conflicts_resolved_to_malicious": conflict_count,
        },
        "balanced_sampling": {
            "target_per_class": target,
            "malicious_selected": len(malicious_sample),
            "benign_selected": len(benign_sample),
            "benign_variant_replacements": benign_variant_replacements,
            "final_rows": len(url_df),
        },
        "output_csv": output_csv,
    }
    (output / "url_training_audit.json").write_text(json.dumps(audit_payload, indent=2), encoding="utf-8")
    return output_csv


if __name__ == "__main__":
    out = run(base_dir="datasets", output_dir="datasets_processed")
    print(out)
