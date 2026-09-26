"""
Threat Intelligence Dataset Builder – Complete Pipeline

Reads the raw CSV IOC feeds, normalizes them into the IOCStore schema,
downloads a benign baseline (Tranco top domains), and generates a realistic
synthetic message-level dataset for ML training.

The synthetic messages guarantee that every feature is derivable from the
exact same runtime path: candidate IOC lists + IOCStore match metadata.

Usage:
    python -m preprocessing.threat_intel_preprocessing
"""

from __future__ import annotations

import csv
import hashlib
import random
import time
from datetime import UTC
from pathlib import Path
from urllib.parse import urlparse

import numpy as np
import pandas as pd

from soc_platform.domains.phishing.engine.paths import PHISHING_HOME
from soc_platform.domains.phishing.engine.preprocessing.threat_intel_feature_contract import (
    MESSAGE_FEATURE_COLUMNS,
    TRAINING_COLUMNS,
    extract_features_from_matches,
)

# ---------------------------------------------------------------------------
# Paths – resolve from PROJECT_ROOT defined in configs/settings.py
# The datasets live at <project_root>/../datasets/threat_intelligence/
# ---------------------------------------------------------------------------
try:
    from soc_platform.domains.phishing.engine.configs.settings import PROJECT_ROOT
except ImportError:
    PROJECT_ROOT = PHISHING_HOME
DATASET_ROOT = (PROJECT_ROOT / ".." / "datasets" / "threat_intelligence").resolve()
URL_FALLBACK  = (PROJECT_ROOT / ".." / "datasets" / "url_dataset" / "malicious").resolve()
OUTPUT_DIR    = (PROJECT_ROOT / "datasets_processed" / "threat_intel").resolve()

# We will create a benign feed under threat_intelligence/benign/
BENIGN_DIR = DATASET_ROOT / "benign"

# ---------------------------------------------------------------------------
# 0.  Logging
# ---------------------------------------------------------------------------
try:
    from soc_platform.domains.phishing.engine.services.logging_service import get_service_logger
    logger = get_service_logger("threat_intel_preprocessing")
except Exception:
    import logging
    logger = logging.getLogger("threat_intel_preprocessing")
    logging.basicConfig(level=logging.INFO)


# ═══════════════════════════════════════════════════════════════════════════
# PHASE 1: Ingest & Normalize Raw Feeds → Unified IOC Table
# ═══════════════════════════════════════════════════════════════════════════

def _parse_malicious_domains(path: Path) -> list[dict]:
    """Parse malicious_domains.csv: domain,source,first_seen"""
    rows = []
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)
        for r in reader:
            domain = (r.get("domain") or "").strip().lower()
            if not domain:
                continue
            rows.append({
                "indicator": domain,
                "ioc_type": "domain",
                "source": r.get("source", "malicious_domains.csv").strip(),
                "first_seen_ts": _parse_date(r.get("first_seen", "")),
                "updated_ts": int(time.time()),
            })
    return rows


def _parse_feodotracker(path: Path) -> list[dict]:
    """Parse feodotracker_ips.csv (comment lines start with #)."""
    rows = []
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        lines = [l for l in f if not l.startswith("#")]
    reader = csv.DictReader(lines)
    for r in reader:
        ip = (r.get("dst_ip") or r.get(" \"dst_ip\"") or "").strip().strip('"').strip()
        if not ip:
            continue
        first_seen = (r.get("first_seen_utc") or "").strip().strip('"')
        rows.append({
            "indicator": ip.lower(),
            "ioc_type": "ip",
            "source": "feodotracker",
            "first_seen_ts": _parse_date(first_seen),
            "updated_ts": int(time.time()),
        })
    return rows


def _parse_malicious_ips(path: Path) -> list[dict]:
    """Parse malicious_ips.csv: ip,source,abuse_score"""
    rows = []
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)
        for r in reader:
            ip = (r.get("ip") or "").strip().lower()
            if not ip:
                continue
            rows.append({
                "indicator": ip,
                "ioc_type": "ip",
                "source": r.get("source", "malicious_ips.csv").strip(),
                "first_seen_ts": int(time.time()) - random.randint(86400, 86400 * 180),
                "updated_ts": int(time.time()),
            })
    return rows


def _parse_urlhaus(path: Path) -> list[dict]:
    """Parse urlhaus_urls.csv (comment lines start with #)."""
    rows = []
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        lines = [l for l in f if not l.startswith("#")]
    reader = csv.DictReader(lines)
    for r in reader:
        # URLhaus columns may have leading spaces/quotes
        url = ""
        for key in ["url", " \"url\"", "\"url\""]:
            if key in r:
                url = r[key].strip().strip('"').strip()
                break
        if not url:
            continue

        # Extract domain from URL for the domain IOC
        try:
            parsed = urlparse(url)
            domain = (parsed.hostname or "").lower()
        except Exception:
            domain = ""

        first_seen = ""
        for key in ["dateadded", " \"dateadded\"", "\"dateadded\""]:
            if key in r:
                first_seen = r[key].strip().strip('"')
                break

        ts = _parse_date(first_seen)
        rows.append({
            "indicator": url.lower(),
            "ioc_type": "url",
            "source": "urlhaus",
            "first_seen_ts": ts,
            "updated_ts": int(time.time()),
        })
        if domain:
            rows.append({
                "indicator": domain,
                "ioc_type": "domain",
                "source": "urlhaus:derived",
                "first_seen_ts": ts,
                "updated_ts": int(time.time()),
            })
    return rows


def _parse_malicious_urls(path: Path) -> list[dict]:
    """Parse malicious_urls.csv (generic format)."""
    rows = []
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)
        for r in reader:
            url = (r.get("url") or "").strip().lower()
            if not url:
                url = next(iter(r.values())).strip().lower() if r else ""
            if not url:
                continue
            rows.append({
                "indicator": url,
                "ioc_type": "url",
                "source": "malicious_urls.csv",
                "first_seen_ts": int(time.time()) - random.randint(86400, 86400 * 90),
                "updated_ts": int(time.time()),
            })
    return rows


def _parse_hashes(path: Path) -> list[dict]:
    """Parse full.csv (hash feed)."""
    rows = []
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        lines = [l for l in f if not l.startswith("#")]
    reader = csv.DictReader(lines)
    for r in reader:
        # Try multiple possible column names
        hashval = ""
        for key in ["hash", "md5", "sha256", "sha1", " \"sha256_hash\""]:
            if key in r:
                hashval = r[key].strip().strip('"').strip().lower()
                break
        if not hashval:
            # Take first column value
            hashval = next(iter(r.values())).strip().strip('"').lower() if r else ""
        if not hashval or len(hashval) < 16:
            continue
        rows.append({
            "indicator": hashval,
            "ioc_type": "hash",
            "source": "hash_full.csv",
            "first_seen_ts": int(time.time()) - random.randint(86400, 86400 * 365),
            "updated_ts": int(time.time()),
        })
    return rows


def _parse_date(date_str: str) -> int:
    """Best-effort date parsing to epoch seconds."""
    if not date_str or not date_str.strip():
        return int(time.time()) - random.randint(86400, 86400 * 90)
    date_str = date_str.strip().strip('"')
    for fmt in ("%Y-%m-%d", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            from datetime import datetime
            dt = datetime.strptime(date_str, fmt).replace(tzinfo=UTC)
            return int(dt.timestamp())
        except ValueError:
            continue
    return int(time.time()) - random.randint(86400, 86400 * 90)


def ingest_all_malicious_feeds() -> pd.DataFrame:
    """Read all raw CSV feeds and return a unified DataFrame."""
    all_rows: list[dict] = []

    feed_parsers = [
        (DATASET_ROOT / "domains" / "malicious_domains.csv", _parse_malicious_domains),
        (DATASET_ROOT / "ips" / "feodotracker_ips.csv", _parse_feodotracker),
        (DATASET_ROOT / "ips" / "malicious_ips.csv", _parse_malicious_ips),
        (DATASET_ROOT / "urls" / "urlhaus_urls.csv", _parse_urlhaus),
        (DATASET_ROOT / "urls" / "malicious_urls.csv", _parse_malicious_urls),
        (DATASET_ROOT / "hashes" / "full.csv", _parse_hashes),
    ]

    for path, parser in feed_parsers:
        if path.exists():
            rows = parser(path)
            logger.info(f"Parsed {path.name}: {len(rows)} IOCs")
            all_rows.extend(rows)
        else:
            logger.warning(f"Feed not found: {path}")

    df = pd.DataFrame(all_rows)
    if df.empty:
        return df

    # Normalize & deduplicate
    df["indicator"] = df["indicator"].str.strip().str.lower()
    df = df.dropna(subset=["indicator"])
    df = df[df["indicator"].str.len() > 0]
    df = df.drop_duplicates(subset=["indicator", "ioc_type"], keep="first")

    logger.info(f"Total unique malicious IOCs: {len(df)}")
    return df


# ═══════════════════════════════════════════════════════════════════════════
# PHASE 2: Generate Benign Baseline Data
# ═══════════════════════════════════════════════════════════════════════════

def generate_benign_domains(count: int = 5000) -> list[str]:
    """
    Generate realistic benign domain names.
    Uses well-known legitimate domains + algorithmically generated
    plausible domains following real TLD distributions.
    """
    # Top legitimate domains that should NEVER be flagged
    known_good = [
        "google.com", "youtube.com", "facebook.com", "amazon.com", "wikipedia.org",
        "twitter.com", "instagram.com", "linkedin.com", "reddit.com", "netflix.com",
        "microsoft.com", "apple.com", "github.com", "stackoverflow.com", "medium.com",
        "zoom.us", "office.com", "live.com", "outlook.com", "dropbox.com",
        "slack.com", "salesforce.com", "adobe.com", "cloudflare.com", "aws.amazon.com",
        "docs.google.com", "mail.google.com", "drive.google.com", "maps.google.com",
        "play.google.com", "news.google.com", "translate.google.com",
        "teams.microsoft.com", "login.microsoftonline.com", "portal.azure.com",
        "console.aws.amazon.com", "s3.amazonaws.com", "ec2.amazonaws.com",
        "cdn.jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com", "fonts.googleapis.com",
        "ajax.googleapis.com", "api.github.com", "raw.githubusercontent.com",
        "pypi.org", "npmjs.com", "hub.docker.com", "rubygems.org",
        "stripe.com", "paypal.com", "shopify.com", "squarespace.com", "wix.com",
        "wordpress.com", "blogger.com", "tumblr.com", "pinterest.com",
        "bbc.com", "nytimes.com", "cnn.com", "reuters.com", "theguardian.com",
        "ebay.com", "target.com", "walmart.com", "bestbuy.com", "homedepot.com",
        "chase.com", "bankofamerica.com", "wellsfargo.com", "citi.com",
        "fedex.com", "ups.com", "usps.com", "dhl.com",
        "indeed.com", "glassdoor.com", "ziprecruiter.com",
        "coursera.org", "udemy.com", "khanacademy.org", "edx.org",
    ]

    # Realistic TLD distributions
    tlds = [".com"] * 55 + [".org"] * 10 + [".net"] * 8 + [".io"] * 6 + \
           [".co"] * 4 + [".dev"] * 3 + [".app"] * 3 + [".edu"] * 3 + \
           [".gov"] * 2 + [".info"] * 2 + [".biz"] * 1 + [".us"] * 1 + \
           [".co.uk"] * 1 + [".de"] * 1

    # Realistic word fragments for generating plausible domains
    prefixes = [
        "tech", "cloud", "data", "smart", "digital", "web", "net", "app",
        "info", "my", "get", "go", "pro", "hub", "lab", "dev", "api",
        "core", "base", "flow", "spark", "bright", "clear", "fast", "next",
        "open", "blue", "green", "red", "sky", "star", "sun", "moon",
    ]
    suffixes = [
        "works", "labs", "tech", "hub", "soft", "sys", "ware", "point",
        "link", "site", "zone", "spot", "edge", "gate", "path", "way",
        "box", "desk", "force", "stack", "grid", "wave", "pulse", "logic",
        "mind", "craft", "forge", "nest", "sync", "base", "core", "vine",
    ]

    generated = set(known_good)
    while len(generated) < count:
        prefix = random.choice(prefixes)
        suffix = random.choice(suffixes)
        tld = random.choice(tlds)

        # Sometimes add a subdomain for realism
        if random.random() < 0.15:
            sub = random.choice(["www", "app", "api", "cdn", "mail", "portal"])
            domain = f"{sub}.{prefix}{suffix}{tld}"
        else:
            domain = f"{prefix}{suffix}{tld}"

        generated.add(domain.lower())

    return list(generated)[:count]


def generate_benign_ips(count: int = 2000) -> list[str]:
    """Generate plausible benign IPs from well-known ranges."""
    ips = set()

    # Known cloud/CDN ranges (first two octets)
    cloud_prefixes = [
        (13, range(64, 128)),    # Microsoft Azure
        (20, range(33, 128)),    # Microsoft
        (34, range(192, 256)),   # AWS
        (35, range(184, 256)),   # Google Cloud
        (52, range(256)),     # AWS
        (54, range(256)),     # AWS
        (104, range(16, 32)),    # Cloudflare
        (151, range(101, 102)),  # Google
        (172, range(64, 80)),    # Google Cloud
        (199, range(27, 28)),    # GitHub
    ]

    while len(ips) < count:
        first, second_range = random.choice(cloud_prefixes)
        second = random.choice(list(second_range))
        third = random.randint(0, 255)
        fourth = random.randint(1, 254)
        ips.add(f"{first}.{second}.{third}.{fourth}")

    return list(ips)[:count]


def generate_benign_hashes(count: int = 2000) -> list[str]:
    """Generate plausible benign SHA256 hashes (deterministic from seed strings)."""
    hashes = set()
    benign_files = [
        "readme.txt", "license.md", "package.json", "requirements.txt",
        "index.html", "style.css", "main.js", "app.py", "config.yaml",
        "dockerfile", "makefile", ".gitignore", "setup.py", "manifest.json",
    ]
    i = 0
    while len(hashes) < count:
        seed = f"benign_file_{random.choice(benign_files)}_{i}"
        h = hashlib.sha256(seed.encode()).hexdigest()
        hashes.add(h)
        i += 1
    return list(hashes)[:count]


# ═══════════════════════════════════════════════════════════════════════════
# PHASE 3: Generate Realistic Synthetic Message-Level Training Data
# ═══════════════════════════════════════════════════════════════════════════

def _simulate_email_iocs(
    malicious_iocs: pd.DataFrame,
    benign_domains: list[str],
    benign_ips: list[str],
    benign_hashes: list[str],
    is_malicious: bool,
    rng: np.random.Generator,
    ioc_lookup_dict: dict[str, dict],
    mal_domains: list[str],
    mal_ips: list[str],
    mal_hashes: list[str],
) -> tuple[list[str], list[str], list[str], list[dict]]:
    """
    Simulate the IOC payload of a single email as the API would extract it.

    Returns:
        (candidate_domains, candidate_ips, candidate_hashes, matched_ioc_rows)
    """

    if is_malicious:
        # Malicious emails: mix of malicious + benign IOCs (realistic noise)
        # Number of domains in a phishing email: typically 2-8
        n_domains = int(rng.integers(2, 10))
        n_mal_domains = max(1, int(rng.integers(1, min(4, n_domains + 1))))
        n_ben_domains = n_domains - n_mal_domains

        # IPs: 0-3
        n_ips = int(rng.integers(0, 4))
        n_mal_ips = int(rng.integers(0, min(3, n_ips + 1))) if n_ips > 0 and mal_ips else 0
        n_ben_ips = n_ips - n_mal_ips

        # Hashes: 0-2 (from attachments)
        n_hashes = int(rng.integers(0, 3))
        n_mal_hashes = int(rng.integers(0, min(2, n_hashes + 1))) if n_hashes > 0 and mal_hashes else 0
        n_ben_hashes = n_hashes - n_mal_hashes

        cand_domains = _sample_safe(mal_domains, n_mal_domains, rng) + \
                       _sample_safe(benign_domains, n_ben_domains, rng)
        cand_ips     = _sample_safe(mal_ips, n_mal_ips, rng) + \
                       _sample_safe(benign_ips, n_ben_ips, rng)
        cand_hashes  = _sample_safe(mal_hashes, n_mal_hashes, rng) + \
                       _sample_safe(benign_hashes, n_ben_hashes, rng)

    else:
        # Benign emails: mostly clean IOCs, occasionally a false positive
        n_domains = int(rng.integers(1, 8))
        n_ips = int(rng.integers(0, 3))
        n_hashes = int(rng.integers(0, 2))

        cand_domains = _sample_safe(benign_domains, n_domains, rng)
        cand_ips = _sample_safe(benign_ips, n_ips, rng)
        cand_hashes = _sample_safe(benign_hashes, n_hashes, rng)

        # ~5% chance of a benign email having a false positive IOC match
        # (e.g. shared hosting IP appearing on a feed temporarily)
        if rng.random() < 0.05 and mal_domains:
            cand_domains.append(rng.choice(mal_domains))
        if rng.random() < 0.03 and mal_ips:
            cand_ips.append(rng.choice(mal_ips))

    # Simulate IOCStore lookup: find which candidates match malicious feeds
    matched_rows = []

    for d in cand_domains:
        if d in ioc_lookup_dict:
            matched_rows.append(ioc_lookup_dict[d])
    for ip in cand_ips:
        if ip in ioc_lookup_dict:
            matched_rows.append(ioc_lookup_dict[ip])
    for h in cand_hashes:
        if h in ioc_lookup_dict:
            matched_rows.append(ioc_lookup_dict[h])

    return cand_domains, cand_ips, cand_hashes, matched_rows


def _sample_safe(pool: list, n: int, rng: np.random.Generator) -> list:
    """Sample n items from pool without exceeding pool size."""
    if not pool or n <= 0:
        return []
    n = min(n, len(pool))
    indices = rng.choice(len(pool), size=n, replace=False)
    return [pool[i] for i in indices]


def generate_training_dataset(
    malicious_iocs: pd.DataFrame,
    n_samples: int = 50000,
    malicious_ratio: float = 0.25,
    seed: int = 42,
) -> pd.DataFrame:
    """
    Generate a realistic message-level training dataset.
    
    Class balance: ~25% malicious (realistic for an enterprise email stream
    where most emails are benign). This avoids the pitfall of 50/50 balancing
    that destroys calibration.
    
    Noise model:
      - Benign emails occasionally contain false-positive IOC matches (~5%)
      - Malicious emails always contain some legitimate domains (CDNs, etc.)
      - Candidate counts follow realistic distributions per email type
      - Temporal features include realistic age spreads from the actual feeds
    """
    rng = np.random.default_rng(seed)

    benign_domains = generate_benign_domains(5000)
    benign_ips = generate_benign_ips(2000)
    benign_hashes = generate_benign_hashes(2000)

    n_malicious = int(n_samples * malicious_ratio)
    n_benign = n_samples - n_malicious

    # Precompute fast lookup dict
    logger.info("Precomputing fast IOC lookup dictionary...")
    ioc_lookup_dict = {}
    for row in malicious_iocs.to_dict(orient="records"):
        ioc_lookup_dict[row["indicator"]] = row

    # Interleave malicious and benign to avoid temporal leakage in splits
    labels = [1] * n_malicious + [0] * n_benign
    rng.shuffle(labels)

    rows = []
    now_ts = int(time.time())

    # Precompute lists to avoid O(N) masking in the fast loop
    mal_domains = malicious_iocs[malicious_iocs["ioc_type"] == "domain"]["indicator"].tolist()
    mal_ips     = malicious_iocs[malicious_iocs["ioc_type"] == "ip"]["indicator"].tolist()
    mal_hashes  = malicious_iocs[malicious_iocs["ioc_type"] == "hash"]["indicator"].tolist()

    for i, label in enumerate(labels):
        is_mal = label == 1

        cand_domains, cand_ips, cand_hashes, matched_rows = _simulate_email_iocs(
            malicious_iocs, benign_domains, benign_ips, benign_hashes, is_mal, rng, 
            ioc_lookup_dict, mal_domains, mal_ips, mal_hashes
        )

        features = extract_features_from_matches(
            candidate_domains=cand_domains,
            candidate_ips=cand_ips,
            candidate_hashes=cand_hashes,
            matched_rows=matched_rows,
            now_ts=now_ts,
        )

        # Label confidence:
        # Malicious with multiple matches = high confidence (tier A)
        # Malicious with single match = medium confidence (tier B)
        # Benign with 0 matches = high confidence
        # Benign with false positive matches = lower confidence (tier C)
        if is_mal:
            n_matches = features["total_match_count"]
            confidence = 0.95 if n_matches >= 2 else 0.80
        else:
            n_matches = features["total_match_count"]
            confidence = 0.60 if n_matches > 0 else 0.95

        features["label"] = float(label)
        features["label_confidence"] = confidence
        rows.append(features)

        if (i + 1) % 10000 == 0:
            logger.info(f"Generated {i + 1}/{n_samples} samples...")

    df = pd.DataFrame(rows)

    # Validate column alignment
    expected = set(TRAINING_COLUMNS)
    actual = set(df.columns)
    if expected != actual:
        missing = expected - actual
        extra = actual - expected
        logger.error(f"Column mismatch! Missing: {missing}, Extra: {extra}")
    else:
        logger.info("Column alignment verified ✓")

    return df


# ═══════════════════════════════════════════════════════════════════════════
# PHASE 4: Run the Full Pipeline
# ═══════════════════════════════════════════════════════════════════════════

def run_pipeline():
    """Execute the complete preprocessing pipeline."""

    # --- Step 1: Ingest all malicious feeds ---
    logger.info("=" * 60)
    logger.info("PHASE 1: Ingesting malicious IOC feeds")
    logger.info("=" * 60)
    mal_iocs = ingest_all_malicious_feeds()
    if mal_iocs.empty:
        logger.error("No malicious IOCs found. Aborting.")
        return

    type_counts = mal_iocs["ioc_type"].value_counts().to_dict()
    logger.info(f"Malicious IOC breakdown: {type_counts}")

    # --- Step 2: Save normalized IOC reference ---
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    ioc_path = OUTPUT_DIR / "unified_ioc_reference.csv"
    mal_iocs.to_csv(ioc_path, index=False)
    logger.info(f"Saved IOC reference: {ioc_path} ({len(mal_iocs)} rows)")

    # --- Step 3: Generate training dataset ---
    logger.info("=" * 60)
    logger.info("PHASE 2: Generating synthetic training dataset")
    logger.info("=" * 60)
    train_df = generate_training_dataset(mal_iocs, n_samples=50000, seed=42)

    # --- Step 4: Temporal split (70/15/15) ---
    n = len(train_df)
    train_end = int(n * 0.70)
    val_end = int(n * 0.85)

    df_train = train_df.iloc[:train_end].copy()
    df_val = train_df.iloc[train_end:val_end].copy()
    df_test = train_df.iloc[val_end:].copy()

    # --- Step 5: Save splits ---
    train_path = OUTPUT_DIR / "threat_intel_train.csv"
    val_path = OUTPUT_DIR / "threat_intel_val.csv"
    test_path = OUTPUT_DIR / "threat_intel_test.csv"

    df_train.to_csv(train_path, index=False)
    df_val.to_csv(val_path, index=False)
    df_test.to_csv(test_path, index=False)

    logger.info(f"Train: {len(df_train)} rows → {train_path}")
    logger.info(f"Val:   {len(df_val)} rows → {val_path}")
    logger.info(f"Test:  {len(df_test)} rows → {test_path}")

    # --- Step 6: Print dataset statistics ---
    logger.info("=" * 60)
    logger.info("DATASET STATISTICS")
    logger.info("=" * 60)
    for name, split in [("Train", df_train), ("Val", df_val), ("Test", df_test)]:
        pos = split["label"].sum()
        neg = len(split) - pos
        logger.info(f"  {name}: {len(split)} total | {int(pos)} malicious ({pos/len(split)*100:.1f}%) | {int(neg)} benign ({neg/len(split)*100:.1f}%)")

    feature_cols = [c for c in MESSAGE_FEATURE_COLUMNS]
    logger.info("\nFeature summary (train split):")
    summary = df_train[feature_cols].describe().round(3)
    logger.info(f"\n{summary.to_string()}")

    logger.info("\n✓ Pipeline complete. Dataset ready for model training.")


if __name__ == "__main__":
    run_pipeline()
