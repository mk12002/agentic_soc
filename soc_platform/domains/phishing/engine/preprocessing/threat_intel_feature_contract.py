"""
Threat Intelligence Feature Contract.

Defines the exact schema for Threat Intel Agent training and inference.
Every feature here is derivable at runtime from:
  1. The candidate IOC lists extracted from an email (domains, ips, hashes)
  2. The IOCStore SQLite schema: (indicator, ioc_type, source, first_seen_ts, updated_ts)

>>> ALIGNMENT RULE: If a feature cannot be computed from the above two
>>> sources during live email analysis, it MUST NOT appear here. <<<

Two schemas are defined:
  - ioc_reference_schema: The feed datastore (maps to the SQLite iocs table).
  - message_feature_columns: The ML training/inference feature vector.
"""

from __future__ import annotations

import time
from typing import Any

# ---------------------------------------------------------------------------
# 1. IOC Reference Schema (mirrors the SQLite `iocs` table in agent.py)
# ---------------------------------------------------------------------------
# These are the ONLY columns the IOCStore actually persists at runtime.
# Any training pipeline must restrict itself to information derivable from
# these columns.
IOC_REFERENCE_COLUMNS = [
    "indicator",       # str  – normalized IOC value (lowercased, stripped)
    "ioc_type",        # str  – domain | ip | hash | url | unknown
    "source",          # str  – feed file name, e.g. "malicious_domains.csv"
    "first_seen_ts",   # int  – epoch seconds when first ingested
    "updated_ts",      # int  – epoch seconds of most recent upsert
]

# ---------------------------------------------------------------------------
# 2. Message-Level Feature Vector (ML Input & Training Target)
# ---------------------------------------------------------------------------
# Every feature below can be computed at runtime by:
#   - Counting candidates from data["iocs"]["domains"|"ips"|"hashes"]
#   - Looking up matches in the IOCStore
#   - Querying the IOCStore for source/type/timestamp metadata on matches
#
# Features are grouped by derivation logic.
MESSAGE_FEATURE_COLUMNS = [
    # --- Candidate counts (from email payload directly) ---
    "candidate_domain_count",       # len(data["iocs"]["domains"])
    "candidate_ip_count",           # len(data["iocs"]["ips"])
    "candidate_hash_count",         # len(data["iocs"]["hashes"])
    "total_candidate_count",        # sum of above

    # --- Match counts (from IOCStore.lookup) ---
    "matched_domain_count",         # matches where ioc_type == "domain"
    "matched_ip_count",             # matches where ioc_type == "ip"
    "matched_hash_count",           # matches where ioc_type == "hash"
    "total_match_count",            # sum of above

    # --- Ratios (derived) ---
    "domain_match_ratio",           # matched_domain / max(candidate_domain, 1)
    "ip_match_ratio",               # matched_ip / max(candidate_ip, 1)
    "hash_match_ratio",             # matched_hash / max(candidate_hash, 1)
    "overall_match_ratio",          # total_match / max(total_candidate, 1)

    # --- Source diversity (from IOCStore source column on matches) ---
    "unique_source_count",          # number of distinct feed sources across matches
    "multi_source_match_count",     # matches confirmed by >1 independent feed

    # --- Temporal features (from IOCStore first_seen_ts/updated_ts) ---
    "newest_match_age_days",        # (now - max(updated_ts)) / 86400
    "oldest_match_age_days",        # (now - min(first_seen_ts)) / 86400
    "mean_match_age_days",          # mean of (now - first_seen_ts) for all matches
    "ioc_freshness_ratio",          # fraction of matches seen in last 30 days

    # --- Type diversity (from IOCStore ioc_type on matches) ---
    "matched_type_diversity",       # number of distinct ioc_types among matches (0-4)
]

# Full column list including the label (only present during training)
TRAINING_COLUMNS = MESSAGE_FEATURE_COLUMNS + [
    "label",                        # 1 = malicious email, 0 = benign
    "label_confidence",             # float 0-1, weight for sample importance
]


def get_zero_features() -> dict[str, float]:
    """Returns a default zero-initialized feature vector for runtime fallback."""
    return {col: 0.0 for col in MESSAGE_FEATURE_COLUMNS}


def extract_features_from_matches(
    candidate_domains: list[str],
    candidate_ips: list[str],
    candidate_hashes: list[str],
    matched_rows: list[dict[str, Any]],
    now_ts: int | None = None,
) -> dict[str, float]:
    """
    Compute the feature vector from email candidates + IOCStore match metadata.
    
    This function is used BOTH during training (on synthetic data) and during
    live inference, guaranteeing perfect alignment.
    
    Args:
        candidate_domains: Domain IOCs extracted from the email.
        candidate_ips: IP IOCs extracted from the email.
        candidate_hashes: Hash IOCs extracted from the email.
        matched_rows: List of dicts with keys matching IOC_REFERENCE_COLUMNS,
                      representing the IOCStore rows that matched.
        now_ts: Current epoch timestamp (defaults to time.time()).
    
    Returns:
        Feature dictionary aligned to MESSAGE_FEATURE_COLUMNS.
    """
    if now_ts is None:
        now_ts = int(time.time())

    n_cand_d = len(candidate_domains)
    n_cand_i = len(candidate_ips)
    n_cand_h = len(candidate_hashes)
    n_cand_total = n_cand_d + n_cand_i + n_cand_h

    # Partition matches by type
    m_domains = [r for r in matched_rows if r.get("ioc_type") == "domain"]
    m_ips     = [r for r in matched_rows if r.get("ioc_type") == "ip"]
    m_hashes  = [r for r in matched_rows if r.get("ioc_type") == "hash"]
    n_match_d = len(m_domains)
    n_match_i = len(m_ips)
    n_match_h = len(m_hashes)
    n_match_total = n_match_d + n_match_i + n_match_h

    # Source diversity
    all_sources = [r.get("source", "") for r in matched_rows]
    unique_sources = set(all_sources)
    # For multi-source: count indicators confirmed by >1 distinct source
    indicator_sources: dict[str, set[str]] = {}
    for r in matched_rows:
        ind = r.get("indicator", "")
        src = r.get("source", "")
        indicator_sources.setdefault(ind, set()).add(src)
    multi_source_count = sum(1 for sources in indicator_sources.values() if len(sources) > 1)

    # Temporal features
    first_seen_list = [r.get("first_seen_ts", now_ts) for r in matched_rows]
    updated_list    = [r.get("updated_ts", now_ts) for r in matched_rows]
    
    if matched_rows:
        newest_age = (now_ts - max(updated_list)) / 86400.0
        oldest_age = (now_ts - min(first_seen_list)) / 86400.0
        mean_age   = sum((now_ts - fs) for fs in first_seen_list) / len(first_seen_list) / 86400.0
        thirty_days_ago = now_ts - (30 * 86400)
        fresh_count = sum(1 for ts in updated_list if ts >= thirty_days_ago)
        freshness_ratio = fresh_count / len(matched_rows)
    else:
        newest_age = 0.0
        oldest_age = 0.0
        mean_age   = 0.0
        freshness_ratio = 0.0

    # Type diversity
    matched_types = set(r.get("ioc_type", "") for r in matched_rows)

    return {
        "candidate_domain_count":    float(n_cand_d),
        "candidate_ip_count":        float(n_cand_i),
        "candidate_hash_count":      float(n_cand_h),
        "total_candidate_count":     float(n_cand_total),

        "matched_domain_count":      float(n_match_d),
        "matched_ip_count":          float(n_match_i),
        "matched_hash_count":        float(n_match_h),
        "total_match_count":         float(n_match_total),

        "domain_match_ratio":        n_match_d / max(n_cand_d, 1),
        "ip_match_ratio":            n_match_i / max(n_cand_i, 1),
        "hash_match_ratio":          n_match_h / max(n_cand_h, 1),
        "overall_match_ratio":       n_match_total / max(n_cand_total, 1),

        "unique_source_count":       float(len(unique_sources)),
        "multi_source_match_count":  float(multi_source_count),

        "newest_match_age_days":     round(newest_age, 2),
        "oldest_match_age_days":     round(oldest_age, 2),
        "mean_match_age_days":       round(mean_age, 2),
        "ioc_freshness_ratio":       round(freshness_ratio, 4),

        "matched_type_diversity":    float(len(matched_types)),
    }
