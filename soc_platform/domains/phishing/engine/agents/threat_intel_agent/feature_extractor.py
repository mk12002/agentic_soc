"""
Feature extractor for the Threat Intelligence Agent.

Transforms candidate IOCs + IOCStore metadata into consistent ML features.
"""

import time
from typing import Any

from soc_platform.domains.phishing.engine.preprocessing.threat_intel_feature_contract import (
    extract_features_from_matches,
)
from soc_platform.domains.phishing.engine.services.logging_service import get_agent_logger

logger = get_agent_logger("threat_intel_agent")


def extract_features(
    data: dict[str, Any], 
    store_matches: list[str], 
    ioc_store: Any
) -> dict[str, Any]:
    """
    Extract features from candidate IOC lists and matched database records.

    Args:
        data: Email payload containing `"iocs": {"domains": [], "ips": [], "hashes": []}`
        store_matches: List of indicator strings that successfully matched in the IOCStore.
        ioc_store: The IOCStore instance for querying metadata.

    Returns:
        Dictionary of extracted features ready for model inference.
    """
    logger.debug("Extracting mapped ML features", agent="threat_intel_agent")
    
    # 1. Grab candidates (must remain identical string arrays as the API produced)
    iocs = data.get("iocs", {}) or {}
    candidate_domains = iocs.get("domains", []) or []
    candidate_ips = iocs.get("ips", []) or []
    candidate_hashes = iocs.get("hashes", []) or []
    
    # 2. Grab full row metadata for the matched indicators from the store.
    # The IOCStore currently only returns a `list[str]` of indicators.
    # To satisfy the ML contract, we need the full SQLite rows (ioc_type, source, first_seen_ts).
    matched_rows = []
    if store_matches:
        try:
            placeholders = ",".join("?" for _ in store_matches)
            with ioc_store._connect() as conn:
                rows = conn.execute(
                    f"SELECT indicator, ioc_type, source, first_seen_ts, updated_ts "
                    f"FROM iocs WHERE indicator IN ({placeholders})",  # nosec B608
                    store_matches,
                ).fetchall()
                
            for r in rows:
                matched_rows.append({
                    "indicator": r[0],
                    "ioc_type": r[1],
                    "source": r[2],
                    "first_seen_ts": r[3],
                    "updated_ts": r[4],
                })
        except Exception as e:
            logger.error("Failed to query IOC metadata: %s", e)

    # 3. Pass to the unified feature generator
    now_ts = int(time.time())
    features = extract_features_from_matches(
        candidate_domains=candidate_domains,
        candidate_ips=candidate_ips,
        candidate_hashes=candidate_hashes,
        matched_rows=matched_rows,
        now_ts=now_ts
    )

    logger.debug("Features extracted", num_features=len(features))
    return features
