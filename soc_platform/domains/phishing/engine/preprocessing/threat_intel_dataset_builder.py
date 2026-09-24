"""
Threat Intelligence Dataset Builder

This utility ingests the raw CSV feeds from `datasets/threat_intelligence`,
cleans and normalizes the data, and converts them into the unified 
`ioc_reference_schema` as a Parquet dataset for the Threat Intel Agent.
"""

from pathlib import Path
import pandas as pd
from datetime import datetime, timezone

from soc_platform.domains.phishing.engine.preprocessing.threat_intel_feature_contract import ioc_reference_schema, validate_dataframe
from soc_platform.domains.phishing.engine.services.logging_service import get_service_logger

logger = get_service_logger("threat_intel_dataset_builder")

# Base directory for the threat intel datasets relative to the project root
DATASET_DIR = Path("../../datasets/threat_intelligence").resolve()
OUTPUT_DIR = Path("../../datasets_processed/threat_intel").resolve()


def create_base_ioc_df(df: pd.DataFrame, ioc_col: str, ioc_type: str, feed_source: str, 
                       default_reliability: float = 0.8) -> pd.DataFrame:
    """Helper to convert a raw CSV into the expected IOC Reference Schema."""
    now = datetime.now(timezone.utc)
    
    # Map the relevant columns to the standard schema
    std_df = pd.DataFrame()
    std_df["ioc_value"] = df[ioc_col].astype(str)
    std_df["ioc_type"] = ioc_type
    std_df["feed_source"] = feed_source
    std_df["source_reliability"] = default_reliability
    std_df["first_seen_utc"] = pd.to_datetime(now)  # Default unless provided
    std_df["last_seen_utc"] = pd.to_datetime(now)
    std_df["confidence_score"] = 0.9  # Default high confidence for known feeds
    std_df["threat_type"] = "unknown"
    std_df["malware_family"] = "unknown"
    std_df["status"] = "active"
    std_df["tags"] = [[] for _ in range(len(df))]
    
    return std_df


def ingest_domains() -> pd.DataFrame:
    """Ingest malicious_domains.csv"""
    file_path = DATASET_DIR / "domains" / "malicious_domains.csv"
    if not file_path.exists():
        logger.warning(f"File not found: {file_path}")
        return pd.DataFrame()
        
    df = pd.read_csv(file_path)
    # Assuming the domain column is the first one or named 'domain'
    col = 'domain' if 'domain' in df.columns else df.columns[0]
    
    return create_base_ioc_df(df, ioc_col=col, ioc_type="domain", feed_source="malicious_domains.csv")


def ingest_ips() -> pd.DataFrame:
    """Ingest FeodoTracker and generic malicious IPs."""
    frames = []
    
    feodo_path = DATASET_DIR / "ips" / "feodotracker_ips.csv"
    if feodo_path.exists():
        # Feodo Tracker has a specific format, often commented lines at the top
        try:
            df_feodo = pd.read_csv(feodo_path, comment='#')
            col = 'ip_address' if 'ip_address' in df_feodo.columns else df_feodo.columns[0]
            std_feodo = create_base_ioc_df(df_feodo, ioc_col=col, ioc_type="ip", feed_source="feodotracker", default_reliability=0.95)
            std_feodo["malware_family"] = df_feodo.get("malware", "unknown")
            frames.append(std_feodo)
        except Exception as e:
            logger.error(f"Failed to parse FeodoTracker: {e}")

    mal_ips_path = DATASET_DIR / "ips" / "malicious_ips.csv"
    if mal_ips_path.exists():
        df_ips = pd.read_csv(mal_ips_path)
        col = 'ip' if 'ip' in df_ips.columns else df_ips.columns[0]
        frames.append(create_base_ioc_df(df_ips, ioc_col=col, ioc_type="ip", feed_source="malicious_ips.csv"))
        
    return pd.concat(frames, ignore_index=True) if frames else pd.DataFrame()


def ingest_urls() -> pd.DataFrame:
    """Ingest URLhaus and generic malicious URLs."""
    frames = []
    
    urlhaus_path = DATASET_DIR / "urls" / "urlhaus_urls.csv"
    if urlhaus_path.exists():
        try:
            # URLhaus uses comment='#' and has specific columns
            df_uh = pd.read_csv(urlhaus_path, comment='#')
            col = 'url' if 'url' in df_uh.columns else df_uh.columns[0]
            std_uh = create_base_ioc_df(df_uh, ioc_col=col, ioc_type="url", feed_source="urlhaus", default_reliability=0.95)
            std_uh["threat_type"] = "malware_download"
            frames.append(std_uh)
        except Exception as e:
            logger.error(f"Failed to parse URLhaus: {e}")

    mal_urls_path = DATASET_DIR / "urls" / "malicious_urls.csv"
    if mal_urls_path.exists():
        df_urls = pd.read_csv(mal_urls_path)
        col = 'url' if 'url' in df_urls.columns else df_urls.columns[0]
        frames.append(create_base_ioc_df(df_urls, ioc_col=col, ioc_type="url", feed_source="malicious_urls.csv"))
        
    return pd.concat(frames, ignore_index=True) if frames else pd.DataFrame()


def ingest_hashes() -> pd.DataFrame:
    """Ingest Malware Hashes."""
    file_path = DATASET_DIR / "hashes" / "full.csv"
    if not file_path.exists():
        logger.warning(f"File not found: {file_path}")
        return pd.DataFrame()
        
    df = pd.read_csv(file_path)
    col = 'hash' if 'hash' in df.columns else df.columns[0]
    
    return create_base_ioc_df(df, ioc_col=col, ioc_type="hash", feed_source="hash_full.csv")


def build_unified_ioc_database():
    """Builds and saves the complete IOC reference database as Parquet."""
    logger.info("Starting IOC database build...")
    
    df_domains = ingest_domains()
    df_ips = ingest_ips()
    df_urls = ingest_urls()
    df_hashes = ingest_hashes()
    
    all_iocs = pd.concat([df_domains, df_ips, df_urls, df_hashes], ignore_index=True)
    
    if all_iocs.empty:
        logger.error("No data found to process.")
        return
        
    # Drop completely empty rows or NA IOC values
    all_iocs = all_iocs.dropna(subset=['ioc_value'])
    all_iocs['ioc_value'] = all_iocs['ioc_value'].str.strip().str.lower()
    
    # Deduplicate keeping highest reliability
    all_iocs = all_iocs.sort_values('source_reliability', ascending=False)
    all_iocs = all_iocs.drop_duplicates(subset=['ioc_value', 'ioc_type'], keep='first')
    
    logger.info(f"Unified IOC database created with {len(all_iocs)} unique indicators.")
    
    # Validate against PyArrow Contract
    if validate_dataframe(all_iocs, ioc_reference_schema):
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        out_path = OUTPUT_DIR / "unified_ioc_reference.parquet"
        
        all_iocs.to_parquet(out_path, engine='pyarrow', schema=ioc_reference_schema)
        logger.info(f"Successfully saved to {out_path}")
    else:
        logger.error("Schema validation failed. File not saved.")


if __name__ == "__main__":
    build_unified_ioc_database()
