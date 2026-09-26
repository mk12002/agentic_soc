"""
Request deduplication system for email analysis.

Implements fingerprinting and caching of identical email analyses to reduce
redundant computation and latency for repeated phishing campaigns.

Uses Redis for distributed cache with TTL-based expiration.
"""

from __future__ import annotations

import hashlib
import importlib
import json
from datetime import UTC, datetime
from typing import Any

from soc_platform.domains.phishing.engine.services.logging_service import get_service_logger

# Resolve the canonical settings singleton at runtime to avoid duplicate
# cached `settings` instances when tests or modules import the settings
# under different package names (e.g., `src.configs.settings` vs
# `soc_platform.domains.phishing.engine.configs.settings`). Prefer the `email_security`-prefixed
# module when available so tests that mutate that object are respected.


def _get_settings_module():
    """Return the settings object from the most appropriate module."""
    try:
        m = importlib.import_module("soc_platform.domains.phishing.engine.configs.settings")
        return getattr(m, "settings", None)
    except Exception:
        try:
            m = importlib.import_module("soc_platform.domains.phishing.engine.configs.settings")
            return getattr(m, "settings", None)
        except Exception:
            return None


settings = _get_settings_module()

logger = get_service_logger("deduplication")


def compute_email_fingerprint(
    headers: dict[str, Any],
    body: str,
    urls: list[str],
    attachment_hashes: list[str],
) -> str:
    """
    Compute a stable SHA256 fingerprint for an email.
    
    Fingerprint includes:
    - Normalized headers (to, from, subject)
    - Body content (normalized)
    - URL set (sorted, deduplicated)
    - Attachment SHA256 hashes (sorted)
    
    This ensures identical emails produce the same fingerprint regardless
    of minor formatting differences or header ordering.
    
    Args:
        headers: Email headers dict
        body: Email body text
        urls: List of extracted URLs
        attachment_hashes: List of attachment SHA256 hashes
    
    Returns:
        SHA256 hex digest (64 chars)
    """
    # Normalize and extract key headers
    normalized_to = headers.get("to", "").lower().strip()
    normalized_from = headers.get("from", "").lower().strip()
    normalized_subject = headers.get("subject", "").lower().strip()
    
    # Normalize body (lowercase, strip extra whitespace)
    normalized_body = body.lower().strip()
    
    # Deduplicate and sort URLs for consistent ordering
    unique_urls = sorted({url.lower() for url in urls})
    
    # Sort attachment hashes
    sorted_attachment_hashes = sorted(attachment_hashes)
    
    # Combine all components
    fingerprint_data = {
        "to": normalized_to,
        "from": normalized_from,
        "subject": normalized_subject,
        "body": normalized_body,
        "urls": unique_urls,
        "attachments": sorted_attachment_hashes,
    }
    
    # Create stable JSON and hash it
    fingerprint_json = json.dumps(fingerprint_data, sort_keys=True, separators=(",", ":"))
    fingerprint_hash = hashlib.sha256(fingerprint_json.encode()).hexdigest()
    
    logger.debug(
        "Computed email fingerprint",
        fingerprint=fingerprint_hash,
        urls_count=len(unique_urls),
        attachments_count=len(sorted_attachment_hashes),
    )
    
    return fingerprint_hash


class DeduplicationCache:
    """
    Caches email analysis results by fingerprint.
    
    Supports:
    - Redis-backed caching for distributed deployments
    - TTL-based expiration (configurable)
    - Cache hit/miss metrics
    - Graceful degradation if Redis unavailable
    """
    
    def __init__(self, redis_client: Any | None = None):
        """
        Initialize deduplication cache.
        
        Args:
            redis_client: Optional Redis client. If None, uses lazy initialization.
        """
        self.redis_client = redis_client
        self.ttl_seconds = int(settings.orchestrator_cache_ttl_seconds or 3600)
        self.enabled = bool(settings.request_deduplication_enabled)
        self.cache_prefix = "email_dedup:"
        self.stats = {
            "hits": 0,
            "misses": 0,
            "errors": 0,
        }
    
    def _get_redis(self) -> Any | None:
        """Lazy initialize Redis client if needed."""
        if self.redis_client is None:
            try:
                import redis
                self.redis_client = redis.from_url(
                    settings.redis_url or "redis://localhost:6379/0",
                    decode_responses=True,
                )
                # Test connection
                self.redis_client.ping()
                logger.info("Redis deduplication cache initialized")
            except Exception as e:
                logger.warning("Failed to initialize Redis for deduplication", error=str(e))
                return None
        return self.redis_client
    
    def get_cached_result(self, fingerprint: str) -> dict[str, Any] | None:
        """
        Retrieve cached analysis result by fingerprint.
        
        Args:
            fingerprint: Email fingerprint (SHA256)
        
        Returns:
            Cached result dict if found, None otherwise
        """
        if not self.enabled:
            return None
        
        redis = self._get_redis()
        if redis is None:
            return None
        
        try:
            cache_key = f"{self.cache_prefix}{fingerprint}"
            cached_json = redis.get(cache_key)
            
            if cached_json:
                self.stats["hits"] += 1
                logger.debug("Deduplication cache hit", fingerprint=fingerprint)
                result = json.loads(cached_json)
                # Update access timestamp
                result["dedup_cache_hit_count"] = result.get("dedup_cache_hit_count", 0) + 1
                result["dedup_last_used_ts"] = datetime.now(UTC).isoformat()
                return result
            
            self.stats["misses"] += 1
            logger.debug("Deduplication cache miss", fingerprint=fingerprint)
            return None
            
        except Exception as e:
            self.stats["errors"] += 1
            logger.warning("Error retrieving from dedup cache", error=str(e), fingerprint=fingerprint)
            return None
    
    def cache_result(self, fingerprint: str, result: dict[str, Any]) -> bool:
        """
        Cache an analysis result by fingerprint.
        
        Args:
            fingerprint: Email fingerprint (SHA256)
            result: Analysis result dict to cache
        
        Returns:
            True if cached successfully, False otherwise
        """
        if not self.enabled:
            return False
        
        redis = self._get_redis()
        if redis is None:
            return False
        
        try:
            cache_key = f"{self.cache_prefix}{fingerprint}"
            
            # Add dedup metadata to result
            result_copy = result.copy()
            result_copy["dedup_fingerprint"] = fingerprint
            result_copy["dedup_cached_ts"] = datetime.now(UTC).isoformat()
            result_copy["dedup_cache_hit_count"] = 0
            
            result_json = json.dumps(result_copy)
            redis.setex(cache_key, self.ttl_seconds, result_json)
            
            logger.debug(
                "Cached analysis result",
                fingerprint=fingerprint,
                ttl_seconds=self.ttl_seconds,
            )
            return True
            
        except Exception as e:
            logger.warning("Error caching result in dedup cache", error=str(e), fingerprint=fingerprint)
            return False
    
    def invalidate(self, fingerprint: str) -> bool:
        """
        Invalidate cached result for a fingerprint.
        
        Useful when analysis logic changes and old results are stale.
        
        Args:
            fingerprint: Email fingerprint to invalidate
        
        Returns:
            True if invalidated, False otherwise
        """
        if not self.enabled:
            return False
        
        redis = self._get_redis()
        if redis is None:
            return False
        
        try:
            cache_key = f"{self.cache_prefix}{fingerprint}"
            redis.delete(cache_key)
            logger.debug("Invalidated dedup cache entry", fingerprint=fingerprint)
            return True
        except Exception as e:
            logger.warning("Error invalidating dedup cache", error=str(e), fingerprint=fingerprint)
            return False
    
    def get_stats(self) -> dict[str, Any]:
        """Get cache hit/miss statistics."""
        total = self.stats["hits"] + self.stats["misses"]
        hit_rate = (self.stats["hits"] / total * 100) if total > 0 else 0
        
        return {
            "enabled": self.enabled,
            "hits": self.stats["hits"],
            "misses": self.stats["misses"],
            "errors": self.stats["errors"],
            "total": total,
            "hit_rate_percent": round(hit_rate, 2),
            "ttl_seconds": self.ttl_seconds,
        }


# Global dedup cache instance
_dedup_cache: DeduplicationCache | None = None


def get_dedup_cache() -> DeduplicationCache:
    """Get or create the global deduplication cache instance."""
    global _dedup_cache
    if _dedup_cache is None:
        _dedup_cache = DeduplicationCache()
    return _dedup_cache


def dedup_email_analysis(
    email_data: dict[str, Any],
) -> tuple[dict[str, Any] | None, bool, str | None]:
    """
    Check if email analysis result is cached via deduplication.
    
    Utility function for orchestrator to check before running full pipeline.
    
    Args:
        email_data: Email dict with keys: headers, body, urls, attachment_hashes
    
    Returns:
        Tuple of (cached_result, was_cached, fingerprint):
        - cached_result: Analysis result if found, None otherwise
        - was_cached: Boolean indicating if result was from cache
        - fingerprint: Computed email fingerprint (SHA256)
    """
    # Evaluate current settings at call time (tests may mutate settings)
    current_settings = _get_settings_module() or settings
    if not (current_settings and getattr(current_settings, "request_deduplication_enabled", False)):
        return None, False, None
    
    try:
        # Extract dedup components
        headers = email_data.get("headers", {})
        body = email_data.get("body", "")
        urls = email_data.get("urls", [])
        attachments = email_data.get("attachments", [])
        
        # Compute attachment hashes
        attachment_hashes = [att.get("sha256") for att in attachments if att.get("sha256")]
        
        # Compute fingerprint
        fingerprint = compute_email_fingerprint(headers, body, urls, attachment_hashes)
        
        # Check cache
        cache = get_dedup_cache()
        cached_result = cache.get_cached_result(fingerprint)
        
        if cached_result:
            logger.info(
                "Deduplication cache hit - skipping full analysis",
                fingerprint=fingerprint,
                analysis_id=email_data.get("analysis_id"),
            )
            return cached_result, True, fingerprint
        
        return None, False, fingerprint
        
    except Exception as e:
        logger.warning("Error in dedup check", error=str(e))
        return None, False, None
