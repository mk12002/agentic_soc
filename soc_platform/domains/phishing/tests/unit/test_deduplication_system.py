"""Tests for the email deduplication system."""

from soc_platform.domains.phishing.engine.orchestrator.deduplication import (
    compute_email_fingerprint,
    DeduplicationCache,
    dedup_email_analysis,
)

def test_compute_email_fingerprint_stability():
    """Verify that fingerprint computation is stable and order-independent."""
    headers1 = {"to": " User@Example.com ", "from": "attacker@bad.com", "subject": " RE: Invoice "}
    headers2 = {"to": "user@example.com", "from": "ATTACKER@BAD.COM", "subject": "re: invoice"}
    
    body1 = "   Please open the attached file.  \n"
    body2 = "please open the attached file."
    
    urls1 = ["http://malicious.com/a", "http://malicious.com/b", "http://malicious.com/a"]
    urls2 = ["http://malicious.com/B", "http://malicious.com/A"]
    
    hashes1 = ["hash2", "hash1"]
    hashes2 = ["hash1", "hash2"]
    
    fp1 = compute_email_fingerprint(headers1, body1, urls1, hashes1)
    fp2 = compute_email_fingerprint(headers2, body2, urls2, hashes2)
    
    assert fp1 == fp2
    assert len(fp1) == 64  # SHA256 length

class MockRedis:
    def __init__(self):
        self.data = {}
        
    def get(self, key):
        return self.data.get(key)
        
    def setex(self, key, ttl, value):
        self.data[key] = value
        
    def delete(self, key):
        if key in self.data:
            del self.data[key]

def test_deduplication_cache_flow():
    """Test standard cache hit and miss flow with a mock Redis."""
    mock_redis = MockRedis()
    cache = DeduplicationCache(redis_client=mock_redis)
    cache.enabled = True
    
    fingerprint = "test_fingerprint_123"
    result = {"verdict": "phishing", "overall_risk_score": 0.95}
    
    # Initial miss
    assert cache.get_cached_result(fingerprint) is None
    
    # Cache result
    assert cache.cache_result(fingerprint, result) is True
    
    # Cache hit
    cached = cache.get_cached_result(fingerprint)
    assert cached is not None
    assert cached["verdict"] == "phishing"
    assert cached["dedup_fingerprint"] == fingerprint
    assert cached["dedup_cache_hit_count"] == 1
    
    # Invalidate
    assert cache.invalidate(fingerprint) is True
    assert cache.get_cached_result(fingerprint) is None

def test_deduplication_cache_disabled():
    """Test behavior when deduplication is disabled via config."""
    mock_redis = MockRedis()
    cache = DeduplicationCache(redis_client=mock_redis)
    cache.enabled = False
    
    assert cache.cache_result("fp", {"verdict": "clean"}) is False
    assert cache.get_cached_result("fp") is None
    
def test_dedup_email_analysis_disabled():
    from soc_platform.domains.phishing.engine.configs.settings import settings
    old_val = settings.request_deduplication_enabled
    settings.request_deduplication_enabled = False
    
    try:
        res, cached, fp = dedup_email_analysis({"body": "test"})
        assert res is None
        assert cached is False
        assert fp is None
    finally:
        settings.request_deduplication_enabled = old_val
