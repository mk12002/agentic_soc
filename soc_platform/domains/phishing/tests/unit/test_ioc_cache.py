"""Tests for the IOC multi-tier cache system."""

import time
from soc_platform.domains.phishing.engine.action_layer.ioc_cache import MultiTierIOCCache

class MockIOCStore:
    class MockConn:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def execute(self, query, params=None):
            class MockCursor:
                def fetchall(self):
                    return [("bad.com", "domain"), ("1.2.3.4", "ip")]
            return MockCursor()

    def _connect(self):
        return self.MockConn()

def test_ioc_cache_memory_management():
    """Test that cache enforces memory limits."""
    # Create cache with tiny memory limit (100 bytes)
    cache = MultiTierIOCCache(redis_client=None, max_memory_mb=0.0001)
    
    # 100 bytes is ~0.000095 MB. One entry easily exceeds this.
    cache.set("indicator1.com", "domain", {"score": 0.9}, tier="common")
    assert len(cache.memory_cache) == 1
    
    # Adding second entry should trigger eviction of the first one
    # We need to sleep to ensure last_accessed_ts is different
    time.sleep(0.01)
    cache.set("indicator2.com", "domain", {"score": 0.8}, tier="common")
    
    # Should still only be 1 item because the limit was reached
    assert len(cache.memory_cache) == 1
    assert "domain:indicator1.com" not in cache.memory_cache
    assert "domain:indicator2.com" in cache.memory_cache

def test_ioc_cache_preload():
    """Test preloading from sqlite works."""
    cache = MultiTierIOCCache(redis_client=None)
    store = MockIOCStore()
    
    loaded = cache.preload_from_sqlite(store, limit=10)
    assert loaded == 2
    
    # Check if they are in cache
    res1 = cache.get("bad.com", "domain")
    assert res1 is not None
    assert res1.get("known_bad") is True
    
    res2 = cache.get("1.2.3.4", "ip")
    assert res2 is not None
    assert res2.get("known_bad") is True

def test_ioc_cache_negative_tier():
    """Test negative caching."""
    cache = MultiTierIOCCache(redis_client=None)
    
    # Cache a negative result
    cache.set("clean.com", "domain", {"score": 0.0}, tier="negative")
    
    res = cache.get("clean.com", "domain")
    assert res is not None
    assert res.get("tier") == "negative"
