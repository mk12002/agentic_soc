"""Tests for 30GB RAM optimization configuration fields."""

from soc_platform.domains.phishing.engine.configs.settings import Settings


def test_30gb_optimization_fields_present():
    """Verify that all 30GB RAM optimization fields are present with correct defaults."""
    settings = Settings()
    
    # Check Orchestrator Caching & Deduplication
    assert hasattr(settings, "orchestrator_max_concurrent_analyses")
    assert settings.orchestrator_max_concurrent_analyses == 50
    assert hasattr(settings, "orchestrator_worker_pool_size")
    assert settings.orchestrator_worker_pool_size == 16
    assert hasattr(settings, "orchestrator_queue_depth")
    assert settings.orchestrator_queue_depth == 500
    assert hasattr(settings, "request_deduplication_enabled")
    assert settings.request_deduplication_enabled is True
    
    # Check Caching Memory Sizes
    assert hasattr(settings, "cache_ioc_memory_size_mb")
    assert settings.cache_ioc_memory_size_mb == 1024
    assert hasattr(settings, "cache_url_reputation_size_mb")
    assert settings.cache_url_reputation_size_mb == 512
    assert hasattr(settings, "cache_threat_intel_ttl_seconds")
    assert settings.cache_threat_intel_ttl_seconds == 3600
    assert hasattr(settings, "cache_model_artifacts_enabled")
    assert settings.cache_model_artifacts_enabled is True
    assert hasattr(settings, "enable_model_preloading")
    assert settings.enable_model_preloading is True

    # Check SLM Parameters
    assert hasattr(settings, "slm_max_sequence_length")
    assert settings.slm_max_sequence_length == 256
    assert hasattr(settings, "slm_max_words_per_sample")
    assert settings.slm_max_words_per_sample == 512
    assert hasattr(settings, "slm_max_samples_per_class")
    assert settings.slm_max_samples_per_class == 500000

    # Check Preprocessing Parameters
    assert hasattr(settings, "preprocessing_chunk_size_mb")
    assert settings.preprocessing_chunk_size_mb == 256
    assert hasattr(settings, "preprocessing_workers")
    assert settings.preprocessing_workers == 8
    assert hasattr(settings, "preprocessing_keep_features_in_memory")
    assert settings.preprocessing_keep_features_in_memory is True

    # Check Azure / Graph
    assert hasattr(settings, "graph_tenant_id")
    assert hasattr(settings, "azure_search_enabled")
    assert settings.azure_search_enabled is True
