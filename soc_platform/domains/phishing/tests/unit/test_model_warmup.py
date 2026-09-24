"""Tests for the model warmup system."""

import pytest
from soc_platform.domains.phishing.engine.agents.model_warmup import ModelWarmup

class MockModelWarmup(ModelWarmup):
    def _warmup_header_agent(self): return "mock_header"
    def _warmup_content_agent(self): return "mock_content"
    def _warmup_url_agent(self): return "mock_url"
    def _warmup_attachment_agent(self): return "mock_attachment"
    def _warmup_sandbox_agent(self): return "mock_sandbox"
    def _warmup_threat_intel_agent(self): return "mock_threat"
    def _warmup_user_behavior_agent(self): raise Exception("Simulated Failure")

def test_warmup_all_models():
    from soc_platform.domains.phishing.engine.configs.settings import settings
    old_val = settings.enable_model_preloading
    settings.enable_model_preloading = True
    
    try:
        warmup = MockModelWarmup()
        results = warmup.warmup_all_models()
        
        assert len(results) == 7
        assert results["header_agent"]["status"] == "✓ loaded"
        assert results["header_agent"]["model"] == "mock_header"
        
        # Test failure case
        assert results["user_behavior_agent"]["status"] == "failed"
        assert "Simulated Failure" in results["user_behavior_agent"]["error"]
    finally:
        settings.enable_model_preloading = old_val

def test_warmup_disabled():
    from soc_platform.domains.phishing.engine.configs.settings import settings
    old_val = settings.enable_model_preloading
    settings.enable_model_preloading = False
    
    try:
        warmup = MockModelWarmup()
        results = warmup.warmup_all_models()
        
        assert len(results) == 0
    finally:
        settings.enable_model_preloading = old_val

def test_warmup_summary():
    warmup = MockModelWarmup()
    warmup.warmup_times = {"header_agent": 150.5, "url_agent": 45.2}
    summary = warmup.get_warmup_summary()
    assert "header_agent" in summary
    assert "url_agent" in summary
    assert "195.7 ms" in summary  # Total
