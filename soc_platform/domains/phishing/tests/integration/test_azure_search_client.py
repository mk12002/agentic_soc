"""Tests for the Azure Search Client."""

from soc_platform.domains.phishing.engine.action_layer.azure_search_client import (
    AzureSearchClient,
    is_azure_search_available,
)


class MockAzureSearchClientSDK:
    def search(self, search_text, **kwargs):
        if kwargs.get("facets"):
            class MockFacetedResults:
                def get_count(self): return 42
            return MockFacetedResults()
            
        return [
            {"indicator": "bad.com", "indicator_type": "domain", "severity": "high", "@search.score": 0.95},
            {"indicator": "evil.org", "indicator_type": "domain", "severity": "medium", "@search.score": 0.85}
        ]
        
    def upload_documents(self, documents):
        return [{"succeeded": True} for _ in documents]

def test_azure_search_client_semantic_search():
    client = AzureSearchClient("mock-service", "mock-key")
    client._client = MockAzureSearchClientSDK()
    
    results = client.semantic_search("phishing domains")
    assert len(results) == 2
    assert results[0]["indicator"] == "bad.com"
    assert results[0]["score"] == 0.95
    assert client.stats["semantic_searches"] == 1

def test_azure_search_client_faceted_search():
    client = AzureSearchClient("mock-service", "mock-key")
    client._client = MockAzureSearchClientSDK()
    
    results = client.faceted_search()
    assert results["total_count"] == 42
    assert client.stats["queries"] == 1



def test_azure_search_client_upload_indicators():
    client = AzureSearchClient("mock-service", "mock-key")
    client._client = MockAzureSearchClientSDK()
    client._ensure_index = lambda: True
    
    success, failed = client.upload_indicators([{"indicator": "1.1.1.1", "indicator_type": "ip"}])
    assert success == 1
    assert failed == 0

def test_azure_search_is_available():
    from soc_platform.domains.phishing.engine.configs.settings import settings
    old_service = settings.azure_search_service
    old_key = settings.azure_search_api_key
    
    settings.azure_search_service = None
    settings.azure_search_api_key = None
    
    assert is_azure_search_available() is False
    
    settings.azure_search_service = old_service
    settings.azure_search_api_key = old_key
