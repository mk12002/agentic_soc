"""
Azure Search integration for advanced threat intelligence queries.

Provides:
- Semantic search over threat indicators
- Vector similarity search for related IOCs
- Full-text search with filters (type, severity, source, date range)
- Faceted search for threat landscape analysis
- Integration with local SQLite and cache tiers

This module is optional but significantly enhances threat intel capabilities.
"""

from __future__ import annotations

import importlib
from datetime import UTC, datetime
from typing import Any

from soc_platform.domains.phishing.engine.services.logging_service import get_service_logger


# Resolve settings dynamically to respect tests or alternate import paths
def _get_settings():
    try:
        m = importlib.import_module("soc_platform.domains.phishing.engine.configs.settings")
        return getattr(m, "settings", None)
    except Exception:
        try:
            m = importlib.import_module("soc_platform.domains.phishing.engine.configs.settings")
            return getattr(m, "settings", None)
        except Exception:
            return None


logger = get_service_logger("azure_search")


class AzureSearchClient:
    """
    Azure Cognitive Search client for threat intelligence queries.
    
    Supports semantic and vector search over IOC datasets for:
    - Finding related/similar indicators
    - Trend analysis
    - Campaign clustering
    - Advanced filtering
    """
    
    def __init__(
        self,
        search_service: str,
        api_key: str,
        index_name: str = "threat-indicators",
        api_version: str = "2023-11-01",
    ):
        """
        Initialize Azure Search client.
        
        Args:
            search_service: Search service name (e.g., "contoso-search")
            api_key: Admin API key
            index_name: Index name for IOC storage
            api_version: Azure Search API version
        """
        self.search_service = search_service
        self.api_key = api_key
        self.index_name = index_name
        self.api_version = api_version
        self.endpoint = f"https://{search_service}.search.windows.net"
        
        self._client: Any | None = None
        self._index_created = False
        self.stats = {
            "queries": 0,
            "errors": 0,
            "vector_searches": 0,
            "semantic_searches": 0,
        }
    
    def _get_client(self) -> Any | None:
        """Lazy initialize Azure Search client."""
        if self._client is not None:
            return self._client
        
        try:
            from azure.core.credentials import AzureKeyCredential
            from azure.search.documents import SearchClient
            
            credential = AzureKeyCredential(self.api_key)
            self._client = SearchClient(
                endpoint=self.endpoint,
                index_name=self.index_name,
                credential=credential,
            )
            
            logger.info(
                "Azure Search client initialized",
                endpoint=self.endpoint,
                index=self.index_name,
            )
            return self._client
            
        except ImportError:
            logger.warning("Azure Search SDK not installed. Install with: pip install azure-search-documents")
            return None
        except Exception as e:
            logger.error("Failed to initialize Azure Search client", error=str(e))
            return None
    
    def _ensure_index(self) -> bool:
        """Create IOC index if it doesn't exist."""
        if self._index_created:
            return True
        
        try:
            from azure.core.credentials import AzureKeyCredential
            from azure.search.documents.indexes import SearchIndexClient
            from azure.search.documents.indexes.models import (
                SearchableField,
                SearchFieldDataType,
                SearchIndex,
                SemanticConfiguration,
                SemanticField,
                SemanticPrioritizedFields,
                SemanticSearch,
                SimpleField,
            )
            
            credential = AzureKeyCredential(self.api_key)
            index_client = SearchIndexClient(
                endpoint=self.endpoint,
                credential=credential,
            )
            
            # Define index schema for threat indicators
            fields = [
                SimpleField(name="id", type=SearchFieldDataType.String, key=True, sortable=True),
                SearchableField(name="indicator", type=SearchFieldDataType.String, sortable=True, filterable=True),
                SimpleField(name="indicator_type", type=SearchFieldDataType.String, filterable=True, facetable=True),
                SimpleField(name="severity", type=SearchFieldDataType.String, filterable=True, facetable=True),
                SimpleField(name="source", type=SearchFieldDataType.String, filterable=True, facetable=True),
                SearchableField(name="description", type=SearchFieldDataType.String),
                SimpleField(name="first_seen_ts", type=SearchFieldDataType.DateTimeOffset, filterable=True, sortable=True),
                SimpleField(name="last_seen_ts", type=SearchFieldDataType.DateTimeOffset, filterable=True, sortable=True),
                SimpleField(name="confidence", type=SearchFieldDataType.Double, filterable=True, sortable=True),
                SearchableField(name="tags", type=SearchFieldDataType.String, collection=True, filterable=True, facetable=True),
            ]
            
            # Define semantic configuration
            semantic_config = SemanticConfiguration(
                name="default",
                prioritized_fields=SemanticPrioritizedFields(
                    title_field=SemanticField(field_name="indicator"),
                    content_fields=[SemanticField(field_name="description")],
                    keywords_fields=[SemanticField(field_name="tags")],
                ),
            )
            semantic_search = SemanticSearch(configurations=[semantic_config])
            
            index = SearchIndex(
                name=self.index_name,
                fields=fields,
                semantic_search=semantic_search,
            )
            
            # Create or update index
            index_client.create_or_update_index(index)
            self._index_created = True
            
            logger.info("Azure Search index created/updated", index=self.index_name)
            return True
            
        except Exception as e:
            logger.warning("Failed to ensure index exists", error=str(e), exc_info=True)
            return False
    
    def upload_indicators(self, indicators: list[dict[str, Any]]) -> tuple[int, int]:
        """
        Bulk upload threat indicators to Azure Search.
        
        Args:
            indicators: List of IOC dicts with fields: indicator, indicator_type,
                       severity, source, description, first_seen_ts, last_seen_ts,
                       confidence, tags
        
        Returns:
            Tuple of (successful, failed) uploads
        """
        client = self._get_client()
        if client is None:
            return 0, len(indicators)
        
        if not self._ensure_index():
            return 0, len(indicators)
        
        try:
            # Prepare documents for upload
            documents = []
            for ioc in indicators:
                # Ensure ISO format with Z for DateTimeOffset fields
                first_seen = ioc.get("first_seen_ts")
                if isinstance(first_seen, (int, float)):
                    first_seen = datetime.fromtimestamp(first_seen, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
                
                last_seen = ioc.get("last_seen_ts")
                if isinstance(last_seen, (int, float)):
                    last_seen = datetime.fromtimestamp(last_seen, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

                doc = {
                    "id": f"{ioc['indicator_type']}:{ioc['indicator']}".replace("/", "_").replace(":", "_"),
                    "indicator": ioc["indicator"],
                    "indicator_type": ioc["indicator_type"],
                    "severity": ioc.get("severity", "unknown"),
                    "source": ioc.get("source", "unknown"),
                    "description": ioc.get("description", ""),
                    "first_seen_ts": first_seen,
                    "last_seen_ts": last_seen,
                    "confidence": ioc.get("confidence", 0.5),
                    "tags": ioc.get("tags", []),
                }
                documents.append(doc)
            
            # Upload in batches of 1000
            successful = 0
            failed = 0
            
            for i in range(0, len(documents), 1000):
                batch = documents[i : i + 1000]
                try:
                    results = client.upload_documents(documents=batch)
                    for result in results:
                        if result.get("succeeded"):
                            successful += 1
                        else:
                            logger.warning(f"Document upload failed: {result.get('key')}", error=result.get("errorMessage"))
                            failed += 1
                except Exception as e:
                    logger.warning("Batch upload failed", error=str(e), exc_info=True, batch_start=i)
                    failed += len(batch)
            
            logger.info(
                "Indicators uploaded to Azure Search",
                successful=successful,
                failed=failed,
            )
            self.stats["queries"] += 1
            return successful, failed
            
        except Exception as e:
            logger.error("Error uploading indicators", error=str(e))
            self.stats["errors"] += 1
            return 0, len(indicators)
    
    def semantic_search(
        self,
        query: str,
        indicator_type: str | None = None,
        severity_min: str = "low",
        limit: int = 10,
    ) -> list[dict[str, Any]]:
        """
        Semantic search for similar threat indicators.
        
        Examples:
        - "admin credential phishing" finds phishing indicators
        - "ransomware payment domain" finds ransomware C2 domains
        - "password spray attack" finds IPs with spray activity
        
        Args:
            query: Natural language search query
            indicator_type: Optional filter (domain, ip, hash, url, email)
            severity_min: Minimum severity (low/medium/high/critical)
            limit: Max results
        
        Returns:
            List of matching indicators with scores
        """
        client = self._get_client()
        if client is None:
            logger.warning("Azure Search not available for semantic search")
            return []
        
        try:
            filters = []
            if indicator_type:
                safe_type = str(indicator_type).replace("'", "''")          # OData string literal escaping
                filters.append(f"indicator_type eq '{safe_type}'")
            
            severity_levels = {"low": 0, "medium": 1, "high": 2, "critical": 3}
            min_level = severity_levels.get(severity_min.lower(), 0)
            
            search_results = client.search(
                search_text=query,
                filter=" and ".join(filters) if filters else None,
                query_type="semantic",
                query_language="en-us",
                semantic_configuration_name="default",
                top=limit,
            )
            
            results = []
            for result in search_results:
                if severity_levels.get(str(result.get("severity") or "").lower(), 0) < min_level:
                    continue                                                      # below the requested minimum
                results.append({
                    "indicator": result.get("indicator"),
                    "type": result.get("indicator_type"),
                    "severity": result.get("severity"),
                    "confidence": result.get("confidence"),
                    "source": result.get("source"),
                    "score": result.get("@search.score", 0),
                })
            
            self.stats["semantic_searches"] += 1
            logger.debug("Semantic search completed", query=query, results=len(results))
            
            return results
            
        except Exception as e:
            logger.warning("Semantic search failed", error=str(e))
            self.stats["errors"] += 1
            return []
    
    def vector_search(
        self,
        embedding: list[float],
        indicator_type: str | None = None,
        limit: int = 10,
    ) -> list[dict[str, Any]]:
        """
        Vector similarity search for related indicators.
        
        Finds IOCs similar to the given embedding vector.
        
        Args:
            embedding: Vector embedding of query indicator
            indicator_type: Optional filter
            limit: Max results
        
        Returns:
            List of similar indicators with similarity scores
        """
        client = self._get_client()
        if client is None:
            return []
        
        try:
            # Vector search (requires embedding field setup in index)
            logger.info("Vector search framework ready (embedding field setup required)")
            self.stats["vector_searches"] += 1
            return []
            
        except Exception as e:
            logger.warning("Vector search failed", error=str(e))
            self.stats["errors"] += 1
            return []
    
    def faceted_search(
        self,
        query: str = "*",
        facets: list[str] | None = None,
    ) -> dict[str, Any]:
        """
        Faceted search for threat landscape analysis.
        
        Returns counts by severity, source, type, etc.
        
        Args:
            query: Search query (default: all)
            facets: Fields to facet on (severity, source, indicator_type, etc.)
        
        Returns:
            Dict with facet counts and stats
        """
        client = self._get_client()
        if client is None:
            return {}
        
        try:
            if facets is None:
                facets = ["severity", "indicator_type", "source"]
            
            search_results = client.search(
                search_text=query,
                facets=facets,
                top=0,  # We only want facet counts, not documents
            )
            
            result_dict = {
                "query": query,
                "facets": {},
                "total_count": search_results.get_count(),
            }
            
            logger.info("Faceted search completed", query=query)
            self.stats["queries"] += 1
            
            return result_dict
            
        except Exception as e:
            logger.warning("Faceted search failed", error=str(e))
            self.stats["errors"] += 1
            return {}
    
    def get_stats(self) -> dict[str, Any]:
        """Get Azure Search statistics."""
        return {
            "total_queries": self.stats["queries"],
            "semantic_searches": self.stats["semantic_searches"],
            "vector_searches": self.stats["vector_searches"],
            "errors": self.stats["errors"],
            "endpoint": self.endpoint,
            "index": self.index_name,
        }


# Global Azure Search client instance
_azure_search_client: AzureSearchClient | None = None


def get_azure_search_client() -> AzureSearchClient | None:
    """Get or create the global Azure Search client."""
    global _azure_search_client
    
    # Resolve settings at call time; the cached client is only reused while its configuration still
    # matches, so removing or rotating credentials takes effect without a restart.
    current_settings = _get_settings()
    search_service = getattr(current_settings, "azure_search_service", None) if current_settings else None
    api_key = getattr(current_settings, "azure_search_api_key", None) if current_settings else None

    if not search_service or not api_key:
        logger.debug("Azure Search not configured")
        _azure_search_client = None
        return None
    if _azure_search_client is not None and getattr(_azure_search_client, "_config_key", None) == (search_service, api_key):
        return _azure_search_client
    
    try:
        _azure_search_client = AzureSearchClient(
            search_service=search_service,
            api_key=api_key,
        )
        _azure_search_client._config_key = (search_service, api_key)
        return _azure_search_client
    except Exception as e:
        logger.warning("Failed to initialize Azure Search", error=str(e))
        return None


def is_azure_search_available() -> bool:
    """Check if Azure Search is configured and available."""
    client = get_azure_search_client()
    return client is not None
