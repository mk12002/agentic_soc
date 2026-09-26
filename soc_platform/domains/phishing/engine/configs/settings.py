"""
Centralized configuration management using Pydantic Settings.

Loads configuration from environment variables and .env file.
All settings are validated and typed at application startup.
"""

import logging
from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from soc_platform.domains.phishing.engine.paths import ENV_FILE, PHISHING_HOME

# Runtime artifact root (models, config, reference data); see engine/paths.py
PROJECT_ROOT = PHISHING_HOME

class Settings(BaseSettings):
    """Application settings loaded from environment variables and .env file."""

    model_config = SettingsConfigDict(
        env_file=str(ENV_FILE),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # --- Application ---
    app_env: str = Field(default="development", description="Application environment")
    app_debug: bool = Field(default=False, description="Debug mode flag (default off for production safety)")
    app_log_level: str = Field(default="INFO", description="Logging level")
    app_version: str = Field(default="1.0.0", description="Application semantic version")
    app_secret_key: str = Field(
        default="change-me-in-production", description="Application secret key"
    )

    # --- API Server ---
    api_host: str = Field(default="127.0.0.1", description="API server host (set API_HOST=0.0.0.0 inside a container)")
    api_port: int = Field(default=8000, description="API server port")
    api_workers: int = Field(default=4, description="Number of API workers")
    api_auth_enabled: bool = Field(
        default=True, description="Enable shared API key authentication for protected endpoints"
    )
    api_auth_key: str | None = Field(
        default=None, description="Shared API key required when API auth is enabled"
    )

    # --- Outbound integrations ---
    webhook_urls: str = Field(
        default="",
        description="Comma-separated webhook URLs to notify on verdict_finalized (SIEM/SOAR/Slack)",
    )

    # --- RabbitMQ ---
    rabbitmq_host: str = Field(default="localhost", description="RabbitMQ host")
    rabbitmq_port: int = Field(default=5672, description="RabbitMQ AMQP port")
    rabbitmq_user: str = Field(default="guest", description="RabbitMQ username")
    rabbitmq_password: str = Field(default="guest", description="RabbitMQ password")
    rabbitmq_heartbeat_seconds: int = Field(
        default=600,
        description="AMQP heartbeat interval in seconds (increase for long-running agent tasks)",
    )
    rabbitmq_blocked_connection_timeout_seconds: int = Field(
        default=600,
        description="Blocked connection timeout in seconds for pika connections",
    )
    new_email_exchange: str = Field(
        default="email.new.exchange", description="Exchange for new email events"
    )
    results_queue: str = Field(
        default="email.results.queue", description="Queue for agent results"
    )
    rabbitmq_dead_letter_exchange: str = Field(
        default="email.dead.letter.exchange",
        description="Dead-letter exchange for failed message processing",
    )
    rabbitmq_dead_letter_queue: str = Field(
        default="email.dead.letter.queue",
        description="Dead-letter queue for failed message processing",
    )
    rabbitmq_poison_queue: str = Field(
        default="email.poison.queue",
        description="Queue for unrecoverable failed messages",
    )
    rabbitmq_max_retries: int = Field(
        default=5, description="Maximum reconnection or message retry attempts"
    )
    rabbitmq_backoff_base: float = Field(
        default=1.0, description="Base for exponential backoff (seconds)"
    )
    rabbitmq_backoff_max: float = Field(
        default=32.0, description="Maximum backoff time (seconds)"
    )
    rabbitmq_circuit_breaker_threshold: int = Field(
        default=10, description="Number of failures before circuit breaker opens"
    )
    rabbitmq_circuit_breaker_timeout: int = Field(
        default=60, description="Time in seconds before circuit breaker attempts reset"
    )
    enable_message_compression: bool = Field(
        default=True, description="Enable gzip compression for large message payloads"
    )
    compression_threshold_kb: int = Field(
        default=10, description="Payload size threshold in KB to trigger compression"
    )

    # --- Parser / Ingestion ---
    email_drop_dir: str = Field(
        default="/mnt/email_drop", description="Directory watched for raw email files"
    )
    attachment_volume_dir: str = Field(
        default="/mnt/attachments", description="Shared attachment volume path"
    )
    parser_poll_seconds: int = Field(
        default=2, description="Polling interval for parser worker"
    )
    
    # --- Local Routing ---
    local_routing_enabled: bool = Field(
        default=True, description="Enable local folder routing for parsed emails"
    )
    local_ingestion_folder: str = Field(
        default="/mnt/data/Ingestion", description="Folder to watch for emails"
    )
    local_staging_folder: str = Field(
        default="/mnt/data/Staging", description="Temporary staging folder"
    )
    local_approved_folder: str = Field(
        default="/mnt/data/Approved", description="Final destination for safe emails"
    )
    local_quarantine_folder: str = Field(
        default="/mnt/data/Quarantine", description="Final destination for malicious emails"
    )
    local_deleted_folder: str = Field(
        default="/mnt/data/Deleted", description="Final destination for deleted emails"
    )

    # --- Google Drive Integration ---
    gdrive_credentials_path: str = Field(
        default="/app/email_security/gdrive_credentials.json", description="Path to GDrive service account JSON"
    )
    gdrive_ingestion_folder_id: str | None = Field(default=None)
    gdrive_staging_folder_id: str | None = Field(default=None)
    gdrive_approved_folder_id: str | None = Field(default=None)
    gdrive_quarantine_folder_id: str | None = Field(default=None)
    gdrive_deleted_folder_id: str | None = Field(default=None)

    # --- OCR / Attachment Text Extraction ---
    enable_ocr_extraction: bool = Field(
        default=False, description="Enable OCR extraction for image/PDF attachments"
    )
    org_context_enabled: bool = Field(
        default=False,
        description="Apply organizational risk-context multipliers (role of targeted recipient) to the fused score",
    )
    ocr_max_file_size_mb: float = Field(
        default=5.0, description="Maximum attachment size in MB for OCR extraction"
    )
    ocr_timeout_seconds: float = Field(
        default=30.0, description="Timeout in seconds for OCR requests"
    )
    azure_ocr_endpoint: str | None = Field(
        default=None, description="Azure AI Vision Endpoint"
    )
    azure_ocr_key: str | None = Field(
        default=None, description="Azure AI Vision API Key"
    )

    # --- Azure OpenAI ---
    azure_openai_endpoint: str | None = Field(
        default=None, description="Azure OpenAI endpoint"
    )
    azure_openai_api_key: str | None = Field(
        default=None, description="Azure OpenAI API key"
    )
    azure_openai_deployment: str | None = Field(
        default=None, description="Azure OpenAI model deployment name"
    )
    azure_openai_api_version: str = Field(
        default="2024-02-15-preview", description="Azure OpenAI API version"
    )
    storyline_enable_llm_mitre_enrichment: bool = Field(
        default=False,
        description="Enable Azure OpenAI enrichment for per-indicator ATT&CK mapping in storyline engine",
    )
    storyline_llm_max_indicators_per_phase: int = Field(
        default=8,
        description="Maximum indicators per phase sent to LLM for ATT&CK enrichment",
    )

    # --- Threat Intelligence API Keys ---
    virustotal_api_key: str | None = Field(
        default=None, description="VirusTotal API key"
    )
    google_safe_browsing_api_key: str | None = Field(
        default=None, description="Google Safe Browsing API key"
    )
    otx_api_key: str | None = Field(
        default=None, description="AlienVault OTX API key"
    )
    abuseipdb_api_key: str | None = Field(
        default=None, description="AbuseIPDB API key"
    )
    enable_virustotal_url_lookup: bool = Field(
        default=False, description="Enable VirusTotal URL lookups in URL agent"
    )
    enable_google_safe_browsing_lookup: bool = Field(
        default=False, description="Enable Google Safe Browsing URL lookups"
    )
    enable_openphish_lookup: bool = Field(
        default=False, description="Enable OpenPhish feed URL lookups"
    )
    enable_urlhaus_lookup: bool = Field(
        default=False, description="Enable URLhaus URL lookups"
    )
    enable_otx_lookup: bool = Field(
        default=False, description="Enable AlienVault OTX IOC lookups"
    )
    enable_abuseipdb_lookup: bool = Field(
        default=False, description="Enable AbuseIPDB IP reputation lookups"
    )
    enable_malwarebazaar_lookup: bool = Field(
        default=False, description="Enable MalwareBazaar hash lookups"
    )
    enable_virustotal_hash_lookup: bool = Field(
        default=False, description="Enable VirusTotal hash lookups in threat intel"
    )
    external_lookup_timeout_seconds: float = Field(
        default=6.0, description="Timeout in seconds for external intel API calls"
    )
    external_lookup_max_indicators: int = Field(
        default=10, description="Max indicators per type for external intel lookups"
    )
    external_lookup_cache_ttl_seconds: int = Field(
        default=21600,
        description="TTL for cached external reputation lookups to improve resilience",
    )
    openphish_feed_url: str = Field(
        default="https://openphish.com/feed.txt", description="OpenPhish feed URL"
    )
    openphish_cache_ttl_seconds: int = Field(
        default=900, description="OpenPhish feed cache TTL in seconds"
    )
    urlhaus_api_url: str = Field(
        default="https://urlhaus-api.abuse.ch/v1/url/", description="URLhaus API endpoint"
    )
    otx_api_base_url: str = Field(
        default="https://otx.alienvault.com", description="AlienVault OTX API base URL"
    )
    abuseipdb_api_url: str = Field(
        default="https://api.abuseipdb.com/api/v2/check", description="AbuseIPDB check endpoint"
    )
    malwarebazaar_api_url: str = Field(
        default="https://mb-api.abuse.ch/api/v1/", description="MalwareBazaar API endpoint"
    )
    urlscan_api_key: str | None = Field(
        default=None, description="URLScan.io API key"
    )
    shodan_api_key: str | None = Field(
        default=None, description="Shodan API key"
    )

    threat_intel_harvest_timeout_seconds: float = Field(
        default=30.0, description="Timeout in seconds for external feed harvesting"
    )
    enable_external_feed_harvesting: bool = Field(
        default=True, description="Enable API-based IOC harvesting from external providers"
    )
    abuseipdb_blacklist_url: str = Field(
        default="https://api.abuseipdb.com/api/v2/blacklist", description="AbuseIPDB blacklist endpoint"
    )
    urlhaus_recent_csv_url: str = Field(
        default="https://urlhaus.abuse.ch/downloads/csv_recent/", description="URLhaus recent CSV feed"
    )

    # --- Model Paths ---
    header_model_path: str = Field(
        default="models/header_agent/", description="Header agent model path"
    )
    content_model_path: str = Field(
        default="models/content_agent/", description="Content agent model path"
    )
    url_model_path: str = Field(
        default="models/url_agent/", description="URL agent model path"
    )
    attachment_model_path: str = Field(
        default="models/attachment_agent/", description="Attachment agent model path"
    )
    sandbox_model_path: str = Field(
        default="models/sandbox_agent/", description="Sandbox agent model path"
    )
    threat_intel_model_path: str = Field(
        default="models/threat_intel_agent/", description="Threat intel model path"
    )
    user_behavior_model_path: str = Field(
        default="models/user_behavior_agent/", description="User behavior agent model path"
    )

    # --- Dataset Paths ---
    dataset_base_path: str = Field(
        default="datasets/", description="Base dataset directory"
    )
    processed_dataset_path: str = Field(
        default="datasets_processed/", description="Processed dataset directory"
    )

    # --- Database ---
    database_url: str = Field(
        default="postgresql://user:password@localhost:5432/email_security",
        description="Database connection URL",
    )

    # --- Redis ---
    redis_url: str = Field(
        default="redis://localhost:6379/0", description="Redis connection URL"
    )

    # --- Orchestrator Finalization Controls ---
    orchestrator_cache_ttl_seconds: int = Field(
        default=900,
        description="Redis TTL for per-analysis aggregated agent results",
    )
    orchestrator_partial_timeout_seconds: int = Field(
        default=90,
        description="Finalize with partial agent results after this many seconds",
    )
    orchestrator_min_agents_for_decision: int = Field(
        default=4,
        description="Minimum agent count required for timeout-based partial finalization",
    )
    orchestrator_max_concurrent_analyses: int = Field(
        default=50,
        description="Max concurrent analyses in the orchestrator pool (30GB optimization)",
    )
    orchestrator_worker_pool_size: int = Field(
        default=16,
        description="Worker pool size for orchestrator components",
    )
    orchestrator_queue_depth: int = Field(
        default=500,
        description="Depth of orchestrator async processing queue",
    )
    request_deduplication_enabled: bool = Field(
        default=True,
        description="Enable request-level deduplication cache to bypass full analysis",
    )

    # --- 30GB RAM Optimizations: Caching ---
    cache_ioc_memory_size_mb: int = Field(
        default=1024,
        description="Max memory size in MB for in-memory IOC caching",
    )
    cache_url_reputation_size_mb: int = Field(
        default=512,
        description="Max memory size in MB for URL reputation caching",
    )
    cache_threat_intel_ttl_seconds: int = Field(
        default=3600,
        description="TTL for threat intelligence lookups",
    )
    cache_model_artifacts_enabled: bool = Field(
        default=True,
        description="Keep model tokenizers/vectorizers hot in memory",
    )
    enable_model_preloading: bool = Field(
        default=True,
        description="Preload all ML models at startup to avoid cold start latency",
    )

    # --- 30GB RAM Optimizations: Model Training ---
    slm_max_sequence_length: int = Field(
        default=256,
        description="Max sequence length for content SLM model",
    )
    slm_max_words_per_sample: int = Field(
        default=512,
        description="Max words processed per sample in SLM training",
    )
    slm_max_samples_per_class: int = Field(
        default=500000,
        description="Max samples per class used for training",
    )

    # --- 30GB RAM Optimizations: Preprocessing ---
    preprocessing_chunk_size_mb: int = Field(
        default=256,
        description="Chunk size in MB for reading large CSVs in pandas",
    )
    preprocessing_workers: int = Field(
        default=8,
        description="Number of parallel workers for preprocessing",
    )
    preprocessing_keep_features_in_memory: bool = Field(
        default=True,
        description="Keep intermediate features in memory instead of disk",
    )

    # --- External API Integrations (Graph & Azure Search) ---
    graph_tenant_id: str | None = Field(
        default=None, description="Microsoft Graph Tenant ID"
    )
    graph_client_id: str | None = Field(
        default=None, description="Microsoft Graph Client ID"
    )
    graph_client_secret: str | None = Field(
        default=None, description="Microsoft Graph Client Secret"
    )
    graph_authority: str = Field(
        default="https://login.microsoftonline.com", description="Graph auth authority"
    )
    graph_scopes: str = Field(
        default="https://graph.microsoft.com/.default", description="Graph scopes"
    )
    action_banner_enabled: bool = Field(
        default=False, description="Enable automated warning banners via Graph"
    )
    action_quarantine_enabled: bool = Field(
        default=False, description="Enable automated email quarantine via Graph"
    )
    azure_search_service: str | None = Field(
        default=None, description="Azure Search service name"
    )
    azure_search_api_key: str | None = Field(
        default=None, description="Azure Search API key"
    )
    azure_search_index_name: str = Field(
        default="threat-indicators", description="Azure Search index name"
    )
    azure_search_enabled: bool = Field(
        default=False, description="Enable Azure Search integration"
    )

    # --- Logging ---
    log_dir: str = Field(default="logs/", description="Log output directory")
    log_format: str = Field(default="json", description="Log format (json or text)")
    log_rotation: str = Field(default="10 MB", description="Log rotation threshold")
    log_retention: str = Field(default="30 days", description="Log retention period")

    # --- Runtime Bootstrap ---
    runtime_bootstrap_enabled: bool = Field(
        default=True,
        description="Run startup bootstrap checks for queue declaration and IOC freshness",
    )
    runtime_bootstrap_declare_results_queue: bool = Field(
        default=True,
        description="Declare results queue during runtime bootstrap",
    )
    runtime_bootstrap_refresh_ioc: bool = Field(
        default=True,
        description="Refresh IOC store during runtime bootstrap",
    )
    runtime_bootstrap_force_ioc_refresh: bool = Field(
        default=True,
        description="Force IOC refresh during runtime bootstrap regardless of interval",
    )

    # --- Garuda Integration ---
    garuda_api_base_url: str = Field(
        default="http://garuda-agent:8088", description="Garuda API base URL"
    )
    garuda_timeout_seconds: int = Field(
        default=15, description="Garuda API request timeout"
    )
    garuda_retry_queue: str = Field(
        default="garuda.retry.queue", description="Queue storing Garuda retry events"
    )
    garuda_dead_letter_queue: str = Field(
        default="garuda.dead.queue", description="Garuda dead-letter queue"
    )
    garuda_retry_max_attempts: int = Field(
        default=6, description="Maximum retry attempts for Garuda delivery"
    )
    garuda_retry_base_seconds: int = Field(
        default=30, description="Base retry backoff in seconds for Garuda events"
    )
    garuda_retry_max_seconds: int = Field(
        default=1800, description="Maximum retry backoff in seconds for Garuda events"
    )

    # --- Action Layer Endpoints ---
    action_simulated_mode: bool = Field(
        default=True,
        description="If true, do not call external action endpoints; only simulate actions",
    )
    action_require_approval: bool = Field(
        default=True,
        description=(
            "NFR-01: if true, live actions run only when the decision carries analyst approval "
            "(e.g. via /api/override); automated verdicts are recorded as pending actions"
        ),
    )
    quarantine_api_url: str | None = Field(
        default=None,
        description="Endpoint URL for quarantine action dispatch",
    )
    soc_alert_api_url: str | None = Field(
        default=None,
        description="Endpoint URL for SOC alert dispatch",
    )

    # --- Threat Intel Local IOC DB ---
    ioc_db_path: str = Field(
        default="data/ioc_store.db",
        description="SQLite path for local IOC database",
    )
    ioc_refresh_seconds: int = Field(
        default=300,
        description="How often to refresh IOC DB from filesystem feeds",
    )
    ioc_stale_seconds: int = Field(
        default=1800,
        description="IOC store is considered stale after this many seconds",
    )
    ioc_warning_age_seconds: int = Field(
        default=900,
        description="IOC age threshold in seconds for warning health",
    )
    ioc_critical_age_seconds: int = Field(
        default=1800,
        description="IOC age threshold in seconds for critical health",
    )
    ioc_min_records: int = Field(
        default=100,
        description="Minimum IOC record count expected for healthy operation",
    )
    threat_intel_auto_refresh_enabled: bool = Field(
        default=True,
        description="Enable periodic IOC auto-refresh loop in API service",
    )

    # --- Sandbox Detonation ---
    sandbox_detonation_image: str = Field(
        default="soc-detonation:1", description="Container image used for sandbox detonation"
    )
    sandbox_timeout_seconds: int = Field(
        default=60, description="Max runtime for each sandbox detonation"
    )
    sandbox_local_docker_enabled: bool = Field(
        default=False,
        description="Enable local Docker detonation mode in sandbox agent",
    )
    sandbox_executor_url: str | None = Field(
        default=None,
        description="Remote sandbox executor service URL",
    )
    sandbox_executor_timeout_seconds: float = Field(
        default=30.0,
        description="Timeout in seconds for remote sandbox executor requests",
    )
    sandbox_executor_shared_token: str | None = Field(
        default=None,
        description="Shared token for sandbox executor service authentication",
    )
    sandbox_executor_attachment_root: str = Field(
        default="/mnt/attachments",
        description="Allowed attachment root for sandbox executor path validation",
    )
    sandbox_allow_network: bool = Field(
        default=False, description="Allow outbound network from detonation containers"
    )
    sandbox_non_root_user: str = Field(
        default="65534:65534", description="UID:GID used inside detonation containers"
    )
    sandbox_memory_limit_mb: int = Field(
        default=256, description="Memory limit in MB for each detonation container"
    )
    sandbox_pids_limit: int = Field(
        default=128, description="PID limit for each detonation container"
    )
    sandbox_runtime: str | None = Field(
        default=None, description="OCI runtime for detonation containers, e.g. 'runsc' (gVisor) - strongly recommended")
    sandbox_cpu_limit: float = Field(default=1.0, description="CPU cores available to a detonation container")
    sandbox_seccomp_profile: str | None = Field(
        default=None, description="Path to a custom seccomp JSON profile (Docker default profile otherwise)")
    sandbox_allow_image_pull: bool = Field(
        default=False, description="Allow pulling the detonation image at runtime (dev only; prod uses a pinned local image)")
    sandbox_max_output_bytes: int = Field(default=2_000_000, description="Cap on captured trace output per detonation")
    sandbox_cape_url: str | None = Field(
        default=None, description="CAPEv2 base URL for Windows payload detonation (isolated analysis VM network)")
    sandbox_cape_token: str | None = Field(default=None, description="CAPEv2 API token")
    sandbox_cape_timeout_seconds: int = Field(default=300, description="Max wait for a CAPE report")
    sandbox_max_detonations: int = Field(
        default=5, description="Maximum attachments to detonate per email"
    )
    sandbox_cleanup_stale_seconds: int = Field(
        default=1800, description="Remove stale detonation containers older than this many seconds"
    )
    sandbox_enable_benign_bootstrap: bool = Field(
        default=True, description="Enable benign bootstrap rows during sandbox preprocessing"
    )
    sandbox_benign_bootstrap_max_rows: int = Field(
        default=5000, description="Maximum number of local benign bootstrap rows"
    )

    # --- 30GB RAM Optimizations: SLM Training ---
    slm_max_seq_len: int = Field(
        default=256, description="Max sequence length for SLM training (increased for 30GB RAM)"
    )
    slm_min_samples_per_class: int = Field(
        default=8000, description="Min samples per class during training"
    )
    slm_num_epochs: int = Field(
        default=5, description="Number of training epochs (reduced for speed)"
    )
    slm_per_device_train_batch_size: int = Field(
        default=32, description="Per-device batch size for SLM training (increased from 8)"
    )
    slm_gradient_accumulation_steps: int = Field(
        default=2, description="Gradient accumulation steps for SLM training"
    )
    slm_num_workers: int = Field(
        default=2, description="Number of tokenization workers (reduced from 6 to prevent process hanging)"
    )
    slm_logging_steps: int = Field(
        default=50, description="Logging interval in steps"
    )

    @property
    def is_production(self) -> bool:
        """Check if running in production environment."""
        return self.app_env.lower() == "production"

    @property
    def ioc_db_file(self) -> Path:
        """IOC store path; relative values resolve under PHISHING_HOME, not the process CWD."""
        p = Path(self.ioc_db_path)
        return p if p.is_absolute() else PROJECT_ROOT / p

    @property
    def log_dir_path(self) -> Path:
        """Resolve absolute path for the log directory."""
        log_path = Path(self.log_dir)
        if not log_path.is_absolute():
            log_path = PROJECT_ROOT / log_path
        return log_path

    def validate_production_settings(self) -> list[str]:
        """Return list of warnings for unsafe production settings."""
        warnings = []
        if self.is_production and self.app_secret_key == "change-me-in-production":  # nosec B105 - detects placeholder
            warnings.append(
                "CRITICAL: APP_SECRET_KEY is using the default value in production! "
                "Set a strong, unique secret key via the APP_SECRET_KEY environment variable."
            )
        if self.is_production and self.app_debug:
            warnings.append(
                "WARNING: APP_DEBUG is enabled in production. Set APP_DEBUG=false."
            )

        if self.is_production and self.sandbox_local_docker_enabled:
            warnings.append(
                "WARNING: SANDBOX_LOCAL_DOCKER_ENABLED=true in production. "
                "Prefer isolated sandbox executor mode and disable local Docker detonation."
            )

        if self.is_production and not self.api_auth_enabled:
            warnings.append("CRITICAL: API_AUTH_ENABLED=false in production - the engine API is unauthenticated.")
        if self.is_production and self.sandbox_allow_network:
            warnings.append("CRITICAL: SANDBOX_ALLOW_NETWORK=true in production - detonation will be refused.")
        if self.is_production and "@sha256:" not in (self.sandbox_detonation_image or ""):
            warnings.append("CRITICAL: SANDBOX_DETONATION_IMAGE must be pinned by digest in production.")
        if self.sandbox_executor_url and not (self.sandbox_executor_shared_token or "").strip():
            warnings.append(
                "WARNING: SANDBOX_EXECUTOR_URL is configured without SANDBOX_EXECUTOR_SHARED_TOKEN. "
                "Set a shared token to protect executor access."
            )

        return warnings


@lru_cache
def get_settings() -> Settings:
    """Return cached settings instance (singleton pattern)."""
    return Settings()


# Module-level singleton for convenience
settings = get_settings()

# Ensure the settings singleton is available under alternative import paths
# Some tests and modules import the settings module via the package root
# `soc_platform.domains.phishing.engine.configs.settings` while application code imports
# `src.configs.settings`. Register the common alias so both names refer to
# the same module object and the same `settings` instance.
try:
    import sys
    alias = "soc_platform.domains.phishing.engine.configs.settings"
    if alias not in sys.modules:
        sys.modules[alias] = sys.modules[__name__]
except Exception:
    # Best-effort only; failures here should not break normal startup.
    logging.getLogger(__name__).debug("settings module alias not registered", exc_info=True)
