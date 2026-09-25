"""Platform configuration, read from environment variables (prefix ``SOC_``).

Secrets are never given defaults here. In production they are injected from a
managed vault (Azure Key Vault via CSI driver / Container Apps secrets) as
environment variables or files; see ``secret()`` (NFR-08).
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

from pydantic import BaseModel, Field


def secret(name: str) -> str | None:
    """Read a secret from ``<NAME>_FILE`` (mounted vault secret) or ``<NAME>``."""
    file_path = os.environ.get(f"{name}_FILE")
    if file_path and Path(file_path).is_file():
        return Path(file_path).read_text(encoding="utf-8").strip()
    return os.environ.get(name)


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


class Settings(BaseModel):
    environment: str = Field(default="dev", description="dev | test | prod")
    database_url: str = "sqlite:///./soc_platform.db"
    raw_payload_dir: str = "./data/raw"
    report_output_dir: str = "./data/reports"

    # Auth (NFR-09). "dev" accepts HS256 tokens signed with dev_jwt_secret;
    # "entra" validates RS256 tokens against the tenant JWKS.
    auth_mode: str = "dev"
    entra_tenant_id: str | None = None
    entra_audience: str | None = None
    dev_jwt_secret: str | None = None
    require_mfa: bool = False             # step-up MFA for approvals/policy/access (default on in prod)
    mfa_auth_context: str | None = None   # Entra Conditional Access auth-context id accepted as MFA (acrs claim)
    break_glass_sha256: str | None = None  # SHA-256 of the sealed break-glass secret; unset = disabled

    # Data protection
    data_keys: list[str] = Field(default_factory=list)   # Fernet keys; first encrypts, all decrypt (rotation)
    raw_retention_days: int = 180
    access_log_retention_days: int = 400
    llm_log_retention_days: int = 180

    # Autonomy (section 5.2). Global kill switch halts every automated action.
    kill_switch: bool = False

    # Connectors: "fake" uses fixture-backed connectors, "live" uses real APIs.
    connector_mode: str = "fake"
    fixtures_dir: str = str(Path(__file__).parent / "fixtures")

    # LLM governance (NFR-11)
    llm_provider: str = "none"  # none | azure_openai | azure_foundry | anthropic | openai_compatible
    llm_endpoint: str | None = None
    llm_deployment: str | None = None
    llm_api_version: str = "2024-10-21"
    llm_model_version: str | None = None  # pinned; change-controlled
    llm_approved_endpoints: list[str] = Field(default_factory=list)
    llm_monthly_token_budget: int = 50_000_000   # sized for a small-to-mid SOC (docs/LLM_TOKENS_AND_COST.md)
    llm_redact_pii: bool = True
    # Internal mail domains: identities in these domains are pseudonymised before any LLM call (PH-T06, R10)
    org_domains: list[str] = Field(default_factory=list)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    env = os.environ
    approved = [e.strip() for e in env.get("SOC_LLM_APPROVED_ENDPOINTS", "").split(",") if e.strip()]
    return Settings(
        environment=env.get("SOC_ENVIRONMENT", "dev"),
        database_url=env.get("SOC_DATABASE_URL", "sqlite:///./soc_platform.db"),
        raw_payload_dir=env.get("SOC_RAW_PAYLOAD_DIR", "./data/raw"),
        report_output_dir=env.get("SOC_REPORT_OUTPUT_DIR", "./data/reports"),
        auth_mode=env.get("SOC_AUTH_MODE", "dev"),
        entra_tenant_id=env.get("SOC_ENTRA_TENANT_ID"),
        entra_audience=env.get("SOC_ENTRA_AUDIENCE"),
        dev_jwt_secret=secret("SOC_DEV_JWT_SECRET"),
        require_mfa=_env_bool("SOC_REQUIRE_MFA", env.get("SOC_ENVIRONMENT", "dev") == "prod"),
        mfa_auth_context=env.get("SOC_MFA_AUTH_CONTEXT"),
        break_glass_sha256=(secret("SOC_BREAKGLASS_SHA256") or "").strip().lower() or None,
        data_keys=[k.strip() for k in (secret("SOC_DATA_KEY") or "").split(",") if k.strip()],
        raw_retention_days=int(env.get("SOC_RAW_RETENTION_DAYS", "180")),
        access_log_retention_days=int(env.get("SOC_ACCESS_LOG_RETENTION_DAYS", "400")),
        llm_log_retention_days=int(env.get("SOC_LLM_LOG_RETENTION_DAYS", "180")),
        kill_switch=_env_bool("SOC_KILL_SWITCH", False),
        connector_mode=env.get("SOC_CONNECTOR_MODE", "fake"),
        fixtures_dir=env.get("SOC_FIXTURES_DIR", str(Path(__file__).parent / "fixtures")),
        llm_provider=env.get("SOC_LLM_PROVIDER", "none"),
        llm_endpoint=env.get("SOC_LLM_ENDPOINT"),
        llm_deployment=env.get("SOC_LLM_DEPLOYMENT"),
        llm_api_version=env.get("SOC_LLM_API_VERSION", "2024-10-21"),
        llm_model_version=env.get("SOC_LLM_MODEL_VERSION"),
        llm_approved_endpoints=approved,
        llm_monthly_token_budget=int(env.get("SOC_LLM_MONTHLY_TOKEN_BUDGET", "50000000")),
        llm_redact_pii=_env_bool("SOC_LLM_REDACT_PII", True),
        org_domains=[d.strip().lower() for d in env.get("SOC_ORG_DOMAINS", "").split(",") if d.strip()],
    )
