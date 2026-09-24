"""
Base FastAPI application for the Agentic Email Security System.

Exposes health check and email analysis endpoints.
This service will be extended in later phases with full agent orchestration.
"""

import base64
import binascii
import asyncio
import hashlib
import ipaddress
import re
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
import tempfile
from typing import Any
from urllib.parse import urlparse
import os

from fastapi import FastAPI
from fastapi import Depends, File, Header, HTTPException, Request, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse, Response, StreamingResponse
from pydantic import BaseModel
from fastapi.staticfiles import StaticFiles
from loguru import logger
import redis.asyncio as redis_async
from prometheus_client import Counter, generate_latest, CONTENT_TYPE_LATEST
try:
    from slowapi import Limiter
    from slowapi.util import get_remote_address
    from slowapi.errors import RateLimitExceeded
    from slowapi.middleware import SlowAPIMiddleware
    _RATE_LIMIT_AVAILABLE = True
except ImportError:
    _RATE_LIMIT_AVAILABLE = False
    logger = __import__('loguru').logger  # keep reference
    logger.warning("slowapi not installed — rate limiting disabled. Run: pip install slowapi")

from soc_platform.domains.phishing.engine.api.schemas import (
    AgentDirectTestRequest,
    AgentDirectTestResponse,
    DiskHealth,
    EmailAnalysisRequest,
    EmailAnalysisResponse,
    AnalysisFeedbackRequest,
    BatchAnalysisRequest,
    BatchAnalysisResponse,
    HealthResponse,
    RabbitMQHealth,
)
from soc_platform.domains.phishing.engine.configs.settings import settings
from soc_platform.domains.phishing.engine.services.database import connect_database
from soc_platform.domains.phishing.engine.services.email_parser import EmailParserService
from soc_platform.domains.phishing.engine.services.logging_service import setup_logging
from soc_platform.domains.phishing.engine.services.messaging_service import RabbitMQClient
from soc_platform.domains.phishing.engine.services.email_validator import EmailValidator
from soc_platform.domains.phishing.engine.services.audit_logger import AuditLogger
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
import json
import time


URL_REGEX = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
IP_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

SUPPORTED_AGENT_TESTS = [
    "header_agent",
    "content_agent",
    "url_agent",
    "attachment_agent",
    "sandbox_agent",
    "threat_intel_agent",
    "user_behavior_agent",
]

AGENT_TEST_EXAMPLES: dict[str, dict[str, Any]] = {
    "header_agent": {
        "headers": {
            "sender": "admin@rnicrosoft.com",
            "reply_to": "hacker@evil.example",
            "subject": "Urgent: verify your account",
            "received": [
                "from mx.github.com by smtp.gmail.com",
                "from internal by mx.github.com"
            ],
            "message_id": "<m-header-1>",
            "authentication_results": "spf=fail; dkim=fail; dmarc=fail",
        }
    },
    "content_agent": {
        "headers": {"subject": "URGENT: Final Notice - Invoice Overdue"},
        "body": {
            "plain": "Dear Customer, your account is past due. If you do not click the link below to process your payment within 24 hours, your services will be terminated and legal action will be taken. Act immediately.",
            "html": ""
        }
    },
    "url_agent": {
        "urls": [
            "http://secure-login-paypa1.example/verify",
            "https://microsoft.com-security-login.example/reset?token=123",
            "https://google.com"
        ]
    },
    "attachment_agent": {
        "attachments": [
            {
                "filename": "invoice_urgent.exe",
                "content_type": "application/x-msdownload",
                "size_bytes": 145760,
                "path": "/tmp/invoice_urgent.exe",  # nosec B108
            },
            {
                "filename": "meeting_notes.txt",
                "content_type": "text/plain",
                "size_bytes": 2048,
                "path": "/tmp/meeting_notes.txt",  # nosec B108
            }
        ]
    },
    "sandbox_agent": {
        "attachments": [
            {
                "filename": "payload.docm",
                "content_type": "application/vnd.ms-word.document.macroEnabled.12",
                "size_bytes": 40960,
                "path": "/tmp/payload.docm",  # nosec B108
            },
            {
                "filename": "summary.pdf",
                "content_type": "application/pdf",
                "size_bytes": 10240,
                "path": "/tmp/summary.pdf",  # nosec B108
            }
        ]
    },
    "threat_intel_agent": {
        "headers": {"sender": "attacker@evil.example"},
        "urls": ["http://known-bad.example/phish", "https://github.com"],
        "iocs": {
            "domains": ["evil.example", "github.com"],
            "ips": ["185.100.87.202", "140.82.112.3"],
            "hashes": ["44d88612fea8a8f36de82e1278abb02f"],
        },
    },
    "user_behavior_agent": {
        "headers": {
            "sender": "finance-team@gmail.com",
            "subject": "Payroll details update URGENT",
        },
        "body": {
             "plain": "Please review payroll changes immediately and confirm via this link.",
             "html": ""
        },
        "recipient_context": {
            "department": "finance",
            "role": "analyst",
            "historical_click_rate": 0.85,
        },
    },
}


# ---------------------------------------------------------------------------
# ML Model Warmup (prevents cold-start latency)
# ---------------------------------------------------------------------------


def _warmup_ml_models() -> None:
    """Preload ML models for content and URL agents to prevent first-request latency."""
    import time
    
    logger.info("🔥 ML Model Warmup: Starting...")
    start = time.time()

    def _build_url_warmup_features(model_bundle: object) -> dict[str, object]:
        """Construct a best-effort URL feature payload for warmup."""
        if isinstance(model_bundle, dict):
            feature_names = model_bundle.get("features")
            if isinstance(feature_names, list) and feature_names:
                feature_map = {str(name): 0.0 for name in feature_names}
                # Include a few representative non-zero hints so model pipelines that
                # use numeric thresholds can exercise their code paths.
                feature_map.update(
                    {
                        "url_count": 2.0,
                        "has_https": 1.0,
                        "has_obfuscation": 0.0,
                    }
                )
                return {"feature_map": feature_map}

            bundle_model = model_bundle.get("model")
            if hasattr(bundle_model, "n_features_in_"):
                feature_count = int(getattr(bundle_model, "n_features_in_", 20) or 20)
                return {"numeric_vector": [[0.5] * feature_count]}

        return {
            "text": "https://example.com/login",
            "numeric_vector": [[0.5] * 20],
        }
    
    try:
        # Warm up content agent (TinyBERT SLM)
        logger.info("  → Warming up Content Agent (NLP/TinyBERT SLM)...")
        try:
            from soc_platform.domains.phishing.engine.agents.content_agent.model_loader import load_model as load_content_model
            from soc_platform.domains.phishing.engine.agents.content_agent.inference import predict as predict_content

            content_model = load_content_model()
            if content_model:
                test_text = {"text": "Click here to verify your account urgently."}
                _ = predict_content(test_text, model=content_model)
                logger.info("  ✓ Content Agent SLM warmed up")
            else:
                logger.info("  → Content Agent model unavailable; heuristic path remains active")
        except Exception as e:
            logger.warning(f"  ⚠ Content Agent warmup failed: {e}")
        
        # Warm up URL agent (XGBoost/RF)
        logger.info("  → Warming up URL Agent (XGBoost/Random Forest)...")
        try:
            from soc_platform.domains.phishing.engine.agents.url_agent.model_loader import load_model as load_url_model
            from soc_platform.domains.phishing.engine.agents.url_agent.inference import predict as predict_url

            url_model = load_url_model()
            if url_model:
                warmup_features = _build_url_warmup_features(url_model)
                _ = predict_url(warmup_features, model=url_model)
                logger.info("  ✓ URL Agent ML model warmed up")
            else:
                logger.info("  → URL Agent model unavailable; heuristic path remains active")
        except Exception as e:
            logger.warning(f"  ⚠ URL Agent warmup failed: {e}")
        
        # Log total warmup time
        elapsed = time.time() - start
        logger.info(f"🔥 ML Model Warmup: Complete ({elapsed:.2f}s)")
        
    except Exception as exc:
        logger.warning(f"ML model warmup encountered unexpected error: {exc}")


# ---------------------------------------------------------------------------
# Application lifespan (startup / shutdown)
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize services on startup and clean up on shutdown."""
    # --- Startup ---
    setup_logging(
        log_dir=settings.log_dir,
        log_level=settings.app_log_level,
        log_format=settings.log_format,
    )
    logger.info(
        "Agentic Email Security API starting",
        environment=settings.app_env,
        host=settings.api_host,
        port=settings.api_port,
    )

    if settings.runtime_bootstrap_enabled:
        try:
            from soc_platform.domains.phishing.tools.bootstrap_runtime_state import bootstrap_runtime_state

            bootstrap_report = bootstrap_runtime_state(
                declare_results_queue=bool(settings.runtime_bootstrap_declare_results_queue),
                refresh_ioc=bool(settings.runtime_bootstrap_refresh_ioc),
                force_ioc_refresh=bool(settings.runtime_bootstrap_force_ioc_refresh),
            )
            if bootstrap_report.get("overall_ok"):
                logger.info("Runtime bootstrap complete", report=bootstrap_report)
            else:
                logger.warning("Runtime bootstrap partial failure", report=bootstrap_report)
        except Exception as exc:
            logger.warning("Runtime bootstrap failed", error=str(exc))

    stop_event = asyncio.Event()
    app.state._threat_intel_refresh_stop = stop_event
    app.state._threat_intel_refresh_task = None
    if settings.threat_intel_auto_refresh_enabled:
        # NOTE: Disabled — the threat_intel agent worker handles its own
        # background refresh.  Running a competing refresh from the API
        # server holds an exclusive SQLite write-lock on ioc_store.db for
        # minutes, blocking the agent from initializing during analyze().
        logger.info("Threat-intel auto-refresh delegated to agent worker")
    
    # Warm up large ML models to prevent cold-start latency for the first API request
    logger.info("Starting ML model pre-warming phase...")
    try:
        if os.environ.get("EMAIL_SECURITY_SKIP_WARMUP") == "1":
            logger.info("Skipping ML model warmup due to EMAIL_SECURITY_SKIP_WARMUP=1")
        else:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, _warmup_ml_models)
            logger.info("ML model pre-warming completed successfully")
    except Exception as exc:
        logger.warning("ML model pre-warming encountered issues", error=str(exc))
    
    yield
    # --- Shutdown ---
    stop_event.set()
    task = getattr(app.state, "_threat_intel_refresh_task", None)
    if task is not None:
        task.cancel()
        try:
            await task
        except Exception:
            pass
    logger.info("Agentic Email Security API shutting down")


# ---------------------------------------------------------------------------
# Prometheus counters
# ---------------------------------------------------------------------------

def _get_or_create_counter(name: str, documentation: str) -> Counter:
    """Create a Counter, tolerating duplicate registration.

    Under pytest, conftest puts both the repo root and the package root on
    sys.path, so this module can be imported under two names (``src.api.main``
    and ``soc_platform.domains.phishing.engine.api.main``). Each import re-runs this module-level
    registration against the global REGISTRY, which raises ``ValueError`` on the
    second pass. Reuse the already-registered collector instead of crashing.
    """
    try:
        return Counter(name, documentation)
    except ValueError:
        from prometheus_client import REGISTRY

        existing = REGISTRY._names_to_collectors.get(name)
        if existing is not None:
            return existing  # type: ignore[return-value]
        raise


PARTIAL_FINALIZATION_COUNTER = _get_or_create_counter(
    "orchestrator_partial_finalizations_total",
    "Number of times the orchestrator finalized with missing agents",
)

# ---------------------------------------------------------------------------
# Rate limiter (C-5)
# ---------------------------------------------------------------------------

if _RATE_LIMIT_AVAILABLE:
    limiter = Limiter(key_func=get_remote_address, default_limits=["200/minute"])
else:
    limiter = None

APP_VERSION = settings.app_version if hasattr(settings, "app_version") else "1.0.0"

# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Agentic Email Security System",
    description=(
        "Production-grade Agentic AI system for phishing email detection. "
        "Uses multiple independent AI agents to analyze email components "
        "and collectively determine threat levels."
    ),
    version=APP_VERSION,
    lifespan=lifespan,
)

if _RATE_LIMIT_AVAILABLE:
    app.state.limiter = limiter
    app.add_middleware(SlowAPIMiddleware)


# Simple in-process rate limit store (fallback when Redis unavailable)
if not hasattr(app.state, "_rate_limit_store"):
    app.state._rate_limit_store = {}

FRONTEND_DIR = Path(__file__).resolve().parent / "frontend"
app.mount("/ui-assets", StaticFiles(directory=str(FRONTEND_DIR)), name="ui-assets")


# ---------------------------------------------------------------------------
# Security middleware and exception handlers
# ---------------------------------------------------------------------------

@app.middleware("http")
async def security_headers_middleware(request, call_next):
    resp = await call_next(request)
    headers = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
        "Permissions-Policy": "geolocation=(), microphone=()",
    }
    for k, v in headers.items():
        if k not in resp.headers:
            resp.headers[k] = v
    return resp


@app.middleware("http")
async def rate_limit_middleware(request, call_next):
    # Per-endpoint simple rate limits (ip-scoped). Uses Redis if configured, else in-memory.
    RATE_LIMIT_CONFIG = {
        "/analyze-email": (30, 60),
        "/analyze-batch": (5, 60),
    }
    path = request.url.path
    cfg = RATE_LIMIT_CONFIG.get(path)
    if not cfg:
        return await call_next(request)

    limit, period = cfg
    client_ip = (request.client.host if request.client else "unknown")
    key = f"rl:{path}:{client_ip}"
    try:
        import redis as _redis
        r = _redis.from_url(settings.redis_url or "redis://localhost:6379/0")
        count = r.incr(key)
        if count == 1:
            r.expire(key, period)
        if count > limit:
            AuditLogger.log_rate_limit_exceeded(client_ip)
            return JSONResponse(status_code=429, content={"detail": "Rate limit exceeded"}, headers={"Retry-After": str(period)})
    except Exception:
        # in-memory fallback (best-effort)
        now = int(time.time())
        store = app.state._rate_limit_store
        window = store.get(key, [])
        window = [t for t in window if t > now - period]
        if len(window) >= limit:
            AuditLogger.log_rate_limit_exceeded(client_ip)
            return JSONResponse(status_code=429, content={"detail": "Rate limit exceeded"}, headers={"Retry-After": str(period)})
        window.append(now)
        store[key] = window

    return await call_next(request)


@app.middleware("http")
async def response_sanitization_middleware(request, call_next):
    resp = await call_next(request)
    try:
        if resp.media_type and "json" in (resp.media_type or ""):
            # Attempt to read body and sanitize JSON keys
            body = b""
            if hasattr(resp, "body"):
                try:
                    body = resp.body
                except Exception:
                    try:
                        body = await resp.body()
                    except Exception:
                        body = b""
            if not body:
                return resp
            try:
                parsed = json.loads(body.decode("utf-8"))
            except Exception:
                return resp

            def _sanitize(obj):
                if isinstance(obj, dict):
                    out = {}
                    for k, v in obj.items():
                        lk = k.lower()
                        if lk in {"raw", "gdrive_file_id", "local_routing_path", "credentials", "secret", "api_key", "authorization", "azure_openai_api_key"}:
                            continue
                        if lk == "llm_explanation" and isinstance(v, str):
                            out[k] = v[:1024]
                            continue
                        out[k] = _sanitize(v)
                    return out
                if isinstance(obj, list):
                    return [_sanitize(x) for x in obj]
                return obj

            sanitized = _sanitize(parsed)
            return JSONResponse(status_code=resp.status_code, content=sanitized, headers=dict(resp.headers))
    except Exception:
        # Don't break responses on sanitization errors
        return resp
    return resp


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc):
    client_ip = (request.client.host if request.client else "unknown")
    AuditLogger.log_validation_error(client_ip, "RequestValidationError", str(exc))
    return JSONResponse(status_code=422, content={"detail": "Invalid request payload"})


@app.exception_handler(Exception)
async def generic_exception_handler(request, exc):
    logger.exception("Unhandled exception in request", error=str(exc))
    client_ip = (request.client.host if request.client else "unknown")
    AuditLogger.log_validation_error(client_ip, "UnhandledException", str(exc))
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})

if _RATE_LIMIT_AVAILABLE:
    @app.exception_handler(RateLimitExceeded)
    async def rate_limit_exception_handler(request, exc):
        client_ip = (request.client.host if request.client else "unknown")
        AuditLogger.log_rate_limit_exceeded(client_ip)
        headers = getattr(exc, "headers", None) or {}
        return JSONResponse(status_code=429, content={"detail": "Rate limit exceeded"}, headers=headers)


def _check_api_key(value: str | None) -> bool:
    """Return True if `value` satisfies shared-key auth (or auth is disabled)."""
    if not settings.api_auth_enabled:
        return True
    configured = (settings.api_auth_key or "").strip()
    if not configured:
        return False
    return (value or "").strip() == configured


def _require_api_key(x_api_key: str | None = Header(default=None)) -> None:
    """Enforce shared-key auth when enabled via configuration."""
    if not settings.api_auth_enabled:
        return

    configured = (settings.api_auth_key or "").strip()
    if not configured:
        raise HTTPException(status_code=503, detail="API auth is enabled but API_AUTH_KEY is not configured")
    if (x_api_key or "").strip() != configured:
        raise HTTPException(status_code=401, detail="Invalid API key")


def _safe_filename(filename: str) -> str:
    candidate = (filename or "attachment.bin").strip()
    if not candidate:
        candidate = "attachment.bin"
    return re.sub(r"[^A-Za-z0-9._-]", "_", candidate)


def _decode_base64_content(payload: str) -> bytes:
    value = (payload or "").strip()
    if value.lower().startswith("data:") and "," in value:
        value = value.split(",", 1)[1]
    try:
        return base64.b64decode(value, validate=True)
    except binascii.Error:
        # Some clients omit base64 padding.
        padded = value + ("=" * (-len(value) % 4))
        return base64.b64decode(padded)


def _extract_urls_from_text(text: str) -> list[str]:
    if not text:
        return []
    return URL_REGEX.findall(text)


def _extract_domains(urls: list[str]) -> list[str]:
    domains = set()
    for url in urls:
        candidate = (url or "").strip()
        if not candidate:
            continue
        if "://" not in candidate:
            candidate = f"https://{candidate}"
        try:
            host = (urlparse(candidate).hostname or "").lower()
        except Exception:
            continue
        if not host:
            continue
        try:
            ipaddress.ip_address(host)
            continue
        except ValueError:
            domains.add(host)
    return sorted(domains)


def _extract_ips(content: str, urls: list[str]) -> list[str]:
    found = set(IP_REGEX.findall(content or ""))
    for url in urls:
        candidate = (url or "").strip()
        if not candidate:
            continue
        if "://" not in candidate:
            candidate = f"https://{candidate}"
        try:
            host = urlparse(candidate).hostname
            if not host:
                continue
            ipaddress.ip_address(host)
            found.add(host)
        except ValueError:
            continue
        except Exception:
            continue
    return sorted(found)


def _get_agent_test_function(agent_name: str):
    from soc_platform.domains.phishing.engine.agents.service_runner import AGENT_FUNCTIONS

    if agent_name not in AGENT_FUNCTIONS:
        raise HTTPException(
            status_code=404,
            detail=(
                f"Unsupported agent '{agent_name}'. "
                f"Expected one of: {sorted(AGENT_FUNCTIONS)}"
            ),
        )
    return AGENT_FUNCTIONS[agent_name]


def _build_attachment_payload(
    analysis_id: str,
    attachments: list,
) -> tuple[list[dict[str, str | int]], list[str]]:
    persisted: list[dict[str, str | int]] = []
    hashes: list[str] = []

    storage_dir = Path(settings.attachment_volume_dir)

    for item in attachments:
        attachment_id = str(uuid.uuid4())
        safe_name = _safe_filename(item.filename)
        size_bytes = int(item.size_bytes or 0)
        sha256 = ""
        path = ""

        if item.content_base64:
            try:
                # C-4: guard against PermissionError on /mnt/attachments
                try:
                    storage_dir.mkdir(parents=True, exist_ok=True)
                except PermissionError:
                    fallback = Path(tempfile.gettempdir()) / "email_security_attachments"
                    fallback.mkdir(parents=True, exist_ok=True)
                    logger.warning(
                        "attachment_dir_fallback",
                        original=str(storage_dir),
                        fallback=str(fallback),
                    )
                    storage_dir = fallback
                blob = _decode_base64_content(item.content_base64)
                size_bytes = len(blob)
                sha256 = hashlib.sha256(blob).hexdigest()
                target_name = f"{analysis_id}_{attachment_id}_{safe_name}"
                target_path = storage_dir / target_name
                target_path.write_bytes(blob)
                path = str(target_path)
                hashes.append(sha256)
            except Exception as exc:
                logger.warning(
                    "Attachment decode/persist failed",
                    analysis_id=analysis_id,
                    filename=item.filename,
                    error=str(exc),
                )

        persisted.append(
            {
                "attachment_id": attachment_id,
                "filename": item.filename,
                "content_type": item.content_type,
                "size_bytes": size_bytes,
                "sha256": sha256,
                "path": path,
            }
        )

    return persisted, hashes


def _soc_queue_names() -> list[str]:
    return [
        settings.results_queue,
        settings.garuda_retry_queue,
        settings.garuda_dead_letter_queue,
        "header_agent.queue",
        "content_agent.queue",
        "url_agent.queue",
        "attachment_agent.queue",
        "sandbox_agent.queue",
        "threat_intel_agent.queue",
        "user_behavior_agent.queue",
    ]


def _fetch_recent_reports(limit: int = 50) -> list[dict]:
    rows: list[dict] = []
    with connect_database(settings.database_url, logger=logger) as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT analysis_id, created_at, overall_risk_score, verdict, report
                FROM threat_reports
                ORDER BY created_at DESC
                LIMIT %s
                """,
                (max(1, int(limit)),),
            )
            for analysis_id, created_at, risk_score, verdict, report in cursor.fetchall():
                if isinstance(report, dict):
                    report_dict = report
                elif isinstance(report, str):
                    try:
                        import json

                        report_dict = json.loads(report)
                    except Exception:
                        report_dict = {}
                else:
                    report_dict = {}
                rows.append(
                    {
                        "analysis_id": analysis_id,
                        "created_at": created_at.isoformat() if hasattr(created_at, "isoformat") else str(created_at),
                        "overall_risk_score": float(risk_score or 0.0),
                        "verdict": verdict,
                        "threat_level": report_dict.get("threat_level", "unknown"),
                        "sender": report_dict.get("sender", ""),
                        "subject": report_dict.get("subject", ""),
                        "recommended_actions": report_dict.get("recommended_actions", []) or [],
                        "agent_results": report_dict.get("agent_results", []) or [],
                    }
                )
    return rows


def _build_soc_overview() -> dict:
    queue_stats: list[dict] = []
    mq = RabbitMQClient()
    try:
        mq.connect()
        queue_stats = mq.get_multi_queue_stats(_soc_queue_names())
    except Exception as exc:
        queue_stats = [{"queue": "_connection", "exists": False, "error": str(exc), "messages_ready": 0, "consumers": 0}]
    finally:
        mq.close()

    reports: list[dict] = []
    reports_error = None
    try:
        reports = _fetch_recent_reports(limit=50)
    except Exception as exc:
        reports_error = str(exc)
        logger.warning("SOC overview could not fetch reports", error=reports_error)
    verdict_counts: dict[str, int] = {}
    total_risk = 0.0
    action_counts: dict[str, int] = {}
    recent_agent_outputs: list[dict] = []

    timeline_data = []

    for report in reports:
        verdict = str(report.get("verdict") or "unknown")
        verdict_counts[verdict] = verdict_counts.get(verdict, 0) + 1
        total_risk += float(report.get("overall_risk_score") or 0.0)

        created_at = report.get("created_at")
        if created_at:
            timeline_data.append({"timestamp": created_at, "verdict": verdict})

        for action in report.get("recommended_actions", []) or []:
            key = str(action)
            action_counts[key] = action_counts.get(key, 0) + 1

        for result in (report.get("agent_results") or [])[:10]:
            recent_agent_outputs.append(
                {
                    "analysis_id": report.get("analysis_id"),
                    "agent_name": result.get("agent_name"),
                    "risk_score": float(result.get("risk_score", 0.0) or 0.0),
                    "confidence": float(result.get("confidence", 0.0) or 0.0),
                }
            )

    avg_risk = (total_risk / len(reports)) if reports else 0.0
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "queue_health": queue_stats,
        "reports": {
            "count": len(reports),
            "avg_risk_score": round(avg_risk, 4),
            "verdict_counts": verdict_counts,
            "recent": reports[:20],
            "error": reports_error,
        },
        "response_actions": action_counts,
        "agent_outputs": recent_agent_outputs[:100],
        "timeline": timeline_data,
    }


async def _threat_intel_refresh_loop(stop_event: asyncio.Event) -> None:
    """Periodically refresh IOC store and emit staleness alerts."""
    from soc_platform.domains.phishing.engine.agents.threat_intel_agent.agent import get_ioc_store_status, refresh_ioc_store

    refresh_every = max(30, int(settings.ioc_refresh_seconds))
    logger.info("Threat-intel auto-refresh loop started", refresh_every_seconds=refresh_every)
    while not stop_event.is_set():
        try:
            refresh_ioc_store(force=False)
            status = get_ioc_store_status()
            if status.get("is_stale"):
                logger.error("IOC store stale alert", status=status)
        except Exception as exc:
            logger.warning("Threat-intel auto-refresh iteration failed", error=str(exc))

        try:
            await asyncio.wait_for(stop_event.wait(), timeout=refresh_every)
        except asyncio.TimeoutError:
            continue


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@app.get("/", include_in_schema=False)
async def root_redirect():
    """Redirect root to the frontend UI."""
    return RedirectResponse(url="/ui")


@app.get("/health", response_model=HealthResponse, tags=["System"])
async def health_check():
    """Return the current health status of the API service."""
    import shutil

    overall_status = "healthy"

    # --- RabbitMQ health ---
    mq = RabbitMQClient()
    mq_status = "healthy"
    mq_error = None
    queue_depths = {}

    try:
        mq.connect()
        monitored_queues = [settings.results_queue, settings.rabbitmq_dead_letter_queue]
        stats = mq.get_multi_queue_stats(monitored_queues)
        for stat in stats:
            queue_depths[stat["queue"]] = stat.get("messages_ready", 0)
    except Exception as exc:
        mq_status = "unhealthy"
        mq_error = str(exc)
        overall_status = "degraded"
        logger.warning("Health check detected unhealthy RabbitMQ connection", error=mq_error)
    finally:
        mq.close()

    # --- Disk space health ---
    try:
        usage = shutil.disk_usage("/")
        free_gb = round(usage.free / (1024 ** 3), 2)
        total_gb = round(usage.total / (1024 ** 3), 2)
        usage_pct = round((usage.used / usage.total) * 100, 1)

        if free_gb < 2.0:
            disk_status = "critical"
            overall_status = "degraded"
        elif free_gb < 5.0:
            disk_status = "warning"
        else:
            disk_status = "healthy"

        disk_health = DiskHealth(
            status=disk_status,
            free_gb=free_gb,
            total_gb=total_gb,
            usage_percent=usage_pct,
        )
    except Exception:
        disk_health = None

    return HealthResponse(
        status=overall_status,
        version=APP_VERSION,
        environment=settings.app_env,
        rabbitmq=RabbitMQHealth(
            status=mq_status,
            error=mq_error,
            queue_depths=queue_depths,
        ),
        disk=disk_health,
    )


@app.get("/metrics", tags=["System"])
async def metrics():
    """Export Prometheus metrics."""
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.get("/ui", tags=["Frontend"])
async def ui_home() -> FileResponse:
    """Serve SOC frontend home page."""
    return FileResponse(FRONTEND_DIR / "index.html")


@app.get("/ui/analyze", tags=["Frontend"])
async def ui_analyze() -> FileResponse:
    """Serve file upload analysis page."""
    return FileResponse(FRONTEND_DIR / "analyze.html")


@app.get("/ui/agents", tags=["Frontend"])
async def ui_agents() -> FileResponse:
    """Serve individual agent testing page."""
    return FileResponse(FRONTEND_DIR / "agents.html")


@app.get("/ui/triage", tags=["Frontend"])
async def ui_triage() -> FileResponse:
    """Serve analyst triage workbench page."""
    return FileResponse(FRONTEND_DIR / "triage.html")


@app.get("/ui/campaigns", tags=["Frontend"])
async def ui_campaigns() -> FileResponse:
    """Serve campaign clustering page."""
    return FileResponse(FRONTEND_DIR / "campaigns.html")


@app.get("/ui/report/{analysis_id}", tags=["Frontend"])
async def ui_report(analysis_id: str) -> FileResponse:
    """Serve the threat report viewer page for a given analysis id."""
    return FileResponse(FRONTEND_DIR / "report.html")


@app.get("/agent-test/agents", tags=["Agent Testing"])
async def list_testable_agents(_auth: None = Depends(_require_api_key)):
    """List agents that can be tested directly with custom payloads."""
    return {
        "supported_agents": SUPPORTED_AGENT_TESTS,
        "usage": "POST /agent-test/{agent_name}",
        "note": "Direct test path bypasses RabbitMQ/orchestrator and does not alter production async flow.",
    }


@app.get("/agent-test/examples", tags=["Agent Testing"])
async def get_agent_test_examples(_auth: None = Depends(_require_api_key)):
    """Return copy-paste sample payloads for each direct agent test endpoint."""
    return {
        "usage": {
            "endpoint": "POST /agent-test/{agent_name}",
            "body": {
                "payload": "<agent-specific JSON payload>",
                "inject_analysis_id": True,
                "print_output": True,
            },
        },
        "examples": AGENT_TEST_EXAMPLES,
        "result_location": {
            "api_response": "Returned immediately in response.output",
            "stdout": "Printed in API service logs when print_output=true",
        },
    }


@app.post(
    "/agent-test/{agent_name}",
    response_model=AgentDirectTestResponse,
    tags=["Agent Testing"],
)
async def direct_agent_test(
    agent_name: str,
    request: AgentDirectTestRequest,
    _auth: None = Depends(_require_api_key),
):
    """
    Run one agent directly against caller-provided payload.

    This endpoint is isolated for manual testing and does not publish events,
    consume queues, or invoke orchestrator/action-layer workflows.
    """
    payload: dict[str, Any] = dict(request.payload or {})
    if request.inject_analysis_id and not payload.get("analysis_id"):
        payload["analysis_id"] = f"manual-agent-test-{uuid.uuid4()}"

    analyze_fn = _get_agent_test_function(agent_name)
    try:
        output = analyze_fn(payload)
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Direct agent test failed", agent_name=agent_name)
        raise HTTPException(
            status_code=500,
            detail=f"Direct test for {agent_name} failed: {exc}",
        ) from exc

    if request.print_output:
        logger.debug(
            "agent_direct_test_io",
            agent_name=agent_name,
            input_keys=sorted(payload.keys()),
            output_keys=sorted(output.keys()) if isinstance(output, dict) else ["raw"],
        )

    logger.info(
        "Direct agent test completed",
        agent_name=agent_name,
        payload_keys=sorted(payload.keys()),
    )

    return AgentDirectTestResponse(
        status="completed",
        agent_name=agent_name,
        message=(
            "Agent tested in isolated direct mode. "
            "No RabbitMQ publish and no orchestrator/action dispatch occurred."
        ),
        input_payload=payload,
        output=output if isinstance(output, dict) else {"raw_output": output},
    )


@app.get("/soc/dashboard", tags=["SOC"], response_class=HTMLResponse)
async def soc_dashboard():
        """Simple analyst-facing SOC dashboard for queue health and outcomes."""
        return HTMLResponse(
                """
<!doctype html>
<html lang="en" class="dark">
<head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Email Security | SOC Intelligence</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        :root {
            --bg-base: #0B0F19;
            --bg-panel: rgba(19, 26, 42, 0.7);
            --bg-card: rgba(26, 35, 58, 0.8);
            --border: rgba(65, 83, 119, 0.4);
            --text-main: #E2E8F0;
            --text-muted: #94A3B8;
            --accent-primary: #3B82F6;
            --accent-glow: rgba(59, 130, 246, 0.5);
            --red: #EF4444;
            --amber: #F59E0B;
            --green: #10B981;
            --glass-blur: blur(12px);
        }
        
        * { box-sizing: border-box; margin: 0; padding: 0; }
        
        body {
            font-family: 'Inter', sans-serif;
            background: radial-gradient(circle at top right, #111827, var(--bg-base) 60%);
            color: var(--text-main);
            min-height: 100vh;
            line-height: 1.5;
            padding-bottom: 2rem;
            overflow-x: hidden;
        }

        /* Animated background elements */
        .bg-orb {
            position: fixed;
            border-radius: 50%;
            filter: blur(80px);
            z-index: -1;
            opacity: 0.4;
            animation: float 10s infinite ease-in-out alternate;
        }
        .orb-1 { top: -10%; left: -10%; width: 400px; height: 400px; background: rgba(59, 130, 246, 0.3); }
        .orb-2 { bottom: -20%; right: -10%; width: 500px; height: 500px; background: rgba(139, 92, 246, 0.2); animation-delay: -5s; }

        @keyframes float {
            0% { transform: translate(0, 0); }
            100% { transform: translate(30px, 50px); }
        }

        header {
            background: rgba(11, 15, 25, 0.8);
            backdrop-filter: var(--glass-blur);
            border-bottom: 1px solid var(--border);
            padding: 1rem 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            position: sticky;
            top: 0;
            z-index: 50;
        }
        
        .logo { font-size: 1.25rem; font-weight: 700; display: flex; align-items: center; gap: 0.5rem; }
        .logo span { color: var(--accent-primary); }
        .timestamp { font-family: monospace; font-size: 0.875rem; color: var(--text-muted); background: var(--bg-card); padding: 0.25rem 0.75rem; border-radius: 9999px; border: 1px solid var(--border); }

        .container { max-width: 1400px; margin: 2rem auto; padding: 0 1.5rem; display: grid; gap: 1.5rem; }
        
        /* Glass Panels */
        .panel {
            background: var(--bg-panel);
            backdrop-filter: var(--glass-blur);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 1.5rem;
            box-shadow: 0 4px 20px rgba(0,0,0,0.2);
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }
        .panel:hover { box-shadow: 0 8px 30px rgba(0,0,0,0.3); }
        .panel-title { font-size: 1rem; font-weight: 600; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 1.25rem; display: flex; justify-content: space-between; align-items: center; }

        /* KPI Grid */
        .kpi-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; }
        .kpi-card { background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px; padding: 1.25rem; text-align: center; position: relative; overflow: hidden; }
        .kpi-card::before { content: ''; position: absolute; top: 0; left: 0; right: 0; height: 3px; background: var(--accent-primary); opacity: 0.5; }
        .kpi-value { font-size: 2.5rem; font-weight: 700; margin: 0.5rem 0; line-height: 1; }
        .kpi-label { font-size: 0.875rem; color: var(--text-muted); }
        
        .val-red { color: var(--red); }
        .val-amber { color: var(--amber); }
        .val-green { color: var(--green); }
        .val-blue { color: var(--accent-primary); }

        /* Charts Layout */
        .chart-row { display: grid; grid-template-columns: 1fr 2fr; gap: 1.5rem; }
        .chart-container { position: relative; height: 300px; width: 100%; }

        /* Tables */
        .table-wrap { overflow-x: auto; border-radius: 12px; border: 1px solid var(--border); background: rgba(0,0,0,0.2); }
        table { width: 100%; border-collapse: collapse; font-size: 0.875rem; table-layout: fixed; }
        th { background: rgba(255,255,255,0.03); padding: 1.25rem 1rem; text-align: left; font-weight: 600; color: var(--text-muted); border-bottom: 1px solid var(--border); text-transform: uppercase; letter-spacing: 0.05em; font-size: 0.75rem; }
        td { padding: 1.25rem 1rem; border-bottom: 1px solid rgba(65, 83, 119, 0.2); word-break: break-word; vertical-align: top; }
        tr:last-child td { border-bottom: none; }
        tr:hover td { background: rgba(59, 130, 246, 0.05); }
        
        /* Set specific column widths to prevent overlap */
        th:nth-child(1), td:nth-child(1) { width: 15%; }
        th:nth-child(2), td:nth-child(2) { width: 15%; }
        th:nth-child(3), td:nth-child(3) { width: 15%; }
        th:nth-child(4), td:nth-child(4) { width: 20%; }
        th:nth-child(5), td:nth-child(5) { width: 35%; }
        
        .pill { padding: 0.35rem 0.85rem; border-radius: 9999px; font-size: 0.75rem; font-weight: 600; display: inline-flex; align-items: center; gap: 0.35rem; }
        .pill.malicious { background: rgba(239, 68, 68, 0.15); color: #FCA5A5; border: 1px solid rgba(239, 68, 68, 0.3); }
        .pill.high_risk { background: rgba(245, 158, 11, 0.15); color: #FCD34D; border: 1px solid rgba(245, 158, 11, 0.3); }
        .pill.suspicious { background: rgba(245, 158, 11, 0.05); color: #FDE68A; border: 1px solid rgba(245, 158, 11, 0.2); }
        .pill.safe, .pill.likely_safe { background: rgba(16, 185, 129, 0.15); color: #6EE7B7; border: 1px solid rgba(16, 185, 129, 0.3); }
        .pill.action { background: rgba(59, 130, 246, 0.15); color: #93C5FD; border: 1px solid rgba(59, 130, 246, 0.3); margin-right: 0.4rem; margin-bottom: 0.4rem; }
        .actions-cell { display: flex; flex-wrap: wrap; gap: 0.25rem; }

        .hash-id { font-family: 'JetBrains Mono', 'Fira Code', monospace; color: var(--accent-primary); background: rgba(59, 130, 246, 0.1); padding: 0.25rem 0.5rem; border-radius: 6px; }
        
        /* Modal CSS */
        .modal-overlay { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.8); z-index: 1000; justify-content: center; align-items: center; }
        .modal { background: var(--bg-panel); border: 1px solid var(--border); border-radius: 16px; width: 90%; max-width: 900px; max-height: 90vh; overflow-y: auto; padding: 2rem; box-shadow: 0 10px 40px rgba(0,0,0,0.5); backdrop-filter: var(--glass-blur); }
        .modal-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem; }
        .modal-close { background: none; border: none; color: var(--text-muted); font-size: 1.5rem; cursor: pointer; }
        .result-section { background: rgba(0,0,0,0.2); border-radius: 12px; margin-bottom: 1rem; border: 1px solid var(--border); overflow: hidden; }
        .result-header { background: rgba(255,255,255,0.03); padding: 0.75rem 1.25rem; font-weight: 600; border-bottom: 1px solid var(--border); }
        .result-body { padding: 1.25rem; }
        .row { display: flex; gap: 0.5rem; flex-wrap: wrap; }
        
        /* Animations */
        @keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
        .fade-in { animation: fadeIn 0.5s ease forwards; }
        .d-1 { animation-delay: 0.1s; } .d-2 { animation-delay: 0.2s; } .d-3 { animation-delay: 0.3s; }
        
        .back-btn {
            text-decoration: none;
            color: var(--text-main);
            font-size: 0.875rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
            background: rgba(255,255,255,0.05);
            padding: 0.5rem 1rem;
            border-radius: 10px;
            border: 1px solid var(--border);
            transition: all 0.2s;
            font-weight: 500;
        }
        .back-btn:hover {
            background: rgba(255,255,255,0.1);
            border-color: var(--accent-primary);
            box-shadow: 0 0 15px var(--accent-glow);
            transform: translateY(-1px);
        }
        
        @media (max-width: 900px) {
            .chart-row { grid-template-columns: 1fr; }
        }
    </style>
</head>
<body>
    <div class="bg-orb orb-1"></div>
    <div class="bg-orb orb-2"></div>

    <header>
        <a href="/ui" style="text-decoration:none; color:inherit;">
            <div class="logo">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color:var(--accent-primary)"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>
                SOC <span>Intelligence</span>
            </div>
        </a>
        <div style="display:flex; align-items:center; gap:1.5rem;">
            <a href="/ui" class="back-btn">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="margin-right:2px"><path d="m3 9 9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg>
                Home
            </a>
            <div id="ts" class="timestamp">Connecting...</div>
        </div>
    </header>

    <div class="container">
        <!-- Key Metrics -->
        <div class="kpi-grid fade-in">
            <div class="kpi-card">
                <div class="kpi-label">Analyzed Emails</div>
                <div class="kpi-value val-blue" id="kpi-total">-</div>
            </div>
            <div class="kpi-card" style="--accent-primary: var(--red);">
                <div class="kpi-label">Malicious Threats</div>
                <div class="kpi-value val-red" id="kpi-malicious">-</div>
            </div>
            <div class="kpi-card" style="--accent-primary: var(--amber);">
                <div class="kpi-label">Average Risk Score</div>
                <div class="kpi-value val-amber" id="kpi-risk">-</div>
            </div>
            <div class="kpi-card" style="--accent-primary: var(--green);">
                <div class="kpi-label">Active Agents/Queues</div>
                <div class="kpi-value val-green" id="kpi-queues">-</div>
            </div>
        </div>

        <!-- Timeline Chart -->
        <div class="panel fade-in d-1" style="margin-bottom: 1.5rem;">
            <div class="panel-title">Threat Volume Over Time (Last 50 Scans grouped by minute)</div>
            <div class="chart-container" style="height: 250px;">
                <canvas id="timelineChart"></canvas>
            </div>
        </div>

        <!-- Charts -->
        <div class="chart-row fade-in d-1">
            <div class="panel">
                <div class="panel-title">Verdict Distribution</div>
                <div class="chart-container">
                    <canvas id="verdictChart"></canvas>
                </div>
            </div>
            <div class="panel">
                <div class="panel-title">Automated Response Actions</div>
                <div class="chart-container">
                    <canvas id="actionChart"></canvas>
                </div>
            </div>
        </div>

        <!-- Recent Threats Table -->
        <div class="panel fade-in d-2">
            <div class="panel-title">
                Recent Threat Reports
                <span class="pill" style="background: rgba(255,255,255,0.1); border:none; color:white;" id="report-count">0 items</span>
            </div>
            <div class="table-wrap">
                <table id="reports-table">
                    <thead>
                        <tr>
                            <th>Analysis ID</th>
                            <th>Time</th>
                            <th>Verdict</th>
                            <th>Risk Score</th>
                            <th>Remediation Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr><td colspan="5" style="text-align:center; color:var(--text-muted);">Initializing telemetry...</td></tr>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <!-- Modal -->
    <div class="modal-overlay" id="reportModal" onclick="if(event.target===this) closeModal()">
        <div class="modal">
            <div class="modal-header">
                <h2 style="margin:0">Analysis Details <span id="modalAnalysisId" style="font-size:0.875rem;color:var(--text-muted);margin-left:1rem;font-family:monospace"></span></h2>
                <button class="modal-close" onclick="closeModal()">&times;</button>
            </div>
            <div id="modalContent">Loading...</div>
        </div>
    </div>

    <script>
        // Chart instances
        let verdictChart = null;
        let actionChart = null;
        let timelineChart = null;

        // Chart.js global defaults for dark theme
        Chart.defaults.color = '#94A3B8';
        Chart.defaults.borderColor = 'rgba(65, 83, 119, 0.2)';
        Chart.defaults.font.family = "'Inter', sans-serif";

        function initCharts() {
            const ctx1 = document.getElementById('verdictChart').getContext('2d');
            verdictChart = new Chart(ctx1, {
                type: 'doughnut',
                data: {
                    labels: ['Malicious', 'High Risk', 'Suspicious', 'Safe'],
                    datasets: [{
                        data: [0, 0, 0, 0],
                        backgroundColor: ['#EF4444', '#F59E0B', '#FCD34D', '#10B981'],
                        borderWidth: 0,
                        hoverOffset: 4
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    cutout: '75%',
                    plugins: {
                        legend: { position: 'bottom', labels: { padding: 20, usePointStyle: true, pointStyle: 'circle' } }
                    }
                }
            });

            const ctx2 = document.getElementById('actionChart').getContext('2d');
            
            // Create gradient for bars
            const gradient = ctx2.createLinearGradient(0, 0, 0, 400);
            gradient.addColorStop(0, 'rgba(59, 130, 246, 0.8)');
            gradient.addColorStop(1, 'rgba(59, 130, 246, 0.2)');

            actionChart = new Chart(ctx2, {
                type: 'bar',
                data: {
                    labels: [],
                    datasets: [{
                        label: 'Executions',
                        data: [],
                        backgroundColor: gradient,
                        borderRadius: 6,
                        borderWidth: 1,
                        borderColor: 'rgba(59, 130, 246, 1)'
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        y: { beginAtZero: true, grid: { drawBorder: false } },
                        x: { grid: { display: false } }
                    },
                    plugins: {
                        legend: { display: false }
                    }
                }
            });

            const ctx3 = document.getElementById('timelineChart').getContext('2d');
            timelineChart = new Chart(ctx3, {
                type: 'line',
                data: {
                    labels: [],
                    datasets: [
                        {
                            label: 'Malicious / High Risk',
                            data: [],
                            borderColor: '#EF4444',
                            backgroundColor: 'rgba(239, 68, 68, 0.1)',
                            tension: 0.4,
                            fill: true,
                            borderWidth: 2,
                            pointRadius: 3
                        },
                        {
                            label: 'Safe / Suspicious',
                            data: [],
                            borderColor: '#10B981',
                            backgroundColor: 'rgba(16, 185, 129, 0.1)',
                            tension: 0.4,
                            fill: true,
                            borderWidth: 2,
                            pointRadius: 3
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        y: { beginAtZero: true, grid: { color: 'rgba(65, 83, 119, 0.1)' }, ticks: { stepSize: 1, precision: 0 } },
                        x: { grid: { display: false } }
                    },
                    plugins: {
                        legend: { position: 'top', labels: { usePointStyle: true, pointStyle: 'circle' } }
                    }
                }
            });
        }

        function formatVerdict(v) {
            const normalized = String(v).toLowerCase();
            return `<span class="pill ${normalized}">${String(v).toUpperCase().replace('_', ' ')}</span>`;
        }

        function formatActions(actions) {
            if (!actions || actions.length === 0) return `<div class="actions-cell"><span class="pill" style="background:transparent;border:1px dashed var(--border);color:var(--text-muted)">None</span></div>`;
            return `<div class="actions-cell">` + actions.map(a => `<span class="pill action">${a}</span>`).join('') + `</div>`;
        }

        async function refreshData() {
            try {
                const res = await fetch('/soc/overview');
                const data = await res.json();
                
                // Update Timestamp
                document.getElementById('ts').innerHTML = `Live &bull; ${new Date(data.generated_at).toLocaleTimeString('en-US', { timeZone: 'Asia/Kolkata' })} (IST)`;

                // Update KPIs
                const reports = data.reports || {};
                const verdicts = reports.verdict_counts || {};
                const queues = (data.queue_health || []).filter(q => q.exists).length;
                
                document.getElementById('kpi-total').textContent = reports.count || 0;
                document.getElementById('kpi-malicious').textContent = verdicts.malicious || 0;
                document.getElementById('kpi-risk').textContent = (reports.avg_risk_score || 0).toFixed(2);
                document.getElementById('kpi-queues').textContent = queues;

                // Update Verdict Chart
                if (verdictChart) {
                    verdictChart.data.datasets[0].data = [
                        verdicts.malicious || 0,
                        verdicts.high_risk || 0,
                        verdicts.suspicious || 0,
                        (verdicts.safe || 0) + (verdicts.likely_safe || 0)
                    ];
                    verdictChart.update();
                }

                // Update Timeline Chart
                if (timelineChart && data.timeline) {
                    const timelineBuckets = {};
                    data.timeline.forEach(item => {
                        const date = new Date(item.timestamp);
                        const timeKey = date.toLocaleTimeString('en-US', { timeZone: 'Asia/Kolkata', hour: '2-digit', minute: '2-digit', hour12: false });
                        if (!timelineBuckets[timeKey]) {
                            timelineBuckets[timeKey] = { threats: 0, safe: 0 };
                        }
                        if (item.verdict === 'malicious' || item.verdict === 'high_risk') {
                            timelineBuckets[timeKey].threats += 1;
                        } else {
                            timelineBuckets[timeKey].safe += 1;
                        }
                    });

                    const sortedKeys = Object.keys(timelineBuckets).sort();
                    timelineChart.data.labels = sortedKeys;
                    timelineChart.data.datasets[0].data = sortedKeys.map(k => timelineBuckets[k].threats);
                    timelineChart.data.datasets[1].data = sortedKeys.map(k => timelineBuckets[k].safe);
                    timelineChart.update();
                }

                // Update Action Chart
                if (actionChart && data.response_actions) {
                    const actionEntries = Object.entries(data.response_actions).sort((a,b) => b[1] - a[1]);
                    actionChart.data.labels = actionEntries.map(e => e[0].replace(/_/g, ' '));
                    actionChart.data.datasets[0].data = actionEntries.map(e => e[1]);
                    actionChart.update();
                }

                // Update Table
                const tbody = document.querySelector('#reports-table tbody');
                const recent10 = (reports.recent || []).slice(0, 10);
                document.getElementById('report-count').textContent = `${recent10.length} items`;
                
                if (recent10.length > 0) {
                    tbody.innerHTML = recent10.map(r => `
                        <tr>
                            <td><a href="#" onclick="openModal('${r.analysis_id}'); return false;" class="hash-id" style="text-decoration:none; cursor:pointer;">${r.analysis_id.substring(0,8)}...${r.analysis_id.substring(r.analysis_id.length-4)}</a></td>
                            <td style="color:var(--text-muted)">${new Date(r.created_at).toLocaleTimeString('en-US', { timeZone: 'Asia/Kolkata' })}</td>
                            <td>${formatVerdict(r.verdict)}</td>
                            <td>
                                <div style="display:flex; align-items:center; gap:8px;">
                                    <div style="width:50px; height:6px; background:var(--bg-base); border-radius:3px; overflow:hidden;">
                                        <div style="width:${Math.min(100, r.overall_risk_score * 100)}%; height:100%; background: ${r.overall_risk_score > 0.8 ? 'var(--red)' : r.overall_risk_score > 0.5 ? 'var(--amber)' : 'var(--green)'};"></div>
                                    </div>
                                    <span style="font-family:monospace">${r.overall_risk_score.toFixed(2)}</span>
                                </div>
                            </td>
                            <td>${formatActions(r.recommended_actions)}</td>
                        </tr>
                    `).join('');
                } else {
                    tbody.innerHTML = `<tr><td colspan="5" style="text-align:center; color:var(--text-muted); padding: 2rem;">No recent activity</td></tr>`;
                }

            } catch (err) {
                console.error("Dashboard refresh failed:", err);
                document.getElementById('ts').innerHTML = `<span style="color:var(--red)">Connection Lost</span>`;
            }
        }
        
        // Modal Logic
        function closeModal() { document.getElementById('reportModal').style.display = 'none'; }
        
        async function openModal(analysisId) {
            document.getElementById('reportModal').style.display = 'flex';
            document.getElementById('modalAnalysisId').textContent = analysisId;
            document.getElementById('modalContent').innerHTML = '<div style="text-align:center;padding:2rem;color:var(--text-muted)">Loading...</div>';
            
            try {
                const res = await fetch(`/reports/${analysisId}`);
                const data = await res.json();
                if (!res.ok) throw new Error(data.detail || "HTTP " + res.status);
                document.getElementById('modalContent').innerHTML = renderReportHTML(data);
            } catch (err) {
                document.getElementById('modalContent').innerHTML = `<div style="color:var(--red)">Failed to load report: ${err.message}</div>`;
            }
        }
        
        function renderReportHTML(data) {
            const verdict = data.verdict || "unknown";
            const risk = data.overall_risk_score ?? "—";
            const explanation = data.llm_explanation || "";
            const agents = data.agent_results || [];
            const actions = data.recommended_actions || [];
            const storyline = data.threat_storyline || [];
            const counterfactual = data.counterfactual_result || null;
            
            const esc = (str) => { const d = document.createElement("div"); d.textContent = str; return d.innerHTML; };
            
            let html = `
              <div style="display:flex; gap:1rem; align-items:center; margin-bottom:1.5rem">
                ${formatVerdict(verdict)}
                <span style="font-size:0.9rem;color:var(--text-muted)">Risk Score: <strong style="color:var(--text-main)">${typeof risk === 'number' ? risk.toFixed(4) : risk}</strong></span>
              </div>`;

            if (explanation) {
              html += `<div class="result-section"><div class="result-header">🧠 AI Summary</div><div class="result-body"><p style="color:var(--text-muted);font-size:0.88rem;line-height:1.6;margin:0">${esc(explanation)}</p></div></div>`;
            }

            if (agents.length) {
              let rows = agents.map(a => `<tr><td style="color:var(--accent-primary);font-weight:600">${a.agent_name}</td><td>${(a.risk_score??0).toFixed(3)}</td><td>${(a.confidence??0).toFixed(3)}</td><td style="font-size:0.78rem;color:var(--text-muted)">${(a.indicators||[]).join(", ") || "—"}</td></tr>`).join("");
              html += `<div class="result-section"><div class="result-header">🔬 Agent Results</div><div class="result-body"><table><thead><tr><th>Agent</th><th>Risk</th><th>Confidence</th><th>Indicators</th></tr></thead><tbody>${rows}</tbody></table></div></div>`;
            }

            if (storyline && storyline.length) {
              if (Array.isArray(storyline)) {
                  let items = storyline.map(s => `<tr><td><span class="pill" style="font-size:0.72rem;background:rgba(255,255,255,0.1)">${s.phase}</span></td><td style="font-size:0.84rem;color:var(--text-muted)">${esc(s.description)}</td><td>${(s.confidence??0).toFixed(2)}</td></tr>`).join("");
                  html += `<div class="result-section"><div class="result-header">📖 Threat Storyline</div><div class="result-body"><table><thead><tr><th>Phase</th><th>Description</th><th>Confidence</th></tr></thead><tbody>${items}</tbody></table></div></div>`;
              } else {
                  html += `<div class="result-section"><div class="result-header">📖 Threat Storyline</div><div class="result-body"><pre style="font-size:0.88rem;color:var(--text-muted);white-space:pre-wrap;margin:0">${esc(storyline)}</pre></div></div>`;
              }
            }

            if (counterfactual) {
              html += `<div class="result-section"><div class="result-header">🔀 Counterfactual Analysis</div><div class="result-body"><pre style="margin:0;border:0;font-size:0.88rem;color:var(--text-muted);max-height:200px;overflow:auto">${esc(typeof counterfactual === 'string' ? counterfactual : JSON.stringify(counterfactual, null, 2))}</pre></div></div>`;
            }

            if (actions.length) {
              html += `<div class="result-section"><div class="result-header">⚡ Recommended Actions</div><div class="result-body"><div class="row">${formatActions(actions)}</div></div></div>`;
            }
            return html;
        }

        // Initialize
        document.addEventListener('DOMContentLoaded', () => {
            initCharts();
            refreshData();
            setInterval(refreshData, 5000); // 5s refresh
        });
    </script>
</body>
</html>
                """
        )


@app.get("/soc/overview", tags=["SOC"])
async def soc_overview(_auth: None = Depends(_require_api_key)):
        """Dashboard backing API for queue health, verdicts, and response actions."""
        return _build_soc_overview()


@app.websocket("/ws/orchestrator")
async def orchestrator_ws(websocket: WebSocket):
    """Real-time pipeline progress via WebSocket. Clients receive agent_update
    and final_verdict events as they happen."""
    # Enforce shared-key auth before accepting. Browsers cannot set custom
    # headers on a WebSocket handshake, so the key is taken from the query string.
    if settings.api_auth_enabled and not _check_api_key(websocket.query_params.get("api_key")):
        await websocket.close(code=1008)
        return
    await websocket.accept()
    redis_sub = None
    try:
        redis_sub = redis_async.from_url(settings.redis_url)
        pubsub = redis_sub.pubsub()
        await pubsub.subscribe("pipeline_ui_events")
        while True:
            msg = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
            if msg and msg["type"] == "message":
                await websocket.send_text(msg["data"].decode() if isinstance(msg["data"], bytes) else msg["data"])
            await asyncio.sleep(0.05)
    except WebSocketDisconnect:
        pass
    except Exception as exc:
        logger.warning(f"WebSocket error: {exc}")
    finally:
        if redis_sub:
            await redis_sub.aclose()


@app.post("/ops/garuda/process-retries", tags=["Operations"])
async def process_garuda_retry_queue(max_items: int = 25, _auth: None = Depends(_require_api_key)):
        """Process pending Garuda retries and return reconciliation stats."""
        from soc_platform.domains.phishing.engine.garuda_integration.retry_queue import process_garuda_retries

        return process_garuda_retries(max_items=max_items)


@app.get("/ops/threat-intel/status", tags=["Operations"])
async def threat_intel_status(_auth: None = Depends(_require_api_key)):
        """Return IOC store lifecycle health and staleness information."""
        from soc_platform.domains.phishing.engine.agents.threat_intel_agent.agent import get_ioc_store_status

        return get_ioc_store_status()


@app.post("/ops/threat-intel/refresh", tags=["Operations"])
async def threat_intel_refresh(force: bool = False, _auth: None = Depends(_require_api_key)):
        """Trigger IOC feed refresh lifecycle job now."""
        from soc_platform.domains.phishing.engine.agents.threat_intel_agent.agent import refresh_ioc_store

        return refresh_ioc_store(force=force)


class SimulateVerdictRequest(BaseModel):
    """Hypothetical per-agent risk scores for the read-only verdict simulator."""

    agent_scores: dict[str, float]


@app.post("/ops/simulate-verdict", tags=["Operations"])
async def simulate_verdict_endpoint(req: SimulateVerdictRequest, _auth: None = Depends(_require_api_key)):
    """Read-only "what-if" verdict simulation. No persistence, no actions taken."""
    from soc_platform.domains.phishing.engine.orchestrator.decision_engine.engine import simulate_verdict

    return simulate_verdict(req.agent_scores)


def _active_learning_safe(method_name: str, days: int) -> dict[str, Any]:
    """Call an ActiveLearningEngine method, degrading gracefully when the DB is down."""
    try:
        from soc_platform.domains.phishing.engine.orchestrator.active_learning import get_active_learning_engine
        engine = get_active_learning_engine()
        return getattr(engine, method_name)(days=days)
    except Exception as exc:
        logger.warning("Active-learning ops query failed", method=method_name, error=str(exc))
        raise HTTPException(status_code=503, detail=f"Analytics backend unavailable: {exc}") from exc


@app.get("/ops/agent-accuracy", tags=["Operations"])
async def ops_agent_accuracy(days: int = 30, _auth: None = Depends(_require_api_key)):
    """Per-agent accuracy from analyst feedback (active-learning)."""
    return _active_learning_safe("compute_agent_accuracy", days)


@app.get("/ops/weight-recommendations", tags=["Operations"])
async def ops_weight_recommendations(days: int = 30, _auth: None = Depends(_require_api_key)):
    """Data-driven agent weight adjustment recommendations."""
    return _active_learning_safe("recommend_weight_adjustments", days)


@app.get("/ops/drift-report", tags=["Operations"])
async def ops_drift_report(days: int = 30, _auth: None = Depends(_require_api_key)):
    """Detection drift report over the requested window."""
    return _active_learning_safe("get_drift_report", days)


@app.get("/ops/feedback-summary", tags=["Operations"])
async def ops_feedback_summary(days: int = 30, _auth: None = Depends(_require_api_key)):
    """Summary of analyst feedback (TP/FP/FN/TN, false-positive rate)."""
    return _active_learning_safe("get_feedback_summary", days)


def _record_campaign_signal(payload: dict[str, Any]) -> dict[str, Any]:
    """Feed an ingested email's sender/subject into the campaign correlation detector."""
    try:
        import redis as _redis_sync

        from soc_platform.domains.phishing.engine.services.campaign_detector import domain_from_sender, get_campaign_detector

        headers = payload.get("headers", {}) or {}
        sender_domain = domain_from_sender(headers.get("sender", "") or "")
        client = _redis_sync.from_url(settings.redis_url or "redis://localhost:6379/0")
        return get_campaign_detector(client).record_and_check(
            sender_domain=sender_domain,
            subject=headers.get("subject", "") or "",
            analysis_id=payload.get("analysis_id", ""),
        )
    except Exception as exc:
        logger.warning("Campaign detection recording failed", error=str(exc))
        return {"campaign_detected": False}


@app.get("/ops/campaigns", tags=["Operations"])
async def list_campaigns(_auth: None = Depends(_require_api_key)):
    """Currently active phishing campaigns, correlated by sender domain + subject fingerprint."""
    from soc_platform.domains.phishing.engine.services.campaign_detector import get_campaign_detector

    try:
        import redis as _redis_sync

        client = _redis_sync.from_url(settings.redis_url or "redis://localhost:6379/0")
        campaigns = get_campaign_detector(client).list_active_campaigns()
    except Exception as exc:
        logger.warning("Failed to fetch active campaigns", error=str(exc))
        campaigns = []
    return {"campaigns": campaigns, "count": len(campaigns)}


@app.post(
    "/analyze-email",
    response_model=EmailAnalysisResponse,
    tags=["Analysis"],
)
async def analyze_email(request: EmailAnalysisRequest, http_request: Request, _auth: None = Depends(_require_api_key)):
    """
    Accept an email for phishing analysis.

    This endpoint normalizes payload content, persists attachments, extracts
    IOC candidates, and publishes a NewEmailEvent for downstream agents.
    Final reports are retrieved asynchronously via GET /reports/{analysis_id}.
    """
    start_ts = time.time()
    client_ip = (http_request.client.host if http_request.client else "unknown")
    try:
        raw_body = await http_request.body()
    except Exception:
        raw_body = b""
    request_size = len(raw_body)

    # Input validation (size, attachments, mime-types)
    try:
        EmailValidator.validate_email_size((request.body or "").encode("utf-8"))
        if len(request.attachments or []) > EmailValidator.MAX_ATTACHMENTS:
            raise HTTPException(status_code=400, detail="Too many attachments")
        for att in (request.attachments or []):
            if att.content_type not in EmailValidator.ALLOWED_MIME_TYPES:
                raise HTTPException(status_code=400, detail=f"Unsupported attachment type: {att.content_type}")
            if getattr(att, "content_base64", None):
                try:
                    blob = _decode_base64_content(att.content_base64)
                    if len(blob) > EmailValidator.MAX_EMAIL_SIZE:
                        raise HTTPException(status_code=413, detail="Attachment exceeds maximum size")
                except HTTPException:
                    raise
                except Exception:
                    raise HTTPException(status_code=400, detail="Invalid attachment content")
    except HTTPException as exc:
        AuditLogger.log_validation_error(client_ip, "validation_failed", str(exc.detail))
        raise

    analysis_id = str(uuid.uuid4())
    body_plain = request.body or ""

    request_urls = [url.strip() for url in request.urls if str(url).strip()]
    discovered_urls = _extract_urls_from_text(body_plain)
    all_urls = sorted(set(request_urls + discovered_urls))

    attachments, attachment_hashes = _build_attachment_payload(
        analysis_id=analysis_id,
        attachments=request.attachments,
    )

    # OCR: extract hidden URLs from image/PDF attachments
    ocr_urls: list[str] = []
    try:
        from soc_platform.domains.phishing.engine.services.ocr_service import extract_urls_from_attachments
        ocr_urls = extract_urls_from_attachments(attachments)
        if ocr_urls:
            all_urls = sorted(set(all_urls + ocr_urls))
    except Exception:
        pass

    ioc_domains = _extract_domains(all_urls)
    ioc_ips = _extract_ips(
        content=f"{request.headers.subject}\n{body_plain}",
        urls=all_urls,
    )

    payload = {
        "event_type": "NewEmailEvent",
        "analysis_id": analysis_id,
        "ingested_at": datetime.now(timezone.utc).isoformat(),
        "headers": {
            "sender": request.headers.sender,
            "reply_to": request.headers.reply_to,
            "subject": request.headers.subject,
            "received": request.headers.received,
            "message_id": request.headers.message_id,
            "authentication_results": request.headers.authentication_results,
            "to": request.headers.to,
            "raw": {},
        },
        "body": {
            "plain": body_plain,
            "html": "",
        },
        "urls": all_urls,
        "attachments": attachments,
        "iocs": {
            "domains": ioc_domains,
            "ips": ioc_ips,
            "hashes": attachment_hashes,
        },
    }

    _record_campaign_signal(payload)

    from soc_platform.domains.phishing.engine.orchestrator.deduplication import dedup_email_analysis
    dedup_result, was_cached, fingerprint = dedup_email_analysis(payload)
    
    if was_cached and dedup_result:
        cached_analysis_id = dedup_result.get("analysis_id", analysis_id)
        logger.info(
            "Email deduplicated from cache",
            analysis_id=analysis_id,
            cached_analysis_id=cached_analysis_id,
            fingerprint=fingerprint,
        )
        return EmailAnalysisResponse(
            status="cached",
            message="Identical email analysis found in cache. Processing skipped.",
            analysis_id=cached_analysis_id,
            agent_results=dedup_result.get("agent_results", []),
            overall_risk_score=dedup_result.get("overall_risk_score"),
            verdict=dedup_result.get("verdict"),
            llm_explanation=dedup_result.get("llm_explanation"),
            report_endpoint=f"/reports/{cached_analysis_id}",
            final_report_features=[
                "agent_results",
                "overall_risk_score",
                "verdict",
                "llm_explanation",
                "counterfactual_result",
                "threat_storyline",
                "recommended_actions",
            ],
        )

    # Cache the mapping so runner.py can cache the final result using this fingerprint
    if fingerprint and settings.request_deduplication_enabled:
        try:
            import redis
            r = redis.from_url(settings.redis_url or "redis://localhost:6379/0")
            r.setex(f"email_dedup_mapping:{analysis_id}", settings.orchestrator_cache_ttl_seconds, fingerprint)
        except Exception as e:
            logger.warning("Failed to store deduplication mapping", error=str(e))

    mq_client = RabbitMQClient()
    mq_client.connect()
    mq_client.publish_new_email(payload)
    mq_client.close()

    logger.info(
        "Email received for analysis",
        analysis_id=analysis_id,
        sender=request.headers.sender,
        subject=request.headers.subject,
        url_count=len(all_urls),
        attachment_count=len(attachments),
        ioc_domain_count=len(ioc_domains),
        ioc_ip_count=len(ioc_ips),
        attachment_hash_count=len(attachment_hashes),
    )

    response_time_ms = (time.time() - start_ts) * 1000.0
    try:
        AuditLogger.log_api_call(
            endpoint="/analyze-email",
            client_ip=client_ip,
            status_code=200,
            request_size=request_size,
            response_time_ms=response_time_ms,
            user_agent=http_request.headers.get("user-agent", ""),
        )
    except Exception:
        pass

    return EmailAnalysisResponse(
        status="received",
        message="Email event accepted and dispatched to all agents",
        analysis_id=analysis_id,
        agent_results=[],
        overall_risk_score=None,
        verdict=None,
        llm_explanation=None,
        report_endpoint=f"/reports/{analysis_id}",
        final_report_features=[
            "agent_results",
            "overall_risk_score",
            "verdict",
            "llm_explanation",
            "counterfactual_result",
            "threat_storyline",
            "recommended_actions",
        ],
    )


@app.post("/ingest-raw-email", response_model=EmailAnalysisResponse, tags=["Analysis"])
async def ingest_raw_email(request: Request, file: UploadFile = File(...), _auth: None = Depends(_require_api_key)):
    """Accept raw .eml/.txt file, parse it fully, and publish NewEmailEvent."""
    suffix = Path(file.filename or "email.eml").suffix.lower()
    parser = EmailParserService()
    if not parser.supports_extension(suffix):
        supported = ", ".join(sorted(parser.supported_extensions()))
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file extension '{suffix}'. Supported: {supported}",
        )

    if getattr(settings, "local_routing_enabled", False):
        import shutil
        from soc_platform.domains.phishing.engine.services.gdrive_client import get_gdrive_client
        
        gdrive = get_gdrive_client()
        
        staging_dir = Path(settings.local_staging_folder)
        staging_dir.mkdir(parents=True, exist_ok=True)
        # Use original filename but prepend timestamp/uuid to avoid collisions
        safe_name = _safe_filename(file.filename)
        staged_path = staging_dir / f"{uuid.uuid4().hex[:8]}_{safe_name}"
        
        with open(staged_path, "wb") as f:
            f.write(await file.read())
            
        try:
            event = parser.parse_file(staged_path)
            event["local_routing_path"] = str(staged_path)
            
            # if gdrive.is_configured():
            #     # Upload to GDrive Staging
            #     file_id = gdrive.upload_file(str(staged_path), gdrive.staging_folder_id)
            #     if file_id:
            #         event["gdrive_file_id"] = file_id
            
            parser.messaging.connect()
            parser.messaging.publish_new_email(event)
            parser.messaging.close()
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"Failed to parse raw email: {exc}") from exc
    else:
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as temp_file:
            temp_file.write(await file.read())
            temp_path = temp_file.name

        try:
            event = parser.parse_and_publish(temp_path)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"Failed to parse raw email: {exc}") from exc

    _record_campaign_signal(event)

    return EmailAnalysisResponse(
        status="received",
        message="Raw email parsed and dispatched",
        analysis_id=event["analysis_id"],
        agent_results=[],
        overall_risk_score=None,
        verdict=None,
        llm_explanation=None,
        report_endpoint=f"/reports/{event['analysis_id']}",
        final_report_features=[
            "agent_results",
            "overall_risk_score",
            "verdict",
            "llm_explanation",
            "counterfactual_result",
            "threat_storyline",
            "recommended_actions",
        ],
    )


# ---------------------------------------------------------------------------
# H-1: Analyst feedback endpoint
# ---------------------------------------------------------------------------

@app.post("/reports/{analysis_id}/feedback", tags=["Analysis"])
async def submit_report_feedback(
    analysis_id: str,
    body: AnalysisFeedbackRequest,
    _auth: None = Depends(_require_api_key),
):
    """
    Submit analyst feedback on a completed analysis.

    Allows SOC analysts to mark verdicts as false positives or confirm
    true positives, building a feedback loop for threshold calibration.
    """
    try:
        with connect_database(settings.database_url, logger=logger) as conn:
            with conn.cursor() as cursor:
                # Ensure the report exists
                cursor.execute(
                    "SELECT 1 FROM threat_reports WHERE analysis_id = %s LIMIT 1",
                    (analysis_id,),
                )
                if not cursor.fetchone():
                    raise HTTPException(status_code=404, detail="Analysis not found")

                # Upsert feedback
                cursor.execute(
                    """
                    INSERT INTO analyst_feedback
                        (analysis_id, analyst_verdict, notes, submitted_at)
                    VALUES (%s, %s, %s, NOW())
                    ON CONFLICT (analysis_id) DO UPDATE SET
                        analyst_verdict = EXCLUDED.analyst_verdict,
                        notes = EXCLUDED.notes,
                        submitted_at = NOW()
                    """,
                    (analysis_id, body.analyst_verdict, body.notes or ""),
                )
            conn.commit()
        logger.info(
            "analyst_feedback_received",
            analysis_id=analysis_id,
            analyst_verdict=body.analyst_verdict,
        )
        return {"status": "accepted", "analysis_id": analysis_id, "analyst_verdict": body.analyst_verdict}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to save feedback: {exc}") from exc


# ---------------------------------------------------------------------------
# H-2: Bulk / batch ingestion endpoint
# ---------------------------------------------------------------------------

@app.post("/analyze-batch", response_model=BatchAnalysisResponse, tags=["Analysis"])
async def analyze_email_batch(
    request: Request,
    body: BatchAnalysisRequest,
    _auth: None = Depends(_require_api_key),
):
    """
    Accept a batch of emails for parallel analysis.

    Each email is assigned a unique analysis_id and published to RabbitMQ
    independently so agents process them in parallel. Returns all analysis_ids
    immediately — poll GET /reports/{analysis_id} for each result.
    """
    start_ts = time.time()
    client_ip = (request.client.host if request.client else "unknown")
    try:
        raw_body = await request.body()
    except Exception:
        raw_body = b""
    request_size = len(raw_body)

    if not body.emails:
        raise HTTPException(status_code=400, detail="No emails provided in batch")

    max_batch = 50
    if len(body.emails) > max_batch:
        raise HTTPException(
            status_code=400,
            detail=f"Batch size {len(body.emails)} exceeds maximum of {max_batch}",
        )

    mq_client = RabbitMQClient()
    mq_client.connect()
    results = []
    errors = []
    # Validate each email's attachments before publishing
    try:
        for idx, email_req in enumerate(body.emails):
            if len(email_req.attachments or []) > EmailValidator.MAX_ATTACHMENTS:
                raise HTTPException(status_code=400, detail=f"Email at index {idx} has too many attachments")
            for att in (email_req.attachments or []):
                if att.content_type not in EmailValidator.ALLOWED_MIME_TYPES:
                    raise HTTPException(status_code=400, detail=f"Email at index {idx} has unsupported attachment type: {att.content_type}")
                if getattr(att, "content_base64", None):
                    try:
                        blob = _decode_base64_content(att.content_base64)
                        if len(blob) > EmailValidator.MAX_EMAIL_SIZE:
                            raise HTTPException(status_code=413, detail=f"Attachment too large in email index {idx}")
                    except HTTPException:
                        raise
                    except Exception:
                        raise HTTPException(status_code=400, detail=f"Invalid attachment content at index {idx}")
    except HTTPException as exc:
        AuditLogger.log_validation_error(client_ip, "batch_validation_failed", str(exc.detail))
        raise

    for idx, email_req in enumerate(body.emails):
        try:
            analysis_id = str(uuid.uuid4())
            body_plain = email_req.body or ""
            request_urls = [url.strip() for url in email_req.urls if str(url).strip()]
            discovered_urls = _extract_urls_from_text(body_plain)
            all_urls = sorted(set(request_urls + discovered_urls))
            attachments, attachment_hashes = _build_attachment_payload(
                analysis_id=analysis_id, attachments=email_req.attachments
            )
            ioc_domains = _extract_domains(all_urls)
            ioc_ips = _extract_ips(
                content=f"{email_req.headers.subject}\n{body_plain}",
                urls=all_urls,
            )
            payload = {
                "event_type": "NewEmailEvent",
                "analysis_id": analysis_id,
                "ingested_at": datetime.now(timezone.utc).isoformat(),
                "headers": {
                    "sender": email_req.headers.sender,
                    "reply_to": email_req.headers.reply_to,
                    "subject": email_req.headers.subject,
                    "received": email_req.headers.received,
                    "message_id": email_req.headers.message_id,
                    "authentication_results": email_req.headers.authentication_results,
                    "to": email_req.headers.to,
                    "raw": {},
                },
                "body": {"plain": body_plain, "html": ""},
                "urls": all_urls,
                "attachments": attachments,
                "iocs": {"domains": ioc_domains, "ips": ioc_ips, "hashes": attachment_hashes},
            }
            _record_campaign_signal(payload)
            mq_client.publish_new_email(payload)
            results.append({"index": idx, "analysis_id": analysis_id, "status": "queued",
                            "report_endpoint": f"/reports/{analysis_id}"})
        except Exception as exc:
            errors.append({"index": idx, "error": str(exc)})
            logger.warning("batch_email_publish_failed", index=idx, error=str(exc))

    mq_client.close()
    logger.info("batch_ingestion_complete", queued=len(results), errors=len(errors))
    response_time_ms = (time.time() - start_ts) * 1000.0
    try:
        AuditLogger.log_api_call(
            endpoint="/analyze-batch",
            client_ip=client_ip,
            status_code=200,
            request_size=request_size,
            response_time_ms=response_time_ms,
            user_agent=request.headers.get("user-agent", ""),
        )
    except Exception:
        pass

    return BatchAnalysisResponse(
        queued=len(results),
        errors=len(errors),
        results=results,
        error_details=errors,
    )


def _load_report(analysis_id: str) -> dict[str, Any]:
    """Fetch the stored threat report (decision dict) or raise HTTP 404/500."""
    try:
        with connect_database(settings.database_url, logger=logger) as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    "SELECT report FROM threat_reports WHERE analysis_id = %s",
                    (analysis_id,),
                )
                row = cursor.fetchone()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to fetch report: {exc}") from exc
    if not row or row[0] is None:
        raise HTTPException(status_code=404, detail="Report not ready")
    report = row[0]
    if isinstance(report, str):
        import json as _json
        try:
            report = _json.loads(report)
        except Exception:
            raise HTTPException(status_code=500, detail="Stored report is not valid JSON")
    return report


@app.get("/reports/{analysis_id}", tags=["Analysis"])
async def get_report(analysis_id: str, _auth: None = Depends(_require_api_key)):
    """Return final orchestrator report for an analysis id."""
    return _load_report(analysis_id)


@app.get("/reports/{analysis_id}/pdf", tags=["Analysis"])
async def get_report_pdf(analysis_id: str, _auth: None = Depends(_require_api_key)):
    """Render the threat report as a downloadable PDF (reportlab)."""
    report = _load_report(analysis_id)
    report.setdefault("analysis_id", analysis_id)
    try:
        from soc_platform.domains.phishing.engine.services.pdf_report import build_report_pdf
    except ImportError as exc:
        raise HTTPException(status_code=503, detail=f"PDF generation unavailable: {exc}") from exc
    try:
        pdf_bytes = build_report_pdf(report)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to render PDF: {exc}") from exc
    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{analysis_id}.pdf"'},
    )


@app.get("/reports/{analysis_id}/stix", tags=["Analysis"])
async def get_report_stix(analysis_id: str, _auth: None = Depends(_require_api_key)):
    """Export the report as a STIX 2.1 bundle for SIEM/SOAR/TI sharing."""
    report = _load_report(analysis_id)
    try:
        from soc_platform.domains.phishing.engine.orchestrator.stix_generator import generate_stix_bundle
        return generate_stix_bundle(
            analysis_id=analysis_id,
            agent_results=report.get("agent_results") or [],
            verdict=report.get("verdict", "unknown"),
            risk_score=float(report.get("overall_risk_score", 0.0) or 0.0),
            email_headers=report.get("email_headers"),
            attack_data=report.get("attack_assessment"),
            recommended_actions=report.get("recommended_actions"),
        )
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to generate STIX bundle: {exc}") from exc


@app.get("/reports/{analysis_id}/navigator", tags=["Analysis"])
async def get_report_navigator(analysis_id: str, _auth: None = Depends(_require_api_key)):
    """Export a MITRE ATT&CK Navigator layer (imports into the official tool)."""
    report = _load_report(analysis_id)
    try:
        from soc_platform.domains.phishing.engine.orchestrator.attack_navigator import generate_navigator_layer
        return generate_navigator_layer(
            agent_results=report.get("agent_results") or [],
            analysis_id=analysis_id,
            verdict=report.get("verdict", "unknown"),
        )
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to generate Navigator layer: {exc}") from exc


class _IOCItem(BaseModel):
    value: str
    type: str = "unknown"


class RetroactiveHuntRequest(BaseModel):
    iocs: list[_IOCItem]
    days_back: int = 30


@app.post("/ops/retroactive-hunt", tags=["Operations"])
async def retroactive_hunt(req: RetroactiveHuntRequest, _auth: None = Depends(_require_api_key)):
    """Search historical reports for the supplied IOCs (threat hunting)."""
    if not req.iocs:
        raise HTTPException(status_code=400, detail="No IOCs supplied")
    try:
        from soc_platform.domains.phishing.engine.services.retroactive_hunt import get_retroactive_hunt_engine
        engine = get_retroactive_hunt_engine()
        iocs = [{"value": i.value, "type": i.type} for i in req.iocs]
        return engine.hunt_multiple_iocs(iocs, days_back=req.days_back)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Retroactive hunt failed: {exc}") from exc


class WebhookRegistration(BaseModel):
    url: str
    events: list[str] | None = None
    headers: dict[str, str] | None = None


@app.get("/ops/webhooks", tags=["Operations"])
async def list_webhooks(_auth: None = Depends(_require_api_key)):
    """List registered outbound webhook endpoints."""
    from soc_platform.domains.phishing.engine.services.webhook_dispatcher import get_webhook_dispatcher
    return {"webhooks": get_webhook_dispatcher().list_webhooks()}


@app.post("/ops/webhooks", tags=["Operations"])
async def register_webhook(req: WebhookRegistration, _auth: None = Depends(_require_api_key)):
    """Register an outbound webhook for verdict/event notifications."""
    if not req.url.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="Webhook URL must be http(s)")
    from soc_platform.domains.phishing.engine.services.webhook_dispatcher import get_webhook_dispatcher
    webhook = get_webhook_dispatcher().register_webhook(req.url, req.events, req.headers)
    return {k: v for k, v in webhook.items() if k != "headers"}


class OverrideRequest(BaseModel):
    analysis_id: str
    new_verdict: str
    actions: list[str] = []
    analyst: str = "unknown"
    reason: str = ""


@app.post("/api/override", tags=["Analysis"])
async def soc_override(req: OverrideRequest, _auth: None = Depends(_require_api_key)):
    """SOC analyst override: re-set a verdict and trigger the response cascade."""
    report = _load_report(req.analysis_id)

    # Build the decision dict the action layer expects, carrying over context
    # from the stored report and applying the analyst's override.
    agent_results = report.get("agent_results") or []
    sender = report.get("sender", "")
    if not sender:
        for res in agent_results:
            if isinstance(res, dict) and res.get("agent_name") == "header_agent":
                sender = (res.get("metadata", {}) or {}).get("sender", "") or ""
                break

    decision = {
        "analysis_id": req.analysis_id,
        "verdict": req.new_verdict,
        "overall_risk_score": report.get("overall_risk_score", 0.0),
        "recommended_actions": req.actions,
        "agent_results": agent_results,
        "sender": sender,
        "user_principal_name": report.get("user_principal_name"),
        "internet_message_id": report.get("internet_message_id"),
        "graph_message_id": report.get("graph_message_id"),
        "llm_explanation": report.get("llm_explanation", ""),
        "reasons": [f"Analyst override by {req.analyst}: {req.reason}".strip()],
        "analyst_approved": True,
    }

    logger.info(
        "soc_override",
        analysis_id=req.analysis_id,
        analyst=req.analyst,
        new_verdict=req.new_verdict,
        actions=req.actions,
        reason=req.reason,
    )

    try:
        from soc_platform.domains.phishing.engine.action_layer.response_engine import ResponseEngine
        ResponseEngine().execute_actions(decision)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Override cascade failed: {exc}") from exc

    return {
        "status": "override_applied",
        "analysis_id": req.analysis_id,
        "new_verdict": req.new_verdict,
        "actions_executed": req.actions,
        "analyst": req.analyst,
    }
