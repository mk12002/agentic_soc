"""Every ``SOC_*`` setting checked before the platform starts, with what is wrong and how to fix it.

Settings come from the environment, where everything is a string and a typo is invisible: a mistyped number used
to crash start-up with a bare traceback, and worse, a mistyped *word* was silently accepted - ``SOC_ENVIRONMENT=
production`` (instead of ``prod``) ran the platform in development mode, with step-up MFA for approvals off, dev
sign-in allowed and the test clock honoured. ``check_environment`` reports every problem at once:

* each known setting against its type, range or allowed values
* a ``SOC_*`` name the platform does not know ("did you mean ...?") - a typo means the setting is silently unused
* production rules: Entra sign-in, MFA, encryption at rest, no dev secrets, PostgreSQL

Errors stop ``serve`` and ``scheduler`` (``python -m soc_platform config check`` lists them too); warnings are shown.
"""

from __future__ import annotations

import base64
import difflib
import ipaddress
import json
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class SettingProblem:
    level: str          # error | warning
    name: str
    message: str
    fix: str = ""

    def __str__(self) -> str:
        return f"{self.level.upper()} {self.name}: {self.message}" + (f" - {self.fix}" if self.fix else "")


BOOL = {"1", "0", "true", "false", "yes", "no", "on", "off"}
_URL = re.compile(r"^https?://[^\s/?#]+", re.IGNORECASE)
_DOMAIN = re.compile(r"^(?=.{1,253}$)([a-z0-9_-]{1,63}\.)+[a-z][a-z0-9-]{1,62}$")

# name -> (kind, argument). Kinds: int / float (argument: (min, max)), bool, choice (allowed values), url, json,
# datetime, file, dir, domains, cidrs, sha256, fernet, dburl, text (no check).
SPEC: dict[str, tuple[str, Any]] = {
    "SOC_ENVIRONMENT": ("choice", ("dev", "test", "prod")),
    "SOC_AUTH_MODE": ("choice", ("dev", "entra")),
    "SOC_CONNECTOR_MODE": ("choice", ("fake", "live")),
    "SOC_BLOB_STORE": ("choice", ("file", "database")),
    "SOC_LLM_PROVIDER": ("choice", ("none", "azure_openai", "azure_foundry", "anthropic", "openai_compatible")),
    "SOC_LOG_LEVEL": ("choice", ("debug", "info", "warning", "error", "critical")),
    "SOC_LOG_FORMAT": ("choice", ("json", "text")),
    "SOC_NOTIFY_MIN_SEVERITY": ("choice", ("informational", "low", "medium", "high", "critical")),
    "SOC_PHISHING_ENGINE": ("choice", ("auto", "1", "0", "true", "false", "on", "off", "yes", "no")),
    "SOC_LLM_MAX_TOKENS_FIELD": ("choice", ("max_tokens", "max_completion_tokens")),
    "SOC_PORT": ("int", (1, 65535)),
    "SOC_API_WORKERS": ("int", (1, 256)),
    "SOC_API_THREADS": ("int", (4, 10_000)),
    "SOC_SHUTDOWN_GRACE_SECONDS": ("int", (1, 3600)),
    "SOC_CONNECTOR_RATE_SHARE": ("int", (1, 64)),
    "SOC_DB_POOL_SIZE": ("int", (1, 10_000)),
    "SOC_DB_MAX_OVERFLOW": ("int", (0, 10_000)),
    "SOC_DB_POOL_RECYCLE": ("int", (0, 86_400 * 7)),
    "SOC_DB_POOL_TIMEOUT": ("float", (0.1, 3_600)),
    "SOC_DB_STATEMENT_TIMEOUT_SECONDS": ("float", (0, 86_400)),
    "SOC_DB_IDLE_TX_TIMEOUT_SECONDS": ("float", (0, 86_400)),
    "SOC_RAW_RETENTION_DAYS": ("int", (1, 36_500)),
    "SOC_ACCESS_LOG_RETENTION_DAYS": ("int", (1, 36_500)),
    "SOC_LLM_LOG_RETENTION_DAYS": ("int", (1, 36_500)),
    "SOC_EVENT_RETENTION_DAYS": ("int", (0, 36_500)),
    "SOC_LLM_MONTHLY_TOKEN_BUDGET": ("int", (0, 10**12)),
    "SOC_LLM_CONCURRENCY": ("int", (1, 256)),
    "SOC_LLM_BREAKER_FAILURES": ("int", (1, 1_000)),
    "SOC_LLM_BREAKER_SECONDS": ("float", (1, 86_400)),
    "SOC_LLM_TIMEOUT_SECONDS": ("float", (1, 3_600)),
    "SOC_LLM_TIMEOUT_LARGE_SECONDS": ("float", (1, 3_600)),
    "SOC_LLM_CONNECT_TIMEOUT_SECONDS": ("float", (0.5, 600)),
    "SOC_BRIEF_CACHE_SECONDS": ("int", (0, 86_400 * 7)),
    "SOC_RISK_CACHE_SECONDS": ("float", (0, 86_400)),
    "SOC_CONFIG_RELOAD_SECONDS": ("float", (0, 3_600)),
    "SOC_RATE_LIMIT_RPS": ("float", (0.1, 1_000_000)),
    "SOC_RATE_LIMIT_BURST": ("int", (1, 1_000_000)),
    "SOC_SYNC_MAX_PAGES": ("int", (1, 10_000_000)),
    "SOC_SYNC_LOCK_WAIT_SECONDS": ("float", (0, 3_600)),
    "SOC_WATERMARK_OVERLAP_MINUTES": ("float", (0, 10_080)),
    "SOC_RESOLUTION_AUTO_THRESHOLD": ("float", (0.6, 1.0)),
    "SOC_RECORD_MAX_CALLS": ("int", (1, 1_000_000)),
    "SOC_SCHEDULER_START_DELAY": ("float", (0, 864_000)),
    "SOC_SCHEDULER_STALE_SECONDS": ("int", (10, 864_000)),
    "SOC_SCHEDULER_STUCK_SECONDS": ("int", (60, 864_000)),
    "SOC_JOB_LEASE_SECONDS": ("int", (30, 86_400)),
    "SOC_ACTION_STUCK_SECONDS": ("int", (60, 86_400)),
    "SOC_SELF_CHECK_CONFIRM_SECONDS": ("float", (0, 3_600)),
    "SOC_VM_FOLLOWUP_DAYS": ("int", (1, 365)),
    "SOC_LOG_FILE_MAX_MB": ("float", (0.1, 100_000)),
    "SOC_LOG_FILE_BACKUPS": ("int", (0, 1_000)),
    "SOC_CLOCK_OFFSET_SECONDS": ("float", (-10**10, 10**10)),
    "SOC_KILL_SWITCH": ("bool", None), "SOC_REQUIRE_MFA": ("bool", None), "SOC_LLM_REDACT_PII": ("bool", None),
    "SOC_EMBEDDED_SCHEDULER": ("bool", None), "SOC_SCHEMA_MANAGE": ("bool", None), "SOC_STORE_RAW_PAYLOADS": ("bool", None), "SOC_DEV_TOKENS_REMOTE": ("bool", None),
    "SOC_LLM_EXPLAIN_AUTO_CLOSED": ("bool", None), "SOC_LLM_JSON_MODE": ("bool", None),
    "SOC_LLM_SERVER_FALLBACK": ("bool", None), "SOC_LOG_CONFIGURE": ("bool", None),
    "SOC_REQUIRE_MODEL_MANIFEST": ("bool", None), "SOC_PHISHING_SANDBOX": ("bool", None),
    "SOC_LLM_ENDPOINT": ("url", None), "SOC_PUBLIC_URL": ("url", None), "SOC_ALERT_API_URL": ("url", None),
    "SOC_LLM_EXTRA_HEADERS": ("json", None),
    "SOC_CLOCK_FREEZE": ("datetime", None),
    "SOC_CONNECTORS_CONFIG": ("file", None), "SOC_SUPPLIERS_FILE": ("file", None), "SOC_LLM_CA_BUNDLE": ("file", None),
    "SOC_FIXTURES_DIR": ("dir", None), "SOC_SAMPLE_CORPUS_DIR": ("dir", None),
    "SOC_ORG_DOMAINS": ("domains", None), "SOC_SUPPLIER_DOMAINS": ("domains", None),
    "SOC_TRUSTED_PROXIES": ("cidrs", None),
    "SOC_BREAKGLASS_SHA256": ("sha256", None),
    "SOC_DATA_KEY": ("fernet", None),
    "SOC_DATABASE_URL": ("dburl", None),
    "SOC_LLM_APPROVED_ENDPOINTS": ("urls", None),
}
# read by the platform, not checked beyond being set (names, ids, paths it creates, secrets)
TEXT = {"SOC_HOST", "SOC_DB_RUNTIME_ROLE", "SOC_ENTRA_TENANT_ID", "SOC_ENTRA_AUDIENCE", "SOC_ENTRA_SCOPE", "SOC_ENTRA_SPA_CLIENT_ID",
        "SOC_DEV_JWT_SECRET", "SOC_MFA_AUTH_CONTEXT", "SOC_RAW_PAYLOAD_DIR", "SOC_REPORT_OUTPUT_DIR",
        "SOC_LLM_API_KEY", "SOC_LLM_API_VERSION", "SOC_LLM_AUTH_HEADER", "SOC_LLM_AUTH_PREFIX", "SOC_LLM_DEPLOYMENT",
        "SOC_LLM_DEPLOYMENT_SMALL", "SOC_LLM_MODEL_VERSION", "SOC_NOTIFY_WEBHOOKS", "SOC_RECORD_FIXTURES_DIR",
        "SOC_RECORD_SALT", "SOC_LOG_FILE", "SOC_SCHEDULER_LIVENESS_FILE", "SOC_PHISHING_HOME", "SOC_PHISHING_ENGINE_LOG_LEVEL", "SOC_ENV_FILE",
        "SOC_JOB_ACTIONS_SECONDS", "SOC_JOB_DAILY_REPORT_SECONDS", "SOC_JOB_FOLLOWUP_SECONDS", "SOC_JOB_INCIDENT_SECONDS",
        "SOC_JOB_INTELLIGENCE_SECONDS", "SOC_JOB_NOTIFY_SECONDS", "SOC_JOB_PHISHING_SECONDS",
        "SOC_JOB_RETENTION_SECONDS", "SOC_JOB_SELF_CHECK_SECONDS", "SOC_JOB_VM_SECONDS", "SOC_JOB_WEEKLY_REPORTS_SECONDS"}
JOB_SECONDS = {n for n in TEXT if n.startswith("SOC_JOB_")}
IGNORED_PREFIXES = ("SOC_TEST_", "SOC_LIVE_")          # test-suite controls


def _num(kind: str, raw: str) -> float | None:
    try:
        return int(raw) if kind == "int" else float(raw)
    except ValueError:
        return None


def _check_one(name: str, raw: str) -> list[SettingProblem]:
    kind, arg = SPEC.get(name, ("job" if name in JOB_SECONDS else "text", None))
    v = raw.strip()
    bad = lambda msg, fix="": [SettingProblem("error", name, msg, fix)]
    if kind == "job":
        n = _num("int", v)
        return [] if n is not None and n >= 10 else bad(f"'{v[:40]}' is not a whole number of seconds (10 or more)",
                                                        "e.g. 600")
    if kind in ("int", "float"):
        n = _num(kind, v)
        if n is None:
            return bad(f"'{v[:40]}' is not {'a whole number' if kind == 'int' else 'a number'}",
                       f"use a number between {arg[0]:,} and {arg[1]:,}")
        if not arg[0] <= n <= arg[1]:
            return bad(f"{n:,} is outside {arg[0]:,}..{arg[1]:,}", "")
        return []
    if kind == "bool":
        return [] if v.lower() in BOOL else bad(f"'{v[:40]}' is not true or false", "use true or false (1 / 0)")
    if kind == "choice":
        if v.lower() in arg:
            return []
        near = difflib.get_close_matches(v.lower(), list(arg), n=1, cutoff=0.4)
        return bad(f"'{v[:40]}' is not one of {', '.join(arg)}", f"did you mean '{near[0]}'?" if near else "")
    if kind == "url":
        return [] if _URL.match(v) else bad(f"'{v[:80]}' is not an http(s) URL", "")
    if kind == "urls":
        wrong = [u for u in v.split(",") if u.strip() and not _URL.match(u.strip())]
        return bad(f"not URLs: {', '.join(w[:60] for w in wrong[:3])}", "") if wrong else []
    if kind == "json":
        try:
            ok = isinstance(json.loads(v), dict)
        except ValueError:
            ok = False
        return [] if ok else bad("must be a JSON object", '{"X-Header": "value"}')
    if kind == "datetime":
        try:
            datetime.fromisoformat(v)
            return []
        except ValueError:
            return bad(f"'{v[:40]}' is not an ISO date-time", "e.g. 2026-09-20T10:00:00+00:00")
    if kind == "file":
        return [] if os.path.isfile(v) else bad(f"file '{v[:120]}' does not exist", "")
    if kind == "dir":
        return [] if os.path.isdir(v) else bad(f"folder '{v[:120]}' does not exist", "")
    if kind == "domains":
        wrong = [d for d in (x.strip().lower() for x in v.split(",")) if d and not _DOMAIN.match(d)]
        return bad(f"not domains: {', '.join(w[:60] for w in wrong[:3])}", "comma-separated, e.g. example.com") \
            if wrong else []
    if kind == "cidrs":
        wrong = []
        for x in (s.strip() for s in v.split(",") if s.strip()):
            try:
                ipaddress.ip_network(x, strict=False)
            except ValueError:
                wrong.append(x)
        return bad(f"not IP addresses or ranges: {', '.join(wrong[:3])}", "e.g. 10.0.0.5,10.1.0.0/16") if wrong else []
    if kind == "sha256":
        return [] if re.fullmatch(r"[0-9a-fA-F]{64}", v) else bad("must be a SHA-256 (64 hex characters)", "")
    if kind == "fernet":
        wrong = 0
        for k in (x.strip() for x in v.split(",") if x.strip()):
            try:
                wrong += len(base64.urlsafe_b64decode(k.encode())) != 32
            except ValueError:
                wrong += 1
        return bad("a key is not a valid Fernet key (32 bytes, URL-safe base64)",
                   "generate one: python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\"") \
            if wrong else []
    if kind == "dburl":
        return [] if v.split(":", 1)[0].split("+")[0] in ("sqlite", "postgresql") else \
            bad("must be a sqlite:/// or postgresql:// URL", "")
    return []


def _setting_value(env: Mapping[str, str], name: str) -> str:
    """A setting's value, from ``NAME`` or the vault-mounted file ``NAME_FILE``."""
    if env.get(name):
        return env[name].strip()
    path = env.get(f"{name}_FILE")
    if path and Path(path).is_file():
        return Path(path).read_text(encoding="utf-8", errors="ignore").strip()
    return ""


def _sslmode(url: str) -> str:
    from urllib.parse import parse_qs, urlsplit

    try:
        return (parse_qs(urlsplit(url).query).get("sslmode") or [""])[0].lower()
    except ValueError:
        return ""


def _known(name: str) -> bool:
    base = name.removesuffix("_FILE")   # NAME_FILE: a vault-mounted secret for NAME
    return base in SPEC or base in TEXT or name in SPEC or name in TEXT


def check_environment(env: Mapping[str, str] | None = None) -> list[SettingProblem]:
    env = os.environ if env is None else env
    out: list[SettingProblem] = []
    names = sorted(SPEC) + sorted(TEXT)
    for name, raw in sorted(env.items()):
        if not name.startswith("SOC_") or name.startswith(IGNORED_PREFIXES):
            continue
        if not _known(name):
            near = difflib.get_close_matches(name, names, n=1, cutoff=0.75)
            out.append(SettingProblem("warning", name, "not a setting of this platform: it is ignored",
                                      f"did you mean {near[0]}?" if near else ""))
            continue
        if name.endswith("_FILE") and name not in SPEC and name not in TEXT and raw.strip():
            # a vault-mounted secret: a wrong path would silently leave the secret empty
            p = Path(raw.strip())
            if not p.is_file():
                out.append(SettingProblem("error", name, f"the secret file {raw.strip()} does not exist",
                                          "mount the secret there, or correct the path"))
            elif not (content := p.read_text(encoding="utf-8", errors="ignore").strip()):
                out.append(SettingProblem("error", name, "the secret file is empty", "write the secret into the file"))
            elif name.removesuffix("_FILE") in SPEC:
                # the mounted value gets the same check as the plain setting (a malformed key fails here, not later)
                out += [SettingProblem(p_.level, name, p_.message, p_.fix)
                        for p_ in _check_one(name.removesuffix("_FILE"), content)]
            continue
        if raw.strip() == "" or name.endswith("_FILE"):
            continue
        out += _check_one(name, raw)
    lower = {k: v.strip().lower() for k, v in env.items() if k.startswith("SOC_")}
    prod = lower.get("SOC_ENVIRONMENT") == "prod"
    mode = lower.get("SOC_AUTH_MODE", "dev")
    if mode == "entra" and not (env.get("SOC_ENTRA_TENANT_ID") and env.get("SOC_ENTRA_AUDIENCE")):
        out.append(SettingProblem("error", "SOC_AUTH_MODE", "Entra sign-in needs SOC_ENTRA_TENANT_ID and SOC_ENTRA_AUDIENCE",
                                  "set both (CLIENT_DEPLOYMENT_GUIDE.md section 3)"))
    env_name = lower.get("SOC_ENVIRONMENT")
    if not env_name and (mode == "entra" or lower.get("SOC_CONNECTOR_MODE") == "live"):
        # a real deployment that forgot SOC_ENVIRONMENT ran as "dev": step-up MFA off, encryption optional
        out.append(SettingProblem("error", "SOC_ENVIRONMENT", "not set, so the platform would run as 'dev' with "
                                  "production protections off", "set SOC_ENVIRONMENT=prod (or dev / test on purpose)"))
    if mode == "dev" and env_name != "test":
        if lower.get("SOC_CONNECTOR_MODE") == "live":
            out.append(SettingProblem("error", "SOC_CONNECTOR_MODE", "real tools with development sign-in: anyone who "
                                      "reaches the port could sign in with any role", "set SOC_AUTH_MODE=entra"))
        secret_len = len((env.get("SOC_DEV_JWT_SECRET") or "").strip())
        if 0 < secret_len < 32:
            out.append(SettingProblem("error", "SOC_DEV_JWT_SECRET", "shorter than 32 characters: tokens can be forged",
                                      "use a long random value (python -c \"import secrets; print(secrets.token_urlsafe(48))\")"))
        if lower.get("SOC_DEV_TOKENS_REMOTE") in {"1", "true", "yes", "on"}:
            out.append(SettingProblem("warning", "SOC_DEV_TOKENS_REMOTE", "any machine that reaches the port can sign in "
                                      "with any role (fixtures only: real tools are refused under dev sign-in)",
                                      "leave it off outside a closed demo"))
    if prod:
        if mode != "entra":
            out.append(SettingProblem("error", "SOC_AUTH_MODE", "production requires Entra sign-in", "set SOC_AUTH_MODE=entra"))
        if lower.get("SOC_REQUIRE_MFA") in {"0", "false", "no", "off"}:
            out.append(SettingProblem("error", "SOC_REQUIRE_MFA", "step-up MFA for approvals is switched off in production",
                                      "remove SOC_REQUIRE_MFA or set it to true"))
        if not (env.get("SOC_DATA_KEY") or env.get("SOC_DATA_KEY_FILE")):
            out.append(SettingProblem("error", "SOC_DATA_KEY", "production requires encryption at rest",
                                      "set SOC_DATA_KEY (or mount SOC_DATA_KEY_FILE)"))
        domains = [d.strip() for d in lower.get("SOC_ORG_DOMAINS", "").split(",") if d.strip()]
        if mode == "entra" and not any(d.endswith(".onmicrosoft.com") for d in domains):
            out.append(SettingProblem("warning", "SOC_ORG_DOMAINS", "no <tenant>.onmicrosoft.com domain: people's "
                                      "addresses in it are not pseudonymised before a model call",
                                      "add the tenant's onmicrosoft.com domain"))
        if lower.get("SOC_LLM_REDACT_PII") in {"0", "false", "no", "off"}:
            out.append(SettingProblem("warning", "SOC_LLM_REDACT_PII", "identities are sent to the model unpseudonymised",
                                      "keep it on unless data protection has approved"))
        for n in ("SOC_DEV_JWT_SECRET", "SOC_DEV_TOKENS_REMOTE", "SOC_CLOCK_OFFSET_SECONDS", "SOC_CLOCK_FREEZE"):
            if env.get(n):
                out.append(SettingProblem("warning", n, "set in production, where it is ignored", "remove it"))
        db_url = _setting_value(env, "SOC_DATABASE_URL") or "sqlite"
        if db_url.startswith("sqlite"):
            out.append(SettingProblem("error", "SOC_DATABASE_URL", "production on SQLite (one host, no failover, no "
                                      "point-in-time recovery)", "use PostgreSQL (CLIENT_DEPLOYMENT_GUIDE.md section 2.1)"))
        elif _sslmode(db_url) not in {"verify-full", "verify-ca"}:
            out.append(SettingProblem("error", "SOC_DATABASE_URL", "the database connection does not verify the "
                                      "server's certificate (libpq's default 'prefer' can be downgraded or intercepted)",
                                      "add ?sslmode=verify-full&sslrootcert=system (managed server) or "
                                      "sslmode=verify-ca&sslrootcert=<cluster CA> (HIGH_AVAILABILITY.md section 4)"))
        if lower.get("SOC_LLM_PROVIDER", "none") != "none":
            approved = [u.strip() for u in (env.get("SOC_LLM_APPROVED_ENDPOINTS") or "").split(",") if u.strip()]
            if not approved:
                out.append(SettingProblem("error", "SOC_LLM_APPROVED_ENDPOINTS", "a model provider is set but no endpoint "
                                          "is approved: prompts could go to any address", "list the approved endpoint(s)"))
            if any(not u.lower().startswith("https://") for u in approved + [env.get("SOC_LLM_ENDPOINT") or "https://"]):
                out.append(SettingProblem("error", "SOC_LLM_ENDPOINT", "model endpoints must use https://", ""))
        if lower.get("SOC_DB_STATEMENT_TIMEOUT_SECONDS") in {"0", "0.0"}:
            out.append(SettingProblem("warning", "SOC_DB_STATEMENT_TIMEOUT_SECONDS", "no limit on one SQL statement: a "
                                      "hung statement holds its locks indefinitely", "leave unset (production default 300)"))
        if lower.get("SOC_BLOB_STORE", "file") == "file":
            out.append(SettingProblem("warning", "SOC_BLOB_STORE", "stored e-mails and reports are on this host's disk: "
                                      "safe only with one host or a volume every replica shares",
                                      "set SOC_BLOB_STORE=database for several hosts (HIGH_AVAILABILITY.md)"))
    return out
