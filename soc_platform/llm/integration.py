"""Which model provider the platform uses, and its credentials - set by an administrator in the console.

Two ways to give the platform a model (the *AI integration* card on the AI usage screen):

* **The organisation's in-house LLM gateway**, reached through its own SDK with a service account: an auth token and a
  session token entered here. Every person signs in with SSO as usual; every model call is made with the service
  account, and each person's use is still counted against their own limits (AI usage policy).
* **An API key** for OpenRouter, an OpenAI-compatible endpoint, Anthropic or Azure AI Foundry.

Rules this module keeps:

* **Credentials are write-only.** They are encrypted at rest with the platform's data key (``SOC_DATA_KEY``), never
  returned by the API, never written to the audit log or the logs (the audit records *which* credential changed, by
  whom), and stored per provider: switching provider never sends one vendor's key to another.
* **Endpoints come from the deployment's approved list** (``SOC_LLM_APPROVED_ENDPOINTS``, mandatory in production):
  an administrator chooses among them but cannot send prompts - which carry investigation data - anywhere else. The
  gateway's SDK and its location are deployment settings (``SOC_LLM_GATEWAY_SDK``), not console ones.
* **The console setting wins over the environment once saved.** Until then the ``SOC_LLM_*`` settings apply, as
  before (their own credentials, from the environment or ``<NAME>_FILE``).

Every change is a new version (who, when, why), audited.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import JSON, Integer, String, Text, select
from sqlalchemy.orm import Mapped, Session, mapped_column

from soc_platform.core.db import Base, BoundedText, UTCDateTime
from soc_platform.core.models import utcnow

# id -> what the console shows and needs. endpoint: "none" (the SDK knows where it is), "required", "optional" or
# "default" (a fixed public address, still subject to the approved list).
PROVIDERS: dict[str, dict[str, Any]] = {
    "none": {"label": "Off - the platform writes every text itself", "secrets": (), "endpoint": "none"},
    "enterprise_gateway": {"label": "In-house LLM gateway (service account)", "secrets": ("auth_token", "session_token"),
                           "endpoint": "none", "needs_one_of": ("auth_token", "session_token")},
    "openrouter": {"label": "OpenRouter (API key)", "secrets": ("api_key",), "endpoint": "default",
                   "default_endpoint": "https://openrouter.ai/api/v1", "needs_one_of": ("api_key",)},
    "openai_compatible": {"label": "OpenAI-compatible endpoint (API key)", "secrets": ("api_key",),
                          "endpoint": "required"},
    "anthropic": {"label": "Anthropic API (API key)", "secrets": ("api_key",), "endpoint": "optional",
                  "needs_one_of": ("api_key",)},
    "azure_foundry": {"label": "Azure AI Foundry (API key)", "secrets": ("api_key",), "endpoint": "required",
                      "needs_one_of": ("api_key",)},
}
SECRET_LABELS = {"auth_token": "Auth token", "session_token": "Session token", "api_key": "API key"}
# where a provider set in the deployment settings (not the console) reads each credential (or <NAME>_FILE)
ENV_SECRETS = {"auth_token": "SOC_LLM_GATEWAY_AUTH_TOKEN", "session_token": "SOC_LLM_GATEWAY_SESSION_TOKEN",
               "api_key": "SOC_LLM_API_KEY"}
SETTINGS_ONLY_LABELS = {"azure_openai": "Azure OpenAI (deployment settings)"}
EXPIRY_WARNING_DAYS = 3
_MAX_SECRET = 16_384


class LLMIntegration(Base):
    """Versioned provider choice; the newest row is in force. No secret is ever stored here."""

    __tablename__ = "llm_integrations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    provider: Mapped[str] = mapped_column(String(32))
    endpoint: Mapped[str | None] = mapped_column(String(512), nullable=True)
    set_by: Mapped[str] = mapped_column(String(256))
    note: Mapped[str] = mapped_column(BoundedText(2000), default="")
    created_at: Mapped[Any] = mapped_column(UTCDateTime(), default=utcnow)


class LLMSecret(Base):
    """One credential of one provider (``openrouter.api_key``), sealed with the data key."""

    __tablename__ = "llm_secrets"

    name: Mapped[str] = mapped_column(String(64), primary_key=True)
    sealed: Mapped[str] = mapped_column(Text)
    encrypted: Mapped[bool] = mapped_column(default=True)
    set_by: Mapped[str] = mapped_column(String(256))
    set_at: Mapped[Any] = mapped_column(UTCDateTime(), default=utcnow)
    expires_at: Mapped[Any | None] = mapped_column(UTCDateTime(), nullable=True)
    meta: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)


@dataclass
class Effective:
    """The provider in force and what it needs. ``secrets`` holds plain values - never log or return it."""

    provider: str
    endpoint: str | None
    source: str                                   # console | settings
    secrets: dict[str, str] = field(default_factory=dict, repr=False)

    @property
    def configured(self) -> bool:
        return self.provider not in ("", "none")


def _seal(settings: Any, value: str) -> tuple[str, bool]:
    from soc_platform.core.crypto import get_cipher

    cipher = get_cipher(settings)                 # in production a data key is mandatory (raises without one)
    if cipher is None:                            # development without SOC_DATA_KEY: stored, and shown as unencrypted
        return base64.b64encode(value.encode()).decode(), False
    return base64.b64encode(cipher.encrypt(value.encode())).decode(), True


def _unseal(settings: Any, row: LLMSecret) -> str:
    from soc_platform.core.crypto import get_cipher

    blob = base64.b64decode(row.sealed.encode())
    if not row.encrypted:
        if settings.environment == "prod":
            raise ValueError(f"credential {row.name} is stored without encryption; enter it again")
        return blob.decode()
    cipher = get_cipher(settings)
    if cipher is None:
        raise ValueError(f"credential {row.name} is encrypted but no data key (SOC_DATA_KEY) is configured")
    return cipher.decrypt(blob).decode()


def _aware(dt: Any) -> Any:
    from datetime import UTC

    return dt.replace(tzinfo=UTC) if dt is not None and dt.tzinfo is None else dt


class IntegrationStore:
    def __init__(self, session: Session, settings: Any) -> None:
        self.s, self.settings = session, settings

    def active_row(self) -> LLMIntegration | None:
        return self.s.execute(select(LLMIntegration).order_by(LLMIntegration.id.desc()).limit(1)).scalars().first()

    def effective(self) -> Effective:
        row = self.active_row()
        if row is None:
            return Effective(self.settings.llm_provider or "none", self.settings.llm_endpoint, "settings")
        secrets: dict[str, str] = {}
        for name in PROVIDERS.get(row.provider, {}).get("secrets", ()):
            sec = self.s.get(LLMSecret, f"{row.provider}.{name}")
            if sec is not None:
                secrets[name] = _unseal(self.settings, sec)
        return Effective(row.provider, row.endpoint, "console", secrets)

    def status(self) -> dict[str, Any]:
        """What the console shows: provider, endpoint, and for each credential whether it is set - never its value."""
        row = self.active_row()
        eff_provider = row.provider if row else (self.settings.llm_provider or "none")
        now = utcnow()
        creds = []
        for name in PROVIDERS.get(eff_provider, {}).get("secrets", ()):
            sec = self.s.get(LLMSecret, f"{eff_provider}.{name}") if row else None
            exp = _aware(sec.expires_at) if sec else None
            if row is None:                    # the deployment provides it (environment or a vault mount)
                from soc_platform.config import secret

                creds.append({"name": name, "label": SECRET_LABELS.get(name, name), "managed_by_deployment": True,
                              "set": bool(secret(ENV_SECRETS[name])), "set_by": None, "set_at": None, "encrypted": None,
                              "expires_at": None, "expired": False, "expires_soon": False})
                continue
            creds.append({"name": name, "label": SECRET_LABELS.get(name, name), "set": sec is not None,
                          "managed_by_deployment": False,
                          "set_by": sec.set_by if sec else None, "set_at": _aware(sec.set_at).isoformat() if sec else None,
                          "encrypted": bool(sec.encrypted) if sec else None,
                          "expires_at": exp.isoformat() if exp else None,
                          "expired": bool(exp and exp <= now),
                          "expires_soon": bool(exp and now < exp <= now + timedelta(days=EXPIRY_WARNING_DAYS))})
        return {"provider": eff_provider, "label": PROVIDERS.get(eff_provider, {}).get(
                    "label", SETTINGS_ONLY_LABELS.get(eff_provider, eff_provider)),
                "endpoint": row.endpoint if row else self.settings.llm_endpoint,
                "source": "console" if row else "settings", "credentials": creds,
                "set_by": row.set_by if row else None, "set_at": _aware(row.created_at).isoformat() if row else None,
                "note": row.note if row else ""}

    def save(self, *, provider: str, endpoint: str | None, secrets: dict[str, str | None] | None,
             expires_at: datetime | None, by: Any, note: str = "") -> LLMIntegration:
        """Set the provider (and replace or clear its credentials). Administrators only (manage_access); audited
        with the credential *names* that changed, never their values."""
        from soc_platform.core.audit import AuditLog
        from soc_platform.core.auth import Perm
        from soc_platform.llm.gateway import check_endpoint

        if by.is_service or by.is_agent or not by.can(Perm.MANAGE_ACCESS):
            raise PermissionError("an administrator (manage_access) sets the AI provider and its credentials")
        spec = PROVIDERS.get(provider)
        if spec is None:
            raise ValueError(f"unknown provider '{provider}' (one of {', '.join(PROVIDERS)})")
        endpoint = (endpoint or "").strip().rstrip("/") or None
        if spec["endpoint"] == "none":
            endpoint = None
        elif spec["endpoint"] == "default":
            endpoint = endpoint or spec["default_endpoint"]
        elif spec["endpoint"] == "required" and not endpoint:
            raise ValueError(f"{spec['label']} needs its endpoint address")
        if endpoint:
            if not endpoint.lower().startswith(("https://", "http://")):
                raise ValueError("the endpoint must be an http(s) address")
            check_endpoint(self.settings, endpoint)       # only an approved endpoint (and https in production)
        secrets = dict(secrets or {})
        unknown = [k for k in secrets if k not in spec["secrets"]]
        if unknown:
            raise ValueError(f"{spec['label']} takes no credential named {', '.join(sorted(unknown))}")
        for k, v in secrets.items():
            if v is not None and (not isinstance(v, str) or not v.strip() or len(v) > _MAX_SECRET
                                  or any(ord(ch) < 32 for ch in v.strip())):
                raise ValueError(f"{SECRET_LABELS.get(k, k)}: paste the value exactly as issued (one line)")
        if expires_at is not None and _aware(expires_at) <= utcnow():
            raise ValueError("the expiry date is in the past")
        have = {n for n in spec["secrets"] if self.s.get(LLMSecret, f"{provider}.{n}") is not None}
        after = (have | {k for k, v in secrets.items() if v}) - {k for k, v in secrets.items() if v is None}
        needs = spec.get("needs_one_of") or ()
        if needs and not after & set(needs):
            raise ValueError(f"{spec['label']} needs its {' or '.join(SECRET_LABELS[n].lower() for n in needs)}")

        before = self.status()
        changed: list[str] = []
        for k, v in secrets.items():
            key = f"{provider}.{k}"
            cur = self.s.get(LLMSecret, key)
            if v is None:
                if cur is not None:
                    self.s.delete(cur)
                    changed.append(f"{k} cleared")
                continue
            sealed, encrypted = _seal(self.settings, v.strip())
            if cur is None:
                cur = LLMSecret(name=key, sealed=sealed, encrypted=encrypted, set_by=by.id)
                self.s.add(cur)
            else:
                cur.sealed, cur.encrypted, cur.set_by, cur.set_at = sealed, encrypted, by.id, utcnow()
            cur.expires_at = expires_at
            changed.append(f"{k} replaced")
        if expires_at is not None and not secrets:        # a new expiry date for the credentials already stored
            for n in have:
                self.s.get(LLMSecret, f"{provider}.{n}").expires_at = expires_at
            changed.append("expiry date")
        row = LLMIntegration(provider=provider, endpoint=endpoint, set_by=by.id, note=(note or "")[:2000])
        self.s.add(row)
        self.s.flush()
        AuditLog(self.s).append(actor_type=by.actor_type, actor_id=by.id, event_type="llm.integration_changed",
                                subject_type="llm_integration", subject_id=str(row.id),
                                payload={"provider": {"from": before["provider"], "to": provider},
                                         "endpoint": {"from": before["endpoint"], "to": endpoint},
                                         "credentials": changed, "note": (note or "")[:500]})
        return row

    def history(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.s.execute(select(LLMIntegration).order_by(LLMIntegration.id.desc()).limit(limit)).scalars()
        return [{"id": r.id, "provider": r.provider, "endpoint": r.endpoint, "set_by": r.set_by, "note": r.note,
                 "created_at": _aware(r.created_at).isoformat()} for r in rows]


def effective(session: Session, settings: Any) -> Effective:
    return IntegrationStore(session, settings).effective()


def configured(session: Session, settings: Any) -> bool:
    """Is any model provider in force (console or settings)? A console choice of "off" wins over the settings."""
    try:
        return effective(session, settings).configured
    except ValueError:                            # a credential that cannot be read: the provider cannot be used
        return False


def is_auth_error(exc: BaseException) -> bool:
    """The provider refused the credentials (expired or revoked token, wrong key) - as opposed to an outage."""
    status = getattr(getattr(exc, "response", None), "status_code", None) or getattr(exc, "status_code", None) \
        or getattr(exc, "status", None)
    if status in (401, 403):
        return True
    name = type(exc).__name__.lower()
    return any(w in name for w in ("auth", "unauthori", "forbidden", "credential", "permissiondenied", "expired"))


def connection_check(s: Session, settings: Any, by: Any) -> dict[str, Any]:
    """Every step a provider must pass before the platform relies on it, each failure with its fix. In the
    organisation's environment this is where the real gateway SDK is first exercised against what the platform
    expects of it."""
    import importlib.util

    from soc_platform.llm.gateway import LLMGateway, NullProvider
    from soc_platform.llm.usage_policy import UsagePolicyStore

    steps: list[dict[str, Any]] = []

    def step(name: str, ok: bool, detail: str, fix: str = "") -> bool:
        steps.append({"step": name, "ok": ok, "detail": detail, "fix": fix})
        return ok

    def done() -> dict[str, Any]:
        return {"ok": all(x["ok"] for x in steps), "steps": steps}

    st = IntegrationStore(s, settings).status()
    if not step("Provider chosen", st["provider"] != "none", PROVIDERS.get(st["provider"], {}).get("label", st["provider"]),
                "choose a provider and enter its credentials"):
        return done()
    if st["provider"] == "enterprise_gateway":
        import os

        mod = os.environ.get("SOC_LLM_GATEWAY_SDK", "").strip()
        try:
            found = bool(mod) and importlib.util.find_spec(mod) is not None
        except (ImportError, ValueError):
            found = False
        if not step("Gateway SDK installed", found, "found" if found else "not found in this environment",
                    "install the gateway's SDK from the organisation's package index and name its module in "
                    "SOC_LLM_GATEWAY_SDK (deployment setting)"):
            return done()
    missing = [c["label"] for c in st["credentials"] if not c["set"]]
    expired = [c["label"] for c in st["credentials"] if c["expired"]]
    if st["source"] == "console":
        step("Credentials entered", not expired and len(missing) < len(st["credentials"]),
             "expired: " + ", ".join(expired) if expired else
             ("all entered" if not missing else "not entered: " + ", ".join(missing)),
             "enter the current token or key" if expired or missing else "")
    try:
        gw = LLMGateway(s, settings, actor=by)
    except Exception as exc:  # noqa: BLE001 - the step's outcome is the point: shown with its fix
        step("Provider starts", False, f"{type(exc).__name__}: {str(exc)[:200]}",
             "the endpoint must be on SOC_LLM_APPROVED_ENDPOINTS (and https in production)")
        return done()
    if not step("Provider starts", not isinstance(gw.provider, NullProvider), gw.provider.name,
                "the stored credentials could not be read: enter them again"):
        return done()
    lister = getattr(gw.provider, "list_models", None)
    listed: list[dict[str, Any]] = []
    if lister is not None:
        try:
            listed = lister()
            step("Model list", True, f"{len(listed)} model(s) offered" if listed else
                 "the provider publishes no list - add model names on this screen instead")
        except Exception as exc:  # noqa: BLE001 - shown with its fix
            auth = is_auth_error(exc)
            step("Model list", False, f"{type(exc).__name__}: {str(exc)[:200]}",
                 "the credentials were refused: enter a new token or key" if auth else
                 "check the endpoint and the SDK's model-list call (SOC_LLM_GATEWAY_MODELS_CALL)")
            if auth:
                return done()
    from soc_platform.llm.usage_policy import _size

    pol = UsagePolicyStore(s, settings).active()
    name = pol["default_models"].get("small") or (pol["models"][0]["name"] if pol["models"] else "")
    offered = sorted(x["name"] for x in listed if not x.get("deprecated")) or sorted(x["name"] for x in listed)
    if offered and name not in offered:     # a first connection: test a model the provider says it serves
        name = next((n for n in offered if _size(n) == "small"), offered[0])
    spec = next((m for m in pol["models"] if m["name"] == name), {"name": name, "deployment": name, "size": _size(name)})
    if not step("A model to test", bool(name), name or "none offered", "refresh the model list or add a model name"):
        return done()
    result = gw.qualify(spec)
    if step("Answer passes the platform's check", bool(result.get("ok")),
            f"{name}: {result.get('detail')}" + (f" ({result['latency_ms']} ms)" if result.get("latency_ms") else ""),
            "the credentials were refused: enter a new token or key" if result.get("auth_error") else
            "choose another model for this size of work, or check the SDK's chat arguments"):
        step("Token usage reported", True,                  # a warning, not a failure: budgets still work
             "the provider reports tokens per answer" if result.get("usage_reported") else
             "no token counts in the answer: budgets use an estimate (about 4 characters per token)")
        steps[-1]["warning"] = not result.get("usage_reported")
        raise_insight(s, "credentials", severity="high", title="", steps=[], resolve=True)
    return done()


def raise_insight(s: Session, key: str, *, title: str, severity: str, steps: list[str], summary: str | None = None,
                  resolve: bool = False) -> None:
    """Keep one platform finding per AI-integration condition in step (notified like every finding). ``resolve``
    closes it when the condition has cleared."""
    from soc_platform.intelligence.correlation import _key
    from soc_platform.intelligence.models import Insight

    dk = _key("platform", f"llm_{key}")
    cur = s.execute(select(Insight).where(Insight.dedupe_key == dk)).scalars().first()
    if resolve:
        if cur is not None and cur.status in {"new", "acknowledged"}:
            cur.status, cur.decided_by = "resolved", "system:llm"
        return
    score = {"critical": 85.0, "high": 65.0, "medium": 45.0, "low": 25.0}.get(severity, 40.0)
    evidence = [{"ref": f"llm_{key}", "signal": f"llm_{key}", "source": "platform", "summary": (summary or title)[:400]}]
    if cur is None:
        s.add(Insight(rule=f"llm_{key.split(':', 1)[0]}"[:64], dedupe_key=dk, severity=severity, score=score, title=title[:500],
                      entity_ids=[], domains=[], evidence=evidence, next_steps=steps, requirement_refs=["NFR-11"]))
    elif cur.title != title[:500] or cur.status == "resolved":     # a dismissal stands while nothing changes
        cur.title, cur.severity, cur.score, cur.evidence, cur.next_steps = title[:500], severity, score, evidence, steps
        cur.status, cur.last_seen = "new", utcnow()
