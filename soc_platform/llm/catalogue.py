"""The models a provider offers, and the newest version of each chosen model the platform uses.

An administrator chooses a model per feature (and per size of work) on the AI usage screen. Unless that feature is
pinned, the choice names a *line* (``GPT 6.1 Sol`` -> the ``gpt sol`` line, see ``model_lines``), and the platform
uses the newest version of that line it has *adopted*:

1. ``refresh`` (the ``llm_catalogue`` job, and *Refresh* on the screen) reads the provider's model list - or uses the
   names an administrator added when the provider publishes none - and records each model with its line and version.
2. For every line in use, a newer version **in the same generation** (6.1 -> 6.2) is checked first
   (``LLMGateway.qualify``: grounded JSON with valid citations and no invented figure). It is adopted only if it
   passes; a failure keeps the current version and raises a finding that says why.
3. A **new generation** (6.x -> 7) waits for an administrator's approval (the same check runs then).
4. Every adoption is a row in ``llm_line_adoptions`` (who or what, from -> to, the check's result), audited and
   raised as a finding; *Roll back* returns the line to the version before and blocks the one rolled back.
5. A version listed as being retired, with nothing newer to move to, raises a finding before calls start failing.

``SOC_LLM_MODEL_VERSION`` pins still win: a pinned line is never upgraded. ``auto_upgrade: false`` in the AI usage
policy switches step 2 off for every line (new versions are then offered like a new generation).

A version change never changes a figure, a verdict or an action: the model only writes narrative from evidence the
platform computed (and its statements are checked against that evidence on every call).
"""

from __future__ import annotations

import os
from datetime import timedelta
from typing import Any

from sqlalchemy import Boolean, Integer, String, UniqueConstraint, select
from sqlalchemy.orm import Mapped, Session, mapped_column

from soc_platform.core.db import Base, BoundedText, UTCDateTime
from soc_platform.core.models import utcnow
from soc_platform.llm.model_lines import newest, parse

RECHECK_FAILED_AFTER = timedelta(hours=24)     # a version that failed the check is tried again a day later


class LLMCatalogueModel(Base):
    __tablename__ = "llm_catalogue_models"
    __table_args__ = (UniqueConstraint("provider", "name", name="uq_llm_catalogue_provider_name"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    provider: Mapped[str] = mapped_column(String(32), index=True)
    name: Mapped[str] = mapped_column(String(128))
    line: Mapped[str] = mapped_column(String(128), index=True)
    version: Mapped[str] = mapped_column(String(32), default="")
    generation: Mapped[int | None] = mapped_column(Integer, nullable=True)
    preview: Mapped[bool] = mapped_column(Boolean, default=False)
    alias: Mapped[bool] = mapped_column(Boolean, default=False)
    deprecated: Mapped[bool] = mapped_column(Boolean, default=False)
    available: Mapped[bool] = mapped_column(Boolean, default=True)
    source: Mapped[str] = mapped_column(String(16), default="provider")     # provider | admin
    blocked: Mapped[bool] = mapped_column(Boolean, default=False)            # rolled back: never adopted again
    added_by: Mapped[str | None] = mapped_column(String(256), nullable=True)
    first_seen: Mapped[Any] = mapped_column(UTCDateTime(), default=utcnow)
    last_seen: Mapped[Any] = mapped_column(UTCDateTime(), default=utcnow)
    check_status: Mapped[str | None] = mapped_column(String(16), nullable=True)   # passed | failed
    check_detail: Mapped[str | None] = mapped_column(BoundedText(500), nullable=True)
    checked_at: Mapped[Any | None] = mapped_column(UTCDateTime(), nullable=True)


class LLMLineAdoption(Base):
    """Append-only: the newest row of a (provider, line) is the version in use."""

    __tablename__ = "llm_line_adoptions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    provider: Mapped[str] = mapped_column(String(32), index=True)
    line: Mapped[str] = mapped_column(String(128), index=True)
    model: Mapped[str] = mapped_column(String(128))
    previous: Mapped[str | None] = mapped_column(String(128), nullable=True)
    reason: Mapped[str] = mapped_column(String(16))          # automatic | approved | rollback | chosen
    by: Mapped[str] = mapped_column(String(256))
    detail: Mapped[str] = mapped_column(BoundedText(500), default="")
    created_at: Mapped[Any] = mapped_column(UTCDateTime(), default=utcnow)


def _aware(dt: Any) -> Any:
    from datetime import UTC

    return dt.replace(tzinfo=UTC) if dt is not None and dt.tzinfo is None else dt


def provider_name(s: Session, settings: Any) -> str:
    from soc_platform.llm.integration import IntegrationStore

    return IntegrationStore(s, settings).status()["provider"]


def rows(s: Session, provider: str) -> list[LLMCatalogueModel]:
    return list(s.execute(select(LLMCatalogueModel).where(LLMCatalogueModel.provider == provider)
                          .order_by(LLMCatalogueModel.line, LLMCatalogueModel.name)).scalars())


def offered(s: Session, provider: str) -> list[str]:
    """Model names a feature may be set to: available, not an alias, not blocked - in a stable order."""
    return [r.name for r in rows(s, provider) if r.available and not r.alias and not r.blocked]


def adopted(s: Session, provider: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for r in s.execute(select(LLMLineAdoption).where(LLMLineAdoption.provider == provider)
                       .order_by(LLMLineAdoption.id)).scalars():
        out[r.line] = r.model
    return out


def _upsert(s: Session, provider: str, name: str, *, source: str, deprecated: bool = False,
            by: str | None = None) -> LLMCatalogueModel:
    m = parse(name)
    row = s.execute(select(LLMCatalogueModel).where(LLMCatalogueModel.provider == provider,
                                                    LLMCatalogueModel.name == m.name)).scalars().first()
    if row is None:
        row = LLMCatalogueModel(provider=provider, name=m.name, line=m.line[:128], version=m.version_text[:32],
                                generation=m.generation, preview=m.preview, alias=m.alias, source=source,
                                added_by=by, deprecated=deprecated)
        s.add(row)
    else:
        row.available, row.deprecated, row.last_seen = True, deprecated, utcnow()
    return row


def add_model(s: Session, settings: Any, name: str, by: Any) -> LLMCatalogueModel:
    """An administrator adds a model name the provider offers (for providers that publish no list). Audited."""
    from soc_platform.core.audit import AuditLog
    from soc_platform.core.auth import Perm

    if by.is_service or by.is_agent or not by.can(Perm.MANAGE_ACCESS):
        raise PermissionError("an administrator (manage_access) adds models")
    name = (name or "").strip()
    if not name or len(name) > 128 or any(ord(c) < 32 for c in name):
        raise ValueError("a model name exactly as the provider writes it (up to 128 characters)")
    provider = provider_name(s, settings)
    if provider == "none":
        raise ValueError("choose a model provider first")
    row = _upsert(s, provider, name, source="admin", by=by.id)
    s.flush()
    AuditLog(s).append(actor_type=by.actor_type, actor_id=by.id, event_type="llm.model_added", subject_type="llm_model",
                       subject_id=row.name, payload={"provider": provider, "line": row.line, "version": row.version})
    return row


def _pinned_lines() -> set[str]:
    return {parse(p.strip()).line for p in (os.environ.get("SOC_LLM_MODEL_VERSION") or "").split(",") if p.strip()}


def lines_in_use(policy: dict[str, Any]) -> dict[str, str]:
    """line -> the model chosen for it (a feature's choice, else a size's default), for every choice that follows
    its line. A pinned feature (``follow: false``) is left where it is."""
    out: dict[str, str] = {}
    for rule in (policy.get("workflows") or {}).values():
        if isinstance(rule, dict) and rule.get("model") and rule.get("follow", True):
            out.setdefault(parse(rule["model"]).line, rule["model"])
    for name in (policy.get("default_models") or {}).values():    # includes an administrator's chosen defaults
        if name:
            out.setdefault(parse(name).line, name)
    return dict(sorted(out.items()))


def _adopt(s: Session, provider: str, line: str, model: str, previous: str | None, reason: str, by: str,
           detail: str = "", actor_type: str = "system") -> LLMLineAdoption:
    from soc_platform.core.audit import AuditLog

    row = LLMLineAdoption(provider=provider, line=line, model=model, previous=previous, reason=reason, by=by,
                          detail=detail[:500])
    s.add(row)
    s.flush()
    AuditLog(s).append(actor_type=actor_type, actor_id=by, event_type="llm.model_adopted", subject_type="llm_line",
                       subject_id=line[:64], payload={"provider": provider, "from": previous, "to": model,
                                                      "reason": reason, "check": detail[:300]})
    return row


def _record_check(row: LLMCatalogueModel | None, result: dict[str, Any]) -> None:
    if row is not None and not result.get("refused"):
        row.check_status = "passed" if result.get("ok") else "failed"
        row.check_detail, row.checked_at = str(result.get("detail") or "")[:500], utcnow()


def _model_spec(name: str) -> dict[str, str]:
    from soc_platform.llm.usage_policy import _size

    return {"name": name, "deployment": name, "size": _size(name)}


def refresh(s: Session, settings: Any, *, gateway: Any = None) -> dict[str, Any]:
    """Read the provider's model list, then move each followed line to its newest checked version. Idempotent: a
    second run with nothing new changes nothing."""
    from soc_platform.llm.gateway import LLMGateway
    from soc_platform.llm.integration import IntegrationStore, configured, is_auth_error, raise_insight
    from soc_platform.llm.usage_policy import UsagePolicyStore

    store = IntegrationStore(s, settings)
    out: dict[str, Any] = {"listed": None, "adopted": [], "failed_checks": [], "awaiting_approval": [],
                           "retiring": []}
    _credential_expiry(s, store)
    if not configured(s, settings):
        out["skipped"] = "no model provider is configured"
        return out
    provider = store.status()["provider"]
    gw = gateway or LLMGateway(s, settings)
    lister = getattr(gw.provider, "list_models", None)
    if lister is not None:
        try:
            listed = lister()
        except Exception as exc:  # noqa: BLE001 - reported on the screen and as a finding; the old list stays
            out["list_error"] = f"{type(exc).__name__}: {str(exc)[:200]}"
            if is_auth_error(exc):
                raise_insight(s, "credentials", severity="high",
                              title="AI provider refused the platform's credentials: AI text falls back to the "
                                    "platform's own wording",
                              steps=["Enter a new token or key in the AI integration card (AI usage screen)",
                                     "Then press Test connection"])
            listed = None
        if listed is not None:
            out["listed"] = len(listed)
            if listed:
                names = set()
                for it in listed:
                    names.add(_upsert(s, provider, it["name"], source="provider",
                                      deprecated=bool(it.get("deprecated"))).name)
                for r in rows(s, provider):           # gone from the provider's list: no longer offered
                    if r.source == "provider" and r.name not in names:
                        r.available = False
                s.flush()
    policy = UsagePolicyStore(s, settings).active()
    auto = policy.get("auto_upgrade", True)
    current = adopted(s, provider)
    cat = {r.name: r for r in rows(s, provider)}
    candidates = [r.name for r in cat.values() if r.available and not r.blocked]
    pinned = _pinned_lines()
    for line, chosen in lines_in_use(policy).items():
        now_name = current.get(line, chosen)
        same, later = newest(candidates, now_name)
        if line in pinned:
            continue
        if same and not auto:                         # automatic upgrades off: offered like a new generation
            later, same = same, None
        if same:
            row = cat.get(same)
            fresh_failure = (row is not None and row.check_status == "failed" and row.checked_at is not None
                             and utcnow() - _aware(row.checked_at) < RECHECK_FAILED_AFTER)
            if not fresh_failure:
                result = gw.qualify(_model_spec(same))
                _record_check(row, result)
                if result.get("ok"):
                    _adopt(s, provider, line, same, now_name, "automatic", "system:llm_catalogue",
                           str(result.get("detail") or ""))
                    out["adopted"].append({"line": line, "from": now_name, "to": same})
                    raise_insight(s, f"adopted:{line}:{same}", severity="medium",
                                  title=f"AI model upgraded: {now_name} -> {same} (passed the platform's check)",
                                  steps=["Nothing to do. To go back, use Roll back for this line on the AI usage screen"])
                    raise_insight(s, f"check_failed:{line}", severity="medium", title="", steps=[], resolve=True)
                    now_name = same
                    later = newest(candidates, now_name)[1]
                elif not result.get("refused"):
                    out["failed_checks"].append({"line": line, "model": same, "detail": result.get("detail")})
                    raise_insight(s, f"check_failed:{line}", severity="medium",
                                  title=f"AI model {same} failed the platform's check: staying on {now_name}",
                                  summary=str(result.get("detail") or ""),
                                  steps=["Nothing breaks: the current version stays in use",
                                         "The platform checks it again in a day"])
        if later:
            out["awaiting_approval"].append({"line": line, "current": now_name, "offered": later})
            raise_insight(s, f"generation:{line}:{later}", severity="medium",
                          title=f"New AI model generation available: {later} (now using {now_name}) - awaiting an "
                                f"administrator's approval",
                          steps=[("Open the AI usage screen and choose Approve for this line: the platform checks "
                                  "the model first, then switches"),
                                 "Cost and behaviour can differ between generations: compare the prices first"])
        row_now = cat.get(now_name)
        if row_now is not None and (row_now.deprecated or not row_now.available):
            out["retiring"].append(now_name)
            raise_insight(s, f"retiring:{line}", severity="high" if not later else "medium",
                          title=f"AI model in use is being retired: {now_name}"
                                + (f" - approve {later} to move on" if later else " and no newer version is offered"),
                          steps=["Choose another model for the features that use it (AI usage screen)",
                                 "Until then calls may fail and fall back to the platform's own text"])
        else:
            raise_insight(s, f"retiring:{line}", severity="high", title="", steps=[], resolve=True)
    return out


def _credential_expiry(s: Session, store: Any) -> None:
    from soc_platform.llm.integration import raise_insight

    st = store.status()
    expired = [c["label"] for c in st["credentials"] if c["expired"]]
    soon = [c["label"] for c in st["credentials"] if c["expires_soon"]]
    if expired or soon:
        raise_insight(s, "credential_expiry", severity="high",
                      title=(f"AI provider {', '.join(expired).lower()} expired: AI text falls back to the platform's "
                             "own wording" if expired else
                             f"AI provider {', '.join(soon).lower()} expires within days"),
                      steps=["Enter the new token, with its new expiry date, in the AI integration card (AI usage)",
                             "Then press Test connection"])
    else:
        raise_insight(s, "credential_expiry", severity="high", title="", steps=[], resolve=True)


def approve(s: Session, settings: Any, line: str, model: str, by: Any, *, gateway: Any = None) -> LLMLineAdoption:
    """An administrator moves a line to a newer generation (or, with automatic upgrades off, a newer version). The
    model is checked first; a failed check refuses the change with its reason."""
    from soc_platform.core.auth import Perm
    from soc_platform.llm.gateway import LLMGateway
    from soc_platform.llm.integration import raise_insight
    from soc_platform.llm.usage_policy import UsagePolicyStore

    if by.is_service or by.is_agent or not by.can(Perm.MANAGE_ACCESS):
        raise PermissionError("an administrator (manage_access) approves a model change")
    provider = provider_name(s, settings)
    row = s.execute(select(LLMCatalogueModel).where(LLMCatalogueModel.provider == provider,
                                                    LLMCatalogueModel.name == model)).scalars().first()
    if row is None or not row.available or row.blocked:
        raise ValueError(f"{model} is not offered by the provider (or was rolled back)")
    in_use = lines_in_use(UsagePolicyStore(s, settings).active())
    if line not in in_use or row.line != line:
        raise ValueError(f"{model} is not a version of a model line in use ({line})")
    current = adopted(s, provider).get(line, in_use[line])
    if parse(model).rank() <= parse(current).rank():
        raise ValueError(f"{model} is not newer than {current}")
    result = (gateway or LLMGateway(s, settings, actor=by)).qualify(_model_spec(model))
    _record_check(row, result)
    if not result.get("ok"):
        raise ValueError(f"{model} failed the platform's check: {result.get('detail')}")
    adoption = _adopt(s, provider, line, model, current, "approved", by.id, str(result.get("detail") or ""),
                      actor_type=by.actor_type)
    raise_insight(s, f"generation:{line}:{model}", severity="medium", title="", steps=[], resolve=True)
    return adoption


def rollback(s: Session, settings: Any, line: str, by: Any) -> LLMLineAdoption:
    """Return a line to the version in use before the last change, and never adopt the rolled-back one again."""
    from soc_platform.core.auth import Perm

    if by.is_service or by.is_agent or not by.can(Perm.MANAGE_ACCESS):
        raise PermissionError("an administrator (manage_access) rolls a model back")
    provider = provider_name(s, settings)
    last = s.execute(select(LLMLineAdoption).where(LLMLineAdoption.provider == provider, LLMLineAdoption.line == line)
                     .order_by(LLMLineAdoption.id.desc()).limit(1)).scalars().first()
    if last is None or not last.previous:
        raise ValueError(f"nothing to roll back for {line}")
    bad = s.execute(select(LLMCatalogueModel).where(LLMCatalogueModel.provider == provider,
                                                    LLMCatalogueModel.name == last.model)).scalars().first()
    if bad is not None:
        bad.blocked = True
    return _adopt(s, provider, line, last.previous, last.model, "rollback", by.id,
                  f"rolled back from {last.model}", actor_type=by.actor_type)


def unblock(s: Session, settings: Any, model: str, by: Any) -> None:
    """Let a rolled-back version be adopted again (after the provider fixed it)."""
    from soc_platform.core.audit import AuditLog
    from soc_platform.core.auth import Perm

    if by.is_service or by.is_agent or not by.can(Perm.MANAGE_ACCESS):
        raise PermissionError("an administrator (manage_access) unblocks a model")
    provider = provider_name(s, settings)
    row = s.execute(select(LLMCatalogueModel).where(LLMCatalogueModel.provider == provider,
                                                    LLMCatalogueModel.name == model)).scalars().first()
    if row is None or not row.blocked:
        raise ValueError(f"{model} is not blocked")
    row.blocked, row.check_status = False, None
    AuditLog(s).append(actor_type=by.actor_type, actor_id=by.id, event_type="llm.model_unblocked",
                       subject_type="llm_model", subject_id=model[:64], payload={"provider": provider})


def view(s: Session, settings: Any) -> dict[str, Any]:
    """What the AI usage screen shows: the catalogue, each line in use (chosen, in use, newer offers) and history."""
    from soc_platform.llm.usage_policy import UsagePolicyStore

    provider = provider_name(s, settings)
    policy = UsagePolicyStore(s, settings).active()
    current = adopted(s, provider)
    rs = rows(s, provider)
    candidates = [r.name for r in rs if r.available and not r.blocked]
    pinned = _pinned_lines()
    lines = []
    for line, chosen in lines_in_use(policy).items():
        in_use = current.get(line, chosen)
        same, later = newest(candidates, in_use)
        last = s.execute(select(LLMLineAdoption).where(LLMLineAdoption.provider == provider,
                                                       LLMLineAdoption.line == line)
                         .order_by(LLMLineAdoption.id.desc()).limit(1)).scalars().first()
        lines.append({"line": line, "chosen": chosen, "in_use": in_use, "pinned": line in pinned,
                      "newer_same_generation": same, "next_generation": later,
                      "can_roll_back": bool(last and last.previous), "last_change": None if last is None else {
                          "from": last.previous, "to": last.model, "reason": last.reason, "by": last.by,
                          "at": _aware(last.created_at).isoformat()}})
    history = [{"line": r.line, "from": r.previous, "to": r.model, "reason": r.reason, "by": r.by, "detail": r.detail,
                "at": _aware(r.created_at).isoformat()}
               for r in s.execute(select(LLMLineAdoption).where(LLMLineAdoption.provider == provider)
                                  .order_by(LLMLineAdoption.id.desc()).limit(50)).scalars()]
    return {"provider": provider, "auto_upgrade": policy.get("auto_upgrade", True), "lines": lines,
            "models": [{"name": r.name, "line": r.line, "version": r.version, "generation": r.generation,
                        "preview": r.preview, "alias": r.alias, "deprecated": r.deprecated, "available": r.available,
                        "blocked": r.blocked, "source": r.source, "check": r.check_status,
                        "check_detail": r.check_detail, "in_use": r.name in set(current.values()) | set(
                            lines_in_use(policy).values()),
                        "first_seen": _aware(r.first_seen).isoformat()} for r in rs],
            "history": history}
