"""Access management (NFR-09, NFR-08): role assignments, service-account API keys, revocation,
break-glass access and durable system flags.

Everything here is audited. Rules that hold regardless of configuration:

* nobody can grant, change or revoke *their own* access
* API-key (service) principals never receive approval / policy / access-management permissions
  (``auth.HUMAN_ONLY_PERMS``) and their keys always expire (max 365 days)
* only a SHA-256 of an API key secret is stored; the secret is shown exactly once
* break-glass access needs a sealed secret whose hash is configured, and every use is audited
  and raised as a critical insight
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from soc_platform.config import Settings
from soc_platform.core.audit import AuditLog
from soc_platform.core.auth import DOMAINS, HUMAN_ONLY_PERMS, ROLE_PERMS, Perm, Principal, Role
from soc_platform.core.models import ApiKey, RoleAssignment, SystemFlag, TokenRevocation, utcnow

KEY_PREFIX = "sk_soc_"
MAX_KEY_DAYS = 365
SERVICE_ROLES = {Role.ANALYST, Role.AUDITOR, Role.AUTOMATION_ADMIN}


def _aware(dt: datetime | None) -> datetime | None:
    return dt.replace(tzinfo=timezone.utc) if dt is not None and dt.tzinfo is None else dt


def _domains(values: list[str] | None) -> list[str]:
    vals = sorted({str(v).lower() for v in (values or ["*"])})
    if "*" in vals:
        return ["*"]
    bad = [v for v in vals if v not in DOMAINS]
    if bad:
        raise ValueError(f"unknown domain(s) {bad}; expected {list(DOMAINS)} or '*'")
    return vals


class AccessService:
    def __init__(self, session: Session, settings: Settings) -> None:
        self.s = session
        self.settings = settings
        self.audit = AuditLog(session)

    # ------------------------------------------------------------------ effective principal

    def effective(self, p: Principal) -> Principal:
        """Apply revocation and add platform-managed role assignments to a token principal."""
        if self.is_revoked(p):
            raise PermissionError("token revoked")
        now = utcnow()
        grants = self.s.execute(select(RoleAssignment).where(
            RoleAssignment.principal_id == p.id, RoleAssignment.revoked_at.is_(None),
            or_(RoleAssignment.expires_at.is_(None), RoleAssignment.expires_at > now))).scalars().all()
        if not grants:
            return p
        roles = set(p.roles)
        domains = set(p.domains) if p.roles else set()
        for g in grants:
            try:
                roles.add(Role(g.role))
            except ValueError:
                continue
            domains.update(g.domains or ["*"])
        return replace(p, roles=frozenset(roles), domains=frozenset({"*"}) if "*" in domains or not domains
                       else frozenset(domains))

    def is_revoked(self, p: Principal) -> bool:
        if p.token_id and self.s.execute(select(TokenRevocation.id).where(
                TokenRevocation.token_id == p.token_id)).first() is not None:
            return True
        nb = self.s.execute(select(TokenRevocation.not_before).where(
            TokenRevocation.principal_id == p.id, TokenRevocation.not_before.is_not(None))
            .order_by(TokenRevocation.not_before.desc())).scalars().first()
        if nb is None:
            return False
        issued = datetime.fromtimestamp(p.issued_at, tz=timezone.utc) if p.issued_at else None
        return issued is None or issued < _aware(nb)

    # ------------------------------------------------------------------ role assignments

    def _require(self, by: Principal, perm: Perm = Perm.MANAGE_ACCESS) -> None:
        if not by.can(perm):
            raise PermissionError(by.why_not(perm))

    def grant(self, by: Principal, principal_id: str, role: str, *, domains: list[str] | None = None,
              days: int | None = None, reason: str = "") -> RoleAssignment:
        self._require(by)
        if principal_id.strip().lower() == by.id.strip().lower():
            raise PermissionError("cannot grant access to yourself (separation of duties)")
        r = Role(role)
        if not reason.strip():
            raise ValueError("a justification is required")
        ga = RoleAssignment(principal_id=principal_id.strip(), role=r.value, domains=_domains(domains),
                            granted_by=by.id, reason=reason.strip(),
                            expires_at=utcnow() + timedelta(days=days) if days else None)
        self.s.add(ga)
        self.s.flush()
        self.audit.append(actor_type="human", actor_id=by.id, event_type="access.grant", subject_type="principal",
                          subject_id=principal_id, payload={"role": r.value, "domains": ga.domains, "days": days,
                                                            "reason": reason, "assignment": ga.id})
        return ga

    def revoke_grant(self, by: Principal, assignment_id: str, reason: str = "") -> RoleAssignment:
        self._require(by)
        ga = self.s.get(RoleAssignment, assignment_id)
        if ga is None or ga.revoked_at is not None:
            raise KeyError("assignment not found or already revoked")
        if ga.principal_id.lower() == by.id.lower():
            raise PermissionError("cannot change your own access")
        ga.revoked_at, ga.revoked_by = utcnow(), by.id
        self.audit.append(actor_type="human", actor_id=by.id, event_type="access.revoke", subject_type="principal",
                          subject_id=ga.principal_id, payload={"assignment": ga.id, "role": ga.role, "reason": reason})
        return ga

    def list_grants(self, include_inactive: bool = False) -> list[dict[str, Any]]:
        q = select(RoleAssignment).order_by(RoleAssignment.granted_at.desc())
        now = utcnow()
        out = []
        for g in self.s.execute(q).scalars():
            active = g.revoked_at is None and (g.expires_at is None or _aware(g.expires_at) > now)
            if active or include_inactive:
                out.append({"id": g.id, "principal_id": g.principal_id, "role": g.role, "domains": g.domains,
                            "granted_by": g.granted_by, "reason": g.reason, "granted_at": g.granted_at.isoformat(),
                            "expires_at": g.expires_at.isoformat() if g.expires_at else None, "active": active})
        return out

    # ------------------------------------------------------------------ API keys (service accounts)

    def create_api_key(self, by: Principal, name: str, roles: list[str], *, domains: list[str] | None = None,
                       days: int = 90) -> tuple[ApiKey, str]:
        self._require(by)
        rs = {Role(r) for r in roles}
        if not rs:
            raise ValueError("at least one role is required")
        if not rs <= SERVICE_ROLES:
            raise PermissionError(f"service accounts may only hold {sorted(r.value for r in SERVICE_ROLES)}")
        if not 1 <= days <= MAX_KEY_DAYS:
            raise ValueError(f"key lifetime must be 1..{MAX_KEY_DAYS} days")
        key = ApiKey(name=name.strip()[:128] or "service", secret_sha256="", roles=sorted(r.value for r in rs),
                     domains=_domains(domains), created_by=by.id, expires_at=utcnow() + timedelta(days=days))
        self.s.add(key)
        self.s.flush()
        secret = secrets.token_urlsafe(32)
        key.secret_sha256 = hashlib.sha256(secret.encode()).hexdigest()
        self.audit.append(actor_type="human", actor_id=by.id, event_type="access.api_key_created", subject_type="api_key",
                          subject_id=key.id, payload={"name": key.name, "roles": key.roles, "domains": key.domains,
                                                      "expires_at": key.expires_at.isoformat()})
        return key, f"{KEY_PREFIX}{key.id}_{secret}"

    def revoke_api_key(self, by: Principal, key_id: str) -> ApiKey:
        self._require(by)
        key = self.s.get(ApiKey, key_id)
        if key is None or key.revoked_at is not None:
            raise KeyError("api key not found or already revoked")
        key.revoked_at = utcnow()
        self.audit.append(actor_type="human", actor_id=by.id, event_type="access.api_key_revoked", subject_type="api_key",
                          subject_id=key.id, payload={"name": key.name})
        return key

    def list_api_keys(self) -> list[dict[str, Any]]:
        now = utcnow()
        return [{"id": k.id, "name": k.name, "roles": k.roles, "domains": k.domains, "created_by": k.created_by,
                 "created_at": k.created_at.isoformat(), "expires_at": k.expires_at.isoformat(),
                 "last_used_at": k.last_used_at.isoformat() if k.last_used_at else None,
                 "active": k.revoked_at is None and _aware(k.expires_at) > now}
                for k in self.s.execute(select(ApiKey).order_by(ApiKey.created_at.desc())).scalars()]

    def authenticate_api_key(self, raw: str) -> Principal:
        if not raw.startswith(KEY_PREFIX) or raw.count("_") < 3:
            raise PermissionError("malformed api key")
        key_id, _, secret = raw[len(KEY_PREFIX):].partition("_")
        key = self.s.get(ApiKey, key_id)
        digest = hashlib.sha256(secret.encode()).hexdigest()
        # constant-time compare even for unknown ids so key ids cannot be probed by timing
        ok = hmac.compare_digest(digest, key.secret_sha256 if key else "0" * 64)
        if key is None or not ok:
            raise PermissionError("invalid api key")
        if key.revoked_at is not None or _aware(key.expires_at) <= utcnow():
            raise PermissionError("api key revoked or expired")
        key.last_used_at = utcnow()
        return Principal(id=f"svc:{key.id}", name=f"service:{key.name}",
                         roles=frozenset(Role(r) for r in key.roles if Role(r) in SERVICE_ROLES),
                         domains=frozenset(key.domains or ["*"]), is_service=True, mfa=False, auth_method="api_key")

    # ------------------------------------------------------------------ revocation

    def revoke_token(self, by: Principal, token_id: str, *, expires_at: datetime | None = None) -> None:
        if not token_id:
            raise ValueError("token has no id (jti)")
        if self.s.execute(select(TokenRevocation.id).where(TokenRevocation.token_id == token_id)).first() is None:
            self.s.add(TokenRevocation(token_id=token_id, expires_at=expires_at, revoked_by=by.id))
        self.audit.append(actor_type=by.actor_type, actor_id=by.id, event_type="access.token_revoked",
                          subject_type="token", subject_id=token_id[:64], payload={})

    def revoke_sessions(self, by: Principal, principal_id: str, reason: str = "") -> None:
        """Invalidate every token issued to ``principal_id`` before now (e.g. suspected compromise)."""
        if principal_id.lower() != by.id.lower():
            self._require(by)
        self.s.add(TokenRevocation(principal_id=principal_id, not_before=utcnow(), revoked_by=by.id))
        self.audit.append(actor_type="human", actor_id=by.id, event_type="access.sessions_revoked",
                          subject_type="principal", subject_id=principal_id, payload={"reason": reason})

    # ------------------------------------------------------------------ break-glass

    def break_glass(self, secret: str, *, client: str, path: str) -> Principal:
        expected = self.settings.break_glass_sha256
        if not expected:
            raise PermissionError("break-glass access is not enabled")
        if not hmac.compare_digest(hashlib.sha256(secret.encode()).hexdigest(), expected):
            self.audit.append(actor_type="system", actor_id="auth", event_type="auth.break_glass_failed",
                              subject_type="principal", subject_id="break-glass", payload={"client": client, "path": path})
            raise PermissionError("invalid break-glass credential")
        self.audit.append(actor_type="human", actor_id="break-glass", event_type="auth.break_glass_used",
                          subject_type="principal", subject_id="break-glass", payload={"client": client, "path": path})
        try:
            from soc_platform.intelligence.models import Insight

            key = f"break_glass:{utcnow():%Y%m%d%H}"
            with self.s.begin_nested():
                if self.s.execute(select(Insight.id).where(Insight.dedupe_key == key)).first() is None:
                    self.s.add(Insight(
                        rule="break_glass_used", dedupe_key=key, severity="critical", score=100.0,
                        title="Break-glass account used", domains=[], entity_ids=[],
                        evidence=[{"client": client, "path": path}],
                        narrative=f"Emergency access was used from {client} ({path}).",
                        next_steps=["Confirm the use was authorised (incident ticket / on-call lead)",
                                    "Rotate the sealed break-glass secret", "Review the access log for the session"],
                        requirement_refs=["NFR-09"]))
        except Exception:  # noqa: BLE001 - alerting must never block emergency access
            pass
        return Principal(id="break-glass", name="Break-glass administrator",
                         roles=frozenset({Role.LEAD, Role.ADMIN}), mfa=True, break_glass=True, auth_method="break_glass")

    # ------------------------------------------------------------------ system flags

    def get_flag(self, name: str, default: Any = None) -> Any:
        f = self.s.get(SystemFlag, name)
        return (f.value or {}).get("value", default) if f else default

    def set_flag(self, by: Principal, name: str, value: Any, *, perm: Perm) -> None:
        self._require(by, perm)
        f = self.s.get(SystemFlag, name)
        if f is None:
            f = SystemFlag(name=name, value={}, updated_by=by.id)
            self.s.add(f)
        f.value, f.updated_by, f.updated_at = {"value": value}, by.id, utcnow()
        self.s.flush()
        self.audit.append(actor_type="human", actor_id=by.id, event_type=f"system.flag.{name}", subject_type="system",
                          subject_id=name, payload={"value": value})


def kill_switch_on(session: Session, settings: Settings) -> bool:
    """Env override OR the durable flag (shared by every API replica and the scheduler)."""
    if settings.kill_switch:
        return True
    f = session.get(SystemFlag, "kill_switch")
    return bool(f and (f.value or {}).get("value"))


def permissions_matrix() -> dict[str, list[str]]:
    return {r.value: sorted(p.value for p in perms) for r, perms in ROLE_PERMS.items()} | {
        "_service_accounts_never": sorted(p.value for p in HUMAN_ONLY_PERMS)}
