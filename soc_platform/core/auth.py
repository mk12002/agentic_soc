"""Identity, roles and permissions (NFR-09, VM-T12).

Production: Entra ID SSO. The UI signs in with MSAL and calls the API with an
access token; we validate RS256 against the tenant JWKS and map Entra app roles
to platform roles. MFA/conditional access are enforced by Entra itself.

Dev/test: HS256 tokens signed with ``SOC_DEV_JWT_SECRET`` (never in prod).

Separation of duties: the roles that configure automation (automation_admin)
are distinct from those that approve actions (lead), and a requester can never
approve their own action or policy change.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from functools import lru_cache

import jwt

from soc_platform.config import Settings


class Role(str, Enum):
    ANALYST = "analyst"
    LEAD = "lead"
    ADMIN = "admin"
    AUTOMATION_ADMIN = "automation_admin"
    AUDITOR = "auditor"


class Perm(str, Enum):
    READ = "read"
    INVESTIGATE = "investigate"          # run enrichment, add dispositions
    REQUEST_ACTION = "request_action"
    APPROVE_ACTION = "approve_action"
    APPROVE_HIGH_IMPACT = "approve_high_impact"
    ROLLBACK_ACTION = "rollback_action"
    RESOLVE_ENTITIES = "resolve_entities"
    PROPOSE_POLICY = "propose_policy"
    APPROVE_POLICY = "approve_policy"
    KILL_SWITCH = "kill_switch"
    READ_AUDIT = "read_audit"
    MANAGE_CONNECTORS = "manage_connectors"


ROLE_PERMS: dict[Role, set[Perm]] = {
    Role.ANALYST: {Perm.READ, Perm.INVESTIGATE, Perm.REQUEST_ACTION, Perm.APPROVE_ACTION,
                   Perm.RESOLVE_ENTITIES, Perm.READ_AUDIT},
    Role.LEAD: {Perm.READ, Perm.INVESTIGATE, Perm.REQUEST_ACTION, Perm.APPROVE_ACTION,
                Perm.APPROVE_HIGH_IMPACT, Perm.ROLLBACK_ACTION, Perm.RESOLVE_ENTITIES,
                Perm.APPROVE_POLICY, Perm.KILL_SWITCH, Perm.READ_AUDIT},
    # Configures automation but cannot approve actions or its own policy (separation of duties).
    Role.AUTOMATION_ADMIN: {Perm.READ, Perm.PROPOSE_POLICY, Perm.MANAGE_CONNECTORS, Perm.READ_AUDIT,
                            Perm.KILL_SWITCH},
    Role.ADMIN: {Perm.READ, Perm.MANAGE_CONNECTORS, Perm.READ_AUDIT, Perm.KILL_SWITCH},
    Role.AUDITOR: {Perm.READ, Perm.READ_AUDIT},
}


@dataclass(frozen=True)
class Principal:
    id: str
    name: str
    roles: frozenset[Role] = field(default_factory=frozenset)
    is_agent: bool = False

    @property
    def actor_type(self) -> str:
        return "agent" if self.is_agent else "human"

    def can(self, perm: Perm) -> bool:
        return any(perm in ROLE_PERMS.get(r, set()) for r in self.roles)


def agent_principal(name: str) -> Principal:
    """Principal used when an agent (not a human) acts. Agents can only request/recommend."""
    return Principal(id=f"agent:{name}", name=name, roles=frozenset(), is_agent=True)


class AuthError(Exception):
    pass


def _roles_from_claims(claims: dict) -> frozenset[Role]:
    raw = claims.get("roles") or []
    if isinstance(raw, str):
        raw = [raw]
    out = set()
    for r in raw:
        name = str(r).split(".")[-1].lower()  # Entra app roles like "SOC.Lead"
        try:
            out.add(Role(name))
        except ValueError:
            continue
    return frozenset(out)


@lru_cache(maxsize=4)
def _jwks_client(tenant_id: str) -> jwt.PyJWKClient:
    return jwt.PyJWKClient(f"https://login.microsoftonline.com/{tenant_id}/discovery/v2.0/keys")


def principal_from_token(token: str, settings: Settings) -> Principal:
    if settings.auth_mode == "entra":
        if not settings.entra_tenant_id or not settings.entra_audience:
            raise AuthError("Entra auth mode requires SOC_ENTRA_TENANT_ID and SOC_ENTRA_AUDIENCE")
        try:
            key = _jwks_client(settings.entra_tenant_id).get_signing_key_from_jwt(token)
            claims = jwt.decode(
                token,
                key.key,
                algorithms=["RS256"],
                audience=settings.entra_audience,
                issuer=f"https://login.microsoftonline.com/{settings.entra_tenant_id}/v2.0",
            )
        except jwt.PyJWTError as exc:
            raise AuthError(f"invalid token: {exc}") from exc
    elif settings.auth_mode == "dev":
        if settings.environment == "prod":
            raise AuthError("dev auth mode is not permitted in prod")
        if not settings.dev_jwt_secret:
            raise AuthError("SOC_DEV_JWT_SECRET not configured")
        try:
            claims = jwt.decode(token, settings.dev_jwt_secret, algorithms=["HS256"])
        except jwt.PyJWTError as exc:
            raise AuthError(f"invalid token: {exc}") from exc
    else:
        raise AuthError(f"unknown auth mode {settings.auth_mode!r}")

    subject = claims.get("oid") or claims.get("sub")
    if not subject:
        raise AuthError("token has no subject")
    name = claims.get("preferred_username") or claims.get("upn") or claims.get("name") or subject
    return Principal(id=str(subject), name=str(name), roles=_roles_from_claims(claims))


def issue_dev_token(secret: str, user: str, roles: list[str], ttl_seconds: int = 8 * 3600) -> str:
    """Mint a dev token (local development and tests only)."""
    import time

    now = int(time.time())
    return jwt.encode(
        {"sub": user, "preferred_username": user, "roles": roles, "iat": now, "exp": now + ttl_seconds},
        secret,
        algorithm="HS256",
    )
