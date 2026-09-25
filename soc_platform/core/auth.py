"""Identity, roles and permissions (NFR-09, VM-T12).

Production: Entra ID SSO. The UI signs in with MSAL and calls the API with an
access token; we validate RS256 against the tenant JWKS and map Entra app roles
to platform roles. MFA/conditional access are enforced by Entra itself.

Dev/test: HS256 tokens signed with ``SOC_DEV_JWT_SECRET`` (never in prod).

Separation of duties: the roles that configure automation (automation_admin)
are distinct from those that approve actions (lead), and a requester can never
approve their own action or policy change.

Additional controls (see ``core/access.py``):
* domain scoping   - a principal may be limited to phishing / incident / vulnerability data
* step-up MFA      - approving, changing policy, the kill switch and access management need a token
                     whose ``amr`` contains ``mfa`` (or the configured Conditional Access auth context)
* service accounts - API-key principals can never approve, change policy or manage access
* revocation       - per-token (jti) and per-principal (not-before) revocation
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
    MANAGE_ACCESS = "manage_access"      # role assignments, API keys, session revocation, retention
    EXPORT_EVIDENCE = "export_evidence"  # compliance evidence packs / full audit export (U17)


DOMAINS = ("phishing", "incident", "vulnerability")
# Need a fresh strong authentication (MFA) - decisions with blast radius.
STEP_UP_PERMS = {Perm.APPROVE_ACTION, Perm.APPROVE_HIGH_IMPACT, Perm.APPROVE_POLICY, Perm.KILL_SWITCH,
                 Perm.MANAGE_ACCESS, Perm.ROLLBACK_ACTION}
# Never granted to non-human (API-key) principals, whatever roles they hold: humans decide.
HUMAN_ONLY_PERMS = {Perm.APPROVE_ACTION, Perm.APPROVE_HIGH_IMPACT, Perm.APPROVE_POLICY, Perm.MANAGE_ACCESS,
                    Perm.PROPOSE_POLICY, Perm.ROLLBACK_ACTION}


ROLE_PERMS: dict[Role, set[Perm]] = {
    Role.ANALYST: {Perm.READ, Perm.INVESTIGATE, Perm.REQUEST_ACTION, Perm.APPROVE_ACTION,
                   Perm.RESOLVE_ENTITIES, Perm.READ_AUDIT},
    Role.LEAD: {Perm.READ, Perm.INVESTIGATE, Perm.REQUEST_ACTION, Perm.APPROVE_ACTION,
                Perm.APPROVE_HIGH_IMPACT, Perm.ROLLBACK_ACTION, Perm.RESOLVE_ENTITIES,
                Perm.APPROVE_POLICY, Perm.KILL_SWITCH, Perm.READ_AUDIT, Perm.EXPORT_EVIDENCE},
    # Configures automation but cannot approve actions or its own policy (separation of duties).
    Role.AUTOMATION_ADMIN: {Perm.READ, Perm.PROPOSE_POLICY, Perm.MANAGE_CONNECTORS, Perm.READ_AUDIT,
                            Perm.KILL_SWITCH},
    Role.ADMIN: {Perm.READ, Perm.MANAGE_CONNECTORS, Perm.READ_AUDIT, Perm.KILL_SWITCH, Perm.MANAGE_ACCESS,
                 Perm.EXPORT_EVIDENCE},
    Role.AUDITOR: {Perm.READ, Perm.READ_AUDIT, Perm.EXPORT_EVIDENCE},
}


@dataclass(frozen=True)
class Principal:
    id: str
    name: str
    roles: frozenset[Role] = field(default_factory=frozenset)
    is_agent: bool = False
    domains: frozenset[str] = frozenset({"*"})   # data scope; "*" = all domains
    is_service: bool = False                     # API-key service account
    mfa: bool = True                             # strong authentication present on this token
    token_id: str | None = None                  # jti / uti, for revocation
    issued_at: int | None = None
    break_glass: bool = False
    auth_method: str = "token"

    @property
    def actor_type(self) -> str:
        return "agent" if self.is_agent else ("service" if self.is_service else "human")

    def can(self, perm: Perm) -> bool:
        if self.is_service and perm in HUMAN_ONLY_PERMS:
            return False
        if perm in STEP_UP_PERMS and not self.mfa:
            return False
        return any(perm in ROLE_PERMS.get(r, set()) for r in self.roles)

    def why_not(self, perm: Perm) -> str:
        if self.is_service and perm in HUMAN_ONLY_PERMS:
            return f"{perm.value} is reserved for human principals"
        if perm in STEP_UP_PERMS and not self.mfa and any(perm in ROLE_PERMS.get(r, set()) for r in self.roles):
            return f"{perm.value} requires multi-factor authentication (step-up)"
        return f"{perm.value} permission required"

    def in_domain(self, domain: str | None) -> bool:
        """``None`` = no data scope needed; ``"*"`` = cross-domain data (only principals scoped to all domains)."""
        if domain is None or "*" in self.domains:
            return True
        return domain != "*" and domain in self.domains


def agent_principal(name: str) -> Principal:
    """Principal used when an agent (not a human) acts. Agents can only request/recommend."""
    return Principal(id=f"agent:{name}", name=name, roles=frozenset(), is_agent=True)


class AuthError(Exception):
    pass


def _roles_from_claims(claims: dict) -> tuple[frozenset[Role], frozenset[str]]:
    """Entra app roles ``SOC.Lead`` (all domains) or ``SOC.Analyst.Phishing`` (scoped to one domain).

    Unknown role names grant nothing. The domain scope is the union over roles; any unscoped role
    gives all domains."""
    raw = claims.get("roles") or []
    if isinstance(raw, str):
        raw = [raw]
    roles, domains, unscoped = set(), set(), False
    for r in raw:
        parts = [x.lower() for x in str(r).split(".") if x]
        role = next((Role(x) for x in parts if x in {m.value for m in Role}), None)
        if role is None:
            continue
        roles.add(role)
        dom = [x for x in parts if x in DOMAINS]
        if dom:
            domains.update(dom)
        else:
            unscoped = True
    for d in claims.get("soc_domains") or []:  # dev tokens / explicit scope claim
        if str(d).lower() in DOMAINS:
            domains.add(str(d).lower())
    if claims.get("soc_domains"):
        unscoped = False
    return frozenset(roles), (frozenset({"*"}) if unscoped or not domains else frozenset(domains))


def _has_mfa(claims: dict, settings: Settings) -> bool:
    if not settings.require_mfa:
        return True
    amr = claims.get("amr") or []
    if isinstance(amr, str):
        amr = [amr]
    if "mfa" in {str(a).lower() for a in amr}:
        return True
    ctx = settings.mfa_auth_context
    acrs = claims.get("acrs") or []
    return bool(ctx and ctx in (acrs if isinstance(acrs, list) else [acrs]))


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
    roles, domains = _roles_from_claims(claims)
    return Principal(id=str(subject), name=str(name), roles=roles, domains=domains, mfa=_has_mfa(claims, settings),
                     token_id=str(claims.get("jti") or claims.get("uti") or "") or None,
                     issued_at=int(claims["iat"]) if str(claims.get("iat", "")).isdigit() else None)


def issue_dev_token(secret: str, user: str, roles: list[str], ttl_seconds: int = 8 * 3600, *,
                    mfa: bool = True, domains: list[str] | None = None) -> str:
    """Mint a dev token (local development and tests only)."""
    import time
    import uuid

    now = int(time.time())
    claims = {"sub": user, "preferred_username": user, "roles": roles, "iat": now, "exp": now + ttl_seconds,
              "jti": uuid.uuid4().hex, "amr": ["pwd", "mfa"] if mfa else ["pwd"]}
    if domains:
        claims["soc_domains"] = domains
    return jwt.encode(claims, secret, algorithm="HS256")
