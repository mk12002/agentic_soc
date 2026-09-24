"""
Organizational risk context scoring.

The same phishing email is not equally dangerous to every recipient: a finance or
executive mailbox is a far higher-value target (BEC, wire fraud) than a general
user. This service maps recipients to organizational roles and derives a risk
multiplier, so the fused score can reflect *who* was targeted.

It is **off by default** (``settings.org_context_enabled``) and degrades to a
no-op when disabled or when no recipients are supplied, so it never changes
behaviour unless explicitly turned on. Role mappings come from an optional local
JSON config (``config/org_roles.json``); otherwise sensible keyword defaults apply.
Everything is derived from the recipient addresses actually present — no inference.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from soc_platform.domains.phishing.engine.services.logging_service import get_service_logger

logger = get_service_logger("org_context")

# Role -> risk multiplier. >1 raises risk for high-value targets.
DEFAULT_ROLE_MULTIPLIERS: dict[str, float] = {
    "executive": 1.5,
    "finance": 1.4,
    "it_admin": 1.4,
    "hr": 1.3,
    "legal": 1.25,
    "general": 1.0,
}

# Substrings in the address local-part that imply a role (checked in priority order).
_ROLE_KEYWORDS: dict[str, list[str]] = {
    "executive": ["ceo", "cfo", "coo", "cto", "president", "exec", "chair", "founder"],
    "finance": ["finance", "accounts", "accounting", "payable", "payroll", "billing", "treasury", "invoice"],
    "it_admin": ["sysadmin", "admin", "root", "helpdesk", "itsupport", "security"],
    "hr": ["hr", "recruit", "talent", "people-ops", "peopleops"],
    "legal": ["legal", "counsel", "compliance"],
}

_MULTIPLIER_CAP = 1.6


def _local_part(address: str) -> str:
    addr = str(address or "").strip().lower()
    return addr.split("@", 1)[0] if "@" in addr else addr


def load_roles_config(path: str | Path = "config/org_roles.json") -> dict[str, Any] | None:
    """Load an optional org roles config: {"addresses": {addr: role}, "multipliers": {role: x}}."""
    p = Path(path)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception as exc:
        logger.warning("Failed to read org_roles config", error=str(exc))
        return None


def classify_recipient_role(address: str, config: dict[str, Any] | None = None) -> str:
    """Return the organizational role for a recipient address."""
    addr = str(address or "").strip().lower()
    if config:
        explicit = (config.get("addresses") or {})
        if addr in explicit:
            return str(explicit[addr])
    local = _local_part(addr)
    for role, keywords in _ROLE_KEYWORDS.items():
        if any(kw in local for kw in keywords):
            return role
    return "general"


def get_recipient_risk_multiplier(
    recipients: list[str] | str | None,
    config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Resolve recipients to roles and return the highest applicable multiplier."""
    if isinstance(recipients, str):
        recipients = [recipients]
    recipients = [r for r in (recipients or []) if r]

    multipliers = dict(DEFAULT_ROLE_MULTIPLIERS)
    if config and isinstance(config.get("multipliers"), dict):
        multipliers.update({str(k): float(v) for k, v in config["multipliers"].items()})

    roles: list[str] = []
    best_role = "general"
    best_mult = 1.0
    for addr in recipients:
        role = classify_recipient_role(addr, config)
        roles.append(role)
        mult = float(multipliers.get(role, 1.0))
        if mult > best_mult:
            best_mult, best_role = mult, role

    return {
        "multiplier": round(min(best_mult, _MULTIPLIER_CAP), 4),
        "highest_role": best_role,
        "roles": roles,
    }


def apply_org_context(
    base_score: float,
    recipients: list[str] | str | None,
    config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Apply the recipient risk multiplier to a base score (clamped to [0, 1]).

    Returns ``{applied, adjusted_score, multiplier, highest_role, roles}``.
    ``applied`` is False (and the score is unchanged) when no multiplier > 1 fires.
    """
    info = get_recipient_risk_multiplier(recipients, config)
    multiplier = info["multiplier"]
    base = max(0.0, min(1.0, float(base_score)))
    if multiplier <= 1.0:
        return {"applied": False, "adjusted_score": round(base, 4), **info}
    adjusted = round(min(1.0, base * multiplier), 4)
    return {"applied": True, "adjusted_score": adjusted, **info}
