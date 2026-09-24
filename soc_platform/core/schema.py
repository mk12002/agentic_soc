"""Canonical schema that every connector normalises to (section 5.3 normalisation layer).

Connectors emit ``NormalizedRecord``. A record is either an *entity* observation
(asset, identity, indicator) that is resolved to a canonical entity, or an
*event* (alert, finding, email, sign-in, click, dns request...) that is stored
with provenance and linked to the entities it references via ``refs``.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

ENTITY_KINDS = {"asset", "identity", "indicator"}
EVENT_KINDS = {
    "alert", "finding", "vulnerability", "email", "signin", "click", "dns", "process",
    "deception", "secret_access", "elevation", "cloud_issue", "mail_event", "ticket",
}

Dimension = Literal[
    "endpoint", "identity", "privileged_access", "dns", "deception", "exposure", "email",
    "threat_intel", "cloud", "ticketing", "other",
]


class EntityRef(BaseModel):
    """Reference from a record to an entity it involves (host, user, IP, hash...)."""

    kind: Literal["asset", "identity", "indicator"]
    role: str = "related"  # e.g. host, user, sender, recipient, destination, observable
    keys: dict[str, str] = Field(default_factory=dict)  # strong keys, e.g. {"upn": "a@b.com"}
    attributes: dict[str, Any] = Field(default_factory=dict)  # hostname, ip, os, display_name...

    _keys = field_validator("keys", mode="before")(lambda cls, v: _clean_keys(v))


class NormalizedRecord(BaseModel):
    kind: str
    tool: str
    source_type: str
    source_id: str
    observed_at: datetime | None = None
    title: str = ""
    severity: str | None = None  # informational | low | medium | high | critical
    attributes: dict[str, Any] = Field(default_factory=dict)
    keys: dict[str, str] = Field(default_factory=dict)  # for entity kinds
    refs: list[EntityRef] = Field(default_factory=list)
    deep_link: str | None = None
    dimension: str = "other"
    raw: dict[str, Any] | None = None  # persisted to object storage, not to the row

    _keys = field_validator("keys", mode="before")(lambda cls, v: _clean_keys(v))

    @property
    def is_entity(self) -> bool:
        return self.kind in ENTITY_KINDS


SEVERITY_ORDER = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _clean_keys(v: Any) -> dict[str, str]:
    return {str(k): str(x) for k, x in (v or {}).items() if x not in (None, "", [], {})}


def severity_rank(sev: str | None) -> int:
    return SEVERITY_ORDER.get((sev or "").lower(), 0)
