"""ORM tables for the shared context store and platform services.

Section 5.3 layers mapped to tables:
  * Context store          -> Entity, SourceRecord, Relation, Evidence
  * Entity resolution      -> ResolutionOverride, UnresolvedItem
  * Decision and approval  -> ActionRequest, PolicyVersion, Disposition
  * Audit and governance   -> AuditRecord (append-only, hash-chained), LLMCall
  * Connector layer        -> ConnectorCheckpoint
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    event,
)
from sqlalchemy.orm import Mapped, mapped_column

from soc_platform.core.db import Base, UTCDateTime


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_id() -> str:
    return uuid.uuid4().hex


# --------------------------------------------------------------------------- context store


class Entity(Base):
    """A canonical, resolved entity: asset, identity, indicator, email, alert, finding, case..."""

    __tablename__ = "entities"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    kind: Mapped[str] = mapped_column(String(32), index=True)
    display_name: Mapped[str] = mapped_column(String(512), default="")
    canonical_key: Mapped[str | None] = mapped_column(String(512), index=True, nullable=True)
    attributes: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    confidence: Mapped[float] = mapped_column(Float, default=1.0)
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, onupdate=utcnow)


class EntityKey(Base):
    """Strong identifier -> entity index used for deterministic resolution."""

    __tablename__ = "entity_keys"
    __table_args__ = (UniqueConstraint("kind", "key_name", "key_value", name="uq_entity_key"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    entity_id: Mapped[str] = mapped_column(ForeignKey("entities.id"), index=True)
    kind: Mapped[str] = mapped_column(String(32))
    key_name: Mapped[str] = mapped_column(String(64))
    key_value: Mapped[str] = mapped_column(String(512), index=True)


class EntityHint(Base):
    """Weak, non-unique identifier (hostname, IP, display name) used for fuzzy candidate lookup."""

    __tablename__ = "entity_hints"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    entity_id: Mapped[str] = mapped_column(ForeignKey("entities.id"), index=True)
    kind: Mapped[str] = mapped_column(String(32))
    hint_name: Mapped[str] = mapped_column(String(64))
    hint_value: Mapped[str] = mapped_column(String(512), index=True)
    seen_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)


class SourceRecord(Base):
    """One record as seen by one tool, with provenance, linked to its resolved entity."""

    __tablename__ = "source_records"
    __table_args__ = (UniqueConstraint("tool", "source_type", "source_id", name="uq_source_record"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    entity_id: Mapped[str | None] = mapped_column(ForeignKey("entities.id"), index=True, nullable=True)
    kind: Mapped[str] = mapped_column(String(32), index=True)
    tool: Mapped[str] = mapped_column(String(64), index=True)
    source_type: Mapped[str] = mapped_column(String(64))
    source_id: Mapped[str] = mapped_column(String(512))
    normalized: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    raw_ref: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    deep_link: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    resolution_method: Mapped[str | None] = mapped_column(String(64), nullable=True)
    resolution_confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    fetched_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)


class Relation(Base):
    __tablename__ = "relations"
    __table_args__ = (UniqueConstraint("src_id", "dst_id", "rel_type", name="uq_relation"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    src_id: Mapped[str] = mapped_column(ForeignKey("entities.id"), index=True)
    dst_id: Mapped[str] = mapped_column(ForeignKey("entities.id"), index=True)
    rel_type: Mapped[str] = mapped_column(String(64))
    attributes: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    source_tool: Mapped[str | None] = mapped_column(String(64), nullable=True)
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)


class Evidence(Base):
    """A retrieved piece of evidence attached to a case/investigation (NFR-02)."""

    __tablename__ = "evidence"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    case_id: Mapped[str] = mapped_column(String(32), index=True)
    entity_id: Mapped[str | None] = mapped_column(String(32), index=True, nullable=True)
    dimension: Mapped[str] = mapped_column(String(32))
    source_tool: Mapped[str] = mapped_column(String(64))
    summary: Mapped[str] = mapped_column(Text, default="")
    data: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    deep_link: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    is_inference: Mapped[bool] = mapped_column(Boolean, default=False)
    observed_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    collected_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)


class Case(Base):
    """Consolidated investigation record shared by phishing and incident workflows (IM-F05, PH-F09)."""

    __tablename__ = "cases"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    domain: Mapped[str] = mapped_column(String(32), index=True)          # phishing | incident | vulnerability
    title: Mapped[str] = mapped_column(String(512))
    status: Mapped[str] = mapped_column(String(32), default="open", index=True)  # open|investigating|awaiting_approval|closed
    severity: Mapped[str] = mapped_column(String(16), default="medium")
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    verdict: Mapped[str | None] = mapped_column(String(64), nullable=True)
    summary: Mapped[str] = mapped_column(Text, default="")
    assessment: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)     # grounded claims, MITRE, scores
    completeness: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)   # sources queried / unavailable (IM-F15)
    attributes: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    autonomy_mode: Mapped[str] = mapped_column(String(16), default="shadow")   # shadow | live
    assignee: Mapped[str | None] = mapped_column(String(256), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, onupdate=utcnow)
    closed_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)


class CaseEntity(Base):
    __tablename__ = "case_entities"
    __table_args__ = (UniqueConstraint("case_id", "entity_id", "role", name="uq_case_entity"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id"), index=True)
    entity_id: Mapped[str] = mapped_column(ForeignKey("entities.id"), index=True)
    role: Mapped[str] = mapped_column(String(64), default="related")


class EnrichmentCache(Base):
    """Response cache for connector lookups (IM-T04 caching, R06 rate-limit protection)."""

    __tablename__ = "enrichment_cache"

    key: Mapped[str] = mapped_column(String(256), primary_key=True)
    source: Mapped[str] = mapped_column(String(64))
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)
    fetched_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)


# --------------------------------------------------------------------------- entity resolution


class ResolutionOverride(Base):
    """Durable analyst decision about identity (VM-F02 / VM-T04)."""

    __tablename__ = "resolution_overrides"
    __table_args__ = (UniqueConstraint("tool", "source_type", "source_id", name="uq_override"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    kind: Mapped[str] = mapped_column(String(32))
    tool: Mapped[str] = mapped_column(String(64))
    source_type: Mapped[str] = mapped_column(String(64))
    source_id: Mapped[str] = mapped_column(String(512))
    entity_id: Mapped[str] = mapped_column(ForeignKey("entities.id"))
    decided_by: Mapped[str] = mapped_column(String(256))
    reason: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)


class UnresolvedItem(Base):
    __tablename__ = "unresolved_items"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    source_record_id: Mapped[str] = mapped_column(ForeignKey("source_records.id"), index=True)
    kind: Mapped[str] = mapped_column(String(32))
    candidates: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    reason: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(16), default="open", index=True)
    resolved_by: Mapped[str | None] = mapped_column(String(256), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)


# --------------------------------------------------------------------------- decisions & actions


class ActionRequest(Base):
    __tablename__ = "action_requests"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    action_type: Mapped[str] = mapped_column(String(64), index=True)
    params: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    targets: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    case_id: Mapped[str | None] = mapped_column(String(64), index=True, nullable=True)
    domain: Mapped[str] = mapped_column(String(32), default="platform")
    rationale: Mapped[str] = mapped_column(Text, default="")
    evidence_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    requested_by: Mapped[str] = mapped_column(String(256))
    requested_by_type: Mapped[str] = mapped_column(String(16), default="agent")
    idempotency_key: Mapped[str] = mapped_column(String(256), unique=True)
    status: Mapped[str] = mapped_column(String(32), index=True)
    autonomy_level: Mapped[int] = mapped_column(Integer, default=2)
    policy_reasons: Mapped[list[str]] = mapped_column(JSON, default=list)
    precondition_failures: Mapped[list[str]] = mapped_column(JSON, default=list)
    approver: Mapped[str | None] = mapped_column(String(256), nullable=True)
    decision_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    result: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    reverse_of: Mapped[str | None] = mapped_column(String(32), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    decided_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    executed_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)


class PolicyVersion(Base):
    """Versioned autonomy policy (section 5.2, NFR-12). Only one row is active."""

    __tablename__ = "policy_versions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    document: Mapped[dict[str, Any]] = mapped_column(JSON)
    proposed_by: Mapped[str] = mapped_column(String(256))
    approved_by: Mapped[str | None] = mapped_column(String(256), nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="proposed")  # proposed|active|superseded|rejected
    note: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    activated_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)


class Disposition(Base):
    """Analyst decision capture (IM-F08, PH-T08, NFR-15) — the feedback & shadow-mode ground truth."""

    __tablename__ = "dispositions"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    domain: Mapped[str] = mapped_column(String(32), index=True)
    subject_type: Mapped[str] = mapped_column(String(32))
    subject_id: Mapped[str] = mapped_column(String(64), index=True)
    system_verdict: Mapped[str | None] = mapped_column(String(64), nullable=True)
    system_confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    analyst_verdict: Mapped[str] = mapped_column(String(64))
    analyst: Mapped[str] = mapped_column(String(256))
    reasoning: Mapped[str] = mapped_column(Text, default="")
    detection_source: Mapped[str | None] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)


# --------------------------------------------------------------------------- audit & governance


class AuditRecord(Base):
    """Append-only, hash-chained audit log (NFR-04). Updates and deletes are refused."""

    __tablename__ = "audit_log"

    seq: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, index=True)
    actor_type: Mapped[str] = mapped_column(String(16))  # agent | human | system
    actor_id: Mapped[str] = mapped_column(String(256), index=True)
    event_type: Mapped[str] = mapped_column(String(64), index=True)
    subject_type: Mapped[str] = mapped_column(String(32))
    subject_id: Mapped[str] = mapped_column(String(64), index=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    prev_hash: Mapped[str] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64), unique=True)


@event.listens_for(AuditRecord, "before_update")
def _refuse_audit_update(*_args) -> None:
    raise PermissionError("audit_log is append-only")


@event.listens_for(AuditRecord, "before_delete")
def _refuse_audit_delete(*_args) -> None:
    raise PermissionError("audit_log is append-only")


class LLMCall(Base):
    """Prompt/response log for every model call (NFR-11, VM-T07)."""

    __tablename__ = "llm_calls"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    ts: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, index=True)
    workflow: Mapped[str] = mapped_column(String(64), index=True)
    provider: Mapped[str] = mapped_column(String(32))
    model: Mapped[str] = mapped_column(String(128))
    prompt_redacted: Mapped[str] = mapped_column(Text)
    response: Mapped[str] = mapped_column(Text, default="")
    prompt_tokens: Mapped[int] = mapped_column(Integer, default=0)
    completion_tokens: Mapped[int] = mapped_column(Integer, default=0)
    grounded: Mapped[bool] = mapped_column(Boolean, default=False)
    status: Mapped[str] = mapped_column(String(32), default="ok")


# --------------------------------------------------------------------------- connectors


class ConnectorCheckpoint(Base):
    """Cursor checkpoint + reconciliation counts per connector stream (VM-T02, NFR-13)."""

    __tablename__ = "connector_checkpoints"

    connector: Mapped[str] = mapped_column(String(64), primary_key=True)
    stream: Mapped[str] = mapped_column(String(64), primary_key=True)
    cursor: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_success_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    last_attempt_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    source_count: Mapped[int] = mapped_column(Integer, default=0)
    ingested_count: Mapped[int] = mapped_column(Integer, default=0)
    failed_count: Mapped[int] = mapped_column(Integer, default=0)


# --------------------------------------------------------------------------- access control (NFR-09)


class RoleAssignment(Base):
    """Platform-managed role grants on top of the identity provider's roles (time-bound, domain-scoped)."""

    __tablename__ = "role_assignments"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    principal_id: Mapped[str] = mapped_column(String(256), index=True)
    role: Mapped[str] = mapped_column(String(32))
    domains: Mapped[list[str]] = mapped_column(JSON, default=lambda: ["*"])
    granted_by: Mapped[str] = mapped_column(String(256))
    reason: Mapped[str] = mapped_column(Text, default="")
    granted_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    revoked_by: Mapped[str | None] = mapped_column(String(256), nullable=True)


class ApiKey(Base):
    """Service-account key. Only a SHA-256 of the secret is stored; the secret is shown once at creation."""

    __tablename__ = "api_keys"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(128))
    secret_sha256: Mapped[str] = mapped_column(String(64))
    roles: Mapped[list[str]] = mapped_column(JSON, default=list)
    domains: Mapped[list[str]] = mapped_column(JSON, default=lambda: ["*"])
    created_by: Mapped[str] = mapped_column(String(256))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime())
    revoked_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)


class TokenRevocation(Base):
    """Revoked token ids (jti) and per-principal not-before times (log-out everywhere)."""

    __tablename__ = "token_revocations"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    token_id: Mapped[str | None] = mapped_column(String(128), nullable=True, unique=True)
    principal_id: Mapped[str | None] = mapped_column(String(256), nullable=True, index=True)
    not_before: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    revoked_by: Mapped[str] = mapped_column(String(256))
    ts: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)


class AccessLogRecord(Base):
    """Who called what (append-only via the ORM; pruned only by the audited retention job)."""

    __tablename__ = "access_log"

    seq: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, index=True)
    principal_id: Mapped[str | None] = mapped_column(String(256), nullable=True, index=True)
    auth_method: Mapped[str | None] = mapped_column(String(32), nullable=True)
    method: Mapped[str] = mapped_column(String(8))
    path: Mapped[str] = mapped_column(String(512))
    status: Mapped[int] = mapped_column(Integer)
    client_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(256), nullable=True)
    latency_ms: Mapped[float] = mapped_column(Float, default=0.0)


@event.listens_for(AccessLogRecord, "before_update")
def _refuse_access_update(*_args) -> None:
    raise PermissionError("access_log is append-only")


@event.listens_for(AccessLogRecord, "before_delete")
def _refuse_access_delete(*_args) -> None:
    raise PermissionError("access_log is append-only (use the retention job)")


class SystemFlag(Base):
    """Durable operational switches shared by every replica (e.g. the global kill switch)."""

    __tablename__ = "system_flags"

    name: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    updated_by: Mapped[str] = mapped_column(String(256))
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)



class JobRun(Base):
    """One execution of a scheduled job (VM-T11): outcome, retries, error and summary; dead-letter visible."""

    __tablename__ = "job_runs"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    job: Mapped[str] = mapped_column(String(64), index=True)
    trigger: Mapped[str] = mapped_column(String(32), default="schedule")
    ordinal: Mapped[int] = mapped_column(BigInteger, index=True, default=0)  # strictly increasing run order
    status: Mapped[str] = mapped_column(String(16), index=True)  # ok | error | dead_letter
    attempts: Mapped[int] = mapped_column(Integer, default=1)
    consecutive_failures: Mapped[int] = mapped_column(Integer, default=0)
    started_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, index=True)
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    summary: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
