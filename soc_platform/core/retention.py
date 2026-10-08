"""Data retention (NFR-08, R10) and audit export (NFR-04).

Retention removes *copies of sensitive source data* once they are no longer needed:

* raw tool payloads older than ``raw_retention_days`` (the normalised record stays: it is what the
  context store, cases and metrics are built from)
* reported ``.eml`` files older than ``raw_retention_days`` whose case is closed (legal hold: the file
  of any open case is kept)
* LLM prompt/response text older than ``llm_log_retention_days`` (token counts and metadata kept
  for budget reporting)
* access-log rows older than ``access_log_retention_days``
* high-volume telemetry in the context store (sign-ins, DNS, mail events, secret accesses, elevations) last seen
  more than ``event_retention_days`` ago (0 keeps everything). A client tenant writes hundreds of thousands of such
  events a day; kept forever they grow every table and index without bound. An event is kept while anything still
  points at it: a case, evidence, an insight or a resolution override. Alerts, findings, assets, people and
  indicators are never pruned here.

The audit log is never pruned by the platform. Every run is itself audited.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import delete, or_, select, update
from sqlalchemy.orm import Session

from soc_platform.config import Settings
from soc_platform.core.audit import AuditLog
from soc_platform.core.models import (
    AccessLogRecord,
    AuditRecord,
    Case,
    CaseEntity,
    Entity,
    EntityHint,
    EntityKey,
    Evidence,
    LLMCall,
    Relation,
    ResolutionOverride,
    SourceRecord,
    UnresolvedItem,
    utcnow,
)

EVENT_KINDS = ("signin", "dns", "mail_event", "secret_access", "elevation")
PRUNE_BATCH = 500           # ids per delete statement: bounded statements and parameter lists on both engines


def _unlink(path: str | None) -> bool:
    if not path:
        return False
    p = Path(path)
    try:
        if p.is_file():
            p.unlink()
            return True
    except OSError:
        return False
    return False


def run_retention(session: Session, settings: Settings, *, actor: str = "system:retention",
                  dry_run: bool = False) -> dict[str, Any]:
    now = utcnow()
    raw_cut = now - timedelta(days=settings.raw_retention_days)
    llm_cut = now - timedelta(days=settings.llm_log_retention_days)
    acc_cut = now - timedelta(days=settings.access_log_retention_days)
    report: dict[str, Any] = {"dry_run": dry_run, "raw_payloads": 0, "emails": 0, "emails_on_hold": 0,
                              "llm_prompts": 0, "access_log_rows": 0,
                              "cutoffs": {"raw": raw_cut.isoformat(), "llm": llm_cut.isoformat(),
                                          "access_log": acc_cut.isoformat()}}

    for src in session.execute(select(SourceRecord).where(SourceRecord.raw_ref.is_not(None),
                                                          SourceRecord.fetched_at < raw_cut)).scalars():
        report["raw_payloads"] += 1
        if not dry_run:
            _unlink(src.raw_ref)
            src.raw_ref = None

    try:
        from soc_platform.domains.phishing.models import Submission
    except ImportError:  # pragma: no cover
        Submission = None  # type: ignore[assignment]
    if Submission is not None:
        for sub in session.execute(select(Submission).where(Submission.raw_path.is_not(None),
                                                            Submission.received_at < raw_cut)).scalars():
            case = session.get(Case, sub.case_id) if sub.case_id else None
            if case is not None and case.status != "closed":
                report["emails_on_hold"] += 1
                continue
            report["emails"] += 1
            if not dry_run:
                _unlink(sub.raw_path)
                sub.raw_path = None

    n = session.execute(select(LLMCall.id).where(LLMCall.ts < llm_cut, LLMCall.prompt_redacted != "[purged]")).all()
    report["llm_prompts"] = len(n)
    if not dry_run and n:
        session.execute(update(LLMCall).where(LLMCall.ts < llm_cut).values(prompt_redacted="[purged]", response="[purged]"))

    report["access_log_rows"] = len(session.execute(select(AccessLogRecord.seq).where(AccessLogRecord.ts < acc_cut)).all())
    if not dry_run and report["access_log_rows"]:
        # Core DELETE: the ORM refuses deletes on this table; this audited job is the only prune path.
        session.execute(delete(AccessLogRecord).where(AccessLogRecord.ts < acc_cut))

    report["events"] = _prune_events(session, settings, now, dry_run)
    if settings.event_retention_days > 0:
        report["cutoffs"]["events"] = (now - timedelta(days=settings.event_retention_days)).isoformat()

    if not dry_run:
        AuditLog(session).append(actor_type="system", actor_id=actor, event_type="retention.run", subject_type="system",
                                 subject_id="retention", payload=report)
    session.flush()
    return report


def _prune_events(session: Session, settings: Settings, now, dry_run: bool) -> int:
    """Delete old telemetry events no case, evidence, insight or override refers to; returns how many."""
    if settings.event_retention_days <= 0:
        return 0
    from soc_platform.intelligence.models import Insight

    cut = now - timedelta(days=settings.event_retention_days)
    held = set(session.execute(select(CaseEntity.entity_id)).scalars())
    held |= set(session.execute(select(Evidence.entity_id).where(Evidence.entity_id.is_not(None))).scalars())
    held |= set(session.execute(select(ResolutionOverride.entity_id)).scalars())
    for ids in session.execute(select(Insight.entity_ids)).scalars():
        held.update(ids or [])
    old = [e for e in session.execute(select(Entity.id).where(Entity.kind.in_(EVENT_KINDS), Entity.last_seen < cut)
                                      .order_by(Entity.id)).scalars() if e not in held]
    if dry_run or not old:
        return len(old)
    for i in range(0, len(old), PRUNE_BATCH):
        ids = old[i:i + PRUNE_BATCH]
        src = select(SourceRecord.id).where(SourceRecord.entity_id.in_(ids))
        session.execute(delete(UnresolvedItem).where(UnresolvedItem.source_record_id.in_(src)))
        session.execute(delete(SourceRecord).where(SourceRecord.entity_id.in_(ids)))
        session.execute(delete(Relation).where(or_(Relation.src_id.in_(ids), Relation.dst_id.in_(ids))))
        session.execute(delete(EntityKey).where(EntityKey.entity_id.in_(ids)))
        session.execute(delete(EntityHint).where(EntityHint.entity_id.in_(ids)))
        session.execute(delete(Entity).where(Entity.id.in_(ids)))
    return len(old)


def export_audit(session: Session, *, since_seq: int = 0) -> Iterator[str]:
    """JSON Lines export of the hash-chained audit log; a final line carries the chain verification."""
    last = None
    for rec in session.execute(select(AuditRecord).where(AuditRecord.seq > since_seq)
                               .order_by(AuditRecord.seq)).scalars():
        last = rec
        yield json.dumps({"seq": rec.seq, "ts": rec.ts.isoformat(), "actor_type": rec.actor_type,
                          "actor_id": rec.actor_id, "event_type": rec.event_type, "subject_type": rec.subject_type,
                          "subject_id": rec.subject_id, "payload": rec.payload, "prev_hash": rec.prev_hash,
                          "hash": rec.hash}, default=str, sort_keys=True) + "\n"
    v = AuditLog(session).verify()
    yield json.dumps({"_verification": v, "_head_hash": last.hash if last else None,
                      "_exported_at": utcnow().isoformat()}, default=str) + "\n"
