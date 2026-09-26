"""Data retention (NFR-08, R10) and audit export (NFR-04).

Retention removes *copies of sensitive source data* once they are no longer needed:

* raw tool payloads older than ``raw_retention_days`` (the normalised record stays: it is what the
  context store, cases and metrics are built from)
* reported ``.eml`` files older than ``raw_retention_days`` whose case is closed (legal hold: the file
  of any open case is kept)
* LLM prompt/response text older than ``llm_log_retention_days`` (token counts and metadata kept
  for budget reporting)
* access-log rows older than ``access_log_retention_days``

The audit log is never pruned by the platform. Every run is itself audited.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import delete, select, update
from sqlalchemy.orm import Session

from soc_platform.config import Settings
from soc_platform.core.audit import AuditLog
from soc_platform.core.models import AccessLogRecord, AuditRecord, Case, LLMCall, SourceRecord, utcnow


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

    if not dry_run:
        AuditLog(session).append(actor_type="system", actor_id=actor, event_type="retention.run", subject_type="system",
                                 subject_id="retention", payload=report)
    session.flush()
    return report


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
