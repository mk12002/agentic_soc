"""Immutable audit trail (NFR-04, PH-F16, IM-F16, VM-F18).

Every retrieval, inference, recommendation, approval, override and action is
appended with actor attribution. Each record's hash covers the previous
record's hash, so any edit or deletion in the database breaks ``verify()``.
The ORM additionally refuses UPDATE/DELETE on the table; in Postgres the
service role should also be granted INSERT/SELECT only.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from soc_platform.core.models import AuditRecord, utcnow
from soc_platform.core.observability import current_trace, event

GENESIS = "0" * 64
CHAIN_LOCK = "audit_chain_head"

ACTOR_AGENT = "agent"
ACTOR_HUMAN = "human"
ACTOR_SYSTEM = "system"


def _canonical(data: Any) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), default=str)


def _ts_str(ts: datetime) -> str:
    # SQLite drops tzinfo on read; normalise to naive-UTC ISO so hashes are stable.
    return ts.replace(tzinfo=None).isoformat(timespec="microseconds")


def compute_hash(prev_hash: str, ts: datetime, actor_type: str, actor_id: str, event_type: str,
                 subject_type: str, subject_id: str, payload: dict[str, Any]) -> str:
    body = _canonical([prev_hash, _ts_str(ts), actor_type, actor_id, event_type, subject_type, subject_id, payload])
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


class AuditLog:
    def __init__(self, session: Session) -> None:
        self.s = session

    def _last_hash(self) -> str:
        last = self.s.execute(select(AuditRecord.hash).order_by(AuditRecord.seq.desc()).limit(1)).scalar()
        return last or GENESIS

    def _lock_chain(self) -> None:
        """Take the chain's write lock before reading its head, held until this transaction ends.

        Appending reads the last hash and links the new record to it. Two transactions doing that at the same moment
        (a scheduled job and a user's approval) would read the same head and fork the chain, which ``verify()`` then
        reports as tampering. Updating one head row first serialises appenders on every database: PostgreSQL locks
        the row, SQLite takes its write lock. The next appender waits, then reads the head this one wrote."""
        from sqlalchemy import update
        from sqlalchemy.exc import IntegrityError

        from soc_platform.core.models import SystemFlag

        stmt = update(SystemFlag).where(SystemFlag.name == CHAIN_LOCK).values(updated_at=utcnow())
        if self.s.execute(stmt).rowcount:
            return
        try:
            with self.s.begin_nested():                      # first append ever: create the head row
                self.s.add(SystemFlag(name=CHAIN_LOCK, value={}, updated_by="audit"))
        except IntegrityError:
            pass                                             # another appender created it first
        self.s.execute(stmt)

    def append(
        self,
        *,
        actor_type: str,
        actor_id: str,
        event_type: str,
        subject_type: str,
        subject_id: str,
        payload: dict[str, Any] | None = None,
    ) -> AuditRecord:
        if actor_type not in {ACTOR_AGENT, ACTOR_HUMAN, ACTOR_SYSTEM}:
            raise ValueError(f"invalid actor_type {actor_type!r}")
        payload = json.loads(_canonical(payload or {}))
        self._lock_chain()
        ts = utcnow()
        prev = self._last_hash()
        rec = AuditRecord(
            ts=ts,
            actor_type=actor_type,
            actor_id=actor_id,
            event_type=event_type,
            subject_type=subject_type,
            subject_id=str(subject_id),
            payload=payload,
            prev_hash=prev,
            hash=compute_hash(prev, ts, actor_type, actor_id, event_type, subject_type, str(subject_id), payload),
            trace_id=current_trace(),
        )
        self.s.add(rec)
        self.s.flush()
        # the request that wrote it has been audited (api.app.db_session adds a generic record otherwise)
        self.s.info["soc_audited"] = self.s.info.get("soc_audited", 0) + 1
        event("audit", event_type=event_type, actor_type=actor_type, actor_id=actor_id, subject_type=subject_type,
              subject_id=str(subject_id), seq=rec.seq)
        return rec

    def verify(self) -> dict[str, Any]:
        """Recompute the chain. Returns ``{"ok": bool, "records": n, "first_bad_seq": int|None}``."""
        prev = GENESIS
        n = 0
        for rec in self.s.execute(select(AuditRecord).order_by(AuditRecord.seq)).scalars():
            n += 1
            expected = compute_hash(prev, rec.ts, rec.actor_type, rec.actor_id, rec.event_type,
                                    rec.subject_type, rec.subject_id, rec.payload)
            if rec.prev_hash != prev or rec.hash != expected:
                return {"ok": False, "records": n, "first_bad_seq": rec.seq}
            prev = rec.hash
        return {"ok": True, "records": n, "first_bad_seq": None, "head": prev}

    def query(
        self,
        *,
        subject_id: str | None = None,
        actor_id: str | None = None,
        event_type: str | None = None,
        limit: int = 200,
    ) -> list[AuditRecord]:
        stmt = select(AuditRecord).order_by(AuditRecord.seq.desc()).limit(limit)
        if subject_id:
            stmt = stmt.where(AuditRecord.subject_id == subject_id)
        if actor_id:
            stmt = stmt.where(AuditRecord.actor_id == actor_id)
        if event_type:
            stmt = stmt.where(AuditRecord.event_type == event_type)
        return list(self.s.execute(stmt).scalars())

    @staticmethod
    def export(records: Iterable[AuditRecord]) -> list[dict[str, Any]]:
        return [
            {
                "seq": r.seq,
                "ts": _ts_str(r.ts),
                "actor_type": r.actor_type,
                "actor_id": r.actor_id,
                "event_type": r.event_type,
                "subject_type": r.subject_type,
                "subject_id": r.subject_id,
                "payload": r.payload,
                "prev_hash": r.prev_hash,
                "hash": r.hash,
                "trace_id": r.trace_id,
            }
            for r in records
        ]
