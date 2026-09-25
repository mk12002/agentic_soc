"""Durable job orchestration (VM-T11, NFR-05, NFR-13).

* every run is recorded (``JobRun``): start, end, attempts, outcome, error, summary
* transient failures are retried with exponential backoff inside a run
* a job that fails ``DEAD_LETTER_AFTER`` runs in a row is marked ``dead_letter`` and raises an insight;
  it keeps being attempted on schedule so it recovers on its own once the cause is fixed
* a database lease guarantees that two scheduler replicas never run the same job concurrently
* any job can be replayed on demand (API / CLI); every job is idempotent (cursors, dedupe keys,
  idempotency keys on actions), so a replay never duplicates work or actions
"""

from __future__ import annotations

import os
import socket
import time
import traceback
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from sqlalchemy import select
from sqlalchemy.orm import Session

from soc_platform.core.models import JobRun, SystemFlag, utcnow

JOBS: dict[str, tuple[str, int]] = {  # name -> (interval env var, default seconds)
    "incident": ("SOC_JOB_INCIDENT_SECONDS", 300),
    "phishing": ("SOC_JOB_PHISHING_SECONDS", 120),
    "vulnerability": ("SOC_JOB_VM_SECONDS", 6 * 3600),
    "follow_up": ("SOC_JOB_FOLLOWUP_SECONDS", 24 * 3600),
    "daily_report": ("SOC_JOB_DAILY_REPORT_SECONDS", 24 * 3600),
    "intelligence": ("SOC_JOB_INTELLIGENCE_SECONDS", 600),
    "retention": ("SOC_JOB_RETENTION_SECONDS", 24 * 3600),
}
RETRIES = 3
DEAD_LETTER_AFTER = 3
LEASE_SECONDS = 1800
HOLDER = f"{socket.gethostname()}:{os.getpid()}"


def _aware(dt: datetime | None) -> datetime | None:
    return dt.replace(tzinfo=timezone.utc) if dt is not None and dt.tzinfo is None else dt


def _body(name: str, s: Session) -> dict[str, Any]:
    from soc_platform.api.app import _intel, _misconfig, _services
    from soc_platform.config import get_settings

    sv = _services(s)
    if name == "incident":
        ing = sv["incident"].ingest()
        cases = sv["incident"].cluster()
        done = [sv["incident"].investigate(c.id) for c in cases if c.status != "closed"]
        return {"synced": ing.synced, "new_incidents": len(cases), "investigated": len(done)}
    if name == "phishing":
        subs = [x for x in sv["phishing"].ingest_reported() if x.status == "new"]
        for sub in subs:
            sv["phishing"].process(sub.id)
        return {"processed": len(subs)}
    if name == "vulnerability":
        out = sv["vulnerability"].refresh()
        mis = _misconfig(s).refresh()
        return {"consolidated": out["consolidation"]["consolidated"],
                "misconfigurations": mis["consolidation"]["consolidated"]}
    if name == "follow_up":
        sync = sv["vulnerability"].sync_tickets()
        fu = sv["vulnerability"].follow_up()
        exp = sv["vulnerability"].expire_exceptions()
        return {"tickets": sync, "escalations": len(fu["escalations"]), "expired_exceptions": len(exp)}
    if name == "intelligence":
        return {"insights": len(_intel(s).refresh())}
    if name == "daily_report":
        from soc_platform.reporting.reports import ReportService

        run = ReportService(s, get_settings().report_output_dir).daily_exposure(sv["vulnerability"])
        return {"report": run.id}
    if name == "retention":
        from soc_platform.core.retention import run_retention

        return run_retention(s, get_settings())
    raise KeyError(f"unknown job {name}")


def _lease(db: Any, name: str, *, release: bool = False) -> bool:
    key = f"job_lease:{name}"
    with db.session() as s:
        f = s.get(SystemFlag, key)
        now = utcnow()
        if release:
            if f is not None and (f.value or {}).get("holder") == HOLDER:
                f.value = {"holder": None, "until": now.isoformat()}
            return True
        if f is not None:
            v = f.value or {}
            until = datetime.fromisoformat(v["until"]) if v.get("until") else now
            if v.get("holder") not in (None, HOLDER) and _aware(until) > now:
                return False
        else:
            f = SystemFlag(name=key, value={}, updated_by="scheduler")
            s.add(f)
        f.value = {"holder": HOLDER, "until": (now + timedelta(seconds=LEASE_SECONDS)).isoformat()}
        f.updated_by, f.updated_at = "scheduler", now
    return True


def run_job(name: str, *, db: Any = None, trigger: str = "schedule", sleep: Callable[[float], None] = time.sleep,
            body: Callable[[str, Session], dict[str, Any]] | None = None) -> JobRun | None:
    """Run one job with lease, retries, run record and dead-lettering. Returns None if another replica holds it."""
    from soc_platform.core.db import get_database

    db = db or get_database()
    if not _lease(db, name):
        return None
    fn = body or _body
    started = utcnow()
    err, summary, attempts = None, {}, 0
    try:
        for attempts in range(1, RETRIES + 1):
            try:
                with db.session() as s:
                    summary = fn(name, s) or {}
                err = None
                break
            except Exception as exc:  # noqa: BLE001 - recorded, retried, dead-lettered
                err = f"{type(exc).__name__}: {exc}"[:1000] + "\n" + traceback.format_exc(limit=3)[-1500:]
                if attempts < RETRIES:
                    sleep(min(60.0, 2.0 ** attempts))
    finally:
        _lease(db, name, release=True)
    with db.session() as s:
        recent = list(s.execute(select(JobRun).where(JobRun.job == name).order_by(JobRun.ordinal.desc())
                                .limit(DEAD_LETTER_AFTER - 1)).scalars())
        failures_in_row = 0 if err is None else 1 + sum(1 for _ in _takewhile_failed(recent))
        status = "ok" if err is None else ("dead_letter" if failures_in_row >= DEAD_LETTER_AFTER else "error")
        run = JobRun(job=name, trigger=trigger, ordinal=_next_ordinal(s), started_at=started, finished_at=utcnow(), attempts=attempts,
                     status=status, error=err, summary=_jsonable(summary), consecutive_failures=failures_in_row)
        s.add(run)
        s.flush()
        if status == "dead_letter":
            _alert(s, name, err or "", failures_in_row)
        s.expunge(run)
    return run


def _next_ordinal(s: Session) -> int:
    """Wall-clock nanoseconds, forced strictly above the last recorded run (clock ties / skew safe)."""
    from sqlalchemy import func

    last = s.execute(select(func.max(JobRun.ordinal))).scalar() or 0
    return max(time.time_ns(), last + 1)


def _takewhile_failed(runs: list[JobRun]):
    for r in runs:
        if r.status == "ok":
            return
        yield r


def _jsonable(v: Any) -> Any:
    import json

    return json.loads(json.dumps(v, default=str))


def _alert(s: Session, name: str, err: str, n: int) -> None:
    from soc_platform.intelligence.correlation import _key
    from soc_platform.intelligence.models import Insight

    key = _key("job", name)
    cur = s.execute(select(Insight).where(Insight.dedupe_key == key)).scalars().first()
    if cur is not None:
        cur.last_seen, cur.status = utcnow(), "new"
        return
    s.add(Insight(rule="job_dead_letter", dedupe_key=key, severity="high", score=65.0,
                  title=f"Scheduled job '{name}' failed {n} runs in a row", entity_ids=[], domains=[],
                  evidence=[{"ref": name, "signal": "job_failure", "source": "scheduler", "summary": err.split(chr(10))[0]}],
                  next_steps=["Check the job run history (GET /api/v1/jobs) and connector health",
                              "Fix the cause, then replay the job (POST /api/v1/jobs/{name}/run)"],
                  requirement_refs=["VM-T11", "NFR-13"]))


def due(now: float, last: dict[str, float]) -> list[str]:
    return [n for n, (env, default) in JOBS.items() if now - last.get(n, 0) >= int(os.environ.get(env, default))]


def history(s: Session, *, job: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
    q = select(JobRun).order_by(JobRun.ordinal.desc()).limit(limit)
    if job:
        q = q.where(JobRun.job == job)
    return [{"id": r.id, "job": r.job, "trigger": r.trigger, "status": r.status, "attempts": r.attempts,
             "started_at": r.started_at.isoformat(), "finished_at": r.finished_at.isoformat() if r.finished_at else None,
             "duration_s": round((_aware(r.finished_at) - _aware(r.started_at)).total_seconds(), 2) if r.finished_at else None,
             "error": (r.error or "").split("\n")[0] or None, "summary": r.summary,
             "consecutive_failures": r.consecutive_failures} for r in s.execute(q).scalars()]
