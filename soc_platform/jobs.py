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
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from soc_platform.core.models import JobRun, SystemFlag, utcnow

# name -> (interval env var, default seconds). Order matters when several are due at once (first start): exposure data
# (vulnerability) is collected before incidents and phishing are scored, so a fresh deployment does not score an
# incident without knowing its host is exposed.
JOBS: dict[str, tuple[str, int]] = {
    "vulnerability": ("SOC_JOB_VM_SECONDS", 6 * 3600),
    "incident": ("SOC_JOB_INCIDENT_SECONDS", 300),
    "phishing": ("SOC_JOB_PHISHING_SECONDS", 120),
    "follow_up": ("SOC_JOB_FOLLOWUP_SECONDS", 24 * 3600),
    "daily_report": ("SOC_JOB_DAILY_REPORT_SECONDS", 24 * 3600),
    "weekly_reports": ("SOC_JOB_WEEKLY_REPORTS_SECONDS", 7 * 24 * 3600),
    "intelligence": ("SOC_JOB_INTELLIGENCE_SECONDS", 600),
    "retention": ("SOC_JOB_RETENTION_SECONDS", 24 * 3600),
    "self_check": ("SOC_JOB_SELF_CHECK_SECONDS", 3600),
    "notify": ("SOC_JOB_NOTIFY_SECONDS", 60),
}
RETRIES = 3
DEAD_LETTER_AFTER = 3
LEASE_SECONDS = 1800
HOLDER = f"{socket.gethostname()}:{os.getpid()}"


def _aware(dt: datetime | None) -> datetime | None:
    return dt.replace(tzinfo=UTC) if dt is not None and dt.tzinfo is None else dt


def _body(name: str, s: Session) -> dict[str, Any]:
    from soc_platform.api.app import _intel, _misconfig, _services
    from soc_platform.config import get_settings

    sv = _services(s)
    if name == "incident":
        ing = sv["incident"].ingest()
        cases = sv["incident"].cluster()
        done = [c.id for c in cases if c.status != "closed"]
        for cid in done:
            sv["incident"].investigate(cid, narrate=False)
        reassessed = sv["incident"].reassess_open(exclude=set(done), narrate=False)   # new exposure on their hosts
        s.commit()          # the cases are visible and actionable now; the written explanations follow
        narrated = sv["incident"].narrate_pending(done + reassessed)
        return {"synced": ing.synced, "new_incidents": len(cases), "investigated": len(done),
                "reassessed": len(reassessed), "narrated": narrated}
    if name == "phishing":
        subs = [x for x in sv["phishing"].ingest_reported() if x.status == "new"]
        case_ids = [sv["phishing"].process(sub.id, narrate=False)["case"]["id"] for sub in subs]
        s.commit()          # verdicts, evidence and recommendations are visible now; the explanations follow
        narrated = sv["phishing"].narrate_pending(case_ids)
        return {"processed": len(subs), "narrated": narrated}
    if name == "vulnerability":
        out = sv["vulnerability"].refresh()
        mis = _misconfig(s).refresh()
        register = sv["vulnerability"].refresh_risk_register()   # critical CVEs proposed; existing entries kept current
        return {"consolidated": out["consolidation"]["consolidated"],
                "misconfigurations": mis["consolidation"]["consolidated"],
                "risk_register": {k: len(v) for k, v in register.items()}}
    if name == "follow_up":
        sync = sv["vulnerability"].sync_tickets()
        fu = sv["vulnerability"].follow_up()
        exp = sv["vulnerability"].expire_exceptions()
        return {"tickets": sync, "escalations": len(fu["escalations"]), "status_checks": len(fu["status_checks"]),
                "expired_exceptions": len(exp)}
    if name == "intelligence":
        svc = _intel(s)
        n = len(svc.refresh())
        try:   # prepare the situation brief now, so the first person to open Intelligence does not wait for it
            svc.analyst.brief()
            warmed = True
        except Exception:
            import logging

            logging.getLogger(__name__).warning("situation brief could not be prepared", exc_info=True)
            warmed = False
        return {"insights": n, "brief_ready": warmed}
    if name == "daily_report":
        from soc_platform.reporting.reports import ReportService

        run = ReportService(s, get_settings().report_output_dir).daily_exposure(sv["vulnerability"])
        return {"report": run.id}
    if name == "weekly_reports":            # the weekly VM report and the weekly management deck
        from soc_platform.api.app import llm
        from soc_platform.reporting.reports import ReportService

        rs = ReportService(s, get_settings().report_output_dir, llm=llm(s))
        vm_run = rs.weekly_vm(sv["vulnerability"])
        deck = rs.weekly_management_deck(sv["vulnerability"], sv["incident"], sv["phishing"])
        return {"weekly_vm": vm_run.id, "weekly_mgmt": deck.id}
    if name == "retention":
        from soc_platform.core.retention import run_retention

        return run_retention(s, get_settings())
    if name == "self_check":
        from soc_platform.core.selfcheck import confirm, llm_budget_alert, raise_or_resolve, run_self_check

        result = confirm(s, run_self_check(s))            # alert only on checks that fail twice (no false alarms)
        raise_or_resolve(s, result)
        budget = llm_budget_alert(s, get_settings())
        return {"passed": result["passed"], "total": result["total"],
                "failing": [c["check"] for c in result["checks"] if not c["ok"]], "llm_budget": budget}
    if name == "notify":
        from soc_platform.core.notify import deliver

        return deliver(s)
    raise KeyError(f"unknown job {name}")


def _holder() -> str:
    """Lease owner: this process *and* thread, so a scheduler thread and a manual replay in the same server are
    told apart like two machines would be."""
    import threading

    return f"{HOLDER}:{threading.get_ident()}"


def next_version(seen: datetime | None) -> datetime:
    """The ``updated_at`` a compare-and-swap writes: now, but always later than the version it read. The Windows clock
    moves in ~15 ms steps, so two writes in one tick got the same stamp and a writer holding a stale copy still matched
    (ABA): a heartbeat put back an old "running job", and a lease could in principle be taken twice."""
    now = utcnow()
    return now if seen is None or now > _aware(seen) else _aware(seen) + timedelta(microseconds=1)


def _lease(db: Any, name: str, *, release: bool = False) -> bool:
    """Take (or release) a job's lease. Atomic across schedulers: the row is changed with a compare-and-swap on its
    ``updated_at``, and the first-ever lease is an insert that only one scheduler can win - the loser of either race
    simply does not get the lease (it never raises)."""
    from sqlalchemy import update
    from sqlalchemy.exc import IntegrityError

    key = f"job_lease:{name}"
    me = _holder()
    now = utcnow()
    mine = {"holder": me, "until": (now + timedelta(seconds=LEASE_SECONDS)).isoformat()}
    try:
        with db.session() as s:
            f = s.get(SystemFlag, key)
            if f is None:
                if release:
                    return True
                s.add(SystemFlag(name=key, value=mine, updated_by="scheduler", updated_at=now))
                return True                                   # the commit fails if another scheduler inserted first
            v, seen = f.value or {}, f.updated_at
            if release:
                if v.get("holder") != me:
                    return True
                value = {"holder": None, "until": now.isoformat()}
            else:
                until = datetime.fromisoformat(v["until"]) if v.get("until") else now
                if v.get("holder") not in (None, me) and _aware(until) > now:
                    return False
                value = mine
            s.expunge(f)
            changed = s.execute(update(SystemFlag).where(SystemFlag.name == key, SystemFlag.updated_at == seen)
                                .values(value=value, updated_by="scheduler", updated_at=next_version(seen))).rowcount
            return release or changed == 1                    # 0 rows: someone else changed it first
    except IntegrityError:
        return False


def run_job(name: str, *, db: Any = None, trigger: str = "schedule", sleep: Callable[[float], None] = time.sleep,
            body: Callable[[str, Session], dict[str, Any]] | None = None,
            still_due: Callable[[], bool] | None = None) -> JobRun | None:
    """Run one job with lease, retries, run record and dead-lettering. Returns None if another scheduler holds it
    or - checked again once the lease is held - has just run it (``still_due``)."""
    from soc_platform.core.db import get_database

    db = db or get_database()
    if not _lease(db, name):
        return None
    if still_due is not None and not still_due():
        _lease(db, name, release=True)                       # someone else ran it between our check and the lease
        return None
    from soc_platform.core.observability import event, new_trace, traced

    with traced(new_trace(f"job-{name}")) as trace:
        return _run_traced(name, db, trigger, sleep, body, trace, event)


def _run_traced(name: str, db: Any, trigger: str, sleep: Callable[[float], None],
                body: Callable[[str, Session], dict[str, Any]] | None, trace: str, event: Callable[..., None]) -> JobRun:
    """The run itself, under its trace id: every audit event, model call and log line it causes carries it."""
    fn = body or _body
    started = utcnow()
    event("job.start", job=name, trigger=trigger)
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
        # record the run *before* releasing the lease: otherwise another scheduler could take the lease in between,
        # find no record of this run and run the job a second time
        with db.session() as s:
            recent = list(s.execute(select(JobRun).where(JobRun.job == name).order_by(JobRun.ordinal.desc())
                                    .limit(DEAD_LETTER_AFTER - 1)).scalars())
            failures_in_row = 0 if err is None else 1 + sum(1 for _ in _takewhile_failed(recent))
            status = "ok" if err is None else ("dead_letter" if failures_in_row >= DEAD_LETTER_AFTER else "error")
            run = JobRun(job=name, trigger=trigger, ordinal=_next_ordinal(s), started_at=started, finished_at=utcnow(),
                         attempts=attempts, status=status, error=err, summary=_jsonable(summary),
                         consecutive_failures=failures_in_row, trace_id=trace)
            s.add(run)
            s.flush()
            if status == "dead_letter":
                _alert(s, name, err or "", failures_in_row)
            s.expunge(run)
    finally:
        _lease(db, name, release=True)
    event("job.end", 20 if run.status == "ok" else 40, job=name, status=run.status, attempts=attempts,
          duration_s=round((run.finished_at - started).total_seconds(), 2) if run.finished_at else None,
          error=(err or "")[:300] or None)
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
             "consecutive_failures": r.consecutive_failures, "trace_id": r.trace_id} for r in s.execute(q).scalars()]
