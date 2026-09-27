"""The job scheduler: runs every recurring job on its interval, inside the API server or as its own process.

Why it is safe to run anywhere, any number of times:

* **The database decides what is due.** A job is due when no run of it (by any scheduler, anywhere) started within its
  interval. A restart does not re-run everything, and two schedulers do not run the same job back to back.
* **A database lease** (``jobs.run_job``) means one job never runs twice at the same moment.
* **It never dies quietly.** An error in one pass is logged and the next pass goes ahead. If the thread itself ever
  stops, the supervisor restarts it.
* **It reports that it is alive.** A small heartbeat thread writes every ``HEARTBEAT_SECONDS``, whatever the jobs are
  doing, so a long job never looks like a dead scheduler. The job loop records its own progress separately, so a
  genuinely stuck job is visible too (``/health`` → ``scheduler.state``).

Embedded (default): ``python -m soc_platform serve`` starts it inside the server. ``SOC_EMBEDDED_SCHEDULER=0`` turns
that off, for deployments that run ``python -m soc_platform scheduler`` as a separate service.
"""

from __future__ import annotations

import hashlib
import logging
import os
import threading
import time
from datetime import timedelta
from typing import Any

from sqlalchemy import func, select

from soc_platform import jobs
from soc_platform.core.models import JobRun, SystemFlag, utcnow

log = logging.getLogger(__name__)

HEARTBEAT_SECONDS = 30
TICK_SECONDS = 15
KEY_PREFIX = "scheduler:"


def _key(holder: str) -> str:
    return KEY_PREFIX + hashlib.sha256(holder.encode()).hexdigest()[:24]


def enabled_embedded() -> bool:
    return os.environ.get("SOC_EMBEDDED_SCHEDULER", "1").strip().lower() not in {"0", "false", "no", "off"}


def interval(name: str) -> int:
    env, default = jobs.JOBS[name]
    return int(os.environ.get(env, default))


def due_jobs(db: Any) -> list[str]:
    """Jobs with no run started within their interval - by this scheduler or any other."""
    now = utcnow()
    with db.session() as s:
        last = dict(s.execute(select(JobRun.job, func.max(JobRun.started_at)).group_by(JobRun.job)).all())
    out = []
    for name in jobs.JOBS:
        started = last.get(name)
        if started is not None and started.tzinfo is None:
            from datetime import UTC

            started = started.replace(tzinfo=UTC)
        if started is None or now - started >= timedelta(seconds=interval(name)):
            out.append(name)
    return out


class Scheduler:
    def __init__(self, db: Any = None, *, mode: str = "embedded", tick: float = TICK_SECONDS,
                 heartbeat: float = HEARTBEAT_SECONDS) -> None:
        from soc_platform.core.db import get_database

        self._db = db
        self._get_db = get_database
        self.mode, self.tick, self.heartbeat = mode, tick, heartbeat
        self.stop = threading.Event()
        self.key = _key(jobs.HOLDER)
        self._threads: list[threading.Thread] = []

    @property
    def db(self) -> Any:
        return self._db or self._get_db()

    # ------------------------------------------------------------------ liveness
    def _beat(self, *, loop: bool = False, job: str | None = None) -> None:
        with self.db.session() as s:
            f = s.get(SystemFlag, self.key)
            if f is None:
                f = SystemFlag(name=self.key, value={}, updated_by="scheduler")
                s.add(f)
            v = dict(f.value or {})
            now = utcnow().isoformat()
            v.update({"holder": jobs.HOLDER, "mode": self.mode, "at": now})
            if loop:
                v["loop_at"], v["job"] = now, job
            f.value, f.updated_by, f.updated_at = v, "scheduler", utcnow()
            if not loop:                                     # forget schedulers gone for a day (old processes)
                cutoff = utcnow() - timedelta(days=1)
                for old in s.execute(select(SystemFlag).where(SystemFlag.name.like(KEY_PREFIX + "%"),
                                                              SystemFlag.name != self.key,
                                                              SystemFlag.updated_at < cutoff)).scalars():
                    s.delete(old)

    def _heartbeat_loop(self) -> None:
        while not self.stop.is_set():
            try:
                self._beat()
            except Exception:
                log.warning("scheduler heartbeat could not be written", exc_info=True)
            self.stop.wait(self.heartbeat)

    # ------------------------------------------------------------------ work
    def run_due(self) -> list[dict[str, Any]]:
        """One pass: run every due job (each leased, retried, recorded, dead-lettered by jobs.run_job)."""
        results = []
        for name in due_jobs(self.db):
            if self.stop.is_set():
                break
            self._beat(loop=True, job=name)
            run = jobs.run_job(name, db=self.db, sleep=lambda secs: self.stop.wait(secs),
                               still_due=lambda n=name: n in due_jobs(self.db))
            results.append({"job": name, "status": run.status if run else "skipped (another scheduler ran or holds it)",
                            "attempts": run.attempts if run else 0,
                            "error": (run.error or "").splitlines()[0] if run and run.error else None})
            if run is not None and run.status != "ok":
                log.warning("scheduled job %s ended %s: %s", name, run.status, results[-1]["error"])
        self._beat(loop=True, job=None)
        return results

    def _job_loop(self, start_delay: float) -> None:
        self.stop.wait(start_delay)                          # let the server finish starting first
        while not self.stop.is_set():
            try:
                self.run_due()
            except Exception:
                log.exception("scheduler pass failed; retrying next tick")
            self.stop.wait(self.tick)

    # ------------------------------------------------------------------ lifecycle
    def start(self, *, start_delay: float = 5.0) -> None:
        """Start the heartbeat and job threads under a supervisor that restarts either if it ever stops."""
        def supervise() -> None:
            workers: dict[str, threading.Thread] = {}
            first = True
            while not self.stop.is_set():
                for name, target, args in (("heartbeat", self._heartbeat_loop, ()),
                                           ("jobs", self._job_loop, (start_delay if first else self.tick,))):
                    t = workers.get(name)
                    if t is None or not t.is_alive():
                        if t is not None:
                            log.error("scheduler %s thread stopped unexpectedly; restarting it", name)
                        workers[name] = threading.Thread(target=target, args=args, name=f"soc-scheduler-{name}",
                                                         daemon=True)
                        workers[name].start()
                first = False
                self.stop.wait(5)

        sup = threading.Thread(target=supervise, name="soc-scheduler", daemon=True)
        sup.start()
        self._threads = [sup]
        log.info("scheduler started (%s)", self.mode)

    def shutdown(self, timeout: float = 5.0) -> None:
        self.stop.set()
        for t in self._threads:
            t.join(timeout)


def status(s: Any) -> dict[str, Any]:
    """What /health reports: running, stuck (alive but a job has not finished for too long), stale, or never."""
    from datetime import UTC, datetime

    now = utcnow()
    stale_after = float(os.environ.get("SOC_SCHEDULER_STALE_SECONDS", str(HEARTBEAT_SECONDS * 6)))
    beats = [f.value or {} for f in s.execute(select(SystemFlag).where(SystemFlag.name.like(KEY_PREFIX + "%"))).scalars()]
    last_run = s.execute(select(func.max(JobRun.finished_at))).scalar()
    if last_run is not None and last_run.tzinfo is None:
        last_run = last_run.replace(tzinfo=UTC)

    def ts(v: Any) -> datetime | None:
        try:
            d = datetime.fromisoformat(v)
            return d if d.tzinfo else d.replace(tzinfo=UTC)
        except (TypeError, ValueError):
            return None

    live = sorted((b for b in beats if ts(b.get("at"))), key=lambda b: ts(b["at"]), reverse=True)
    out: dict[str, Any] = {"last_run": last_run.isoformat() if last_run else None}
    if not live:
        out["state"] = "never" if last_run is None else "stale"
        if last_run is not None:
            out["age_seconds"] = round((now - last_run).total_seconds())
        return out
    b = live[0]
    age = (now - ts(b["at"])).total_seconds()
    out.update({"mode": b.get("mode"), "heartbeat_age_seconds": round(age), "schedulers": sum(
        1 for x in live if (now - ts(x["at"])).total_seconds() <= stale_after)})
    loop_at = ts(b.get("loop_at"))
    if age > stale_after:
        out["state"] = "stale"
    elif loop_at is not None and (now - loop_at).total_seconds() > jobs.LEASE_SECONDS and b.get("job"):
        out["state"], out["stuck_job"] = "stuck", b.get("job")
    else:
        out["state"] = "running"
    return out


def run_forever(*, once: bool = False) -> None:
    """The standalone service (``python -m soc_platform scheduler``): same code, in the foreground."""
    sch = Scheduler(mode="service")
    if once:
        sch._beat()
        for r in sch.run_due():
            print(r, flush=True)
        return
    sch.start(start_delay=0)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        sch.shutdown()
