"""The scheduler: runs inside the server, decides what is due from the database, survives errors, restarts its own
threads, reports a heartbeat, and never runs a job twice however many schedulers are running."""

from __future__ import annotations

import threading
import time
from datetime import timedelta

import pytest

from soc_platform import jobs
from soc_platform import scheduler as sched
from soc_platform.core.db import Database
from soc_platform.core.models import JobRun, SystemFlag, utcnow


@pytest.fixture()
def db(tmp_path):
    d = Database(f"sqlite:///{tmp_path / 'sched.db'}")
    d.create_all()
    return d


@pytest.fixture()
def calls(monkeypatch):
    """Replace every job body with a recorder: these tests are about scheduling, not about the jobs themselves."""
    seen: list[str] = []
    lock = threading.Lock()

    def body(name, _s):
        with lock:
            seen.append(name)
        return {"ok": True}

    monkeypatch.setattr(jobs, "_body", body)
    return seen


def test_what_is_due_comes_from_the_database_not_memory(db, calls):
    assert set(sched.due_jobs(db)) == set(jobs.JOBS)                              # nothing has ever run
    sched.Scheduler(db).run_due()
    assert sorted(calls) == sorted(jobs.JOBS) and sched.due_jobs(db) == []
    # a new scheduler (a restart, or another server) sees the same history: nothing is re-run
    sched.Scheduler(db).run_due()
    assert len(calls) == len(jobs.JOBS)


def test_a_job_falls_due_again_after_its_interval(db, calls, monkeypatch):
    sched.Scheduler(db).run_due()
    env = jobs.JOBS["phishing"][0]
    monkeypatch.setenv("SOC_CLOCK_OFFSET_SECONDS", str(sched.interval("phishing") + 1))
    assert "phishing" in sched.due_jobs(db) and "vulnerability" not in sched.due_jobs(db)
    monkeypatch.setenv(env, "5")
    assert "phishing" in sched.due_jobs(db)


def test_two_schedulers_at_once_never_run_a_job_twice(db, calls):
    a, b = sched.Scheduler(db), sched.Scheduler(db)
    ta, tb = threading.Thread(target=a.run_due), threading.Thread(target=b.run_due)
    ta.start()
    tb.start()
    ta.join()
    tb.join()
    with db.session() as s:
        runs = s.query(JobRun).all()
    per_job = {n: sum(1 for r in runs if r.job == n and r.status == "ok") for n in jobs.JOBS}
    assert all(v == 1 for v in per_job.values()), per_job
    assert sorted(calls) == sorted(jobs.JOBS)


def test_health_states_running_stale_stuck_never(db, monkeypatch):
    with db.session() as s:
        assert sched.status(s)["state"] == "never"
    sc = sched.Scheduler(db)
    sc._beat()
    with db.session() as s:
        st = sched.status(s)
        assert st["state"] == "running" and st["mode"] == "embedded" and st["schedulers"] == 1
    sc._beat(loop=True, job="vulnerability")                                        # a job starts...
    monkeypatch.setenv("SOC_CLOCK_OFFSET_SECONDS", str(jobs.LEASE_SECONDS + 60))
    sc._beat()                                                                      # ...process alive, job not done
    with db.session() as s:
        st = sched.status(s)
        assert st["state"] == "stuck" and st["stuck_job"] == "vulnerability"
    monkeypatch.setenv("SOC_CLOCK_OFFSET_SECONDS", str(jobs.LEASE_SECONDS + 3600))  # no heartbeat for an hour
    with db.session() as s:
        assert sched.status(s)["state"] == "stale"


def test_an_error_in_a_pass_never_stops_the_schedule(db, calls, monkeypatch):
    real, failures = sched.due_jobs, []

    def flaky(d):
        if not failures:
            failures.append(1)
            raise RuntimeError("database briefly unavailable")
        return real(d)

    monkeypatch.setattr(sched, "due_jobs", flaky)
    sc = sched.Scheduler(db, tick=0.05, heartbeat=0.05)
    sc.start(start_delay=0)
    try:
        deadline = time.time() + 20
        while len(calls) < len(jobs.JOBS) and time.time() < deadline:
            time.sleep(0.05)
    finally:
        sc.shutdown()
    assert failures and sorted(calls) == sorted(jobs.JOBS)                          # recovered on the next tick


def test_a_dead_scheduler_thread_is_restarted(db, calls, monkeypatch):
    sc = sched.Scheduler(db, tick=0.05, heartbeat=0.05)
    real, starts = sc._job_loop, []

    def dies_first_time(delay):
        starts.append(1)
        if len(starts) == 1:
            return                                                                  # the thread ends unexpectedly
        real(0)

    monkeypatch.setattr(sc, "_job_loop", dies_first_time)
    sc.start(start_delay=0)
    try:
        deadline = time.time() + 20
        while len(calls) < len(jobs.JOBS) and time.time() < deadline:
            time.sleep(0.1)
    finally:
        sc.shutdown()
    assert len(starts) >= 2 and sorted(calls) == sorted(jobs.JOBS)


def test_a_failing_job_is_recorded_and_the_others_still_run(db, monkeypatch):
    ran = []

    def body(name, _s):
        ran.append(name)
        if name == "incident":
            raise RuntimeError("EDR API down")
        return {}

    monkeypatch.setattr(jobs, "_body", body)
    out = sched.Scheduler(db).run_due()
    assert set(ran) >= set(jobs.JOBS)
    assert next(r for r in out if r["job"] == "incident")["status"] == "error"
    assert all(r["status"] == "ok" for r in out if r["job"] != "incident")


def test_the_server_runs_the_scheduler_itself(tmp_path, monkeypatch, calls):
    """One process is the whole platform: starting the API starts the scheduler, stopping it stops the scheduler."""
    import os

    from fastapi.testclient import TestClient

    from soc_platform.api import app as appmod
    from soc_platform.config import get_settings
    from soc_platform.core import db as dbm

    env = {"SOC_EMBEDDED_SCHEDULER": "1", "SOC_SCHEDULER_START_DELAY": "0", "SOC_AUTH_MODE": "dev",
           "SOC_DEV_JWT_SECRET": "s" * 40, "SOC_DATABASE_URL": f"sqlite:///{tmp_path / 'embedded.db'}"}
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    saved = dbm._default
    get_settings.cache_clear()
    dbm._default = None
    try:
        with TestClient(appmod.app) as c:                                           # runs the server's lifespan
            deadline = time.time() + 30
            while len(calls) < len(jobs.JOBS) and time.time() < deadline:
                time.sleep(0.1)
            deadline = time.time() + 10
            while c.get("/health").json()["scheduler"]["state"] != "running" and time.time() < deadline:
                time.sleep(0.1)
            h = c.get("/health").json()["scheduler"]
            assert h["state"] == "running" and h["mode"] == "embedded"
            assert sorted(calls) == sorted(jobs.JOBS)
        live = [t for t in threading.enumerate() if t.name.startswith("soc-scheduler") and t.is_alive()]
        deadline = time.time() + 10
        while live and time.time() < deadline:
            time.sleep(0.1)
            live = [t for t in threading.enumerate() if t.name.startswith("soc-scheduler") and t.is_alive()]
        assert not live                                                             # stopped with the server
    finally:
        get_settings.cache_clear()
        dbm._default = saved
        os.environ.pop("SOC_SCHEDULER_START_DELAY", None)


def test_old_heartbeats_are_pruned(db):
    with db.session() as s:
        s.add(SystemFlag(name=sched.KEY_PREFIX + "gone", value={"at": (utcnow() - timedelta(days=3)).isoformat()},
                         updated_by="scheduler", updated_at=utcnow() - timedelta(days=3)))
    sched.Scheduler(db)._beat()
    with db.session() as s:
        names = [f.name for f in s.query(SystemFlag).filter(SystemFlag.name.like(sched.KEY_PREFIX + "%"))]
    assert names == [sched._key(jobs.HOLDER)]
