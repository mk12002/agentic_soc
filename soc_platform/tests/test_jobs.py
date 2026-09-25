"""Durable jobs (VM-T11): retries, run records, dead-lettering with an alert, recovery, and replica leases."""

from __future__ import annotations

from soc_platform import jobs
from soc_platform.core.db import Database
from soc_platform.core.models import JobRun, SystemFlag, utcnow
from soc_platform.intelligence.models import Insight


def _db():
    db = Database("sqlite://")
    db.create_all()
    return db


def test_transient_failure_is_retried_and_recorded():
    db, calls = _db(), []

    def flaky(name, s):
        calls.append(1)
        if len(calls) < 2:
            raise ConnectionError("tool unavailable")
        return {"synced": 5}

    run = jobs.run_job("incident", db=db, body=flaky, sleep=lambda _: None)
    assert run.status == "ok" and run.attempts == 2 and run.summary == {"synced": 5}


def test_repeated_failures_dead_letter_raise_insight_and_recover():
    db = _db()

    def broken(name, s):
        raise RuntimeError("401 from CrowdStrike: client secret expired")

    statuses = [jobs.run_job("incident", db=db, body=broken, sleep=lambda _: None).status for _ in range(3)]
    assert statuses == ["error", "error", "dead_letter"]
    with db.session() as s:
        ins = s.query(Insight).filter(Insight.rule == "job_dead_letter").one()
        assert "secret expired" in ins.evidence[0]["summary"] and "VM-T11" in ins.requirement_refs
        assert s.query(JobRun).count() == 3
    ok = jobs.run_job("incident", db=db, body=lambda n, s: {"ok": 1}, sleep=lambda _: None, trigger="manual:lead")
    assert ok.status == "ok" and ok.consecutive_failures == 0 and ok.trigger == "manual:lead"
    with db.session() as s:
        assert jobs.history(s, job="incident")[0]["status"] == "ok"


def test_lease_prevents_two_replicas_running_the_same_job():
    from datetime import timedelta

    db = _db()
    with db.session() as s:
        s.add(SystemFlag(name="job_lease:vulnerability", updated_by="scheduler",
                         value={"holder": "other-host:1", "until": (utcnow() + timedelta(minutes=5)).isoformat()}))
    assert jobs.run_job("vulnerability", db=db, body=lambda n, s: {}, sleep=lambda _: None) is None
    with db.session() as s:  # expired lease is taken over
        s.get(SystemFlag, "job_lease:vulnerability").value = {"holder": "other-host:1",
                                                              "until": (utcnow() - timedelta(minutes=1)).isoformat()}
    assert jobs.run_job("vulnerability", db=db, body=lambda n, s: {}, sleep=lambda _: None).status == "ok"


def test_every_scheduled_job_runs_end_to_end_on_fixtures(tmp_path, monkeypatch):
    """The real job bodies against the fixture estate: all succeed, and a second run is idempotent."""
    monkeypatch.setenv("SOC_REPORT_OUTPUT_DIR", str(tmp_path / "rep"))
    from soc_platform.config import get_settings
    from soc_platform.core import db as dbm

    get_settings.cache_clear()
    db = _db()
    monkeypatch.setattr(dbm, "_default", db)
    from soc_platform.api import app as appmod

    appmod.registry.cache_clear()
    first = {n: jobs.run_job(n, db=db, sleep=lambda _: None) for n in jobs.JOBS}
    assert {n: r.status for n, r in first.items()} == {n: "ok" for n in jobs.JOBS}, \
        {n: r.error for n, r in first.items() if r.status != "ok"}
    again = jobs.run_job("incident", db=db, sleep=lambda _: None)
    assert again.status == "ok" and again.summary["new_incidents"] == 0   # replay does not duplicate incidents
    get_settings.cache_clear()
