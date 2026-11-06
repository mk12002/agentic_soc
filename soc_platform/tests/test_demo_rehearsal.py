"""Defects found by rehearsing the live demo as written: the documented reset + serve with the model on, every tab read
and every click made. Each of these passed every other test and would have been visible to an audience."""

from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path

import pytest

from soc_platform import jobs
from soc_platform.core.db import Database
from soc_platform.llm.gateway import Completion, Provider, _probe_error


def _ctx(session):
    from types import SimpleNamespace

    return SimpleNamespace(s=session)


class Writer(Provider):
    """Answers like a model, and on every call tries what a request or the heartbeat does meanwhile: take the write lock."""

    name = "fake"

    def __init__(self, path: Path) -> None:
        self.path, self.blocked, self.calls = path, 0, 0

    def complete(self, system, user, *, tier, max_tokens=None):
        self.calls += 1
        other = sqlite3.connect(self.path, timeout=0.2)
        try:
            other.execute("BEGIN IMMEDIATE")
            other.execute("ROLLBACK")
        except sqlite3.OperationalError:
            self.blocked += 1
        finally:
            other.close()
        return Completion(json.dumps({"summary": "Narrative.", "claims": []}), 10, 5, "fake-1")


@pytest.fixture()
def file_db(tmp_path, monkeypatch):
    if os.environ.get("SOC_TEST_POSTGRES"):
        pytest.skip("SQLite's single writer is what this guards")
    from soc_platform.api import app as appmod
    from soc_platform.config import get_settings
    from soc_platform.core import db as dbm

    monkeypatch.setenv("SOC_REPORT_OUTPUT_DIR", str(tmp_path / "rep"))
    monkeypatch.setenv("SOC_RAW_PAYLOAD_DIR", str(tmp_path / "raw"))
    get_settings.cache_clear()
    path = tmp_path / "soc.db"
    db = Database(f"sqlite:///{path.as_posix()}")
    db.create_all()
    monkeypatch.setattr(dbm, "_default", db)
    appmod.registry.cache_clear()
    yield db, path
    db.engine.dispose()
    get_settings.cache_clear()


def test_the_intelligence_job_holds_no_write_lock_while_the_model_writes(file_db, monkeypatch):
    """The job once kept a write transaction open across every narrative (64 s on the first run of a demo): the
    Intelligence screen answered 503 'database busy', the scheduler's heartbeat failed and the job lost its own lease."""
    from soc_platform.api import app as appmod
    from soc_platform.config import get_settings
    from soc_platform.llm.gateway import LLMGateway

    db, path = file_db
    monkeypatch.setenv("SOC_LLM_CONCURRENCY", "1")           # calls in turn: each must find the database free
    assert jobs.run_job("vulnerability", db=db, sleep=lambda _: None).status == "ok"
    assert jobs.run_job("incident", db=db, sleep=lambda _: None).status == "ok"
    model = Writer(path)
    monkeypatch.setattr(appmod, "llm", lambda s, p=None: LLMGateway(s, get_settings(), provider=model))
    run = jobs.run_job("intelligence", db=db, sleep=lambda _: None)
    assert run.status == "ok" and run.summary["insights"] > 0
    assert model.calls >= run.summary["insights"]            # every finding, then the brief
    assert model.blocked == 0, f"{model.blocked} of {model.calls} model calls ran with the database write-locked"


def test_a_failed_situation_brief_is_tried_again_soon(session, monkeypatch):
    """The platform's fallback text after one model timeout must not stay on screen for the whole cache period."""
    from soc_platform.intelligence import analyst as an

    class Clock:
        now = 1000.0

        def monotonic(self):
            return self.now

    clock, calls = Clock(), []

    class Gateway:
        def grounded(self, *a, **k):
            calls.append(1)
            return {"summary": "Fallback" if len(calls) == 1 else "Written by the model", "claims": [],
                    "source": "deterministic" if len(calls) == 1 else "llm"}

    an._BRIEF_CACHE.clear()
    monkeypatch.setattr("time.monotonic", clock.monotonic)
    intel = an.IntelligenceAnalyst(session, Gateway())
    assert intel.brief()["source"] == "deterministic"        # the model failed: the platform's own text
    assert intel.brief()["cached"] is True                   # not on every visit
    clock.now += 61
    assert intel.brief()["summary"] == "Written by the model"
    clock.now += 600
    assert intel.brief()["cached"] is True                   # a real answer stays for the cache period
    an._BRIEF_CACHE.clear()


def test_a_failing_model_gives_the_same_words_as_no_model(session, monkeypatch):
    """The network drops mid-demo: the brief and the analyst's answer once read "7 evidence item(s) from 7 source(s)..."
    (the gateway's generic fallback) instead of the platform's own text, which is what they say with the AI switched off."""
    from soc_platform.config import Settings
    from soc_platform.intelligence import analyst as an
    from soc_platform.llm.gateway import LLMGateway

    class Down(Provider):
        name = "down"

        def complete(self, system, user, *, tier, max_tokens=None):
            raise ConnectionError("endpoint unreachable")

    an._BRIEF_CACHE.clear()
    off = an.IntelligenceAnalyst(session, None)
    down = an.IntelligenceAnalyst(session, LLMGateway(session, Settings(llm_provider="fake"), provider=Down()))
    assert down.brief()["summary"] == off.brief()["summary"]
    assert "evidence item(s)" not in down.brief()["summary"]
    question = "Which hosts are most at risk?"
    assert down.ask(question)["answer"] == off.ask(question)["answer"]
    assert "evidence item(s)" not in down.ask(question)["answer"]
    an._BRIEF_CACHE.clear()


def test_an_incident_reads_as_its_result_without_the_model(file_db):
    from sqlalchemy import select

    from soc_platform.core.models import Case

    db, _ = file_db
    assert jobs.run_job("vulnerability", db=db, sleep=lambda _: None).status == "ok"
    assert jobs.run_job("incident", db=db, sleep=lambda _: None).status == "ok"
    with db.session() as s:
        cases = s.execute(select(Case).where(Case.domain == "incident")).scalars().all()
        assert cases
        for c in cases:
            assert c.summary.startswith(f"{c.title}: rated {c.severity} with {round(c.confidence * 100)} % confidence")
            assert "evidence item(s)" not in c.summary


def test_verdict_quality_in_a_report_says_there_is_no_measure_yet(session):
    """The quarterly control report once printed "insufficient_data; agreement None; PSI None"."""
    from soc_platform.reporting.builder import src_drift

    facts = dict(src_drift(_ctx(session))["facts"])
    assert facts and set(facts.values()) == {"not enough analyst decisions yet"}


def test_a_model_check_says_what_is_wrong_without_the_endpoint_address():
    import httpx

    url = "https://private-resource.example.net/openai/v1/chat/completions"

    def failed(status):
        req = httpx.Request("POST", url)
        return httpx.HTTPStatusError(f"Client error '{status}' for url '{url}'", request=req, response=httpx.Response(status, request=req))

    assert _probe_error(failed(404)) == "HTTP 404: this model is not deployed on the endpoint"
    assert "credentials" in _probe_error(failed(401))
    assert _probe_error(failed(500)) == "HTTP 500 from the endpoint"
    assert "private-resource" not in _probe_error(ConnectionError(f"cannot reach {url} now"))


def test_supplier_findings_read_as_words():
    from soc_platform.domains.phishing.supplier import _auth_words

    assert _auth_words({"spf": "pass", "dkim": "pass", "dmarc": "pass"}) == "SPF pass, DKIM pass, DMARC pass"
    assert _auth_words(None) == "no authentication results"


def test_one_exposure_row_per_host_and_cve_whatever_each_scanner_calls_the_host():
    from soc_platform.intelligence.story import _clip, _exposure_rows

    rows = _exposure_rows([
        {"title": "CVE-1 on HOST", "tool": "crowdstrike", "severity": "high", "entity": "host.example", "cve": "CVE-1"},
        {"title": "CVE-1 on mde-host", "tool": "defender_endpoint", "severity": "high", "entity": "host.example", "cve": "CVE-1"},
        {"title": "Public bucket", "tool": "wiz", "severity": "medium", "entity": "host.example", "cve": None}])
    assert [(r["title"], r["tool"]) for r in rows] == [("CVE-1 on host.example", "crowdstrike, defender_endpoint"),
                                                       ("Public bucket", "wiz")]
    assert _clip("short", 90) == "short"
    assert _clip("your password expires today", 19) == "your password…"      # never inside a word


def test_the_status_bar_is_refreshed_on_every_screen_change():
    """The approvals badge said 36 beside a tile saying 39: it was refreshed only at sign-in and after one's own action,
    so a second lead's approval, a job, or a stopped scheduler did not show until a reload."""
    app = (Path(__file__).parents[1] / "api" / "static" / "app.js").read_text(encoding="utf-8")
    body = app[app.index("async function render()"):app.index("const view = (window.VIEWS")]
    assert "refreshStatus();" in body


def test_the_console_shows_no_dead_automation_field_and_the_intelligence_screen_never_waits_for_the_brief():
    views = (Path(__file__).parents[1] / "api" / "static" / "views.js").read_text(encoding="utf-8")
    assert "automation mode" not in views                    # Case.autonomy_mode is always its default; nothing reads it
    body = views[views.index("async function Intelligence()"):views.index("async function askIntel()")]
    assert "Promise.all([api('/api/v1/intelligence/brief')" not in body
    assert body.index("setMainG(") < body.index("await briefing")
