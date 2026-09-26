"""Time passing: SLAs fall due, the token budget rolls over, retention prunes, risk decays - and every surface still
agrees at every point in time. Runs on every sample estate; every day count is derived from the platform's own
settings. Uses the platform clock offset (SOC_CLOCK_OFFSET_SECONDS; ignored in prod)."""

from __future__ import annotations

import math
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from soc_platform.tests.conftest import ESTATES, estate_env


def _travel(monkeypatch, days: float) -> None:
    monkeypatch.setenv("SOC_CLOCK_OFFSET_SECONDS", str(days * 86400))


@pytest.fixture(params=ESTATES)
def estate(request, session, tmp_path, estate_configs):
    """One sample estate loaded the way the scheduler loads it, reported mail kept under a temporary folder."""
    from soc_platform.connectors.registry import ConnectorRegistry
    from soc_platform.domains.incident.service import IncidentService
    from soc_platform.domains.phishing.service import PhishingService
    from soc_platform.domains.vulnerability.service import VulnerabilityService
    from soc_platform.intelligence.analyst import IntelligenceService

    with estate_env(estate_configs[request.param]) as cfg:
        reg = ConnectorRegistry.all_fake()
        vm = VulnerabilityService(session, reg)
        vm.refresh()
        inc = IncidentService(session, reg)
        inc.ingest()
        for c in inc.cluster():
            inc.investigate(c.id)
        ph = PhishingService(session, reg, org_domains=[cfg["org"]], raw_dir=tmp_path / "raw")
        for sub in ph.ingest_reported():
            ph.process(sub.id)
        for f in cfg["uploads"]:
            sub = ph.submit_raw((Path(cfg["corpus_dir"]) / f).read_bytes(), source="upload", reporter=cfg["lead"])
            ph.process(sub.id)
        IntelligenceService(session, vm=vm).refresh()
        yield {"reg": reg, "vm": vm, "ph": ph, "cfg": cfg}


def _self_check_ok(session) -> None:
    from soc_platform.core.selfcheck import run_self_check

    sc = run_self_check(session)
    assert sc["ok"], [c for c in sc["checks"] if not c["ok"]]


def test_the_platform_clock_never_moves_in_prod(monkeypatch):
    from soc_platform.core.models import utcnow

    base = utcnow()
    _travel(monkeypatch, 30)
    assert (utcnow() - base).days >= 29
    monkeypatch.setenv("SOC_ENVIRONMENT", "prod")
    assert abs((utcnow() - base).total_seconds()) < 60


def test_slas_fall_due_and_every_surface_agrees_as_time_passes(session, estate, monkeypatch):
    from soc_platform.api.dashboards import overview
    from soc_platform.core.models import utcnow
    from soc_platform.domains.vulnerability.models import ConsolidatedFinding
    from soc_platform.intelligence.analyst import IntelligenceService

    vm = estate["vm"]
    open_f = session.query(ConsolidatedFinding).filter(ConsolidatedFinding.status.in_(("open", "reopened"))).all()
    dues = sorted({(f.sla_due - utcnow()).days for f in open_f})
    seen = []
    for days in (0, *dues, dues[-1] + 2):                                         # at, between and past every due date
        _travel(monkeypatch, max(days, 0))
        now = utcnow()
        expected = sum(1 for f in open_f if f.sla_due < now)
        m, ov = vm.metrics(), overview(session, frozenset({"*"}))
        brief = IntelligenceService(session, vm=vm).analyst.brief()["facts"]["vulnerability"]
        assert m["sla_breached"] == ov["vulnerability"]["sla_breached"] == brief["sla_breached"] == expected, days
        _self_check_ok(session)
        seen.append(expected)
    assert seen == sorted(seen) and seen[-1] == len(open_f)                        # monotonic, eventually all due


def test_token_budget_rolls_over_at_the_month_boundary(session, monkeypatch):
    from soc_platform.config import Settings
    from soc_platform.core.models import LLMCall, utcnow
    from soc_platform.core.selfcheck import llm_budget_alert
    from soc_platform.intelligence.models import Insight
    from soc_platform.llm.gateway import LLMGateway

    budget = Settings().llm_monthly_token_budget
    st = Settings(llm_provider="openai_compatible", llm_monthly_token_budget=budget)
    used = budget + 1                                                             # just over the cap
    session.add(LLMCall(workflow="t", provider="x", model="m", prompt_redacted="", response="", prompt_tokens=used // 2,
                        completion_tokens=used - used // 2, status="ok", grounded=True))
    session.flush()
    llm_budget_alert(session, st)
    assert session.query(Insight).filter(Insight.rule == "llm_budget").one().status == "new"
    now = utcnow()
    first_of_next = (now.replace(day=1) + timedelta(days=32)).replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    _travel(monkeypatch, (first_of_next - now).total_seconds() / 86400 + 1 / 24)   # an hour into next month
    assert LLMGateway(session, st).tokens_this_month() == 0
    llm_budget_alert(session, st)
    assert session.query(Insight).filter(Insight.rule == "llm_budget").one().status == "resolved"


def test_retention_prunes_old_mail_but_keeps_open_cases(session, estate, monkeypatch):
    from soc_platform.config import Settings
    from soc_platform.core.models import Case
    from soc_platform.core.retention import run_retention
    from soc_platform.domains.phishing.models import Submission

    keep = Settings().raw_retention_days
    subs = session.query(Submission).all()
    assert subs and all(s.raw_path and Path(s.raw_path).exists() for s in subs)
    _travel(monkeypatch, keep - 1)
    assert run_retention(session, Settings())["emails"] == 0                      # nothing is old enough yet
    _travel(monkeypatch, keep + 1)
    r = run_retention(session, Settings())
    closed = [s for s in subs if session.get(Case, s.case_id).status == "closed"]
    held = [s for s in subs if session.get(Case, s.case_id).status != "closed"]
    assert closed and held and r["emails"] == len(closed) and r["emails_on_hold"] == len(held)
    assert all(s.raw_path is None for s in closed) and all(s.raw_path and Path(s.raw_path).exists() for s in held)
    _self_check_ok(session)                                                       # figures still agree after pruning


NEGLIGIBLE = 0.05                                                                 # points


def test_activity_decays_by_half_every_half_life_but_open_exposure_does_not(session, estate):
    from soc_platform.intelligence.risk import HALF_LIFE_DAYS, RiskEngine
    from soc_platform.intelligence.risk import STANDING_SIGNALS as STANDING

    eng = RiskEngine(session)
    now = eng._now()
    checked = set()
    for top in eng.top(None, 10):
        p0 = eng.profile(top.entity_id)
        p1 = RiskEngine(session, as_of=now + timedelta(days=HALF_LIFE_DAYS)).profile(top.entity_id)
        # far enough that every activity factor has left the window and decayed below the threshold
        heaviest = max(f.weight for f in p0.factors)
        far_days = max(eng.window.days + 1, HALF_LIFE_DAYS * (math.log2(heaviest / NEGLIGIBLE) + 1))   # +1 half-life: stored to 2 dp
        latest = max([now, *(datetime.fromisoformat(f.when) for f in p0.factors if f.when)])
        far = RiskEngine(session, as_of=latest + timedelta(days=far_days)).profile(top.entity_id)
        for f0, f1 in zip(p0.factors, p1.factors, strict=True):
            assert f0.signal == f1.signal
            if f0.signal in STANDING:                                             # counts in full while open
                assert f0.decayed == f1.decayed == f0.weight, f0.signal
            elif f0.decayed:                                                      # activity and its amplifiers fade
                assert f1.decayed == pytest.approx(f0.decayed / 2, abs=0.02), f0.signal
            checked.add(f0.signal)
        # once activity has left the window, only what is still open (and nothing it amplified) remains
        assert {f.signal for f in far.factors if f.decayed >= NEGLIGIBLE} == {f.signal for f in p0.factors if f.signal in STANDING}, [(f.signal, f.weight, f.decayed, f.when) for f in far.factors] + [far_days, str(latest)]
        assert far.score <= p0.score
    assert checked & STANDING and checked - STANDING                                # both kinds were exercised
