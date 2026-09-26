"""Attack Story + deep analysis: correctness, no invented evidence, guardrails on the LLM review."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from soc_platform.config import Settings
from soc_platform.connectors.registry import ConnectorRegistry
from soc_platform.core.models import Case, Entity
from soc_platform.intelligence.story import story_for_case
from soc_platform.llm.gateway import Completion, LLMGateway, Provider
from soc_platform.tests.conftest import ESTATES, estate_env

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture()
def estate(session):
    from soc_platform.domains.incident.service import IncidentService
    from soc_platform.domains.phishing.service import PhishingService
    from soc_platform.domains.vulnerability.service import VulnerabilityService

    reg = ConnectorRegistry.all_fake()
    VulnerabilityService(session, reg).refresh()
    inc = IncidentService(session, reg)
    inc.ingest()
    for c in inc.cluster():
        inc.investigate(c.id)
    ph = PhishingService(session, reg, org_domains=["acme-demo.com"])
    for sub in ph.ingest_reported():
        ph.process(sub.id)
    return reg, ph


def _case(session, domain, **kw):
    q = session.query(Case).filter(Case.domain == domain)
    for k, v in kw.items():
        q = q.filter(getattr(Case, k) == v)
    return q.first()


def test_story_reconstructs_the_cross_tool_chain(session, estate):
    reg, _ = estate
    st = story_for_case(session, _case(session, "phishing").id, reg)
    stages = [s["stage_name"] for s in st["steps"]]
    for must in ("Initial Access", "Execution", "Credential Access", "Lateral Movement"):
        assert must in stages, stages
    timed = [s["start"] for s in st["steps"] if s["start"]]
    assert timed == sorted(timed)                                                        # chronological
    assert st["assessment"]["verdict"] == "confirmed_compromise"
    assert len(st["tools"]) >= 5 and st["blast_radius"]["stats"]["users_received"] == 8
    assert st["blast_radius"]["stats"]["users_interacted"] == 1 and st["blast_radius"]["secrets"] == ["SAP-Prod-Finance-Service"]
    blocked = [s for s in st["steps"] if s["outcome"] == "blocked"]
    assert blocked and blocked[0]["stage_name"] == "Privilege Escalation"               # elevation denied is shown as blocked
    exfil = next(g for g in st["gaps"] if g["stage_name"] == "Exfiltration")
    assert exfil["status"] == "no_evidence" and exfil["checked_tools"]
    hyp = {h["hypothesis"]: h["status"] for h in st["hypotheses"]}
    assert hyp["The risky sign-in was the user travelling or on a corporate VPN"] == "rejected"
    assert hyp["The script execution was legitimate IT / admin activity"] == "rejected"
    phases = [p["phase"] for p in st["response_plan"]]
    assert phases[:2] == ["contain", "preserve"] and "recover" in phases
    assert "Confirmed compromise of jane.doe@acme-demo.com" in st["summary"]


def test_story_never_invents_evidence(session, estate):
    reg, _ = estate
    st = story_for_case(session, _case(session, "incident", severity="critical").id, reg)
    refs = {e["ref"] for e in st["events"]}
    for s in st["steps"]:
        assert set(s["evidence"]) <= refs
    for e in st["events"]:
        src = e["source"]
        if src.startswith("case:"):
            assert session.get(Case, src[5:]) is not None
        else:
            assert session.get(Entity, src) is not None                                  # every step is a stored record
    for h in st["hypotheses"]:
        assert set(h["evidence"]) <= refs
    # the incident case and the phishing case about the same person tell the same story
    assert st["fingerprint"] == story_for_case(session, _case(session, "phishing").id, reg)["fingerprint"]


def test_clean_email_produces_no_attack_story(session, estate):
    reg, ph = estate
    sub = ph.submit_raw((ROOT / "artifacts/phishing/corpus/legit_vendor_invoice.eml").read_bytes(), source="test")
    ph.process(sub.id)
    st = story_for_case(session, sub.case_id, reg)
    assert st["steps"] == [] and st["assessment"]["verdict"] == "no_attack_activity"


def _step(stage, outcome="succeeded", tools=("crowdstrike",)):
    return {"stage": stage, "outcome": outcome, "tools": list(tools)}


@pytest.mark.parametrize("steps,hyps,verdict,conf", [
    ([], [], "no_attack_activity", "medium"),
    ([_step("TA0001", "blocked"), _step("TA0011", "blocked", ("umbrella",))], [], "attempt_blocked", "high"),
    ([_step("TA0001")], [], "suspicious_activity", "low"),
    ([_step("TA0001"), _step("TA0002")], [], "likely_compromise", "high"),
    ([_step("TA0001"), _step("TA0006")], [{"status": "plausible"}], "likely_compromise", "medium"),
    ([_step("TA0001", tools=("o365",)), _step("TA0002"), _step("TA0006", tools=("entra",))], [], "confirmed_compromise", "high"),
    ([_step("TA0001", tools=("o365",)), _step("TA0002"), _step("TA0006", tools=("entra",))], [{"status": "plausible"}],
     "likely_compromise", "medium"),                                                     # an open benign explanation caps it
    ([_step("TA0001"), _step("TA0004", "blocked")], [], "suspicious_activity", "low"),     # a blocked step is not progress
])
def test_every_verdict_follows_from_the_steps(steps, hyps, verdict, conf):
    from soc_platform.intelligence.story import AttackStory

    a = AttackStory._assess(steps, hyps)
    assert (a["verdict"], a["confidence"]) == (verdict, conf), a
    if verdict == "attempt_blocked":
        assert "blocked" in a["reason"]
    assert ("blocked" in a["reason"]) == any(x["outcome"] == "blocked" for x in steps) or verdict == "confirmed_compromise"


@pytest.mark.parametrize("name", ESTATES)
def test_every_incident_tells_a_self_consistent_story(session, name, estate_configs):
    """Not only the phishing chain: host-centric incidents with no email in them obey the same rules, on every estate."""
    from soc_platform.domains.incident.service import IncidentService

    with estate_env(estate_configs[name]):
        reg = ConnectorRegistry.all_fake()
        inc = IncidentService(session, reg)
        inc.ingest()
        for c in inc.cluster():
            inc.investigate(c.id)
        _check_incident_stories(session, reg)


def _check_incident_stories(session, reg):
    incidents = session.query(Case).filter(Case.domain == "incident").all()
    assert len(incidents) >= 2
    for case in incidents:
        st = story_for_case(session, case.id, reg)
        refs = {e["ref"] for e in st["events"]}
        assert all(set(x["evidence"]) <= refs for x in st["steps"]), case.title
        timed = [x["start"] for x in st["steps"] if x["start"]]
        assert timed == sorted(timed), case.title
        reached = {x["stage"] for x in st["steps"] if x["outcome"] != "blocked"}
        a = st["assessment"]
        if st["steps"] and reached:
            assert a["reason"].startswith(f"{len(reached)} kill-chain stage(s) reached") or a["verdict"] == "suspicious_activity", case.title
        elif st["steps"]:
            assert a["verdict"] == "attempt_blocked", case.title
        assert sorted(st["tools"]) == sorted({t for x in st["steps"] for t in x["tools"]}), case.title
        pending = sum(1 + len(x.get("duplicate_ids", [])) for ph_ in st["response_plan"] for x in ph_["actions"] if x["approvable"])
        if st["steps"] and pending:
            assert f"({pending} action(s) awaiting approval)" in st["summary"], case.title
        assert st["fingerprint"] == story_for_case(session, case.id, reg)["fingerprint"], case.title   # reproducible


class ReviewLLM(Provider):
    """Returns a review mixing valid citations, invented ids, a fake action and a bad status."""

    name = "scripted"

    def __init__(self) -> None:
        self.prompts: list[str] = []

    def complete(self, system, user, *, tier):
        self.prompts.append(user)
        return Completion(json.dumps({
            "assessment": "The user was phished and the attacker reached privileged credentials.",
            "confidence": "high",
            "attacker_objective": {"text": "Access to finance systems", "evidence_ids": ["S13"]},
            "key_findings": [{"text": "PowerShell pulled a payload from the phishing domain", "kind": "fact", "evidence_ids": ["S5"]},
                             {"text": "Attacker exfiltrated 40 GB", "kind": "fact", "evidence_ids": ["S999"]},          # invented
                             {"text": "Uncited opinion", "kind": "inference", "evidence_ids": []}],
            "alternative_explanations": [{"hypothesis": "Travel", "status": "rejected", "reasoning": "anonymiser", "evidence_ids": ["H2"]},
                                         {"hypothesis": "Maybe fine", "status": "totally_fine", "reasoning": "x", "evidence_ids": ["H1"]}],
            "open_questions": [{"question": "Was the SAP secret used after 09:45?", "why": "no telemetry", "evidence_ids": ["G1"]}],
            "priorities": [{"action_ref": "P1", "text": "Contain the laptop first", "why": "active payload", "evidence_ids": ["S5"]},
                           {"action_ref": "P404", "text": "Wipe the domain controller", "why": "?", "evidence_ids": ["S5"]},  # not a real action
                           {"action_ref": "manual", "text": "Call the SAP owner", "why": "secret copied", "evidence_ids": ["S14"]}]}),
            200, 120, "claude-test")


def test_deep_analysis_is_bound_to_evidence(session, estate):
    from soc_platform.intelligence.deep_analysis import run_deep_analysis

    reg, _ = estate
    case = _case(session, "phishing")
    st = story_for_case(session, case.id, reg)
    prov = ReviewLLM()
    gw = LLMGateway(session, Settings(llm_redact_pii=True, org_domains=["acme-demo.com"]), provider=prov)
    r = run_deep_analysis(session, st, gw, actor="lena", org_domains=["acme-demo.com"])
    assert r["ok"] and r["confidence"] == "high"
    assert [f["text"] for f in r["key_findings"]] == ["PowerShell pulled a payload from the phishing domain"]
    assert [h["hypothesis"] for h in r["alternative_explanations"]] == ["Travel"]
    assert {p["action_ref"] for p in r["priorities"]} == {"P1", "manual"}                 # fake action dropped
    assert r["priorities"][0]["action_id"]                                                # P1 maps to a real pending action
    assert r["dropped_statements"] == 4
    assert "jane.doe@acme-demo.com" not in prov.prompts[-1]                               # identities pseudonymised
    again = run_deep_analysis(session, st, gw, actor="lena")
    assert again["cached"] and len(prov.prompts) == 1                                     # cached per evidence fingerprint
    assert (session.get(Case, case.id).assessment or {})["deep_analysis"]["model"] == "claude-test"
    assert run_deep_analysis(session, st, None, actor="x")["available"] is False           # no LLM configured


def test_deep_analysis_respects_the_token_budget(session, estate):
    from soc_platform.intelligence.deep_analysis import run_deep_analysis

    reg, _ = estate
    st = story_for_case(session, _case(session, "phishing").id, reg)
    gw = LLMGateway(session, Settings(llm_monthly_token_budget=1), provider=ReviewLLM())
    run_deep_analysis(session, st, gw, actor="x", force=True)                              # uses the budget
    r = run_deep_analysis(session, {**st, "fingerprint": "changed"}, gw, actor="x", force=True)
    assert r["ok"] is False and "budget" in r["reason"].lower()


def test_analyst_tells_the_story(session, estate):
    from soc_platform.intelligence.analyst import IntelligenceService

    r = IntelligenceService(session).analyst.ask("What happened to jane.doe@acme-demo.com?")
    assert "attack_story" in [c["tool"] for c in r["tool_calls"]]
    assert r["answer"].startswith("Confirmed compromise of jane.doe@acme-demo.com")
    assert any("Credential Access" in c["text"] for c in r["claims"])


def test_story_over_http_bundle_approval_keeps_governance(tmp_path, monkeypatch):
    import os

    monkeypatch.setenv("SOC_AUTH_MODE", "dev")
    monkeypatch.setenv("SOC_DEV_JWT_SECRET", "s" * 40)
    monkeypatch.setenv("SOC_ENVIRONMENT", "test")
    monkeypatch.setenv("SOC_DATABASE_URL", f"sqlite:///{tmp_path / 's.db'}")
    monkeypatch.setenv("SOC_REPORT_OUTPUT_DIR", str(tmp_path / "rep"))
    monkeypatch.setenv("SOC_RAW_PAYLOAD_DIR", str(tmp_path / "raw"))
    monkeypatch.setenv("SOC_ORG_DOMAINS", "acme-demo.com")
    from soc_platform.config import get_settings
    from soc_platform.core import db as dbm

    get_settings.cache_clear()
    dbm._default = None
    from fastapi.testclient import TestClient

    from soc_platform.api import app as appmod

    appmod.registry.cache_clear()
    c = TestClient(appmod.app)
    H = lambda u, r: {"Authorization": "Bearer " + c.get(f"/api/v1/dev/token?user={u}&roles={r}").json()["token"]}
    lead, analyst = H("lena", "lead"), H("alice", "analyst")
    c.post("/api/v1/incidents/run", headers=lead)
    c.post("/api/v1/phishing/ingest", headers=lead)
    cid = next(x["id"] for x in c.get("/api/v1/cases?domain=phishing", headers=lead).json())
    st = c.get(f"/api/v1/cases/{cid}/story", headers=lead).json()
    assert st["steps"] and st["deep_analysis"] is None
    assert c.post(f"/api/v1/cases/{cid}/deep-analysis", headers=lead, json={}).json()["available"] is False
    contain = [a for a in st["response_plan"][0]["actions"] if a["approvable"]]
    four_eyes = next(a for a in contain if a["four_eyes"])
    r = c.post(f"/api/v1/cases/{cid}/story/approve", headers=analyst, json={"action_ids": [four_eyes["id"]]}).json()
    assert r["approved"] == 0 and not r["results"][0]["ok"]                               # analyst cannot pass four-eyes
    r = c.post(f"/api/v1/cases/{cid}/story/approve", headers=lead,
               json={"action_ids": [a["id"] for a in contain] + ["not-a-story-action"]}).json()
    assert r["approved"] == len(contain) and r["results"][-1]["error"] == "not a pending action of this story"
    os.environ.pop("SOC_ORG_DOMAINS", None)
    get_settings.cache_clear()
    dbm._default = None
