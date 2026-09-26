"""AI report builder: standard reports, reports described in words, grounding, scope and encryption at rest."""

from __future__ import annotations

import io
import json
import zipfile

import pytest

from soc_platform.config import Settings
from soc_platform.connectors.registry import ConnectorRegistry
from soc_platform.core.models import Case
from soc_platform.llm.gateway import Completion, LLMGateway, Provider
from soc_platform.reporting import builder as B


@pytest.fixture()
def estate(session):
    from soc_platform.domains.incident.service import IncidentService
    from soc_platform.domains.phishing.service import PhishingService
    from soc_platform.domains.vulnerability.misconfig import MisconfigurationService
    from soc_platform.domains.vulnerability.service import VulnerabilityService
    from soc_platform.intelligence.analyst import IntelligenceService

    reg = ConnectorRegistry.all_fake()
    VulnerabilityService(session, reg).refresh()
    MisconfigurationService(session, reg).refresh()
    inc = IncidentService(session, reg)
    inc.ingest()
    for c in inc.cluster():
        inc.investigate(c.id)
    ph = PhishingService(session, reg, org_domains=["acme-demo.com"])
    for sub in ph.ingest_reported():
        ph.process(sub.id)
    IntelligenceService(session).refresh()
    return reg


def test_every_standard_report_builds_from_computed_figures(session, estate, tmp_path):
    case = session.query(Case).filter(Case.domain == "incident", Case.severity == "critical").first()
    for tid in B.STANDARD:
        spec = B.get_template(session, tid)
        r = B.build_report(session, estate, spec, tmp_path, llm=None, by="t", case_id=case.id)
        assert r["sections"] and not r["skipped"], (tid, r["skipped"])
        assert r["writer"] == "deterministic templates"
        for sec in r["sections"]:
            assert sec["narrative"].strip() and sec["facts"]
    files = list(tmp_path.iterdir())
    assert {f.suffix for f in files} == {".docx", ".pptx"} and len(files) == len(B.STANDARD)
    post = next(x for x in B.build_report(session, estate, B.get_template(session, "incident_postmortem"), tmp_path, llm=None,
                                          by="t", case_id=case.id)["sections"])
    assert post["narrative"].startswith("Confirmed compromise")                            # the case's attack story


class ReportLLM(Provider):
    """Writes each section citing real figures plus one invented figure (F99)."""

    name = "scripted"

    def __init__(self) -> None:
        self.prompts: list[str] = []

    def complete(self, system, user, *, tier):
        self.prompts.append(user)
        if "CATALOGUE" in user:
            return Completion(json.dumps({"title": "Board phishing brief", "audience": "board", "format": "pptx", "days": 90,
                                          "sections": [{"source": "phishing", "title": "Phishing", "instruction": "trend"},
                                                       {"source": "customer_database_dump", "title": "Exfil", "instruction": "x"},
                                                       {"source": "case_story", "title": "sneaky", "instruction": "x"},
                                                       {"source": "supplier_risk", "instruction": "vendors"}]}), 50, 50, "claude-test")
        return Completion(json.dumps({"summary": "s", "claims": [
            {"text": "Exposure is concentrated on a few assets.", "kind": "inference", "evidence_ids": ["F1"]},
            {"text": "Attackers stole 2 TB of data.", "kind": "fact", "evidence_ids": ["F99"]},        # invented -> dropped
            {"text": "Uncited opinion.", "kind": "inference", "evidence_ids": []}]}), 100, 60, "claude-test")


def test_llm_narrative_is_grounded_and_figures_never_come_from_the_model(session, estate, tmp_path):
    prov = ReportLLM()
    gw = LLMGateway(session, Settings(llm_redact_pii=True, org_domains=["acme-demo.com"]), provider=prov)
    r = B.build_report(session, estate, B.get_template(session, "ciso_weekly"), tmp_path, llm=gw, by="t")
    assert r["writer"].startswith("LLM (scripted)")
    for sec in r["sections"]:
        assert sec["writer"] == "llm"
        assert "2 TB" not in sec["narrative"] and "Uncited" not in sec["narrative"]
        assert sec["narrative"].endswith("[F1]")
    risk = next(s for s in r["sections"] if s["source"] == "risk")
    from soc_platform.intelligence.risk import RiskEngine
    top = RiskEngine(session).top(None, 1)[0]
    assert (top.name, f"risk {top.score}/100") in [(k, v.split(" (")[0]) for k, v in risk["facts"]]   # figures from code
    assert all("jane.doe@acme-demo.com" not in p for p in prov.prompts)                     # identities pseudonymised


def test_prompt_planner_only_uses_catalogue_sources(session):
    gw = LLMGateway(session, Settings(), provider=ReportLLM())
    sp = B.plan_report("board brief on phishing and suppliers", gw)
    assert sp["planner"] == "llm" and sp["format"] == "pptx" and sp["days"] == 90
    assert [x["source"] for x in sp["sections"]] == ["phishing", "supplier_risk"]           # invented + case-bound dropped
    rules = B.plan_report("A one-page board brief on phishing and supplier risk this quarter, as slides", None)
    assert rules["planner"] == "rules" and rules["format"] == "pptx" and rules["days"] == 90
    assert [x["source"] for x in rules["sections"]] == ["overview", "phishing", "supplier_risk"]
    assert [x["source"] for x in B.plan_report("weekly patching status for platform teams", None)["sections"]] == \
        ["vulnerability_posture", "top_vulnerabilities"]
    with pytest.raises(ValueError):
        B.validate_spec({"title": "x", "sections": [{"source": "rm -rf"}]})


def test_report_builder_over_http_scope_and_encryption(tmp_path, monkeypatch):
    from cryptography.fernet import Fernet

    monkeypatch.setenv("SOC_AUTH_MODE", "dev")
    monkeypatch.setenv("SOC_DEV_JWT_SECRET", "s" * 40)
    monkeypatch.setenv("SOC_ENVIRONMENT", "test")
    monkeypatch.setenv("SOC_DATABASE_URL", f"sqlite:///{tmp_path / 's.db'}")
    monkeypatch.setenv("SOC_REPORT_OUTPUT_DIR", str(tmp_path / "rep"))
    monkeypatch.setenv("SOC_RAW_PAYLOAD_DIR", str(tmp_path / "raw"))
    monkeypatch.setenv("SOC_ORG_DOMAINS", "acme-demo.com")
    monkeypatch.setenv("SOC_DATA_KEY", Fernet.generate_key().decode())
    from soc_platform.config import get_settings
    from soc_platform.core import db as dbm
    from soc_platform.domains.vulnerability.models import ReportRun

    get_settings.cache_clear()
    dbm._default = None
    from fastapi.testclient import TestClient

    from soc_platform.api import app as appmod

    appmod.registry.cache_clear()
    try:
        c = TestClient(appmod.app)
        H = lambda u, r, d="*": {"Authorization": "Bearer " + c.get(f"/api/v1/dev/token?user={u}&roles={r}&domains={d}").json()["token"]}
        lead, vm_analyst, ph_analyst = H("lena", "lead"), H("vic", "analyst", "vulnerability"), H("pia", "analyst", "phishing")
        c.post("/api/v1/incidents/run", headers=lead)
        c.post("/api/v1/phishing/ingest", headers=lead)
        c.post("/api/v1/vm/refresh", headers=lead)
        tp = c.get("/api/v1/reports/templates", headers=lead).json()
        assert {t["id"] for t in tp["templates"]} >= set(B.STANDARD) and len(tp["sources"]) == len(B.SOURCES)

        sp = c.post("/api/v1/reports/plan", headers=lead, json={"request": "weekly vulnerability status for platform teams"}).json()
        saved = c.post("/api/v1/reports/templates", headers=lead, json={"spec": sp}).json()
        assert any(t["id"] == saved["id"] and not t["standard"] for t in c.get("/api/v1/reports/templates", headers=lead).json()["templates"])
        r = c.post("/api/v1/reports/build", headers=lead, json={"template_id": saved["id"]}).json()
        run_path = get_settings().report_output_dir
        blob = next(p for p in __import__("pathlib").Path(run_path).iterdir()).read_bytes()
        assert blob.startswith(b"SOCENC1:")                                                # encrypted at rest
        doc = c.get(f"/api/v1/reports/{r['id']}/download", headers=lead).content
        assert zipfile.is_zipfile(io.BytesIO(doc))                                         # decrypted on download

        # a vulnerability-only analyst gets the VM sections of a board report, never cross-domain ones
        b = c.post("/api/v1/reports/build", headers=vm_analyst, json={"template_id": "board_monthly"}).json()
        assert [x["source"] for x in b["sections"]] == ["overview", "vulnerability_posture"]
        assert {x["source"] for x in b["skipped"]} >= {"attack_stories", "phishing", "compliance"}
        ov = dict(b["sections"][0]["facts"])
        assert "phishing" not in ov["Open cases by domain"] and "incident" not in ov["Open cases by domain"]  # scoped counts
        assert c.get(f"/api/v1/reports/{b['id']}/download", headers=vm_analyst).status_code == 200
        assert c.get(f"/api/v1/reports/{b['id']}/download", headers=ph_analyst).status_code == 404
        assert c.get(f"/api/v1/reports/{r['id']}/download", headers=ph_analyst).status_code == 404

        # case-bound report needs a case the caller can see
        assert c.post("/api/v1/reports/build", headers=lead, json={"template_id": "incident_postmortem"}).status_code == 422
        inc = next(x["id"] for x in c.get("/api/v1/cases?domain=incident", headers=lead).json())
        assert c.post("/api/v1/reports/build", headers=ph_analyst, json={"template_id": "incident_postmortem", "case_id": inc}).status_code in (403, 404)
        pm = c.post("/api/v1/reports/build", headers=lead, json={"template_id": "incident_postmortem", "case_id": inc}).json()
        assert pm["sections"][0]["source"] == "case_story"
        assert c.post("/api/v1/reports/build", headers=lead, json={"spec": {"sections": [{"source": "nope"}]}}).status_code == 422
        with dbm.get_database().session() as s:
            assert s.query(ReportRun).filter(ReportRun.kind.like("custom:%")).count() == 3
    finally:
        get_settings.cache_clear()
        dbm._default = None
