"""Reported / phishing email handling, end to end (PH-F01..F16) on fixtures + a labelled corpus."""

from __future__ import annotations

import copy
import json
import subprocess
import sys
from pathlib import Path

import pytest

from soc_platform.connectors.registry import ConnectorRegistry
from soc_platform.core.actions import ActionService
from soc_platform.core.audit import AuditLog
from soc_platform.core.policy import DEFAULT_POLICY, PolicyEngine
from soc_platform.domains.phishing.agents.decompose import decompose
from soc_platform.domains.phishing.models import Submission
from soc_platform.domains.phishing.service import AutoClosePolicy, PhishingService

ROOT = Path(__file__).resolve().parents[2]
CORPUS = ROOT / "artifacts" / "phishing" / "corpus"


@pytest.fixture(scope="session")
def corpus() -> Path:
    if not (CORPUS / "labels.json").exists():
        subprocess.run([sys.executable, str(ROOT / "scripts" / "build_email_corpus.py"), str(CORPUS)], check=True)
    return CORPUS


@pytest.fixture()
def ph(session, tmp_path):
    pol = copy.deepcopy(DEFAULT_POLICY)
    pol["vip"]["identities"] = ["raj.mehta@acme-demo.com"]
    return PhishingService(session, ConnectorRegistry.all_fake(), policy=PolicyEngine(pol), org_domains=["acme-demo.com"],
                           raw_dir=tmp_path, auto_close=AutoClosePolicy(sample_rate=0.0))


def test_reported_message_ingested_with_original_headers(session, ph):
    subs = ph.ingest_reported()
    assert len(subs) == 1 and subs[0].reporter == "bob.lee@acme-demo.com"
    raw = Path(subs[0].raw_path).read_bytes()
    assert b"Authentication-Results" in raw and b"Received: from mail.micros0ft-helpdesk.com" in raw
    assert ph.ingest_reported() == []                                            # replay returns nothing new
    from soc_platform.domains.phishing.models import Submission
    assert session.query(Submission).count() == 1                                  # ... and duplicates nothing
    first = ph.process(subs[0].id)
    assert ph.process(subs[0].id)["case"]["id"] == first["case"]["id"]              # re-processing: same case
    assert ph.process(subs[0].id, force=True)["case"]["id"] != first["case"]["id"]  # explicit re-analysis only


def test_full_investigation_of_reported_campaign(session, ph):
    sub = ph.ingest_reported()[0]
    v = ph.process(sub.id)
    a = v["assessment"]
    assert v["case"]["verdict"] == "malicious" and v["case"]["severity"] == "critical"
    # PH-F04 both gateways passed it
    assert a["reconciliation"]["disagreements"][0]["type"] == "missed_by_controls"
    # PH-F05 tenant-wide scope incl. the Re: variant, unrelated newsletter rejected
    assert len(a["campaign"]["recipients"]) == 8 and a["campaign"]["rejected_candidates"] == 1
    assert len(a["campaign"]["variants"]) == 2
    # PH-F06/07/08
    ui = a["user_impact"]
    assert ui["clicked"] == ["jane.doe@acme-demo.com"] and "priya.nair@acme-demo.com" not in ui["clicked"]
    assert ui["identity_compromise"] == ["jane.doe@acme-demo.com"] and ui["endpoint_impact"] == ["jane.doe@acme-demo.com"]
    assert v["completeness"]["complete"]
    assert {m["technique"] for m in a["mitre"]} >= {"T1566.002", "T1078"}


def test_remediation_recommendations_are_gated_and_vip_aware(session, ph, lead, analyst):
    v = ph.process(ph.ingest_reported()[0].id)
    acts = {x["action_type"]: x for x in v["actions"]}
    purge = acts["email.campaign_purge"]
    assert purge["status"] == "recommended" and len(purge["targets"]) == 9
    assert any(t["vip"] for t in purge["targets"])  # CEO mailbox in scope -> high-impact approval
    assert any("VIP" in r for r in purge["policy_reasons"])
    with pytest.raises(PermissionError):
        ActionService(session, ph.actions, ph.policy).approve(purge["id"], analyst)
    done = ActionService(session, ph.actions, ph.policy).approve(purge["id"], lead)
    assert done.status == "executed" and done.result["messages"] == 9
    assert acts["identity.revoke_sessions"]["targets"][0]["upn"] == "jane.doe@acme-demo.com"
    assert acts["endpoint.isolate"]["targets"][0]["mde_device_id"] == "mde-jane01"
    assert acts["dns.block_domain"]["targets"][0]["value"] == "login.micros0ft-helpdesk.com"
    fb = acts["email.reporter_feedback"]
    assert fb["targets"][0]["upn"] == "bob.lee@acme-demo.com"


def test_confirmation_propagates_indicators_to_shared_store(session, ph, analyst):
    v = ph.process(ph.ingest_reported()[0].id)
    out = ph.confirm(v["case"]["id"], analyst, verdict="malicious", reasoning="credential phish, 1 compromise")
    assert "domain:login.micros0ft-helpdesk.com" in out["propagated_indicators"]
    assert any(i["indicator"] == "email:it-support@micros0ft-helpdesk.com" for i in ph.confirmed_indicators())
    assert session.query(Submission).one().status == "closed"


def test_corpus_verdicts(session, ph, corpus):
    labels = json.loads((corpus / "labels.json").read_text())
    wrong = []
    for name, label in labels.items():
        sub = ph.submit_raw((corpus / f"{name}.eml").read_bytes(), source="upload", reporter="jane.doe@acme-demo.com")
        v = ph.process(sub.id)
        if v["case"]["verdict"] != label:
            wrong.append((name, label, v["case"]["verdict"]))
    assert not wrong, wrong


def test_qr_code_is_decoded_and_bec_detected(corpus):
    em = decompose((corpus / "quishing_qr.eml").read_bytes())
    assert em.qr_urls == ["https://benefits-portal.payroll-update.support/sso?u=jane"]
    bec = decompose((corpus / "bec_ceo_fraud.eml").read_bytes())
    assert bec.reply_to == "raj.mehta.ceo@proton.example" and bec.origin_ip == "102.165.48.90"


def test_auto_close_with_sampling(session, tmp_path, corpus, analyst):
    ph = PhishingService(session, ConnectorRegistry.all_fake(), org_domains=["acme-demo.com"], raw_dir=tmp_path,
                         auto_close=AutoClosePolicy(sample_rate=1.0))
    sub = ph.submit_raw((corpus / "legit_github.eml").read_bytes(), source="upload", reporter="jane.doe@acme-demo.com")
    v = ph.process(sub.id)
    assert sub.auto_closed and sub.sampled_for_review and v["case"]["status"] == "awaiting_qa"
    ph2 = PhishingService(session, ConnectorRegistry.all_fake(), org_domains=["acme-demo.com"], raw_dir=tmp_path,
                          auto_close=AutoClosePolicy(sample_rate=0.0))
    s2 = ph2.submit_raw((corpus / "marketing_spam.eml").read_bytes(), source="upload", reporter="li.chen@acme-demo.com")
    v2 = ph2.process(s2.id)
    assert s2.auto_closed and v2["case"]["status"] == "closed"
    assert any(a["action_type"] == "email.reporter_feedback" for a in v2["actions"])
    mal = ph2.submit_raw((corpus / "bec_ceo_fraud.eml").read_bytes(), source="upload", reporter="priya.nair@acme-demo.com")
    ph2.process(mal.id)
    assert not mal.auto_closed and mal.status == "escalated"


def test_metrics_and_audit(session, ph, analyst, lead):
    v = ph.process(ph.ingest_reported()[0].id)
    purge = next(a for a in v["actions"] if a["action_type"] == "email.campaign_purge")
    ActionService(session, ph.actions, ph.policy).approve(purge["id"], lead)
    m = ph.metrics()
    assert m["reported"] == 1 and m["verdict_mix"] == {"malicious": 1} and m["clickers"] == {"jane.doe@acme-demo.com": 1}
    assert m["time_to_containment_minutes"]["samples"] == 1
    events = {r.event_type for r in AuditLog(session).query(limit=1000)}
    assert {"phishing.reported", "case.created", "case.assessed", "action.requested", "action.executed"} <= events
    assert AuditLog(session).verify()["ok"]


def test_supplier_email_risk_u18(session):
    """A real supplier asking to change bank details and a look-alike of that supplier are both surfaced."""
    from pathlib import Path

    from soc_platform.connectors.registry import ConnectorRegistry
    from soc_platform.domains.phishing.service import PhishingService
    from soc_platform.domains.phishing.supplier import SupplierMonitor, load_suppliers
    from soc_platform.intelligence.correlation import CorrelationEngine

    corpus = Path(__file__).resolve().parents[2] / "artifacts" / "phishing" / "corpus"
    svc = PhishingService(session, ConnectorRegistry.all_fake(), org_domains=["acme-demo.com"])
    for name in ("supplier_bank_change", "supplier_lookalike_payment", "legit_vendor_invoice"):
        sub = svc.submit_raw((corpus / f"{name}.eml").read_bytes(), source="test", reporter="arun.k@acme-demo.com")
        svc.process(sub.id)
    rep = SupplierMonitor(session, load_suppliers()).assess()
    kl = rep["suppliers"]["Krishna Logistics"]
    kinds = {f["type"] for f in kl["findings"]}
    assert {"supplier_payment_diversion", "supplier_impersonation"} <= kinds, kl
    assert kl["status"] == "critical"                     # high-criticality supplier escalates
    ms = rep["suppliers"]["Microsoft (cloud provider)"]
    assert ms["findings"] == [] and ms["status"] == "ok"  # authentic, clean vendor mail raises nothing
    ins = [i for i in CorrelationEngine(session).run() if i.rule == "supplier_risk"]
    assert ins and all("U18" in i.requirement_refs for i in ins)


def test_auto_closed_reports_do_not_spend_llm_tokens(session, ph, monkeypatch):
    """Cost at volume: clear-benign / clear-spam reports that auto-close get the deterministic, cited explanation."""
    import json as _json

    from soc_platform.config import Settings
    from soc_platform.llm.gateway import Completion, LLMGateway, Provider

    class Counting(Provider):
        name = "scripted"

        def __init__(self):
            self.workflows = []

        def complete(self, system, user, *, tier):
            import re as _re
            self.workflows.append(tier)
            ids = _re.findall(r"^\[([A-Z]\d+)\]", user, _re.M) or ["E1"]
            return Completion(_json.dumps({"summary": "s", "claims": [{"text": "x", "kind": "fact", "evidence_ids": ids[:1]}]}), 5, 5, "m")

    prov = Counting()
    ph.llm = LLMGateway(session, Settings(), provider=prov)
    benign = ph.submit_raw((ROOT / "artifacts/phishing/corpus/legit_vendor_invoice.eml").read_bytes(), source="test")
    v = ph.process(benign.id)
    assert v["case"]["verdict"] == "safe" and prov.workflows == []                    # no model call, still cited
    bad = ph.submit_raw((ROOT / "artifacts/phishing/corpus/bec_ceo_fraud.eml").read_bytes(), source="test")
    ph.process(bad.id)
    assert prov.workflows == ["small"]                                                # routine narrative -> small tier
    monkeypatch.setenv("SOC_LLM_EXPLAIN_AUTO_CLOSED", "1")
    again = ph.submit_raw((ROOT / "artifacts/phishing/corpus/marketing_spam.eml").read_bytes(), source="test")
    ph.process(again.id)
    assert len(prov.workflows) == 2                                                   # opt back in
