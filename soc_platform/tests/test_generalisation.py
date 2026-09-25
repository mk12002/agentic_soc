"""Nothing is hardcoded to the demo: the whole platform run on a renamed organisation gives the same results.

The sample estate is rewritten into "Northwind Labs" (different domain, people, hosts, IPs, phishing infrastructure,
secrets, suppliers) by scripts/rename_estate.py. Every workflow runs on both estates and must produce structurally
identical results, and no output about the renamed estate may mention an original name.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("rename_estate", ROOT / "scripts" / "rename_estate.py")
rename = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rename)

ORIGINAL_TOKENS = ["jane", "cci-demo", "micros0ft", "krishna", "sap-prod", "185.220.101.4", "web01"]


def _registry(rx=None, table=None, domain="cci-demo.com"):
    from soc_platform.connectors.registry import ConnectorRegistry, discover

    manifests = discover()
    cfg = {}
    for n, m in manifests.items():
        settings = {k: (rename.rename_text(v, rx, table) if isinstance(v, str) and rx else v) for k, v in m.fake_settings.items()}
        cfg[n] = {"enabled": True, "mode": "fake", "settings": settings}
    return ConnectorRegistry({"connectors": cfg}, manifests=manifests)


def _run(session, reg, corpus: Path, org: str, suppliers_file: Path, names: list[str] | None = None) -> dict:
    from soc_platform.core.models import Case
    from soc_platform.domains.incident.service import IncidentService
    from soc_platform.domains.phishing.agents.analyzer import HeuristicAnalyzer
    from soc_platform.domains.phishing.agents.decompose import decompose
    from soc_platform.domains.phishing.service import PhishingService
    from soc_platform.domains.phishing.supplier import SupplierMonitor, load_suppliers
    from soc_platform.domains.vulnerability.misconfig import MisconfigurationService
    from soc_platform.domains.vulnerability.service import VulnerabilityService
    from soc_platform.intelligence.analyst import IntelligenceService
    from soc_platform.intelligence.attack_coverage import coverage
    from soc_platform.intelligence.shadow_it import shadow_it_report
    from soc_platform.intelligence.story import story_for_case

    vm = VulnerabilityService(session, reg).refresh()
    mis = MisconfigurationService(session, reg).refresh()
    inc = IncidentService(session, reg)
    inc.ingest()
    clusters = inc.cluster()
    for c in clusters:
        inc.investigate(c.id)
    ph = PhishingService(session, reg, org_domains=[org])
    for sub in ph.ingest_reported():
        ph.process(sub.id)
    labels = names or list(json.loads((corpus / "labels.json").read_text()))
    suppliers = load_suppliers(suppliers_file)
    heur = HeuristicAnalyzer(org_domains=[org], partner_domains=[d for s_ in suppliers for d in s_.domains])
    verdicts = {}
    for name in labels:
        raw = (corpus / f"{name}.eml").read_bytes()
        verdicts[name] = heur.analyze(decompose(raw), raw).verdict
        sub = ph.submit_raw(raw, source="gen-test")
        ph.process(sub.id)
    intel = IntelligenceService(session)
    insights = intel.refresh()
    pcase = session.query(Case).filter(Case.domain == "phishing", Case.severity == "critical").order_by(Case.created_at).first()
    st = story_for_case(session, pcase.id, reg)
    sup = SupplierMonitor(session, suppliers).assess()
    shadow = shadow_it_report(reg)
    cov = coverage(session, reg.enabled_names())
    import tempfile

    from soc_platform.reporting.builder import STANDARD, build_report, get_template

    reports = [build_report(session, reg, get_template(session, tid), tempfile.mkdtemp(), llm=None, by="gen-test", case_id=pcase.id)
               for tid in STANDARD]
    ask = intel.analyst.ask(f"What happened to {st['principals'][0]['name'] if st['principals'] else 'the user'}?")
    signature = {
        "vm_consolidated": vm["consolidation"]["consolidated"], "vm_bands": vm["priority_bands"],
        "asset_match": vm["asset_match_rate"]["match_rate"], "misconfigs": mis["consolidation"]["consolidated"],
        "misconfig_unknown_owner": len(mis["ownership"]["unknown_owner_resources"]),
        "incidents": len(clusters), "incident_severities": sorted(c.severity for c in session.query(Case).filter(Case.domain == "incident")),
        "verdicts": verdicts, "insight_rules": sorted({i.rule for i in insights}),
        "story_verdict": st["assessment"]["verdict"], "story_stages": [s["stage"] for s in st["steps"]],
        "story_outcomes": [s["outcome"] for s in st["steps"]], "blast": st["blast_radius"]["stats"],
        "hypotheses": [h["status"] for h in st["hypotheses"]], "gaps": [(g["stage"], g["status"]) for g in st["gaps"]],
        "plan_phases": [p["phase"] for p in st["response_plan"]],
        "supplier_status": sorted(v["status"] for v in sup["suppliers"].values()),
        "supplier_findings": sorted(f["type"] for f in sup["findings"]),
        "shadow": shadow["summary"], "coverage": cov["summary"],
        "ask_uses_story": "attack_story" in [c["tool"] for c in ask["tool_calls"]],
        "reports": [[(x["source"], len(x["facts"])) for x in r["sections"]] for r in reports],
    }
    text = json.dumps({"story": st, "insights": [i.title + i.narrative for i in insights], "ask": ask["answer"],
                       "sup": sup, "shadow": shadow, "reports": reports}, default=str).lower()
    return {"signature": signature, "text": text, "story": st}


@pytest.fixture(scope="module")
def both(tmp_path_factory):
    import os

    from soc_platform.core.db import Database

    out = rename.main(str(tmp_path_factory.mktemp("northwind")))
    rx, table = rename.build_pattern(rename.DEFAULT_MAP)
    results = {}
    for label, fixtures, corpus, org, sup, reg_args in [
            ("original", None, ROOT / "artifacts/phishing/corpus", "cci-demo.com", ROOT / "config/suppliers.yaml", {}),
            ("renamed", out / "fixtures", out / "corpus", "northwind-labs.io", out / "suppliers.yaml", {"rx": rx, "table": table})]:
        old = os.environ.get("SOC_FIXTURES_DIR"), os.environ.get("SOC_SUPPLIERS_FILE")
        if fixtures:
            os.environ["SOC_FIXTURES_DIR"] = str(fixtures)
        os.environ["SOC_SUPPLIERS_FILE"] = str(sup)
        try:
            db = Database("sqlite://")
            db.create_all()
            with db.session() as s:
                results[label] = _run(s, _registry(**reg_args), corpus, org, sup,
                                      names=list(json.loads((out / "corpus" / "labels.json").read_text())))
        finally:
            for k, v in zip(("SOC_FIXTURES_DIR", "SOC_SUPPLIERS_FILE"), old):
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
    return results


def test_renamed_estate_gives_structurally_identical_results(both):
    a, b = both["original"]["signature"], both["renamed"]["signature"]
    diffs = {k: (a[k], b[k]) for k in a if a[k] != b[k]}
    assert not diffs, diffs


def test_every_feature_produced_real_output_on_the_new_organisation(both):
    sig = both["renamed"]["signature"]
    assert sig["story_verdict"] == "confirmed_compromise" and len(sig["story_stages"]) >= 8
    assert sig["vm_consolidated"] >= 6 and sig["incidents"] >= 3 and sig["misconfigs"] == 2
    assert sig["ask_uses_story"] and sig["shadow"]["unsanctioned_services"] >= 3
    assert "supplier_impersonation" in sig["supplier_findings"]
    assert len(sig["reports"]) >= 7 and all(sig["reports"])                               # every standard report builds
    assert all(v in {"malicious", "suspicious"} for k, v in sig["verdicts"].items() if k.startswith(("cred", "bec", "supplier_look")))
    st = both["renamed"]["story"]
    assert st["principals"] and any("northwind-labs.io" in p["name"] for p in st["principals"])


def test_no_original_names_leak_into_the_new_organisation(both):
    text = both["renamed"]["text"]
    leaks = [t for t in ORIGINAL_TOKENS if t in text]
    assert not leaks, leaks
