"""The platform on seeded variant estates: different organisation, people, machines, suppliers and volumes.

These prove behaviour is driven by the data, not by the built-in estate: the variants really differ, every feature
produces correct output on them, and no output mentions the built-in estate.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from soc_platform.tests.conftest import ESTATES, estate_env

VARIANTS = [e for e in ESTATES if e != "demo"]


def _load(s, cfg):
    from soc_platform.connectors.registry import ConnectorRegistry
    from soc_platform.domains.incident.service import IncidentService
    from soc_platform.domains.phishing.service import PhishingService
    from soc_platform.domains.vulnerability.misconfig import MisconfigurationService
    from soc_platform.domains.vulnerability.service import VulnerabilityService
    from soc_platform.intelligence.analyst import IntelligenceService

    reg = ConnectorRegistry.all_fake()
    vm = VulnerabilityService(s, reg)
    vm.refresh()
    MisconfigurationService(s, reg).refresh()
    inc = IncidentService(s, reg)
    inc.ingest()
    for c in inc.cluster():
        inc.investigate(c.id)
    ph = PhishingService(s, reg, org_domains=[cfg["org"]])
    for sub in ph.ingest_reported():
        ph.process(sub.id)
    IntelligenceService(s).refresh()
    return reg, vm, ph


@pytest.fixture(params=["demo", *VARIANTS])
def loaded(request, estate_configs, session):
    with estate_env(estate_configs[request.param]) as cfg:
        reg, vm, ph = _load(session, cfg)
        yield {"cfg": cfg, "s": session, "reg": reg, "vm": vm, "ph": ph}


def test_variants_really_differ_from_the_built_in_estate(estate_configs):
    from soc_platform.connectors.registry import ConnectorRegistry
    from soc_platform.core.db import Database
    from soc_platform.domains.vulnerability.service import VulnerabilityService
    from soc_platform.intelligence.shadow_it import shadow_it_report

    seen = {}
    for name in ESTATES:
        db = Database("sqlite://")
        db.create_all()
        with estate_env(estate_configs[name]) as cfg, db.session() as s:
            reg = ConnectorRegistry.all_fake()
            vm = VulnerabilityService(s, reg)
            vm.refresh()
            users = reg.get("entra").get("/v1.0/users").get("value", [])
            seen[name] = {"org": cfg["org"], "users": len(users), "findings": vm.metrics()["open"],
                          "edr_gaps": len(vm.coverage()["missing_edr"]), "shadow": shadow_it_report(reg)["summary"]["unsanctioned_services"],
                          "people": sorted(u["userPrincipalName"] for u in users)}
    assert len({v["org"] for v in seen.values()}) == len(ESTATES)                     # different organisations
    assert not set(seen["demo"]["people"]) & set(seen["seed7"]["people"])             # different people
    for v in VARIANTS:
        cfg = estate_configs[v]
        assert seen[v]["users"] == seen["demo"]["users"] + cfg["extra_users"]
        assert seen[v]["edr_gaps"] >= seen["demo"]["edr_gaps"] + cfg["laptops_without_edr"] - 1
    assert len({(x["users"], x["findings"], x["shadow"]) for x in seen.values()}) == len(ESTATES)   # different volumes


def test_phishing_verdicts_match_labels_on_every_corpus(estate_configs):
    from soc_platform.domains.phishing.agents.analyzer import HeuristicAnalyzer
    from soc_platform.domains.phishing.agents.decompose import decompose
    from soc_platform.domains.phishing.supplier import load_suppliers

    for name in ESTATES:
        cfg = estate_configs[name]
        corpus = Path(cfg["corpus_dir"])
        labels = json.loads((corpus / "labels.json").read_text())
        suppliers = load_suppliers(cfg["suppliers_file"])
        heur = HeuristicAnalyzer(org_domains=[cfg["org"]], partner_domains=[d for s_ in suppliers for d in s_.domains])
        wrong = {}
        for stem, label in labels.items():
            raw = (corpus / f"{stem}.eml").read_bytes()
            got = heur.analyze(decompose(raw), raw).verdict
            positive = {"malicious", "suspicious"}
            if (label in positive) != (got in positive) or (label not in positive and got != label and {label, got} != {"safe", "spam"}):
                wrong[stem] = (label, got)
        assert not wrong, (name, wrong)


def test_attack_story_follows_the_data(loaded):
    from soc_platform.core.models import Case
    from soc_platform.intelligence.story import story_for_case

    s, cfg = loaded["s"], loaded["cfg"]
    case = s.query(Case).filter(Case.domain == "phishing").first()
    st = story_for_case(s, case.id, loaded["reg"])
    assert st["assessment"]["verdict"] == "confirmed_compromise"
    assert any(p["name"] == cfg["focus_upn"] for p in st["principals"])
    assert st["summary"].startswith(f"Confirmed compromise of {cfg['focus_upn']}")
    assert st["blast_radius"]["stats"]["users_received"] == 8 + cfg.get("extra_recipients", 0)   # campaign grows with the data
    stages = {x["stage_name"] for x in st["steps"]}
    assert {"Initial Access", "Execution", "Credential Access"} <= stages


def test_reports_and_answers_never_mention_another_estate(loaded, tmp_path):
    from soc_platform.intelligence.analyst import IntelligenceService
    from soc_platform.reporting.builder import STANDARD, build_report, get_template

    s, cfg = loaded["s"], loaded["cfg"]
    from soc_platform.core.models import Case
    inc = s.query(Case).filter(Case.domain == "incident", Case.severity == "critical").first()
    texts = []
    for tid in STANDARD:
        r = build_report(s, loaded["reg"], get_template(s, tid), tmp_path, llm=None, by="t", case_id=inc.id)
        assert r["sections"] and not r["skipped"], (cfg["name"], tid, r["skipped"])
        texts += [x["narrative"] + json.dumps(x["facts"]) for x in r["sections"]]
    ans = IntelligenceService(s).analyst.ask(f"What happened to {cfg['focus_upn']} and what should we do first?")
    texts.append(ans["answer"])
    toks = cfg.get("original_tokens") or []
    for t in toks:
        rx = re.compile(r"(?<![a-z0-9])" + re.escape(t) + r"(?![a-z0-9])", re.I)
        assert not any(rx.search(x) for x in texts), (cfg["name"], t)


def test_vulnerability_coverage_tracks_the_generated_gaps(loaded):
    cfg, vm = loaded["cfg"], loaded["vm"]
    cov = vm.coverage()
    assert vm.metrics()["open"] > 0
    if cfg["name"] != "demo":
        assert len(cov["missing_edr"]) >= cfg["laptops_without_edr"]
    assert not [a for a in cov["missing_edr"] if a.endswith("backups")]              # cloud storage never an EDR gap
