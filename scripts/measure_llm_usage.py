"""Measure LLM tokens per component on a sample estate, with the configured (real) model.

    python scripts/measure_llm_usage.py                         # built-in estate
    python scripts/measure_llm_usage.py --estate OUT/estate.json --out usage.json

Runs every component that calls the model - incident summaries, phishing explanations, insight narratives, the
situation brief, analyst questions (planner + answer), deep analysis, report planning and report narrative - then
aggregates the platform's own LLM call log (the same log production keeps). Reads SOC_LLM_* from the environment
or the repository's .env. Costs a few cents on gpt-4.1-mini.
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def _llm_env() -> None:
    if os.environ.get("SOC_LLM_PROVIDER"):
        return
    env = ROOT / ".env"
    if env.is_file():
        for line in env.read_text(encoding="utf-8").splitlines():
            k, sep, v = line.partition("=")
            if sep and k.strip().startswith("SOC_LLM_"):
                os.environ[k.strip()] = v.split(" #")[0].strip()


def measure(estate: dict) -> dict:
    from soc_platform.config import get_settings
    from soc_platform.connectors.registry import ConnectorRegistry
    from soc_platform.core.db import Database
    from soc_platform.core.models import Case, Evidence, LLMCall
    from soc_platform.domains.incident.service import IncidentService
    from soc_platform.domains.phishing.service import PhishingService
    from soc_platform.domains.vulnerability.service import VulnerabilityService
    from soc_platform.intelligence import analyst as an
    from soc_platform.intelligence.analyst import IntelligenceService
    from soc_platform.intelligence.deep_analysis import run_deep_analysis
    from soc_platform.intelligence.story import story_for_case
    from soc_platform.llm.gateway import LLMGateway
    from soc_platform.reporting.builder import build_report, get_template, plan_report

    get_settings.cache_clear()
    settings = get_settings()
    assert settings.llm_provider != "none", "configure SOC_LLM_* (an approved endpoint) first"
    db = Database("sqlite://")
    db.create_all()
    reg = ConnectorRegistry.all_fake()
    an._BRIEF_CACHE.clear()
    started = time.monotonic()
    with db.session() as s:
        gw = LLMGateway(s, settings.model_copy(update={"org_domains": [estate["org"]]}))
        VulnerabilityService(s, reg, llm=gw).refresh()
        inc = IncidentService(s, reg, llm=gw)
        inc.ingest()
        for c in inc.cluster():
            inc.investigate(c.id)
        ph = PhishingService(s, reg, org_domains=[estate["org"]], llm=gw)
        for sub in ph.ingest_reported():
            ph.process(sub.id)
        for f in estate["uploads"]:
            sub = ph.submit_raw((Path(estate["corpus_dir"]) / f).read_bytes(), source="upload", reporter=estate["lead"])
            ph.process(sub.id)
        intel = IntelligenceService(s, gw)
        intel.refresh()
        intel.analyst.brief()
        intel.analyst.brief()                                                   # second view: served from cache
        for q in (f"Is {estate['focus_upn']} compromised and what should we do first?",
                  "Which internet-facing hosts have known-exploited vulnerabilities?",
                  "What is waiting for approval and what is most urgent?"):
            intel.analyst.ask(q)
        case = s.query(Case).filter(Case.domain == "phishing", Case.severity == "critical").first()
        run_deep_analysis(s, story_for_case(s, case.id, reg), gw, actor="measure", org_domains=[estate["org"]])
        out = Path(tempfile.mkdtemp())
        build_report(s, reg, get_template(s, "ciso_weekly"), out, llm=gw, by="measure")
        spec = plan_report("A one-page board brief on phishing and supplier risk this quarter, as slides", gw)
        build_report(s, reg, spec, out, llm=gw, by="measure")

        calls = s.query(LLMCall).all()
        volumes = {"incidents": s.query(Case).filter(Case.domain == "incident").count(),
                   "reported_emails": s.query(Case).filter(Case.domain == "phishing").count(),
                   "insights": len(intel.analyst._list_insights()),
                   "evidence_rows": s.query(Evidence).count()}
    by: dict[str, list] = {}
    for c in calls:
        wf = "report.section" if c.workflow.startswith("report.section.") else c.workflow
        by.setdefault(wf, []).append(c)
    rows = {}
    for wf, cs in sorted(by.items()):
        pt, ct = [c.prompt_tokens for c in cs], [c.completion_tokens for c in cs]
        rows[wf] = {"calls": len(cs), "prompt_mean": round(statistics.mean(pt)), "prompt_max": max(pt),
                    "completion_mean": round(statistics.mean(ct)), "completion_max": max(ct),
                    "tokens_total": sum(pt) + sum(ct), "statuses": sorted({c.status for c in cs})}
    return {"estate": estate.get("org"), "model": sorted({c.model for c in calls}), "volumes": volumes, "components": rows,
            "totals": {"calls": len(calls), "prompt": sum(c.prompt_tokens for c in calls),
                       "completion": sum(c.completion_tokens for c in calls)},
            "seconds": round(time.monotonic() - started, 1)}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--estate", help="estate.json from scripts/build_estate_variant.py (default: built-in estate)")
    ap.add_argument("--out", help="write the result as JSON")
    a = ap.parse_args()
    _llm_env()
    if a.estate:
        estate = json.loads(Path(a.estate).read_text())
        os.environ["SOC_FIXTURES_DIR"] = estate["fixtures_dir"]
        os.environ["SOC_SUPPLIERS_FILE"] = estate["suppliers_file"]
    else:
        estate = {"org": "acme-demo.com", "lead": "lena@acme-demo.com", "focus_upn": "jane.doe@acme-demo.com",
                  "corpus_dir": str(ROOT / "artifacts/phishing/corpus"),
                  "uploads": ["supplier_bank_change.eml", "supplier_lookalike_payment.eml", "bec_ceo_fraud.eml",
                              "quishing_qr.eml", "legit_vendor_invoice.eml", "marketing_spam.eml"]}
    os.environ["SOC_ORG_DOMAINS"] = estate["org"]
    r = measure(estate)
    print(json.dumps(r, indent=1))
    if a.out:
        Path(a.out).write_text(json.dumps(r, indent=1), encoding="utf-8")


if __name__ == "__main__":
    main()
