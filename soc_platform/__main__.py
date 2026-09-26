"""Command line entry point:  python -m soc_platform <command>

  init-db     create tables in SOC_DATABASE_URL
  demo        run all three workflows end to end on fixture connectors and write reports
  serve       start the API + console (uvicorn)
  scheduler   run recurring jobs (syncs, investigations, follow-ups, reports)
  token       mint a dev token:  python -m soc_platform token alice@acme-demo.com analyst,lead
  fixtures    regenerate connector fixtures and the labelled email corpus
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _db():
    from soc_platform.core.db import get_database

    return get_database()


def cmd_init_db() -> None:
    _db().create_all()
    print("database ready:", os.environ.get("SOC_DATABASE_URL", "sqlite:///./soc_platform.db"))


SAMPLE_ORG = "acme-demo.com"
BUILTIN_CORPUS = Path(__file__).resolve().parents[1] / "artifacts" / "phishing" / "corpus"
SAMPLE_UPLOADS = ("supplier_bank_change.eml", "supplier_lookalike_payment.eml", "bec_ceo_fraud.eml", "quishing_qr.eml",
                  "legit_vendor_invoice.eml", "marketing_spam.eml")


def cmd_demo() -> None:
    from soc_platform.config import get_settings
    from soc_platform.connectors.registry import ConnectorRegistry
    from soc_platform.core.audit import AuditLog
    from soc_platform.core.auth import Principal, Role
    from soc_platform.domains.incident.service import IncidentService
    from soc_platform.domains.phishing.service import PhishingService
    from soc_platform.domains.vulnerability.service import VulnerabilityService
    from soc_platform.reporting.reports import ReportService

    st = get_settings()
    reg = ConnectorRegistry.all_fake()
    out = Path(st.report_output_dir)
    org = st.org_domains or [SAMPLE_ORG]                     # the built-in sample organisation unless configured
    analyst = Principal(f"demo.analyst@{org[0]}", "Demo Analyst", frozenset({Role.ANALYST}))
    with _db().session() as s:
        vm = VulnerabilityService(s, reg)
        r = vm.refresh()
        print(f"[VM] {r['consolidation']['raw_findings']} raw findings -> {r['consolidation']['consolidated']} consolidated; "
              f"priority {r['priority_bands']}; asset match rate {r['asset_match_rate']['match_rate']}")
        camp = vm.create_campaign("CVE-2021-44228", analyst, notify_via="ticket")
        print(f"[VM] campaign {camp.id} created for CVE-2021-44228 (notifications await approval)")
        im = IncidentService(s, reg)
        im.ingest()
        cases = im.cluster()
        for c in cases:
            if c.status != "closed":
                v = im.investigate(c.id)
                print(f"[IM] {v['case']['severity']:>8} {v['case']['title'][:70]} - {len(v['actions'])} recommended action(s)")
        ph = PhishingService(s, reg, org_domains=org, raw_dir=Path(st.raw_payload_dir) / "phishing")
        for sub in ph.ingest_reported():
            v = ph.process(sub.id)
            a = v["assessment"]
            print(f"[PH] {v['case']['verdict']} '{v['case']['title'][:50]}': {len(a['campaign']['recipients'])} recipients, "
                  f"clicked {a['user_impact']['clicked']}, compromised {a['user_impact']['identity_compromise']}")
        # the sample messages a presenter uploads in the console (supplier fraud, CEO fraud, QR phishing, benign, spam)
        corpus = Path(os.environ.get("SOC_SAMPLE_CORPUS_DIR") or BUILTIN_CORPUS)   # a variant estate brings its own
        for f in SAMPLE_UPLOADS:
            path = corpus / f
            if path.exists():
                v = ph.process(ph.submit_raw(path.read_bytes(), source="upload", reporter=analyst.id).id)
                print(f"[PH] {v['case']['verdict']:>10} '{v['case']['title'][:60]}' (uploaded sample)")
        from soc_platform.domains.vulnerability.misconfig import MisconfigurationService

        mis = MisconfigurationService(s, reg)
        mis.refresh()
        mis.route(analyst)
        from soc_platform.intelligence.analyst import IntelligenceService

        intel = IntelligenceService(s, vm=vm)
        for ins in sorted(intel.refresh(), key=lambda i: -i.score)[:6]:
            print(f"[INTEL] {ins.severity:>8} {ins.title}")
        ans = intel.analyst.ask("Is jane.doe@acme-demo.com compromised?")
        print(f"[ASK] {ans['answer']}  (tools: {', '.join(c['tool'] for c in ans['tool_calls'])})")
        rs = ReportService(s, out)
        for run in (rs.daily_exposure(vm), rs.weekly_vm(vm), rs.weekly_management_deck(vm, im, ph)):
            print(f"[REPORT] {run.kind}: {run.path}")
        print("[AUDIT]", AuditLog(s).verify())


def cmd_serve() -> None:
    import uvicorn

    uvicorn.run("soc_platform.api.app:app", host=os.environ.get("SOC_HOST", "127.0.0.1"),
                port=int(os.environ.get("SOC_PORT", "8080")))


def cmd_token(user: str = "analyst@acme-demo.com", roles: str = "analyst") -> None:
    from soc_platform.config import get_settings
    from soc_platform.core.auth import issue_dev_token

    st = get_settings()
    if not st.dev_jwt_secret:
        sys.exit("set SOC_DEV_JWT_SECRET first")
    print(issue_dev_token(st.dev_jwt_secret, user, roles.split(",")))


def cmd_fixtures() -> None:
    subprocess.run([sys.executable, str(ROOT / "scripts" / "build_fixtures.py")], check=True)
    subprocess.run([sys.executable, str(ROOT / "scripts" / "build_email_corpus.py")], check=True)


def cmd_scheduler(once: bool = False) -> None:
    """Run due jobs forever (or once). Each run is leased, retried, recorded and dead-lettered (see jobs.py)."""
    from soc_platform import jobs

    last: dict[str, float] = {}
    while True:
        for name in jobs.due(time.time(), last):
            last[name] = time.time()
            run = jobs.run_job(name)
            print(json.dumps({"job": name, "status": run.status if run else "skipped (lease held elsewhere)",
                              "attempts": run.attempts if run else 0,
                              "error": (run.error or "").splitlines()[0] if run and run.error else None,
                              "at": time.time()}), flush=True)
        if once:
            return
        time.sleep(15)


def main(argv: list[str]) -> None:
    if not argv:
        print(__doc__)
        return
    cmd, args = argv[0].replace("-", "_"), argv[1:]
    fn = globals().get(f"cmd_{cmd}")
    if fn is None:
        sys.exit(f"unknown command {argv[0]}\n{__doc__}")
    fn(*args) if cmd != "scheduler" else fn(once="--once" in args)


if __name__ == "__main__":
    main(sys.argv[1:])
