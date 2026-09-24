"""Command line entry point:  python -m soc_platform <command>

  init-db     create tables in SOC_DATABASE_URL
  demo        run all three workflows end to end on fixture connectors and write reports
  serve       start the API + console (uvicorn)
  scheduler   run recurring jobs (syncs, investigations, follow-ups, reports)
  token       mint a dev token:  python -m soc_platform token alice@cci-demo.com analyst,lead
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


def cmd_demo() -> None:
    from soc_platform.connectors.registry import ConnectorRegistry
    from soc_platform.core.audit import AuditLog
    from soc_platform.core.auth import Principal, Role
    from soc_platform.domains.incident.service import IncidentService
    from soc_platform.domains.phishing.service import PhishingService
    from soc_platform.domains.vulnerability.service import VulnerabilityService
    from soc_platform.reporting.reports import ReportService

    reg = ConnectorRegistry.all_fake()
    out = Path(os.environ.get("SOC_REPORT_OUTPUT_DIR", "./data/reports"))
    analyst = Principal("demo.analyst@cci-demo.com", "Demo Analyst", frozenset({Role.ANALYST}))
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
        ph = PhishingService(s, reg, org_domains=["cci-demo.com"], raw_dir=Path("./data/raw/phishing"))
        for sub in ph.ingest_reported():
            v = ph.process(sub.id)
            a = v["assessment"]
            print(f"[PH] {v['case']['verdict']} '{v['case']['title'][:50]}': {len(a['campaign']['recipients'])} recipients, "
                  f"clicked {a['user_impact']['clicked']}, compromised {a['user_impact']['identity_compromise']}")
        from soc_platform.intelligence.analyst import IntelligenceService

        intel = IntelligenceService(s, vm=vm)
        for ins in sorted(intel.refresh(), key=lambda i: -i.score)[:6]:
            print(f"[INTEL] {ins.severity:>8} {ins.title}")
        ans = intel.analyst.ask("Is jane.doe@cci-demo.com compromised?")
        print(f"[ASK] {ans['answer']}  (tools: {', '.join(c['tool'] for c in ans['tool_calls'])})")
        rs = ReportService(s, out)
        for run in (rs.daily_exposure(vm), rs.weekly_vm(vm), rs.weekly_management_deck(vm, im, ph)):
            print(f"[REPORT] {run.kind}: {run.path}")
        print("[AUDIT]", AuditLog(s).verify())


def cmd_serve() -> None:
    import uvicorn

    uvicorn.run("soc_platform.api.app:app", host=os.environ.get("SOC_HOST", "127.0.0.1"),
                port=int(os.environ.get("SOC_PORT", "8080")))


def cmd_token(user: str = "analyst@cci-demo.com", roles: str = "analyst") -> None:
    from soc_platform.config import get_settings
    from soc_platform.core.auth import issue_dev_token

    st = get_settings()
    if not st.dev_jwt_secret:
        sys.exit("set SOC_DEV_JWT_SECRET first")
    print(issue_dev_token(st.dev_jwt_secret, user, roles.split(",")))


def cmd_fixtures() -> None:
    subprocess.run([sys.executable, str(ROOT / "scripts" / "build_fixtures.py")], check=True)
    subprocess.run([sys.executable, str(ROOT / "scripts" / "build_email_corpus.py")], check=True)


JOBS = {  # name -> (interval seconds env var, default seconds)
    "incident": ("SOC_JOB_INCIDENT_SECONDS", 300),
    "phishing": ("SOC_JOB_PHISHING_SECONDS", 120),
    "vulnerability": ("SOC_JOB_VM_SECONDS", 6 * 3600),
    "follow_up": ("SOC_JOB_FOLLOWUP_SECONDS", 24 * 3600),
    "daily_report": ("SOC_JOB_DAILY_REPORT_SECONDS", 24 * 3600),
    "intelligence": ("SOC_JOB_INTELLIGENCE_SECONDS", 600),
}


def cmd_scheduler(once: bool = False) -> None:
    from soc_platform.api.app import _services
    from soc_platform.reporting.reports import ReportService
    from soc_platform.config import get_settings

    last: dict[str, float] = {}
    while True:
        for name, (env, default) in JOBS.items():
            every = int(os.environ.get(env, default))
            if time.time() - last.get(name, 0) < every:
                continue
            last[name] = time.time()
            try:
                with _db().session() as s:
                    sv = _services(s)
                    if name == "incident":
                        sv["incident"].ingest()
                        for c in sv["incident"].cluster():
                            if c.status != "closed":
                                sv["incident"].investigate(c.id)
                    elif name == "phishing":
                        for sub in sv["phishing"].ingest_reported():
                            if sub.status == "new":
                                sv["phishing"].process(sub.id)
                    elif name == "vulnerability":
                        sv["vulnerability"].refresh()
                    elif name == "follow_up":
                        sv["vulnerability"].follow_up()
                        sv["vulnerability"].expire_exceptions()
                    elif name == "intelligence":
                        from soc_platform.api.app import _intel

                        _intel(s).refresh()
                    elif name == "daily_report":
                        ReportService(s, get_settings().report_output_dir).daily_exposure(sv["vulnerability"])
                print(json.dumps({"job": name, "status": "ok", "at": time.time()}), flush=True)
            except Exception as exc:  # a failing job must not stop the scheduler
                print(json.dumps({"job": name, "status": "error", "error": str(exc)[:300]}), flush=True)
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
