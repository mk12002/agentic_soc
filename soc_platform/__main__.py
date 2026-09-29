"""Command line entry point:  python -m soc_platform <command>

  init-db     create tables in SOC_DATABASE_URL
  demo        run all three workflows end to end on fixture connectors and write reports
  reset-demo  wipe the demo database and generated files, then init-db + demo  (--yes skips the question)
  serve       start the API + console (uvicorn)
  scheduler   run recurring jobs as a separate service (serve already runs them unless SOC_EMBEDDED_SCHEDULER=0)
  token       mint a dev token:  python -m soc_platform token alice@acme-demo.com analyst,lead
  fixtures    regenerate connector fixtures and the labelled email corpus
"""

from __future__ import annotations

import os
import subprocess
import sys
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
        from soc_platform.domains.phishing.agents.analyzer import engine_enabled

        engine = engine_enabled()                            # the trained models, when installed (SOC_PHISHING_ENGINE)
        print(f"[PH] analysis: {'ML engine + heuristic' if engine else 'heuristic only'}")
        ph = PhishingService(s, reg, org_domains=org, raw_dir=Path(st.raw_payload_dir) / "phishing", use_engine=engine)
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


def _inside(path: Path, *roots: Path) -> bool:
    p = path.resolve()
    return any(p == r.resolve() or r.resolve() in p.parents for r in roots)


def _server_running(host: str, port: int) -> bool:
    import socket

    with socket.socket() as sock:
        sock.settimeout(0.5)
        return sock.connect_ex((host, port)) == 0


def cmd_reset_demo(*args: str) -> None:
    """Start the demo again from nothing, in one command: the database is emptied, raw payloads and generated reports
    are removed, then init-db and demo run. For demo and development databases only - never production."""
    import shutil

    from sqlalchemy.engine import make_url

    from soc_platform.config import get_settings

    st = get_settings()
    if st.environment == "prod":
        sys.exit("reset-demo refuses to run with SOC_ENVIRONMENT=prod")
    host, port = os.environ.get("SOC_HOST", "127.0.0.1"), int(os.environ.get("SOC_PORT", "8080"))
    if _server_running("127.0.0.1" if host in {"0.0.0.0", "::"} else host, port):  # nosec B104 - comparing, not binding
        sys.exit(f"the server is running on port {port}: stop it first (Ctrl+C in its window), then run reset-demo again")
    url = make_url(st.database_url)
    print(f"This deletes everything in {url.render_as_string(hide_password=True)}"
          f" and the files in {st.raw_payload_dir} and {st.report_output_dir}.")
    if "--yes" not in args and input("Type RESET to continue: ").strip() != "RESET":
        sys.exit("cancelled - nothing was changed")

    from soc_platform.core.db import Base

    db = _db()                                                # the engine actually in use decides how to empty it
    real = db.engine.url
    if real.get_backend_name() == "sqlite" and real.database and real.database != ":memory:":
        db.engine.dispose()
        db_file = Path(real.database)
        for f in (db_file, Path(f"{db_file}-wal"), Path(f"{db_file}-shm")):
            try:
                f.unlink(missing_ok=True)
            except PermissionError:
                sys.exit(f"{f} is in use - stop the server or any other process using it, then run reset-demo again")
    else:
        Base.metadata.drop_all(db.engine)                     # every table is registered by get_database()
        db.engine.dispose()
    for folder in (Path(st.raw_payload_dir), Path(st.report_output_dir)):
        if not folder.exists():
            continue
        if _inside(folder, Path.cwd(), ROOT):
            shutil.rmtree(folder)
        else:
            print(f"note: {folder} is outside this folder, so it was left alone - clear it yourself if needed")

    from soc_platform.core import db as dbm

    dbm._default = None                                       # a fresh engine on the fresh database
    cmd_init_db()
    cmd_demo()
    print("reset complete - start the server with: python -m soc_platform serve")


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
    """Run the scheduler as its own service (the server also runs one unless SOC_EMBEDDED_SCHEDULER=0). Both are
    safe together: the database decides what is due and a lease stops any job running twice at once."""
    from soc_platform import scheduler

    scheduler.run_forever(once=once)


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
