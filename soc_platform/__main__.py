"""Command line entry point:  python -m soc_platform <command>

  init-db     create tables in SOC_DATABASE_URL
  demo        run all three workflows end to end on fixture connectors and write reports
  reset-demo  wipe the demo database and generated files, then init-db + demo  (--yes skips the question)
  serve       start the API + console (uvicorn)
  scheduler   run recurring jobs as a separate service (serve already runs them unless SOC_EMBEDDED_SCHEDULER=0)
  token       mint a dev token:  python -m soc_platform token alice@acme-demo.com analyst,lead
  fixtures    regenerate connector fixtures and the labelled email corpus
  config      check | export [--out F] | diff FILE | import FILE --by EMAIL [--note TEXT]
              check the connector configuration (file + approved console changes) and every secret it needs; export
              it as one file; compare a file with it; propose a file as a change (approved in the console)
  preflight   [NAME ... | --all] [--by EMAIL]   run every check a tool must pass before it goes live
  connector   new NAME --category CAT [--tool "Vendor Product"] [--vendor V]  |  check NAME
              scaffold a new connector that already follows the platform's rules, then prove it conforms
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
    from sqlalchemy.engine import make_url

    from soc_platform.config import get_settings

    print("database ready:", make_url(get_settings().database_url).render_as_string(hide_password=True))


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


def _refuse_bad_config() -> None:
    """Typos, unknown tools or keys and broken YAML in config/connectors.yaml stop a start (they would otherwise be
    silently ignored). A live tool whose secret is missing does not: it is isolated and shown, the rest start."""
    from soc_platform.connectors.config_schema import errors
    from soc_platform.core.connector_config import startup_problems

    problems = startup_problems()
    for pr in problems:
        print(pr, file=sys.stderr)
    if errors(problems):
        sys.exit("the connector configuration has errors (listed above). Fix them and start again; "
                 "`python -m soc_platform config check` lists every problem with how to fix it.")


def cmd_serve() -> None:
    """One process serves requests on one CPU core: under many analysts at once, requests queue behind each other
    (measured: 40 analysts on one process waited ~0.3 s even for /health). SOC_API_WORKERS starts several processes
    on the same port; jobs stay safe with any number of them (each takes a database lease before running)."""
    import uvicorn

    _refuse_bad_config()

    workers = max(1, int(os.environ.get("SOC_API_WORKERS", "1") or 1))
    uvicorn.run("soc_platform.api.app:app", host=os.environ.get("SOC_HOST", "127.0.0.1"),
                port=int(os.environ.get("SOC_PORT", "8080")), workers=workers,
                proxy_headers=False)   # X-Forwarded-For is handled by the app (SOC_TRUSTED_PROXIES, right-most hop)


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

    _refuse_bad_config()
    scheduler.run_forever(once=once)


def _store_session():
    """A database session for the configuration store, or None when the database is not reachable (the file alone
    is then what applies)."""
    from sqlalchemy.exc import SQLAlchemyError

    try:
        db = _db()
        db.create_all()
        return db.session()
    except SQLAlchemyError as exc:
        print(f"note: database not reachable ({type(exc).__name__}); using config/connectors.yaml alone", file=sys.stderr)
        return None


def _cli_principal(by: str | None):
    from soc_platform.core.auth import Principal, Role

    who = by or f"cli:{os.environ.get('USERNAME') or os.environ.get('USER') or 'operator'}"
    return Principal(who, who, frozenset({Role.AUTOMATION_ADMIN}))


def cmd_config(*args: str) -> None:
    import argparse

    ap = argparse.ArgumentParser(prog="python -m soc_platform config")
    ap.add_argument("action", choices=("check", "export", "diff", "import"))
    ap.add_argument("file", nargs="?")
    ap.add_argument("--out")
    ap.add_argument("--by", help="who proposes an import (it is approved by someone else in the console)")
    ap.add_argument("--note", default="")
    ap.add_argument("--no-env", action="store_true", help="check: do not require secrets (a build machine)")
    a = ap.parse_args(list(args))
    from soc_platform.connectors.config_schema import check_document, errors, load_file, load_yaml
    from soc_platform.core.connector_config import (
        ConfigRejected,
        ConfigStore,
        default_mode,
        describe_changes,
        manifests,
    )

    ctx = _store_session()
    if a.action == "check":
        doc, problems = load_file(a.file)
        version = None
        if ctx is not None and not a.file:
            with ctx as s:
                store = ConfigStore(s)
                doc, version = store.effective(), store.active_version()
        problems += check_document(doc, manifests(), default_mode=default_mode(), check_env=not a.no_env)
        for pr in problems:
            print(pr)
        n_err = len(errors(problems))
        print(f"{n_err} error(s), {len(problems) - n_err} warning(s) in the configuration"
              + (f" (file + console version {version})" if version else ""))
        sys.exit(1 if n_err else 0)
    if ctx is None:
        sys.exit("export, diff and import need the database (SOC_DATABASE_URL)")
    with ctx as s:
        store = ConfigStore(s)
        if a.action == "export":
            text = store.export_yaml()
            if a.out:
                Path(a.out).write_text(text, encoding="utf-8")
                print(f"written to {a.out}")
            else:
                print(text)
            return
        if not a.file:
            sys.exit(f"config {a.action} needs a FILE")
        text = Path(a.file).read_text(encoding="utf-8")
        if a.action == "diff":
            doc, problems = load_yaml(text)
            for pr in problems:
                print(pr)
            changes = describe_changes(store.effective(), doc or {})
            for c in changes:
                print(f"{c['connector']}.{c['field']}: {c['from']!r} -> {c['to']!r}")
            print(f"{len(changes)} difference(s) from the configuration in force")
            return
        if not a.by:
            sys.exit("config import needs --by EMAIL (the proposer; someone else approves it in the console)")
        try:
            v = store.import_yaml(text, _cli_principal(a.by), a.note)
        except ConfigRejected as exc:
            for pr in exc.problems:
                print(pr)
            sys.exit(str(exc))
        s.commit()
        print(f"proposed as configuration version {v.id} ({len(v.changes)} change(s)); approve it in Integrations")


def cmd_preflight(*args: str) -> None:
    import argparse

    ap = argparse.ArgumentParser(prog="python -m soc_platform preflight")
    ap.add_argument("names", nargs="*")
    ap.add_argument("--all", action="store_true", help="every switched-on connector")
    ap.add_argument("--by")
    a = ap.parse_args(list(args))
    from soc_platform.connectors.preflight import run_preflight
    from soc_platform.connectors.registry import ConnectorRegistry
    from soc_platform.core.connector_config import ConfigStore

    ctx = _store_session()
    s = ctx.__enter__() if ctx is not None else None
    try:
        store = ConfigStore(s) if s is not None else None
        reg = store.registry() if store else ConnectorRegistry.from_file()
        names = reg.configured_names() if a.all or not a.names else a.names
        unknown = [n for n in names if n not in reg.manifests]
        if unknown:
            sys.exit(f"unknown connector(s): {', '.join(unknown)}")
        failed = 0
        for n in names:
            res = store.preflight(n, _cli_principal(a.by), registry=reg) if store else run_preflight(reg, n)
            failed += not res["ok"]
            print(f"\n{res['tool']} ({n}) - stage {res['stage_label']} - {res['verdict'].upper()}")
            for c in res["checks"]:
                print(f"  [{c['status']:>7}] {c['check']}: {c['detail']}" + (f"\n            fix: {c['fix']}" if c.get("fix") else ""))
                for st in c.get("streams", []):
                    line = f"            {st['stream']}: {st['status']}"
                    if st.get("records") is not None:
                        line += f", {st['records']} record(s), {st.get('latency_ms')} ms"
                    if st.get("volume"):
                        line += f", {st['volume']}"
                    print(line + "".join(f"\n              - {x}" for x in st.get("notes", [])))
        if s is not None:
            s.commit()
        print(f"\n{len(names) - failed} of {len(names)} ready")
        sys.exit(1 if failed else 0)
    finally:
        if ctx is not None:
            ctx.__exit__(None, None, None)


def cmd_connector(*args: str) -> None:
    import argparse

    ap = argparse.ArgumentParser(prog="python -m soc_platform connector")
    ap.add_argument("action", choices=("new", "check"))
    ap.add_argument("name")
    ap.add_argument("--category")
    ap.add_argument("--tool", default="")
    ap.add_argument("--vendor", default="")
    a = ap.parse_args(list(args))
    from soc_platform.connectors import devkit

    if a.action == "new":
        if not a.category:
            sys.exit(f"--category is required: {', '.join(devkit.CATEGORIES)}")
        try:
            files = devkit.scaffold(a.name, a.category, a.tool, a.vendor)
        except ValueError as exc:
            sys.exit(str(exc))
        print("written:\n  " + "\n  ".join(str(f) for f in files))
        print(f"next: adapt the endpoint paths and fields to the vendor's API, then run "
              f"`python -m soc_platform connector check {a.name}`")
        return
    sys.exit(devkit.check(a.name))


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
