"""Measure how the platform scales with the volume of a tenant.

    python scripts/measure_scale.py [--scales 1,10,40] [--seed 7] [--db postgresql://...] [--json out.json]

For each scale a messy estate is generated (``build_estate_variant.py --messy``: more people, machines, sign-ins,
DNS events, alerts and findings, with real-tenant disorder) and the whole platform runs on it: every connector sync,
then the vulnerability, incident and phishing pipelines, the intelligence refresh, the overview dashboard and the
self-check. Per stage it reports wall time and SQL statements, and per stored record the statements of the sync -
a stage whose statements per record grow with the estate is the one that would not survive a large tenant.

Each scale runs in its own process (fresh caches, fresh database). SQLite by default; ``--db`` takes a PostgreSQL URL
whose database is reused (each run drops and recreates its tables).
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run_one(scale: float, seed: int, db_url: str | None) -> dict:
    """Child process: build the estate, run every stage, return the measurements."""
    import importlib.util

    tmp = Path(tempfile.mkdtemp(prefix=f"soc-scale-{scale:g}-"))
    spec = importlib.util.spec_from_file_location("build_estate_variant", ROOT / "scripts" / "build_estate_variant.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    est = json.loads((mod.main(str(tmp / "estate"), seed=seed, scale=scale, messy=True) / "estate.json").read_text())
    os.environ.update({"SOC_FIXTURES_DIR": est["fixtures_dir"], "SOC_SUPPLIERS_FILE": est["suppliers_file"],
                       "SOC_ORG_DOMAINS": est["org"], "SOC_LLM_PROVIDER": "none", "SOC_PHISHING_ENGINE": "0",
                       "SOC_EMBEDDED_SCHEDULER": "0", "SOC_RAW_PAYLOAD_DIR": str(tmp / "raw"),
                       "SOC_REPORT_OUTPUT_DIR": str(tmp / "reports"),
                       "SOC_DATABASE_URL": db_url or f"sqlite:///{(tmp / 'scale.db').as_posix()}"})
    sys.path.insert(0, str(ROOT))
    from sqlalchemy import event, func, select

    from soc_platform.api.dashboards import overview
    from soc_platform.connectors.base import SyncRunner
    from soc_platform.connectors.registry import ConnectorRegistry
    from soc_platform.core.context_store import ContextStore
    from soc_platform.core.db import Base, Database
    from soc_platform.core.models import Entity, SourceRecord, UnresolvedItem
    from soc_platform.core.selfcheck import run_self_check
    from soc_platform.domains.incident.service import IncidentService
    from soc_platform.domains.phishing.service import PhishingService
    from soc_platform.domains.vulnerability.misconfig import MisconfigurationService
    from soc_platform.domains.vulnerability.service import VulnerabilityService
    from soc_platform.intelligence.analyst import IntelligenceService

    db = Database(os.environ["SOC_DATABASE_URL"])
    db.create_all()                      # registers every model, so drop_all below knows the whole schema
    if db_url:
        Base.metadata.drop_all(db.engine)
        db.create_all()
    counter = {"n": 0}
    event.listen(db.engine, "before_cursor_execute", lambda *a, **k: counter.__setitem__("n", counter["n"] + 1))
    reg = ConnectorRegistry.all_fake()
    stages: list[dict] = []

    def stage(name: str, fn) -> None:
        n0, t0 = counter["n"], time.perf_counter()
        with db.session() as s:
            out = fn(s)
        stages.append({"stage": name, "seconds": round(time.perf_counter() - t0, 2), "statements": counter["n"] - n0,
                       **({"detail": out} if isinstance(out, dict) else {})})

    def sync_all(s):
        runner = SyncRunner(s, ContextStore(s))
        reps = runner.sync_many([(reg.get(n), st) for n in reg.enabled_names() for st in reg.get(n).streams])
        return {"records": sum(r.ingested for r in reps), "failed": sum(r.failed for r in reps),
                "errors": sorted({f"{r.connector}.{r.stream}" for r in reps if r.errors})}

    stage("sync every connector", sync_all)
    with db.session() as s:
        records = s.execute(select(func.count()).select_from(SourceRecord)).scalar()
        entities = s.execute(select(func.count()).select_from(Entity)).scalar()
        review = dict(s.execute(select(UnresolvedItem.reason, func.count()).where(UnresolvedItem.status == "open")
                                .group_by(UnresolvedItem.reason)).all())

    def vulnerability(s):
        VulnerabilityService(s, reg).refresh()
        MisconfigurationService(s, reg).refresh()

    stage("vulnerability refresh", vulnerability)

    def incidents(s):
        svc = IncidentService(s, reg)
        cases = svc.cluster()
        for c in cases:
            svc.investigate(c.id, narrate=False)
        return {"incident_cases": len(cases)}

    stage("incident pipeline", incidents)

    def phishing(s):
        svc = PhishingService(s, reg, org_domains=[est["org"]], raw_dir=tmp / "raw" / "phishing")
        subs = svc.ingest_reported()
        for sub in subs:
            svc.process(sub.id, narrate=False)
        return {"reported": len(subs)}

    stage("phishing pipeline", phishing)
    stage("intelligence refresh", lambda s: {"insights": len(IntelligenceService(s, None).refresh())})
    stage("overview dashboard", lambda s: overview(s, frozenset({"*"})) and None)
    stage("self-check", lambda s: {"ok": run_self_check(s).get("ok")})
    sync_stage = stages[0]
    db.engine.dispose()
    import shutil

    shutil.rmtree(tmp, ignore_errors=True)            # the estate and its database are tens of megabytes per scale
    return {"scale": scale, "people": est["extra_users"] + 10, "laptops": est["extra_laptops"], "messy": est["messy"],
            "source_records": records, "entities": entities, "review_queue": review,
            "sync_statements_per_record": round(sync_stage["statements"] / max(1, records), 2), "stages": stages}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--scales", default="1,10,40")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--db", default=None, help="PostgreSQL URL (default: a fresh SQLite file per scale)")
    ap.add_argument("--json", default=None, help="write the results here")
    ap.add_argument("--one", type=float, default=None, help=argparse.SUPPRESS)       # child process mode
    a = ap.parse_args()
    if a.one is not None:
        print("RESULT " + json.dumps(run_one(a.one, a.seed, a.db)))
        return
    results = []
    for sc in [float(x) for x in a.scales.split(",")]:
        cmd = [sys.executable, __file__, "--one", str(sc), "--seed", str(a.seed)] + (["--db", a.db] if a.db else [])
        out = subprocess.run(cmd, capture_output=True, text=True, cwd=ROOT, check=False)
        line = next((x for x in out.stdout.splitlines() if x.startswith("RESULT ")), None)
        if line is None:
            sys.exit(f"scale {sc} failed:\n{out.stderr[-3000:]}")
        r = json.loads(line[7:])
        results.append(r)
        print(f"\nscale {sc:g}: {r['people']} people, {r['laptops']} laptops, {r['source_records']} records, "
              f"{r['entities']} entities, {r['sync_statements_per_record']} statements per synced record, "
              f"{sum(r['review_queue'].values())} open review items {r['review_queue']}")
        for st in r["stages"]:
            print(f"  {st['stage']:24s} {st['seconds']:8.2f} s {st['statements']:9d} statements  {st.get('detail', '')}")
    if a.json:
        Path(a.json).write_text(json.dumps(results, indent=1), encoding="utf-8")


if __name__ == "__main__":
    main()
