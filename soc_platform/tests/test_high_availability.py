"""High availability: no part of the platform's state lives on one host's disk or in one process.

* stored files (reported e-mails, generated reports) in the database when ``SOC_BLOB_STORE=database``, readable by
  every replica, encrypted, integrity-checked, migrated from the file store without loss, removed by retention;
* job leases renewed while a job runs, and taken over quickly when the scheduler holding one dies;
* liveness that never depends on the database, readiness that does;
* production settings that warn about a host-local file store.
"""

from __future__ import annotations

import base64
import copy
import os
import threading
import time
from datetime import timedelta
from pathlib import Path

import pytest

from soc_platform.connectors.registry import ConnectorRegistry
from soc_platform.core.policy import DEFAULT_POLICY, PolicyEngine

ROOT = Path(__file__).resolve().parents[2]
KEY = base64.urlsafe_b64encode(b"h" * 32).decode()      # fixed test key (Fernet adds its own random IV per message)


def _set_env(values: dict[str, str | None]):
    """Apply env values and return a restore function that also resets the settings cache afterwards (restoring
    the environment first, then clearing, so no test leaks a cached database blob store)."""
    from soc_platform.config import get_settings

    saved = {k: os.environ.get(k) for k in values}
    for k, v in values.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v
    get_settings.cache_clear()

    def restore() -> None:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        get_settings.cache_clear()
    return restore


@pytest.fixture()
def db_blobs(request):
    restore = _set_env({"SOC_BLOB_STORE": "database", "SOC_DATA_KEY": KEY})
    request.addfinalizer(restore)


@pytest.fixture()
def file_blobs(request):
    restore = _set_env({"SOC_BLOB_STORE": "file", "SOC_DATA_KEY": KEY})
    request.addfinalizer(restore)


def _phishing(session, raw_dir):
    from soc_platform.domains.phishing.service import AutoClosePolicy, PhishingService

    pol = copy.deepcopy(DEFAULT_POLICY)
    return PhishingService(session, ConnectorRegistry.all_fake(), policy=PolicyEngine(pol), org_domains=["acme-demo.com"],
                           raw_dir=raw_dir, auto_close=AutoClosePolicy(sample_rate=0.0))


# ---------------------------------------------------------------------------------------------------- blob store


def test_a_reported_email_on_the_database_store_is_readable_by_any_replica(session, db_blobs, tmp_path):
    from soc_platform.core.blobstore import Blob

    a = _phishing(session, tmp_path / "replica_a")
    sub = a.ingest_reported()[0]
    assert sub.raw_path.startswith("db:phishing/") and not (tmp_path / "replica_a").exists()   # nothing on disk
    assert not sub.source_ref.startswith("db:") and a.ingest_reported() == []                  # replay still deduped
    row = session.get(Blob, sub.raw_path[3:])
    assert row.data.startswith(b"SOCENC1:") and b"Authentication-Results" not in row.data      # encrypted at rest
    first = a.process(sub.id)
    b = _phishing(session, tmp_path / "replica_b_never_saw_the_file")                          # another host
    again = b.process(sub.id, force=True)                                                      # re-reads the e-mail
    assert again["case"]["id"] != first["case"]["id"] and again["case"]["verdict"] == first["case"]["verdict"]


def test_a_tampered_database_blob_is_refused_not_served(session, db_blobs, tmp_path):
    from soc_platform.core.blobstore import Blob, BlobStore
    from soc_platform.core.crypto import DataProtectionError

    store = BlobStore(session)
    ref = store.put(tmp_path / "x.bin", "reports/x.bin", b"original content")
    assert store.get(ref) == b"original content"
    row = session.get(Blob, "reports/x.bin")
    row.sha256 = "0" * 64                                                   # stored checksum no longer matches
    session.flush()
    with pytest.raises(DataProtectionError):
        store.get(ref)


def test_reports_on_the_database_store_leave_no_local_file_and_download_everywhere(session, db_blobs, tmp_path):
    from soc_platform.core.blobstore import BlobStore
    from soc_platform.domains.vulnerability.service import VulnerabilityService
    from soc_platform.reporting.reports import ReportService

    run = ReportService(session, tmp_path / "out").daily_exposure(VulnerabilityService(session, ConnectorRegistry.all_fake()))
    assert run.path.startswith("db:reports/")
    assert not any(p.is_file() for p in (tmp_path / "out").rglob("*"))     # the scratch file was moved, not copied
    assert BlobStore(session).get(run.path)[:2] == b"PK"                     # a real .docx, decrypted


def test_file_store_blobs_migrate_into_the_database_without_loss_and_idempotently(session, file_blobs, tmp_path):
    from soc_platform.config import get_settings
    from soc_platform.core.blobstore import BlobStore, check_references, migrate_to_database

    sub = _phishing(session, tmp_path / "raw").ingest_reported()[0]
    original = Path(sub.raw_path).read_bytes()
    assert check_references(session)["file"] >= 1
    out = migrate_to_database(session)
    assert out["moved"] >= 1 and out["missing"] == [] and sub.raw_path.startswith("db:phishing/")
    assert Path(out["files"][0]).read_bytes() == original                    # the file itself is left for the caller
    restore = _set_env({"SOC_BLOB_STORE": "database"})
    try:
        assert get_settings().blob_store == "database"
        assert b"Authentication-Results" in BlobStore(session).get(sub.raw_path)
    finally:
        restore()
    again = migrate_to_database(session)
    assert again["moved"] == 0 and again["already"] >= 1                    # nothing moved twice
    assert check_references(session)["unreadable"] == []


def test_migration_reports_an_unreadable_file_instead_of_losing_the_record(session, file_blobs, tmp_path):
    from soc_platform.core.blobstore import migrate_to_database

    sub = _phishing(session, tmp_path / "raw").ingest_reported()[0]
    Path(sub.raw_path).unlink()                                            # e.g. a file on another host
    out = migrate_to_database(session)
    assert [m["table"] for m in out["missing"]] == ["ph_submissions"] and not sub.raw_path.startswith("db:")


def test_retention_removes_a_database_blob_with_its_record(session, db_blobs, tmp_path):
    from soc_platform.config import get_settings
    from soc_platform.core.blobstore import BlobStore
    from soc_platform.core.models import Case
    from soc_platform.core.retention import run_retention

    ph = _phishing(session, tmp_path)
    sub = ph.ingest_reported()[0]
    ph.process(sub.id)
    ref = sub.raw_path
    sub.received_at = sub.received_at - timedelta(days=get_settings().raw_retention_days + 1)
    session.get(Case, sub.case_id).status = "closed"
    session.flush()
    report = run_retention(session, get_settings())
    assert report["emails"] == 1 and sub.raw_path is None and not BlobStore(session).exists(ref)


def test_cli_blobs_check_and_migrate(tmp_path):
    import subprocess
    import sys

    env = {**os.environ, "SOC_DATABASE_URL": f"sqlite:///{(tmp_path / 'cli.db').as_posix()}", "SOC_BLOB_STORE": "file",
           "SOC_RAW_PAYLOAD_DIR": str(tmp_path / "raw"), "SOC_REPORT_OUTPUT_DIR": str(tmp_path / "rep"),
           "SOC_LOG_CONFIGURE": "0"}
    run = lambda *a: subprocess.run([sys.executable, "-m", "soc_platform", "blobs", *a], cwd=ROOT, env=env, check=False,
                                    capture_output=True, text=True, timeout=300)
    assert run("check").returncode == 0                                   # an empty database: nothing unreadable
    out = run("migrate")
    assert out.returncode == 0 and '"moved": 0' in out.stdout
    assert run("frobnicate").returncode != 0


# ---------------------------------------------------------------------------------------------------- job leases


def test_a_lease_is_renewed_only_by_its_holder(db):
    from soc_platform import jobs
    from soc_platform.core.models import SystemFlag

    assert jobs._lease(db, "incident")
    me = jobs._holder()
    with db.session() as s:
        before = s.get(SystemFlag, "job_lease:incident").value["until"]
    assert jobs._renew(db, "incident", me)
    with db.session() as s:
        assert s.get(SystemFlag, "job_lease:incident").value["until"] >= before
    assert not jobs._renew(db, "incident", "another-host:1:1")


def test_a_running_job_keeps_its_lease_and_no_other_scheduler_can_take_it(db, monkeypatch):
    from soc_platform import jobs
    from soc_platform.core.models import SystemFlag

    monkeypatch.setattr(jobs, "lease_seconds", lambda: 0.6)            # renewed every 0.2 s
    seen: list[str] = []
    stolen: list[bool] = []

    def body(name, s):
        deadline = time.monotonic() + 60                                # ends as soon as three renewals are seen
        while len(set(seen)) < 4 and time.monotonic() < deadline:
            with db.session() as x:
                seen.append(x.get(SystemFlag, "job_lease:incident").value["until"])
            t = threading.Thread(target=lambda: stolen.append(jobs._lease(db, "incident")))
            t.start()
            t.join()
            time.sleep(0.05)
        return {"renewals_seen": len(set(seen)) - 1}

    run = jobs.run_job("incident", db=db, body=body)
    assert run is not None and run.status == "ok" and run.summary["renewals_seen"] >= 3
    assert stolen and not any(stolen)                                     # every takeover attempt refused


def test_a_job_whose_scheduler_died_is_taken_over_after_one_lease(db, monkeypatch):
    from soc_platform import jobs
    from soc_platform.core.models import SystemFlag, utcnow

    dead = {"holder": "dead-host:1:1", "until": (utcnow() + timedelta(seconds=jobs.lease_seconds())).isoformat()}
    with db.session() as s:
        s.add(SystemFlag(name="job_lease:incident", value=dead, updated_by="scheduler", updated_at=utcnow()))
    body = lambda n, s: {"ran": True}
    assert jobs.run_job("incident", db=db, body=body) is None            # still within its lease
    monkeypatch.setenv("SOC_CLOCK_OFFSET_SECONDS", str(jobs.lease_seconds() + 5))
    run = jobs.run_job("incident", db=db, body=body)                       # lease expired: taken over
    assert run is not None and run.status == "ok"
    assert jobs.lease_seconds() <= 300                                     # minutes, not the old half hour


def test_a_lost_lease_is_noticed_and_reported(db, monkeypatch):
    from soc_platform import jobs
    from soc_platform.core.models import SystemFlag

    monkeypatch.setattr(jobs, "lease_seconds", lambda: 0.3)
    assert jobs._lease(db, "phishing")
    keeper = jobs._LeaseKeeper(db, "phishing", jobs._holder(), "t-lost")
    with db.session() as s:                                                # someone else now holds it
        s.get(SystemFlag, "job_lease:phishing").value = {"holder": "other:1:1", "until": "2999-01-01T00:00:00+00:00"}
    with keeper:
        keeper.thread.join(timeout=30)
    assert keeper.lost


# ---------------------------------------------------------------------------------------------------- health


@pytest.fixture()
def api(request, tmp_path):
    from fastapi.testclient import TestClient

    from soc_platform.core import db as dbm

    restore = _set_env({"SOC_AUTH_MODE": "dev", "SOC_DEV_JWT_SECRET": "ha-test-secret-0123456789abcdef0123456789",
                        "SOC_DATABASE_URL": f"sqlite:///{(tmp_path / 'ha.db').as_posix()}", "SOC_BLOB_STORE": "database",
                        "SOC_REPORT_OUTPUT_DIR": str(tmp_path / "rep"), "SOC_RAW_PAYLOAD_DIR": str(tmp_path / "raw"),
                        "SOC_ORG_DOMAINS": "acme-demo.com", "SOC_ENVIRONMENT": "test", "SOC_EMBEDDED_SCHEDULER": "0",
                        "SOC_CONNECTORS_CONFIG": str(ROOT / "config" / "connectors.yaml")})
    saved_db = dbm._default

    def done():
        dbm._default = saved_db
        restore()
        from soc_platform.api import app as appmod
        appmod.registry.cache_clear()
    request.addfinalizer(done)
    dbm._default = None
    from soc_platform.api import app as appmod

    appmod.registry.cache_clear()
    with TestClient(appmod.app) as c:
        yield c


def test_liveness_never_depends_on_the_database_and_readiness_does(api, monkeypatch):
    from sqlalchemy.exc import OperationalError

    from soc_platform.api import app as appmod

    assert api.get("/health/live").json()["status"] == "alive"
    assert api.get("/health/ready").status_code == 200

    class Down:
        def session(self):
            raise OperationalError("SELECT 1", {}, Exception("connection refused"))

    monkeypatch.setattr(appmod, "get_database", lambda: Down())
    r = api.get("/health/ready")
    assert r.status_code == 503 and r.headers["Retry-After"] and r.json()["status"] == "not_ready"
    assert api.get("/health/live").status_code == 200                      # no restart storm during an outage


def test_a_report_built_by_one_replica_downloads_through_another(api):
    def tok(user, roles):
        return {"Authorization": "Bearer " + api.get(f"/api/v1/dev/token?user={user}&roles={roles}").json()["token"]}

    a = tok("alice", "analyst")
    api.post("/api/v1/vm/refresh", headers=a)
    run = api.post("/api/v1/reports/daily_exposure", headers=a).json()
    assert run["path"].startswith("db:reports/")
    r = api.get(f"/api/v1/reports/{run['id']}/download", headers=a)        # served from the database, not a disk
    assert r.status_code == 200 and r.content[:2] == b"PK" and "attachment" in r.headers["content-disposition"]


def test_a_download_whose_blob_is_gone_answers_404_not_500(api):
    from soc_platform.core.blobstore import Blob
    from soc_platform.core.db import get_database

    a = {"Authorization": "Bearer " + api.get("/api/v1/dev/token?user=alice&roles=analyst").json()["token"]}
    run = api.post("/api/v1/reports/daily_exposure", headers=a).json()
    with get_database().session() as s:
        s.delete(s.get(Blob, run["path"][3:]))
    assert api.get(f"/api/v1/reports/{run['id']}/download", headers=a).status_code == 404


# ---------------------------------------------------------------------------------------------------- settings


def test_production_warns_about_a_host_local_file_store_and_validates_the_new_settings():
    from soc_platform.settings_check import check_environment

    prod = {"SOC_ENVIRONMENT": "prod", "SOC_AUTH_MODE": "entra", "SOC_ENTRA_TENANT_ID": "t", "SOC_ENTRA_AUDIENCE": "a",
            "SOC_DATA_KEY": KEY, "SOC_DATABASE_URL": "postgresql://u@db/soc"}
    names = lambda env: {(p.level, p.name) for p in check_environment(env)}
    assert ("warning", "SOC_BLOB_STORE") in names(prod)
    assert ("warning", "SOC_BLOB_STORE") not in names({**prod, "SOC_BLOB_STORE": "database"})
    assert ("error", "SOC_BLOB_STORE") in names({**prod, "SOC_BLOB_STORE": "s3"})
    assert ("error", "SOC_JOB_LEASE_SECONDS") in names({**prod, "SOC_JOB_LEASE_SECONDS": "5"})
    assert ("error", "SOC_SCHEDULER_STUCK_SECONDS") in names({**prod, "SOC_SCHEDULER_STUCK_SECONDS": "abc"})


# ---------------------------------------------------------------------------------------------------- start-up


def test_many_processes_creating_the_schema_at_once_all_succeed(tmp_path):
    """A fresh deployment starts every replica's workers together; each creates the schema on first use. They must
    take turns (PostgreSQL advisory lock) or retry a lost race (SQLite), never fail a first request."""
    from concurrent.futures import ThreadPoolExecutor

    from sqlalchemy import inspect

    from soc_platform.core.db import Database

    url = f"sqlite:///{(tmp_path / 'fresh.db').as_posix()}"
    start = threading.Barrier(8)
    processes = [Database(url) for _ in range(8)]                         # one engine each, like separate processes

    def boot(d: Database) -> int:
        start.wait(timeout=60)                                            # all eight begin at the same moment
        d.create_all()
        return len(inspect(d.engine).get_table_names())

    with ThreadPoolExecutor(max_workers=8) as pool:
        counts = list(pool.map(boot, processes))
    assert len(set(counts)) == 1 and counts[0] > 20 and "blobs" in inspect(Database(url).engine).get_table_names()


def test_signed_in_analysts_keep_working_when_the_entra_key_endpoint_is_unreachable(monkeypatch):
    import json
    import time as _time

    import jwt
    from cryptography.hazmat.primitives.asymmetric import rsa

    from soc_platform.config import Settings
    from soc_platform.core import auth

    tenant, aud = "11111111-2222-3333-4444-555555555555", "api://soc-platform"
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    jwks = {"keys": [{**jwk, "kid": "k1", "use": "sig", "alg": "RS256"}]}
    calls = {"n": 0, "down": False}

    def fetch(self):
        calls["n"] += 1
        if calls["down"]:
            raise jwt.PyJWKClientConnectionError("login.microsoftonline.com unreachable")
        return jwks

    monkeypatch.setattr(jwt.PyJWKClient, "fetch_data", fetch)
    auth._jwks_client.cache_clear()
    st = Settings(auth_mode="entra", entra_tenant_id=tenant, entra_audience=aud, environment="prod")
    now = int(_time.time())
    claims = {"oid": "u-1", "preferred_username": "analyst@example.com", "roles": ["SOC.Analyst"], "amr": ["mfa"],
              "aud": aud, "iss": f"https://login.microsoftonline.com/{tenant}/v2.0", "iat": now, "exp": now + 600}
    token = jwt.encode(claims, key, algorithm="RS256", headers={"kid": "k1"})
    try:
        assert auth.principal_from_token(token, st).id == "u-1"
        calls["down"] = True                                              # Entra's key endpoint goes away ...
        auth._jwks_client(tenant).jwk_set_cache = None                     # ... and the key-set cache has expired
        assert auth.principal_from_token(token, st).id == "u-1"            # the known key still validates
    finally:
        auth._jwks_client.cache_clear()


def test_a_job_that_runs_past_the_stuck_threshold_stops_renewing_so_another_scheduler_can_retry(db, monkeypatch):
    from soc_platform import jobs

    monkeypatch.setattr(jobs, "lease_seconds", lambda: 0.3)
    monkeypatch.setattr(jobs, "stuck_seconds", lambda: 0.5)
    assert jobs._lease(db, "incident")
    keeper = jobs._LeaseKeeper(db, "incident", jobs._holder(), "t-stuck")
    with keeper:
        keeper.thread.join(timeout=30)                                     # it ends by itself once "stuck"
    assert keeper.gave_up and not keeper.lost


def _sync_alerts(session):
    from soc_platform.connectors.base import SyncRunner
    from soc_platform.core.context_store import ContextStore
    from soc_platform.core.models import SourceRecord

    SyncRunner(session, ContextStore(session), commit_pages=False).sync(ConnectorRegistry.all_fake().get("crowdstrike"), "alerts")
    return session.query(SourceRecord).filter(SourceRecord.tool == "crowdstrike").all()


def test_original_vendor_payloads_are_not_kept_unless_switched_on(session, db_blobs):
    rows = _sync_alerts(session)
    assert rows and all(r.raw_ref is None for r in rows)


def test_switched_on_original_payloads_go_to_the_blob_store_and_follow_raw_retention(session, request):
    from soc_platform.config import get_settings
    from soc_platform.core.blobstore import BlobStore
    from soc_platform.core.context_store import RawStore
    from soc_platform.core.retention import run_retention

    request.addfinalizer(_set_env({"SOC_BLOB_STORE": "database", "SOC_DATA_KEY": KEY, "SOC_STORE_RAW_PAYLOADS": "1"}))
    rows = _sync_alerts(session)
    assert rows and all(r.raw_ref.startswith(f"db:raw/crowdstrike/{r.source_type}/") for r in rows)
    original = RawStore("unused", session=session).get(rows[0].raw_ref)
    assert isinstance(original, dict) and original                          # the vendor's own JSON, decrypted
    for r in rows:
        r.fetched_at = r.fetched_at - timedelta(days=get_settings().raw_retention_days + 1)
    session.flush()
    refs = [r.raw_ref for r in rows]
    assert run_retention(session, get_settings())["raw_payloads"] == len(rows)
    assert not any(BlobStore(session).exists(ref) for ref in refs)


def test_the_scheduler_touches_its_liveness_file_only_while_its_threads_run(db, tmp_path, monkeypatch):
    from soc_platform import scheduler as sched

    alive = tmp_path / "alive"
    monkeypatch.setenv("SOC_SCHEDULER_LIVENESS_FILE", str(alive))
    sc = sched.Scheduler(db)
    sc._touch_liveness()
    assert not alive.exists()                                              # not started: no threads, no touch
    monkeypatch.setattr(sc, "run_due", list)                               # no jobs: only the threads matter here
    sc.start(start_delay=3600)
    try:
        deadline = time.monotonic() + 60
        while not alive.exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        assert alive.exists()
    finally:
        sc.shutdown()


# ---------------------------------------------------------------------------------------------------- one sync per stream


def _file_db(tmp_path):
    from soc_platform.core.db import Database

    d = Database(f"sqlite:///{(tmp_path / 'sync.db').as_posix()}")
    d.create_all()
    return d


def test_a_stream_held_by_another_replica_is_waited_for_then_skipped_and_the_lease_is_released(tmp_path, monkeypatch):
    from soc_platform.connectors.base import SyncRunner
    from soc_platform.core.context_store import ContextStore
    from soc_platform.core.models import SystemFlag, utcnow

    d = _file_db(tmp_path)
    conn = ConnectorRegistry.all_fake().get("crowdstrike")
    key = SyncRunner._lease_key("crowdstrike", "alerts")
    with d.session() as s:                                                 # another replica is syncing it
        s.add(SystemFlag(name=key, value={"holder": "other:1:1", "until": (utcnow() + timedelta(minutes=5)).isoformat()},
                         updated_by="sync", updated_at=utcnow()))
    monkeypatch.setenv("SOC_SYNC_LOCK_WAIT_SECONDS", "1")
    with d.session() as s:
        rep = SyncRunner(s, ContextStore(s)).sync(conn, "alerts")
        assert rep.skipped and rep.pages == 0 and rep.waited_seconds >= 1
    with d.session() as s:                                                 # the other replica finishes
        s.get(SystemFlag, key).value = {"holder": None, "until": utcnow().isoformat()}
    with d.session() as s:
        rep = SyncRunner(s, ContextStore(s)).sync(conn, "alerts")
        assert rep.skipped is None and rep.pages >= 1 and rep.ingested >= 1
    with d.session() as s:
        assert s.get(SystemFlag, key).value["holder"] is None              # released after the sync


def test_two_syncs_of_one_stream_at_once_take_turns_and_both_complete(tmp_path):
    """The Docker check found this: the scheduler and the demo synced the same stream together and one failed on a
    duplicate first checkpoint. Now they take turns, and the second continues from the first's checkpoint."""
    from concurrent.futures import ThreadPoolExecutor

    from soc_platform.connectors.base import SyncRunner
    from soc_platform.core.context_store import ContextStore
    from soc_platform.core.models import ConnectorCheckpoint, SourceRecord

    d = _file_db(tmp_path)
    start = threading.Barrier(2)

    def run(_):
        conn = ConnectorRegistry.all_fake().get("rapid7")
        with d.session() as s:
            start.wait(timeout=60)
            r = SyncRunner(s, ContextStore(s)).sync(conn, "assets")
            return r.skipped, r.errors
    with ThreadPoolExecutor(2) as pool:
        results = list(pool.map(run, range(2)))
    assert results == [(None, []), (None, [])]
    with d.session() as s:
        assert s.query(ConnectorCheckpoint).filter_by(connector="rapid7", stream="assets").count() == 1
        ids = [r.source_id for r in s.query(SourceRecord).filter_by(tool="rapid7").all()]
        assert ids and len(ids) == len(set(ids))                           # no record stored twice


def test_production_refuses_unsealed_blobs_and_reencrypt_seals_them_and_retires_a_key(tmp_path):
    """Stored data without the encryption marker used to be returned as "legacy plaintext" - anyone able to write to
    the store could swap a sealed report for their own. In production it is refused; `blobs reencrypt` seals it and
    moves everything to the newest key, after which the old key can be removed."""
    import hashlib

    from cryptography.fernet import Fernet

    from soc_platform.config import Settings
    from soc_platform.core.blobstore import Blob, BlobStore, reencrypt
    from soc_platform.core.crypto import DataProtectionError
    from soc_platform.core.db import Database
    from soc_platform.core.models import utcnow

    old, new = Fernet.generate_key().decode(), Fernet.generate_key().decode()
    db = Database(f"sqlite:///{(tmp_path / 'b.db').as_posix()}")
    db.create_all()
    st = lambda keys: Settings(environment="prod", data_keys=keys, blob_store="database")
    with db.session() as s:
        BlobStore(s, st([old])).put("unused", "reports/a.docx", b"sealed report")
        s.add(Blob(key="reports/legacy.docx", data=b"plain", size=5, sha256=hashlib.sha256(b"plain").hexdigest(),
                   created_at=utcnow()))
    with db.session() as s:
        with pytest.raises(DataProtectionError):
            BlobStore(s, st([old])).get("db:reports/legacy.docx")
        out = reencrypt(s, st([new, old]))
        assert out["database"] == 2 and not out["unreadable"]
    with db.session() as s:
        only_new = BlobStore(s, st([new]))
        assert only_new.get("db:reports/a.docx") == b"sealed report"
        assert only_new.get("db:reports/legacy.docx") == b"plain"
