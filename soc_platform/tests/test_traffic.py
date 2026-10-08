"""Traffic: many people and integrations using the platform at once.

Request load is measured by ``scripts/load_test.py`` (a real server, many analysts, jobs writing meanwhile); these
tests keep its findings fixed: the connection pool is sized for the server's request threads and checks connections
before use, a saturated or locked database answers 503 with Retry-After (a client retries) instead of hanging and
failing with 500, and a burst of concurrent analysts on a real multi-process server gets no server error.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest
from sqlalchemy.exc import OperationalError
from sqlalchemy.exc import TimeoutError as SQLATimeoutError

from soc_platform.core.db import Database

ROOT = Path(__file__).resolve().parents[2]


def test_the_connection_pool_is_sized_for_concurrent_requests_and_checks_connections(tmp_path, monkeypatch):
    # on a PostgreSQL run, the production engine against the real server (the harness's own engines use no pool)
    pg = os.environ.get("SOC_TEST_POSTGRES")
    url = (lambda n: pg) if pg else (lambda n: f"sqlite:///{(tmp_path / n).as_posix()}")
    db = Database(url("p.db"))
    assert db.engine.pool.size() == 20 and db.engine.pool._max_overflow == 20 and db.engine.pool._pre_ping
    monkeypatch.setenv("SOC_DB_POOL_SIZE", "50")
    monkeypatch.setenv("SOC_DB_POOL_RECYCLE", "600")
    db = Database(url("q.db"))
    assert db.engine.pool.size() == 50 and db.engine.pool._recycle == 600
    with db.engine.connect() as c:                                  # and it really connects
        assert c.exec_driver_sql("SELECT 1").scalar() == 1
    db.engine.dispose()


@pytest.fixture()
def client(tmp_path, monkeypatch):
    from soc_platform.api import app as appmod
    from soc_platform.config import get_settings
    from soc_platform.core import db as dbm

    for k, v in {"SOC_AUTH_MODE": "dev", "SOC_DEV_JWT_SECRET": "traffic-secret-0123456789abcdef0123",
                 "SOC_ENVIRONMENT": "test", "SOC_DATABASE_URL": f"sqlite:///{(tmp_path / 't.db').as_posix()}",
                 "SOC_LLM_PROVIDER": "none"}.items():
        monkeypatch.setenv(k, v)
    get_settings.cache_clear()
    monkeypatch.setattr(dbm, "_default", None)
    from fastapi.testclient import TestClient

    c = TestClient(appmod.app, raise_server_exceptions=False)
    tok = c.get("/api/v1/dev/token?user=lena@acme-demo.com&roles=lead").json()["token"]
    yield c, {"Authorization": f"Bearer {tok}"}, appmod
    get_settings.cache_clear()


@pytest.mark.parametrize("exc", [SQLATimeoutError("QueuePool limit reached"),
                                 OperationalError("SELECT 1", {}, Exception("database is locked"))])
def test_a_saturated_or_locked_database_answers_retry_later_not_a_server_error(client, monkeypatch, exc):
    c, h, appmod = client

    class Busy:
        def status(self):
            raise exc

    monkeypatch.setattr(appmod, "registry", lambda: Busy())
    r = c.get("/api/v1/connectors", headers=h)
    assert r.status_code == 503 and r.headers.get("retry-after") and "retry" in r.json()["detail"], r.text


def test_many_analysts_at_once_on_a_real_multi_process_server_get_no_server_error(tmp_path):
    """A short burst of the load test: 12 analysts with 2 server processes while the incident job runs."""
    env = {**os.environ, "SOC_RAW_PAYLOAD_DIR": str(tmp_path / "raw")}
    env.pop("SOC_DATABASE_URL", None)
    r = subprocess.run([sys.executable, str(ROOT / "scripts" / "load_test.py"), "--users", "12", "--seconds", "8",
                        "--workers", "2", "--json", str(tmp_path / "load.json")], cwd=ROOT, env=env,
                       capture_output=True, text=True, timeout=600, check=False)
    assert r.returncode == 0, r.stdout[-2000:] + r.stderr[-2000:]
    import json

    out = json.loads((tmp_path / "load.json").read_text())
    assert out["server_errors"] == 0 and out["requests"] > 100
    assert {e["endpoint"] for e in out["endpoints"]} >= {"overview", "case", "attack story", "add note", "brief"}
