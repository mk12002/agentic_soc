"""Every request commits before its response is sent.

FastAPI's default runs a dependency's cleanup (our commit) *after* the response. A real-server check found an
uploaded report's case missing from the very next case list in 28 of 40 tries, and a failed commit would still have
been reported to the client as success.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest

ROOT = Path(__file__).resolve().parents[2]


def _session_scopes(dependant, found):
    from soc_platform.api.app import db_session

    for d in dependant.dependencies:
        if d.call is db_session:
            found.append(d.scope)
        _session_scopes(d, found)
    return found


def test_every_route_commits_its_session_before_responding():
    from fastapi.routing import APIRoute

    from soc_platform.api.app import app

    checked = 0
    for route in app.routes:
        if isinstance(route, APIRoute):
            scopes = _session_scopes(route.dependant, [])
            assert all(sc == "function" for sc in scopes), f"{route.path}: session scope {scopes}"
            checked += bool(scopes)
    assert checked > 50                                     # the whole API, not a handful of routes


@pytest.mark.skipif(bool(os.environ.get("SOC_TEST_POSTGRES")), reason="real-server check runs on the SQLite pass")
def test_an_uploaded_report_is_readable_as_soon_as_the_upload_returns(tmp_path):
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    env = {**os.environ, "SOC_AUTH_MODE": "dev", "SOC_DEV_JWT_SECRET": "x" * 40, "SOC_ENVIRONMENT": "test",
           "SOC_DATABASE_URL": f"sqlite:///{(tmp_path / 'r.db').as_posix()}", "SOC_ORG_DOMAINS": "acme-demo.com",
           "SOC_RAW_PAYLOAD_DIR": str(tmp_path / "raw"), "SOC_REPORT_OUTPUT_DIR": str(tmp_path / "rep"),
           "SOC_EMBEDDED_SCHEDULER": "0", "SOC_LLM_PROVIDER": "none", "SOC_RATE_LIMIT_RPS": "1000"}
    srv = subprocess.Popen([sys.executable, "-m", "uvicorn", "soc_platform.api.app:app", "--port", str(port)],
                           cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    base = f"http://127.0.0.1:{port}"
    try:
        for _ in range(480):                                  # up to 120 s: a busy machine can start slowly
            try:
                httpx.get(base + "/health", timeout=2)
                break
            except httpx.HTTPError:
                time.sleep(0.25)
        tok = httpx.get(base + "/api/v1/dev/token?user=lena@acme-demo.com&roles=lead").json()["token"]
        with httpx.Client(headers={"Authorization": "Bearer " + tok}, timeout=60) as c:
            for i in range(15):
                mail = (f"From: a{i}@supplier.example\r\nTo: jane.doe@acme-demo.com\r\nSubject: report {i}\r\n"
                        f"Message-ID: <r{i}@supplier.example>\r\n\r\nhello\r\n").encode()
                case_id = c.post(base + "/api/v1/phishing/submit",
                                 files={"file": (f"r{i}.eml", mail, "message/rfc822")}).json()["case"]["id"]
                assert any(x["id"] == case_id for x in c.get(base + "/api/v1/cases").json()), f"upload {i} not committed"
    finally:
        srv.terminate()
        srv.wait(20)
