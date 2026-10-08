"""Load test: many analysts using the console at once, against a real server, while jobs write.

    python scripts/load_test.py [--users 40] [--seconds 60] [--db postgresql://...] [--json out.json]

A fresh database gets the demo organisation (``python -m soc_platform demo``), then a real uvicorn server starts on it
and ``--users`` virtual analysts work for ``--seconds``: each signs in with their own token from their own address
(sent through a trusted-proxy header, so per-client rate limits apply as in production) and loops over what an
analyst does - overview, case list, a case, its attack story, approvals, search, an entity, the brief - adding a note
now and then. Meanwhile an administrator replays the incident job every 15 s (background writes and model-free
re-investigation). Reported per endpoint: requests, p50 / p95 / p99 latency, errors; overall throughput, 429s and any
5xx. The run fails (exit 1) on any 5xx or request error.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import socket
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from collections import defaultdict
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
SECRET = "load-test-secret-0123456789abcdef0123456789"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def stop_tree(proc: subprocess.Popen) -> None:
    """Stop the server and its worker processes: terminating only the parent leaves uvicorn's workers running on
    Windows (they kept the port and the database open after earlier runs)."""
    if os.name == "nt":
        subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"], capture_output=True, check=False)
    else:
        import signal

        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    try:
        proc.wait(timeout=30)
    except subprocess.TimeoutExpired:
        proc.kill()


def pct(xs: list[float], p: float) -> float:
    if not xs:
        return 0.0
    xs = sorted(xs)
    return xs[min(len(xs) - 1, round(p / 100 * (len(xs) - 1)))]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--users", type=int, default=40)
    ap.add_argument("--seconds", type=int, default=60)
    ap.add_argument("--db", default=None, help="PostgreSQL URL (its tables are dropped and recreated)")
    ap.add_argument("--workers", type=int, default=4, help="server processes (SOC_API_WORKERS)")
    ap.add_argument("--json", default=None)
    a = ap.parse_args()

    tmp = Path(tempfile.mkdtemp(prefix="soc-load-"))
    db_url = a.db or f"sqlite:///{(tmp / 'load.db').as_posix()}"
    env = {**os.environ, "SOC_DATABASE_URL": db_url, "SOC_AUTH_MODE": "dev", "SOC_DEV_JWT_SECRET": SECRET,
           "SOC_ENVIRONMENT": "test", "SOC_LLM_PROVIDER": "none", "SOC_ORG_DOMAINS": "acme-demo.com",
           "SOC_RAW_PAYLOAD_DIR": str(tmp / "raw"), "SOC_REPORT_OUTPUT_DIR": str(tmp / "reports"),
           "SOC_PHISHING_ENGINE": "0", "SOC_EMBEDDED_SCHEDULER": "0", "SOC_TRUSTED_PROXIES": "127.0.0.1",
           "SOC_REQUIRE_MFA": "0"}
    env.pop("SOC_FIXTURES_DIR", None)
    if a.db:
        reset = (f"from soc_platform.core.db import Database, Base; d = Database({db_url!r}); d.create_all(); "
                 "Base.metadata.drop_all(d.engine)")
        subprocess.run([sys.executable, "-c", reset], cwd=ROOT, env=env, check=True)
    print("loading the demo organisation ...", flush=True)
    subprocess.run([sys.executable, "-m", "soc_platform", "demo"], cwd=ROOT, env=env, check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    port = free_port()
    base = f"http://127.0.0.1:{port}"
    srv = subprocess.Popen([sys.executable, "-m", "uvicorn", "soc_platform.api.app:app", "--host", "127.0.0.1",
                            "--port", str(port), "--log-level", "warning", "--workers", str(a.workers),
                            "--no-proxy-headers"], cwd=ROOT, env=env,
                           stdout=subprocess.DEVNULL, stderr=open(tmp / "server.log", "w"),   # noqa: SIM115
                           start_new_session=os.name != "nt")
    try:
        for _ in range(120):
            try:
                if httpx.get(base + "/health", timeout=2).status_code == 200:
                    break
            except httpx.HTTPError:
                time.sleep(0.5)
        else:
            print("server did not start; see", tmp / "server.log")
            return 1
        code = run(a, base, tmp)
    finally:
        stop_tree(srv)
    if code == 0:                                     # kept on failure: server.log explains it
        import shutil

        shutil.rmtree(tmp, ignore_errors=True)
    return code


def run(a, base: str, tmp: Path) -> int:
    def token(user: str, roles: str) -> str:
        return httpx.get(f"{base}/api/v1/dev/token", params={"user": user, "roles": roles}).json()["token"]

    admin = {"Authorization": "Bearer " + token("ops@acme-demo.com", "admin")}
    lead = {"Authorization": "Bearer " + token("lena@acme-demo.com", "lead")}
    cases = httpx.get(f"{base}/api/v1/cases", headers=lead).json()
    entities = [e["id"] for c in cases[:5] for e in httpx.get(f"{base}/api/v1/cases/{c['id']}", headers=lead).json()
                .get("entities", [])][:20]
    case_ids = [c["id"] for c in cases]
    stop = time.monotonic() + a.seconds
    lat: dict[str, list[float]] = defaultdict(list)
    codes: dict[str, dict[int, int]] = defaultdict(lambda: defaultdict(int))
    errors: list[str] = []
    lock = threading.Lock()

    def hit(client: httpx.Client, name: str, method: str, path: str, **kw) -> None:
        t0 = time.perf_counter()
        try:
            r = client.request(method, path, **kw)
            code = r.status_code
        except httpx.HTTPError as exc:
            code = -1
            with lock:
                errors.append(f"{name}: {type(exc).__name__}: {exc}")
        dt = (time.perf_counter() - t0) * 1000
        with lock:
            lat[name].append(dt)
            codes[name][code] += 1

    def analyst(i: int) -> None:
        rng = random.Random(i)
        role = "lead" if i % 5 == 0 else "analyst"
        hdr = {"Authorization": "Bearer " + token(f"analyst{i:03d}@acme-demo.com", role),
               "X-Forwarded-For": f"10.99.{i // 250}.{i % 250 + 1}"}           # each analyst from their own address
        with httpx.Client(base_url=base, headers=hdr, timeout=60) as c:
            while time.monotonic() < stop:
                cid = rng.choice(case_ids)
                step = rng.random()
                if step < 0.15:
                    hit(c, "overview", "GET", "/api/v1/dashboard/overview")
                elif step < 0.30:
                    hit(c, "case list", "GET", "/api/v1/cases")
                elif step < 0.45:
                    hit(c, "case", "GET", f"/api/v1/cases/{cid}")
                elif step < 0.53:
                    hit(c, "attack story", "GET", f"/api/v1/cases/{cid}/story")
                elif step < 0.63:
                    hit(c, "approvals", "GET", "/api/v1/actions", params={"status": "recommended,pending_approval"})
                elif step < 0.71:
                    hit(c, "search", "GET", "/api/v1/search", params={"q": rng.choice(["jane", "web01", "CVE-2021", "micros0ft"])})
                elif step < 0.78 and entities:
                    hit(c, "entity 360", "GET", f"/api/v1/entities/{rng.choice(entities)}/360")
                elif step < 0.84:
                    hit(c, "brief", "GET", "/api/v1/intelligence/brief")
                elif step < 0.90:
                    hit(c, "vulnerabilities", "GET", "/api/v1/vm/findings")
                elif step < 0.95:
                    hit(c, "add note", "POST", f"/api/v1/cases/{cid}/notes", json={"text": f"checked by analyst {i}"})
                else:
                    hit(c, "health", "GET", "/health")
                time.sleep(rng.uniform(0.05, 0.4))                         # reading time between clicks

    def jobs() -> None:
        with httpx.Client(base_url=base, headers={**admin, "X-Forwarded-For": "10.98.0.1"}, timeout=300) as c:
            while time.monotonic() < stop:
                hit(c, "incident job (admin)", "POST", "/api/v1/jobs/incident/run")
                time.sleep(15)

    threads = [threading.Thread(target=analyst, args=(i,)) for i in range(a.users)] + [threading.Thread(target=jobs)]
    t0 = time.monotonic()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    wall = time.monotonic() - t0
    total = sum(len(v) for v in lat.values())
    rows = []
    for name in sorted(lat):
        xs = lat[name]
        rows.append({"endpoint": name, "requests": len(xs), "p50_ms": round(statistics.median(xs)), "p95_ms": round(pct(xs, 95)),
                     "p99_ms": round(pct(xs, 99)), "codes": dict(codes[name])})
    five = sum(n for r in rows for c, n in r["codes"].items() if c >= 500 or c == -1)
    throttled = sum(n for r in rows for c, n in r["codes"].items() if c == 429)
    print(f"\n{a.users} analysts for {a.seconds} s ({a.workers} server processes): {total} requests, {total / wall:.0f}/s, {five} server errors, "
          f"{throttled} throttled (429)")
    print(f"  {'endpoint':24s} {'requests':>8s} {'p50 ms':>7s} {'p95 ms':>7s} {'p99 ms':>7s}  status codes")
    for r in rows:
        print(f"  {r['endpoint']:24s} {r['requests']:8d} {r['p50_ms']:7d} {r['p95_ms']:7d} {r['p99_ms']:7d}  {r['codes']}")
    for e in errors[:5]:
        print("  error:", e)
    if a.json:
        Path(a.json).write_text(json.dumps({"users": a.users, "seconds": a.seconds, "requests": total,
                                            "per_second": round(total / wall, 1), "server_errors": five,
                                            "throttled": throttled, "endpoints": rows}, indent=1), encoding="utf-8")
    if five:
        print("  server log:", tmp / "server.log")
    return 1 if five else 0


if __name__ == "__main__":
    sys.exit(main())
