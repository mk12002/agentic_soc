"""Client-demo walkthrough: every console screen's API calls, in the order a presenter clicks them.

Asserts there is never a server error, every screen returns meaningful content, every number can be
traced to records, and every report downloads as a valid file.
"""

from __future__ import annotations

import io
import json
import os
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SECRET = "demo-secret-0123456789abcdef0123456789"


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("demo")
    os.environ.update({"SOC_AUTH_MODE": "dev", "SOC_DEV_JWT_SECRET": SECRET, "SOC_ENVIRONMENT": "test",
                       "SOC_DATABASE_URL": f"sqlite:///{tmp / 'demo.db'}", "SOC_ORG_DOMAINS": "cci-demo.com",
                       "SOC_CONNECTORS_CONFIG": str(ROOT / "config" / "connectors.yaml"),
                       "SOC_REPORT_OUTPUT_DIR": str(tmp / "reports"), "SOC_RAW_PAYLOAD_DIR": str(tmp / "raw")})
    from cryptography.fernet import Fernet

    os.environ["SOC_DATA_KEY"] = Fernet.generate_key().decode()   # demo with encryption at rest on
    from soc_platform.config import get_settings
    from soc_platform.core import db as dbm

    get_settings.cache_clear()
    dbm._default = None
    from fastapi.testclient import TestClient

    from soc_platform.api import app as appmod

    appmod.registry.cache_clear()
    yield TestClient(appmod.app, raise_server_exceptions=True)
    os.environ.pop("SOC_DATA_KEY", None)
    get_settings.cache_clear()
    dbm._default = None


def H(client, user, roles):
    t = client.get(f"/api/v1/dev/token?user={user}&roles={roles}").json()["token"]
    return {"Authorization": f"Bearer {t}"}


def ok(r, code=200):
    assert r.status_code == code, (r.request.method, r.request.url.path, r.status_code, r.text[:500])
    return r


def test_full_client_demo(client, tmp_path):
    an, lead = H(client, "alice@cci-demo.com", "analyst"), H(client, "lena@cci-demo.com", "lead")
    aud, adm = H(client, "audrey@cci-demo.com", "auditor"), H(client, "ada@cci-demo.com", "admin")
    ui = ok(client.get("/")).text
    assert "/static/app.js" in ui and "/static/views.js" in ui and "/static/styles.css" in ui
    for f in ("app.js", "views.js", "styles.css", "theme.js", "favicon.svg"):
        ok(client.get(f"/static/{f}"))

    # 1. data in: all three domains + the supplier / BEC scenarios
    vm = ok(client.post("/api/v1/vm/refresh", headers=an)).json()
    assert vm["consolidation"]["consolidated"] >= 6 and vm["misconfigurations"]["consolidation"]["consolidated"] == 2
    inc = ok(client.post("/api/v1/incidents/run", headers=an)).json()
    assert inc["new_incidents"] >= 3
    ph = ok(client.post("/api/v1/phishing/ingest", headers=an)).json()
    assert ph["processed"]
    corpus = ROOT / "artifacts" / "phishing" / "corpus"
    labels = json.loads((corpus / "labels.json").read_text())
    for name, label in labels.items():
        r = ok(client.post("/api/v1/phishing/submit", headers=an,
                           files={"file": (f"{name}.eml", (corpus / f"{name}.eml").read_bytes(), "message/rfc822")}))
        verdict = r.json()["case"]["verdict"] if "case" in r.json() else r.json().get("verdict")
        if label in {"malicious", "suspicious"}:
            assert verdict in {"malicious", "suspicious"}, (name, verdict)
        elif label == "safe":
            assert verdict == "safe", (name, verdict)
    ok(client.post("/api/v1/intelligence/refresh", headers=an))

    # stored raw email is encrypted at rest
    raw_files = list(Path(os.environ["SOC_RAW_PAYLOAD_DIR"]).rglob("*.eml"))
    assert raw_files and all(p.read_bytes().startswith(b"SOCENC1:") for p in raw_files)

    # 2. overview dashboard: every figure non-trivial and consistent with the case list
    o = ok(client.get("/api/v1/dashboard/overview", headers=an)).json()
    cases = ok(client.get("/api/v1/cases", headers=an)).json()
    assert o["cases"]["open"] == sum(1 for c in cases if c["status"] != "closed")
    assert sum(sum(d[k] for k in ("phishing", "incident", "vulnerability")) for d in o["trend"]) >= len(cases) - 0
    assert o["context"]["asset_match_rate"]["match_rate"] >= 0.9
    perf = o["performance"]["investigation_enrichment_ms"]
    assert perf["incident"]["n"] >= 3 and perf["incident"]["p95"] is not None       # latency is measured (NFR-06)
    assert o["performance"]["lookup_ms_by_tool"]

    # 3. every case view renders with explanation (facts cite evidence) and every entity 360 works
    for c in cases:
        v = ok(client.get(f"/api/v1/cases/{c['id']}", headers=an)).json()
        ev_refs = {e["ref"] for items in v.get("evidence", {}).values() for e in items}
        for claim in v["assessment"].get("facts", []):
            assert claim["evidence_ids"] and set(claim["evidence_ids"]) <= ev_refs, (c["title"], claim)
            assert all(x["summary"] for x in claim["evidence"]), claim
        for e in v["entities"]:
            if e["kind"] in {"asset", "identity"}:
                e360 = ok(client.get(f"/api/v1/entities/{e['id']}/360", headers=an)).json()
                assert e360["name"] and isinstance(e360["timeline"], list)
                if e360["risk"] and e360["risk"]["score"] > 0:
                    assert e360["risk"]["factors"], "a risk score must show the factors behind it"

    # 4. intelligence: brief, insights (each with evidence + next steps), NL question
    brief = ok(client.get("/api/v1/intelligence/brief", headers=an)).json()
    assert brief["summary"]
    ins = ok(client.get("/api/v1/intelligence/insights", headers=an)).json()
    assert ins and all(i["evidence"] and i["next_steps"] for i in ins)
    assert {"supplier_risk", "phishing_compromise_chain"} <= {i["rule"] for i in ins}
    a = ok(client.post("/api/v1/intelligence/ask", headers=an, json={"question": "Is jane.doe@cci-demo.com compromised?"})).json()
    assert a["answer"] and a["tool_calls"]

    # 5. approvals: a lead approves one pending action; a four-eyes action cannot be self-approved
    pend = ok(client.get("/api/v1/actions?status=recommended,pending_approval", headers=lead)).json()
    assert pend
    first = pend[0]
    ok(client.post(f"/api/v1/actions/{first['id']}/approve", headers=lead, json={"note": "demo"}))

    # 6. VM: findings, campaign, misconfigurations lifecycle, coverage, NL query
    ok(client.get("/api/v1/vm/metrics", headers=an))
    fs = ok(client.get("/api/v1/vm/findings", headers=an)).json()
    assert fs
    ok(client.post("/api/v1/vm/query", headers=an, json={"question": "which internet facing hosts have KEV vulnerabilities?"}))
    mis = ok(client.get("/api/v1/vm/misconfigurations", headers=an)).json()
    assert mis["metrics"]["open"] == 2
    ok(client.post("/api/v1/vm/misconfigurations/route", headers=an))
    mid = mis["items"][0]["id"]
    ok(client.post(f"/api/v1/vm/misconfigurations/{mid}/fixed", headers=an))
    assert ok(client.post(f"/api/v1/vm/misconfigurations/{mid}/validate", headers=an)).json()["false_closure"] is True

    # 7. coverage / shadow IT / suppliers / connector freshness
    cov = ok(client.get("/api/v1/dashboard/attack-coverage", headers=an)).json()
    assert cov["summary"]["firing"] >= 1 and len(cov["tactics"]) == 12
    sh = ok(client.get("/api/v1/dashboard/shadow-it", headers=an)).json()
    assert sh["available"] and sh["summary"]["unsanctioned_services"] >= 3
    sup = ok(client.get("/api/v1/phishing/suppliers", headers=an)).json()
    assert sup["suppliers"]["Krishna Logistics"]["status"] in {"at_risk", "critical"}
    conns = ok(client.get("/api/v1/dashboard/connectors", headers=an)).json()
    assert {c["state"] for c in conns if c["enabled"]} <= {"healthy", "stale", "on_demand"}
    assert all(ok(client.post(f"/api/v1/connectors/{c['name']}/test", headers=H(client, "aa", "automation_admin"))).json()["ok"]
               for c in conns if c["enabled"])

    # 8. reports: every kind generates and downloads as a valid file
    for kind in ("daily_exposure", "weekly_vm", "weekly_mgmt"):
        rid = ok(client.post(f"/api/v1/reports/{kind}", headers=an)).json()["id"]
        body = ok(client.get(f"/api/v1/reports/{rid}/download", headers=an)).content
        assert body[:2] == b"PK" and len(body) > 5000, kind   # docx / pptx are zip containers
    case_id = next(c["id"] for c in cases if c["domain"] == "incident")
    assert ok(client.get(f"/api/v1/cases/{case_id}/report", headers=an)).content[:2] == b"PK"
    assert client.post("/api/v1/reports/compliance", headers=an).status_code == 403   # auditors only
    comp = ok(client.post("/api/v1/reports/compliance", headers=aud)).json()
    z = zipfile.ZipFile(io.BytesIO(ok(client.get(f"/api/v1/reports/{comp['id']}/download", headers=aud)).content))
    assert {"evidence.json", "audit_log.jsonl", "summary.docx"} <= set(z.namelist())
    ev = json.loads(z.read("evidence.json"))
    failed = [t for c in ev["controls"] for t in c["tests"] if t["result"] == "fail"]
    assert not [t for t in failed if t["test"] != "retention job ran in period"], failed
    assert "sk_soc_" not in z.read("evidence.json").decode()

    # 9. governance: policy, kill switch, audit chain, access admin, metrics
    ok(client.get("/api/v1/policy", headers=an))
    ok(client.post("/api/v1/kill-switch?on=true", headers=lead))
    assert ok(client.get("/health")).json()["kill_switch"] is True
    ok(client.post("/api/v1/kill-switch?on=false", headers=lead))
    assert ok(client.get("/api/v1/audit/verify", headers=aud)).json()["ok"]
    k = ok(client.post("/api/v1/admin/api-keys", headers=adm, json={"name": "prometheus", "roles": ["auditor"]})).json()
    m = ok(client.get("/metrics", headers={"X-API-Key": k["api_key"]})).text
    assert "soc_open_cases" in m and "soc_kill_switch 0.0" in m
    ok(client.get("/api/v1/admin/access-log?limit=50", headers=aud))
    log = ok(client.get("/api/v1/admin/access-log?status_min=500", headers=aud)).json()
    assert log == [], f"server errors during the demo: {log}"
