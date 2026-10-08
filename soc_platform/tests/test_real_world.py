"""The whole platform in situations a demo never shows.

* an empty tenant - a new deployment, or tools with no data yet: every pipeline, screen read model, report and the
  brief work with zero records
* every tool down at once - a network outage or the proxy failing: pipelines finish, nothing crashes, connectors show
  their error, and a reported e-mail is still analysed from its own content
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from soc_platform.connectors.http import FixtureTransport
from soc_platform.connectors.registry import FIXTURES_DIR, ConnectorRegistry
from soc_platform.core.auth import Principal, Role
from soc_platform.core.db import Database

ROOT = Path(__file__).resolve().parents[2]
CORPUS = ROOT / "artifacts" / "phishing" / "corpus"
LEAD = Principal("lena@acme-demo.com", "Lena", frozenset({Role.LEAD}))


def _emptied(body: Any) -> Any:
    """The same response shape with every list empty (a tenant with nothing in it yet)."""
    if isinstance(body, list):
        return []
    if isinstance(body, dict):
        return {k: _emptied(v) for k, v in body.items()}
    return body


def _registry(transform) -> ConnectorRegistry:
    reg = ConnectorRegistry.all_fake()
    for name in reg.enabled_names():
        routes = json.loads((Path(FIXTURES_DIR) / f"{name}.json").read_text(encoding="utf-8")).get("routes", [])
        t = FixtureTransport(transform(routes), name)
        conn = reg.get(name)
        conn.http = t
        if hasattr(conn, "transports"):                 # threat-intel fusion: one transport per source
            conn.transports = {k: t for k in conn.transports}
    return reg


def _everything(db: Database, reg: ConnectorRegistry, tmp: Path) -> dict[str, Any]:
    """Every pipeline, read model, report and the self-check, as the jobs and screens run them."""
    from soc_platform.api.dashboards import connector_freshness, overview
    from soc_platform.core.selfcheck import run_self_check
    from soc_platform.domains.incident.service import IncidentService
    from soc_platform.domains.phishing.service import PhishingService
    from soc_platform.domains.vulnerability.misconfig import MisconfigurationService
    from soc_platform.domains.vulnerability.service import VulnerabilityService
    from soc_platform.intelligence.analyst import IntelligenceService
    from soc_platform.reporting.builder import build_report, get_template, list_templates, validate_spec

    out: dict[str, Any] = {}
    with db.session() as s:
        vm = VulnerabilityService(s, reg)
        out["vm"] = vm.refresh()
        mis = MisconfigurationService(s, reg)
        mis.refresh()
        mis.route(LEAD)
        inc = IncidentService(s, reg)
        out["ingest"] = inc.ingest()
        for c in inc.cluster():
            inc.investigate(c.id, narrate=False)
        ph = PhishingService(s, reg, org_domains=["acme-demo.com"], raw_dir=tmp / "raw")
        for sub in ph.ingest_reported():
            ph.process(sub.id, narrate=False)
        sub = ph.submit_raw((CORPUS / "cred_phish_lookalike.eml").read_bytes(), source="upload", reporter=LEAD.id)
        out["uploaded"] = ph.process(sub.id, narrate=False)
        intel = IntelligenceService(s, None, vm=vm)
        intel.refresh()
        out["brief"] = intel.analyst.brief()
        out["answer"] = intel.analyst.ask("Who is most at risk right now?")
        out["overview"] = overview(s, frozenset({"*"}))
        out["freshness"] = connector_freshness(s, reg)
        out["reports"] = {}
        for tpl in list_templates(s):
            spec = validate_spec(get_template(s, tpl["id"]))
            if not spec["needs_case"]:
                r = build_report(s, reg, {**spec, "id": tpl["id"]}, tmp / "reports", llm=None, by=LEAD.id,
                                 domains=frozenset({"*"}))
                out["reports"][tpl["id"]] = r
        out["self_check"] = run_self_check(s)
    return out


@pytest.fixture()
def db(tmp_path):
    d = Database(f"sqlite:///{(tmp_path / 'w.db').as_posix()}")
    d.create_all()
    return d


def test_an_empty_tenant_runs_every_pipeline_screen_and_report(db, tmp_path, monkeypatch):
    monkeypatch.setenv("SOC_RAW_PAYLOAD_DIR", str(tmp_path / "raw"))
    reg = _registry(lambda routes: [{**r, "body": _emptied(r.get("body"))} for r in routes])
    out = _everything(db, reg, tmp_path)
    assert out["self_check"]["ok"], [c for c in out["self_check"].get("checks", []) if not c.get("ok")]
    assert out["overview"] is not None and out["brief"]["summary"] and out["answer"]["answer"]
    assert out["reports"] and all(r.get("id") and r.get("sections") for r in out["reports"].values())
    case = out["uploaded"]["case"]
    assert case["verdict"] in ("malicious", "suspicious")          # judged from the message itself


def test_every_tool_down_at_once_degrades_without_crashing(db, tmp_path, monkeypatch):
    from soc_platform.connectors import base

    monkeypatch.setattr(base, "_sleep", lambda s: None)            # retries without waiting out the back-off
    monkeypatch.setenv("SOC_RAW_PAYLOAD_DIR", str(tmp_path / "raw"))
    down = [{"method": m, "path": ".*", "status": 503, "body": None} for m in ("GET", "POST", "PUT", "PATCH", "DELETE")]
    reg = _registry(lambda routes: down)
    out = _everything(db, reg, tmp_path)
    assert out["ingest"].errors                                    # the outage is reported, per stream
    assert any(f.get("state") in ("error", "stale", "never") for f in out["freshness"]) if isinstance(out["freshness"], list) \
        else out["freshness"]
    assert out["uploaded"]["case"]["verdict"] in ("malicious", "suspicious")   # still analysed from its content
    assert out["brief"]["summary"] and out["reports"]
    assert out["self_check"]["ok"], [c for c in out["self_check"].get("checks", []) if not c.get("ok")]
