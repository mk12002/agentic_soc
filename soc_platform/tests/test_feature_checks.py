"""Direct checks for features otherwise covered only through the end-to-end walkthrough (see docs/FEATURE_VERIFICATION.md)."""

from __future__ import annotations

from pathlib import Path

from soc_platform.connectors.registry import ConnectorRegistry
from soc_platform.core.models import ActionRequest, Case, Entity

ROOT = Path(__file__).resolve().parents[2]


def _row(domain, verdict, cats, user="u@x.com", host="H1"):
    return {"domain": domain, "verdict": verdict, "timestamp": "2026-09-20T10:00:00Z",
            "categories": [{"label": c} for c in cats],
            "identities": [{"label": host, "type": {"type": "roaming"}}, {"label": user, "type": {"type": "directory_user"}}]}


def test_shadow_it_classifies_services_and_risky_destinations():
    """U11: sanctioned services excluded, remote access allowed = high risk, reached vs blocked risky sites."""
    from soc_platform.intelligence.shadow_it import analyse

    rows = [_row("anydesk.com", "allowed", ["Remote Access"]),
            _row("files.wetransfer.com", "allowed", ["File Storage"], user="a@x.com"),
            _row("wetransfer.com", "allowed", ["File Storage"], user="b@x.com"),
            _row("nordvpn.com", "blocked", ["Personal VPN"]),
            _row("tenant.sharepoint.com", "allowed", ["File Storage"]),          # sanctioned
            _row("teams.microsoft.com", "allowed", ["Business Services"]),     # not a watched category
            _row("evil.example", "allowed", ["Malware"]),
            _row("bad.example", "blocked", ["Phishing"])]
    r = analyse(rows, sanctioned={"sharepoint.com"})
    svc = {s["service"]: s for s in r["unsanctioned_services"]}
    assert set(svc) == {"anydesk.com", "wetransfer.com", "nordvpn.com"}
    assert svc["anydesk.com"]["risk"] == "high" and svc["nordvpn.com"]["risk"] == "low"   # blocked VPN = low
    assert svc["wetransfer.com"]["users"] == 2 and svc["wetransfer.com"]["requests"] == 2  # subdomains roll up
    status = {d["domain"]: d["status"] for d in r["risky_destinations"]}
    assert status == {"evil.example": "reached", "bad.example": "blocked"}
    assert r["summary"]["risky_destinations_reached"] == 1


def test_attack_coverage_reflects_enabled_tools_and_observed_alerts(session):
    """U09: blind spots appear when tools are removed; observed techniques are counted from real alerts."""
    from soc_platform.intelligence.attack_coverage import CAPABILITY, coverage

    full = coverage(session, list(CAPABILITY))
    assert full["summary"]["priority_blind_spots"] == 0
    dns_only = coverage(session, ["umbrella"])
    blind = {b["technique"] for b in dns_only["priority_blind_spots"]}
    assert {"T1059.001", "T1003.001", "T1486"} <= blind          # no EDR -> execution / credential / impact blind
    assert "T1071.004" not in blind                              # DNS C2 still covered by Umbrella
    session.add(Entity(kind="alert", canonical_key="x:alert:1", display_name="ps",
                       attributes={"tool": "defender_endpoint", "mitre_techniques": ["T1059.001", "T1059.001.x"]}))
    session.flush()
    row = next(t for tac in coverage(session, list(CAPABILITY))["tactics"] for t in tac["techniques"] if t["technique"] == "T1059.001")
    assert row["observed"] >= 1 and row["status"] == "firing" and "defender_endpoint" in row["observed_via"]


def test_block_sender_goes_through_the_exchange_admin_api():
    """PH-F11: sender block is a Tenant Allow/Block List entry via the Exchange admin API (own token audience live)."""
    reg = ConnectorRegistry.all_fake()
    spec = reg.action_registry().get("email.block_sender")
    out = spec.execute({"reason": "phishing campaign"}, [{"type": "indicator", "indicator_type": "domain",
                                                          "id": "evil.example", "value": "evil.example"}])
    assert out.get("blocked") == ["evil.example"] or "evil.example" in str(out)
    calls = reg.get("defender_office365").http.calls
    call = next(c for c in calls if "adminapi" in c["path"])
    assert call["path"].endswith("/InvokeCommand") and call["json"]["CmdletInput"]["CmdletName"] == "New-TenantAllowBlockListItems"


def test_phishing_verdict_is_explained_with_counterfactual_and_citations(session):
    """PH-F10 / NFR-02: every verdict carries a counterfactual and claims that cite real evidence."""
    from soc_platform.core.cases import CaseService
    from soc_platform.domains.phishing.service import PhishingService

    svc = PhishingService(session, ConnectorRegistry.all_fake(), org_domains=["cci-demo.com"])
    sub = svc.submit_raw((ROOT / "artifacts/phishing/corpus/cred_phish_lookalike.eml").read_bytes(), source="test")
    svc.process(sub.id)
    case = session.get(Case, sub.case_id)
    assert case.verdict == "malicious" and (case.assessment or {}).get("counterfactual")
    view = CaseService(session).view(case.id)
    refs = {e["ref"] for items in view["evidence"].values() for e in items}
    assert view["assessment"]["facts"] and all(set(c["evidence_ids"]) <= refs for c in view["assessment"]["facts"])


def test_incident_recommends_reversible_containment_and_read_only_forensics(session):
    """IM-F07 / IM-F10 / NFR-03: containment is reversible, forensic collection is recommended and read-only."""
    from soc_platform.domains.incident.service import IncidentService

    svc = IncidentService(session, ConnectorRegistry.all_fake())
    svc.ingest()
    cases = svc.cluster()
    for c in cases:
        svc.investigate(c.id)
    acts = session.query(ActionRequest).all()
    types = {a.action_type for a in acts}
    assert {"endpoint.isolate", "endpoint.collect_forensics"} <= types
    forensic = next(a for a in acts if a.action_type == "endpoint.collect_forensics")
    assert "read-only" in (forensic.result or {}).get("blast_radius", "")
    isolate = next(a for a in acts if a.action_type == "endpoint.isolate")
    assert (isolate.result or {}).get("reversible") is not False and isolate.status in {"recommended", "pending_approval"}


def test_compliance_pack_fails_when_a_control_is_violated(session):
    """U17: the evidence pack is not vacuous - a self-approved four-eyes action makes the control test fail."""
    from soc_platform.config import Settings
    from soc_platform.reporting.compliance import build_evidence

    def sod_result():
        ev = build_evidence(session, Settings(), period_days=30)
        return next(t for c in ev["controls"] for t in c["tests"] if t["test"].startswith("four-eyes"))["result"]

    assert sod_result() == "pass"
    session.add(ActionRequest(action_type="endpoint.isolate", targets=[{"id": "h1"}], requested_by="mallory",
                              approver="mallory", idempotency_key="k-selfapprove", status="executed",
                              policy_reasons=["configured level L2", "four-eyes: a second person must approve"]))
    session.flush()
    assert sod_result() == "fail"
