"""Rapid7 vulnerability exceptions: paging, and what the platform does with a scanner's own accepted-risk records."""

from soc_platform.connectors.registry import ConnectorRegistry
from soc_platform.domains.vulnerability.models import ConsolidatedFinding
from soc_platform.domains.vulnerability.service import VulnerabilityService
from soc_platform.tests.test_connector_conformance import demo_route, demo_routes, fresh, reroute, sync

PAGING_TESTED = {("rapid7", "exceptions")}


def test_rapid7_exceptions_page_by_page_number_and_are_read_in_full_each_sync(session):
    src = demo_route("rapid7", "GET", "/api/3/vulnerability_exceptions")
    rows = src["body"]["resources"]
    routes = [{**src, "times": 1, "body": {"resources": rows[:1], "page": {"number": 0, "totalPages": 2}}},
              {**src, "body": {"resources": rows[1:], "page": {"number": 1, "totalPages": 2}}},
              *[r for r in demo_routes("rapid7") if r["path"] != src["path"]]]
    conn = fresh("rapid7", routes)
    rep, cp = sync(session, conn, "exceptions")
    assert not rep.errors and rep.pages == 2 and rep.ingested == len(rows), rep.errors
    assert [c["params"]["page"] for c in conn.http.calls if c["path"] == "/api/3/vulnerability_exceptions"] == [0, 1]
    assert cp.cursor is None                                   # state and expiry change: never resumed mid-list
    t = reroute(conn, routes)
    sync(session, conn, "exceptions")
    assert next(c for c in t.calls if c["path"] == "/api/3/vulnerability_exceptions")["params"]["page"] == 0


def test_a_scanner_exception_is_shown_on_its_finding_but_never_closes_or_suppresses_it(session, monkeypatch):
    """VM-02: accepted risk is not fixed, and an exception past its expiry must not suppress active risk."""
    monkeypatch.setenv("SOC_CLOCK_FREEZE", "2026-10-01T00:00:00+00:00")   # between the two expiry dates, for good
    vm = VulnerabilityService(session, ConnectorRegistry.all_fake())
    vm.refresh()
    held = {}
    for f in session.query(ConsolidatedFinding):
        ex = (f.sources.get("rapid7") or {}).get("tool_exception")
        if ex:
            held[(f.asset_name, f.cve)] = (ex, f.status)
    assert len(held) == 2, held
    states = sorted((ex["in_force"], ex["expired"]) for ex, _ in held.values())
    assert states == [(False, True), (True, False)]            # one in force, one past its expiry
    assert all(status in {"open", "reopened"} for _, status in held.values())   # neither is closed or accepted
    expired = next(ex for ex, _ in held.values() if ex["expired"])
    assert expired["reason"] and expired["expires"]
