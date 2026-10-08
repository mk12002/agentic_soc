"""Every connector against the API behaviour a real tenant has and the demo fixtures do not show.

* paging     - each stream read across two pages in its vendor's own style (OData next links, offsets, page numbers,
               GraphQL cursors, scroll ids, page tokens), then a second sync that resumes correctly: from a time
               watermark where the API offers one, otherwise from the start - never from an expired continuation token
* throttling - a 429 with Retry-After is waited out and the sync completes
* tokens     - a refused (expired / rotated) token is renewed once and the sync completes
* permission - a 403 stops the stream at once (no retry storm) and the health check names the permission to grant
* fields     - removing any field of a record, or setting it to null, never crashes the normaliser
* coverage   - every (connector, stream) pair is in the paging table or listed with the reason it has no paging
"""

from __future__ import annotations

import copy
import json
import threading
from datetime import timedelta
from pathlib import Path

import httpx
import pytest

from soc_platform.connectors.base import (
    AuthExpired,
    BaseConnector,
    ConnectorError,
    Page,
    PermissionDenied,
    RateLimited,
    SyncRunner,
    TransientError,
)
from soc_platform.connectors.http import FixtureTransport, HttpTransport, OAuth2ClientCredentials
from soc_platform.connectors.registry import FIXTURES_DIR, ConnectorRegistry
from soc_platform.connectors.tools._common import parse_ts
from soc_platform.core.context_store import ContextStore
from soc_platform.core.models import ConnectorCheckpoint

# Streams with no paging to exercise, and why (the coverage test keeps this list honest).
NO_PAGING = {
    ("canary", "devices"): "one document (all devices)",
    ("cmdb_csv", "cmdb"): "one CSV / ownership document",
    ("cisa_kev", "catalog"): "one catalogue file",
    ("generic_siem", "pushed"): "push-only: alerts arrive at POST /api/v1/ingest/alerts",
}


def demo_routes(name: str) -> list[dict]:
    return json.loads((Path(FIXTURES_DIR) / f"{name}.json").read_text(encoding="utf-8"))["routes"]


def demo_route(name: str, method: str, contains: str) -> dict:
    for r in demo_routes(name):
        if r["method"] == method and contains in r["path"] and not r.get("params") and not r.get("body_contains"):
            return r
    raise KeyError((name, method, contains))


def fresh(name: str, routes: list[dict]):
    """A new connector in fake mode, answering from ``routes`` (no state carried over)."""
    conn = ConnectorRegistry.all_fake().get(name)
    conn.http = FixtureTransport(copy.deepcopy(routes), name)
    return conn


def reroute(conn, routes: list[dict]) -> FixtureTransport:
    """Same connector (its watermark state kept), new transport: a later sync against the same tenant."""
    conn.http = FixtureTransport(copy.deepcopy(routes), conn.name)
    return conn.http


def at_least(items: list[dict], n: int = 4) -> list[dict]:
    """Clone records (with distinct ids) until there are enough for two pages."""
    items = copy.deepcopy(items)
    i = 0
    while len(items) < n:
        c = copy.deepcopy(items[i % len(items)])
        for k in ("id", "name", "composite_id", "device_id", "sys_id", "secretAuditId", "eventId", "aid"):
            if isinstance(c.get(k), str):
                c[k] = f"{c[k]}-p{len(items)}"
            elif isinstance(c.get(k), int):
                c[k] = c[k] + 10_000 + len(items)
        items.append(c)
        i += 1
    return items


def stamp(items: list[dict], field: str) -> str:
    """Give every record a distinct change time; returns the newest (the watermark the next sync must use)."""
    for i, it in enumerate(items):
        cur, parts = it, field.split(".")
        for p in parts[:-1]:
            cur = cur.setdefault(p, {})
        cur[parts[-1]] = f"2026-09-20T10:{i:02d}:00Z"
    return f"2026-09-20T10:{len(items) - 1:02d}:00Z"


def asked_from(newest: str) -> str:
    """The time the next sync asks from: the newest time seen minus the default 30-minute overlap (late-indexed logs)."""
    return (parse_ts(newest) - timedelta(minutes=30)).strftime("%Y-%m-%dT%H:%M:%SZ")


def sync(session, conn, stream, *, full: bool = False):
    rep = SyncRunner(session, ContextStore(session)).sync(conn, stream, full_backfill=full)
    session.flush()
    return rep, session.get(ConnectorCheckpoint, (conn.name, stream))


def calls_to(t: FixtureTransport, needle: str, method: str | None = None) -> list[dict]:
    return [c for c in t.calls if needle in c["path"] and (method is None or c["method"] == method)]


# ============================================================================== paging and resume
ODATA = [  # (connector, stream, demo path fragment, watermark field, filter field) - Graph, Defender, Sentinel
    ("defender_endpoint", "alerts", "/api/alerts", "lastUpdateTime", "lastUpdateTime"),
    ("defender_endpoint", "machines", "/api/machines", None, None),
    ("defender_endpoint", "vulnerabilities", "machinesVulnerabilities", None, None),
    ("defender_office365", "reported_messages", "mailFolders/inbox/messages", "receivedDateTime", "receivedDateTime"),
    ("defender_office365", "email_alerts", "alerts_v2", "lastUpdateDateTime", "lastUpdateDateTime"),
    ("entra", "users", "/v1.0/users$", None, None),
    ("entra", "signins", "auditLogs/signIns", "createdDateTime", "createdDateTime"),
    ("entra", "risky_users", "riskyUsers", "riskLastUpdatedDateTime", "riskLastUpdatedDateTime"),
    ("entra", "risk_detections", "riskDetections", "detectedDateTime", "detectedDateTime"),
    ("entra", "directory_audits", "directoryAudits", "activityDateTime", "activityDateTime"),
    ("sentinel", "incidents", "/incidents$", "properties.lastModifiedTimeUtc", "properties/lastModifiedTimeUtc"),
]


@pytest.mark.parametrize("name,stream,fragment,watermark,filter_field", ODATA, ids=[f"{a}.{b}" for a, b, *_ in ODATA])
def test_odata_streams_page_through_next_links_and_resume_without_them(session, name, stream, fragment, watermark,
                                                                       filter_field):
    src = demo_route(name, "GET", fragment)
    items = at_least(src["body"]["value"])
    newest = stamp(items, watermark) if watermark else None
    next_key = "nextLink" if name == "sentinel" else "@odata.nextLink"
    path_plain = src["path"].strip("^$")
    page1 = {**src, "times": 1, "body": {"value": items[:2], next_key: f"https://api.example{path_plain}?$skiptoken=P2"}}
    page2 = {**src, "body": {"value": items[2:]}}
    others = [r for r in demo_routes(name) if r["method"] != "GET"]       # e.g. Sentinel's per-incident entities
    routes = [page1, page2, *others]
    conn = fresh(name, routes)
    rep, cp = sync(session, conn, stream)
    assert not rep.errors and rep.pages == 2 and rep.ingested == len(items), (rep.errors, rep.pages, rep.ingested)
    first, second = calls_to(conn.http, path_plain.split("/")[-1], "GET")[:2]
    assert "$filter" not in (first["params"] or {}) or "ge 20" not in first["params"]["$filter"]   # a full first read
    assert not second["params"], "the second page must come from the next link, not a new query"
    assert cp.cursor == (f"since:{newest}" if watermark else None), cp.cursor     # never the expired next link

    t = reroute(conn, routes)
    rep2, cp2 = sync(session, conn, stream)
    assert not rep2.errors, rep2.errors
    q = calls_to(t, path_plain.split("/")[-1], "GET")[0]
    if watermark:
        assert f"{filter_field} ge {asked_from(newest)}" in q["params"]["$filter"], q["params"]
    else:
        assert q["params"] and "$filter" not in q["params"], q          # starts over: a fresh query, all records
    assert cp2.cursor == (f"since:{newest}" if watermark else None)


def _cs_query_pages(path, ids, total_key="total"):
    return [{"method": "GET", "path": path, "times": 1, "status": 200,
             "body": {"resources": ids[:2], "meta": {"pagination": {"offset": 0, "limit": 100, total_key: len(ids)}}}},
            {"method": "GET", "path": path, "status": 200,
             "body": {"resources": ids[2:], "meta": {"pagination": {"offset": 2, "limit": 100, total_key: len(ids)}}}}]


def test_crowdstrike_alerts_page_by_offset_and_resume_from_the_newest_update(session):
    ents = demo_route("crowdstrike", "POST", "/alerts/entities/alerts/v2")
    alerts = at_least(ents["body"]["resources"])
    newest = stamp(alerts, "updated_timestamp")
    routes = [*_cs_query_pages(r"^/alerts/queries/alerts/v2$", [a["composite_id"] for a in alerts]),
              {**ents, "body": {"resources": alerts}}]
    conn = fresh("crowdstrike", routes)
    rep, cp = sync(session, conn, "alerts")
    assert not rep.errors and rep.ingested == len(alerts)
    q = calls_to(conn.http, "/alerts/queries", "GET")
    assert q[1]["params"]["offset"] == 2 and "filter" not in q[0]["params"]
    assert cp.cursor == f"since:{newest}"
    t = reroute(conn, routes)
    sync(session, conn, "alerts")
    first = calls_to(t, "/alerts/queries", "GET")[0]["params"]
    assert first["filter"] == f"updated_timestamp:>='{asked_from(newest)}'" and first["offset"] == 0
    assert first["sort"] == "updated_timestamp.asc"


def test_crowdstrike_alerts_past_the_offset_limit_restart_from_the_newest_update(session, monkeypatch):
    # Falcon refuses offset + limit > 10,000; a backlog bigger than that must still be read to the end
    from soc_platform.connectors.tools import crowdstrike

    monkeypatch.setattr(crowdstrike, "MAX_OFFSET", 3)
    ents = demo_route("crowdstrike", "POST", "/alerts/entities/alerts/v2")
    alerts = at_least(ents["body"]["resources"], 4)
    for i, a in enumerate(alerts):                      # distinct, increasing update times
        a["updated_timestamp"] = f"2026-09-20T10:{i:02d}:00Z"
    ids = [a["composite_id"] for a in alerts]
    routes = [{"method": "GET", "path": r"^/alerts/queries/alerts/v2$", "times": 1, "status": 200,
               "body": {"resources": ids[:2], "meta": {"pagination": {"total": len(ids)}}}},
              {"method": "GET", "path": r"^/alerts/queries/alerts/v2$", "status": 200,
               "body": {"resources": ids[1:], "meta": {"pagination": {"total": len(ids) - 1}}}},
              {**ents, "body": {"resources": alerts}, "select": {"from": "json.composite_ids", "list": "resources",
                                                                 "key": "composite_id"}}]
    conn = fresh("crowdstrike", routes)
    rep, cp = sync(session, conn, "alerts")
    assert not rep.errors
    q = calls_to(conn.http, "/alerts/queries", "GET")
    assert q[1]["params"]["offset"] == 0 and q[1]["params"]["filter"] == f"updated_timestamp:>='{alerts[1]['updated_timestamp']}'"
    assert cp.cursor == f"since:{alerts[-1]['updated_timestamp']}"


def test_crowdstrike_hosts_scroll_by_token_and_are_read_in_full_each_sync(session):
    ents = demo_route("crowdstrike", "POST", "/devices/entities/devices/v2")
    devs = at_least(ents["body"]["resources"])
    ids = [d["device_id"] for d in devs]
    path = r"^/devices/queries/devices-scroll/v1$"
    routes = [{"method": "GET", "path": path, "times": 1, "status": 200,
               "body": {"resources": ids[:2], "meta": {"pagination": {"offset": "tok-1", "total": len(ids)}}}},
              {"method": "GET", "path": path, "status": 200,
               "body": {"resources": ids[2:], "meta": {"pagination": {"offset": "tok-2", "total": len(ids)}}}},
              {**ents, "body": {"resources": devs}}]
    conn = fresh("crowdstrike", routes)
    rep, cp = sync(session, conn, "hosts")
    assert not rep.errors and rep.ingested == len(devs)
    q = calls_to(conn.http, "/devices/queries", "GET")
    assert len(q) == 2 and "offset" not in q[0]["params"] and q[1]["params"]["offset"] == "tok-1"
    assert cp.cursor is None
    t = reroute(conn, routes)
    sync(session, conn, "hosts")
    assert "offset" not in calls_to(t, "/devices/queries", "GET")[0]["params"]


def test_crowdstrike_spotlight_follows_after_tokens_and_never_reuses_one(session):
    src = demo_route("crowdstrike", "GET", "/spotlight/combined/vulnerabilities/v1")
    vulns = at_least(src["body"]["resources"])
    routes = [{**src, "times": 1, "body": {"resources": vulns[:2], "meta": {"pagination": {"after": "tok-2"}}}},
              {**src, "body": {"resources": vulns[2:], "meta": {"pagination": {}}}}]
    conn = fresh("crowdstrike", routes)
    rep, cp = sync(session, conn, "vulnerabilities")
    assert not rep.errors and rep.ingested == len(vulns)
    assert calls_to(conn.http, "spotlight")[1]["params"]["after"] == "tok-2" and cp.cursor is None
    t = reroute(conn, routes)
    sync(session, conn, "vulnerabilities")
    assert "after" not in calls_to(t, "spotlight")[0]["params"]


@pytest.mark.parametrize("stream", ["assets", "findings"])
def test_rapid7_pages_by_page_number_and_reads_assets_in_full_each_sync(session, stream):
    src = demo_route("rapid7", "GET", "/api/3/assets$")
    assets = src["body"]["resources"]
    assert len(assets) >= 2
    routes = [{**src, "times": 1, "body": {"resources": assets[:2], "page": {"number": 0, "size": 2, "totalPages": 2}}},
              {**src, "body": {"resources": assets[2:], "page": {"number": 1, "size": 2, "totalPages": 2}}},
              *[r for r in demo_routes("rapid7") if r is not src and r["path"] != src["path"]]]
    conn = fresh("rapid7", routes)
    rep, cp = sync(session, conn, stream)
    assert not rep.errors and rep.pages == 2
    lists = [c for c in conn.http.calls if c["path"] == "/api/3/assets"]
    assert [c["params"]["page"] for c in lists] == [0, 1]
    assert cp.cursor is None                      # it was "2": the next sync asked for a page past the end
    t = reroute(conn, routes)
    sync(session, conn, stream)
    assert next(c for c in t.calls if c["path"] == "/api/3/assets")["params"]["page"] == 0


@pytest.mark.parametrize("stream,marker,key", [("resources", "cloudResources", "cloudResources"),
                                               ("vulnerabilities", "vulnerabilityFindings", "vulnerabilityFindings"),
                                               ("issues", "issuesV2(", "issuesV2")])
def test_wiz_follows_graphql_end_cursors_and_reads_in_full_each_sync(session, stream, marker, key):
    src = next(r for r in demo_routes("wiz") if r.get("body_contains") == marker)
    nodes = at_least(src["body"]["data"][key]["nodes"])
    routes = [{**src, "times": 1, "body": {"data": {key: {"nodes": nodes[:2], "totalCount": len(nodes),
                                                          "pageInfo": {"hasNextPage": True, "endCursor": "cur-2"}}}}},
              {**src, "body": {"data": {key: {"nodes": nodes[2:], "totalCount": len(nodes),
                                              "pageInfo": {"hasNextPage": False, "endCursor": "cur-3"}}}}}]
    conn = fresh("wiz", routes)
    rep, cp = sync(session, conn, stream)
    assert not rep.errors and rep.ingested == len(nodes)
    variables = [c["json"].get("variables") or {} for c in conn.http.calls if c["method"] == "POST"]
    assert variables[0].get("after") is None and variables[1].get("after") == "cur-2"
    assert cp.cursor is None
    t = reroute(conn, routes)
    sync(session, conn, stream)
    assert (t.calls[0]["json"].get("variables") or {}).get("after") is None


def test_umbrella_pages_by_offset_and_resumes_from_the_newest_dns_event(session):
    src = demo_route("umbrella", "GET", "/reports/v2/activity/dns")
    base = src["body"]["data"][0]
    rows = []
    for i in range(1003):                         # the API pages at 1,000 rows
        r = copy.deepcopy(base)
        r["timestamp"] = f"2026-09-20T{10 + i // 3600:02d}:{(i // 60) % 60:02d}:{i % 60:02d}Z"
        rows.append(r)
    cats = demo_route("umbrella", "GET", "/reports/v2/categories")
    routes = [cats, {**src, "times": 1, "body": {"data": rows[:1000]}}, {**src, "body": {"data": rows[1000:]}}]
    conn = fresh("umbrella", routes)
    rep, cp = sync(session, conn, "dns_activity")
    assert not rep.errors and rep.ingested == 1003 and rep.pages == 2
    c1, c2 = calls_to(conn.http, "activity/dns")[:2]
    assert c2["params"]["offset"] == 1000 and c2["params"]["from"] == c1["params"]["from"]
    assert c1["params"]["categories"] == "65,66,68" and len(calls_to(conn.http, "categories")) == 1   # read once
    newest = rows[-1]["timestamp"]
    assert cp.cursor == f"since:{newest}"
    t = reroute(conn, routes)
    sync(session, conn, "dns_activity")
    q = calls_to(t, "activity/dns")[0]["params"]
    assert q["from"] == str(int(parse_ts(asked_from(newest)).timestamp() * 1000)) and q["offset"] == 0


@pytest.mark.parametrize("stream,template_path", [("cmdb", "/api/now/table/cmdb_ci_computer$"),
                                                  ("tickets", "/api/now/table/incident/sn-sys-0001$")])
def test_servicenow_pages_by_offset_and_reads_in_full_each_sync(session, stream, template_path):
    tmpl = demo_route("servicenow", "GET", template_path)["body"]["result"]
    tmpl = tmpl[0] if isinstance(tmpl, list) else tmpl
    rows = []
    for i in range(503):                          # the connector pages at 500 rows
        r = copy.deepcopy(tmpl)
        r["sys_id"] = {"value": f"sn-{stream}-{i:04d}", "display_value": f"sn-{stream}-{i:04d}"}
        if isinstance(r.get("number"), dict):
            r["number"] = {"value": f"INC{20000 + i}", "display_value": f"INC{20000 + i}"}
        if "name" in r and isinstance(r["name"], dict):
            r["name"] = {**r["name"], "value": f"host{i:04d}", "display_value": f"host{i:04d}"}
        rows.append(r)
    table = "cmdb_ci_computer" if stream == "cmdb" else "incident"
    path = rf"^/api/now/table/{table}$"
    routes = [{"method": "GET", "path": path, "status": 200, "times": 1, "body": {"result": rows[:500]}},
              {"method": "GET", "path": path, "status": 200, "body": {"result": rows[500:]}}]
    conn = fresh("servicenow", routes)
    rep, cp = sync(session, conn, stream)
    assert not rep.errors and rep.ingested == 503 and rep.pages == 2
    offsets = [c["params"]["sysparm_offset"] for c in calls_to(conn.http, f"/table/{table}")]
    assert offsets == [0, 500] and cp.cursor is None
    t = reroute(conn, routes)
    sync(session, conn, stream)
    assert calls_to(t, f"/table/{table}")[0]["params"]["sysparm_offset"] == 0


def test_jira_follows_page_tokens_and_never_reuses_an_expired_one(session):
    src = demo_route("jira", "GET", "search/jql")
    issues = at_least(src["body"]["issues"])
    routes = [{**src, "times": 1, "body": {"issues": issues[:2], "nextPageToken": "tok-2", "isLast": False}},
              {**src, "body": {"issues": issues[2:], "isLast": True}}]
    conn = fresh("jira", routes)
    rep, cp = sync(session, conn, "tickets")
    assert not rep.errors and rep.ingested == len(issues)
    c = calls_to(conn.http, "search/jql")
    assert "nextPageToken" not in c[0]["params"] and c[1]["params"]["nextPageToken"] == "tok-2"
    assert cp.cursor is None
    t = reroute(conn, routes)
    sync(session, conn, "tickets")
    assert "nextPageToken" not in calls_to(t, "search/jql")[0]["params"]


def test_nvd_pages_by_start_index(session):
    src = demo_route("nvd", "GET", "/rest/json/cves/2.0")
    vulns = [v for r in demo_routes("nvd") for v in r["body"]["vulnerabilities"]]
    assert len(vulns) >= 4
    routes = [{**src, "times": 1, "body": {"totalResults": len(vulns), "startIndex": 0, "vulnerabilities": vulns[:2]}},
              {**src, "body": {"totalResults": len(vulns), "startIndex": 2, "vulnerabilities": vulns[2:]}}]
    conn = fresh("nvd", routes)
    rep, cp = sync(session, conn, "recent_cves")
    assert not rep.errors and rep.source_records == len(vulns)
    assert [c["params"]["startIndex"] for c in calls_to(conn.http, "cves")] == [0, 2] and cp.cursor is None


def test_delinea_secret_audits_page_by_skip_and_resume_after_the_last_record(session):
    src = demo_route("delinea_secret_server", "GET", "/api/v1/secret-audits")
    recs = at_least(src["body"]["records"])
    routes = [{**src, "times": 1, "body": {"records": recs[:2], "total": len(recs), "hasNext": True}},
              {**src, "body": {"records": recs[2:], "total": len(recs), "hasNext": False}}]
    conn = fresh("delinea_secret_server", routes)
    rep, cp = sync(session, conn, "secret_audits")
    assert not rep.errors and rep.ingested == len(recs)
    assert [c["params"]["skip"] for c in calls_to(conn.http, "secret-audits")] == [0, 2]
    assert cp.cursor == str(len(recs))           # audit records are append-only: resume after the last one


def test_delinea_privilege_manager_pages_by_last_id(session):
    src = demo_route("delinea_privilege_manager", "GET", "/events/elevation")
    items = at_least(src["body"]["items"])
    routes = [{**src, "times": 1, "body": {"items": items[:2], "hasMore": True, "lastId": "L-2"}},
              {**src, "body": {"items": items[2:], "hasMore": False, "lastId": "L-4"}}]
    conn = fresh("delinea_privilege_manager", routes)
    rep, cp = sync(session, conn, "elevation_events")
    assert not rep.errors and rep.ingested == len(items)
    assert calls_to(conn.http, "elevation")[1]["params"]["after"] == "L-2" and cp.cursor == "L-4"


def test_avanan_follows_scroll_ids_within_a_sync_and_resumes_from_the_newest_event(session):
    src = demo_route("avanan", "POST", "/event/query")
    events = at_least(src["body"]["responseData"])
    newest = stamp(events, "eventCreated")
    env = src["body"]["responseEnvelope"]
    routes = [{**src, "times": 1, "body": {"responseEnvelope": {**env, "scrollId": "s-2", "recordsNumber": len(events)},
                                           "responseData": events[:2]}},
              {**src, "body": {"responseEnvelope": {**env, "scrollId": None, "recordsNumber": len(events)},
                               "responseData": events[2:]}},
              *[r for r in demo_routes("avanan") if r["method"] == "GET"]]
    conn = fresh("avanan", routes)
    rep, cp = sync(session, conn, "security_events")
    assert not rep.errors and rep.ingested == len(events)
    posts = calls_to(conn.http, "/event/query", "POST")
    assert posts[1]["json"] == {"requestData": {"scrollId": "s-2"}}
    assert parse_ts(cp.cursor) == parse_ts(newest)


def test_canary_resumes_incidents_from_the_last_updated_id(session):
    conn = fresh("canary", demo_routes("canary"))
    rep, cp = sync(session, conn, "incidents")
    assert not rep.errors and cp.cursor
    t = reroute(conn, demo_routes("canary"))
    sync(session, conn, "incidents")
    assert str(calls_to(t, "incidents/all")[0]["params"]["incidents_since"]) == cp.cursor


PAGING_TESTED = {(n, s) for n, s, *_ in ODATA} | {
    ("crowdstrike", "alerts"), ("crowdstrike", "hosts"), ("crowdstrike", "vulnerabilities"), ("rapid7", "assets"),
    ("rapid7", "findings"), ("wiz", "resources"), ("wiz", "vulnerabilities"), ("wiz", "issues"),
    ("umbrella", "dns_activity"), ("servicenow", "cmdb"), ("servicenow", "tickets"), ("jira", "tickets"),
    ("nvd", "recent_cves"), ("delinea_secret_server", "secret_audits"), ("delinea_privilege_manager", "elevation_events"),
    ("avanan", "security_events"), ("canary", "incidents")}


def all_streams() -> list[tuple[str, str]]:
    reg = ConnectorRegistry.all_fake()
    return sorted((n, s) for n in reg.enabled_names() for s in reg.get(n).streams)


def _paging_tested_elsewhere() -> set[tuple[str, str]]:
    """Connectors made with ``connector new`` carry their paging test in test_connector_<name>.py (PAGING_TESTED)."""
    import importlib

    out: set[tuple[str, str]] = set()
    for f in sorted(Path(__file__).parent.glob("test_connector_*.py")):
        if f.stem != "test_connector_conformance":
            out |= set(getattr(importlib.import_module(f"soc_platform.tests.{f.stem}"), "PAGING_TESTED", set()))
    return out


def test_every_connector_stream_is_paging_tested_or_has_a_stated_reason():
    tested = PAGING_TESTED | _paging_tested_elsewhere()
    missing = [p for p in all_streams() if p not in tested and p not in NO_PAGING]
    assert not missing, f"add a paging test (or a NO_PAGING reason) for {missing}"
    assert not (PAGING_TESTED & set(NO_PAGING))


# ============================================================================== throttling, tokens, permissions
def _baseline(session, name, stream):
    conn = fresh(name, demo_routes(name))
    rep, _ = sync(session, conn, stream)
    return rep, len(conn.http.calls)


FAULT_STREAMS = [p for p in all_streams() if p != ("generic_siem", "pushed")]


def _fault(status: int, times: int | None, headers: dict | None = None) -> list[dict]:
    r = {"path": ".*", "status": status, "body": None}
    if times is not None:
        r["times"] = times
    if headers:
        r["headers"] = headers
    return [{**r, "method": "GET"}, {**r, "method": "POST"}]


@pytest.mark.parametrize("name,stream", FAULT_STREAMS, ids=[f"{a}.{b}" for a, b in FAULT_STREAMS])
def test_throttling_and_a_refused_token_are_recovered_without_losing_records(session, name, stream):
    base, n_calls = _baseline(session, name, stream)
    if n_calls == 0:
        pytest.skip("stream makes no API call")
    throttled = fresh(name, _fault(429, 1, {"Retry-After": "0"}) + demo_routes(name))
    rep, _ = sync(session, throttled, stream, full=True)
    assert not rep.errors and rep.ingested == base.ingested, rep.errors
    expired = fresh(name, _fault(401, 1) + demo_routes(name))
    rep, _ = sync(session, expired, stream, full=True)
    assert not rep.errors and rep.ingested == base.ingested, rep.errors
    assert expired.http.reauthentications >= 1


@pytest.mark.parametrize("name,stream", FAULT_STREAMS, ids=[f"{a}.{b}" for a, b in FAULT_STREAMS])
def test_a_missing_permission_stops_at_once_and_names_what_to_grant(session, name, stream):
    _, n_calls = _baseline(session, name, stream)
    if n_calls == 0:
        pytest.skip("stream makes no API call")
    conn = fresh(name, _fault(403, None) + demo_routes(name))
    rep, cp = sync(session, conn, stream, full=True)
    assert rep.errors and "403" in rep.errors[-1] and "PermissionDenied" in cp.last_error, rep.errors
    assert len(conn.http.calls) <= 2, "a refused permission must not be retried"
    if conn.streams and (conn.health_stream or conn.streams[0]) == stream:
        h = conn.health()
        assert h["ok"] is False and h["missing_permission"] is True and "required_scopes" in h


# ============================================================================== missing and null fields
FIELD_STREAMS = [p for p in all_streams() if p != ("generic_siem", "pushed")]
CRASHES = (KeyError, TypeError, AttributeError, IndexError)


def _variants(rec: dict):
    for k in list(rec):
        drop = {x: v for x, v in rec.items() if x != k}
        yield f"-{k}", drop
        yield f"{k}=null", {**rec, k: None}
        if isinstance(rec[k], dict):
            for kk in list(rec[k]):
                yield f"-{k}.{kk}", {**rec, k: {x: v for x, v in rec[k].items() if x != kk}}
                yield f"{k}.{kk}=null", {**rec, k: {**rec[k], kk: None}}


@pytest.mark.parametrize("name,stream", FIELD_STREAMS, ids=[f"{a}.{b}" for a, b in FIELD_STREAMS])
def test_missing_or_null_fields_never_crash_a_normaliser(name, stream):
    conn = fresh(name, demo_routes(name))
    records = conn.fetch_page(stream, None).records
    crashes = []
    for rec in records[:5]:
        for label, variant in _variants(rec):
            try:
                conn.normalize(stream, variant)
            except CRASHES as exc:
                crashes.append(f"{label}: {type(exc).__name__}: {exc}")
            except ValueError:
                pass                     # deliberate: a record without its identifier is refused with a reason
    assert not crashes, sorted(set(crashes))[:15]


# ============================================================================== the live transport itself
def _live(handler, auth=None) -> HttpTransport:
    t = HttpTransport("https://api.example", auth)
    t.client = httpx.Client(transport=httpx.MockTransport(handler))
    return t


def test_live_transport_maps_statuses_and_renews_a_refused_token(monkeypatch):
    issued = []

    def token_post(url, **kw):
        issued.append(url)
        return httpx.Response(200, json={"access_token": f"tok-{len(issued)}", "expires_in": 3600})

    monkeypatch.setattr("soc_platform.connectors.http.httpx.post", token_post)
    auth = OAuth2ClientCredentials("https://login.example/token", "id", "secret")
    seen = []

    def handler(req):
        seen.append(req.headers.get("authorization"))
        return httpx.Response(401) if len(seen) == 1 else httpx.Response(200, json={"ok": True})

    t = _live(handler, auth)
    conn = ConnectorRegistry.all_fake().get("canary")
    conn.http = t
    assert conn.get("/x") == {"ok": True}
    assert seen == ["Bearer tok-1", "Bearer tok-2"] and len(issued) == 2      # cached token dropped, new one fetched

    with pytest.raises(PermissionDenied):
        _live(lambda r: httpx.Response(403, text="Insufficient privileges")).request("GET", "/x")
    with pytest.raises(AuthExpired):
        _live(lambda r: httpx.Response(401)).request("GET", "/x")
    with pytest.raises(RateLimited) as e:
        _live(lambda r: httpx.Response(429, headers={"Retry-After": "7"})).request("GET", "/x")
    assert e.value.retry_after == 7
    with pytest.raises(RateLimited) as e:
        _live(lambda r: httpx.Response(429, headers={"Retry-After": "Wed, 21 Oct 2015 07:28:00 GMT"})).request("GET", "/x")
    assert e.value.retry_after == 0                                              # a date in the past: retry now


# ============================================================================== Sentinel, Jira and SIEM push content
def test_sentinel_incidents_carry_their_entities(session):
    conn = fresh("sentinel", demo_routes("sentinel"))
    rep, _ = sync(session, conn, "incidents")
    assert not rep.errors and rep.ingested == 2
    recs = [r for raw in conn.fetch_page("incidents", None).records for r in conn.normalize("incidents", raw)]
    kinds = {(ref.kind, ref.role) for r in recs for ref in r.refs}
    assert ("identity", "user") in kinds and ("asset", "host") in kinds and ("indicator", "observable") in kinds
    host = next(ref for r in recs for ref in r.refs if ref.kind == "asset")
    assert host.keys.get("mde_device_id") and host.attributes.get("fqdn")


def test_jira_times_keep_their_offset():
    conn = fresh("jira", demo_routes("jira"))
    recs = [r for raw in conn.fetch_page("tickets", None).records for r in conn.normalize("tickets", raw)]
    assert recs and all(r.observed_at.utcoffset() is not None for r in recs)
    by_key = {r.attributes["number"]: r for r in recs}
    assert by_key["SEC-118"].observed_at.isoformat() == "2026-09-20T15:10:00+05:30"   # not 15:10 UTC


@pytest.mark.parametrize("shape", ["flat", "splunk_es_notable", "elastic_security"])
def test_pushed_siem_alerts_of_common_shapes_map_to_hosts_people_and_indicators(shape):
    sample = json.loads((Path(FIXTURES_DIR) / "generic_siem.json").read_text(encoding="utf-8"))["push_samples"][shape]
    conn = ConnectorRegistry.all_fake().get("generic_siem")
    conn.settings = {**conn.settings, "field_map": sample["field_map"], "user_domain": "acme-demo.com"}
    for alert in sample["alerts"]:
        (rec,) = conn.normalize("pushed", alert)
        kinds = {r.kind for r in rec.refs}
        assert rec.source_id and rec.observed_at and rec.title != "alert", rec
        assert {"asset", "identity", "indicator"} <= kinds, (shape, kinds)
        assert rec.severity == "high"


# ============================================================================== the sync layer under real-world conditions
def test_late_records_are_caught_by_the_overlap_and_future_times_never_move_the_mark(session, monkeypatch):
    src = demo_route("entra", "GET", "auditLogs/signIns")
    items = at_least(src["body"]["value"])
    newest = stamp(items, "createdDateTime")
    items[0]["createdDateTime"] = "2099-01-01T00:00:00Z"       # a device with a wrong clock
    conn = fresh("entra", [{**src, "body": {"value": items}}])
    _, cp = sync(session, conn, "signins")
    assert cp.cursor == f"since:{newest}", cp.cursor           # the 2099 record is stored, but is not the mark
    monkeypatch.setenv("SOC_WATERMARK_OVERLAP_MINUTES", "90")
    t = reroute(conn, [{**src, "body": {"value": items}}])
    sync(session, conn, "signins")
    want = (parse_ts(newest) - timedelta(minutes=90)).strftime("%Y-%m-%dT%H:%M:%SZ")
    assert f"createdDateTime ge {want}" in t.calls[0]["params"]["$filter"]


def test_an_html_page_instead_of_json_is_a_clear_error_and_a_corrupt_body_is_retried():
    html = _live(lambda r: httpx.Response(200, text="<html><body>Sign in to continue</body></html>",
                                          headers={"content-type": "text/html"}))
    with pytest.raises(ConnectorError, match="HTML page instead of the API"):
        html.request("GET", "/x")
    corrupt = _live(lambda r: httpx.Response(200, content=b'{"value": [', headers={"content-type": "application/json"}))
    with pytest.raises(TransientError):
        corrupt.request("GET", "/x")


class _Pages(BaseConnector):
    """A stream of N pages that records how far downloading runs ahead of ingestion."""
    name = tool = "pages"
    streams = ("s",)

    def __init__(self, n: int) -> None:
        super().__init__(rate_per_sec=1e6, burst=10**6)
        self.n, self.fetched, self.ingested, self.ahead = n, 0, 0, 0

    def fetch_page(self, stream, cursor):
        i = int(cursor or 0)
        self.fetched += 1
        self.ahead = max(self.ahead, self.fetched - self.ingested)
        return Page([{"id": f"r{i}"}], str(i + 1), has_more=i + 1 < self.n)

    def normalize(self, stream, raw):
        self.ingested += 1
        return []


def test_a_page_limit_is_reported_and_the_next_sync_continues_where_it_stopped(session, monkeypatch):
    monkeypatch.setenv("SOC_SYNC_MAX_PAGES", "3")
    conn = _Pages(5)
    runner = SyncRunner(session, ContextStore(session))
    rep = runner.sync(conn, "s")
    assert rep.pages == 3 and rep.truncated and rep.cursor == "3" and not rep.errors
    rep = runner.sync(conn, "s")
    assert rep.pages == 2 and not rep.truncated and conn.ingested == 5    # nothing lost, nothing read twice


def test_parallel_downloads_stay_a_bounded_distance_ahead_of_ingestion(session, monkeypatch):
    from soc_platform.connectors import base

    monkeypatch.setattr(base, "PAGE_BUFFER", 2)
    conn = _Pages(40)
    (rep,) = SyncRunner(session, ContextStore(session)).sync_many([(conn, "s")])
    assert rep.pages == 40 and conn.ingested == 40
    assert conn.ahead <= 2 + 3, conn.ahead            # buffer + the page in hand on each side - not the whole stream


def test_ingestion_stopping_early_never_leaves_a_download_blocked(session, monkeypatch):
    from soc_platform.connectors import base

    monkeypatch.setattr(base, "PAGE_BUFFER", 1)
    def stops_after_one_page(self, connector, stream, *, pages=None, **kw):
        next(iter(pages))                             # e.g. the database went away after the first page
        return base.SyncReport(connector.name, stream, pages=1)

    monkeypatch.setattr(SyncRunner, "sync", stops_after_one_page)
    out = []
    runner = SyncRunner(session, ContextStore(session))
    worker = threading.Thread(target=lambda: out.append(runner.sync_many([(_Pages(30), "s"), (_Pages(30), "s")])))
    worker.start()
    worker.join(timeout=30)
    assert not worker.is_alive(), "sync_many hung on a full download buffer"
    assert len(out[0]) == 2


def test_dns_sync_stores_security_activity_by_default_and_never_silently_everything(session):
    conn = fresh("umbrella", demo_routes("umbrella"))
    sync(session, conn, "dns_activity")
    assert calls_to(conn.http, "activity/dns")[0]["params"]["categories"] == "65,66,68"
    no_list = fresh("umbrella", [r for r in demo_routes("umbrella") if "categories" not in r["path"]])
    sync(session, no_list, "dns_activity", full=True)
    q = calls_to(no_list.http, "activity/dns")[0]["params"]
    assert q["verdict"] == "blocked" and "categories" not in q                  # the list was unreadable: blocked only
    everything = fresh("umbrella", demo_routes("umbrella"))
    everything.settings = {**everything.settings, "dns_sync": "all"}
    sync(session, everything, "dns_activity", full=True)
    q = calls_to(everything.http, "activity/dns")[0]["params"]
    assert "categories" not in q and "verdict" not in q


def test_a_connection_failure_keeps_its_cause_after_the_retries(monkeypatch):
    """TLS inspection by a corporate proxy, a DNS failure and an outage need different fixes: say which it was."""
    from soc_platform.connectors import base

    monkeypatch.setattr(base, "_sleep", lambda s: None)

    def tls_refused(request):
        raise httpx.ConnectError("[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: self-signed certificate")

    conn = ConnectorRegistry.all_fake().get("canary")
    conn.http = _live(tls_refused)
    with pytest.raises(ConnectorError, match="CERTIFICATE_VERIFY_FAILED"):
        conn.get("/x")
