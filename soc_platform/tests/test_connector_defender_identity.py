"""Defender for Identity: logon-event paging and resume, and how its records join the rest of the estate. Its alerts
stream pages through the shared OData test in test_connector_conformance.py, which also runs throttling, token
renewal, missing-permission and missing-field checks on it automatically."""

import copy

from soc_platform.connectors.registry import ConnectorRegistry
from soc_platform.core.context_store import ContextStore
from soc_platform.core.models import Entity, EntityKey
from soc_platform.tests.test_connector_conformance import calls_to, demo_routes, fresh, reroute, sync

# read by the shared coverage test: every stream of every connector needs a paging test
PAGING_TESTED = {("defender_identity", "logon_events")}

HUNT = "runHuntingQuery"


def _logon_route() -> dict:
    return next(r for r in demo_routes("defender_identity") if r.get("body_contains") == "IdentityLogonEvents")


def _rows(n: int) -> list[dict]:
    src = _logon_route()["body"]["results"]
    out = []
    for i in range(n):
        r = copy.deepcopy(src[i % len(src)])
        r["ReportId"], r["Timestamp"] = f"mdi-logon-t{i:03d}", f"2026-09-20T10:{i:02d}:00Z"
        out.append(r)
    return out


def test_logon_events_continue_from_the_newest_time_and_resume_from_it(session):
    rows = _rows(5)
    hunt = {k: v for k, v in _logon_route().items() if k != "body_contains"}
    # what the tool answers: oldest first, at most 3 rows, from the time asked (the boundary row is read again)
    routes = [{**hunt, "times": 1, "body": {"results": rows[:3]}}, {**hunt, "times": 1, "body": {"results": rows[2:]}},
              {**hunt, "body": {"results": rows[4:]}}]
    conn = fresh("defender_identity", routes)
    conn.settings = {**conn.settings, "hunting_page_size": 3}
    rep, cp = sync(session, conn, "logon_events")
    assert not rep.errors and rep.pages == 3, (rep.errors, rep.pages)
    asked = [c["json"]["Query"] for c in calls_to(conn.http, HUNT, "POST")]
    assert "ago(7d)" in asked[0]                                         # first sync: the configured lookback
    assert "datetime(2026-09-20T10:02:00Z)" in asked[1]                  # within a sync: the exact newest time,
    assert "datetime(2026-09-20T10:04:00Z)" in asked[2]                  # no overlap (it would re-read and stall)
    assert cp.cursor == "since:2026-09-20T10:04:00Z"                     # a time, never a hunting continuation
    assert session.query(Entity).filter(Entity.kind == "signin").count() == 5   # re-read boundary rows not doubled

    t = reroute(conn, [{**hunt, "body": {"results": []}}])
    sync(session, conn, "logon_events")                                  # next sync: newest time minus the overlap
    assert "datetime(2026-09-20T09:34:00Z)" in calls_to(t, HUNT, "POST")[0]["json"]["Query"]


def test_a_full_page_at_one_timestamp_cannot_loop_forever(session):
    rows = [{**r, "Timestamp": "2026-09-20T10:00:00Z"} for r in _rows(3)]
    hunt = {k: v for k, v in _logon_route().items() if k != "body_contains"}
    conn = fresh("defender_identity", [{**hunt, "body": {"results": rows}}])
    conn.settings = {**conn.settings, "hunting_page_size": 3}
    rep, cp = sync(session, conn, "logon_events")
    assert not rep.errors and rep.pages <= 2 and cp.cursor == "since:2026-09-20T10:00:00Z"


def test_a_person_named_only_by_sid_joins_the_entra_user_through_the_directory(session):
    """The workbook's rule for on-premises identities: AccountSid maps to Entra by the directory
    (onPremisesSecurityIdentifier), not by name similarity; machine accounts are not people."""
    reg = ConnectorRegistry.all_fake()
    sync(session, reg.get("entra"), "users")
    sync(session, reg.get("defender_identity"), "alerts")
    sync(session, reg.get("defender_identity"), "logon_events")
    store = ContextStore(session)
    sids = {r["AccountSid"] for r in _logon_route()["body"]["results"] if r["AccountSid"]}
    for s in sids:
        hits = session.query(EntityKey).filter(EntityKey.key_name == "sid", EntityKey.key_value == s.lower()).all()
        assert len(hits) == 1, s                                          # one person per SID, never a duplicate
        person = session.get(Entity, hits[0].entity_id)
        assert store.keys_of(person.id).get("entra_object_id"), "the SID resolved to the directory user"
    alert = demo_routes("defender_identity")[0]["body"]["value"][0]
    sid = next(e["userAccount"]["userSid"] for e in alert["evidence"] if "userAccount" in e)
    owner = session.query(EntityKey).filter(EntityKey.key_name == "sid", EntityKey.key_value == sid.lower()).one()
    linked = [e for _, e in store.neighbors(owner.entity_id) if e.kind == "alert"]
    assert [e.display_name for e in linked] == [alert["title"]]
    people = session.query(Entity).filter(Entity.kind == "identity").all()
    assert not [p for p in people if p.display_name.endswith("$")]       # the machine account is not a person
