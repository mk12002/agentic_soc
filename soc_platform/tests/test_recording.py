"""Record-and-sanitise: live responses become replayable test fixtures that identify nobody."""

from __future__ import annotations

import json

import pytest

from soc_platform.connectors.base import SyncRunner
from soc_platform.connectors.http import FixtureTransport
from soc_platform.connectors.recording import RecordingTransport, Sanitizer, scan
from soc_platform.connectors.registry import ConnectorRegistry
from soc_platform.core.context_store import ContextStore
from soc_platform.core.db import Database

SALT = "test-salt-0123456789abcdef"
# who and what the demo estate is: none of it may survive in a recording
IDENTIFYING = ["jane.doe", "acme-demo.com", "JANE-LT01", "jane-lt01", "10.20.1.15", "Jane Doe", "u-jane-0001",
               "bob.lee", "Priya Nair"]
STREAMS = [("entra", "users"), ("entra", "signins"), ("crowdstrike", "hosts"), ("crowdstrike", "alerts"),
           ("defender_endpoint", "alerts"), ("defender_endpoint", "machines"), ("umbrella", "dns_activity"),
           ("sentinel", "incidents"), ("servicenow", "cmdb"), ("rapid7", "assets"), ("wiz", "resources"),
           ("delinea_secret_server", "secret_audits"), ("jira", "tickets")]


@pytest.fixture()
def recorded(tmp_path):
    """Every listed stream synced through the recorder, as if live (fixture responses stand in for the tenant)."""
    reg = ConnectorRegistry.all_fake()
    db = Database(f"sqlite:///{(tmp_path / 'rec.db').as_posix()}")
    db.create_all()
    counts = {}
    for name in sorted({n for n, _ in STREAMS}):
        conn = reg.get(name)
        conn.http = RecordingTransport(conn.http, name, tmp_path / "rec", Sanitizer(SALT, ["acme-demo.com"]))
        for n, stream in STREAMS:
            if n == name:
                with db.session() as s:
                    rep = SyncRunner(s, ContextStore(s)).sync(conn, stream, full_backfill=True)
                assert not rep.errors, (name, stream, rep.errors)
                counts[(name, stream)] = rep.ingested
    return tmp_path / "rec", counts


def test_a_recording_identifies_no_one_but_keeps_what_tests_need(recorded):
    folder, _ = recorded
    text = "\n".join(f.read_text(encoding="utf-8") for f in folder.glob("*.json") if f.name != "_scan.json")
    leaks = [x for x in IDENTIFYING if x.lower() in text.lower()]
    assert not leaks, leaks
    assert '"Authorization"' not in text and "client_secret" not in text
    for kept in ('"Phishing"', '"High"', "micros0ft-helpdesk.com",                  # vendor vocabulary, attacker domain
                 "a3f5c0e1b2d4f6a8c0e2b4d6f8a0c2e4b6d8f0a2c4e6b8d0f2a4c6e8b0d2f4a6"):  # file hashes are evidence
        assert kept in text, kept
    report = json.loads((folder / "_scan.json").read_text(encoding="utf-8"))
    assert set(report) >= {n for n, _ in STREAMS} and not any(report.values()), report


def test_a_recording_replays_through_the_same_connectors(recorded, tmp_path):
    folder, counts = recorded
    reg = ConnectorRegistry.all_fake()
    db = Database(f"sqlite:///{(tmp_path / 'replay.db').as_posix()}")
    db.create_all()
    for (name, stream), n in counts.items():
        conn = reg.get(name)
        conn.http = FixtureTransport.from_file(folder / f"{name}.json", name)
        with db.session() as s:
            rep = SyncRunner(s, ContextStore(s)).sync(conn, stream, full_backfill=True)
        assert not rep.errors and rep.ingested == n, (name, stream, rep.errors[:2], rep.ingested, n)


def test_pseudonyms_are_stable_per_salt_and_unlinkable_across_salts():
    a, b, c = Sanitizer(SALT, ["acme-demo.com"]), Sanitizer(SALT, ["acme-demo.com"]), Sanitizer("another-salt-0123456789", ["acme-demo.com"])
    rec = {"userPrincipalName": "jane.doe@acme-demo.com", "ipAddress": "10.20.1.15", "id": "5b7f1c2e-1111-2222-3333-444455556666",
           "hostName": "JANE-LT01", "description": "Jane asked about her laptop JANE-LT01 again today", "severity": "High"}
    assert a.body(rec) == b.body(rec) != c.body(rec)
    out = a.body(rec)
    assert out["severity"] == "High" and out["description"].startswith("[text,") and out["hostName"].isupper()
    assert out["ipAddress"].startswith("10.250.") and out["userPrincipalName"].endswith(".example")
    assert len(out["id"]) == 36 and out["id"].count("-") == 4                       # same shape, other value
    with pytest.raises(ValueError):
        Sanitizer("short")


def test_the_scan_flags_what_sanitising_missed():
    assert scan({"note": "contact bob@acme-demo.com from 10.1.2.3"}) == ["IPv4 address: 10.1.2.3",
                                                                       "e-mail address: bob@acme-demo.com"]
    assert scan({"x": "user-ab12cd@org-1f2e.example from 10.250.3.4"}) == []
