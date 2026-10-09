"""Discrepancies in data and inputs degrade one field or one item, visibly - they never break the platform.

* vendor records  - a field in an unexpected type is brought to the stream's documented shape (connectors/conform.py),
                    the record is kept, and the sync reports which fields needed it (a data-quality log line)
* canonical schema - a numeric id is the same id as text; an odd title, severity or attribute map is emptied
* reported e-mail - content the parser cannot read reliably (UTF-16, NUL bytes, no sender, damaged MIME) is never
                    called safe: it is held for an analyst with the reason as evidence
* settings        - a mistyped value stops the start with every problem and its fix, never a bare traceback; a
                    misspelt setting name is reported with the nearest real one
"""

from __future__ import annotations

import logging
from collections import Counter
from datetime import UTC

import pytest

from soc_platform.config import SettingsError, get_settings
from soc_platform.connectors.base import SyncRunner
from soc_platform.connectors.conform import conform, shape_of
from soc_platform.connectors.registry import ConnectorRegistry
from soc_platform.core.context_store import ContextStore
from soc_platform.core.schema import NormalizedRecord
from soc_platform.domains.phishing.agents.decompose import decompose
from soc_platform.domains.phishing.service import PhishingService
from soc_platform.settings_check import check_environment
from soc_platform.tests.test_phishing import CORPUS, corpus  # noqa: F401 - pytest fixture


# ============================================================================== shape conforming
def test_a_record_in_the_documented_shape_is_returned_untouched():
    rec = {"id": "a1", "host": {"name": "web01", "ips": ["10.0.0.1"]}, "score": 7.5, "open": True}
    notes: Counter = Counter()
    assert conform(rec, shape_of(rec), notes) is rec and not notes


def test_wrong_typed_fields_are_brought_to_the_documented_shape_and_counted():
    shape = shape_of({"host": {"name": "x"}, "tags": [{"k": "v"}], "score": 1, "open": False, "label": "x"})
    notes: Counter = Counter()
    rec = {"host": "web01", "tags": {"k": "v"}, "score": "42", "open": "yes", "label": 12345, "extra": [1]}
    out = conform(rec, shape, notes)
    assert out == {"host": {}, "tags": [{"k": "v"}], "score": 42, "open": True, "label": "12345", "extra": [1]}
    assert rec["host"] == "web01"                       # the vendor's record itself is not modified
    assert notes == {"host: expected an object": 1, "tags: expected a list (got one object)": 1}


def test_values_that_cannot_be_read_as_the_documented_type_become_empty():
    shape = shape_of({"score": 1, "open": True, "name": "x", "items": [{"a": 1}]})
    notes: Counter = Counter()
    out = conform({"score": "high", "open": "maybe", "name": {"x": 1}, "items": ["junk", {"a": 2}, None]}, shape, notes)
    assert out == {"score": None, "open": None, "name": None, "items": [{"a": 2}, None]}
    assert set(notes) == {"score: expected a number", "open: expected true or false", "name: expected text",
                          "items: expected a list of objects"}


def test_the_canonical_schema_accepts_numeric_ids_and_empties_odd_fields():
    rec = NormalizedRecord(kind="alert", tool="t", source_type="alert", source_id=123, title={"x": 1},
                           severity=["high"], attributes=None, deep_link=7)
    assert (rec.source_id, rec.title, rec.severity, rec.attributes, rec.deep_link) == ("123", "", None, {}, None)
    assert NormalizedRecord(kind="alert", tool="t", source_type="a", source_id="x", title=404).title == "404"
    with pytest.raises(ValueError):                    # a boolean or an object is never an identifier
        NormalizedRecord(kind="alert", tool="t", source_type="alert", source_id=True)


def test_a_sync_keeps_records_with_malformed_fields_and_reports_them(session, caplog):
    caplog.set_level(logging.WARNING, logger="soc.events")
    conn = ConnectorRegistry.all_fake().get("defender_endpoint")
    original = conn.fetch_page
    seen: list[int] = []

    def fetch_page(stream, cursor):
        page = original(stream, cursor)
        page.records = [{**r, "title": {"unexpected": "object"}} for r in page.records]
        seen.append(len(page.records))
        return page

    conn.fetch_page = fetch_page
    rep = SyncRunner(session, ContextStore(session)).sync(conn, "alerts")
    assert sum(seen) > 0 and rep.failed == 0 and rep.ingested == sum(seen)
    assert rep.coerced == {"title: expected text": sum(seen)}
    line = next(r for r in caplog.records if r.getMessage() == "connector.data_quality")
    assert line.soc_fields["connector"] == "defender_endpoint" and line.soc_fields["stream"] == "alerts"
    assert line.soc_fields["fields_coerced"] == sum(seen)
    assert conn.take_quality("alerts") == {}            # reported once, then cleared


def test_a_record_without_a_usable_identifier_is_refused_with_a_reason_and_the_rest_land(session):
    conn = ConnectorRegistry.all_fake().get("rapid7")
    original = conn.fetch_page

    def fetch_page(stream, cursor):
        page = original(stream, cursor)
        if page.records:
            page.records = [{**page.records[0], "asset": {**page.records[0]["asset"], "id": True}}, *page.records[1:]]
        return page

    conn.fetch_page = fetch_page
    rep = SyncRunner(session, ContextStore(session)).sync(conn, "findings")
    assert rep.failed == 1 and rep.ingested >= 1
    assert "identifier" in rep.errors[0]


# ============================================================================== vendor times
@pytest.mark.parametrize("value,expected", [
    (0, None), (-1, None), (10**15, None), (1e308, None), (float("nan"), None), (True, None), ("junk", None),
    ("0001-01-01T00:00:00Z", None),                                  # .NET's "no value"
    ("1700000000", "2023-11-14T22:13:20+00:00"), (1700000000123, "2023-11-14T22:13:20.123000+00:00"),
    ("2026-09-20T10:00:00.1234567Z", "2026-09-20T10:00:00.123456+00:00"), ("2026-09-20 10:00:00", "2026-09-20T10:00:00+00:00"),
])
def test_vendor_times_are_read_or_treated_as_absent_never_raised(value, expected):
    from soc_platform.connectors.tools._common import parse_ts

    got = parse_ts(value)
    assert (got.isoformat() if got else None) == expected


def test_a_time_far_in_the_future_is_stored_as_seen_now_and_does_not_skew_risk(session):
    from datetime import datetime, timedelta

    from soc_platform.core.models import Entity, utcnow

    store = ContextStore(session)
    src = store.ingest(NormalizedRecord(kind="alert", tool="t", source_type="alert", source_id="far-future",
                                        observed_at=datetime(9999, 12, 31, tzinfo=UTC), title="placeholder date"))
    assert abs(src.last_seen - utcnow()) < timedelta(minutes=5)
    assert src.normalized["attributes"]["reported_time"].startswith("9999-12-31")
    latest = session.query(Entity).order_by(Entity.last_seen.desc()).first().last_seen
    assert latest.year < 9999


# ============================================================================== the ownership spreadsheet
def _cmdb(path):
    from soc_platform.connectors.tools.itsm import CsvCmdbConnector

    return CsvCmdbConnector({"path": str(path)}, None)


@pytest.mark.parametrize("encoding,sep", [("utf-8", ","), ("utf-8-sig", ","), ("cp1252", ";"), ("utf-8", "\t")])
def test_the_ownership_file_is_read_however_excel_saved_it(tmp_path, encoding, sep):
    f = tmp_path / "owners.csv"
    rows = [["Host Name", " Owner Email ", "Team", "Env", "Criticality"],
            ["web01", "zoë.ops@acme-demo.com", "Web Team", "prod", "high"], [], ["db*", "dba@acme-demo.com", "DBA", "", ""]]
    f.write_bytes("\r\n".join(sep.join(r) for r in rows).encode(encoding))
    conn = _cmdb(f)
    assert conn.owner_for({"hostname": "WEB01.acme-demo.com"})["owner"] == "zoë.ops@acme-demo.com"
    assert conn.owner_for({"hostname": "db07"})["platform_team"] == "DBA"
    (rec,) = [r for raw in conn.rows() for r in conn.normalize("cmdb", raw)]   # the pattern row is a rule, not an asset
    assert rec.attributes["hostname"] == "web01" and rec.attributes["environment"] == "prod"


def test_an_ownership_file_without_a_hostname_column_yields_nothing_and_says_so(tmp_path, caplog):
    f = tmp_path / "owners.csv"
    f.write_text("machine,person\nweb01,a@acme-demo.com\n", encoding="utf-8")
    assert _cmdb(f).rows() == [] and "no hostname or subscription column" in caplog.text


def test_the_ownership_file_is_re_read_only_when_it_changes(tmp_path, monkeypatch):
    import os

    f = tmp_path / "owners.csv"
    f.write_text("hostname,owner\nweb01,a@acme-demo.com\n", encoding="utf-8")
    conn = _cmdb(f)
    reads = []
    real = type(f).read_bytes
    monkeypatch.setattr(type(f), "read_bytes", lambda self: reads.append(1) or real(self))
    for _ in range(5):
        conn.owner_for({"hostname": "web01"})
    assert len(reads) == 1
    f.write_text("hostname,owner\nweb01,b@acme-demo.com\n", encoding="utf-8")
    os.utime(f, ns=(f.stat().st_atime_ns, f.stat().st_mtime_ns + 10_000_000))
    assert conn.owner_for({"hostname": "web01"})["owner"] == "b@acme-demo.com" and len(reads) == 2


# ============================================================================== reported e-mail
@pytest.fixture()
def legit(corpus) -> bytes:  # noqa: F811 - the fixture imported above
    return (corpus / "legit_github.eml").read_bytes()


def _verdict(session, tmp_path, raw: bytes) -> dict:
    ph = PhishingService(session, ConnectorRegistry.all_fake(), org_domains=["acme-demo.com"], raw_dir=tmp_path)
    sub = ph.submit_raw(raw, source="upload", reporter="jane.doe@acme-demo.com")
    return ph.process(sub.id, narrate=False)


def test_a_message_hidden_in_utf16_is_read_and_flagged(legit):
    plain, wide = decompose(legit), decompose(legit.decode("latin-1").encode("utf-16"))
    assert wide.subject == plain.subject and wide.sender == plain.sender
    assert any("UTF-16" in a for a in wide.anomalies) and not plain.anomalies


def test_nul_bytes_are_removed_before_analysis_and_flagged(legit):
    em = decompose(legit.replace(b"github", b"git\x00hub"))
    assert any("NUL" in a for a in em.anomalies)
    assert all("\x00" not in u for u in em.urls)


@pytest.mark.parametrize("label", ["utf16", "nul bytes", "no sender", "damaged mime"])
def test_a_message_that_cannot_be_read_reliably_is_never_called_safe(session, tmp_path, legit, label):
    head, _, body = legit.partition(b"\n\n")
    raw = {
        "utf16": legit.decode("latin-1").encode("utf-16"),
        "nul bytes": legit.replace(b"e", b"e\x00", 40),
        "no sender": b"\n".join(h for h in head.split(b"\n") if not h.lower().startswith(b"from:")) + b"\n\n" + body,
        "damaged mime": b'From: a@example.org\nContent-Type: multipart/mixed; boundary="zz"\nSubject: t\n\n'
                        b"--zz\nContent-Type: text/plain\nContent-Transfer-Encoding: base64\n\n!!not base64!!\n--yy--",
    }[label]
    out = _verdict(session, tmp_path, raw)
    assert out["case"]["verdict"] in {"suspicious", "malicious"}, out["case"]["verdict"]


def test_the_untouched_message_is_still_safe(session, tmp_path, legit):
    assert _verdict(session, tmp_path, legit)["case"]["verdict"] == "safe"


# ============================================================================== admin documents
ODD_VALUES = [None, "x", "", -1, 10**30, 1.5, float("inf"), float("nan"), True, [], ["x"], {}, {"a": 1}]


def _mutations(doc, path=()):
    """The document with each node in turn replaced by each odd value."""
    for k, v in (doc.items() if isinstance(doc, dict) else []):
        for odd in ODD_VALUES:
            yield (*path, k), odd
        yield from _mutations(v, (*path, k))


def _with(doc, path, value):
    import copy

    out = copy.deepcopy(doc)
    cur = out
    for k in path[:-1]:
        cur = cur[k]
    cur[path[-1]] = value
    return out


def _admin_documents():
    from soc_platform.connectors.config_schema import check_document, load_file
    from soc_platform.core.connector_config import manifests
    from soc_platform.core.policy import DEFAULT_POLICY, policy_problems
    from soc_platform.llm.usage_policy import KNOWN_WORKFLOWS, validate

    usage = {"monthly_tokens": 1000, "daily_tokens": 100, "alert_at": 0.8,
             "user_default": {"hourly_tokens": 10, "daily_tokens": 20}, "roles": {"lead": {"daily_tokens": 50}},
             "users": {"ann@acme-demo.com": {"hourly_tokens": 5}},
             "workflows": {min(KNOWN_WORKFLOWS): {"tier": "small", "max_output_tokens": 500, "enabled": True}},
             "max_output_tokens": {"small": 1500}, "prices": {"small": {"input": 0.4, "output": 1.6}}}
    connectors, _ = load_file()
    ms = manifests()
    return [("autonomy policy", DEFAULT_POLICY, policy_problems), ("AI usage policy", usage, validate),
            ("connector config", connectors, lambda d: check_document(d, ms, check_env=False))]


@pytest.mark.parametrize("label,doc,check", _admin_documents(), ids=lambda x: x if isinstance(x, str) else "")
def test_any_wrong_value_in_an_admin_document_is_rejected_with_a_reason_never_a_crash(label, doc, check):
    assert not [p for p in check(doc) if getattr(p, "level", "error") == "error"], f"the {label} sample is valid"
    crashes = []
    for path, odd in _mutations(doc):
        try:
            check(_with(doc, path, odd))
        except Exception as exc:  # noqa: BLE001 - any exception is the defect under test
            crashes.append(f"{'.'.join(map(str, path))}={odd!r}: {type(exc).__name__}: {exc}")
    assert not crashes, crashes[:10]


def test_an_autonomy_policy_with_a_wrong_type_is_not_saved_and_a_stored_one_fails_safe(session, automation_admin):
    from soc_platform.core.policy import DEFAULT_POLICY, Level, PolicyEngine, PolicyStore

    for bad in ({**DEFAULT_POLICY, "default_level": "abc"}, {**DEFAULT_POLICY, "actions": ["endpoint.isolate"]},
                {**DEFAULT_POLICY, "vip": {"identities": "ceo@acme-demo.com"}}, {**DEFAULT_POLICY, "defualt_level": 2}):
        with pytest.raises(ValueError, match="not saved"):
            PolicyStore(session).propose(bad, automation_admin)
    legacy = PolicyEngine({**DEFAULT_POLICY, "actions": {"endpoint.isolate": {"level": "high", "four_eyes": "true"}}})
    view = legacy.view("endpoint.isolate")
    assert view.level == Level.L2_RECOMMEND and view.four_eyes          # unreadable entry -> recommend, two approvers
    assert PolicyEngine({**DEFAULT_POLICY, "vip": {"identities": "abc"}}).decide(
        "identity.revoke_sessions", [{"type": "identity", "id": "a"}], destructive=False).outcome == "recommended"


# ============================================================================== settings
def test_a_mistyped_value_is_an_error_naming_the_setting():
    problems = check_environment({"SOC_RAW_RETENTION_DAYS": "ten", "SOC_API_WORKERS": "4"})
    assert [(p.level, p.name) for p in problems] == [("error", "SOC_RAW_RETENTION_DAYS")]


def test_a_misspelt_setting_name_is_reported_with_the_nearest_real_one():
    (p,) = check_environment({"SOC_RAW_RETENTON_DAYS": "30"})
    assert p.level == "warning" and "SOC_RAW_RETENTION_DAYS" in p.fix


def test_production_refuses_dev_sign_in_and_no_encryption_key():
    names = {p.name for p in check_environment({"SOC_ENVIRONMENT": "prod"}) if p.level == "error"}
    assert {"SOC_AUTH_MODE", "SOC_DATA_KEY"} <= names


def test_unreadable_settings_stop_with_every_problem_not_a_traceback(monkeypatch):
    monkeypatch.setenv("SOC_RAW_RETENTION_DAYS", "ten")
    monkeypatch.setenv("SOC_LLM_MONTHLY_TOKEN_BUDGET", "50M")
    get_settings.cache_clear()
    try:
        with pytest.raises(SettingsError) as err:
            get_settings()
        assert "SOC_RAW_RETENTION_DAYS" in str(err.value) and "SOC_LLM_MONTHLY_TOKEN_BUDGET" in str(err.value)
    finally:
        monkeypatch.undo()
        get_settings.cache_clear()


def test_config_check_fails_on_a_settings_error(monkeypatch, capsys):
    from soc_platform.__main__ import main

    monkeypatch.setenv("SOC_DB_POOL_SIZE", "lots")
    with pytest.raises(SystemExit) as stop:
        main(["config", "check", "--no-env"])
    assert stop.value.code == 1 and "SOC_DB_POOL_SIZE" in capsys.readouterr().out


def test_postgres_connections_carry_the_statement_timeout(monkeypatch):
    import soc_platform.core.db as dbmod

    class Captured(Exception):
        pass

    seen: dict = {}

    def create_engine(url, **kw):
        seen.update(kw)
        raise Captured

    monkeypatch.setattr(dbmod, "create_engine", create_engine)
    monkeypatch.setenv("SOC_DB_STATEMENT_TIMEOUT_SECONDS", "120")
    with pytest.raises(Captured):
        dbmod.Database("postgresql+psycopg2://u:p@127.0.0.1:1/x")
    assert seen["connect_args"]["options"] == "-c statement_timeout=120000"
    monkeypatch.setenv("SOC_DB_STATEMENT_TIMEOUT_SECONDS", "0")
    assert dbmod.statement_timeout_ms() == 0
