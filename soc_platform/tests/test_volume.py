"""Volume: the work per record must not grow with the size of the estate.

A client tenant is far larger than the demo. These tests count SQL statements (deterministic, unlike timings) and
require the cost of one more record to stay flat as the estate grows - the property that broke before: every new
host loaded every host behind the company's NAT address, and 50 arbitrary hosts sharing its naming prefix.
"""

from __future__ import annotations

import importlib.util
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import event

from soc_platform.connectors.base import SyncRunner
from soc_platform.core.context_store import ContextStore
from soc_platform.core.db import Database
from soc_platform.core.schema import EntityRef, NormalizedRecord

ROOT = Path(__file__).resolve().parents[2]
WHEN = datetime(2026, 9, 20, 10, 0, tzinfo=UTC)


class Counter:
    def __init__(self, db: Database) -> None:
        self.n = 0
        event.listen(db.engine, "before_cursor_execute", self._on)

    def _on(self, *a, **k) -> None:
        self.n += 1


def _host(i: int) -> NormalizedRecord:
    """A laptop as an EDR reports it: sequential fleet name, own IP, and the NAT egress address the whole company
    shares."""
    return NormalizedRecord(kind="asset", tool="crowdstrike", source_type="device", source_id=f"aid-{i:05d}",
                            observed_at=WHEN, title=f"LAPTOP-{i:05d}",
                            keys={"crowdstrike_aid": f"aid-{i:05d}", "serial": f"SN{i:07d}"},
                            attributes={"hostname": f"LAPTOP-{i:05d}", "ips": [f"10.{i // 250}.{i % 250}.10", "198.51.100.44"],
                                        "os": "Windows 11 Enterprise"})


def _cost_of_next_hosts(store: ContextStore, counter: Counter, start: int, n: int = 20) -> float:
    before = counter.n
    for i in range(start, start + n):
        store.ingest(_host(i))
    return (counter.n - before) / n


def test_a_new_host_costs_the_same_with_a_large_fleet_behind_one_nat_address(tmp_path):
    db = Database(f"sqlite:///{(tmp_path / 'v.db').as_posix()}")
    db.create_all()
    counter = Counter(db)
    with db.session() as s:
        store = ContextStore(s)
        small = (_cost_of_next_hosts(store, counter, 0, 40), _cost_of_next_hosts(store, counter, 40))
        for i in range(60, 600):                          # grow the fleet: same prefix, same egress address
            store.ingest(_host(i))
        large = _cost_of_next_hosts(store, counter, 600)
    assert large <= small[1] * 1.2 + 2, (small, large)  # flat - it grew with the fleet before (O(n) per host)


def test_a_dns_event_naming_a_host_with_a_namesake_links_by_its_ip_instead_of_queueing(tmp_path):
    db = Database(f"sqlite:///{(tmp_path / 'n.db').as_posix()}")
    db.create_all()
    with db.session() as s:
        store = ContextStore(s)
        for aid, ip, seen in (("aid-a", "10.0.0.5", WHEN), ("aid-b", "10.9.9.9", datetime(2026, 6, 1, tzinfo=UTC))):
            store.ingest(NormalizedRecord(kind="asset", tool="crowdstrike", source_type="device", source_id=aid,
                                          observed_at=seen, title="KIOSK-01", keys={"crowdstrike_aid": aid},
                                          attributes={"hostname": "KIOSK-01", "ip": ip, "os": "Windows 11"}))
        dns = NormalizedRecord(kind="dns", tool="umbrella", source_type="dns_request", source_id="q1", observed_at=WHEN,
                               title="DNS allowed example.org",
                               refs=[EntityRef(kind="asset", role="host", attributes={"hostname": "KIOSK-01", "ip": "10.0.0.5"})])
        store.ingest(dns)
        from soc_platform.core.models import UnresolvedItem

        assert s.query(UnresolvedItem).filter(UnresolvedItem.status == "open").count() == 0


def test_the_entity_lookup_every_record_makes_uses_an_index(tmp_path):
    db = Database(f"sqlite:///{(tmp_path / 'i.db').as_posix()}")
    db.create_all()
    q = "SELECT * FROM entities WHERE kind = 'dns' AND canonical_key = 'x'"
    with db.engine.connect() as c:
        if db.engine.dialect.name == "postgresql":
            # PostgreSQL plans from statistics: give it a realistic table (many events of one kind), then ask
            c.exec_driver_sql("INSERT INTO entities (id, kind, display_name, canonical_key, attributes, confidence, "
                              "first_seen, last_seen, updated_at) SELECT md5(g::text), 'dns', '', 'k' || g, '{}', 1, "
                              "now(), now(), now() FROM generate_series(1, 5000) g")
            c.exec_driver_sql("ANALYZE entities")
            plan = " ".join(r[0] for r in c.exec_driver_sql(f"EXPLAIN {q}").fetchall())
            c.rollback()
            # either index that covers the canonical key is selective; the kind-only index (or a scan) is not
            assert "ix_entities_kind_canonical" in plan or "ix_entities_canonical_key" in plan, plan
            return
        plan = " ".join(r[-1] for r in c.exec_driver_sql(f"EXPLAIN QUERY PLAN {q}").fetchall())
    assert "ix_entities_kind_canonical" in plan, plan


@pytest.fixture(scope="module")
def messy_estates(tmp_path_factory):
    spec = importlib.util.spec_from_file_location("build_estate_variant", ROOT / "scripts" / "build_estate_variant.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return {sc: json.loads((mod.main(str(tmp_path_factory.mktemp(f"messy{sc}")), seed=11, scale=sc, messy=True)
                            / "estate.json").read_text()) for sc in (2, 8)}


def test_sync_cost_per_record_stays_flat_on_a_messy_estate_four_times_larger(messy_estates, monkeypatch, tmp_path):
    from soc_platform.connectors.registry import ConnectorRegistry

    per_record = {}
    for sc, est in messy_estates.items():
        monkeypatch.setenv("SOC_FIXTURES_DIR", est["fixtures_dir"])
        monkeypatch.setenv("SOC_ORG_DOMAINS", est["org"])
        monkeypatch.setenv("SOC_RAW_PAYLOAD_DIR", str(tmp_path / f"raw{sc}"))
        db = Database(f"sqlite:///{(tmp_path / f'm{sc}.db').as_posix()}")
        db.create_all()
        counter = Counter(db)
        reg = ConnectorRegistry.all_fake()
        with db.session() as s:
            reps = SyncRunner(s, ContextStore(s)).sync_many(
                [(reg.get(n), st) for n in reg.enabled_names() for st in reg.get(n).streams])
        assert sum(r.failed for r in reps) == 0 and not [r.errors for r in reps if r.errors]
        records = sum(r.ingested for r in reps)
        assert est["messy"]["renamed"] + est["messy"]["unicode"] + est["messy"]["stale"] > 0   # the disorder is there
        per_record[sc] = counter.n / records
    assert per_record[8] <= per_record[2] * 1.15, per_record


class _Stream:
    """N pages of records; ``break_at`` makes the download fail there (a network outage mid-backfill)."""
    name = tool = "stream"
    streams = ("s",)

    def __init__(self, pages: int, per_page: int = 50, break_at: int | None = None, bad: str | None = None) -> None:
        from soc_platform.connectors.base import BaseConnector

        self.base = BaseConnector
        self.pages, self.per_page, self.break_at, self.bad = pages, per_page, break_at, bad

    def call(self, fn):
        return fn()

    def fetch_page(self, stream, cursor):
        from soc_platform.connectors.base import Page, TransientError

        i = int(cursor or 0)
        if self.break_at is not None and i == self.break_at:
            raise TransientError("connection reset")
        recs = [{"id": f"r{i}-{j}"} for j in range(self.per_page)]
        return Page(recs, str(i + 1), has_more=i + 1 < self.pages)

    def normalize(self, stream, raw):
        return [NormalizedRecord(kind="process", tool="stream", source_type="ev", source_id=raw["id"],
                                 observed_at=WHEN, title=raw["id"],
                                 attributes={"bad": "\x00" * 9000} if raw["id"] == self.bad else {})]


def test_a_sync_takes_one_savepoint_per_page_not_per_record(tmp_path):
    db = Database(f"sqlite:///{(tmp_path / 's.db').as_posix()}")
    db.create_all()
    savepoints = []
    event.listen(db.engine, "before_cursor_execute",
                 lambda c, cur, stmt, *a: savepoints.append(1) if stmt.startswith("SAVEPOINT") else None)
    with db.session() as s:
        rep = SyncRunner(s, ContextStore(s)).sync(_Stream(4, per_page=200), "s")
    assert rep.ingested == 800 and len(savepoints) <= 4 * 2, len(savepoints)   # was 800: a PostgreSQL lock each


def test_an_interrupted_backfill_keeps_its_pages_and_resumes_after_the_last_one(tmp_path):
    from soc_platform.core.models import SourceRecord

    db = Database(f"sqlite:///{(tmp_path / 'b.db').as_posix()}")
    db.create_all()
    with db.session() as s:
        rep = SyncRunner(s, ContextStore(s)).sync(_Stream(6, break_at=3), "s")
        assert rep.errors and rep.pages == 3
        s.rollback()                                   # the job failed: its transaction is rolled back
    with db.session() as s:
        assert s.query(SourceRecord).count() == 150   # ...but the three pages already read stay stored
        rep = SyncRunner(s, ContextStore(s)).sync(_Stream(6), "s")
        assert rep.pages == 3 and rep.ingested == 150  # and the next run goes on from page 3, not from the start
        assert s.query(SourceRecord).count() == 300


def test_one_record_that_cannot_be_stored_is_isolated_and_the_page_still_lands(tmp_path):
    from soc_platform.core.models import SourceRecord

    db = Database(f"sqlite:///{(tmp_path / 'r.db').as_posix()}")
    db.create_all()
    with db.session() as s:
        store = ContextStore(s)
        real = store.ingest

        def ingest(rec):
            if rec.source_id == "r0-7":
                raise ValueError("database refused the value")
            return real(rec)

        store.ingest = ingest
        rep = SyncRunner(s, store).sync(_Stream(1), "s")
        assert rep.ingested == 49 and rep.failed == 1 and "refused" in rep.errors[0]
        assert s.query(SourceRecord).count() == 49


def test_old_telemetry_is_pruned_unless_something_still_points_at_it(tmp_path):
    # a client tenant writes hundreds of thousands of sign-ins and DNS events a day: kept forever, every table and index
    # grows without bound. Old events go; what a case, evidence or an insight cites stays, and so does every asset.
    from sqlalchemy import func, select

    from soc_platform.config import Settings
    from soc_platform.core.models import Case, CaseEntity, Entity, EntityKey, Relation, SourceRecord
    from soc_platform.core.retention import run_retention
    from soc_platform.core.selfcheck import run_self_check

    old, new = datetime(2025, 1, 10, tzinfo=UTC), WHEN
    db = Database(f"sqlite:///{(tmp_path / 'r.db').as_posix()}")
    db.create_all()

    def signin(sid: str, when: datetime) -> NormalizedRecord:
        return NormalizedRecord(kind="signin", tool="entra", source_type="signin", source_id=sid, observed_at=when,
                                title="Sign-in success to Outlook", keys={"entra_signin_id": sid},
                                refs=[EntityRef(kind="identity", role="user", keys={"upn": "jo@example.org"})])

    with db.session() as s:
        store = ContextStore(s)
        store.ingest(_host(1))
        gone, cited, recent = (store.ingest(signin(i, w)).entity_id for i, w in
                               (("s-old", old), ("s-cited", old), ("s-new", new)))
        store.ingest(NormalizedRecord(kind="alert", tool="crowdstrike", source_type="alert", source_id="a-old",
                                      observed_at=old, title="Old alert", severity="low"))
        case = Case(domain="incident", title="Account review")
        s.add(case)
        s.flush()
        s.add(CaseEntity(case_id=case.id, entity_id=cited, role="evidence"))
        s.flush()
        st = Settings().model_copy(update={"event_retention_days": 400})
        events = select(func.count()).select_from(Entity).where(Entity.kind == "signin")
        assert run_retention(s, st.model_copy(update={"event_retention_days": 0}))["events"] == 0      # 0 keeps everything
        assert run_retention(s, st, dry_run=True)["events"] == 1 and s.execute(events).scalar() == 3
        assert run_retention(s, st)["events"] == 1
        left = set(s.execute(select(Entity.id)).scalars())
        assert gone not in left and {cited, recent} <= left
        assert s.execute(select(func.count()).select_from(Entity).where(Entity.kind.in_(("alert", "asset")))).scalar() == 2
        for col in (SourceRecord.entity_id, EntityKey.entity_id, Relation.src_id, Relation.dst_id):
            assert not s.execute(select(col).where(col == gone)).first(), col       # nothing left pointing at it
        assert run_retention(s, st)["events"] == 0                                 # a re-run changes nothing
        assert run_self_check(s)["ok"]
