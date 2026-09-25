from __future__ import annotations

from datetime import datetime, timedelta, timezone

from soc_platform.connectors.base import BaseConnector, RateLimited, SyncRunner, iter_records, with_backoff
from soc_platform.core.context_store import ContextStore
from soc_platform.core.entity_resolution import EntityResolver
from soc_platform.core.models import UnresolvedItem
from soc_platform.core.schema import EntityRef, NormalizedRecord
from soc_platform.llm.gateway import LLMGateway, Provider, Completion, deterministic_grounded
from soc_platform.llm.redaction import Redactor
from soc_platform.config import Settings

T0 = datetime(2026, 9, 1, tzinfo=timezone.utc)


def asset(tool, sid, keys=None, **attrs):
    return NormalizedRecord(kind="asset", tool=tool, source_type="host", source_id=sid, keys=keys or {},
                            attributes=attrs, observed_at=T0)


# --------------------------------------------------------------------------- entity resolution (6.2)


def test_deterministic_cross_tool_match_on_serial(session):
    store = ContextStore(session)
    a = store.ingest(asset("crowdstrike", "cs1", {"crowdstrike_aid": "AID1", "serial_number": "SN123"},
                           hostname="WEB01.corp.local", os="Windows Server 2019"))
    b = store.ingest(asset("defender", "md1", {"mde_device_id": "MD1", "serial_number": "sn123"},
                           hostname="web01", os="Windows"))
    assert a.entity_id == b.entity_id and b.resolution_method == "deterministic"


def test_probabilistic_match_requires_multiple_signals(session):
    store = ContextStore(session)
    a = store.ingest(asset("rapid7", "r1", {"rapid7_asset_id": "1"}, fqdn="db01.corp.local", ip="10.0.0.5",
                           os="Ubuntu Linux"))
    b = store.ingest(asset("wiz", "w1", {"wiz_id": "x"}, fqdn="db01.corp.local", ip="10.0.0.5", os="linux"))
    assert b.entity_id == a.entity_id and b.resolution_method == "probabilistic"


def test_ambiguous_goes_to_unresolved_queue_not_merged(session, analyst):
    store = ContextStore(session)
    store.ingest(asset("rapid7", "r1", {"rapid7_asset_id": "1"}, hostname="app01", os="windows"))
    b = store.ingest(asset("wiz", "w1", {"wiz_id": "x"}, hostname="app01", os="windows"))
    assert b.entity_id is None and b.resolution_method == "ambiguous"
    item = session.query(UnresolvedItem).one()
    rate = EntityResolver(session).match_rate("asset")
    assert rate["unresolved"] == 1 and rate["match_rate"] == 0.5
    # Analyst decides; the decision is durable for re-ingestion of the same record.
    target = item.candidates[0]["entity_id"]
    EntityResolver(session).override(item.id, target, analyst, reason="same VM")
    again = store.ingest(asset("wiz", "w1", {"wiz_id": "x"}, hostname="app01", os="windows"))
    assert again.entity_id == target
    assert EntityResolver(session).match_rate("asset")["match_rate"] == 1.0


def test_conflicting_serial_prevents_merge(session):
    store = ContextStore(session)
    a = store.ingest(asset("crowdstrike", "c1", {"serial_number": "AAA"}, fqdn="h.corp", ip="10.1.1.1", os="windows"))
    b = store.ingest(asset("defender", "d1", {"serial_number": "BBB"}, fqdn="h.corp", ip="10.1.1.1", os="windows"))
    assert a.entity_id != b.entity_id


def test_stale_ip_is_ignored():
    from soc_platform.core.entity_resolution import score_asset
    from soc_platform.core.models import Entity

    cand = Entity(id="e", kind="asset", attributes={"os": "windows"}, last_seen=T0 - timedelta(days=30))
    c = score_asset({"ip": ["10.0.0.9"]}, {"os": "windows"}, T0, cand, {"ip": {"10.0.0.9"}}, timedelta(days=3))
    assert "ip match outside window (ignored)" in c.reasons


# --------------------------------------------------------------------------- events, relations, timeline


def test_event_links_resolved_entities_and_timeline(session):
    store = ContextStore(session)
    store.ingest(asset("crowdstrike", "c1", {"crowdstrike_aid": "A1"}, hostname="laptop7", os="windows"))
    alert = NormalizedRecord(
        kind="alert", tool="crowdstrike", source_type="detection", source_id="d1", observed_at=T0,
        title="Suspicious PowerShell", severity="high",
        refs=[EntityRef(kind="asset", role="host", keys={"crowdstrike_aid": "A1"}),
              EntityRef(kind="identity", role="user", keys={"upn": "Jane@corp.com"}),
              EntityRef(kind="indicator", role="observable", keys={"value": "EVIL.com"}, attributes={"type": "domain"})])
    store.ingest(alert)
    signin = NormalizedRecord(kind="signin", tool="entra", source_type="signin", source_id="s1",
                              observed_at=T0 + timedelta(minutes=5), title="Risky sign-in",
                              refs=[EntityRef(kind="identity", role="user", keys={"upn": "jane@corp.com"})])
    store.ingest(signin)
    user = store.find("identity", "upn", "JANE@corp.com")
    host = store.find("asset", "crowdstrike_aid", "a1")
    assert user and host
    assert store.find("indicator", "domain", "evil.com") is not None
    tl = store.timeline([user.id, host.id])
    assert [r["title"] for r in tl] == ["Suspicious PowerShell", "Risky sign-in"]


def test_reference_by_hostname_links_single_exact_candidate(session):
    store = ContextStore(session)
    h = store.ingest(asset("crowdstrike", "c1", {"crowdstrike_aid": "A1"}, hostname="kiosk42"))
    for i in range(2):
        store.ingest(NormalizedRecord(kind="dns", tool="umbrella", source_type="dns", source_id=f"q{i}",
                                      observed_at=T0, refs=[EntityRef(kind="asset", role="host",
                                                                      attributes={"hostname": "KIOSK42"})]))
    events = store.events_for(h.entity_id)
    assert len(events) == 2


# --------------------------------------------------------------------------- connectors (VM-T02)


class ListConnector(BaseConnector):
    name = tool = "listtool"
    streams = ("hosts",)

    def __init__(self, rows, page_size=2, bad=None):
        super().__init__(rate_per_sec=1000, burst=1000)
        self.rows, self.page_size, self.bad = rows, page_size, bad or set()

    def fetch_page(self, stream, cursor):
        return iter_records(self.rows, self.page_size, cursor)

    def normalize(self, stream, raw):
        if raw["id"] in self.bad:
            raise ValueError("malformed")
        return [asset(self.tool, raw["id"], {"crowdstrike_aid": raw["id"]}, hostname=raw["id"])]


def test_sync_checkpoints_reconciles_and_isolates_bad_records(session):
    rows = [{"id": f"h{i}"} for i in range(5)]
    runner = SyncRunner(session, ContextStore(session))
    rep = runner.sync(ListConnector(rows, bad={"h3"}), "hosts")
    assert rep.pages == 3 and rep.source_records == 5 and rep.ingested == 4 and rep.failed == 1
    assert not rep.reconciled
    rows.append({"id": "h5"})
    rep2 = runner.sync(ListConnector(rows), "hosts")  # incremental: resumes at the cursor
    assert rep2.source_records == 1 and rep2.ingested == 1


def test_backoff_retries_rate_limits():
    calls = {"n": 0}

    def flaky():
        calls["n"] += 1
        if calls["n"] < 3:
            raise RateLimited(retry_after=0)
        return "ok"

    assert with_backoff(flaky, sleep=lambda _: None) == "ok" and calls["n"] == 3


# --------------------------------------------------------------------------- LLM governance (NFR-11)


def test_redaction_pseudonymises_internal_people_but_keeps_iocs():
    r = Redactor(internal_domains={"cci.com"}, known_names={"Priya Sharma"})
    text = "Priya Sharma (priya@cci.com, +91 98765 43210) clicked http://evil.io from 10.2.3.4, sender a@evil.io"
    out = r.redact(text)
    assert "priya@cci.com" not in out and "Priya Sharma" not in out and "98765" not in out
    assert "http://evil.io" in out and "10.2.3.4" in out and "a@evil.io" in out
    assert r.restore(out) == text


class FakeProvider(Provider):
    name = "fake"

    def __init__(self, text):
        self.text = text
        self.last_user = ""

    def complete(self, system, user, *, tier):
        self.last_user = user
        return Completion(self.text, 100, 50, "gpt-test")


def test_grounded_drops_uncited_claims_and_logs(session):
    prov = FakeProvider('{"summary": "phish", "claims": ['
                        '{"text": "sender spoofed", "kind": "fact", "evidence_ids": ["E1"]},'
                        '{"text": "made up", "kind": "fact", "evidence_ids": ["E99"]}]}')
    gw = LLMGateway(session, Settings(), provider=prov)
    out = gw.grounded("test", "why?", [{"id": "E1", "claim": "SPF fail", "source": "header"}])
    assert [c["text"] for c in out["claims"]] == ["sender spoofed"] and out["source"] == "llm"
    assert gw.tokens_this_month() == 150


def test_grounded_insufficient_evidence_and_budget(session):
    gw = LLMGateway(session, Settings(llm_monthly_token_budget=100), provider=FakeProvider("{}"))
    assert gw.grounded("t", "q", [])["insufficient_evidence"] is True
    gw.complete_json("t", "s", "u")  # consumes 150 tokens
    out = gw.grounded("t", "q", [{"id": "E1", "claim": "x"}])  # budget exceeded -> deterministic
    assert out["source"] == "deterministic"
    assert deterministic_grounded([{"id": "E1", "claim": "x"}])["claims"][0]["evidence_ids"] == ["E1"]
