"""The data handoff workbook's estate (scripts/build_estate_variant.py --handoff): its data rules, its privacy rules and
every acceptance scenario's ground truth, on the real pipelines. docs/DATA_HANDOFF_RECONCILIATION.md maps each test
to the workbook row it proves."""

from __future__ import annotations

import ipaddress
import json
import re
import sys
from pathlib import Path

import pytest

from soc_platform.tests.conftest import estate_env
from soc_platform.tests.test_consistency import _estate

ROOT = Path(__file__).resolve().parents[2]
RESERVED_TLDS = (".invalid", ".example", ".test", ".localhost")
DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]


@pytest.fixture(scope="module")
def handoff(estate_configs):
    """The estate's pipelines run once (phishing, incident, vulnerability, misconfiguration, intelligence)."""
    from soc_platform.connectors.registry import ConnectorRegistry
    from soc_platform.core.db import Database

    cfg = estate_configs["handoff"]
    db = Database("sqlite://")
    db.create_all()
    with estate_env(cfg):
        reg = ConnectorRegistry.all_fake()
        with db.session() as s:
            _estate(s, reg, cfg)
        yield cfg, db


def _profile(cfg):
    sys.path.insert(0, str(ROOT / "scripts"))
    import estate_profile

    with estate_env(cfg):
        return estate_profile.profile(cfg["fixtures_dir"], cfg["org"])


# ------------------------------------------------------------------ the workbook's data rules


def test_the_estate_carries_the_workbook_volume_benign_share_and_replays(estate_configs):
    p = _profile(estate_configs["handoff"])
    assert p["events"] >= 1000, p                                   # ">= 1,000 events across identities and devices"
    assert 0.80 <= p["benign_share"] <= 0.95, p                     # "80-95 % benign background"
    assert 0.01 <= p["replay_share"] <= 0.03, p                     # "1-3 % duplicate / replayed events"


def test_every_address_and_mailbox_is_reserved_for_testing(estate_configs):
    """Privacy rule: fictional entities only, RFC 5737 / private addresses, reserved domains for every mailbox."""
    text = "\n".join(f.read_text(encoding="utf-8") for f in Path(estate_configs["handoff"]["fixtures_dir"]).glob("*.json"))
    public = set()
    for ip in set(re.findall(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])", text)):
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if a.version == 4 and not (a.is_private or a.is_loopback or a.is_unspecified or any(a in n for n in DOC_NETS)):
            public.add(ip)
    assert not public, sorted(public)[:20]
    mailboxes = {m.lower() for m in re.findall(r"[\w.+-]{1,64}@([\w-]{1,63}(?:\.[\w-]{1,63})+)", text)}
    assert not [d for d in mailboxes if not d.endswith(RESERVED_TLDS)], sorted(mailboxes)


def test_documentation_addresses_are_outside_addresses_for_threat_intelligence():
    from soc_platform.connectors.tools.threat_intel import internal_indicator

    assert internal_indicator("ip", "198.51.100.66") is None       # a test-net "attacker" address is looked up
    assert internal_indicator("ip", "10.20.1.15") == "private or reserved address"


# ------------------------------------------------------------------ scenarios


def test_phish_01_the_click_is_found_the_blocked_click_is_not_and_nothing_runs_unapproved(handoff):
    from soc_platform.core.models import ActionRequest, Case

    cfg, db = handoff
    with db.session() as s:
        case = next(c for c in s.query(Case).filter(Case.domain == "phishing")
                    if ((c.assessment or {}).get("user_impact") or {}).get("clicked"))
        impact = case.assessment["user_impact"]
        assert cfg["focus_upn"] in impact["clicked"]
        blocked = [u for u, r in impact["per_user"].items() if r.get("click_blocked")]
        assert blocked and not set(blocked) & set(impact["clicked"])
        assert {a.status for a in s.query(ActionRequest)} <= {"recommended", "pending_approval", "blocked"}


def test_phish_02_consent_after_the_click_is_flagged_and_a_routine_consent_is_not(handoff):
    from soc_platform.intelligence.models import Insight

    cfg, db = handoff
    with db.session() as s:
        ins = s.query(Insight).filter(Insight.rule == "consent_after_phishing").all()
        assert len(ins) == 1 and cfg["focus_upn"] in ins[0].title and "verify the application" in ins[0].title
        assert "other.demo" not in " ".join(i.title for i in ins)


def test_inc_01_and_edge_01_one_device_many_tools_distinct_alert_ids_and_the_disagreement_held(handoff):
    from soc_platform.core.models import ActionRequest, Case, CaseEntity, Entity

    _cfg, db = handoff
    with db.session() as s:
        case = next(c for c in s.query(Case).filter(Case.domain == "incident") if (c.assessment or {}).get("verdict_conflict"))
        alerts = [s.get(Entity, ln.entity_id) for ln in s.query(CaseEntity).filter(CaseEntity.case_id == case.id,
                                                                                    CaseEntity.role == "alert")]
        tools = {(a.attributes or {}).get("tool") for a in alerts}
        assert {"crowdstrike", "defender_endpoint"} <= tools
        assert len({a.id for a in alerts}) == len(alerts)
        acts = s.query(ActionRequest).filter(ActionRequest.case_id == case.id).all()
        assert acts and all(a.autonomy_level <= 3 for a in acts)


def test_edge_01_two_people_on_one_public_address_stay_two_people(handoff):
    from soc_platform.core.context_store import ContextStore
    from soc_platform.core.models import Entity

    cfg, db = handoff
    with db.session() as s:
        store = ContextStore(s)
        upns = {store.keys_of(e.id).get("upn") for e in s.query(Entity).filter(Entity.kind == "identity")}
        assert {f"analyst.demo@{cfg['org']}", f"other.demo@{cfg['org']}"} <= upns


def test_edge_02_a_reused_host_name_and_address_never_joins_the_device(handoff):
    from soc_platform.core.context_store import ContextStore
    from soc_platform.core.models import Entity, UnresolvedItem

    _cfg, db = handoff
    with db.session() as s:
        store = ContextStore(s)
        laptop = [e for e in s.query(Entity).filter(Entity.kind == "asset")
                  if store.keys_of(e.id).get("crowdstrike_aid") == "cs-aid-reuse-0001"]
        assert not [e for e in laptop if store.keys_of(e.id).get("serial_number") != "CZC9REUSE01"]   # never merged
        held = [u for u in s.query(UnresolvedItem) if "cs-aid-reuse-0001" in json.dumps(u.__dict__, default=str)]
        assert laptop or held                                          # its own record, or waiting for an analyst


def test_edge_03_replayed_records_are_stored_once(handoff):
    from soc_platform.core.models import SourceRecord

    _cfg, db = handoff
    with db.session() as s:
        keys = [(r.tool, r.source_type, r.source_id) for r in s.query(SourceRecord)]
        assert len(keys) == len(set(keys))


def test_vm_01_and_vm_02_one_finding_per_asset_and_cve_and_an_expired_exception_suppresses_nothing(handoff):
    from soc_platform.domains.vulnerability.models import ConsolidatedFinding

    _cfg, db = handoff
    with db.session() as s:
        rows = s.query(ConsolidatedFinding).all()
        pairs = [(f.asset_id, f.cve) for f in rows]
        assert rows and len(pairs) == len(set(pairs))
        held = [f for f in rows if (f.sources.get("rapid7") or {}).get("tool_exception")]
        assert held and all(f.status in {"open", "reopened"} for f in held)
