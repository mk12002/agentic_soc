from __future__ import annotations

import pytest
from sqlalchemy import text

from soc_platform.core.actions import ActionService
from soc_platform.core.audit import AuditLog
from soc_platform.core.auth import Role, agent_principal
from soc_platform.core.models import AuditRecord
from soc_platform.core.policy import DEFAULT_POLICY, Level, PolicyEngine, PolicyStore
from soc_platform.tests.conftest import person


def _policy(**levels: int) -> PolicyEngine:
    doc = {**DEFAULT_POLICY, "actions": {**DEFAULT_POLICY["actions"]}}
    for k, v in levels.items():
        doc["actions"][k.replace("__", ".")] = {**doc["actions"].get(k.replace("__", "."), {}), "level": v}
    return PolicyEngine(doc)


# --------------------------------------------------------------------------- audit (NFR-04)


def test_audit_chain_verifies_and_detects_tampering(session):
    log = AuditLog(session)
    for i in range(3):
        log.append(actor_type="agent", actor_id="agent:x", event_type="e", subject_type="t",
                   subject_id=str(i), payload={"i": i})
    assert log.verify()["ok"] is True
    # The database refuses raw SQL too (trigger), so an attacker would need the schema owner's rights to drop it
    import sqlalchemy

    with pytest.raises(sqlalchemy.exc.DatabaseError), session.begin_nested():
        session.execute(text("UPDATE audit_log SET payload = '{\"i\": 99}' WHERE seq = 2"))
    # ... with which they could: the hash chain still exposes the edit
    dialect = session.get_bind().dialect.name
    session.execute(text("DROP TRIGGER audit_log_no_update" if dialect == "sqlite"
                         else "ALTER TABLE audit_log DISABLE TRIGGER audit_log_append_only"))
    session.execute(text("UPDATE audit_log SET payload = '{\"i\": 99}' WHERE seq = 2"))
    session.expire_all()
    result = log.verify()
    assert result["ok"] is False and result["first_bad_seq"] == 2


def test_audit_orm_refuses_update_and_delete(session):
    rec = AuditLog(session).append(actor_type="system", actor_id="sys", event_type="e",
                                   subject_type="t", subject_id="1")
    rec.event_type = "changed"
    with pytest.raises(PermissionError):
        session.flush()
    session.rollback()
    rec = session.get(AuditRecord, 1) or AuditLog(session).append(
        actor_type="system", actor_id="sys", event_type="e", subject_type="t", subject_id="1")
    session.delete(rec)
    with pytest.raises(PermissionError):
        session.flush()
    session.rollback()


def test_audit_rejects_unknown_actor_type(session):
    with pytest.raises(ValueError):
        AuditLog(session).append(actor_type="robot", actor_id="r", event_type="e", subject_type="t", subject_id="1")


# --------------------------------------------------------------------------- policy gates (5.2, R04)


def test_default_posture_is_recommend_only():
    d = PolicyEngine().decide("endpoint.isolate", [{"type": "asset", "id": "h1"}], destructive=False)
    assert d.outcome == "recommended" and d.effective_level == Level.L2_RECOMMEND


def test_destructive_and_vip_and_killswitch_cap_autonomy():
    pe = _policy(email__soft_delete=4, endpoint__isolate=4)
    assert pe.decide("email.soft_delete", [], destructive=True).outcome == "pending_approval"
    d = pe.decide("endpoint.isolate", [{"type": "asset", "id": "h", "tags": ["critical"]}], destructive=False)
    assert d.outcome == "pending_approval" and d.high_impact
    pe.kill_switch = True
    assert pe.decide("endpoint.isolate", [{"type": "asset", "id": "h"}], destructive=False).outcome == "pending_approval"


def test_blast_radius_limits():
    pe = _policy(email__tag=4)
    many = [{"type": "identity", "id": f"u{i}"} for i in range(30)]
    d = pe.decide("email.tag", many, destructive=False)
    assert d.outcome == "pending_approval" and d.high_impact
    pe.document["default_hard_limit"] = 10
    assert pe.decide("email.tag", many, destructive=False).outcome == "blocked"


# --------------------------------------------------------------------------- action service (NFR-01, IM-T06/07)


def test_agent_request_waits_for_human_approval(session, registry, analyst):
    svc = ActionService(session, registry, PolicyEngine())
    req = svc.request("endpoint.isolate", targets=[{"type": "asset", "id": "h1"}],
                      requested_by=agent_principal("incident"), case_id="C1")
    assert req.status == "recommended"
    assert registry.get("endpoint.isolate").calls == []
    with pytest.raises(PermissionError):
        svc.approve(req.id, agent_principal("other"))
    # endpoint.isolate is four-eyes in the default policy -> needs a lead
    with pytest.raises(PermissionError):
        svc.approve(req.id, analyst)


def test_lead_approval_executes_and_audits(session, registry, lead):
    svc = ActionService(session, registry, PolicyEngine())
    req = svc.request("endpoint.isolate", targets=[{"type": "asset", "id": "h1"}],
                      requested_by=agent_principal("incident"), case_id="C1")
    done = svc.approve(req.id, lead, note="confirmed")
    assert done.status == "executed" and done.approver == "lena"
    events = [r.event_type for r in AuditLog(session).query(subject_id=req.id)]
    assert {"action.requested", "action.approved", "action.executed"} <= set(events)
    assert AuditLog(session).verify()["ok"]


def test_requester_cannot_self_approve_four_eyes(session, registry, lead):
    svc = ActionService(session, registry, PolicyEngine())
    req = svc.request("endpoint.isolate", targets=[{"type": "asset", "id": "h1"}], requested_by=lead)
    assert req.status == "recommended"
    with pytest.raises(PermissionError):
        svc.approve(req.id, lead)


def test_analyst_request_of_normal_action_is_explicit_approval(session, registry, analyst):
    svc = ActionService(session, registry, PolicyEngine())
    req = svc.request("email.tag", targets=[{"type": "email", "id": "m1"}], requested_by=analyst)
    assert req.status == "executed" and req.approver == "alice"


def test_idempotency_on_replay(session, registry):
    svc = ActionService(session, registry, PolicyEngine())
    a = svc.request("email.tag", targets=[{"type": "email", "id": "m1"}], requested_by=agent_principal("p"),
                    case_id="C9")
    b = svc.request("email.tag", targets=[{"type": "email", "id": "m1"}], requested_by=agent_principal("p"),
                    case_id="C9")
    assert a.id == b.id


def test_l4_executes_autonomously_and_rollback_uses_reverse(session, registry, lead):
    svc = ActionService(session, registry, _policy(endpoint__isolate=4))
    svc.policy.document["actions"]["endpoint.isolate"]["four_eyes"] = False
    req = svc.request("endpoint.isolate", targets=[{"type": "asset", "id": "h1"}], requested_by=agent_principal("canary"))
    assert req.status == "executed" and req.approver == "policy:L4"
    # the release is an action like any other: four-eyes in the default policy, so a second lead must approve it
    rev = svc.rollback(req.id, lead, note="false positive")
    assert rev.action_type == "endpoint.release" and rev.status == "recommended" and rev.reverse_of == req.id
    assert registry.get("endpoint.release").calls == [] and session.get(type(req), req.id).status == "executed"
    with pytest.raises(PermissionError):
        svc.approve(rev.id, lead)                                       # not the person who asked for it
    done = svc.approve(rev.id, person("lars", Role.LEAD))
    assert done.status == "executed" and session.get(type(req), req.id).status == "rolled_back"


def test_rollback_goes_through_the_policy_and_cannot_skip_four_eyes(session, registry, lead):
    """Rollback used to execute at once with no policy decision: one person could release a host whose isolation
    needed two."""
    svc = ActionService(session, registry, PolicyEngine())
    req = svc.request("endpoint.isolate", targets=[{"type": "asset", "id": "h2"}], requested_by=agent_principal("i"))
    svc.approve(req.id, person("lars", Role.LEAD))
    rev = svc.rollback(req.id, lead)
    assert rev.status == "recommended" and registry.get("endpoint.release").calls == []
    assert {"action.rollback_requested", "action.requested"} <= {
        r.event_type for r in AuditLog(session).query(limit=20)}


def test_the_tool_call_runs_after_a_durable_executing_record_and_holds_no_lock(tmp_path, registry, lead):
    """The vendor call used to run inside the open transaction, holding the audit chain's lock: every audited write
    on the platform waited for the tool, and a failed commit after a successful call left an executed containment
    with no record (and approvable again). Now the 'executing' record is committed before the call."""
    from soc_platform.core.db import Database
    from soc_platform.core.models import ActionRequest

    db = Database(f"sqlite:///{(tmp_path / 'a.db').as_posix()}")
    db.create_all()
    seen = {}

    class Probe(type(registry.get("email.tag"))):
        def execute(self, params, targets):
            with db.session() as other:                                 # another connection, as another replica
                row = other.execute(text("SELECT status FROM action_requests")).scalar()
                seen["status"] = row
                AuditLog(other).append(actor_type="system", actor_id="x", event_type="concurrent",
                                       subject_type="t", subject_id="1")   # would wait on the chain lock before
            return {"ok": True}

    registry.register(Probe("endpoint.isolate"))
    with db.session() as s:
        svc = ActionService(s, registry, PolicyEngine())
        req = svc.request("endpoint.isolate", targets=[{"type": "asset", "id": "h1"}], requested_by=agent_principal("i"))
        done = svc.approve(req.id, lead)
        assert done.status == "executed"
    assert seen["status"] == "executing"
    with db.session() as s:
        events = [r.event_type for r in AuditLog(s).query(subject_id=req.id, limit=20)]
        assert "action.executing" in events and "action.executed" in events
        assert AuditLog(s).verify()["ok"] and s.get(ActionRequest, req.id).started_at is not None


def test_an_action_left_executing_is_marked_unverified_never_rerun(session, registry, lead):
    from datetime import timedelta

    from soc_platform.core.models import ActionRequest, utcnow
    from soc_platform.intelligence.models import Insight

    svc = ActionService(session, registry, PolicyEngine())
    req = svc.request("endpoint.isolate", targets=[{"type": "asset", "id": "h1"}], requested_by=agent_principal("i"))
    req.status, req.started_at = "executing", utcnow() - timedelta(hours=1)    # the process died mid-call
    session.flush()
    assert [r.id for r in svc.reconcile_stuck(900)] == [req.id]
    assert session.get(ActionRequest, req.id).status == "unverified"
    assert registry.get("endpoint.isolate").calls == []
    assert session.query(Insight).filter_by(rule="action_outcome_unknown").count() == 1
    assert svc.reconcile_stuck(900) == [] and svc.execute_pending() == []      # idempotent, nothing re-run


def test_an_action_approved_inside_a_savepoint_runs_after_the_commit(session, registry, lead):
    """A job isolates each item in a savepoint, which cannot be committed: the action waits, then runs."""
    svc = ActionService(session, registry, _policy(email__tag=4))
    with session.begin_nested():
        req = svc.request("email.tag", targets=[{"type": "email", "id": "m7"}], requested_by=agent_principal("p"))
        assert req.status == "approved" and registry.get("email.tag").calls == []
    session.commit()
    ran = svc.execute_pending(list(session.info.get("soc_pending_actions", [])))
    assert [r.status for r in ran] == ["executed"] and len(registry.get("email.tag").calls) == 1


def test_a_deferred_autonomous_action_is_held_when_the_kill_switch_comes_on(session, registry):
    svc = ActionService(session, registry, _policy(email__tag=4))
    with session.begin_nested():
        req = svc.request("email.tag", targets=[{"type": "email", "id": "m8"}], requested_by=agent_principal("p"))
    session.commit()
    (held,) = svc.execute_pending(kill_switch=True)
    assert held.id == req.id and held.status == "pending_approval" and registry.get("email.tag").calls == []


def test_failed_precondition_blocks(session, registry, analyst):
    registry.get("email.tag").precondition = "message no longer in mailbox"
    svc = ActionService(session, registry, PolicyEngine())
    req = svc.request("email.tag", targets=[], requested_by=analyst)
    assert req.status == "blocked" and "message no longer" in req.precondition_failures[0]


def test_execution_failure_is_recorded(session, registry, analyst):
    registry.get("email.tag").fail = True
    req = ActionService(session, registry, PolicyEngine()).request("email.tag", targets=[], requested_by=analyst)
    assert req.status == "failed" and "tool said no" in req.result["error"]


# --------------------------------------------------------------------------- policy change control (NFR-12)


def test_policy_change_needs_different_approver(session, automation_admin, lead, analyst):
    store = PolicyStore(session)
    doc = store.active()
    doc["actions"]["canary.escalate"] = {"level": 4}
    with pytest.raises(PermissionError):
        store.propose(doc, analyst)
    v = store.propose(doc, automation_admin, note="promote canary")
    with pytest.raises(PermissionError):
        store.approve(v.id, automation_admin)
    store.approve(v.id, lead)
    assert store.active()["actions"]["canary.escalate"]["level"] == 4


def test_same_containment_from_two_cases_is_one_approval(session, registry):
    """The phishing case and the incident case both recommend blocking the same host: the analyst decides once."""
    from soc_platform.core.cases import CaseService

    cs = CaseService(session)
    c1, c2 = cs.create("phishing", "p", actor="agent:x"), cs.create("incident", "i", actor="agent:x")
    svc = ActionService(session, registry, PolicyEngine())
    t = [{"type": "asset", "id": "jane-lt01"}]
    a = svc.request("endpoint.isolate", targets=t, requested_by=agent_principal("ph"), case_id=c1.id)
    b = svc.request("endpoint.isolate", targets=t, requested_by=agent_principal("im"), case_id=c2.id)
    assert a.id == b.id and c2.id in a.result["linked_cases"]
    assert any(x["id"] == a.id for x in cs.view(c2.id)["actions"])        # visible from both cases
    t1 = svc.request("email.tag", targets=[{"type": "email", "id": "m1"}], requested_by=agent_principal("p"), case_id=c1.id)
    t2 = svc.request("email.tag", targets=[{"type": "email", "id": "m2"}], requested_by=agent_principal("p"), case_id=c2.id)
    assert t1.id != t2.id                                                    # different targets stay separate


def test_same_host_described_differently_is_still_one_approval(session, registry):
    from soc_platform.core.cases import CaseService

    cs = CaseService(session)
    c1, c2 = cs.create("phishing", "p", actor="agent:x"), cs.create("incident", "i", actor="agent:x")
    svc = ActionService(session, registry, PolicyEngine())
    a = svc.request("endpoint.isolate", targets=[{"type": "asset", "id": "jane-lt01"}], requested_by=agent_principal("ph"), case_id=c1.id)
    b = svc.request("endpoint.isolate", targets=[{"type": "asset", "id": "jane-lt01.acme-demo.com", "crowdstrike_aid": "cs-1"}],
                    requested_by=agent_principal("im"), case_id=c2.id)
    assert a.id == b.id
    c = svc.request("endpoint.isolate", targets=[{"type": "asset", "id": "bob-lt02.acme-demo.com"}], requested_by=agent_principal("im"), case_id=c2.id)
    assert c.id != a.id


def test_same_short_name_with_different_device_ids_is_not_merged(session, registry):
    from soc_platform.core.cases import CaseService

    cs = CaseService(session)
    c1, c2 = cs.create("incident", "a", actor="agent:x"), cs.create("incident", "b", actor="agent:x")
    svc = ActionService(session, registry, PolicyEngine())
    a = svc.request("endpoint.isolate", targets=[{"type": "asset", "id": "web01.eu.corp", "crowdstrike_aid": "aid-1"}],
                    requested_by=agent_principal("im"), case_id=c1.id)
    b = svc.request("endpoint.isolate", targets=[{"type": "asset", "id": "web01.us.corp", "crowdstrike_aid": "aid-2"}],
                    requested_by=agent_principal("im"), case_id=c2.id)
    assert a.id != b.id


def test_notes_stay_newest_first_even_within_one_clock_tick(session, analyst, monkeypatch):
    """Two notes written in the same instant (Windows' clock ticks every ~15 ms) once came back in random order."""
    from soc_platform.core.cases import CaseService

    monkeypatch.setenv("SOC_CLOCK_FREEZE", "2026-09-28T10:00:00+00:00")
    svc = CaseService(session)
    case = svc.create("incident", "Frozen-clock case", severity="low", attributes={}, actor="test")
    for i in range(5):
        svc.add_note(case.id, f"note {i}", by=analyst)
    assert [n["text"] for n in svc.view(case.id)["notes"]] == [f"note {i}" for i in reversed(range(5))]


def test_irreversible_actions_are_never_autonomous_whatever_the_policy_says():
    # The policy has always capped destructive action types at L3 (a person approves), but no action was marked
    # destructive, so a policy promoting everything to L4 would have let password resets, secret rotation, mail purges
    # and "confirm compromised" run unattended.
    import copy

    from soc_platform.connectors.registry import ConnectorRegistry

    specs = dict(ConnectorRegistry.all_fake().action_registry()._specs)
    assert {t for t, s in specs.items() if s.destructive} == {
        "email.campaign_purge", "identity.reset_password", "identity.confirm_compromised", "pam.rotate_secret"}
    doc = copy.deepcopy(DEFAULT_POLICY)
    doc["default_level"] = 4
    doc["actions"] = {t: {"level": 4} for t in specs}
    engine = PolicyEngine(doc)
    for t, s in specs.items():
        decision = engine.decide(t, [{"type": "asset", "id": "h1"}], destructive=s.destructive)
        assert (decision.outcome == "execute") is (not s.destructive), (t, decision.outcome)
