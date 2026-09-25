from __future__ import annotations

import pytest
from sqlalchemy import text

from soc_platform.core.actions import ActionService
from soc_platform.core.audit import AuditLog
from soc_platform.core.auth import agent_principal
from soc_platform.core.models import AuditRecord
from soc_platform.core.policy import DEFAULT_POLICY, Level, PolicyEngine, PolicyStore


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
    # Bypass the ORM guard with raw SQL, as an attacker with DB access would.
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
    rev = svc.rollback(req.id, lead, note="false positive")
    assert rev.action_type == "endpoint.release" and rev.status == "executed"
    assert session.get(type(req), req.id).status == "rolled_back"


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
