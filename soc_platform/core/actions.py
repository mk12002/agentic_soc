"""Uniform action layer (section 5.3, IM-T06, IM-T07, NFR-01, NFR-03).

An ``ActionSpec`` wraps one native-tool operation (Graph purge, CrowdStrike
containment, Umbrella block...) with pre-conditions, a reverse action and an
execution record. ``ActionService`` is the only path to execution: it applies
the autonomy policy, enforces approvals and separation of duties, provides
idempotency for replays/concurrent processing, and audits every transition.
"""

from __future__ import annotations

import hashlib
import json
from abc import ABC, abstractmethod
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from soc_platform.core.audit import AuditLog
from soc_platform.core.auth import Perm, Principal
from soc_platform.core.models import ActionRequest, utcnow
from soc_platform.core.policy import PolicyDecision, PolicyEngine

APPROVABLE = ("recommended", "pending_approval")
TERMINAL_RETRYABLE = ("rejected", "failed", "rolled_back", "blocked", "superseded")


class ActionSpec(ABC):
    action_type: str = ""
    description: str = ""
    tool: str = ""
    destructive: bool = False
    reverse_type: str | None = None

    def preconditions(self, params: dict[str, Any], targets: list[dict[str, Any]]) -> list[str]:
        """Return a list of failed pre-condition descriptions (empty means OK)."""
        return []

    @abstractmethod
    def execute(self, params: dict[str, Any], targets: list[dict[str, Any]]) -> dict[str, Any]:
        """Perform the action. Raise on failure. Return an execution record."""

    def reverse(self, params: dict[str, Any], targets: list[dict[str, Any]],
                result: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]] | None:
        """Params/targets for the reverse action, or None if not reversible."""
        return None

    @property
    def reversible(self) -> bool:
        return self.reverse_type is not None


class ActionRegistry:
    def __init__(self) -> None:
        self._specs: dict[str, ActionSpec] = {}

    def register(self, spec: ActionSpec) -> ActionSpec:
        if not spec.action_type:
            raise ValueError("ActionSpec.action_type required")
        self._specs[spec.action_type] = spec
        return spec

    def get(self, action_type: str) -> ActionSpec:
        try:
            return self._specs[action_type]
        except KeyError as exc:
            raise KeyError(f"unknown action type {action_type!r}") from exc

    def catalog(self) -> list[dict[str, Any]]:
        return [
            {"action_type": s.action_type, "description": s.description, "tool": s.tool,
             "destructive": s.destructive, "reversible": s.reversible, "reverse_type": s.reverse_type}
            for s in sorted(self._specs.values(), key=lambda x: x.action_type)
        ]


def idempotency_key(action_type: str, params: dict[str, Any], targets: list[dict[str, Any]],
                    case_id: str | None) -> str:
    body = json.dumps([action_type, params, targets, case_id], sort_keys=True, default=str)
    return f"{action_type}:{hashlib.sha256(body.encode()).hexdigest()[:40]}"


class ActionService:
    def __init__(self, session: Session, registry: ActionRegistry, policy: PolicyEngine) -> None:
        self.s = session
        self.registry = registry
        self.policy = policy
        self.audit = AuditLog(session)

    # ------------------------------------------------------------------ request

    def request(
        self,
        action_type: str,
        *,
        params: dict[str, Any] | None = None,
        targets: list[dict[str, Any]] | None = None,
        requested_by: Principal,
        case_id: str | None = None,
        domain: str = "platform",
        rationale: str = "",
        evidence_ids: list[str] | None = None,
        key: str | None = None,
    ) -> ActionRequest:
        spec = self.registry.get(action_type)
        params = params or {}
        targets = targets or []
        if not requested_by.is_agent and not requested_by.can(Perm.REQUEST_ACTION):
            raise PermissionError("request_action permission required")
        key = key or idempotency_key(action_type, params, targets, case_id)

        existing = self._by_key(key)
        if existing is not None:
            if existing.status not in TERMINAL_RETRYABLE:
                return existing  # IM-T07: replay / concurrent duplicate -> same request
            existing.idempotency_key = f"{existing.idempotency_key}#superseded:{existing.id}"
            self.s.flush()

        shared = self._open_for_same_targets(action_type, targets, case_id)
        if shared is not None:
            # Same containment already awaiting a decision from another case: link, don't duplicate the approval.
            res = dict(shared.result or {})
            res["linked_cases"] = sorted({*res.get("linked_cases", []), case_id})
            shared.result = res
            self.s.flush()
            self.audit.append(actor_type=requested_by.actor_type, actor_id=requested_by.id, event_type="action.linked",
                              subject_type="action", subject_id=shared.id,
                              payload={"case_id": case_id, "rationale": rationale})
            return shared

        failures = spec.preconditions(params, targets)
        decision = self.policy.decide(action_type, targets, destructive=spec.destructive,
                                      precondition_failures=failures)
        req = ActionRequest(
            action_type=action_type, params=params, targets=targets, case_id=case_id, domain=domain,
            rationale=rationale, evidence_ids=list(evidence_ids or []), requested_by=requested_by.id,
            requested_by_type=requested_by.actor_type, idempotency_key=key,
            status=decision.outcome if decision.outcome != "execute" else "approved",
            autonomy_level=int(decision.effective_level), policy_reasons=decision.reasons,
            precondition_failures=failures,
        )
        req.result = {"high_impact": decision.high_impact, "four_eyes": decision.four_eyes}
        try:
            with self.s.begin_nested():
                self.s.add(req)
                self.s.flush()
        except IntegrityError:
            dup = self._by_key(key)
            if dup is not None:
                return dup
            raise
        self.audit.append(actor_type=requested_by.actor_type, actor_id=requested_by.id,
                          event_type="action.requested", subject_type="action", subject_id=req.id,
                          payload={"action_type": action_type, "targets": targets, "case_id": case_id,
                                   "outcome": decision.outcome, "level": int(decision.effective_level),
                                   "reasons": decision.reasons, "rationale": rationale,
                                   "evidence_ids": list(evidence_ids or [])})

        if decision.outcome == "execute":
            req.approver = "policy:L4"
            return self._execute(req, spec, actor=requested_by)

        # A human who requests an action they are allowed to approve is giving explicit approval,
        # unless four-eyes applies (then a different person must approve).
        if (not requested_by.is_agent and req.status in APPROVABLE and not decision.four_eyes
                and self._may_approve(requested_by, decision.high_impact)):
            return self.approve(req.id, requested_by, note="requested and approved by analyst", _self_ok=True)
        return req

    # ------------------------------------------------------------------ decisions

    def approve(self, request_id: str, approver: Principal, note: str = "", *, _self_ok: bool = False) -> ActionRequest:
        req = self._get(request_id)
        if req.status not in APPROVABLE:
            raise ValueError(f"action {request_id} is {req.status}, not awaiting approval")
        high_impact = bool(req.result.get("high_impact"))
        if approver.is_agent:
            raise PermissionError("agents cannot approve actions")
        if not self._may_approve(approver, high_impact):
            raise PermissionError("approve_high_impact permission required" if high_impact
                                  else "approve_action permission required")
        if req.requested_by == approver.id and not _self_ok:
            raise PermissionError("separation of duties: requester cannot approve their own action")
        spec = self.registry.get(req.action_type)
        # Pre-conditions are re-checked at execution time; state may have changed since the request.
        failures = spec.preconditions(req.params, req.targets)
        if failures:
            req.status = "blocked"
            req.precondition_failures = failures
            self.audit.append(actor_type="human", actor_id=approver.id, event_type="action.blocked",
                              subject_type="action", subject_id=req.id, payload={"failures": failures})
            return req
        claimed = self.s.execute(
            update(ActionRequest).where(ActionRequest.id == req.id, ActionRequest.status.in_(APPROVABLE))
            .values(status="approved", approver=approver.id, decision_note=note, decided_at=utcnow())
        ).rowcount
        if claimed != 1:
            raise ValueError("action was decided concurrently")
        self.s.refresh(req)
        self.audit.append(actor_type="human", actor_id=approver.id, event_type="action.approved",
                          subject_type="action", subject_id=req.id, payload={"note": note})
        return self._execute(req, spec, actor=approver)

    def reject(self, request_id: str, approver: Principal, note: str = "") -> ActionRequest:
        req = self._get(request_id)
        if req.status not in APPROVABLE:
            raise ValueError(f"action {request_id} is {req.status}, not awaiting approval")
        if approver.is_agent or not approver.can(Perm.APPROVE_ACTION):
            raise PermissionError("approve_action permission required")
        req.status, req.approver, req.decision_note, req.decided_at = "rejected", approver.id, note, utcnow()
        self.audit.append(actor_type="human", actor_id=approver.id, event_type="action.rejected",
                          subject_type="action", subject_id=req.id, payload={"note": note})
        return req

    def rollback(self, request_id: str, by: Principal, note: str = "") -> ActionRequest:
        req = self._get(request_id)
        if req.status != "executed":
            raise ValueError("only executed actions can be rolled back")
        if by.is_agent or not by.can(Perm.ROLLBACK_ACTION):
            raise PermissionError("rollback_action permission required")
        spec = self.registry.get(req.action_type)
        rev = spec.reverse(req.params, req.targets, req.result) if spec.reversible else None
        if rev is None or spec.reverse_type is None:
            raise ValueError(f"{req.action_type} has no reverse action on this platform")
        params, targets = rev
        rev_spec = self.registry.get(spec.reverse_type)
        rev_req = ActionRequest(
            action_type=spec.reverse_type, params=params, targets=targets, case_id=req.case_id,
            domain=req.domain, rationale=f"rollback of {req.id}: {note}", requested_by=by.id,
            requested_by_type="human", idempotency_key=f"rollback:{req.id}", status="approved",
            autonomy_level=3, approver=by.id, reverse_of=req.id, decided_at=utcnow(),
        )
        self.s.add(rev_req)
        self.s.flush()
        self.audit.append(actor_type="human", actor_id=by.id, event_type="action.rollback_requested",
                          subject_type="action", subject_id=req.id, payload={"reverse_action": rev_req.id, "note": note})
        self._execute(rev_req, rev_spec, actor=by)
        if rev_req.status == "executed":
            req.status = "rolled_back"
        return rev_req

    # ------------------------------------------------------------------ internals

    def _may_approve(self, p: Principal, high_impact: bool) -> bool:
        return p.can(Perm.APPROVE_HIGH_IMPACT) if high_impact else p.can(Perm.APPROVE_ACTION)

    def _execute(self, req: ActionRequest, spec: ActionSpec, *, actor: Principal) -> ActionRequest:
        claimed = self.s.execute(
            update(ActionRequest).where(ActionRequest.id == req.id, ActionRequest.status == "approved")
            .values(status="executing")
        ).rowcount
        if claimed != 1:
            self.s.refresh(req)
            return req
        try:
            result = spec.execute(req.params, req.targets) or {}
            status = "executed"
        except Exception as exc:  # recorded, never swallowed silently
            result = {"error": f"{type(exc).__name__}: {exc}"}
            status = "failed"
        self.s.execute(
            update(ActionRequest).where(ActionRequest.id == req.id)
            .values(status=status, result={**(req.result or {}), **result}, executed_at=utcnow())
        )
        self.s.refresh(req)
        self.audit.append(actor_type=actor.actor_type, actor_id=actor.id, event_type=f"action.{status}",
                          subject_type="action", subject_id=req.id,
                          payload={"action_type": req.action_type, "tool": spec.tool, "result": result,
                                   "approver": req.approver})
        return req

    def _get(self, request_id: str) -> ActionRequest:
        req = self.s.get(ActionRequest, request_id)
        if req is None:
            raise KeyError(f"unknown action request {request_id}")
        return req

    PER_CASE_ACTIONS = {"ticket.create", "ticket.update", "notify.email", "email.reporter_feedback"}

    def _open_for_same_targets(self, action_type: str, targets: list[dict[str, Any]],
                               case_id: str | None) -> ActionRequest | None:
        if action_type in self.PER_CASE_ACTIONS or not case_id or not targets:
            return None
        ids = sorted(str(t.get("id") or t.get("value") or "") for t in targets)
        if not all(ids):
            return None
        for r in self.s.execute(select(ActionRequest).where(
                ActionRequest.action_type == action_type, ActionRequest.case_id != case_id,
                ActionRequest.status.in_(("recommended", "pending_approval")))).scalars():
            if sorted(str(t.get("id") or t.get("value") or "") for t in (r.targets or [])) == ids:
                return r
        return None

    def _by_key(self, key: str) -> ActionRequest | None:
        return self.s.execute(select(ActionRequest).where(ActionRequest.idempotency_key == key)).scalars().first()


__all__ = ["ActionSpec", "ActionRegistry", "ActionService", "PolicyDecision", "idempotency_key"]
