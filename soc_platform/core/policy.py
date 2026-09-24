"""Graduated autonomy policy (section 5.2, NFR-01, NFR-12, R04).

Every action type has an explicit autonomy level recorded in a versioned policy:

  L0 observe   - analysed and recorded only (shadow mode)
  L1 enrich    - context assembled, no assessment/recommendation surfaced
  L2 recommend - recommendation shown; executes only when an analyst approves
  L3 approve   - staged for execution; executes on explicit approval
  L4 autonomous- executes within the policy envelope; analyst notified, reversible

Hard gates cap the effective level regardless of configuration:
  * kill switch            -> nothing runs autonomously
  * destructive actions    -> never L4
  * VIP / critical targets -> never L4, high-impact approval required
  * blast radius           -> above ``max_targets`` needs high-impact approval;
                              above ``hard_limit`` the request is blocked
Policy changes follow propose -> approve (different person) -> activate.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from soc_platform.core.audit import AuditLog
from soc_platform.core.auth import Perm, Principal
from soc_platform.core.models import PolicyVersion, utcnow


class Level(IntEnum):
    L0_OBSERVE = 0
    L1_ENRICH = 1
    L2_RECOMMEND = 2
    L3_APPROVE = 3
    L4_AUTONOMOUS = 4


# Go-live posture recommended in section 5.2: L1-L2 everywhere; promote per action on evidence.
DEFAULT_POLICY: dict[str, Any] = {
    "default_level": 2,
    "default_max_targets": 25,
    "default_hard_limit": 5000,
    "actions": {
        # Phishing
        "email.tag": {"level": 2},
        "email.banner": {"level": 2},
        "email.move_to_junk": {"level": 2},
        "email.soft_delete": {"level": 2, "max_targets": 50},
        "email.campaign_purge": {"level": 2, "max_targets": 200},
        "email.block_sender": {"level": 2},
        "email.reporter_feedback": {"level": 2},
        "email.auto_close_report": {"level": 2},
        # Identity
        "identity.revoke_sessions": {"level": 2, "max_targets": 10},
        "identity.disable_account": {"level": 2, "max_targets": 3, "four_eyes": True},
        "identity.reset_password": {"level": 2, "max_targets": 10},
        # Endpoint
        "endpoint.isolate": {"level": 2, "max_targets": 5, "four_eyes": True},
        "endpoint.release": {"level": 2},
        "endpoint.scan": {"level": 2},
        "endpoint.collect_forensics": {"level": 2},
        # Network / DNS
        "dns.block_domain": {"level": 2},
        "dns.unblock_domain": {"level": 2},
        "indicator.block": {"level": 2},
        # Privileged access
        "pam.rotate_secret": {"level": 2, "max_targets": 5},
        # Vulnerability management
        "notify.email": {"level": 2},
        "ticket.create": {"level": 2},
        "ticket.update": {"level": 2},
        "vm.create_ticket": {"level": 2},
        "vm.risk_register_update": {"level": 2},
        # Deception
        "canary.escalate": {"level": 2},
    },
    "vip": {"identities": [], "assets": [], "asset_tags": ["critical", "crown_jewel"]},
}


@dataclass
class ActionPolicyView:
    level: Level
    max_targets: int
    hard_limit: int
    four_eyes: bool


@dataclass
class PolicyDecision:
    configured_level: Level
    effective_level: Level
    outcome: str  # observed | recommended | pending_approval | execute | blocked
    reasons: list[str] = field(default_factory=list)
    high_impact: bool = False
    four_eyes: bool = False


def is_vip_target(target: dict[str, Any], vip: dict[str, Any]) -> bool:
    if target.get("vip") or target.get("criticality") in {"critical", "vip"}:
        return True
    ident = str(target.get("id") or target.get("upn") or "").lower()
    if target.get("type") == "identity" and ident in {i.lower() for i in vip.get("identities", [])}:
        return True
    if target.get("type") == "asset":
        if ident in {a.lower() for a in vip.get("assets", [])}:
            return True
        tags = {str(t).lower() for t in target.get("tags", [])}
        if tags & {t.lower() for t in vip.get("asset_tags", [])}:
            return True
    return False


class PolicyEngine:
    def __init__(self, document: dict[str, Any] | None = None, kill_switch: bool = False) -> None:
        self.document = copy.deepcopy(document or DEFAULT_POLICY)
        self.kill_switch = kill_switch

    def view(self, action_type: str) -> ActionPolicyView:
        doc = self.document
        cfg = doc.get("actions", {}).get(action_type, {})
        return ActionPolicyView(
            level=Level(int(cfg.get("level", doc.get("default_level", 2)))),
            max_targets=int(cfg.get("max_targets", doc.get("default_max_targets", 25))),
            hard_limit=int(cfg.get("hard_limit", doc.get("default_hard_limit", 5000))),
            four_eyes=bool(cfg.get("four_eyes", False)),
        )

    def decide(self, action_type: str, targets: list[dict[str, Any]], *, destructive: bool,
               precondition_failures: list[str] | None = None) -> PolicyDecision:
        v = self.view(action_type)
        level = v.level
        reasons: list[str] = [f"configured level L{int(v.level)} for {action_type}"]
        high_impact = False

        if precondition_failures:
            return PolicyDecision(v.level, level, "blocked",
                                  reasons + [f"precondition failed: {f}" for f in precondition_failures])
        if len(targets) > v.hard_limit:
            return PolicyDecision(v.level, level, "blocked",
                                  reasons + [f"blast radius {len(targets)} exceeds hard limit {v.hard_limit}"])

        def cap(to: Level, why: str) -> None:
            nonlocal level
            if level > to:
                level = to
            reasons.append(why)  # always visible to the analyst, even when no cap was needed

        if self.kill_switch:
            cap(Level.L3_APPROVE, "kill switch engaged: autonomous execution disabled")
        if destructive:
            cap(Level.L3_APPROVE, "destructive action type: never autonomous")
        vip_hits = [t for t in targets if is_vip_target(t, self.document.get("vip", {}))]
        if vip_hits:
            high_impact = True
            cap(Level.L3_APPROVE, f"{len(vip_hits)} VIP/critical target(s): approval required")
        if len(targets) > v.max_targets:
            high_impact = True
            cap(Level.L3_APPROVE, f"blast radius {len(targets)} exceeds {v.max_targets}: lead approval required")
        if v.four_eyes:
            high_impact = True
            reasons.append("four-eyes: a second person must approve")

        outcome = {
            Level.L0_OBSERVE: "observed",
            Level.L1_ENRICH: "observed",
            Level.L2_RECOMMEND: "recommended",
            Level.L3_APPROVE: "pending_approval",
            Level.L4_AUTONOMOUS: "execute",
        }[level]
        return PolicyDecision(v.level, level, outcome, reasons, high_impact=high_impact, four_eyes=v.four_eyes)


class PolicyStore:
    """Versioned policy with propose/approve separation of duties (NFR-09, NFR-12)."""

    def __init__(self, session: Session) -> None:
        self.s = session
        self.audit = AuditLog(session)

    def active(self) -> dict[str, Any]:
        row = self.s.execute(
            select(PolicyVersion).where(PolicyVersion.status == "active").order_by(PolicyVersion.id.desc())
        ).scalars().first()
        return copy.deepcopy(row.document) if row else copy.deepcopy(DEFAULT_POLICY)

    def active_version(self) -> int | None:
        row = self.s.execute(
            select(PolicyVersion.id).where(PolicyVersion.status == "active").order_by(PolicyVersion.id.desc())
        ).scalars().first()
        return row

    def propose(self, document: dict[str, Any], by: Principal, note: str = "") -> PolicyVersion:
        if not by.can(Perm.PROPOSE_POLICY):
            raise PermissionError("propose_policy permission required")
        _validate_policy(document)
        row = PolicyVersion(document=document, proposed_by=by.id, note=note, status="proposed")
        self.s.add(row)
        self.s.flush()
        self.audit.append(actor_type=by.actor_type, actor_id=by.id, event_type="policy.proposed",
                          subject_type="policy", subject_id=str(row.id),
                          payload={"note": note, "diff": _diff(self.active(), document)})
        return row

    def approve(self, version_id: int, by: Principal) -> PolicyVersion:
        if not by.can(Perm.APPROVE_POLICY):
            raise PermissionError("approve_policy permission required")
        row = self.s.get(PolicyVersion, version_id)
        if row is None or row.status != "proposed":
            raise ValueError("policy version is not awaiting approval")
        if row.proposed_by == by.id:
            raise PermissionError("separation of duties: proposer cannot approve their own policy change")
        for old in self.s.execute(select(PolicyVersion).where(PolicyVersion.status == "active")).scalars():
            old.status = "superseded"
        row.status = "active"
        row.approved_by = by.id
        row.activated_at = utcnow()
        self.audit.append(actor_type=by.actor_type, actor_id=by.id, event_type="policy.activated",
                          subject_type="policy", subject_id=str(row.id), payload={"proposed_by": row.proposed_by})
        return row


def _validate_policy(doc: dict[str, Any]) -> None:
    for name, cfg in (doc.get("actions") or {}).items():
        lvl = int(cfg.get("level", doc.get("default_level", 2)))
        if lvl not in range(0, 5):
            raise ValueError(f"{name}: level must be 0-4")


def _diff(old: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    changes: dict[str, Any] = {}
    oa, na = old.get("actions", {}), new.get("actions", {})
    for k in sorted(set(oa) | set(na)):
        if oa.get(k) != na.get(k):
            changes[k] = {"from": oa.get(k), "to": na.get(k)}
    for k in ("default_level", "vip", "default_max_targets", "default_hard_limit"):
        if old.get(k) != new.get(k):
            changes[k] = {"from": old.get(k), "to": new.get(k)}
    return changes
