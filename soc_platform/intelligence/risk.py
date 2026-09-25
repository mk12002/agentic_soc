"""Entity risk engine: one explainable, time-decayed risk score per user and per host, fused from every
data stream in the shared context store (U07 identity-centric risk view, U06 exposure-informed triage).

Every point of score is traceable to a specific event / finding / case with its source tool, so the
score can be audited and argued with. No model is involved; the LLM layer narrates on top of this.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from soc_platform.core.context_store import ContextStore
from soc_platform.core.models import Case, CaseEntity, Entity, utcnow

SEV_W = {"critical": 40.0, "high": 25.0, "medium": 10.0, "low": 3.0, "informational": 0.0}
HALF_LIFE_DAYS = 7.0
BANDS = [(80, "critical"), (60, "high"), (30, "medium"), (0, "low")]


@dataclass
class Factor:
    signal: str
    dimension: str
    weight: float
    decayed: float
    source: str
    ref: str
    when: str | None
    detail: str


@dataclass
class RiskProfile:
    entity_id: str
    kind: str
    name: str
    score: float
    band: str
    factors: list[Factor] = field(default_factory=list)

    @property
    def dimensions(self) -> list[str]:
        return sorted({f.dimension for f in self.factors if f.decayed > 0})

    def signals(self) -> set[str]:
        return {f.signal for f in self.factors}

    def as_dict(self) -> dict[str, Any]:
        return {"entity_id": self.entity_id, "kind": self.kind, "name": self.name, "score": self.score,
                "band": self.band, "dimensions": self.dimensions,
                "factors": [f.__dict__ for f in sorted(self.factors, key=lambda x: -x.decayed)]}


def _aware(dt: datetime | None) -> datetime:
    dt = dt or utcnow()
    return dt if dt.tzinfo else dt.replace(tzinfo=utcnow().tzinfo)


class RiskEngine:
    def __init__(self, session: Session, *, window_days: int = 30, as_of: datetime | None = None) -> None:
        self.s = session
        self.store = ContextStore(session)
        self.window = timedelta(days=window_days)
        self.as_of = as_of

    def _now(self) -> datetime:
        if self.as_of:
            return _aware(self.as_of)
        # Reference "now" = the latest observation in the store, so replayed/historic data decays sensibly.
        latest = self.s.execute(select(Entity.last_seen).order_by(Entity.last_seen.desc()).limit(1)).scalar()
        return _aware(latest)

    def _decay(self, when: datetime | None, now: datetime) -> float:
        age = max(0.0, (now - _aware(when)).total_seconds() / 86400) if when else 0.0
        return 0.5 ** (age / HALF_LIFE_DAYS)

    def profile(self, entity_id: str) -> RiskProfile | None:
        ent = self.s.get(Entity, entity_id)
        if ent is None or ent.kind not in {"asset", "identity"} or (ent.attributes or {}).get("deception"):
            return None  # decoys (Canary devices) are sensors, not assets at risk
        now = self._now()
        since = now - self.window
        factors: list[Factor] = []

        def add(signal: str, dim: str, w: float, source: str, ref: str, when: datetime | None, detail: str) -> None:
            factors.append(Factor(signal, dim, w, round(w * self._decay(when, now), 2), source or "platform", ref,
                                  _aware(when).isoformat() if when else None, detail))

        for ev in self.store.events_for(entity_id, since=since):
            a = ev.attributes or {}
            tool, sev = a.get("tool"), (a.get("severity") or "informational").lower()
            if ev.kind == "deception":
                add("deception_hit", "deception", 50, tool, ev.id, ev.first_seen, ev.display_name)
            elif ev.kind == "alert":
                dim = a.get("dimension") or "endpoint"
                sig = "identity_risk" if dim == "identity" else "endpoint_alert" if dim == "endpoint" else f"{dim}_alert"
                add(sig, dim, SEV_W.get(sev, 5), tool, ev.id, ev.first_seen, ev.display_name)
            elif ev.kind == "signin" and (a.get("risk_level") or "none") in {"high", "medium"}:
                add("risky_signin", "identity", 30 if a.get("risk_level") == "high" else 15, tool, ev.id,
                    ev.first_seen, f"{ev.display_name} from {a.get('ip')} ({a.get('country')})")
            elif ev.kind == "secret_access" and sev == "medium":
                add("privileged_credential_access", "privileged_access", 15, tool, ev.id, ev.first_seen,
                    ev.display_name)
            elif ev.kind == "elevation" and str(a.get("outcome", "")).lower() in {"denied", "blocked"}:
                add("elevation_denied", "privileged_access", 8, tool, ev.id, ev.first_seen, ev.display_name)
            elif ev.kind == "dns" and sev == "high":
                add("malicious_destination_reached", "dns", 12, tool, ev.id, ev.first_seen, ev.display_name)
            elif ev.kind == "cloud_issue":
                add("cloud_misconfiguration", "cloud", SEV_W.get(sev, 5) / 2, tool, ev.id, ev.first_seen,
                    ev.display_name)

        # Cases this entity is part of (phishing interaction, incidents)
        # An entity can be linked to one case in several roles (recipient and clicker): count each case once.
        roles: dict[str, set[str]] = {}
        for ln in self.s.execute(select(CaseEntity).where(CaseEntity.entity_id == entity_id)).scalars():
            roles.setdefault(ln.case_id, set()).add(ln.role)
        compromised_via: list[Case] = []
        for case_id, rs in roles.items():
            case = self.s.get(Case, case_id)
            if case is None or case.status == "closed" and case.verdict in {"false_positive", "benign", "safe"}:
                continue
            if case.domain == "phishing":
                ui = (case.assessment or {}).get("user_impact") or {}
                upn = self.store.keys_of(entity_id).get("upn", "")
                if upn and upn in (ui.get("clicked") or []):
                    add("phishing_click", "email", 20, "phishing", case.id, case.created_at,
                        f"clicked a {case.verdict} email: {case.title}")
                if upn and upn in (ui.get("identity_compromise") or []):
                    compromised_via.append(case)
                elif "recipient" in rs and case.verdict == "malicious":
                    add("phishing_recipient", "email", 4, "phishing", case.id, case.created_at,
                        f"received {case.verdict} email: {case.title}")
            elif case.domain == "incident" and case.status != "closed" and rs - {"alert"}:
                add("open_incident", "incident", SEV_W.get(case.severity, 5) / 2, "incident", case.id,
                    case.created_at, case.title)
        if compromised_via:
            # one compromise, however many phishing cases point at it
            latest = max(compromised_via, key=lambda c: c.created_at)
            add("phishing_identity_compromise", "identity", 30, "phishing", latest.id, latest.created_at,
                "identity compromise indicators after phishing click"
                + (f" (seen from {len(compromised_via)} phishing cases)" if len(compromised_via) > 1 else ""))

        if ent.kind == "asset":
            from soc_platform.domains.vulnerability.models import ConsolidatedFinding, VulnIntel

            for f in self.s.execute(select(ConsolidatedFinding).where(
                    ConsolidatedFinding.asset_id == entity_id,
                    ConsolidatedFinding.status.in_(("open", "reopened")))).scalars():
                vi = self.s.get(VulnIntel, f.cve)
                if vi is not None and vi.kev:
                    add("kev_exposure", "exposure", 15, ",".join(sorted(f.sources)), f.id, f.first_seen,
                        f"{f.cve} (KEV) open")
                elif f.priority_band in {"P1", "P2"}:
                    add("priority_vulnerability", "exposure", 8 if f.priority_band == "P1" else 4,
                        ",".join(sorted(f.sources)), f.id, f.first_seen, f"{f.cve} {f.priority_band}")
                if f.internet_exposed:
                    add("internet_exposed_vulnerable", "exposure", 5, "wiz", f.id, f.first_seen,
                        f"{f.cve} on internet-exposed asset")
            from soc_platform.core.asset_types import needs_endpoint_agent

            has_edr = {"crowdstrike", "defender_endpoint"} & set((ent.attributes or {}).get("by_tool", {}))
            if not has_edr and factors and needs_endpoint_agent(self.s, ent):
                add("no_edr_coverage", "coverage", 5, "platform", entity_id, None, "no EDR telemetry for this host")
        if ent.kind == "identity":
            priv = [r for r, o in self.store.neighbors(entity_id) if o.kind == "secret_access"]
            if priv and any(f.signal in {"identity_risk", "risky_signin", "phishing_identity_compromise"} for f in factors):
                add("privileged_user_at_risk", "privileged_access", 10, "platform", entity_id, None,
                    "account with privileged credential access shows compromise indicators")

        raw = sum(f.decayed for f in factors)
        score = int(round(100 * (1 - math.exp(-raw / 60))))     # whole points: the same figure on every screen and answer
        band = next(b for t, b in BANDS if score >= t)
        return RiskProfile(entity_id, ent.kind, ent.display_name, score, band, factors)

    def candidates(self) -> set[str]:
        """Entities with at least one risk source (a relation to an event, a case link or an open finding). Every
        other entity scores 0 and can raise no finding, so ranking and correlation profile only these."""
        from soc_platform.core.models import CaseEntity, Relation
        from soc_platform.domains.vulnerability.models import ConsolidatedFinding

        return (set(self.s.execute(select(Relation.src_id)).scalars()) | set(self.s.execute(select(Relation.dst_id)).scalars())
                | set(self.s.execute(select(CaseEntity.entity_id)).scalars())
                | set(self.s.execute(select(ConsolidatedFinding.asset_id).where(
                    ConsolidatedFinding.status.in_(("open", "reopened")))).scalars()))

    def top(self, kind: str | None = None, limit: int = 10) -> list[RiskProfile]:
        """Highest-risk users / hosts (profiles only entities with a risk source: fast on large tenants)."""
        candidates = self.candidates()
        q = select(Entity.id).where(Entity.kind.in_([kind] if kind else ["asset", "identity"]))
        out = [p for eid in self.s.execute(q).scalars() if eid in candidates and (p := self.profile(eid)) and p.score > 0]
        return sorted(out, key=lambda p: -p.score)[:limit]
