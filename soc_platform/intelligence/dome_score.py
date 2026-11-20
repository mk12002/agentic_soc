"""Dome Score: one security posture figure (0-100) built from eight pillars, each computed from the platform's records.

Every pillar is a published, recomputable formula ("X of Y" or a stated penalty); the overall score is the
weighted average of the pillar scores that have data:

    Dome Score = round( sum(weight x pillar score) / sum(weight) )   over pillars with data and a weight above 0

The weights are the organisation's choice (what matters more to this CISO), set by a lead, versioned and audited.
Changing a weight changes only how the pillars are combined - never a pillar's own figure. The model plays no part.
"""

from __future__ import annotations

import copy
from collections import Counter
from datetime import timedelta
from typing import Any

from sqlalchemy import JSON, Integer, String, select
from sqlalchemy.orm import Mapped, Session, mapped_column

from soc_platform.core.db import Base, BoundedText, UTCDateTime
from soc_platform.core.models import Case, Entity, utcnow

# key: (name, CyberDome module, what is counted, how, where to drill down)
PILLARS: dict[str, tuple[str, str, str, str, str]] = {
    "identity": ("Identity", "Dome Graph", "People not at high or critical risk",
                 "people whose risk is below high / people known", "#/intelligence"),
    "endpoint": ("Endpoint", "Dome Graph", "Hosts not at high or critical risk",
                 "hosts whose risk is below high / hosts known", "#/intelligence"),
    "vulnerability": ("Vulnerability exposure", "Dome Graph", "Hosts with no open P1 or P2 finding",
                      "hosts without an open P1 / P2 finding / hosts known", "#/vulnerabilities"),
    "cloud": ("Cloud posture", "Dome Graph", "Cloud resources with no open high or critical misconfiguration",
              ("resources without an open high / critical misconfiguration / resources with any misconfiguration "
               "on record"), "#/cloud"),
    "email": ("Email", "Dome Agents", "Malicious or suspicious reported e-mails that nobody clicked",
              "reports nobody clicked / malicious or suspicious reports, 90 days up to the newest report",
              "#/phishing"),
    "response": ("Response", "Dome Agents", "Open high and critical cases",
                 "100 minus 15 for each open critical case and 8 for each open high case (not below 0)", "#/cases"),
    "detection": ("Detection coverage", "Dome Connect", "ATT&CK techniques the enabled tools can see",
                  "weighted ATT&CK coverage: full counts 1, partial 0.5", "#/coverage"),
    "tool_health": ("Tool health", "Dome Connect", "Enabled tools that are configured, syncing and fresh",
                    "healthy enabled tools / enabled tools", "#/integrations"),
}
DEFAULT_WEIGHTS = {"identity": 20, "endpoint": 15, "vulnerability": 20, "cloud": 10, "email": 10, "response": 10,
                   "detection": 10, "tool_health": 5}
MAX_WEIGHT = 100
BANDS = ((80, "strong"), (60, "fair"), (0, "weak"))
CRITICAL_PENALTY, HIGH_PENALTY = 15, 8
EMAIL_WINDOW_DAYS = 90
OPEN_FINDING = ("open", "reopened")
OPEN_MISCONFIG = ("open", "routed", "reopened", "pending_validation")
FORMULA = ("Dome Score = round( sum(weight x pillar score) / sum(weight) ), over the pillars that have data and a "
           "weight above 0. Each pillar is 0-100 and computed from the platform's records; weights only decide how "
           "much each pillar counts.")


class DomeScoreWeights(Base):
    """Versioned pillar weights; the newest row is in force (none = the defaults)."""

    __tablename__ = "dome_score_weights"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    weights: Mapped[dict[str, Any]] = mapped_column(JSON)
    set_by: Mapped[str] = mapped_column(String(256))
    note: Mapped[str] = mapped_column(BoundedText(2000), default="")
    created_at: Mapped[Any] = mapped_column(UTCDateTime(), default=utcnow)


def validate(weights: Any) -> list[str]:
    if not isinstance(weights, dict):
        return ["weights must be an object: pillar -> whole number 0-100"]
    out = [f"{k}: unknown pillar ({', '.join(PILLARS)})" for k in weights if k not in PILLARS]
    for k, v in weights.items():
        if k in PILLARS and (isinstance(v, bool) or not isinstance(v, int) or not 0 <= v <= MAX_WEIGHT):
            out.append(f"{k}: a whole number from 0 to {MAX_WEIGHT}")
    if not out and not any(weights.get(k, DEFAULT_WEIGHTS[k]) for k in PILLARS):
        out.append("at least one pillar needs a weight above 0")
    return out


def _full(weights: dict[str, Any] | None) -> dict[str, int]:
    """Weights for every pillar: what was given, the defaults for the rest."""
    return {k: int((weights or {}).get(k, DEFAULT_WEIGHTS[k])) for k in PILLARS}


class WeightStore:
    def __init__(self, session: Session) -> None:
        self.s = session

    def active_row(self) -> DomeScoreWeights | None:
        return self.s.execute(select(DomeScoreWeights).order_by(DomeScoreWeights.id.desc()).limit(1)).scalars().first()

    def active(self) -> dict[str, int]:
        row = self.active_row()
        return _full(row.weights if row else None)

    def save(self, weights: dict[str, Any], by: Any, note: str = "") -> DomeScoreWeights:
        from soc_platform.core.audit import AuditLog
        from soc_platform.core.auth import Perm

        # a lead decides how the headline figure is weighted; a service key or an agent never does
        if by.is_service or by.is_agent or not by.can(Perm.APPROVE_POLICY):
            raise PermissionError("a lead (approve_policy) sets the Dome Score weights")
        problems = validate(weights)
        if problems:
            raise ValueError("; ".join(problems))
        before, after = self.active(), _full(weights)
        row = DomeScoreWeights(weights=copy.deepcopy(after), set_by=by.id, note=(note or "")[:2000])
        self.s.add(row)
        self.s.flush()
        AuditLog(self.s).append(actor_type=by.actor_type, actor_id=by.id, event_type="dome_score.weights_changed",
                                subject_type="dome_score", subject_id=str(row.id),
                                payload={"note": (note or "")[:500], "changes": {
                                    k: {"from": before[k], "to": after[k]} for k in PILLARS if before[k] != after[k]}})
        return row

    def history(self, limit: int = 30) -> list[dict[str, Any]]:
        return [{"id": r.id, "set_by": r.set_by, "note": r.note, "created_at": r.created_at.isoformat(),
                 "weights": _full(r.weights)}
                for r in self.s.execute(select(DomeScoreWeights).order_by(DomeScoreWeights.id.desc())
                                        .limit(limit)).scalars()]


# ------------------------------------------------------------------------------------------------- the pillars
def _ratio(good: int, total: int, noun: str) -> dict[str, Any]:
    if not total:
        return {"score": None, "good": 0, "total": 0, "detail": f"No {noun} on record yet"}
    return {"score": round(100 * good / total), "good": good, "total": total, "detail": f"{good} of {total} {noun}"}


def _risk(s: Session, kind: str, noun: str) -> dict[str, Any]:
    from soc_platform.intelligence.risk import RiskEngine

    total = s.execute(select(Entity.id).where(Entity.kind == kind)).scalars().all()
    at_risk = sum(1 for p in RiskEngine(s).top(kind, limit=len(total) or 1) if p.band in ("high", "critical"))
    return _ratio(len(total) - at_risk, len(total), noun)


def _vulnerability(s: Session) -> dict[str, Any]:
    from soc_platform.domains.vulnerability.models import ConsolidatedFinding

    hosts = set(s.execute(select(Entity.id).where(Entity.kind == "asset")).scalars())
    exposed = set(s.execute(select(ConsolidatedFinding.asset_id).where(
        ConsolidatedFinding.status.in_(OPEN_FINDING), ConsolidatedFinding.priority_band.in_(("P1", "P2")))).scalars())
    return _ratio(len(hosts - exposed), len(hosts), "hosts")


def _cloud(s: Session) -> dict[str, Any]:
    from soc_platform.domains.vulnerability.models import CloudMisconfiguration

    rows = s.execute(select(CloudMisconfiguration.resource_id, CloudMisconfiguration.status,
                            CloudMisconfiguration.severity)).all()
    resources = {r for r, _, _ in rows}
    bad = {r for r, st, sev in rows if st in OPEN_MISCONFIG and str(sev).lower() in ("high", "critical")}
    return _ratio(len(resources - bad), len(resources), "cloud resources")


def _email(s: Session) -> dict[str, Any]:
    from soc_platform.domains.phishing.models import Submission

    rows = [x for x in s.execute(select(Submission).where(Submission.verdict.in_(("malicious", "suspicious"))))
            .scalars()]
    if rows:   # the window ends at the newest report, not the wall clock: replayed or quiet periods keep their data
        newest = max(x.received_at for x in rows)
        rows = [x for x in rows if x.received_at >= newest - timedelta(days=EMAIL_WINDOW_DAYS)]
    clicked = sum(1 for x in rows if (x.analysis or {}).get("clicked"))
    return _ratio(len(rows) - clicked, len(rows), "malicious or suspicious reports with no click")


def _response(s: Session) -> dict[str, Any]:
    sev = Counter(s.execute(select(Case.severity).where(Case.status != "closed",
                                                        Case.severity.in_(("critical", "high")))).scalars())
    crit, high = sev.get("critical", 0), sev.get("high", 0)
    if not s.execute(select(Case.id).limit(1)).first():
        return {"score": None, "good": 0, "total": 0, "detail": "No cases on record yet"}
    score = max(0, 100 - CRITICAL_PENALTY * crit - HIGH_PENALTY * high)
    return {"score": score, "good": None, "total": None,
            "detail": f"{crit} open critical and {high} open high case{'s' if high != 1 else ''}"}


def _detection(s: Session, registry: Any) -> dict[str, Any]:
    from soc_platform.intelligence.attack_coverage import coverage

    summ = coverage(s, registry.enabled_names())["summary"]
    if not summ.get("techniques"):
        return {"score": None, "good": 0, "total": 0, "detail": "No ATT&CK techniques in the catalogue"}
    return {"score": round(summ["weighted_coverage_pct"]), "good": summ["covered"], "total": summ["techniques"],
            "detail": f"{summ['covered']} of {summ['techniques']} techniques visible, {summ['full']} of them fully"}


def _tool_health(s: Session, registry: Any) -> dict[str, Any]:
    from soc_platform.connectors.health import HEALTHY_STATES, connector_freshness

    enabled = [x for x in connector_freshness(s, registry) if x["enabled"]]
    return _ratio(sum(1 for x in enabled if x["state"] in HEALTHY_STATES), len(enabled), "enabled tools healthy")


def _measure(s: Session, registry: Any) -> dict[str, dict[str, Any]]:
    """Each pillar's own figure. A tool or table that cannot be read leaves that pillar without data, never the
    whole score."""
    import logging

    fns = {"identity": lambda: _risk(s, "identity", "people"), "endpoint": lambda: _risk(s, "asset", "hosts"),
           "vulnerability": lambda: _vulnerability(s), "cloud": lambda: _cloud(s), "email": lambda: _email(s),
           "response": lambda: _response(s), "detection": lambda: _detection(s, registry),
           "tool_health": lambda: _tool_health(s, registry)}
    out = {}
    for k, fn in fns.items():
        try:
            out[k] = fn()
        except Exception as exc:  # noqa: BLE001 - one pillar's failure must not take the posture figure down
            logging.getLogger(__name__).warning("dome score pillar %s unavailable: %s", k, type(exc).__name__)
            out[k] = {"score": None, "good": 0, "total": 0, "detail": "Unavailable: the data could not be read"}
    return out


def combine(measured: dict[str, dict[str, Any]], weights: dict[str, int]) -> dict[str, Any]:
    """Pure arithmetic over the pillar scores as shown, so anyone can recompute the headline from the screen."""
    used = {k: weights[k] for k in PILLARS if weights[k] > 0 and measured[k]["score"] is not None}
    total_w = sum(used.values())
    pillars = []
    for k, (name, module, what, how, link) in PILLARS.items():
        m = measured[k]
        share = 100 * used[k] / total_w if k in used else 0.0
        pillars.append({"key": k, "name": name, "module": module, "measures": what, "formula": how, "link": link,
                        "score": m["score"], "detail": m["detail"], "good": m["good"], "total": m["total"],
                        "weight": weights[k], "counted": k in used, "share_pct": round(share, 1),
                        "contribution": round(share * m["score"] / 100, 1) if k in used else 0.0})
    score = round(sum(used[k] * measured[k]["score"] for k in used) / total_w) if total_w else None
    band = next(b for t, b in BANDS if score >= t) if score is not None else "no data"
    return {"score": score, "band": band, "pillars": pillars, "weights": weights}


def dome_score(s: Session, registry: Any, weights: dict[str, Any] | None = None) -> dict[str, Any]:
    """The score with the weights in force, or with `weights` (a preview: nothing is saved)."""
    store = WeightStore(s)
    preview = weights is not None
    if preview:
        problems = validate(weights)
        if problems:
            raise ValueError("; ".join(problems))
    w = _full(weights) if preview else store.active()
    row = store.active_row()
    out = combine(_measure(s, registry), w)
    out.update({"generated_at": utcnow().isoformat(), "formula": FORMULA, "preview": preview,
                "default_weights": dict(DEFAULT_WEIGHTS), "bands": {b: t for t, b in BANDS},
                "weights_version": {"id": row.id, "set_by": row.set_by, "note": row.note,
                                    "created_at": row.created_at.isoformat()} if row else None})
    return out
