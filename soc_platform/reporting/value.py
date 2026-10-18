"""Value scorecard: the benefits the platform is deployed for, measured against the organisation's own baseline.

Every figure is computed here, in code, from the platform's records (case, submission, action, finding, report and
disposition timestamps) or entered by a SOC lead where software cannot measure it - analyst *effort* is not elapsed
time, so effort per case and report hours come from a time study. The LLM never produces or changes any of them.

Each KPI says where its value comes from:
* ``platform``   - measured from the platform's own records over the period;
* ``time_study`` - entered (``kind="measured"``) from a time study during the pilot;
* ``derived``    - computed from the two (capacity freed = effort saved per case x case volume).

A KPI's status compares its current value with its baseline and target: ``met`` (target reached), ``improving``
(better than baseline, short of target), ``not_improved``, ``no_baseline`` or ``no_data``. Targets default to the
change agreed in the customer presentation (for example -50 % handling time) and can be replaced by a lead.
"""

from __future__ import annotations

from datetime import timedelta
from statistics import median
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from soc_platform.core.models import ActionRequest, Case, Disposition, utcnow

WEEKS_PER_MONTH = 52 / 12
CONTAINMENT_ACTIONS = ("email.campaign_purge", "endpoint.isolate", "identity.revoke_sessions")

# id -> definition. ``target_change``: the default target as a change from baseline (-0.5 = half); ``target`` an
# absolute default. ``domain``: who may see it (a domain-scoped person sees their domain's KPIs only).
KPIS: dict[str, dict[str, Any]] = {
    "phishing_handling_minutes": {
        "label": "Phishing handling time per reported e-mail", "unit": "minutes", "better": "lower",
        "category": "efficiency", "source": "platform", "domain": "phishing", "target_change": -0.5,
        "measured_from": "reported e-mail received -> case closed (median)"},
    "phishing_containment_minutes": {
        "label": "Time to contain a clicked phishing e-mail", "unit": "minutes", "better": "lower",
        "category": "threat", "source": "platform", "domain": "phishing", "target_change": -0.5,
        "measured_from": "reported e-mail received -> first containment action executed (median)"},
    "incident_decision_hours": {
        "label": "Incident: alert to analyst decision", "unit": "hours", "better": "lower",
        "category": "efficiency", "source": "platform", "domain": "incident", "target_change": -0.4,
        "measured_from": "incident case created -> first analyst disposition or closure (median)"},
    "vuln_mttr_days": {
        "label": "Time to validated fix, critical / known-exploited", "unit": "days", "better": "lower",
        "category": "threat", "source": "platform", "domain": "vulnerability", "target_change": -0.3,
        "measured_from": "finding first seen -> remediation validated by a scan (mean, P1 or CISA KEV)"},
    "findings_past_sla": {
        "label": "Critical findings past SLA (known-exploited or internet-exposed)", "unit": "findings",
        "better": "lower", "category": "threat", "source": "platform", "domain": "vulnerability",
        "target_change": -0.5, "measured_from": "open findings past their SLA date that are KEV-listed or exposed (now)"},
    "report_hours_per_week": {
        "label": "Analyst hours on recurring reports per week", "unit": "hours", "better": "lower",
        "category": "efficiency", "source": "time_study", "domain": "vulnerability", "target_change": -0.7,
        "measured_from": "analyst hours from a time study; the platform counts the reports it drafted"},
    "capacity_freed_pct": {
        "label": "Tier-1 analyst capacity freed", "unit": "%", "better": "higher", "category": "capacity",
        "source": "derived", "domain": "*", "target": 30.0,
        "measured_from": "(effort saved per case x case volume + report hours saved) / tier-1 hours per month"},
    "analyst_agreement_pct": {
        "label": "Agreement with analyst decisions (shadow mode)", "unit": "%", "better": "higher",
        "category": "quality", "source": "platform", "domain": "*", "target": 90.0,
        "measured_from": "platform verdict vs the analyst's recorded disposition; missed threats reported alongside"},
}

# Entered figures that feed the derived KPI (time study before and during the pilot).
INPUTS: dict[str, dict[str, Any]] = {
    "phishing_effort_minutes": {"label": "Analyst effort per reported e-mail", "unit": "minutes"},
    "incident_effort_minutes": {"label": "Analyst effort per incident", "unit": "minutes"},
    "tier1_hours_per_month": {"label": "Tier-1 analyst hours available per month", "unit": "hours"},
}
KINDS = ("baseline", "target", "measured")
MISSED_THREATS_TARGET_PCT = 2.0


class ValueInputError(ValueError):
    pass


def inputs(s: Session) -> dict[str, dict[str, Any]]:
    """Every entered figure, latest per (kpi, kind)."""
    from soc_platform.reporting.models import ValueInput

    out: dict[str, dict[str, Any]] = {}
    for row in s.execute(select(ValueInput).order_by(ValueInput.set_at, ValueInput.id)).scalars():
        out.setdefault(row.kpi, {})[row.kind] = {"value": row.value, "note": row.note, "set_by": row.set_by,
                                                 "set_at": row.set_at.isoformat()}
    return out


def set_input(s: Session, kpi: str, kind: str, value: float, *, note: str, by: str) -> dict[str, Any]:
    """Record a baseline, target or time-study measurement (replacing the previous one) and audit it."""
    import math

    from soc_platform.core.audit import AuditLog
    from soc_platform.reporting.models import ValueInput

    if kpi not in KPIS and kpi not in INPUTS:
        raise ValueInputError(f"unknown KPI or input {kpi!r}")
    if kind not in KINDS:
        raise ValueInputError(f"kind must be one of {', '.join(KINDS)}")
    if kind == "measured" and kpi in KPIS and KPIS[kpi]["source"] != "time_study":
        raise ValueInputError(f"{kpi} is measured by the platform; only its baseline or target can be entered")
    if isinstance(value, bool) or not isinstance(value, int | float) or not math.isfinite(value) or value < 0:
        raise ValueInputError("value must be a non-negative number")
    unit = (KPIS.get(kpi) or INPUTS[kpi])["unit"]
    if unit == "%" and value > 100:
        raise ValueInputError("a percentage cannot exceed 100")
    previous = inputs(s).get(kpi, {}).get(kind)
    for old in s.execute(select(ValueInput).where(ValueInput.kpi == kpi, ValueInput.kind == kind)).scalars():
        s.delete(old)
    row = ValueInput(kpi=kpi, kind=kind, value=float(value), note=note[:500], set_by=by, set_at=utcnow())
    s.add(row)
    s.flush()
    AuditLog(s).append(actor_type="human", actor_id=by, event_type="value.input_set", subject_type="value_kpi",
                       subject_id=kpi, payload={"kind": kind, "value": float(value), "note": note[:200],
                                                "previous": previous["value"] if previous else None})
    return {"kpi": kpi, "kind": kind, "value": float(value), "note": row.note}


# ---------------------------------------------------------------------------------------------------- measurement


def _aware(dt):
    from datetime import UTC

    return dt.replace(tzinfo=UTC) if dt is not None and dt.tzinfo is None else dt


def _med(values: list[float]) -> float | None:
    return round(median(values), 1) if values else None


def _measure(s: Session, since) -> dict[str, dict[str, Any]]:
    """Platform-measured current values over the period, with sample sizes."""
    from soc_platform.domains.phishing.models import Submission
    from soc_platform.domains.vulnerability.models import ConsolidatedFinding, ReportRun, VulnIntel

    out: dict[str, dict[str, Any]] = {}
    subs = list(s.execute(select(Submission).where(Submission.received_at >= since, Submission.case_id.is_not(None))
                          .order_by(Submission.received_at, Submission.id)).scalars())
    cases = {c.id: c for c in s.execute(select(Case).where(Case.id.in_([x.case_id for x in subs]))).scalars()} if subs else {}
    handling = [(_aware(cases[x.case_id].closed_at) - _aware(x.received_at)).total_seconds() / 60
                for x in subs if x.case_id in cases and cases[x.case_id].closed_at]
    out["phishing_handling_minutes"] = {"current": _med(handling), "samples": len(handling),
                                        "volume": len(subs)}
    contain = []
    for x in subs:
        first = s.execute(select(ActionRequest.executed_at).where(
            ActionRequest.case_id == x.case_id, ActionRequest.status == "executed",
            ActionRequest.action_type.in_(CONTAINMENT_ACTIONS)).order_by(ActionRequest.executed_at)).scalars().first()
        if first:
            contain.append((_aware(first) - _aware(x.received_at)).total_seconds() / 60)
    out["phishing_containment_minutes"] = {"current": _med(contain), "samples": len(contain)}

    incidents = list(s.execute(select(Case).where(Case.domain == "incident", Case.created_at >= since)
                               .order_by(Case.created_at, Case.id)).scalars())
    decided = []
    for c in incidents:
        first = s.execute(select(Disposition.created_at).where(Disposition.subject_id == c.id)
                          .order_by(Disposition.created_at)).scalars().first()
        at = first or c.closed_at
        if at:
            decided.append((_aware(at) - _aware(c.created_at)).total_seconds() / 3600)
    out["incident_decision_hours"] = {"current": _med(decided), "samples": len(decided), "volume": len(incidents)}

    kev = {v.cve for v in s.execute(select(VulnIntel).where(VulnIntel.kev.is_(True))).scalars()}
    findings = list(s.execute(select(ConsolidatedFinding)).scalars())
    fixed = [f for f in findings if f.status == "remediated" and f.closed_at and _aware(f.closed_at) >= since
             and (f.priority_band == "P1" or f.cve in kev)]
    mttr = (sum((_aware(f.closed_at) - _aware(f.first_seen)).total_seconds() for f in fixed) / len(fixed) / 86400
            if fixed else None)
    out["vuln_mttr_days"] = {"current": round(mttr, 1) if mttr is not None else None, "samples": len(fixed)}
    now = utcnow()
    open_rows = [f for f in findings if f.status in ("open", "reopened")]
    past = [f for f in open_rows if f.sla_due and now > _aware(f.sla_due) and (f.cve in kev or f.internet_exposed)]
    out["findings_past_sla"] = {"current": float(len(past)), "samples": len(open_rows)}

    recurring = ("daily_exposure", "weekly_vm", "weekly_mgmt")
    drafted = [r for r in s.execute(select(ReportRun).where(ReportRun.generated_at >= since)).scalars()
               if r.kind in recurring or r.kind.startswith("custom:")]
    out["report_hours_per_week"] = {"current": None, "samples": 0, "reports_drafted": len(drafted)}

    from soc_platform.core.cases import agreement_report

    rates = [agreement_report(s, d, since=since) for d in ("phishing", "incident")]
    n = sum(r["sample_size"] for r in rates)
    agree = sum((r["agreement_rate"] or 0) * r["sample_size"] for r in rates)
    missed = sum((r["false_negative_rate"] or 0) * r["sample_size"] for r in rates)
    out["analyst_agreement_pct"] = {"current": round(100 * agree / n, 1) if n else None, "samples": n,
                                    "missed_threats_pct": round(100 * missed / n, 1) if n else None}
    return out


def _status(defn: dict[str, Any], baseline: float | None, current: float | None, target: float | None) -> str:
    if current is None:
        return "no_data"
    lower = defn["better"] == "lower"
    if target is not None and (current <= target if lower else current >= target):
        return "met"
    if baseline is None:
        return "no_baseline"
    return "improving" if (current < baseline if lower else current > baseline) else "not_improved"


def scorecard(s: Session, *, days: int = 30, domains: frozenset[str] | set[str] = frozenset({"*"})) -> dict[str, Any]:
    """The scorecard for the last ``days``: every KPI with baseline, current value, target, change and status."""
    since = utcnow() - timedelta(days=days)
    entered = inputs(s)
    measured = _measure(s, since)
    every = "*" in domains
    rows = []
    for kid, d in KPIS.items():
        if not every and (d["domain"] == "*" or d["domain"] not in domains):
            continue
        e = entered.get(kid, {})
        baseline = e.get("baseline", {}).get("value")
        m = dict(measured.get(kid, {}))
        current = e.get("measured", {}).get("value") if d["source"] == "time_study" else m.pop("current", None)
        m.pop("current", None)
        if e.get("target"):
            target = e["target"]["value"]
        elif "target" in d:
            target = d["target"]
        elif baseline is not None:
            target = round(baseline * (1 + d["target_change"]), 1)
        else:
            target = None
        rows.append({"id": kid, **{k: d[k] for k in ("label", "unit", "better", "category", "source", "measured_from")},
                     "baseline": baseline, "baseline_note": e.get("baseline", {}).get("note"),
                     "current": current, "target": target,
                     "change_pct": round(100 * (current - baseline) / baseline, 1) if current is not None and baseline else None,
                     "status": _status(d, baseline, current, target), "supporting": m})
    out: dict[str, Any] = {"period_days": days, "since": since.isoformat(), "kpis": rows,
                           "statuses": {st: sum(1 for r in rows if r["status"] == st)
                                        for st in ("met", "improving", "not_improved", "no_baseline", "no_data")}}
    cap = next((r for r in rows if r["id"] == "capacity_freed_pct"), None)
    if cap is not None:
        cap_value, detail = _capacity(entered, measured, days)
        cap.update(current=cap_value, supporting=detail, status=_status(KPIS["capacity_freed_pct"], None, cap_value, cap["target"]))
    agree = next((r for r in rows if r["id"] == "analyst_agreement_pct"), None)
    if agree is not None:
        missed = agree["supporting"].get("missed_threats_pct")
        agree["supporting"]["missed_threats_target_pct"] = MISSED_THREATS_TARGET_PCT
        if agree["status"] == "met" and missed is not None and missed > MISSED_THREATS_TARGET_PCT:
            agree["status"] = "improving"          # agreement alone is not enough while threats are being missed
        out["automation_gate_open"] = (agree["status"] == "met")
    out["statuses"] = {st: sum(1 for r in rows if r["status"] == st)
                       for st in ("met", "improving", "not_improved", "no_baseline", "no_data")}
    out["inputs"] = {k: {**INPUTS[k], **entered.get(k, {})} for k in INPUTS} if every else {}
    return out


def _capacity(entered: dict[str, dict[str, Any]], measured: dict[str, dict[str, Any]], days: int
              ) -> tuple[float | None, dict[str, Any]]:
    """Hours freed per month = effort saved per case x cases per month (phishing, incidents) + report hours saved;
    as a share of tier-1 hours per month. Needs the time-study figures; returns None until they are entered."""
    def pair(key: str) -> tuple[float | None, float | None]:
        e = entered.get(key, {})
        return e.get("baseline", {}).get("value"), e.get("measured", {}).get("value")

    per_month = 30 / days
    hours = 0.0
    used: dict[str, Any] = {}
    for key, kpi in (("phishing_effort_minutes", "phishing_handling_minutes"), ("incident_effort_minutes", "incident_decision_hours")):
        before, now = pair(key)
        volume = measured.get(kpi, {}).get("volume", 0) * per_month
        if before is not None and now is not None:
            saved = max(0.0, before - now) * volume / 60
            hours += saved
            used[key] = {"saved_minutes_per_case": round(before - now, 1), "cases_per_month": round(volume, 1),
                         "hours_per_month": round(saved, 1)}
    before, now = pair("report_hours_per_week")
    if before is not None and now is not None:
        saved = max(0.0, before - now) * WEEKS_PER_MONTH
        hours += saved
        used["report_hours_per_week"] = {"hours_per_month": round(saved, 1)}
    tier1 = entered.get("tier1_hours_per_month", {}).get("baseline", {}).get("value")
    detail = {"hours_freed_per_month": round(hours, 1) if used else None, "components": used,
              "tier1_hours_per_month": tier1}
    if not used or not tier1:
        return None, detail
    return round(100 * hours / tier1, 1), detail
