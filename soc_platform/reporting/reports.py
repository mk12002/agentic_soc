"""Recurring and per-case reporting (VM-F13, VM-F14, VM-T08, IM-F12, PH-F14, U01, U05, U15).

All figures are computed deterministically by the domain services; this module only
lays them out. Narrative commentary comes from the LLM gateway (grounded on the
computed figures, which are passed as evidence) or from deterministic sentences when
no model is configured. the client's own templates can be supplied: a ``.docx`` template is
used as the base document (its styles/header/footer are kept) and a ``.pptx``
template supplies the slide master.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pptx.util import Inches
from sqlalchemy.orm import Session

from soc_platform.core.models import utcnow
from soc_platform.domains.vulnerability.models import ReportRun
from soc_platform.llm.gateway import LLMGateway


def _commentary(llm: LLMGateway | None, workflow: str, question: str, facts: dict[str, Any]) -> tuple[str, str]:
    evidence = [{"id": f"E{i + 1}", "claim": f"{k}: {v}", "source": "computed"} for i, (k, v) in enumerate(facts.items())]
    if llm is not None:
        g = llm.grounded(workflow, question, evidence, tier="small")
        if g.get("source") == "llm" and g.get("claims"):
            return " ".join(c["text"] for c in g["claims"]), "llm (grounded on computed figures)"
    return _deterministic_commentary(facts), "deterministic"


def _deterministic_commentary(f: dict[str, Any]) -> str:
    parts = []
    if "open" in f:
        parts.append(f"{f['open']} open findings")
    if f.get("kev_open"):
        parts.append(f"{f['kev_open']} on the CISA KEV list")
    if f.get("sla_breached"):
        parts.append(f"{f['sla_breached']} past SLA")
    if f.get("internet_exposed_open"):
        parts.append(f"{f['internet_exposed_open']} on internet-exposed assets")
    s = ("Exposure summary: " + ", ".join(parts) + ".") if parts else ""
    if f.get("by_priority"):
        s += " Priority mix " + ", ".join(f"{k}={v}" for k, v in sorted(f["by_priority"].items())) + "."
    return s or "No material change."


def _names(items: list[str], limit: int = 8) -> str:
    """A list a reader can take in: the count, the first few, and how many more (a live tenant has hundreds)."""
    items = sorted(items)
    if not items:
        return "none"
    shown = ", ".join(items[:limit])
    return f"{len(items)}: {shown}" + (f" and {len(items) - limit} more (full list in the console)" if len(items) > limit else "")


SHORT = {"crowdstrike": "CS", "defender_endpoint": "MDE", "rapid7": "R7", "wiz": "Wiz", "defender_office365": "MDO",
         "defender_identity": "MDI", "entra": "Entra", "umbrella": "Umbrella", "sentinel": "Sentinel"}   # table space


class ReportService:
    def __init__(self, session: Session, out_dir: str | Path, *, llm: LLMGateway | None = None,
                 templates: dict[str, str] | None = None) -> None:
        self.s = session
        self.out = Path(out_dir)
        self.out.mkdir(parents=True, exist_ok=True)
        self.llm = llm
        self.templates = templates or {}

    def _record(self, kind: str, path: Path, metrics: dict[str, Any], by: str) -> ReportRun:
        from soc_platform.core.blobstore import BlobStore

        # reports carry case details: encrypted at rest like raw payloads, on the shared store when configured
        ref = BlobStore(self.s).store_generated(path, f"reports/{Path(path).name}")
        run = ReportRun(kind=kind, path=ref, metrics=metrics, generated_by=by)
        self.s.add(run)
        self.s.flush()
        return run

    # ------------------------------------------------------------------ shared vulnerability view

    def _vm_view(self, vm: Any) -> dict[str, Any]:
        """What the vulnerability reports show, computed once: findings with their KEV flag, what needs action today,
        per-team performance, ageing by priority, and the last day's and week's changes."""
        from datetime import timedelta

        from sqlalchemy import select

        from soc_platform.domains.vulnerability.models import ConsolidatedFinding, VulnException, VulnIntel

        now = utcnow()
        m = vm.metrics()
        kev = {v.cve for v in self.s.execute(select(VulnIntel).where(VulnIntel.kev.is_(True))).scalars()}
        intel = {v.cve: v for v in self.s.execute(select(VulnIntel)).scalars()}
        rows = list(self.s.execute(select(ConsolidatedFinding)).scalars())
        open_rows = [f for f in rows if f.status in ("open", "reopened")]

        def aware(dt):
            from datetime import UTC

            return dt.replace(tzinfo=UTC) if dt is not None and dt.tzinfo is None else dt

        def sla_text(f) -> str:
            if not f.sla_due:
                return "no SLA"
            days = (aware(f.sla_due) - now).days
            return f"{-days} d late" if days < 0 else ("due today" if days == 0 else f"due in {days} d")

        def overdue(f) -> bool:
            return bool(f.sla_due and now > aware(f.sla_due))

        urgent = sorted((f for f in open_rows if f.priority_band == "P1" or f.cve in kev or overdue(f)),
                        key=lambda f: (-f.priority_score, f.cve, f.asset_name))
        def name(f) -> str:
            vi = intel.get(f.cve)
            return (f.title or f.product or (vi.description if vi else "") or f.cve)[:60]

        act = [[f.priority_band, f.cve, name(f), f.asset_name, f.platform_team or "unassigned", sla_text(f),
                "yes" if f.cve in kev else "", "yes" if f.internet_exposed else "", ", ".join(sorted(SHORT.get(x, x) for x in f.sources))]
               for f in urgent]
        teams: dict[str, dict[str, Any]] = {}
        for f in rows:
            t = teams.setdefault(f.platform_team or "unassigned", {"open": 0, "p1": 0, "past": 0, "fixed": 0, "oldest": 0,
                                                                   "accepted": 0})
            if f.status in ("open", "reopened"):
                t["open"] += 1
                t["p1"] += f.priority_band == "P1"
                t["past"] += overdue(f)
                t["oldest"] = max(t["oldest"], (now - aware(f.first_seen)).days)
            elif f.status == "remediated":
                t["fixed"] += 1
            elif f.status == "risk_accepted":
                t["accepted"] += 1
        buckets = ("0-7", "8-30", "31-90", "90+")

        def bucket(f) -> str:
            age = (now - aware(f.first_seen)).days
            return "0-7" if age <= 7 else "8-30" if age <= 30 else "31-90" if age <= 90 else "90+"
        bands = sorted({f.priority_band for f in open_rows}) or ["P1"]
        ageing = {b: [sum(1 for f in open_rows if f.priority_band == b and bucket(f) == k) for k in buckets] for b in bands}
        day, week = now - timedelta(days=1), now - timedelta(days=7)
        new_day = [f for f in rows if aware(f.first_seen) >= day]
        fixed_day = [f for f in rows if f.status == "remediated" and f.closed_at and aware(f.closed_at) >= day]
        fixed_week = [f for f in rows if f.status == "remediated" and f.closed_at and aware(f.closed_at) >= week]
        new_week = [f for f in rows if aware(f.first_seen) >= week]
        exc = list(self.s.execute(select(VulnException).where(VulnException.status == "active")).scalars())
        expiring = sorted((x for x in exc if aware(x.expires_at) <= now + timedelta(days=30)), key=lambda x: x.expires_at)
        by_id = {f.id: f for f in rows}
        compliant = sum(1 for f in open_rows if not overdue(f))
        return {"m": m, "now": now, "act": act, "teams": teams, "buckets": buckets, "ageing": ageing,
                "new_day": new_day, "fixed_day": fixed_day, "new_week": new_week, "fixed_week": fixed_week,
                "expiring": [[by_id[x.finding_id].cve if x.finding_id in by_id else "", by_id[x.finding_id].asset_name
                              if x.finding_id in by_id else "", f"{aware(x.expires_at):%d %b %Y}", x.approver or "",
                              (x.justification or "")[:60]] for x in expiring],
                "sla_compliance": round(100 * compliant / len(open_rows), 1) if open_rows else None,
                "sources": sorted({s for f in rows for s in f.sources})}

    def _vm_charts(self, v: dict[str, Any]) -> dict[str, bytes | None]:
        from soc_platform.reporting import charts

        m, teams = v["m"], v["teams"]
        names = sorted(t for t in teams if teams[t]["open"])
        return {
            "priority": charts.donut_png("Open findings by priority", m["by_priority"], order=("P1", "P2", "P3", "P4"),
                                         centre_label="open"),
            "teams": charts.stacked_png("Open findings by team", names,
                                        [("past SLA", [teams[t]["past"] for t in names]),
                                         ("within SLA", [teams[t]["open"] - teams[t]["past"] for t in names])]),
            "ageing": charts.columns_png("Age of open findings (days)", list(v["buckets"]),
                                         [(b, vals) for b, vals in sorted(v["ageing"].items())]),
        }

    # ------------------------------------------------------------------ VM-F13 daily exposure

    def daily_exposure(self, vm: Any, *, by: str = "system:scheduler") -> ReportRun:
        from soc_platform.reporting import design as D

        v = self._vm_view(vm)
        m = v["m"]
        cov = vm.coverage()
        text, src = _commentary(self.llm, "report.daily_exposure", "Write a 3-sentence daily exposure commentary.", m)
        d = D.new_document("Daily exposure report", template=self.templates.get("daily_exposure"))
        D.cover(d, "Daily exposure report", f"{v['now']:%A %d %B %Y}",
                f"As of {v['now']:%H:%M} UTC  ·  sources: {', '.join(v['sources']) or 'none connected'}  ·  "
                f"commentary: {src}")
        D.tiles(d, [("Open findings", m["open"], "neutral"), ("Known-exploited (KEV)", m["kev_open"], "bad" if m["kev_open"] else "good"),
                    ("Internet-exposed", m["internet_exposed_open"], "warn" if m["internet_exposed_open"] else "good"),
                    ("Past SLA", m["sla_breached"], "bad" if m["sla_breached"] else "good"),
                    ("New in 24 h", len(v["new_day"]), "info"), ("Fixed in 24 h", len(v["fixed_day"]), "good")])
        D.paragraph(d, text)
        ch = self._vm_charts(v)
        D.picture_row(d, [ch["priority"], ch["teams"]])
        D.section(d, "Act today", "Open findings that are priority 1, known to be exploited (CISA KEV) or past their SLA, "
                                  "highest priority first. Owners are from the CMDB / ownership sheet.")
        D.table(d, ["Pri", "CVE", "Vulnerability", "Asset", "Team", "SLA", "KEV", "Internet", "Seen by"], v["act"],
                widths_cm=[0.8, 2.6, 3.4, 2.7, 2.1, 1.8, 0.9, 1.5, 1.6], tone_col=0, max_rows=15,
                empty="Nothing needs action today: no P1, known-exploited or overdue finding is open.")
        D.section(d, "By team")
        D.table(d, ["Team", "Open", "P1", "Past SLA", "Oldest open (days)", "Fixed (total)"],
                [[t, x["open"], x["p1"], x["past"], x["oldest"], x["fixed"]] for t, x in sorted(v["teams"].items())],
                numeric={1, 2, 3, 4, 5})
        D.section(d, "Ageing", "How long open findings have been open, by priority.")
        D.picture_row(d, [ch["ageing"]])
        D.table(d, ["Priority", *[f"{b} d" for b in v["buckets"]], "Total"],
                [[b, *vals, sum(vals)] for b, vals in sorted(v["ageing"].items())], numeric={1, 2, 3, 4, 5}, tone_col=0)
        D.section(d, "Changes in the last 24 hours")
        changes = ([["fixed (validated)", f.cve, f.asset_name, f.platform_team or ""] for f in v["fixed_day"]]
                   + [["new", f.cve, f.asset_name, f.platform_team or ""] for f in v["new_day"]])
        D.table(d, ["Change", "CVE", "Asset", "Team"], changes, max_rows=20,
                more_note=f"{max(0, len(changes) - 20)} more changes in the console ({len(v['new_day'])} new, "
                          f"{len(v['fixed_day'])} fixed in 24 h).",
                empty="No finding opened or closed in the last 24 hours.")
        D.section(d, "Coverage and data quality")
        D.table(d, ["Check", "Result"], [["Assets in scope", cov["assets"]],
                                         ["Assets without EDR", _names(cov["missing_edr"])],
                                         ["Assets not in the CMDB", _names(cov["not_in_cmdb"])],
                                         ["Asset match rate", D.fmt((m["asset_match_rate"] or 0) * 100, "%")],
                                         ["People awaiting identity resolution", cov["unresolved_queue"]]],
                widths_cm=[6.0, 11.0])
        D.note(d, f"Generated {utcnow():%Y-%m-%d %H:%M} UTC by the SOC platform. Every figure is computed from the "
                  f"connected tools; the commentary ({src}) only describes them.")
        path = self.out / f"daily_exposure_{utcnow():%Y%m%d_%H%M%S}.docx"
        d.save(path)
        return self._record("daily_exposure", path, m, by)

    # ------------------------------------------------------------------ VM-F13 weekly VM report

    def weekly_vm(self, vm: Any, *, by: str = "system:scheduler") -> ReportRun:
        from sqlalchemy import select

        from soc_platform.domains.vulnerability.models import ActionPlan, RemediationCampaign
        from soc_platform.reporting import design as D

        v = self._vm_view(vm)
        m = v["m"]
        text, src = _commentary(self.llm, "report.weekly_vm", "Write a weekly vulnerability management summary.", m)
        d = D.new_document("Weekly vulnerability management report", template=self.templates.get("weekly_vm"))
        D.cover(d, "Weekly vulnerability management report", f"Week ending {v['now']:%d %B %Y}",
                f"Generated {v['now']:%H:%M} UTC  ·  sources: {', '.join(v['sources']) or 'none connected'}  ·  commentary: {src}")
        D.tiles(d, [("Open findings", m["open"], "neutral"), ("Fixed this week", len(v["fixed_week"]), "good"),
                    ("New this week", len(v["new_week"]), "info"),
                    ("SLA compliance", v["sla_compliance"], "good" if (v["sla_compliance"] or 0) >= 90 else "bad"),
                    ("Mean time to fix", m["mttr_days"], "neutral"), ("Reopened", m["reopened_total"], "warn" if m["reopened_total"] else "good")],
                unit_map={"SLA compliance": "%", "Mean time to fix": "days"})
        D.paragraph(d, text)
        ch = self._vm_charts(v)
        D.picture_row(d, [ch["teams"], ch["priority"]])
        D.section(d, "Team performance", "SLA compliance is the share of a team's open findings that are not past their SLA.")
        D.table(d, ["Platform team", "Open", "P1", "Past SLA", "SLA compliance", "Fixed", "Risk accepted"],
                [[t, x["open"], x["p1"], x["past"], D.fmt(round(100 * (x["open"] - x["past"]) / x["open"], 1), "%") if x["open"] else "–",
                  x["fixed"], x["accepted"]] for t, x in sorted(v["teams"].items())], numeric={1, 2, 3, 4, 5, 6})
        D.section(d, "Remediation campaigns")
        camp = []
        for c in self.s.execute(select(RemediationCampaign).order_by(RemediationCampaign.title)).scalars():
            plans = self.s.execute(select(ActionPlan).where(ActionPlan.campaign_id == c.id)).scalars().all()
            camp.append([c.title, c.status, len(plans), sum(1 for x in plans if x.status == "acknowledged"),
                         sum(1 for x in plans if x.followups), f"{c.target_date:%d %b %Y}" if c.target_date else ""])
        D.table(d, ["Campaign", "Status", "Teams", "Acknowledged", "Escalated", "Target"], camp, numeric={2, 3, 4},
                empty="No remediation campaign is open.")
        D.section(d, "Priority 1, known-exploited and overdue findings")
        D.table(d, ["Pri", "CVE", "Vulnerability", "Asset", "Team", "SLA", "KEV", "Internet", "Seen by"], v["act"],
                widths_cm=[0.8, 2.6, 3.4, 2.7, 2.1, 1.8, 0.9, 1.5, 1.6], tone_col=0, max_rows=25)
        D.section(d, "Ageing")
        D.picture_row(d, [ch["ageing"]])
        D.section(d, "Risk exceptions expiring in the next 30 days")
        D.table(d, ["CVE", "Asset", "Expires", "Approved by", "Justification"], v["expiring"],
                empty="No approved exception expires in the next 30 days.")
        D.section(d, "Trend indicators")
        D.table(d, ["Measure", "Value"], [["Mean time to validated fix", D.fmt(m["mttr_days"], "days")],
                                          ["Findings ever reopened", m["reopened_total"]],
                                          ["Recurrence rate", D.fmt(round(100 * (m["recurrence_rate"] or 0), 1), "%")],
                                          ["Asset match rate", D.fmt((m["asset_match_rate"] or 0) * 100, "%")]],
                widths_cm=[8.0, 9.0])
        D.note(d, f"Generated {utcnow():%Y-%m-%d %H:%M} UTC by the SOC platform. Every figure is computed from the "
                  f"connected tools; the commentary ({src}) only describes them.")
        path = self.out / f"weekly_vm_{utcnow():%Y%m%d_%H%M%S}.docx"
        d.save(path)
        return self._record("weekly_vm", path, m, by)

    # ------------------------------------------------------------------ weekly management presentation

    def weekly_management_deck(self, vm: Any, incident: Any | None = None, phishing: Any | None = None, *,
                               by: str = "system:scheduler") -> ReportRun:

        from soc_platform.reporting import design as D

        v = self._vm_view(vm)
        m = v["m"]
        report = "Weekly management update"
        prs = D.new_deck(self.templates.get("weekly_mgmt_pptx"))
        D.title_slide(prs, "SOC weekly management update", f"Week ending {v['now']:%d %B %Y}",
                      "Every figure is computed from the connected security tools  ·  " + D.CLASSIFICATION)
        h = incident.handover(hours=24 * 7) if incident is not None else None
        p = phishing.metrics() if phishing is not None else None
        n = 1

        def slide(title: str, subtitle: str | None = None):
            nonlocal n
            n += 1
            return D.content_slide(prs, title, report, n, subtitle)

        s = slide("The week in numbers", "Exposure, incidents and reported phishing at a glance")
        items = [("Open vulnerabilities", m["open"], "neutral"), ("Known-exploited open", m["kev_open"], "bad" if m["kev_open"] else "good"),
                 ("Past SLA", m["sla_breached"], "bad" if m["sla_breached"] else "good")]
        if h is not None:
            items += [("Open incidents", h["open_total"], "warn" if h["open_total"] else "good"),
                      ("Incidents awaiting a decision", len(h["awaiting_approval"]), "warn" if h["awaiting_approval"] else "good")]
        if p is not None:
            items += [("Phishing reports handled", p["reported"], "info")]
        D.deck_tiles(s, items, Inches(0.6), Inches(1.8), Inches(12.1), per_row=3, h=Inches(1.5))
        D.deck_note(s, _deterministic_commentary(m), Inches(0.6), Inches(5.4), Inches(12.1), Inches(1.2), size=14)

        s = slide("Vulnerability exposure", f"SLA compliance {D.fmt(v['sla_compliance'], '%')}  ·  fixed this week "
                                            f"{len(v['fixed_week'])}  ·  new this week {len(v['new_week'])}")
        names = sorted(t for t in v["teams"] if v["teams"][t]["open"])
        D.deck_stacked(s, "Open findings by team", names, [("past SLA", [v["teams"][t]["past"] for t in names]),
                                                          ("within SLA", [v["teams"][t]["open"] - v["teams"][t]["past"] for t in names])],
                       Inches(0.5), Inches(1.75), Inches(7.4), Inches(5.1))
        D.deck_doughnut(s, "By priority", m["by_priority"], Inches(8.1), Inches(1.75), Inches(4.7), Inches(3.3),
                        order=("P1", "P2", "P3", "P4"))
        D.deck_tiles(s, [("Internet-exposed", m["internet_exposed_open"], "warn"), ("Mean time to fix", m["mttr_days"], "neutral")],
                     Inches(8.1), Inches(5.25), Inches(4.7), per_row=2, h=Inches(1.4), unit_map={"Mean time to fix": "days"})

        s = slide("Priority vulnerabilities to close", "Priority 1, known-exploited or overdue - highest priority first")
        D.deck_table(s, ["Pri", "CVE", "Asset", "Team", "SLA", "KEV", "Internet"],
                     [[r[0], r[1], r[3], r[4], r[5], r[6], r[7]] for r in v["act"][:9]], Inches(0.6), Inches(1.8),
                     Inches(12.1), col_widths=[0.6, 1.6, 2.4, 2.2, 1.5, 0.7, 0.9], tone_col=0,
                     empty="Nothing needs action: no P1, known-exploited or overdue finding is open.")

        if h is not None:
            s = slide("Incidents", f"Open {h['open_total']}  ·  new this week {h['new_this_shift']}  ·  closed this week "
                                   f"{h['closed_this_shift']}")
            D.deck_doughnut(s, "Open incidents by severity", h["open_by_severity"], Inches(0.5), Inches(1.75),
                            Inches(5.0), Inches(4.0), order=("critical", "high", "medium", "low", "informational"))
            D.deck_table(s, ["Severity", "Incident", "Status"],
                         [[x["severity"], x["title"][:70], x["status"].replace("_", " ")] for x in h["top_open"][:7]],
                         Inches(5.8), Inches(1.8), Inches(7.0), col_widths=[1.1, 4.6, 1.5], tone_col=0, font=11,
                         empty="No open incident.")
        if p is not None:
            ttc = p["time_to_containment_minutes"]["median"]
            s = slide("Reported phishing", f"{p['reported']} reports  ·  {p['campaigns']} campaigns  ·  "
                                           f"{len(p['repeat_clickers'])} repeat clicker(s)")
            D.deck_doughnut(s, "Verdicts of reported e-mails", p["verdict_mix"], Inches(0.5), Inches(1.75), Inches(6.2),
                            Inches(4.6), order=("malicious", "suspicious", "spam", "safe", "pending"))
            D.deck_tiles(s, [("Closed automatically (QA-sampled)", p["auto_closed"], "good"),
                             ("Campaigns", p["campaigns"], "warn" if p["campaigns"] else "good"),
                             ("Median time to contain", ttc, "neutral"),
                             ("Repeat clickers", len(p["repeat_clickers"]), "warn" if p["repeat_clickers"] else "good")],
                         Inches(7.0), Inches(1.8), Inches(5.8), per_row=2, h=Inches(1.5),
                         unit_map={"Median time to contain": "min"})

        from soc_platform.reporting.value import scorecard

        sc = scorecard(self.s, days=7)
        status_tone = {"met": "good", "improving": "info", "not improved": "bad", "awaiting baseline": "neutral",
                       "no data yet": "neutral"}
        label = {"met": "met", "improving": "improving", "not_improved": "not improved", "no_baseline": "awaiting baseline",
                 "no_data": "no data yet"}
        s = slide("Value scorecard", "The benefits the platform is measured on, against the organisation's baseline")
        D.deck_table(s, ["KPI", "Baseline", "Now", "Target", "Status"],
                     [[k["label"], D.fmt(k["baseline"], k["unit"], missing="–"), D.fmt(k["current"], k["unit"], missing="–"),
                       D.fmt(k["target"], k["unit"], missing="–"), label[k["status"]]] for k in sc["kpis"]],
                     Inches(0.6), Inches(1.8), Inches(12.1), col_widths=[5.2, 1.6, 1.6, 1.6, 2.1], tone_col=4,
                     tones=status_tone, font=11)

        if h is not None and h["awaiting_approval"]:
            s = slide("Decisions needed", "Incident cases with recommended actions waiting for an analyst or lead")
            D.deck_table(s, ["Severity", "Case"], [[x["severity"], x["title"][:100]] for x in h["awaiting_approval"][:9]],
                         Inches(0.6), Inches(1.8), Inches(12.1), col_widths=[1.2, 9.0], tone_col=0)
        path = self.out / f"weekly_mgmt_{utcnow():%Y%m%d_%H%M%S}.pptx"
        prs.save(path)
        return self._record("weekly_mgmt", path, m, by)

    # ------------------------------------------------------------------ IM-F12 / U15 investigation record & evidence pack

    def investigation_report(self, view: dict[str, Any], *, by: str) -> ReportRun:
        from soc_platform.reporting import design as D

        c = view["case"]
        a = view["assessment"]
        d = D.new_document("Investigation record", template=self.templates.get("investigation"))
        opened = str(c["created_at"])[:16].replace("T", " ") + " UTC"
        D.cover(d, "Investigation record", c["title"],
                f"Case {c['id']}  ·  {c['domain']}  ·  opened {opened}  ·  status {c['status'].replace('_', ' ')}")
        sev_tone = D.SEVERITY_TONE.get(c["severity"], "neutral")
        # the evidence that can be cited (it has a statement) - the same count the summary and the explanation use
        cited = sum(1 for items in view["evidence"].values() for it in items if it.get("summary"))
        D.tiles(d, [("Severity", c["severity"], sev_tone), ("Verdict", (c["verdict"] or "undetermined").replace("_", " "), sev_tone),
                    ("Confidence", round(100 * float(c["confidence"] or 0)), "neutral"),
                    ("Actions", len(view["actions"]), "info"), ("Cited evidence", cited, "neutral")],
                unit_map={"Confidence": "%"})
        D.section(d, "Summary")
        D.paragraph(d, c["summary"] or "No summary recorded.")
        comp = view.get("completeness") or {}
        if comp.get("unavailable"):
            D.note(d, "INCOMPLETE - these sources could not be queried: " + ", ".join(u["source"] for u in comp["unavailable"]))
        D.section(d, "Findings", "Facts are established by the evidence cited; inferences are the analysis built on them.")
        D.table(d, ["Kind", "Statement", "Evidence"],
                [["fact", cl["text"], ", ".join(cl["evidence_ids"])] for cl in a.get("facts", [])]
                + [["inference", cl["text"], ", ".join(cl["evidence_ids"])] for cl in a.get("inferences", [])],
                widths_cm=[2.0, 12.4, 3.0], tone_col=0, tones={"fact": "neutral", "inference": "info"},
                empty="No findings recorded.")
        D.section(d, "MITRE ATT&CK")
        D.table(d, ["Technique", "Name", "Basis"], [[x["technique"], x.get("name", ""), x.get("basis", "")] for x in a.get("mitre", [])],
                widths_cm=[2.6, 5.4, 9.4], empty="No technique mapped.")
        D.section(d, "Entities")
        D.table(d, ["Kind", "Role", "Name", "Seen by"], [[e["kind"], e["role"], e["name"], ", ".join(e["seen_by"])] for e in view["entities"]],
                widths_cm=[2.2, 2.6, 6.6, 6.0])
        D.section(d, "Timeline")
        D.table(d, ["Time (UTC)", "Source", "Event"], [[x["ts"], x.get("tool"), x["title"]] for x in view["timeline"]],
                widths_cm=[4.2, 3.0, 10.2], empty="No timeline events.")
        D.section(d, "Evidence")
        D.table(d, ["Dimension", "Type", "Source", "Summary"],
                [[dim, it["type"], it["source"], it["summary"]] for dim, items in view["evidence"].items() for it in items],
                widths_cm=[2.6, 2.2, 2.8, 9.8], empty="No evidence recorded.")
        D.section(d, "Actions")
        D.table(d, ["Action", "Status", "Approver", "Rationale"],
                [[x["action_type"], x["status"].replace("_", " "), x.get("approver") or "", x["rationale"]] for x in view["actions"]],
                widths_cm=[4.0, 2.6, 3.0, 7.8], empty="No action requested.")
        D.section(d, "Analyst decisions")
        D.table(d, ["Analyst", "Verdict", "Reasoning", "At"], [[x["analyst"], x["verdict"], x["reasoning"], x["at"]] for x in view["dispositions"]],
                widths_cm=[3.6, 2.6, 7.4, 3.8], empty="No analyst decision recorded yet.")
        D.section(d, "Audit trail (chain of custody)")
        D.table(d, ["Seq", "Time (UTC)", "Actor", "Event"], [[x["seq"], x["ts"], x["actor"], x["event"]] for x in view["audit"]],
                widths_cm=[1.4, 4.4, 5.0, 6.6], numeric={0})
        D.note(d, f"Generated {utcnow():%Y-%m-%d %H:%M} UTC from the case record. Every statement cites its evidence.")
        path = self.out / f"investigation_{c['id']}_{utcnow():%Y%m%d_%H%M%S}.docx"
        d.save(path)
        return self._record("investigation", path, {"case_id": c["id"]}, by)
