"""AI report builder: preconfigured standard reports and reports described in plain language (U01, VM-F13, U15).

A report is a **spec**: title, audience, format (docx | pptx) and sections. Each section pairs a **data source**
(computed in code from the platform's records - the only place numbers come from) with a **writing instruction**.

* Standard reports ship as specs (``STANDARD``) and can be extended with saved specs (``ReportTemplate``).
* A custom report is described in words ("a one-page board brief on phishing and supplier risk this month"); the
  planner (LLM when configured, keyword rules otherwise) turns the request into a spec using **only** catalogue
  sources, and the user can review the plan before generating.
* Narrative per section is written by the governed LLM from that section's facts: every sentence must cite a fact
  id (F#) or it is dropped; internal identities are pseudonymised; without an LLM a deterministic writer is used.
  Figures, tables and charts never come from the model.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Callable

from docx import Document
from docx.shared import Pt, RGBColor
from pptx import Presentation
from pptx.util import Inches
from pptx.util import Pt as PPt
from sqlalchemy import select
from sqlalchemy.orm import Session

from soc_platform.core.models import Case, utcnow
from soc_platform.llm.gateway import BudgetExceeded, LLMGateway

Facts = list[tuple[str, Any]]


# ---------------------------------------------------------------------------------------------- data sources
class Ctx:
    def __init__(self, session: Session, registry: Any, *, days: int = 30, case_id: str | None = None,
                 domains: frozenset[str] = frozenset({"*"})) -> None:
        self.s, self.reg, self.days, self.case_id, self.domains = session, registry, days, case_id, domains

    def vm(self):
        from soc_platform.domains.vulnerability.service import VulnerabilityService

        return VulnerabilityService(self.s, self.reg)


def _n(n, one: str, many: str | None = None) -> str:
    return f"{n} {one if n == 1 else (many or one + 's')}"


def _pct(x) -> str:
    return "n/a" if x is None else f"{x * 100:.1f}%"


def src_overview(c: Ctx) -> dict:
    from soc_platform.api.dashboards import overview

    o = overview(c.s, c.domains, days=min(c.days, 90))              # counts limited to the reader's data scope
    cs, a = o["cases"], o["actions"]
    facts: Facts = [("Open cases", cs["open"]), ("Open cases by domain", ", ".join(f"{k} {v}" for k, v in cs["open_by_domain"].items()) or "none"),
                    ("Open cases by severity", ", ".join(f"{k} {v}" for k, v in cs["open_by_severity"].items()) or "none"),
                    ("Actions awaiting approval", a["pending_approval"]), ("Actions in window", a["in_window"]),
                    ("Automation rate", f"{a['automation_rate_pct']}%"), ("Median hours to close", cs["median_hours_to_close"]),
                    ("Open correlated insights", o["insights"]["open"])]
    return {"facts": facts, "table": {"header": ["Date", "Phishing", "Incident", "Vulnerability"],
                                      "rows": [[d["date"], d["phishing"], d["incident"], d["vulnerability"]] for d in o["trend"] if any(d[k] for k in ("phishing", "incident", "vulnerability"))]},
            "det": lambda f: (f"There are {f['Open cases']} open cases ({f['Open cases by domain']}); {f['Actions awaiting approval']} actions await "
                              f"approval and the automation rate is {f['Automation rate']}. {f['Open correlated insights']} correlated findings are open.")}


def src_vm(c: Ctx) -> dict:
    m = c.vm().metrics()
    facts: Facts = [("Open findings", m["open"]), ("KEV-listed open findings", m["kev_open"]),
                    ("Internet-exposed open findings", m["internet_exposed_open"]), ("Findings past SLA", m["sla_breached"]),
                    ("Mean time to remediate (days)", m.get("mttr_days")), ("Asset match rate", _pct(m.get("asset_match_rate"))),
                    ("Priority mix", ", ".join(f"{k} {v}" for k, v in sorted(m["by_priority"].items())))]
    rows = [[t, v.get("open", 0), v.get("sla_breached", 0)] for t, v in sorted(m.get("per_team", {}).items())]
    return {"facts": facts, "table": {"header": ["Team", "Open", "Past SLA"], "rows": rows}, "domain": "vulnerability",
            "det": lambda f: (f"{f['Open findings']} vulnerability findings are open ({f['Priority mix']}); {f['KEV-listed open findings']} are "
                              f"known-exploited (CISA KEV), {f['Internet-exposed open findings']} sit on internet-exposed assets and "
                              f"{_n(f['Findings past SLA'], 'is', 'are')} past SLA.")}


def src_vm_top(c: Ctx) -> dict:
    from soc_platform.domains.vulnerability.models import ConsolidatedFinding

    fs = sorted(c.s.execute(select(ConsolidatedFinding).where(ConsolidatedFinding.status.in_(("open", "reopened")))).scalars(),
                key=lambda f: -f.priority_score)[:10]
    facts: Facts = [(f"{f.cve} on {f.asset_name}", f"{f.priority_band}, owner {f.platform_team or 'unknown'}, SLA {f.sla_due.date() if f.sla_due else 'n/a'}"
                     + (", internet-exposed" if f.internet_exposed else "")) for f in fs]
    return {"facts": facts or [("Open findings", 0)], "domain": "vulnerability",
            "table": {"header": ["Priority", "CVE", "Asset", "Owner", "SLA due"],
                      "rows": [[f.priority_band, f.cve, f.asset_name, f.platform_team or "unknown", f.sla_due.date() if f.sla_due else ""] for f in fs]},
            "det": lambda f: "Top priorities: " + "; ".join(f"{k} ({v})" for k, v in list(f.items())[:4]) + "."}


def src_misconfig(c: Ctx) -> dict:
    from soc_platform.domains.vulnerability.misconfig import MisconfigurationService

    svc = MisconfigurationService(c.s, c.reg)
    m, items = svc.metrics(), svc.list()
    facts: Facts = [("Open cloud misconfigurations", m["open"]), ("Past SLA", m["overdue"]), ("False closures detected", m["false_closures"]),
                    ("By severity", ", ".join(f"{k} {v}" for k, v in m["by_severity"].items()) or "none")]
    return {"facts": facts, "domain": "vulnerability",
            "table": {"header": ["Severity", "Rule", "Resource", "Owner", "Status"],
                      "rows": [[x["severity"], x["rule"], x["resource"], x["platform_team"] or "unknown", x["status"]] for x in items[:10]]},
            "det": lambda f: (f"{f['Open cloud misconfigurations']} cloud misconfigurations are open ({f['By severity']}); {f['Past SLA']} past SLA "
                              f"and {f['False closures detected']} claimed fixes were not confirmed by Wiz.")}


def src_phishing(c: Ctx) -> dict:
    from soc_platform.domains.phishing.service import PhishingService

    p = PhishingService(c.s, c.reg).metrics()
    ttc = p["time_to_containment_minutes"]
    facts: Facts = [("Emails reported by users (all verdicts, not all phishing)", p["reported"]),
                    ("Verdicts of the reported emails", ", ".join(f"{k} {v}" for k, v in p["verdict_mix"].items()) or "none"),
                    ("Reports auto-closed as clearly benign", p["auto_closed"]),
                    ("Auto-closed reports sampled for QA review", p["sampled_for_qa"]),
                    ("Distinct phishing campaigns (malicious or suspicious reports only)", p["campaigns"]),
                    ("Users who clicked in more than one campaign", len(p["repeat_clickers"])),
                    ("Median minutes from report to containment", ttc["median"] if ttc["median"] is not None
                     else "not measured yet (no containment action executed)")]
    return {"facts": facts, "domain": "phishing",
            "table": {"header": ["User", "Clicks"], "rows": sorted(([u, n] for u, n in p["clickers"].items()), key=lambda r: -r[1])[:10]},
            "det": lambda f: (f"Users reported {_n(f['Emails reported by users (all verdicts, not all phishing)'], 'email')} "
                              f"({f['Verdicts of the reported emails']}); {_n(f['Distinct phishing campaigns (malicious or suspicious reports only)'], 'phishing campaign')} "
                              f"identified and {_n(f['Users who clicked in more than one campaign'], 'user')} clicked in more than one campaign.")}


def src_suppliers(c: Ctx) -> dict:
    from soc_platform.domains.phishing.supplier import SupplierMonitor

    r = SupplierMonitor(c.s).assess(days=c.days)
    facts: Facts = [(f"Supplier {n}", f"{v['status']} ({len(v['findings'])} finding(s))") for n, v in r["suppliers"].items()]
    return {"facts": facts or [("Suppliers configured", 0)], "domain": "phishing",
            "table": {"header": ["Supplier", "Finding", "Severity", "Detail"],
                      "rows": [[f["supplier"], f["type"].replace("supplier_", ""), f["severity"], f["detail"][:90]] for f in r["findings"][:10]]},
            "det": lambda f: "Supplier email risk: " + "; ".join(f"{k.replace('Supplier ', '')} {v}" for k, v in f.items()) + "."}


def src_incidents(c: Ctx) -> dict:
    from soc_platform.domains.incident.service import IncidentService

    h = IncidentService(c.s, c.reg).handover(hours=24 * c.days)
    open_cases = [x for x in c.s.execute(select(Case).where(Case.domain == "incident", Case.status != "closed")).scalars()]
    facts: Facts = [("Open incidents", h["open_total"]), ("By severity", ", ".join(f"{k} {v}" for k, v in h["open_by_severity"].items()) or "none"),
                    ("Awaiting approval", len(h["awaiting_approval"])), ("Closed in period", h["closed_this_shift"])]
    return {"facts": facts, "domain": "incident",
            "table": {"header": ["Severity", "Incident", "Status"], "rows": [[x.severity, x.title, x.status] for x in open_cases[:10]]},
            "det": lambda f: (f"{f['Open incidents']} incidents are open ({f['By severity']}); {f['Awaiting approval']} have actions awaiting "
                              f"approval and {f['Closed in period']} were closed in the period.")}


def src_stories(c: Ctx) -> dict:
    from soc_platform.intelligence.story import story_for_case

    crit = [x for x in c.s.execute(select(Case).where(Case.severity.in_(("critical", "high")), Case.status != "closed")).scalars()]
    seen, facts, rows = set(), [], []
    for case in sorted(crit, key=lambda x: x.severity != "critical"):
        st = story_for_case(c.s, case.id, c.reg)
        if st["fingerprint"] in seen or not st["steps"]:
            continue
        seen.add(st["fingerprint"])
        facts.append((f"Attack story: {case.title}", st["summary"]))
        rows.append([st["assessment"]["label"], case.title, len(st["steps"]), ", ".join(st["tools"][:5])])
        if len(facts) >= 4:
            break
    return {"facts": facts or [("Attack stories", "no critical or high attack activity")], "domain": "*",
            "table": {"header": ["Assessment", "Case", "Steps", "Tools"], "rows": rows},
            "det": lambda f: " ".join(str(v) for v in f.values())}


def src_story_case(c: Ctx) -> dict:
    from soc_platform.intelligence.story import story_for_case

    if not c.case_id:
        return {"facts": [("Case", "no case selected")], "table": {"header": [], "rows": []}, "det": lambda f: "No case selected."}
    st = story_for_case(c.s, c.case_id, c.reg)
    facts: Facts = [("Assessment", f"{st['assessment']['label']} ({st['assessment']['confidence']}): {st['assessment']['reason']}"),
                    ("Summary", st["summary"])]
    facts += [(f"Step {s['n']} {s['stage_name']}", f"{s['start'] or 'time n/a'} {s['title']} ({s['outcome']}; {', '.join(s['tools'])})") for s in st["steps"]]
    facts += [(f"Explanation tested: {h['hypothesis']}", f"{h['status']} - {h['reasoning']}") for h in st["hypotheses"]]
    facts += [(f"Gap: {g['stage_name']}", g["text"]) for g in st["gaps"]]
    return {"facts": facts, "domain": None,
            "table": {"header": ["When", "Stage", "What happened", "Outcome", "Tools"],
                      "rows": [[(s["start"] or "")[:16].replace("T", " "), s["stage_name"], s["title"][:80], s["outcome"], ", ".join(s["tools"])] for s in st["steps"]]},
            "det": lambda f: f["Summary"]}


def src_insights(c: Ctx) -> dict:
    from soc_platform.intelligence.models import Insight

    allins = list(c.s.execute(select(Insight).where(Insight.status.in_(("new", "acknowledged"))).order_by(Insight.score.desc())).scalars())
    ins = allins[:8]
    facts: Facts = [("Open correlated findings", len(allins))] + [(i.title, f"{i.severity} ({i.rule})") for i in ins]
    return {"facts": facts, "domain": "*",
            "table": {"header": ["Severity", "Finding", "Rule"], "rows": [[i.severity, i.title, i.rule] for i in ins]},
            "det": lambda f: (f"{len(allins)} correlated findings are open; the most serious: " + "; ".join(list(f)[1:4]) + ".") if ins else "No correlated findings are open."}


def src_risk(c: Ctx) -> dict:
    from soc_platform.intelligence.risk import RiskEngine

    top = RiskEngine(c.s).top(None, 8)
    facts: Facts = [(p.name, f"risk {p.score:.0f}/100 ({p.band}) across {', '.join(p.dimensions)}") for p in top]
    return {"facts": facts or [("Risky entities", 0)], "domain": "*",
            "table": {"header": ["User / host", "Risk", "Band", "Dimensions"], "rows": [[p.name, round(p.score), p.band, ", ".join(p.dimensions)] for p in top]},
            "det": lambda f: "Highest-risk users and hosts: " + "; ".join(f"{k} ({v.split(' across')[0]})" for k, v in list(f.items())[:4]) + "."}


def src_coverage(c: Ctx) -> dict:
    from soc_platform.intelligence.attack_coverage import coverage

    cov = coverage(c.s, c.reg.enabled_names())
    s = cov["summary"]
    facts: Facts = [("Weighted ATT&CK coverage", f"{s['weighted_coverage_pct']}%"), ("Techniques covered", f"{s['covered']} of {s['techniques']}"),
                    ("Priority blind spots", s["priority_blind_spots"]), ("Single-source priority techniques", s["single_source_priority"]),
                    ("Techniques observed firing", s["firing"])]
    return {"facts": facts, "domain": None,
            "table": {"header": ["Blind spot", "Technique"], "rows": [[b["technique"], b["name"]] for b in cov["priority_blind_spots"]]
                      or [[x["technique"], f"only {', '.join(x['only'])}"] for x in cov["single_source_priority"]]},
            "det": lambda f: (f"Detection coverage is {f['Weighted ATT&CK coverage']} ({f['Techniques covered']} techniques) with "
                              f"{f['Priority blind spots']} priority blind spots and {f['Single-source priority techniques']} techniques relying on one tool.")}


def src_shadow(c: Ctx) -> dict:
    from soc_platform.intelligence.shadow_it import shadow_it_report

    r = shadow_it_report(c.reg, since=f"-{min(c.days, 30)}days")
    if not r.get("available"):
        return {"facts": [("Shadow IT", r.get("reason"))], "table": {"header": [], "rows": []}, "det": lambda f: f["Shadow IT"], "domain": "incident"}
    s = r["summary"]
    facts: Facts = [("Unsanctioned services", s["unsanctioned_services"]), ("High-risk services", s["high_risk_services"]),
                    ("Users on unsanctioned services", s["users_on_unsanctioned_services"]), ("Risky destinations reached", s["risky_destinations_reached"])]
    return {"facts": facts, "domain": "incident",
            "table": {"header": ["Service", "Risk", "Users", "Requests"], "rows": [[x["service"], x["risk"], x["users"], x["requests"]] for x in r["unsanctioned_services"][:10]]},
            "det": lambda f: (f"{f['Unsanctioned services']} unsanctioned services are in use by {f['Users on unsanctioned services']} users "
                              f"({f['High-risk services']} high-risk); {f['Risky destinations reached']} risky destinations were reached.")}


def src_compliance(c: Ctx) -> dict:
    from soc_platform.config import get_settings
    from soc_platform.reporting.compliance import build_evidence

    ev = build_evidence(c.s, get_settings(), period_days=c.days)
    facts: Facts = [("Control tests passed", f"{ev['summary']['passed']} of {ev['summary']['tests']}")]
    facts += [(t["test"], f"{t['result']} - {t['detail']}") for ctl in ev["controls"] for t in ctl["tests"] if t["result"] == "fail"]
    return {"facts": facts, "domain": "*",
            "table": {"header": ["Control", "Test", "Result"], "rows": [[ctl["control"][:40], t["test"], t["result"]] for ctl in ev["controls"] for t in ctl["tests"]]},
            "det": lambda f: f"{f['Control tests passed']} control tests passed." + (" Failures: " + "; ".join(k for k in list(f)[1:]) + "." if len(f) > 1 else "")}


def src_drift(c: Ctx) -> dict:
    from soc_platform.intelligence.drift import drift_report

    d = drift_report(c.s)
    facts: Facts = [(f"{k.title()} verdict quality", f"{v['status']}; agreement {v['agreement']['recent']}; PSI {v['psi_verdicts']}") for k, v in d["domains"].items()]
    return {"facts": facts, "domain": "*", "table": {"header": [], "rows": []},
            "det": lambda f: "Verdict quality against analyst decisions: " + "; ".join(f"{k}: {v.split(';')[0]}" for k, v in f.items()) + "."}


def src_connectors(c: Ctx) -> dict:
    from soc_platform.api.dashboards import connector_freshness

    cs = connector_freshness(c.s, c.reg)
    bad = [x for x in cs if x["enabled"] and x["state"] in {"error", "stale", "misconfigured"}]
    facts: Facts = [("Enabled connectors", sum(1 for x in cs if x["enabled"])), ("Connectors needing attention", len(bad))]
    facts += [(x["tool"], x["state"]) for x in bad]
    return {"facts": facts, "domain": None, "table": {"header": ["Tool", "State"], "rows": [[x["tool"], x["state"]] for x in cs if x["enabled"]]},
            "det": lambda f: f"{f['Enabled connectors']} connectors are enabled; {f['Connectors needing attention']} need attention."}


SOURCES: dict[str, tuple[str, str, Callable[[Ctx], dict]]] = {
    "overview": ("SOC overview", "cases, approvals, automation rate, trend", src_overview),
    "vulnerability_posture": ("Vulnerability posture", "open findings, KEV, exposure, SLA, per team", src_vm),
    "top_vulnerabilities": ("Top vulnerabilities", "highest-priority findings with owners", src_vm_top),
    "cloud_misconfigurations": ("Cloud misconfigurations", "Wiz issues, SLA, false closures", src_misconfig),
    "phishing": ("Reported phishing", "volume, verdicts, campaigns, clickers, containment", src_phishing),
    "supplier_risk": ("Supplier email risk", "vendor compromise, impersonation, payment diversion", src_suppliers),
    "incidents": ("Incidents", "open incidents by severity, approvals, closures", src_incidents),
    "attack_stories": ("Attack stories", "reconstructed chains for critical/high cases", src_stories),
    "case_story": ("Incident narrative", "attack story of one case (post-incident report)", src_story_case),
    "correlated_findings": ("Correlated findings", "cross-domain insights", src_insights),
    "risk": ("Highest-risk users and hosts", "explainable fused risk", src_risk),
    "detection_coverage": ("Detection coverage", "ATT&CK coverage and blind spots", src_coverage),
    "shadow_it": ("Shadow IT", "unsanctioned services and risky destinations", src_shadow),
    "compliance": ("Control evidence", "compliance control tests", src_compliance),
    "verdict_quality": ("Verdict quality", "agreement with analysts, drift", src_drift),
    "integrations": ("Integration health", "connector freshness", src_connectors),
}

STANDARD: dict[str, dict[str, Any]] = {
    "board_monthly": {"title": "Monthly security report to the board", "audience": "board", "format": "pptx", "days": 30,
                      "description": "Business-level risk, incidents, exposure and control health for directors.",
                      "sections": [{"source": "overview", "instruction": "Headline the overall security posture in business terms."},
                                   {"source": "attack_stories", "instruction": "Explain the most serious attacks and their business impact without jargon."},
                                   {"source": "vulnerability_posture", "instruction": "Summarise exposure and whether remediation is on track."},
                                   {"source": "phishing", "instruction": "Describe the phishing threat and user behaviour."},
                                   {"source": "supplier_risk", "instruction": "Flag any third-party risk the board should know about."},
                                   {"source": "compliance", "instruction": "State control assurance in one or two sentences."}]},
    "ciso_weekly": {"title": "CISO weekly brief", "audience": "CISO", "format": "docx", "days": 7,
                    "description": "What happened this week, what needs a decision, where we are exposed.",
                    "sections": [{"source": "overview", "instruction": "Lead with what changed and what needs a decision."},
                                 {"source": "correlated_findings", "instruction": "Prioritise the correlated findings."},
                                 {"source": "attack_stories", "instruction": "Summarise each attack story in two sentences."},
                                 {"source": "risk", "instruction": "Name who and what needs attention first and why."},
                                 {"source": "detection_coverage", "instruction": "Call out blind spots worth investing in."},
                                 {"source": "integrations", "instruction": "Note any data-source problems affecting confidence."}]},
    "vm_weekly": {"title": "Weekly vulnerability management report", "audience": "platform teams and IT leadership", "format": "docx", "days": 7,
                  "description": "Exposure, priorities, owners, SLA and cloud misconfigurations.",
                  "sections": [{"source": "vulnerability_posture", "instruction": "Summarise exposure and SLA performance."},
                               {"source": "top_vulnerabilities", "instruction": "Explain why the top items are prioritised and who owns them."},
                               {"source": "cloud_misconfigurations", "instruction": "Summarise cloud posture and false closures."}]},
    "phishing_monthly": {"title": "Monthly phishing and awareness report", "audience": "security awareness and HR", "format": "docx", "days": 30,
                         "description": "Reported mail, campaigns, repeat clickers and supplier risk.",
                         "sections": [{"source": "phishing", "instruction": "Describe the month's phishing activity and response speed."},
                                      {"source": "supplier_risk", "instruction": "Summarise supplier impersonation and payment-fraud attempts."},
                                      {"source": "risk", "instruction": "Identify users who need targeted awareness, without blame."}]},
    "incident_postmortem": {"title": "Post-incident report", "audience": "incident review board", "format": "docx", "days": 30, "needs_case": True,
                            "description": "Timeline, root cause, what worked, gaps and actions for one incident.",
                            "sections": [{"source": "case_story", "instruction": "Write the incident narrative: what happened, how it was detected, impact, what was tested and ruled out, gaps, and follow-up actions."}]},
    "compliance_quarterly": {"title": "Quarterly control assurance report", "audience": "audit and risk committee", "format": "docx", "days": 90,
                             "description": "Control tests, verdict quality and integration health.",
                             "sections": [{"source": "compliance", "instruction": "Report control test results and any failures with remediation."},
                                          {"source": "verdict_quality", "instruction": "Explain how AI verdict quality is monitored and its current state."},
                                          {"source": "integrations", "instruction": "State data-source health."}]},
    "soc_daily": {"title": "SOC daily situation report", "audience": "SOC team", "format": "docx", "days": 1,
                  "description": "Queue, approvals, top findings and shadow IT for the shift.",
                  "sections": [{"source": "incidents", "instruction": "Summarise the queue and what needs approval."},
                               {"source": "correlated_findings", "instruction": "List what to look at first."},
                               {"source": "shadow_it", "instruction": "Note any risky destinations reached."}]},
}

# topic keywords (regex) -> sources; audience keywords only add defaults when the request names no topic
KEYWORDS: list[tuple[str, list[str]]] = [
    (r"vuln|patch|cve|exposure", ["vulnerability_posture", "top_vulnerabilities"]), (r"cloud|wiz|misconfig", ["cloud_misconfigurations"]),
    (r"phish|e-?mail|click", ["phishing"]), (r"supplier|vendor|third[- ]party|payment fraud", ["supplier_risk"]),
    (r"incident|breach|intrusion", ["incidents", "attack_stories"]), (r"attack|story|compromise", ["attack_stories"]),
    (r"risky|highest[- ]risk|user risk|insider", ["risk"]), (r"coverage|att&?ck|mitre|blind ?spot|detection", ["detection_coverage"]),
    (r"shadow|saas|unsanctioned", ["shadow_it"]), (r"complian|audit|control|iso|soc ?2|nist", ["compliance"]),
    (r"quality|drift|accuracy", ["verdict_quality"]), (r"connector|integration|data source", ["integrations"]),
    (r"insight|correlat|cross[- ]domain", ["correlated_findings"]), (r"overview|posture|summary|headline", ["overview"]),
]
AUDIENCE_DEFAULTS: list[tuple[str, list[str]]] = [
    (r"board|director|exec", ["overview", "attack_stories", "vulnerability_posture", "compliance"]),
    (r"ciso|leadership", ["overview", "correlated_findings", "risk"]), (r"soc|analyst|shift", ["incidents", "correlated_findings"]),
]


def list_templates(session: Session) -> list[dict[str, Any]]:
    from soc_platform.reporting.models import ReportTemplate

    out = [{"id": k, "standard": True, **v} for k, v in STANDARD.items()]
    for t in session.execute(select(ReportTemplate).order_by(ReportTemplate.created_at.desc())).scalars():
        out.append({**t.spec, "id": t.id, "title": t.title, "standard": False, "created_by": t.created_by})
    return out


def get_template(session: Session, tid: str) -> dict[str, Any] | None:
    from soc_platform.reporting.models import ReportTemplate

    if tid in STANDARD:
        return {"id": tid, **STANDARD[tid]}
    t = session.get(ReportTemplate, tid)
    return {**t.spec, "id": t.id, "title": t.title} if t else None


def validate_spec(spec: dict[str, Any]) -> dict[str, Any]:
    """Normalise a user- or LLM-provided spec: catalogue sources only, bounded sizes."""
    secs = [{"source": x["source"], "title": str(x.get("title") or SOURCES[x["source"]][0])[:120],
             "instruction": str(x.get("instruction") or "")[:500]}
            for x in (spec.get("sections") or []) if isinstance(x, dict) and x.get("source") in SOURCES][:10]
    if not secs:
        raise ValueError("a report needs at least one section from the catalogue")
    days = spec.get("days")
    return {"title": str(spec.get("title") or "Custom report")[:160], "audience": str(spec.get("audience") or "security leadership")[:80],
            "format": spec.get("format") if spec.get("format") in {"docx", "pptx"} else "docx",
            "days": max(1, min(int(days), 365)) if isinstance(days, int) or str(days).isdigit() else 30,
            "description": str(spec.get("description") or spec.get("request") or "")[:300], "sections": secs,
            "needs_case": any(x["source"] == "case_story" for x in secs)}


def catalogue() -> list[dict[str, str]]:
    return [{"id": k, "title": v[0], "description": v[1]} for k, v in SOURCES.items()]


# ---------------------------------------------------------------------------------------------- planning
PLAN_SYSTEM = ("You design security reports. Choose sections ONLY from the catalogue by id. Keep the number of sections "
               "proportional to the request (one-page = 2-3 sections). Respond with JSON only.")


def plan_report(request: str, llm: LLMGateway | None) -> dict[str, Any]:
    """Turn a plain-language request into a spec using catalogue sources only."""
    req = request.strip()[:1500]
    days = 7 if re.search(r"\b(week|weekly|7 days)\b", req, re.I) else 1 if re.search(r"\b(today|daily|24 ?h)\b", req, re.I) else \
        90 if re.search(r"\b(quarter|quarterly|90 days)\b", req, re.I) else 30
    fmt = "pptx" if re.search(r"\b(deck|slides|presentation|pptx|powerpoint)\b", req, re.I) else "docx"
    if llm is not None:
        cat = "\n".join(f"- {k}: {v[0]} ({v[1]})" for k, v in SOURCES.items() if k != "case_story")
        try:
            data = llm.complete_json("report.plan", PLAN_SYSTEM,
                                     f"CATALOGUE:\n{cat}\n\nREQUEST: {req}\n\nReturn JSON: "
                                     '{"title": "...", "audience": "...", "format": "docx|pptx", "days": 30, '
                                     '"sections": [{"source": "<catalogue id>", "title": "...", "instruction": "..."}]}', tier="small")
        except BudgetExceeded:
            data = None
        if data:
            secs = [{"source": s.get("source"), "title": str(s.get("title") or SOURCES[s["source"]][0])[:120],
                     "instruction": str(s.get("instruction") or "")[:500]}
                    for s in data.get("sections") or [] if isinstance(s, dict) and s.get("source") in SOURCES and s.get("source") != "case_story"]
            if secs:
                return {"title": str(data.get("title") or req[:80])[:160], "audience": str(data.get("audience") or "security leadership")[:80],
                        "format": data.get("format") if data.get("format") in {"docx", "pptx"} else fmt,
                        "days": int(data.get("days") or days) if str(data.get("days") or "").isdigit() else days,
                        "sections": secs[:8], "planner": "llm", "request": req}
    low = req.lower()
    chosen: list[str] = []
    for rx, srcs in KEYWORDS:
        if re.search(rx, low):
            chosen += [x for x in srcs if x not in chosen]
    if not chosen:
        chosen = next((srcs for rx, srcs in AUDIENCE_DEFAULTS if re.search(rx, low)), ["overview", "correlated_findings", "risk"])
    elif re.search(r"board|director|exec", low) and "overview" not in chosen:
        chosen = ["overview"] + chosen                                   # boards always get the headline first
    if re.search(r"one[- ]page|brief|short|summary|quick", low):
        chosen = chosen[:3]
    audience = next((a for a in ("board", "CISO", "auditor", "SOC team", "IT") if a.lower() in req.lower()), "security leadership")
    return {"title": req[:1].upper() + req[1:80], "audience": audience, "format": fmt, "days": days, "planner": "rules", "request": req,
            "sections": [{"source": s, "title": SOURCES[s][0], "instruction": f"Summarise {SOURCES[s][1]} for the {audience}."} for s in chosen[:8]]}


# ---------------------------------------------------------------------------------------------- writing
WRITE_RULES = ("Write the section for the stated audience in clear prose (2-5 sentences). Use ONLY the facts provided; "
               "cite fact ids (F#) for every sentence; do not invent numbers.")


def _narrate(llm: LLMGateway | None, spec: dict, section: dict, data: dict) -> dict[str, Any]:
    facts = [(k, "not available" if v is None else v) for k, v in data["facts"]]
    data["facts"] = facts
    evidence = [{"id": f"F{i}", "claim": f"{k}: {v}", "source": section["source"]} for i, (k, v) in enumerate(facts, 1)]
    fdict = {k: v for k, v in facts}
    if llm is not None:
        q = (f"Report '{spec['title']}' for {spec['audience']}. Section '{section.get('title') or SOURCES[section['source']][0]}'. "
             f"Instruction: {section.get('instruction') or 'summarise'}. {WRITE_RULES}")
        g = llm.grounded(f"report.section.{section['source']}", q, evidence, tier="large")
        if g.get("source") == "llm" and g.get("claims"):
            return {"text": " ".join(f"{c['text']} [{', '.join(c['evidence_ids'])}]" for c in g["claims"]), "source": "llm",
                    "evidence": evidence}
    try:
        text = data["det"](fdict)
    except (KeyError, TypeError, IndexError):
        text = "; ".join(f"{k}: {v}" for k, v in facts[:5]) + "."
    return {"text": text, "source": "deterministic", "evidence": evidence}


# ---------------------------------------------------------------------------------------------- rendering
def _docx(path: Path, spec: dict, sections: list[dict], meta: dict) -> None:
    d = Document()
    d.styles["Normal"].font.name = "Calibri"
    d.styles["Normal"].font.size = Pt(10.5)
    d.add_heading(spec["title"], 0)
    p = d.add_paragraph(f"Audience: {spec['audience']} · Period: last {spec['days']} day(s) · Generated {meta['at']} UTC")
    p.runs[0].font.color.rgb = RGBColor(0x55, 0x5f, 0x6d)
    for s in sections:
        d.add_heading(s["title"], level=1)
        d.add_paragraph(s["narrative"]["text"])
        tbl = s["data"]["table"]
        if tbl["header"] and tbl["rows"]:
            t = d.add_table(rows=1, cols=len(tbl["header"]))
            t.style = "Light Grid Accent 1"
            for i, h in enumerate(tbl["header"]):
                t.rows[0].cells[i].text = str(h)
            for r in tbl["rows"][:25]:
                cells = t.add_row().cells
                for i, v in enumerate(r):
                    cells[i].text = "" if v is None else str(v)
    d.add_heading("Evidence", level=1)
    for s in sections:
        for e in s["narrative"]["evidence"]:
            para = d.add_paragraph(f"{s['source']}·{e['id']}  {e['claim']}")
            para.runs[0].font.size = Pt(8)
    foot = d.add_paragraph(f"Figures are computed from the platform's records; narrative: {meta['writer']}. "
                           "Every narrative sentence cites the facts above (F#).")
    foot.runs[0].font.size = Pt(8)
    d.save(path)


def _pptx(path: Path, spec: dict, sections: list[dict], meta: dict) -> None:
    prs = Presentation()
    prs.slide_width, prs.slide_height = Inches(13.333), Inches(7.5)
    title = prs.slides.add_slide(prs.slide_layouts[0])
    title.shapes.title.text = spec["title"]
    title.placeholders[1].text = f"{spec['audience']} · last {spec['days']} day(s) · {meta['at']} UTC"
    for s in sections:
        sl = prs.slides.add_slide(prs.slide_layouts[5])
        sl.shapes.title.text = s["title"]
        box = sl.shapes.add_textbox(Inches(0.6), Inches(1.4), Inches(6.2), Inches(5.4)).text_frame
        box.word_wrap = True
        box.text = s["narrative"]["text"]
        for para in box.paragraphs:
            for r in para.runs:
                r.font.size = PPt(15)
        facts = s["data"]["facts"][:7]
        fb = sl.shapes.add_textbox(Inches(7.1), Inches(1.4), Inches(5.7), Inches(5.4)).text_frame
        fb.word_wrap = True
        fb.text = "Key figures"
        fb.paragraphs[0].runs[0].font.bold = True
        for k, v in facts:
            para = fb.add_paragraph()
            para.text = f"{k}: {v}"[:160]
            for r in para.runs:
                r.font.size = PPt(12)
    end = prs.slides.add_slide(prs.slide_layouts[5])
    end.shapes.title.text = "About this report"
    tb = end.shapes.add_textbox(Inches(0.6), Inches(1.5), Inches(12), Inches(3)).text_frame
    tb.word_wrap = True
    tb.text = (f"Figures computed from the SOC platform's records. Narrative: {meta['writer']}; every statement cites the "
               "figures it rests on. Generated by the SOC platform.")
    prs.save(path)


# ---------------------------------------------------------------------------------------------- build
def build_report(session: Session, registry: Any, spec: dict, out_dir: str | Path, *, llm: LLMGateway | None, by: str,
                 domains: frozenset[str] = frozenset({"*"}), case_id: str | None = None,
                 denied_sources: frozenset[str] = frozenset()) -> dict[str, Any]:
    from soc_platform.core.audit import AuditLog
    from soc_platform.core.crypto import seal_file
    from soc_platform.domains.vulnerability.models import ReportRun

    ctx = Ctx(session, registry, days=int(spec.get("days") or 30), case_id=case_id, domains=domains)
    built, skipped, used = [], [], set()
    for sec in spec["sections"]:
        if sec["source"] not in SOURCES:
            skipped.append({"source": sec["source"], "reason": "unknown source"})
            continue
        if sec["source"] in denied_sources:
            skipped.append({"source": sec["source"], "reason": "your role cannot include this data"})
            continue
        data = SOURCES[sec["source"]][2](ctx)
        dom = data.get("domain")
        if dom == "*" and "*" not in domains or dom not in (None, "*") and not ("*" in domains or dom in domains):
            skipped.append({"source": sec["source"], "reason": "outside your data scope"})
            continue
        if dom:
            used.add(dom)
        narrative = _narrate(llm, spec, sec, data)
        built.append({"source": sec["source"], "title": sec.get("title") or SOURCES[sec["source"]][0], "data": data, "narrative": narrative})
    writers = {s["narrative"]["source"] for s in built}
    meta = {"at": f"{utcnow():%Y-%m-%d %H:%M}",
            "writer": ("LLM (" + (llm.provider.name if llm else "") + "), grounded on computed facts") if "llm" in writers else "deterministic templates"}
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    slug = re.sub(r"[^a-z0-9]+", "_", spec["title"].lower()).strip("_")[:40] or "report"
    path = out / f"{slug}_{utcnow():%Y%m%d_%H%M%S}.{spec.get('format', 'docx')}"
    (_pptx if spec.get("format") == "pptx" else _docx)(path, spec, built, meta)
    seal_file(path)
    run = ReportRun(kind=f"custom:{spec.get('id') or slug}", path=str(path),
                    metrics={"sections": len(built), "writer": meta["writer"], "skipped": skipped, "domains": sorted(used), "scope": sorted(domains),
                             "case_id": case_id, "title": spec["title"]}, generated_by=by)
    session.add(run)
    session.flush()
    AuditLog(session).append(actor_type="human" if not by.startswith("agent:") else "agent", actor_id=by, event_type="report.built",
                             subject_type="report", subject_id=run.id,
                             payload={"title": spec["title"], "sections": [s["source"] for s in built], "writer": meta["writer"],
                                      "planner": spec.get("planner"), "skipped": skipped})
    return {"id": run.id, "title": spec["title"], "format": spec.get("format", "docx"), "writer": meta["writer"], "skipped": skipped,
            "sections": [{"source": s["source"], "title": s["title"], "narrative": s["narrative"]["text"], "writer": s["narrative"]["source"],
                          "facts": [[k, str(v)] for k, v in s["data"]["facts"][:12]]} for s in built]}
