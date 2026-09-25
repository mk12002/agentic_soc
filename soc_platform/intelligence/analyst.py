"""LLM intelligence analyst over every data stream (IM-F06, IM-F11, VM-F15, U05, U07, U12, U13).

The model is an analyst, never an actor:
  * it only sees evidence the platform retrieved (insights, risk factors, tool results)
  * it can *request* read-only tools from a fixed catalogue; the platform executes them (no SQL, no actions)
  * every claim must cite a result id (R1, R2...) or it is dropped (gateway grounding)
  * the tool calls it made are returned to the analyst for verification
Without a configured model, a deterministic planner and fact-list answers provide the same interface.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Callable

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from soc_platform.core.context_store import ContextStore
from soc_platform.core.models import ActionRequest, Case, Entity
from soc_platform.intelligence.correlation import CorrelationEngine
from soc_platform.intelligence.models import Insight
from soc_platform.intelligence.risk import RiskEngine
from soc_platform.llm.gateway import BudgetExceeded, LLMGateway

PLANNER_SYSTEM = (
    "You are a SOC investigation planner. Choose read-only tools to answer the analyst's question. "
    "Use only tools from the catalogue, with the documented arguments. Prefer the fewest calls that fully "
    "answer the question (max 5). Return JSON: {\"calls\": [{\"tool\": \"name\", \"args\": {...}}]}.")


@dataclass
class ToolSpec:
    name: str
    args: str
    description: str
    fn: Callable[..., Any]


class IntelligenceAnalyst:
    def __init__(self, session: Session, llm: LLMGateway | None = None, *, vm: Any = None) -> None:
        self.s = session
        self.llm = llm
        self.store = ContextStore(session)
        self.risk = RiskEngine(session)
        self.vm = vm
        self.tools: dict[str, ToolSpec] = {t.name: t for t in [
            ToolSpec("find_entity", "kind: asset|identity|indicator, key: upn|email|hostname|crowdstrike_aid|"
                     "mde_device_id|domain|ip|url|sha256, value", "Resolve a user, host or indicator.", self._find),
            ToolSpec("search_entities", "text", "Search users/hosts/indicators by name fragment.", self._search),
            ToolSpec("entity_risk", "entity_id", "Fused risk score with every contributing signal.", self._entity_risk),
            ToolSpec("entity_timeline", "entity_id", "Chronological events across all tools.", self._timeline),
            ToolSpec("top_risky", "kind: asset|identity (optional), limit", "Riskiest users/hosts.", self._top_risky),
            ToolSpec("list_insights", "severity (optional), rule (optional)", "Cross-domain correlations.",
                     self._list_insights),
            ToolSpec("search_cases", "text (optional), domain (optional), status (optional)",
                     "Incidents and phishing cases.", self._search_cases),
            ToolSpec("case_summary", "case_id", "Summary, verdict, MITRE and actions of a case.", self._case_summary),
            ToolSpec("vulnerability_query", "question", "Vulnerability findings in natural language.", self._vm_query),
            ToolSpec("affected_devices", "cve", "Assets affected by a CVE with owners.", self._affected),
            ToolSpec("pending_approvals", "", "Actions waiting for analyst approval.", self._pending),
            ToolSpec("attack_story", "case_id", "Reconstructed cross-tool attack chain, gaps, reach and plan for a case.",
                     self._attack_story),
            ToolSpec("entity_context", "entity_id", "Cases, correlated findings and pending actions for a user/host.",
                     self._entity_context),
        ]}

    # ------------------------------------------------------------------ tools (read-only)

    def _entity_brief(self, e: Entity) -> dict[str, Any]:
        return {"entity_id": e.id, "kind": e.kind, "name": e.display_name,
                "keys": self.store.keys_of(e.id), "last_seen": e.last_seen.isoformat()}

    def _find(self, kind: str = "identity", key: str = "upn", value: str = "") -> Any:
        if kind == "asset" and key == "hostname":
            return self._search(value)
        e = self.store.find(kind, key, value)
        return self._entity_brief(e) if e else {"not_found": f"{kind} {key}={value}"}

    def _search(self, text: str = "") -> Any:
        t = f"%{text.lower()}%"
        rows = self.s.execute(select(Entity).where(Entity.kind.in_(("asset", "identity", "indicator")),
                                                   or_(Entity.display_name.ilike(t), Entity.canonical_key.ilike(t)))
                              .limit(10)).scalars().all()
        return [self._entity_brief(e) for e in rows]

    def _entity_risk(self, entity_id: str = "") -> Any:
        p = self.risk.profile(entity_id)
        return p.as_dict() if p else {"not_found": entity_id}

    def _timeline(self, entity_id: str = "") -> Any:
        return self.store.timeline([entity_id])[-40:]

    def _top_risky(self, kind: str | None = None, limit: int = 5) -> Any:
        return [{"entity_id": p.entity_id, "name": p.name, "kind": p.kind, "score": p.score, "band": p.band,
                 "dimensions": p.dimensions} for p in self.risk.top(kind or None, int(limit or 5))]

    def _list_insights(self, severity: str | None = None, rule: str | None = None) -> Any:
        q = select(Insight).where(Insight.status != "dismissed").order_by(Insight.score.desc()).limit(20)
        if severity:
            q = q.where(Insight.severity == severity)
        if rule:
            q = q.where(Insight.rule == rule)
        return [{"insight_id": i.id, "rule": i.rule, "title": i.title, "severity": i.severity, "score": i.score}
                for i in self.s.execute(q).scalars()]

    def _search_cases(self, text: str | None = None, domain: str | None = None, status: str | None = None) -> Any:
        q = select(Case).order_by(Case.created_at.desc()).limit(15)
        if domain:
            q = q.where(Case.domain == domain)
        if status:
            q = q.where(Case.status == status)
        if text:
            q = q.where(Case.title.ilike(f"%{text}%"))
        return [{"case_id": c.id, "domain": c.domain, "title": c.title, "severity": c.severity, "verdict": c.verdict,
                 "status": c.status} for c in self.s.execute(q).scalars()]

    def _case_summary(self, case_id: str = "") -> Any:
        c = self.s.get(Case, case_id)
        if c is None:
            return {"not_found": case_id}
        acts = self.s.execute(select(ActionRequest).where(ActionRequest.case_id == c.id)).scalars().all()
        return {"case_id": c.id, "title": c.title, "verdict": c.verdict, "severity": c.severity, "summary": c.summary,
                "mitre": [m.get("technique") for m in (c.assessment or {}).get("mitre", [])],
                "actions": [f"{a.action_type}:{a.status}" for a in acts]}

    def _vm_query(self, question: str = "") -> Any:
        if self.vm is None:
            return {"unavailable": "vulnerability service not attached"}
        r = self.vm.query(question)
        return {"answer": r["answer"], "filter": r["generated_filter"], "records": r["records"][:15]}

    def _affected(self, cve: str = "") -> Any:
        if self.vm is None:
            return {"unavailable": "vulnerability service not attached"}
        r = self.vm.affected_devices(cve.upper())
        return {"cve": r["cve"], "affected": r["affected"], "intel": r["intel"],
                "assets": [{k: a[k] for k in ("asset", "platform_team", "priority", "status", "internet_exposed")}
                           for a in r["assets"]]}

    def _attack_story(self, case_id: str = "") -> Any:
        from soc_platform.intelligence.story import story_for_case

        try:
            st = story_for_case(self.s, case_id)
        except KeyError:
            return {"not_found": case_id}
        return {"case_id": case_id, "summary": st["summary"], "assessment": st["assessment"],
                "steps": [f"{(x['start'] or 'time n/a')[:16]} {x['stage_name']}: {x['title'][:120]} ({x['outcome']})" for x in st["steps"]],
                "gaps": [g["text"] for g in st["gaps"]]}

    def _entity_context(self, entity_id: str = "") -> Any:
        """Cases, correlated findings and pending actions that involve one user/host."""
        from soc_platform.core.models import CaseEntity

        case_ids = list(dict.fromkeys(ce.case_id for ce in self.s.execute(
            select(CaseEntity).where(CaseEntity.entity_id == entity_id)).scalars()))
        cases = [c for c in (self.s.get(Case, i) for i in case_ids) if c is not None]
        ins = [i for i in self.s.execute(select(Insight).where(Insight.status != "dismissed")
                                         .order_by(Insight.score.desc())).scalars() if entity_id in (i.entity_ids or [])]
        acts = self.s.execute(select(ActionRequest).where(ActionRequest.case_id.in_(case_ids or ["-"]),
                                                          ActionRequest.status.in_(("recommended", "pending_approval")))
                              ).scalars().all()
        return {"cases": [{"case_id": c.id, "title": c.title, "severity": c.severity, "verdict": c.verdict,
                           "status": c.status, "domain": c.domain} for c in cases],
                "insights": [{"insight_id": i.id, "title": i.title, "severity": i.severity, "rule": i.rule,
                              "next_steps": i.next_steps} for i in ins[:5]],
                "pending_actions": [{"action_id": a.id, "action": a.action_type, "rationale": a.rationale} for a in acts]}

    def _pending(self) -> Any:
        rows = self.s.execute(select(ActionRequest).where(ActionRequest.status.in_(("recommended", "pending_approval")))
                              .limit(30)).scalars().all()
        return [{"action_id": a.id, "action": a.action_type, "case_id": a.case_id, "rationale": a.rationale}
                for a in rows]

    # ------------------------------------------------------------------ planning

    def _catalogue(self) -> str:
        return "\n".join(f"- {t.name}({t.args}): {t.description}" for t in self.tools.values())

    def _deterministic_plan(self, q: str) -> list[dict[str, Any]]:
        calls: list[dict[str, Any]] = []
        ql = q.lower()
        for cve in re.findall(r"cve-\d{4}-\d{4,7}", ql):
            calls.append({"tool": "affected_devices", "args": {"cve": cve}})
        for upn in re.findall(r"[\w.+-]+@[\w-]+\.[\w.-]+", q):
            calls.append({"tool": "find_entity", "args": {"kind": "identity", "key": "upn", "value": upn}})
        for host in re.findall(r"\b([a-z]+[-_]?[a-z]*\d+[a-z0-9-]*)\b", ql):
            if not host.startswith("cve"):
                calls.append({"tool": "search_entities", "args": {"text": host}})
        if any(w in ql for w in ("risk", "riskiest", "most at risk", "worst")):
            calls.append({"tool": "top_risky", "args": {"limit": 5}})
        if any(w in ql for w in ("correlat", "insight", "chain", "going on", "happening", "summary", "priorit")):
            calls.append({"tool": "list_insights", "args": {}})
        if any(w in ql for w in ("vuln", "patch", "kev", "exposed", "sla")) and not any(c["tool"] == "affected_devices"
                                                                                  for c in calls):
            calls.append({"tool": "vulnerability_query", "args": {"question": q}})
        if any(w in ql for w in ("approv", "pending", "waiting")):
            calls.append({"tool": "pending_approvals", "args": {}})
        if any(w in ql for w in ("incident", "case", "phish")):
            calls.append({"tool": "search_cases", "args": {}})
        return calls[:6] or [{"tool": "list_insights", "args": {}}, {"tool": "top_risky", "args": {"limit": 5}}]

    def _plan(self, q: str) -> tuple[list[dict[str, Any]], str]:
        if self.llm is not None:
            try:
                data = self.llm.complete_json("intelligence.plan", PLANNER_SYSTEM,
                                              f"TOOLS:\n{self._catalogue()}\n\nQUESTION: {q}", tier="small")
            except BudgetExceeded:
                data = None
            calls = [c for c in (data or {}).get("calls", []) if isinstance(c, dict) and c.get("tool") in self.tools]
            if calls:
                return calls[:5], "llm"
        return self._deterministic_plan(q), "deterministic"

    def _execute(self, calls: list[dict[str, Any]]) -> list[dict[str, Any]]:
        results = []
        for c in calls:
            spec = self.tools[c["tool"]]
            args = c.get("args") if isinstance(c.get("args"), dict) else {}
            try:
                out = spec.fn(**{k: v for k, v in args.items() if isinstance(v, (str, int, float)) or v is None})
            except TypeError as exc:
                out = {"error": f"bad arguments: {exc}"}
            except Exception as exc:  # a failing tool never breaks the answer
                out = {"error": f"{type(exc).__name__}: {exc}"}
            results.append({"tool": spec.name, "args": args, "result": out})
        # Follow-up: resolved entities get their risk + timeline automatically (one hop, deterministic).
        for r in list(results):
            items = r["result"] if isinstance(r["result"], list) else [r["result"]]
            for it in items[:3]:
                if isinstance(it, dict) and it.get("entity_id") and it.get("kind") in {"asset", "identity"} and \
                        r["tool"] in {"find_entity", "search_entities"}:
                    results.append({"tool": "entity_risk", "args": {"entity_id": it["entity_id"]},
                                    "result": self._entity_risk(it["entity_id"])})
                    results.append({"tool": "entity_context", "args": {"entity_id": it["entity_id"]},
                                    "result": self._entity_context(it["entity_id"])})
        return results

    @staticmethod
    def _to_evidence(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
        ev = []
        for i, r in enumerate(results, start=1):
            text = json.dumps(r["result"], default=str)
            ev.append({"id": f"R{i}", "claim": f"{r['tool']}({json.dumps(r['args'], default=str)}) -> {text[:1800]}",
                       "source": r["tool"]})
        return ev

    # ------------------------------------------------------------------ public API

    def ask(self, question: str) -> dict[str, Any]:
        calls, planner = self._plan(question)
        results = self._execute(calls)
        if re.search(r"what happened|story|timeline|how did|attack chain|kill chain|walk me through", question, re.I):
            sev = {"critical": 4, "high": 3, "medium": 2, "low": 1}
            cases = [c for r in results if r["tool"] == "entity_context" and isinstance(r["result"], dict)
                     for c in r["result"].get("cases", []) if c.get("status") != "closed"]
            if cases and not any(r["tool"] == "attack_story" for r in results):
                top = max(cases, key=lambda c: sev.get(c.get("severity"), 0))
                results.append({"tool": "attack_story", "args": {"case_id": top["case_id"]},
                                "result": self._attack_story(top["case_id"])})
        evidence = self._to_evidence(results)
        if self.llm is not None:
            answer = self.llm.grounded("intelligence.answer", question, evidence)
        else:
            answer = {"summary": _facts_summary(results), "claims": _readable_claims(results),
                      "source": "deterministic", "insufficient_evidence": not any(
                          r["result"] and not (isinstance(r["result"], dict) and r["result"].get("not_found"))
                          for r in results)}
        return {"question": question, "planner": planner, "tool_calls": [{"tool": r["tool"], "args": r["args"]}
                                                                        for r in results],
                "answer": answer["summary"], "claims": answer.get("claims", []),
                "insufficient_evidence": answer.get("insufficient_evidence", False), "source": answer.get("source"),
                "results": results}

    def narrate(self, insight: Insight) -> Insight:
        evidence = [{"id": f"E{i + 1}", "claim": f"{e.get('signal')}: {e.get('summary')} ({e.get('source')}, "
                                                 f"{e.get('when') or 'n/a'})", "source": e.get("source")}
                    for i, e in enumerate(insight.evidence)]
        if self.llm is not None:
            g = self.llm.grounded("intelligence.narrate",
                                  f"Explain this correlated finding to a SOC analyst in 3-5 sentences: {insight.title}. "
                                  "What happened, in what order, why it matters, and what is uncertain.", evidence)
            if g.get("source") == "llm":
                insight.narrative = g["summary"] + ("\n" + "\n".join(f"- {c['text']} [{', '.join(c['evidence_ids'])}]"
                                                                     for c in g["claims"]) if g["claims"] else "")
                insight.narrative_source = "llm"
                return insight
        ordered = sorted(insight.evidence, key=lambda e: e.get("when") or "")
        insight.narrative = (f"{insight.title}. Sequence: " +
                             "; ".join(f"{(e.get('when') or '')[:16]} {e.get('summary')} [{e.get('source')}]"
                                       for e in ordered[:8]) + ".")
        insight.narrative_source = "deterministic"
        return insight

    def brief(self, *, hours: int = 24) -> dict[str, Any]:
        """Cross-domain situation brief for the SOC lead / CISO (U05, U01)."""
        insights = self._list_insights()
        risky = self._top_risky(limit=8)
        pending = self._pending()
        open_cases = self._search_cases(status=None)
        vm = self.vm.metrics() if self.vm is not None else {}
        facts = {"insights": insights[:10], "riskiest_entities": risky, "pending_approvals": len(pending),
                 "open_cases": [c for c in open_cases if c["status"] != "closed"][:10],
                 "vulnerability": {k: vm.get(k) for k in ("open", "kev_open", "sla_breached", "internet_exposed_open",
                                                          "by_priority")} if vm else {}}
        evidence = [{"id": f"B{i + 1}", "claim": f"{k}: {json.dumps(v, default=str)[:1800]}", "source": k}
                    for i, (k, v) in enumerate(facts.items())]
        if self.llm is not None:
            g = self.llm.grounded("intelligence.brief", "Write the SOC situation brief: top threats and why, "
                                  "which users/hosts need attention first, what is waiting on analysts, and "
                                  "exposure posture. Lead with what matters most.", evidence)
        else:
            g = {"summary": _brief_text(facts), "claims": [], "source": "deterministic"}
        return {"summary": g["summary"], "claims": g.get("claims", []), "source": g.get("source"), "facts": facts}


def _ref(results: list[dict[str, Any]], r: dict[str, Any]) -> str:
    return f"R{results.index(r) + 1}"


def _facts_summary(results: list[dict[str, Any]]) -> str:
    """Plain-language answer built only from tool results (no model); every sentence is backed by a claim."""
    parts: list[str] = []
    ctx = {r["args"].get("entity_id"): r["result"] for r in results if r["tool"] == "entity_context"}
    for r in results:
        res = r["result"]
        if r["tool"] == "entity_risk" and isinstance(res, dict) and "score" in res:
            drivers = list(dict.fromkeys(f["signal"].replace("_", " ") for f in res["factors"]))[:4]
            parts.append(f"{res['name']} is at {res['band'].upper()} risk ({res['score']:.0f}/100)"
                         + (f"; main drivers: {', '.join(drivers)}" if drivers else "; no risk signals in the window"))
            c = ctx.get(res.get("entity_id")) or {}
            if c.get("cases") or c.get("insights"):
                open_cases = [x for x in c.get("cases", []) if x["status"] != "closed"]
                parts.append(f"involved in {len(open_cases)} open case(s) and {len(c.get('insights', []))} correlated "
                             f"finding(s)" + (f", the most serious being \"{c['insights'][0]['title']}\"" if c.get("insights") else ""))
            steps = [st for i in (c.get("insights") or []) for st in (i.get("next_steps") or [])]
            if steps:
                parts.append(f"recommended first step: {steps[0]}")
            elif c.get("pending_actions"):
                first = c["pending_actions"][0]
                parts.append(f"recommended first step: review and approve the pending {first['action']} "
                             f"({first['rationale'][:120]})")
            if c.get("pending_actions"):
                parts.append(f"{len(c['pending_actions'])} containment action(s) for this entity are waiting for approval ("
                             + ", ".join(a["action"] for a in c["pending_actions"][:3]) + ")")
        elif r["tool"] == "attack_story" and isinstance(res, dict) and res.get("summary"):
            parts.insert(0, res["summary"].rstrip("."))
        elif r["tool"] == "find_entity" and isinstance(res, dict) and res.get("not_found"):
            parts.append(f"no record found for {res['not_found']}")
        elif r["tool"] == "affected_devices" and isinstance(res, dict) and "affected" in res:
            parts.append(f"{res['cve']} affects {res['affected']} asset(s)"
                         + (": " + ", ".join(a["asset"] for a in res.get("assets", [])[:5]) if res.get("assets") else ""))
        elif r["tool"] == "list_insights" and isinstance(res, list):
            parts.append(f"{len(res)} active correlated finding(s)" + (": " + "; ".join(i["title"] for i in res[:3]) if res else ""))
        elif r["tool"] == "top_risky" and isinstance(res, list):
            parts.append("highest-risk users/hosts: " + ", ".join(f"{x['name']} ({x['score']:.0f}, {x['band']})" for x in res[:5]))
        elif r["tool"] == "vulnerability_query" and isinstance(res, dict) and "answer" in res:
            parts.append(res["answer"])
        elif r["tool"] == "pending_approvals" and isinstance(res, list):
            parts.append(f"{len(res)} action(s) awaiting approval")
        elif r["tool"] == "search_cases" and isinstance(res, list):
            parts.append(f"{len(res)} matching case(s)")
    if not parts:
        return "No matching data found."
    def cap(p: str) -> str:  # never capitalise an address or host name that opens a sentence
        first = p.split(" ", 1)[0]
        return p if ("@" in first or "." in first or first[:1].isdigit()) else p[0].upper() + p[1:]

    text = ". ".join(cap(p) for p in parts)
    return text + "."


def _readable_claims(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """One fact per piece of evidence, in words, citing the tool result (R#) it came from."""
    claims: list[dict[str, Any]] = []

    def add(text: str, r: dict[str, Any], kind: str = "fact") -> None:
        claims.append({"text": text, "kind": kind, "evidence_ids": [_ref(results, r)]})

    # the reconstructed attack chain is the most important evidence when present: list it first
    for r in sorted(results, key=lambda x: x["tool"] != "attack_story"):
        res = r["result"]
        if isinstance(res, dict) and res.get("error"):
            add(f"{r['tool']} could not run: {res['error']}", r, "inference")
        elif r["tool"] == "find_entity" and isinstance(res, dict) and res.get("entity_id"):
            add(f"Resolved {res['name']} as one {res['kind']} across tools (keys: "
                + ", ".join(f"{k}={v}" for k, v in list(res.get("keys", {}).items())[:4]) + ")", r)
        elif r["tool"] == "entity_risk" and isinstance(res, dict) and "factors" in res:
            for f in res["factors"][:6]:
                add(f"{f['signal'].replace('_', ' ')} (+{f['decayed']:.0f}): {f['detail']} "
                    f"[{f['source']}, {str(f.get('when') or '')[:16]}]", r)
        elif r["tool"] == "entity_context" and isinstance(res, dict):
            for c in res.get("cases", [])[:5]:
                add(f"Case \"{c['title']}\" ({c['domain']}, {c['severity']}, verdict {c['verdict'] or 'pending'}, {c['status']})", r)
            for i in res.get("insights", [])[:3]:
                add(f"Correlated finding ({i['severity']}): {i['title']}", r)
            for a in res.get("pending_actions", [])[:3]:
                add(f"Awaiting approval: {a['action']} - {a['rationale']}", r)
        elif r["tool"] == "attack_story" and isinstance(res, dict) and res.get("steps"):
            for stp in res["steps"][:10]:
                add(stp, r)
            for g in res.get("gaps", [])[:3]:
                add(g, r, "inference")
        elif r["tool"] == "affected_devices" and isinstance(res, dict):
            for a in res.get("assets", [])[:8]:
                add(f"{a['asset']}: priority {a['priority']}, owner {a.get('platform_team') or 'unknown'}, "
                    f"{'internet-exposed' if a.get('internet_exposed') else 'internal'}", r)
        elif r["tool"] in {"list_insights", "top_risky", "search_cases", "pending_approvals"} and isinstance(res, list):
            for x in res[:5]:
                add(x.get("title") or f"{x.get('name')} risk {x.get('score', 0):.0f} ({x.get('band')})"
                    if "title" in x or "name" in x else f"{x.get('action')}: {x.get('rationale')}", r)
    return claims[:20]


def _brief_text(f: dict[str, Any]) -> str:
    lines = []
    if f["insights"]:
        lines.append("Top correlated threats: " + "; ".join(f"[{i['severity']}] {i['title']}" for i in f["insights"][:4]))
    if f["riskiest_entities"]:
        lines.append("Highest-risk users/hosts: " + ", ".join(f"{r['name']} {r['score']:.0f}/100"
                                                             for r in f["riskiest_entities"][:5]))
    lines.append(f"{f['pending_approvals']} action(s) awaiting approval; {len(f['open_cases'])} open case(s).")
    v = f.get("vulnerability") or {}
    if v:
        lines.append(f"Exposure: {v.get('open')} open findings, {v.get('kev_open')} KEV-listed, "
                     f"{v.get('sla_breached')} past SLA, {v.get('internet_exposed_open')} internet-exposed.")
    return "\n".join(lines)


class IntelligenceService:
    """Facade: correlate -> narrate -> expose. Used by the API, the scheduler and the domain pipelines."""

    def __init__(self, session: Session, llm: LLMGateway | None = None, *, vm: Any = None) -> None:
        self.s = session
        self.analyst = IntelligenceAnalyst(session, llm, vm=vm)
        self.correlation = CorrelationEngine(session, risk=self.analyst.risk)

    def refresh(self, entity_ids: list[str] | None = None, *, narrate: bool = True) -> list[Insight]:
        insights = self.correlation.run(entity_ids)
        if narrate:
            for i in insights:
                if not i.narrative or i.narrative_source == "deterministic":
                    self.analyst.narrate(i)
        return insights
