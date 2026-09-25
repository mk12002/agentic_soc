"""Attack Story: cross-tool reconstruction of what happened, how far it reached and what to do (analysis layer).

Given a case, the story:

1. scopes the *principal* users and hosts (the ones the case is about) and pulls in every other case that touches
   them, so the phishing case and the endpoint incident about the same person tell one story;
2. reconstructs the attack chain from events in every connected tool plus milestones the domain analyses already
   measured (delivery, click, payload execution), classifies each step on the MITRE ATT&CK kill chain and groups
   them; every step cites the exact events it rests on (``S1``, ``S2`` ...);
3. states the **gaps** - kill-chain stages with no evidence, naming the enabled tools that would have seen them (or
   calling out a blind spot when none would);
4. tests **benign explanations** against the evidence (legitimate mail, travel / VPN, IT admin activity, authorised
   scanner, normal duties) and marks each rejected / unlikely / plausible / cannot assess, with reasons;
5. maps the **blast radius** (recipients, who interacted, hosts, indicators, privileged secrets, related cases);
6. turns pending actions from all related cases into a phased **response plan** (contain, preserve, eradicate,
   recover, communicate).

Everything is computed from stored records - no model is involved and nothing is invented: an event that is not
in the store cannot appear in the story. ``deep_analysis`` adds an optional, evidence-bound LLM review on top.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from soc_platform.core.context_store import ContextStore
from soc_platform.core.models import ActionRequest, Case, CaseEntity, Entity
from soc_platform.intelligence.attack_coverage import CAPABILITY, TACTICS, TECHNIQUES

TACTIC_NAME = dict(TACTICS)
TACTIC_ORDER = {t: i for i, (t, _) in enumerate(TACTICS)}
PRINCIPAL_ROLES = {"user", "host", "source_host", "compromised", "clicked", "affected_user", "affected_host"}
SENSITIVE_SECRET_ACTIONS = {"VIEW", "COPY PASSWORD", "EXPORT", "CHECKOUT", "LAUNCH", "DOWNLOAD"}
PLATFORM_TOOLS = {"phishing", "incident", "platform", "vulnerability"}
PHASES = [("contain", "Contain", {"endpoint.isolate", "identity.revoke_sessions", "identity.disable_account", "identity.confirm_compromised"}),
          ("preserve", "Preserve evidence", {"endpoint.collect_forensics"}),
          ("eradicate", "Eradicate", {"email.campaign_purge", "indicator.block", "dns.block_domain", "email.block_sender",
                                      "email.gateway_quarantine", "endpoint.scan"}),
          ("recover", "Recover", {"identity.reset_password", "pam.rotate_secret", "identity.enable_account", "endpoint.release"}),
          ("communicate", "Communicate", {"email.reporter_feedback", "ticket.create", "ticket.update", "notify.email"})]


def _aware(dt: datetime | None) -> datetime | None:
    return dt.replace(tzinfo=timezone.utc) if dt is not None and dt.tzinfo is None else dt


def _parse(ts: Any) -> datetime | None:
    if isinstance(ts, datetime):
        return _aware(ts)
    if not ts:
        return None
    try:
        return _aware(datetime.fromisoformat(str(ts).replace("Z", "+00:00")))
    except ValueError:
        return None


@dataclass
class Ev:
    ref: str
    ts: datetime | None
    tool: str
    title: str
    kind: str
    tactic: str
    techniques: list[str]
    severity: str
    entity: str
    source: str                       # event entity id or "case:<id>"
    blocked: bool = False
    detail: dict[str, Any] = field(default_factory=dict)

    def public(self) -> dict[str, Any]:
        return {"ref": self.ref, "ts": self.ts.isoformat() if self.ts else None, "tool": self.tool, "title": self.title,
                "kind": self.kind, "stage": self.tactic, "stage_name": TACTIC_NAME.get(self.tactic, self.tactic),
                "techniques": [{"id": t, "name": TECHNIQUES.get(t, (t,))[0]} for t in self.techniques],
                "severity": self.severity, "entity": self.entity, "source": self.source, "blocked": self.blocked,
                "detail": self.detail}


SEV_RANK = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _tactic_of(techniques: list[str]) -> str | None:
    tacs = [TECHNIQUES[t][1] for t in techniques if t in TECHNIQUES]
    return min(tacs, key=lambda x: TACTIC_ORDER.get(x, 99)) if tacs else None


def classify(ent: Entity) -> tuple[str, list[str], bool] | None:
    """Kill-chain stage for one stored event: (tactic, techniques, blocked) or None when not an attack step."""
    a = ent.attributes or {}
    kind, sev = ent.kind, str(a.get("severity") or "informational").lower()
    title = (ent.display_name or "").lower()
    techs = [str(t) for t in [a.get("technique_id"), *(a.get("mitre_techniques") or [])] if t]
    if kind in {"finding", "cloud_issue"}:
        return None                                              # exposure, not an attack step
    if kind == "signin":
        if str(a.get("risk_level") or "none").lower() not in {"medium", "high"}:
            return None                                          # baseline, used by hypotheses
        return "TA0001", ["T1078"], False
    if kind == "secret_access":
        if str(a.get("action") or "").upper() not in SENSITIVE_SECRET_ACTIONS and sev != "medium":
            return None
        return "TA0006", ["T1555"], False
    if kind == "elevation":
        denied = str(a.get("outcome") or "").lower() in {"denied", "blocked"}
        return "TA0004", ["T1548.002"], denied
    if kind == "deception":
        return "TA0008", ["T1021.002", "T1135"], False
    if kind == "dns":
        cats = {str(c).lower() for c in a.get("categories") or []}
        if not cats & {"phishing", "malware", "command and control", "cryptomining", "newly seen domains"}:
            return None
        blocked = str(a.get("verdict") or "").lower() != "allowed"
        if cats & {"malware", "command and control"}:
            return "TA0011", ["T1071.004"], blocked
        return "TA0001", ["T1566.002"], blocked
    if kind == "alert":
        if "inbox" in title or "forward" in title:
            techs = techs or ["T1114.003"]
        if "anonymized" in title or "unfamiliar" in title or "impossible travel" in title or a.get("dimension") == "identity":
            techs = techs or ["T1078"]
        tac = _tactic_of(techs)
        if tac is None:
            dim = a.get("dimension")
            tac = {"endpoint": "TA0002", "identity": "TA0001", "email": "TA0001", "cloud": "TA0001", "dns": "TA0011"}.get(dim)
        if tac is None and sev in {"informational", "low"}:
            return None
        blocked = "blocked" in title or "prevented" in title
        return tac or "TA0002", techs, blocked
    return None


def _merge_same(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Related cases each propose their own copy of e.g. ticket.create: show one row per (action, target) and
    carry the copies' ids so approving the row approves every copy (each still passes its own policy checks)."""
    out: list[dict[str, Any]] = []
    index: dict[tuple, dict[str, Any]] = {}
    for it in items:
        key = (it["action_type"], tuple(map(str, it["targets"])), it["approvable"])
        if key in index:
            index[key]["duplicate_ids"].append(it["id"])
            index[key]["four_eyes"] = index[key]["four_eyes"] or it["four_eyes"]
            continue
        it = {**it, "duplicate_ids": []}
        index[key] = it
        out.append(it)
    return out


class AttackStory:
    def __init__(self, session: Session, registry: Any | None = None) -> None:
        self.s = session
        self.store = ContextStore(session)
        self.registry = registry

    # ------------------------------------------------------------------ scope
    def _principals(self, case: Case) -> set[str]:
        ids = set()
        for ce in self.s.execute(select(CaseEntity).where(CaseEntity.case_id == case.id)).scalars():
            e = self.s.get(Entity, ce.entity_id)
            if e is not None and e.kind in {"asset", "identity"} and ce.role in PRINCIPAL_ROLES:
                ids.add(e.id)
        # phishing: devices of users with endpoint impact are principals too
        for upn, pu in ((case.assessment or {}).get("user_impact") or {}).get("per_user", {}).items():
            if not (pu.get("clicked") or pu.get("reached_site")):
                continue
            ident = self.store.find("identity", "upn", upn)
            if ident is not None:
                ids.add(ident.id)
            for dev in (pu.get("endpoint") or {}).get("devices") or []:
                host = self._host(dev)
                if host is not None:
                    ids.add(host.id)
        return ids

    def _host(self, name: str) -> Entity | None:
        short = str(name).lower().split(".")[0]
        for e in self.s.execute(select(Entity).where(Entity.kind == "asset")).scalars():
            dn = (e.display_name or "").lower()
            if dn == str(name).lower() or dn.split(".")[0] == short:
                return e
        return None

    def _related_cases(self, principals: set[str], seed: Case) -> list[Case]:
        ids = {ce.case_id for ce in self.s.execute(select(CaseEntity).where(CaseEntity.entity_id.in_(principals or {"-"}))).scalars()}
        ids.discard(seed.id)
        cases = [c for c in (self.s.get(Case, i) for i in ids) if c is not None]
        return sorted(cases, key=lambda c: -SEV_RANK.get(c.severity, 0))[:10]

    # ------------------------------------------------------------------ events
    def _events(self, principals: set[str], cases: list[Case]) -> tuple[list[Ev], list[dict[str, Any]], list[dict[str, Any]]]:
        evs: list[Ev] = []
        baseline: list[dict[str, Any]] = []
        exposure: list[dict[str, Any]] = []
        names = {i: (self.s.get(Entity, i).display_name if self.s.get(Entity, i) else i) for i in principals}
        seen: set[str] = set()
        for pid in principals:
            for _, ent in self.store.neighbors(pid):
                if ent.id in seen or ent.kind in {"asset", "identity", "indicator"}:
                    continue
                seen.add(ent.id)
                a = ent.attributes or {}
                tool = str(a.get("tool") or "")
                if tool in PLATFORM_TOOLS:
                    continue
                if ent.kind in {"finding", "cloud_issue"}:
                    exposure.append({"title": ent.display_name, "tool": tool, "severity": a.get("severity"),
                                     "first_seen": _aware(ent.first_seen).isoformat(), "entity": names[pid], "cve": a.get("cve")})
                    continue
                if ent.kind == "signin" and str(a.get("risk_level") or "none").lower() not in {"medium", "high"}:
                    baseline.append({"ts": _aware(ent.first_seen).isoformat(), "country": a.get("country"), "ip": a.get("ip"),
                                     "tool": tool, "entity": names[pid]})
                    continue
                c = classify(ent)
                if c is None:
                    continue
                tac, techs, blocked = c
                title = ent.display_name or ent.kind
                if ent.kind == "signin":
                    title = (f"Risky sign-in ({a.get('risk_level')}) - {title}" + (f" from {a.get('ip')}" if a.get("ip") else "")
                             + (f" ({a.get('country')})" if a.get("country") else ""))
                evs.append(Ev("", _aware(ent.first_seen), tool, title, ent.kind, tac, techs,
                              str(a.get("severity") or "informational").lower(), names[pid], ent.id, blocked,
                              {k: a.get(k) for k in ("ip", "country", "action", "outcome", "secret_name", "categories",
                                                    "risk_level", "verdict", "domain") if a.get(k)}))
        # milestones measured by the phishing analysis (delivery, click, payload activity, identity changes)
        for case in cases:
            if case.domain != "phishing" or case.verdict not in {"malicious", "suspicious"}:
                continue
            asm = case.assessment or {}
            per_user = (asm.get("user_impact") or {}).get("per_user", {})
            members = (asm.get("campaign") or {}).get("members") or []
            principals_upn = {self.store.keys_of(p).get("upn") for p in principals} - {None}
            for upn, pu in per_user.items():
                if upn not in principals_upn:
                    continue
                first = min((m for m in members if m.get("recipient") == upn), key=lambda m: m.get("timestamp") or "", default=None)
                if first:
                    evs.append(Ev("", _parse(first.get("timestamp")), "defender_office365",
                                  f"Phishing email delivered to {upn}: \"{first.get('subject')}\" from {first.get('sender')}",
                                  "email", "TA0001", ["T1566.002"], "high", upn, f"case:{case.id}", False,
                                  {"sender": first.get("sender"), "recipients": len({m.get('recipient') for m in members})}))
                if pu.get("clicked"):
                    evs.append(Ev("", _parse(pu.get("click_time")), "defender_office365",
                                  f"{upn} clicked the phishing link" + (" (blocked by Safe Links)" if pu.get("click_blocked") else ""),
                                  "click", "TA0002", ["T1204.001"], "high", upn, f"case:{case.id}", bool(pu.get("click_blocked"))))
                for act in (pu.get("endpoint") or {}).get("ioc_activity") or []:
                    at = str(act.get("ActionType") or "")
                    if at == "ProcessCreated":
                        cmd = str(act.get("ProcessCommandLine") or act.get("FileName") or "")
                        techs = ["T1059.001"] if "powershell" in cmd.lower() else ["T1204.002"]
                        if re.search(r"\b(iwr|invoke-webrequest|downloadstring|wget|curl)\b", cmd.lower()):
                            techs.append("T1105")
                        evs.append(Ev("", _parse(act.get("Timestamp")), "defender_endpoint",
                                      f"{act.get('FileName')} started on {act.get('DeviceName')}: {cmd[:140]}", "process",
                                      "TA0002", techs, "critical", str(act.get("DeviceName")), f"case:{case.id}", False,
                                      {"sha256": act.get("SHA256")}))
                    elif at.startswith("Connection"):
                        evs.append(Ev("", _parse(act.get("Timestamp")), "defender_endpoint",
                                      f"{act.get('DeviceName')} connected to {act.get('RemoteUrl') or act.get('RemoteIP')}",
                                      "network", "TA0011", ["T1071.001"], "high", str(act.get("DeviceName")), f"case:{case.id}"))
                ident = pu.get("identity") or {}
                if ident.get("suspicious_inbox_rules"):
                    evs.append(Ev("", None, "entra", f"Suspicious inbox forwarding / hiding rule on {upn}'s mailbox",
                                  "mailbox_rule", "TA0009", ["T1114.003"], "high", upn, f"case:{case.id}", False,
                                  {"time_reported": False}))
                if ident.get("new_devices"):
                    evs.append(Ev("", None, "entra", f"New device registered for {upn} after the click", "device_registration",
                                  "TA0003", ["T1098.005"], "medium", upn, f"case:{case.id}", False, {"time_reported": False}))
        # order: timed events chronologically; untimed ones after the step they logically follow
        timed = sorted([e for e in evs if e.ts], key=lambda e: e.ts)
        untimed = sorted([e for e in evs if not e.ts], key=lambda e: TACTIC_ORDER.get(e.tactic, 99))
        ordered = timed + untimed
        for i, e in enumerate(ordered, 1):
            e.ref = f"S{i}"
        return ordered, baseline, exposure

    # ------------------------------------------------------------------ steps
    @staticmethod
    def _steps(evs: list[Ev]) -> list[dict[str, Any]]:
        steps: list[dict[str, Any]] = []
        for e in evs:
            last = steps[-1] if steps else None
            joinable = last and last["stage"] == e.tactic and (
                e.ts is None or last["_end"] is None or (e.ts - last["_end"]) <= timedelta(minutes=15))
            if joinable:
                last["events"].append(e)
                last["_end"] = e.ts or last["_end"]
            else:
                steps.append({"stage": e.tactic, "events": [e], "_start": e.ts, "_end": e.ts})
        out = []
        for i, st in enumerate(steps, 1):
            es: list[Ev] = st["events"]
            tools = sorted({e.tool for e in es})
            sev = max((e.severity for e in es), key=lambda x: SEV_RANK.get(x, 0))
            blocked = all(e.blocked for e in es)
            techs = sorted({t for e in es for t in e.techniques})
            conf, why = ("high", f"corroborated by {len(tools)} tools") if len(tools) >= 2 else \
                ("high", "critical-severity detection") if sev == "critical" else \
                ("medium", f"single source ({tools[0]})") if SEV_RANK.get(sev, 0) >= 2 else ("low", "low-severity single signal")
            lead = max(es, key=lambda e: SEV_RANK.get(e.severity, 0))
            out.append({"n": i, "stage": st["stage"], "stage_name": TACTIC_NAME.get(st["stage"], st["stage"]),
                        "start": st["_start"].isoformat() if st["_start"] else None, "end": st["_end"].isoformat() if st["_end"] else None,
                        "title": lead.title, "techniques": [{"id": t, "name": TECHNIQUES.get(t, (t,))[0]} for t in techs],
                        "tools": tools, "severity": sev, "outcome": "blocked" if blocked else "succeeded",
                        "confidence": conf, "confidence_reason": why, "entities": sorted({e.entity for e in es}),
                        "evidence": [e.ref for e in es],
                        "narrative": " · ".join(dict.fromkeys(e.title for e in es))})
        return out

    # ------------------------------------------------------------------ gaps
    def _gaps(self, steps: list[dict[str, Any]]) -> list[dict[str, Any]]:
        observed = {s["stage"] for s in steps}
        if not observed:
            return []
        first = min(TACTIC_ORDER[s] for s in observed)
        enabled = self.registry.enabled_names() if self.registry is not None else list(CAPABILITY)
        out = []
        for tac, name in TACTICS:
            if tac in observed or TACTIC_ORDER[tac] < first:
                continue
            techs = [t for t, (_, ta, _) in TECHNIQUES.items() if ta == tac]
            tools = sorted({tool for tool in enabled if tool in CAPABILITY and any(t in CAPABILITY[tool] for t in techs)})
            out.append({"stage": tac, "stage_name": name, "status": "no_evidence" if tools else "blind_spot",
                        "checked_tools": tools,
                        "text": (f"No evidence of {name.lower()} - checked {', '.join(tools)}" if tools
                                 else f"Blind spot: no enabled tool can detect {name.lower()}")})
        return out

    # ------------------------------------------------------------------ hypotheses
    def _hypotheses(self, evs: list[Ev], cases: list[Case], baseline: list[dict[str, Any]], principals: set[str]) -> list[dict[str, Any]]:
        hyps = []

        def add(h, status, reason, refs):
            hyps.append({"hypothesis": h, "status": status, "reasoning": reason, "evidence": refs})

        phish = [c for c in cases if c.domain == "phishing"]
        if phish:
            c = phish[0]
            sigs = [s.get("name") for s in (c.assessment or {}).get("signals") or [] if isinstance(s, dict)]
            refs = [e.ref for e in evs if e.kind in {"email", "click"}]
            if c.verdict in {"malicious", "suspicious"}:
                add("The reported email was legitimate", "rejected",
                    f"analysis verdict {c.verdict} ({', '.join(x for x in sigs if x)[:160] or 'multiple signals'})", refs)
            else:
                add("The reported email was legitimate", "plausible", f"analysis verdict {c.verdict}", refs)
        risky = [e for e in evs if e.kind == "signin" or (e.kind == "alert" and "T1078" in e.techniques)]
        if risky:
            base_countries = sorted({b["country"] for b in baseline if b.get("country")})
            risky_countries = sorted({str(e.detail.get("country")) for e in risky if e.detail.get("country")})
            anon = any("anonymi" in e.title.lower() or "tor" in e.title.lower() for e in risky)
            if anon:
                add("The risky sign-in was the user travelling or on a corporate VPN", "rejected",
                    "sign-in came from an anonymising network (identity protection: anonymized IP address)" +
                    (f"; normal sign-ins are from {', '.join(base_countries)}" if base_countries else ""), [e.ref for e in risky])
            elif base_countries and risky_countries and set(risky_countries) <= set(base_countries):
                add("The risky sign-in was the user travelling or on a corporate VPN", "plausible",
                    f"risky sign-in country {', '.join(risky_countries)} matches normal locations", [e.ref for e in risky])
            else:
                add("The risky sign-in was the user travelling or on a corporate VPN", "unlikely",
                    f"new location {', '.join(risky_countries) or 'unknown'} vs normal {', '.join(base_countries) or 'unknown'}",
                    [e.ref for e in risky])
        exec_evs = [e for e in evs if e.tactic == "TA0002" and e.kind != "click"]
        if exec_evs:
            email_domains = set()
            for c in phish:
                for u in ((c.assessment or {}).get("decomposition") or {}).get("urls") or []:
                    m = re.match(r"https?://([^/]+)", str(u))
                    if m:
                        email_domains.add(m.group(1).lower())
            linked = [e for e in exec_evs if any(d in e.title.lower() for d in email_domains)]
            if linked:
                add("The script execution was legitimate IT / admin activity", "rejected",
                    f"the command downloaded from the same domain as the phishing link ({', '.join(sorted(email_domains))})",
                    [e.ref for e in linked])
            else:
                add("The script execution was legitimate IT / admin activity", "cannot_assess",
                    "no link between the execution and the delivery infrastructure was found; check the change calendar",
                    [e.ref for e in exec_evs])
        dec = [e for e in evs if e.kind == "deception"]
        if dec:
            hosts = [self.s.get(Entity, p) for p in principals]
            tags = {str(t).lower() for h in hosts if h is not None and h.kind == "asset" for t in (h.attributes or {}).get("tags") or []}
            if tags & {"scanner", "vulnerability scanner", "pentest", "red team"}:
                add("The decoy was touched by an authorised scanner or test", "plausible", f"source host tagged {sorted(tags)}",
                    [e.ref for e in dec])
            else:
                add("The decoy was touched by an authorised scanner or test", "rejected",
                    "the source is a user workstation with no scanner / test tag; decoys have no business use", [e.ref for e in dec])
        sec = [e for e in evs if e.kind == "secret_access"]
        if sec:
            comp_ts = [e.ts for e in evs if e.ts and e.tactic in {"TA0001", "TA0002"} and not e.blocked]
            after = [e for e in sec if e.ts and comp_ts and e.ts > min(comp_ts)]
            if after:
                mins = int((min(e.ts for e in after) - min(comp_ts)).total_seconds() // 60)
                add("The privileged secret access was part of normal duties", "unlikely",
                    f"access happened {mins} min after the first compromise indicator; confirm with the secret owner",
                    [e.ref for e in after])
            else:
                add("The privileged secret access was part of normal duties", "cannot_assess",
                    "no compromise indicator precedes the access", [e.ref for e in sec])
        return hyps

    # ------------------------------------------------------------------ blast radius
    def _blast(self, principals: set[str], cases: list[Case], evs: list[Ev]) -> dict[str, Any]:
        nodes: dict[str, dict[str, Any]] = {}
        edges: list[dict[str, str]] = []

        def node(nid, label, kind, **kw):
            nodes.setdefault(nid, {"id": nid, "label": label, "kind": kind, **kw})

        for p in principals:
            e = self.s.get(Entity, p)
            if e is not None:
                node(p, e.display_name, e.kind, principal=True)
        recipients, interacted = set(), set()
        for c in cases:
            asm = c.assessment or {}
            for r in (asm.get("campaign") or {}).get("recipients") or []:
                recipients.add(r)
            ui = asm.get("user_impact") or {}
            interacted |= set(ui.get("clicked") or []) | set(ui.get("reached_site") or [])
            node(f"case:{c.id}", c.title, "case", severity=c.severity, domain=c.domain)
            for p in principals:
                if self.s.execute(select(CaseEntity.id).where(CaseEntity.case_id == c.id, CaseEntity.entity_id == p)).first():
                    edges.append({"from": p, "to": f"case:{c.id}", "rel": "in case"})
            for ce in self.s.execute(select(CaseEntity).where(CaseEntity.case_id == c.id)).scalars():
                ent = self.s.get(Entity, ce.entity_id)
                if ent is not None and ent.kind == "indicator":
                    node(ent.id, ent.display_name, "indicator", role=ce.role)
                    edges.append({"from": f"case:{c.id}", "to": ent.id, "rel": ce.role})
        principal_upns = {self.store.keys_of(p).get("upn") for p in principals}
        for r in sorted(recipients - principal_upns - {None}):
            node(f"user:{r}", r, "recipient", interacted=r in interacted)
            edges.append({"from": "campaign", "to": f"user:{r}", "rel": "received"})
        if recipients:
            node("campaign", f"Phishing campaign ({len(recipients)} recipients)", "campaign")
        secrets = sorted({e.title.split("'")[1] for e in evs if e.kind == "secret_access" and "'" in e.title})
        for sname in secrets:
            node(f"secret:{sname}", sname, "secret")
            src = next((p for p in principals if (self.s.get(Entity, p) or Entity()).kind == "identity"), None)
            if src:
                edges.append({"from": src, "to": f"secret:{sname}", "rel": "accessed"})
        hosts = {n["label"] for n in nodes.values() if n["kind"] == "asset"}
        return {"nodes": list(nodes.values()), "edges": edges,
                "stats": {"users_received": len(recipients), "users_interacted": len(interacted),
                          "hosts": len(hosts), "privileged_secrets": len(secrets),
                          "indicators": sum(1 for n in nodes.values() if n["kind"] == "indicator"),
                          "related_cases": sum(1 for n in nodes.values() if n["kind"] == "case")},
                "secrets": secrets, "recipients": sorted(recipients), "interacted": sorted(interacted)}

    # ------------------------------------------------------------------ plan
    def _plan(self, cases: list[Case]) -> list[dict[str, Any]]:
        ids = {c.id for c in cases}
        acts = list(self.s.execute(select(ActionRequest).where(ActionRequest.case_id.in_(ids))).scalars())
        acts += [a for a in self.s.execute(select(ActionRequest).where(ActionRequest.status.in_(("recommended", "pending_approval"))))
                 .scalars() if set((a.result or {}).get("linked_cases", [])) & ids]
        seen, phases = set(), []
        for key, label, types in PHASES:
            items = []
            for a in sorted(acts, key=lambda x: x.created_at):
                if a.id in seen or a.action_type not in types:
                    continue
                seen.add(a.id)
                items.append({"id": a.id, "action_type": a.action_type, "targets": [t.get("name") or t.get("recipient") or t.get("id") for t in a.targets or []][:5],
                              "status": a.status, "rationale": a.rationale, "case_id": a.case_id,
                              "four_eyes": any("four-eyes" in str(r) for r in a.policy_reasons or []),
                              "approvable": a.status in {"recommended", "pending_approval"}})
            if items:
                phases.append({"phase": key, "label": label, "actions": _merge_same(items)})
        rest = [a for a in acts if a.id not in seen]
        if rest:
            phases.append({"phase": "other", "label": "Other", "actions": [
                {"id": a.id, "action_type": a.action_type, "targets": [t.get("name") or t.get("recipient") or t.get("id") for t in a.targets or []][:5], "status": a.status,
                 "rationale": a.rationale, "case_id": a.case_id, "four_eyes": False,
                 "approvable": a.status in {"recommended", "pending_approval"}} for a in rest]})
        return phases

    # ------------------------------------------------------------------ assembly
    def build(self, case_id: str) -> dict[str, Any]:
        seed = self.s.get(Case, case_id)
        if seed is None:
            raise KeyError("unknown case")
        principals = self._principals(seed)
        related = self._related_cases(principals, seed)
        for c in related:                         # one hop: principals of related cases join the scope
            principals |= self._principals(c)
        cases = [seed, *related]
        evs, baseline, exposure = self._events(principals, cases)
        steps = self._steps(evs)
        gaps = self._gaps(steps)
        hyps = self._hypotheses(evs, cases, baseline, principals)
        blast = self._blast(principals, cases, evs)
        plan = self._plan(cases)
        assessment = self._assess(steps, hyps)
        timed = [s for s in steps if s["start"]]
        span = None
        if len(timed) >= 1:
            t0, t1 = _parse(timed[0]["start"]), _parse(timed[-1]["end"] or timed[-1]["start"])
            span = int((t1 - t0).total_seconds() // 60)
        summary = self._summary(assessment, steps, blast, gaps, plan, span, principals)
        fp = hashlib.sha256(json.dumps([[e.ref, e.title, e.ts.isoformat() if e.ts else None] for e in evs]
                                       + [[s["n"], s["outcome"]] for s in steps], sort_keys=True).encode()).hexdigest()[:20]
        return {"case_id": seed.id, "title": seed.title, "generated_from": [c.id for c in cases],
                "principals": [{"id": p, "name": (self.s.get(Entity, p).display_name if self.s.get(Entity, p) else p),
                                "kind": (self.s.get(Entity, p).kind if self.s.get(Entity, p) else "")} for p in sorted(principals)],
                "assessment": assessment, "summary": summary, "span_minutes": span,
                "stages_observed": sorted({s["stage"] for s in steps}, key=lambda t: TACTIC_ORDER.get(t, 99)),
                "kill_chain": [{"id": t, "name": n, "state": ("blocked" if any(s["stage"] == t and s["outcome"] == "blocked" for s in steps)
                                                             and not any(s["stage"] == t and s["outcome"] == "succeeded" for s in steps)
                                                             else "observed" if any(s["stage"] == t for s in steps)
                                                             else next((g["status"] for g in gaps if g["stage"] == t), "before_scope"))}
                               for t, n in TACTICS],
                "steps": steps, "events": [e.public() for e in evs], "gaps": gaps, "hypotheses": hyps,
                "blast_radius": blast, "response_plan": plan, "exposure": exposure[:20], "baseline": baseline[:10],
                "tools": sorted({t for s in steps for t in s["tools"]}), "fingerprint": fp}

    @staticmethod
    def _assess(steps: list[dict[str, Any]], hyps: list[dict[str, Any]]) -> dict[str, Any]:
        succ = [s for s in steps if s["outcome"] == "succeeded"]
        deep = {"TA0003", "TA0004", "TA0006", "TA0007", "TA0008", "TA0009", "TA0010", "TA0040"}
        tools = {t for s in succ for t in s["tools"]}
        stages = {s["stage"] for s in succ}
        blocked_only = {s["stage"] for s in steps if s["outcome"] == "blocked"} - stages
        reached = f"{len(stages)} kill-chain stage(s) reached" + (f" ({len(blocked_only)} more blocked)" if blocked_only else "")
        benign_open = [h for h in hyps if h["status"] == "plausible"]
        if not steps:
            verdict, conf, why = "no_attack_activity", "medium", "no attack step found in any connected tool"
        elif not succ:
            verdict, conf, why = "attempt_blocked", "high", "every observed step was blocked by a control"
        elif len(stages) >= 3 and stages & deep and len(tools) >= 3 and not benign_open:
            verdict, conf, why = "confirmed_compromise", "high", f"{reached}, corroborated by {len(tools)} tools; benign explanations rejected"
        elif stages & deep or len(stages) >= 2:
            verdict, conf, why = "likely_compromise", "medium" if benign_open else "high", \
                f"{reached} across {len(tools)} tool(s)" + (f"; {len(benign_open)} benign explanation(s) still plausible" if benign_open else "")
        else:
            verdict, conf, why = "suspicious_activity", "low", "a single initial step without follow-on activity"
        return {"verdict": verdict, "label": verdict.replace("_", " ").capitalize(), "confidence": conf, "reason": why}

    def _summary(self, a, steps, blast, gaps, plan, span, principals) -> str:
        ents = [self.s.get(Entity, p) for p in principals]
        who = ", ".join(sorted(e.display_name for e in ents if e is not None and e.kind == "identity")) or             ", ".join(sorted(e.display_name for e in ents if e is not None and e.kind == "asset")) or "the affected assets"
        if not steps:
            return f"No attack activity was found for {who} in any connected tool."
        first = steps[0]
        last = next((s for s in reversed(steps) if s["start"]), steps[-1])
        parts = [f"{a['label']} of {who} ({a['confidence']} confidence)."]
        parts.append(f"It began with {first['stage_name'].lower()} ({first['title'][:90]})"
                     + (f" and reached {last['stage_name'].lower()} within {span} minutes" if span and len(steps) > 1 else "") + ".")
        parts.append(f"{len(steps)} step(s) across {len({t for s in steps for t in s['tools']})} tools.")
        st = blast["stats"]
        reach = [f"{st['hosts']} host(s)"] + ([f"{st['privileged_secrets']} privileged secret(s)"] if st["privileged_secrets"] else []) + \
                ([f"{st['users_received']} users received the email, {st['users_interacted']} interacted"] if st["users_received"] else [])
        parts.append("Reach: " + "; ".join(reach) + ".")
        no_ev = [g["stage_name"].lower() for g in gaps if g["status"] == "no_evidence" and g["stage"] in {"TA0010", "TA0040"}]
        if no_ev:
            parts.append(f"No evidence of {' or '.join(no_ev)}.")
        blind = [g["stage_name"].lower() for g in gaps if g["status"] == "blind_spot"]
        if blind:
            parts.append(f"Blind spots: {', '.join(blind)}.")
        pending = [x for ph in plan for x in ph["actions"] if x["approvable"]]
        if pending:
            parts.append(f"First action: {plan[0]['label'].lower()} - {pending[0]['action_type']} on "
                         f"{', '.join(map(str, pending[0]['targets'][:2])) or 'the targets'} "
                         f"({sum(1 + len(x.get('duplicate_ids', [])) for x in pending)} action(s) awaiting approval).")
        return " ".join(parts)


def story_for_case(session: Session, case_id: str, registry: Any | None = None) -> dict[str, Any]:
    return AttackStory(session, registry).build(case_id)


def evidence_for_llm(story: dict[str, Any]) -> list[dict[str, Any]]:
    """Every item the deep analysis may cite: events (S#), gaps (G#), hypotheses (H#), reach facts (B#), plan (P#)."""
    ev = [{"id": e["ref"], "claim": f"{e['ts'] or 'time not reported'} [{e['tool']}] {e['title']} "
                                   f"(stage {e['stage_name']}; {', '.join(t['id'] for t in e['techniques'])}; {'blocked' if e['blocked'] else 'not blocked'})",
           "source": e["tool"]} for e in story["events"]]
    ev += [{"id": f"G{i}", "claim": g["text"], "source": "coverage"} for i, g in enumerate(story["gaps"], 1)]
    ev += [{"id": f"H{i}", "claim": f"Benign explanation '{h['hypothesis']}': {h['status']} - {h['reasoning']}", "source": "hypothesis"}
           for i, h in enumerate(story["hypotheses"], 1)]
    st = story["blast_radius"]["stats"]
    ev += [{"id": "B1", "claim": f"Reach: {st['users_received']} users received the email, {st['users_interacted']} interacted, "
                                 f"{st['hosts']} host(s), {st['privileged_secrets']} privileged secret(s) "
                                 f"({', '.join(story['blast_radius']['secrets'])}), {st['related_cases']} related case(s)", "source": "graph"}]
    n = 0
    for ph in story["response_plan"]:
        for a in ph["actions"]:
            n += 1
            ev.append({"id": f"P{n}", "claim": f"Pending action ({ph['label']}): {a['action_type']} on {', '.join(map(str, a['targets']))} - "
                                              f"{a['rationale']} [status {a['status']}]", "source": "plan", "action_id": a["id"]})
    for i, x in enumerate(story.get("exposure", [])[:5], 1):
        ev.append({"id": f"X{i}", "claim": f"Exposure: {x['title']} ({x['tool']}, {x['severity']}, since {x['first_seen'][:10]})",
                   "source": "exposure"})
    return ev
