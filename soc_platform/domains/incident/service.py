"""Incident Management domain (section 7: IM-F01..F16, IM-T01..T11, U04, U05, U06, U13, U14).

Pipeline: ingest alerts from every alert-producing connector -> cluster related alerts
into incidents (entity + time window, noise suppression from disposition history) ->
extract entities -> parallel multi-dimension enrichment -> deterministic severity with
exposure-informed boost -> MITRE mapping with evidence -> grounded summary -> ranked,
policy-gated recommendations -> analyst decision -> documentation / handover.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from soc_platform.connectors.base import SyncRunner
from soc_platform.connectors.registry import ConnectorRegistry
from soc_platform.core.actions import ActionRegistry
from soc_platform.core.cases import CaseService, Recommendation, detection_quality
from soc_platform.core.context_store import ContextStore
from soc_platform.core.enrichment import EnrichmentOrchestrator, Target, evidence_for_llm
from soc_platform.core.models import Case, CaseEntity, Disposition, Entity, Evidence, utcnow
from soc_platform.core.policy import PolicyEngine
from soc_platform.core.schema import severity_rank
from soc_platform.llm.gateway import LLMGateway, deterministic_grounded

AGENT = "incident"
ALERT_STREAMS = {"alerts", "incidents", "risk_detections", "email_alerts"}
ALERT_KINDS = {"alert", "deception"}
SEV = ["informational", "low", "medium", "high", "critical"]
URL_RE = re.compile(r"https?://[^\s'\"<>)]+")

def _handled_by_phishing(alert: Entity) -> bool:
    """User-report alerts belong to the phishing workflow (it investigates the reported message itself)."""
    a = alert.attributes or {}
    return a.get("tool") == "defender_office365" and "reported by user" in (alert.display_name or "").lower()


@dataclass
class IngestReport:
    synced: dict[str, int]
    errors: dict[str, list[str]]


class IncidentService:
    def __init__(self, session: Session, registry: ConnectorRegistry, *, policy: PolicyEngine | None = None,
                 llm: LLMGateway | None = None, actions: ActionRegistry | None = None) -> None:
        self.s = session
        self.registry = registry
        self.policy = policy or PolicyEngine()
        self.llm = llm
        self.actions = actions or registry.action_registry()
        self.store = ContextStore(session)
        self.cases = CaseService(session)

    # ------------------------------------------------------------------ IM-F01 ingestion

    def ingest(self) -> IngestReport:
        runner = SyncRunner(self.s, self.store)
        synced: dict[str, int] = {}
        errors: dict[str, list[str]] = {}
        for c in self.registry.enabled():
            for stream in c.streams:
                if stream not in ALERT_STREAMS:
                    continue
                rep = runner.sync(c, stream)
                synced[f"{c.name}.{stream}"] = rep.ingested
                if rep.errors:
                    errors[f"{c.name}.{stream}"] = rep.errors[:3]
        return IngestReport(synced, errors)

    # ------------------------------------------------------------------ IM-F02 clustering & suppression

    def _unassigned_alerts(self, since_days: int) -> list[Entity]:
        assigned = {r for (r,) in self.s.execute(select(CaseEntity.entity_id).where(CaseEntity.role == "alert")).all()}
        cutoff = utcnow() - timedelta(days=since_days)
        rows = self.s.execute(select(Entity).where(Entity.kind.in_(ALERT_KINDS))).scalars().all()
        return [a for a in rows if a.id not in assigned and not _handled_by_phishing(a)
                and a.first_seen.replace(tzinfo=None) >= cutoff.replace(tzinfo=None)]

    def cluster(self, *, window_hours: int = 24, since_days: int = 30) -> list[Case]:
        alerts = sorted(self._unassigned_alerts(since_days), key=lambda a: a.first_seen)
        noisy = {d["detection"] for d in detection_quality(self.s, "incident")}
        parent = {a.id: a.id for a in alerts}

        def find(x: str) -> str:
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        by_entity: dict[str, list[Entity]] = defaultdict(list)
        for a in alerts:
            for rel, ent in self.store.neighbors(a.id, kinds={"asset", "identity"}):
                by_entity[ent.id].append(a)
        window = timedelta(hours=window_hours)
        for members in by_entity.values():
            members.sort(key=lambda a: a.first_seen)
            for x, y in zip(members, members[1:]):
                if y.first_seen - x.first_seen <= window:
                    parent[find(y.id)] = find(x.id)
        groups: dict[str, list[Entity]] = defaultdict(list)
        for a in alerts:
            groups[find(a.id)].append(a)

        created = []
        for members in groups.values():
            titles = [m.display_name for m in members]
            sev = max((m.attributes or {}).get("severity") or "low" for m in members) if members else "low"
            sev = SEV[max(severity_rank((m.attributes or {}).get("severity")) for m in members)]
            suppressed = all(t in noisy for t in titles) and severity_rank(sev) <= 2
            tools = sorted({(m.attributes or {}).get("tool") for m in members if (m.attributes or {}).get("tool")})
            is_deception = any(m.kind == "deception" for m in members)
            title = (f"Deception alert: {titles[0]}" if is_deception else
                     titles[0] if len(members) == 1 else f"{titles[0]} (+{len(members) - 1} related alert(s))")
            case = self.cases.create("incident", title, severity="critical" if is_deception else sev,
                                     attributes={"alert_count": len(members), "tools": tools, "suppressed": suppressed,
                                                 "detection_source": titles[0], "deception": is_deception},
                                     actor=f"agent:{AGENT}")
            if suppressed:
                case.status = "closed"
                case.verdict = "suppressed_noise"
                case.summary = "Auto-suppressed: detection consistently dispositioned benign (see detection quality)."
            for m in members:
                self.cases.link(case.id, m.id, "alert")
                for rel, ent in self.store.neighbors(m.id, kinds={"asset", "identity", "indicator"}):
                    self.cases.link(case.id, ent.id, rel.rel_type)
            created.append(case)
        return created

    # ------------------------------------------------------------------ IM-F03 entity extraction

    def extract_entities(self, case_id: str) -> list[Target]:
        links = self.s.execute(select(CaseEntity).where(CaseEntity.case_id == case_id)).scalars().all()
        targets: dict[tuple[str, str], Target] = {}
        since = None
        for ln in links:
            e = self.s.get(Entity, ln.entity_id)
            if e is None:
                continue
            a = e.attributes or {}
            if ln.role == "alert":
                since = min(since, e.first_seen) if since else e.first_seen
                for key in ("cmdline", "parent_cmdline", "description"):
                    for url in URL_RE.findall(str(a.get(key) or "")):
                        dom = re.sub(r"^https?://", "", url).split("/")[0]
                        targets.setdefault(("url", url), Target("url", url))
                        targets.setdefault(("domain", dom), Target("domain", dom))
                continue
            keys = self.store.keys_of(e.id)
            if e.kind == "asset":
                name = a.get("hostname") or a.get("fqdn") or e.display_name
                if name and not a.get("deception"):
                    targets.setdefault(("host", str(name).split(".")[0]), Target("host", str(name).split(".")[0], e.id))
                if a.get("ip"):
                    targets.setdefault(("ip", a["ip"]), Target("ip", a["ip"], e.id))
            elif e.kind == "identity":
                upn = keys.get("upn")
                if upn:
                    targets.setdefault(("user", upn), Target("user", upn, e.id))
            elif e.kind == "indicator":
                t, _, v = (e.canonical_key or keys.get("value", "")).partition(":")
                etype = {"sha256": "hash", "sha1": "hash", "md5": "hash"}.get(t, t)
                if etype in {"ip", "domain", "url", "hash"} and v:
                    targets.setdefault((etype, v), Target(etype, v, e.id))
        if since:
            for t in targets.values():
                t.context["since"] = (since - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ")
        return list(targets.values())

    # ------------------------------------------------------------------ IM-F04..F07 investigation

    def investigate(self, case_id: str) -> dict[str, Any]:
        case = self.s.get(Case, case_id)
        targets = self.extract_entities(case_id)
        outcome = EnrichmentOrchestrator(self.s, self.registry).enrich(case_id, targets, actor=f"agent:{AGENT}")
        evidence = self.s.execute(select(Evidence).where(Evidence.case_id == case_id)).scalars().all()

        # Exposure-informed severity (U06): KEV-listed findings on involved hosts.
        kev = self._kev_findings_on_case_hosts(case_id)
        for f in kev:
            self.cases.add_evidence(case_id, summary=f"Host {f['host']} carries KEV-listed {f['cve']} "
                                                     f"(CVSS {f.get('cvss')}) reported by {f['tool']}",
                                    source=f["tool"], dimension="exposure", entity_id=f["host_id"])
        evidence = self.s.execute(select(Evidence).where(Evidence.case_id == case_id)).scalars().all()
        ev_llm = evidence_for_llm(evidence)

        severity, confidence, factors = self._score(case, evidence, bool(kev))
        mitre = self._mitre(case_id, evidence, ev_llm)
        question = (f"Assess this security incident '{case.title}'. Summarise what happened, which accounts and hosts are "
                    "affected, whether this is a true positive, and what is uncertain.")
        grounded = self.llm.grounded("incident.summary", question, ev_llm) if self.llm else deterministic_grounded(ev_llm)
        verdict = "true_positive" if severity_rank(severity) >= 3 and confidence >= 0.6 else \
            "needs_review" if severity_rank(severity) >= 2 else "likely_benign"
        self.cases.set_assessment(case, verdict=verdict, severity=severity, confidence=confidence,
                                  summary=grounded["summary"],
                                  assessment={"claims": grounded["claims"], "mitre": mitre, "scoring": factors,
                                              "insufficient_evidence": grounded.get("insufficient_evidence", False),
                                              "evidence_index": {e["id"]: e["evidence_row"] for e in ev_llm},
                                              "similar_incidents": self.similar(case_id)},
                                  completeness=outcome.completeness(), actor=f"agent:{AGENT}")
        recs = self._recommendations(case, evidence, ev_llm, severity)
        self.cases.recommend(case, recs, self.actions, self.policy, agent=AGENT)
        return self.cases.view(case_id)

    def _kev_findings_on_case_hosts(self, case_id: str) -> list[dict[str, Any]]:
        kev_conn = self.registry.get("cisa_kev") if "cisa_kev" in self.registry.enabled_names() else None
        catalog = kev_conn.catalog() if kev_conn else {}
        out = []
        for ln in self.s.execute(select(CaseEntity).where(CaseEntity.case_id == case_id)).scalars():
            host = self.s.get(Entity, ln.entity_id)
            if host is None or host.kind != "asset":
                continue
            for f in self.store.events_for(host.id, kinds={"finding"}):
                cve = (f.attributes or {}).get("cve")
                if cve and (cve in catalog or (f.attributes or {}).get("kev")):
                    out.append({"host": host.display_name, "host_id": host.id, "cve": cve,
                                "cvss": (f.attributes or {}).get("cvss"), "tool": (f.attributes or {}).get("tool")})
        uniq = {(x["host_id"], x["cve"]): x for x in out}
        return list(uniq.values())

    @staticmethod
    def _signals(evidence: list[Evidence]) -> list[tuple[Evidence, dict[str, Any]]]:
        return [(e, (e.data or {}).get("signals") or {}) for e in evidence]

    def _score(self, case: Case, evidence: list[Evidence], kev: bool) -> tuple[str, float, dict[str, Any]]:
        """Deterministic severity/confidence from structured connector signals (no model-generated figures, R02)."""
        base = severity_rank(case.severity)
        sig = self._signals(evidence)
        dims: set[str] = set()
        factors: dict[str, Any] = {"base_alert_severity": SEV[base]}

        def any_sig(key: str, pred=lambda v: bool(v)) -> list[Evidence]:
            return [e for e, s in sig if key in s and pred(s[key])]

        if any_sig("deception_hits"):
            base, factors["deception_hit"] = 4, True
            dims.add("deception")
        if any_sig("risky_signins") or any_sig("user_risk", lambda v: v in {"high", "medium"}):
            factors["risky_signin"] = True
            dims.add("identity")
        if any_sig("suspicious_inbox_rules"):
            factors["mailbox_rule"] = True
            dims.add("identity")
        if any_sig("sensitive_access"):
            factors["privileged_credential_access"] = True
            dims.add("privileged_access")
        if any_sig("endpoint_alerts") or any_sig("malicious"):
            dims.add("endpoint")
        if any_sig("verdict", lambda v: v == "malicious"):
            factors["threat_intel_malicious"] = True
            dims.add("threat_intel")
        if any_sig("allowed") or any_sig("clicks"):
            factors["destination_reached"] = True
            dims.add("dns")
        if kev:
            factors["kev_exposure_boost"] = True
            base = min(4, base + 1)
            dims.add("exposure")
        if len(dims) >= 3:
            base = max(base, 3)
        confidence = min(0.95, 0.35 + 0.1 * len(dims))
        factors["corroborating_dimensions"] = sorted(dims)
        return SEV[base], round(confidence, 2), factors

    def _mitre(self, case_id: str, evidence: list[Evidence], ev_llm: list[dict[str, Any]]) -> list[dict[str, Any]]:
        by_row = {e["evidence_row"]: e["id"] for e in ev_llm}
        techniques: dict[str, dict[str, Any]] = {}
        for ln in self.s.execute(select(CaseEntity).where(CaseEntity.case_id == case_id, CaseEntity.role == "alert")).scalars():
            a = (self.s.get(Entity, ln.entity_id).attributes or {})
            for t in [a.get("technique_id"), *(a.get("mitre_techniques") or [])]:
                if t:
                    techniques.setdefault(t, {"technique": t, "name": a.get("technique") or "", "basis": "alert",
                                              "evidence_ids": []})
        rules = [("deception_hits", "T1039", "Data from Network Shared Drive (deception token touched)"),
                 ("suspicious_inbox_rules", "T1114.003", "Email Forwarding Rule"),
                 ("risky_signins", "T1078", "Valid Accounts"),
                 ("sensitive_access", "T1555", "Credentials from Password Stores"),
                 ("clicks", "T1566.002", "Spearphishing Link"),
                 ("new_devices", "T1098.005", "Device Registration")]
        for e, s in self._signals(evidence):
            for key, tid, name in rules:
                if s.get(key):
                    t = techniques.setdefault(tid, {"technique": tid, "name": name, "basis": "evidence", "evidence_ids": []})
                    if e.id in by_row:
                        t["evidence_ids"].append(by_row[e.id])
        return sorted(techniques.values(), key=lambda x: x["technique"])

    def _recommendations(self, case: Case, evidence: list[Evidence], ev_llm: list[dict[str, Any]],
                         severity: str) -> list[Recommendation]:
        by_row = {e["evidence_row"]: e["id"] for e in ev_llm}
        sig = self._signals(evidence)

        def cite(pred) -> list[str]:
            return [by_row[e.id] for e, s in sig if e.id in by_row and pred(e, s)]

        recs: list[Recommendation] = []
        hosts, users = [], []
        for ln in self.s.execute(select(CaseEntity).where(CaseEntity.case_id == case.id)).scalars():
            e = self.s.get(Entity, ln.entity_id)
            if e is None or ln.role == "alert":
                continue
            keys = self.store.keys_of(e.id)
            attrs = e.attributes or {}
            if e.kind == "asset" and not attrs.get("deception") and (keys.get("crowdstrike_aid") or keys.get("mde_device_id")):
                if not any(h["id"] == e.display_name for h in hosts):
                    hosts.append({"type": "asset", "id": e.display_name,
                                  **{k: v for k, v in keys.items() if k in {"crowdstrike_aid", "mde_device_id"}},
                                  "tags": attrs.get("tags", []), "criticality": attrs.get("criticality")})
            if e.kind == "identity" and keys.get("upn") and not any(u["upn"] == keys["upn"] for u in users):
                users.append({"type": "identity", "id": keys["upn"], "upn": keys["upn"],
                              "entra_object_id": keys.get("entra_object_id")})
        high = severity_rank(severity) >= 3
        identity_compromise = any(s.get("risky_signins") or s.get("suspicious_inbox_rules") or
                                  s.get("user_risk") in {"high"} for _, s in sig)
        if high and hosts:
            recs.append(Recommendation(
                "endpoint.isolate", hosts, "Contain the affected endpoint(s); network isolation is reversible and "
                "preserves forensic state.", cite(lambda e, s: s.get("endpoint_alerts") or s.get("deception_hits")),
                expected_impact="Stops C2 and lateral movement from the host",
                blast_radius=f"{len(hosts)} host(s); user loses network access until released", priority=10))
            recs.append(Recommendation(
                "endpoint.collect_forensics", hosts, "Collect volatile evidence (processes, connections, temp files) "
                "before any remediation.", cite(lambda e, s: s.get("endpoint_alerts")),
                expected_impact="Preserves forensic evidence", blast_radius="none (read-only collection)", priority=12))
        if users and identity_compromise:
            idc = cite(lambda e, s: s.get("risky_signins") or s.get("suspicious_inbox_rules") or s.get("new_devices"))
            recs.append(Recommendation("identity.revoke_sessions", users, "Risky sign-in and mailbox tampering indicate "
                                       "session theft; revoke refresh tokens.", idc,
                                       expected_impact="Forces re-authentication with MFA",
                                       blast_radius=f"{len(users)} user(s) signed out everywhere", reversible=False,
                                       priority=15))
            recs.append(Recommendation("identity.reset_password", users, "Credential likely exposed; force a change at "
                                       "next sign-in.", idc, expected_impact="Invalidates the stolen password",
                                       blast_radius=f"{len(users)} user(s)", reversible=False, priority=18))
        if any(s.get("suspicious_inbox_rules") for _, s in sig):
            recs.append(Recommendation("mailbox.remove_inbox_rule", users, "Remove the external forwarding / hiding "
                                       "inbox rule (manual in Exchange admin until a connector action is approved).",
                                       cite(lambda e, s: s.get("suspicious_inbox_rules")), priority=19))
        secrets = sorted({x for _, s in sig for x in s.get("secrets") or []})
        if secrets:
            recs.append(Recommendation("pam.rotate_secret", [{"type": "secret", "id": x, "secret_id": x} for x in secrets],
                                       "Privileged secret(s) were viewed/copied after compromise indicators; rotate.",
                                       cite(lambda e, s: s.get("sensitive_access")),
                                       expected_impact="Invalidates the exposed credential",
                                       blast_radius="services using the secret must pick up the new value", priority=20))
        seen: set[tuple[str, str]] = set()
        for e, s in sig:
            if e.source_tool != "threat_intel" or s.get("verdict") != "malicious":
                continue
            lookup, value = (e.data or {}).get("lookup"), (e.data or {}).get("value")
            if lookup == "url":
                domain = re.sub(r"^https?://", "", value).split("/")[0]
                items = [("domain", domain), ("url", value)]
            else:
                items = [({"hash": "sha256"}.get(lookup, lookup), value)]
            for itype, v in items:
                if (itype, v) in seen:
                    continue
                seen.add((itype, v))
                tgt = [{"type": "indicator", "id": v, "value": v, "indicator_type": itype}]
                ref = [by_row[e.id]] if e.id in by_row else []
                if itype == "domain":
                    recs.append(Recommendation("dns.block_domain", tgt, f"Threat intel rates {v} malicious.", ref,
                                               expected_impact="Blocks resolution org-wide at Umbrella",
                                               blast_radius="1 domain", priority=25))
                recs.append(Recommendation("indicator.block", tgt, f"Block {itype} {v} on endpoints.", ref,
                                           expected_impact="EDR blocks the indicator", blast_radius="1 indicator",
                                           priority=26))
        if high:
            recs.append(Recommendation("ticket.create", [], "Track containment and follow-up in ITSM.", [],
                                       params={"title": f"[SOC] {case.title}", "description": case.summary or case.title,
                                               "group": "SOC", "priority": 1 if severity == "critical" else 2,
                                               "correlation_id": case.id}, priority=60))
        return recs

    # ------------------------------------------------------------------ IM-F11 similar incidents

    def _signature(self, case_id: str) -> set[str]:
        case = self.s.get(Case, case_id)
        sig = {f"t:{t['technique']}" for t in (case.assessment or {}).get("mitre", [])}
        sig |= {f"w:{w}" for w in re.findall(r"[a-z]{4,}", (case.title or "").lower())}
        for ln in self.s.execute(select(CaseEntity).where(CaseEntity.case_id == case_id)).scalars():
            sig.add(f"r:{ln.role}")
        return sig

    def similar(self, case_id: str, limit: int = 3) -> list[dict[str, Any]]:
        mine = self._signature(case_id)
        out = []
        for c in self.s.execute(select(Case).where(Case.domain == "incident", Case.id != case_id,
                                                   Case.status == "closed")).scalars():
            other = self._signature(c.id)
            j = len(mine & other) / len(mine | other) if mine | other else 0
            if j >= 0.25:
                d = self.s.execute(select(Disposition).where(Disposition.subject_id == c.id)).scalars().first()
                out.append({"case_id": c.id, "title": c.title, "similarity": round(j, 2),
                            "disposition": d.analyst_verdict if d else c.verdict,
                            "analyst_reasoning": d.reasoning if d else ""})
        return sorted(out, key=lambda x: -x["similarity"])[:limit]

    # ------------------------------------------------------------------ U04 Canary auto-triage

    def triage_deception(self) -> list[dict[str, Any]]:
        out = []
        for case in self.s.execute(select(Case).where(Case.domain == "incident", Case.status == "open")).scalars():
            if (case.attributes or {}).get("deception"):
                out.append(self.investigate(case.id))
        return out

    # ------------------------------------------------------------------ IM-F13 shift handover

    def handover(self, *, hours: int = 12) -> dict[str, Any]:
        since = utcnow() - timedelta(hours=hours)
        open_cases = self.s.execute(select(Case).where(Case.domain == "incident", Case.status != "closed")).scalars().all()
        new = [c for c in open_cases if c.created_at.replace(tzinfo=None) >= since.replace(tzinfo=None)]
        closed = self.s.execute(select(Case).where(Case.domain == "incident", Case.status == "closed")).scalars().all()
        closed_recent = [c for c in closed if c.closed_at and c.closed_at.replace(tzinfo=None) >= since.replace(tzinfo=None)]
        by_sev: dict[str, int] = defaultdict(int)
        for c in open_cases:
            by_sev[c.severity] += 1
        awaiting = [c for c in open_cases if c.status == "awaiting_approval"]
        return {"window_hours": hours, "open_total": len(open_cases), "open_by_severity": dict(by_sev),
                "new_this_shift": len(new), "closed_this_shift": len(closed_recent),
                "awaiting_approval": [{"case_id": c.id, "title": c.title, "severity": c.severity} for c in awaiting],
                "top_open": [{"case_id": c.id, "title": c.title, "severity": c.severity, "status": c.status,
                              "summary": (c.summary or "")[:240]}
                             for c in sorted(open_cases, key=lambda c: -severity_rank(c.severity))[:10]]}
