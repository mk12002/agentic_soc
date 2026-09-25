"""Reported / Phishing Email Handling domain (section 8: PH-F01..F16, PH-T01..T09, U08, U16).

Workflow for each user report:
  ingest (PH-F01) -> decompose (F02) -> multi-signal analysis (F03, engine and/or heuristic)
  -> control reconciliation (F04) -> campaign scope (F05) -> user interaction + endpoint +
  identity impact (F06-F08) -> consolidated case with grounded explanation (F09, F10)
  -> gated remediation recommendations (F11) -> reporter feedback draft (F12)
  -> auto-close policy with analyst sampling (F13) -> indicator propagation on
  confirmation (F15). Reporting (F14) and audit (F16) run over the same records.
Shadow mode (PH-T08) is the default: everything is recommended, nothing executes
until an analyst approves or an action type is promoted in the autonomy policy.
"""

from __future__ import annotations

import hashlib
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from soc_platform.connectors.registry import ConnectorRegistry
from soc_platform.core.actions import ActionRegistry
from soc_platform.core.audit import AuditLog
from soc_platform.core.auth import Principal
from soc_platform.core.crypto import read_protected, write_protected
from soc_platform.core.cases import CaseService, Recommendation
from soc_platform.core.context_store import ContextStore
from soc_platform.core.enrichment import evidence_for_llm
from soc_platform.core.models import ActionRequest, Case, Entity, Evidence, utcnow
from soc_platform.core.policy import PolicyEngine
from soc_platform.core.schema import EntityRef, NormalizedRecord
from soc_platform.domains.phishing.agents.analyzer import AnalysisResult, CompositeAnalyzer, EngineAnalyzer, HeuristicAnalyzer
from soc_platform.domains.phishing.agents.decompose import DecomposedEmail, decompose
from soc_platform.domains.phishing.agents.investigation import campaign_scope, reconcile, user_impact
from soc_platform.domains.phishing.models import Submission
from soc_platform.llm.gateway import LLMGateway, deterministic_grounded
from soc_platform.llm.redaction import Redactor

AGENT = "phishing"
SEVERITY = {"malicious": "high", "suspicious": "medium", "spam": "low", "safe": "informational"}

FEEDBACK = {
    "malicious": ("Thank you - the email you reported was malicious",
                  "Thank you for reporting \"{subject}\". Our security team confirmed it was a phishing attempt and has "
                  "removed it from mailboxes across the organisation. If you clicked the link or entered your password, "
                  "please contact the IT service desk immediately."),
    "suspicious": ("Thank you - we are investigating the email you reported",
                   "Thank you for reporting \"{subject}\". It shows suspicious characteristics and the security team is "
                   "investigating. Please do not interact with it."),
    "spam": ("Thank you - the email you reported is spam",
             "Thank you for reporting \"{subject}\". It is unsolicited bulk mail rather than a targeted attack. You can "
             "safely delete it."),
    "safe": ("Thank you - the email you reported is legitimate",
             "Thank you for reporting \"{subject}\". Our checks found it to be legitimate. Reporting anything that looks "
             "unusual is always the right call - thank you for staying vigilant."),
}


@dataclass
class AutoClosePolicy:
    """PH-F13: close clear-benign / clear-spam reports; sample a share for analyst QA."""

    enabled: bool = True
    verdicts: tuple[str, ...] = ("safe", "spam")
    min_confidence: float = 0.7
    sample_rate: float = 0.1

    def sampled(self, key: str) -> bool:
        return int(hashlib.sha256(key.encode()).hexdigest(), 16) % 1000 < int(self.sample_rate * 1000)


class PhishingService:
    def __init__(self, session: Session, registry: ConnectorRegistry, *, policy: PolicyEngine | None = None,
                 llm: LLMGateway | None = None, actions: ActionRegistry | None = None, use_engine: bool = False,
                 org_domains: list[str] | None = None, auto_close: AutoClosePolicy | None = None,
                 raw_dir: str | Path = "./data/raw/phishing", campaign_threshold: float = 0.5) -> None:
        self.s = session
        self.registry = registry
        self.policy = policy or PolicyEngine.for_session(session)
        self.llm = llm
        self.actions = actions or registry.action_registry()
        self.cases = CaseService(session)
        self.store = ContextStore(session)
        self.audit = AuditLog(session)
        self.org_domains = [d.lower() for d in (org_domains or [])]
        ti = registry.get("threat_intel") if "threat_intel" in registry.enabled_names() else None
        from soc_platform.domains.phishing.supplier import load_suppliers

        partners = [d for sup in load_suppliers() for d in sup.domains]
        heuristic = HeuristicAnalyzer(org_domains=self.org_domains, threat_intel=ti, partner_domains=partners)
        self.analyzer = CompositeAnalyzer(heuristic, EngineAnalyzer() if use_engine else None)
        self.auto_close = auto_close or AutoClosePolicy()
        self.raw_dir = Path(raw_dir)
        self.campaign_threshold = campaign_threshold

    # ------------------------------------------------------------------ PH-F01 ingestion

    def submit_raw(self, raw: bytes, *, source: str, source_ref: str | None = None,
                   reporter: str | None = None) -> Submission:
        sha = hashlib.sha256(raw).hexdigest()
        ref = source_ref or f"{source}:{sha}"
        existing = self.s.execute(select(Submission).where(Submission.source_ref == ref)).scalars().first()
        if existing:
            return existing  # replay-safe
        path = self.raw_dir / f"{sha}.eml"
        write_protected(path, raw)  # original message preserved intact (headers included); encrypted at rest
        em = decompose(raw)
        sub = Submission(source=source, source_ref=ref, reporter=(reporter or "").lower() or None,
                         internet_message_id=em.message_id, subject=em.subject, sender=em.sender, mime_sha256=sha,
                         raw_path=str(path))
        self.s.add(sub)
        self.s.flush()
        self.audit.append(actor_type="agent", actor_id=f"agent:{AGENT}", event_type="phishing.reported",
                          subject_type="submission", subject_id=sub.id,
                          payload={"source": source, "reporter": sub.reporter, "sha256": sha, "subject": em.subject})
        return sub

    def ingest_reported(self) -> list[Submission]:
        """Pull user-reported messages from the SOC reporting mailbox (Defender user-reported settings)."""
        mdo = self.registry.get("defender_office365") if "defender_office365" in self.registry.enabled_names() else None
        if mdo is None:
            return []
        subs, cursor = [], None
        for _ in range(100):
            page = mdo.fetch_page("reported_messages", cursor)
            for rep in page.records:
                if self.s.execute(select(Submission.id).where(Submission.source_ref == f"mdo:{rep['id']}")).first():
                    continue            # already ingested: don't re-download the message, don't return it again
                raw, _att = mdo.original_mime(rep["id"])
                if not raw:
                    continue
                reporter = ((rep.get("from") or {}).get("emailAddress") or {}).get("address")
                subs.append(self.submit_raw(raw, source="defender_office365", source_ref=f"mdo:{rep['id']}",
                                            reporter=reporter))
            if not page.more:
                break
            cursor = page.next_cursor
        return subs

    # ------------------------------------------------------------------ full pipeline

    def process(self, submission_id: str, *, force: bool = False) -> dict[str, Any]:
        """Analyse a submission into a case. Idempotent: a submission that already has a case returns that case
        (re-running an ingest or a job never creates a second case for the same report); ``force`` re-analyses."""
        sub = self.s.get(Submission, submission_id)
        if sub is None:
            raise KeyError(f"unknown submission {submission_id}")
        if sub.case_id and not force and self.s.get(Case, sub.case_id) is not None:
            return self.cases.view(sub.case_id)
        if not sub.raw_path:
            raise ValueError("original message no longer retained (retention policy)")
        raw = read_protected(sub.raw_path)
        em = decompose(raw)
        result = self.analyzer.analyze(em, raw)
        case = self.cases.create("phishing", f"Reported: {em.subject or '(no subject)'}", severity=SEVERITY[result.verdict],
                                 attributes={"submission_id": sub.id, "reporter": sub.reporter, "sender": em.sender,
                                             "internet_message_id": em.message_id,
                                             "detection_source": f"user_report:{em.sender_domain}"},
                                 actor=f"agent:{AGENT}")
        sub.case_id = case.id
        self._link_entities(case, sub, em)
        for sig in result.signals:
            self.cases.add_evidence(case.id, summary=sig.evidence, source=f"phishing.{sig.agent}", dimension="email",
                                    data={"signal": sig.name, "weight": sig.weight})
        for w in em.warnings:
            self.cases.add_evidence(case.id, summary=f"Decomposition warning: {w}", source="phishing.decompose",
                                    dimension="email", is_inference=True)
        unavailable: list[str] = []
        rec = reconcile(self.registry, em, result.verdict)
        camp = {"members": [], "recipients": [], "evidence": [], "unavailable": []}
        impact = {"per_user": {}, "clicked": [], "reached_site": [], "identity_compromise": [], "endpoint_impact": [],
                  "evidence": [], "unavailable": []}
        if result.verdict in {"malicious", "suspicious"} or rec["disagreements"]:
            camp = campaign_scope(self.registry, em, threshold=self.campaign_threshold)
            recips = sorted(set(camp["recipients"]) | set(em.to) | ({sub.reporter} if sub.reporter else set()))
            impact = user_impact(self.registry, em, recips)
        for upn in sorted(set(camp["recipients"]) | set(impact["clicked"]) | set(impact["identity_compromise"])):
            ent = self.store.find("identity", "upn", upn)
            if ent is not None:
                role = ("compromised" if upn in impact["identity_compromise"] else
                        "clicked" if upn in impact["clicked"] else "recipient")
                self.cases.link(case.id, ent.id, role)
        for block in (rec, camp, impact):
            unavailable += block.get("unavailable", [])
            for ev in block.get("evidence", []):
                self.cases.add_evidence(case.id, summary=ev.summary, source=ev.source, dimension=ev.dimension,
                                        data=ev.data, deep_link=ev.deep_link, is_inference=ev.is_inference)
        sub.campaign_key = hashlib.sha256(f"{em.sender_domain}|{sorted(em.url_domains)}".encode()).hexdigest()[:16]

        # Grounded explanation over everything gathered (PH-F10). Figures stay in the evidence, not the model.
        evidence = self.s.execute(select(Evidence).where(Evidence.case_id == case.id)).scalars().all()
        ev_llm = evidence_for_llm(evidence)
        redactor = Redactor(internal_domains=set(self.org_domains))
        q = ("Explain whether this reported email is phishing, what makes it so, who else received it, who interacted "
             "with it and whether any account or device shows compromise. Separate facts from inferences.")
        grounded = (self.llm.grounded("phishing.explanation", q, ev_llm, redactor=redactor) if self.llm
                    else deterministic_grounded(ev_llm, limit=10))
        severity = SEVERITY[result.verdict]
        if impact["identity_compromise"] or impact["endpoint_impact"]:
            severity = "critical"
        elif impact["clicked"] and result.verdict == "malicious":
            severity = "high"
        completeness = {"complete": not unavailable, "unavailable": [{"source": u.split(":")[0], "error": u}
                                                                     for u in unavailable],
                        "analysis_backend": result.backend, "missing_agents": result.missing_agents}
        self.cases.set_assessment(case, verdict=result.verdict, severity=severity, confidence=result.confidence,
                                  summary=grounded["summary"] if grounded.get("source") == "llm" else
                                  self._fact_summary(em, result, camp, impact, rec),
                                  assessment={"claims": grounded["claims"], "score": result.score,
                                              "mitre": result.mitre + ([{"technique": "T1078", "name": "Valid Accounts"}]
                                                                       if impact["identity_compromise"] else []),
                                              "counterfactual": result.counterfactual,
                                              "engine_explanation": result.explanation,
                                              "signals": [s.__dict__ for s in result.signals],
                                              "reconciliation": {k: v for k, v in rec.items() if k != "evidence"},
                                              "campaign": {k: v for k, v in camp.items() if k != "evidence"},
                                              "user_impact": {k: v for k, v in impact.items() if k != "evidence"},
                                              "decomposition": {"auth": em.auth, "origin_ip": em.origin_ip,
                                                                "urls": em.urls, "qr_urls": em.qr_urls,
                                                                "attachments": [a.__dict__ for a in em.attachments],
                                                                "hops": len(em.received_path)},
                                              "backend_detail": result.raw},
                                  completeness=completeness, actor=f"agent:{AGENT}")
        sub.status, sub.verdict, sub.score = "analysed", result.verdict, result.score
        sub.analysis = {"verdict": result.verdict, "score": result.score, "backend": result.backend,
                        "campaign_recipients": len(camp["recipients"]), "clicked": impact["clicked"]}

        recs = self._recommendations(case, sub, em, result, camp, impact, ev_llm, evidence)
        self.cases.recommend(case, recs, self.actions, self.policy, agent=AGENT)
        self._apply_auto_close(case, sub, result, camp, impact, rec)
        return self.cases.view(case.id)

    def _fact_summary(self, em: DecomposedEmail, r: AnalysisResult, camp: dict, impact: dict, rec: dict) -> str:
        parts = [f"Verdict {r.verdict} (score {r.score:.2f}, backend {r.backend}) for '{em.subject}' from {em.sender}."]
        top = sorted(r.signals, key=lambda s: -s.weight)[:3]
        if top:
            parts.append("Key signals: " + "; ".join(s.evidence for s in top) + ".")
        if camp["recipients"]:
            parts.append(f"Campaign reached {len(camp['recipients'])} recipient(s).")
        if impact["clicked"]:
            parts.append(f"Clicked by {', '.join(impact['clicked'])}.")
        if impact["identity_compromise"]:
            parts.append(f"Identity compromise indicators for {', '.join(impact['identity_compromise'])}.")
        if impact["endpoint_impact"]:
            parts.append(f"Endpoint activity for {', '.join(impact['endpoint_impact'])}.")
        for d in rec["disagreements"]:
            parts.append(f"{', '.join(d['controls'])} did not flag this message.")
        return " ".join(parts)

    def _link_entities(self, case: Case, sub: Submission, em: DecomposedEmail) -> None:
        refs = [EntityRef(kind="indicator", role="sender", keys={"value": em.sender}, attributes={"type": "email"})] \
            if em.sender else []
        refs += [EntityRef(kind="indicator", role="url_domain", keys={"value": d}, attributes={"type": "domain"})
                 for d in em.url_domains if d not in self.org_domains]
        refs += [EntityRef(kind="indicator", role="url", keys={"value": u}, attributes={"type": "url"}) for u in em.urls[:20]]
        refs += [EntityRef(kind="indicator", role="attachment", keys={"value": a.sha256}, attributes={"type": "sha256"})
                 for a in em.attachments]
        if em.origin_ip:
            refs.append(EntityRef(kind="indicator", role="sender_ip", keys={"value": em.origin_ip}, attributes={"type": "ip"}))
        refs += [EntityRef(kind="identity", role="recipient", keys={"upn": r}) for r in em.to
                 if r.split("@")[-1] in self.org_domains or not self.org_domains]
        if sub.reporter:
            refs.append(EntityRef(kind="identity", role="reporter", keys={"upn": sub.reporter}))
        src = self.store.ingest(NormalizedRecord(kind="email", tool="phishing", source_type="reported_email",
                                                 source_id=sub.mime_sha256 or sub.id, title=em.subject, refs=refs,
                                                 dimension="email", attributes={"sender": em.sender, "subject": em.subject,
                                                                                "message_id": em.message_id}))
        self.cases.link(case.id, src.entity_id, "email")
        for rel, ent in self.store.neighbors(src.entity_id):
            self.cases.link(case.id, ent.id, rel.rel_type)

    # ------------------------------------------------------------------ PH-F11 recommendations

    def _recommendations(self, case: Case, sub: Submission, em: DecomposedEmail, r: AnalysisResult, camp: dict,
                         impact: dict, ev_llm: list[dict[str, Any]], evidence: list[Evidence]) -> list[Recommendation]:
        by_row = {e["evidence_row"]: e["id"] for e in ev_llm}
        cite = lambda *srcs: [by_row[e.id] for e in evidence if e.id in by_row and  # noqa: E731
                              any(e.source_tool.startswith(s) for s in srcs)]
        recs: list[Recommendation] = []
        if sub.reporter:
            subject, body = FEEDBACK[r.verdict]
            recs.append(Recommendation("email.reporter_feedback", [{"type": "identity", "id": sub.reporter,
                                                                    "upn": sub.reporter}],
                                       "Close the loop with the reporting user.", cite("phishing"),
                                       params={"subject": subject, "body_html": body.format(subject=em.subject)},
                                       expected_impact="Reporter informed", blast_radius="1 user", priority=90))
        if r.verdict not in {"malicious", "suspicious"}:
            return recs
        vip = {v.lower() for v in self.policy.document.get("vip", {}).get("identities", [])}
        members = [m for m in camp["members"] if (m.get("delivery_location") or "").lower() != "junk"]
        if members:
            recs.append(Recommendation(
                "email.campaign_purge",
                [{"type": "email", "id": f"{m['network_message_id']}:{m['recipient']}",
                  "network_message_id": m["network_message_id"], "recipient": m["recipient"],
                  "vip": m["recipient"] in vip} for m in members],
                f"Soft-delete {len(members)} delivered cop(ies) of the campaign across the tenant (reversible).",
                cite("defender_office365", "phishing"), params={"mode": "softDelete", "reason": f"case {case.id}"},
                expected_impact="Removes the lure from every mailbox",
                blast_radius=f"{len(members)} message(s) in {len({m['recipient'] for m in members})} mailbox(es)",
                priority=10))
        users = impact["identity_compromise"]
        if users:
            tg = [{"type": "identity", "id": u, "upn": u,
                   "entra_object_id": impact["per_user"][u]["identity"].get("entra_object_id"), "vip": u in vip}
                  for u in users]
            recs.append(Recommendation("identity.revoke_sessions", tg, "Risky sign-in / mailbox rule after the click "
                                       "indicates credential theft; revoke sessions.", cite("entra"),
                                       expected_impact="Attacker sessions invalidated", blast_radius=f"{len(tg)} user(s)",
                                       reversible=False, priority=11))
            recs.append(Recommendation("identity.reset_password", tg, "Force password change for compromised user(s).",
                                       cite("entra"), expected_impact="Stolen password invalidated",
                                       blast_radius=f"{len(tg)} user(s)", reversible=False, priority=12))
        hosts = []
        for u in impact["endpoint_impact"]:
            for d in impact["per_user"][u]["endpoint"].get("device_keys", []):
                t = {"type": "asset", "id": d["hostname"]}
                if d.get("mde_device_id"):
                    t["mde_device_id"] = d["mde_device_id"]
                ent = self.store.find("asset", "mde_device_id", d.get("mde_device_id") or "")
                if ent is not None:
                    t.update({k: v for k, v in self.store.keys_of(ent.id).items() if k == "crowdstrike_aid"})
                hosts.append(t)
        if hosts:
            recs.append(Recommendation("endpoint.isolate", hosts, "Campaign indicators executed on the device(s); "
                                       "isolate pending forensic review.", cite("defender_endpoint", "crowdstrike"),
                                       expected_impact="Stops follow-on payload activity",
                                       blast_radius=f"{len(hosts)} host(s)", priority=13))
        for d in em.url_domains:
            if d in self.org_domains:
                continue
            tgt = [{"type": "indicator", "id": d, "value": d, "indicator_type": "domain"}]
            recs.append(Recommendation("dns.block_domain", tgt, f"Block phishing domain {d} at Umbrella.",
                                       cite("phishing.url", "phishing.threat_intel", "umbrella"),
                                       expected_impact="Stops further clicks resolving", blast_radius="1 domain",
                                       priority=20))
            recs.append(Recommendation("indicator.block", tgt, f"Block {d} on endpoints (Defender indicator).",
                                       cite("phishing"), expected_impact="EDR blocks the destination",
                                       blast_radius="1 indicator", priority=21))
        for a in em.attachments:
            if a.risky_extension or a.has_macros_hint:
                recs.append(Recommendation("indicator.block", [{"type": "indicator", "id": a.sha256, "value": a.sha256,
                                                                "indicator_type": "sha256"}],
                                           f"Block attachment {a.filename} by hash.", cite("phishing.attachment"),
                                           priority=22))
        if em.sender_domain and em.sender_domain not in self.org_domains and r.verdict == "malicious":
            recs.append(Recommendation("email.block_sender", [{"type": "indicator", "id": em.sender_domain,
                                                               "value": em.sender_domain, "indicator_type": "domain"}],
                                       f"Block sender domain {em.sender_domain} in the tenant allow/block list.",
                                       cite("phishing.header"), priority=23))
        if r.verdict == "malicious" and (users or hosts or impact["clicked"]):
            recs.append(Recommendation("ticket.create", [], "Track phishing compromise follow-up.", [],
                                       params={"title": f"[Phishing] {em.subject}", "description": case.summary,
                                               "group": "SOC", "priority": 1, "correlation_id": case.id}, priority=60))
        return recs

    # ------------------------------------------------------------------ PH-F13 auto-close with sampling

    def _apply_auto_close(self, case: Case, sub: Submission, r: AnalysisResult, camp: dict, impact: dict,
                          rec: dict) -> None:
        p = self.auto_close
        gateway_flagged = any(d["type"] == "platform_less_severe" for d in rec["disagreements"])
        eligible = (p.enabled and r.verdict in p.verdicts and r.confidence >= p.min_confidence and not impact["clicked"]
                    and not gateway_flagged)
        if not eligible:
            sub.status = "escalated" if r.verdict in {"malicious", "suspicious"} or gateway_flagged else "analysed"
            return
        sub.auto_closed = True
        # stable key: the same message always gets the same QA decision (reproducible), still a uniform sample
        sub.sampled_for_review = p.sampled(f"{sub.mime_sha256 or sub.internet_message_id or sub.id}|{sub.reporter or ''}")
        if sub.sampled_for_review:
            sub.status = "auto_closed"
            case.status = "awaiting_qa"
        else:
            sub.status = "auto_closed"
            case.status, case.closed_at = "closed", utcnow()
        self.audit.append(actor_type="agent", actor_id=f"agent:{AGENT}", event_type="phishing.auto_closed",
                          subject_type="case", subject_id=case.id,
                          payload={"verdict": r.verdict, "confidence": r.confidence, "sampled": sub.sampled_for_review,
                                   "policy": p.__dict__})

    # ------------------------------------------------------------------ PH-F15 indicator propagation

    def confirm(self, case_id: str, analyst: Principal, *, verdict: str, reasoning: str = "") -> dict[str, Any]:
        d = self.cases.decide(case_id, analyst, verdict=verdict, reasoning=reasoning)
        propagated = []
        if verdict in {"malicious", "phishing", "true_positive"}:
            from soc_platform.core.models import CaseEntity

            for ln in self.s.execute(select(CaseEntity).where(CaseEntity.case_id == case_id)).scalars():
                e = self.s.get(Entity, ln.entity_id)
                if e is not None and e.kind == "indicator" and ln.role in {"sender", "url_domain", "url", "attachment",
                                                                          "sender_ip"}:
                    e.attributes = {**(e.attributes or {}), "confirmed_malicious": True, "confirmed_in_case": case_id,
                                    "confirmed_by": analyst.id, "confirmed_at": utcnow().isoformat()}
                    propagated.append(e.canonical_key or e.display_name)
            self.audit.append(actor_type="human", actor_id=analyst.id, event_type="phishing.indicators_propagated",
                              subject_type="case", subject_id=case_id, payload={"indicators": propagated})
        sub = self.s.execute(select(Submission).where(Submission.case_id == case_id)).scalars().first()
        if sub:
            sub.status = "closed"
        return {"disposition": d.analyst_verdict, "propagated_indicators": propagated}

    def confirmed_indicators(self) -> list[dict[str, Any]]:
        """Shared with incident and vulnerability workflows through the context store."""
        rows = self.s.execute(select(Entity).where(Entity.kind == "indicator")).scalars().all()
        return [{"indicator": e.canonical_key, "case": (e.attributes or {}).get("confirmed_in_case")}
                for e in rows if (e.attributes or {}).get("confirmed_malicious")]

    # ------------------------------------------------------------------ PH-F14 reporting

    def metrics(self) -> dict[str, Any]:
        subs = self.s.execute(select(Submission)).scalars().all()
        verdicts = Counter(s.verdict or "pending" for s in subs)
        clicks: Counter[str] = Counter()
        for s in subs:
            for u in (s.analysis or {}).get("clicked", []):
                clicks[u] += 1
        ttc = []
        for s in subs:
            if not s.case_id:
                continue
            first = self.s.execute(select(ActionRequest).where(
                ActionRequest.case_id == s.case_id, ActionRequest.status == "executed",
                ActionRequest.action_type.in_(("email.campaign_purge", "endpoint.isolate", "identity.revoke_sessions")))
                .order_by(ActionRequest.executed_at)).scalars().first()
            if first and first.executed_at:
                ttc.append((first.executed_at.replace(tzinfo=None) - s.received_at.replace(tzinfo=None)).total_seconds() / 60)
        return {"reported": len(subs), "verdict_mix": dict(verdicts),
                "auto_closed": sum(1 for s in subs if s.auto_closed),
                "sampled_for_qa": sum(1 for s in subs if s.sampled_for_review),
                "campaigns": len({s.campaign_key for s in subs if s.campaign_key and s.verdict in {"malicious", "suspicious"}}),
                "clickers": dict(clicks), "repeat_clickers": sorted(u for u, n in clicks.items() if n >= 2),
                "time_to_containment_minutes": {"median": sorted(ttc)[len(ttc) // 2] if ttc else None, "samples": len(ttc)},
                "top_reporters": Counter(s.reporter for s in subs if s.reporter).most_common(5)}
