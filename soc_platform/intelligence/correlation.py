"""Cross-domain correlation engine: deterministic rules over the shared context store that surface what no
single tool can see. Each rule emits an ``Insight`` with the exact evidence it relied on; the LLM analyst
(when configured) narrates insights but never creates them.

Rules and the requirement / use case each serves:
  phishing_compromise_chain   U08 phishing -> endpoint -> identity chaining
  privileged_after_compromise U07 privileged credential access after compromise indicators
  privileged_after_compromise U07 identity-centric risk (privileged access after compromise indicators)
  deception_corroborated      U04 / IM deception hit corroborated by other telemetry
  exposed_host_under_attack   U06 exposure-informed triage (KEV / P1 vuln on an attacked host)
  attacked_host_without_edr   VM-F17 / IM coverage gap on a host that is being attacked
  control_gap                 U10 continuous control validation (confirmed-bad destination still reachable)
  repeat_clicker              U16 targeted awareness
  new_kev_exposure            U02 / VM-F16 newly KEV-listed CVE present on internet-exposed assets
  shared_infrastructure       indicator seen across several users / hosts (campaign blast radius)
  entity_risk_high            U07 any user/host whose fused risk is high/critical across >= 3 dimensions
  supplier_risk               U18 vendor email compromise / impersonation / payment diversion
  model_drift                 R14 / NFR-13 verdict quality drift against analyst dispositions
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from collections import defaultdict
from datetime import timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from soc_platform.core.audit import AuditLog
from soc_platform.core.context_store import ContextStore
from soc_platform.core.models import Entity, utcnow
from soc_platform.intelligence.models import Insight
from soc_platform.intelligence.risk import RiskEngine, RiskProfile

SEV_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def _key(*parts: Any) -> str:
    return hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()[:40]


def _ev(f) -> dict[str, Any]:
    return {"ref": f.ref, "signal": f.signal, "source": f.source, "dimension": f.dimension, "when": f.when,
            "summary": f.detail}


def _basis(ins: Insight) -> str:
    """What a narrative is written from: severity and the evidence itself (not the time-decayed score, which the
    narrative is told not to state), so it is rewritten when the finding changes, not every scheduler tick."""
    ev = sorted(f"{e.get('signal')}|{e.get('summary')}|{e.get('when')}" for e in (ins.evidence or []))
    return json.dumps([ins.severity, ev])


class CorrelationEngine:
    def __init__(self, session: Session, *, risk: RiskEngine | None = None) -> None:
        self.s = session
        self.store = ContextStore(session)
        self.risk = risk or RiskEngine(session)

    # ------------------------------------------------------------------ public

    def run(self, entity_ids: list[str] | None = None) -> list[Insight]:
        if entity_ids is None:
            candidates = self.risk.candidates()          # entities without any risk source can raise no finding
            entity_ids = [e for e in self.s.execute(select(Entity.id).where(Entity.kind.in_(("asset", "identity")))).scalars()
                          if e in candidates]
        profiles = {eid: p for eid in entity_ids if (p := self.risk.profile(eid)) is not None}
        found: list[Insight] = []
        for p in profiles.values():
            for rule in (self._phishing_chain, self._privileged_after_compromise, self._deception_corroborated,
                         self._exposed_host_under_attack, self._attacked_host_without_edr, self._entity_risk_high):
                ins = rule(p)
                if ins is not None:
                    found.append(ins)
        found += (self._repeat_clickers() + self._control_gaps() + self._new_kev_exposure() + self._shared_infra()
                  + self._supplier_risk() + self._drift())
        stored = [self._upsert(i) for i in found]
        if stored:
            AuditLog(self.s).append(actor_type="agent", actor_id="agent:correlation", event_type="intelligence.run",
                                    subject_type="insight", subject_id="batch",
                                    payload={"insights": len(stored), "rules": sorted({i.rule for i in stored})})
        return stored

    # ------------------------------------------------------------------ per-entity rules

    def _phishing_chain(self, p: RiskProfile) -> Insight | None:
        if p.kind != "identity":
            return None
        click = [f for f in p.factors if f.signal == "phishing_click"]
        endpoint = [f for f in p.factors if f.signal == "endpoint_alert"]
        ident = [f for f in p.factors if f.signal in {"risky_signin", "identity_risk", "phishing_identity_compromise"}]
        # Endpoint alerts that name the user are already factors of the identity (alert -> user relation).
        if not (click and (endpoint or ident)):
            return None
        stages = ["click"] + (["endpoint execution"] if endpoint else []) + (["identity compromise"] if ident else [])
        sev = "critical" if endpoint and ident else "high"
        return Insight(rule="phishing_compromise_chain", dedupe_key=_key("chain", p.entity_id),
                       title=f"Phishing led to compromise of {p.name}: {' -> '.join(stages)}", severity=sev,
                       score=p.score, entity_ids=[p.entity_id], domains=["phishing", "incident"],
                       evidence=[_ev(f) for f in click + endpoint + ident],
                       next_steps=["Revoke sessions and reset credentials for the user",
                                   "Isolate the device that executed the payload pending forensics",
                                   "Purge the campaign tenant-wide and block its domains",
                                   "Review mailbox rules and new device registrations since the click"],
                       requirement_refs=["U08", "PH-F06", "PH-F07", "PH-F08"])

    def _privileged_after_compromise(self, p: RiskProfile) -> Insight | None:
        if p.kind != "identity":
            return None
        risk = [f for f in p.factors if f.signal in {"risky_signin", "identity_risk", "phishing_identity_compromise",
                                                      "phishing_click"}]
        priv = [f for f in p.factors if f.signal == "privileged_credential_access"]
        if not (risk and priv):
            return None
        first_risk = min((f.when for f in risk if f.when), default=None)
        after = [f for f in priv if not first_risk or (f.when or "") >= first_risk]
        if not after:
            return None
        return Insight(rule="privileged_after_compromise", dedupe_key=_key("priv", p.entity_id),
                       title=f"{p.name} accessed privileged credentials after compromise indicators", severity="critical",
                       score=p.score, entity_ids=[p.entity_id], domains=["incident"],
                       evidence=[_ev(f) for f in risk + after],
                       next_steps=["Rotate every secret the account accessed after the first risk signal",
                                   "Review privileged sessions launched by the account",
                                   "Temporarily remove standing privileged access"],
                       requirement_refs=["U07", "IM-F04"])

    def _deception_corroborated(self, p: RiskProfile) -> Insight | None:
        dec = [f for f in p.factors if f.signal == "deception_hit"]
        other = [f for f in p.factors if f.signal != "deception_hit" and f.dimension not in {"exposure", "coverage"}
                 and f.decayed > 0]
        if not (dec and other):
            return None
        return Insight(rule="deception_corroborated", dedupe_key=_key("dec", p.entity_id),
                       title=f"Deception hit on {p.name} corroborated by {len({f.dimension for f in other})} other "
                             "data source(s)", severity="critical", score=p.score, entity_ids=[p.entity_id],
                       domains=["incident"], evidence=[_ev(f) for f in dec + other],
                       next_steps=["Treat as active intrusion: contain the source host",
                                   "Hunt for lateral movement from the source host in the last 72 hours"],
                       requirement_refs=["U04", "IM-F04"])

    def _exposed_host_under_attack(self, p: RiskProfile) -> Insight | None:
        if p.kind != "asset":
            return None
        attack = [f for f in p.factors if (f.signal == "endpoint_alert" and f.weight >= 10) or f.signal == "deception_hit"]
        vuln = [f for f in p.factors if f.signal in {"kev_exposure", "priority_vulnerability"}]
        if not (attack and vuln):
            return None
        kev = any(f.signal == "kev_exposure" for f in vuln)
        exploit = any(re.search(r"exploit|T1190|public-facing", f.detail or "", re.IGNORECASE) for f in attack)
        what = "an exploitation attempt" if exploit else "active attack"
        return Insight(rule="exposed_host_under_attack", dedupe_key=_key("exp", p.entity_id),
                       title=f"{p.name} shows {what} and carries {'KEV-listed' if kev else 'priority'} vulnerabilities",
                       severity="critical" if kev else "high", score=p.score, entity_ids=[p.entity_id],
                       domains=["incident", "vulnerability"], evidence=[_ev(f) for f in attack + vuln],
                       next_steps=["Raise incident priority (exposure-informed triage)",
                                   "Emergency-patch or mitigate the listed CVEs on this host",
                                   "Check whether the alerts match exploitation of these CVEs"],
                       requirement_refs=["U06", "IM-F06", "VM-F04"])

    def _attacked_host_without_edr(self, p: RiskProfile) -> Insight | None:
        if p.kind != "asset" or "no_edr_coverage" not in p.signals():
            return None
        attack = [f for f in p.factors if f.signal in {"endpoint_alert", "deception_hit", "open_incident",
                                                        "malicious_destination_reached"}]
        if not attack:
            return None
        return Insight(rule="attacked_host_without_edr", dedupe_key=_key("noedr", p.entity_id),
                       title=f"{p.name} shows attack activity but has no EDR telemetry", severity="high",
                       score=p.score, entity_ids=[p.entity_id], domains=["incident", "vulnerability"],
                       evidence=[_ev(f) for f in attack], next_steps=["Deploy CrowdStrike/Defender to the host",
                                                                      "Investigate via network and identity telemetry"],
                       requirement_refs=["VM-F17", "IM-F15"])

    def _entity_risk_high(self, p: RiskProfile) -> Insight | None:
        if SEV_RANK.get(p.band, 0) < 3 or len(p.dimensions) < 3:
            return None
        return Insight(rule="entity_risk_high", dedupe_key=_key("risk", p.entity_id),
                       title=f"{p.kind.title()} {p.name}: {p.band} risk ({p.score:.0f}/100) across "
                             f"{', '.join(p.dimensions)}", severity=p.band, score=p.score, entity_ids=[p.entity_id],
                       domains=["incident", "phishing", "vulnerability"],
                       evidence=[_ev(f) for f in sorted(p.factors, key=lambda x: -x.decayed)[:8]],
                       next_steps=["Open the entity view and review the contributing signals"],
                       requirement_refs=["U07"])

    # ------------------------------------------------------------------ population rules

    def _repeat_clickers(self) -> list[Insight]:
        from soc_platform.domains.phishing.models import Submission

        clicks: dict[str, set[str]] = defaultdict(set)
        for sub in self.s.execute(select(Submission)).scalars():
            for u in (sub.analysis or {}).get("clicked", []):
                clicks[u].add(sub.campaign_key or sub.id)
        out = []
        for upn, campaigns in clicks.items():
            if len(campaigns) >= 2:
                ent = self.store.find("identity", "upn", upn)
                out.append(Insight(rule="repeat_clicker", dedupe_key=_key("rc", upn), severity="medium",
                                   title=f"{upn} clicked links in {len(campaigns)} different phishing campaigns",
                                   score=min(100.0, 30.0 * len(campaigns)), entity_ids=[ent.id] if ent else [],
                                   domains=["phishing"], evidence=[{"ref": c, "signal": "phishing_click",
                                                                    "source": "phishing", "summary": "campaign"}
                                                                   for c in sorted(campaigns)],
                                   next_steps=["Enrol in targeted awareness training", "Consider stricter Safe Links"],
                                   requirement_refs=["U16", "PH-F14"]))
        return out

    def _control_gaps(self) -> list[Insight]:
        """Destinations rated/confirmed malicious that a control still allowed (U10)."""
        out = []
        for ind in self.s.execute(select(Entity).where(Entity.kind == "indicator")).scalars():
            key = ind.canonical_key or ""
            if not key.startswith("domain:"):
                continue
            allowed = [e for _, e in self.store.neighbors(ind.id)
                       if e.kind == "dns" and (e.attributes or {}).get("verdict") == "allowed"
                       and (e.attributes or {}).get("severity") == "high"]
            confirmed = (ind.attributes or {}).get("confirmed_malicious")
            if allowed and (confirmed or len(allowed) >= 1):
                hosts = sorted({(e.attributes or {}).get("identity") or "" for e in allowed} - {""})
                out.append(Insight(rule="control_gap", dedupe_key=_key("cg", key), severity="high",
                                   title=f"{key.split(':', 1)[1]} is security-categorised yet was allowed "
                                         f"{len(allowed)} time(s)" + (" after being confirmed malicious" if confirmed else ""),
                                   score=60.0 + 5 * len(allowed), entity_ids=[ind.id], domains=["phishing", "incident"],
                                   evidence=[{"ref": e.id, "signal": "dns_allowed", "source": "umbrella",
                                              "when": e.first_seen.isoformat(), "summary": e.display_name} for e in allowed],
                                   next_steps=["Add the domain to the Umbrella block list (dns.block_domain)",
                                               f"Check the devices that resolved it: {', '.join(hosts) or 'n/a'}",
                                               "Verify Defender indicators enforce the same block"],
                                   requirement_refs=["U10"]))
        return out

    def _new_kev_exposure(self) -> list[Insight]:
        from soc_platform.domains.vulnerability.models import ConsolidatedFinding, VulnIntel

        out = []
        recent = (utcnow() - timedelta(days=14)).date().isoformat()
        for vi in self.s.execute(select(VulnIntel).where(VulnIntel.kev.is_(True))).scalars():
            if not vi.kev_date_added or vi.kev_date_added < recent:
                continue
            rows = self.s.execute(select(ConsolidatedFinding).where(
                ConsolidatedFinding.cve == vi.cve, ConsolidatedFinding.status.in_(("open", "reopened")))).scalars().all()
            if not rows:
                continue
            exposed = [r for r in rows if r.internet_exposed]
            out.append(Insight(rule="new_kev_exposure", dedupe_key=_key("kev", vi.cve), severity="critical" if exposed else "high",
                               title=f"Newly KEV-listed {vi.cve} is present on {len(rows)} asset(s)"
                                     + (f" ({len(exposed)} internet-exposed)" if exposed else ""),
                               score=90.0 if exposed else 70.0, entity_ids=[r.asset_id for r in rows],
                               domains=["vulnerability"],
                               evidence=[{"ref": r.id, "signal": "kev_exposure", "source": ",".join(sorted(r.sources)),
                                          "summary": f"{r.cve} on {r.asset_name} ({r.platform_team})"} for r in rows],
                               next_steps=[f"Open a remediation campaign for {vi.cve}", "Notify the owning teams"],
                               requirement_refs=["U02", "VM-F16"]))
        return out

    def _shared_infra(self) -> list[Insight]:
        out = []
        for ind in self.s.execute(select(Entity).where(Entity.kind == "indicator")).scalars():
            touched: set[str] = set()
            for _, ev in self.store.neighbors(ind.id):
                for _, ent in self.store.neighbors(ev.id, kinds={"asset", "identity"}):
                    touched.add(ent.id)
            if len(touched) >= 3:
                names = sorted(self.s.get(Entity, t).display_name for t in touched)
                out.append(Insight(rule="shared_infrastructure", dedupe_key=_key("si", ind.canonical_key), severity="medium",
                                   title=f"{ind.canonical_key} links {len(touched)} users/hosts",
                                   score=min(100.0, 15.0 * len(touched)), entity_ids=[ind.id, *sorted(touched)],
                                   domains=["incident", "phishing"],
                                   evidence=[{"ref": ind.id, "signal": "indicator", "source": "context_store",
                                              "summary": ", ".join(names[:10])}],
                                   next_steps=["Scope every linked entity for compromise"], requirement_refs=["IM-F02"]))
        return out

    # ------------------------------------------------------------------ persistence

    def _drift(self) -> list[Insight]:
        from soc_platform.intelligence.drift import drift_insights

        try:
            return drift_insights(self.s)
        except Exception:
            logging.getLogger(__name__).warning("drift rule failed; its findings are missing this run", exc_info=True)
            return []

    def _supplier_risk(self) -> list[Insight]:
        from soc_platform.domains.phishing.supplier import SupplierMonitor

        try:
            report = SupplierMonitor(self.s).assess()
        except Exception:
            logging.getLogger(__name__).warning("supplier rule failed; its findings are missing this run", exc_info=True)
            return []
        steps = {"supplier_account_compromise": [("Call the supplier on a number on file: their mailbox/tenant is likely "
                                                 "compromised"), "Hold pending payments to this supplier",
                                                 "Search and purge other messages from the sender"],
                 "supplier_payment_diversion": ["Do not change bank details on email instructions",
                                                "Verify with the supplier by phone (number from the vendor master)",
                                                "Alert accounts payable"],
                 "supplier_impersonation": ["Block the look-alike domain at the mail gateway and Umbrella",
                                            "Warn accounts payable / procurement"],
                 "supplier_spoofing": ["Ask the supplier to enforce DMARC (p=reject)",
                                       "Add a transport rule to quarantine unauthenticated mail claiming this domain"]}
        out = []
        for f in report["findings"]:
            out.append(Insight(rule="supplier_risk", dedupe_key=_key("sup", f["type"], f["case_id"]),
                               severity=f["severity"] if f["severity"] in SEV_RANK else "medium",
                               title=f"{f['supplier']}: {f['type'].replace('supplier_', '').replace('_', ' ')} "
                                     f"({f['sender']})",
                               score={"critical": 95.0, "high": 75.0, "medium": 50.0}.get(f["severity"], 30.0),
                               entity_ids=[], domains=["phishing"],
                               evidence=[{"ref": f["case_id"], "signal": f["type"], "source": "phishing",
                                          "summary": f["detail"]}],
                               next_steps=steps.get(f["type"], []), requirement_refs=["U18"]))
        return out

    def _upsert(self, ins: Insight) -> Insight:
        cur = self.s.execute(select(Insight).where(Insight.dedupe_key == ins.dedupe_key)).scalars().first()
        if cur is None:
            self.s.add(ins)
            self.s.flush()
            return ins
        if cur.status == "dismissed" and SEV_RANK.get(ins.severity, 0) <= SEV_RANK.get(cur.severity, 0):
            return cur  # analyst dismissed it and nothing got worse
        if cur.narrative_source == "llm" and _basis(cur) != _basis(ins):
            cur.narrative_source = "stale"      # substance changed: the next refresh rewrites the narrative
        for f in ("title", "severity", "score", "entity_ids", "domains", "evidence", "next_steps", "requirement_refs"):
            setattr(cur, f, getattr(ins, f))
        cur.last_seen = utcnow()
        if cur.status == "dismissed":
            cur.status = "new"  # re-opened because severity increased
        return cur
