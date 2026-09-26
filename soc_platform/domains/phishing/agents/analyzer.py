"""Multi-signal analysis backends (PH-F03, PH-F10, PH-T02).

``EngineAnalyzer`` runs the existing seven-agent ML swarm + LangGraph decision graph
in-process (header, content NLP, URL, attachment/OCR, sandbox, threat intel, user
behaviour) with persistence, actions and the retired Garuda hop disabled - the
platform's own action layer and impact agents replace them.

``HeuristicAnalyzer`` is a dependency-light fallback (and a second opinion) built
from authentication results, lookalike-domain distance, link tricks, urgency
language, risky attachments and platform threat intelligence.

Both return an ``AnalysisResult`` whose ``signals`` each carry the evidence text used
downstream for grounded explanations.
"""

from __future__ import annotations

import logging
import os
import re
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, ClassVar

from rapidfuzz.distance import Levenshtein

from soc_platform.domains.phishing.agents.decompose import DecomposedEmail

BRANDS = {"microsoft": ["microsoft.com", "office.com", "outlook.com", "live.com", "microsoftonline.com"],
          "office 365": ["office.com", "microsoft.com"], "google": ["google.com", "gmail.com"],
          "paypal": ["paypal.com"], "docusign": ["docusign.com", "docusign.net"], "dhl": ["dhl.com"],
          "amazon": ["amazon.com", "amazon.in"], "apple": ["apple.com", "icloud.com"],
          "linkedin": ["linkedin.com"], "adobe": ["adobe.com"], "sbi": ["sbi.co.in", "onlinesbi.sbi"],
          "hdfc": ["hdfcbank.com"], "icici": ["icicibank.com"]}
URGENCY = re.compile(r"\b(urgent|immediately|expires? today|within 24 hours|suspend|locked|verify your account|"
                     r"unusual (sign-in|activity)|final notice|action required|password expir\w*|confirm your|"
                     r"wire transfer|gift cards?|invoice attached|payment (is )?overdue|kindly)\b", re.IGNORECASE)
CRED_WORDS = re.compile(r"\b(log ?in|sign ?in|verify|password|credential|account|mfa|authenticate|sso|enrol\w*)\b", re.IGNORECASE)
BANK_CHANGE = re.compile(r"\b(bank (account )?details (have|has) (changed|been (updated|changed))|new bank (account|details)|"
                         r"change of bank|update(d)? (our |the )?bank (account|details)|old (bank )?account is "
                         r"(frozen|closed|blocked|under audit))\b", re.IGNORECASE)
PAYMENT = re.compile(r"\b(wire transfer|bank transfer|remittance|new (vendor|bank) (details|account)|change of bank|"
                     r"gift cards?|payment (today|urgently)|INR [\d,]+|USD [\d,]+)\b", re.IGNORECASE)
SECRECY = re.compile(r"\b(confidential|keep this (between us|quiet)|do not (call|discuss)|reply by email only|"
                     r"in a (board )?meeting)\b", re.IGNORECASE)
BULK = re.compile(r"(unsubscribe|\d+% off|\bdeals?\b|\bsale\b|limited time|shop now|newsletter)", re.IGNORECASE)
CONTAINER_EXT = {".iso", ".img", ".vhd", ".vhdx"}
# Advance-fee ("419") fraud vocabulary - count distinct hits, require several to fire.
ADVANCE_FEE = re.compile(r"\b(next of kin|beneficiary|transfer (of|the) (the )?(sum|fund|funds)|(\d+[.,]?\d*|\w+) million "
                         r"(united states |us |u\.s\. )?dollars|us\$ ?\d|foreign (partner|account)|"
                         r"strictly confidential|confidential (transaction|business)|(late|deceased) (client|husband|father)|"
                         r"inheritance|compensation fund|lottery|won (the )?(sum|prize)|claims? (agent|officer)|"
                         r"diplomatic|consignment box|bank draft|barrister|god (reveals?|fearing)|noble proposal|"
                         r"urgent (and )?(capable )?assistance)\b", re.IGNORECASE)
SUSPICIOUS_TLD = {"xyz", "top", "click", "zip", "mov", "icu", "buzz", "cam", "rest", "shop", "live", "support",
                  "work", "gq", "tk", "ml", "cf", "ga"}
SEVERE = {"malicious", "phishing"}


@dataclass
class Signal:
    name: str
    weight: float
    evidence: str
    agent: str


@dataclass
class AnalysisResult:
    verdict: str                  # malicious | suspicious | spam | safe
    score: float
    confidence: float
    signals: list[Signal] = field(default_factory=list)
    backend: str = "heuristic"
    explanation: str = ""
    counterfactual: dict[str, Any] = field(default_factory=dict)
    mitre: list[dict[str, Any]] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)
    missing_agents: list[str] = field(default_factory=list)


def lookalike(domain: str, protected: list[str]) -> tuple[str, str] | None:
    """Return (protected domain, how) if ``domain`` imitates it: homoglyph/edit-distance or brand embedding."""
    base = domain.split(".")[-2] if domain.count(".") >= 1 else domain
    norm = base.replace("0", "o").replace("1", "l").replace("3", "e").replace("5", "s").replace("rn", "m")
    best: tuple[str, str, int] | None = None
    for p in protected:
        pb = p.split(".")[0]
        if domain == p or domain.endswith("." + p):
            return None
        d = Levenshtein.distance(base, pb)
        if norm == pb or (0 < d <= 2 and len(pb) >= 5):
            how, rank = (f"character substitution ({base} vs {pb})" if norm == pb and base != pb
                         else f"edit distance {d}"), d
        elif len(pb) >= 5 and pb in norm:
            how, rank = (f"embeds brand '{pb}'" + (" with look-alike characters" if pb not in base else "")), 5
        else:
            continue
        if best is None or rank < best[2]:
            best = (p, how, rank)
    return (best[0], best[1]) if best else None


class HeuristicAnalyzer:
    name = "heuristic"

    def __init__(self, *, org_domains: list[str] | None = None, threat_intel: Any = None,
                 partner_domains: list[str] | None = None) -> None:
        self.org_domains = [d.lower() for d in (org_domains or [])]
        # key suppliers / partners (U18): their look-alikes are impersonation, like look-alikes of our own domains
        self.partner_domains = [d.lower() for d in (partner_domains or [])]
        self.ti = threat_intel

    def analyze(self, em: DecomposedEmail, raw: bytes | None = None) -> AnalysisResult:
        s: list[Signal] = []
        add = lambda n, w, e, a: s.append(Signal(n, w, e, a))
        auth = em.auth
        if auth.get("dmarc") == "fail":
            add("dmarc_fail", 0.25, f"DMARC {auth['dmarc']} for {em.sender_domain}", "header")
        if auth.get("spf") in {"fail", "softfail"}:
            add("spf_fail", 0.1, f"SPF {auth['spf']}", "header")
        if auth.get("dkim") in {"fail", "none"} and auth.get("dmarc") != "pass":
            add("dkim_missing", 0.05, f"DKIM {auth['dkim']}", "header")
        if auth.get("compauth") == "fail":
            add("compauth_fail", 0.1, "Microsoft composite authentication failed", "header")
        protected = self.org_domains + self.partner_domains + [d for ds in BRANDS.values() for d in ds]
        la = lookalike(em.sender_domain, protected) if em.sender_domain else None
        if la:
            add("lookalike_sender_domain", 0.3, f"sender domain {em.sender_domain} imitates {la[0]} ({la[1]})", "header")
        dn = (em.display_name or "").lower()
        for brand, doms in BRANDS.items():
            if brand in dn and em.sender_domain and not any(em.sender_domain.endswith(d) for d in doms):
                add("display_name_impersonation", 0.2, f"display name '{em.display_name}' but sender domain "
                                                        f"{em.sender_domain}", "header")
                break
        if em.reply_to and em.reply_to.split("@")[-1].lower() != em.sender_domain:
            add("reply_to_mismatch", 0.1, f"Reply-To {em.reply_to} differs from sender domain", "header")
        for d in em.url_domains:
            lad = lookalike(d, protected)
            if lad:
                add("lookalike_url_domain", 0.3, f"link domain {d} imitates {lad[0]} ({lad[1]})", "url")
            if d.split(".")[-1] in SUSPICIOUS_TLD:
                add("suspicious_tld", 0.05, f"link uses high-abuse TLD .{d.split('.')[-1]}", "url")
            if re.fullmatch(r"[\d.]+", d):
                add("ip_url", 0.15, f"link to raw IP {d}", "url")
            if d.startswith("xn--") or ".xn--" in d:
                add("punycode_url", 0.15, f"punycode link domain {d}", "url")
        for m in em.hidden_link_mismatch[:3]:
            add("link_text_mismatch", 0.15, f"link text shows {m['shown']} but points to {m['href']}", "url")
        if em.qr_urls:
            add("qr_code_link", 0.3, f"QR code in image resolves to {em.qr_urls[0]} (moves the click to an unmanaged "
                                     "phone)", "attachment")
        urgency = sorted({m.group(0).lower() for m in URGENCY.finditer(em.subject + " " + em.body_text)})
        if urgency:
            add("urgency_language", min(0.2, 0.07 * len(urgency)), f"urgency/pressure language: {urgency[:5]}", "content")
        if CRED_WORDS.search(em.subject + " " + em.body_text) and em.urls:
            add("credential_lure", 0.1, "asks the user to sign in / verify via a link", "content")
        if PAYMENT.search(em.subject + " " + em.body_text) and not em.urls and em.sender_domain not in self.org_domains:
            secrecy = bool(SECRECY.search(em.body_text))
            add("bec_payment_request", 0.3 if secrecy else 0.2, "external sender requests a payment/transfer"
                + (" with secrecy/unavailability pressure" if secrecy else ""), "content")
        if BANK_CHANGE.search(em.subject + " " + em.body_text) and em.sender_domain not in self.org_domains:
            # Vendor email compromise: authentic-looking mail from a real partner changing where money goes.
            add("bank_detail_change", 0.3, "external sender asks to change bank / payment details - verify out of "
                                           "band on a known number before any change", "content")
        fee_hits = sorted({m.group(0).lower() for m in ADVANCE_FEE.finditer(em.subject + " " + em.body_text)})
        if len(fee_hits) >= 2:
            add("advance_fee_fraud", min(0.6, 0.2 * len(fee_hits)), f"advance-fee fraud language: {fee_hits[:5]}", "content")
        if re.match(r"^\s*(re|fwd?)\s*:", em.subject or "", re.IGNORECASE) and not (em.headers.get("In-Reply-To") or
                                                                            em.headers.get("References")):
            add("fake_reply", 0.15, "subject pretends to be a reply/forward but no In-Reply-To/References header", "header")
        if em.sender_domain.split(".")[-1] in SUSPICIOUS_TLD:
            add("suspicious_sender_tld", 0.1, f"sender uses high-abuse TLD .{em.sender_domain.split('.')[-1]}", "header")
        for a in em.attachments:
            if "." + a.filename.rsplit(".", 1)[-1].lower() in CONTAINER_EXT:
                add("container_attachment", 0.35, f"attachment {a.filename} is a disk-image container used to bypass "
                                                  "Mark-of-the-Web", "attachment")
                continue
            if a.risky_extension:
                add("risky_attachment", 0.25, f"attachment {a.filename} has a high-risk file type", "attachment")
            if a.has_macros_hint:
                add("macro_attachment", 0.3, f"attachment {a.filename} contains VBA macros", "attachment")
        if self.ti is not None:
            iocs = [("domain", d) for d in {em.sender_domain, *em.url_domains} if d] + \
                   [("hash", a.sha256) for a in em.attachments] + ([("ip", em.origin_ip)] if em.origin_ip else [])
            for itype, v in iocs[:12]:
                try:
                    e = self.ti.enrich(itype, v)
                except Exception:
                    logging.getLogger(__name__).warning("threat-intel lookup failed for an indicator; source treated as unavailable", exc_info=True)
                    continue
                if e.get("verdict") == "malicious":
                    add("threat_intel_malicious", 0.35, f"{itype} {v} rated malicious by "
                                                        f"{e['sources_hit']} intel source(s)", "threat_intel")
                elif e.get("verdict") == "suspicious":
                    add("threat_intel_suspicious", 0.15, f"{itype} {v} rated suspicious", "threat_intel")
        if self.org_domains and em.sender_domain in self.org_domains and auth.get("dmarc") == "pass" and not s:
            add("internal_authenticated", -0.3, "authenticated internal sender", "header")
        if auth.get("dmarc") == "pass" and auth.get("dkim") == "pass" and not la:
            add("strong_authentication", -0.15, f"DMARC and DKIM pass for {em.sender_domain}", "header")

        score = max(0.0, min(1.0, sum(x.weight for x in s)))
        names = {x.name for x in s}
        bulk = bool(BULK.search(em.subject + " " + em.body_text + " " + em.body_html))
        verdict = ("malicious" if score >= 0.7 or ("threat_intel_malicious" in names and score >= 0.5) else
                   "suspicious" if score >= 0.35 else
                   "spam" if (bulk or urgency) and not names & {"lookalike_sender_domain", "lookalike_url_domain",
                                                               "credential_lure", "bec_payment_request",
                                                               "advance_fee_fraud", "bank_detail_change"}
                   and (bulk or score >= 0.15) else "safe")
        if verdict == "spam":
            add("bulk_marketing", 0.0, "bulk/promotional mail characteristics (unsubscribe link, offers)", "content")
        confidence = round(min(0.95, 0.5 + abs(score - 0.5)), 2)
        mitre = []
        if em.urls and verdict in {"malicious", "suspicious"}:
            mitre.append({"technique": "T1566.002", "name": "Spearphishing Link"})
        if any(a.risky_extension or a.has_macros_hint for a in em.attachments):
            mitre.append({"technique": "T1566.001", "name": "Spearphishing Attachment"})
        if "credential_lure" in names:
            mitre.append({"technique": "T1598.003", "name": "Phishing for Information: Spearphishing Link"})
        if "display_name_impersonation" in names or "lookalike_sender_domain" in names:
            mitre.append({"technique": "T1656", "name": "Impersonation"})
        # Counterfactual: which signals would have to be absent for the verdict to drop a band.
        cf_needed = []
        acc = score
        for x in sorted(s, key=lambda x: -x.weight):
            if acc < 0.35:
                break
            acc -= max(0.0, x.weight)
            cf_needed.append(x.name)
        return AnalysisResult(verdict, round(score, 3), confidence, s, "heuristic",
                              counterfactual={"signals_that_drive_verdict": cf_needed,
                                              "note": "verdict drops below 'suspicious' only if all of these were absent"},
                              mitre=mitre)


class EngineAnalyzer:
    """In-process adapter over the ML swarm (soc_platform.domains.phishing.engine)."""

    name = "engine"
    _lock = threading.Lock()
    _loaded = False

    OFFLINE_ENV: ClassVar[dict[str, str]] = {
        "AZURE_OPENAI_API_KEY": "", "AZURE_OPENAI_ENDPOINT": "", "AZURE_SEARCH_ENABLED": "false",
        "AZURE_SEARCH_API_KEY": "", "AZURE_OCR_KEY": "", "VIRUSTOTAL_API_KEY": "", "GOOGLE_SAFE_BROWSING_API_KEY": "",
        "ABUSEIPDB_API_KEY": "", "URLSCAN_API_KEY": "", "SHODAN_API_KEY": "", "OTX_API_KEY": "",
        "THREAT_INTEL_AUTO_REFRESH_ENABLED": "0", "SANDBOX_LOCAL_DOCKER_ENABLED": "0", "SANDBOX_EXECUTOR_URL": "",
        "ACTION_SIMULATED_MODE": "1", "ACTION_REQUIRE_APPROVAL": "1", "REQUEST_DEDUPLICATION_ENABLED": "false",
        "ENGINE_DATABASE_ENABLED": "0", "DOMAIN_WHOIS_ENABLED": "0",
    }

    def __init__(self, *, offline: bool = True) -> None:
        self.offline = offline

    @classmethod
    def available(cls) -> bool:
        try:
            import torch  # noqa: F401
            import transformers  # noqa: F401

            return True
        except Exception:
            return False

    def _load(self):
        with self._lock:
            if self.offline:
                for k, v in self.OFFLINE_ENV.items():
                    os.environ[k] = v
                os.environ.setdefault("IOC_DB_PATH", str(Path(tempfile.gettempdir()) / "soc_platform_ioc_store.db"))
            from soc_platform.domains.phishing.engine.agents.service_runner import AGENT_FUNCTIONS
            from soc_platform.domains.phishing.engine.orchestrator.langgraph_workflow import LangGraphOrchestrator
            from soc_platform.domains.phishing.engine.services.email_parser import EmailParserService

            class _NoGaruda(LangGraphOrchestrator):
                def _needs_garuda(self, state):  # endpoint hunting is done by the platform's impact agents
                    return "persist"

            self.agents = AGENT_FUNCTIONS
            self.parser = EmailParserService()
            self.graph = _NoGaruda(save_report=lambda *_: None, execute_actions=lambda *_: None)
            EngineAnalyzer._loaded = True

    def analyze(self, em: DecomposedEmail, raw: bytes | None = None) -> AnalysisResult:
        if not hasattr(self, "graph"):
            self._load()
        with tempfile.NamedTemporaryFile(suffix=".eml", delete=False) as tmp:
            tmp.write(raw or b"")
            path = tmp.name
        try:
            payload = self.parser.parse_file(path)
        finally:
            os.unlink(path)
        results: list[dict[str, Any]] = []
        missing: list[str] = []
        with ThreadPoolExecutor(max_workers=7) as pool:
            futs = {n: pool.submit(fn, dict(payload)) for n, fn in self.agents.items()}
            for n, f in futs.items():
                try:
                    r = f.result(timeout=120)
                    r.setdefault("agent_name", n)
                    results.append(r)
                except Exception:
                    missing.append(n)
        state = {"analysis_id": payload["analysis_id"], "agent_results": results,
                 "finalization_reason": "complete" if not missing else "partial",
                 "received_agents": sorted(r["agent_name"] for r in results), "missing_agents": missing,
                 "is_partial": bool(missing), "user_principal_name": payload.get("user_principal_name", ""),
                 "internet_message_id": payload.get("internet_message_id", ""),
                 "sender": (payload.get("headers") or {}).get("sender", ""),
                 "subject": (payload.get("headers") or {}).get("subject", "")}
        final = self.graph.run(state)
        d = final.get("decision", {}) or {}
        verdict_map = {"malicious": "malicious", "phishing": "malicious", "high_risk": "malicious",
                       "suspicious": "suspicious", "likely_safe": "safe", "safe": "safe", "spam": "spam"}
        verdict = verdict_map.get(str(d.get("verdict", "")).lower(), "suspicious")
        signals = []
        for r in results:
            for ind in (r.get("indicators") or [])[:6]:
                signals.append(Signal(str(ind)[:80], float(r.get("risk_score", 0) or 0) / max(1, len(r.get("indicators") or [])),
                                      f"{r['agent_name']}: {ind}", r["agent_name"].replace("_agent", "")))
        mitre = [{"technique": t.get("technique_id") or t.get("id"), "name": t.get("name") or t.get("technique_name", "")}
                 for t in ((d.get("attack_assessment") or {}).get("techniques") or []) if isinstance(t, dict)]
        return AnalysisResult(verdict, round(float(d.get("overall_risk_score", 0) or 0), 3),
                              round(float(d.get("confidence", 0.7) or 0.7), 2), signals, "engine",
                              explanation=str(d.get("llm_explanation") or ""),
                              counterfactual=d.get("counterfactual_result") or d.get("counterfactual") or {},
                              mitre=mitre, raw={"decision_keys": sorted(d), "agent_scores": {
                                  r["agent_name"]: r.get("risk_score") for r in results}}, missing_agents=missing)


class CompositeAnalyzer:
    """Engine when available (primary), heuristic always (second opinion + fallback)."""

    def __init__(self, heuristic: HeuristicAnalyzer, engine: EngineAnalyzer | None = None) -> None:
        self.heuristic = heuristic
        self.engine = engine

    def analyze(self, em: DecomposedEmail, raw: bytes | None = None) -> AnalysisResult:
        h = self.heuristic.analyze(em, raw)
        if self.engine is None:
            return h
        try:
            e = self.engine.analyze(em, raw)
        except Exception as exc:
            h.raw["engine_error"] = f"{type(exc).__name__}: {exc}"[:300]
            return h
        # Most severe verdict wins; both opinions are kept for the analyst.
        order = ["safe", "spam", "suspicious", "malicious"]
        primary = e if order.index(e.verdict) >= order.index(h.verdict) else h
        verdict = primary.verdict
        h_names = {x.name for x in h.signals}
        note = None
        if (e.verdict == "malicious" and h.verdict == "safe" and "strong_authentication" in h_names
                and e.score < 0.85 and not any(x.weight > 0 for x in h.signals)):
            # Engine-only signal against a strongly authenticated sender: route to an analyst rather than
            # declaring it malicious (observed false positive on legitimate vendor invoices).
            verdict = "suspicious"
            note = "engine-only moderate signal on a DMARC/DKIM-authenticated sender; downgraded to suspicious for review"
        merged = AnalysisResult(verdict, max(e.score, h.score), max(e.confidence, h.confidence),
                                h.signals + e.signals, "engine+heuristic", explanation=e.explanation,
                                counterfactual=e.counterfactual or h.counterfactual,
                                mitre=e.mitre or h.mitre, missing_agents=e.missing_agents,
                                raw={"engine": {"verdict": e.verdict, "score": e.score, **e.raw},
                                     "heuristic": {"verdict": h.verdict, "score": h.score}, "fusion_note": note})
        return merged
