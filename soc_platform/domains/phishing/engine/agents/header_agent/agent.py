"""Header analysis agent with auth checks, look-alike domain detection, and ML anomaly scoring."""

from __future__ import annotations

from typing import Any

from Levenshtein import distance as levenshtein_distance

from soc_platform.domains.phishing.engine.agents.header_agent.feature_extractor import extract_features
from soc_platform.domains.phishing.engine.agents.header_agent.inference import predict
from soc_platform.domains.phishing.engine.agents.header_agent.model_loader import load_model
from soc_platform.domains.phishing.engine.agents.ml_runtime import clamp as _clamp
from soc_platform.domains.phishing.engine.services.logging_service import get_agent_logger

logger = get_agent_logger("header_agent")

TRUSTED_DOMAINS = {
    "microsoft.com",
    "google.com",
    "paypal.com",
    "amazon.com",
    "apple.com",
}

_model_cache = None

def _get_model():
    global _model_cache
    if _model_cache is None:
        try:
            _model_cache = load_model()
        except Exception:
            _model_cache = False  # Use False to distinguish between None (not loaded) and False (failed to load)
    return _model_cache if _model_cache is not False else None



def _domain_from_sender(sender: str) -> str:
    if "@" not in sender:
        return ""
    return sender.split("@")[-1].strip().lower()


def _auth_all_pass(auth: str) -> bool:
    auth_l = (auth or "").lower()
    return (
        "spf=pass" in auth_l
        and "dkim=pass" in auth_l
        and "dmarc=pass" in auth_l
    )


def analyze(data: dict[str, Any]) -> dict[str, Any]:
    logger.info("Starting analysis", agent="header_agent")
    headers = data.get("headers", {}) or {}
    auth = (headers.get("authentication_results") or "").lower()
    sender = headers.get("sender", "")
    reply_to = headers.get("reply_to", "") or ""
    sender_domain = _domain_from_sender(sender)
    reply_to_domain = _domain_from_sender(reply_to)
    received = headers.get("received", []) or []
    auth_all_pass = _auth_all_pass(auth)

    indicators: list[str] = []
    missing_data_indicators: list[str] = []
    malicious_evidence_indicators: list[str] = []
    risk = 0.0

    # 1. Heuristic Setup
    if "spf=fail" in auth or "spf=softfail" in auth:
        risk += 0.25
        indicators.append("spf_failed")
        malicious_evidence_indicators.append("spf_failed")
    if "dkim=fail" in auth:
        risk += 0.2
        indicators.append("dkim_failed")
        malicious_evidence_indicators.append("dkim_failed")
    if "dmarc=fail" in auth:
        risk += 0.25
        indicators.append("dmarc_failed")
        malicious_evidence_indicators.append("dmarc_failed")

    # Unicode homograph check first: a domain built from confusable characters is
    # visually identical to a brand but its ASCII skeleton reveals the deception.
    # This is reported even when Levenshtein distance on the raw codepoints would
    # exceed the threshold below (3+ substitutions look identical yet score high).
    from soc_platform.domains.phishing.engine.utils.unicode_normalizer import analyze_text as _analyze_unicode

    unicode_flagged = False
    if sender_domain:
        u_report = _analyze_unicode(sender_domain)
        if u_report["has_zero_width"]:
            risk += 0.25
            indicators.append(f"zero_width_chars:{','.join(u_report['zero_width'])}")
            malicious_evidence_indicators.append("zero_width_chars")
        if u_report["has_confusables"]:
            folded = u_report["skeleton"]
            for trusted in TRUSTED_DOMAINS:
                if folded == trusted or levenshtein_distance(folded, trusted) <= 2:
                    risk += 0.85
                    indicators.append(f"unicode_domain_spoofing:{sender_domain}->{trusted}")
                    malicious_evidence_indicators.append("unicode_domain_spoofing")
                    unicode_flagged = True
                    break

    for trusted in TRUSTED_DOMAINS:
        if unicode_flagged:
            break
        if sender_domain and sender_domain != trusted and levenshtein_distance(sender_domain, trusted) <= 2:
            risk += 0.85
            indicators.append(f"lookalike_domain:{sender_domain}->{trusted}")
            malicious_evidence_indicators.append("lookalike_domain")
            break

    if len(received) <= 1:
        missing_data_indicators.append("short_smtp_trace")
        indicators.append("missing_data:short_smtp_trace")

        # Authenticated single-hop traffic can still be suspicious in SOC triage.
        # Keep these events in review band rather than auto-safe.
        if auth_all_pass and len(received) == 1:
            risk += 0.28
            indicators.append("authenticated_single_hop_anomaly")
            malicious_evidence_indicators.append("authenticated_single_hop_anomaly")

    # ARC chain integrity + Received-hop forensics (RFC 8617 + relay timestamp order).
    # These surface forged routing that authentication results alone can miss.
    from soc_platform.domains.phishing.engine.agents.header_agent.arc_validator import analyze_headers as _analyze_routing

    routing = _analyze_routing(headers)
    if routing["risk_contribution"] > 0.0:
        risk += routing["risk_contribution"]
        for ind in routing["indicators"]:
            indicators.append(ind)
            # cv=fail and out-of-order chains are concrete forgery evidence, not just missing data.
            if ind.startswith("arc_chain_broken") or ind == "received_chain_out_of_order" or ind == "received_hop_future_dated":
                malicious_evidence_indicators.append(ind)

    if reply_to_domain and sender_domain and reply_to_domain != sender_domain:
        risk += 0.24
        indicators.append("reply_to_domain_mismatch")
        malicious_evidence_indicators.append("reply_to_domain_mismatch")

        if auth_all_pass:
            risk += 0.12
            indicators.append("authenticated_reply_to_anomaly")
            malicious_evidence_indicators.append("authenticated_reply_to_anomaly")

    if not sender_domain:
        missing_data_indicators.append("sender_missing")
        indicators.append("missing_data:sender_missing")

    if not auth:
        missing_data_indicators.append("authentication_results_missing")
        indicators.append("missing_data:authentication_results_missing")
        # Explicit uplift: sender exists but zero authentication headers present
        if sender_domain:
            risk += 0.15
            indicators.append("no_auth_headers_with_domain")
            malicious_evidence_indicators.append("no_auth_headers_with_domain")
    elif "spf=" not in auth:
        # SPF silently absent (auth header exists but no SPF record)
        risk += 0.10
        indicators.append("spf_record_absent")
        malicious_evidence_indicators.append("spf_record_absent")

    heuristic_confidence = _clamp(0.65 + min(0.25, len(indicators) * 0.05))

    # 2. ML Prediction
    features = extract_features(data)
    ml_result = predict(features, _get_model())

    if ml_result.get("confidence", 0.0) > 0.0:
        # Weighted fusion: 60% ML, 40% heuristic (consistent with other agents)
        fused_risk = (0.6 * ml_result["risk_score"]) + (0.4 * risk)
        # Prevent ML from diluting strong heuristic signals
        if len(malicious_evidence_indicators) > 0:
            final_risk = _clamp(max(risk, fused_risk))
        else:
            final_risk = _clamp(fused_risk)
        final_confidence = _clamp(max(heuristic_confidence, ml_result.get("confidence", 0.0)))
        indicators.extend(ml_result.get("indicators", []))
    else:
        final_risk = _clamp(risk)
        final_confidence = heuristic_confidence

    # SOC guardrail: ensure authenticated-but-anomalous headers stay reviewable.
    if (
        "authenticated_single_hop_anomaly" in indicators
        or "authenticated_reply_to_anomaly" in indicators
    ):
        final_risk = _clamp(max(final_risk, 0.42))

    insufficient_evidence = (
        len(malicious_evidence_indicators) == 0
        and len(missing_data_indicators) > 0
    )
    if insufficient_evidence:
        # When auth is completely absent but domain is present, that's suspicious
        # and should score higher (phishing often lacks auth headers)
        if "authentication_results_missing" in missing_data_indicators and sender_domain:
            final_risk = _clamp(max(final_risk, 0.35))
        else:
            final_risk = _clamp(min(final_risk, 0.18))

    if final_risk >= 0.8:
        header_verdict = "malicious"
    elif final_risk >= 0.4:
        header_verdict = "suspicious"
    elif insufficient_evidence:
        header_verdict = "insufficient_evidence"
    else:
        header_verdict = "benign"

    result = {
        "agent_name": "header_agent",
        "risk_score": final_risk,
        "confidence": final_confidence,
        "header_verdict": header_verdict,
        "evidence_summary": {
            "missing_data_indicators": missing_data_indicators[:10],
            "malicious_evidence_indicators": malicious_evidence_indicators[:10],
        },
        "indicators": indicators[:20],
    }
    logger.info("Analysis complete", risk_score=result["risk_score"], used_ml=ml_result.get("confidence", 0.0) > 0)
    return result
