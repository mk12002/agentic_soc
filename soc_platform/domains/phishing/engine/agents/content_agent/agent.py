"""Content phishing detection agent using semantic heuristics and ML-ready hooks."""

from __future__ import annotations

import re
from typing import Any

from soc_platform.domains.phishing.engine.agents.content_agent.feature_extractor import extract_features
from soc_platform.domains.phishing.engine.agents.content_agent.inference import predict
from soc_platform.domains.phishing.engine.agents.content_agent.model_loader import load_model
from soc_platform.domains.phishing.engine.agents.content_agent.multilingual import analyze_multilingual
from soc_platform.domains.phishing.engine.agents.ml_runtime import clamp as _clamp
from soc_platform.domains.phishing.engine.agents.trust_signals import assess_transactional_legitimacy
from soc_platform.domains.phishing.engine.services.logging_service import get_agent_logger

logger = get_agent_logger("content_agent")

PHISHING_PATTERNS = {
    "urgency": ["urgent", "immediately", "action required", "asap", "suspended", "verify", "confirm"],
    "credential": ["verify account", "password", "login", "confirm identity", "mfa", "credentials"],
    "financial": ["invoice", "payment", "wire", "bank", "refund", "transfer", "fund", "money"],
}

SPAM_MARKETING_PATTERNS = [
    "investment properties",
    "pay cash",
    "full commission",
    "to unsubscribe",
    "pre-qualified",
    "project home",
    "contact me",
    "best wishes",
]





def analyze(data: dict[str, Any]) -> dict[str, Any]:
    logger.info("Starting analysis", agent="content_agent")
    raw_body = data.get("body", "")
    if isinstance(raw_body, dict):
        body = str(raw_body.get("plain", "") or "")
        body_html = str(raw_body.get("html", "") or "")
    else:
        body = str(raw_body or "")
        body_html = ""
    subject = (data.get("headers", {}) or {}).get("subject", "")

    combined = f"{subject}\n{body}\n{body_html}".lower()
    indicators: list[str] = []
    risk = 0.0

    # Track which pattern types we found
    pattern_hits = {}
    for pattern_type, keywords in PHISHING_PATTERNS.items():
        hits = [term for term in keywords if term in combined]
        pattern_hits[pattern_type] = hits
        if hits:
            indicators.append(f"{pattern_type}_signals:{','.join(hits[:3])}")
            # Higher scoring for phishing patterns - each hit is significant
            if pattern_type == "financial":
                risk += min(0.5, 0.2 * len(hits))  # Increased from 0.08 to 0.2
            elif pattern_type == "urgency":
                risk += min(0.45, 0.15 * len(hits))  # Increased from 0.08 to 0.15
            else:  # credential
                risk += min(0.35, 0.15 * len(hits))  # Increased from 0.12 to 0.15
    
    # BONUS: If both financial AND urgency signals present (classic BEC pattern), boost significantly
    if pattern_hits.get("financial") and pattern_hits.get("urgency"):
        risk += 0.25  # Strong BEC indicator
        indicators.append("bec_pattern_both_urgency_and_financial")

    if len(combined) > 2500:
        risk += 0.05
        indicators.append("long_email_body")

    if "http" in combined and "click" in combined:
        risk += 0.15
        indicators.append("click_through_language")

    # BEC / Wire fraud specific patterns
    bec_patterns = ["wire transfer", "wire fund", "urgent payment", "immediate payment", "business transfer", 
                     "partnership", "secure account", "company account", "quick transfer", "confidential"]
    bec_hits = [term for term in bec_patterns if term in combined]
    if bec_hits:
        risk += min(0.5, 0.12 * len(bec_hits))
        indicators.append(f"bec_fraud_signals:{','.join(bec_hits[:3])}")

    spam_hits = [term for term in SPAM_MARKETING_PATTERNS if term in combined]
    # Only count as spam if NOT combined with financial/urgency signals (those are fraud, not marketing)
    if spam_hits and not (any(t in combined for t in PHISHING_PATTERNS.get("financial", [])) or 
                          any(t in combined for t in PHISHING_PATTERNS.get("urgency", []))):
        indicators.append(f"spam_marketing_signals:{','.join(spam_hits[:4])}")
        risk += min(0.25, 0.08 * len(spam_hits))  # Reduced significantly

    # Common phone-number pattern in unsolicited marketing emails.
    if re.search(r"\b\d{3}[\.-]\d{3}[\.-]\d{4}\b", combined):
        indicators.append("marketing_phone_pattern")
        # Higher risk if combined with financial signals (Nigerian scam pattern)
        if any(term in combined for term in PHISHING_PATTERNS.get("financial", [])):
            risk += 0.25
        else:
            risk += 0.12

    # Multi-language phishing: catches non-English lures (Spanish/French/German/
    # Portuguese/Italian) that the English-only PHISHING_PATTERNS above miss entirely.
    multilingual = analyze_multilingual(combined)
    if multilingual["risk_contribution"] > 0.0:
        risk += multilingual["risk_contribution"]
        indicators.extend(multilingual["indicators"])

    heuristic_result = {
        "agent_name": "content_agent",
        "risk_score": _clamp(risk),
        "confidence": _clamp(0.55 + min(0.35, len(indicators) * 0.05)),
        "indicators": indicators,
    }

    legitimacy = assess_transactional_legitimacy(data)

    features = extract_features(data)
    model = load_model()
    ml_prediction = predict(features, model=model)

    if ml_prediction.get("confidence", 0.0) > 0.0:
        ml_risk = ml_prediction.get("risk_score", 0.0)
        heur_risk = heuristic_result["risk_score"]
        # Use weighted blend — NOT max() which defeats multi-signal fusion
        # by always picking the worst case even when one signal is benign.
        fused_risk = (0.6 * ml_risk) + (0.4 * heur_risk)
        # Only let a single signal dominate if it's extremely confident
        # (>= 0.85 risk), otherwise trust the blend.
        if ml_risk >= 0.85 or heur_risk >= 0.85:
            final_risk = _clamp(max(fused_risk, ml_risk, heur_risk))
        else:
            final_risk = _clamp(fused_risk)
        final_confidence = _clamp(max(heuristic_result["confidence"], ml_prediction.get("confidence", 0.0)))
        final_indicators = (heuristic_result["indicators"] + ml_prediction.get("indicators", []))[:20]
    else:
        final_risk = heuristic_result["risk_score"]
        final_confidence = heuristic_result["confidence"]
        final_indicators = heuristic_result["indicators"]

    # Reduce lexical false positives for authenticated transactional reminders.
    # BUT: Don't cap if we found BEC/wire fraud patterns (too risky)
    has_bec_patterns = any(term in combined for term in ["wire transfer", "wire fund", "urgent payment", 
                                                         "immediate payment", "business transfer", 
                                                         "partnership", "confidential"])
    has_financial_patterns = any(term in combined for term in PHISHING_PATTERNS.get("financial", []))
    has_urgency_patterns = any(term in combined for term in PHISHING_PATTERNS.get("urgency", []))
    
    # Only apply legitimacy cap if NOT BEC/wire fraud (too risky to cap those)
    if (legitimacy.level in {"strong", "moderate"} and legitimacy.credential_bait_hits == 0 
        and not (has_bec_patterns and has_financial_patterns)):
        if legitimacy.level == "strong":
            final_risk = _clamp(min(final_risk, 0.35))
            final_confidence = _clamp(min(final_confidence, 0.88))
        else:
            final_risk = _clamp(min(final_risk, 0.50))
        final_indicators.append(f"transactional_legitimacy_profile:{legitimacy.level}")
        final_indicators.extend(legitimacy.indicators[:3])

    result = {
        "agent_name": "content_agent",
        "risk_score": final_risk,
        "confidence": final_confidence,
        "indicators": final_indicators,
    }
    if ml_prediction.get("feature_importance"):
        result["feature_importance"] = ml_prediction["feature_importance"]
    logger.info("Analysis complete", risk_score=result["risk_score"], used_ml=ml_prediction.get("confidence", 0.0) > 0)
    return result
