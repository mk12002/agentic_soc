"""User interaction prediction agent for click-risk estimation."""

from __future__ import annotations

from typing import Any

from soc_platform.domains.phishing.engine.agents.user_behavior_agent.feature_extractor import extract_features
from soc_platform.domains.phishing.engine.agents.user_behavior_agent.inference import predict
from soc_platform.domains.phishing.engine.agents.user_behavior_agent.model_loader import load_model
from soc_platform.domains.phishing.engine.agents.ml_runtime import clamp as _clamp
from soc_platform.domains.phishing.engine.agents.trust_signals import assess_transactional_legitimacy
from soc_platform.domains.phishing.engine.services.logging_service import get_agent_logger

logger = get_agent_logger("user_behavior_agent")

FAMILIAR_DOMAINS = {"company.com", "microsoft.com", "google.com", "github.com"}
URGENCY_TERMS = {"urgent", "immediately", "verify", "final notice", "action required"}

# High-risk TLDs commonly abused for phishing / malware staging
HIGH_RISK_TLDS = {
    ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq",
    ".ru", ".top", ".click", ".online", ".site",
    ".pw", ".cc", ".ws", ".info",
}



def analyze(data: dict[str, Any]) -> dict[str, Any]:
    logger.info("Starting analysis", agent="user_behavior_agent")

    headers = data.get("headers", {}) or {}
    subject = (headers.get("subject") or "").lower()
    sender = (headers.get("sender") or "").lower()

    sender_domain = sender.split("@")[-1] if "@" in sender else sender
    sender_familiarity = 1.0 if sender_domain in FAMILIAR_DOMAINS else 0.0
    urgency_hits = sum(1 for term in URGENCY_TERMS if term in subject)
    legitimacy = assess_transactional_legitimacy(data)

    click_probability = 0.2
    click_probability += 0.25 * min(2, urgency_hits)
    click_probability += 0.2 * (1.0 - sender_familiarity)
    indicators: list[str] = []

    # High-risk TLD check
    sender_tld = "." + sender_domain.rsplit(".", 1)[-1] if "." in sender_domain else ""
    if sender_tld and sender_tld in HIGH_RISK_TLDS:
        click_probability += 0.20
        indicators.append(f"high_risk_tld:{sender_tld}")

    # Domain-age check via the hardened enrichment service. It validates the
    # hostname before invoking python-whois (which shells out to the system
    # `whois` binary), guarding against command-injection / SSRF from untrusted
    # sender domains, and degrades gracefully if WHOIS is unavailable.
    try:
        from soc_platform.domains.phishing.engine.services.domain_enrichment import enrich_domain
        enrichment = enrich_domain(sender_domain)
        age_days = enrichment.get("domain_age_days")
        if enrichment.get("whois_available") and age_days is not None and age_days < 90:
            click_probability += 0.25
            indicators.append(f"new_domain_age:{age_days}d")
    except Exception:
        pass  # WHOIS lookup unavailable or timed out — skip silently

    if legitimacy.level == "strong" and legitimacy.credential_bait_hits == 0:
        click_probability -= 0.18
    elif legitimacy.level == "moderate" and legitimacy.credential_bait_hits == 0:
        click_probability -= 0.10

    if urgency_hits:
        indicators.append(f"subject_urgency_hits:{urgency_hits}")
    if sender_familiarity < 1.0:
        indicators.append("unfamiliar_sender_domain")

    heuristic_result = {
        "agent_name": "user_behavior_agent",
        "risk_score": _clamp(click_probability),
        "confidence": 0.72,
        "indicators": indicators or ["low_click_likelihood"],
    }

    # Execute deterministic ML inference based on offline dataset Graph
    features = extract_features(data)
    model = load_model()
    ml_prediction = predict(features, model=model)

    if ml_prediction.get("confidence", 0.0) > 0.0:
        ml_risk = ml_prediction.get("risk_score", 0.0)
        # Blend deterministic heuristics with ML so the agent does not collapse
        # to a repetitive default score when the model is uncertain.
        fused_risk = (0.85 * ml_risk) + (0.15 * heuristic_result["risk_score"])
        final_risk = _clamp(fused_risk)
        if ml_risk >= 0.88 or heuristic_result["risk_score"] >= 0.88:
            final_risk = _clamp(max(final_risk, ml_risk, heuristic_result["risk_score"]))
        final_confidence = _clamp(max(heuristic_result["confidence"], ml_prediction.get("confidence", 0.0)))
        final_indicators = list(set(heuristic_result["indicators"] + ml_prediction.get("indicators", [])))[:20]
    else:
        final_risk = heuristic_result["risk_score"]
        final_confidence = heuristic_result["confidence"]
        final_indicators = heuristic_result["indicators"]

    if legitimacy.level in {"strong", "moderate"} and legitimacy.credential_bait_hits == 0:
        cap = 0.58 if legitimacy.level == "strong" else 0.68
        final_risk = _clamp(min(final_risk, cap))
        final_indicators.append(f"transactional_legitimacy_profile:{legitimacy.level}")
        final_indicators.extend(legitimacy.indicators[:2])

    result = {
        "agent_name": "user_behavior_agent",
        "risk_score": final_risk,
        "confidence": final_confidence,
        "indicators": final_indicators,
    }

    logger.info("Analysis complete", risk_score=result["risk_score"])
    return result
