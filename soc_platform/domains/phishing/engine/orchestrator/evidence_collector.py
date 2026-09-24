"""
Evidence collector for grounded LLM reasoning.

Turns the *real* indicators that agents already emit (e.g. ``brand_impersonation:microsoft``,
``financial_signals:invoice,payment,wire``, ``lookalike_domain:a->b``, ``spf_failed``) into structured,
citable ``Evidence`` records. The grounded reasoner is only allowed to make claims that reference one of
these evidence ids, which removes the ability to fabricate details that are not present in agent output.

Every evidence record is derived directly from agent results, so it is faithful by construction: the
``raw_value`` is the concrete matched value the agent reported, not an LLM invention.
"""

from __future__ import annotations

from typing import Any

# Map of known indicator prefixes -> (evidence_type, human-readable claim template).
# ``{value}`` in the template is replaced with the concrete matched value (text after the first colon).
# Anything not listed still becomes evidence via a generic fallback, so no real signal is dropped.
_INDICATOR_RULES: dict[str, tuple[str, str]] = {
    "spf_failed": ("email_authentication", "SPF authentication failed for the sender."),
    "dkim_failed": ("email_authentication", "DKIM signature verification failed."),
    "dmarc_failed": ("email_authentication", "DMARC alignment/policy check failed."),
    "authentication_results_missing": ("email_authentication", "No SPF/DKIM/DMARC authentication results were present."),
    "missing_data": ("email_authentication", "Expected authentication data was missing: {value}."),
    "reply_to_domain_mismatch": ("header_anomaly", "Reply-To domain differs from the sender domain."),
    "authenticated_reply_to_anomaly": ("header_anomaly", "Authenticated message has an anomalous Reply-To."),
    "arc_chain_broken": ("routing_forgery", "ARC chain validation failed (cv=fail) — the authentication chain was broken or forged in transit."),
    "arc_chain_noncontiguous": ("routing_forgery", "ARC chain instances are non-contiguous, indicating a tampered authentication chain."),
    "arc_instance_incomplete": ("routing_forgery", "An ARC instance is missing required headers: {value}."),
    "arc_chain_invalid_cv_none": ("routing_forgery", "ARC chain reports cv=none beyond the first hop, which is invalid."),
    "received_chain_out_of_order": ("routing_forgery", "Received header timestamps are out of order, indicating a forged relay hop."),
    "received_hop_future_dated": ("routing_forgery", "A Received relay hop is stamped with a future date."),
    "received_hop_large_gap": ("header_anomaly", "An unusually large time gap exists between relay hops."),
    "received_hop_count_high": ("header_anomaly", "The message traversed an unusually high number of relays: {value}."),
    "lookalike_domain": ("domain_spoofing", "Sender domain looks like a trusted brand: {value}."),
    "unicode_domain_spoofing": ("domain_spoofing", "Sender domain uses confusable Unicode characters."),
    "brand_impersonation": ("brand_impersonation", "URL impersonates the brand '{value}'."),
    "homoglyph_attack": ("brand_impersonation", "URL uses homoglyph substitution: {value}."),
    "urgency_signals": ("content_pattern", "Urgency/pressure language present: {value}."),
    "credential_signals": ("content_pattern", "Credential-harvesting language present: {value}."),
    "financial_signals": ("content_pattern", "Financial-lure language present: {value}."),
    "bec_fraud_signals": ("content_pattern", "Business-email-compromise / wire-fraud language present: {value}."),
    "bec_pattern_both_urgency_and_financial": ("content_pattern", "Classic BEC pattern: both urgency and financial language present."),
    "multilingual_urgency_signals": ("content_pattern", "Non-English urgency/pressure language present: {value}."),
    "multilingual_credential_signals": ("content_pattern", "Non-English credential-harvesting language present: {value}."),
    "multilingual_financial_signals": ("content_pattern", "Non-English financial-lure language present: {value}."),
    "multilingual_bec_pattern": ("content_pattern", "Non-English BEC pattern (urgency + financial) present in: {value}."),
    "cross_language_phishing": ("evasion", "Phishing language is non-English, a filter-evasion technique: {value}."),
    "spam_marketing_signals": ("content_pattern", "Bulk/marketing spam language present: {value}."),
    "click_through_language": ("content_pattern", "Email pushes the reader to click a link."),
    "marketing_phone_pattern": ("content_pattern", "Unsolicited marketing-style phone number present."),
    "long_email_body": ("content_pattern", "Unusually long email body."),
    "url_length_high": ("url_heuristic", "URL is unusually long."),
    "many_subdomains": ("url_heuristic", "URL has an unusual number of subdomains."),
    "credential_bait_terms": ("url_heuristic", "URL contains credential-bait terms."),
    "high_entropy_subdomain": ("url_heuristic", "URL has a high-entropy (random-looking) subdomain."),
    "non_https": ("url_heuristic", "URL does not use HTTPS."),
    "high_risk_tld": ("sender_reputation", "Sender uses a high-risk top-level domain: {value}."),
    "new_domain_age": ("sender_reputation", "Sender domain is newly registered: {value}."),
    "unfamiliar_sender_domain": ("sender_reputation", "Sender domain is unfamiliar to this organization."),
    "subject_urgency_hits": ("social_engineering", "Subject line contains urgency cues: {value}."),
}


def _split_indicator(indicator: str) -> tuple[str, str | None]:
    """Split ``prefix:value`` -> (prefix, value). Returns (indicator, None) when there is no colon."""
    text = str(indicator)
    if ":" in text:
        prefix, value = text.split(":", 1)
        return prefix.strip(), value.strip()
    return text.strip(), None


def _claim_for(indicator: str) -> tuple[str, str, str | None]:
    """Return (evidence_type, claim, raw_value) for a single indicator string."""
    prefix, value = _split_indicator(indicator)
    rule = _INDICATOR_RULES.get(prefix)
    if rule is not None:
        evidence_type, template = rule
        claim = template.replace("{value}", value) if value is not None else template.replace("{value}", "").strip()
        return evidence_type, claim, value
    # Generic fallback — still faithful: surface the raw indicator the agent emitted.
    pretty = prefix.replace("_", " ")
    if value is not None:
        return "indicator", f"Detector signal '{pretty}': {value}.", value
    return "indicator", f"Detector signal '{pretty}' was raised.", None


def collect_evidence(
    agent_results: list[dict[str, Any]],
    max_items: int = 40,
) -> list[dict[str, Any]]:
    """
    Build a list of citable evidence records from agent results.

    Each record: ``{id, agent, type, claim, raw_value, indicator}``. Agents are processed in descending
    risk order so the most relevant evidence survives the ``max_items`` cap. One ``agent_score`` anchor is
    emitted per agent so the reasoner can also cite the numeric score it is explaining.
    """
    evidence: list[dict[str, Any]] = []
    counter = 0

    ordered = sorted(
        agent_results or [],
        key=lambda r: float(r.get("risk_score", 0.0) or 0.0),
        reverse=True,
    )

    for result in ordered:
        agent = str(result.get("agent_name", "unknown"))
        risk = float(result.get("risk_score", 0.0) or 0.0)
        confidence = float(result.get("confidence", 0.0) or 0.0)

        # Numeric anchor so score-level claims are also grounded.
        counter += 1
        evidence.append(
            {
                "id": f"E{counter}",
                "agent": agent,
                "type": "agent_score",
                "claim": f"{agent} reported risk={risk:.2f} at confidence={confidence:.2f}.",
                "raw_value": f"{risk:.4f}",
                "indicator": None,
            }
        )

        for indicator in (result.get("indicators", []) or []):
            if not indicator:
                continue
            evidence_type, claim, raw_value = _claim_for(str(indicator))
            counter += 1
            evidence.append(
                {
                    "id": f"E{counter}",
                    "agent": agent,
                    "type": evidence_type,
                    "claim": claim,
                    "raw_value": raw_value,
                    "indicator": str(indicator),
                }
            )
            if len(evidence) >= max_items:
                return evidence

    return evidence


def evidence_ids(evidence: list[dict[str, Any]]) -> set[str]:
    """Return the set of valid evidence ids — used to validate that LLM claims cite real evidence."""
    return {str(item.get("id")) for item in (evidence or []) if item.get("id")}
