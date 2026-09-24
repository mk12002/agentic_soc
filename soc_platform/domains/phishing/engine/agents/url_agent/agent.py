"""URL reputation and heuristic agent with offline fallback mode."""

from __future__ import annotations

import math
import time
from typing import Any
from urllib.parse import urlparse

import httpx

from soc_platform.domains.phishing.engine.agents.url_agent.feature_extractor import extract_features
from soc_platform.domains.phishing.engine.agents.url_agent.inference import predict
from soc_platform.domains.phishing.engine.agents.url_agent.model_loader import load_model
from soc_platform.domains.phishing.engine.agents.trust_signals import assess_transactional_legitimacy
from soc_platform.domains.phishing.engine.configs.settings import settings
from soc_platform.domains.phishing.engine.services.logging_service import get_agent_logger

logger = get_agent_logger("url_agent")

_OPENPHISH_CACHE: dict[str, Any] = {"fetched_at": 0.0, "urls": set()}


BENIGN_ALLOWLIST = {"github.com", "python.org", "microsoft.com", "google.com", "www.github.com", "www.google.com",
                    "rzp.io", "icaiaa.com", "razorpay.com"}
TRUSTED_TRACKING_DOMAINS = {"mucp.api.account.microsoft.com", "go.microsoft.com", "aka.ms",
                            "click.email.microsoftonline.com", "tracking.google.com"}
BRAND_TOKENS = {"microsoft", "google", "paypal", "amazon", "apple", "github"}

def _clamp(value: float) -> float:
    return max(0.0, min(1.0, round(value, 4)))


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    probs = [text.count(char) / len(text) for char in set(text)]
    return -sum(prob * math.log(prob, 2) for prob in probs)


def _is_trusted_tracking_url(host: str) -> bool:
    """Check if a host belongs to a known trusted tracking/pixel domain."""
    for trusted in TRUSTED_TRACKING_DOMAINS:
        if host == trusted or host.endswith(f".{trusted}"):
            return True
    for trusted in BENIGN_ALLOWLIST:
        if host == trusted or host.endswith(f".{trusted}"):
            return True
    return False


def _heuristic_score(url: str) -> tuple[float, list[str]]:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    indicators: list[str] = []
    score = 0.0

    # Skip length/entropy penalties for known trusted tracking/pixel URLs
    is_trusted = _is_trusted_tracking_url(host)

    if len(url) > 90 and not is_trusted:
        score += 0.18
        indicators.append("url_length_high")
    if host.count(".") >= 3 and not is_trusted:
        score += 0.15
        indicators.append("many_subdomains")
    if any(token in url for token in ["@", "%40", "login", "verify", "secure"]):
        score += 0.2
        indicators.append("credential_bait_terms")
    if _entropy(host) > 3.5 and not is_trusted:
        score += 0.2
        indicators.append("high_subdomain_entropy")
    if parsed.scheme != "https":
        score += 0.08
        indicators.append("non_https_url")
    return _clamp(score), indicators



def _normalized_host(url: str) -> str:
    from urllib.parse import urlparse
    host = (urlparse(str(url)).hostname or "").lower().strip(".")
    if host.startswith("www."):
        return host[4:]
    return host

def _external_state(indicators: list[str], score: float) -> str:
    if score > 0.0:
        return "hit"
    lowered = [str(item).lower() for item in indicators]
    if any("unavailable" in item for item in lowered):
        return "unknown"
    return "clean"

def _brand_impersonation_indicator(url: str) -> str | None:
    host = _normalized_host(url)
    if not host:
        return None

    for brand in BRAND_TOKENS:
        legit_root = f"{brand}.com"
        if host == legit_root or host.endswith(f".{legit_root}"):
            continue
        if brand not in host:
            continue
        if (
            f"{legit_root}-" in host or f"-{legit_root}" in host
            or f"{brand}-" in host or f"-{brand}" in host
            or (f"{legit_root}." in host and not host.endswith(f".{legit_root}"))
        ):
            return f"brand_impersonation:{brand}"
    return None


def _unicode_deception_indicators(url: str) -> list[str]:
    """Detect homoglyph / zero-width / mixed-script deception in a URL host.

    Complements the ASCII-only ``_brand_impersonation_indicator``: a Cyrillic
    look-alike such as ``pаypal.com`` contains no ASCII ``paypal`` substring and
    would otherwise be missed entirely. We fold the host to its ASCII skeleton and
    check whether the *folded* form impersonates a known brand, then report the
    concrete original->skeleton mapping so the evidence stays grounded in truth.
    """
    from urllib.parse import urlparse
    from soc_platform.domains.phishing.engine.utils.unicode_normalizer import analyze_text

    host = (urlparse(str(url)).hostname or "").lower().strip(".")
    if not host:
        return []

    indicators: list[str] = []
    report = analyze_text(host)

    if report["has_zero_width"]:
        indicators.append(f"zero_width_chars:{','.join(report['zero_width'])}")

    # Only meaningful when confusable substitution actually changed the host.
    if report["has_confusables"]:
        folded = report["skeleton"]
        folded_root = folded[4:] if folded.startswith("www.") else folded
        for brand in BRAND_TOKENS:
            legit_root = f"{brand}.com"
            if folded_root == legit_root or folded_root.endswith(f".{legit_root}") or brand in folded_root:
                # Homoglyph substitution disguised as a trusted brand.
                indicators.append(f"homoglyph_attack:{host}->{folded}")
                break
        else:
            # Confusables present but not brand-targeted — still a deception signal.
            indicators.append(f"unicode_confusable_host:{host}->{folded}")
        if report["mixed_script"]:
            indicators.append(f"mixed_script_domain:{'+'.join(report['scripts'])}")

    return indicators

def _apply_allowlist_prior(url: str, score: float, external_state_label: str, heur_score: float) -> tuple[float, str | None]:
    host = _normalized_host(url)
    if host not in BENIGN_ALLOWLIST:
        return score, None
    if external_state_label == "hit":
        return score, None
    if heur_score >= 0.7:
        return _clamp(score - 0.08), f"benign_allowlist_soft:{host}"
    return _clamp(score - 0.2), f"benign_allowlist_prior:{host}"

def _request_timeout() -> float:

    return max(1.0, float(settings.external_lookup_timeout_seconds))


def _virustotal_score(url: str) -> tuple[float, list[str]]:
    if not settings.enable_virustotal_url_lookup:
        return 0.0, []
    if not settings.virustotal_api_key:
        return 0.0, ["virustotal_not_configured"]

    api_url = "https://www.virustotal.com/api/v3/urls"
    headers = {"x-apikey": settings.virustotal_api_key}

    try:
        with httpx.Client(timeout=_request_timeout()) as client:
            submit = client.post(api_url, headers=headers, data={"url": url})
            submit.raise_for_status()
            analysis_id = submit.json().get("data", {}).get("id")
            if not analysis_id:
                return 0.0, []

            report = client.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers)
            report.raise_for_status()
            stats = report.json().get("data", {}).get("attributes", {}).get("stats", {})
            malicious = float(stats.get("malicious", 0))
            suspicious = float(stats.get("suspicious", 0))
            total = max(1.0, sum(float(v) for v in stats.values()))
            score = min(1.0, (malicious + (0.5 * suspicious)) / total)
            if score <= 0.0:
                return 0.0, []
            return round(score, 4), [f"virustotal_malicious={int(malicious)}", f"virustotal_suspicious={int(suspicious)}"]
    except Exception:
        return 0.0, ["virustotal_unavailable"]


def _google_safe_browsing_score(url: str) -> tuple[float, list[str]]:
    if not settings.enable_google_safe_browsing_lookup:
        return 0.0, []
    if not settings.google_safe_browsing_api_key:
        return 0.0, ["google_safe_browsing_not_configured"]

    api_url = (
        "https://safebrowsing.googleapis.com/v4/threatMatches:find"
        f"?key={settings.google_safe_browsing_api_key}"
    )
    payload = {
        "client": {
            "clientId": "email_security_platform",
            "clientVersion": "1.0.0",
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    try:
        with httpx.Client(timeout=_request_timeout()) as client:
            response = client.post(api_url, json=payload)
            response.raise_for_status()
            matches = response.json().get("matches", []) or []
            if not matches:
                return 0.0, []
            threat_types = sorted(
                {
                    str(match.get("threatType", "unknown")).lower()
                    for match in matches
                    if isinstance(match, dict)
                }
            )
            score = min(1.0, 0.75 + (0.05 * len(matches)))
            indicators = [f"google_safe_browsing_match={item}" for item in threat_types[:3]]
            return _clamp(score), indicators
    except Exception:
        return 0.0, ["google_safe_browsing_unavailable"]


def _openphish_score(url: str) -> tuple[float, list[str]]:
    if not settings.enable_openphish_lookup:
        return 0.0, []

    feed_url = (settings.openphish_feed_url or "").strip()
    if not feed_url:
        return 0.0, ["openphish_not_configured"]

    try:
        ttl = max(60, int(settings.openphish_cache_ttl_seconds))
        now = time.time()
        cache_age = now - float(_OPENPHISH_CACHE.get("fetched_at", 0.0))
        cached_urls = _OPENPHISH_CACHE.get("urls")

        if not isinstance(cached_urls, set) or not cached_urls or cache_age > ttl:
            with httpx.Client(timeout=_request_timeout(), follow_redirects=True) as client:
                response = client.get(feed_url)
                response.raise_for_status()
                lines = response.text.splitlines()

            cached_urls = {
                line.strip().rstrip("/")
                for line in lines
                if line.strip() and not line.strip().startswith("#")
            }
            _OPENPHISH_CACHE["urls"] = cached_urls
            _OPENPHISH_CACHE["fetched_at"] = now

        needle = str(url).strip().rstrip("/")
        if needle and needle in cached_urls:
            return 0.95, ["openphish_match"]
        return 0.0, []
    except Exception:
        return 0.0, ["openphish_unavailable"]


def _urlhaus_score(url: str) -> tuple[float, list[str]]:
    if not settings.enable_urlhaus_lookup:
        return 0.0, []

    api_url = (settings.urlhaus_api_url or "").strip()
    if not api_url:
        return 0.0, ["urlhaus_not_configured"]

    try:
        with httpx.Client(timeout=_request_timeout()) as client:
            response = client.post(api_url, data={"url": url})
            response.raise_for_status()
            payload = response.json()

        status = str(payload.get("query_status", "")).lower()
        if status != "ok":
            return 0.0, []

        url_status = str(payload.get("url_status", "unknown")).lower()
        tags = payload.get("tags") or []
        threat = str(payload.get("threat", "")).lower()
        score = 0.92 if url_status == "online" else 0.82
        indicators = [f"urlhaus_status={url_status}"]
        if threat:
            indicators.append(f"urlhaus_threat={threat}")
        if isinstance(tags, list) and tags:
            indicators.append(f"urlhaus_tag={str(tags[0]).lower()}")
        return _clamp(score), indicators
    except httpx.HTTPStatusError as e:
        if e.response.status_code in {401, 403}:
            return 0.0, ["urlhaus_unauthorized"]
        return 0.0, ["urlhaus_unavailable"]
    except Exception:
        return 0.0, ["urlhaus_unavailable"]


def _external_score(url: str) -> tuple[float, list[str]]:
    provider_scores: list[float] = []
    indicators: list[str] = []
    for lookup in (
        _google_safe_browsing_score,
        _openphish_score,
        _urlhaus_score,
        _virustotal_score,
    ):
        score, provider_indicators = lookup(url)
        if score > 0.0:
            provider_scores.append(score)
        indicators.extend(provider_indicators)

    if not provider_scores:
        return 0.0, indicators
    return _clamp(max(provider_scores)), indicators


def _any_external_lookup_enabled() -> bool:
    return any(
        (
            settings.enable_google_safe_browsing_lookup,
            settings.enable_openphish_lookup,
            settings.enable_urlhaus_lookup,
            settings.enable_virustotal_url_lookup,
        )
    )


def analyze(data: dict[str, Any]) -> dict[str, Any]:
    logger.info("Starting analysis", agent="url_agent")
    from soc_platform.domains.phishing.engine.agents.url_agent.calibration import apply_calibration
    urls = data.get("urls", []) or []
    if not urls:
        return {"agent_name": "url_agent", "risk_score": 0.0, "confidence": 0.7, "indicators": ["no_urls_detected"]}

    legitimacy = assess_transactional_legitimacy(data)

    combined_scores: list[float] = []
    heuristic_scores: list[float] = []
    external_scores: list[float] = []
    conflict_count = 0
    brand_impersonation_count = 0
    all_allowlisted_clean = True
    url_level_indicators: list[str] = []

    for url in urls[:20]:
        heur_score, heur_ind = _heuristic_score(url)
        external_score, external_ind = _external_score(url)
        brand_indicator = _brand_impersonation_indicator(url)
        if brand_indicator:
            brand_impersonation_count += 1
            heur_ind.append(brand_indicator)
            heur_score = _clamp(max(heur_score, 0.85))

        unicode_indicators = _unicode_deception_indicators(url)
        if unicode_indicators:
            heur_ind.extend(unicode_indicators)
            # A homoglyph attack disguised as a brand is as strong as ASCII brand
            # impersonation; other confusable/zero-width signals are weaker.
            if any(ind.startswith("homoglyph_attack:") for ind in unicode_indicators):
                brand_impersonation_count += 1
                heur_score = _clamp(max(heur_score, 0.85))
            else:
                heur_score = _clamp(max(heur_score, 0.45))

        state = _external_state(external_ind, external_score)
        if external_score > 0.0:
            final_score = _clamp(max(external_score, heur_score))
        elif state == "clean":
            final_score = _clamp(0.65 * heur_score)
        else:
            final_score = _clamp(0.8 * heur_score)

        if heur_score > 0.8:
            final_score = _clamp(max(final_score, heur_score))

        final_score, allowlist_indicator = _apply_allowlist_prior(
            url=url, score=final_score, external_state_label=state, heur_score=heur_score
        )
        if allowlist_indicator:
            external_ind.append(allowlist_indicator)

        if heur_score >= 0.45 and external_score <= 0.0 and state == "clean":
            conflict_count += 1
            external_ind.append("heuristic_reputation_conflict")

        if not (_normalized_host(url) in BENIGN_ALLOWLIST and state != "hit"):
            all_allowlisted_clean = False

        combined_scores.append(final_score)
        heuristic_scores.append(heur_score)
        external_scores.append(external_score)
        url_level_indicators.extend(heur_ind + external_ind)

    heuristic_risk = _clamp(sum(heuristic_scores) / len(heuristic_scores))
    external_risk = _clamp(sum(external_scores) / len(external_scores))
    evidence_delta = abs(heuristic_risk - external_risk)
    if external_risk <= 0.0:
        evidence_risk = _clamp(sum(combined_scores) / len(combined_scores))
    else:
        evidence_risk = _clamp(max(sum(combined_scores) / len(combined_scores), (0.45 * heuristic_risk) + (0.55 * external_risk)))

    summary_indicators = [
        f"urls_analyzed={len(combined_scores)}",
        f"heuristic_risk={heuristic_risk}",
        f"external_risk={external_risk}",
    ]
    if _any_external_lookup_enabled():
        summary_indicators.append("external_lookups_enabled")
    else:
        summary_indicators.append("external_lookups_disabled")

    # To avoid the averaging issue, run ML over each URL individually, take max risk
    model = load_model()
    max_ml_risk = 0.0
    max_ml_conf = 0.0
    ml_indicators = []
    result_feature_importance = {}
    
    for u in urls[:20]:
        f = extract_features({"urls": [u]})
        pred = predict(f, model=model)
        if pred.get("confidence", 0.0) > 0.0:
            if float(pred.get("risk_score", 0.0)) > max_ml_risk:
                max_ml_risk = float(pred.get("risk_score", 0.0))
                max_ml_conf = float(pred.get("confidence", 0.0))
                if "feature_importance" in pred:
                    result_feature_importance.update(pred["feature_importance"])
                for ind in pred.get("indicators", []):
                    if ind not in ml_indicators:
                        ml_indicators.append(ind)

    if max_ml_conf > 0.0:
        risk_score = _clamp(max(evidence_risk, max_ml_risk, heuristic_risk))
        calibrated_risk, calibration_method = apply_calibration(risk_score)
        risk_score = calibrated_risk

        confidence_floor = (0.65 + min(0.25, 0.02 * len(urls)) + (0.05 if external_risk > 0.0 else 0.0) + min(0.1, 0.12 * heuristic_risk) + min(0.05, 0.08 * evidence_delta))
        confidence = _clamp(max(confidence_floor, max_ml_conf))
        if conflict_count > 0:
            confidence = _clamp(confidence - min(0.2, 0.08 * conflict_count))
            summary_indicators.append(f"confidence_penalty_conflict={conflict_count}")
        if calibration_method:
            summary_indicators.append(f"risk_calibrated={calibration_method}")
    else:
        risk_score = evidence_risk
        confidence = _clamp(0.58 + min(0.25, 0.02 * len(urls)) + (0.08 if external_risk > 0.0 else 0.0) + min(0.1, 0.12 * heuristic_risk) + min(0.05, 0.08 * evidence_delta))
        if conflict_count > 0:
            confidence = _clamp(confidence - min(0.2, 0.08 * conflict_count))
            summary_indicators.append(f"confidence_penalty_conflict={conflict_count}")
        calibrated_risk, calibration_method = apply_calibration(risk_score)
        risk_score = calibrated_risk
        if calibration_method:
            summary_indicators.append(f"risk_calibrated={calibration_method}")

    if len(urls) > 1:
        multi_url_boost = _clamp(min(0.18, 0.03 * (len(urls) - 1)))
        risk_score = _clamp(max(risk_score, evidence_risk + multi_url_boost))
        summary_indicators.append(f"many_urls:{len(urls)}")

    if all_allowlisted_clean and risk_score > 0.0:
        risk_score = _clamp(risk_score * 0.3)
        summary_indicators.append("global_allowlist_prior_applied")
        
    if brand_impersonation_count > 0 and external_risk <= 0.0 and heuristic_risk >= 0.35:
        risk_score = _clamp(max(risk_score, 0.45))
        summary_indicators.append("brand_impersonation_suspicious_floor")

    if external_risk <= 0.0 and heuristic_risk <= 0.25:
        confidence = _clamp(min(confidence, 0.82))
        summary_indicators.append("confidence_capped_low_evidence")

    # Authenticated transactional reminders often include long gateway/tracking URLs.
    if (
        legitimacy.level in {"strong", "moderate"}
        and legitimacy.credential_bait_hits == 0
        and external_risk <= 0.0
        and brand_impersonation_count == 0
    ):
        multiplier = 0.40 if legitimacy.level == "strong" else 0.65
        risk_score = _clamp(risk_score * multiplier)
        confidence = _clamp(min(confidence, 0.82 if legitimacy.level == "strong" else 0.88))
        summary_indicators.append(f"transactional_legitimacy_profile:{legitimacy.level}")
        summary_indicators.extend(legitimacy.indicators[:2])

    summary_indicators.extend(ml_indicators)

    result = {
        "agent_name": "url_agent",
        "risk_score": risk_score,
        "confidence": confidence,
        "indicators": (summary_indicators + url_level_indicators)[:20],
        "feature_importance": result_feature_importance,
    }
    logger.info("Analysis complete", risk_score=result["risk_score"], url_count=len(urls))
    return result
