"""
Domain Enrichment Service for the Agentic Email Security System.

Enriches email analysis with WHOIS data, domain age checking,
and registrar reputation scoring.
"""

from __future__ import annotations

import re
import time
from datetime import UTC, datetime
from typing import Any

from soc_platform.domains.phishing.engine.services.logging_service import get_service_logger

logger = get_service_logger("domain_enrichment")

# Simple in-memory cache for domain lookups
_domain_cache: dict[str, dict[str, Any]] = {}
_CACHE_TTL = 3600  # 1 hour

# Strict hostname validation. python-whois shells out to the system `whois`
# binary, so only well-formed registrable domains may reach it (defends against
# command-injection / SSRF via attacker-controlled email content). IP literals
# and malformed input are rejected here and handled by heuristics only.
_VALID_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"([a-zA-Z]{2,63}|xn--[a-zA-Z0-9]{2,59})$"  # allow punycode (IDN) TLDs
)


def is_valid_domain(domain: str) -> bool:
    """Return True if `domain` is a well-formed registrable hostname safe to look up."""
    return bool(_VALID_DOMAIN_RE.match((domain or "").strip()))


def enrich_domain(domain: str) -> dict[str, Any]:
    """
    Enrich a domain with age, WHOIS, and risk signals.

    Uses python-whois if available, otherwise falls back to
    heuristic analysis.
    """
    domain = domain.lower().strip()
    if not domain:
        return {"domain": domain, "status": "invalid"}

    # Check cache
    cached = _domain_cache.get(domain)
    if cached and (time.time() - cached.get("_cached_at", 0)) < _CACHE_TTL:
        return cached

    result: dict[str, Any] = {
        "domain": domain,
        "domain_age_days": None,
        "creation_date": None,
        "registrar": None,
        "is_newly_registered": False,
        "risk_signals": [],
        "risk_score_adjustment": 0.0,
        "whois_available": False,
    }

    # Try WHOIS lookup — only for well-formed registrable domains. Malformed
    # input or IP literals never reach the system `whois` binary; heuristics
    # below still flag them.
    if not is_valid_domain(domain):
        result["risk_signals"].append("invalid_domain_format")
        _apply_heuristics(domain, result)
        result["_cached_at"] = time.time()
        _domain_cache[domain] = result
        return result

    try:
        import os

        if os.environ.get("DOMAIN_WHOIS_ENABLED", "1") == "0":
            raise ImportError("WHOIS disabled by DOMAIN_WHOIS_ENABLED=0")
        import whois
        w = whois.whois(domain)
        if w:
            result["whois_available"] = True
            # Use getattr: python-whois objects (and test doubles) may omit
            # fields entirely. Direct attribute access would raise AttributeError
            # and abort age computation before it runs.
            registrar = getattr(w, "registrar", None)
            result["registrar"] = str(registrar) if registrar else None

            creation = getattr(w, "creation_date", None)
            if isinstance(creation, list):
                creation = creation[0]
            if creation:
                if isinstance(creation, str):
                    try:
                        creation = datetime.fromisoformat(creation)
                    except Exception:
                        creation = None
                if creation:
                    result["creation_date"] = creation.isoformat()
                    age_days = (datetime.now(UTC) - creation.replace(tzinfo=UTC if creation.tzinfo is None else creation.tzinfo)).days
                    result["domain_age_days"] = age_days
                    if age_days < 30:
                        result["is_newly_registered"] = True
                        result["risk_signals"].append(f"newly_registered_domain ({age_days} days)")
                        result["risk_score_adjustment"] = 0.15
                    elif age_days < 90:
                        result["risk_signals"].append(f"recently_registered_domain ({age_days} days)")
                        result["risk_score_adjustment"] = 0.08
    except ImportError:
        logger.debug("python-whois not installed, using heuristic analysis")
    except Exception as e:
        logger.debug("WHOIS lookup failed", domain=domain, error=str(e))

    # Heuristic analysis (always runs)
    _apply_heuristics(domain, result)

    result["_cached_at"] = time.time()
    _domain_cache[domain] = result
    return result


def _apply_heuristics(domain: str, result: dict[str, Any]) -> None:
    """Apply heuristic risk signals to a domain."""
    # Check for suspicious TLDs
    suspicious_tlds = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top",
                       ".work", ".click", ".link", ".info", ".buzz", ".icu"}
    for tld in suspicious_tlds:
        if domain.endswith(tld):
            result["risk_signals"].append(f"suspicious_tld ({tld})")
            result["risk_score_adjustment"] = max(result["risk_score_adjustment"], 0.10)
            break

    # Check for IP-based domains
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain):
        result["risk_signals"].append("ip_based_domain")
        result["risk_score_adjustment"] = max(result["risk_score_adjustment"], 0.12)

    # Check for excessive subdomains
    parts = domain.split(".")
    if len(parts) > 4:
        result["risk_signals"].append(f"excessive_subdomains ({len(parts)} levels)")
        result["risk_score_adjustment"] = max(result["risk_score_adjustment"], 0.08)

    # Check for long domain names (common in phishing)
    if len(domain) > 50:
        result["risk_signals"].append(f"unusually_long_domain ({len(domain)} chars)")
        result["risk_score_adjustment"] = max(result["risk_score_adjustment"], 0.05)

    # Check for brand impersonation patterns
    brand_patterns = ["paypal", "microsoft", "google", "apple", "amazon",
                      "netflix", "facebook", "instagram", "whatsapp", "linkedin",
                      "dropbox", "chase", "wellsfargo", "bankofamerica"]
    for brand in brand_patterns:
        if brand in domain and not domain.endswith(f"{brand}.com"):
            result["risk_signals"].append(f"potential_brand_impersonation ({brand})")
            result["risk_score_adjustment"] = max(result["risk_score_adjustment"], 0.15)
            break

    # Check for homoglyph characters in punycode
    if domain.startswith("xn--"):
        result["risk_signals"].append("punycode_homoglyph_domain")
        result["risk_score_adjustment"] = max(result["risk_score_adjustment"], 0.12)

    # Check for randomized-looking domains
    consonant_clusters = sum(1 for i in range(len(domain) - 2)
                             if domain[i:i+3].isalpha() and
                             all(c not in "aeiou" for c in domain[i:i+3].lower()))
    if consonant_clusters > 3:
        result["risk_signals"].append("randomized_domain_pattern")
        result["risk_score_adjustment"] = max(result["risk_score_adjustment"], 0.08)


def enrich_domains_from_email(
    sender: str,
    urls: list[str],
) -> dict[str, Any]:
    """Enrich all domains found in an email."""
    domains: set[str] = set()

    # Extract sender domain
    if "@" in sender:
        domains.add(sender.split("@")[-1].lower())

    # Extract URL domains
    for url in urls:
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            if parsed.hostname:
                domains.add(parsed.hostname.lower())
        except Exception:
            logger.opt(exception=True).debug("could not parse a URL for domain enrichment")

    enrichments = {}
    total_adjustment = 0.0
    all_signals: list[str] = []

    for domain in domains:
        enrichment = enrich_domain(domain)
        enrichments[domain] = enrichment
        total_adjustment = max(total_adjustment, enrichment.get("risk_score_adjustment", 0))
        all_signals.extend(enrichment.get("risk_signals", []))

    return {
        "domains_analyzed": len(domains),
        "enrichments": enrichments,
        "max_risk_adjustment": round(total_adjustment, 4),
        "all_risk_signals": all_signals,
        "newly_registered_domains": [d for d, e in enrichments.items() if e.get("is_newly_registered")],
    }
