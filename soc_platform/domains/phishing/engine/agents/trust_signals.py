"""Shared trust signal helpers for transactional-email false-positive reduction."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

TRUSTED_TRANSACTIONAL_DOMAINS = {
    "go.microsoft.com",
    "account.microsoft.com",
    "microsoft.com",
    "msr-cmt.org",
    "rzp.io",
    "razorpay.com",
    "stripe.com",
    "paypal.com",
    "icaiaa.com",
    "mucp.api.account.microsoft.com",
}

TRANSACTIONAL_TERMS = {
    "payment",
    "reminder",
    "invoice",
    "registration",
    "conference",
    "fee",
    "deadline",
}

CREDENTIAL_BAIT_TERMS = {
    "verify account",
    "confirm identity",
    "password",
    "login",
    "mfa",
    "otp",
}


def _clamp(value: float) -> float:
    return max(0.0, min(1.0, round(value, 4)))


def _parse_auth_results(headers: dict[str, Any]) -> tuple[bool, bool, bool]:
    auth_text = str(headers.get("authentication_results") or "").lower()
    return (
        "spf=pass" in auth_text,
        "dkim=pass" in auth_text,
        "dmarc=pass" in auth_text,
    )


def _normalized_hosts(urls: list[str]) -> list[str]:
    hosts: list[str] = []
    for raw in urls:
        host = (urlparse(str(raw)).hostname or "").lower().strip(".")
        host = host.removeprefix("www.")
        if host:
            hosts.append(host)
    return hosts


def _host_matches_trusted(host: str) -> bool:
    for trusted in TRUSTED_TRANSACTIONAL_DOMAINS:
        if host == trusted or host.endswith(f".{trusted}"):
            return True
    return False


@dataclass(frozen=True)
class TransactionalLegitimacyProfile:
    score: float
    level: str
    auth_all_pass: bool
    trusted_url_ratio: float
    transactional_hits: int
    credential_bait_hits: int
    has_attachments: bool
    indicators: list[str]


def assess_transactional_legitimacy(data: dict[str, Any]) -> TransactionalLegitimacyProfile:
    """Score whether an email resembles a legitimate transactional reminder."""
    headers = data.get("headers") or {}
    body = data.get("body") or {}
    if isinstance(body, str):
        plain = body
        html = ""
    else:
        plain = str(body.get("plain") or "")
        html = str(body.get("html") or "")
    subject = str(headers.get("subject") or "")
    combined = f"{subject}\n{plain}\n{html}".lower()

    spf_pass, dkim_pass, dmarc_pass = _parse_auth_results(headers)
    auth_pass_count = int(spf_pass) + int(dkim_pass) + int(dmarc_pass)
    auth_all_pass = auth_pass_count == 3

    urls = [str(item) for item in (data.get("urls") or [])]
    hosts = _normalized_hosts(urls)
    trusted_hosts = [host for host in hosts if _host_matches_trusted(host)]
    trusted_url_ratio = (len(trusted_hosts) / max(1, len(hosts))) if hosts else 0.0

    transactional_hits = sum(1 for term in TRANSACTIONAL_TERMS if term in combined)
    credential_bait_hits = sum(1 for term in CREDENTIAL_BAIT_TERMS if term in combined)

    attachments = data.get("attachments") or []
    has_attachments = len(attachments) > 0

    score = 0.0
    indicators: list[str] = []

    score += 0.18 * auth_pass_count
    if auth_all_pass:
        indicators.append("txn_trust:auth_all_pass")

    if trusted_url_ratio > 0.0:
        score += min(0.35, 0.35 * trusted_url_ratio)
        indicators.append(f"txn_trust:trusted_url_ratio={round(trusted_url_ratio, 2)}")

    if transactional_hits > 0:
        score += min(0.25, 0.08 * transactional_hits)
        indicators.append(f"txn_trust:transactional_hits={transactional_hits}")

    if credential_bait_hits > 0:
        score -= min(0.28, 0.12 * credential_bait_hits)
        indicators.append(f"txn_trust:credential_bait_hits={credential_bait_hits}")

    if has_attachments:
        score -= 0.12
        indicators.append("txn_trust:attachments_present")

    score = _clamp(score)
    if score >= 0.7:
        level = "strong"
    elif score >= 0.45:
        level = "moderate"
    else:
        level = "weak"

    return TransactionalLegitimacyProfile(
        score=score,
        level=level,
        auth_all_pass=auth_all_pass,
        trusted_url_ratio=trusted_url_ratio,
        transactional_hits=transactional_hits,
        credential_bait_hits=credential_bait_hits,
        has_attachments=has_attachments,
        indicators=indicators,
    )
