"""
ARC chain integrity and Received-hop analysis for the header agent.

Two dependency-free header forensics that the agent did not perform before:

1. **Received-hop analysis** — parses the timestamps and relay identities out of the
   ``Received`` header chain. Because each relay *prepends* its own header, the chain
   must be ordered newest-first; a lower (older-position) hop that is *newer* than the
   hop above it indicates a forged/inserted ``Received`` line. We also flag future-dated
   hops and implausibly large inter-hop gaps. Works on the ``received: list[str]``
   present in both the JSON API and the parsed ``.eml`` paths.

2. **ARC chain validation (RFC 8617)** — checks the ARC-Seal / ARC-Message-Signature /
   ARC-Authentication-Results set. A valid chain has contiguous instances ``i=1..n``,
   each with all three header types, and a sealing ``cv=`` of ``none`` (only at i=1) or
   ``pass``; ``cv=fail`` means the chain was broken/forged in transit. Operates on a
   structured ``headers['arc']`` dict (lists per header type), since a flat header dict
   collapses the duplicated ARC headers.

Everything reported is derived directly from the header text — no inference or
fabrication — so it feeds the grounded-evidence explainability layer faithfully.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from typing import Any

# Tolerances chosen to avoid false positives from benign clock skew.
_ORDER_SKEW_TOLERANCE = timedelta(seconds=90)
_FUTURE_TOLERANCE = timedelta(minutes=5)
_LARGE_GAP = timedelta(hours=24)

_INSTANCE_RE = re.compile(r"\bi=(\d+)")
_CV_RE = re.compile(r"\bcv=([a-zA-Z]+)")


def _parse_received_date(received: str) -> datetime | None:
    """Extract and parse the timestamp from a single Received header value."""
    if ";" not in received:
        return None
    date_part = received.rsplit(";", 1)[-1].strip()
    try:
        dt = parsedate_to_datetime(date_part)
    except (TypeError, ValueError, IndexError):
        return None
    if dt is None:
        return None
    # Normalize to aware UTC so comparisons never mix naive/aware datetimes.
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def analyze_received_hops(received: list[str], now: datetime | None = None) -> dict[str, Any]:
    """Analyze the Received chain for ordering, future-date, and gap anomalies."""
    now = now or datetime.now(timezone.utc)
    indicators: list[str] = []
    risk = 0.0

    hops = list(received or [])
    hop_count = len(hops)
    dates = [_parse_received_date(h) for h in hops]
    parsed = [d for d in dates if d is not None]

    if hop_count > 12:
        indicators.append(f"received_hop_count_high:{hop_count}")
        risk += 0.10

    # Future-dated hops (beyond tolerance) — a relay cannot stamp a future time.
    for d in parsed:
        if d > now + _FUTURE_TOLERANCE:
            indicators.append("received_hop_future_dated")
            risk += 0.30
            break

    # Ordering: chain is newest-first, so dates should be non-increasing going down.
    # A later (lower) hop newer than an earlier (upper) hop beyond skew = forgery.
    out_of_order = False
    large_gap = False
    for upper, lower in zip(parsed, parsed[1:]):
        if lower > upper + _ORDER_SKEW_TOLERANCE:
            out_of_order = True
        if abs(upper - lower) > _LARGE_GAP:
            large_gap = True
    if out_of_order:
        indicators.append("received_chain_out_of_order")
        risk += 0.35
    if large_gap:
        indicators.append("received_hop_large_gap")
        risk += 0.10

    return {
        "hop_count": hop_count,
        "parsed_timestamps": len(parsed),
        "indicators": indicators,
        "risk_contribution": round(min(risk, 0.85), 4),
    }


def _arc_lists(arc: Any) -> tuple[list[str], list[str], list[str]]:
    """Normalize the structured ARC payload into three header lists."""
    if not isinstance(arc, dict):
        return [], [], []
    seal = [str(x) for x in (arc.get("seal") or [])]
    ams = [str(x) for x in (arc.get("message_signature") or [])]
    aar = [str(x) for x in (arc.get("authentication_results") or [])]
    return seal, ams, aar


def _instances(headers: list[str]) -> list[int]:
    out: list[int] = []
    for h in headers:
        m = _INSTANCE_RE.search(h)
        if m:
            out.append(int(m.group(1)))
    return out


def validate_arc_chain(arc: Any) -> dict[str, Any]:
    """Validate ARC chain integrity per RFC 8617 semantics."""
    seal, ams, aar = _arc_lists(arc)
    present = bool(seal or ams or aar)
    indicators: list[str] = []
    risk = 0.0

    if not present:
        return {"present": False, "cv": None, "indicators": [], "risk_contribution": 0.0}

    seal_instances = sorted(_instances(seal))
    ams_instances = set(_instances(ams))
    aar_instances = set(_instances(aar))

    n = max(seal_instances) if seal_instances else 0

    # Contiguity: instances must be exactly 1..n with no gaps or duplicates.
    if sorted(set(seal_instances)) != list(range(1, n + 1)) or len(seal_instances) != n:
        indicators.append("arc_chain_noncontiguous")
        risk += 0.30

    # Each instance needs the full triple (Seal + Message-Signature + Auth-Results).
    for i in range(1, n + 1):
        if i not in ams_instances or i not in aar_instances:
            indicators.append(f"arc_instance_incomplete:i={i}")
            risk += 0.20
            break

    # Chain validation value from the most recent seal.
    cv: str | None = None
    if seal_instances:
        top = max(seal_instances)
        top_seal = next((h for h in seal if (m := _INSTANCE_RE.search(h)) and int(m.group(1)) == top), "")
        cvm = _CV_RE.search(top_seal)
        cv = cvm.group(1).lower() if cvm else None
        if cv == "fail":
            indicators.append("arc_chain_broken:cv=fail")
            risk += 0.55
        elif cv == "none" and top > 1:
            # cv=none is only valid for the first hop of a chain.
            indicators.append("arc_chain_invalid_cv_none")
            risk += 0.25

    return {
        "present": True,
        "instances": n,
        "cv": cv,
        "indicators": indicators,
        "risk_contribution": round(min(risk, 0.85), 4),
    }


def analyze_headers(headers: dict[str, Any], now: datetime | None = None) -> dict[str, Any]:
    """Run both analyses over a header dict and return combined indicators + risk."""
    received = headers.get("received", []) or []
    arc = headers.get("arc")

    hop = analyze_received_hops(received, now=now)
    arc_result = validate_arc_chain(arc)

    indicators = list(hop["indicators"]) + list(arc_result["indicators"])
    # Combine conservatively (max, not sum) so a single forensic stays bounded.
    risk = max(hop["risk_contribution"], arc_result["risk_contribution"])

    return {
        "indicators": indicators,
        "risk_contribution": round(risk, 4),
        "hop": hop,
        "arc": arc_result,
    }
