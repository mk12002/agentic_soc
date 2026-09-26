"""
STIX 2.1 Bundle Generator for the Agentic Email Security System.

Generates standardized STIX 2.1 bundles from analysis results for
interoperability with SIEMs, SOAR platforms, and threat intelligence sharing.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime
from typing import Any

from soc_platform.domains.phishing.engine.services.logging_service import get_service_logger

logger = get_service_logger("stix_generator")

STIX_SPEC_VERSION = "2.1"
IDENTITY_ID = "identity--agentic-email-security-system"


def _deterministic_id(stix_type: str, *parts: str) -> str:
    """Generate a deterministic STIX ID from type and content parts."""
    seed = "|".join(str(p) for p in parts)
    h = hashlib.sha256(seed.encode()).hexdigest()[:32]
    return f"{stix_type}--{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


def _now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def generate_stix_bundle(
    analysis_id: str,
    agent_results: list[dict[str, Any]],
    verdict: str,
    risk_score: float,
    email_headers: dict[str, Any] | None = None,
    attack_data: dict[str, Any] | None = None,
    recommended_actions: list[str] | None = None,
) -> dict[str, Any]:
    """
    Generate a STIX 2.1 bundle from analysis results.

    Returns:
        STIX 2.1 bundle dict with Indicator, Malware, AttackPattern,
        ObservedData, and Relationship objects.
    """
    now = _now_iso()
    objects: list[dict[str, Any]] = []
    headers = email_headers or {}

    # 1. Identity object — the system itself
    identity = {
        "type": "identity", "spec_version": STIX_SPEC_VERSION,
        "id": IDENTITY_ID, "created": now, "modified": now,
        "name": "Agentic Email Security System",
        "identity_class": "system",
        "description": "Multi-agent AI email security analysis platform.",
    }
    objects.append(identity)

    # 2. Report object — the analysis itself
    report_id = _deterministic_id("report", analysis_id)
    report = {
        "type": "report", "spec_version": STIX_SPEC_VERSION,
        "id": report_id, "created": now, "modified": now,
        "name": f"Email Threat Analysis: {analysis_id}",
        "description": f"Automated analysis verdict: {verdict}. Risk score: {risk_score:.4f}.",
        "published": now,
        "report_types": ["threat-report"],
        "object_refs": [],
        "created_by_ref": IDENTITY_ID,
    }

    # 3. Email-Address observable
    sender = headers.get("sender", "")
    if sender:
        sender_id = _deterministic_id("email-addr", sender)
        sender_obj = {
            "type": "email-addr", "spec_version": STIX_SPEC_VERSION,
            "id": sender_id, "value": sender,
        }
        objects.append(sender_obj)
        report["object_refs"].append(sender_id)

    # 4. Indicator objects from agent indicators
    all_indicators: list[str] = []
    for result in agent_results:
        agent_name = result.get("agent_name", "unknown")
        agent_risk = float(result.get("risk_score", 0) or 0)
        for indicator_text in (result.get("indicators", []) or []):
            indicator_text = str(indicator_text)
            all_indicators.append(indicator_text)
            ind_id = _deterministic_id("indicator", analysis_id, agent_name, indicator_text)
            ind_obj = {
                "type": "indicator", "spec_version": STIX_SPEC_VERSION,
                "id": ind_id, "created": now, "modified": now,
                "name": f"[{agent_name}] {indicator_text[:80]}",
                "description": f"Detected by {agent_name} with risk score {agent_risk:.3f}.",
                "indicator_types": ["malicious-activity"] if agent_risk >= 0.5 else ["anomalous-activity"],
                "pattern_type": "stix",
                "pattern": f"[email-message:body CONTAINS '{indicator_text[:60]}']",
                "valid_from": now,
                "created_by_ref": IDENTITY_ID,
                "confidence": int(min(100, agent_risk * 100)),
            }
            objects.append(ind_obj)
            report["object_refs"].append(ind_id)

    # 5. Attack Pattern objects from ATT&CK data
    if attack_data:
        for tech in attack_data.get("techniques", [])[:15]:
            ap_id = _deterministic_id("attack-pattern", tech["technique_id"])
            ap = {
                "type": "attack-pattern", "spec_version": STIX_SPEC_VERSION,
                "id": ap_id, "created": now, "modified": now,
                "name": f"{tech['technique_id']}: {tech['technique_name']}",
                "description": f"Tactic: {tech['tactic_name']}. Phase: {tech.get('phase', 'N/A')}.",
                "external_references": [{
                    "source_name": "mitre-attack",
                    "external_id": tech["technique_id"],
                    "url": f"https://attack.mitre.org/techniques/{tech['technique_id'].replace('.', '/')}/",
                }],
                "created_by_ref": IDENTITY_ID,
            }
            objects.append(ap)
            report["object_refs"].append(ap_id)

    # 6. Malware object if verdict is malicious
    if verdict in ("malicious", "high_risk"):
        malware_id = _deterministic_id("malware", analysis_id, "email_threat")
        malware = {
            "type": "malware", "spec_version": STIX_SPEC_VERSION,
            "id": malware_id, "created": now, "modified": now,
            "name": f"Email Threat [{analysis_id[:8]}]",
            "description": f"Phishing email classified as {verdict} with risk {risk_score:.4f}.",
            "malware_types": ["phishing"] if "bec" not in str(all_indicators).lower() else ["phishing", "fraud"],
            "is_family": False,
            "created_by_ref": IDENTITY_ID,
        }
        objects.append(malware)
        report["object_refs"].append(malware_id)

    # 7. Course of Action objects from recommended actions
    for action in (recommended_actions or []):
        coa_id = _deterministic_id("course-of-action", analysis_id, action)
        coa = {
            "type": "course-of-action", "spec_version": STIX_SPEC_VERSION,
            "id": coa_id, "created": now, "modified": now,
            "name": action.replace("_", " ").title(),
            "description": f"Automated response action: {action}.",
            "created_by_ref": IDENTITY_ID,
        }
        objects.append(coa)
        report["object_refs"].append(coa_id)

    objects.append(report)

    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects,
    }

    logger.info("STIX bundle generated", analysis_id=analysis_id, object_count=len(objects))
    return bundle
