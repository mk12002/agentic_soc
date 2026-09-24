"""
Compliance Mapper for the Agentic Email Security System.

Maps detection events and response actions to regulatory compliance
frameworks (NIST CSF, ISO 27001, SOC 2, GDPR).
"""

from __future__ import annotations
from typing import Any
from soc_platform.domains.phishing.engine.services.logging_service import get_service_logger

logger = get_service_logger("compliance_mapper")

# Framework control mappings
COMPLIANCE_MAPPINGS: dict[str, dict[str, dict[str, str]]] = {
    "NIST_CSF": {
        "email_analysis": {
            "control_id": "DE.CM-1", "control_name": "Network Monitoring",
            "description": "The network is monitored to detect potential cybersecurity events.",
        },
        "threat_detection": {
            "control_id": "DE.AE-2", "control_name": "Event Analysis",
            "description": "Detected events are analyzed to understand attack targets and methods.",
        },
        "automated_response": {
            "control_id": "RS.MI-1", "control_name": "Incident Mitigation",
            "description": "Incidents are contained to minimize impact.",
        },
        "quarantine": {
            "control_id": "RS.MI-2", "control_name": "Incident Mitigation",
            "description": "Incidents are mitigated.",
        },
        "data_protection": {
            "control_id": "PR.DS-5", "control_name": "Data Leak Prevention",
            "description": "Protections against data leaks are implemented.",
        },
        "audit_logging": {
            "control_id": "DE.AE-3", "control_name": "Event Data Aggregation",
            "description": "Event data are collected and correlated from multiple sources.",
        },
        "analyst_feedback": {
            "control_id": "RS.AN-2", "control_name": "Impact Analysis",
            "description": "The impact of the incident is understood.",
        },
    },
    "ISO_27001": {
        "email_analysis": {
            "control_id": "A.12.6.1", "control_name": "Management of Technical Vulnerabilities",
            "description": "Information about technical vulnerabilities is obtained and evaluated.",
        },
        "threat_detection": {
            "control_id": "A.12.4.1", "control_name": "Event Logging",
            "description": "Event logs recording activities are produced and kept.",
        },
        "automated_response": {
            "control_id": "A.16.1.5", "control_name": "Response to Information Security Incidents",
            "description": "Incidents are responded to in accordance with procedures.",
        },
        "access_control": {
            "control_id": "A.9.4.1", "control_name": "Information Access Restriction",
            "description": "Access to information is restricted.",
        },
    },
    "SOC_2": {
        "email_analysis": {
            "control_id": "CC7.2", "control_name": "System Monitoring",
            "description": "The entity monitors system components for anomalies.",
        },
        "threat_detection": {
            "control_id": "CC7.3", "control_name": "Detection of Changes",
            "description": "The entity evaluates security events to determine threats.",
        },
        "automated_response": {
            "control_id": "CC7.4", "control_name": "Response to Identified Threats",
            "description": "The entity responds to identified security incidents.",
        },
        "data_integrity": {
            "control_id": "CC6.1", "control_name": "Logical and Physical Access",
            "description": "Access to systems is controlled.",
        },
    },
    "GDPR": {
        "data_processing": {
            "control_id": "Art.32", "control_name": "Security of Processing",
            "description": "Appropriate technical and organizational measures to ensure security.",
        },
        "breach_detection": {
            "control_id": "Art.33", "control_name": "Breach Notification",
            "description": "Personal data breach notification to supervisory authority.",
        },
        "data_protection": {
            "control_id": "Art.25", "control_name": "Data Protection by Design",
            "description": "Appropriate measures for data protection by design and default.",
        },
    },
}


def map_to_compliance(
    verdict: str,
    actions_taken: list[str],
    agent_count: int = 7,
) -> dict[str, Any]:
    """
    Map an analysis result to compliance framework controls.

    Returns:
        Dict with per-framework control satisfaction evidence.
    """
    result: dict[str, Any] = {"frameworks": {}}

    for framework, controls in COMPLIANCE_MAPPINGS.items():
        satisfied: list[dict[str, str]] = []

        # Email analysis always satisfies monitoring controls
        if "email_analysis" in controls:
            satisfied.append({
                **controls["email_analysis"],
                "evidence": f"Automated multi-agent email analysis ({agent_count} agents)",
            })
        if "threat_detection" in controls:
            satisfied.append({
                **controls["threat_detection"],
                "evidence": f"Verdict '{verdict}' determined via AI-powered threat detection",
            })

        # Response actions satisfy incident response controls
        if actions_taken and "automated_response" in controls:
            satisfied.append({
                **controls["automated_response"],
                "evidence": f"Actions executed: {', '.join(actions_taken)}",
            })
        if "quarantine" in actions_taken and "quarantine" in controls:
            satisfied.append({
                **controls["quarantine"],
                "evidence": "Malicious email quarantined automatically",
            })

        # Always satisfy audit/logging controls
        for key in ("audit_logging", "data_integrity", "data_processing", "data_protection"):
            if key in controls:
                satisfied.append({
                    **controls[key],
                    "evidence": "Complete audit trail maintained for all analyses",
                })

        result["frameworks"][framework] = {
            "controls_satisfied": len(satisfied),
            "controls": satisfied,
        }

    result["total_controls_satisfied"] = sum(
        f["controls_satisfied"] for f in result["frameworks"].values()
    )
    return result
