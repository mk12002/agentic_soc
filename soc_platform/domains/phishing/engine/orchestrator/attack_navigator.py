"""
ATT&CK Navigator Layer Export for the Agentic Email Security System.

Generates MITRE ATT&CK Navigator-compatible JSON layers from analysis results,
enabling analysts to visualize detected techniques on the official ATT&CK matrix.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from soc_platform.domains.phishing.engine.orchestrator.mitre_attack_engine import map_agent_results_to_attack
from soc_platform.domains.phishing.engine.services.logging_service import get_service_logger

logger = get_service_logger("attack_navigator")

# ATT&CK Navigator layer schema version
NAVIGATOR_VERSION = "4.9"
LAYER_VERSION = "4.5"
ATT_CK_DOMAIN = "enterprise-attack"


def _confidence_to_color(confidence: float) -> str:
    """Map confidence score to a color gradient (green → yellow → red)."""
    if confidence >= 0.85:
        return "#ff0000"  # Red — high confidence detection
    if confidence >= 0.70:
        return "#ff6600"  # Orange
    if confidence >= 0.50:
        return "#ffcc00"  # Yellow
    if confidence >= 0.30:
        return "#99cc00"  # Yellow-green
    return "#66cc66"      # Light green — low confidence


def _confidence_to_score(confidence: float) -> int:
    """Map confidence to Navigator score (1-100)."""
    return max(1, min(100, int(confidence * 100)))


def generate_navigator_layer(
    agent_results: list[dict[str, Any]],
    analysis_id: str = "",
    verdict: str = "",
    layer_name: str = "",
) -> dict[str, Any]:
    """
    Generate a MITRE ATT&CK Navigator layer JSON from analysis results.

    The output can be imported directly into the ATT&CK Navigator web tool
    (https://mitre-attack.github.io/attack-navigator/).

    Args:
        agent_results: List of agent result dicts.
        analysis_id: Analysis UUID for metadata.
        verdict: Final verdict for layer metadata.
        layer_name: Optional custom layer name.

    Returns:
        ATT&CK Navigator layer JSON dict.
    """
    attack_data = map_agent_results_to_attack(agent_results)
    techniques = attack_data.get("techniques", [])

    if not layer_name:
        layer_name = f"Email Analysis: {analysis_id[:12]}..." if analysis_id else "Email Threat Analysis"

    # Build Navigator technique annotations
    nav_techniques = []
    for tech in techniques:
        tech_id = tech["technique_id"]
        confidence = tech["confidence"]
        evidence = tech.get("evidence", [])

        # Build comment from evidence
        evidence_text = "; ".join(evidence[:3])
        comment = f"Confidence: {confidence:.0%} | {evidence_text}"

        entry = {
            "techniqueID": tech_id,
            "tactic": _tactic_id_to_shortname(tech.get("tactic_id", "")),
            "color": _confidence_to_color(confidence),
            "comment": comment,
            "score": _confidence_to_score(confidence),
            "enabled": True,
            "showSubtechniques": tech.get("is_subtechnique", False),
            "metadata": [
                {"name": "verdict", "value": verdict},
                {"name": "analysis_id", "value": analysis_id},
                {"name": "confidence", "value": f"{confidence:.4f}"},
                {"name": "phase", "value": tech.get("phase", "")},
            ],
        }
        nav_techniques.append(entry)

    # Build gradient legend
    gradient = {
        "colors": ["#66cc66", "#99cc00", "#ffcc00", "#ff6600", "#ff0000"],
        "minValue": 0,
        "maxValue": 100,
    }

    layer = {
        "name": layer_name,
        "versions": {
            "attack": "15",
            "navigator": NAVIGATOR_VERSION,
            "layer": LAYER_VERSION,
        },
        "domain": ATT_CK_DOMAIN,
        "description": (
            f"Auto-generated ATT&CK layer from Agentic Email Security System analysis. "
            f"Analysis ID: {analysis_id}. Verdict: {verdict}. "
            f"Generated at {datetime.now(timezone.utc).isoformat()}. "
            f"Techniques detected: {len(nav_techniques)}."
        ),
        "filters": {
            "platforms": ["Windows", "macOS", "Linux", "Office 365", "Google Workspace"],
        },
        "sorting": 3,  # Sort by score descending
        "layout": {
            "layout": "side",
            "aggregateFunction": "max",
            "showID": True,
            "showName": True,
            "showAggregateScores": True,
            "countUnscored": False,
        },
        "hideDisabled": False,
        "techniques": nav_techniques,
        "gradient": gradient,
        "legendItems": [
            {"label": "High confidence (≥85%)", "color": "#ff0000"},
            {"label": "Medium-high (70-84%)", "color": "#ff6600"},
            {"label": "Medium (50-69%)", "color": "#ffcc00"},
            {"label": "Low-medium (30-49%)", "color": "#99cc00"},
            {"label": "Low confidence (<30%)", "color": "#66cc66"},
        ],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#1a1a2e",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": True,
        "selectVisibleTechniques": False,
        "metadata": [
            {"name": "system", "value": "Agentic Email Security System"},
            {"name": "analysis_id", "value": analysis_id},
            {"name": "verdict", "value": verdict},
            {"name": "generated_at", "value": datetime.now(timezone.utc).isoformat()},
            {"name": "technique_count", "value": str(len(nav_techniques))},
        ],
    }

    logger.info(
        "ATT&CK Navigator layer generated",
        analysis_id=analysis_id,
        technique_count=len(nav_techniques),
    )
    return layer


def generate_campaign_overlay_layer(
    analyses: list[dict[str, Any]],
    campaign_name: str = "Campaign Analysis",
) -> dict[str, Any]:
    """
    Generate an overlay layer combining multiple analyses for campaign correlation.

    Shows technique convergence across multiple emails in the same campaign.
    """
    technique_hits: dict[str, dict[str, Any]] = {}

    for analysis in analyses:
        agent_results = analysis.get("agent_results", [])
        attack_data = map_agent_results_to_attack(agent_results)

        for tech in attack_data.get("techniques", []):
            tech_id = tech["technique_id"]
            if tech_id not in technique_hits:
                technique_hits[tech_id] = {
                    "count": 0,
                    "max_confidence": 0.0,
                    "tactic_id": tech.get("tactic_id", ""),
                    "analysis_ids": [],
                }
            technique_hits[tech_id]["count"] += 1
            technique_hits[tech_id]["max_confidence"] = max(
                technique_hits[tech_id]["max_confidence"],
                tech["confidence"],
            )
            aid = analysis.get("analysis_id", "")
            if aid and aid not in technique_hits[tech_id]["analysis_ids"]:
                technique_hits[tech_id]["analysis_ids"].append(aid)

    nav_techniques = []
    for tech_id, data in technique_hits.items():
        score = min(100, data["count"] * 25)
        nav_techniques.append({
            "techniqueID": tech_id,
            "tactic": _tactic_id_to_shortname(data["tactic_id"]),
            "color": _confidence_to_color(data["max_confidence"]),
            "comment": f"Seen in {data['count']} emails. Max confidence: {data['max_confidence']:.0%}",
            "score": score,
            "enabled": True,
            "metadata": [
                {"name": "email_count", "value": str(data["count"])},
                {"name": "analysis_ids", "value": ", ".join(data["analysis_ids"][:5])},
            ],
        })

    return {
        "name": campaign_name,
        "versions": {"attack": "15", "navigator": NAVIGATOR_VERSION, "layer": LAYER_VERSION},
        "domain": ATT_CK_DOMAIN,
        "description": f"Campaign overlay layer for {len(analyses)} emails.",
        "techniques": nav_techniques,
        "gradient": {
            "colors": ["#66cc66", "#ffcc00", "#ff0000"],
            "minValue": 0,
            "maxValue": 100,
        },
    }


def _tactic_id_to_shortname(tactic_id: str) -> str:
    """Convert tactic ID to Navigator-expected shortname."""
    mapping = {
        "TA0043": "reconnaissance",
        "TA0042": "resource-development",
        "TA0001": "initial-access",
        "TA0002": "execution",
        "TA0003": "persistence",
        "TA0004": "privilege-escalation",
        "TA0005": "defense-evasion",
        "TA0006": "credential-access",
        "TA0007": "discovery",
        "TA0008": "lateral-movement",
        "TA0009": "collection",
        "TA0011": "command-and-control",
        "TA0010": "exfiltration",
        "TA0040": "impact",
    }
    return mapping.get(tactic_id, "initial-access")
