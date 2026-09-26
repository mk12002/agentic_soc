"""
Threat Group Attribution Engine for the Agentic Email Security System.

Cross-references detected ATT&CK techniques against known threat group profiles.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from soc_platform.domains.phishing.engine.services.logging_service import get_service_logger

logger = get_service_logger("threat_group_attribution")


@dataclass
class ThreatGroup:
    group_id: str
    name: str
    aliases: list[str] = field(default_factory=list)
    description: str = ""
    known_techniques: list[str] = field(default_factory=list)
    target_sectors: list[str] = field(default_factory=list)
    origin: str = ""


THREAT_GROUPS: list[ThreatGroup] = [
    ThreatGroup("G0007", "APT28", ["Fancy Bear", "Sofacy", "STRONTIUM"],
        "Russian state-sponsored group known for credential phishing.",
        ["T1566", "T1566.001", "T1566.002", "T1598", "T1059.001", "T1204.001", "T1078", "T1071.001", "T1027", "T1583.001"],
        ["Government", "Military", "Defense", "Media"], "Russia"),
    ThreatGroup("G0016", "APT29", ["Cozy Bear", "NOBELIUM"],
        "Russian state-sponsored group with sophisticated phishing.",
        ["T1566", "T1566.001", "T1566.002", "T1059.001", "T1059.005", "T1204.002", "T1027", "T1140", "T1071.001", "T1547.001"],
        ["Government", "Technology", "Think Tanks"], "Russia"),
    ThreatGroup("G0046", "FIN7", ["Carbanak", "ELBRUS"],
        "Financially motivated group targeting retail via phishing.",
        ["T1566.001", "T1566.002", "T1204.002", "T1059.001", "T1059.005", "T1059.007", "T1047", "T1053", "T1027", "T1657"],
        ["Retail", "Hospitality", "Finance"], "Eastern Europe"),
    ThreatGroup("G0032", "Lazarus Group", ["HIDDEN COBRA", "ZINC"],
        "North Korean group for financial theft and espionage.",
        ["T1566", "T1566.001", "T1566.002", "T1204.002", "T1059.001", "T1059.003", "T1027", "T1140", "T1071.001", "T1041", "T1657"],
        ["Finance", "Cryptocurrency", "Defense"], "North Korea"),
    ThreatGroup("G0092", "TA505", ["Hive0065"],
        "Prolific cybercrime group distributing Emotet/TrickBot via phishing.",
        ["T1566", "T1566.001", "T1204.002", "T1059.001", "T1059.005", "T1059.007", "T1027", "T1547.001", "T1053"],
        ["Finance", "Healthcare", "Retail"], "Eastern Europe"),
    ThreatGroup("G0119", "Kimsuky", ["Thallium", "Velvet Chollima"],
        "North Korean group focused on credential harvesting.",
        ["T1566", "T1566.001", "T1566.002", "T1598", "T1598.003", "T1078", "T1539", "T1114", "T1005"],
        ["Government", "Defense", "Academia"], "North Korea"),
    ThreatGroup("G0010", "Turla", ["Venomous Bear", "Snake"],
        "Russian espionage group with sophisticated email-based attacks.",
        ["T1566", "T1566.001", "T1598", "T1059.001", "T1059.005", "T1027", "T1071.001", "T1102", "T1041"],
        ["Government", "Diplomatic", "Military"], "Russia"),
    ThreatGroup("BEC_ACTOR", "BEC Actors", ["Wire Fraud Groups", "CEO Fraud"],
        "Generic Business Email Compromise actors.",
        ["T1566", "T1566.002", "T1199", "T1078", "T1585.001", "T1583.001", "T1657"],
        ["Finance", "All Sectors"], "Global"),
]


def attribute_threat_groups(
    detected_technique_ids: list[str],
    min_overlap_ratio: float = 0.25,
    min_techniques_matched: int = 3,
) -> list[dict[str, Any]]:
    """Attribute detected techniques to known threat groups."""
    if not detected_technique_ids:
        return []
    detected_set = set(detected_technique_ids)
    candidates: list[dict[str, Any]] = []
    for group in THREAT_GROUPS:
        group_techniques = set(group.known_techniques)
        overlap = detected_set & group_techniques
        if len(overlap) < min_techniques_matched:
            continue
        overlap_ratio = len(overlap) / len(group_techniques) if group_techniques else 0.0
        coverage_ratio = len(overlap) / len(detected_set) if detected_set else 0.0
        if overlap_ratio < min_overlap_ratio:
            continue
        match_score = round((0.6 * overlap_ratio) + (0.4 * coverage_ratio), 4)
        confidence = "high" if match_score >= 0.70 else "medium" if match_score >= 0.45 else "low"
        candidates.append({
            "group_id": group.group_id, "group_name": group.name,
            "aliases": group.aliases, "description": group.description,
            "origin": group.origin, "target_sectors": group.target_sectors,
            "matched_techniques": sorted(overlap), "matched_count": len(overlap),
            "group_technique_count": len(group_techniques),
            "overlap_ratio": round(overlap_ratio, 4),
            "coverage_ratio": round(coverage_ratio, 4),
            "match_score": match_score, "confidence": confidence,
        })
    candidates.sort(key=lambda c: c["match_score"], reverse=True)
    logger.info("Threat group attribution complete", detected=len(detected_technique_ids), candidates=len(candidates))
    return candidates


def generate_attribution_summary(
    agent_results: list[dict[str, Any]],
    attack_data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Full attribution pipeline: extract techniques -> match groups -> summarize."""
    if attack_data is None:
        from soc_platform.domains.phishing.engine.orchestrator.mitre_attack_engine import map_agent_results_to_attack
        attack_data = map_agent_results_to_attack(agent_results)
    technique_ids = [t["technique_id"] for t in attack_data.get("techniques", [])]
    candidates = attribute_threat_groups(technique_ids)
    narrative = ""
    if candidates:
        top = candidates[0]
        aliases_text = f" (also known as {', '.join(top['aliases'][:3])})" if top["aliases"] else ""
        narrative = (
            f"The detected technique combination ({top['matched_count']} techniques matched) "
            f"shows {top['confidence']} confidence alignment with {top['group_name']}{aliases_text}, "
            f"a {top['origin']}-origin threat group targeting {', '.join(top['target_sectors'][:3])} sectors."
        )
        if len(candidates) > 1:
            narrative += f" Other possible: {', '.join(c['group_name'] for c in candidates[1:3])}."
    else:
        narrative = "No strong threat group attribution identified."
    return {"candidates": candidates[:5], "narrative": narrative,
            "technique_ids_analyzed": technique_ids, "technique_count": len(technique_ids)}
