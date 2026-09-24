"""
MITRE ATT&CK Mapping Engine for the Agentic Email Security System.

Provides comprehensive, granular mapping of agent indicators to MITRE ATT&CK
tactics, techniques, and sub-techniques. Supports:
- 30+ email-relevant ATT&CK techniques across all kill chain phases
- Confidence-weighted scoring per technique
- Threat group attribution based on technique combinations
- ATT&CK Navigator layer export
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from soc_platform.domains.phishing.engine.services.logging_service import get_service_logger

logger = get_service_logger("mitre_attack_engine")


# ---------------------------------------------------------------------------
# ATT&CK Technique Definitions
# ---------------------------------------------------------------------------

@dataclass
class AttackTechnique:
    """A single MITRE ATT&CK technique or sub-technique."""
    technique_id: str
    name: str
    tactic_id: str
    tactic_name: str
    description: str
    url: str = ""
    is_subtechnique: bool = False


# Comprehensive technique catalog for email-based attacks
TECHNIQUE_CATALOG: dict[str, AttackTechnique] = {
    # --- TA0043: Reconnaissance ---
    "T1598": AttackTechnique("T1598", "Phishing for Information", "TA0043", "Reconnaissance",
                              "Adversary sends phishing messages to gather information."),
    "T1598.001": AttackTechnique("T1598.001", "Spearphishing Service", "TA0043", "Reconnaissance",
                                  "Phishing for information via third-party services.", is_subtechnique=True),
    "T1598.002": AttackTechnique("T1598.002", "Spearphishing Attachment (Recon)", "TA0043", "Reconnaissance",
                                  "Phishing for information via malicious attachments.", is_subtechnique=True),
    "T1598.003": AttackTechnique("T1598.003", "Spearphishing Link (Recon)", "TA0043", "Reconnaissance",
                                  "Phishing for information via malicious links.", is_subtechnique=True),

    # --- TA0042: Resource Development ---
    "T1583.001": AttackTechnique("T1583.001", "Domains", "TA0042", "Resource Development",
                                  "Adversary acquires domains for operations.", is_subtechnique=True),
    "T1585.001": AttackTechnique("T1585.001", "Email Accounts", "TA0042", "Resource Development",
                                  "Adversary creates email accounts for use in targeting.", is_subtechnique=True),
    "T1608.005": AttackTechnique("T1608.005", "Link Target", "TA0042", "Resource Development",
                                  "Adversary prepares resources for link-based delivery.", is_subtechnique=True),

    # --- TA0001: Initial Access ---
    "T1566": AttackTechnique("T1566", "Phishing", "TA0001", "Initial Access",
                              "Adversary sends phishing messages to gain access."),
    "T1566.001": AttackTechnique("T1566.001", "Spearphishing Attachment", "TA0001", "Initial Access",
                                  "Spearphishing with malicious attachment.", is_subtechnique=True),
    "T1566.002": AttackTechnique("T1566.002", "Spearphishing Link", "TA0001", "Initial Access",
                                  "Spearphishing with malicious link.", is_subtechnique=True),
    "T1566.003": AttackTechnique("T1566.003", "Spearphishing via Service", "TA0001", "Initial Access",
                                  "Spearphishing via third-party service.", is_subtechnique=True),
    "T1199": AttackTechnique("T1199", "Trusted Relationship", "TA0001", "Initial Access",
                              "Abuse of trusted third-party relationship."),
    "T1078": AttackTechnique("T1078", "Valid Accounts", "TA0001", "Initial Access",
                              "Use of compromised credentials for access."),

    # --- TA0002: Execution ---
    "T1204": AttackTechnique("T1204", "User Execution", "TA0002", "Execution",
                              "Relies on user to execute malicious content."),
    "T1204.001": AttackTechnique("T1204.001", "Malicious Link", "TA0002", "Execution",
                                  "User clicks malicious link.", is_subtechnique=True),
    "T1204.002": AttackTechnique("T1204.002", "Malicious File", "TA0002", "Execution",
                                  "User opens malicious file.", is_subtechnique=True),
    "T1059": AttackTechnique("T1059", "Command and Scripting Interpreter", "TA0002", "Execution",
                              "Execution via command-line or scripting interpreter."),
    "T1059.001": AttackTechnique("T1059.001", "PowerShell", "TA0002", "Execution",
                                  "Execution via PowerShell.", is_subtechnique=True),
    "T1059.003": AttackTechnique("T1059.003", "Windows Command Shell", "TA0002", "Execution",
                                  "Execution via cmd.exe.", is_subtechnique=True),
    "T1059.005": AttackTechnique("T1059.005", "Visual Basic", "TA0002", "Execution",
                                  "Execution via VBA/VBScript.", is_subtechnique=True),
    "T1059.007": AttackTechnique("T1059.007", "JavaScript", "TA0002", "Execution",
                                  "Execution via JavaScript.", is_subtechnique=True),
    "T1047": AttackTechnique("T1047", "Windows Management Instrumentation", "TA0002", "Execution",
                              "Execution via WMI."),

    # --- TA0005: Defense Evasion ---
    "T1027": AttackTechnique("T1027", "Obfuscated Files or Information", "TA0005", "Defense Evasion",
                              "Obfuscation to impede detection."),
    "T1027.002": AttackTechnique("T1027.002", "Software Packing", "TA0005", "Defense Evasion",
                                  "Executable packing for evasion.", is_subtechnique=True),
    "T1140": AttackTechnique("T1140", "Deobfuscate/Decode Files or Information", "TA0005", "Defense Evasion",
                              "Decode obfuscated content during execution."),
    "T1218": AttackTechnique("T1218", "System Binary Proxy Execution", "TA0005", "Defense Evasion",
                              "Use of trusted system binaries for execution."),
    "T1218.011": AttackTechnique("T1218.011", "Rundll32", "TA0005", "Defense Evasion",
                                  "Execution via rundll32.exe.", is_subtechnique=True),

    # --- TA0003: Persistence ---
    "T1137": AttackTechnique("T1137", "Office Application Startup", "TA0003", "Persistence",
                              "Persistence via Office startup mechanisms."),
    "T1547.001": AttackTechnique("T1547.001", "Registry Run Keys / Startup Folder", "TA0003", "Persistence",
                                  "Registry-based autostart persistence.", is_subtechnique=True),
    "T1053": AttackTechnique("T1053", "Scheduled Task/Job", "TA0003", "Persistence",
                              "Persistence via scheduled tasks."),

    # --- TA0006: Credential Access ---
    "T1056": AttackTechnique("T1056", "Input Capture", "TA0006", "Credential Access",
                              "Capture user input including credentials."),
    "T1056.001": AttackTechnique("T1056.001", "Keylogging", "TA0006", "Credential Access",
                                  "Keylogging for credential capture.", is_subtechnique=True),
    "T1539": AttackTechnique("T1539", "Steal Web Session Cookie", "TA0006", "Credential Access",
                              "Steal web session cookies."),
    "T1111": AttackTechnique("T1111", "Multi-Factor Authentication Interception", "TA0006", "Credential Access",
                              "Intercept MFA tokens."),

    # --- TA0009: Collection ---
    "T1114": AttackTechnique("T1114", "Email Collection", "TA0009", "Collection",
                              "Collection of email data."),
    "T1114.001": AttackTechnique("T1114.001", "Local Email Collection", "TA0009", "Collection",
                                  "Collect email from local sources.", is_subtechnique=True),
    "T1114.002": AttackTechnique("T1114.002", "Remote Email Collection", "TA0009", "Collection",
                                  "Collect email from remote sources.", is_subtechnique=True),
    "T1005": AttackTechnique("T1005", "Data from Local System", "TA0009", "Collection",
                              "Collect data from local file system."),

    # --- TA0011: Command and Control ---
    "T1071": AttackTechnique("T1071", "Application Layer Protocol", "TA0011", "Command and Control",
                              "C2 via application layer protocols."),
    "T1071.001": AttackTechnique("T1071.001", "Web Protocols", "TA0011", "Command and Control",
                                  "C2 via HTTP/HTTPS.", is_subtechnique=True),
    "T1102": AttackTechnique("T1102", "Web Service", "TA0011", "Command and Control",
                              "C2 via legitimate web services."),

    # --- TA0010: Exfiltration ---
    "T1041": AttackTechnique("T1041", "Exfiltration Over C2 Channel", "TA0010", "Exfiltration",
                              "Exfiltration via C2 channel."),
    "T1567": AttackTechnique("T1567", "Exfiltration Over Web Service", "TA0010", "Exfiltration",
                              "Exfiltration via web services."),

    # --- TA0040: Impact ---
    "T1657": AttackTechnique("T1657", "Financial Theft", "TA0040", "Impact",
                              "Financial theft via BEC or wire fraud."),
}


# ---------------------------------------------------------------------------
# Indicator → Technique Mapping Rules
# ---------------------------------------------------------------------------

@dataclass
class MappingRule:
    """A rule that maps agent indicators to ATT&CK techniques."""
    agent_name: str          # Agent that produces the indicator
    keywords: list[str]      # Keywords to match in indicator text
    technique_ids: list[str]  # ATT&CK technique IDs to map to
    confidence: float = 0.8  # Confidence in mapping [0, 1]
    phase: str = ""          # Kill chain phase hint
    require_all: bool = False  # If True, ALL keywords must match


MAPPING_RULES: list[MappingRule] = [
    # --- Header Agent Mappings ---
    MappingRule("header_agent", ["dmarc_failed", "dmarc_fail"], ["T1566", "T1583.001"], 0.85, "Delivery"),
    MappingRule("header_agent", ["dkim_failed", "dkim_fail"], ["T1566", "T1583.001"], 0.80, "Delivery"),
    MappingRule("header_agent", ["spf_failed", "spf_fail"], ["T1566", "T1583.001"], 0.80, "Delivery"),
    MappingRule("header_agent", ["lookalike_domain", "typosquat"], ["T1566", "T1583.001", "T1585.001"], 0.90, "Delivery"),
    MappingRule("header_agent", ["domain_spoofing", "spoof"], ["T1566", "T1199"], 0.85, "Delivery"),
    MappingRule("header_agent", ["reply_to_domain_mismatch"], ["T1566", "T1585.001"], 0.75, "Delivery"),
    MappingRule("header_agent", ["authentication_results_missing", "no_auth_headers"], ["T1566"], 0.65, "Delivery"),
    MappingRule("header_agent", ["short_smtp_trace"], ["T1566", "T1583.001"], 0.60, "Delivery"),
    MappingRule("header_agent", ["newly_registered_domain", "domain_age"], ["T1583.001", "T1608.005"], 0.80, "Delivery"),

    # --- Content Agent Mappings ---
    MappingRule("content_agent", ["urgency_signals", "urgent"], ["T1566", "T1204"], 0.75, "Lure"),
    MappingRule("content_agent", ["credential_signals", "password", "login", "verify account"], ["T1566", "T1598.003", "T1078"], 0.85, "Lure"),
    MappingRule("content_agent", ["financial_signals", "invoice", "payment", "wire", "transfer"], ["T1566", "T1657"], 0.85, "Lure"),
    MappingRule("content_agent", ["bec_fraud_signals", "bec_pattern"], ["T1566", "T1657", "T1199"], 0.90, "Lure"),
    MappingRule("content_agent", ["spam_marketing_signals"], ["T1566"], 0.50, "Lure"),
    MappingRule("content_agent", ["ml_slm_label:phishing"], ["T1566", "T1204"], 0.80, "Lure"),
    MappingRule("content_agent", ["ml_slm_label:spam"], ["T1566"], 0.45, "Lure"),

    # --- URL Agent Mappings ---
    MappingRule("url_agent", ["brand_impersonation"], ["T1566.002", "T1598.003", "T1608.005"], 0.90, "Weaponization"),
    MappingRule("url_agent", ["credential_bait", "credential_harvesting"], ["T1566.002", "T1078", "T1539"], 0.90, "Weaponization"),
    MappingRule("url_agent", ["shortener", "redirect", "url_shortener"], ["T1566.002", "T1608.005"], 0.70, "Weaponization"),
    MappingRule("url_agent", ["non_https_url"], ["T1566.002"], 0.55, "Weaponization"),
    MappingRule("url_agent", ["many_urls"], ["T1566.002"], 0.50, "Weaponization"),
    MappingRule("url_agent", ["ip_based_url"], ["T1566.002", "T1071.001"], 0.75, "Weaponization"),
    MappingRule("url_agent", ["obfuscated_url", "encoded_url"], ["T1027", "T1566.002"], 0.80, "Weaponization"),
    MappingRule("url_agent", ["data_uri"], ["T1027", "T1140"], 0.80, "Weaponization"),

    # --- Attachment Agent Mappings ---
    MappingRule("attachment_agent", ["risky_executable", ".exe", "executable"], ["T1566.001", "T1204.002"], 0.95, "Weaponization"),
    MappingRule("attachment_agent", ["macro", ".docm", ".xlsm", "macro_enabled"], ["T1566.001", "T1204.002", "T1059.005", "T1137"], 0.90, "Weaponization"),
    MappingRule("attachment_agent", [".zip", ".rar", ".7z", "archive"], ["T1566.001", "T1027"], 0.70, "Weaponization"),
    MappingRule("attachment_agent", [".pdf"], ["T1566.001", "T1204.002"], 0.55, "Weaponization"),
    MappingRule("attachment_agent", [".js", ".vbs", ".wsf", "script"], ["T1566.001", "T1059.007", "T1059.005"], 0.90, "Weaponization"),
    MappingRule("attachment_agent", [".iso", ".img", "disk_image"], ["T1566.001", "T1027"], 0.85, "Weaponization"),
    MappingRule("attachment_agent", [".lnk", "shortcut"], ["T1566.001", "T1204.002"], 0.85, "Weaponization"),
    MappingRule("attachment_agent", ["double_extension"], ["T1036", "T1566.001"], 0.85, "Weaponization"),
    MappingRule("attachment_agent", ["high_entropy", "packed", "encrypted"], ["T1027", "T1027.002"], 0.75, "Weaponization"),

    # --- Sandbox Agent Mappings ---
    MappingRule("sandbox_agent", ["powershell", "pwsh"], ["T1059.001", "T1204.002"], 0.90, "Execution"),
    MappingRule("sandbox_agent", ["cmd", "cmd.exe", "command_shell"], ["T1059.003", "T1204.002"], 0.85, "Execution"),
    MappingRule("sandbox_agent", ["wscript", "cscript", "vbscript"], ["T1059.005"], 0.85, "Execution"),
    MappingRule("sandbox_agent", ["rundll32"], ["T1218.011"], 0.85, "Execution"),
    MappingRule("sandbox_agent", ["wmi", "wmiprvse"], ["T1047"], 0.80, "Execution"),
    MappingRule("sandbox_agent", ["scheduled_task", "schtasks"], ["T1053"], 0.80, "Persistence"),
    MappingRule("sandbox_agent", ["registry_modification", "registry_run", "autostart"], ["T1547.001"], 0.85, "Persistence"),
    MappingRule("sandbox_agent", ["network_connection", "dns_query", "http_request", "c2_callback"], ["T1071.001", "T1102"], 0.80, "C2"),
    MappingRule("sandbox_agent", ["process_injection", "inject"], ["T1055"], 0.85, "Execution"),
    MappingRule("sandbox_agent", ["keylog", "input_capture"], ["T1056.001"], 0.80, "Collection"),
    MappingRule("sandbox_agent", ["file_download", "dropper"], ["T1105"], 0.80, "C2"),
    MappingRule("sandbox_agent", ["data_exfil", "exfiltration"], ["T1041", "T1567"], 0.80, "Exfiltration"),

    # --- Threat Intel Agent Mappings ---
    MappingRule("threat_intel_agent", ["known_bad_domain", "blacklisted_domain"], ["T1566", "T1583.001"], 0.95, "Delivery"),
    MappingRule("threat_intel_agent", ["known_bad_ip", "blacklisted_ip"], ["T1071.001"], 0.90, "C2"),
    MappingRule("threat_intel_agent", ["known_bad_hash", "malware_hash"], ["T1566.001", "T1204.002"], 0.95, "Weaponization"),
    MappingRule("threat_intel_agent", ["phishing_feed_match"], ["T1566", "T1598"], 0.90, "Delivery"),

    # --- User Behavior Agent Mappings ---
    MappingRule("user_behavior_agent", ["unfamiliar_sender_domain"], ["T1566", "T1585.001"], 0.70, "Delivery"),
    MappingRule("user_behavior_agent", ["high_risk_recipient", "targeted_role"], ["T1566", "T1598"], 0.75, "Delivery"),
    MappingRule("user_behavior_agent", ["anomalous_sending_pattern"], ["T1078", "T1585.001"], 0.65, "Delivery"),
]


# ---------------------------------------------------------------------------
# Core Mapping Functions
# ---------------------------------------------------------------------------

@dataclass
class TechniqueMatch:
    """A matched ATT&CK technique with confidence and evidence."""
    technique: AttackTechnique
    confidence: float
    evidence: list[str] = field(default_factory=list)
    agent_name: str = ""
    phase: str = ""


def map_indicator_to_techniques(
    agent_name: str,
    indicator: str,
    agent_risk_score: float = 0.0,
    agent_confidence: float = 0.0,
) -> list[TechniqueMatch]:
    """
    Map a single agent indicator to ATT&CK techniques.

    Args:
        agent_name: Name of the agent producing the indicator.
        indicator: Raw indicator string.
        agent_risk_score: Agent's risk score for confidence weighting.
        agent_confidence: Agent's confidence score.

    Returns:
        List of TechniqueMatch objects.
    """
    text = str(indicator).lower()
    matches: list[TechniqueMatch] = []
    seen_technique_ids: set[str] = set()

    for rule in MAPPING_RULES:
        if rule.agent_name != agent_name:
            continue

        if rule.require_all:
            matched = all(kw in text for kw in rule.keywords)
        else:
            matched = any(kw in text for kw in rule.keywords)

        if not matched:
            continue

        # Weight confidence by agent risk and agent confidence
        weighted_confidence = rule.confidence * max(0.3, min(1.0, agent_risk_score)) * max(0.5, agent_confidence)
        weighted_confidence = round(min(1.0, weighted_confidence), 4)

        for tech_id in rule.technique_ids:
            if tech_id in seen_technique_ids:
                continue
            seen_technique_ids.add(tech_id)

            technique = TECHNIQUE_CATALOG.get(tech_id)
            if not technique:
                continue

            matches.append(TechniqueMatch(
                technique=technique,
                confidence=weighted_confidence,
                evidence=[f"[{agent_name}] {indicator}"],
                agent_name=agent_name,
                phase=rule.phase,
            ))

    return matches


def map_agent_results_to_attack(
    agent_results: list[dict[str, Any]],
) -> dict[str, Any]:
    """
    Map all agent results to a comprehensive ATT&CK assessment.

    Returns:
        Dict containing:
        - techniques: list of matched techniques with confidence
        - tactics_summary: aggregated tactic coverage
        - kill_chain_phases: ordered kill chain phase mapping
        - technique_count: total unique techniques detected
    """
    all_matches: list[TechniqueMatch] = []
    technique_aggregation: dict[str, TechniqueMatch] = {}

    for result in agent_results:
        agent_name = str(result.get("agent_name", ""))
        risk_score = float(result.get("risk_score", 0.0) or 0.0)
        confidence = float(result.get("confidence", 0.0) or 0.0)
        indicators = result.get("indicators", []) or []

        for indicator in indicators:
            matches = map_indicator_to_techniques(
                agent_name=agent_name,
                indicator=str(indicator),
                agent_risk_score=risk_score,
                agent_confidence=confidence,
            )
            for match in matches:
                tech_id = match.technique.technique_id
                if tech_id in technique_aggregation:
                    existing = technique_aggregation[tech_id]
                    existing.confidence = max(existing.confidence, match.confidence)
                    existing.evidence.extend(match.evidence)
                else:
                    technique_aggregation[tech_id] = match

    # Build sorted techniques list
    techniques = sorted(
        technique_aggregation.values(),
        key=lambda m: m.confidence,
        reverse=True,
    )

    # Aggregate by tactic
    tactics_summary: dict[str, dict[str, Any]] = {}
    for match in techniques:
        tactic_id = match.technique.tactic_id
        tactic_name = match.technique.tactic_name
        key = f"{tactic_id}: {tactic_name}"
        if key not in tactics_summary:
            tactics_summary[key] = {
                "tactic_id": tactic_id,
                "tactic_name": tactic_name,
                "technique_count": 0,
                "max_confidence": 0.0,
                "techniques": [],
            }
        tactics_summary[key]["technique_count"] += 1
        tactics_summary[key]["max_confidence"] = max(
            tactics_summary[key]["max_confidence"],
            match.confidence,
        )
        tactics_summary[key]["techniques"].append(match.technique.technique_id)

    # Build kill chain phases
    phase_order = [
        "Reconnaissance", "Resource Development", "Delivery", "Lure",
        "Weaponization", "Execution", "Persistence", "Defense Evasion",
        "Credential Access", "Collection", "C2", "Exfiltration", "Impact",
    ]
    kill_chain: list[dict[str, Any]] = []
    for phase in phase_order:
        phase_techniques = [m for m in techniques if m.phase == phase or m.technique.tactic_name == phase]
        if phase_techniques:
            kill_chain.append({
                "phase": phase,
                "techniques": [
                    {
                        "technique_id": m.technique.technique_id,
                        "name": m.technique.name,
                        "confidence": m.confidence,
                        "evidence_count": len(m.evidence),
                    }
                    for m in phase_techniques
                ],
                "max_confidence": max(m.confidence for m in phase_techniques),
            })

    result = {
        "techniques": [
            {
                "technique_id": m.technique.technique_id,
                "technique_name": m.technique.name,
                "tactic_id": m.technique.tactic_id,
                "tactic_name": m.technique.tactic_name,
                "confidence": m.confidence,
                "evidence": m.evidence[:5],  # Limit evidence per technique
                "phase": m.phase,
                "is_subtechnique": m.technique.is_subtechnique,
            }
            for m in techniques
        ],
        "tactics_summary": tactics_summary,
        "kill_chain_phases": kill_chain,
        "technique_count": len(techniques),
        "tactic_count": len(tactics_summary),
    }

    logger.info(
        "ATT&CK mapping complete",
        technique_count=result["technique_count"],
        tactic_count=result["tactic_count"],
    )
    return result


def format_attack_label(technique_id: str) -> str:
    """Format a technique ID into a human-readable ATT&CK label."""
    tech = TECHNIQUE_CATALOG.get(technique_id)
    if tech:
        return f"{tech.tactic_id}: {tech.tactic_name} | {tech.technique_id}: {tech.name}"
    return f"{technique_id}: Unknown Technique"
