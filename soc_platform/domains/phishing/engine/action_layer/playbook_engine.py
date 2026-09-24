"""
Response Playbook Engine for the Agentic Email Security System.

Defines and executes playbook-driven automated response workflows
per threat type (BEC, ransomware, credential phishing, etc.).
"""

from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable
from soc_platform.domains.phishing.engine.services.logging_service import get_service_logger

logger = get_service_logger("playbook_engine")


@dataclass
class PlaybookStep:
    """A single step in a response playbook."""
    action: str
    description: str
    auto_execute: bool = True
    requires_approval: bool = False
    parameters: dict[str, Any] = field(default_factory=dict)


@dataclass
class Playbook:
    """A complete response playbook for a threat type."""
    playbook_id: str
    name: str
    description: str
    threat_types: list[str]
    min_risk_score: float = 0.5
    steps: list[PlaybookStep] = field(default_factory=list)
    enabled: bool = True


# Built-in playbooks
PLAYBOOKS: dict[str, Playbook] = {
    "credential_phishing": Playbook(
        "credential_phishing", "Credential Phishing Response",
        "Automated response for credential harvesting attempts.",
        ["credential_phishing", "credential_bait", "login_phishing"],
        min_risk_score=0.6,
        steps=[
            PlaybookStep("quarantine_email", "Quarantine the phishing email"),
            PlaybookStep("add_banner", "Add warning banner to similar emails in transit"),
            PlaybookStep("block_sender", "Block sender domain"),
            PlaybookStep("notify_recipient", "Alert the targeted user"),
            PlaybookStep("extract_iocs", "Extract and store all IOCs (URLs, domains)"),
            PlaybookStep("retroactive_hunt", "Search for similar emails in the last 7 days",
                        auto_execute=False, parameters={"hunt_days": 7}),
        ],
    ),
    "bec_fraud": Playbook(
        "bec_fraud", "Business Email Compromise Response",
        "High-priority response for BEC/wire fraud attempts.",
        ["bec", "wire_fraud", "ceo_fraud", "invoice_fraud"],
        min_risk_score=0.7,
        steps=[
            PlaybookStep("quarantine_email", "Immediate email quarantine"),
            PlaybookStep("block_sender", "Block sender address and domain"),
            PlaybookStep("alert_finance", "Alert finance/treasury team",
                        parameters={"priority": "critical"}),
            PlaybookStep("notify_recipient", "Notify the targeted executive"),
            PlaybookStep("soc_escalation", "Escalate to SOC Tier 2",
                        parameters={"priority": "P1"}),
            PlaybookStep("retroactive_hunt", "Hunt for related BEC attempts",
                        auto_execute=True, parameters={"hunt_days": 30}),
        ],
    ),
    "malware_delivery": Playbook(
        "malware_delivery", "Malware Delivery Response",
        "Response for emails delivering malware via attachments.",
        ["malware", "ransomware", "trojan", "dropper"],
        min_risk_score=0.7,
        steps=[
            PlaybookStep("delete_email", "Delete the malicious email"),
            PlaybookStep("block_sender", "Block sender address"),
            PlaybookStep("quarantine_attachment", "Isolate attachment in sandbox"),
            PlaybookStep("extract_iocs", "Extract IOCs from attachment analysis"),
            PlaybookStep("retroactive_hunt", "Search organization for same attachment hash",
                        parameters={"hunt_days": 14}),
            PlaybookStep("soc_escalation", "Escalate for malware analysis",
                        parameters={"priority": "P1"}),
        ],
    ),
    "spearphishing_link": Playbook(
        "spearphishing_link", "Spearphishing Link Response",
        "Response for targeted spearphishing with malicious links.",
        ["spearphishing", "malicious_link", "drive_by"],
        min_risk_score=0.6,
        steps=[
            PlaybookStep("quarantine_email", "Quarantine the email"),
            PlaybookStep("block_url", "Block malicious URL at proxy/gateway"),
            PlaybookStep("add_banner", "Add warning banner"),
            PlaybookStep("notify_recipient", "Alert the targeted user"),
            PlaybookStep("extract_iocs", "Extract URL IOCs"),
        ],
    ),
    "generic_suspicious": Playbook(
        "generic_suspicious", "Generic Suspicious Email Response",
        "Standard response for suspicious emails below high-risk threshold.",
        ["suspicious", "anomalous"],
        min_risk_score=0.4,
        steps=[
            PlaybookStep("add_banner", "Add caution banner to email"),
            PlaybookStep("log_for_review", "Queue for analyst review"),
            PlaybookStep("extract_iocs", "Extract IOCs for tracking"),
        ],
    ),
}


def select_playbook(
    verdict: str,
    risk_score: float,
    indicators: list[str],
    decision_notes: list[str] | None = None,
) -> Playbook | None:
    """
    Select the most appropriate playbook based on verdict and indicators.
    """
    indicators_text = " ".join(str(i).lower() for i in indicators)
    notes_text = " ".join(str(n).lower() for n in (decision_notes or []))
    combined = f"{indicators_text} {notes_text} {verdict.lower()}"

    # Priority-ordered matching
    if any(kw in combined for kw in ["bec", "wire_fraud", "ceo_fraud", "invoice_fraud",
                                      "bec_fraud_pattern", "financial_fraud"]):
        pb = PLAYBOOKS["bec_fraud"]
        if risk_score >= pb.min_risk_score:
            return pb

    if any(kw in combined for kw in ["malware", "ransomware", "trojan", "dropper",
                                      "executable", "macro_enabled"]):
        pb = PLAYBOOKS["malware_delivery"]
        if risk_score >= pb.min_risk_score:
            return pb

    if any(kw in combined for kw in ["credential", "login", "password", "verify_account",
                                      "credential_bait", "credential_harvesting"]):
        pb = PLAYBOOKS["credential_phishing"]
        if risk_score >= pb.min_risk_score:
            return pb

    if any(kw in combined for kw in ["spearphishing", "malicious_link", "brand_impersonation"]):
        pb = PLAYBOOKS["spearphishing_link"]
        if risk_score >= pb.min_risk_score:
            return pb

    if verdict in ("suspicious",) and risk_score >= 0.4:
        return PLAYBOOKS["generic_suspicious"]

    return None


def execute_playbook(
    playbook: Playbook,
    analysis_id: str,
    report_data: dict[str, Any],
) -> dict[str, Any]:
    """
    Build the recommended step list for an analysis result.

    This performs no actions. Steps are recorded as ``recommended`` (or
    ``pending_approval``); real execution happens only through the action
    layer, behind the analyst-approval gate (NFR-01).
    """
    execution_log = {
        "playbook_id": playbook.playbook_id,
        "playbook_name": playbook.name,
        "analysis_id": analysis_id,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "steps": [],
        "status": "recommended",
    }

    for step in playbook.steps:
        step_result = {
            "action": step.action,
            "description": step.description,
            "auto_execute": step.auto_execute,
            "requires_approval": step.requires_approval,
            "status": "pending_approval" if step.requires_approval else "recommended",
            "recorded_at": datetime.now(timezone.utc).isoformat(),
        }

        if step.requires_approval:
            step_result["message"] = "Requires analyst approval before execution"

        execution_log["steps"].append(step_result)

    execution_log["completed_at"] = datetime.now(timezone.utc).isoformat()
    logger.info(
        "Playbook executed",
        playbook=playbook.playbook_id,
        analysis_id=analysis_id,
        steps_count=len(execution_log["steps"]),
    )
    return execution_log


def list_playbooks() -> list[dict[str, Any]]:
    """List all available playbooks."""
    return [
        {
            "playbook_id": pb.playbook_id,
            "name": pb.name,
            "description": pb.description,
            "threat_types": pb.threat_types,
            "min_risk_score": pb.min_risk_score,
            "step_count": len(pb.steps),
            "enabled": pb.enabled,
            "steps": [{"action": s.action, "description": s.description,
                       "auto_execute": s.auto_execute} for s in pb.steps],
        }
        for pb in PLAYBOOKS.values()
    ]
