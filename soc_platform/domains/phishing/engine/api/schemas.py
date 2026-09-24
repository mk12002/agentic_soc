"""
Pydantic schemas for the Email Analysis API.

Defines request and response models for all API endpoints.
"""

from typing import Optional
from typing import Any

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# H-1: Feedback schema
# ---------------------------------------------------------------------------

VALID_ANALYST_VERDICTS = {"true_positive", "false_positive", "true_negative", "false_negative", "needs_review"}


class AnalysisFeedbackRequest(BaseModel):
    """Analyst feedback on a completed threat analysis."""

    analyst_verdict: str = Field(
        ...,
        description="Analyst assessment: true_positive | false_positive | true_negative | false_negative | needs_review",
    )
    notes: Optional[str] = Field(
        default=None,
        description="Optional analyst notes explaining the assessment",
    )


# ---------------------------------------------------------------------------
# H-2: Batch ingestion schemas
# ---------------------------------------------------------------------------

class BatchAnalysisRequest(BaseModel):
    """Request body for POST /analyze-batch — up to 50 emails per call."""

    emails: list["EmailAnalysisRequest"] = Field(
        ...,
        description="List of emails to analyse in parallel (max 50)",
    )


class BatchAnalysisResponse(BaseModel):
    """Response body for POST /analyze-batch."""

    queued: int = Field(..., description="Number of emails successfully queued")
    errors: int = Field(..., description="Number of emails that failed to queue")
    results: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Per-email {index, analysis_id, status, report_endpoint}",
    )
    error_details: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Per-email {index, error} for failures",
    )


# ---------------------------------------------------------------------------
# Agent result schema (shared by all agents)
# ---------------------------------------------------------------------------

class AgentResult(BaseModel):
    """Standard output schema returned by every analysis agent."""

    agent_name: str = Field(..., description="Name of the analysis agent")
    risk_score: float = Field(
        default=0.0, ge=0.0, le=1.0, description="Risk score between 0 and 1"
    )
    confidence: float = Field(
        default=0.0, ge=0.0, le=1.0, description="Confidence level between 0 and 1"
    )
    indicators: list[str] = Field(
        default_factory=list, description="List of detected threat indicators"
    )


# ---------------------------------------------------------------------------
# Email analysis request
# ---------------------------------------------------------------------------

class EmailHeaders(BaseModel):
    """Parsed email header fields."""

    sender: str = Field(..., description="Sender email address")
    reply_to: Optional[str] = Field(default=None, description="Reply-To address")
    subject: str = Field(default="", description="Email subject line")
    received: list[str] = Field(
        default_factory=list, description="Received header chain"
    )
    message_id: Optional[str] = Field(default=None, description="Message-ID header")
    authentication_results: Optional[str] = Field(
        default=None, description="SPF/DKIM/DMARC results"
    )
    to: list[str] = Field(default_factory=list, description="Recipient email addresses")


class AttachmentInfo(BaseModel):
    """Metadata for an email attachment."""

    filename: str = Field(..., description="Attachment filename")
    content_type: str = Field(..., description="MIME content type")
    size_bytes: int = Field(default=0, description="File size in bytes")
    content_base64: Optional[str] = Field(
        default=None, description="Base64-encoded file content"
    )


class EmailAnalysisRequest(BaseModel):
    """Request body for the /analyze-email endpoint."""

    headers: EmailHeaders
    body: str = Field(default="", description="Plain-text or HTML email body")
    urls: list[str] = Field(
        default_factory=list, description="URLs extracted from the email"
    )
    attachments: list[AttachmentInfo] = Field(
        default_factory=list, description="Email attachments"
    )


# ---------------------------------------------------------------------------
# Email analysis response
# ---------------------------------------------------------------------------

class StorylineIndicator(BaseModel):
    """Normalized indicator with ATT&CK-like tactic mapping and confidence metadata."""

    value: str = Field(..., description="Observable indicator detail")
    severity: str = Field(..., description="Normalized indicator severity (low/medium/high)")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Indicator confidence from contributing agents")
    tactic: str = Field(..., description="ATT&CK-like tactic label associated with this indicator")


class StorylineEvent(BaseModel):
    """A chronologically mapped component of an email attack."""

    phase: str = Field(..., description="The stage of the attack (Delivery, Lure, Weaponization, Containment)")
    description: str = Field(..., description="High level description of what happened in this phase")
    severity: str = Field(..., description="Normalized phase severity (low/medium/high)")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Aggregated phase confidence")
    tactics: list[str] = Field(default_factory=list, description="ATT&CK-like tactics relevant to the phase")
    indicators: list[StorylineIndicator] = Field(default_factory=list, description="Extracted threat observables triggering this phase")


class EmailAnalysisResponse(BaseModel):
    """Response body for the /analyze-email endpoint."""

    status: str = Field(..., description="Processing status")
    message: str = Field(..., description="Human-readable result message")
    analysis_id: Optional[str] = Field(
        default=None, description="Unique analysis tracking ID"
    )
    agent_results: list[AgentResult] = Field(
        default_factory=list, description="Individual agent analysis results"
    )
    overall_risk_score: Optional[float] = Field(
        default=None, description="Aggregated risk score"
    )
    verdict: Optional[str] = Field(default=None, description="Final decision verdict")
    llm_explanation: Optional[str] = Field(
        default=None, description="LLM-generated explanation for SOC analysts"
    )
    grounded_evidence: Optional[list[dict[str, Any]]] = Field(
        default=None,
        description="Citable evidence records {id, agent, type, claim, raw_value, indicator} derived from agent indicators; every llm_explanation claim references these ids",
    )
    grounded_claims: Optional[list[dict[str, Any]]] = Field(
        default=None,
        description="Validated explanation claims {text, evidence_ids}; each claim cites one or more grounded_evidence ids (anti-hallucination)",
    )
    analyst_brief: Optional[dict[str, Any]] = Field(
        default=None,
        description="SOC-ready structured brief {executive_summary, key_evidence, confidence_assessment, investigation_steps, false_positive_indicators, escalation_recommendation}; built deterministically from the same grounded evidence",
    )
    provenance_chain: Optional[list[dict[str, Any]]] = Field(
        default=None,
        description="Ordered, auditable record of how the verdict was reached: raw_signals -> agent_score -> correlation_boost -> guardrail -> counterfactual -> verdict, each with impact_on_score and refs",
    )
    threat_storyline: Optional[list[StorylineEvent]] = Field(
        default=None, description="Chronological timeline of the attack flow"
    )
    counterfactual_result: Optional[dict] = Field(
        default=None, description="Decision boundary perturbation result explaining what minimum change is needed to make the email safe"
    )
    report_endpoint: Optional[str] = Field(
        default=None,
        description="Endpoint to poll for the final orchestration report",
    )
    final_report_features: Optional[list[str]] = Field(
        default=None,
        description="Fields that are available in final report payloads from /reports/{analysis_id}",
    )


class RabbitMQHealth(BaseModel):
    """Health status for RabbitMQ connection and queues."""

    status: str = Field(..., description="Connection status (healthy/unhealthy)")
    error: Optional[str] = Field(default=None, description="Detailed error message if unhealthy")
    queue_depths: dict[str, int] = Field(
        default_factory=dict, description="Current message counts for monitored queues"
    )


class DiskHealth(BaseModel):
    """Disk space health status."""

    status: str = Field(..., description="Disk status (healthy/warning/critical)")
    free_gb: float = Field(..., description="Free disk space in GB")
    total_gb: float = Field(..., description="Total disk space in GB")
    usage_percent: float = Field(..., description="Disk usage percentage")


class HealthResponse(BaseModel):
    """Response body for the /health endpoint."""

    status: str = Field(default="healthy")
    version: str = Field(default="1.0.0")
    environment: str = Field(default="development")
    rabbitmq: Optional[RabbitMQHealth] = Field(
        default=None, description="RabbitMQ-specific health details"
    )
    disk: Optional[DiskHealth] = Field(
        default=None, description="Disk space health details"
    )


class AgentDirectTestRequest(BaseModel):
    """Request body for direct per-agent testing endpoints."""

    payload: dict[str, Any] = Field(
        default_factory=dict,
        description="Agent-specific payload to test directly without using the event pipeline",
    )
    inject_analysis_id: bool = Field(
        default=True,
        description="If true, add a generated analysis_id when missing from payload",
    )
    print_output: bool = Field(
        default=True,
        description="If true, print agent output to API process stdout for quick local inspection",
    )


class AgentDirectTestResponse(BaseModel):
    """Response body for direct per-agent testing endpoints."""

    status: str = Field(..., description="Execution status")
    agent_name: str = Field(..., description="Tested agent name")
    message: str = Field(..., description="Human-readable execution summary")
    input_payload: dict[str, Any] = Field(
        default_factory=dict,
        description="Payload submitted to the agent",
    )
    output: dict[str, Any] = Field(
        default_factory=dict,
        description="Raw output emitted by the agent",
    )
