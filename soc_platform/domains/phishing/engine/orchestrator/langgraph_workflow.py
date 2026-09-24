"""LangGraph-based orchestrator workflow for threat decisioning."""

from __future__ import annotations

from typing import Any, Callable

from langgraph.graph import END, StateGraph

from soc_platform.domains.phishing.engine.garuda_integration.bridge import trigger_garuda_investigation
from soc_platform.domains.phishing.engine.orchestrator.counterfactual_engine import calculate_counterfactual, threshold_for_verdict
from soc_platform.domains.phishing.engine.orchestrator.evidence_collector import collect_evidence
from soc_platform.domains.phishing.engine.orchestrator.llm_reasoner import generate_grounded_reasoning, generate_reasoning
from soc_platform.domains.phishing.engine.orchestrator.scoring_engine import calculate_threat_score
from soc_platform.domains.phishing.engine.orchestrator.storyline_engine import generate_storyline
from soc_platform.domains.phishing.engine.orchestrator.threat_correlation import correlate_threats
from soc_platform.domains.phishing.engine.orchestrator.langgraph_state import OrchestratorState
from soc_platform.domains.phishing.engine.services.logging_service import get_service_logger

logger = get_service_logger("langgraph_orchestrator")


def _cf_names(counterfactual: dict[str, Any]) -> list[str]:
    """Extract agent names from a counterfactual ``agents_altered`` list (dict or legacy string shape)."""
    names: list[str] = []
    for entry in ((counterfactual or {}).get("agents_altered") or []):
        if isinstance(entry, dict):
            names.append(str(entry.get("agent_name", "unknown")))
        else:
            names.append(str(entry))
    return names


def _contains_indicator(agent: dict[str, Any], token: str) -> bool:
    indicators = [str(item).lower() for item in (agent.get("indicators") or [])]
    return any(token in item for item in indicators)


def _has_hard_malicious_signal(agent_results: list[dict[str, Any]]) -> bool:
    for item in agent_results:
        name = str(item.get("agent_name") or "")
        risk = float(item.get("risk_score") or 0.0)
        if name in {"attachment_agent", "sandbox_agent"} and risk >= 0.75:
            return True
        if name == "threat_intel_agent" and risk >= 0.6:
            return True
        if name == "header_agent" and risk >= 0.5:
            return True
    return False


def _has_strong_transactional_legitimacy(agent_results: list[dict[str, Any]]) -> bool:
    strong_votes = 0
    for item in agent_results:
        if _contains_indicator(item, "transactional_legitimacy_profile:strong"):
            strong_votes += 1
    return strong_votes >= 2


def _has_weak_malicious_compound_warning(agent_results: list[dict[str, Any]]) -> bool:
    content = next((item for item in agent_results if str(item.get("agent_name")) == "content_agent"), None)
    header = next((item for item in agent_results if str(item.get("agent_name")) == "header_agent"), None)
    url = next((item for item in agent_results if str(item.get("agent_name")) == "url_agent"), None)
    user_behavior = next((item for item in agent_results if str(item.get("agent_name")) == "user_behavior_agent"), None)

    if not header or not user_behavior:
        return False

    header_risk = float(header.get("risk_score") or 0.0)
    content_risk = float(content.get("risk_score") or 0.0) if content is not None else 0.0
    url_risk = float(url.get("risk_score") or 0.0) if url is not None else 0.0
    user_risk = float(user_behavior.get("risk_score") or 0.0)

    header_warning = header_risk >= 0.12 and any(
        _contains_indicator(header, token)
        for token in (
            "authentication_results_missing",
            "reply_to_domain_mismatch",
            "no_auth_headers_with_domain",
            "lookalike_domain",
            "dmarc_failed",
        )
    )
    content_warning = content is not None and content_risk >= 0.05 and (
        _contains_indicator(content, "financial_signals:")
        or _contains_indicator(content, "credential_signals:")
        or _contains_indicator(content, "spam_marketing_signals:")
        or _contains_indicator(content, "long_email_body")
    )
    url_warning = url is not None and url_risk >= 0.05 and (
        _contains_indicator(url, "many_urls:")
        or _contains_indicator(url, "non_https_url")
        or _contains_indicator(url, "brand_impersonation")
        or _contains_indicator(url, "credential_bait")
    )
    user_warning = user_risk >= 0.25 and _contains_indicator(user_behavior, "unfamiliar_sender_domain")

    warning_votes = sum((header_warning, content_warning, url_warning, user_warning))
    if warning_votes < 3 or not (header_warning and user_warning):
        return False

    return True


def _apply_transactional_legitimacy_override(
    verdict: str,
    actions: list[str],
    normalized_score: float,
    agent_results: list[dict[str, Any]],
) -> tuple[str, list[str], float, list[str]]:
    decision_notes: list[str] = []
    if (
        verdict in {"suspicious", "high_risk"}
        and _has_strong_transactional_legitimacy(agent_results)
        and not _has_hard_malicious_signal(agent_results)
    ):
        decision_notes.append("downgraded_by_transactional_legitimacy")
        return "likely_safe", ["deliver_with_banner"], min(normalized_score, 0.39), decision_notes
    return verdict, actions, normalized_score, decision_notes


def _has_spam_campaign_pattern(agent_results: list[dict[str, Any]]) -> bool:
    content = next((item for item in agent_results if str(item.get("agent_name")) == "content_agent"), None)
    header = next((item for item in agent_results if str(item.get("agent_name")) == "header_agent"), None)
    if not content:
        return False

    content_risk = float(content.get("risk_score") or 0.0)
    content_indicators = [str(item).lower() for item in (content.get("indicators") or [])]
    has_spam_content = any(ind.startswith("ml_slm_label:spam") for ind in content_indicators) or any(
        ind.startswith("spam_marketing_signals:") for ind in content_indicators
    )
    if not has_spam_content or content_risk < 0.55:
        return False

    header_indicators = [str(item).lower() for item in ((header or {}).get("indicators") or [])]
    has_delivery_anomaly = any(
        token in indicator
        for indicator in header_indicators
        for token in ("authentication_results_missing", "short_smtp_trace", "no_auth_headers_with_domain")
    )
    return has_delivery_anomaly


def _contains_bec_keywords(agent_results: list[dict[str, Any]]) -> bool:
    """Direct keyword check for BEC emails using email data from state.
    
    This is a fallback pattern match when agent indicators aren't sufficient.
    """
    # Get content indicators which often contain the actual email text terms
    all_indicators: list[str] = []
    for agent in agent_results:
        all_indicators.extend([str(i).lower() for i in (agent.get("indicators") or [])])
    
    indicators_text = "\n".join(all_indicators)
    
    # Direct BEC phrases that are unmistakable when combined with urgency
    bec_phrases = [
        "wire", "remit", "transfer", "urgent", "immediate", "asap", 
        "confidential", "swift", "payment", "bank account", "invest"
    ]
    
    # Count how many BEC phrases appear (at least 3 = strong BEC signal)
    phrase_count = sum(1 for phrase in bec_phrases if phrase in indicators_text)
    
    return phrase_count >= 3


def _has_uncertain_conflict_pattern(agent_results: list[dict[str, Any]], normalized_score: float) -> bool:
    """Identify evidence disagreement strong enough to force manual review.

    Trigger only below blocking threshold to avoid overriding clear malicious outcomes.
    """
    if normalized_score >= 0.4:
        return False

    informative = [
        item
        for item in agent_results
        if float(item.get("confidence") or 0.0) >= 0.7
    ]
    if len(informative) < 3:
        return False

    scores = [float(item.get("risk_score") or 0.0) for item in informative]
    high_votes = sum(1 for score in scores if score >= 0.65)
    low_votes = sum(1 for score in scores if score <= 0.2)
    spread = max(scores) - min(scores)

    return high_votes >= 1 and low_votes >= 2 and spread >= 0.45


def _has_obvious_bec_or_fraud_pattern(agent_results: list[dict[str, Any]]) -> bool:
    """Detect classic Business Email Compromise / wire fraud patterns from agent indicators and scores.
    
    BEC emails typically have:
    1. Financial + urgency language signals (content, url agents)
    2. Domain spoofing/authentication failure (header agent)
    3. Unfamiliar sender (user behavior agent)
    
    Don't just look at indicators (which depend on agent implementation).
    Also check risk scores directly: if content + user_behavior both elevated + header shows spoofing = BEC
    """
    # Get individual agent scores
    agent_scores = {item.get("agent_name", ""): float(item.get("risk_score", 0.0)) for item in agent_results}
    
    # Collect all indicators from all agents
    all_indicators: list[str] = []
    for agent in agent_results:
        all_indicators.extend([str(i).lower() for i in (agent.get("indicators") or [])])
    indicators_text = "\n".join(all_indicators)
    
    # Check for objective fraud signals
    content_risk = agent_scores.get("content_agent", 0.0)
    header_risk = agent_scores.get("header_agent", 0.0)
    user_behavior_risk = agent_scores.get("user_behavior_agent", 0.0)
    url_risk = agent_scores.get("url_agent", 0.0)
    
    # Fraud indicators in text
    has_financial_signal = any(term in indicators_text for term in [
        "financial_signals:", "bec_fraud_signals:", "bec_pattern_both",
        "wire", "transfer", "payment", "invoice", "money", "bank"
    ])
    has_urgency_signal = any(term in indicators_text for term in [
        "urgency_signals:", "urgent", "immediately", "asap"
    ])
    has_spoofing_indicator = any(term in indicators_text for term in [
        "lookalike_domain", "domain_spoofing", "no_auth_headers_with_domain", "dmarc_failed",
        "authentication_results_missing", "reply_to_domain_mismatch"
    ])
    has_fraudulent_content = any(term in indicators_text for term in [
        "financial_signals:", "credential_signals:", "bec_fraud_signals:", "bec_pattern_both",
        "wire", "transfer", "payment", "invoice", "money", "bank", "verify account", "password", "login"
    ])
    
    # PATTERN 1: Classic BEC = financial + urgency + spoofing
    if has_financial_signal and has_urgency_signal and has_spoofing_indicator:
        return True
    
    # PATTERN 2: Strong financial + urgency signals + unfamiliar sender with weak auth
    if has_financial_signal and has_urgency_signal and user_behavior_risk >= 0.35:
        return True
    
    # PATTERN 3: Multiple agents detecting fraud independently
    #   - If content_agent is moderately high AND header shows delivery anomaly OR user_behavior high
    high_content = (content_risk >= 0.40 or "bec_fraud_signals:" in indicators_text) and has_fraudulent_content
    high_header_anomaly = (header_risk >= 0.15 and has_spoofing_indicator)
    high_user_behavior = user_behavior_risk >= 0.35
    
    if high_content and (high_header_anomaly or high_user_behavior):
        return True
    
    # PATTERN 4: Very explicit fraud indicators with ANY multi-agent agreement
    if "bec_fraud_signals:" in indicators_text and user_behavior_risk >= 0.3:
        return True
    
    return False


class LangGraphOrchestrator:
    """Builds and executes graph-driven orchestration for final threat decisions."""

    def __init__(
        self,
        save_report: Callable[[str, dict[str, Any]], None],
        execute_actions: Callable[[dict[str, Any]], None],
    ):
        self._save_report = save_report
        self._execute_actions = execute_actions
        self._graph = self._build_graph()

    def _build_graph(self):
        graph = StateGraph(OrchestratorState)

        graph.add_node("score", self._score_node)
        graph.add_node("correlate", self._correlate_node)
        graph.add_node("decide", self._decide_node)
        graph.add_node("reason", self._reason_node)
        graph.add_node("garuda", self._garuda_node)
        graph.add_node("persist", self._persist_node)
        graph.add_node("act", self._act_node)
        graph.add_node("finalize", self._finalize_node)

        graph.set_entry_point("score")
        graph.add_edge("score", "correlate")
        graph.add_edge("correlate", "decide")
        graph.add_edge("decide", "reason")
        graph.add_conditional_edges(
            "reason",
            self._needs_garuda,
            {
                "garuda": "garuda",
                "persist": "persist",
            },
        )
        graph.add_edge("garuda", "persist")
        graph.add_edge("persist", "act")
        graph.add_edge("act", "finalize")
        graph.add_edge("finalize", END)

        return graph.compile()

    def run(self, initial_state: OrchestratorState) -> OrchestratorState:
        return self._graph.invoke(initial_state)

    def _score_node(self, state: OrchestratorState) -> OrchestratorState:
        results = state.get("agent_results", [])
        score_data = calculate_threat_score(results)

        # Organizational risk context: raise the score when a high-value recipient
        # (finance/executive/etc.) was targeted. Gated by settings; no-op by default.
        try:
            from soc_platform.domains.phishing.engine.configs.settings import settings as _settings
            if getattr(_settings, "org_context_enabled", False):
                from soc_platform.domains.phishing.engine.services.org_context import apply_org_context, load_roles_config
                recipients = state.get("recipients") or ((state.get("headers") or {}).get("to") or [])
                org = apply_org_context(score_data.get("overall_score", 0.0), recipients, load_roles_config())
                if org.get("applied"):
                    score_data["overall_score"] = org["adjusted_score"]
                    score_data["org_context"] = org
        except Exception as exc:
            logger.debug("Org context scoring skipped", error=str(exc))

        logger.info("LangGraph node complete", node="score", analysis_id=state.get("analysis_id"))
        return {"score_data": score_data}

    def _correlate_node(self, state: OrchestratorState) -> OrchestratorState:
        results = state.get("agent_results", [])
        correlation = correlate_threats(results)
        logger.info("LangGraph node complete", node="correlate", analysis_id=state.get("analysis_id"))
        return {"correlation": correlation}

    def _decide_node(self, state: OrchestratorState) -> OrchestratorState:
        score_data = state.get("score_data", {})
        correlation = state.get("correlation", {})
        agent_results = state.get("agent_results", [])

        overall = float(score_data.get("overall_score", 0.0))
        corr_score = float(correlation.get("correlation_score", 0.0))
        normalized_score = min(1.0, overall + (0.2 * corr_score))

        if normalized_score >= 0.75:
            verdict = "malicious"
            actions = ["delete", "soc_alert"]
        elif normalized_score >= 0.55:
            verdict = "high_risk"
            actions = ["quarantine", "soc_alert", "trigger_garuda"]
        elif normalized_score >= 0.42:  # LOWERED from 0.4 - include BEC patterns at compound warning threshold
            verdict = "suspicious"
            actions = ["quarantine", "soc_alert", "trigger_garuda"]
        elif normalized_score >= 0.1:
            verdict = "likely_safe"
            actions = ["deliver_with_banner"]
        else:
            verdict = "safe"
            actions = ["deliver"]
        verdict, actions, normalized_score, override_notes = _apply_transactional_legitimacy_override(
            verdict,
            actions,
            normalized_score,
            agent_results,
        )
        decision_notes: list[str] = list(override_notes)

        if (
            verdict in ("likely_safe", "safe")
            and _has_spam_campaign_pattern(agent_results)
            and not _has_strong_transactional_legitimacy(agent_results)
        ):
            verdict = "suspicious"
            actions = ["quarantine", "soc_alert", "trigger_garuda"]
            normalized_score = max(normalized_score, 0.42)
            decision_notes.append("escalated_by_spam_campaign_pattern")

        if (
            verdict in ("safe", "likely_safe")
            and _has_weak_malicious_compound_warning(agent_results)
            and not _has_hard_malicious_signal(agent_results)
            and not _has_strong_transactional_legitimacy(agent_results)
        ):
            verdict = "suspicious"
            actions = ["quarantine", "soc_alert", "trigger_garuda"]
            normalized_score = max(normalized_score, 0.42)
            decision_notes.append("escalated_by_weak_malicious_compound_warning")

        # CRITICAL: Escalate obvious BEC/wire fraud patterns to high_risk or malicious
        # BEC emails are objective threats and should NOT stay as "suspicious"
        # Use BOTH the complex pattern detection AND simple keyword matching
        if verdict in ("suspicious",) and (_has_obvious_bec_or_fraud_pattern(agent_results) or _contains_bec_keywords(agent_results)):
            verdict = "high_risk"
            actions = ["quarantine", "soc_alert", "trigger_garuda"]
            normalized_score = max(normalized_score, 0.70)  # Force to ensure high_risk verdict (>=0.55)
            decision_notes.append("force_escalated_bec_fraud_pattern")

        if verdict in ("likely_safe", "safe") and _has_uncertain_conflict_pattern(agent_results, normalized_score):
            verdict = "suspicious"
            actions = ["quarantine", "soc_alert", "trigger_garuda"]
            normalized_score = max(normalized_score, 0.4)
            decision_notes.append("escalated_by_uncertain_conflict_guardrail")

        logger.info("LangGraph node complete", node="decide", analysis_id=state.get("analysis_id"))
        return {
            "normalized_score": round(normalized_score, 4),
            "overall_risk_score": round(normalized_score, 4),
            "verdict": verdict,
            "recommended_actions": actions,
            "threat_level": score_data.get("threat_level", "unknown"),
            "decision_notes": decision_notes,
        }

    def _reason_node(self, state: OrchestratorState) -> OrchestratorState:
        agent_results = state.get("agent_results", [])
        overall_score = float(state.get("normalized_score", 0.0))
        correlation = state.get("correlation", {})
        verdict = state.get("verdict", "unknown")
        actions = state.get("recommended_actions", [])
        decision_notes = state.get("decision_notes", [])

        threshold = threshold_for_verdict(verdict)
        if threshold is not None and agent_results:
            counterfactual = calculate_counterfactual(
                agent_results=agent_results,
                correlation=correlation,
                current_normalized_score=overall_score,
                threshold=threshold,
            )
        else:
            counterfactual = {"is_counterfactual": False, "reason": "no_blocking_boundary"}

        storyline = generate_storyline(agent_results, verdict, actions) if agent_results else []

        # --- Enhanced: MITRE ATT&CK deep mapping ---
        attack_assessment = {}
        threat_attribution = {}
        try:
            from soc_platform.domains.phishing.engine.orchestrator.mitre_attack_engine import map_agent_results_to_attack
            attack_assessment = map_agent_results_to_attack(agent_results)
        except Exception as exc:
            logger.debug("ATT&CK mapping skipped", error=str(exc))

        # --- Enhanced: Threat group attribution ---
        try:
            from soc_platform.domains.phishing.engine.orchestrator.threat_group_attribution import generate_attribution_summary
            threat_attribution = generate_attribution_summary(agent_results, attack_data=attack_assessment or None)
        except Exception as exc:
            logger.debug("Threat group attribution skipped", error=str(exc))

        # --- Enhanced: Compliance mapping ---
        compliance_mapping = {}
        try:
            from soc_platform.domains.phishing.engine.orchestrator.compliance_mapper import map_to_compliance
            compliance_mapping = map_to_compliance(verdict, actions)
        except Exception as exc:
            logger.debug("Compliance mapping skipped", error=str(exc))

        # --- Enhanced: Playbook selection ---
        playbook_result = None
        try:
            from soc_platform.domains.phishing.engine.action_layer.playbook_engine import select_playbook, execute_playbook
            all_indicators = []
            for r in agent_results:
                all_indicators.extend(r.get("indicators", []) or [])
            pb = select_playbook(verdict, overall_score, all_indicators, decision_notes)
            if pb:
                playbook_result = execute_playbook(pb, state.get("analysis_id", ""), {})
        except Exception as exc:
            logger.debug("Playbook selection skipped", error=str(exc))

        # --- Enhanced: Counterfactual narrative ---
        counterfactual_narrative = ""
        if counterfactual.get("is_counterfactual") and counterfactual.get("agents_altered"):
            try:
                from soc_platform.domains.phishing.engine.orchestrator.llm_reasoner import explain_counterfactual
                parts = []
                for agent_delta in counterfactual.get("agents_altered", []):
                    # agents_altered is a list of {agent_name, original_risk, attenuated_risk} dicts.
                    if not isinstance(agent_delta, dict):
                        parts.append(str(agent_delta))
                        continue
                    name = agent_delta.get("agent_name", "unknown")
                    orig = float(agent_delta.get("original_risk", 0) or 0)
                    new = float(agent_delta.get("attenuated_risk", 0) or 0)
                    parts.append(f"{name} (risk {orig:.2f} → {new:.2f})")
                new_score = float(counterfactual.get("new_normalized_score", 0) or 0)
                fallback_narrative = (
                    f"If the following agents had not flagged this email — {', '.join(parts)} — "
                    f"the overall risk score would drop to {new_score:.2f}, "
                    f"which falls below the '{verdict}' threshold. "
                    f"This means these {len(parts)} agent(s) were the critical factors "
                    f"in the '{verdict}' classification."
                )
                # Attempt to get LLM reasoning
                llm_narrative = explain_counterfactual(counterfactual)
                if llm_narrative and "Raw Counterfactual:" not in llm_narrative:
                    counterfactual_narrative = llm_narrative
                else:
                    counterfactual_narrative = fallback_narrative

                counterfactual["narrative"] = counterfactual_narrative
            except Exception as exc:
                logger.warning("Counterfactual narrative generation failed", error=str(exc))
                # Best-effort fallback so the analyst still sees something grounded.
                counterfactual["narrative"] = (
                    f"Critical agents {', '.join(_cf_names(counterfactual))} drove the '{verdict}' verdict; "
                    f"neutralizing them would drop the score to {counterfactual.get('new_normalized_score')}."
                )

        # --- Enhanced: Decision audit trail ---
        decision_audit_trail = []
        for note in decision_notes:
            explanation_map = {
                "force_escalated_bec_fraud_pattern": "Escalated from suspicious to high_risk because BEC/wire fraud indicators (financial language + urgency + unfamiliar sender) were detected.",
                "escalated_by_spam_campaign_pattern": "Escalated due to coordinated spam campaign pattern detected across multiple recipients.",
                "escalated_by_weak_malicious_compound_warning": "Escalated because multiple weak malicious signals compounded to warrant investigation.",
                "escalated_by_uncertain_conflict_guardrail": "Escalated because conflicting agent signals created uncertainty requiring analyst review.",
            }
            decision_audit_trail.append({
                "guardrail": note,
                "explanation": explanation_map.get(note, f"Decision guardrail applied: {note}"),
            })

        # Evidence-grounded reasoning: build citable evidence from the agents' real indicators, then
        # produce an explanation where every claim must reference a real evidence id (anti-hallucination).
        grounded_evidence: list[dict[str, Any]] = []
        grounded_claims: list[dict[str, Any]] = []
        try:
            grounded_evidence = collect_evidence(agent_results)
            grounded = generate_grounded_reasoning(
                agent_results,
                overall_score,
                grounded_evidence,
                counterfactual=counterfactual,
            )
            explanation = grounded.get("explanation") or ""
            grounded_claims = grounded.get("claims", [])
        except Exception as exc:
            logger.warning("Grounded reasoning failed; falling back to legacy reasoning", error=str(exc))
            explanation = ""

        # Defensive fallback to the legacy reasoner if grounding produced nothing.
        if not explanation:
            explanation = generate_reasoning(
                agent_results,
                overall_score,
                counterfactual=counterfactual,
            )

        # Structured analyst brief — grounded in the same evidence, deterministic fallback.
        analyst_brief: dict[str, Any] = {}
        try:
            from soc_platform.domains.phishing.engine.orchestrator.llm_reasoner import generate_structured_brief
            analyst_brief = generate_structured_brief(
                agent_results, overall_score, grounded_evidence, verdict, counterfactual=counterfactual
            )
        except Exception as exc:
            logger.debug("Analyst brief generation skipped", error=str(exc))

        # Provenance chain — ordered, auditable record of how the verdict was reached.
        provenance: list[dict[str, Any]] = []
        try:
            from soc_platform.domains.phishing.engine.orchestrator.provenance_chain import build_provenance_chain
            provenance = build_provenance_chain(
                agent_results=agent_results,
                score_data=state.get("score_data", {}),
                correlation=correlation,
                decision_audit_trail=decision_audit_trail,
                counterfactual=counterfactual,
                verdict=verdict,
                overall_score=overall_score,
            )
        except Exception as exc:
            logger.debug("Provenance chain build skipped", error=str(exc))

        logger.info("LangGraph node complete", node="reason", analysis_id=state.get("analysis_id"))
        return {
            "llm_explanation": explanation,
            "grounded_evidence": grounded_evidence,
            "grounded_claims": grounded_claims,
            "analyst_brief": analyst_brief,
            "provenance_chain": provenance,
            "counterfactual_result": counterfactual,
            "threat_storyline": storyline,
            "attack_assessment": attack_assessment,
            "threat_attribution": threat_attribution,
            "compliance_mapping": compliance_mapping,
            "playbook_result": playbook_result,
            "decision_audit_trail": decision_audit_trail,
        }

    def _needs_garuda(self, state: OrchestratorState) -> str:
        return "garuda" if float(state.get("overall_risk_score", 0.0)) > 0.7 else "persist"

    def _garuda_node(self, state: OrchestratorState) -> OrchestratorState:
        decision = self._assemble_decision(state)
        feedback = trigger_garuda_investigation(decision)
        logger.info("LangGraph node complete", node="garuda", analysis_id=state.get("analysis_id"))
        return {"garuda_feedback": feedback}

    def _persist_node(self, state: OrchestratorState) -> OrchestratorState:
        analysis_id = str(state.get("analysis_id", ""))
        decision = self._assemble_decision(state)
        self._save_report(analysis_id, decision)
        logger.info("LangGraph node complete", node="persist", analysis_id=analysis_id)
        return {
            "decision": decision,
            "persistence_status": "saved",
        }

    def _act_node(self, state: OrchestratorState) -> OrchestratorState:
        decision = state.get("decision") or self._assemble_decision(state)
        self._execute_actions(decision)
        logger.info("LangGraph node complete", node="act", analysis_id=state.get("analysis_id"))
        return {"action_status": "dispatched"}

    def _finalize_node(self, state: OrchestratorState) -> OrchestratorState:
        decision = state.get("decision") or self._assemble_decision(state)
        logger.info("LangGraph node complete", node="finalize", analysis_id=state.get("analysis_id"))
        return {"decision": decision}

    def _assemble_decision(self, state: OrchestratorState) -> dict[str, Any]:
        decision = {
            "analysis_id": state.get("analysis_id"),
            "overall_risk_score": float(state.get("overall_risk_score", 0.0)),
            "verdict": state.get("verdict", "unknown"),
            "recommended_actions": state.get("recommended_actions", []),
            "threat_level": state.get("threat_level", "unknown"),
            "llm_explanation": state.get("llm_explanation", ""),
            "agent_results": state.get("agent_results", []),
            "correlation": state.get("correlation", {}),
            "score_data": state.get("score_data", {}),
            "finalization_reason": state.get("finalization_reason", "complete"),
            "received_agents": state.get("received_agents", []),
            "missing_agents": state.get("missing_agents", []),
            "is_partial": bool(state.get("is_partial", False)),
            "threat_storyline": state.get("threat_storyline", []),
            "counterfactual_result": state.get("counterfactual_result", None),
            "grounded_evidence": state.get("grounded_evidence", []),
            "grounded_claims": state.get("grounded_claims", []),
            "analyst_brief": state.get("analyst_brief", {}),
            "provenance_chain": state.get("provenance_chain", []),
            "decision_notes": state.get("decision_notes", []),
            # Email identity for Graph action layer
            "user_principal_name": state.get("user_principal_name", ""),
            "internet_message_id": state.get("internet_message_id", ""),
            "sender": state.get("sender", ""),
            "subject": state.get("subject", ""),
            # Enhanced features
            "attack_assessment": state.get("attack_assessment", {}),
            "threat_attribution": state.get("threat_attribution", {}),
            "compliance_mapping": state.get("compliance_mapping", {}),
            "playbook_result": state.get("playbook_result"),
            "decision_audit_trail": state.get("decision_audit_trail", []),
        }
        if state.get("garuda_feedback"):
            decision["garuda_feedback"] = state.get("garuda_feedback")
        return decision
