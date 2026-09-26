"""
Threat Storyline Engine for translating disconnected agent indicators into
a chronological narrative (Delivery -> Lure -> Weaponization -> Result).
"""

import json
from typing import Any

from openai import AzureOpenAI

from soc_platform.domains.phishing.engine.configs.settings import settings
from soc_platform.domains.phishing.engine.services.logging_service import get_service_logger

logger = get_service_logger("storyline_engine")


def _severity_from_risk(risk_score: float) -> str:
    value = float(risk_score or 0.0)
    if value >= 0.8:
        return "high"
    if value >= 0.5:
        return "medium"
    return "low"


def _aggregate_event_stats(items: list[dict[str, Any]]) -> tuple[str, float]:
    if not items:
        return "low", 0.0
    max_risk = max(float(item.get("risk_score", 0.0) or 0.0) for item in items)
    avg_conf = sum(float(item.get("confidence", 0.0) or 0.0) for item in items) / len(items)
    return _severity_from_risk(max_risk), round(max(0.0, min(1.0, avg_conf)), 4)


def _mitre_mapping_for_indicator(agent_name: str, indicator: str, phase: str) -> str:
    """
    ATT&CK mapping using the comprehensive MITRE ATT&CK mapping engine.

    Delegates to mitre_attack_engine.map_indicator_to_techniques() for
    granular technique resolution, falling back to phase-based defaults.
    """
    try:
        from soc_platform.domains.phishing.engine.orchestrator.mitre_attack_engine import (
            format_attack_label,
            map_indicator_to_techniques,
        )
        matches = map_indicator_to_techniques(
            agent_name=agent_name,
            indicator=indicator,
            agent_risk_score=0.7,  # Default weight for storyline context
            agent_confidence=0.7,
        )
        if matches:
            # Return the highest-confidence technique label
            best = max(matches, key=lambda m: m.confidence)
            return format_attack_label(best.technique.technique_id)
    except Exception:
        logger.opt(exception=True).debug("ATT&CK technique lookup failed for a storyline step")

    # Fallback: basic phase-based defaults
    text = indicator.lower()
    agent = agent_name.lower()

    if phase == "Delivery":
        if any(token in text for token in ["dmarc", "dkim", "spf", "spoof", "lookalike", "typosquat", "domain"]):
            return "TA0001: Initial Access | T1566: Phishing"
        return "TA0001: Initial Access | T1566: Phishing"

    if phase == "Lure":
        if any(token in text for token in ["urgent", "invoice", "payment", "verify", "password", "account", "credential"]):
            return "TA0001: Initial Access | T1566: Phishing | T1204: User Execution"
        return "TA0001: Initial Access | T1566: Phishing"

    if phase == "Weaponization":
        if "url_agent" in agent or any(token in text for token in ["url", "link", "shortener", "redirect"]):
            return "TA0001: Initial Access | T1566.002: Spearphishing Link"
        if "attachment_agent" in agent or any(token in text for token in ["attachment", "macro", "docm", "xlsm", "pdf", "exe", "zip"]):
            return "TA0001: Initial Access | T1566.001: Spearphishing Attachment"
        if "sandbox_agent" in agent or any(token in text for token in ["powershell", "cmd", "script", "execution", "rundll32", "wscript"]):
            return "TA0002: Execution | T1059: Command and Scripting Interpreter"
        return "TA0002: Execution"

    return "ATT&CK Mapping Unavailable"


def _llm_mitre_enrich_indicators(
    phase: str,
    indicators: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Optionally refine per-indicator ATT&CK mappings via Azure OpenAI."""
    if not settings.storyline_enable_llm_mitre_enrichment:
        return indicators

    if not (
        settings.azure_openai_endpoint
        and settings.azure_openai_api_key
        and settings.azure_openai_deployment
    ):
        return indicators

    if not indicators:
        return indicators

    max_items = max(1, int(settings.storyline_llm_max_indicators_per_phase or 8))
    sample = indicators[:max_items]
    payload = [
        {
            "index": idx,
            "value": str(item.get("value", "")),
            "current_tactic": str(item.get("tactic", "")),
        }
        for idx, item in enumerate(sample)
    ]

    prompt = (
        "You are a SOC ATT&CK mapper. Return strict JSON only.\n"
        "Given phase + indicators, refine ATT&CK tactic/technique mappings.\n"
        "Rules:\n"
        "1) Keep mappings concise.\n"
        "2) Prefer known phishing and execution techniques for email attacks when evidence supports it.\n"
        "3) If uncertain, keep current mapping.\n"
        "Output format:\n"
        "{\"mappings\":[{\"index\":0,\"tactic\":\"TA0001: Initial Access | T1566: Phishing\"}]}\n"
        f"Phase: {phase}\n"
        f"Indicators: {payload}"
    )

    try:
        client = AzureOpenAI(
            api_key=settings.azure_openai_api_key,
            azure_endpoint=settings.azure_openai_endpoint,
            api_version=settings.azure_openai_api_version,
        )
        completion = client.chat.completions.create(
            model=settings.azure_openai_deployment,
            messages=[
                {"role": "system", "content": "You map email threat indicators to MITRE ATT&CK for SOC analysts."},
                {"role": "user", "content": prompt},
            ],
            temperature=0.0,
            max_tokens=500,
        )
        content = completion.choices[0].message.content or ""
        parsed = json.loads(content)
        mappings = parsed.get("mappings", []) if isinstance(parsed, dict) else []
        tactic_by_index: dict[int, str] = {}
        for item in mappings:
            if not isinstance(item, dict):
                continue
            idx = item.get("index")
            tactic = str(item.get("tactic", "")).strip()
            if isinstance(idx, int) and tactic:
                tactic_by_index[idx] = tactic

        enriched = indicators[:]
        for idx, original in enumerate(sample):
            tactic = tactic_by_index.get(idx)
            if tactic:
                enriched[idx] = {**original, "tactic": tactic}
        return enriched
    except Exception as exc:
        logger.warning("LLM ATT&CK enrichment skipped", error=str(exc), phase=phase)
        return indicators


def _build_indicator_objects_for_phase(items: list[dict[str, Any]], phase: str, fallback_tactic: str) -> list[dict[str, Any]]:
    mapped: list[dict[str, Any]] = []
    for entry in items:
        agent_name = str(entry.get("agent_name", "unknown_agent"))
        confidence = round(max(0.0, min(1.0, float(entry.get("confidence", 0.0) or 0.0))), 4)
        severity = _severity_from_risk(float(entry.get("risk_score", 0.0) or 0.0))
        for indicator in entry.get("indicators", []) or []:
            mapped.append(
                {
                    "value": f"[{agent_name}] {indicator}",
                    "severity": severity,
                    "confidence": confidence,
                    "tactic": _mitre_mapping_for_indicator(agent_name, str(indicator), phase) or fallback_tactic,
                }
            )
    return _llm_mitre_enrich_indicators(phase, mapped)


def _collect_phase_tactics(indicators: list[dict[str, Any]], fallback: list[str]) -> list[str]:
    seen: list[str] = []
    for indicator in indicators:
        tactic = str(indicator.get("tactic", "")).strip()
        if tactic and tactic not in seen:
            seen.append(tactic)
    return seen or fallback


def _extract_top_signals(items: list[dict[str, Any]], limit: int = 3) -> tuple[list[str], list[str]]:
    """Return top agent names and indicator snippets ranked by risk and confidence."""
    ranked = sorted(
        items,
        key=lambda entry: (
            float(entry.get("risk_score", 0.0) or 0.0),
            float(entry.get("confidence", 0.0) or 0.0),
        ),
        reverse=True,
    )

    agent_names: list[str] = []
    for entry in ranked:
        name = str(entry.get("agent_name", "unknown_agent"))
        if name not in agent_names:
            agent_names.append(name)

    signals: list[str] = []
    for entry in ranked:
        for indicator in entry.get("indicators", []) or []:
            signal = str(indicator).strip()
            if signal and signal not in signals:
                signals.append(signal)
            if len(signals) >= limit:
                break
        if len(signals) >= limit:
            break

    return agent_names[:limit], signals[:limit]


def _phase_description(phase: str, items: list[dict[str, Any]]) -> str:
    agents, signals = _extract_top_signals(items)
    agent_text = ", ".join(agents) if agents else "multiple detectors"
    signal_text = "; ".join(signals) if signals else "no high-confidence signals"

    if phase == "Delivery":
        return f"Delivery anomalies were flagged by {agent_text}: {signal_text}."
    if phase == "Lure":
        return f"Lure characteristics suggest social engineering from {agent_text}: {signal_text}."
    if phase == "Weaponization":
        return f"Weaponization evidence indicates possible payload execution paths via {agent_text}: {signal_text}."
    return f"{phase} evidence from {agent_text}: {signal_text}."


def generate_storyline(
    agent_results: list[dict[str, Any]], verdict: str, recommended_actions: list[str]
) -> list[dict[str, Any]]:
    """
    Given the list of agent evaluations, map them to chronological attack phases.
    """
    logger.info("Generating threat storyline timeline")
    storyline = []

    # Map agent names to logical phases
    delivery_agents = {"header_agent", "threat_intel_agent"}
    lure_agents = {"content_agent", "user_behavior_agent"}
    weapon_agents = {"url_agent", "attachment_agent", "sandbox_agent"}

    delivery_items: list[dict[str, Any]] = []
    lure_items: list[dict[str, Any]] = []
    weapon_items: list[dict[str, Any]] = []

    for result in agent_results:
        agent_name = result.get("agent_name", "")
        # Only extract indicators if the agent flagged some risk or explicitly found things
        indicators = result.get("indicators", [])
        if not indicators:
            continue

        if agent_name in delivery_agents:
            delivery_items.append(result)
        elif agent_name in lure_agents:
            lure_items.append(result)
        elif agent_name in weapon_agents:
            weapon_items.append(result)
        else:
            # Fallback for unknown agents
            weapon_items.append(result)

    # 1. Delivery Phase
    if delivery_items:
        severity, confidence = _aggregate_event_stats(delivery_items)
        delivery_indicators = _build_indicator_objects_for_phase(
            delivery_items,
            "Delivery",
            "TA0001: Initial Access | T1566: Phishing",
        )
        storyline.append({
            "phase": "Delivery",
            "description": _phase_description("Delivery", delivery_items),
            "severity": severity,
            "confidence": confidence,
            "tactics": _collect_phase_tactics(
                delivery_indicators,
                ["TA0001: Initial Access", "T1566: Phishing"],
            ),
            "indicators": delivery_indicators,
        })
    else:
        storyline.append({
            "phase": "Delivery",
            "description": "Standard delivery infrastructure. No obvious addressing anomalies.",
            "severity": "low",
            "confidence": 0.9,
            "tactics": ["TA0001: Initial Access", "T1566: Phishing"],
            "indicators": [
                {
                    "value": "No negative delivery indicators detected.",
                    "severity": "low",
                    "confidence": 0.9,
                    "tactic": "TA0001: Initial Access | T1566: Phishing",
                }
            ],
        })

    # 2. Lure Phase
    if lure_items:
        severity, confidence = _aggregate_event_stats(lure_items)
        lure_indicators = _build_indicator_objects_for_phase(
            lure_items,
            "Lure",
            "TA0001: Initial Access | T1566: Phishing",
        )
        storyline.append({
            "phase": "Lure",
            "description": _phase_description("Lure", lure_items),
            "severity": severity,
            "confidence": confidence,
            "tactics": _collect_phase_tactics(
                lure_indicators,
                ["TA0001: Initial Access", "T1566: Phishing", "T1204: User Execution"],
            ),
            "indicators": lure_indicators,
        })

    # 3. Weaponization Phase
    if weapon_items:
        severity, confidence = _aggregate_event_stats(weapon_items)
        weapon_indicators = _build_indicator_objects_for_phase(
            weapon_items,
            "Weaponization",
            "TA0002: Execution",
        )
        storyline.append({
            "phase": "Weaponization",
            "description": _phase_description("Weaponization", weapon_items),
            "severity": severity,
            "confidence": confidence,
            "tactics": _collect_phase_tactics(
                weapon_indicators,
                ["TA0001: Initial Access", "TA0002: Execution"],
            ),
            "indicators": weapon_indicators,
        })

    # 4. Containment / Action Phase
    containment_severity = "high" if verdict in {"malicious", "high_risk"} else "medium" if verdict == "suspicious" else "low"
    action_text = ", ".join(recommended_actions) if recommended_actions else "monitor"
    storyline.append({
        "phase": "Containment",
        "description": (
            f"System classified this email as '{verdict}' after correlating phase evidence; "
            f"response actions: {action_text}."
        ),
        "severity": containment_severity,
        "confidence": 0.95,
        "tactics": ["Defender Action: Containment"],
        "indicators": [
            {
                "value": f"Recommended platform actions: {action_text}",
                "severity": containment_severity,
                "confidence": 0.95,
                "tactic": "Defender Action: Containment",
            }
        ],
    })

    return storyline
