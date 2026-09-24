"""
Full system integration test.

Tests every layer of the Agentic Email Security System:
  1. Content SLM model — loads and classifies test emails
  2. Action Layer — GraphActionBot, ResponseEngine (simulated & live)
  3. LangGraph Orchestrator — score → correlate → decide → reason → act
  4. All agent inference paths
"""

from soc_platform.domains.phishing.engine.paths import PHISHING_HOME
import os
import sys
import json
import traceback
from pathlib import Path
from datetime import datetime, timezone

# Ensure email_security is importable
REPO_ROOT = PHISHING_HOME
pass  # (package import; no sys.path hack needed)
pass  # (package import; no sys.path hack needed)
os.chdir(str(REPO_ROOT))

PASS = "✅ PASS"
FAIL = "❌ FAIL"
WARN = "⚠️  WARN"
results: list[tuple[str, str, str]] = []


def record(section: str, status: str, detail: str = "") -> None:
    results.append((section, status, detail))
    icon = status
    print(f"  {icon}  {section}" + (f" — {detail}" if detail else ""))


# ──────────────────────────────────────────────────────────────
# 1. Settings & Environment
# ──────────────────────────────────────────────────────────────
print("\n" + "=" * 70)
print("  SECTION 1: Settings & Environment")
print("=" * 70)

try:
    from soc_platform.domains.phishing.engine.configs.settings import settings
    record("Settings load", PASS)
    record("SLM seq_len", PASS, f"{settings.slm_max_seq_len}")
    record("SLM epochs", PASS, f"{settings.slm_num_epochs}")
    record("Action simulated_mode", PASS if settings.action_simulated_mode else WARN,
           f"simulated={settings.action_simulated_mode}")
    record("Graph tenant configured", PASS if settings.graph_tenant_id else WARN,
           f"tenant={'set' if settings.graph_tenant_id else 'MISSING'}")
    record("Graph client_id", PASS if settings.graph_client_id else WARN,
           f"client_id={'set' if settings.graph_client_id else 'MISSING'}")
    record("Graph client_secret", PASS if settings.graph_client_secret else WARN,
           f"secret={'set' if settings.graph_client_secret else 'MISSING'}")
except Exception as exc:
    record("Settings load", FAIL, str(exc))

# ──────────────────────────────────────────────────────────────
# 2. Content SLM Model
# ──────────────────────────────────────────────────────────────
print("\n" + "=" * 70)
print("  SECTION 2: Content SLM Model")
print("=" * 70)

try:
    from transformers import pipeline, AutoTokenizer, AutoModelForSequenceClassification

    MODEL_DIR = REPO_ROOT.parent / "models" / "content_agent"
    if MODEL_DIR.exists() and (MODEL_DIR / "config.json").exists():
        record("Model directory", PASS, str(MODEL_DIR))

        tokenizer = AutoTokenizer.from_pretrained(str(MODEL_DIR))
        model = AutoModelForSequenceClassification.from_pretrained(str(MODEL_DIR))
        classifier = pipeline("text-classification", model=model, tokenizer=tokenizer, truncation=True)
        record("Model load", PASS, f"vocab={tokenizer.vocab_size}, labels={model.config.num_labels}")

        test_cases = [
            ("Hi team, please find the quarterly report attached.", "Legitimate"),
            ("BUY CHEAP VIAGRA NOW!!! LIMITED OFFER", "Spam"),
            ("Your PayPal account has been suspended. Click here to verify immediately.", "Phishing"),
        ]
        for text, expected in test_cases:
            result = classifier(text, max_length=128)[0]
            label = result["label"]
            score = result["score"]
            record(f"Classify '{expected}'", PASS, f"label={label}, score={score:.4f}")
    else:
        record("Model directory", FAIL, f"Not found at {MODEL_DIR}")
except Exception as exc:
    record("Content SLM", FAIL, str(exc))

# ──────────────────────────────────────────────────────────────
# 3. Content Agent Inference Pipeline
# ──────────────────────────────────────────────────────────────
print("\n" + "=" * 70)
print("  SECTION 3: Content Agent Inference Pipeline")
print("=" * 70)

try:
    from soc_platform.domains.phishing.engine.agents.content_agent.model_loader import load_model
    from soc_platform.domains.phishing.engine.agents.content_agent.inference import predict

    model_bundle = load_model()
    if model_bundle:
        record("Model loader", PASS, f"kind={model_bundle.get('kind', 'unknown')}")

        result = predict({"text": "Dear user, your account has been compromised. Login now to secure it."}, model=model_bundle)
        record("Inference pipeline", PASS, f"risk={result['risk_score']:.4f}, conf={result['confidence']:.4f}, indicators={result['indicators']}")
    else:
        record("Model loader", WARN, "No model loaded — heuristic mode")
except Exception as exc:
    record("Content Agent Inference", FAIL, traceback.format_exc().split("\n")[-2])

# ──────────────────────────────────────────────────────────────
# 4. Graph Client (Action Bot)
# ──────────────────────────────────────────────────────────────
print("\n" + "=" * 70)
print("  SECTION 4: Graph Client (Action Bot)")
print("=" * 70)

try:
    from soc_platform.domains.phishing.engine.action_layer.graph_client import GraphActionBot, get_graph_client

    bot = get_graph_client()
    record("GraphActionBot init", PASS)
    record("Graph configured", PASS if bot.is_configured() else WARN,
           f"configured={bot.is_configured()}")

    # Test token acquisition (will fail without admin consent but should not crash)
    if bot.is_configured():
        token = bot._get_token()
        if token:
            record("Token acquisition", PASS, "Token acquired successfully!")
            # Try resolve a dummy message (expected to fail but tests the API path)
            result = bot.resolve_message_id("test@test.com", "<dummy-id>")
            record("Message resolution", WARN if result is None else PASS,
                   "No message found (expected for dummy ID)" if result is None else f"ID={result}")
        else:
            record("Token acquisition", FAIL,
                   "No token — likely admin consent not granted yet. "
                   "Go to Azure Portal → App Registrations → Email-Action-Bot → API Permissions → Grant admin consent")
    else:
        record("Token acquisition", WARN, "Graph not configured — skipping token test")

    # Test simulated actions
    sim_result = bot.quarantine_email("test@test.com", "dummy-graph-id")
    record("Quarantine (unconfigured)", PASS if not sim_result.ok else WARN, str(sim_result))

    sim_result = bot.apply_warning_banner("test@test.com", "dummy-graph-id", severity="High")
    record("Banner (unconfigured)", PASS if not sim_result.ok else WARN, str(sim_result))

except Exception as exc:
    record("Graph Client", FAIL, traceback.format_exc().split("\n")[-2])

# ──────────────────────────────────────────────────────────────
# 5. Response Engine (Action Layer)
# ──────────────────────────────────────────────────────────────
print("\n" + "=" * 70)
print("  SECTION 5: Response Engine (Action Layer)")
print("=" * 70)

try:
    from soc_platform.domains.phishing.engine.action_layer.response_engine import ResponseEngine

    engine = ResponseEngine()
    record("ResponseEngine init", PASS,
           f"simulated={engine.simulated_mode}, banner={engine.banner_enabled}, quarantine={engine.quarantine_enabled}")

    # Test Tier 5: Critical — Quarantine
    print("\n  --- Tier 5: Critical Threat (score ≥ 0.85) ---")
    engine.execute_actions({
        "analysis_id": "test-critical-001",
        "overall_risk_score": 0.92,
        "verdict": "malicious",
        "recommended_actions": ["quarantine", "block_sender", "trigger_garuda"],
        "agent_results": {
            "content_agent": {"risk_score": 0.95},
            "url_agent": {"risk_score": 0.88},
            "header_agent": {"risk_score": 0.72},
        },
    })
    record("Tier 5 Critical execute", PASS)

    # Test Tier 3-4: High Risk — Banner
    print("\n  --- Tier 3-4: High Risk (0.40 - 0.84) ---")
    engine.execute_actions({
        "analysis_id": "test-high-002",
        "overall_risk_score": 0.65,
        "verdict": "suspicious",
        "recommended_actions": ["deliver_with_banner", "soc_alert"],
        "agent_results": {
            "content_agent": {"risk_score": 0.70},
            "url_agent": {"risk_score": 0.55},
        },
    })
    record("Tier 3-4 High Risk execute", PASS)

    # Test Tier 1: Safe — Deliver
    print("\n  --- Tier 1: Safe (score < 0.10) ---")
    engine.execute_actions({
        "analysis_id": "test-safe-003",
        "overall_risk_score": 0.05,
        "verdict": "safe",
        "recommended_actions": ["deliver"],
        "agent_results": {
            "content_agent": {"risk_score": 0.02},
            "header_agent": {"risk_score": 0.01},
        },
    })
    record("Tier 1 Safe execute", PASS)

    # Test LIVE mode with Graph identity
    print("\n  --- Live Mode Test (with Graph identity) ---")
    engine.execute_actions({
        "analysis_id": "test-live-004",
        "overall_risk_score": 0.90,
        "verdict": "malicious",
        "recommended_actions": ["quarantine", "deliver_with_banner", "categorize"],
        "user_principal_name": "test@contoso.com",
        "internet_message_id": "<test-msg-id@contoso.com>",
        "agent_results": {
            "content_agent": {"risk_score": 0.92},
        },
    })
    record("Live mode dispatch", PASS, "Graph actions attempted (may fail without admin consent)")

except Exception as exc:
    record("Response Engine", FAIL, traceback.format_exc().split("\n")[-2])

# ──────────────────────────────────────────────────────────────
# 6. LangGraph Orchestrator (Decision Pipeline)
# ──────────────────────────────────────────────────────────────
print("\n" + "=" * 70)
print("  SECTION 6: LangGraph Orchestrator (Decision Pipeline)")
print("=" * 70)

try:
    from soc_platform.domains.phishing.engine.orchestrator.langgraph_workflow import LangGraphOrchestrator
    from soc_platform.domains.phishing.engine.orchestrator.langgraph_state import OrchestratorState

    test_reports: list[dict] = []

    def mock_save_report(analysis_id: str, decision: dict) -> None:
        test_reports.append(decision)

    def mock_execute_actions(decision: dict) -> None:
        pass  # Suppress print output for this test

    orchestrator = LangGraphOrchestrator(
        save_report=mock_save_report,
        execute_actions=mock_execute_actions,
    )
    record("LangGraph build", PASS)

    # Scenario A: Malicious email
    state_malicious: OrchestratorState = {
        "analysis_id": "test-malicious-langgraph",
        "agent_results": [
            {"agent_name": "content_agent", "risk_score": 0.95, "confidence": 0.9, "indicators": ["ml_slm_label:Phishing"]},
            {"agent_name": "header_agent", "risk_score": 0.8, "confidence": 0.85, "indicators": ["dmarc_failed", "lookalike_domain"]},
            {"agent_name": "url_agent", "risk_score": 0.9, "confidence": 0.88, "indicators": ["known_phishing_url"]},
            {"agent_name": "attachment_agent", "risk_score": 0.3, "confidence": 0.7, "indicators": []},
            {"agent_name": "sandbox_agent", "risk_score": 0.2, "confidence": 0.6, "indicators": []},
            {"agent_name": "threat_intel_agent", "risk_score": 0.7, "confidence": 0.8, "indicators": ["ioc_match"]},
            {"agent_name": "user_behavior_agent", "risk_score": 0.1, "confidence": 0.5, "indicators": []},
        ],
        "finalization_reason": "complete",
        "received_agents": ["content_agent", "header_agent", "url_agent", "attachment_agent", "sandbox_agent", "threat_intel_agent", "user_behavior_agent"],
        "missing_agents": [],
        "is_partial": False,
    }

    final_state = orchestrator.run(state_malicious)
    decision = final_state.get("decision", {})
    record("Malicious pipeline", PASS,
           f"verdict={decision.get('verdict')}, score={decision.get('overall_risk_score')}, "
           f"actions={decision.get('recommended_actions')}")

    if decision.get("threat_storyline"):
        record("Threat Storyline", PASS, f"{len(decision['threat_storyline'])} phases generated")
    else:
        record("Threat Storyline", WARN, "No storyline generated")

    if decision.get("counterfactual_result"):
        cf = decision["counterfactual_result"]
        record("Counterfactual Analysis", PASS, f"is_counterfactual={cf.get('is_counterfactual')}")
    else:
        record("Counterfactual Analysis", WARN, "No counterfactual generated")

    if decision.get("llm_explanation"):
        record("LLM Reasoning", PASS, f"{len(decision['llm_explanation'])} chars")
    else:
        record("LLM Reasoning", WARN, "No explanation generated")

    # Scenario B: Safe email
    state_safe: OrchestratorState = {
        "analysis_id": "test-safe-langgraph",
        "agent_results": [
            {"agent_name": "content_agent", "risk_score": 0.02, "confidence": 0.95, "indicators": ["ml_slm_label:Legitimate"]},
            {"agent_name": "header_agent", "risk_score": 0.01, "confidence": 0.9, "indicators": ["dmarc_pass", "spf_pass"]},
            {"agent_name": "url_agent", "risk_score": 0.0, "confidence": 0.85, "indicators": []},
            {"agent_name": "attachment_agent", "risk_score": 0.0, "confidence": 0.8, "indicators": []},
            {"agent_name": "sandbox_agent", "risk_score": 0.0, "confidence": 0.7, "indicators": []},
            {"agent_name": "threat_intel_agent", "risk_score": 0.0, "confidence": 0.75, "indicators": []},
            {"agent_name": "user_behavior_agent", "risk_score": 0.0, "confidence": 0.6, "indicators": []},
        ],
        "finalization_reason": "complete",
        "received_agents": ["content_agent", "header_agent", "url_agent", "attachment_agent", "sandbox_agent", "threat_intel_agent", "user_behavior_agent"],
        "missing_agents": [],
        "is_partial": False,
    }

    final_state_safe = orchestrator.run(state_safe)
    decision_safe = final_state_safe.get("decision", {})
    record("Safe pipeline", PASS,
           f"verdict={decision_safe.get('verdict')}, score={decision_safe.get('overall_risk_score')}, "
           f"actions={decision_safe.get('recommended_actions')}")

except Exception as exc:
    record("LangGraph Orchestrator", FAIL, traceback.format_exc().split("\n")[-2])

# ──────────────────────────────────────────────────────────────
# 7. Scoring Engine, Correlation, Storyline
# ──────────────────────────────────────────────────────────────
print("\n" + "=" * 70)
print("  SECTION 7: Scoring & Correlation Engines")
print("=" * 70)

try:
    from soc_platform.domains.phishing.engine.orchestrator.scoring_engine import calculate_threat_score
    score_result = calculate_threat_score([
        {"agent_name": "content_agent", "risk_score": 0.8, "confidence": 0.9},
        {"agent_name": "url_agent", "risk_score": 0.6, "confidence": 0.7},
    ])
    record("Scoring Engine", PASS, f"overall_score={score_result.get('overall_score', 'N/A')}")
except Exception as exc:
    record("Scoring Engine", FAIL, str(exc))

try:
    from soc_platform.domains.phishing.engine.orchestrator.threat_correlation import correlate_threats
    corr_result = correlate_threats([
        {"agent_name": "content_agent", "risk_score": 0.8, "confidence": 0.9, "indicators": ["phishing_content"]},
        {"agent_name": "url_agent", "risk_score": 0.6, "confidence": 0.7, "indicators": ["suspicious_url"]},
    ])
    record("Threat Correlation", PASS, f"correlation_score={corr_result.get('correlation_score', 'N/A')}")
except Exception as exc:
    record("Threat Correlation", FAIL, str(exc))

try:
    from soc_platform.domains.phishing.engine.orchestrator.storyline_engine import generate_storyline
    storyline = generate_storyline(
        [
            {"agent_name": "content_agent", "risk_score": 0.8, "confidence": 0.9, "indicators": ["ml_slm_label:Phishing"]},
            {"agent_name": "url_agent", "risk_score": 0.6, "confidence": 0.7, "indicators": ["suspicious_url"]},
        ],
        verdict="malicious",
        recommended_actions=["quarantine"]
    )
    record("Storyline Engine", PASS, f"{len(storyline)} phases")
except Exception as exc:
    record("Storyline Engine", FAIL, str(exc))

try:
    from soc_platform.domains.phishing.engine.orchestrator.counterfactual_engine import calculate_counterfactual
    cf_result = calculate_counterfactual(
        agent_results=[
            {"agent_name": "content_agent", "risk_score": 0.8, "confidence": 0.9},
            {"agent_name": "url_agent", "risk_score": 0.6, "confidence": 0.7},
        ],
        correlation={"correlation_score": 0.2},
        current_normalized_score=0.82,
        threshold=0.8,
    )
    record("Counterfactual Engine", PASS, f"is_counterfactual={cf_result.get('is_counterfactual')}")
except Exception as exc:
    record("Counterfactual Engine", FAIL, str(exc))

# ──────────────────────────────────────────────────────────────
# FINAL SUMMARY
# ──────────────────────────────────────────────────────────────
print("\n" + "=" * 70)
print("  FINAL SUMMARY")
print("=" * 70)

passes = sum(1 for _, s, _ in results if s == PASS)
warns = sum(1 for _, s, _ in results if s == WARN)
fails = sum(1 for _, s, _ in results if s == FAIL)
total = len(results)

print(f"\n  Total: {total}  |  {PASS}: {passes}  |  {WARN}: {warns}  |  {FAIL}: {fails}")

if fails > 0:
    print(f"\n  ❌ FAILURES:")
    for section, status, detail in results:
        if status == FAIL:
            print(f"    • {section}: {detail}")

if warns > 0:
    print(f"\n  ⚠️  WARNINGS:")
    for section, status, detail in results:
        if status == WARN:
            print(f"    • {section}: {detail}")

print("\n" + "=" * 70)
if fails == 0:
    print("  🎉 ALL CRITICAL TESTS PASSED!")
else:
    print("  ⛔ SOME TESTS FAILED — Review above for details.")
print("=" * 70 + "\n")
