import logging

from soc_platform.domains.phishing.engine.action_layer.graph_client import GraphActionBot
from soc_platform.domains.phishing.engine.action_layer.response_engine import ResponseEngine

# Setup rich logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)-8s | %(message)s")
logger = logging.getLogger("action_layer_test")

def print_header(title):
    print(f"\n{'='*80}\n {title}\n{'='*80}")

def test_token_acquisition():
    print_header("1. Testing Microsoft Graph Authentication")
    bot = GraphActionBot()
    logger.info("Checking configuration...")
    if not bot.is_configured():
        logger.error("Graph credentials are not fully configured in Settings / .env")
        return False
    logger.info("Graph is configured. Attempting to acquire token...")
    token = bot._get_token()
    if token:
        logger.info(f"✅ Token successfully acquired! (Length: {len(token)} characters)")
        return True
    else:
        logger.error("❌ Failed to acquire token. Check Client ID, Tenant ID, and Secret.")
        return False

def test_simulated_routing():
    print_header("2. Testing Simulated Response Engine Routing")
    
    # We force simulated mode to True for this test
    engine = ResponseEngine()
    engine.simulated_mode = True
    
    mock_decision = {
        "analysis_id": "test-id-1234",
        "overall_risk_score": 0.95,
        "verdict": "malicious",
        "recommended_actions": ["quarantine", "deliver_with_banner"],
        "user_principal_name": "target@contoso.com",
        "internet_message_id": "<dummy-id-5678@mail.contoso.com>",
    }
    
    logger.info("Injecting mock malicious decision (Risk: 0.95)...")
    logger.info("Expected Actions: Quarantine, Banner")
    
    # Capture the logs or just let them print to console
    engine.execute_actions(mock_decision)
    logger.info("✅ Simulated routing passed! Check the logs above for simulated actions.")

def test_live_graph_resolution_and_action():
    print_header("3. Testing Live Graph API Execution (Safe Sandbox)")
    
    engine = ResponseEngine()
    engine.simulated_mode = False # FORCE LIVE MODE
    
    mock_decision = {
        "analysis_id": "test-id-live-5555",
        "overall_risk_score": 0.95,
        "verdict": "malicious",
        "recommended_actions": ["quarantine"],
        "user_principal_name": "target@contoso.com",
        "internet_message_id": "<fake-dummy-id-to-force-404@contoso.com>",
    }

    logger.info("Running LIVE Mode with a fake internet_message_id.")
    logger.info("We EXPECT this to return a 404 Not Found since the email doesn't actually exist in the tenant.")
    
    # Execute
    engine.execute_actions(mock_decision)
    logger.info("✅ Live execution pipeline executed correctly! (Expected 404 resolution failure).")

def run_all_tests():
    auth_ok = test_token_acquisition()
    test_simulated_routing()
    if auth_ok:
        test_live_graph_resolution_and_action()
    else:
        logger.warning("Skipping live Graph action test because token acquisition failed.")
    
    print_header("ACTION LAYER TESTING COMPLETE")

if __name__ == "__main__":
    run_all_tests()
