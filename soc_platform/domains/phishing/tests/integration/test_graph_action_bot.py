"""Tests for the Graph Action Bot."""

from soc_platform.domains.phishing.engine.action_layer.graph_client import GraphActionBot, GraphActionResult

class MockGraphActionBot(GraphActionBot):
    def __init__(self):
        super().__init__()
        self.tenant_id = "mock-tenant"
        self.client_id = "mock-client"
        self.client_secret = "mock-secret"
        
    def _graph_request(self, method, endpoint, json_data=None, params=None):
        if "messages" in endpoint and method == "GET":
            return 200, {"value": [{"id": "graph_msg_123"}]}
        if "move" in endpoint and method == "POST":
            return 200, {}
        if method == "PATCH":
            return 200, {}
        return 400, {}

def test_graph_bot_is_configured():
    bot = MockGraphActionBot()
    assert bot.is_configured() is True
    
    bot.client_secret = ""
    assert bot.is_configured() is False

def test_graph_resolve_message_id():
    bot = MockGraphActionBot()
    msg_id = bot.resolve_message_id("user@test.com", "internet_msg_id")
    assert msg_id == "graph_msg_123"

def test_graph_quarantine_email():
    bot = MockGraphActionBot()
    res = bot.quarantine_email("user@test.com", "graph_msg_123")
    assert res.ok is True
    assert res.action == "quarantine"
    assert res.graph_message_id == "graph_msg_123"

def test_graph_apply_warning_banner():
    bot = MockGraphActionBot()
    res = bot.apply_warning_banner("user@test.com", "graph_msg_123", "High")
    assert res.ok is True
    assert res.action == "apply_warning_banner"

def test_graph_add_categories():
    bot = MockGraphActionBot()
    res = bot.add_categories("user@test.com", "graph_msg_123", ["Phishing"])
    assert res.ok is True
    assert res.action == "add_categories"

def test_graph_action_result_str():
    res = GraphActionResult(ok=True, action="test", detail="msg")
    assert str(res) == "✓ test: msg"
    
    res = GraphActionResult(ok=False, action="test", detail="error")
    assert str(res) == "✗ test: error"
