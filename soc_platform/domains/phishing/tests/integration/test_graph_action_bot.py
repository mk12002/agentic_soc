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

class _MessageGraph(GraphActionBot):
    """Records requests; answers the message read with the given draft state and body."""

    def __init__(self, is_draft):
        super().__init__()
        self.tenant_id, self.client_id, self.client_secret = "t", "c", "s"
        self.is_draft, self.calls = is_draft, []

    def _graph_request(self, method, endpoint, json_data=None, params=None):
        self.calls.append((method, endpoint, json_data))
        if method == "GET":
            return 200, {"isDraft": self.is_draft, "categories": ["Finance"],
                         "body": {"contentType": "text", "content": "Pay <now>"}}
        return 200, {}


def test_graph_apply_warning_banner_on_a_delivered_message_tags_it():
    bot = _MessageGraph(is_draft=False)
    res = bot.apply_warning_banner("user@test.com", "graph_msg_123", "High")
    assert res.ok is True and res.action == "apply_warning_banner" and "tagged" in res.detail
    method, _, body = bot.calls[-1]
    assert method == "PATCH" and body == {"categories": ["Finance", "Security warning: High risk"]}


def test_graph_apply_warning_banner_on_a_draft_prepends_the_banner():
    bot = _MessageGraph(is_draft=True)
    res = bot.apply_warning_banner("user@test.com", "graph_msg_123", "High")
    assert res.ok is True and "prepended" in res.detail
    content = bot.calls[-1][2]["body"]["content"]
    assert "Security Warning: High Risk" in content and "Pay &lt;now&gt;" in content   # original text kept, escaped

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
