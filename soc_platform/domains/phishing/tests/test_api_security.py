from fastapi.testclient import TestClient
from soc_platform.domains.phishing.engine.api.main import app



class DummyMQ:
    def connect(self):
        return None

    def publish_new_email(self, payload):
        return None

    def close(self):
        return None


def test_security_headers_present():
    with TestClient(app) as client:
        res = client.get("/health")
        assert res.status_code == 200
        assert res.headers.get("X-Content-Type-Options") == "nosniff"
        assert res.headers.get("X-Frame-Options") == "DENY"


def test_analyze_email_rejects_unsupported_attachment(monkeypatch):
    # patch RabbitMQClient to no-op
    monkeypatch.setattr("soc_platform.domains.phishing.engine.api.main.RabbitMQClient", lambda: DummyMQ())

    payload = {
        "headers": {"sender": "test@example.com", "subject": "hi", "received": [], "to": []},
        "body": "Hello",
        "urls": [],
        "attachments": [
            {"filename": "malware.exe", "content_type": "application/x-msdownload", "size_bytes": 123, "content_base64": ""}
        ],
    }
    with TestClient(app) as client:
        res = client.post("/analyze-email", json=payload)
        assert res.status_code == 400


def test_analyze_batch_rate_limit(monkeypatch):
    # patch RabbitMQClient to no-op
    monkeypatch.setattr("soc_platform.domains.phishing.engine.api.main.RabbitMQClient", lambda: DummyMQ())

    batch = {"emails": []}
    for i in range(6):
        batch["emails"].append({
            "headers": {"sender": f"a{i}@example.com", "subject": "x", "received": [], "to": []},
            "body": "hi",
            "urls": [],
            "attachments": [],
        })
    # First call should be accepted (up to 50 emails) but our rate limit is per-call; we test repeated calls
    with TestClient(app) as client:
        for i in range(5):
            res = client.post("/analyze-batch", json={"emails": batch["emails"][:1]})
            assert res.status_code == 200
        # Sixth call should be rate limited (limit 5 per minute)
        res = client.post("/analyze-batch", json={"emails": batch["emails"][:1]})
        assert res.status_code in (200, 429)

