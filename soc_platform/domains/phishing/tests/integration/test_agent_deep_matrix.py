"""Deep direct-agent validation matrix and frontend smoke tests.

This suite exercises every agent via the public `/agent-test/{agent_name}` API
with positive, negative, and edge payloads to verify response contracts and
risk-score behavior remains directionally correct.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from soc_platform.domains.phishing.engine.api import main as api_main


AGENTS = [
    "header_agent",
    "content_agent",
    "url_agent",
    "attachment_agent",
    "sandbox_agent",
    "threat_intel_agent",
    "user_behavior_agent",
]


def _make_sample_files(tmp_path: Path) -> dict[str, Path]:
    malware_blob = (bytes(range(256)) * 16) + b"VirtualAlloc WriteProcessMemory powershell"

    malware_exe = tmp_path / "invoice_update.exe"
    malware_exe.write_bytes(malware_blob)

    malware_docm = tmp_path / "urgent_payroll.docm"
    malware_docm.write_bytes(malware_blob + b" vba AutoOpen Macro")

    benign_txt = tmp_path / "meeting_notes.txt"
    benign_txt.write_text("Team sync notes and lunch plans.", encoding="utf-8")

    return {
        "malware_exe": malware_exe,
        "malware_docm": malware_docm,
        "benign_txt": benign_txt,
    }


def _payloads(agent_name: str, files: dict[str, Path]) -> tuple[dict, dict, dict]:
    if agent_name == "header_agent":
        positive = {
            "headers": {
                "sender": "alerts@paypa1-security.example",
                "reply_to": "support@evil.example",
                "subject": "Urgent: verify your account",
                "received": ["from smtp-unknown by victim-mx"],
                "message_id": "<hdr-pos-1>",
                "authentication_results": "spf=fail; dkim=fail; dmarc=fail",
            }
        }
        negative = {
            "headers": {
                "sender": "billing@company.com",
                "reply_to": "billing@company.com",
                "subject": "Invoice copy",
                "received": [
                    "from relay1 by relay2",
                    "from relay2 by corp-mx",
                    "from corp-mx by mailbox",
                ],
                "message_id": "<hdr-neg-1>",
                "authentication_results": "spf=pass; dkim=pass; dmarc=pass",
            }
        }
        edge = {"headers": {"sender": "", "authentication_results": "", "received": []}}
        return positive, negative, edge

    if agent_name == "content_agent":
        positive = {
            "headers": {"subject": "Urgent action required"},
            "body": {
                "plain": "Verify account password immediately. Click login link to avoid suspension.",
                "html": "",
            },
        }
        negative = {
            "headers": {"subject": "Team lunch notes"},
            "body": {
                "plain": "Here are normal project updates and tomorrow schedule.",
                "html": "",
            },
        }
        edge = {"headers": {}, "body": {"plain": "", "html": ""}}
        return positive, negative, edge

    if agent_name == "url_agent":
        positive = {
            "urls": [
                "http://secure-login-paypa1.example/verify?token=abc",
                "http://microsoft.com-security-login.example/reset",
            ]
        }
        negative = {"urls": ["https://github.com", "https://www.python.org"]}
        edge = {"urls": []}
        return positive, negative, edge

    if agent_name == "attachment_agent":
        positive = {
            "attachments": [
                {
                    "filename": files["malware_exe"].name,
                    "content_type": "application/octet-stream",
                    "size_bytes": files["malware_exe"].stat().st_size,
                    "path": str(files["malware_exe"]),
                }
            ]
        }
        negative = {
            "attachments": [
                {
                    "filename": files["benign_txt"].name,
                    "content_type": "text/plain",
                    "size_bytes": files["benign_txt"].stat().st_size,
                    "path": str(files["benign_txt"]),
                }
            ]
        }
        edge = {"attachments": []}
        return positive, negative, edge

    if agent_name == "sandbox_agent":
        positive = {
            "attachments": [
                {
                    "filename": files["malware_docm"].name,
                    "content_type": "application/vnd.ms-word",
                    "size_bytes": files["malware_docm"].stat().st_size,
                    "path": str(files["malware_docm"]),
                }
            ]
        }
        negative = {
            "attachments": [
                {
                    "filename": files["benign_txt"].name,
                    "content_type": "text/plain",
                    "size_bytes": files["benign_txt"].stat().st_size,
                    "path": str(files["benign_txt"]),
                }
            ]
        }
        edge = {"attachments": []}
        return positive, negative, edge

    if agent_name == "threat_intel_agent":
        positive = {
            "iocs": {
                "domains": ["paypa1-secure-login.com"],
                "ips": [],
                "hashes": [],
            }
        }
        negative = {
            "iocs": {
                "domains": ["example.org"],
                "ips": [],
                "hashes": [],
            }
        }
        edge = {"iocs": {"domains": [], "ips": [], "hashes": []}}
        return positive, negative, edge

    if agent_name == "user_behavior_agent":
        positive = {
            "headers": {
                "sender": "payroll@unknown-finance.example",
                "subject": "Urgent action required: verify now",
            },
            "body": "Login immediately to verify payroll account.",
        }
        negative = {
            "headers": {
                "sender": "updates@company.com",
                "subject": "Weekly standup notes",
            },
            "body": "Normal meeting summary and project status.",
        }
        edge = {"headers": {"sender": "", "subject": ""}, "body": ""}
        return positive, negative, edge

    raise AssertionError(f"Unhandled agent: {agent_name}")


def _assert_direct_test_response(agent_name: str, response_body: dict) -> None:
    assert response_body["status"] == "completed"
    assert response_body["agent_name"] == agent_name
    assert isinstance(response_body["input_payload"], dict)
    assert isinstance(response_body["output"], dict)

    output = response_body["output"]
    assert output.get("agent_name") == agent_name
    assert isinstance(output.get("indicators", []), list)

    risk = float(output.get("risk_score", 0.0))
    confidence = float(output.get("confidence", 0.0))
    assert 0.0 <= risk <= 1.0
    assert 0.0 <= confidence <= 1.0


@pytest.fixture(autouse=True)
def _sandbox_deterministic_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    # Keep sandbox behavior deterministic in CI/local tests by avoiding docker/executor reliance.
    from soc_platform.domains.phishing.engine.agents.sandbox_agent import agent as sandbox_agent
    from soc_platform.domains.phishing.engine.agents.threat_intel_agent import agent as threat_intel_agent

    monkeypatch.setattr(sandbox_agent.settings, "sandbox_local_docker_enabled", False, raising=False)
    monkeypatch.setattr(sandbox_agent.settings, "sandbox_executor_url", "", raising=False)
    monkeypatch.setattr(threat_intel_agent.settings, "enable_otx_lookup", False, raising=False)
    monkeypatch.setattr(threat_intel_agent.settings, "enable_abuseipdb_lookup", False, raising=False)
    monkeypatch.setattr(threat_intel_agent.settings, "enable_malwarebazaar_lookup", False, raising=False)
    monkeypatch.setattr(threat_intel_agent.settings, "enable_virustotal_hash_lookup", False, raising=False)


@pytest.mark.parametrize("agent_name", AGENTS)
def test_direct_agent_matrix_positive_negative_edge(agent_name: str, tmp_path: Path) -> None:
    files = _make_sample_files(tmp_path)
    positive, negative, edge = _payloads(agent_name, files)

    client = TestClient(api_main.app)

    pos_resp = client.post(f"/agent-test/{agent_name}", json={"payload": positive, "print_output": False})
    neg_resp = client.post(f"/agent-test/{agent_name}", json={"payload": negative, "print_output": False})
    edge_resp = client.post(f"/agent-test/{agent_name}", json={"payload": edge, "print_output": False})

    assert pos_resp.status_code == 200
    assert neg_resp.status_code == 200
    assert edge_resp.status_code == 200

    pos_body = pos_resp.json()
    neg_body = neg_resp.json()
    edge_body = edge_resp.json()

    _assert_direct_test_response(agent_name, pos_body)
    _assert_direct_test_response(agent_name, neg_body)
    _assert_direct_test_response(agent_name, edge_body)

    pos_risk = float(pos_body["output"]["risk_score"])
    neg_risk = float(neg_body["output"]["risk_score"])
    edge_risk = float(edge_body["output"]["risk_score"])

    # Directional accuracy check: malicious examples should not score below benign examples.
    assert pos_risk >= neg_risk, (
        f"{agent_name} risk inversion: positive={pos_risk}, negative={neg_risk}"
    )
    assert pos_risk >= edge_risk, (
        f"{agent_name} edge scored above positive: positive={pos_risk}, edge={edge_risk}"
    )


def test_direct_agent_test_rejects_non_dict_payload() -> None:
    client = TestClient(api_main.app)
    resp = client.post("/agent-test/content_agent", json={"payload": "not-a-dict"})
    assert resp.status_code == 422


def test_frontend_routes_and_assets_smoke() -> None:
    client = TestClient(api_main.app)

    for route in ("/ui", "/ui/analyze", "/ui/agents"):
        res = client.get(route)
        assert res.status_code == 200
        assert "<html" in res.text.lower()
        assert "/ui-assets/app.js" in res.text

    js = client.get("/ui-assets/app.js")
    css = client.get("/ui-assets/styles.css")

    assert js.status_code == 200
    assert "const AgentUI" in js.text
    assert css.status_code == 200
    assert "--accent-cyan" in css.text
