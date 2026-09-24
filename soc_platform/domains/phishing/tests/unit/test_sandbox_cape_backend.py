"""CAPEv2 detonation backend (Windows payloads) with a mocked CAPE API."""

from __future__ import annotations

from pathlib import Path

import httpx

from soc_platform.domains.phishing.engine.agents.sandbox_agent import agent as sandbox_agent


def test_cape_submission_poll_and_report_mapping(monkeypatch, tmp_path: Path) -> None:
    sample = tmp_path / "invoice.docm"
    sample.write_bytes(b"PK\x03\x04 vbaProject.bin AutoOpen")
    calls = []
    status = iter(["pending", "running", "reported"])

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append((req.method, req.url.path, req.headers.get("authorization")))
        if req.url.path.endswith("/tasks/create/file/"):
            assert b"route" in req.content and b"none" in req.content  # no internet for the analysis VM
            return httpx.Response(200, json={"data": {"task_ids": [77]}})
        if "/tasks/status/77/" in req.url.path:
            return httpx.Response(200, json={"data": next(status)})
        return httpx.Response(200, json={"malscore": 8.5, "detections": "Emotet",
                                         "signatures": [{"name": "office_macro_autoexec"}, {"name": "spawns_powershell"}],
                                         "behavior": {"processes": [{"process_name": "WINWORD.EXE"},
                                                                    {"process_name": "powershell.exe"}]},
                                         "network": {"hosts": [{"ip": "185.244.25.18"}, {"ip": "10.0.0.5"}]}})

    real_client = httpx.Client
    monkeypatch.setattr(sandbox_agent.httpx, "Client", lambda **kw: real_client(transport=httpx.MockTransport(handler)))
    monkeypatch.setattr(sandbox_agent.time, "sleep", lambda s: None)
    monkeypatch.setattr(sandbox_agent.settings, "sandbox_cape_url", "https://cape.lab.local", raising=False)
    monkeypatch.setattr(sandbox_agent.settings, "sandbox_cape_token", "t0k", raising=False)
    monkeypatch.setattr(sandbox_agent.settings, "sandbox_allow_network", False, raising=False)
    monkeypatch.setattr(sandbox_agent, "SANDBOX_RUNTIME_CSV", tmp_path / "rt.csv")

    assert sandbox_agent._select_detonator(sample, None) is sandbox_agent._detonate_via_cape
    assert sandbox_agent._select_detonator(tmp_path / "x.sh", "local") == "local"
    score, indicators, behavior, _ = sandbox_agent._detonate_via_cape(sample)
    assert score == 0.85 and behavior["shell_spawned"] and behavior["remote_ips"] == ["185.244.25.18"]
    assert "cape_signature:office_macro_autoexec" in indicators and behavior["cape_families"] == "Emotet"
    assert all(c[2] == "Token t0k" for c in calls)
