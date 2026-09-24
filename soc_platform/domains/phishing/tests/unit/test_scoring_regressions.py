from __future__ import annotations

from pathlib import Path

import pytest

from soc_platform.domains.phishing.engine.agents.attachment_agent import agent as attachment_agent
from soc_platform.domains.phishing.engine.orchestrator.scoring_engine.scorer import calculate_threat_score


def test_scoring_prevents_severe_dilution() -> None:
    result = calculate_threat_score(
        [
            {"agent_name": "content_agent", "risk_score": 0.8},
            {"agent_name": "header_agent", "risk_score": 0.1},
        ]
    )

    # 0.8 triggers the max_single_risk >= 0.80 check, so overall_score should be 0.8
    assert result["overall_score"] == pytest.approx(0.8, abs=1e-4)
    assert result["threat_level"] == "critical"


def test_attachment_agent_uses_per_file_max_risk(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    benign = tmp_path / "notes.txt"
    benign.write_bytes(b"hello world")

    malicious = tmp_path / "invoice.pdf.exe"
    malicious.write_bytes(b"not really malware, just an extension test")

    monkeypatch.setattr(attachment_agent, "load_model", lambda: object())
    monkeypatch.setattr(
        attachment_agent,
        "predict",
        lambda _features, model=None: {"risk_score": 0.0, "confidence": 0.0, "indicators": []},
    )

    result = attachment_agent.analyze(
        {
            "attachments": [
                {"filename": benign.name, "path": str(benign)},
                {"filename": malicious.name, "path": str(malicious)},
            ]
        }
    )

    assert result["risk_score"] >= 0.55
    assert any("double_extension_evasion:invoice.pdf.exe" in item for item in result["indicators"])
