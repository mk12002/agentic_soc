from __future__ import annotations

import pytest

from soc_platform.domains.phishing.engine.agents.threat_intel_agent import agent as threat_intel_agent
from soc_platform.domains.phishing.engine.agents.url_agent import agent as url_agent


def test_url_agent_external_enrichment_fusion(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(url_agent, "_heuristic_score", lambda _url: (0.2, ["heuristic_signal"]))
    monkeypatch.setattr(url_agent, "_external_score", lambda _url: (1.0, ["external_signal"]))
    monkeypatch.setattr(url_agent, "_any_external_lookup_enabled", lambda: True)
    monkeypatch.setattr(url_agent, "extract_features", lambda _payload: {"metrics": {}})
    monkeypatch.setattr(url_agent, "load_model", lambda: object())
    monkeypatch.setattr(
        url_agent,
        "predict",
        lambda _features, model=None: {
            "risk_score": 0.4,
            "confidence": 0.8,
            "indicators": ["ml_url_model_used"],
        },
    )

    result = url_agent.analyze({"urls": ["http://suspicious.example/login"]})

    # External threat signal should dominate URL evidence when available.
    assert result["risk_score"] == pytest.approx(1.000, abs=1e-3)
    assert result["confidence"] == pytest.approx(0.800, abs=1e-3)
    assert any("external_risk=1.0" == item for item in result["indicators"])
    assert any("external_lookups_enabled" == item for item in result["indicators"])


def test_threat_intel_external_enrichment_fusion(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(threat_intel_agent, "_refresh_ioc_store_if_needed", lambda: 42)
    monkeypatch.setattr(threat_intel_agent._STORE, "lookup", lambda _candidates: ["evil.example"])
    monkeypatch.setattr(threat_intel_agent, "load_model", lambda: object())
    monkeypatch.setattr(threat_intel_agent, "extract_features", lambda *_args, **_kwargs: {"f": 1.0})
    monkeypatch.setattr(
        threat_intel_agent,
        "predict",
        lambda _features, _model: {
            "risk_score": 0.5,
            "confidence": 0.7,
            "indicators": [],
        },
    )
    monkeypatch.setattr(
        threat_intel_agent,
        "_external_enrichment_score",
        lambda _iocs: (0.8, ["otx_hit:domain:evil.example"]),
    )
    monkeypatch.setattr(threat_intel_agent.settings, "enable_otx_lookup", True, raising=False)
    monkeypatch.setattr(threat_intel_agent.settings, "enable_abuseipdb_lookup", False, raising=False)
    monkeypatch.setattr(threat_intel_agent.settings, "enable_malwarebazaar_lookup", False, raising=False)
    monkeypatch.setattr(threat_intel_agent.settings, "enable_virustotal_hash_lookup", False, raising=False)

    result = threat_intel_agent.analyze(
        {
            "iocs": {
                "domains": ["evil.example", "safe.example"],
                "ips": [],
                "hashes": [],
            }
        }
    )

    # Using the new max() logic, max(0.5, 0.5, 0.8, 0.545) = 0.8
    # confidence max(0.7, 0.55+0.2+0.1)=0.85
    assert result["risk_score"] == pytest.approx(0.800, abs=1e-3)
    assert result["confidence"] == pytest.approx(0.850, abs=1e-3)
    assert any(str(item).startswith("ioc_match:") for item in result["indicators"])
    assert "external_threat_enrichment_enabled" in result["indicators"]


def test_url_agent_risk_gap_and_confidence_penalty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(url_agent, "_any_external_lookup_enabled", lambda: True)

    def _heuristic(url: str):
        if "paypa1" in url:
            return 0.8, ["credential_bait_terms"]
        return 0.55, ["credential_bait_terms"]

    monkeypatch.setattr(url_agent, "_heuristic_score", _heuristic)
    monkeypatch.setattr(url_agent, "_external_score", lambda _url: (0.0, []))
    monkeypatch.setattr(url_agent, "extract_features", lambda payload: payload)

    def _predict(features, model=None):
        url = (features.get("urls") or [""])[0]
        if "paypa1" in url:
            return {"risk_score": 0.85, "confidence": 0.9, "indicators": ["ml_url_model_used"]}
        return {"risk_score": 0.75, "confidence": 0.9, "indicators": ["ml_url_model_used"]}

    monkeypatch.setattr(url_agent, "load_model", lambda: object())
    monkeypatch.setattr(url_agent, "predict", _predict)

    malicious = url_agent.analyze({"urls": ["http://secure-paypa1-account.example/login"]})
    benign = url_agent.analyze({"urls": ["https://github.com/login"]})

    gap = float(malicious["risk_score"]) - float(benign["risk_score"])
    assert gap >= 0.25
    assert any(str(item).startswith("confidence_penalty_conflict=") for item in malicious["indicators"])
    assert "global_allowlist_prior_applied" in benign["indicators"]


def test_url_agent_brand_impersonation_floor(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(url_agent, "_any_external_lookup_enabled", lambda: True)
    monkeypatch.setattr(url_agent, "_external_score", lambda _url: (0.0, ["openphish_unavailable", "urlhaus_unavailable"]))
    monkeypatch.setattr(url_agent, "extract_features", lambda payload: payload)
    monkeypatch.setattr(url_agent, "load_model", lambda: object())
    monkeypatch.setattr(
        url_agent,
        "predict",
        lambda _features, model=None: {
            "risk_score": 0.2,
            "confidence": 0.85,
            "indicators": ["ml_url_model_used"],
        },
    )

    result = url_agent.analyze({"urls": ["https://microsoft.com-security-login.example/reset"]})

    assert result["risk_score"] >= 0.45
    assert "brand_impersonation_suspicious_floor" in result["indicators"]
    assert any("brand_impersonation:microsoft" in item for item in result["indicators"])


def test_url_agent_brand_impersonation_does_not_additively_inflate(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(url_agent, "_any_external_lookup_enabled", lambda: True)
    monkeypatch.setattr(url_agent, "_external_score", lambda _url: (0.0, []))
    monkeypatch.setattr(url_agent, "extract_features", lambda payload: payload)
    monkeypatch.setattr(url_agent, "load_model", lambda: object())
    monkeypatch.setattr(
        url_agent,
        "predict",
        lambda _features, model=None: {
            "risk_score": 0.2,
            "confidence": 0.85,
            "indicators": ["ml_url_model_used"],
        },
    )

    result = url_agent.analyze(
        {
            "urls": [
                "https://microsoft.com-security-login.example/reset",
                "https://microsoft.com-security-verify.example/confirm",
            ]
        }
    )

    assert result["risk_score"] == pytest.approx(0.88, abs=1e-3)
    assert result["risk_score"] < 0.9
    assert any("brand_impersonation:microsoft" in item for item in result["indicators"])


def test_url_agent_multi_url_boost(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(url_agent, "_any_external_lookup_enabled", lambda: False)
    monkeypatch.setattr(url_agent, "_heuristic_score", lambda _url: (0.08, ["non_https_url"]))
    monkeypatch.setattr(url_agent, "_external_score", lambda _url: (0.0, []))
    monkeypatch.setattr(url_agent, "extract_features", lambda payload: payload)
    monkeypatch.setattr(url_agent, "load_model", lambda: object())
    monkeypatch.setattr(
        url_agent,
        "predict",
        lambda _features, model=None: {
            "risk_score": 0.0,
            "confidence": 0.0,
            "indicators": [],
        },
    )

    result = url_agent.analyze({"urls": ["http://a.example", "http://b.example", "http://c.example"]})

    assert result["risk_score"] >= 0.11
    assert any("many_urls:3" in item for item in result["indicators"])
