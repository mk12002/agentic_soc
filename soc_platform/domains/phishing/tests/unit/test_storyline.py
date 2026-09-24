import pytest
from soc_platform.domains.phishing.engine.orchestrator.storyline_engine import generate_storyline

def test_storyline_generation():
    agent_results = [
        {"agent_name": "header_agent", "risk_score": 0.7, "confidence": 0.9, "indicators": ["Spoofed Domain", "Failed DMARC"]},
        {"agent_name": "content_agent", "risk_score": 0.8, "confidence": 0.85, "indicators": ["Urgent language", "Extortion phrase"]},
        {"agent_name": "url_agent", "risk_score": 0.95, "confidence": 0.95, "indicators": ["Malicious URL inside body"]},
        {"agent_name": "attachment_agent", "indicators": []}, # Empty, shouldn't appear
    ]
    
    storyline = generate_storyline(agent_results, verdict="malicious", recommended_actions=["quarantine"])
    
    assert len(storyline) == 4
    
    # 1. Delivery
    assert storyline[0]["phase"] == "Delivery"
    assert storyline[0]["severity"] in {"low", "medium", "high"}
    assert storyline[0]["confidence"] > 0
    assert "TA0001" in storyline[0]["tactics"][0]
    assert "Spoofed Domain" in storyline[0]["indicators"][0]["value"]
    
    # 2. Lure
    assert storyline[1]["phase"] == "Lure"
    assert "Urgent language" in storyline[1]["indicators"][0]["value"]
    
    # 3. Weaponization
    assert storyline[2]["phase"] == "Weaponization"
    assert "url_agent" in storyline[2]["indicators"][0]["value"]
    
    # 4. Containment
    assert storyline[3]["phase"] == "Containment"
    assert "quarantine" in storyline[3]["indicators"][0]["value"]

def test_storyline_clean_email():
    agent_results = [
        {"agent_name": "header_agent", "risk_score": 0.0, "confidence": 0.95, "indicators": []},
    ]
    storyline = generate_storyline(agent_results, verdict="safe", recommended_actions=["deliver"])
    # Delivery, Containment should still exist, but Weapon and Lure shouldn't
    assert len(storyline) == 2
    assert storyline[0]["phase"] == "Delivery"
    assert "No negative delivery indicators" in storyline[0]["indicators"][0]["value"]
    assert storyline[1]["phase"] == "Containment"
