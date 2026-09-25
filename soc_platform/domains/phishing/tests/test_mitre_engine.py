from soc_platform.domains.phishing.engine.orchestrator.mitre_attack_engine import map_indicator_to_techniques, map_agent_results_to_attack

def test_map_indicator_to_techniques():
    # Test DMARC failure mapping
    matches = map_indicator_to_techniques("header_agent", "dmarc_failed", agent_risk_score=0.8, agent_confidence=0.9)
    assert len(matches) > 0
    tech_ids = [m.technique.technique_id for m in matches]
    assert "T1566" in tech_ids
    assert "T1583.001" in tech_ids

    # Test Powershell mapping
    matches = map_indicator_to_techniques("sandbox_agent", "powershell execution detected", agent_risk_score=0.9, agent_confidence=1.0)
    assert len(matches) > 0
    tech_ids = [m.technique.technique_id for m in matches]
    assert "T1059.001" in tech_ids

def test_map_agent_results_to_attack():
    agent_results = [
        {
            "agent_name": "header_agent",
            "risk_score": 0.8,
            "confidence": 0.9,
            "indicators": ["dmarc_failed", "domain_spoofing"]
        },
        {
            "agent_name": "url_agent",
            "risk_score": 0.9,
            "confidence": 0.85,
            "indicators": ["credential_harvesting"]
        }
    ]
    
    attack_data = map_agent_results_to_attack(agent_results)
    assert attack_data["technique_count"] > 0
    assert len(attack_data["kill_chain_phases"]) > 0
    
    tactics = [t.get("tactic_id") for t in attack_data["techniques"]]
    assert "TA0001" in tactics # Initial Access from header spoofing
    assert "TA0006" in tactics # Credential Access from harvesting
