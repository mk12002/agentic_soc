from soc_platform.domains.phishing.engine.orchestrator.stix_generator import generate_stix_bundle


def test_generate_stix_bundle():
    agent_results = [
        {
            "agent_name": "url_agent",
            "risk_score": 0.95,
            "confidence": 0.9,
            "indicators": ["credential_harvesting"]
        }
    ]
    attack_data = {
        "techniques": [
            {
                "technique_id": "T1566.002",
                "technique_name": "Spearphishing Link",
                "tactic_name": "Initial Access"
            }
        ]
    }
    recommended_actions = ["quarantine", "block_sender"]
    
    bundle = generate_stix_bundle(
        analysis_id="test-1234",
        agent_results=agent_results,
        verdict="malicious",
        risk_score=0.95,
        email_headers={"sender": "attacker@evil.com"},
        attack_data=attack_data,
        recommended_actions=recommended_actions
    )
    
    assert bundle["type"] == "bundle"
    assert len(bundle["objects"]) > 0
    
    types = [obj["type"] for obj in bundle["objects"]]
    assert "report" in types
    assert "indicator" in types
    assert "malware" in types
    assert "attack-pattern" in types
    assert "course-of-action" in types
    assert "email-addr" in types
