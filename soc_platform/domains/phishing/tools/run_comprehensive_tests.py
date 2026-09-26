import json
import warnings

from soc_platform.domains.phishing.engine.agents.attachment_agent import analyze as attachment_analyze
from soc_platform.domains.phishing.engine.agents.content_agent import analyze as content_analyze
from soc_platform.domains.phishing.engine.agents.header_agent import analyze as header_analyze
from soc_platform.domains.phishing.engine.agents.sandbox_agent import analyze as sandbox_analyze
from soc_platform.domains.phishing.engine.agents.threat_intel_agent import analyze as threat_intel_analyze
from soc_platform.domains.phishing.engine.agents.url_agent import analyze as url_analyze
from soc_platform.domains.phishing.engine.agents.user_behavior_agent.agent import analyze as user_behavior_analyze

warnings.filterwarnings("ignore")

agents = {
    "header_agent": header_analyze,
    "content_agent": content_analyze,
    "url_agent": url_analyze,
    "attachment_agent": attachment_analyze,
    "sandbox_agent": sandbox_analyze,
    "threat_intel_agent": threat_intel_analyze,
    "user_behavior_agent": user_behavior_analyze
}

test_scenarios = {
    "header_agent": {
        "Benign": {
            "headers": {
                "sender": "notifications@github.com",
                "reply_to": "noreply@github.com",
                "subject": "Code pushed",
                "received": [
                    "from mx.github.com by smtp.gmail.com",
                    "from internal by mx.github.com"
                ],
                "authentication_results": "spf=pass; dkim=pass; dmarc=pass"
            }
        },
        "Malicious": {
            "headers": {
                "sender": "admin@rnicrosoft.com",
                "reply_to": "hacker@evil.example",
                "subject": "Urgent: Password expiry",
                "received": [
                    "from unknown by target"
                ],
                "authentication_results": "spf=fail; dkim=fail; dmarc=fail"
            }
        }
    },
    "content_agent": {
        "Benign": {
            "headers": {"subject": "Q3 Planning meeting notes"},
            "body": {"plain": "Hi team, please find the notes from yesterday's Q3 planning session attached. Let me know if you have questions."}
        },
        "Malicious": {
            "headers": {"subject": "URGENT OVERDUE INVOICE"},
            "body": {"plain": "Dear customer, your payment is overdue. Immediately verify your password and login to process the wire transfer or your account will be suspended."}
        }
    },
    "url_agent": {
        "Benign": {
            "urls": ["https://www.github.com/LabsKraft", "https://google.com"]
        },
        "Malicious": {
            "urls": ["http://192.168.1.100/payload.exe", "http://login.microsoftonline.com-verify.auth3-b.info/login"]
        }
    },
    "attachment_agent": {
        "Benign": {
            "attachments": [
                {"filename": "notes.txt", "content_type": "text/plain", "size_bytes": 1024}
            ]
        },
        "Malicious": {
            "attachments": [
                {"filename": "invoice_urgent.exe", "content_type": "application/x-msdownload", "size_bytes": 150000},
                {"filename": "resume.pdf.js", "content_type": "application/javascript", "size_bytes": 500}
            ]
        }
    },
    "sandbox_agent": {
        "Benign": {
            "attachments": [
                {"filename": "hello.txt", "content_type": "text/plain", "size_bytes": 1024, "path": "path"}
            ]
        },
        "Malicious": {
            "attachments": [
                {"filename": "malware.docm", "content_type": "application/vnd.ms-word.document.macroEnabled.12", "size_bytes": 45000, "path": "path"}
            ]
        }
    },
    "threat_intel_agent": {
        "Benign": {
            "headers": {"sender": "noreply@github.com"},
            "urls": ["https://github.com"],
            "iocs": {"domains": ["github.com"], "ips": ["140.82.112.3"], "hashes": []}
        },
        "Malicious": {
            "headers": {"sender": "botnet@evil.example"},
            "urls": ["http://known-bad.example/phish"],
            "iocs": {"domains": ["evil.example", "known-bad.example"], "ips": ["185.100.87.202"], "hashes": ["44d88612fea8a8f36de82e1278abb02f"]}
        }
    },
    "user_behavior_agent": {
        "Benign": {
            "headers": {"sender": "hr@company.com", "subject": "Holiday schedule"},
            "recipient_context": {"department": "engineering", "role": "dev", "historical_click_rate": 0.05}
        },
        "Malicious": {
            "headers": {"sender": "ceo@gmail.com", "subject": "Wire Transfer Needed URGENT"},
            "recipient_context": {"department": "finance", "role": "manager", "historical_click_rate": 0.85}
        }
    }
}

results = {}
for agent_name, test_cases in test_scenarios.items():
    results[agent_name] = {}
    func = agents[agent_name]
    for case_name, payload in test_cases.items():
        try:
            res = func(payload)
            results[agent_name][case_name] = {
                "risk_score": res.get("risk_score"),
                "confidence": res.get("confidence"),
                "indicators": res.get("indicators", [])
            }
        except Exception as e:
            results[agent_name][case_name] = {"error": str(e)}

with open("agent_test_report.json", "w") as f:
    json.dump(results, f, indent=2)
print("done")
