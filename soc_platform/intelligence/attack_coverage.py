"""Detection coverage mapping against MITRE ATT&CK (U09).

Two layers per technique:

* **capability** - which *enabled* connected tools can detect it (static map below, maintained with the
  detection engineering team; "partial" means limited telemetry or configuration-dependent)
* **observed**   - how often it actually appeared in alerts and cases (evidence that detections fire)

A *blind spot* is a technique on the priority list that no enabled tool can detect; a *silent* technique
is covered on paper but has never fired (worth a purple-team test - U10). Coverage is recomputed from
the connector registry, so enabling a connector immediately changes the map.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from soc_platform.core.models import Case, Entity

TACTICS = [("TA0001", "Initial Access"), ("TA0002", "Execution"), ("TA0003", "Persistence"),
           ("TA0004", "Privilege Escalation"), ("TA0005", "Defense Evasion"), ("TA0006", "Credential Access"),
           ("TA0007", "Discovery"), ("TA0008", "Lateral Movement"), ("TA0009", "Collection"),
           ("TA0011", "Command and Control"), ("TA0010", "Exfiltration"), ("TA0040", "Impact")]

# technique -> (name, tactic, priority). Priority = commonly used in intrusions against organisations like CCI.
TECHNIQUES: dict[str, tuple[str, str, bool]] = {
    "T1566.001": ("Spearphishing Attachment", "TA0001", True),
    "T1566.002": ("Spearphishing Link", "TA0001", True),
    "T1566.003": ("Spearphishing via Service", "TA0001", False),
    "T1190": ("Exploit Public-Facing Application", "TA0001", True),
    "T1133": ("External Remote Services", "TA0001", True),
    "T1078": ("Valid Accounts", "TA0001", True),
    "T1078.004": ("Cloud Accounts", "TA0001", True),
    "T1199": ("Trusted Relationship", "TA0001", True),
    "T1059.001": ("PowerShell", "TA0002", True),
    "T1059.003": ("Windows Command Shell", "TA0002", True),
    "T1047": ("Windows Management Instrumentation", "TA0002", False),
    "T1204.001": ("User Execution: Malicious Link", "TA0002", True),
    "T1204.002": ("User Execution: Malicious File", "TA0002", True),
    "T1053.005": ("Scheduled Task", "TA0003", True),
    "T1547.001": ("Registry Run Keys / Startup Folder", "TA0003", True),
    "T1136": ("Create Account", "TA0003", True),
    "T1098": ("Account Manipulation", "TA0003", True),
    "T1098.005": ("Device Registration", "TA0003", False),
    "T1505.003": ("Web Shell", "TA0003", True),
    "T1068": ("Exploitation for Privilege Escalation", "TA0004", True),
    "T1548.002": ("Bypass User Account Control", "TA0004", False),
    "T1562.001": ("Disable or Modify Tools", "TA0005", True),
    "T1070.001": ("Clear Windows Event Logs", "TA0005", True),
    "T1027": ("Obfuscated Files or Information", "TA0005", False),
    "T1218": ("System Binary Proxy Execution", "TA0005", False),
    "T1003.001": ("OS Credential Dumping: LSASS Memory", "TA0006", True),
    "T1110": ("Brute Force", "TA0006", True),
    "T1110.003": ("Password Spraying", "TA0006", True),
    "T1555": ("Credentials from Password Stores", "TA0006", True),
    "T1552": ("Unsecured Credentials", "TA0006", False),
    "T1557": ("Adversary-in-the-Middle (AiTM phishing)", "TA0006", True),
    "T1621": ("MFA Request Generation", "TA0006", True),
    "T1528": ("Steal Application Access Token", "TA0006", False),
    "T1083": ("File and Directory Discovery", "TA0007", False),
    "T1087": ("Account Discovery", "TA0007", True),
    "T1135": ("Network Share Discovery", "TA0007", True),
    "T1046": ("Network Service Discovery", "TA0007", True),
    "T1021.001": ("Remote Desktop Protocol", "TA0008", True),
    "T1021.002": ("SMB / Windows Admin Shares", "TA0008", True),
    "T1570": ("Lateral Tool Transfer", "TA0008", False),
    "T1550": ("Use Alternate Authentication Material", "TA0008", True),
    "T1039": ("Data from Network Shared Drive", "TA0009", False),
    "T1114.003": ("Email Forwarding Rule", "TA0009", True),
    "T1530": ("Data from Cloud Storage", "TA0009", True),
    "T1560": ("Archive Collected Data", "TA0009", False),
    "T1071.001": ("Application Layer Protocol: Web", "TA0011", True),
    "T1071.004": ("Application Layer Protocol: DNS", "TA0011", True),
    "T1568": ("Dynamic Resolution", "TA0011", False),
    "T1105": ("Ingress Tool Transfer", "TA0011", True),
    "T1219": ("Remote Access Software", "TA0011", True),
    "T1090.003": ("Multi-hop Proxy", "TA0011", False),
    "T1567.002": ("Exfiltration to Cloud Storage", "TA0010", True),
    "T1048": ("Exfiltration Over Alternative Protocol", "TA0010", False),
    "T1486": ("Data Encrypted for Impact", "TA0040", True),
    "T1490": ("Inhibit System Recovery", "TA0040", True),
    "T1657": ("Financial Theft (BEC / payment diversion)", "TA0040", True),
}

_EDR = {"T1059.001", "T1059.003", "T1047", "T1204.002", "T1053.005", "T1547.001", "T1136", "T1505.003", "T1068",
        "T1548.002", "T1562.001", "T1070.001", "T1027", "T1218", "T1003.001", "T1555", "T1083", "T1087", "T1135",
        "T1046", "T1021.001", "T1021.002", "T1570", "T1550", "T1560", "T1071.001", "T1105", "T1219", "T1486",
        "T1490", "T1190"}
# tool -> {technique: "full" | "partial"}
CAPABILITY: dict[str, dict[str, str]] = {
    "crowdstrike": {t: "full" for t in _EDR} | {"T1204.001": "partial", "T1552": "partial", "T1048": "partial"},
    "defender_endpoint": {t: "full" for t in _EDR} | {"T1204.001": "partial", "T1552": "partial"},
    "entra": {"T1078": "full", "T1078.004": "full", "T1110": "full", "T1110.003": "full", "T1621": "full",
              "T1528": "partial", "T1098": "full", "T1098.005": "full", "T1136": "partial", "T1557": "partial",
              "T1133": "partial"},
    "defender_office365": {"T1566.001": "full", "T1566.002": "full", "T1566.003": "partial", "T1114.003": "full",
                           "T1557": "partial", "T1204.001": "full", "T1657": "partial", "T1199": "partial"},
    "avanan": {"T1566.001": "full", "T1566.002": "full", "T1566.003": "full", "T1114.003": "partial",
               "T1657": "partial", "T1199": "partial"},
    "umbrella": {"T1071.004": "full", "T1568": "full", "T1071.001": "partial", "T1567.002": "partial",
                 "T1204.001": "full", "T1566.002": "partial", "T1090.003": "full", "T1219": "partial", "T1105": "partial"},
    "canary": {"T1083": "full", "T1135": "full", "T1087": "partial", "T1021.001": "full", "T1021.002": "full",
               "T1046": "full", "T1552": "full", "T1039": "full", "T1110": "partial", "T1530": "partial"},
    "delinea_secret_server": {"T1555": "full", "T1078": "partial", "T1098": "partial", "T1552": "partial"},
    "delinea_privilege_manager": {"T1548.002": "full", "T1068": "partial", "T1204.002": "partial",
                                  "T1059.001": "partial", "T1219": "partial"},
    "wiz": {"T1190": "partial", "T1078.004": "partial", "T1530": "full", "T1133": "partial", "T1552": "partial"},
}
RANK = {"full": 2, "partial": 1}


def _observed(session: Session) -> tuple[Counter, dict[str, set[str]]]:
    counts: Counter[str] = Counter()
    sources: dict[str, set[str]] = defaultdict(set)
    for case in session.execute(select(Case).where(Case.domain.in_(("incident", "phishing")))).scalars():
        for m in (case.assessment or {}).get("mitre") or []:
            t = (m.get("technique") if isinstance(m, dict) else str(m)) or ""
            if t:
                counts[t] += 1
                sources[t].add(f"case:{case.domain}")
    for ev in session.execute(select(Entity).where(Entity.kind == "alert")).scalars():
        a = ev.attributes or {}
        for t in {a.get("technique_id"), *(a.get("mitre_techniques") or [])} - {None, ""}:
            counts[str(t)] += 1
            sources[str(t)].add(str(a.get("tool") or "alert"))
    return counts, sources


def coverage(session: Session, enabled_tools: list[str]) -> dict[str, Any]:
    enabled = [t for t in enabled_tools if t in CAPABILITY]
    counts, sources = _observed(session)
    rows = []
    for tid, (name, tactic, priority) in TECHNIQUES.items():
        # sub-technique alerts count for the parent row and vice versa for observation
        obs = counts.get(tid, 0) + sum(v for k, v in counts.items() if k.startswith(tid + ".") )
        by = {tool: CAPABILITY[tool][tid] for tool in enabled if tid in CAPABILITY[tool]}
        level = max((RANK[v] for v in by.values()), default=0)
        rows.append({"technique": tid, "name": name, "tactic": tactic, "priority": priority,
                     "coverage": {2: "full", 1: "partial", 0: "none"}[level], "detected_by": by,
                     "sources_count": len(by), "observed": obs, "observed_via": sorted(sources.get(tid, set())),
                     "status": ("blind_spot" if level == 0 else "silent" if obs == 0 else "firing")})
    tactics = []
    for ta, tname in TACTICS:
        tr = [r for r in rows if r["tactic"] == ta]
        tactics.append({"id": ta, "name": tname, "techniques": tr,
                        "coverage_pct": round(100 * sum(RANK.get(r["coverage"], 0) for r in tr) / (2 * len(tr)), 1)
                        if tr else 0.0})
    blind = [r for r in rows if r["status"] == "blind_spot" and r["priority"]]
    single = [r for r in rows if r["sources_count"] == 1 and r["priority"]]
    unknown = sorted(t for t in counts if t not in TECHNIQUES and not any(t.startswith(k + ".") for k in TECHNIQUES))
    total = len(rows)
    return {"enabled_detection_tools": enabled, "tactics": tactics,
            "summary": {"techniques": total,
                        "covered": sum(1 for r in rows if r["coverage"] != "none"),
                        "full": sum(1 for r in rows if r["coverage"] == "full"),
                        "priority_blind_spots": len(blind), "single_source_priority": len(single),
                        "firing": sum(1 for r in rows if r["status"] == "firing"),
                        "weighted_coverage_pct": round(100 * sum(RANK.get(r["coverage"], 0) for r in rows) / (2 * total), 1)},
            "priority_blind_spots": [{k: r[k] for k in ("technique", "name", "tactic")} for r in blind],
            "single_source_priority": [{"technique": r["technique"], "name": r["name"], "only": list(r["detected_by"])}
                                       for r in single],
            "observed_outside_catalogue": unknown}
