# Security tool integrations

| | |
|---|---|
| **Document** | Security tool integrations - Agentic SOC platform |
| **Version** | 1.0 - 2026-10-10 |
| **Audience** | Security engineering, identity and access management, tool owners |

## About the platform

The Agentic SOC platform is an investigation and automation layer that runs inside the organisation's own environment,
on top of the security tools it already owns (EDR, e-mail security, identity, DNS, deception, privileged access,
vulnerability scanners, cloud posture, ITSM / CMDB, SIEM). It reads from those tools through their APIs, resolves every
record to one host or one person, and runs three workflows - reported phishing, incident management and
vulnerability management - plus a cross-domain intelligence layer. Every change it makes to a security tool is an
*action request* that passes through one governed action layer and a versioned *autonomy policy*, whose default is
**recommend**: a person approves each action. An optional large language model, reached only through the
organisation's own LLM gateway, writes explanatory narrative but never produces a figure, verdict, score or decision.

**Status terms used in this document:** *Implemented* - built, enforced in code and covered by automated tests that
run on every build; *Configured at deployment* - built, with the value chosen by or taken from the organisation's
environment; *To validate in the organisation's environment* - built and tested against vendor-shaped data, not yet
exercised against the organisation's own tenants, volumes or users (covered by the pilot).

## 1 Summary

- **20 connectors**, one per tool or feed. The organisation enables only the tools it owns; a tool switched off
  disappears from every workflow and screen.
- Every connector uses the **vendor's documented API over HTTPS**, initiated by the platform, with a **dedicated
  service identity per tool**. No agent is installed and no tool connects to the platform (except an optional SIEM
  pushing alerts).
- **Read by default.** Each tool is first connected read-only. Write permissions are granted **per action type**, only
  when the organisation approves that action type; without them, actions are still recommended but cannot execute.
- **Every write is an approved action request.** No workflow, screen or AI component calls a tool's write API
  directly; all writes go through the action layer and the autonomy policy.
- **Credentials never enter the platform's configuration or database.** They live in the organisation's vault and
  are mounted as files; the console shows only *set / not set*.
- Each tool is promoted **one stage at a time**, by a proposal one person makes and another approves, after an
  automatic **preflight** has proven sign-in, every permission and the data shape (section 5).

## 2 Integration overview

| Connector | Tool | Category | Authentication | Read | Write (optional, per approved action) | Status |
|---|---|---|---|---|---|---|
| `entra` | Microsoft Entra ID (+ Azure role assignments) | Identity | OAuth 2.0 client credentials, Entra app registration; certificate (recommended) or secret | Yes | Revoke sessions, disable / enable account, force password change, confirm compromised | Implemented; to validate in tenant |
| `defender_endpoint` | Microsoft Defender for Endpoint | EDR | As Entra | Yes | Isolate / release, AV scan, collect investigation package, block / unblock indicator | Implemented; to validate in tenant |
| `defender_office365` | Microsoft Defender for Office 365 / Exchange Online | E-mail | As Entra | Yes | Campaign soft-delete / restore, block / unblock sender, tag, reporter feedback e-mail | Implemented; to validate in tenant |
| `crowdstrike` | CrowdStrike Falcon | EDR | OAuth 2.0 client credentials (API client) | Yes | Contain / lift containment, Real Time Response collection | Implemented; to validate in tenant |
| `avanan` | Check Point Harmony Email & Collaboration (Avanan) | E-mail | Infinity Portal API key exchanged for a bearer token | Yes | Quarantine / restore | Implemented; to validate in tenant |
| `umbrella` | Cisco Umbrella | DNS | OAuth 2.0 client credentials (API key / secret) | Yes | Block / unblock domain (SOC destination list) | Implemented; to validate in tenant |
| `canary` | Thinkst Canary | Deception | API auth token | Yes | Acknowledge incident | Implemented; to validate in tenant |
| `delinea_secret_server` | Delinea Secret Server | Privileged access | OAuth 2.0 password grant (API user) | Yes | Rotate secret (Change Password Now) | Implemented; endpoint paths to confirm per version |
| `delinea_privilege_manager` | Delinea Privilege Manager | Privileged access | OAuth 2.0 client credentials | Yes | - | Implemented; endpoint paths to confirm per version |
| `rapid7` | Rapid7 InsightVM / Nexpose | Vulnerability | HTTP Basic, read-only console user (or scheduled CSV export) | Yes | - | Implemented; to validate in tenant |
| `wiz` | Wiz | Cloud posture | OAuth 2.0 client credentials (service account) | Yes | - | Implemented; to validate in tenant |
| `servicenow` | ServiceNow (ITSM + CMDB) | Ticketing / CMDB | OAuth 2.0 client credentials or HTTP Basic (integration user) | Yes | Create / update tickets | Implemented; to validate in tenant |
| `jira` | Jira (alternative to ServiceNow) | Ticketing | HTTP Basic: integration user e-mail + API token | Yes | Create / update issues | Implemented; to validate in tenant |
| `cmdb_csv` | Ownership spreadsheet (fallback CMDB) | CMDB | File on a mounted volume | Yes | - | Implemented |
| `sentinel` | Microsoft Sentinel | SIEM | As Entra | Yes | - | Implemented; to validate in tenant |
| `generic_siem` | Any SIEM / SOAR (push) | SIEM | Inbound: platform API key held by the SIEM | Receives | - | Implemented |
| `nvd` | NIST National Vulnerability Database | Public intel | None (optional API key raises the rate limit) | Yes | - | Implemented; verified live |
| `epss` | FIRST EPSS | Public intel | None | Yes | - | Implemented; verified live |
| `cisa_kev` | CISA Known Exploited Vulnerabilities | Public intel | None | Yes | - | Implemented; verified live |
| `threat_intel` | Threat-intel fusion: VirusTotal, AbuseIPDB, OTX, URLhaus, ThreatFox, MalwareBazaar, GreyNoise, Shodan | Threat intel | Per-source API key; each source used only if its key is present | Lookups | - | Implemented; each source opt-in |

"To validate in tenant": every connector parses the vendor's documented response shapes, was audited field by field
against the vendor's public documentation and public reference integrations, and passes a conformance suite (paging,
resume, throttling, token refresh, missing permissions, every field missing or null, wrong-typed fields). Running it
against the organisation's own tenant is part of the pilot.

## 3 Per-tool permissions and connectivity

Permissions are the minimum each function needs. Grant the **read** column at onboarding; grant a **write** item only
when the organisation approves the action type it enables.

### Microsoft Entra ID (`entra`)

| | |
|---|---|
| Used for | Who a person is (department, manager), sign-ins and risk, directory and Azure role assignments (privileged accounts), MFA methods, inbox rules |
| Identity | Dedicated app registration (separate from the console sign-in registration) |
| Read (Microsoft Graph application permissions, admin consent) | `User.Read.All`, `AuditLog.Read.All`, `IdentityRiskyUser.Read.All`, `IdentityRiskEvent.Read.All`, `RoleManagement.Read.Directory`, `UserAuthenticationMethod.Read.All`, `MailboxSettings.Read`; Azure RBAC **Reader** on the subscriptions (or a management group) for Azure role assignments |
| Write | `User.RevokeSessions.All`, `User.EnableDisableAccount.All`, `IdentityRiskyUser.ReadWrite.All`, `User-PasswordProfile.ReadWrite.All` |
| Egress | `graph.microsoft.com`, `management.azure.com`, `login.microsoftonline.com` |
| Licence dependency | Entra ID P2 for risky users and risk detections (other data works without it) |
| Settings | `ENTRA_TENANT_ID`, `ENTRA_CLIENT_ID`, `ENTRA_CLIENT_CERTIFICATE` (recommended) or `ENTRA_CLIENT_SECRET`, optional `ENTRA_AZURE_SUBSCRIPTIONS` |

### Microsoft Defender for Endpoint (`defender_endpoint`)

| | |
|---|---|
| Used for | Alerts with evidence, device inventory, vulnerability management (TVM), advanced hunting for lookups |
| Read (WindowsDefenderATP application permissions) | `Alert.Read.All`, `Machine.Read.All`, `Vulnerability.Read.All`, `AdvancedQuery.Read.All`, `Ti.Read.All` |
| Write | `Machine.Isolate`, `Machine.Scan`, `Machine.CollectForensics`, `Ti.ReadWrite.All` |
| Egress | `api.securitycenter.microsoft.com` (or the regional host), `login.microsoftonline.com` |
| Licence dependency | Defender for Endpoint P2 (advanced hunting, TVM) |

### Microsoft Defender for Office 365 (`defender_office365`)

| | |
|---|---|
| Used for | User-reported messages (the phishing workflow's input), e-mail alerts, message trace and campaign scope, who clicked, sender history |
| Prerequisite | User-reported messages delivered to a dedicated reporting mailbox (Defender portal → User reported settings) |
| Read (Microsoft Graph application permissions) | `Mail.Read` **scoped to the reporting mailbox only** (Exchange Online RBAC for Applications or an Application Access Policy, verified with `Test-ApplicationAccessPolicy`), `SecurityAlert.Read.All`, `ThreatHunting.Read.All` |
| Write | `SecurityAnalyzedMessage.ReadWrite.All` (remediation), `Mail.ReadWrite` (scoped; tagging), `Mail.Send` (scoped to the SOC mailbox; reporter feedback), `Exchange.ManageAsApp` with an Exchange role covering the Tenant Allow/Block List (block sender) |
| Egress | `graph.microsoft.com`, `outlook.office365.com`, `login.microsoftonline.com` |
| Licence dependency | Defender for Office 365 Plan 2 for advanced hunting and click telemetry |
| Note | Remediation uses Microsoft Graph's `analyzedEmails/remediate`, a beta API at the time of writing |

### CrowdStrike Falcon (`crowdstrike`)

| | |
|---|---|
| Used for | Alerts, host inventory, Spotlight vulnerabilities, indicator lookups |
| Read (API client scopes) | Alerts: Read, Hosts: Read, Spotlight vulnerabilities: Read, IOCs: Read |
| Write | Hosts: Write (containment), Real time response: Write (collection; also needs an RTR response policy on the hosts) |
| Egress | The API host of the organisation's Falcon cloud (US-1, US-2, EU-1, ...) |
| Licence dependency | Spotlight / Falcon Exposure Management for vulnerabilities |

### Check Point Harmony Email & Collaboration - Avanan (`avanan`)

| | |
|---|---|
| Used for | Avanan security events and per-message verdicts, reconciled with Defender's |
| Read | Infinity Portal API key for the Email & Collaboration service with a read-only role |
| Write | The same service with a read-write role (quarantine / restore) |
| Egress | The region-specific Check Point gateway shown with the key |
| Licence dependency | HEC API licensing; fallback: Avanan's reports delivered to the reporting mailbox |

### Cisco Umbrella (`umbrella`)

| | |
|---|---|
| Used for | Whether a user reached a site, security categories, shadow IT |
| Read (API key scopes) | `reports.aggregations:read`, `reports.customerDNS:read`, `policies.destinationLists:read` |
| Write | `policies.destinations:write` on a dedicated SOC destination list |
| Egress | `api.umbrella.com` |
| Volume note | By default only DNS queries in Umbrella's security categories are stored (allowed or blocked), not every query |

### Thinkst Canary (`canary`)

| | |
|---|---|
| Used for | Canary and Canarytoken incidents (high-fidelity), device inventory |
| Read | Console API auth token (read-only token where offered) |
| Write | Acknowledge incident (normal token) |
| Egress | `<hash>.canary.tools` |
| Note | Canary's API takes the token as a request parameter; the platform never logs query strings |

### Delinea Secret Server and Privilege Manager

| | |
|---|---|
| Used for | Who opened which privileged secret or session; elevation events |
| Read | Secret Server API user with *View Secret Audit* and *View Launched Sessions*; Privilege Manager API client allowed to read elevation events |
| Write | *Change Password Now* on the target secrets only (rotation) |
| Egress | The organisation's Delinea servers (internal) |
| Note | API paths differ between Delinea versions and are settings; privileged-access data needs the organisation's explicit governance approval |

### Rapid7 InsightVM / Nexpose (`rapid7`)

| | |
|---|---|
| Used for | Asset inventory, vulnerability findings with fix text, fix validation |
| Read | Security Console user with a read-only role (*View Site Asset Data*, *View Group Asset Data*) |
| Write | None |
| Egress | The console host (internal, often port 3780) |
| Note | TLS verification on by default; an internally issued certificate is trusted by supplying the corporate CA, not by disabling verification. Fallback: a scheduled CSV export |

### Wiz (`wiz`)

| | |
|---|---|
| Used for | Cloud inventory, vulnerability findings with internet exposure, misconfiguration issues |
| Read | Service account (Custom Integration, GraphQL API) with `read:resources`, `read:vulnerabilities`, `read:issues` |
| Write | None |
| Egress | The tenant's API endpoint and authentication host |

### ServiceNow (`servicenow`) / Jira (`jira`) / ownership CSV (`cmdb_csv`)

| | |
|---|---|
| Used for | Remediation and incident tickets with status sync back; owner, support group, criticality and location of each host |
| ServiceNow | Integration user (web-service access only) with `itil` (ticket table) and `cmdb_read`; OAuth client credentials (where enabled on the instance) or Basic |
| Jira | Integration user with *Browse projects*, *Create issues*, *Add comments*, *Transition issues* on the SOC project; API token |
| Ownership CSV | A maintained spreadsheet on a mounted volume, used where no CMDB is usable |
| Egress | `<instance>.service-now.com` / `<site>.atlassian.net` |

### Microsoft Sentinel (`sentinel`) and SIEM push (`generic_siem`)

| | |
|---|---|
| Sentinel | App registration with **Microsoft Sentinel Reader** on the workspace; incidents and their entities are read; egress `management.azure.com` |
| Any SIEM / SOAR | Pushes `{"alerts": [...]}` to `POST /api/v1/ingest/alerts` with a platform API key (analyst role, incident domain); replays are de-duplicated; a malformed alert is refused with its reason while the rest of the batch lands; field names are mapped by configuration |

### Public intelligence and threat-intel fusion

| | |
|---|---|
| NVD, EPSS, CISA KEV | No account; only CVE identifiers are sent; an NVD API key is optional. Egress `services.nvd.nist.gov`, `api.first.org`, `www.cisa.gov` |
| Threat-intel sources | Each of the eight sources is used only when its API key is configured. Lookups send **indicators** (IP address, domain, URL or file hash) - never e-mail content, user names or internal hostnames. The organisation decides which sources may receive its indicators and checks each source's licence for commercial use |

## 4 Controls common to every integration

| Control | Behaviour | Status |
|---|---|---|
| Least privilege | One identity per tool; read scopes at onboarding; write scopes per approved action type | Configured at deployment |
| Credential storage | Secrets only in the vault, mounted as files (`<NAME>_FILE`); configuration holds only `${VAR}` references; the console cannot accept, store or show a secret; exports carry no secret values | Implemented |
| Certificate credentials | Microsoft connectors sign each token request with the app registration's certificate (a 10-minute client assertion, RFC 7523) when one is configured, so no shared secret is sent | Implemented |
| Transport security | HTTPS with certificate verification on every call; the organisation's CA bundle for internally issued certificates; proxies supported (`HTTPS_PROXY` / `NO_PROXY`) | Implemented |
| Rate limits | A per-tool request budget (token bucket) that parallel work cannot exceed; split across processes so together they stay within the vendor's limit | Implemented |
| Throttling and errors | `Retry-After` honoured (capped at 120 s); a refused token (401) renewed once; a missing permission (403) reported at once with the scope to grant, never retried; an HTML page answering instead of the API (a proxy or login page) reported as such | Implemented |
| Resumption | Event streams resume from a time watermark (with a 30-minute overlap for late-indexed logs); inventories are read in full; each page is committed as it is stored, so an interrupted backfill resumes | Implemented |
| Data quality | Records are brought to the vendor's documented shape before parsing; a malformed field empties that field only; a record without an identifier is refused with the reason; shape drift is logged per sync | Implemented |
| Isolation | A connector that is misconfigured, cannot be built or fails to import is left out of every workflow with the reason; all other tools keep working | Implemented |
| Outage handling | A tool that is down makes its evidence *unavailable* by name; workflows continue; feeds keep their last known values | Implemented |
| Logging | One structured line per outbound call: host, path, status, time - never query strings, headers or bodies | Implemented |

## 5 Onboarding and change control for a tool

| Stage | Reads | Actions |
|---|---|---|
| Fixtures | Vendor-shaped sample data (demonstrations, tests) | Demonstration only |
| Recording | Live; responses also saved as sanitised test fixtures | None - recommendations appear as manual steps |
| Read-only | Live | None - manual steps |
| Recommend | Live | Offered; **never above L2** - a person approves every one, whatever the policy says |
| Automate | Live | Follow the approved autonomy policy (default still L2) |

A tool moves forward one stage at a time. Each move is a **proposal** made by a person with `manage_connectors`
(an administrator or automation administrator, never an API key or an automated agent) and **approved by a different
person** with `approve_policy` and MFA. Proposing a live stage runs the **preflight** automatically:

| Preflight check | Example failure reported with its fix |
|---|---|
| Configuration | Unknown key, malformed URL, a secret written in clear |
| Start-up | The connector cannot be built (missing secret) |
| Sign-in | Token refused, wrong tenant, clock skew |
| Every stream | The permission it needs is missing (and which scope to grant); parsing fails; data older than expected; volume out of range |
| Write scopes | The permissions the stage's actions will need are absent |

Errors refuse the proposal; warnings are shown to the approver. The approval re-checks that the preflight still
matches (same settings, same secrets present, less than 7 days old). **Pausing** a tool is immediate (audited, reason
required); switching it back on is a normal proposal. Every version of the configuration is kept and can be
restored.

## 6 What the organisation provides per tool

1. A dedicated service identity with the read permissions above (and, later, approved write permissions).
2. Its credentials in the vault, under the names the console's *Configure* panel shows.
3. Outbound HTTPS from the platform to the tool's hosts.
4. Confirmation of licence tiers where a capability depends on them (Entra ID P2, Defender P2 plans, Spotlight, HEC API).
5. A named tool owner who reviews the preflight result and approves the promotion to each stage.
