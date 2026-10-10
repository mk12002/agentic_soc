# Connectors

Generated from the connector manifests by `scripts/build_connector_docs.py` - regenerate after changing a connector.

Every connector runs in one of two modes, set per connector in `config/connectors.yaml`:

* **fake** - replays vendor-shaped fixture responses (`soc_platform/fixtures/<name>.json`) through exactly the same
  parsing, normalisation, lookup and action code as live mode. Used for development, tests and demos.
* **live** - calls the vendor API with the credentials in the config (use `${ENV}` or `<NAME>_FILE` vault mounts,
  never literals).

**Verification status.** Every connector is implemented against the vendor's documented API and verified end to end
on fixtures shaped like the documented responses (`soc_platform/tests/test_connectors.py`). Request and response
formats were audited field by field against the vendors' public API references and public reference integrations
(round 14 in `docs/TEST_REPORT.md` lists what that audit corrected). The public feeds (NVD, EPSS, CISA KEV) are also
verified live. Beyond the documented shapes, every connector passes a conformance suite
(`soc_platform/tests/test_connector_conformance.py`, round 16): reading across pages in its vendor's own paging style,
resuming the next sync correctly (a time watermark with an overlap for late logs, or a fresh read - never an expired
continuation token), throttling with `Retry-After`, a refused token renewed once, a missing permission reported at
once, and every field of every record missing, null or of the wrong type (a malformed field is conformed to the
stream's documented shape and reported, never fatal to the record). The demo fixtures are one scripted scenario, far smaller and
tidier than a tenant; `scripts/build_estate_variant.py --messy --scale N` generates large, disorderly estates for
volume tests, and record-and-sanitise (`SOC_RECORD_FIXTURES_DIR`) turns the first live responses into fixtures.
The vendor connectors have **not yet been run against the client's tenants**: do that per connector with
the *Preflight* button (Integrations screen), `python -m soc_platform preflight <name>` or
`POST /api/v1/config/connectors/{name}/preflight`, which checks sign-in, every stream and the permission it needs,
parsing, data freshness and volume, and says how to fix each failure. Items under *To confirm* are licence or
permission questions for the client (A01, A03). Step-by-step onboarding of every tool in the client's environment:
`docs/CLIENT_DEPLOYMENT_GUIDE.md`.

**Onboarding a tool (live):**

1. Create a dedicated service principal / API client with the read scopes listed (write scopes only for the
   actions you intend to approve).
2. Put the secrets in the vault (or environment) under the names *Integrations -> Configure* shows (convention
   `<CONNECTOR>_<SETTING>`); they are never typed into the console.
3. *Configure*: the non-secret settings and the stage **Recording** or **Read-only**; propose. The preflight runs on the
   proposal; a lead approves; it applies within seconds, no restart. (Or `stage: read` in `config/connectors.yaml`.)
4. Check the Integrations screen: records ingested, freshness, reconciliation against the tool's own total.
5. Promote to **Recommend** (actions offered, never above L2), later **Automate** (the autonomy policy decides).

**Adding a tool that has no connector:** `python -m soc_platform connector new <name> --category <cat> --tool "Vendor
Product"` writes a connector that already follows the platform's rules, its fixtures, its paging test and a switched-off
config entry; adapt the endpoints and fields, then `python -m soc_platform connector check <name>`.


| Connector | Tool | Category | Streams | Lookups | Actions | Confidence |
|---|---|---|---|---|---|---|
| `avanan` | Avanan (Check Point Harmony Email) | email | security_events | email_message, domain | email.gateway_quarantine, email.gateway_restore | Low-Medium |
| `canary` | Thinkst Canary | deception | incidents, devices | ip, host | canary.acknowledge | High |
| `cisa_kev` | CISA KEV catalogue | intel | catalog | cve | - | High |
| `cmdb_csv` | Ownership mapping (CSV) | cmdb | cmdb | host | - | High |
| `crowdstrike` | CrowdStrike Falcon | edr | alerts, hosts, vulnerabilities | host, hash, domain, ip, user | endpoint.collect_forensics, endpoint.isolate, endpoint.release | High |
| `defender_endpoint` | Microsoft Defender for Endpoint | edr | alerts, machines, vulnerabilities | host, ip, hash, domain, user | endpoint.collect_forensics, endpoint.isolate, endpoint.release, endpoint.scan, indicator.block, indicator.unblock | High |
| `defender_office365` | Microsoft Defender for Office 365 | email | reported_messages, email_alerts | email_message, user, domain, url, hash | email.block_sender, email.campaign_purge, email.reporter_feedback, email.restore, email.tag, email.unblock_sender, notify.email | High |
| `delinea_privilege_manager` | Delinea Privilege Manager | pam | elevation_events | user, host | - | Medium |
| `delinea_secret_server` | Delinea Secret Server | pam | secret_audits | user | pam.rotate_secret | Medium |
| `entra` | Microsoft Entra ID | identity | users, signins, risky_users, risk_detections, directory_audits | user, ip | identity.confirm_compromised, identity.disable_account, identity.enable_account, identity.reset_password, identity.revoke_sessions | High |
| `epss` | FIRST EPSS | intel | - | cve | - | High |
| `generic_siem` | Generic SIEM/SOAR webhook | siem | pushed | - | - | High |
| `jira` | Jira (ITSM) | itsm | tickets | - | ticket.create, ticket.update | Unknown |
| `nvd` | NIST NVD | intel | recent_cves | cve | - | High |
| `rapid7` | Rapid7 InsightVM / Nexpose | vuln | assets, findings | host, ip, cve | - | Medium-High |
| `sentinel` | Microsoft Sentinel | siem | incidents | - | - | Unknown |
| `servicenow` | ServiceNow (ITSM + CMDB) | itsm | tickets, cmdb | host | ticket.create, ticket.update | Unknown |
| `threat_intel` | Threat intelligence fusion | intel | - | ip, domain, url, hash | - | High |
| `umbrella` | Cisco Umbrella | dns | dns_activity | domain, host, ip | dns.block_domain, dns.unblock_domain | Medium-High |
| `wiz` | Wiz | cloud | resources, vulnerabilities, issues | host, cve | - | High |

## Per-connector setup

### Avanan (Check Point Harmony Email) (`avanan`)

Security events, per-message verdicts and actions for reconciliation; quarantine/restore.

- Vendor: Check Point · focus areas: phishing
- Read scopes: Infinity Portal API key for the Email & Collaboration service (read events and entities)
- Write scopes (only for approved actions): same API key with a read-write role: quarantine / restore
- To confirm with the client: API availability and scope under current licence (fallbacks: journaling, shared mailbox, export)
- Configuration:
  - `api_url` (optional): Smart API gateway URL (region specific)
  - `client_id` (secret): Infinity Portal API client id
  - `access_key` (secret): API access key
  - `fallback` (optional): shared_mailbox | export if the API is not licensed
  - `sync_from` (optional): First sync starts here (ISO time; default 2026-01-01T00:00:00Z)

### Thinkst Canary (`canary`)

Canary and Canarytoken incidents and device inventory; high-fidelity deception signal.

- Vendor: Thinkst · focus areas: incident
- Read scopes: API auth token (read-only where available)
- Write scopes (only for approved actions): acknowledge incidents
- To confirm with the client: API token provisioning
- Configuration:
  - `domain_hash`: Console hash (<hash>.canary.tools)
  - `auth_token` (secret): API auth token
  - `user_domain` (optional): UPN suffix for Canary usernames

### CISA KEV catalogue (`cisa_kev`)

Known Exploited Vulnerabilities catalogue; additions trigger exposure assessment.

- Vendor: CISA · focus areas: vulnerability, incident
- Read scopes: see vendor docs / to confirm
- Write scopes (only for approved actions): -
- To confirm with the client: -
- Configuration:
  - none

### Ownership mapping (CSV) (`cmdb_csv`)

Maintained hostname-pattern to owner/platform-team/criticality mapping (fallback for A04/D06).

- Vendor: internal · focus areas: vulnerability, incident
- Read scopes: see vendor docs / to confirm
- Write scopes (only for approved actions): -
- To confirm with the client: -
- Configuration:
  - `path`: CSV path: hostname,owner,platform_team,environment,criticality,serial_number

### CrowdStrike Falcon (`crowdstrike`)

Detections, host inventory, Spotlight vulnerabilities, IOC lookup, containment and RTR collection.

- Vendor: CrowdStrike · focus areas: incident, vulnerability, phishing
- Read scopes: Alerts:read, Hosts:read, Spotlight vulnerabilities:read, IOCs:read
- Write scopes (only for approved actions): Hosts:write, Real time response:write
- To confirm with the client: API client scopes; Spotlight/Exposure licence; RTR response policy
- Configuration:
  - `base_url` (optional): API base (e.g. https://api.eu-1.crowdstrike.com)
  - `client_id` (secret): OAuth2 API client id
  - `client_secret` (secret): OAuth2 API client secret
  - `user_domain` (optional): Domain appended to bare user names to form a UPN

### Microsoft Defender for Endpoint (`defender_endpoint`)

Alerts, device inventory, TVM vulnerabilities, advanced hunting, isolation, scans, custom indicators.

- Vendor: Microsoft · focus areas: incident, vulnerability, phishing
- Read scopes: Alert.Read.All, Machine.Read.All, Vulnerability.Read.All, AdvancedQuery.Read.All, Ti.Read.All
- Write scopes (only for approved actions): Machine.Isolate, Machine.Scan, Machine.CollectForensics, Ti.ReadWrite.All
- To confirm with the client: Licence tier (P2 for advanced hunting/TVM); app permissions; hunting quota
- Configuration:
  - `tenant_id`: Entra tenant id
  - `client_id` (secret): App registration (client) id
  - `client_secret` (secret) (optional): App registration secret (or use client_certificate)
  - `client_certificate` (secret) (optional): App registration certificate: one PEM with the private key and the certificate (recommended over a secret; mount it with <CONNECTOR>_CLIENT_CERTIFICATE_FILE)
  - `user_domain` (optional): UPN suffix for alert users
  - `mde_base` (optional): API base (regional endpoints)

### Microsoft Defender for Office 365 (`defender_office365`)

User-reported mail, email alerts, message trace & campaign hunting, click telemetry, remediation.

- Vendor: Microsoft · focus areas: phishing, incident
- Read scopes: Mail.Read (reporting mailbox, app-access-policy scoped), SecurityAlert.Read.All, ThreatHunting.Read.All
- Write scopes (only for approved actions): SecurityAnalyzedMessage.ReadWrite.All, Mail.ReadWrite (scoped), Mail.Send (SOC mailbox), Exchange.ManageAsApp (tenant allow/block list)
- To confirm with the client: Licence tier for advanced hunting and Safe Links click telemetry; Graph app permissions; Exchange app-access policy scoping the SOC mailbox
- Configuration:
  - `tenant_id`: Entra tenant id
  - `client_id` (secret): App registration (client) id
  - `client_secret` (secret) (optional): App registration secret (or use client_certificate)
  - `client_certificate` (secret) (optional): App registration certificate: one PEM with the private key and the certificate (recommended over a secret; mount it with <CONNECTOR>_CLIENT_CERTIFICATE_FILE)
  - `reporting_mailbox`: Mailbox receiving user-reported messages / SOC mailbox
  - `graph_base` (optional): Microsoft Graph base (national clouds only)

### Delinea Privilege Manager (`delinea_privilege_manager`)

Elevation and application-control events.

- Vendor: Delinea · focus areas: incident
- Read scopes: see vendor docs / to confirm
- Write scopes (only for approved actions): -
- To confirm with the client: API access approval and available event granularity
- Configuration:
  - `base_url`: Privilege Manager URL
  - `client_id` (secret): API client id
  - `client_secret` (secret): API client secret
  - `user_domain` (optional): UPN suffix
  - `events_path` (optional): Elevation events endpoint (default /Tms/api/v1/events/elevation)

### Delinea Secret Server (`delinea_secret_server`)

Secret access audit, privileged sessions, standing privilege; credential rotation.

- Vendor: Delinea · focus areas: incident
- Read scopes: View Secret Audit, View Launched Sessions
- Write scopes (only for approved actions): Change Password Now on target secrets
- To confirm with the client: API access approval - privileged access data needs extra governance
- Configuration:
  - `base_url`: Secret Server URL
  - `username` (secret): API user
  - `password` (secret): API user password
  - `user_domain` (optional): UPN suffix
  - `audit_path` (optional): Secret audit endpoint (default /api/v1/secret-audits)
  - `sessions_path` (optional): Launched sessions endpoint (default /api/v1/launched-sessions)
  - `sync_from` (optional): First sync starts here (ISO date; default: everything)

### Microsoft Entra ID (`entra`)

Users, sign-ins, risky users and detections, directory and Azure roles, MFA, inbox rules; session revoke and account control.

- Vendor: Microsoft · focus areas: incident, phishing
- Read scopes: User.Read.All, AuditLog.Read.All, IdentityRiskyUser.Read.All, IdentityRiskEvent.Read.All, RoleManagement.Read.Directory, UserAuthenticationMethod.Read.All, MailboxSettings.Read
- Write scopes (only for approved actions): User.RevokeSessions.All, User.EnableDisableAccount.All, IdentityRiskyUser.ReadWrite.All, User-PasswordProfile.ReadWrite.All
- To confirm with the client: Entra ID P2 for Identity Protection risk data; write permissions for response actions; the Reader role on the Azure subscriptions (or a management group) for Azure role assignments
- Configuration:
  - `tenant_id`: Entra tenant id
  - `client_id` (secret): App registration (client) id
  - `client_secret` (secret) (optional): App registration secret (or use client_certificate)
  - `client_certificate` (secret) (optional): App registration certificate: one PEM with the private key and the certificate (recommended over a secret; mount it with <CONNECTOR>_CLIENT_CERTIFICATE_FILE)
  - `azure_subscriptions` (optional): Azure subscription ids to read role assignments from (comma-separated; empty = every subscription the app can read)
  - `graph_base` (optional): Microsoft Graph base (national clouds only)
  - `arm_base` (optional): Azure Resource Manager base (national clouds only)

### FIRST EPSS (`epss`)

Exploit Prediction Scoring System probabilities per CVE.

- Vendor: FIRST · focus areas: vulnerability
- Read scopes: see vendor docs / to confirm
- Write scopes (only for approved actions): -
- To confirm with the client: -
- Configuration:
  - none

### Generic SIEM/SOAR webhook (`generic_siem`)

Normalises alerts pushed to /api/v1/ingest/alerts from any SIEM/SOAR.

- Vendor: any · focus areas: incident
- Read scopes: see vendor docs / to confirm
- Write scopes (only for approved actions): -
- To confirm with the client: -
- Configuration:
  - `field_map` (optional): Mapping of platform fields to payload keys

### Jira (ITSM) (`jira`)

Remediation tickets as Jira issues with comments/status sync.

- Vendor: Atlassian · focus areas: vulnerability, incident
- Read scopes: Browse projects
- Write scopes (only for approved actions): Create issues, Add comments, Transition issues
- To confirm with the client: Only if the client uses Jira (Q03)
- Configuration:
  - `base_url`: https://<site>.atlassian.net
  - `email`: Integration user email
  - `api_token` (secret): API token
  - `project_key` (optional): Project key
  - `issue_type` (optional): Issue type for new tickets (default Task)

### NIST NVD (`nvd`)

CVE metadata (CVSS, CWE, references) from the NVD CVE API 2.0.

- Vendor: NIST · focus areas: vulnerability
- Read scopes: see vendor docs / to confirm
- Write scopes (only for approved actions): -
- To confirm with the client: -
- Configuration:
  - `api_key` (secret) (optional): Optional NVD API key (raises rate limit)
  - `since` (optional): Read CVEs modified since this ISO time (default: full catalogue pages)

### Rapid7 InsightVM / Nexpose (`rapid7`)

Asset inventory and vulnerability findings from the Security Console API (or CSV export fallback).

- Vendor: Rapid7 · focus areas: vulnerability, incident
- Read scopes: Security Console: read-only user / API key
- Write scopes (only for approved actions): -
- To confirm with the client: Authoritative product/version; live API availability
- Configuration:
  - `console_url`: Security Console URL, e.g. https://ivm.example.local:3780
  - `username` (secret): Read-only API user
  - `password` (secret): API user password
  - `verify_tls` (optional): Verify console TLS certificate
  - `export_csv` (optional): Fallback: path to a findings CSV export (legacy Nexpose)

### Microsoft Sentinel (`sentinel`)

Sentinel incidents (if Sentinel is the client's SIEM).

- Vendor: Microsoft · focus areas: incident
- Read scopes: Microsoft Sentinel Reader on the workspace (Azure RBAC)
- Write scopes (only for approved actions): -
- To confirm with the client: Whether a SIEM exists and which (Q01)
- Configuration:
  - `tenant_id`: Entra tenant id
  - `client_id` (secret): App registration (client) id
  - `client_secret` (secret) (optional): App registration secret (or use client_certificate)
  - `client_certificate` (secret) (optional): App registration certificate: one PEM with the private key and the certificate (recommended over a secret)
  - `subscription_id`: Azure subscription holding the Sentinel workspace
  - `resource_group`: Resource group of the Log Analytics workspace
  - `workspace`: Log Analytics workspace name

### ServiceNow (ITSM + CMDB) (`servicenow`)

Remediation/incident tickets with bidirectional status; CMDB ownership and criticality.

- Vendor: ServiceNow · focus areas: vulnerability, incident
- Read scopes: itil (read the ticket table), cmdb_read (CMDB CI table)
- Write scopes (only for approved actions): itil (create and update tickets, work notes)
- To confirm with the client: Which ITSM system; API access; workflow ownership (Q03)
- Configuration:
  - `instance_url`: https://<instance>.service-now.com
  - `client_id` (secret) (optional): OAuth client id
  - `client_secret` (secret) (optional): OAuth client secret
  - `username` (secret) (optional): Basic-auth integration user
  - `password` (secret) (optional): Basic-auth password
  - `ticket_table` (optional): incident | sn_vul_vulnerable_item | custom
  - `cmdb_table` (optional): CMDB CI table

### Threat intelligence fusion (`threat_intel`)

VirusTotal, AbuseIPDB, OTX, URLhaus, ThreatFox, MalwareBazaar, GreyNoise, Shodan - fused verdict.

- Vendor: multiple · focus areas: phishing, incident, vulnerability
- Read scopes: see vendor docs / to confirm
- Write scopes (only for approved actions): -
- To confirm with the client: client-approved intelligence sources and licensing
- Configuration:
  - `virustotal_api_key` (secret) (optional): virustotal API key
  - `abuseipdb_api_key` (secret) (optional): abuseipdb API key
  - `otx_api_key` (secret) (optional): otx API key
  - `greynoise_api_key` (secret) (optional): greynoise API key
  - `shodan_api_key` (secret) (optional): shodan API key
  - `abusech_auth_key` (secret) (optional): abuse.ch Auth-Key (URLhaus/ThreatFox/MalwareBazaar)

### Cisco Umbrella (`umbrella`)

DNS/proxy activity (did the user reach the site?), categories, domain blocking via destination lists.

- Vendor: Cisco · focus areas: phishing, incident
- Read scopes: reports.aggregations:read, reports.customerDNS:read, policies.destinationLists:read
- Write scopes (only for approved actions): policies.destinations:write
- To confirm with the client: API key provisioning; reporting retention window
- Configuration:
  - `api_key` (secret): Umbrella API key
  - `api_secret` (secret): API secret
  - `block_list_id` (optional): Destination list id used for blocks
  - `dns_sync` (optional): DNS activity stored: security (security categories only) or all
  - `sync_from` (optional): First sync starts here (default -1days)

### Wiz (`wiz`)

Cloud inventory, vulnerability findings, internet exposure and misconfiguration issues (GraphQL).

- Vendor: Wiz · focus areas: vulnerability, incident
- Read scopes: read:resources, read:vulnerabilities, read:issues
- Write scopes (only for approved actions): -
- To confirm with the client: Service account provisioning; scope of cloud coverage
- Configuration:
  - `api_url`: Tenant API endpoint, e.g. https://api.eu1.app.wiz.io
  - `client_id` (secret): Service account client id
  - `client_secret` (secret): Service account secret
  - `auth_url` (optional): Token URL
  - `lookup_max_pages` (optional): Max GraphQL pages per lookup (default 20)

