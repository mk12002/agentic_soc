# Client deployment guide

How to take the platform from the demo (fixtures, a demo organisation, a demo Azure AI Foundry model) into the
client's own environment: real security tools, the client's identity provider, and the client's in-house LLM platform.

It is written for the engineer doing the deployment. Every setting named here exists in the code; where something
could not be verified without the client's tenants it says so. Related references: `docs/CONNECTORS.md` (generated
connector reference), `docs/OPERATIONS.md` (settings, jobs, monitoring), `docs/SECURITY.md` (threat model),
`docs/RUN_GUIDE.md` (running and troubleshooting).

---

## 0. What changes between the demo and the client environment

| Area | Demo | Client environment | Section |
|---|---|---|---|
| Hosting | laptop, SQLite or local PostgreSQL | container host / VM / Kubernetes, PostgreSQL 16, TLS reverse proxy | 1, 2 |
| Data | `python -m soc_platform demo` loads the Acme sample organisation | **never run `demo`**; data arrives from the client's tools | 2.4 |
| Organisation facts | `acme-demo.com`, demo suppliers | the client's mail domains, supplier list, sanctioned SaaS list | 2.3 |
| Sign-in | dev tokens (`SOC_AUTH_MODE=dev`) | Entra ID single sign-on with app roles and MFA (`SOC_AUTH_MODE=entra`) | 3 |
| Connectors | `mode: fake` (vendor-shaped fixtures) | `mode: live` per tool, credentials from a vault | 4 |
| LLM | the developer's Azure AI Foundry deployment | the client's in-house LLM platform (Claude / Gemini / OpenAI models behind it) | 5 |
| Actions | recommended, approved in the demo | recommended only (L2) until the client's change board promotes them | 6 |
| Secrets | `.env` on a laptop | Key Vault (or similar) mounted as files: `<NAME>_FILE` | 2.2 |

**Code changes needed:** none for a standard deployment. Everything below is configuration. The exceptions (an LLM
gateway that needs OAuth tokens instead of a static key, or a tool API the client runs in a non-standard way) are
called out where they apply, with the file to change.

**Deployment order** (each step is usable on its own):

1. Platform up on PostgreSQL with Entra sign-in, no connectors live (section 1-3).
2. Read-only connectors, one at a time: identity and EDR first, then e-mail, then vulnerability, then the rest (4).
3. The in-house LLM (5). The platform is fully functional before this; the LLM only adds narrative.
4. Write permissions and action rollout, per action type, through the autonomy policy (6).

---

## 1. Target architecture

```text
                        Analysts' browsers (Entra SSO + MFA)
                                     │ HTTPS
                          ┌──────────▼──────────┐
                          │ TLS reverse proxy /  │  (App Gateway, nginx, IIS ARR...)
                          │ WAF                  │
                          └──────────┬──────────┘
                                     │ HTTP 8080 (private)
             ┌───────────────────────▼───────────────────────┐
             │ platform-api   (python -m soc_platform serve)  │──┐
             │ platform-scheduler (python -m soc_platform     │  │ outbound HTTPS only:
             │                     scheduler)                  │  │  - vendor APIs (section 4)
             └───────────────┬────────────────────────────────┘  │  - client LLM gateway (section 5)
                             │                                    │  - Entra ID (login.microsoftonline.com)
                    ┌────────▼────────┐                          │
                    │ PostgreSQL 16    │                          │
                    └─────────────────┘                          │
             Secrets: Key Vault → files mounted at /run/secrets ──┘
```

- **Images:** `deploy/Dockerfile` (multi-stage, non-root user `soc`, port 8080). Build with the phishing ML engine:
  `docker build --build-arg WITH_PHISHING_ENGINE=true -f deploy/Dockerfile -t soc-platform:<tag> .`
- **Compose reference:** `deploy/docker-compose.yml` (`postgres`, `platform-api`, `platform-scheduler`; the
  `engine` profile services are the ML engine's own legacy services and are **not** needed - the engine runs inside
  the platform process).
- **Windows hosts** are supported (the platform is developed and fully tested on Windows 11 with SQLite and
  PostgreSQL); containers on Linux are the recommended production shape.
- **High availability and scaling:** the API is stateless (any number of replicas behind the proxy) and schedulers
  take renewed database leases, so several are safe and a dead one's job is taken over within two minutes. Set
  `SOC_BLOB_STORE=database` so stored e-mails and reports are in PostgreSQL, readable by every replica. The
  Kubernetes package (`deploy/kubernetes`, Azure and on-prem overlays), the reference topologies, the connection budget,
  recovery targets and the failover drill are in `docs/HIGH_AVAILABILITY.md`. The image runs `SOC_API_WORKERS=4` processes; give one per CPU core and keep
  `workers x (SOC_DB_POOL_SIZE + SOC_DB_MAX_OVERFLOW)` under PostgreSQL's `max_connections`. Measured on a laptop
  (`docs/OPERATIONS.md` - Server and database under load, Connector sync and volume): four processes served 100
  concurrent analysts at 150 requests/s with no error; sync stores about 146 records/s on SQLite and about 75 on a
  local PostgreSQL, flat as the estate grows. The client's own volume is measured during deployment
  (`scripts/measure_scale.py`, `scripts/load_test.py` against the target environment).
- **Inbound:** only the reverse proxy reaches port 8080. Nothing in the platform accepts connections from the tools
  except the optional SIEM push endpoint (`POST /api/v1/ingest/alerts`, authenticated with an API key).
- **Outbound:** HTTPS to the hosts listed per connector in section 4, the LLM gateway, and Entra ID. Nothing ever
  fetches URLs found in e-mail content (no SSRF surface), and the ML engine makes no outbound calls at all.
- **WAF and DDoS protection:** put the console behind the client's web application firewall / reverse proxy (Azure
  Application Gateway WAF, Front Door or the on-premises equivalent) with TLS; the platform adds its own rate limit,
  request-size cap and security headers. Keep the console off the internet where possible (internal network / VPN).
- **Logs to the SIEM:** collect every container's stdout (`SOC_LOG_FORMAT=json`) and the audit export into the
  client's SIEM (for example Microsoft Sentinel through its log agent), so the SOC monitors the platform itself.
- **Encryption at rest:** files the platform writes (raw payloads, reported e-mail, reports) are encrypted with
  `SOC_DATA_KEY`; the database is protected by the managed PostgreSQL service's encryption or encrypted volumes
  (Azure Disk Encryption / BitLocker / LUKS) - confirm one is on before go-live.

---

## 2. Install and base configuration

### 2.1 Database

PostgreSQL 16, a dedicated database and **two** logins - one that owns the schema, one the platform runs as:

```sql
CREATE ROLE soc LOGIN PASSWORD '<from vault>';            -- schema owner: used only by init-db
CREATE ROLE soc_app LOGIN PASSWORD '<from vault>';        -- the running platform
CREATE DATABASE soc_platform OWNER soc;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT CONNECT ON DATABASE soc_platform TO soc_app;
```

Both URLs verify the server's certificate: `?sslmode=verify-full&sslrootcert=system` for a managed server with a
public CA chain (Azure Flexible Server), or `sslrootcert=<path to the CA>` for your own. Production refuses any other
`sslmode` (libpq's default `prefer` can be downgraded or intercepted). The URLs carry passwords, so keep them in the
vault and mount them: `SOC_DATABASE_URL_FILE=/run/secrets/db_url` (runtime) for the platform, and the owner's URL only
for the migration step:

```bash
SOC_DATABASE_URL_FILE=/run/secrets/db_owner_url SOC_DB_RUNTIME_ROLE=soc_app python -m soc_platform init-db
# creates / extends the tables, then grants soc_app read / write on every table, SELECT + INSERT only on audit_log
# (a database trigger refuses UPDATE / DELETE / TRUNCATE on it too) and no schema rights
```

The platform's processes then run with `SOC_SCHEMA_MANAGE=0` (they only check the schema exists). Allow-list the
`pg_trgm` extension (Azure: server parameter `azure.extensions`; deploy/azure/main.bicep does): it backs the search
box's indexes, and without it search scans tables.

Upgrades: `init-db` (the migration step, run before the new version's pods start) creates new tables, adds new
*nullable* columns and widens text columns on existing databases. There is no migration framework, so a release that adds a required column, renames or drops one will
say so and ship a scripted migration.

### 2.2 Secrets

Every secret setting can be supplied as `<NAME>_FILE` pointing at a mounted file (Key Vault CSI driver, Docker/K8s
secrets). Connector settings in `config/connectors.yaml` use `${ENV_NAME}`, and `ENV_NAME_FILE` works for those too.
Never write a literal secret into `connectors.yaml`.

Generate the platform's own keys once:

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"   # SOC_DATA_KEY
python -c "import secrets; print(secrets.token_urlsafe(48))"                                # break-glass secret
python -c "import hashlib,sys; print(hashlib.sha256(sys.argv[1].encode()).hexdigest())" '<break-glass secret>'
```

Store the break-glass secret sealed (two-person), and give the platform only its SHA-256 (`SOC_BREAKGLASS_SHA256`).

On Azure, keep every secret in Key Vault and mount it as a file (the overlay does this; nothing is synced into a
Kubernetes Secret, so no secret value sits in etcd). Connector secrets the same way: add the object to
`keyvault-secrets.yaml` and set `<ENV_NAME>_FILE=/mnt/secrets/<object>` in the settings ConfigMap.

### 2.3 Production settings

The minimum production environment (all names are real settings; full list in `.env.example` and
`docs/OPERATIONS.md`):

```bash
SOC_ENVIRONMENT=prod                      # refuses dev tokens and time-travel test settings; requires SOC_DATA_KEY
SOC_DATABASE_URL_FILE=/run/secrets/db_url  # the runtime role, ?sslmode=verify-full&sslrootcert=...
SOC_SCHEMA_MANAGE=0                       # init-db (schema owner) changes the schema; the platform never does
SOC_DATA_KEY_FILE=/run/secrets/data_key   # encryption at rest for raw payloads and reported e-mails
SOC_ORG_DOMAINS=client.com,client.co.in,client.onmicrosoft.com   # every internal mail domain incl. the tenant's
SOC_CONNECTOR_MODE=live                   # default mode; each connector can still override in connectors.yaml
SOC_CONNECTORS_CONFIG=/app/config/connectors.yaml
SOC_PUBLIC_URL=https://soc.client.com     # links in notifications
SOC_TRUSTED_PROXIES=10.0.0.0/24          # the reverse proxy's address or subnet (X-Forwarded-For is trusted only from it)
SOC_BREAKGLASS_SHA256_FILE=/run/secrets/breakglass_sha256
SOC_BLOB_STORE=database                   # stored e-mails and reports in PostgreSQL (several hosts; HIGH_AVAILABILITY.md)
SOC_RAW_PAYLOAD_DIR=/data/raw             # scratch with the database store; the store itself with SOC_BLOB_STORE=file
SOC_REPORT_OUTPUT_DIR=/data/reports
SSL_CERT_FILE=/etc/ssl/certs/client-ca-bundle.pem   # only if internal consoles or the LLM gateway use a corporate CA
# identity: section 3; connectors: section 4; LLM: section 5
```

Organisation facts to replace (files under `config/`, mounted into the container):

| File / setting | What to put in it |
|---|---|
| `config/suppliers.yaml` (+ `SOC_SUPPLIER_DOMAINS`) | the client's real suppliers and their domains - used to recognise supplier impersonation and look-alike domains |
| `config/sanctioned_services.yaml` | SaaS the client has approved - everything else seen in DNS is reported as shadow IT |
| `config/connectors.yaml` | which tools exist (`enabled`), `mode: live`, and `${ENV}` references (section 4) |
| `SOC_ORG_DOMAINS` | all internal mail domains |

### 2.4 First start

The packaged ways are the Kubernetes overlays (`deploy/kubernetes`, HIGH_AVAILABILITY.md; on Azure the resources come
from `deploy/azure/main.bicep`) and, for one host, `deploy/docker-compose.yml` (production defaults; TLS to
PostgreSQL, the role split, a TLS proxy and nightly dumps as profiles). By hand:

```bash
SOC_DATABASE_URL_FILE=/run/secrets/db_owner_url SOC_DB_RUNTIME_ROLE=soc_app python -m soc_platform init-db
python -m soc_platform serve            # API + console + embedded scheduler, or:
SOC_EMBEDDED_SCHEDULER=0 python -m soc_platform serve   &   python -m soc_platform scheduler
```

- **Do not run `demo` or `reset-demo`** in the client environment (`reset-demo` refuses in prod anyway).
- Check `GET /health` signed in (database, audit chain, kill switch; anonymous callers only get "ok") and
  `GET /api/v1/admin/self-check` (cross-surface consistency proof) after the first syncs.
- The phishing ML engine is on automatically when the image was built with it (`SOC_PHISHING_ENGINE=auto`); it runs
  fully offline. `SOC_PHISHING_ENGINE=1` makes it mandatory (start-up fails if missing), `0` turns it off.

---

## 3. Identity and sign-in (Entra ID)

The API validates Entra ID v2.0 access tokens (RS256, tenant JWKS, audience, issuer, expiry); the console signs users
in with the Entra authorization-code flow with PKCE. Roles come from **app roles** on the platform's app registration.

> Verification status: the token validation is covered by tests; the console's sign-in flow is implemented to the
> documented Entra v2.0 SPA flow and unit-tested for its configuration, but it can only be exercised end to end in a
> real tenant. Test it on day one (3.4).

### 3.1 App registration (one registration for API and console)

In the client's Entra admin centre → App registrations → New registration:

1. **Name:** `SOC Platform`. Supported account types: this organisation only.
2. **Expose an API:** set the Application ID URI to `api://<application-id>` (the default). Add a scope, e.g.
   `access_as_user` (admins and users can consent).
3. **Manifest:** set `"requestedAccessTokenVersion": 2` (older portals: `accessTokenAcceptedVersion`). The platform
   accepts v2.0 tokens (issuer `https://login.microsoftonline.com/<tenant>/v2.0`) and the tenant's v1 tokens
   (`https://sts.windows.net/<tenant>/`), with a minute of clock-skew leeway; any other tenant is refused.
4. **Authentication → Add a platform → Single-page application:** redirect URI `https://soc.client.com/` (the
   console's origin followed by `/`). Also add it as the front-channel logout URL if desired.
5. **API permissions:** add `SOC Platform → access_as_user` (delegated) and grant admin consent.
6. **App roles** (Allowed member types: **Users/Groups** only - an application holding an app role is treated as a
   service account by the platform anyway: a token without a delegated scope can never approve, change policy or
   manage access):

| App role value | Platform role | Scope |
|---|---|---|
| `SOC.Analyst` | analyst - investigate, request actions | all domains |
| `SOC.Lead` | lead - approve actions, approve policy | all domains |
| `SOC.Admin` | admin - access management | all domains |
| `SOC.Automation_Admin` | automation_admin - connectors, propose policy (cannot approve) | all domains |
| `SOC.Auditor` | auditor - read-only incl. audit log and evidence export | all domains |
| `SOC.Analyst.Phishing`, `SOC.Lead.Vulnerability`, ... | the same role limited to one domain | `Phishing` / `Incident` / `Vulnerability` |

7. **Enterprise applications → SOC Platform → Users and groups:** assign security groups to the roles
   (e.g. `SG-SOC-L1` → `SOC.Analyst`, `SG-SOC-Leads` → `SOC.Lead`). Set "Assignment required" = Yes.
8. **Conditional Access:** require MFA for the app. For step-up on sensitive operations (approvals, policy, kill
   switch, access management) the platform checks the token's `amr` for `mfa`, or a Conditional Access authentication
   context: create one (e.g. `c1`) and set `SOC_MFA_AUTH_CONTEXT=c1`.

### 3.2 Settings

```bash
SOC_AUTH_MODE=entra
SOC_ENTRA_TENANT_ID=<tenant id>
SOC_ENTRA_AUDIENCE=api://<application id>
# only if the console has its OWN registration instead of sharing the API's:
# SOC_ENTRA_SPA_CLIENT_ID=<console app id>
# SOC_ENTRA_SCOPE=api://<api app id>/access_as_user      (default: <audience>/.default)
SOC_REQUIRE_MFA=1                          # default in prod
```

The console fetches `GET /api/v1/auth/config` (tenant, client id, scope - public values), sends the user to
`login.microsoftonline.com`, redeems the code with PKCE, and uses the access token for the API. When the token
expires the user presses *Sign in with Microsoft* again (Entra keeps the session, so it is one click). *Sign out*
ends the Entra session too.

### 3.3 Service accounts and break-glass

- **API keys** (Access screen → API keys): for the Prometheus scraper (auditor, all domains), a SIEM pushing alerts
  (analyst, incident domain), automation. Keys are hashed, expire within 365 days, and can never approve actions,
  change policy or manage access.
- **Break-glass:** `POST /api/v1/auth/break-glass` with the header `X-Break-Glass: <secret>`, verified against
  `SOC_BREAKGLASS_SHA256`, returns a 15-minute Bearer token (the secret is accepted nowhere else). Every use is
  audited and raises a critical finding; failed guesses are throttled per address. Test it once, then re-seal.
- **Privileged platform grants** (lead, admin, automation_admin on the Access screen) need a second administrator's
  approval and expire within 90 days. Prefer Entra app-role assignments through PIM for standing access.

### 3.4 Day-one sign-in test

1. Open `https://soc.client.com/` → *Sign in with Microsoft* → MFA prompt → Overview loads.
2. `GET /api/v1/me` (browser dev tools, or the Access screen) shows the expected roles and `role_scopes`.
3. A user with only `SOC.Analyst.Phishing` sees phishing only; incident case URLs answer 404.
4. `GET /api/v1/dev/token` answers 404.
5. Failures: `401` from every call = audience/issuer mismatch (check `requestedAccessTokenVersion: 2` and
   `SOC_ENTRA_AUDIENCE`); roles empty = users not assigned to app roles; sign-in page error `AADSTS50011` = redirect
   URI not registered exactly as the console origin + `/`.

---

## 4. Connecting the tools

### 4.1 The procedure for every tool

1. **Create a dedicated identity** in the tool (service principal / API client / integration user) with the **read**
   permissions listed below. Add write permissions only for action types the client has approved (section 6).
2. **Store the credentials** in the vault; expose them to the container as the environment variables (or `_FILE`
   mounts) named in the tool's section - *Integrations → Configure* shows the exact names and whether each is set.
   Secrets are never typed into the console or stored by the platform.
3. **Allow outbound HTTPS** from the platform to the tool's hosts.
4. **Configure and promote it in the console** (*Integrations → Configure*): enter the non-secret settings (base URL,
   tenant id, mailbox...), choose the stage **Recording** (live reads, responses saved as sanitised fixtures, no
   actions) or **Read-only**, and propose. The **preflight** runs on the proposal - sign-in, every stream and the
   permission it needs, parsing, data freshness, clock, expected volume - and refuses it with the fix if anything is
   wrong. A lead approves (never the proposer); it applies within seconds, no restart. Tools the client does not own:
   switch them off (they disappear from every workflow and dashboard). The same can be done in
   `config/connectors.yaml` (`stage: read`) for the deployment baseline; `python -m soc_platform config check` and
   `python -m soc_platform preflight <name>` give the same checks from a shell.
5. **Check** the Integrations screen: records ingested, freshness per stream, and reconciliation against the tool's
   own total where the tool reports one; then the resolution queue (Overview → *Awaiting resolution*, or
   `GET /api/v1/resolution/unresolved`) for identity/asset matches needing review.
6. Leave it running on the scheduler for a day before enabling the next tool, so problems have one cause.
7. **Promote** when the client approves its actions: **Recommend** (every action offered, a person approves each -
   never above L2 whatever the policy says), later **Automate** (the autonomy policy decides, section 6). A tool that
   misbehaves can be **paused** at once from the same screen (audited; switching it back on is approved).

All connectors share: a per-connector token-bucket rate limit (never exceeds the vendor's budget, even with parallel
lookups), retries with back-off that honour `Retry-After` (seconds or a date, capped at 120 s), a refused token (401)
renewed once and the call repeated, a missing permission (403) reported at once - not retried - with the scopes to
grant (the preflight names the stream, the permission and the scopes), an HTML page answering instead of the API (a proxy
or login page) reported as such, and a circuit that marks the connector *error* on the Integrations screen instead of
failing workflows. A tool being down makes the affected evidence "unavailable" in the case; it never changes a
verdict silently.

**Resuming.** Event streams (sign-ins, audits, risk detections, alerts, reported mail, DNS, Sentinel incidents) resume
from the newest change time seen, minus a 30-minute overlap for logs indexed late (`SOC_WATERMARK_OVERLAP_MINUTES`):
a sync reads what is new, not 30 days again. Inventories (users, machines, assets, CMDB, findings) are read in full
each sync. A continuation token is never kept between syncs (Graph and Jira tokens expire). Each page is committed as
it is stored, so the first backfill of a large tenant can be interrupted and resumes after its last page; a backlog
beyond `SOC_SYNC_MAX_PAGES` (1,000 pages per stream per sync) continues on the next sync.

Data formats: each connector parses the vendor's documented response shapes. They were audited field by field
against the vendors' public documentation and public reference integrations, and every connector passes a
conformance suite (`soc_platform/tests/test_connector_conformance.py`): reading across pages in its vendor's paging
style, resuming correctly, throttling, a refused token, a missing permission, and every field of every record missing
or null. What remains is running each connector against the client's real tenant - step 5 above.

**Record the first live responses.** Put each tool in the **Recording** stage for its first syncs (or set
`SOC_RECORD_FIXTURES_DIR` for every live tool; `docs/OPERATIONS.md` - Recording): every live response is written,
sanitised, as a test fixture. The pseudonym key comes from `SOC_RECORD_SALT`, else from `SOC_DATA_KEY`. After review of the
files and of `_scan.json` (and the client's approval), the recordings let a connector fix be tested against the
tenant's real shapes, optional fields and oddities without access to the tenant.

### 4.2 Microsoft Entra ID (`entra`)

**Used for:** who a person is (users, department, manager), sign-ins and risk (impossible travel, anonymous IPs,
risky users), directory role and Azure role assignments (privileged accounts), MFA methods, inbox rules; response
actions (revoke sessions, disable account, reset password, confirm compromised).

**Create:** an app registration `SOC Platform - Entra connector` (separate from the sign-in registration), with a
certificate (recommended: the platform signs a short-lived client assertion with it, so no shared secret is sent) or a
secret. Application permissions on Microsoft Graph, admin-consented:

| Read (required) | Write (only for approved actions) |
|---|---|
| `User.Read.All`, `AuditLog.Read.All`, `IdentityRiskyUser.Read.All`, `IdentityRiskEvent.Read.All`, `GroupMember.Read.All`, `RoleManagement.Read.Directory`, `UserAuthenticationMethod.Read.All`, `MailboxSettings.Read` | `User.RevokeSessions.All`, `User.EnableDisableAccount.All`, `IdentityRiskyUser.ReadWrite.All`, `User-PasswordProfile.ReadWrite.All` |

`GroupMember.Read.All` and `RoleManagement.Read.Directory` are both needed: with `User.Read.All` alone Graph returns a
person's groups and directory roles with every name blank, and the privileged-role check would find nothing.

**Accounts with admin roles:** Graph permissions alone do not let an app disable an administrator or reset their
password - Microsoft requires the caller to hold an administrator role at least as privileged as the target's. To
let approved actions reach admin accounts, assign the service principal *Privileged Authentication Administrator*
(or handle admin accounts manually and say so in the runbook); otherwise those actions fail on admin targets with
403 and the failure is recorded on the action.

Azure role assignments: give the same service principal the **Reader** role on the Azure subscriptions (or on a
management group above them).

**Licences:** Entra ID P1 (or P2) to read sign-in logs through Graph; P2 for Identity Protection (risky users / risk
detections). Without P2 those reads are refused: the streams report it, and an identity lookup lists the part as
*unavailable* and still returns everything else.

**Settings:** `ENTRA_TENANT_ID`, `ENTRA_CLIENT_ID`, `ENTRA_CLIENT_CERTIFICATE` (one PEM with the private key and the
certificate, mounted as `ENTRA_CLIENT_CERTIFICATE_FILE`; recommended) or `ENTRA_CLIENT_SECRET`, optional `ENTRA_AZURE_SUBSCRIPTIONS`
(comma-separated ids; empty = every subscription the app can read).

**Egress:** `graph.microsoft.com`, `management.azure.com`, `login.microsoftonline.com`.

**Notes:** sign-ins are read from the v1.0 API (`isInteractive`, `riskEventTypes_v2`, Conditional Access status,
device compliance). If Azure is unreadable the identity data still loads (tested).

**Microsoft's limits the connector keeps to** (per tenant, whatever else the app does): sign-in and audit logs 5
requests per 10 seconds; Identity Protection 1 request per second (its throttling replies carry no `Retry-After`). The
connector paces those two families separately from its overall budget, so a busy investigation queues rather than
being throttled.

**Newly registered devices** come from the directory audit log (*Add registered owner to device*): Graph's per-user
device lists (`registeredDevices`, `ownedDevices`) do not accept application permissions.

### 4.3 Microsoft Defender for Endpoint (`defender_endpoint`)

**Used for:** alerts (with evidence: files, IPs, URLs), device inventory, TVM vulnerabilities, advanced hunting for
lookups; actions: isolate / release, AV scan, collect investigation package, custom indicators (block/unblock).

**Create:** app registration with API permissions on **WindowsDefenderATP** (application):

| Read | Write (only for approved actions) |
|---|---|
| `Alert.Read.All`, `Machine.Read.All`, `Vulnerability.Read.All`, `AdvancedQuery.Read.All`, `Ti.Read.All`; **`Machine.ReadWrite.All`** for "which device had this IP" | `Machine.Isolate`, `Machine.Scan`, `Machine.CollectForensics`, `Ti.ReadWrite.All` |

`Machine.ReadWrite.All` is what Microsoft requires for the *find devices by internal IP* API (it can also edit device
tags). If the client will not grant it, leave it out: that one lookup reports *permission denied* and everything else
works; the IP is still resolved from the other tools.

**Licences:** Defender for Endpoint P2 (advanced hunting, TVM).

**Settings:** `DEFENDER_ENDPOINT_TENANT_ID`, `DEFENDER_ENDPOINT_CLIENT_ID`, `DEFENDER_ENDPOINT_CLIENT_CERTIFICATE`
(recommended) or `DEFENDER_ENDPOINT_CLIENT_SECRET`,
optional `DEFENDER_ENDPOINT_USER_DOMAIN` (UPN suffix for bare account names), optional `DEFENDER_ENDPOINT_MDE_BASE`
for a regional host (`https://eu.api.security.microsoft.com`, `us.`, `uk.`, `au.`; government clouds use their own).

**Egress:** `api.security.microsoft.com` (or the regional host), `login.microsoftonline.com`. The token is issued for
the `https://api.securitycenter.microsoft.com` resource whichever host is called (as Microsoft documents).

**Limits:** 100 calls a minute and 1,500 an hour per API; the connector stays under them.

### 4.4 Microsoft Defender for Office 365 (`defender_office365`)

**Used for:** user-reported messages (the phishing pipeline's input), e-mail alerts, message trace and campaign scope
(advanced hunting over `EmailEvents` / `UrlClickEvents` / `EmailAttachmentInfo`), who clicked, sender history for
the behaviour model; actions: soft/hard delete and restore across mailboxes, block/unblock sender (Tenant
Allow/Block List), tag, reporter feedback e-mail.

**Prerequisite in the Defender portal:** *Settings → Email & collaboration → User reported settings*: send reported
messages to **a reporting mailbox** (e.g. `soc-reports@client.com`). The connector reads that mailbox, resuming
from the newest message it has seen (minus the watermark overlap), so a mailbox that already holds years of reports
is not re-read every run. An outage shows as the `reported_messages` checkpoint's error on Integrations; a message
that cannot be fetched is retried on the next run.

**Create:** app registration; Microsoft Graph application permissions:

| Read | Write (only for approved actions) |
|---|---|
| `Mail.Read` (scoped to the reporting mailbox - see below), `SecurityAlert.Read.All`, `ThreatHunting.Read.All` | `SecurityAnalyzedMessage.ReadWrite.All` (remediation), `Mail.ReadWrite` (scoped; tagging), `Mail.Send` (scoped; reporter feedback), `Exchange.ManageAsApp` on Office 365 Exchange Online + an Exchange role that includes the Tenant Allow/Block List cmdlets (block sender) |

**Scope the mailbox permissions** so the app can read only the reporting mailbox. Microsoft's current method is
**RBAC for Applications** in Exchange Online (it replaces Application Access Policies, which are legacy): a management
scope containing the reporting mailbox, and the roles *Application Mail.Read*, *Application Mail.ReadWrite* and
*Application Mail.Send* assigned to the app's service principal over that scope - then the tenant-wide Graph
`Mail.*` grants can be removed. A tenant still on Application Access Policies can use
`New-ApplicationAccessPolicy -AppId <app id> -PolicyScopeGroupId <group with the reporting mailbox> -AccessRight
RestrictAccess`. Either way, prove that another mailbox is denied before go-live.

**Licences:** Defender for Office 365 Plan 2 for advanced hunting and click telemetry.

**Settings:** `DEFENDER_OFFICE365_TENANT_ID`, `..._CLIENT_ID`, `..._CLIENT_CERTIFICATE` (recommended) or `..._CLIENT_SECRET`,
`DEFENDER_OFFICE365_REPORTING_MAILBOX`.

**Egress:** `graph.microsoft.com`, `outlook.office365.com`, `login.microsoftonline.com`.

**Notes:**
- Remediation uses Graph's `analyzedEmails/remediate`, a **beta** Graph API (Microsoft does not support beta APIs in
  production). It is the only API for the purge; each remediation appears in the Defender portal's Action center. If
  Microsoft changes it, only `_remediate` in `soc_platform/connectors/tools/defender_office365.py` changes.
- **Block sender** adds a Tenant Allow/Block List entry through Exchange Online's admin endpoint
  (`adminapi/beta/<tenant>/InvokeCommand` running `New-TenantAllowBlockListItems`) - the same endpoint the Exchange
  Online PowerShell module uses. Microsoft documents the cmdlet, not this endpoint, and there is no Graph API for the
  list. If the client does not accept that, leave the block-sender action switched off and block senders in the
  portal; nothing else depends on it.

### 4.5 Microsoft Defender for Identity (`defender_identity`)

**Used for:** on-premises Active Directory identity alerts (Graph `security/alerts_v2`, service source
`microsoftDefenderForIdentity`) and domain-controller logon events (`IdentityLogonEvents` through advanced hunting:
success / failure, protocol, source device) as investigation evidence. A person is linked by the on-premises SID,
which the directory maps to the Entra user (`onPremisesSecurityIdentifier`); machine and built-in accounts are never
people. Read-only: containment of an identity goes through Entra ID.

**Create:** app registration; Microsoft Graph application permissions `SecurityAlert.Read.All` and
`ThreatHunting.Read.All` (no write permission).

**Licences:** Defender for Identity, with sensors on the domain controllers.

**Settings:** `DEFENDER_IDENTITY_TENANT_ID`, `DEFENDER_IDENTITY_CLIENT_ID`, `DEFENDER_IDENTITY_CLIENT_CERTIFICATE`
(recommended) or `DEFENDER_IDENTITY_CLIENT_SECRET`, optional `DEFENDER_IDENTITY_USER_DOMAIN`. Connector settings
`lookback_days` (logon events read on the first sync, default 7) and `hunting_page_size` (rows per hunting call,
default 1000) can be set in `config/connectors.yaml`.

**Egress:** `graph.microsoft.com`, `login.microsoftonline.com`.

### 4.6 CrowdStrike Falcon (`crowdstrike`)

**Used for:** alerts, host inventory, Spotlight vulnerabilities, IOC lookups; actions: contain / lift containment,
RTR forensic collection.

**Create:** Falcon console → *Support and resources → API clients and keys* → new client with scopes:

| Read | Write (only for approved actions) |
|---|---|
| Alerts: Read, Hosts: Read, Vulnerabilities: Read (Spotlight), IOC Management: Read | Hosts: Write (containment), Real time response: Read (read-only collection - `ps`, `netstat`, `ls`; the hosts' response policy must also allow RTR) |

RTR commands are asynchronous: the connector queues each one, reads its output back until complete (at most a minute
per command) and closes the session. Verify the RTR scope in the tenant's API client screen: CrowdStrike groups the
read-only commands under *Real time response*; active-responder commands are not used.

**Settings:** `CROWDSTRIKE_CLIENT_ID`, `CROWDSTRIKE_CLIENT_SECRET`, `CROWDSTRIKE_BASE_URL` = the client's cloud
(`https://api.crowdstrike.com` US-1, `https://api.us-2.crowdstrike.com`, `https://api.eu-1.crowdstrike.com`,
`https://api.laggar.gcw.crowdstrike.com` US-GOV-1), optional `CROWDSTRIKE_USER_DOMAIN`. Use the client's own cloud's URL (the connector does not follow redirects to
another cloud); a wrong one fails preflight's sign-in check.

**Limits:** the alert query API refuses an offset past 10,000 - the connector restarts from its watermark instead; host
inventory uses the scroll API, which has no such limit.

**Egress:** the base URL host.

**Licences:** Spotlight (Falcon Exposure Management) for vulnerabilities.

### 4.7 Rapid7 InsightVM / Nexpose (`rapid7`)

**Used for:** asset inventory and vulnerability findings (with fix text), CVE-to-asset lookups, fix validation, and
the console's vulnerability exceptions (state, expiry, reason - shown on the matching finding as in force or
expired; never used to close or suppress it: an exception the platform honours is approved in the platform).

**Create:** a Security Console user with a read-only role that can view site and asset-group data (a custom role
with *View Site Asset Data* and *View Group Asset Data* is enough), plus the right to view vulnerability exceptions
(confirm the role permission for the console's version; without it the exceptions stream reports a missing
permission and everything else keeps working). The API is the console's own v3 API (basic
authentication).

**Settings:** `RAPID7_CONSOLE_URL` (e.g. `https://ivm.client.local:3780`), `RAPID7_USERNAME`, `RAPID7_PASSWORD`,
`RAPID7_VERIFY_TLS` (`true` by default; the console's certificate is often internally issued - prefer adding the
corporate CA via `SSL_CERT_FILE` over setting `false`).

**Fallback:** `RAPID7_EXPORT_CSV=/data/rapid7_findings.csv` ingests a scheduled CSV export instead of the API
(columns `asset_id, hostname, ip, os, vuln_id, cve, title, cvss, severity, status, first_found`).

**Egress:** the console host and port (usually on-premises).

**Notes:** the findings stream reads each asset's vulnerabilities (one call per asset) and each vulnerability
definition once (cached) plus its solution text. On a console with tens of thousands of assets a full sync takes
hours: run the first one outside office hours, and size `SOC_JOB_VM_SECONDS` above the measured sync time (preflight
shows the volume). If that is too slow, use the CSV export fallback below.

**Only the on-premises console's v3 API is supported.** A client on the cloud-only Insight platform API (v4,
`<region>.api.insight.rapid7.com`, `X-Api-Key`) needs a small connector change - confirm which one the client runs.

### 4.8 Wiz (`wiz`)

**Used for:** cloud inventory, vulnerability findings with internet exposure, misconfiguration issues (which share
the vulnerability lifecycle).

**Create:** Wiz → *Settings → Service Accounts* → *Custom Integration (GraphQL API)* with scopes `read:resources`,
`read:vulnerabilities`, `read:issues`. Note the **API endpoint URL** from *User settings → Tenant info*.

**Settings:** `WIZ_API_URL` (e.g. `https://api.eu1.app.wiz.io`), `WIZ_CLIENT_ID`, `WIZ_CLIENT_SECRET`, optional
`WIZ_AUTH_URL` (default `https://auth.app.wiz.io/oauth/token`; tenants on another identity endpoint use theirs),
optional `WIZ_LOOKUP_MAX_PAGES`.

**Egress:** the API host, the auth host.

**Notes:** the connector's GraphQL queries (`cloudResources`, `vulnerabilityFindings`, `issuesV2`) are checked against
the tenant by preflight: a field Wiz has renamed or retired fails preflight with Wiz's own error, before go-live. Pages
are 500 rows (Wiz's maximum).

### 4.9 Avanan / Check Point Harmony Email & Collaboration (`avanan`)

**Used for:** Avanan's security events and per-message verdicts (reconciled with Defender's), quarantine / restore.

**Create:** Check Point Infinity Portal → *Global settings → API Keys* → new key for the **Email & Collaboration**
service; a read-only role for ingestion, a read-write role only if quarantine/restore actions are approved. Note the
region-specific gateway URL shown with the key.

**Settings:** `AVANAN_API_URL` (the regional gateway, e.g. `https://cloudinfra-gw.portal.checkpoint.com`),
`AVANAN_CLIENT_ID`, `AVANAN_ACCESS_KEY`.

**Egress:** the gateway host. The default gateway is the EU one (`cloudinfra-gw.portal.checkpoint.com`); US tenants
use `cloudinfra-gw-us.portal.checkpoint.com` and other regions their own - take it from the API key screen.

**Notes:** access tokens last about 30 minutes; the connector renews them from their own expiry (and once more on a
401). Security events name the e-mail only by entity id, so the connector reads each event's entity for sender,
recipients, subject and Message-ID. The overall verdict is the worst verdict any Avanan engine gave. If the HEC API is
not licensed, set `AVANAN_FALLBACK=shared_mailbox` and have Avanan's reports delivered to the reporting mailbox.

### 4.10 Cisco Umbrella (`umbrella`)

**Used for:** did the user reach the site (DNS activity), categories, shadow IT; action: block domain via a
destination list.

**Create:** Umbrella dashboard → *Admin → API Keys* → new key with scopes `reports.aggregations:read`,
`reports.customerDNS:read`, `policies.destinationLists:read`, and (for blocking) `policies.destinations:write`.
Create a destination list for SOC blocks attached to the relevant policy; note its id.

**Settings:** `UMBRELLA_API_KEY`, `UMBRELLA_API_SECRET`, `UMBRELLA_BLOCK_LIST_ID`; `dns_sync` (default
`security`).

**Volume:** a tenant makes tens of millions of DNS queries a day. By default only queries in Umbrella's security
categories (malware, phishing, command and control...), allowed or blocked, are stored - the only DNS events any
analysis uses (control gaps, the risk signal). The category ids are read once from `/reports/v2/categories`; if that
fails, blocked queries only. `dns_sync: all` stores every query (small tenants only). "Did anyone reach this site?"
and shadow IT query Umbrella live, whatever the setting.

**Egress:** `api.umbrella.com`.

**Paging:** the Reporting API pages with `offset` / `limit`; Cisco does not publish a maximum offset. The connector
reads security-category queries only by default and resumes from the newest event, so a page window stays small; if
the client stores every query (`dns_sync: all`) on a large tenant, run preflight to see the daily volume first.

### 4.11 Thinkst Canary (`canary`)

**Used for:** Canary and Canarytoken incidents (high-fidelity), device inventory; action: acknowledge.

**Create:** Canary console → *Settings → API* → enable the API, copy the auth token (a read-only token if the
console offers one; acknowledge needs a normal token).

**Settings:** `CANARY_DOMAIN_HASH` (the `<hash>` in `<hash>.canary.tools`), `CANARY_AUTH_TOKEN`, optional
`CANARY_USER_DOMAIN`.

**Egress:** `<hash>.canary.tools`.

### 4.12 Delinea Secret Server (`delinea_secret_server`) and Privilege Manager (`delinea_privilege_manager`)

**Used for:** who opened which privileged secret and session (Secret Server), elevation events (Privilege Manager);
action: rotate a secret.

**Secret Server - create:** an API user (local or AD) with *View Secret Audit* and *View Launched Sessions*; for
rotation, *Change Password Now* on the target secrets only. Authentication is the OAuth2 password grant at
`<base>/oauth2/token`.

**Privilege Manager - create:** an API client (client credentials, `<base>/Tms/oauth2/token`) allowed to read
elevation events.

**Settings:** `DELINEA_SECRET_SERVER_BASE_URL` (e.g. `https://pam.client.local/SecretServer`),
`DELINEA_SECRET_SERVER_USERNAME`, `DELINEA_SECRET_SERVER_PASSWORD`; `DELINEA_PRIVILEGE_MANAGER_BASE_URL`,
`..._CLIENT_ID`, `..._CLIENT_SECRET`; optional `..._USER_DOMAIN`.

**Endpoint paths differ between Delinea versions**, so they are settings: `DELINEA_SECRET_SERVER_AUDIT_PATH`
(default `/api/v1/secret-audits`), `DELINEA_SECRET_SERVER_SESSIONS_PATH` (default `/api/v1/launched-sessions`),
`DELINEA_PRIVILEGE_MANAGER_EVENTS_PATH` (default `/Tms/api/v1/events/elevation`).

> **Must be confirmed on the client's instance before go-live - these are the least certain integrations.**
> - Delinea's public documentation shows secret audits **per secret** (`/api/v1/secrets/{id}/audits`); a tenant-wide
>   secret-audit list at the default path could not be confirmed from it. Check the instance's own REST API reference
>   (*Help → REST API*). If there is no tenant-wide list, the usual route is to run the built-in *Secret Audit* report
>   through the Reports API on a schedule; that needs a small connector change.
> - The rotation call (`POST /api/v1/secrets/{id}/change-password`) must be checked against the same reference; keep
>   the rotate action switched off until it has been tried on a test secret.
> - Privilege Manager documents its API only in each console's Swagger page (*Help → API Reference*, visible to the
>   Privilege Manager Administrators role). Read the elevation-events path and the token path there, and set them.
> Preflight reads each stream - the secret-audit and elevation-event paths - and reports a wrong path (404); the
> launched-sessions path is used only in investigations, so check it once by hand.

**Admin accounts:** optional `DELINEA_SECRET_SERVER_ACCOUNT_OWNERS` - the approved map of admin account to the
person who owns it, as JSON (`{"adm-jane": "jane.doe@client.com"}`). A mapped account's activity is linked to its
owner as well; the admin account stays its own identity. Leave shared accounts out: an owner is never guessed from
the account name.

**Governance:** privileged-access data needs the client's explicit approval (it is flagged "to confirm").

### 4.13 ServiceNow (`servicenow`) - tickets and CMDB

**Used for:** remediation / incident tickets with status sync back, and the CMDB for owner, support group,
criticality and location of each host (drives vulnerability ownership and campaigns).

**Create:** an integration user (web-service access only) with roles `itil` (read/create/update the ticket table)
and `cmdb_read`. OAuth: *System OAuth → Application Registry* → client credentials (the client-credentials grant
must be enabled on the instance - it exists only in recent ServiceNow releases); otherwise basic auth for the
integration user.

**Settings:** `SERVICENOW_INSTANCE_URL`, either `SERVICENOW_CLIENT_ID` + `SERVICENOW_CLIENT_SECRET` or
`SERVICENOW_USERNAME` + `SERVICENOW_PASSWORD`, optional `SERVICENOW_TICKET_TABLE` (`incident` by default,
`sn_vul_vulnerable_item` for Vulnerability Response, or a custom table), optional `SERVICENOW_CMDB_TABLE` (default
`cmdb_ci_computer`).

**Egress:** `<instance>.service-now.com`.

**Notes:** reads use `sysparm_display_value=all`, so codes and UTC timestamps come from the raw values and names from
the display values (display timestamps would be in the integration user's timezone). If the client's CMDB uses other
field names for criticality or environment, map them in `normalize` / `owner_for` in
`soc_platform/connectors/tools/itsm.py`.

### 4.14 Jira (`jira`) - alternative ticketing

Only if the client tickets in Jira instead of ServiceNow (enable one of them). Integration user with *Browse
projects*, *Create issues*, *Add comments*, *Transition issues* on the SOC project; an API token.
Settings: `JIRA_BASE_URL` (`https://<site>.atlassian.net`), `JIRA_EMAIL`, `JIRA_API_TOKEN`, `JIRA_PROJECT_KEY`.
Uses the current `/rest/api/3/search/jql` endpoint (the old `/search` was removed by Atlassian). Atlassian API
tokens now expire (at most a year): note the expiry date and rotate the token before it. Egress: the site host.

### 4.15 Ownership CSV (`cmdb_csv`) - fallback CMDB

If there is no usable CMDB: a maintained CSV `hostname,owner,platform_team,environment,criticality,serial_number`
(hostname may be a pattern), path in `CMDB_CSV_PATH`. Can run alongside ServiceNow as a gap-filler. Save it from
Excel as it comes: UTF-8 (with or without the byte-order mark) or Windows-1252, separated by commas, semicolons, tabs
or pipes; headers in any case or spacing, and the usual aliases (`Host Name`, `Server`, `Owner Email`, `Team`, `Env`,
`Serial`, `Subscription ID`) are recognised. A file with neither a hostname nor a subscription column is reported in
the log and assigns no owners. The file is re-read when it changes; no restart is needed.

### 4.16 Microsoft Sentinel (`sentinel`) and generic SIEM push (`generic_siem`)

**Sentinel (pull):** app registration with **Microsoft Sentinel Reader** on the workspace (Azure RBAC). Settings:
`SENTINEL_TENANT_ID`, `SENTINEL_CLIENT_ID`, `SENTINEL_CLIENT_CERTIFICATE` (recommended) or `SENTINEL_CLIENT_SECRET`, `SENTINEL_SUBSCRIPTION_ID`,
`SENTINEL_RESOURCE_GROUP`, `SENTINEL_WORKSPACE`. Egress: `management.azure.com`. Each incident's entities
(accounts, hosts, IPs, URLs, file hashes) are read with *Incidents - List Entities*, so a Sentinel incident joins the
cases of the hosts and people it names (the same Reader role covers it).

**Defender portal move:** Microsoft retires Sentinel in the Azure portal on 31 March 2027; from then on Sentinel is
used in the Defender portal, where Sentinel and Defender XDR incidents share one incident model. The connector reads
incidents through the Azure SecurityInsights REST API (`api-version 2024-03-01`), which the move does not retire as
far as Microsoft has announced. Confirm with the client whether its workspace is already onboarded to the Defender
portal, and re-run this connector's preflight after the move. (The Defender connectors read only their own service's
Graph alerts, so no incident is read twice.)

**Any other SIEM/SOAR (push):** create an API key (analyst role, incident domain) and have the SIEM POST
`{"alerts": [ ... ]}` to `https://soc.client.com/api/v1/ingest/alerts` with header `X-API-Key`. Replays are
de-duplicated. If its field names differ from the defaults (`id, title, severity, timestamp, host, user, src_ip,
dst_ip, domain, url, sha256, source`), set `GENERIC_SIEM_FIELD_MAP` to a JSON object, e.g.
`{"id": "alert_id", "title": "rule_name", "time": "event_time"}`. Nested payloads are mapped with dotted paths
(Elastic Security: `{"id": "kibana.alert.uuid", "title": "kibana.alert.rule.name", "host": "host.name",
"user": "user.name"}`); `soc_platform/fixtures/generic_siem.json` has worked samples for a flat payload, a Splunk ES
notable and an Elastic Security alert. The response is `{"ingested": n, "rejected": n, "reasons": [...]}`: an alert
without its id is refused with the reason while the rest of the batch lands, so the SIEM should not resend the batch
on a partial rejection (an `ingest.rejected` line is also logged).

### 4.17 Public intelligence (`nvd`, `epss`, `cisa_kev`) and threat-intel fusion (`threat_intel`)

- **NVD / EPSS / CISA KEV:** no account needed; an NVD API key (`NVD_API_KEY`, free from NIST) raises the rate limit
  from 5 to 50 requests per 30 seconds. With `since` set, the NVD connector asks in windows of at most 120 days with
  both `lastModStartDate` and `lastModEndDate` - NVD refuses one without the other or a longer range.
  Egress: `services.nvd.nist.gov`, `api.first.org`, `www.cisa.gov`. Verified live.
- **Threat-intel fusion:** each source is optional and used only when its key is present:
  `THREAT_INTEL_VIRUSTOTAL_API_KEY`, `..._ABUSEIPDB_API_KEY`, `..._OTX_API_KEY`, `..._GREYNOISE_API_KEY`,
  `..._SHODAN_API_KEY`, `..._ABUSECH_AUTH_KEY` (URLhaus, ThreatFox, MalwareBazaar). Egress: `www.virustotal.com`,
  `api.abuseipdb.com`, `otx.alienvault.com`, `urlhaus-api.abuse.ch`, `threatfox-api.abuse.ch`, `mb-api.abuse.ch`,
  `api.greynoise.io`, `api.shodan.io`. The client must approve which sources may receive its indicators and check
  each source's licence for commercial use. Internal indicators are never sent: private / reserved IP addresses (documentation ranges - RFC 5737 - belong to no organisation and may be looked up),
  single-label and private-suffix host names and anything under `SOC_ORG_DOMAINS` read "not checked".

### 4.18 Outbound allow-list (all tools)

| Host | For |
|---|---|
| `login.microsoftonline.com` | Entra sign-in and every Microsoft connector's token |
| `graph.microsoft.com`, `management.azure.com`, `api.security.microsoft.com` (or regional), `outlook.office365.com` | Entra, Azure roles, Sentinel, Defender for Endpoint, Defender for Office 365, Defender for Identity |
| CrowdStrike API host of the client's cloud | CrowdStrike |
| Wiz API and auth hosts | Wiz |
| Check Point regional gateway | Avanan |
| `api.umbrella.com` | Umbrella |
| `<hash>.canary.tools` | Canary |
| `<instance>.service-now.com` / `<site>.atlassian.net` | ticketing |
| internal: Rapid7 console, Delinea servers | vulnerability, PAM |
| `services.nvd.nist.gov`, `api.first.org`, `www.cisa.gov` | public vulnerability intelligence |
| approved threat-intel sources (4.17) | enrichment |
| the client's LLM gateway | narrative (section 5) |
| the client's Teams/Slack webhook hosts | notifications (`SOC_NOTIFY_WEBHOOKS`) |

**Through a forward proxy:** set `HTTPS_PROXY` (and `NO_PROXY` for internal hosts such as the Rapid7 console and the
Delinea servers) in the platform's environment; every connector and token request uses them. **TLS inspection** (the
proxy re-signs HTTPS with the organisation's own root): set `SSL_CERT_FILE` to a PEM bundle that includes that root,
or every call fails. The error then names the cause - `gave up after 5 retries: ... CERTIFICATE_VERIFY_FAILED` -
rather than a bare failure. A proxy or SSO page answering in place of an API is reported as "returned an HTML page
instead of the API's JSON".

---

## 5. Connecting the client's in-house LLM platform

### 5.1 What the LLM does here (and what it never does)

The platform works completely without an LLM. With one, it writes narrative: case summaries, attack-story prose,
report commentary, deep-analysis write-ups, answers in analyst Q&A, and plans reports from a prompt. **It never
produces a figure, verdict, score or decision** - all of those are computed in code and handed to the model as
cited evidence; a numeric-fidelity guardrail drops any sentence whose figures are not in the cited evidence, and
uncited claims are dropped. Switching the model therefore changes wording only: every verdict, score, count and
recommended action is identical with the LLM on, off, or on a different vendor (a test proves on/off identity).

Every prompt passes through the platform's gateway (`soc_platform/llm/gateway.py`): pseudonymisation of internal
identities before the call and restoration after, a monthly token budget, a circuit breaker, bounded timeouts, an
approved-endpoint allow-list, model-version pinning, and a log of every call (redacted prompt, response, tokens,
latency) kept for `SOC_LLM_LOG_RETENTION_DAYS`.

### 5.2 Replacing the demo Azure model

The demo uses the developer's own Azure AI Foundry deployment (`SOC_LLM_PROVIDER=azure_foundry`). In the client
environment:

1. **Remove** every demo LLM value: `SOC_LLM_ENDPOINT`, `SOC_LLM_API_KEY`, `SOC_LLM_DEPLOYMENT*`,
   `SOC_LLM_APPROVED_ENDPOINTS`, `SOC_LLM_MODEL_VERSION`. Nothing of the demo Azure resource may remain in the client
   configuration, and the demo key must never be copied into the client's vault. Rotate the demo key after the
   hand-over if it was ever on a shared machine.
2. **Configure the client's gateway** as below. No code changes are needed when the gateway speaks either of the two
   protocols the platform supports.

### 5.3 Which provider setting to use

The client's platform gives access to Claude, Gemini and OpenAI models. The question is which **API shape** its
backend endpoint exposes:

| The gateway exposes | `SOC_LLM_PROVIDER` | Works for |
|---|---|---|
| OpenAI-style `POST .../v1/chat/completions` (most multi-vendor gateways: LiteLLM, Portkey, Kong AI, Azure APIM AI gateway, custom) | `openai_compatible` | any model behind it - Claude, Gemini and OpenAI models are all selected by model name |
| The Claude Messages API (`POST .../v1/messages`) | `anthropic` | Claude models |
| Azure OpenAI / Azure AI Foundry directly | `azure_foundry` (v1 API) or `azure_openai` | OpenAI models on Azure |
| Only a vendor-native Gemini API (`generateContent`) and nothing else | - (needs a small provider class, 5.7) | Gemini |

**Recommended:** `openai_compatible` against the gateway's OpenAI-compatible endpoint. One configuration reaches all
three vendors, and different features can even use different vendors' models.

### 5.4 Configuration: OpenAI-compatible gateway (recommended)

```bash
SOC_LLM_PROVIDER=openai_compatible
SOC_LLM_ENDPOINT=https://llm-gateway.client.internal/v1        # base URL; /chat/completions is appended
SOC_LLM_API_KEY_FILE=/run/secrets/llm_gateway_key              # the key the gateway issued to this application
SOC_LLM_MODELS=<model names as the gateway names them, comma-separated>   # offered per feature on the AI usage screen
SOC_LLM_DEPLOYMENT=<default model for summaries and reports>
SOC_LLM_DEPLOYMENT_SMALL=<default model for routine narrative>
SOC_LLM_APPROVED_ENDPOINTS=https://llm-gateway.client.internal/v1   # anything else is refused at start-up
SOC_LLM_MODEL_VERSION=<model-version pins, comma-separated>      # optional; a different version is logged as a mismatch
SOC_LLM_MONTHLY_TOKEN_BUDGET=50000000                          # see 5.6

# how the gateway wants to be called (no code changes):
SOC_LLM_AUTH_HEADER=Authorization        # or x-api-key, api-key, Ocp-Apim-Subscription-Key ...
SOC_LLM_AUTH_PREFIX="Bearer "            # "" when the header carries the bare key
SOC_LLM_EXTRA_HEADERS={"x-app-id":"soc-platform","x-cost-centre":"SEC-001"}   # fixed, non-secret headers
SOC_LLM_CA_BUNDLE=/etc/ssl/certs/client-ca.pem                 # when the gateway's certificate is internally issued
SOC_LLM_JSON_MODE=1                      # set 0 if the gateway or a model rejects response_format
```

The platform sends `{"model", "temperature": 0.1, "messages": [system, user], "response_format": {"type":
"json_object"}}` and reads `choices[0].message.content` and `usage.prompt_tokens / completion_tokens`. With
`SOC_LLM_JSON_MODE=0` the `response_format` field is left out and the JSON requirement is written into the system
instruction instead; replies are parsed tolerantly (the first JSON object in the reply) either way.

**Choosing models** (names depend on how the client's gateway exposes them). `SOC_LLM_MODELS` lists the models an
administrator can pick per feature on the AI usage screen (default: gpt-4.1-nano, gpt-4.1-mini, gpt-4.1; more are
added to the list as the client deploys them, `name=id` where the gateway's id differs). The two defaults:

| Default | Used for | Pick |
|---|---|---|
| `SOC_LLM_DEPLOYMENT` | case and incident summaries, attack story, deep analysis, reports | the strongest reasoning model the client allows (a Claude Opus/Sonnet-class, GPT-4.1-class or Gemini Pro-class model) |
| `SOC_LLM_DEPLOYMENT_SMALL` | routine narrative, notifications, short commentary, planners | a fast, cheap model (Claude Haiku-class, GPT mini-class, Gemini Flash-class) |

After go-live, *AI usage -> Models -> Check which models answer* confirms which listed models the endpoint serves.

Requirements for a model to be suitable: reliable JSON output, instruction following for citations
(`[E1]`-style evidence ids), and a context window larger than the biggest prompt measured in
`docs/LLM_TOKENS_AND_COST.md`. Run the checks in 5.8 for each candidate and read a few narratives: a model that
often ignores the citation format loses sentences to the guardrail and gives thinner prose.

### 5.5 Configuration: Claude Messages API through the gateway

```bash
SOC_LLM_PROVIDER=anthropic
SOC_LLM_ENDPOINT=https://llm-gateway.client.internal/anthropic   # base URL the SDK calls /v1/messages on
SOC_LLM_API_KEY_FILE=/run/secrets/llm_gateway_key                # sent as x-api-key by the official SDK
SOC_LLM_DEPLOYMENT=<Claude model id as the gateway names it>
SOC_LLM_DEPLOYMENT_SMALL=<smaller Claude model id>
SOC_LLM_APPROVED_ENDPOINTS=https://llm-gateway.client.internal/anthropic
SOC_LLM_EXTRA_HEADERS={"x-app-id":"soc-platform"}                # optional
SOC_LLM_CA_BUNDLE=/etc/ssl/certs/client-ca.pem                   # optional
SOC_LLM_SERVER_FALLBACK=0     # if the gateway rejects the beta refusal-fallback feature (see below)
```

With the model ids `claude-opus-5` or `claude-fable-5-1` the provider asks the Claude API for a server-side fallback
model if the first declines (a beta feature). A gateway that does not pass beta features through will fail those
calls; `SOC_LLM_SERVER_FALLBACK=0` turns it off (a refusal then simply uses the deterministic text).

### 5.6 Budget, rate and data-handling settings

| Setting | Default | Set it to |
|---|---|---|
| `SOC_LLM_MONTHLY_TOKEN_BUDGET` | 50,000,000 | the starting monthly allocation. After go-live, administrators manage the monthly and daily budgets, per-person limits and each feature's model and answer cap on the **AI usage** screen (no restart; versioned, audited). Enter the client's per-model prices there so cost is shown in its terms. Measured tokens per component: `docs/LLM_TOKENS_AND_COST.md`. |
| `SOC_LLM_MAX_TOKENS_FIELD` | `max_tokens` | `max_completion_tokens` if the gateway or model rejects `max_tokens` (the answer cap the AI usage policy sets) |
| `SOC_LLM_CONCURRENCY` | 4 | at most the gateway's per-application concurrency |
| `SOC_LLM_TIMEOUT_SECONDS` / `SOC_LLM_TIMEOUT_LARGE_SECONDS` / `SOC_LLM_CONNECT_TIMEOUT_SECONDS` | 30 / 120 / 10 | raise the large timeout if the gateway queues requests |
| `SOC_LLM_BREAKER_FAILURES` / `SOC_LLM_BREAKER_SECONDS` | 3 / 60 | how quickly screens stop waiting for a failing gateway |
| `SOC_LLM_REDACT_PII` | on | **keep on**, even for an in-house model: prompts then carry pseudonyms (`USER_1`, `HOST_2` ...) instead of names and addresses, and names are restored in the answer, so narrative quality is unchanged while the gateway's own logs never hold identities. Turn off only with the client's data-protection approval. |
| `SOC_LLM_LOG_RETENTION_DAYS` | 180 | the client's retention policy for AI interaction logs |
| `SOC_EVENT_RETENTION_DAYS` | 400 | how long sign-ins, DNS and other telemetry stay in the context store (events cited by a case or insight are kept); set to the client's security-evidence retention (Q24) |

Being trained on company data does not give the model any of the platform's case data: it only sees the evidence
the platform sends in each prompt. Nothing in the platform fine-tunes or trains a model.

### 5.7 When code changes are needed

| Situation | Change | Where |
|---|---|---|
| The gateway requires an OAuth / Entra ID access token per call instead of a static key | a provider subclass that obtains and caches the token (the connectors' `entra_app_auth` / `OAuth2ClientCredentials` in `soc_platform/connectors/http.py` can be reused) and returns it from `_headers()` | `soc_platform/llm/providers/openai_compatible.py` |
| The gateway speaks neither the OpenAI nor the Claude protocol (e.g. only Gemini `generateContent`, or a proprietary JSON) | a new `Provider` with one method `complete(system, user, *, tier, max_tokens=None, model=None) -> Completion` (`model`: the model the AI usage policy chose), registered in `build_provider` | `soc_platform/llm/providers/<name>.py`, `soc_platform/llm/gateway.py` |
| The gateway returns token usage under other field names | adjust the `usage` parsing in the provider | same file |

Each is a small, isolated change (the existing providers are about 50 lines each); the gateway, guardrails,
redaction and fallbacks stay as they are. Add a test like `test_openai_compatible_provider` in
`soc_platform/tests/test_intelligence.py`.

### 5.8 Verifying the LLM connection

1. `GET /api/v1/llm/status` - provider, models, budget used, per-workflow latency.
2. Live test (sends a few small prompts; costs tokens):
   `SOC_LIVE_LLM=1 python -m pytest soc_platform/tests/test_live_llm.py -q`
3. Full check including model-written report and deep analysis: `python scripts/verify_features.py --llm`
   (reads the `SOC_LLM_*` lines from `.env`).
4. Token measurement for the client's cost model: `python scripts/measure_llm_usage.py`, then update
   `docs/LLM_TOKENS_AND_COST.md`.
5. In the console: the Overview's *Situation brief* is marked *LLM narrative*; a case narrative carries citations;
   the Reports screen names the configured provider; an attack story offers the *Deep analysis* panel.
6. Failure behaviour to confirm once: point the endpoint at a closed port → screens keep working with deterministic
   text, calls are logged with status `error`, and after 3 failures the circuit opens for 60 s (status
   `circuit_open`) so screens stop waiting.

---

## 6. Actions and autonomy rollout

- Every write to a tool is an `ActionRequest` evaluated by the versioned autonomy policy. The default is **L2 -
  recommend**: the platform proposes, a human approves in the console, the connector executes, the result and the
  reverse action are recorded. Actions marked four-eyes in the policy (by default: isolate and release a host, disable an account, reset a password, purge a campaign, rotate a privileged secret, block a domain)
  need two different people - two leads when the platform recommended them, and every action type has a per-request target limit (e.g. campaign purge 200).
- **Grant write permissions per action type only when the client approves that action type.** Without the write
  permission the action is still recommended; execution fails cleanly and is recorded.
- **Per tool, first:** a tool offers actions only from the **Recommend** stage (never above L2 there) and follows the
  policy only in **Automate** (section 4.1, step 7). In Recording and Read-only its actions appear as manual steps.
- **Promotion** (e.g. auto-quarantine of a confirmed phishing campaign at L3) is a policy change: proposed by an
  automation admin, approved by a lead, versioned and audited (*Automation policy* screen). Use the shadow-mode metrics
  (`GET /api/v1/metrics/shadow?domain=...`) - agreement between what the platform recommended and what analysts
  decided - as the evidence for promotion.
- **Kill switch** (*Automation policy* screen → *Engage kill switch*, or `SOC_KILL_SWITCH=true`): stops every autonomous action execution at once (each action then waits for a person's approval; pause a tool to stop its writes entirely), durable
  across replicas. Test it before go-live.

---

## 7. First-sync plan

| Day | Enable | Check |
|---|---|---|
| 1 | Entra | users resolve to people; Access screen roles; sign-in risk visible |
| 2 | Defender for Endpoint and/or CrowdStrike | hosts resolve across both EDRs (one host, two tools); Unresolved queue reviewed |
| 3 | ServiceNow CMDB (or ownership CSV) | owners and criticality on hosts |
| 4 | Defender for Office 365 (reporting mailbox), Avanan | a test report (an internal simulation mail) becomes a case with verdict and scope |
| 5 | Rapid7, Wiz, NVD/EPSS/KEV | one finding per host + CVE across scanners; priorities; campaigns |
| 6 | Umbrella, Canary, Delinea, Sentinel / SIEM push | incident clusters; attack story across tools |
| 7 | LLM (section 5) | narratives with citations; figures unchanged |

After each step: Integrations screen green, reconciliation matches the tool's own totals where available,
`GET /api/v1/admin/self-check` passes, `/health` audit chain `true`.

---

## 8. Production hardening checklist

- [ ] `SOC_ENVIRONMENT=prod`, `SOC_AUTH_MODE=entra`, `SOC_REQUIRE_MFA=1`, `SOC_DEV_JWT_SECRET` unset.
- [ ] `SOC_DATA_KEY` from the vault; rotation = prepend a new key, `python -m soc_platform blobs reencrypt`, remove the old.
- [ ] TLS at the reverse proxy (TLS 1.2+); `SOC_TRUSTED_PROXIES` set to the proxy (address or subnet) only; port 8080
  not reachable otherwise. Internet-facing: WAF in prevention mode with the rate-limit rule (deploy/azure/main.bicep,
  `internetFacing=true`). Internal: the existing gateway's owner grants the AGIC identity Contributor on it.
- [ ] PostgreSQL: `sslmode=verify-full`, the owner / runtime role split (`SOC_DB_RUNTIME_ROLE`, `SOC_SCHEMA_MANAGE=0`),
  `pg_trgm` allowed, backups and a tested restore (`docs/OPERATIONS.md` - Backups).
- [ ] Images: built by the release workflow, deployed **by digest**, signature verified at admission
  (`deploy/kubernetes/policy/verify-images.yaml`: Kyverno; or Azure Policy with Ratify).
- [ ] Network: default-deny policies applied; the database reachable only from the platform's pods (overlay
  `soc-database-egress`); the ingress rule matches the real gateway (Azure: the Application Gateway subnet).
- [ ] Every connector credential in the vault; least privilege as listed; write scopes only for approved actions.
- [ ] Break-glass secret sealed; hash configured; tested once.
- [ ] Outbound allow-list (4.18) enforced at the firewall/proxy.
- [ ] LLM: approved endpoint set, budget set, redaction on, demo keys absent.
- [ ] Monitoring: `/metrics` scraped with an auditor API key (`kubectl apply -k deploy/kubernetes/monitoring`); the
  alert rules routed to on-call; `audit.anchor` log lines kept in write-once retention in the log platform.
- [ ] Logs: stdout of every container collected (`SOC_LOG_FORMAT=json`) into the client's log platform / SIEM;
  alerts on WARNING / ERROR lines, failed jobs and model-call errors (`docs/OPERATIONS.md` - Logs, traces and
  diagnostics). If the reverse proxy sets `X-Request-ID`, the same id appears in its logs and the platform's.
- [ ] Retention periods and legal-hold process agreed with the client.
- [ ] Banned-data check: no demo data loaded (`demo` never run), no tool the client owns left in the Fixtures stage.
- [ ] `python -m soc_platform config check` clean; `python -m soc_platform preflight --all` ready for every tool in use;
  the configuration exported (*Integrations → Export*) and kept with the deployment record.
- [ ] Key suppliers and sanctioned services replaced with the client's lists (*Integrations → Suppliers & sanctioned
  services*, approved by a lead) - the demo lists must not stay in force.
- [ ] Recording off: no tool left in the Recording stage and `SOC_RECORD_FIXTURES_DIR` unset after the first syncs; recordings reviewed (`_scan.json`) and kept
  only where the client approved; the salt not stored with them.
- [ ] Capacity: `SOC_API_WORKERS` one per core; `workers x (SOC_DB_POOL_SIZE + SOC_DB_MAX_OVERFLOW)` below PostgreSQL's
  `max_connections`; `scripts/load_test.py` run against the target environment with the expected number of analysts.
- [ ] `SOC_CONNECTOR_RATE_SHARE` = API workers + 1 (the scheduler service), so together the processes stay within each
  tool's rate budget; statement and idle-transaction timeouts left at their production defaults (300 s / 600 s);
  `SOC_SHUTDOWN_GRACE_SECONDS` below the orchestrator's stop grace period.
- [ ] A restore drill done on the target environment, and `GET /api/v1/audit/verify` clean on the restored copy;
  `python -m soc_platform audit verify --anchor SEQ:HASH` with the latest anchored head from the log platform.
- [ ] Separation of duties: the default policy's four-eyes actions reviewed with the client (isolate / release a host,
  disable an account, reset passwords, campaign purge, rotate a privileged secret, block a domain); at least two
  people hold the lead role, or four-eyes actions cannot be approved.

---

## 9. Still to confirm with the client

| Topic | Needed for |
|---|---|
| Licence tiers: Entra ID P2, Defender for Endpoint P2, Defender for Office 365 P2, CrowdStrike Spotlight | risk data, advanced hunting, TVM, click telemetry, vulnerabilities |
| Avanan HEC API licensing and region | Avanan connector (else shared-mailbox fallback) |
| Delinea versions and API access approval | endpoint paths, privileged-access governance |
| Rapid7 product/version and API access | live API vs CSV export |
| ITSM system (ServiceNow or Jira), ticket table, CMDB field names | ticketing, ownership |
| SIEM (Sentinel or another) | incident ingestion |
| Approved threat-intel sources | enrichment |
| The in-house LLM gateway: protocol, auth method, the model names to offer per feature (`SOC_LLM_MODELS`), concurrency and token allocation, whether it passes `response_format` | section 5 |
| Delinea: the instance's REST API reference (secret-audit and sessions paths, the rotation call) and Privilege Manager's Swagger page (elevation-events and token paths) | 4.12 |
| Whether approved actions may target admin accounts (needs a privileged Entra role on the connector's service principal) | 4.2 |
| Rapid7: on-premises console (v3 API, supported) or the cloud Insight platform API (v4, needs a connector change) | 4.7 |
| Which action types may be executed, and at which autonomy level | section 6 |
