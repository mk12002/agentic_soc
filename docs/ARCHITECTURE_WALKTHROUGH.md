# Architecture walkthrough - what to say for each diagram

A presenter's guide to the two technical diagrams:

- `diagrams/platform-technical-architecture.svg` - the platform as it runs in the client's environment.
- `diagrams/dev-vm-technical-architecture.svg` - the internal VM used to build and demonstrate it.

Each part says what the box is, why it is there, and the security point to make. Likely review questions and their
answers are at the end.

---

## Part 1 - The platform (production, in the client's environment)

### 1.1 The one-minute summary (say this first)

"The platform is an investigation and automation layer that runs **inside the client's own environment**, on top of
the security tools they already own. It reads from those tools through their official APIs, links every record to one
host or one person, and runs three workflows - phishing, incidents, vulnerabilities - plus a correlation layer across
them. It **recommends** actions; a person approves them. An AI model can write explanations, but it never decides
anything. There is exactly one path that can change a security tool, and it is drawn in orange."

Then explain how to read the diagram: three zones - **client services** on the left, **the platform** in the middle,
**what lies outside** on the right - and every arrow starts at the side that opens the connection. Almost every arrow
points outwards from the platform: nothing outside connects in, except the analysts' browsers and an optional SIEM
push.

### 1.2 Left zone - client environment services

These belong to the client; the platform uses them, it does not replace them.

| Box | What to say |
|---|---|
| **SOC users** | Five roles: analyst, lead, automation administrator, administrator, auditor. Each role can be limited to a domain - for example an analyst who only sees vulnerability work. What you can *see* and what you can *do* are checked separately. |
| **Microsoft Entra ID** | All sign-in goes through the client's Entra ID: standard OIDC with PKCE, MFA enforced by their Conditional Access, roles assigned as Entra app roles. The platform never stores passwords. The `JWKS` arrow is the platform fetching Entra's public keys to verify each token's signature. |
| **Key Vault** | Every secret - tool API credentials, database password, encryption key - lives in the client's vault and is mounted into the containers as a file. Secrets are never in configuration files, the database or the console; the console only shows "set" or "not set". If a mounted secret file is missing or empty, the platform refuses to start. |
| **SIEM** | Two flows. Out: the platform's structured logs, access log and audit export, so the client's SOC can monitor the platform itself. In (optional): the SIEM can push alerts into the platform, authenticated with an API key; replays are ignored and one bad alert never rejects a whole batch. |
| **Teams / Slack / webhook** | Notifications for findings above a chosen severity. HTTPS only, configured in settings; the webhook URL (which contains a credential) is never logged or displayed. |
| **Monitoring** | `/health` reports the scheduler, the audit chain and the self-check; `/metrics` is a Prometheus endpoint read with an auditor-level API key. |
| **Network rules** | Inbound: only the reverse proxy reaches the API port (8080), plus the optional SIEM push. Outbound: an explicit allow-list - each tool's API host, the LLM gateway, Entra. |

### 1.3 Centre zone - the platform, top to bottom

Explain that the layers only depend downwards: the API calls the workflows, the workflows call the core services, the
core services call the connectors. Nothing calls upwards, so every request takes the same controlled path.

**Reverse proxy and WAF (dark bar).** Provided by the client - Azure Application Gateway, Front Door or an on-premises
equivalent. It terminates TLS and filters web attacks before anything reaches the platform. The platform trusts the
client address in `X-Forwarded-For` only from that proxy, so nobody can spoof their address to dodge rate limits.

**API service (four boxes).** Every request passes through them in order:

1. **Request guard** - rejects oversized bodies (30 MB cap), malformed input (null bytes, bad sizes), and rate-limits
   at 20 requests a second with bursts of 120. Adds security headers and writes an access-log row.
2. **Authentication** - who is calling: an Entra token (signature, expiry and issue time all checked), an API key for
   machines, or a sealed, audited break-glass credential for emergencies. Revoked tokens are refused.
3. **Authorisation** - may they do this here: role permissions combined with the domain scope. Sensitive operations
   (approvals, policy changes, access management) require a fresh MFA step-up and can never be done with an API key.
   A record outside your scope answers "not found", so nobody can probe for its existence.
4. **Web console** - plain JavaScript with a strict Content-Security-Policy: no inline scripts, every value escaped.
   Each request uses one database session that commits before the response is sent.

**Workflows and intelligence (four blue boxes).**

- **Phishing** - a reported e-mail is decomposed (headers, sender, links, attachments), analysed by deterministic rules
  plus an offline machine-learning engine that makes no network calls, then scoped: who else received it, who clicked
  (a blocked click is never counted as a click), what happened on their endpoint and identity afterwards. Output: a
  verdict with evidence and recommended remediation.
- **Incident** - alerts and directory audits are grouped into incidents by the host and person they concern, enriched
  across every tool in parallel, given a severity by fixed rules, mapped to MITRE ATT&CK, and checked for tools that
  disagree (a disagreement is shown and every action held for approval).
- **Vulnerability** - findings from four scanners become one finding per host and CVE, prioritised from CVSS, exploit
  probability (EPSS), known exploitation (CISA KEV), internet exposure and asset criticality; then owner routing,
  remediation campaigns, fixes verified by rescans, and time-bound exceptions that need two people.
- **Intelligence and reporting** - risk per person and host, 13 correlation rules across domains, the attack story
  (a timeline reconstructed across tools), an analyst assistant that can only use read-only tools, and the Word /
  PowerPoint reports and compliance pack.

**Core services (eight boxes).** Shared by every workflow, which is what makes behaviour consistent:

| Box | What to say |
|---|---|
| Context store | The shared picture: every record in one canonical format, resolved to one host or person. Strong identifiers link records automatically; weak hints such as a host name need several signals together; anything ambiguous goes to an analyst's review queue rather than being guessed. |
| Cases and evidence | Every case, its cited evidence, notes, owner and decisions. Evidence is what the explanations and approvals refer to. |
| Enrichment orchestrator | Asks every connected tool about a host, user, IP or file at once, with a 20-second deadline. A tool that is down is reported as "unavailable" - never as "clean". |
| Observability | A trace id follows every request, job and model call, so any outcome can be traced back; logs are structured JSON with secrets masked. |
| Audit trail | Append-only and hash-chained: each entry includes the hash of the previous one, so any alteration breaks the chain and is detected. Every write is audited; the trail is never pruned. |
| Crypto and retention | Files at rest are encrypted (Fernet), with key rotation. Retention is set per data class; open cases are automatically on legal hold. |
| **Action service + policy** (orange) | The single gate for changing a security tool - see flow 4. |
| Governance stores | Versioned autonomy policy, connector configuration (every change proposed by one person, approved by another) and the AI usage policy. |

**Connector framework (wide box).** 21 connectors - the client's 13 tool families plus public intelligence, threat-intel
fusion, Jira, an ownership spreadsheet, Sentinel and SIEM push. Every connector has a rate budget so the platform never
exceeds a vendor's limits, backs off on throttling, resumes exactly where it stopped, and checks each record's shape.
Each tool goes live one stage at a time - recording, read-only, recommend, automate - and passes an automatic preflight
(sign-in, every permission, data shape) before each promotion, which itself needs a second person. Internal addresses
and the client's own domains are never sent to outside threat-intel services.

**Bottom row.** PostgreSQL holds the cases, entities, audit chain and logs on an encrypted volume or managed service.
The encrypted file store holds raw vendor data, reported e-mails and reports. The scheduler runs the periodic jobs;
database leases make it safe to run more than one. The LLM gateway is described in flow 5.

### 1.4 Right zone - outside the platform

- **Never contacted (red box)** - say this explicitly: no vendor-hosted service and no telemetry home; no link found
  in an e-mail is ever opened; the machine-learning engine makes no network calls; no model is trained on client data.
- **Public vulnerability intelligence** - NVD, EPSS, CISA KEV receive CVE identifiers only. If a feed is down, the last
  known values are kept rather than cleared.
- **Threat-intel sources** - opt-in, one at a time, only when the client provides that source's key; they receive
  external indicators only.
- **Client security tools** - each reached through its official API with its own least-privilege service identity;
  read-only first, write permission added only for action types the client approves.
- **Client's LLM gateway** - the only model endpoint the platform will call, and only with pseudonymised text.

### 1.5 The six flows (bottom of the diagram)

**1 - Sign in.** Browser → proxy → API. The API verifies the Entra token against Entra's published keys, reads the
user's roles and domain scope, and shows only what that role may see. Privileged steps ask for MFA again.

**2 - Collect.** The scheduler's jobs call the connectors: alerts, inventory and directory audits on a schedule;
sign-ins, DNS and logons on demand during an investigation (far too much volume to copy wholesale). Each record lands
in the context store and is resolved to its host or person; ambiguous matches wait for an analyst.

**3 - Investigate.** The workflow asks every tool about the entities in the case at once, scores the result with fixed,
explainable rules, maps it to MITRE ATT&CK, and the intelligence layer correlates across domains - for example a
phishing click followed by an endpoint alert and a risky sign-in for the same person.

**4 - Decide and act (orange - the most important flow).** The workflow proposes actions. Every proposal goes through the
autonomy policy:

- The default for every action type is **L2: recommend** - a person must approve.
- High-impact actions (many targets, VIP assets) need **two people**.
- **Irreversible actions** - deleting mail, resetting passwords, rotating privileged secrets - can never run on their
  own, whatever the policy says.
- A **kill switch** stops all automatic execution instantly; **pausing a tool** blocks every write to it.

Once approved, the action service sends it through that tool's connector. The request is idempotent (a retry can never
act twice), recorded in the audit trail, and a reversible action keeps its rollback. No workflow, screen or AI component
can call a tool's write API directly - this is the only way.

**5 - Explain (optional AI).** The LLM gateway replaces names of people and hosts with placeholders, sends only the cited
evidence to the client's LLM, then checks the answer: any statement without a valid citation, or any figure that is not
in the evidence, is removed. Names are restored for the analyst. Budgets limit spend per month, per person and per
feature. Every score, verdict, priority and action is computed in code: with the AI switched off, every figure and
recommendation is identical - only the written narrative is missing.

**6 - Observe.** Logs, the access log and the audit export go to the client's SIEM; `/health` and `/metrics` feed their
monitoring; notifications go out for findings above a threshold; an hourly self-check verifies the audit chain.

---

## Part 2 - The development VM

### 2.1 The one-minute summary

"This VM is for one engineer, for one month, to build and demonstrate the platform. It holds **synthetic data only** -
no client or company data - and connects to **no** security tool. It has no inbound internet; outbound is restricted to
an allow-list. After the month the platform is deployed in the client's environment and this VM is deleted."

### 2.2 Walk the diagram

- **Company network (left).** The engineer's company laptop (company SSO and MFA) reaches the VM through the company
  VPN or bastion; the VM has no public address. Company IT keeps its usual controls: EDR, patching, scanning, backups.
  Logs can optionally be forwarded to the company SIEM.
- **The VM (centre).**
  - *Host:* company EDR agent, host firewall, disk encryption, patching by IT.
  - *Containers:* the API (listening on localhost only, development sign-in for the single user), the scheduler,
    PostgreSQL (its port not published outside the container network) and the encrypted file store.
  - *Connectors in fake mode:* all 21 run against realistic synthetic data shaped like each vendor's API - no
    credentials, no calls to any tool.
  - *Secrets:* the only secret is the Azure OpenAI key, kept in a file only the service account can read, with a
    monthly token budget; it is rotated when the VM is retired.
  - *Synthetic data:* a fictional demo organisation and the client's own data handoff scenarios, rebuilt with reserved
    test domains and addresses.
  - *LLM gateway and logs:* exactly as in production - pseudonymisation, citation checks, the audit trail.
- **Firewall / proxy (dark bar).** Outbound HTTPS only, to an allow-list.
- **Internet (right).** Azure OpenAI (company subscription), the public vulnerability feeds (CVE identifiers only),
  package and image registries for building, and GitHub with the CI pipeline that checks every change: lint, static
  security analysis, dependency audit, secret scans, the full test suite on two databases, a software bill of
  materials, and a container image scan.
- **Red panel.** What is never on or connected to the VM, and the decommissioning steps.

---

## Part 3 - Questions a CISO team is likely to ask

| Question | Answer |
|---|---|
| Can the AI take an action on its own? | No. The model only writes explanations from evidence it is given. It cannot produce a score, verdict or action, and nothing it writes reaches the action path. With it switched off, every result is identical. |
| Can the platform change our tools without approval? | Not by default: every action type starts at "recommend" and needs a person. Promoting an action type to automatic is a policy change that needs two people; irreversible actions can never be automatic; the kill switch and tool pause stop writes at once. |
| What data leaves our environment? | Only what the right-hand zone shows: API calls to your own tools, CVE identifiers to public feeds, external indicators to threat-intel sources you approve, and pseudonymised evidence to your own LLM gateway if you enable it. Nothing else. |
| Where are credentials kept? | In your vault, mounted as files at run time. Never in configuration, the database, the console or logs. One least-privilege identity per tool, read-only first. |
| How do you prevent one compromised account doing damage? | Role and domain scope limit what each person sees and does; sensitive steps need MFA again; high-impact actions need a second approver; API keys cannot approve anything; every step is in a tamper-evident audit trail. |
| How would we detect tampering? | The audit trail is hash-chained and verified hourly by the self-check and on `/health`; any change breaks the chain. |
| What if a tool is down? | The investigation continues with the others and shows that tool as "unavailable" - never as "clean". A public feed outage keeps the last known values. |
| How is the platform itself tested? | Every change: automated attack tests (authentication bypass, role scope, injection, ReDoS, stored XSS in a real browser), static security analysis, dependency audit, the full test suite on SQLite and PostgreSQL, secret scans. An independent penetration test is planned before client data is used. |
| Is it multi-tenant? | No. One deployment per client, in their environment, with its own database and keys. |
| What happens to the dev VM? | One month, synthetic data only, then the API key is rotated and the VM and its disks are deleted. |
