# Infrastructure, data and costs - the complete picture

What the platform needs to run in production, where every piece lives, how data flows from the security tools into
it, how much it stores and for how long, how reports and dashboards are built from live data, what it costs per
month on premises or in the cloud, and what the LLM costs on three model families. Written so every figure can be
traced: each number carries a tag.

| Tag | Meaning |
|---|---|
| **[M]** | **Measured** by running the platform (test estates, real PostgreSQL, real LLM). Re-runnable; the command is named. |
| **[P]** | **List price** read on **2026-10-18** from the vendor: Azure Retail Prices API (`prices.azure.com`, region Central India, USD, pay-as-you-go unless stated) and Anthropic's published API prices. Excludes tax, support plans and negotiated discounts. |
| **[A]** | **Assumption** - stated, with the formula, so it can be replaced by the organisation's own numbers. |

Companion documents: `HIGH_AVAILABILITY.md` (failover design and drill), `LLM_TOKENS_AND_COST.md` (token
measurement method), `CLIENT_DEPLOYMENT_GUIDE.md` (per-tool permissions and setup), `client_review/` (security review).

---

## 1. Summary for decision makers

| Question | Answer | Basis |
|---|---|---|
| What does it run on? | Two small application services (API, scheduler) in containers and **one PostgreSQL database**. Nothing else is required. | Architecture |
| Recommended hosting | **Azure** (the organisation's identity, Defender, Sentinel and Azure OpenAI are already there), across three availability zones. On premises is fully supported with the same images. | Section 9 |
| Monthly infrastructure, production HA | **Small SOC: ≈ $554 on demand, ≈ $351 with 1-year reservations (lean HA, no Kubernetes, section 10.1a).** Small-to-mid with Kubernetes: **≈ $701 pay-as-you-go; ≈ $470 with 1-year reservations** (Azure, small-to-mid SOC, every component redundant across three availability zones). Large SOC: ≈ $1,386 / $924. Add $389 for a dedicated WAF **only if** the console is reachable from the internet. | [P] section 10.1 |
| Monthly LLM cost | **$5-$26 (small / mid SOC) on gpt-4.1-mini**; $1.50-$7.50 on Claude Haiku 5.5; about $93-$100 on premium models for a mid SOC. Capped by a hard budget. | [M] tokens x [P] prices, section 11 |
| Storage | **About 5.7 KB per stored record**, all indexes and links included. A mid-size SOC needs roughly 30-60 GB for a full year. | [M] section 5 |
| Capacity | 100 concurrent analysts served at 150 requests/s with no error by four server processes on a laptop; sync of 21,691 records in 6 minutes on PostgreSQL. A real SOC's load is a fraction of this. | [M] section 6 |
| Is the tools' data copied into a data lake? | **No.** Each tool record is normalised in memory, then stored once in PostgreSQL in a common shape and linked to one host or person. Only security-relevant records are kept; the SIEM remains the log archive. | Section 4 |
| Can it go down? | No single point of failure: 2+ replicas of everything across three zones, zone-redundant PostgreSQL (Microsoft SLA about 99.99 %, failover in 60-120 s with no data loss), a dead scheduler's job taken over within 120 s. Each of these choices is justified with its cost in section 10.2. | [P] section 10.2, `HIGH_AVAILABILITY.md` |
| Does the AI decide anything? | No. Figures, verdicts and actions are computed in code; the model only writes narrative, and the platform works the same with it switched off. | Design rule, tested |

---

## 2. What runs

| Component | What it is | Resources it needs | Replicas in production |
|---|---|---|---|
| `soc-api` | The API and the analyst console (Python 3.11, FastAPI, uvicorn) | 1 vCPU / 1-2 GB per pod (1 worker process) | 2-4 (autoscaled on CPU); 3-4 on Azure, one per zone |
| `soc-scheduler` | The scheduled jobs: syncs, investigations, correlation, reports, retention, notifications | 0.25 vCPU requested / 1-2 GB (mostly waits on the tools' APIs) | 2 |
| PostgreSQL 16 | **All** state: records, cases, actions, audit chain, stored e-mails and reports | 2 vCore / 8 GB and 64 GiB for a small-to-mid SOC; 4 vCore / 16 GB and 256 GiB for a large SOC (sections 5, 10.1) | 1 primary + 1 synchronous standby in another zone (cloud) or 3-node cluster (on-prem) |
| Ingress / WAF | TLS termination; a web application firewall when the console is internet-facing | the organisation's existing gateway or an internal load balancer; a dedicated WAF only if internet-facing (section 10.2, D5) | 2+ / managed |
| Secrets store | Database URL, data-encryption key, API keys | managed service (Key Vault) or the organisation's vault | managed |
| Optional: phishing ML engine | Trained models for e-mail analysis, offline | runs inside the API image when enabled | with the API |

No message queue, cache server, search cluster or object store is required in production: durable state is in
PostgreSQL by design, which keeps the infrastructure to one stateful component to protect.

---

## 3. Every tool: where it lives and how the platform reaches it

The platform only ever **calls out** to the tools' official APIs, over HTTPS 443, with one read-only identity per
tool (writes only after a person approves an action). The one inbound path is an optional SIEM push.

| Tool | Hosted where | What the platform reads | How often | Implication for hosting the platform |
|---|---|---|---|---|
| Microsoft Entra ID | Microsoft cloud | users, risky users, risk detections, directory audits; sign-ins on investigation | every 5 min (incremental) | internet egress to `graph.microsoft.com` |
| Defender for Endpoint | Microsoft cloud | alerts, machines, vulnerabilities (TVM) | 5 min (alerts, machines) / 6 h (vulnerabilities) | `api.security.microsoft.com` |
| Defender for Office 365 | Microsoft cloud | reported messages, e-mail alerts; mail-flow look-ups | every 2 min (reports) | `graph.microsoft.com` |
| Defender for Identity | Microsoft cloud (via Graph) | alerts; logon events on investigation | 5 min | `graph.microsoft.com` |
| Microsoft Sentinel | Azure | incidents | 5 min | `management.azure.com` |
| CrowdStrike Falcon | CrowdStrike cloud | alerts, hosts, Spotlight vulnerabilities | 5 min (alerts, hosts) / 6 h (vulnerabilities) | the tenant's API host |
| Wiz | Wiz SaaS | cloud resources, vulnerabilities, issues | 6 h | Wiz API host |
| Avanan (Check Point) | Check Point cloud | its verdict on each reported e-mail | per reported e-mail (look-up) | regional gateway |
| Cisco Umbrella | Cisco cloud | DNS activity in security categories only (by default) | on investigation (look-up) | `api.umbrella.com` |
| Thinkst Canary | Thinkst cloud console | incidents, devices | 5 min | `<id>.canary.tools` |
| ServiceNow | ServiceNow SaaS | tickets, CMDB (owners) | 6 h (CMDB, with the vulnerability refresh) / on demand (tickets) | `<instance>.service-now.com` |
| Jira (alternative) | Atlassian cloud or the organisation's server | tickets | on demand | as hosted |
| Rapid7 InsightVM | **Usually on premises** (security console) | assets, findings, exceptions | 6 h | **cloud hosting needs private connectivity** (existing VPN / ExpressRoute) to reach it |
| Delinea Secret Server / Privilege Manager | **On premises or Delinea cloud** | secret audits, elevation events, account owners | on investigation | same as Rapid7 when on premises |
| Ownership CSV | A file the organisation maintains | owner, team, criticality per host | on change | mounted file |
| NIST NVD, FIRST EPSS, CISA KEV | Public internet | CVE details, exploit probability, known-exploited list | 6 h | public egress (CVE identifiers only are sent) |
| Threat-intel sources (opt-in) | Vendor SaaS | reputation of **external** indicators only | on investigation | egress per approved source |
| Generic SIEM push | The organisation's SIEM / SOAR | alerts pushed **into** the platform | as sent | the one inbound path, authenticated with an API key |
| LLM | Azure OpenAI or the organisation's LLM gateway | (calls out with pseudonymised evidence) | on narrative | egress to the approved endpoint only |
| Teams / Slack webhooks | SaaS | (calls out with findings above a threshold) | every minute if any | egress to the webhook hosts |

**What this means for the hosting decision:** 16 of the 21 connectors call **SaaS or public internet** services, 3 reach tools that are usually on premises (the Rapid7 console and the two Delinea products), one reads a file and one receives pushes. So in either
hosting model the data already comes from the cloud; an on-premises platform still needs outbound internet to those
APIs, and a cloud platform needs private connectivity only for the on-premises tools (Rapid7 console, Delinea when
self-hosted). Hosting on premises therefore does not keep the security data off the internet - it is born there.

---

## 4. How data flows in: is it stored in PostgreSQL and then normalised?

**It is normalised first, in memory, and stored once - already normalised - in PostgreSQL.** There is no staging
table of raw vendor data and no separate data lake.

```
 Tool API (vendor JSON, one page)
   │  connector: paging, rate limit, retries, resume point
   ▼
 Conform  - fields of the wrong type brought to the documented shape; counted and reported, never silently absorbed
   ▼
 Normalise - one common record (NormalizedRecord): kind, time, source id, deep link to the vendor console,
             the entities it mentions (host, user, IP, hash, CVE ...) with their identifiers
   ▼
 Store (PostgreSQL, one transaction per page)
   ├─ source_records   one row per tool record: tool, type, id, the normalised fields, first / last seen, deep link
   ├─ entities         one row per real host, person, indicator, alert, finding, sign-in, DNS event ...
   ├─ entity_keys      the strong identifiers that resolve a record to its entity (serial, object id, SID, UPN)
   ├─ entity_hints     weaker clues (host name, IP) scored for fuzzy matching; uncertain matches go to review
   └─ relations        links between entities: this alert -> this host -> this user -> this sign-in
   ▼
 Workflows read the linked picture: incidents, phishing cases, vulnerability findings, risk, correlation, reports
```

| Question | Answer |
|---|---|
| Is the raw vendor payload kept? | **Not by default.** The normalised fields and a deep link back to the record in the vendor's console are kept. `SOC_STORE_RAW_PAYLOADS=1` also keeps each original payload, encrypted, in the database's blob table for the raw retention period (adds about 0.9 KB per record [M]). |
| One record per tool, or merged? | Both: each tool's record is kept (`source_records`, provenance intact) **and** linked to one shared entity. A laptop seen by CrowdStrike, Defender, Rapid7 and ServiceNow is four source records and **one** asset. |
| What if the same record arrives twice? | Upserted by (tool, type, id): re-reads change nothing. Syncs re-read 30 minutes back to catch late logs, de-duplicated. |
| What if a record is malformed? | That record alone is refused with its reason; the rest of the page is stored. |
| Is everything from every tool pulled? | No. Scheduled syncs pull alerts, inventories and directory audits. High-volume activity (sign-ins, DNS, privileged-access audits, domain logons) is looked up **when an investigation needs it**, for the people and hosts involved. Umbrella DNS is limited to its security categories by default. This is what keeps storage small. |
| Where do cases, verdicts and actions live? | In the same PostgreSQL database: `cases`, `evidence`, `case_entities`, `action_requests`, `ph_submissions`, `vm_findings`, `insights`, `audit_log` (hash-chained), and `blobs` (stored e-mails and reports, encrypted). |
| Can we use an existing PostgreSQL? | Yes, PostgreSQL 14 or newer. The platform creates its own tables; nothing outside them is touched. |

### Data handling guarantees

| Guarantee | How |
|---|---|
| Nothing is lost if a sync is interrupted | Each page is committed as it is stored; the next sync resumes after the last committed page |
| Late or out-of-order logs are caught | Event streams resume from the newest time seen minus 30 minutes |
| A tool's rate limit is never exceeded | Every call goes through that tool's rate budget, shared across replicas |
| A tool outage does not stop the platform | The tool's evidence is shown as unavailable; everything else continues; feeds keep their last values |
| Two syncs never collide | One sync per stream at a time, across replicas (a database lease) |
| Data quality is visible | Each sync reports fields it had to correct, by name and count |

---

## 5. Storage: how much, for how long

### Measured cost per record [M]

Measured on PostgreSQL 16 with a messy test organisation 40 times the demo (250 people, 192 laptops, 21,683 synced
records, real-tenant disorder), encryption at rest on (`scripts/measure_scale.py --scales 40 --db postgresql://...`,
then table sizes from `pg_total_relation_size`):

| What | Size |
|---|---|
| Whole database | 144.1 MB for 21,683 records |
| **Per stored record, everything included** (source record, entity, keys, hints, relations, indexes, cases, audit) | **5.7 KB** without raw payloads, **6.6 KB** with raw payloads kept |
| Original vendor payload, encrypted (only if switched on) | 664 bytes average (424 bytes plaintext) |
| Generated report (Word) | 97 KB average |
| Reported e-mail (stored encrypted) | the e-mail's own size - typically tens of KB [A] |

The test payloads are vendor-shaped but compact; real vendor payloads are often several times larger. That affects
only the optional raw payload store, not the normalised record, which keeps a fixed set of fields.

### Growth scenarios [A]

Formula: **database size ≈ records stored per day × 5.7 KB × days retained + reported e-mails per day × average
e-mail size × 180 days**. Records per day are what scheduled syncs keep (alerts, directory audits, inventory changes,
security DNS) plus the activity pulled for investigations.

| Profile | Records stored per day [A] | Reported e-mails per day [A] (75 KB avg) | Database after 400 days | Provision |
|---|---|---|---|---|
| Small SOC (≈1,000 staff) | 2,000 | 30 | 4.6 GB records + 0.4 GB e-mail ≈ **5 GB** | 64 GiB |
| Mid-size SOC (≈5,000 staff) | 10,000 | 300 | 22.8 GB + 4.1 GB ≈ **27 GB** | 64 GiB with storage auto-grow (2.4x headroom) |
| Large SOC (≈20,000 staff) | 50,000 | 3,000 | 114 GB + 40.5 GB ≈ **155 GB** | 256 GiB |

These volumes are deliberately generous: the activity mix in the measured estate was 68 % DNS and 28 % sign-ins [M],
both pulled on investigation rather than wholesale. The real figure is visible from day one on the Integrations
screen (records per stream) and should replace the assumption after the first week.

### Retention (all configurable) [code defaults]

| Data | Kept for | Setting |
|---|---|---|
| Reported e-mails | 180 days after the case closes; **kept while the case is open (legal hold)** | `SOC_RAW_RETENTION_DAYS` |
| Original vendor payloads (if switched on) | 180 days | `SOC_RAW_RETENTION_DAYS` |
| Activity records (sign-ins, DNS, mail events, secret access, elevations) | 400 days, unless a case, evidence or finding refers to them | `SOC_EVENT_RETENTION_DAYS` |
| Access log (who called what) | 400 days | `SOC_ACCESS_LOG_RETENTION_DAYS` |
| LLM prompts and answers (pseudonymised) | 180 days, then blanked | `SOC_LLM_LOG_RETENTION_DAYS` |
| Cases, evidence, actions, findings, people and hosts | kept (they are the record of decisions) | - |
| Audit log (hash-chained) | **never deleted** by the platform | - |

A daily retention job applies these in batches; its report and audit entry say how much it removed.

### Protection and backup

| Item | How |
|---|---|
| Encryption at rest | Stored e-mails, reports and raw payloads encrypted with the organisation's key (Fernet, rotatable); the database volume encrypted by the platform (Azure) or the storage layer (on-prem) |
| Integrity | Stored files carry a SHA-256 checked on every read; the audit log is hash-chained and verified hourly |
| Backup | PostgreSQL point-in-time recovery (Azure: built-in, retention configurable from 7 to 35 days; on-prem: base backups + continuous WAL to a second site). With the database file store, the database backup is the only backup needed |
| Key escrow | The data key held in two places; without it stored e-mails and reports cannot be decrypted |

---

## 6. Capacity and performance [M]

| Measurement | Result | Source |
|---|---|---|
| Concurrent analysts | 4 server processes served **100 analysts at 150 requests/s with no error or timeout** (laptop, SQLite); 127 requests/s on PostgreSQL. Each screen alone takes 6-50 ms. Real analysts click every few seconds, so this is several times a real SOC's load. | `scripts/load_test.py`, OPERATIONS.md |
| Sync throughput | 21,691 records from every connector in 359 s on PostgreSQL (**60 records/s**, laptop, embedded server), 0 failed; about 146 records/s on SQLite | `measure_scale.py`, today |
| Cost per record stays flat | 30.7 SQL statements per synced record at every scale | `measure_scale.py`, `test_volume.py` |
| Pipelines at 40x | vulnerability refresh 58 s, incident pipeline 45 s (mostly waiting on tools' rate budgets), intelligence refresh 34 s, overview dashboard 0.05 s, self-check 0.3 s | `measure_scale.py`, today |
| Headroom | A large SOC's 50,000 records per day [A] is 0.6 records/s on average - about 100 times below the measured sync rate | arithmetic |

---

## 7. Reports and dashboards from live data

| Surface | What it shows | How it is computed | Freshness |
|---|---|---|---|
| Console screens (Overview, Vulnerabilities, Phishing, Incidents, Approvals, Intelligence, Cloud posture ...) | KPIs, charts, cases, findings, approvals | Read directly from PostgreSQL on every page view - no copy, no separate reporting database | as current as the last sync (2-5 min for alerts and reports, 6 h for scanner data) |
| Value scorecard | 8 benefit KPIs against the organisation's baseline | computed from case, action and finding timestamps | live |
| Daily exposure report (Word) | what needs action today, changes in 24 h, team standing, ageing, coverage | the same queries as the screens | daily at the configured time |
| Weekly VM report (Word), weekly management deck (PowerPoint) | team SLA compliance, campaigns, exceptions; the week in numbers to the decisions needed | same | weekly |
| Board monthly (PowerPoint), CISO weekly, phishing monthly, compliance quarterly, post-incident | standard leadership reports, each with charts and the value scorecard | 17 data sources computed in code | scheduled or on demand |
| Reports described in words | any combination of the 17 sources, planned by the LLM from a request ("a slide pack for the CISO on phishing and supplier risk this month") | the LLM chooses sections and writes narrative; **every figure from code**, each sentence cites it | on demand |

Live-data behaviour is tested, not assumed: every screen and report is checked against the API figure-for-figure,
on four different organisations including a messy one 20 times the demo; a browser tour audits every screen at four
widths in light and dark mode; reports were rendered from the 20x estate and reviewed page by page (it caught long
host lists and a missing "more" note, both fixed). Reports render at 97 KB per Word document [M].

---

## 8. The correlation rules

Correlation finds what no single tool can see. Every rule is **deterministic code** over the linked records; it
raises an *insight* with the exact evidence it used, a severity, and recommended next steps. The LLM may describe an
insight; it never creates one. Insights are de-duplicated (one per subject; re-runs update it), run every 10 minutes,
and a dismissed insight returns only if its severity rises.

They build on the **risk profile** of each person and host: signals from every tool (phishing clicks, endpoint
alerts, risky sign-ins, privileged access, deception hits, exposure) weighted by severity and decaying by half every
7 days - except open exposures and open incidents, which do not decay. Score bands: critical ≥ 80, high ≥ 60,
medium ≥ 30, else low.

### Rules about one person or host

| # | Rule | Fires when | Severity | Why it matters / what to do |
|---|---|---|---|---|
| 1 | **Phishing led to compromise** (`phishing_compromise_chain`) | A person clicked a phishing link **and** then has an endpoint alert or an identity-risk signal (risky sign-in, identity risk, compromise found by the phishing investigation) | **critical** if both endpoint and identity follow the click; **high** if one | The classic chain - e-mail to device to account - assembled across e-mail, EDR and identity tools. Revoke sessions, reset credentials, isolate the device, purge the campaign, review mailbox rules |
| 2 | **Consent after phishing** (`consent_after_phishing`) | A person granted an application access (OAuth consent) **within 7 days after** a phishing click | high | Consent phishing gives data access without a password. Verify the application and its permissions; revoke through the approval workflow if unapproved; look for corroboration before calling it a compromise |
| 3 | **Privileged access after compromise indicators** (`privileged_after_compromise`) | An account with compromise indicators (risky sign-in, identity risk, phishing click or compromise) **then** accessed privileged credentials in the PAM vault | critical | An attacker using a compromised account to reach admin secrets. Rotate every secret accessed after the first risk signal; review privileged sessions; remove standing access temporarily |
| 4 | **Deception hit corroborated** (`deception_corroborated`) | A decoy (Canary) was touched **and** the same host or person has at least one other current signal (an alert, identity risk, a click - exposure and coverage gaps do not count) | critical | Decoys have no legitimate use; corroboration rules out noise. Treat as active intrusion: contain the source host, hunt for lateral movement in the last 72 hours |
| 5 | **Exposed host under attack** (`exposed_host_under_attack`) | A host has a significant (medium or above) endpoint alert - any endpoint alert when the host is internet-exposed - or a deception hit, **and** carries a known-exploited (KEV) or priority vulnerability | **critical** with KEV, high otherwise | Exposure-informed triage: the attack may be exploiting the open vulnerability. Raise incident priority, patch or mitigate those CVEs now |
| 6 | **Attacked host without EDR** (`attacked_host_without_edr`) | A host shows attack activity (alert, deception hit, open incident, malicious site reached) **and** has no EDR telemetry | high | A blind spot during an attack. Deploy EDR; investigate through network and identity data |
| 7 | **High fused risk** (`entity_risk_high`) | A person or host's risk is high or critical **and** comes from at least 3 different dimensions | the risk band | Many moderate signals from different tools can add up to serious risk none of them shows alone |

### Rules across the organisation

| # | Rule | Fires when | Severity | Why it matters / what to do |
|---|---|---|---|---|
| 8 | **Repeat clicker** (`repeat_clicker`) | A person clicked links in **2 or more different** phishing campaigns | medium | Targeted awareness training; stricter link protection for that person |
| 9 | **Control gap** (`control_gap`) | A domain in a security category (or confirmed malicious) was **allowed** by DNS security | high | A preventive control let a known-bad destination through. Block it (approval workflow), check the devices that resolved it, align the EDR indicators |
| 10 | **Newly known-exploited vulnerability present** (`new_kev_exposure`) | A CVE added to CISA KEV in the last 14 days (anchored to the catalogue, not the calendar) is open on any asset | **critical** if any affected asset is internet-exposed; high otherwise | Attackers are using it now. Open a remediation campaign, notify the owning teams |
| 11 | **Shared infrastructure** (`shared_infrastructure`) | One indicator (domain, IP, hash, URL) links **3 or more** people or hosts | medium | The blast radius of a campaign or attacker infrastructure. Scope every linked entity for compromise |
| 12 | **Supplier e-mail risk** (`supplier_risk`) | A supplier's e-mail shows account compromise, payment diversion, impersonation (look-alike domain) or spoofing | from the finding (critical / high / medium) | Business e-mail compromise through the supply chain. Verify by phone on a number on file, hold payments, block look-alike domains, ask the supplier to enforce DMARC |
| 13 | **Verdict quality drift** (`model_drift`) | Over the last 7 days compared with the 28 before (at least 20 analyst decisions in each), agreement with analysts fell by more than 10 points, or the verdict mix shifted (PSI > 0.2) | per finding | The platform's verdicts are diverging from analysts' decisions: review recent disagreements before trusting automation further |

Each rule has a positive and a negative test case; `test_handoff_scenarios.py` also proves them against the
scenarios in the organisation's data-types workbook.

---

## 9. On premises or cloud?

| Factor | Azure (recommended) | On premises |
|---|---|---|
| Fit with existing estate | Entra ID, Defender, Sentinel and Azure OpenAI are already in Microsoft's cloud; same identity, logging and network policies | Fits if the organisation runs Kubernetes and PostgreSQL operations in-house |
| Where the data comes from | 16 of 21 connectors call SaaS or public services: the data is already in Microsoft's and the vendors' clouds | Still pulled from the same SaaS APIs over the internet |
| High availability | Zone-redundant PostgreSQL with automatic failover, managed; AKS across 3 zones | 3-node PostgreSQL cluster (CloudNativePG) and 3 Kubernetes nodes the organisation operates |
| Operations effort [A] | ≈ 1 person-day/month: image updates, reviewing alerts; the database, its patching, backups and failover are managed | ≈ 3-4 person-days/month: OS, Kubernetes and PostgreSQL upgrades, backup and restore drills, storage, hardware lifecycle |
| Time to production [A] | days, from the Kubernetes package and a managed database | weeks, if a Kubernetes and PostgreSQL platform must first be built |
| Connectivity to on-prem tools | Needs the existing private link (VPN / ExpressRoute) for the Rapid7 console and self-hosted Delinea | Local |
| Cash cost | **$470-$701/month** for production HA, small-to-mid SOC ([P], section 10.1) | Hardware or VM capacity at internal rates + people time; no licence is required (all components open source) |
| Data residency | The organisation chooses the Azure region (prices here: Central India) | On site |

**When on premises is the better choice:** the organisation already runs a Kubernetes platform and PostgreSQL with
on-call operations and spare capacity; policy forbids hosting security data in a public cloud; or the internal cost
of the capacity in section 10.3 plus the people time is below the cloud figure. **Break-even:** on premises is
cheaper in cash when *(6-9 VMs' worth of capacity + 1-2 TB of storage + 3-4 person-days a month)* costs the
organisation less than about **$470 a month** (the 1-year-reserved cloud figure). Even with the hardware free, that
means platform operations at under **$120-$155 per person-day** ($470 / 4 and $470 / 3) - so on premises is chosen for
policy or existing-platform reasons, rarely for cash.

The application is identical in both: the same container image, the same Kubernetes base, an `azure` or `onprem`
overlay (`deploy/kubernetes`). Moving later in either direction is a database restore plus applying the other overlay.

---

## 10. Infrastructure costs

### 10.1 Azure - monthly [P]

730 hours a month. Unit prices from the Azure Retail Prices API, Central India, 2026-10-18. **Recommended** is the
production configuration for a small-to-mid SOC (up to the mid-size profile of section 5: about 5,000 staff, 10,000
stored records a day); **Large SOC** is the same design with more headroom; **Pilot** has no redundancy.

| Item | Unit price [P] | **Recommended HA**, pay-as-you-go | **Recommended HA**, 1-year reserved | Large SOC HA, pay-as-you-go | Large SOC HA, 1-year reserved | Pilot (no HA), pay-as-you-go |
|---|---|---|---|---|---|---|
| AKS cluster management | Standard tier $0.10/h; Free tier $0 | Standard: $73.00 | $73.00 | $73.00 | $73.00 | Free: $0 |
| Nodes | D2s_v5 (2 vCPU, 8 GB) $0.101/h, reserved $546/yr; D4s_v5 (4 vCPU, 16 GB) $0.202/h, reserved $1,092/yr | 3 x D2s_v5, one per zone: $221.19 | $136.50 | 3 x D4s_v5: $442.38 | $273.00 | 2 x D2s_v5: $147.46 |
| PostgreSQL Flexible Server compute, General Purpose (Ddsv5) | $0.1255 per vCore-hour; reserved $660 per vCore-year; the standby is billed like the primary | 2 vCore + zone-redundant standby: $366.46 | $220.00 | 4 vCore + zone-redundant standby: $732.92 | $440.00 | 2 vCore, no standby: $183.23 |
| PostgreSQL storage (primary and standby) | $0.131/GB-month | 64 GiB x 2: $16.77 | $16.77 | 256 GiB x 2: $67.07 | $67.07 | 64 GiB: $8.38 |
| Backup storage (point-in-time restore, 7-35 days) | free up to 100 % of provisioned storage, then $0.095/GB-month | $0 | $0 | $0 | $0 | $0 |
| Ingress | the organisation's existing Application Gateway or an internal load balancer [A] | $0 | $0 | $0 | $0 | $0 |
| Log Analytics | $3.22/GB (the 5 GB monthly free allowance is per billing account; assumed already used) | 5 GB [A]: $16.10 | $16.10 | 15 GB [A]: $48.30 | $48.30 | 2 GB [A]: $6.44 |
| Key Vault | $0.03 per 10,000 operations | ≈700k ops [A]: $2.10 | $2.10 | $2.10 | $2.10 | $2.10 |
| Container Registry | Basic $0.1666/day; Standard $0.6666/day | Basic: $5.07 | $5.07 | Standard: $20.28 | $20.28 | Basic: $5.07 |
| **Total infrastructure** | | **$700.69** | **$469.54** | **$1,386.05** | **$923.75** | **$352.68** |
| *Optional:* dedicated Application Gateway WAF v2 - only if the console is internet-facing | $0.504/h + $0.0144 per capacity unit-hour | +$388.94 (2 CU) | +$388.94 | +$409.97 (4 CU) | +$409.97 | - |

Not included: tax, the Azure support plan, private connectivity to on-premises tools (usually already in place), the
cluster's own load-balancer rules, and network egress (API traffic is small: even 50,000 records a day at 5 KB each is
about 250 MB/day [A]). Three-year reservations cut the node and database lines further ($1,048 per D2s_v5 node and
$1,319 per vCore for 3 years [P]). Backup stays free while the backups fit in the provisioned storage: with 7 days'
retention, a mid-size SOC's database (27 GB after 400 days, section 5) and its daily changes fit in 64 GiB [A];
geo-redundant backup (decision D6) is billed for the part above the provisioned size.

**Lowering the bill.** These are list prices, not fixed prices. With the same high-availability design:

| Lever | Recommended HA, per month | How |
|---|---|---|
| Pay-as-you-go (the table above) | $700.69 | - |
| 1-year reservations (nodes, database) | $469.54 | the table above |
| 3-year reservations | **≈ $346.93** | nodes 3 x $1,048 / 36 = $87.33, database 4 vCore x $1,319 / 36 = $146.56 (primary + standby), the other lines unchanged at $113.04 [P] |
| The organisation's Microsoft agreement | lower again | Enterprise Agreement / Azure commitment discounts apply on top of list price; not known here |
| An existing shared AKS cluster and registry | minus $73 + most of the $221 nodes | the platform needs about 4 vCPU of pod requests (section 2) on a cluster that already has an SLA and spare capacity |
| Right-size after measuring | depends | sizes here are generous for the mid profile; `load_test.py` and `measure_scale.py` against the real environment (section 14) |

Savings that **reduce availability** (acceptable for a pilot, not for production): no zone-redundant standby
(-$191.61 pay-as-you-go), two nodes instead of three (-$73.73), AKS Free tier (-$73.00) - section 10.2 says what each
one costs in resilience. The pilot configuration without redundancy is $352.68.

**Where the money goes (recommended, pay-as-you-go):** the database with its standby 55 %, the three nodes 32 %, the
AKS SLA 10 %, everything else 3 %.

**Sizing basis - why this size is enough:**

| Component | Load it must carry | Measured capacity | Margin |
|---|---|---|---|
| API, 3 pods x 1 worker on 2-vCPU nodes | A mid-size SOC with 25 analysts on screen at once, each page view making about 5 API calls every 10 s [A]: **≈ 12.5 requests/s** | One worker process saturates at **43 requests/s** [M] (`OPERATIONS.md`); four served 100 analysts at 150 requests/s with no error [M] | One pod carries the assumed load 3 times over; three run for availability, and a zone loss leaves two |
| Scheduler, 2 pods x 0.25 vCPU | Syncs every 2-5 minutes, pipelines every 10 minutes | At 40x the demo, the incident pipeline took 45 s and was mostly waiting on the tools' rate budgets [M] | CPU is not the limit; the vendors' rate limits are |
| Database, 2 vCore / 8 GB, 64 GiB | 10,000 records a day [A] = **0.12 records/s**; **27 GB** after 400 days | 60 records/s synced into PostgreSQL on a laptop [M] | Writes about 500x; storage 2.4x, with storage auto-grow on |
| Large SOC | 50,000 records a day (0.6/s), 155 GB after 400 days [A] | same | 4 vCore, 256 GiB and 4-vCPU nodes for headroom |

**Not yet measured:** the 2-vCore managed database and 2-vCPU nodes themselves. Before go-live, run
`scripts/load_test.py` and `scripts/measure_scale.py --db <the Azure server>` against the provisioned environment;
moving to the large size is a setting change (Microsoft: scaling database compute causes a short downtime even with
HA, so schedule it).

### 10.1a Lean HA for a small SOC - no Kubernetes [P]

At a small SOC's volume (the small profile of section 5, or an organisation's own ticket counts well below it) the
application tier needs very little: the cost of 10.1 is the redundant database and the Kubernetes machinery, not
capacity. The lean design keeps the guarantee that matters - **the database survives a zone with no committed data
lost** - and runs the two application services on two plain VMs instead of a cluster. Unit prices from the Azure
Retail Prices API, Central India, read **2026-10-21** (VMs) and 2026-10-18 (the rest, as in 10.1):

| Item | Unit price [P] | Lean HA, on demand | 1-year reserved | 3-year reserved |
|---|---|---|---|---|
| 2 VMs `Standard_D2s_v5` (2 vCPU, 8 GB), one per availability zone, each running the API and the scheduler | $0.101/h; reserved $546 per year, $1,048 per 3 years | $147.46 | $91.00 | $58.22 |
| PostgreSQL Flexible Server, General Purpose 2 vCore + zone-redundant standby | as 10.1 | $366.46 | $220.00 | $146.56 |
| PostgreSQL storage, primary and standby | as 10.1 | $16.77 | $16.77 | $16.77 |
| Log Analytics 5 GB, Key Vault, Container Registry Basic | as 10.1 | $23.27 | $23.27 | $23.27 |
| Load balancing | the organisation's existing Application Gateway or load balancer [A] | $0 | $0 | $0 |
| **Total** | | **$553.96** | **$351.04** | **$244.82** |

Against 10.1's recommended configuration that is $146.73 less on demand, $118.50 less with 1-year reservations and
$102.11 less with 3-year reservations. What it gives up: the managed Kubernetes control plane's self-healing and
autoscaling, and zero-downtime rolling deploys (a deploy updates one VM at a time). What it keeps: two copies of the
application in two zones (a job on a failed VM is taken over within one 120 s lease, `test_high_availability.py`),
the zone-redundant database (D1), point-in-time backups. Stored e-mails and reports must be in the database
(`SOC_BLOB_STORE=database`), as in 10.1. **Deployment:** each VM runs only the API and scheduler services of `deploy/docker-compose.yml`
(not its `postgres` service) with `SOC_DATABASE_URL` pointed at the managed server - the smallest deployment without
a single point of failure in `HIGH_AVAILABILITY.md` section 3.3. D2s_v5 is chosen over the burstable B2ms ($0.0896/h, no
reservation listed in Central India on 2026-10-21) because reserved it is cheaper and its CPU is not credit-limited.

**Pilot, no redundancy:** one `Standard_B2ms` VM ($0.0896/h = $65.41) and PostgreSQL Flexible Server Burstable B2s
($0.098/h = $71.54; Burstable cannot have an HA standby) with 64 GiB storage ($8.38) and the same $23.27 of logs,
vault and registry: **≈ $168.60 a month** on demand. A zone outage means a point-in-time restore (minutes to hours).
Neither burstable size has been measured with the platform: run `scripts/load_test.py` and
`scripts/measure_scale.py` against it, as for every size in this section.

### 10.2 Every availability decision, justified

All of the platform's state - records, cases, approvals, the audit chain, stored e-mails and reports - is in
PostgreSQL, and the application tier holds none. So the design rule is simple: **the database must survive a zone,
and every other component must have a second copy in another zone.** Microsoft's SLAs translate into allowed downtime
as follows (730-hour month, 8,760-hour year):

| Availability | Downtime allowed per month | per year |
|---|---|---|
| 99.9 % | 43.8 min | 8.8 h |
| 99.95 % | 21.9 min | 4.4 h |
| 99.99 % | 4.4 min | 52.6 min |

An SLA is Microsoft's financially backed commitment (service credits), not a guarantee; the failover drill in
`HIGH_AVAILABILITY.md` section 7 measures what the platform actually does.

| # | Decision | Extra cost per month [P] | What it protects against | Evidence | What happens without it |
|---|---|---|---|---|---|
| **D1** | **PostgreSQL with zone-redundant HA** (synchronous standby in another zone) | **+$191.61** pay-as-you-go (standby compute $183.23 + storage $8.38); +$118.38 reserved | Loss of the database server, its host or its whole availability zone | Microsoft: automatic failover **within 60-120 s with zero data loss**; SLA **about 99.99 %**. Commits wait for the standby to persist them, so a committed case or approval is never lost. The platform rides through the switch: connections are checked before use and replaced, requests answer 503 + Retry-After, readiness takes pods out of the load balancer until the database answers (`HIGH_AVAILABILITY.md` section 2) | Without HA (Microsoft: "not recommended", lower SLA) a failed server is rebuilt on a new machine with its storage re-attached; a zone outage stops the platform until a point-in-time restore completes ("a few minutes up to a few hours"). Since every screen, job and approval needs the database, this is the one component whose loss stops everything |
| | *Rejected alternative:* same-zone HA | the same price (the standby is billed alike) | node failures only | Microsoft: if the zone fails, **both** primary and standby are down and recovery is a point-in-time restore; SLA about 99.95 % | Weaker protection at the same price, so never the better choice where zones exist |
| **D2** | **Three nodes, one per availability zone** | **+$73.73** for the third node pay-as-you-go; +$45.50 reserved | Loss of a node or a zone; node upgrades (AKS drains nodes one at a time) | After any single loss, two nodes (4 vCPU) remain, against an assumed load one API pod can carry (10.1). The API spreads one replica per zone (`overlays/azure/zones.yaml`), matching the database's zone pair | With two nodes in two zones, a zone loss leaves **one** node: the platform runs on a single point of failure until the zone returns, and every node upgrade halves capacity |
| **D3** | **AKS Standard tier** | **+$73.00** | The Kubernetes control plane: financially backed **99.95 %** with availability zones (99.9 % without) | Microsoft positions the Free tier for development, test and non-production work: best-effort, **no financially backed SLA**. Running pods keep serving when the control plane is down; what stops is the self-healing - moving pods off a failed node, autoscaling, rolling deploys | The recovery path that D2 and D4 rely on would have no SLA. $73 is 10 % of the recommended bill |
| **D4** | **Two or more replicas of every service** (API 3, scheduler 2) | **$0** - they fit on the three nodes (3.5 vCPU requested of 6) | A pod crash, a node or zone loss, a deploy | A failed API pod leaves the load balancer within about 10 s (readiness every 5 s, 2 failures); a dead scheduler's job is taken over within one 120 s lease (`test_high_availability.py`); deploys add a pod before removing one (`maxUnavailable: 0`) and node drains keep at least one (PodDisruptionBudget) | With one replica, a node loss is an outage of several minutes: Kubernetes by default waits 300 s before moving pods off an unreachable node, then restarts them; every deploy is an outage too |
| **D5** | **A dedicated WAF only if the console is internet-facing** | **$0** if internal; **+$388.94** if internet-facing (55 % of the recommended bill) | Internet-scale scanning and web attacks: OWASP rule sets, a rate limit shared across replicas at the edge | Analysts are the organisation's own staff, signing in with Entra ID. The platform itself already requires authentication on every route and enforces a 30 MB body cap, a per-process rate limit (20 requests/s, burst 120), strict content-security policy and security headers, and it is attacked by 24 automated penetration tests on every test run (`SECURITY.md`, `test_pentest.py`) | **Internet-facing: the WAF is mandatory** - do not expose the console without it. Reachable only from the corporate network, VPN or private link: use the organisation's existing Application Gateway (the overlay's ingress targets one) or an internal load balancer; the WAF would then mostly protect against people who have already signed in to the corporate network, and the rate limit applies per replica (each of the 3 allows a client 20 requests/s). An Application Gateway Standard v2 without WAF ($216.08 for 2 CU [P]) is not recommended: internet-facing needs the WAF, internal does not need the gateway |
| **D6** | **Geo-redundant backup on** (must be chosen when the server is created - it cannot be added later) | only the backup storage above the provisioned size (local copy x 2 minus provisioned, at $0.095/GB-month): small at these sizes | Loss of the whole region | Microsoft: geo-restore to the paired region with a recovery point of up to 1 hour and a recovery time of "a few minutes up to a few hours"; the cluster is rebuilt from the same manifests | Without it, a region loss means losing the database. A warm standby region (a cross-region replica and a second cluster) would add roughly the recommended configuration again; not recommended for a tool whose source data stays in the security tools and can be synced again |
| | *Not bought:* AKS Premium tier | more than Standard (not priced here) | adds 24-month Kubernetes long-term support | Microsoft: the same uptime SLA as Standard, plus long-term support - no availability gain | - |

**What HA does not cover:** a mistaken deletion or bad data is copied to the standby at once (Microsoft says so
explicitly). That is what point-in-time restore is for (7-35 days, free within the provisioned storage), plus the
platform's own protections: the audit log is append-only and hash-chained, and cases and decisions are never deleted
by the platform.

**Cluster autoscaler:** switch it on for the node pool (minimum 3, maximum 4). After a zone loss the remaining two
nodes carry all three API pods and both schedulers tightly; the autoscaler adds a node in a surviving zone, billed only
while it runs ($0.101/h).

### 10.3 On premises - what to provision

| Purpose | Quantity | Each | Notes |
|---|---|---|---|
| Kubernetes worker nodes (API, scheduler, pooler, ingress) | 3 | 4 vCPU, 16 GB RAM, 100 GB disk | on 3 different hosts; they also run the pooler and ingress. On an existing cluster the platform itself needs about 4 vCPU of requests (section 2) |
| PostgreSQL nodes (CloudNativePG: primary, synchronous replica, async replica) | 3 | 2 vCPU, 8 GB RAM, 64-128 GB SSD (small-to-mid SOC); 4 vCPU, 16 GB, 256 GB (large) | on 3 different hosts - the same sizing basis as section 10.1 |
| Kubernetes control plane | 3 | 2 vCPU, 8 GB | if no cluster exists yet |
| Backup object store (MinIO or existing S3-compatible storage) at a second location | 1 | 1-2 TB | base backups + WAL for point-in-time recovery |
| Load-balancer pair / ingress | existing | - | TLS and the shared rate limit |

**Software licences: none required.** Kubernetes, PostgreSQL, CloudNativePG, PgBouncer, ingress-nginx and MinIO are
open source (MinIO is AGPL-3.0; internal use is fine, or use existing S3-compatible storage). Optional commercial
support (an OpenShift or Tanzu subscription, PostgreSQL vendor support) at the organisation's choice.

**Monthly cost formula [A]:** 9 VMs (or 6 if a cluster exists) × the internal monthly VM rate + 1-2 TB backup storage
× the internal storage rate + 3-4 person-days of platform operations × the internal day rate.

**Indicative monthly cost on dedicated hardware [A]** - for comparison with section 10.1; replace every line with the
organisation's own quote and internal rates. The 9 VMs run on three physical servers, one per failure domain (losing a
server loses one VM of each kind, which the design tolerates), so each server carries about 8 vCPU, 32 GB and 500 GB:

| Item | Assumption | Per month |
|---|---|---|
| 3 servers: 8 cores, 64 GB RAM, 2 x 960 GB SSD (mirrored) | $4,000-6,000 each, written off over 5 years [A]; vendor list prices vary widely with configuration - an entry 1U model (for example the Dell PowerEdge R360: one Xeon E-2400, up to 8 cores) fits | $200-300 |
| Backup NAS at a second site, 2 TB | about $1,500, 5 years [A] | $25 |
| Power and cooling | about 0.4 kW of equipment, 0.6 kW with cooling (PUE 1.5), 730 h, at $0.10-0.18 per kWh [A] | $45-80 |
| Hardware support | about 10 % of the hardware price a year [A] | $100-150 |
| Platform operations | 3-4 person-days a month at $150-300 a day [A] | $450-1,200 |
| Software licences | none (open source) | $0 |
| **Total** | | **≈ $820-1,760** |

People are half to two-thirds of the total. On an **existing** virtualisation or Kubernetes platform with spare
capacity the server, backup, power and support lines largely disappear (the VMs come from existing capacity at the
internal charge-back rate) and the extra operations effort is about 1-2 person-days a month: that is the only case in
which on premises is cheaper in cash than Azure's reserved price (section 9).

---

## 11. LLM costs - three model families

The LLM is optional; it writes narrative only. Token use per item is **measured** with the real model through the
platform's own call log on three different organisations (`scripts/measure_llm_usage.py`; method and full tables in
`LLM_TOKENS_AND_COST.md`). Tokens per item barely move as the organisation grows; cost grows with **items processed**.

### Measured tokens per item [M]

| Item | Tier | Input tokens | Output tokens |
|---|---|---|---|
| Incident summary | large | 1,198 | 911 |
| Phishing explanation (reports not auto-closed) | small | 504 | 682 |
| Correlated-finding narrative | small | 411 | 430 |
| Situation brief (when its facts change) | large | 2,006 | 598 |
| Analyst question (planner + answer) | small + large | 344 + 891 | 42 + 228 |
| Deep analysis (on request, cached) | large | 3,008 | 1,819 |
| Report section | large | 383 | 308 |

### Volume profiles [A] (per day)

| Profile | Reported e-mails (70 % auto-close) | Incidents | Changed findings | Brief updates | Questions | Deep analyses | Report sections |
|---|---|---|---|---|---|---|---|
| Small SOC | 30 | 15 | 25 | 30 | 40 | 3 | 12 |
| Mid-size SOC | 300 | 80 | 150 | 60 | 250 | 20 | 60 |
| Large SOC | 3,000 | 500 | 800 | 96 | 1,500 | 100 | 240 |

### Monthly cost by model [M] tokens × [P] prices

Prices per million tokens (input / output): gpt-4.1-mini $0.40 / $1.60, gpt-4.1-nano $0.10 / $0.40, gpt-4.1 $2.00 /
$8.00 (Azure OpenAI, global deployment); Claude Haiku 5.5 $0.10 / $0.50, Claude Sonnet 5.5 $2.00 / $10.00 (Anthropic).

| Option | Small SOC (6.7 M tokens) | Mid-size SOC (32 M) | Large SOC (179 M) |
|---|---|---|---|
| **A. gpt-4.1-mini, both tiers** (measured configuration) | **$5.16** | **$25.72** | **$148.14** |
| B. gpt-4.1-nano for small tasks + gpt-4.1-mini for large | $4.23 | $19.07 | $99.71 |
| C. gpt-4.1-mini small + gpt-4.1 large (premium reasoning) | $20.85 | $93.14 | $482.40 |
| D. Claude Haiku 5.5, both tiers | $1.49 | $7.50 | $43.43 |
| E. Claude Haiku 5.5 small + Claude Sonnet 5.5 large (premium) | $22.97 | $100.14 | $503.67 |

How to read it:
- **The default option costs less than one month of a single 2-vCPU node** ($25.72 against $73.73 for a mid SOC); the premium options cost about one large node. The LLM is a small share of the total (section 12).
- Token counts were measured on the OpenAI tokenizer; Claude counts tokens differently, so options D and E should be
  re-measured with `measure_llm_usage.py` against that model before relying on them (expect the same order of magnitude).
- **Quality is checked, not assumed:** the AI usage screen shows, per feature, how often answers were usable and how
  many statements the evidence guardrail removed, and advises a smaller or larger model by name (*try gpt-4.1-mini*,
  *use gpt-4.1*) from those figures; the model is chosen per feature on that screen.
- Batch APIs (50 % cheaper at both Azure and Anthropic) could carry the scheduled reports; not used today.
- **The organisation's own LLM gateway** can be used instead (CLIENT_DEPLOYMENT_GUIDE.md section 5); the token counts
  above stay valid, priced at its internal rates.

### Spending controls (built in)

| Control | Default |
|---|---|
| Monthly platform budget (hard cap; finding raised at 80 % and 100 %) | 50 M tokens - fits a small or mid SOC with headroom; set 250-300 M for a large SOC |
| Daily cap | a tenth of the month |
| Per-person limits (questions, deep analyses, reports) | 100,000 tokens/hour, 400,000/day |
| Over any limit | nothing fails: the platform's own cited text is used and the reason is shown |

---

## 12. Total monthly cost

| Scenario | Infrastructure (Azure) | LLM (option A, gpt-4.1-mini) | LLM (option D, Claude Haiku 5.5) | **Total (option A)** |
|---|---|---|---|---|
| Pilot (no HA), small SOC | $353 | $5 | $1.50 | **≈ $358** |
| **Recommended HA**, small SOC, 1-year reserved | $470 | $5 | $1.50 | **≈ $475** |
| **Recommended HA**, mid-size SOC, pay-as-you-go | $701 | $26 | $7.50 | **≈ $727** |
| **Recommended HA**, mid-size SOC, 1-year reserved | $470 | $26 | $7.50 | **≈ $496** |
| **Lean HA (10.1a)**, small SOC, on demand | $554 | $5 | $1.50 | **≈ $559** |
| **Lean HA (10.1a)**, small SOC, 1-year reserved | $351 | $5 | $1.50 | **≈ $356** |
| **Lean HA (10.1a)**, small SOC, 3-year reserved | $245 | $5 | $1.50 | **≈ $250** |
| Pilot, single VM + burstable database (10.1a) | $169 | $5 | $1.50 | **≈ $174** |
| Large SOC HA, pay-as-you-go | $1,386 | $148 | $43 | **≈ $1,534** |
| Large SOC HA, 1-year reserved | $924 | $148 | $43 | **≈ $1,072** |
| Any of the above, console internet-facing | + $389 (large: + $410) dedicated WAF | - | - | - |
| On premises | internal capacity and people time (section 10.3) | same LLM figures | same | - |

The security tools' own licences are unchanged; the platform adds no per-user or per-device fee in this estimate.

---

## 13. Questions stakeholders are likely to ask

**Is the data from all tools stored in a PostgreSQL table and then normalised?**
Normalised first, then stored once in PostgreSQL in a common shape, linked to one host or person (section 4). There
is no raw staging area and no data lake; raw payloads are kept only if switched on.

**Why PostgreSQL and not a SIEM or a data lake?**
The platform keeps what investigations need - alerts, inventories, findings, the activity of investigated people and
hosts, and its own decisions - not every log line. That is gigabytes, not terabytes (section 5), which PostgreSQL
handles with managed high availability. The SIEM stays the log archive.

**Will it cope with our volume?**
Measured: 60 records/s sync on PostgreSQL on a laptop, 100 concurrent analysts without error, flat cost per record as
volume grows (section 6). A large SOC's assumed 50,000 records a day is 0.6 records/s. The real rate is visible on
the Integrations screen in the first week.

**What does it cost if usage doubles?**
Infrastructure: nothing until the API autoscales past what three nodes hold (+$73.73/month per extra 2-vCPU node,
$45.50 reserved [P]); doubling the database from 2 to 4 vCore with its standby adds $366.46 ($220 reserved) [P]. LLM:
linear in items processed, capped by the budget (section 11). Storage: +5.7 KB per extra record [M].

**What if Azure has an outage?**
A node or a zone: nothing lost, traffic moves to the other replicas, the database fails over automatically. A
region: restore to the paired region from geo-redundant backups (`HIGH_AVAILABILITY.md` section 6, with the drill).

**Does anything we own leave our environment?**
CVE identifiers to NVD; external indicators (never internal addresses or our own domains) to approved threat-intel
sources; pseudonymised evidence to the approved LLM endpoint. Nothing else.

**What if the LLM is off, down or over budget?**
Figures, verdicts and actions are identical; narrative falls back to the platform's own cited text.

**How long do we keep data, and can we delete it?**
Section 5 retention table; every period is a setting. Open cases are on legal hold. The audit log is never deleted.

**Why not cheaper hosting, for example one VM?**
The single-host Compose deployment costs a fraction (one VM) and is right for a demo - but it is a single point of
failure. The pilot configuration ($353) drops the database standby, the third node and the AKS SLA: it saves $348 a
month and accepts that a database failure or a zone outage stops the platform until it is restored. Section 10.2 lists
each availability decision with its price and what is lost without it.

**Why not bigger, to be safe?**
Capacity is not availability. The recommended size carries the assumed mid-size load with a measured margin
(section 10.1, sizing basis); a larger database or node size is a setting change when the measurements call for it.
The first estimate of this document priced the large configuration as the default.

**How do we know the dashboards will be right on live data?**
They read the same database the workflows write, with no copy in between; the figures are cross-checked screen
against API by an automated browser tour; and the platform has been run on four differently shaped organisations,
including one 20 times the demo with real-tenant disorder. What has not been done yet is running against the
organisation's real tenants: the go-live plan starts with a *record* stage that captures real responses (identities
removed) and replays them through the test suite, then read-only and shadow mode (CLIENT_DEPLOYMENT_GUIDE.md).

---

## 14. Assumptions to replace with the organisation's numbers

| Assumption | Used in | How to measure it |
|---|---|---|
| Records stored per day (2,000 / 10,000 / 50,000) | storage, egress | Integrations screen after the first week (records per stream) |
| Reported e-mails per day and average size | storage, LLM | Phishing screen; mail gateway statistics |
| Daily volumes of incidents, questions, reports | LLM cost | AI usage screen (calls per feature, 30 days) |
| Log Analytics ingestion (5 / 15 GB) | cloud cost | the workspace's usage blade after a week |
| Concurrent analysts and calls per page (25 analysts, ≈12.5 requests/s) | node and pod sizing | `scripts/load_test.py` against the provisioned environment before go-live |
| The 2-vCore database carries the mid-size load | database size | `scripts/measure_scale.py --db <server>` and the load test before go-live |
| Whether the console is reachable from the internet | the WAF line (D5) | the organisation's access design |
| Operations effort (1 vs 3-4 person-days/month) | hosting decision | the organisation's platform team |
| On-premises hardware, power, support and day rates (section 10.3) | on-premises cost | the organisation's hardware quote and internal rates |
| Real vendor payload size (only if raw payloads are kept) | storage | `SOC_STORE_RAW_PAYLOADS=1` in the record stage, then the `blobs` table size |
| Claude token counts | options D, E | `scripts/measure_llm_usage.py` against the chosen model |

## 15. Sources

- Azure Retail Prices API, `https://prices.azure.com/api/retail/prices`, queried 2026-10-18, region `centralindia`
  (Azure OpenAI from `eastus2`, global deployment meters): Virtual Machines `Standard_D2s_v5` and `Standard_D4s_v5`
  with 1- and 3-year reservations; Azure Database for PostgreSQL Flexible Server General Purpose Ddsv5 compute and
  reservations; Flexible Server storage and backup storage; Application Gateway WAF v2 and Standard v2; Azure
  Kubernetes Service; Log Analytics; Key Vault; Container Registry; Foundry Models (Azure OpenAI) gpt-4.1,
  gpt-4.1-mini, gpt-4.1-nano.
- Microsoft Learn, read 2026-10-18: AKS pricing tiers and uptime SLA,
  `https://learn.microsoft.com/en-us/azure/aks/free-standard-pricing-tiers`; PostgreSQL Flexible Server high
  availability (zone-redundant vs same-zone, failover time, SLA, user errors replicating to the standby),
  `https://learn.microsoft.com/en-us/azure/postgresql/high-availability/concepts-high-availability`; backup and
  restore (retention 7-35 days, free backup storage up to the provisioned size, geo-redundant backup set only at
  creation, geo-restore recovery point),
  `https://learn.microsoft.com/en-us/azure/postgresql/backup-restore/concepts-backup-restore`. Kubernetes' default
  300 s toleration for unreachable nodes: the `DefaultTolerationSeconds` admission plugin.
- Anthropic API pricing, `https://platform.claude.com/docs/en/about-claude/pricing`, read 2026-10-18: Claude Haiku 5.5,
  Claude Sonnet 5.5; Batch API 50 % discount.
- Measurements in this repository: `scripts/measure_scale.py` (40x estate on PostgreSQL 16, 2026-10-18),
  `scripts/load_test.py` and `scripts/measure_llm_usage.py` (results in `OPERATIONS.md` and `LLM_TOKENS_AND_COST.md`),
  PostgreSQL table sizes via `pg_total_relation_size`.
