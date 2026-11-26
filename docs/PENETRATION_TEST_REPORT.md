# CyberDome - Penetration Test and Security Controls Report

| | |
|---|---|
| **Assessment date** | 2026-11-26 |
| **System under test** | CyberDome platform, commit `82f56ba` plus the fixes listed in section 4 |
| **Environment** | Windows Server 2025 demo host (AWS EC2), Python 3.12, SQLite; all 21 connectors in fake mode (vendor-shaped sample data, no live tool) |
| **Assessment type** | Internal white-box assessment: automated attack suites, live probing of a running instance, code review, dependency and static analysis |
| **Status** | Every finding in the platform's code is fixed and retested. Open items are environment and operator actions (section 5) and the independent test (section 8) |

---

## 1. Executive summary

CyberDome connects to an organisation's security tools with read access and, once approved, the ability to act on
them. It is therefore assessed as production security infrastructure: a compromise of the platform would be a
compromise of the security estate.

**What was tested.**
- Four automated attack suites: 68 test functions covering authentication, authorisation, injection, abuse, data
  protection and deployment hardening.
- 41 live probes against a separate running instance.
- A browser tour that tries stored cross-site scripting on eight screens.
- Static analysis: 60,337 lines with bandit.
- A dependency audit with pip-audit.

**What was found.** This round found **3 security findings** (1 medium, 2 low) and **5 reliability and correctness
defects** that affected how far security results could be trusted. All are fixed and retested (section 4).

**What was not found.**
- No route answered without credentials.
- No forged or tampered token was accepted.
- No role could act outside its permissions or its data domain.
- No injection payload changed or exposed data.
- No file could be reached by path traversal.

**History.** Earlier rounds found 81 issues, all fixed in code. Two of them still need an action by the system's
owner: rotating credentials from an old configuration file, and removing a real e-mail from the git history.

**Overall assessment.** The application-level controls are strong and are tested on every build. Before the platform
handles client data, three things are still needed:
- **An independent penetration test** of the deployed system (section 8).
- **The production configuration** (section 5): single sign-on, encryption key, TLS, and a service account in place
  of the administrator.
- **The owner actions** listed above.

| Severity | Found this round | Fixed | Open |
|---|---|---|---|
| Critical | 0 | 0 | 0 |
| High | 0 | 0 | 0 |
| Medium | 1 | 1 | 0 |
| Low | 2 | 2 | 0 |
| Reliability / correctness (affects trust in results) | 5 | 5 | 0 |
| Environment (demo host configuration) | 9 | - | 9 (section 5; expected for a demo host, must not reach production) |

---

## 2. Scope and method

### 2.1 In scope

- The web console and every API route (154 protected routes, plus the public health and sign-in configuration
  routes).
- Authentication: development tokens (as used on the demo host), API keys, break-glass sessions, token revocation.
- Authorisation: every role (analyst, lead, admin, automation admin, auditor, CISO) and domain scoping (phishing,
  incident and vulnerability).
- The action path: approvals, four-eyes, the autonomy policy and the kill switch.
- Input handling: queries, identifiers, request bodies, file uploads and reported e-mail.
- Browser protections: Content-Security-Policy, framing, caching and cross-origin requests.
- Abuse resistance: rate limiting and request size limits.
- The AI boundary: prompt injection, grounding, pseudonymisation and spend limits.
- The supply chain: dependencies, lock files and build pipeline controls.

### 2.2 Out of scope

- The client's security tools and their APIs (all connectors ran on sample data).
- Production infrastructure that does not yet exist: Entra ID single sign-on, the TLS reverse proxy, PostgreSQL
  with TLS, Kubernetes or IIS hosting. Their configuration is covered by automated manifest tests, not by live
  probing.
- Denial-of-service volume testing.
- Social engineering and physical access.

### 2.3 Method

| Technique | What was done | Result |
|---|---|---|
| Automated attack suites | `test_pentest.py` (25 tests), `test_access_security.py` (21), `test_resilience_security.py` (13), `test_go_live_hardening.py` (9), plus the executive-view permission tests | All pass after the fixes in section 4 |
| Live probing | 41 probes against a second running instance on its own port, with a copy of the demo database (the live demo was not touched). Probes were paced to the platform's own rate limit, except the rate-limit probe itself | 41 of 41 passed (Appendix A) |
| Stored cross-site scripting | The browser tour uploads an e-mail with script in the subject, sender, body, links and attachment name, then views it on eight screens with the Content-Security-Policy disabled | Nothing executed or injected |
| Code review | Authentication, authorisation, the action path, uploads, storage, outbound calls, the audit chain and the console's HTML handling | Findings in section 4 |
| Static analysis | bandit over `soc_platform` and `scripts`, medium severity and above | 0 issues in 60,337 lines |
| Dependency audit | pip-audit over the running environment; the locks are checked by the pipeline | 0 known vulnerabilities (after section 4, F-08) |

**Severity scale.**

| Severity | Meaning |
|---|---|
| Critical | Takeover of the platform or of a connected tool |
| High | Unauthorised action, or access to another domain's data |
| Medium | Limited disclosure, or a weakened control |
| Low | Minor disclosure, or a control that can raise a false alarm |
| Reliability / correctness | Not a vulnerability, but it undermines trust in what the platform reports |

---

## 3. Results by area

| Area | Tests | Result |
|---|---|---|
| **Authentication** | Every protected route called with no credentials (154). Forged tokens: an unsigned token (`alg: none`), a token signed with the wrong key, a correctly signed but expired token, one with no expiry, one not yet valid, HS512 instead of HS256, and a token with its roles edited but not re-signed. Also HTTP Basic credentials, SQL injection in an API key, and a token reused after sign-out | All refused (401). The anonymous `/health` answer contains only `status` |
| **Authorisation** | Analyst approving a high-impact action; auditor, admin and CISO approving anything; CISO and auditor turning on the kill switch; analyst granting themselves admin or creating an API key; lead and admin opening the CISO's executive view; the same lead giving both four-eyes approvals (with the name typed in different capitals) | All refused (403) |
| **Domain scoping** | A phishing-only analyst reading an incident case, reading an incident action's context and approving an incident action; a vulnerability-only analyst reading cross-domain intelligence | Refused. Records outside the user's scope answer "not found" (404), so the platform doesn't confirm that they exist |
| **Injection** | 10 payloads (SQL, NoSQL, template, path traversal, script, NUL byte, 5,000-character strings) in search, case ids and finding ids; a vulnerability question written as SQL that asks for API keys | No server error, no database or interpreter text, no key material. The vulnerability question became an ordinary findings filter |
| **Files** | Path traversal to `.env` and to the database file through static files and report downloads | Never served |
| **Request handling** | NUL byte in the path; a body declared over 30 MB; the TRACE method; a cross-origin pre-flight from another site | 400, 413 (refused before the body is read), 405, and no cross-origin permission given |
| **Browser protections** | Response headers on the console | Content-Security-Policy (`script-src 'self'` with no inline script; `frame-ancestors 'none'`), `X-Content-Type-Options`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store`, `Cross-Origin-Opener-Policy`, `Permissions-Policy`. No `Server` banner |
| **Abuse** | 400 rapid requests with a guessed token from one address | 252 answered 429 once the burst allowance (120) was used up |
| **Error handling** | A malformed JSON body; out-of-range numbers and unknown ids (attack suite) | Clean 4xx answers with no stack traces or internal text |

---

## 4. Findings this round and their remediation

### F-01 - The executive view was open to every all-domain role (Medium, fixed)

- **Description.** The executive view and its written brief needed only read access across all domains, so a lead, an
  all-domain analyst, an auditor or an administrator could open the organisation-wide summary meant for the CISO,
  and saw it in their menu.
- **Impact.** Disclosure of aggregated posture, open risks and workload to roles that are not meant to have the
  leadership summary. Every figure on it was already visible on those roles' own screens, so there is no new raw
  data access. The effect is a broader audience for the consolidated picture.
- **Remediation.**
  - A dedicated permission, `view_executive`, is held by the CISO role only. It is enforced by the server on both
    routes (`GET /api/v1/executive`, `POST /api/v1/executive/brief`).
  - The menu shows the view only to holders of that permission.
  - A user who opens the link directly sees "This screen is for the CISO".
  - A CISO's menu is limited to the executive view, the Dome Score and the reports.
- **Verification.**
  - `test_executive.py::test_only_the_ciso_opens_the_executive_view` fails on the previous code (a lead got 200)
    and passes now.
  - Live probes: lead and admin get 403.
  - The browser tour checks the CISO's menu, and that the admin and lead have no executive entry.

### F-02 - The integrity check on /health could raise a false tampering alarm (Low, fixed)

- **Description.** `/health` reports whether the hash-chained audit log verifies. To stay cheap, it remembers the last
  record it verified and the result, for the whole server process. That memory was not tied to a database, and it
  was trusted even when the database no longer contained that record.
- **Impact.** After a database is restored from a backup while the server keeps running, the console reported "audit
  chain broken" although the log was intact: a false alarm that could trigger an incident response or teach staff
  to ignore the signal. In a process that opens several databases (the test suite), one database was judged against
  another's record and could be reported broken. Real tampering was never hidden: the hourly self-check verifies the
  full chain independently. This was found because a security test failed only when the suites ran in a particular
  order.
- **Remediation.** The remembered position now belongs to one database, and a mismatch against it is re-checked from
  the self-check's stored checkpoint, or in full, before the chain is reported broken. Real tampering is still
  reported.
- **Verification.**
  - `test_access_security.py::test_the_health_audit_check_belongs_to_one_database_and_survives_a_restore` covers a
    second database, a restored database and a genuinely edited record.
  - The test fails on the previous code and passes now. The five security test files pass in the order that showed
    the problem.

### F-03 - A new user started on the previous user's page (Low, fixed)

- **Description.** Signing out left the last page's address in the browser, for example an approval or a case. The
  next person to sign in on that browser opened on that page instead of their own role's landing page.
- **Impact.** It exposes the previous person's navigation context (which case or screen they were on) to the next
  user. The data itself was still subject to the new user's permissions. It also caused confusion when switching
  roles in a demo.
- **Remediation.** Sign-out clears the page address, so every sign-in starts on the role's landing page (the CISO on
  the executive view, everyone else on the overview). A session that expires keeps the page, because the same
  person signs back in.
- **Verification.** The browser tour signs out as the admin and in as the CISO, who must land on the executive view.
  It also switches from a phishing analyst to a lead, who must land on the overview.

### F-04 to F-08 - Reliability and correctness defects (all fixed)

These are not exploitable, but each made security results less trustworthy or hid a capability failure.

| # | Defect | Impact | Remediation | Verification |
|---|---|---|---|---|
| F-04 | A missing system library (the Visual C++ 2013 runtime) silently disabled QR-code decoding, and the ML engine in the server process, on the Windows host. The only sign was a warning in the server log | A QR-code phishing e-mail was rated *suspicious* instead of *malicious*, and 4 of its recommended actions were missing. Detection was degraded without any visible alert | Runtime installed. QR decoding and the ML engine load, and the demo again produces the documented 37 actions | Demo re-run: the QR sample is rated malicious; `pyzbar` loads. **Recommendation R-04** (section 7) makes such a loss visible |
| F-05 | The LLM's answer cap followed the model's size, not the work's size. With one small model deployed, the deep analysis (large work) was cut off mid-answer | The deep analysis always failed with "no usable answer" | When no model is chosen for a feature, the cap follows the size of the work. An administrator's choice of model keeps its own cap | `test_llm_usage.py::test_one_small_deployment_serving_every_size_gives_large_work_room_to_finish` (fails before, passes after). Live: a deep analysis used 1,894 tokens and completed |
| F-06 | The analyst assistant's tools accepted only internal ids. When the model passed a person's address instead, the tool found nothing | "No risk information" for a person at risk 100/100: a wrong answer about a compromised account | Names are resolved to exactly one person or host in code before the tool runs. An ambiguous name is not guessed | `test_intelligence.py::test_a_person_named_where_the_model_should_pass_an_id_is_still_answered_about` (fails before, passes after) |
| F-07 | Remediation tickets of vulnerability campaigns could not be approved: the approve route treated the campaign id as a case id and answered "unknown case" | A remediation request (for example Log4Shell) could never be sent to its owner | One scope check for actions: a campaign ticket is judged by its domain | `test_api.py::test_a_remediation_campaign_ticket_can_be_approved_from_the_list` |
| F-08 | The development environment carried phishing-engine packages with published advisories (pyasn1, soupsieve, opentelemetry-api). The project's locks already pinned fixed versions; only this host was behind | Known vulnerabilities in packages that parse e-mail content | Environment brought to the locked versions. pip-audit reports none | `pip-audit`: "No known vulnerabilities found". **Recommendation R-05** rebuilds environments from the locks |

---

## 5. Demo host configuration (not production)

The assessed host is a demonstration machine. These settings are expected there and are the reason it must never
hold client data or connect to live tools as configured. Each has a production control, already built and enforced
where code can enforce it.

| # | Observation | Risk if carried to production | Production control |
|---|---|---|---|
| E-1 | Development sign-in is on: anyone using the machine can sign in as any role | Full control of the platform | Production refuses development sign-in (`SOC_ENVIRONMENT=prod` and `SOC_AUTH_MODE=entra`). While it is on, every live tool is isolated by the platform |
| E-2 | `/docs` and `/openapi.json` are served | Easier reconnaissance | Not served in production (tested) |
| E-3 | No TLS: plain HTTP | Interception | The server listens on 127.0.0.1 only (verified), so it isn't reachable from the network. Production runs behind a TLS reverse proxy with HSTS |
| E-4 | The server runs under the Administrator account | A platform compromise becomes a host compromise | Install with `deploy/windows/install.ps1`: LOCAL SERVICE or a group managed service account, read-only program folder, minimal writable folders |
| E-5 | `SOC_DATA_KEY` is not set, so stored e-mails and reports are not encrypted at rest | Disclosure of stored e-mail | Mandatory in production: unsealed data is refused |
| E-6 | The host's `.env` holds API keys for outside threat-intelligence services the platform does not use (the engine is forced offline) | Exposure of unused credentials | Remove them and rotate them at the services. The secret scan found no `.env` value in any tracked file |
| E-7 | A real phishing e-mail received by staff is still in the git history (2 commits), though removed from the current files | Personal data in the repository history | Owner decision: rewrite the history (for example with `git filter-repo`) and force-push |
| E-8 | The confidential client-name pattern is not configured on this host, so the local pre-commit check cannot detect it | A client name committed by mistake | Configure `.git/info/banned-names`. CI runs the check from its own secret on every push |
| E-9 | Credentials present in an older `.env` were flagged for rotation in an earlier round. Rotation is the owner's action and could not be confirmed | Use of leaked credentials | Rotate every credential named in that review, and confirm it |

---

## 6. Security controls in place

Every control below is enforced in code or in the deployment packages, and is covered by automated tests that run on
every build.

### 6.1 Identity and authentication
- **Production sign-in.** Entra ID with authorisation code and PKCE. Tokens are validated against the tenant's keys:
  RS256, issuer, audience, tenant id, expiry with one minute of skew. An application's own token is a service, never
  a person.
- **Token rules.** Every token must carry an expiry and an issue time. Forged, unsigned, re-signed and
  algorithm-confused tokens are refused. Tokens can be revoked individually and per user (sign-out, session
  revocation).
- **Step-up MFA** is required for approvals, rollback, policy, the kill switch, access management, watch lists and
  tuning.
- **Service-account API keys.** Stored as SHA-256 hashes, they expire within 365 days and can never hold approval,
  policy or access permissions.
- **Break-glass access** for an identity-provider outage:
  - a sealed secret is exchanged once for a 15-minute session;
  - only sessions the exchange recorded are honoured;
  - every use is audited and raised as a critical finding;
  - failed attempts are throttled.

### 6.2 Authorisation and separation of duties
- **Role-based access with per-role domain scope.** A user sees the union of their roles' domains, but acts only where
  the specific role allows. Out-of-scope records answer "not found".
- **The CISO is read-only** and the only role with the executive view.
- **Separation of duties.**
  - Nobody approves their own request, policy, exception or access grant. Names are compared without regard to case.
  - Four-eyes actions need two different leads.
  - A privileged access grant needs a second administrator and ends within 90 days.
  - Administrators cannot approve actions.

### 6.3 Safe actions on security tools
- **One controlled path.** Every change to a tool is an action request that goes through the autonomy policy
  (L0-L4). The default for every action is recommend only.
- **Never automatic.** Destructive actions (mail purge, password reset, secret rotation) never run on their own,
  whatever the policy says. Neither do actions on VIP or critical targets, or with a large blast radius.
- **Kill switch.** Durable and shared by every server; it stops all automatic execution.
- **Execution safeguards.**
  - Preconditions are re-checked at execution.
  - Idempotency keys stop an action running twice.
  - Status changes use compare-and-set.
  - An action is recorded as executing before the tool is called, and its outcome after.
  - A lost outcome is flagged for a person, never re-run blindly.
- **Forensic collection** on a host runs read-only commands only.

### 6.4 Data protection
- **Encryption at rest.** Reported e-mails, raw payloads, reports and evidence packs are encrypted (Fernet, with key
  rotation) and integrity-checked on read.
- **Database connections** must verify the server certificate in production. The application's database role has no
  schema rights and can only insert and read the audit log.
- **Retention** with legal hold.
- **Personal data minimisation toward the AI.** Users, names, internal hosts, internal IPs, phone, card and national
  id numbers are pseudonymised before a prompt leaves the platform, with one map per call.
- **Outside services** receive only external indicators. Internal addresses and the organisation's own domains are
  never sent.

### 6.5 Audit and integrity
- **A tamper-evident audit log.**
  - Append-only: the application refuses changes, a database trigger refuses them, and the runtime role cannot
    change them either.
  - Every record is hash-chained (SHA-256) to the one before it.
  - It is verified hourly in full, and incrementally on `/health`.
  - The chain's head is shipped to the log platform every hour, so even a database owner cannot rewrite history
    unnoticed.
- **Every successful write request is audited.**
- **One trace id** links each request or job to every record it caused.
- **Audit exports** (JSON, CSV, Excel, Word) are guarded against formula injection, and can be re-verified outside
  the platform.

### 6.6 AI and LLM safety
- **The model never decides.** Every figure, score, verdict and action is computed in code; the model only writes
  narrative from evidence it is given.
- **Grounding.**
  - Every statement must cite evidence, or it is removed.
  - A statement with a number that is not in its cited evidence is removed.
  - Model output is treated as untrusted input.
- **Prompt injection.** Instructions hidden in an e-mail do not change its verdict. The analyst assistant can only
  call a fixed list of read-only tools.
- **Approved endpoints only.** The list is mandatory and HTTPS-only in production. Model versions can be pinned.
- **Spend control.** Monthly and daily token budgets, per-person limits, a cap on every answer, and an off switch per
  feature. Only administrators can change these, and every change is audited.

### 6.7 Input handling and the web console
- **Content-Security-Policy** with no inline script and no framing. Every dynamic value is escaped. Clicks go through
  a fixed allow-list.
- **Hostile e-mail** is parsed in linear time; every pattern is bounded, which was tested on 2.4 MB pathological
  bodies.
- **Uploaded files.**
  - Excel and Word files are refused if they declare a DTD or entity, or use a multi-byte encoding.
  - Unpacked size is capped, and macro-enabled files are refused.
  - Images are size-checked and re-encoded.
- **Investigation values** are escaped for every vendor query language (OData, FQL, URL paths).
- **No link from an e-mail is ever fetched.** Outbound calls go only to configured tool endpoints and notification
  webhooks.

### 6.8 Availability and abuse
- **Rate limiting** per client address: 20 requests a second, with bursts up to 120. Behind a proxy, only the
  right-most untrusted address counts.
- **Request limits.** A 30 MB request cap enforced on the stream itself, and a 25 MB cap on e-mail.
- **No blocking work on the event loop.** The database transaction is committed before slow AI calls.
- **Isolation of failures.** A tool that is down shows as "unavailable", and everything else keeps working; this is
  tested with every tool down at once. One broken item never fails a batch.

### 6.9 Integrations
- **Least privilege.** One service account per tool, with read scopes first; write scopes are added only for approved
  actions. Secrets come from a vault, and the console only shows *set* or *not set*.
- **Configuration changes** are proposed by one person and approved by another, versioned and audited. A preflight
  check must pass first. Pausing a tool is immediate.
- **Credentials stay on the tool's own host.** They are never sent to another origin, even if a vendor response
  points elsewhere.

### 6.10 Supply chain and deployment
- **Pinned dependencies.** Every dependency is pinned. Container and Windows installs use hash-locked files. Base
  images are pinned by digest, and CI actions by commit.
- **Pipeline checks on every build:**
  - pip-audit;
  - bandit;
  - Trivy scans of both images;
  - an SBOM (CycloneDX);
  - secret scanning;
  - a check for confidential names.
  Release images are signed, and only signed images are admitted.
- **Container and Kubernetes.** Non-root, read-only root filesystem, all capabilities dropped, a default-deny network
  policy, and secrets as vault files.
- **Windows host.** A service account (not an administrator), loopback-only behind IIS, and locked-down folder
  permissions.
- **ML models** are verified against a SHA-256 manifest before loading.
- **The attachment sandbox** runs with no network, a read-only filesystem and no capabilities, and fails closed.

---

## 7. Recommendations

| # | Recommendation | Priority | Owner |
|---|---|---|---|
| R-01 | Commission the independent penetration test of the deployed platform (scope in section 8) and fix every high or critical finding before client data | Before go-live | Project owner |
| R-02 | Complete the production configuration: Entra sign-in with MFA, `SOC_ENVIRONMENT=prod`, `SOC_DATA_KEY`, TLS proxy with `SOC_TRUSTED_PROXIES`, PostgreSQL with certificate verification, service-account hosting (E-1 to E-5) | Before go-live | Operations |
| R-03 | Owner actions: rotate the credentials from the earlier review and remove unused third-party keys (E-6, E-9); rewrite the git history to remove the real e-mail (E-7); configure the confidential-name pattern on every developer machine (E-8) | Now | Project owner |
| R-04 | Make silent capability loss visible: report on `/health` and the Integrations screen when a detection component fails to load (the ML engine, QR decoding, YARA), not only in the server log (F-04) | High | Development |
| R-05 | Build every environment from the hash-locked files, and run pip-audit after every pull, so a long-lived machine cannot lag behind the fixed versions (F-08) | Medium | Development / operations |
| R-06 | Have detection engineers validate the ATT&CK capability map against the tools as configured. It is currently a standard map in code, so coverage figures are "on paper" until validated | Medium | Detection engineering |

---

## 8. Independent penetration test - planned scope

- **In scope:**
  - the deployed console and API;
  - Entra sign-in and API keys;
  - authorisation per role and domain;
  - the SIEM push endpoint, e-mail upload and report downloads;
  - rate and size limits;
  - the container image and the reverse proxy.
- **Accounts:** one per role, a domain-scoped analyst and one API key. Connectors stay in fake mode, so no client tool
  is touched.
- **Out of scope:** the client's tools and volume denial-of-service against shared infrastructure.
- **Exit criterion:** every high or critical finding fixed and retested before go-live. The report is shared with the
  client.

---

## 9. Previous assessment rounds

All findings below are fixed in code; detail and tests in `docs/SECURITY.md`.

| Round | Date | Findings | Critical | High | Medium | Low / Info |
|---|---|---|---|---|---|---|
| Initial hardening | before 2026-09 | 34 | 2 | 10 | 15 | 7 |
| Penetration test round 1 (attack suite) | 2026-09 | 7 | not graded | not graded | not graded | not graded (included a token without an expiry being accepted forever, and parsing and redaction defects found by the attacks) |
| Penetration test round 2 (white-box and live probing) | 2026-09-29 | 14 | 0 | 3 | 6 | 5 |
| Go-live review (architecture, infrastructure, security) | 2026-10-18 | 20 | 2 | 11 | 6 | 1 |
| Security audit (code review, probing, dependencies) | 2026-11-15 | 6 | 0 | 1 | 3 | 2 |
| **This assessment** | 2026-11-26 | 3 security + 5 reliability | 0 | 0 | 1 | 2 (+ 5) |

Two earlier items depend on the owner rather than code: rotating credentials that were present in an old
configuration file (initial hardening, Critical), and removing a real e-mail from the git history. Both are carried
into section 5 (E-9, E-7).

---

## Appendix A - Live probe results

41 probes against a separate instance (port 8099, a copy of the demo database). Every probe passed.

| Area | Probe | Expected | Observed |
|---|---|---|---|
| Authentication | Every protected route (154) called with no credentials | 401 on every route | All 401 |
| Authentication | Anonymous `/health` answer | Status only | `status` only |
| Authentication | Forged token: garbage string | 401 | 401 |
| Authentication | Forged token: `alg: none` (unsigned) | 401 | 401 |
| Authentication | Forged token: signed with a wrong key | 401 | 401 |
| Authentication | Forged token: expired (correctly signed) | 401 | 401 |
| Authentication | Forged token: no expiry (correctly signed) | 401 | 401 |
| Authentication | Forged token: not yet valid (correctly signed) | 401 | 401 |
| Authentication | Forged token: HS512 instead of HS256 | 401 | 401 |
| Authentication | Forged token: roles edited without re-signing | 401 | 401 |
| Authentication | HTTP Basic credentials | 401 | 401 |
| Authentication | SQL injection in an API key | 401 | 401 |
| Authentication | Token reused after sign-out | 401 (revoked) | 401 |
| Authorisation | Analyst approves a high-impact action | 403 | 403 |
| Authorisation | Auditor approves an action | 403 | 403 |
| Authorisation | Admin approves an action (separation of duties) | 403 | 403 |
| Authorisation | CISO approves an action (read-only role) | 403 | 403 |
| Authorisation | CISO turns the kill switch on | 403 | 403 |
| Authorisation | Auditor turns the kill switch on | 403 | 403 |
| Authorisation | Analyst grants themselves admin | 403 or 422 | 403 |
| Authorisation | Analyst creates an API key | 403 or 422 | 403 |
| Authorisation | Lead opens the CISO's executive view | 403 | 403 |
| Authorisation | Admin opens the CISO's executive view | 403 | 403 |
| Authorisation | Phishing-only analyst reads an incident case by id | 404 | 404 |
| Authorisation | Phishing-only analyst reads an incident action's context | 404 | 404 |
| Authorisation | Phishing-only analyst approves an incident action | 403 or 404 | 404 |
| Authorisation | Vulnerability-only analyst reads cross-domain intelligence | 403 or 404 | 403 |
| Authorisation | Same lead gives the second four-eyes approval (name in different capitals) | 403 | 403, "a second, different person must approve" |
| Injection | 10 SQL / NoSQL / template / traversal / script payloads in search, case ids and finding ids; SQL asking for API keys | No 5xx, no internals, no key material | Clean |
| Error handling | Malformed JSON body | 4xx without internals | 422 |
| Files | Path traversal to `.env` and the database file | Never served | None served |
| Request handling | NUL byte in the path | 400 | 400 |
| Request handling | Body declared over 30 MB | 413 before the body is read | 413 |
| Request handling | TRACE method | 405 | 405 |
| Request handling | Cross-origin pre-flight from another site | No `Access-Control-Allow-Origin` | None |
| Browser protections | Security headers on the console | All seven present | All present |
| Browser protections | Content-Security-Policy | No inline script, no framing | `script-src 'self'`, `frame-ancestors 'none'` |
| Browser protections | Server software banner | None | None |
| Exposure | `/openapi.json`, `/docs` | Development only | Served on the development instance (E-2); refused in production (attack suite) |
| Abuse | 400 rapid requests with a guessed token from one address | Rate-limited | 252 of 400 answered 429 |

## Appendix B - Reproducing this assessment

```bash
# attack suites
.venv/Scripts/python -m pytest soc_platform/tests/test_pentest.py soc_platform/tests/test_access_security.py \
    soc_platform/tests/test_resilience_security.py soc_platform/tests/test_go_live_hardening.py \
    soc_platform/tests/test_executive.py -q -p no:cacheprovider
# static analysis and dependencies
.venv/Scripts/bandit -r soc_platform scripts -ll -x "soc_platform/tests,scripts/ui_tour/node_modules,soc_platform/domains/phishing/tests"
.venv/Scripts/python -m pip_audit
# browser tour with the stored-XSS probe
python scripts/verify_features.py --browser
```

The live probes were run with a script against a second instance started with its own port and database
(`SOC_PORT=8099`, `SOC_DATABASE_URL` pointing at a copy of the demo database, `SOC_EMBEDDED_SCHEDULER=0`).
