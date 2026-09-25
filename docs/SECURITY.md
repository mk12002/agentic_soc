# Security model and hardening

The platform holds read (and, once approved, write) access across the security estate, so it is
treated as production security infrastructure (requirements NFR-08, R07). This document lists the
controls, where they are enforced in code, what was fixed during hardening, and what remains the
responsibility of the hosting environment.

## Threat model (summary)

| Threat | Control | Where |
|---|---|---|
| Stolen / forged API tokens | Entra ID RS256 tokens validated against tenant JWKS (issuer + audience); dev HS256 tokens refused in `prod` and served only to the local machine in dev; unknown role claims grant nothing; per-token (jti) and per-user (not-before) revocation | `core/auth.py`, `core/access.py` |
| Stolen session used for high-impact decisions | Step-up MFA (`amr` = mfa or Conditional Access auth context) required for approvals, rollback, policy, kill switch and access management | `core/auth.py` |
| Insider abuse / over-privilege | RBAC (analyst, lead, admin, automation_admin, auditor) + **domain scoping** (phishing / incident / vulnerability; cross-domain views require all-domain access; out-of-scope records answer 404); separation of duties: no self-approval of four-eyes actions, policies, exceptions or access grants; time-bound, justified platform grants | `core/auth.py`, `core/access.py`, `api/app.py` |
| Compromised integration credential | Service-account API keys: SHA-256 stored, expiry ≤ 365 days, roles limited to analyst / auditor / automation admin, **never** approval, policy or access permissions | `core/access.py` |
| Identity-provider outage | Break-glass: sealed secret, only its hash configured, every use and failure audited and raised as a critical insight | `core/access.py` |
| Repudiation of who did what | Append-only access log (ORM refuses update/delete; pruned only by the audited retention job) in addition to the audit chain | `api/app.py`, `core/models.py` |
| Data at rest exposure | Raw payloads, reported emails and **generated reports / evidence packs** encrypted with Fernet (`SOC_DATA_KEY`, rotation supported; mandatory in prod); retention with legal hold | `core/crypto.py`, `core/retention.py` |
| Over-automation (R04) | Autonomy levels L0–L4 per action; destructive actions never autonomous; VIP / critical assets and blast radius force approval; hard blast-radius limit blocks; global kill switch | `core/policy.py` |
| Tampering with evidence / history | Append-only audit table (ORM refuses UPDATE/DELETE) with SHA-256 hash chain; `/api/v1/audit/verify` detects any edit; grant the DB role INSERT/SELECT only | `core/audit.py` |
| Duplicate / replayed actions | Idempotency keys, compare-and-set status transitions, pre-conditions re-checked at execution | `core/actions.py` |
| LLM hallucination / prompt injection (R02) | Model sees only retrieved evidence; claims must cite valid evidence ids or are dropped; statements (and summary sentences) stating a figure absent from their cited evidence are dropped (numeric fidelity); time-decayed scores are not given to the model; verdicts, scores and all figures are computed in code; model output can never trigger an action | `llm/gateway.py`, domain services; tested in `test_resilience_security.py` |
| LLM analyst misuse / prompt injection via data | Analyst can only request tools from a fixed read-only catalogue (unknown tools ignored); arguments type-checked; answers must cite tool results; every question and tool call audited | `intelligence/analyst.py` |
| LLM deep analysis of an attack story | Only the story's stored evidence is sent (identities pseudonymised); statements must cite S#/G#/H#/B#/P#/X# ids or are removed (count shown); priorities may only reference real pending actions or "manual"; disagreement with the deterministic assessment is flagged; cached per evidence fingerprint; bundle approval still runs policy and four-eyes per action | `intelligence/deep_analysis.py`, `api/app.py` |
| Report builder misuse (prompt-planned reports) | Planner may only choose sources from a fixed catalogue (unknown / case-bound sources dropped); specs validated and size-bounded; figures computed in code, narrative sentences must cite a figure (F#); sections outside the requester's data scope skipped and scope-dependent counts computed for the requester; download requires a scope covering both the report's domains and the builder's scope; case reports require access to the case; compliance data needs the evidence-export permission | `reporting/builder.py`, `api/app.py` |
| Personal-data leakage to the LLM (R10) | Internal users, names, phone numbers, national ids pseudonymised before the prompt leaves the platform and restored after; prompts/responses logged; approved-endpoint allow-list; model pinning; token budget | `llm/redaction.py`, `llm/gateway.py` |
| Malicious attachments (R12) | Hardened detonation (below); Windows payloads to CAPEv2 on an isolated analysis network | `engine/agents/sandbox_agent/agent.py` |
| Tampered ML models (pickle = code execution) | SHA-256 manifest verified before any joblib/pickle artifact is deserialised; unlisted artifacts refused | `engine/integrity.py`, `artifacts/phishing/models/MANIFEST.sha256` |
| Web attacks on the console | Strict CSP (`script-src 'self'`, no inline script or handlers, `frame-ancestors 'none'`), all dynamic values HTML-escaped, deep links restricted to http(s), no-store caching, nosniff, DENY framing | `api/app.py`, `api/static/` |
| Abuse / DoS | Per-client-address rate limiting (X-Forwarded-For only from configured proxies), 30 MB request cap enforced on the byte stream (chunked uploads included), 25 MB email cap, cached /health, connector request budgets so enrichment cannot degrade source tools (R06) | `api/app.py`, `connectors/base.py` |
| Secret exposure | No secrets in the repository; `.env` git-ignored; `<NAME>_FILE` vault mounts supported; per-tool least-privilege service principals, read scopes by default | `config.py`, `config/connectors.yaml` |
| Supply chain | `pip-audit` clean (setuptools pinned ≥ 83, unused packages removed incl. `nltk` with an unfixed advisory); detonation image built locally and pinned by digest in prod | `requirements/`, `deploy/sandbox/Dockerfile` |

## Attachment sandbox

**Detonation backends** (selected per attachment):

1. **CAPEv2** (`SANDBOX_CAPE_URL`) for Windows payloads (PE, Office, script hosts, LNK, ISO/IMG, PDF). A
   Linux container cannot meaningfully execute these, which are the majority of email malware. Analysis
   VMs run on an isolated network; submissions use `route=none` unless explicitly allowed.
2. **Remote executor** (`SANDBOX_EXECUTOR_URL`) on a dedicated detonation host; shared token required
   (≥ 24 chars, constant-time comparison). The executor **refuses all requests** if no token is configured.
3. **Local Docker** (development only, `deploy/docker-compose.dev.yml`).

**Container hardening** (every item is mandatory; if the daemon rejects any of them, the sample is
**not** detonated: fail closed; the previous code silently retried without seccomp / PID / tmpfs limits):

* no network (`network_mode=none`), no IPC namespace sharing, hostname `sandbox`
* read-only root filesystem; `noexec,nosuid,nodev` tmpfs for writable paths; sample mounted read-only
* all capabilities dropped, `no-new-privileges`, Docker default seccomp profile (or a custom profile via
  `SANDBOX_SECCOMP_PROFILE`), non-root user (root is refused)
* memory hard limit with swap disabled, CPU quota, PID limit, `nofile`/`fsize` limits, no core dumps
* optional gVisor (`SANDBOX_RUNTIME=runsc`) - recommended for production
* host-side watchdog kills the container if the in-container `timeout` is bypassed; trace output capped
* production: image must be pinned by digest; runtime image pulls disabled; `SANDBOX_ALLOW_NETWORK`
  refused

## Fixed during hardening

| Finding | Severity | Fix |
|---|---|---|
| Live keys (Azure OpenAI, Graph secret, TI keys, GCP service-account key) in working tree | Critical | Kept out of git; **rotation required by the owner** |
| Actions executed automatically with no analyst approval | Critical | Approval gate + autonomy policy (NFR-01) |
| Engine API authentication disabled by default | High | Default on, fail closed without a key, constant-time comparison |
| Sandbox fell back to weaker isolation when options were rejected | High | Fail closed (`SandboxHardeningError`) |
| Sandbox executor accepted unauthenticated requests when no token set | High | Refuses all requests without a ≥ 24-char token |
| Docker socket mounted into agent containers | High | Removed from base deployment (dev override only) |
| No host-side detonation deadline; unbounded output capture | Medium | Watchdog + output cap |
| Unpinned detonation image pulled at runtime; image lacked `strace` | Medium | Local pinned image with strace, no pulls in prod |
| Pickle model loading without integrity check | Medium | SHA-256 manifest verification |
| Database outage stalled every analysis ~45 s (retry ladder per call) | Medium | Circuit breaker |
| Cloned-VM serial numbers merged unrelated hosts in asset resolution | High (data integrity) | Vendor ids as conflict keys; hardware keys need name corroboration |
| Bidirectional-override characters in source | Low | Replaced by escapes |
| Engine API key check referenced an unimported `hmac` (every authenticated call would fail) | High | Import added; covered by lint in CI |
| No MFA / domain scope / service accounts / revocation / break-glass | High (NFR-09) | Implemented (see threat model) |
| Kill switch held in process memory (lost on restart, not shared by replicas) | High | Durable DB flag read by every replica and the scheduler |
| Services defaulted to a bare policy (ignored approved policy and kill switch) outside the API | High | `PolicyEngine.for_session` default everywhere |
| Cross-domain data readable by domain-scoped users (intelligence, entities, action list, case-less actions) | High | Cross-domain endpoints require all-domain scope; lists filtered; decisions scope-checked |
| Rate limit keyed on the presented credential (random tokens bypassed it) | Medium | Keyed on client address |
| Request cap only checked `Content-Length` (chunked bodies unbounded) | Medium | ASGI stream-level limit |
| Unauthenticated `/health` verified the whole audit chain per call | Medium | Verification cached (5 min); on-demand endpoint for auditors |
| Dev sign-in reachable from any host in dev mode | Medium | Loopback only unless `SOC_DEV_TOKENS_REMOTE=1`; never in prod |
| Access-log writes blocked requests for 5 s on SQLite and were silently lost | Medium | Background batched writer |
| Raw payloads and emails stored in plaintext | Medium | Encryption at rest |
| Generated reports and compliance packs stored in plaintext | Medium | Sealed on write, decrypted on authorised download |
| A real phishing email received in a staff mailbox was tracked in the repository (`artifacts/phishing/samples`) | Medium (privacy) | Removed from the tree and kept locally under the git-ignored `test_reports/private/`; it remains in git history until history is rewritten (owner decision) |
| Pseudonym tokens the model wrote without brackets (``USER_1``) were not restored and reached analysts | Low | Restore matches tokens with or without brackets, as whole words; live test asserts zero placeholders |
| Service-account key visible in a documentation screenshot (ephemeral test server) | Low | Tour masks the key before capturing |
| Report overview section computed across all domains for a domain-scoped requester (caught by test before release) | Medium | Overview computed with the requester's scope; download re-checks builder scope |
| Concurrent first-use DB initialisation race | Low | Locked, publish-after-create |
| Identity records silently dropping keys owned by another person | Low (data integrity) | Queued as key collisions for analyst review |
| Dependency advisories (setuptools, nltk) | Low | Upgraded / removed |

## Operator responsibilities (cannot be solved in code)

* Rotate every credential that was present in the old `.env`, and the GCP service-account key.
* Set `SOC_ENVIRONMENT=prod`, `SOC_AUTH_MODE=entra`, `SOC_DATA_KEY`, and (optionally) `SOC_BREAKGLASS_SHA256`;
  keep `SOC_DEV_TOKENS_REMOTE` unset. Configure `SOC_TRUSTED_PROXIES` for the reverse proxy.
* Create Entra app roles `SOC.<Role>` / `SOC.<Role>.<Domain>` and require MFA via Conditional Access.
* Run behind TLS (reverse proxy / App Gateway) and restrict network access to the API and executor.
* Provision per-tool service principals with read scopes first; add write scopes per approved action.
* Grant the audit-log database role INSERT/SELECT only; back up and retain per the organisation's policy.
* Store secrets in a vault (Azure Key Vault) and mount them as `*_FILE`.
* Operate CAPEv2 / the detonation host on an isolated network segment with no route to production.
