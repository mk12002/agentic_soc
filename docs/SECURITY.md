# Security model and hardening

The platform holds read (and, once approved, write) access across the security estate, so it is
treated as production security infrastructure (requirements NFR-08, R07). This document lists the
controls, where they are enforced in code, what was fixed during hardening, and what remains the
responsibility of the hosting environment.

## Threat model (summary)

| Threat | Control | Where |
|---|---|---|
| Stolen / forged API tokens | Entra ID RS256 tokens validated against tenant JWKS (issuer + audience); dev HS256 tokens refused in `prod`; unknown role claims grant nothing | `core/auth.py` |
| Insider abuse / over-privilege | RBAC (analyst, lead, admin, automation_admin, auditor); separation of duties: requester cannot approve own action; policy proposer cannot approve own policy; high-impact / four-eyes actions need a lead | `core/auth.py`, `core/actions.py`, `core/policy.py` |
| Over-automation (R04) | Autonomy levels L0–L4 per action; destructive actions never autonomous; VIP / critical assets and blast radius force approval; hard blast-radius limit blocks; global kill switch | `core/policy.py` |
| Tampering with evidence / history | Append-only audit table (ORM refuses UPDATE/DELETE) with SHA-256 hash chain; `/api/v1/audit/verify` detects any edit; grant the DB role INSERT/SELECT only | `core/audit.py` |
| Duplicate / replayed actions | Idempotency keys, compare-and-set status transitions, pre-conditions re-checked at execution | `core/actions.py` |
| LLM hallucination / prompt injection (R02) | Model sees only retrieved evidence; claims must cite valid evidence ids or are dropped; verdicts, scores and all figures are computed in code; model output can never trigger an action | `llm/gateway.py`, domain services; tested in `test_resilience_security.py` |
| Personal-data leakage to the LLM (R10) | Internal users, names, phone numbers, national ids pseudonymised before the prompt leaves the platform and restored after; prompts/responses logged; approved-endpoint allow-list; model pinning; token budget | `llm/redaction.py`, `llm/gateway.py` |
| Malicious attachments (R12) | Hardened detonation (below); Windows payloads to CAPEv2 on an isolated analysis network | `engine/agents/sandbox_agent/agent.py` |
| Tampered ML models (pickle = code execution) | SHA-256 manifest verified before any joblib/pickle artifact is deserialised; unlisted artifacts refused | `engine/integrity.py`, `artifacts/phishing/models/MANIFEST.sha256` |
| Web attacks on the console | Strict CSP (`script-src 'self'`, no inline script or handlers, `frame-ancestors 'none'`), all dynamic values HTML-escaped, deep links restricted to http(s), no-store caching, nosniff, DENY framing | `api/app.py`, `api/static/` |
| Abuse / DoS | Per-client rate limiting, 30 MB request cap, 25 MB email cap, connector request budgets so enrichment cannot degrade source tools (R06) | `api/app.py`, `connectors/base.py` |
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
| Dependency advisories (setuptools, nltk) | Low | Upgraded / removed |

## Operator responsibilities (cannot be solved in code)

* Rotate every credential that was present in the old `.env`, and the GCP service-account key.
* Run behind TLS (reverse proxy / App Gateway) and restrict network access to the API and executor.
* Provision per-tool service principals with read scopes first; add write scopes per approved action.
* Grant the audit-log database role INSERT/SELECT only; back up and retain per CCI policy.
* Store secrets in a vault (Azure Key Vault) and mount them as `*_FILE`.
* Operate CAPEv2 / the detonation host on an isolated network segment with no route to production.
