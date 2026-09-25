# Failure modes and how the platform handles them

What can go wrong in production, how it shows up, what the platform does, and what was changed to make it
robust. Items marked **fixed** were found in the latest review rounds and are covered by tests.

## External dependencies

| Failure | Detection | Behaviour | Status |
|---|---|---|---|
| **LLM endpoint slow, hung or down** | Call errors and timeouts in the LLM log; `status=error` / `circuit_open` | Connecting is capped at 10 s, so a down endpoint is known quickly. Reads are capped at 30 s for short small-tier answers and 120 s for long large-tier answers; a first version with one 30 s limit broke deep analysis on the real endpoint (caught by the live suite). After 3 consecutive failures a circuit breaker skips the model for 60 s, so screens, reports and answers fall back **instantly** to deterministic, cited text; the next success closes it. Previously a hung endpoint made each call wait up to 120 s, one call after another (an 8-section report could take ~16 minutes). | **fixed** - `test_failing_model_endpoint_trips_the_breaker_and_screens_fall_back_instantly` |
| **LLM throttling / transient 5xx** | 429 / 5xx responses | One retry after `Retry-After` (capped at 5 s), then the deterministic fallback. A real transient error was observed in live measurement and degraded gracefully. | **fixed** - `test_throttled_model_call_is_retried_once` |
| **Monthly token budget exhausted** | Budget status | A finding is raised at 80 % and at 100 %. After the cap, the deterministic path is used until the month rolls over. The old 5 M default would have run out within days even for a small SOC; it is now 50 M and sized in LLM_TOKENS_AND_COST.md. | **fixed** - `test_budget_alert_and_confirmed_self_check_alerts` |
| **Model writes something unsupported** | Guardrails | Statements without valid citations, statements with figures absent from their evidence, and references to non-existent actions are removed, and the removals are counted. Pseudonym tokens are restored even without brackets. | covered - core/story tests, live LLM suite |
| **Endpoint not on the approved list** | Provider start-up | Refused (fail closed); the platform runs deterministically. | covered |
| **A connector's credentials expire / API down / rate-limited** | Freshness against each stream's cadence ("stale" / "error" on Integrations); job runs | Per-tool budgets, backoff and retry; malformed records are isolated; enrichment reports the source as *unavailable* rather than silently "clean". | covered - connector resilience tests |
| **A vendor API changes its answer shape** | Live tests (`SOC_LIVE_TESTS=1`) | NVD began answering single-CVE lookups with an empty page unless the page size is explicit, so live mode silently lacked NVD scores. Prioritisation falls back to scanner CVSS; the connector now requests the page explicitly. | **fixed** - live NVD test |

## The platform itself

| Failure | Detection | Behaviour | Status |
|---|---|---|---|
| **Scheduler process dies** | `/health` → `scheduler.state` (`running` / `stale` / `never`); a **"Scheduler stopped"** banner on every screen | A dead scheduler runs no jobs, so none can fail or alert; it is now watched from the API side (stale after 30 min, `SOC_SCHEDULER_STALE_SECONDS`). | **fixed** - `test_health_reports_a_stopped_scheduler` |
| **A job keeps failing** | Job history | Retries with backoff; after 3 failed runs it is dead-lettered and a finding is raised. It can be replayed from Integrations. | covered |
| **Two scheduler replicas** | Database lease | Only one runs each job. | covered |
| **Pipelines or jobs run twice** (restart, replay, overlap) | Self-check "one case per reported email", "no duplicate active campaigns" | Everything is idempotent. Previously a re-pull of the reporting mailbox created a second case per email (doubling risk scores), and a second campaign per CVE notified owners twice. | **fixed** - `test_rerunning_every_pipeline_and_job_changes_nothing` (3 estates) |
| **Figures drift between screens** | Hourly **platform self-check** | Recomputes each shared figure through every code path and resolves every reference. A finding is raised only if a check fails **twice** in a row, so commits landing between counts cannot cause false alarms. | **fixed** - self-check tests |
| **Large tenant slows the screens** | - | The risk ranking and the correlation job profiled every user and host. They now profile only entities with a risk source: at 20,000 entities the ranking went from ~16 s (2.5 s at 3,000) to **0.06 s**, and correlation from **36.5 s to 0.09 s**, with identical results. The case page's shared-action lookup is narrowed in the database: **0.47 s → 0.005 s** at 20,000 executed actions. | **fixed** - `test_risk_ranking_only_profiles_entities_with_risk_sources` |
| **Lists longer than 500 rows** | - | Badges and tabs use true totals (summary endpoints); lists filter by domain on the server and say "showing N of M". | **fixed** |
| **Timestamps read in the wrong time zone** | - | All timestamps are stored and returned as UTC with an explicit offset; the UI says "All times UTC". | **fixed** |
| **Malformed input / unknown ids** | - | Every write route is fuzzed and every unknown id answers 4xx. Unknown incidents and campaigns used to answer 500. | **fixed** - route sweep + fuzz tests |
| **Cross-domain data exposure** | - | The audit and access logs were readable across domains; they are now scoped. Every GET route is swept as 7 roles on 3 estates. | **fixed** |
| **Encryption key missing / rotated** | Start-up in prod | Fails closed without `SOC_DATA_KEY` in prod; rotation keeps old keys for decryption. | covered |
| **Identity provider outage** | - | Sealed break-glass access, audited and alerted. | covered |
| **Automation misbehaves** | - | Kill switch (durable, all replicas); actions are idempotent, pre-conditions are re-checked, reversible actions roll back. | covered |
| **Audit tampering** | `/api/v1/audit/verify`, hourly self-check | The hash chain breaks at the edited record. | covered |

## Remaining risks (need the client's environment)

- **Real volumes:** load not yet tested at the client's scale. Mitigation: the scaling fixes above, a stateless API,
  leased jobs and PostgreSQL. Measure with production data before go-live.
- **Live connector behaviour:** each connector must be tested against the client's tenants. Live mode is exercised
  only for the public feeds and the LLM.
- **Accuracy on the client's data:** measured by shadow mode and drift monitoring once live.
