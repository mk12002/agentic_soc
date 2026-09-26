# Test report - Agentic SOC platform

Date: 2026-09-26 (round 8; earlier rounds 2026-09-24 to 2026-09-25) · Environment: Windows 11, Python 3.11.9, CPU only · Branch: `main`

This report covers what was tested, on what data, what was found, what was fixed, and what can
**not** be claimed yet. Accuracy figures below come from synthetic or public data; they are design
evidence, not a statement of performance in the client's environment. That is measured in shadow mode against
the client's own analyst dispositions (PH-T08, NFR-15), which the platform records automatically
(`/api/v1/metrics/shadow`).

## 0. Round 8 (2026-09-26) - latest results: PostgreSQL, time, accessibility, code quality

| Check | Result |
|---|---|
| Platform test suite on **SQLite**, with PostgreSQL's rules enforced (column widths, 32-bit integers, NUL characters) | **235 passed**, 0 failed |
| The same suite on **PostgreSQL 16** (the production engine) | **236 passed**, 0 failed (one test runs on PostgreSQL only) |
| Phishing engine suite (unit + integration) | 205 passed |
| Time-travel tests on 3 estates: SLAs falling due, budget month roll-over, retention with legal hold, risk decay | all passed |
| Browser tour: 19 screens, light + dark, 1440 / 1280 / 1024 / 768 px, axe-core WCAG 2.1 A/AA | 0 problems, 0 accessibility findings (was 18 serious / critical) |
| Lint (ruff 0.16, whole repository) | 0 findings (was ~1,250) |

**Found and fixed on PostgreSQL** (SQLite hid these):
- A manual job run by a user with a long e-mail address failed.
- `%00` in an id answered 500 on 20 routes.
- A NUL character in a reported e-mail would have failed its case write.
- Free text wider than its column would have failed the write.

**Found by moving the clock:**
- Approvals waiting longer than 14 days dropped out of the dashboard and reports.
- Open vulnerabilities and incidents faded from risk while still open.
- The "privileged user at risk" amplifier never faded.
- The dashboard's action figures were not scoped to the viewer's domains.

**Found by the accessibility scan:**
- Unlabelled back links, verdict selector and file input.
- In-text links told apart by colour only.
- Low-contrast tab counts.

**Found by code review and lint:**
- 40 silent error handlers now log.
- The warning-banner action did not change the message.
- A search ignored its severity filter.
- IOC times were mislabelled as UTC.
- A blocking write sat in an async handler.
- A file handle was leaked.
- Several dead variables were removed.

**Test harness:**
- A failed estate fixture could leak its environment into later tests; cleanup is now registered before setup.
- Tests run on every sample estate, with day counts taken from settings rather than written into the tests.

## 0z. Round 7 (2026-09-25): new data sets, failure modes, cost

| Check | Result |
|---|---|
| Platform test suite | **211 passed**, 0 failed (12 opt-in live tests run in verification) |
| Feature verification (`--browser --engine --live --llm`) | **89 of 89 features verified**; 215 test cases incl. 9 live LLM + 3 live feed tests; engine 162 passed; browser tour 0 problems |
| Consistency suite on **3 estates** (built-in + seeded variants "Veridian Foods" and "Tidewell Insurance") | 22 passed (input fuzz once, on the built-in estate) |
| Variant-specific tests (the variants really differ; phishing verdicts match labels on every corpus; story, coverage and reports follow the data; no built-in names in any output) | 11 passed |
| Browser tour on a variant (different organisation, 18 hosts / 23 users) | 0 problems; every screen value equals the API |
| Live token measurement on 3 estates (real gpt-4.1-mini) | per-component tokens stable across estates; see LLM_TOKENS_AND_COST.md |
| Scale benchmarks (20,000 entities / 20,000 executed actions) | risk ranking 0.06 s (was ~16 s), correlation 0.09 s (was 36.5 s), case actions 0.005 s (was 0.47 s); identical results |

Found and fixed: the connector listing showed a demo URL in help text; the re-run test had hidden the scheduled
pipeline jobs (now included; test-harness registry cache fixed); a hung LLM endpoint froze screens for up to 120 s per
call (bounded timeout, retry, circuit breaker); the token budget default (5 M) would run out within days even for a
small SOC (50 M, with findings at 80 % / 100 %); a stopped scheduler was invisible (health heartbeat and banner);
self-check alerts could fire on a momentary difference between counts (confirmed on a re-run); the ranking,
correlation and case-action lookups degraded linearly with tenant size; the situation brief called the model on
every page view (cached by fact fingerprint); auto-closed benign mail spent tokens (deterministic explanation);
routine narratives now use the small tier.

## 0a. Round 6 (2026-09-25): testing from every angle

| Angle | Result |
|---|---|
| Platform test suite | **179 passed**, 0 failed (12 opt-in live tests separate) |
| Same figure on every surface (dashboards, lists, badges, brief, analyst tools, report facts, Word documents) | all agree (`test_consistency.py`) |
| Screen vs API (browser reads every KPI, badge, tab count) | all agree; layout audit 0 problems, LLM on |
| Re-run every pipeline and all 8 scheduled jobs twice | 0 of 39 tables change |
| LLM on vs off (scripted LLM inventing figures) | identical verdicts, scores, risk, insights, actions, findings; invented figures never shown |
| Every GET route x 7 roles, real and unknown ids | no 5xx, auth required, no cross-domain leaks, explicit UTC timestamps |
| Every write route fuzzed (bogus ids, malformed bodies) | no 5xx |
| Stored references and citations | all resolve |
| Real-LLM output audit (46 responses) | 0 unsupported figures, 0 placeholder leaks |
| Platform self-check (new, in product) | 14/14 on the demo and renamed estates; catches injected corruption |

Found and fixed: duplicate case per re-ingested email (doubled risk) and duplicate campaigns per CVE; audit log and
access log readable across domains; 500s on unknown incident/campaign ids (and a phishing case accepted by the
incident endpoint); case page vs actions API listing different actions; badge/tab counts derived from a 500-row
list (true totals now, with "showing N of M"); timestamps without timezone; run-to-run changes in the QA sample;
an intermittent guardrail hole (digits inside ids counted as support for invented figures).

## 0b. Round 5 (2026-09-25)

Added: Azure AI Foundry provider (live), full live-LLM test suite, numeric-fidelity guardrail, output review of a
complete run with the real model, client name removed from the repository.

| Area | Result |
|---|---|
| Platform test suite | **170 passed**, 0 failed (12 opt-in live tests run separately, below) |
| Live LLM suite - Azure AI Foundry, gpt-4.1-mini (`SOC_LIVE_LLM=1`) | **9 passed**: provider round trip on the pinned model; grounded answers cited and redacted; incident summaries, phishing explanations and analyst answers written by the model and cited; deep analysis bound to the story; all 7 standard reports with model narrative + prompt planner; every call OK; no pseudonym placeholders reaching analysts |
| Live public feeds (NVD, EPSS, CISA KEV) | **3 passed** (after the NVD fix below) |
| Feature verification (`verify_features.py --browser --engine --live --llm`) | **76 of 76 features verified** (173 test cases passed, 154 distinct tests mapped to features); see FEATURE_VERIFICATION.md |
| Phishing ML engine suite | **162 passed** |
| Browser tour with the LLM on (4 roles, every screen, light + dark, 1440/1280/1024 px) | 29 screenshots, 57 screens audited: **0 problems** - including a new rule that no table may need sideways scrolling at desktop widths |
| Output review of a full LLM run (46 model responses) | every figure stated by the model cross-checked against its evidence: 0 unsupported figures after fixes; 0 placeholder leaks; 46/46 calls OK on the pinned model (~57k tokens) |
| bandit / pip-audit / secret scan | 0 high, 0 medium / no known vulnerabilities / no secrets |

Found and fixed in this round (each with a regression test where it is code):

* **Stale figure in a narrative** - an insight titled 100/100 kept a narrative written at 94/100. The model is no
  longer given the time-decayed score; narratives are rewritten when the finding's evidence or severity changes.
* **Capped counts** - the brief said "30 pending approvals" with 34 open (a 30-row list was counted); insight and
  case counts had the same flaw. All are true totals now.
* **Ambiguous report labels** - "Reported emails" read by the model as "phishing emails"; labels made explicit.
* **Numeric-fidelity guardrail** - statements (and summary sentences) stating a figure absent from their evidence
  are now removed everywhere the model writes, including deep analysis.
* **Placeholder leak** - the model sometimes wrote pseudonym tokens without brackets (`USER_1`); restore now
  handles that.
* **Risk double counting** - one compromise counted once per phishing case, and cases linked in several roles
  counted twice; both fixed.
* **Storage account reported as "No EDR"** and risk-scored for it; only machines are expected to run an agent.
* **Two readings of one count** - kill-chain stages (7 reached vs 8 including blocked) and plan rows vs actions;
  labels and counts made explicit.
* **Live NVD lookups returned nothing** - NVD answers single-CVE queries with an empty page unless the page size is
  explicit; live mode would silently have lacked NVD scores. Connector fixed; live test passes.
* **Presentation** - secret shown as "42" (now its name), clipped action buttons, tables needing sideways scroll,
  unlabelled category counts, a service-account key visible in a screenshot (now masked).
* **Repository hygiene** - client name removed from every file and file name (identifiers → fictional "Acme"),
  including emails embedded as base64; a real mailbox email moved out of the repository.

## 0c. Round 4 (2026-09-25)

Added: attack story, evidence-bound deep analysis, AI report builder, reports encrypted at rest, generalisation test.
Full per-feature evidence: [FEATURE_VERIFICATION.md](FEATURE_VERIFICATION.md) (generated by `scripts/verify_features.py`).

| Area | Result |
|---|---|
| Platform test suite, incl. live public-feed tests (NVD, EPSS, KEV) | **165 passed**, 0 failed |
| Features mapped to the tests that prove them | **73 of 73 verified** |
| Phishing ML engine unit suite | **162 passed**, 2 skipped |
| Generalisation: whole platform on a renamed organisation (every workflow, story, 7 standard reports) | identical results, **0 leaked names** |
| Browser tour (real server + Chrome, 4 roles) + layout audit at 1440 / 1280 / 1024 px, light + dark | 29 screenshots, 57 screens audited: **0 browser errors, 0 HTTP 5xx, 0 clipped / off-screen / overflowing elements** |
| Labelled phishing corpus / identity (300) / asset (400) stress tests | 100 % detection, 0 % FP / 0 false merges / 0 false merges |
| bandit / pip-audit / secret scan | 0 high, 0 medium / no known vulnerabilities / no secrets |

Found and fixed in this round (each with a regression test): ATT&CK matrix and case page clipped at narrower
widths, timeline titles squeezed to zero width (the layout audit now checks every element, not just the page);
two API tests depending on test order; analyst story claims truncated by the claim cap; the fixture directory
override ignored; base64-embedded emails not renamed in the generalisation estate; a report overview section
computed across all domains for a domain-scoped requester (now scoped, and downloads re-check the builder's scope);
report files and compliance packs stored in plaintext (now sealed); duplicate response-plan rows from related cases
(merged, approved together); 9 bandit medium findings in offline phishing tools (HF revision pinning, http(s)-only
URLs).

## 0d. Round 3 (2026-09-25)

| Area | Result |
|---|---|
| Platform test suite | **144 passed**, 3 live-API tests skipped by default |
| Phishing ML engine unit suite | **162 passed**, 2 skipped |
| Clean virtual environment (README install from scratch) | **142 passed**, 3 skipped (run before the last two tests were added) |
| Client-demo walkthrough test (every screen's API calls, 5 roles, all reports downloaded) | passed, 0 server errors |
| Browser tour (real server + Chrome, 24 screens, light + dark, 3 roles) | **0 browser errors, 0 HTTP 5xx, 0 horizontal overflow** - screenshots in `docs/screenshots/` |
| Identity resolution stress test (300 people, 4 seeds) | **0 false merges, 0 % splits**, 0 phantom built-in accounts |
| Asset resolution stress test (400 hosts) | 0 false merges |
| Labelled phishing corpus (20 messages) | **100 % detection, 0 % false positives** (suspicious labels now counted as positives - an earlier eval bug hid one miss) |
| Screen latency after fixes | dashboards 10-50 ms; incident pipeline 3.3 s (was 16 s); write actions no longer delayed 5 s |
| bandit / pip-audit / secret scan | 0 high, 0 medium / no known vulnerabilities / no secrets |

Found and fixed in this round (each with a regression test): identity splits and alias gaps; key collisions silently
dropped; engine API `hmac` import missing (auth would crash); access-log writer blocking requests 5 s on SQLite;
DB initialisation race; navigation race painting a stale page; cross-domain data readable by domain-scoped users
(intelligence, entities, action list, case-less actions); rate limit bypass with random tokens; request cap
bypass with chunked bodies; unauthenticated `/health` scanning the whole audit chain; dev sign-in reachable from
other hosts; duplicate approvals for the same containment across cases (incl. differently named hosts); wildcard
CMDB rows ingested as assets; flaky tests from clock resolution (boundary dates, job ordering).

## 1. Summary (rounds 1-2)

| Area | Result |
|---|---|
| Platform test suite (`soc_platform/tests`) | **108 passed**, 3 live tests skipped by default (pass with `SOC_LIVE_TESTS=1`) |
| Phishing ML engine suite (`soc_platform/domains/phishing/tests`) | **224 passed** (182 unit/top-level + 42 integration), 2 skipped |
| Connectors | **20/20** discovered; every stream syncs, every lookup answers, actions route to the right vendor |
| Asset identity resolution at scale | **0 false merges** across 3 × 400-host messy estates (was 23 hosts wrongly merged before fixes) |
| Live public APIs (NVD, EPSS, CISA KEV) | **working** against the real services |
| Phishing detection (labelled set, 18 msgs) | composite: 12/12 malicious flagged, 0 false "malicious" after fusion rule (see §5) |
| Security scans | bandit: all high/medium findings fixed or verified false positives; pip-audit: **no known vulnerabilities** |
| Fresh clone install (platform requirements only) | **98 passed** - README quick start verified |
| Real HTTP server smoke test | health, auth (401 without token), security headers, console assets, cases across domains |

## 2. What "realistic data" means here

No client credentials were available, so every connector has a **fake mode** that feeds the *same connector
code* (requests, pagination, normalisation) with vendor-shaped JSON. Fixtures are generated from one
consistent scenario (`scripts/build_fixtures.py`) so that data from different tools corroborates or
contradicts itself the way real tool data does:

* **Tenant `acme-demo.com`** (fictional): 8 users (incl. a VIP CEO), 5 hosts, 1 Canary file share.
* **Phishing campaign** from `micros0ft-helpdesk.com`: 8 recipients + a `Re:` variant, an unrelated
  newsletter that looks similar, one ZAP-moved copy, one allowed and one blocked Safe Links click.
* **Compromise chain**: click → PowerShell payload on JANE-LT01 (CrowdStrike + Defender alerts) → Tor
  sign-in with MFA push approved → forwarding inbox rule → new device registration → Canary share opened
  → privileged Delinea secret copied → elevation denied by Privilege Manager.
* **Exposure**: Log4Shell / HTTP-2 Rapid Reset / OpenSSH / SmartScreen / ProxyNotShell reported by
  **overlapping, inconsistent scanners** (different ids, hostname forms, a scanner coverage gap).
* **Gateway disagreement**: Defender for Office 365 and Avanan both pass the phishing mail.

Additional data sets:

| Set | Size | Use |
|---|---|---|
| Messy synthetic estate (`scripts/eval_resolution_at_scale.py`) | 400 hosts / ~1,420 records per run | entity resolution stress test |
| Labelled email corpus (`scripts/build_email_corpus.py`) | 10 RFC-5322 messages incl. real QR PNG, macro `.docm`, ISO, HTML credential form | phishing accuracy |
| Original project samples | 11 messages (2002 SpamAssassin spam, some mislabelled as BEC) | independent check |
| Public SpamAssassin corpus | 23 messages (unlabelled) | false-positive behaviour |
| Real inbox messages (4, **not committed**) | 4 | qualitative check only |
| Live NVD / EPSS / CISA KEV | real services | intel connectors |

## 3. Connectors (all 20)

`test_connectors.py`, `test_resilience_security.py`

* Every stream of every connector syncs through the context store with **0 failed records**.
* Lookups verified per tool (host, user, IP, domain, hash, CVE, message), with structured `signals`.
* **Routed actions**: `endpoint.isolate` on a Defender-only host goes to MDE, on a Falcon host to
  CrowdStrike; rollback calls CrowdStrike `lift_containment`.
* **Outage handling**: with Entra and Umbrella failing mid-investigation, the investigation still
  completes, is marked *incomplete*, and names both missing sources (IM-F15 / NFR-05).
* **Rate limits / 5xx**: retried with exponential backoff; per-tool token-bucket budgets enforced.
* **Malformed vendor record** in a batch: that record fails, the rest ingest, reconciliation reports the gap.
* **Replay**: re-syncing the same alerts does not create duplicate incidents.
* **Bug found and fixed**: the fixture transport returned HTTP 5xx bodies as data instead of raising like
  the live transport, so outages were invisible in fake mode.

## 4. Asset identity resolution (R01 - the hardest problem in the requirements)

Estate defects injected: hostname case/FQDN drift, DHCP IP churn, stale records, missing serials,
**cloned-VM template serials shared by ~8% of VMs**, junk MACs, coverage gaps, decommissioned hosts,
look-alike names.

| Metric (400 hosts, 3 seeds) | Before fixes | After fixes |
|---|---|---|
| False merges (two real hosts collapsed) | **1 entity containing 23 hosts** | **0** |
| Hosts split into >1 entity | 28 % | 9.5-10.8 % |
| Records sent to analyst review queue | 25 % | 3-6 % |
| Match rate | 75 % | 94-97 % |
| Throughput (SQLite, single process) | 171 rec/s | 110-170 rec/s |

Fixes: vendor device ids are conflict keys (one host has one id per tool); serial/MAC matches need name
corroboration; exact recent FQDN and unique-name evidence; nameless IP-only scanner records are queued
or merged transitively instead of becoming phantom assets. Remaining splits are mostly IP-only scanner
records whose IP changed - genuinely unresolvable without names; they appear in the coverage report.
Regression test: `test_resolution_scale.py` (zero false merges is a hard requirement).

## 5. Phishing

`test_phishing.py`, `scripts/eval_phishing.py`

**Scenario (end to end)**: reported mail ingested from the SOC mailbox with original headers; verdict
malicious; **both gateways missed it** (flagged as high-value disagreement); campaign scope 8 recipients /
2 variants with the look-alike newsletter rejected; Jane clicked (Priya's click blocked); endpoint and
identity compromise found; 9 ranked recommendations, all waiting for approval; purge including the CEO's
mailbox requires a **lead** (VIP gate); confirming the case propagates indicators to the shared store.

**Accuracy (18 labelled messages)** - `malicious`/`suspicious` count as flagged:

| Backend | Flagged malicious | False positives | Note |
|---|---|---|---|
| Heuristic, initial | 8 / 12 | 0 / 6 | missed advance-fee fraud and fake-reply spam |
| Heuristic, after two general rules | 12 / 12 | 0 / 6 | rules informed by these samples - not held-out |
| ML engine (7 agents, offline) | 11 / 12 | 1 / 6 | FP: legitimate Azure invoice; miss: HTML-attachment phish |
| **Composite (as deployed)** | **12 / 12** | **0 "malicious"** (1 → suspicious) | engine-only moderate signal on DMARC/DKIM-authenticated sender is downgraded to *suspicious* for review |

Public SpamAssassin set (unlabelled, 23): heuristic → 14 safe, 8 spam, 1 malicious.
Real inbox (4 messages, not committed, no ground truth): the engine flags an "exclusive employee
ticket offer" and a brand event invitation; the heuristic flags one as suspicious. **Unverified** - these
are exactly the cases shadow mode exists for.

QR codes are decoded from images (quishing detected); BEC with reply-to mismatch and payment pressure is
detected without any URL.

**Latency**: heuristic median 0.5 ms / p95 10 ms per message; ML engine median 1.0 s / p95 5.7 s after
model warm-up (CPU); full report-to-case pipeline 1.2 s on fixtures.

**Bug found and fixed**: the engine's threat-intel agent stalled ~48 s per email when PostgreSQL was
unreachable (retry ladder on every call) and ran live WHOIS in offline mode → circuit breaker + switch;
now 0.26 s.

## 6. Incident and vulnerability management

`test_incident.py`, `test_vulnerability.py`

* Alerts from CrowdStrike, Defender, Entra and Canary about Jane cluster into **one critical incident**;
  unrelated web01/db01 alerts stay separate; user-report alerts are routed to the phishing workflow.
* Enrichment covers all 8 dimensions of §7.2; MITRE: T1059.001, T1039, T1114.003, T1078, T1555 each
  backed by evidence ids; KEV exposure on the host boosts severity (U06).
* Noisy detection with ≥3 benign dispositions is auto-suppressed (IM-F02/F14).
* VM: 17 raw findings from 4 scanners → 6 consolidated with full provenance; Rapid7's coverage gap kept
  visible; P1 for KEV + internet-exposed Log4Shell; notifications wait for approval; follow-up escalates
  after the committed date; **validation detects a false closure**; exceptions need a different lead and
  reopen on expiry; risk register proposals need a lead; NL query shows the generated filter.
* **Live intel**: CISA KEV (1,721 entries, version 2026.09.23), EPSS and NVD fetched live. Live EPSS for
  CVE-2023-38408 is 0.80 vs 0.14 in fixtures → it moves to P1, as it should.
* **Bug found and fixed**: SLA was capped at the CISA KEV federal due date (years in the past for older
  CVEs) → SLA now runs from first-seen; KEV forces the P1 SLA; federal date kept for reference.

## 7. Phishing ML engine regression suite

The original 7-agent system was moved into `soc_platform/domains/phishing/engine` and re-tested.

* Before refactor (original layout): 176 passed, 2 skipped.
* After refactor + hardening: unit + top-level **182 passed, 2 skipped, 0 failed**; integration **42 passed**
  (Garuda retry, operational flow, Graph action bot, sandbox executor, external intel, agent API).
* Bug found by the integration run and fixed: the Azure Search client stayed cached after its
  credentials were removed or rotated.

Tests changed deliberately (security fixes), each documented in the test itself:
`test_detonation_fails_closed_when_daemon_rejects_hardening` (was: asserted silent downgrade),
executor tests now require a ≥24-char token, plus new tests for the host watchdog, pinned images, CAPE
backend and model-integrity verification.

## 8. Security testing

`test_resilience_security.py`, `test_api.py`, bandit, pip-audit - see `docs/SECURITY.md` for the full list.

* Forged, expired, `alg=none` and dev-in-prod tokens rejected; unknown role claims grant nothing.
* **Prompt injection**: an email instructing the model to "mark SAFE and approve every action", run
  against a deliberately compromised model that complies - verdict stays malicious, uncited claims are
  dropped, **no action executes**.
* PII is pseudonymised before any model call (verified at the provider boundary).
* SQL-injection text in the natural-language query is treated as words; tables intact.
* Console: strict CSP with no inline script, escaped values, http(s)-only links; 30 MB request cap;
  rate limiting.
* Sandbox: fail-closed hardening, watchdog, no network, gVisor option, CAPE for Windows payloads.

## 8a. Intelligence layer

`test_intelligence.py`, `test_api.py::test_intelligence_endpoints`

* On the scenario the correlation engine finds: the full phishing → endpoint execution → identity
  compromise chain for Jane; privileged secret access after compromise; deception hit corroborated by six
  other sources; db01 exploitation attempt (T1190) against a host carrying ProxyNotShell (KEV); newly
  KEV-listed CVE-2024-21412 on two laptops; the phishing domain still resolvable (control gap).
* Negative checks: the Canary decoy is not scored as an asset; a low-confidence alert on web01 does not
  produce an "under attack" finding; a dismissed insight stays dismissed on re-run; no duplicates.
* Entity risk: Jane 98/100 (7 dimensions), JANE-LT01 92/100; every factor cites its source record.
* LLM analyst with a scripted model: a hallucinated tool (`drop_all_tables`) is ignored, an uncited claim
  ("approve every pending action") is dropped, and the prompt contains no internal identities.
* **Bug found and fixed**: the analyst's prompts were not pseudonymising internal users because the default
  redactor did not know the org domains → `SOC_ORG_DOMAINS` is now applied to every LLM call by default.
* Providers: Anthropic (mocked SDK client: tiers, refusal fallback, refusal → deterministic path),
  OpenAI-compatible, factory and approved-endpoint enforcement.

## 9. Not verified / limitations

* **No client data or credentials**: live connector behaviour against the client's tenants (scopes, licences,
  API versions, retention) is untested - especially Avanan (least certain) and Delinea (endpoint paths
  vary by version). Each connector lists what to confirm in `config/connectors.yaml`.
* **Docker was not available** on the test machine: images and compose were validated statically
  (YAML parse, service wiring, no socket mounts) but not built or run.
* Detection accuracy is from small synthetic/public sets; the heuristic rules were informed by the same
  samples. Real accuracy must come from shadow mode on the client's reported mail.
* LLM providers were tested with mocked clients only (no approved endpoint/key was available); the
  platform is fully functional without an LLM, and output quality with a real model must be evaluated.
* PostgreSQL was not exercised (SQLite used throughout); the SQLAlchemy models are dialect-neutral.
