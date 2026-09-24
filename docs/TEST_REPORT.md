# Test report - Agentic SOC platform

Date: 2026-09-24 · Environment: Windows 11, Python 3.11.9, CPU only · Branch: `main`

This report covers what was tested, on what data, what was found, what was fixed, and what can
**not** be claimed yet. Accuracy figures below come from synthetic or public data; they are design
evidence, not a statement of performance in CCI's environment. That is measured in shadow mode against
CCI's own analyst dispositions (PH-T08, NFR-15), which the platform records automatically
(`/api/v1/metrics/shadow`).

## 1. Summary

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

No CCI credentials were available, so every connector has a **fake mode** that feeds the *same connector
code* (requests, pagination, normalisation) with vendor-shaped JSON. Fixtures are generated from one
consistent scenario (`scripts/build_fixtures.py`) so that data from different tools corroborates or
contradicts itself the way real tool data does:

* **Tenant `cci-demo.com`** (fictional): 8 users (incl. a VIP CEO), 5 hosts, 1 Canary file share.
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

* **No CCI data or credentials**: live connector behaviour against CCI's tenants (scopes, licences,
  API versions, retention) is untested - especially Avanan (least certain) and Delinea (endpoint paths
  vary by version). Each connector lists what to confirm in `config/connectors.yaml`.
* **Docker was not available** on the test machine: images and compose were validated statically
  (YAML parse, service wiring, no socket mounts) but not built or run.
* Detection accuracy is from small synthetic/public sets; the heuristic rules were informed by the same
  samples. Real accuracy must come from shadow mode on CCI's reported mail.
* LLM providers were tested with mocked clients only (no approved endpoint/key was available); the
  platform is fully functional without an LLM, and output quality with a real model must be evaluated.
* PostgreSQL was not exercised (SQLite used throughout); the SQLAlchemy models are dialect-neutral.
