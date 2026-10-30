# Test report - Agentic SOC platform

Date: 2026-10-30 (rounds 15-31; earlier rounds 2026-09-24 to 2026-09-30) · Environment: Windows 11, Python 3.11.9, CPU only · Branch: `main`

This report covers what was tested, on what data, what was found, what was fixed, and what can
**not** be claimed yet. Accuracy figures below come from synthetic or public data; they are design
evidence, not a statement of performance in the client's environment. That is measured in shadow mode against
the client's own analyst dispositions (PH-T08, NFR-15), which the platform records automatically
(`/api/v1/metrics/shadow`).

## 0. Round 31 (2026-10-30) - latest results: code review of every module, and the ownership mapping upload

Aim: two requests. (1) Review all the code for bugs and gaps. (2) Wiz has no CMDB, so cloud resources had no owning
team: let a lead upload a file of resource / subscription -> owning team.

| Found or built | Fix and check | Evidence |
|---|---|---|
| The hardened .xlsx / .docx / .pptx reader refused a DTD only when written in ASCII: the same declaration in a UTF-16 part passed the byte check | One check for both readers (`core/text.unsafe_xml`): UTF-16 byte-order marks and NUL bytes are refused with the DTD / entity check (watch lists, ownership mapping, report templates) | UTF-16 workbook test in `test_watchlists.py` |
| A single cell in column XFD made every row 16,384 cells wide | Columns past 256 are ignored | `test_a_cell_far_to_the_right_is_ignored_instead_of_widening_every_row` |
| A listed IP written differently by a tool (an IPv6 address in long form or upper case) did not match | Addresses are compared in canonical form on both sides | `test_ip_addresses_match_whatever_form_a_tool_wrote_them_in` |
| A tiny PNG declaring gigapixels reached the decoder | Refused as a decompression bomb with the logo's size rule | `test_a_tiny_png_claiming_gigapixels_is_refused_not_decoded` |
| The audit export's "how to verify" text did not state the hash recipe exactly (timestamp form, key order, escaping) | The recipe is a constant, written into every export; a test re-verifies an export using that text alone | `test_the_written_recipe_alone_re_verifies_an_export_without_the_platforms_code` |
| An event-type filter containing `%`, `_` or `\` acted as a wildcard | Escaped in the prefix match | `test_an_event_type_prefix_with_like_wildcards_or_backslashes_matches_literally` |
| A quote in a user, host or indicator name could change a vendor query (Graph / Defender OData filters, CrowdStrike FQL) or a URL path | Every value is escaped for its query language (`odata_str`, `fql_str`, `path_part` in `connectors/tools/_common.py`) | `test_a_quote_in_a_name_is_escaped_in_every_vendor_query_and_cannot_change_it` |
| The forensic collection action accepted any CrowdStrike RTR command | Read-only commands only (a precondition and a check in the call); a failure to close the session is logged, not raised over the collected output | RTR test in `test_tool_onboarding.py` |
| An Avanan sign-in answer without a token raised a bare `KeyError` | A connector error that names the likely cause (base URL / region) | 4 cases in `test_tool_onboarding.py` |
| The browser tour's clean-up failed when Windows still held the demo database open | Retries, then a note (the tour itself had passed) | browser tour |
| **Ownership mapping** (`core/ownership.py`, *Cloud posture* screen): Excel / CSV upload of resource name or pattern, subscription, cloud, resource type -> team, owner, environment, criticality; preview with how many unowned misconfigurations and findings it would cover; export; clear; versions; `manage_ownership` (lead, automation admin, admin; never an API key); audited | Fills only the gaps the CMDBs leave (ServiceNow, then `cmdb_csv`) and never overrides them; exact name beats pattern beats subscription; cloud and type narrow a row; every unusable row named with sheet and row; the same hostile-file refusals as watch lists | `test_ownership.py` (7 tests) |

Nothing changes in Wiz or the cloud: cloud posture still notifies, routes and validates.

**In the browser.** The browser tour: 35 screenshots, **0 problems, 0 accessibility notes**. The ownership card renders
on the Cloud posture screen. Lint, bandit, `pip_audit`, the supply-chain check and the pre-commit scan are clean.

**Counts:** 896 passed, 16 skipped on SQLite; 895 passed, 17 skipped on PostgreSQL 16 (912 collected; 18 new tests).
The demo is unchanged, because the mapping starts empty.

## 0.00000 Round 30 (2026-10-29): watch lists, audit exports, report style, models by name, tool onboarding review

Aim: five client requests. (1) Upload a **block list** and an **exception list** - users, hosts, IP addresses,
domains, URLs, hashes, as Excel sheets - and have every case that involves a listed item say so. (2) Export the
audit trail in the formats reviewers ask for, and state the facts about the audit log (retention, protection,
access) on its screen. (3) Upload templates, a logo, brand settings and a writing guide (a "skill") so reports
follow the client's design and style. (4) Choose AI models by name (gpt-4.1-nano, gpt-4.1-mini, gpt-4.1) instead of
"small / large", with room for more. (5) Check every tool integration against the vendor's current
documentation so onboarding has no surprises, and flag what must be confirmed.

| Built | How it was checked | Evidence |
|---|---|---|
| Watch lists (`core/watchlists.py`, *Govern -> Watch lists*): .xlsx (every sheet) or CSV upload with preview, add / replace, remove, CSV export; lead only (`manage_watchlists`, MFA, never an API key); every change audited with its values | Parsing of a workbook written by a real spreadsheet library (openpyxl, committed as `tests/data/watchlist_sample.xlsx`) and of an Excel-style shared-strings workbook; typed columns, a *Type* column, header-less lists, `DOMAIN\user`, `Name <address>`, numeric cells; every rejected value with sheet and row | `test_watchlists.py` (10 tests) |
| The .xlsx reader is the platform's own (no new dependency): a part declaring a DTD or entity is refused (XXE / entity expansion), unpacked parts and the file are size-capped, old .xls refused with a fix | Hostile workbook, fake zip, old Excel and an oversized file each refused with a reason | `test_unreadable_or_hostile_files_are_refused_with_a_reason` |
| Matching on the case's people (address, account name; a bare name only in the organisation's domains), hosts (name, FQDN, short name, IP, device ids) and indicators (a domain also its sub-domains, senders and links); case page banner, case list badge, investigation record section | Identifiers taken from the estate's own cases (no sample names in the test); severity, verdict, confidence and actions of every case compared before and after an upload - identical; an outside sender sharing a listed user name is not matched; *replace* and removal apply to every case at once | `test_watchlists.py` |
| Audit exports (`core/audit_export.py`): JSON Lines (default, unchanged), JSON, CSV, Excel, Word; filters by period, event type (prefix), actor, subject; every export audited | An unfiltered JSON export re-verified outside the platform (each hash recomputed); every .xlsx part parsed as XML and the workbook opened by openpyxl (outside the repo); CSV formula guard; control characters and 40,000-character cells handled; permission and all-domain scope enforced | `test_audit_export.py` (8 tests) |
| Report style (`reporting/style.py`, *Reports -> Report style*): Word template (.docx / .dotx), PowerPoint template (.pptx / .potx, 16:9), logo, brand (organisation, colours, font, classification, footer), writing guide; a .zip style pack; preview; reset; lead / admin only, versioned and audited; applied to every Word report and deck through a context (no mixing between concurrent reports) | Templates made in-test (incl. .dotx / .potx content types and a template without heading styles), the template's header kept and its sample text removed, the deck's sample slide removed, a 4:3 deck refused, a logo on cover / header / title slide and re-encoded as PNG; macro, DTD, zip-bomb and unknown files refused with nothing half-applied; files stored in `blobs`; the guide reaches the model prompt below the grounding rules while figures stay identical with and without the model | `test_report_style.py` (17 tests); `test_report_design.py` unchanged and passing |
| Models by name (`usage_policy.models()`, `SOC_LLM_MODELS`): each feature picks gpt-4.1-nano, gpt-4.1-mini or gpt-4.1 (more by setting); prices per model; advice names the model to try; *Check which models answer*; per-model version pins; older tier-based policies read as the matching models | The chosen model reaches the Azure, OpenAI-compatible and Anthropic providers; defaults follow the configured deployment (one deployment still serves everything); an undeployed model is refused on save; a legacy saved policy is upgraded on read; the model check is admin-only and logged per model | `test_llm_usage.py` (7 new tests; 3 updated from tiers to models) |
| Tool onboarding review: every connector's endpoints, sign-in, permissions, paging and limits checked against the vendor's current documentation | Fixed: Defender for Endpoint `findbyip` called as the documented OData function (and its `Machine.ReadWrite.All` permission listed); Entra device registrations read from the audit log (Graph's per-user device lists refuse application permissions, which would have failed every identity lookup), each optional part of an identity lookup failing on its own (Identity Protection without P2, a mailbox outside the app's scope), `GroupMember.Read.All` listed (without it group and role names come back blank), Graph's per-tenant limits for audit logs and Identity Protection kept; CrowdStrike RTR output read back and the session closed (commands are asynchronous - the collection returned nothing); NVD asked with both dates in windows of at most 120 days (a start date alone is refused); Avanan tokens renewed from their own ~30-minute expiry and on a 401; the Defender for Endpoint host moved to `api.security.microsoft.com` (token audience unchanged). Flagged for confirmation: Delinea paths and rotation call, Privilege Manager API (per-console Swagger only), the Office 365 block-sender endpoint (undocumented) and remediation (Graph beta), admin targets needing a privileged role, Rapid7 cloud API v4, Sentinel's move to the Defender portal | `test_tool_onboarding.py` (10 tests, each tied to the documented vendor behaviour); fixtures regenerated from the builders (only the changed routes); `docs/CLIENT_DEPLOYMENT_GUIDE.md` section 4 and the review pack updated |
| *About this audit log* on the Audit screen (`GET /api/v1/audit/info`): records and period, by actor and kind, last full verification, retention of the log and of every other data class from the settings in force, protections, who may read and export | Figures equal the settings and the log's own counts | `test_the_audit_facts_are_read_from_the_log_and_the_settings` |

**In the browser.** The browser tour (Chrome; every screen, light + dark, layout audited at 1440 / 1280 / 1024 / 768 px,
axe-core accessibility scan, stored-XSS probe, every on-screen count cross-checked against the API; the Watch lists
screen added to its route list) first found 14 layout problems, all in this round's screens: the report-style form's
fields clipped at half width, the new model table needing 107 px of sideways scroll at 1280 px, and model names breaking
at their hyphens. Fixed (the style cards and the model table take full rows; model names do not wrap); the final tour:
35 screenshots, **0 problems, 0 accessibility notes**. A functional run through the console as lead, auditor, analyst
and administrator (35 checks: preview and upload of an Excel and a CSV list, case badges and banner, removal, the
investigation record's section, a style pack, brand, both previews, a report built in the style, reset, every audit
export format and a filtered one, read-only views per role, model choice and the model check, markup in a list note and
the organisation name shown as text) passed 35 of 35 with no browser error after fixing a **bug that predates this
round**: the console's download helper parsed any response whose type contained "json", so JSON Lines and JSON
downloads (the Reports screen's audit export among them) never started; downloads now take the response as it is.
Every downloaded file was opened: the .xlsx by openpyxl, the .docx / .pptx by python-docx / python-pptx, the JSON
exports' chain verification reads `ok`.

Found and fixed on the way: upper-case URL schemes and hashes were not recognised as URLs / hashes (tests written
first); FEATURES.md still called autonomy level L1 "notify" (the code: enrich). Checked in a browser: the new screen,
the case banner and badges, the upload preview and the Audit screen as lead, analyst and auditor (no console errors).

**Counts:** 878 passed, 16 skipped on SQLite; 877 passed, 17 skipped on PostgreSQL 16 (894 collected:
52 new tests since round 29, and 6 more cases from the existing sweeps over every route). The demo is unchanged (both lists start
empty). Lint and bandit clean.

## 0.0000 Round 29 (2026-10-22): the demo script checked claim by claim

Aim: make every statement in the client demo video script true of the running system. Each claim was checked against
a freshly reset demo (every screen's API answer) and against the code; where the system fell short, the system was
fixed rather than the script softened.

| Found | Now | Evidence |
|---|---|---|
| **Four-eyes was one person for the platform's own recommendations**: a single lead's approval ran an isolation, password reset, campaign purge, domain block or secret rotation, while the screens, the client review pack and the deployment guide said a second person approves | Two different people: the first approval is recorded and audited (`action.first_approval`), nothing runs until a second, different lead approves; the same lead twice is refused; the compliance pack fails an agent-recommended four-eyes action executed on one approval | `test_core_governance.py` (two new tests), `test_feature_checks.py`, `test_api.py`; SECURITY.md finding 20, ENGINEERING.md decision 99 |
| The attack story filed LDAP reconnaissance under Initial Access and file-share enumeration under Execution, while reporting "no evidence of discovery" - the vendors' own techniques (T1087.002, T1135) were not read | Vendor techniques, sub-techniques (parent fallback) and vendor tactic names are read: both steps are Discovery | `test_story.py::test_vendor_techniques_put_reconnaissance_under_discovery` |
| The story's blast radius and response plan included cases found benign (the spam and the legitimate invoice the same person received), with their links and senders | Cases with a benign verdict are not part of a story | `test_story.py::test_a_benign_case_about_the_same_person_is_not_part_of_the_attack` (fails without the fix) |
| The story's "legitimate IT work" rejection named unrelated domains (portal.azure.com); its verdict counted 9 tools while its summary said 10; a signal list ended ", )" | Only the matching domain; both counts stated ("9 tools (1 more blocked a step)"); the list complete | `test_story.py` |
| Incident severity factors were stored but never shown | Incident cases show "Why &lt;severity&gt;": every fixed rule that set the severity and confidence | console |
| Risk factors (+50, +40 ...) added up to far more than the score of 100 with no explanation | The entity view shows the points total and the curve (score = 100 x (1 - e^(-points / 60))); the API returns `points` | `test_intelligence.py::test_the_score_is_explained_by_points_on_a_curve_that_never_passes_100` |
| Evidence references showed nothing on hover (a browser tooltip that rarely appears, repeating the fact) | A popover on hover or keyboard focus (tool, time, evidence); a click scrolls to the evidence row; on the case and the story | console |
| Preflight warned "the newest record is 31 days old" on fixed sample data - three tests failed as the sample dates aged | Freshness is judged for live tools only | `test_connector_admin.py` |
| A server started without `.env` answered sign-in with "disabled on this server" and logged nothing | `serve` prints whether development sign-in is on and, if not, why | `test_cli.py::test_serve_says_at_start_why_development_sign_in_is_off` |
| ATT&CK chips without a name (T1190); insight titles saying "other" and "privileged_access"; the recommended-actions "#" column showing a sort weight (10, 11, 20 ... 90) | Named from the technique catalogue; "SIEM" and "privileged access"; the rank 1..N | console |

**Live data, not demo data:** no pipeline code holds a demo value (a search of all platform code outside tests and
sample data for demo names, hosts, domains, CVEs and ids found only comments, connectors' sample-data settings, the
dev sign-in default and the `demo` command). Not provable here: a run against a real tenant - the record / read /
recommend stages and the preflight exist to find vendor differences before anything acts.

**A fresh clone, followed as a newcomer would** (cloned from GitHub into an empty folder, installed from zero, the
README run step by step): code, fixtures, corpus and the Git LFS models all arrived; the demo matched this machine
figure for figure; 55 tests passed in the clone, the engine's included. Three things stopped a newcomer and are fixed:
the first command failed ("unable to open database file" - `.env.example` puts the database in `./data/`, which git
ignores and SQLite does not create; the platform now creates the folder); the README never loaded `.env` (sign-in was
disabled, and the demo and the server used different databases); `config check` called a template setting
(`SOC_APP_DB_PASSWORD`, used by Compose) unknown. Regression tests: `test_data_tolerance.py` (both fail without the fixes).

**Counts:** 820 passed, 16 skipped on SQLite; 819 passed, 17 skipped on PostgreSQL 16 (836 collected; the SQLite
database-folder check skips on PostgreSQL). Lint clean.

## 0.00 Round 28 (2026-10-20): Python 3.13, and figures that aged with the calendar

Aim: answer "does the whole system run on Python 3.13?" by installing and testing it there, on Linux, against
Python 3.11 on Linux (the production image) and Windows (development). Running it two days after round 27 exposed
something more important: the sample data had crossed 30 days of age, and three parts of the platform aged out with
the calendar.

| Found | Now | Evidence |
|---|---|---|
| Incident clustering looked back 30 days from the wall clock: 30 days after the sample alerts the demo had **one incident instead of three** (and a backfill after an outage would lose its own) | The window ends at the newest alert (capped at now); live data is unchanged | `test_incident_clustering_is_anchored_to_the_alerts_not_the_wall_clock` (0 / 45 / 400 days later; fails on the old code) |
| Risk's "now" was the newest record of any kind - but people, hosts, indicators and findings are "seen" at every directory or scanner sync - so "now" was the wall clock and the top user fell from critical, three correlation rules stopped firing | "Now" is the newest event (alerts, sign-ins, e-mail, DNS, deception, secret access, elevation) | `test_risk_and_correlations_do_not_age_out_with_the_calendar` (0 / 45 / 400 days; fails on the old code), `test_intelligence.py` |
| Reported e-mails were stored with the processing time, which also moved every recipient to "today"; a phishing click was dated by when its case was created, so it never decayed | E-mails carry their Date header (else the mailbox's received time); clicks their click time | same tests; `test_activity_decays_by_half_every_half_life_but_open_exposure_does_not` |
| Eight processes creating a new SQLite schema at once: "database schema has changed" was not retried (seen on the newer SQLite of the 3.13 image) | Retried like "already exists" | `test_many_processes_creating_the_schema_at_once_all_succeed` on Linux 3.13 |
| The API test module mixed month-old sample data with alerts pushed "now" | Its clock is placed in the sample's era (restored at teardown) | `test_api.py` |
| An engine test asserted a developer's `.env` value instead of the default | Reads the real defaults | `test_config_settings_30gb.py` |
| `pip install -r requirements/dev.txt` failed on 3.13 (`pgserver`, test-only, has no 3.13 build) | Marker: skipped on 3.13 | dev install on 3.13 succeeds |

**Python 3.13:** every platform and engine dependency installs on 3.13 at the locked versions (scikit-learn 1.8.0 -
the trained models' version - numpy, scipy, pandas, xgboost, lightgbm, psycopg2-binary, pydantic, SQLAlchemy,
FastAPI, cryptography, langgraph); no removed standard-library module is used. Linux 3.13: platform 802 passed with
3 failures, all also explained on 3.11 (the two above, plus `test_ci_runs_every_gate`, which needs a git checkout the
test container did not have); ML engine 203 passed, 0 failed; the ML engine inside the platform 16 passed; demo ran.
After the fixes, the affected files on 3.13: 112 passed, 0 failed. Linux 3.11 behaved the same (803 passed, the same
two explained failures; engine 203 passed). **Nothing failed on 3.13 alone** except the SQLite start-up race, fixed.

**Counts:** COUNTS_PLACEHOLDER

## 0.0 Round 27 (2026-10-18): functional review (does every output mean what it says)

Aim: run the platform end to end on a fresh database and judge each output against the platform's intent, not only
against "no error". Checked: the demo's totals, every incident's severity and recommendations against its evidence,
phishing verdicts against the labelled corpus (all three backends), identity and asset resolution at scale, every
correlation insight, analyst answers about named people and hosts, vulnerability priorities and SLAs, every piece of
analyst-facing evidence text, the generated Word / PowerPoint reports, and the console (browser tour).

| Found | Now | Evidence |
|---|---|---|
| The internet-facing, business-critical web server with Log4Shell had an "unusual outbound connection" alert that stayed **medium with no recommendation**, and the exposure-informed rule (U06) skipped it as a "weak alert" - the very case U06 exists for | KEV exposure on an internet-exposed or business-critical host makes an incident at least high; U06 counts a weak alert on an internet-exposed vulnerable host (elsewhere still medium and above) and cites the exposure | `test_an_alert_on_an_internet_facing_critical_host_with_a_kev_cve_is_at_least_high`, `test_cross_domain_correlations`; demo: web01 high, 3 recommendations, U06 insight |
| The EDR that raised the alert reported the host **"not found"**: Falcon was searched by host name although the platform held its device id; MDE's fallback `startswith(name)` would also return `web010` for `web01` (another machine's alerts) | Look-ups go by the vendor device id first; the name fallback accepts only the host itself | `test_a_host_lookup_uses_the_known_device_id_and_never_matches_a_similar_name` |
| Evidence read "CVE-2021-44228 **(CVSS None)**": the CVSS came from whichever scanner row was kept last | NVD intelligence first, else the highest scanner value, omitted when unknown; every reporting scanner listed | incident test above (`CVSS 10`, four scanners) |
| Analyst answer: "**23** containment actions for this entity" when 5 targeted the person - every action on any of their cases was counted | Counts actions whose targets name the entity; the rest reported as "N more on its cases" | `test_the_analyst_answers_about_the_entity_named_and_counts_only_its_own_actions` |
| "What is happening with jane-lt01" opened with 17 organisation-wide findings; a medium finding was called "the most serious" next to critical ones | A named entity scopes the answer; organisation-wide lists only for organisation-wide wording; findings ordered by severity, then score | same test |
| Evidence text showed Python renderings to analysts and the model: `risk=['Low']`, `destinations: []`, `signer=None`, `MFA: ['…']`, `ownership: {'owner': …}` | Normalised where evidence is stored (both paths), CMDB owners written as text; linear on hostile input | incident test above (no reprs), redaction / hostile-input timing |
| Falcon and MDE fake-mode fixtures answered by-id and per-device queries for one laptop only | Generated for every device (`build_fixtures.py`); only those two fixture files changed | fixtures regenerated, byte-identical elsewhere |

Confirmed correct (no change): the demo's totals (7 + 3 cases, 6 open vulnerabilities; pending approvals now 37,
incident 18 - web01's three); phishing combined backend 20 / 20 exact on the labelled corpus (heuristic 18, engine 18;
detection 100 %, false positives 0 %; the supplier bank-change e-mail is labelled suspicious); identity resolution on
300 people with 6 naming conventions: 0 false merges, 0 splits; asset resolution on a 400-host messy estate: 0 false
merges, 94.6 % match rate, 77 records left to the analyst queue (the designed trade-off: a split is recoverable, a
wrong merge is not); vulnerability priorities (Log4Shell on the internet-facing critical server first; a CVSS 9.8
OpenSSH flaw without known exploitation P2) and SLAs (a KEV CVE takes the 7-day SLA whatever its band - documented);
reports: 0 placeholder leaks in 380 text blocks; browser tour: 34 screenshots at four widths, light and dark, every
on-screen count cross-checked with the API, 0 problems.

**Design decision reversed - please confirm:** U06 previously required a medium-or-higher alert, and a test pinned
web01 as excluded ("weak alert only"). It now also counts a weak alert on an internet-exposed vulnerable host. To
restore the old behaviour, revert `_exposed_host_under_attack` in `intelligence/correlation.py` and the
`exposed_or_critical_host_with_kev` rule in `IncidentService._score`.

**Counts:** 801 passed, 16 skipped (817 collected) on SQLite and on PostgreSQL 16. Lint and lock checks clean.

**Still open against the requirements** (implemented, completion needs the client - REQUIREMENTS_TRACEABILITY.md 🟡):
live-tenant verification of every connector, the client's report and risk-register formats, performance targets on
client baselines, and IM-T09 (re-hosting Volatility / Ghidra / YARA analysis of collected forensic artefacts - not
built).

## 0.1 Round 26 (2026-10-18): go-live review (architecture, infrastructure, security)

Aim: a senior-architect review of everything that could fail or be abused in production, then fix every finding.
The full list, with severities, is SECURITY.md "Go-live review"; each row here names its evidence. New tests:
`test_go_live_hardening.py` and additions to the access, governance, pentest, HA, deployment-manifest, context
and supply-chain files.

| Found | Now | Evidence |
|---|---|---|
| A deployment without `SOC_ENVIRONMENT` ran as `dev`; Compose defaulted to dev sign-in with remote token minting - any role for anyone reaching the port, with live tools | Fails closed: image defaults to prod; settings check refuses dev + live, an unset environment with Entra / live tools, a dev secret < 32 characters; every live tool isolated while dev sign-in is on; the demo is an explicit Compose override | `test_a_real_deployment_that_forgot_its_environment_is_refused`, `test_development_sign_in_isolates_every_live_tool`; the image refused to start unconfigured |
| Vendor write calls ran inside the open transaction holding the audit-chain lock; a failed commit after a successful call lost the action's record | Committed `executing` before the call, outcome after; deferred execution inside savepoints; `actions` job; stuck executions become `unverified` findings | `test_the_tool_call_runs_after_a_durable_executing_record_and_holds_no_lock` (a second connection reads `executing` and appends to the audit chain during the call), `test_an_action_left_executing_is_marked_unverified_never_rerun`, `test_an_action_approved_inside_a_savepoint_runs_after_the_commit`, `test_a_deferred_autonomous_action_is_held_when_the_kill_switch_comes_on` |
| `SOC_TRUSTED_PROXIES` ranges (both overlays) never matched | CIDR support | `test_trusted_proxies_accept_a_gateway_subnet` |
| The upload route blocked the event loop | Thread pool, narration after commit | `test_api.py` |
| Rollback bypassed the policy; privileged grants single-person; kill switch released by an administrator | Rollback through the policy (release four-eyes); second-administrator approval and 90-day limit; release needs a lead | `test_l4_executes_autonomously_and_rollback_uses_reverse`, `test_rollback_goes_through_the_policy_and_cannot_skip_four_eyes`, `test_a_privileged_grant_needs_a_second_administrator_and_an_end_date`, `test_only_a_lead_turns_the_kill_switch_back_off` |
| Credentials followed any absolute next link | Same origin only | `test_credentials_never_follow_a_next_link_to_another_host` |
| Database: unverified TLS, no statement / idle limits, application role owned the schema | `verify-full` required in prod; 300 s / 600 s; owner / runtime split, append-only trigger and grants | `test_production_needs_a_verified_database_connection_...`, `test_audit_chain_verifies_and_detects_tampering` (trigger first refuses the edit); **live on PostgreSQL 16 (Compose)**: the runtime role was refused UPDATE on `audit_log` and CREATE TABLE, a non-TLS connection was refused by `pg_hba`, the triggers and six trigram indexes existed, and the whole `demo` workload ran as the runtime role with an intact chain |
| LLM allow-list open when empty | Mandatory, https-only in prod | `test_prompts_go_only_to_an_approved_https_endpoint_in_production` |
| Anonymous `/health` re-hashed the whole audit log and disclosed version and state | Minimal anonymous answer; incremental verification from the self-check's checkpoint; heads anchored hourly; `audit verify --anchor` | `test_health_tells_anonymous_callers_only_that_it_is_up`, `test_health_verifies_only_new_records_after_a_full_pass_and_keeps_a_failure`, `test_audit_verify_checks_heads_shipped_to_the_log_pipeline` |
| Break-glass secret in every request; unthrottled audited failures | 15-minute session exchange; throttle | `test_break_glass_is_exchanged_for_a_short_session_and_guessing_is_throttled` |
| Pseudonymisation missed accounts, host names, internal IPs; parallel narrations shared one pseudonym map | Covered; one map per call | `test_redaction_covers_accounts_internal_hosts_and_addresses_not_just_e_mail`, property tests (round trip, public indicators kept); hostile 200 KB inputs redacted in 0.02-0.15 s |
| Entra v1 tokens refused, no skew, app tokens as people | Fixed | `test_entra_tokens_are_verified_strictly` |
| Unsealed stored data accepted in prod; no rotation path | Refused; `blobs reencrypt` | `test_production_refuses_unsealed_blobs_and_reencrypt_seals_them_and_retires_a_key` |
| Supply chain: engine dependencies unpinned and unscanned; tags everywhere; the CI image-scan action's tag no longer existed | Hashed Linux locks, digests and commit SHAs, both images scanned, signed releases | `test_images_and_packages_are_pinned_so_a_moved_tag_cannot_change_what_runs`, `test_the_container_build_is_constrained_by_the_lock`; pip-audit of both locks: no known vulnerabilities; Trivy of the built platform image: 0 fixable high / critical |
| Kubernetes: Azure ingress policy would block AGIC; on-prem default-deny cut the database pods off; database egress to any address; Key Vault secrets synced into etcd; no workload-identity annotation | Fixed in the overlays | `test_azure_keeps_secrets_out_of_kubernetes_and_onprem_lets_the_database_talk`, `test_only_the_migration_step_holds_schema_rights`, both overlays rendered with kubectl |
| Compose: no TLS proxy, Redis open, engine in development mode, unbounded logs, no limits or backups; the scheduler could never be healthy | Fixed; production stack run end to end | `test_production_compose_fails_closed_and_the_demo_is_an_explicit_override`; live run (above) |
| No infrastructure as code, no external alerting | `deploy/azure/main.bicep` (compiles, no warnings), ServiceMonitor and alert rules, new metrics | `test_a_service_key_can_be_sent_as_bearer_for_scrapers_and_metrics_cover_what_alerts_watch`; `az bicep build` |

**Counts:** 798 passed, 16 skipped (814 collected) on SQLite and on PostgreSQL 16 (embedded server, which lacks
`pg_trgm`, so the search-index fallback ran there; the Compose PostgreSQL 16 has it and built all six indexes).
Feature verification (offline, `scripts/verify_features.py`): 104 of 108 verified, 229 mapped tests run, 0 failed;
the 4 not run are the opt-in live features (real LLM endpoint, public NVD / EPSS / KEV feeds), not re-run this round
(`--live --llm` calls the paid model). Browser tour and ML engine suite not re-run this round either. Lint, bandit and the lock checks
clean. **Not proved here** (go-live steps): a Bicep `what-if` in the client's subscription, the failover drill on the
real cluster (CloudNativePG policies and pooler certificate), admission enforcement of signatures.

## 0.2 Round 25 (2026-10-17): no single point of failure, and the value scorecard

Aim: make the platform run with no single point of failure, on premises or in the cloud, and measure the benefits the
customer is promised. Each row is something found and fixed; the tests named fail without the fix.

| Found | Now | Evidence |
|---|---|---|
| Reported e-mails and reports were saved on one host's disk; another replica could not read them (a report the scheduler built could not be downloaded through the API) | `SOC_BLOB_STORE=database`: rows in `blobs`, encrypted, checksummed, committed with their record; `blobs migrate` moves existing files; reads follow each record's reference | `test_high_availability.py`; Docker: a report built by the scheduler container downloaded through the API container |
| Job leases were a fixed 30 minutes: a crashed scheduler stalled even the 2-minute phishing job for half an hour | 120-second lease renewed every 40 s while the job runs; taken over within one lease; stops renewing past the stuck threshold so a hung job can be retried | `test_a_job_whose_scheduler_died_is_taken_over_after_one_lease`, `test_a_running_job_keeps_its_lease_...`, `test_a_job_that_runs_past_the_stuck_threshold_...` |
| One reported e-mail or incident that raised an unexpected error failed its whole job, which was dead-lettered and held up every other e-mail | Each item in its own savepoint; recorded, audited, retried on the next 3 runs, then left to an analyst; waiting submissions picked up next run | `test_one_failing_email_never_holds_up_the_others_...`, `test_one_failing_incident_...` |
| Eight connections opening a new SQLite file together failed on the WAL switch; every process creates the schema on first use | WAL switch retried; schema creation serialised (PostgreSQL advisory lock, a safeguard - the race did not reproduce there) | `test_many_processes_creating_the_schema_at_once_all_succeed` (both engines) |
| A liveness probe on `/health` would restart every pod during a database outage | `/health/live` (no database) and `/health/ready` (database, 503 + Retry-After); scheduler pods get a local liveness file | `test_liveness_never_depends_on_the_database_and_readiness_does`, `test_the_scheduler_touches_its_liveness_file_...` |
| Signed-in analysts were rejected five minutes into an Entra key-endpoint outage | Signing keys kept per process by key id | `test_signed_in_analysts_keep_working_when_the_entra_key_endpoint_is_unreachable` |
| The Docker check: `demo` and the scheduler synced one stream together and one failed on a duplicate first checkpoint | A per-stream sync lease (wait, then continue from the checkpoint; or skip and say so); the first checkpoint insert tolerates a lost race | `test_two_syncs_of_one_stream_at_once_take_turns_and_both_complete`, `test_a_stream_held_by_another_replica_...`; Docker: `demo` during the scheduler's first pass |
| The docs said raw vendor payloads were stored; production never stored them | Opt-in `SOC_STORE_RAW_PAYLOADS` through the blob store, under raw retention; docs corrected | `test_switched_on_original_payloads_go_to_the_blob_store_...`, `test_original_vendor_payloads_are_not_kept_unless_switched_on` |
| Only a single-host Compose file existed | Kubernetes package: base (2+ replicas of everything, zone / node spread, probes, disruption budgets, autoscaling, restricted pod security, default-deny network policy, init-db) + Azure and on-prem overlays | `test_deployment_manifests.py` (overlays rendered with kubectl) |
| The customer deck promised benefit KPIs "measured and reported"; nothing computed them against a baseline | Value scorecard: 8 KPIs against baseline and target (Overview card, board monthly and CISO weekly reports, `GET /api/v1/value/scorecard`); lead-entered baselines and time-study figures, audited | `test_value_scorecard.py` (exact figures from controlled timestamps, statuses, capacity, permissions, the board report) |
| The recurring reports were correct but plain: default Office styling, an empty second page, "n/a" shown, chart axes in steps of 0.5, a management deck of near-empty slides, and no "what to do today" | One house style for every report (`reporting/design.py`): cover, colour-coded tiles, charts beside the tables, styled tables, header with classification, footer with page X of Y; the daily report opens with *Act today*; the weekly deck runs from the week in numbers to the decisions needed; reports described in words (planned by the LLM, figures from code) get the same look | `test_report_design.py`; every page rendered through Word and PowerPoint and reviewed |
| Run on a messy estate 20 times the demo (179 findings, 253 assets, real-tenant disorder), the reports listed every host without EDR or CMDB entry in one cell (100+ names), the changes table showed 10 rows under a tile of 94 with no "more" note, and the same host lists filled the console card; in dark mode the bar charts' white numbers failed contrast | Lists show the count, the first names and "N more"; every capped table says how many more; bar charts carry no text on colour (totals and the split beside them, exact values on hover) | Reports re-rendered from the messy estate; browser tour on the messy estate: 0 problems |
| The working screens were mostly tables | Charts on Vulnerabilities (priority, team past / within SLA, age), Phishing (who clicked, reporters, handling), Approvals (by domain, by action type) and Cloud posture (severity, owner) | Browser tour at 4 widths, light and dark: 0 problems (it first caught chart labels cut with an ellipsis; they now wrap) |
| RUN_GUIDE's Compose steps omitted `RABBITMQ_PASSWORD`, which Compose checks for every service | Added to the guide | Docker check |

| Check | Result |
|---|---|
| Platform suite on SQLite | **772 passed**, 0 failed, 16 skipped (788 collected) - round 25; round 26: 798 / 814 |
| Platform suite on PostgreSQL 16 | **772 passed**, 0 failed, 16 skipped |
| Docker Compose (Docker Desktop 29) | API healthy on `/health/ready`; `demo` during the scheduler's first pass: 7 + 3 cases, 34 awaiting approval, 6 open vulnerabilities; 13 stored files all in the database and readable; a scheduler-built report downloaded through the API; everything survives a restart |
| Browser tour | 34 screenshots at 4 widths, light and dark, 0 problems (the new scorecard and dashboard charts included) |
| Feature verification | **108 of 108** with `--browser --engine --live --llm`: 240 mapped tests, 0 failed; browser tour with the live LLM 0 problems (35 screenshots); ML engine 205 passed; also a browser tour on a messy estate 20 times the demo: 0 problems |
| Lint / bandit / lock / JavaScript | clean / no issues / matches / clean |

## Round 24 (2026-10-15): supply chain, build pipeline and dev-VM security

Aim: close the gaps raised by the internal security preliminary assessment for the development VM.

| Gap | Now | Evidence |
|---|---|---|
| Dependencies were minimum versions only, no SBOM | `requirements/platform.lock` (50 packages, exact versions; the container build uses it as constraints) and a deterministic CycloneDX 1.5 SBOM (`scripts/supply_chain.py`); pip-audit over the lock: 0 known vulnerabilities | `test_supply_chain.py` |
| Gates ran only on the developer's machine | `.github/workflows/ci.yml`: lint, bandit, pip-audit, lock check, JavaScript syntax, secret and confidential-name scan, gitleaks, both test suites, SBOM, Trivy image scan | `test_ci_runs_every_gate` (the workflow itself runs on the first push) |
| No commit-time secret block | `scripts/precommit_scan.py` (git hook and CI); the name pattern lives outside the repository | `test_the_pre_commit_scan_blocks_secrets_and_confidential_names` |
| A `*_FILE` secret pointing at a missing or empty file left the secret silently empty | `config check` (and therefore `serve`) reports it as an error | `test_a_secret_file_that_is_missing_or_empty_is_an_error_not_a_silently_empty_secret` |

| Check | Result |
|---|---|
| Platform suite on SQLite | **713 passed**, 0 failed, 16 skipped (729 collected) |
| Platform suite on PostgreSQL 16 | **713 passed**, 0 failed, 16 skipped |
| Feature verification (`--browser --engine --live --llm`) | **108 of 108 features verified**; 240 mapped tests run, 0 failed; browser tour with the live LLM 0 problems (35 screenshots); ML engine 205 passed |
| ML engine warnings | the verification run showed 301 warnings (was 1): every one from the engine calling the Redis client's deprecated `setex` - replaced by `set(..., ex=ttl)` at all five call sites; engine suite rerun: 205 passed, 0 warnings; the platform's engine and phishing tests rerun: 29 passed |
| Container image (Trivy, fixable high / critical) | first scan: 2 high (the base image's setuptools vendored `wheel` 0.45.1 and `jaraco.context` 5.3.0); after upgrading pip: 4 high in pip's own vendored libraries (`msgpack`, `urllib3`, `setuptools`). Fixed: setuptools upgraded to the locked version, pip removed from the runtime image. **Final: 0**; the container starts, runs as the non-root user and `/health` reports ok |
| Lint / bandit / pip-audit (lock) / scan of tracked files | clean / no issues / 0 known vulnerabilities / clean |

## Round 23 (2026-10-14): the data handoff workbook's own estate, and what it exposed

Aim: test the platform on data built to the organisation's data handoff workbook rules, not only on the presenter demo.
A fourth test estate (`build_estate_variant.py --handoff`) carries the workbook's naming (`example.invalid`,
`analyst.demo`, `demo-laptop-01`), only private and RFC 5737 addresses, the full storyline plus the workbook scenarios
it lacked (OAuth consent after the click and a routine consent, a contradicting EDR verdict, two people on one public
IP, a stale device re-using a host name and address), and real-tenant volume. Measured through the connectors' own
parsers (`scripts/estate_profile.py`): **1,279 activity events, 89.5 % benign, 1.95 % replayed records**, delivered
out of order. Every multi-estate test now also runs on it, and `test_handoff_estate.py` checks the rules and each
scenario's ground truth. Results on the final code:

| Check | Result |
|---|---|
| Platform suite on SQLite | **707 passed**, 0 failed, 16 skipped (723 collected) |
| Platform suite on PostgreSQL 16 | **707 passed**, 0 failed, 16 skipped |
| Feature verification (`--browser --engine --live --llm`) | **108 of 108 features verified**; 240 mapped tests run, 0 failed; ML engine 205 passed; browser tour with the live LLM 0 problems (35 screenshots) |
| Production run (scheduled jobs only, demo and workbook estate) | every job ok; the storyline's correlation rules fire, incl. consent after phishing on the workbook estate |
| Configuration check / preflight `--all` / Compose | 0 errors, 0 warnings / 21 of 21 ready / valid (refuses to start without its passwords) |
| Demo seed | unchanged: 7 phishing + 3 incident cases, 34 recommended actions, 6 open vulnerabilities |

What the estate exposed, each fixed with a test:

| Finding | Effect | Fix |
|---|---|---|
| No scheduled job synced Entra directory audits | the consent-after-phishing rule could never fire in production | directory audits are synced with the alerts (`IncidentService.AUDIT_STREAMS`) |
| Defender for Identity had no look-up | its domain logons were never used as evidence | per-person / per-address look-up (`IdentityLogonEvents`, investigation window) |
| RFC 5737 documentation addresses counted as "private" | an attacker address in a synthetic estate was never checked against threat intelligence | documentation ranges are outside addresses; real private ranges still withheld |
| Switching estates in a test kept the learned record shapes | a shape learned on another estate's fixtures disabled type coercion for later tests | `estate_env` resets the shapes |
| The look-alike detector read "1" only as "l" and never "l" as "i" | `m1crosoft-...` and `mlcrosoft-...` senders were not flagged as imitating a protected brand (the workbook estate's supplier-impersonation finding was missing) | every reading compared; corpus still 100 % detection / 0 % false positives; 30 common legitimate domains raise nothing |
| The decay test compared two points in time strictly | it failed once the calendar passed 23 days after the fixture date (activity leaves the risk window) | a factor may leave only if its activity left the window |

## Round 22 (2026-10-12): the organisation's data handoff workbook, reconciled connector by connector

Aim: line the platform up with the organisation's security tool data types handoff workbook (13 tool families, 38
synthetic payload types, 17 correlation rules, 8 acceptance scenarios, generation rules, 21 integration rows) and make
each expectation either true in code with a test or listed as open. The answer is
`docs/DATA_HANDOFF_RECONCILIATION.md`. Results on the final code:

| Check | Result |
|---|---|
| Platform suite on SQLite | **682 passed**, 0 failed, 15 skipped (697 collected) |
| Platform suite on PostgreSQL 16 | **682 passed**, 0 failed, 15 skipped |
| Feature verification (`--browser --engine --live --llm`) | **108 of 108 features verified**; 240 mapped tests run, 0 failed; ML engine 205 passed; browser tour with the live LLM 0 problems (35 screenshots) |
| Lint / bandit / pip-audit / JS syntax | clean / no issues / **0 known vulnerabilities** / clean |
| Demo seed | unchanged: 7 phishing + 3 incident cases, 34 recommended actions, 6 open vulnerabilities |

What changed, each with tests:

| Workbook expectation | Before | Now |
|---|---|---|
| Microsoft Defender for Identity is one of the 13 tool families | no connector | `defender_identity`: alerts (Graph alerts_v2) and domain logon events (`IdentityLogonEvents`); people linked to Entra by the on-premises SID (a directory fact), machine accounts never people. 21 connectors = the workbook's 21 integration rows |
| PHISH-02: flag risky OAuth consent, no compromise without corroboration | consent audits ingested as plain directory events | rule `consent_after_phishing` (consent within 7 days after a click; "verify the application"); 4 negative cases |
| EDGE-01: conflicting EDR verdicts flagged, no autonomous containment | not detected | a tool's own disposition is normalised (`source_verdict`); a case where tools disagree carries the conflict as evidence and every action is capped at approval |
| VM-02: exception expiry tracked; accepted risk is not fixed | platform exceptions only | Rapid7 exceptions read and shown on the finding (in force / expired), never applied |
| Privileged identity: explicit admin -> person mapping | none | approved `account_owners` map on Secret Server; never inferred from the account name |
| Ticket evidence keeps the original alert ids | ticket carried the case id only | platform tickets list `tool:alert id` of every alert on the case |
| Field dictionary | - | added: Defender alert IP evidence, Entra correlationId / appId / authenticationRequirement, Umbrella return code, Wiz rule id, ServiceNow priority / opened / resolved / assignee / CI / parent |

The full runs (680 passed on each database) caught one leak: the help text of the new Secret Server setting used a
demo name as its example, shown by the connectors API on every generated estate; replaced with a neutral placeholder,
the 2 affected route-sweep tests re-run on both databases and passing.

Found while building it: the new hunting stream applied the watermark's 30-minute overlap between pages of one sync,
so a busy stream would re-read its first rows and stall; a continuation now asks from the exact newest time (overlap
only between syncs) - `test_connector_defender_identity.py`.

Checked and already aligned (now proven by named tests): a blocked click never counts as a click-through; a name alone,
or a re-used name and address at another time, never joins two devices (review queue); a unique name plus the same
address inside the IP window and the same OS family joins the two tools' records (the workbook's "host name plus
inventory and time"); people sharing a public IP stay separate; one hash seen by two tools is one indicator.

Open (in the reconciliation document): a workbook-conformant synthetic estate (`example.invalid`, RFC 5737 addresses,
≥ 1,000 events, set benign share and duplicates) is not generated yet; a few fields no workflow uses are not read
(Entra `mfaResult`, Umbrella policy name, Secret Server checkout expiry, Privilege Manager policyId / approvedBy,
ServiceNow state history, Rapid7 scan runs); the workbook calls the SIEM push outbound, the platform's is inbound.

## Round 21 (2026-10-10): client security review pack, and the controls it claims verified in code

Aim: write the review pack the client's security and architecture teams asked for (`docs/client_review/`: solution
architecture, security tool integrations, data flow and protection, AI / LLM security, security risk and governance,
deployment and validation, with six diagrams and a Word edition) - and check, before writing each security claim,
that the code really enforces it. Results on the final code:

| Check | Result |
|---|---|
| Platform suite on SQLite | **648 passed**, 0 failed, 15 skipped (663 collected; the same opt-in / single-database skips) |
| Platform suite on PostgreSQL 16 | **648 passed**, 0 failed, 15 skipped |
| Feature verification (`--browser --engine --live --llm`) | **108 of 108 features verified**; 240 mapped tests run, 0 failed; ML engine 205 passed; browser tour with the live LLM 0 problems (35 screenshots) |
| Lint / bandit / pip-audit / JS syntax | clean / no issues / **0 known vulnerabilities** / clean |

Three claims were not true in code; each is fixed with a regression test that fails on the old code:

| Claim (in SECURITY / ARCHITECTURE / the deployment guide) | What the code did | Fix |
|---|---|---|
| "Destructive actions are never autonomous" | The policy capped destructive types at L3, but **no action was marked destructive**: a policy raising everything to L4 would have run password resets, secret rotation, mail purges and "confirm compromised" unattended | Those four are marked destructive; a test raises every action to L4 and requires exactly these four to wait for a person |
| Microsoft app registrations "with a certificate or secret" | Secret only | Certificate credentials (RFC 7523 client assertion signed with the app's key, `x5t` thumbprint, 10-minute lifetime) for Entra ID, Defender for Endpoint, Defender for Office 365 and Sentinel; the secret still works |
| Threat-intel lookups send "indicators only" | Internal IP addresses and the organisation's own domains (a link to its intranet in a reported e-mail, an incident's 10.x address) would have been sent to VirusTotal, Shodan and the other sources | Private / reserved addresses, single-label and private-suffix host names and anything under `SOC_ORG_DOMAINS` are withheld ("not checked") in the one path every lookup takes |

One claim was overstated in the docs and is now described as the code behaves: the kill switch stops **autonomous**
execution (every action then needs a person's approval); a human-approved action still executes, and pausing a tool
stops every write to it.

## Round 20 (2026-10-09): bad data and bad input degrade one item, never the platform

Aim: a critical review for production - find every way discrepancies in data or inputs (vendor records, times,
pushed alerts, spreadsheets, e-mail, settings, policy documents, model output, API parameters) or an operational
event (a deploy, a runaway query, several processes) could break the platform, fix each with a regression test,
and list what cannot be fixed in code. Method: fuzzers written for each input surface, then the findings turned into
tests. Results on the final code:

| Check | Result |
|---|---|
| Platform suite on SQLite | **645 passed**, 0 failed, 15 skipped (660 collected; the same opt-in / single-database skips) |
| Platform suite on PostgreSQL 16 | **645 passed**, 0 failed, 15 skipped |
| Feature verification (`--browser --engine --live --llm`) | **108 of 108 features verified**; 240 mapped tests run, 0 failed; ML engine 205 passed; browser tour with the live LLM 0 problems (35 screenshots) |
| Lint / bandit / pip-audit / JS syntax | clean / no issues / **0 known vulnerabilities** / clean |

Probes run (and how much they found before the fixes):

| Probe | Before | After |
|---|---|---|
| Every connector normaliser, every field of the first records of every stream given 11 wrong-typed or odd values | **715** crashing mutations in **26 of 27** streams | 0 (only refusals of records whose identifier is unusable, with the reason) |
| 17 corrupted reported e-mails (empty, binary, UTF-16, NUL bytes, broken MIME, invalid base64, bit flips...) | none crashed, but unreadable content could be analysed as if complete | all 17 processed; none called safe |
| Every request body field (12 odd values) and query parameter (8) of every API route, from the OpenAPI schema, as lead and admin | 4 server errors (2 routes) | 0 |
| Every node of the autonomy policy, AI usage policy and connector configuration given 13 odd values | validator crashes; wrong types accepted by the autonomy policy | each rejected with a reason |
| Every field of the model's JSON for grounded answers, the analyst planner, the report planner and deep analysis | crashes on lists / numbers in place of words / lists | 0 |
| 14 mistyped settings | tracebacks at start, crashes later, or silently ignored | start refused with every problem and its fix |

Found and fixed (details in FAILURE_MODES.md):

| What was wrong | Effect | Fix |
|---|---|---|
| Vendor fields of the wrong type crashed the parsers | a whole record (sign-in, host, alert) set aside for one field | records conformed to the stream's documented shape, learned from the fixtures; coercions reported per sync (`connector.data_quality`) |
| A numeric id or an odd title failed the canonical schema | record lost | numeric ids accepted as text; odd title / severity / link / attributes emptied |
| Future vendor times (`9999-12-31`, a device clock years ahead) became the latest observation | every risk score would decay as if decades old | times more than 24 h ahead stored as now, vendor value kept |
| `.NET` `0001-01-01`, epoch 0, out-of-range or negative epochs, epoch as text | year-1 dates stored; exceptions; times lost | read as no time, or read |
| One alert without an id in a SIEM batch | whole batch refused (and resent forever) | per-alert isolation; response lists rejected alerts and reasons |
| Ownership CSV saved by Excel (BOM, Windows-1252, semicolons, `Host Name` headers) | silently no owners, or an error | read in every one of those forms; re-read only when it changes; file handle closed |
| UTF-16 / NUL-byte / damaged-MIME e-mail | parts of the message unseen by the analysis | decoded and cleaned; never called safe - held for an analyst with the reason |
| Mistyped settings | traceback, crash mid-request, or ignored | validated as a whole at start, with fixes and "did you mean" |
| Autonomy policy accepted wrong types | an approved policy could stop every action decision | validated field by field; an unreadable stored entry decides at L2 with four-eyes; VIP names never matched letter by letter |
| AI usage policy validator crashed on a list for a map; accepted infinite prices | a 500 on save; meaningless cost figures | type checks; finite numbers only |
| Model JSON with a list for a word, a number for a list, `"false"` as text | answers, deep analysis and report plans crashed; insufficient evidence misread; a 99,999,999-day report possible | defensive readers; period kept within 1-730 days |
| An analyst tool the database refused | on PostgreSQL the rest of the request failed (aborted transaction) | one savepoint per tool |
| Oversized numbers in two query parameters | integer overflow, 500 | bounded, 422 |
| Case and approval lists stopped at 500 | older cases reachable only by search | paged (`?offset=`, Older / Newer), id tiebreak |
| SIGTERM | scheduler killed mid-job; last access-log rows lost; shutdown unbounded | clean stop between jobs, access log flushed, 20 s grace inside compose's 30 s |
| No bound on one SQL statement | a runaway query could hold connections and locks | `SOC_DB_STATEMENT_TIMEOUT_SECONDS` (PostgreSQL) |
| Each process held a full tool request budget | vendors could see 5x the configured rate | `SOC_CONNECTOR_RATE_SHARE` |
| Duck-typed connectors (found by the suite) | the new data-quality report crashed syncs of connectors not derived from `BaseConnector` | reported only where the connector offers it |

New: `connectors/conform.py`, `settings_check.py`, `test_data_tolerance.py` (42 test cases), a wrong-type fuzz per stream
in the conformance suite, model-output fuzzes in `test_intelligence.py` / `test_story.py`; ENGINEERING.md decisions
62-66 and three new known limitations.

Not fixable in code alone (also in ENGINEERING.md §26 and FAILURE_MODES.md):

- **Live tenants**: every connector is proven against documented shapes; record and sanitise real responses during
  deployment so the fixtures, and therefore the conformed shapes, match the client's tenants.
- **Schema migrations**: additive changes are automatic; the first NOT NULL column, rename or drop needs Alembic.
- **Per-person erasure** (GDPR): no tool yet; the hash-chained audit log needs an agreed design.
- **Limits shared across processes**: the API's per-client limit is per process; put a hard limit on the proxy.
- **Restore drill, independent penetration test, manual accessibility review, load at the client's volume**.

## Round 19 (2026-10-08): every agent call diagnosable, every action auditable, ample logs

Aim: for any request, job or model call, answer "what happened and why" from the platform's own records; leave no
change on the platform unaudited; produce structured logs an operations team and a SIEM can use. Results on the
final code:

| Check | Result |
|---|---|
| Platform suite on SQLite | **564 passed**, 0 failed, 15 skipped (579 collected; the same opt-in / single-database skips) |
| Platform suite on PostgreSQL 16 | **564 passed**, 0 failed, 15 skipped |
| Feature verification (`--browser --engine --live --llm`) | **103 of 103 features verified**; 221 mapped tests run, 0 failed; ML engine 205 passed; browser tour with the live LLM 0 problems (35 screenshots, incl. the trace view; `docs/screenshots` refreshed from this run) |
| Lint / bandit / pip-audit / JS syntax | clean / no issues / **0 known vulnerabilities** / clean |

New: `core/observability.py` (trace ids, structured logs), the trace view (`GET /api/v1/admin/trace/{id}`, *Audit
log -> Trace*), model-call diagnostics (`/api/v1/admin/llm/calls`, *AI usage -> Recent model calls*), the write-audit
guarantee; OPERATIONS.md "Logs, traces and diagnostics"; ENGINEERING.md decisions 59-61; `test_observability.py`
(10 tests).

Found and fixed:

| What was wrong | Effect | Fix |
|---|---|---|
| No logging configuration at all | only Python's default warnings, unstructured, reached the container log; no line for requests, model calls, outbound calls or jobs | structured JSON (prod) / text lines for requests, audit events, model calls, outbound calls to tools, job start and end, CLI commands; optional rotating file |
| Nothing linked the access log, audit events, model calls and job runs | "what did this request / job do?" could not be answered | one trace id per request / job / CLI command on every record and log line; trace view |
| The evidence check's removals were only counted | "why is this explanation thin?" had no answer | each removed statement stored with its reason on the model call |
| Some successful writes left no audit event (pushed SIEM alerts) | a change on the platform with only an access-log row | generic `api.<method>` audit event in the same transaction when a route wrote none |
| Tier advice counted calls the endpoint failed to answer (down, slow, circuit open) as poor answers - seen as "33 % usable" for incident summaries on the AI usage screen during a tour run on a heavily loaded machine (with the same live model the summaries all succeeded) | an outage would have pushed features towards "use large" for no quality reason | quality counts only calls the model answered; failures to answer shown separately as *not answered* |
| The trace id was added only by the platform's log handler (found by the tests) | a host's own log handler would have seen lines without it | stamped on each event when it is created |

## Round 18 (2026-10-08): AI budgets, per-person limits and model choice

Aim: no person, script or burst of work can run up the AI bill or starve scheduled work; administrators decide the
limits and each feature's model; the choice between the small and the large model is made from measured figures.
Results on the final code:

| Check | Result |
|---|---|
| Platform suite on SQLite | **553 passed**, 0 failed, 15 skipped (568 collected; the same opt-in / single-database skips) |
| Platform suite on PostgreSQL 16 | **553 passed**, 0 failed, 15 skipped |
| Browser tour | **0 problems** (33 screenshots; the new *AI usage* screen at 4 widths, light and dark, axe-core, stored XSS) |
| Feature verification (`--browser --engine --live --llm`) | **103 of 103 features verified**; 221 mapped tests run, 0 failed; ML engine 205 passed; browser tour with the live LLM 0 problems |
| Lint / bandit / pip-audit / JS syntax | clean / no issues / **0 known vulnerabilities** / clean |

New: the AI usage policy (`llm/usage_policy.py`, *Govern -> AI usage*; LLM_TOKENS_AND_COST.md sections 4 and 4b;
ENGINEERING.md decisions 57-58) and `test_llm_usage.py` (18 tests).

Found and fixed:

| What was wrong | Effect | Fix |
|---|---|---|
| Only a monthly cap | a burst (a script asking questions in a loop, a flood of incidents) could spend the month in a day | daily cap (default a tenth of the month) with a finding while it is used up |
| No per-person limit | one person could use the whole budget, leaving scheduled explanations without the model | per-person hourly / daily limits (role and person overrides; 0 = off); scheduled work counts only against the platform caps |
| Answer length bounded only by the prompt (except the Claude provider, 16,000) | a misbehaving model could write - and bill - pages | a hard cap per call (1,500 small / 3,000 large by default), set per feature |
| Budget only in an environment variable | changing it needed a restart and left no record | set on the AI usage screen by administrators, versioned and audited |
| Tier choice fixed in code, with no data to judge it | no way to know whether a cheaper model would do | the call log now records tier, who asked and the statements the evidence check kept and removed; the screen advises a tier from those figures |
| An answer that was not JSON was logged as `ok` | quality figures overstated | logged as `unparseable` |
| The AI usage screen's role table overflowed at 1280 px (found by the browser tour) | sideways scroll | tables laid out to fit |
| The analyst assistant's findings tool (and the brief built from it) counted resolved findings as current - found when the new daily-budget finding cleared and the self-check saw 2 open findings on the assistant against 1 everywhere else | a cleared alert could be presented as a current threat | only open findings (new, acknowledged), as every other surface counts them |
| Test runs and the browser tour left their temporary folders behind (about 400 small folders per run, the tour's database and screenshots each time) | the system temp directory grew run after run - repeated runs here filled the disk | the test session puts every temporary folder under one root removed at exit; the tour deletes its folder when it finishes |
| The first daily-budget alert reused the monthly alert's rule and fired alongside it once the month was used up | two findings for one cause | its own rule (`llm_daily_budget`), silent while the monthly finding stands |

## Round 17 (2026-10-08): connecting and administering tools

Aim: an administrator connects, configures, rolls out, pauses and restores tools from the console - no file edit, no
restart - and no configuration mistake can take the platform down. Results on the final code:

| Check | Result |
|---|---|
| Platform suite on SQLite | **535 passed**, 0 failed, 15 skipped (550 collected; the same 15 opt-in / single-database skips as round 16) |
| Platform suite on PostgreSQL 16 | **535 passed**, 0 failed, 15 skipped |
| Browser tour (layout at 4 widths, light + dark, axe-core, stored XSS, screen-vs-API) | **0 problems** - now also runs a preflight, opens *Configure* and proposes a change |
| Feature verification (`--browser --engine --live --llm`) | **103 of 103 features verified**; 221 mapped tests run, 0 failed; ML engine 205 passed |
| Lint / bandit / pip-audit / JS syntax | clean / no issues / **0 known vulnerabilities** / clean |

New: strict configuration schema, connector isolation, rollout stages, preflight, console configuration with
four-eyes approval and hot reload, pause, history / restore, export / import, editable supplier and sanctioned-service
lists, the connector development kit (OPERATIONS.md "Connecting and changing tools"; ENGINEERING.md §5.5 and decisions
51-56). New test file `test_connector_admin.py` (36 tests).

Found and fixed while building it (each with a regression test):

| What was wrong | Effect | Fix |
|---|---|---|
| One live connector with a missing secret raised `ConfigError` out of the action registry and enrichment | phishing, incident and vulnerability handling and the approvals screen all failed | the connector is isolated with the reason; the rest work |
| A connector module that failed to import stopped discovery | the whole platform failed to start | the module is skipped and logged |
| Typos in `connectors.yaml` were ignored (`crowdstrik:`, `enabeld: false`, a misspelled setting) | a tool silently never ran, or stayed on | strict schema with "did you mean"; `serve` / `scheduler` refuse a broken file; YAML errors name the line |
| Settings read by connectors were never declared (`sync_from` in three tools, `since`, `issue_type`, `graph_base` in two, `arm_base`) | invisible to validation and to any form | declared, with kinds |
| The fixture transport did not treat an HTML page as the live transport does | a proxy page read as a connector defect in tests | one `html_page_error` for both |
| Recording needed a separate salt | the Recording stage could not be chosen without another secret | salt derived from `SOC_DATA_KEY` when `SOC_RECORD_SALT` is unset; the config check says when neither exists |
| Exported supplier domains were not in the console's normal form | re-importing an unchanged export proposed a change | both sides normalised |

## Round 16 (2026-10-07): real-tenant behaviour, volume and traffic

Aim: nothing a real tenant does (paging, throttling, expired tokens, missing permissions, missing fields, outages,
late logs, client-scale volume, concurrent users) should first be met in production. Results on the final code:

| Check | Result |
|---|---|
| Platform suite on SQLite | **499 passed**, 0 failed, 15 skipped (514 collected; skips are the opt-in live LLM and live feed tests, input fuzzing run once on the built-in estate, and one check that runs only on the other database) |
| Platform suite on PostgreSQL 16 | **499 passed**, 0 failed, 15 skipped |
| ML engine suite | 205 passed, 2 skipped |
| Lint / bandit / pip-audit / JS syntax | clean / no issues / **0 known vulnerabilities** / clean |

New test files:

| File | What it proves |
|---|---|
| `test_connector_conformance.py` | every connector and stream: paging to the last page and resuming correctly (time watermark or full re-read, never a stale continuation token); 429 (seconds or date), 401 (token renewed once), 403 (stops, names the permission); every field of every record removed and nulled; HTML instead of JSON; page limit; bounded page buffer; late records; realistic Sentinel (with entities), Jira and SIEM push (flat, Splunk ES notable, Elastic Security) samples |
| `test_volume.py` | entity resolution cost stays flat for a NAT'd fleet and namesake hosts; the queries use the indexes; messy estates at 2x and 8x; one savepoint per page; an interrupted backfill resumes; one bad record never sinks its page |
| `test_traffic.py` | connection pool limits; a saturated pool answers 503 + `Retry-After` instead of hanging; a real multi-worker server under concurrent load |
| `test_recording.py` | record-and-sanitise mode: pseudonyms are stable and keyed, nothing identifying survives (`_scan.json`), recordings replay through the same parsers |
| `test_real_world.py` | an empty tenant and every tool down at once: every pipeline, screen read model, report, the brief and the self-check still work |

Found and fixed (each with a regression test; details in FAILURE_MODES.md):

| Area | What was wrong | Fix |
|---|---|---|
| Resume (9 connectors) | the last page's continuation token was kept as the next sync's start: re-read pages, expired tokens, or (Rapid7) never seeing an asset again | event streams resume from a time watermark with a 30-minute overlap (late logs); inventories are re-read in full |
| Tokens / permissions / throttling | a refused token was reused until its own expiry; a 403 was retried; `Retry-After` as a date was ignored | renew once on 401; stop on 403 and name the scope; both `Retry-After` forms honoured (capped at 120 s) |
| Missing fields | 14 connectors crashed on some missing or null field | optional fields tolerated; a record without its identifier is refused and counted |
| Timestamps | `.000+0530` lost its offset | offset kept |
| Sentinel | incidents read without their entities | entities read per incident |
| Umbrella | every DNS query stored (tens of millions a day in a real tenant) | security-categorised queries only by default (`dns_sync`) |
| CrowdStrike | offset paging stops at 10,000 hosts or alerts | hosts via the scroll query; alerts restart from the watermark |
| PostgreSQL at volume | a failed page replayed in savepoints until "out of shared memory"; `SELECT DISTINCT ... ORDER BY` rejected | one savepoint per page, replay stops after 20 identical failures; query fixed |
| Entity resolution at volume | candidate search scanned by name pattern and IP without bounds | exact and bounded range queries, a squashed-hostname hint, IP candidates only with a name, three new indexes added to existing databases at start-up |
| Risk ranking | recomputed on every screen | cached on a data fingerprint, invalidated on every relevant write |
| Vulnerability intel | one unreachable feed crashed the refresh; an empty KEV answer would clear every KEV flag | feed skipped, last values kept, KEV never cleared by an outage |
| Reporting mailbox | job failed on an outage; read from the oldest message every run (5,000 cap - new reports unreachable once the mailbox held more) | resumes from its checkpoint; outage recorded; unreadable message retried next run |
| Shadow IT / reports | crashed when Umbrella was down | "unavailable" screen; report section skipped with the reason |
| Context store growth | retention kept every event record forever (unbounded tables at client volume) | telemetry events older than `SOC_EVENT_RETENTION_DAYS` (400) pruned unless a case, evidence, insight or override cites them |
| Connection failures | "gave up after N retries" with no cause | the last error's type and text (e.g. TLS inspection) |
| Server under load | single process; pool exhaustion hung requests | `SOC_API_WORKERS` (4 in Docker), pool settings, 503 + `Retry-After` |

Measured (this machine, details in ENGINEERING.md §16 and OPERATIONS.md):
- 40x messy estate on SQLite: full sync 244 s -> 149 s; 29 statements per record; review queue at 20x 142 -> 18.
  On PostgreSQL the 40x estate syncs with 0 failed records.
- Risk ranking 9.4 s -> 4.7 s cold, 0.02 s warm; situation brief 9.4 s -> 0.03 s.
- Load: one process 43 requests/s; four processes 128 requests/s at 40 users and 150 requests/s at 100 users, 0 errors.
- Identity resolution evaluation: 195 records/s (was 122); unchanged accuracy (31 splits, 5.41 % unresolved,
  0 false merges); at `SOC_RESOLUTION_AUTO_THRESHOLD=0.75`, 2.18 % unresolved.

Still needs the client's environment: real throughput limits of each tenant, the client's proxy/TLS inspection and
real data quality; the record-and-sanitise mode exists so the first week's live responses become fixtures.

## Round 15 (2026-10-07): the 4-week development plan checked item by item

Results on the final code:

| Check | Result |
|---|---|
| Platform suite on SQLite | **345 passed**, 0 failed, 15 skipped |
| Platform suite on PostgreSQL 16 | **345 passed**, 0 failed, 15 skipped |
| Feature verification | **103 of 103 features verified** (`--browser --engine --live --llm`): 260 mapped test cases incl. live LLM and live feeds; ML engine suite 205 passed; evaluations and browser tour clean |
| Phishing evaluation, built-in labelled corpus (20 messages) | combined analysis 20 of 20 exact; 14 of 14 malicious caught, 0 false positives (engine alone 13 of 14, 0 false positives) |
| Docker (Desktop 29.8, Compose 5.5) | images built (core 1.7 GB; with the ML engine 3.7 GB, no PyTorch); stack started from empty volumes; first scheduler pass vulnerability -> incident -> phishing; after `demo`: 7 + 3 cases, 34 actions awaiting approval (phishing 16, incident 15, vulnerability 3), 6 open vulnerabilities, verdicts identical to a laptop with and without the engine; figures survive a restart; reports with charts built and downloaded through the API; no errors in the API or scheduler logs |
| Lint / bandit / pip-audit / JS syntax | clean / 0 medium or high / **0 known vulnerabilities** / clean |

Every checklist item of the development plan was compared with the code and with real runs (a fresh `demo` load:
7 phishing and 3 incident cases, 17 raw scanner findings consolidated into 6 vulnerabilities). Found and fixed:

| Plan item | What was wrong | Fix |
|---|---|---|
| Week 3 - reports "with charts" | no report contained a chart | charts from the computed figures: native, editable charts in PowerPoint, PNG (Pillow) in Word; test compares chart values with the platform's own figures |
| Week 4 - "zero high/medium findings" (pip-audit) | one known vulnerability (oauthlib 3.3.1, PYSEC-2026-4114), pulled in only by the unused `google-auth-oauthlib` | dependency removed; pip-audit reports none |
| Week 4 - security / tests never write into the project | the in-platform ML engine read the project's `.env` itself; its relative `IOC_DB_PATH` resolved inside `artifacts/phishing/` and runs rewrote a tracked file | the platform always keeps the engine's IOC store outside the source tree; regression test |
| Week 4 - health and monitoring | `/health` reported `audit_chain: null` for the first 5 minutes after a host boots (the verification cache started at monotonic time 0, which on Windows is the uptime) | the cache starts as "never verified"; regression test |
| Week 3 - correlation rules | the "newly KEV-listed exposure" rule used the wall clock, so the demo's finding disappeared two weeks after the fixture date (found because a week had passed) | measured from the catalogue's latest addition, capped at today (live behaviour unchanged); test moves the clock a year ahead |
| Week 1 - scheduler / job leases (a random failure in one full run) | compare-and-swap writes used `updated_at = now` as the version; the Windows clock moves in ~15 ms steps, so two writes in one tick got the same stamp and a stale writer still matched: the heartbeat put back an older "running job" (1 failure in 1 of 5 full runs), and a lease could in principle be taken twice | every swap writes a version strictly later than the one it read; a frozen-clock test reproduces the race every time (fails before the fix, passes after); the original test passed 40 of 40 repeats |
| Week 4 - feature verification | the verification report ran only the engine's unit tests (162) while the docs quote 205 (unit + integration) | the report runs both |
| Week 4 - Docker deployment (found by running it) | no `.dockerignore`: the build context would have carried `.env`, `.venv`, local databases and documents | `.dockerignore` added; the image contains no `.env` and runs as uid 1001 |
| Week 2 - incident workflow (found by the Docker run) | scheduled from a fresh start, the incident job ran before the first vulnerability sync, so the Exchange incident was scored without its host's exposure (medium, no actions instead of high, three actions) and nothing ever looked again | jobs run vulnerability first when several are due; open incidents are reassessed when KEV-listed exposure appears on their hosts; evidence creation is idempotent (same case, source, wording, entity and lookup), so reassessments never duplicate rows; tests for reassessment, idempotence and unchanged evidence on a single run (132 rows before and after) |
| Week 4 - ML engine in Docker (found by the Docker run) | the engine read the developer's `.env`: local QR decoding was on on the laptop and off in the container, so one e-mail scored 0.82 vs 0.92 | the setting is pinned in the platform's offline settings; the container now scores exactly like the laptop; regression test |
| Week 4 - ML engine packaging | the engine was "available" only with PyTorch and transformers installed, but nothing imports them (the content model is TF-IDF) | availability checks the libraries really used; PyTorch and transformers removed from requirements and the image; the 7 models were run with both libraries blocked from import |

Not fully met, and why (`docker compose up`, open earlier in this round, is now verified - see the Docker row):
- **"Migration support"** (week 1): new tables and new nullable columns reach existing databases automatically, and
  PostgreSQL text columns are widened; there is no migration framework for required columns, renames or drops.
- **Plan wording:** the plan calls the board deck "a formatted Word document"; it is a PowerPoint deck by design.

## Round 14 (2026-09-30): connector formats audited, client deployment readiness

Final results for this round's code are in round 15 (its full runs were interrupted when the machine restarted).

**Connector data formats audited against the vendors.** Every connector's requests and parsed fields were compared
with the vendor's public API reference and, where the reference is gated, with public reference integrations and
their recorded sample responses. Found and fixed (the fixtures now reproduce the real shapes, so the demo shows what a
live tenant returns):

| Connector | What was wrong | Effect in a live tenant before the fix |
|---|---|---|
| Avanan (Check Point HEC) | security events carry no sender, recipients, subject or Message-ID - only an entity id; `combinedVerdict` is one verdict per engine, not a string; the search filter key is `entityExtendedFilter`; actions need `entityType`; severities are "1"-"5" | events without people or messages; reconciliation crashing on the verdict; searches and quarantine rejected |
| Wiz | the issue rule is a GraphQL union (needs fragments); cloud resources have no top-level `externalId` / `region` / `updatedAt` | both queries rejected by the API |
| ServiceNow | `sysparm_display_value=true` returns timestamps in the integration user's timezone; `get_ticket` sent no display parameter, so the group came back as a bare link | times shifted by the user's offset; ticket sync without the assignment group |
| Rapid7 InsightVM | a vulnerability definition has no `solution` field (fix text lives under `/solutions`); its severity words ("Severe", "Moderate") were copied through; `RAPID7_VERIFY_TLS=false` evaluated to true | no fix text; severities off the platform scale; verification could not be turned off |
| Defender for Endpoint | alerts carry evidence only with `$expand=evidence` | alerts without files, IPs and URLs |
| Entra sign-ins | `mfaDetail` / `authenticationRequirement` exist only in the beta API | fields always empty on v1.0 |
| Defender for Office 365 | alert message evidence (recipient, sender, Message-IDs) was not read | recipients only from separate user evidence |
| Generic SIEM | `field_map` from an environment variable is a JSON string | ingestion crashed when the map was set via the environment |

Checked and correct: CrowdStrike, Umbrella, Canary, Jira, Sentinel, Delinea (paths are settings), NVD / EPSS / KEV
(also live), and all eight threat-intelligence sources. Each fix has a regression test.

**Ready for the client's environment:**
- `docs/CLIENT_DEPLOYMENT_GUIDE.md`: hosting, Entra sign-in, every tool's permissions, settings and egress hosts,
  the client's in-house LLM, action rollout, first-sync plan, hardening checklist.
- The console had no production sign-in (only the dev form). It now runs Entra ID authorization code + PKCE itself;
  `GET /api/v1/auth/config` supplies the public values. Covered by a configuration test and the pentest's
  unauthenticated-route sweep; the full flow needs a real tenant.
- An organisation's own LLM gateway (Claude, Gemini and OpenAI models behind one endpoint) is configuration only:
  auth header and prefix, extra headers, CA bundle, JSON mode, beta fallback switch - with tests.
- The database URL can come from a vault file; `init-db` no longer prints the database password.

**Not claimed:** no connector has yet run against the client's tenants, and the console sign-in has not run against
a real Entra tenant.

## Round 13 (2026-09-29): new content model, the ML engine made strictly offline

Results on the final code (this round's work together with the round 12 security fixes):

| Check | Result |
|---|---|
| Platform suite on SQLite | **329 passed**, 0 failed, 15 skipped |
| Platform suite on PostgreSQL 16 | **329 passed**, 0 failed, 15 skipped |
| Phishing engine suite | **205 passed**, 0 failed |
| Feature verification (`--browser --engine --live --llm`) | **103 of 103 features verified**; 260 test cases incl. live LLM and live feeds; browser tour with the LLM and models on: 0 problems |
| Lint | clean |

**The content model was replaced.** The delivered 2-layer BERT and its replacement were scored on the same 2,000
held-out public messages. The new model is TF-IDF word and character features with logistic regression, trained with
`scripts/train_content_model.py` on public data (Nazario phishing 2019-2025, CC BY 4.0; SpamAssassin; the "Safe
Email" rows of zefang-liu/phishing-email-dataset) and re-trained after the round 12 text-preparation hardening:

| | Old transformer | New classifier |
|---|---|---|
| Hold-out accuracy (2,000 public messages) | 68 % | **99 %** |
| Phishing caught on the hold-out | 25 % | **99 %** |
| Platform corpus, 12 base messages (never trained on) | 7 right | **10 right**, every phishing message caught |
| Separation on the 46 labelled messages | 0.88 | **0.99** |
| Size / time per e-mail | 18 MB | **9.5 MB / ~6 ms** |

With it the engine alone catches 25 of 28 malicious messages (was 22) with no false alarms; combined with the rules
all 46 labelled messages are still exactly right. It still reads invoice wording as phishing, so it never confirms
an alarm on its own.

**Found and fixed:**
- **The ML engine could send e-mail content to external services.** It read the project's `.env` itself when first
  imported; with an OCR key there, image attachments went to an Azure OCR service, and its URL / threat-intel agents
  queried public lookup services with e-mail URLs and hashes. Offline mode now clears every lookup switch and
  credential on the engine's live settings; a test blocks all network access and requires zero connection attempts
  (3 before the fix, 0 after).
- The public "phishing" dataset first considered was mostly ordinary spam; its phishing rows were left out.
- Explaining a score rebuilt the list of 300,000 feature names for every e-mail (149 ms); it is now built once (~6 ms).
- The round 12 hardening of the text preparation changed 2.5 % of the training text (a stray "<" no longer swallows
  text up to the next ">"); the model was re-trained so training and inference match exactly.
- The browser tour now reports why it crashed instead of a missing-file error.

**A rare random test failure, traced to its cause and removed.** One PostgreSQL run had one failure in the
retention time-travel test (no reported e-mail of the seed-23 organisation had been auto-closed). Cause: the generated
organisations' extra e-mails got a random `Message-ID` (Python's `make_msgid`: time + process id + random number), so
every build produced different bytes; the auto-close QA sample is keyed on the message's content hash, so which reports
were held for QA changed from run to run, and once in a while every auto-close candidate of that organisation was
sampled. Fixed at the source: Message-IDs and MIME boundaries are now derived from the message itself, and a new test
builds the same organisation twice and requires byte-identical data. The same review removed every other way a test
could fail at random:
- tests that proved parallelism by wall-clock time (a busy machine stretches it) now prove it by counting calls in
  flight - sequential code can never pass them, parallel code always does;
- real-server tests wait up to 120 s for the server to start (was 20-30 s); the ReDoS guard allows 30 s (the fixed
  code takes ~0.15 s; the vulnerable patterns grow quadratically and would take far longer);
- a test run whose PostgreSQL setting is empty now stops with an error instead of quietly running on SQLite.
The timing-sensitive test files were then run on PostgreSQL with every CPU core saturated (24 busy processes on 12
cores) - see the result below.

A verification run during an internet outage failed its live tests; the re-run after the connection returned passed.

## 0a. Round 12 (2026-09-29): penetration test round 2 (white-box)

| Check | Result |
|---|---|
| Platform suite on SQLite | **329 passed**, 0 failed, 15 skipped |
| Platform suite on PostgreSQL 16 | **329 passed**, 0 failed, 15 skipped |
| Penetration tests (`test_pentest.py`) | **24 passed** (17 before + 7 new, one per attack class found in this round) |
| Phishing ML engine suite | **205 passed**, 2 skipped (after the `text_prep.py` pattern changes) |
| Lint / bandit / pip-audit / JS syntax | clean / no issues / no known vulnerabilities / clean |

**Method.** Every API route and the services behind it, the auth and access layers, and the console's HTML sinks
were reviewed by hand. Each suspected weakness was then attacked on a live instance with the demo data. For denial of
service, every module-level regex (44 patterns) was timed against 21 pathological inputs, and the e-mail parsing
chain was run on hostile bodies of up to 2.4 MB.

**Found and fixed** (full table with severities in SECURITY.md, "Penetration test round 2"):

| Severity | Finding | Measured before → after |
|---|---|---|
| High | Role scopes merged: a phishing lead who was also an all-domain auditor approved an incident action | executed → 403 |
| High | A phishing-only analyst self-approved platform-wide actions through `POST /actions` | 8 action types executed → filed in the case's domain, never self-approved outside scope |
| High | ReDoS in e-mail parsing (decomposer anchors/tags, analyser advance-fee/bulk patterns, content-model text preparation) | 240 KB of `<a href='x'>`: 16 s → 2.4 MB: 0.15 s |
| Medium | ReDoS in the LLM pseudonymiser's e-mail pattern | 200 KB of `1.1.1…`: 95 s → 2 MB: 0.13 s |
| Medium | Left-most `X-Forwarded-For` trusted behind a proxy (rate-limit bypass, fake loopback) | spoofed → right-most untrusted hop |
| Medium | Auditor could request risk exceptions and acknowledge plans; 100-year / negative exceptions accepted | 200 → 403 / 422 |
| Medium | Rejected exceptions could be re-approved; decided risk entries re-decided | 200 → 400 |
| Medium | A scoped administrator could grant all-domain roles and keys | allowed → 403 |
| Medium | Global policy decided by a domain-scoped lead | allowed → all-domain roles only |
| Low | Entity 360 vulnerabilities, `/metrics` counts and drift of other domains shown to scoped users | shown → removed / 403 |
| Low | Unknown ids and huge numbers answered 500 or `'NoneType' object has no attribute …` | 500 → 404 / 422 |
| Low | No HSTS behind a TLS-terminating proxy; rate-limiter table wiped at 50,000 addresses | fixed |

Two of the fixes touch uncommitted work in progress: the content model's `text_prep.py` (bounded address and tag
patterns, bounded input) and `scripts/train_content_model.py` (SHA-1 marked as not used for security; same hashes).

## 0b. Round 11 (2026-09-29): the phishing models, the client deck, recurring VM work

| Check | Result |
|---|---|
| Platform suite on SQLite | **321 passed**, 0 failed, 15 skipped |
| Platform suite on PostgreSQL 16 | **321 passed**, 0 failed, 15 skipped |
| Feature verification (`--browser --engine --live --llm`) | **102 of 102 features verified**; 259 test cases incl. live LLM and live feeds; engine 162 passed; browser tour with the LLM and the ML models on: 30 screenshots, 0 problems |
| Lint / bandit / pip-audit / JS syntax | clean / no issues / no known vulnerabilities / clean |

**The phishing ML models, checked one by one.** The engine (a trained model per e-mail component) now runs inside
the platform by default. Each model was measured on its own on 46 labelled messages (the built-in corpus plus two
generated organisations, each analysed against its own tools and people):

| Model | Finding | Action |
|---|---|---|
| Header | Good: never flagged legitimate mail (separation 0.85) | kept; may confirm an alarm |
| URL | Good: every phishing link above every legitimate one (1.00 on messages with links) | kept; may confirm |
| Attachment | Ranks correctly (1.00 on messages with attachments), scores many malicious ones low | kept; may confirm; recalibration recommended |
| Content transformer | Weakest: confidently wrong on 5 of 12 base messages, never outputs *Spam*; the integration was checked (labels, preprocessing) and is correct - it is the model (2-layer BERT, first 128 tokens) | kept, but may not decide alone; retraining recommended |
| User behaviour | 4 of 7 inputs were defaults in-platform, so every first-time external sender looked risky | now fed real mail-flow contact history, department, arrival time: separation 0.86 → 0.93, legitimate flagged 3 → 0 |
| Threat intel | Always 0 in-platform (no keys, empty local store) | now fed the platform's 8-source threat intel: 100 on the demo campaign |
| Sandbox | Static fallback only without detonation: no better than chance (0.40) | not run unless a detonation host is configured |

| | Detection | Legitimate called malicious | Exact verdict (of 46) |
|---|---|---|---|
| Engine as delivered | 22 / 28 | 3 | 33 |
| Engine with the platform's data | 22 / 28 | **0** | 36 |
| **Combined with the rules, as the platform runs it** | **28 / 28** | **0** | **46** |

The one decision the models had flipped - a genuine Azure invoice called malicious - is gone: with the platform's
data the models see a sender the recipient hears from monthly. A models-only alarm now needs a reliable model
(header, URL, attachment, threat intel) or the rules to agree, otherwise an analyst decides. Each case's *Analysis*
card shows both verdicts, every model's score and its measured reliability. Caveat: the data is small and synthetic;
real accuracy is measured on the client's reported mail in shadow mode.

**The client's management deck, checked item by item** (tools, the three workflows step by step, the recurring
workload, the operating principle; the map is in REQUIREMENTS_TRACEABILITY.md). Gaps found and closed:
- the weekly VM report and weekly management deck were not scheduled - now the `weekly_reports` job
- the risk register was updated only on request - now after every vulnerability refresh (proposals, updates,
  remediated, returned)
- follow-up nagged overdue teams daily and never checked on plans that were on track - now weekly per plan
- "Azure Identity & Access" was not covered beyond Entra - Azure role assignments per subscription and resource
  group are now read from Azure Resource Manager (Owner, Contributor... directly or through a group)

**Found and fixed in this round:**
- The models were cited as evidence for their own status (`virustotal_not_configured`, `no_attachments`, ...).
- The Notifications card, the scheduler banner and the out-of-scope screens (see round 10) - plus a false "Scheduler
  stopped" banner in an LLM-heavy SQLite demo: a heartbeat write waiting for the database lock was read as a dead
  scheduler. The server now asks its own in-process scheduler; the bulk endpoints commit before the model writes.
- Generated organisations would have shown the sample's "Acme" Azure subscription names; they are renamed.
- scikit-learn was unpinned while the models were saved with 1.8 (scores checked identical; now pinned).
- Docker's compose file forced the models off even in an image built with them.

## 0c. Round 10 (2026-09-28/29): scheduler, speed, teamwork, notifications

**Final results (2026-09-29), after the additions and fixes listed below:**

| Check | Result |
|---|---|
| Platform suite on SQLite | **301 passed**, 0 failed, 15 skipped |
| Platform suite on PostgreSQL 16 | **301 passed**, 0 failed, 15 skipped |
| Feature verification (`--browser --engine --live --llm`) | **98 of 98 features verified**; 242 test cases; engine 162 passed; browser tour with the LLM on: 30 screenshots, 0 problems |
| Lint / JS syntax | clean |

**Added on 2026-09-29:**
- *Send test message* on the Notifications card
- `python -m soc_platform reset-demo` (measured 14 s without the LLM)
- a Data scope choice on the dev sign-in
- screenshots refreshed, including a new search screenshot

The browser tour now also:
- takes a case and adds a note in the UI
- searches from the top bar
- presses *Send test message* as Admin
- signs in as a phishing-only analyst
- fails on `undefined` / `NaN` / `[native code]` on any screen, or a scheduler banner while the scheduler runs

**Found and fixed on 2026-09-29:**
- **Writes were acknowledged before they were committed.** FastAPI ended each request's database session after
  sending the response. Against a real server, an uploaded report's case was missing from the next case list in
  **28 of 40** tries, and a commit failure would have been reported as success. Every request now commits before
  replying (0 of 40). Found because the extended browser tour read a case back straight after uploading it; the
  normal test client cannot show this race.
- **The scheduler's status could show an older running job.** The heartbeat wrote back a stale copy of the shared
  row; reproduced in 1 of 10 runs. Now a compare-and-swap.
- **The Notifications card showed `function sub() { [native code] }`** as its subtitle, and the new test button
  was missing (wrong argument to the card helper). The new screen guard catches this class of bug.
- **A domain-scoped user who typed in the address of an out-of-scope screen** got a page of refused requests. The
  console now says which scope the screen needs.
- **The search box kept the last query** on every other page.
- **The reset command, run under the PostgreSQL test mode**, emptied the configured SQLite file instead of the
  database actually in use. It now decides from the live connection.

**Earlier in this round (2026-09-28).** New in this round:
- the built-in scheduler
- parallel vendor I/O in all three modules
- deferred case explanations
- case ownership and notes
- global search
- Teams / Slack / webhook notifications
- automatic addition of new optional columns
- recorded model response times

| Check | Result |
|---|---|
| Platform test suite on **SQLite** (PostgreSQL's rules enforced), 2026-09-28 | **292 passed**, 0 failed, 15 skipped (opt-in live / PostgreSQL-only) |
| The same suite on **PostgreSQL 16** | **293 passed**, 0 failed, 14 skipped |
| Feature verification (`--browser --engine --live --llm`) | **96 of 96 features verified**; 232 test cases incl. live LLM and live feed tests; engine 162 passed; browser tour with the LLM on: 0 problems |
| Lint (ruff, whole repository) / bandit (platform) / `node --check` | 0 findings / no platform findings / clean |

**New tests:**
- `test_notify.py`: threshold, once per channel, escalation, retry cap, HTTPS-only parsing, secret file, job wiring.
- `test_schema.py`: an old database gains a new column with its data intact, on both engines; model response times
  recorded and summarised.
- Deferred narration (`test_incident.py`, `test_phishing.py`): decisions unchanged, model calls overlap, evidence
  numbers match, nothing left pending.
- API tests for ownership and notes, search scope and literal wildcards, and the notification settings (never the
  secret).
- `test_scheduler.py`: first leases taken at the same moment.
- `test_core_governance.py`: note order under a frozen clock.

**Found and fixed in this round:**
- **Two schedulers could run one job twice.** Two separate races, both found by a test running two schedulers:
  - due-ness was checked before the lease was taken, and the lease holder was per process
  - the lease was released before the run was recorded

  Fixed with a per-thread holder, a re-check once the lease is held, and releasing only after the run is recorded.
- **The audit chain could fork** under concurrent appends (reproduced on SQLite and PostgreSQL). Appends now lock
  the chain head first.
- **Taking a first lease or writing a first heartbeat at the same moment crashed one scheduler's pass.** Both
  threads inserted the row. The test still passed, because the crash only raised a thread warning. Leases are now
  a compare-and-swap, a lost insert means "not acquired", and the heartbeat retries onto the existing row. The
  scheduler tests now fail on any exception in a background thread.
- **Notes written within one clock tick came back in random order** (Windows' clock advances in ~15 ms steps).
  Found by the full suite. Each case's note times are now strictly increasing.
- **A vendor's `Retry-After` of hours could stall a job.** It is now capped at 120 s.

## 0d. Round 9 (2026-09-26): penetration testing, fuzzing, types, coverage

| Check | Result |
|---|---|
| Penetration tests (`test_pentest.py`), details in SECURITY.md | 17 attack groups, all refused |
| Stored-XSS probe in the browser (8 screens, CSP disabled) | Nothing executed or injected |
| Property-based fuzzing (Hypothesis, thousands of generated inputs: redaction, numeric guardrail, timestamps, text bounding, e-mail decomposer) | 11 properties hold |
| Type check (pyright, platform core, 77 files) | Findings triaged; no reachable crash left (the rest are library typing limits) |
| Test coverage, platform core | 90.2 % of 10,105 statements; the untested production sign-in and card redaction are now covered |
| Dependency audit (pip-audit, npm audit) | No known vulnerabilities |

**Found and fixed:**
- Tokens without an expiry were accepted.
- Redaction crashed on marker lookalikes, masked spaced card numbers only partly, and could corrupt an IP address.
- The e-mail decomposer crashed on malformed headers.
- Concurrent writes of the same message failed on Windows.
- An unwired scaffold claimed "benign 95 %".

## 0e. Round 8 (2026-09-26): PostgreSQL, time, accessibility, code quality

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

## 0f. Round 7 (2026-09-25): new data sets, failure modes, cost

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

## 0g. Round 6 (2026-09-25): testing from every angle

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

## 0h. Round 5 (2026-09-25)

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

## 0i. Round 4 (2026-09-25)

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

## 0j. Round 3 (2026-09-25)

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
