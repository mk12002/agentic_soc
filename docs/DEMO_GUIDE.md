# Client demo guide

The word-for-word script is [LIVE_DEMO_20MIN.md](LIVE_DEMO_20MIN.md), and the detail behind every screen is
[LIVE_DEMO_NOTES.md](LIVE_DEMO_NOTES.md). This page is the short version.

A 25-minute walkthrough of the platform on the built-in scenario (fixture mode: realistic, vendor-shaped data from
21 tools about one fictional organisation, `acme-demo.com`). Everything shown is computed live by the platform.

## What a demo proves, and what it does not

**It proves:** the end-to-end workflows, cross-tool correlation, entity resolution, explainability (every
conclusion cites its evidence), governance (approvals, autonomy policy, kill switch, audit chain), RBAC, reports,
and the analyst experience. The code paths are the same as in live mode.

**It does not prove (say so if asked):** behaviour on the client's own tenants and data volumes. The vendor connectors
are built to the documented APIs and verified on fixtures, but must each be connected and tested in the client's
environment (connector *Preflight* button, then the rollout stages), and accuracy/latency targets must be measured on the client's historical data
(A07, A09). The LLM is optional: without one the platform gives deterministic, cited answers; with an approved
endpoint it adds narrative - claims are still restricted to cited evidence.

## Setup (5 minutes, before the meeting)

```bat
scripts\serve_with_env.cmd reset     :: .env loaded, demo data rebuilt (about 2 minutes with the AI on), then http://127.0.0.1:8080
```

Sign in as **Lena** (Lead) in one browser profile, **Alice** (Lead) in a second and **Ada** (Admin) in a third. Check: Cases
*All 10 · Phishing 7 · Incident 3*; Approvals 37; Vulnerabilities 6. Rehearse once.
Between audiences: stop the server (Ctrl+C) and run the same command again. Without the AI, `.env` needs no `SOC_LLM_*`
settings and everything except the written narrative is identical.

## Script

1. **Overview** (2 min) - open cases by domain, automation rate, pending approvals, trend, data quality (match
   rates), integration health, enrichment latency, verdict drift. *"Every number here is computed, and every tile
   drills down to the records."*
2. **Intelligence** (5 min) - the situation brief; the top insight *jane.doe accessed privileged credentials after
   compromise indicators*. Ask: *"Is jane.doe@acme-demo.com compromised and what should we do first?"* - point out
   the cited evidence (Canary, CrowdStrike, Entra, Delinea, phishing) and that the answer names the first step.
3. **Case** (5 min) - open the phishing case: verdict, why (hover the E-numbers to see the evidence), campaign
   scope, who clicked, endpoint/identity impact, MITRE, recommended actions with blast radius and reversibility.
   Click the user → **entity 360**: one person across every tool, the risk factors and the unified timeline.
4. **Approvals** (2 min) - each row names its case (or campaign); open **Why and what** on a containment to show
   the evidence it cites, what will happen and whether it can be undone. Approve it as lead (it waits for a second
   lead; approve it in a second lead window and it runs); show that an analyst cannot approve a four-eyes action
   and that nothing ran without approval. Policy screen: autonomy levels, kill switch.
5. **Vulnerabilities** (4 min) - four scanners → one record per host×CVE, KEV/EPSS/exposure prioritisation, owner
   routing, campaign; *Cloud posture*: mark fixed, **Validate** → false closure caught.
6. **Coverage / Shadow IT / Supplier risk** (3 min) - ATT&CK blind spots per enabled tool; unsanctioned services
   (WeTransfer, DeepSeek, AnyDesk); Krishna Logistics look-alike and bank-detail-change mail.
7. **Governance** (2 min) - Watch lists (upload `artifacts/demo/watchlist_demo.xlsx`, the case badges appear), Tuning (a
   request in words becomes a checked rule a second lead approves), Audit (chain verified, what it
   keeps and for how long, export to Excel), Access (roles, service accounts, MFA), Reports → report style preview and
   compliance pack (sign in as auditor).

## Likely questions

| Question | Answer |
|---|---|
| Does it replace our SIEM/SOAR/EDR? | No - it orchestrates them through their APIs (R09). |
| Can it take actions on its own? | Only if you promote an action type in the versioned policy (reviewed, four-eyes). Default: recommend only. |
| What if the AI is wrong? | Scores/verdicts are deterministic; the LLM only explains and must cite evidence; shadow-mode metrics and drift monitoring measure agreement with your analysts. |
| What data leaves our environment? | Nothing without an approved LLM endpoint; with one, internal identities are pseudonymised and every prompt is logged. |
| What do you need from us? | API access per tool (read scopes first), Entra app registration, CMDB/ownership source, sample historical data - see REQUIREMENTS_TRACEABILITY (A/D items). |
