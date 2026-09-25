# Client demo guide

A 25-minute walkthrough of the platform on the built-in scenario (fixture mode: realistic, vendor-shaped data from
20 tools about one fictional organisation, `cci-demo.com`). Everything shown is computed live by the platform.

## What a demo proves, and what it does not

**It proves:** the end-to-end workflows, cross-tool correlation, entity resolution, explainability (every
conclusion cites its evidence), governance (approvals, autonomy policy, kill switch, audit chain), RBAC, reports,
and the analyst experience. The code paths are the same as in live mode.

**It does not prove (say so if asked):** behaviour on CCI's own tenants and data volumes. The vendor connectors
are built to the documented APIs and verified on fixtures, but must each be connected and tested in CCI's
environment (connector *Test* button), and accuracy/latency targets must be measured on CCI's historical data
(A07, A09). The LLM is optional: without one the platform gives deterministic, cited answers; with an approved
endpoint it adds narrative - claims are still restricted to cited evidence.

## Setup (5 minutes, before the meeting)

```bash
python -m soc_platform init-db
python -m soc_platform serve        # http://127.0.0.1:8080
```

Sign in as **lead** (role selector, *Sign in (dev)*). Then, in order:
Cases → *Run incident pipeline*, *Pull reported emails*; Vulnerabilities → *Refresh*; Intelligence → *Re-correlate*.
(Or run `python -m soc_platform demo` once beforehand.) Rehearse once - the first run takes ~10 s in total.

## Script

1. **Overview** (2 min) - open cases by domain, automation rate, pending approvals, trend, data quality (match
   rates), integration health, enrichment latency, verdict drift. *"Every number here is computed, and every tile
   drills down to the records."*
2. **Intelligence** (5 min) - the situation brief; the top insight *jane.doe accessed privileged credentials after
   compromise indicators*. Ask: *"Is jane.doe@cci-demo.com compromised and what should we do first?"* - point out
   the cited evidence (Canary, CrowdStrike, Entra, Delinea, phishing) and that the answer names the first step.
3. **Case** (5 min) - open the phishing case: verdict, why (hover the E-numbers to see the evidence), campaign
   scope, who clicked, endpoint/identity impact, MITRE, recommended actions with blast radius and reversibility.
   Click the user → **entity 360**: one person across every tool, the risk factors and the unified timeline.
4. **Approvals** (2 min) - approve one containment as lead; show that an analyst cannot approve a four-eyes action
   and that nothing ran without approval. Policy screen: autonomy levels, kill switch.
5. **Vulnerabilities** (4 min) - four scanners → one record per host×CVE, KEV/EPSS/exposure prioritisation, owner
   routing, campaign; *Cloud misconfigurations*: route to owners, mark fixed, **Validate** → false closure caught.
6. **Coverage / Shadow IT / Supplier risk** (3 min) - ATT&CK blind spots per enabled tool; unsanctioned services
   (WeTransfer, DeepSeek, AnyDesk); Krishna Logistics look-alike and bank-detail-change mail.
7. **Governance** (2 min) - Audit (chain verified), Access (roles, service accounts, MFA), Reports → compliance
   pack (sign in as auditor).

## Likely questions

| Question | Answer |
|---|---|
| Does it replace our SIEM/SOAR/EDR? | No - it orchestrates them through their APIs (R09). |
| Can it take actions on its own? | Only if you promote an action type in the versioned policy (reviewed, four-eyes). Default: recommend only. |
| What if the AI is wrong? | Scores/verdicts are deterministic; the LLM only explains and must cite evidence; shadow-mode metrics and drift monitoring measure agreement with your analysts. |
| What data leaves our environment? | Nothing without an approved LLM endpoint; with one, internal identities are pseudonymised and every prompt is logged. |
| What do you need from us? | API access per tool (read scopes first), Entra app registration, CMDB/ownership source, sample historical data - see REQUIREMENTS_TRACEABILITY (A/D items). |
