# Architecture

## One platform, three workflows, one context

```
                 ┌──────────────────────── Analyst console (static JS, strict CSP) ────────────────────────┐
                 │ Overview · Intelligence · Cases · Approvals · VM · Phishing · Coverage · Shadow IT ·     │
                 │ Integrations · Policy · Access · Audit                                                   │
                 └───────────────────────────────────────┬──────────────────────────────────────────────────┘
                                                         │ HTTPS + Entra token / service-account key
┌────────────────────────────────────── API (FastAPI, soc_platform/api) ─────────────────────────────────────────┐
│ auth: Entra RS256 / dev HS256 / API keys / break-glass · RBAC + domain scope + step-up MFA · rate limit · CSP  │
│ access log (async writer) · dashboards · reports · admin                                                       │
└──────────┬───────────────────────┬──────────────────────────┬──────────────────────────┬──────────────────────┘
   Phishing domain          Incident domain          Vulnerability domain        Intelligence layer
   (+ ML engine, supplier   (cluster, enrich,        (consolidate, prioritise,   (risk engine, 12 correlation
    risk U18)                MITRE, recommend)        route, validate, U03)       rules, analyst Q&A, drift,
                                                                                  ATT&CK coverage, shadow IT)
           └───────────────────────┴─────────────┬────────────┴──────────────────────────┘
                                                 │
┌──────────────────────────────────────── Core (soc_platform/core) ─────────────────────────────────────────────┐
│ context store + entity resolution (assets & identities) · cases & evidence · enrichment fan-out              │
│ autonomy policy (L0-L4) · action layer (preconditions, approvals, idempotency, rollback) · audit hash chain  │
│ access (grants, keys, revocation, flags) · crypto (Fernet at rest) · retention · jobs (leases, dead letter)  │
└──────────────────────────────────────────────────────┬────────────────────────────────────────────────────────┘
                                                       │ uniform connector SDK (rate budget, backoff, cursors)
  CrowdStrike · Defender for Endpoint · Defender for Office 365 / Exchange · Entra ID · Rapid7 · Wiz · Avanan ·
  Umbrella · Canary · Delinea SS/PM · NVD · EPSS · CISA KEV · TI fusion · ServiceNow · Jira · CMDB CSV · Sentinel ·
  generic SIEM webhook              (fake mode: vendor-shaped fixtures through the same code)
```

## Data flow

1. **Ingest.** Connectors pull streams with cursors (or receive webhooks) and normalise each record into a
   `NormalizedRecord` with `EntityRef`s (hosts, users, indicators). Raw payloads go to the encrypted raw store.
2. **Resolve.** `EntityResolver` maps every reference to one canonical entity:
   deterministic keys (vendor ids, serial, FQDN, UPN/SAM/aliases) → scored fuzzy match (hostname, IP-in-window,
   OS) → unresolved queue → analyst override. Vendor ids are *conflict keys*: two different CrowdStrike AIDs are
   never merged. For people, an authoritative directory record (Entra object id) merges the partial identities it
   proves identical, and absorbs alias / former-address identities it lists in `proxyAddresses`. Built-in accounts
   (SYSTEM, root, `HOST$`) never become people. Stress tests: 0 false merges for assets (400 hosts) and identities
   (300 people, 6 naming conventions, random arrival order).
3. **Investigate.** Each domain service builds a case, fans enrichment out in parallel across dimensions, records
   evidence (fact vs inference, source, deep link), scores deterministically and asks the LLM (if configured) only
   to *explain*, citing evidence ids. Uncited claims are dropped.
4. **Decide & act.** Recommendations become `ActionRequest`s evaluated by the versioned autonomy policy. By
   default every action is L2 (recommend; a human approves). Destructive actions are never autonomous; blast
   radius, VIP and four-eyes gates apply; the kill switch (durable, shared by all replicas) halts everything.
5. **Correlate.** The intelligence layer computes explainable, time-decayed risk per user/host across all
   domains and runs correlation rules that raise insights with their evidence and next steps.
6. **Prove.** Every step is in the append-only hash-chained audit log; compliance packs and audit exports are
   generated from it.

## Deployment

* `api` - stateless FastAPI app (scale horizontally behind TLS).
* `scheduler` - runs the jobs in `soc_platform/jobs.py`; several replicas are safe (per-job DB lease).
* `postgres` - relational store (SQLite for dev). Raw payloads / reports on a volume or blob storage.
* optional `engine` profile - phishing ML microservices; detonation on an isolated host / CAPEv2.

## Key design decisions

| Decision | Why |
|---|---|
| Deterministic scoring, LLM only narrates | A wrong number presented confidently ends adoption (R02); figures must be reproducible |
| Every connector has a fixture mode through the same code | The whole platform is testable and demonstrable without credentials; parsing is exercised continuously |
| Recommend-by-default autonomy | NFR-01 / A06; promotion to automation is a reviewed, audited policy change |
| Conflict keys + authoritative merge in resolution | Wrong merges route notifications to the wrong team (R01); splits are recoverable, merges are not |
| Hash-chained audit, ORM-level append-only | Tamper evidence without special infrastructure; grant the DB role INSERT/SELECT only in prod |
