"""Generate the component-level architecture diagram (docs/diagrams/platform-component-architecture.svg).

    python scripts/build_component_diagram.py

Every box lists real components (modules, technologies, tables, vendor API endpoints), not features. Text is checked
against its box before anything is written: a line that would overflow stops the build with the box and the line.
Numbered badges mark the flows explained in docs/ARCHITECTURE_COMPONENTS.md.
"""

from __future__ import annotations

import sys
from html import escape
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "diagrams" / "platform-component-architecture.svg"
W, H = 2400, 1700
CHAR = {"s": 6.15, "t": 7.4, "m": 6.6}         # average glyph width per text class (Segoe UI / Arial)
LINE, HEAD, PAD = 15, 24, 10
parts: list[str] = []
problems: list[str] = []


def text(x, y, s, cls="s", anchor=None):
    a = f' text-anchor="{anchor}"' if anchor else ""
    parts.append(f'<text x="{x}" y="{y}" class="{cls}"{a}>{escape(s)}</text>')


def fits(s: str, w: float, cls: str, where: str) -> None:
    if len(s) * CHAR[cls] > w - 2 * PAD + 2:
        problems.append(f"{where}: '{s}' ({len(s)} chars, box {w}px)")


def box(x, y, w, title, lines, style="box", mono=False):
    h = HEAD + LINE * len(lines) + PAD
    parts.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="7" class="{style}"/>')
    fits(title, w, "t", title)
    text(x + PAD, y + 18, title, "t")
    for i, ln in enumerate(lines):
        cls = "m" if mono else "s"
        fits(ln, w, cls, title)
        text(x + PAD, y + HEAD + 12 + i * LINE, ln, cls)
    return h


def zone(x, y, w, h, label, cls="zone"):
    parts.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="12" class="{cls}"/>')
    text(x + 14, y + 20, label, "z")


def badge(x, y, n, colour="#2563eb"):
    parts.append(f'<circle cx="{x}" cy="{y}" r="11" fill="{colour}"/>')
    parts.append(f'<text x="{x}" y="{y + 4}" class="n" text-anchor="middle">{n}</text>')


def arrow(d, cls="line"):
    parts.append(f'<path d="{d}" class="{cls}"/>')


# ----------------------------------------------------------------------------------------------- left: client services
zone(20, 70, 300, 1610, "Client environment services")
y = 100
left = [
    ("Analyst browser", ["Static console: index.html, app.js,", "views.js, theme.js, styles.css", "(vanilla JS, strict CSP, no inline", "handlers; esc() on every value)"]),
    ("Reverse proxy + WAF", ["Azure App Gateway / Front Door /", "nginx / IIS ARR; TLS 443 -> :8080;", "SOC_TRUSTED_PROXIES for", "X-Forwarded-For"]),
    ("Microsoft Entra ID", ["OIDC auth code + PKCE (console)", "RS256 access tokens, JWKS keys", "App roles SOC.<Role>[.<Domain>]", "MFA via Conditional Access"]),
    ("Azure Key Vault", ["Secrets mounted as files:", "<NAME>_FILE (DB URL, SOC_DATA_KEY,", "tool keys, PEM certificates,", "SOC_LLM_API_KEY, webhooks)"]),
    ("Client LLM gateway", ["Azure OpenAI / AI Foundry, or", "Anthropic / OpenAI-compatible", "endpoint approved by the client", "(SOC_LLM_PROVIDER, _ENDPOINT)"]),
    ("SIEM (Microsoft Sentinel)", ["Log agent reads container stdout", "(SOC_LOG_FORMAT=json) + audit", "export; optional push to", "POST /api/v1/ingest/alerts"]),
    ("Teams / Slack / JSON webhook", ["SOC_NOTIFY_WEBHOOKS (HTTPS only)", "kind|url; label kind:host only"]),
    ("Prometheus / monitoring", ["GET /metrics (auditor key) + alert", "rules; GET /health details when", "signed in: scheduler, audit chain"]),
    ("GitHub + Actions CI", ["ruff, bandit, pip-audit (lock),", "pytest SQLite + PostgreSQL 16,", "precommit_scan, gitleaks,", "CycloneDX SBOM, Trivy image scan"]),
]
for title, lines in left:
    y += box(32, y, 276, title, lines) + 14
badge(298, 104, 1)
badge(298, 212, 1)

# ----------------------------------------------------------------------------------------------- centre: platform
zone(340, 70, 1300, 1610, "Agentic SOC platform (Python 3.11) - Docker images, non-root uid 1001", "zoneb")
X0, CW = 352, 1276
# R1 runtime
y = 100
rt = [
    ("soc-api (2+ replicas)", ["python -m soc_platform serve", "uvicorn, SOC_API_WORKERS processes", "FastAPI / Starlette, port 8080", "probes /health/live, /health/ready"]),
    ("soc-scheduler (2 replicas)", ["python -m soc_platform scheduler", "scheduler.py + jobs.py JOBS", "leases renewed while running;", "dead one taken over in 120 s"]),
    ("PostgreSQL 16 (HA)", ["managed zone-redundant / 3-node", "SQLAlchemy 2 + psycopg2, pre-ping", "pool per worker; column widening", "SQLite for dev (PG rules enforced)"]),
    ("Build and supply chain", ["deploy/Dockerfile (multi-stage)", "requirements/platform.lock", "scripts/supply_chain.py (SBOM)", "no pip in the runtime image"]),
]
bw = (CW - 3 * 12) / 4
for i, (t, ls) in enumerate(rt):
    box(X0 + i * (bw + 12), y, bw, t, ls, "ctr")
badge(X0 + bw - 6, 104, 2)

# R2 request pipeline
y = 220
zone(X0, y, CW, 150, "Request pipeline - api/app.py (every request, in this order)", "zoned")
chain = [
    ("BodyLimitMiddleware", ["rejects bodies > 30 MB", "(streamed, not buffered)"]),
    ("SecurityMiddleware", ["NUL in path/query -> 400", "bad Content-Length -> 413", "token bucket 20/s, burst 120"]),
    ("current_user", ["core/auth.py: Entra RS256 /", "dev HS256 (PyJWT); API key;", "break-glass; core/access.py"]),
    ("need(Perm, domain)", ["role permissions + domain", "scope; step-up MFA; human-", "only perms; out of scope=404"]),
    ("Route handler", ["api/app.py, api/dashboards.py", "DataError 400, KeyError 404,", "PermissionError 403"]),
    ("db_session + response", ["commit before reply", "security headers + CSP", "queued access-log row"]),
]
cw = (CW - 24 - 5 * 14) / 6
for i, (t, ls) in enumerate(chain):
    bx = X0 + 12 + i * (cw + 14)
    box(bx, y + 32, cw, t, ls)
    if i:
        arrow(f"M{bx - 13} {y + 70} H{bx - 2}")
badge(X0 + 12 + cw - 6, y + 36, 3)

# R3 domains, intelligence, reporting
y = 384
dom = [
    ("domains/phishing/", ["service.py pipeline, models.py", "agents/decompose.py (MIME, QR:", "pyzbar, Pillow; ppdeep hashes)", "agents/analyzer.py (rules, look-", "alikes) + CompositeAnalyzer.fuse", "engine/: LangGraph 7-agent swarm,", "scikit-learn 1.8 TF-IDF (offline)", "agents/investigation.py (impact)", "supplier.py (vendor e-mail risk)"]),
    ("domains/incident/", ["service.py: ingest ALERT_STREAMS", "+ AUDIT_STREAMS (Entra audits),", "cluster by host / person,", "investigate: enrichment, _score", "(deterministic severity), _mitre,", "_verdict_conflict (tools disagree),", "_recommendations, reassess_open,", "narrate_pending (deferred LLM)"]),
    ("domains/vulnerability/", ["service.py: ingest 4 scanners,", "consolidate (asset + CVE),", "refresh_intel (NVD/EPSS/KEV),", "prioritise P1-P4 + SLA, owners,", "campaigns, follow_up, validate", "(verify_finding), exceptions", "(four-eyes, expiry), risk register;", "misconfig.py (Wiz issues)"]),
    ("intelligence/", ["risk.py RiskEngine (cached,", "data-anchored decay)", "correlation.py (13 rules)", "story.py (attack story)", "deep_analysis.py, analyst.py", "attack_coverage.py (ATT&CK)", "shadow_it.py, drift.py (PSI)"]),
    ("reporting/", ["builder.py: 17 sources,", "7 standard reports, planner", "reports.py: python-docx,", "python-pptx, charts", "compliance.py: evidence pack", "value.py: KPI scorecard"]),
]
dw = (CW - 4 * 12) / 5
for i, (t, ls) in enumerate(dom):
    box(X0 + i * (dw + 12), y, dw, t, ls, "key")
badge(X0 + dw - 6, y + 4, 5)
badge(X0 + 2 * (dw + 12) - 18, y + 4, 4)
badge(X0 + 3 * (dw + 12) - 18, y + 4, 6)

# R4 core
y = 572
zone(X0, y, CW, 330, "core/ - shared services (services take a Session and never commit; the request or job owns the transaction)", "zoned")
core = [
    ("context_store.py", ["ingest(), neighbors, timelines,", "keys_of; one SourceRecord each"]),
    ("entity_resolution.py", ["keys -> scored hints (rapidfuzz)", "auto 0.85, review 0.55 -> queue"]),
    ("identity.py", ["user_ref(): UPN / SAM / SID keys", "built-in & machine accounts out"]),
    ("cases.py (CaseService)", ["cases, evidence, notes, owner,", "recommend(ceiling=), narration"]),
    ("enrichment.py", ["EnrichmentOrchestrator: 16", "threads, 20 s deadline, cache"]),
    ("actions.py (ActionService)", ["the ONLY write path; idempotency", "keys; conditional updates"]),
    ("policy.py", ["L0-L4, PolicyEngine.decide(ceiling)", "PolicyStore propose / approve"]),
    ("auth.py + access.py", ["roles/perms, token checks; grants,", "API keys, revocation, kill switch"]),
    ("audit.py", ["hash-chained append-only log;", "_lock_chain serialises appends"]),
    ("crypto.py", ["Fernet / MultiFernet; atomic", "0600 writes; key rotation"]),
    ("retention.py + selfcheck.py", ["per-class retention, legal hold;", "cross-surface consistency proof"]),
    ("connector_config.py", ["ConfigStore: propose / approve /", "pause / restore; preflight gate"]),
    ("observability.py", ["trace ids (TRACE, traced()),", "event() JSON logs, masking"]),
    ("notify.py", ["Notification table, webhook", "delivery, dedupe per channel"]),
    ("db.py + models.py", ["UTCDateTime, BoundedText, NUL", "strip; utcnow(), new_id()"]),
    ("settings_check.py + config.py", ["SPEC validation, secret() reads", "<NAME>_FILE; missing file = error"]),
]
qw = (CW - 24 - 3 * 12) / 4
for i, (t, ls) in enumerate(core):
    r, c = divmod(i, 4)
    style = "gov" if t.startswith(("actions", "policy")) else "box"
    box(X0 + 12 + c * (qw + 12), y + 32 + r * 74, qw, t, ls, style)
badge(X0 + 12 + 2 * (qw + 12) - 18, y + 36 + 74, 7, "#c2410c")

# R5 llm + connectors framework
y = 916
box(X0, y, 400, "llm/ - model access (optional)", [
    "gateway.py: LLMGateway grounded() /", "complete_json(); citations validated,",
    "numeric-fidelity guardrail, breaker,", "timeouts, SOC_LLM_CONCURRENCY",
    "redaction.py: Redactor pseudonymise /", "restore", "usage_policy.py: budgets, per-person",
    "limits, per-feature tier, usage_report", "providers/: openai_compatible",
    "(azure_openai), anthropic_provider"], "key")
badge(X0 + 388, y + 4, 8)
box(X0 + 412, y, CW - 412, "connectors/ - integration framework", [
    "base.py: BaseConnector, TokenBucket (thread-safe rate budget), with_backoff (Retry-After <= 120 s), SyncRunner",
    "(sync, sync_many: parallel download, ordered ingest, savepoint + commit per page), Page, Watermark, LookupResult",
    "http.py: HttpTransport (httpx), FixtureTransport (fake mode), OAuth2ClientCredentials, RFC 7523 certificate",
    "assertion (x5t, 10 min), BasicAuth, ApiKeyHeader/Query, RoutingTransport (Graph + ARM), raise_for_status",
    "registry.py: MANIFEST discovery, ConnectorRegistry (isolation, stages fake/record/read/recommend/automate)",
    "config_schema.py (strict, did-you-mean) | preflight.py (sign-in, streams, scopes) | conform.py (shape from fixtures)",
    "recording.py (record-and-sanitise) | devkit.py (connector new / check) | tools/*.py: one module per tool (21)",
    "Outbound only through each connector's TokenBucket; 401 -> token renewed once, 403 -> PermissionDenied",
], "key")
badge(X0 + CW - 14, y + 4, 2)

# R6 data
y = 1110
box(X0, y, 760, "PostgreSQL 16 - main table groups", [
    "Context: entities, entity_keys, entity_hints, relations, source_records, unresolved_items, resolution_overrides",
    "Cases: cases, evidence, case_entities, case_notes, decisions, dispositions",
    "Actions and governance: action_requests, policy_versions, connector_config_versions, access grants, api keys",
    "Audit and logs: audit_log (hash chain), access_log, llm_calls / usage, job_runs, system_flags (leases, kill switch)",
    "Phishing: ph_submissions (unique source_ref) | Vulnerability: vm_findings, campaigns, action plans,",
    "vuln_exceptions, risk register, vuln_intel | Intelligence: insights, briefs | notifications | blobs (stored files)",
], "box")
box(X0 + 772, y, 252, "Encrypted blob store", ["SOC_BLOB_STORE=database: blobs", "table, every replica reads it", "(or a volume: SOC_RAW_PAYLOAD_DIR,", "SOC_REPORT_OUTPUT_DIR)", "Fernet (SOC_DATA_KEY), SHA-256"])
box(X0 + 1036, y, CW - 1036, "Configuration + artefacts", ["config/connectors.yaml (${VAR}", "refs only), suppliers.yaml,", "sanctioned_services.yaml;", "artifacts/phishing/models/", "(trained models, offline)"])

# flow legend inside the platform zone
y = 1262
zone(X0, y, CW, 400, "Flows (numbered badges) - each explained step by step in the component architecture document", "zone")
legend = [
    ("1", "#2563eb", "Sign-in: browser -> proxy/WAF -> soc-api; Entra token (RS256, JWKS) -> roles + domain scope."),
    ("2", "#2563eb", "Collect: scheduler job -> SyncRunner.sync_many -> connector fetch_page -> normalize -> context_store.ingest."),
    ("3", "#2563eb", "Request: BodyLimit -> Security -> current_user -> need(Perm, domain) -> handler -> commit -> headers."),
    ("4", "#2563eb", "Investigate: workflow -> EnrichmentOrchestrator (parallel lookups) -> evidence -> fixed-rule scoring."),
    ("5", "#2563eb", "Phishing: reported mail -> decompose -> rules + offline ML -> campaign / clicks / impact -> case."),
    ("6", "#2563eb", "Correlate and report: RiskEngine -> 13 rules -> insights -> notify / reports (python-docx / pptx)."),
    ("7", "#c2410c", "Act: recommendation -> PolicyEngine.decide -> approval (four-eyes) -> ActionService -> connector write."),
    ("8", "#2563eb", "Explain: LLMGateway -> Redactor -> client LLM -> citation + figure checks -> narrative stored."),
    ("A", "#475569", "Every step: trace id (observability.py), audit_log append, access_log row, JSON log to SIEM."),
]
for i, (n, col, s) in enumerate(legend):
    badge(X0 + 28, y + 50 + i * 38, n, col)
    fits(s, CW - 40, "s", "legend")
    text(X0 + 48, y + 54 + i * 38, s, "s")

# ----------------------------------------------------------------------------------------------- right: 21 connectors
zone(1660, 70, 720, 1610, "21 connectors (tools/*.py) - vendor APIs over HTTPS 443, one least-privilege identity per tool")
tiles = [
    ("CrowdStrike Falcon  (crowdstrike)", "OAuth2 client credentials", ["R /alerts/queries + entities/alerts/v2", "R /devices/queries/devices-scroll/v1", "R /spotlight/combined/vulnerabilities/v1", "W /devices/entities/devices-actions/v2", "W /real-time-response/entities/*"]),
    ("Defender for Endpoint  (defender_endpoint)", "Entra app: certificate or secret", ["R /api/alerts, /api/machines", "R /api/vulnerabilities/machinesVuln...", "R /api/advancedqueries/run", "W /api/machines/{id}/isolate | scan |", "  collectInvestigationPackage; /api/indicators"]),
    ("Defender for O365  (defender_office365)", "Graph + Exchange admin API", ["R users/{mbox}/mailFolders/inbox/messages", "R security/alerts_v2, runHuntingQuery", "  (EmailEvents, UrlClickEvents, ...)", "W beta analyzedEmails/remediate, sendMail", "W adminapi InvokeCommand (block list)"]),
    ("Defender for Identity  (defender_identity)", "Entra app via Graph (read-only)", ["R security/alerts_v2 (MDI source)", "R runHuntingQuery: IdentityLogonEvents", "  (look-up per person / address)"]),
    ("Microsoft Entra ID  (entra)", "Graph + ARM, certificate or secret", ["R /v1.0/users, auditLogs/signIns,", "  auditLogs/directoryAudits", "R identityProtection/riskyUsers, ...", "R ARM roleAssignments (Azure roles)", "W revoke sessions, disable, reset, risk"]),
    ("Avanan / Harmony Email  (avanan)", "API key exchanged for a token", ["R /app/hec-api/v1.0 search / event", "R verdict by internetMessageId", "W quarantine / restore action"]),
    ("Cisco Umbrella  (umbrella)", "OAuth2 client credentials", ["R /reports/v2/activity/dns", "R /reports/v2/categories", "W /policies/v2/destinationlists/{id}/", "  destinations (+ /remove)"]),
    ("Thinkst Canary  (canary)", "API auth token", ["R /api/v1/incidents/all", "R /api/v1/devices/all", "W /api/v1/incident/acknowledge"]),
    ("Delinea Secret Server", "OAuth2 password grant (API user)", ["R /api/v1/secret-audits", "R /api/v1/launched-sessions", "W secret change-password (rotation)", "account_owners map (admin -> person)"]),
    ("Delinea Privilege Manager", "OAuth2 client credentials", ["R /Tms/api/v1/events/elevation"]),
    ("Rapid7 InsightVM  (rapid7)", "HTTP Basic, read-only user (or CSV)", ["R /api/3/assets (+ /{id}/vulnerabilities)", "R /api/3/vulnerabilities/{id} (+solutions)", "R /api/3/vulnerability_exceptions"]),
    ("Wiz  (wiz)", "OAuth2 service account", ["R POST /graphql: cloudResources,", "  vulnerabilityFindings, issuesV2", "  (cursor paging)"]),
    ("ServiceNow  (servicenow)", "OAuth2 client credentials or Basic", ["R/W /api/now/table/{ticket_table}", "R /api/now/table/cmdb_ci_computer", "W create / update ticket (correlation_id)"]),
    ("Jira  (jira)", "Basic: e-mail + API token", ["R /rest/api/3/search/jql", "W /rest/api/3/issue (+ /comment)"]),
    ("Ownership CSV  (cmdb_csv)", "mounted file", ["owner, platform team, environment,", "criticality per host"]),
    ("Microsoft Sentinel  (sentinel)", "Entra app via ARM (Reader)", ["R /subscriptions/../workspaces/..", "  /Microsoft.SecurityInsights/incidents", "  (+ entities)"]),
    ("Generic SIEM push  (generic_siem)", "inbound: platform API key", ["POST /api/v1/ingest/alerts", "field map; bad item refused alone"]),
    ("NIST NVD  (nvd)", "optional API key", ["R services.nvd.nist.gov", "  /rest/json/cves/2.0 (CVE ids only)"]),
    ("FIRST EPSS  (epss)", "none", ["R api.first.org/data/v1/epss"]),
    ("CISA KEV  (cisa_kev)", "none", ["R www.cisa.gov .../known_exploited_", "  vulnerabilities.json"]),
    ("Threat-intel fusion  (threat_intel)", "per-source API key (opt-in)", ["VirusTotal v3, AbuseIPDB v2/check, OTX,", "URLhaus, ThreatFox, MalwareBazaar,", "GreyNoise, Shodan - external", "indicators only (internal withheld)"]),
]
cols = [[], []]
heights = [100, 100]
TW = 344
for t, auth, eps in tiles:
    c = 0 if heights[0] <= heights[1] else 1
    x = 1672 + c * (TW + 12)
    yy = heights[c]
    h = box(x, yy, TW, t, [auth, *eps], "ext")
    heights[c] += h + 10
if max(heights) > 1670:
    problems.append(f"connector tiles overflow the zone (bottom at {max(heights)})")

# main arrows
arrow("M308 196 H348")                                         # browser/proxy -> platform
arrow(f"M{X0 + CW} 1000 H1668", "line")                        # connectors -> tools
# approved write path, highlighted
# from the side of actions.py (row 2, column 2) down the gap between columns 2 and 3 into the connectors
act_right = X0 + 12 + 2 * qw + 12
gap = act_right + 6
arrow(f"M{act_right} 712 H{gap} V912", "write")
text(gap + 8, 912, "policy-gated writes only", "wl")
arrow(f"M{X0 + CW} 1030 H1668", "write")

if problems:
    print("text does not fit:\n  " + "\n  ".join(problems))
    sys.exit(1)

svg = f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" font-family="Segoe UI, Arial, sans-serif" font-size="14">
  <defs>
    <marker id="a" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="#475569"/></marker>
    <marker id="w" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="#c2410c"/></marker>
    <style>
      .zone{{fill:#f1f5f9;stroke:#94a3b8;stroke-dasharray:6 4}}
      .zoneb{{fill:#eef4ff;stroke:#7ea2d6;stroke-dasharray:6 4}}
      .zoned{{fill:#f3f0ff;stroke:#a495d6;stroke-dasharray:6 4}}
      .box{{fill:#ffffff;stroke:#334155;stroke-width:1.2}}
      .ctr{{fill:#ffffff;stroke:#0f766e;stroke-width:1.4}}
      .key{{fill:#ffffff;stroke:#2563eb;stroke-width:1.4}}
      .gov{{fill:#fff7ed;stroke:#c2410c;stroke-width:1.5}}
      .ext{{fill:#fff7e8;stroke:#c2410c;stroke-width:1.1}}
      .t{{font-weight:600;fill:#0f172a;font-size:13px}}
      .s{{fill:#334155;font-size:11.5px}}
      .m{{fill:#334155;font-size:11.5px}}
      .z{{fill:#334155;font-weight:600;font-size:13px}}
      .n{{fill:#ffffff;font-weight:700;font-size:12px}}
      .h{{font-weight:600;fill:#0f172a}}
      .line{{stroke:#475569;stroke-width:1.6;fill:none;marker-end:url(#a)}}
      .none{{stroke:none;fill:none}}
      .write{{stroke:#c2410c;stroke-width:2.4;fill:none;marker-end:url(#w)}}
      .lbl{{fill:#1e293b;font-size:11.5px;font-weight:600}}
      .wl{{fill:#c2410c;font-size:11.5px;font-weight:700}}
    </style>
  </defs>
  <rect width="{W}" height="{H}" fill="#ffffff"/>
  <text x="30" y="34" class="h" font-size="22">Agentic SOC platform - component architecture (tools, modules, technologies, endpoints)</text>
  <text x="30" y="56" class="s">Production shape in the client's environment. Boxes are real components (file / module / technology / table / vendor endpoint). R = read, W = write (policy-gated). Orange = the only path that can change a security tool.</text>
  {chr(10).join(parts)}
</svg>
"""
OUT.write_text(svg, encoding="utf-8")
print(f"{OUT} ({len(tiles)} connector tiles)")
