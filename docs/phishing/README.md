# Phishing ML engine - internal documentation

These documents describe the **phishing ML engine** (the 7-agent swarm, LangGraph orchestration,
sandbox, and the engine's own API), which now lives at `soc_platform/domains/phishing/engine/`
with trained models in `artifacts/phishing/`. Paths in these documents have been updated to the
platform layout.

The engine is one analysis backend of the platform's phishing workflow. The workflow itself
(ingestion from the reporting mailbox, reconciliation with Defender/Avanan, campaign scope, user
and endpoint/identity impact, supplier risk, gated remediation, reporter feedback) is in
`soc_platform/domains/phishing/service.py` and is documented in the top-level
[README](../../README.md), [ARCHITECTURE](../ARCHITECTURE.md) and
[REQUIREMENTS_TRACEABILITY](../REQUIREMENTS_TRACEABILITY.md).

Where these documents and the platform docs differ (deployment, security, authentication), the
platform docs are authoritative: in particular the engine is deployed with
`deploy/docker-compose.yml --profile engine`, its API requires an API key by default, the sandbox
fails closed, and all remediation goes through the platform's policy-gated action layer.

| Document | Scope |
|---|---|
| `architecture.md`, `final_arch.png` | engine internals: agents, orchestration, scoring |
| `agent_testing_guide.md` | testing individual agents |
| `AZURE_API_CONFIGURATION.md` | Azure OpenAI / Graph / Search settings used by the engine |
| `deployment_runbook.md`, `recovery_runbook.md`, `monitoring_alerting.md` | engine service operations |
| `TECHNICAL_PROJECT_REPORT.md` | original project report (historical) |
