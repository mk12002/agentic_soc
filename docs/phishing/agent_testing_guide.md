# Agent Direct Testing Guide

This guide explains exactly where to input test data, what to input, how to run tests per agent, and where to get results.

## Purpose

Use the direct agent test endpoints to test each agent independently with your own payloads.

Important:
- This does **not** use RabbitMQ.
- This does **not** trigger orchestrator decisioning.
- This does **not** trigger action-layer execution.
- Your current production data flow remains unchanged.

## Endpoints

- `GET /agent-test/agents`
- `GET /agent-test/examples`
- `POST /agent-test/{agent_name}`

Supported agent names:
- `header_agent`
- `content_agent`
- `url_agent`
- `attachment_agent`
- `sandbox_agent`
- `threat_intel_agent`
- `user_behavior_agent`

## Where To Input

You can input data in either of these places:

1. Swagger UI
- Open `http://localhost:8000/docs`
- Go to the `Agent Testing` section
- Use `POST /agent-test/{agent_name}`

2. Terminal (curl)
- Send JSON request body to `POST /agent-test/{agent_name}`

## What To Input

Request body format:

```json
{
  "payload": {
    "...": "agent-specific fields"
  },
  "inject_analysis_id": true,
  "print_output": true
}
```

Fields:
- `payload`: Your custom input for that specific agent.
- `inject_analysis_id`: If `true`, a test `analysis_id` is added when missing.
- `print_output`: If `true`, input and output are printed in API logs.

## How To Input (Step-by-Step)

1. Start API service.
2. Call `GET /agent-test/examples` to copy a template payload.
3. Edit that payload with your own test values.
4. Call `POST /agent-test/{agent_name}` with the edited payload.
5. Review JSON response and optional logs.

## Copy-Paste Commands

### 1) List testable agents

```bash
curl http://localhost:8000/agent-test/agents
```

### 2) Fetch example payloads

```bash
curl http://localhost:8000/agent-test/examples
```

### 3) Test content agent

```bash
curl -X POST http://localhost:8000/agent-test/content_agent \
  -H "Content-Type: application/json" \
  -d '{
    "payload": {
      "headers": {"subject": "Invoice overdue"},
      "body": "Urgent action required. Confirm your password now."
    },
    "inject_analysis_id": true,
    "print_output": true
  }'
```

### 4) Test URL agent

```bash
curl -X POST http://localhost:8000/agent-test/url_agent \
  -H "Content-Type: application/json" \
  -d '{
    "payload": {
      "urls": [
        "http://secure-login-paypa1.example/verify",
        "https://microsoft.com-security-login.example/reset"
      ]
    },
    "inject_analysis_id": true,
    "print_output": true
  }'
```

### 5) Test header agent

```bash
curl -X POST http://localhost:8000/agent-test/header_agent \
  -H "Content-Type: application/json" \
  -d '{
    "payload": {
      "headers": {
        "sender": "alerts-security@paypa1-security.example",
        "reply_to": "support@evil.example",
        "subject": "Urgent: verify your account",
        "received": ["from smtp-unknown by victim-mx"],
        "message_id": "<m-header-1>",
        "authentication_results": "spf=fail; dkim=fail; dmarc=fail"
      }
    },
    "inject_analysis_id": true,
    "print_output": true
  }'
```

If API auth is enabled, also add:

```bash
-H "X-API-Key: <your_api_key>"
```

## Where You Get Results

1. API response (primary)
- Returned immediately from `POST /agent-test/{agent_name}`.
- Result is in `output`.

2. API logs (optional)
- Available when `print_output=true`.
- Log lines include:
  - `[AGENT-TEST][<agent_name>] INPUT: ...`
  - `[AGENT-TEST][<agent_name>] OUTPUT: ...`

## Response Shape

Example response:

```json
{
  "status": "completed",
  "agent_name": "content_agent",
  "message": "Agent tested in isolated direct mode. No RabbitMQ publish and no orchestrator/action dispatch occurred.",
  "input_payload": {
    "analysis_id": "manual-agent-test-...",
    "headers": {"subject": "Invoice overdue"},
    "body": "Urgent action required..."
  },
  "output": {
    "agent_name": "content_agent",
    "risk_score": 0.42,
    "confidence": 0.88,
    "indicators": ["..."]
  }
}
```

## Notes For Attachment and Sandbox Tests

For `attachment_agent` and `sandbox_agent`, include realistic attachment metadata in `payload.attachments` and a valid `path` when your agent logic expects on-disk files.

## File Location

This guide is saved at:
- `email_security/docs/agent_testing_guide.md`

graph TD
    classDef newFeature fill:#1e40af,stroke:#60a5fa,stroke-width:2px,color:#fff
    classDef agent fill:#0f172a,stroke:#3b82f6,color:#fff
    classDef core fill:#334155,stroke:#94a3b8,color:#fff
    classDef db fill:#064e3b,stroke:#34d399,color:#fff

    subgraph "Ingestion & API Layer"
        API[FastAPI Endpoint: /analyze-email]:::core --> RMQ[RabbitMQ Task Queue]:::core
    end

    subgraph "Agentic Analysis Layer (Parallel Execution)"
        RMQ --> HA[Header Agent]:::agent
        RMQ --> CA[Content Agent]:::agent
        RMQ --> UA[URL Agent]:::agent
        RMQ --> AA[Attachment Static Agent]:::agent
        RMQ --> SA[Sandbox Dynamic Agent]:::agent
        RMQ --> TI[Threat Intel Agent]:::agent
        RMQ --> UB[User Behavior Agent]:::agent
    end

    subgraph "Orchestrator Layer (LangGraph State Machine)"
        HA & CA & UA & AA & SA & TI & UB --> |"State: Agent Results"| S[Node: Score Engine]:::core
        S --> C[Node: Correlate Threats]:::core
        C --> D[Node: Decide Final Verdict]:::core
        
        %% --- NEWLY ADDED COMPONENTS --- %%
        D --> CF[Node: Counterfactual Engine\nFinds Minimum Change Threshold]:::newFeature
        CF --> R[Node: Azure OpenAI Reasoner]:::core
        R --> SL[Node: Threat Storyline Engine\nChronological Attacker Phases]:::newFeature
        %% -------------------------------- %%
    end

    subgraph "Action & Persistence Layer"
        SL --> Cond{Needs Garuda?}
        Cond -->|Yes: Score > 0.7| GA[Node: Garuda Endpoint Threat Hunting]:::core
        Cond -->|No| P
        GA --> P[Node: Persist to Storage]:::core
        P --> DB[(PostgreSQL & Local IOCs)]:::db
        P --> Act[Node: Dispatch Actions]:::core
        Act --> Qu[Quarantine / Alerts]:::core
        Act --> Fin[Node: Finalize API Response]:::core
    end
    
    Fin --> UI[SOC Dashboard]:::core
