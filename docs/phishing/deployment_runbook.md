# Deployment Runbook

## 1. Scope
This runbook describes production startup and validation for the Agentic Email Security platform.

## 2. Preconditions
- Production secrets populated in `.env` (no defaults from `.env.template`).
- PostgreSQL, RabbitMQ, Redis reachable.
- Attachment and email-drop volumes provisioned.
- Sandbox detonation isolated from host Docker socket.

## 3. Required Environment Values
- `DATABASE_URL`
- `RABBITMQ_HOST`, `RABBITMQ_USER`, `RABBITMQ_PASSWORD`
- `REDIS_URL`
- `QUARANTINE_API_URL`, `SOC_ALERT_API_URL`
- `AZURE_OPENAI_ENDPOINT`, `AZURE_OPENAI_API_KEY`, `AZURE_OPENAI_DEPLOYMENT`
- `VIRUSTOTAL_API_KEY` (if used)
- `GOOGLE_SAFE_BROWSING_API_KEY` (if used)
- `OTX_API_KEY`, `ABUSEIPDB_API_KEY` (if used)
- `ENABLE_VIRUSTOTAL_URL_LOOKUP`, `ENABLE_GOOGLE_SAFE_BROWSING_LOOKUP`, `ENABLE_OPENPHISH_LOOKUP`, `ENABLE_URLHAUS_LOOKUP`
- `ENABLE_OTX_LOOKUP`, `ENABLE_ABUSEIPDB_LOOKUP`, `ENABLE_MALWAREBAZAAR_LOOKUP`, `ENABLE_VIRUSTOTAL_HASH_LOOKUP`
- `EXTERNAL_LOOKUP_TIMEOUT_SECONDS`, `EXTERNAL_LOOKUP_MAX_INDICATORS`
- `ORCHESTRATOR_PARTIAL_TIMEOUT_SECONDS`, `ORCHESTRATOR_MIN_AGENTS_FOR_DECISION`

## 4. Hardened Compose Notes
- In `docker/docker-compose.yml`, sandbox service does not mount `/var/run/docker.sock`.
- Use isolated detonation workers/VMs for dynamic analysis.

## 5. Startup Sequence
1. Pull/build images.
2. Start infrastructure services first: database, redis, rabbitmq.
3. Start api, parser, orchestrator.
4. Start agent services.

## 6. Startup Commands
```bash
cd docker
docker compose up -d --build
```

## 7. Health Checks
- API health:
```bash
curl -s http://localhost:8000/health
```
- RabbitMQ management UI: `http://localhost:15672`
- Confirm no crash loops:
```bash
docker ps
docker compose logs --tail=200 orchestrator_service
```

## 8. E2E Validation
1. Submit an email:
```bash
curl -s -X POST http://localhost:8000/analyze-email \
  -H "Content-Type: application/json" \
  -d '{
    "headers": {"sender":"attacker@evil.example","subject":"Urgent verify"},
    "body":"Login now https://evil.example/login",
    "urls": ["https://evil.example/login"],
    "attachments": []
  }'
```
2. Capture `analysis_id` from response.
3. Poll final report:
```bash
curl -s http://localhost:8000/reports/<analysis_id>
```
4. Verify decision contains expected actions and that quarantine/SOC endpoints received callbacks.

## 9. Go-Live Checklist
- [ ] No default credentials remain.
- [ ] Quarantine and SOC callback endpoints verified.
- [ ] Orchestrator partial-finalization thresholds approved by SOC.
- [ ] Monitoring alerts installed from `configs/monitoring/prometheus_alert_rules.yml`.
- [ ] Runbook and rollback owner assigned.
