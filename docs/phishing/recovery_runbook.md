# Recovery Runbook

## 1. Incident Types
- Queue backlog spike.
- Database outage or write failures.
- Agent crash loop.
- Elevated partial finalization rate.
- Action endpoint outage (quarantine/SOC).

## 2. Immediate Triage
1. Check service health and logs:
```bash
docker compose ps
docker compose logs --tail=200 api_service orchestrator_service parser_service
```
2. Check RabbitMQ queue depth and consumer status.
3. Check DB connectivity from orchestrator container.
4. Check error-rate and partial-finalization alerts.

## 3. Queue Backlog Recovery
1. Validate agents are consuming.
2. If one agent is down, restart only that service.
3. Temporarily scale critical consumers:
```bash
docker compose up -d --scale header_agent_service=2 --scale url_agent_service=2
```
4. Reduce ingestion rate if backlog keeps growing.

## 4. Database Outage Recovery
1. Confirm DB container/service availability.
2. Restore DB connectivity.
3. Restart orchestrator after DB recovery.
4. Replay pending results from queue if needed.

## 5. Action Endpoint Outage Recovery
1. Confirm `QUARANTINE_API_URL` and `SOC_ALERT_API_URL` reachability.
2. Restore endpoint service.
3. Re-run high-risk decisions from persisted reports if callbacks were skipped.

## 6. Partial-Finalization Spike
1. Check which agents are missing from `missing_agents` in reports.
2. Increase capacity for lagging agents.
3. Review and tune:
- `ORCHESTRATOR_PARTIAL_TIMEOUT_SECONDS`
- `ORCHESTRATOR_MIN_AGENTS_FOR_DECISION`

## 7. Rollback Procedure
1. Identify last known good image tags.
2. Roll back service images.
3. Restart stack with previous tags.
4. Validate via:
- `/health`
- POST analyze
- GET report
- action callback checks

## 8. Data Integrity Checks After Recovery
- Verify `threat_reports` insert/update activity resumed.
- Verify no sustained growth in unacked RabbitMQ messages.
- Verify report retrieval works for new `analysis_id` values.
