# Monitoring and Alerting Guide

## 1. Required SLO Signals
- Queue depth per queue (ingestion + results).
- Agent lag (seconds since last successful result per agent).
- Error rate per service.
- Partial-finalization rate in orchestrator.

## 2. Core Metrics
Use RabbitMQ exporter + app/service metrics.

### Queue Depth
- `rabbitmq_queue_messages_ready{queue="..."}`
- `rabbitmq_queue_messages_unacked{queue="..."}`

### Agent Lag
- `email_security_agent_lag_seconds{agent_name="..."}`

### Error Rate
- `email_security_errors_total{service="..."}`

### Partial Finalization
- `email_security_orchestrator_finalizations_total{reason="partial_timeout"}`
- `email_security_orchestrator_finalizations_total{reason="complete"}`

## 3. Alert Rules Source
See: `configs/monitoring/prometheus_alert_rules.yml`

## 4. Alert Routing
- Warning alerts -> SOC operations channel.
- Critical alerts -> Pager/on-call rotation.

## 5. Suggested Dashboards
1. Ingestion and queue dashboard.
2. Agent processing latency and lag dashboard.
3. Error-rate dashboard per component.
4. Orchestrator quality dashboard (complete vs partial finalization).

## 6. Operator Actions by Alert Type
- Queue depth high: verify consumers, scale bottleneck agents, reduce ingress.
- Agent lag high: restart affected agent and inspect model/runtime errors.
- Error-rate high: inspect latest deployment changes and exception hotspots.
- Partial-finalization high: tune timeout/min-agent settings and fix lagging agent.
