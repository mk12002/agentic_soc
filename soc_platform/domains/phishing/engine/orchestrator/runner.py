"""
Orchestrator worker.

Consumes results from all agents, aggregates per analysis_id, stores final reports,
and triggers Garuda/action layer for high-risk cases.
"""

from __future__ import annotations

import json
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from typing import Any

import redis
from psycopg2.extras import Json

from soc_platform.domains.phishing.engine.action_layer.response_engine import execute_actions
from soc_platform.domains.phishing.engine.agents.model_warmup import warmup_orchestrator_at_startup
from soc_platform.domains.phishing.engine.configs.settings import settings
from soc_platform.domains.phishing.engine.orchestrator.langgraph_state import OrchestratorState
from soc_platform.domains.phishing.engine.orchestrator.langgraph_workflow import LangGraphOrchestrator
from soc_platform.domains.phishing.engine.services.database import connect_database
from soc_platform.domains.phishing.engine.services.logging_service import get_service_logger, setup_logging
from soc_platform.domains.phishing.engine.services.messaging_service import RabbitMQClient

logger = get_service_logger("orchestrator_runner")

EXPECTED_AGENTS = {
    "header_agent",
    "content_agent",
    "url_agent",
    "attachment_agent",
    "sandbox_agent",
    "threat_intel_agent",
    "user_behavior_agent",
}


class OrchestratorWorker:
    def __init__(self):
        self.messaging = RabbitMQClient()
        self.redis_client = redis.from_url(settings.redis_url, decode_responses=True)
        self.graph = LangGraphOrchestrator(
            save_report=self._save_report,
            execute_actions=execute_actions,
        )
        self.executor = ThreadPoolExecutor(max_workers=settings.orchestrator_worker_pool_size)
        self._finalize_timers: dict[str, threading.Timer] = {}
        self._timer_lock = threading.Lock()

    def _ensure_timer_state(self) -> None:
        if not hasattr(self, "_finalize_timers"):
            self._finalize_timers = {}
        if not hasattr(self, "_timer_lock"):
            self._timer_lock = threading.Lock()

    def _async_handle_result(self, payload: dict[str, Any]) -> None:
        self.executor.submit(self._handle_result, payload)

    def _pg_conn(self, max_retries: int = 10, initial_delay: float = 1.0):
        """Connect to PostgreSQL with exponential backoff retry logic.
        
        Args:
            max_retries: Maximum number of connection attempts
            initial_delay: Initial delay in seconds between retries
            
        Returns:
            psycopg2 connection object
            
        Raises:
            psycopg2.OperationalError: If all retries exhausted
        """
        return connect_database(
            settings.database_url,
            max_retries=max_retries,
            initial_delay=initial_delay,
            connect_timeout=5,
            logger=logger,
        )

    def _ensure_schema(self) -> None:
        with self._pg_conn() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS threat_reports (
                        id SERIAL PRIMARY KEY,
                        analysis_id TEXT UNIQUE NOT NULL,
                        created_at TIMESTAMPTZ NOT NULL,
                        overall_risk_score DOUBLE PRECISION NOT NULL,
                        verdict TEXT NOT NULL,
                        llm_explanation TEXT,
                        report JSONB NOT NULL
                    );
                    """
                )
                # H-5: indexes for SOC dashboard query performance
                cursor.execute(
                    "CREATE INDEX IF NOT EXISTS idx_threat_reports_created_at ON threat_reports (created_at DESC);"
                )
                cursor.execute(
                    "CREATE INDEX IF NOT EXISTS idx_threat_reports_verdict ON threat_reports (verdict);"
                )
                # H-1: analyst feedback table
                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS analyst_feedback (
                        id SERIAL PRIMARY KEY,
                        analysis_id TEXT UNIQUE NOT NULL,
                        analyst_verdict TEXT NOT NULL,
                        notes TEXT,
                        submitted_at TIMESTAMPTZ DEFAULT NOW()
                    );
                    """
                )
            conn.commit()

    def _save_report(self, analysis_id: str, decision: dict[str, Any]) -> None:
        with self._pg_conn() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO threat_reports (analysis_id, created_at, overall_risk_score, verdict, llm_explanation, report)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    ON CONFLICT (analysis_id)
                    DO UPDATE SET
                      created_at = EXCLUDED.created_at,
                      overall_risk_score = EXCLUDED.overall_risk_score,
                      verdict = EXCLUDED.verdict,
                      llm_explanation = EXCLUDED.llm_explanation,
                      report = EXCLUDED.report;
                    """,
                    (
                        analysis_id,
                        datetime.now(UTC),
                        float(decision.get("overall_risk_score", 0.0)),
                        decision.get("verdict", "unknown"),
                        decision.get("llm_explanation", ""),
                        Json(decision),
                    ),
                )
            conn.commit()

    def _cache_key(self, analysis_id: str) -> str:
        return f"analysis:{analysis_id}:agent_results"

    def _cancel_finalize_timer(self, analysis_id: str) -> None:
        self._ensure_timer_state()
        with self._timer_lock:
            timer = self._finalize_timers.pop(analysis_id, None)
        if timer is not None:
            timer.cancel()

    def _schedule_partial_finalize(self, analysis_id: str) -> None:
        self._ensure_timer_state()
        with self._timer_lock:
            existing = self._finalize_timers.get(analysis_id)
            if existing is not None and existing.is_alive():
                return

            def _timer_callback() -> None:
                try:
                    self._finalize_pending_analysis(analysis_id)
                finally:
                    self._cancel_finalize_timer(analysis_id)

            timer = threading.Timer(settings.orchestrator_partial_timeout_seconds, _timer_callback)
            timer.daemon = True
            self._finalize_timers[analysis_id] = timer
            timer.start()

    def _finalize_pending_analysis(self, analysis_id: str) -> None:
        if self._report_exists(analysis_id):
            return

        current = self.redis_client.get(self._cache_key(analysis_id))
        if not current:
            return

        try:
            decoded = json.loads(current)
        except Exception:
            return

        if isinstance(decoded, dict):
            first_seen_ts = float(decoded.get("first_seen_ts", datetime.now(UTC).timestamp()))
            merged = decoded.get("results", []) or []
        elif isinstance(decoded, list):
            first_seen_ts = datetime.now(UTC).timestamp()
            merged = decoded
        else:
            return

        finalize, reason = self._should_finalize(merged, first_seen_ts)
        if not finalize:
            return

        logger.info("Partial-finalize timer triggered", analysis_id=analysis_id, reason=reason)
        # H-3: emit structured warning so log aggregators can alert on partial finalizations
        missing = sorted(EXPECTED_AGENTS - {
            entry.get("agent_name", "") for entry in merged
        })
        logger.warning(
            "partial_finalization_triggered",
            analysis_id=analysis_id,
            reason=reason,
            missing_agents=missing,
            received_count=len(merged),
            expected_count=len(EXPECTED_AGENTS),
        )
        self._finalize_analysis(analysis_id, merged, reason)

    def _report_exists(self, analysis_id: str) -> bool:
        with self._pg_conn() as conn, conn.cursor() as cursor:
            cursor.execute(
                """
                    SELECT 1
                    FROM threat_reports
                    WHERE analysis_id = %s
                    LIMIT 1
                    """,
                (analysis_id,),
            )
            return cursor.fetchone() is not None

    def _finalize_analysis(self, analysis_id: str, merged: list[dict[str, Any]], reason: str) -> None:
        received_agents = sorted(
            {entry.get("agent_name") for entry in merged if entry.get("agent_name")}
        )

        # Extract Graph identity fields from the first agent that carries them
        user_principal_name = ""
        internet_message_id = ""
        sender = ""
        subject = ""
        for entry in merged:
            if not user_principal_name and entry.get("user_principal_name"):
                user_principal_name = entry["user_principal_name"]
            if not internet_message_id and entry.get("internet_message_id"):
                internet_message_id = entry["internet_message_id"]
            if not sender and entry.get("sender"):
                sender = entry["sender"]
            if not subject and entry.get("subject"):
                subject = entry["subject"]
            if user_principal_name and internet_message_id and sender and subject:
                break

        initial_state: OrchestratorState = {
            "analysis_id": analysis_id,
            "agent_results": merged,
            "finalization_reason": reason,
            "received_agents": received_agents,
            "missing_agents": sorted(EXPECTED_AGENTS - set(received_agents)),
            "is_partial": reason != "complete",
            "user_principal_name": user_principal_name,
            "internet_message_id": internet_message_id,
            "sender": sender,
            "subject": subject,
        }

        final_state = self.graph.run(initial_state)
        decision = final_state.get("decision", {})

        self._save_report(analysis_id, decision)

        if settings.request_deduplication_enabled:
            try:
                fingerprint = self.redis_client.get(f"email_dedup_mapping:{analysis_id}")
                if fingerprint:
                    from soc_platform.domains.phishing.engine.orchestrator.deduplication import get_dedup_cache

                    cache_payload = decision.copy()
                    cache_payload["analysis_id"] = analysis_id
                    cache_payload["agent_results"] = merged

                    get_dedup_cache().cache_result(fingerprint, cache_payload)
                    self.redis_client.delete(f"email_dedup_mapping:{analysis_id}")
            except Exception as e:
                logger.warning("Failed to cache deduplication result", error=str(e))

        self.redis_client.delete(self._cache_key(analysis_id))
        logger.info(
            "Final decision produced",
            analysis_id=analysis_id,
            verdict=decision.get("verdict"),
            score=decision.get("overall_risk_score"),
            reason=reason,
        )

        try:
            self.redis_client.publish(
                "pipeline_ui_events",
                json.dumps({
                    "analysis_id": analysis_id,
                    "event_type": "final_verdict",
                    "verdict": decision.get("verdict"),
                    "overall_risk_score": decision.get("overall_risk_score"),
                    "recommended_actions": decision.get("recommended_actions")
                })
            )
        except Exception as e:
            logger.warning("Failed to publish final UI verdict", error=str(e))

        # Fire verdict webhooks to external SIEM/SOAR/Slack endpoints. Runs in a
        # daemon thread so slow/unreachable endpoints never block the pipeline.
        try:
            from soc_platform.domains.phishing.engine.services.webhook_dispatcher import get_webhook_dispatcher

            dispatcher = get_webhook_dispatcher()
            if dispatcher.list_webhooks():
                import threading

                threading.Thread(
                    target=dispatcher.dispatch_verdict,
                    args=(
                        analysis_id,
                        decision.get("verdict", "unknown"),
                        float(decision.get("overall_risk_score", 0.0) or 0.0),
                        decision,
                    ),
                    daemon=True,
                ).start()
        except Exception as e:
            logger.warning("Failed to dispatch verdict webhooks", error=str(e))

    def _merge_results(self, analysis_id: str, incoming: dict[str, Any]) -> tuple[list[dict[str, Any]], float]:
        """Atomically merge an incoming agent result into the Redis cache.

        Uses Redis WATCH/MULTI/EXEC to prevent the race condition where
        two near-simultaneous agent results overwrite each other during the
        GET → modify → SET cycle.
        """
        key = self._cache_key(analysis_id)
        max_retries = 10

        for attempt in range(max_retries):
            try:
                with self.redis_client.pipeline() as pipe:
                    pipe.watch(key)

                    # --- Read current state under WATCH ---
                    current = pipe.get(key)
                    first_seen_ts = datetime.now(UTC).timestamp()
                    items: list[dict[str, Any]] = []

                    if current:
                        decoded = json.loads(current)
                        if isinstance(decoded, dict):
                            first_seen_ts = float(decoded.get("first_seen_ts", first_seen_ts))
                            items = decoded.get("results", []) or []
                        elif isinstance(decoded, list):
                            items = decoded

                    # Deduplicate: remove any prior result from same agent, then append
                    filtered = [entry for entry in items if entry.get("agent_name") != incoming.get("agent_name")]
                    filtered.append(incoming)

                    state = {
                        "first_seen_ts": first_seen_ts,
                        "results": filtered,
                    }

                    # --- Atomic write (fails if key was modified since WATCH) ---
                    pipe.multi()
                    pipe.setex(key, settings.orchestrator_cache_ttl_seconds, json.dumps(state))
                    pipe.execute()

                    return filtered, first_seen_ts

            except redis.WatchError:
                # Another thread modified the key; retry with fresh state
                if attempt < max_retries - 1:
                    continue
                logger.warning(
                    "Redis merge exhausted retries",
                    analysis_id=analysis_id,
                    attempts=max_retries,
                )
                # Last-resort fallback: non-atomic merge
                break

        # Fallback (should rarely reach here)
        current = self.redis_client.get(key)
        first_seen_ts = datetime.now(UTC).timestamp()
        items = []
        if current:
            decoded = json.loads(current)
            if isinstance(decoded, dict):
                first_seen_ts = float(decoded.get("first_seen_ts", first_seen_ts))
                items = decoded.get("results", []) or []
            elif isinstance(decoded, list):
                items = decoded

        filtered = [entry for entry in items if entry.get("agent_name") != incoming.get("agent_name")]
        filtered.append(incoming)
        state = {"first_seen_ts": first_seen_ts, "results": filtered}
        self.redis_client.setex(key, settings.orchestrator_cache_ttl_seconds, json.dumps(state))
        return filtered, first_seen_ts

    def _is_complete(self, agent_results: list[dict[str, Any]]) -> bool:
        names = {entry.get("agent_name") for entry in agent_results}
        return EXPECTED_AGENTS.issubset(names)

    def _should_finalize(self, agent_results: list[dict[str, Any]], first_seen_ts: float) -> tuple[bool, str]:
        if self._is_complete(agent_results):
            return True, "complete"

        elapsed = datetime.now(UTC).timestamp() - first_seen_ts
        if (
            elapsed >= settings.orchestrator_partial_timeout_seconds
            and len(agent_results) >= settings.orchestrator_min_agents_for_decision
        ):
            return True, "partial_timeout"

        return False, "waiting"

    def _handle_result(self, payload: dict[str, Any]) -> None:
        analysis_id = payload.get("analysis_id")
        if not analysis_id:
            logger.warning("Skipping result without analysis_id")
            return

        if self._report_exists(analysis_id):
            logger.info("Ignoring late result for finalized analysis", analysis_id=analysis_id)
            return

        merged, first_seen_ts = self._merge_results(analysis_id, payload)
        logger.info("Result received", analysis_id=analysis_id, count=len(merged))

        if not self._is_complete(merged):
            self._schedule_partial_finalize(analysis_id)

        try:
            self.redis_client.publish(
                "pipeline_ui_events",
                json.dumps({
                    "analysis_id": analysis_id,
                    "event_type": "agent_update",
                    "agent_name": payload.get("agent_name"),
                    "risk_score": payload.get("risk_score"),
                    "confidence": payload.get("confidence")
                })
            )
        except Exception as e:
            logger.warning("Failed to publish UI event", error=str(e))

        finalize, reason = self._should_finalize(merged, first_seen_ts)
        if not finalize:
            return

        self._cancel_finalize_timer(analysis_id)
        self._finalize_analysis(analysis_id, merged, reason)

    def _garuda_retry_loop(self) -> None:
        """Background loop that drains the Garuda retry queue periodically."""
        from soc_platform.domains.phishing.engine.garuda_integration.retry_queue import process_garuda_retries

        interval = 60  # seconds
        logger.info("Garuda background retry consumer started", interval_seconds=interval)
        while True:
            try:
                import time as _time
                _time.sleep(interval)
                stats = process_garuda_retries(max_items=10)
                if stats.get("processed", 0) > 0:
                    logger.info("Garuda retry sweep complete", stats=stats)
            except Exception as exc:
                logger.warning("Garuda retry sweep failed", error=str(exc))

    def run(self) -> None:
        self._ensure_schema()

        # Start background Garuda retry consumer
        garuda_thread = threading.Thread(target=self._garuda_retry_loop, daemon=True, name="garuda-retry")
        garuda_thread.start()

        self.messaging.connect()
        self.messaging.declare_results_queue(settings.results_queue)
        self.messaging.consume(settings.results_queue, self._async_handle_result)


def main() -> None:
    setup_logging(settings.log_dir, settings.app_log_level, settings.log_format)
    
    # 30GB RAM Optimization: Preload all models at startup
    logger.info("=" * 60)
    logger.info("Orchestrator Starting (30GB RAM Optimized)")
    logger.info("=" * 60)
    warmup_orchestrator_at_startup()
    logger.info(f"Orchestrator concurrency: {settings.orchestrator_max_concurrent_analyses} max parallel analyses")
    logger.info(f"Worker pool size: {settings.orchestrator_worker_pool_size}")
    logger.info("=" * 60)
    
    OrchestratorWorker().run()


if __name__ == "__main__":
    main()
