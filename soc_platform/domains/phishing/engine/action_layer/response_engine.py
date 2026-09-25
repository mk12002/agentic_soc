"""
Action layer for quarantine and alert responses.

Supports both simulated mode and real Microsoft Graph-backed actions
for email remediation including quarantine and banner insertion.

Fixes applied (2026-05-18):
- C-1: Replaced all print() calls with structured logger calls
- C-2: Wired real llm_explanation from decision dict (removed hardcoded placeholder)
- C-3: block_sender now persists blocked senders to local IOC store
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

import httpx

from soc_platform.domains.phishing.engine.action_layer.graph_client import get_graph_client
from soc_platform.domains.phishing.engine.configs.settings import settings
from soc_platform.domains.phishing.engine.services.logging_service import get_service_logger

logger = get_service_logger("response_engine")


def _safe_call(url: str, payload: dict[str, Any]) -> None:
    try:
        with httpx.Client(timeout=5) as client:
            client.post(url, json=payload)
    except Exception as exc:
        logger.warning("Action endpoint unavailable", url=url, error=str(exc))


def _block_sender_in_ioc_store(sender: str, analysis_id: str) -> bool:
    """Persist a blocked sender into the local IOC SQLite database.

    Stores the sender email as an IOC of type 'email_sender' so future
    analyses automatically flag it via the threat_intel_agent.

    Returns True if persisted successfully, False otherwise.
    """
    if not sender or sender == "unknown":
        return False
    try:
        ioc_db_path = settings.ioc_db_file
        if not ioc_db_path.parent.exists():
            ioc_db_path.parent.mkdir(parents=True, exist_ok=True)
            
        with sqlite3.connect(str(ioc_db_path), timeout=10) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS iocs (
                    indicator TEXT PRIMARY KEY,
                    ioc_type TEXT,
                    source TEXT,
                    first_seen_ts INTEGER,
                    updated_ts INTEGER
                )
                """
            )
            import time
            current_ts = int(time.time())
            conn.execute(
                """
                INSERT INTO iocs (indicator, ioc_type, source, first_seen_ts, updated_ts)
                VALUES (?, 'email_sender', 'action_layer', ?, ?)
                ON CONFLICT(indicator) DO UPDATE SET
                    updated_ts = ?
                """,
                (sender.lower().strip(), current_ts, current_ts, current_ts),
            )
            conn.commit()
        logger.info(
            "sender_blocked_in_ioc_store",
            sender=sender,
            analysis_id=analysis_id,
            ioc_db=str(ioc_db_path),
        )
        return True
    except Exception as exc:
        logger.warning(
            "block_sender_ioc_persist_failed",
            sender=sender,
            analysis_id=analysis_id,
            error=str(exc),
        )
        return False


class ResponseEngine:
    """
    Action Layer responsible for taking automated responses based on orchestrator decisions.

    Supports two modes:
    1. **Simulated Mode** (default): Actions are logged for testing/audit
    2. **Live Mode**: Real Graph API calls for email quarantine and banner insertion

    With 30GB RAM optimizations, we can now afford real Graph actions with proper
    error handling and audit trails.
    """

    def __init__(self):
        self.azure_openai_endpoint = settings.azure_openai_endpoint
        self.azure_openai_api_key = settings.azure_openai_api_key
        self.azure_openai_deployment = settings.azure_openai_deployment
        self.azure_openai_api_version = settings.azure_openai_api_version

        self.simulated_mode = bool(settings.action_simulated_mode)
        self.banner_enabled = settings.action_banner_enabled
        self.quarantine_enabled = settings.action_quarantine_enabled
        self.require_approval = bool(getattr(settings, "action_require_approval", True))

        self.graph = get_graph_client()

        logger.info(
            "Action Layer Initialized",
            simulated_mode=self.simulated_mode,
            graph_configured=self.graph.is_configured(),
            banner_enabled=self.banner_enabled,
            quarantine_enabled=self.quarantine_enabled,
        )

    @staticmethod
    def _iter_agent_risks(agent_results: Any) -> list[tuple[str, float]]:
        """Normalize heterogeneous agent_results payloads into (agent_name, risk_score)."""
        normalized: list[tuple[str, float]] = []

        if isinstance(agent_results, dict):
            for agent_name, result in agent_results.items():
                if not isinstance(result, dict):
                    continue
                try:
                    risk = float(result.get("risk_score", 0.0) or 0.0)
                except Exception:
                    risk = 0.0
                normalized.append((str(agent_name), risk))
            return normalized

        if isinstance(agent_results, list):
            for entry in agent_results:
                if not isinstance(entry, dict):
                    continue
                agent_name = str(entry.get("agent_name") or entry.get("agent") or "unknown_agent")
                try:
                    risk = float(entry.get("risk_score", 0.0) or 0.0)
                except Exception:
                    risk = 0.0
                normalized.append((agent_name, risk))

        return normalized

    def execute_actions(self, decision: dict[str, Any]) -> None:
        actions = decision.get("recommended_actions", [])
        analysis_id = decision.get("analysis_id", "unknown-id")
        score = decision.get("overall_risk_score", 0.0)
        verdict = decision.get("verdict", "unknown")

        # Graph identity fields for real actions
        user_principal_name = decision.get("user_principal_name")
        internet_message_id = decision.get("internet_message_id")
        graph_message_id = decision.get("graph_message_id")
        
        # Local & GDrive routing path
        local_routing_path = ""
        gdrive_file_id = ""
        for res in (decision.get("agent_results") or []):
            if res.get("local_routing_path"):
                local_routing_path = res.get("local_routing_path")
            if res.get("gdrive_file_id"):
                gdrive_file_id = res.get("gdrive_file_id")
            if local_routing_path and gdrive_file_id:
                break

        # Sender for block_sender action (extracted from agent_results headers)
        sender = decision.get("sender", "")
        if not sender:
            for res in (decision.get("agent_results") or []):
                if res.get("agent_name") == "header_agent":
                    sender = res.get("metadata", {}).get("sender", "") or ""
                    break

        # Build reasons from agent outputs if not already supplied
        reasons = decision.get("reasons", [])
        if not reasons:
            reasons = [f"Verdict is {verdict} with a risk score of {score:.2f}"]
            for agent_name, risk in self._iter_agent_risks(decision.get("agent_results", {})):
                if risk > 0.6:
                    reasons.append(f"{agent_name} reported high risk ({risk:.2f})")

        # Use the real LLM explanation generated by llm_reasoner (C-2 fix)
        ai_summary = (decision.get("llm_explanation") or "").strip() or "LLM explanation unavailable."

        # Log verdict + context in a single structured event
        logger.info(
            "action_layer_verdict",
            analysis_id=analysis_id,
            verdict=verdict.upper(),
            risk_score=round(float(score), 4),
            recommended_actions=actions,
            reasons=reasons[:5],
        )

        if not actions:
            logger.info("no_actions_recommended", analysis_id=analysis_id)
            return

        # NFR-01: without analyst approval, live actions are only recorded as pending.
        approved = bool(decision.get("analyst_approved"))
        if self.require_approval and not approved:
            logger.info(
                "actions_pending_approval",
                analysis_id=analysis_id,
                pending_actions=actions,
            )
            self._execute_simulated_actions(actions, analysis_id, sender=sender)
        # Live mode: attempt real Graph API actions
        elif not self.simulated_mode and self.graph.is_configured() and user_principal_name:
            self._execute_graph_actions(
                actions, analysis_id, verdict, score,
                user_principal_name, internet_message_id, graph_message_id,
                sender=sender,
            )
        else:
            self._execute_simulated_actions(actions, analysis_id, sender=sender)

        logger.info(
            "action_layer_ai_summary",
            analysis_id=analysis_id,
            summary=ai_summary[:500],
        )

        if local_routing_path:
            self._execute_local_routing(local_routing_path, verdict, analysis_id)
            
        if gdrive_file_id:
            self._execute_gdrive_routing(gdrive_file_id, verdict, analysis_id)

    def _execute_gdrive_routing(self, file_id: str, verdict: str, analysis_id: str) -> None:
        """Route the file within GDrive based on verdict."""
        from soc_platform.domains.phishing.engine.services.gdrive_client import get_gdrive_client
        gdrive = get_gdrive_client()
        if not gdrive.is_configured():
            return
            
        if verdict in {"safe", "likely_safe"}:
            dest_id = gdrive.approved_folder_id
        elif verdict == "malicious":
            dest_id = gdrive.deleted_folder_id
        elif verdict in {"high_risk", "phishing", "suspicious"}:
            dest_id = gdrive.quarantine_folder_id
        else:
            dest_id = gdrive.quarantine_folder_id
            
        if dest_id:
            gdrive.move_file(file_id, gdrive.staging_folder_id, dest_id)
            logger.info("gdrive_routing_complete", analysis_id=analysis_id, file_id=file_id, dest=dest_id, verdict=verdict)

    def _execute_local_routing(self, source_path: str, verdict: str, analysis_id: str) -> None:
        """Route the locally ingested file to its final destination."""
        import shutil
        
        src = Path(source_path)
        if not src.exists():
            logger.warning("local_routing_source_missing", path=str(src), analysis_id=analysis_id)
            return

        if verdict in {"safe", "likely_safe"}:
            dest_dir = Path(getattr(settings, "local_approved_folder", "/mnt/data/Approved"))
        elif verdict == "malicious":
            dest_dir = Path(getattr(settings, "local_deleted_folder", "/mnt/data/Deleted"))
        elif verdict in {"high_risk", "phishing", "suspicious"}:
            dest_dir = Path(getattr(settings, "local_quarantine_folder", "/mnt/data/Quarantine"))
        else:
            dest_dir = Path(getattr(settings, "local_quarantine_folder", "/mnt/data/Quarantine"))
            
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest_path = dest_dir / src.name
        try:
            shutil.move(str(src), str(dest_path))
            logger.info("local_routing_complete", analysis_id=analysis_id, src=str(src), dest=str(dest_path), verdict=verdict)
        except Exception as exc:
            logger.error("local_routing_failed", analysis_id=analysis_id, src=str(src), error=str(exc))

    def _execute_graph_actions(
        self,
        actions: list[str],
        analysis_id: str,
        verdict: str,
        score: float,
        upn: str,
        internet_message_id: str | None,
        graph_message_id: str | None,
        sender: str = "",
    ) -> None:
        """Execute real Graph API actions for email remediation."""
        logger.info("graph_actions_starting", analysis_id=analysis_id, upn=upn, actions=actions)

        # Resolve message ID if not provided
        if not graph_message_id and internet_message_id:
            resolved = self.graph.resolve_message_id(upn, internet_message_id)
            if resolved:
                graph_message_id = resolved
                logger.info("graph_message_id_resolved", analysis_id=analysis_id, upn=upn)
            else:
                logger.warning(
                    "graph_message_id_resolve_failed_fallback_simulated",
                    analysis_id=analysis_id, upn=upn,
                )
                self._execute_simulated_actions(actions, analysis_id, sender=sender)
                return

        if not graph_message_id:
            logger.warning(
                "no_graph_message_id_fallback_simulated",
                analysis_id=analysis_id,
            )
            self._execute_simulated_actions(actions, analysis_id, sender=sender)
            return

        if "quarantine" in actions and self.quarantine_enabled:
            result = self.graph.quarantine_email(upn, graph_message_id)
            logger.info("graph_quarantine", analysis_id=analysis_id, ok=result.ok, detail=result.detail)

        if "delete" in actions and self.quarantine_enabled:
            result = self.graph.delete_email(upn, graph_message_id)
            logger.info("graph_delete", analysis_id=analysis_id, ok=result.ok, detail=result.detail)

        if "deliver_with_banner" in actions and self.banner_enabled:
            severity = "Critical" if score >= 0.85 else "High" if score >= 0.60 else "Medium"
            result = self.graph.apply_warning_banner(upn, graph_message_id, severity=severity)
            logger.info("graph_banner", analysis_id=analysis_id, ok=result.ok, severity=severity)

        if "categorize" in actions:
            categories = ["PhishingLure"] if verdict == "phishing" else ["Suspicious"] if verdict == "suspicious" else []
            if categories:
                result = self.graph.add_categories(upn, graph_message_id, categories)
                logger.info("graph_categorize", analysis_id=analysis_id, ok=result.ok, categories=categories)

        if "block_sender" in actions and sender:
            ok = _block_sender_in_ioc_store(sender, analysis_id)
            logger.info("block_sender_graph_mode", analysis_id=analysis_id, sender=sender, persisted=ok)

    def _execute_simulated_actions(
        self,
        actions: list[str],
        analysis_id: str,
        sender: str = "",
    ) -> None:
        """Execute simulated actions — structured logging only, no external calls."""
        logger.info("simulated_actions_dispatched", analysis_id=analysis_id, actions=actions)

        if "quarantine" in actions:
            logger.info(
                "action_quarantine",
                analysis_id=analysis_id,
                simulated=True,
                enabled=self.quarantine_enabled,
                detail="Would move email to Junk folder via Graph API",
            )

        if "delete" in actions:
            logger.info(
                "action_delete",
                analysis_id=analysis_id,
                simulated=True,
                enabled=self.quarantine_enabled,
                detail="Would move email to Deleted Items folder via Graph API",
            )

        if "deliver_with_banner" in actions:
            logger.info(
                "action_banner",
                analysis_id=analysis_id,
                simulated=True,
                enabled=self.banner_enabled,
                detail="Would insert security warning banner via Graph API",
            )

        if "soc_alert" in actions or "trigger_garuda" in actions:
            logger.info(
                "action_soc_alert",
                analysis_id=analysis_id,
                simulated=True,
                detail="Would notify SOC team / trigger Garuda investigation",
            )

        if "block_sender" in actions:
            # C-3 fix: persist even in simulated mode — the IOC store is always local
            ok = _block_sender_in_ioc_store(sender, analysis_id) if sender else False
            logger.info(
                "action_block_sender",
                analysis_id=analysis_id,
                simulated=True,
                sender=sender or "unknown",
                ioc_persisted=ok,
                detail="Sender added to local IOC store for future threat intel lookups",
            )

        if "reset_credentials" in actions:
            logger.info(
                "action_reset_credentials",
                analysis_id=analysis_id,
                simulated=True,
                detail="Would trigger forced password reset via IdP",
            )

        if "deliver" in actions:
            logger.info(
                "action_deliver",
                analysis_id=analysis_id,
                simulated=True,
                detail="Email would be delivered normally",
            )

        if "categorize" in actions:
            logger.info(
                "action_categorize",
                analysis_id=analysis_id,
                simulated=True,
                detail="Would apply classification tags via Graph API",
            )

        if "manual_review" in actions:
            logger.info(
                "action_manual_review",
                analysis_id=analysis_id,
                simulated=True,
                detail="Flagged for analyst manual review queue",
            )


# Module-level singleton and functional entrypoint (backward compatible)
response_engine = ResponseEngine()
execute_actions = response_engine.execute_actions
