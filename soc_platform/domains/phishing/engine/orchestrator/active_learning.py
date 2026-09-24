"""
Active Learning Engine for the Agentic Email Security System.

Uses analyst feedback (true_positive, false_positive, etc.) to:
- Compute per-agent accuracy metrics
- Recommend agent weight adjustments for the scorer
- Generate model drift reports
- Build learned allowlists/blocklists from confirmed FPs/TPs
"""

from __future__ import annotations
from datetime import datetime, timezone, timedelta
from typing import Any, Optional
from soc_platform.domains.phishing.engine.services.logging_service import get_service_logger

logger = get_service_logger("active_learning")

# Default agent weights (from scorer.py)
DEFAULT_WEIGHTS = {
    "header_agent": 0.15,
    "content_agent": 0.20,
    "url_agent": 0.20,
    "attachment_agent": 0.15,
    "sandbox_agent": 0.10,
    "threat_intel_agent": 0.10,
    "user_behavior_agent": 0.10,
}


class ActiveLearningEngine:
    """Learn from analyst feedback to improve detection accuracy."""

    def __init__(self, database_url: str | None = None):
        self._database_url = database_url

    def _connect(self):
        from soc_platform.domains.phishing.engine.configs.settings import settings
        from soc_platform.domains.phishing.engine.services.database import connect_database
        return connect_database(self._database_url or settings.database_url, logger=logger)

    def compute_agent_accuracy(self, days: int = 30) -> dict[str, Any]:
        """
        Compute per-agent accuracy metrics from analyst feedback.

        Returns:
            Dict with per-agent TP/FP/FN/TN counts and accuracy.
        """
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        try:
            with self._connect() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        SELECT tr.report->>'agent_results' AS agent_results,
                               tr.report->>'verdict' AS verdict,
                               af.analyst_verdict
                        FROM threat_reports tr
                        JOIN analyst_feedback af ON tr.analysis_id = af.analysis_id
                        WHERE af.submitted_at >= %s
                    """, (cutoff,))
                    rows = cur.fetchall()

            if not rows:
                return {"status": "no_feedback", "period_days": days, "agents": {}}

            import json
            agent_stats: dict[str, dict[str, int]] = {}
            for agent_name in DEFAULT_WEIGHTS:
                agent_stats[agent_name] = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}

            for agent_results_json, system_verdict, analyst_verdict in rows:
                try:
                    agent_results = json.loads(agent_results_json) if isinstance(agent_results_json, str) else (agent_results_json or [])
                except Exception:
                    continue

                is_actually_bad = analyst_verdict in ("true_positive", "false_negative")
                is_actually_safe = analyst_verdict in ("true_negative", "false_positive")

                for result in agent_results:
                    name = result.get("agent_name", "")
                    if name not in agent_stats:
                        continue
                    risk = float(result.get("risk_score", 0) or 0)
                    agent_flagged = risk >= 0.5

                    if agent_flagged and is_actually_bad:
                        agent_stats[name]["tp"] += 1
                    elif agent_flagged and is_actually_safe:
                        agent_stats[name]["fp"] += 1
                    elif not agent_flagged and is_actually_bad:
                        agent_stats[name]["fn"] += 1
                    elif not agent_flagged and is_actually_safe:
                        agent_stats[name]["tn"] += 1

            # Calculate metrics
            agent_metrics = {}
            for name, stats in agent_stats.items():
                total = stats["tp"] + stats["fp"] + stats["fn"] + stats["tn"]
                accuracy = (stats["tp"] + stats["tn"]) / total if total > 0 else None
                precision = stats["tp"] / (stats["tp"] + stats["fp"]) if (stats["tp"] + stats["fp"]) > 0 else None
                recall = stats["tp"] / (stats["tp"] + stats["fn"]) if (stats["tp"] + stats["fn"]) > 0 else None
                f1 = (2 * precision * recall / (precision + recall)) if (precision and recall and (precision + recall) > 0) else None

                agent_metrics[name] = {
                    **stats, "total": total,
                    "accuracy": round(accuracy, 4) if accuracy is not None else None,
                    "precision": round(precision, 4) if precision is not None else None,
                    "recall": round(recall, 4) if recall is not None else None,
                    "f1_score": round(f1, 4) if f1 is not None else None,
                }

            return {
                "status": "computed", "period_days": days,
                "feedback_count": len(rows),
                "agents": agent_metrics,
                "generated_at": datetime.now(timezone.utc).isoformat(),
            }
        except Exception as e:
            logger.warning("Failed to compute agent accuracy", error=str(e))
            return {"status": "error", "error": str(e)}

    def recommend_weight_adjustments(self, days: int = 30) -> dict[str, Any]:
        """
        Recommend agent weight adjustments based on accuracy metrics.

        High-accuracy agents get higher weights, low-accuracy get reduced.
        """
        accuracy_data = self.compute_agent_accuracy(days)
        if accuracy_data.get("status") != "computed":
            return {"status": "insufficient_data", "recommendations": {}}

        recommendations: dict[str, dict[str, Any]] = {}
        agents = accuracy_data.get("agents", {})

        for name, metrics in agents.items():
            current_weight = DEFAULT_WEIGHTS.get(name, 0.1)
            f1 = metrics.get("f1_score")
            total = metrics.get("total", 0)

            if f1 is None or total < 10:
                recommendations[name] = {
                    "current_weight": current_weight,
                    "recommended_weight": current_weight,
                    "adjustment": 0,
                    "reason": "Insufficient data for adjustment",
                }
                continue

            # Adjust weight based on F1 score
            if f1 >= 0.9:
                adjustment = 0.05
                reason = f"Excellent F1 ({f1:.2f}), increase weight"
            elif f1 >= 0.75:
                adjustment = 0.02
                reason = f"Good F1 ({f1:.2f}), slight increase"
            elif f1 >= 0.5:
                adjustment = 0
                reason = f"Adequate F1 ({f1:.2f}), maintain weight"
            elif f1 >= 0.3:
                adjustment = -0.03
                reason = f"Low F1 ({f1:.2f}), reduce weight"
            else:
                adjustment = -0.05
                reason = f"Poor F1 ({f1:.2f}), significant reduction"

            new_weight = max(0.02, min(0.35, current_weight + adjustment))
            recommendations[name] = {
                "current_weight": current_weight,
                "recommended_weight": round(new_weight, 4),
                "adjustment": round(adjustment, 4),
                "reason": reason,
                "f1_score": f1,
                "sample_size": total,
            }

        return {
            "status": "computed",
            "recommendations": recommendations,
            "period_days": days,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    def get_drift_report(self, days: int = 30) -> dict[str, Any]:
        """Generate a model drift report comparing recent vs. baseline accuracy."""
        recent = self.compute_agent_accuracy(days=7)
        baseline = self.compute_agent_accuracy(days=days)

        if recent.get("status") != "computed" or baseline.get("status") != "computed":
            return {"status": "insufficient_data"}

        drift_alerts: list[dict[str, Any]] = []
        for name in DEFAULT_WEIGHTS:
            recent_f1 = (recent.get("agents", {}).get(name, {}).get("f1_score"))
            baseline_f1 = (baseline.get("agents", {}).get(name, {}).get("f1_score"))

            if recent_f1 is not None and baseline_f1 is not None:
                drift = recent_f1 - baseline_f1
                if abs(drift) > 0.1:
                    drift_alerts.append({
                        "agent": name,
                        "baseline_f1": baseline_f1,
                        "recent_f1": recent_f1,
                        "drift": round(drift, 4),
                        "severity": "high" if abs(drift) > 0.2 else "medium",
                        "direction": "degraded" if drift < 0 else "improved",
                    })

        return {
            "status": "computed",
            "drift_alerts": drift_alerts,
            "has_drift": len(drift_alerts) > 0,
            "recent_period_days": 7,
            "baseline_period_days": days,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    def get_feedback_summary(self, days: int = 30) -> dict[str, Any]:
        """Get summary statistics of analyst feedback."""
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        try:
            with self._connect() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        SELECT analyst_verdict, COUNT(*) as cnt
                        FROM analyst_feedback
                        WHERE submitted_at >= %s
                        GROUP BY analyst_verdict
                    """, (cutoff,))
                    rows = cur.fetchall()
            verdict_counts = {row[0]: row[1] for row in rows}
            total = sum(verdict_counts.values())
            fp_rate = verdict_counts.get("false_positive", 0) / total if total > 0 else 0
            return {
                "period_days": days, "total_feedback": total,
                "verdict_counts": verdict_counts,
                "false_positive_rate": round(fp_rate, 4),
            }
        except Exception as e:
            return {"status": "error", "error": str(e)}


_engine: Optional[ActiveLearningEngine] = None

def get_active_learning_engine() -> ActiveLearningEngine:
    global _engine
    if _engine is None:
        _engine = ActiveLearningEngine()
    return _engine
