"""
Retroactive IOC Hunt Engine for the Agentic Email Security System.

When new IOCs are discovered, scans historical analysis reports to find
emails that contained those indicators.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

from soc_platform.domains.phishing.engine.services.logging_service import get_service_logger

logger = get_service_logger("retroactive_hunt")


class RetroactiveHuntEngine:
    """Search historical reports for IOCs."""

    def __init__(self, database_url: str | None = None):
        self._database_url = database_url

    def _connect(self):
        from soc_platform.domains.phishing.engine.configs.settings import settings
        from soc_platform.domains.phishing.engine.services.database import connect_database
        return connect_database(self._database_url or settings.database_url, logger=logger)

    def hunt_ioc(
        self,
        ioc_value: str,
        ioc_type: str = "any",
        days_back: int = 30,
        max_results: int = 100,
    ) -> dict[str, Any]:
        """
        Search historical reports for a specific IOC.

        Args:
            ioc_value: The IOC to search for (domain, IP, hash, URL, etc.)
            ioc_type: Type of IOC (domain, ip, hash, url, or any)
            days_back: How many days to look back
            max_results: Maximum results to return

        Returns:
            Hunt results with matching analyses.
        """
        cutoff = datetime.now(UTC) - timedelta(days=days_back)
        ioc_lower = ioc_value.lower().strip()

        try:
            with self._connect() as conn, conn.cursor() as cur:
                # Search reports containing the IOC in the JSON report column
                cur.execute("""
                        SELECT analysis_id, report, created_at
                        FROM threat_reports
                        WHERE created_at >= %s
                        ORDER BY created_at DESC
                        LIMIT %s
                    """, (cutoff, max_results * 5))  # Fetch more to filter
                rows = cur.fetchall()

            matches: list[dict[str, Any]] = []
            for analysis_id, report_data, created_at in rows:
                if len(matches) >= max_results:
                    break

                report = report_data if isinstance(report_data, dict) else {}
                report_text = json.dumps(report).lower()

                if ioc_lower in report_text:
                    # Find where the IOC was found
                    found_in: list[str] = []
                    for result in report.get("agent_results", []):
                        for indicator in result.get("indicators", []):
                            if ioc_lower in str(indicator).lower():
                                found_in.append(result.get("agent_name", "unknown"))
                                break

                    matches.append({
                        "analysis_id": analysis_id,
                        "verdict": report.get("verdict", "unknown"),
                        "risk_score": report.get("overall_risk_score"),
                        "created_at": created_at.isoformat() if created_at else None,
                        "found_in_agents": found_in,
                        "recommended_actions": report.get("recommended_actions", []),
                    })

            return {
                "status": "completed",
                "ioc_value": ioc_value,
                "ioc_type": ioc_type,
                "days_searched": days_back,
                "reports_scanned": len(rows),
                "matches_found": len(matches),
                "matches": matches,
                "hunted_at": datetime.now(UTC).isoformat(),
            }

        except Exception as e:
            logger.warning("Retroactive hunt failed", error=str(e), ioc=ioc_value[:30])
            return {"status": "error", "error": str(e), "ioc_value": ioc_value}

    def hunt_multiple_iocs(
        self,
        iocs: list[dict[str, str]],
        days_back: int = 30,
    ) -> dict[str, Any]:
        """Hunt for multiple IOCs at once."""
        results = []
        for ioc in iocs[:20]:  # Limit to 20 IOCs per batch
            result = self.hunt_ioc(
                ioc_value=ioc.get("value", ""),
                ioc_type=ioc.get("type", "any"),
                days_back=days_back,
            )
            results.append(result)

        total_matches = sum(r.get("matches_found", 0) for r in results)
        return {
            "status": "completed",
            "iocs_hunted": len(results),
            "total_matches": total_matches,
            "results": results,
        }


_engine = None

def get_retroactive_hunt_engine() -> RetroactiveHuntEngine:
    global _engine
    if _engine is None:
        _engine = RetroactiveHuntEngine()
    return _engine
