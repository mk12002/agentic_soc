"""SIEM / case-management alert sources (IM-F01, IM-T02, Q01).

Whether the client runs a SIEM is the top open question. Two implementations:
  * ``sentinel``     - Microsoft Sentinel incidents via the Azure management API
  * ``generic_siem`` - any SIEM/SOAR that can POST JSON alerts to the platform
                       webhook (``POST /api/v1/ingest/alerts``); this connector
                       normalises that payload with a configurable field map.
"""

from __future__ import annotations

from typing import Any

from soc_platform.connectors.base import Page
from soc_platform.connectors.http import HttpTransport, NoAuth, entra_app_auth
from soc_platform.connectors.registry import ConfigField, ConnectorManifest
from soc_platform.connectors.tools._common import ToolConnector, parse_ts, sev_name
from soc_platform.core.identity import user_ref
from soc_platform.core.schema import EntityRef, NormalizedRecord


class SentinelConnector(ToolConnector):
    name = "sentinel"
    tool = "sentinel"
    dimension = "other"
    streams = ("incidents",)

    def _ws(self) -> str:
        s = self.settings
        return (f"/subscriptions/{s['subscription_id']}/resourceGroups/{s['resource_group']}/providers/"
                f"Microsoft.OperationalInsights/workspaces/{s['workspace']}/providers/Microsoft.SecurityInsights")

    def fetch_page(self, stream: str, cursor: str | None) -> Page:
        body = self.get(cursor) if cursor and cursor.startswith("http") else \
            self.get(f"{self._ws()}/incidents", params={"api-version": "2024-03-01", "$top": 200,
                                                        "$orderby": "properties/lastModifiedTimeUtc asc"})
        nxt = body.get("nextLink")
        return Page(body.get("value") or [], nxt or cursor, has_more=bool(nxt))

    def normalize(self, stream: str, inc: dict[str, Any]) -> list[NormalizedRecord]:
        p = inc.get("properties") or {}
        return [NormalizedRecord(
            kind="alert", tool=self.tool, source_type="incident", source_id=inc.get("name") or inc["id"],
            observed_at=parse_ts(p.get("createdTimeUtc")), title=p.get("title", "Sentinel incident"),
            severity=sev_name(p.get("severity")), dimension="other",
            attributes={"status": p.get("status"), "incident_number": p.get("incidentNumber"),
                        "tactics": (p.get("additionalData") or {}).get("tactics"),
                        "alert_count": (p.get("additionalData") or {}).get("alertsCount")},
            deep_link=p.get("incidentUrl"))]


class GenericSiemConnector(ToolConnector):
    """Normalises pushed alerts. Field map config: {"id": "alert_id", "title": "rule_name", ...}."""

    name = "generic_siem"
    tool = "generic_siem"
    streams = ("pushed",)

    def fetch_page(self, stream, cursor):
        return Page([], None, has_more=False)  # push-only

    def normalize(self, stream: str, a: dict[str, Any]) -> list[NormalizedRecord]:
        fm = {"id": "id", "title": "title", "severity": "severity", "time": "timestamp", "host": "host", "user": "user",
              "src_ip": "src_ip", "dst_ip": "dst_ip", "domain": "domain", "url": "url", "hash": "sha256",
              "source": "source", **(self.settings.get("field_map") or {})}
        g = lambda k: a.get(fm[k])
        refs = []
        if g("host"):
            refs.append(EntityRef(kind="asset", role="host", attributes={"hostname": g("host")}))
        u = user_ref(g("user"), default_domain=self.settings.get("user_domain"))
        if u is not None:
            refs.append(u)
        for k, t in (("src_ip", "ip"), ("dst_ip", "ip"), ("domain", "domain"), ("url", "url"), ("hash", "sha256")):
            if g(k):
                refs.append(EntityRef(kind="indicator", role=k, keys={"value": str(g(k))}, attributes={"type": t}))
        return [NormalizedRecord(kind="alert", tool=str(g("source") or self.tool), source_type="pushed_alert",
                                 source_id=str(g("id")), observed_at=parse_ts(g("time")), title=str(g("title") or "alert"),
                                 severity=sev_name(g("severity")), refs=refs,
                                 attributes={k: v for k, v in a.items() if k not in fm.values()})]


MANIFESTS = [
    ConnectorManifest(
        name="sentinel", tool="Microsoft Sentinel", vendor="Microsoft", category="siem", dimension="other",
        description="Sentinel incidents (if Sentinel is the client's SIEM).",
        factory=lambda s, t: SentinelConnector(s, t, rate_per_sec=2, burst=4),
        live_transport=lambda s: HttpTransport("https://management.azure.com", entra_app_auth(
            s["tenant_id"], s["client_id"], s["client_secret"], "https://management.azure.com/.default")),
        config=[ConfigField("tenant_id"), ConfigField("client_id", secret=True), ConfigField("client_secret", secret=True),
                ConfigField("subscription_id"), ConfigField("resource_group"), ConfigField("workspace")],
        confidence="Unknown", to_confirm="Whether a SIEM exists and which (Q01)", focus_areas=("incident",)),
    ConnectorManifest(
        name="generic_siem", tool="Generic SIEM/SOAR webhook", vendor="any", category="siem", dimension="other",
        description="Normalises alerts pushed to /api/v1/ingest/alerts from any SIEM/SOAR.",
        factory=lambda s, t: GenericSiemConnector(s, t, rate_per_sec=100, burst=100),
        live_transport=lambda s: HttpTransport("http://localhost", NoAuth()),
        config=[ConfigField("field_map", "Mapping of platform fields to payload keys", required=False)],
        confidence="High", focus_areas=("incident",)),
]
