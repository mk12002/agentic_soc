"""SIEM / case-management alert sources (IM-F01, IM-T02, Q01).

Whether the client runs a SIEM is the top open question. Two implementations:
  * ``sentinel``     - Microsoft Sentinel incidents via the Azure management API
  * ``generic_siem`` - any SIEM/SOAR that can POST JSON alerts to the platform
                       webhook (``POST /api/v1/ingest/alerts``); this connector
                       normalises that payload with a configurable field map.
"""

from __future__ import annotations

import json
import logging
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from soc_platform.connectors.base import ConnectorError, Page
from soc_platform.connectors.http import HttpTransport, NoAuth, entra_app_auth
from soc_platform.connectors.registry import ConfigField, ConnectorManifest
from soc_platform.connectors.tools._common import ToolConnector, parse_ts, sev_name
from soc_platform.connectors.tools._microsoft import odata_page
from soc_platform.core.identity import user_ref
from soc_platform.core.schema import EntityRef, NormalizedRecord

log = logging.getLogger(__name__)
API_VERSION = "2024-03-01"


class SentinelConnector(ToolConnector):
    name = "sentinel"
    tool = "sentinel"
    dimension = "other"
    streams = ("incidents",)
    read_scopes = ("Microsoft Sentinel Reader on the workspace (Azure RBAC)",)

    def _ws(self) -> str:
        s = self.settings
        return (f"/subscriptions/{s['subscription_id']}/resourceGroups/{s['resource_group']}/providers/"
                f"Microsoft.OperationalInsights/workspaces/{s['workspace']}/providers/Microsoft.SecurityInsights")

    def fetch_page(self, stream: str, cursor: str | None) -> Page:
        # new and changed incidents since the last sync (watermark on lastModifiedTimeUtc)
        page = odata_page(self, f"{self._ws()}/incidents", cursor,
                          {"api-version": API_VERSION, "$top": 200, "$orderby": "properties/lastModifiedTimeUtc asc"},
                          watermark="properties.lastModifiedTimeUtc", filter_field="properties/lastModifiedTimeUtc")
        # An incident lists its accounts, hosts, IPs, URLs and files separately ("List Entities"). Without them every
        # Sentinel incident would stand alone, linked to no host or person.
        names = [i.get("name") or i.get("id") for i in page.records]
        with ThreadPoolExecutor(max_workers=4) as pool:
            for inc, ents in zip(page.records, pool.map(self._entities, names), strict=True):
                inc["_entities"] = ents
        return page

    def _entities(self, name: str | None) -> list[dict[str, Any]]:
        if not name:
            return []
        try:
            body = self.post(f"{self._ws()}/incidents/{name}/entities", params={"api-version": API_VERSION})
        except ConnectorError as exc:            # the incident is still worth ingesting without its entities
            log.warning("sentinel: entities of incident %s not readable: %s", name, exc)
            return []
        return (body or {}).get("entities") or []

    def _refs(self, entities: list[dict[str, Any]]) -> list[EntityRef]:
        refs: list[EntityRef] = []
        for e in entities:
            kind, p = str(e.get("kind") or ""), e.get("properties") or {}
            if kind == "Account":
                name, suffix, dom = p.get("accountName"), p.get("upnSuffix"), p.get("ntDomain")
                raw = f"{name}@{suffix}" if name and suffix else (f"{dom}\\{name}" if name and dom else name)
                u = user_ref(raw, default_domain=self.settings.get("user_domain"))
                if u is not None:
                    refs.append(u)
            elif kind == "Mailbox" and p.get("mailboxPrimaryAddress"):
                u = user_ref(p["mailboxPrimaryAddress"], role="recipient")
                if u is not None:
                    refs.append(u)
            elif kind == "Host" and (p.get("hostName") or p.get("netBiosName")):
                host = str(p.get("hostName") or p.get("netBiosName"))
                attrs = {"hostname": host.split(".")[0]}
                if p.get("dnsDomain"):
                    attrs["fqdn"] = f"{attrs['hostname']}.{p['dnsDomain']}".lower()
                mde = (p.get("additionalData") or {}).get("MdatpDeviceId")
                refs.append(EntityRef(kind="asset", role="host", keys={"mde_device_id": mde} if mde else {},
                                      attributes=attrs))
            else:
                value, typ = {"Ip": (p.get("address"), "ip"), "Url": (p.get("url"), "url"),
                              "DnsResolution": (p.get("domainName"), "domain"),
                              "FileHash": (p.get("hashValue") if str(p.get("algorithm", "")).upper() == "SHA256" else None,
                                           "sha256")}.get(kind, (None, None))
                if value:
                    refs.append(EntityRef(kind="indicator", role="observable", keys={"value": str(value)},
                                          attributes={"type": typ}))
        return refs

    def normalize(self, stream: str, inc: dict[str, Any]) -> list[NormalizedRecord]:
        p = inc.get("properties") or {}
        extra = p.get("additionalData") or {}
        source_id = inc.get("name") or inc.get("id")
        if not source_id:
            raise ValueError("Sentinel incident without a name or id")
        return [NormalizedRecord(
            kind="alert", tool=self.tool, source_type="incident", source_id=str(source_id),
            observed_at=parse_ts(p.get("createdTimeUtc") or p.get("firstActivityTimeUtc")),
            title=p.get("title") or "Sentinel incident", severity=sev_name(p.get("severity")), dimension="other",
            refs=self._refs(inc.get("_entities") or []),
            attributes={"status": p.get("status"), "incident_number": p.get("incidentNumber"),
                        "classification": p.get("classification"), "tactics": extra.get("tactics"),
                        "techniques": extra.get("techniques"), "alert_count": extra.get("alertsCount"),
                        "products": extra.get("alertProductNames"), "description": p.get("description"),
                        "labels": [x.get("labelName") for x in p.get("labels") or [] if isinstance(x, dict)]},
            deep_link=p.get("incidentUrl"))]


def _field_map(v: Any) -> dict[str, str]:
    """From connectors.yaml the map is a mapping; from an environment variable it is a JSON string."""
    if not v:
        return {}
    value = json.loads(v) if isinstance(v, str) else v
    if not isinstance(value, dict):
        raise TypeError("generic_siem field_map must be a JSON object")
    return {str(k): str(x) for k, x in value.items()}


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
              "source": "source", **_field_map(self.settings.get("field_map"))}
        g = lambda k: _pick(a, fm[k])
        if g("id") in (None, ""):
            raise ValueError(f"pushed alert without an id (field '{fm['id']}')")
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
                                 attributes={k: v for k, v in a.items() if k not in fm.values()
                                             and k.split(".")[0] not in {f.split(".")[0] for f in fm.values()}})]


def _pick(payload: dict[str, Any], key: str) -> Any:
    """A field by its flat name, or by a dotted path into nested objects (Elastic ``host.name``, ``kibana.alert.uuid``):
    a literal dotted key wins over the path. Lists yield their first element."""
    if key in payload:
        return payload[key]
    cur: Any = payload
    parts = key.split(".")
    i = 0
    while i < len(parts):
        if isinstance(cur, list):
            cur = cur[0] if cur else None
            continue
        if not isinstance(cur, dict):
            return None
        for j in range(len(parts), i, -1):        # longest dotted key first ("kibana.alert" inside a flat-ish object)
            k = ".".join(parts[i:j])
            if k in cur:
                cur, i = cur[k], j
                break
        else:
            return None
    return cur[0] if isinstance(cur, list) and cur else cur


MANIFESTS = [
    ConnectorManifest(
        name="sentinel", tool="Microsoft Sentinel", vendor="Microsoft", category="siem", dimension="other",
        description="Sentinel incidents (if Sentinel is the client's SIEM).",
        factory=lambda s, t: SentinelConnector(s, t, rate_per_sec=2, burst=4),
        live_transport=lambda s: HttpTransport("https://management.azure.com", entra_app_auth(
            s["tenant_id"], s["client_id"], s["client_secret"], "https://management.azure.com/.default")),
        config=[ConfigField("tenant_id", "Entra tenant id"),
                ConfigField("client_id", "App registration (client) id", secret=True),
                ConfigField("client_secret", "App registration secret", secret=True),
                ConfigField("subscription_id", "Azure subscription holding the Sentinel workspace"),
                ConfigField("resource_group", "Resource group of the Log Analytics workspace"),
                ConfigField("workspace", "Log Analytics workspace name")],
        fake_settings={"subscription_id": "sub-001", "resource_group": "rg-acme-security", "workspace": "law-acme-sentinel"},
        confidence="Unknown", to_confirm="Whether a SIEM exists and which (Q01)", focus_areas=("incident",)),
    ConnectorManifest(
        name="generic_siem", tool="Generic SIEM/SOAR webhook", vendor="any", category="siem", dimension="other",
        description="Normalises alerts pushed to /api/v1/ingest/alerts from any SIEM/SOAR.",
        factory=lambda s, t: GenericSiemConnector(s, t, rate_per_sec=100, burst=100),
        live_transport=lambda s: HttpTransport("http://localhost", NoAuth()),
        config=[ConfigField("field_map", "Mapping of platform fields to payload keys", required=False, kind="map")],
        confidence="High", focus_areas=("incident",)),
]
