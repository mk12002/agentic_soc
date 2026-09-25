"""Thinkst Canary connector (IM-T01, IM-F04 deception, U04).

Canary incidents are near-zero false positive, which makes them the first
candidate for a higher autonomy level (policy: ``canary.escalate``).
"""

from __future__ import annotations

from typing import Any

from soc_platform.connectors.base import LookupResult, Page
from soc_platform.connectors.http import ApiKeyQuery, HttpTransport
from soc_platform.connectors.registry import ConfigField, ConnectorManifest
from soc_platform.connectors.tools._common import ConnectorAction, ToolConnector, ok_lookup, parse_ts
from soc_platform.core.identity import user_ref
from soc_platform.core.schema import EntityRef, NormalizedRecord


class CanaryConnector(ToolConnector):
    name = "canary"
    tool = "canary"
    dimension = "deception"
    streams = ("incidents", "devices")
    lookups = ("ip", "host")
    read_scopes = ("API auth token (read-only where available)",)
    write_scopes = ("acknowledge incidents",)

    @property
    def console(self) -> str:
        return f"https://{self.settings.get('domain_hash', 'example')}.canary.tools"

    def fetch_page(self, stream: str, cursor: str | None) -> Page:
        if stream == "devices":
            return Page(self.get("/api/v1/devices/all").get("devices") or [], None, has_more=False)
        params = {"incidents_since": cursor or 0, "shrink": "true"}
        body = self.get("/api/v1/incidents/all", params=params)
        incidents = body.get("incidents") or []
        return Page(incidents, str(body.get("max_updated_id") or cursor or 0), has_more=False)

    def normalize(self, stream: str, raw: dict[str, Any]) -> list[NormalizedRecord]:
        if stream == "devices":
            return [NormalizedRecord(kind="asset", tool=self.tool, source_type="canary_device", source_id=raw["id"],
                                     keys={"canary_device_id": raw["id"]}, dimension="deception",
                                     attributes={"hostname": raw.get("name"), "ip": raw.get("ip_address"),
                                                 "deception": True, "location": raw.get("location")})]
        d = raw.get("description") or raw
        src_ip = d.get("src_host") or d.get("src_ip")
        refs = [EntityRef(kind="asset", role="canary", keys={"canary_device_id": d.get("node_id")} if d.get("node_id") else {},
                          attributes={"hostname": d.get("name"), "ip": d.get("dst_host"), "deception": True})]
        if src_ip:
            refs.append(EntityRef(kind="asset", role="source_host", attributes={"ip": src_ip,
                                                                                "hostname": d.get("src_host_reverse")}))
            refs.append(EntityRef(kind="indicator", role="source_ip", keys={"value": src_ip}, attributes={"type": "ip"}))
        user = (d.get("logdata") or [{}])[0].get("USERNAME") if isinstance(d.get("logdata"), list) else None
        u = user_ref(user, default_domain=self.settings.get("user_domain"))
        if u is not None:
            refs.append(u)
        return [NormalizedRecord(
            kind="deception", tool=self.tool, source_type="incident", source_id=str(raw.get("id") or d.get("incident_id")),
            observed_at=parse_ts(d.get("created_std") or d.get("created")), title=d.get("description") or "Canary incident",
            severity="critical", dimension="deception", refs=refs,
            attributes={"canary": d.get("name"), "src_ip": src_ip, "dst_port": d.get("dst_port"),
                        "event_type": d.get("description"), "acknowledged": d.get("acknowledged") in (True, "True"),
                        "logtype": d.get("logtype"), "events_count": d.get("events_count")},
            deep_link=f"{self.console}/nest/incident/{raw.get('id') or d.get('incident_id')}")]

    def lookup(self, entity_type: str, value: str, **context: Any) -> LookupResult:
        def run() -> LookupResult:
            body = self.get("/api/v1/incidents/all", params={"shrink": "true"})
            hits = []
            for inc in body.get("incidents") or []:
                d = inc.get("description") or inc
                if value.lower() in {str(d.get("src_host", "")).lower(), str(d.get("src_host_reverse", "")).lower().split(".")[0],
                                     str(d.get("src_host_reverse", "")).lower()}:
                    hits.append(inc)
            recs = [r for h in hits for r in self.normalize("incidents", h)]
            summary = (f"DECEPTION HIT: {len(hits)} Canary incident(s) involving {value}" if hits
                       else f"no Canary incidents involving {value}")
            return ok_lookup(self, recs, summary, recs[0].deep_link if recs else None, deception_hits=len(hits))

        return self.timed_lookup(run)

    def acknowledge(self, params: dict, targets: list) -> dict:
        ids = [t["id"] for t in targets if t.get("type") == "deception"]
        for i in ids:
            self.post("/api/v1/incident/acknowledge", data={"incident": i})
        return {"acknowledged": ids}


def _actions(c: CanaryConnector) -> list:
    return [ConnectorAction("canary.acknowledge", c, c.acknowledge, description="Acknowledge Canary incident(s)")]


def _live(s: dict[str, Any]) -> HttpTransport:
    return HttpTransport(f"https://{s['domain_hash']}.canary.tools", ApiKeyQuery("auth_token", s["auth_token"]))


MANIFEST = ConnectorManifest(
    name="canary", tool="Thinkst Canary", vendor="Thinkst", category="deception", dimension="deception",
    description="Canary and Canarytoken incidents and device inventory; high-fidelity deception signal.",
    factory=lambda s, t: CanaryConnector(s, t, rate_per_sec=2, burst=4), live_transport=_live,
    config=[ConfigField("domain_hash", "Console hash (<hash>.canary.tools)"),
            ConfigField("auth_token", "API auth token", secret=True),
            ConfigField("user_domain", "UPN suffix for Canary usernames", required=False)],
    actions=_actions, confidence="High", to_confirm="API token provisioning", focus_areas=("incident",),
    fake_settings={"domain_hash": "cci-demo", "user_domain": "cci-demo.com"},
)
