"""CrowdStrike Falcon connector (IM-T01, VM-T01, IM-F09, IM-F10, IM-T09).

Read: alerts (detections), host inventory, Spotlight vulnerabilities, IOC lookups.
Write (policy-gated): network containment / lift, Real Time Response collection.
To confirm with the client: API client scopes, Spotlight/Exposure licence, RTR response policy.
"""

from __future__ import annotations

from typing import Any

from soc_platform.connectors.base import LookupResult, Page
from soc_platform.connectors.http import HttpTransport, OAuth2ClientCredentials
from soc_platform.connectors.registry import ConfigField, ConnectorManifest
from soc_platform.connectors.tools._common import (
    ConnectorAction,
    ToolConnector,
    Watermark,
    need,
    ok_lookup,
    parse_ts,
    targets_of,
)
from soc_platform.core.identity import user_ref
from soc_platform.core.schema import EntityRef, NormalizedRecord

CONSOLE = "https://falcon.crowdstrike.com"
MAX_OFFSET = 10_000         # Falcon query APIs refuse offset + limit beyond this


def _sev(score: Any) -> str:
    s = int(score or 0)
    return "critical" if s >= 80 else "high" if s >= 60 else "medium" if s >= 40 else "low" if s > 0 else "informational"


class CrowdStrikeConnector(ToolConnector):
    name = "crowdstrike"
    tool = "crowdstrike"
    dimension = "endpoint"
    streams = ("alerts", "hosts", "vulnerabilities")
    lookups = ("host", "hash", "domain", "ip", "user")
    read_scopes = ("Alerts:read", "Hosts:read", "Spotlight vulnerabilities:read", "IOCs:read")
    write_scopes = ("Hosts:write", "Real time response:write")
    page_size = 100

    # ------------------------------------------------------------------ streams

    def fetch_page(self, stream: str, cursor: str | None) -> Page:
        if stream == "alerts":
            # Resume from the newest update seen (cursor "since:<time>"), so status changes on older alerts arrive
            # too; within one sync the cursor is "<offset>|<since>".
            off_s, _, since = (cursor or "").partition("|")
            wm = Watermark.of(self, "alerts")
            if not off_s.isdigit():                       # first page of this sync
                since, off_s = wm.start(cursor) or "", "0"
            offset = int(off_s)
            params: dict[str, Any] = {"offset": offset, "limit": self.page_size, "sort": "updated_timestamp.asc"}
            if since:
                params["filter"] = f"updated_timestamp:>='{since}'"
            q = self.get("/alerts/queries/alerts/v2", params=params)
            ids = q.get("resources") or []
            total = int(((q.get("meta") or {}).get("pagination") or {}).get("total", len(ids)))
            recs = self.post("/alerts/entities/alerts/v2", json={"composite_ids": ids}).get("resources", []) if ids else []
            wm.see(recs, "updated_timestamp")
            nxt = offset + len(ids)
            if ids and nxt < total:
                if nxt + self.page_size > MAX_OFFSET:
                    # the query API refuses offset+limit past 10,000: restart from the newest update seen (sorted
                    # ascending, ">=" re-reads that second; ingest is idempotent). No progress -> carry on and fail loudly.
                    mark = (wm.finish() or "")[6:]
                    if mark and mark != since:
                        return Page(recs, f"0|{mark}", source_total=total, has_more=True)
                return Page(recs, f"{nxt}|{since}", source_total=total, has_more=True)
            return Page(recs, wm.finish(), source_total=total, has_more=False, reset=True)
        if stream == "hosts":
            # inventory: read in full each sync (last seen, tags change). The scroll query has no 10,000 offset limit
            # (the plain device query has); its continuation is a token, the cursor is "<read so far>|<token>".
            seen_s, _, token = (cursor or "").partition("|")
            params: dict[str, Any] = {"limit": self.page_size}
            if token:
                params["offset"] = token
            q = self.get("/devices/queries/devices-scroll/v1", params=params)
            ids = q.get("resources") or []
            pag = (q.get("meta") or {}).get("pagination") or {}
            seen = int(seen_s or 0) + len(ids)
            total = int(pag.get("total", seen))
            recs = self.post("/devices/entities/devices/v2", json={"ids": ids}).get("resources", []) if ids else []
            nxt = pag.get("offset")
            if ids and seen < total and nxt and str(nxt) != token:
                return Page(recs, f"{seen}|{nxt}", source_total=total, has_more=True)
            return Page(recs, None, source_total=total, has_more=False, reset=True)
        if stream == "vulnerabilities":                   # open findings: in full each sync; "after" tokens expire
            params = {"filter": "status:['open','reopen']", "limit": self.page_size,
                      "facet": ["cve", "host_info", "remediation"]}
            if cursor:
                params["after"] = cursor
            body = self.get("/spotlight/combined/vulnerabilities/v1", params=params)
            after = ((body.get("meta") or {}).get("pagination") or {}).get("after")
            recs = body.get("resources") or []
            if after and recs:
                return Page(recs, after, has_more=True)
            return Page(recs, None, has_more=False, reset=True)
        raise ValueError(f"unknown stream {stream}")

    def normalize(self, stream: str, raw: dict[str, Any]) -> list[NormalizedRecord]:
        if stream == "hosts":
            return [self._host(raw)]
        if stream == "alerts":
            return [self._alert(raw)]
        if stream == "vulnerabilities":
            return [self._vuln(raw)]
        return []

    def _host_ref(self, dev: dict[str, Any], aid: str | None = None) -> EntityRef:
        return EntityRef(kind="asset", role="host",
                         keys={k: v for k, v in {"crowdstrike_aid": aid or dev.get("device_id")}.items() if v},
                         attributes={"hostname": dev.get("hostname"), "ip": dev.get("local_ip"),
                                     "os": dev.get("os_version") or dev.get("platform_name")})

    def _user_ref(self, user: str | None) -> EntityRef | None:
        return user_ref(user, default_domain=self.settings.get("user_domain"))

    def _host(self, d: dict[str, Any]) -> NormalizedRecord:
        return NormalizedRecord(
            kind="asset", tool=self.tool, source_type="device", source_id=need(d, "device_id"),
            observed_at=parse_ts(d.get("last_seen")), dimension="endpoint",
            keys={"crowdstrike_aid": d.get("device_id"), "serial_number": d.get("serial_number"),
                  "mac": d.get("mac_address")},
            attributes={"hostname": d.get("hostname"), "ip": d.get("local_ip"),
                        "ips": [x for x in [d.get("local_ip"), d.get("external_ip")] if x],
                        "os": d.get("os_version") or d.get("platform_name"), "platform": d.get("platform_name"),
                        "containment": d.get("status"), "sensor_version": d.get("agent_version"),
                        "last_seen": d.get("last_seen"), "tags": d.get("tags") or []},
            deep_link=f"{CONSOLE}/host-management/hosts/{d['device_id']}",
        )

    def _alert(self, a: dict[str, Any]) -> NormalizedRecord:
        dev = a.get("device") or {}
        refs = [self._host_ref(dev)]
        u = self._user_ref(a.get("user_name"))
        if u:
            refs.append(u)
        for h in [a.get("sha256")]:
            if h:
                refs.append(EntityRef(kind="indicator", role="observable", keys={"value": h}, attributes={"type": "sha256"}))
        return NormalizedRecord(
            kind="alert", tool=self.tool, source_type="alert", source_id=need(a, "composite_id"),
            observed_at=parse_ts(a.get("created_timestamp")), title=a.get("display_name") or a.get("name", "Falcon alert"),
            severity=_sev(a.get("severity")), dimension="endpoint", refs=refs,
            attributes={"description": a.get("description"), "tactic": a.get("tactic"), "technique": a.get("technique"),
                        "technique_id": a.get("technique_id"), "cmdline": a.get("cmdline"), "filename": a.get("filename"),
                        "sha256": a.get("sha256"), "parent_cmdline": (a.get("parent_details") or {}).get("cmdline"),
                        "status": a.get("status"), "confidence": a.get("confidence")},
            deep_link=a.get("falcon_host_link"),
        )

    def _vuln(self, v: dict[str, Any]) -> NormalizedRecord:
        cve = v.get("cve") or {}
        host = v.get("host_info") or {}
        apps = v.get("apps") or []
        return NormalizedRecord(
            kind="finding", tool=self.tool, source_type="spotlight_vulnerability", source_id=need(v, "id"),
            observed_at=parse_ts(v.get("updated_timestamp") or v.get("created_timestamp")),
            title=f"{cve.get('id')} on {host.get('hostname')}", severity=(cve.get("severity") or "").lower() or None,
            dimension="exposure",
            refs=[EntityRef(kind="asset", role="host", keys={"crowdstrike_aid": v.get("aid")},
                            attributes={"hostname": host.get("hostname"), "ip": host.get("local_ip"),
                                        "os": host.get("os_version")})],
            attributes={"cve": cve.get("id"), "cvss": cve.get("base_score"), "status": v.get("status"),
                        "exploit_status": cve.get("exploit_status"), "exprt_rating": cve.get("exprt_rating"),
                        "product": apps[0].get("product_name_version") if apps else None,
                        "first_seen": v.get("created_timestamp"),
                        "remediation": [r.get("action") for r in ((v.get("remediation") or {}).get("entities") or [])
                                        if isinstance(r, dict)]},
            deep_link=f"{CONSOLE}/spotlight-v2/vulnerabilities?filter=cve.id:'{cve.get('id')}'",
        )

    # ------------------------------------------------------------------ lookups

    def lookup(self, entity_type: str, value: str, **context: Any) -> LookupResult:
        def run() -> LookupResult:
            if entity_type == "host":
                ids = self.get("/devices/queries/devices/v1", params={"filter": f"hostname:'{value}'"}).get("resources") or []
                devs = self.post("/devices/entities/devices/v2", json={"ids": ids}).get("resources", []) if ids else []
                recs = [self._host(d) for d in devs]
                alerts = []
                for d in devs:
                    q = self.get("/alerts/queries/alerts/v2", params={"filter": f"device.device_id:'{d['device_id']}'"})
                    aids = q.get("resources") or []
                    if aids:
                        alerts += [self._alert(a) for a in
                                   self.post("/alerts/entities/alerts/v2", json={"composite_ids": aids}).get("resources", [])]
                summary = (f"{len(devs)} Falcon host(s); containment={[d.get('status') for d in devs]}; "
                           f"{len(alerts)} alert(s)") if devs else f"host {value} not found in Falcon"
                return ok_lookup(self, recs + alerts, summary, recs[0].deep_link if recs else None,
                                 found=bool(devs), endpoint_alerts=len(alerts),
                                 contained=any(d.get("status") == "contained" for d in devs))
            if entity_type == "user":
                q = self.get("/alerts/queries/alerts/v2", params={"filter": f"user_name:'{value.split('@')[0]}'"})
                aids = q.get("resources") or []
                alerts = [self._alert(a) for a in self.post("/alerts/entities/alerts/v2", json={"composite_ids": aids})
                          .get("resources", [])] if aids else []
                return ok_lookup(self, alerts, f"{len(alerts)} Falcon alert(s) for user {value}",
                                 endpoint_alerts=len(alerts))
            itype = {"hash": "sha256", "domain": "domain", "ip": "ipv4"}[entity_type]
            body = self.get("/iocs/combined/indicator/v1", params={"filter": f"type:'{itype}'+value:'{value.lower()}'"})
            iocs = body.get("resources") or []
            summary = (f"custom IOC present: action={iocs[0].get('action')}, severity={iocs[0].get('severity')}"
                       if iocs else f"no custom IOC for {value}")
            return ok_lookup(self, [], summary, custom_ioc=bool(iocs))

        return self.timed_lookup(run)

    # ------------------------------------------------------------------ actions

    def contain(self, params: dict, targets: list) -> dict:
        ids = targets_of(targets, "asset", "crowdstrike_aid")
        if not ids:
            raise ValueError("no CrowdStrike device ids in targets")
        body = self.post("/devices/entities/devices-actions/v2", params={"action_name": "contain"}, json={"ids": ids})
        return {"contained": ids, "response": body}

    def lift(self, params: dict, targets: list) -> dict:
        ids = targets_of(targets, "asset", "crowdstrike_aid")
        body = self.post("/devices/entities/devices-actions/v2", params={"action_name": "lift_containment"}, json={"ids": ids})
        return {"released": ids, "response": body}

    def rtr_collect(self, params: dict, targets: list) -> dict:
        """Evidence-preserving collection over RTR (replaces the custom polling agent, IM-T09)."""
        out = {}
        commands = params.get("commands") or ["ps", "netstat", "ls C:\\Windows\\Temp"]
        for aid in targets_of(targets, "asset", "crowdstrike_aid"):
            sess = self.post("/real-time-response/entities/sessions/v1", json={"device_id": aid, "origin": "soc_platform"})
            sid = ((sess.get("resources") or [{}])[0]).get("session_id", "fixture-session")
            results = []
            for cmd in commands:
                base = cmd.split()[0]
                r = self.post("/real-time-response/entities/command/v1",
                              json={"base_command": base, "command_string": cmd, "session_id": sid})
                results.append({"command": cmd, "response": r})
            out[aid] = results
        return {"collected": out}


def _preconditions_has_aid(params: dict, targets: list) -> list[str]:
    return [] if targets_of(targets, "asset", "crowdstrike_aid") else ["target asset has no CrowdStrike agent id"]


def _actions(c: CrowdStrikeConnector) -> list:
    return [
        ConnectorAction("endpoint.isolate", c, c.contain, description="Falcon network containment",
                        reverse_type="endpoint.release", preconditions=_preconditions_has_aid),
        ConnectorAction("endpoint.release", c, c.lift, description="Lift Falcon network containment",
                        preconditions=_preconditions_has_aid),
        ConnectorAction("endpoint.collect_forensics", c, c.rtr_collect,
                        description="Real Time Response read-only collection (ps/netstat/file listing)",
                        preconditions=_preconditions_has_aid),
    ]


def _live(settings: dict[str, Any]) -> HttpTransport:
    base = settings.get("base_url") or "https://api.crowdstrike.com"
    return HttpTransport(base, OAuth2ClientCredentials(f"{base}/oauth2/token", settings["client_id"],
                                                       settings["client_secret"]))


MANIFEST = ConnectorManifest(
    name="crowdstrike", tool="CrowdStrike Falcon", vendor="CrowdStrike", category="edr", dimension="endpoint",
    description="Detections, host inventory, Spotlight vulnerabilities, IOC lookup, containment and RTR collection.",
    factory=lambda s, t: CrowdStrikeConnector(s, t, rate_per_sec=8, burst=15),
    live_transport=_live,
    config=[ConfigField("base_url", "API base (e.g. https://api.eu-1.crowdstrike.com)", required=False,
                        default="https://api.crowdstrike.com", kind="url"),
            ConfigField("client_id", "OAuth2 API client id", secret=True),
            ConfigField("client_secret", "OAuth2 API client secret", secret=True),
            ConfigField("user_domain", "Domain appended to bare user names to form a UPN", required=False)],
    actions=_actions, confidence="High",
    to_confirm="API client scopes; Spotlight/Exposure licence; RTR response policy",
    fake_settings={"user_domain": "acme-demo.com"},
    focus_areas=("incident", "vulnerability", "phishing"),
)
