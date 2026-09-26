"""Microsoft Defender for Endpoint connector (IM-T01, VM-T01, IM-F09, IM-F10, PH-F07).

Read: alerts, device inventory, TVM vulnerabilities, advanced hunting (Device* tables),
file / IP / domain lookups. Write (policy-gated): isolate / release, AV scan,
investigation package, custom indicators (block URL / domain / IP / file) with removal.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from soc_platform.connectors.base import LookupResult, Page
from soc_platform.connectors.registry import ConfigField, ConnectorManifest
from soc_platform.connectors.tools._common import ConnectorAction, ok_lookup, parse_ts, sev_name, targets_of
from soc_platform.connectors.tools._microsoft import APP_FIELDS, MicrosoftConnector, kql_str, mde_transport
from soc_platform.core.identity import user_ref
from soc_platform.core.schema import EntityRef, NormalizedRecord

PORTAL = "https://security.microsoft.com"
INDICATOR_TYPES = {"domain": "DomainName", "url": "Url", "ip": "IpAddress", "sha256": "FileSha256", "sha1": "FileSha1"}



def _ts(at: Any) -> str:
    """findbyip needs an ISO-8601 UTC timestamp: the IP owner is looked up +-15 min around it."""
    if isinstance(at, datetime):
        return at.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    return str(at) if at else __import__("soc_platform.core.models", fromlist=["utcnow"]).utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

class DefenderEndpointConnector(MicrosoftConnector):
    name = "defender_endpoint"
    tool = "defender_endpoint"
    dimension = "endpoint"
    streams = ("alerts", "machines", "vulnerabilities")
    lookups = ("host", "ip", "hash", "domain", "user")
    read_scopes = ("Alert.Read.All", "Machine.Read.All", "Vulnerability.Read.All", "AdvancedQuery.Read.All",
                   "Ti.Read.All")
    write_scopes = ("Machine.Isolate", "Machine.Scan", "Machine.CollectForensics", "Ti.ReadWrite.All")

    def fetch_page(self, stream: str, cursor: str | None) -> Page:
        path = {"alerts": "/api/alerts", "machines": "/api/machines",
                "vulnerabilities": "/api/vulnerabilities/machinesVulnerabilities"}[stream]
        return self.odata_page(path, cursor, {"$top": 1000})

    def normalize(self, stream: str, raw: dict[str, Any]) -> list[NormalizedRecord]:
        return [{"alerts": self._alert, "machines": self._machine, "vulnerabilities": self._vuln}[stream](raw)]

    def _machine(self, m: dict[str, Any]) -> NormalizedRecord:
        fqdn = m.get("computerDnsName") or ""
        return NormalizedRecord(
            kind="asset", tool=self.tool, source_type="machine", source_id=m["id"], observed_at=parse_ts(m.get("lastSeen")),
            keys={"mde_device_id": m["id"], "aad_device_id": m.get("aadDeviceId")},
            attributes={"hostname": fqdn.split(".")[0], "fqdn": fqdn if "." in fqdn else None,
                        "ip": m.get("lastIpAddress"), "ips": [x for x in [m.get("lastIpAddress")] if x],
                        "os": f"{m.get('osPlatform', '')} {m.get('osVersion') or ''}".strip(),
                        "risk_score": m.get("riskScore"), "exposure_level": m.get("exposureLevel"),
                        "health_status": m.get("healthStatus"), "onboarding_status": m.get("onboardingStatus"),
                        "tags": m.get("machineTags") or [], "last_seen": m.get("lastSeen")},
            deep_link=f"{PORTAL}/machines/{m['id']}/overview", dimension="endpoint")

    def _alert(self, a: dict[str, Any]) -> NormalizedRecord:
        refs = [EntityRef(kind="asset", role="host", keys={"mde_device_id": a.get("machineId")},
                          attributes={"hostname": (a.get("computerDnsName") or "").split(".")[0],
                                      "fqdn": a.get("computerDnsName")})] if a.get("machineId") else []
        ru = a.get("relatedUser") or {}
        if ru.get("userName"):
            raw_user = f"{ru['domainName']}\\{ru['userName']}" if ru.get("domainName") else ru["userName"]
            u = user_ref(raw_user, default_domain=self.settings.get("user_domain"))
            if u is not None:
                refs.append(u)
        for ev in a.get("evidence") or []:
            if ev.get("sha256"):
                refs.append(EntityRef(kind="indicator", role="observable", keys={"value": ev["sha256"]},
                                      attributes={"type": "sha256"}))
            if ev.get("url"):
                refs.append(EntityRef(kind="indicator", role="observable", keys={"value": ev["url"]},
                                      attributes={"type": "url"}))
        return NormalizedRecord(
            kind="alert", tool=self.tool, source_type="alert", source_id=a["id"],
            observed_at=parse_ts(a.get("alertCreationTime")), title=a.get("title", "Defender alert"),
            severity=sev_name(a.get("severity")), refs=refs, dimension="endpoint",
            attributes={"category": a.get("category"), "status": a.get("status"),
                        "mitre_techniques": a.get("mitreTechniques") or [], "description": a.get("description"),
                        "detection_source": a.get("detectionSource"), "incident_id": a.get("incidentId")},
            deep_link=f"{PORTAL}/alerts/{a['id']}")

    def _vuln(self, v: dict[str, Any]) -> NormalizedRecord:
        return NormalizedRecord(
            kind="finding", tool=self.tool, source_type="machine_vulnerability", source_id=v["id"],
            title=f"{v.get('cveId')} on {v.get('machineId')}", severity=sev_name(v.get("severity")), dimension="exposure",
            refs=[EntityRef(kind="asset", role="host", keys={"mde_device_id": v.get("machineId")})],
            attributes={"cve": v.get("cveId"), "product": f"{v.get('productName', '')} {v.get('productVersion', '')}".strip(),
                        "fixing_kb": v.get("fixingKbId"), "status": "open"},
            deep_link=f"{PORTAL}/vulnerabilities/vulnerability/{v.get('cveId')}/overview")

    # ------------------------------------------------------------------ lookups & hunting

    def hunt(self, query: str) -> list[dict[str, Any]]:
        body = self.post("/api/advancedqueries/run", json={"Query": query})
        return body.get("Results") or body.get("results") or []

    def lookup(self, entity_type: str, value: str, **context: Any) -> LookupResult:
        def run() -> LookupResult:
            if entity_type == "host":
                ms = self.get("/api/machines", params={"$filter": f"computerDnsName eq '{value.lower()}'"}).get("value", [])
                if not ms:
                    ms = self.get("/api/machines", params={"$filter": f"startswith(computerDnsName,'{value.lower()}')"}).get("value", [])
                recs = [self._machine(m) for m in ms]
                alerts = []
                for m in ms:
                    alerts += [self._alert(a) for a in self.get(f"/api/machines/{m['id']}/alerts").get("value", [])]
                summary = (f"MDE: {len(ms)} device(s), risk={[m.get('riskScore') for m in ms]}, "
                           f"exposure={[m.get('exposureLevel') for m in ms]}, {len(alerts)} alert(s)") if ms \
                    else f"host {value} not onboarded to MDE"
                return ok_lookup(self, recs + alerts, summary, recs[0].deep_link if recs else None, found=bool(ms),
                                 endpoint_alerts=len(alerts), risk=[m.get("riskScore") for m in ms])
            if entity_type == "ip":
                ms = self.get("/api/machines/findbyip", params={"ip": value, "timestamp": _ts(context.get("at"))}).get("value", [])
                return ok_lookup(self, [self._machine(m) for m in ms], f"{len(ms)} device(s) used IP {value}")
            if entity_type == "hash":
                f = self.get(f"/api/files/{value}")
                return ok_lookup(self, [], f"file prevalence={f.get('globalPrevalence')}, "
                                           f"determination={f.get('determinationType')}, signer={f.get('signer')}",
                                 malicious=str(f.get("determinationType", "")).lower() == "malware")
            if entity_type == "domain":
                st = self.get(f"/api/domains/{value}/stats")
                return ok_lookup(self, [], f"domain seen on {st.get('orgPrevalence', 0)} device(s) in the org")
            if entity_type == "user":
                ms = self.get(f"/api/users/{value.split('@')[0]}/machines").get("value", [])
                return ok_lookup(self, [self._machine(m) for m in ms], f"user logged on to {len(ms)} device(s)")
            raise ValueError(entity_type)

        return self.timed_lookup(run)

    def process_activity(self, device_name: str, since_iso: str, indicators: list[str]) -> list[dict[str, Any]]:
        """Process/file/network activity touching given indicators on a device (PH-F07)."""
        q = (f"let iocs = dynamic([{', '.join(kql_str(i) for i in indicators)}]);\n"
             "union DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents\n"
             f"| where DeviceName =~ {kql_str(device_name)} and Timestamp >= datetime({since_iso})\n"
             "| where ProcessCommandLine has_any (iocs) or RemoteUrl has_any (iocs) or SHA256 in (iocs)"
             " or InitiatingProcessCommandLine has_any (iocs)\n"
             "| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine, RemoteUrl, SHA256\n"
             "| order by Timestamp asc")
        return self.hunt(q)

    # ------------------------------------------------------------------ actions

    def _machines(self, targets: list) -> list[str]:
        return targets_of(targets, "asset", "mde_device_id")

    def isolate(self, params: dict, targets: list) -> dict:
        out = {mid: self.post(f"/api/machines/{mid}/isolate", json={
            "Comment": params.get("comment", "SOC platform isolation"),
            "IsolationType": params.get("isolation_type", "Selective")}) for mid in self._machines(targets)}
        return {"isolated": list(out), "responses": out}

    def release(self, params: dict, targets: list) -> dict:
        out = {mid: self.post(f"/api/machines/{mid}/unisolate", json={"Comment": "SOC platform release"})
               for mid in self._machines(targets)}
        return {"released": list(out), "responses": out}

    def scan(self, params: dict, targets: list) -> dict:
        return {mid: self.post(f"/api/machines/{mid}/runAntiVirusScan",
                               json={"Comment": "SOC platform scan", "ScanType": params.get("scan_type", "Quick")})
                for mid in self._machines(targets)}

    def collect(self, params: dict, targets: list) -> dict:
        return {mid: self.post(f"/api/machines/{mid}/collectInvestigationPackage", json={"Comment": "SOC platform"})
                for mid in self._machines(targets)}

    def block_indicator(self, params: dict, targets: list) -> dict:
        created = []
        for t in targets:
            itype = INDICATOR_TYPES.get(str(t.get("indicator_type") or t.get("ioc_type")))
            if t.get("type") != "indicator" or not itype:
                continue
            body = self.post("/api/indicators", json={
                "indicatorValue": t["value"], "indicatorType": itype, "action": params.get("action", "Block"),
                "title": params.get("title", "SOC platform block"), "severity": params.get("severity", "High"),
                "description": params.get("reason", "Confirmed malicious by SOC analyst"),
                "generateAlert": True})
            created.append({"value": t["value"], "indicator_id": body.get("id"), "response": body})
        return {"created": created}

    def unblock_indicator(self, params: dict, targets: list) -> dict:
        removed = []
        for ind in params.get("created", []):
            if ind.get("indicator_id"):
                self.req("DELETE", f"/api/indicators/{ind['indicator_id']}")
                removed.append(ind["indicator_id"])
        return {"removed": removed}


def _has_mde(params: dict, targets: list) -> list[str]:
    return [] if targets_of(targets, "asset", "mde_device_id") else ["target asset has no Defender device id"]


def _actions(c: DefenderEndpointConnector) -> list:
    return [
        ConnectorAction("endpoint.isolate", c, c.isolate, description="Defender device isolation (selective)",
                        reverse_type="endpoint.release", preconditions=_has_mde),
        ConnectorAction("endpoint.release", c, c.release, description="Release Defender isolation", preconditions=_has_mde),
        ConnectorAction("endpoint.scan", c, c.scan, description="Defender AV scan", preconditions=_has_mde),
        ConnectorAction("endpoint.collect_forensics", c, c.collect, description="Collect investigation package",
                        preconditions=_has_mde),
        ConnectorAction("indicator.block", c, c.block_indicator,
                        description="Create Defender custom indicator (block URL/domain/IP/file)",
                        reverse_type="indicator.unblock",
                        reverse=lambda p, t, r: ({"created": r.get("created", [])}, t)),
        ConnectorAction("indicator.unblock", c, c.unblock_indicator, description="Remove Defender custom indicator"),
    ]


MANIFEST = ConnectorManifest(
    name="defender_endpoint", tool="Microsoft Defender for Endpoint", vendor="Microsoft", category="edr",
    dimension="endpoint",
    description="Alerts, device inventory, TVM vulnerabilities, advanced hunting, isolation, scans, custom indicators.",
    factory=lambda s, t: DefenderEndpointConnector(s, t, rate_per_sec=1.5, burst=20),  # MDE: 100 calls/min per app
    live_transport=mde_transport,
    config=APP_FIELDS + [ConfigField("user_domain", "UPN suffix for alert users", required=False),
                         ConfigField("mde_base", "API base (regional endpoints)", required=False)],
    actions=_actions, confidence="High",
    to_confirm="Licence tier (P2 for advanced hunting/TVM); app permissions; hunting quota",
    fake_settings={"user_domain": "acme-demo.com", "tenant_id": "demo-tenant"},
    focus_areas=("incident", "vulnerability", "phishing"),
)
