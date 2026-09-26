"""Rapid7 InsightVM / Nexpose connector (VM-T01, VM-F01, VM-F10, IM-F04 exposure).

Uses the InsightVM Security Console API v3 (/api/3). Assets page with their
vulnerability findings; vulnerability definitions are cached per CVE.
Legacy Nexpose without API: point ``export_csv`` at a data-warehouse / report export instead.
"""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any

from soc_platform.connectors.base import LookupResult, Page
from soc_platform.connectors.http import BasicAuth, HttpTransport
from soc_platform.connectors.registry import ConfigField, ConnectorManifest
from soc_platform.connectors.tools._common import ToolConnector, ok_lookup, parse_ts, sev_from_score
from soc_platform.core.schema import EntityRef, NormalizedRecord


class Rapid7Connector(ToolConnector):
    name = "rapid7"
    tool = "rapid7"
    dimension = "exposure"
    streams = ("assets", "findings")
    lookups = ("host", "ip", "cve")
    read_scopes = ("Security Console: read-only user / API key",)
    page_size = 500

    def __init__(self, settings, transport, **kw):
        super().__init__(settings, transport, **kw)
        self._vuln_cache: dict[str, dict[str, Any]] = {}

    @property
    def console(self) -> str:
        return (self.settings.get("console_url") or "https://insightvm.example.com:3780").rstrip("/")

    def fetch_page(self, stream: str, cursor: str | None) -> Page:
        if self.settings.get("export_csv"):
            return self._csv_page(stream, cursor)
        page = int(cursor or 0)
        body = self.get("/api/3/assets", params={"page": page, "size": self.page_size})
        info = body.get("page") or {}
        assets = body.get("resources") or []
        if stream == "findings":
            rows = []
            for a in assets:
                vulns = self.get(f"/api/3/assets/{a['id']}/vulnerabilities", params={"size": 500}).get("resources") or []
                for v in vulns:
                    rows.append({"asset": a, "finding": v, "definition": self._definition(v["id"])})
            assets = rows
        total_pages = int(info.get("totalPages", 1))
        return Page(assets, str(page + 1), source_total=None, has_more=page + 1 < total_pages)

    def _definition(self, vuln_id: str) -> dict[str, Any]:
        if vuln_id not in self._vuln_cache:
            try:
                self._vuln_cache[vuln_id] = self.get(f"/api/3/vulnerabilities/{vuln_id}")
            except Exception:
                self._vuln_cache[vuln_id] = {"id": vuln_id}
        return self._vuln_cache[vuln_id]

    def _csv_page(self, stream: str, cursor: str | None) -> Page:
        with Path(self.settings["export_csv"]).open(encoding="utf-8", newline="") as fh:
            rows = list(csv.DictReader(fh))
        if stream == "assets":
            seen: dict[str, dict] = {}
            for r in rows:
                seen.setdefault(r["asset_id"], {"id": int(r["asset_id"]), "hostName": r.get("hostname"),
                                                "ip": r.get("ip"), "os": r.get("os")})
            return Page(list(seen.values()), None, has_more=False)
        out = [{"asset": {"id": int(r["asset_id"]), "hostName": r.get("hostname"), "ip": r.get("ip"), "os": r.get("os")},
                "finding": {"id": r["vuln_id"], "status": r.get("status", "vulnerable"), "since": r.get("first_found")},
                "definition": {"id": r["vuln_id"], "title": r.get("title"), "cves": [r["cve"]] if r.get("cve") else [],
                               "cvss": {"v3": {"score": float(r.get("cvss") or 0)}}, "severity": r.get("severity")}}
               for r in rows]
        return Page(out, None, has_more=False)

    def normalize(self, stream: str, raw: dict[str, Any]) -> list[NormalizedRecord]:
        if stream == "assets":
            return [self._asset(raw)]
        a, f, d = raw["asset"], raw["finding"], raw["definition"]
        cves = d.get("cves") or []
        cvss = ((d.get("cvss") or {}).get("v3") or {}).get("score") or ((d.get("cvss") or {}).get("v2") or {}).get("score")
        out = []
        for cve in (cves or [None]):
            out.append(NormalizedRecord(
                kind="finding", tool=self.tool, source_type="asset_vulnerability",
                source_id=f"{a['id']}:{f['id']}:{cve or ''}", observed_at=parse_ts(f.get("since")),
                title=f"{cve or d.get('title') or f['id']} on {a.get('hostName') or a.get('ip')}",
                severity=sev_from_score(cvss) if cvss else (d.get("severity") or "").lower() or None,
                dimension="exposure",
                refs=[EntityRef(kind="asset", role="host", keys={"rapid7_asset_id": str(a["id"])},
                                attributes={"hostname": a.get("hostName"), "fqdn": a.get("hostName") if "." in str(a.get("hostName") or "") else None,
                                            "ip": a.get("ip"), "os": a.get("os")})],
                attributes={"cve": cve, "vuln_id": f["id"], "title": d.get("title"), "cvss": cvss,
                            "status": "open" if f.get("status", "vulnerable").startswith("vulnerable") else f.get("status"),
                            "first_seen": f.get("since"), "exploits": d.get("exploits", 0),
                            "malware_kits": d.get("malwareKits", 0), "solution": (d.get("solution") or {}).get("summary")},
                deep_link=f"{self.console}/asset.jsp?devid={a['id']}"))
        return out

    def _asset(self, a: dict[str, Any]) -> NormalizedRecord:
        host = a.get("hostName") or ""
        macs = [x.get("mac") for x in a.get("addresses") or [] if x.get("mac")]
        return NormalizedRecord(
            kind="asset", tool=self.tool, source_type="asset", source_id=str(a["id"]), dimension="exposure",
            observed_at=parse_ts(((a.get("history") or [{}])[-1]).get("date")),
            keys={"rapid7_asset_id": str(a["id"]), "mac": macs[0] if macs else None},
            attributes={"hostname": host.split(".")[0] if host else None, "fqdn": host if "." in host else None,
                        "ip": a.get("ip"), "os": a.get("os"), "risk_score": a.get("riskScore"),
                        "vulnerabilities": a.get("vulnerabilities"), "tags": [t.get("name") for t in a.get("tags") or []]},
            deep_link=f"{self.console}/asset.jsp?devid={a['id']}")

    def lookup(self, entity_type: str, value: str, **context: Any) -> LookupResult:
        def run() -> LookupResult:
            if entity_type in {"host", "ip"}:
                field = "host-name" if entity_type == "host" else "ip-address"
                body = self.post("/api/3/assets/search", json={
                    "match": "all", "filters": [{"field": field, "operator": "contains" if entity_type == "host" else "is",
                                                 "value": value}]})
                assets = body.get("resources") or []
                recs = [self._asset(a) for a in assets]
                vulns = sum(int((a.get("vulnerabilities") or {}).get("total", 0)) for a in assets)
                crit = sum(int((a.get("vulnerabilities") or {}).get("critical", 0)) for a in assets)
                return ok_lookup(self, recs, f"Rapid7: {len(assets)} asset(s), {vulns} vulnerabilities ({crit} critical)",
                                 recs[0].deep_link if recs else None, vulnerabilities=vulns, critical=crit)
            if entity_type == "cve":
                body = self.post("/api/3/assets/search", params={"size": 500}, json={
                    "match": "all", "filters": [{"field": "cve", "operator": "is", "value": value.upper()}]})
                assets = body.get("resources") or []
                recs = [self._asset(a) for a in assets]
                hosts = sorted({a.get("hostName") or a.get("ip") for a in assets})
                return ok_lookup(self, recs, f"{value}: {len(assets)} affected asset(s) in Rapid7"
                                             + (f" ({', '.join(hosts[:10])})" if hosts else ""),
                                 affected_assets=len(assets), hosts=hosts)
            raise ValueError(entity_type)

        return self.timed_lookup(run)

    def verify_finding(self, asset_id: str, cve: str) -> str:
        """Re-query one asset for a CVE (VM-F10): 'still_present' | 'not_present' | 'asset_missing'."""
        try:
            self.get(f"/api/3/assets/{asset_id}")
        except Exception:
            return "asset_missing"
        vulns = self.get(f"/api/3/assets/{asset_id}/vulnerabilities", params={"size": 500}).get("resources") or []
        for v in vulns:
            if cve in (self._definition(v["id"]).get("cves") or []):
                return "still_present"
        return "not_present"


def _live(s: dict[str, Any]) -> HttpTransport:
    return HttpTransport(s["console_url"], BasicAuth(s["username"], s["password"]), verify=bool(s.get("verify_tls", True)))


MANIFEST = ConnectorManifest(
    name="rapid7", tool="Rapid7 InsightVM / Nexpose", vendor="Rapid7", category="vuln", dimension="exposure",
    description="Asset inventory and vulnerability findings from the Security Console API (or CSV export fallback).",
    factory=lambda s, t: Rapid7Connector(s, t, rate_per_sec=4, burst=8), live_transport=_live,
    config=[ConfigField("console_url", "Security Console URL, e.g. https://ivm.example.local:3780"),
            ConfigField("username", "Read-only API user", secret=True),
            ConfigField("password", "API user password", secret=True),
            ConfigField("verify_tls", "Verify console TLS certificate", required=False, default=True),
            ConfigField("export_csv", "Fallback: path to a findings CSV export (legacy Nexpose)", required=False)],
    confidence="Medium-High", to_confirm="Authoritative product/version; live API availability",
    fake_settings={"console_url": "https://ivm.acme-demo.com:3780"},
    focus_areas=("vulnerability", "incident"),
)
