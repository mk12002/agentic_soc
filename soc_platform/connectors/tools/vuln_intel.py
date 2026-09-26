"""Vulnerability intelligence feeds: NVD CVE 2.0, FIRST EPSS, CISA KEV (VM-F04, VM-T06, VM-F16, U02).

Public feeds, no credentials required (NVD API key optional for higher rate limits).
Each lookup returns structured data the VM prioritiser consumes; feeds are cached
by the caller with an explicit freshness timestamp (VM-T06 staleness indication).
"""

from __future__ import annotations

from typing import Any

from soc_platform.connectors.base import LookupResult, Page
from soc_platform.connectors.http import ApiKeyHeader, HttpTransport, NoAuth
from soc_platform.connectors.registry import ConfigField, ConnectorManifest
from soc_platform.connectors.tools._common import ToolConnector, ok_lookup


class NvdConnector(ToolConnector):
    name = "nvd"
    tool = "nvd"
    dimension = "threat_intel"
    streams = ("recent_cves",)
    lookups = ("cve",)

    def fetch_page(self, stream: str, cursor: str | None) -> Page:
        start = int(cursor or 0)
        body = self.get("/rest/json/cves/2.0", params={"startIndex": start, "resultsPerPage": 2000,
                                                       "lastModStartDate": self.settings.get("since", "")} if
                        self.settings.get("since") else {"startIndex": start, "resultsPerPage": 2000})
        vulns = body.get("vulnerabilities") or []
        total = int(body.get("totalResults", len(vulns)))
        nxt = start + len(vulns)
        return Page(vulns, str(nxt), source_total=total, has_more=nxt < total)

    def normalize(self, stream, raw):  # feed data is consumed via cve_detail(); nothing to store as entities
        return []

    def cve_detail(self, cve_id: str) -> dict[str, Any] | None:
        # explicit page: NVD has answered single-CVE lookups with resultsPerPage=0 (totalResults 1, empty page)
        body = self.get("/rest/json/cves/2.0", params={"cveId": cve_id, "resultsPerPage": 1, "startIndex": 0})
        items = body.get("vulnerabilities") or []
        if not items:
            return None
        c = items[0]["cve"]
        metrics = c.get("metrics") or {}
        m31 = (metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30") or [{}])[0].get("cvssData") or {}
        desc = next((d["value"] for d in c.get("descriptions") or [] if d.get("lang") == "en"), "")
        cwes = [d["value"] for w in c.get("weaknesses") or [] for d in w.get("description") or []]
        refs = [r["url"] for r in c.get("references") or []][:10]
        return {"cve": cve_id, "published": c.get("published"), "last_modified": c.get("lastModified"),
                "description": desc, "cvss": m31.get("baseScore"), "vector": m31.get("vectorString"),
                "severity": m31.get("baseSeverity"), "cwes": cwes, "references": refs,
                "exploit_references": [r["url"] for r in c.get("references") or [] if "Exploit" in (r.get("tags") or [])]}

    def lookup(self, entity_type: str, value: str, **context: Any) -> LookupResult:
        def run() -> LookupResult:
            d = self.cve_detail(value)
            summary = f"{value}: CVSS {d['cvss']} {d['severity']} - {d['description'][:160]}" if d else f"{value} not in NVD"
            return ok_lookup(self, [], summary, f"https://nvd.nist.gov/vuln/detail/{value}")

        return self.timed_lookup(run)


class EpssConnector(ToolConnector):
    name = "epss"
    tool = "epss"
    dimension = "threat_intel"
    lookups = ("cve",)

    def fetch_page(self, stream, cursor):
        return Page([], None, has_more=False)

    def normalize(self, stream, raw):
        return []

    def scores(self, cves: list[str]) -> dict[str, dict[str, float]]:
        out: dict[str, dict[str, float]] = {}
        for i in range(0, len(cves), 100):
            body = self.get("/data/v1/epss", params={"cve": ",".join(cves[i:i + 100])})
            for row in body.get("data") or []:
                out[row["cve"]] = {"epss": float(row["epss"]), "percentile": float(row["percentile"]), "date": row.get("date")}
        return out

    def lookup(self, entity_type: str, value: str, **context: Any) -> LookupResult:
        def run():
            s = self.scores([value]).get(value)
            return ok_lookup(self, [], f"{value}: EPSS {s['epss']:.3f} (p{s['percentile'] * 100:.0f})" if s
                             else f"{value}: no EPSS score")
        return self.timed_lookup(run)


class KevConnector(ToolConnector):
    name = "cisa_kev"
    tool = "cisa_kev"
    dimension = "threat_intel"
    streams = ("catalog",)
    lookups = ("cve",)

    def __init__(self, settings, transport, **kw):
        super().__init__(settings, transport, **kw)
        self._catalog: dict[str, dict[str, Any]] | None = None
        self.catalog_version: str | None = None

    def catalog(self, refresh: bool = False) -> dict[str, dict[str, Any]]:
        if self._catalog is None or refresh:
            body = self.get("/sites/default/files/feeds/known_exploited_vulnerabilities.json")
            self.catalog_version = body.get("catalogVersion")
            self._catalog = {v["cveID"]: v for v in body.get("vulnerabilities") or []}
        return self._catalog

    def fetch_page(self, stream, cursor):
        return Page(list(self.catalog(refresh=True).values()), self.catalog_version, has_more=False)

    def normalize(self, stream, raw):
        return []

    def added_since(self, date_iso: str) -> list[dict[str, Any]]:
        """KEV additions since a date - drives the new-CVE exposure assessment (VM-F16, U02)."""
        return sorted([v for v in self.catalog().values() if str(v.get("dateAdded", "")) >= date_iso[:10]],
                      key=lambda v: v.get("dateAdded", ""))

    def lookup(self, entity_type: str, value: str, **context: Any) -> LookupResult:
        def run():
            v = self.catalog().get(value)
            return ok_lookup(self, [], f"{value} is on CISA KEV (added {v.get('dateAdded')}, due {v.get('dueDate')}, "
                                       f"ransomware use: {v.get('knownRansomwareCampaignUse')})" if v
                             else f"{value} is not on CISA KEV")
        return self.timed_lookup(run)


MANIFESTS = [
    ConnectorManifest(
        name="nvd", tool="NIST NVD", vendor="NIST", category="intel", dimension="threat_intel",
        description="CVE metadata (CVSS, CWE, references) from the NVD CVE API 2.0.",
        factory=lambda s, t: NvdConnector(s, t, rate_per_sec=0.15 if not s.get("api_key") else 1.5, burst=5),
        live_transport=lambda s: HttpTransport("https://services.nvd.nist.gov",
                                               ApiKeyHeader("apiKey", s["api_key"]) if s.get("api_key") else NoAuth()),
        config=[ConfigField("api_key", "Optional NVD API key (raises rate limit)", secret=True, required=False)],
        confidence="High", focus_areas=("vulnerability",)),
    ConnectorManifest(
        name="epss", tool="FIRST EPSS", vendor="FIRST", category="intel", dimension="threat_intel",
        description="Exploit Prediction Scoring System probabilities per CVE.",
        factory=lambda s, t: EpssConnector(s, t, rate_per_sec=2, burst=4),
        live_transport=lambda s: HttpTransport("https://api.first.org"), confidence="High",
        focus_areas=("vulnerability",)),
    ConnectorManifest(
        name="cisa_kev", tool="CISA KEV catalogue", vendor="CISA", category="intel", dimension="threat_intel",
        description="Known Exploited Vulnerabilities catalogue; additions trigger exposure assessment.",
        factory=lambda s, t: KevConnector(s, t, rate_per_sec=1, burst=2),
        live_transport=lambda s: HttpTransport("https://www.cisa.gov"), confidence="High",
        focus_areas=("vulnerability", "incident")),
]
