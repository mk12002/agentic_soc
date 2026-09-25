"""Multi-source threat-intelligence fusion connector (IM-F04 threat intel, PH-F03, VM-F04).

Sources (each optional, enabled by providing its key): VirusTotal, AbuseIPDB,
AlienVault OTX, URLhaus, ThreatFox, MalwareBazaar, GreyNoise, Shodan, urlscan.
The eight sources of the endpoint system are covered; results are fused into a
single verdict with per-source attribution so every claim stays traceable.
Queries run through one transport per source; in fake mode all sources share a
fixture transport keyed by path prefix.
"""

from __future__ import annotations

from typing import Any, Callable

from soc_platform.connectors.base import LookupResult, Page
from soc_platform.connectors.http import ApiKeyHeader, HttpTransport, NoAuth, Transport
from soc_platform.connectors.registry import ConfigField, ConnectorManifest
from soc_platform.connectors.tools._common import ToolConnector, ok_lookup

SOURCES: dict[str, dict[str, Any]] = {
    "virustotal": {"base": "https://www.virustotal.com", "prefix": "/vt", "key": "virustotal_api_key",
                   "auth": lambda k: ApiKeyHeader("x-apikey", k), "types": {"ip", "domain", "url", "hash"}},
    "abuseipdb": {"base": "https://api.abuseipdb.com", "prefix": "/abuseipdb", "key": "abuseipdb_api_key",
                  "auth": lambda k: ApiKeyHeader("Key", k), "types": {"ip"}},
    "otx": {"base": "https://otx.alienvault.com", "prefix": "/otx", "key": "otx_api_key",
            "auth": lambda k: ApiKeyHeader("X-OTX-API-KEY", k), "types": {"ip", "domain", "url", "hash"}},
    "urlhaus": {"base": "https://urlhaus-api.abuse.ch", "prefix": "/urlhaus", "key": "abusech_auth_key",
                "auth": lambda k: ApiKeyHeader("Auth-Key", k), "types": {"url", "domain"}},
    "threatfox": {"base": "https://threatfox-api.abuse.ch", "prefix": "/threatfox", "key": "abusech_auth_key",
                  "auth": lambda k: ApiKeyHeader("Auth-Key", k), "types": {"ip", "domain", "url", "hash"}},
    "malwarebazaar": {"base": "https://mb-api.abuse.ch", "prefix": "/malwarebazaar", "key": "abusech_auth_key",
                      "auth": lambda k: ApiKeyHeader("Auth-Key", k), "types": {"hash"}},
    "greynoise": {"base": "https://api.greynoise.io", "prefix": "/greynoise", "key": "greynoise_api_key",
                  "auth": lambda k: ApiKeyHeader("key", k), "types": {"ip"}},
    "shodan": {"base": "https://api.shodan.io", "prefix": "/shodan", "key": "shodan_api_key",
               "auth": lambda k: NoAuth(), "types": {"ip"}},
}


class ThreatIntelConnector(ToolConnector):
    name = "threat_intel"
    tool = "threat_intel"
    dimension = "threat_intel"
    lookups = ("ip", "domain", "url", "hash")

    def __init__(self, settings: dict[str, Any], transports: dict[str, Transport], **kw: Any) -> None:
        super().__init__(settings, next(iter(transports.values())) if transports else None, **kw)
        self.transports = transports

    def fetch_page(self, stream, cursor):
        return Page([], None, has_more=False)

    def normalize(self, stream, raw):
        return []

    def _q(self, src: str, method: str, path: str, **kw: Any) -> Any:
        t = self.transports[src]
        prefix = SOURCES[src]["prefix"] if getattr(t, "tool", None) == "threat_intel" else ""
        return self.call(lambda: t.request(method, prefix + path, **kw)).body

    # Each checker returns (malicious_score 0..1 or None, one-line summary).
    def _virustotal(self, t: str, v: str):
        path = {"ip": f"/api/v3/ip_addresses/{v}", "domain": f"/api/v3/domains/{v}", "hash": f"/api/v3/files/{v}",
                "url": "/api/v3/urls/" + __import__("base64").urlsafe_b64encode(v.encode()).decode().rstrip("=")}[t]
        st = ((self._q("virustotal", "GET", path).get("data") or {}).get("attributes") or {}).get("last_analysis_stats") or {}
        total = sum(int(x or 0) for x in st.values()) or 1
        mal = int(st.get("malicious", 0)) + int(st.get("suspicious", 0))
        return min(1.0, mal / max(5, total * 0.25)), f"VirusTotal {st.get('malicious', 0)}/{total} engines malicious"

    def _abuseipdb(self, t, v):
        d = self._q("abuseipdb", "GET", "/api/v2/check", params={"ipAddress": v, "maxAgeInDays": 90}).get("data") or {}
        s = int(d.get("abuseConfidenceScore", 0))
        return s / 100.0, f"AbuseIPDB confidence {s}% ({d.get('totalReports', 0)} reports, {d.get('isp')}, tor={d.get('isTor')})"

    def _otx(self, t, v):
        sect = {"ip": "IPv4", "domain": "domain", "url": "url", "hash": "file"}[t]
        pulses = ((self._q("otx", "GET", f"/api/v1/indicators/{sect}/{v}/general").get("pulse_info") or {}).get("count", 0))
        return (min(1.0, pulses / 5), f"OTX in {pulses} pulse(s)") if pulses else (0.0, "OTX: no pulses")

    def _urlhaus(self, t, v):
        body = self._q("urlhaus", "POST", "/v1/url/" if t == "url" else "/v1/host/",
                       data={"url": v} if t == "url" else {"host": v})
        if body.get("query_status") != "ok":
            return 0.0, "URLhaus: no match"
        return 0.9, f"URLhaus: listed ({body.get('threat') or body.get('url_count', '')} {body.get('url_status', '')})".strip()

    def _threatfox(self, t, v):
        body = self._q("threatfox", "POST", "/api/v1/", json={"query": "search_ioc", "search_term": v})
        data = body.get("data") if isinstance(body.get("data"), list) else []
        if not data:
            return 0.0, "ThreatFox: no match"
        return 0.9, f"ThreatFox: {data[0].get('malware_printable')} ({data[0].get('threat_type')})"

    def _malwarebazaar(self, t, v):
        body = self._q("malwarebazaar", "POST", "/api/v1/", data={"query": "get_info", "hash": v})
        data = body.get("data") or []
        if body.get("query_status") != "ok" or not data:
            return 0.0, "MalwareBazaar: unknown hash"
        return 1.0, f"MalwareBazaar: {data[0].get('signature')} ({data[0].get('file_type')})"

    def _greynoise(self, t, v):
        body = self._q("greynoise", "GET", f"/v3/community/{v}")
        cls = body.get("classification")
        return ({"malicious": 0.8, "benign": 0.0}.get(cls, 0.2) if body.get("noise") or body.get("riot") else 0.1,
                f"GreyNoise: {cls or 'unknown'} ({body.get('name', '')})")

    def _shodan(self, t, v):
        body = self._q("shodan", "GET", f"/shodan/host/{v}", params={"key": self.settings.get("shodan_api_key", "")})
        ports = body.get("ports") or []
        return None, f"Shodan: {len(ports)} open port(s) {ports[:8]}, org={body.get('org')}, tags={body.get('tags')}"

    def enrich(self, ioc_type: str, value: str) -> dict[str, Any]:
        results: dict[str, Any] = {}
        for src, meta in SOURCES.items():
            if src not in self.transports or ioc_type not in meta["types"]:
                continue
            fn: Callable = getattr(self, f"_{src}")
            try:
                score, summary = fn(ioc_type, value)
                results[src] = {"ok": True, "score": score, "summary": summary}
            except Exception as exc:
                results[src] = {"ok": False, "error": f"{type(exc).__name__}: {str(exc)[:120]}"}
        scored = [r["score"] for r in results.values() if r.get("ok") and r.get("score") is not None]
        verdict_score = max(scored) if scored else None
        hits = sum(1 for s in scored if s >= 0.5)
        verdict = ("malicious" if verdict_score is not None and verdict_score >= 0.7 and hits >= 1 else
                   "suspicious" if verdict_score is not None and verdict_score >= 0.4 else
                   "unknown" if verdict_score is None else "no_reputation_hits")
        return {"type": ioc_type, "value": value, "verdict": verdict, "score": verdict_score, "sources_hit": hits,
                "sources": results, "unavailable": [s for s, r in results.items() if not r.get("ok")]}

    def lookup(self, entity_type: str, value: str, **context: Any) -> LookupResult:
        def run():
            e = self.enrich(entity_type, value)
            parts = [r["summary"] for r in e["sources"].values() if r.get("ok")]
            res = ok_lookup(self, [], f"{value}: {e['verdict']} ({e['sources_hit']} source(s) flagging) | " + "; ".join(parts),
                            verdict=e["verdict"], score=e["score"], sources_hit=e["sources_hit"])
            if e["unavailable"]:
                res.summary += f" | unavailable: {e['unavailable']}"
            return res
        return self.timed_lookup(run)


def _live_transports(s: dict[str, Any]) -> dict[str, Transport]:
    out = {}
    for src, meta in SOURCES.items():
        key = s.get(meta["key"])
        if key or src in {"urlhaus", "threatfox", "malwarebazaar"} and s.get("abusech_auth_key"):
            out[src] = HttpTransport(meta["base"], meta["auth"](key))
    return out


class _LiveBundle:
    """Adapter so the registry's single-transport contract carries per-source transports."""

    def __init__(self, transports: dict[str, Transport]) -> None:
        self.transports = transports

    def request(self, *a, **kw):  # pragma: no cover - never used directly
        raise RuntimeError("use per-source transports")


def _factory(s: dict[str, Any], t: Any) -> ThreatIntelConnector:
    if isinstance(t, _LiveBundle):
        return ThreatIntelConnector(s, t.transports, rate_per_sec=4, burst=8)
    return ThreatIntelConnector(s, {src: t for src in SOURCES}, rate_per_sec=50, burst=50)


MANIFEST = ConnectorManifest(
    name="threat_intel", tool="Threat intelligence fusion", vendor="multiple", category="intel", dimension="threat_intel",
    description="VirusTotal, AbuseIPDB, OTX, URLhaus, ThreatFox, MalwareBazaar, GreyNoise, Shodan - fused verdict.",
    factory=_factory, live_transport=lambda s: _LiveBundle(_live_transports(s)),
    config=[ConfigField(m["key"], f"{src} API key", secret=True, required=False) for src, m in SOURCES.items()
            if m["key"] != "abusech_auth_key"] + [ConfigField("abusech_auth_key", "abuse.ch Auth-Key (URLhaus/ThreatFox/"
                                                                                  "MalwareBazaar)", secret=True, required=False)],
    confidence="High", to_confirm="client-approved intelligence sources and licensing",
    focus_areas=("phishing", "incident", "vulnerability"),
)
