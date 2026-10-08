"""Record-and-sanitise: turn the first live responses from a client's tools into new test fixtures.

Enabled only on purpose (``SOC_RECORD_FIXTURES_DIR``): every live connector's transport is wrapped, and each response
is written - sanitised - in the fixture format ``FixtureTransport`` replays (``<dir>/<connector>.json``). The demo
fixtures are built from vendor documentation; recordings show the shapes, optional fields, volumes and oddities of the
client's real tenant, so a connector fix can be tested against them without the tenant.

What leaves the client environment must not identify anyone or anything, so sanitising is deliberate and stable:

* secrets never reach a recording: request headers (Authorization, API keys) are not recorded at all, and any field
  whose name says token / secret / password / key / cookie is dropped
* people, hosts and organisations become stable pseudonyms: e-mail addresses (user@domain -> user-3f2a@org-91c0.example),
  host names and FQDNs, display / user / account names, and the client's own domains
* internal (RFC 1918) addresses map to stable addresses in 10.250.0.0/16; public addresses map into 198.18.0.0/15
  (the benchmarking range) - the same input always gives the same output, so cross-references survive
* identifiers (GUIDs, long hex / numeric ids) are replaced by keyed hashes of the same shape
* free text (subjects, descriptions, comments, command lines, bodies) is replaced by "[text, N chars]"
* URLs keep their scheme and path shape; host and query values are pseudonymised

The mapping is keyed with ``SOC_RECORD_SALT`` (generate one per recording; never commit it) and is never written, so
a recording cannot be turned back into the original values. Each run ends with a scan report (``_scan.json``) listing
anything that still looks like an e-mail address or IP, for review before a recording leaves the client.
Structure, enum values, severities, timestamps and counts are kept: they are what the tests need.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import logging
import os
import re
import threading
from pathlib import Path
from typing import Any

from soc_platform.connectors.http import Response

log = logging.getLogger(__name__)

SECRET_FIELD = re.compile(r"(token|secret|password|passwd|api[_-]?key|apikey|cookie|credential|authorization|signature)",
                          re.IGNORECASE)
EMAIL = re.compile(r"(?<![\w.+-])([\w.+-]{1,64})@([\w-]{1,63}(?:\.[\w-]{1,63}){1,8})\b")
IPV4 = re.compile(r"(?<![\d.])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?![\d.])")
GUID = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")
LONG_HEX = re.compile(r"\b[0-9a-fA-F]{16,}\b")
# a field naming a person, account or machine - matched anywhere in the key (byUserName, onPremisesSamAccountName,
# friendlyName, netBiosName, owned_by, assigned_to ...)
NAME_FIELD = re.compile(r"(name|user|account|sam$|upn$|owner|owned|host|computer|device|machine|netbios|fqdn|friendly|"
                        r"principal|assign|manager|requester|caller|label)", re.IGNORECASE)
DOMAIN_FIELD = re.compile(r"(dns_?domain|upn_?suffix|domain_?name$|nt_?domain|^domain$)", re.IGNORECASE)
ID_FIELD = re.compile(r"(^id$|id$|_id$|^sys_id$)", re.IGNORECASE)
WRAPPER_KEYS = {"value", "display_value", "displayvalue", "link"}       # ServiceNow {value, display_value} fields
TEXT_FIELD = re.compile(r"(subject|description|comment|body|message|command_?line|cmdline|summary|notes?|details?|"
                        r"text|reason|justification|preview)$", re.IGNORECASE)
KEEP_FIELD = re.compile(r"(severity|status|state|verdict|category|categories|type|kind|risk|level|classification|"
                        r"determination|tactic|technique|action|outcome|result|platform|os|version|priority|"
                        r"protocol|querytype|direction|enabled|count|total|score|time|date|_at$|timestamp|"
                        r"mitre|cve|cvss|epss|kev)", re.IGNORECASE)
HASHES = re.compile(r"^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$")       # file hashes are evidence: kept


class Sanitizer:
    def __init__(self, salt: str, org_domains: list[str] | None = None) -> None:
        if len(salt) < 16:
            raise ValueError("SOC_RECORD_SALT must be at least 16 characters (generate one per recording)")
        self.key = salt.encode()
        self.org = {d.lower() for d in (org_domains or []) if d}
        alts = "|".join(re.escape(d) for d in sorted(self.org, key=len, reverse=True))
        # any name under the client's own domains, wherever it appears (host.corp.example, corp.example)
        self.org_names = re.compile(rf"\b(?:([\w-]+)\.)?((?:[\w-]+\.)*(?:{alts}))\b", re.IGNORECASE) if alts else None

    def _h(self, kind: str, value: str, n: int = 6) -> str:
        return hmac.new(self.key, f"{kind}|{value.lower()}".encode(), hashlib.sha256).hexdigest()[:n]

    def email(self, local: str, domain: str) -> str:
        return f"user-{self._h('user', local + '@' + domain)}@{self.domain(domain)}"

    def domain(self, d: str) -> str:
        d = d.lower()
        if any(d == o or d.endswith("." + o) for o in self.org):
            return f"org-{self._h('org', d, 4)}.example"
        return d                                    # external domains are indicators (evidence): kept

    def host(self, h: str) -> str:
        short = h.split(".")[0]
        out = f"host-{self._h('host', short)}"
        return out.upper() if short.isupper() else out

    def ip(self, value: str) -> str:
        try:
            addr = ipaddress.ip_address(value)
        except ValueError:
            return value
        if addr.is_loopback or addr.is_unspecified:
            return value
        n = int(self._h("ip", value, 8), 16)
        if addr.is_private:
            return f"10.250.{(n >> 8) & 255}.{n & 255}"
        return f"198.{18 + ((n >> 16) & 1)}.{(n >> 8) & 255}.{n & 255}"

    def ident(self, value: str) -> str:
        if GUID.fullmatch(value):
            h = self._h("guid", value, 32)
            return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"
        return self._h("id", value, len(value))

    def text(self, value: str) -> str:
        """Identifying fragments inside any string: addresses, the client's own host and domain names, IPs, GUIDs,
        long hex ids."""
        value = EMAIL.sub(lambda m: self.email(m.group(1), m.group(2)), value)
        if self.org_names is not None:
            value = self.org_names.sub(lambda m: (self.host(m.group(1)) + "." if m.group(1) else "") + self.domain(m.group(2)),
                                       value)
        value = IPV4.sub(lambda m: self.ip(m.group(1)), value)
        value = GUID.sub(lambda m: self.ident(m.group(0)), value)
        return LONG_HEX.sub(lambda m: m.group(0) if HASHES.match(m.group(0)) else self.ident(m.group(0)), value)

    def value(self, key: str, v: Any, parent: str = "") -> Any:
        if isinstance(v, dict):
            return {k: self.value(k, x, key) for k, x in v.items() if not SECRET_FIELD.search(str(k))}
        if isinstance(v, list):
            return [self.value(key, x, parent) for x in v]
        if not isinstance(v, str) or not v:
            return v
        if str(key).lower() in WRAPPER_KEYS and parent:
            key, parent = parent, ""                  # a wrapped field is classified by its own name
        k = str(key)
        if GUID.fullmatch(v) or (len(v) >= 16 and LONG_HEX.fullmatch(v) and not HASHES.match(v)):
            return self.ident(v)                      # the same pseudonym as in URL paths: cross-references survive
        if (KEEP_FIELD.search(k) and not NAME_FIELD.search(k)) or (KEEP_FIELD.search(parent) and not NAME_FIELD.search(parent)):
            # vendor vocabulary (severities, categories {"label": "Phishing"}, states): what tests need, kept
            return self.text(v) if ("@" in v or IPV4.search(v)) else v
        if k.lower() == "title":                      # detection names: kept, but no address or IP inside survives
            return self.text(v)
        if DOMAIN_FIELD.search(k):
            return self.domain(v) if "." in v else f"DOM-{self._h('dom', v, 4)}"
        if ID_FIELD.search(k) and not v.isdigit():    # vendor ids that are not GUIDs (u-jane-0001): same shape, hashed
            return self.ident(v)
        if TEXT_FIELD.search(k) and len(v) > 24:
            return f"[text, {len(v)} chars]"
        if NAME_FIELD.search(k):
            if "@" in v:
                return self.text(v)
            if "\\" in v:                              # DOMAIN\\user
                dom, _, user = v.partition("\\")
                return f"DOM-{self._h('dom', dom, 4)}\\user-{self._h('user', user)}"
            return self.host(v) if re.fullmatch(r"[A-Za-z0-9._-]+", v) else f"name-{self._h('name', v)}"
        if v.startswith(("http://", "https://")):
            m = re.match(r"(https?://)([^/?#]+)([^?#]*)(\?[^#]*)?", v)
            if m:
                host = m.group(2)
                host = self.domain(host) if not IPV4.fullmatch(host) else self.ip(host)
                q = re.sub(r"=([^&]*)", lambda x: "=" + self._h("q", x.group(1)), m.group(4) or "")
                return f"{m.group(1)}{host}{self.text(m.group(3))}{q}"
        if IPV4.fullmatch(v):
            return self.ip(v)
        return self.text(v)

    def body(self, b: Any) -> Any:
        return self.value("", b)

    def path(self, p: str) -> str:
        return self.text(p)


# (GUIDs are not listed: every one is replaced by value, and pseudonyms keep the GUID shape)
LEFTOVER = [("e-mail address", EMAIL), ("IPv4 address", IPV4)]


def scan(obj: Any) -> list[str]:
    """What still looks identifying after sanitising (pseudonyms themselves excluded) - for human review."""
    text = json.dumps(obj, ensure_ascii=False)
    out = []
    for label, rx in LEFTOVER:
        for m in rx.finditer(text):
            s = m.group(0)
            if s.endswith(".example") or s.startswith(("10.250.", "198.18.", "198.19.", "127.", "0.")):
                continue
            out.append(f"{label}: {s}")
    return sorted(set(out))[:200]


class RecordingTransport:
    """Wraps a live transport: answers exactly as the wrapped one, and appends each sanitised exchange to the
    recording. The recorded routes replay in order (``times: 1``; the last answer for a path repeats)."""

    def __init__(self, inner: Any, tool: str, out_dir: str | Path, sanitizer: Sanitizer, *, max_calls: int = 200) -> None:
        self.inner, self.tool, self.sanitizer, self.max_calls = inner, tool, sanitizer, max_calls
        self.file = Path(out_dir) / f"{tool}.json"
        self.routes: list[dict[str, Any]] = []
        self._lock = threading.Lock()

    def request(self, method: str, path: str, **kw: Any) -> Response:
        resp = self.inner.request(method, path, **kw)
        with self._lock:
            if len(self.routes) < self.max_calls:
                try:
                    clean = self.sanitizer.path(re.sub(r"^https?://[^/]+", "", path).split("?")[0])
                    # the last three segments: a path's leading part carries configuration (subscription, workspace,
                    # mailbox) that differs where the recording is replayed
                    tail = "/" + "/".join([s for s in clean.split("/") if s][-3:])
                    self.routes.append({"method": method.upper(), "path": re.escape(tail) + "$",
                                        "status": resp.status, "times": 1, "body": self.sanitizer.body(resp.body)})
                    self._write()
                except Exception:
                    log.exception("recording %s failed for one response; the call itself succeeded", self.tool)
        return resp

    def reauthenticate(self) -> None:
        fn = getattr(self.inner, "reauthenticate", None)
        if fn is not None:
            fn()

    def _write(self) -> None:
        routes = [dict(r) for r in self.routes]
        last_by_path: dict[tuple[str, str], int] = {}
        for i, r in enumerate(routes):
            last_by_path[(r["method"], r["path"])] = i
        for i in last_by_path.values():                  # the final answer for a path repeats on replay
            routes[i].pop("times", None)
        self.file.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.file.with_suffix(".tmp")
        tmp.write_text(json.dumps({"routes": routes, "_recorded": {"tool": self.tool, "calls": len(routes),
                                                                   "sanitised": True}}, indent=1), encoding="utf-8")
        tmp.replace(self.file)
        (self.file.parent / "_scan.json").write_text(json.dumps(
            {**_read_scan(self.file.parent), self.tool: scan(routes)}, indent=1), encoding="utf-8")


def _read_scan(folder: Path) -> dict[str, Any]:
    f = folder / "_scan.json"
    try:
        return json.loads(f.read_text(encoding="utf-8")) if f.exists() else {}
    except (OSError, ValueError):
        return {}


def recording_salt() -> str:
    """SOC_RECORD_SALT, or one derived from the platform's encryption key (SOC_DATA_KEY, mandatory in production) so
    the Recording stage needs no extra secret; empty when neither is set (recording is then refused, with the reason)."""
    import hashlib

    from soc_platform.config import secret

    own = os.environ.get("SOC_RECORD_SALT", "")
    if own:
        return own
    key = (secret("SOC_DATA_KEY") or "").split(",")[0].strip()
    return hashlib.sha256(f"soc-record-salt:{key}".encode()).hexdigest() if key else ""


def wrap_for_recording(transport: Any, tool: str, out_dir: str | None = None) -> Any:
    """Called for live connectors: wraps the transport when the connector is in the ``record`` stage (``out_dir``) or
    SOC_RECORD_FIXTURES_DIR is set for every live tool; otherwise returns it unchanged."""
    out = out_dir or os.environ.get("SOC_RECORD_FIXTURES_DIR")
    if not out:
        return transport
    salt = recording_salt()
    orgs = [d.strip() for d in os.environ.get("SOC_ORG_DOMAINS", "").split(",") if d.strip()]
    log.warning("recording sanitised responses of %s to %s (SOC_RECORD_FIXTURES_DIR is set)", tool, out)
    return RecordingTransport(transport, tool, out, Sanitizer(salt, orgs),
                              max_calls=int(os.environ.get("SOC_RECORD_MAX_CALLS", "200") or 200))
