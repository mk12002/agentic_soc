"""Shadow IT and risky destination analytics (U11).

Umbrella DNS activity is already pulled for incident enrichment; aggregated, it shows which
unsanctioned services people use (file sharing, generative AI, personal VPNs, remote access...) and
which risky destinations were reached or attempted. Rows are aggregated in memory per run and are
not stored (DNS volume is high and the individual rows are personal data).

Sanctioned services come from ``config/sanctioned_services.yaml`` (domains the organisation has
approved, e.g. the corporate file-sharing and AI tools); everything else in a watched category is
reported as unsanctioned.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import yaml

CONFIG = Path(__file__).resolve().parents[2] / "config" / "sanctioned_services.yaml"
WATCHED = {"file storage", "file sharing", "online storage and backup", "generative ai", "personal vpn",
           "proxy/anonymizer", "anonymizer", "remote access", "peer file transfer", "p2p/file sharing", "webmail",
           "cryptocurrency", "cryptomining", "dynamic dns", "url shortener", "pastebin"}
HIGH_RISK_WATCHED = {"personal vpn", "proxy/anonymizer", "anonymizer", "remote access", "peer file transfer",
                     "p2p/file sharing", "cryptomining"}
SECURITY = {"malware", "phishing", "command and control", "cryptomining", "newly seen domains", "dns tunneling vpn",
            "potentially harmful", "dynamic dns", "botnet"}
TWO_LEVEL = {"co.uk", "co.in", "com.au", "co.jp", "com.br", "co.za", "com.sg", "org.uk", "net.in", "gov.in"}


def registrable(domain: str) -> str:
    parts = domain.lower().strip(".").split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in TWO_LEVEL:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain.lower()


def load_sanctioned(path: str | Path | None = None) -> set[str]:
    p = Path(path or CONFIG)
    if not p.is_file():
        return set()
    doc = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    return {registrable(str(d)) for d in doc.get("sanctioned") or []}


def analyse(rows: list[dict[str, Any]], *, sanctioned: set[str] | None = None) -> dict[str, Any]:
    sanctioned = sanctioned if sanctioned is not None else load_sanctioned()
    services: dict[str, dict[str, Any]] = {}
    users_unsanctioned: dict[str, set[str]] = defaultdict(set)
    risky: dict[str, dict[str, Any]] = {}
    cat_counts: Counter[str] = Counter()
    for r in rows:
        dom = str(r.get("domain") or "").lower().rstrip(".")
        if not dom:
            continue
        cats = [str(c.get("label") if isinstance(c, dict) else c) for c in r.get("categories") or []]
        lcats = {c.lower() for c in cats}
        user = next((i.get("label") for i in r.get("identities") or [] if (i.get("type") or {}).get("type") ==
                     "directory_user"), None) or r.get("user")
        host = next((i.get("label") for i in r.get("identities") or [] if (i.get("type") or {}).get("type") in
                     {"roaming", "anyconnect", "network_devices"}), None) or r.get("identity")
        verdict = str(r.get("verdict") or "").lower()
        base = registrable(dom)
        sec = lcats & SECURITY
        if sec:
            d = risky.setdefault(dom, {"domain": dom, "categories": sorted(sec), "allowed": 0, "blocked": 0,
                                       "users": set(), "hosts": set(), "first": r.get("timestamp"), "last": r.get("timestamp")})
            d["allowed" if verdict == "allowed" else "blocked"] += 1
            d["users"].add(user) if user else None
            d["hosts"].add(host) if host else None
            d["last"] = max(str(d["last"] or ""), str(r.get("timestamp") or ""))
            continue
        watched = lcats & WATCHED
        if not watched or base in sanctioned:
            continue
        svc = services.setdefault(base, {"service": base, "categories": set(), "requests": 0, "allowed": 0,
                                         "blocked": 0, "users": set(), "hosts": set()})
        svc["categories"].update(c for c in cats if c.lower() in WATCHED)
        svc["requests"] += 1
        svc["allowed" if verdict == "allowed" else "blocked"] += 1
        if user:
            svc["users"].add(user)
            users_unsanctioned[user].add(base)
        if host:
            svc["hosts"].add(host)
        for c in watched:
            cat_counts[c] += 1

    def risk_of(svc: dict[str, Any]) -> str:
        cats = {c.lower() for c in svc["categories"]}
        if cats & HIGH_RISK_WATCHED and svc["allowed"]:
            return "high"
        if cats & {"generative ai", "file storage", "file sharing", "online storage and backup"} and svc["allowed"]:
            return "medium"  # data-leakage channel
        return "low"

    svc_out = sorted(({**v, "categories": sorted(v["categories"]), "users": len(v["users"]), "hosts": len(v["hosts"]),
                       "user_list": sorted(v["users"])[:20], "risk": risk_of(v)} for v in services.values()),
                     key=lambda x: ({"high": 0, "medium": 1, "low": 2}[x["risk"]], -x["users"], -x["requests"]))
    risky_out = sorted(({**v, "users": sorted(v["users"]), "hosts": sorted(v["hosts"]),
                         "status": "reached" if v["allowed"] else "blocked"} for v in risky.values()),
                       key=lambda x: (x["status"] != "reached", -(x["allowed"] + x["blocked"])))
    return {"rows_analysed": len(rows), "unsanctioned_services": svc_out, "risky_destinations": risky_out,
            "by_category": dict(cat_counts.most_common()),
            "top_users": sorted(({"user": u, "services": sorted(s), "count": len(s)} for u, s in users_unsanctioned.items()),
                                key=lambda x: -x["count"])[:15],
            "summary": {"unsanctioned_services": len(svc_out),
                        "high_risk_services": sum(1 for s in svc_out if s["risk"] == "high"),
                        "risky_destinations_reached": sum(1 for r in risky_out if r["status"] == "reached"),
                        "users_on_unsanctioned_services": len(users_unsanctioned)}}


def shadow_it_report(registry: Any, *, since: str = "-7days", max_rows: int = 50_000) -> dict[str, Any]:
    if "umbrella" not in registry.enabled_names():
        return {"available": False, "reason": "umbrella connector not enabled"}
    rows, truncated = registry.get("umbrella").activity_all(since=since, max_rows=max_rows)
    return {"available": True, "window": since, "truncated": truncated, **analyse(rows)}
