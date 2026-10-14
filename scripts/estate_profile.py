"""Profile an estate through the connectors' own parsers: event records, how many are suspicious, replays.

    python scripts/estate_profile.py FIXTURES_DIR ORG_DOMAIN

Every enabled connector stream is read page by page (fake mode, the estate's fixtures) and normalised exactly as a sync
would. Activity events are alerts, deception hits, sign-ins, DNS queries, e-mail events, secret access and elevation
(inventory such as vulnerability findings and tickets is neither benign nor suspicious and is not counted). An event is
suspicious when it is a security signal: any alert or deception hit, a reported e-mail or e-mail security event, a risky
sign-in, a DNS query in a security category (allowed or blocked), denied elevation, or secret access rated medium+. Used by the data handoff tests (the workbook asks for >= 1,000 events with an 80-95 % benign share).
"""

from __future__ import annotations

import json
import os
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ACTIVITY = {"alert", "deception", "signin", "dns", "email", "mail_event", "click", "secret_access", "elevation"}


def _suspicious(rec, raw: dict) -> bool:
    a, sev = rec.attributes or {}, str(rec.severity or "").lower()
    if rec.kind in {"alert", "deception", "email", "mail_event", "click"}:
        return True
    if rec.kind == "signin":
        return str(a.get("risk_level") or "none").lower() in {"low", "medium", "high"}
    if rec.kind == "dns":
        return any(isinstance(c, dict) and c.get("type") == "security" for c in raw.get("categories") or [])
    if rec.kind == "elevation":
        return str(a.get("outcome") or "").lower() in {"denied", "blocked"}
    return sev in {"medium", "high", "critical"}


def profile(fixtures_dir: str, org: str) -> dict:
    os.environ["SOC_FIXTURES_DIR"], os.environ["SOC_ORG_DOMAINS"] = fixtures_dir, org
    sys.path.insert(0, str(ROOT))
    from soc_platform.config import get_settings
    from soc_platform.connectors.registry import ConnectorRegistry

    get_settings.cache_clear()
    reg = ConnectorRegistry.all_fake()
    events = suspicious = 0
    seen: Counter = Counter()
    by_stream: dict[str, int] = {}
    for name in sorted(reg.enabled_names()):
        conn = reg.get(name)
        for stream in conn.streams:
            cursor, n = None, 0
            for _ in range(200):
                page = conn.fetch_page(stream, cursor)
                for raw in page.records:
                    for rec in conn.normalize(stream, raw):
                        if rec.kind not in ACTIVITY:
                            continue
                        n += 1
                        seen[(rec.tool, rec.source_type, rec.source_id)] += 1
                        if _suspicious(rec, raw):
                            suspicious += 1
                if not page.more:
                    break
                cursor = page.next_cursor
            if n:
                by_stream[f"{name}.{stream}"] = n
            events += n
    replays = sum(c - 1 for c in seen.values() if c > 1)
    return {"events": events, "suspicious": suspicious, "benign_share": round(1 - suspicious / events, 4) if events else 0,
            "replayed_records": replays, "replay_share": round(replays / events, 4) if events else 0, "by_stream": by_stream}


if __name__ == "__main__":
    print(json.dumps(profile(sys.argv[1], sys.argv[2]), indent=1))
