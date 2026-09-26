"""Asset identity resolution at scale on a deliberately messy synthetic estate (R01, VM-F02).

    python scripts/eval_resolution_at_scale.py [n_hosts] [seed]

Ground truth: N real hosts. Each tool sees an overlapping subset with its own IDs and the
realistic defects seen in enterprise inventories:
  * hostname case / FQDN vs short-name drift, occasional "-old"/numeric rename
  * DHCP IP churn between tools, stale last-seen dates beyond the IP window
  * serial missing in some tools; VMware template clones sharing one serial
  * junk MACs (00:00:00...), missing OS strings, CMDB rows with stale IPs
  * coverage gaps (hosts missing from scanners / EDR), decommissioned hosts only in the CMDB
  * look-alike neighbours (web01 / web010 / web01a) to tempt false merges
Metrics: false-merge rate (two real hosts collapsed - the dangerous error), split rate (one real
host left as several entities), unresolved-queue share, deterministic vs probabilistic share.
"""

from __future__ import annotations

import json
import random
import sys
import time
from collections import defaultdict
from datetime import UTC, datetime, timedelta

from soc_platform.core.context_store import ContextStore
from soc_platform.core.db import Database
from soc_platform.core.entity_resolution import EntityResolver
from soc_platform.core.models import SourceRecord, UnresolvedItem
from soc_platform.core.schema import NormalizedRecord

T0 = datetime(2026, 9, 20, tzinfo=UTC)
OSES = ["Windows 11 Enterprise", "Windows Server 2019", "Windows Server 2022", "Ubuntu 22.04 LTS", "RHEL 8.9",
        "macOS 14.5"]


def make_estate(n: int, rnd: random.Random) -> list[dict]:
    hosts = []
    clone_serial = "VMware-42 00 aa bb"
    roles = ["web", "app", "db", "fs", "jump", "lt", "ws", "k8s-node", "dc", "print"]
    used = set()
    for i in range(n):
        role = rnd.choice(roles)
        name = f"{role}{i:03d}"
        # look-alike neighbours: web010 next to web01x
        if rnd.random() < 0.05 and f"{name}a" not in used:
            name = f"{name}a"
        used.add(name)
        is_vm = role not in {"lt", "ws"}
        serial = clone_serial if (is_vm and rnd.random() < 0.08) else f"SN{rnd.randrange(10**9):09d}"
        hosts.append({"gt": i, "name": name, "fqdn": f"{name}.corp.acme.local", "serial": serial,
                      "mac": ":".join(f"{rnd.randrange(256):02x}" for _ in range(6)),
                      "ip": f"10.{rnd.randrange(1, 60)}.{rnd.randrange(256)}.{rnd.randrange(1, 255)}",
                      "os": rnd.choice(OSES[3:5] if role in {"web", "k8s-node"} else OSES),
                      "cloud": rnd.random() < 0.25 and is_vm, "decom": rnd.random() < 0.03})
    return hosts


def observations(hosts: list[dict], rnd: random.Random) -> list[tuple[int, NormalizedRecord]]:
    obs = []

    def rec(tool, sid, keys, attrs, age_days=0.0):
        return NormalizedRecord(kind="asset", tool=tool, source_type="asset", source_id=sid, keys=keys, attributes=attrs,
                                observed_at=T0 - timedelta(days=age_days))

    for h in hosts:
        drift_ip = lambda h=h: h["ip"] if rnd.random() < 0.75 else f"10.99.{rnd.randrange(256)}.{rnd.randrange(1, 255)}"
        name_case = lambda h=h: rnd.choice([h["name"], h["name"].upper(), h["fqdn"], h["fqdn"].upper()])
        os_ = lambda h=h: h["os"] if rnd.random() < 0.9 else None
        if h["decom"]:
            obs.append((h["gt"], rec("servicenow", f"ci-{h['gt']}", {"serial_number": h["serial"]},
                                     {"hostname": h["name"], "fqdn": h["fqdn"], "ip": h["ip"], "os": h["os"]}, 60)))
            continue
        if rnd.random() < 0.9:   # CrowdStrike: strong agent id, serial usually, MAC sometimes junk
            obs.append((h["gt"], rec("crowdstrike", f"cs-{h['gt']}",
                                     {"crowdstrike_aid": f"aid{h['gt']:06d}",
                                      "serial_number": h["serial"] if rnd.random() < 0.85 else None,
                                      "mac": h["mac"] if rnd.random() < 0.8 else "00:00:00:00:00:00"},
                                     {"hostname": name_case(), "ip": drift_ip(), "os": os_()}, rnd.random() * 2)))
        if rnd.random() < 0.85:  # Defender: device id, FQDN, no serial
            obs.append((h["gt"], rec("defender_endpoint", f"mde-{h['gt']}", {"mde_device_id": f"mde{h['gt']:06d}"},
                                     {"hostname": h["name"], "fqdn": h["fqdn"], "ip": drift_ip(), "os": os_()},
                                     rnd.random() * 2)))
        if rnd.random() < 0.8:   # Rapid7: its own id, FQDN or IP only, sometimes stale
            stale = rnd.random() < 0.1
            obs.append((h["gt"], rec("rapid7", f"r7-{h['gt']}", {"rapid7_asset_id": str(10000 + h["gt"]),
                                                                 "mac": h["mac"] if rnd.random() < 0.5 else None},
                                     {"hostname": h["fqdn"] if rnd.random() < 0.7 else None, "ip": drift_ip(),
                                      "os": os_()}, 10 if stale else rnd.random() * 3)))
        if h["cloud"]:           # Wiz: cloud resource id + name
            obs.append((h["gt"], rec("wiz", f"wiz-{h['gt']}", {"wiz_id": f"wiz{h['gt']}",
                                                              "cloud_resource_id": f"/subscriptions/s/vm/{h['name']}"},
                                     {"hostname": h["name"], "ip": h["ip"], "os": "Linux" if "Ubuntu" in h["os"]
                                      or "RHEL" in h["os"] else h["os"]}, rnd.random())))
        if rnd.random() < 0.9:   # CMDB: serial + names, IP may be stale
            obs.append((h["gt"], rec("servicenow", f"ci-{h['gt']}", {"serial_number": h["serial"]},
                                     {"hostname": h["name"].upper(), "fqdn": h["fqdn"],
                                      "ip": h["ip"] if rnd.random() < 0.6 else "10.250.0.1", "os": h["os"]},
                                     rnd.random() * 5)))
    rnd.shuffle(obs)
    return obs


def evaluate(n: int = 400, seed: int = 7) -> dict:
    rnd = random.Random(seed)
    hosts = make_estate(n, rnd)
    obs = observations(hosts, rnd)
    db = Database("sqlite://")
    db.create_all()
    t = time.perf_counter()
    with db.session() as s:
        store = ContextStore(s)
        gt_of: dict[str, int] = {}
        for gt, rec in obs:
            src = store.ingest(rec)
            gt_of[src.id] = gt
        elapsed = time.perf_counter() - t
        entity_to_gts: dict[str, set[int]] = defaultdict(set)
        gt_to_entities: dict[int, set[str]] = defaultdict(set)
        unresolved = 0
        for sr in s.query(SourceRecord).filter(SourceRecord.kind == "asset"):
            gt = gt_of[sr.id]
            if sr.entity_id is None:
                unresolved += 1
                continue
            entity_to_gts[sr.entity_id].add(gt)
            gt_to_entities[gt].add(sr.entity_id)
        false_merge_entities = [e for e, g in entity_to_gts.items() if len(g) > 1]
        hosts_in_false_merge = sum(len(entity_to_gts[e]) for e in false_merge_entities)
        split_hosts = [g for g, es in gt_to_entities.items() if len(es) > 1]
        rate = EntityResolver(s).match_rate("asset")
        queue = s.query(UnresolvedItem).filter(UnresolvedItem.status == "open").count()
        return {
            "real_hosts": n, "observations": len(obs), "canonical_entities": len(entity_to_gts),
            "false_merges": len(false_merge_entities), "hosts_affected_by_false_merge": hosts_in_false_merge,
            "false_merge_host_rate": round(hosts_in_false_merge / n, 4),
            "split_hosts": len(split_hosts), "split_rate": round(len(split_hosts) / n, 4),
            "unresolved_records": unresolved, "unresolved_rate": round(unresolved / len(obs), 4),
            "open_review_queue": queue, "match_rate": rate["match_rate"], "by_method": rate["by_method"],
            "ingest_seconds": round(elapsed, 2), "records_per_second": round(len(obs) / elapsed, 1),
            "false_merge_examples": [sorted(entity_to_gts[e]) for e in false_merge_entities[:5]],
        }


if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 400
    seed = int(sys.argv[2]) if len(sys.argv) > 2 else 7
    print(json.dumps(evaluate(n, seed), indent=1))
