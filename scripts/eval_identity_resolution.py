"""User identity resolution across sources at scale (U07, IM-T03): never merge two people.

    python scripts/eval_identity_resolution.py [n_users] [seed]

Each tool names people its own way - exactly the connector code paths (``core.identity.user_ref``):
  Entra        objectId + UPN + mail + SAM + proxyAddresses/otherMails (cloud-only users: no SAM)
  CrowdStrike  ``CORP\\sam``          Defender   relatedUser {userName: sam, domainName: CORP}
  Delinea      ``CORP\\sam``          Canary     bare ``sam``
  Umbrella     UPN or an alias        Email      recipient = primary address or alias
Defects: SAM != UPN prefix (30%), renamed users whose *old* address appears in older events (5%),
display-name collisions (distinct people named alike), external contractors, built-in accounts
(SYSTEM, www-data, HOST$) that must never become people, and random arrival order (alerts often
arrive before the directory record).
"""

from __future__ import annotations

import json
import random
import sys
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from soc_platform.core.context_store import ContextStore
from soc_platform.core.db import Database
from soc_platform.core.identity import user_ref
from soc_platform.core.models import Entity, EntityKey, SourceRecord
from soc_platform.core.schema import EntityRef, NormalizedRecord

T0 = datetime(2026, 9, 20, tzinfo=timezone.utc)
FIRST = ["jane", "john", "priya", "arun", "meera", "tom", "li", "sara", "ravi", "anil", "sunita", "rahul", "neha",
         "vikram", "maria", "david", "omar", "fatima", "chen", "yuki"]
LAST = ["doe", "smith", "nair", "kumar", "shah", "white", "chen", "iyer", "rao", "mehta", "patel", "singh",
        "khan", "gupta", "das", "roy", "bose", "jain", "verma", "sethi"]
DOM, NETBIOS = "corp.acme.com", "CORP"


def people(n: int, rnd: random.Random) -> list[dict]:
    out, used_upn, used_sam = [], set(), set()
    while len(out) < n:
        f, l = rnd.choice(FIRST), rnd.choice(LAST)
        upn = f"{f}.{l}@{DOM}"
        k = 2
        while upn in used_upn:
            upn = f"{f}.{l}{k}@{DOM}"
            k += 1
        used_upn.add(upn)
        sam = upn.split("@")[0] if rnd.random() > 0.3 else f"{f[0]}{l}"
        k = 2
        base = sam
        while sam in used_sam:
            sam = f"{base}{k}"
            k += 1
        used_sam.add(sam)
        cloud_only = rnd.random() < 0.08
        alias = f"{f}@{DOM}" if rnd.random() < 0.3 and f"{f}@{DOM}" not in used_upn else None
        if alias:
            used_upn.add(alias)
        renamed_from = f"{f}.old{l}{len(out)}@{DOM}" if rnd.random() < 0.05 else None  # addresses are unique
        out.append({"gt": len(out), "upn": upn, "sam": None if cloud_only else sam, "oid": f"oid-{len(out):05d}",
                    "name": f"{f.title()} {l.title()}", "alias": alias, "renamed_from": renamed_from})
    return out


def observations(ps: list[dict], rnd: random.Random) -> list[tuple[int | None, NormalizedRecord]]:
    obs: list[tuple[int | None, NormalizedRecord]] = []
    n = 0

    def event(gt, tool, ref: EntityRef | None, kind="alert"):
        nonlocal n
        n += 1
        if ref is None:
            return
        obs.append((gt, NormalizedRecord(kind=kind, tool=tool, source_type="evt", source_id=f"{tool}-{n}",
                                         observed_at=T0 - timedelta(hours=rnd.random() * 48), refs=[ref])))

    for p in ps:
        proxies = [f"SMTP:{p['upn']}"] + ([f"smtp:{p['alias']}"] if p["alias"] else []) + \
                  ([f"smtp:{p['renamed_from']}"] if p["renamed_from"] else [])
        obs.append((p["gt"], NormalizedRecord(
            kind="identity", tool="entra", source_type="user", source_id=p["oid"], observed_at=T0,
            keys={"entra_object_id": p["oid"], "upn": p["upn"], "email": p["upn"], "sam": p["sam"]},
            attributes={"display_name": p["name"], "email_aliases": [x.split(":", 1)[1].lower() for x in proxies]})))
        sam = p["sam"] or p["upn"].split("@")[0]
        if rnd.random() < 0.5:
            event(p["gt"], "crowdstrike", user_ref(f"{NETBIOS}\\{sam}" if p["sam"] else p["upn"], default_domain=DOM))
        if rnd.random() < 0.5:
            event(p["gt"], "defender_endpoint", user_ref(f"{NETBIOS}\\{sam}" if p["sam"] else p["upn"], default_domain=DOM))
        if rnd.random() < 0.3 and p["sam"]:
            event(p["gt"], "delinea", user_ref(f"{NETBIOS}\\{p['sam']}", default_domain=DOM), kind="secret_access")
        if rnd.random() < 0.1 and p["sam"]:
            event(p["gt"], "canary", user_ref(p["sam"], default_domain=DOM), kind="deception")
        if rnd.random() < 0.6:
            addr = p["alias"] if p["alias"] and rnd.random() < 0.5 else (p["renamed_from"] or p["upn"])
            event(p["gt"], "umbrella", user_ref(addr), kind="dns")
        if rnd.random() < 0.6:
            addr = p["alias"] if p["alias"] and rnd.random() < 0.5 else p["upn"]
            event(p["gt"], "email", user_ref(addr, role="recipient"), kind="email")
    for i in range(40):  # built-in accounts in alerts: must NOT become people
        event(None, "crowdstrike", user_ref(rnd.choice(["NT AUTHORITY\\SYSTEM", "www-data", "root", "WEB01$",
                                                        "NT AUTHORITY\\NETWORK SERVICE", "Window Manager\\DWM-1"])))
    for i in range(20):  # external contractors / partners: distinct people
        event(-1000 - i, "email", user_ref(f"partner{i}@supplier{i % 3}.example", role="sender"), kind="email")
    rnd.shuffle(obs)
    return obs


def evaluate(n: int = 300, seed: int = 5) -> dict:
    rnd = random.Random(seed)
    ps = people(n, rnd)
    obs = observations(ps, rnd)
    db = Database("sqlite://")
    db.create_all()
    with db.session() as s:
        store = ContextStore(s)
        event_gt: dict[str, int] = {}
        for gt, rec in obs:
            src = store.ingest(rec)
            if rec.kind != "identity":
                event_gt[src.entity_id] = gt
            else:
                event_gt[("id", src.id)] = gt
        ent_people: dict[str, set[int]] = defaultdict(set)
        person_ents: dict[int, set[str]] = defaultdict(set)
        # Entra directory records
        for sr in s.query(SourceRecord).filter(SourceRecord.tool == "entra"):
            gt = event_gt[("id", sr.id)]
            if sr.entity_id:
                ent_people[sr.entity_id].add(gt)
                person_ents[gt].add(sr.entity_id)
        # event references
        for ev_id, gt in list(event_gt.items()):
            if isinstance(ev_id, tuple) or gt is None:
                continue
            for _, ent in store.neighbors(ev_id, kinds={"identity"}):
                ent_people[ent.id].add(gt)
                person_ents[gt].add(ent.id)
        phantom_builtin = s.query(EntityKey).filter(EntityKey.kind == "identity", EntityKey.key_name == "sam",
                                                    EntityKey.key_value.in_(["system", "www-data", "root", "web01$"])).count()
        false_merges = [sorted(g) for g in ent_people.values() if len({x for x in g if x is not None}) > 1]
        real = [p["gt"] for p in ps]
        split = [g for g in real if len(person_ents[g]) > 1]
        return {"people": n, "observations": len(obs),
                "identity_entities": s.query(Entity).filter(Entity.kind == "identity").count(),
                "false_merges": len(false_merges), "false_merge_examples": false_merges[:5],
                "split_people": len(split), "split_rate": round(len(split) / n, 4),
                "phantom_builtin_identities": phantom_builtin}


if __name__ == "__main__":
    print(json.dumps(evaluate(int(sys.argv[1]) if len(sys.argv) > 1 else 300,
                              int(sys.argv[2]) if len(sys.argv) > 2 else 5), indent=1))
