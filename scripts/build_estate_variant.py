"""Generate a seeded variant of the sample estate: a different organisation with different volumes.

    python scripts/build_estate_variant.py OUT_DIR [--seed 7] [--scale 1.0]

What changes per seed (so tests on several seeds prove nothing depends on one data set):

* organisation name, domain, NetBIOS name, tenant settings; supplier names and domains
* every person (first/last names), every machine name (a different naming scheme), the internal IP plan
* phishing / attacker infrastructure, the privileged secret and the honeypot share names
* **volumes**: extra staff (directory users with groups and methods), extra laptops - some with CrowdStrike, some
  with Defender, some with both, some with no EDR at all and some missing from the CMDB - extra vulnerable
  machines, a larger phishing campaign, more shadow-IT activity and extra benign / bulk emails

The attack storyline stays the one the built-in estate models; everything around it varies. Output:
``fixtures/`` (+ ``settings.json``), ``corpus/`` (+ ``labels.json``), ``suppliers.yaml``, ``estate.json``.
"""

from __future__ import annotations

import argparse
import base64
import copy
import importlib.util
import json
import random
import re
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"

FIRST = ["Aisha", "Mateo", "Hannah", "Ravi", "Chloe", "Kwame", "Elif", "Tomasz", "Yuki", "Ingrid", "Diego", "Leila", "Oscar",
         "Mei", "Samir", "Freya", "Jonah", "Anika", "Luca", "Zara", "Ethan", "Noor", "Felix", "Ama", "Sven", "Rosa", "Idris",
         "Clara", "Hugo", "Tara", "Nikhil", "Esme", "Kofi", "Lina", "Marco", "Signe", "Tobias", "Valeria", "Wen", "Yara"]
LAST = ["Okafor", "Lindqvist", "Moreau", "Castillo", "Nakamura", "Petrov", "Haddad", "Fischer", "Adeyemi", "Kowalski",
        "Brennan", "Varga", "Oyelaran", "Duarte", "Sato", "Novak", "Achebe", "Bergstrom", "Rahman", "Costa", "Ibarra",
        "Mensah", "Holm", "Quintero", "Abara", "Keller", "Rinaldi", "Sorensen", "Tanaka", "Yilmaz", "Farouk", "Laine",
        "Oduya", "Pereira", "Schultz", "Vance", "Whitaker", "Zhou", "Amari", "Delgado"]
ORGS = [("Harbourline Logistics", "harbourline-demo.net", "HBL"), ("Veridian Foods", "veridianfoods-demo.com", "VRF"),
        ("Kestrel Energy", "kestrel-energy-demo.io", "KES"), ("Brightwater Health", "brightwater-demo.org", "BWH"),
        ("Solano Retail Group", "solano-retail-demo.com", "SRG"), ("Tidewell Insurance", "tidewell-demo.co", "TWI")]
LOOKALIKE = ["micr0soft-servicedesk.net", "m1crosoft-accountteam.com", "microsfot-passwordhelp.com", "mlcrosoft-idverify.net"]
QR_INFRA = [("staff-benefits.salary-review.help", "salary-review.help"), ("hr-portal.bonus-confirm.info", "bonus-confirm.info")]
TOR = ["45.155.205.99", "185.107.56.14", "193.189.100.201", "171.25.193.78"]
SUPPLIERS = [("Meridian Freight", "meridian-freight.com"), ("Pinecrest Industrial", "pinecrest-industrial.com"),
             ("Silverline Components", "silverline-components.com"), ("Brixton Packaging", "brixton-packaging.co")]
SECOND_SUPPLIERS = [("Atlas Cargo Group", "atlas-cargo-group.com"), ("Northgate Chemicals", "northgate-chemicals.com")]
ERP = ["Oracle-ERP-Payroll-Admin", "Workday-Prod-Integration", "Dynamics-Finance-Service", "NetSuite-Prod-Treasury"]
DEPTS = [("Operations", "Operations Coordinator"), ("Finance", "Financial Analyst"), ("Sales", "Account Executive"),
         ("Engineering", "Software Engineer"), ("HR", "People Partner"), ("Legal", "Paralegal"), ("Marketing", "Campaign Manager"),
         ("Procurement", "Buyer"), ("IT", "Service Desk Analyst"), ("Customer Care", "Support Specialist")]
SHADOW = [("dropbox.com", [{"label": "File Storage", "type": "content"}]),
          ("chatgpt.com", [{"label": "Generative AI", "type": "application"}]),
          ("teamviewer.com", [{"label": "Remote Access", "type": "content"}]),
          ("protonvpn.com", [{"label": "Personal VPN", "type": "content"}]),
          ("gofile.io", [{"label": "File Storage", "type": "content"}]),
          ("perplexity.ai", [{"label": "Generative AI", "type": "application"}])]


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def mapping_for(seed: int) -> tuple[list[tuple[str, str]], dict]:
    rng = random.Random(seed)
    org_name, dom, nb = ORGS[seed % len(ORGS)]
    slug = dom.split(".")[0]
    firsts, lasts = rng.sample(FIRST, 12), rng.sample(LAST, 12)
    people = {"jane": 0, "bob": 1, "priya": 2, "raj": 3, "arun": 4, "meera": 5, "tom": 6, "li": 7, "sunita": 8, "anil": 9}
    lastn = {"doe": 0, "lee": 1, "nair": 2, "mehta": 3, "chen": 7, "iyer": 8, "rao": 9}
    first = {k: firsts[i].lower() for k, i in people.items()}
    last = {k: lasts[i].lower() for k, i in lastn.items()}
    style = seed % 3                                     # three different machine naming schemes

    def laptop(n: int, who: str) -> str:
        return [f"{nb}-NB-{n:04d}", f"{first[who].upper()}-{nb}-L{n % 100:02d}", f"LT{n:05d}-{nb}"][style]

    hosts = {"JANE-LT01": laptop(412, "jane"), "BOB-LT02": laptop(377, "bob"), "PRIYA-LT07": laptop(233, "priya"),
             "ARUN-LT05": laptop(519, "arun"), "MEERA-LT06": laptop(611, "meera"), "TOM-LT07": laptop(702, "tom"),
             "LI-DEV08": laptop(588, "li")}
    servers = {"web01": ["web", "portal", "shop"][style] + f"{rng.randint(2, 9):02d}",
               "db01": ["sql", "pgdb", "ora"][style] + f"{rng.randint(2, 9):02d}",
               "fs01": ["files", "nas", "share"][style] + f"{rng.randint(2, 9):02d}"}
    a, b, c = rng.randint(16, 60), rng.randint(1, 250), rng.randint(61, 120)
    supplier, supplier_dom = rng.choice(SUPPLIERS)
    second, second_dom = rng.choice(SECOND_SUPPLIERS)
    lookalike_supplier = supplier_dom.replace("i", "l", 1)
    qr_full, qr_root = QR_INFRA[seed % len(QR_INFRA)]
    org_look = dom.replace("o", "0", 1)
    m: list[tuple[str, str]] = [
        ("Acme Human Resources", f"{org_name} Human Resources"), ("acmebackups", slug.replace("-", "") + "backups"),
        ("acme-demo.com", dom), ("acme-dem0.com", org_look), ("acme-demo", slug), ("ACME", nb),
        ("micros0ft-helpdesk.com", LOOKALIKE[seed % len(LOOKALIKE)]), ("micros0ft", LOOKALIKE[seed % len(LOOKALIKE)].split("-")[0]),
        ("185.220.101.4", TOR[seed % len(TOR)]),
        ("benefits-portal.payroll-update.support", qr_full), ("payroll-update.support", qr_root),
        ("krishna-logistlcs.com", lookalike_supplier), ("krishna-logistics.com", supplier_dom), ("Krishna Logistics", supplier),
        ("Global Freight Ltd", second), ("Global Freight", second.split(" Group")[0]), ("global-freight-ltd.com", second_dom),
        ("SAP-Prod-Finance-Service", ERP[seed % len(ERP)]),
        ("FS01-Finance-Backups", f"{servers['fs01'].upper()}-Finance-Archive"),
        *hosts.items(), *servers.items(),
        ("10.20.1.", f"10.{a}.{b}."), ("10.10.0.", f"10.{c}.0."), ("203.0.113.10", f"198.51.100.{rng.randint(20, 250)}"),
        *first.items(), *last.items(),
    ]
    meta = {"seed": seed, "org_name": org_name, "org": dom, "netbios": nb, "supplier": supplier, "supplier_domain": supplier_dom,
            "lookalike_supplier": lookalike_supplier, "people_pool": list(zip(firsts[10:], lasts[10:]))}
    return m, meta


# ------------------------------------------------------------------------------------------------ helpers
def _rename_eml(raw: bytes, rx, table, rename_text) -> bytes:
    """Rename headers and text, including base64-encoded text parts (decoded, renamed, re-encoded)."""
    text = raw.decode("utf-8", errors="surrogateescape")

    def block(mt):
        body = mt.group(2)
        try:
            dec = base64.b64decode("".join(body.split()), validate=True).decode("utf-8")
        except (ValueError, UnicodeDecodeError):              # not base64 text (binascii.Error is a ValueError)
            return mt.group(0)
        new = rename_text(dec, rx, table)
        if new == dec:
            return mt.group(0)
        enc = base64.b64encode(new.encode()).decode()
        width = max(len(x) for x in body.strip().splitlines()) or 76
        eol = "\r\n" if "\r\n" in body else "\n"
        return mt.group(1) + eol.join(enc[i:i + width] for i in range(0, len(enc), width)) + eol

    text = re.sub(r"(Content-Transfer-Encoding:\s*base64[^\n]*\n(?:[^\n]+\n)*?\r?\n)((?:[A-Za-z0-9+/=]+\r?\n)+)", block, text, flags=re.IGNORECASE)
    return rename_text(text, rx, table).encode("utf-8", errors="surrogateescape")


def _route(routes, method, path, params=None, body_contains=None):
    for r in routes:
        if r["method"] == method and r["path"] == path and r.get("params") == params and r.get("body_contains") == body_contains:
            return r
    raise KeyError((method, path, params, body_contains))


def _insert_before(routes, anchor, new):
    i = routes.index(anchor)
    routes[i:i] = new


# ------------------------------------------------------------------------------------------------ main
def main(out: str, seed: int = 7, scale: float = 1.0) -> Path:
    rng = random.Random(seed * 7919)
    ren = _load("rename_estate")
    bf = _load("build_fixtures")
    tmp = Path(tempfile.mkdtemp())
    bf.OUT = tmp                                               # regenerate the built-in fixtures, then transform them
    sys.path.insert(0, str(SCRIPTS))
    fb = _load("fixture_builders")
    for b in [bf.crowdstrike, *fb.BUILDERS]:
        b()
    mapping, meta = mapping_for(seed)
    rx, table = ren.build_pattern(mapping)
    org, nb = meta["org"], meta["netbios"]
    dst = Path(out)
    shutil.rmtree(dst, ignore_errors=True)
    (dst / "fixtures").mkdir(parents=True)
    (dst / "corpus").mkdir(parents=True)
    fx = {f.stem: ren._walk(json.loads(f.read_text(encoding="utf-8")), rx, table) for f in tmp.glob("*.json")}

    # threat-intel URL lookups are keyed by the URL's base64url id: re-key the phishing URL route for the new URL
    new_url = "https://login." + next(v for k, v in mapping if k == "micros0ft-helpdesk.com")
    for r in fx["threat_intel"]["routes"]:
        if r["path"].startswith(r"^/vt/api/v3/urls/") and r["path"] != r"^/vt/":
            r["path"] = r"^/vt/api/v3/urls/" + base64.urlsafe_b64encode(new_url[:24].encode()).decode()

    # ---------------- volumes: extra staff and laptops
    n_users = max(3, int(rng.randint(6, 14) * scale))
    pool_first = [f for f in FIRST if f.lower() not in {v for k, v in mapping if k.islower() and k.isalpha()}]
    pool_last = list(LAST)
    rng.shuffle(pool_first)
    rng.shuffle(pool_last)
    extra = []
    for i in range(n_users):
        fn, ln = pool_first[i % len(pool_first)], pool_last[(i * 3 + 1) % len(pool_last)]
        dept, title = DEPTS[rng.randrange(len(DEPTS))]
        sam = f"{fn.lower()}.{ln.lower()}{'' if i < len(pool_first) else i}"
        extra.append({"id": f"u-x{seed}-{i:03d}", "sam": sam, "upn": f"{sam}@{org}", "name": f"{fn} {ln}", "dept": dept, "title": title})
    users_route = _route(fx["entra"]["routes"], "GET", r"^/v1.0/users$")
    for u in extra:
        users_route["body"]["value"].append({"id": u["id"], "userPrincipalName": u["upn"], "mail": u["upn"], "displayName": u["name"],
                                             "department": u["dept"], "jobTitle": u["title"], "accountEnabled": True,
                                             "onPremisesSamAccountName": u["sam"], "createdDateTime": "2023-03-01T00:00:00Z"})
        fx["entra"]["routes"] += [
            {"method": "GET", "path": rf"^/v1.0/users/{u['upn']}$", "status": 200, "body": users_route["body"]["value"][-1]},
            {"method": "GET", "path": rf"^/v1.0/users/{u['upn']}/transitiveMemberOf$", "status": 200,
             "body": {"value": [{"@odata.type": "#microsoft.graph.group", "displayName": f"{u['dept']} Team"}]}},
            {"method": "GET", "path": rf"^/v1.0/users/{u['upn']}/authentication/methods$", "status": 200, "body": {"value": [
                {"@odata.type": "#microsoft.graph.passwordAuthenticationMethod"},
                {"@odata.type": "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod"}]}},
            {"method": "GET", "path": rf"^/v1.0/users/{u['upn']}/mailFolders/inbox/messageRules$", "status": 200, "body": {"value": []}},
            {"method": "GET", "path": rf"^/v1.0/users/{u['upn']}/registeredDevices$", "status": 200, "body": {"value": []}}]

    laptops = []
    net = next(v for k, v in mapping if k == "10.20.1.")
    for i, u in enumerate(extra[: max(2, int(len(extra) * 0.8))]):
        n = 800 + i * 7 + seed
        name = [f"{nb}-NB-{n:04d}", f"{u['sam'].split('.')[0].upper()}-{nb}-L{n % 100:02d}", f"LT{n:05d}-{nb}"][seed % 3]
        edr = rng.choice(["cs", "mde", "both", "both", "none"])
        laptops.append({"user": u, "hostname": name, "fqdn": f"{name.lower()}.{org}", "ip": f"{net}{100 + i}",
                        "cs": f"cs-x{seed}-{i:03d}" if edr in {"cs", "both"} else None,
                        "mde": f"mde-x{seed}-{i:03d}" if edr in {"mde", "both"} else None, "serial": f"PF{rng.randrange(16**6):06X}",
                        "vulnerable": rng.random() < 0.6, "in_cmdb": rng.random() < 0.7})
    cs, mde = fx["crowdstrike"]["routes"], fx["defender_endpoint"]["routes"]
    cs_ids = _route(cs, "GET", r"^/devices/queries/devices/v1$")
    cs_devs = _route(cs, "POST", r"^/devices/entities/devices/v2$")
    cs_star = _route(cs, "GET", r"^/devices/queries/devices/v1$", {"filter": "*"})
    cs_vulns = _route(cs, "GET", r"^/spotlight/combined/vulnerabilities/v1$")
    tmpl_vuln = next(v for v in cs_vulns["body"]["resources"] if v["cve"]["id"] == "CVE-2024-21412")
    md_all = _route(mde, "GET", r"^/api/machines$")
    md_star = _route(mde, "GET", r"^/api/machines$", {"$filter": "*"})
    md_vulns = _route(mde, "GET", r"^/api/vulnerabilities/machinesVulnerabilities$")
    md_users = next(r for r in mde if r["path"] == r"^/api/users/[^/]+/machines$")
    for h in laptops:
        if h["cs"]:
            cs_ids["body"]["resources"].append(h["cs"])
            cs_devs["body"]["resources"].append({"device_id": h["cs"], "hostname": h["hostname"], "local_ip": h["ip"],
                                                 "external_ip": "198.51.100.44", "mac_address": None, "serial_number": h["serial"],
                                                 "os_version": "Windows 11 Enterprise", "platform_name": "Windows",
                                                 "agent_version": "7.18.18209.0", "status": "normal", "last_seen": "2026-09-20T10:00:00Z",
                                                 "tags": []})
            _insert_before(cs, cs_star, [{"method": "GET", "path": r"^/devices/queries/devices/v1$", "status": 200,
                                          "params": {"filter": f"hostname:'{h['hostname']}'"},
                                          "body": {"resources": [h["cs"]], "meta": {}}}])
            if h["vulnerable"]:
                v = copy.deepcopy(tmpl_vuln)
                v.update({"id": f"{h['cs']}_CVE-2024-21412", "aid": h["cs"]})
                v["host_info"] = {"hostname": h["hostname"], "local_ip": h["ip"], "os_version": "Windows 11 Enterprise"}
                cs_vulns["body"]["resources"].append(v)
        if h["mde"]:
            m = {"id": h["mde"], "computerDnsName": h["fqdn"], "aadDeviceId": None, "lastIpAddress": h["ip"], "osPlatform": "Windows",
                 "osVersion": "Windows 11 Enterprise", "riskScore": "Low", "exposureLevel": "Medium", "healthStatus": "Active",
                 "onboardingStatus": "Onboarded", "lastSeen": "2026-09-20T10:00:00Z", "machineTags": []}
            md_all["body"]["value"].append(m)
            _insert_before(mde, md_star, [
                {"method": "GET", "path": r"^/api/machines$", "status": 200, "params": {"$filter": f"computerDnsName eq '{h['fqdn']}'"},
                 "body": {"value": [m]}},
                {"method": "GET", "path": r"^/api/machines$", "status": 200,
                 "params": {"$filter": f"startswith(computerDnsName,'{h['hostname'].lower()}')"}, "body": {"value": [m]}}])
            _insert_before(mde, md_users, [{"method": "GET", "path": rf"^/api/users/{h['user']['sam']}/machines$", "status": 200,
                                            "body": {"value": [m]}}])
            if h["vulnerable"]:
                md_vulns["body"]["value"].append({"id": f"{h['mde']}_CVE-2024-21412", "machineId": h["mde"], "cveId": "CVE-2024-21412",
                                                  "productName": "Microsoft Windows", "productVersion": "11", "severity": "High",
                                                  "fixingKbId": "KB5034765"})
    sn = fx["servicenow"]["routes"]
    sn_all = _route(sn, "GET", r"^/api/now/table/cmdb_ci_computer$")
    sn_star = _route(sn, "GET", r"^/api/now/table/cmdb_ci_computer$", {"sysparm_query": "*"})
    for h in laptops:
        if h["in_cmdb"]:
            ci = {"sys_id": f"ci-{h['hostname'].lower()}", "name": h["hostname"], "fqdn": h["fqdn"], "ip_address": h["ip"],
                  "os": "Windows 11 Enterprise", "serial_number": h["serial"], "owned_by": {"display_value": h["user"]["name"]},
                  "support_group": {"display_value": "End User Computing"}, "environment": "Corporate",
                  "business_criticality": "3 - less critical", "location": {"display_value": "HQ"}, "sys_updated_on": "2026-09-20T02:00:00"}
            sn_all["body"]["result"].append(ci)
            _insert_before(sn, sn_star, [{"method": "GET", "path": r"^/api/now/table/cmdb_ci_computer$", "status": 200,
                                          "params": {"sysparm_query": f"name={h['hostname']}"}, "body": {"result": [ci]}}])

    # ---------------- a bigger phishing campaign
    o365 = fx["defender_office365"]["routes"]
    senders = _route(o365, "POST", r"^/v1.0/security/runHuntingQuery$", None, "let senders")
    base_ev = senders["body"]["results"][0]
    extra_rcpt = rng.sample(extra, k=rng.randint(2, max(3, (2 * len(extra)) // 3)))
    new_events = [dict(base_ev, RecipientEmailAddress=u["upn"], Timestamp=f"2026-09-20T09:02:{30 + i:02d}Z")
                  for i, u in enumerate(extra_rcpt)]
    nmid = base_ev["NetworkMessageId"]
    for r in o365:
        bc = r.get("body_contains")
        if r["path"].endswith("runHuntingQuery$") and (bc == "let senders" or bc == nmid or bc == base_ev["InternetMessageId"]):
            r["body"]["results"] = r["body"]["results"][: len(r["body"]["results"])] + new_events

    # ---------------- more shadow IT
    umb = fx["umbrella"]["routes"]
    umb_all = _route(umb, "GET", r"^/reports/v2/activity/dns$")
    umb_ip_star = _route(umb, "GET", r"^/reports/v2/activity/dns$", {"ip": "*"})
    for i, h in enumerate(laptops):
        rows = []
        for dom_, cats in rng.sample(SHADOW, k=rng.randint(0, 2)):
            for j in range(rng.randint(1, 3)):
                rows.append({"timestamp": f"2026-09-20T{10 + i % 8:02d}:{(7 * j + i) % 60:02d}:00Z", "domain": dom_,
                             "verdict": "allowed" if rng.random() < 0.8 else "blocked", "internalip": h["ip"],
                             "externalip": "198.51.100.44", "querytype": "A", "categories": cats,
                             "identities": [{"label": h["hostname"], "type": {"type": "roaming"}},
                                            {"label": h["user"]["upn"], "type": {"type": "directory_user"}}]})
        umb_all["body"]["data"] += rows
        _insert_before(umb, umb_ip_star, [{"method": "GET", "path": r"^/reports/v2/activity/dns$", "status": 200,
                                           "params": {"ip": h["ip"]}, "body": {"data": rows}}])

    for name, doc in fx.items():
        (dst / "fixtures" / f"{name}.json").write_text(json.dumps(doc, indent=1), encoding="utf-8")

    # ---------------- tenant settings for the connectors
    sys.path.insert(0, str(ROOT))
    from soc_platform.connectors.registry import discover

    settings = {n: {k: ren.rename_text(v, rx, table) if isinstance(v, str) else v for k, v in m_.fake_settings.items()}
                for n, m_ in discover().items() if m_.fake_settings}
    (dst / "fixtures" / "settings.json").write_text(json.dumps(settings, indent=1), encoding="utf-8")

    # ---------------- corpus (renamed, plus seed-specific benign and bulk mail)
    labels = json.loads((ROOT / "artifacts/phishing/corpus/labels.json").read_text())
    labels.pop("quishing_qr", None)                          # its URL lives in QR pixels, which text renaming cannot change
    for f in (ROOT / "artifacts/phishing/corpus").glob("*.eml"):
        if f.stem in labels:
            (dst / "corpus" / f.name).write_bytes(_rename_eml(f.read_bytes(), rx, table, ren.rename_text))
    ec = _load("build_email_corpus")
    ec.ORG = org
    extra_mail = [
        ("safe", f"it-announcements@{org}", f"{meta['org_name']} IT", "Planned maintenance: VPN gateway upgrade on Saturday",
         "The VPN gateway will be upgraded on Saturday 22:00-23:00. No action is needed.", "spf=pass dkim=pass dmarc=pass", f"mail.{org}", "10.0.0.30"),
        ("safe", "no-reply@calendar.example", "Calendar", "Invitation: Quarterly planning review",
         "You have been invited to the quarterly planning review on Thursday at 10:00.", "spf=pass dkim=pass dmarc=pass", "mta.calendar.example", "198.51.100.61"),
        ("spam", "hello@growth-webinars.example", "Growth Webinars", "Last chance: free webinar on scaling your team",
         "Register today for our free webinar. Limited seats. Unsubscribe any time.", "spf=pass dkim=pass dmarc=pass", "mta.growth-webinars.example", "198.51.100.88"),
        ("spam", "promo@office-supplies-deals.example", "Office Supplies Deals", "Big savings on printer paper this month",
         "Save big on office supplies this month only. Unsubscribe from promotional mail here.", "spf=pass dkim=pass dmarc=pass", "mta.office-supplies-deals.example", "198.51.100.93"),
    ]
    for i, (label, frm, disp, subj, body, auth, relay, ip) in enumerate(rng.sample(extra_mail, k=rng.randint(2, 4))):
        m = ec._base(label, frm, disp, extra[i % len(extra)]["upn"], subj, auth=auth, relay=relay, ip=ip, minutes=30 + i)
        m.set_content(body)
        stem = f"extra_{label}_{i}"
        (dst / "corpus" / f"{stem}.eml").write_bytes(bytes(m))
        labels[stem] = label
    (dst / "corpus" / "labels.json").write_text(json.dumps(labels, indent=1), encoding="utf-8")

    sup = (ROOT / "config" / "suppliers.yaml").read_text(encoding="utf-8")
    (dst / "suppliers.yaml").write_text(ren.rename_text(sup, rx, table), encoding="utf-8")
    focus = ren.rename_text("jane.doe@acme-demo.com", rx, table)
    uploads = [f"{s}.eml" for s in labels if s not in {"cred_phish_lookalike", "html_attachment_phish", "iso_dropper",
                                                        "malspam_macro", "legit_github", "legit_internal"}]
    estate = {**meta, "fixtures_dir": str(dst / "fixtures"), "corpus_dir": str(dst / "corpus"),
              "suppliers_file": str(dst / "suppliers.yaml"), "focus_upn": focus, "campaign_cve": "CVE-2021-44228",
              "phish_subject_token": "password expires", "uploads": sorted(uploads), "lead": f"soc.lead@{org}",
              "extra_users": len(extra), "extra_laptops": len(laptops), "extra_recipients": len(extra_rcpt),
              "laptops_without_edr": sum(1 for h in laptops if not h["cs"] and not h["mde"]),
              "original_tokens": ["jane", "acme", "krishna", "micros0ft", "web01", "sap-prod", "185.220.101.4"]}
    (dst / "estate.json").write_text(json.dumps(estate, indent=1), encoding="utf-8")
    shutil.rmtree(tmp, ignore_errors=True)
    return dst


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("out")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--scale", type=float, default=1.0)
    a = ap.parse_args()
    print(main(a.out, a.seed, a.scale))
