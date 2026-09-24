"""
Generate synthetic datasets for agents that lack sufficient training data.

Produces:
    1. Threat intel IOC feeds  → datasets/threat_intelligence/{domains,ips,urls}/*.csv
    2. Sandbox behavior    → datasets/sandbox_behavior/sandbox_logs.csv        (500 rows)
    3. Header training     → datasets/email_content/header_training.csv        (3 000 rows)

Usage:
    cd <repo root>
    python scripts/generate_synthetic_datasets.py
"""

from __future__ import annotations
from soc_platform.domains.phishing.engine.paths import PHISHING_HOME

import csv
import hashlib
import json
import math
import random
import string
from pathlib import Path


SEED = 42
random.seed(SEED)

BASE = PHISHING_HOME / "datasets"


# ─────────────────────────────────────────────────────────────
#  1.  Threat Intelligence IOC Feeds
# ─────────────────────────────────────────────────────────────

def _random_domain(malicious: bool = True) -> str:
    tlds_malicious = [".xyz", ".top", ".buzz", ".club", ".info", ".cc", ".tk", ".ml", ".ga"]
    tlds_benign = [".com", ".org", ".net", ".edu"]
    if malicious:
        name_len = random.randint(6, 18)
        name = "".join(random.choices(string.ascii_lowercase + string.digits, k=name_len))
        tld = random.choice(tlds_malicious)
    else:
        name_len = random.randint(4, 10)
        name = "".join(random.choices(string.ascii_lowercase, k=name_len))
        tld = random.choice(tlds_benign)
    return name + tld


def _random_ip() -> str:
    # Avoid reserved ranges
    return f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def _generate_threat_intel() -> None:
    """Generate IOC feed CSVs in threat_intelligence subdirectories."""
    # Malicious domains
    dom_dir = BASE / "threat_intelligence" / "domains"
    dom_dir.mkdir(parents=True, exist_ok=True)
    domains = [_random_domain(malicious=True) for _ in range(500)]
    with open(dom_dir / "malicious_domains.csv", "w", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["domain", "source", "first_seen"])
        for d in domains:
            writer.writerow([d, random.choice(["phishtank", "openphish", "urlhaus", "otx"]),
                             f"2026-{random.randint(1,3):02d}-{random.randint(1,28):02d}"])
    print(f"  ✓ IOC domains: {len(domains)} entries → {dom_dir / 'malicious_domains.csv'}")

    # Malicious IPs
    ip_dir = BASE / "threat_intelligence" / "ips"
    ip_dir.mkdir(parents=True, exist_ok=True)
    ips = [_random_ip() for _ in range(300)]
    with open(ip_dir / "malicious_ips.csv", "w", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["ip", "source", "abuse_score"])
        for ip in ips:
            writer.writerow([ip, random.choice(["abuseipdb", "shodan", "otx"]),
                             random.randint(50, 100)])
    print(f"  ✓ IOC IPs: {len(ips)} entries → {ip_dir / 'malicious_ips.csv'}")

    # Malicious URLs
    url_dir = BASE / "threat_intelligence" / "urls"
    url_dir.mkdir(parents=True, exist_ok=True)
    urls = [f"http://{_random_domain(True)}/{'/'.join(random.choices(string.ascii_lowercase, k=random.randint(2,5)))}"
            for _ in range(400)]
    with open(url_dir / "malicious_urls.csv", "w", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["url", "threat_type", "source"])
        for u in urls:
            writer.writerow([u, random.choice(["phishing", "malware_download", "c2", "scam"]),
                             random.choice(["urlhaus", "phishtank", "openphish"])])
    print(f"  ✓ IOC URLs: {len(urls)} entries → {url_dir / 'malicious_urls.csv'}")


# ─────────────────────────────────────────────────────────────
#  2.  Sandbox Behavior Logs  (500 rows)
# ─────────────────────────────────────────────────────────────

def _generate_sandbox_logs(n: int = 500) -> None:
    """Generate synthetic sandbox detonation results."""
    out = BASE / "sandbox_behavior" / "sandbox_logs.csv"
    out.parent.mkdir(parents=True, exist_ok=True)

    rows = []
    for i in range(n):
        is_malicious = random.random() < 0.55  # slight malicious bias
        ext = random.choice([".exe", ".dll", ".js", ".ps1", ".py", ".pdf", ".docx", ".xlsx"])

        if is_malicious:
            executed = True
            return_code = random.choice([0, 1, -1, 137])
            timed_out = random.random() < 0.2
            spawned = random.randint(2, 12)
            suspicious_procs = random.randint(1, min(5, spawned))
            entropy = round(random.uniform(6.5, 7.99), 2)
        else:
            executed = random.random() < 0.7
            return_code = 0
            timed_out = random.random() < 0.03
            spawned = random.randint(0, 3)
            suspicious_procs = 0
            entropy = round(random.uniform(3.0, 6.5), 2)

        rows.append({
            "sample_id": f"sample_{i:04d}",
            "file_extension": ext,
            "executed": int(executed),
            "return_code": return_code,
            "timed_out": int(timed_out),
            "spawned_processes": spawned,
            "suspicious_process_count": suspicious_procs,
            "file_entropy": entropy,
            "label": 1 if is_malicious else 0,
        })

    with open(out, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    print(f"  ✓ Sandbox behavior: {len(rows)} rows → {out}")


# ─────────────────────────────────────────────────────────────
#  3.  Header Training Dataset  (10 000 rows)
#
#  Uses archetype-based generation for realistic, correlated
#  features that mirror real-world email header patterns.
# ─────────────────────────────────────────────────────────────

# Real-world domain entropy values (pre-calculated from common domains)
_REAL_DOMAINS = {
    # Benign domains with known entropy values
    "gmail.com": 2.25,
    "yahoo.com": 2.81,
    "outlook.com": 3.09,
    "hotmail.com": 3.09,
    "icloud.com": 2.81,
    "protonmail.com": 3.42,
    "zoho.com": 2.0,
    "aol.com": 1.58,
    "company.com": 2.81,
    "acme.org": 2.32,
    "example.net": 3.09,
    "university.edu": 3.61,
    "hospital.org": 3.25,
    "govoffice.gov": 3.46,
    "smallbiz.co": 2.85,
    "startup.io": 2.85,
    "consulting-firm.com": 3.81,
    "techcorp.com": 3.17,
}


def _realistic_domain_entropy(malicious: bool) -> tuple[float, float]:
    """Return (domain_length, domain_entropy) based on realistic distributions."""
    if malicious:
        pattern = random.choices(
            ["random_gibberish", "lookalike", "compromised_legit", "free_tld", "subdomain_abuse"],
            weights=[30, 25, 15, 20, 10],
            k=1,
        )[0]
        if pattern == "random_gibberish":
            # e.g., xk49fj-services.top  →  high entropy, long
            length = float(random.randint(15, 40))
            entropy = round(random.gauss(4.0, 0.35), 4)
        elif pattern == "lookalike":
            # e.g., paypa1.com, amaz0n.co  →  similar to real domains
            length = float(random.randint(8, 18))
            entropy = round(random.gauss(2.8, 0.4), 4)
        elif pattern == "compromised_legit":
            # Attacker using a real-looking domain  →  normal entropy
            length = float(random.randint(8, 16))
            entropy = round(random.gauss(2.7, 0.3), 4)
        elif pattern == "free_tld":
            # e.g., something.tk, phish.ml  →  short, low-ish entropy
            length = float(random.randint(6, 14))
            entropy = round(random.gauss(3.0, 0.5), 4)
        else:  # subdomain_abuse
            # e.g., login.secure.microsoft.phishing.xyz  →  very long
            length = float(random.randint(25, 50))
            entropy = round(random.gauss(3.5, 0.4), 4)
    else:
        # Pick from real domain stats or generate realistic ones
        if random.random() < 0.4:
            name, ent = random.choice(list(_REAL_DOMAINS.items()))
            length = float(len(name))
            entropy = round(ent + random.gauss(0, 0.05), 4)
        else:
            length = float(random.randint(6, 20))
            entropy = round(random.gauss(2.8, 0.5), 4)
    return length, max(0.5, entropy)


def _generate_archetype_row(archetype: str) -> dict:
    """Generate a single row from a specific email archetype."""

    if archetype == "corporate_legit":
        # Standard corporate email — all auth passes, normal hops
        spf = 1.0 if random.random() < 0.95 else 0.0
        dkim = 1.0 if random.random() < 0.93 else 0.0
        dmarc = 1.0 if random.random() < 0.90 else 0.0
        dom_len, dom_ent = _realistic_domain_entropy(False)
        display_mm = 0.0
        hops = float(random.choices([2, 3, 4, 5], weights=[15, 40, 30, 15], k=1)[0])
        reply_mm = 0.0
        label = 0

    elif archetype == "forwarded_legit":
        # Forwarded email — SPF often fails, DKIM may survive, extra hops
        spf = 1.0 if random.random() < 0.30 else 0.0  # SPF frequently breaks on forward
        dkim = 1.0 if random.random() < 0.75 else 0.0  # DKIM often survives
        dmarc = 1.0 if random.random() < 0.40 else 0.0  # Depends on alignment
        dom_len, dom_ent = _realistic_domain_entropy(False)
        display_mm = 0.0
        hops = float(random.choices([3, 4, 5, 6, 7, 8], weights=[10, 20, 25, 25, 15, 5], k=1)[0])
        reply_mm = 1.0 if random.random() < 0.15 else 0.0  # Sometimes forwarded reply-to differs
        label = 0

    elif archetype == "newsletter_legit":
        # Marketing/newsletter — auth usually passes, dedicated sending infra
        spf = 1.0 if random.random() < 0.88 else 0.0
        dkim = 1.0 if random.random() < 0.92 else 0.0
        dmarc = 1.0 if random.random() < 0.80 else 0.0
        dom_len = float(random.randint(10, 25))  # Subdomains like mail.company.com
        dom_ent = round(random.gauss(3.2, 0.4), 4)
        display_mm = 0.0
        hops = float(random.choices([2, 3, 4], weights=[30, 50, 20], k=1)[0])
        reply_mm = 1.0 if random.random() < 0.30 else 0.0  # reply-to often differs (noreply vs support)
        label = 0

    elif archetype == "personal_legit":
        # Personal email from freemail — generally passes auth
        spf = 1.0 if random.random() < 0.92 else 0.0
        dkim = 1.0 if random.random() < 0.95 else 0.0
        dmarc = 1.0 if random.random() < 0.85 else 0.0
        dom_len, dom_ent = _realistic_domain_entropy(False)
        display_mm = 0.0
        hops = float(random.choices([2, 3, 4], weights=[40, 40, 20], k=1)[0])
        reply_mm = 0.0
        label = 0

    elif archetype == "legacy_server_legit":
        # Old mail server — no/broken auth, few hops
        spf = 1.0 if random.random() < 0.10 else 0.0
        dkim = 1.0 if random.random() < 0.05 else 0.0
        dmarc = 1.0 if random.random() < 0.05 else 0.0
        dom_len = float(random.randint(8, 18))
        dom_ent = round(random.gauss(3.0, 0.4), 4)
        display_mm = 0.0
        hops = float(random.choices([1, 2, 3], weights=[30, 50, 20], k=1)[0])
        reply_mm = 0.0
        label = 0

    elif archetype == "mass_phishing":
        # Mass phishing — random domain, all auth fails, short trace
        spf = 1.0 if random.random() < 0.08 else 0.0
        dkim = 1.0 if random.random() < 0.05 else 0.0
        dmarc = 1.0 if random.random() < 0.03 else 0.0
        dom_len, dom_ent = _realistic_domain_entropy(True)
        display_mm = 1.0 if random.random() < 0.60 else 0.0
        hops = float(random.choices([1, 2], weights=[70, 30], k=1)[0])
        reply_mm = 1.0 if random.random() < 0.55 else 0.0
        label = 1

    elif archetype == "spear_phishing":
        # Targeted spear phishing — lookalike domain, may pass some auth
        spf = 1.0 if random.random() < 0.40 else 0.0  # Sometimes properly configured
        dkim = 1.0 if random.random() < 0.35 else 0.0
        dmarc = 1.0 if random.random() < 0.20 else 0.0
        dom_len, dom_ent = _realistic_domain_entropy(True)
        display_mm = 1.0 if random.random() < 0.70 else 0.0
        hops = float(random.choices([1, 2, 3], weights=[30, 45, 25], k=1)[0])
        reply_mm = 1.0 if random.random() < 0.40 else 0.0
        label = 1

    elif archetype == "bec_attack":
        # Business Email Compromise — compromised legit account or convincing lookalike
        # This is the hardest to detect: often passes auth, normal-looking domain
        spf = 1.0 if random.random() < 0.65 else 0.0
        dkim = 1.0 if random.random() < 0.55 else 0.0
        dmarc = 1.0 if random.random() < 0.45 else 0.0
        dom_len, dom_ent = _realistic_domain_entropy(True)
        # BEC often uses display name spoofing
        display_mm = 1.0 if random.random() < 0.50 else 0.0
        hops = float(random.choices([2, 3, 4], weights=[40, 40, 20], k=1)[0])
        reply_mm = 1.0 if random.random() < 0.65 else 0.0  # Key BEC tell: reply-to goes elsewhere
        label = 1

    elif archetype == "credential_harvest":
        # Credential harvesting phishing — random domain, aggressive indicators
        spf = 1.0 if random.random() < 0.12 else 0.0
        dkim = 1.0 if random.random() < 0.08 else 0.0
        dmarc = 1.0 if random.random() < 0.05 else 0.0
        dom_len, dom_ent = _realistic_domain_entropy(True)
        display_mm = 1.0 if random.random() < 0.75 else 0.0
        hops = float(random.choices([1, 2], weights=[80, 20], k=1)[0])
        reply_mm = 1.0 if random.random() < 0.50 else 0.0
        label = 1

    elif archetype == "compromised_account":
        # Legitimate account that's been hijacked — passes ALL auth
        # This tests the model's ability to detect anomalies beyond auth
        spf = 1.0 if random.random() < 0.90 else 0.0
        dkim = 1.0 if random.random() < 0.88 else 0.0
        dmarc = 1.0 if random.random() < 0.85 else 0.0
        dom_len, dom_ent = _realistic_domain_entropy(False)  # Real domain!
        display_mm = 0.0  # No display mismatch — it IS the real account
        hops = float(random.choices([2, 3], weights=[50, 50], k=1)[0])
        reply_mm = 1.0 if random.random() < 0.60 else 0.0  # Only tell: unusual reply-to
        label = 1

    else:
        raise ValueError(f"Unknown archetype: {archetype}")

    # ── Global noise injection ──
    dom_ent = round(dom_ent + random.gauss(0, 0.12), 4)
    dom_ent = round(max(0.5, dom_ent), 4)
    dom_len = max(3.0, dom_len + random.gauss(0, 1.0))
    dom_len = round(dom_len)
    hops = max(1.0, hops + random.choices([-1, 0, 0, 0, 1], k=1)[0])

    return {
        "spf_pass": spf,
        "dkim_pass": dkim,
        "dmarc_pass": dmarc,
        "sender_domain_len": float(dom_len),
        "display_name_mismatch": display_mm,
        "hop_count": float(hops),
        "reply_to_mismatch": reply_mm,
        "sender_domain_entropy": dom_ent,
        "label": label,
    }


def _generate_header_training(n: int = 10000) -> None:
    """Generate realistic header analysis training data using email archetypes."""
    out = BASE / "email_content" / "header_training.csv"
    out.parent.mkdir(parents=True, exist_ok=True)

    # Archetype distribution mirrors real-world email composition
    benign_archetypes = [
        ("corporate_legit", 0.30),
        ("personal_legit", 0.20),
        ("newsletter_legit", 0.15),
        ("forwarded_legit", 0.10),
        ("legacy_server_legit", 0.05),
    ]
    phishing_archetypes = [
        ("mass_phishing", 0.08),
        ("credential_harvest", 0.05),
        ("spear_phishing", 0.03),
        ("bec_attack", 0.02),
        ("compromised_account", 0.02),
    ]

    all_archetypes = benign_archetypes + phishing_archetypes
    names = [a[0] for a in all_archetypes]
    weights = [a[1] for a in all_archetypes]

    rows = []
    archetype_counts: dict[str, int] = {name: 0 for name in names}
    for _ in range(n):
        archetype = random.choices(names, weights=weights, k=1)[0]
        archetype_counts[archetype] += 1
        rows.append(_generate_archetype_row(archetype))

    # Shuffle
    random.shuffle(rows)

    with open(out, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    benign_count = sum(1 for r in rows if r["label"] == 0)
    phish_count = sum(1 for r in rows if r["label"] == 1)
    print(f"  ✓ Header training: {len(rows)} rows ({benign_count} benign, {phish_count} phishing) → {out}")
    print(f"    Archetypes: {json.dumps(archetype_counts, indent=6)}")


# ─────────────────────────────────────────────────────────────
#  Main
# ─────────────────────────────────────────────────────────────

def main() -> None:
    print(f"Generating synthetic datasets into: {BASE}\n")
    _generate_threat_intel()
    _generate_sandbox_logs()
    _generate_header_training()
    print("\n✅ All synthetic datasets generated successfully.")


if __name__ == "__main__":
    main()
