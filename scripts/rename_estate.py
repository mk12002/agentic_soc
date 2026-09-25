"""Rename the sample estate into a different organisation (generalisation testing, or a client-branded demo).

    python scripts/rename_estate.py OUT_DIR            # default mapping -> "Northwind Labs"
    SOC_FIXTURES_DIR=OUT_DIR/fixtures python -m soc_platform serve

Every fixture file and sample email is rewritten with a consistent mapping (people, hosts, domains, IPs, phishing
infrastructure, secrets, suppliers), preserving case variants (``JANE-LT01`` / ``jane-lt01`` / ``Jane Doe``) and
matching only whole name tokens (``li`` never touches ``link``). Output: ``OUT_DIR/fixtures``, ``OUT_DIR/corpus``,
``OUT_DIR/suppliers.yaml``, ``OUT_DIR/mapping.json``.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

DEFAULT_MAP: list[tuple[str, str]] = [
    # organisation, domains, tenant
    ("cci-demo.com", "northwind-labs.io"), ("cci-demo", "northwind-labs"), ("CCI", "NWL"),
    # phishing / attacker infrastructure (still a look-alike of a real brand, but different strings)
    ("micros0ft-helpdesk.com", "micr0soft-servicedesk.net"), ("185.220.101.4", "45.155.205.99"),
    ("benefits-portal.payroll-update.support", "hr-benefits.salary-review.help"), ("payroll-update.support", "salary-review.help"),
    ("cci-dem0.com", "northwind-lab5.io"), ("global-freight-ltd.com", "atlas-cargo-group.com"),
    ("krishna-logistics.com", "blueriver-freight.com"), ("krishna-logistlcs.com", "blueriver-frelght.com"),
    ("Krishna Logistics", "BlueRiver Freight"),
    # people (first / last name tokens)
    ("jane", "maria"), ("doe", "okafor"), ("bob", "kenji"), ("lee", "tanaka"), ("priya", "lucas"), ("nair", "ferreira"),
    ("raj", "sofia"), ("mehta", "rossi"), ("arun", "omar"), ("meera", "elena"), ("tom", "david"), ("li", "ana"),
    ("chen", "silva"), ("sunita", "grace"), ("iyer", "mensah"), ("anil", "tariq"), ("rao", "haddad"),
    # hosts, secrets, shares
    ("web01", "app07"), ("db01", "sql04"), ("fs01", "nas02"), ("SAP-Prod-Finance-Service", "Oracle-ERP-Payroll-Admin"),
    ("FS01-Finance-Backups", "NAS02-HR-Archive"),
    # internal address plan
    ("10.20.1.", "172.16.8."), ("10.10.0.", "172.17.3."), ("203.0.113.10", "198.51.100.44"),
]


def _case_variants(src: str, dst: str) -> list[tuple[str, str]]:
    out = [(src, dst), (src.lower(), dst.lower()), (src.upper(), dst.upper()), (src.title(), dst.title())]
    if src[:1].isalpha():
        out.append((src[:1].upper() + src[1:].lower(), dst[:1].upper() + dst[1:].lower()))
    return list(dict.fromkeys(out))


def build_pattern(mapping: list[tuple[str, str]]):
    table: dict[str, str] = {}
    for src, dst in mapping:
        for s, d in _case_variants(src, dst):
            table.setdefault(s, d)
    keys = sorted(table, key=len, reverse=True)
    # a token must not be glued to other letters (so "li" != "link", "doe" != "does"); digits/punctuation are fine
    rx = re.compile("|".join(f"(?<![A-Za-z]){re.escape(k)}(?![A-Za-z])" if k[:1].isalpha() and k[-1:].isalpha()
                             else re.escape(k) for k in keys))
    return rx, table


def rename_text(text: str, rx, table) -> str:
    return rx.sub(lambda m: table[m.group(0)], text)


def _walk(v, rx, table):
    """Rename every string, including base64-embedded messages (e.g. reported .eml attachments)."""
    if isinstance(v, dict):
        return {k: (_b64(x, rx, table) if k == "contentBytes" and isinstance(x, str) else _walk(x, rx, table)) for k, x in v.items()}
    if isinstance(v, list):
        return [_walk(x, rx, table) for x in v]
    if isinstance(v, str):
        return rename_text(v, rx, table)
    return v


def _b64(value: str, rx, table) -> str:
    import base64

    try:
        raw = base64.b64decode(value, validate=True)
    except ValueError:
        return rename_text(value, rx, table)
    text = raw.decode("utf-8", errors="surrogateescape")
    return base64.b64encode(rename_text(text, rx, table).encode("utf-8", errors="surrogateescape")).decode()


def main(out: str, mapping: list[tuple[str, str]] | None = None) -> Path:
    mapping = mapping or DEFAULT_MAP
    rx, table = build_pattern(mapping)
    dst = Path(out)
    (dst / "fixtures").mkdir(parents=True, exist_ok=True)
    (dst / "corpus").mkdir(parents=True, exist_ok=True)
    for f in (ROOT / "soc_platform" / "fixtures").glob("*.json"):
        doc = _walk(json.loads(f.read_text(encoding="utf-8")), rx, table)
        (dst / "fixtures" / f.name).write_text(json.dumps(doc, indent=1), encoding="utf-8")
    # QR-code emails carry their URL inside image pixels, which text renaming cannot rewrite: skipped
    skip = {"quishing_qr"}
    labels = json.loads((ROOT / "artifacts" / "phishing" / "corpus" / "labels.json").read_text())
    (dst / "corpus" / "labels.json").write_text(json.dumps({k: v for k, v in labels.items() if k not in skip}, indent=1))
    for f in (ROOT / "artifacts" / "phishing" / "corpus").iterdir():
        if f.suffix == ".eml" and f.stem not in skip:
            raw = f.read_bytes().decode("utf-8", errors="surrogateescape")
            (dst / "corpus" / f.name).write_bytes(rename_text(raw, rx, table).encode("utf-8", errors="surrogateescape"))
    sup = (ROOT / "config" / "suppliers.yaml").read_text(encoding="utf-8")
    (dst / "suppliers.yaml").write_text(rename_text(sup, rx, table), encoding="utf-8")
    san = (ROOT / "config" / "sanctioned_services.yaml").read_text(encoding="utf-8")
    (dst / "sanctioned_services.yaml").write_text(san, encoding="utf-8")
    (dst / "mapping.json").write_text(json.dumps(dict(mapping), indent=1), encoding="utf-8")
    return dst


if __name__ == "__main__":
    print(main(sys.argv[1] if len(sys.argv) > 1 else "renamed_estate"))
