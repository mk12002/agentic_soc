"""Third-party / vendor email risk monitoring (U18).

Mail from real suppliers is trusted by users and passes generic controls, which is why a compromised
supplier mailbox is such an effective initial-access and payment-fraud vector. For every configured
supplier this looks at analysed messages and reports:

  supplier_account_compromise  malicious/suspicious mail that *authenticates* as the supplier
                               (DMARC/DKIM/SPF pass) - their mailbox or tenant is likely compromised
  supplier_payment_diversion   bank-detail / payment-change language from the supplier or a look-alike
  supplier_impersonation       look-alike of a supplier domain (homoglyph / edit distance / brand embedding)
  supplier_spoofing            mail claiming the supplier's domain that fails authentication

Suppliers come from ``config/suppliers.yaml`` (name, domains, criticality) or ``SOC_SUPPLIER_DOMAINS``.
"""

from __future__ import annotations

import os
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any

import yaml
from sqlalchemy import select
from sqlalchemy.orm import Session

from soc_platform.core.models import Case, utcnow
from soc_platform.domains.phishing.agents.analyzer import lookalike

CONFIG = Path(__file__).resolve().parents[3] / "config" / "suppliers.yaml"
BAD = {"malicious", "suspicious"}
PAYMENT_SIGNALS = {"bec_payment_request", "advance_fee_fraud"}


@dataclass
class Supplier:
    name: str
    domains: list[str]
    criticality: str = "medium"


@dataclass
class SupplierFinding:
    type: str
    severity: str
    supplier: str
    case_id: str
    sender: str
    subject: str
    detail: str
    clicked: list[str] = field(default_factory=list)


def load_suppliers(path: str | Path | None = None) -> list[Supplier]:
    p = Path(path or os.environ.get("SOC_SUPPLIERS_FILE") or CONFIG)
    out: list[Supplier] = []
    if p.is_file():
        for row in (yaml.safe_load(p.read_text(encoding="utf-8")) or {}).get("suppliers") or []:
            doms = [str(d).lower().strip() for d in row.get("domains") or [] if str(d).strip()]
            if doms:
                out.append(Supplier(str(row.get("name") or doms[0]), doms, str(row.get("criticality") or "medium").lower()))
    for d in (os.environ.get("SOC_SUPPLIER_DOMAINS") or "").split(","):
        d = d.strip().lower()
        if d and not any(d in s.domains for s in out):
            out.append(Supplier(d, [d]))
    return out


def _owns(domain: str, s: Supplier) -> bool:
    return any(domain == d or domain.endswith("." + d) for d in s.domains)


def _authenticated(auth: dict[str, str]) -> bool:
    a = {k: str(v).lower() for k, v in (auth or {}).items()}
    return a.get("dmarc") == "pass" or (a.get("dkim") == "pass" and a.get("spf") in {"pass", None})


def _auth_failed(auth: dict[str, str]) -> bool:
    a = {k: str(v).lower() for k, v in (auth or {}).items()}
    return a.get("dmarc") in {"fail", "none"} and a.get("spf") in {"fail", "softfail", None} or a.get("compauth") == "fail"


class SupplierMonitor:
    def __init__(self, session: Session, suppliers: list[Supplier] | None = None) -> None:
        self.s = session
        self.suppliers = suppliers if suppliers is not None else load_suppliers()

    def assess(self, *, days: int = 90) -> dict[str, Any]:
        since = utcnow() - timedelta(days=days)
        findings: list[SupplierFinding] = []
        per: dict[str, Counter] = defaultdict(Counter)
        for case in self.s.execute(select(Case).where(Case.domain == "phishing")).scalars():
            created = case.created_at if case.created_at.tzinfo else case.created_at.replace(tzinfo=since.tzinfo)
            if created < since:
                continue
            attrs, asm = case.attributes or {}, case.assessment or {}
            sender = str(attrs.get("sender") or "").lower()
            dom = sender.rsplit("@", 1)[-1] if "@" in sender else ""
            if not dom:
                continue
            auth = (asm.get("decomposition") or {}).get("auth") or {}
            sigs = {s.get("name") for s in asm.get("signals") or [] if isinstance(s, dict)}
            clicked = list((asm.get("user_impact") or {}).get("clicked") or [])
            verdict = case.verdict or ""
            for sup in self.suppliers:
                own = _owns(dom, sup)
                look = None if own else lookalike(dom, sup.domains)
                if not own and not look:
                    continue
                per[sup.name]["messages"] += 1
                per[sup.name][f"verdict_{verdict or 'unknown'}"] += 1

                def add(kind: str, sev: str, detail: str, sup: Supplier = sup, case: Case = case,
                        sender: str = sender, clicked: bool = clicked) -> None:
                    if sup.criticality == "high" and sev == "high":
                        sev = "critical"
                    if clicked and sev in {"medium", "high"}:
                        sev = {"medium": "high", "high": "critical"}[sev]
                    findings.append(SupplierFinding(kind, sev, sup.name, case.id, sender, case.title, detail, clicked))

                if own and verdict in BAD and _authenticated(auth):
                    add("supplier_account_compromise", "high",
                        f"{verdict} message authenticated as {dom} (auth {auth}); the supplier's mailbox or tenant is "
                        "likely compromised")
                if own and _auth_failed(auth):
                    add("supplier_spoofing", "medium", f"message claims {dom} but fails authentication ({auth})")
                if look and verdict in BAD | {"spam"}:
                    add("supplier_impersonation", "high", f"{dom} imitates supplier domain {look[0]} ({look[1]})")
                if sigs & PAYMENT_SIGNALS:  # even when the message itself looks clean: verify out of band
                    add("supplier_payment_diversion", "high",
                        "payment / bank-detail change request from a supplier identity - verify by phone using a "
                        "number on file before any payment change")
        by_sup = {s.name: {"domains": s.domains, "criticality": s.criticality, **dict(per.get(s.name, {})),
                           "findings": [f.__dict__ for f in findings if f.supplier == s.name]}
                  for s in self.suppliers}
        for v in by_sup.values():
            sev = [f["severity"] for f in v["findings"]]
            v["status"] = ("critical" if "critical" in sev else "at_risk" if "high" in sev else
                           "watch" if sev else "ok")
        return {"suppliers": by_sup, "findings": [f.__dict__ for f in findings], "window_days": days,
                "configured": len(self.suppliers)}
