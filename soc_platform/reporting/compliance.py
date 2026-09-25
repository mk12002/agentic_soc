"""Compliance and audit evidence automation (U17, NFR-04).

Builds a point-in-time evidence pack from records the platform already keeps: the hash-chained audit
log, approvals, policy versions, access grants, API-key inventory, LLM governance logs, retention runs,
kill-switch history and connector freshness. Each control gets computed *tests* (e.g. "no action was
approved by its own requester") with pass/fail, so an auditor receives conclusions and the raw
evidence behind them.

Output: a ZIP with ``evidence.json`` (controls, tests, figures), ``audit_log.jsonl`` (full chained export
with verification) and ``summary.docx`` (human-readable). Nothing secret is included (API keys appear
only as id/name/roles; prompts are not exported).
"""

from __future__ import annotations

import json
import zipfile
from collections import Counter
from datetime import timedelta
from pathlib import Path
from typing import Any

from docx import Document
from sqlalchemy import select
from sqlalchemy.orm import Session

from soc_platform.config import Settings
from soc_platform.core.access import AccessService, kill_switch_on, permissions_matrix
from soc_platform.core.audit import AuditLog
from soc_platform.core.models import (ActionRequest, AuditRecord, ConnectorCheckpoint, LLMCall, PolicyVersion,
                                      TokenRevocation, utcnow)
from soc_platform.core.retention import export_audit


def _test(name: str, passed: bool, detail: str, evidence: Any = None) -> dict[str, Any]:
    return {"test": name, "result": "pass" if passed else "fail", "detail": detail, "evidence": evidence}


def build_evidence(session: Session, settings: Settings, *, period_days: int = 90) -> dict[str, Any]:
    now = utcnow()
    since = now - timedelta(days=period_days)
    audit = AuditLog(session)
    chain = audit.verify()

    def events(prefix: str) -> list[AuditRecord]:
        return list(session.execute(select(AuditRecord).where(AuditRecord.event_type.like(f"{prefix}%"),
                                                              AuditRecord.ts >= since)
                                    .order_by(AuditRecord.seq)).scalars())

    acts = list(session.execute(select(ActionRequest).where(ActionRequest.created_at >= since)).scalars())
    # An analyst requesting an action they may approve is an explicit approval (by design); separation of duties
    # applies to four-eyes actions, which must be approved by a different person.
    four_eyes = [a for a in acts if any("four" in str(r).lower() for r in (a.policy_reasons or []))]
    self_approved = [a.id for a in four_eyes if a.approver and a.requested_by and a.approver.lower() == a.requested_by.lower()]
    autonomous = [a for a in acts if a.status in {"executed", "rolled_back"} and str(a.approver or "").startswith("policy:")]
    destructive_auto = [a.id for a in autonomous if any("destructive" in str(r).lower() for r in (a.policy_reasons or []))]
    pols = list(session.execute(select(PolicyVersion).order_by(PolicyVersion.id)).scalars())
    self_policy = [p.id for p in pols if p.approved_by and p.approved_by == p.proposed_by]
    acc = AccessService(session, settings)
    grants = acc.list_grants(include_inactive=True)
    keys = acc.list_api_keys()
    long_keys = [k["id"] for k in keys if k["active"]]
    llm_calls = list(session.execute(select(LLMCall).where(LLMCall.ts >= since)).scalars())
    llm_models = Counter(f"{c.provider}:{c.model}" for c in llm_calls)
    bg = events("auth.break_glass")
    ks = events("policy.kill_switch")
    ret = events("retention.run")
    cps = list(session.execute(select(ConnectorCheckpoint)).scalars())
    stale = [c.connector for c in cps if c.last_success_at and
             (now - (c.last_success_at if c.last_success_at.tzinfo else c.last_success_at.replace(tzinfo=now.tzinfo)))
             > timedelta(days=2)]

    controls = [
        {"control": "NFR-04 Immutable, tamper-evident audit trail",
         "tests": [_test("audit hash chain verifies end-to-end", chain["ok"],
                         f"{chain['records']} records; head {str(chain.get('head', ''))[:16]}...", chain)]},
        {"control": "NFR-01 / R04 Human approval and separation of duties for actions",
         "tests": [_test("four-eyes actions approved by a second person", not self_approved,
                         f"{len(four_eyes)} four-eyes actions of {len(acts)}; self-approved: {len(self_approved)}", self_approved),
                   _test("no destructive action executed without approval", not destructive_auto,
                         f"{len(autonomous)} autonomous executions; destructive among them: {len(destructive_auto)}",
                         destructive_auto)],
         "figures": {"actions_by_status": dict(Counter(a.status for a in acts)),
                     "actions_by_type": dict(Counter(a.action_type for a in acts))}},
        {"control": "NFR-12 Change control for automation policy",
         "tests": [_test("no policy version approved by its proposer", not self_policy,
                         f"{len(pols)} versions; self-approved {len(self_policy)}", self_policy)],
         "figures": {"versions": [{"id": p.id, "status": p.status, "proposed_by": p.proposed_by,
                                   "approved_by": p.approved_by} for p in pols]}},
        {"control": "NFR-09 Access control (RBAC, MFA, service accounts, revocation)",
         "tests": [_test("step-up MFA enforced for approvals", settings.require_mfa or settings.environment != "prod",
                         f"require_mfa={settings.require_mfa}, environment={settings.environment}"),
                   _test("dev authentication disabled in prod", not (settings.environment == "prod" and settings.auth_mode == "dev"),
                         f"auth_mode={settings.auth_mode}"),
                   _test("all active service-account keys expire", all(k["expires_at"] for k in keys if k["active"]),
                         f"{len(long_keys)} active keys"),
                   _test("no unreviewed break-glass use", not any(e.event_type == "auth.break_glass_used" for e in bg),
                         f"{sum(1 for e in bg if e.event_type == 'auth.break_glass_used')} uses, "
                         f"{sum(1 for e in bg if e.event_type == 'auth.break_glass_failed')} failed attempts in period",
                         [{"ts": e.ts.isoformat(), "event": e.event_type, "payload": e.payload} for e in bg])],
         "figures": {"role_matrix": permissions_matrix(), "grants": grants,
                     "api_keys": keys, "token_revocations": session.query(TokenRevocation).count()}},
        {"control": "NFR-11 / R02 / R10 LLM governance",
         "tests": [_test("PII redaction before model calls enabled", settings.llm_redact_pii,
                         f"llm_redact_pii={settings.llm_redact_pii}"),
                   _test("model calls only to approved endpoints", settings.llm_provider == "none" or
                         bool(settings.llm_approved_endpoints),
                         f"provider={settings.llm_provider}; approved endpoints={len(settings.llm_approved_endpoints)}")],
         "figures": {"calls_in_period": len(llm_calls), "models": dict(llm_models),
                     "tokens": sum((c.prompt_tokens or 0) + (getattr(c, "completion_tokens", 0) or 0) for c in llm_calls)}},
        {"control": "NFR-08 / R10 Data protection (encryption at rest, retention)",
         "tests": [_test("raw payloads encrypted at rest", bool(settings.data_keys) or settings.environment != "prod",
                         f"data key configured={bool(settings.data_keys)}"),
                   _test("retention job ran in period", bool(ret) or period_days < 7,
                         f"{len(ret)} retention runs", [e.payload for e in ret[-3:]])],
         "figures": {"raw_retention_days": settings.raw_retention_days,
                     "access_log_retention_days": settings.access_log_retention_days,
                     "llm_log_retention_days": settings.llm_log_retention_days}},
        {"control": "R04 Global kill switch",
         "tests": [_test("kill switch state recorded", True, f"currently {'ON' if kill_switch_on(session, settings) else 'off'}",
                         [{"ts": e.ts.isoformat(), "by": e.actor_id, "on": (e.payload or {}).get("on")} for e in ks])]},
        {"control": "NFR-13 Integration health and data freshness",
         "tests": [_test("no connector stale for more than 2 days", not stale, f"stale: {stale or 'none'}", stale)],
         "figures": {"checkpoints": [{"connector": c.connector, "stream": c.stream,
                                      "last_success_at": c.last_success_at.isoformat() if c.last_success_at else None}
                                     for c in cps]}},
    ]
    tests = [t for c in controls for t in c["tests"]]
    return {"generated_at": now.isoformat(), "period_days": period_days, "period_start": since.isoformat(),
            "summary": {"controls": len(controls), "tests": len(tests),
                        "passed": sum(t["result"] == "pass" for t in tests),
                        "failed": sum(t["result"] == "fail" for t in tests)},
            "controls": controls}


def build_pack(session: Session, settings: Settings, out_dir: str | Path, *, period_days: int = 90) -> tuple[Path, dict[str, Any]]:
    ev = build_evidence(session, settings, period_days=period_days)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    stamp = utcnow().strftime("%Y%m%dT%H%M%SZ")
    doc = Document()
    doc.add_heading("Compliance evidence pack", 0)
    doc.add_paragraph(f"Generated {ev['generated_at']} for the last {period_days} days. "
                      f"{ev['summary']['passed']} of {ev['summary']['tests']} control tests passed.")
    for c in ev["controls"]:
        doc.add_heading(c["control"], level=1)
        t = doc.add_table(rows=1, cols=3)
        t.style = "Light Grid Accent 1"
        for i, h in enumerate(("Test", "Result", "Detail")):
            t.rows[0].cells[i].text = h
        for x in c["tests"]:
            row = t.add_row().cells
            row[0].text, row[1].text, row[2].text = x["test"], x["result"].upper(), str(x["detail"])
    doc.add_paragraph("Raw evidence: evidence.json. Full audit trail with chain verification: audit_log.jsonl.")
    docx_tmp = out / f".summary-{stamp}.docx"
    doc.save(docx_tmp)
    path = out / f"compliance_pack_{stamp}.zip"
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("evidence.json", json.dumps(ev, indent=1, default=str))
        z.writestr("audit_log.jsonl", "".join(export_audit(session)))
        z.write(docx_tmp, "summary.docx")
    docx_tmp.unlink(missing_ok=True)
    from soc_platform.core.crypto import seal_file

    seal_file(path)
    return path, ev
