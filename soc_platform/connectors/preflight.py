"""Preflight: everything a tool must pass before it is trusted in workflows, checked in one go and explained.

The old *Test* read one page of one stream. A preflight checks, and says how to fix each failure:

1. configuration   - every required setting and secret present and well-formed (``config_schema``)
2. start-up        - the connector can be built from that configuration
3. sign-in         - the tool is reachable and accepts the credentials (stops here if not: no retry storm)
4. every stream    - one page each: the permission it needs (named when missing), records parse, how fresh the newest
                     record is (a clock or time-zone fault shows as times in the future), and the volume to expect
5. actions         - the write permissions approved actions will need (listed; never exercised - that would change
                     the tool)

It builds its own connector instance, so its reads share no paging or watermark state with the running one. Nothing is
written to the context store. The result is a checklist: ``ok`` is False when any check is an error; warnings are
allowed through but shown to whoever approves the change.
"""

from __future__ import annotations

import hashlib
import json
import time
from datetime import UTC, datetime, timedelta
from typing import Any

from soc_platform.connectors.base import AuthExpired, ConnectorError, PermissionDenied, RateLimited, TransientError

PARSE_SAMPLE = 20
FUTURE = timedelta(hours=1)
OLD_DAYS = 30
STREAM_BUDGET_S = 90.0          # a whole preflight stops reading further streams after this long
# Records whose time says when something happened (so a very old newest one means no fresh data reaches us). Assets,
# findings and tickets carry first-seen or creation times: old ones are normal.
EVENT_KINDS = {"alert", "signin", "dns", "mail_event", "secret_access", "elevation", "deception"}


def _redact(msg: str) -> str:
    from soc_platform.connectors.tools._common import _redact as r

    return r(msg)


def _check(name: str, status: str, detail: str, fix: str = "", **extra: Any) -> dict[str, Any]:
    return {"check": name, "status": status, "detail": detail, "fix": fix, **extra}


def fingerprint(registry: Any, name: str) -> str:
    """What the preflight was run against: stage and non-secret settings, plus *whether* each secret is set (never
    the secret itself). An approval compares it, so a passing result cannot vouch for a different configuration."""
    m = registry.manifests[name]
    s = registry.settings_for(name)
    secret_names = {f.name for f in m.config if f.secret}
    body = {"stage": registry.stage_of(name),
            "settings": {k: (bool(v) if k in secret_names else v) for k, v in sorted(s.items())}}
    return hashlib.sha256(json.dumps(body, sort_keys=True, default=str).encode()).hexdigest()[:24]


def _classify(exc: Exception, read_scopes: list[str]) -> tuple[str, str, str]:
    """(status, detail, fix) for a failed read."""
    text = _redact(str(exc))[:300]
    if isinstance(exc, PermissionDenied):
        return ("error", "the tool refused this read (403)",
                "grant the read permission" + (f": {', '.join(read_scopes)}" if read_scopes else "") +
                " to the integration account (and grant admin consent where the tool needs it)")
    if isinstance(exc, AuthExpired):
        return ("error", "the credentials were refused (401) even after a fresh token",
                "check the client id / secret (or user / password) and that the account is enabled and not expired")
    if isinstance(exc, RateLimited):
        return ("warning", "the tool is throttling requests right now",
                "run the preflight again later; if it persists, ask the vendor for a higher API rate")
    if "HTML page" in text:
        return ("error", text, ("a proxy, firewall or sign-in page answered: allow the API host through the egress "
                                "proxy (HTTPS_PROXY / NO_PROXY) and check the base URL"))
    if isinstance(exc, TransientError) or "gave up after" in text:
        hint = ("the TLS certificate is not trusted: install the inspecting proxy's CA (SSL_CERT_FILE)"
                if "CERTIFICATE" in text.upper() or "SSL" in text.upper() else
                "check the base URL, DNS, the firewall / egress allow-list and the proxy settings")
        return ("error", f"the tool could not be reached: {text}", hint)
    if isinstance(exc, ConnectorError):
        return ("error", text, "see the message; correct the setting it names")
    return ("error", f"{type(exc).__name__}: {text}", "this looks like a defect in the connector: report it with this message")


def _aware(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt


def _stream(conn: Any, stream: str, now: datetime) -> dict[str, Any]:
    t0 = time.perf_counter()
    page = conn.fetch_page(stream, None)
    ms = round((time.perf_counter() - t0) * 1000, 1)
    recs = list(page.records or [])
    parsed, bad, first_bad, times, kinds = 0, 0, "", [], set()
    for raw in recs[:PARSE_SAMPLE]:
        try:
            for r in conn.normalize(stream, raw):
                parsed += 1
                kinds.add(r.kind)
                if r.observed_at:
                    times.append(_aware(r.observed_at))
        except Exception as exc:  # a record the connector cannot read is counted and shown, not raised
            bad += 1
            first_bad = first_bad or f"{type(exc).__name__}: {_redact(str(exc))[:160]}"
    newest = max(times) if times else None
    oldest = min(times) if times else None
    row: dict[str, Any] = {"stream": stream, "records": len(recs), "latency_ms": ms, "more": page.more,
                           "source_total": page.source_total, "newest": newest.isoformat() if newest else None}
    notes, status = [], "ok"
    if bad:
        status = "warning"
        notes.append(f"{bad} of {min(len(recs), PARSE_SAMPLE)} sampled records could not be read ({first_bad})")
    if newest and newest > now + FUTURE:
        status = "warning"
        notes.append("records are dated in the future: the tool's clock or time zone is wrong (times are read as UTC "
                     "unless the record says otherwise)")
    elif newest and kinds and kinds <= EVENT_KINDS and (now - newest).days > OLD_DAYS:
        status = "warning"
        notes.append(f"the newest record is {(now - newest).days} days old: is this the right tenant / workspace, and "
                     "is the licence for this data active?")
    if not recs:
        notes.append("no records yet (an empty tenant, or nothing in the default time window)")
    if page.source_total:
        row["volume"] = f"about {page.source_total:,} record{'' if page.source_total == 1 else 's'} in the tool"
    elif page.more and oldest and newest and newest > oldest:
        per_day = len(recs) / max((newest - oldest).total_seconds() / 86400, 1 / 24)
        row["volume"] = f"about {int(per_day):,} records a day"
    elif not page.more:
        row["volume"] = f"{len(recs):,} record{'' if len(recs) == 1 else 's'} (one page)"
    row["status"], row["notes"] = status, notes
    return row


def run_preflight(registry: Any, name: str) -> dict[str, Any]:
    """Run every check for one connector as currently configured in ``registry``."""
    from soc_platform.connectors.config_schema import STAGE_LABELS, check_entry
    from soc_platform.core.models import utcnow

    started, now = time.perf_counter(), utcnow()
    m = registry.manifests[name]
    stage = registry.stage_of(name)
    checks: list[dict[str, Any]] = []
    out: dict[str, Any] = {"connector": name, "tool": m.tool, "stage": stage, "stage_label": STAGE_LABELS.get(stage),
                           "mode": registry.mode_of(name), "ran_at": now.isoformat(), "checks": checks}

    def finish() -> dict[str, Any]:
        errs = sum(c["status"] == "error" for c in checks)
        warns = sum(c["status"] == "warning" for c in checks) + sum(
            s.get("status") == "warning" for c in checks for s in c.get("streams", []))
        out.update({"ok": errs == 0, "errors": errs, "warnings": warns,
                    "verdict": "not ready" if errs else "ready with warnings" if warns else "ready",
                    "duration_ms": round((time.perf_counter() - started) * 1000), "fingerprint": fingerprint(registry, name)})
        return out

    problems = [p for p in check_entry(name, registry.config.get(name), registry.manifests,
                                       default_mode=registry.default_mode) if p.level == "error"]
    problems_text = [str(p) for p in problems] + [x for x in registry.problems_of(name)
                                                  if not any(p.where.split(".")[-1] in x for p in problems)]
    if problems_text:
        checks.append(_check("Configuration", "error", "; ".join(problems_text)[:1200],
                             "; ".join(p.fix for p in problems if p.fix)[:600] or "complete the settings named"))
        return finish()
    checks.append(_check("Configuration", "ok", "every required setting and secret is present and well-formed"))

    try:
        inst = registry.construct(name)
    except Exception as exc:  # reported as a failed check: the preflight itself never fails
        checks.append(_check("Start-up", "error", f"{type(exc).__name__}: {_redact(str(exc))[:300]}",
                             "correct the setting the message names"))
        return finish()
    conn = inst.connector
    read_scopes = list(getattr(conn, "read_scopes", ()) or [])

    streams = list(conn.streams)
    if not streams:
        checks.append(_check("Sign-in", "ok", "no pull streams: this tool is queried on demand (lookups) or pushes to "
                                              "the platform", lookups=list(conn.lookups)))
    else:
        rows, signed_in, stopped = [], False, ""
        for st in streams:
            if stopped:
                rows.append({"stream": st, "status": "skipped", "notes": [stopped]})
                continue
            if time.perf_counter() - started > STREAM_BUDGET_S:
                stopped = "not read: the preflight time budget was used up by slower streams"
                rows.append({"stream": st, "status": "skipped", "notes": [stopped]})
                continue
            try:
                rows.append(_stream(conn, st, now))
                signed_in = True
            except Exception as exc:  # each failure is classified into a check with a fix
                status, detail, fix = _classify(exc, read_scopes)
                rows.append({"stream": st, "status": status, "notes": [detail], "fix": fix})
                if isinstance(exc, AuthExpired) or (not signed_in and status == "error"
                                                    and not isinstance(exc, PermissionDenied)):
                    stopped = "not read: sign-in or connection failed on an earlier stream"
        refused = [r for r in rows if r["status"] == "error"]
        if signed_in:
            checks.append(_check("Sign-in", "ok", "reached the tool and the credentials were accepted"
                                 if inst.mode == "live" else "read the sample data (Fixtures stage: no network, no "
                                                             "credentials - run it again after moving to a live stage)"))
        else:
            first = refused[0] if refused else {"notes": ["no stream could be read"], "fix": ""}
            checks.append(_check("Sign-in", "error", first["notes"][0], first.get("fix", "")))
        if refused and signed_in:
            checks.append(_check("Permissions", "error",
                                 f"{len(refused)} of {len(rows)} streams refused: "
                                 + ", ".join(r["stream"] for r in refused),
                                 refused[0].get("fix", "")))
        elif signed_in:
            checks.append(_check("Permissions", "ok", f"every stream readable ({len(rows)})"))
        checks.append(_check("Streams", "warning" if any(r["status"] == "warning" for r in rows) else
                             "ok" if signed_in else "skipped", f"{sum(r['status'] == 'ok' for r in rows)} of "
                             f"{len(rows)} streams read cleanly", streams=rows))

    write_scopes = list(getattr(conn, "write_scopes", ()) or [])
    try:
        n_actions = len(list(m.actions(conn)))
    except Exception:  # an action factory fault is shown, not raised
        n_actions = 0
    if n_actions:
        checks.append(_check("Actions", "info",
                             f"{n_actions} action(s) available"
                             + (f"; they need: {', '.join(write_scopes)}" if write_scopes else "")
                             + ". Not exercised - that would change the tool.",
                             "grant the write permissions before moving to the Recommend stage"
                             if stage in ("fake", "record", "read") else ""))
    return finish()
