"""Audit trail exports in the formats reviewers and tools ask for, and the facts about the log itself.

Formats: JSON Lines (one record per line, last line = chain verification - for SIEM / archiving), JSON (one document:
the export's details, then the records), CSV and Excel (.xlsx: the records plus a "About this export" sheet) for
spreadsheets, and Word (.docx: a readable audit report - a summary and the first ``DOCX_MAX_ROWS`` records).

Every format carries each record's ``prev_hash`` and ``hash`` (Word: the export's details only), so an unfiltered
export can be re-verified outside the platform, and every export states the whole chain's verification at the time.
Filters (time window, event type, actor, subject, from a sequence number) narrow what is exported; a filtered export
is a selection, so it is labelled as one and cannot be re-chained on its own.

Written without third-party spreadsheet libraries: the .xlsx is a minimal Office Open XML package built here
(inline strings only, so nothing in a cell is ever evaluated as a formula); CSV cells that a spreadsheet would run as
a formula are prefixed with ``'``.
"""

from __future__ import annotations

import csv
import io
import json
import re
import zipfile
from collections import Counter
from datetime import datetime
from typing import Any
from xml.sax.saxutils import escape

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from soc_platform.core.audit import AuditLog
from soc_platform.core.models import AuditRecord, utcnow

FORMATS = {
    "jsonl": ("application/x-ndjson", "jsonl", "JSON Lines - one record per line, chain verification last (SIEM, archive)"),
    "json": ("application/json", "json", "JSON - one document: export details and records"),
    "csv": ("text/csv", "csv", "CSV - opens in any spreadsheet"),
    "xlsx": ("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "xlsx",
             "Excel workbook - records plus an 'About this export' sheet"),
    "docx": ("application/vnd.openxmlformats-officedocument.wordprocessingml.document", "docx",
             "Word report - summary and the first records, for a reviewer"),
}
COLUMNS = ["seq", "ts_utc", "actor_type", "actor_id", "event_type", "subject_type", "subject_id", "trace_id",
           "payload", "prev_hash", "hash"]
XLSX_MAX_ROWS = 1_000_000        # Excel's sheet limit is 1,048,576 rows
XLSX_MAX_CELL = 32_000           # Excel's cell limit is 32,767 characters
DOCX_MAX_ROWS = 1_000
# Exactly what audit.compute_hash does, so anyone can re-check an export with any language's SHA-256 and JSON.
VERIFY_RECIPE = ("hash = lower-case hex SHA-256 of the UTF-8 JSON array [prev_hash, ts, actor_type, actor_id, "
                 "event_type, subject_type, subject_id, payload], written with sorted object keys, no spaces "
                 "(separators ',' and ':') and non-ASCII characters as \\u escapes. ts is the record's time in UTC "
                 "with six microsecond digits and no offset (2026-10-01T09:30:00.000000 - the ts_utc column without "
                 "its +00:00, and .000000 added when it has no fraction). The first record's prev_hash is 64 zeros; every later one is the hash of the record before.")
_BAD_XML = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\ud800-\udfff￾￿]")


# ---------------------------------------------------------------------------------------------- selecting


def parse_when(value: str | None, *, end: bool = False) -> datetime | None:
    """``2026-10-01`` or ``2026-10-01T09:30[:00][Z|+hh:mm]`` -> aware UTC. A bare date as the end of a window means
    the end of that day."""
    if not value:
        return None
    from datetime import UTC, timedelta

    v = value.strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(v)
    except ValueError as exc:
        raise ValueError(f"not a date or time: {value!r} (use 2026-10-01 or 2026-10-01T09:30)") from exc
    dt = dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)
    return dt + timedelta(days=1) if end and len(v) == 10 else dt


def records(session: Session, *, since_seq: int = 0, start: datetime | None = None, end: datetime | None = None,
            event_type: str | None = None, actor_id: str | None = None, subject_id: str | None = None) -> list[AuditRecord]:
    """Records in order. ``event_type`` ending in ``*`` is a prefix (``case.*``); ``end`` is exclusive."""
    q = select(AuditRecord).where(AuditRecord.seq > since_seq)
    if start:
        q = q.where(AuditRecord.ts >= start)
    if end:
        q = q.where(AuditRecord.ts < end)
    if event_type:
        et = event_type.strip()
        prefix = et[:-1].replace("\\", "\\\\").replace("%", r"\%").replace("_", r"\_")
        q = (q.where(AuditRecord.event_type.like(prefix + "%", escape="\\"))
             if et.endswith("*") else q.where(AuditRecord.event_type == et))
    if actor_id:
        q = q.where(AuditRecord.actor_id == actor_id.strip())
    if subject_id:
        q = q.where(AuditRecord.subject_id == subject_id.strip())
    return list(session.execute(q.order_by(AuditRecord.seq)).scalars())


def _row(r: AuditRecord) -> dict[str, Any]:
    return {"seq": r.seq, "ts_utc": r.ts.isoformat(), "actor_type": r.actor_type, "actor_id": r.actor_id,
            "event_type": r.event_type, "subject_type": r.subject_type, "subject_id": r.subject_id,
            "trace_id": r.trace_id, "payload": r.payload, "prev_hash": r.prev_hash, "hash": r.hash}


# ---------------------------------------------------------------------------------------------- exporting


def export(session: Session, fmt: str, *, by: str, filters: dict[str, Any]) -> tuple[bytes, str, str]:
    """``(body, media type, file name)``. ``filters``: since_seq, start, end, event_type, actor_id, subject_id."""
    if fmt not in FORMATS:
        raise ValueError(f"unknown format {fmt!r}: {', '.join(FORMATS)}")
    start, end = parse_when(filters.get("start")), parse_when(filters.get("end"), end=True)
    if start and end and end <= start:
        raise ValueError("the end of the window is before its start")
    rows = records(session, since_seq=int(filters.get("since_seq") or 0), start=start, end=end,
                   event_type=filters.get("event_type"), actor_id=filters.get("actor_id"),
                   subject_id=filters.get("subject_id"))
    used = {k: v for k, v in filters.items() if v not in (None, "", 0)}
    meta = {"exported_at": utcnow().isoformat(), "exported_by": by, "format": fmt, "filters": used,
            "records": len(rows), "first_seq": rows[0].seq if rows else None, "last_seq": rows[-1].seq if rows else None,
            "first_ts": rows[0].ts.isoformat() if rows else None, "last_ts": rows[-1].ts.isoformat() if rows else None,
            "selection": "filtered - a selection of the chain; verify the full log in the platform" if used else
                         "the whole log - re-verify by recomputing each hash over the previous one",
            "chain_verification": AuditLog(session).verify()}
    stamp = utcnow().strftime("%Y%m%d_%H%M%S")
    media, ext, _ = FORMATS[fmt]
    if fmt == "docx":
        from soc_platform.reporting.style import use_style

        with use_style(session):                      # the organisation's report style, like every Word report
            body = _docx(rows, meta)
    else:
        body = {"jsonl": _jsonl, "json": _json, "csv": _csv, "xlsx": _xlsx}[fmt](rows, meta)
    return body, media, f"audit_log_{stamp}.{ext}"


def _jsonl(rows: list[AuditRecord], meta: dict[str, Any]) -> bytes:
    out = [json.dumps({k: v for k, v in _row(r).items() if k != "ts_utc"} | {"ts": r.ts.isoformat()},
                      default=str, sort_keys=True) for r in rows]
    out.append(json.dumps({"_verification": meta["chain_verification"], "_head_hash": rows[-1].hash if rows else None,
                           "_exported_at": meta["exported_at"], "_export": {k: v for k, v in meta.items()
                                                                            if k != "chain_verification"}},
                          default=str))
    return ("\n".join(out) + "\n").encode("utf-8")


def _json(rows: list[AuditRecord], meta: dict[str, Any]) -> bytes:
    return json.dumps({"export": meta, "records": [_row(r) for r in rows]}, default=str, indent=1).encode("utf-8")


def _safe(v: Any) -> str:
    """A CSV cell a spreadsheet will not run as a formula."""
    s = v if isinstance(v, str) else json.dumps(v, default=str, sort_keys=True) if isinstance(v, (dict, list)) else (
        "" if v is None else str(v))
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


def _csv(rows: list[AuditRecord], meta: dict[str, Any]) -> bytes:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\r\n")
    w.writerow(COLUMNS)
    for r in rows:
        d = _row(r)
        w.writerow([d["seq"]] + [_safe(d[c]) for c in COLUMNS[1:]])
    return ("﻿" + buf.getvalue()).encode("utf-8")        # the BOM makes Excel read UTF-8


# ---------------------------------------------------------------------------------------------- xlsx


def _xs(v: Any) -> str:
    s = v if isinstance(v, str) else json.dumps(v, default=str, sort_keys=True) if isinstance(v, (dict, list)) else (
        "" if v is None else str(v))
    s = _BAD_XML.sub("", s)
    if len(s) > XLSX_MAX_CELL:
        s = s[:XLSX_MAX_CELL] + " …[cut: full text in the JSON export]"
    return escape(s)


def _ref(col: int, row: int) -> str:
    name = ""
    col += 1
    while col:
        col, rem = divmod(col - 1, 26)
        name = chr(65 + rem) + name
    return f"{name}{row}"


def _sheet(rows: list[list[Any]], widths: list[int], *, header: bool = True) -> str:
    out = [('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
           '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">')]
    if header:
        out.append('<sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" '
                   'state="frozen"/></sheetView></sheetViews>')
    out.append("<cols>" + "".join(f'<col min="{i + 1}" max="{i + 1}" width="{w}" customWidth="1"/>'
                                  for i, w in enumerate(widths)) + "</cols><sheetData>")
    for ri, row in enumerate(rows, 1):
        cells = []
        for ci, v in enumerate(row):
            style = ' s="1"' if header and ri == 1 else ""
            if isinstance(v, (int, float)) and not isinstance(v, bool):
                cells.append(f'<c r="{_ref(ci, ri)}"{style}><v>{v}</v></c>')
            elif v not in (None, ""):
                cells.append(f'<c r="{_ref(ci, ri)}" t="inlineStr"{style}><is><t xml:space="preserve">{_xs(v)}</t></is></c>')
        out.append(f'<row r="{ri}">{"".join(cells)}</row>')
    out.append("</sheetData>")
    if header and len(rows) > 1:
        out.append(f'<autoFilter ref="A1:{_ref(len(rows[0]) - 1, len(rows))}"/>')
    out.append("</worksheet>")
    return "".join(out)


def _about(meta: dict[str, Any]) -> list[list[Any]]:
    v = meta["chain_verification"]
    rows: list[list[Any]] = [["Item", "Value"],
                             ["Exported at (UTC)", meta["exported_at"]], ["Exported by", meta["exported_by"]],
                             ["Records in this export", meta["records"]],
                             ["Sequence numbers", f"{meta['first_seq']} to {meta['last_seq']}" if meta["records"] else "none"],
                             ["Period covered (UTC)", f"{meta['first_ts']} to {meta['last_ts']}" if meta["records"] else "none"],
                             ["Selection", meta["selection"]]]
    rows += [[f"Filter: {k}", str(val)] for k, val in meta["filters"].items()]
    rows += [["Whole chain verified at export", "yes" if v.get("ok") else f"NO - broken at #{v.get('first_bad_seq')}"],
             ["Records in the whole log", v.get("records")], ["Head of the chain", v.get("head") or ""],
             ["How to verify", VERIFY_RECIPE]]
    return rows


def _xlsx(rows: list[AuditRecord], meta: dict[str, Any]) -> bytes:
    data: list[list[Any]] = [COLUMNS]
    for r in rows[:XLSX_MAX_ROWS]:
        d = _row(r)
        data.append([d[c] for c in COLUMNS])
    about = _about(meta)
    if len(rows) > XLSX_MAX_ROWS:
        about.append(["Rows cut", (f"Excel holds {XLSX_MAX_ROWS:,} rows a sheet: the first {XLSX_MAX_ROWS:,} of "
                                  f"{len(rows):,} are here - export the rest from seq {rows[XLSX_MAX_ROWS].seq}")])
    ns = 'xmlns="http://schemas.openxmlformats.org/package/2006/relationships"'
    parts = {
        "[Content_Types].xml":
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<Types xmlns="http://schemas.openxmlformats.org/'
            'package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.'
            'relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/'
            'workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
            '<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.'
            'spreadsheetml.worksheet+xml"/><Override PartName="/xl/worksheets/sheet2.xml" ContentType="application/'
            'vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/><Override PartName="/xl/styles.xml" '
            'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/></Types>',
        "_rels/.rels":
            f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<Relationships {ns}><Relationship Id="rId1" '
            'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
            'Target="xl/workbook.xml"/></Relationships>',
        "xl/workbook.xml":
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<workbook xmlns="http://schemas.openxmlformats.org/'
            'spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
            '<sheets><sheet name="Audit log" sheetId="1" r:id="rId1"/><sheet name="About this export" sheetId="2" '
            'r:id="rId2"/></sheets>' + ('<definedNames><definedName name="_xlnm._FilterDatabase" localSheetId="0" '
                                        f'hidden="1">\'Audit log\'!$A$1:$K${len(data)}</definedName></definedNames>'
                                        if len(data) > 1 else '') + '</workbook>',
        "xl/_rels/workbook.xml.rels":
            f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<Relationships {ns}>'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" '
            'Target="worksheets/sheet1.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/'
            'officeDocument/2006/relationships/worksheet" Target="worksheets/sheet2.xml"/><Relationship Id="rId3" '
            'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>'
            '</Relationships>',
        "xl/styles.xml":
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<styleSheet xmlns="http://schemas.openxmlformats.org/'
            'spreadsheetml/2006/main"><fonts count="2"><font><sz val="10"/><name val="Calibri"/></font><font><b/>'
            '<sz val="10"/><color rgb="FFFFFFFF"/><name val="Calibri"/></font></fonts><fills count="3"><fill>'
            '<patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill><fill>'
            '<patternFill patternType="solid"><fgColor rgb="FF1F3864"/><bgColor indexed="64"/></patternFill></fill>'
            '</fills><borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>'
            '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>'
            '<cellXfs count="2"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/><xf numFmtId="0" '
            'fontId="1" fillId="2" borderId="0" xfId="0" applyFont="1" applyFill="1"/></cellXfs><cellStyles count="1">'
            '<cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles></styleSheet>',
        "xl/worksheets/sheet1.xml": _sheet(data, [8, 27, 10, 30, 28, 14, 34, 30, 60, 20, 20]),
        "xl/worksheets/sheet2.xml": _sheet(about, [32, 100]),
    }
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, text in parts.items():
            z.writestr(zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0)), text.encode("utf-8"),
                       compress_type=zipfile.ZIP_DEFLATED)
    return buf.getvalue()


# ---------------------------------------------------------------------------------------------- docx


def _docx(rows: list[AuditRecord], meta: dict[str, Any]) -> bytes:
    from soc_platform.reporting import design as D

    v = meta["chain_verification"]
    d = D.new_document("Audit trail", landscape=True)
    period = f"{meta['first_ts'][:16].replace('T', ' ')} to {meta['last_ts'][:16].replace('T', ' ')} UTC" \
        if meta["records"] else "no records in the selection"
    D.cover(d, "Audit trail", period, f"Exported {meta['exported_at'][:16].replace('T', ' ')} UTC by "
                                      f"{meta['exported_by']} · {meta['selection']}")
    D.tiles(d, [("Records in this export", meta["records"], "neutral"),
                ("People and agents", len({r.actor_id for r in rows}), "neutral"),
                ("Whole chain", "verified" if v.get("ok") else "BROKEN", "good" if v.get("ok") else "bad"),
                ("Records in the whole log", v.get("records"), "neutral")])
    D.section(d, "About this export", "What was selected and how the chain stands. The full records, with every "
                                     "hash, are in the JSON, CSV and Excel exports.")
    D.table(d, ["Item", "Value"], [[a, b] for a, b in _about(meta)[1:]], widths_cm=[6.5, 19.5])
    by_cat = Counter(r.event_type.split(".")[0] for r in rows)
    by_actor = Counter(f"{r.actor_type} · {r.actor_id}" for r in rows)
    D.section(d, "What happened", "Records by kind of event, and the people and agents who caused them.")
    D.table(d, ["Kind of event", "Records"], [[k, n] for k, n in by_cat.most_common()], numeric={1},
            widths_cm=[10, 4])
    D.table(d, ["Actor", "Records"], [[k, n] for k, n in by_actor.most_common(20)], numeric={1}, widths_cm=[14, 4],
            max_rows=20, more_note=f"{max(len(by_actor) - 20, 0)} more actors in the spreadsheet exports.")
    D.section(d, "Records", f"In order of the chain. The first {min(len(rows), DOCX_MAX_ROWS):,} of {len(rows):,}"
                            + (" - the Excel or CSV export holds all of them." if len(rows) > DOCX_MAX_ROWS else "."))
    D.table(d, ["#", "Time (UTC)", "Actor", "Event", "Subject", "Detail"],
            [[r.seq, r.ts.isoformat()[:19].replace("T", " "), f"{r.actor_type} · {r.actor_id}", r.event_type,
              f"{r.subject_type} {r.subject_id}", _BAD_XML.sub("", json.dumps(r.payload, default=str, sort_keys=True))[:160]]
             for r in rows[:DOCX_MAX_ROWS]],
            widths_cm=[1.4, 3.4, 5.2, 4.2, 4.6, 7.2], numeric={0}, empty="No records in the selection.")
    buf = io.BytesIO()
    d.save(buf)
    return buf.getvalue()


# ---------------------------------------------------------------------------------------------- facts


def info(session: Session, settings: Any) -> dict[str, Any]:
    """What the audit page states about the log: size, span, verification, what is recorded, retention, protection,
    access and export formats - every figure read from the database or the settings in force."""
    import os

    from soc_platform.core.auth import ROLE_PERMS, Perm
    from soc_platform.jobs import JOBS

    def interval(job: str) -> int:
        env, default = JOBS[job]
        return int(os.environ.get(env, default))

    total, first, last = session.execute(select(func.count(), func.min(AuditRecord.ts), func.max(AuditRecord.ts))).one()
    head = session.execute(select(AuditRecord.seq, AuditRecord.hash).order_by(AuditRecord.seq.desc()).limit(1)).first()
    by_type = session.execute(select(AuditRecord.event_type, AuditRecord.actor_type, func.count())
                              .group_by(AuditRecord.event_type, AuditRecord.actor_type)).all()
    cats: Counter[str] = Counter()
    actors: Counter[str] = Counter()
    for et, at, n in by_type:
        cats[et.split(".")[0]] += n
        actors[at] += n
    roles = lambda p: sorted(r.value for r, perms in ROLE_PERMS.items() if p in perms)
    self_check = interval("self_check") if "self_check" in JOBS else None
    return {
        "records": total, "first_ts": first.isoformat() if first else None, "last_ts": last.isoformat() if last else None,
        "head_seq": head[0] if head else None, "head_hash": head[1] if head else None,
        "by_actor_type": dict(sorted(actors.items())),
        "by_category": [{"category": k, "records": n} for k, n in cats.most_common()],
        "last_full_verification": AuditLog(session).checkpoint(),
        "self_check_seconds": self_check,
        "retention": {
            "audit": "kept indefinitely: the platform never edits or deletes audit records and the retention job "
                     "does not touch them; the database itself refuses to change or delete them",
            "other": [
                {"data": "Raw tool payloads and reported e-mail files", "days": settings.raw_retention_days,
                 "note": "the e-mail of a case still open is kept (legal hold); normalised records stay"},
                {"data": "Model prompts and answers", "days": settings.llm_log_retention_days,
                 "note": "token counts, cost and status are kept for budget reporting"},
                {"data": "Access log (every request)", "days": settings.access_log_retention_days, "note": ""},
                {"data": "High-volume activity (sign-ins, DNS, mail, secret access, elevations)",
                 "days": settings.event_retention_days or None,
                 "note": "0 keeps everything; anything a case, finding or override points at is kept"},
            ],
            "job_seconds": interval("retention") if "retention" in JOBS else None,
        },
        "protection": [
            ("Append-only: the application refuses to update or delete an audit record, and so does the database "
            "(triggers refuse UPDATE, DELETE and TRUNCATE on the table). With a separate runtime database role "
            "(SOC_DB_RUNTIME_ROLE) the platform signs in with insert and select rights only on it."),
            ("Hash-chained: each record's SHA-256 covers the previous record's hash, so an edit, deletion or "
            "re-ordering breaks every hash after it."),
            ("Verified: a full pass runs with the hourly self-check (its result is stored); the health check "
            "verifies records written since."),
            ("Anchored: after each full pass the chain's head (sequence and hash) is written to the log pipeline, "
            "outside the database - 'python -m soc_platform audit verify --anchor SEQ:HASH' proves the log still "
            "contains it."),
            ("Attributed and traceable: every record names its actor (person, agent or system) and carries the trace "
            "id of the request or job that caused it."),
            "Exports are audited themselves (who, which format, which filters).",
        ],
        "access": {"read": roles(Perm.READ_AUDIT), "export": roles(Perm.EXPORT_EVIDENCE),
                   "scope": "people limited to some domains see the records about those domains; exports need "
                            "all-domain access"},
        "formats": [{"format": k, "label": v[2]} for k, v in FORMATS.items()],
        "docx_max_rows": DOCX_MAX_ROWS,
    }
