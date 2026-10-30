"""Watch lists: what the SOC has named in advance - a block list and an exception list.

A lead uploads a list as an Excel workbook (.xlsx, every sheet is read) or a CSV: user names, e-mail addresses, host
names, IP addresses, domains, URLs, file hashes or device ids. When a case involves something on a list - an
alert's user or host, a phishing recipient, reporter, clicker, sender, link or attachment - the case says so: which
list, the entry, who added it and why.

Rules:

* **Context, never a decision.** A match is shown on the case, its investigation record and the case list. It does not
  change a severity, verdict, confidence or recommended action, and it never suppresses an alert: an exception-listed
  account that is compromised is still investigated in full.
* **Matched on identifiers, exactly** (case-insensitive): a user's address / account name, a host's name, FQDN, IP or
  device id, an indicator's value. A domain also matches its sub-domains, a sender address in it and a link to it. A
  bare user name matches the local part of an address only in the organisation's own domains (``SOC_ORG_DOMAINS``).
  A ``type`` column (or a typed column such as ``Hostname``) limits an entry to that kind; an untyped entry matches
  any kind of identifier.
* **Read when the case is read**, so an entry added or removed today applies to every case at once.
* **Every change is audited** (who, which file, what was added or removed); removed entries are kept, marked removed.
"""

from __future__ import annotations

import csv
import io
import ipaddress
import re
import zipfile
from collections import defaultdict
from collections.abc import Iterable
from datetime import datetime
from typing import Any
from xml.etree import ElementTree as ET  # nosec B405 - parts are refused if they declare a DTD or entity (_xml)

from sqlalchemy import Index, String, select
from sqlalchemy.orm import Mapped, Session, mapped_column

from soc_platform.core.audit import AuditLog
from soc_platform.core.auth import Perm, Principal
from soc_platform.core.db import Base, BoundedText, UTCDateTime
from soc_platform.core.identity import EMAIL_RE, is_builtin, split_account
from soc_platform.core.models import CaseEntity, Entity, EntityHint, EntityKey, new_id, utcnow
from soc_platform.core.text import unsafe_xml

LISTS = {"block": "Block list", "exception": "Exception list"}
KINDS = {"user": "user", "email": "e-mail address", "host": "host", "ip": "IP address", "domain": "domain",
         "url": "URL", "hash": "file hash", "any": "any identifier"}
MAX_FILE_BYTES = 5_000_000
MAX_XML_BYTES = 40_000_000           # an .xlsx is compressed: refuse a part that would unpack beyond this
MAX_ENTRIES = 10_000
MAX_COLUMNS = 256                    # cells further right are ignored: a cell at XFD would make every row 16,384 wide
_COLUMNS = {
    "user": ("username", "user_name", "user", "upn", "user_principal_name", "account", "account_name",
             "samaccountname", "login", "identity", "employee"),
    "email": ("email", "e_mail", "email_address", "mail", "sender", "sender_address", "address"),
    "host": ("host", "hostname", "host_name", "computer", "computer_name", "device", "device_name", "machine",
             "asset", "asset_name", "endpoint", "fqdn", "server", "workstation"),
    "ip": ("ip", "ip_address", "ipaddress", "ip_addr", "source_ip", "address_ip"),
    "domain": ("domain", "domain_name", "website"),
    "url": ("url", "link", "uri"),
    "hash": ("hash", "sha256", "sha1", "md5", "file_hash"),
    "any": ("value", "indicator", "ioc", "entity", "item", "identifier", "observable", "entry"),
}
_TYPE_COLUMNS = ("type", "kind", "category", "entity_type", "indicator_type", "ioc_type", "identifier_type")
_NOTE_COLUMNS = ("note", "notes", "reason", "comment", "comments", "description", "justification")
_TYPE_WORDS = {w: k for k, ws in _COLUMNS.items() for w in ws} | {"ipv4": "ip", "ipv6": "ip", "fqdn": "host",
                                                                   "e-mail": "email", "file": "hash"}
# which identifiers of a case an entry of each kind is compared with
_COMPARES = {"user": {"user"}, "email": {"user", "email"}, "host": {"host", "device"}, "ip": {"ip"},
             "domain": {"domain"}, "url": {"url"}, "hash": {"hash"}}
_PREFIX_KIND = {"email": "email", "domain": "domain", "ip": "ip", "url": "url", "sha256": "hash", "sha1": "hash",
                "md5": "hash"}
_SAM_RE = re.compile(r"[\w.'$-]{1,104}")
_HOST_RE = re.compile(r"[a-z0-9_]([a-z0-9_-]{0,62})(\.[a-z0-9_]([a-z0-9_-]{0,62}))*\.?")
_HASH_RE = re.compile(r"[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}")
_URL_RE = re.compile(r"(?:https?|ftp)://[^\s]{1,2000}", re.IGNORECASE)
_CHUNK = 500


class WatchlistEntry(Base):
    """One identifier on one list. Removing it keeps the row (``removed_at``), so the history stays readable."""

    __tablename__ = "watchlist_entries"
    __table_args__ = (Index("ix_watchlist_value", "list_name", "value"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    list_name: Mapped[str] = mapped_column(String(16), index=True)      # block | exception
    value: Mapped[str] = mapped_column(String(2048))                     # normalised (lower-case, canonical IP)
    kind: Mapped[str] = mapped_column(String(16))                        # user | email | host | ip | domain | url | hash | any
    written: Mapped[str] = mapped_column(BoundedText(2048), default="")  # as the file had it (ACME\jdoe)
    note: Mapped[str] = mapped_column(BoundedText(500), default="")
    source: Mapped[str] = mapped_column(BoundedText(256), default="")    # file (and sheet), or "console"
    added_by: Mapped[str] = mapped_column(String(256))
    added_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    removed_by: Mapped[str | None] = mapped_column(String(256), nullable=True)
    removed_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True, index=True)


# ---------------------------------------------------------------------------------------------- values


def guess_kind(s: str) -> str:
    """The kind an untyped value most likely is. Ambiguous ones (``web01``, ``jdoe``, ``corp.example``) stay ``any``."""
    try:
        ipaddress.ip_address(s)
        return "ip"
    except ValueError:
        pass
    if _URL_RE.fullmatch(s):
        return "url"
    if "@" in s:
        return "email"
    if "\\" in s:
        return "user"
    if _HASH_RE.fullmatch(s.lower()):
        return "hash"
    return "any"


def normalise(raw: str, kind: str | None = None) -> tuple[str, str] | str:
    """``(value, kind)`` for an identifier, or the reason it cannot be listed. ``ACME\\jdoe`` -> ``("jdoe", "user")``;
    ``Jane <Jane.Doe@x.com>`` -> ``("jane.doe@x.com", "email")``; ``10.0.0.05``-style IPs are made canonical."""
    s = (raw or "").strip().strip('"').strip("'").strip()
    if not s:
        return "empty"
    if len(s) > 2048 or any(ord(c) < 32 for c in s):
        return "not an identifier (too long, or control characters)"
    k = kind or guess_kind(s)
    if k in ("user", "email") or (k == "any" and "@" in s):
        if is_builtin(s):
            return "a built-in or machine account, not a person"
        _, user = split_account(s)
        u = user.strip().lower()
        if "@" in u:
            return (u, "email" if k == "email" else k) if EMAIL_RE.fullmatch(u) else "not a valid e-mail address"
        if k == "email":
            return "not a valid e-mail address"
        return (u, k) if _SAM_RE.fullmatch(u) else "not a valid user name"
    v = s.lower()
    if k == "ip":
        try:
            return str(ipaddress.ip_address(v)), "ip"
        except ValueError:
            return "not a valid IP address"
    if k == "url":
        return (v.rstrip("/"), "url") if _URL_RE.fullmatch(v) else "not a valid URL (http://, https:// or ftp://)"
    if k == "hash":
        return (v, "hash") if _HASH_RE.fullmatch(v) else "not an MD5, SHA-1 or SHA-256 hash"
    if k in ("host", "domain"):
        v = v.rstrip(".")
        return (v, k) if _HOST_RE.fullmatch(v) else f"not a valid {KINDS[k]} name"
    if any(c.isspace() for c in v):
        return "contains spaces - one identifier per cell"
    return v, "any"


# ---------------------------------------------------------------------------------------------- reading files


def read_rows(data: bytes, filename: str = "") -> list[tuple[str, list[str]]]:
    """``(where, cells)`` for every non-empty row: every sheet of an .xlsx workbook, or the lines of a CSV / text
    file. ``where`` names the place for the uploader ("Sheet1 row 5", "line 5")."""
    if len(data) > MAX_FILE_BYTES:
        raise ValueError(f"the file is larger than {MAX_FILE_BYTES // 1_000_000} MB - split it")
    name = (filename or "").lower()
    if data[:2] == b"PK":
        return _xlsx_rows(data)
    if data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" or name.endswith(".xls"):
        raise ValueError("this is an old Excel 97-2003 (.xls) file - save it as .xlsx (Excel Workbook) or CSV")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        text = data.decode("cp1252", errors="replace")
    lines = [(n, ln) for n, ln in enumerate(text.splitlines(), 1) if ln.strip() and not ln.lstrip().startswith("#")]
    if not lines:
        return []
    first = lines[0][1]
    delim = "\t" if "\t" in first and "," not in first else ";" if ";" in first and "," not in first else ","
    return [(f"line {n}", next(csv.reader([ln], delimiter=delim), [])) for n, ln in lines]


def _xml(z: zipfile.ZipFile, part: str) -> ET.Element | None:
    try:
        info = z.getinfo(part)
    except KeyError:
        return None
    if info.file_size > MAX_XML_BYTES:
        raise ValueError("the workbook is too large once unpacked - split it")
    raw = z.read(info)
    if unsafe_xml(raw):                  # a workbook never needs a DTD; refusing them closes XXE / entity expansion
        raise ValueError("the workbook contains a document type declaration or an unusual encoding - "
                         "not a normal Excel file")
    return ET.fromstring(raw)  # nosec B314 - DTDs, entities and multi-byte encodings refused above


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _col(ref: str) -> int:
    n = 0
    for ch in ref:
        if not ch.isalpha():
            break
        n = n * 26 + (ord(ch.upper()) - 64)
    return max(n - 1, 0)


def _text(si: ET.Element) -> str:
    """A string item's text: its <t>, or its rich-text runs' <t> (phonetic guides are left out)."""
    parts = [x for x in si if _local(x.tag) == "t"] or [t for r in si if _local(r.tag) == "r" for t in r if _local(t.tag) == "t"]
    return "".join(x.text or "" for x in parts)


def _xlsx_rows(data: bytes) -> list[tuple[str, list[str]]]:
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise ValueError("not a readable .xlsx workbook") from exc
    with z:
        if sum(i.file_size for i in z.infolist()) > MAX_XML_BYTES * 2:
            raise ValueError("the workbook is too large once unpacked - split it")
        wb = _xml(z, "xl/workbook.xml")
        if wb is None:
            raise ValueError("not an Excel workbook (.xlsx): no xl/workbook.xml")
        rels = _xml(z, "xl/_rels/workbook.xml.rels")
        target = {r.get("Id"): r.get("Target", "") for r in (rels if rels is not None else [])}
        shared: list[str] = []
        sst = _xml(z, "xl/sharedStrings.xml")
        for si in (sst if sst is not None else []):
            shared.append(_text(si))
        out: list[tuple[str, list[str]]] = []
        for sh in (x for x in wb.iter() if _local(x.tag) == "sheet"):
            rid = next((v for k, v in sh.attrib.items() if _local(k) == "id"), None)
            path = target.get(rid, "")
            path = path.lstrip("/") if path.startswith("/") else "xl/" + path
            ws = _xml(z, path)
            if ws is None:
                continue
            title = sh.get("name") or "sheet"
            for row in (r for r in ws.iter() if _local(r.tag) == "row"):
                cells: dict[int, str] = {}
                for c in (c for c in row if _local(c.tag) == "c"):
                    t, v = c.get("t"), next((x.text or "" for x in c if _local(x.tag) == "v"), "")
                    if t == "s":
                        val = shared[int(v)] if v.isdigit() and int(v) < len(shared) else ""
                    elif t == "inlineStr":
                        val = next((_text(x) for x in c if _local(x.tag) == "is"), "")
                    else:
                        val = v[:-2] if t in (None, "n") and v.endswith(".0") else v
                    col = _col(c.get("r") or "A") if c.get("r") else len(cells)
                    if col < MAX_COLUMNS:
                        cells[col] = val
                if any(x.strip() for x in cells.values()):
                    width = max(cells) + 1
                    out.append((f"{title} row {row.get('r') or len(out) + 1}", [cells.get(i, "") for i in range(width)]))
                if len(out) > MAX_ENTRIES * 2:
                    raise ValueError(f"a list holds at most {MAX_ENTRIES:,} entries")
        return out


def _head(cell: str) -> str:
    return re.sub(r"[\s\-/.]+", "_", (cell or "").strip().lower()).strip("_")


def parse(rows: list[tuple[str, list[str]]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """The entries in a file's rows, and a problem per rejected value. A header row (in each sheet) names the
    columns: identifier columns (``Username``, ``Hostname``, ``IP address``, ``Value``...; every one is read),
    optionally ``Type`` (for untyped columns) and ``Note`` / ``Reason``. Without a header, the first cell of each row
    is the identifier and the rest is the note."""
    out: list[dict[str, Any]] = []
    problems: list[dict[str, Any]] = []
    seen: set[str] = set()
    layout: tuple[list[tuple[int, str]], int, int] | None = None
    sheet = None
    for where, cells in rows:
        this_sheet = where.rsplit(" row ", 1)[0] if " row " in where else "csv"
        if this_sheet != sheet:
            sheet, layout = this_sheet, None
            head = [_head(c) for c in cells]
            ids = [(i, k) for i, h in enumerate(head) for k, ws in _COLUMNS.items() if h in ws]
            if ids:
                type_col = next((i for i, h in enumerate(head) if h in _TYPE_COLUMNS), -1)
                note_col = next((i for i, h in enumerate(head) if h in _NOTE_COLUMNS), -1)
                layout = (ids, type_col, note_col)
                continue
        if layout is None:
            values = [(cells[0] if cells else "", None)]
            note = ", ".join(c.strip() for c in cells[1:] if c.strip())
        else:
            ids, type_col, note_col = layout
            typed = _TYPE_WORDS.get(_head(cells[type_col])) if 0 <= type_col < len(cells) and cells[type_col].strip() else None
            if 0 <= type_col < len(cells) and cells[type_col].strip() and typed is None:
                problems.append({"where": where, "value": cells[type_col][:120],
                                 "problem": "unknown type (user, email, host, ip, domain, url or hash)"})
                continue
            values = [(cells[i] if i < len(cells) else "", typed if k == "any" else k) for i, k in ids]
            note = cells[note_col].strip() if 0 <= note_col < len(cells) else ""
        for raw, kind in values:
            if not str(raw).strip():
                continue
            got = normalise(str(raw), kind)
            if isinstance(got, str):
                problems.append({"where": where, "value": str(raw)[:120], "problem": got})
            elif got[0] in seen:
                problems.append({"where": where, "value": str(raw)[:120], "problem": "repeated in this file (first one kept)"})
            else:
                seen.add(got[0])
                out.append({"value": got[0], "kind": got[1], "written": str(raw).strip()[:2048], "note": note[:500],
                            "sheet": this_sheet if this_sheet != "csv" else ""})
        if len(out) > MAX_ENTRIES:
            raise ValueError(f"a list holds at most {MAX_ENTRIES:,} entries")
    return out, problems


# ---------------------------------------------------------------------------------------------- service


class WatchlistService:
    def __init__(self, session: Session) -> None:
        self.s = session
        self.audit = AuditLog(session)

    # ------------------------------------------------------------- reading
    def active(self, list_name: str | None = None) -> list[WatchlistEntry]:
        q = select(WatchlistEntry).where(WatchlistEntry.removed_at.is_(None))
        if list_name:
            q = q.where(WatchlistEntry.list_name == _check_list(list_name))
        return list(self.s.execute(q.order_by(WatchlistEntry.list_name, WatchlistEntry.value,
                                              WatchlistEntry.added_at)).scalars())

    def view(self) -> dict[str, Any]:
        by: dict[str, list[dict[str, Any]]] = {k: [] for k in LISTS}
        for e in self.active():
            by[e.list_name].append(entry_dict(e))
        return {"lists": [{"name": k, "label": v, "count": len(by[k]),
                           "by_kind": dict(sorted(_count(x["kind"] for x in by[k]).items())), "entries": by[k]}
                          for k, v in LISTS.items()],
                "kinds": KINDS, "max_entries": MAX_ENTRIES, "max_file_mb": MAX_FILE_BYTES // 1_000_000}

    def export_csv(self, list_name: str) -> str:
        buf = io.StringIO()
        w = csv.writer(buf, lineterminator="\n")
        w.writerow(["value", "type", "note", "added_by", "added_at", "source"])
        for e in self.active(list_name):
            w.writerow([_cell(e.value), e.kind, _cell(e.note), _cell(e.added_by), e.added_at.isoformat(), _cell(e.source)])
        return buf.getvalue()

    # ------------------------------------------------------------- changing
    def upload(self, list_name: str, data: bytes, by: Principal, *, filename: str = "", mode: str = "add",
               note: str = "", dry_run: bool = False) -> dict[str, Any]:
        """Add a file's entries to a list (``add``) or make the list equal the file (``replace``). ``dry_run``
        reports what would change and every rejected value without changing anything."""
        _may_manage(by)
        name = _check_list(list_name)
        if mode not in ("add", "replace"):
            raise ValueError("mode is add or replace")
        items, problems = parse(read_rows(data, filename))
        other = {e.value: e for e in self.active() if e.list_name != name}
        keep = []
        for it in items:
            clash = other.get(it["value"])
            if clash is not None:
                problems.append({"where": None, "value": it["written"][:120],
                                 "problem": f"already on the {LISTS[clash.list_name].lower()} - remove it there first"})
            else:
                keep.append(it)
        if not keep:
            raise ValueError("the file has no entry that can be listed" +
                             (f" ({len(problems)} value(s) rejected: {problems[0]['problem']})" if problems else ""))
        current = {e.value: e for e in self.active(name)}
        added = [i for i in keep if i["value"] not in current]
        wanted = {i["value"] for i in keep}
        removed = [e for v, e in current.items() if v not in wanted] if mode == "replace" else []
        after = len(current) + len(added) - len(removed)
        if after > MAX_ENTRIES:
            raise ValueError(f"a list holds at most {MAX_ENTRIES:,} entries; this would make {after:,}")
        result = {"list": name, "label": LISTS[name], "mode": mode, "dry_run": dry_run, "valid": len(keep),
                  "added": [{"value": i["value"], "kind": i["kind"], "note": i["note"]} for i in added],
                  "added_by_kind": dict(sorted(_count(i["kind"] for i in added).items())),
                  "already_listed": len(keep) - len(added), "removed": sorted(e.value for e in removed),
                  "problems": problems, "count_after": after}
        if dry_run:
            return result
        now, fname = utcnow(), (filename or "console").strip()[:200]
        for i in added:
            self.s.add(WatchlistEntry(list_name=name, value=i["value"], kind=i["kind"], written=i["written"],
                                      note=i["note"] or note[:500], added_by=by.id, added_at=now,
                                      source=f"{fname} ({i['sheet']})"[:256] if i["sheet"] else fname))
        for e in removed:
            e.removed_at, e.removed_by = now, by.id
        self.s.flush()
        self.audit.append(actor_type=by.actor_type, actor_id=by.id, event_type="watchlist.uploaded",
                          subject_type="watchlist", subject_id=name,
                          payload={"mode": mode, "file": fname, "note": note[:500],
                                   "added": [f"{i['kind']}:{i['value']}" for i in added][:500],
                                   "removed": result["removed"][:500], "added_count": len(added),
                                   "removed_count": len(removed), "already_listed": result["already_listed"],
                                   "rejected": len(problems), "count_after": after})
        return result

    def remove(self, entry_id: str, by: Principal, reason: str = "") -> WatchlistEntry:
        _may_manage(by)
        e = self.s.get(WatchlistEntry, entry_id)
        if e is None or e.removed_at is not None:
            raise KeyError(f"no listed entry {entry_id}")
        e.removed_at, e.removed_by = utcnow(), by.id
        self.s.flush()
        self.audit.append(actor_type=by.actor_type, actor_id=by.id, event_type="watchlist.entry_removed",
                          subject_type="watchlist", subject_id=e.list_name,
                          payload={"value": e.value, "kind": e.kind, "entry": e.id, "reason": (reason or "")[:500]})
        return e

    # ------------------------------------------------------------- matching cases
    def case_matches(self, case_ids: list[str], org_domains: list[str] | None = None) -> dict[str, list[dict[str, Any]]]:
        """For each case, the people, hosts and indicators on a list: ``{case_id: [match, ...]}``, block list first.
        A few queries per 500 cases, whatever the size of the lists."""
        entries = self.active()
        if not entries or not case_ids:
            return {}
        index: dict[str, list[WatchlistEntry]] = defaultdict(list)
        for e in entries:
            index[e.value].append(e)
        own = {d.lower() for d in (org_domains or [])}
        found: dict[str, dict[tuple[str, str, str], dict[str, Any]]] = defaultdict(dict)
        ids = sorted(set(case_ids))
        for i in range(0, len(ids), _CHUNK):
            links = self.s.execute(
                select(CaseEntity.case_id, CaseEntity.role, Entity.id, Entity.kind, Entity.display_name)
                .join(Entity, Entity.id == CaseEntity.entity_id)
                .where(CaseEntity.case_id.in_(ids[i:i + _CHUNK]),
                       Entity.kind.in_(("identity", "asset", "indicator")))).all()
            idents = self._identifiers({(eid, kind, name) for _, _, eid, kind, name in links}, own)
            for cid, role, eid, kind, name in links:
                for ikind, val, how in idents.get(eid, []):
                    for e in index.get(val, []):
                        if e.kind == "any" or ikind in _COMPARES.get(e.kind, set()):
                            found[cid].setdefault((e.list_name, eid, e.id), {
                                "list": e.list_name, "list_label": LISTS[e.list_name], "entity_id": eid,
                                "kind": kind, "name": _plain(kind, name), "role": role, "matched_on": how,
                                "entry": entry_dict(e)})
        order = list(LISTS)
        return {cid: sorted(m.values(), key=lambda x: (order.index(x["list"]), x["name"], x["entry"]["value"]))
                for cid, m in found.items()}

    def _identifiers(self, ents: set[tuple[str, str, str]], own: set[str]) -> dict[str, list[tuple[str, str, str]]]:
        """Every identifier of each entity as ``(kind, value, how it is described)``, lower-case."""
        out: dict[str, list[tuple[str, str, str]]] = defaultdict(list)
        kind_of = {eid: kind for eid, kind, _ in ents}
        eids = sorted(kind_of)
        for i in range(0, len(eids), _CHUNK):
            part = eids[i:i + _CHUNK]
            keys = self.s.execute(select(EntityKey.entity_id, EntityKey.key_name, EntityKey.key_value)
                                  .where(EntityKey.entity_id.in_(part))).all()
            hints = self.s.execute(select(EntityHint.entity_id, EntityHint.hint_name, EntityHint.hint_value)
                                   .where(EntityHint.entity_id.in_(part),
                                          EntityHint.hint_name.in_(("hostname", "fqdn", "ip")))).all()
            for eid, name, val in [*keys, *hints]:
                out[eid] += _describe(kind_of[eid], name, (val or "").strip().lower(), own)
        for eid, kind, name in ents:
            if kind == "asset" and name:
                out[eid] += _describe("asset", "fqdn", name.strip().lower(), own)
        return {eid: sorted(set(v)) for eid, v in out.items()}


def _describe(kind: str, key: str, val: str, own: set[str]) -> list[tuple[str, str, str]]:
    if not val:
        return []
    if kind == "identity":
        if key in ("upn", "email"):
            local, _, dom = val.partition("@")
            return [("user", val, f"address {val}")] + ([("user", local, f"user name {local} ({val})")] if dom in own else [])
        return [("user", val, f"account name {val}")] if key == "sam" else []
    if kind == "asset":
        if key in ("hostname", "fqdn"):
            short = val.split(".")[0]
            return [("host", val, f"host {val}")] + ([("host", short, f"host {val}")] if short != val else [])
        if key == "ip":
            return [("ip", _ip(val), f"IP address {val}")]
        return [("device", val, f"{key.replace('_', ' ')} {val}")]
    if key != "value" or ":" not in val:                  # indicators: "<type>:<value>"
        return []
    prefix, v = val.split(":", 1)
    k = _PREFIX_KIND.get(prefix, prefix)
    if k == "email":
        dom = v.partition("@")[2]
        return [("email", v, f"sender address {v}")] + [("domain", d, f"sender address {v}") for d in _parents(dom)]
    if k == "domain":
        return [("domain", d, f"domain {v}") for d in _parents(v)]
    if k == "url":
        host = re.sub(r"^[a-z]+://", "", v).split("/")[0].split(":")[0]
        return [("url", v.rstrip("/"), f"link {v}")] + [("domain", d, f"link {v}") for d in _parents(host)]
    return [(k, _ip(v) if k == "ip" else v, f"{KINDS.get(k, k)} {v}")]


def _ip(v: str) -> str:
    """An address in the one form list entries are stored in (``2001:DB8:0:0::1`` -> ``2001:db8::1``)."""
    try:
        return str(ipaddress.ip_address(v))
    except ValueError:
        return v


def _plain(kind: str, name: str) -> str:
    """An indicator's name without its type prefix (``domain:x.com`` -> ``x.com``)."""
    if kind == "indicator" and ":" in (name or "") and name.split(":", 1)[0] in (*_PREFIX_KIND, "hash"):
        return name.split(":", 1)[1]
    return name or ""


def _parents(dom: str) -> list[str]:
    """``a.b.example.com`` -> itself, ``b.example.com``, ``example.com`` (never a bare top-level label)."""
    labels = [x for x in dom.strip(".").split(".") if x]
    return [".".join(labels[i:]) for i in range(max(len(labels) - 1, 1))] if labels else []


def _count(items: Iterable[str]) -> dict[str, int]:
    out: dict[str, int] = defaultdict(int)
    for x in items:
        out[x] += 1
    return dict(out)


def entry_dict(e: WatchlistEntry) -> dict[str, Any]:
    return {"id": e.id, "list": e.list_name, "value": e.value, "kind": e.kind, "kind_label": KINDS.get(e.kind, e.kind),
            "written": e.written, "note": e.note, "source": e.source, "added_by": e.added_by,
            "added_at": e.added_at.isoformat()}


def _check_list(name: str) -> str:
    if name not in LISTS:
        raise ValueError(f"unknown list {name!r}: {', '.join(LISTS)}")
    return name


def _may_manage(by: Principal) -> None:
    if by.is_service or by.is_agent or not by.can(Perm.MANAGE_WATCHLISTS):
        raise PermissionError("a person with manage_watchlists (a lead) changes the watch lists")


def _cell(v: Any) -> str:
    """A CSV cell a spreadsheet will not run as a formula (=, +, -, @ at the start)."""
    s = str(v if v is not None else "")
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s
