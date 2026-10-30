"""Ownership mapping uploaded from the console: which team owns which hosts and cloud resources.

Wiz reports cloud resources - storage accounts, cloud VMs, clusters, databases - that the CMDB does not hold, so a
misconfiguration or vulnerability on them has nobody to route to. A lead or an administrator uploads the mapping as
an Excel workbook (.xlsx, every sheet) or a CSV. Each row names what it covers and who owns it:

* **what**: a resource or host name (wildcards ``*`` and ``?`` allowed: ``acme-prod-*``), and/or a subscription /
  account / project; optionally narrowed to one cloud (``azure``, ``aws``, ``gcp``) or one resource type
* **who**: the owning team (required), and optionally the owner, environment and criticality

Rules:

* **Fills gaps, never overrides.** ServiceNow and the ownership-file connector are asked first; this mapping answers
  only where they give no team.
* **The most specific row wins**: an exact name, then a name pattern, then a subscription / account; ties go to the
  row higher in the file.
* **Each upload replaces the mapping** as a new version (who, when, which file, why - audited); the history is kept
  and the mapping can be cleared. It applies at once to open findings and misconfigurations, and at every refresh.
* Criticality feeds the vulnerability priority exactly as a CMDB criticality does (computed, never the model).
"""

from __future__ import annotations

import csv
import fnmatch
import io
import re
from collections import Counter
from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Integer, String, select
from sqlalchemy.orm import Mapped, Session, mapped_column

from soc_platform.core.audit import AuditLog
from soc_platform.core.auth import Perm, Principal
from soc_platform.core.db import Base, BoundedText, UTCDateTime
from soc_platform.core.models import utcnow

MAX_ROWS = 10_000
CRITICALITY = ("critical", "high", "medium", "low")
# header spellings people use, after lower-casing and joining words with "_"
_HEADERS = {
    "name": ("name", "hostname", "host", "host_name", "resource", "resource_name", "asset", "asset_name", "computer",
             "computer_name", "server", "device", "device_name", "fqdn", "machine", "bucket", "storage_account", "vm",
             "vm_name"),
    "subscription": ("subscription", "subscription_id", "subscription_name", "account", "account_id", "aws_account",
                     "aws_account_id", "project", "project_id", "gcp_project", "cloud_account"),
    "cloud": ("cloud", "provider", "cloud_provider", "cloud_platform"),
    "resource_type": ("resource_type", "type", "kind", "asset_type"),
    "team": ("team", "platform_team", "owning_team", "owner_team", "support_group", "assignment_group", "group",
             "squad", "responsible_team"),
    "owner": ("owner", "owner_email", "owner_upn", "owned_by", "contact", "technical_owner", "responsible"),
    "environment": ("environment", "env", "stage"),
    "criticality": ("criticality", "business_criticality", "importance", "tier"),
    "note": ("note", "notes", "comment", "comments", "description", "reason"),
}
_FIELD_OF = {alias: field for field, aliases in _HEADERS.items() for alias in aliases}
_CLOUDS = {"azure": "azure", "microsoft": "azure", "aws": "aws", "amazon": "aws", "gcp": "gcp", "google": "gcp",
           "oci": "oci", "oracle": "oci", "alibaba": "alibaba"}
_CRIT_WORDS = {"critical": "critical", "crit": "critical", "very high": "critical", "high": "high",
               "medium": "medium", "med": "medium", "moderate": "medium", "low": "low"}


class OwnershipVersion(Base):
    """One uploaded version of the mapping; the newest is in force (an empty one = cleared)."""

    __tablename__ = "ownership_mappings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    rows: Mapped[list[dict[str, Any]]] = mapped_column(JSON)
    filename: Mapped[str] = mapped_column(BoundedText(200), default="")
    set_by: Mapped[str] = mapped_column(String(256))
    note: Mapped[str] = mapped_column(BoundedText(500), default="")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)


# ---------------------------------------------------------------------------------------------- reading a file


def _head(cell: str) -> str:
    return re.sub(r"[\s\-/.]+", "_", (cell or "").strip().lower()).strip("_")


def _type(v: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", v.strip().lower()).strip("_")


def parse(rows: list[tuple[str, list[str]]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """The mapping rows in a file's rows, and a problem per row that cannot be used. Each sheet needs a header row
    with a team column and a name or subscription column."""
    out: list[dict[str, Any]] = []
    problems: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str]] = set()
    cols: dict[str, int] | None = None
    sheet = None
    for where, cells in rows:
        this_sheet = where.rsplit(" row ", 1)[0] if " row " in where else "csv"
        if this_sheet != sheet:
            sheet, cols = this_sheet, None
            found: dict[str, int] = {}
            for i, c in enumerate(cells):
                f = _FIELD_OF.get(_head(c))
                if f and f not in found:
                    found[f] = i
            if "team" in found and ("name" in found or "subscription" in found):
                cols = found
            else:
                problems.append({"where": where, "value": ", ".join(c for c in cells if c)[:120],
                                 "problem": "no header row naming a team column and a resource / host name or "
                                            "subscription column - this sheet was skipped"})
            continue
        if cols is None:
            continue

        def cell(field: str, row: list[str] = cells, at: dict[str, int] = cols) -> str:
            i = at.get(field, -1)
            return (row[i] if 0 <= i < len(row) else "").strip()

        got = {f: cell(f) for f in _HEADERS}
        if any(any(ord(ch) < 32 for ch in v) for v in got.values()):
            problems.append({"where": where, "value": got["name"][:120], "problem": "control characters in a cell"})
            continue
        name, sub, team = got["name"].lower().rstrip("."), got["subscription"].lower(), got["team"]
        if not name and not sub:
            problems.append({"where": where, "value": team[:120],
                             "problem": "needs a resource / host name or a subscription / account"})
            continue
        if not team:
            problems.append({"where": where, "value": (name or sub)[:120], "problem": "no owning team"})
            continue
        if len(name) > 256 or len(sub) > 128 or len(team) > 128 or any(c.isspace() for c in name):
            problems.append({"where": where, "value": (name or sub)[:120],
                             "problem": "name over 256 characters or with spaces, subscription over 128 or team over 128"})
            continue
        crit = got["criticality"].lower()
        if crit and crit not in _CRIT_WORDS:
            problems.append({"where": where, "value": got["criticality"][:120],
                             "problem": "criticality is critical, high, medium or low"})
            continue
        cloud = _CLOUDS.get(got["cloud"].lower(), _type(got["cloud"])) if got["cloud"] else ""
        rtype = _type(got["resource_type"]) if got["resource_type"] else ""
        key = (name, sub, cloud, rtype)
        if key in seen:
            problems.append({"where": where, "value": (name or sub)[:120], "problem": "repeated in this file (first one kept)"})
            continue
        seen.add(key)
        out.append({"name": name, "subscription": sub, "cloud": cloud, "resource_type": rtype, "team": team,
                    "owner": got["owner"][:256], "environment": got["environment"][:64],
                    "criticality": _CRIT_WORDS.get(crit, ""), "note": got["note"][:300],
                    "where": where})
        if len(out) > MAX_ROWS:
            raise ValueError(f"the mapping holds at most {MAX_ROWS:,} rows - split it by team or subscription")
    return out, problems


# ---------------------------------------------------------------------------------------------- matching


def match(rows: list[dict[str, Any]], attrs: dict[str, Any]) -> dict[str, Any] | None:
    """The row that owns an asset or cloud resource (``hostname`` / ``fqdn`` / ``resource_name``, ``subscription``,
    ``cloud``, ``resource_type``), or None. Exact name > name pattern > subscription; ties go to the earlier row."""
    full = {str(attrs.get(k) or "").strip().lower().rstrip(".") for k in ("hostname", "fqdn", "resource_name")}
    names = {n for n in full if n} | {n.split(".")[0] for n in full if n}
    sub = str(attrs.get("subscription") or "").strip().lower()
    cloud = _CLOUDS.get(str(attrs.get("cloud") or "").lower(), _type(str(attrs.get("cloud") or "")))
    rtype = _type(str(attrs.get("resource_type") or ""))
    best, best_rank = None, 9
    for r in rows:
        if (r.get("cloud") and r["cloud"] != cloud) or (r.get("resource_type") and r["resource_type"] != rtype):
            continue
        sub_ok = bool(sub) and bool(r.get("subscription")) and fnmatch.fnmatchcase(sub, r["subscription"])
        if r.get("name"):
            if not any(fnmatch.fnmatchcase(n, r["name"]) for n in names):
                continue
            if r.get("subscription") and not sub_ok:
                continue
            rank = 1 if any(ch in r["name"] for ch in "*?[") else 0
        elif sub_ok:
            rank = 2
        else:
            continue
        if rank < best_rank:
            best, best_rank = r, rank
    if best is None:
        return None
    return {"owner": best.get("owner") or None, "platform_team": best["team"],
            "environment": best.get("environment") or None, "criticality": best.get("criticality") or None,
            "source": "ownership_upload", "matched_on": best.get("name") or best.get("subscription")}


# ---------------------------------------------------------------------------------------------- the store


class OwnershipStore:
    def __init__(self, session: Session) -> None:
        self.s = session
        self._rows: list[dict[str, Any]] | None = None

    def active_row(self) -> OwnershipVersion | None:
        return self.s.execute(select(OwnershipVersion).order_by(OwnershipVersion.id.desc()).limit(1)).scalars().first()

    def rows(self) -> list[dict[str, Any]]:
        if self._rows is None:
            row = self.active_row()
            self._rows = list(row.rows or []) if row else []
        return self._rows

    def owner_for(self, attrs: dict[str, Any]) -> dict[str, Any] | None:
        return match(self.rows(), attrs)

    def view(self, *, limit: int = 1000) -> dict[str, Any]:
        row = self.active_row()
        rows = self.rows()
        return {"version": row.id if row else None, "count": len(rows), "rows": rows[:limit], "truncated": len(rows) > limit,
                "filename": row.filename if row else "", "set_by": row.set_by if row else None,
                "set_at": row.created_at.isoformat() if row else None, "note": row.note if row else "",
                "by_team": dict(sorted(Counter(r["team"] for r in rows).items())), "max_rows": MAX_ROWS,
                "columns": {k: list(v[:6]) for k, v in _HEADERS.items()},
                "history": [{"id": h.id, "set_by": h.set_by, "note": h.note, "filename": h.filename,
                             "rows": len(h.rows or []), "created_at": h.created_at.isoformat()}
                            for h in self.s.execute(select(OwnershipVersion).order_by(OwnershipVersion.id.desc())
                                                    .limit(20)).scalars()]}

    def export_csv(self) -> str:
        buf = io.StringIO()
        w = csv.writer(buf, lineterminator="\n")
        w.writerow(["name", "subscription", "cloud", "resource_type", "team", "owner", "environment", "criticality", "note"])
        for r in self.rows():
            w.writerow([_cell(r.get(k, "")) for k in ("name", "subscription", "cloud", "resource_type", "team", "owner",
                                                      "environment", "criticality", "note")])
        return buf.getvalue()

    def upload(self, data: bytes, by: Principal, *, filename: str = "", note: str = "", dry_run: bool = False,
               coverage: Any = None) -> dict[str, Any]:
        """Replace the mapping with a file's rows. ``dry_run`` reports what it holds and every unusable row,
        changing nothing. ``coverage(rows)`` (from the caller, which knows the findings) says what the rows would
        give an owner."""
        from soc_platform.core.watchlists import read_rows

        _may_manage(by)
        items, problems = parse(read_rows(data, filename))
        if not items:
            raise ValueError("the file has no usable ownership row" +
                             (f" ({len(problems)} problem(s): {problems[0]['problem']})" if problems else ""))
        before = self.rows()
        old_keys = {(r["name"], r["subscription"], r["cloud"], r["resource_type"]) for r in before}
        new_keys = {(r["name"], r["subscription"], r["cloud"], r["resource_type"]) for r in items}
        result = {"dry_run": dry_run, "rows": len(items), "added": len(new_keys - old_keys),
                  "removed": len(old_keys - new_keys), "by_team": dict(sorted(Counter(r["team"] for r in items).items())),
                  "problems": problems[:200], "problem_count": len(problems), "preview": items[:20]}
        if coverage is not None:
            result["coverage"] = coverage(items)
        if dry_run:
            return result
        fname = (filename or "upload").replace("\\", "/").rsplit("/", 1)[-1][:200]
        v = OwnershipVersion(rows=items, filename=fname, set_by=by.id, note=(note or "")[:500])
        self.s.add(v)
        self.s.flush()
        self._rows = items
        AuditLog(self.s).append(actor_type=by.actor_type, actor_id=by.id, event_type="ownership.uploaded",
                                subject_type="ownership", subject_id=str(v.id),
                                payload={"file": fname, "note": (note or "")[:500], "rows": len(items),
                                         "added": result["added"], "removed": result["removed"],
                                         "teams": sorted(result["by_team"])[:200], "rejected": len(problems)})
        return {**result, "version": v.id}

    def clear(self, by: Principal, note: str = "") -> OwnershipVersion:
        _may_manage(by)
        if not self.rows():
            raise ValueError("the ownership mapping is already empty")
        v = OwnershipVersion(rows=[], filename="", set_by=by.id, note=(note or "cleared")[:500])
        self.s.add(v)
        self.s.flush()
        previous = len(self.rows())
        self._rows = []
        AuditLog(self.s).append(actor_type=by.actor_type, actor_id=by.id, event_type="ownership.cleared",
                                subject_type="ownership", subject_id=str(v.id),
                                payload={"note": (note or "")[:500], "rows_removed": previous})
        return v


def _may_manage(by: Principal) -> None:
    if by.is_service or by.is_agent or not by.can(Perm.MANAGE_OWNERSHIP):
        raise PermissionError("a lead or an administrator (manage_ownership) changes the ownership mapping")


def _cell(v: Any) -> str:
    """A CSV cell a spreadsheet will not run as a formula."""
    s = str(v if v is not None else "")
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s
