#!/usr/bin/env python3
"""Populate behavior_graph.db from real email sender/recipient relationships.

This script builds user behavior graph context used by user_behavior_agent.
It extracts sender/recipient pairs from:
- Raw email files under datasets/email_content (eml/txt/no extension)
- CSV datasets that include sender/recipient columns or embedded RFC822-like text

Outputs:
- Upserts rows into data/behavior_graph.db tables:
  - employees(email_address, department)
  - interactions(recipient_email, sender_domain, interaction_count, days_since_last)
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import email.utils
import logging
import re
import sqlite3
from collections import defaultdict
from collections.abc import Iterable
from pathlib import Path

from soc_platform.domains.phishing.engine.paths import PHISHING_HOME

WORKSPACE_ROOT = PHISHING_HOME
EMAIL_ROOT = WORKSPACE_ROOT / "datasets" / "email_content"
DB_PATH = WORKSPACE_ROOT / "data" / "behavior_graph.db"

SENDER_COL_CANDIDATES = (
    "from",
    "sender",
    "from_address",
    "sender_email",
    "mail_from",
)

RECIPIENT_COL_CANDIDATES = (
    "to",
    "recipient",
    "recipient_email",
    "to_address",
    "mail_to",
)

TEXT_COL_CANDIDATES = (
    "message",
    "body",
    "content",
    "text",
    "email",
)

HEADER_FROM_RE = re.compile(r"^from:\s*(.+)$", re.IGNORECASE | re.MULTILINE)
HEADER_TO_RE = re.compile(r"^to:\s*(.+)$", re.IGNORECASE | re.MULTILINE)


def _ensure_schema(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS employees (
            email_address TEXT PRIMARY KEY,
            department TEXT
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS interactions (
            recipient_email TEXT NOT NULL,
            sender_domain TEXT NOT NULL,
            interaction_count REAL NOT NULL,
            days_since_last REAL NOT NULL,
            PRIMARY KEY (recipient_email, sender_domain)
        )
        """
    )
    conn.commit()


def _normalize_email(value: str) -> str:
    _name, addr = email.utils.parseaddr(str(value or "").strip())
    addr = addr.strip().lower()
    if "@" not in addr:
        return ""
    local, domain = addr.split("@", 1)
    if not local or not domain:
        return ""
    return f"{local}@{domain}"


def _extract_addresses(field: str) -> list[str]:
    if not field:
        return []
    parsed = email.utils.getaddresses([field])
    out = []
    for _name, addr in parsed:
        normalized = _normalize_email(addr)
        if normalized:
            out.append(normalized)
    return out


def _sender_domain(sender_email: str) -> str:
    if "@" not in sender_email:
        return ""
    return sender_email.split("@", 1)[1].strip().lower()


def _infer_department(recipient_email: str) -> str:
    local = recipient_email.split("@", 1)[0].lower()
    if any(k in local for k in ("finance", "account", "payroll", "invoice")):
        return "finance"
    if any(k in local for k in ("hr", "recruit", "talent")):
        return "hr"
    if any(k in local for k in ("ceo", "cfo", "coo", "cto", "exec", "director")):
        return "executive"
    if any(k in local for k in ("sales", "bizdev")):
        return "sales"
    if any(k in local for k in ("marketing", "brand", "campaign")):
        return "marketing"
    if any(k in local for k in ("eng", "dev", "sre", "qa", "tech")):
        return "engineering"
    if any(k in local for k in ("it", "helpdesk", "support", "ops")):
        return "it"
    return "operations"


def _parse_embedded_headers(text: str) -> tuple[str, list[str]]:
    if not text:
        return "", []

    sender = ""
    recipients: list[str] = []

    from_match = HEADER_FROM_RE.search(text)
    if from_match:
        sender_candidates = _extract_addresses(from_match.group(1))
        if sender_candidates:
            sender = sender_candidates[0]

    to_match = HEADER_TO_RE.search(text)
    if to_match:
        recipients = _extract_addresses(to_match.group(1))

    return sender, recipients


def _iter_email_files(root: Path, max_files: int) -> Iterable[Path]:
    count = 0
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        # Skip very large non-email binary payloads.
        if path.suffix.lower() in {".png", ".jpg", ".jpeg", ".pdf", ".zip", ".exe"}:
            continue
        yield path
        count += 1
        if max_files > 0 and count >= max_files:
            return


def build_graph(email_root: Path, max_files: int, max_csv_rows: int) -> tuple[dict[str, str], dict[tuple[str, str], tuple[float, float]]]:
    now_ts = dt.datetime.now(dt.UTC).timestamp()

    employees: dict[str, str] = {}
    # interactions[(recipient_email, sender_domain)] = (count, latest_seen_ts)
    interactions: dict[tuple[str, str], tuple[float, float]] = defaultdict(lambda: (0.0, 0.0))

    processed_files = 0
    for file_path in _iter_email_files(email_root, max_files=max_files):
        processed_files += 1
        ext = file_path.suffix.lower()

        if ext == ".csv":
            try:
                with file_path.open("r", encoding="utf-8", errors="ignore", newline="") as handle:
                    reader = csv.DictReader(handle)
                    row_count = 0
                    for row in reader:
                        row_count += 1
                        if max_csv_rows > 0 and row_count > max_csv_rows:
                            break

                        cols_lower = {str(k).lower(): k for k in row}
                        sender = ""
                        recipients: list[str] = []

                        for candidate in SENDER_COL_CANDIDATES:
                            if candidate in cols_lower:
                                sender_list = _extract_addresses(str(row.get(cols_lower[candidate], "")))
                                if sender_list:
                                    sender = sender_list[0]
                                    break

                        for candidate in RECIPIENT_COL_CANDIDATES:
                            if candidate in cols_lower:
                                recipients = _extract_addresses(str(row.get(cols_lower[candidate], "")))
                                if recipients:
                                    break

                        if not sender or not recipients:
                            for candidate in TEXT_COL_CANDIDATES:
                                if candidate not in cols_lower:
                                    continue
                                embedded_sender, embedded_to = _parse_embedded_headers(str(row.get(cols_lower[candidate], "")))
                                sender = sender or embedded_sender
                                recipients = recipients or embedded_to
                                if sender and recipients:
                                    break

                        if not sender or not recipients:
                            continue

                        sender_domain = _sender_domain(sender)
                        if not sender_domain:
                            continue

                        for recipient in recipients:
                            employees.setdefault(recipient, _infer_department(recipient))
                            key = (recipient, sender_domain)
                            count, latest = interactions[key]
                            interactions[key] = (count + 1.0, max(latest, now_ts))
            except Exception:
                logging.getLogger(__name__).warning("skipping an unreadable CSV", exc_info=True)
                continue
            continue

        # Non-CSV text-like files
        try:
            text = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            logging.getLogger(__name__).warning("skipping an unreadable file", exc_info=True)
            continue

        sender, recipients = _parse_embedded_headers(text)
        if not sender or not recipients:
            continue

        sender_domain = _sender_domain(sender)
        if not sender_domain:
            continue

        seen_ts = file_path.stat().st_mtime if file_path.exists() else now_ts
        for recipient in recipients:
            employees.setdefault(recipient, _infer_department(recipient))
            key = (recipient, sender_domain)
            count, latest = interactions[key]
            interactions[key] = (count + 1.0, max(latest, seen_ts))

    # Convert latest_ts to days_since_last
    prepared: dict[tuple[str, str], tuple[float, float]] = {}
    for key, (count, latest_seen) in interactions.items():
        age_days = max(0.0, round((now_ts - latest_seen) / 86400.0, 4))
        prepared[key] = (round(count, 4), age_days)

    print(f"Processed files: {processed_files}")
    print(f"Employees extracted: {len(employees)}")
    print(f"Interaction edges extracted: {len(prepared)}")

    return employees, prepared


def persist(db_path: Path, employees: dict[str, str], interactions: dict[tuple[str, str], tuple[float, float]]) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(db_path))
    _ensure_schema(con)

    # Keep existing data only if no extracted edges found.
    if interactions:
        con.execute("DELETE FROM interactions")
    if employees:
        con.execute("DELETE FROM employees")

    con.executemany(
        "INSERT OR REPLACE INTO employees (email_address, department) VALUES (?, ?)",
        sorted(employees.items()),
    )

    con.executemany(
        """
        INSERT OR REPLACE INTO interactions
            (recipient_email, sender_domain, interaction_count, days_since_last)
        VALUES (?, ?, ?, ?)
        """,
        [
            (recipient, sender_domain, count, days_since_last)
            for (recipient, sender_domain), (count, days_since_last) in interactions.items()
        ],
    )

    con.commit()

    cur = con.cursor()
    employees_count = cur.execute("SELECT COUNT(*) FROM employees").fetchone()[0]
    interactions_count = cur.execute("SELECT COUNT(*) FROM interactions").fetchone()[0]
    top_edges = cur.execute(
        """
        SELECT recipient_email, sender_domain, interaction_count, days_since_last
        FROM interactions
        ORDER BY interaction_count DESC, days_since_last ASC
        LIMIT 10
        """
    ).fetchall()

    con.close()

    print(f"Persisted employees: {employees_count}")
    print(f"Persisted interactions: {interactions_count}")
    print("Top interactions:")
    for row in top_edges:
        print(f"  recipient={row[0]} sender_domain={row[1]} count={row[2]} days_since_last={row[3]}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Populate behavior_graph.db from email corpora")
    parser.add_argument("--email-root", default=str(EMAIL_ROOT), help="Root folder containing email datasets")
    parser.add_argument("--db-path", default=str(DB_PATH), help="SQLite DB path for behavior graph")
    parser.add_argument("--max-files", type=int, default=0, help="Optional cap on number of files scanned (0 = all)")
    parser.add_argument("--max-csv-rows", type=int, default=0, help="Optional cap per CSV file (0 = all rows)")
    args = parser.parse_args()

    email_root = Path(args.email_root)
    db_path = Path(args.db_path)

    if not email_root.exists():
        raise SystemExit(f"Email root not found: {email_root}")

    employees, interactions = build_graph(
        email_root=email_root,
        max_files=max(0, int(args.max_files)),
        max_csv_rows=max(0, int(args.max_csv_rows)),
    )

    if not employees or not interactions:
        print("No real interactions extracted; database was not overwritten.")
        return 1

    persist(db_path=db_path, employees=employees, interactions=interactions)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
