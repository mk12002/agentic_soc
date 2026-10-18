"""Database engine and session management (SQLite for dev/test, Postgres in prod)."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import DateTime, String, create_engine, event, inspect, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.types import TypeDecorator

SCHEMA_LOCK_KEY = 0x50C5C4E3A  # pg_advisory_lock key that serialises schema creation across processes

class Base(DeclarativeBase):
    pass


class UTCDateTime(TypeDecorator):
    """Timestamps are always timezone-aware UTC in Python, whatever the database keeps.

    SQLite drops the offset, so values read back were naive; serialised naive, a browser reads them as the viewer's
    local time and the same event shows different times on different screens. Stored as UTC; returned aware.
    """

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value: Any, dialect: Any) -> Any:
        if isinstance(value, datetime):
            return (value.replace(tzinfo=UTC) if value.tzinfo is None else value).astimezone(UTC)
        return value

    def process_result_value(self, value: Any, dialect: Any) -> Any:
        if isinstance(value, datetime) and value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value


class BoundedText(TypeDecorator):
    """Free text from vendors and people (titles, subjects, names, user agents): kept to the column width.

    PostgreSQL rejects a value longer than its column, or one containing NUL, and the whole write fails; SQLite
    accepts both, so this only ever failed in production. Over-long text is cut and ends with an ellipsis. Identifiers
    and keys are never BoundedText: cutting those would silently break matching, so they fail loudly instead.
    """

    impl = String
    cache_ok = True
    truncates = True

    def process_bind_param(self, value: Any, dialect: Any) -> Any:
        if isinstance(value, str):
            value = value.replace("\x00", "")
            n = self.impl.length
            if n and len(value) > n:
                value = value[: n - 1] + "\u2026"
        return value


class Database:
    """Owns one engine and session factory. Tests create their own in-memory instance."""

    def __init__(self, url: str) -> None:
        kwargs: dict = {"future": True}
        if url.startswith("sqlite"):
            kwargs["connect_args"] = {"check_same_thread": False}
        if url in {"sqlite://", "sqlite:///:memory:"}:
            from sqlalchemy.pool import StaticPool

            kwargs["poolclass"] = StaticPool
        else:
            kwargs.update(pool_settings())
        timeout, idle = statement_timeout_ms(), idle_tx_timeout_ms()
        if (timeout or idle) and url.startswith("postgresql"):
            # a runaway query, or a transaction left open by a stuck caller, releases its connection and locks (the
            # audit chain's head row among them) instead of holding them until someone notices
            opts = " ".join(o for o in (f"-c statement_timeout={timeout}" if timeout else "",
                                        f"-c idle_in_transaction_session_timeout={idle}" if idle else "") if o)
            kwargs["connect_args"] = {**kwargs.get("connect_args", {}), "options": opts}
        self.engine: Engine = create_engine(url, **kwargs)
        if url.startswith("sqlite"):
            event.listen(self.engine, "connect", _sqlite_pragmas)
        self._factory = sessionmaker(bind=self.engine, expire_on_commit=False, future=True)

    @staticmethod
    def _register_models() -> None:
        from soc_platform.core import blobstore as _blobs  # noqa: F401
        from soc_platform.core import models  # noqa: F401  (register tables)
        from soc_platform.core import notify as _notify  # noqa: F401
        from soc_platform.domains.phishing import models as _ph  # noqa: F401
        from soc_platform.domains.vulnerability import models as _vm  # noqa: F401
        from soc_platform.intelligence import models as _intel  # noqa: F401
        from soc_platform.llm import usage_policy as _llm_policy  # noqa: F401
        from soc_platform.reporting import models as _rep  # noqa: F401

    def create_all(self) -> None:
        self._register_models()

        # Every process creates the schema on first use, and a fresh deployment starts many at once (replicas x
        # workers). Unserialised, they race on CREATE / ALTER TABLE ("already exists", a failed first request).
        # PostgreSQL: one session-level advisory lock, so they take turns and the later ones find nothing to do.
        # Other engines (SQLite, one host): a lost race is retried, and the retry finds the tables in place.
        if self.engine.dialect.name == "postgresql":
            with self.engine.connect() as lock:
                lock.execute(text("SELECT pg_advisory_lock(:k)"), {"k": SCHEMA_LOCK_KEY})
                try:
                    self._create_schema()
                finally:
                    lock.execute(text("SELECT pg_advisory_unlock(:k)"), {"k": SCHEMA_LOCK_KEY})
                    lock.commit()
            return
        for attempt in range(5):
            try:
                self._create_schema()
                return
            except SQLAlchemyError as exc:
                if "already exists" not in str(exc).lower() or attempt == 4:
                    raise
                __import__("time").sleep(0.1 * (attempt + 1))

    def _create_schema(self) -> None:
        Base.metadata.create_all(self.engine)
        self._add_missing_columns()
        self._add_missing_indexes()
        self._audit_guards()
        if self.engine.dialect.name == "postgresql":
            self._widen_columns()
            self._search_indexes()

    def missing_tables(self) -> list[str]:
        """Tables the code needs that the database lacks (a runtime role that may not create them checks this)."""
        self._register_models()
        have = set(inspect(self.engine).get_table_names())
        return sorted(t for t in Base.metadata.tables if t not in have)

    def verify_schema(self) -> None:
        """For processes that do not manage the schema (SOC_SCHEMA_MANAGE=0, a runtime role without DDL rights):
        stop at once with what to do, rather than fail on the first query that touches a missing table."""
        missing = self.missing_tables()
        if missing:
            raise RuntimeError(f"the database lacks {len(missing)} table(s) ({', '.join(missing[:5])}...): run "
                               "`python -m soc_platform init-db` with the migration credentials first")

    def _audit_guards(self) -> None:
        """The database itself refuses UPDATE, DELETE and TRUNCATE on the audit log, not only the ORM: a raw SQL
        statement from the application's role is refused too. Only the schema owner (the migration role, which the
        running platform does not hold) could drop the trigger - and that is itself a visible DDL change."""
        if self.engine.dialect.name == "postgresql":
            with self.engine.begin() as c:
                c.execute(text(
                    "CREATE OR REPLACE FUNCTION soc_audit_append_only() RETURNS trigger LANGUAGE plpgsql AS $$ "
                    "BEGIN RAISE EXCEPTION 'audit_log is append-only'; END $$"))
                c.execute(text("DROP TRIGGER IF EXISTS audit_log_append_only ON audit_log"))
                c.execute(text("CREATE TRIGGER audit_log_append_only BEFORE UPDATE OR DELETE ON audit_log "
                               "FOR EACH ROW EXECUTE FUNCTION soc_audit_append_only()"))
                c.execute(text("DROP TRIGGER IF EXISTS audit_log_no_truncate ON audit_log"))
                c.execute(text("CREATE TRIGGER audit_log_no_truncate BEFORE TRUNCATE ON audit_log "
                               "FOR EACH STATEMENT EXECUTE FUNCTION soc_audit_append_only()"))
        elif self.engine.dialect.name == "sqlite":
            with self.engine.begin() as c:
                for op in ("UPDATE", "DELETE"):
                    c.execute(text(f"CREATE TRIGGER IF NOT EXISTS audit_log_no_{op.lower()} BEFORE {op} ON audit_log "
                                   "BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END"))

    def grant_runtime(self, role: str) -> list[str]:
        """PostgreSQL least privilege: give the role the running platform signs in with read / write on every table
        and sequence, but on the audit log only SELECT and INSERT, and no right to change the schema. Run by
        ``init-db`` (migration credentials) when SOC_DB_RUNTIME_ROLE is set; idempotent."""
        import re

        if self.engine.dialect.name != "postgresql":
            return []
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,62}", role):
            raise ValueError(f"not a role name: {role!r}")
        stmts = [f'GRANT USAGE ON SCHEMA public TO "{role}"',
                 f'GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO "{role}"',
                 f'GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO "{role}"',
                 f'REVOKE UPDATE, DELETE, TRUNCATE ON audit_log FROM "{role}"',
                 f'REVOKE CREATE ON SCHEMA public FROM "{role}"']
        with self.engine.begin() as c:
            for s in stmts:
                c.execute(text(s))     # nosec B608 - the role name is validated above; statements are fixed
        return stmts

    # (index name, table, column): the search box matches any part of these case-insensitively
    SEARCH_INDEXES = (("ix_trgm_entity_keys_value", "entity_keys", "key_value"),
                      ("ix_trgm_entities_display_name", "entities", "display_name"),
                      ("ix_trgm_cases_title", "cases", "title"),
                      ("ix_trgm_insights_title", "insights", "title"),
                      ("ix_trgm_findings_asset", "vm_findings", "asset_name"),
                      ("ix_trgm_findings_cve", "vm_findings", "cve"))

    def _search_indexes(self) -> list[str]:
        """Trigram indexes for the search box (PostgreSQL). ``lower(col) LIKE '%term%'`` cannot use a B-tree index,
        so every search scanned the identifier table, which grows with the estate. Best effort: without the pg_trgm
        extension (a managed server must allow-list it) search still works, by scanning, and a warning says so."""
        import logging

        made: list[str] = []
        with self.engine.connect() as c:
            try:
                c.execute(text("CREATE EXTENSION IF NOT EXISTS pg_trgm"))
                c.commit()
            except SQLAlchemyError as exc:
                c.rollback()
                logging.getLogger(__name__).warning("pg_trgm unavailable - search will scan tables (%s)",
                                                    str(exc).splitlines()[0][:200])
                return made
            tables = set(inspect(self.engine).get_table_names())
            for name, table, column in self.SEARCH_INDEXES:
                if table not in tables:
                    continue
                c.execute(text(f"CREATE INDEX IF NOT EXISTS {name} ON {table} "     # nosec B608 - fixed identifiers
                               f"USING gin (lower({column}) gin_trgm_ops)"))
                made.append(name)
            c.commit()
        return made

    def _add_missing_indexes(self) -> list[str]:
        """Like columns, an index the model gained after a table was created is never added by create_all. Indexes
        are purely additive (no data changes), so create each one the model defines that the database lacks - e.g. the
        (kind, canonical_key) lookup every ingested record makes, which without it scanned all entities of a kind."""
        import logging

        insp = inspect(self.engine)
        existing = set(insp.get_table_names())
        added: list[str] = []
        for table in Base.metadata.sorted_tables:
            if table.name not in existing:
                continue
            have = {ix["name"] for ix in insp.get_indexes(table.name)}
            for ix in table.indexes:
                if ix.name and ix.name not in have:
                    ix.create(self.engine, checkfirst=True)
                    added.append(ix.name)
        if added:
            logging.getLogger(__name__).info("schema: added index(es) %s", ", ".join(added))
        return added

    def _add_missing_columns(self) -> list[str]:
        """create_all creates missing *tables* but never changes existing ones. Add each column the model defines that
        an existing table lacks - only when that is safe: the column is nullable (existing rows get NULL). Nothing is
        ever dropped, renamed or narrowed; a new NOT NULL column without a default needs a scripted migration and is
        reported instead. Works on SQLite and PostgreSQL."""
        import logging

        insp = inspect(self.engine)
        existing = set(insp.get_table_names())
        quote = self.engine.dialect.identifier_preparer.quote
        added: list[str] = []
        with self.engine.begin() as conn:
            for table in Base.metadata.sorted_tables:
                if table.name not in existing:
                    continue
                have = {c["name"] for c in insp.get_columns(table.name)}
                for col in table.columns:
                    if col.name in have:
                        continue
                    if not col.nullable or col.primary_key:
                        logging.getLogger(__name__).warning(
                            "schema: %s.%s is new and NOT NULL - add it with a scripted migration", table.name, col.name)
                        continue
                    ddl = col.type.compile(dialect=self.engine.dialect)
                    conn.execute(text(f"ALTER TABLE {quote(table.name)} ADD COLUMN {quote(col.name)} {ddl}"))
                    added.append(f"{table.name}.{col.name}")
        if added:
            logging.getLogger(__name__).info("schema: added column(s) %s", ", ".join(added))
        return added

    def _widen_columns(self) -> None:
        """create_all never changes an existing table: widen VARCHAR columns the model has since made longer (always
        safe - no value is lost), so an upgrade does not leave production on an older, narrower schema."""
        insp = inspect(self.engine)
        existing = set(insp.get_table_names())
        with self.engine.begin() as conn:
            for table in Base.metadata.sorted_tables:
                if table.name not in existing:
                    continue
                have = {c["name"]: c["type"] for c in insp.get_columns(table.name)}
                for col in table.columns:
                    want = getattr(col.type, "length", None) or getattr(getattr(col.type, "impl", None), "length", None)
                    cur = getattr(have.get(col.name), "length", None)
                    if want and cur and want > cur:
                        conn.execute(text(f'ALTER TABLE "{table.name}" ALTER COLUMN "{col.name}" TYPE VARCHAR({int(want)})'))

    @contextmanager
    def session(self) -> Iterator[Session]:
        s = self._factory()
        try:
            yield s
            s.commit()
        except Exception:
            s.rollback()
            raise
        finally:
            s.close()


@event.listens_for(Session, "before_flush")
def _strip_nul(session: Session, _ctx: Any, _instances: Any) -> None:
    """PostgreSQL rejects NUL in any text column and fails the whole write. Mail bodies, vendor payloads and uploads
    can carry one, so no text value is stored with it - on every table, whichever code path wrote it."""
    for obj in (*session.new, *session.dirty):
        state = inspect(obj)
        for attr in state.mapper.column_attrs:
            v = state.dict.get(attr.key)
            if isinstance(v, str) and "\x00" in v:
                setattr(obj, attr.key, v.replace("\x00", ""))


def _seconds_ms(name: str, prod_default: float) -> int:
    import os

    default = prod_default if os.environ.get("SOC_ENVIRONMENT", "dev") == "prod" else 0
    raw = os.environ.get(name, "")
    try:
        return max(0, int(float(raw if raw.strip() else default) * 1000))
    except ValueError:
        return int(default * 1000)


def statement_timeout_ms() -> int:
    """SOC_DB_STATEMENT_TIMEOUT_SECONDS (PostgreSQL): the longest one SQL statement may run; 0 = no limit. Production
    default 300 s (every statement is per page or per item, so a large backfill is never one statement); elsewhere
    no limit."""
    return _seconds_ms("SOC_DB_STATEMENT_TIMEOUT_SECONDS", 300)


def idle_tx_timeout_ms() -> int:
    """SOC_DB_IDLE_TX_TIMEOUT_SECONDS (PostgreSQL): how long a transaction may sit idle before the server ends it.
    Production default 600 s - far above any lookup or model deadline, low enough that a stuck process cannot hold
    the audit chain's lock for ever; elsewhere no limit."""
    return _seconds_ms("SOC_DB_IDLE_TX_TIMEOUT_SECONDS", 600)


def pool_settings() -> dict[str, Any]:
    """Connection pool for a server under load (SOC_DB_POOL_*). The defaults cover the API's request threads plus the
    scheduler and the access-log writer; a connection is checked before use (a database restart or failover, or a
    firewall dropping idle connections, otherwise surfaces as errors on the next requests) and recycled after
    SOC_DB_POOL_RECYCLE seconds. Waiting longer than SOC_DB_POOL_TIMEOUT for a connection answers 503, not a hang."""
    import os

    def num(name: str, default: int) -> int:
        try:
            return max(0, int(os.environ.get(name, default)))
        except ValueError:
            return default

    return {"pool_size": max(1, num("SOC_DB_POOL_SIZE", 20)), "max_overflow": num("SOC_DB_MAX_OVERFLOW", 20),
            "pool_timeout": max(1, num("SOC_DB_POOL_TIMEOUT", 10)), "pool_recycle": num("SOC_DB_POOL_RECYCLE", 1800),
            "pool_pre_ping": True}


def _sqlite_pragmas(dbapi_conn, _record) -> None:
    cur = dbapi_conn.cursor()
    cur.execute("PRAGMA foreign_keys=ON")
    # The server runs the scheduler alongside requests: let readers work during a write (WAL) and make a writer wait
    # for a busy database instead of failing at once. In-memory databases do not support WAL and ignore it.
    cur.execute("PRAGMA busy_timeout=30000")
    # Switching a new file to WAL ignores busy_timeout: several workers opening a fresh database together got
    # "database is locked" here. The mode is stored in the file, so retry until one connection has switched it.
    import sqlite3
    import time

    for attempt in range(100):
        try:
            cur.execute("PRAGMA journal_mode=WAL")
            break
        except sqlite3.OperationalError as exc:
            if "locked" not in str(exc).lower() or attempt == 99:
                raise
            time.sleep(0.05)
    cur.close()


_default: Database | None = None
_init_lock = __import__("threading").Lock()


def get_database() -> Database:
    """Process-wide database, created once (thread-safe: request threads and background writers race here)."""
    global _default
    db = _default
    if db is not None:
        return db
    with _init_lock:
        if _default is None:
            import os

            from soc_platform.config import get_settings

            fresh = Database(get_settings().database_url)
            if os.environ.get("SOC_SCHEMA_MANAGE", "1").strip().lower() in {"0", "false", "no", "off"}:
                fresh.verify_schema()        # a runtime role without DDL rights: init-db (migration role) made it
            else:
                fresh.create_all()
            _default = fresh  # published only once the schema exists
        return _default


def set_database(db: Database) -> None:
    """Override the process-wide database (used by tests and the API factory)."""
    global _default
    _default = db
