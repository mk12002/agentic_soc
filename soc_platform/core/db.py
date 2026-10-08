"""Database engine and session management (SQLite for dev/test, Postgres in prod)."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import DateTime, String, create_engine, event, inspect, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.types import TypeDecorator


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
        self.engine: Engine = create_engine(url, **kwargs)
        if url.startswith("sqlite"):
            event.listen(self.engine, "connect", _sqlite_pragmas)
        self._factory = sessionmaker(bind=self.engine, expire_on_commit=False, future=True)

    def create_all(self) -> None:
        from soc_platform.core import models  # noqa: F401  (register tables)
        from soc_platform.core import notify as _notify  # noqa: F401
        from soc_platform.domains.phishing import models as _ph  # noqa: F401
        from soc_platform.domains.vulnerability import models as _vm  # noqa: F401
        from soc_platform.intelligence import models as _intel  # noqa: F401
        from soc_platform.llm import usage_policy as _llm_policy  # noqa: F401
        from soc_platform.reporting import models as _rep  # noqa: F401

        Base.metadata.create_all(self.engine)
        self._add_missing_columns()
        self._add_missing_indexes()
        if self.engine.dialect.name == "postgresql":
            self._widen_columns()

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
    cur.execute("PRAGMA journal_mode=WAL")
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
            from soc_platform.config import get_settings

            fresh = Database(get_settings().database_url)
            fresh.create_all()
            _default = fresh  # published only once the schema exists
        return _default


def set_database(db: Database) -> None:
    """Override the process-wide database (used by tests and the API factory)."""
    global _default
    _default = db
