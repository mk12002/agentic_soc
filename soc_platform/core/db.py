"""Database engine and session management (SQLite for dev/test, Postgres in prod)."""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Iterator

from sqlalchemy import DateTime, create_engine, event
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
            return (value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value).astimezone(timezone.utc)
        return value

    def process_result_value(self, value: Any, dialect: Any) -> Any:
        if isinstance(value, datetime) and value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
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
        self.engine: Engine = create_engine(url, **kwargs)
        if url.startswith("sqlite"):
            event.listen(self.engine, "connect", _sqlite_pragmas)
        self._factory = sessionmaker(bind=self.engine, expire_on_commit=False, future=True)

    def create_all(self) -> None:
        from soc_platform.core import models  # noqa: F401  (register tables)
        from soc_platform.domains.phishing import models as _ph  # noqa: F401
        from soc_platform.domains.vulnerability import models as _vm  # noqa: F401
        from soc_platform.intelligence import models as _intel  # noqa: F401
        from soc_platform.reporting import models as _rep  # noqa: F401

        Base.metadata.create_all(self.engine)

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


def _sqlite_pragmas(dbapi_conn, _record) -> None:
    cur = dbapi_conn.cursor()
    cur.execute("PRAGMA foreign_keys=ON")
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
