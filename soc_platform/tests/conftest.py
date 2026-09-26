from __future__ import annotations

from typing import Any

import pytest

from soc_platform.core.actions import ActionRegistry, ActionSpec
from soc_platform.core.auth import Principal, Role
from soc_platform.core.db import Database

# ------------------------------------------------------------------------------------------------ PostgreSQL runs
# SOC_TEST_POSTGRES=postgresql://user:pw@host:port/postgres runs the whole suite on PostgreSQL (the production
# engine): every SQLite database a test creates becomes a fresh PostgreSQL database - the same file URL maps to the
# same database, each in-memory database gets its own. Engines do not pool, so ~200 tests stay within limits.
_PG = __import__("os").environ.get("SOC_TEST_POSTGRES")
if _PG:
    import hashlib as _hashlib
    import uuid as _uuid

    import psycopg2 as _pg
    from sqlalchemy import create_engine as _create_engine
    from sqlalchemy.orm import sessionmaker as _sessionmaker
    from sqlalchemy.pool import NullPool as _NullPool

    _orig_init = Database.__init__
    _made: set[str] = set()

    def _pg_url(url: str) -> str:
        name = ("t_" + _uuid.uuid4().hex[:16]) if url in {"sqlite://", "sqlite:///:memory:"} else             "f_" + _hashlib.sha256(url.encode()).hexdigest()[:16]
        if name not in _made:
            conn = _pg.connect(_PG)
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute("select 1 from pg_database where datname = %s", (name,))
                if not cur.fetchone():
                    cur.execute(f'create database "{name}"')
            conn.close()
            _made.add(name)
        return _PG.rsplit("/", 1)[0] + "/" + name

    def _pg_init(self, url: str) -> None:
        if not url.startswith("sqlite"):
            return _orig_init(self, url)
        self.engine = _create_engine(_pg_url(url).replace("postgresql://", "postgresql+psycopg2://"), future=True, poolclass=_NullPool)
        self._factory = _sessionmaker(bind=self.engine, expire_on_commit=False, future=True)

    Database.__init__ = _pg_init
else:
    # SQLite is lax where PostgreSQL (production) is strict. Hold every SQLite test to PostgreSQL's rules so the fast
    # suite catches what would only fail in production: text longer than its column, integers beyond 32 bits in an
    # Integer column, and NUL characters (PostgreSQL rejects them in text, in writes and in query parameters).
    from sqlalchemy import BigInteger as _BigInteger
    from sqlalchemy import Integer as _Integer
    from sqlalchemy import String as _String
    from sqlalchemy import event as _event
    from sqlalchemy import inspect as _inspect
    from sqlalchemy.engine import Engine as _Engine
    from sqlalchemy.orm import Session as _Session

    class PostgresRuleViolation(Exception):
        pass

    @_event.listens_for(_Session, "before_flush")
    def _pg_strict_flush(session, _ctx, _instances) -> None:
        for obj in list(session.new) + list(session.dirty):
            for col in _inspect(obj).mapper.columns:
                v = getattr(obj, col.key, None)
                if v is None:
                    continue
                t = col.type
                if getattr(t, "truncates", False):          # BoundedText: kept to width and NUL-free on the way in
                    continue
                if isinstance(v, str):                     # (NUL is stripped for every column by core.db._strip_nul)
                    if isinstance(t, _String) and t.length and len(v) > t.length:
                        raise PostgresRuleViolation(f"{obj.__tablename__}.{col.key}: {len(v)} chars > {t.length}: {v[:60]!r}")
                elif isinstance(v, int) and isinstance(t, _Integer) and not isinstance(t, _BigInteger) and not -2**31 <= v < 2**31:
                    raise PostgresRuleViolation(f"{obj.__tablename__}.{col.key}: {v} exceeds a 32-bit Integer")

    @_event.listens_for(_Engine, "before_cursor_execute")
    def _pg_strict_params(_conn, _cursor, _stmt, params, _ctx, _many) -> None:
        def values(p):                                   # dict, tuple, list of either, or a scalar (bulk inserts)
            if isinstance(p, dict):
                return p.values()
            return p if isinstance(p, (list, tuple)) else (p,)

        stack = list(values(params))
        while stack:
            v = stack.pop()
            if isinstance(v, (dict, list, tuple)):
                stack.extend(values(v))
            elif isinstance(v, str) and "\x00" in v:
                raise PostgresRuleViolation("NUL character in a query parameter")


@pytest.fixture()
def db() -> Database:
    d = Database("sqlite://")
    d.create_all()
    return d


@pytest.fixture()
def session(db: Database):
    with db.session() as s:
        yield s


def person(pid: str, *roles: Role) -> Principal:
    return Principal(id=pid, name=pid, roles=frozenset(roles))


@pytest.fixture()
def analyst() -> Principal:
    return person("alice", Role.ANALYST)


@pytest.fixture()
def analyst2() -> Principal:
    return person("bob", Role.ANALYST)


@pytest.fixture()
def lead() -> Principal:
    return person("lena", Role.LEAD)


@pytest.fixture()
def automation_admin() -> Principal:
    return person("adam", Role.AUTOMATION_ADMIN)


class RecordingSpec(ActionSpec):
    def __init__(self, action_type: str, *, destructive: bool = False, reverse_type: str | None = None,
                 fail: bool = False, precondition: str | None = None) -> None:
        self.action_type = action_type
        self.tool = "test"
        self.destructive = destructive
        self.reverse_type = reverse_type
        self.fail = fail
        self.precondition = precondition
        self.calls: list[tuple[dict[str, Any], list[dict[str, Any]]]] = []

    def preconditions(self, params, targets):
        return [self.precondition] if self.precondition else []

    def execute(self, params, targets):
        if self.fail:
            raise RuntimeError("tool said no")
        self.calls.append((params, targets))
        return {"done": True}

    def reverse(self, params, targets, result):
        return (params, targets) if self.reverse_type else None


@pytest.fixture()
def registry() -> ActionRegistry:
    r = ActionRegistry()
    r.register(RecordingSpec("endpoint.isolate", reverse_type="endpoint.release"))
    r.register(RecordingSpec("endpoint.release"))
    r.register(RecordingSpec("email.soft_delete", destructive=True))
    r.register(RecordingSpec("email.tag"))
    return r


# ------------------------------------------------------------------------------------------------ sample estates
# The built-in estate plus seeded variants (different organisation, people, machines, IP plan, suppliers,
# volumes). Tests that assert relationships run on all of them, so nothing can depend on one data set.
ESTATES = ["demo", "seed7", "seed23"]


@pytest.fixture(scope="session")
def estate_configs(tmp_path_factory) -> dict[str, dict[str, Any]]:
    import importlib.util
    import json
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    corpus = root / "artifacts" / "phishing" / "corpus"
    out = {"demo": {"name": "demo", "org": "acme-demo.com", "fixtures_dir": None, "corpus_dir": str(corpus),
                    "suppliers_file": str(root / "config" / "suppliers.yaml"), "focus_upn": "jane.doe@acme-demo.com",
                    "campaign_cve": "CVE-2021-44228", "phish_subject_token": "password expires", "lead": "lena@acme-demo.com",
                    "uploads": ["supplier_bank_change.eml", "supplier_lookalike_payment.eml", "bec_ceo_fraud.eml", "quishing_qr.eml",
                                "legit_vendor_invoice.eml", "marketing_spam.eml"], "original_tokens": []}}
    spec = importlib.util.spec_from_file_location("build_estate_variant", root / "scripts" / "build_estate_variant.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    for name in ESTATES[1:]:
        d = mod.main(str(tmp_path_factory.mktemp(name)), seed=int(name[4:]))
        out[name] = {**json.loads((d / "estate.json").read_text()), "name": name}
    return out


class estate_env:
    """Point the platform at one estate (fixtures, tenant settings, suppliers, org domain) for a block of code."""

    KEYS = ("SOC_FIXTURES_DIR", "SOC_SUPPLIERS_FILE", "SOC_ORG_DOMAINS")

    def __init__(self, cfg: dict[str, Any]) -> None:
        self.cfg = cfg

    def __enter__(self):
        import os

        self.saved = {k: os.environ.get(k) for k in self.KEYS}
        if self.cfg.get("fixtures_dir"):
            os.environ["SOC_FIXTURES_DIR"] = self.cfg["fixtures_dir"]
        else:
            os.environ.pop("SOC_FIXTURES_DIR", None)
        os.environ["SOC_SUPPLIERS_FILE"] = self.cfg["suppliers_file"]
        os.environ["SOC_ORG_DOMAINS"] = self.cfg["org"]
        self._reset()
        return self.cfg

    @staticmethod
    def _reset():
        """The API caches its connector registry (and connectors keep their fixture transport): rebuild on switch."""
        import sys

        app = sys.modules.get("soc_platform.api.app")
        if app is not None:
            app.registry.cache_clear()
        from soc_platform.config import get_settings

        get_settings.cache_clear()

    def __exit__(self, *exc):
        import os

        for k, v in self.saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        self._reset()


@pytest.fixture(autouse=True)
def _reset_llm_breaker():
    """The model circuit breaker is per process: never let one test's failures leak into the next."""
    from soc_platform.llm import gateway

    gateway._Breaker.failures, gateway._Breaker.open_until = 0, 0.0
    yield
    gateway._Breaker.failures, gateway._Breaker.open_until = 0, 0.0
