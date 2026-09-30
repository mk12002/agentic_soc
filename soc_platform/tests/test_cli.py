"""`python -m soc_platform reset-demo`: one safe command to start a demo again from nothing."""

from __future__ import annotations

import socket

import pytest
from sqlalchemy import func, select

from soc_platform import __main__ as cli


@pytest.fixture()
def demo_env(tmp_path, monkeypatch):
    """A demo installation in a temporary folder: its own SQLite file, raw and report folders, a free port."""
    from soc_platform.config import get_settings
    from soc_platform.core import db as dbm

    monkeypatch.chdir(tmp_path)
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    monkeypatch.setenv("SOC_DATABASE_URL", f"sqlite:///{(tmp_path / 'demo.db').as_posix()}")
    monkeypatch.setenv("SOC_RAW_PAYLOAD_DIR", str(tmp_path / "data" / "raw"))
    monkeypatch.setenv("SOC_REPORT_OUTPUT_DIR", str(tmp_path / "data" / "reports"))
    monkeypatch.setenv("SOC_ORG_DOMAINS", "acme-demo.com")
    monkeypatch.setenv("SOC_ENVIRONMENT", "dev")
    monkeypatch.setenv("SOC_HOST", "127.0.0.1")
    monkeypatch.setenv("SOC_PORT", str(port))
    get_settings.cache_clear()
    dbm._default = None
    yield tmp_path, port
    if dbm._default is not None:
        dbm._default.engine.dispose()
    dbm._default = None
    get_settings.cache_clear()


def _case_titles() -> list[str]:
    from soc_platform.core.db import get_database
    from soc_platform.core.models import Case

    with get_database().session() as s:
        return list(s.execute(select(Case.title)).scalars())


def _seed_leftovers(root):
    from soc_platform.core.cases import CaseService
    from soc_platform.core.db import get_database

    cli.cmd_init_db()
    with get_database().session() as s:
        CaseService(s).create("incident", "Left over from yesterday", severity="low", attributes={}, actor="test")
    for d in ("raw", "reports"):
        (root / "data" / d).mkdir(parents=True, exist_ok=True)
        (root / "data" / d / "old.bin").write_bytes(b"x")
    get_database().engine.dispose()


def test_reset_demo_starts_again_from_nothing(demo_env):
    root, _ = demo_env
    _seed_leftovers(root)
    cli.cmd_reset_demo("--yes")
    titles = _case_titles()
    assert "Left over from yesterday" not in titles and len(titles) >= 10          # the sample organisation, fresh
    assert not (root / "data" / "raw" / "old.bin").exists() and not (root / "data" / "reports" / "old.bin").exists()
    from soc_platform.core.audit import AuditLog
    from soc_platform.core.db import get_database
    from soc_platform.core.models import AuditRecord

    with get_database().session() as s:
        assert AuditLog(s).verify()["ok"] and s.execute(select(func.count()).select_from(AuditRecord)).scalar() > 0


def test_reset_demo_asks_first_and_changes_nothing_when_cancelled(demo_env, monkeypatch):
    root, _ = demo_env
    _seed_leftovers(root)
    monkeypatch.setattr("builtins.input", lambda _prompt: "no")
    with pytest.raises(SystemExit, match="cancelled"):
        cli.cmd_reset_demo()
    assert "Left over from yesterday" in _case_titles() and (root / "data" / "raw" / "old.bin").exists()


def test_reset_demo_refuses_in_production_and_while_the_server_runs(demo_env, monkeypatch):
    from soc_platform.config import get_settings

    root, port = demo_env
    _seed_leftovers(root)
    with socket.socket() as server:                        # something is serving on the configured port
        server.bind(("127.0.0.1", port))
        server.listen(1)
        with pytest.raises(SystemExit, match="server is running"):
            cli.cmd_reset_demo("--yes")
    monkeypatch.setenv("SOC_ENVIRONMENT", "prod")
    monkeypatch.setenv("SOC_DATA_KEY", "x")                  # prod settings validation, irrelevant here
    get_settings.cache_clear()
    with pytest.raises(SystemExit, match="prod"):
        cli.cmd_reset_demo("--yes")
    monkeypatch.setenv("SOC_ENVIRONMENT", "dev")
    get_settings.cache_clear()
    assert "Left over from yesterday" in _case_titles()


def test_reset_demo_never_deletes_folders_outside_the_project(demo_env, monkeypatch, tmp_path_factory):
    from soc_platform.config import get_settings

    outside =tmp_path_factory.mktemp("elsewhere") / "reports"
    outside.mkdir()
    (outside / "keep.docx").write_bytes(b"x")
    monkeypatch.setenv("SOC_REPORT_OUTPUT_DIR", str(outside))
    get_settings.cache_clear()
    monkeypatch.setattr(cli, "cmd_demo", lambda: None)       # the demo itself is covered above
    cli.cmd_reset_demo("--yes")
    assert (outside / "keep.docx").exists()


def test_database_url_comes_from_a_vault_file_and_init_db_never_prints_its_password(tmp_path, monkeypatch, capsys):
    from types import SimpleNamespace

    from soc_platform.config import get_settings

    f = tmp_path / "db_url"
    f.write_text("postgresql+psycopg2://soc:s3cret-Pa55@db.internal:5432/soc_platform\n", encoding="utf-8")
    monkeypatch.delenv("SOC_DATABASE_URL", raising=False)
    monkeypatch.setenv("SOC_DATABASE_URL_FILE", str(f))
    monkeypatch.setattr(cli, "_db", lambda: SimpleNamespace(create_all=lambda: None))
    get_settings.cache_clear()
    try:
        assert get_settings().database_url.endswith("@db.internal:5432/soc_platform")
        cli.cmd_init_db()
        out = capsys.readouterr().out
        assert "db.internal" in out and "s3cret-Pa55" not in out
    finally:
        get_settings.cache_clear()
