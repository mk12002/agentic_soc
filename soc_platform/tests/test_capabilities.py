"""Platform capabilities: a library that is installed but cannot load (a missing system library) must be seen.

It once switched off QR decoding and the phishing ML engine with only a warning in the server log. Now it is reported
as "broken" - with the error, the impact and the fix - on /health (signed in), the console's banner and Integrations
card (/api/v1/admin/capabilities), `config check`, a Prometheus gauge, and a high finding notified like any other;
an option simply not installed, or switched off by a setting, is not an alarm."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from soc_platform.core import capabilities

ROOT = Path(__file__).resolve().parents[2]
SECRET = "capabilities-test-secret-0123456789abcdef"


@pytest.fixture(autouse=True)
def _fresh_probes():
    yield
    capabilities.refresh()          # monkeypatches are undone by now: the next test sees this host's real state


def _zbar_missing(monkeypatch):
    """pyzbar installed, the zbar shared library not: exactly how pyzbar fails to import."""
    real = capabilities._import

    def fake(module):
        if module == "pyzbar.pyzbar":
            raise ImportError("Unable to find zbar shared library")
        return real(module)

    monkeypatch.setattr(capabilities, "_installed", lambda m: True)
    monkeypatch.setattr(capabilities, "_import", fake)


def _by_name():
    return {c["name"]: c for c in capabilities.refresh()}


def test_a_library_installed_but_unable_to_load_is_broken_with_its_error_impact_and_fix(monkeypatch):
    _zbar_missing(monkeypatch)
    qr = _by_name()["qr_decoding"]
    assert qr["state"] == "broken"
    assert "Unable to find zbar shared library" in qr["detail"] and "pyzbar.pyzbar" in qr["detail"]
    assert "libzbar0" in qr["fix"] and "restart" in qr["fix"]
    assert "QR codes" in qr["impact"]
    assert capabilities.summary() == {"status": "degraded", "degraded": ["qr_decoding"]}


def test_a_missing_openmp_runtime_names_its_package(monkeypatch):
    real = capabilities._import

    def fake(module):
        if module == "xgboost":
            raise OSError("libgomp.so.1: cannot open shared object file: No such file or directory")
        return real(module)

    monkeypatch.setattr(capabilities, "_installed", lambda m: True)
    monkeypatch.setattr(capabilities, "_import", fake)
    monkeypatch.setenv("SOC_PHISHING_ENGINE", "auto")
    eng = _by_name()["phishing_engine"]
    assert eng["state"] == "broken" and "libgomp" in eng["detail"] and "libgomp1" in eng["fix"]
    assert "rule-based" in eng["impact"]


def test_an_option_not_installed_or_switched_off_is_not_an_alarm_but_a_required_one_is(monkeypatch):
    monkeypatch.setattr(capabilities, "_installed", lambda m: m.split(".")[0] not in {"xgboost", "yara"})
    monkeypatch.setenv("SOC_PHISHING_ENGINE", "auto")
    caps = _by_name()
    assert caps["phishing_engine"]["state"] == "not_installed" and caps["yara_rules"]["state"] == "not_installed"
    assert "phishing_engine" not in capabilities.summary()["degraded"]
    monkeypatch.setenv("SOC_PHISHING_ENGINE", "0")
    caps = _by_name()
    assert caps["phishing_engine"]["state"] == "off" and caps["yara_rules"]["state"] == "off"
    monkeypatch.setenv("SOC_PHISHING_ENGINE", "1")                # asked for and cannot run: broken
    assert _by_name()["phishing_engine"]["state"] == "broken"


def test_a_core_package_missing_from_a_core_install_is_broken(monkeypatch):
    monkeypatch.setattr(capabilities, "_installed", lambda m: m != "ppdeep")
    fz = _by_name()["fuzzy_hashing"]
    assert fz["state"] == "broken" and "reinstall" in fz["fix"]


@pytest.mark.skipif(not capabilities._installed("xgboost"), reason="the ML engine's libraries are not installed")
def test_trained_models_left_as_git_lfs_pointers_are_reported(tmp_path, monkeypatch):
    model = tmp_path / "models" / "url_agent" / "model.joblib"
    model.parent.mkdir(parents=True)
    model.write_bytes(b"version https://git-lfs.github.com/spec/v1\noid sha256:abc\nsize 12345\n")
    monkeypatch.setenv("SOC_PHISHING_HOME", str(tmp_path))
    monkeypatch.setenv("SOC_PHISHING_ENGINE", "auto")
    eng = _by_name()["phishing_engine"]
    assert eng["state"] == "broken" and "git lfs pull" in eng["detail"]


def test_a_broken_capability_raises_one_high_finding_that_resolves_when_fixed(session, monkeypatch):
    from sqlalchemy import select

    from soc_platform.intelligence.models import Insight

    _zbar_missing(monkeypatch)
    capabilities.raise_or_resolve(session)
    capabilities.raise_or_resolve(session)                       # hourly re-runs keep one finding
    session.flush()
    rows = session.execute(select(Insight).where(Insight.rule == "platform_capability")).scalars().all()
    assert len(rows) == 1 and rows[0].severity == "high" and rows[0].status == "new"
    assert "QR-code decoding" in rows[0].title and any("libzbar0" in s for s in rows[0].next_steps)
    monkeypatch.undo()
    capabilities.raise_or_resolve(session)
    assert rows[0].status == "resolved"


def test_config_check_names_a_broken_capability(monkeypatch, capsys):
    from soc_platform import __main__ as cli

    _zbar_missing(monkeypatch)
    capabilities.refresh()
    with pytest.raises(SystemExit):
        cli.cmd_config("check", "--no-env")
    out = capsys.readouterr().out
    assert "WARNING capability qr_decoding" in out and "libzbar0" in out
    assert "1 platform capability problem(s) on this host" in out


# ----------------------------------------------------------------------------- over HTTP

@pytest.fixture(scope="module")
def client(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("caps")
    saved = {k: os.environ.get(k) for k in ("SOC_AUTH_MODE", "SOC_DEV_JWT_SECRET", "SOC_ENVIRONMENT", "SOC_DATABASE_URL",
                                            "SOC_CONNECTORS_CONFIG", "SOC_REPORT_OUTPUT_DIR", "SOC_RAW_PAYLOAD_DIR")}
    os.environ.update({"SOC_AUTH_MODE": "dev", "SOC_DEV_JWT_SECRET": SECRET, "SOC_ENVIRONMENT": "test",
                       "SOC_DATABASE_URL": f"sqlite:///{(tmp / 'c.db').as_posix()}",
                       "SOC_CONNECTORS_CONFIG": str(ROOT / "config" / "connectors.yaml"),
                       "SOC_REPORT_OUTPUT_DIR": str(tmp / "reports"), "SOC_RAW_PAYLOAD_DIR": str(tmp / "raw")})
    from fastapi.testclient import TestClient

    from soc_platform.api import app as appmod
    from soc_platform.config import get_settings
    from soc_platform.core import db as dbm

    get_settings.cache_clear()
    dbm._default = None
    appmod.registry.cache_clear()
    yield TestClient(appmod.app)
    for k, v in saved.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v
    get_settings.cache_clear()
    dbm._default = None


def _h(client, user, roles):
    t = client.get(f"/api/v1/dev/token?user={user}&roles={roles}&mfa=true").json()["token"]
    return {"Authorization": f"Bearer {t}"}


def test_health_and_the_integrations_screen_show_a_broken_capability(client, monkeypatch):
    _zbar_missing(monkeypatch)
    capabilities.refresh()
    assert client.get("/health").json() == {"status": "ok"}           # anonymous callers learn nothing more
    h = client.get("/health", headers=_h(client, "a1", "analyst")).json()
    assert h["status"] == "degraded" and h["capabilities"]["degraded"] == ["qr_decoding"]
    assert client.get("/health/ready").status_code == 200              # still serving: only the capability is gone
    body = client.get("/api/v1/admin/capabilities", headers=_h(client, "a2", "analyst")).json()
    qr = {c["name"]: c for c in body["capabilities"]}["qr_decoding"]
    assert body["status"] == "degraded" and body["host"] and qr["state"] == "broken" and "libzbar0" in qr["fix"]
    assert client.get("/api/v1/admin/capabilities").status_code == 401


def test_healthy_capabilities_read_ok_everywhere(client):
    capabilities.refresh()
    if capabilities.broken():
        pytest.skip(f"this host really lacks: {[c['name'] for c in capabilities.broken()]}")
    h = client.get("/health", headers=_h(client, "a3", "auditor")).json()
    assert h["status"] == "ok" and h["capabilities"] == {"status": "ok", "degraded": []}


def test_the_metrics_gauge_is_zero_for_a_broken_capability(client, monkeypatch):
    from soc_platform.api import app as appmod
    from soc_platform.api.dashboards import prometheus
    from soc_platform.core.db import get_database

    _zbar_missing(monkeypatch)
    capabilities.refresh()
    with get_database().session() as s:
        text = prometheus(s, appmod.registry())
    assert 'soc_capability_ok{capability="qr_decoding"} 0' in text
    assert 'soc_capability_ok{capability="fuzzy_hashing"} 1' in text


def test_the_console_banner_and_integrations_card_read_the_capabilities():
    app_js = (ROOT / "soc_platform" / "api" / "static" / "app.js").read_text(encoding="utf-8")
    views = (ROOT / "soc_platform" / "api" / "static" / "views.js").read_text(encoding="utf-8")
    assert 'id="cap-status"' in app_js and "h.capabilities" in app_js
    assert "/api/v1/admin/capabilities" in views and "capabilitiesCard(caps)" in views
    alerts = (ROOT / "deploy" / "kubernetes" / "monitoring" / "alerts.yaml").read_text(encoding="utf-8")
    assert "SocCapabilityBroken" in alerts and "soc_capability_ok" in alerts
