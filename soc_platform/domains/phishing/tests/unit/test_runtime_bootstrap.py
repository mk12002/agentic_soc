"""Tests for runtime bootstrap helper."""

from __future__ import annotations

from soc_platform.domains.phishing.tools import bootstrap_runtime_state as bootstrap


class _DummyMQ:
    def __init__(self) -> None:
        self.connected = False
        self.closed = False

    def connect(self) -> None:
        self.connected = True

    def declare_results_queue(self, queue_name: str) -> str:
        return queue_name

    def close(self) -> None:
        self.closed = True


def test_bootstrap_runtime_state_success(monkeypatch) -> None:
    monkeypatch.setattr(bootstrap, "RabbitMQClient", _DummyMQ)
    monkeypatch.setattr(
        bootstrap,
        "refresh_ioc_store",
        lambda force=True: {"refreshed": True, "force": bool(force)},
    )
    monkeypatch.setattr(
        bootstrap,
        "get_ioc_store_status",
        lambda: {"is_stale": False, "health_level": "healthy"},
    )

    report = bootstrap.bootstrap_runtime_state(
        declare_results_queue=True,
        refresh_ioc=True,
        force_ioc_refresh=True,
    )

    assert report["overall_ok"] is True
    assert report["declare_results_queue"]["ok"] is True
    assert report["declare_results_queue"]["queue"] == "email.results.queue"
    assert report["ioc_refresh"]["ok"] is True
    assert report["ioc_refresh"]["status"]["health_level"] == "healthy"


def test_bootstrap_runtime_state_handles_queue_error(monkeypatch) -> None:
    class _BrokenMQ(_DummyMQ):
        def connect(self) -> None:
            raise RuntimeError("broker down")

    monkeypatch.setattr(bootstrap, "RabbitMQClient", _BrokenMQ)
    monkeypatch.setattr(bootstrap, "refresh_ioc_store", lambda force=True: {"refreshed": True})
    monkeypatch.setattr(bootstrap, "get_ioc_store_status", lambda: {"is_stale": False})

    report = bootstrap.bootstrap_runtime_state(
        declare_results_queue=True,
        refresh_ioc=True,
        force_ioc_refresh=False,
    )

    assert report["overall_ok"] is False
    assert report["declare_results_queue"]["ok"] is False
    assert "broker down" in report["declare_results_queue"]["error"]


def test_bootstrap_runtime_state_handles_stale_ioc(monkeypatch) -> None:
    monkeypatch.setattr(bootstrap, "RabbitMQClient", _DummyMQ)
    monkeypatch.setattr(bootstrap, "refresh_ioc_store", lambda force=True: {"refreshed": False})
    monkeypatch.setattr(
        bootstrap,
        "get_ioc_store_status",
        lambda: {"is_stale": True, "health_level": "critical"},
    )

    report = bootstrap.bootstrap_runtime_state(
        declare_results_queue=True,
        refresh_ioc=True,
        force_ioc_refresh=False,
    )

    assert report["declare_results_queue"]["ok"] is True
    assert report["ioc_refresh"]["ok"] is False
    assert report["overall_ok"] is False
