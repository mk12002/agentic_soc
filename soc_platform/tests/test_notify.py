"""Outbound notifications: important findings reach Teams / Slack / a webhook once per channel, escalations are sent
again, failures are retried up to a limit, and destinations come only from configuration (HTTPS)."""

from __future__ import annotations

import pytest

from soc_platform.core import notify
from soc_platform.intelligence.models import Insight


@pytest.fixture()
def hooks(monkeypatch):
    monkeypatch.setenv("SOC_NOTIFY_WEBHOOKS", "teams|https://acme.webhook.office.com/x/secret,json|https://siem.acme-demo.com/hook")
    monkeypatch.delenv("SOC_NOTIFY_MIN_SEVERITY", raising=False)
    monkeypatch.setenv("SOC_PUBLIC_URL", "https://soc.acme-demo.com/")


def _insight(session, key, severity, **kw):
    i = Insight(rule=kw.pop("rule", "test_rule"), dedupe_key=key, title=kw.pop("title", f"Finding {key}"),
                severity=severity, next_steps=["Isolate the host", "Reset the password"], domains=["incident"], **kw)
    session.add(i)
    session.flush()
    return i


def test_only_https_channels_from_configuration_are_used(monkeypatch):
    monkeypatch.setenv("SOC_NOTIFY_WEBHOOKS", "teams|https://a.example/x, slack|http://evil.example/x, json|http://localhost:9/h,"
                                              "carrier-pigeon|https://b.example, nonsense, json|ftp://c.example/")
    assert [c.label for c in notify.channels()] == ["teams:a.example", "json:localhost"]
    monkeypatch.delenv("SOC_NOTIFY_WEBHOOKS")
    assert notify.channels() == []


def test_findings_at_or_above_the_threshold_are_sent_once_per_channel(session, hooks):
    sent = []
    crit = _insight(session, "k-crit", "critical")
    _insight(session, "k-high", "high")
    _insight(session, "k-med", "medium")                                   # below the default threshold
    _insight(session, "k-done", "critical", status="resolved")             # no longer open
    out = notify.deliver(session, post=lambda url, body: sent.append((url, body)))
    assert out["sent"] == 4 and out["failed"] == 0                          # 2 findings x 2 channels
    assert sent[0][0].startswith("https://acme.webhook.office.com") and sent[0][1]["text"].startswith("[CRITICAL] Finding k-crit")
    assert "- Isolate the host" in sent[0][1]["text"] and "Open: https://soc.acme-demo.com/#/intelligence" in sent[0][1]["text"]
    assert sent[1][1]["id"] == crit.id and sent[1][1]["severity"] == "critical"         # structured JSON for a SIEM
    assert notify.deliver(session, post=lambda url, body: sent.append(body))["sent"] == 0   # nothing repeated
    # an escalation is news: it is sent again
    session.get(Insight, session.query(Insight).filter_by(dedupe_key="k-high").one().id).severity = "critical"
    assert notify.deliver(session, post=lambda url, body: sent.append(body))["sent"] == 2
    rows = notify.recent(session, limit=50)
    assert len(rows) == 6 and all(r["status"] == "sent" for r in rows)
    assert all("secret" not in r["channel"] for r in rows)                  # the webhook URL is never stored


def test_the_threshold_is_configurable(session, hooks, monkeypatch):
    monkeypatch.setenv("SOC_NOTIFY_MIN_SEVERITY", "medium")
    _insight(session, "m1", "medium")
    _insight(session, "l1", "low")
    assert notify.deliver(session, post=lambda url, body: None)["sent"] == 2   # medium on 2 channels, low skipped


def test_failures_are_recorded_and_retried_up_to_a_limit(session, hooks):
    _insight(session, "k-fail", "critical")

    def down(url, body):
        raise RuntimeError("webhook answered 503")

    for _ in range(notify.MAX_ATTEMPTS + 2):
        notify.deliver(session, post=down)
    rows = notify.recent(session)
    assert len(rows) == 2 and all(r["status"] == "failed" and r["attempts"] == notify.MAX_ATTEMPTS for r in rows)
    assert "503" in rows[0]["error"]
    # a channel that recovers before the limit gets the message
    _insight(session, "k-later", "high")
    calls = {"n": 0}

    def flaky(url, body):
        calls["n"] += 1
        if calls["n"] <= 2:
            raise RuntimeError("timeout")

    notify.deliver(session, post=flaky)
    assert notify.deliver(session, post=flaky)["sent"] == 2


def test_no_channels_means_nothing_is_sent(session, monkeypatch):
    monkeypatch.delenv("SOC_NOTIFY_WEBHOOKS", raising=False)
    _insight(session, "k-x", "critical")
    assert notify.deliver(session, post=lambda *_: pytest.fail("must not send"))["skipped_no_channels"] == 1


def test_notify_is_a_scheduled_job(db, hooks, monkeypatch):
    from soc_platform import jobs

    assert jobs.JOBS["notify"] == ("SOC_JOB_NOTIFY_SECONDS", 60)
    sent = []
    monkeypatch.setattr(notify, "_post", lambda url, body: sent.append(url))
    with db.session() as s:
        _insight(s, "k-job", "high")
    run = jobs.run_job("notify", db=db, sleep=lambda _: None)
    assert run.status == "ok" and run.summary["sent"] == 2 and len(sent) == 2


def test_webhooks_can_come_from_a_mounted_secret_file(monkeypatch, tmp_path):
    f = tmp_path / "hooks"
    f.write_text("slack|https://hooks.slack.com/services/T/B/x\n", encoding="utf-8")
    monkeypatch.delenv("SOC_NOTIFY_WEBHOOKS", raising=False)
    monkeypatch.setenv("SOC_NOTIFY_WEBHOOKS_FILE", str(f))
    assert [c.label for c in notify.channels()] == ["slack:hooks.slack.com"]
