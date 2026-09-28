"""Schema evolution: an existing database from an earlier release gains the columns a newer release adds (when that
is safe), without losing data - on SQLite and on PostgreSQL."""

from __future__ import annotations

from sqlalchemy import inspect, text

from soc_platform.core.db import Database


def test_start_up_adds_new_optional_columns_and_keeps_the_data(tmp_path):
    db = Database(f"sqlite:///{tmp_path / 'old.db'}")
    db.create_all()
    with db.engine.begin() as c:                                   # an older release: llm_calls without latency_ms
        c.execute(text('INSERT INTO llm_calls (id, ts, workflow, provider, model, prompt_redacted, response, '
                       "prompt_tokens, completion_tokens, grounded, status) VALUES ('a1', '2026-09-01 10:00:00', "
                       "'w', 'p', 'm', '', '', 1, 2, TRUE, 'ok')"))
        if db.engine.dialect.name == "sqlite":
            c.execute(text("ALTER TABLE llm_calls DROP COLUMN latency_ms"))
        else:
            c.execute(text('ALTER TABLE llm_calls DROP COLUMN "latency_ms"'))
    assert "latency_ms" not in {col["name"] for col in inspect(db.engine).get_columns("llm_calls")}
    db.create_all()                                                # the new release starts
    assert "latency_ms" in {col["name"] for col in inspect(db.engine).get_columns("llm_calls")}
    with db.engine.connect() as c:
        assert c.execute(text("SELECT prompt_tokens, latency_ms FROM llm_calls WHERE id = 'a1'")).one() == (1, None)
    db.create_all()                                                # and again: nothing left to do, no error


def test_model_call_durations_are_recorded_and_summarised(session):
    from soc_platform.config import Settings
    from soc_platform.llm.gateway import Completion, LLMGateway, Provider

    class Slowish(Provider):
        name = "scripted"

        def complete(self, system, user, *, tier):
            import time

            time.sleep(0.02)
            return Completion('{"summary": "ok", "claims": []}', 10, 5, "m")

    gw = LLMGateway(session, Settings(llm_provider="openai_compatible"), provider=Slowish())
    for _ in range(3):
        gw.complete_json("latency.test", "s", "u")
    st = gw.latency_status()["latency.test"]
    assert st["calls"] == 3 and st["median_ms"] >= 15 and st["p95_ms"] >= st["median_ms"]
