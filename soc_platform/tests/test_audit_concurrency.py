"""The audit chain stays intact when many transactions append at the same moment (a scheduled job and several users).

Appending reads the chain's last hash and links the new record to it. Without serialisation, two transactions can
read the same last hash and fork the chain, which ``verify()`` then reports as tampering."""

from __future__ import annotations

import threading

from soc_platform.core.audit import AuditLog
from soc_platform.core.db import Database


def test_concurrent_appends_keep_one_unbroken_chain(tmp_path):
    db = Database(f"sqlite:///{tmp_path / 'audit.db'}")
    db.create_all()
    start = threading.Barrier(8)
    errors: list[str] = []

    def writer(n: int) -> None:
        try:
            start.wait()
            for i in range(15):
                with db.session() as s:
                    AuditLog(s).append(actor_type="human", actor_id=f"user{n}", event_type="test.event",
                                       subject_type="case", subject_id=f"c{n}-{i}", payload={"i": i})
        except Exception as exc:  # noqa: BLE001 - collected and asserted below
            errors.append(f"{type(exc).__name__}: {exc}")

    threads = [threading.Thread(target=writer, args=(n,)) for n in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    with db.session() as s:
        result = AuditLog(s).verify()
    assert not errors, errors[:3]
    assert result["ok"] and result["records"] == 8 * 15, result
