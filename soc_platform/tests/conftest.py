from __future__ import annotations

from typing import Any

import pytest

from soc_platform.core.actions import ActionRegistry, ActionSpec
from soc_platform.core.auth import Principal, Role
from soc_platform.core.db import Database


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
