"""User identity resolution across tools (U07, IM-T03): never merge two people, no built-in phantoms."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "eval_identity_resolution.py"


@pytest.mark.parametrize("seed", [5, 9])
def test_identities_never_falsely_merged(seed):
    spec = importlib.util.spec_from_file_location("eval_id", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    r = mod.evaluate(150, seed)
    assert r["false_merges"] == 0, r["false_merge_examples"]
    assert r["phantom_builtin_identities"] == 0, r
    assert r["split_rate"] <= 0.02, r


def _ctx():
    from soc_platform.core.db import Database

    db = Database("sqlite://")
    db.create_all()
    return db


def _entra(oid, upn, sam=None, aliases=()):
    from datetime import datetime, timezone

    from soc_platform.core.schema import NormalizedRecord

    return NormalizedRecord(kind="identity", tool="entra", source_type="user", source_id=oid,
                            observed_at=datetime.now(timezone.utc),
                            keys={"entra_object_id": oid, "upn": upn, "email": upn, "sam": sam},
                            attributes={"display_name": upn, "email_aliases": [upn, *aliases]})


def _event(tool, ref, i):
    from datetime import datetime, timezone

    from soc_platform.core.schema import NormalizedRecord

    return NormalizedRecord(kind="alert", tool=tool, source_type="evt", source_id=f"{tool}-{i}",
                            observed_at=datetime.now(timezone.utc), refs=[ref])


def _identities(s):
    from soc_platform.core.models import Entity

    return s.query(Entity).filter(Entity.kind == "identity").all()


def test_alias_and_sam_seen_before_directory_collapse_into_one_person():
    from soc_platform.core.context_store import ContextStore
    from soc_platform.core.identity import user_ref

    db = _ctx()
    with db.session() as s:
        st = ContextStore(s)
        st.ingest(_event("umbrella", user_ref("jane@corp.cci.com"), 1))            # alias
        st.ingest(_event("crowdstrike", user_ref(r"CORP\jdoe", default_domain="corp.cci.com"), 2))  # SAM != UPN prefix
        st.ingest(_event("email", user_ref("jane.doe@corp.cci.com"), 3))           # primary address
        assert len(_identities(s)) == 3
        st.ingest(_entra("oid-1", "jane.doe@corp.cci.com", "jdoe", ["jane@corp.cci.com"]))
        assert len(_identities(s)) == 1
        st.ingest(_event("delinea", user_ref(r"CORP\jdoe", default_domain="corp.cci.com"), 4))
        assert len(_identities(s)) == 1


def test_two_directory_users_are_never_merged_even_when_a_record_bridges_them():
    from soc_platform.core.context_store import ContextStore
    from soc_platform.core.models import UnresolvedItem
    from soc_platform.core.schema import NormalizedRecord

    db = _ctx()
    with db.session() as s:
        st = ContextStore(s)
        st.ingest(_entra("oid-1", "a.one@corp.cci.com", "aone"))
        st.ingest(_entra("oid-2", "b.two@corp.cci.com", "btwo"))
        # A corrupted record claims oid-1 together with the other person's address: must not merge.
        st.ingest(_entra("oid-1", "b.two@corp.cci.com", "aone"))
        assert len(_identities(s)) == 2
        assert s.query(UnresolvedItem).count() == 1
        # A built-in account never becomes a person.
        from soc_platform.core.identity import user_ref
        assert user_ref(r"NT AUTHORITY\SYSTEM") is None and user_ref("WEB01$") is None
        assert isinstance(_entra("x", "y@z.com"), NormalizedRecord)
