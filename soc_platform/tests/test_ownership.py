"""The uploaded ownership mapping: which team owns which cloud resources and hosts the CMDB does not hold."""

from __future__ import annotations

import base64
import csv
import io
import os
from pathlib import Path

import pytest

from soc_platform.core.auth import Principal, Role
from soc_platform.core.ownership import OwnershipStore, match, parse
from soc_platform.core.watchlists import read_rows
from soc_platform.tests.test_watchlists import xlsx

LEAD = Principal("lena@example.com", "Lena", frozenset({Role.LEAD}), mfa=True)
ADMIN = Principal("ada@example.com", "Ada", frozenset({Role.ADMIN}), mfa=True)
ANALYST = Principal("ana@example.com", "Ana", frozenset({Role.ANALYST}), mfa=True)
ROOT = Path(__file__).resolve().parents[2]

SHEET = {"Cloud": [["Resource name", "Subscription", "Cloud", "Resource type", "Owning team", "Owner email", "Env",
                    "Criticality", "Notes"],
                   ["acmebackups", "", "Azure", "Storage Account", "Storage Team", "st@example.com", "prod", "High", ""],
                   ["web-*", "", "", "", "Web Platform", "", "", "critical", "all web hosts"],
                   ["", "sub-123", "", "", "Cloud Platform", "", "", "", "everything else there"],
                   ["web-01", "", "", "", "Web Exact", "", "", "", ""]],
         "Bad": [["Resource", "Team", "Criticality"], ["db-01", "", ""], ["db-02", "DB", "urgent"], ["has space", "DB", ""],
                 ["db-03", "DB", "low"], ["db-03", "DB", "low"]],
         "Notes": [["Just", "some", "text"], ["ignored", "", ""]]}


def _csv(rows: list[list[str]]) -> bytes:
    buf = io.StringIO()
    csv.writer(buf).writerows(rows)
    return buf.getvalue().encode("utf-8-sig")


# ---------------------------------------------------------------------------------------------- reading and matching


def test_a_workbook_is_read_with_forgiving_headers_and_every_unusable_row_is_named():
    rows, problems = parse(read_rows(xlsx(SHEET), "owners.xlsx"))
    got = {(r["name"], r["subscription"]): r for r in rows}
    want = {"cloud": "azure", "resource_type": "storage_account", "team": "Storage Team", "owner": "st@example.com",
            "environment": "prod", "criticality": "high"}
    assert {k: got[("acmebackups", "")][k] for k in want} == want
    assert ("", "sub-123") in got and ("db-03", "") in got
    reasons = {p["value"]: p["problem"] for p in problems}
    assert reasons["db-01"] == "no owning team"
    assert "critical, high, medium or low" in reasons["urgent"]
    assert "spaces" in reasons["has space"]
    assert "repeated" in reasons["db-03"]
    assert any("this sheet was skipped" in p["problem"] for p in problems)        # the "Notes" sheet has no header
    assert all(p["where"] for p in problems)


def test_the_most_specific_row_wins_and_cloud_or_type_narrow_a_row():
    rows, _ = parse(read_rows(xlsx(SHEET), "owners.xlsx"))
    assert match(rows, {"hostname": "WEB-01.corp.example"})["platform_team"] == "Web Exact"      # exact beats pattern
    assert match(rows, {"hostname": "web-02"})["platform_team"] == "Web Platform"               # pattern
    assert match(rows, {"resource_name": "other", "subscription": "SUB-123"})["platform_team"] == "Cloud Platform"
    hit = match(rows, {"resource_name": "acmebackups", "cloud": "azure", "resource_type": "STORAGE_ACCOUNT",
                       "subscription": "sub-123"})
    assert hit["platform_team"] == "Storage Team" and hit["criticality"] == "high"              # name beats subscription
    assert match(rows, {"resource_name": "acmebackups", "cloud": "aws", "resource_type": "storage_account"}) is None
    assert match(rows, {"hostname": "unknown"}) is None


def test_a_plain_csv_works_and_a_file_without_a_team_column_is_refused():
    rows, problems = parse(read_rows(_csv([["Hostname", "Team"], ["build-07", "CI"]]), "o.csv"))
    assert [(r["name"], r["team"]) for r in rows] == [("build-07", "CI")] and not problems
    rows, problems = parse(read_rows(_csv([["Hostname", "Owner"], ["build-07", "x@example.com"]]), "o.csv"))
    assert not rows and "team column" in problems[0]["problem"]


# ---------------------------------------------------------------------------------------------- the store


def test_an_upload_replaces_the_mapping_as_an_audited_version_and_a_preview_changes_nothing(session):
    from soc_platform.core.models import AuditRecord

    st = OwnershipStore(session)
    pre = st.upload(xlsx(SHEET), LEAD, filename="owners.xlsx", dry_run=True, coverage=lambda rows: {"rows_seen": len(rows)})
    assert pre["dry_run"] and pre["rows"] == 5 and pre["coverage"] == {"rows_seen": 5} and pre["problem_count"] >= 5
    assert OwnershipStore(session).rows() == []
    st.upload(xlsx(SHEET), LEAD, filename="owners.xlsx", note="first")
    second = st.upload(_csv([["Resource", "Team"], ["acmebackups", "Storage Team"]]), ADMIN, filename="o.csv")
    assert second["removed"] == 5 and second["added"] == 1           # its row has no cloud or type: a new row
    view = OwnershipStore(session).view()
    assert view["count"] == 1 and view["filename"] == "o.csv" and [h["rows"] for h in view["history"]] == [1, 5]
    st.clear(LEAD, "moving to the CMDB")
    assert OwnershipStore(session).rows() == []
    with pytest.raises(ValueError, match="already empty"):
        st.clear(LEAD)
    events = [a.event_type for a in session.query(AuditRecord).order_by(AuditRecord.seq).all()]
    assert events == ["ownership.uploaded", "ownership.uploaded", "ownership.cleared"]


def test_only_a_person_with_manage_ownership_changes_the_mapping(session):
    st = OwnershipStore(session)
    for who in (ANALYST, Principal("svc", "svc", frozenset({Role.ADMIN}), is_service=True)):
        with pytest.raises(PermissionError):
            st.upload(xlsx(SHEET), who)
    with pytest.raises(ValueError, match="no usable ownership row"):
        st.upload(_csv([["Hostname", "Team"], ["", "CI"]]), LEAD)
    with pytest.raises(ValueError, match="document type"):
        st.upload(_hostile(), LEAD, filename="o.xlsx")


def _hostile() -> bytes:
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("xl/workbook.xml", '<!DOCTYPE x [<!ENTITY e "boom">]><workbook>&e;</workbook>')
    return buf.getvalue()


def test_the_mapping_fills_the_gaps_the_cmdb_leaves_and_never_overrides_it(session):
    from soc_platform.core.models import Entity
    from soc_platform.domains.vulnerability.misconfig import MisconfigurationService
    from soc_platform.domains.vulnerability.models import CloudMisconfiguration

    class Cmdb:                         # a CMDB that knows one of the two resources
        def owner_for(self, attrs):
            return {"platform_team": "Team From CMDB", "owner": None} if attrs.get("hostname") == "web-02" else None

    class OneCmdb:
        def enabled_names(self):
            return ["cmdb_csv"]

        def get(self, name):
            return Cmdb()

    def resource(name: str) -> str:
        e = Entity(kind="asset", display_name=name, canonical_key=f"wiz:{name}")
        session.add(e)
        session.flush()
        return e.id

    gap = CloudMisconfiguration(resource_id=resource("acmebackups"), resource_name="acmebackups", rule="public blob",
                                severity="medium", cloud="azure", resource_type="STORAGE_ACCOUNT", subscription="sub-9")
    owned = CloudMisconfiguration(resource_id=resource("web-02"), resource_name="web-02", rule="open port",
                                  severity="high")        # the mapping's "web-*" row would also cover it
    session.add_all([gap, owned])
    session.flush()
    OwnershipStore(session).upload(xlsx(SHEET), LEAD, filename="owners.xlsx")
    svc = MisconfigurationService(session, OneCmdb(), actions=object())
    assert svc.enrich_ownership()["unknown_owner_resources"] == []
    assert (gap.platform_team, gap.owner) == ("Storage Team", "st@example.com")    # the gap: filled by the mapping
    assert owned.platform_team == "Team From CMDB"                                 # the CMDB's answer stands


# ---------------------------------------------------------------------------------------------- the API

SECRET = "test-secret-0123456789abcdef0123456789"
_ENV = ("SOC_AUTH_MODE", "SOC_DEV_JWT_SECRET", "SOC_DATABASE_URL", "SOC_CONNECTORS_CONFIG", "SOC_REPORT_OUTPUT_DIR",
        "SOC_RAW_PAYLOAD_DIR", "SOC_ENVIRONMENT")


@pytest.fixture
def client(tmp_path):
    from soc_platform.config import get_settings
    from soc_platform.core import db as dbm

    saved = {k: os.environ.get(k) for k in _ENV}
    os.environ.update({"SOC_AUTH_MODE": "dev", "SOC_DEV_JWT_SECRET": SECRET, "SOC_ENVIRONMENT": "test",
                       "SOC_DATABASE_URL": f"sqlite:///{tmp_path / 'own.db'}",
                       "SOC_CONNECTORS_CONFIG": str(ROOT / "config" / "connectors.yaml"),
                       "SOC_REPORT_OUTPUT_DIR": str(tmp_path / "reports"), "SOC_RAW_PAYLOAD_DIR": str(tmp_path / "raw")})
    get_settings.cache_clear()
    dbm._default = None
    from fastapi.testclient import TestClient

    from soc_platform.api import app as appmod

    appmod.registry.cache_clear()
    try:
        yield TestClient(appmod.app)
    finally:
        appmod.registry.cache_clear()
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        get_settings.cache_clear()
        dbm._default = None


def _tok(c, user, roles):
    return {"Authorization": f"Bearer {c.get(f'/api/v1/dev/token?user={user}&roles={roles}').json()['token']}"}


def test_the_console_previews_uploads_exports_and_clears_the_mapping(client):
    lead, analyst = _tok(client, "lena@example.com", "lead"), _tok(client, "ana@example.com", "analyst")
    body = {"content_b64": base64.b64encode(xlsx(SHEET)).decode(), "filename": "owners.xlsx", "note": "Wiz owners"}
    assert client.post("/api/v1/ownership/upload", headers=analyst, json=body).status_code == 403
    pre = client.post("/api/v1/ownership/upload", headers=lead, json={**body, "dry_run": True}).json()
    assert pre["dry_run"] and set(pre["coverage"]) >= {"misconfigurations_covered", "findings_covered"}
    assert client.get("/api/v1/ownership", headers=analyst).json()["count"] == 0
    done = client.post("/api/v1/ownership/upload", headers=lead, json=body).json()
    assert done["rows"] == 5 and set(done["applied"]) == {"misconfigurations", "findings"}
    view = client.get("/api/v1/ownership", headers=analyst).json()
    assert view["count"] == 5 and view["set_by"] == "lena@example.com" and view["by_team"]["Storage Team"] == 1
    exported = client.get("/api/v1/ownership/export", headers=analyst).text.lstrip("﻿")
    assert exported.splitlines()[0].startswith("name,subscription") and "Storage Team" in exported
    assert client.post("/api/v1/ownership/upload", headers=lead, json={**body, "content_b64": "%%%%"}).status_code == 400
    assert client.post("/api/v1/ownership/clear", headers=lead, json={"reason": "done"}).json()["cleared"]
    assert client.get("/api/v1/ownership", headers=analyst).json()["count"] == 0
