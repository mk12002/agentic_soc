"""Live checks against real public APIs (no credentials). Run with SOC_LIVE_TESTS=1."""

from __future__ import annotations

import os

import pytest

from soc_platform.connectors.registry import ConnectorRegistry

pytestmark = [pytest.mark.live,
              pytest.mark.skipif(os.environ.get("SOC_LIVE_TESTS") != "1", reason="set SOC_LIVE_TESTS=1 for live API tests")]


@pytest.fixture(scope="module")
def live():
    return ConnectorRegistry({"connectors": {n: {"enabled": True, "mode": "live"} for n in ("nvd", "epss", "cisa_kev")}})


def test_cisa_kev_catalogue(live):
    cat = live.get("cisa_kev").catalog()
    assert len(cat) > 1000 and "CVE-2021-44228" in cat


def test_epss_scores(live):
    s = live.get("epss").scores(["CVE-2021-44228"])
    assert 0.5 < s["CVE-2021-44228"]["epss"] <= 1.0


def test_nvd_detail(live):
    d = live.get("nvd").cve_detail("CVE-2021-44228")
    assert d["cvss"] == 10.0 and d["references"]
