"""Supply chain: the dependency lock matches the requirements and the environment, the SBOM is a valid, deterministic
CycloneDX document naming every component, the container build is constrained by the lock, and the pre-commit scan
blocks secrets and confidential names."""

from __future__ import annotations

import importlib.util
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_the_lock_pins_every_requirement_and_matches_the_environment():
    sc = _load("supply_chain")
    direct = sc.direct_requirements()
    lock = (ROOT / "requirements" / "platform.lock").read_text(encoding="utf-8")
    pinned = {sc._canon(line.split("==")[0]): line.split("==")[1] for line in lock.splitlines() if "==" in line}
    assert set(direct) <= set(pinned), sorted(set(direct) - set(pinned))       # every direct requirement is locked
    assert sc.main(["check"]) == 0, "requirements/platform.lock is stale: run python scripts/supply_chain.py lock"


def test_the_sbom_is_a_deterministic_cyclonedx_document_naming_every_component(tmp_path):
    sc = _load("supply_chain")
    a, b = tmp_path / "a.json", tmp_path / "b.json"
    sc.main(["sbom", "--out", str(a)])
    sc.main(["sbom", "--out", str(b)])
    assert a.read_bytes() == b.read_bytes()                                    # same environment, same bytes
    doc = json.loads(a.read_text(encoding="utf-8"))
    assert doc["bomFormat"] == "CycloneDX" and doc["specVersion"] == "1.5" and doc["serialNumber"].startswith("urn:uuid:")
    names = {c["purl"].split("/")[1].split("@")[0] for c in doc["components"]}
    assert set(sc.direct_requirements()) <= names
    assert all(c["version"] and c["purl"].startswith("pkg:pypi/") for c in doc["components"])
    direct_refs = set(doc["dependencies"][0]["dependsOn"])
    assert len(direct_refs) == len([c for c in doc["components"] if c["properties"][0]["value"] == "true"])


def test_the_container_build_is_constrained_by_the_lock():
    docker = (ROOT / "deploy" / "Dockerfile").read_text(encoding="utf-8")
    assert "-r requirements/platform.txt -c requirements/platform.lock" in docker
    # runtime image hardening (each was a Trivy finding): the base image's stale setuptools is upgraded to the locked
    # version, and pip - whose vendored libraries carried known CVEs - is not shipped
    assert "--upgrade setuptools -c /tmp/platform.lock" in docker
    assert "python -m pip uninstall -y pip" in docker


def test_the_pre_commit_scan_blocks_secrets_and_confidential_names(tmp_path):
    pc = _load("precommit_scan")
    (tmp_path / ".env").write_text("SOC_LLM_API_KEY=sk-test-0123456789abcdef\nSOC_ORG_DOMAINS=example.invalid\n",
                                   encoding="utf-8")
    clean = tmp_path / "clean.py"
    clean.write_text("print('nothing to see')\n", encoding="utf-8")
    leaked = tmp_path / "leak.md"
    leaked.write_text("key: sk-test-0123456789abcdef\n", encoding="utf-8")
    named = tmp_path / "named.md"
    named.write_text("Prepared for Contoso Widgets\n", encoding="utf-8")
    findings = pc.scan([clean, leaked, named], env_file=tmp_path / ".env", banned=r"(?i)contoso")
    assert sorted((Path(f).name, why) for f, why in findings) == [("leak.md", "secret value from .env"),
                                                                 ("named.md", "confidential name")]
    assert pc.scan([clean], env_file=tmp_path / ".env", banned=None) == []


def test_ci_runs_every_gate():
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    for gate in ("ruff check", "bandit", "pip_audit", "node --check", "SOC_TEST_POSTGRES", "supply_chain.py sbom",
                 "trivy", "precommit_scan.py", "pytest"):
        assert gate in ci, gate
    subprocess.run(["git", "check-ignore", "-q", "sbom/x.json"], cwd=ROOT, check=True)   # generated, never committed
