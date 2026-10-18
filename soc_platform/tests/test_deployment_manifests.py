"""The deployment packages keep their promises: no single replica of anything, probes that cannot cause a restart
storm, the restricted pod security profile, secrets only by reference, settings the platform knows, and overlays
that render. Kubernetes manifests are read as YAML; overlays are rendered with kubectl when it is installed."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
K8S = ROOT / "deploy" / "kubernetes"


def _docs(path: Path) -> list[dict]:
    return [d for d in yaml.safe_load_all(path.read_text(encoding="utf-8")) if d]


def _base() -> dict[tuple[str, str], dict]:
    out = {}
    for f in sorted((K8S / "base").glob("*.yaml")):
        if f.name == "kustomization.yaml":
            continue
        for d in _docs(f):
            out[(d["kind"], d["metadata"]["name"])] = d
    return out


def _containers(dep: dict) -> list[dict]:
    spec = dep["spec"]["template"]["spec"]
    return spec.get("initContainers", []) + spec["containers"]


def test_nothing_runs_as_a_single_replica():
    base = _base()
    deps = {n: d for (k, n), d in base.items() if k == "Deployment"}
    assert set(deps) == {"soc-api", "soc-scheduler"}
    for name, dep in deps.items():
        assert dep["spec"]["replicas"] >= 2, name
        assert dep["spec"]["strategy"]["rollingUpdate"]["maxUnavailable"] == 0, name     # deploys keep capacity
        assert ("PodDisruptionBudget", name) in base, name                                 # drains keep one
        spread = dep["spec"]["template"]["spec"]["topologySpreadConstraints"]
        assert {c["topologyKey"] for c in spread} == {"kubernetes.io/hostname", "topology.kubernetes.io/zone"}, name
    assert base[("HorizontalPodAutoscaler", "soc-api")]["spec"]["minReplicas"] >= 2


def test_liveness_never_depends_on_the_database_and_readiness_does():
    api = _base()[("Deployment", "soc-api")]
    c = api["spec"]["template"]["spec"]["containers"][0]
    assert c["livenessProbe"]["httpGet"]["path"] == "/health/live"
    assert c["startupProbe"]["httpGet"]["path"] == "/health/live"
    assert c["readinessProbe"]["httpGet"]["path"] == "/health/ready"


def test_the_scheduler_has_a_liveness_probe_that_never_asks_the_database():
    sch = _base()[("Deployment", "soc-scheduler")]["spec"]["template"]["spec"]["containers"][0]
    path = next(e["value"] for e in sch["env"] if e["name"] == "SOC_SCHEDULER_LIVENESS_FILE")
    probe = " ".join(sch["livenessProbe"]["exec"]["command"])
    assert path in probe and "getmtime" in probe and "SOC_DATABASE_URL" not in probe
    assert sch["livenessProbe"]["initialDelaySeconds"] >= 60


def test_shutdown_fits_inside_the_grace_period():
    base = _base()
    api = base[("Deployment", "soc-api")]["spec"]["template"]["spec"]
    settings = base[("ConfigMap", "soc-platform-settings")]["data"]
    pre_stop = 10                                                   # the preStop pause in api.yaml
    assert "sleep(10)" in " ".join(api["containers"][0]["lifecycle"]["preStop"]["exec"]["command"])
    assert api["terminationGracePeriodSeconds"] > pre_stop + int(settings["SOC_SHUTDOWN_GRACE_SECONDS"])


def test_every_container_meets_the_restricted_pod_security_profile():
    base = _base()
    assert base[("Namespace", "agentic-soc")]["metadata"]["labels"]["pod-security.kubernetes.io/enforce"] == "restricted"
    for (kind, name), dep in base.items():
        if kind != "Deployment":
            continue
        pod = dep["spec"]["template"]["spec"]
        assert pod["securityContext"]["runAsNonRoot"] is True and pod["securityContext"]["runAsUser"] == 1001, name
        assert pod["securityContext"]["seccompProfile"]["type"] == "RuntimeDefault", name
        assert pod["automountServiceAccountToken"] is False, name
        for c in _containers(dep):
            sc = c["securityContext"]
            assert sc["allowPrivilegeEscalation"] is False and sc["readOnlyRootFilesystem"] is True, (name, c["name"])
            assert sc["capabilities"]["drop"] == ["ALL"], (name, c["name"])
            assert c["resources"]["requests"] and c["resources"]["limits"]["memory"], (name, c["name"])


def test_secrets_are_only_referenced_and_settings_are_ones_the_platform_knows():
    from soc_platform.settings_check import SPEC, TEXT, _known

    settings = _base()[("ConfigMap", "soc-platform-settings")]["data"]
    secretish = ("KEY", "SECRET", "PASSWORD", "TOKEN", "DATABASE_URL", "WEBHOOK")
    # a *_FILE setting is a path to a mounted secret (Key Vault), not a secret
    secret_value = lambda k: any(s in k for s in secretish) and not k.endswith("_FILE")
    assert not [k for k in settings if secret_value(k)]
    unknown = [k for k in settings if k.startswith("SOC_") and k not in SPEC and k not in TEXT]
    assert unknown == []
    assert settings["SOC_BLOB_STORE"] == "database" and settings["SOC_EMBEDDED_SCHEDULER"] == "0"
    assert settings["SOC_ENVIRONMENT"] == "prod"
    for overlay in ("azure", "onprem"):
        data = _docs(K8S / "overlays" / overlay / "settings.yaml")[0]["data"]
        assert not [k for k in data if secret_value(k)], overlay
        assert all(v.startswith("/mnt/secrets/") for k, v in data.items() if k.endswith("_FILE")), overlay
        assert not [k for k in data if k.startswith("SOC_") and not _known(k)], overlay


def test_default_deny_network_policy_with_explicit_allowances():
    base = _base()
    deny = base[("NetworkPolicy", "default-deny")]["spec"]
    assert deny["podSelector"] == {} and set(deny["policyTypes"]) == {"Ingress", "Egress"}
    egress = base[("NetworkPolicy", "soc-egress")]["spec"]["egress"]
    assert {p["port"] for rule in egress for p in rule["ports"]} == {53, 443}      # the database: per overlay
    dns = next(r for r in egress if any(p["port"] == 53 for p in r["ports"]))
    assert dns["to"][0]["podSelector"] == {"matchLabels": {"k8s-app": "kube-dns"}}   # the cluster resolver only


def test_compose_and_image_use_the_shared_store_and_readiness():
    compose = (ROOT / "deploy" / "docker-compose.yml").read_text(encoding="utf-8")
    assert "SOC_BLOB_STORE: database" in compose
    assert "127.0.0.1:8080/health/ready" in (ROOT / "deploy" / "Dockerfile").read_text(encoding="utf-8")


def test_images_and_packages_are_pinned_so_a_moved_tag_cannot_change_what_runs():
    import re

    dockerfile = (ROOT / "deploy" / "Dockerfile").read_text(encoding="utf-8")
    froms = re.findall(r"^FROM\s+(\S+)", dockerfile, re.MULTILINE)
    assert froms and all("@sha256:" in f for f in froms), froms
    installs = [ln for ln in dockerfile.splitlines() if "apt-get install" in ln]
    assert "--require-hashes" in dockerfile and not [ln for ln in installs if " curl" in ln]       # no curl, pip
    for compose in ("docker-compose.yml",):
        images = re.findall(r"^\s+image:\s+(\S+)", (ROOT / "deploy" / compose).read_text(encoding="utf-8"), re.MULTILINE)
        third_party = [i for i in images if not i.startswith("soc-platform")]
        assert third_party and all("@sha256:" in i for i in third_party), third_party
    for overlay in ("azure", "onprem"):
        k = yaml.safe_load((K8S / "overlays" / overlay / "kustomization.yaml").read_text(encoding="utf-8"))
        assert all("digest" in i and "newTag" not in i for i in k["images"]), overlay
    for wf in (ROOT / ".github" / "workflows").glob("*.yml"):
        uses = re.findall(r"uses:\s+(\S+)", wf.read_text(encoding="utf-8"))
        assert all(re.search(r"@[0-9a-f]{40}$", u) for u in uses), [u for u in uses if not re.search(r"@[0-9a-f]{40}$", u)]


def test_only_the_migration_step_holds_schema_rights():
    base = _base()
    settings = base[("ConfigMap", "soc-platform-settings")]["data"]
    assert settings["SOC_SCHEMA_MANAGE"] == "0"
    api = base[("Deployment", "soc-api")]["spec"]["template"]["spec"]
    init_refs = [e.get("secretRef", {}).get("name") for e in api["initContainers"][0]["envFrom"]]
    assert init_refs[-1] == "soc-platform-migrator"                     # last source wins: the schema owner
    for dep in (api, base[("Deployment", "soc-scheduler")]["spec"]["template"]["spec"]):
        refs = [e.get("secretRef", {}).get("name") for c in dep["containers"] for e in c["envFrom"]]
        assert "soc-platform-migrator" not in refs
    for overlay in ("azure", "onprem"):
        data = _docs(K8S / "overlays" / overlay / "settings.yaml")[0]["data"]
        assert data["SOC_DB_RUNTIME_ROLE"], overlay


def test_production_compose_fails_closed_and_the_demo_is_an_explicit_override():
    compose = yaml.safe_load((ROOT / "deploy" / "docker-compose.yml").read_text(encoding="utf-8"))
    env = compose["x-platform-env"]
    assert env["SOC_ENVIRONMENT"] == "${SOC_ENVIRONMENT:-prod}" and env["SOC_AUTH_MODE"] == "${SOC_AUTH_MODE:-entra}"
    assert "SOC_DEV_TOKENS_REMOTE" not in env and "SOC_DEV_JWT_SECRET" not in env
    assert "sslmode=verify-full" in env["SOC_DATABASE_URL"] and env["SOC_DATABASE_URL"].startswith("postgresql+psycopg2://soc_app:")
    services = compose["services"]
    assert services["platform-api"]["ports"][0].startswith("${SOC_API_BIND:-127.0.0.1}")
    for name in ("platform-api", "platform-scheduler", "platform-migrate"):
        assert services[name]["read_only"] is True and services[name]["cap_drop"] == ["ALL"], name
    assert "--requirepass" in services["redis"]["command"]
    demo = yaml.safe_load((ROOT / "deploy" / "docker-compose.demo.yml").read_text(encoding="utf-8"))
    assert demo["x-demo-env"]["SOC_AUTH_MODE"] == "dev" and demo["x-demo-env"]["SOC_CONNECTOR_MODE"] == "fake"


def test_azure_keeps_secrets_out_of_kubernetes_and_onprem_lets_the_database_talk():
    spc = _docs(K8S / "overlays" / "azure" / "keyvault-secrets.yaml")[0]
    assert "secretObjects" not in spc["spec"]                          # nothing synced into etcd
    assert "soc-database-migrator-url" in spc["spec"]["parameters"]["objects"]
    sa = _docs(K8S / "overlays" / "azure" / "serviceaccount.yaml")[0]
    assert "azure.workload.identity/client-id" in sa["metadata"]["annotations"]
    agw = _docs(K8S / "overlays" / "azure" / "network.yaml")[0]
    assert "ipBlock" in agw["spec"]["ingress"][0]["from"][0]          # AGIC sends from its subnet, not a namespace
    policies = {d["metadata"]["name"]: d for d in _docs(K8S / "overlays" / "onprem" / "network.yaml")}
    assert {"soc-pg", "soc-pg-pooler", "soc-database-egress"} <= set(policies)
    pg = _docs(K8S / "overlays" / "onprem" / "postgres.yaml")[0]["spec"]
    assert "soc-pg-pooler" in pg["certificates"]["serverAltDNSNames"] and pg["managed"]["roles"][0]["name"] == "soc_runtime"
    url = (K8S / "overlays" / "onprem" / "database-url.yaml").read_text(encoding="utf-8")
    assert url.count("sslmode=verify-full") == 3 and "soc_runtime:" in url


@pytest.mark.skipif(shutil.which("kubectl") is None, reason="kubectl not installed")
@pytest.mark.parametrize("overlay", ["azure", "onprem"])
def test_overlays_render_and_harden_the_base(overlay):
    out = subprocess.run(["kubectl", "kustomize", str(K8S / "overlays" / overlay)], capture_output=True, text=True,
                         timeout=120, check=True).stdout
    docs = {(d["kind"], d["metadata"]["name"]): d for d in yaml.safe_load_all(out) if d}
    api = docs[("Deployment", "soc-api")]
    strict = {c["topologyKey"] for c in api["spec"]["template"]["spec"]["topologySpreadConstraints"]
              if c["whenUnsatisfiable"] == "DoNotSchedule"}
    assert "kubernetes.io/hostname" in strict
    assert docs[("Ingress", "soc-api")]
    for d in docs.values():
        assert d["metadata"].get("namespace", "agentic-soc") == "agentic-soc" or d["kind"] == "Namespace"
    if overlay == "azure":
        assert api["spec"]["replicas"] == 3 and "topology.kubernetes.io/zone" in strict
        assert ("SecretProviderClass", "soc-keyvault") in docs
    else:
        pg = docs[("Cluster", "soc-pg")]["spec"]
        assert pg["instances"] == 3 and pg["minSyncReplicas"] >= 1 and pg["backup"]["barmanObjectStore"]
        assert docs[("Pooler", "soc-pg-pooler")]["spec"]["instances"] >= 2
        for dep in (api, docs[("Deployment", "soc-scheduler")]):
            for c in _containers(dep):                                 # init-db too: never the SQLite default
                assert any(e["name"] == "SOC_DATABASE_URL" for e in c.get("env", [])), c["name"]
        sched_env = docs[("Deployment", "soc-scheduler")]["spec"]["template"]["spec"]["containers"][0]["env"]
        assert any(e["name"] == "SOC_SCHEDULER_LIVENESS_FILE" for e in sched_env)    # the overlay keeps base env
