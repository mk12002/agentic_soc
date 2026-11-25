"""Dependency lock and software bill of materials (SBOM) for the platform.

    python scripts/supply_chain.py lock   [--out requirements/platform.lock]
    python scripts/supply_chain.py sbom   [--out sbom/platform.cdx.json]
    python scripts/supply_chain.py check                        # the lock matches the environment and the requirements
    python scripts/supply_chain.py image-lock                   # requirements/image*.lock: Linux, hash-pinned (Docker)
    python scripts/supply_chain.py windows-lock                 # requirements/windows*.lock: Windows host, hash-pinned

Both are derived from the same thing: the direct requirements in requirements/platform.txt and their transitive
dependencies as installed in the current environment (markers evaluated for this platform). ``lock`` writes every
package with its exact version (used as pip constraints by the container build and audited by pip-audit in CI);
``sbom`` writes a CycloneDX 1.5 JSON document (component, version, package URL, licence, SHA-256 of the lock line set).
Output is deterministic: the same environment gives byte-identical files.

``image-lock`` resolves the container images' dependencies on Linux, inside the same pinned base image the Dockerfile
uses, with a SHA-256 for every file (``requirements/image.lock`` for the platform, ``requirements/image-engine.lock``
with the phishing ML engine). The Dockerfile installs them with ``--require-hashes``: a package that changed on the
index after it was locked fails the build instead of reaching the image. The versions are constrained by
``platform.lock``, so the image and the tested environment agree; ``check`` verifies that too.

``windows-lock`` does the same for a Windows host (``deploy/windows/install.ps1``): ``requirements/windows.lock`` and
``requirements/windows-engine.lock``, resolved on Windows with this interpreter (run it with the deployment's Python,
3.13; the hashes cover every published file of each version, so the locks install on 3.11 to 3.13) and held to the
image locks' versions, so a Windows host and a container run the same packages. Needs pip-tools in the environment.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata as md
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REQUIREMENTS = ROOT / "requirements" / "platform.txt"
# the Dockerfile's base image (keep in step with its FROM lines)
BASE_IMAGE = "python:3.11-slim@sha256:e88e9763f943ec1834f992a4b51e0f24500486803e8bc534e5767af9ea65f6ce"
PIP_TOOLS = "pip-tools==7.5.2"
IMAGE_LOCKS = {"image.lock": ["platform.txt"], "image-engine.lock": ["platform.txt", "phishing.txt"]}
WINDOWS_LOCKS = {"windows.lock": ["platform.txt"], "windows-engine.lock": ["platform.txt", "phishing.txt"]}
PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s;\\]+)", re.MULTILINE)


def image_lock() -> int:
    import subprocess  # nosec B404 - runs the fixed docker command below

    req = ROOT / "requirements"
    steps = [f"pip install -q {PIP_TOOLS}"]
    for out, inputs in IMAGE_LOCKS.items():
        steps.append("pip-compile -q --generate-hashes --allow-unsafe --strip-extras --no-header "
                     f"--annotation-style=line -c platform.lock -o /tmp/{out} {' '.join(inputs)} && cp /tmp/{out} /req/{out}")
    cmd = ["docker", "run", "--rm", "-v", f"{req.resolve()}:/req", "-w", "/req", BASE_IMAGE, "bash", "-c", " && ".join(steps)]
    return subprocess.run(cmd, check=False).returncode  # nosec B603 - fixed arguments, no shell


def windows_lock() -> int:
    """Hash-pinned locks for a Windows host, resolved here and held to the image locks' versions."""
    import subprocess  # nosec B404 - runs pip-compile from this environment with fixed arguments
    import tempfile

    if sys.platform != "win32":
        print("windows-lock resolves for Windows: run it on Windows with the deployment's Python (3.13)")
        return 2
    req = ROOT / "requirements"
    pins: dict[str, str] = {}
    for name in IMAGE_LOCKS:            # the container's versions, without Linux-only markers or hashes
        for m in PIN.finditer((req / name).read_text(encoding="utf-8")):
            pins.setdefault(_canon(m.group(1)), m.group(2))
    with tempfile.TemporaryDirectory() as tmp:
        cons = Path(tmp) / "image-versions.txt"
        cons.write_text("".join(f"{k}=={v}\n" for k, v in sorted(pins.items())), encoding="utf-8")
        for out, inputs in WINDOWS_LOCKS.items():
            cmd = [sys.executable, "-m", "piptools", "compile", "-q", "--generate-hashes", "--allow-unsafe",
                   "--strip-extras", "--no-header", "--annotation-style=line", "--no-emit-index-url",
                   "-c", "platform.lock", "-c", str(cons), "-o", str(Path(tmp) / out), *inputs]
            rc = subprocess.run(cmd, cwd=req, check=False).returncode  # nosec B603 - fixed arguments, no shell
            if rc:
                return rc
            body = (Path(tmp) / out).read_text(encoding="utf-8").replace(str(cons), "image locks")
            (req / out).write_text(f"# Generated by scripts/supply_chain.py windows-lock (Windows, Python "
                                   f"{sys.version_info[0]}.{sys.version_info[1]}): install with\n"
                                   f"#   pip install --require-hashes --no-deps -r requirements/{out}\n" + body,
                                   encoding="utf-8")
            print(f"requirements/{out}: {len(PIN.findall(body))} packages")
    return 0


def image_lock_problems() -> list[str]:
    """Every image lock line is hashed, and every package both locks name has the same version."""
    locked = ROOT / "requirements" / "platform.lock"
    pins = {_canon(x.split("==")[0]): x.split("==")[1].strip() for x in locked.read_text(encoding="utf-8").splitlines()
            if "==" in x and not x.startswith("#")}
    out = []
    image: dict[str, str] = {}
    for name, command in [*((n, "image-lock") for n in IMAGE_LOCKS), *((n, "windows-lock") for n in WINDOWS_LOCKS)]:
        path = ROOT / "requirements" / name
        if not path.is_file():
            out.append(f"requirements/{name} is missing: run python scripts/supply_chain.py {command}")
            continue
        text = path.read_text(encoding="utf-8")
        for m in PIN.finditer(text):
            k, v = _canon(m.group(1)), m.group(2)
            if k in pins and pins[k] != v:
                out.append(f"{name}: {k} {v} but platform.lock has {pins[k]}")
            if command == "image-lock":
                image.setdefault(k, v)
            elif k in image and image[k] != v:      # a Windows host runs the container's versions
                out.append(f"{name}: {k} {v} but the image locks have {image[k]}")
        if "--hash=sha256:" not in text:
            out.append(f"{name}: no hashes")
    return out


def _canon(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _requirement(line: str) -> tuple[str, set[str]] | None:
    line = line.split("#", 1)[0].strip()
    if not line or line.startswith("-"):
        return None
    m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(\[([^\]]*)\])?", line)
    if not m:
        return None
    extras = {e.strip() for e in (m.group(3) or "").split(",") if e.strip()}
    return _canon(m.group(1)), extras


def direct_requirements(path: Path = REQUIREMENTS) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        r = _requirement(line)
        if r:
            out.setdefault(r[0], set()).update(r[1])
    return out


def _marker_ok(marker: str | None, extras: set[str]) -> bool:
    if not marker:
        return True
    try:
        from packaging.markers import Marker
    except ImportError:          # packaging ships with pip / setuptools; without it keep the dependency (safer)
        return True
    m = Marker(marker)
    return any(m.evaluate({"extra": e}) for e in (extras or {""}))


def closure(direct: dict[str, set[str]]) -> dict[str, md.Distribution]:
    """Every installed distribution reachable from the direct requirements (with their extras)."""
    seen: dict[str, md.Distribution] = {}
    todo = [(n, set(x)) for n, x in sorted(direct.items())]
    while todo:
        name, extras = todo.pop()
        try:
            dist = md.distribution(name)
        except md.PackageNotFoundError:
            continue                    # not needed on this platform (or not installed): reported by ``check``
        key = _canon(dist.metadata["Name"])
        first = key not in seen
        seen[key] = dist
        if not first and not extras:
            continue
        for req in dist.requires or []:
            spec, _, marker = req.partition(";")
            r = _requirement(spec)
            if r and _marker_ok(marker.strip() or None, extras) and (r[0] not in seen or r[1]):
                todo.append(r)
    return dict(sorted(seen.items()))


def _licence(dist: md.Distribution) -> str | None:
    meta = dist.metadata
    lic = meta.get("License-Expression") or meta.get("License")
    if lic and len(lic) < 80 and "\n" not in lic:
        return lic.strip()
    classifiers = [c.split("::")[-1].strip() for c in meta.get_all("Classifier") or [] if c.startswith("License ::")]
    return classifiers[0] if classifiers else None


def lock_text(dists: dict[str, md.Distribution]) -> str:
    lines = ["# Generated by scripts/supply_chain.py lock - exact versions of requirements/platform.txt and every",
             "# transitive dependency (container build constraints; audited by pip-audit). Do not edit by hand."]
    lines += [f"{d.metadata['Name']}=={d.version}" for d in dists.values()]
    return "\n".join(lines) + "\n"


def sbom(dists: dict[str, md.Distribution], direct: dict[str, set[str]]) -> dict:
    lock = lock_text(dists)
    components = []
    for key, d in dists.items():
        c = {"type": "library", "bom-ref": f"pkg:pypi/{key}@{d.version}", "name": d.metadata["Name"], "version": d.version,
             "purl": f"pkg:pypi/{key}@{d.version}", "scope": "required",
             "properties": [{"name": "soc:direct", "value": "true" if key in direct else "false"}]}
        lic = _licence(d)
        if lic:
            c["licenses"] = [{"license": {"name": lic}}]
        components.append(c)
    digest = hashlib.sha256(lock.encode()).hexdigest()
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
            "serialNumber": f"urn:uuid:{digest[:8]}-{digest[8:12]}-{digest[12:16]}-{digest[16:20]}-{digest[20:32]}",
            "metadata": {"component": {"type": "application", "name": "soc-platform", "version": "0.1.0",
                                       "bom-ref": "soc-platform"},
                         "properties": [{"name": "soc:lock-sha256", "value": digest},
                                        {"name": "soc:python", "value": ".".join(map(str, sys.version_info[:3]))}]},
            "components": components,
            "dependencies": [{"ref": "soc-platform", "dependsOn": [c["bom-ref"] for c in components
                                                                   if c["properties"][0]["value"] == "true"]}]}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("command", choices=["lock", "sbom", "check", "image-lock", "windows-lock"])
    ap.add_argument("--out")
    a = ap.parse_args(argv)
    if a.command == "image-lock":
        return image_lock()
    if a.command == "windows-lock":
        return windows_lock()
    direct = direct_requirements()
    dists = closure(direct)
    if a.command == "lock":
        out = Path(a.out or ROOT / "requirements" / "platform.lock")
        out.write_text(lock_text(dists), encoding="utf-8")
    elif a.command == "sbom":
        out = Path(a.out or ROOT / "sbom" / "platform.cdx.json")
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(sbom(dists, direct), indent=1) + "\n", encoding="utf-8")
    else:
        # every direct requirement is locked, and every installed package the lock names has the locked version;
        # packages that exist on one operating system only (colorama on Windows, uvloop on Linux) are not a mismatch
        locked = ROOT / "requirements" / "platform.lock"
        if not locked.is_file():
            print("requirements/platform.lock is missing: run python scripts/supply_chain.py lock")
            return 1
        pins = {_canon(x.split("==")[0]): x.split("==")[1] for x in locked.read_text(encoding="utf-8").splitlines()
                if "==" in x and not x.startswith("#")}
        unlocked = sorted(n for n in direct if n not in pins)
        drift = sorted(f"{k} {d.version} (locked {pins[k]})" for k, d in dists.items() if k in pins and pins[k] != d.version)
        if unlocked or drift:
            print(f"not locked: {unlocked}; version drift: {drift} - run python scripts/supply_chain.py lock")
            return 1
        image = image_lock_problems()
        if image:
            print("image / Windows locks: " + "; ".join(image[:10]))
            return 1
        print(f"ok: {len(direct)} direct, {len(pins)} locked; image and Windows locks hashed and in step")
        return 0
    print(f"{out}: {len(dists)} packages ({len(direct)} direct)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
