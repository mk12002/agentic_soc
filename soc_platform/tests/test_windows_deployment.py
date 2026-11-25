"""The Windows host deployment (deploy/windows): the scripts parse and run on Windows PowerShell 5.1, the settings
template names only real settings and holds no secret, the launcher loads settings without printing them, runs the
configuration check, restarts a process that exits and stops on request, the installer refuses an unsupported Python,
folder permissions give the service account only its right, the locks are hashed and match the container's versions,
and the IIS front end passes requests to the platform's port with the platform's body limit.

The full install (packages from the hash-pinned lock, schema, a running server) is opt-in: SOC_WINDOWS_INSTALL_TEST=1
(CI's Windows job and the test round run it; it downloads every package)."""

from __future__ import annotations

import importlib.util
import os
import re
import secrets
import shutil
import subprocess
import sys
import time
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
WIN = ROOT / "deploy" / "windows"
POWERSHELL = shutil.which("powershell.exe") if sys.platform == "win32" else None
windows_only = pytest.mark.skipif(POWERSHELL is None, reason="Windows PowerShell is needed")


def _ps(command: str, timeout: int = 120, env: dict | None = None) -> subprocess.CompletedProcess:
    return subprocess.run([POWERSHELL, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", command],
                          capture_output=True, text=True, timeout=timeout, env=env, check=False)


def _script(name: str, *args: str, timeout: int = 120) -> subprocess.CompletedProcess:
    return subprocess.run([POWERSHELL, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File",
                           str(WIN / name), *args], capture_output=True, text=True, timeout=timeout, check=False)


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _settings_lines(path: Path) -> list[tuple[str, str]]:
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        t = line.strip()
        if t and not t.startswith("#") and "=" in t:
            k, v = t.split("=", 1)
            out.append((k.strip(), re.sub(r"\s+#.*$", "", v).strip()))
    return out


# --- static ---------------------------------------------------------------------------------------------------------

def test_the_settings_template_names_only_real_settings_and_holds_no_secret():
    from soc_platform import settings_check

    pairs = _settings_lines(WIN / "cyberdome.env.example")
    assert pairs
    unknown = [k for k, _ in pairs if k.startswith("SOC_") and not settings_check._known(k)]
    assert unknown == [], unknown
    for k, v in pairs:
        if re.search(r"(KEY|SECRET|_TOKEN|PASSWORD)$", k):
            assert v == "", f"{k} must not carry a value in the template (use {k}_FILE)"
    names = dict(pairs)
    # the template's database contract is the one setup_postgres.ps1 and install.ps1 fulfil
    assert names["SOC_SCHEMA_MANAGE"] == "0" and names["SOC_DB_RUNTIME_ROLE"]
    assert names["SOC_DATABASE_URL_FILE"].endswith(r"\secrets\database_url")


def test_the_launcher_sets_every_production_default_the_container_image_sets():
    docker = (ROOT / "deploy" / "Dockerfile").read_text(encoding="utf-8")
    env_block = docker[docker.index("ENV SOC_ENVIRONMENT"):docker.index("EXPOSE")]
    image_defaults = set(re.findall(r"\b([A-Z][A-Z0-9_]+)=", env_block))
    run = (WIN / "run.ps1").read_text(encoding="utf-8")
    launcher_defaults = set(re.findall(r'Set-DefaultSetting "([A-Z0-9_]+)"', run))
    missing = image_defaults - launcher_defaults
    assert missing == set(), f"run.ps1 does not set {sorted(missing)} like the image does"
    assert 'Set-DefaultSetting "SOC_HOST" "127.0.0.1"' in run   # only the proxy on the host reaches the platform


def test_the_windows_locks_are_hashed_and_run_the_containers_versions():
    sc = _load("supply_chain")
    assert sc.image_lock_problems() == []
    for name in sc.WINDOWS_LOCKS:
        text = (ROOT / "requirements" / name).read_text(encoding="utf-8")
        pins = sc.PIN.findall(text)
        assert pins and text.count("--hash=sha256:") >= len(pins)
        assert "--index-url" not in text and "extra-index-url" not in text   # the host's pip configuration decides
    engine = (ROOT / "requirements" / "windows-engine.lock").read_text(encoding="utf-8")
    # the attachment agent's YARA rules: a Windows host scores attachments like the container does
    assert re.search(r"^yara-python==", engine, re.MULTILINE)
    install = (WIN / "install.ps1").read_text(encoding="utf-8")
    assert '"--require-hashes", "--no-deps"' in install and "windows-engine.lock" in install


def test_the_iis_front_end_passes_everything_to_the_platform_with_its_body_limit():
    from soc_platform.api.app import MAX_BODY_BYTES

    root = ET.parse(WIN / "iis" / "web.config").getroot()
    action = root.find("./system.webServer/rewrite/rules/rule/action")
    assert action is not None and action.get("url") == "http://127.0.0.1:8080{UNENCODED_URL}"
    assert action.get("appendQueryString") == "false"               # UNENCODED_URL already carries the query
    limits = root.find("./system.webServer/security/requestFiltering/requestLimits")
    assert int(limits.get("maxAllowedContentLength")) >= MAX_BODY_BYTES
    template = dict(_settings_lines(WIN / "cyberdome.env.example"))
    assert "127.0.0.1/32" in template["SOC_TRUSTED_PROXIES"]       # the platform reads the client address ARR adds


def test_ci_tests_windows_and_python_313():
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "windows-latest" in ci and '"3.13"' in ci
    assert "SOC_WINDOWS_INSTALL_TEST" in ci                          # the real install runs on a Windows runner
    assert "supply_chain.py check" in ci


# --- Windows PowerShell -------------------------------------------------------------------------------------------

@windows_only
def test_every_script_parses_on_windows_powershell_and_is_plain_ascii():
    for f in sorted(WIN.glob("*.ps1")):
        raw = f.read_bytes()
        assert all(b < 128 for b in raw), f"{f.name}: Windows PowerShell 5.1 reads a file without BOM as ANSI"
        r = _ps("$t=$null;$e=$null;[void][System.Management.Automation.Language.Parser]::ParseFile("
                f"'{f}',[ref]$t,[ref]$e); $e.Count")
        assert r.returncode == 0 and r.stdout.strip() == "0", (f.name, r.stdout, r.stderr)


@windows_only
def test_the_settings_loader_follows_the_env_file_rules_and_prints_no_value(tmp_path):
    secret = "s3cr3t-" + secrets.token_hex(8)
    f = tmp_path / "x.env"
    f.write_text("# comment\n\nSOC_A=plain\nSOC_B = \"quoted value\"   # trailing note\nSOC_C=a=b=c\nSOC_D=\n"
                 f"SOC_SECRET_X={secret}\n", encoding="utf-8")
    r = _ps(f". '{WIN / 'common.ps1'}'; $n = Import-CyberDomeSettings -Path '{f}'; ($n -join ','); "
            "'A=' + $env:SOC_A; 'B=' + $env:SOC_B; 'C=' + $env:SOC_C; 'D=' + [string]($env:SOC_D -eq $null)")
    assert r.returncode == 0, r.stderr
    lines = r.stdout.splitlines()
    assert lines[0] == "SOC_A,SOC_B,SOC_C,SOC_SECRET_X"                # an empty value is "the default": not set
    assert lines[1:] == ["A=plain", "B=quoted value", "C=a=b=c", "D=True"]
    bad = tmp_path / "bad.env"
    bad.write_text(f"not a setting line {secret}\n", encoding="utf-8")
    r = _ps(f". '{WIN / 'common.ps1'}'; Import-CyberDomeSettings -Path '{bad}'")
    assert r.returncode != 0 and "line 1" in (r.stdout + r.stderr) and secret not in r.stdout + r.stderr


def _data_dir(tmp_path: Path, settings: str) -> Path:
    data = tmp_path / "data"
    (data / "config").mkdir(parents=True)
    (data / "config" / "cyberdome.env").write_text(settings, encoding="utf-8")
    for f in ("connectors.yaml", "suppliers.yaml"):               # as install.ps1 places them
        shutil.copy(ROOT / "config" / f, data / "config" / f)
    return data


@windows_only
def test_the_launcher_check_runs_the_configuration_check_with_the_settings_and_prints_no_value(tmp_path):
    secret = "dev-" + secrets.token_hex(24)
    data = _data_dir(tmp_path, f"SOC_ENVIRONMENT=dev\nSOC_AUTH_MODE=dev\nSOC_DEV_JWT_SECRET={secret}\n"
                               "SOC_ORG_DOMAINS=example.invalid\n"
                               # never the project folder: the check opens the database (it once created ./x.db there)
                               f"SOC_DATABASE_URL=sqlite:///{(tmp_path / 'check.db').as_posix()}\n")
    args = ("-Role", "api", "-InstallDir", str(tmp_path / "prog"), "-DataDir", str(data), "-Python", sys.executable,
            "-AppDir", str(ROOT), "-CheckOnly")
    ok = _script("run.ps1", *args)
    assert ok.returncode == 0, ok.stdout + ok.stderr
    assert secret not in ok.stdout + ok.stderr
    (data / "config" / "cyberdome.env").write_text(f"SOC_ENVIRONMENT=dev\nSOC_DEV_JWT_SECRET={secret}\n"
                                                   "SOC_API_WORKERS=many\n", encoding="utf-8")
    bad = _script("run.ps1", *args)
    assert bad.returncode == 1 and "SOC_API_WORKERS" in bad.stdout and secret not in bad.stdout + bad.stderr


@windows_only
def test_the_launcher_restarts_a_process_that_exits_and_gives_up_at_its_limit(tmp_path):
    data = _data_dir(tmp_path, "SOC_ENVIRONMENT=dev\n")
    code = 'import os, sys; print("argument with spaces", os.environ["SOC_HOST"]); sys.exit(3)'
    r = _script("run.ps1", "-Role", "api", "-InstallDir", str(tmp_path / "prog"), "-DataDir", str(data),
                "-Python", sys.executable, "-AppDir", str(ROOT), "-Code", code,
                "-MaxRestarts", "2", "-BackoffSeconds", "0", timeout=180)
    log = (data / "logs" / "api-supervisor.log").read_text(encoding="utf-8")
    assert r.returncode == 1, r.stdout + r.stderr
    assert log.count(" started") == 3 and "exit 3" in log and "restart limit 2 reached" in log
    outs = sorted((data / "logs").glob("api-2*.log"))
    outs = [p for p in outs if not p.name.endswith(".err.log")]
    assert outs and "argument with spaces 127.0.0.1" in outs[-1].read_text(encoding="utf-8")
    assert not (data / "run" / "api.pid").exists()


@windows_only
def test_a_stop_request_ends_the_process_tree_and_the_launcher_without_a_restart(tmp_path):
    data = _data_dir(tmp_path, "SOC_ENVIRONMENT=dev\n")
    code = ("import subprocess, sys, time; subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(120)']); "
            "time.sleep(120)")
    launcher = subprocess.Popen([POWERSHELL, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File",
                                 str(WIN / "run.ps1"), "-Role", "api", "-InstallDir", str(tmp_path / "prog"),
                                 "-DataDir", str(data), "-Python", sys.executable, "-AppDir", str(ROOT),
                                 "-Code", code, "-BackoffSeconds", "0"],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        pid_file = data / "run" / "api.pid"
        deadline = time.monotonic() + 60
        while not pid_file.exists() and time.monotonic() < deadline:
            time.sleep(0.2)
        pid = int(pid_file.read_text().strip())
        (data / "run" / "api.stop").write_text("")
        subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"], capture_output=True, check=False)
        assert launcher.wait(timeout=60) == 0
        log = (data / "logs" / "api-supervisor.log").read_text(encoding="utf-8")
        assert "after a stop request" in log and log.count(" started") == 1
        alive = subprocess.run(["tasklist", "/FI", f"PID eq {pid}"], capture_output=True, text=True,
                               check=False).stdout
        assert str(pid) not in alive
    finally:
        if launcher.poll() is None:
            subprocess.run(["taskkill", "/PID", str(launcher.pid), "/T", "/F"], capture_output=True, check=False)


@windows_only
@pytest.mark.parametrize(("version", "message"), [("3.10.11 64", "not supported"), ("3.14.0 64", "not supported"),
                                                  ("3.13.17 32", "64-bit")])
def test_the_installer_refuses_an_unsupported_python(tmp_path, version, message):
    fake = tmp_path / "python.cmd"
    fake.write_text(f"@echo {version}\n", encoding="ascii")
    r = _script("install.ps1", "-Python", str(fake), "-InstallDir", str(tmp_path / "prog"), "-DataDir",
                str(tmp_path / "data"), "-NoTasks", "-ServiceAccount", os.environ.get("USERNAME", "Users"),
                "-AdminPrincipal", os.environ.get("USERNAME", "Users"))
    assert r.returncode != 0 and message in r.stdout + r.stderr, r.stdout + r.stderr
    assert not (tmp_path / "prog").exists()                         # refused before anything was written


@windows_only
def test_folder_permissions_give_the_service_account_only_its_right(tmp_path):
    target = tmp_path / "secrets"
    me = _ps("[Security.Principal.WindowsIdentity]::GetCurrent().User.Value").stdout.strip()
    r = _ps(f". '{WIN / 'common.ps1'}'; Set-FolderAccess -Path '{target}' -AdminSid '{me}' -ServiceSid 'S-1-5-19' "
            "-Right R; (Get-Acl -LiteralPath '" + str(target) + "').Access | ForEach-Object { '{0}|{1}|{2}' -f "
            "$_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value, $_.FileSystemRights, "
            "$_.IsInherited }")
    assert r.returncode == 0, r.stderr
    rows = {line.split("|")[0]: line.split("|")[1:] for line in r.stdout.splitlines() if "|" in line}
    assert set(rows) == {me, "S-1-5-18", "S-1-5-19"}                 # nobody else: inheritance removed
    assert rows[me][0] == "FullControl" and rows["S-1-5-18"][0] == "FullControl"
    assert "Write" not in rows["S-1-5-19"][0] and "Read" in rows["S-1-5-19"][0]
    assert all(v[1] == "False" for v in rows.values())
    (target / "file.txt").write_text("x", encoding="utf-8")         # the installing administrator still writes
    # an administrator who is also named as the service account keeps full control (a grant once replaced it, and the
    # installer could not create its own sub-folders)
    same = tmp_path / "same"
    r = _ps(f". '{WIN / 'common.ps1'}'; Set-FolderAccess -Path '{same}' -AdminSid '{me}' -ServiceSid '{me}' -Right RX")
    assert r.returncode == 0, r.stderr
    (same / "child").mkdir()


@windows_only
def test_starting_a_server_returns_when_the_starter_exits_not_when_the_server_does(tmp_path):
    """`pg_ctl restart | Out-Null` waited for ever (setup_postgres.ps1 without a service name): the server it starts
    inherits the pipe. Invoke-Starter waits for the starter alone and still reports its failure."""
    starter = tmp_path / "starter.py"
    starter.write_text("import subprocess, sys\n"
                       "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(90)'])\n"
                       "print('started')\nsys.exit(int(sys.argv[1]))\n", encoding="utf-8")
    t0 = time.monotonic()
    ok = _ps(f". '{WIN / 'common.ps1'}'; Invoke-Starter '{sys.executable}' @('{starter}', '0'); 'returned'", timeout=60)
    assert ok.returncode == 0 and "returned" in ok.stdout and time.monotonic() - t0 < 45, ok.stderr
    bad = _ps(f". '{WIN / 'common.ps1'}'; Invoke-Starter '{sys.executable}' @('{starter}', '3')", timeout=60)
    assert bad.returncode != 0 and "exit 3" in bad.stdout + bad.stderr


def _acl(path: Path) -> dict[str, str]:
    r = _ps("(Get-Acl -LiteralPath '" + str(path) + "').Access | ForEach-Object { '{0}|{1}' -f "
            "$_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value, $_.FileSystemRights }")
    return {line.split("|")[0]: line.split("|")[1] for line in r.stdout.splitlines() if "|" in line}


# --- the real install (opt-in: downloads every package) ------------------------------------------------------------

@windows_only
@pytest.mark.skipif(os.environ.get("SOC_WINDOWS_INSTALL_TEST") != "1", reason="set SOC_WINDOWS_INSTALL_TEST=1")
def test_the_installer_builds_a_working_host_from_the_hashed_lock(tmp_path):
    me = os.environ.get("USERNAME") or "Users"
    prog, data = tmp_path / "prog", tmp_path / "data"
    r = _script("install.ps1", "-Python", sys.executable, "-InstallDir", str(prog), "-DataDir", str(data), "-NoTasks",
                "-AdminPrincipal", me, timeout=1800)   # service account: LOCAL SERVICE
    assert r.returncode == 0, r.stdout[-3000:] + r.stderr[-3000:]
    py = prog / "venv" / "Scripts" / "python.exe"
    assert (data / "secrets" / "data_key").stat().st_size == 44     # a Fernet key, never printed
    key_text = (data / "secrets" / "data_key").read_text(encoding="ascii")
    assert key_text not in r.stdout + r.stderr
    # permissions as documented (CLIENT_DEPLOYMENT_GUIDE.md 1A.3): LOCAL SERVICE reads secrets, writes only data/logs/run,
    # never sees the owner connection; nobody else is listed
    secrets_acl, admin_acl, logs_acl = _acl(data / "secrets"), _acl(data / "admin"), _acl(data / "logs")
    assert "S-1-5-19" in secrets_acl and "Write" not in secrets_acl["S-1-5-19"]
    assert "S-1-5-19" not in admin_acl
    assert "Modify" in logs_acl["S-1-5-19"]
    assert not {"S-1-5-32-545", "S-1-5-11", "S-1-1-0"} & set(secrets_acl)   # Users, Authenticated Users, Everyone
    assert (data / "config" / "cyberdome.env").read_text(encoding="utf-8") == \
        (WIN / "cyberdome.env.example").read_text(encoding="utf-8")
    code = "import soc_platform, yara, sklearn, sys; print(soc_platform.__file__); print(sys.version_info[:2])"
    probe = subprocess.run([str(py), "-c", code], capture_output=True, text=True, check=True,
                           cwd=tmp_path).stdout   # not the repository: Python puts the working folder first on its path
    assert str(prog / "app") in probe and f"{sys.version_info[:2]}" in probe
    # a re-run is an upgrade: settings and the key are kept
    key = (data / "secrets" / "data_key").read_bytes()
    (data / "config" / "cyberdome.env").write_text("SOC_ENVIRONMENT=dev\nSOC_AUTH_MODE=dev\nSOC_DEV_JWT_SECRET="
                                                   + secrets.token_hex(24) + "\nSOC_ORG_DOMAINS=example.invalid\n"
                                                   "SOC_DATABASE_URL=sqlite:///" + str(data / "data" / "soc.db").replace("\\", "/")
                                                   + "\nSOC_PORT=18631\nSOC_API_WORKERS=2\nSOC_SCHEDULER_START_DELAY=86400\n",
                                                   encoding="utf-8")
    r2 = _script("install.ps1", "-Python", sys.executable, "-InstallDir", str(prog), "-DataDir", str(data), "-NoTasks",
                 "-AdminPrincipal", me, timeout=1800)   # service account: LOCAL SERVICE
    assert r2.returncode == 0 and (data / "secrets" / "data_key").read_bytes() == key
    assert "SOC_PORT=18631" in (data / "config" / "cyberdome.env").read_text(encoding="utf-8")
    launcher = subprocess.Popen([POWERSHELL, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File",
                                 str(prog / "app" / "deploy" / "windows" / "run.ps1"), "-InstallDir", str(prog),
                                 "-DataDir", str(data)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        status, deadline = None, time.monotonic() + 180
        while time.monotonic() < deadline:
            try:
                with urllib.request.urlopen("http://127.0.0.1:18631/health/ready", timeout=5) as resp:
                    status = resp.status
                    break
            except OSError:
                time.sleep(1)
        assert status == 200, (data / "logs").glob("*.log") and "".join(
            p.read_text(encoding="utf-8", errors="replace")[-2000:] for p in (data / "logs").glob("*.log"))
    finally:
        pid_file = data / "run" / "api.pid"
        (data / "run" / "api.stop").write_text("")
        if pid_file.exists():
            subprocess.run(["taskkill", "/PID", pid_file.read_text().strip(), "/T", "/F"], capture_output=True, check=False)
        try:
            assert launcher.wait(timeout=60) == 0
        finally:
            if launcher.poll() is None:
                subprocess.run(["taskkill", "/PID", str(launcher.pid), "/T", "/F"], capture_output=True, check=False)
