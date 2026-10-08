"""Strict checking of connector configuration - the file, console changes and imports alike.

A typo in ``config/connectors.yaml`` used to be silent: a misspelled connector name was ignored, ``enabeld: false`` left
the tool enabled (enabled is the default) and a mistyped setting was simply never read. Every configuration now passes
through ``check_document`` before it is used, and each problem names the place, says what is wrong and how to fix it
("did you mean ...?"). Errors stop a start-up or a change; warnings are shown and allowed.

Stages (the rollout of one tool, in order):

* ``fake``      - vendor-shaped fixtures, no credentials (demo, development)
* ``record``    - live reads; responses are also saved, sanitised, as test fixtures; no actions
* ``read``      - live reads only; no actions (recommendations appear as manual steps)
* ``recommend`` - actions offered, never above L2 (a person approves every one)
* ``automate``  - actions follow the approved autonomy policy

``mode: fake | live`` (the older form) still works: fake means stage ``fake``, live means stage ``automate``.
"""

from __future__ import annotations

import difflib
import json
import os
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

STAGES = ("fake", "record", "read", "recommend", "automate")
LIVE_STAGES = STAGES[1:]
ACTION_STAGES = ("recommend", "automate")            # stages whose connector's actions are offered at all
STAGE_LABELS = {"fake": "Fixtures", "record": "Recording", "read": "Read-only", "recommend": "Recommend",
                "automate": "Automate"}
ENTRY_KEYS = ("enabled", "mode", "stage", "settings")
TRUE = {"1", "true", "yes", "on"}
FALSE = {"0", "false", "no", "off", ""}
_VAR = re.compile(r"\$\{([A-Z0-9_]+)(?::-([^}]*))?\}")
_URL = re.compile(r"^https?://[^\s/:?#]+(:\d{1,5})?(/[^\s]*)?$", re.IGNORECASE)


@dataclass(frozen=True)
class Problem:
    level: str                  # error | warning
    where: str                  # "crowdstrike.settings.base_url", "file", ...
    message: str
    fix: str = ""

    def as_dict(self) -> dict[str, str]:
        return asdict(self)

    def __str__(self) -> str:
        return f"{self.level.upper()} {self.where}: {self.message}" + (f" - {self.fix}" if self.fix else "")


def env_var_for(connector: str, field: str) -> str:
    """The environment variable (or ``<NAME>_FILE`` vault mount) a setting is read from by convention."""
    return re.sub(r"[^A-Z0-9]", "_", f"{connector}_{field}".upper())


def stage_of(entry: dict[str, Any] | None, default_mode: str = "fake") -> str:
    entry = entry or {}
    st = entry.get("stage")
    if st in STAGES:
        return st
    mode = entry.get("mode", default_mode)
    return "fake" if mode == "fake" else "automate"


def mode_for(stage: str) -> str:
    return "fake" if stage == "fake" else "live"


def suggest(word: str, options: list[str] | tuple[str, ...]) -> str:
    near = difflib.get_close_matches(str(word), list(options), n=1, cutoff=0.6)
    return f"did you mean '{near[0]}'?" if near else ""


def as_bool(v: Any) -> bool | None:
    """A boolean from YAML or an environment string; None when it is neither (so a typo is an error, not 'true')."""
    if isinstance(v, bool):
        return v
    s = str(v).strip().lower()
    return True if s in TRUE else False if s in FALSE else None


def unresolved_vars(value: Any) -> list[str]:
    """Environment variables a value refers to that are not set (neither NAME nor a readable NAME_FILE)."""
    from soc_platform.config import secret

    if not isinstance(value, str):
        return []
    return [m.group(1) for m in _VAR.finditer(value) if secret(m.group(1)) is None and m.group(2) is None]


def _check_value(kind: str, choices: tuple[str, ...], v: Any, where: str, live: bool) -> list[Problem]:
    if v in (None, ""):
        return []
    s = str(v).strip()
    if kind == "url":
        if not _URL.match(s):
            return [Problem("error", where, f"'{s[:80]}' is not a URL", "use the full address, e.g. https://api.vendor.com")]
        host = re.sub(r"^https?://", "", s, flags=re.IGNORECASE).split("/")[0].split(":")[0].lower()
        if live and s.lower().startswith("http://") and host not in ("localhost", "127.0.0.1"):
            return [Problem("warning", where, "plain http: credentials and data would cross the network unencrypted",
                            "use https://")]
    elif kind == "bool":
        if as_bool(v) is None:
            return [Problem("error", where, f"'{s[:40]}' is not true or false", "use true or false")]
    elif kind == "int":
        try:
            if float(s) < 0:
                raise ValueError
        except ValueError:
            return [Problem("error", where, f"'{s[:40]}' is not a non-negative number", "use a number such as 30")]
    elif kind == "choice":
        if s not in choices:
            hint = suggest(s, choices)
            return [Problem("error", where, f"'{s[:40]}' is not one of {', '.join(choices)}", hint)]
    elif kind == "map":
        if not isinstance(v, dict):
            try:
                ok = isinstance(json.loads(s), dict)
            except ValueError:
                ok = False
            if not ok:
                return [Problem("error", where, "expected a mapping (YAML mapping or a JSON object)",
                                'e.g. {"title": "rule_name", "host": "dest.hostname"}')]
    elif kind == "email":
        if "@" not in s:
            return [Problem("error", where, f"'{s[:60]}' is not an e-mail address", "")]
    elif kind == "path" and live and not Path(s).is_file():
        return [Problem("warning", where, f"file '{s[:120]}' does not exist on this machine",
                        "mount the file into the container or correct the path")]
    return []


def check_entry(name: str, entry: Any, manifests: dict[str, Any], *, default_mode: str = "fake",
                check_env: bool = True) -> list[Problem]:
    """Problems with one connector's entry. ``check_env`` also requires the secrets and settings of a live tool to be
    present (off when checking a file on a build machine that has no secrets)."""
    from soc_platform.connectors.registry import COMMON_FIELDS

    out: list[Problem] = []
    if name not in manifests:
        hint = suggest(name, sorted(manifests))
        return [Problem("error", name, "no connector of this name is installed",
                        hint or f"installed connectors: {', '.join(sorted(manifests))}")]
    if entry is None:
        entry = {}
    if not isinstance(entry, dict):
        return [Problem("error", name, "expected a mapping with enabled / stage / settings", "")]
    for k in entry:
        if k not in ENTRY_KEYS:
            out.append(Problem("error", f"{name}.{k}", "unknown key", suggest(k, ENTRY_KEYS) or f"allowed: {', '.join(ENTRY_KEYS)}"))
    if "enabled" in entry and as_bool(entry["enabled"]) is None:
        out.append(Problem("error", f"{name}.enabled", f"'{entry['enabled']}' is not true or false", "use true or false"))
    mode, stage = entry.get("mode"), entry.get("stage")
    if mode is not None and mode not in ("fake", "live"):
        out.append(Problem("error", f"{name}.mode", f"'{mode}' is not fake or live", suggest(mode, ("fake", "live"))))
    if stage is not None and stage not in STAGES:
        out.append(Problem("error", f"{name}.stage", f"'{stage}' is not a stage",
                           suggest(stage, STAGES) or f"stages: {', '.join(STAGES)}"))
    if mode in ("fake", "live") and stage in STAGES and mode_for(stage) != mode:
        out.append(Problem("error", f"{name}", f"mode '{mode}' contradicts stage '{stage}'",
                           "remove mode: the stage decides it"))
    settings = entry.get("settings") or {}
    if not isinstance(settings, dict):
        return out + [Problem("error", f"{name}.settings", "expected a mapping of setting: value", "")]
    m = manifests[name]
    fields = {f.name: f for f in [*m.config, *COMMON_FIELDS]}
    for k in settings:
        if k not in fields:
            hint = suggest(k, sorted(fields))
            out.append(Problem("error" if hint else "warning", f"{name}.settings.{k}",
                               "not a setting of this connector" + ("" if hint else "; it is passed on but nothing "
                                                                    "documented reads it"), hint))
    live = stage_of(entry, default_mode) != "fake"
    if check_env and stage_of(entry, default_mode) == "record":
        from soc_platform.connectors.recording import recording_salt

        if len(recording_salt()) < 16:
            out.append(Problem("error", f"{name}.stage", "the Recording stage needs a key for its pseudonyms",
                               "set SOC_DATA_KEY (the platform's encryption key) or SOC_RECORD_SALT (16+ characters)"))
    from soc_platform.connectors.registry import interpolate

    for fname, f in fields.items():
        raw = settings.get(fname)
        where = f"{name}.settings.{fname}"
        if f.secret and raw not in (None, "") and not (isinstance(raw, str) and _VAR.fullmatch(raw.strip())):
            out.append(Problem("error" if live else "warning", where, "a secret is written into the configuration",
                               f"reference it instead: \"${{{env_var_for(name, fname)}}}\" and store the value in the "
                               "vault (or the environment)"))
            continue
        value = interpolate(raw) if raw is not None else None
        if live and check_env and f.required and value in (None, ""):
            var = (unresolved_vars(raw) or [env_var_for(name, fname)])[0]
            out.append(Problem("error", where, f"required{' secret' if f.secret else ''} '{fname}' has no value",
                               f"set {var} (or mount {var}_FILE)" if raw not in (None, "") or f.secret else
                               f"set it here or in {var}"))
            continue
        if not f.secret:
            out += _check_value(f.kind, tuple(f.choices), value, where, live)
    return out


LIST_KEYS = ("suppliers", "sanctioned")
SUPPLIER_KEYS = ("name", "domains", "criticality")
_DOMAIN = re.compile(r"^(?=.{1,253}$)([a-z0-9_-]{1,63}\.)+[a-z][a-z0-9-]{1,62}$")


def check_lists(lists: Any, where: str = "lists") -> list[Problem]:
    """The organisation's lists edited in the console: key suppliers (vendor e-mail compromise) and sanctioned
    services (shadow IT). A domain must look like one; a supplier needs a name and at least one domain."""
    if lists is None:
        return []
    if not isinstance(lists, dict):
        return [Problem("error", where, "expected suppliers / sanctioned", "")]
    out = [Problem("error", f"{where}.{k}", "unknown list", suggest(k, LIST_KEYS) or f"lists: {', '.join(LIST_KEYS)}")
           for k in lists if k not in LIST_KEYS]
    sup = lists.get("suppliers")
    if sup is not None:
        if not isinstance(sup, list):
            out.append(Problem("error", f"{where}.suppliers", "expected a list of suppliers", ""))
        else:
            for i, s in enumerate(sup):
                w = f"{where}.suppliers[{i + 1}]"
                if not isinstance(s, dict):
                    out.append(Problem("error", w, "expected name / domains / criticality", ""))
                    continue
                out += [Problem("error", f"{w}.{k}", "unknown key", suggest(k, SUPPLIER_KEYS)) for k in s
                        if k not in SUPPLIER_KEYS]
                if not str(s.get("name") or "").strip():
                    out.append(Problem("error", w, "a supplier needs a name", ""))
                doms = s.get("domains")
                if not isinstance(doms, list) or not doms:
                    out.append(Problem("error", w, "a supplier needs at least one domain", "e.g. [supplier.com]"))
                else:
                    out += [Problem("error", f"{w}.domains", f"'{str(d)[:80]}' is not a domain", "e.g. supplier.com")
                            for d in doms if not _DOMAIN.match(str(d).strip().lower())]
                if s.get("criticality") not in (None, "low", "medium", "high"):
                    out.append(Problem("error", f"{w}.criticality", f"'{s['criticality']}' is not low, medium or high",
                                       suggest(str(s["criticality"]), ("low", "medium", "high"))))
    san = lists.get("sanctioned")
    if san is not None:
        if not isinstance(san, list):
            out.append(Problem("error", f"{where}.sanctioned", "expected a list of domains", ""))
        else:
            out += [Problem("error", f"{where}.sanctioned", f"'{str(d)[:80]}' is not a domain", "e.g. sharepoint.com")
                    for d in san if not _DOMAIN.match(str(d).strip().lower())]
    return out


def check_document(doc: Any, manifests: dict[str, Any], *, default_mode: str = "fake",
                   check_env: bool = True) -> list[Problem]:
    if doc in (None, {}):
        return []
    if not isinstance(doc, dict):
        return [Problem("error", "file", "expected a mapping with a top-level 'connectors:' key", "")]
    out = [Problem("error", k, "unknown top-level key", suggest(k, ("connectors", "lists")) or
                   "only 'connectors' and 'lists' are allowed")
           for k in doc if k not in ("connectors", "lists")]
    out += check_lists(doc.get("lists"))
    conns = doc.get("connectors") or {}
    if not isinstance(conns, dict):
        return out + [Problem("error", "connectors", "expected a mapping of connector name: settings", "")]
    for name, entry in conns.items():
        out += check_entry(str(name), entry, manifests, default_mode=default_mode, check_env=check_env)
    return out


def load_yaml(text: str) -> tuple[Any, list[Problem]]:
    """Parse YAML; a syntax error becomes one Problem naming the line and column."""
    import yaml

    try:
        return yaml.safe_load(text) or {}, []
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        where = f"line {mark.line + 1}, column {mark.column + 1}" if mark else "file"
        what = getattr(exc, "problem", None) or str(exc).splitlines()[0]
        return {}, [Problem("error", where, f"YAML syntax: {what}", "check indentation (spaces, not tabs) and quotes")]


def config_path() -> Path:
    return Path(os.environ.get("SOC_CONNECTORS_CONFIG", "config/connectors.yaml"))


def load_file(path: str | Path | None = None) -> tuple[dict[str, Any], list[Problem]]:
    p = Path(path) if path else config_path()
    if not p.exists():
        return {}, []
    try:
        text = p.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        return {}, [Problem("error", str(p), f"cannot read the file: {exc}", "")]
    return load_yaml(text)


def errors(problems: list[Problem]) -> list[Problem]:
    return [p for p in problems if p.level == "error"]
