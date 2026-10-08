"""Plug-and-play connector registry (NFR-14, R15).

Discovery
  * every module in ``soc_platform.connectors.tools`` exporting ``MANIFEST`` (or ``MANIFESTS``)
  * any installed distribution exposing the entry-point group ``soc_platform.connectors``
    (``my_pkg.my_module:MANIFEST``) - third-party connectors need no platform change.

Configuration (``config/connectors.yaml``, plus approved console changes on top - ``core/connector_config.py``)::

    connectors:
      crowdstrike:
        enabled: true
        stage: read           # fake | record | read | recommend | automate  (or the older mode: fake | live)
        settings:
          base_url: https://api.crowdstrike.com
          client_id: ${CROWDSTRIKE_CLIENT_ID}          # env var, or <NAME>_FILE for vault-mounted secrets
          client_secret: ${CROWDSTRIKE_CLIENT_SECRET}

One broken tool never stops the others: a connector whose configuration is incomplete or whose construction fails is
left out of every workflow (with the reason on the Integrations screen), and everything else keeps working.

Swapping a tool (e.g. Avanan -> another gateway) is a config change plus one module.
"""

from __future__ import annotations

import importlib
import logging
import os
import pkgutil
import re
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from importlib.metadata import entry_points
from pathlib import Path
from typing import Any

from soc_platform.config import secret
from soc_platform.connectors.base import BaseConnector
from soc_platform.connectors.http import FixtureTransport, Transport
from soc_platform.core.actions import ActionRegistry, ActionSpec

log = logging.getLogger(__name__)
FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures"


@dataclass
class ConfigField:
    name: str
    description: str = ""
    secret: bool = False
    required: bool = True
    default: Any = None
    kind: str = "text"             # text | url | bool | int | choice | map | list | email | path (checked and rendered)
    choices: tuple[str, ...] = ()


# Settings every connector accepts (read by the shared connector code, not by one tool).
COMMON_FIELDS = [
    ConfigField("watermark_overlap_minutes", "Re-read window for late-arriving logs (default 30, SOC_WATERMARK_OVERLAP_MINUTES)",
                required=False, kind="int"),
]


@dataclass
class ConnectorManifest:
    name: str                      # unique connector id, e.g. "crowdstrike"
    tool: str                      # product name
    vendor: str
    category: str                  # edr | email | identity | dns | deception | pam | vuln | cloud | intel | itsm | cmdb | siem
    dimension: str                 # context dimension (section 7.2)
    description: str
    factory: Callable[[dict[str, Any], Transport], BaseConnector]
    live_transport: Callable[[dict[str, Any]], Transport]
    config: list[ConfigField] = field(default_factory=list)
    actions: Callable[[BaseConnector], list[ActionSpec]] = lambda _c: []
    confidence: str = ""           # integration confidence (section 10)
    to_confirm: str = ""           # what must be confirmed with the client
    focus_areas: tuple[str, ...] = ()  # phishing | incident | vulnerability
    fake_settings: dict[str, Any] = field(default_factory=dict)  # demo defaults applied in fake mode only

    def fixture_transport(self) -> FixtureTransport:
        base = Path(os.environ.get("SOC_FIXTURES_DIR") or FIXTURES_DIR)   # a different sample estate can be loaded
        return FixtureTransport.from_file(base / f"{self.name}.json", tool=self.name)

    def describe(self) -> dict[str, Any]:
        return {"name": self.name, "tool": self.tool, "vendor": self.vendor, "category": self.category,
                "dimension": self.dimension, "description": self.description, "confidence": self.confidence,
                "to_confirm": self.to_confirm, "focus_areas": list(self.focus_areas),
                "config": [{"name": f.name, "secret": f.secret, "required": f.required, "kind": f.kind,
                            "choices": list(f.choices), "description": f.description} for f in self.config]}


class ConfigError(Exception):
    pass


_VAR = re.compile(r"\$\{([A-Z0-9_]+)(?::-([^}]*))?\}")


def interpolate(value: Any) -> Any:
    if isinstance(value, str):
        def repl(m: re.Match) -> str:
            v = secret(m.group(1))
            return v if v is not None else (m.group(2) or "")
        return _VAR.sub(repl, value)
    if isinstance(value, dict):
        return {k: interpolate(v) for k, v in value.items()}
    if isinstance(value, list):
        return [interpolate(v) for v in value]
    return value


def discover() -> dict[str, ConnectorManifest]:
    found: dict[str, ConnectorManifest] = {}
    from soc_platform.connectors import tools as tools_pkg

    for mod in pkgutil.iter_modules(tools_pkg.__path__):
        if mod.name.startswith("_"):
            continue
        try:
            module = importlib.import_module(f"{tools_pkg.__name__}.{mod.name}")
        except Exception:  # one broken connector module must not stop every other tool loading
            log.exception("connector module %s could not be loaded; it is left out", mod.name)
            continue
        for m in _manifests_of(module):
            found[m.name] = m
    try:
        eps = entry_points(group="soc_platform.connectors")
    except TypeError:  # pragma: no cover - old importlib.metadata API
        eps = entry_points().get("soc_platform.connectors", [])
    for ep in eps:
        try:
            obj = ep.load()
        except Exception:  # a broken third-party package must not stop the platform
            log.exception("connector package %s could not be loaded; it is left out", ep.name)
            continue
        for m in (obj if isinstance(obj, (list, tuple)) else [obj]):
            found[m.name] = m
    return found


def _manifests_of(module: Any) -> list[ConnectorManifest]:
    if hasattr(module, "MANIFESTS"):
        return list(module.MANIFESTS)
    if hasattr(module, "MANIFEST"):
        return [module.MANIFEST]
    return []


@dataclass
class ConnectorInstance:
    manifest: ConnectorManifest
    connector: BaseConnector
    mode: str
    transport: Transport
    stage: str = "fake"


class StagedAction(ActionSpec):
    """An action of a connector in the ``recommend`` stage: offered, but never above L2 whatever the policy says."""

    def __init__(self, spec: ActionSpec, max_level: int, reason: str) -> None:
        self.spec = spec
        self.action_type, self.tool, self.description = spec.action_type, spec.tool, spec.description
        self.destructive, self.reverse_type = spec.destructive, spec.reverse_type
        self.max_level, self.max_level_reason = max_level, reason

    def preconditions(self, params, targets):
        return self.spec.preconditions(params, targets)

    def execute(self, params, targets):
        return self.spec.execute(params, targets)

    def reverse(self, params, targets, result):
        return self.spec.reverse(params, targets, result)


class RoutedAction(ActionSpec):
    """Dispatch one action type to the first provider whose pre-conditions accept the targets."""

    def __init__(self, action_type: str, providers: list[ActionSpec]) -> None:
        self.action_type = action_type
        self.providers = providers
        self.tool = "+".join(p.tool for p in providers)
        self.description = " | ".join(p.description for p in providers)
        self.destructive = any(p.destructive for p in providers)
        self.reverse_type = providers[0].reverse_type if all(p.reverse_type for p in providers) else None
        caps = [p for p in providers if getattr(p, "max_level", None) is not None]
        if caps:                                         # the most careful provider's stage sets the ceiling
            low = min(caps, key=lambda p: p.max_level)
            self.max_level, self.max_level_reason = low.max_level, low.max_level_reason

    def _pick(self, params: dict[str, Any], targets: list[dict[str, Any]]) -> ActionSpec | None:
        for p in self.providers:
            if not p.preconditions(params, targets):
                return p
        return None

    def preconditions(self, params, targets):
        if self._pick(params, targets):
            return []
        return ["no provider can act on these targets: " + "; ".join(
            f"{p.tool}: {', '.join(p.preconditions(params, targets))}" for p in self.providers)]

    def execute(self, params, targets):
        p = self._pick(params, targets)
        if p is None:
            raise ValueError("no provider accepts the targets")
        return {"provider": p.tool, **(p.execute(params, targets) or {})}

    def reverse(self, params, targets, result):
        for p in self.providers:
            if p.tool == result.get("provider"):
                return p.reverse(params, targets, result)
        return None


def _estate_settings() -> dict[str, dict[str, Any]]:
    """A sample estate can ship its own tenant settings (reporting mailbox, user domain...) next to its fixtures."""
    f = Path(os.environ.get("SOC_FIXTURES_DIR") or FIXTURES_DIR) / "settings.json"
    if not f.is_file():
        return {}
    import json

    return json.loads(f.read_text(encoding="utf-8"))


def recordings_dir() -> str:
    """Where the ``record`` stage writes sanitised responses (SOC_RECORD_FIXTURES_DIR, else next to the raw store)."""
    from soc_platform.config import get_settings

    return os.environ.get("SOC_RECORD_FIXTURES_DIR") or str(Path(get_settings().raw_payload_dir).parent / "recordings")


class ConnectorRegistry:
    def __init__(self, config: dict[str, Any] | None = None, *, default_mode: str = "fake",
                 manifests: dict[str, ConnectorManifest] | None = None, version: int | None = None) -> None:
        self.manifests = manifests if manifests is not None else discover()
        raw = (config or {}).get("connectors", {}) if isinstance(config, dict) else {}
        self.config: dict[str, Any] = raw if isinstance(raw, dict) else {}
        self.default_mode = default_mode
        self.version = version                     # the approved console configuration this was built from
        self.file_problems: list[Any] = []         # problems found in the configuration document (config_schema)
        self.lists: dict[str, Any] = {}            # organisation lists set in the console (suppliers, sanctioned)
        self._instances: dict[str, ConnectorInstance] = {}
        self._problems: dict[str, list[str]] = {}  # why a configured connector is unusable (checked once)
        self._instance_lock = threading.RLock()

    @classmethod
    def from_file(cls, path: str | Path | None = None, *, default_mode: str | None = None) -> ConnectorRegistry:
        from soc_platform.connectors.config_schema import load_file

        cfg, problems = load_file(path)
        reg = cls(cfg or {}, default_mode=default_mode or os.environ.get("SOC_CONNECTOR_MODE", "fake"))
        reg.file_problems = problems
        for p in problems:
            log.error("connector configuration: %s", p)
        return reg

    @classmethod
    def all_fake(cls) -> ConnectorRegistry:
        """Every discovered connector enabled in fixture mode (demos, tests, local dev)."""
        manifests = discover()
        return cls({"connectors": {n: {"enabled": True, "mode": "fake"} for n in manifests}},
                   manifests=manifests)

    # ------------------------------------------------------------------ configuration

    def _entry(self, name: str) -> dict[str, Any]:
        e = self.config.get(name)
        return e if isinstance(e, dict) else {}

    def configured_names(self) -> list[str]:
        """Connectors switched on in the configuration (usable or not)."""
        from soc_platform.connectors.config_schema import as_bool

        out = []
        for n, c in self.config.items():
            if n not in self.manifests:
                continue
            on = as_bool((c if isinstance(c, dict) else {}).get("enabled", True))
            if on is not False:            # a malformed value counts as on, so it is reported, not silently dropped
                out.append(n)
        return sorted(out)

    def enabled_names(self) -> list[str]:
        """Connectors that are switched on *and* usable - what every workflow works with."""
        return [n for n in self.configured_names() if not self.problems_of(n)]

    def problems_of(self, name: str) -> list[str]:
        """Why a configured connector cannot be used (empty when it can). Checked once per registry; a construction
        failure found later is added by ``instance``."""
        if name not in self._problems:
            self._problems[name] = self._check(name)
        return self._problems[name]

    def _check(self, name: str) -> list[str]:
        from soc_platform.connectors.config_schema import ENTRY_KEYS, STAGES, as_bool, mode_for

        raw = self.config.get(name)
        if raw is not None and not isinstance(raw, dict):
            return [f"{name}: the entry must be a mapping (enabled / stage / settings)"]
        e = raw or {}
        out = [f"{name}: unknown key '{k}'" for k in e if k not in ENTRY_KEYS]
        if "enabled" in e and as_bool(e["enabled"]) is None:
            out.append(f"{name}: enabled must be true or false, not '{e['enabled']}'")
        if e.get("mode") is not None and e["mode"] not in ("fake", "live"):
            out.append(f"{name}: unknown mode {e['mode']!r} (fake or live)")
        if e.get("stage") is not None and e["stage"] not in STAGES:
            out.append(f"{name}: unknown stage {e['stage']!r} ({', '.join(STAGES)})")
        if e.get("mode") in ("fake", "live") and e.get("stage") in STAGES and mode_for(e["stage"]) != e["mode"]:
            out.append(f"{name}: mode '{e['mode']}' contradicts stage '{e['stage']}'")
        if e.get("settings") is not None and not isinstance(e["settings"], dict):
            out.append(f"{name}: settings must be a mapping")
        return out or self.validate(name)

    def stage_of(self, name: str) -> str:
        from soc_platform.connectors.config_schema import STAGES, stage_of

        st = stage_of(self._entry(name), self.default_mode)
        return st if st in STAGES else "fake"

    def mode_of(self, name: str) -> str:
        from soc_platform.connectors.config_schema import mode_for

        return mode_for(self.stage_of(name))

    def settings_for(self, name: str) -> dict[str, Any]:
        m = self.manifests[name]
        raw_settings = self._entry(name).get("settings")
        raw = interpolate(raw_settings if isinstance(raw_settings, dict) else {})
        if self.mode_of(name) == "fake":
            raw = {**m.fake_settings, **_estate_settings().get(name, {}), **{k: v for k, v in raw.items() if v not in (None, "")}}
        out = {f.name: raw.get(f.name) if raw.get(f.name) not in (None, "") else f.default for f in m.config}
        out.update({k: v for k, v in raw.items() if k not in out})
        return out

    def validate(self, name: str) -> list[str]:
        m = self.manifests[name]
        if self.mode_of(name) != "live":
            return []
        s = self.settings_for(name)
        return [f"{name}: missing required setting '{f.name}'" for f in m.config
                if f.required and s.get(f.name) in (None, "")]

    # ------------------------------------------------------------------ build

    def get(self, name: str) -> BaseConnector:
        return self.instance(name).connector

    def instance(self, name: str) -> ConnectorInstance:
        if name in self._instances:
            return self._instances[name]
        with self._instance_lock:                            # lookups now run in parallel: build each connector once
            if name in self._instances:
                return self._instances[name]
            if name not in self.manifests:
                raise KeyError(f"no connector named {name!r}; discovered: {sorted(self.manifests)}")
            problems = self.problems_of(name)
            if problems:
                raise ConfigError("; ".join(problems))
            try:
                inst = self.construct(name)
            except ConfigError as exc:
                self._problems[name] = [str(exc)]
                raise
            except Exception as exc:  # one connector that cannot be built is isolated, the rest work
                log.exception("connector %s could not be built; it is left out of every workflow", name)
                self._problems[name] = [f"{name}: could not be started: {type(exc).__name__}: {str(exc)[:200]}"]
                raise ConfigError(self._problems[name][0]) from exc
            self._instances[name] = inst
            return inst

    def construct(self, name: str) -> ConnectorInstance:
        """A new, uncached instance from the current configuration (preflight builds one so its reads share no state
        with the running connector)."""
        m = self.manifests[name]
        stage, mode = self.stage_of(name), self.mode_of(name)
        settings = self.settings_for(name)
        if mode == "live":
            problems = self.validate(name)
            if problems:
                raise ConfigError("; ".join(problems))
            from soc_platform.connectors.recording import wrap_for_recording

            # stage "record" (or SOC_RECORD_FIXTURES_DIR for every live tool): sanitised responses become test fixtures
            transport: Transport = wrap_for_recording(m.live_transport(settings), name,
                                                      out_dir=recordings_dir() if stage == "record" else None)
        else:
            transport = m.fixture_transport()
        return ConnectorInstance(m, m.factory(settings, transport), mode, transport, stage)

    def _usable(self) -> list[tuple[str, BaseConnector]]:
        out = []
        for n in self.enabled_names():
            try:
                out.append((n, self.get(n)))
            except ConfigError:
                continue                     # isolated: recorded in problems_of(n), shown on Integrations
        return out

    def enabled(self) -> list[BaseConnector]:
        return [c for _, c in self._usable()]

    def by_category(self, category: str) -> list[BaseConnector]:
        return [c for n, c in self._usable() if self.manifests[n].category == category]

    def with_lookup(self, entity_type: str) -> list[BaseConnector]:
        return [c for c in self.enabled() if entity_type in c.lookups]

    def with_stream(self, stream: str) -> list[BaseConnector]:
        return [c for c in self.enabled() if stream in c.streams]

    def action_registry(self, base: ActionRegistry | None = None) -> ActionRegistry:
        """All enabled connectors' actions. When several connectors implement the same action type
        (e.g. endpoint.isolate on CrowdStrike and Defender) they are wrapped in a ``RoutedAction``.
        Stages: ``fake`` / ``automate`` offer actions under the policy, ``recommend`` caps them at L2, ``record`` and
        ``read`` offer none (the recommendation is shown as a manual step)."""
        from soc_platform.connectors.config_schema import STAGE_LABELS

        reg = base or ActionRegistry()
        grouped: dict[str, list[ActionSpec]] = {}
        for n, conn in self._usable():
            stage = self.stage_of(n)
            if stage in ("record", "read"):
                continue
            try:
                specs = list(self.manifests[n].actions(conn))
            except Exception:  # a broken action factory removes that tool's actions, not every tool's
                log.exception("actions of connector %s could not be loaded", n)
                self._problems[n] = [f"{n}: its actions could not be loaded"]
                continue
            for spec in specs:
                if stage == "recommend":
                    spec = StagedAction(spec, 2, f"{self.manifests[n].tool} is in the {STAGE_LABELS[stage]} stage: "
                                                 "a person approves every action")
                grouped.setdefault(spec.action_type, []).append(spec)
        for action_type, specs in grouped.items():
            reg.register(specs[0] if len(specs) == 1 else RoutedAction(action_type, specs))
        return reg

    def status(self, *, probe: bool = False) -> list[dict[str, Any]]:
        """Connector inventory. ``probe=True`` also runs each enabled connector's live health check (one API read
        per connector) - use it deliberately, not on every page load."""
        from soc_platform.connectors.config_schema import STAGE_LABELS

        out = []
        configured = set(self.configured_names())
        for n in sorted(self.manifests):
            m = self.manifests[n]
            stage = self.stage_of(n)
            row = {**m.describe(), "enabled": n in configured, "mode": self.mode_of(n), "stage": stage,
                   "stage_label": STAGE_LABELS.get(stage, stage), "config_problems": []}
            if row["enabled"]:
                try:
                    c = self.get(n)
                    row.update({"streams": list(c.streams), "lookups": list(c.lookups),
                                "health": c.health() if probe else {"ok": None, "detail": "not probed"}})
                except ConfigError:
                    pass
                except Exception as exc:  # a probe failure is reported in the row, never raised
                    row["health"] = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
                row["config_problems"] = list(self.problems_of(n))
            out.append(row)
        return out
