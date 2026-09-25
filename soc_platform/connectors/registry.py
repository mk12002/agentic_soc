"""Plug-and-play connector registry (NFR-14, R15).

Discovery
  * every module in ``soc_platform.connectors.tools`` exporting ``MANIFEST`` (or ``MANIFESTS``)
  * any installed distribution exposing the entry-point group ``soc_platform.connectors``
    (``my_pkg.my_module:MANIFEST``) - third-party connectors need no platform change.

Configuration (``config/connectors.yaml``)::

    connectors:
      crowdstrike:
        enabled: true
        mode: fake            # fake (fixtures) | live (real API)
        settings:
          base_url: https://api.crowdstrike.com
          client_id: ${CROWDSTRIKE_CLIENT_ID}          # env var, or <NAME>_FILE for vault-mounted secrets
          client_secret: ${CROWDSTRIKE_CLIENT_SECRET}

Swapping a tool (e.g. Avanan -> another gateway) is a config change plus one module.
"""

from __future__ import annotations

import importlib
import os
import pkgutil
import re
from dataclasses import dataclass, field
from importlib.metadata import entry_points
from pathlib import Path
from typing import Any, Callable

import yaml

from soc_platform.config import secret
from soc_platform.connectors.base import BaseConnector
from soc_platform.connectors.http import FixtureTransport, Transport
from soc_platform.core.actions import ActionRegistry, ActionSpec

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures"


@dataclass
class ConfigField:
    name: str
    description: str = ""
    secret: bool = False
    required: bool = True
    default: Any = None


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
                "config": [{"name": f.name, "secret": f.secret, "required": f.required,
                            "description": f.description} for f in self.config]}


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
        module = importlib.import_module(f"{tools_pkg.__name__}.{mod.name}")
        for m in _manifests_of(module):
            found[m.name] = m
    try:
        eps = entry_points(group="soc_platform.connectors")
    except TypeError:  # pragma: no cover - old importlib.metadata API
        eps = entry_points().get("soc_platform.connectors", [])
    for ep in eps:
        obj = ep.load()
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


class RoutedAction(ActionSpec):
    """Dispatch one action type to the first provider whose pre-conditions accept the targets."""

    def __init__(self, action_type: str, providers: list[ActionSpec]) -> None:
        self.action_type = action_type
        self.providers = providers
        self.tool = "+".join(p.tool for p in providers)
        self.description = " | ".join(p.description for p in providers)
        self.destructive = any(p.destructive for p in providers)
        self.reverse_type = providers[0].reverse_type if all(p.reverse_type for p in providers) else None

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


class ConnectorRegistry:
    def __init__(self, config: dict[str, Any] | None = None, *, default_mode: str = "fake",
                 manifests: dict[str, ConnectorManifest] | None = None) -> None:
        self.manifests = manifests if manifests is not None else discover()
        self.config = (config or {}).get("connectors", {}) if config else {}
        self.default_mode = default_mode
        self._instances: dict[str, ConnectorInstance] = {}

    @classmethod
    def from_file(cls, path: str | Path | None = None, *, default_mode: str | None = None) -> "ConnectorRegistry":
        path = Path(path or os.environ.get("SOC_CONNECTORS_CONFIG", "config/connectors.yaml"))
        cfg = yaml.safe_load(path.read_text(encoding="utf-8")) if path.exists() else {}
        return cls(cfg or {}, default_mode=default_mode or os.environ.get("SOC_CONNECTOR_MODE", "fake"))

    @classmethod
    def all_fake(cls) -> "ConnectorRegistry":
        """Every discovered connector enabled in fixture mode (demos, tests, local dev)."""
        manifests = discover()
        return cls({"connectors": {n: {"enabled": True, "mode": "fake"} for n in manifests}},
                   manifests=manifests)

    # ------------------------------------------------------------------ build

    def enabled_names(self) -> list[str]:
        return sorted(n for n, c in self.config.items() if c.get("enabled", True) and n in self.manifests)

    def mode_of(self, name: str) -> str:
        return (self.config.get(name) or {}).get("mode", self.default_mode)

    def settings_for(self, name: str) -> dict[str, Any]:
        m = self.manifests[name]
        raw = interpolate((self.config.get(name) or {}).get("settings") or {})
        if self.mode_of(name) == "fake":
            raw = {**m.fake_settings, **_estate_settings().get(name, {}), **{k: v for k, v in raw.items() if v not in (None, "")}}
        out = {f.name: raw.get(f.name) if raw.get(f.name) not in (None, "") else f.default for f in m.config}
        out.update({k: v for k, v in raw.items() if k not in out})
        return out

    def validate(self, name: str) -> list[str]:
        m = self.manifests[name]
        mode = (self.config.get(name) or {}).get("mode", self.default_mode)
        if mode != "live":
            return []
        s = self.settings_for(name)
        return [f"{name}: missing required setting '{f.name}'" for f in m.config
                if f.required and s.get(f.name) in (None, "")]

    def get(self, name: str) -> BaseConnector:
        return self.instance(name).connector

    def instance(self, name: str) -> ConnectorInstance:
        if name in self._instances:
            return self._instances[name]
        if name not in self.manifests:
            raise KeyError(f"no connector named {name!r}; discovered: {sorted(self.manifests)}")
        m = self.manifests[name]
        mode = (self.config.get(name) or {}).get("mode", self.default_mode)
        settings = self.settings_for(name)
        if mode == "live":
            problems = self.validate(name)
            if problems:
                raise ConfigError("; ".join(problems))
            transport: Transport = m.live_transport(settings)
        elif mode == "fake":
            transport = m.fixture_transport()
        else:
            raise ConfigError(f"{name}: unknown mode {mode!r}")
        inst = ConnectorInstance(m, m.factory(settings, transport), mode, transport)
        self._instances[name] = inst
        return inst

    def enabled(self) -> list[BaseConnector]:
        return [self.get(n) for n in self.enabled_names()]

    def by_category(self, category: str) -> list[BaseConnector]:
        return [self.get(n) for n in self.enabled_names() if self.manifests[n].category == category]

    def with_lookup(self, entity_type: str) -> list[BaseConnector]:
        return [c for c in self.enabled() if entity_type in c.lookups]

    def with_stream(self, stream: str) -> list[BaseConnector]:
        return [c for c in self.enabled() if stream in c.streams]

    def action_registry(self, base: ActionRegistry | None = None) -> ActionRegistry:
        """All enabled connectors' actions. When several connectors implement the same action type
        (e.g. endpoint.isolate on CrowdStrike and Defender) they are wrapped in a ``RoutedAction``."""
        reg = base or ActionRegistry()
        grouped: dict[str, list[ActionSpec]] = {}
        for n in self.enabled_names():
            inst = self.instance(n)
            for spec in inst.manifest.actions(inst.connector):
                grouped.setdefault(spec.action_type, []).append(spec)
        for action_type, specs in grouped.items():
            reg.register(specs[0] if len(specs) == 1 else RoutedAction(action_type, specs))
        return reg

    def status(self, *, probe: bool = False) -> list[dict[str, Any]]:
        """Connector inventory. ``probe=True`` also runs each enabled connector's live health check (one API read
        per connector) - use it deliberately, not on every page load."""
        out = []
        for n in sorted(self.manifests):
            m = self.manifests[n]
            cfg = self.config.get(n) or {}
            row = {**m.describe(), "enabled": n in self.enabled_names(), "mode": cfg.get("mode", self.default_mode),
                   "config_problems": self.validate(n) if n in self.enabled_names() else []}
            if row["enabled"] and not row["config_problems"]:
                try:
                    c = self.get(n)
                    row.update({"streams": list(c.streams), "lookups": list(c.lookups),
                                "health": c.health() if probe else {"ok": None, "detail": "not probed"}})
                except Exception as exc:
                    row["health"] = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
            out.append(row)
        return out
