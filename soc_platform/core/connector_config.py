"""Connector configuration that admins change in the console - governed like the autonomy policy (NFR-12, NFR-14).

The configuration in force is ``config/connectors.yaml`` with the active console version layered on top. A change
(switch a tool on or off, move it to another rollout stage, edit a non-secret setting, import a whole file, restore an
earlier version) is *proposed* by one person and *approved* by another; it is checked before it can be proposed and
again before it is approved, every version is kept, and every step is audited. Every API process and the scheduler
pick an approved change up within seconds, without a restart (``registry_for``).

Safety rules:

* **No secret is ever stored.** A secret setting may only be a ``${VAR}`` reference; the value stays in the vault
  (``<VAR>_FILE``) or the environment. The console shows whether it is set and when its file last changed.
* **Live only after a passing preflight.** Moving a tool into a live stage, switching a live tool on, or changing a
  live tool's settings runs the preflight on the proposed configuration; errors refuse the proposal, warnings are
  shown to the approver. Approval refuses a preflight that no longer matches the configuration or is over a week old.
* **Stale proposals cannot overwrite newer ones.** A proposal records the version it was made from; if another change
  was approved meanwhile, it must be proposed again.
* **Pausing is immediate.** Switching a tool *off* only ever reduces what the platform does, so it takes effect at once
  (audited, reason required) - for a tool that misbehaves. Switching it back on is a normal proposal.
"""

from __future__ import annotations

import copy
import os
from datetime import timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from soc_platform.connectors.config_schema import (
    LIST_KEYS,
    LIVE_STAGES,
    STAGE_LABELS,
    STAGES,
    Problem,
    as_bool,
    check_document,
    check_entry,
    check_lists,
    env_var_for,
    load_file,
    load_yaml,
)
from soc_platform.connectors.registry import COMMON_FIELDS, ConnectorRegistry, discover
from soc_platform.core.audit import AuditLog
from soc_platform.core.auth import Perm, Principal
from soc_platform.core.models import ConnectorConfigVersion, ConnectorPreflight, utcnow

PREFLIGHT_MAX_AGE = timedelta(days=7)
_VAR_ONLY = __import__("re").compile(r"^\$\{[A-Z0-9_]+(?::-[^}]*)?\}$")


class ConfigRejected(ValueError):
    """A change that cannot be proposed or approved; ``problems`` / ``preflight`` say why and how to fix it."""

    def __init__(self, message: str, *, problems: list[Problem] | None = None,
                 preflight: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.problems = problems or []
        self.preflight = preflight or {}

    def detail(self) -> dict[str, Any]:
        return {"message": str(self), "problems": [p.as_dict() for p in self.problems], "preflight": self.preflight}


_MANIFESTS: dict[str, Any] = {}


def manifests() -> dict[str, Any]:
    if not _MANIFESTS:
        _MANIFESTS.update(discover())
    return _MANIFESTS


def default_mode() -> str:
    return os.environ.get("SOC_CONNECTOR_MODE", "fake")


# ---------------------------------------------------------------------------------------------- documents


def merge(base: dict[str, Any], overrides: dict[str, Any]) -> dict[str, Any]:
    """The file document with console overrides applied. A stage given in the console replaces the file's older
    ``mode`` key (they would otherwise contradict each other)."""
    doc = copy.deepcopy(base if isinstance(base, dict) else {})
    conns = doc.setdefault("connectors", {}) or {}
    doc["connectors"] = conns
    for name, o in ((overrides or {}).get("connectors") or {}).items():
        listed = name in conns
        entry = copy.deepcopy(conns.get(name) or {})
        if not isinstance(entry, dict):
            entry = {}
        if not listed and "enabled" not in o:
            entry["enabled"] = False         # editing a setting of an unlisted tool must not quietly switch it on
        if "enabled" in o:
            entry["enabled"] = o["enabled"]
        if "stage" in o:
            entry["stage"] = o["stage"]
            entry.pop("mode", None)
        if o.get("settings"):
            entry["settings"] = {**(entry.get("settings") or {}), **o["settings"]}
        conns[name] = entry
    return doc


def apply_changes(overrides: dict[str, Any], changes: dict[str, Any]) -> dict[str, Any]:
    """New overrides from a change set: ``{name: {enabled?, stage?, settings?: {field: value | None}}}``; a setting
    of None drops the console value (the file's applies again); ``{name: None}`` drops every console value of a tool."""
    out = copy.deepcopy(overrides or {"connectors": {}})
    conns = out.setdefault("connectors", {})
    for name, ch in changes.items():
        if ch is None:
            conns.pop(name, None)
            continue
        entry = conns.setdefault(name, {})
        for k in ("enabled", "stage"):
            if k in ch:
                entry[k] = ch[k]
        for k, v in (ch.get("settings") or {}).items():
            s = entry.setdefault("settings", {})
            if v is None:
                s.pop(k, None)
            else:
                s[k] = v
        if not entry.get("settings"):
            entry.pop("settings", None)
        if not entry:
            conns.pop(name, None)
    return out


def _validate_changes(changes: Any) -> list[Problem]:
    """Shape and safety of a change set, before it is merged (unknown tools / keys, secrets written in clear)."""
    ms = manifests()
    if not isinstance(changes, dict) or not changes:
        return [Problem("error", "changes", "nothing to change", "")]
    out: list[Problem] = []
    for name, ch in changes.items():
        if name not in ms:
            from soc_platform.connectors.config_schema import suggest

            out.append(Problem("error", str(name), "no connector of this name is installed", suggest(name, sorted(ms))))
            continue
        if ch is None:
            continue
        if not isinstance(ch, dict):
            out.append(Problem("error", name, "expected enabled / stage / settings", ""))
            continue
        for k in ch:
            if k not in ("enabled", "stage", "settings"):
                out.append(Problem("error", f"{name}.{k}", "cannot be changed here", "use enabled, stage or settings"))
        if "enabled" in ch and not isinstance(ch["enabled"], bool):
            out.append(Problem("error", f"{name}.enabled", "must be true or false", ""))
        if "stage" in ch and ch["stage"] not in STAGES:
            out.append(Problem("error", f"{name}.stage", f"'{ch['stage']}' is not a stage", ", ".join(STAGES)))
        settings = ch.get("settings") or {}
        if not isinstance(settings, dict):
            out.append(Problem("error", f"{name}.settings", "expected a mapping", ""))
            continue
        fields = {f.name: f for f in [*ms[name].config, *COMMON_FIELDS]}
        for k, v in settings.items():
            f = fields.get(k)
            if f is None:
                from soc_platform.connectors.config_schema import suggest

                out.append(Problem("error", f"{name}.settings.{k}", "not a setting of this connector",
                                   suggest(k, sorted(fields))))
            elif v is not None and not isinstance(v, (str, int, float, bool, dict, list)):
                out.append(Problem("error", f"{name}.settings.{k}", "unsupported value", ""))
            elif f.secret and v not in (None, "") and not (isinstance(v, str) and _VAR_ONLY.match(v.strip())):
                out.append(Problem("error", f"{name}.settings.{k}", "secrets are never stored in the platform",
                                   f"put the value in the vault / environment as {env_var_for(name, k)} and refer to "
                                   f"it as ${{{env_var_for(name, k)}}}"))
    return out


def file_lists() -> dict[str, list[Any]]:
    """The lists as the files define them (config/suppliers.yaml, config/sanctioned_services.yaml)."""
    from soc_platform.domains.phishing.supplier import load_suppliers
    from soc_platform.intelligence.shadow_it import load_sanctioned

    return {"suppliers": [{"name": s.name, "domains": list(s.domains), "criticality": s.criticality}
                          for s in load_suppliers(include_env=False)],
            "sanctioned": sorted(load_sanctioned())}


def effective_lists(overrides: dict[str, Any]) -> dict[str, list[Any]]:
    """The lists in force, in one normal form (lower-case, sorted domains) whether they come from a file or the
    console, so an unchanged list never shows as a change."""
    base, over = file_lists(), (overrides or {}).get("lists") or {}
    return _normal_lists({k: over[k] if k in over else base[k] for k in LIST_KEYS})


def console_lists(session: Session) -> dict[str, Any]:
    """The approved console lists (only the ones the console sets; a missing key means the file's list applies)."""
    row = ConfigStore(session).active_row()
    return copy.deepcopy((row.document or {}).get("lists") or {}) if row else {}


def _normal_lists(lists: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in lists.items():
        if v is None:
            out[k] = None
        elif k == "suppliers":
            out[k] = [{"name": str(s["name"]).strip(), "domains": sorted({str(d).strip().lower() for d in s["domains"]}),
                       "criticality": s.get("criticality") or "medium"} for s in v]
        else:
            out[k] = sorted({str(d).strip().lower() for d in v})
    return out


def apply_lists(overrides: dict[str, Any], lists: dict[str, Any] | None) -> dict[str, Any]:
    out = copy.deepcopy(overrides)
    if not lists:
        return out
    cur = out.setdefault("lists", {})
    for k, v in _normal_lists(lists).items():
        if v is None:
            cur.pop(k, None)              # the file's list applies again
        else:
            cur[k] = v
    if not cur:
        out.pop("lists", None)
    return out


def _item(k: str, x: Any) -> str:
    return f"{x['name']} ({', '.join(x['domains'])}; {x['criticality']})" if k == "suppliers" else str(x)


def describe_list_changes(before_over: dict[str, Any], after_over: dict[str, Any]) -> list[dict[str, Any]]:
    b, a = effective_lists(before_over), effective_lists(after_over)
    out = []
    for k in LIST_KEYS:
        if b[k] != a[k]:
            old, new = {_item(k, x) for x in b[k]}, {_item(k, x) for x in a[k]}
            out.append({"connector": "(lists)", "field": k, "from": sorted(old - new) or None,
                        "to": sorted(new - old) or None, "count": len(a[k])})
    return out


def _flat(conns: dict[str, Any], name: str, dmode: str) -> dict[str, Any]:
    """One tool's entry as flat fields. A tool absent from the document is off; one listed (even empty) is on."""
    from soc_platform.connectors.config_schema import stage_of

    entry = conns.get(name)
    e = entry if isinstance(entry, dict) else {}
    on = as_bool(e.get("enabled", True)) if name in conns else False
    return {"enabled": on is not False, "stage": stage_of(e, dmode), **{f"settings.{k}": v for k, v in
                                                                         (e.get("settings") or {}).items()}}


def describe_changes(before: dict[str, Any], after: dict[str, Any]) -> list[dict[str, Any]]:
    """Field-by-field differences between two effective documents (secrets appear only as their ${VAR} reference)."""
    dmode = default_mode()
    b, a = (before or {}).get("connectors") or {}, (after or {}).get("connectors") or {}
    out = []
    for name in sorted(set(b) | set(a)):
        fb, fa = _flat(b, name, dmode), _flat(a, name, dmode)
        for k in sorted(set(fb) | set(fa)):
            if fb.get(k) != fa.get(k):
                out.append({"connector": name, "field": k, "from": fb.get(k), "to": fa.get(k)})
    return out


def _live_affecting(name: str, before: dict[str, Any], after: dict[str, Any]) -> bool:
    """Does this change put a tool into live use, or change how a live tool connects?"""
    dmode = default_mode()
    fb = _flat((before or {}).get("connectors") or {}, name, dmode)
    fa = _flat((after or {}).get("connectors") or {}, name, dmode)
    if not fa["enabled"] or fa["stage"] not in LIVE_STAGES:
        return False
    if not fb["enabled"] or fb["stage"] not in LIVE_STAGES:
        return True
    return any(k.startswith("settings.") and fa.get(k) != fb.get(k) for k in set(fa) | set(fb))


# ---------------------------------------------------------------------------------------------- store


class ConfigStore:
    def __init__(self, session: Session) -> None:
        self.s = session
        self.audit = AuditLog(session)

    # ------------------------------------------------------------- reading
    def active_row(self) -> ConnectorConfigVersion | None:
        return self.s.execute(select(ConnectorConfigVersion).where(ConnectorConfigVersion.status == "active")
                              .order_by(ConnectorConfigVersion.id.desc())).scalars().first()

    def active_version(self) -> int | None:
        row = self.active_row()
        return row.id if row else None

    def overrides(self) -> dict[str, Any]:
        row = self.active_row()
        return copy.deepcopy(row.document) if row else {"connectors": {}}

    @staticmethod
    def file_document() -> tuple[dict[str, Any], list[Problem]]:
        return load_file()

    def effective(self, overrides: dict[str, Any] | None = None) -> dict[str, Any]:
        doc, _ = self.file_document()
        return merge(doc, self.overrides() if overrides is None else overrides)

    def registry(self, overrides: dict[str, Any] | None = None) -> ConnectorRegistry:
        doc, problems = self.file_document()
        over = self.overrides() if overrides is None else overrides
        reg = ConnectorRegistry(merge(doc, over), default_mode=default_mode(), manifests=manifests(),
                                version=self.active_version())
        reg.file_problems = problems
        reg.lists = copy.deepcopy(over.get("lists") or {})       # suppliers / sanctioned set in the console
        return reg

    def pending(self) -> list[ConnectorConfigVersion]:
        return list(self.s.execute(select(ConnectorConfigVersion).where(ConnectorConfigVersion.status == "proposed")
                                   .order_by(ConnectorConfigVersion.id)).scalars())

    def history(self, limit: int = 50) -> list[ConnectorConfigVersion]:
        return list(self.s.execute(select(ConnectorConfigVersion).order_by(ConnectorConfigVersion.id.desc())
                                   .limit(limit)).scalars())

    def last_preflights(self) -> dict[str, ConnectorPreflight]:
        out: dict[str, ConnectorPreflight] = {}
        for row in self.s.execute(select(ConnectorPreflight).order_by(ConnectorPreflight.id.desc()).limit(500)).scalars():
            out.setdefault(row.connector, row)
        return out

    # ------------------------------------------------------------- preflight
    def preflight(self, name: str, by: Principal, *, registry: ConnectorRegistry | None = None) -> dict[str, Any]:
        from soc_platform.connectors.preflight import run_preflight

        if not by.can(Perm.MANAGE_CONNECTORS):
            raise PermissionError("manage_connectors permission required")
        reg = registry or self.registry()
        if name not in reg.manifests:
            raise KeyError(f"no connector named {name!r}")
        res = run_preflight(reg, name)
        self.s.add(ConnectorPreflight(connector=name, ran_by=by.id, ok=res["ok"], verdict=res["verdict"],
                                      stage=res["stage"], fingerprint=res["fingerprint"], result=res))
        self.audit.append(actor_type=by.actor_type, actor_id=by.id, event_type="connector.preflight",
                          subject_type="connector", subject_id=name,
                          payload={"verdict": res["verdict"], "errors": res["errors"], "warnings": res["warnings"]})
        self.s.flush()
        return res

    # ------------------------------------------------------------- changing
    def propose(self, changes: dict[str, Any], by: Principal, note: str = "", *, kind: str = "change",
                lists: dict[str, Any] | None = None) -> ConnectorConfigVersion:
        """``changes``: per connector (enabled / stage / settings); ``lists``: suppliers and / or sanctioned services
        (a list replaces the file's; None gives the file's back)."""
        if by.is_service or by.is_agent or not by.can(Perm.MANAGE_CONNECTORS):
            raise PermissionError("a person with manage_connectors proposes configuration changes")
        problems = _validate_changes(changes) if changes or not lists else []
        problems += check_lists({k: v for k, v in (lists or {}).items() if v is not None} if isinstance(lists, dict)
                                else lists)
        if any(p.level == "error" for p in problems):
            raise ConfigRejected("the change is not valid", problems=problems)
        base = self.active_row()
        before_over = self.overrides()
        after_over = apply_lists(apply_changes(before_over, changes or {}), lists)
        before, after = self.effective(before_over), self.effective(after_over)
        diff = describe_changes(before, after) + describe_list_changes(before_over, after_over)
        if not diff:
            raise ConfigRejected("this changes nothing in the configuration in force")
        touched = sorted({d["connector"] for d in diff} - {"(lists)"})
        ms = manifests()
        errs = [p for n in touched for p in check_entry(n, after["connectors"].get(n), ms, default_mode=default_mode())
                if p.level == "error"]
        if errs:
            raise ConfigRejected("the configuration would not work: " + "; ".join(str(p) for p in errs[:5]),
                                 problems=errs)
        reg = self.registry(after_over)
        flights: dict[str, Any] = {}
        for n in touched:
            if _live_affecting(n, before, after):
                res = self.preflight(n, by, registry=reg)
                flights[n] = _summary(res)
                if not res["ok"]:
                    raise ConfigRejected(f"{n}: the preflight found problems - fix them and propose again",
                                         preflight=res)
        row = ConnectorConfigVersion(document=after_over, changes=diff, base_version=base.id if base else None,
                                     kind=kind, status="proposed", proposed_by=by.id, note=note[:2000], preflight=flights)
        self.s.add(row)
        self.s.flush()
        self.audit.append(actor_type=by.actor_type, actor_id=by.id, event_type="connector_config.proposed",
                          subject_type="connector_config", subject_id=str(row.id),
                          payload={"kind": kind, "note": note[:500], "changes": diff, "preflight": flights})
        return row

    def approve(self, version_id: int, by: Principal) -> ConnectorConfigVersion:
        if not by.can(Perm.APPROVE_POLICY):
            raise PermissionError("approve_policy permission required")
        row = self.s.get(ConnectorConfigVersion, version_id)
        if row is None or row.status != "proposed":
            raise ValueError("this configuration change is not awaiting approval")
        if row.proposed_by == by.id:
            raise PermissionError("separation of duties: the proposer cannot approve their own change")
        active = self.active_row()
        if (active.id if active else None) != row.base_version:
            raise ConfigRejected("another change was approved after this one was proposed: propose it again so it is "
                                 "reviewed against the configuration now in force")
        after = self.effective(row.document)
        ms = manifests()
        touched = sorted({c["connector"] for c in row.changes or []} - {"(lists)"})
        errs = [p for n in touched for p in check_entry(n, after["connectors"].get(n), ms, default_mode=default_mode())
                if p.level == "error"]
        if errs:
            raise ConfigRejected("the configuration no longer works (a secret may have been removed): "
                                 + "; ".join(str(p) for p in errs[:5]), problems=errs)
        if row.preflight:
            from soc_platform.connectors.preflight import fingerprint

            reg = self.registry(row.document)
            for n, pf in row.preflight.items():
                if pf.get("fingerprint") != fingerprint(reg, n):
                    raise ConfigRejected(f"{n}: the settings or secrets changed since its preflight - propose again")
                ran = pf.get("ran_at")
                from datetime import datetime

                if ran and utcnow() - datetime.fromisoformat(ran) > PREFLIGHT_MAX_AGE:
                    raise ConfigRejected(f"{n}: its preflight is more than {PREFLIGHT_MAX_AGE.days} days old - propose "
                                         "again so it is checked against the tool as it is today")
        self._activate(row, by.id)
        self.audit.append(actor_type=by.actor_type, actor_id=by.id, event_type="connector_config.activated",
                          subject_type="connector_config", subject_id=str(row.id),
                          payload={"proposed_by": row.proposed_by, "changes": row.changes})
        return row

    def reject(self, version_id: int, by: Principal, reason: str = "") -> ConnectorConfigVersion:
        row = self.s.get(ConnectorConfigVersion, version_id)
        if row is None or row.status != "proposed":
            raise ValueError("this configuration change is not awaiting a decision")
        own = row.proposed_by == by.id
        if not own and not by.can(Perm.APPROVE_POLICY):
            raise PermissionError("approve_policy permission required (or withdraw your own proposal)")
        row.status, row.decided_at = ("withdrawn" if own else "rejected"), utcnow()
        self.audit.append(actor_type=by.actor_type, actor_id=by.id, event_type=f"connector_config.{row.status}",
                          subject_type="connector_config", subject_id=str(row.id), payload={"reason": reason[:500]})
        self.s.flush()
        return row

    def pause(self, name: str, by: Principal, reason: str) -> ConnectorConfigVersion:
        """Switch one tool off at once (the safe direction: no second approver needed)."""
        if by.is_agent or not (by.can(Perm.MANAGE_CONNECTORS) or by.can(Perm.KILL_SWITCH)):
            raise PermissionError("manage_connectors or kill_switch permission required")
        if len((reason or "").strip()) < 3:
            raise ValueError("say why the tool is paused")
        if name not in manifests():
            raise KeyError(f"no connector named {name!r}")
        before_over = self.overrides()
        after_over = apply_changes(before_over, {name: {"enabled": False}})
        diff = describe_changes(self.effective(before_over), self.effective(after_over))
        if not diff:
            raise ValueError(f"{name} is already off")
        row = ConnectorConfigVersion(document=after_over, changes=diff, base_version=self.active_version(), kind="pause",
                                     status="proposed", proposed_by=by.id, note=reason[:2000])
        self.s.add(row)
        self.s.flush()
        self._activate(row, f"{by.id} (pause: takes effect at once)")
        self.audit.append(actor_type=by.actor_type, actor_id=by.id, event_type="connector_config.paused",
                          subject_type="connector", subject_id=name, payload={"reason": reason[:500], "version": row.id})
        return row

    def restore(self, version_id: int, by: Principal, note: str = "") -> ConnectorConfigVersion:
        """Propose going back to an earlier version (it still needs a second person's approval)."""
        old = self.s.get(ConnectorConfigVersion, version_id)
        if old is None or old.status not in ("active", "superseded"):
            raise ValueError("only a version that was in force can be restored")
        cur = self.overrides().get("connectors") or {}
        target = (old.document or {}).get("connectors") or {}
        changes: dict[str, Any] = {n: None for n in cur if n not in target}
        for n, entry in target.items():
            ch: dict[str, Any] = {k: entry[k] for k in ("enabled", "stage") if k in entry}
            cur_settings = (cur.get(n) or {}).get("settings") or {}
            settings = {**{k: None for k in cur_settings}, **(entry.get("settings") or {})}
            if settings:
                ch["settings"] = settings
            changes[n] = ch
        old_lists = (old.document or {}).get("lists") or {}
        lists = {k: old_lists.get(k) for k in LIST_KEYS if k in old_lists or k in (self.overrides().get("lists") or {})}
        return self.propose({n: c for n, c in changes.items() if c != {}}, by, note or f"restore version {version_id}",
                            kind="restore", lists=lists or None)

    def _activate(self, row: ConnectorConfigVersion, approved_by: str) -> None:
        for old in self.s.execute(select(ConnectorConfigVersion).where(ConnectorConfigVersion.status == "active")).scalars():
            old.status = "superseded"
        row.status, row.approved_by, row.decided_at = "active", approved_by[:256], utcnow()
        self.s.flush()

    # ------------------------------------------------------------- export / import
    def export_yaml(self) -> str:
        import yaml

        doc = self.effective()
        doc["lists"] = effective_lists(self.overrides())
        head = (f"# Connector configuration in force (file + console version {self.active_version() or 'none'}), "
                f"exported {utcnow().isoformat(timespec='seconds')}.\n"
                "# Secrets appear only as ${VAR} references; their values stay in the vault / environment.\n")
        return head + yaml.safe_dump(doc, sort_keys=True, allow_unicode=True)

    def import_yaml(self, text: str, by: Principal, note: str = "") -> ConnectorConfigVersion:
        """Make the configuration in force equal an exported file (as one proposal). Tools absent from it are
        switched off."""
        doc, problems = load_yaml(text)
        problems += check_document(doc, manifests(), default_mode=default_mode(), check_env=False)
        if any(p.level == "error" for p in problems):
            raise ConfigRejected("the file is not a valid configuration", problems=problems)
        want = doc.get("connectors") or {}
        cur = self.effective().get("connectors") or {}
        dmode = default_mode()
        changes: dict[str, Any] = {}
        for n in sorted(set(want) | set(cur)):
            if n not in manifests():
                continue
            w, c = _flat(want, n, dmode), _flat(cur, n, dmode)
            if n not in want:
                w = {**c, "enabled": False}
            ch: dict[str, Any] = {k: w[k] for k in ("enabled", "stage") if w[k] != c[k]}
            settings = {k[9:]: w.get(k) for k in set(w) | set(c) if k.startswith("settings.") and w.get(k) != c.get(k)}
            if settings:
                ch["settings"] = {k: ("" if v is None else v) for k, v in settings.items()}
            if ch:
                changes[n] = ch
        lists = None
        if isinstance(doc.get("lists"), dict):
            cur_lists = effective_lists(self.overrides())
            lists = {k: v for k, v in _normal_lists({k: v for k, v in doc["lists"].items() if v is not None}).items()
                     if v != cur_lists.get(k)} or None
        if not changes and not lists:
            raise ConfigRejected("the file matches the configuration in force: nothing to import")
        return self.propose(changes, by, note or "import", kind="import", lists=lists)

    # ------------------------------------------------------------- the console view
    def view(self) -> dict[str, Any]:
        reg = self.registry()
        doc, file_problems = self.file_document()
        file_conns = doc.get("connectors") or {}
        over = (self.overrides().get("connectors") or {})
        flights = self.last_preflights()
        version = self.active_version()
        dmode = default_mode()
        out = []
        for n in sorted(reg.manifests):
            m = reg.manifests[n]
            entry = reg.config.get(n) if isinstance(reg.config.get(n), dict) else {}
            o = over.get(n) or {}
            raw_settings = (entry or {}).get("settings") or {}
            fields = []
            for f in [*m.config, *COMMON_FIELDS]:
                raw = raw_settings.get(f.name)
                src = (f"console v{version}" if f.name in (o.get("settings") or {}) else
                       "file" if f.name in ((file_conns.get(n) or {}).get("settings") or {}) else "default")
                var = None
                if isinstance(raw, str) and _VAR_ONLY.match(raw.strip()):
                    var = raw.strip()[2:-1].split(":-")[0]
                row = {"name": f.name, "description": f.description, "kind": "secret" if f.secret else f.kind,
                       "choices": list(f.choices), "required": f.required, "secret": f.secret, "source": src,
                       "env_var": var or env_var_for(n, f.name), "common": f in COMMON_FIELDS}
                resolved = reg.settings_for(n).get(f.name) if reg.mode_of(n) == "live" else None
                if f.secret:
                    row["set"] = resolved not in (None, "") if reg.mode_of(n) == "live" else None
                    file_var = os.environ.get(f"{row['env_var']}_FILE")
                    if file_var and Path(file_var).is_file():
                        from datetime import UTC, datetime

                        row["rotated_at"] = datetime.fromtimestamp(Path(file_var).stat().st_mtime, UTC).isoformat()
                else:
                    row["value"] = raw if not var else None
                    row["resolved"] = resolved if var else None
                fields.append(row)
            pf = flights.get(n)
            out.append({**m.describe(), "config": fields, "enabled": n in reg.configured_names(),
                        "usable": n in reg.enabled_names(), "stage": reg.stage_of(n),
                        "stage_label": STAGE_LABELS.get(reg.stage_of(n)), "mode": reg.mode_of(n),
                        "in_file": n in file_conns, "console_override": bool(o),
                        "problems": [p.as_dict() for p in check_entry(n, entry, reg.manifests, default_mode=dmode)]
                        if n in reg.configured_names() or o else [],
                        "isolated": list(reg.problems_of(n)) if n in reg.configured_names() else [],
                        "last_preflight": _summary(pf.result) | {"ran_by": pf.ran_by} if pf else None})
        attributed = {n for n in reg.manifests}
        over_lists = self.overrides().get("lists") or {}
        eff = effective_lists(self.overrides())
        lists_view = {k: {"items": eff[k], "source": f"console v{version}" if k in over_lists else "file"}
                      for k in LIST_KEYS}
        return {"active_version": version, "stages": [{"id": s, "label": STAGE_LABELS[s]} for s in STAGES],
                "lists": lists_view,
                "connectors": out,
                "file_problems": [p.as_dict() for p in file_problems] + [
                    p.as_dict() for p in check_document(doc, reg.manifests, default_mode=dmode, check_env=False)
                    if p.where.split(".")[0] not in attributed],
                "pending": [version_dict(v) for v in self.pending()]}


def _summary(res: dict[str, Any]) -> dict[str, Any]:
    return {k: res.get(k) for k in ("verdict", "ok", "errors", "warnings", "ran_at", "fingerprint", "stage",
                                    "duration_ms")}


def version_dict(v: ConnectorConfigVersion) -> dict[str, Any]:
    return {"id": v.id, "kind": v.kind, "status": v.status, "proposed_by": v.proposed_by, "approved_by": v.approved_by,
            "note": v.note, "changes": v.changes or [], "preflight": v.preflight or {}, "base_version": v.base_version,
            "created_at": v.created_at.isoformat() if v.created_at else None,
            "decided_at": v.decided_at.isoformat() if v.decided_at else None}


# ---------------------------------------------------------------------------------------------- start-up check


def startup_problems(path: str | Path | None = None) -> list[Problem]:
    """Errors in the configuration file that should stop a server or scheduler from starting (typos, unknown tools
    or keys, bad YAML). Missing secrets are not among them: that tool is isolated and shown, the rest start."""
    doc, problems = load_file(path)
    return problems + check_document(doc, manifests(), default_mode=default_mode(), check_env=False)
