"""Tolerance for malformed vendor records: every field is brought to the shape the vendor normally sends.

A vendor API occasionally sends a field in an unexpected type - an object as a string, a list as a single object, a
number where text is expected, ``"N/A"`` where a list should be. Parsers written for the documented shape then
crashed (``'str' object has no attribute 'get'``), and the whole record - a sign-in, a host, an alert - was set aside
because of one field the analysis may not even use. A fuzz of every parser with wrong-typed fields found 715 such
crashes across 26 of the 27 streams.

Each connector's fake-mode fixtures already show the documented shape of every stream. Before a record is parsed,
``conform`` walks it against that shape (learned once per stream from the fixtures, in live mode too):

* object expected, something else found  -> an empty object (a list holding one object -> that object)
* list expected, a single object found   -> a list of that object; a scalar -> an empty list; list members of the
  wrong type are dropped
* text expected, a number or boolean     -> the same value as text (numeric ids keep working)
* number expected, numeric text          -> the number; anything else -> empty
* boolean expected, "true" / "false" / 0 / 1 -> the boolean; anything else -> empty

Fields the shape does not know are passed through untouched; a record that already matches is returned as is.
Every coercion is counted per field path (never with the value) and reported once per sync as a data-quality line,
so a vendor change is visible instead of silently absorbed.
"""

from __future__ import annotations

import logging
import threading
from collections import Counter
from typing import Any

log = logging.getLogger(__name__)
_LOCK = threading.Lock()
_SHAPES: dict[tuple[str, str], dict[str, Any] | None] = {}
_MAX_DEPTH = 8


def shape_of(value: Any, depth: int = 0) -> dict[str, Any]:
    if depth > _MAX_DEPTH:
        return {"t": "any"}
    if isinstance(value, dict):
        return {"t": "dict", "k": {str(k): shape_of(v, depth + 1) for k, v in value.items()}}
    if isinstance(value, list):
        el: dict[str, Any] | None = None
        for x in value[:50]:
            el = merge(el, shape_of(x, depth + 1))
        return {"t": "list", "e": el}
    if isinstance(value, bool):
        return {"t": "bool"}
    if isinstance(value, (int, float)):
        return {"t": "num"}
    if isinstance(value, str):
        return {"t": "str"}
    return {"t": "null"}


def merge(a: dict[str, Any] | None, b: dict[str, Any] | None) -> dict[str, Any] | None:
    if a is None:
        return b
    if b is None:
        return a
    if a["t"] == "null":
        return b
    if b["t"] == "null":
        return a
    if a["t"] != b["t"]:
        return {"t": "any"}                       # the vendor itself varies: do not constrain
    if a["t"] == "dict":
        keys = set(a["k"]) | set(b["k"])
        return {"t": "dict", "k": {k: merge(a["k"].get(k), b["k"].get(k)) or {"t": "null"} for k in keys}}
    if a["t"] == "list":
        return {"t": "list", "e": merge(a.get("e"), b.get("e"))}
    return a


def shape_for(connector: Any, stream: str) -> dict[str, Any] | None:
    """The documented shape of a stream's records, learned once from the connector's fixtures (None if unknown)."""
    manifest = getattr(connector, "_manifest", None)
    if manifest is None:
        return None
    key = (manifest.name, stream)
    with _LOCK:
        if key in _SHAPES:
            return _SHAPES[key]
    shape: dict[str, Any] | None = None
    try:
        sample = manifest.factory(dict(manifest.fake_settings), manifest.fixture_transport())
        for rec in sample.fetch_page(stream, None).records:
            if isinstance(rec, dict):
                shape = merge(shape, shape_of(rec))
    except Exception:  # no fixtures for this stream (or they cannot be read): records are parsed as they come
        log.debug("no documented shape for %s.%s", *key, exc_info=True)
        shape = None
    with _LOCK:
        _SHAPES[key] = shape
    return shape


def reset_shapes() -> None:
    """Forget learned shapes (tests switch sample estates)."""
    with _LOCK:
        _SHAPES.clear()


def conform(value: Any, shape: dict[str, Any] | None, notes: Counter | None = None, path: str = "") -> Any:
    if shape is None or value is None:
        return value
    t = shape["t"]
    if t in ("any", "null"):
        return value

    def note(expected: str) -> None:
        if notes is not None:
            notes[f"{path or '(record)'}: expected {expected}"] += 1

    if t == "dict":
        if isinstance(value, list) and len(value) == 1 and isinstance(value[0], dict):
            note("an object (got a list of one)")
            value = value[0]
        if not isinstance(value, dict):
            note("an object")
            return {}
        out = value
        for k, sub in shape["k"].items():
            if k in value:
                new = conform(value[k], sub, notes, f"{path}.{k}" if path else k)
                if new is not value[k]:
                    if out is value:
                        out = dict(value)     # copy on first change: a record that already conforms is untouched
                    out[k] = new
        return out
    if t == "list":
        if isinstance(value, dict):
            note("a list (got one object)")
            value = [value]
        if not isinstance(value, list):
            note("a list")
            return []
        el = shape.get("e")
        if el is None:
            return value
        kept = []
        changed = False
        for i, x in enumerate(value):
            if el["t"] == "dict" and not isinstance(x, dict) and x is not None:
                note("a list of objects")
                changed = True
                continue
            new = conform(x, el, notes, f"{path}[]")
            changed = changed or new is not x
            kept.append(new)
            if i > 10_000:                    # pathological lists are not walked forever
                kept.extend(value[i + 1:])
                break
        return kept if changed else value
    if t == "str":
        if isinstance(value, str):
            return value
        if isinstance(value, (int, float)):   # numeric ids and codes as text, without a note: vendors mix them
            return str(value)
        note("text")
        return None
    if t == "num":
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return value
        if isinstance(value, str):
            try:
                n = float(value.strip())
                return int(n) if n.is_integer() and "." not in value else n
            except ValueError:
                pass
        note("a number")
        return None
    if t == "bool":
        if isinstance(value, bool):
            return value
        s = str(value).strip().lower()
        if s in ("true", "1", "yes"):
            return True
        if s in ("false", "0", "no"):
            return False
        note("true or false")
        return None
    return value
