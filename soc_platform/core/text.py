"""Text that people read: evidence summaries written by connectors, made plain before they are stored."""

from __future__ import annotations

import re

_LIST = re.compile(r"\[((?:'[^'\[\]]{0,200}'|\"[^\"\[\]]{0,200}\"|None|-?\d+(?:\.\d+)?)(?:,\s{0,3}(?:'[^'\[\]]{0,200}'|\"[^\"\[\]]{0,200}\"|None|-?\d+(?:\.\d+)?)){0,50})\]")


def readable(text: str) -> str:
    """Evidence is read by analysts (and given to the model): a connector's Python rendering of a list or a missing
    value - ``['Low', 'High']``, ``[]``, ``signer=None`` - becomes plain words. Bounded patterns (linear on any input)."""
    if not text or ("[" not in text and "None" not in text):
        return text

    def items(m: re.Match) -> str:
        vals = [v.strip().strip("'\"") for v in re.findall(r"'[^']*'|\"[^\"]*\"|None|-?\d+(?:\.\d+)?", m.group(0))]
        vals = [v for v in vals if v and v != "None"]
        return ", ".join(vals) if vals else "none"

    out = _LIST.sub(items, text)
    out = re.sub(r"\[\]", "none", out)
    return re.sub(r"(?<=[=:(] )None\b|(?<=[=:(])None\b", "unknown", out)
