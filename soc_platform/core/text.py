"""Text that people read: evidence summaries written by connectors, made plain before they are stored."""

from __future__ import annotations

import re

_LIST = re.compile(r"\[((?:'[^'\[\]]{0,200}'|\"[^\"\[\]]{0,200}\"|None|-?\d+(?:\.\d+)?)(?:,\s{0,3}(?:'[^'\[\]]{0,200}'|\"[^\"\[\]]{0,200}\"|None|-?\d+(?:\.\d+)?)){0,50})\]")


def readable(text: str) -> str:
    """Evidence is read by analysts (and given to the model): a connector's Python rendering of a list or a missing
    value - ``['Low', 'High']``, ``[]``, ``signer=None``, ``exposed=True`` - becomes plain words. Bounded patterns
    (linear on any input)."""
    if not text or not any(x in text for x in ("[", "None", "True", "False")):
        return text

    def items(m: re.Match) -> str:
        vals = [v.strip().strip("'\"") for v in re.findall(r"'[^']*'|\"[^\"]*\"|None|-?\d+(?:\.\d+)?", m.group(0))]
        vals = [v for v in vals if v and v != "None"]
        return ", ".join(vals) if vals else "none"

    out = _LIST.sub(items, text)
    out = re.sub(r"\[\]", "none", out)
    out = re.sub(r"(?<=[=:(] )None\b|(?<=[=:(])None\b", "unknown", out)
    # a flag printed as Python prints it ("standing admin role: False", "internet-exposed=True")
    return re.sub(r"(?<=[=:] )(?:True|False)\b|(?<=[=:])(?:True|False)\b",
                  lambda m: "yes" if m.group(0) == "True" else "no", out)


def unsafe_xml(raw: bytes) -> bool:
    """True when an uploaded XML part (an .xlsx / .docx / .pptx part) must not be parsed: it declares a document type
    or an entity (XXE, entity expansion), or it is in a multi-byte encoding (UTF-16 / UTF-32), where those
    declarations would not show as plain bytes. Office writes its parts in UTF-8, so nothing real is refused."""
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff") or b"\x00" in raw:
        return True
    return b"<!DOCTYPE" in raw or b"<!ENTITY" in raw
