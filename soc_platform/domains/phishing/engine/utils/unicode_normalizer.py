"""
Unicode deception detection for phishing — homoglyphs, zero-width characters,
and mixed-script / punycode domain spoofing.

Why this exists (grounded in real gaps):
- ``url_agent._brand_impersonation_indicator`` checks ``brand not in host`` on the
  raw string, so a Cyrillic look-alike like ``pаypal.com`` (the second character is
  U+0430 CYRILLIC SMALL LETTER A) contains no ASCII ``paypal`` substring and is
  missed entirely.
- ``header_agent`` uses Levenshtein distance ``<= 2`` against trusted domains, so a
  domain built from 3+ homoglyph substitutions is visually identical to a brand yet
  exceeds the edit-distance threshold and escapes.

This module is **dependency-free** (standard-library ``unicodedata`` only). The
confusables table is a *curated subset* covering the scripts most abused in real
homograph attacks (Cyrillic, Greek, fullwidth/Latin variants) — it is deliberately
not the full Unicode confusables database, and every mapping here is a real,
verifiable look-alike. Detection is conservative: it only fires on genuinely
non-ASCII or invisible characters, so pure-ASCII input is never affected.
"""

from __future__ import annotations

import unicodedata
from typing import Any

# ---------------------------------------------------------------------------
# Curated confusable map: look-alike codepoint -> intended ASCII character.
# Each entry is a real visual confusable abused in IDN homograph phishing.
# ---------------------------------------------------------------------------
_CONFUSABLES: dict[str, str] = {
    # Cyrillic lowercase look-alikes
    "а": "a",  # а CYRILLIC SMALL LETTER A
    "е": "e",  # е CYRILLIC SMALL LETTER IE
    "о": "o",  # о CYRILLIC SMALL LETTER O
    "р": "p",  # р CYRILLIC SMALL LETTER ER
    "с": "c",  # с CYRILLIC SMALL LETTER ES
    "х": "x",  # х CYRILLIC SMALL LETTER HA
    "у": "y",  # у CYRILLIC SMALL LETTER U
    "ѕ": "s",  # ѕ CYRILLIC SMALL LETTER DZE
    "і": "i",  # і CYRILLIC SMALL LETTER BYELORUSSIAN-UKRAINIAN I
    "ј": "j",  # ј CYRILLIC SMALL LETTER JE
    "һ": "h",  # һ CYRILLIC SMALL LETTER SHHA
    "ԁ": "d",  # ԁ CYRILLIC SMALL LETTER KOMI DE
    "ԛ": "q",  # ԛ CYRILLIC SMALL LETTER QA
    "ɡ": "g",  # ɡ LATIN SMALL LETTER SCRIPT G
    # Cyrillic uppercase look-alikes
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M",
    "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T",
    "Х": "X", "І": "I", "Ј": "J", "Ѕ": "S",
    # Greek look-alikes
    "ο": "o",  # ο GREEK SMALL LETTER OMICRON
    "α": "a",  # α GREEK SMALL LETTER ALPHA
    "ρ": "p",  # ρ GREEK SMALL LETTER RHO
    "ε": "e",  # ε GREEK SMALL LETTER EPSILON
    "ν": "v",  # ν GREEK SMALL LETTER NU
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H",
    "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O",
    "Ρ": "P", "Τ": "T", "Χ": "X", "Υ": "Y",
    # Latin-1 / extended accented forms commonly used to dress up brands
    "ı": "i",  # ı LATIN SMALL LETTER DOTLESS I
    "ӏ": "l",  # ӏ CYRILLIC SMALL LETTER PALOCHKA
}

# Zero-width and bidirectional control characters. These are invisible and are used
# to break up brand keywords (``pay​pal``) or visually reorder text.
_ZERO_WIDTH: dict[str, str] = {
    "​": "ZERO WIDTH SPACE",
    "‌": "ZERO WIDTH NON-JOINER",
    "‍": "ZERO WIDTH JOINER",
    "⁠": "WORD JOINER",
    "﻿": "ZERO WIDTH NO-BREAK SPACE",
    "­": "SOFT HYPHEN",
    "‎": "LEFT-TO-RIGHT MARK",
    "‏": "RIGHT-TO-LEFT MARK",
    "‪": "LEFT-TO-RIGHT EMBEDDING",
    "‫": "RIGHT-TO-LEFT EMBEDDING",
    "‬": "POP DIRECTIONAL FORMATTING",
    "‭": "LEFT-TO-RIGHT OVERRIDE",
    "‮": "RIGHT-TO-LEFT OVERRIDE",
    "⁦": "LEFT-TO-RIGHT ISOLATE",
    "⁧": "RIGHT-TO-LEFT ISOLATE",
    "⁨": "FIRST STRONG ISOLATE",
    "⁩": "POP DIRECTIONAL ISOLATE",
}


def strip_zero_width(text: str) -> str:
    """Remove zero-width / bidi control characters."""
    return "".join(ch for ch in (text or "") if ch not in _ZERO_WIDTH)


def find_zero_width(text: str) -> list[str]:
    """Return the human-readable names of any zero-width/bidi chars present."""
    seen: list[str] = []
    for ch in text or "":
        name = _ZERO_WIDTH.get(ch)
        if name and name not in seen:
            seen.append(name)
    return seen


def skeleton(text: str) -> str:
    """
    Map a string to its ASCII "skeleton" by replacing known confusable characters
    with their intended ASCII look-alike and dropping invisible characters.

    ``skeleton("pаypal.com")`` -> ``"paypal.com"`` (Cyrillic 'а' folded to 'a').
    Pure-ASCII input is returned unchanged.
    """
    cleaned = strip_zero_width(text or "")
    return "".join(_CONFUSABLES.get(ch, ch) for ch in cleaned)


def _script_of(ch: str) -> str | None:
    """Best-effort script name for a letter, derived from its Unicode name.

    This is an approximation (Python's stdlib does not expose the Script property
    directly) but is reliable for the Latin/Cyrillic/Greek scripts that dominate
    homograph attacks. Non-letters and unnamed characters return ``None``.
    """
    if not ch.isalpha():
        return None
    try:
        name = unicodedata.name(ch)
    except ValueError:
        return None
    first = name.split(" ", 1)[0]
    if first in {"LATIN", "CYRILLIC", "GREEK", "ARMENIAN", "HEBREW", "ARABIC"}:
        return first
    if first == "FULLWIDTH":
        return "FULLWIDTH"
    return "OTHER"


def scripts_used(text: str) -> set[str]:
    """Return the set of letter-scripts present in ``text``."""
    return {s for ch in (text or "") if (s := _script_of(ch)) is not None}


def is_mixed_script(text: str) -> bool:
    """True if a single token mixes scripts (e.g. Latin + Cyrillic) — a strong
    IDN-homograph signal that almost never occurs in legitimate domains."""
    return len(scripts_used(text)) > 1


def is_punycode(host: str) -> bool:
    """True if any label of the host is IDNA/punycode (``xn--``)."""
    return any(label.startswith("xn--") for label in (host or "").lower().split("."))


def has_non_ascii(text: str) -> bool:
    return any(ord(ch) > 127 for ch in text or "")


def analyze_text(text: str) -> dict[str, Any]:
    """
    Inspect arbitrary text (a hostname, URL, or domain) for Unicode deception.

    Returns a structured, faithful report. ``skeleton`` is the folded ASCII form;
    callers compare it against known brands. Everything reported is derived
    directly from the input characters — nothing is inferred or fabricated.
    """
    raw = text or ""
    folded = skeleton(raw)
    zero_width = find_zero_width(raw)
    scripts = scripts_used(strip_zero_width(raw))
    return {
        "raw": raw,
        "skeleton": folded,
        "changed": folded != raw,
        "has_confusables": folded != strip_zero_width(raw),
        "zero_width": zero_width,
        "has_zero_width": bool(zero_width),
        "scripts": sorted(scripts),
        "mixed_script": len(scripts) > 1,
        "punycode": is_punycode(raw),
    }
