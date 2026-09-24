"""
Unicode deception detection for phishing \u2014 homoglyphs, zero-width characters,
and mixed-script / punycode domain spoofing.

Why this exists (grounded in real gaps):
- ``url_agent._brand_impersonation_indicator`` checks ``brand not in host`` on the
  raw string, so a Cyrillic look-alike like ``p\u0430ypal.com`` (the second character is
  U+0430 CYRILLIC SMALL LETTER A) contains no ASCII ``paypal`` substring and is
  missed entirely.
- ``header_agent`` uses Levenshtein distance ``<= 2`` against trusted domains, so a
  domain built from 3+ homoglyph substitutions is visually identical to a brand yet
  exceeds the edit-distance threshold and escapes.

This module is **dependency-free** (standard-library ``unicodedata`` only). The
confusables table is a *curated subset* covering the scripts most abused in real
homograph attacks (Cyrillic, Greek, fullwidth/Latin variants) \u2014 it is deliberately
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
    "\u0430": "a",  # <U+0430> CYRILLIC SMALL LETTER A
    "\u0435": "e",  # <U+0435> CYRILLIC SMALL LETTER IE
    "\u043e": "o",  # <U+043E> CYRILLIC SMALL LETTER O
    "\u0440": "p",  # <U+0440> CYRILLIC SMALL LETTER ER
    "\u0441": "c",  # <U+0441> CYRILLIC SMALL LETTER ES
    "\u0445": "x",  # <U+0445> CYRILLIC SMALL LETTER HA
    "\u0443": "y",  # <U+0443> CYRILLIC SMALL LETTER U
    "\u0455": "s",  # <U+0455> CYRILLIC SMALL LETTER DZE
    "\u0456": "i",  # <U+0456> CYRILLIC SMALL LETTER BYELORUSSIAN-UKRAINIAN I
    "\u0458": "j",  # <U+0458> CYRILLIC SMALL LETTER JE
    "\u04bb": "h",  # <U+04BB> CYRILLIC SMALL LETTER SHHA
    "\u0501": "d",  # <U+0501> CYRILLIC SMALL LETTER KOMI DE
    "\u051b": "q",  # <U+051B> CYRILLIC SMALL LETTER QA
    "\u0261": "g",  # <U+0261> LATIN SMALL LETTER SCRIPT G
    # Cyrillic uppercase look-alikes
    "\u0410": "A", "\u0412": "B", "\u0415": "E", "\u041a": "K", "\u041c": "M",
    "\u041d": "H", "\u041e": "O", "\u0420": "P", "\u0421": "C", "\u0422": "T",
    "\u0425": "X", "\u0406": "I", "\u0408": "J", "\u0405": "S",
    # Greek look-alikes
    "\u03bf": "o",  # <U+03BF> GREEK SMALL LETTER OMICRON
    "\u03b1": "a",  # <U+03B1> GREEK SMALL LETTER ALPHA
    "\u03c1": "p",  # <U+03C1> GREEK SMALL LETTER RHO
    "\u03b5": "e",  # <U+03B5> GREEK SMALL LETTER EPSILON
    "\u03bd": "v",  # <U+03BD> GREEK SMALL LETTER NU
    "\u0391": "A", "\u0392": "B", "\u0395": "E", "\u0396": "Z", "\u0397": "H",
    "\u0399": "I", "\u039a": "K", "\u039c": "M", "\u039d": "N", "\u039f": "O",
    "\u03a1": "P", "\u03a4": "T", "\u03a7": "X", "\u03a5": "Y",
    # Latin-1 / extended accented forms commonly used to dress up brands
    "\u0131": "i",  # <U+0131> LATIN SMALL LETTER DOTLESS I
    "\u04cf": "l",  # <U+04CF> CYRILLIC SMALL LETTER PALOCHKA
}

# Zero-width and bidirectional control characters. These are invisible and are used
# to break up brand keywords (``pay<U+200B>pal``) or visually reorder text.
_ZERO_WIDTH: dict[str, str] = {
    "\u200b": "ZERO WIDTH SPACE",
    "\u200c": "ZERO WIDTH NON-JOINER",
    "\u200d": "ZERO WIDTH JOINER",
    "\u2060": "WORD JOINER",
    "\ufeff": "ZERO WIDTH NO-BREAK SPACE",
    "\u00ad": "SOFT HYPHEN",
    "\u200e": "LEFT-TO-RIGHT MARK",
    "\u200f": "RIGHT-TO-LEFT MARK",
    "\u202a": "LEFT-TO-RIGHT EMBEDDING",
    "\u202b": "RIGHT-TO-LEFT EMBEDDING",
    "\u202c": "POP DIRECTIONAL FORMATTING",
    "\u202d": "LEFT-TO-RIGHT OVERRIDE",
    "\u202e": "RIGHT-TO-LEFT OVERRIDE",
    "\u2066": "LEFT-TO-RIGHT ISOLATE",
    "\u2067": "RIGHT-TO-LEFT ISOLATE",
    "\u2068": "FIRST STRONG ISOLATE",
    "\u2069": "POP DIRECTIONAL ISOLATE",
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

    ``skeleton("p\u0430ypal.com")`` -> ``"paypal.com"`` (Cyrillic '\u0430' folded to 'a').
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
    """True if a single token mixes scripts (e.g. Latin + Cyrillic) \u2014 a strong
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
    directly from the input characters \u2014 nothing is inferred or fabricated.
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
