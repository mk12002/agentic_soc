"""Model names read as a *line* and a *version*, so the platform follows a line instead of pinning a version.

Providers publish new versions of a model under new names, written in many styles::

    GPT 6.1 Sol  ->  GPT 6.2 Sol               (display names: family, version, variant)
    gpt-4.1-mini ->  gpt-5.1-mini              (API ids)
    claude-sonnet-4-5-20250929                 (version as separate numbers, then a dated snapshot)
    anthropic/claude-sonnet-4.5                (a router's vendor prefix)

``parse`` strips the version (and a snapshot date) out of the name; what is left - the words, in order - is the line.
``GPT 6.1 Sol`` and ``GPT 6.2 Sol`` are one line (``gpt sol``) at versions 6.1 and 6.2; ``GPT 6.2 Astra`` is another
line, and so is ``gpt-4.1-mini`` (``gpt mini``) against ``gpt-4.1`` (``gpt``): a variant or a size word changes what
the model is, so it is never an upgrade. A name with no version (``Auto``, an alias such as ``...-latest``) has no
newer version to follow.

The first number is the *generation* (``6`` in ``6.2``). A newer version in the same generation is adopted
automatically (after the platform's own check); a new generation is offered for an administrator's approval - cost
and behaviour can change a lot between generations.

Pure functions: no settings, no database, no network.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

PREVIEW_WORDS = frozenset({"preview", "exp", "experimental", "beta", "alpha", "rc", "test", "dev", "canary"})
ALIAS_WORDS = frozenset({"latest", "auto", "default", "stable"})
_SPLIT = re.compile(r"[\s\-_/:]+")
_NUM = re.compile(r"^\d{1,4}(?:\.\d{1,4}){0,3}$")
_DATE8 = re.compile(r"^(19|20)\d{6}$")          # 20250929
_YYMM = re.compile(r"^(2[3-9]|3\d)(0[1-9]|1[0-2])$")   # 2411: a year-month release name, not version 2411
_NUM_WORD = re.compile(r"^(\d{1,4}(?:\.\d{1,4}){0,3})([a-z]{1,12})$")   # 4o, 3.5turbo
_WORD_NUM = re.compile(r"^([a-z]{1,2})(\d{1,4}(?:\.\d{1,4}){0,3})$")    # o3, o4 (a letter or two, then the version)


@dataclass(frozen=True)
class ModelName:
    name: str                       # as the provider writes it (what is sent in a call)
    line: str                       # the words without the version: "gpt sol"
    version: tuple[int, ...] | None  # (6, 2); None when the name carries no version
    snapshot: str = ""              # a dated build, "20250929": newer snapshots of one version rank higher
    preview: bool = False           # preview / experimental builds are never adopted automatically
    alias: bool = False             # "latest" / "auto": the provider decides - not a version to follow

    @property
    def generation(self) -> int | None:
        return self.version[0] if self.version else None

    @property
    def version_text(self) -> str:
        return ".".join(str(x) for x in self.version) if self.version else ""

    def rank(self) -> tuple[tuple[int, ...], str]:
        """Ordering within a line: the version (6 < 6.1 < 6.2 < 7), then the snapshot date."""
        v = self.version or ()
        return tuple(list(v) + [0] * (4 - len(v))), self.snapshot


def parse(name: str) -> ModelName:
    raw = (name or "").strip()
    tokens = [t for t in _SPLIT.split(raw.lower()) if t]
    words: list[str] = []
    numbers: list[str] = []
    snapshot = ""
    preview = alias = False
    for i, t in enumerate(tokens):
        if not t:                           # consumed by a date written in three parts
            continue
        if _DATE8.match(t) or (_YYMM.match(t) and words and not numbers):
            snapshot = t                    # 20250929, or a year-month release such as mistral-large-2411
            continue
        # a date written 2024-08-06 arrives as three tokens: keep it as one snapshot, not version numbers
        if (re.fullmatch(r"(19|20)\d{2}", t) and i + 2 < len(tokens) and re.fullmatch(r"\d{2}", tokens[i + 1])
                and re.fullmatch(r"\d{2}", tokens[i + 2]) and numbers):
            snapshot = t + tokens[i + 1] + tokens[i + 2]
            tokens[i + 1] = tokens[i + 2] = ""
            continue
        if t in PREVIEW_WORDS:
            preview = True
            continue
        if t in ALIAS_WORDS:
            alias = True
            words.append(t)
            continue
        if _NUM.match(t):
            if not words and not numbers:   # a name that starts with a number keeps it as a word
                words.append(t)
            elif not numbers:
                numbers.append(t)
            elif "." not in "".join(numbers) and "." not in t and len(t) <= 2 and len(numbers) < 4:
                numbers.append(t)           # "claude-sonnet-4-5": 4 then 5 is version 4.5
            else:
                words.append(t)             # a second, separate number is part of the name
            continue
        m = _NUM_WORD.match(t)
        if m and not numbers:               # "4o": version 4, variant word "o"
            numbers.append(m.group(1))
            words.append(m.group(2))
            continue
        m = _WORD_NUM.match(t)
        if m and not numbers and t not in {"v1", "v2"}:    # "o3": variant word "o", version 3
            words.append(m.group(1))
            numbers.append(m.group(2))
            continue
        words.append(t)
    version: tuple[int, ...] | None = None
    if numbers and not alias:
        parts: list[int] = []
        for n in numbers:                   # "4", "5" -> 4.5 ; "6.2" -> 6.2
            parts += [int(x) for x in n.split(".")]
        version = tuple(parts[:4])
    elif snapshot and not alias:
        version = ()                        # dated releases only: ordered by their date, one generation
    line = " ".join(words) or raw.lower()
    return ModelName(name=raw, line=line, version=version, snapshot=snapshot, preview=preview, alias=alias)


def newest(candidates: list[str], current: str, *, allow_preview: bool = False) -> tuple[str | None, str | None]:
    """The newest version of ``current``'s line among ``candidates``: ``(same_generation, next_generation)``.

    ``same_generation`` is what may be adopted on its own; ``next_generation`` is the newest in a later generation,
    which waits for an administrator. Each is None when nothing newer exists. Ties are broken by name, so the answer
    never depends on the order a provider lists its models in.
    """
    cur = parse(current)
    if cur.version is None or cur.alias:
        return None, None
    same: list[ModelName] = []
    later: list[ModelName] = []
    for c in candidates:
        m = parse(c)
        if m.line != cur.line or m.version is None or m.alias or (m.preview and not allow_preview):
            continue
        if m.rank() <= cur.rank():
            continue
        (same if m.generation == cur.generation else later if (m.generation or 0) > (cur.generation or 0) else []).append(m)

    def best(xs: list[ModelName]) -> str | None:
        return max(xs, key=lambda m: (m.rank(), m.name)).name if xs else None
    return best(same), best(later)
