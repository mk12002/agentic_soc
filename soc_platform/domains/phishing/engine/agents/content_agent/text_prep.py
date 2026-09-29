"""Text preparation for the content model - used identically in training and at inference (no train/serve skew).

The model sees words, not markup: HTML is reduced to its visible text, and the things that differ between datasets
and eras without saying anything about intent (links, addresses, numbers, dates) become neutral tokens. The whole
message is used (up to ``MAX_CHARS``), not only its first hundred words.
"""

from __future__ import annotations

import html as _html
import re

MAX_CHARS = 20000

_SCRIPT_STYLE = re.compile(r"<(script|style|head)\b[^<>]*>(?:(?!<\1\b).)*?</\1>", re.IGNORECASE | re.DOTALL)
_TAG = re.compile(r"<[^<>]*>")   # stops at the next "<": linear on hostile markup
_URL = re.compile(r"(?:https?://|www\.)\S+", re.IGNORECASE)
_EMAIL = re.compile(r"(?<![\w.+-])[\w.+-]{1,64}@[\w-]{1,63}(?:\.[\w-]{1,63}){1,8}\b")   # bounded: linear
_NUM = re.compile(r"\b\d[\d,./:-]*\b")
_SPACE = re.compile(r"\s+")


def visible_text(text: str) -> str:
    """HTML to the words a reader sees (scripts, styles and tags removed, entities decoded)."""
    # only a bounded prefix is ever used, and an unclosed <script> is otherwise searched to the end from every tag
    t = _SCRIPT_STYLE.sub(" ", str(text or "")[:MAX_CHARS * 10])
    t = _TAG.sub(" ", t)
    return _html.unescape(t)


def normalize(text: str) -> str:
    """The vectoriser's preprocessor: visible text, lower case, links / addresses / numbers as tokens."""
    t = visible_text(text)[:MAX_CHARS].lower()
    t = _URL.sub(" urltoken ", t)
    t = _EMAIL.sub(" emailtoken ", t)
    t = _NUM.sub(" numtoken ", t)
    return _SPACE.sub(" ", t).strip()
