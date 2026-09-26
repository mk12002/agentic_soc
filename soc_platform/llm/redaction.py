"""Personal-data minimisation before LLM calls (PH-T06, NFR-10, R10).

Internal people are pseudonymised with stable tokens (``<USER_1>``) that are
restored in the model output; external/attacker indicators (sender domains,
URLs, hashes) are left intact because they *are* the evidence.
"""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass, field

EMAIL_RE = re.compile(r"\b([A-Za-z0-9._%+-]+)@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")
PHONE_RE = re.compile(r"(?<![\w.])\+?\d[\d\s()-]{7,16}\d(?![\w.])")
CARD_RE = re.compile(r"\b(?:\d[ -]?){13,16}\b")
PAN_RE = re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b")          # Indian PAN
AADHAAR_RE = re.compile(r"\b\d{4}\s?\d{4}\s?\d{4}\b")    # Indian Aadhaar
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


@dataclass
class Redactor:
    internal_domains: set[str] = field(default_factory=set)
    known_names: set[str] = field(default_factory=set)  # internal display names to pseudonymise
    mapping: dict[str, str] = field(default_factory=dict)
    _counters: dict[str, int] = field(default_factory=dict)

    def _token(self, kind: str, original: str) -> str:
        for tok, orig in self.mapping.items():
            if orig == original:
                return tok
        self._counters[kind] = self._counters.get(kind, 0) + 1
        tok = f"<{kind}_{self._counters[kind]}>"
        self.mapping[tok] = original
        return tok

    def _is_internal(self, domain: str) -> bool:
        d = domain.lower()
        return any(d == i or d.endswith("." + i) for i in self.internal_domains)

    def redact(self, text: str) -> str:
        if not text:
            return text

        def _email(m: re.Match) -> str:
            return self._token("USER", m.group(0)) if self._is_internal(m.group(2)) else m.group(0)

        out = EMAIL_RE.sub(_email, text)
        # IPs are indicators (evidence), never personal data: shield them before any number pattern runs, so a card,
        # id or phone pattern can never swallow an octet. The marker carries a random tag in private-use
        # characters, so text in a hostile e-mail can never pass for one.
        ips: list[str] = []
        tag = secrets.token_hex(4)
        out = IP_RE.sub(lambda m: (ips.append(m.group(0)), f"\ue000{tag}:{len(ips) - 1}\ue001")[1], out)
        for name in sorted(self.known_names, key=len, reverse=True):
            if name and len(name) > 3:
                out = re.sub(re.escape(name), lambda m: self._token("PERSON", m.group(0)), out, flags=re.IGNORECASE)
        out = PAN_RE.sub(lambda m: self._token("ID", m.group(0)), out)
        # cards before the 12-digit national id: a spaced card number would otherwise be cut at 12 digits
        out = CARD_RE.sub(lambda m: self._token("CARD", m.group(0)) if _luhn(m.group(0)) else m.group(0), out)
        out = AADHAAR_RE.sub(lambda m: self._token("ID", m.group(0)), out)
        out = PHONE_RE.sub(lambda m: self._token("PHONE", m.group(0)) if 10 <= sum(c.isdigit() for c in m.group(0)) <= 13
                           else m.group(0), out)
        return re.sub("\ue000" + tag + r":(\d+)\ue001",
                      lambda m: ips[int(m.group(1))] if int(m.group(1)) < len(ips) else m.group(0), out)

    def restore(self, text: str) -> str:
        """Put the originals back. Models sometimes drop the brackets (``USER_1`` for ``<USER_1>``), so a token is
        matched with or without them - as a whole word, so ``USER_1`` never matches inside ``USER_10``."""
        if not self.mapping or not text:
            return text
        bare = {tok.strip("<>").upper(): orig for tok, orig in self.mapping.items()}
        rx = re.compile(r"<?\b(" + "|".join(re.escape(k) for k in sorted(bare, key=len, reverse=True)) + r")\b>?", re.IGNORECASE)
        return rx.sub(lambda m: bare[m.group(1).upper()], text)


def _luhn(s: str) -> bool:
    digits = [int(c) for c in s if c.isdigit()]
    if len(digits) < 13:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0
