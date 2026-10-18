"""Personal-data minimisation before LLM calls (PH-T06, NFR-10, R10).

Internal people are pseudonymised with stable tokens (``<USER_1>``) that are
restored in the model output; external/attacker indicators (sender domains,
URLs, hashes, public IP addresses) are left intact because they *are* the evidence.

Internal is: an address in an organisation domain, a ``DOMAIN\\user`` account, a host name under an organisation
domain (``jane-lt01.corp.example.com``), an internal IP address (RFC 1918, carrier-grade NAT, link-local) and the
known display names / host names a caller passes. Each of them identifies a person or their device.
"""

from __future__ import annotations

import ipaddress
import re
import secrets
from dataclasses import dataclass, field

# Bounded to RFC 5321 lengths and anchored to the start of a run: with an unbounded local part, text such as
# "1.1.1.1..." (no "@") was rescanned to its end from every position - 200 KB of it took ~95 s (ReDoS).
EMAIL_RE = re.compile(r"(?<![A-Za-z0-9._%+-])([A-Za-z0-9._%+-]{1,64})@([A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,24})\b")
PHONE_RE = re.compile(r"(?<![\w.])\+?\d[\d\s()-]{7,16}\d(?![\w.])")
CARD_RE = re.compile(r"\b(?:\d[ -]?){13,16}\b")
PAN_RE = re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b")          # Indian PAN
AADHAAR_RE = re.compile(r"\b\d{4}\s?\d{4}\s?\d{4}\b")    # Indian Aadhaar
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# NETBIOS-DOMAIN\account (bounded runs: linear on hostile input)
DOWNLEVEL_RE = re.compile(r"(?<![\w\\])([A-Za-z][A-Za-z0-9-]{0,14})\\([A-Za-z0-9._$-]{1,64})\b")
INTERNAL_NETS = tuple(ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16"))


def _internal_ip(text: str) -> bool:
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return False
    return any(ip in n for n in INTERNAL_NETS)


@dataclass
class Redactor:
    internal_domains: set[str] = field(default_factory=set)
    known_names: set[str] = field(default_factory=set)  # internal display names to pseudonymise
    known_hosts: set[str] = field(default_factory=set)  # internal host names without a domain (laptop names)
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
        out = DOWNLEVEL_RE.sub(lambda m: self._token("USER", m.group(0)), out)
        if self.internal_domains:
            # host names inside the organisation's domains (an e-mail address was already replaced above)
            alt = "|".join(re.escape(d) for d in sorted(self.internal_domains, key=len, reverse=True) if d)
            host_re = re.compile(r"(?<![\w.@-])((?:[A-Za-z0-9-]{1,63}\.){1,8}(?:" + alt + r"))\b", re.IGNORECASE)
            out = host_re.sub(lambda m: self._token("HOST", m.group(1)), out)
        # Public IPs are indicators (evidence): shield them before any number pattern runs, so a card, id or phone
        # pattern can never swallow an octet. Internal IPs identify a person's device: pseudonymised. The marker
        # carries a random tag in private-use characters, so text in a hostile e-mail can never pass for one.
        ips: list[str] = []
        tag = secrets.token_hex(4)
        out = IP_RE.sub(lambda m: self._token("IP", m.group(0)) if _internal_ip(m.group(0))
                        else (ips.append(m.group(0)), f"\ue000{tag}:{len(ips) - 1}\ue001")[1], out)
        for name in sorted(self.known_names, key=len, reverse=True):
            if name and len(name) > 3:
                out = re.sub(re.escape(name), lambda m: self._token("PERSON", m.group(0)), out, flags=re.IGNORECASE)
        for host in sorted(self.known_hosts, key=len, reverse=True):
            if host and len(host) > 3:
                out = re.sub(r"(?<![\w-])" + re.escape(host) + r"(?![\w-])", lambda m: self._token("HOST", m.group(0)),
                             out, flags=re.IGNORECASE)
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
