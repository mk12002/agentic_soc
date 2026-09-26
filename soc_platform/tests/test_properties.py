"""Property-based fuzzing: rules that must hold for *every* input, checked against thousands of generated ones.

Redaction (what leaves for the LLM), the numeric-fidelity guardrail, vendor timestamp parsing, text bounding and the
e-mail decomposer.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from soc_platform.llm.redaction import Redactor, _luhn

FAST = settings(max_examples=400, deadline=None, suppress_health_check=[HealthCheck.too_slow])
ORG = "acme-demo.com"


def _luhn_complete(prefix: str) -> str:
    for d in "0123456789":
        if _luhn(prefix + d):
            return prefix + d
    raise AssertionError


internal_email = st.from_regex(r"[a-z]{1,8}\.[a-z]{1,8}@acme-demo\.com", fullmatch=True)
external_email = st.from_regex(r"[a-z]{1,8}@evil[a-z]{0,4}\.example", fullmatch=True)
ip = st.tuples(*[st.integers(0, 255)] * 4).map(lambda t: ".".join(map(str, t)))
card = st.from_regex(r"4[0-9]{14}", fullmatch=True).map(_luhn_complete)
spaced_card = card.map(lambda c: " ".join(c[i:i + 4] for i in range(0, 16, 4)))
word = st.from_regex(r"[A-Za-z]{1,10}", fullmatch=True)
piece = st.one_of(word, internal_email, external_email, ip, card, spaced_card,
                  st.sampled_from([",", ".", " - ", "\n", ":", "(", ")"]))
document = st.lists(piece, min_size=1, max_size=30).map(" ".join)


@FAST
@given(document)
def test_redaction_round_trips_exactly(text):
    r = Redactor(internal_domains={ORG})
    assert r.restore(r.redact(text)) == text


@FAST
@given(document)
def test_no_internal_identity_or_card_number_leaves(text):
    out = Redactor(internal_domains={ORG}).redact(text)
    assert not re.search(r"@acme-demo\.com", out)
    for m in re.finditer(r"(?:\d[ -]?){13,16}", out):
        assert not _luhn(m.group(0)), m.group(0)                                   # no valid card number, spaced or not
    assert not re.search(r"\b(\d{4} ){3}\d{4}\b", out)                              # not even a partly-masked one


@FAST
@given(document)
def test_attacker_indicators_are_kept_as_evidence(text):
    out = Redactor(internal_domains={ORG}).redact(text)
    for e in re.findall(r"[a-z]+@evil[a-z]*\.example", text):
        assert e in out
    for addr in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text):
        assert addr in out


@FAST
@given(st.text(max_size=400))
def test_redaction_never_crashes_on_arbitrary_text(text):
    r = Redactor(internal_domains={ORG}, known_names={"Jane Doe"})
    r.restore(r.redact(text))
    r.redact(text + "\x00IP7\x00" + text)                                          # marker-lookalikes in hostile mail


# ------------------------------------------------------------------------ numeric-fidelity guardrail
numbers = st.lists(st.integers(0, 10**6), min_size=1, max_size=6)


@FAST
@given(numbers)
def test_guardrail_accepts_statements_whose_figures_are_all_in_the_evidence(ns):
    from soc_platform.llm.gateway import unsupported_numbers

    evidence = "Counts: " + ", ".join(str(n) for n in ns)
    statement = "The data shows " + " and ".join(str(n) for n in ns) + "."
    assert not unsupported_numbers(statement, evidence)


@FAST
@given(numbers, st.integers(10**7, 10**8))
def test_guardrail_rejects_a_figure_absent_from_the_evidence(ns, invented):
    from soc_platform.llm.gateway import unsupported_numbers

    evidence = "Counts: " + ", ".join(str(n) for n in ns)
    assert unsupported_numbers(f"There were {invented} events.", evidence)


# ------------------------------------------------------------------------ vendor timestamps
@FAST
@given(st.datetimes(min_value=datetime(2000, 1, 1), max_value=datetime(2100, 1, 1), timezones=st.just(UTC)))  # noqa: DTZ001 - hypothesis takes naive bounds and adds the zone
def test_every_vendor_timestamp_format_parses_to_the_same_utc_instant(dt):
    from soc_platform.connectors.tools._common import parse_ts

    dt = dt.replace(microsecond=0)
    forms = [dt.isoformat(), dt.strftime("%Y-%m-%dT%H:%M:%SZ"), dt.strftime("%Y-%m-%d %H:%M:%S"),
             dt.strftime("%Y-%m-%dT%H:%M:%S.0000000Z"), str(int(dt.timestamp()))]
    for f in forms:
        got = parse_ts(f)
        if got is not None:
            assert got == dt and got.tzinfo is not None, f


@FAST
@given(st.text(max_size=60))
def test_timestamp_parser_never_crashes(text):
    from soc_platform.connectors.tools._common import parse_ts

    got = parse_ts(text)
    assert got is None or got.tzinfo is not None


# ------------------------------------------------------------------------ bounded text
@FAST
@given(st.text(max_size=600), st.integers(2, 300))
def test_bounded_text_always_fits_and_keeps_short_values(text, width):
    from soc_platform.core.db import BoundedText

    out = BoundedText(width).process_bind_param(text, None)
    assert len(out) <= width and "\x00" not in out
    if len(text.replace("\x00", "")) <= width:
        assert out == text.replace("\x00", "")


# ------------------------------------------------------------------------ e-mail decomposer
@settings(max_examples=250, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(st.binary(max_size=3000))
def test_email_decomposer_never_crashes_on_arbitrary_bytes(raw):
    from soc_platform.domains.phishing.agents.decompose import decompose

    decompose(b"From: a@b.example\r\nSubject: x\r\n\r\n" + raw)
    decompose(raw)


@settings(max_examples=150, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(st.text(max_size=200), st.sampled_from(["text/plain", "text/html", "application/pdf", "image/png",
                                                 "multipart/mixed", "message/rfc822"]),
       st.sampled_from(["7bit", "base64", "quoted-printable", "8bit", "x-unknown"]))
def test_email_decomposer_handles_hostile_mime(body, ctype, cte):
    from soc_platform.domains.phishing.agents.decompose import decompose

    raw = (f"From: \"{body[:30]}\" <x@evil.example>\r\nSubject: {body[:50]}\r\nMIME-Version: 1.0\r\n"
           f"Content-Type: multipart/mixed; boundary=\"B\"\r\n\r\n--B\r\nContent-Type: {ctype}; name=\"{body[:20]}.bin\"\r\n"
           f"Content-Transfer-Encoding: {cte}\r\nContent-Disposition: attachment; filename=\"{body[:20]}.bin\"\r\n\r\n"
           f"{body}\r\n--B--\r\n").encode("utf-8", "surrogatepass")
    decompose(raw)
