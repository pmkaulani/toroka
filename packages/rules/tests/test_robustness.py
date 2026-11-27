"""Fuzzing and worst-case timing. assess() must never raise, never leak a PIN, never be slow, and always return valid offsets."""
import re
import time
from dataclasses import asdict

import pytest
from hypothesis import HealthCheck, given, settings, strategies as st
from ssi_rules import Label, assess
from ssi_rules.signals import mask_credential_values

BITS = ["Pay", "KSh 350", "send", "PIN", "OTP", "1234", "to activate", "Safaricom", "KRA", "bit.ly/x", "https://a.example.com/p", "0712 345 678", "Till 123456", "mistake", "fee", "processing fee",
        "congratulations", "umeshinda", "kimakosa", "Nairobi", "@shop", "Instagram", "guaranteed returns", "\n", " ", "•", "…", "\u202e", "😀", "ß", "İ", "٣", "。"]
text_strat = st.one_of(st.text(max_size=600), st.lists(st.sampled_from(BITS), max_size=120).map(" ".join), st.text(alphabet=st.characters(), min_size=0, max_size=5000))


@settings(max_examples=400, deadline=None, suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large])
@given(text_strat)
def test_assess_total_safe_and_consistent(text):
    t0 = time.perf_counter()
    a = assess(text)
    assert time.perf_counter() - t0 < 1.5
    assert a.label in set(Label) and a.summary and a.coverage and a.limitations and a.policy_version
    masked, _ = mask_credential_values(text)
    for f in a.findings:
        if f.start is not None:
            assert 0 <= f.start <= f.end <= len(masked) and f.excerpt == masked[f.start:f.end].strip()
    assert not re.search(r"(?i)\b(scammer|fraudster|criminal)\b", a.summary + " ".join(f.plain_text + f.why_it_matters for f in a.findings))
    output_blob = repr(asdict(a)).replace(a.checked_at, "").replace("\\n", " ").replace("0712345678", "")
    for m in re.finditer(r"(?i)\b(?:pin|otp|password|passcode|code|nywila)\b\s*(?:is|was|ni|:|=)?\s*(\d{4,8})\b", text):
        # Whole numeric token only: a PIN like 0712 must not be falsely matched
        # inside an unrelated decimal probability such as 0.0712.
        leaked = re.search(rf"(?<![\d.]){re.escape(m.group(1))}(?![\d.])", output_blob)
        assert not leaked or m.group(1) in text.replace(m.group(0), ""), "credential value leaked"
    if a.label == Label.NO_KNOWN_THREATS_FOUND:
        assert not any(c.blocking and c.status.value != "checked" for c in a.coverage) and not a.findings


@settings(max_examples=150, deadline=None)
@given(st.text(max_size=2000))
def test_deterministic(text):
    from datetime import datetime, timezone
    t = datetime(2026, 10, 20, tzinfo=timezone.utc)
    assert assess(text, now=t) == assess(text, now=t)


PATHOLOGICAL = {
    "long letters": "a" * 5000, "many pays": "pay " * 1250, "pay then long gap": "Pay " + "x" * 4990, "pay-gap-repeat": ("send " + "x" * 59 + " ") * 80,
    "pin spam": "send your pin " * 350, "number soup": "0712 " * 1000, "digits": "1" * 5000, "dots": "a." * 2500, "slashes": "https://" + "a/" * 2400,
    "url labels": "www." + "a-" * 2400 + ".com", "spaces": " " * 5000, "newlines": "\n" * 5000, "bullets": "•" * 5000, "mixed fee": ("processing and clearance fee " * 170),
    "kra repeat": "KRA " * 1250 + "pay Ksh 5 application fee", "emoji": "😀" * 2500, "pin nums": "PIN 1234 " * 550, "ksh": "KSh " * 1250 + "1", "at handles": "@a" * 2500,
    "quotes": '"' * 5000, "backslashes": "\\" * 5000, "angle": "<" * 5000, "percent": "%" * 5000, "congrats": "congratulations you have won " * 170,
}


@pytest.mark.parametrize("name", list(PATHOLOGICAL))
@pytest.mark.performance
def test_pathological_inputs_finish_quickly(name):
    t0 = time.perf_counter(); a = assess(PATHOLOGICAL[name][:5000]); dt = time.perf_counter() - t0
    assert dt < 1.0, f"{name} took {dt:.2f}s"
    assert a.label in set(Label)


@pytest.mark.performance
def test_typical_message_is_fast():
    t0 = time.perf_counter()
    for _ in range(200):
        assess("Safaricom: Your M-PESA is locked. Reply with your M-PESA PIN to unlock it. Pay KSh 350 to activate funds at https://safaricom-rewards.xyz/claim")
    assert (time.perf_counter() - t0) / 200 < 0.02          # under 20 ms each on this machine
