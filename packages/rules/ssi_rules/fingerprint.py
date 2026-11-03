"""Script fingerprints for duplicate detection and campaign clustering (blueprint 3.2, 4.11).

Greeting names ("Dear Mary"), numbers, amounts and links are replaced with placeholders so the same script sent with
different details still matches. Similarity is estimated with a small MinHash.
"""
from __future__ import annotations

import hashlib
import re

from .normalize import _PHONE_RE, _URL_RE

_N_HASHES = 32


def normalise_script(text: str) -> str:
    t = re.sub(r"\b(Dear|Hello|Hi|Hey|Habari|Mpendwa)\s+[A-Z][a-z]+", r"\1 <name>", text)
    t = _URL_RE.sub(" <url> ", t)
    t = _PHONE_RE.sub(" <phone> ", t)
    t = re.sub(r"(?i)\b(?:ksh?s?|kes)\.?\s?\d[\d,.]*", " <amt> ", t)
    t = re.sub(r"\d+", " <n> ", t)
    t = re.sub(r"[^\w<>\s']", " ", t.lower())
    return re.sub(r"\s+", " ", t).strip()


def script_hash(text: str) -> str:
    return hashlib.sha256(normalise_script(text).encode()).hexdigest()


def minhash(text: str) -> list[int]:
    words = normalise_script(text).split()
    grams = {" ".join(words[i:i + 3]) for i in range(max(1, len(words) - 2))} or {""}
    return [min(int.from_bytes(hashlib.blake2b(f"{seed}|{g}".encode(), digest_size=6).digest(), "big") for g in grams)
            for seed in range(_N_HASHES)]


def similarity(a: list[int], b: list[int]) -> float:
    return sum(x == y for x, y in zip(a, b)) / max(1, min(len(a), len(b)))
