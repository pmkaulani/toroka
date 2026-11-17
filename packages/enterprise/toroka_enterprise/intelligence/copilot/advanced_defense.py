"""Advanced Anti-Evasion & Prompt Injection Defense for Banking Intelligence Narratives.

Defends LLM copilot and automated investigation reporting against indirect prompt
injection, unicode evasion, base64 payload smuggling, and adversarial delimiters
embedded in transaction memos, customer complaints, and banking transfer narratives.
"""
from __future__ import annotations

import base64
import re
from dataclasses import dataclass
from typing import Any


# Zero-width and invisible unicode characters used to bypass word-boundary tokenizers
ZERO_WIDTH_CHARS = [
    "\u200b",  # Zero-width space
    "\u200c",  # Zero-width non-joiner
    "\u200d",  # Zero-width joiner
    "\ufeff",  # Byte order mark / zero-width no-break space
    "\u00ad",  # Soft hyphen
    "\u200e",  # Left-to-right mark
    "\u200f",  # Right-to-left mark
    "\u2060",  # Word joiner
]

# Common Cyrillic and Greek homoglyphs used to evade English keyword filters
HOMOGLYPH_MAP = {
    "а": "a", "А": "A",
    "с": "c", "С": "C",
    "е": "e", "Е": "E",
    "о": "o", "О": "O",
    "р": "p", "Р": "P",
    "х": "x", "Х": "X",
    "у": "y", "У": "Y",
    "і": "i", "І": "I",
    "ј": "j", "Ј": "J",
    "ѕ": "s", "Ѕ": "S",
    "ԛ": "q", "Ԛ": "Q",
}

# Delimiters that attackers attempt to inject to escape prompt enclosures
DANGEROUS_DELIMITERS = [
    re.compile(r"---+\s*(BEGIN|END)\s+[A-Z0-9_\s]+---+", re.IGNORECASE),
    re.compile(r"</?(system|evidence|prompt|instruction|context|record)[^>]*>", re.IGNORECASE),
    re.compile(r"\[(SYSTEM|ADMIN|INSTRUCTION|OVERRIDE)[^\]]*\]", re.IGNORECASE),
]

# High-threat instruction patterns
INJECTION_KEYWORDS = [
    re.compile(r"\bignore\s+(all\s+)?(previous|past|prior)\s+instructions\b", re.IGNORECASE),
    re.compile(r"\bdisregard\s+(the\s+)?(above|rules|system|policy)\b", re.IGNORECASE),
    re.compile(r"\byou\s+are\s+now\s+(an?\s+)?(admin|developer|unrestricted|god\s+mode)\b", re.IGNORECASE),
    re.compile(r"\breveal\s+(all\s+)?(passwords?|credentials?|secrets?|keys?|api[_\s]?keys?)\b", re.IGNORECASE),
    re.compile(r"\bdump\s+(the\s+)?(database|vault|table|schema)\b", re.IGNORECASE),
    re.compile(r"\boverride\s+(safety|security|governance|fraud\s+rules)\b", re.IGNORECASE),
    re.compile(r"\bclassify\s+(this\s+)?(as\s+)?(legitimate|safe|innocent|authorized)\b", re.IGNORECASE),
]


@dataclass(frozen=True)
class NarrativeSecurityScan:
    """Security analysis of an untrusted banking narrative."""
    clean_text: str
    is_adversarial: bool
    detected_threats: tuple[str, ...]
    sanitized_differs: bool
    hidden_payload_detected: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "clean_text": self.clean_text,
            "is_adversarial": self.is_adversarial,
            "detected_threats": list(self.detected_threats),
            "sanitized_differs": self.sanitized_differs,
            "hidden_payload_detected": self.hidden_payload_detected,
        }


def strip_invisible_characters(text: str) -> str:
    """Removes all zero-width and invisible unicode characters."""
    for ch in ZERO_WIDTH_CHARS:
        text = text.replace(ch, "")
    return text


def normalize_homoglyphs(text: str) -> str:
    """Normalizes cross-script homoglyphs to standard Latin ASCII equivalents."""
    chars = [HOMOGLYPH_MAP.get(ch, ch) for ch in text]
    return "".join(chars)


def scan_for_base64_payloads(text: str) -> list[str]:
    """Detects and decodes hidden base64 chunks that conceal adversarial instructions."""
    detected: list[str] = []
    # Match potential base64 strings of 16+ chars
    candidates = re.findall(r"\b[A-Za-z0-9+/]{16,}={0,2}\b", text)
    for cand in candidates:
        try:
            decoded = base64.b64decode(cand).decode("utf-8", errors="ignore")
            # If decoded text contains an adversarial keyword
            for pat in INJECTION_KEYWORDS:
                if pat.search(decoded):
                    detected.append(f"BASE64_INSTRUCTION_SMUGGLING: '{cand}' -> '{decoded.strip()}'")
                    break
        except Exception:
            continue
    return detected


def sanitize_narrative(text: str) -> NarrativeSecurityScan:
    """Performs deep sanitization and adversarial inspection on banking narratives."""
    threats: list[str] = []
    hidden_payload = False

    # 1. Check for Base64 Smuggling
    b64_threats = scan_for_base64_payloads(text)
    if b64_threats:
        threats.extend(b64_threats)
        hidden_payload = True

    # 2. Check for invisible unicode characters
    cleaned = strip_invisible_characters(text)
    if len(cleaned) != len(text):
        threats.append("UNICODE_ZERO_WIDTH_ATTACK: Stripped invisible characters")
        hidden_payload = True

    # 3. Check for homoglyphs
    homo_norm = normalize_homoglyphs(cleaned)
    if homo_norm != cleaned:
        threats.append("HOMOGLYPH_OBFUSCATION: Converted lookalike characters to Latin")

    # 4. Check for delimiter breakout attempts
    for delim in DANGEROUS_DELIMITERS:
        if delim.search(homo_norm):
            threats.append(f"DELIMITER_INJECTION_ATTEMPT: Matched '{delim.pattern}'")

    # 5. Check for adversarial keywords in normalized form
    for kw in INJECTION_KEYWORDS:
        if kw.search(homo_norm):
            threats.append(f"ADVERSARIAL_INSTRUCTION: Matched '{kw.pattern}'")

    # Escape XML/HTML tags in output
    safe_output = (
        cleaned
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("---", "- - -")
    )

    is_adversarial = len(threats) > 0

    return NarrativeSecurityScan(
        clean_text=safe_output,
        is_adversarial=is_adversarial,
        detected_threats=tuple(threats),
        sanitized_differs=safe_output != text,
        hidden_payload_detected=hidden_payload,
    )
