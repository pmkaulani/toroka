"""Misleading ads and product claims (blueprint 4.9). Claims are flagged for verification.

No rule here may mark a claim as false: that needs a cited source (see registry checks).
"""
from __future__ import annotations

import re

from .signals import Finding, _excerpt
from .vocabulary import ClaimStatus, EvidenceType, Strength

_RULES = [
    ("GUARANTEED_RETURNS", Strength.SUPPORTING, ClaimStatus.SUSPICIOUS_PATTERN,
     re.compile(r"(?i)\bguarantee[sd]?\b[^.\n]{0,25}\b(?:returns?|profits?|income|earnings?)\b|\b(?:double|triple)\s+your\s+(?:money|investment)\b"
                r"|\b\d{2,3}\s?%\s+(?:daily|weekly|monthly)\s+(?:returns?|profit|interest)\b|\bhakika\s+ya\s+faida\b"),
     "The message promises guaranteed or unusually high returns.",
     "Genuine investments cannot guarantee returns. Check whether the provider is licensed with the relevant regulator, using details you look up yourself."),
    ("GOVERNMENT_APPROVAL_CLAIM", Strength.WEAK, ClaimStatus.UNSUPPORTED,
     re.compile(r"(?i)\b(?:approved|endorsed|licen[sc]ed|certified)\s+by\s+(?:the\s+)?(?:government|cbk|central\s+bank|president|ministry|kebs|knbs|capital\s+markets)\b"),
     "The message says a government body approved or endorsed it.",
     "We did not check this claim against the named body, so it is unsupported until you confirm it with that body directly."),
    ("UNSUPPORTED_MEDICAL_CLAIM", Strength.SUPPORTING, ClaimStatus.UNSUPPORTED,
     re.compile(r"(?i)\b(?:cures?|heals?|treats?)\b[^.\n]{0,30}\b(?:cancer|diabetes|hiv|aids|hypertension|ulcers?|infertility)\b"),
     "The message claims a product cures or treats a serious illness.",
     "Strong health claims need evidence from a health regulator or a qualified professional. None was checked here."),
    ("MANIPULATED_DISCOUNT_FRAMING", Strength.WEAK, ClaimStatus.SUSPICIOUS_PATTERN,
     re.compile(r"(?i)\b(?:[5-9]\d)\s?%\s+off\b[^.\n]{0,30}\b(?:today\s+only|ends\s+tonight|last\s+day|while\s+stocks?\s+last)\b"),
     "The message pairs a very large discount with a countdown.",
     "Big discounts and deadlines appear in genuine sales too, so this is a weak signal. Compare the price with the seller's regular price."),
]


def claim_findings(text: str) -> list[Finding]:
    out = []
    for code, strength, status, rx, plain, why in _RULES:
        m = rx.search(text)
        if m:
            out.append(Finding(code, EvidenceType.UNRESOLVED_CLAIM if status == ClaimStatus.UNSUPPORTED else EvidenceType.AUTOMATED_OBSERVATION,
                               strength, plain, why, _excerpt(text, m.start(), m.end()), m.start(), m.end(),
                               needs_external_verification=True, claim_status=status))
    return out
