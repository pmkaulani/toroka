"""Investigation category detection and specialist dispatch.

Identifies whether the request concerns:
1. Recruitment and overseas employment fraud (recruitment_overseas / job)
2. Online shopping fraud (online_shopping)
3. Social media seller investigations (social_seller / shop)
4. M-PESA and payment fraud (mpesa_payment / payment)
5. Government grants and impersonation (government_grants / grant)
6. Prize and winnings messages (prize_winnings)
7. Phishing and credential theft (phishing_credential / website)
8. Investment fraud (investment_fraud)
9. Other emerging fraud patterns (emerging_other / message)

Each category drives its own evidence sources, detection rules, and protective advice.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum


class InvestigationCategory(str, Enum):
    RECRUITMENT_OVERSEAS = "recruitment_overseas"
    ONLINE_SHOPPING = "online_shopping"
    SOCIAL_SELLER = "social_seller"
    MPESA_PAYMENT = "mpesa_payment"
    GOVERNMENT_GRANTS = "government_grants"
    PRIZE_WINNINGS = "prize_winnings"
    PHISHING_CREDENTIAL = "phishing_credential"
    INVESTMENT_FRAUD = "investment_fraud"
    EMERGING_OTHER = "emerging_other"


# Legacy category strings for full backward compatibility
CATEGORIES = ("message", "job", "grant", "payment", "shop", "website")

INVESTIGATION_CATEGORIES = tuple(c.value for c in InvestigationCategory)

# Legacy alias mappings
_LEGACY_TO_INVESTIGATION = {
    "job": InvestigationCategory.RECRUITMENT_OVERSEAS.value,
    "shop": InvestigationCategory.SOCIAL_SELLER.value,
    "payment": InvestigationCategory.MPESA_PAYMENT.value,
    "grant": InvestigationCategory.GOVERNMENT_GRANTS.value,
    "website": InvestigationCategory.PHISHING_CREDENTIAL.value,
    "message": InvestigationCategory.EMERGING_OTHER.value,
}

_INVESTIGATION_TO_LEGACY = {
    InvestigationCategory.RECRUITMENT_OVERSEAS.value: "job",
    InvestigationCategory.ONLINE_SHOPPING.value: "shop",
    InvestigationCategory.SOCIAL_SELLER.value: "shop",
    InvestigationCategory.MPESA_PAYMENT.value: "payment",
    InvestigationCategory.GOVERNMENT_GRANTS.value: "grant",
    InvestigationCategory.PRIZE_WINNINGS.value: "message",
    InvestigationCategory.PHISHING_CREDENTIAL.value: "website",
    InvestigationCategory.INVESTMENT_FRAUD.value: "message",
    InvestigationCategory.EMERGING_OTHER.value: "message",
}

# Domain & phrase keywords for high-precision category identification
_KW: dict[str, re.Pattern] = {
    InvestigationCategory.RECRUITMENT_OVERSEAS.value: re.compile(
        r"(?i)\b(?:recruit\w*|vacanc\w+|appointment\s+letter|interview|hiring|trainee|"
        r"internship|attachment|job\s+offer|ajira|kazi|work\s+permit|visa\s+sponsor\w*|"
        r"overseas\s+job\w*|difference\s+job|united\s+states|form\s+four\s+certificate|"
        r"diaspora|employment\s+in\s+[a-z]+|jobs?\s+in\s+(?:the\s+)?(?:us|usa|united\s+states|"
        r"uk|united\s+kingdom|canada|qatar|dubai|uae|saudi|kuwait|germany|australia|abroad)|"
        r"work\s+abroad|recruitment\s+agency|application\s+fee|medical\s+fee\s+for\s+job|"
        r"apply\s+(?:to\s+)?register|job\s+application)\b"
    ),
    InvestigationCategory.GOVERNMENT_GRANTS.value: re.compile(
        r"(?i)\b(?:grants?|bursary|bursaries|scholarship|funding|helb|programme|program|"
        r"loan\s+scheme|ruzuku|hustler\s+fund|inua\s+jamii|gov(?:ernment)?\s+grant|"
        r"ministry\s+of|huduma|disbursement\s+fee|processing\s+fee\s+for\s+grant)\b"
    ),
    InvestigationCategory.MPESA_PAYMENT.value: re.compile(
        r"(?i)\b(?:pay\s?bill|till\s*(?:no|number)?|m-?pesa|send\s+(?:money|ksh)|lipa|"
        r"tuma|nimetuma|nimekutumia|kimakosa|kwa\s+makosa|rudisha|nirudishie|rudishiwa|"
        r"reversal|reverse\s+(?:the\s+)?(?:transaction|sms|money)|fuliza|"
        r"overdrawn|mpesa\s+pin|mpesa\s+balance|confirmed\.\s*ksh|wrong\s+recipient|"
        r"reversal\s+request|send\s+back)\b"
    ),
    InvestigationCategory.SOCIAL_SELLER.value: re.compile(
        r"(?i)\b(?:instagram|tiktok|facebook|marketplace|dm\s+to\s+order|delivery|"
        r"in\s+stock|order\s+now|price|selling|for\s+sale|bei|store|shop|boutique|"
        r"seller|clothing|shoes|watches|electronics|pay\s+on\s+delivery)\b|(?<![\w@])@[\w.]{3,30}\b"
    ),
    InvestigationCategory.PRIZE_WINNINGS.value: re.compile(
        r"(?i)\b(?:congratulations|you\s+have\s+won|winner|prize|lottery|draw|"
        r"claim\s+your\s+prize|jackpot|free\s+bet|betting\s+bonus|spin\s+and\s+win|"
        r"promotional\s+reward|voucher\s+code|cash\s+prize|shinda)\b"
    ),
    InvestigationCategory.PHISHING_CREDENTIAL.value: re.compile(
        r"(?i)\b(?:account\s+suspended|verify\s+(?:your\s+)?account|security\s+alert|"
        r"unauthorized\s+access|click\s+here\s+to\s+unlock|login\s+to|enter\s+(?:your\s+)?(?:password|pin|otp|code)|"
        r"update\s+(?:your\s+)?(?:kyc|credentials|details)|safaricom\s+line\s+suspended|"
        r"suspended\s+line|gmail\s+password|email\s+password|credential\s+harvesting)\b"
    ),
    InvestigationCategory.INVESTMENT_FRAUD.value: re.compile(
        r"(?i)\b(?:crypto|bitcoin|forex|binary\s+options|guaranteed\s+(?:daily|weekly|monthly)?\s*(?:profit|returns?)|"
        r"investment\s+platform|deposit\s+and\s+earn|trading\s+bot|double\s+your\s+money|"
        r"ponzi|pyramid\s+scheme|daily\s+interest|roi|multiplier)\b"
    ),
}

# Legacy keyword regex table for direct backward compatibility
_LEGACY_KW = {
    "job": _KW[InvestigationCategory.RECRUITMENT_OVERSEAS.value],
    "grant": _KW[InvestigationCategory.GOVERNMENT_GRANTS.value],
    "payment": _KW[InvestigationCategory.MPESA_PAYMENT.value],
    "shop": _KW[InvestigationCategory.SOCIAL_SELLER.value],
}


@dataclass
class CategoryGuess:
    suggested: str                                      # Legacy string ("job", "shop", etc.)
    alternatives: list[str] = field(default_factory=list)
    investigation_category: str = InvestigationCategory.EMERGING_OTHER.value
    confidence: float = 0.5


def normalize_category(category: str | None) -> str:
    """Normalize any legacy or granular category to standard investigation category."""
    if not category:
        return InvestigationCategory.EMERGING_OTHER.value
    cat = category.strip().lower()
    if cat in _LEGACY_TO_INVESTIGATION:
        return _LEGACY_TO_INVESTIGATION[cat]
    if cat in INVESTIGATION_CATEGORIES:
        return cat
    return InvestigationCategory.EMERGING_OTHER.value


def to_legacy_category(investigation_category: str) -> str:
    """Map standard investigation category to legacy category code."""
    return _INVESTIGATION_TO_LEGACY.get(investigation_category, "message")


def detect_category(text: str, urls: list | None = None, phones: list | None = None, payment_ids: list | None = None) -> CategoryGuess:
    """Identify the primary investigation category from evidence text and identifiers."""
    urls = urls or []
    phones = phones or []
    payment_ids = payment_ids or []

    scores: dict[str, int] = {}
    for cat_val, rx in _KW.items():
        matches = rx.findall(text)
        scores[cat_val] = len(matches)

    # Contextual boosts
    if payment_ids:
        scores[InvestigationCategory.MPESA_PAYMENT.value] = scores.get(InvestigationCategory.MPESA_PAYMENT.value, 0) + 2

    # Job and Grant claims outrank generic payment or message mentions
    recruitment_cat = InvestigationCategory.RECRUITMENT_OVERSEAS.value
    grant_cat = InvestigationCategory.GOVERNMENT_GRANTS.value
    phishing_cat = InvestigationCategory.PHISHING_CREDENTIAL.value

    # If text is an explicit overseas job offer or application
    if scores.get(recruitment_cat, 0) >= 1:
        scores[recruitment_cat] += 4

    # If credential harvesting or login is mentioned alongside links
    if urls and re.search(r"(?i)\b(?:login|password|verify\s+account|pin|otp)\b", text):
        scores[phishing_cat] = scores.get(phishing_cat, 0) + 3

    ranked = [c for c, n in sorted(scores.items(), key=lambda kv: -kv[1]) if n > 0]

    if not ranked:
        if urls:
            legacy = "website"
            inv = InvestigationCategory.PHISHING_CREDENTIAL.value
        else:
            legacy = "message"
            inv = InvestigationCategory.EMERGING_OTHER.value
        return CategoryGuess(suggested=legacy, alternatives=[], investigation_category=inv, confidence=0.3)

    primary_inv = ranked[0]
    legacy_suggested = to_legacy_category(primary_inv)
    alternatives = [to_legacy_category(c) for c in ranked[1:3] if to_legacy_category(c) != legacy_suggested]

    return CategoryGuess(
        suggested=legacy_suggested,
        alternatives=alternatives,
        investigation_category=primary_inv,
        confidence=min(1.0, 0.4 + 0.15 * scores[primary_inv]),
    )
