"""Social-shop profile extraction (blueprint 4.5). Descriptive only: nothing here is scored as fraud.

New account, low price, personal mobile money and no shopfront are NOT treated as proof of fraud.
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field

from .location import extract_location_claims
from .normalize import extract_amounts

_PLATFORM_URL = [
    ("instagram", re.compile(r"(?i)instagram\.com/([A-Za-z0-9_.]{2,30})")),
    ("tiktok", re.compile(r"(?i)tiktok\.com/@([A-Za-z0-9_.]{2,30})")),
    ("facebook", re.compile(r"(?i)facebook\.com/(?!marketplace)([A-Za-z0-9_.\-]{2,50})")),
    ("x", re.compile(r"(?i)(?:x|twitter)\.com/([A-Za-z0-9_]{2,15})")),
    ("whatsapp", re.compile(r"(?i)wa\.me/(\d{9,15})")),
]
_HANDLE = re.compile(r"(?<![\w@.])@([A-Za-z0-9_.]{3,30})\b")
_PLATFORM_WORD = re.compile(r"(?i)\b(instagram|insta|tiktok|facebook|fb|marketplace|whatsapp business|whatsapp)\b")
_DELIVERY = re.compile(r"(?i)\b(?:delivery|deliver(?:ed|y)?|we\s+deliver|countrywide|pick\s?-?up|collect(?:ion)?|g4s|fargo|courier)\b")
_RETURNS = re.compile(r"(?i)\b(?:returns?|refunds?|exchange|money\s+back|warranty)\b")

_NON_SHOP_EXCLUSIONS = {
    "this", "that", "it", "website", "domain", "link", "message", "sms", "email",
    "number", "phone", "chatgpt", "ai", "safe", "legit", "scam", "application",
    "recruitment", "interview", "appointment", "hiring", "job", "vacancy", "vacancies",
    "there", "here", "available", "required", "difference", "opportunity", "grant",
}


@dataclass
class ShopProfile:
    platform: str | None = None
    handle: str | None = None
    prices_ksh: list[str] = field(default_factory=list)
    claimed_counties: list[str] = field(default_factory=list)
    delivery_mentioned: bool = False
    returns_terms_mentioned: bool = False
    notes: list[str] = field(default_factory=list)

    def as_dict(self):
        return asdict(self)


def extract_shop_profile(text: str) -> ShopProfile | None:
    # Never infer a shopping profile on recruitment, employment, or grant inquiries
    # unless an explicit e-commerce action (selling, order now, price, dm to buy) is present.
    job_match = re.search(r"(?i)\b(?:recruit\w*|vacanc\w+|job\s+offer|difference\s+job|employment|hiring|work\s+permit|form\s+four\s+certificate|overseas\s+job|ajira|kazi)\b", text)
    shop_intent = re.search(r"(?i)\b(?:buy|sell\w*|order\s+now|dm\s+to\s+order|price|bei|in\s+stock|delivery\s+fee|boutique|store|shop\s+page)\b", text)
    if job_match and not shop_intent:
        return None

    platform = handle = None
    for name, rx in _PLATFORM_URL:
        m = rx.search(text)
        if m:
            platform, handle = name, m.group(1)
            break
    if not platform:
        w = _PLATFORM_WORD.search(text)
        if w:
            platform = {"insta": "instagram", "fb": "facebook"}.get(w.group(1).lower(), w.group(1).lower().replace(" business", ""))
        h = _HANDLE.search(text)
        if h:
            handle = h.group(1)
            platform = platform or "unknown"
    if not platform:
        inq = re.search(r"(?i)\b(?:look\s+into|check|investigate|audit|verify|is)\s+(?:the\s+)?(?:page|shop|store|seller|handle)\s*@?([A-Za-z0-9_.]{3,35})\b", text)
        if inq:
            cand = inq.group(1).lower()
            if cand not in _NON_SHOP_EXCLUSIONS:
                handle = cand
                platform = "social_media"
    if not platform:
        und = re.search(r"(?i)\b([A-Za-z0-9]{2,25}_[A-Za-z0-9_]{2,25})\b", text)
        if und and shop_intent:
            cand = und.group(1)
            if cand.lower() not in {"m_pesa", "user_id", "check_id", "test_id"}:
                handle = cand
                platform = "social_media"
    if not platform:
        return None
    p = ShopProfile(platform=platform, handle=handle, prices_ksh=[a.normalized for a in extract_amounts(text)],
                    claimed_counties=[c for _, c in extract_location_claims(text)],
                    delivery_mentioned=bool(_DELIVERY.search(text)), returns_terms_mentioned=bool(_RETURNS.search(text)))
    if not p.returns_terms_mentioned:
        p.notes.append("No return or refund terms appear in what you submitted. Ask for them in writing before paying.")
    if not p.claimed_counties:
        p.notes.append("No pickup or business location was stated. Ask where the goods are collected from.")
    return p


NO_ADVANCE_PAYMENT = "Before sending money, independently verify the seller, payment recipient, delivery terms, and any available buyer protection. Advance payment can be legitimate; pressure, contradictory details, or an unverifiable recipient are stronger warning signs."
SAFER_BUYING = [
    NO_ADVANCE_PAYMENT,
    "Contact the seller through a channel you find independently, not only the one in the advert.",
    "Get the order, price, delivery and refund terms in writing and keep screenshots.",
    "Compare the seller's name and payment name before sending money; ask for clarification if they do not match.",
]
