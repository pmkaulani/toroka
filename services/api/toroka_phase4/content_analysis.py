from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import re
from typing import Any
from urllib.parse import urlsplit


@dataclass(slots=True)
class ContentSignal:
    category: str
    severity: str
    summary: str
    reason: str
    excerpt: str = ""
    polarity: str = "risk"
    confidence: float = 0.65
    limitations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ContentAnalysis:
    channel: str
    language_hint: str
    signals: list[ContentSignal]
    extracted_domains: list[str]
    extracted_phones_masked: list[str]
    analyzed_at: str
    raw_content_stored: bool = False
    limitations: list[str] = field(default_factory=list)

    @property
    def highest_severity(self) -> str:
        order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "context": 0}
        return max((s.severity for s in self.signals), key=lambda x: order.get(x, 0), default="none")

    def to_dict(self) -> dict[str, Any]:
        return {
            "channel": self.channel,
            "language_hint": self.language_hint,
            "signals": [s.to_dict() for s in self.signals],
            "extracted_domains": list(self.extracted_domains),
            "extracted_phones_masked": list(self.extracted_phones_masked),
            "analyzed_at": self.analyzed_at,
            "raw_content_stored": self.raw_content_stored,
            "highest_severity": self.highest_severity,
            "limitations": list(self.limitations),
        }


# Pattern groups are deliberately phrase-based and transparent. They are not a
# trained classifier and must not be described as proof of fraud.
_PATTERNS: list[tuple[str, list[str], str, str, float]] = [
    ("prize_or_betting_bait", [
        r"\b(you have won|you.ve won|winner|claim your prize|free bet|freebets|free airtime|jackpot|aviator bonus|bonus unlocked)\b",
        r"\b(umeshinda|umepata zawadi|zawadi yako|bahati yako|dau la bure|bonasi ya bure)\b",
    ], "medium", "An unexpected prize, bonus or betting reward is being promoted.", 0.72),
    ("advance_fee_for_benefit", [
        r"\b(processing fee|release fee|activation fee|unlock fee|claim fee|pay to receive|deposit to receive|send money to unlock|fee to access)\b",
        r"\b(lipa ada|ada ya usajili|ada ya kutoa|tuma pesa ili|lipa kwanza|amana ili kupata|ada ya uchakataji)\b",
    ], "high", "The message asks for money before a promised benefit, prize, grant or service is released.", 0.83),
    ("job_or_recruitment_fee", [
        r"\b(application fee|recruitment fee|interview fee|job registration fee|training fee|uniform fee|pay to secure (the )?job)\b",
        r"\b(ada ya kazi|ada ya maombi|ada ya interview|lipa ili upate kazi|ada ya usaili|ada ya mafunzo)\b",
    ], "high", "A job or recruitment opportunity appears to require an upfront payment.", 0.82),
    ("government_or_grant_fee", [
        r"\b(government grant|county grant|government fund|bursary|social protection payment|public benefit)\b",
        r"\b(ripoti ya serikali|ruzuku ya serikali|mfuko wa serikali|ufadhili|bursary|msaada wa serikali)\b",
    ], "context", "The message invokes a government, county, grant or public-benefit programme.", 0.70),
    ("credential_or_otp_request", [
        r"\b(send|share|reply with|enter|confirm|verify) (your )?((m[- ]?pesa )?(pin|password|passcode|otp|one.time password|verification code))\b",
        r"\b(mpesa|m-pesa) (pin|otp|one.time password|verification code)\b",
        r"\b(usiambie mtu|nitumie pin|tuma pin|nipe otp|nambari ya siri|nenosiri|msimbo wa uthibitisho)\b",
    ], "critical", "The message appears to request a secret authentication code, PIN or password.", 0.92),
    ("account_pressure", [
        r"\b(account (will be|is) (suspended|blocked|closed)|suspend your account|immediate action required|verify now or|within \d+ hours)\b",
        r"\b(akaunti yako (imefungwa|itafungwa)|thibitisha sasa|hatua za haraka|akaunti itasitishwa)\b",
    ], "medium", "Urgency or account-threat language is being used to prompt action.", 0.73),
    ("guaranteed_investment_return", [
        r"\b(guaranteed (profit|returns?)|double your money|risk.free investment|fixed daily returns|100% returns?)\b",
        r"\b(faida ya uhakika|pesa mara mbili|rudufu pesa|faida ya kila siku|hakuna hasara)\b",
    ], "high", "The offer promises unusually certain or guaranteed investment returns.", 0.80),
    ("delivery_or_customs_fee", [
        r"\b(parcel held|delivery failed|customs fee|clearance fee|pay redelivery fee|package awaiting payment)\b",
        r"\b(kifurushi kimeshikiliwa|ada ya forodha|lipa ada ya usafirishaji|mzigo umesimama)\b",
    ], "medium", "The message claims a parcel or delivery requires an unexpected payment.", 0.72),
]

_BRANDS = {
    "safaricom": "Safaricom", "mpesa": "M-PESA", "m-pesa": "M-PESA",
    "kra": "KRA", "sha": "SHA", "helb": "HELB", "ecitizen": "eCitizen",
    "kplc": "Kenya Power", "kenya power": "Kenya Power", "huduma": "Huduma Kenya",
    "ntsa": "NTSA", "nssf": "NSSF", "nhif": "NHIF",
}

_DOMAIN_RE = re.compile(r"(?i)(?<![@\w])(?:https?://)?(?:www\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}(?:/[^\s<>\"']*)?")
_PHONE_RE = re.compile(r"(?<!\w)(?:\+?254\s?7\d{2}[\s-]?\d{3}[\s-]?\d{3}|0?7\d{2}[\s-]?\d{3}[\s-]?\d{3})(?!\w)")
_EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)
_LONG_NUMBER_RE = re.compile(r"(?<!\d)\d{8,}(?!\d)")


def _normalize_domain(raw: str) -> str | None:
    candidate = raw.strip().rstrip(".,;:)")
    if not candidate.lower().startswith(("http://", "https://")):
        candidate = "https://" + candidate
    try:
        parts = urlsplit(candidate)
        host = (parts.hostname or "").encode("idna").decode("ascii").lower().rstrip(".")
        if not host or "." not in host or len(host) > 253 or any(not p or len(p) > 63 for p in host.split(".")):
            return None
        if host in {"localhost", "localhost.localdomain"} or host.endswith((".local", ".internal", ".test", ".invalid")):
            return None
        return host
    except (ValueError, UnicodeError):
        return None


def _mask_phone(value: str) -> str:
    digits = re.sub(r"\D", "", value)
    return ("+254" + digits[-9:])[:-4] + "••••" if len(digits) >= 9 else "••••"


def _safe_excerpt(text: str, pattern: str, limit: int = 180) -> str:
    match = re.search(pattern, text, re.I)
    if not match:
        return ""
    start = max(0, match.start() - 55)
    end = min(len(text), match.end() + 95)
    excerpt = text[start:end].replace("\n", " ")
    excerpt = _PHONE_RE.sub("[phone redacted]", excerpt)
    excerpt = _EMAIL_RE.sub("[email redacted]", excerpt)
    excerpt = re.sub(r"(?i)\b(?:national\s+)?id(?:\s+number)?\s*[:#-]?\s*[a-z0-9-]{6,}\b", "[identifier redacted]", excerpt)
    excerpt = re.sub(r"(?i)\b(?:transaction|receipt|reference|account)\s*(?:id|number|ref)?\s*[:#-]?\s*[a-z0-9-]{6,}\b", "[reference redacted]", excerpt)
    excerpt = re.sub(r"(?i)\b(pin|otp|password|passcode|verification code)\b\s*(?:is|:|=)?\s*[a-z0-9]{4,12}", r"\1 [secret redacted]", excerpt)
    excerpt = _LONG_NUMBER_RE.sub("[number redacted]", excerpt)
    # Preserve the public host but never show user-specific URL paths or parameters.
    excerpt = _DOMAIN_RE.sub(lambda m: (_normalize_domain(m.group(0)) or "[link redacted]"), excerpt)
    excerpt = re.sub(r"\s+", " ", excerpt).strip()
    return excerpt[:limit]


def analyze_content(text: str, *, channel: str = "message", max_chars: int = 20_000) -> ContentAnalysis:
    """Analyze extracted text from SMS, chat or OCR. Raw input is never retained."""
    if not isinstance(text, str):
        raise TypeError("text must be a string")
    allowed_channels = {"message", "sms", "whatsapp", "instagram", "facebook", "tiktok",
                        "email", "screenshot", "webpage", "call", "unknown"}
    if channel not in allowed_channels:
        raise ValueError("channel must be a predefined source type")
    if len(text) > max_chars:
        text = text[:max_chars]
    normalized = text.casefold()
    signals: list[ContentSignal] = []

    # Each group can contain language alternatives; only one signal is emitted per group.
    for category, alternatives, severity, explanation, confidence in _PATTERNS:
        matched = next((p for p in alternatives if re.search(p, normalized, re.I)), None)
        if not matched:
            continue
        actual_severity = severity
        # A government/grant mention by itself is context. It becomes risk-bearing
        # only when paired with an advance-fee demand.
        polarity = "context" if category == "government_or_grant_fee" else "risk"
        if category == "government_or_grant_fee" and re.search(
            r"\b(processing fee|release fee|activation fee|deposit to receive|pay to receive|lipa ada|lipa kwanza|tuma pesa)\b", normalized, re.I
        ):
            actual_severity, polarity = "high", "risk"
            explanation = "A public-benefit or government programme is invoked together with an upfront payment demand."
            confidence = 0.84
        signals.append(ContentSignal(
            category=category, severity=actual_severity, summary=explanation,
            reason="Phrase-pattern match in user-supplied or OCR-extracted content; this is a lead for investigation, not a factual finding.",
            excerpt=_safe_excerpt(text, matched), polarity=polarity, confidence=confidence,
            limitations=["Rule-based phrase match; wording may be quoted, satirical, legitimate or taken out of context.", "Verify the sender, domain and payment recipient independently."],
        ))

    # A payment request is context unless there are additional deceptive signals.
    payment_match = re.search(r"\b(mpesa|m-pesa|till number|paybill|send money|lipa|tuma pesa|buy goods)\b", normalized, re.I)
    if payment_match and not any(s.category in {"advance_fee_for_benefit", "job_or_recruitment_fee", "government_or_grant_fee", "credential_or_otp_request"} for s in signals):
        signals.append(ContentSignal(
            category="payment_instruction_present", severity="context",
            summary="The content includes a payment instruction or M-PESA reference.",
            reason="Payment instructions are common in legitimate commerce; recipient and transaction details need separate verification.",
            excerpt=_safe_excerpt(text, payment_match.re.pattern), polarity="context", confidence=0.95,
            limitations=["The presence of an M-PESA or payment instruction is not a scam indicator by itself."],
        ))

    brands = sorted({label for key, label in _BRANDS.items() if re.search(r"(?<!\w)" + re.escape(key) + r"(?!\w)", normalized)})
    for brand in brands:
        signals.append(ContentSignal(
            category="brand_or_public_service_mentioned", severity="context",
            summary=f"The message mentions {brand}.",
            reason="A brand or public-service name is mentioned; this alone does not establish impersonation or authorization.",
            excerpt=_safe_excerpt(text, re.escape(brand)), polarity="context", confidence=0.98,
            limitations=["Brand mention is not proof the message came from that organization."],
        ))

    domains = sorted({d for raw in _DOMAIN_RE.findall(text) if (d := _normalize_domain(raw))})
    phones = sorted({_mask_phone(p) for p in _PHONE_RE.findall(text)})
    sw_markers = sum(1 for p in ["umeshinda", "lipa kwanza", "tuma pesa", "akaunti yako", "nambari ya siri", "kifurushi"] if p in normalized)
    en_markers = sum(1 for p in ["you have won", "processing fee", "account suspended", "claim your prize", "application fee", "send money"] if p in normalized)
    language = "sw" if sw_markers > en_markers and sw_markers else ("en" if en_markers > 0 else "undetermined")

    return ContentAnalysis(
        channel=channel, language_hint=language, signals=signals,
        extracted_domains=domains, extracted_phones_masked=phones,
        analyzed_at=datetime.now(timezone.utc).isoformat(), raw_content_stored=False,
        limitations=[
            "Only extracted text was analyzed; no independent sender or account authentication was performed.",
            "OCR errors, language mixing, sarcasm and context can change interpretation.",
            "A clean phrase-pattern result is not proof that a message or seller is safe.",
        ],
    )
