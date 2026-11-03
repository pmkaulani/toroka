"""Text signals: small, readable, individually testable rules.

Rules never accuse a person. They describe a pattern in the text and say why it matters.
Input is treated strictly as data: nothing in it is ever executed or obeyed.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .normalize import ParsedUrl, extract_phones
from .vocabulary import ClaimStatus, EvidenceType, Strength


@dataclass
class Finding:
    code: str
    evidence_type: EvidenceType
    strength: Strength
    plain_text: str
    why_it_matters: str
    excerpt: str | None = None
    start: int | None = None
    end: int | None = None
    source_id: str | None = None
    needs_external_verification: bool = False
    claim_status: ClaimStatus | None = None
    polarity: str = "risk"             # "positive" findings (verified records) never raise risk and never count as a warning
    # Evidence separation and provenance fields (Quality Standard Spec 5)
    source: str | None = None
    date: str | None = None
    target_match: str | None = None          # "exact", "domain", "associated", "unverified"
    verification_status: str | None = None   # "confirmed", "observed", "reported", "unverified", "contradictory", "unavailable"
    reliability: str | None = None           # "high", "moderate", "low", "unverified"
    limitations: str | None = None


# --- credential masking (before any scanning, so excerpts can never leak values) ---
_CRED_VALUE_RE = re.compile(r"(?i)\b(pin|otp|password|passcode|code|nywila)\b(\s*(?:is|was|ni|:|=)?\s*)(?P<val>\d{4,8}\b|•{4,8})")


def mask_credential_values(text: str) -> tuple[str, bool]:
    """Replace PIN/OTP-like values with bullets, preserving length so offsets still line up."""
    found = False

    def _sub(m: re.Match) -> str:
        nonlocal found
        found = True
        return m.group(0)[: m.start("val") - m.start()] + "•" * len(m.group("val"))

    return _CRED_VALUE_RE.sub(_sub, text), found


# --- helpers -----------------------------------------------------------------
_NEGATION_TAIL = re.compile(r"(?i)(?:do not|don't|dont|never|will not|won't|usi\w*|no|without)\s+(?:ever\s+)?$")


def _negated(text: str, start: int) -> bool:
    """True for warnings like 'never share your PIN' (a genuine safety message)."""
    return bool(_NEGATION_TAIL.search(text[max(0, start - 20): start]))


def _excerpt(text: str, start: int, end: int, pad: int = 0) -> str:
    return text[max(0, start - pad): min(len(text), end + pad)].strip()


# --- rules -------------------------------------------------------------------
_SECRET = (r"(?:m-?pesa\s+)?(?:pin|otp|password|passcode|verification\s+code|one[- ]time\s+(?:pin|password|code)"
           r"|nywila|namba\s+ya\s+siri)")
_PIN_ASK = re.compile(r"(?i)\b(?:share|send|give|provide|confirm|enter|tell|reply(?:\s+with)?|tuma|toa|nipe|ingiza|thibitisha)\b"
                      r"[^.!?]{0,100}?\b" + _SECRET + r"\b")
_PIN_NEEDED = re.compile(r"(?i)\b(?:pin|otp|password|passcode)\b[^.\n]{0,25}\b(?:required|needed|to\s+verify|to\s+confirm|to\s+activate|to\s+reverse)\b")


def pin_or_otp_request(text: str) -> list[Finding]:
    for rx in (_PIN_ASK, _PIN_NEEDED):
        for m in rx.finditer(text):
            if _negated(text, m.start()) or re.search(r"(?i)\bkra\s+pin\b", m.group(0)):
                continue
            return [Finding(
                "PIN_OR_OTP_REQUEST", EvidenceType.AUTOMATED_OBSERVATION, Strength.SUPPORTING,
                "The message asks you to share a PIN, password or one-time code.",
                "Banks, mobile-money providers and government offices do not need you to send them a secret code by message or call.",
                _excerpt(text, m.start(), m.end()), m.start(), m.end())]
    return []


_FEE_KIND = (r"(?:activation|processing|clearance|registration|release|admin(?:istration)?|customs|facilitation|unlock(?:ing)?|application)"
             r"\s+(?:fee|charge|cost|payment)s?")
_PAY_VERB = r"(?:pay|send|deposit|lipa|tuma|transfer|remit)"
_FEE_PATTERNS = [
    re.compile(r"(?i)\b" + _PAY_VERB + r"\b[^.!?]{0,120}?\b" + _FEE_KIND + r"\b"),
    re.compile(r"(?i)\b" + _PAY_VERB + r"\b[^.!?]{0,120}?\bto\s+(?:activate|unlock|release|claim|receive|withdraw|process|clear|apply)\b"),
    re.compile(r"(?i)\b" + _FEE_KIND + r"\b[^.!?]{0,100}?\b(?:required|payable|is\s+due|must\s+be\s+paid|is\s+needed|needed|needs?|requires?)\b"),
    re.compile(r"(?i)\b" + _FEE_KIND + r"\b[^.!?]{0,100}?\b" + _PAY_VERB + r"\b"),
]


def advance_fee_request(text: str) -> list[Finding]:
    for rx in _FEE_PATTERNS:
        m = rx.search(text)
        if m and not _negated(text, m.start()):
            return [Finding(
                "ADVANCE_FEE_REQUEST", EvidenceType.AUTOMATED_OBSERVATION, Strength.SUPPORTING,
                "The message asks for money up front before you receive something.",
                "An upfront payment is a warning sign. Some real organisations do charge fees, so we could not confirm this one is part of an official process.",
                _excerpt(text, m.start(), m.end()), m.start(), m.end(), needs_external_verification=True)]
    return []


_PRIZE = re.compile(r"(?i)\b(?:you(?:'ve|\s+have)?\s+(?:won|been\s+selected|been\s+chosen)|congratulations|umeshinda|umechaguliwa|winner)\b")


def prize_or_benefit_claim(text: str) -> list[Finding]:
    m = _PRIZE.search(text)
    if not m:
        return []
    return [Finding("PRIZE_OR_BENEFIT_CLAIM", EvidenceType.UNRESOLVED_CLAIM, Strength.WEAK,
                    "The message says you have won or been selected for something.",
                    "Real prizes and programmes exist, so this alone proves nothing. It matters when combined with a payment or link request.",
                    _excerpt(text, m.start(), m.end()), m.start(), m.end(), needs_external_verification=True)]


_GAMBLING_BONUS = re.compile(
    r"(?i)\b(?:free\s+(?:bets?|betting|freespins?|casino\s+bonus)|freebets?|aviator\s+(?:freebets?|bonus)|casino\s+bonus|betting\s+bonus|sportsbook\s+bonus)\b"
)


def gambling_bonus_promotion(text: str) -> list[Finding]:
    m = _GAMBLING_BONUS.search(text)
    if not m:
        return []
    return [Finding(
        "GAMBLING_BONUS_PROMOTION", EvidenceType.UNRESOLVED_CLAIM, Strength.WEAK,
        "The message appears to advertise a betting or casino promotion.",
        "Promotional wording alone does not show that the message is fraudulent or genuine. The sender, exact domain, promotion terms and any request for money or credentials need separate verification. Free bets are not cash or guaranteed earnings; gambling is for adults and carries financial risk.",
        _excerpt(text, m.start(), m.end()), m.start(), m.end(), needs_external_verification=True,
        polarity="unresolved")]


_URGENCY = re.compile(r"(?i)\b(?:within\s+\d+\s*(?:hours?|hrs?|minutes?|mins?)|immediately|urgent(?:ly)?|act\s+now|expires?\s+(?:today|soon|tonight)|last\s+chance|haraka|sasa\s+hivi)\b")


def urgency_pressure(text: str) -> list[Finding]:
    m = _URGENCY.search(text)
    if not m:
        return []
    return [Finding("URGENCY_PRESSURE", EvidenceType.AUTOMATED_OBSERVATION, Strength.WEAK,
                    "The message pushes you to act quickly.",
                    "Pressure to hurry is common in scams, and also in genuine reminders, so it is only a weak signal.",
                    _excerpt(text, m.start(), m.end()), m.start(), m.end())]


_REVERSAL = [
    re.compile(r"(?i)\b(?:sent|transferred|deposited)\b[^.\n]{0,50}\b(?:by\s+mistake|in\s+error|wrongly|wrong\s+number)\b"),
    re.compile(r"(?i)\b(?:nime(?:kutumia|tuma|kuwekea)|tumetuma)\b[^.\n]{0,50}\b(?:kimakosa|kwa\s+makosa)\b"),
]
_BACK = re.compile(r"(?i)\b(?:send|return|reverse|refund)\b[^.\n]{0,15}\bback\b")
_MONEYISH = re.compile(r"(?i)\b(?:ksh?s?|kes|money|pesa|cash|m-?pesa)\b")


def wrong_transfer_reversal(text: str) -> list[Finding]:
    hit = next((m for rx in _REVERSAL if (m := rx.search(text))), None)
    if not hit:
        b = _BACK.search(text)
        hit = b if (b and _MONEYISH.search(text) and re.search(r"(?i)mistake|error|wrong|makosa", text)) else None
    if not hit:
        return []
    return [Finding("WRONG_TRANSFER_REVERSAL", EvidenceType.AUTOMATED_OBSERVATION, Strength.SUPPORTING,
                    "The message says money was sent to you by mistake and asks for it back.",
                    "Fake 'sent by mistake' messages are a known trick. Check your balance by SMS or in the M-PESA app before sending anything.",
                    _excerpt(text, hit.start(), hit.end()), hit.start(), hit.end(), needs_external_verification=True)]


def shortened_url(urls: list[ParsedUrl], text: str) -> list[Finding]:
    for u in urls:
        if u.is_shortener:
            return [Finding("SHORTENED_URL", EvidenceType.AUTOMATED_OBSERVATION, Strength.WEAK,
                            "The message uses a shortened link, so the real destination is hidden.",
                            "Shortened links are used by genuine senders too. The destination has not been checked here.",
                            _excerpt(text, u.start, u.end), u.start, u.end)]
    return []


_PAY_CTX = re.compile(r"(?i)\b" + _PAY_VERB + r"\b[^.\n]{0,50}$")


def payment_to_mobile_number(text: str) -> list[Finding]:
    for p in extract_phones(text):
        before = text[max(0, p.start - 60): p.start]
        if _PAY_CTX.search(before) and not _negated(text, p.start - 5):
            return [Finding("PAYMENT_TO_MOBILE_NUMBER", EvidenceType.AUTOMATED_OBSERVATION, Strength.WEAK,
                            "The message asks you to send money to an ordinary mobile number.",
                            "Many genuine sellers use personal numbers. It is a reason to confirm who owns the number before paying.",
                            _excerpt(text, max(0, p.start - 25), min(len(text), p.end + 25)), max(0, p.start - 25), min(len(text), p.end + 25), needs_external_verification=True)]
    return []


_ADV = [
    re.compile(r"(?i)\b(?:pay|send|deposit|lipa|tuma|transfer)\b[^.!?]{0,100}?\b(?:in\s+advance|up-?front|half(?:\s+of\s+(?:it|the\s+\w+))?\s+(?:payment|upfront|first|now)|50\s?%\s+(?:deposit|first|now|upfront)|deposit\s+first|before\s+(?:delivery|we\s+deliver|you\s+receive|collection)|to\s+(?:reserve|book|secure)|mapema)\b"),
    re.compile(r"(?i)\b(?:a\s+)?(?:deposit|half\s+payment|advance\s+payment|booking\s+fee|reservation\s+fee)\b[^.\n]{0,25}?\b(?:first|required|upfront|up-front|before\s+(?:delivery|collection))\b"),
]


def advance_payment_request(text: str) -> list[Finding]:
    for rx in _ADV:
        m = rx.search(text)
        if m and not _negated(text, m.start()):
            return [Finding("ADVANCE_PAYMENT_REQUEST", EvidenceType.AUTOMATED_OBSERVATION, Strength.SUPPORTING,
                            "The message asks you to pay in advance, even partly.",
                            "An advance payment can be legitimate in some contexts, but a request to pay before receiving a promised item or benefit is a reason to verify the recipient, written terms, refund method and any buyer protection independently.",
                            _excerpt(text, m.start(), m.end()), m.start(), m.end(), needs_external_verification=True)]
    return []


_TASK_SCAM = [
    re.compile(r"(?i)\b(?:like|watch|subscribe|follow)\b[^.!?]{0,100}\b(?:videos?|youtube|tiktok|reels?|posts?|channels?)\b[^.\n]{0,50}\b(?:earn|paid|daily|ksh|kes|\$|salary)\b"),
    re.compile(r"(?i)\b(?:earn|daily\s+income|daily\s+pay)\b[^.!?]{0,100}\b(?:ksh|kes)?\s*\d{3,5}\b[^.\n]{0,50}\b(?:telegram|whatsapp|tiktok|task|online\s+job|work\s+from\s+home)\b"),
    re.compile(r"(?i)\b(?:online\s+writing|data\s+entry|rating\s+products?)\b[^.!?]{0,100}\b(?:earn|daily|weekly|bonus)\b[^.!?]{0,100}\b(?:telegram|whatsapp)\b"),
]


def task_scam_lure(text: str) -> list[Finding]:
    for rx in _TASK_SCAM:
        m = rx.search(text)
        if m and not _negated(text, m.start()):
            return [Finding("TASK_SCAM_LURE", EvidenceType.AUTOMATED_OBSERVATION, Strength.SUPPORTING,
                            "The message promotes earning money for simple online tasks (like watching videos or liking posts).",
                            "Pay-per-task schemes ('TikTok/Telegram promotion teams') are widespread scams in Kenya. They initially pay small rewards to build trust, then demand a deposit or 'VIP upgrade fee' before locking your funds.",
                            _excerpt(text, m.start(), m.end()), m.start(), m.end(), needs_external_verification=True)]
    return []


_RECRUIT_KW = re.compile(r"(?i)\b(?:hiring|recruit\w*|vacanc\w+|job\s+offer|cleaners?|drivers?|storekeepers?|receptionists?|security\s+guards?|office\s+assistants?)\b")
_PERSONAL_APPLY = re.compile(r"(?i)\b(?:whatsapp|wa\.me|dm\s+to|apply\s+(?:via|to)|send\s+cv\s+to)\b[^.!?]{0,100}\b(?:\+?254|0)[17]\d{8}\b")


def recruitment_personal_channel(text: str) -> list[Finding]:
    m_rec = _RECRUIT_KW.search(text)
    if m_rec and not _negated(text, m_rec.start()):
        m_app = _PERSONAL_APPLY.search(text)
        if m_app:
            start = min(m_rec.start(), m_app.start())
            end = max(m_rec.end(), m_app.end())
            return [Finding("RECRUITMENT_PERSONAL_CHANNEL", EvidenceType.AUTOMATED_OBSERVATION, Strength.SUPPORTING,
                            "The job or vacancy directs applicants to a personal WhatsApp number.",
                            "Legitimate institutions, corporate employers, and hospitals use official career portals. Fraudulent recruiters use personal WhatsApp lines and later ask for 'medical examination', 'uniform', or 'interview booking' fees.",
                            _excerpt(text, start, end), start, end, needs_external_verification=True)]
    return []


_PRICE_OUTLIER = re.compile(r"(?i)\b(?:iphone\s*(?:1[1-6]|pro|promax|max)|macbook|ps5|playstation\s*5)\b[^.\n]{0,80}\b(?:ksh?|kes)?\s*(?:1[0-9]|2[0-9]|3[0-5])[,\.]?000\b")


def price_outlier_risk(text: str) -> list[Finding]:
    m = _PRICE_OUTLIER.search(text)
    if m and not _negated(text, m.start()):
        return [Finding("PRICE_OUTLIER_RISK", EvidenceType.AUTOMATED_OBSERVATION, Strength.SUPPORTING,
                        "High-value electronics offered at an unrealistically steep discount or impossible price.",
                        "Scammers advertise brand new high-end items at 70-80% below market price to entice buyers into paying advance deposits or courier fees before vanishing.",
                        _excerpt(text, m.start(), m.end()), m.start(), m.end(), needs_external_verification=True)]
    return []


_MPESA_RECEIPT = re.compile(r"(?i)\b[A-Z0-9]{10}\s+Confirmed\.?\s*(?:Ksh|KES)\s*[\d,]+(?:\.\d{2})?\s+(?:received\s+from|sent\s+to|paid\s+to|deposited\b)")


def mpesa_sms_receipt_notice(text: str) -> list[Finding]:
    m = _MPESA_RECEIPT.search(text)
    if m:
        return [Finding("MPESA_SMS_NOTICE", EvidenceType.AUTOMATED_OBSERVATION, Strength.WEAK,
                        "The message is formatted as an M-PESA SMS confirmation.",
                        "SMS messages can be easily forged or sent from ordinary numbers. Always verify received funds by checking your actual balance via *334# or the M-PESA app before releasing goods or refunding money.",
                        _excerpt(text, m.start(), m.end()), m.start(), m.end(), polarity="neutral")]
    return []


_PAID_TERMS = re.compile(
    r"(?i)\b(?:i\s+(?:s[ea]nd|s[ea]nt|paid|pay|transferred|gave|bought|ordered)|"
    r"already\s+(?:paid|s[ea]nt?|transferred)|we\s+(?:paid|s[ea]nt?)|"
    r"nimetuma|nililipa|tumetuma|tulinunua|nimenunua|alichukua\s+(?:pesa|chapaa|ganji))\b"
)
_NEG_TERMS = re.compile(
    r"(?i)\b(?:did\s*not|never|didn'?t|not|no|haven'?t|hasn'?t|refused\s+to|failed\s+to|"
    r"hawaja\w*|bila|without|hajaniletea|hajatuma|hakuleta)\b"
)
_DELIVERY_TERMS = re.compile(
    r"(?i)\b(?:del[ei]{1,2}ver\w*|receive\w*|arrive\w*|send\s+the|goods|items?|package|parcel|order|"
    r"shoes|phone|clothes|electronics|tv|mzigo|bidhaa|vitu)\b"
)
_SCAM_DIRECT = re.compile(
    r"(?i)\b(?:scammed\s+me|conned\s+me|stole\s+my\s+money|took\s+my\s+money|lost\s+my\s+money|"
    r"wameniibia|nimetapeliwa|wameniblock|blocked\s+me|fake\s+(?:seller|shop|page)|scam\s+(?:seller|shop|page)|"
    r"walinilaghai)\b"
)
_BLOCKED_TERMS = re.compile(
    r"(?i)\b(?:blocked\s+me|wameniblock|hapatikani|switched\s+off|cut\s+me\s+off|disappeared|vanished)\b"
)


def reported_incident_check(text: str) -> list[Finding]:
    m_direct = _SCAM_DIRECT.search(text)
    m_paid = _PAID_TERMS.search(text)
    m_neg = _NEG_TERMS.search(text)
    m_del = _DELIVERY_TERMS.search(text)
    m_block = _BLOCKED_TERMS.search(text)

    if m_direct or (m_paid and m_neg and m_del) or (m_paid and m_block):
        start = m_direct.start() if m_direct else m_paid.start()
        end = m_direct.end() if m_direct else max(m_paid.end(), m_neg.end() if m_neg else 0, m_del.end() if m_del else 0, m_block.end() if m_block else 0)
        return [Finding("REPORTED_FRAUD_INCIDENT", EvidenceType.UNRESOLVED_CLAIM, Strength.STRONG,
                        "You describe paying for goods or services that were not delivered, or being defrauded.",
                        "Non-delivery after advance payment is the most common online shopping scam in Kenya. Scammers take payment and block the buyer. Do not send any additional 'clearance' or 'courier fee'. Take immediate recovery steps.",
                        _excerpt(text, start, end), start, end, needs_external_verification=True)]
    return []


_FAKE_INVOICE_GENERATOR = re.compile(
    r"(?i)\b(?:invoicebase|invoicemaker|invoice\s*simple|zoho\s*invoice|wave\s*invoice|billdu|canva\s*invoice|"
    r"inv-?0{2,5}[1-9]\b|invoice\s*#?\s*inv-?0{2,5}[1-9]\b|invoice\s*#?\s*0{3,5}[1-9]\b)"
)


def fake_invoice_generator_notice(text: str) -> list[Finding]:
    m = _FAKE_INVOICE_GENERATOR.search(text)
    if m:
        return [Finding("FAKE_INVOICE_GENERATOR", EvidenceType.AUTOMATED_OBSERVATION, Strength.WEAK,
                        "The submitted text contains a consumer invoice-template name or starter-style invoice number.",
                        "Template names and sequential invoice numbers can appear on legitimate invoices too. This is only a clue; check the issuer independently and whether the document is paired with a request to pay a fee to release a promised payout.",
                        _excerpt(text, m.start(), m.end()), m.start(), m.end(), needs_external_verification=True)]
    return []


_REDEMPTION_ADVANCE_FEE = re.compile(
    r"(?i)\b(?:redemption|reward\s+claim|(?:inheritance|grant|funds?|winnings?|lottery|prize|commission|settlement)?\s*payout|payout\s+of|prize\s+redemption|commission\s+release|payout\s+release|settlement\s+release)\b"
)


def foreign_redemption_or_payout_risk(text: str) -> list[Finding]:
    m = _REDEMPTION_ADVANCE_FEE.search(text)
    if not m:
        return []
    has_invoice_or_foreign = bool(re.search(r"(?i)(?:invoice|bill\s+to|subtotal|due\s+date|balance\s+due|[\*+]44|[\*+]1|[\*+]234|[€$£]|eur|usd|gbp|cooo|eooo)", text))

    # The word “redemption” and foreign currency alone are not proof. A request for
    # money in order to release the supposed payout is the materially stronger signal.
    # Search across OCR line breaks, but stop at sentence punctuation so unrelated
    # paragraphs are not joined into a false fee request.
    asks_release_fee = bool(re.search(
        r"(?is)(?:\b(?:pay|send|transfer|deposit|lipa|tuma)\b[^.!?]{0,160}"
        r"\b(?:fee|tax|clearance|release|conversion|processing|activation|customs|withdrawal)\b"
        r"|\b(?:fee|tax|clearance|release|conversion|processing|activation|customs|withdrawal)\b[^.!?]{0,160}"
        r"\b(?:pay|send|transfer|deposit|lipa|tuma)\b"
        r"|\b(?:pay|send|transfer|deposit|lipa|tuma)\b[^.!?]{0,160}"
        r"\b(?:before|to|for)\s+(?:the\s+)?(?:release|unlock|withdrawal|withdraw|payout|redemption|funds|money)\b)", text))
    # An explicit fee to release a claimed reward/payout is itself the key pattern;
    # invoice formatting or a foreign currency is not a prerequisite.
    if not (has_invoice_or_foreign or asks_release_fee):
        return []
    strength = Strength.SUPPORTING if asks_release_fee else Strength.WEAK
    why = (
        "The text couples a promised payout with a request for an upfront fee. That is a common advance-fee scam pattern. "
        "The document alone does not verify whether the payout exists or who issued it; independently verify the issuer and payment recipient."
        if asks_release_fee else
        "A foreign-currency amount or the word 'redemption' alone does not establish fraud. Verify the issuer and check whether anyone is asking you to pay money to release the promised funds."
    )
    return [Finding("REDEMPTION_PAYOUT_TRAP", EvidenceType.AUTOMATED_OBSERVATION, strength,
                    "The submitted text combines a redemption/payout term with invoice-like or foreign-currency details.",
                    why, _excerpt(text, m.start(), m.end()), m.start(), m.end(), needs_external_verification=True)]


_JKIA_CUSTOMS_PARCEL = re.compile(
    r"(?i)\b(?:diplomatic\s+parcel|jkia\s+customs|gift\s+box(?:\s+(?:clearance|held|stuck))?|"
    r"parcel\s+(?:held|stuck|intercepted)\s+at\s+(?:airport|jkia|customs)|"
    r"held\s+as\s+parcel\s+at\s+(?:airport|jkia|customs)|anti[- ]money\s+laundering\s+clearance)\b"
)


def jkia_customs_parcel_risk(text: str) -> list[Finding]:
    # Generic words such as "clearance fee" also appear on legitimate invoices.
    # Require both a specific overseas/airport/diplomatic-parcel clue and an actual
    # fee request before applying this specialised pattern. Either part alone is insufficient.
    m = _JKIA_CUSTOMS_PARCEL.search(text)
    fee_requested = bool(advance_fee_request(text) or advance_payment_request(text))
    if m and fee_requested and not _negated(text, m.start()):
        return [Finding("DIPLOMATIC_PARCEL_CUSTOMS_TRAP", EvidenceType.AUTOMATED_OBSERVATION, Strength.SUPPORTING,
                        "The message refers to a diplomatic parcel, gift box, airport customs, or a related clearance claim.",
                        "This wording is associated with parcel-clearance scams, but the phrase alone does not prove fraud. Independently check the shipment with the named courier or customs authority using contact details you find yourself, and be especially cautious if a personal recipient demands an unexplained release fee.",
                        _excerpt(text, m.start(), m.end()), m.start(), m.end(), needs_external_verification=True)]
    return []


_ADVANCE_DELIVERY_FEE_TRAP = re.compile(
    r"(?i)\b(?:no\s+pay\s+on\s+delivery|pay\s+(?:before|prior\s+to)\s+delivery|rider\s+(?:fee|money)\s+(?:first|before|in\s+advance)|"
    r"delivery\s+(?:is\s+)?paid\s+first|deposit\s+before\s+(?:delivery|dispatch))\b"
)


def advance_delivery_fee_trap(text: str) -> list[Finding]:
    m = _ADVANCE_DELIVERY_FEE_TRAP.search(text)
    if m and not _negated(text, m.start()):
        return [Finding("ADVANCE_DELIVERY_FEE_TRAP", EvidenceType.AUTOMATED_OBSERVATION, Strength.SUPPORTING,
                        "The message says the seller refuses pay-on-delivery and asks for an upfront delivery or rider fee before dispatch.",
                        "This combination merits verification, particularly if the recipient cannot be independently identified, the tracking details cannot be confirmed, or the seller uses pressure. Some legitimate sellers and couriers charge in advance, so the request alone does not prove fraud.",
                        _excerpt(text, m.start(), m.end()), m.start(), m.end(), needs_external_verification=True)]
    return []


_VIEWING_FEE_TRAP = re.compile(
    r"(?i)\b(?:viewing\s+fee|viewing\s+charge|fee\s+to\s+view|deposit\s+before\s+viewing|ada\s+ya\s+kuona\s+nyumba)\b"
)


def viewing_fee_trap(text: str) -> list[Finding]:
    m = _VIEWING_FEE_TRAP.search(text)
    if m and not _negated(text, m.start()):
        return [Finding("VIEWING_FEE_TRAP", EvidenceType.AUTOMATED_OBSERVATION, Strength.SUPPORTING,
                        "Upfront 'viewing fee' or fuel deposit demanded before viewing a house or bedsitter.",
                        "Legitimate Kenyan caretakers, landlords, and registered real estate agents do not charge viewing fees to inspect rental premises. Scammers post attractive apartment photos online and pocket viewing fees from multiple prospective tenants before switching off their phones.",
                        _excerpt(text, m.start(), m.end()), m.start(), m.end(), needs_external_verification=True)]
    return []


TEXT_RULES = [pin_or_otp_request, advance_fee_request, advance_payment_request, prize_or_benefit_claim, gambling_bonus_promotion, urgency_pressure,
              wrong_transfer_reversal, payment_to_mobile_number, task_scam_lure, recruitment_personal_channel,
              price_outlier_risk, mpesa_sms_receipt_notice, reported_incident_check,
              fake_invoice_generator_notice, foreign_redemption_or_payout_risk,
              jkia_customs_parcel_risk, advance_delivery_fee_trap, viewing_fee_trap]
