from __future__ import annotations

from dataclasses import dataclass, asdict
from decimal import Decimal, InvalidOperation
import re
from typing import Any

from .models import EvidenceSignal, SOURCE_GROUPS
from .privacy import normalize_ke_phone, safe_excerpt

_AMOUNT_RE = re.compile(r"(?i)(?:transaction\s+amount|amount(?:\s+(?:sent|paid|received))?|ksh|kes)\s*[:=-]?\s*(?:ksh\s*|kes\s*)?([\d,]+(?:\.\d{1,2})?)")
_REFERENCE_RE = re.compile(r"(?i)(?:transaction\s*(?:id|code|reference)?|receipt\s*(?:no|number)?|ref(?:erence)?)\s*[:#=-]?\s*([A-Z0-9]{8,12})\b")
_RECIPIENT_ID_RE = re.compile(r"(?i)(?:paybill|till(?:\s+number)?|business\s+number|account\s+number|mobile\s+number|phone\s+(?:no|number))\s*[:#=-]?\s*(\+?254[\s-]?7\d{2}[\s-]?\d{3}[\s-]?\d{3}|0?7\d{2}[\s-]?\d{3}[\s-]?\d{3}|\d{5,8})\b")
_RECIPIENT_NAME_RE = re.compile(r"(?i)(?:sent\s+to|paid\s+to|recipient|business\s+name|account\s+name)\s*[:=-]\s*([A-Z][A-Z .'-]{2,48})")


def _decimal(raw: str) -> Decimal | None:
    try:
        value = Decimal(raw.replace(",", ""))
        return value if value >= 0 else None
    except InvalidOperation:
        return None


def _masked_reference(raw: str | None) -> str | None:
    if not raw:
        return None
    return raw[:2] + "••••" + raw[-2:]


def _masked_name(raw: str | None) -> str | None:
    if not raw:
        return None
    words = raw.strip().split()
    return " ".join((w[0] + "•••") if w else "" for w in words[:3])


@dataclass(slots=True)
class ReceiptAnalysis:
    parsed_amount: str | None
    masked_transaction_reference: str | None
    recipient_identifier_masked: str | None
    recipient_name_masked: str | None
    amount_match: bool | None
    recipient_identifier_match: bool | None
    recipient_name_match: bool | None
    status: str
    signals: list[EvidenceSignal]
    limitations: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "parsed_amount": self.parsed_amount,
            "masked_transaction_reference": self.masked_transaction_reference,
            "recipient_identifier_masked": self.recipient_identifier_masked,
            "recipient_name_masked": self.recipient_name_masked,
            "amount_match": self.amount_match,
            "recipient_identifier_match": self.recipient_identifier_match,
            "recipient_name_match": self.recipient_name_match,
            "status": self.status,
            "comparison_basis": "user_or_order_expectations_supplied_to_toroka; not independently verified",
            "signals": [s.to_dict() for s in self.signals],
            "limitations": list(self.limitations),
            "payment_verified": False,
        }


def analyze_receipt_text(
    text: str, *, evidence_ref: str, source_group: str = "user_receipt",
    expected_amount: str | int | float | Decimal | None = None,
    expected_recipient_identifier: str | None = None,
    expected_recipient_name: str | None = None,
) -> ReceiptAnalysis:
    """Analyze OCR text for consistency only. This never verifies M-PESA settlement."""
    if not isinstance(text, str) or len(text) > 20_000:
        raise ValueError("receipt text must be at most 20,000 characters")
    if source_group not in SOURCE_GROUPS:
        raise ValueError("invalid source_group")

    amount_match = _AMOUNT_RE.search(text)
    amount = _decimal(amount_match.group(1)) if amount_match else None
    ref_match = _REFERENCE_RE.search(text)
    recipient_match = _RECIPIENT_ID_RE.search(text)
    name_match = _RECIPIENT_NAME_RE.search(text)
    reference = ref_match.group(1).upper() if ref_match else None
    recipient_id = recipient_match.group(1) if recipient_match else None
    recipient_name = name_match.group(1).strip() if name_match else None

    amount_ok: bool | None = None
    if expected_amount is not None and amount is not None:
        expected = _decimal(str(expected_amount))
        if expected is not None:
            amount_ok = amount == expected

    recipient_ok: bool | None = None
    if expected_recipient_identifier and recipient_id:
        exp_phone = normalize_ke_phone(expected_recipient_identifier)
        actual_phone = normalize_ke_phone(recipient_id)
        if exp_phone and actual_phone:
            recipient_ok = exp_phone == actual_phone
        else:
            recipient_ok = re.sub(r"\D", "", expected_recipient_identifier) == re.sub(r"\D", "", recipient_id)

    name_ok: bool | None = None
    if expected_recipient_name and recipient_name:
        name_ok = " ".join(expected_recipient_name.casefold().split()) == " ".join(recipient_name.casefold().split())

    signals: list[EvidenceSignal] = []
    if amount_ok is False:
        signals.append(EvidenceSignal(
            evidence_ref=evidence_ref, source_group=source_group,
            category="receipt_amount_mismatch", severity="high", polarity="risk",
            summary="The amount visible in the receipt text differs from the expected amount.",
            explanation="This is an OCR-derived consistency mismatch. Confirm the original receipt and order details before drawing a conclusion.",
            confidence=0.82, excerpt=safe_excerpt(text),
            limitations=("OCR can misread digits or decimal separators.", "A mismatch does not prove fraud or establish whether money settled."),
        ))
    if recipient_ok is False:
        signals.append(EvidenceSignal(
            evidence_ref=evidence_ref, source_group=source_group,
            category="receipt_recipient_mismatch", severity="high", polarity="risk",
            summary="The visible payment recipient identifier differs from the expected recipient.",
            explanation="The identifier extracted from the supplied receipt text does not match the identifier supplied for this order. Verify against the original message and official transaction record.",
            confidence=0.84, excerpt=safe_excerpt(text),
            limitations=("OCR may confuse digits.", "The comparison does not authenticate ownership of a Till, Paybill or phone number."),
        ))
    if name_ok is False:
        signals.append(EvidenceSignal(
            evidence_ref=evidence_ref, source_group=source_group,
            category="receipt_recipient_name_mismatch", severity="medium", polarity="risk",
            summary="The visible recipient name differs from the expected business or payee name.",
            explanation="Name formats can differ, but the discrepancy should be checked with the merchant through an independently sourced contact channel.",
            confidence=0.68, excerpt=safe_excerpt(text),
            limitations=("OCR and name formatting can cause false mismatches.", "A name mismatch is not proof of wrongdoing."),
        ))

    parsed_fields = sum(x is not None for x in (amount, reference, recipient_id, recipient_name))
    status = "parsed_consistency_check_only" if parsed_fields >= 2 else "insufficient_receipt_fields"
    limitations = [
        "This component analyzes text extracted from an image; it does not authenticate the image or receipt.",
        "A receipt screenshot is not proof that a transaction settled or that funds reached the intended recipient.",
        "Live transaction verification requires an authorized payment-provider or business-side integration.",
        "Only masked identifiers are returned; raw OCR text is not retained by this package.",
    ]
    return ReceiptAnalysis(
        parsed_amount=str(amount) if amount is not None else None,
        masked_transaction_reference=_masked_reference(reference),
        recipient_identifier_masked=(recipient_id[:2] + "•••" + recipient_id[-2:]) if recipient_id else None,
        recipient_name_masked=_masked_name(recipient_name),
        amount_match=amount_ok, recipient_identifier_match=recipient_ok,
        recipient_name_match=name_ok, status=status, signals=signals, limitations=limitations,
    )
