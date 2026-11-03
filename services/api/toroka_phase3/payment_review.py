from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from decimal import Decimal, InvalidOperation
from typing import Literal


def _amount(value: str | int | float | Decimal | None) -> Decimal | None:
    if value is None or str(value).strip() == "":
        return None
    raw = re.sub(r"[^0-9.,-]", "", str(value)).replace(",", "")
    try:
        result = Decimal(raw)
        if not result.is_finite() or result < 0:
            return None
        return result.quantize(Decimal("0.01"))
    except InvalidOperation:
        return None


def _norm_text(value: str | None) -> str | None:
    if value is None:
        return None
    clean = " ".join(value.casefold().split())
    return clean or None


def _digits(value: str | None) -> str | None:
    if value is None:
        return None
    digits = re.sub(r"\D", "", value)
    return digits or None


@dataclass(slots=True)
class PaymentClaim:
    """Ephemeral values extracted from an order and a user-supplied receipt.

    Do not persist this object unredacted. The receipt is treated as user-supplied,
    not authenticated proof from Safaricom or a bank.
    """
    expected_amount: str | int | float | None = None
    observed_amount: str | int | float | None = None
    expected_recipient_name: str | None = None
    observed_recipient_name: str | None = None
    expected_business_number: str | None = None
    observed_business_number: str | None = None
    expected_account_reference: str | None = None
    observed_account_reference: str | None = None
    transaction_reference_present: bool = False


@dataclass(slots=True)
class PaymentReview:
    status: Literal["mismatch_detected", "details_match_user_claims", "insufficient_details"]
    checks: dict[str, bool | None]
    mismatches: list[str]
    matched_fields: list[str]
    transaction_reference_present: bool
    source_classification: str = "user_supplied_receipt_not_independently_verified"
    payment_confirmed: bool = False
    conclusion: str = "A text or screenshot match does not authenticate an M-PESA transaction or prove the recipient owns the business."
    recommended_action: str = "Check the transaction in the official M-PESA message and contact the merchant through an independently sourced channel."

    def to_dict(self) -> dict:
        return asdict(self)


def review_payment_claim(claim: PaymentClaim) -> PaymentReview:
    checks: dict[str, bool | None] = {}
    mismatches: list[str] = []
    matched: list[str] = []

    exp_amount, obs_amount = _amount(claim.expected_amount), _amount(claim.observed_amount)
    checks["amount_match"] = (exp_amount == obs_amount) if exp_amount is not None and obs_amount is not None else None
    if checks["amount_match"] is False:
        mismatches.append("amount")
    elif checks["amount_match"] is True:
        matched.append("amount")

    exp_name, obs_name = _norm_text(claim.expected_recipient_name), _norm_text(claim.observed_recipient_name)
    checks["recipient_name_match"] = (exp_name == obs_name) if exp_name and obs_name else None
    if checks["recipient_name_match"] is False:
        mismatches.append("recipient_name")
    elif checks["recipient_name_match"] is True:
        matched.append("recipient_name")

    exp_business, obs_business = _digits(claim.expected_business_number), _digits(claim.observed_business_number)
    checks["business_number_match"] = (exp_business == obs_business) if exp_business and obs_business else None
    if checks["business_number_match"] is False:
        mismatches.append("business_number")
    elif checks["business_number_match"] is True:
        matched.append("business_number")

    exp_ref, obs_ref = _norm_text(claim.expected_account_reference), _norm_text(claim.observed_account_reference)
    checks["account_reference_match"] = (exp_ref == obs_ref) if exp_ref and obs_ref else None
    if checks["account_reference_match"] is False:
        mismatches.append("account_reference")
    elif checks["account_reference_match"] is True:
        matched.append("account_reference")

    if mismatches:
        status = "mismatch_detected"
    elif matched:
        status = "details_match_user_claims"
    else:
        status = "insufficient_details"
    return PaymentReview(
        status=status,
        checks=checks,
        mismatches=mismatches,
        matched_fields=matched,
        transaction_reference_present=bool(claim.transaction_reference_present),
    )
