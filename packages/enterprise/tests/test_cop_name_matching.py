"""Unit and integration tests for Confirmation of Payee (CoP) Engine."""
import pytest
from toroka_enterprise.integrations.cop import (
    ConfirmationOfPayeeEngine,
    CopAccountType,
    CopInquiryRequest,
    CopStatus,
    CopVerificationResult,
)


def test_cop_exact_name_match():
    req = CopInquiryRequest(
        intended_name="Patrick Mwangi",
        registered_name="Patrick Mwangi",
        account_number="01100998877",
        account_type=CopAccountType.PERSONAL,
    )
    result = ConfirmationOfPayeeEngine.verify(req)

    assert result.status == CopStatus.MATCH
    assert result.match_score == 1.0
    assert result.reason_code == "EXACT_NAME_MATCH"
    assert result.suggested_name is None
    assert len(result.inquiry_digest) == 64


def test_cop_token_permutation_match():
    # Surname first vs given name first
    req = CopInquiryRequest(
        intended_name="Mwangi Patrick",
        registered_name="Patrick Mwangi",
        account_number="01100998877",
    )
    result = ConfirmationOfPayeeEngine.verify(req)

    assert result.status == CopStatus.MATCH
    assert result.match_score >= 0.95
    assert result.reason_code == "TOKEN_PERMUTATION_MATCH"
    assert result.suggested_name is None


def test_cop_initials_and_surname_expansion():
    # Intended has middle initial; registered has full middle name
    req = CopInquiryRequest(
        intended_name="Patrick K. Mwangi",
        registered_name="Patrick Kariuki Mwangi",
        account_number="01100998877",
    )
    result = ConfirmationOfPayeeEngine.verify(req)

    assert result.status == CopStatus.MATCH
    assert result.match_score >= 0.90
    assert result.reason_code == "INITIALS_EXPANSION_MATCH"


def test_cop_business_name_suffix_canonicalization():
    # Ltd vs Limited, Enterprises vs Ent
    req = CopInquiryRequest(
        intended_name="Kamau Ent Ltd",
        registered_name="Kamau Enterprises Limited",
        account_number="02200334455",
        account_type=CopAccountType.BUSINESS,
    )
    result = ConfirmationOfPayeeEngine.verify(req)

    assert result.status == CopStatus.MATCH
    assert result.match_score >= 0.95
    assert result.reason_code in ("EXACT_NAME_MATCH", "TOKEN_PERMUTATION_MATCH", "TOKEN_SUBSET_MATCH")


def test_cop_paybill_prefix_stripping():
    # Paybill prefix on registered name
    req = CopInquiryRequest(
        intended_name="Safaricom PLC",
        registered_name="Paybill 522522 - Safaricom PLC",
        account_number="522522",
        account_type=CopAccountType.BUSINESS,
    )
    result = ConfirmationOfPayeeEngine.verify(req)

    assert result.status == CopStatus.MATCH
    assert result.match_score >= 0.95


def test_cop_close_match_typo():
    # Slight spelling error gives CLOSE_MATCH with suggested name
    req = CopInquiryRequest(
        intended_name="Patrik Mwangi",
        registered_name="Patrick Mwangi",
        account_number="01100998877",
    )
    result = ConfirmationOfPayeeEngine.verify(req)

    assert result.status == CopStatus.CLOSE_MATCH
    assert 0.65 <= result.match_score < 0.88
    assert result.suggested_name == "Patrick Mwangi"
    assert "Close Match" in result.advisory_message


def test_cop_no_match_impersonation_detection():
    # Complete mismatch / impersonation attempt
    req = CopInquiryRequest(
        intended_name="Safaricom Customer Care",
        registered_name="Daniel Kipchoge",
        account_number="0712345678",
    )
    result = ConfirmationOfPayeeEngine.verify(req)

    assert result.status == CopStatus.NO_MATCH
    assert result.match_score < 0.65
    assert result.suggested_name is None
    assert "Warning - No Match" in result.advisory_message
    assert result.reason_code == "LOW_SIMILARITY_NO_MATCH"


def test_cop_empty_name_edge_case():
    req = CopInquiryRequest(
        intended_name="",
        registered_name="Valid Name",
        account_number="12345",
    )
    result = ConfirmationOfPayeeEngine.verify(req)

    assert result.status == CopStatus.NO_MATCH
    assert result.match_score == 0.0
    assert result.reason_code == "EMPTY_NAME_NO_MATCH"


def test_cop_sub_millisecond_latency():
    import time
    req = CopInquiryRequest(
        intended_name="John Kariuki Kamau Enterprises Limited",
        registered_name="Kamau John Kariuki Enterprises Ltd",
        account_number="99887766",
        account_type=CopAccountType.BUSINESS,
    )
    t0 = time.perf_counter()
    for _ in range(100):
        ConfirmationOfPayeeEngine.verify(req)
    t1 = time.perf_counter()
    avg_ms = ((t1 - t0) / 100) * 1000.0
    assert avg_ms < 1.0  # Must be sub-millisecond per verification
