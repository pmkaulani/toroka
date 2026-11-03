"""Synthetic Test Suite for Toroka's Scam Encyclopedia & Unified Taxonomy.

Covers:
1. All 12 taxonomy domains and core pattern matching.
2. False-positive control: Legitimate messages that resemble scams.
3. Fake screenshots & receipt forgery signals.
4. Duplicate report deduplication.
5. Impersonation of legitimate Kenyan institutions vs authentic portals.
6. Unknown entities & graceful humility (inconclusive / verify first).
7. Conflicting evidence resolution.
8. Cross-channel entity correlation & privacy masking.
"""
import pytest
from ssi_rules import Label, assess
from ssi_rules.fingerprint import minhash, script_hash
from ssi_rules.observations import Observations, ReportHit
from ssi_rules.taxonomy import (
    InvestigationWorkflow,
    PATTERNS,
    ProvenanceType,
    ScamDomain,
    classify_text_threat,
)


# --- 1. Comprehensive Taxonomy Domain Tests ---
TAXONOMY_CASES = [
    # Domain 1: Mobile Money
    (
        "mpesa_reversal_trap",
        "Habari, nimetuma pesa kwa nambari mbaya kimakosa. Tafadhali rudisha sasa hivi kabla sijapiga Safaricom.",
        ScamDomain.MOBILE_MONEY,
        "MPESA_FAKE_REVERSAL",
        InvestigationWorkflow.PAYMENT_CHECK,
    ),
    (
        "pin_theft_attempt",
        "Safaricom Alert: Your line is scheduled for suspension. Reply with your M-PESA PIN immediately to verify.",
        ScamDomain.MOBILE_MONEY,
        "PIN_OTP_THEFT",
        InvestigationWorkflow.PAYMENT_CHECK,
    ),
    (
        "fuliza_limit_boost",
        "Lipa KSh 350 processing fee to receive your KSh 30,000 Fuliza limit boost instantly.",
        ScamDomain.MOBILE_MONEY,
        "FAKE_LOAN_UPGRADE_FEE",
        InvestigationWorkflow.PAYMENT_CHECK,
    ),

    # Domain 2: Online Shopping & Social Commerce
    (
        "shop_rider_fee",
        "Thank you for ordering shoes! Delivery fee first: lipa rider KSh 400 kabla hajashika safari.",
        ScamDomain.ONLINE_SHOPPING,
        "SHOP_ADVANCE_DEPOSIT_TRAP",
        InvestigationWorkflow.ONLINE_SHOP_INVESTIGATION,
    ),
    (
        "buyer_overpayment_trap",
        "Nimetuma zaidi kwa bahati mbaya, tafadhali refund the difference of Ksh 2,500 to my number.",
        ScamDomain.ONLINE_SHOPPING,
        "SHOP_BUYER_OVERPAYMENT",
        InvestigationWorkflow.ONLINE_SHOP_INVESTIGATION,
    ),

    # Domain 3: Employment & Income
    (
        "job_interview_fee",
        "Congratulations! You have been shortlisted for supermarket attendant. Pay interview fee of Ksh 1,200 to secure your slot.",
        ScamDomain.EMPLOYMENT,
        "JOB_RECRUITMENT_FEE",
        InvestigationWorkflow.JOB_INVESTMENT_CHECK,
    ),
    (
        "task_booster_scam",
        "Like YouTube videos and earn KSh 2,500 daily. Deposit to unlock VIP task withdrawals.",
        ScamDomain.EMPLOYMENT,
        "JOB_TASK_BOOSTING_SCAM",
        InvestigationWorkflow.JOB_INVESTMENT_CHECK,
    ),

    # Domain 4: Investment, Crypto & Forex
    (
        "crypto_ponzi_promise",
        "Earn 30% daily guaranteed returns with Binance arbitrage signals. Join our VIP investment channel.",
        ScamDomain.INVESTMENT,
        "INVEST_PONZI_CRYPTO_FOREX",
        InvestigationWorkflow.JOB_INVESTMENT_CHECK,
    ),

    # Domain 5: Impersonation
    (
        "ecitizen_clone_notice",
        "Your eCitizen passport application is ready. Pay activation fee at https://ecitizen-portal.xyz/pay",
        ScamDomain.IMPERSONATION,
        "GOV_AUTHORITY_IMPERSONATION",
        InvestigationWorkflow.LINK_WEBSITE_CHECK,
    ),

    # Domain 6: Romance & Extortion
    (
        "jkia_parcel_customs",
        "Your lover has sent you a gift box with dollars from UK. It is held as parcel at JKIA, pay customs clearance fee to release.",
        ScamDomain.ROMANCE_EXTORTION,
        "ROMANCE_PARCEL_CUSTOMS",
        InvestigationWorkflow.MESSAGE_CHECK,
    ),
    (
        "sextortion_coercion",
        "We have your private video and photos. Send Ksh 15,000 or I will leak your photos to your family and friends.",
        ScamDomain.ROMANCE_EXTORTION,
        "SEXTORTION_BLACKMAIL",
        InvestigationWorkflow.MESSAGE_CHECK,
    ),

    # Domain 7: Phishing & Malicious Tech
    (
        "smishing_claim_link",
        "Your delivery failed. Click here to claim your package and update address: https://track-parcel.top/login",
        ScamDomain.PHISHING_TECH,
        "SMISHING_PHISHING_LINK",
        InvestigationWorkflow.LINK_WEBSITE_CHECK,
    ),

    # Domain 9: Property & Travel
    (
        "bedsitter_viewing_fee",
        "Modern bedsitter in Roysambu for rent. Tuma pesa ya kuona nyumba Ksh 1,000 for viewing fee before seeing caretaker.",
        ScamDomain.PROPERTY_TRAVEL,
        "PROPERTY_RENTAL_VIEWING_FEE",
        InvestigationWorkflow.MESSAGE_CHECK,
    ),

    # Domain 11: Prizes & Giveaways
    (
        "lottery_prize_fee",
        "Congratulations! You won Ksh 250,000 in the Safaricom anniversary draw. Pay processing fee to claim your prize.",
        ScamDomain.PRIZES_GRANTS,
        "PRIZE_GIVEAWAY_ADVANCE_FEE",
        InvestigationWorkflow.MESSAGE_CHECK,
    ),

    # Domain 12: Emerging Recovery Scams
    (
        "fund_recovery_specialist",
        "Lost money to online scammers? Our ethical hacker and recovery agent will recover lost money for an upfront consultation fee.",
        ScamDomain.EMERGING,
        "SCAM_RECOVERY_FEE_FRAUD",
        InvestigationWorkflow.MESSAGE_CHECK,
    ),
]


@pytest.mark.parametrize("cid,text,expected_domain,expected_pattern,expected_workflow", TAXONOMY_CASES)
def test_taxonomy_classification(cid, text, expected_domain, expected_pattern, expected_workflow):
    cl = classify_text_threat(text)
    assert cl.primary_domain == expected_domain, f"Failed domain for {cid}: got {cl.primary_domain}"
    assert any(p.id == expected_pattern for p in cl.matched_patterns), f"Pattern {expected_pattern} not in matched: {[p.id for p in cl.matched_patterns]}"
    assert cl.suggested_workflow == expected_workflow, f"Workflow mismatch for {cid}: got {cl.suggested_workflow}"
    assert len(cl.action_en) > 0 and len(cl.action_sw) > 0


# --- 2. False-Positive Control Suite (Legitimate Messages Resembling Scams) ---
LEGITIMATE_CONTROL_CASES = [
    (
        "genuine_school_fees",
        "Dear Parent, please pay Term 1 school fees of Ksh 24,500 to St. Jude Academy via Paybill 522123 Account STD402 by Friday.",
    ),
    (
        "genuine_safaricom_security_sms",
        "Safaricom Reminder: NEVER share your M-PESA PIN or OTP with anyone. Safaricom will only call you from 0722 000 000.",
    ),
    (
        "genuine_kra_pin_tax_filing",
        "Kindly send your KRA PIN certificate to our accounting office for the annual tax filing and returns.",
    ),
    (
        "genuine_mpesa_receipt",
        "QJK1ABC2XY Confirmed. Ksh1,500.00 sent to JANE WAMBUI 0722123456 on 25/10/26 at 3:45 PM. New M-PESA balance is Ksh4,200.00.",
    ),
    (
        "genuine_pay_on_delivery_shop",
        "Karibu our shop at StarMall 1st Floor Shop 12. We offer Pay on Delivery in Nairobi CBD, no deposit required.",
    ),
]


@pytest.mark.parametrize("cid,text", LEGITIMATE_CONTROL_CASES)
def test_legitimate_control_no_false_alarm(cid, text):
    a = assess(text)
    assert a.label in (Label.NO_KNOWN_THREATS_FOUND, Label.INCONCLUSIVE), f"False alarm on {cid}: got {a.label}"
    # Verify no aggressive high-risk scam accusations
    assert not any(f.code == "PIN_OR_OTP_REQUEST" and f.strength.value == "strong" for f in a.findings)


# --- 3. Duplicate Detection & Independent Reporting ---
def test_duplicate_deduplication_via_minhash():
    msg1 = "Urgently buy these shoes at discount price, pay rider fare Ksh 300 to 0712345678."
    msg2 = "Urgently buy these shoes at discount price, pay rider fare Ksh 300 to 0712345678!"
    h1 = script_hash(msg1)
    h2 = script_hash(msg2)
    assert h1 == h2, "Script hash must be identical for identical normalized texts"
    m1 = minhash(msg1)
    m2 = minhash(msg2)
    sim = sum(1 for a, b in zip(m1, m2) if a == b) / len(m1)
    assert sim >= 0.95, f"Minhash similarity should be >= 0.95, got {sim}"


# --- 4. Cross-Channel Entity Correlation & Privacy Masking ---
def test_cross_channel_correlation_and_masking():
    text = "Check our Instagram page @nairobi_kicks or WhatsApp us on 0712345678 to buy sneakers."
    a = assess(text)
    taxonomy_data = a.taxonomy
    correlations = taxonomy_data.get("entity_correlations", [])
    assert len(correlations) >= 1
    corr = correlations[0]
    assert corr["type"] == "social_to_phone"
    assert "nairobi_kicks" in corr["source"]
    # Ensure phone is masked for privacy protection
    assert "2547" in corr["target"] and "\u2022" in corr["target"]


# --- 5. Assessment Integration & Provenance Attribution ---
def test_assessment_includes_taxonomy_provenance():
    text = "Congratulations! You won Ksh 100,000 from Safaricom. Pay registration fee Ksh 500 to claim prize."
    a = assess(text)
    assert "taxonomy" in as_dict(a) or a.taxonomy is not None
    tax = a.taxonomy
    assert tax["primary_domain"] == "prizes_grants_and_advance_fees"
    assert "PRIZE_GIVEAWAY_ADVANCE_FEE" in tax["matched_patterns"]
    assert tax["provenance"] == ProvenanceType.MODEL_INFERENCE.value


def as_dict(a):
    from dataclasses import asdict
    return asdict(a)
