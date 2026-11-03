"""Specialist investigation rules by fraud category.

Evaluates category-specific evidence to produce grounded, distinct findings
tailored to the user's scenario with strict evidence-vs-conclusion separation
(Quality Standard Section 4 & 5).
"""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit

from .signals import Finding
from .vocabulary import EvidenceType, Strength, ClaimStatus, VerificationStatus, ReliabilityClassification
from .category import InvestigationCategory


def evaluate_specialist_rules(
    text: str,
    category: str,
    *,
    urls: list[Any] | None = None,
    domain: str | None = None,
    path: str | None = None,
) -> list[Finding]:
    """Evaluate specialist rules matching the identified investigation category."""
    findings: list[Finding] = []
    text_lower = text.lower()

    if category in (InvestigationCategory.RECRUITMENT_OVERSEAS.value, "job"):
        findings.extend(_evaluate_recruitment_rules(text, text_lower, urls=urls, domain=domain, path=path))
    elif category in (InvestigationCategory.ONLINE_SHOPPING.value, InvestigationCategory.SOCIAL_SELLER.value, "shop"):
        findings.extend(_evaluate_shopping_rules(text, text_lower, urls=urls, domain=domain))
    elif category in (InvestigationCategory.MPESA_PAYMENT.value, "payment"):
        findings.extend(_evaluate_mpesa_rules(text, text_lower, urls=urls))
    elif category in (InvestigationCategory.GOVERNMENT_GRANTS.value, "grant"):
        findings.extend(_evaluate_grant_rules(text, text_lower, urls=urls))
    elif category == InvestigationCategory.PRIZE_WINNINGS.value:
        findings.extend(_evaluate_prize_rules(text, text_lower, urls=urls))
    elif category in (InvestigationCategory.PHISHING_CREDENTIAL.value, "website"):
        findings.extend(_evaluate_phishing_rules(text, text_lower, urls=urls, domain=domain))
    elif category == InvestigationCategory.INVESTMENT_FRAUD.value:
        findings.extend(_evaluate_investment_rules(text, text_lower, urls=urls))

    return findings


# ---------------------------------------------------------------------------
# 1. Recruitment & Overseas Employment Rules
# ---------------------------------------------------------------------------

def _evaluate_recruitment_rules(
    text: str,
    low: str,
    *,
    urls: list[Any] | None = None,
    domain: str | None = None,
    path: str | None = None,
) -> list[Finding]:
    findings: list[Finding] = []

    # Check 1: Unnamed Employer
    has_employer_name = bool(re.search(
        r"(?i)\b(?:company|employer|organisation|hospital|hotel|firm|corporation|llc|inc|ltd):\s*[A-Z][A-Za-z0-9\s.,&-]{2,40}\b",
        text,
    ))
    if not has_employer_name and any(term in low for term in ("job in", "jobs in", "difference job", "vacancies in", "recruiting for")):
        findings.append(Finding(
            code="RECRUITMENT_UNNAMED_EMPLOYER",
            evidence_type=EvidenceType.UNRESOLVED_CLAIM,
            strength=Strength.SUPPORTING,
            plain_text="No actual employer or hiring company is identified",
            why_it_matters=(
                "Legitimate employment offers clearly state the hiring company's legal name, "
                "registered physical location, and verifiable contact details."
            ),
            source="Message text analysis",
            verification_status="unverified",
            reliability="high",
            target_match="exact",
            limitations="Based on supplied text; the sender may provide details later upon inquiry.",
        ))

    # Check 2: Missing Vacancy / Job Description Details
    has_specific_title = bool(re.search(
        r"(?i)\b(?:nurse|driver|security\s+guard|cook|chef|waiter|waitress|electrician|"
        r"plumber|caregiver|carpenter|engineer|accountant|welder|mason|cleaner|mechanic)\b",
        low,
    ))
    if not has_specific_title and any(term in low for term in ("difference job", "application of job", "register to apply", "available jobs")):
        findings.append(Finding(
            code="RECRUITMENT_NO_VACANCY_DETAILS",
            evidence_type=EvidenceType.UNRESOLVED_CLAIM,
            strength=Strength.SUPPORTING,
            plain_text="No specific vacancy, job title, or role duties are provided",
            why_it_matters=(
                "Legitimate job adverts identify specific vacancies and role responsibilities "
                "rather than asking applicants to register for vague or unspecified positions."
            ),
            source="Message text analysis",
            verification_status="unverified",
            reliability="high",
            target_match="exact",
        ))

    # Check 3: Implausible Immigration & Work Authorization Pathway
    if "united states" in low or "usa" in low or "u.s." in low:
        has_form_four = bool(re.search(r"(?i)\bform\s+four\s+(?:certificate|leaver)\b", low))
        has_visa_petition = bool(re.search(r"(?i)\b(?:uscis|petition|h-?2[ab]|visa\s+sponsorship)\b", low))
        if has_form_four and not has_visa_petition:
            findings.append(Finding(
                code="RECRUITMENT_IMPLAUSIBLE_IMMIGRATION",
                evidence_type=EvidenceType.UNRESOLVED_CLAIM,
                strength=Strength.SUPPORTING,
                plain_text="Unverified US work authorization and immigration pathway",
                why_it_matters=(
                    "For temporary employment in the United States, an authorized US employer must "
                    "petition USCIS (uscis.gov) on behalf of the worker before a visa can be issued. "
                    "A secondary school certificate alone does not confer US work authorization."
                ),
                source="USCIS / Diaspora Affairs work authorization rules",
                verification_status="observed",
                reliability="high",
                target_match="exact",
            ))

    # Check 4: Unlicensed Recruitment Agency
    has_agency_licence = bool(re.search(r"(?i)\b(?:nea|national\s+employment\s+authority|licen[cs]e\s+no|reg\s+no)\b", low))
    if any(term in low for term in ("overseas", "abroad", "united states", "qatar", "dubai", "canada", "uk")) and not has_agency_licence:
        findings.append(Finding(
            code="RECRUITMENT_UNLICENSED_AGENCY",
            evidence_type=EvidenceType.UNRESOLVED_CLAIM,
            strength=Strength.SUPPORTING,
            plain_text="No recruitment agency name or NEA licence number is supplied",
            why_it_matters=(
                "Kenyan law requires agencies recruiting for foreign employment to be registered "
                "with the National Employment Authority (NEA) and verifiable through the State "
                "Department for Diaspora Affairs (diaspora.go.ke/verify)."
            ),
            source="National Employment Authority (NEA) regulations",
            verification_status="unverified",
            reliability="high",
            target_match="exact",
        ))

    # Check 5: Suspicious Application Portal Domain
    target_domain = (domain or "").lower()
    if target_domain and not any(target_domain.endswith(tld) for tld in (".go.ke", ".gov", ".edu", ".ac.ke")):
        suspicious_words = ("financial", "fund", "credit", "wealth", "claim", "portal", "bonus", "reward")
        if any(w in target_domain for w in suspicious_words):
            findings.append(Finding(
                code="RECRUITMENT_SUSPICIOUS_PORTAL",
                evidence_type=EvidenceType.UNRESOLVED_CLAIM,
                strength=Strength.SUPPORTING,
                plain_text=f"Job application directed to generic domain '{target_domain}'",
                why_it_matters=(
                    f"The link directs applicants to '{target_domain}', which resembles a generic "
                    "financial or placeholder domain rather than an official corporate careers portal "
                    "or accredited recruitment agency site."
                ),
                source="Domain naming heuristic",
                verification_status="observed",
                reliability="moderate",
                target_match="domain",
            ))

    # Check 6: Random URL Path Pattern
    url_path = (path or "").strip("/")
    if url_path and len(url_path) >= 8 and re.match(r"^[a-zA-Z0-9]+$", url_path) and not re.search(r"(?i)\b(?:apply|jobs?|careers?|register|vacancy)\b", url_path):
        findings.append(Finding(
            code="RANDOM_URL_PATH_PATTERN",
            evidence_type=EvidenceType.AUTOMATED_OBSERVATION,
            strength=Strength.WEAK,
            plain_text=f"Randomly generated URL path '/{url_path}'",
            why_it_matters=(
                "The destination uses a randomly generated alphanumeric path, a pattern commonly "
                "used in phishing campaigns to distribute disposable links across identical templates."
            ),
            source="URL structural inspection",
            verification_status="observed",
            reliability="moderate",
            target_match="exact",
            limitations="Random paths can occasionally be used for session tokens or URL shortening.",
        ))

    # Check 7: Credential or Registration Fee Solicitation
    if any(term in low for term in ("registration fee", "application fee", "medical fee", "processing fee", "interview fee")):
        findings.append(Finding(
            code="RECRUITMENT_APPLICATION_FEE",
            evidence_type=EvidenceType.AUTOMATED_OBSERVATION,
            strength=Strength.STRONG,
            plain_text="Soliciting upfront application or processing fees",
            why_it_matters=(
                "Legitimate employers and ethical recruitment agencies do not demand upfront fees "
                "from jobseekers before interviews or employment contracts are confirmed."
            ),
            source="Message text analysis",
            verification_status="observed",
            reliability="high",
            target_match="exact",
        ))

    return findings


# ---------------------------------------------------------------------------
# 2. Online Shopping & Social Media Seller Rules
# ---------------------------------------------------------------------------

def _evaluate_shopping_rules(
    text: str,
    low: str,
    *,
    urls: list[Any] | None = None,
    domain: str | None = None,
) -> list[Finding]:
    findings: list[Finding] = []

    has_pay_in_advance = bool(re.search(r"(?i)\b(?:pay\s+before|lipa\s+kwanza|upfront\s+payment|advance\s+payment)\b", low))
    if has_pay_in_advance:
        findings.append(Finding(
            code="SHOP_UPFRONT_PAYMENT_DEMAND",
            evidence_type=EvidenceType.AUTOMATED_OBSERVATION,
            strength=Strength.SUPPORTING,
            plain_text="Full upfront payment demanded before dispatch",
            why_it_matters=(
                "Demanding 100% advance payment without verifiable pickup location or escrow "
                "protection is a leading risk factor in social media shopping scams."
            ),
            source="Message text analysis",
            verification_status="observed",
            reliability="moderate",
            target_match="exact",
        ))

    return findings


# ---------------------------------------------------------------------------
# 3. M-PESA & Payment Fraud Rules
# ---------------------------------------------------------------------------

def _evaluate_mpesa_rules(
    text: str,
    low: str,
    *,
    urls: list[Any] | None = None,
) -> list[Finding]:
    findings: list[Finding] = []

    # Fake reversal claims
    if any(phrase in low for phrase in ("sent by mistake", "reverse the transaction", "wrong recipient", "send back the money")):
        if not re.search(r"(?i)\bconfirmed\b", low) or "safaricom" not in low:
            findings.append(Finding(
                code="MPESA_SUSPICIOUS_REVERSAL_CLAIM",
                evidence_type=EvidenceType.UNRESOLVED_CLAIM,
                strength=Strength.SUPPORTING,
                plain_text="Unverified M-PESA reversal or mistaken payment claim",
                why_it_matters=(
                    "Scammers often claim to have sent funds by mistake using forged SMS messages. "
                    "Never send funds back manually; check your real M-PESA statement or use official *456#."
                ),
                source="Message text analysis",
                verification_status="unverified",
                reliability="high",
                target_match="exact",
            ))

    return findings


# ---------------------------------------------------------------------------
# 4. Government Grants & Impersonation Rules
# ---------------------------------------------------------------------------

def _evaluate_grant_rules(
    text: str,
    low: str,
    *,
    urls: list[Any] | None = None,
) -> list[Finding]:
    findings: list[Finding] = []

    if any(g in low for g in ("hustler fund", "inua jamii", "helb", "bursary")):
        if urls:
            for u in urls:
                host = getattr(u, "host", "") or str(u)
                if not host.endswith(".go.ke"):
                    findings.append(Finding(
                        code="GRANT_UNOFFICIAL_PORTAL",
                        evidence_type=EvidenceType.AUTOMATED_OBSERVATION,
                        strength=Strength.STRONG,
                        plain_text=f"Government programme advertised on non-government domain '{host}'",
                        why_it_matters=(
                            "Kenyan government programmes and ministries operate exclusively on '.go.ke' "
                            "domains. Third-party domains claiming to offer grants are frequently phishing lures."
                        ),
                        source="Official domain verification",
                        verification_status="observed",
                        reliability="high",
                        target_match="domain",
                    ))
                    break

    return findings


# ---------------------------------------------------------------------------
# 5. Prize & Winnings Rules
# ---------------------------------------------------------------------------

def _evaluate_prize_rules(
    text: str,
    low: str,
    *,
    urls: list[Any] | None = None,
) -> list[Finding]:
    findings: list[Finding] = []

    if any(w in low for w in ("congratulations", "you have won", "jackpot", "claim your prize", "lottery")):
        if any(f in low for f in ("fee", "tax", "clearance", "processing", "mpesa", "delivery fee")):
            findings.append(Finding(
                code="PRIZE_ADVANCE_FEE_DEMAND",
                evidence_type=EvidenceType.AUTOMATED_OBSERVATION,
                strength=Strength.STRONG,
                plain_text="Advance fee requested to release claimed prize",
                why_it_matters=(
                    "Legitimate lotteries and promotions never require winners to pay a fee or tax "
                    "in advance to receive winnings."
                ),
                source="Message text analysis",
                verification_status="observed",
                reliability="high",
                target_match="exact",
            ))

    return findings


# ---------------------------------------------------------------------------
# 6. Phishing & Credential Theft Rules
# ---------------------------------------------------------------------------

def _evaluate_phishing_rules(
    text: str,
    low: str,
    *,
    urls: list[Any] | None = None,
    domain: str | None = None,
) -> list[Finding]:
    findings: list[Finding] = []

    if any(p in low for p in ("password", "gmail password", "email password", "enter pin", "otp")):
        findings.append(Finding(
            code="CREDENTIAL_HARVESTING_INDICATOR",
            evidence_type=EvidenceType.AUTOMATED_OBSERVATION,
            strength=Strength.STRONG,
            plain_text="Soliciting sensitive account credentials or passwords",
            why_it_matters=(
                "Entering your email password, OTP, or PIN on external forms exposes your accounts "
                "to immediate unauthorized takeover."
            ),
            source="Message text analysis",
            verification_status="observed",
            reliability="high",
            target_match="exact",
        ))

    return findings


# ---------------------------------------------------------------------------
# 7. Investment Fraud Rules
# ---------------------------------------------------------------------------

def _evaluate_investment_rules(
    text: str,
    low: str,
    *,
    urls: list[Any] | None = None,
) -> list[Finding]:
    findings: list[Finding] = []

    if any(term in low for term in ("guaranteed daily", "guaranteed profit", "double your money", "daily return", "risk free")):
        findings.append(Finding(
            code="INVESTMENT_UNREALISTIC_RETURNS",
            evidence_type=EvidenceType.UNRESOLVED_CLAIM,
            strength=Strength.STRONG,
            plain_text="Guaranteed or implausibly high investment returns",
            why_it_matters=(
                "Legitimate investments carry risk; promises of guaranteed or doubled daily returns "
                "are hallmark signatures of Ponzi or fraudulent investment schemes."
            ),
            source="Financial market standards",
            verification_status="unverified",
            reliability="high",
            target_match="exact",
        ))

    return findings
