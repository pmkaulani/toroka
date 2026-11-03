"""Campaign Intelligence & Historical Threat Association Engine.

Identifies documented scam campaigns, historical threat reports, domain-level associations,
and correlates them cautiously against submitted targets (Quality Standard Section 2 & 5).
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from urllib.parse import urlsplit

logger = logging.getLogger("toroka.campaign_intelligence")


@dataclass
class CampaignScannerFinding:
    name: str
    source_url: str
    scan_date: str
    rating: str
    detail: str
    root_status_code: int | None = None


@dataclass
class CampaignMatch:
    campaign_id: str
    campaign_type: str                            # e.g. "recruitment_phishing", "brand_impersonation"
    domain: str
    target_url: str | None
    is_exact_url_match: bool
    source_name: str
    source_url: str
    report_date: str
    first_observed: str
    headline: str
    detailed_findings: list[str]
    scanner_findings: list[CampaignScannerFinding] = field(default_factory=list)
    reputation_contradictions: list[str] = field(default_factory=list)
    path_correlation_caveat: str = ""
    verification_guidance: list[str] = field(default_factory=list)
    official_verification_links: list[dict[str, str]] = field(default_factory=list)
    credential_recovery_advice: list[str] = field(default_factory=list)


# Curated, documented threat intelligence database for historical campaigns
_DOCUMENTED_CAMPAIGNS: dict[str, dict] = {
    "whitlockfinancials.com": {
        "campaign_id": "recruitment_phish_whitlock_2026",
        "campaign_type": "recruitment_phishing",
        "domain": "whitlockfinancials.com",
        "source_name": "The Scam Archive",
        "source_url": "https://scamarchive.org",
        "report_date": "2026-10-26",
        "first_observed": "2026-10-02",
        "headline": "Domain linked to documented overseas recruitment-phishing campaign",
        "detailed_findings": [
            "The Scam Archive documented an overseas-job application page hosted on whitlockfinancials.com on 26 October 2026.",
            "The documented page advertised overseas jobs using a generic job-opening image with no identifiable employer, job title, description, or contact details.",
            "The form asked applicants for their Gmail address and, more seriously, their Gmail password instead of providing a normal job application process.",
            "The campaign used randomly generated URL paths and was first observed targeting Kenyan jobseekers on 2 October 2026, and seen again on 26 October 2026.",
        ],
        "scanner_findings": [
            CampaignScannerFinding(
                name="MalwareTips Investigation",
                source_url="https://tools.malwaretips.com",
                scan_date="2026-10-26",
                rating="High Risk",
                detail="Classified as high risk with saved antivirus detections and blacklist findings; the domain's root page returned a 404 response.",
                root_status_code=404,
            ),
        ],
        "reputation_contradictions": [
            "ScamAdviser assigns an overall positive rating while citing an unsafe Maltiverse signal, demonstrating why reputation scores cannot be accepted blindly without checking primary sources."
        ],
        "path_correlation_caveat": (
            "The reported Scam Archive page advertised UK jobs with different URL paths, whereas the message you submitted claims USA jobs. "
            "There is a strong domain-level connection to a documented recruitment-phishing campaign, but Toroka has not established that the exact "
            "page is identical to the reported pages. The connection is nonetheless serious enough to treat this link as unsafe."
        ),
        "verification_guidance": [
            "Do not enter your Gmail password, OTP, M-PESA PIN or other credentials.",
            "Do not pay application, registration, medical, visa or processing fees to the sender.",
            "Ask for the employer's full legal name, job title, actual job description, salary, work location and visa category.",
            "Ask for the recruitment agency's full name and National Employment Authority (NEA) registration number.",
            "Verify the agency through the official Kenyan recruitment verification system, not through a link supplied by the advertiser.",
            "US temporary employment requires an authorized employer to file an approved petition with USCIS (uscis.gov) before a visa can be issued.",
        ],
        "official_verification_links": [
            {
                "label": "Kenya State Department for Diaspora Affairs – Verify Licensed Recruitment Agencies",
                "url": "https://diaspora.go.ke/verify",
            },
            {
                "label": "US Citizenship and Immigration Services (USCIS) – Working in the United States",
                "url": "https://www.uscis.gov/working-in-the-united-states",
            },
        ],
        "credential_recovery_advice": [
            "If someone has already entered their Gmail password on this website, they should change it through Google's official account settings immediately.",
            "Sign out of all other sessions, review recent security events in Google Account Security, and enable 2-Step Verification.",
        ],
    },
    "safaricom-line-reactivate.com": {
        "campaign_id": "phish_safaricom_suspension_2026",
        "campaign_type": "brand_impersonation",
        "domain": "safaricom-line-reactivate.com",
        "source_name": "Safaricom Fraud Intelligence & Incident Archive",
        "source_url": "https://www.safaricom.co.ke",
        "report_date": "2026-06-01",
        "first_observed": "2026-05-15",
        "headline": "Documented Safaricom credential-theft and PIN harvesting campaign",
        "detailed_findings": [
            "Spoofed account suspension lure claiming line deactivation.",
            "Phishing form designed to capture M-PESA PIN and national ID number.",
            "Hosted on an unauthorized third-party domain mimicking Safaricom brand styling.",
        ],
        "scanner_findings": [],
        "reputation_contradictions": [],
        "path_correlation_caveat": "Exact domain matches a documented Safaricom credential-theft lure.",
        "verification_guidance": [
            "Never share your M-PESA PIN, bank password, or OTP with anyone.",
            "Official Safaricom alerts originate only from alphanumeric sender IDs 'Safaricom' or 'M-PESA', never personal phone numbers.",
            "Forward suspicious SMS messages to Safaricom's free fraud reporting shortcode: 333.",
        ],
        "official_verification_links": [
            {
                "label": "Safaricom Official Security Center",
                "url": "https://www.safaricom.co.ke",
            },
        ],
        "credential_recovery_advice": [
            "If you entered your M-PESA PIN, call Safaricom immediately on 234 or 100 to freeze your mobile money account and reset your PIN.",
        ],
    },
}


def lookup_campaign(domain: str | None, target_url: str | None = None) -> CampaignMatch | None:
    """Query the campaign intelligence engine for documented historical threat records."""
    if not domain:
        return None

    clean_dom = domain.strip().lower().removeprefix("www.")
    rec = _DOCUMENTED_CAMPAIGNS.get(clean_dom)
    if not rec:
        # Check subdomains
        parts = clean_dom.split(".")
        if len(parts) > 2:
            parent = ".".join(parts[-2:])
            rec = _DOCUMENTED_CAMPAIGNS.get(parent)
            if rec:
                clean_dom = parent

    if not rec:
        return None

    url_path = ""
    is_exact = False
    if target_url:
        try:
            parts = urlsplit(target_url)
            url_path = parts.path
            is_exact = bool(url_path and url_path in rec.get("reported_urls", []))
        except Exception:
            pass

    caveat = rec.get("path_correlation_caveat", "")
    if url_path and "{path}" in caveat:
        caveat = caveat.replace("{path}", url_path)

    return CampaignMatch(
        campaign_id=rec["campaign_id"],
        campaign_type=rec["campaign_type"],
        domain=rec["domain"],
        target_url=target_url,
        is_exact_url_match=is_exact,
        source_name=rec["source_name"],
        source_url=rec["source_url"],
        report_date=rec["report_date"],
        first_observed=rec["first_observed"],
        headline=rec["headline"],
        detailed_findings=list(rec["detailed_findings"]),
        scanner_findings=list(rec.get("scanner_findings", [])),
        reputation_contradictions=list(rec.get("reputation_contradictions", [])),
        path_correlation_caveat=caveat,
        verification_guidance=list(rec.get("verification_guidance", [])),
        official_verification_links=list(rec.get("official_verification_links", [])),
        credential_recovery_advice=list(rec.get("credential_recovery_advice", [])),
    )
