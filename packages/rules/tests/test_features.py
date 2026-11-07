"""New-feature golden cases: observations, reports, programmes, claims, shops, location, fingerprints, recovery."""
from datetime import datetime, timezone

import pytest
from ssi_rules import (CoverageStatus, GeocodeObservation, Label, Observations, Opportunity, ReportHit, Reputation, UrlObservation, assess)
from ssi_rules.category import detect_category
from ssi_rules.fingerprint import minhash, script_hash, similarity
from ssi_rules.location import extract_location_claims
from ssi_rules.recovery import triage

CS = CoverageStatus
LINK = "Claim your reward now at https://prize-claims.example.com/win thanks"
SHORT = "Open the details here: bit.ly/3AbCdEf thank you"


def rep(status=CS.CHECKED, threats=()):
    return Reputation(status, "TestFeed", list(threats), "2026-10-20T10:00:00Z", "2026-10-21T10:00:00Z")


def test_threat_feed_match_is_high_risk_and_cites_the_source():
    o = Observations(urls={"https://prize-claims.example.com/win": UrlObservation("https://prize-claims.example.com/win", rep(threats=["SOCIAL_ENGINEERING"]))})
    a = assess(LINK, observations=o)
    assert a.label == Label.HIGH_RISK and a.findings[0].code == "THREAT_FEED_MATCH"
    assert any(s.id == "reputation:TestFeed" for s in a.sources)


def test_clean_reputation_unblocks_but_never_guarantees():
    o = Observations(urls={"https://prize-claims.example.com/win": UrlObservation("https://prize-claims.example.com/win", rep())})
    a = assess("Lunch menu: https://menu.example.com/week", observations=Observations(urls={"https://menu.example.com/week": UrlObservation("https://menu.example.com/week", rep())}))
    assert a.label == Label.NO_KNOWN_THREATS_FOUND
    assert "not exhaustive" in next(c for c in a.coverage if c.id == "url_reputation").detail


def test_reputation_outage_is_could_not_check_not_silence():
    o = Observations(urls={"https://menu.example.com/week": UrlObservation("https://menu.example.com/week", rep(CS.COULD_NOT_CHECK))})
    a = assess("Lunch menu: https://menu.example.com/week", observations=o)
    item = next(c for c in a.coverage if c.id == "url_reputation")
    assert a.label == Label.INCONCLUSIVE and item.status == CS.COULD_NOT_CHECK and any("could not be checked" in l for l in a.limitations)


def test_resolved_shortener_to_lookalike_is_suspicious():
    o = Observations(urls={"bit.ly/3AbCdEf": UrlObservation("bit.ly/3AbCdEf", rep(), final_url="https://safaricom-rewards.xyz/claim", redirect_status=CS.CHECKED, hops=2)})
    a = assess(SHORT, observations=o)
    assert a.label == Label.SUSPICIOUS_VERIFY_FIRST and "LOOKALIKE_DOMAIN" in {f.code for f in a.findings}
    assert next(c for c in a.coverage if c.id == "redirect_destination").status == CS.CHECKED


def test_failed_redirect_follow_keeps_result_inconclusive():
    o = Observations(urls={"bit.ly/3AbCdEf": UrlObservation("bit.ly/3AbCdEf", rep(), redirect_status=CS.COULD_NOT_CHECK)})
    a = assess(SHORT, observations=o)
    assert a.label == Label.INCONCLUSIVE and next(c for c in a.coverage if c.id == "redirect_destination").status == CS.COULD_NOT_CHECK


def test_new_domain_alone_is_only_weak():
    o = Observations(urls={"https://menu.example.com/week": UrlObservation("https://menu.example.com/week", rep(), domain_age_days=5, domain_facts_status=CS.CHECKED)})
    a = assess("Lunch menu: https://menu.example.com/week", observations=o)
    assert a.label == Label.INCONCLUSIVE and {f.code for f in a.findings} == {"NEW_DOMAIN"}


@pytest.mark.parametrize("n,under_review,label", [(1, False, Label.SUSPICIOUS_VERIFY_FIRST), (3, False, Label.HIGH_RISK), (3, True, Label.INCONCLUSIVE)])
def test_moderated_reports_scale_with_independence_and_respect_appeals(n, under_review, label):
    o = Observations(report_lookup_ran=True, report_hits={"till:123456": ReportHit("till", n, True, "ind-1", "2026-10", under_review)})
    a = assess("Please pay for the goods to Till Number 123456 today.", observations=o)
    assert a.label == label
    assert any(s.id == "indicator:ind-1" for s in a.sources)


def test_no_reports_is_not_found_not_clean():
    o = Observations(report_lookup_ran=True)
    a = assess("Please pay for the goods to Till Number 123456 today.", observations=o)
    assert next(c for c in a.coverage if c.id == "number_reports").status == CS.NOT_FOUND and a.label == Label.INCONCLUSIVE


GRANT = "You have been selected for the Youth Business Grant. Pay KSh 350 to activate funds."


def test_unknown_programme_with_fee_is_suspicious_and_says_not_independently_verified():
    a = assess(GRANT, observations=Observations(opportunity_lookup_ran=True))
    assert a.label == Label.SUSPICIOUS_VERIFY_FIRST and "OFFICIAL_SOURCE_NOT_FOUND" in {f.code for f in a.findings}
    assert next(c for c in a.coverage if c.id == "official_programmes").status == CS.NOT_FOUND


def test_unknown_programme_without_a_fee_is_inconclusive_not_accusatory():
    a = assess("You have been selected for the Youth Business Grant, details to follow.", observations=Observations(opportunity_lookup_ran=True))
    assert a.label == Label.INCONCLUSIVE


OPP = Opportunity("kra-careers", "KRA careers", "Kenya Revenue Authority", "kra.go.ke", "https://kra.go.ke/careers", "no_fee", [],
                  "https://kra.go.ke/news-center/public-notices/586-recruitment-fraud", "2026-10-20", "2027-01-18")


def test_matched_programme_fee_policy_contradiction_is_high_risk():
    a = assess("Vacancy: the Youth Employment Programme needs a processing fee payment: pay Ksh 500 as an application fee.", observations=Observations(opportunities=[OPP], opportunity_lookup_ran=True))
    assert a.label == Label.HIGH_RISK and a.findings[0].code == "PROGRAMME_FEE_CONTRADICTION"


def test_matched_programme_wrong_link_and_county():
    opp = Opportunity("cdf-x", "County Bursary", "County Gov", "county.go.ke", None, None, ["Kisumu"], "https://county.go.ke/b", "2026-10-20", "2027-01-18")
    a = assess("County bursary applications open for Nakuru students, apply at https://bursary-apply.example.com/form", observations=Observations(opportunities=[opp], opportunity_lookup_ran=True))
    assert {"PROGRAMME_DOMAIN_MISMATCH", "PROGRAMME_COUNTY_MISMATCH"} <= {f.code for f in a.findings} and a.label == Label.SUSPICIOUS_VERIFY_FIRST


def test_stale_programme_record_is_downgraded():
    a = assess("Vacancy: pay Ksh 500 as an application fee.", observations=Observations(opportunities=[OPP], opportunity_lookup_ran=True),
               now=datetime(2027, 6, 1, tzinfo=timezone.utc))
    assert a.label == Label.SUSPICIOUS_VERIFY_FIRST and "opportunity:kra-careers" in a.stale_sources


@pytest.mark.parametrize("text,code,label", [
    ("Invest today: guaranteed returns of 50% weekly, double your money in days!", "GUARANTEED_RETURNS", Label.SUSPICIOUS_VERIFY_FIRST),
    ("This herbal tea cures diabetes and cancer, order now", "UNSUPPORTED_MEDICAL_CLAIM", Label.SUSPICIOUS_VERIFY_FIRST),
    ("Our forex bot is approved by the Central Bank of Kenya", "GOVERNMENT_APPROVAL_CLAIM", Label.INCONCLUSIVE),
    ("90% off today only while stocks last", "MANIPULATED_DISCOUNT_FRAMING", Label.INCONCLUSIVE),
])
def test_claims_are_flagged_for_verification_never_called_false(text, code, label):
    a = assess(text)
    f = next(x for x in a.findings if x.code == code)
    assert a.label == label and f.claim_status is not None and f.claim_status.value in ("unsupported", "suspicious_pattern")


def test_unreviewed_source_note_is_not_used_to_call_a_claim_wrong():
    a = assess("Safaricom: reply with your PIN to unlock your M-PESA.")
    finding = next(f for f in a.findings if f.code == "SAFARICOM_NEVER_ASKS_PIN")
    assert finding.claim_status.value == "unsupported"
    assert finding.evidence_type.value == "unresolved_claim"
    assert a.label == Label.HIGH_RISK  # the direct PIN request is independently high risk
    assert not any((f.claim_status and f.claim_status.value == "verified_false") for f in assess("guaranteed returns 50% weekly").findings)


def test_current_reviewed_source_can_contradict_a_claim():
    from dataclasses import replace
    from ssi_rules.registry import load_registry
    registry = load_registry()
    old = registry.statements["safaricom-never-asks-pin"]
    registry.statements["safaricom-never-asks-pin"] = replace(old, reviewer="Toroka Reviewer")
    a = assess("Safaricom: reply with your PIN to unlock your M-PESA.", registry=registry)
    finding = next(f for f in a.findings if f.code == "SAFARICOM_NEVER_ASKS_PIN")
    assert finding.claim_status.value == "contradicted_by_source"
    assert finding.evidence_type.value == "verified_source" and finding.strength.value == "strong"


SHOP = "Selling sneakers on Instagram @kicks_ke, KSh 1,500 only! Delivery in Nairobi. Send money to 0712345678 and DM to order."


def test_shop_profile_extracted_and_weak_signals_are_not_accusations():
    a = assess(SHOP)
    assert a.shop_profile["platform"] == "instagram" and a.shop_profile["handle"] == "kicks_ke" and "Nairobi" in a.shop_profile["claimed_counties"]
    assert a.label == Label.INCONCLUSIVE                       # personal M-PESA + low price are not proof of fraud
    assert any("independently verify the seller" in n.text for n in a.next_steps)
    assert next(c for c in a.coverage if c.id == "platform_profile").status == CS.NOT_CHECKED


def test_shop_url_forms():
    assert assess("Shop here https://www.tiktok.com/@mama_mboga_ke and pay on delivery").shop_profile["platform"] == "tiktok"
    assert assess("See https://instagram.com/duka_la_viatu/ prices inside").shop_profile["handle"] == "duka_la_viatu"


def test_location_claims_counties_and_towns_and_differences():
    assert extract_location_claims("Pick up at Thika, deliver to Nairobi") == [("Thika", "Kiambu"), ("Nairobi", "Nairobi")]
    a = assess("combined", pieces={"text": "We are based in Mombasa, call us", "screenshot-1": "Our shop is in Eldoret town"})
    assert "LOCATION_CLAIMS_DIFFER" in {f.code for f in a.findings}
    same = assess("combined", pieces={"text": "Based in Mombasa", "screenshot-1": "Mombasa shop open daily"})
    assert "LOCATION_CLAIMS_DIFFER" not in {f.code for f in same.findings}


def test_geocode_not_found_is_weak_context_only():
    o = Observations(geocodes={"Nairobi": GeocodeObservation("Nairobi", CS.CHECKED, False, "test", "2026-10-20")})
    a = assess("Our shop is at 12 Moi Avenue, Nairobi. Delivery countrywide.", observations=o)
    f = next(x for x in a.findings if x.code == "PLACE_NOT_FOUND")
    assert f.strength.value == "weak" and a.label == Label.INCONCLUSIVE


def test_category_detection():
    assert detect_category("KRA recruitment: appointment letter ready", [], [], []).suggested == "job"
    assert detect_category("Bursary applications now open", [], [], []).suggested == "grant"
    assert detect_category("Hello friend, how was the weekend?", [], [], []).suggested == "message"
    assert assess("Check https://menu.example.com/week please").category["suggested"] == "website"
    assert assess("anything here to check", category_hint="job").category["used"] == "job"


def test_fingerprints_match_the_same_script_with_different_details():
    a = "Dear Mary, you won Ksh 50,000. Pay KSh 350 to 0712 345 678 to activate your prize at www.prize-ke.example.com"
    b = "Dear John, you won Ksh 90,000. Pay KSh 500 to 0733 111 222 to activate your prize at http://claim.example.net"
    c = "Reminder: the school fees balance is due on Friday, please pay promptly"
    assert script_hash(a) == script_hash(b) and script_hash(a) != script_hash(c)
    assert similarity(minhash(a), minhash(b)) == 1.0 and similarity(minhash(a), minhash(c)) < 0.2


def test_recovery_asks_only_what_is_missing_and_never_promises():
    t = triage({"paid": True, "shared_credentials": None})
    assert {q["id"] for q in t["questions"]} == {"shared_credentials", "installed_app", "sent_id_documents"}
    blob = " ".join(s["text"] for s in t["steps"]) + t["limits"]
    assert "official website" in blob and "cannot reverse" in t["limits"] and "PIN" in t["limits"]
    assert triage({k: False for k in ("paid", "shared_credentials", "installed_app", "sent_id_documents")})["steps"] == []


def test_swahili_localisation_falls_back_honestly():
    from dataclasses import asdict
    from ssi_rules.i18n import localize
    d = asdict(assess("You have a pending grant. Pay KSh 350 to activate funds."))
    sw = localize(d, "sw")
    assert sw["label_text"] == "Una shaka: thibitisha kwanza" and "mapema" in sw["findings"][0]["plain_text"]
    assert sw["summary"].startswith("Una shaka") and sw["translation_status"].startswith("draft_needs_native_review")
    en = localize(d, "en")
    assert en["summary"] == d["summary"] and en["label_text"] == "Suspicious: verify first"
    assert localize(d, "fr")["language"] == "en"


def test_marketplace_product_urls_enter_online_shopping_category():
    from ssi_rules.normalize import parse_url

    url = "https://www.jumia.co.ke/wireless-headphones-123.html"
    parsed = parse_url(url)
    assert parsed is not None
    guess = detect_category("Please check this listing: " + url, [parsed], [], [])
    assert guess.investigation_category == "online_shopping"
    assert guess.suggested == "shop"


def test_fake_marketplace_name_inside_an_unrelated_domain_does_not_trigger_shopping_category():
    from ssi_rules.normalize import parse_url

    url = "https://jumia.co.ke.fake-shop.example/product/123"
    parsed = parse_url(url)
    assert parsed is not None
    guess = detect_category("Please check: " + url, [parsed], [], [])
    assert guess.investigation_category != "online_shopping"
