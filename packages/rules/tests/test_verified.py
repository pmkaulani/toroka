"""Verified records: the site is vouched for, never the offer. Positive evidence must never raise or hide a warning."""
from datetime import datetime, timezone

import pytest
from ssi_rules import CoverageStatus as CS, Label, Observations, Reputation, UrlObservation, assess, load_registry
from ssi_rules.observations import VerifiedEntity
from ssi_rules.registry import verified_entities_from_registry

REG = load_registry()
SHOP = VerifiedEntity("mama-shop", "Mama Mboga Shop", "online_shop", ["mamamboga.co.ke"], ["instagram:mama_mboga_ke"], False, "moderator_verified_documents",
                      "https://example.org/proof", "2026-10-20", "2027-04-18", "A. Reviewer")
SAFARICOM_REVIEWED = VerifiedEntity("safaricom-reviewed", "Safaricom", "organisation", ["safaricom.co.ke"], ["instagram:safaricomplc"], True,
                                    "official_registry", "https://www.safaricom.co.ke/fraud-awareness", "2026-10-20", "2027-04-18", "A. Reviewer")


def obs(*extra, **kw):
    return Observations(verified_entities=[*verified_entities_from_registry(REG), *extra], **kw)


def test_official_domain_is_verified_only_after_a_human_review_with_the_standard_warning():
    # The static registry's seeded records are explicitly marked unreviewed.
    unreviewed = assess("Is https://www.safaricom.co.ke/fraud-awareness a real website?", observations=obs())
    assert unreviewed.label != Label.VERIFIED_OFFICIAL
    a = assess("Is https://www.safaricom.co.ke/fraud-awareness a real website?", observations=obs(SAFARICOM_REVIEWED))
    assert a.label == Label.VERIFIED_OFFICIAL and a.findings[0].code == "VERIFIED_OFFICIAL_SITE" and a.findings[0].polarity == "positive"
    assert a.verified[0]["name"] == "Safaricom" and any(s.id == "verified:safaricom-reviewed" and s.source_url and s.review_due for s in a.sources)
    steps = " ".join(n.text for n in a.next_steps)
    assert "typing its address yourself" in steps and "Copies of genuine sites exist" in steps
    assert "genuine, not that every offer" in a.summary
    assert "not even half" not in steps and "not even half" not in a.summary
    assert not any(f.polarity == "risk" and f.strength.value != "weak" for f in a.findings)


def test_verified_site_never_excuses_a_pin_or_fee_request():
    assert assess("Safaricom says send your PIN at https://www.safaricom.co.ke to unlock", observations=obs()).label == Label.HIGH_RISK
    a = assess("Pay a deposit first, details at https://www.mamamboga.co.ke/order", observations=obs(SHOP))
    assert a.label == Label.SUSPICIOUS_VERIFY_FIRST and a.findings[0].polarity == "risk"      # the warning leads; the verified site is still listed
    assert any(f.code == "VERIFIED_OFFICIAL_SITE" for f in a.findings)


@pytest.mark.parametrize("text", [
    "Check https://safaricom-shop.example.com now",                                  # lookalike
    "See https://www.safaricom.co.ke and also https://deals.example.com/win",        # one verified, one unknown link
    "See http://www.safaricom.co.ke/page",                                           # explicit http
    "See https://xn--sfaricom-q1a.co.ke",                                            # punycode
    "See https://evil.safaricom.co.ke.example.com/x",                                # verified name as a subdomain of someone else
    "See https://safaricom.co.ke@evil.example.com/",                                 # credentials trick
    "See https://203.0.113.9/safaricom.co.ke",                                       # bare IP
    "See bit.ly/abc123 for the safaricom page",                                      # unresolved shortener
])
def test_near_misses_are_not_verified(text):
    assert assess(text, observations=obs()).label != Label.VERIFIED_OFFICIAL


def test_shortener_that_resolves_to_a_verified_site_is_verified():
    o = obs(); o.urls = {"bit.ly/abc123": UrlObservation("bit.ly/abc123", None, "https://www.mamamboga.co.ke/shop", 1, CS.CHECKED)}
    o.verified_entities.append(SHOP)
    assert assess("Our shop: bit.ly/abc123", observations=o).label == Label.VERIFIED_OFFICIAL
    o.urls["bit.ly/abc123"] = UrlObservation("bit.ly/abc123", None, "http://www.mamamboga.co.ke/shop", 1, CS.CHECKED)
    assert assess("Our shop: bit.ly/abc123", observations=o).label != Label.VERIFIED_OFFICIAL


def test_subdomain_rule_and_stale_records():
    sub = assess("Open https://shop.mamamboga.co.ke/x", observations=obs(SHOP)); assert sub.label != Label.VERIFIED_OFFICIAL                    # not covered unless the record says so
    wide = VerifiedEntity(**{**SHOP.__dict__, "include_subdomains": True}); assert assess("Open https://shop.mamamboga.co.ke/x", observations=obs(wide)).label == Label.VERIFIED_OFFICIAL
    stale = assess("Open https://www.mamamboga.co.ke/x", observations=obs(SHOP), now=datetime(2027, 6, 1, tzinfo=timezone.utc))
    assert stale.label != Label.VERIFIED_OFFICIAL and "verified:mama-shop" in stale.stale_sources


def test_verified_shop_account_by_handle_only_when_no_other_link():
    a = assess("Selling shoes on Instagram @mama_mboga_ke, pay on delivery in Nairobi", observations=obs(SHOP))
    assert a.label == Label.VERIFIED_OFFICIAL and a.findings[0].code == "VERIFIED_OFFICIAL_SHOP"
    assert assess("Selling shoes on Instagram @someone_else, DM to order", observations=obs(SHOP)).label != Label.VERIFIED_OFFICIAL


def test_link_reputation_hit_beats_a_verified_record():
    o = obs(SHOP); o.urls = {"https://www.mamamboga.co.ke/x": UrlObservation("https://www.mamamboga.co.ke/x", Reputation(CS.CHECKED, "Feed", ["SOCIAL_ENGINEERING"]))}
    assert assess("Order at https://www.mamamboga.co.ke/x", observations=o).label == Label.HIGH_RISK


def test_shop_and_website_results_do_not_use_a_blanket_advance_payment_warning():
    for t in ["Selling sneakers on Instagram @kicks_ke, KSh 1,500, delivery in Nairobi", "Check https://menu.example.com/week please", "Great deals at https://deals.example.com"]:
        a = assess(t)
        assert all("not even half" not in n.text.lower() for n in a.next_steps), t
        assert all("don't pay in advance" not in n.text.lower() for n in a.next_steps), t
    shop = assess("Selling sneakers on Instagram @kicks_ke, KSh 1,500, delivery in Nairobi")
    assert any("independently verify the seller" in n.text for n in shop.next_steps)


def test_no_verified_without_a_record():
    assert assess("Is https://www.safaricom.co.ke genuine?").label != Label.VERIFIED_OFFICIAL            # no observations, no verification


def test_swahili_verified_copy():
    from dataclasses import asdict
    from ssi_rules.i18n import localize
    sw = localize(asdict(assess("Is https://www.safaricom.co.ke genuine?", observations=obs(SAFARICOM_REVIEWED))), "sw")
    assert sw["label_text"] == "Imethibitishwa" and "Thibitisha ofa husika" in sw["summary"] and "hakikisha inalingana kabisa" in sw["next_steps"][0]["text"]
