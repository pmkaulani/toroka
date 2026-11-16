import pytest
from ssi_connectors.deceptive_links import deceptive_link_flags as flags, registered_domain, within_one

BRANDS = {"Jumia": {"jumia.co.ke", "jumia.com.ng", "jumia.com"}, "Safaricom": {"safaricom.co.ke"}, "Kilimall": {"kilimall.co.ke"}, "Amazon": {"amazon.com"}}


@pytest.mark.parametrize("url,code,sev", [
    ("https://jumia-kenya-deals.com/promo", "brand_in_domain", "major"),
    ("https://www.jumia.co.ke.cheap-phones.xyz/login", "embedded_official_domain", "critical"),
    ("https://jumia.co.ke@cheap-phones.xyz/", "userinfo_trick", "critical"),
    ("https://jumia.co.ke:pw@cheap-phones.xyz/", "userinfo_trick", "critical"),
    ("https://www.jum1a.co.ke/phone", "misspelled_brand", "major"),
    ("https://jumla.co.ke", "misspelled_brand", "major"),
    ("https://jumia.cheap-phones.xyz/", "brand_in_subdomain", "critical"),
    ("https://safaricom-promo.com", "brand_in_domain", "major"),
    ("https://xn--jumia-9ua.co.ke", "lookalike_characters", "major"),
    ("https://amazonia-coffee.co.ke", "brand_in_domain", "major"),
])
def test_deceptive_links_are_flagged(url, code, sev):
    f = flags(url, BRANDS); assert f and f[0].code == code or code in {x.code for x in f}, f
    assert any(x.code == code and x.severity == sev for x in f)


@pytest.mark.parametrize("url", ["https://www.jumia.co.ke/phone-123.html", "https://jumia.co.ke", "https://m.jumia.com.ng/x", "https://www.safaricom.co.ke/fraud-awareness", "https://www.kilimall.co.ke/listing/1",
                                 "https://www.jiji.co.ke/phones", "https://jumbo.co.ke", "https://www.mamamboga-shop.co.ke/p/1", "https://example.com", "tiktok.com/@jumia_fan"])
def test_real_and_unrelated_links_are_not_flagged(url):
    assert flags(url, BRANDS) == [], flags(url, BRANDS)


def test_helpers():
    assert registered_domain("a.b.jumia.co.ke") == "jumia.co.ke" and registered_domain("www.shop.com") == "shop.com"
    assert within_one("jumia", "jum1a") and within_one("jumia", "jmia") and within_one("jumia", "jumiaa") and within_one("jumia", "jumai") and not within_one("jumia", "jumbo")
