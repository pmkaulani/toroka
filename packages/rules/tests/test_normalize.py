import pytest
from ssi_rules.normalize import (extract_phones, extract_urls, is_fetch_safe, mask_phone, normalize_ke_phone,
                                 parse_url, registered_domain, extract_payment_ids, extract_amounts)


@pytest.mark.parametrize("raw", ["0722000000", "0722 000 000", "+254 722 000 000", "254722000000", "(0722) 000-000"])
def test_phone_variants_normalise_to_e164(raw):
    assert normalize_ke_phone(raw) == "+254722000000"


@pytest.mark.parametrize("raw", ["333", "072200000", "07220000000", "0422000000", "+255722000000", "abc"])
def test_non_phones_rejected(raw):
    assert normalize_ke_phone(raw) is None


def test_01_range_accepted_and_masking_hides_middle():
    n = normalize_ke_phone("0112345678")
    assert n == "+254112345678"
    assert mask_phone(n) == "+2541••••678" and "2345" not in mask_phone(n)


def test_extract_phones_ignores_mpesa_codes_and_amounts():
    t = "QJK1ABC2XY Confirmed. Ksh500.00 sent to JOHN 0712345678 on 20/10/26."
    assert [p.normalized for p in extract_phones(t)] == ["+254712345678"]


def test_extract_urls_bare_domains_and_trailing_punctuation_and_email():
    t = "Visit www.safaricom.co.ke, or bit.ly/abc123. Email me at john.doe@gmail.com. Also https://kra.go.ke/en/careers!"
    hosts = [u.host for u in extract_urls(t)]
    assert hosts == ["www.safaricom.co.ke", "bit.ly", "kra.go.ke"]


def test_registered_domain_handles_kenyan_second_level():
    assert registered_domain("m.safaricom.co.ke") == "safaricom.co.ke"
    assert registered_domain("a.b.kra.go.ke") == "kra.go.ke"
    assert registered_domain("safaricom-rewards.xyz") == "safaricom-rewards.xyz"


def test_parse_url_flags():
    assert parse_url("http://bit.ly/x").is_shortener
    assert parse_url("http://192.168.1.5/login").is_ip
    assert parse_url("https://xn--sfaricom-q1a.com").is_punycode
    assert parse_url("https://kra.go.ke@evil.example/").has_userinfo
    assert parse_url("http://[::1") is None


def test_amounts_and_payment_ids():
    assert [a.normalized for a in extract_amounts("Pay Ksh4,500 and KES 350.50")] == ["4500", "350.50"]
    assert [p.normalized for p in extract_payment_ids("Pay to Till Number 123456 or paybill: 987654")] == ["till:123456", "paybill:987654"]


@pytest.mark.parametrize("url", [
    "http://127.0.0.1/admin", "http://localhost/x", "http://169.254.169.254/latest/meta-data/", "http://10.0.0.5/",
    "http://[::1]/", "http://[::ffff:127.0.0.1]/", "http://2130706433/", "http://0x7f000001/", "http://0177.0.0.1/",
    "ftp://example.com/", "file:///etc/passwd", "http://user:pw@example.com/", "http://example.com:8080/", "http://printer.local/"])
def test_ssrf_guard_rejects_unsafe_targets(url):
    ok, reason = is_fetch_safe(url)
    assert not ok, (url, reason)


@pytest.mark.parametrize("url", ["https://kra.go.ke/careers", "http://example.com/a?b=c", "https://8.8.8.8/"])
def test_ssrf_guard_allows_public_targets(url):
    assert is_fetch_safe(url)[0]
