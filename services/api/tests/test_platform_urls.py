import pytest

from app.platform_urls import parse_social_url
from app.url_pipeline import parse_platform_profile

CASES = [
    ("https://www.tiktok.com/@kicks.nairobi", "tiktok", "kicks.nairobi", "profile"),
    ("https://www.tiktok.com/@kicks.nairobi/video/7312345678901234567?is_from_webapp=1&sender_device=pc", "tiktok", "kicks.nairobi", "video"),
    ("tiktok.com/@kicks.nairobi/photo/7312345678901234567", "tiktok", "kicks.nairobi", "photo"),
    ("https://www.tiktok.com/@kicks.nairobi/live", "tiktok", "kicks.nairobi", "live"),
    ("https://vm.tiktok.com/ZMabc123/", "tiktok", None, "short_link"),
    ("https://www.tiktok.com/t/ZTRabc123/", "tiktok", None, "short_link"),
    ("https://www.tiktok.com/view/product/1729384756", "tiktok", None, "product"),
    ("https://www.instagram.com/duka_la_viatu/", "instagram", "duka_la_viatu", "profile"),
    ("https://www.instagram.com/duka_la_viatu/reel/CxYz123/", "instagram", "duka_la_viatu", "reel"),
    ("https://www.instagram.com/p/CxYz123AbC/?igsh=abc", "instagram", None, "post"),
    ("https://www.instagram.com/reel/CxYz123AbC/", "instagram", None, "reel"),
    ("https://instagr.am/p/CxYz123", "instagram", None, "short_link"),
    ("https://www.facebook.com/mamamboga.shop", "facebook", "mamamboga.shop", "profile"),
    ("https://www.facebook.com/mamamboga.shop/posts/pfbid02abc", "facebook", "mamamboga.shop", "post"),
    ("https://www.facebook.com/profile.php?id=100089912345678", "facebook", "id100089912345678", "profile"),
    ("https://web.facebook.com/marketplace/item/7654321098/", "facebook", None, "marketplace_item"),
    ("https://fb.watch/xYz12/", "facebook", None, "short_link"),
    ("https://x.com/kicksnairobi/status/1788888888", "x", "kicksnairobi", "post"),
    ("https://twitter.com/kicksnairobi", "x", "kicksnairobi", "profile"),
    ("https://wa.me/254712345678", "whatsapp", None, "chat"),
    ("https://chat.whatsapp.com/Abc123Def", "whatsapp", None, "group_invite"),
    ("https://t.me/kenya_shop", "telegram", "kenya_shop", "profile"),
    ("https://t.me/kenya_shop/42", "telegram", "kenya_shop", "post"),
    ("https://t.me/joinchat/Abc123Def", "telegram", None, "group_invite"),
    ("https://t.me/+Abc123Def", "telegram", None, "group_invite"),
]


@pytest.mark.parametrize("url,platform,handle,kind", CASES)
def test_every_supported_social_url_shape(url, platform, handle, kind):
    link = parse_social_url(url)
    assert link is not None
    assert (link.platform, link.handle, link.content_kind) == (platform, handle, kind)
    profile = parse_platform_profile(url)
    assert profile.platform == platform
    assert profile.handle == handle or (kind == "group_invite" and profile.handle == link.content_id)
    assert profile.content_kind == kind


def test_non_social_and_reserved_paths_are_not_accounts():
    assert parse_social_url("https://www.mamamboga-shop.co.ke/products/air-max-90") is None
    assert parse_social_url("https://example.com/@kicks") is None
    assert parse_social_url("https://www.instagram.com/explore/").handle is None
    assert parse_social_url("https://www.tiktok.com/foryou").handle is None


def test_social_parser_rejects_credentials_and_non_standard_ports():
    assert parse_social_url("https://user:pass@www.tiktok.com/@shop/video/123456789") is None
    assert parse_social_url("https://www.tiktok.com:8080/@shop/video/123456789") is None


def test_instagram_reel_canonicalization_preserves_revealed_account():
    from app.url_pipeline import _canonical_profile_url, parse_platform_profile

    raw = "https://www.instagram.com/duka_la_viatu/reel/CxYz123AbC/?igsh=tracking"
    profile = parse_platform_profile(raw)
    assert profile.handle == "duka_la_viatu"
    assert profile.content_kind == "reel"
    assert _canonical_profile_url(raw) == "https://www.instagram.com/duka_la_viatu/reel/CxYz123AbC/"
