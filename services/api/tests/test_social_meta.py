import httpx

from app.social_meta import fetch_tiktok_oembed, parse_tiktok_oembed, tiktok_oembed_url

SAMPLE = {
    "version": "1.0", "type": "video",
    "title": "Air Max 90 KSh 3,500 only! Pay half to reserve, DM",
    "author_url": "https://www.tiktok.com/@kicks.nairobi",
    "author_name": "Kicks Nairobi", "thumbnail_url": "https://p16.example/x.jpg", "provider_name": "TikTok",
}


def test_parse_metadata_and_encode_url():
    metadata = parse_tiktok_oembed(SAMPLE)
    assert metadata["account_name"] == "Kicks Nairobi"
    assert metadata["handle"] == "kicks.nairobi"
    assert "Pay half" in metadata["caption"]
    assert tiktok_oembed_url("https://www.tiktok.com/@aa/video/123456789?x=1") == (
        "https://www.tiktok.com/oembed?url=https%3A%2F%2Fwww.tiktok.com%2F%40aa%2Fvideo%2F123456789%3Fx%3D1"
    )
    assert parse_tiktok_oembed({}) is None
    assert parse_tiktok_oembed("not a mapping") is None


def test_fetch_uses_fixed_tiktok_oembed_host_and_fails_closed():
    client = httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(200, json=SAMPLE)))
    result = fetch_tiktok_oembed("https://www.tiktok.com/@aa/video/123456789", client=client)
    assert result and result["handle"] == "kicks.nairobi"
    assert fetch_tiktok_oembed("https://evil.example/@a/video/123456789", client=client) is None

    for response in (httpx.Response(404), httpx.Response(200, text="<html>not json</html>"), httpx.Response(500)):
        bad_client = httpx.Client(transport=httpx.MockTransport(lambda request, r=response: r))
        assert fetch_tiktok_oembed("https://www.tiktok.com/@aa/video/123456789", client=bad_client) is None
