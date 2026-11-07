import hashlib, hmac, io, json
import httpx
import pytest
from PIL import Image, ImageDraw, ImageFont
from ssi_connectors import channels, images, ocr, rdap, reputation, safe_fetch
from ssi_connectors.geocode import NominatimGeocoder
from ssi_rules.vocabulary import CoverageStatus as CS

PUBLIC = lambda host: ["93.184.216.34"]


def mock(routes):
    seen = []
    def handler(req: httpx.Request):
        seen.append(req)
        loc = routes.get((req.headers["host"], req.url.path))
        if isinstance(loc, int):
            return httpx.Response(loc)
        return httpx.Response(302, headers={"location": loc}) if loc else httpx.Response(200)
    return httpx.MockTransport(handler), seen


# ---- safe redirect following ----
def test_follows_redirects_pinned_to_the_validated_ip_with_original_host():
    t, seen = mock({("bit.ly", "/abc"): "https://safaricom-rewards.xyz/claim", ("safaricom-rewards.xyz", "/claim"): None})
    r = safe_fetch.follow_redirects("bit.ly/abc", transport=t, resolver=PUBLIC)
    assert r.status == CS.CHECKED and r.final_url == "https://safaricom-rewards.xyz/claim" and r.hops == 1
    assert [s.url.host for s in seen] == ["93.184.216.34", "93.184.216.34"] and seen[0].headers["host"] == "bit.ly"
    assert all(s.method == "GET" and s.headers["range"] == "bytes=0-0" for s in seen)          # headers only, no body download


@pytest.mark.parametrize("url,resolver", [
    ("http://127.0.0.1/x", PUBLIC), ("http://169.254.169.254/latest/meta-data", PUBLIC), ("file:///etc/passwd", PUBLIC),
    ("http://internal.example.com/", lambda h: ["10.0.0.7"]), ("http://mixed.example.com/", lambda h: ["93.184.216.34", "192.168.1.1"]),
    ("http://rebind.example.com/", lambda h: ["::ffff:127.0.0.1"])])
def test_blocks_private_targets_before_any_request(url, resolver):
    t, seen = mock({})
    r = safe_fetch.follow_redirects(url, transport=t, resolver=resolver)
    assert r.status == CS.COULD_NOT_CHECK and not seen and "blocked" in r.reason


def test_redirect_into_a_private_address_is_stopped_mid_chain():
    t, seen = mock({("example.com", "/"): "http://169.254.169.254/latest"})
    r = safe_fetch.follow_redirects("http://example.com/", transport=t, resolver=PUBLIC)
    assert r.status == CS.COULD_NOT_CHECK and len(seen) == 1 and "blocked" in r.reason


def test_redirect_loops_and_unresolvable_names_fail_safely():
    t, _ = mock({("a.example", "/"): "http://a.example/"})
    assert safe_fetch.follow_redirects("http://a.example/", transport=t, resolver=PUBLIC, max_hops=3).reason == "too many redirects"
    def boom(h): raise OSError("nxdomain")
    assert safe_fetch.follow_redirects("http://nope.example/", transport=t, resolver=boom).reason == "name did not resolve"


# ---- reputation ----
def test_local_blocklist_matches_host_and_registered_domain():
    bl = reputation.LocalBlocklist([{"value": "prize-claims.example.com"}, {"value": "evil.example", "kind": "domain", "threat": "MALWARE"}])
    assert bl.lookup("https://prize-claims.example.com/win").threat_types == ["SOCIAL_ENGINEERING"]
    assert bl.lookup("http://cdn.evil.example/x").threat_types == ["MALWARE"]
    assert bl.lookup("https://menu.example.com").threat_types == [] and bl.lookup("https://menu.example.com").status == CS.CHECKED


def test_webrisk_adapter_parses_hit_miss_error_and_caches():
    calls = []
    def handler(req):
        calls.append(req)
        u = req.url.params["uri"]
        if "bad" in u: return httpx.Response(200, json={"threat": {"threatTypes": ["SOCIAL_ENGINEERING"], "expireTime": "2026-10-21T00:00:00Z"}})
        if "err" in u: return httpx.Response(500)
        return httpx.Response(200, json={})
    p = reputation.WebRiskProvider("KEY", httpx.MockTransport(handler))
    assert p.lookup("https://bad.example/").threat_types == ["SOCIAL_ENGINEERING"]
    assert p.lookup("https://good.example/").threat_types == [] and p.lookup("https://err.example/").status == CS.COULD_NOT_CHECK
    n = len(calls); p.lookup("https://bad.example/"); assert len(calls) == n              # cached
    assert "THREAT" not in str(calls[0].url) and calls[0].url.params["key"] == "KEY" and "SOCIAL_ENGINEERING" in str(calls[0].url)


def test_combine_providers_and_nothing_configured():
    assert reputation.combine([], "https://x.example") is None
    bl = reputation.LocalBlocklist([{"value": "x.example"}])
    r = reputation.combine([bl], "https://x.example/p")
    assert r.status == CS.CHECKED and r.threat_types == ["SOCIAL_ENGINEERING"]


# ---- rdap, geocode ----
def test_rdap_age_and_failures():
    t = httpx.MockTransport(lambda req: httpx.Response(200, json={"events": [{"eventAction": "registration", "eventDate": "2026-10-10T00:00:00Z"}]}))
    st, age = rdap.domain_age_days("new.example", transport=t)
    assert st == CS.CHECKED and 0 <= age < 3000
    assert rdap.domain_age_days("x.example", transport=httpx.MockTransport(lambda r: httpx.Response(500)))[0] == CS.COULD_NOT_CHECK


def test_nominatim_needs_identifying_user_agent_and_reports_found_or_not():
    with pytest.raises(ValueError):
        NominatimGeocoder("python-requests")
    g = NominatimGeocoder("SSI/0.1 (contact@example.com)", httpx.MockTransport(lambda r: httpx.Response(200, json=[])))
    obs = g.lookup("12 Nowhere Road, Nairobi")
    assert obs.status == CS.CHECKED and obs.found is False


# ---- images and OCR ----
def _font(size=44):
    for name in ["arial.ttf", "Arial.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", "DejaVuSans.ttf"]:
        try:
            return ImageFont.truetype(name, size)
        except OSError:
            pass
    return ImageFont.load_default()


def png_with_text(text="Pay KSh 350 to activate funds", size=(900, 160)):
    img = Image.new("RGB", size, "white")
    ImageDraw.Draw(img).text((20, 50), text, fill="black", font=_font(44))
    b = io.BytesIO(); img.save(b, "PNG"); return b.getvalue()


def test_image_sanitizer_rejects_wrong_types_and_oversize_and_strips_exif():
    with pytest.raises(images.ImageRejected): images.sanitize(b"MZ\x90\x00 not an image")
    with pytest.raises(images.ImageRejected): images.sanitize(b"\x89PNG\r\n\x1a\n" + b"x" * 20)                  # looks like PNG, is not
    with pytest.raises(images.ImageRejected): images.sanitize(b"\x89PNG\r\n\x1a\n" + b"0" * (images.MAX_BYTES + 1))
    img = Image.new("RGB", (40, 40), "red"); exif = Image.Exif(); exif[0x010F] = "SecretPhoneMaker"
    b = io.BytesIO(); img.save(b, "JPEG", exif=exif.tobytes())
    assert b"SecretPhoneMaker" in b.getvalue()
    clean = images.sanitize(b.getvalue())
    assert b"SecretPhoneMaker" not in clean.png and clean.detected == "jpeg" and Image.open(io.BytesIO(clean.png)).getexif() == {}


def photo_like(seed, size=(480, 360)):
    import random
    r = random.Random(seed); img = Image.new("RGB", size, (r.randrange(256),) * 3); d = ImageDraw.Draw(img)
    for _ in range(40):
        x, y = r.randrange(size[0]), r.randrange(size[1])
        d.rectangle([x, y, x + r.randrange(40, 200), y + r.randrange(40, 160)], fill=tuple(r.randrange(256) for _ in range(3)))
    b = io.BytesIO(); img.save(b, "PNG"); return img, b.getvalue()


def test_dhash_matches_resized_copies_and_differs_for_other_images():
    img, raw = photo_like(1)
    small = io.BytesIO(); img.resize((240, 180)).save(small, "JPEG", quality=80)
    a = images.sanitize(raw)
    assert images.hamming(a.dhash, images.sanitize(small.getvalue()).dhash) <= 8       # a match is a lead, not proof
    assert images.hamming(a.dhash, images.sanitize(photo_like(2)[1]).dhash) > 8


def test_ocr_reads_text_and_reports_confidence_and_language_note():
    r = ocr.ocr_png(images.sanitize(png_with_text()).png)
    assert r.status == CS.CHECKED and "350" in r.text and "activate" in r.text.lower() and r.mean_confidence and r.mean_confidence > 60
    if "swa" in ocr.available_languages():
        assert "swa" in r.language.lower() and "Swahili" not in r.note
    else:
        assert "Swahili" in r.note


# ---- channels ----
def test_meta_signature_and_whatsapp_parsing():
    body = json.dumps({"entry": [{"changes": [{"value": {"messages": [
        {"from": "254712345678", "id": "wamid.1", "type": "text", "text": {"body": "Pay KSh 350 to activate funds"}},
        {"from": "254712345678", "id": "wamid.2", "type": "image"}]}}]}]}).encode()
    sig = "sha256=" + hmac.new(b"secret", body, hashlib.sha256).hexdigest()
    assert channels.verify_meta_signature("secret", body, sig) and not channels.verify_meta_signature("other", body, sig)
    assert not channels.verify_meta_signature("secret", body, None) and not channels.verify_meta_signature("secret", body, "sha1=abc")
    msgs = channels.parse_whatsapp(json.loads(body))
    assert [(m.sender, m.text) for m in msgs] == [("254712345678", "Pay KSh 350 to activate funds")]


def test_africastalking_parse_and_reply_format_is_short_and_honest():
    from dataclasses import asdict
    from ssi_rules import assess
    m = channels.parse_africastalking({"from": "+254712345678", "text": "Pay KSh 350 to activate funds", "id": "AT1"})
    assert m and m.channel == "sms" and channels.parse_africastalking({"from": "+254712345678"}) is None
    msg = channels.format_reply(asdict(assess(m.text)), "https://ssi.example/r/abc", max_len=320)
    assert len(msg) <= 320 and msg.startswith("Suspicious") and "https://ssi.example/r/abc" in msg and "scammer" not in msg.lower()
    sw = channels.format_reply(asdict(assess(m.text)), None, lang="sw")
    assert sw.startswith("Una shaka")


def test_senders_post_expected_requests_and_swallow_failures():
    seen = []
    def h(req): seen.append(req); return httpx.Response(200, json={})
    assert channels.WhatsAppSender("TOKEN", "123", transport=httpx.MockTransport(h)).send_text("254712345678", "hi")
    assert seen[0].headers["authorization"] == "Bearer TOKEN" and "/123/messages" in str(seen[0].url) and b'"preview_url":false' in seen[0].content.replace(b" ", b"")
    assert channels.AfricasTalkingSender("sandbox", "KEY", transport=httpx.MockTransport(h)).send_text("254712345678", "hi")
    assert seen[1].headers["apikey"] == "KEY" and b"%2B254712345678" in seen[1].content
    assert not channels.WhatsAppSender("T", "1", transport=httpx.MockTransport(lambda r: httpx.Response(500))).send_text("1", "x")


def test_marketplace_fetch_extracts_product_offer_seller_and_rating_from_jsonld():
    from ssi_connectors.url_fetcher import safe_fetch_page
    from ssi_rules.vocabulary import CoverageStatus

    html = '''<!doctype html><html><head>
      <title>Wireless Headphones - Jumia</title>
      <meta property="og:description" content="Wireless headphones with noise reduction">
      <link rel="canonical" href="https://www.jumia.co.ke/wireless-headphones-123.html">
      <script type="application/ld+json">{
        "@context":"https://schema.org",
        "@type":"Product",
        "name":"Wireless Headphones X200",
        "description":"Bluetooth headphones with noise reduction",
        "sku":"X200-KE",
        "brand":{"@type":"Brand","name":"SoundMax"},
        "image":["https://images.example.test/x200.jpg"],
        "aggregateRating":{"@type":"AggregateRating","ratingValue":"4.2","ratingCount":"84"},
        "offers":{"@type":"Offer","price":"3499","priceCurrency":"KES","availability":"https://schema.org/InStock",
          "seller":{"@type":"Organization","name":"Acme Digital","aggregateRating":{"@type":"AggregateRating","ratingValue":"4.6"}}},
        "review":[{"@type":"Review","reviewBody":"Battery life is good for daily use."}]
      }</script>
    </head><body><main>Delivery information and returns policy available.</main></body></html>'''

    transport = httpx.MockTransport(lambda request: httpx.Response(
        200, headers={"content-type": "text/html; charset=utf-8"}, text=html
    ))
    result = safe_fetch_page(
        "https://www.jumia.co.ke/wireless-headphones-123.html",
        transport=transport,
        resolver=PUBLIC,
    )

    assert result.status == CoverageStatus.CHECKED
    product = result.product_data
    assert product["detected"] is True
    assert product["extraction_status"] == "complete"
    assert product["name"] == "Wireless Headphones X200"
    assert product["price"] == 3499.0 and product["currency"] == "KES"
    assert product["seller_name"] == "Acme Digital"
    assert product["seller_rating"] == "4.6"
    assert product["aggregate_rating"] == "4.2"
    assert product["rating_count"] == "84"
    assert product["availability"] == "InStock"
    assert product["sku"] == "X200-KE"
    assert product["canonical_url"].endswith("wireless-headphones-123.html")
    assert product["review_excerpts"] == ["Battery life is good for daily use."]
    assert product["delivery_terms_found"] and product["return_terms_found"]
    assert "Wireless Headphones X200" not in result.visible_text  # JSON-LD is not rendered as visible page text.


@pytest.mark.parametrize(
    "status,expected,reason_fragment",
    [
        (401, CS.INACCESSIBLE, "denied automated access"),
        (403, CS.INACCESSIBLE, "denied automated access"),
        (429, CS.INACCESSIBLE, "rate-limited"),
        (404, CS.NOT_FOUND, "not found"),
        (410, CS.NOT_FOUND, "not found"),
        (500, CS.COULD_NOT_CHECK, "HTTP 500"),
    ],
)
def test_safe_fetch_never_treats_http_error_pages_as_successful_inspections(status, expected, reason_fragment):
    transport = httpx.MockTransport(lambda request: httpx.Response(status, headers={"content-type": "text/html"}, text="Access denied"))
    from ssi_connectors.url_fetcher import safe_fetch_page
    result = safe_fetch_page(
        "https://shop.example.test/item/123",
        transport=transport,
        resolver=PUBLIC,
    )
    assert result.status == expected
    assert result.status_code == status
    assert reason_fragment in result.reason
    assert not result.visible_text


def test_marketplace_host_detection_uses_domain_boundaries():
    from ssi_connectors.marketplace import identify_marketplace

    assert identify_marketplace("https://www.jumia.co.ke/product/123")["name"] == "Jumia"
    assert identify_marketplace("https://seller.kilimall.co.ke/item/123")["name"] == "Kilimall"
    assert identify_marketplace("https://notjumia.co.ke/product/123")["is_marketplace"] is False
    assert identify_marketplace("https://jumia.co.ke.attacker.example/product/123")["is_marketplace"] is False


def test_jsonld_walker_is_bounded_for_deeply_nested_page_data():
    from ssi_connectors.url_fetcher import _jsonld_nodes

    nested = {"@type": "Thing"}
    for _ in range(40):
        nested = {"nested": nested}
    nodes = list(_jsonld_nodes(nested))
    assert len(nodes) <= 17
