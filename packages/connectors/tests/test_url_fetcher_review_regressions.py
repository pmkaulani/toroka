"""Regression tests from the 2026-11 code review of safe_fetch_page."""
import time
import tracemalloc
import zlib

import httpx
import pytest

from ssi_connectors.url_fetcher import safe_fetch_page
from ssi_rules.vocabulary import CoverageStatus

PUBLIC = lambda host: ["93.184.216.34"]  # noqa: E731
PAGE = b"<html><head><title>Login</title></head><body><input type='password'> verify now</body></html>"


def _ok(req):
    return httpx.Response(200, headers={"content-type": "text/html"}, content=PAGE)


@pytest.mark.parametrize("url", [
    "https://evil.example/?.apk",
    "https://evil.example/#.exe",
    "https://www.bing.com/",
    "https://shop.battery-kenya.co.ke/",
    "https://www.isosport.co.ke/",
    "https://www.binance.com/",
])
def test_binary_extension_filter_does_not_skip_html_pages(url):
    r = safe_fetch_page(url, transport=httpx.MockTransport(_ok), resolver=PUBLIC)
    assert r.status == CoverageStatus.CHECKED
    assert r.has_password_field is True


def test_real_binary_content_type_is_still_skipped():
    def h(req):
        return httpx.Response(200, headers={"content-type": "application/vnd.android.package-archive"}, content=b"PK")
    r = safe_fetch_page("https://evil.example/app", transport=httpx.MockTransport(h), resolver=PUBLIC)
    assert r.status == CoverageStatus.NOT_APPLICABLE


def test_missing_content_type_falls_back_to_path_extension():
    def h(req):
        return httpx.Response(200, content=b"MZ\x90")
    r = safe_fetch_page("https://evil.example/setup.exe", transport=httpx.MockTransport(h), resolver=PUBLIC)
    assert r.status == CoverageStatus.NOT_APPLICABLE


def test_total_budget_is_enforced_while_streaming_the_body():
    class Drip(httpx.SyncByteStream):
        def __iter__(self):
            for _ in range(20):
                time.sleep(0.25)
                yield b"<p>x</p>"

    def h(req):
        return httpx.Response(200, headers={"content-type": "text/html"}, stream=Drip())

    t0 = time.monotonic()
    r = safe_fetch_page("https://slow.example/", transport=httpx.MockTransport(h), resolver=PUBLIC,
                        total_budget=0.8, max_bytes=10_000)
    assert time.monotonic() - t0 < 2.0
    assert r.status == CoverageStatus.COULD_NOT_CHECK
    assert "budget" in r.reason.lower()


class _Chunks(httpx.SyncByteStream):
    """A real streaming body, so decoding happens inside the fetcher (httpx.Response(content=...) decodes eagerly)."""
    def __init__(self, data, size=65536):
        self.data, self.size = data, size

    def __iter__(self):
        for i in range(0, len(self.data), self.size):
            yield self.data[i:i + self.size]


def test_compression_bomb_is_bounded():
    bomb = zlib.compress(b"A" * (300 * 1024 * 1024), 9)

    def h(req):
        return httpx.Response(200, headers={"content-type": "text/html", "content-encoding": "deflate"}, stream=_Chunks(bomb))

    tracemalloc.start()
    try:
        r = safe_fetch_page("https://bomb.example/", transport=httpx.MockTransport(h), resolver=PUBLIC)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < 20 * 1024 * 1024, f"peak {peak/1e6:.0f} MB"
    assert r.status in (CoverageStatus.CHECKED, CoverageStatus.COULD_NOT_CHECK)


def test_gzip_body_still_parsed():
    import gzip
    gz = gzip.compress(PAGE)

    def h(req):
        return httpx.Response(200, headers={"content-type": "text/html", "content-encoding": "gzip"}, stream=_Chunks(gz, 16))

    r = safe_fetch_page("https://ok.example/", transport=httpx.MockTransport(h), resolver=PUBLIC)
    assert r.status == CoverageStatus.CHECKED and r.has_password_field


def test_unsupported_encoding_is_reported_not_guessed():
    def h(req):
        return httpx.Response(200, headers={"content-type": "text/html", "content-encoding": "br"}, stream=_Chunks(b"\x00"))
    r = safe_fetch_page("https://ok.example/", transport=httpx.MockTransport(h), resolver=PUBLIC)
    assert r.status == CoverageStatus.COULD_NOT_CHECK
