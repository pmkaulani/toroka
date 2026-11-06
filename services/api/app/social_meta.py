"""Public, no-key social metadata helpers. Fail closed and never scrape profile pages."""
from __future__ import annotations

import re
from urllib.parse import quote, urlsplit

import httpx

from .platform_urls import parse_social_url

OEMBED = "https://www.tiktok.com/oembed?url="
_HANDLE = re.compile(r"^[A-Za-z0-9_.-]{2,50}$")


def tiktok_oembed_url(video_url: str) -> str:
    return OEMBED + quote(video_url, safe="")


def parse_tiktok_oembed(payload: dict) -> dict | None:
    if not isinstance(payload, dict) or not (payload.get("author_name") or payload.get("title")):
        return None
    author_url = str(payload.get("author_url") or "").strip()
    handle = str(payload.get("author_unique_id") or "").strip().lstrip("@")
    if not handle and author_url:
        try:
            parts = urlsplit(author_url)
            if parts.scheme == "https" and (parts.hostname or "").lower() in {"www.tiktok.com", "tiktok.com"}:
                match = re.fullmatch(r"/@([A-Za-z0-9_.-]{2,50})/?", parts.path)
                if match:
                    handle = match.group(1)
        except ValueError:
            handle = ""
    if handle and not _HANDLE.fullmatch(handle):
        handle = ""
    return {
        "account_name": str(payload.get("author_name") or "").strip()[:80] or None,
        "handle": handle[:50] or None,
        "caption": str(payload.get("title") or "").strip()[:1000],
        "author_url": author_url if author_url.startswith("https://www.tiktok.com/@") else None,
    }


def fetch_tiktok_oembed(video_url: str, *, client: httpx.Client | None = None, timeout: float = 5.0) -> dict | None:
    """Fetch TikTok's public oEmbed metadata for known TikTok video/share URLs only."""
    link = parse_social_url(video_url)
    if not link or link.platform != "tiktok" or link.content_kind not in {"video", "photo", "short_link"}:
        return None
    try:
        owned_client = client is None
        c = client or httpx.Client(timeout=timeout, follow_redirects=False, headers={"User-Agent": "Toroka/1.0 (+public oEmbed metadata)", "Accept": "application/json"})
        try:
            response = c.get(tiktok_oembed_url(video_url))
            if response.status_code != 200:
                return None
            if len(response.content) > 200_000:
                return None
            return parse_tiktok_oembed(response.json())
        finally:
            if owned_client:
                c.close()
    except (httpx.HTTPError, ValueError, TypeError):
        return None
    except Exception:
        return None
