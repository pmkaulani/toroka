"""Parse public social URLs into account and content identities without scraping.

Only exact, known platform hosts are accepted. Query strings are deliberately not
used to infer identities and are never retained in parsed identifiers.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import parse_qs, urlsplit

RESERVED = {
    "p", "reel", "reels", "tv", "stories", "explore", "accounts", "share",
    "login", "about", "help", "legal", "watch", "groups", "pages", "marketplace",
    "events", "photo", "video", "videos", "hashtag", "tag", "search", "discover",
    "foryou", "following", "live", "shop", "view", "t", "i", "intent", "home",
    "settings", "privacy", "terms", "policies", "business", "directory", "gaming",
}
SHORT_HOSTS = {"vm.tiktok.com", "vt.tiktok.com", "instagr.am", "fb.me", "fb.watch", "t.co"}
HOSTS = {
    "tiktok": {"tiktok.com", "www.tiktok.com", "m.tiktok.com", "vm.tiktok.com", "vt.tiktok.com"},
    "instagram": {"instagram.com", "www.instagram.com", "m.instagram.com", "instagr.am"},
    "facebook": {"facebook.com", "www.facebook.com", "m.facebook.com", "web.facebook.com", "fb.com", "fb.me", "fb.watch"},
    "x": {"x.com", "www.x.com", "twitter.com", "www.twitter.com", "mobile.twitter.com", "t.co"},
    "whatsapp": {"wa.me", "chat.whatsapp.com", "api.whatsapp.com"},
}
_HANDLE = re.compile(r"^[A-Za-z0-9_.-]{2,50}$")
_CONTENT_ID = re.compile(r"^[A-Za-z0-9_-]{3,80}$")


@dataclass(frozen=True)
class SocialLink:
    platform: str
    handle: str | None
    content_kind: str
    content_id: str | None = None
    profile_url: str | None = None
    needs_redirect: bool = False
    phone: str | None = None

    @property
    def is_account_known(self) -> bool:
        return bool(self.handle or self.phone)


def _platform(host: str) -> str | None:
    host = host.lower().rstrip(".")
    return next((name for name, hosts in HOSTS.items() if host in hosts), None)


def _valid_handle(value: str | None) -> bool:
    return bool(value and _HANDLE.fullmatch(value) and value.casefold() not in RESERVED and not value.isdigit())


def parse_social_url(raw: str) -> SocialLink | None:
    """Recognise profiles, videos, posts, reels, listings and platform share links."""
    value = (raw or "").strip()
    if not value:
        return None
    if "://" not in value:
        value = "https://" + value
    try:
        parsed = urlsplit(value)
        host = (parsed.hostname or "").lower().rstrip(".")
        # Reject credentials, unsupported schemes, non-standard ports and malformed URLs.
        if parsed.scheme not in {"http", "https"} or parsed.username or parsed.password:
            return None
        if parsed.port not in (None, 80, 443):
            return None
    except ValueError:
        return None
    platform = _platform(host)
    if not platform:
        return None
    path = parsed.path.rstrip("/") or "/"
    query = parse_qs(parsed.query, keep_blank_values=False)

    # Share URLs hide their final account until the platform's own metadata endpoint resolves them.
    if host in SHORT_HOSTS or (platform == "tiktok" and re.fullmatch(r"/t/[A-Za-z0-9_-]+", path)):
        token = path.strip("/").split("/")[-1] or None
        return SocialLink(platform, None, "short_link", token, None, True)

    if platform == "tiktok":
        match = re.fullmatch(r"/@([A-Za-z0-9_.-]{2,50})/(video|photo)/([0-9]{6,30})", path, re.I)
        if match and _valid_handle(match.group(1)):
            handle, kind, content_id = match.groups()
            return SocialLink("tiktok", handle, kind.lower(), content_id, f"https://www.tiktok.com/@{handle}")
        match = re.fullmatch(r"/@([A-Za-z0-9_.-]{2,50})/live", path, re.I)
        if match and _valid_handle(match.group(1)):
            handle = match.group(1)
            return SocialLink("tiktok", handle, "live", None, f"https://www.tiktok.com/@{handle}")
        match = re.fullmatch(r"/(?:view/product|shop/(?:pdp|product))/(?:[^/]+/)?([0-9]{5,30})", path, re.I)
        if match:
            return SocialLink("tiktok", None, "product", match.group(1))
        match = re.fullmatch(r"/@([A-Za-z0-9_.-]{2,50})", path, re.I)
        if match and _valid_handle(match.group(1)):
            handle = match.group(1)
            return SocialLink("tiktok", handle, "profile", None, f"https://www.tiktok.com/@{handle}")

    elif platform == "instagram":
        match = re.fullmatch(r"/([A-Za-z0-9_.-]{2,50})/(reel|reels|tv)/([A-Za-z0-9_-]{3,80})", path, re.I)
        if match and _valid_handle(match.group(1)):
            handle, route, content_id = match.groups()
            kind = "reel" if route.lower() in {"reel", "reels"} else "tv"
            return SocialLink("instagram", handle, kind, content_id, f"https://www.instagram.com/{handle}/")
        match = re.fullmatch(r"/(p|reel|reels|tv)/([A-Za-z0-9_-]{3,80})", path, re.I)
        if match:
            route, content_id = match.groups()
            kind = "post" if route.lower() == "p" else "reel" if route.lower() in {"reel", "reels"} else "tv"
            return SocialLink("instagram", None, kind, content_id)
        match = re.fullmatch(r"/stories/([A-Za-z0-9_.-]{2,50})/([0-9]{3,30})", path, re.I)
        if match and _valid_handle(match.group(1)):
            handle, content_id = match.groups()
            return SocialLink("instagram", handle, "story", content_id, f"https://www.instagram.com/{handle}/")
        match = re.fullmatch(r"/@?([A-Za-z0-9_.-]{2,50})", path, re.I)
        if match and _valid_handle(match.group(1)):
            handle = match.group(1)
            return SocialLink("instagram", handle, "profile", None, f"https://www.instagram.com/{handle}/")

    elif platform == "facebook":
        if path == "/profile.php" and query.get("id") and query["id"][0].isdigit():
            handle = "id" + query["id"][0]
            return SocialLink("facebook", handle, "profile", None, f"https://www.facebook.com/profile.php?id={query['id'][0]}")
        match = re.fullmatch(r"/marketplace/item/([0-9]{5,30})", path, re.I)
        if match:
            return SocialLink("facebook", None, "marketplace_item", match.group(1))
        match = re.fullmatch(r"/people/([^/]+)/([0-9]{5,30})", path, re.I)
        if match:
            handle = "id" + match.group(2)
            return SocialLink("facebook", handle, "profile", None, f"https://www.facebook.com/profile.php?id={match.group(2)}")
        match = re.fullmatch(r"/([A-Za-z0-9_.-]{2,50})/(posts|videos|photos|reel|reels)/([^/]+)", path, re.I)
        if match and _valid_handle(match.group(1)):
            handle, route, content_id = match.groups()
            kind = "post" if route.lower() == "posts" else route.lower().rstrip("s")
            return SocialLink("facebook", handle, kind, content_id[:80], f"https://www.facebook.com/{handle}")
        match = re.fullmatch(r"/@?([A-Za-z0-9_.-]{2,50})", path, re.I)
        if match and _valid_handle(match.group(1)):
            handle = match.group(1)
            return SocialLink("facebook", handle, "profile", None, f"https://www.facebook.com/{handle}")

    elif platform == "x":
        match = re.fullmatch(r"/@?([A-Za-z0-9_]{1,15})/status/([0-9]{5,30})", path, re.I)
        if match:
            handle, content_id = match.groups()
            return SocialLink("x", handle, "post", content_id, f"https://x.com/{handle}")
        match = re.fullmatch(r"/@?([A-Za-z0-9_]{1,15})", path, re.I)
        if match:
            handle = match.group(1)
            return SocialLink("x", handle, "profile", None, f"https://x.com/{handle}")

    elif platform == "whatsapp":
        if host == "wa.me":
            match = re.fullmatch(r"/\+?([0-9]{9,15})", path)
            if match:
                return SocialLink("whatsapp", None, "chat", None, None, False, "+" + match.group(1))
        if host == "chat.whatsapp.com" and path.strip("/"):
            token = path.strip("/")
            if re.fullmatch(r"[A-Za-z0-9_-]{5,80}", token):
                return SocialLink("whatsapp", None, "group_invite", token)
        if host == "api.whatsapp.com" and path == "/send" and query.get("phone"):
            number = query["phone"][0]
            if re.fullmatch(r"\+?[0-9]{9,15}", number):
                return SocialLink("whatsapp", None, "chat", None, None, False, number if number.startswith("+") else "+" + number)

    return SocialLink(platform, None, "other")
