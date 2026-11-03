"""Optional social-platform intelligence providers for Toroka.

This module only retrieves publicly accessible data through configured third-party
APIs. It returns leads/observations; it NEVER assigns a fraud verdict.

Provider documentation:
- Weir: https://docs.weirapp.io/
- Scrape Creators: https://docs.scrapecreators.com/

Keep API keys on the server. Do not send raw conversations, phone numbers, M-PESA
identifiers, PINs, OTPs, passwords, or private screenshots to these providers.
"""
from __future__ import annotations

import copy
import hashlib
import json
import logging
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import threading
import time
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx

logger = logging.getLogger("toroka.social_intelligence")

WEIR_BASE = "https://api.weirapp.io/v1"
SCRAPE_CREATORS_BASE = "https://api.scrapecreators.com"
REQUEST_TIMEOUT = 8.0
MAX_SOCIAL_RESULTS_PER_PROVIDER = 12
MAX_EVIDENCE_RECORDS = 20
SOCIAL_CACHE_TTL_SECONDS = 900
_SOCIAL_CACHE_MAX_ENTRIES = 500
_SOCIAL_CACHE: dict[str, tuple[float, dict[str, Any]]] = {}
_SOCIAL_CACHE_LOCK = threading.Lock()

PLATFORM_PROFILE_URLS = {
    "instagram": "https://www.instagram.com/{handle}/",
    "tiktok": "https://www.tiktok.com/@{handle}",
    "facebook": "https://www.facebook.com/{handle}/",
}

# Complaint language is only used to categorise public allegations. It is not proof.
_COMPLAINT_PATTERNS: dict[str, re.Pattern[str]] = {
    "non_delivery": re.compile(
        r"\b(?:never received|not received|never arrived|not delivered|no delivery|"
        r"failed to deliver|did(?: not|n't) deliver|paid.{0,50}(?:blocked|ignored|disappeared))\b|"
        r"\b(?:hawakutuma|hawajatumia|sijatumiwa|sijapokea|haijafika|hawakudeliver|"
        r"walichukua pesa|amechukua pesa)\b",
        re.I,
    ),
    "payment_dispute": re.compile(
        r"\b(?:took my money|stole my money|paid.{0,40}(?:blocked|ghosted|ignored)|"
        r"payment.{0,30}(?:disappeared|not acknowledged)|refund.{0,30}(?:refused|ignored))\b|"
        r"\b(?:nimeibiwa|wamenipiga|hela zangu|pesa zangu|walikula pesa)\b",
        re.I,
    ),
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _identifier_value(target: dict[str, Any]) -> str:
    return str(target.get("identifier") or "").strip().lstrip("@")[:100]


def _platform(target: dict[str, Any]) -> str:
    value = str(target.get("platform") or "").strip().lower()
    return "x" if value == "twitter" else value


def _safe_profile_url(platform: str, handle: str) -> str | None:
    template = PLATFORM_PROFILE_URLS.get(platform)
    if not template or not re.fullmatch(r"[A-Za-z0-9_.-]{2,60}", handle):
        return None
    return template.format(handle=handle)


def _request_json(method: str, url: str, *, headers: dict[str, str], params: dict[str, Any] | None = None,
                  json_body: dict[str, Any] | None = None) -> tuple[str, dict[str, Any] | None, str]:
    """Return (status, JSON object, safe detail). Never log response bodies or keys."""
    try:
        with httpx.Client(timeout=REQUEST_TIMEOUT, follow_redirects=False) as client:
            response = client.request(method, url, headers=headers, params=params, json=json_body)
        if response.status_code == 404:
            return "checked_no_match", None, "The provider returned no matching public record."
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, dict):
            return "failed", None, "The provider returned an unexpected response format."
        return "checked", payload, "Request completed."
    except httpx.TimeoutException:
        return "failed", None, "The provider timed out."
    except httpx.HTTPStatusError as exc:
        # Do not expose provider response bodies; they may echo user-supplied identifiers.
        code = exc.response.status_code
        if code in (401, 403):
            detail = "The provider rejected the API credential or does not permit this request."
        elif code == 429:
            detail = "The provider rate limit or free allowance was reached."
        else:
            detail = f"The provider returned HTTP {code}."
        logger.warning("Social intelligence provider HTTP failure: %s", code)
        return "failed", None, detail
    except (httpx.HTTPError, ValueError):
        logger.warning("Social intelligence provider request failed")
        return "failed", None, "The provider could not be reached or returned invalid JSON."


def _walk_records(value: Any, *, depth: int = 0) -> list[dict[str, Any]]:
    """Find likely post/video dictionaries in common API response envelopes."""
    if depth > 5:
        return []
    if isinstance(value, list):
        rows: list[dict[str, Any]] = []
        for item in value:
            if isinstance(item, dict):
                if any(k in item for k in ("url", "permalink", "share_url", "text", "caption", "description", "desc", "tweet", "post_id", "id", "aweme_info", "selftext")):
                    rows.append(item)
                else:
                    rows.extend(_walk_records(item, depth=depth + 1))
        return rows
    if not isinstance(value, dict):
        return []
    for key in ("posts", "tweets", "videos", "search_item_list", "aweme_list", "item_list", "results", "items", "edges", "entries", "data"):
        child = value.get(key)
        if isinstance(child, (list, dict)):
            rows = _walk_records(child, depth=depth + 1)
            if rows:
                return rows
    # Some APIs wrap the actual object in a single nested `result` or `post`.
    for key in ("result", "post", "tweet", "video"):
        child = value.get(key)
        if isinstance(child, dict):
            rows = _walk_records(child, depth=depth + 1)
            if rows:
                return rows
            if any(k in child for k in ("url", "permalink", "text", "caption", "description", "id")):
                return [child]
    return []


def _first_text(item: dict[str, Any], names: tuple[str, ...], limit: int = 800) -> str:
    for name in names:
        value = item.get(name)
        if isinstance(value, str) and value.strip():
            return re.sub(r"\s+", " ", value).strip()[:limit]
        if isinstance(value, (int, float)) and name in {"id", "created_at", "timestamp"}:
            return str(value)[:limit]
    return ""


def _author(item: dict[str, Any]) -> str:
    for key in ("author", "user", "owner", "creator"):
        nested = item.get(key)
        if isinstance(nested, dict):
            name = _first_text(nested, ("username", "screen_name", "handle", "unique_id", "name"), 100)
            if name:
                return name.lstrip("@")
    return _first_text(item, ("username", "author_username", "screen_name", "unique_id"), 100).lstrip("@")


def _normalise_url(url: str) -> str:
    try:
        parts = urlsplit(url.strip())
        if parts.scheme not in {"http", "https"} or not parts.netloc:
            return ""
        kept = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True)
                if not (k.lower().startswith("utm_") or k.lower() in {"igsh", "xtok", "fbclid", "gclid", "ref", "source"})]
        return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), parts.path.rstrip("/"), urlencode(kept), ""))[:1500]
    except Exception:
        return ""


def _exact_identity_match(target: dict[str, Any], title: str, snippet: str, url: str, author: str = "") -> tuple[bool, str]:
    identifier = _identifier_value(target)
    if not identifier:
        return False, "no_identifier"
    combined = f"{title} {snippet} {url}".casefold()
    needle = identifier.casefold()
    if author and author.casefold().lstrip("@") == needle:
        return True, "exact_author_match"
    # Domain match is hostname-based; handle/name match must appear as an exact token.
    if target.get("kind") == "domain":
        host = (urlsplit(url).hostname or "").casefold()
        return (host == needle or host.endswith("." + needle) or needle in combined,
                "exact_domain_match" if needle in combined else "unmatched")
    if target.get("kind") == "shop_name":
        name_pattern = re.compile(r"(?<![A-Za-z0-9])" + re.escape(needle) + r"(?![A-Za-z0-9])", re.I)
        if name_pattern.search(combined):
            return True, "exact_name_mention"
    else:
        token = re.compile(r"(?<![A-Za-z0-9_.-])" + re.escape(needle) + r"(?![A-Za-z0-9_.-])", re.I)
        if token.search(combined):
            return True, "exact_identifier_mention"
    return False, "unmatched"


def _make_source(*, target: dict[str, Any], provider: str, platform: str, url: str,
                 title: str, snippet: str, published_date: str = "", author: str = "",
                 observed_profile: bool = False, scoped_account_post: bool = False) -> dict[str, Any] | None:
    safe_url = _normalise_url(url)
    if not safe_url:
        return None
    matched, match_type = _exact_identity_match(target, title, snippet, safe_url, author)
    if not matched and not observed_profile and not scoped_account_post:
        return None
    source_type = "social_profile_observation" if observed_profile else "social_intelligence_lead"
    if scoped_account_post:
        match_type = "exact_account_scoped_post"
    return {
        "source_type": source_type,
        "provider": provider,
        "platform": platform,
        "title": (title or "Public social-media result")[:220],
        "url": safe_url,
        "snippet": (snippet or "")[:800],
        "published_date": (published_date or "")[:80],
        "searched_identifier": _identifier_value(target),
        "relevance": ("exact_entity" if observed_profile else
                      "account_scoped_post" if scoped_account_post or match_type == "exact_author_match" else "entity_mention"),
        "relevance_reason": match_type,
        "identity_match": match_type,
        "author_username": author[:100],
        "verification_status": ("observed_public_profile" if observed_profile else
                                 "observed_public_page_post" if scoped_account_post else "unverified_public_mention"),
        "evidence_type": ("public_profile_observation" if observed_profile else
                          "page_owned_public_post" if scoped_account_post else "public_post_or_complaint_lead"),
        "source_url_present": True,
        "checked_at": _now(),
    }


def _profile_observation(target: dict[str, Any], payload: dict[str, Any], provider: str) -> dict[str, Any] | None:
    handle = _identifier_value(target)
    platform = _platform(target)
    if payload.get("success") is False or payload.get("error"):
        return None
    raw = payload.get("data") if isinstance(payload.get("data"), dict) else payload
    if not isinstance(raw, dict):
        raw = payload.get("profile") if isinstance(payload.get("profile"), dict) else payload.get("user") if isinstance(payload.get("user"), dict) else payload
    returned_handle = _first_text(raw, ("username", "handle", "unique_id", "screen_name"), 100).lstrip("@")
    if returned_handle and returned_handle.casefold() != handle.casefold():
        return None
    display = _first_text(raw, ("full_name", "name", "display_name", "username", "handle"), 160) or handle
    bio = _first_text(raw, ("biography", "bio", "description", "about"), 650)
    website = _first_text(raw, ("external_url", "website", "website_url", "link"), 250)
    pieces = []
    if bio:
        pieces.append(f"Public profile description: {bio}")
    if website:
        pieces.append(f"Public profile website link: {website}")
    if not pieces:
        pieces.append("The provider returned a public profile record; detailed profile fields were not available in the response.")
    profile_url = _safe_profile_url(platform, handle)
    if not profile_url:
        return None
    source = _make_source(target=target, provider=provider, platform=platform, url=profile_url,
                          title=f"{display} — {platform.title()} public profile", snippet=" ".join(pieces),
                          observed_profile=True)
    if source:
        # Preserve structured public profile fields. The shared investigation layer
        # extracts them into attributed location claims and profile-linked websites.
        source["bio"] = bio
        source["external_url"] = website
        for field in ("location", "address", "physical_address", "street_address", "business_address",
                      "store_address", "shop_address", "office_address", "city", "town", "county",
                      "region", "country", "delivery_area", "delivery_areas", "service_area", "service_areas"):
            if raw.get(field) is not None:
                source[field] = raw.get(field)
    return source


def _post_sources(target: dict[str, Any], payload: dict[str, Any], provider: str, platform: str,
                  *, scoped_account_posts: bool = False) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for row in _walk_records(payload)[:MAX_SOCIAL_RESULTS_PER_PROVIDER]:
        nested = row.get("aweme_info") if isinstance(row.get("aweme_info"), dict) else row.get("node") if isinstance(row.get("node"), dict) else row
        url = _first_text(row, ("url", "permalink", "share_url", "web_url", "post_url"), 1500)
        if not url and nested is not row:
            url = _first_text(nested, ("url", "permalink", "share_url", "web_url", "post_url"), 1500)
        if not url:
            url = _first_text(nested, ("url", "permalink", "share_url", "web_url", "post_url"), 1500)
        snippet = _first_text(row, ("text", "full_text", "caption", "description", "desc", "content", "title", "selftext"), 800)
        if not snippet and nested is not row:
            snippet = _first_text(nested, ("text", "full_text", "caption", "description", "content", "title", "selftext", "desc"), 800)
        title = _first_text(row, ("title", "name"), 200) or f"Public {platform} post"
        published = _first_text(row, ("created_at", "published_at", "timestamp", "date"), 80)
        author = _author(row) or (_author(nested) if nested is not row else "")
        if url:
            item = _make_source(target=target, provider=provider, platform=platform, url=url,
                                title=title, snippet=snippet, published_date=published, author=author,
                                scoped_account_post=scoped_account_posts)
            if item:
                results.append(item)
    return results


def _call_weir(target: dict[str, Any], api_key: str, platform: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    identifier = _identifier_value(target)
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    if platform == "x":
        # X query syntax supports quoted exact phrases and OR alternatives. Keep the
        # search anchored to the identifier and bounded to a small result count.
        body = {
            "query": f'"{identifier}" (scam OR fraud OR complaint OR blocked OR paid OR delivery OR refund OR tapeli OR hawakutuma OR hawakudeliver)',
            "limit": 12,
            "sort": "latest",
        }
        url = f"{WEIR_BASE}/x/search"
    else:
        body = {"query": f'"{identifier}" (scam OR fraud OR complaint OR delivery OR blocked)', "limit": 5, "sort": "new", "time": "year"}
        url = f"{WEIR_BASE}/reddit/search"
    status, payload, detail = _request_json("POST", url, headers=headers, json_body=body)
    if status != "checked" or payload is None:
        return [], {"provider": "Weir", "platform": platform, "status": status, "detail": detail, "results": 0}
    sources = _post_sources(target, payload, "Weir", platform)
    # Reddit search results are posts; X search results are public posts.
    return sources, {"provider": "Weir", "platform": platform,
                     "status": "checked" if sources else "checked_no_match",
                     "detail": f"Retrieved {len(sources)} exact-identifier public result(s); mentions remain unverified leads." if sources else "No exact-identifier public posts were returned by this search. This is not evidence of safety.",
                     "results": len(sources)}


def _call_scrape_creators(target: dict[str, Any], api_key: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    platform = _platform(target)
    handle = _identifier_value(target)
    profile_url = _safe_profile_url(platform, handle)
    if not profile_url:
        return [], {"provider": "Scrape Creators", "platform": platform, "status": "not_supported", "detail": "No direct public-profile endpoint is configured for this target platform.", "results": 0}

    headers = {"x-api-key": api_key, "Accept": "application/json"}
    if platform == "instagram":
        endpoint, params = f"{SCRAPE_CREATORS_BASE}/v1/instagram/profile", {"handle": handle}
    elif platform == "tiktok":
        endpoint, params = f"{SCRAPE_CREATORS_BASE}/v1/tiktok/profile", {"handle": handle}
    elif platform == "facebook":
        endpoint, params = f"{SCRAPE_CREATORS_BASE}/v1/facebook/profile", {"url": profile_url}
    else:
        return [], {"provider": "Scrape Creators", "platform": platform, "status": "not_supported", "detail": "No direct profile check is configured for this platform.", "results": 0}

    profile_status, payload, profile_detail = _request_json("GET", endpoint, headers=headers, params=params)
    profile = _profile_observation(target, payload, "Scrape Creators") if profile_status == "checked" and payload else None
    if profile_status == "checked" and payload and profile is None:
        profile_detail = "A response was received, but the returned profile could not be matched to the exact requested handle."
    sources = [profile] if profile else []

    # One bounded keyword/topic search per target helps find posts mentioning the exact
    # handle. Results are retained only when the exact identifier appears in the post,
    # URL, or author. This does not search private content or bypass platform controls.
    secondary_detail = ""
    secondary_status = "not_attempted"
    if platform == "instagram":
        search_status, search_payload, search_detail = _request_json(
            "GET", f"{SCRAPE_CREATORS_BASE}/v1/instagram/search/popular", headers=headers,
            params={"query": handle},
        )
        secondary_status = search_status
        if search_status == "checked" and search_payload:
            search_sources = _post_sources(target, search_payload, "Scrape Creators", "instagram")
            sources.extend(search_sources)
            secondary_detail = f"Instagram topic search returned {len(search_sources)} exact-handle post(s); unrelated results were excluded."
        else:
            secondary_detail = f"Instagram topic search: {search_detail}"
    elif platform == "tiktok":
        search_status, search_payload, search_detail = _request_json(
            "GET", f"{SCRAPE_CREATORS_BASE}/v1/tiktok/search/keyword", headers=headers,
            params={"query": handle, "date_posted": "all-time", "sort_by": "relevance", "trim": "true"},
        )
        secondary_status = search_status
        if search_status == "checked" and search_payload:
            search_sources = _post_sources(target, search_payload, "Scrape Creators", "tiktok")
            sources.extend(search_sources)
            secondary_detail = f"TikTok keyword search returned {len(search_sources)} exact-handle post(s); unrelated results were excluded."
        else:
            secondary_detail = f"TikTok keyword search: {search_detail}"

    # For Facebook, public Page posts are available when the Page URL is known.
    if platform == "facebook":
        posts_status, posts_payload, posts_detail = _request_json(
            "GET", f"{SCRAPE_CREATORS_BASE}/v1/facebook/profile/posts", headers=headers,
            params={"url": profile_url},
        )
        secondary_status = posts_status
        if posts_status == "checked" and posts_payload:
            sources.extend(_post_sources(target, posts_payload, "Scrape Creators", "facebook", scoped_account_posts=True))
            secondary_detail = "Public Page-post inspection completed for the exact Page URL."
        else:
            secondary_detail = f"Facebook Page-post inspection: {posts_detail}"

    base_detail = ("Retrieved a public profile observation. Profile claims are self-published and are not independently verified."
                   if profile else f"Profile inspection: {profile_detail}")
    if secondary_detail:
        base_detail = f"{base_detail} {secondary_detail}".strip()
    failed = profile_status == "failed" or secondary_status == "failed"
    result_status = "checked" if sources else "failed" if failed else "checked_no_match"
    return sources, {"provider": "Scrape Creators", "platform": platform,
                     "status": result_status,
                     "detail": base_detail,
                     "results": len(sources)}


def _complaint_flags(sources: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Summarise repeated public allegations without turning them into verified facts."""
    flags: list[dict[str, Any]] = []
    for code, pattern in _COMPLAINT_PATTERNS.items():
        matches = [s for s in sources if s.get("source_type") == "social_intelligence_lead"
                   and s.get("evidence_type") == "public_post_or_complaint_lead"
                   and (not s.get("author_username") or str(s.get("author_username")).casefold().lstrip("@")
                        != str(s.get("searched_identifier") or "").casefold().lstrip("@"))
                   and pattern.search(str(s.get("snippet") or ""))]
        urls = {str(s.get("url")) for s in matches if s.get("url")}
        authors = {str(s.get("author_username") or "").casefold() for s in matches if s.get("author_username")}
        if not matches:
            continue
        independent = len(urls) >= 2 and len(authors) >= 2
        label = "Repeated public non-delivery allegations" if code == "non_delivery" else "Repeated public payment-dispute allegations"
        flags.append({
            "source_type": "social_flag_summary",
            "code": f"REPORTED_{code.upper()}_PATTERN",
            "label": label,
            "status": "reported_pattern",
            "strength": "supporting" if independent else "weak",
            "distinct_posts": len(urls),
            "distinct_authors_identified": len(authors),
            "independent_corroboration_threshold_met": independent,
            "evidence_urls": sorted(urls)[:8],
            "explanation": (
                "Multiple distinct public posts by different identified authors describe a similar experience. "
                "These remain allegations; Toroka has not independently verified the underlying transactions."
                if independent else
                "A public post contains language consistent with this complaint pattern. A single or non-independent allegation is not proof."
            ),
        })
    return flags


def _social_cache_key(targets: list[dict[str, Any]], weir_key: str, scrape_key: str) -> str:
    """Cache by public targets and credential fingerprints, never by storing API keys."""
    target_rows = [
        {"kind": str(t.get("kind") or ""), "identifier": _identifier_value(t).casefold(), "platform": _platform(t)}
        for t in (targets or [])[:3] if isinstance(t, dict)
    ]
    credential_fingerprints = {
        "weir": hashlib.sha256(weir_key.encode("utf-8")).hexdigest()[:16] if weir_key else "absent",
        "scrape_creators": hashlib.sha256(scrape_key.encode("utf-8")).hexdigest()[:16] if scrape_key else "absent",
    }
    encoded = json.dumps({"targets": target_rows, "providers": credential_fingerprints}, sort_keys=True)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def investigate_social_targets(targets: list[dict[str, Any]], settings: Any) -> dict[str, Any]:
    """Run bounded, optional social lookups for public identifiers only.

    The function is safe when no keys are configured: it returns not-configured
    statuses and never treats missing providers as clean results.
    """
    sources: list[dict[str, Any]] = []
    statuses: list[dict[str, Any]] = []
    jobs: list[tuple[str, dict[str, Any], Any]] = []
    weir_key = str(getattr(settings, "weir_api_key", "") or "").strip()
    scrape_key = str(getattr(settings, "scrape_creators_api_key", "") or "").strip()
    cache_key = _social_cache_key(targets or [], weir_key, scrape_key)
    now_monotonic = time.monotonic()
    with _SOCIAL_CACHE_LOCK:
        cached = _SOCIAL_CACHE.get(cache_key)
        if cached and now_monotonic - cached[0] < SOCIAL_CACHE_TTL_SECONDS:
            result = copy.deepcopy(cached[1])
            result["cache"] = {"hit": True, "ttl_seconds": SOCIAL_CACHE_TTL_SECONDS}
            return result
        if cached:
            _SOCIAL_CACHE.pop(cache_key, None)

    for target in (targets or [])[:3]:
        if not isinstance(target, dict):
            continue
        kind = str(target.get("kind") or "")
        platform = _platform(target)
        identifier = _identifier_value(target)
        if not identifier or kind not in {"handle", "shop_name", "domain"}:
            continue
        if weir_key:
            jobs.append(("weir_x", target, lambda t=target: _call_weir(t, weir_key, "x")))
            jobs.append(("weir_reddit", target, lambda t=target: _call_weir(t, weir_key, "reddit")))
        else:
            statuses.append({"provider": "Weir", "platform": "x/reddit", "status": "not_configured",
                             "detail": "WEIR_API_KEY is not configured; X and Reddit were not checked.", "results": 0})
        if scrape_key and kind == "handle" and platform in {"instagram", "tiktok", "facebook"}:
            jobs.append(("scrape_creators", target, lambda t=target: _call_scrape_creators(t, scrape_key)))
        elif kind == "handle" and platform in {"instagram", "tiktok", "facebook"}:
            statuses.append({"provider": "Scrape Creators", "platform": platform, "status": "not_configured",
                             "detail": "SCRAPE_CREATORS_API_KEY is not configured; direct social profile inspection was not performed.", "results": 0})

    # Limit concurrency and wait only for provider timeouts. No provider can stall the
    # main conversation indefinitely, and individual failures do not cancel other checks.
    with ThreadPoolExecutor(max_workers=4, thread_name_prefix="toroka-social") as pool:
        future_map = {pool.submit(fn): (name, target) for name, target, fn in jobs}
        for future in as_completed(future_map):
            name, target = future_map[future]
            try:
                new_sources, status = future.result()
            except Exception as exc:  # Defensive boundary around each provider adapter.
                logger.warning("Social provider adapter failed: %s", type(exc).__name__)
                new_sources, status = [], {"provider": name, "status": "failed", "detail": "Provider adapter failed safely.", "results": 0}
            sources.extend(new_sources)
            statuses.append({**status, "searched_identifier": _identifier_value(target)})

    # Deduplicate same post returned by multiple APIs before counting allegations.
    deduped: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in sources:
        url = str(item.get("url") or "")
        key = url.casefold() or hashlib.sha256(str(item).encode("utf-8")).hexdigest()
        if key not in seen:
            seen.add(key)
            deduped.append(item)
        if len(deduped) >= MAX_EVIDENCE_RECORDS:
            break

    flags = _complaint_flags(deduped)
    result = {
        "sources": deduped,
        "statuses": statuses,
        "red_flags": flags,
        "checked_at": _now(),
        "cache": {"hit": False, "ttl_seconds": SOCIAL_CACHE_TTL_SECONDS},
        "summary": {
            "targets_checked": min(len(targets or []), 3),
            "sources_retrieved": len(deduped),
            "providers_configured": len({s.get("provider") for s in statuses if s.get("status") not in {"not_configured", "not_supported"}}),
            "providers_unavailable": len([s for s in statuses if s.get("status") in {"failed", "not_configured"}]),
            "red_flag_patterns": len(flags),
        },
    }
    with _SOCIAL_CACHE_LOCK:
        if len(_SOCIAL_CACHE) >= _SOCIAL_CACHE_MAX_ENTRIES:
            # Remove expired entries first; then evict the oldest insertion if still full.
            expired = [key for key, (created, _) in _SOCIAL_CACHE.items()
                       if time.monotonic() - created >= SOCIAL_CACHE_TTL_SECONDS]
            for key in expired:
                _SOCIAL_CACHE.pop(key, None)
            if len(_SOCIAL_CACHE) >= _SOCIAL_CACHE_MAX_ENTRIES:
                oldest_key = min(_SOCIAL_CACHE, key=lambda key: _SOCIAL_CACHE[key][0])
                _SOCIAL_CACHE.pop(oldest_key, None)
        _SOCIAL_CACHE[cache_key] = (time.monotonic(), copy.deepcopy(result))
    return result
