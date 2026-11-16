"""Multi-provider, evidence-led public investigation for Toroka.

This module coordinates optional public-data providers. It never sends the raw user
message, screenshots, phone numbers, payment IDs, passwords, PINs or OTPs to providers.
Provider output is treated as unverified public evidence until independently assessed.
The module is deliberately stateless across users; only a short in-process cache is used.
"""
from __future__ import annotations

import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
import re
import threading
import time
from datetime import datetime, timezone
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx

from .public_search import public_search, filter_public_search_results, manual_search_url
from .evidence_graph import build_evidence_graph
from ssi_connectors.places import search_places
from ssi_connectors.urlscan import normalize_domain, search_historical_domain
from ssi_connectors.domain_intelligence import investigate_domain_infrastructure

logger = logging.getLogger("toroka.investigation_intelligence")

_TIMEOUT = httpx.Timeout(8.0, connect=3.0)
_MAX_EVIDENCE = 30
_MAX_TEXT = 1800
_MAX_QUERY = 240
_CACHE: dict[str, tuple[float, dict[str, Any]]] = {}
_CACHE_LOCK = threading.Lock()


# ----------------------------- safe primitives -----------------------------

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _clean_text(value: Any, limit: int = _MAX_TEXT) -> str:
    value = re.sub(r"\s+", " ", str(value or "")).strip()
    return value[:limit]


def _safe_http_url(value: Any) -> str | None:
    try:
        p = urlsplit(str(value or "").strip())
        if p.scheme not in {"http", "https"} or not p.hostname:
            return None
        if p.username or p.password:
            return None
        # Strip fragments and common tracking / session parameters. Preserve functional
        # query parameters that identify content, but never persist obvious tokens.
        tracking = {
            "fbclid", "gclid", "dclid", "msclkid", "igshid", "igsh", "xtok",
            "ref", "ref_src", "source", "mc_cid", "mc_eid", "_ga", "_gl",
            "session", "sessionid", "access_token", "auth_token", "token", "api_key",
        }
        kept = []
        for key, item in parse_qsl(p.query[:1200], keep_blank_values=False):
            key_norm = key.casefold()
            if key_norm in tracking or key_norm.startswith("utm_"):
                continue
            if re.search(r"(?i)(?:token|secret|password|session|auth|credential)", key_norm):
                continue
            kept.append((key[:80], item[:180]))
        query = urlencode(kept, doseq=True)[:300]
        return urlunsplit((p.scheme.lower(), p.netloc.lower(), p.path[:800], query, ""))[:1400]
    except Exception:
        return None


def _target_key(target: dict[str, Any]) -> str:
    return f"{target.get('kind')}:{str(target.get('platform') or '').lower()}:{str(target.get('identifier') or '').lower()}"


def _cache_get(key: str, ttl: int) -> dict[str, Any] | None:
    if ttl <= 0:
        return None
    with _CACHE_LOCK:
        item = _CACHE.get(key)
        if not item:
            return None
        expires, value = item
        if expires <= time.monotonic():
            _CACHE.pop(key, None)
            return None
        # Provider outputs are JSON-shaped; shallow copy all mutable collections.
        return {**value, "evidence": [dict(x) for x in value.get("evidence", [])],
                "providers": [dict(x) for x in value.get("providers", [])],
                "map_candidates": [dict(x) for x in value.get("map_candidates", [])],
                "domain_infrastructure": [dict(x) for x in value.get("domain_infrastructure", [])]}


def _cache_set(key: str, value: dict[str, Any], ttl: int) -> None:
    if ttl <= 0:
        return
    with _CACHE_LOCK:
        _CACHE[key] = (time.monotonic() + ttl, value)
        # Keep memory bounded in long-lived workers.
        if len(_CACHE) > 500:
            oldest = sorted(_CACHE, key=lambda k: _CACHE[k][0])[:100]
            for old in oldest:
                _CACHE.pop(old, None)


def _query_terms(target: dict[str, Any], category: str) -> list[str]:
    """Build narrowly scoped queries from public identifiers only."""
    ident = _clean_text(target.get("identifier"), 90).strip()
    if not ident:
        return []
    quoted = f'"{ident}"'
    if category == "job":
        terms = ["recruitment job offer complaints scam", "Gmail password application fee overseas job"]
    elif category == "grant":
        terms = ["grant application deposit fee impersonation scam", "official programme warning Kenya"]
    elif category == "payment":
        terms = ["payment fraud complaints impersonation warning", "M-PESA transaction scam reports"]
    elif category == "shop":
        # Search for the seller's public trading footprint as well as complaints.
        # The result is still only a lead until the destination page is inspected.
        terms = ["physical shop address store location contact delivery area Kenya", "online shop seller complaints non delivery scam"]
    else:
        terms = ["scam fraud complaint warning", "phishing malicious reports"]
    platform = _clean_text(target.get("platform"), 20)
    prefix = f"{quoted} {platform}" if platform and platform != "not specified" else quoted
    return [f"{prefix} {term}"[:_MAX_QUERY] for term in terms[:2]]


def _matches_target(item: dict[str, Any], target: dict[str, Any]) -> tuple[bool, str]:
    """Conservative identity matching. Shop-name matches remain possible, not exact."""
    ident = _clean_text(target.get("identifier"), 120).lstrip("@").casefold()
    kind = str(target.get("kind") or "")
    platform = str(target.get("platform") or "").casefold()
    url = _safe_http_url(item.get("url")) or ""
    title = _clean_text(item.get("title"), 240).casefold()
    text = _clean_text(item.get("text") or item.get("snippet"), 700).casefold()
    host = (urlsplit(url).hostname or "").casefold()
    if not ident:
        return False, "missing_target_identifier"
    if kind == "domain":
        domain = ident.removeprefix("www.")
        if host == domain or host.endswith("." + domain):
            return True, "exact_domain_url_match"
        if re.search(rf"(?<![a-z0-9.-]){re.escape(domain)}(?![a-z0-9.-])", f"{title} {text}"):
            return True, "exact_domain_text_match"
        return False, "no_exact_domain_match"
    if kind == "handle":
        hosts = {
            "instagram": {"instagram.com", "www.instagram.com"},
            "tiktok": {"tiktok.com", "www.tiktok.com", "m.tiktok.com"},
            "facebook": {"facebook.com", "www.facebook.com", "m.facebook.com"},
            "x": {"x.com", "www.x.com", "twitter.com", "www.twitter.com"},
            "twitter": {"x.com", "www.x.com", "twitter.com", "www.twitter.com"},
        }.get(platform, set())
        first_path = next((x for x in urlsplit(url).path.split("/") if x), "").lstrip("@").casefold()
        if host in hosts and first_path == ident:
            return True, "exact_social_profile_match"
        # Word-boundary exact handle mention; still only a mention, not profile identity.
        if re.search(rf"(?<![a-z0-9_])@?{re.escape(ident)}(?![a-z0-9_])", f"{title} {text}"):
            return True, "exact_handle_mention"
        return False, "no_exact_handle_match"
    if kind == "shop_name":
        if re.search(rf"(?<![a-z0-9]){re.escape(ident)}(?![a-z0-9])", f"{title} {text}"):
            return True, "possible_business_name_match"
        return False, "no_name_match"
    return False, "unsupported_target_kind"



_LOCATION_FIELD_GROUPS = {
    "physical_address": ("address", "physical_address", "street_address", "business_address", "store_address", "shop_address", "office_address", "contact_address", "visit_address"),
    "profile_location": ("location", "location_name", "city", "town", "county", "region", "country", "business_location"),
    "delivery_area": ("delivery_area", "delivery_areas", "service_area", "service_areas", "shipping_area", "shipping_areas", "delivery_locations"),
}


def _location_string(value: Any) -> str:
    """Extract a short, human-readable location from common provider shapes."""
    if isinstance(value, str):
        return _clean_text(value, 180)
    if isinstance(value, dict):
        parts = []
        for key in ("address", "street", "name", "city", "town", "county", "region", "country", "formatted_address"):
            candidate = value.get(key)
            if isinstance(candidate, str) and candidate.strip() and candidate not in parts:
                parts.append(candidate.strip())
        return _clean_text(", ".join(parts), 180)
    if isinstance(value, list):
        parts = [_location_string(x) for x in value]
        return _clean_text(", ".join(x for x in parts if x), 180)
    return ""


def _extract_location_claims(raw: dict[str, Any], text: str) -> list[dict[str, str]]:
    """Extract explicit location claims; never geocode or infer a missing address."""
    claims: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def add(kind: str, value: Any, field: str, excerpt: str = "") -> None:
        clean = _location_string(value).strip(" ,.;|:-")
        if len(clean) < 3 or len(clean) > 180:
            return
        # Reject values that are plainly URLs, contact details, coordinates or generic marketing.
        if re.match(r"(?i)^(?:https?://|www\.|@|\+?\d[\d\s().-]{6,})", clean):
            return
        if re.fullmatch(r"(?i)(?:worldwide|countrywide|nationwide|online|everywhere|global)", clean):
            if kind != "delivery_area":
                return
        key = (kind, re.sub(r"\W+", " ", clean.casefold()).strip())
        if key in seen:
            return
        seen.add(key)
        claims.append({"kind": kind, "value": clean, "field": field, "excerpt": _clean_text(excerpt or f"{field}: {clean}", 220)})

    for kind, names in _LOCATION_FIELD_GROUPS.items():
        for field in names:
            value = raw.get(field)
            if value is not None:
                add(kind, value, field)

    # Some providers return a nested contact/business object.
    for parent_name in ("contact", "business", "profile", "shop", "location_data"):
        parent = raw.get(parent_name)
        if isinstance(parent, dict):
            for kind, names in _LOCATION_FIELD_GROUPS.items():
                for field in names:
                    if parent.get(field) is not None:
                        add(kind, parent.get(field), f"{parent_name}.{field}")

    value = _clean_text(text, _MAX_TEXT)
    text_patterns = [
        ("physical_address", "explicit_address", re.compile(r"(?i)\b(?:physical\s+address|shop\s+address|store\s+address|business\s+address|office\s+address|address|visit\s+us\s+at|find\s+us\s+at)\s*[:\-]?\s*([^\n|;]{5,130})")),
        ("physical_address", "visit_location", re.compile(r"(?i)\b(?:our\s+shop|our\s+store|physical\s+shop|physical\s+store)\s+(?:is\s+)?(?:located\s+)?(?:at|in)\s+([^\n|;]{4,110})")),
        ("profile_location", "business_base", re.compile(r"(?i)\b(?:based|located|operating)\s+(?:in|at)\s+([^\n|;]{3,90})")),
        ("delivery_area", "delivery_area_text", re.compile(r"(?i)\b(?:deliver(?:y|ing|ies)?|we\s+serve|serving)\s+(?:to|in|across|within)\s+([^\n|;]{3,100})")),
    ]
    for kind, field, pattern in text_patterns:
        for match in pattern.finditer(value):
            candidate = re.split(r"(?i)(?:[.!?]\s+|\s+(?:for\s+orders?|call|whatsapp|contact|open\s+daily|delivery|we\s+deliver)\b)", match.group(1))[0]
            candidate = candidate.strip(" ,.;:-")
            add(kind, candidate, field, match.group(0))
            if len(claims) >= 8:
                return claims
    return claims[:8]


def _is_target_controlled_source(item: dict[str, Any]) -> bool:
    source_type = str(item.get("source_type") or "")
    identity_match = str(item.get("identity_match") or "")
    if source_type in {"social_profile_observation", "social_public_profile_observation", "social_public_profile_post"}:
        return True
    return source_type == "inspected_public_web_page" and identity_match == "exact_domain_url_match"



def _extract_outbound_links(raw: dict[str, Any]) -> list[str]:
    """Collect public website links explicitly attached to a profile record."""
    values: list[Any] = []
    for key in ("external_url", "website", "website_url", "link_in_bio", "contact_website", "external_links", "bio_links", "links"):
        if raw.get(key) is not None:
            values.append(raw.get(key))
    links: list[str] = []

    def walk(value: Any) -> None:
        if isinstance(value, str):
            # Support a plain single URL only; do not mine arbitrary text for links here.
            safe = _safe_http_url(value)
            if safe and safe not in links:
                links.append(safe)
        elif isinstance(value, dict):
            for key in ("url", "href", "link", "external_url", "website"):
                if value.get(key):
                    walk(value.get(key))
        elif isinstance(value, list):
            for item in value[:10]:
                walk(item)

    for value in values:
        walk(value)
        if len(links) >= 8:
            break
    return links[:8]

def _shop_places_query(target: dict[str, Any], evidence: list[dict[str, Any]]) -> str:
    """Build a minimal Google Places query from a public seller identifier and own claims."""
    identifier = _clean_text(target.get("identifier"), 100).lstrip("@")
    if not identifier:
        return ""
    name = re.sub(r"[_-]+", " ", identifier).strip()
    own_locations: list[str] = []
    for item in evidence:
        if not isinstance(item, dict) or not _is_target_controlled_source(item):
            continue
        for claim in item.get("location_claims") or []:
            if not isinstance(claim, dict) or claim.get("kind") == "delivery_area":
                continue
            value = _clean_text(claim.get("value"), 100)
            if value and value.casefold() not in {x.casefold() for x in own_locations}:
                own_locations.append(value)
    # Limit location context to one seller-published location claim. Third-party claims
    # are not used as search context because that could reinforce a false association.
    location = own_locations[0] if own_locations else "Kenya"
    return _clean_text(f"{name} {location} Kenya", 180)


def _places_candidate_records(target: dict[str, Any], places_result: dict[str, Any]) -> list[dict[str, Any]]:
    """Keep only plausible name candidates; a candidate is never an identity verification."""
    ident = re.sub(r"[^a-z0-9]+", " ", _clean_text(target.get("identifier"), 100).lstrip("@").casefold()).strip()
    target_tokens = set(ident.split())
    candidates = []
    for place in (places_result.get("places") or [])[:5]:
        if not isinstance(place, dict):
            continue
        name = _clean_text(place.get("name"), 180)
        place_tokens = set(re.sub(r"[^a-z0-9]+", " ", name.casefold()).split())
        overlap = len(target_tokens & place_tokens) / max(1, len(target_tokens | place_tokens))
        # Handle tokens like "shop" or "official" should not be mistaken for a name match.
        if not target_tokens or not place_tokens or overlap < 0.30:
            continue
        candidates.append({
            **place,
            "name_overlap": round(overlap, 2),
            "identity_status": "possible_name_match_not_identity_verified",
            "target_identifier": _clean_text(target.get("identifier"), 120),
            "match_basis": "Google Places returned a listing with overlapping name terms for the public seller identifier.",
        })
    return candidates[:5]


def build_shop_discovery(evidence: list[dict[str, Any]], targets: list[dict[str, Any]] | None = None, map_candidates: list[dict[str, Any]] | None = None, map_search_status: str | None = None) -> dict[str, Any]:
    """Build source-attributed shop location and online-presence facts for UI display."""
    locations: list[dict[str, Any]] = []
    seen_locations: set[tuple[str, str]] = set()
    storefronts: list[dict[str, Any]] = []
    seen_storefronts: set[str] = set()
    for item in evidence or []:
        if not isinstance(item, dict):
            continue
        url = _safe_http_url(item.get("url"))
        controlled = _is_target_controlled_source(item)
        origin = "self_published" if controlled else "third_party_source"
        origin_label = "Published by the seller's own profile or website" if controlled else "Mentioned by a third-party source"
        for claim in (item.get("location_claims") or []):
            if not isinstance(claim, dict):
                continue
            kind = str(claim.get("kind") or "profile_location")
            value = _clean_text(claim.get("value"), 180)
            key = (kind, value.casefold())
            if not value or key in seen_locations:
                continue
            seen_locations.add(key)
            locations.append({
                "kind": kind,
                "value": value,
                "claim_origin": origin,
                "claim_label": origin_label,
                "verification_status": "self_declared_not_independently_verified" if controlled else "third_party_claim_not_independently_verified",
                "source_evidence_id": item.get("evidence_id"),
                "source_title": _clean_text(item.get("title") or item.get("provider") or "Public source", 180),
                "source_url": url,
                "maps_search_url": ("https://www.google.com/maps/search/?" + urlencode({"api": "1", "query": value}) if kind in {"physical_address", "profile_location"} else None),
                "source_type": item.get("source_type"),
                "published_at": _clean_text(item.get("published_at"), 80),
                "excerpt": _clean_text(claim.get("excerpt") or f"{claim.get('field')}: {value}", 220),
            })

        source_type = str(item.get("source_type") or "")
        if url and controlled and source_type in {"social_profile_observation", "social_public_profile_observation", "inspected_public_web_page"}:
            if url not in seen_storefronts:
                seen_storefronts.add(url)
                storefronts.append({
                    "platform": _clean_text(item.get("platform") or item.get("provider") or "Website", 60),
                    "title": _clean_text(item.get("title") or item.get("target_identifier") or "Seller storefront", 160),
                    "url": url,
                    "status": "public_profile_or_site_observed",
                    "source_evidence_id": item.get("evidence_id"),
                })
        if controlled:
            for link in (item.get("outbound_links") or [])[:8]:
                safe_link = _safe_http_url(link)
                if safe_link and safe_link not in seen_storefronts:
                    seen_storefronts.add(safe_link)
                    storefronts.append({
                        "platform": "Website linked from seller profile",
                        "title": "Website linked from seller's public profile",
                        "url": safe_link,
                        "status": "linked_from_seller_profile_not_independently_verified",
                        "source_evidence_id": item.get("evidence_id"),
                    })

    if locations:
        if any(x["claim_origin"] == "self_published" for x in locations):
            location_status = "self_published_location_found"
        else:
            location_status = "third_party_location_claims_found"
    else:
        location_status = "no_location_found"
    return {
        "status": location_status,
        "locations": locations[:12],
        "online_storefronts": storefronts[:10],
        "map_search_status": map_search_status or "not_checked",
        "map_candidates": (map_candidates or [])[:5],
        "map_note": "Map results are candidate directory listings. A name or address match does not prove that the submitted social account controls the listed business. Confirm ownership directly before treating it as the same seller.",
        "location_note": "These are source-attributed location claims, not independent proof that the seller operates from that address. Toroka does not infer a physical shop from a social-media bio or delivery area.",
    }


def build_verdict_explanation(
    label: str,
    summary: str,
    flags: list[dict[str, Any]],
    evidence: list[dict[str, Any]],
    limitations: list[str] | None = None,
    assessment_sources: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Create an inspectable explanation that links every public claim to source records."""
    by_id = {str(x.get("evidence_id")): x for x in evidence if isinstance(x, dict) and x.get("evidence_id")}
    by_url = {str(x.get("url")): x for x in evidence if isinstance(x, dict) and x.get("url")}
    reasons = []
    for flag in flags or []:
        if not isinstance(flag, dict):
            continue
        refs = []
        for source_ref in (flag.get("source_ids") or []):
            ref = str(source_ref or "")
            item = by_id.get(ref) or by_url.get(ref)
            if item and item not in refs:
                refs.append(item)
        evidence_status = str(flag.get("evidence_status") or "")
        if evidence_status == "directly_observed_in_submission":
            basis = "observed_in_submitted_content"
        elif refs:
            basis = "linked_public_sources"
        elif evidence_status:
            basis = evidence_status
        else:
            basis = "assessment_finding"
        reasons.append({
            "code": str(flag.get("code") or "ASSESSMENT_REASON"),
            "statement": _clean_text(flag.get("statement") or "Assessment factor", 360),
            "why_it_matters": _clean_text(flag.get("why_it_matters") or "", 520),
            "strength": str(flag.get("severity") or "supporting"),
            "basis": basis,
            "observed_excerpt": _clean_text(flag.get("observed_excerpt") or "", 240),
            "evidence": [{
                "evidence_id": x.get("evidence_id"),
                "title": _clean_text(x.get("title") or x.get("provider") or "Public source", 180),
                "snippet": _clean_text(x.get("snippet") or "", 500),
                "url": _safe_http_url(x.get("url")),
                "provider": _clean_text(x.get("provider") or "Public source", 80),
                "source_type": x.get("source_type"),
                "claim_status": x.get("claim_status"),
                "identity_match": x.get("identity_match"),
                "published_at": x.get("published_at"),
            } for x in refs[:5]],
        })

    positive_sources = []
    for source in assessment_sources or []:
        if not isinstance(source, dict):
            continue
        reviewer = str(source.get("reviewer") or "")
        statement = str(source.get("statement") or "")
        if "toroka-verified-" in str(source.get("id") or "") or "official verified record" in statement.casefold() or "verified official" in reviewer.casefold():
            positive_sources.append({
                "title": _clean_text(statement, 260),
                "url": _safe_http_url(source.get("source_url")),
                "verified_at": source.get("last_verified_at"),
                "reviewer": _clean_text(reviewer, 100),
                "basis": "current_toroka_verified_registry_match",
            })

    direct_count = sum(1 for x in reasons if x["basis"] == "observed_in_submitted_content")
    linked_count = sum(len(x["evidence"]) for x in reasons)
    if positive_sources:
        strength = "registry_match_and_assessment_evidence"
    elif direct_count and linked_count:
        strength = "direct_submission_and_public_sources"
    elif direct_count:
        strength = "direct_submission_evidence"
    elif linked_count:
        strength = "public_sources_require_context"
    else:
        strength = "limited_evidence"

    return {
        "verdict": label,
        "summary": _clean_text(summary or "", 500),
        "basis_strength": strength,
        "reasons": reasons[:12],
        "positive_identity_matches": positive_sources[:5],
        "limitations": [_clean_text(x, 300) for x in (limitations or []) if x][:10],
        "interpretation_note": "A public search result is not proof by itself. An allegation stays an allegation unless independently corroborated; no result found is not proof of safety.",
    }

def _normalise_record(
    provider: str,
    raw: dict[str, Any],
    target: dict[str, Any],
    *,
    source_type: str,
    parent_url: str | None = None,
    identity_context: str | None = None,
    identity_parent_url: str | None = None,
) -> dict[str, Any] | None:
    """Normalise one source item without upgrading a report to verified fact.

    ``parent_url`` is used only for content fetched from an exact target profile's
    own posts/comments endpoint. It is never used for generic keyword-search results.
    """
    def nested_text(value: Any) -> str:
        if isinstance(value, str):
            return value
        if isinstance(value, dict):
            for key in ("text", "caption", "description", "content", "full_text"):
                found = value.get(key)
                if isinstance(found, str) and found.strip():
                    return found
        if isinstance(value, list):
            return " ".join(nested_text(x) for x in value if x)
        return ""

    url_value = raw.get("url") or raw.get("link") or raw.get("permalink") or raw.get("share_url")
    if not url_value and provider == "Instagram":
        shortcode = raw.get("code") or raw.get("shortcode")
        if shortcode:
            url_value = f"https://www.instagram.com/p/{shortcode}/"
    if not url_value and provider == "TikTok":
        video_id = raw.get("aweme_id") or raw.get("video_id") or raw.get("id")
        author_obj = raw.get("author") if isinstance(raw.get("author"), dict) else {}
        author_handle = author_obj.get("unique_id") or author_obj.get("username") or raw.get("username")
        if video_id and author_handle:
            url_value = f"https://www.tiktok.com/@{author_handle}/video/{video_id}"
    url = _safe_http_url(url_value)

    caption = raw.get("caption")
    if isinstance(caption, dict):
        caption_text = nested_text(caption)
    else:
        caption_text = str(caption or "")
    edge_caption = raw.get("edge_media_to_caption")
    if not caption_text and isinstance(edge_caption, dict):
        edges = edge_caption.get("edges") or []
        if edges and isinstance(edges[0], dict):
            caption_text = nested_text(edges[0].get("node") or {})
    text = _clean_text(
        raw.get("text") or raw.get("raw_content") or raw.get("content") or raw.get("snippet") or raw.get("description")
        or raw.get("bio") or raw.get("biography") or raw.get("location") or raw.get("desc") or raw.get("desc_text") or caption_text or raw.get("share_info", {}).get("title", "")
        if isinstance(raw.get("share_info"), dict) else
        (raw.get("text") or raw.get("raw_content") or raw.get("content") or raw.get("snippet") or raw.get("description") or raw.get("bio") or raw.get("biography") or raw.get("location") or raw.get("desc") or raw.get("desc_text") or caption_text),
        _MAX_TEXT,
    )
    title = _clean_text(raw.get("title") or raw.get("name") or raw.get("full_name") or raw.get("fullName")
                        or raw.get("author_name") or provider, 220)
    candidate = {"url": url, "title": title, "text": text}
    matched, match_type = _matches_target(candidate, target)
    if matched and source_type == "social_public_profile_post" and match_type == "exact_social_profile_match":
        match_type = "exact_social_profile_post_match"
    if not matched and (identity_parent_url or parent_url):
        parent_safe = _safe_http_url(identity_parent_url or parent_url)
        parent_matches, _ = _matches_target({"url": parent_safe, "title": "", "text": ""}, target)
        if parent_matches:
            matched = True
            if source_type == "social_public_comment_on_profile_post":
                match_type = f"comment_on_exact_{str(target.get('platform') or 'social')}_profile_post"
            else:
                match_type = f"content_from_exact_{str(target.get('platform') or 'social')}_profile"
    if not matched:
        return None

    user_obj = raw.get("user") if isinstance(raw.get("user"), dict) else {}
    author_obj = raw.get("author") if isinstance(raw.get("author"), dict) else {}
    author = _clean_text(
        raw.get("author") if isinstance(raw.get("author"), str) else
        raw.get("username") or raw.get("userName") or user_obj.get("username") or user_obj.get("unique_id")
        or user_obj.get("name") or author_obj.get("username") or author_obj.get("unique_id") or author_obj.get("name"), 100
    )
    external_id = _clean_text(raw.get("id") or raw.get("postId") or raw.get("tweetId") or raw.get("shortcode")
                              or raw.get("aweme_id") or raw.get("cid") or raw.get("pk"), 100)
    published = _clean_text(raw.get("published_at") or raw.get("createdAt") or raw.get("created_at")
                            or raw.get("create_time_utc") or raw.get("taken_at") or raw.get("create_time")
                            or raw.get("date") or raw.get("timestamp"), 80)
    allegation_pattern = re.compile(
        r"(?i)(?:\bscam(?:mer)?s?\b|\bfraud(?:ulent)?\b|\bstole\b|\bstolen\b|"
        r"\bcomplaint\b|\bwarning\b|\bfake seller\b|\bpaid.{0,35}(?:no|never).{0,24}(?:deliver\w*|arriv\w*)|"
        r"\b(?:never|not)\s+(?:received|delivered)\b|\btook my money\b|"
        r"\bno response after (?:payment|paying)\b|\bblocked after (?:payment|paying)\b|\bblocked me after (?:payment|paying|I paid|i paid)\b|"
        r"\b(?:did not|didn't|never)\s+receive\b|\bno delivery\b|\bnever came\b|"
        r"\brefund(?:ed)?\b.{0,35}\b(?:ignored|refused|never)\b|"
        r"\b(?:tapeli|matapeli|nimeibiwa|hawakudeliver|hakufika)\b)"
    )
    allegation = bool(allegation_pattern.search(f"{title} {text}"))
    return {
        "evidence_id": hashlib.sha256(f"{provider}|{url or external_id}|{text}".encode()).hexdigest()[:16],
        "provider": provider,
        "platform": provider if provider in {"Weir X", "Weir Reddit", "Instagram", "TikTok", "Facebook"} else "web",
        "source_type": source_type,
        "content_status": "page_content_retrieved" if source_type == "inspected_public_web_page" else "public_result_retrieved",
        "evidence_type": "public_complaint_or_mention" if allegation else "public_mention",
        "claim_status": "reported_allegation" if allegation else "unverified_public_mention",
        "identity_match": match_type,
        "identity_context": _clean_text(identity_context, 100) if identity_context else None,
        "target_identifier": _clean_text(target.get("identifier"), 120),
        "title": title,
        "snippet": text,
        "location_claims": _extract_location_claims(raw, text),
        "outbound_links": _extract_outbound_links(raw),
        "url": url or _safe_http_url(parent_url),
        "author": author,
        "external_id": external_id,
        "published_at": published,
        "collected_at": _now(),
        "independence_key": (author.casefold() if author else "") + "|" + (url or external_id or hashlib.sha256(text.casefold().encode()).hexdigest()[:16]),
        "verified": False,
    }


def _extract_items(data: Any) -> list[dict[str, Any]]:
    """Handle common wrappers from Weir and social scrapers without losing posts."""
    if isinstance(data, list):
        out: list[dict[str, Any]] = []
        for item in data:
            if not isinstance(item, dict):
                continue
            if isinstance(item.get("node"), dict):
                out.append(item["node"])
            elif isinstance(item.get("aweme_info"), dict):
                out.append(item["aweme_info"])
            elif isinstance(item.get("item"), dict):
                out.append(item["item"])
            else:
                out.append(item)
        return out
    if not isinstance(data, dict):
        return []

    for key in ("data", "results", "tweets", "posts", "items", "videos", "profiles", "users", "aweme_list", "search_item_list",
                "comments", "profile_grid_items", "edges"):
        val = data.get(key)
        if isinstance(val, list):
            return _extract_items(val)
        if isinstance(val, dict):
            nested = _extract_items(val)
            if nested:
                return nested

    # Instagram profile responses put public media inside edge-based structures.
    for key in ("edge_owner_to_timeline_media", "edge_felix_video_timeline", "edge_media_to_parent_comment"):
        edge_container = data.get(key)
        if isinstance(edge_container, dict) and isinstance(edge_container.get("edges"), list):
            return _extract_items(edge_container["edges"])

    for key in ("profile", "user", "result", "aweme_info"):
        nested_value = data.get(key)
        if isinstance(nested_value, dict):
            nested = _extract_items(nested_value)
            if nested:
                return nested

    # Scrapers return profile records as a single object, including nested recent-post data.
    if any(k in data for k in ("url", "username", "handle", "id", "title", "unique_id", "biography")):
        return [data]
    return []


def _request_json(method: str, url: str, *, headers: dict[str, str], params: dict[str, Any] | None = None,
                  json_body: dict[str, Any] | None = None) -> tuple[str, Any, str | None]:
    try:
        with httpx.Client(timeout=_TIMEOUT, follow_redirects=False) as client:
            response = client.request(method, url, headers=headers, params=params, json=json_body)
            response.raise_for_status()
            return "checked", response.json(), None
    except httpx.HTTPStatusError as exc:
        # Do not log response bodies; they may contain data or provider diagnostics.
        return "failed", None, f"http_{exc.response.status_code}"
    except (httpx.TimeoutException, httpx.ConnectError):
        return "failed", None, "network_or_timeout"
    except (ValueError, TypeError):
        return "failed", None, "invalid_provider_response"
    except Exception as exc:
        logger.warning("Intelligence provider request failed: %s", type(exc).__name__)
        return "failed", None, type(exc).__name__


# ------------------------------ provider APIs ------------------------------

def _weir_search(api_key: str, platform: str, query: str, limit: int = 10) -> tuple[str, list[dict[str, Any]], str | None]:
    if not api_key:
        return "not_configured", [], None
    endpoint = "x/search" if platform == "x" else "reddit/search"
    status, data, error = _request_json(
        "POST", f"https://api.weirapp.io/v1/{endpoint}",
        headers={"Authorization": f"Bearer {api_key}", "Accept": "application/json"},
        json_body={"query": query, "limit": max(1, min(limit, 10))},
    )
    return status, _extract_items(data)[:limit] if data else [], error


def _scrape_get(api_key: str, path: str, params: dict[str, Any]) -> tuple[str, list[dict[str, Any]], str | None]:
    if not api_key:
        return "not_configured", [], None
    status, data, error = _request_json(
        "GET", f"https://api.scrapecreators.com{path}",
        headers={"x-api-key": api_key, "Accept": "application/json"}, params=params,
    )
    return status, _extract_items(data)[:10] if data else [], error


def _tavily_extract(api_key: str, urls: list[str]) -> tuple[str, list[dict[str, Any]], str | None]:
    """Extract a small, curated set of public pages discovered by Tavily search."""
    safe_urls: list[str] = []
    for value in urls[:3]:
        safe = _safe_http_url(value)
        if not safe:
            continue
        host = (urlsplit(safe).hostname or "").casefold()
        # Social posts are investigated through their platform-specific connectors.
        if any(host == d or host.endswith("." + d) for d in (
            "instagram.com", "tiktok.com", "facebook.com", "x.com", "twitter.com", "reddit.com"
        )):
            continue
        if safe not in safe_urls:
            safe_urls.append(safe)
    if not safe_urls:
        return "not_applicable", [], None
    status, data, error = _request_json(
        "POST", "https://api.tavily.com/extract",
        headers={"Accept": "application/json", "Content-Type": "application/json"},
        json_body={"api_key": api_key, "urls": safe_urls, "extract_depth": "basic", "include_images": False},
    )
    return status, _extract_items(data)[:3] if data else [], error


def _social_profile_checks(target: dict[str, Any], api_key: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Inspect public profile data, a bounded post sample, and relevant comments.

    Search/discovery results are not treated as profile-owned content. Post/comment
    records get a parent identity context only when fetched from the exact submitted
    profile's own posts endpoint. At most two posts per profile have comments read.
    """
    platform = str(target.get("platform") or "").casefold()
    handle = str(target.get("identifier") or "").lstrip("@")
    if not api_key:
        return [], [{"provider": "Scrape Creators", "operation": "public_lookup", "status": "not_configured",
                     "results_retrieved": 0, "results_relevant": 0,
                     "detail": "SCRAPE_CREATORS_API_KEY is not configured; no social-platform lookup was performed."}]

    profile_url = _safe_http_url(target.get("url"))
    if not profile_url and target.get("kind") == "handle" and handle:
        if platform == "instagram":
            profile_url = f"https://www.instagram.com/{handle}/"
        elif platform == "tiktok":
            profile_url = f"https://www.tiktok.com/@{handle}"
        elif platform == "facebook":
            profile_url = f"https://www.facebook.com/{handle}"

    # For a business name or domain, do bounded public keyword discovery on platforms
    # that actually expose search. This is not a global search of every platform post.
    checks: list[tuple[str, str, dict[str, Any], str, bool]] = []
    if target.get("kind") == "handle" and handle:
        if platform == "instagram":
            checks = [
                ("Instagram", "/v1/instagram/profile", {"handle": handle, "cache_max_age": "7d"}, "profile", False),
                ("Instagram", "/v2/instagram/user/posts", {"handle": handle, "trim": "true"}, "profile_posts", True),
                ("Instagram", "/v1/instagram/search/profiles", {"query": handle}, "profile_discovery", False),
                ("Instagram", "/v2/instagram/reels/search", {"query": f'"{handle}" scam complaint', "date_posted": "last-year", "page": 1}, "keyword_search", False),
            ]
        elif platform == "tiktok":
            checks = [
                ("TikTok", "/v1/tiktok/profile", {"handle": handle, "cache_max_age": "7d"}, "profile", False),
                ("TikTok", "/v3/tiktok/profile/videos", {"handle": handle, "sort_by": "latest", "region": "KE", "trim": "true"}, "profile_videos", True),
                ("TikTok", "/v1/tiktok/search/keyword", {"query": f'"{handle}" scam complaint', "date_posted": "last-6-months", "sort_by": "date-posted", "region": "KE", "trim": "true"}, "keyword_search", False),
            ]
        elif platform == "facebook" and profile_url:
            checks = [
                ("Facebook", "/v1/facebook/profile", {"url": profile_url, "cache_max_age": "7d"}, "profile", False),
                ("Facebook", "/v1/facebook/profile/posts", {"url": profile_url}, "public_posts", True),
            ]
    elif target.get("kind") in {"shop_name", "domain"}:
        keyword = _clean_text(target.get("identifier"), 90)
        if keyword:
            checks = [
                ("Instagram", "/v1/instagram/search", {"query": keyword}, "keyword_discovery", False),
                ("Instagram", "/v2/instagram/reels/search", {"query": f'"{keyword}" scam complaint', "date_posted": "last-year", "page": 1}, "keyword_search", False),
                ("TikTok", "/v1/tiktok/search/keyword", {"query": f'"{keyword}" scam complaint', "date_posted": "last-6-months", "sort_by": "date-posted", "region": "KE", "trim": "true"}, "keyword_discovery", False),
            ]

    evidence: list[dict[str, Any]] = []
    statuses: list[dict[str, Any]] = []
    posts_for_comments: list[tuple[str, str, str, dict[str, Any]]] = []

    def fetch(check):
        provider, path, params, operation, is_target_owned = check
        status, records, error = _scrape_get(api_key, path, params)
        return provider, path, operation, is_target_owned, status, records, error

    if checks:
        with ThreadPoolExecutor(max_workers=max(1, min(6, len(checks)))) as pool:
            futures = [pool.submit(fetch, check) for check in checks]
            for future in as_completed(futures):
                try:
                    provider, path, operation, is_target_owned, status, records, error = future.result()
                except Exception as exc:
                    logger.warning("Social lookup worker failed: %s", type(exc).__name__)
                    statuses.append({"provider": "Scrape Creators", "operation": "public_lookup", "status": "failed",
                                     "results_retrieved": 0, "results_relevant": 0, "failure_reason": type(exc).__name__,
                                     "detail": "A social lookup failed. No finding was inferred from the failure."})
                    continue

                matched_count = 0
                for record in records:
                    candidate = dict(record)
                    # Normalize common nested captions and authors returned by the platforms.
                    caption = candidate.get("caption")
                    if isinstance(caption, dict):
                        caption = caption.get("text") or ""
                    author_obj = candidate.get("author") if isinstance(candidate.get("author"), dict) else {}
                    user_obj = candidate.get("user") if isinstance(candidate.get("user"), dict) else {}
                    candidate_text = " ".join(str(candidate.get(k) or "") for k in (
                        "bio", "biography", "description", "text", "desc", "desc_text", "full_name", "fullName", "display_name"
                    ))
                    if caption:
                        candidate_text = " ".join([candidate_text, str(caption)])
                    if not candidate.get("text"):
                        candidate["text"] = candidate_text
                    candidate.setdefault("title", candidate.get("full_name") or candidate.get("fullName") or candidate.get("display_name")
                                         or candidate.get("username") or candidate.get("handle") or author_obj.get("name")
                                         or user_obj.get("nickname") or user_obj.get("name") or provider)
                    if not candidate.get("author"):
                        candidate["author"] = author_obj.get("username") or author_obj.get("unique_id") or author_obj.get("name")                                                or user_obj.get("username") or user_obj.get("unique_id") or user_obj.get("nickname")

                    if operation == "profile":
                        if provider == "Instagram" and not candidate.get("url"):
                            candidate["url"] = f"https://www.instagram.com/{handle}/"
                        elif provider == "TikTok" and not candidate.get("url"):
                            candidate["url"] = f"https://www.tiktok.com/@{handle}"
                        elif provider == "Facebook" and not candidate.get("url"):
                            candidate["url"] = profile_url
                        candidate.setdefault("username", handle)
                    elif operation == "profile_discovery":
                        # Search is for possible account identity; only retain an exact handle match.
                        result_handle = str(candidate.get("username") or candidate.get("handle") or "").lstrip("@").casefold()
                        if result_handle != handle.casefold():
                            continue
                        if provider == "Instagram" and not candidate.get("url"):
                            candidate["url"] = f"https://www.instagram.com/{handle}/"
                    elif operation in {"profile_posts", "profile_videos", "public_posts"}:
                        # These records are returned by the provider's endpoint for this exact profile.
                        if not candidate.get("url") and provider == "Instagram":
                            shortcode = candidate.get("code") or candidate.get("shortcode")
                            if shortcode:
                                candidate["url"] = f"https://www.instagram.com/p/{shortcode}/"
                        if not candidate.get("url") and provider == "TikTok":
                            video_id = candidate.get("aweme_id") or candidate.get("video_id") or candidate.get("id")
                            if video_id:
                                candidate["url"] = f"https://www.tiktok.com/@{handle}/video/{video_id}"
                        candidate.setdefault("title", f"Public {provider} post by @{handle}" if handle else f"Public {provider} post")

                    rec = _normalise_record(
                        provider, candidate, target,
                        source_type=("social_profile_observation" if operation == "profile" else
                                     "social_public_profile_post" if operation in {"profile_posts", "profile_videos", "public_posts"} else
                                     "social_public_search_lead"),
                        parent_url=profile_url if is_target_owned else None,
                        identity_context=("exact_profile_endpoint" if is_target_owned else None),
                    )
                    if rec:
                        matched_count += 1
                        evidence.append(rec)
                        if is_target_owned and candidate.get("url") and operation in {"profile_posts", "profile_videos", "public_posts"}:
                            # Keep the exact profile URL separately from the post URL. A comment
                            # belongs to this post, which was retrieved from the exact profile feed.
                            posts_for_comments.append((provider, str(candidate["url"]), str(profile_url or ""), candidate))

                statuses.append({"provider": provider, "operation": operation, "status": status,
                                 "results_retrieved": len(records), "results_relevant": matched_count, "failure_reason": error,
                                 "detail": (f"Retrieved {len(records)} public result(s); {matched_count} matched the submitted target. "
                                            "Profile posts are direct observations of public profile content; search results are leads, not proof.")})

    # Inspect comments on only two recent posts per exact profile. This is a bounded
    # first pass designed to surface customer complaints without scraping every comment.
    complaint_terms = re.compile(
        r"(?i)\b(scam|scammer|fraud|stole|stolen|never received|not received|not delivered|never delivered|"
        r"paid.{0,25}(?:no|never).{0,18}(?:deliver|arriv)|no response|blocked me|refund|fake seller|"
        r"tapeli|matapeli|nimeibiwa|hawakudeliver|hakufika|wamenichukua pesa)\b"
    )
    comment_endpoint = {"Instagram": "/v2/instagram/post/comments", "TikTok": "/v1/tiktok/video/comments", "Facebook": "/v1/facebook/post/comments"}
    comment_jobs: list[tuple[str, str, str]] = []
    seen_post_urls: set[str] = set()
    for provider, post_url, identity_profile_url, _post in posts_for_comments:
        safe_post = _safe_http_url(post_url)
        if not safe_post or safe_post in seen_post_urls or provider not in comment_endpoint:
            continue
        seen_post_urls.add(safe_post)
        comment_jobs.append((provider, safe_post, comment_endpoint[provider], identity_profile_url))
        if len(comment_jobs) >= 2:
            break

    def fetch_comments(job):
        provider, post_url, endpoint, identity_profile_url = job
        params = {"url": post_url}
        if provider == "TikTok":
            params["trim"] = "true"
        status, records, error = _scrape_get(api_key, endpoint, params)
        return provider, post_url, identity_profile_url, status, records, error

    if comment_jobs:
        with ThreadPoolExecutor(max_workers=min(2, len(comment_jobs))) as pool:
            futures = [pool.submit(fetch_comments, job) for job in comment_jobs]
            for future in as_completed(futures):
                try:
                    provider, post_url, identity_profile_url, status, comments, error = future.result()
                except Exception as exc:
                    logger.warning("Social comment lookup failed: %s", type(exc).__name__)
                    statuses.append({"provider": "Scrape Creators", "operation": "public_comments", "status": "failed",
                                     "results_retrieved": 0, "results_relevant": 0, "failure_reason": type(exc).__name__})
                    continue
                matched_comments = 0
                for comment in comments:
                    text_value = _clean_text(comment.get("text") or comment.get("content"), _MAX_TEXT)
                    # Ordinary praise is not useful as fraud evidence; retain comments that
                    # mention complaints, payment loss, refunds, scam warnings or non-delivery.
                    if not text_value or not complaint_terms.search(text_value):
                        continue
                    normalized = dict(comment)
                    normalized["text"] = text_value
                    user_obj = normalized.get("user") if isinstance(normalized.get("user"), dict) else {}
                    normalized["author"] = (normalized.get("author") or user_obj.get("username") or user_obj.get("unique_id")
                                             or user_obj.get("name") or user_obj.get("nickname"))
                    normalized["title"] = f"Public comment on {platform} seller post"
                    rec = _normalise_record(
                        provider, normalized, target, source_type="social_public_comment_on_profile_post",
                        parent_url=post_url, identity_parent_url=identity_profile_url,
                        identity_context="comment_on_exact_profile_post",
                    )
                    if rec:
                        matched_comments += 1
                        evidence.append(rec)
                statuses.append({"provider": provider, "operation": "public_comments", "status": status,
                                 "results_retrieved": len(comments), "results_relevant": matched_comments, "failure_reason": error,
                                 "detail": (f"Read {len(comments)} public comment(s) from up to two posts; "
                                            f"{matched_comments} contained complaint or warning language. "
                                            "Comments are unverified user reports, not established facts.")})

    if not statuses and target.get("kind") == "handle" and platform in {"instagram", "tiktok", "facebook"}:
        statuses.append({"provider": "Scrape Creators", "operation": "public_lookup", "status": "not_checked",
                         "results_retrieved": 0, "results_relevant": 0,
                         "detail": "The supplied target did not provide a supported public profile identifier."})
    return evidence, statuses



def _social_item_to_evidence(source: dict[str, Any], target: dict[str, Any]) -> dict[str, Any] | None:
    """Adapt the current social provider contract into the shared evidence schema.

    The social provider has already applied exact-handle/account scoping. Preserve its
    match decision, but never promote a public allegation to verified fact.
    """
    identifier = _clean_text(target.get("identifier"), 120).lstrip("@").casefold()
    searched = _clean_text(source.get("searched_identifier"), 120).lstrip("@").casefold()
    if not identifier or (searched and searched != identifier):
        return None
    url = _safe_http_url(source.get("url"))
    if not url:
        return None
    title = _clean_text(source.get("title"), 220)
    snippet = _clean_text(source.get("snippet"), _MAX_TEXT)
    provider = _clean_text(source.get("provider") or "Social provider", 80)
    platform = _clean_text(source.get("platform") or provider, 40)
    source_kind = str(source.get("source_type") or "")
    observed_profile = source_kind == "social_profile_observation"
    # A post is a reported allegation only when its actual text contains complaint or
    # warning language. Ordinary posts and promotional content remain unverified mentions.
    allegation_pattern = re.compile(
        r"(?i)\b(?:scam(?:mer)?s?|fraud(?:ulent)?|complaint|warning|stole|stolen|"
        r"never received|not delivered|never delivered|paid.{0,35}(?:no|never).{0,24}(?:deliver|arriv)|"
        r"blocked after (?:payment|paying)|refund.{0,35}(?:ignored|refused)|tapeli|matapeli|nimeibiwa|hawakudeliver)\b"
    )
    reported = bool(not observed_profile and allegation_pattern.search(f"{title} {snippet}"))
    external_id = _clean_text(source.get("external_id") or source.get("id") or "", 100)
    author = _clean_text(source.get("author_username") or source.get("author") or "", 100).lstrip("@")
    collected = _clean_text(source.get("checked_at") or source.get("collected_at") or _now(), 80)
    return {
        "evidence_id": hashlib.sha256(f"{provider}|{url}|{snippet}".encode()).hexdigest()[:16],
        "provider": provider,
        "platform": platform,
        "source_type": "social_public_profile_observation" if observed_profile else "social_public_search_lead",
        "content_status": "public_profile_observed" if observed_profile else "public_post_retrieved",
        "evidence_type": "public_profile_observation" if observed_profile else "public_complaint_or_mention",
        "claim_status": "reported_allegation" if reported else "unverified_public_mention",
        "identity_match": _clean_text(source.get("identity_match") or source.get("relevance_reason") or source.get("relevance") or "provider_exact_target_filter", 100),
        "target_identifier": _clean_text(target.get("identifier"), 120),
        "title": title,
        "snippet": snippet,
        "location_claims": _extract_location_claims({key: source.get(key) for key in (
            "bio", "biography", "location", "profile_location", "address", "physical_address", "street_address",
            "business_address", "store_address", "shop_address", "office_address", "contact_address", "visit_address",
            "city", "town", "county", "region", "country", "delivery_area", "delivery_areas", "service_area", "service_areas"
        ) if source.get(key) is not None}, snippet),
        "outbound_links": _extract_outbound_links(source),
        "url": url,
        "author": author,
        "external_id": external_id,
        "published_at": _clean_text(source.get("published_date") or "", 80),
        "collected_at": collected,
        "independence_key": (author.casefold() if author else "") + "|" + (url or external_id),
        "verified": False,
        "source_verification_status": _clean_text(source.get("verification_status") or "unverified_public_content", 80),
    }

# --------------------------- local red-flag rules ---------------------------

_JOB_CREDENTIAL_PATTERNS = [
    re.compile(r"(?i)\b(?:gmail|email|google)\s+(?:account\s+)?password\b"),
    re.compile(r"(?i)\bpassword\s+(?:for|of)\s+(?:your\s+)?(?:gmail|email|google)\b"),
]
_JOB_FEE_PATTERN = re.compile(r"(?i)\b(?:job|recruitment|registration|application|processing|medical|visa)\s+(?:fee|payment|deposit)\b|\bpay\s+(?:to\s+)?(?:apply|register|secure|get)\s+(?:the\s+)?job\b")
_NON_DELIVERY_PATTERN = re.compile(r"(?i)\b(?:paid.{0,35}(?:no|never).{0,24}(?:deliver\w*|arriv\w*)|(?:never|not)\s+(?:received|delivered)|took my money|hawakudeliver|nimeibiwa|hakufika)\b")
_VAGUE_OVERSEAS_JOB_PATTERN = re.compile(r"(?i)\b(?:jobs?\s+(?:in|abroad|overseas)|work\s+in\s+(?:the\s+)?(?:united states|usa|uk|canada)|employment\s+(?:in|abroad)|kazi\s+(?:marekani|nje ya nchi))\b")


def analyse_submitted_content(text: str, category: str) -> list[dict[str, Any]]:
    """Run local rules on already-masked user content. Never sends this to providers."""
    value = str(text or "")
    flags: list[dict[str, Any]] = []
    if category == "job":
        if any(p.search(value) for p in _JOB_CREDENTIAL_PATTERNS):
            observed = next((match.group(0) for pattern in _JOB_CREDENTIAL_PATTERNS if (match := pattern.search(value))), "")
            flags.append({"code": "JOB_EMAIL_PASSWORD_REQUEST", "severity": "critical", "evidence_status": "directly_observed_in_submission",
                          "observed_excerpt": observed,
                          "statement": "The submitted advert asks for an email or Gmail password.",
                          "why_it_matters": "A legitimate recruiter does not need the applicant's email password. This can enable account takeover.",
                          "advice": ["Do not enter the password.", "If already entered, change it through Google's official account settings and review active sessions."],
                          "source_ids": []})
        fee_match = _JOB_FEE_PATTERN.search(value)
        if fee_match:
            flags.append({"code": "JOB_UPFRONT_FEE_LANGUAGE", "severity": "high", "evidence_status": "directly_observed_in_submission",
                          "observed_excerpt": fee_match.group(0),
                          "statement": "The submitted content appears to mention a payment connected to applying for or obtaining a job.",
                          "why_it_matters": "An unexplained upfront recruitment or processing payment is a significant warning sign; the exact fee and applicable recruitment rules need verification.",
                          "advice": ["Do not pay until the recruiter and fee basis are independently verified."], "source_ids": []})
        vague_match = _VAGUE_OVERSEAS_JOB_PATTERN.search(value)
        if vague_match and not re.search(r"(?i)\b(?:company|employer|job title|salary|vacancy|recruitment agency|agency name)\b", value):
            flags.append({"code": "VAGUE_OVERSEAS_JOB_ADVERT", "severity": "weak", "evidence_status": "verification_gap_in_submission",
                          "observed_excerpt": vague_match.group(0),
                          "statement": "The overseas-job message does not identify a specific employer, vacancy or recruiter.",
                          "why_it_matters": "A vague advert is a verification gap. It is not proof of fraud, but the employer and recruitment route should be identified before anyone applies or pays.",
                          "advice": ["Ask for the employer's legal name, job title, location, salary and recruiter details."], "source_ids": []})
    non_delivery_match = _NON_DELIVERY_PATTERN.search(value)
    if non_delivery_match:
        flags.append({"code": "NON_DELIVERY_LANGUAGE", "severity": "supporting", "evidence_status": "directly_observed_in_submission",
                      "observed_excerpt": non_delivery_match.group(0),
                      "statement": "The submitted content contains language about payment followed by non-delivery.",
                      "why_it_matters": "This is a complaint pattern to investigate, not proof that the complaint is true.", "advice": [], "source_ids": []})
    return flags


def detect_evidence_flags(category: str, evidence: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Derive cautious, category-specific flags from target-matched source evidence.

    These flags describe what a source reports. They never turn third-party claims
    into verified facts, and every flag links back to the evidence IDs supporting it.
    """
    flags: list[dict[str, Any]] = []
    if category == "job":
        credential_pattern = re.compile(
            r"(?i)(?:gmail|email|google)\s+(?:account\s+)?password|password\s+(?:for|of)\s+(?:your\s+)?(?:gmail|email|google)|"
            r"asked applicants? for.{0,40}(?:password|credentials)|requested.{0,40}(?:gmail|email).{0,20}password"
        )
        supporting = [item for item in evidence if credential_pattern.search(
            f"{item.get('title') or ''} {item.get('snippet') or ''}"
        )]
        if supporting:
            flags.append({
                "code": "REPORTED_JOB_CREDENTIAL_HARVESTING",
                "severity": "high",
                "evidence_status": "reported_in_target_matched_public_sources",
                "statement": "A public source associated with this exact target reports that a job-application page requested an email or Gmail password.",
                "why_it_matters": "Recruiters do not need an applicant's email password. A page requesting it can enable account takeover. The report may concern another path or an earlier version of the site, so the exact submitted page still needs direct verification.",
                "source_ids": [item.get("evidence_id") for item in supporting[:5]],
                "advice": ["Do not enter an email password or OTP on this site.", "If credentials were already entered, change the password through the email provider's official site, review active sessions and enable two-step verification."],
            })

        recruitment_pattern = re.compile(r"(?i)\b(recruitment|job application|overseas job|employment offer).{0,70}\b(scam|phishing|fraud|credential|password)\b|\b(scam|phishing|fraud).{0,70}\b(recruitment|job application|overseas job)\b")
        reported = [item for item in evidence if recruitment_pattern.search(
            f"{item.get('title') or ''} {item.get('snippet') or ''}"
        )]
        if reported and not supporting:
            flags.append({
                "code": "REPORTED_RECRUITMENT_SCAM_ASSOCIATION",
                "severity": "high",
                "evidence_status": "reported_in_target_matched_public_sources",
                "statement": "A public source associates this exact domain or identifier with a recruitment-related scam or phishing report.",
                "why_it_matters": "A relevant historical report warrants caution, but it does not by itself prove that the exact message, sender or URL path is the same campaign.",
                "source_ids": [item.get("evidence_id") for item in reported[:5]],
                "advice": ["Do not apply or pay through the link until the employer and recruiter are independently verified."],
            })

    general_report_pattern = re.compile(r"(?i)\b(scam|scammer|phishing|malware|fraudulent|blacklist warning|security warning)\b")
    reported_targets = [item for item in evidence if item.get("claim_status") == "reported_allegation"
                        and general_report_pattern.search(f"{item.get('title') or ''} {item.get('snippet') or ''}")]
    if reported_targets and not any(x.get("code") in {"REPORTED_JOB_CREDENTIAL_HARVESTING", "REPORTED_RECRUITMENT_SCAM_ASSOCIATION"} for x in flags):
        flags.append({
            "code": "PUBLIC_RISK_REPORT_ASSOCIATED_WITH_TARGET",
            "severity": "supporting",
            "evidence_status": "reported_in_target_matched_public_sources",
            "statement": "One or more target-matched public sources contain scam, phishing or security-warning claims about this target.",
            "why_it_matters": "These are reports to investigate, not proof. Check the original pages, dates and exact entity match before relying on them.",
            "source_ids": [item.get("evidence_id") for item in reported_targets[:5]],
            "advice": ["Review the linked original reports and verify that they refer to the exact account or domain you submitted."],
        })
    historical_malicious = [item for item in evidence
                            if item.get("source_type") == "urlscan_historical_scan" and item.get("malicious_verdict") is True]
    if historical_malicious:
        flags.append({
            "code": "URLSCAN_HISTORICAL_MALICIOUS_VERDICT",
            "severity": "supporting",
            "evidence_status": "historical_scanner_observation",
            "statement": "urlscan.io has a historical scan record for this domain that carried a malicious verdict.",
            "why_it_matters": "This is a useful technical warning signal, but the scan may concern an earlier page version or a different path on the same domain. Review the dated scan itself and corroborate with current evidence; this historical result alone does not prove the current site or seller is fraudulent.",
            "source_ids": [item.get("evidence_id") for item in historical_malicious[:5]],
            "advice": ["Open the historical scan record and compare its date, domain, page title and observed behaviour with the URL being investigated.", "Do not rely on a historical scanner result as the only reason to accuse a seller."],
        })
    return flags


def upgrade_url_assessment(existing_band: str, flags: list[dict[str, Any]]) -> tuple[str, str | None]:
    """Apply narrowly defined deterministic upgrades from new target-matched evidence.

    Third-party reports can raise a target to ``suspicious_verify_first`` but cannot
    create ``high_risk`` on their own. Existing authoritative high-risk decisions are
    never downgraded. A reviewed official identity is retained unless a direct critical
    credential request is present in the submitted material.
    """
    band = str(existing_band or "inconclusive")
    if band == "high_risk":
        return band, None
    critical_submission = any(x.get("code") == "JOB_EMAIL_PASSWORD_REQUEST" for x in flags)
    high_flags = [x for x in flags if x.get("severity") in {"high", "critical"}]
    multiple_reports = any(x.get("code") == "MULTIPLE_NON_DELIVERY_ALLEGATIONS" for x in flags)
    if critical_submission or high_flags or multiple_reports:
        strongest = next((x for x in flags if x.get("severity") == "critical"), None) or next(iter(high_flags), None)
        reason = str((strongest or {}).get("statement") or "Target-matched evidence contains warning signs that require independent verification.")
        return "suspicious_verify_first", reason
    return band, None


def detect_cross_source_flags(evidence: list[dict[str, Any]]) -> list[dict[str, Any]]:
    allegations = [e for e in evidence if e.get("claim_status") == "reported_allegation" and _NON_DELIVERY_PATTERN.search(str(e.get("snippet") or ""))]
    # Count genuinely distinct authors and source URLs. One author posting repeatedly is one report.
    distinct: dict[str, dict[str, Any]] = {}
    for item in allegations:
        author = str(item.get("author") or "").casefold().strip()
        url = str(item.get("url") or item.get("external_id") or "")
        key = author or url
        if key and key not in distinct:
            distinct[key] = item
    if len(distinct) >= 2:
        return [{"code": "MULTIPLE_NON_DELIVERY_ALLEGATIONS", "severity": "supporting", "evidence_status": "multiple_unverified_public_allegations",
                 "statement": f"{len(distinct)} distinct public source/author record(s) allege non-delivery or loss after payment.",
                 "why_it_matters": "Multiple distinct reports deserve attention, but they remain allegations until their authors, transactions and target identity are independently corroborated.",
                 "source_ids": [x.get("evidence_id") for x in list(distinct.values())[:8]],
                 "advice": ["Check whether the reports describe the exact same account or domain.", "Look for independent transaction details and any response from the business."]}]
    return []


def _dedupe_evidence(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in items:
        url = str(item.get("url") or "").split("?", 1)[0].rstrip("/").casefold()
        external = str(item.get("external_id") or "")
        text_hash = hashlib.sha256(re.sub(r"\W+", " ", str(item.get("snippet") or "").casefold()).encode()).hexdigest()[:16]
        snippet = str(item.get("snippet") or "").strip()
        # Exact copied text is one underlying report even when reposted across URLs.
        key = ("text:" + text_hash) if len(snippet) >= 35 else (url or (str(item.get("provider")) + ":" + external if external else text_hash))
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
        if len(out) >= _MAX_EVIDENCE:
            break
    return out


# ------------------------------- orchestrator -------------------------------

def investigate_public_targets(
    targets: list[dict[str, Any]],
    *,
    category: str,
    submitted_text: str,
    settings: Any,
    max_queries_per_target: int = 2,
    skip_tavily: bool = False,
    web_search_fn=None,
    search_seed_results: list[dict[str, Any]] | None = None,
    social_result: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run bounded, category-aware public investigations and return structured evidence."""
    safe_targets = [t for t in (targets or [])[:3] if isinstance(t, dict) and t.get("identifier") and t.get("kind") in {"domain", "handle", "shop_name"}]
    result: dict[str, Any] = {
        "category": category if category in {"message", "job", "grant", "payment", "shop", "website"} else "message",
        "targets": [{"kind": t.get("kind"), "identifier": _clean_text(t.get("identifier"), 120), "platform": _clean_text(t.get("platform"), 24)} for t in safe_targets],
        "providers": [], "evidence": [], "red_flags": [], "advice": [], "limitations": [], "manual_searches": [],
        "domain_infrastructure": [], "official_registry_checks": [],
        "checked_at": _now(), "version": "toroka-intelligence-v1",
    }
    result["red_flags"].extend(analyse_submitted_content(submitted_text, result["category"]))
    if not safe_targets:
        result["limitations"].append("No public domain, social handle or explicit shop name could be isolated for external search. Only the submitted content was assessed.")

    tavily_key = getattr(settings, "tavily_api_key", "") or ""
    weir_key = getattr(settings, "weir_api_key", "") or ""
    scrape_key = getattr(settings, "scrape_creators_api_key", "") or ""
    places_key = getattr(settings, "google_places_api_key", "") or ""
    urlscan_key = getattr(settings, "urlscan_api_key", "") or ""
    domain_intel_enabled = bool(getattr(settings, "enable_domain_intelligence", False))
    certspotter_key = getattr(settings, "certspotter_api_key", "") or ""
    domain_intel_subdomains = bool(getattr(settings, "domain_intel_include_subdomains", False))
    ttl = int(getattr(settings, "intelligence_cache_ttl_seconds", 900) or 0)
    all_evidence: list[dict[str, Any]] = []
    all_map_candidates: list[dict[str, Any]] = []
    map_statuses: list[str] = []
    processed_infrastructure_domains: set[str] = set()
    search_fn = web_search_fn or public_search

    for target in safe_targets:
        # Cache identity includes provider availability. Otherwise a no-key result
        # could be served later after the operator configures a provider (or vice versa).
        provider_profile = (f"tavily:{bool(tavily_key)}|weir:{bool(weir_key)}|scrape:{bool(scrape_key)}|"
                            f"places:{bool(places_key)}|urlscan:{bool(urlscan_key)}|domainintel:{domain_intel_enabled}|"
                            f"certspotter:{bool(certspotter_key)}|ct_subdomains:{domain_intel_subdomains}")
        cache_key = hashlib.sha256((_target_key(target) + "|" + result["category"] + "|" + provider_profile + "|v6").encode()).hexdigest()
        cached = _cache_get(cache_key, ttl)
        if cached:
            all_evidence.extend(cached.get("evidence", []))
            all_map_candidates.extend(cached.get("map_candidates", []))
            result["domain_infrastructure"].extend(cached.get("domain_infrastructure", []))
            result["providers"].extend(cached.get("providers", []))
            if result["category"] == "shop":
                places_status = next((p.get("status") for p in cached.get("providers", []) if p.get("provider") == "Google Places"), None)
                if places_status:
                    map_statuses.append(str(places_status))
            continue

        local_evidence: list[dict[str, Any]] = []
        local_providers: list[dict[str, Any]] = []
        local_domain_infrastructure: list[dict[str, Any]] = []
        # Run independent providers concurrently to keep the synchronous chat endpoint bounded.
        queries = _query_terms(target, result["category"])[:max(1, min(max_queries_per_target, 2))]

        def tavily_job(query: str):
            outcome = search_fn(query, tavily_key, max_results=5)
            filtered = filter_public_search_results(
                outcome.get("results", []), identifier=str(target["identifier"]),
                kind=str(target.get("kind") or "handle"), platform=target.get("platform"),
            )
            status_record = {"provider": "Tavily", "operation": "search", "status": outcome.get("status", "failed"),
                             "query": query, "manual_search_url": manual_search_url(query), "results_retrieved": filtered.get("raw_result_count", outcome.get("results_retrieved", 0)),
                             "results_relevant": filtered.get("relevant_count", 0),
                             "results_background": filtered.get("background_count", 0),
                             "results_excluded": filtered.get("irrelevant_count", 0),
                             "detail": (f"Public search retrieved {filtered.get('raw_result_count', 0)} result(s): "
                                        f"{filtered.get('relevant_count', 0)} result(s) mention or link to the exact target, "
                                        f"{filtered.get('background_count', 0)} general background result(s), and "
                                        f"{filtered.get('irrelevant_count', 0)} unrelated result(s) excluded. "
                                        "Entity-related results are unverified leads, not proof of fraud or legitimacy.")}
            records = []
            relevant = filtered.get("relevant_results", [])
            for item in relevant:
                record = _normalise_record("Tavily", item, target, source_type="public_web_search_lead")
                if record:
                    records.append(record)

            # Search snippets are leads. Read only the top two exact-target pages per
            # query, excluding social URLs handled by platform-specific providers.
            extract_urls = [str(item.get("url") or "") for item in relevant[:2]]
            extract_status, extracted, extract_error = _tavily_extract(tavily_key, extract_urls)
            extracted_records = []
            search_by_url = {str(item.get("url") or ""): item for item in relevant}
            for page in extracted:
                page_url = str(page.get("url") or "")
                source = search_by_url.get(page_url, {})
                candidate = {
                    "url": page_url,
                    "title": source.get("title") or page.get("title") or page_url,
                    "raw_content": page.get("raw_content") or page.get("content") or "",
                }
                record = _normalise_record("Tavily", candidate, target, source_type="inspected_public_web_page")
                if record:
                    extracted_records.append(record)

            extract_record = {
                "provider": "Tavily", "operation": "extract", "status": extract_status,
                "results_retrieved": len(extracted), "results_relevant": len(extracted_records),
                "failure_reason": extract_error,
                "detail": (f"Attempted to read up to two relevant public pages; retrieved {len(extracted)} page(s), "
                           f"of which {len(extracted_records)} matched the target. Retrieved page content is direct source material, "
                           "but claims made on those pages remain unverified unless independently corroborated."),
            }
            return status_record, records, extract_record, extracted_records

        def tavily_seed_extract_job():
            seeds = []
            for seed in (search_seed_results or []):
                if not isinstance(seed, dict):
                    continue
                candidate = {"url": seed.get("url"), "title": seed.get("title"), "text": seed.get("snippet") or seed.get("title")}
                if _matches_target(candidate, target)[0]:
                    seeds.append(seed)
            urls = [str(x.get("url") or "") for x in seeds[:3]]
            status, pages, error = _tavily_extract(tavily_key, urls)
            seed_by_url = {str(x.get("url") or ""): x for x in seeds}
            extracted = []
            for page in pages:
                page_url = str(page.get("url") or "")
                seed = seed_by_url.get(page_url, {})
                candidate = {"url": page_url, "title": seed.get("title") or page.get("title") or page_url,
                             "raw_content": page.get("raw_content") or page.get("content") or ""}
                rec = _normalise_record("Tavily", candidate, target, source_type="inspected_public_web_page")
                if rec:
                    extracted.append(rec)
            provider_status = {
                "provider": "Tavily", "operation": "extract_existing_search_leads", "status": status,
                "results_retrieved": len(pages), "results_relevant": len(extracted), "failure_reason": error,
                "detail": (f"Read up to three previously discovered, target-matched public pages; retrieved {len(pages)} page(s), "
                           f"{len(extracted)} matched the target. Page claims remain unverified until corroborated."),
            }
            return provider_status, extracted

        def weir_job(platform: str, query: str):
            status, records, error = _weir_search(weir_key, platform, query, limit=10)
            provider_name = "Weir X" if platform == "x" else "Weir Reddit"
            matched_records = []
            for raw in records:
                candidate = dict(raw)
                user_obj = raw.get("user") if isinstance(raw.get("user"), dict) else {}
                candidate.setdefault("author", user_obj.get("username") or raw.get("username"))
                candidate.setdefault("text", raw.get("text") or raw.get("body") or raw.get("selftext"))
                candidate.setdefault("url", raw.get("url") or raw.get("permalink"))
                rec = _normalise_record(provider_name, candidate, target, source_type="social_public_search_lead")
                if rec:
                    matched_records.append(rec)
            status_record = {"provider": provider_name, "operation": "search", "status": status,
                             "query": query, "results_retrieved": len(records), "results_relevant": len(matched_records),
                             "failure_reason": error,
                             "detail": (f"Retrieved {len(records)} public result(s); {len(matched_records)} matched the target. "
                                        "Public posts and comments are allegations or mentions, not verified facts.")}
            return status_record, matched_records

        jobs = []
        if tavily_key and not skip_tavily:
            for query in queries:
                jobs.append(("tavily", query, lambda q=query: tavily_job(q)))
        elif not skip_tavily:
            local_providers.append({"provider": "Tavily", "operation": "search", "status": "not_configured", "results_retrieved": 0, "results_relevant": 0,
                                    "detail": "TAVILY_API_KEY is not configured; no live Tavily search was performed."})
        elif tavily_key and search_seed_results:
            jobs.append(("tavily_seed_extract", "", tavily_seed_extract_job))
        if social_result is not None:
            # Reuse the newer project's social adapter output. Do not make duplicate
            # X/Reddit/Instagram/TikTok/Facebook API calls from this orchestrator.
            for source in (social_result.get("sources") or []):
                if isinstance(source, dict):
                    record = _social_item_to_evidence(source, target)
                    if record:
                        local_evidence.append(record)
            for status in (social_result.get("statuses") or []):
                if not isinstance(status, dict):
                    continue
                searched = _clean_text(status.get("searched_identifier"), 120).lstrip("@").casefold()
                if searched and searched != _clean_text(target.get("identifier"), 120).lstrip("@").casefold():
                    continue
                local_providers.append({
                    "provider": _clean_text(status.get("provider") or "Social provider", 80),
                    "operation": _clean_text(status.get("operation") or "public_lookup", 60),
                    "platform": _clean_text(status.get("platform") or "", 30),
                    "status": status.get("status") or "failed",
                    "results_retrieved": int(status.get("results") or status.get("results_retrieved") or 0),
                    "results_relevant": int(status.get("results_relevant") or status.get("results") or 0),
                    "detail": _clean_text(status.get("detail") or "Social provider returned no status detail.", 600),
                })
        else:
            if weir_key:
                x_query = queries[0] if queries else f'"{target["identifier"]}" scam complaint'
                reddit_query = queries[1] if len(queries) > 1 else x_query
                jobs.append(("weir_x", x_query, lambda q=x_query: weir_job("x", q)))
                jobs.append(("weir_reddit", reddit_query, lambda q=reddit_query: weir_job("reddit", q)))
            else:
                for provider_name in ("Weir X", "Weir Reddit"):
                    local_providers.append({"provider": provider_name, "operation": "search", "status": "not_configured", "results_retrieved": 0, "results_relevant": 0,
                                            "detail": "WEIR_API_KEY is not configured; this provider was not checked."})
            social_platform_handle = target.get("kind") == "handle" and str(target.get("platform") or "").casefold() in {"instagram", "tiktok", "facebook"}
            social_name_or_domain = target.get("kind") in {"shop_name", "domain"}
            if scrape_key and (social_platform_handle or social_name_or_domain):
                jobs.append(("social_profile", "", lambda: _social_profile_checks(target, scrape_key)))
            elif social_platform_handle or social_name_or_domain:
                local_providers.append({"provider": "Scrape Creators", "operation": "public_discovery", "status": "not_configured", "results_retrieved": 0, "results_relevant": 0,
                                        "detail": "SCRAPE_CREATORS_API_KEY is not configured; public social discovery was not checked."})

        with ThreadPoolExecutor(max_workers=max(1, min(6, len(jobs)))) as pool:
            futures = [pool.submit(fn) for _kind, _query, fn in jobs]
            for future in as_completed(futures):
                try:
                    value = future.result()
                    if isinstance(value, tuple) and len(value) == 2 and isinstance(value[0], list):
                        profile_evidence, profile_status = value
                        local_evidence.extend(profile_evidence)
                        local_providers.extend(profile_status)
                    elif isinstance(value, tuple) and len(value) == 2 and isinstance(value[0], dict):
                        provider_status, provider_evidence = value
                        local_providers.append(provider_status)
                        local_evidence.extend(provider_evidence)
                    elif isinstance(value, tuple) and len(value) == 4:
                        search_status, search_evidence, extract_status, extract_evidence = value
                        local_providers.extend([search_status, extract_status])
                        local_evidence.extend(search_evidence)
                        local_evidence.extend(extract_evidence)
                    else:
                        provider_status, provider_evidence = value
                        local_providers.append(provider_status)
                        local_evidence.extend(provider_evidence)
                except Exception as exc:
                    logger.warning("Investigation task failed: %s", type(exc).__name__)
                    local_providers.append({"provider": "Investigation provider", "operation": "task", "status": "failed",
                                            "results_retrieved": 0, "results_relevant": 0, "failure_reason": type(exc).__name__,
                                            "detail": "A provider task failed; no finding was inferred from the failure."})

        local_map_candidates: list[dict[str, Any]] = []
        if result["category"] == "shop":
            places_query = _shop_places_query(target, local_evidence)
            places_result = search_places(places_key, places_query) if places_query else {
                "status": "not_checked", "provider": "Google Places", "detail": "No usable public shop name was available for a map listing search.", "places": [], "results_retrieved": 0,
            }
            local_map_candidates = _places_candidate_records(target, places_result)
            places_status = str(places_result.get("status") or "failed")
            map_statuses.append(places_status)
            local_providers.append({
                "provider": "Google Places", "operation": "shop_location_search", "status": places_status,
                "query": places_result.get("query") or places_query,
                "results_retrieved": int(places_result.get("results_retrieved") or 0),
                "results_relevant": len(local_map_candidates),
                "detail": str(places_result.get("detail") or "No location search detail was supplied."),
                "failure_reason": places_result.get("failure_reason"),
            })

        # urlscan historical lookup only receives a domain, never the submitted URL.
        # For social shops, the domain must have been explicitly linked by a
        # target-controlled public profile/page or an inspected target website.
        domain_sources: dict[str, str | None] = {}
        if target.get("kind") == "domain":
            direct_domain = normalize_domain(str(target.get("identifier") or ""))
            if direct_domain:
                domain_sources[direct_domain] = None
        else:
            excluded_hosts = {
                "instagram.com", "tiktok.com", "facebook.com", "fb.com", "x.com", "twitter.com",
                "reddit.com", "youtube.com", "linkedin.com", "threads.net", "pinterest.com",
                "snapchat.com", "whatsapp.com", "telegram.org", "t.me", "google.com",
                "maps.app.goo.gl",
            }
            for source_item in local_evidence:
                if not isinstance(source_item, dict) or not _is_target_controlled_source(source_item):
                    continue
                parent_id = str(source_item.get("evidence_id") or "") or None
                for public_link in (source_item.get("outbound_links") or [])[:8]:
                    host = normalize_domain(str(public_link or ""))
                    if not host or any(host == blocked or host.endswith("." + blocked) for blocked in excluded_hosts):
                        continue
                    domain_sources.setdefault(host, parent_id)
                    if len(domain_sources) >= 2:
                        break
                if len(domain_sources) >= 2:
                    break

        # Build 2: bounded passive domain/infrastructure investigation. A domain is
        # queried only when it is the submitted target or an explicit outbound link
        # from a target-controlled public profile/page. Never derive this list from
        # arbitrary third-party search-result domains.
        if domain_intel_enabled:
            for infra_domain, parent_evidence_id in list(domain_sources.items())[:2]:
                if len(result["domain_infrastructure"]) + len(local_domain_infrastructure) >= 2:
                    break
                if infra_domain in processed_infrastructure_domains:
                    continue
                processed_infrastructure_domains.add(infra_domain)
                try:
                    infra = investigate_domain_infrastructure(
                        infra_domain,
                        ct_api_key=certspotter_key,
                        include_subdomains=domain_intel_subdomains,
                    )
                    if isinstance(infra, dict):
                        if parent_evidence_id:
                            infra["linked_from_evidence_id"] = parent_evidence_id
                        local_domain_infrastructure.append(infra)
                        local_evidence.extend([x for x in infra.get("evidence", []) if isinstance(x, dict)])
                        for provider in infra.get("providers", []):
                            if not isinstance(provider, dict):
                                continue
                            local_providers.append({
                                **provider,
                                "query_domain": infra_domain,
                            })
                except Exception as exc:
                    logger.warning("Domain infrastructure lookup failed: %s", type(exc).__name__)
                    local_providers.append({
                        "provider": "Toroka domain intelligence", "operation": "passive_infrastructure_lookup",
                        "status": "failed", "query_domain": infra_domain,
                        "results_retrieved": 0, "results_relevant": 0,
                        "failure_reason": type(exc).__name__,
                        "detail": "Domain infrastructure lookup could not be completed; no conclusion was inferred.",
                    })

        for scanned_domain, parent_evidence_id in list(domain_sources.items())[:2]:
            scan_result = search_historical_domain(urlscan_key, scanned_domain)
            scan_records = scan_result.get("results") if isinstance(scan_result.get("results"), list) else []
            local_providers.append({
                "provider": "urlscan.io", "operation": "historical_domain_search",
                "status": str(scan_result.get("status") or "failed"),
                "query_domain": scanned_domain,
                "results_retrieved": int(scan_result.get("results_retrieved") or 0),
                "results_relevant": len(scan_records),
                "search_date_limit_days": scan_result.get("search_date_limit_days"),
                "failure_reason": scan_result.get("failure_reason"),
                "detail": _clean_text(scan_result.get("detail") or "Historical scan lookup did not return a detail.", 700),
            })
            for scan in scan_records[:5]:
                if not isinstance(scan, dict):
                    continue
                scan_id = _clean_text(scan.get("scan_id"), 80)
                if not scan_id:
                    continue
                malicious = scan.get("malicious_verdict") if isinstance(scan.get("malicious_verdict"), bool) else None
                verdict_text = (
                    "The historical scanner verdict was marked malicious."
                    if malicious is True else
                    "The historical scanner verdict was not marked malicious. This does not establish that the current site is safe."
                    if malicious is False else
                    "The historical record did not include a machine-readable malicious verdict."
                )
                scan_date = _clean_text(scan.get("scan_date"), 80) or "date not supplied"
                title = _clean_text(scan.get("page_title"), 160) or scanned_domain
                snippet = _clean_text(
                    f"Historical urlscan.io scan of {scanned_domain} on {scan_date}. {verdict_text} "
                    f"Visibility: {scan.get('visibility') or 'unknown'}. "
                    f"Score: {scan.get('verdict_score') if scan.get('verdict_score') is not None else 'not supplied'}. "
                    f"Redirect: {scan.get('redirected') or 'not supplied'}. This is a historical observation, not a live scan or proof of current behaviour.",
                    900,
                )
                evidence_id = hashlib.sha256(
                    f"urlscan|{_target_key(target)}|{scanned_domain}|{scan_id}".encode("utf-8", "ignore")
                ).hexdigest()[:16]
                local_evidence.append({
                    "evidence_id": evidence_id,
                    "provider": "urlscan.io",
                    "source_type": "urlscan_historical_scan",
                    "content_status": "historical_scan_record",
                    "evidence_type": "automated_scanner_observation",
                    "claim_status": "historical_scanner_observation",
                    "identity_match": "exact_domain_historical_scan_match" if target.get("kind") == "domain" and scanned_domain == normalize_domain(str(target.get("identifier") or "")) else "seller_published_external_domain_historical_scan",
                    "target_identifier": _clean_text(target.get("identifier"), 120),
                    "related_domain": scanned_domain,
                    "linked_from_evidence_id": parent_evidence_id,
                    "title": title,
                    "snippet": snippet,
                    "url": _safe_http_url(scan.get("result_url")) or f"https://urlscan.io/result/{scan_id}/",
                    "collected_at": _now(),
                    "scan_date": scan_date,
                    "scan_id": scan_id,
                    "malicious_verdict": malicious,
                    "verdict_score": scan.get("verdict_score"),
                    "redirected": _clean_text(scan.get("redirected"), 50),
                    "visibility": _clean_text(scan.get("visibility"), 20),
                    "verified": False,
                })

        # Provider records cached separately by exact public target, never by user/session.
        if local_evidence or local_map_candidates or any(p.get("status") in {"checked", "checked_no_match"} for p in local_providers):
            _cache_set(cache_key, {"evidence": _dedupe_evidence(local_evidence), "providers": local_providers,
                                   "map_candidates": local_map_candidates,
                                   "domain_infrastructure": local_domain_infrastructure}, ttl)
        all_evidence.extend(local_evidence)
        all_map_candidates.extend(local_map_candidates)
        result["domain_infrastructure"].extend(local_domain_infrastructure)
        result["providers"].extend(local_providers)

    result["evidence"] = _dedupe_evidence(all_evidence)
    if result["category"] == "shop":
        map_status = "checked" if "checked" in map_statuses else "checked_no_match" if map_statuses and set(map_statuses) <= {"checked_no_match", "not_found"} else "not_configured" if "not_configured" in map_statuses else "failed" if map_statuses else "not_checked"
        result["shop_discovery"] = build_shop_discovery(result["evidence"], safe_targets, all_map_candidates, map_status)
    result["evidence_graph"] = build_evidence_graph(safe_targets, result["evidence"], shop_discovery=result.get("shop_discovery"))
    result["red_flags"].extend(detect_evidence_flags(result["category"], result["evidence"]))
    result["red_flags"].extend(detect_cross_source_flags(result["evidence"]))

    # Kenya-specific official verification is linked as a manual, authoritative
    # workflow. No private registry endpoint is scraped and no registration is
    # described as checked unless a separate authorized source returns a record.
    if result["category"] in {"job", "shop"}:
        result["official_registry_checks"].append({
            "registry": "Business Registration Service (BRS)",
            "status": "manual_verification_required",
            "automated_lookup_performed": False,
            "official_portal_url": "https://brs.ecitizen.go.ke/",
            "what_to_verify": [
                "Search the exact legal or registered business name through the official BRS/eCitizen service.",
                "Where appropriate, obtain an official search or company record and compare the registration number and current status.",
                "Compare the record with the seller's claimed legal identity; a similar name is not an identity match.",
            ],
            "interpretation_note": "A registration record does not prove that a social account or website is operated by that business, nor that a particular offer is genuine.",
        })
    if result["category"] == "job":
        result["official_registry_checks"].append({
            "registry": "National Employment Authority (NEA)",
            "status": "manual_verification_required",
            "automated_lookup_performed": False,
            "official_portal_url": "https://www.diaspora.go.ke/verify",
            "what_to_verify": [
                "Search the exact recruitment agency name or licence details on the official NEA verification portal.",
                "Check the displayed licence status and validity period on the date you perform the lookup.",
                "Independently confirm the vacancy and employer using contact details obtained from the employer's own official website.",
            ],
            "interpretation_note": "A listed agency licence does not verify every job advertisement or prove that a person contacting you represents that agency.",
        })

    if result["category"] == "job":
        result["advice"] = [
            "Do not provide an email password, OTP, M-PESA PIN or account recovery code to a recruiter.",
            "Verify the recruiter through Kenya's official National Employment Authority channels and obtain the employer's legal name and vacancy details.",
            "Check the actual employer, written contract, work location and applicable US visa/work-authorisation route independently.",
            "Do not pay an unexplained recruitment, registration, medical or processing fee before verifying the agency and legal basis.",
        ]
    elif result["category"] == "shop":
        result["advice"] = [
            "Confirm that public complaints refer to this exact profile, website or payment identity; similar names may belong to different sellers.",
            "Verify the payment recipient, written order terms, delivery arrangements and refund process independently before paying.",
            "Keep order messages, receipts and screenshots. Do not share PINs or OTPs.",
        ]
    elif result["category"] == "grant":
        result["advice"] = [
            "Find the programme on the responsible organisation's official website using contact details you obtain independently.",
            "Do not pay an unexplained release, registration or facilitation fee, and never share account credentials or OTPs.",
        ]
    elif result["category"] == "payment":
        result["advice"] = [
            "Check the transaction in your own official payment history; do not rely on a screenshot or incoming message alone.",
            "Never disclose your M-PESA PIN or OTP. Contact the provider using its independently obtained official channel.",
        ]
    else:
        result["advice"] = [
            "Do not enter passwords, PINs, OTPs or payment details into an unsolicited link.",
            "Verify the organisation and claim through independently obtained official contact details.",
        ]

    if result["category"] == "job" and any(flag.get("code") in {"JOB_EMAIL_PASSWORD_REQUEST", "REPORTED_JOB_CREDENTIAL_HARVESTING"} for flag in result["red_flags"]):
        result["advice"] = [
            "Do not enter an email password, OTP or account recovery code on the application page.",
            "If you already entered your email password, change it through the email provider's official website, review signed-in devices/sessions, remove unfamiliar app access and enable two-step verification.",
            "Do not pay application, registration, medical or processing fees until the employer and recruiter are independently verified.",
            "Ask for the employer's legal name, exact vacancy, written job description, salary, location and recruiter details; verify the agency through Kenya's official National Employment Authority channels.",
            "For a US job, independently establish the employer and the relevant work-authorisation route before sharing identity documents.",
        ]

    if not result["evidence"]:
        result["limitations"].append("No target-matched public social or web evidence was retrieved. This is not proof that the target is safe or fraudulent.")
    if any(p.get("status") in {"not_configured", "failed"} for p in result["providers"]):
        result["limitations"].append("Some external checks were unavailable; the live profile was not independently inspected.")
    seen_manual: set[str] = set()
    for provider in result["providers"]:
        query = _clean_text(provider.get("query") or "", 240)
        manual_url = _safe_http_url(provider.get("manual_search_url")) or (manual_search_url(query) if query else None)
        if manual_url and manual_url not in seen_manual:
            seen_manual.add(manual_url)
            result["manual_searches"].append({
                "label": f"Search the web for {provider.get('searched_identifier') or provider.get('query') or 'this target'}",
                "url": manual_url,
                "identifier": _clean_text(provider.get("searched_identifier") or "", 120),
            })

    result["summary"] = (
        f"Collected {len(result['evidence'])} target-matched public evidence item(s) from "
        f"{len({e.get('provider') for e in result['evidence']})} provider(s). Public reports remain allegations until verified."
    )
    return result
