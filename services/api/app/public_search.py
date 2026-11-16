"""Optional public-web search for public identifiers only.

Search results are unverified leads. This module never sends raw private message text,
phone numbers, PINs, OTPs, or screenshots to the search provider.
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote_plus, urlsplit

import httpx

logger = logging.getLogger("toroka.public_search")


def manual_search_url(query: str) -> str | None:
    """Build a user-clicked public search link from an already-minimised query."""
    clean = " ".join((query or "").split())[:300]
    if not clean:
        return None
    return "https://www.google.com/search?q=" + quote_plus(clean)


def public_search(query: str, api_key: str, max_results: int = 5) -> dict[str, Any]:
    query = " ".join((query or "").split())[:300]
    now_iso = datetime.now(timezone.utc).isoformat()
    if not query:
        return {
            "status": "not_checked",
            "provider": "Tavily",
            "query": "",
            "detail": "No public identifier was available to search.",
            "results": [],
            "results_retrieved": 0,
            "manual_search_url": None,
            "checked_at": now_iso,
        }
    manual_url = manual_search_url(query)
    if not api_key:
        return {
            "status": "not_checked",
            "provider": "Tavily",
            "query": query,
            "detail": "Toroka did not perform live web search because TAVILY_API_KEY is not configured. You can open a manual web search; results will not have been checked by Toroka.",
            "results": [],
            "results_retrieved": 0,
            "manual_search_url": manual_url,
            "checked_at": now_iso,
        }
    payload = {"api_key": api_key, "query": query, "search_depth": "basic", "topic": "general", "max_results": max(1, min(max_results, 5)), "include_answer": False, "include_raw_content": False}
    try:
        with httpx.Client(timeout=4.0, follow_redirects=False) as client:
            response = client.post("https://api.tavily.com/search", json=payload)
            response.raise_for_status()
            data = response.json()
        results: list[dict[str, str]] = []
        for item in data.get("results", [])[:max_results]:
            url = str(item.get("url", "")).strip()
            parts = urlsplit(url)
            if parts.scheme not in ("http", "https") or not parts.netloc:
                continue
            results.append({
                "title": str(item.get("title", ""))[:240],
                "url": url[:1500],
                "snippet": str(item.get("content", ""))[:1000],
                "published_date": str(item.get("published_date") or "")[:60],
                "source_type": "public_search_lead",
            })
        if results:
            return {
                "status": "checked",
                "provider": "Tavily",
                "query": query,
                "detail": f"Public search returned {len(results)} result(s). These are leads and have not been independently verified.",
                "results": results,
                "results_retrieved": len(results),
                "manual_search_url": manual_url,
                "checked_at": datetime.now(timezone.utc).isoformat(),
            }
        return {
            "status": "checked_no_match",
            "provider": "Tavily",
            "query": query,
            "detail": "The search provider returned no matching results for this identifier. No results is not proof of safety or fraud.",
            "results": [],
            "results_retrieved": 0,
            "manual_search_url": manual_url,
            "checked_at": datetime.now(timezone.utc).isoformat(),
        }
    except Exception as exc:
        logger.warning("Public web search failed: %s", type(exc).__name__)
        return {
            "status": "failed",
            "provider": "Tavily",
            "query": query,
            "detail": f"The public search service could not be reached ({type(exc).__name__}). No conclusion was drawn from this failure.",
            "results": [],
            "results_retrieved": 0,
            "manual_search_url": manual_url,
            "checked_at": datetime.now(timezone.utc).isoformat(),
            "failure_reason": type(exc).__name__,
        }


# Search engines return a mixture of exact-entity mentions, general safety articles,
# and unrelated lookalike results. Only entity-relevant results should be attached to
# an investigation as leads; general background must never be treated as evidence.
_PLATFORM_HOSTS = {
    "instagram": {"instagram.com", "www.instagram.com"},
    "tiktok": {"tiktok.com", "www.tiktok.com", "m.tiktok.com"},
    "facebook": {"facebook.com", "www.facebook.com", "m.facebook.com"},
    "x": {"x.com", "www.x.com", "twitter.com", "www.twitter.com"},
    "twitter": {"x.com", "www.x.com", "twitter.com", "www.twitter.com"},
}
_BACKGROUND_TERMS = re.compile(
    r"(?i)\b(?:how to spot|how to avoid|tips to avoid|safety guide|scam awareness|"
    r"instagram scams|seller scams|online shopping safety|protect yourself from scams|"
    r"avoid fake pages|red flags to watch|beware of fake|watch out for fake|please be cautious|"
    r"fraud alert|scam alert)\b"
)
_CLAIM_TERMS = re.compile(
    r"(?i)\b(?:scam|scammer|fraud|fraudulent|complaint|complaints|non.delivery|never arrived|"
    r"not delivered|took my money|stole|impersonat|fake shop|refund refused|warning against)\b"
)


def _normalised_search_text(value: str) -> str:
    # Search snippets sometimes escape underscores for Markdown (base\\_menswear).
    import html
    raw = html.unescape(str(value or "")).replace("\\_", "_").replace("\\.", ".")
    return " ".join(re.findall(r"[a-z0-9]+", raw.casefold()))


def _contains_entity_phrase(value: str, identifier: str) -> bool:
    needle = _normalised_search_text(identifier.lstrip("@"))
    haystack = _normalised_search_text(value)
    if not needle:
        return False
    # Phrase matching on normalised tokens tolerates punctuation/escaped underscores
    # without conflating a different identifier such as baseusclothing.
    return f" {needle} " in f" {haystack} "


def classify_search_result_relevance(
    result: dict[str, Any],
    *,
    identifier: str,
    kind: str = "handle",
    platform: str | None = None,
    target_url: str | None = None,
) -> dict[str, str | bool]:
    """Classify a public search result without treating a name mention as proof.

    Returns relevance metadata: exact_entity, entity_mention, domain_reference,
    background, or irrelevant. Only the first three are eligible for the main
    investigation source list, and even those remain unverified search leads.
    """
    url = str(result.get("url", "") or "").strip()
    title = str(result.get("title", "") or "")
    snippet = str(result.get("snippet", result.get("content", "") or "") or "")
    combined = f"{title} {snippet} {url}"
    host = (urlsplit(url).hostname or "").casefold().rstrip(".")
    path_parts = [part.casefold() for part in urlsplit(url).path.split("/") if part]
    ident = identifier.lstrip("@").strip()
    platform_key = (platform or "").casefold()

    target_host = (urlsplit(target_url).hostname or "").casefold().rstrip(".") if target_url else ""
    if kind == "domain":
        target_domain = ident.casefold().removeprefix("www.")
        target_host_matches = host == target_domain or host.endswith("." + target_domain)
        domain_phrase = _contains_entity_phrase(combined, target_domain)
        if target_host_matches or domain_phrase:
            claim_context = any(
                _CLAIM_TERMS.search(part) and _contains_entity_phrase(part, target_domain)
                for part in (title, snippet)
            )
            return {"relevance": "exact_entity", "relevant": True, "background": False,
                    "relevance_reason": "The result URL or content refers to the exact target domain.",
                    "claim_signal": bool(claim_context)}
    else:
        # Exact profile URLs are stronger entity identity matches than a text mention.
        platform_hosts = _PLATFORM_HOSTS.get(platform_key, set())
        if host in platform_hosts and path_parts and path_parts[0].lstrip("@") == ident.casefold():
            claim_context = any(
                _CLAIM_TERMS.search(part) and _contains_entity_phrase(part, ident)
                for part in (title, snippet)
            )
            return {"relevance": "exact_entity", "relevant": True, "background": False,
                    "relevance_reason": "The result URL resolves to the exact platform profile path.",
                    "claim_signal": bool(claim_context)}
        # For profile posts/reels, an exact handle in the title/snippet is an entity
        # reference, but not proof of a complaint or of wrongdoing.
        if _contains_entity_phrase(f"{title} {snippet}", ident):
            claim_context = any(
                _CLAIM_TERMS.search(part) and _contains_entity_phrase(part, ident)
                for part in (title, snippet)
            )
            return {"relevance": "entity_mention", "relevant": True, "background": False,
                    "relevance_reason": "The title or snippet mentions the exact handle; the claim still needs source inspection.",
                    "claim_signal": bool(claim_context)}

    if _BACKGROUND_TERMS.search(combined) and (not platform_key or platform_key in _normalised_search_text(combined)):
        return {"relevance": "background", "relevant": False, "background": True,
                "relevance_reason": "General safety information; it does not identify the exact target.",
                "claim_signal": False}
    return {"relevance": "irrelevant", "relevant": False, "background": False,
            "relevance_reason": "No exact identity, target domain, or supported relationship to the target was found.",
            "claim_signal": False}


def filter_public_search_results(
    results: list[dict[str, Any]],
    *,
    identifier: str,
    kind: str = "handle",
    platform: str | None = None,
    target_url: str | None = None,
) -> dict[str, Any]:
    """Keep entity-related search leads separate from generic background/irrelevant hits."""
    relevant: list[dict[str, Any]] = []
    background: list[dict[str, Any]] = []
    irrelevant_count = 0
    for item in results or []:
        if not isinstance(item, dict):
            continue
        meta = classify_search_result_relevance(
            item, identifier=identifier, kind=kind, platform=platform, target_url=target_url
        )
        enriched = {**item, **meta}
        if meta["relevant"]:
            relevant.append(enriched)
        elif meta["background"]:
            background.append(enriched)
        else:
            irrelevant_count += 1
    return {
        "relevant_results": relevant,
        "background_results": background,
        "raw_result_count": len(results or []),
        "relevant_count": len(relevant),
        "background_count": len(background),
        "irrelevant_count": irrelevant_count,
    }


def evaluate_search_relevance(
    item: dict[str, str],
    *,
    platform: str | None = None,
    handle: str | None = None,
    canonical_url: str | None = None,
    domain: str | None = None,
    verified_aliases: list[str] | None = None,
    linked_domains: list[str] | None = None,
) -> dict[str, Any]:
    """Calculate and record whether a search result matches:
    - The exact profile URL.
    - The exact platform and username.
    - A known verified alias.
    - A reliably linked business domain.
    - A specific incident or payment identifier with evidence of a relationship.

    Separates into 4 mutually exclusive categories:
    1. direct_evidence: Directly about the exact entity.
    2. related_evidence: Credible evidence about a demonstrably related entity.
    3. general_background: General educational, awareness, or market guidance.
    4. irrelevant: Different business, unrelated website, or noisy substring match.
    """
    raw_url = str(item.get("url") or "").strip()
    u = raw_url.lower()
    title = str(item.get("title") or "")
    snippet = str(item.get("snippet") or "")
    combined = f"{title} {snippet}"
    combined_lower = combined.lower()

    # 1. Exact profile URL match
    if canonical_url and u:
        norm_res_url = u.split("?")[0].rstrip("/")
        norm_can_url = canonical_url.lower().split("?")[0].rstrip("/")
        if norm_res_url == norm_can_url:
            return {
                "category": "direct_evidence",
                "reason": f"Exact canonical profile URL match: {canonical_url}",
                "is_entity_match": True,
            }

    # 2. Platform + Handle match
    if platform and handle:
        h_clean = handle.lower().lstrip("@").strip()
        # Direct URL match on the same platform
        if f"{platform.lower()}.com/{h_clean}" in u or f"{platform.lower()}.com/@{h_clean}" in u:
            return {
                "category": "direct_evidence",
                "reason": f"Exact profile handle @{handle} on {platform.capitalize()} URL",
                "is_entity_match": True,
            }

        # Check for unrelated domains that merely share a substring (e.g. baseusclothing.com for base_menswear)
        try:
            res_host = urlsplit(u).netloc.lower()
        except Exception:
            res_host = ""

        # Unrelated domain check: if domain has substring collisions but is a known distinct brand
        unrelated_domains = {"baseus", "growyourclothingbrand", "aliexpress", "amazon", "ebay", "shein"}
        if any(ud in res_host for ud in unrelated_domains) and not (f"@{h_clean}" in combined_lower or f"/{h_clean}" in u):
            if "growyourclothingbrand" in res_host or "how-to" in u or "safety" in u:
                return {
                    "category": "general_background",
                    "reason": "General advice or background guide; does not establish evidence about this account",
                    "is_entity_match": False,
                }
            return {
                "category": "irrelevant",
                "reason": f"Unrelated domain ({res_host}) with no verifiable link to @{handle}",
                "is_entity_match": False,
            }

        # Handle token search with word boundaries
        h_token_pattern = r"(?i)(?<![a-z0-9_])@" + re.escape(h_clean) + r"(?![a-z0-9_])"
        h_plain_pattern = r"(?i)(?<![a-z0-9_])" + re.escape(h_clean) + r"(?![a-z0-9_])"

        has_explicit_handle = bool(re.search(h_token_pattern, combined))
        has_plain_handle = bool(re.search(h_plain_pattern, combined))

        if has_explicit_handle:
            return {
                "category": "direct_evidence",
                "reason": f"Search result directly names @{handle}",
                "is_entity_match": True,
            }

        if has_plain_handle and any(w in combined_lower for w in [platform.lower(), "shop", "scam", "store", "seller", "review", "complaint", "kenya", "nairobi"]):
            return {
                "category": "direct_evidence",
                "reason": f"Search result names account handle '{h_clean}' in relevant shop/safety context",
                "is_entity_match": True,
            }

        # Decomposed handle match (e.g. "base menswear" for "base_menswear")
        if "_" in h_clean or "." in h_clean:
            spaced = h_clean.replace("_", " ").replace(".", " ")
            spaced_pattern = r"(?i)\b" + re.escape(spaced) + r"\b"
            if re.search(spaced_pattern, combined):
                # Ensure context matches shop/clothing/local commerce
                if any(w in combined_lower for w in ["shop", "clothing", "menswear", "store", "seller", "kenya", "nairobi", platform.lower()]):
                    return {
                        "category": "related_evidence",
                        "reason": f"Matches business name '{spaced}' in Kenyan commercial context",
                        "is_entity_match": True,
                    }

        # Linked domains or verified aliases
        if linked_domains and any(ld.lower() in u for ld in linked_domains):
            return {
                "category": "related_evidence",
                "reason": f"Matches linked business domain: {raw_url}",
                "is_entity_match": True,
            }

        if verified_aliases and any(va.lower() in combined_lower for va in verified_aliases):
            return {
                "category": "related_evidence",
                "reason": "Matches verified alias in official records",
                "is_entity_match": True,
            }

        # General scam warning / educational material
        general_indicators = [
            "grow your clothing brand", "how to avoid scams", "online shopping safety",
            "tips for buying safely", "scam awareness", "safe shopping", "buyer protection"
        ]
        if any(gi in combined_lower for gi in general_indicators):
            return {
                "category": "general_background",
                "reason": "General background or educational guide; does not establish facts about this account",
                "is_entity_match": False,
            }

        return {
            "category": "irrelevant",
            "reason": f"Search lead does not match @{handle} or a verified link",
            "is_entity_match": False,
        }

    # 3. Domain investigation (non-social)
    if domain:
        d_clean = domain.lower().replace("www.", "").strip()
        if d_clean in u or d_clean in combined_lower:
            return {
                "category": "direct_evidence",
                "reason": f"Direct match for domain {domain}",
                "is_entity_match": True,
            }
        return {
            "category": "irrelevant",
            "reason": f"Does not match domain {domain}",
            "is_entity_match": False,
        }

    return {
        "category": "irrelevant",
        "reason": "No matching target criteria",
        "is_entity_match": False,
    }


def find_public_identifiers(text: str, context_text: str = "", platform_hint: str | None = None) -> list[dict[str, str]]:
    """Extract public identifiers only, never submit the raw private message.

    Supports exact social URLs, @handles, domains, and explicit requests like
    "look into this store clothingctrl". Context is only used to extract public
    identifiers or infer one unambiguous platform; it is never sent verbatim.
    """
    current, context = text or "", context_text or ""
    out: list[dict[str, str]] = []
    seen: set[str] = set()
    valid_platforms = {"instagram", "tiktok", "facebook", "x", "twitter", "whatsapp"}
    reserved_handles = {
        "marketplace", "t", "share", "share_link", "reel", "reels", "p", "stories",
        "explore", "accounts", "login", "about", "help", "legal", "watch", "groups",
        "pages", "events", "photo", "video", "videos", "hashtag", "tag", "search",
        "discover", "foryou", "following", "live", "shop", "view", "i", "intent",
        "home", "settings", "privacy", "terms", "policies", "business", "directory",
        "gaming", "item", "items", "people",
    }

    def add(key: str, item: dict[str, str]) -> None:
        if key not in seen and len(out) < 4:
            out.append(item)
            seen.add(key)

    inferred_platform = (platform_hint or "").lower().strip()
    if inferred_platform not in valid_platforms:
        inferred_platform = ""
    if not inferred_platform:
        platform_matches = set()
        for source in (current, context):
            for found in re.findall(r"(?i)\b(instagram|tiktok|facebook|twitter|x\s*\(twitter\)|whatsapp)\b", source):
                platform = found.lower().replace(" ", "")
                if platform == "twitter" or platform.startswith("x("):
                    platform = "x"
                platform_matches.add(platform)
        if len(platform_matches) == 1:
            inferred_platform = next(iter(platform_matches))

    # Exact public social profile URLs.
    for m in re.finditer(r"(?i)(?<![a-z0-9.-])(?:https?://)?(?:www\.)?(instagram\.com|tiktok\.com|facebook\.com|x\.com|twitter\.com)/@?([a-z0-9_.]{3,35})", current):
        host = m.group(1).lower()
        platform = "x" if host in {"x.com", "twitter.com"} else host.split(".")[0]
        handle = m.group(2).rstrip(".")
        if handle.lower() in reserved_handles:
            continue
        add(f"handle:{platform}:{handle.lower()}", {"kind": "handle", "identifier": f"@{handle}", "platform": platform,
             "query": f'"{handle}" {platform} official profile shop seller reviews complaints Kenya'})

    # Bare @handles. If platform is ambiguous, search the main public platforms without assuming one.
    for m in re.finditer(r"(?<![\w.+-])@([a-zA-Z0-9_.]{3,35})\b", current):
        handle = m.group(1).rstrip(".")
        if handle.lower() in reserved_handles:
            continue
        if inferred_platform:
            platform, query = inferred_platform, f'"{handle}" {inferred_platform} shop seller profile reviews complaints Kenya'
            key = f"handle:{platform}:{handle.lower()}"
        else:
            platform, query = "not specified", f'"{handle}" Instagram TikTok Facebook shop seller profile reviews complaints Kenya'
            key = f"handle:any:{handle.lower()}"
        add(key, {"kind": "handle", "identifier": f"@{handle}", "platform": platform, "query": query})

    domain_pattern = re.compile(r'''(?i)(?<![@\w.-])(?:https?://)?(?:www\.)?([a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9-]+)*\.(?:co\.ke|go\.ke|or\.ke|ac\.ke|com|net|org|info|biz|xyz|shop|online|site|app|ke))(?:/[^\s<>"']*)?''')
    social_hosts = {
        "instagram.com", "tiktok.com", "facebook.com", "x.com", "twitter.com",
        "vm.tiktok.com", "vt.tiktok.com", "web.facebook.com", "m.facebook.com",
        "fb.com", "fb.me", "fb.watch", "instagr.am", "t.co", "wa.me",
    }
    for m in domain_pattern.finditer(current):
        domain = m.group(1).lower().strip(".")
        if domain in social_hosts:
            continue
        add(f"domain:{domain}", {"kind": "domain", "identifier": domain,
             "query": f'"{domain}" official terms operator licence regulator complaints scam Kenya'})

    # A shop name without @/URL is searchable only when an investigation verb and shop type appear.
    shop_query = re.compile(
        r"(?i)\b(?:look\s+into|investigate|check|verify|research|audit|kagua|chunguza|angalia|tazama)\s+"
        r"(?:(?:this|that|the|a|an)\s+)?(?:(?:instagram|insta|tiktok|facebook|social\s+media)\s+)?"
        r"(?:online\s+)?(?:shop|store|seller|vendor|page|account|brand|boutique)\s+@?([a-zA-Z0-9][a-zA-Z0-9._-]{2,50})\b"
    )
    excluded = {"this", "that", "shop", "store", "seller", "vendor", "page", "account", "brand", "me", "for", "please", "website", "link", "message", "sms"}
    for source in (current, context):
        for m in shop_query.finditer(source):
            name = m.group(1).rstrip(".,!?;:")
            if name.lower() in excluded or name.startswith(".") or name.endswith("."):
                continue
            if any(item.get("identifier", "").lstrip("@").lower() == name.lower() for item in out):
                continue
            add(f"shopname:{name.lower()}", {"kind": "shop_name", "identifier": name,
                 "platform": inferred_platform or "not specified",
                 "query": f'"{name}" online clothing shop seller Instagram TikTok Kenya reviews complaints scam'})

    return out[:3]
