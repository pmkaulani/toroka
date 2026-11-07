"""Marketplace identification and conservative listing-signal extraction.

This module does not bypass marketplace access controls. It only identifies known
marketplace hosts and interprets product data already exposed by a safe page fetch.
"""
from __future__ import annotations

import re
from urllib.parse import urlsplit
from typing import Any

# Exact registrable hostnames. Subdomains are accepted only as true DNS suffixes.
_MARKETPLACES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("Jumia", ("jumia.co.ke", "jumia.com", "jumia.com.ng", "jumia.ug", "jumia.com.gh", "jumia.dz", "jumia.ma", "jumia.ci", "jumia.sn", "jumia.com.eg", "jumia.com.tn")),
    ("Kilimall", ("kilimall.co.ke", "kilimall.com")),
    ("Jiji", ("jiji.co.ke", "jiji.ng", "jiji.ug", "jiji.com")),
    ("Masoko", ("masoko.com",)),
    ("Pigiame", ("pigiame.co.ke",)),
    ("Amazon", ("amazon.com", "amazon.co.uk", "amazon.de", "amazon.fr", "amazon.it", "amazon.es", "amazon.ae", "amazon.in")),
    ("eBay", ("ebay.com", "ebay.co.uk", "ebay.de", "ebay.com.au")),
    ("AliExpress", ("aliexpress.com",)),
    ("Temu", ("temu.com",)),
    ("SHEIN", ("shein.com",)),
)


def identify_marketplace(url: str) -> dict[str, Any]:
    """Return marketplace context without asserting the seller or listing is safe."""
    try:
        host = (urlsplit(url if "://" in url else "https://" + url).hostname or "").lower().rstrip(".")
    except ValueError:
        host = ""
    for name, domains in _MARKETPLACES:
        for domain in domains:
            if host == domain or host.endswith("." + domain):
                return {
                    "is_marketplace": True,
                    "name": name,
                    "host": host,
                    "registered_domain": domain,
                    "product_detected": False,
                    "product_extraction_status": "not_attempted",
                    "seller_detected": False,
                    "seller_verification": "not_verified",
                }
    return {
        "is_marketplace": False,
        "name": None,
        "host": host,
        "registered_domain": None,
        "product_detected": False,
        "product_extraction_status": "not_applicable",
        "seller_detected": False,
        "seller_verification": "not_verified",
    }


def _text(value: Any, limit: int = 240) -> str | None:
    if value is None:
        return None
    if isinstance(value, dict):
        value = value.get("name") or value.get("@value") or value.get("url")
    if isinstance(value, (list, tuple)):
        value = next((x for x in value if x), None)
    if value is None:
        return None
    value = re.sub(r"\s+", " ", str(value)).strip()
    return value[:limit] if value else None


def _number(value: Any) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        # JSON-LD normally uses a decimal string or number.
        result = float(str(value).replace(",", "").strip())
        return result if 0 <= result < 1_000_000_000 else None
    except (TypeError, ValueError):
        return None


def normalize_product_data(raw: dict[str, Any] | None) -> dict[str, Any]:
    """Reduce an extractor result to a small, safe, serialisable public data shape."""
    raw = raw if isinstance(raw, dict) else {}
    price = _number(raw.get("price"))
    rating = _number(raw.get("seller_rating"))
    aggregate_rating = _number(raw.get("aggregate_rating"))
    rating_count = _number(raw.get("rating_count"))
    review_count = _number(raw.get("review_count"))
    images = []
    for image in raw.get("images") or []:
        candidate = _text(image, 800)
        if candidate and candidate.startswith("https://") and candidate not in images:
            images.append(candidate)
        if len(images) >= 3:
            break
    reviews = []
    for review in raw.get("review_excerpts") or []:
        candidate = _text(review, 240)
        if candidate and candidate not in reviews:
            reviews.append(candidate)
        if len(reviews) >= 3:
            break
    return {
        "detected": bool(raw.get("detected")),
        "extraction_status": str(raw.get("extraction_status") or "not_detected"),
        "method": str(raw.get("method") or "none"),
        "name": _text(raw.get("name"), 180),
        "description": _text(raw.get("description"), 600),
        "brand": _text(raw.get("brand"), 100),
        "sku": _text(raw.get("sku"), 80),
        "category": _text(raw.get("category"), 100),
        "price": price,
        "currency": _text(raw.get("currency"), 8),
        "availability": _text(raw.get("availability"), 80),
        "seller_name": _text(raw.get("seller_name"), 140),
        "seller_rating": rating,
        "aggregate_rating": aggregate_rating,
        "rating_count": int(rating_count) if rating_count is not None else None,
        "review_count": int(review_count) if review_count is not None else None,
        "images": images,
        "review_excerpts": reviews,
        "canonical_url": _text(raw.get("canonical_url"), 1000),
        "delivery_terms_found": bool(raw.get("delivery_terms_found")),
        "return_terms_found": bool(raw.get("return_terms_found")),
    }
