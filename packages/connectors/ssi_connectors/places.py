"""Google Places API (New) shop-location candidate connector.

Searches Google Places Text Search (New) for candidate business listings
matching a public seller name and location context. Candidate results are
corroborating hints only; they never prove identity or ownership.
"""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit

import httpx

PLACES_TEXT_SEARCH_URL = "https://places.googleapis.com/v1/places:searchText"
_FIELD_MASK = (
    "places.id,places.displayName,places.formattedAddress,"
    "places.websiteUri,places.nationalPhoneNumber,places.googleMapsUri,"
    "places.businessStatus,places.location"
)


def _safe_url(raw: Any) -> str | None:
    if not isinstance(raw, str):
        return None
    val = raw.strip()
    if not val:
        return None
    try:
        parts = urlsplit(val)
        if parts.scheme in {"http", "https"} and parts.netloc:
            return val
    except Exception:
        pass
    return None


def search_places(
    api_key: str,
    query: str,
    *,
    transport: httpx.BaseTransport | None = None,
    timeout: float = 6.0,
    size: int = 5,
) -> dict[str, Any]:
    """Search Google Places for business listings matching a query string."""
    clean_query = str(query or "").strip()
    if not api_key:
        return {
            "status": "not_configured",
            "provider": "Google Places",
            "detail": "GOOGLE_PLACES_API_KEY is not configured; shop location candidates were not searched.",
            "places": [],
            "results_retrieved": 0,
            "query": clean_query,
        }
    if not clean_query:
        return {
            "status": "not_checked",
            "provider": "Google Places",
            "detail": "No usable query was supplied for a shop location search.",
            "places": [],
            "results_retrieved": 0,
            "query": "",
        }

    headers = {
        "X-Goog-Api-Key": api_key,
        "X-Goog-FieldMask": _FIELD_MASK,
        "Content-Type": "application/json",
    }
    payload = {
        "textQuery": clean_query,
        "languageCode": "en",
        "pageSize": max(1, min(int(size), 5)),
    }

    try:
        with httpx.Client(transport=transport, timeout=timeout) as client:
            resp = client.post(PLACES_TEXT_SEARCH_URL, headers=headers, json=payload)
            resp.raise_for_status()
            data = resp.json()
    except httpx.HTTPStatusError as exc:
        code = exc.response.status_code
        return {
            "status": "failed",
            "provider": "Google Places",
            "failure_reason": f"http_{code}",
            "detail": f"Google Places search returned HTTP {code}.",
            "places": [],
            "results_retrieved": 0,
            "query": clean_query,
        }
    except Exception as exc:
        return {
            "status": "failed",
            "provider": "Google Places",
            "failure_reason": type(exc).__name__.lower(),
            "detail": "The Google Places directory lookup timed out or failed.",
            "places": [],
            "results_retrieved": 0,
            "query": clean_query,
        }

    raw_places = data.get("places") if isinstance(data, dict) else []
    if not isinstance(raw_places, list):
        raw_places = []

    places = []
    for item in raw_places[:5]:
        if not isinstance(item, dict):
            continue
        display_name = item.get("displayName")
        name = ""
        if isinstance(display_name, dict):
            name = str(display_name.get("text") or "").strip()
        elif isinstance(display_name, str):
            name = display_name.strip()
        if not name:
            name = str(item.get("name") or "").strip()

        address = str(item.get("formattedAddress") or "").strip()
        maps_url = _safe_url(item.get("googleMapsUri"))
        website_url = _safe_url(item.get("websiteUri"))
        phone = str(item.get("nationalPhoneNumber") or "").strip() or None
        status = str(item.get("businessStatus") or "unknown").strip().lower()
        place_id = str(item.get("id") or "").strip()
        location = item.get("location") if isinstance(item.get("location"), dict) else None

        places.append({
            "place_id": place_id,
            "name": name,
            "address": address,
            "maps_url": maps_url,
            "website_url": website_url,
            "phone": phone,
            "business_status": status,
            "location": location,
        })

    retrieved = len(places)
    if retrieved == 0:
        return {
            "status": "checked_no_match",
            "provider": "Google Places",
            "detail": "No matching business listings were found on Google Maps for this query.",
            "places": [],
            "results_retrieved": 0,
            "query": clean_query,
        }

    return {
        "status": "checked",
        "provider": "Google Places",
        "detail": f"Found {retrieved} candidate business listing(s) on Google Maps.",
        "places": places,
        "results_retrieved": retrieved,
        "query": clean_query,
    }
