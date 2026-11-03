from __future__ import annotations
import os
from ..models import InvestigationRequest, LocationMatch, utc_now
from ..normalize import normalize_phone, normalize_domain
from .http import post_json


class GooglePlacesProvider:
    """Find candidate public business listings. Results are never labelled official verification."""
    name = "Google Places"
    def __init__(self, api_key: str | None = None):
        self.api_key = api_key or os.getenv("GOOGLE_MAPS_API_KEY")
        self.is_configured = bool(self.api_key)

    def is_applicable(self, request: InvestigationRequest) -> bool:
        return bool((request.business_name or request.social_handle) and request.search_location)

    def find_locations(self, request: InvestigationRequest) -> list[LocationMatch]:
        query = request.business_name or (request.social_handle or "").lstrip("@").replace("_", " ").replace("-", " ")
        if not self.api_key or not query or not request.search_location:
            return []
        data = post_json(
            "https://places.googleapis.com/v1/places:searchText",
            {"textQuery": f"{query} {request.search_location}", "languageCode": "en"},
            {"X-Goog-Api-Key": self.api_key,
             "X-Goog-FieldMask": "places.id,places.displayName,places.formattedAddress,places.websiteUri,places.nationalPhoneNumber,places.googleMapsUri,places.businessStatus,places.location"}
        )
        results: list[LocationMatch] = []
        claimed_phone = normalize_phone(request.claimed_phone)
        for place in data.get("places", [])[:5]:
            found_phone = normalize_phone(place.get("nationalPhoneNumber"))
            website = place.get("websiteUri")
            phone_match = (claimed_phone == found_phone) if claimed_phone and found_phone else None
            website_match = None
            if website and request.claimed_website:
                website_match = normalize_domain(website) == normalize_domain(request.claimed_website)
            limitations = [
                "A Google Maps listing is a third-party directory result, not proof of legal registration or ownership.",
                "A listing can be stale, user-suggested, impersonated, or belong to a different business with a similar name.",
                "Re-check the listing live before relying on it; comply with Google Places attribution and caching rules."
            ]
            match_bits = []
            if phone_match is True: match_bits.append("phone matches")
            elif phone_match is False: match_bits.append("phone differs")
            if website_match is True: match_bits.append("website domain matches")
            elif website_match is False: match_bits.append("website domain differs")
            if not match_bits: match_bits.append("name-and-area candidate only")
            location = place.get("location") or {}
            results.append(LocationMatch(
                name=(place.get("displayName") or {}).get("text", query),
                address=place.get("formattedAddress", ""), source=self.name,
                source_url=place.get("googleMapsUri"), website_url=website,
                phone=place.get("nationalPhoneNumber"), place_id=place.get("id"),
                phone_match=phone_match, website_match=website_match,
                latitude=location.get("latitude"), longitude=location.get("longitude"),
                business_status=place.get("businessStatus"),
                match_summary="; ".join(match_bits),
                status="third_party_listing_unverified", checked_at=utc_now(), limitations=limitations
            ))
        return results
