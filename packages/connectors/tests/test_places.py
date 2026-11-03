import httpx
import pytest

from ssi_connectors.places import search_places


def test_search_places_not_configured_when_no_api_key():
    res = search_places("", "Nairobi Electronics")
    assert res["status"] == "not_configured"
    assert res["results_retrieved"] == 0
    assert res["places"] == []


def test_search_places_not_checked_when_empty_query():
    res = search_places("test-key", "   ")
    assert res["status"] == "not_checked"
    assert res["results_retrieved"] == 0
    assert res["places"] == []


def test_search_places_successful_results():
    seen = {}

    def handler(request: httpx.Request):
        seen["url"] = str(request.url)
        seen["key"] = request.headers.get("X-Goog-Api-Key")
        seen["mask"] = request.headers.get("X-Goog-FieldMask")
        return httpx.Response(200, json={
            "places": [
                {
                    "id": "places/ChIJ12345",
                    "displayName": {"text": "Nairobi Menswear Shop"},
                    "formattedAddress": "Moi Avenue, Nairobi, Kenya",
                    "googleMapsUri": "https://maps.google.com/?cid=12345",
                    "websiteUri": "https://nairobimenswear.example",
                    "nationalPhoneNumber": "0712345678",
                    "businessStatus": "OPERATIONAL",
                    "location": {"latitude": -1.28333, "longitude": 36.81667},
                }
            ]
        })

    result = search_places("test-google-key", "Nairobi Menswear Moi Avenue Kenya", transport=httpx.MockTransport(handler))
    assert result["status"] == "checked"
    assert result["results_retrieved"] == 1
    assert seen["key"] == "test-google-key"
    assert "places.displayName" in seen["mask"]
    place = result["places"][0]
    assert place["name"] == "Nairobi Menswear Shop"
    assert place["address"] == "Moi Avenue, Nairobi, Kenya"
    assert place["maps_url"] == "https://maps.google.com/?cid=12345"
    assert place["website_url"] == "https://nairobimenswear.example"
    assert place["phone"] == "0712345678"
    assert place["business_status"] == "operational"


def test_search_places_no_match():
    def handler(request: httpx.Request):
        return httpx.Response(200, json={"places": []})

    result = search_places("test-google-key", "NonExistentStore123 Nairobi", transport=httpx.MockTransport(handler))
    assert result["status"] == "checked_no_match"
    assert result["results_retrieved"] == 0
    assert result["places"] == []


def test_search_places_http_error():
    def handler(request: httpx.Request):
        return httpx.Response(403, json={"error": {"message": "The provided API key is invalid."}})

    result = search_places("bad-key", "Store Nairobi", transport=httpx.MockTransport(handler))
    assert result["status"] == "failed"
    assert result["failure_reason"] == "http_403"
