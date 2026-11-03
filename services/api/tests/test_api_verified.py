"""Verified sites and shops: only reviewed, dated, revocable records can produce a 'verified' result, and it never hides a warning."""
import pytest
from app import db as m
from sqlalchemy import select

SHOP = {"id": "mama-mboga", "name": "Mama Mboga Shop", "entity_type": "online_shop", "domains": ["mamamboga.co.ke"], "handles": ["instagram:mama_mboga_ke"], "basis": "moderator_verified_documents",
        "evidence_note": "Business registration certificate and the till name matched the shop name.", "source_url": "https://example.org/proof/mama-mboga", "last_verified_at": "2026-10-20", "reviewer": "A. Reviewer"}


def labels(env, text):
    a = env.check(text)["assessment"]; return a["label"], a


def test_seeded_unreviewed_official_sites_are_not_presented_as_verified(env):
    label, a = labels(env, "Is https://www.safaricom.co.ke/fraud-awareness a real website?")
    assert label != "verified_official"
    assert not a.get("verified")
    assert not any(f.get("code") == "VERIFIED_OFFICIAL_SITE" for f in a.get("findings", []))


def test_public_list_excludes_unreviewed_seed_candidates(env):
    v = env.client.get("/v1/verified-entities").json()["verified"]
    assert "org-safaricom" not in {x["id"] for x in v}
    assert "org-kra" not in {x["id"] for x in v}
    assert all(x["last_verified_at"] and x["review_due"] and "does not prove every offer" in x["note"] for x in v)
    assert all("evidence_note" not in x and "reviewer" not in x for x in v)


def test_only_moderators_add_records_and_the_rules_are_strict(env):
    assert env.client.put("/v1/admin/verified-entities", json=SHOP).status_code == 401
    user, _ = env.user("plain@example.com"); assert env.client.put("/v1/admin/verified-entities", json=SHOP, headers=user).status_code == 403
    mod, _ = env.user("mod@example.com", "moderator"); put = lambda **kw: env.client.put("/v1/admin/verified-entities", json={**SHOP, **kw}, headers=mod)
    assert put(domains=["mamamboga.vercel.app"]).status_code == 422 and put(domains=["facebook.com"]).status_code == 422 and put(domains=["co.ke"]).status_code == 422 and put(domains=["203.0.113.5"]).status_code == 422
    assert put(domains=["xn--mama-6q1a.co.ke"]).status_code == 422 and put(domains=[], handles=[]).status_code == 422 and put(handles=["myspace:mama"]).status_code == 422
    assert put(evidence_note="ok").status_code == 422 and put(source_url="http://example.org/x").status_code == 422
    r = put(); assert r.status_code == 200 and r.json()["review_due"] == "2027-04-18" and r.json()["domains"] == ["mamamboga.co.ke"]
    with env.db() as db:
        assert db.execute(select(m.AuditEvent).where(m.AuditEvent.action == "verified.upsert")).scalars().first()


def test_verified_shop_site_and_handle_then_revoked_then_expired(env):
    mod, _ = env.user("mod@example.com", "moderator"); env.client.put("/v1/admin/verified-entities", json=SHOP, headers=mod)
    assert labels(env, "Our shop is https://www.mamamboga.co.ke, order there")[0] == "verified_official"
    assert labels(env, "Selling on Instagram @mama_mboga_ke, pay on delivery in Nairobi")[0] == "verified_official"
    assert labels(env, "Selling on Instagram @mama_mboga_ke2, pay on delivery in Nairobi")[0] != "verified_official"
    assert labels(env, "See https://mamamboga.co.ke.evil.example.com/shop")[0] != "verified_official"
    # a deposit request in the name of a verified shop still gets a warning first
    label, a = labels(env, "Pay half now to reserve, details at https://www.mamamboga.co.ke/order")
    assert label == "suspicious_verify_first" and a["findings"][0]["polarity"] == "risk" and any(f["code"] == "VERIFIED_OFFICIAL_SITE" for f in a["findings"])
    assert env.client.post("/v1/moderation/verified-entities/mama-mboga/revoke", json={"reason_code": "complaints"}, headers=mod).json()["status"] == "revoked"
    assert labels(env, "Our shop is https://www.mamamboga.co.ke, order there")[0] != "verified_official"
    assert "mama-mboga" not in {x["id"] for x in env.client.get("/v1/verified-entities").json()["verified"]}
    old = {**SHOP, "last_verified_at": "2025-01-01", "review_interval_days": 30}
    env.client.put("/v1/admin/verified-entities", json=old, headers=mod)
    label, a = labels(env, "Our shop is https://www.mamamboga.co.ke, order there"); assert label != "verified_official" and "verified:mama-mboga" in a["stale_sources"]


def test_revocation_needs_a_moderator_and_a_reason(env):
    assert env.client.post("/v1/moderation/verified-entities/org-kra/revoke", json={"reason_code": "x"}).status_code == 401
    mod, _ = env.user("mod@example.com", "moderator")
    assert env.client.post("/v1/moderation/verified-entities/org-kra/revoke", json={}, headers=mod).status_code == 422


def test_verified_site_never_excuses_a_pin_request_over_the_api(env):
    assert labels(env, "Safaricom says send your PIN at https://www.safaricom.co.ke to unlock")[0] == "high_risk"


def test_swahili_verified_result_requires_a_reviewed_record(env):
    # Seed rows are explicitly marked unreviewed; an authenticated moderator must
    # review the domain before the UI can say it is verified.
    moderator, _ = env.user("sw-verified-mod@example.com", "moderator")
    body = {"id": "org-safaricom", "name": "Safaricom", "entity_type": "organisation", "domains": ["safaricom.co.ke"],
            "handles": ["instagram:safaricomplc"], "basis": "official_registry", "source_url": "https://www.safaricom.co.ke/fraud-awareness",
            "last_verified_at": "2026-10-20", "review_interval_days": 180, "reviewer": "client-supplied-reviewer"}
    assert env.client.put("/v1/admin/verified-entities", json=body, headers=moderator).status_code == 200
    a = env.check("Is https://www.safaricom.co.ke genuine?", language="sw")["assessment"]
    assert a["label_text"] == "Imethibitishwa" and "Thibitisha ofa husika" in a["summary"]
