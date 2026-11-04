import hashlib, hmac, io, json, os
import httpx
import pytest
from app import db as m
from app.pipeline import Deps
from conftest import Env, photo_like, png_with_text
from sqlalchemy import select
from ssi_connectors import channels, reputation, safe_fetch
from ssi_rules.vocabulary import CoverageStatus as CS

FEE = "You have a pending grant. Pay KSh 350 to activate funds."
PIN = "Safaricom: Your M-PESA is locked. Reply with your M-PESA PIN to unlock it."


def test_health_ready_headers(env):
    r = env.client.get("/v1/health", headers={"X-Request-ID": "abc-1"})
    assert r.status_code == 200 and r.headers["x-request-id"] == "abc-1" and r.headers["cache-control"] == "no-store"
    assert "default-src 'self'" in r.headers["content-security-policy"] and r.headers["x-content-type-options"] == "nosniff"
    j = env.client.get("/v1/ready").json()
    assert j["status"] == "ready" and j["connectors"]["link_reputation"] == "not configured" and j["policy_version"] == "assessment-policy-v0.3"


def test_check_returns_status_steps_evidence_and_coverage(env):
    j = env.check(FEE)
    a = j["assessment"]
    assert j["status"] == "completed" and j["guest_token"] and j["request_id"] and [s["name"] for s in j["steps"]][0] == "Reading text"
    assert a["label"] == "suspicious_verify_first" and a["category"]["suggested"] in ("grant", "payment") and a["coverage"] and a["limitations"]
    assert a["label_text"] == "Suspicious: verify first"


def test_high_risk_has_dated_sources_and_audit_trail_rows(env):
    j = env.check(PIN)
    a = j["assessment"]
    assert a["label"] == "high_risk" and any(s["id"] == "safaricom-never-asks-pin" and s["last_verified_at"] and s["review_due"] for s in a["sources"])
    with env.db() as db:
        assert db.execute(select(m.Assessment).where(m.Assessment.check_id == j["check_id"])).scalar_one().status_label == "high_risk"
        assert {r.signal_code for r in db.execute(select(m.RiskSignal)).scalars()} >= {"PIN_OR_OTP_REQUEST", "SAFARICOM_NEVER_ASKS_PIN"}
        assert db.execute(select(m.SourceObservation)).scalars().first() is not None
        assert db.execute(select(m.AuditEvent).where(m.AuditEvent.action == "check.create")).scalars().first().request_id


def test_guest_token_gates_reads_and_hides_unknown_vs_wrong(env):
    j = env.check(FEE)
    url = f"/v1/checks/{j['check_id']}"
    assert env.client.get(url, headers={"X-Guest-Token": j["guest_token"]}).status_code == 200
    for h in ({}, {"X-Guest-Token": "wrong"}):
        assert env.client.get(url, headers=h).status_code == 404
    assert env.client.get("/v1/checks/nope", headers={"X-Guest-Token": j["guest_token"]}).status_code == 404


def test_text_is_encrypted_at_rest_credentials_never_stored_and_export_delete_work(env):
    j = env.check("Please keep 7QX-unique-marker private. Safaricom: reply with PIN 4821 now. Pay KSh 350 to activate funds.")
    h = {"X-Guest-Token": j["guest_token"]}
    with env.db() as db:
        row = db.get(m.Check, j["check_id"])
        assert "7QX-unique-marker" not in row.input_encrypted and "4821" not in row.input_encrypted
        assert "4821" not in json.dumps(row.result_json) and "4821" not in json.dumps(j)
        assert env.ctx.crypto.dec(row.input_encrypted).count("4821") == 0 and "7QX-unique-marker" in env.ctx.crypto.dec(row.input_encrypted)
    ex = env.client.get(f"/v1/checks/{j['check_id']}/export", headers=h).json()
    assert "7QX-unique-marker" in ex["submitted_text"] and "4821" not in ex["submitted_text"]
    assert env.client.delete(f"/v1/checks/{j['check_id']}", headers=h).status_code == 200
    assert env.client.get(f"/v1/checks/{j['check_id']}", headers=h).status_code == 404
    with env.db() as db:
        assert db.get(m.Check, j["check_id"]) is None and not db.execute(select(m.RiskSignal)).scalars().all()


def test_retention_purge_removes_expired_checks_and_files(env):
    from app.routes_core import purge_expired
    j = env.check(FEE, headers={})
    h = {"X-Guest-Token": j["guest_token"]}
    env.client.post(f"/v1/checks/{j['check_id']}/evidence", files={"file": ("a.png", png_with_text(), "image/png")}, headers=h)
    files = os.listdir(env.settings.storage_dir); assert len(files) == 1
    with env.db() as db:
        db.get(m.Check, j["check_id"]).expires_at = "2020-01-01T00:00:00+00:00"; db.commit()
        assert env.client.get(f"/v1/checks/{j['check_id']}", headers=h).status_code == 404          # expired means gone to the user already
        assert purge_expired(db, env.ctx) == 1
    assert os.listdir(env.settings.storage_dir) == []


def test_too_little_text_asks_for_more_instead_of_concluding(env):
    j = env.check("hi")
    assert j["status"] == "needs_more_information" and "screenshot" in j["prompt"] and j["assessment"]["label"] == "inconclusive"


def test_swahili_language_and_validation(env):
    j = env.check(FEE, language="sw")
    assert j["assessment"]["label_text"] == "Una shaka: thibitisha kwanza" and j["assessment"]["language"] == "sw"
    for bad in ({}, {"text": ""}, {"text": " \n "}, {"text": "x" * 5001}, {"text": "hello there friend", "category": "nonsense"}):
        assert env.client.post("/v1/checks", json=bad).status_code == 422


def test_category_hint_is_used(env):
    assert env.check("Some message about nothing much really", category="job")["assessment"]["category"]["used"] == "job"


def test_rate_limit_returns_429_with_retry_after(make_env):
    e = make_env(rl_checks=(2, 3600))
    e.check(FEE); e.check(FEE)
    r = e.client.post("/v1/checks", json={"text": FEE})
    assert r.status_code == 429 and int(r.headers["retry-after"]) > 0 and "try again" in r.json()["detail"]


# ---------------- accounts
def test_accounts_history_and_ownership(env):
    h, uid = env.user()
    assert env.client.post("/v1/auth/register", json={"email": "ADA@example.com", "password": "another long pass"}).status_code == 409
    assert env.client.post("/v1/auth/login", json={"email": "ada@example.com", "password": "wrong password!!"}).status_code == 401
    j = env.check(FEE, headers=h)
    assert j.get("guest_token") is None
    assert env.client.get(f"/v1/checks/{j['check_id']}", headers=h).status_code == 200
    hist = env.client.get("/v1/me/checks", headers=h).json()["checks"]
    assert hist[0]["check_id"] == j["check_id"] and hist[0]["label"] == "suspicious_verify_first"
    other, _ = env.user("bob@example.com")
    assert env.client.get(f"/v1/checks/{j['check_id']}", headers=other).status_code == 404
    assert env.client.get("/v1/me/checks").status_code == 401
    assert env.client.post("/v1/auth/logout", headers=h).status_code == 200 and env.client.get("/v1/me/checks", headers=h).status_code == 401
    with env.db() as db:
        u = db.get(m.User, uid)
        assert "ada@example.com" not in u.email_encrypted and u.password_hash.startswith("scrypt$") and "correct horse" not in u.password_hash


def test_short_passwords_rejected(env):
    assert env.client.post("/v1/auth/register", json={"email": "a@b.co", "password": "short"}).status_code == 422


def test_moderator_can_read_a_check_and_it_is_audited(env):
    j = env.check(FEE)
    mod, mid = env.user("mod@example.com", "moderator")
    assert env.client.get(f"/v1/checks/{j['check_id']}", headers=mod).status_code == 200
    with env.db() as db:
        assert db.execute(select(m.AuditEvent).where(m.AuditEvent.action == "check.moderator_read", m.AuditEvent.actor_id == mid)).scalars().first()


# ---------------- evidence and OCR
def test_screenshot_is_read_assessed_encrypted_and_never_served(env):
    j = env.check("Please see my screenshot below for the details of the offer.")
    h = {"X-Guest-Token": j["guest_token"]}
    r = env.client.post(f"/v1/checks/{j['check_id']}/evidence", files={"file": ("shot.png", png_with_text(), "image/png")}, headers=h)
    assert r.status_code == 201, r.text
    j2 = r.json()
    assert "ADVANCE_FEE_REQUEST" in [f["code"] for f in j2["assessment"]["findings"]] and j2["assessment"]["label"] == "suspicious_verify_first"
    ev = j2["evidence"][0]
    assert ev["ocr_status"] == "checked" and "350" in ev["extracted_text"] and ev["redaction_state"] == "metadata_stripped"
    from ssi_connectors import ocr
    if "swa" in ocr.available_languages():
        assert "Swahili" not in ev["ocr_note"]
    else:
        assert "Swahili" in ev["ocr_note"]
    assert any(c["id"].startswith("image_text") for c in j2["assessment"]["coverage"])
    stored = open(os.path.join(env.settings.storage_dir, os.listdir(env.settings.storage_dir)[0]), "rb").read()
    assert not stored.startswith(b"\x89PNG") and b"IHDR" not in stored                       # encrypted at rest
    assert env.client.get(f"/v1/checks/{j['check_id']}/evidence", headers=h).json()[0]["evidence_id"] == ev["evidence_id"]
    assert env.client.get(f"/v1/checks/{j['check_id']}/evidence").status_code == 404           # needs the token
    assert env.client.get(f"/static/{ev['evidence_id']}").status_code == 404                   # no route serves stored files


def test_evidence_rejects_bad_files_and_enforces_limits(make_env):
    e = make_env(max_evidence_per_check=2)
    j = e.check(FEE); h = {"X-Guest-Token": j["guest_token"]}; url = f"/v1/checks/{j['check_id']}/evidence"
    assert e.client.post(url, files={"file": ("x.png", b"MZ\x90\x00not-an-image", "image/png")}, headers=h).status_code == 400
    assert e.client.post(url, files={"file": ("x.png", b"\x89PNG\r\n\x1a\n" + b"x" * 50, "image/png")}, headers=h).status_code == 400
    assert e.client.post(url, files={"file": ("a.png", png_with_text(), "image/png")}).status_code == 404       # not the owner
    for _ in range(2):
        assert e.client.post(url, files={"file": ("a.png", png_with_text(), "image/png")}, headers=h).status_code == 201
    assert e.client.post(url, files={"file": ("a.png", png_with_text(), "image/png")}, headers=h).status_code == 409


def test_conflicting_places_across_pieces_are_noted_not_accused(env):
    j = env.check("Our shop is in Mombasa, deliveries countrywide. See the receipt screenshot.")
    h = {"X-Guest-Token": j["guest_token"]}
    r = env.client.post(f"/v1/checks/{j['check_id']}/evidence", files={"file": ("r.png", png_with_text("Receipt from our Eldoret branch"), "image/png")}, headers=h).json()
    assert "LOCATION_CLAIMS_DIFFER" in [f["code"] for f in r["assessment"]["findings"]]


def test_similar_photo_in_another_check_is_only_a_weak_lead(env):
    img = photo_like(7)
    a = env.check("Selling a phone, photo attached for you to see.")
    env.client.post(f"/v1/checks/{a['check_id']}/evidence", files={"file": ("p.png", img, "image/png")}, data={"consent_scope": "cross_case_campaign"}, headers={"X-Guest-Token": a["guest_token"]})
    b = env.check("Brand new phone for sale, photo attached for you.")
    r = env.client.post(f"/v1/checks/{b['check_id']}/evidence", files={"file": ("p.png", img, "image/png")}, data={"consent_scope": "cross_case_campaign"}, headers={"X-Guest-Token": b["guest_token"]}).json()
    f = next(x for x in r["assessment"]["findings"] if x["code"] == "SIMILAR_IMAGE_SEEN_ELSEWHERE")
    assert f["strength"] == "weak" and "lead" in f["why_it_matters"]
    assert r["assessment"]["label"] != "high_risk"


# ---------------- connectors wired through the pipeline
def test_blocklist_hit_makes_high_risk_and_provider_outage_is_visible(make_env):
    e = make_env(deps=Deps(reputation_providers=[reputation.LocalBlocklist([{"value": "prize-claims.example.com"}], source="CuratedList")]))
    a = e.check("Claim your reward now at https://prize-claims.example.com/win thanks")["assessment"]
    assert a["label"] == "high_risk" and any(s["id"] == "reputation:CuratedList" for s in a["sources"])

    class Down:
        def lookup(self, url):
            from ssi_rules.observations import Reputation
            return Reputation(CS.COULD_NOT_CHECK, "Down")
    e2 = make_env(deps=Deps(reputation_providers=[Down()]))
    a2 = e2.check("Lunch menu for the week is at https://menu.example.com/week")["assessment"]
    assert a2["label"] == "inconclusive" and next(c for c in a2["coverage"] if c["id"] == "url_reputation")["status"] == "could_not_check"
    assert any("could not be checked" in l for l in a2["limitations"])


def test_shortener_resolved_to_lookalike_through_the_safe_fetcher(make_env):
    def handler(req):
        if req.headers["host"] == "bit.ly":
            return httpx.Response(302, headers={"location": "https://safaricom-rewards.xyz/claim"})
        return httpx.Response(200)
    t = httpx.MockTransport(handler)
    d = Deps(follow_redirects=lambda u: safe_fetch.follow_redirects(u, transport=t, resolver=lambda h: ["93.184.216.34"]))
    a = make_env(deps=d).check("Details here: bit.ly/3AbCdEf thank you very much")["assessment"]
    assert "LOOKALIKE_DOMAIN" in [f["code"] for f in a["findings"]] and a["label"] == "suspicious_verify_first"
    assert next(c for c in a["coverage"] if c["id"] == "redirect_destination")["status"] == "checked"


def test_connector_crash_is_isolated_not_a_silent_pass(make_env):
    def boom(u): raise RuntimeError("socket exploded")
    a = make_env(deps=Deps(follow_redirects=boom)).check("Details here: bit.ly/3AbCdEf thank you very much")["assessment"]
    assert a["label"] == "inconclusive" and next(c for c in a["coverage"] if c["id"] == "redirect_destination")["status"] == "could_not_check"


# ---------------- recovery and opportunities
def test_recovery_endpoint_asks_only_what_is_missing(env):
    j = env.client.post("/v1/recovery", json={"paid": True}).json()
    assert {q["id"] for q in j["questions"]} == {"shared_credentials", "installed_app", "sent_id_documents"} and j["steps"] and "cannot reverse" in j["limits"]


def test_opportunity_registry_is_public_dated_and_admin_editable(env):
    j = env.client.get("/v1/opportunities/kra-careers").json()
    assert j["fee_policy"] == "no_fee" and j["last_verified_at"] and j["review_due"] and j["is_stale"] is False and j["reviewer"] == "unreviewed"
    assert env.client.get("/v1/opportunities?q=revenue").json()["opportunities"][0]["id"] == "kra-careers"
    body = {"id": "demo-bursary", "opportunity_type": "bursary", "official_name": "Demo County Bursary", "administering_body": "Demo County", "aliases": ["demo county bursary"],
            "official_domain": "demo.go.ke", "counties": ["Kisumu"], "fee_policy": "no_fee", "source_url": "https://demo.go.ke/bursary", "last_verified_at": "2026-10-20", "reviewer": "A. Reviewer"}
    assert env.client.put("/v1/admin/opportunities", json=body).status_code == 401
    mod, _ = env.user("mod@example.com", "moderator")
    assert env.client.put("/v1/admin/opportunities", json=body, headers=mod).json()["review_due"] == "2027-01-18"
    a = env.check("The Demo County Bursary needs an application fee: pay Ksh 500 to apply for the bursary now")["assessment"]
    assert a["label"] == "high_risk" and a["findings"][0]["code"] == "PROGRAMME_FEE_CONTRADICTION"
    assert any(s["id"] == "opportunity:demo-bursary" for s in a["sources"])


def test_unknown_programme_is_not_independently_verified(env):
    a = env.check("You were selected for the Youth Business Grant. Pay KSh 350 to activate funds.")["assessment"]
    assert "OFFICIAL_SOURCE_NOT_FOUND" in [f["code"] for f in a["findings"]] and next(c for c in a["coverage"] if c["id"] == "official_programmes")["status"] == "not_found"


# ---------------- channels
def test_whatsapp_webhook_verifies_signature_replies_and_never_stores_the_number(make_env):
    sent = []
    class S:
        def send_text(self, to, body): sent.append((to, body)); return True
    e = make_env(senders={"whatsapp": S()}, whatsapp_app_secret="shh", whatsapp_verify_token="vt")
    assert e.client.get("/v1/channels/whatsapp/webhook", params={"hub.mode": "subscribe", "hub.verify_token": "vt", "hub.challenge": "1234"}).text == "1234"
    assert e.client.get("/v1/channels/whatsapp/webhook", params={"hub.mode": "subscribe", "hub.verify_token": "bad", "hub.challenge": "1"}).status_code == 403
    body = json.dumps({"entry": [{"changes": [{"value": {"messages": [{"from": "254712345678", "id": "w1", "type": "text", "text": {"body": FEE}}]}}]}]}).encode()
    assert e.client.post("/v1/channels/whatsapp/webhook", content=body, headers={"X-Hub-Signature-256": "sha256=bad"}).status_code == 403
    sig = "sha256=" + hmac.new(b"shh", body, hashlib.sha256).hexdigest()
    assert e.client.post("/v1/channels/whatsapp/webhook", content=body, headers={"X-Hub-Signature-256": sig}).json() == {"handled": 1}
    to, reply = sent[0]
    assert to == "254712345678" and reply.startswith("Suspicious") and "https://ssi.test/#r=" in reply and len(reply) <= 900
    with e.db() as db:
        assert "254712345678" not in repr([c.input_encrypted for c in db.execute(select(m.Check)).scalars()])
        n = db.execute(select(m.Notification)).scalar_one()
        assert n.status == "sent" and "254712345678" not in n.to_encrypted


def test_sms_callback_needs_secret_and_queues_when_no_sender_is_configured(make_env):
    e = make_env(at_callback_secret="s3cret")
    assert e.client.post("/v1/channels/sms/africastalking/wrong", data={"from": "+254712345678", "text": FEE}).status_code == 403
    assert e.client.post("/v1/channels/sms/africastalking/s3cret", data={"from": "+254712345678", "text": FEE}).json() == {"handled": 1}
    with e.db() as db:
        assert db.execute(select(m.Notification)).scalar_one().status == "unsent_not_configured"
