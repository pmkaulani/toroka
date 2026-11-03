"""Reports, moderation, public indicators, appeals, business claims. Privacy and fairness rules are tested as behaviour."""
import json
import pytest
from app import db as m
from sqlalchemy import select

TILL = {"type": "till", "value": "123456"}
NARR = "I was told to pay for goods on Instagram, sent Ksh 3,000 to this till and the seller vanished and blocked me."


def report(env, narrative=NARR, ids=(TILL,), headers=None, **kw):
    r = env.client.post("/v1/reports", json={"category": "shop", "narrative": narrative, "identifiers": list(ids), **kw}, headers=headers or {})
    return r


def reporter(env, n):
    """A distinct independent reporter: a registered user (guests share one client key in tests)."""
    h, uid = env.user(f"reporter{n}@example.com")
    return h


def approve(env, mod, rid, publish=False, **kw):
    return env.client.post(f"/v1/moderation/reports/{rid}/action", json={"action": "approve", "reason_code": "corroborated", "publish": publish, **kw}, headers=mod)


def publish_till(env, reporters=2):
    mod, _ = env.user("mod@example.com", "moderator")
    ids = []
    for i in range(reporters):
        ids.append(report(env, NARR + f" Detail {i}: it happened on day {i}.", headers=reporter(env, i)).json()["report_id"])
    for i, rid in enumerate(ids):
        assert approve(env, mod, rid, publish=(i == len(ids) - 1)).status_code == 200
    return mod, ids


def test_report_is_private_validated_and_masks_credentials(env):
    r = report(env, narrative=NARR + " He asked for my PIN 4821 too.")
    assert r.status_code == 201 and r.json()["status"] == "pending" and r.json()["credential_values_hidden"] and "Nothing is public yet" in r.json()["message"]
    with env.db() as db:
        row = db.execute(select(m.Report)).scalar_one()
        assert "4821" not in env.ctx.crypto.dec(row.narrative_encrypted) and NARR[:20] not in row.narrative_encrypted
        s = db.execute(select(m.Subject)).scalar_one()
        assert "123456" not in s.lookup_hmac and "123456" not in s.value_encrypted and s.display_masked == "till ••456"
    assert env.client.get("/v1/reports/search", params={"type": "till", "value": "123456"}).json()["found"] is False       # unpublished stays invisible
    for bad in ({"identifiers": [{"type": "phone", "value": "12345"}]}, {"identifiers": [{"type": "till", "value": "12"}]}, {"identifiers": []}, {"narrative": "too short"}):
        body = {"category": "shop", "narrative": NARR, "identifiers": [TILL], **bad}
        assert env.client.post("/v1/reports", json=body).status_code == 422


def test_report_tracking_needs_the_report_token(env):
    j = report(env).json()
    assert env.client.get(f"/v1/reports/{j['report_id']}").status_code == 404
    assert env.client.get(f"/v1/reports/{j['report_id']}", headers={"X-Report-Token": j["report_token"]}).json()["status"] == "pending"


def test_same_reporter_duplicates_are_merged_not_counted(env):
    first = report(env).json()
    dup = report(env, narrative=NARR + " (sending again)").json()
    assert dup["status"] == "duplicate" and dup["duplicate_of"] == first["report_id"]
    mod, _ = env.user("mod@example.com", "moderator")
    q = env.client.get("/v1/moderation/queue", headers=mod).json()["reports"]
    assert [x["report_id"] for x in q] == [first["report_id"]]


def test_moderation_endpoints_need_the_right_role(env):
    rid = report(env).json()["report_id"]
    assert env.client.get("/v1/moderation/queue").status_code == 401
    user, _ = env.user("plain@example.com")
    assert env.client.get("/v1/moderation/queue", headers=user).status_code == 403
    assert env.client.post(f"/v1/moderation/reports/{rid}/action", json={"action": "approve", "reason_code": "x" * 3}, headers=user).status_code == 403


def test_queue_shows_narrative_to_moderators_with_masked_identifiers_and_signals(env):
    report(env, headers=reporter(env, 1)); report(env, headers=reporter(env, 2))
    mod, _ = env.user("mod@example.com", "moderator")
    q = env.client.get("/v1/moderation/queue", headers=mod).json()["reports"]
    assert q[0]["narrative"].startswith("I was told") and q[0]["identifiers"][0]["masked"] == "till ••456" and "123456" not in json.dumps(q)
    assert q[0]["same_script_reports"] == 1 and q[0]["distinct_reporters_same_script"] == 2
    with env.db() as db:
        assert db.execute(select(m.AuditEvent).where(m.AuditEvent.action == "moderation.queue_read")).scalars().first()


def test_publication_needs_independent_reports_and_moderator_approval(env):
    mod, ids = publish_till(env, reporters=1)                      # one report, even approved and "published", is not enough
    assert env.client.get("/v1/reports/search", params={"type": "till", "value": "123456"}).json()["found"] is False
    r2 = report(env, narrative=NARR + " Different person, different day, same till.", headers=reporter(env, 9)).json()["report_id"]
    approve(env, mod, r2)                                           # now two independent approved reports; a later publish request goes through
    r3 = report(env, narrative=NARR + " A third account of the same payment destination.", headers=reporter(env, 10)).json()["report_id"]
    assert approve(env, mod, r3, publish=True).json()["indicators"][0]["independent_reports"] == 3
    f = env.client.get("/v1/reports/search", params={"type": "till", "value": "123456"}).json()
    assert f["found"] and f["indicator"]["independent_reports"] == 3 and f["indicator"]["identifier"] == "till ••456" and "disclaimer" in f["indicator"]
    assert "narrative" not in json.dumps(f) and "Instagram" not in json.dumps(f) and "vanished" not in json.dumps(f)         # never raw victim text


def test_same_person_many_reports_never_counts_as_independent(env):
    mod, _ = env.user("mod@example.com", "moderator")
    h = reporter(env, 1)
    ids = [report(env, narrative=NARR + f" Entry {i}: " + "x" * (i * 5 + 1) + " different words each time to avoid the duplicate check " * (i + 1), headers=h).json() for i in range(3)]
    approved = [r["report_id"] for r in ids if r["status"] == "pending"]
    for rid in approved:
        approve(env, mod, rid, publish=True)
    assert env.client.get("/v1/reports/search", params={"type": "till", "value": "123456"}).json()["found"] is False


def test_verified_by_source_can_publish_on_one_report_with_a_cited_basis(env):
    mod, _ = env.user("mod@example.com", "moderator")
    rid = report(env, headers=reporter(env, 1)).json()["report_id"]
    out = approve(env, mod, rid, publish=True, verified_by_source="Provider confirmed the till is closed (ref 55)").json()
    assert out["indicators"][0]["status"] == "published"
    assert env.client.get("/v1/reports/search", params={"type": "till", "value": "123456"}).json()["indicator"]["basis"] == "verified_by_source"


def test_assessment_uses_published_indicators_and_scales_with_independence(env):
    msg = "Please pay for the goods to Till Number 123456 today."
    assert env.check(msg)["assessment"]["label"] == "inconclusive"
    publish_till(env, reporters=2)
    a = env.check(msg)["assessment"]
    assert a["label"] == "suspicious_verify_first" and a["findings"][0]["code"] == "REPORTED_PAYMENT_DESTINATION"
    mod, _ = env.user("mod2@example.com", "moderator")
    rid = report(env, narrative=NARR + " A third independent report of this till number.", headers=reporter(env, 20)).json()["report_id"]
    approve(env, mod, rid)
    a = env.check(msg)["assessment"]
    assert a["label"] == "high_risk" and any(s["id"].startswith("indicator:") for s in a["sources"])


def test_search_is_rate_limited_and_resists_enumeration(make_env):
    e = make_env(rl_search_distinct=3)
    for n in range(3):
        assert e.client.get("/v1/reports/search", params={"type": "till", "value": f"12345{n}"}).status_code == 200
    r = e.client.get("/v1/reports/search", params={"type": "till", "value": "999999"})
    assert r.status_code == 429 and "Retry-After" in r.headers
    assert e.client.get("/v1/reports/search", params={"type": "till", "value": "123450"}).status_code == 200            # repeating a lookup is fine
    assert e.client.get("/v1/reports/search", params={"type": "bogus", "value": "x"}).status_code == 422


def test_reports_are_rate_limited(make_env):
    e = make_env(rl_reports=(2, 86400))
    for i in range(2):
        assert report(e, narrative=NARR + " number %d with other words " % i + "z" * 30 * (i + 1)).status_code == 201
    assert report(e, narrative=NARR + " one more extra with new words entirely").status_code == 429


# ---------------- appeals and corrections
def open_appeal(env, ind_id):
    r = env.client.post("/v1/appeals", json={"indicator_id": ind_id, "contact": "owner@shop.example", "issue_type": "correction",
                                             "statement": "This till belongs to my legitimate shop; the payments listed were refunded in full."})
    assert r.status_code == 201, r.text
    return r.json()


def search_status(env):
    return env.client.get("/v1/reports/search", params={"type": "till", "value": "123456"}).json()


def test_appeal_needs_verification_then_marks_entry_under_review_and_can_be_upheld(env):
    mod, _ = publish_till(env, 2)
    ind_id = search_status(env)["indicator"]["id"]
    ap = open_appeal(env, ind_id)
    h = {"X-Appeal-Token": ap["appeal_token"]}
    assert ap["status"] == "pending_verification" and search_status(env)["indicator"]["status"] == "published"          # nothing changes until verified
    assert env.client.post(f"/v1/appeals/{ap['appeal_id']}/verify", json={"code": "000000" if ap["dev_code"] != "000000" else "111111"}, headers=h).status_code == 400
    assert env.client.post(f"/v1/appeals/{ap['appeal_id']}/verify", json={"code": ap["dev_code"]}).status_code == 404         # needs the token
    assert env.client.post(f"/v1/appeals/{ap['appeal_id']}/verify", json={"code": ap["dev_code"]}, headers=h).json()["status"] == "open"
    s = search_status(env)["indicator"]
    assert s["status"] == "under_review" and "under review" in s["note"]
    a = env.check("Please pay for the goods to Till Number 123456 today.")["assessment"]
    assert a["findings"][0]["strength"] == "weak" and "under review" in a["findings"][0]["plain_text"] and a["label"] != "high_risk"       # appeal softens the result
    assert env.client.get("/v1/moderation/appeals", headers=mod).json()["appeals"][0]["statement"].startswith("This till belongs")
    res = env.client.post(f"/v1/moderation/appeals/{ap['appeal_id']}/resolve", json={"outcome": "upheld", "reason_code": "payments_refunded", "notes": "checked with provider"}, headers=mod)
    assert res.json()["status"] == "upheld" and search_status(env)["found"] is False
    assert env.client.get(f"/v1/appeals/{ap['appeal_id']}", headers=h).json()["outcome"] == "The entry was removed or corrected."
    with env.db() as db:
        kinds = {n.template for n in db.execute(select(m.Notification)).scalars()}
        assert {"appeal_verification", "appeal_outcome"} <= kinds
        assert db.execute(select(m.ModerationAction).where(m.ModerationAction.action == "upheld")).scalar_one().reason_code == "payments_refunded"


def test_rejected_appeal_restores_the_entry(env):
    mod, _ = publish_till(env, 2)
    ap = open_appeal(env, search_status(env)["indicator"]["id"]); h = {"X-Appeal-Token": ap["appeal_token"]}
    env.client.post(f"/v1/appeals/{ap['appeal_id']}/verify", json={"code": ap["dev_code"]}, headers=h)
    env.client.post(f"/v1/moderation/appeals/{ap['appeal_id']}/resolve", json={"outcome": "rejected", "reason_code": "no_evidence"}, headers=mod)
    assert search_status(env)["indicator"]["status"] == "published"


def test_wrong_codes_lock_out_and_bad_contacts_are_refused(env):
    publish_till(env, 2)
    ind = search_status(env)["indicator"]["id"]
    assert env.client.post("/v1/appeals", json={"indicator_id": ind, "contact": "not a contact", "issue_type": "appeal", "statement": "x" * 30}).status_code == 422
    ap = open_appeal(env, ind); h = {"X-Appeal-Token": ap["appeal_token"]}
    for _ in range(5):
        assert env.client.post(f"/v1/appeals/{ap['appeal_id']}/verify", json={"code": "abcdef"}, headers=h).status_code == 400
    assert env.client.post(f"/v1/appeals/{ap['appeal_id']}/verify", json={"code": ap["dev_code"]}, headers=h).status_code == 429


def test_businesses_cannot_pay_or_claim_their_way_out(env):
    mod, _ = publish_till(env, 2)
    owner, _ = env.user("owner@shop.example")
    c = env.client.post("/v1/business-claims", json={"business_name": "Mama Mboga Shop", "domain": "https://www.mamamboga.co.ke/shop"}, headers=owner).json()
    assert c["status"] == "pending" and "never removes or hides reports" in c["message"]
    assert env.client.post(f"/v1/moderation/business-claims/{c['claim_id']}/review", json={"status": "approved", "reason_code": "documents_ok"}, headers=owner).status_code == 403
    assert env.client.post(f"/v1/moderation/business-claims/{c['claim_id']}/review", json={"status": "approved", "reason_code": "documents_ok"}, headers=mod).json()["status"] == "approved"
    assert env.client.get("/v1/business-claims/mine", headers=owner).json()["claims"][0]["domain"] == "mamamboga.co.ke"
    assert search_status(env)["found"] is True                       # an approved claim never hides a published entry


# ---------------- takedown, campaigns, graph
def test_urgent_takedown_is_immediate_and_audited(env):
    mod, _ = publish_till(env, 2)
    ind = search_status(env)["indicator"]["id"]
    assert env.client.post(f"/v1/moderation/indicators/{ind}/takedown", json={"action": "reject", "reason_code": "legal_request", "notes": "counsel request"}, headers=mod).json()["status"] == "withdrawn"
    assert search_status(env)["found"] is False
    with env.db() as db:
        assert db.execute(select(m.AuditEvent).where(m.AuditEvent.action == "moderation.urgent_takedown")).scalars().first()
        assert db.execute(select(m.ModerationAction).where(m.ModerationAction.action == "urgent_takedown")).scalar_one().reason_code == "legal_request"


def test_campaign_clustering_and_entity_edges(env):
    mod, _ = env.user("mod@example.com", "moderator")
    script = "Hello Mary you won Ksh 50000 in the youth grant. Pay Ksh 350 to {n} to activate your grant funds today."
    report(env, narrative=script.format(n="0712 345 678"), ids=[{"type": "phone", "value": "0712345678"}], headers=reporter(env, 1))
    report(env, narrative=script.replace("Mary", "John").format(n="0733 111 222"), ids=[{"type": "phone", "value": "0733111222"}, {"type": "till", "value": "654321"}], headers=reporter(env, 2))
    cs = env.client.get("/v1/moderation/campaigns", headers=mod).json()["campaigns"]
    assert len(cs) == 1 and cs[0]["reports"] == 2 and cs[0]["distinct_reporters"] == 2 and cs[0]["identifiers"] == 3
    with env.db() as db:
        rels = {e.relation_type for e in db.execute(select(m.EntityEdge)).scalars()}
        assert rels == {"co_reported", "same_script"}


def test_other_reports_cannot_be_published_without_approval_and_publish_flag_needs_approve(env):
    mod, _ = env.user("mod@example.com", "moderator")
    rid = report(env).json()["report_id"]
    r = env.client.post(f"/v1/moderation/reports/{rid}/action", json={"action": "reject", "reason_code": "no_evidence", "publish": True}, headers=mod)
    assert r.status_code == 422
    r = env.client.post(f"/v1/moderation/reports/{rid}/action", json={"action": "mark_duplicate", "reason_code": "dup"}, headers=mod)
    assert r.status_code == 422


def test_reporter_is_told_the_outcome_only_with_consent(env):
    mod, _ = env.user("mod@example.com", "moderator")
    r1 = report(env, contact="reporter@example.com", consent_to_contact=True, headers=reporter(env, 1)).json()
    r2 = report(env, narrative=NARR + " second one, no consent.", contact="x@example.com", consent_to_contact=False, headers=reporter(env, 2)).json()
    approve(env, mod, r1["report_id"]); approve(env, mod, r2["report_id"])
    with env.db() as db:
        n = db.execute(select(m.Notification).where(m.Notification.template == "report_outcome")).scalars().all()
        assert len(n) == 1 and env.ctx.crypto.dec(n[0].to_encrypted) == "reporter@example.com"
        assert "reporter@example" not in n[0].to_encrypted


def test_social_profile_handle_can_be_reported_and_looked_up_by_exact_url_or_bare_handle(env):
    mod, _ = env.user("handle-mod@example.com", "moderator")
    profile = {"type": "handle", "value": "https://instagram.com/clothing.ctrl"}
    bare = {"type": "handle", "value": "@clothing.ctrl"}
    ids = []
    for n in range(2):
        r = report(env, narrative=(NARR + f" Independent incident from account {n}: item not delivered and seller blocked buyer."),
                   ids=(profile,), headers=reporter(env, 70 + n))
        assert r.status_code == 201, r.text
        ids.append(r.json()["report_id"])
    for n, rid in enumerate(ids):
        result = approve(env, mod, rid, publish=(n == 1))
        assert result.status_code == 200, result.text
    exact = env.client.get("/v1/reports/search", params={"type": "handle", "value": profile["value"]})
    assert exact.status_code == 200, exact.text
    exact_body = exact.json()
    assert exact_body["found"] is True
    assert exact_body["indicator"]["kind"] == "handle"
    assert exact_body["indicator"]["independent_reports"] == 2
    generic = env.client.get("/v1/reports/search", params={"type": "handle", "value": bare["value"]})
    assert generic.status_code == 200, generic.text
    generic_body = generic.json()
    assert generic_body["found"] is True
    assert generic_body["ambiguous_platform"] is True
    assert len(generic_body["matches"]) == 1
    assert generic_body["matches"][0]["identifier"].startswith("@clothing.ctrl")

    # The formal assessment endpoint must retrieve the same exact profile report,
    # not only the conversational chat route.
    checked = env.check("Please investigate this Instagram shop https://instagram.com/clothing.ctrl before buying")
    assessment = checked["assessment"]
    assert any(f["code"] == "REPORTED_SOCIAL_HANDLE" for f in assessment["findings"])
    assert assessment["label"] in {"suspicious_verify_first", "high_risk"}

    # A bare @handle should search platform candidates separately and must not
    # combine unrelated Instagram/TikTok identities into a single aggregate.
    bare_check = env.check("Please investigate @clothing.ctrl before buying")
    assert any(f["code"] == "REPORTED_SOCIAL_HANDLE" for f in bare_check["assessment"]["findings"])


def test_platform_specific_handle_reports_remain_separate(env):
    mod, _ = env.user("handle-mod-2@example.com", "moderator")
    ids = []
    for n, profile in enumerate(("https://instagram.com/shared.name", "https://tiktok.com/@shared.name")):
        r = report(env, narrative=(NARR + f" Different platform and independent incident {n}, seller did not deliver item."),
                   ids=({"type": "handle", "value": profile},), headers=reporter(env, 80 + n))
        assert r.status_code == 201, r.text
        ids.append(r.json()["report_id"])
    for rid in ids:
        assert approve(env, mod, rid, publish=True, verified_by_source="Moderator confirmed evidence for this test fixture").status_code == 200
    bare = env.client.get("/v1/reports/search", params={"type": "handle", "value": "@shared.name"})
    assert bare.status_code == 200, bare.text
    body = bare.json()
    assert body["found"] is True
    assert "matches" in body and len(body["matches"]) == 2
    assert body["ambiguous_platform"] is True
    assert all(x["identifier"] != body["matches"][0]["identifier"] for x in body["matches"][1:])
