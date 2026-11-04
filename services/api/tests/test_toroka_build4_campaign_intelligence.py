from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from app import db as m
from toroka_build4.campaigns import build4_case_context, _image_reuse_context


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _create_subject(db, env, kind="phone", value="+254712345678", masked="+254 7•• ••• 678"):
    row = m.Subject(
        subject_type=kind,
        lookup_hmac=env.ctx.crypto.lookup(kind, value),
        display_masked=masked,
        value_encrypted=env.ctx.crypto.enc(value),
    )
    db.add(row)
    db.flush()
    return row


def _create_report(db, env, *, reporter, subject, report_id=None, script_hash="same-script", status="approved"):
    row = m.Report(
        id=report_id or m.uid(),
        reporter_key=env.ctx.crypto.lookup("reporter", reporter),
        token_hash=env.ctx.crypto.lookup("token", reporter),
        category="shop",
        narrative_encrypted=env.ctx.crypto.enc("Synthetic report narrative; never displayed publicly."),
        script_hash=script_hash,
        minhash=[],
        moderation_status=status,
        publication_scope="private",
        created_at=_now(),
        incident_date=datetime.now(timezone.utc).date().isoformat(),
    )
    db.add(row)
    db.flush()
    db.add(m.ReportSubject(report_id=row.id, subject_id=subject.id))
    db.flush()
    return row


def test_build4_is_on_the_normal_check_path_and_only_uses_published_indicators(env):
    with env.db() as db:
        phone = _create_subject(db, env)
        db.add(m.Indicator(subject_id=phone.id, status="published", independent_reports=3,
                           last_reported=datetime.now(timezone.utc).date().isoformat(), basis="independent_reports"))
        # Pending report for an unrelated number must not be exposed in guest results.
        pending = _create_subject(db, env, value="+254700000001", masked="+254 7•• ••• 001")
        _create_report(db, env, reporter="pending-person", subject=pending, status="pending", script_hash="unrelated")
        db.commit()

    submitted = "Please investigate this payment contact +254712345678 and explain what is known."
    result = env.check(submitted)
    context = result["assessment"]["investigation_intelligence"]["campaign_intelligence"]
    assert context["status"] == "context_found"
    assert context["matched_published_indicators"][0]["kind"] == "phone"
    assert context["matched_published_indicators"][0]["independent_reports"] == 3
    assert "+254700000001" not in str(context)
    assert context["risk_propagation"] == "never_automatic"
    # The Build 4 panel itself contains no verdict or score field; the pre-existing
    # deterministic assessment remains the sole owner of the result label.
    assert not ({"label", "verdict", "risk_band", "risk_score"} & set(context))


def test_private_or_pending_reports_are_not_returned_in_public_case_context(env):
    with env.db() as db:
        phone = _create_subject(db, env)
        report = _create_report(db, env, reporter="one-pending-reporter", subject=phone, status="pending")
        db.commit()
        chk = m.Check(expires_at=(datetime.now(timezone.utc) + timedelta(days=7)).isoformat(),
                      input_sha256="a" * 64, input_chars=40)
        db.add(chk); db.flush()
        context = build4_case_context(db, env.ctx.crypto, chk, "+254712345678", [])
        assert context is None
        assert report.narrative_encrypted != "Synthetic report narrative; never displayed publicly."


def test_image_matching_requires_both_current_and_historical_opt_in(env):
    first = env.check("First synthetic check with a product image and no personal details.")
    second = env.check("Second synthetic check with a similar product image and no personal details.")
    now = _now()
    with env.db() as db:
        old_check = db.get(m.Check, first["check_id"])
        current_check = db.get(m.Check, second["check_id"])
        db.add(m.EvidenceFile(check_id=old_check.id, object_key="old.bin", sha256="a" * 64,
                              mime_type="image/png", size_bytes=128, width=100, height=100,
                              dhash="0123456789abcdef", consent_scope="cross_case_campaign",
                              retention_until=old_check.expires_at, created_at=now))
        db.add(m.EvidenceFile(check_id=current_check.id, object_key="current.bin", sha256="b" * 64,
                              mime_type="image/png", size_bytes=128, width=100, height=100,
                              dhash="0123456789abcdef", consent_scope="this_check_only",
                              retention_until=current_check.expires_at, created_at=now))
        db.flush()
        assert _image_reuse_context(db, current_check, ["0123456789abcdef"]) is None
        current_file = db.execute(select(m.EvidenceFile).where(m.EvidenceFile.check_id == current_check.id)).scalar_one()
        current_file.consent_scope = "cross_case_campaign"
        db.flush()
        result = _image_reuse_context(db, current_check, ["0123456789abcdef"])
        assert result["status"] == "matches_found"
        assert result["matching_opted_in_checks"] == 1
        assert "check_ids" not in result and "case_ids" not in result


def test_campaign_moderation_endpoints_are_role_restricted_and_record_disposition(env):
    with env.db() as db:
        subject = _create_subject(db, env)
        _create_report(db, env, reporter="reporter-one", subject=subject)
        _create_report(db, env, reporter="reporter-two", subject=subject)
        db.commit()

    assert env.client.get("/v1/moderation/build4/campaigns").status_code == 401
    user, _ = env.user("build4-user@example.com")
    assert env.client.get("/v1/moderation/build4/campaigns", headers=user).status_code == 403
    moderator, moderator_id = env.user("build4-mod@example.com", "moderator")
    response = env.client.get("/v1/moderation/build4/campaigns?limit=100", headers=moderator)
    assert response.status_code == 200, response.text
    candidate = next(x for x in response.json()["campaigns"] if x["campaign_type"] == "repeated_advertisement_text")
    assert len(candidate["report_ids"]) == 2
    saved = env.client.post(
        f"/v1/moderation/build4/campaigns/{candidate['campaign_id']}/review",
        headers=moderator,
        json={"status": "insufficient_evidence", "reason_code": "no_corroboration", "notes": "Synthetic test note."},
    )
    assert saved.status_code == 200, saved.text
    assert saved.json()["status"] == "insufficient_evidence"
    with env.db() as db:
        record = db.execute(select(m.CampaignReview).where(m.CampaignReview.campaign_id == candidate["campaign_id"])).scalar_one()
        assert env.ctx.crypto.dec(record.notes_encrypted) == "Synthetic test note."
        assert record.reviewer_id == moderator_id
        actions = db.execute(select(m.ModerationAction).where(m.ModerationAction.action == "build4_campaign_review")).scalars().all()
        assert actions and "Synthetic test note." not in (actions[-1].notes or "")


def test_evidence_upload_rejects_unknown_consent_scope_and_defaults_to_check_only(env):
    check = env.check("Please inspect the attached example image for this check only.")
    url = f"/v1/checks/{check['check_id']}/evidence"
    headers = {"X-Guest-Token": check["guest_token"]}
    from conftest import png_with_text

    bad = env.client.post(url, headers=headers, data={"consent_scope": "share_everything"},
                          files={"file": ("bad-scope.png", png_with_text(), "image/png")})
    assert bad.status_code == 422

    ok = env.client.post(url, headers=headers,
                         files={"file": ("check-only.png", png_with_text(), "image/png")})
    assert ok.status_code == 201, ok.text
    with env.db() as db:
        evidence = db.execute(select(m.EvidenceFile).where(m.EvidenceFile.check_id == check["check_id"])).scalar_one()
        assert evidence.consent_scope == "this_check_only"


def test_evidence_upload_records_explicit_cross_case_image_opt_in(env):
    check = env.check("Please inspect this product screenshot and check for reused images.")
    url = f"/v1/checks/{check['check_id']}/evidence"
    headers = {"X-Guest-Token": check["guest_token"]}
    from conftest import png_with_text

    response = env.client.post(url, headers=headers, data={"consent_scope": "cross_case_campaign"},
                               files={"file": ("opt-in.png", png_with_text(), "image/png")})
    assert response.status_code == 201, response.text
    with env.db() as db:
        evidence = db.execute(select(m.EvidenceFile).where(m.EvidenceFile.check_id == check["check_id"])).scalar_one()
        assert evidence.consent_scope == "cross_case_campaign"
        events = db.execute(select(m.AuditEvent).where(m.AuditEvent.action == "evidence.upload")).scalars().all()
        assert events[-1].safe_metadata["cross_case_image_matching_opt_in"] is True


def test_related_public_identifiers_require_two_distinct_approved_reporters(env):
    with env.db() as db:
        phone = _create_subject(db, env)
        domain = _create_subject(db, env, kind="domain", value="marketplace.example", masked="marketplace.example")
        for subject in (phone, domain):
            db.add(m.Indicator(subject_id=subject.id, status="published", independent_reports=2,
                               last_reported=datetime.now(timezone.utc).date().isoformat(), basis="independent_reports"))
        db.flush()
        for reporter in ("independent-one", "independent-two"):
            report = _create_report(db, env, reporter=reporter, subject=phone, script_hash=f"campaign-{reporter}")
            db.add(m.ReportSubject(report_id=report.id, subject_id=domain.id))
        db.commit()

    result = env.check("Please investigate the payment phone +254712345678 and explain what is known.")
    context = result["assessment"]["investigation_intelligence"]["campaign_intelligence"]
    related = context["related_public_identifiers"]
    match = next(item for item in related if item["kind"] == "domain")
    assert match["masked_value"] == "marketplace.example"
    assert match["independent_reports"] == 2
    assert match["relationship"] == "appeared_together_in_independently_reported_moderated_cases"
    assert "report_ids" not in match and "narrative" not in match


def test_phase2_image_lead_also_requires_opt_in_from_both_cases(env):
    from conftest import photo_like
    image = photo_like(991)
    first = env.check("First synthetic product photo check, kept for this check.")
    env.client.post(
        f"/v1/checks/{first['check_id']}/evidence",
        headers={"X-Guest-Token": first["guest_token"]},
        files={"file": ("first.png", image, "image/png")},
    )
    second = env.check("Second synthetic product photo check, no cross-case permission.")
    result = env.client.post(
        f"/v1/checks/{second['check_id']}/evidence",
        headers={"X-Guest-Token": second["guest_token"]},
        files={"file": ("second.png", image, "image/png")},
    )
    assert result.status_code == 201, result.text
    codes = {finding["code"] for finding in result.json()["assessment"]["findings"]}
    assert "SIMILAR_IMAGE_SEEN_ELSEWHERE" not in codes


def test_campaign_report_details_are_moderator_only_decrypted_and_audited(env):
    with env.db() as db:
        subject = _create_subject(db, env)
        report = _create_report(db, env, reporter="private-detail-reporter", subject=subject)
        report_id = report.id
        db.commit()

    assert env.client.get(f"/v1/moderation/build4/reports/{report_id}").status_code == 401
    user, _ = env.user("build4-detail-user@example.com")
    assert env.client.get(f"/v1/moderation/build4/reports/{report_id}", headers=user).status_code == 403
    moderator, moderator_id = env.user("build4-detail-mod@example.com", "moderator")
    response = env.client.get(f"/v1/moderation/build4/reports/{report_id}", headers=moderator)
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["report_id"] == report_id
    assert payload["narrative"] == "Synthetic report narrative; never displayed publicly."
    assert payload["identifiers"][0]["masked_value"] == "+254 7•• ••• 678"
    assert "allegation" in payload["note"].lower()
    with env.db() as db:
        events = db.execute(
            select(m.AuditEvent).where(
                m.AuditEvent.action == "build4.campaign_report.read",
                m.AuditEvent.actor_id == moderator_id,
            )
        ).scalars().all()
        assert events and events[-1].target_id == report_id
