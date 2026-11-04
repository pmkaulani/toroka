from __future__ import annotations

import base64

from toroka_email_forensics import analyze_email


def _raw(headers: str = "", body: str = "Hello") -> bytes:
    base = headers or (
        "From: Example Sender <sender@example.org>\r\n"
        "To: recipient@example.net\r\n"
        "Subject: A normal message\r\n"
        "Date: Wed, 05 Nov 2026 00:00:00 +0300\r\n"
        "Message-ID: <test@example.org>\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
    )
    return (base + "\r\n" + body).encode("utf-8")


def test_basic_email_analysis_does_not_return_or_store_body():
    raw = _raw(body="Unique private sentence that must not be returned by Toroka.")
    result = analyze_email(raw)
    assert result["status"] == "analysis_complete"
    assert result["privacy"]["raw_email_stored"] is False
    assert result["privacy"]["raw_email_returned"] is False
    assert "Unique private sentence" not in str(result)
    assert result["sender_identity"]["from_domain"] == "example.org"


def test_from_reply_to_domain_mismatch_is_reported():
    raw = _raw(
        "From: Finance <finance@company.example>\r\n"
        "Reply-To: approvals@outside.example\r\n"
        "Return-Path: <bounce@company.example>\r\n"
        "Received: from sender.company.example by mx.receiver.example; Wed, 05 Nov 2026 00:00:00 +0300\r\n"
        "Subject: Invoice update\r\n",
    )
    result = analyze_email(raw)
    assert "FROM_REPLY_TO_DOMAIN_MISMATCH" in {f["code"] for f in result["findings"]}


def test_display_name_brand_claim_against_lookalike_domain_is_flagged():
    raw = _raw(
        "From: Microsoft Account Security <security@microsoft-account-verify.example>\r\n"
        "Reply-To: help@unrelated.example\r\n"
        "Subject: Action required\r\n"
    )
    result = analyze_email(raw)
    finding = next(f for f in result["findings"] if f["code"] == "DISPLAY_NAME_BRAND_DOMAIN_MISMATCH")
    assert finding["severity"] == "high"
    assert result["attention_level"] == "high_attention"


def test_authentication_results_are_untrusted_by_default():
    raw = _raw(
        "Received: from relay.example.net by mx.google.com with ESMTPS; Wed, 05 Nov 2026 00:00:00 +0300\r\n"
        "Authentication-Results: mx.google.com; spf=fail smtp.mailfrom=example.org; dkim=fail; dmarc=fail\r\n"
        "From: Sender <sender@example.org>\r\n"
    )
    result = analyze_email(raw)
    assert result["authentication"]["trusted_receiver_results"] == []
    assert result["authentication"]["untrusted_header_claims"][0]["results"]["dmarc"] == "fail"
    assert "AUTH_RESULTS_NOT_TRUSTED" in {f["code"] for f in result["findings"]}


def test_authentication_results_need_allowlisted_authserv_and_newest_received_hop():
    raw = _raw(
        "Received: from relay.example.net by mx.google.com with ESMTPS; Wed, 05 Nov 2026 00:00:00 +0300\r\n"
        "Authentication-Results: mx.google.com; spf=pass smtp.mailfrom=example.org; dkim=pass header.d=example.org; dmarc=pass header.from=example.org\r\n"
        "From: Sender <sender@example.org>\r\n"
    )
    result = analyze_email(raw, trusted_authserv_ids=("mx.google.com",))
    trusted = result["authentication"]["trusted_receiver_results"]
    assert len(trusted) == 1
    assert trusted[0]["results"]["dmarc"] == "pass"
    assert "TRUSTED_DMARC_PASS" in {f["code"] for f in result["findings"]}


def test_allowlisted_authserv_is_not_trusted_if_not_in_newest_received_hop():
    raw = _raw(
        "Received: from relay.example.net by mx.receiver.example with ESMTPS; Wed, 05 Nov 2026 00:00:00 +0300\r\n"
        "Authentication-Results: mx.google.com; dmarc=pass\r\n"
        "From: Sender <sender@example.org>\r\n"
    )
    result = analyze_email(raw, trusted_authserv_ids=("mx.google.com",))
    assert result["authentication"]["trusted_receiver_results"] == []


def test_html_link_destination_mismatch_is_reported_without_fetching_link():
    raw = (
        "From: Microsoft <account@microsoft.com>\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: text/html; charset=utf-8\r\n\r\n"
        "<p>Sign in at <a href='https://login-attacker.example/auth'>https://login.microsoft.com</a></p>"
    ).encode()
    result = analyze_email(raw)
    assert "LINK_TEXT_DESTINATION_MISMATCH" in {f["code"] for f in result["findings"]}
    assert result["links"]["items"][0]["destination_domain"] == "login-attacker.example"


def test_url_shortener_and_punycode_are_detected_as_context():
    raw = _raw(body="Visit https://bit.ly/abc and https://xn--pple-43d.example/login")
    result = analyze_email(raw)
    codes = {code for item in result["links"]["items"] for code in item["warning_codes"]}
    assert "url_shortener" in codes
    assert "punycode_hostname" in codes


def test_attachment_metadata_only_and_executable_type_warning():
    binary = b"MZ" + (b"\x00" * 100)
    encoded = base64.b64encode(binary).decode()
    raw = (
        "From: Sender <sender@example.org>\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: multipart/mixed; boundary=BOUND\r\n\r\n"
        "--BOUND\r\nContent-Type: text/plain\r\n\r\nPlease review.\r\n"
        "--BOUND\r\nContent-Type: application/octet-stream; name=invoice.exe\r\n"
        "Content-Disposition: attachment; filename=invoice.exe\r\n"
        "Content-Transfer-Encoding: base64\r\n\r\n" + encoded + "\r\n--BOUND--\r\n"
    ).encode()
    result = analyze_email(raw)
    assert result["attachments"]["count"] == 1
    assert result["attachments"]["content_opened"] is False
    assert result["attachments"]["executed"] is False
    assert "ACTIVE_ATTACHMENT_TYPE" in {f["code"] for f in result["findings"]}
    assert result["attachments"]["items"][0]["sha256"]


def test_multiple_from_headers_create_ambiguity_finding():
    raw = _raw(
        "From: One <one@example.org>\r\n"
        "From: Two <two@example.net>\r\n"
        "Subject: Ambiguous\r\n"
    )
    result = analyze_email(raw)
    assert "MULTIPLE_OR_INVALID_FROM" in {f["code"] for f in result["findings"]}


def test_dns_checks_are_not_run_without_explicit_opt_in():
    result = analyze_email(_raw())
    assert result["privacy"]["external_dns_queries_performed"] is False
    assert result["authentication"]["dns_posture"]["status"] == "not_requested"


def test_oversized_message_is_rejected():
    import pytest
    from toroka_email_forensics.analyzer import MAX_EMAIL_BYTES
    with pytest.raises(ValueError, match="5 MB"):
        analyze_email(b"From: x@example.org\r\n\r\n" + (b"x" * (MAX_EMAIL_BYTES + 1)))


def test_untrusted_return_path_difference_is_not_high_severity():
    raw = _raw(
        "From: Updates <updates@example.org>\r\n"
        "Return-Path: <bounce@bulk-mail.example>\r\n"
    )
    result = analyze_email(raw)
    finding = next(f for f in result["findings"] if f["code"] == "FROM_RETURN_PATH_DOMAIN_DIFFERENCE")
    assert finding["severity"] == "informational"


def test_authentication_claims_are_not_reused_as_real_verification_without_trust():
    raw = _raw(
        "Authentication-Results: mx.google.com; spf=pass; dkim=pass; dmarc=pass\r\n"
        "From: Sender <sender@example.org>\r\n"
    )
    result = analyze_email(raw)
    codes = {f["code"] for f in result["findings"]}
    assert "TRUSTED_DMARC_PASS" not in codes
    assert result["authentication"]["trusted_receiver_results"] == []


def test_pasted_full_headers_api_endpoint_is_guest_accessible_and_private(env):
    raw = (
        "From: Example <sender@example.org>\r\n"
        "To: user@example.net\r\n"
        "Subject: Example\r\n"
        "Date: Wed, 05 Nov 2026 00:00:00 +0300\r\n\r\n"
        "Private body phrase that should never be reflected."
    )
    response = env.client.post("/v1/email/analyze", data={"raw_email": raw})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["privacy"]["raw_email_stored"] is False
    assert "Private body phrase" not in response.text


def test_email_api_rejects_both_file_and_pasted_content(env):
    response = env.client.post(
        "/v1/email/analyze",
        data={"raw_email": "From: a@example.org\n\nhello"},
        files={"file": ("mail.eml", b"From: b@example.org\n\nhello", "message/rfc822")},
    )
    assert response.status_code == 422


def test_email_api_rejects_binary_msg_format(env):
    response = env.client.post(
        "/v1/email/analyze", files={"file": ("mail.msg", b"\x00\x01\x02binary", "application/octet-stream")}
    )
    assert response.status_code == 415


def test_email_api_rejects_oversized_upload(env):
    from toroka_email_forensics.analyzer import MAX_EMAIL_BYTES
    response = env.client.post(
        "/v1/email/analyze", files={"file": ("large.eml", b"x" * (MAX_EMAIL_BYTES + 1), "message/rfc822")}
    )
    assert response.status_code == 413


def test_email_api_accepts_original_eml_upload(env):
    raw = b"From: sender@example.org\r\nTo: user@example.net\r\nSubject: Original\r\n\r\nHello"
    response = env.client.post("/v1/email/analyze", files={"file": ("original.eml", raw, "message/rfc822")})
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "analysis_complete"


def test_sender_idn_domain_is_highlighted_as_context():
    raw = _raw("From: Support <help@xn--pple-43d.example>\r\n")
    result = analyze_email(raw)
    assert "SENDER_INTERNATIONALIZED_DOMAIN" in {f["code"] for f in result["findings"]}


def test_html_active_link_scheme_is_flagged_without_execution():
    raw = (
        "From: Sender <sender@example.org>\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: text/html; charset=utf-8\r\n\r\n"
        "<a href='javascript:alert(1)'>Open invoice</a>"
    ).encode()
    result = analyze_email(raw)
    assert "NON_HTTP_ACTIVE_LINK_SCHEME" in {f["code"] for f in result["findings"]}


def test_dkim_signature_domain_alignment_is_reported():
    raw = _raw(
        "From: Accounts <accounts@company.example>\r\n"
        "DKIM-Signature: v=1; a=rsa-sha256; d=mailer.example; s=s1; b=abc;\r\n"
    )
    result = analyze_email(raw)
    assert result["authentication"]["dkim_signatures"][0]["signing_domain"] == "mailer.example"
    assert result["authentication"]["dkim_signatures"][0]["aligned_with_from"] is False
    assert "DKIM_SIGNING_DOMAIN_NOT_ALIGNED" in {f["code"] for f in result["findings"]}
