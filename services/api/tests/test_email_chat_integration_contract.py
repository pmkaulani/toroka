from pathlib import Path


API_DIR = Path(__file__).resolve().parents[1]
STATIC = API_DIR / "app" / "static"


def test_email_has_no_separate_tool_button_or_modal():
    html = (STATIC / "index.html").read_text(encoding="utf-8")
    js = (STATIC / "app.js").read_text(encoding="utf-8")
    assert "email-forensics-open" not in html
    assert "email-forensics-dialog" not in html
    assert "Investigate an email" not in html
    assert "initEmailForensics" not in js


def test_normal_composer_accepts_original_email_sources():
    html = (STATIC / "index.html").read_text(encoding="utf-8")
    assert 'id="file"' in html
    assert ".eml" in html and ".headers" in html


def test_raw_email_detection_and_file_upload_share_the_chat_submit_path():
    js = (STATIC / "app.js").read_text(encoding="utf-8")
    assert "function looksLikeRawEmailSource(text)" in js
    assert "async function doEmailCheck" in js
    assert 'api("/v1/email/analyze"' in js
    assert "if (emailFile || rawEmail)" in js
    assert 'renderEmailForensicsResult(result, report)' in js


def test_plain_images_still_use_the_normal_evidence_check():
    js = (STATIC / "app.js").read_text(encoding="utf-8")
    assert "else if (imageFiles.length > 0 || looksLikeEvidence(text, imageFiles))" in js
    assert "await doCheck(text, imageFiles, u.bubble, crossCaseImageConsent)" in js


def test_raw_email_headers_are_not_echoed_into_the_chat_bubble():
    js = (STATIC / "app.js").read_text(encoding="utf-8")
    assert '"Email source provided for investigation"' in js
    assert 'userMsg(displayText, imageUrls, null, fl.map(f => f.name))' in js
