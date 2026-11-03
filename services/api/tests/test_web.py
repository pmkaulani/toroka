"""Static checks on Toroka's front end: design tokens meet the accessibility thresholds; the shell is CSP-safe, installable and fully translated."""
import json
import re
from pathlib import Path

STATIC = Path(__file__).parents[1] / "app" / "static"
CSS = (STATIC / "styles.css").read_text(encoding="utf-8")
JS = (STATIC / "app.js").read_text(encoding="utf-8")


def tokens():
    root = re.search(r":root\s*{(.*?)}", CSS, re.S).group(1)
    return dict(re.findall(r"--([\w-]+):\s*(#[0-9A-Fa-f]{6})", root))


def lum(h):
    r, g, b = [int(h.lstrip("#")[i:i + 2], 16) / 255 for i in (0, 2, 4)]
    f = lambda c: c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4
    return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b)


def ratio(a, b):
    x, y = sorted((lum(a), lum(b)), reverse=True)
    return (x + 0.05) / (y + 0.05)


def test_text_tokens_meet_wcag_aa_on_every_surface():
    t = tokens()
    for fg, bgs in {"ink": ["canvas", "surface", "risk-bg", "verify-bg", "none-bg", "unknown-bg", "verified-bg"], "text-secondary": ["canvas", "surface", "unknown-bg"],
                    "action-hover": ["canvas", "surface"], "risk-fg": ["surface", "risk-bg"], "verify-fg": ["surface", "verify-bg"], "none-fg": ["surface", "none-bg"],
                    "unknown-fg": ["surface", "unknown-bg"], "verified-fg": ["surface", "verified-bg"]}.items():
        for bg in bgs:
            assert ratio(t[fg], t[bg]) >= 4.5, (fg, bg, ratio(t[fg], t[bg]))
    assert ratio("#FFFFFF", t["action"]) >= 4.5 and ratio("#FFFFFF", t["action-hover"]) >= 4.5      # send button and primary actions


def test_controls_and_focus_meet_non_text_contrast():
    t = tokens()
    for bg in ("surface", "canvas"):
        assert ratio(t["border-control"], t[bg]) >= 3.0 and ratio(t["focus"], t[bg]) >= 3.0, bg
    assert ratio(t["border-subtle"], t["surface"]) < 3.0                    # decorative only: never used on a control
    assert re.search(r"\.box\s*{[^}]*border: 1px solid var\(--border-control\)", CSS) and re.search(r"\.suggest button\s*{[^}]*var\(--border-control\)", CSS)
    assert "border-subtle" not in re.search(r"\.chips button\s*{[^}]*}", CSS).group(0)


def test_touch_targets_focus_and_reduced_motion_are_specified():
    assert "--target: 44px" in CSS and "min-height: var(--target)" in CSS and ":focus-visible" in CSS
    anim = CSS[CSS.index("@media (prefers-reduced-motion: no-preference)"):]
    assert "animation" in anim and ".runner.run" in anim                       # every animation sits behind the motion preference
    assert not re.search(r"^\s*\.runner\.run[^{]*{[^}]*animation", CSS[:CSS.index("@media (prefers-reduced-motion: no-preference)")], re.M)


def test_status_is_never_colour_only_and_only_verified_has_a_tick():
    assert "label_text" in JS and "aria-hidden" in JS and "the only shape with a tick" in JS and "never a tick" in JS
    assert JS.count("M8.5 12l2.5") == 1


def test_shell_is_csp_safe_and_installable(env):
    html = (STATIC / "index.html").read_text()
    assert '<html lang="en">' in html and "viewport-fit=cover" in html and 'rel="manifest"' in html and html.count("<h1") == 1
    assert not re.search(r"<script(?![^>]*src=)", html) and " style=" not in html and not re.search(r"\son\w+=", html)
    assert html.index('class="skip"') < html.index("<header") and 'aria-label="Message Toroka"' in html and 'role="status"' in html
    m = json.loads((STATIC / "manifest.webmanifest").read_text())
    assert m["name"] == "Toroka" and m["display"] == "standalone" and m["share_target"]["method"] == "GET"
    sw = (STATIC / "sw.js").read_text(); assert "/v1/" in sw and "startsWith" in sw and "/static/i18n.js" in sw
    r = env.client.get("/")
    assert r.status_code == 200 and "Toroka" in r.text and "script-src 'self'" in r.headers["content-security-policy"] and "frame-ancestors 'none'" in r.headers["content-security-policy"]
    for path in ("/static/app.js", "/static/i18n.js", "/static/i18n-chat.js", "/static/styles.css", "/static/icon.svg", "/sw.js"):
        assert env.client.get(path).status_code == 200, path
    assert env.client.get("/manifest.webmanifest").headers["content-type"].startswith("application/manifest+json")


def _keys(lang_marker_start, lang_marker_end, text):
    a = text.index(lang_marker_start)
    return set(re.findall(r"(?:^|[\s,{])([a-z][a-z_0-9]*):\s*[\"`]", text[a:text.index(lang_marker_end, a + 1)]))


def test_every_string_the_app_uses_exists_in_english_and_kiswahili():
    base = (STATIC / "i18n.js").read_text(); chat = (STATIC / "i18n-chat.js").read_text()
    en = _keys("en: {", "\n  sw: {", base) | _keys("Object.assign(T.en", "Object.assign(T.sw", chat)
    sw = _keys("\n  sw: {", "};", base) | _keys("Object.assign(T.sw", "});\n", chat + "});\n")
    used = set(re.findall(r"\bt\(\"([a-z][a-z_0-9]*)\"\)", JS)) | {f"ev_{x}" for x in ("verified_source", "moderated_report", "automated_observation", "unresolved_claim")} \
        | {f"st_{x}" for x in ("strong", "supporting", "weak")} | {"cov_checked", "cov_not_checked", "cov_could_not_check", "cov_not_found"} | {f"sug{n}" for n in range(1, 5)} | {f"sug{n}_r" for n in range(1, 5)} | {f"q_{k}" for k in ("paid", "shared_credentials", "installed_app", "sent_id_documents")}
    assert used, "no strings found"
    assert not (used - en), f"missing in English: {sorted(used - en)}"
    assert not (used - sw), f"missing in Kiswahili: {sorted(used - sw)}"


def test_welcome_actions_match_their_real_workflows_without_account_gate():
    html = (STATIC / "index.html").read_text()
    assert 'id="welcome-h" data-t-key="welcome_hi">What would you like to investigate?' in html
    assert len(re.findall(r'data-sug="[1-4]"', html)) == 4
    assert 'id="sug4"' in html and 'data-t-key="sug4_t">I already paid or shared something' in html
    assert 'data-t-key="sug4_d">Get calm next steps' in html
    assert not re.search(r'<(?:a|button|form)\b[^>]*(?:login|log-in|sign.?up|register)', html, re.I)
    assert 'id="new-check-btn"' in html and 'id="text"' in html and 'id="attach"' in html
    assert 'data-t-key="local_note"' in html and 'id="open-safety-btn"' in html


def test_history_search_bookmarks_and_attachment_privacy_are_supported():
    html = (STATIC / "index.html").read_text()
    assert 'id="nav-search-btn"' in html and 'id="nav-saved-btn"' in html
    assert 'id="sidebar-search-input"' in html and 'id="top-search-input"' in html
    assert "function toggleSavedConversation(id)" in JS and '"aria-pressed": String(!!c.saved)' in JS
    assert "function messagesForLocalStorage(messages)" in JS
    assert 'return { ...msg, imgs: [], attachmentNames:' in JS
    assert "No account is required" in (STATIC / "i18n-chat.js").read_text()


def test_safety_topics_are_keyboard_accessible_and_context_hides_during_chat():
    html = (STATIC / "index.html").read_text()
    assert len(re.findall(r'<button type="button" class="scam-topic-card"', html)) == 4
    assert 'class="topic-desc"' in html and not re.search(r'<p\s+class="topic-desc"', html)
    assert ".app-layout.chat-active .context-panel { display: none; }" in CSS
    assert ".scam-topic-card:focus-visible" in CSS
    assert "prefers-reduced-motion: reduce" in CSS


def test_conversation_design_uses_open_content_and_hides_dashboard_rail():
    html = (STATIC / "index.html").read_text()
    css = CSS
    assert ".context-panel { display: none !important; }" in css
    assert ".prompt-card-icon { display: none !important; }" in css
    assert ".suggest .prompt-action-card" in css and "border: 0;" in css
    assert ".reply details:last-of-type" in css and "border: 0;" in css
    assert 'id="welcome-h"' in html and 'id="thread"' in html
    assert "headingMatch" in JS and "container.appendChild(heading)" in JS
