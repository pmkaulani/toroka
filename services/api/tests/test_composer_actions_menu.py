from pathlib import Path

STATIC = Path(__file__).parents[1] / "app" / "static"
HTML = (STATIC / "index.html").read_text(encoding="utf-8")
JS = (STATIC / "app.js").read_text(encoding="utf-8")
CSS = (STATIC / "styles.css").read_text(encoding="utf-8")
I18N = (STATIC / "i18n-chat.js").read_text(encoding="utf-8")

def test_composer_has_one_plus_trigger_and_compact_actions_menu():
    assert 'id="attach" class="icon plus-trigger"' in HTML
    assert 'id="composer-actions-menu" class="composer-actions-menu" role="menu"' in HTML
    assert 'id="menu-add-images"' in HTML and 'id="menu-add-email"' in HTML
    assert 'id="menu-paste"' in HTML
    assert 'data-menu-prompt="menu_prompt_link"' in HTML
    assert 'data-menu-prompt="menu_prompt_shop"' in HTML
    assert 'data-menu-prompt="menu_prompt_payment"' in HTML
    assert HTML.count('id="attach"') == 1

def test_no_separate_email_button_or_email_dialog_remains():
    assert 'id="email-forensics-open"' not in HTML
    assert 'id="email-forensics-dialog"' not in HTML
    assert 'email-tool-entry' not in HTML
    assert 'initEmailForensics' not in JS

def test_eml_and_headers_route_through_the_existing_chat_submit():
    assert 'function looksLikeRawEmailSource(text)' in JS
    assert 'async function doEmailCheck' in JS
    assert 'await doEmailCheck({ file: emailFile' in JS
    assert 'api("/v1/email/analyze"' in JS
    assert 'EMAIL_SOURCE_EXTENSIONS' in JS

def test_plus_menu_has_accessibility_and_localized_labels():
    assert 'aria-haspopup="menu"' in HTML and 'aria-expanded="false"' in HTML
    assert 'role="menuitem"' in HTML
    assert 'ArrowDown' in JS and 'Escape' in JS
    assert 'Object.assign(T.en' in I18N and 'Object.assign(T.sw' in I18N
    assert '.composer-actions-menu[hidden] { display: none; }' in CSS
