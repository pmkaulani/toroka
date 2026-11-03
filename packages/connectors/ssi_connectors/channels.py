"""Forward-to-check channels: WhatsApp Cloud API webhook and Africa's Talking SMS callback.

Parsing and signature checks are implemented against the documented payload shapes and tested with samples.
Sending needs real credentials and approved accounts/short codes, so senders are disabled unless configured.
The sender's number is used only to reply and for rate-limit keys (as an HMAC); it is not stored in plaintext.
"""
from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass

import httpx


@dataclass
class Inbound:
    channel: str
    sender: str
    text: str
    message_id: str | None = None


def verify_meta_signature(app_secret: str, body: bytes, header: str | None) -> bool:
    if not header or not header.startswith("sha256="):
        return False
    expected = hmac.new(app_secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, header.split("=", 1)[1])


def parse_whatsapp(payload: dict) -> list[Inbound]:
    out = []
    for entry in payload.get("entry", []):
        for ch in entry.get("changes", []):
            val = ch.get("value", {})
            for m in val.get("messages", []):
                if m.get("type") == "text" and m.get("text", {}).get("body"):
                    out.append(Inbound("whatsapp", m["from"], m["text"]["body"], m.get("id")))
    return out


def parse_africastalking(form: dict) -> Inbound | None:
    if not form.get("from") or not form.get("text"):
        return None
    return Inbound("sms", form["from"], form["text"], form.get("id"))


def format_reply(a: dict, result_url: str | None, *, max_len: int = 600, lang: str = "en") -> str:
    """Short, plain-text, no accusations. Always says what was not checked."""
    from ssi_rules.i18n import localize
    d = localize(a, lang)
    lines = [f"{d['label_text']}."]
    if d["findings"]:
        lines.append(d["findings"][0]["plain_text"])
    if d["next_steps"]:
        lines.append(d["next_steps"][0]["text"])
    gaps = [c["name"] for c in d["coverage"] if c["status"] in ("not_checked", "could_not_check")][:2]
    if gaps:
        lines.append("Not checked: " + "; ".join(gaps) + ".")
    if result_url:
        lines.append(result_url)
    msg = " ".join(lines)
    return msg if len(msg) <= max_len else msg[: max_len - 1].rsplit(" ", 1)[0] + "…"


class WhatsAppSender:
    def __init__(self, token: str, phone_number_id: str, api_version: str = "v21.0", transport: httpx.BaseTransport | None = None):
        self.token, self.pid, self.ver, self.transport = token, phone_number_id, api_version, transport

    def send_text(self, to: str, body: str) -> bool:
        try:
            with httpx.Client(transport=self.transport, timeout=8.0) as c:
                r = c.post(f"https://graph.facebook.com/{self.ver}/{self.pid}/messages", headers={"Authorization": f"Bearer {self.token}"},
                           json={"messaging_product": "whatsapp", "to": to, "type": "text", "text": {"body": body, "preview_url": False}})
            return r.status_code < 300
        except Exception:
            return False


class AfricasTalkingSender:
    def __init__(self, username: str, api_key: str, shortcode: str | None = None, transport: httpx.BaseTransport | None = None,
                 url: str = "https://api.africastalking.com/version1/messaging"):
        self.username, self.key, self.shortcode, self.transport, self.url = username, api_key, shortcode, transport, url

    def send_text(self, to: str, body: str) -> bool:
        data = {"username": self.username, "to": to if to.startswith("+") else "+" + to, "message": body}
        if self.shortcode:
            data["from"] = self.shortcode
        try:
            with httpx.Client(transport=self.transport, timeout=8.0) as c:
                r = c.post(self.url, headers={"apiKey": self.key, "Accept": "application/json"}, data=data)
            return r.status_code < 300
        except Exception:
            return False
