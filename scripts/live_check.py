"""Start the real server and exercise every endpoint family over real HTTP, then hammer it with concurrent clients.

    python scripts/live_check.py [--requests 600] [--workers 32]

Exit code is non-zero on any failed expectation, any 5xx, or any traceback in the server log.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import random
import secrets
import statistics
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor

import httpx

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PORT = int(os.environ.get("SSI_LIVE_PORT", "8768"))
BASE = f"http://127.0.0.1:{PORT}"
fails: list[str] = []


def expect(cond, msg):
    if not cond:
        fails.append(msg)
        print("  FAIL", msg)
    return cond


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--requests", type=int, default=600); ap.add_argument("--workers", type=int, default=32); a = ap.parse_args()
    tmp = tempfile.mkdtemp(prefix="ssi-live-")
    from cryptography.fernet import Fernet
    env = {**os.environ, "SSI_ENV": "dev", "DATABASE_URL": f"sqlite:///{tmp}/live.db", "STORAGE_DIR": f"{tmp}/ev", "ENCRYPTION_KEY": Fernet.generate_key().decode(), "HMAC_KEY": secrets.token_hex(32),
           "PYTHONPATH": os.pathsep.join(os.path.join(ROOT, p) for p in ("packages/rules", "packages/connectors", "services/api")), "DEV_ECHO_CODES": "1",
           "WHATSAPP_APP_SECRET": "shh", "WHATSAPP_VERIFY_TOKEN": "vt", "AT_CALLBACK_SECRET": "s3cret",
           "RL_CHECKS": "100000/3600", "RL_EVIDENCE": "100000/3600", "RL_REPORTS": "100000/3600", "RL_SEARCH": "100000/3600", "RL_SEARCH_DISTINCT": "100000", "RL_AUTH": "100000/900", "RL_APPEALS": "100000/3600"}
    log = open(f"{tmp}/server.log", "w")
    srv = subprocess.Popen([sys.executable, "-m", "uvicorn", "app.main:app", "--app-dir", "services/api", "--port", str(PORT), "--log-level", "warning"], cwd=ROOT, env=env, stdout=log, stderr=log)
    try:
        for i in range(80):
            try:
                if httpx.get(BASE + "/v1/health").status_code == 200:
                    break
            except Exception:
                time.sleep(0.25)
        else:
            raise SystemExit("server did not start")
        c = httpx.Client(base_url=BASE, timeout=30)
        flows(c, env, tmp)
        load(a.requests, a.workers)
    finally:
        srv.terminate(); srv.wait(10); log.close()
    text = open(f"{tmp}/server.log").read()
    expect("Traceback" not in text, "server log contains a traceback:\n" + text[-1500:])
    expect("4821" not in text and "pending grant" not in text, "message text appeared in the server log")
    print("\nRESULT:", "FAIL (%d)" % len(fails) if fails else "pass")
    return 1 if fails else 0


def flows(c: httpx.Client, env, tmp):
    print("flows over real HTTP")
    r = c.get("/v1/ready"); expect(r.status_code == 200 and r.json()["status"] == "ready", "ready")
    expect(c.get("/openapi.json").status_code == 200 and "/v1/checks" in c.get("/openapi.json").json()["paths"], "openapi")
    expect(c.get("/docs").status_code == 200, "docs page")
    for path in ("/", "/static/app.js", "/static/styles.css", "/static/icon.svg", "/manifest.webmanifest", "/sw.js"):
        expect(c.get(path).status_code == 200, "static " + path)
    expect(c.get("/nope").status_code == 404, "404 shape")
    # headers
    h = c.get("/v1/health").headers; expect(h.get("cache-control") == "no-store" and "x-request-id" in h and h.get("x-content-type-options") == "nosniff", "headers")
    # check + token gate
    j = c.post("/v1/checks", json={"text": "Safaricom: Your M-PESA is locked. Reply with your M-PESA PIN 4821 to unlock it."}).json()
    expect(j["assessment"]["label"] == "high_risk" and j["guest_token"], "high risk check")
    expect(c.get(f"/v1/checks/{j['check_id']}").status_code == 404 and c.get(f"/v1/checks/{j['check_id']}", headers={"X-Guest-Token": j["guest_token"]}).status_code == 200, "token gate")
    expect("4821" not in json.dumps(j), "pin echoed")
    # malformed and hostile requests
    expect(c.post("/v1/checks", content=b"{not json", headers={"content-type": "application/json"}).status_code == 422, "bad json")
    expect(c.post("/v1/checks", json={"text": "x" * 5001}).status_code == 422, "too long")
    expect(c.post("/v1/checks", json={"text": "hello there friend", "category": ["x"]}).status_code == 422, "wrong type")
    expect(c.post("/v1/checks", content=b"\xff\xfe\x00bad", headers={"content-type": "application/json"}).status_code == 422, "binary body")
    expect(c.get("/v1/checks/../../etc/passwd").status_code in (404, 422), "path traversal id")
    expect(c.post("/v1/checks", json={"text": "Pay KSh 350 to activate funds \x00\x07\u202e ok"}).status_code == 201, "control chars")
    big = c.post("/v1/checks", json={"text": "a" * 4999 + "b"}); expect(big.status_code == 201, "5000 chars")
    # evidence over real multipart
    from PIL import Image, ImageDraw, ImageFont
    import io
    try:
        fnt = ImageFont.truetype("arial.ttf", 44)
    except Exception:
        try:
            fnt = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 44)
        except Exception:
            fnt = ImageFont.load_default()
    im = Image.new("RGB", (900, 160), "white"); ImageDraw.Draw(im).text((20, 50), "Pay KSh 350 to activate funds", fill="black", font=fnt); b = io.BytesIO(); im.save(b, "PNG")
    t = c.post("/v1/checks", json={"text": "See the screenshot for the offer details please."}).json(); hdr = {"X-Guest-Token": t["guest_token"]}
    r = c.post(f"/v1/checks/{t['check_id']}/evidence", files={"file": ("s.png", b.getvalue(), "image/png")}, headers=hdr); expect(r.status_code == 201 and r.json()["assessment"]["label"] == "suspicious_verify_first", "evidence upload " + r.text[:200])
    expect(c.post(f"/v1/checks/{t['check_id']}/evidence", files={"file": ("s.png", b"MZ not an image", "image/png")}, headers=hdr).status_code == 400, "bad image")
    expect(c.post(f"/v1/checks/{t['check_id']}/evidence", files={"file": ("s.png", b"\x89PNG\r\n\x1a\n" + b"0" * (6 * 1024 * 1024), "image/png")}, headers=hdr).status_code == 400, "oversize image")
    ex = c.get(f"/v1/checks/{t['check_id']}/export", headers=hdr); expect(ex.status_code == 200 and "submitted_text" in ex.json(), "export")
    expect(c.delete(f"/v1/checks/{t['check_id']}", headers=hdr).status_code == 200 and c.get(f"/v1/checks/{t['check_id']}", headers=hdr).status_code == 404, "delete")
    # accounts, moderator, reports, publication, appeals
    sub = subprocess.run([sys.executable, "-m", "app.cli", "create-user", "--email", "mod@example.com", "--role", "moderator"], cwd=os.path.join(ROOT, "services/api"), env={**env, "SSI_NEW_PASSWORD": "correct horse battery"}, capture_output=True, text=True)
    expect(sub.returncode == 0, "cli create-user: " + sub.stderr[-300:])
    mod = {"Authorization": "Bearer " + c.post("/v1/auth/login", json={"email": "mod@example.com", "password": "correct horse battery"}).json()["token"]}
    ids = []
    for i in range(3):
        u = c.post("/v1/auth/register", json={"email": f"r{i}@example.com", "password": "correct horse battery"}).json()
        r = c.post("/v1/reports", json={"category": "shop", "narrative": f"Paid till 424242 and the seller vanished. Report number {i} with my own details.", "identifiers": [{"type": "till", "value": "424242"}]}, headers={"Authorization": "Bearer " + u["token"]})
        expect(r.status_code == 201, "report " + r.text[:150]); ids.append(r.json()["report_id"])
    expect(c.get("/v1/moderation/queue").status_code == 401 and c.get("/v1/moderation/queue", headers={"Authorization": "Bearer nope"}).status_code == 401, "queue needs login")
    q = c.get("/v1/moderation/queue", headers=mod); expect(q.status_code == 200 and len(q.json()["reports"]) == 3, "queue content")
    for i, rid in enumerate(ids):
        expect(c.post(f"/v1/moderation/reports/{rid}/action", json={"action": "approve", "reason_code": "corroborated", "publish": i == 2}, headers=mod).status_code == 200, "approve")
    s = c.get("/v1/reports/search", params={"type": "till", "value": "424242"}).json(); expect(s["found"] and s["indicator"]["independent_reports"] == 3, "published " + str(s))
    expect("vanished" not in json.dumps(s), "narrative leaked in search")
    chk = c.post("/v1/checks", json={"text": "Please pay for the goods to Till Number 424242 today."}).json()["assessment"]; expect(chk["label"] == "high_risk", "indicator drives high risk: " + chk["label"])
    ap = c.post("/v1/appeals", json={"indicator_id": s["indicator"]["id"], "contact": "owner@shop.example", "issue_type": "correction", "statement": "This till is mine and every customer was refunded in full."}).json()
    expect(c.post(f"/v1/appeals/{ap['appeal_id']}/verify", json={"code": ap["dev_code"]}, headers={"X-Appeal-Token": ap["appeal_token"]}).json()["status"] == "open", "appeal verify")
    expect(c.get("/v1/reports/search", params={"type": "till", "value": "424242"}).json()["indicator"]["status"] == "under_review", "under review")
    expect(c.post(f"/v1/moderation/appeals/{ap['appeal_id']}/resolve", json={"outcome": "upheld", "reason_code": "refunded"}, headers=mod).status_code == 200, "resolve")
    expect(c.get("/v1/reports/search", params={"type": "till", "value": "424242"}).json()["found"] is False, "removed after upheld appeal")
    expect(c.get("/v1/moderation/campaigns", headers=mod).status_code == 200, "campaigns")
    # opportunities, recovery, channels, business claims
    expect(c.get("/v1/opportunities").json()["opportunities"], "opportunities")
    expect(c.post("/v1/recovery", json={"paid": True}).json()["steps"], "recovery")
    body = json.dumps({"entry": [{"changes": [{"value": {"messages": [{"from": "254712345678", "id": "w1", "type": "text", "text": {"body": "Pay KSh 350 to activate funds now"}}]}}]}]}).encode()
    sig = "sha256=" + hmac.new(b"shh", body, hashlib.sha256).hexdigest()
    expect(c.post("/v1/channels/whatsapp/webhook", content=body, headers={"X-Hub-Signature-256": sig}).json() == {"handled": 1}, "whatsapp")
    expect(c.post("/v1/channels/whatsapp/webhook", content=body, headers={"X-Hub-Signature-256": "sha256=00"}).status_code == 403, "whatsapp bad sig")
    expect(c.post("/v1/channels/sms/africastalking/s3cret", data={"from": "+254712345678", "text": "Pay KSh 350 to activate funds now"}).json() == {"handled": 1}, "sms")
    u = c.post("/v1/auth/register", json={"email": "biz@example.com", "password": "correct horse battery"}).json()
    cl = c.post("/v1/business-claims", json={"business_name": "Mama Shop", "domain": "mamashop.co.ke"}, headers={"Authorization": "Bearer " + u["token"]}); expect(cl.status_code == 201, "claim")
    expect(c.post(f"/v1/moderation/business-claims/{cl.json()['claim_id']}/review", json={"status": "approved", "reason_code": "docs_ok"}, headers=mod).status_code == 200, "claim review")
    # URL investigation & diagnostics
    diag = c.get("/v1/system/diagnostics"); expect(diag.status_code == 200 and "ml_engine" in diag.json(), "diagnostics")
    expect("gemini" in diag.json() and "threat_feeds" in diag.json(), "diagnostic services")
    url_res = c.post("/v1/investigate/url", json={"url": "https://www.safaricom.co.ke"}).json()
    expect(url_res["risk_band"] != "high_risk", "safaricom official URL is not falsely accused; seed record remains unreviewed")
    phish_res = c.post("/v1/investigate/url", json={"url": "http://safaricom-line-reactivate.com"}).json()
    expect(phish_res["risk_band"] == "high_risk", "safaricom phish url")
    ssrf_res = c.post("/v1/investigate/url", json={"url": "http://127.0.0.1:8768/v1/health"}).json()
    expect(ssrf_res["risk_band"] in ("blocked", "high_risk"), "ssrf blocked")
    chat_url = c.post("/v1/chat", json={"message": "Check this link: https://www.safaricom.co.ke"}).json()
    expect(chat_url.get("url_investigation") is not None, "chat url investigation attached")
    expect("action_chips" in chat_url, "chat action chips present")
    print("  flows done")


def load(n: int, workers: int):
    print(f"load: {n} requests, {workers} concurrent clients")
    msgs = ["Pay KSh 350 to activate funds", "Hi are we meeting at five?", "Safaricom: reply with your PIN 1234", "Please pay Till Number 424242", "KRA job offer: pay Ksh 500 application fee",
            "bit.ly/abc123 click now", "Samahani nimetuma pesa kwa makosa", "Guaranteed returns 50% weekly!"]
    lat, codes = [], {}

    def one(i):
        c = httpx.Client(base_url=BASE, timeout=60); r = random.Random(i); k = r.random(); t0 = time.perf_counter()
        try:
            if k < 0.6:
                x = c.post("/v1/checks", json={"text": r.choice(msgs) + f" ref {i}"}); code = x.status_code
            elif k < 0.8:
                x = c.get("/v1/reports/search", params={"type": "till", "value": str(100000 + i % 5000)}); code = x.status_code
            elif k < 0.9:
                j = c.post("/v1/checks", json={"text": r.choice(msgs)}).json(); x = c.get(f"/v1/checks/{j['check_id']}", headers={"X-Guest-Token": j["guest_token"]}); code = x.status_code
            elif k < 0.95:
                x = c.post("/v1/reports", json={"category": "shop", "narrative": f"Load test narrative number {i} with enough words to pass validation.", "identifiers": [{"type": "till", "value": str(200000 + i)}]}); code = x.status_code
            else:
                x = c.get("/v1/ready"); code = x.status_code
        except Exception as e:
            code = "EXC " + type(e).__name__
        lat.append(time.perf_counter() - t0); codes[code] = codes.get(code, 0) + 1
    t0 = time.perf_counter()
    with ThreadPoolExecutor(workers) as ex:
        list(ex.map(one, range(n)))
    dur = time.perf_counter() - t0; lat.sort()
    print(f"  {n / dur:.0f} req/s | p50 {statistics.median(lat) * 1000:.0f} ms | p95 {lat[int(len(lat) * .95)] * 1000:.0f} ms | max {lat[-1] * 1000:.0f} ms | status codes {codes}")
    bad = {k: v for k, v in codes.items() if not (isinstance(k, int) and k < 500) or k in (429,)}
    expect(not bad, f"server errors or exceptions under load: {bad}")


if __name__ == "__main__":
    sys.exit(main())
