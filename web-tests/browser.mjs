// Real-browser test suite (Chromium via Playwright). Starts its own server. Run:  node browser.mjs
// Covers: console/CSP cleanliness, desktop and phone layouts, keyboard-only use, accessibility (axe, WCAG 2.1 AA), offline,
// errors and slow networks, double submit, XSS payloads, screenshot upload, language switch. Screenshots go to $SHOTS (default /tmp/shots).
import { spawn } from "node:child_process";
import { readFileSync, mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import path from "node:path";
import chromium from "@sparticuz/chromium";
import { chromium as pw } from "playwright-core";

const here = path.dirname(fileURLToPath(import.meta.url)), root = path.join(here, "..");
const PORT = process.env.SSI_PORT || "8766", BASE = `http://127.0.0.1:${PORT}`, SHOTS = process.env.SHOTS || "/tmp/shots";
mkdirSync(SHOTS, { recursive: true });
const AXE = readFileSync(path.join(here, "node_modules/axe-core/axe.min.js"), "utf8");
const FIXTURE = path.join(here, "fixture-shot.png");
const tmp = mkdtempSync(path.join(tmpdir(), "ssi-br-"));
const wait = (ms) => new Promise((r) => setTimeout(r, ms));

// ---------- server ----------
import { randomBytes } from "node:crypto";
const serverEnv = { ...process.env, SSI_ENV: "dev", DATABASE_URL: `sqlite:///${tmp}/br.db`, STORAGE_DIR: `${tmp}/ev`, PYTHONPATH: path.join(root, "packages/rules") + ":" + path.join(root, "packages/connectors") + ":" + path.join(root, "services/api"),
  ENCRYPTION_KEY: randomBytes(32).toString("base64").replace(/\+/g, "-").replace(/\//g, "_"), HMAC_KEY: randomBytes(32).toString("hex"),
  RL_CHECKS: "5000/3600", RL_EVIDENCE: "5000/3600", RL_REPORTS: "5000/3600", RL_SEARCH: "5000/3600", RL_SEARCH_DISTINCT: "1000", DEV_ECHO_CODES: "1" };
const server = spawn(process.env.SSI_PY || "python3", ["-m", "uvicorn", "app.main:app", "--app-dir", "services/api", "--port", PORT, "--log-level", "warning"], { cwd: root, stdio: ["ignore", "ignore", "pipe"], env: serverEnv });
let serverErr = ""; server.stderr.on("data", (d) => { serverErr += d; });
for (let i = 0; ; i++) { try { if ((await fetch(BASE + "/v1/health")).ok) break; } catch {} if (i > 60) throw new Error("server did not start\n" + serverErr); await wait(250); }

// ---------- harness ----------
const results = []; let current = "";
async function test(name, fn) { current = name; try { await fn(); results.push([true, name]); console.log("  ok  " + name); } catch (e) { results.push([false, name, e]); console.log("  FAIL " + name + "\n       " + String(e.message || e).split("\n").slice(0, 6).join("\n       ")); } }
const eq = (a, b, m) => { if (a !== b) throw new Error(`${m || "expected equal"}: got ${JSON.stringify(a)}, wanted ${JSON.stringify(b)}`); };
const ok = (c, m) => { if (!c) throw new Error(m || "assertion failed"); };
const has = (s, re, m) => { if (!re.test(s)) throw new Error((m || "text mismatch") + `: ${JSON.stringify(String(s).slice(0, 300))} !~ ${re}`); };

const browser = await pw.launch({ executablePath: await chromium.executablePath(), headless: true, args: ["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu", "--font-render-hinting=none"] });
const DESKTOP = { viewport: { width: 1280, height: 800 }, locale: "en-KE" };
const PHONE = { viewport: { width: 360, height: 740 }, deviceScaleFactor: 2, isMobile: true, hasTouch: true, locale: "en-KE",
  userAgent: "Mozilla/5.0 (Linux; Android 13; Tecno Spark) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Mobile Safari/537.36" };

async function newPage(opts = DESKTOP) {
  const context = await browser.newContext({ ...opts, serviceWorkers: "allow" });
  const page = await context.newPage(); page.problems = []; page.dialogs = [];
  await page.addInitScript(() => { window.__csp = []; document.addEventListener("securitypolicyviolation", (e) => window.__csp.push(`${e.violatedDirective} ${e.blockedURI}`)); });
  page.on("console", (m) => { if (["error", "warning"].includes(m.type())) page.problems.push("console." + m.type() + ": " + m.text()); });
  page.on("pageerror", (e) => page.problems.push("pageerror: " + e.message));
  page.on("response", (r) => { if (r.status() >= 400 && !page.expectErrors) page.problems.push(`HTTP ${r.status()} ${r.url()}`); });
  page.on("dialog", async (d) => { page.dialogs.push(d.message()); await d.dismiss(); });
  await page.goto(BASE + "/"); await page.waitForSelector("#lang-sw"); await page.waitForFunction(() => !!document.querySelector(".logo .runner"));
  return page;
}
const csp = (page) => page.evaluate(() => window.__csp);
const shot = (page, name, full = true) => page.screenshot({ path: path.join(SHOTS, name + ".png"), fullPage: full });
const SAMPLES = {
  high: "Safaricom: Your M-PESA is locked. Reply with your M-PESA PIN 4821 to unlock it.",
  suspicious: "You have a pending grant. Pay KSh 350 to activate funds.",
  inconclusive: "Please see the details here: bit.ly/3AbCdEf thanks",
  none: "Hi, are we still meeting at five near the main stage tomorrow?",
  verified: "Is https://www.safaricom.co.ke/fraud-awareness a real website?",
};
const done = (p) => p.locator(".reply .chips").count();
async function send(p, text) {
  const before = await done(p); await p.fill("#text", text); await p.press("#text", "Enter");
  await p.waitForFunction((n) => document.querySelectorAll(".reply .chips").length > n && !document.querySelector(".think"), before, { timeout: 25000 });
}
const last = (p) => p.locator(".msg.bot").last();
async function runAxe(setup, label, opts = DESKTOP) {
  const ctx = await browser.newContext({ ...opts, bypassCSP: true }); const p = await ctx.newPage();
  await p.goto(BASE + "/"); await p.waitForSelector("#lang-sw"); await p.waitForFunction(() => !!document.querySelector(".logo .runner")); await setup(p);
  await p.addScriptTag({ content: AXE });
  const r = await p.evaluate(async () => await window.axe.run(document, { runOnly: { type: "tag", values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "best-practice"] } }));
  await ctx.close();
  const bad = r.violations.map((v) => `${v.id} (${v.impact}) x${v.nodes.length}: ${v.nodes.slice(0, 2).map((n) => n.target.join(" ")).join(" | ")} :: ${v.help}`);
  if (bad.length) throw new Error(`${label}: ${bad.length} accessibility violation(s)\n` + bad.join("\n"));
}

console.log("Chromium " + browser.version() + " against " + BASE + "\n");
const API = async (m, u, b, h = {}) => { const r = await fetch(BASE + u, { method: m, headers: { "content-type": "application/json", ...h }, body: b ? JSON.stringify(b) : undefined }); return { status: r.status, json: await r.json().catch(() => ({})) }; };
let MOD;
async function moderator() {
  if (MOD) return MOD;
  await new Promise((res, rej) => { const c = spawn("python3", ["-m", "app.cli", "create-user", "--email", "mod-br@example.com", "--role", "moderator"], { cwd: path.join(root, "services/api"), env: { ...serverEnv, SSI_NEW_PASSWORD: "correct horse battery" }, stdio: "ignore" }); c.on("exit", (x) => (x === 0 ? res() : rej(new Error("create moderator failed")))); });
  MOD = { Authorization: "Bearer " + (await API("POST", "/v1/auth/login", { email: "mod-br@example.com", password: "correct horse battery" })).json.token }; return MOD;
}

// ================= first impressions =================
await test("desktop: Toroka opens clean: one question, four suggestions, a runner logo, no console errors or CSP violations", async () => {
  const p = await newPage(); has(await p.title(), /Toroka/); has(await p.textContent("#welcome-h"), /What should we look into\?|What would you like to check/); eq(await p.locator("h1").count(), 1); eq(await p.locator(".suggest button").count(), 4);
  ok((await p.locator(".logo .runner").count()) === 1 && (await p.locator("#welcome .runner.big").count()) === 1, "runner logos");
  ok(await p.locator(".welcome-search-mark svg").isVisible(), "welcome magnifying glass should be visible");
  ok(await p.locator("#text").evaluate((e) => document.activeElement === e), "composer should have focus");
  eq((await csp(p)).length, 0, "CSP violations"); eq(p.problems.length, 0, p.problems.join("; ")); await shot(p, "01-welcome-desktop"); await p.context().close();
});
await test("the runner really animates (and stops), and reduced-motion turns the animation off", async () => {
  const p = await newPage(); const anim = () => p.evaluate(() => getComputedStyle(document.querySelector(".logo .runner .leg-f")).animationName);
  await wait(300); has(await anim(), /swing/, "should be running at load"); await p.waitForFunction(() => !document.querySelector(".logo .runner").classList.contains("run"), null, { timeout: 6000 }); eq(await anim(), "none", "should rest afterwards");
  await p.locator(".logo").hover(); await wait(200); has(await anim(), /swing/, "runs when hovered");
  await p.context().close(); const q = await newPage(); await q.emulateMedia({ reducedMotion: "reduce" }); await q.evaluate(() => document.querySelector(".logo .runner").classList.add("run")); eq(await q.evaluate(() => getComputedStyle(document.querySelector(".logo .runner .leg-f")).animationName), "none"); await q.context().close();
});
await test("phone 360px: welcome fits with no sideways scrolling and the composer sits at the bottom of the screen", async () => {
  const p = await newPage(PHONE); const o = await p.evaluate(() => [document.documentElement.scrollWidth, document.documentElement.clientWidth]); ok(o[0] <= o[1], `overflow ${o}`);
  const b = await p.locator("#composer .box").boundingBox(); ok(b.y + b.height <= 740 && b.y > 400, "composer position " + JSON.stringify(b)); await shot(p, "02-welcome-phone"); await p.context().close();
});

// ================= automatic email recognition =================
await test("email sources use the normal chat composer: no special email button or dialog", async () => {
  const p = await newPage();
  eq(await p.locator("#email-forensics-open").count(), 0, "separate email action must be removed");
  eq(await p.locator("#email-forensics-dialog").count(), 0, "email modal must be removed");
  has(await p.getAttribute("#file", "accept"), /\.eml/);
  let emailCalls = 0, checkCalls = 0;
  await p.route("**/v1/checks", async (r) => { if (r.request().method() === "POST") checkCalls++; await r.continue(); });
  await p.route("**/v1/email/analyze", async (r) => {
    emailCalls++;
    await r.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({
      attention_level: "review_recommended", summary: "The visible sender and reply address use different domains.",
      sender_identity: { from: [{ display_name: "Account Security", address: "security@example.com" }], from_domain: "example.com", reply_to: [{ address: "reply@other.example" }] },
      authentication: { trusted_receiver_results: [], untrusted_header_claims: [], dkim_signature_count: 0 },
      findings: [{ code: "reply_to_domain_mismatch", title: "Reply address differs", detail: "The reply address uses another domain." }],
      links: { items: [] }, attachments: { items: [] }, routing: { hops: [] }, limitations: ["A domain mismatch alone does not prove fraud."]
    }) });
  });
  await p.locator("#file").setInputFiles({ name: "notice.eml", mimeType: "message/rfc822", buffer: Buffer.from("From: security@example.com\r\nTo: user@example.net\r\nSubject: Account notice\r\n\r\nPlease review this message.") });
  ok(await p.locator(".attachment-document-item").isVisible(), "email should appear as a normal composer attachment");
  await p.press("#text", "Enter");
  await p.waitForSelector(".email-results-chat .email-attention");
  eq(emailCalls, 1, "email forensic route should be called once"); eq(checkCalls, 0, "email source must not be sent through image evidence route");
  has(await p.locator(".email-results-chat").innerText(), /Reply address differs/);
  await p.context().close();
});

// ================= the conversation =================
await test("chat: message sent, Toroka thinks (runner runs), then replies; PIN never shown; flagged words marked in my message", async () => {
  const p = await newPage(); const bodies = []; p.on("response", async (r) => { if (r.url().includes("/v1/")) { try { bodies.push(await r.text()); } catch {} } });
  await p.route("**/v1/checks", async (r) => { if (r.request().method() === "POST") await wait(1200); await r.continue(); });
  await p.fill("#text", SAMPLES.high); await p.press("#text", "Enter"); await p.waitForSelector(".think"); ok(await p.locator(".think").evaluate((e) => e.closest(".msg").querySelector(".runner").classList.contains("run")), "runner should run while thinking");
  has(await p.textContent(".think"), /Reading|Checking|Looking|Ninasoma|Ninakagua/); eq(await p.inputValue("#text"), "", "composer cleared"); has(await p.textContent("#thread"), /Safaricom: Your M-PESA is locked/);
  await p.waitForFunction(() => document.querySelectorAll(".reply .chips").length > 0 && !document.querySelector(".think"), null, { timeout: 25000 });
  has(await p.textContent(".reply .pill"), /High risk/); const all = await p.innerText("#thread"); ok(!/4821/.test(all), "PIN in thread"); ok(!bodies.some((b) => b.includes("4821")), "PIN in a response"); has(all, /••••/);
  ok((await p.locator(".bubble mark").count()) >= 1, "flagged phrase not marked"); await p.waitForFunction(() => /Toroka replied/.test(document.querySelector("#status").textContent)); ok(await p.evaluate(() => document.activeElement.id === "text"), "focus should return to the box");
  ok(!/scammer|fraudster/i.test(all), "accusatory wording"); eq(await p.evaluate(() => document.querySelector("#welcome").hidden), true); eq((await csp(p)).length, 0); eq(p.problems.length, 0, p.problems.join("; ")); await shot(p, "03-chat-high-desktop"); await p.context().close();
});
await test("chat: all five outcomes read clearly, with five different shapes; only 'Verified' has a tick", async () => {
  const p = await newPage(); const seen = {};
  for (const [k, text] of Object.entries(SAMPLES)) { await send(p, text); const pill = last(p).locator(".pill"); seen[k] = { label: await pill.textContent(), icon: await pill.innerHTML() }; await shot(p, "04-reply-" + k, false); }
  has(seen.high.label, /High risk/); has(seen.suspicious.label, /Suspicious/); has(seen.inconclusive.label, /Inconclusive/); has(seen.none.label, /No known threats found/); has(seen.verified.label, /Verified/);
  eq(new Set(Object.values(seen).map((s) => s.icon)).size, 5, "five different pill icons"); ok(seen.verified.icon.includes("M8.5 12") && !seen.none.icon.includes("M8.5 12"), "tick only on verified");
  has(await p.innerText("#thread"), /not a guarantee/i); await p.context().close();
});
await test("verified website: says it is genuine, shows the source and date, and still warns: don't pay in advance, even half", async () => {
  const p = await newPage(); await send(p, SAMPLES.verified); const r = last(p); has(await r.locator(".pill").textContent(), /Verified/);
  const txt = await r.innerText(); has(txt, /official website of Safaricom/i); has(txt, /genuine, not that every offer/i); has(txt, /typing its address yourself/); ok(!txt.includes("not even half"), "verified site must not get an unconditional payment warning");
  await r.locator("summary", { hasText: "Sources and search leads" }).click(); has(await r.innerText(), /verified 2026-/i); ok((await r.locator("a[href^='https://safaricom.co.ke']").count()) >= 1, "source link"); await shot(p, "05-verified-desktop", false); await p.context().close();
  const q = await newPage(PHONE); await send(q, SAMPLES.verified); await shot(q, "06-verified-phone"); const o = await q.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth); ok(o <= 0, "overflow " + o); await q.context().close();
});
await test("shops and websites always carry the no-advance-payment warning; a deposit request on a verified site is not excused", async () => {
  const p = await newPage(); await send(p, "Selling sneakers on Instagram @kicks_ke, KSh 1,500, delivery in Nairobi");
  has(await last(p).innerText(), /independently verify the seller|verify the seller|recipient/i);
  ok(!(await last(p).innerText()).includes("Don't pay in advance, not even half"), "generic shop identity must not trigger an absolute deposit warning");
  await send(p, "Pay half now to reserve, details at https://www.safaricom.co.ke/shop"); has(await last(p).locator(".pill").textContent(), /Suspicious/); has(await last(p).innerText(), /pay in advance, even partly/i); await p.context().close();
});
await test("a moderator-verified shop (by site and by Instagram handle) is recognised, and revoking it takes effect at once", async () => {
  const auth = await moderator(); const rec = { id: "mama-mboga", name: "Mama Mboga Shop", entity_type: "online_shop", domains: ["mamamboga.co.ke"], handles: ["instagram:mama_mboga_ke"], basis: "moderator_verified_documents", evidence_note: "Business certificate and the till name matched the shop name.", source_url: "https://example.org/proof/mama-mboga", last_verified_at: new Date().toISOString().slice(0, 10), reviewer: "A. Reviewer" };
  eq((await API("PUT", "/v1/admin/verified-entities", rec, auth)).status, 200); eq((await API("PUT", "/v1/admin/verified-entities", { ...rec, id: "bad", domains: ["bad.vercel.app"] }, auth)).status, 422);
  const p = await newPage(); await send(p, "Is https://www.mamamboga.co.ke a real shop?"); has(await last(p).locator(".pill").textContent(), /Verified/); await send(p, "Selling on Instagram @mama_mboga_ke, pay on delivery in Nairobi"); has(await last(p).locator(".pill").textContent(), /Verified/);
  await send(p, "See https://mamamboga.co.ke.evil.example.com/shop"); ok(!/Verified/.test(await last(p).locator(".pill").textContent()), "lookalike must not be verified");
  eq((await API("POST", "/v1/moderation/verified-entities/mama-mboga/revoke", { reason_code: "complaints" }, auth)).status, 200); await send(p, "Is https://www.mamamboga.co.ke a real shop?"); ok(!/Verified/.test(await last(p).locator(".pill").textContent()), "revoked");
  await p.context().close();
});
await test("details are folded away by default and open with the keyboard; next steps are visible straight away", async () => {
  const p = await newPage(); await send(p, SAMPLES.suspicious); const r = last(p); ok(await r.locator("ol li").first().isVisible(), "next steps visible"); eq(await r.locator("details[open]").count(), 0, "details closed");
  await r.locator("summary").first().focus(); await p.keyboard.press("Enter"); eq(await r.locator("details[open]").count(), 1); has(await r.locator("details[open]").innerText(), /pending|asks for money|up front/i); await p.context().close();
});
await test("Enter sends, Shift+Enter makes a new line, the send button is disabled when there is nothing to send, and the box grows", async () => {
  const p = await newPage(); eq(await p.isDisabled("#send"), true); await p.fill("#text", "line one"); eq(await p.isDisabled("#send"), false);
  await p.press("#text", "Shift+Enter"); await p.keyboard.type("line two"); has(await p.inputValue("#text"), /line one\nline two/); eq(await p.locator(".msg").count(), 0, "must not send yet");
  const h1 = await p.locator("#text").evaluate((e) => e.offsetHeight); await p.fill("#text", "x\n".repeat(6)); ok((await p.locator("#text").evaluate((e) => e.offsetHeight)) > h1, "textarea should grow"); await p.context().close();
});
await test("double Enter sends once", async () => {
  const p = await newPage(); let posts = 0; await p.route("**/v1/checks", async (r) => { if (r.request().method() === "POST") { posts++; await wait(700); } await r.continue(); });
  await p.fill("#text", SAMPLES.suspicious); await p.press("#text", "Enter"); await p.press("#text", "Enter"); await p.waitForSelector(".reply .chips", { timeout: 20000 }); eq(posts, 1); eq(await p.locator(".msg.user").count(), 1); await p.context().close();
});

// ================= screenshots =================
await test("screenshots: attach with the paperclip (real file chooser), remove one, send a screenshot alone, and Toroka reads it", async () => {
  const p = await newPage(); const [fc] = await Promise.all([p.waitForEvent("filechooser"), p.click("#attach")]); await fc.setFiles([FIXTURE, FIXTURE]); await p.waitForSelector("#attachments:not([hidden])"); eq(await p.locator("#attachments li").count(), 2);
  eq(await p.isDisabled("#send"), false, "a screenshot alone can be sent"); await p.locator("#attachments button").first().click(); eq(await p.locator("#attachments li").count(), 1); await p.press("#text", "Enter");
  await p.waitForSelector(".reply .chips", { timeout: 25000 }); has(await last(p).locator(".pill").textContent(), /Suspicious/); ok((await p.locator(".bubble img").count()) === 1, "thumbnail in my message");
  await last(p).locator("summary", { hasText: "checked" }).click(); has(await last(p).innerText(), /screenshot/i); eq(await p.locator("#attachments").isHidden(), true); await shot(p, "07-screenshot-reply", false); await p.context().close();
});
await test("screenshots: pasting an image and dropping an image both attach it; wrong types and server rejections are explained in the chat", async () => {
  const p = await newPage(); await p.evaluate(async () => { const c = document.createElement("canvas"); c.width = 40; c.height = 40; c.getContext("2d").fillRect(0, 0, 40, 40); const b = await new Promise((r) => c.toBlob(r, "image/png"));
    const dt = new DataTransfer(); dt.items.add(new File([b], "p.png", { type: "image/png" })); document.getElementById("text").dispatchEvent(new ClipboardEvent("paste", { clipboardData: dt, bubbles: true, cancelable: true }));
    const dt2 = new DataTransfer(); dt2.items.add(new File([b], "d.png", { type: "image/png" })); window.dispatchEvent(new DragEvent("drop", { dataTransfer: dt2, bubbles: true, cancelable: true })); });
  eq(await p.locator("#attachments li").count(), 2); await p.locator("#attachments button").first().click(); await p.locator("#attachments button").first().click();
  writeFileSync(path.join(tmp, "note.txt"), "hello"); const [fc] = await Promise.all([p.waitForEvent("filechooser"), p.click("#attach")]); await fc.setFiles(path.join(tmp, "note.txt")); await p.waitForSelector("#errors:not([hidden])"); has(await p.textContent("#errors"), /PNG, JPEG or WebP/);
  p.expectErrors = true; writeFileSync(path.join(tmp, "fake.png"), "MZ definitely not an image"); const [fc2] = await Promise.all([p.waitForEvent("filechooser"), p.click("#attach")]); await fc2.setFiles(path.join(tmp, "fake.png")); await p.fill("#text", "Please look at my screenshot of the offer"); await p.press("#text", "Enter");
  await p.waitForFunction(() => /couldn't finish|could not use that file/i.test(document.querySelector("#thread").textContent), null, { timeout: 25000 }); await p.context().close();
});

// ================= other things you can ask =================
await test("lookup by chat: ask, give a Till number, get an honest 'no reports is not proof'; bad input is asked for again", async () => {
  const p = await newPage(); await p.click("#sug3"); await p.waitForFunction(() => /Send me the phone number, Till, Paybill or website/.test(document.querySelector("#thread").textContent)); await p.fill("#text", "hello?"); await p.press("#text", "Enter"); await p.waitForFunction(() => /couldn't read that/.test(document.querySelector("#thread").textContent));
  await p.fill("#text", "till 654321"); await p.press("#text", "Enter"); await p.waitForFunction(() => /not proof of anything[\s\S]*paste it and I'll read that too/.test(document.querySelector("#thread").textContent)); await shot(p, "08-lookup", false);
  await p.fill("#text", "0712 345 678"); await p.press("#text", "Enter"); await p.waitForFunction(() => (document.querySelector("#thread").textContent.match(/No published reports/g) || []).length === 2); await p.context().close();
});
await test("recovery by chat: four quick questions with buttons, then calm steps that promise nothing", async () => {
  const p = await newPage(); await p.click("#sug4"); for (const name of ["Yes", "No", "Not sure", "No"]) { await p.locator(".chips button:not(:disabled)", { hasText: new RegExp("^" + name + "$") }).last().click(); }
  await p.waitForFunction(() => /Stop any further payments/.test(document.querySelector("#thread").textContent), null, { timeout: 15000 }); has(await p.textContent("#thread"), /cannot reverse payments/); has(await p.textContent("#thread"), /not your fault/i); await shot(p, "09-recovery", false); await p.context().close();
});
await test("report by chat after a result: asks for the number, then the story, then gives a receipt code", async () => {
  const p = await newPage(); await send(p, SAMPLES.suspicious); await last(p).locator(".chips button", { hasText: "Report this" }).click(); await p.waitForFunction(() => /What is the phone number, Till, Paybill or website to report/.test(document.querySelector("#thread").textContent));
  await p.fill("#text", "paybill 889900"); await p.press("#text", "Enter"); await p.waitForFunction(() => /What happened/.test(document.querySelector("#thread").textContent)); await p.fill("#text", "I paid this paybill for goods and the seller never replied again."); await p.press("#text", "Enter");
  await p.waitForSelector(".reply code", { timeout: 15000 }); ok((await p.textContent(".reply code")).length > 20); has(await p.textContent("#thread"), /private and a moderator/); await p.context().close();
});
await test("appeal by chat: a published entry can be questioned, verified with a code, and then shows as under review", async () => {
  const auth = await moderator(); const ids = [];
  for (let i = 0; i < 2; i++) { const u = (await API("POST", "/v1/auth/register", { email: `rep${i}-br@example.com`, password: "correct horse battery" })).json;
    ids.push((await API("POST", "/v1/reports", { category: "shop", narrative: `Paid this till for goods, then the seller vanished. Account ${i} of the same payment problem.`, identifiers: [{ type: "till", value: "777777" }] }, { Authorization: "Bearer " + u.token })).json.report_id); }
  for (const [i, id] of ids.entries()) eq((await API("POST", `/v1/moderation/reports/${id}/action`, { action: "approve", reason_code: "corroborated", publish: i === 1 }, auth)).status, 200);
  const p = await newPage(); await p.click("#sug3"); await p.fill("#text", "till 777777"); await p.press("#text", "Enter"); await p.waitForSelector(".pill:has-text('Reviewed entry')"); has(await p.innerText("#thread"), /2 independent reports/); ok(!/vanished|Account 0/.test(await p.innerText("#thread")), "narrative leaked");
  await p.locator(".chips button", { hasText: "This is mine and it is wrong" }).click(); await p.fill("#text", "owner@shop.example"); await p.press("#text", "Enter"); await p.waitForFunction(() => /What is wrong/.test(document.querySelector("#thread").textContent));
  const [ar] = await Promise.all([p.waitForResponse((r) => r.url().endsWith("/v1/appeals") && r.request().method() === "POST"), (async () => { await p.fill("#text", "This till belongs to my genuine shop and every customer was refunded in full."); await p.press("#text", "Enter"); })()]); const ap = await ar.json();
  await p.waitForFunction(() => /Enter it to open your request/.test(document.querySelector("#thread").textContent)); await p.fill("#text", ap.dev_code === "000000" ? "111111" : "000000"); await p.press("#text", "Enter"); await p.waitForFunction(() => /code isn't right/.test(document.querySelector("#thread").textContent));
  await p.fill("#text", ap.dev_code); await p.press("#text", "Enter"); await p.waitForFunction(() => /Verified\. The entry shows as under review/.test(document.querySelector("#thread").textContent));
  await p.fill("#text", "till 777777"); await p.press("#text", "Enter"); await p.waitForFunction(() => /under review/.test(document.querySelector("#thread").textContent.split("Verified. The entry")[1] || "")); await shot(p, "10-under-review", false); await p.context().close();
});
await test("delete and download from the chat: the check is really gone, and the download holds my own data", async () => {
  const p = await newPage(); await send(p, SAMPLES.suspicious); const id = await p.evaluate(() => Object.keys(sessionStorage).find((k) => k.startsWith("ssi.t.")).slice(6)); const tok = await p.evaluate((i) => sessionStorage.getItem("ssi.t." + i), id);
  const [dl] = await Promise.all([p.waitForEvent("download"), last(p).locator(".chips button", { hasText: "Download my data" }).click()]); eq(dl.suggestedFilename(), "my-check.json"); has(JSON.parse(readFileSync(await dl.path(), "utf8")).submitted_text, /pending grant/);
  await last(p).locator(".chips button", { hasText: "Delete this check" }).click(); await p.waitForFunction(() => /Deleted/.test(document.querySelector("#thread").textContent)); eq((await p.request.get(`${BASE}/v1/checks/${id}`, { headers: { "X-Guest-Token": tok } })).status(), 404); await p.context().close();
});
await test("Kiswahili: the page, the placeholder and Toroka's replies switch language (English first, then back)", async () => {
  const p = await newPage(); await p.click("#lang-sw"); eq(await p.getAttribute("html", "lang"), "sw"); has(await p.textContent("#welcome-h"), /Tuchunguze nini|Ungependa kukagua nini/); has(await p.getAttribute("#text", "placeholder"), /Bandika ujumbe/); eq(await p.getAttribute("#lang-sw", "aria-pressed"), "true");
  await send(p, SAMPLES.suspicious); has(await last(p).locator(".pill").textContent(), /Una shaka/); await send(p, SAMPLES.verified); has(await last(p).locator(".pill").textContent(), /Imethibitishwa/); has(await last(p).innerText(), /jina la mpokeaji|thibitisha muuzaji/i); ok(!(await last(p).innerText()).includes("Usilipe mapema, hata nusu"), "verified site must not receive an unconditional advance-payment warning"); await shot(p, "11-swahili", false);
  await p.click("#lang-en"); has(await p.getAttribute("#text", "placeholder"), /Paste a message/); await p.context().close();
});
await test("New chat clears the conversation and returns to the welcome screen", async () => {
  const p = await newPage(); await send(p, SAMPLES.suspicious); await p.click("#new-chat"); eq(await p.locator(".msg").count(), 0); eq(await p.locator("#welcome").isVisible(), true); ok(await p.evaluate(() => document.activeElement.id === "text")); await p.context().close();
});

// ================= keyboard and screen reader =================
await test("keyboard only: skip link first, sensible order, a visible focus ring on every stop, suggestions work with Enter", async () => {
  const p = await newPage(); await p.focus("#skip"); const stops = [{ id: "skip", text: "Skip to the message box", outline: "solid", w: 3, inBox: false, tag: "A" }];
  for (let i = 0; i < 20; i++) { await p.keyboard.press("Tab"); const s = await p.evaluate(() => { const e = document.activeElement, cs = getComputedStyle(e); return { id: e.id, tag: e.tagName, text: (e.getAttribute("aria-label") || e.textContent || "").trim().slice(0, 28), outline: cs.outlineStyle, w: parseFloat(cs.outlineWidth), inBox: !!e.closest(".box") }; }); if (s.tag === "BODY") break; stops.push(s); }
  ok(await p.evaluate(() => document.querySelector("a.skip") === document.querySelector("body").firstElementChild), "skip link must be first in the page"); const ids = stops.map((s) => s.id || s.text); ok(ids.indexOf("lang-sw") < ids.indexOf("sug1") && ids.indexOf("sug4") < ids.indexOf("text"), "order: " + ids.join(" > ")); ok(stops.length >= 10, "stops " + stops.length);
  const bad = stops.filter((s) => !s.inBox && (s.outline === "none" || s.w < 2)); eq(bad.length, 0, "no focus ring: " + JSON.stringify(bad));
  await p.focus("#sug2"); await p.keyboard.press("Enter"); await p.waitForFunction(() => /Send me the link[\s\S]*I will say so|I'll say so/.test(document.querySelector("#thread").textContent) && document.activeElement.id === "text", null, { timeout: 15000 }); await p.context().close();
});
await test("screen reader: the conversation is a labelled list, each message says who spoke, and each reply is announced once it is complete", async () => {
  const p = await newPage(); await send(p, SAMPLES.suspicious); eq(await p.getAttribute("#thread", "aria-label"), "Conversation"); eq(await p.evaluate(() => document.querySelector("#thread").tagName), "OL");
  has(await p.innerText(".msg.user .sr-only") || await p.locator(".msg.user .sr-only").textContent(), /You said/); has(await p.locator(".msg.bot .sr-only").first().textContent(), /Toroka replied/);
  await p.waitForFunction(() => /Toroka replied:/.test(document.querySelector("#status").textContent)); eq(await p.getAttribute("#status", "aria-live"), "polite"); ok(!(await p.locator("#thread[aria-live], .reply[aria-live]").count()), "streaming text must not be a live region");
  ok((await p.locator("svg:not([aria-hidden=true])").count()) === 0, "decorative svg must be hidden"); await p.context().close();
});

// ================= when things go wrong =================
await test("server error, rate limit and offline: a kind message in the chat, and the text comes back to the box", async () => {
  const p = await newPage(); p.expectErrors = true; let mode = "500";
  await p.route("**/v1/checks", (r) => r.request().method() !== "POST" ? r.continue() : mode === "500" ? r.fulfill({ status: 500, contentType: "application/json", body: JSON.stringify({ detail: "Something went wrong on our side. Nothing was concluded about your message." }) }) : mode === "429" ? r.fulfill({ status: 429, headers: { "retry-after": "60" }, contentType: "application/json", body: "{}" }) : r.continue());
  await p.fill("#text", SAMPLES.suspicious); await p.press("#text", "Enter"); await p.waitForFunction(() => /back in the box/.test(document.querySelector("#thread").textContent)); eq(await p.inputValue("#text"), SAMPLES.suspicious); has(await p.textContent("#thread"), /Nothing was concluded/);
  mode = "429"; await p.press("#text", "Enter"); await p.waitForFunction(() => /Too many requests[\s\S]*back in the box/.test(document.querySelector("#thread").textContent)); eq(await p.inputValue("#text"), SAMPLES.suspicious); mode = "ok"; await p.press("#text", "Enter"); await p.waitForSelector(".reply .pill", { timeout: 20000 }); await p.context().close();
});
await test("hostile text is shown as plain words: no script runs, no element is injected, no dialog opens", async () => {
  const p = await newPage(); const payload = `<img src=x onerror="window.__x=1"> "><script>window.__x=2</script> <svg onload="window.__x=3"> javascript:alert(1) Pay KSh 350 to activate funds`;
  await send(p, payload); eq(await p.evaluate(() => window.__x), undefined, "script executed"); eq(p.dialogs.length, 0); eq(await p.locator("#thread img, #thread script, #thread iframe, #thread [onload], #thread [onerror]").count(), 0); has(await p.innerText("#thread"), /<img src=x/); eq((await csp(p)).length, 0);
  await send(p, "🎉 Hongera! Umeshinda ZAWADI 🎁 Tuma KSh 500: مرحبا 你好 \u202Eevil\u202C"); eq(p.problems.length, 0, p.problems.join("; ")); await p.context().close();
});
await test("a very long message with an unbroken string does not break the layout on a phone", async () => {
  const p = await newPage(PHONE); await send(p, ("Pay KSh 350 to activate funds " + "A".repeat(400) + " https://example.com/" + "x".repeat(300)).slice(0, 5000)); const o = await p.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth); ok(o <= 0, "overflow " + o); await p.context().close();
});

// ================= phone layout and touch =================
await test("phone: a full conversation has no sideways scrolling and every control is at least 44px; text at 200% still fits", async () => {
  const p = await newPage(PHONE); const problems = [];
  const audit = async (label) => { const r = await p.evaluate(() => { const out = [], vis = (e) => { const b = e.getBoundingClientRect(); return b.width > 0 && b.height > 0 && getComputedStyle(e).visibility !== "hidden"; };
    for (const e of document.querySelectorAll("button, summary, a[href], textarea")) { if (!vis(e) || e.closest(".sr-only") || e.matches(".skip")) continue; const b = e.getBoundingClientRect(); if (b.height < 43.5 || (e.matches("button") && b.width < 43.5)) out.push(`${e.tagName} "${(e.getAttribute("aria-label") || e.textContent || e.id).trim().slice(0, 24)}" ${Math.round(b.width)}x${Math.round(b.height)}`); }
    return { out, over: document.documentElement.scrollWidth - document.documentElement.clientWidth }; }); r.out.forEach((x) => problems.push(label + ": " + x)); if (r.over > 0) problems.push(label + ": overflow " + r.over); };
  await audit("welcome"); await send(p, SAMPLES.high); await audit("high"); await send(p, SAMPLES.verified); await audit("verified"); await last(p).locator("summary").first().click(); await audit("details open"); await shot(p, "12-phone-chat");
  await p.click("#lang-sw"); await audit("swahili"); eq(problems.length, 0, "\n" + problems.join("\n"));
  await p.evaluate(() => { document.documentElement.style.fontSize = "200%"; }); await wait(250); const o = await p.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth); ok(o <= 1, "200% overflow " + o); await p.context().close();
});

// ================= install, offline, links =================
await test("installable: valid manifest named Toroka, service worker takes control, API responses are never cached", async () => {
  const p = await newPage(); const m = await (await p.request.get(BASE + "/manifest.webmanifest")).json(); eq(m.name, "Toroka"); eq(m.display, "standalone"); ok(m.share_target && m.icons.length);
  await p.waitForFunction(async () => { const r = await navigator.serviceWorker.getRegistration(); return !!(r && r.active); }, null, { timeout: 15000 }); await p.reload(); await p.waitForFunction(() => !!navigator.serviceWorker.controller, null, { timeout: 15000 });
  const cached = await p.evaluate(async () => { const out = []; for (const k of await caches.keys()) for (const r of await (await caches.open(k)).keys()) out.push(new URL(r.url).pathname); return out; });
  ok(cached.includes("/static/app.js") && cached.includes("/static/i18n.js") && cached.includes("/"), "shell not cached: " + cached); ok(!cached.some((x) => x.startsWith("/v1/")), "API cached"); await p.context().close();
});
await test("offline: the app still opens; sending explains the problem kindly and keeps the text; reconnecting works", async () => {
  const p = await newPage(); await p.waitForFunction(async () => { const r = await navigator.serviceWorker.getRegistration(); return !!(r && r.active); }, null, { timeout: 15000 }); await p.reload(); await p.waitForFunction(() => !!navigator.serviceWorker.controller);
  await p.context().setOffline(true); await p.reload(); has(await p.textContent("#welcome-h"), /What should we look into\?|What would you like to check/); p.expectErrors = true; await p.fill("#text", SAMPLES.suspicious); await p.press("#text", "Enter");
  await p.waitForFunction(() => /offline/i.test(document.querySelector("#thread").textContent)); eq(await p.inputValue("#text"), SAMPLES.suspicious); await p.context().setOffline(false); await p.press("#text", "Enter"); await p.waitForSelector(".reply .pill", { timeout: 20000 }); await p.context().close();
});
await test("a shared result link (#r=…) opens in the chat and the token leaves the address bar; the share target fills the box", async () => {
  const r = (await API("POST", "/v1/checks", { text: SAMPLES.suspicious })).json; const ctx = await browser.newContext(DESKTOP); const p = await ctx.newPage(); await p.goto(`${BASE}/#r=${r.check_id}.${r.guest_token}`);
  await p.waitForSelector(".reply .pill", { timeout: 20000 }); has(await p.textContent(".reply .pill"), /Suspicious/); await wait(200); eq(await p.evaluate(() => location.hash), ""); ok(!p.url().includes(r.guest_token)); await ctx.close();
  const c2 = await browser.newContext(DESKTOP); const q = await c2.newPage(); await q.goto(BASE + "/?title=Offer&text=Pay%20KSh%20350%20to%20activate&url=https%3A%2F%2Fexample.com%2Fx"); await q.waitForSelector("#text"); has(await q.inputValue("#text"), /Offer\nPay KSh 350/); eq(await q.isDisabled("#send"), false); await c2.close();
});
await test("security headers reach the browser: inline script is blocked and framing is denied", async () => {
  const p = await newPage(); await p.evaluate(() => { const s = document.createElement("script"); s.textContent = "window.__inline = 1"; document.body.append(s); }); eq(await p.evaluate(() => window.__inline), undefined);
  ok((await csp(p)).some((v) => /script-src/.test(v))); has((await p.request.get(BASE + "/")).headers()["content-security-policy"], /frame-ancestors 'none'/); await p.context().close();
});

// ================= accessibility (axe-core: WCAG 2.1 A and AA + best practice, colour contrast in a real renderer) =================
await test("axe: welcome screen has no violations (English, Kiswahili, phone)", async () => { await runAxe(async () => {}, "welcome en"); await runAxe(async (p) => { await p.click("#lang-sw"); }, "welcome sw"); await runAxe(async () => {}, "welcome phone", PHONE); });
for (const [k, text] of Object.entries(SAMPLES)) {
  await test(`axe: a ${k} reply (with every section open) has no violations in English, Kiswahili and on a phone`, async () => {
    const setup = async (p) => { await send(p, text); await p.evaluate(() => document.querySelectorAll("details").forEach((d) => { d.open = true; })); };
    await runAxe(setup, k + " en"); await runAxe(async (p) => { await p.click("#lang-sw"); await setup(p); }, k + " sw"); await runAxe(setup, k + " phone", PHONE);
  });
}
await test("axe: a shop reply, the recovery flow, an error message and attached screenshots have no violations", async () => {
  await runAxe(async (p) => { await send(p, "Selling sneakers on Instagram @kicks_ke, KSh 1,500, delivery in Nairobi"); }, "shop");
  await runAxe(async (p) => { await p.click("#sug4"); await p.waitForSelector(".chips button"); }, "recovery chips", PHONE);
  await runAxe(async (p) => { const [fc] = await Promise.all([p.waitForEvent("filechooser"), p.click("#attach")]); await fc.setFiles(FIXTURE); await p.waitForSelector("#attachments:not([hidden])"); await p.evaluate(() => { const e = document.getElementById("errors"); e.textContent = "Only PNG, JPEG or WebP images, please."; e.hidden = false; }); }, "attachments and error");
});

await browser.close(); server.kill();
const failed = results.filter((r) => !r[0]); console.log(`\n${results.length - failed.length}/${results.length} browser tests passed`); console.log("Screenshots in " + SHOTS);
if (serverErr.includes("Traceback")) { console.log("\nSERVER TRACEBACK:\n" + serverErr.slice(0, 2000)); }
process.exit(failed.length || serverErr.includes("Traceback") ? 1 : 0);
