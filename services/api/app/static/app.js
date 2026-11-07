"use strict";
/* Toroka: a chat interface over the Smart Scam Identifier API. No framework, no inline script or style (CSP); all text is set with textContent. */
let lang = "en";
const $ = (s, r = document) => r.querySelector(s);
const t = k => (T[lang] && T[lang][k]) || T.en[k] || k;
const NS = "http://www.w3.org/2000/svg";
const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;
const COV = { checked: "cov_checked", not_checked: "cov_not_checked", could_not_check: "cov_could_not_check", not_found: "cov_not_found" };
const LABEL_PREFIX = /^(High risk|Suspicious\. Verify first|Verified|Hatari kubwa|Una shaka\. Thibitisha kwanza|Imethibitishwa)\.\s*/;
const MAX_FILES = 5, MAX_BYTES = 5 * 1024 * 1024, OK_TYPES = ["image/png", "image/jpeg", "image/webp"];
const EMAIL_SOURCE_EXTENSIONS = [".eml", ".headers", ".txt"];
const isEmailSourceFile = file => !!file && EMAIL_SOURCE_EXTENSIONS.some(ext => String(file.name || "").toLowerCase().endsWith(ext));
const isImageFile = file => !!file && OK_TYPES.includes(file.type);
const STORAGE_KEY = "toroka_conversations";
let current = null, pending = null, files = [], busy = false, activeRecovery = null, chatHistory = [], activeConversationId = null, convMessages = [], isReplaying = false;
let sidebarView = "recent", sidebarSearchQuery = "", lastSidebarFocus = null;

function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) { if (v === false || v == null) continue; if (k === "text") el.textContent = v; else el.setAttribute(k, v === true ? "" : v); }
  for (const kid of kids.flat()) if (kid != null) el.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  return el;
}
function svg(w, ...parts) {
  const s = document.createElementNS(NS, "svg"); s.setAttribute("viewBox", "0 0 24 24"); s.setAttribute("aria-hidden", "true"); s.setAttribute("focusable", "false"); s.setAttribute("class", w || "");
  for (const d of parts) { const p = document.createElementNS(NS, "path"); p.setAttribute("d", d); p.setAttribute("fill", "none"); p.setAttribute("stroke", "currentColor"); p.setAttribute("stroke-width", "2"); p.setAttribute("stroke-linecap", "round"); p.setAttribute("stroke-linejoin", "round"); s.append(p); }
  return s;
}
function say(msg) { const s = $("#status"); s.textContent = ""; setTimeout(() => { s.textContent = msg; }, 30); }
function showError(msg) { const e = $("#errors"); e.textContent = msg; e.hidden = false; e.focus(); }
function clearError() { const e = $("#errors"); e.hidden = true; e.textContent = ""; }
class Err extends Error {}

/* ---------- the runner (Toroka means "run away") ---------- */
function runner(extra = "") {
  const s = document.createElementNS(NS, "svg"); s.setAttribute("viewBox", "0 0 48 48"); s.setAttribute("class", "runner " + extra); s.setAttribute("aria-hidden", "true"); s.setAttribute("focusable", "false");
  const g = (cls, ...kids) => { const e = document.createElementNS(NS, "g"); e.setAttribute("class", cls); kids.forEach(k => e.append(k)); return e; };
  const p = (d, cls) => { const e = document.createElementNS(NS, "path"); e.setAttribute("d", d); if (cls) e.setAttribute("class", cls); return e; };
  const head = document.createElementNS(NS, "circle"); head.setAttribute("cx", "31"); head.setAttribute("cy", "9"); head.setAttribute("r", "4.4"); head.setAttribute("class", "head");
  s.append(g("all", head, p("M29 15 L23 29"), g("arm-b", p("M28 18 L21 22 L17 19")), g("arm-f", p("M28 18 L34 24 L39 20")),
    g("leg-b", p("M23 29 L16 34"), g("shin-b", p("M16 34 L10 37"))), g("leg-f", p("M23 29 L30 35"), g("shin-f", p("M30 35 L29 43")))));
  return s;
}
function run(el, ms) { el.classList.add("run"); if (ms) setTimeout(() => el.classList.remove("run"), ms); }
function pillIcon(label) {
  if (label === "high_risk") return svg("", "M8 2h8l6 6v8l-6 6H8l-6-6V8z", "M12 7v6M12 16.5v.5");
  if (label === "suspicious_verify_first") return svg("", "M12 3 22 20H2z", "M12 10v5M12 17.5v.5");
  if (label === "inconclusive") return svg("", "M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18z", "M9.5 9.5a2.5 2.5 0 1 1 3.5 2.3c-.7.4-1 1-1 1.7M12 17v.5");
  if (label === "verified_official") return svg("", "M12 3 20 6v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z", "M8.5 12l2.5 2.500 4.500-5");     // the only shape with a tick
  return svg("", "M12 3 20 6v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z", "M9 12h6");                                               // "no known threats": a dash, never a tick
}

/* ---------- Local conversation storage ---------- */
function loadStoredConversations() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    const parsed = raw ? JSON.parse(raw) : [];
    return Array.isArray(parsed) ? parsed.filter(c => c && typeof c.id === "string") : [];
  } catch (_) { return []; }
}
function saveStoredConversations(list) {
  try { localStorage.setItem(STORAGE_KEY, JSON.stringify(list)); } catch (_) {}
}
function getConversation(id) {
  return loadStoredConversations().find(c => c.id === id);
}
function deleteConversation(id) {
  let convs = loadStoredConversations().filter(c => c.id !== id);
  saveStoredConversations(convs);
  if (activeConversationId === id) newChat();
  else renderSidebarHistory();
}
function formatRelativeTime(ts) {
  const diffSec = Math.floor((Date.now() - ts) / 1000);
  if (diffSec < 60) return t("time_just_now");
  const diffMin = Math.floor(diffSec / 60);
  if (diffMin < 60) return diffMin + t("time_m_ago");
  const diffHours = Math.floor(diffMin / 60);
  if (diffHours < 24) return diffHours + t("time_h_ago");
  const diffDays = Math.floor(diffHours / 24);
  return diffDays + t("time_d_ago");
}
function latestAttachmentNames(messages = convMessages) {
  const last = [...messages].reverse().find(msg => msg && msg.role === "user" && ((msg.attachmentNames && msg.attachmentNames.length) || (msg.imgs && msg.imgs.length)));
  if (!last) return [];
  return Array.isArray(last.attachmentNames) && last.attachmentNames.length ? last.attachmentNames.slice(0, MAX_FILES) : [t("saved_attachment")];
}
function messagesForLocalStorage(messages) {
  return messages.map(msg => {
    if (!msg || msg.role !== "user") return msg;
    const names = Array.isArray(msg.attachmentNames) ? msg.attachmentNames : [];
    const hadImages = Array.isArray(msg.imgs) && msg.imgs.length > 0;
    return { ...msg, imgs: [], attachmentNames: names.length ? names : (hadImages ? [t("saved_attachment")] : []) };
  });
}
function saveOrUpdateCurrentConversation(title, lastText) {
  if (isReplaying) return;
  const convs = loadStoredConversations();
  if (!activeConversationId) {
    activeConversationId = "c_" + Date.now() + "_" + Math.random().toString(36).slice(2, 7);
    const newConv = {
      id: activeConversationId,
      title: title || (lastText ? lastText.slice(0, 36) : t("btn_new_check")),
      snippet: lastText ? lastText.slice(0, 60) : "",
      updatedAt: Date.now(),
      saved: false,
      convMessages: messagesForLocalStorage(convMessages),
      chatHistory: [...chatHistory],
      checkCurrent: current ? { id: current.id, token: current.token, text: current.text, data: current.data, attachmentNames: latestAttachmentNames() } : null
    };
    convs.unshift(newConv);
  } else {
    const idx = convs.findIndex(c => c.id === activeConversationId);
    if (idx >= 0) {
      if (title) convs[idx].title = title;
      if (lastText) convs[idx].snippet = lastText.slice(0, 60);
      convs[idx].updatedAt = Date.now();
      convs[idx].convMessages = messagesForLocalStorage(convMessages);
      convs[idx].chatHistory = [...chatHistory];
      if (current) convs[idx].checkCurrent = { id: current.id, token: current.token, text: current.text, data: current.data, attachmentNames: latestAttachmentNames() };
    }
  }
  saveStoredConversations(convs.slice(0, 50));
  renderSidebarHistory();
}
function toggleSavedConversation(id) {
  const convs = loadStoredConversations();
  const conv = convs.find(c => c.id === id);
  if (!conv) return;
  conv.saved = !conv.saved;
  saveStoredConversations(convs);
  renderSidebarHistory();
  say(conv.saved ? t("saved_now") : t("unsaved_now"));
}
function renderSidebarHistory(filter = undefined) {
  const container = $("#sidebar-history");
  if (!container) return;

  if (filter === "saved") {
    sidebarView = "saved";
    sidebarSearchQuery = "";
  } else if (typeof filter === "string") {
    sidebarSearchQuery = filter.trim();
    sidebarView = sidebarSearchQuery ? "search" : "recent";
  }

  const query = sidebarSearchQuery.toLocaleLowerCase();
  const topSearch = $("#top-search-input");
  const sideSearch = $("#sidebar-search-input");
  if (topSearch && topSearch.value !== sidebarSearchQuery) topSearch.value = sidebarSearchQuery;
  if (sideSearch && sideSearch.value !== sidebarSearchQuery) sideSearch.value = sidebarSearchQuery;

  let convs = loadStoredConversations();
  if (sidebarView === "saved") convs = convs.filter(c => c.saved);
  if (query) convs = convs.filter(c => (c.title && c.title.toLocaleLowerCase().includes(query)) || (c.snippet && c.snippet.toLocaleLowerCase().includes(query)));

  const savedNav = $("#nav-saved-btn"), searchNav = $("#nav-search-btn");
  if (savedNav) savedNav.classList.toggle("active", sidebarView === "saved");
  if (searchNav) searchNav.classList.toggle("active", sidebarView === "search");
  if (savedNav) savedNav.setAttribute("aria-pressed", String(sidebarView === "saved"));
  if (searchNav) searchNav.setAttribute("aria-pressed", String(sidebarView === "search"));

  container.replaceChildren();
  if (!convs.length) {
    let emptyText = t("no_recent_chats");
    if (sidebarView === "saved") emptyText = t("no_saved_checks");
    else if (sidebarView === "search") emptyText = t("no_search_results");
    container.append(h("div", { class: "sidebar-empty", text: emptyText }));
    return;
  }

  for (const c of convs) {
    const item = h("div", { class: "history-item" + (c.id === activeConversationId ? " active" : ""), role: "listitem" });
    const content = h("button", { type: "button", class: "history-item-content", "aria-current": c.id === activeConversationId ? "page" : false },
      h("span", { class: "history-item-title", text: c.title || t("btn_new_check") }),
      h("span", { class: "history-item-sub" },
        h("span", { class: "history-item-time", text: formatRelativeTime(c.updatedAt || Date.now()) }),
        c.snippet ? h("span", { class: "history-item-snippet", text: "· " + c.snippet }) : null
      )
    );
    content.addEventListener("click", () => switchConversation(c.id));

    const actions = h("div", { class: "history-item-actions" });
    const saveBtn = h("button", {
      type: "button",
      class: "history-item-save" + (c.saved ? " is-saved" : ""),
      "aria-label": t(c.saved ? "unsave_check" : "save_check"),
      title: t(c.saved ? "unsave_check" : "save_check"),
      "aria-pressed": String(!!c.saved)
    }, svg("", "M19 21l-7-5-7 5V5a2 2 0 0 1 2-2h10a2 2 0 0 1 2 2z"));
    saveBtn.addEventListener("click", e => { e.stopPropagation(); toggleSavedConversation(c.id); });

    const delBtn = h("button", {
      type: "button",
      class: "history-item-del",
      "aria-label": t("delete_chat_title"),
      title: t("delete_chat_title")
    }, svg("", "M3 6h18M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"));
    delBtn.addEventListener("click", e => {
      e.stopPropagation();
      if (confirm(t("confirm_delete_chat"))) deleteConversation(c.id);
    });

    actions.append(saveBtn, delBtn);
    item.append(content, actions);
    container.append(item);
  }
}
async function switchConversation(id) {
  const conv = getConversation(id);
  if (!conv) return;
  closeMobileSidebar(false);
  activeConversationId = id;
  $("#app-layout")?.classList.add("chat-active");
  thread().replaceChildren();
  thread().hidden = false;
  $("#welcome").hidden = true;
  files = [];
  renderFiles();

  const titleEl = $("#header-main-title");
  if (titleEl && conv.title) titleEl.textContent = conv.title;

  chatHistory = conv.chatHistory ? [...conv.chatHistory] : [];
  current = conv.checkCurrent ? { ...conv.checkCurrent } : null;

  isReplaying = true;
  try {
    if (conv.convMessages && conv.convMessages.length) {
      convMessages = [...conv.convMessages];
      for (const msg of conv.convMessages) {
        if (msg.role === "user") {
          userMsg(msg.text, msg.imgs || [], msg.tKey, msg.attachmentNames || []);
        } else if (msg.role === "bot") {
          await botSay(msg.text, null, msg.tKey);
        } else if (msg.role === "check") {
          if (msg.data) {
            current = { id: msg.check_id || (msg.data && msg.data.check_id), token: msg.token, text: msg.text, data: msg.data };
            await renderCheck(msg.data, msg.text || "", null);
          } else if (msg.check_id) {
            const th = think();
            try {
              const d = await api(`/v1/checks/${msg.check_id}?lang=${lang}`, { headers: msg.token ? { "X-Guest-Token": msg.token } : {} });
              th.stop();
              current = { id: msg.check_id, token: msg.token, text: msg.text, data: d };
              await renderCheck(d, msg.text || "", null);
            } catch (e) {
              th.stop();
              await botSay(t("sorry") + " " + e.message);
            }
          }
        }
      }
    } else {
      // Legacy conversations or single checks saved before convMessages:
      convMessages = [];
      if (conv.checkCurrent && conv.checkCurrent.id) {
        const checkText = conv.checkCurrent.text || "";
        const attachmentNames = Array.isArray(conv.checkCurrent.attachmentNames) ? conv.checkCurrent.attachmentNames : [];
        if (checkText || attachmentNames.length) {
          const displayText = checkText || t("count_shots");
          userMsg(displayText, [], checkText ? null : "count_shots", attachmentNames);
          convMessages.push({ role: "user", text: displayText, imgs: [], attachmentNames, tKey: checkText ? null : "count_shots" });
        }
        if (conv.checkCurrent.data) {
          await renderCheck(conv.checkCurrent.data, checkText, null);
          convMessages.push({ role: "check", text: checkText, check_id: conv.checkCurrent.id, data: conv.checkCurrent.data });
        } else {
          const th = think();
          try {
            const d = await api(`/v1/checks/${conv.checkCurrent.id}?lang=${lang}`, {
              headers: conv.checkCurrent.token ? { "X-Guest-Token": conv.checkCurrent.token } : {}
            });
            th.stop();
            current = { id: conv.checkCurrent.id, token: conv.checkCurrent.token, text: conv.checkCurrent.text, data: d };
            await renderCheck(d, conv.checkCurrent.text || "", null);
            convMessages.push({ role: "check", text: conv.checkCurrent.text, check_id: conv.checkCurrent.id, data: d });
          } catch (e) {
            th.stop();
            if (conv.snippet) {
              await botSay(conv.snippet);
              convMessages.push({ role: "bot", text: conv.snippet });
            }
          }
        }
      } else if (conv.chatHistory && conv.chatHistory.length) {
        for (const msg of conv.chatHistory) {
          if (msg.role === "user") {
            userMsg(msg.text, msg.imgs || []);
            convMessages.push({ role: "user", text: msg.text, imgs: msg.imgs || [] });
          } else {
            await botSay(msg.text);
            convMessages.push({ role: "bot", text: msg.text });
          }
        }
      } else if (conv.snippet) {
        await botSay(conv.snippet);
        convMessages.push({ role: "bot", text: conv.snippet });
      }
    }
  } finally {
    isReplaying = false;
  }

  thread().lastElementChild?.scrollIntoView({ block: "end" });
  renderSidebarHistory();
  box().focus();
}

/* ---------- Theme ---------- */
function initTheme() {
  const saved = localStorage.getItem("toroka_theme") || "light";
  applyTheme(saved);
}
function applyTheme(theme) {
  const isDark = theme === "dark" || (theme === "system" && matchMedia("(prefers-color-scheme: dark)").matches);
  if (isDark) document.body.classList.add("dark-theme");
  else document.body.classList.remove("dark-theme");
  localStorage.setItem("toroka_theme", theme);
  const sun = $(".sun"), moon = $(".moon");
  if (sun && moon) { sun.hidden = isDark; moon.hidden = !isDark; }
  document.querySelectorAll(".setting-chip-btn[data-theme-val]").forEach(btn => {
    btn.classList.toggle("active", btn.dataset.themeVal === theme);
  });
}

/* ---------- Sidebar & Mobile Drawer ---------- */
function toggleSidebar() {
  const sb = $("#sidebar"), btn = $("#sidebar-toggle-btn");
  if (!sb) return;
  const collapsed = sb.classList.toggle("collapsed");
  if (btn) btn.setAttribute("aria-expanded", String(!collapsed));
}
function openMobileSidebar() {
  const sb = $("#sidebar"), bd = $("#sidebar-backdrop");
  if (!sb) return;
  if (!sb.classList.contains("mobile-open")) lastSidebarFocus = document.activeElement;
  if (matchMedia("(max-width: 768px)").matches) { sb.classList.remove("collapsed"); $("#sidebar-toggle-btn")?.setAttribute("aria-expanded", "true"); }
  sb.classList.add("mobile-open");
  if (bd) bd.classList.add("active");
  $("#mobile-menu-btn")?.setAttribute("aria-expanded", "true");
  document.body.classList.add("drawer-open");
  $("#sidebar-close-btn")?.focus({ preventScroll: true });
}
function closeMobileSidebar(restoreFocus = true) {
  const sb = $("#sidebar"), bd = $("#sidebar-backdrop");
  const wasOpen = !!sb?.classList.contains("mobile-open");
  if (sb) sb.classList.remove("mobile-open");
  if (bd) bd.classList.remove("active");
  $("#mobile-menu-btn")?.setAttribute("aria-expanded", "false");
  document.body.classList.remove("drawer-open");
  if (restoreFocus && wasOpen && lastSidebarFocus && lastSidebarFocus.isConnected) {
    lastSidebarFocus.focus({ preventScroll: true });
  }
  lastSidebarFocus = null;
}
function toggleMobileSidebar() {
  const sb = $("#sidebar");
  if (sb && sb.classList.contains("mobile-open")) closeMobileSidebar();
  else openMobileSidebar();
}

/* ---------- API ---------- */
async function api(path, { method = "GET", body, headers = {}, form } = {}) {
  let r;
  try { r = await fetch(path, { method, headers: { ...(body ? { "Content-Type": "application/json" } : {}), ...headers }, body: form || (body ? JSON.stringify(body) : undefined) }); }
  catch { throw new Err(t("err_offline")); }
  if (r.status === 429) throw new Err(t("err_wait"));
  const data = await r.json().catch(() => ({}));
  if (!r.ok) {
    if (Array.isArray(data.detail)) throw new Err(data.detail.map(d => d.msg).join("; "));
    throw new Err(typeof data.detail === "string" ? data.detail : t("err_generic"));
  }
  return data;
}

/* ---------- Thread ---------- */
const thread = () => $("#thread");
function show() {
  $("#welcome").hidden = true;
  thread().hidden = false;
  $("#app-layout")?.classList.add("chat-active");
}
function toEnd(el, align = "end") {
  if (!el) return;
  const m = $("#main");
  if (!m) {
    el.scrollIntoView({ block: align === "start" ? "start" : "end", behavior: reduced ? "auto" : "smooth" });
    return;
  }
  const mRect = m.getBoundingClientRect();
  if (align === "start") {
    const anchor = el.previousElementSibling || el;
    const aRect = anchor.getBoundingClientRect();
    const isAlreadyVisible = aRect.top >= mRect.top - 12 && aRect.top <= mRect.top + 140;
    if (isAlreadyVisible) return;
    const targetTop = aRect.top - mRect.top + m.scrollTop - 14;
    m.scrollTo({ top: Math.max(0, targetTop), behavior: reduced ? "auto" : "smooth" });
  } else {
    const elRect = el.getBoundingClientRect();
    if (elRect.bottom > mRect.bottom || elRect.top < mRect.top) {
      m.scrollTo({ top: m.scrollHeight, behavior: reduced ? "auto" : "smooth" });
    }
  }
}
const CRED_RX = /\b(pin|otp|password|passcode|code|nywila)\b(\s*(?:is|was|ni|:|=)?\s*)(\d{4,8})\b/gi;
const maskCreds = s => s.replace(CRED_RX, (m, k, sep, v) => k + sep + "•".repeat(v.length));

function userMsg(text, imgs = [], tKey = null, attachmentNames = []) {
  show();
  const said = h("span", { class: "said", text: maskCreds(text) });
  if (tKey) said.dataset.tKey = tKey;
  const b = h("div", { class: "bubble" }, h("span", { class: "sr-only", text: t("you_said") + " " }), said);
  const liveImgs = isReplaying ? imgs.filter(u => typeof u === "string" && !u.startsWith("blob:")) : imgs;
  liveImgs.forEach(u => b.append(h("img", { src: u, alt: t("shot_note") })));
  if (isReplaying && !liveImgs.length && (attachmentNames.length || imgs.length)) {
    const names = attachmentNames.length ? attachmentNames : [t("saved_attachment")];
    const list = h("div", { class: "attachment-history", "aria-label": t("saved_attachments_label") });
    names.slice(0, MAX_FILES).forEach(name => list.append(h("span", { class: "attachment-history-item" },
      svg("", "M8 12.5 15.5 5a4 4 0 0 1 5.7 5.7L11 20.9a6 6 0 0 1-8.5-8.5L13 1.9"),
      h("span", { text: name || t("saved_attachment") }))));
    b.append(list);
  }
  const li = h("li", { class: "msg user" }, b); thread().append(li);
  if (!isReplaying) {
    toEnd(li);
    convMessages.push({ role: "user", text, imgs: [...imgs], attachmentNames: [...attachmentNames], tKey });
  }
  return { li, bubble: b, text };
}
function botMsg() {
  show();
  const av = h("div", { class: "avatar" }, runner()), body = h("div", { class: "reply" }, h("span", { class: "sr-only", text: t("toroka_said") + " " }));
  const li = h("li", { class: "msg bot" }, av, body); thread().append(li); toEnd(li); return { li, body, avatar: av };
}
function inlineTokens(str) {
  const tokens = [];
  const pattern = /(\*\*[^*]+\*\*|\[[^\]]+\]\(https?:\/\/[^)\s]+\))/g;
  let last = 0, match;
  while ((match = pattern.exec(str)) !== null) {
    if (match.index > last) tokens.push({ type: "text", value: str.slice(last, match.index) });
    const raw = match[0];
    if (raw.startsWith("**")) tokens.push({ type: "strong", value: raw.slice(2, -2) });
    else {
      const parsed = /^\[([^\]]+)\]\((https?:\/\/[^)\s]+)\)$/.exec(raw);
      const url = parsed ? safeEvidenceUrl(parsed[2]) : null;
      if (parsed && url) tokens.push({ type: "link", value: parsed[1], url });
      else tokens.push({ type: "text", value: raw });
    }
    last = pattern.lastIndex;
  }
  if (last < str.length) tokens.push({ type: "text", value: str.slice(last) });
  return tokens;
}
function inlineMarkup(str) {
  const frag = document.createDocumentFragment();
  for (const token of inlineTokens(str)) {
    if (token.type === "strong") frag.appendChild(h("strong", { text: token.value }));
    else if (token.type === "link") frag.appendChild(h("a", { href: token.url, target: "_blank", rel: "noopener noreferrer", text: token.value }));
    else frag.appendChild(document.createTextNode(token.value));
  }
  return frag;
}
function parseFormattedBlocks(text) {
  const blocks = [];
  const lines = text.split("\n");
  let curType = null, curLines = [];
  function flush() {
    if (!curLines.length) return;
    if (curType === "ul" || curType === "ol") blocks.push({ type: curType, items: [...curLines] });
    else { const pText = curLines.join(" ").trim(); if (pText) blocks.push({ type: "p", text: pText }); }
    curLines = []; curType = null;
  }
  for (let raw of lines) {
    const trimmed = raw.trim();
    if (!trimmed) { flush(); continue; }
    const headingMatch = /^(#{1,3})\s+(.+)$/.exec(trimmed);
    const ulMatch = /^[•\-\*]\s+(.*)$/.exec(trimmed);
    const olMatch = /^(\d+)[\.\)]\s+(.*)$/.exec(trimmed);
    if (headingMatch) {
      flush();
      const level = Math.min(4, headingMatch[1].length + 1);
      blocks.push({ type: `h${level}`, text: headingMatch[2].trim() });
    }
    else if (ulMatch) { if (curType !== "ul") flush(); curType = "ul"; curLines.push(ulMatch[1]); }
    else if (olMatch) { if (curType !== "ol") flush(); curType = "ol"; curLines.push(olMatch[2]); }
    else { if (curType === "ul" || curType === "ol") flush(); curType = "p"; curLines.push(trimmed); }
  }
  flush(); return blocks;
}
function renderRichContent(container, text) {
  container.replaceChildren();
  const blocks = parseFormattedBlocks(text);
  for (const b of blocks) {
    if (b.type === "ul" || b.type === "ol") {
      const listEl = h(b.type, { class: "bot-points" });
      b.items.forEach(it => { const li = h("li"); li.appendChild(inlineMarkup(it)); listEl.appendChild(li); });
      container.appendChild(listEl);
    } else if (/^h[2-4]$/.test(b.type)) {
      const heading = h(b.type);
      heading.appendChild(inlineMarkup(b.text));
      container.appendChild(heading);
    } else {
      const p = h("p"); p.appendChild(inlineMarkup(b.text)); container.appendChild(p);
    }
  }
}
async function typeInlineContent(container, value, totalChars) {
  const tokens = inlineTokens(value);
  const share = value.length / Math.max(1, totalChars);
  const ticks = Math.max(2, Math.min(24, Math.round(share * 180)));
  for (const token of tokens) {
    let target = container;
    if (token.type === "strong") { target = h("strong"); container.append(target); }
    else if (token.type === "link") {
      target = h("a", { href: token.url, target: "_blank", rel: "noopener noreferrer" });
      container.append(target);
    }
    const node = document.createTextNode("");
    target.append(node);
    if (reduced || token.value.length < 12) { node.textContent = token.value; continue; }
    const tokenTicks = Math.max(1, Math.round(ticks * token.value.length / Math.max(1, value.length)));
    for (let i = 1; i <= tokenTicks; i++) {
      node.textContent = token.value.slice(0, Math.ceil(token.value.length * i / tokenTicks));
      await new Promise(resolve => setTimeout(resolve, 9));
    }
  }
}
async function renderRichContentStreaming(container, text) {
  if (reduced || isReplaying) { renderRichContent(container, text); return; }
  container.replaceChildren();
  const blocks = parseFormattedBlocks(text);
  const totalChars = Math.max(1, blocks.reduce((sum, block) => sum + (
    block.type === "ul" || block.type === "ol"
      ? block.items.reduce((count, item) => count + item.length, 0)
      : block.text.length
  ), 0));
  for (const block of blocks) {
    if (block.type === "ul" || block.type === "ol") {
      const list = h(block.type, { class: "bot-points" });
      container.append(list);
      for (const item of block.items) {
        const li = h("li"); list.append(li);
        await typeInlineContent(li, item, totalChars);
      }
    } else {
      const tag = /^h[2-4]$/.test(block.type) ? block.type : "p";
      const element = h(tag); container.append(element);
      await typeInlineContent(element, block.text, totalChars);
    }
  }
}

function stream(p, text) {
  return new Promise(res => {
    const words = text.split(" ");
    if (reduced || words.length < 2) { p.textContent = text; return res(); }
    let i = 0; const step = Math.max(1, Math.ceil(words.length / 45));
    const tick = () => { i = Math.min(words.length, i + step); p.textContent = words.slice(0, i).join(" "); if (i < words.length) setTimeout(tick, 22); else res(); };
    tick();
  });
}
async function botSay(text, chips, tKey = null) {
  const m = botMsg(), wrap = h("div", { class: "bot-content" });
  if (tKey) wrap.dataset.tKey = tKey;
  m.body.append(wrap);
  await renderRichContentStreaming(wrap, text);
  if (chips) m.body.append(chipsRow(chips));
  if (!isReplaying) {
    toEnd(m.li, text.length > 200 ? "start" : "end");
    say(t("toroka_said") + " " + text.replace(/[*#]/g, ""));
    convMessages.push({ role: "bot", text, tKey });
  }
  return m;
}
function chipsRow(items, single = true) {
  const ul = h("ul", { class: "chips" });
  for (const item of items) {
    const [label, fn, keep, tKey] = item;
    const b = h("button", { type: "button", text: label });
    if (tKey) b.dataset.tKey = tKey;
    b.addEventListener("click", () => {
      if (single) ul.querySelectorAll("button").forEach(x => { x.disabled = true; });
      else if (!keep) b.disabled = true;
      fn(label);
    });
    ul.append(h("li", {}, b));
  }
  return ul;
}
function thinkingStepKeys(context = "") {
  const value = String(context || "").toLowerCase();
  if (/\b(?:email|e-mail|from:|reply-to:|return-path|dkim|spf|dmarc|\.eml)\b/.test(value)) {
    return ["th_email_1", "th_email_2", "th_email_3", "th_email_4", "th5"];
  }
  if (/https?:\/\/|www\.|\b(?:[a-z0-9-]+\.)+(?:com|org|net|co\.ke|ke)\b|instagram|tiktok|facebook|@\w+/.test(value)) {
    return ["th_web_1", "th_web_2", "th_web_3", "th_web_4", "th5"];
  }
  if (/\b(?:m[\s-]?pesa|till|paybill|payment|paid|transaction|receipt|bank details)\b/.test(value)) {
    return ["th_pay_1", "th_pay_2", "th_pay_3", "th_pay_4", "th5"];
  }
  if (/\b(?:image|screenshot|photo|picture|attachment)\b/.test(value)) {
    return ["th_image_1", "th_image_2", "th_image_3", "th_image_4", "th5"];
  }
  return ["th1", "th2", "th3", "th4", "th5"];
}
function think(context = "") {
  const m = botMsg();
  const keys = thinkingStepKeys(context);
  const line = h("span", { class: "think-copy", "aria-hidden": "true", text: t(keys[0]) });
  const live = h("span", { class: "sr-only", role: "status", "aria-live": "polite", text: t(keys[0]) });
  const row = h("div", { class: "think" },
    h("span", { class: "think-orbit", "aria-hidden": "true" }),
    line, h("span", { class: "dots", "aria-hidden": "true" }), live
  );
  m.body.append(row); run(m.avatar.firstChild); say(t("thinking"));

  let index = 0, typeTimer = null, stageTimer = null, stopped = false;
  const typeLine = value => {
    if (typeTimer) clearTimeout(typeTimer);
    live.textContent = value;
    line.textContent = "";
    if (reduced) { line.textContent = value; return; }
    let position = 0;
    const tick = () => {
      if (stopped) return;
      position = Math.min(value.length, position + (position < 24 ? 2 : 3));
      line.textContent = value.slice(0, position);
      if (position < value.length) typeTimer = setTimeout(tick, 18);
    };
    tick();
  };
  const advance = () => {
    if (stopped) return;
    if (index < keys.length - 1) {
      index += 1;
      typeLine(t(keys[index]));
      stageTimer = setTimeout(advance, 2600);
    } else {
      stageTimer = setTimeout(() => typeLine(t("th_wait")), 4200);
    }
  };
  if (!reduced) stageTimer = setTimeout(advance, 2500);
  return { stop() {
    stopped = true;
    if (stageTimer) clearTimeout(stageTimer);
    if (typeTimer) clearTimeout(typeTimer);
    m.li.remove();
  } };
}
function ask(text, handler, chips, tKey = null) { pending = handler; return botSay(text, chips, tKey).then(m => { $("#text").focus(); return m; }); }

/* ---------- Checks ---------- */
async function doCheck(text, fl, bubble, crossCaseImageConsent = false) {
  // A new evidence check starts a new context. Keep older messages visually in history,
  // but don't pass them as AI conversational memory for this unrelated investigation.
  chatHistory = [];
  const th = think(text || (fl.length ? "image screenshot attachment" : "")); let data, fileErr = [];
  try {
    data = await api("/v1/checks", { method: "POST", body: { text: text.trim() || t("shot_note"), language: lang } });
    sessionStorage.setItem("ssi.t." + data.check_id, data.guest_token); current = { id: data.check_id, token: data.guest_token, text };
    for (const f of fl) {
      const fd = new FormData(); fd.append("file", f); fd.append("lang", lang);
      fd.append("consent_scope", crossCaseImageConsent ? "cross_case_campaign" : "this_check_only");
      try { data = await api(`/v1/checks/${data.check_id}/evidence`, { method: "POST", headers: { "X-Guest-Token": current.token }, form: fd }); } catch (e) { fileErr.push(e.message); }
    }
  } catch (e) { th.stop(); await fail(e, text); return; }
  th.stop(); await renderCheck(data, text, bubble); for (const m of fileErr) await botSay(t("sorry") + " " + m);
}
async function fail(e, text) {
  if (text) { $("#text").value = text; fit(); syncSend(); }
  botSay(`${t("sorry")} ${e.message} ${text ? t("back_in_box") : ""}`.trim());
}
function strip(label, summary, callout) {
  const s = summary.replace(LABEL_PREFIX, ""); return callout ? s.replace(/\s*(Don't pay in advance, not even half\.|Usilipe mapema, hata nusu\.)/, "") : s;
}
function updateCheckBubbleContent(body, data) {
  const a = data.assessment;
  if (!a) return;
  const pillText = body.querySelector(".pill-text");
  if (pillText) pillText.textContent = a.label_text || a.label;
  const pay = a.next_steps.find(n => /^(Don't pay in advance|Usilipe mapema)/.test(n.text));
  const summaryEl = body.querySelector(".check-summary");
  if (summaryEl) summaryEl.textContent = strip(a.label, a.summary, !!pay);
  const callout = body.querySelector(".callout");
  if (callout) {
    if (pay) { callout.hidden = false; const ct = callout.querySelector(".callout-text"); if (ct) ct.textContent = " " + pay.text; }
    else { callout.hidden = true; }
  }
  const rest = a.next_steps.filter(n => n !== pay);
  const ol = body.querySelector(".next-steps-list");
  if (ol && rest.length) ol.replaceChildren(...rest.map(n => h("li", { text: n.text })));
  const ulWhy = body.querySelector(".det-why ul");
  if (ulWhy && a.findings) ulWhy.replaceChildren(...findingNodes(a.findings));
  const ulSources = body.querySelector(".det-sources ul");
  if (ulSources && a.sources) ulSources.replaceChildren(...a.sources.map(s => h("li", {}, h("span", { text: s.statement + " " }), s.source_url ? h("a", { href: s.source_url, rel: "noopener noreferrer", target: "_blank", text: t("open_source"), "data-t-key": "open_source" }) : null)));
  const coverageList = body.querySelector(".det-checked .coverage-list");
  if (coverageList && a.coverage) coverageList.replaceChildren(...coverageNodes(a));
  const limitsList = body.querySelector(".det-limits ul");
  if (limitsList && a.limitations) limitsList.replaceChildren(...a.limitations.map(x => h("li", { text: x })));
  intelligencePanels(body, a);
  if (current && current.bubbleUser && !data.evidence.length) {
    const hl = highlight(maskCreds(current.originalText), a.findings);
    if (hl) current.bubbleUser.querySelector(".said").replaceChildren(...hl);
  }
}
function safeManualSearchUrl(raw) {
  try {
    const u = new URL(String(raw || ""));
    if (u.protocol !== "https:" || u.hostname !== "www.google.com" || u.pathname !== "/search") return null;
    return u.href;
  } catch (_) { return null; }
}
function manualSearchNodes(searches) {
  return (searches || []).map(s => {
    const url = safeManualSearchUrl(s.url);
    return url ? h("li", {}, h("a", { href: url, rel: "noopener noreferrer", target: "_blank", text: t("manual_search_label") })) : null;
  }).filter(Boolean);
}
function safeEvidenceUrl(raw) {
  try {
    const u = new URL(String(raw || ""));
    return (u.protocol === "https:" || u.protocol === "http:") ? u.href : null;
  } catch (_) { return null; }
}
function findingNodes(findings) {
  return (findings || []).map(f => {
    const sourceUrl = safeEvidenceUrl(f.source_id);
    return h("li", { class: "fnd" },
      h("strong", { text: f.plain_text }),
      f.excerpt ? h("blockquote", { class: "fnd-excerpt" }, `${t("ev_observed_excerpt")}: “${f.excerpt}”`) : null,
      h("p", { text: f.why_it_matters }),
      sourceUrl ? h("a", { href: sourceUrl, rel: "noopener noreferrer", target: "_blank", text: t("open_source") }) : null
    );
  });
}
function evidenceBasisLabel(basis) {
  const labels = {
    observed_in_submitted_content: t("ev_observed_input"),
    linked_public_sources: t("ev_linked_public"),
    reported_in_target_matched_public_sources: t("ev_public_report"),
    verification_gap_in_submission: t("ev_verification_gap"),
    multiple_unverified_public_allegations: t("ev_multiple_reports"),
    directly_observed_on_target: t("ev_page_observed"),
    assessment_finding: t("ev_assessment_factor")
  };
  return labels[basis] || String(basis || t("ev_assessment_factor")).replaceAll("_", " ");
}
function evidenceSourceNode(source) {
  const claim = source.source_type === "urlscan_historical_scan" ? t("ev_historical_scan")
    : source.claim_status === "reported_allegation" ? t("ev_allegation_not_proof")
    : (source.source_type === "social_profile_observation" || source.source_type === "social_public_profile_observation") ? t("ev_seller_profile")
    : source.source_type === "inspected_public_web_page" ? t("ev_page_read_not_verified")
    : t("ev_public_search_lead");
  const url = safeEvidenceUrl(source.url);
  return h("li", { class: "evidence-source" },
    h("div", { class: "evidence-source-head" }, h("strong", { text: source.title || source.provider || t("ev_source") }), h("span", { class: "evidence-tag", text: claim })),
    source.snippet ? h("p", { class: "evidence-snippet", text: source.snippet }) : null,
    h("small", { class: "evidence-meta", text: [source.provider, source.published_at].filter(Boolean).join(" · ") }),
    source.identity_match ? h("small", { class: "evidence-meta", text: `${t("ev_identity_match")}: ${String(source.identity_match).replaceAll("_", " ")}` }) : null,
    url ? h("a", { href: url, rel: "noopener noreferrer", target: "_blank", text: t("open_source") }) : null
  );
}
function intelligencePanels(parent, assessment) {
  parent.querySelectorAll(".det-intel-evidence, .det-shop-discovery, .det-domain-infrastructure, .det-official-registry, .det-build3-entity-verification, .det-build4-campaign-intelligence, .det-evidence-graph").forEach(node => node.remove());
  const intel = assessment && assessment.investigation_intelligence;
  if (!intel) return;
  const explanation = intel.evidence_explanation;
  if (explanation) {
    const reasons = (explanation.reasons || []).map(reason => h("li", { class: "evidence-reason" },
      h("div", { class: "evidence-reason-head" }, h("strong", { text: reason.statement || t("ev_assessment_factor") }), h("span", { class: "evidence-tag", text: evidenceBasisLabel(reason.basis) })),
      reason.observed_excerpt ? h("blockquote", { class: "evidence-quote" }, `“${reason.observed_excerpt}”`) : null,
      reason.why_it_matters ? h("p", { class: "evidence-why", text: reason.why_it_matters }) : null,
      reason.strength ? h("small", { class: "evidence-meta", text: `${t("ev_strength")}: ${String(reason.strength).replaceAll("_", " ")}` }) : null,
      (reason.evidence || []).length ? h("ul", { class: "evidence-source-list" }, reason.evidence.map(evidenceSourceNode)) : null
    ));
    const positives = (explanation.positive_identity_matches || []).map(item => h("li", { class: "evidence-source" },
      h("strong", { text: item.title || t("ev_registry_match") }),
      item.verified_at ? h("small", { class: "evidence-meta", text: `${t("ev_last_reviewed")}: ${item.verified_at}` }) : null,
      safeEvidenceUrl(item.url) ? h("a", { href: safeEvidenceUrl(item.url), rel: "noopener noreferrer", target: "_blank", text: t("open_source") }) : null
    ));
    const content = [];
    content.push(h("p", { class: "evidence-intro", text: explanation.interpretation_note || t("ev_interpretation_note") }));
    if (reasons.length) content.push(h("ul", { class: "evidence-reason-list" }, reasons));
    else content.push(h("p", { class: "evidence-empty", text: t("ev_no_specific_reasons") }));
    if (positives.length) content.push(h("div", { class: "evidence-positive" }, h("strong", { text: t("ev_positive_matches") }), h("ul", { class: "evidence-source-list" }, positives)));
    if (explanation.limitations && explanation.limitations.length) content.push(h("div", { class: "evidence-caveats" }, h("strong", { text: t("ev_limits") }), h("ul", {}, explanation.limitations.map(x => h("li", { text: x })))));
    parent.append(h("details", { class: "det-intel-evidence", open: true }, h("summary", { text: t("r_evidence") }), ...content));
  }

  const shop = intel.shop_discovery;
  if (shop && (assessment.category?.used === "shop" || intel.category === "shop")) {
    const locations = shop.locations || [];
    const storefronts = shop.online_storefronts || [];
    const locationItems = locations.map(loc => {
      const kind = loc.kind === "physical_address" ? t("loc_physical_address") : loc.kind === "delivery_area" ? t("loc_delivery_area") : t("loc_profile_location");
      const sourceUrl = safeEvidenceUrl(loc.source_url);
      return h("li", { class: "location-claim" },
        h("strong", { text: loc.value }),
        h("span", { class: "evidence-tag" , text: kind }),
        h("small", { class: "evidence-meta", text: loc.claim_label || t("loc_unverified_source") }),
        loc.excerpt ? h("p", { class: "evidence-snippet", text: loc.excerpt }) : null,
        loc.source_title ? h("small", { class: "evidence-meta", text: `${t("ev_source")}: ${loc.source_title}` }) : null,
        sourceUrl ? h("a", { href: sourceUrl, rel: "noopener noreferrer", target: "_blank", text: t("open_source") }) : null,
        safeEvidenceUrl(loc.maps_search_url) ? h("a", { href: safeEvidenceUrl(loc.maps_search_url), rel: "noopener noreferrer", target: "_blank", text: t("loc_check_maps") }) : null
      );
    });
    const storefrontItems = storefronts.map(item => {
      const url = safeEvidenceUrl(item.url);
      return url ? h("li", { class: "storefront-item" }, h("strong", { text: item.title || item.platform || t("loc_online_storefront") }), h("small", { class: "evidence-meta", text: item.platform || t("loc_online_storefront") }), h("a", { href: url, rel: "noopener noreferrer", target: "_blank", text: t("loc_open_storefront") })) : null;
    }).filter(Boolean);
    const mapItems = (shop.map_candidates || []).map(item => {
      const mapsUrl = safeEvidenceUrl(item.maps_url);
      const websiteUrl = safeEvidenceUrl(item.website_url);
      const row = h("li", { class: "location-claim map-candidate" },
        h("strong", { text: item.name || t("loc_map_candidates") }),
        item.address ? h("span", { class: "evidence-meta", text: item.address }) : null,
        h("span", { class: "evidence-tag", text: t("loc_possible_match") }),
        item.business_status && item.business_status !== "unknown" ? h("small", { class: "evidence-meta", text: String(item.business_status).replaceAll("_", " ") }) : null,
        item.match_basis ? h("p", { class: "evidence-snippet", text: item.match_basis }) : null,
        mapsUrl ? h("a", { href: mapsUrl, rel: "noopener noreferrer", target: "_blank", text: t("loc_open_map_listing") }) : null,
        websiteUrl ? h("a", { href: websiteUrl, rel: "noopener noreferrer", target: "_blank", text: t("loc_open_business_website") }) : null
      );
      return row;
    });
    const children = [];
    if (locationItems.length) children.push(h("div", { class: "location-list-wrap" }, h("h4", { text: t("loc_public_location_claims") }), h("ul", { class: "location-list" }, locationItems)));
    else children.push(h("p", { class: "evidence-empty", text: t("loc_none_found") }));
    if (mapItems.length) children.push(h("div", { class: "location-list-wrap" }, h("h4", { text: t("loc_map_candidates") }), h("ul", { class: "location-list" }, mapItems)));
    if (storefrontItems.length) children.push(h("div", { class: "storefront-list-wrap" }, h("h4", { text: t("loc_online_storefronts") }), h("ul", { class: "storefront-list" }, storefrontItems)));
    if (shop.map_note) children.push(h("p", { class: "evidence-intro", text: shop.map_note }));
    if (shop.location_note) children.push(h("p", { class: "evidence-intro", text: shop.location_note }));
    parent.append(h("details", { class: "det-shop-discovery", open: locations.length > 0 || storefronts.length > 0 || mapItems.length > 0 }, h("summary", { text: t("r_location") }), ...children));
  }

  const infrastructure = Array.isArray(intel.domain_infrastructure) ? intel.domain_infrastructure : [];
  if (infrastructure.length) {
    const rows = infrastructure.slice(0, 2).map(bundle => {
      const rdap = bundle.rdap || {};
      const registration = rdap.events && rdap.events.registration;
      const dnsRecords = (bundle.dns && bundle.dns.records || []).slice(0, 10);
      const ipRows = (bundle.ip_observations || []).slice(0, 2);
      const ctIssues = (bundle.certificate_transparency && bundle.certificate_transparency.issuances || []).slice(0, 5);
      const providerRows = (bundle.providers || []).map(provider => h("li", { class: "evidence-source" },
        h("strong", { text: provider.provider || t("domainintel_provider") }),
        h("span", { class: "evidence-tag", text: String(provider.status || "unknown").replaceAll("_", " ") }),
        provider.detail ? h("small", { class: "evidence-meta", text: provider.detail }) : null
      ));
      const children = [];
      children.push(h("p", { class: "evidence-intro", text: bundle.interpretation_note || t("domainintel_note") }));
      if (registration) children.push(h("p", { class: "evidence-meta", text: `${t("domainintel_registration")}: ${registration}` }));
      if (rdap.registrar) children.push(h("p", { class: "evidence-meta", text: `${t("domainintel_registrar")}: ${rdap.registrar}` }));
      if (dnsRecords.length) children.push(h("div", { class: "location-list-wrap" },
        h("h4", { text: t("domainintel_dns") }),
        h("ul", { class: "location-list" }, dnsRecords.map(record => h("li", { class: "location-claim" },
          h("span", { class: "evidence-tag", text: record.type || "DNS" }),
          h("strong", { text: String(record.value || "").slice(0, 180) }),
          record.priority !== undefined ? h("small", { class: "evidence-meta", text: `Priority: ${record.priority}` }) : null,
          record.ttl !== undefined && record.ttl !== null ? h("small", { class: "evidence-meta", text: `TTL: ${record.ttl}` }) : null
        )))));
      if (ipRows.length) children.push(h("div", { class: "location-list-wrap" },
        h("h4", { text: t("domainintel_network") }),
        h("ul", { class: "location-list" }, ipRows.map(row => {
          const asn = row.asn_lookup || {};
          const asnRdap = row.asn_rdap || {};
          const ipRdap = row.rdap || {};
          const details = [asn.asn ? `AS${asn.asn}` : "", asnRdap.name || "", asn.prefix || "", ipRdap.name || ""].filter(Boolean).join(" · ");
          return h("li", { class: "location-claim" }, h("strong", { text: row.ip || "IP address" }),
            details ? h("small", { class: "evidence-meta", text: details }) : null,
            asn.registry_country ? h("small", { class: "evidence-meta", text: `${t("domainintel_registry_country")}: ${asn.registry_country} (${t("domainintel_not_geo")})` }) : null,
            safeEvidenceUrl(asnRdap.rdap_url || ipRdap.rdap_url) ? h("a", { href: safeEvidenceUrl(asnRdap.rdap_url || ipRdap.rdap_url), rel: "noopener noreferrer", target: "_blank", text: t("open_source") }) : null
          );
        }))));
      if (ctIssues.length) children.push(h("div", { class: "location-list-wrap" },
        h("h4", { text: t("domainintel_ct") }),
        h("ul", { class: "location-list" }, ctIssues.map(issue => h("li", { class: "location-claim" },
          h("strong", { text: (issue.dns_names || []).slice(0, 6).join(", ") || t("domainintel_ct_record") }),
          issue.not_before || issue.not_after ? h("small", { class: "evidence-meta", text: `${issue.not_before || "?"} – ${issue.not_after || "?"}` }) : null,
          issue.issuer ? h("small", { class: "evidence-meta", text: `${t("domainintel_issuer")}: ${issue.issuer}` }) : null,
          issue.revoked === true ? h("span", { class: "evidence-tag", text: t("domainintel_revoked") }) : null
        )))));
      if (providerRows.length) children.push(h("div", { class: "location-list-wrap" }, h("h4", { text: t("domainintel_sources") }), h("ul", { class: "evidence-source-list" }, providerRows)));
      const rdapUrl = safeEvidenceUrl(rdap.rdap_url);
      const dnsUrl = safeEvidenceUrl(bundle.dns && bundle.dns.source_url);
      const ctUrl = safeEvidenceUrl(bundle.certificate_transparency && bundle.certificate_transparency.source_url);
      const links = [rdapUrl, dnsUrl, ctUrl].filter(Boolean);
      if (links.length) children.push(h("div", { class: "evidence-source-list" }, links.map(url => h("a", { href: url, rel: "noopener noreferrer", target: "_blank", text: t("open_source") }))));
      return h("li", { class: "location-claim" }, h("strong", { text: bundle.domain || t("domainintel_domain") }),
        h("span", { class: "evidence-tag", text: String(bundle.status || "unknown").replaceAll("_", " ") }),
        ...children
      );
    });
    parent.append(h("details", { class: "det-domain-infrastructure", open: true },
      h("summary", { text: t("domainintel_h") }),
      h("p", { class: "evidence-intro", text: t("domainintel_note") }),
      h("ul", { class: "location-list" }, rows)
    ));
  }

  const registryChecks = Array.isArray(intel.official_registry_checks) ? intel.official_registry_checks : [];
  if (registryChecks.length) {
    const registryRows = registryChecks.slice(0, 3).map(item => h("li", { class: "location-claim" },
      h("strong", { text: item.registry || t("registry_h") }),
      h("span", { class: "evidence-tag", text: t("registry_manual") }),
      h("p", { class: "evidence-snippet", text: item.interpretation_note || t("registry_note") }),
      item.what_to_verify && item.what_to_verify.length ? h("ul", { class: "evidence-source-list" }, item.what_to_verify.slice(0, 5).map(step => h("li", { text: step }))) : null,
      safeEvidenceUrl(item.official_portal_url) ? h("a", { href: safeEvidenceUrl(item.official_portal_url), rel: "noopener noreferrer", target: "_blank", text: t("registry_open") }) : null
    ));
    parent.append(h("details", { class: "det-official-registry", open: true },
      h("summary", { text: t("registry_h") }),
      h("p", { class: "evidence-intro", text: t("registry_note") }),
      h("ul", { class: "location-list" }, registryRows)
    ));
  }

  const entityVerification = intel.entity_verification;
  if (entityVerification && (entityVerification.nea || entityVerification.brs)) {
    const sections = [];
    const addRegistrySection = (item, kind) => {
      if (!item) return;
      const list = [];
      list.push(h("span", { class: "evidence-tag", text: String(item.status || "review_required").replaceAll("_", " ") }));
      if (item.snapshot) {
        list.push(h("small", { class: "evidence-meta", text: `${t("entity_snapshot_date")}: ${item.snapshot.data_as_of || "unknown"} · ${item.snapshot.freshness || "unknown"}` }));
      }
      if (item.candidates && item.candidates.length) {
        for (const candidate of item.candidates.slice(0, 4)) {
          list.push(h("div", { class: "location-claim" },
            h("strong", { text: candidate.agency_name || t("entity_candidate") }),
            h("small", { class: "evidence-meta", text: `${candidate.registration_number || ""} · ${candidate.service_type || ""}` }),
            h("span", { class: "evidence-tag", text: String(candidate.display_status || candidate.licence_status_in_source || "unknown").replaceAll("_", " ") }),
            candidate.expires_on ? h("small", { class: "evidence-meta", text: `${t("entity_expiry")}: ${candidate.expires_on}` }) : null,
            h("small", { class: "evidence-meta", text: `${t("entity_match_basis")}: ${String(candidate.match_basis || "").replaceAll("_", " ")}` }),
            safeEvidenceUrl(candidate.record_source_url) ? h("a", { href: safeEvidenceUrl(candidate.record_source_url), rel: "noopener noreferrer", target: "_blank", text: t("open_source") }) : null
          ));
        }
      }
      if (item.record) {
        const r = item.record;
        list.push(h("div", { class: "location-claim" },
          h("strong", { text: r.registered_name || t("entity_brs_record") }),
          h("small", { class: "evidence-meta", text: `${r.registration_type || ""} · ${r.registration_number_masked || ""}` }),
          h("span", { class: "evidence-tag", text: String(item.status || "review_required").replaceAll("_", " ") }),
          h("small", { class: "evidence-meta", text: `${t("entity_checked")}: ${r.source_checked_at || "unknown"} · ${t("entity_review_due")}: ${r.review_due || "unknown"}` }),
          safeEvidenceUrl(r.source_url) ? h("a", { href: safeEvidenceUrl(r.source_url), rel: "noopener noreferrer", target: "_blank", text: t("open_source") }) : null
        ));
      }
      if (item.name_candidates && item.name_candidates.length) {
        list.push(h("h4", { text: t("entity_name_candidates") }));
        for (const candidate of item.name_candidates.slice(0, 4)) list.push(h("div", { class: "location-claim" },
          h("strong", { text: candidate.registered_name }),
          h("small", { class: "evidence-meta", text: candidate.registration_number_masked || "" }),
          safeEvidenceUrl(candidate.source_url) ? h("a", { href: safeEvidenceUrl(candidate.source_url), rel: "noopener noreferrer", target: "_blank", text: t("open_source") }) : null
        ));
      }
      if (item.verified_associations && item.verified_associations.length) {
        list.push(h("h4", { text: t("entity_linked_presence") }));
        for (const association of item.verified_associations.slice(0, 8)) list.push(h("div", { class: "location-claim" },
          h("strong", { text: association.value || association.type }),
          h("span", { class: "evidence-tag", text: String(association.type || "").replaceAll("_", " ") }),
          h("small", { class: "evidence-meta", text: `${t("entity_checked")}: ${association.reviewed_at || "unknown"} · ${t("entity_review_due")}: ${association.review_due || "unknown"}` }),
          safeEvidenceUrl(association.source_url) ? h("a", { href: safeEvidenceUrl(association.source_url), rel: "noopener noreferrer", target: "_blank", text: t("open_source") }) : null
        ));
      }
      if (item.what_to_verify && item.what_to_verify.length) list.push(h("ul", { class: "evidence-source-list" }, item.what_to_verify.slice(0, 5).map(step => h("li", { text: step }))));
      if (item.interpretation_note) list.push(h("p", { class: "evidence-intro", text: item.interpretation_note }));
      const portal = safeEvidenceUrl(item.official_portal_url);
      if (portal) list.push(h("a", { href: portal, rel: "noopener noreferrer", target: "_blank", text: t("registry_open") }));
      sections.push(h("div", { class: "location-list-wrap" }, h("h4", { text: item.registry || (kind === "nea" ? "NEA" : "BRS") }), ...list));
    };
    addRegistrySection(entityVerification.nea, "nea");
    addRegistrySection(entityVerification.brs, "brs");
    parent.append(h("details", { class: "det-build3-entity-verification", open: true },
      h("summary", { text: t("entity_verify_h") }),
      h("p", { class: "evidence-intro", text: entityVerification.interpretation_note || t("entity_verify_note") }),
      ...sections,
      entityVerification.limitations && entityVerification.limitations.length ? h("div", { class: "evidence-caveats" }, h("strong", { text: t("ev_limits") }), h("ul", {}, entityVerification.limitations.map(x => h("li", { text: x })))) : null
    ));
  }

  const campaign = intel.campaign_intelligence;
  if (campaign && campaign.status === "context_found") {
    const rows = [];
    for (const item of (campaign.matched_published_indicators || []).slice(0, 8)) {
      rows.push(h("li", { class: "evidence-source" },
        h("strong", { text: `${item.kind || "Identifier"}: ${item.masked_value || "••••"}` }),
        h("span", { class: "evidence-tag", text: `${item.independent_reports || 0} ${t("campaign_independent_reports")}` }),
        h("small", { class: "evidence-meta", text: `${t("campaign_last_reported")}: ${item.last_reported || t("campaign_unknown")}` }),
        h("p", { class: "evidence-why", text: item.interpretation || t("campaign_indicator_note") })
      ));
    }
    for (const item of (campaign.related_public_identifiers || []).slice(0, 8)) {
      rows.push(h("li", { class: "evidence-source" },
        h("strong", { text: `${item.kind || "Identifier"}: ${item.masked_value || "••••"}` }),
        h("span", { class: "evidence-tag", text: `${item.independent_reports || 0} ${t("campaign_independent_reports")}` }),
        h("small", { class: "evidence-meta", text: `${t("campaign_seen_range")}: ${item.first_seen || "?"} — ${item.last_seen || "?"}` }),
        h("p", { class: "evidence-why", text: t("campaign_relationship_note") })
      ));
    }
    const img = campaign.image_reuse;
    const imageNode = img ? h("div", { class: "location-list-wrap" },
      h("strong", { text: t("campaign_image_title") }),
      h("p", { class: "evidence-intro", text: img.status === "matches_found"
        ? `${img.matching_opted_in_checks || 0} ${t("campaign_opted_checks")}; ${img.exact_file_matches || 0} ${t("campaign_exact_matches")}; ${img.perceptual_similarity_matches || 0} ${t("campaign_visual_matches")}.`
        : t("campaign_no_image_match") }),
      h("p", { class: "evidence-why", text: img.interpretation_note || "" })
    ) : null;
    const limits = campaign.limitations || [];
    parent.append(h("details", { class: "det-build4-campaign-intelligence", open: true },
      h("summary", { text: t("campaign_intelligence_title") }),
      h("p", { class: "evidence-intro", text: campaign.interpretation_note || t("campaign_intelligence_note") }),
      rows.length ? h("ul", { class: "evidence-source-list" }, rows) : h("p", { class: "evidence-empty", text: t("campaign_no_public_links") }),
      imageNode,
      limits.length ? h("div", { class: "evidence-caveats" }, h("strong", { text: t("ev_limits") }), h("ul", {}, limits.map(x => h("li", { text: x })))) : null
    ));
  }

  const graph = intel.evidence_graph;
  if (graph && Array.isArray(graph.edges) && graph.edges.length) {
    const nodeById = new Map((graph.nodes || []).map(node => [node.id, node]));
    const graphRows = graph.edges.slice(0, 16).map(edge => {
      const from = nodeById.get(edge.from), to = nodeById.get(edge.to);
      if (!from || !to) return null;
      const ev = edge.evidence_id ? (intel.evidence || []).find(x => x.evidence_id === edge.evidence_id) : null;
      const sourceUrl = ev && safeEvidenceUrl(ev.url);
      return h("li", { class: "evidence-source" },
        h("strong", { text: from.label || from.type }),
        h("span", { class: "evidence-tag", text: String(edge.relation || t("graph_relationship")).replaceAll("_", " ") }),
        h("strong", { text: to.label || to.type }),
        h("small", { class: "evidence-meta", text: `${String(edge.basis || "").replaceAll("_", " ")} · ${String(edge.strength || "context")}` }),
        sourceUrl ? h("a", { href: sourceUrl, rel: "noopener noreferrer", target: "_blank", text: t("open_source") }) : null
      );
    }).filter(Boolean);
    parent.append(h("details", { class: "det-evidence-graph" },
      h("summary", { text: t("graph_h") }),
      h("p", { class: "evidence-intro", text: graph.interpretation_note || t("graph_note") }),
      graphRows.length ? h("ul", { class: "evidence-source-list" }, graphRows) : h("p", { class: "evidence-empty", text: t("graph_empty") })
    ));
  }
}

function coverageNodes(a) {
  const label = status => ({
    checked: t("cov_checked"),
    checked_match: t("cov_checked_match") || "Match found",
    checked_no_match: t("cov_checked_no_match") || "No reports found",
    not_configured: t("cov_not_configured") || "Not configured",
    not_checked: t("cov_not_checked"),
    could_not_check: t("cov_could_not_check"),
    failed: t("cov_failed") || "Failed",
    not_found: t("cov_not_found"),
    partial: t("cov_could_not_check")
  })[status] || status;
  return (a.coverage || []).map(c => {
    const isLiveSearch = c.id === "tavily_search" || c.id === "public_web_search";
    const note = (isLiveSearch && (c.status === "checked_match" || c.status === "checked_no_match" || (c.results_retrieved && c.results_retrieved > 0)))
      ? (t("live_search_note") || "Toroka searched public records automatically. Use these links to inspect public results yourself.")
      : t("manual_search_note");
    return h("li", { class: "coverage-item" },
      h("div", { class: "coverage-head" }, h("strong", { text: c.name }), h("span", { class: `coverage-status ${c.status}`, text: label(c.status) })),
      h("p", { text: c.detail || "No further detail was supplied." }),
      c.manual_searches && c.manual_searches.length ? h("div", { class: "manual-searches" }, h("p", { class: "manual-search-note", text: note }), h("ul", {}, manualSearchNodes(c.manual_searches))) : null
    );
  });
}
function feedbackFlow(checkId, assessment, sampleText) {
  const m = botMsg();
  m.body.append(h("p", { text: t("fb_title") }));
  const options = [
    [t("fb_false_alarm"), () => sendFeedback(checkId, sampleText, assessment, "mistake_false_positive", "False alarm: legitimate message was flagged"), false],
    [t("fb_missed_scam"), () => sendFeedback(checkId, sampleText, assessment, "mistake_false_negative", "Missed scam: suspicious offer was not flagged"), false],
    [t("fb_inaccurate"), () => sendFeedback(checkId, sampleText, assessment, "inaccurate_detail", "Inaccurate explanation or details"), false],
  ];
  m.body.append(chipsRow(options, false));
  toEnd(m.li, "start");
}

async function sendFeedback(checkId, sampleText, assessment, feedbackType, comment) {
  try {
    await fetch("/v1/feedback", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        check_id: checkId,
        sample_text: sampleText || (assessment && assessment.summary) || "Check",
        predicted_label: (assessment && assessment.label) || "",
        predicted_category: (assessment && assessment.category && assessment.category.used) || null,
        user_feedback: feedbackType,
        user_comment: comment,
      }),
    });
    botSay(t("fb_thanks"));
  } catch (err) {
    botSay(t("err_generic"));
  }
}

function responseHighlights(parent, findings, limit = 2) {
  const items = (findings || []).filter(f => f && f.plain_text && f.why_it_matters).slice(0, limit);
  if (!items.length) return;
  const section = h("section", { class: "response-highlights", "aria-label": t("r_highlights") },
    h("h3", { text: t("r_highlights") }),
    h("div", { class: "response-highlight-list" }, items.map(item => h("article", { class: "response-highlight" },
      h("strong", { text: item.plain_text }),
      h("p", { text: item.why_it_matters }),
      item.excerpt ? h("blockquote", { text: `“${item.excerpt}”` }) : null
    )))
  );
  parent.append(section);
}

async function renderCheck(data, text, bubble) {
  const a = data.assessment, m = botMsg();
  if (!a || data.status === "failed_safely") { await stream(m.body.appendChild(h("p")), t("failed_safely")); return; }
  current = current || {};
  current.data = data; current.id = data.check_id; current.checkBubble = m.body; current.originalText = text; current.bubbleUser = bubble;
  m.body.append(h("div", {}, h("span", { class: "pill " + a.label }, pillIcon(a.label), h("span", { class: "pill-text", text: a.label_text || a.label }))));
  const pay = a.next_steps.find(n => /^(Don't pay in advance|Usilipe mapema)/.test(n.text));
  const p = h("p", { class: "check-summary" }); m.body.append(p);
  if (isReplaying) {
    p.textContent = strip(a.label, a.summary, !!pay);
  } else {
    await stream(p, strip(a.label, a.summary, !!pay));
  }
  // Put urgent advice immediately after the answer, before supporting details.
  if (pay) m.body.append(h("div", { class: "callout" }, h("strong", { "data-t-key": "before_pay", text: t("before_pay") }), h("span", { class: "callout-text", text: " " + pay.text })));
  responseHighlights(m.body, a.findings, 2);
  const rest = a.next_steps.filter(n => n !== pay);
  if (rest.length) {
    const nsWrap = h("div", { class: "next-steps-wrap" },
      h("p", {}, h("strong", { "data-t-key": "r_next", text: t("r_next") })),
      h("ol", { class: "next-steps-list" }, rest.map(n => h("li", { text: n.text })))
    );
    m.body.append(nsWrap);
  }
  const det = (cls, tKey, title, ...kids) => m.body.append(h("details", { class: cls }, h("summary", { "data-t-key": tKey, text: title }), ...kids));
  if (a.findings.length) det("det-why", "r_why", t("r_why"), h("ul", {}, findingNodes(a.findings)));
  intelligencePanels(m.body, a);
  if (a.coverage && a.coverage.length) det("det-checked", "r_checked", t("r_checked"), h("ul", { class: "coverage-list" }, coverageNodes(a)));
  if (a.limitations && a.limitations.length) det("det-limits", "r_limits", t("r_limits"), h("ul", {}, a.limitations.map(x => h("li", { text: x }))));
  if (a.sources.length) det("det-sources", "r_sources", t("r_sources"), h("ul", {}, a.sources.map(s => h("li", {}, h("span", { text: s.statement + " " }), s.source_url ? h("a", { href: s.source_url, rel: "noopener noreferrer", target: "_blank", text: t("open_source"), "data-t-key": "open_source" }) : null))));
  if (bubble && !data.evidence.length) { const hl = highlight(maskCreds(text), a.findings); if (hl) bubble.querySelector(".said").replaceChildren(...hl); }
  const id = data.check_id, tok = current && current.token;
  const isIncident = a.findings && a.findings.some(f => f.code === "REPORTED_FRAUD_INCIDENT");
  const chips = isIncident ? [
    [t("btn_report_this"), l => { userMsg(l, [], "btn_report_this"); reportFlow(); }, false, "btn_report_this"],
    [t("btn_reversal_help"), () => { userMsg(t("btn_reversal_help"), [], "btn_reversal_help"); recoveryFlow(true); }, false, "btn_reversal_help"],
    [t("share_whatsapp"), () => {
      const curA = (current && current.data && current.data.assessment) || a;
      const shareTxt = `*Toroka Alert:* ${curA.summary}\nVerify here: ${location.origin}/#r=${id}`;
      window.open(`https://api.whatsapp.com/send?text=${encodeURIComponent(shareTxt)}`, "_blank");
    }, false, "share_whatsapp"],
    [t("btn_report_mistake"), () => feedbackFlow(id, a, text), false, "btn_report_mistake"],
    [t("btn_delete"), () => deleteCheck(id, tok, m), false, "btn_delete"]
  ] : [
    [t("share_whatsapp"), () => {
      const curA = (current && current.data && current.data.assessment) || a;
      const shareTxt = `*Toroka Scam Check:* ${curA.summary}\n\nReview the evidence and verify important details independently: ${location.origin}/#r=${id}`;
      window.open(`https://api.whatsapp.com/send?text=${encodeURIComponent(shareTxt)}`, "_blank");
    }, false, "share_whatsapp"],
    [t("btn_report_this"), l => { userMsg(l, [], "btn_report_this"); reportFlow(); }, false, "btn_report_this"],
    [t("btn_report_mistake"), () => feedbackFlow(id, a, text), false, "btn_report_mistake"],
    [t("btn_delete"), () => deleteCheck(id, tok, m), false, "btn_delete"]
  ];
  m.body.append(chipsRow(chips, false));
  toEnd(m.li, "start");
  if (!isReplaying) {
    say(`${t("toroka_said")} ${a.label_text}. ${strip(a.label, a.summary)}`);
    convMessages.push({ role: "check", text, check_id: data.check_id, token: tok, data });
    saveOrUpdateCurrentConversation(text ? text.slice(0, 32) : "Screenshot check", a.summary);
    if (isIncident) setTimeout(() => { botSay(t("incident_ask_seller"), null, "incident_ask_seller"); }, 500);
  }
}
function highlight(original, findings) {
  const spans = [];
  for (const f of findings) { if (!f.excerpt || f.polarity === "positive") continue; const i = original.indexOf(f.excerpt); if (i >= 0) spans.push([i, i + f.excerpt.length]); }
  spans.sort((a, b) => a[0] - b[0]); if (!spans.length) return null;
  const out = []; let pos = 0;
  for (const [s, e] of spans) { if (s < pos) continue; out.push(document.createTextNode(original.slice(pos, s)), h("mark", {}, h("span", { class: "sr-only", text: lang === "sw" ? "imetiwa alama: " : "flagged: " }), original.slice(s, e))); pos = e; }
  out.push(document.createTextNode(original.slice(pos))); return out;
}
async function exportCheck(id, tok) {
  try { const d = await api(`/v1/checks/${id}/export`, { headers: { "X-Guest-Token": tok } }); const u = URL.createObjectURL(new Blob([JSON.stringify(d, null, 2)], { type: "application/json" })); const l = h("a", { href: u, download: "my-check.json" }); document.body.append(l); l.click(); l.remove(); setTimeout(() => URL.revokeObjectURL(u), 1000); }
  catch (e) { showError(e.message); }
}
async function deleteCheck(id, tok, m) {
  try { await api("/v1/checks/" + id, { method: "DELETE", headers: { "X-Guest-Token": tok } }); m.li.remove(); await botSay(t("deleted"), null, "deleted"); } catch (e) { showError(e.message); }
}

/* ---------- Lookups & Flows ---------- */
const PHONE = /^(?:\+?254|0)[\s-]?[17]\d{2}[\s-]?\d{3}[\s-]?\d{3}$/;
function parseId(s) {
  s = s.trim(); if (PHONE.test(s)) return ["phone", s];
  const m = /^(?:mpesa\s+)?(till|paybill)\s*(?:no\.?|number|#)?\s*[:\-]?\s*(\d{5,7})$/i.exec(s); if (m) return [m[1].toLowerCase(), m[2]];
  const profile = /^(?:https?:\/\/)?(?:www\.)?(instagram\.com|tiktok\.com|facebook\.com|x\.com|twitter\.com|threads\.net)\/@?([a-z0-9_.-]{2,50})\/?(?:[?#].*)?$/i.exec(s);
  if (profile) {
    const platform = /(?:^|\.)twitter\.com$/i.test(profile[1]) ? "x" : (profile[1].toLowerCase().split(".")[0]);
    return ["handle", `${platform}:${profile[2].toLowerCase()}`];
  }
  const prefixed = /^(instagram|tiktok|facebook|x|twitter|whatsapp|threads):@?([a-z0-9][a-z0-9_.-]{1,49})$/i.exec(s);
  if (prefixed) return ["handle", `${prefixed[1].toLowerCase() === "twitter" ? "x" : prefixed[1].toLowerCase()}:${prefixed[2].toLowerCase()}`];
  if (/^@[a-z0-9][a-z0-9_.-]{1,49}$/i.test(s)) return ["handle", s];
  if (!/\s/.test(s) && /^(?:https?:\/\/)?(?:www\.)?[a-z0-9-]+(?:\.[a-z0-9-]+)+(?:\/\S*)?$/i.test(s)) return ["domain", s];
  const embeddedTill = /\b(?:mpesa\s+)?(till|paybill)\s*(?:no\.?|number|#)?\s*[:\-]?\s*(\d{5,7})\b/i.exec(s);
  if (embeddedTill && s.length < 50) return [embeddedTill[1].toLowerCase(), embeddedTill[2]];
  return null;
}
async function lookup(type, value) {
  const th = think(value);
  try {
    const d = await api(`/v1/reports/search?type=${encodeURIComponent(type)}&value=${encodeURIComponent(value)}`); th.stop();
    if (!d.found) {
      const chips = [
        [t("btn_report_this"), () => { userMsg(t("btn_report_this"), [], "btn_report_this"); reportFlow(); }, false, "btn_report_this"],
        [t("btn_again"), () => newChat(), false, "btn_again"]
      ];
      await botSay(t("lk_none_full"), chips, "lk_none_full");
      saveOrUpdateCurrentConversation(`Lookup: ${value}`, t("lk_none_full"));
      return;
    }
    const matches = Array.isArray(d.matches) ? d.matches : [d.indicator];
    const m = botMsg();
    if (d.ambiguous_platform) m.body.append(h("p", { class: "help", text: d.message || t("lk_platform_ambiguous") }));
    for (const i of matches) {
      const section = h("div", { class: "lookup-match" });
      const pillSpan = h("span", { text: `${t("lk_found")}: ${i.identifier}` });
      pillSpan.dataset.lkFound = i.identifier;
      section.append(h("div", {}, h("span", { class: "pill inconclusive" }, pillIcon("inconclusive"), pillSpan)));
      const pCount = h("p", { text: `${i.independent_reports} ${t("lk_n")}.${i.last_reported ? " " + i.last_reported : ""}` });
      pCount.dataset.lkReports = String(i.independent_reports);
      pCount.dataset.lkLast = i.last_reported || "";
      section.append(pCount);
      if (i.status === "under_review") section.append(h("p", { "data-t-key": "lk_under", text: t("lk_under") }));
      section.append(h("p", { class: "help", "data-t-key": "lk_disclaimer", text: t("lk_disclaimer") }));
      section.append(chipsRow([[t("btn_correct"), l => { userMsg(l, [], "btn_correct"); appealFlow(i.id); }, false, "btn_correct"]]));
      m.body.append(section);
    }
    toEnd(m.li, "start");
    const lookupLabel = matches.map(i => i.identifier).join(", ");
    say(`${t("toroka_said")} ${t("lk_found")}: ${lookupLabel}`);
    saveOrUpdateCurrentConversation(`Lookup: ${lookupLabel}`, matches.map(i => `${i.independent_reports} ${t("lk_n")}`).join("; "));
  } catch (e) { th.stop(); await fail(e); }
}
function lookupAsk() {
  const onId = async txt => {
    if (looksLikeEvidence(txt, files)) {
      await doCheck(txt, files);
      return;
    }
    const id = parseId(txt);
    if (!id) {
      if (txt.length > 60 || /\b(?:challenge|fundraising|school fees|job|register|win|money|dollar|invest|cash)\b/i.test(txt)) {
        await doCheck(txt, files);
        return;
      }
      ask(t("rep_bad"), onId, null, "rep_bad");
      return;
    }
    await lookup(...id);
  };
  return ask(t("sug3_r"), onId, null, "sug3_r").then(() => saveOrUpdateCurrentConversation(t("sug3"), t("sug3_r")));
}

async function recoveryFlow(alreadyPaid = false) {
  const keys = alreadyPaid
    ? ["shared_credentials", "installed_app", "sent_id_documents"]
    : ["paid", "shared_credentials", "installed_app", "sent_id_documents"];
  const ans = alreadyPaid ? { paid: true } : {};
  if (alreadyPaid) await botSay(t("rec_start_paid"), null, "rec_start_paid");
  else await botSay(t("sug4_r"), null, "sug4_r");

  for (const k of keys) {
    const v = await new Promise(res => {
      botSay(t("q_" + k), [
        [t("yes"), () => res(true), false, "yes"],
        [t("no"), () => res(false), false, "no"],
        [t("unsure"), () => res(null), false, "unsure"]
      ], "q_" + k);
    });
    ans[k] = v;
    const vKey = v === true ? "yes" : (v === false ? "no" : "unsure");
    userMsg(t(vKey), [], vKey);
  }
  const th = think();
  try {
    const d = await api("/v1/recovery", { method: "POST", body: { ...ans, language: lang } });
    th.stop();
    const m = botMsg(); activeRecovery = { m, ans };
    const pReass = h("p", { text: d.reassurance }); pReass.dataset.rec = "reass"; m.body.append(pReass);
    if (d.steps.length) { const ol = h("ol", { class: "rec-steps" }, d.steps.map(s => h("li", { text: s.text }))); m.body.append(ol); }
    const pLim = h("p", { class: "help rec-limits", text: d.limits }); m.body.append(pLim);
    toEnd(m.li, "start"); say(d.reassurance);
    saveOrUpdateCurrentConversation("Payment Recovery Advice", d.reassurance);
  } catch (e) { th.stop(); await fail(e); }
}
function reportFlow() {
  const onStory = id => async story => {
    const th = think();
    try {
      const r = await api("/v1/reports", { method: "POST", body: { category: "message", narrative: story, identifiers: [{ type: id[0], value: id[1] }], consent_to_contact: false } }); th.stop();
      const m = await botSay(t("rp_done"), null, "rp_done"); m.body.append(h("p", {}, t("rp_keep") + " ", h("code", { text: r.report_token })));
    } catch (e) { th.stop(); await fail(e); }
  };
  const onId = async txt => { const id = parseId(txt); if (!id) { ask(t("rep_bad"), onId, null, "rep_bad"); return; } ask(t("rep_story"), onStory(id), null, "rep_story"); };
  return ask(t("rep_id"), onId, null, "rep_id");
}
function appealFlow(indicatorId) {
  ask(t("ap_contact"), contact => { ask(t("ap_stmt"), async stmt => {
    const th = think();
    try {
      const r = await api("/v1/appeals", { method: "POST", body: { indicator_id: indicatorId, contact, issue_type: "correction", statement: stmt } }); th.stop();
      const verify = async code => { try { await api(`/v1/appeals/${r.appeal_id}/verify`, { method: "POST", body: { code: code.trim() }, headers: { "X-Appeal-Token": r.appeal_token } }); await botSay(t("ap_open"), null, "ap_open"); } catch (e) { ask(t("ap_bad"), verify, null, "ap_bad"); } };
      ask(t("ap_sent"), verify, null, "ap_sent");
    } catch (e) { th.stop(); await fail(e); }
  }, null, "ap_stmt"); }, null, "ap_contact");
}
function suggestion(n) {
  if (busy) return;
  if (n === "screenshot") { $("#file").click(); return; }
  if (n === "mpesa") {
    userMsg(t("sug5_t"), [], "sug5_t");
    botSay(t("sug5_d") + ". " + t("prompt_mpesa_check")).then(() => saveOrUpdateCurrentConversation(t("sug5_t"), t("prompt_mpesa_check")));
    box().focus();
    return;
  }
  userMsg(t("sug" + n), [], "sug" + n);
  if (n === "1" || n === "2") botSay(t("sug" + n + "_r"), null, "sug" + n + "_r").then(() => { saveOrUpdateCurrentConversation(t("sug" + n), t("sug" + n + "_r")); box().focus(); });
  else if (n === "3") lookupAsk();
  else { saveOrUpdateCurrentConversation(t("sug4"), t("sug4_r")); recoveryFlow(false); }
}

/* ---------- Composer ---------- */
const box = () => $("#text");
// Detect full URLs, known social profiles, and bare domains (including common Kenyan TLDs).
// Global matching lets us skip email addresses and continue to a later real URL in the message.
const URL_EXTRACT_RX = /(?:https?:\/\/|www\.)[^\s<>"']+|(?:instagram\.com|tiktok\.com|facebook\.com|x\.com|twitter\.com)\/[@a-zA-Z0-9_.-]+|\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+(?:co\.ke|go\.ke|or\.ke|ac\.ke|sc\.ke|me\.ke|com|org|net|info|biz|xyz|shop|online|site|app|ke|io|ai|dev|store|tech|co|me|tv|mobi|travel|aero)(?:\/[^\s<>"']*)?/ig;

function detectComposerUrls(text) {
  if (!text) return null;
  const rx = new RegExp(URL_EXTRACT_RX.source, "ig");
  for (const match of text.matchAll(rx)) {
    const previous = match.index > 0 ? text[match.index - 1] : "";
    // Avoid treating an email address or the tail of a larger token as a website.
    if (previous && /[\w@.+-]/.test(previous)) continue;
    const candidate = match[0].replace(/[.,;:!?)\]}]+$/, "");
    if (candidate) return candidate;
  }
  return null;
}

function updateUrlPreview() {
  const bar = $("#url-preview-bar");
  if (!bar) return;
  const val = box().value;
  const url = detectComposerUrls(val);
  if (!url) {
    bar.hidden = true;
    return;
  }
  bar.hidden = false;
  const badge = $("#url-preview-badge");
  const target = $("#url-preview-target");
  if (/instagram\.com/i.test(url)) badge.textContent = "Instagram Profile";
  else if (/tiktok\.com/i.test(url)) badge.textContent = "TikTok Profile";
  else if (/facebook\.com/i.test(url)) badge.textContent = "Facebook Link";
  else if (/wa\.me|whatsapp\.com/i.test(url)) badge.textContent = "WhatsApp Link";
  else badge.textContent = t("url_detected") || "Link detected";
  
  target.textContent = url.length > 40 ? url.slice(0, 40) + "…" : url;
}

function fit() { const e = box(); e.style.height = "auto"; e.style.height = (!e.value ? "40px" : Math.max(40, Math.min(e.scrollHeight, 120)) + "px"); }
function syncSend() { $("#send").disabled = busy || (!box().value.trim() && !files.length); }
function renderFiles() {
  const ul = $("#attachments"); ul.replaceChildren(); ul.hidden = !files.length;
  const hasImages = files.some(isImageFile);
  const consentWrap = $("#campaign-image-consent");
  if (consentWrap) consentWrap.hidden = !hasImages;
  if (!hasImages) { const toggle = $("#campaign-image-consent-toggle"); if (toggle) toggle.checked = false; }
  files.forEach((f, i) => {
    const remove = h("button", { type: "button", "aria-label": t("remove_file") }, h("span", { text: "×", "aria-hidden": "true" }));
    remove.addEventListener("click", () => { if (f.__url) URL.revokeObjectURL(f.__url); files.splice(i, 1); renderFiles(); syncSend(); box().focus(); });
    const preview = isImageFile(f)
      ? h("img", { src: f.__url, alt: f.name })
      : h("span", { class: "attachment-file-chip", title: f.name }, svg("attachment-file-icon", "M8 3h6l5 5v13H5V3z", "M14 3v6h5"), h("span", { text: f.name }));
    ul.append(h("li", { class: isImageFile(f) ? "attachment-image-item" : "attachment-document-item" }, preview, remove));
  });
}
function compressImage(file, maxWidth = 1200) {
  if (!file.type.startsWith("image/") || file.size < 200000) return Promise.resolve(file);
  return new Promise(resolve => {
    const img = new Image(); const url = URL.createObjectURL(file); img.src = url;
    img.onload = () => {
      URL.revokeObjectURL(url);
      if (img.width <= maxWidth && file.size < 400000) { resolve(file); return; }
      const scale = Math.min(1, maxWidth / Math.max(img.width, 1));
      const c = document.createElement("canvas"); c.width = Math.round(img.width * scale); c.height = Math.round(img.height * scale);
      const ctx = c.getContext("2d"); ctx.drawImage(img, 0, 0, c.width, c.height);
      c.toBlob(blob => {
        if (!blob || blob.size >= file.size) { resolve(file); return; }
        resolve(new File([blob], file.name.replace(/\.[^.]+$/, ".jpg"), { type: "image/jpeg" }));
      }, "image/jpeg", 0.8);
    };
    img.onerror = () => { URL.revokeObjectURL(url); resolve(file); };
  });
}
async function addFiles(list) {
  for (const raw of list) {
    const image = isImageFile(raw);
    const name = String(raw.name || "").toLowerCase();
    let emailSource = [".eml", ".headers"].some(ext => name.endsWith(ext)) &&
      ["text/plain", "message/rfc822", "application/octet-stream", ""].includes(raw.type || "");
    if (!emailSource && name.endsWith(".txt") && (raw.type === "text/plain" || !raw.type)) {
      try { emailSource = looksLikeRawEmailSource(await raw.slice(0, 128 * 1024).text()); } catch (_) { emailSource = false; }
    }
    if (!image && !emailSource) { showError(t("err_type")); continue; }
    if (raw.size > MAX_BYTES || files.length >= MAX_FILES) { showError(t("err_files")); continue; }
    const file = image ? await compressImage(raw) : raw;
    if (image) file.__url = URL.createObjectURL(file);
    files.push(file);
  }
  renderFiles(); syncSend();
}
function looksLikeEvidence(text, fl) {
  if (fl && fl.length > 0) return true;
  if (!text) return false;
  if (/\b(?:https?:\/\/|www\.)\S+/i.test(text)) return true;
  if (/\b[A-Z0-9]{10}\s+Confirmed\b/i.test(text)) return true;
  if (/\b(?:till|paybill)\s*(?:no\.?|number|#)?\s*[:\-]?\s*\d{5,7}\b/i.test(text) && text.trim().split(/\s+/).length > 3) return true;
  if (text.length > 130 && !/^(hi|hello|habari|mambo|niaje|who|what|how|why|can|is|je|nawezaje|wewe)\b/i.test(text.trim())) return true;
  return false;
}
function shouldUseCurrentCheckContext(text) {
  if (!current || !current.id || !text) return false;
  const s = text.trim().toLowerCase();
  if (s.length > 180 || /(?:https?:\/\/|www\.|(?<![\w.+-])@[a-z0-9_.]{2,35}\b|(?:\+?254|0)[17]\d{8}|\b(?:till|paybill)\s*\d{5,7}|instagram:|tiktok:|facebook:|x:|whatsapp:)/i.test(s)) return false;
  if (/\b(?:look into|investigate|check|verify|audit|shop|seller|store|duka|muuzaji|menswear|clothes|clothing|brand|product|order|buy|new message|another shop|different shop|another link|analyze|analyse|inspect|kagua|chunguza)\b/i.test(s)) return false;
  return /^(?:why|how come|explain|tell me more|more details|what did you find|what did you check|what does that mean|what should i do|what next|is it safe|is this safe|could this be|i already paid|i paid|i clicked|i shared|i sent money|and if|what about that|can you explain|kwa nini|mbona|nielezee|niambie zaidi|nifanye nini|nimeshalipa|nimelipa|nilituma pesa|nilibonyeza|ndiyo|hapana)\b/i.test(s) || ["this one", "that one", "the second one", "same one", "hii", "hiyo"].includes(s);
}

function renderMarketplacePanel(marketplace, product) {
  if (!marketplace || !marketplace.name) return null;
  const sw = lang === "sw";
  const copy = sw ? {
    kicker: "TANGAZO LA SOKO",
    note: "Jukwaa limetambuliwa kupitia kiungo. Hii haithibitishi muuzaji binafsi, uhalisi wa bidhaa au uwasilishaji wake.",
    price: "Bei iliyoonyeshwa", brand: "Chapa", sku: "Nambari ya bidhaa",
    availability: "Upatikanaji ulioonyeshwa", seller: "Muuzaji aliyeonyeshwa",
    sellerRating: "Ukadiriaji wa muuzaji", productRating: "Ukadiriaji wa bidhaa",
    ratings: "ukadiriaji", reviewsTitle: "Maoni yaliyoonyeshwa kwenye tangazo",
    reviewNote: "Haya ni maoni yaliyotolewa na ukurasa; hayajathibitishwa kivyake.",
    delivery: "Ukurasa una maneno kuhusu uwasilishaji", returns: "Ukurasa una maneno kuhusu kurejesha bidhaa au pesa",
    readTerms: "Soma masharti halisi kabla ya kuagiza.",
    partial: "Ukurasa ulirudisha HTML inayosomeka, lakini Toroka haikuweza kutoa maelezo ya bidhaa yaliyopangwa. Hili linaweza kutokea pale jukwaa linapopakia data kwa JavaScript au kuzuia maudhui ya ukurasa.",
    unread: "Toroka imetambua jukwaa kupitia URL, lakini haikuweza kusoma yaliyomo kwenye tangazo. Hakuna maelezo ya bidhaa au muuzaji yaliyokisiwa.",
    sellerCaveat: "Uthibitishaji wa muuzaji: haujafanywa kivyake. Lipa kupitia mfumo rasmi wa malipo na ulinzi wa mnunuzi wa jukwaa pekee."
  } : {
    kicker: "MARKETPLACE LISTING",
    note: "The platform was identified from the link. This does not verify the individual seller, the product's authenticity or successful delivery.",
    price: "Price shown", brand: "Brand", sku: "Product reference",
    availability: "Availability shown", seller: "Seller shown",
    sellerRating: "Seller rating shown", productRating: "Product rating shown",
    ratings: "ratings", reviewsTitle: "Review text displayed on the listing",
    reviewNote: "These are excerpts supplied by the page, not independently verified customer reviews.",
    delivery: "Delivery wording appears on the page", returns: "Return or refund wording appears on the page",
    readTerms: "Read the actual terms before ordering.",
    partial: "The page returned readable HTML, but Toroka could not extract structured product details. This can happen when a marketplace loads listing data with JavaScript or restricts automated page content.",
    unread: "Toroka could identify the marketplace from the URL, but could not read the listing contents. No product or seller details are being assumed.",
    sellerCaveat: "Seller verification: not independently verified. Keep payment inside the marketplace's official checkout and buyer-protection process."
  };
  const panel = h("section", { class: "marketplace-evidence", "aria-label": sw ? "Maelezo ya tangazo la sokoni" : "Marketplace listing details" });
  panel.append(h("div", { class: "marketplace-evidence-kicker", text: copy.kicker }));
  panel.append(h("h4", { class: "marketplace-evidence-title", text: marketplace.name }));
  panel.append(h("p", { class: "marketplace-evidence-note", text: copy.note }));

  const data = product && typeof product === "object" ? product : {};
  if (data.detected) {
    if (data.name) panel.append(h("h5", { class: "marketplace-product-name", text: data.name }));
    const rows = [];
    if (data.price !== null && data.price !== undefined && Number.isFinite(Number(data.price))) {
      const amount = Number(data.price).toLocaleString(undefined, { maximumFractionDigits: 2 });
      rows.push([copy.price, `${data.currency || (sw ? "Bei" : "Price")} ${amount}`]);
    }
    if (data.brand) rows.push([copy.brand, data.brand]);
    if (data.sku) rows.push([copy.sku, data.sku]);
    if (data.availability) rows.push([copy.availability, data.availability]);
    if (data.seller_name) rows.push([copy.seller, data.seller_name]);
    if (data.seller_rating !== null && data.seller_rating !== undefined) rows.push([copy.sellerRating, `${data.seller_rating}/5`]);
    if (data.aggregate_rating !== null && data.aggregate_rating !== undefined) {
      const count = data.rating_count !== null && data.rating_count !== undefined ? ` (${data.rating_count} ${copy.ratings})` : "";
      rows.push([copy.productRating, `${data.aggregate_rating}/5${count}`]);
    }
    if (rows.length) {
      const list = h("dl", { class: "marketplace-product-facts" });
      for (const [label, value] of rows) list.append(h("div", { class: "marketplace-product-fact" }, h("dt", { text: label }), h("dd", { text: String(value) })));
      panel.append(list);
    }
    if (data.description) panel.append(h("p", { class: "marketplace-product-description", text: data.description }));
    if (data.delivery_terms_found || data.return_terms_found) {
      const terms = [];
      if (data.delivery_terms_found) terms.push(copy.delivery);
      if (data.return_terms_found) terms.push(copy.returns);
      panel.append(h("p", { class: "marketplace-product-terms", text: terms.join(" · ") + `. ${copy.readTerms}` }));
    }
    if (Array.isArray(data.review_excerpts) && data.review_excerpts.length) {
      panel.append(h("h5", { class: "marketplace-reviews-title", text: copy.reviewsTitle }));
      panel.append(h("ul", { class: "marketplace-review-excerpts" }, data.review_excerpts.map(item => h("li", { text: String(item) }))));
      panel.append(h("p", { class: "marketplace-evidence-note", text: copy.reviewNote }));
    }
  } else {
    panel.append(h("p", { class: "marketplace-evidence-unavailable", text: marketplace.page_read ? copy.partial : copy.unread }));
  }
  panel.append(h("p", { class: "marketplace-seller-caveat", text: copy.sellerCaveat }));
  return panel;
}
function renderDecisionCard(d) {
  const card = h("section", { class: "decision-report", "aria-label": d.headline || "Investigation decision" });
  const status = h("p", { class: "decision-headline", text: d.headline || "I could not reach a reliable conclusion yet." });
  card.append(status);
  const marketplacePanel = renderMarketplacePanel(d.marketplace, d.product);
  if (marketplacePanel) card.append(marketplacePanel);
  const headers = d.headers || {};
  const section = (title, items, tag = "ul", cls = "") => {
    if (!Array.isArray(items) || !items.length) return;
    card.append(h("h4", { text: title }));
    card.append(h(tag, { class: cls }, items.map(item => h("li", { text: String(item) }))));
  };
  section(headers.hdr_found || "What I found", d.found);
  section(headers.hdr_red || "Warning signs", d.red_flags);
  section(headers.hdr_good || "Positive signs", d.good_signs);
  section(headers.hdr_unknown || "What I could not check", d.could_not_check);
  if (Array.isArray(d.before_you_pay) && d.before_you_pay.length) {
    const advice = h("div", { class: "decision-safety" });
    advice.append(h("h4", { text: headers.hdr_before || "Before you pay" }));
    advice.append(h("ul", {}, d.before_you_pay.map(item => h("li", { text: String(item) }))));
    card.append(advice);
  }
  section(headers.hdr_find || "Five checks you can do yourself", d.how_to_find_out, "ol", "decision-self-checks");
  if (d.ask_the_seller) {
    card.append(h("h4", { text: headers.hdr_ask || "A message you can send the seller" }));
    const textarea = h("textarea", { readonly: true, rows: "5", "aria-label": headers.hdr_ask || "Message to seller" });
    textarea.value = String(d.ask_the_seller);
    const copy = h("button", { type: "button", class: "decision-copy", text: "Copy message" });
    copy.addEventListener("click", async () => {
      try { await navigator.clipboard.writeText(textarea.value); copy.textContent = "Copied"; }
      catch (_) { textarea.focus(); textarea.select(); copy.textContent = "Select and copy"; }
    });
    card.append(textarea, copy);
  }
  if (Array.isArray(d.if_you_already_paid) && d.if_you_already_paid.length) {
    card.append(h("details", { class: "decision-paid" },
      h("summary", { text: headers.hdr_paid || "If you already paid" }),
      h("ul", {}, d.if_you_already_paid.map(item => h("li", { text: String(item) })) )));
  }
  if (d.confidence_note) card.append(h("p", { class: "decision-confidence", text: d.confidence_note }));
  return card;
}
async function renderUrlInvestigation(inv, replyText, actionChips) {
  current = { id: null, type: "url_investigation", data: inv };
  const m = botMsg();
  if (inv.decision) m.body.append(renderDecisionCard(inv.decision));
  const band = inv.risk_band || "inconclusive";
  const pillLabel = band === "verified_official" ? "Verified Official" : (band === "high_risk" ? "High Risk" : (band === "suspicious_verify_first" ? "Caution" : (band === "no_known_threats_found" ? "No Known Threats Found" : "Inconclusive")));
  if (!inv.decision) {
    m.body.append(h("div", {}, h("span", { class: "pill " + band }, pillIcon(band), h("span", { class: "pill-text", text: pillLabel }))));
    
    const pSum = h("p", { class: "check-summary" });
    m.body.append(pSum);
    if (isReplaying) {
      pSum.textContent = inv.summary;
    } else {
      await stream(pSum, inv.summary);
    }

    responseHighlights(m.body, inv.findings, 3);
  }

  if (!inv.decision && inv.contradictions && inv.contradictions.length) {
    const cBox = h("div", { class: "contradiction-callout" });
    cBox.append(h("strong", { text: (t("url_contradictions") || "Contradictions detected") + ": " }));
    inv.contradictions.forEach(c => cBox.append(h("p", { text: c })));
    m.body.append(cBox);
  }

  if (!inv.decision && inv.next_steps && inv.next_steps.length) {
    const nsWrap = h("div", { class: "next-steps-wrap" },
      h("p", {}, h("strong", { "data-t-key": "r_next", text: t("r_next") })),
      h("ol", { class: "next-steps-list" }, inv.next_steps.map(s => h("li", { text: s })))
    );
    m.body.append(nsWrap);
  }

  const det = (cls, tKey, title, ...kids) => m.body.append(h("details", { class: cls }, h("summary", { "data-t-key": tKey, text: title }), ...kids));
  
  if (!inv.decision && inv.findings && inv.findings.length) {
    det("det-why", "r_why", t("r_why"), h("ul", {}, findingNodes(inv.findings)));
  }
  if (inv.investigation_intelligence) {
    intelligencePanels(m.body, { category: { used: inv.investigation_intelligence.category }, investigation_intelligence: inv.investigation_intelligence });
  }

  if (!inv.decision && inv.coverage && inv.coverage.length) {
    const label = status => ({
      checked: t("cov_checked"),
      checked_match: t("cov_checked_match") || "Match found",
      checked_no_match: t("cov_checked_no_match") || "No reports found",
      not_configured: t("cov_not_configured") || "Not configured",
      not_checked: t("cov_not_checked"),
      could_not_check: t("cov_could_not_check"),
      failed: t("cov_failed") || "Failed",
      not_found: t("cov_not_found"),
      partial: t("cov_could_not_check")
    })[status] || status;
    det("det-checked", "r_checked", t("r_checked"), h("ul", { class: "coverage-list" }, inv.coverage.map(c => h("li", { class: "coverage-item" },
      h("div", { class: "coverage-head" }, h("strong", { text: c.name }), h("span", { class: `coverage-status ${c.status}`, text: label(c.status) })),
      h("p", { text: c.detail })
    ))));
  }

  if (inv.sources && inv.sources.length) {
    det("det-sources", "r_sources", t("r_sources"), h("ul", {}, inv.sources.map(s => h("li", {}, h("span", { text: s.statement + " " }), s.source_url ? h("a", { href: s.source_url, rel: "noopener noreferrer", target: "_blank", text: t("open_source") }) : null))));
  }

  if (!inv.decision && inv.limitations && inv.limitations.length) {
    det("det-limits", "r_limits", t("r_limits"), h("ul", {}, inv.limitations.map(x => h("li", { text: x }))));
  }

  const chips = [];
  if (actionChips && actionChips.length) {
    for (const c of actionChips) {
      chips.push([c.label, () => {
        userMsg(c.label);
        if (c.action === "report") reportFlow();
        else if (c.action === "reversal") recoveryFlow(true);
        else lookupAsk();
      }, false]);
    }
  } else {
    chips.push([t("share_whatsapp"), () => {
      const shareTxt = `*Toroka Scam Check:* ${inv.summary}\n\nReview evidence: ${location.origin}`;
      window.open(`https://api.whatsapp.com/send?text=${encodeURIComponent(shareTxt)}`, "_blank");
    }, false]);
  }
  m.body.append(chipsRow(chips, false));

  toEnd(m.li, "start");
  if (!isReplaying) {
    say(`${t("toroka_said")} ${inv.summary}`);
    convMessages.push({ role: "url_investigation", text: inv.target_url, data: inv });
    saveOrUpdateCurrentConversation(inv.domain || inv.target_url, inv.summary);
  }
}

async function doChat(text) {
  const th = think();
  chatHistory.push({ role: "user", text: maskCreds(text) });
  try {
    const payload = { message: text, history: chatHistory.slice(-10), language: lang, check_id: shouldUseCurrentCheckContext(text) ? current.id : null };
    const res = await api("/v1/chat", { method: "POST", body: payload }); th.stop();
    chatHistory.push({ role: "model", text: res.reply });
    if (res.url_investigation) {
      await renderUrlInvestigation(res.url_investigation, res.reply, res.action_chips);
      return;
    }
    const chips = [];
    if (res.action_chips && res.action_chips.length) {
      for (const chip of res.action_chips) {
        const k = chip.key || (chip.action === "reversal" ? "btn_reversal_help" : (chip.action === "report" ? "btn_report_this" : "btn_lookup_another"));
        const lbl = t(k) || chip.label;
        if (chip.action === "reversal") chips.push([lbl, () => { userMsg(t(k) || lbl, [], k); recoveryFlow(true); }, false, k]);
        else if (chip.action === "report") chips.push([lbl, () => { userMsg(t(k) || lbl, [], k); reportFlow(); }, false, k]);
        else if (chip.action === "lookup") chips.push([lbl, () => { userMsg(t(k) || lbl, [], k); lookupAsk(); }, false, k]);
      }
    }
    const m = await botSay(res.reply, chips.length ? chips : null);
    if (m && m.body) {
      const manualNodes = manualSearchNodes(res.manual_searches);
      const isLiveRun = res.url_investigation && res.url_investigation.coverage && res.url_investigation.coverage.some(c => c.id === "tavily_search" && (c.status === "checked_match" || c.status === "checked_no_match"));
      const note = isLiveRun ? (t("live_search_note") || "Toroka searched public records automatically. Use these links to inspect public results yourself.") : t("manual_search_note");
      if (manualNodes.length) m.body.append(h("div", { class: "manual-searches chat-manual-searches" }, h("p", { class: "manual-search-note", text: note }), h("ul", {}, manualNodes)));
      const wrap = m.body.querySelector(".bot-content");
      if (wrap && res.reply_en && res.reply_sw) { wrap.dataset.textEn = res.reply_en; wrap.dataset.textSw = res.reply_sw; }
    }
    saveOrUpdateCurrentConversation(text.slice(0, 32), res.reply);
  } catch (e) { th.stop(); await fail(e); }
}
function looksLikeRawEmailSource(text) {
  if (!text || text.length < 40) return false;
  const lines = text.split(/\r?\n/).slice(0, 100);
  const headerNames = ["from", "to", "cc", "subject", "date", "sender", "reply-to", "return-path", "received", "message-id", "authentication-results", "dkim-signature", "mime-version", "content-type"];
  const found = new Set();
  for (const line of lines) {
    const match = /^([A-Za-z][A-Za-z0-9-]{1,40}):\s*/.exec(line);
    if (match && headerNames.includes(match[1].toLowerCase())) found.add(match[1].toLowerCase());
  }
  const hasSender = found.has("from") || found.has("sender");
  const supporting = ["to", "subject", "date", "received", "return-path", "authentication-results", "dkim-signature", "mime-version"].some(x => found.has(x));
  return hasSender && supporting && found.size >= 2;
}

async function doEmailCheck({ file = null, rawText = "", bubble = null, label = "" } = {}) {
  const context = file ? `email ${file.name || "attachment"}` : rawText.slice(0, 160);
  const th = think(context || "email investigation");
  try {
    const formData = new FormData();
    if (file) formData.append("file", file, file.name || "original-email.eml");
    else formData.append("raw_email", rawText);
    formData.append("allow_dns_checks", "false");
    const result = await api("/v1/email/analyze", { method: "POST", form: formData });
    th.stop();
    const m = botMsg();
    const report = h("section", { class: "email-results email-results-chat", "aria-label": t("email_report_aria") });
    m.body.append(report);
    renderEmailForensicsResult(result, report);
    const summary = result.summary || t("email_done");
    convMessages.push({ role: "bot", text: summary });
    saveOrUpdateCurrentConversation(label || t("email_title"), summary);
    if (bubble && !label) bubble.dataset.emailAnalyzed = "true";
  } catch (error) {
    th.stop();
    await fail(error);
  }
}

async function submit(ev) {
  ev && ev.preventDefault(); if (busy) return; clearError();
  const text = box().value.trim(), fl = files.slice(); if (!text && !fl.length) return;
  const emailFile = fl.find(isEmailSourceFile) || null;
  const imageFiles = fl.filter(isImageFile);
  const rawEmail = !emailFile && looksLikeRawEmailSource(text);
  const crossCaseImageConsent = imageFiles.length > 0 && $("#campaign-image-consent-toggle")?.checked === true;
  box().value = ""; files = []; fit(); renderFiles(); busy = true; syncSend();
  const displayText = emailFile && !text
    ? (lang === "sw" ? `Barua pepe asili imeambatishwa: ${emailFile.name}` : `Original email attached: ${emailFile.name}`)
    : rawEmail
      ? (lang === "sw" ? "Chanzo cha barua pepe kimetumwa kwa uchunguzi" : "Email source provided for investigation")
      : (text || (fl.length ? t("count_shots") : ""));
  const imageUrls = imageFiles.filter(f => f.__url).map(f => f.__url);
  const u = userMsg(displayText, imageUrls, null, fl.map(f => f.name));
  try {
    pending = null;
    if (emailFile || rawEmail) {
      await doEmailCheck({ file: emailFile, rawText: rawEmail ? text : "", bubble: u.bubble, label: emailFile?.name || t("email_title") });
      if (imageFiles.length) await doCheck(text || "Screenshots accompanying an email investigation", imageFiles, u.bubble, crossCaseImageConsent);
    } else if (imageFiles.length > 0 || looksLikeEvidence(text, imageFiles)) {
      await doCheck(text, imageFiles, u.bubble, crossCaseImageConsent);
    } else if (pending) {
      const fn = pending; pending = null; await fn(text);
    } else {
      const id = parseId(text);
      if (id && id[0] !== "domain" && id[0] !== "handle" && text.length < 30 && !fl.length && !current) await lookup(...id);
      else await doChat(text);
    }
  } finally { busy = false; syncSend(); box().focus(); }
}
/* ---------- Email forensics: raw .eml/header analysis ---------- */
function renderEmailForensicsResult(data, targetRoot = null) {
  const root = targetRoot || $("#email-forensics-results");
  if (!root) return;
  root.replaceChildren();
  root.hidden = false;
  const attention = data.attention_level || "insufficient_email_identity_data";
  const cls = attention === "high_attention" ? "high" : (attention === "review_recommended" || attention === "some_indicators") ? "review" : "";
  const attentionLabel = attention === "high_attention" ? t("email_high") :
    attention === "review_recommended" ? t("email_review") :
    attention === "some_indicators" ? t("email_some") : t("email_no_major");
  root.append(h("div", { class: "email-attention " + cls },
    h("strong", { text: attentionLabel }),
    h("p", { text: data.summary || "" })
  ));
  const group = (title, items) => {
    if (!items || !items.length) return;
    const list = h("ul", { class: "email-result-list" });
    items.forEach(item => {
      const main = typeof item === "string" ? item : item.main;
      const detail = typeof item === "string" ? "" : item.detail;
      const li = h("li", {}, main || "");
      if (detail) li.append(h("small", { text: detail }));
      list.append(li);
    });
    root.append(h("section", { class: "email-result-group" }, h("h3", { text: title }), list));
  };
  const sender = data.sender_identity || {};
  const fmt = arr => (arr || []).map(x => `${x.display_name ? x.display_name + " — " : ""}${x.address}`);
  const senderRows = [];
  if (sender.from?.length) senderRows.push({ main: t("email_from") + ": " + fmt(sender.from).join("; "), detail: sender.from_domain || "" });
  if (sender.reply_to?.length) senderRows.push({ main: t("email_reply") + ": " + fmt(sender.reply_to).join("; ") });
  if (sender.return_path_domain) senderRows.push({ main: t("email_return") + ": " + sender.return_path_domain });
  if (sender.sender?.length) senderRows.push({ main: "Sender: " + fmt(sender.sender).join("; ") });
  group(t("email_sender"), senderRows);

  const auth = data.authentication || {};
  const authRows = [];
  (auth.trusted_receiver_results || []).forEach(x => authRows.push({ main: `${x.authserv_id}: ${Object.entries(x.results || {}).map(([k, v]) => k.toUpperCase() + "=" + v).join(" · ")}`, detail: t("email_trusted") }));
  (auth.untrusted_header_claims || []).forEach(x => authRows.push({ main: `${x.authserv_id || "Unknown receiver"}: ${Object.entries(x.results || {}).map(([k, v]) => k.toUpperCase() + "=" + v).join(" · ")}`, detail: t("email_untrusted") }));
  if (auth.dkim_signature_count) authRows.push({ main: `${t("email_dkim")}: ${auth.dkim_verification?.status || t("email_not_checked")}` });
  const dns = auth.dns_posture;
  if (dns?.status === "checked") (dns.domains || []).forEach(x => authRows.push({ main: `${t("email_dns")}: ${x.domain}`, detail: `SPF records: ${x.spf_record_count}; DMARC records: ${x.dmarc_record_count}; DMARC policy: ${x.dmarc_policy || "not found"}` }));
  if (!authRows.length) authRows.push({ main: t("email_not_checked") });
  group(t("email_auth"), authRows);

  const findings = (data.findings || []).map(x => ({
    main: `${x.title || x.code} `,
    detail: `${x.detail || ""}${x.limitation ? " " + x.limitation : ""}`
  }));
  group(t("email_findings"), findings.length ? findings : [{ main: t("email_no_findings") }]);
  const linkRows = (data.links?.items || []).map(x => ({
    main: `${x.display_text ? x.display_text + " → " : ""}${x.destination_host || "Unrecognized destination"}`,
    detail: (x.warning_codes || []).join(" · ")
  }));
  group(t("email_links"), linkRows);
  const attachmentRows = (data.attachments?.items || []).map(x => ({
    main: `${x.filename} (${x.content_type}, ${x.size_bytes} bytes)`,
    detail: `${x.risk_note || "No extension-based warning"}${x.sha256 ? " · SHA-256: " + x.sha256 : ""}`
  }));
  group(t("email_attachments"), attachmentRows);
  const hopRows = (data.routing?.hops || []).map((x, i) => ({
    main: `${i + 1}. ${x.from_host || "unknown source"} → ${x.by_host || "unknown receiving host"}`,
    detail: x.date_text || ""
  }));
  group(t("email_routing"), hopRows);
  group(t("email_limits"), (data.limitations || []).map(x => ({ main: x })));
}


/* ---------- ChatGPT-style composer actions menu ---------- */
function closeComposerActionsMenu({ restoreFocus = false } = {}) {
  const menu = $("#composer-actions-menu"), trigger = $("#attach");
  if (!menu || !trigger || menu.hidden) return;
  menu.hidden = true;
  trigger.setAttribute("aria-expanded", "false");
  if (restoreFocus) trigger.focus();
}
function openComposerActionsMenu() {
  const menu = $("#composer-actions-menu"), trigger = $("#attach");
  if (!menu || !trigger) return;
  menu.hidden = false;
  trigger.setAttribute("aria-expanded", "true");
  menu.querySelector("[role='menuitem']")?.focus();
}
function toggleComposerActionsMenu() {
  const menu = $("#composer-actions-menu");
  if (!menu) return;
  if (menu.hidden) openComposerActionsMenu(); else closeComposerActionsMenu();
}
async function pasteComposerClipboard() {
  try {
    if (!navigator.clipboard?.readText) throw new Error("Clipboard access unavailable");
    const value = await navigator.clipboard.readText();
    if (value) {
      const el = box(), start = el.selectionStart ?? el.value.length, end = el.selectionEnd ?? start;
      el.setRangeText(value, start, end, "end");
      fit(); syncSend(); el.focus();
    }
  } catch (_) {
    box().focus();
    showError(t("clipboard_unavailable"));
  }
}
function insertComposerPrompt(key) {
  const prompts = {
    menu_prompt_link: t("insert_link_prompt"),
    menu_prompt_shop: t("insert_shop_prompt"),
    menu_prompt_payment: t("insert_payment_prompt")
  };
  const value = prompts[key];
  if (!value) return;
  const el = box();
  if (el.value.trim()) el.value = `${el.value.trim()}\n${value}`;
  else el.value = value;
  fit(); syncSend(); el.focus(); el.setSelectionRange(el.value.length, el.value.length);
}
function initComposerActionsMenu() {
  const menu = $("#composer-actions-menu"), trigger = $("#attach"), input = $("#file");
  if (!menu || !trigger || !input) return;
  trigger.addEventListener("click", toggleComposerActionsMenu);
  $("#menu-add-images")?.addEventListener("click", () => {
    closeComposerActionsMenu(); input.accept = "image/png,image/jpeg,image/webp"; input.click();
  });
  $("#menu-add-email")?.addEventListener("click", () => {
    closeComposerActionsMenu(); input.accept = ".eml,.headers,.txt,message/rfc822,text/plain,application/octet-stream"; input.click();
  });
  $("#menu-paste")?.addEventListener("click", () => { closeComposerActionsMenu(); pasteComposerClipboard(); });
  menu.querySelectorAll("[data-menu-prompt]").forEach(button => button.addEventListener("click", () => {
    const key = button.dataset.menuPrompt;
    closeComposerActionsMenu(); insertComposerPrompt(key);
  }));
  menu.addEventListener("keydown", ev => {
    const items = [...menu.querySelectorAll("[role='menuitem']:not(:disabled)")];
    const index = items.indexOf(document.activeElement);
    if (ev.key === "Escape") { ev.preventDefault(); closeComposerActionsMenu({ restoreFocus: true }); }
    else if (ev.key === "ArrowDown" || ev.key === "ArrowUp") {
      ev.preventDefault();
      const delta = ev.key === "ArrowDown" ? 1 : -1;
      items[(index + delta + items.length) % items.length]?.focus();
    }
    else if (ev.key === "Home") { ev.preventDefault(); items[0]?.focus(); }
    else if (ev.key === "End") { ev.preventDefault(); items.at(-1)?.focus(); }
  });
  document.addEventListener("pointerdown", ev => {
    if (!menu.hidden && !ev.target.closest(".composer-actions-wrap")) closeComposerActionsMenu();
  });
  document.addEventListener("keydown", ev => {
    if (ev.key === "Escape" && !menu.hidden) { ev.preventDefault(); closeComposerActionsMenu({ restoreFocus: true }); }
  });
}

/* ---------- Language & Boot ---------- */
function applyLang(l) {
  lang = l; document.documentElement.lang = l;
  $("#lang-en").setAttribute("aria-pressed", String(l === "en")); $("#lang-sw").setAttribute("aria-pressed", String(l === "sw"));
  $("#set-lang-en")?.classList.toggle("active", l === "en"); $("#set-lang-sw")?.classList.toggle("active", l === "sw");
  const set = (sel, k) => { const e = $(sel); if (e) e.textContent = t(k); };
  set("#welcome-h", "welcome_hi"); set("#welcome-subtitle", "welcome_sub"); set("#welcome-p", "welcome_desc");
  set("#page-h", "page_h"); $("#composer").setAttribute("aria-label", t("compose_label"));
  const fineEl = $("#fine [data-t-key='disclaimer_fine']"); if (fineEl) fineEl.textContent = t("disclaimer_fine");
  set("#new-chat", "btn_new_check"); set("#skip", "skip_to");
  set("#recent-chats-label", "recent_chats");
  if (!activeConversationId) set("#header-main-title", "active_check_title");
  set("#header-sub-title", "active_check_sub");
  set("#sug1 .prompt-card-title", "sug1_t"); set("#sug1 .prompt-card-desc", "sug1_d");
  set("#sug2 .prompt-card-title", "sug2_t"); set("#sug2 .prompt-card-desc", "sug2_d");
  set("#sug3 .prompt-card-title", "sug3_t"); set("#sug3 .prompt-card-desc", "sug3_d");
  set("#sug4 .prompt-card-title", "sug4_t"); set("#sug4 .prompt-card-desc", "sug4_d");
  box().placeholder = t("ph"); $("#attach").setAttribute("aria-label", t("attach")); $("#send").setAttribute("aria-label", t("send")); thread().setAttribute("aria-label", t("conv"));
  $(".lang").setAttribute("aria-label", t("lang_label")); $("#logo").setAttribute("aria-label", "Toroka, " + t("new_chat")); document.body.dataset.drop = t("dropped");
  $("#sidebar-toggle-btn")?.setAttribute("aria-label", t("sidebar_toggle_label")); $("#sidebar-toggle-btn")?.setAttribute("title", t("sidebar_toggle_label"));
  $("#mobile-menu-btn")?.setAttribute("aria-label", t("mobile_menu_label")); $("#mobile-menu-btn")?.setAttribute("title", t("mobile_menu_label"));
  $("#sidebar-close-btn")?.setAttribute("aria-label", t("close_menu_label")); $("#sidebar-close-btn")?.setAttribute("title", t("close_menu_label"));
  const topSearch = $("#top-search-input"); if (topSearch) { topSearch.placeholder = t("search_conv_placeholder"); topSearch.setAttribute("aria-label", t("search_conv_label")); }
  const sideSearch = $("#sidebar-search-input"); if (sideSearch) { sideSearch.placeholder = t("search_conv_placeholder"); sideSearch.setAttribute("aria-label", t("search_conv_label")); }

  document.querySelectorAll("[data-t-key]").forEach(el => {
    const k = el.dataset.tKey;
    if (k) {
      if (el.classList.contains("bot-content")) renderRichContent(el, t(k));
      else el.textContent = t(k);
    }
  });
  document.querySelectorAll(".bot-content[data-text-en][data-text-sw]").forEach(el => {
    const txt = l === "sw" ? el.dataset.textSw : el.dataset.textEn;
    renderRichContent(el, txt);
  });
  document.querySelectorAll("[data-lk-found]").forEach(el => { el.textContent = `${t("lk_found")}: ${el.dataset.lkFound}`; });
  document.querySelectorAll("[data-lk-reports]").forEach(el => {
    const n = el.dataset.lkReports, last = el.dataset.lkLast ? " " + el.dataset.lkLast : "";
    el.textContent = `${n} ${t("lk_n")}.${last}`;
  });
  document.querySelectorAll(".msg.user .sr-only").forEach(el => { el.textContent = t("you_said") + " "; });
  document.querySelectorAll(".msg.bot .reply > .sr-only").forEach(el => { el.textContent = t("toroka_said") + " "; });

  if (activeRecovery && activeRecovery.m && activeRecovery.ans) {
    api("/v1/recovery", { method: "POST", body: { ...activeRecovery.ans, language: l } }).then(d => {
      const pReass = activeRecovery.m.body.querySelector('[data-rec="reass"]');
      if (pReass) pReass.textContent = d.reassurance;
      const ol = activeRecovery.m.body.querySelector("ol.rec-steps");
      if (ol && d.steps) ol.replaceChildren(...d.steps.map(s => h("li", { text: s.text })));
      const pLim = activeRecovery.m.body.querySelector("p.rec-limits");
      if (pLim) pLim.textContent = d.limits;
    }).catch(() => {});
  }
  if (current && current.id && current.checkBubble) {
    api(`/v1/checks/${current.id}?lang=${l}`, { headers: current.token ? { "X-Guest-Token": current.token } : {} }).then(d => {
      current.data = d; updateCheckBubbleContent(current.checkBubble, d);
    }).catch(() => {});
  }
  renderSidebarHistory();
}
function newChat() {
  closeMobileSidebar(false);
  $("#app-layout")?.classList.remove("chat-active");
  thread().replaceChildren(); thread().hidden = true; $("#welcome").hidden = false;
  activeConversationId = null; current = null; pending = null; files = []; chatHistory = []; convMessages = [];
  const imageConsent = $("#campaign-image-consent-toggle"); if (imageConsent) imageConsent.checked = false;
  sidebarView = "recent"; sidebarSearchQuery = "";
  const sideSearch = $("#sidebar-search-input"); if (sideSearch) sideSearch.value = "";
  const sideSearchField = $("#sidebar-search-field"); if (sideSearchField) sideSearchField.hidden = true;
  const titleEl = $("#header-main-title"); if (titleEl) titleEl.textContent = t("active_check_title");
  renderFiles(); box().value = ""; fit(); syncSend(); clearError(); renderSidebarHistory("");
  box().focus();
  const r = $("#welcome .runner"); if (r) run(r, 2600);
}
async function openShared(id, tok) {
  const th = think();
  try { const d = await api(`/v1/checks/${id}?lang=${lang}`, { headers: { "X-Guest-Token": tok } }); th.stop(); current = { id, token: tok, text: "" }; await renderCheck(d, "", null); } catch (e) { th.stop(); await fail(e); }
}
function boot() {
  initTheme();
  document.querySelectorAll("[data-runner]").forEach(s => { const r = runner(s.classList.contains("big") ? "big" : ""); s.replaceWith(r); run(r, 2600); });
  document.querySelectorAll(".logo, .logo *").forEach(x => x.addEventListener("mouseenter", () => run($("#logo .runner"), 1400), { once: false }));
  $("#logo").addEventListener("click", ev => { ev.preventDefault(); newChat(); });
  $("#new-chat").addEventListener("click", newChat);
  $("#new-check-btn")?.addEventListener("click", newChat);
  $("#lang-en").addEventListener("click", () => applyLang("en"));
  $("#lang-sw").addEventListener("click", () => applyLang("sw"));
  document.querySelectorAll("[data-sug]").forEach(b => b.addEventListener("click", () => suggestion(b.dataset.sug)));

  $("#sidebar-toggle-btn")?.addEventListener("click", toggleSidebar);
  $("#mobile-menu-btn")?.addEventListener("click", toggleMobileSidebar);
  $("#sidebar-close-btn")?.addEventListener("click", closeMobileSidebar);
  $("#sidebar-backdrop")?.addEventListener("click", closeMobileSidebar);
  window.addEventListener("keydown", ev => {
    const sb = $("#sidebar");
    if (ev.key === "Escape") { closeMobileSidebar(); return; }
    if (ev.key !== "Tab" || !sb?.classList.contains("mobile-open")) return;
    const focusable = [...sb.querySelectorAll('a[href], button:not(:disabled), input:not(:disabled), [tabindex]:not([tabindex="-1"])')]
      .filter(el => el.getClientRects().length && getComputedStyle(el).visibility !== "hidden");
    if (!focusable.length) return;
    const first = focusable[0], last = focusable[focusable.length - 1];
    if (ev.shiftKey && (document.activeElement === first || !sb.contains(document.activeElement))) { ev.preventDefault(); last.focus(); }
    else if (!ev.shiftKey && (document.activeElement === last || !sb.contains(document.activeElement))) { ev.preventDefault(); first.focus(); }
  });

  $("#composer").addEventListener("submit", submit);
  box().addEventListener("input", () => { fit(); syncSend(); });
  box().addEventListener("keydown", ev => { if (ev.key === "Enter" && !ev.shiftKey && !ev.isComposing) { ev.preventDefault(); submit(); } });
  box().addEventListener("paste", ev => { const imgs = [...(ev.clipboardData ? ev.clipboardData.files : [])].filter(f => f.type.startsWith("image/")); if (imgs.length) { ev.preventDefault(); addFiles(imgs); } });
  initComposerActionsMenu();
  $("#file").addEventListener("change", async ev => {
    await addFiles([...ev.target.files]);
    ev.target.value = "";
    ev.target.accept = "image/png,image/jpeg,image/webp,.eml,.headers,.txt,message/rfc822,text/plain";
  });

  // Settings Dialog
  const settingsDlg = $("#settings-dialog");
  const openSettings = $("#open-settings-btn");
  if (openSettings && settingsDlg) openSettings.addEventListener("click", () => {
    closeMobileSidebar(false);
    settingsDlg.showModal();
  });
  $("#close-settings-btn")?.addEventListener("click", () => settingsDlg?.close());
  $("#done-settings-btn")?.addEventListener("click", () => settingsDlg?.close());

  $("#theme-light-btn")?.addEventListener("click", () => applyTheme("light"));
  $("#theme-dark-btn")?.addEventListener("click", () => applyTheme("dark"));
  $("#theme-system-btn")?.addEventListener("click", () => applyTheme("system"));
  $("#theme-toggle-btn")?.addEventListener("click", () => {
    const isDark = document.body.classList.contains("dark-theme");
    applyTheme(isDark ? "light" : "dark");
  });
  $("#set-lang-en")?.addEventListener("click", () => applyLang("en"));
  $("#set-lang-sw")?.addEventListener("click", () => applyLang("sw"));

  $("#clear-history-btn")?.addEventListener("click", () => {
    if (confirm(t("confirm_clear_history"))) {
      localStorage.removeItem(STORAGE_KEY);
      newChat();
      settingsDlg?.close();
    }
  });
  $("#export-history-btn")?.addEventListener("click", () => {
    const convs = loadStoredConversations();
    const blob = new Blob([JSON.stringify(convs, null, 2)], { type: "application/json" });
    const u = URL.createObjectURL(blob);
    const a = h("a", { href: u, download: "toroka_history.json" });
    document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(u), 1000);
  });


  // Safety Dialog
  const safetyDlg = $("#safety-dialog");
  const safetyButtons = [$("#learn-more-btn"), $("#open-safety-btn")].filter(Boolean);
  if (safetyDlg) safetyButtons.forEach(button => button.addEventListener("click", () => {
    closeMobileSidebar(false);
    safetyDlg.showModal();
  }));
  $("#close-safety-btn")?.addEventListener("click", () => safetyDlg?.close());
  $("#done-safety-btn")?.addEventListener("click", () => safetyDlg?.close());

  // Search in sidebar & nav items
  const topSearch = $("#top-search-input");
  const sideSearch = $("#sidebar-search-input");
  const sideSearchField = $("#sidebar-search-field");
  if (topSearch) topSearch.addEventListener("input", e => renderSidebarHistory(e.target.value));
  if (sideSearch) sideSearch.addEventListener("input", e => renderSidebarHistory(e.target.value));
  $("#nav-search-btn")?.addEventListener("click", () => {
    sidebarView = "recent";
    if (topSearch && getComputedStyle(topSearch.closest(".top-search-container")).display !== "none") {
      topSearch.value = "";
      renderSidebarHistory("");
      topSearch.focus();
    } else if (sideSearchField && sideSearch) {
      sideSearchField.hidden = false;
      sideSearch.value = "";
      renderSidebarHistory("");
      sideSearch.focus();
    }
  });
  $("#nav-saved-btn")?.addEventListener("click", () => {
    if (topSearch) topSearch.value = "";
    if (sideSearch) sideSearch.value = "";
    renderSidebarHistory("saved");
  });

  // Common scams topics in right panel
  document.querySelectorAll(".scam-topic-card").forEach(card => {
    card.addEventListener("click", () => {
      const topic = card.dataset.topic;
      if (topic === "shops") { suggestion("2"); }
      else if (topic === "mpesa") {
        userMsg(t("scam_mpesa_title"), [], "scam_mpesa_title");
        botSay(t("scam_mpesa_desc") + ". " + t("prompt_mpesa_check")).then(() => saveOrUpdateCurrentConversation(t("scam_mpesa_title"), t("prompt_mpesa_check")));
      } else if (topic === "impersonation") {
        userMsg(t("scam_impersonation_title"), [], "scam_impersonation_title");
        botSay(t("scam_impersonation_desc") + ". " + t("prompt_impersonation_check")).then(() => saveOrUpdateCurrentConversation(t("scam_impersonation_title"), t("prompt_impersonation_check")));
      } else if (topic === "jobs") {
        userMsg(t("scam_jobs_title"), [], "scam_jobs_title");
        botSay(t("scam_jobs_desc") + ". " + t("prompt_jobs_check")).then(() => saveOrUpdateCurrentConversation(t("scam_jobs_title"), t("prompt_jobs_check")));
      }
    });
  });

  let deferredPrompt = null;
  window.addEventListener("beforeinstallprompt", e => {
    e.preventDefault(); deferredPrompt = e;
    const ib = $("#install-btn");
    if (ib) {
      ib.hidden = false;
      ib.addEventListener("click", () => {
        ib.hidden = true;
        if (deferredPrompt) { deferredPrompt.prompt(); deferredPrompt = null; }
      });
    }
  });

  let depth = 0;
  addEventListener("dragenter", ev => { if (ev.dataTransfer && [...ev.dataTransfer.types].includes("Files")) { depth++; document.body.classList.add("drag"); } });
  addEventListener("dragleave", () => { depth = Math.max(0, depth - 1); if (!depth) document.body.classList.remove("drag"); });
  addEventListener("dragover", ev => ev.preventDefault());
  addEventListener("drop", ev => { ev.preventDefault(); depth = 0; document.body.classList.remove("drag"); addFiles([...(ev.dataTransfer ? ev.dataTransfer.files : [])]); });

  applyLang(navigator.language && navigator.language.toLowerCase().startsWith("sw") ? "sw" : "en");
  syncSend();
  renderSidebarHistory("");

  const q = new URLSearchParams(location.search), shared = [q.get("title"), q.get("text"), q.get("url")].filter(Boolean).join("\n");
  if (shared) { box().value = shared.slice(0, 5000); fit(); syncSend(); }
  const m = /^#r=([0-9a-f-]{36})\.([\w-]+)$/.exec(location.hash);
  if (m) { history.replaceState(null, "", location.pathname); openShared(m[1], m[2]); }
  if ("serviceWorker" in navigator && window.isSecureContext) navigator.serviceWorker.register("/sw.js").catch(() => {});
  const mainEl = $("#main");
  const wrapperEl = $("#main-wrapper");
  if (wrapperEl && mainEl) {
    wrapperEl.addEventListener("wheel", ev => {
      if (ev.target && ev.target.tagName === "TEXTAREA" && ev.target.scrollHeight > ev.target.clientHeight) {
        return;
      }
      if (!mainEl.contains(ev.target)) {
        mainEl.scrollTop += ev.deltaY;
      }
    }, { passive: true });
  }

  if (matchMedia("(min-width: 769px)").matches) box().focus();
}
document.readyState === "loading" ? document.addEventListener("DOMContentLoaded", boot) : boot();
