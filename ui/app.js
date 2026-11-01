"use strict";
/* ================================================================ پایه */
const $ = (s, r = document) => r.querySelector(s);
// خطاهای JavaScript در لاگ برنامه ثبت می‌شوند (عیب‌یابی روی ویندوز)
function reportJsError(msg) { try { if (window.pywebview && window.pywebview.api && window.pywebview.api.js_error) window.pywebview.api.js_error(String(msg).slice(0, 2000)); } catch (_) { /* نادیده */ } }
window.addEventListener("error", (e) => reportJsError(`${e.message} @ ${e.filename}:${e.lineno}:${e.colno}`));
window.addEventListener("unhandledrejection", (e) => reportJsError("promise: " + ((e.reason && (e.reason.stack || e.reason.message)) || e.reason)));
const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
/* «←» بین نام‌های لاتین (Splunk ← AbuseIPDB) در متن فارسی بدون RLM چپ‌به‌راست کنار هم می‌نشیند و ترتیب برعکس دیده می‌شود */
const ARW = "\u200f ← \u200f";
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const clone = (o) => JSON.parse(JSON.stringify(o));
const STEPS = ["splunk", "abuse", "fortigate", "redmine"];
const STEP_TITLE = { splunk: "Splunk", abuse: "AbuseIPDB", fortigate: "FortiGate", redmine: "Redmine", dns: "DNS", ssh: "SSH", scan: "اسکن شبکه", intel: "بررسی تکمیلی" };
const keyTitle = (k) => { const [t, n] = String(k).split("_"); return (STEP_TITLE[t] || t) + (n ? " " + n : ""); };
const CONN_TITLE = { splunk: "Splunk", abuseipdb: "AbuseIPDB", fortigate: "FortiGate", redmine: "Redmine" };
const STATE_TXT = { pending: "در صف", running: "در حال اجرا", done: "انجام شد", error: "خطا", awaiting: "منتظر تأیید", skipped: "اجرا نشد", cancelled: "متوقف شد", off: "انتخاب نشده" };

const ready = new Promise((res) => {
  if (window.pywebview && window.pywebview.api) res();
  else window.addEventListener("pywebviewready", () => res(), { once: true });
});
const WEB = !!window.__AKRP_WEB__;   // حالت سرور (مرورگر)
/** حالت وب: انتخاب فایل با آپلود به سرور؛ خروجی: مسیر فایل آپلودشده روی سرور */
function webPickFile(accept = ".csv,.txt,text/csv") {
  return new Promise((resolve) => {
    const inp = document.createElement("input");
    inp.type = "file"; inp.accept = accept; inp.style.display = "none";
    document.body.appendChild(inp);
    inp.onchange = async () => {
      const f = inp.files && inp.files[0]; inp.remove();
      if (!f) return resolve({ ok: true, path: "" });
      if (f.size > 64 * 1024 * 1024) return resolve({ ok: false, error: "فایل بزرگ‌تر از ۶۴ مگابایت است." });
      try {
        const r = await fetch("/upload", { method: "POST", credentials: "same-origin", body: f,
          headers: { "X-AKRP-CSRF": window.__AKRP_WEB__.csrf, "X-Filename": encodeURIComponent(f.name), "Content-Type": "application/octet-stream" } });
        if (r.status === 401) { location.href = "/login"; return resolve({ ok: false, error: "نشست منقضی شد" }); }
        const j = await r.json(); resolve(j.ok ? { ok: true, path: j.path, name: j.name } : j);
      } catch (e) { resolve({ ok: false, error: String(e && e.message || e) }); }
    };
    window.addEventListener("focus", () => setTimeout(() => { if (inp.isConnected && !inp.files.length) { inp.remove(); resolve({ ok: true, path: "" }); } }, 800), { once: true });
    inp.click();
  });
}
function webDownload(url, name) {
  const a = document.createElement("a"); a.href = url; a.download = name || ""; a.rel = "noopener";
  document.body.appendChild(a); a.click(); a.remove();
}
async function webLogout() {
  try { await fetch("/auth/logout", { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json", "X-AKRP-CSRF": window.__AKRP_WEB__.csrf }, body: "{}" }); } catch (e) { /* */ }
  location.href = "/login";
}
async function api(name, ...args) {
  await ready;
  try {
    if (WEB && name === "pick_csv") return await webPickFile();
    if (WEB && name === "pick_folder") return { ok: false, error: "در حالت سرور انتخاب پوشه‌ی سیستم سرور از مرورگر ممکن نیست." };
    const fn = window.pywebview.api[name];
    if (!fn) return { ok: false, error: `متد ${name} در دسترس نیست` };
    const t0 = performance.now();
    const res = (await fn(...args)) || { ok: false, error: "پاسخی دریافت نشد" };
    if (WEB && res && res.download) { webDownload(res.download, res.filename); res.path = res.path || `دانلود: ${res.filename || ""}`; }
    if (WEB && res && res.logout) { location.href = "/login"; }
    const ms = performance.now() - t0;
    if (ms > 800 && !WEB && !["ui_perf", "term_read", "xfer_put", "xfer_local", "term_open", "xfer_open"].includes(name) && window.pywebview.api.ui_perf) window.pywebview.api.ui_perf(name, Math.round(ms));   // درخواست کند → لاگ
    return res;
  } catch (e) { return { ok: false, error: String(e && e.message || e) }; }
}

const S = { settings: null, draft: null, paths: {}, tplVars: {}, state: null, seq: 0, events: [], page: "dashboard",
  run: null, runSig: "", approvalKey: "", resultTab: "summary", notifiedApproval: "",
  ips: [], ipSort: { k: "checked_at", d: -1 }, ipSel: new Set(), ipFilter: "all", hist: [], runs: [], histFilter: "all",
  setTab: "general", autoTab: "daily", feedFilter: "all" };

function toast(msg, level = "info") {
  const el = document.createElement("div");
  el.className = `toast ${level}`;
  el.textContent = msg;
  $("#toasts").appendChild(el);
  setTimeout(() => el.remove(), level === "error" ? 7000 : 4200);
}
async function withSpin(btn, fn) {
  if (btn) { btn.classList.add("loading"); btn.disabled = true; }
  try { return await fn(); } finally { if (btn) { btn.classList.remove("loading"); btn.disabled = false; } }
}
function fmtTime(ts) { if (!ts) return "—"; const d = new Date(ts * 1000); return d.toLocaleTimeString("en-GB"); }
function fmtDate(ts) {
  if (!ts) return "—"; const d = new Date(ts * 1000); const p = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}
const num = (v) => (v === null || v === undefined || v === "" ? "—" : Number(v).toLocaleString("en-US"));

/* ---------------------------------------------------------------- مرتب‌سازی عمومی جدول‌ها
 * کلیک روی سرستون هر جدول (table.grid) مرتب می‌کند؛ کلیک دوباره برعکس. جدول آدرس‌ها مرتب‌سازی خودش را دارد.
 * ترتیب انتخاب‌شده بعد از به‌روزرسانی خودکار همان جدول (مثلاً نتیجه‌ی اجرا) دوباره اعمال می‌شود. */
const TSORT = new Map();
function tsKey(t) {
  const h = t.tHead && t.tHead.rows[0];
  const host = t.id || (t.closest("[id]") || {}).id || "";
  return h ? host + "|" + [...h.cells].map((c) => c.textContent.replace(/[▲▼]/g, "").trim()).join("|") : "";
}
function tsVal(td) {
  if (!td) return { t: 2, v: "" };
  let s = (td.dataset.sv !== undefined ? td.dataset.sv : td.textContent).trim()
    .replace(/[۰-۹]/g, (d) => "۰۱۲۳۴۵۶۷۸۹".indexOf(d)).replace(/[٠-٩]/g, (d) => "٠١٢٣٤٥٦٧٨٩".indexOf(d));
  if (!s || s === "—" || s === "-") return { t: 2, v: "" };                       // خالی‌ها همیشه آخر
  const ip = s.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?::(\d+))?(?:\/(\d+))?$/);
  if (ip) return { t: 0, v: ip.slice(1, 5).reduce((a, x) => a * 256 + Number(x), 0) * 100000 + Number(ip[5] || ip[6] || 0) };
  const n = s.replace(/[,٬\s]/g, "").match(/^#?([-+]?\d*\.?\d+)(%|٪|ms|KB|MB|s)?$/i);
  if (n) return { t: 0, v: Number(n[1]) };
  return { t: 1, v: s.toLowerCase() };
}
function tsApply(t, col, dir) {
  const tb = t.tBodies[0]; if (!tb) return;
  const rows = [...tb.rows];
  if (rows.length < 2 || rows.some((r) => r.querySelector("td[colspan]") && r.cells.length === 1)) return;
  const keyed = rows.map((r, i) => ({ r, i, k: tsVal(r.cells[col]) }));
  keyed.sort((a, b) => {
    if (a.k.t === 2 || b.k.t === 2) return a.k.t === b.k.t ? a.i - b.i : a.k.t === 2 ? 1 : -1;
    if (a.k.t !== b.k.t) return (a.k.t - b.k.t) * dir;
    const c = a.k.t === 0 ? a.k.v - b.k.v : a.k.v.localeCompare(b.k.v, "fa", { numeric: true });
    return c ? c * dir : a.i - b.i;
  });
  if (!keyed.every((x, j) => x.i === j)) keyed.forEach((x) => tb.appendChild(x.r));   // اگر مرتب است دست نمی‌خورد (بدون حلقه)
  [...t.tHead.rows[0].cells].forEach((c, i) => {
    const a = c.querySelector(".arr.ts"), want = i === col ? (dir > 0 ? "▲" : "▼") : "";
    if (a && a.textContent === want) return;
    if (a) a.remove();
    if (want) { const x = document.createElement("span"); x.className = "arr ts"; x.textContent = want; c.appendChild(x); }
  });
}
document.addEventListener("click", (e) => {
  const th = e.target.closest("table.grid > thead th");
  if (!th || th.closest("#ipTable") || th.classList.contains("chk") || e.target.closest("input,button,select,a")) return;
  if (!th.textContent.replace(/[▲▼]/g, "").trim()) return;
  const t = th.closest("table"), key = tsKey(t), col = th.cellIndex;
  const cur = TSORT.get(key), dir = cur && cur.col === col ? -cur.dir : 1;
  TSORT.set(key, { col, dir }); tsApply(t, col, dir);
});
new MutationObserver((muts) => {
  if (!TSORT.size) return;
  const seen = new Set();
  for (const m of muts) for (const n of m.addedNodes) {
    if (n.nodeType !== 1) continue;
    if (["THEAD", "TBODY", "TR"].includes(n.tagName)) { const t = n.closest("table.grid"); if (t) seen.add(t); continue; }
    if (n.matches("table.grid")) seen.add(n);
    else if (n.querySelectorAll) n.querySelectorAll("table.grid").forEach((t) => seen.add(t));
  }
  for (const t of seen) { if (t.id === "ipTable") continue; const st = TSORT.get(tsKey(t)); if (st) tsApply(t, st.col, st.dir); }
}).observe(document.body, { childList: true, subtree: true });

/* ---------------------------------------------------------------- modal */
let modalClose = null;
function openModal({ title, body, foot = "", wide = false, onOpen }) {
  const back = $("#modalBack"), m = $("#modal");
  m.className = "modal" + (wide ? " wide" : "");
  m.innerHTML = `<div class="m-head"><h2>${esc(title)}</h2><button class="m-close" aria-label="بستن"><svg><use href="#i-x"/></svg></button></div>
    <div class="m-body">${body}</div>${foot ? `<div class="m-foot">${foot}</div>` : ""}`;
  back.hidden = false;
  back.classList.toggle("over-noc", !!document.getElementById("noc"));   // 1.37: پنجره روی NOC هم دیده شود (مثلاً «بستن برنامه»)
  clearTips();
  return new Promise((resolve) => {
    modalClose = (v) => { clearTips(); back.hidden = true; m.innerHTML = ""; m._dirty = false; modalClose = null; back.classList.remove("over-noc"); resolve(v); };
    m._dirty = false;     // 1.23: تغییر فرم با کاربر ← Esc اول می‌پرسد (keys.js)
    $(".m-close", m).onclick = () => modalClose(null);
    // 1.22: کلیک بیرون پنجره آن را نمی‌بندد (داده‌ی فرم با یک کلیک اشتباه پاک نشود)؛ فقط دکمه‌ی بستن یا دکمه‌های خود پنجره
    back.onclick = (e) => { if (e.target === back) { m.classList.remove("nudge"); void m.offsetWidth; m.classList.add("nudge"); } };
    if (onOpen) onOpen(m, modalClose);
    const f = $("[autofocus], .m-foot .btn.primary, .m-foot .btn.danger", m); if (f) f.focus();
  });
}
/* Esc و کلیدهای دیگر در keys.js (1.23) */

/** تأیید مرحله‌ی دوم. اگر ack داده شود، دکمه تا زدن تیک فعال نمی‌شود. */
function confirm2({ title, body, confirm, danger = false, ack = null }) {
  return openModal({
    title, body: body + (ack ? `<label class="chk" style="margin-top:14px"><input type="checkbox" id="ack">${esc(ack)}</label>` : ""),
    foot: `<button class="btn ghost" data-r="0">انصراف</button><button class="btn ${danger ? "danger" : "primary"}" data-r="1" ${ack ? "disabled" : ""}>${esc(confirm)}</button>`,
    onOpen: (m, close) => {
      $$("[data-r]", m).forEach((b) => (b.onclick = () => close(b.dataset.r === "1")));
      const a = $("#ack", m); if (a) a.onchange = () => ($("[data-r='1']", m).disabled = !a.checked);
    },
  }).then((v) => v === true);
}

/* ---------------------------------------------------------------- nav */
function clearTips() { document.querySelectorAll(".hover-tip").forEach((x) => x.remove()); }
// 1.37: راهنمای نمودار وقتی نمودار دوباره رسم یا پنجره بسته شد (mouseleave دیگر نمی‌آید) جا نماند
let _tipChk = 0;
document.addEventListener("mousemove", (e) => {
  const n = Date.now(); if (n - _tipChk < 120) return; _tipChk = n;
  if (document.querySelector(".hover-tip") && !(e.target && e.target.closest && e.target.closest(".hit"))) clearTips();
}, { passive: true });
["scroll", "wheel", "blur"].forEach((ev) => window.addEventListener(ev, clearTips, { passive: true, capture: ev === "scroll" }));
document.addEventListener("visibilitychange", clearTips);
function go(page) {
  S.page = page;
  clearTips();          // راهنمای نمودار وقتی صفحه عوض می‌شود (mouseleave دیگر نمی‌آید) وسط صفحه نماند
  $$("#nav button").forEach((b) => b.classList.toggle("active", b.dataset.page === page));
  $$(".page").forEach((p) => p.classList.toggle("active", p.id === `page-${page}`));
  // صفحه فوراً با آخرین داده نمایش داده می‌شود و در پس‌زمینه به‌روز می‌شود
  if (page === "dashboard" && S.state) renderDashboard(S.state);
  if (page === "ips") { if (S.ips.length) renderIps(); loadIps(); }
  if (page === "history") { if (S.hist.length) renderHist(); loadHist(); }
  if (page === "settings") renderSettings();
  if (page === "auto") renderAuto();
  if (page === "about") renderAbout();
  if (page === "ssh") { loadSsh(); pollSsh(true); }
  if (page === "monitor") { if (typeof MON !== "undefined" && MON.targets.length) renderMon(); loadMon(); }
  if (page === "assets") loadAssets();
  if (page === "stats" && ST.tab === "monitor") { stTabApply(); renderMonStats(); }
  else if (page === "stats" && ST.tab === "repeat") { stTabApply(); renderRepeat(); loadRepeat(); }
  else if (page === "stats") {
    const cal = S.settings && S.settings.ui && S.settings.ui.calendar;
    if (cal && cal !== ST.cal) { ST.cal = cal; $$("#stCal button").forEach((x) => x.classList.toggle("on", x.dataset.v === cal)); }
    if (ST.data) renderStats();
    loadStats();
  }
  if (page === "run") { runTabApply(); renderStageForm(); loadToolsData(); pollRun(true); }
  $(".main").scrollTop = 0;
}
$("#nav").addEventListener("click", (e) => { const b = e.target.closest("button[data-page]"); if (b) go(b.dataset.page); });
/* صفحه‌ی ابزارها: «اجرای ابزارها» یا «ابزارهای آفلاین» */
function runTabApply() {
  if (S.runTab === "offline" && !shown("offline")) S.runTab = "run";
  const off = S.runTab === "offline";
  $$("#runTabs button").forEach((b) => b.classList.toggle("on", b.dataset.t === (S.runTab || "run")));
  $("#runPane").hidden = off; $("#offPane").hidden = !off; $("#runActs").hidden = off;
  if (off && typeof offRender === "function" && !$("#offSeg")) offRender();
}
$("#runTabs").addEventListener("click", (e) => { const b = e.target.closest("button[data-t]"); if (!b) return; S.runTab = b.dataset.t; runTabApply(); });
document.addEventListener("click", (e) => { const g = e.target.closest("[data-goto]"); if (g) go(g.dataset.goto); });

/* ================================================================ settings / draft */
async function loadSettings() {
  const r = await api("get_settings");
  if (!r.ok) { toast(r.error, "error"); return; }
  S.settings = r.settings; S.paths = r.paths; S.tplVars = r.template_vars;
  S.draft = clone(r.settings);
  applyLang((r.settings.ui && r.settings.ui.lang) || I18N.lang || "en", false);
  applyBranding(r.settings);
}
/* ---------------------------------------------------------------- language */
function applyLang(l, rerender = true) {
  l = l === "en" ? "en" : "fa";
  const changed = I18N.lang !== l;
  I18N.apply(l);
  try { localStorage.setItem("akrp_lang", l); } catch (e) { /* صفحه‌ی ورود وب همین زبان را نشان می‌دهد */ }
  $("#langLabel").textContent = l === "en" ? "فارسی" : "English";
  if (!(S.settings && S.settings.ui && S.settings.ui.calendar)) {
    ST.cal = l === "en" ? "gregorian" : "jalali";
    $$("#stCal button").forEach((x) => x.classList.toggle("on", x.dataset.v === ST.cal));
  }
  if (changed && rerender) {
    LS.sig = "";   // صفحه‌ی قفل دوباره ساخته شود
    if (S.state) { renderSide(S.state); renderDashboard(S.state); renderLock(S.state.security); }
    renderFeed();
    if (S.page === "stats" && ST.data) loadStats();
  }
}
async function toggleLang() {
  const l = I18N.lang === "en" ? "fa" : "en";
  applyLang(l);
  if (S.settings) { S.settings.ui = S.settings.ui || {}; S.settings.ui.lang = l; }
  if (S.draft) { S.draft.ui = S.draft.ui || {}; S.draft.ui.lang = l; }
  await api("save_ui", "lang", l);
}
document.addEventListener("click", (e) => { if (e.target.closest("#btnLang, .lang-toggle")) toggleLang(); });
function applyBranding(s) {
  const b = s.branding || {};
  $("#brandName").textContent = b.app_name || "AutoKRP";
  $("#brandSub").textContent = b.subtitle || "";
  document.title = I18N.t(b.app_name || "AutoKRP");
  document.documentElement.dataset.theme = s.theme === "light" ? "light" : "dark";
  applyLogo(b);
}
function logoHtml(b) {
  return b && b.logo_data ? `<img src="${b.logo_data}" alt="">` : esc(((b && (b.logo_text || (b.app_name || "A").slice(0, 1))) || "A").slice(0, 2));
}
function applyLogo(b) {
  if (!b || b.logo_data === undefined) return;
  const el = $("#brandLogo"), key = (b.logo_data || "").length + (b.logo_text || "");
  if (el.dataset.k === key) return;
  el.dataset.k = key; el.innerHTML = logoHtml(b); el.classList.toggle("has-img", !!b.logo_data);
}
function getPath(o, p) { return p.split(".").reduce((a, k) => (a == null ? undefined : a[k]), o); }
function setPath(o, p, v) { const ks = p.split("."); let c = o; ks.slice(0, -1).forEach((k) => { if (typeof c[k] !== "object" || c[k] === null) c[k] = {}; c = c[k]; }); c[ks[ks.length - 1]] = v; }
function readInput(el) {
  const t = el.dataset.type;
  if (t === "bool") return el.checked;
  if (t === "num") return el.value === "" ? "" : Number(el.value);
  if (t === "lines") return el.value.split(/\r?\n/).map((x) => x.trim()).filter(Boolean);
  return el.value;
}
function bindInputs(root) {
  $$("[data-path]", root).forEach((el) => {
    const h = () => { setPath(S.draft, el.dataset.path, readInput(el)); if (el.dataset.rerender) el.dataset.rerender === "settings" ? renderSettings() : renderAuto(); };
    el.addEventListener(el.type === "checkbox" || el.tagName === "SELECT" ? "change" : "input", h);
  });
}
function draftPatch() {
  const p = clone(S.draft);
  for (const c of [...Object.keys(CONN_TITLE), ...Object.keys(p).filter((x) => /^fortigate\d+$/.test(x))]) {
    if (!p[c]) continue;
    Object.keys(p[c]).filter((k) => k.startsWith("has_")).forEach((k) => delete p[c][k]);
    for (const sk of ["token", "password", "extra_tokens"]) if (p[c][sk] === "" || p[c][sk] === undefined) delete p[c][sk];
    delete p[c].extra_tokens_count;
  }
  delete p.has_password; delete p.security;
  if (p.branding) { delete p.branding.logo_file; delete p.branding.icon_file; delete p.branding.logo_data; }
  return p;
}
/* لغو تغییرهای ذخیره‌نشده‌ی تنظیمات و کارهای خودکار: پیش‌نویس به آخرین تنظیمات ذخیره‌شده برمی‌گردد */
function draftDirty() {
  if (!S.draft || !S.settings) return false;
  const a = draftPatch(), saved = S.draft; S.draft = clone(S.settings);
  const b = draftPatch(); S.draft = saved;
  return JSON.stringify(a) !== JSON.stringify(b);
}
function undoDraft() {
  if (!draftDirty()) return toast("تغییر ذخیره‌نشده‌ای نیست.", "info");
  S.draft = clone(S.settings);
  if (S.page === "settings") renderSettings();
  if (S.page === "auto") renderAuto();
  toast("تغییرهای ذخیره‌نشده لغو شد", "warn");
}
$$("[data-undo]").forEach((b) => b.addEventListener("click", undoDraft));
/* 1.39: درخت بخش‌ها و ابزارهای فعال (کلیدها همان perms.SECTIONS؛ زیرمجموعه در تنظیمات با «:») */
const TE_TREE = [
  ["sec", "امنیت (ابزارها، آدرس‌ها، کارهای خودکار)", [["splunk", "Splunk"], ["abuse", "AbuseIPDB"], ["fortigate", "FortiGate (بلاک)"], ["redmine", "Redmine (تیکت)"], ["dns", "DNS"], ["scan", "اسکن شبکه"], ["intel", "بررسی تکمیلی"]],
    "کارهای زمان‌بندی‌شده‌ی همین ابزارها اجرا نمی‌شوند"],
  ["dev", "ارتباط با دستگاه‌ها", [["ssh", "دستگاه‌ها و اجرای دستور (SSH/Telnet)"], ["ssh.backup", "پشتیبان کانفیگ", 1], ["term", "ترمینال"], ["term.xfer", "انتقال فایل (SFTP/FTP)", 1],
    ["term.tftp", "سرور TFTP", 1], ["term.serial", "کنسول سریال (فقط دسکتاپ)", 1], ["nettools", "ابزارهای شبکه"], ["apitool", "ابزار API"]],
    "نشست‌های ترمینال و انتقال فایل بسته، سرور TFTP قطع و پشتیبان‌گیری زمان‌بندی‌شده انجام نمی‌شود"],
  ["monitor", "مانیتورینگ", [["monitor.events", "دریافت Trap و Syslog", 1], ["monitor.maps", "نقشه‌ها", 1], ["monitor.topo", "نقشه‌ی خودکار (LLDP)", 1], ["monitor.noc", "نمای NOC و داشبوردها", 1],
    ["monitor.live", "بررسی زنده‌ی موقت", 1]], "همه‌ی بررسی‌ها، کارگرهای SNMP و شنونده‌های Trap/Syslog متوقف می‌شوند"],
  ["asset", "دارایی‌ها", [["asset.scan", "اسکن دارایی", 1]], "اسکن دارایی (دستی و زمان‌بندی‌شده) انجام نمی‌شود"],
  ["offline", "ابزارهای آفلاین", [], ""],
];
const teKey = (k) => k.replace(".", ":");
function teOn(D, k) { return ((D.tools_enabled || {})[teKey(k)] ?? true) !== false; }
function teTreeHtml(D) {
  return `<div class="te-tree">${TE_TREE.map(([k, t, kids, stop]) => `<div class="te-sec" data-tes="${k}"><div class="te-head">${sw("tools_enabled." + teKey(k), teOn(D, k), `<b>${esc(I18N.t(t))}</b>`)}
      <span class="tag ${teOn(D, k) ? "ok" : "err"}">${teOn(D, k) ? "فعال" : "متوقف"}</span></div>
    ${kids.length ? `<div class="te-kids">${kids.map(([c, ct, sub]) => `<label class="chk ${sub ? "te-sub" : ""}"><input type="checkbox" data-type="bool" data-path="tools_enabled.${teKey(c)}" ${teOn(D, c) ? "checked" : ""}>${esc(I18N.t(ct))}</label>`).join("")}</div>` : ""}
    ${stop ? `<div class="hint te-stop"><span>خاموش کردن:</span> ${esc(I18N.t(stop))}</div>` : ""}</div>`).join("")}</div>`;
}
/** کلیدهایی که با این ذخیره خاموش می‌شوند (روشن در تنظیمات فعلی، خاموش در پیش‌نویس) */
function teTurningOff() {
  const out = [];
  for (const [k, t, kids] of TE_TREE) {
    const was = teOn(S.settings, k), now = teOn(S.draft, k);
    if (was && !now) { out.push(I18N.t(t)); continue; }
    if (now) for (const [c, ct] of kids) if (teOn(S.settings, c) && !teOn(S.draft, c) && teOn(S.settings, k)) out.push(I18N.t(ct));
  }
  return out;
}
async function saveDraft(btn) {
  const off = S.draft && S.settings ? teTurningOff() : [];
  if (off.length && !(await confirm2({ title: "خاموش کردن بخش‌ها", confirm: "خاموش و ذخیره", danger: true,
    body: `<p>${esc("این بخش‌ها برای همه‌ی کاربران خاموش و کارهای در حال اجرایشان متوقف می‌شوند (داده و تنظیماتشان پاک نمی‌شود):")}</p><ul>${off.map((x) => `<li>${esc(x)}</li>`).join("")}</ul>` }))) return;
  if (S.draft && S.settings && S.draft.splunk && (S.draft.splunk.query || "") !== (S.settings.splunk.query || "")) {
    const ok = await confirm2({ title: "کوئری Splunk تغییر کرده است", confirm: "ذخیره بدون تأیید نگاشت",
      body: "<p>کوئری عوض شده ولی نگاشت ستون‌ها برایش تأیید نشده است. بهتر است در تب Splunk «اجرا و پیش‌نمایش» را بزنید و «تأیید نگاشت و ذخیره‌ی کوئری» را انتخاب کنید. اگر ستون IP مبدأ در خروجی نباشد، اجرا با خطا متوقف می‌شود.</p>" });
    if (!ok) return;
  }
  await withSpin(btn, async () => {
    const r = await api("save_settings", draftPatch());
    if (!r.ok) { toast(r.error, "error"); return; }
    S.settings = r.settings; S.draft = clone(r.settings);
    applyBranding(r.settings);
    toast("تنظیمات ذخیره شد", "ok");
    if (S.page === "settings") renderSettings();
    if (S.page === "auto") renderAuto();
    refreshState();
  });
}

/* ================================================================ state polling */
let stateBusy = false, sideSig = "", logoSig = "";
async function refreshState() {
  if (stateBusy) return;   // درخواست قبلی هنوز برنگشته؛ صف درخواست‌ها در پل ویندوز پر نشود
  stateBusy = true;
  let r;
  try { r = await api("get_state", S.seq); } finally { stateBusy = false; }
  if (!r.ok) return;
  S.state = r;
  if (r.events.length) {
    S.seq = r.events[r.events.length - 1].seq;
    S.events.push(...r.events);
    if (S.events.length > 600) S.events.splice(0, S.events.length - 600);
    renderFeed();
  }
  // فقط چیزی که تغییر کرده دوباره ساخته می‌شود؛ داشبورد فقط وقتی همان صفحه باز است
  const sg = JSON.stringify([r.conn, r.test_mode, r.master, r.counts, hiddenTools(), r.tools_enabled, r.db && [r.db.backend, r.db.ok], r.assets_pending]);
  if (sg !== sideSig) { sideSig = sg; renderSide(r); }
  if (S.page === "dashboard") renderDashboard(r);
  const lg = JSON.stringify(r.branding);
  if (lg !== logoSig) { logoSig = lg; applyLogo(r.branding); }
  renderLock(r.security);
  applyRole(r);
  if (typeof dbMaybePrompt === "function") dbMaybePrompt(r);
  const run = r.run;
  const active = run && (run.status === "running" || run.status === "awaiting");
  $("#navRunDot").hidden = !(run && run.approval);
  if (run && run.approval && S.notifiedApproval !== run.id + run.status + JSON.stringify(run.stages)) {
    const key = run.id + ":" + Object.keys(run.stages).find((s) => run.stages[s].state === "awaiting");
    if (S.notifiedApproval !== key) { S.notifiedApproval = key; if (S.page !== "run") toast("یک اجرا منتظر تأیید شماست — صفحه‌ی «ابزارها»", "warn"); }
  }
  if (S.page === "run" && (active || S.runWasActive)) pollRun();
  S.runWasActive = active;
}
// هر ثانیه وقتی اجرایی فعال است؛ در حالت بیکار هر ۲.۵ ثانیه؛ وقتی پنجره کوچک/پنهان است، نه
(function stateLoop() {
  const run = S.state && S.state.run, active = run && (run.status === "running" || run.status === "awaiting");
  if (!document.hidden) refreshState();
  setTimeout(stateLoop, active ? 1000 : 2500);
})();

function connTitle(k) { return CONN_TITLE[k] && !(k === "fortigate" && fgDevices().length > 1) ? CONN_TITLE[k] : /^fortigate/.test(k) ? fgDevName(k) : k; }
function connChip(name, st) {
  return `<span class="chip" title="${esc(st.message)}"><span class="dot ${esc(st.state)}"></span><span>${esc(connTitle(name))}</span></span>`;
}
/* نمایش ابزارها: ابزار/بخش خاموش (تنظیمات ← عمومی، برای همه) یا پنهان در «ابزارهای من» (فقط همین کاربر) */
const CONN_TOOL = { splunk: "splunk", abuseipdb: "abuse", fortigate: "fortigate", redmine: "redmine" };
const FEATS = [["monitor", "مانیتورینگ"], ["term", "ترمینال و انتقال فایل"], ["offline", "ابزارهای آفلاین"], ["nettools", "ابزارهای شبکه"]];
function hiddenTools() { return (S.settings && S.settings.ui && S.settings.ui.hidden_tools) || []; }
function shown(t) {
  if (hiddenTools().includes(t)) return false;
  const st = S.state || {};
  if (st.access && t in st.access) return st.access[t] !== "none";      // 1.32: سطح دسترسی همین کاربر
  if (FEATS.some(([k]) => k === t)) return !st.features || st.features.includes(t);
  return !st.tools_enabled || st.tools_enabled.includes(t);
}
function showTool(t) { return canTool(t) && shown(t); }
function connShown(k) { k = /^fortigate\d+$/.test(k) ? "fortigate" : k; return !CONN_TOOL[k] || shown(CONN_TOOL[k]); }
function renderSide(r) {
  $("#sideConn").innerHTML = Object.entries(r.conn).filter(([k]) => connShown(k)).map(([k, v]) =>
    `<div class="conn-row" title="${esc(v.message)}"><span class="dot ${esc(v.state)}"></span><span>${esc(connTitle(k))}</span><span style="margin-inline-start:auto;font-size:11.5px">${
      { ok: "متصل", error: "خطا", unset: "تنظیم نشده", idle: "—", unknown: "…" }[v.state] || ""}</span></div>`).join("");
  if (r.db && r.db.backend === "mysql") $("#sideConn").insertAdjacentHTML("beforeend", `<div class="conn-row" title="${esc(r.db.error || "")}"><span class="dot ${r.db.ok === false ? "error" : "ok"}"></span>MySQL<span style="margin-inline-start:auto;font-size:11.5px">${r.db.ok === false ? "خطا" : "متصل"}</span></div>`);
  $("#testBadge").hidden = !r.test_mode;
  $("#sideVer").textContent = `نسخه ${r.version}${r.demo ? " — Demo" : ""}`;
  $("#btnLock").hidden = !(r.security && r.security.unlocked && (r.security.mode === "password" || WEB));
  if (WEB) $("#btnLock").lastChild.textContent = "خروج";
  const n = r.counts.fw_pending;            // آدرس‌ها: تعداد جامانده از بلاک
  $("#navReview").hidden = !n; $("#navReview").textContent = n; $("#navReview").title = I18N.t("جامانده از بلاک");
  const sa = r.sec_alerts || 0;              // 1.33: نسخه‌ی تازه یا آسیب‌پذیری کتابخانه‌ها (ادمین)
  $("#navAbout").hidden = !sa; $("#navAbout").textContent = sa; $("#navAbout").title = I18N.t("به‌روزرسانی و امنیت");
  const ap = r.assets_pending || 0;          // دارایی‌ها: تغییرهای در انتظار تأیید
  $("#navAssets").hidden = !ap; $("#navAssets").textContent = ap; $("#navAssets").title = I18N.t("در انتظار تأیید");
  if (S.page === "assets" && typeof AS !== "undefined" && AS.pendN !== ap) { AS.pendN = ap; asPendBadge(); }
}

/* ---------------------------------------------------------------- نقش کاربر */
const ROLE_FA = { admin: "ادمین", operator: "اپراتور", readonly: "فقط‌خواندنی" };
let roleSig = "";
const SEC_TOOLS = ["splunk", "abuse", "fortigate", "redmine", "dns", "scan", "intel"];
function canTool(t) { return !S.state || !S.state.tools || S.state.tools.includes(t); }
function isAdmin() { return !S.state || !S.state.me || S.state.me.role === "admin"; }
function isRO() { return !!(S.state && S.state.me && S.state.me.role === "readonly"); }
/** 1.39: سطح دسترسی این کاربر به یک بخش یا زیرمجموعه (monitor.maps، term.tftp، …) */
function axOk(k, lvl = "view") {
  const v = ((S.state && S.state.access) || {})[k];
  if (v === undefined) return true;          // پیش از رسیدن وضعیت از سرور (سرور خودش بررسی می‌کند)
  return lvl === "run" ? v === "run" : v !== "none";
}
function applyRole(r) {
  const hid = hiddenTools();
  const me = r.me, sig = JSON.stringify([me, r.tools, r.tools_enabled, r.features, hid, r.hidden_modes, r.access]);
  if (sig === roleSig) return;
  roleSig = sig;
  const role = me ? me.role : "admin";
  document.body.classList.toggle("nadm", role !== "admin");
  document.body.classList.toggle("ro", role === "readonly");
  // اپراتور: «ترمینال و انتقال فایل» فقط با دسترسی term خودش (1.22)؛ بقیه‌ی بخش‌ها با روشن بودن کلی
  // 1.32: سطح هر ابزار از سرور (r.access: none | view | run)؛ «پنهان» = دیده نمی‌شود، «دیدن» = بدون دکمه‌های اجرا
  const AX = r.access || {};
  const tl = Object.keys(AX).filter((k) => AX[k] !== "none" && !hid.includes(k));
  $$("[data-need-tool]").forEach((el) => el.classList.toggle("tool-off", !tl.includes(el.dataset.needTool)));
  Object.keys(AX).forEach((k) => {
    document.body.classList.toggle("nrun-" + k.replace(".", "-"), AX[k] !== "run");
    document.body.classList.toggle("nsee-" + k.replace(".", "-"), AX[k] === "none" || hid.includes(k));
  });
  // 1.31: بخش مخصوص حالت دیگر (مثلاً کابل کنسول فقط در کلاینت) اصلاً دیده نمی‌شود
  $$("[data-mode]").forEach((el) => el.classList.toggle("mode-off", (r.hidden_modes || []).includes(el.dataset.mode)));
  $("#navSsh").hidden = !["ssh", "term", "nettools", "apitool"].some((k) => tl.includes(k));      // صفحه‌ی «ارتباط با دستگاه‌ها»
  const xfTab = $(`#sshTabs button[data-t="xfer"]`);       // 1.39: «انتقال فایل» = SFTP/FTP یا سرور TFTP
  if (xfTab && !xfTab.classList.contains("tool-off") && !tl.includes("term.xfer") && !tl.includes("term.tftp")) xfTab.classList.add("tool-off");
  if (typeof MON !== "undefined" && ["events", "maps", "topo"].includes(MON.tab) && !tl.includes("monitor." + MON.tab)) MON.tab = "targets";
  // 1.37: «فقط مانیتورینگ» — وقتی هیچ ابزار امنیتی (Splunk، AbuseIPDB، FortiGate، …) برای این کاربر نیست، صفحه‌های همان ابزارها
  // (داشبورد امنیتی، ابزارها، کارهای خودکار، آدرس‌ها) و اتصال‌های کنار منو پنهان و صفحه‌ی اول «مانیتورینگ» است
  const monOnly = tl.includes("monitor") && !SEC_TOOLS.some((k) => tl.includes(k));
  document.body.classList.toggle("mon-only", monOnly);
  if (monOnly && ["dashboard", "run", "auto", "ips"].includes(S.page)) go("monitor");
  // تب یا صفحه‌ای که الان پنهان شد
  const off = (sel) => { const b = $(sel); return !!b && b.classList.contains("tool-off"); };
  if (off(`#setTabs button[data-t="${S.setTab}"]`)) { S.setTab = "general"; if (S.page === "settings") renderSettings(); }
  if (off(`#autoTabs button[data-t="${S.autoTab}"]`)) { S.autoTab = "daily"; if (S.page === "auto") renderAuto(); }
  if (typeof SSH !== "undefined" && off(`#sshTabs button[data-t="${SSH.tab}"]`)) {
    const first = $$("#sshTabs button").find((b) => !b.classList.contains("tool-off") && getComputedStyle(b).display !== "none");
    SSH.tab = first ? first.dataset.t : "devices"; if (S.page === "ssh") loadSsh();
  }
  if (ST.tab === "monitor" && off(`#stTab button[data-v="monitor"]`)) { ST.tab = "general"; if (S.page === "stats") { stTabApply(); loadStats(); } }
  if (S.page === "monitor" && off(`#nav button[data-page="monitor"]`)) go("dashboard");
  if (S.page === "assets" && off(`#nav button[data-page="assets"]`)) go("dashboard");
  if (S.page === "run" && S.runTab === "offline" && off(`#runTabs button[data-t="offline"]`)) { S.runTab = "run"; runTabApply(); }
  const chip = $("#userChip");
  chip.hidden = !(me && !me.single);
  if (me && !me.single) chip.innerHTML = `<svg style="width:14px;height:14px"><use href="#i-lock"/></svg><b class="ltr">${esc(me.username)}</b> — ${ROLE_FA[me.role] || me.role}`;
  if (!me) return;
  const forbidden = (role !== "admin" && S.page === "settings") || ($("#navSsh").hidden && S.page === "ssh");
  if (forbidden) go("dashboard");
  if (S.page === "run") renderStageForm();
  if (S.page === "auto") renderAuto();
}
async function myTools() {
  const st = S.state || {}, role = st.me ? st.me.role : "admin";
  const AX = st.access || {};
  const avail = UTOOLS.concat(FEATS).filter(([k]) => (AX[k] || "none") !== "none").map(([k, t]) => [k, STEP_TITLE[k] || t]);
  const hid = new Set(hiddenTools());
  const res = await openModal({ title: "ابزارهای من",
    body: `<p class="hint">ابزارهایی را که لازم ندارید پنهان کنید؛ فقط برای ${st.me && !st.me.single ? "حساب شما" : "همین برنامه"} اعمال می‌شود (منو، صفحه‌ی ابزارها، تب‌های تنظیمات و اتصال‌ها) و دسترسی‌ها یا کارهای خودکار را عوض نمی‌کند.</p>
      <div class="chks">${avail.map(([k, t]) => `<label class="chk"><input type="checkbox" class="mtT" value="${k}" ${hid.has(k) ? "" : "checked"}>${esc(t)}</label>`).join("")}</div>
      ${role === "admin" ? `<p class="hint">خاموش کردن یک ابزار برای همه: تنظیمات ← عمومی ← ابزارهای فعال برنامه.</p>` : ""}`,
    foot: `<button class="btn ghost" data-r="0">انصراف</button><button class="btn primary" data-r="1">ذخیره</button>`,
    onOpen: (m, close) => $$("[data-r]", m).forEach((b) => (b.onclick = () => close(b.dataset.r === "1" ? $$(".mtT", m).filter((c) => !c.checked).map((c) => c.value) : null))) });
  if (!res) return;
  const keep = hiddenTools().filter((k) => !avail.some(([a]) => a === k));   // پنهان‌های ابزارهایی که الان در دسترس نیستند حفظ شوند
  const val = [...new Set(res.concat(keep))];
  const r = await api("save_ui", "hidden_tools", val);
  if (!r.ok) return toast(r.error, "error");
  S.settings.ui = { ...(S.settings.ui || {}), hidden_tools: val };
  roleSig = ""; sideSig = ""; if (S.state) { applyRole(S.state); renderSide(S.state); }
  if (S.page === "run") renderStageForm();
  if (S.page === "dashboard" && S.state) renderDashboard(S.state);
  toast("ذخیره شد", "ok");
}
$("#btnMyTools").addEventListener("click", myTools);
let _touchAt = 0;
["mousedown", "keydown", "wheel", "touchstart"].forEach((ev) => document.addEventListener(ev, () => {
  const n = Date.now(); if (n - _touchAt > 30000) { _touchAt = n; api("ui_touch"); }
}, { passive: true }));

/* ================================================================ dashboard */
function renderDashboard(r) {
  const sw = $("#masterSwitch");
  if (document.activeElement !== sw) sw.checked = !!r.master;
  $("#masterLabel").textContent = r.master ? "کار خودکار روشن است" : "کار خودکار خاموش است";
  $("#masterSub").textContent = r.master ? (r.jobs_on ? `${num(r.jobs_on)} کار زمان‌بندی‌شده فعال است` : "هیچ کار زمان‌بندی‌شده‌ای فعال نیست") : "اجرای زمان‌بندی‌شده انجام نمی‌شود";
  $("#dashConn").innerHTML = Object.entries(r.conn).filter(([k]) => connShown(k)).map(([k, v]) => connChip(k, v)).join("");
  $("#lastCheck").textContent = r.last_check ? fmtTime(r.last_check) : "—";
  const src = r.run || r.last_run;
  if (src) {
    const stages = r.run ? r.run.stages : Object.fromEntries(Object.keys(src.steps || {}).map((s) => [s, { state: src.steps[s] || "off", message: "" }]));
    renderRail($("#dashRail"), stages, src.summary || {}, r.run && r.run.order);
    $("#railMeta").textContent = `${fmtDate(src.started)} — ${{ manual: "دستی", schedule: "زمان‌بندی", retry: "چک مجدد", sync: "بررسی کامل FortiGate" }[src.trigger] || src.trigger} — ${STATE_TXT[src.status] || { done: "کامل", failed: "ناموفق" }[src.status] || src.status}`;
  } else {
    $("#dashRail").innerHTML = `<div class="empty" style="grid-column:1/-1">هنوز اجرایی انجام نشده است. از «ابزارها» شروع کنید.</div>`;
    $("#railMeta").textContent = "";
  }
  const c = r.counts;
  $("#todayCounts").innerHTML = [
    ["acc", c.abuse_today, "IP مخرب امروز"], ["ok", c.ban, "بلاک‌شده امروز"], ["err", c.ban_error, "بلاک ناموفق امروز"],
    ["", c.ticket, "تیکت امروز"], ["err", c.fw_pending, "جامانده از بلاک (کل دیتابیس)"], ["warn", c.unchecked, "بررسی‌نشده در AbuseIPDB"],
  ].map(([cls, v, t]) => `<div class="count ${cls}"><b>${num(v)}</b><span>${t}</span></div>`).join("");
  healthLoad();
}
/* 1.24: سلامت سرور (فقط ادمین) — حداکثر هر ۶۰ ثانیه */
let HL = { at: 0, busy: false };
async function healthLoad(force) {
  const box = $("#healthBox"); if (!box || !isAdmin() || HL.busy || (!force && Date.now() - HL.at < 60000)) return;
  HL.busy = true;
  try {
    const r = await api("srv_health"); HL.at = Date.now();
    if (!r.ok) { box.hidden = true; return; }
    const B = (n) => (n == null ? "—" : fmtBytes(n)), dk = r.disk || {}, z = r.sizes || {};
    const bar = (pct, bad) => `<span class="sn-bar ${bad ? "bad" : ""}"><i style="width:${Math.min(100, Math.max(0, pct || 0))}%"></i></span>`;
    const usedPct = dk.total ? 100 - (dk.pct_free || 0) : 0, lowDisk = r.problems.some((p) => p.key === "disk");
    box.hidden = false;
    box.innerHTML = `<div class="panel-head"><h2>سلامت سرور</h2><span class="muted">${r.problems.length ? `<span class="tag err">${num(r.problems.length)} مشکل</span>` : `<span class="tag ok">سالم</span>`} · فعال از ${monDur(r.uptime)} پیش</span></div>
      ${r.problems.length ? `<div class="hl-probs">${r.problems.map((p) => `<div>⚠ ${esc(p.msg)}</div>`).join("")}</div>` : ""}
      <div class="hl-grid">
        <div><small>فضای دیسک داده‌ها</small><b>${B(dk.free)} آزاد</b>${bar(usedPct, lowDisk)}<span class="muted">از ${B(dk.total)} (${num(dk.pct_free)}٪ آزاد)${r.days_left != null ? ` · حدود ${num(r.days_left)} روز تا پر شدن` : ""}</span></div>
        <div><small>RAM برنامه</small><b>${B(r.rss)}</b><span class="muted">حد هشدار ${num(r.cfg.ram_max_mb)} مگ</span></div>
        <div><small>CPU برنامه (۵ دقیقه)</small><b>${r.cpu_core == null ? "—" : num(r.cpu_core) + "٪ یک هسته"}</b><span class="muted">${r.cpu == null ? "" : num(r.cpu) + "٪ کل · "}${num(r.cores)} هسته · ${num(r.threads)} ترد</span></div>
        <div><small>حجم داده‌ها</small><b>${B(z.total)}</b><span class="muted">مانیتورینگ ${B(z.monitor)} · پایگاه داده ${B(z.db)} · اجراها ${B(z.runs)} · بکاپ ${B(z.backups)}${z.growth_day ? ` · رشد ${B(z.growth_day)}/روز` : ""}</span></div>
      </div>`;
  } finally { HL.busy = false; }
}
function renderRail(el, stages, sm, order) {
  const keys = (order && order.length ? order : Object.keys(stages)).filter((k) => stages[k] && stages[k].state !== "off");
  const big = {
    splunk: (m) => m ? `${num(m.src)}<small>آی‌پی مبدأ</small>` : "",
    abuse: (m) => m ? `${num(m.abuse)}<small>مخرب</small>` : "",
    fortigate: (m) => m ? `${num((m.banned || 0) + (m.converted || 0) + (m.test || 0) + (m.done || 0))}<small>${m.task ? (m.test ? "کار (تست)" : "کار") : m.test ? "بلاک (تست)" : "بلاک"}</small>` : "",
    redmine: (m) => m ? (m.issue ? `#${esc(m.issue)}` : `<small>تست</small>`) : "",
    dns: (m) => m ? `${num(m.found)}<small>از ${num(m.total)}</small>` : "",
    ssh: (m) => m ? `${num(m.ok)}<small>از ${num(m.devices)} دستگاه</small>` : "",
    scan: (m) => m ? (m.mode === "ports" ? `${num(m.open)}<small>پورت باز</small>` : `${num(m.hosts)}<small>هاست روشن</small>`) : "",
    intel: (m) => m ? `${num(m.malicious)}<small>مخرب</small>` : "",
  };
  const sub = {
    splunk: (m) => m ? `${num(m.rows)} ردیف` : "",
    abuse: (m) => m ? `${num(m.clean)} غیرمخرب، ${num(m.error)} خطا` : "",
    fortigate: (m) => m ? (m.actions !== undefined ? `${num(m.actions)} کار از ${num(m.rows)} ردیف` : `از قبل ${num(m.already)}، Address ${num(m.address)}، داخلی ${num(m.ignored)}`) : "",
    redmine: () => "",
    dns: (m) => m ? (m.mode === "url" ? "میزبان resolve شد" : "IP با PTR") : "",
    scan: (m) => m ? `${num(m.targets)} آدرس${m.new ? `، ${num(m.new)} تازه` : ""}` : "",
    intel: (m) => m ? `${num(m.clean)} پاک از ${num(m.total)}` : "",
  };
  el.innerHTML = keys.length ? keys.map((k, i) => {
    const st = stages[k], tool = st.tool || k.split("_")[0], m = st.summary || (keys.filter((x) => x.split("_")[0] === tool).length === 1 ? sm[tool] : null);
    const next = stages[keys[i + 1]];
    const flow = st.state === "done" && next && next.state !== "off" && next.state !== "pending";
    const prog = st.progress ? `<div class="st-bar"><i style="width:${Math.round(100 * st.progress[0] / st.progress[1])}%"></i></div>` : "";
    return `<div class="station st-${st.state} ${flow ? "flow" : ""}">
      <div class="node">${i + 1}</div><div class="st-name">${esc(st.title || keyTitle(k))}</div>
      <div class="st-big">${(big[tool] || (() => ""))(m) || "&nbsp;"}</div>
      <div class="st-msg">${esc(st.message || (sub[tool] || (() => ""))(m))}</div>${prog}
      <div class="st-state"><span class="tag ${{ done: "ok", error: "err", awaiting: "warn", running: "info" }[st.state] || "mute"}">${STATE_TXT[st.state] || st.state}</span></div></div>`;
  }).join("") : `<div class="empty" style="grid-column:1/-1">ابزاری در این اجرا نیست.</div>`;
}
function renderFeed() {
  const f = S.feedFilter;
  const evs = S.events.filter((e) => f === "all" || e.level === f).slice(-250).reverse();
  $("#feed").innerHTML = evs.length ? evs.map((e) =>
    `<div class="ev ${esc(e.level)}"><time>${fmtTime(e.ts)}</time><span class="dot"></span><span class="msg">${esc(e.msg)}</span></div>`).join("")
    : `<div class="empty">رویدادی برای نمایش نیست.</div>`;
}
$("#feedFilter").addEventListener("click", (e) => {
  const b = e.target.closest("button"); if (!b) return;
  S.feedFilter = b.dataset.f; $$("#feedFilter button").forEach((x) => x.classList.toggle("on", x === b)); renderFeed();
});
$("#masterSwitch").addEventListener("change", async (e) => {
  const on = e.target.checked;
  if (on && !((S.state && S.state.jobs_on) || S.settings.automation.retry_errors.enabled || (S.settings.automation.backup || {}).enabled))
    toast("کلید اصلی روشن شد، ولی هیچ کار خودکاری فعال نیست. از «کارهای خودکار» فعالشان کنید.", "warn");
  const r = await api("set_master", on);
  if (!r.ok) { toast(r.error, "error"); e.target.checked = !on; return; }
  S.settings.automation.master = on; if (S.draft) S.draft.automation.master = on;
  toast(on ? "کار خودکار روشن شد" : "کار خودکار خاموش شد", on ? "ok" : "warn");
  refreshState();
});
$("#btnCheckConn").addEventListener("click", (e) => withSpin(e.currentTarget, async () => {
  const names = [...Object.keys(CONN_TITLE).filter((n) => n !== "abuseipdb"), ...fgDevices().slice(1).map((d) => d.conn)];
  const res = await Promise.all(names.map((n) => api("test_connection", n, {})));
  res.forEach((r, i) => toast(`${connTitle(names[i])}: ${r.ok ? r.message : r.error}`, r.ok ? "ok" : "error"));
  refreshState();
}));

/* ================================================================ run page */
/* ---------------------------------------------------------------- ابزارها: ترتیب اجرا با کلیک */
const DNS_TYPES = { ip: ["PTR", "A", "CNAME", "NS", "MX", "TXT"], url: ["A", "AAAA", "CNAME", "NS", "MX", "TXT", "PTR"] };
const DNS_DEF = { ip: ["PTR", "A", "CNAME"], url: ["A", "AAAA", "CNAME"] };
const TOOL_DESC = {
  splunk: "یک کوئری ذخیره‌شده را اجرا و CSV را ذخیره می‌کند.",
  abuse: "IPها را در AbuseIPDB بررسی و به مخرب/غیرمخرب تقسیم می‌کند.",
  fortigate: "رنج داخلی، Address Object و Banned را چک و بقیه را بعد از تأیید بلاک می‌کند.",
  redmine: "بعد از پیش‌نمایش و تأیید، تیکت Security Events می‌سازد.",
  dns: "لوکاپ DNS روی IP (PTR و رکوردهای نام) یا روی URL/دامنه.",
  ssh: "اسکریپت را با داده‌ی ورودی (مثلاً src_ip) می‌سازد و بعد از تأیید روی دستگاه‌ها اجرا می‌کند.",
  scan: "Ping برای پیدا کردن هاست‌های روشن و/یا اسکن پورت‌های TCP، فقط در رنج‌های مجاز.",
  intel: "IPها (معمولاً غیرمخرب‌های AbuseIPDB) را دوباره با فید آنلاین FFraud و لیست داخلی شما بررسی می‌کند؛ مخرب‌ها برای ابزار بعدی (FortiGate) و همه برای دیتابیس.",
};
const RF = { seq: [], uid: 0, ssh: { devices: [], scripts: [] }, jobs: [], job: null };
async function loadToolsData() {
  const [a, b] = await Promise.all([api("ssh_list"), api("jobs_list")]);
  if (a.ok) RF.ssh = { devices: a.devices, scripts: a.scripts };
  if (b.ok) RF.jobs = b.jobs;
  renderStageForm();
}
const SSH_TPL_HINT = `هر ستون ورودی یک متغیر است (src_ip، dest_ip، url و ...؛ src هم به‌عنوان src_ip شناخته می‌شود). نمونه:
  <div class="codebox ltr" data-no-i18n style="white-space:pre;margin:6px 0">{% for src in src_ip %}
 permit tcp host 10.10.10.1 host {{src}} eq 443
{% endfor %}
remark {{src_ip|count}} addresses: {{src_ip|join:, }}</div>متغیرهای دستگاه مثل {host} مثل قبل کار می‌کنند.`;
function rfNew(tool) {
  const before = RF.seq.map((x) => x.tool), prev = before[before.length - 1];
  const it = { uid: ++RF.uid, tool, src: "list", text: "", path: "", column: "" };
  if (tool === "splunk") Object.assign(it, { query_id: "default", earliest: "", latest: "" });
  if (tool === "abuse") it.src = prev === "splunk" || prev === "dns" || prev === "scan" ? "prev" : "list";
  if (tool === "fortigate") Object.assign(it, { src: prev === "abuse" || prev === "intel" ? "prev" : "list", device: "fortigate", scenario: "" });
  if (tool === "intel") it.src = ["abuse", "splunk", "dns", "scan"].includes(prev) ? "prev" : "list";
  if (tool === "redmine") Object.assign(it, { src: before.includes("splunk") ? "run" : "csv", template_id: "" });
  if (tool === "dns") Object.assign(it, { src: prev && prev !== "redmine" && prev !== "ssh" ? "prev" : "list", mode: "ip", types: [...DNS_DEF.ip], concurrency: "" });
  if (tool === "scan") Object.assign(it, { src: prev && prev !== "redmine" && prev !== "ssh" ? "prev" : "list", ping: true, ports: "common", only_alive: false, banners: false, http: false, baseline: false, workers: "", timeout: "" });
  if (tool === "ssh") Object.assign(it, { src: prev && prev !== "redmine" ? "prev" : "list", var: "src_ip", script_id: "", body: "", mode: "config", use_sudo: false, save_config: false, dry_run: false, devs: [] });
  return it;
}
function segHtml(uid, opts, cur) {
  return `<div class="seg" data-seg="${uid}">${opts.map(([v, t, dis]) =>
    `<button data-v="${v}" class="${v === cur ? "on" : ""}" ${dis ? `disabled title="${esc(dis === true ? "ابزار مناسب پیش از این نیست" : dis)}"` : ""}>${t}</button>`).join("")}</div>`;
}
function csvPicker(uid, val) {
  return `<div class="row"><input type="text" class="ltr" data-rf="${uid}.path" value="${esc(WEB && val ? val.split(/[\\/]/).pop() : val)}" ${WEB ? `readonly placeholder="«انتخاب…» = آپلود فایل"` : `placeholder="C:\\reports\\file.csv"`}><button class="btn sm" data-pick="${uid}">انتخاب…</button></div>`;
}
/* 1.28: دستگاه و تسک (سناریو) گام FortiGate */
function fgDevices() { return (S.state && S.state.fg_devices) || [{ conn: "fortigate", name: "FortiGate 1" }]; }
function fgScenarios() { return (S.settings && S.settings.fg_scenarios) || []; }
function fgDevName(conn) { const d = fgDevices().find((x) => x.conn === conn); return d ? d.name : conn; }
const PREV_COLS = { abuse: "IP, ISP, Usage Type, ASN, Domain, Country Code, Country, City, Abuse Confidence Score, Total Reports, …, Status", intel: "ip, …",
  dns: "ستون‌های DNS (IP، PTR، A …)", scan: "ip, ports, …", splunk: "ستون‌های همان کوئری", ssh: "Device, Host, Status, Message, Output — یا با «خروجی آخرین دستور به‌صورت CSV»: Device, Host + ستون‌های همان CSV", fortigate: "Method, Path, Note, Result + ستون‌های ردیف" };
function fgPick(it) {
  const u = it.uid, devs = fgDevices(), scs = fgScenarios();
  if (!devs.some((d) => d.conn === it.device)) it.device = "fortigate";
  const sc = scs.find((x) => x.id === it.scenario);
  if (it.scenario && !sc) it.scenario = "";
  return `<div class="row" style="gap:10px;flex-wrap:wrap;margin-top:8px">
      <label class="field" style="flex:1;min-width:150px"><span>دستگاه</span><select data-rf="${u}.device">${devs.map((d) => `<option value="${esc(d.conn)}" ${d.conn === it.device ? "selected" : ""}>${esc(d.name)}</option>`).join("")}</select></label>
      <label class="field" style="flex:1;min-width:150px"><span>تسک</span><select data-rf="${u}.scenario"><option value="">پیش‌فرض: Ban IP (لیست Banned)</option>${scs.map((x) => `<option value="${esc(x.id)}" ${x.id === it.scenario ? "selected" : ""}>${esc(x.name)}</option>`).join("")}</select></label></div>
    <details class="fg-steps"><summary class="muted" style="cursor:pointer">${sc ? "کد تسک" : "کارهای تسک پیش‌فرض"}</summary>
      ${sc ? `${sc.note ? `<p class="hint" data-no-i18n>${esc(sc.note)}</p>` : ""}<div class="codebox ltr" data-no-i18n style="max-height:320px;overflow:auto;white-space:pre">${esc(sc.code)}</div>`
        : `<ol class="steps-ol">${FG_DEFAULT_DESC.map((x) => `<li>${esc(x)}</li>`).join("")}</ol>`}
      <div class="hint">${isAdmin() ? "تسک‌ها در «تنظیمات ← FortiGate ← تسک‌ها» ساخته و ویرایش می‌شوند." : "تسک‌ها را ادمین در تنظیمات می‌سازد."}</div></details>`;
}
const FG_DEFAULT_DESC = ["IPهای داخل «رنج‌های مستثنا» رد می‌شوند.",
  "Address Objectهای دستگاه خوانده می‌شوند؛ IPی که در یکی از آن‌ها هست بلاک نمی‌شود (Addressهای ساخته‌ی تسک‌ها با توضیح «AutoKRP» حساب نمی‌شوند).",
  "لیست Banned خوانده می‌شود؛ IPی که از قبل هست رد می‌شود.",
  "بلاک خودکار (IPS، …) یا با انقضا، اگر «تبدیل بلاک‌های خودکار» روشن باشد: پاک و دوباره Administrative.",
  "بقیه پس از تأیید شما به لیست Banned اضافه می‌شوند (POST /api/v2/monitor/user/banned/add_users)."];
function toolCard(it, i) {
  const before = RF.seq.slice(0, i).map((x) => x.tool), prev = before[before.length - 1], u = it.uid;
  const sp = (S.settings && S.settings.splunk) || {};
  const list = (ph) => `<textarea class="ltr" data-rf="${u}.text" placeholder="${esc(ph)}">${esc(it.text)}</textarea>`;
  let inner = "";
  if (it.tool === "splunk") {
    const qs = [["default", "پیش‌فرض (کوئری اصلی)"], ...((sp.queries || []).map((q) => [q.id, q.name]))];
    inner = `<label class="field"><span>کوئری</span><select data-rf="${u}.query_id">${qs.map(([v, t]) => `<option value="${esc(v)}" ${v === it.query_id ? "selected" : ""}>${esc(t)}</option>`).join("")}</select></label>
      <div class="row"><label class="field"><span>از</span><input type="text" class="ltr" data-rf="${u}.earliest" value="${esc(it.earliest)}" placeholder="${esc(sp.earliest || "-24h")}"></label>
      <label class="field"><span>تا</span><input type="text" class="ltr" data-rf="${u}.latest" value="${esc(it.latest)}" placeholder="${esc(sp.latest || "now")}"></label></div>
      <div class="hint">کوئری‌ها در «تنظیمات ← Splunk» ذخیره می‌شوند. بازه‌ی خالی = بازه‌ی همان کوئری یا تنظیمات.</div>`;
  } else if (it.tool === "abuse") {
    inner = segHtml(u, [["prev", "خروجی ابزار قبلی", !(prev === "splunk" || prev === "dns" || prev === "scan")], ["list", "لیست"], ["csv", "فایل CSV"]], it.src)
      + (it.src === "list" ? list("هر IP در یک خط یا جدا با ویرگول") : "")
      + (it.src === "csv" ? csvPicker(u, it.path) + `<label class="field"><span>ستون</span><input type="text" class="ltr" data-rf="${u}.column" value="${esc(it.column)}" placeholder="auto"></label>
        <div class="hint">auto = اگر ستون src باشد همان، وگرنه همه‌ی ستون‌ها. all = همه‌ی ستون‌ها.</div>` : "")
      + (it.src === "prev" ? `<div class="hint">${prev === "dns" || prev === "scan" ? `آدرس‌های به‌دست‌آمده از ${STEP_TITLE[prev]} بررسی می‌شوند.` : "ستون IP مبدأ (src_ip یا src) خروجی Splunk بررسی می‌شود."}</div>` : "")
      + `<div class="hint">${policyHint()}</div>`;
  } else if (it.tool === "fortigate") {
    const task = it.scenario && fgScenarios().find((x) => x.id === it.scenario);
    if (task) {
      if (it.src === "db") it.src = "prev";
      inner = segHtml(u, [["prev", prev ? `خروجی ${STEP_TITLE[prev]}` : "خروجی ابزار قبلی", !prev || prev === "redmine"], ["list", "لیست"], ["csv", "CSV"]], it.src)
        + (it.src === "list" ? list("src,name,group\n45.1.2.3,AKRP_45.1.2.3,Blocked-IPs") + `<div class="hint">خط اول نام ستون‌هاست (جدا با ویرگول)؛ همین نام‌ها در کد تسک در دسترس‌اند: r["src"]. اگر خط اول یک IP باشد، ستون «ip» فرض می‌شود.</div>` : "")
        + (it.src === "csv" ? csvPicker(u, it.path) + `<div class="hint">خط اول فایل نام ستون‌هاست؛ هر ستون در کد تسک با همان نام.</div>` : "")
        + (it.src === "prev" && prev ? `<div class="hint">ستون‌های خروجی ${STEP_TITLE[prev]}: <span class="tech">${esc(PREV_COLS[prev] || "ستون‌های همان خروجی")}</span></div>` : "");
    } else {
      inner = segHtml(u, [["prev", prev === "intel" ? "مخرب‌های بررسی تکمیلی" : "مخرب‌های AbuseIPDB قبلی", prev !== "abuse" && prev !== "intel"], ["db", "دیتابیس"], ["list", "لیست"], ["csv", "CSV"]], it.src)
        + (it.src === "db" ? `<div class="hint">همه‌ی IPهای دیتابیس که طبق قانون فعلی باید بلاک باشند؛ آن‌هایی که در FortiGate نیستند بلاک می‌شوند.</div>` : "")
        + (it.src === "list" ? list("IP یا CIDR، هر مورد در یک خط") : "")
        + (it.src === "csv" ? csvPicker(u, it.path) + `<div class="hint">ستون اول فایل خوانده می‌شود.</div>` : "")
        + (it.src === "prev" ? `<div class="hint">فقط IPهای مخرب ارسال می‌شوند؛ غیرمخرب‌ها و خطاها ارسال نمی‌شوند.${prev === "intel" ? " بلاک مخرب‌های بررسی تکمیلی همیشه تأیید می‌خواهد مگر در «تنظیمات ← بررسی تکمیلی» اجازه داده باشید." : ""}</div>` : "");
    }
    inner += fgPick(it);
  } else if (it.tool === "intel") {
    const ic = (S.settings && S.settings.intel) || {};
    const srcs = [ic.feed_enabled !== false ? "فید آنلاین FFraud" : "", ic.local_enabled ? "لیست داخلی" : ""].filter(Boolean);
    inner = segHtml(u, [["prev", prev === "abuse" ? "غیرمخرب‌های AbuseIPDB قبلی" : "خروجی ابزار قبلی", !["abuse", "splunk", "dns", "scan"].includes(prev)], ["db", "غیرمخرب‌های دیتابیس"], ["list", "لیست"], ["csv", "فایل CSV"]], it.src)
      + (it.src === "list" ? list("هر IP در یک خط یا جدا با ویرگول") : "")
      + (it.src === "csv" ? csvPicker(u, it.path) + `<label class="field"><span>ستون</span><input type="text" class="ltr" data-rf="${u}.column" value="${esc(it.column)}" placeholder="auto"></label>` : "")
      + (it.src === "prev" ? `<div class="hint">${prev === "abuse" ? "فقط IPهایی که AbuseIPDB غیرمخرب دانسته دوباره بررسی می‌شوند." : `آدرس‌های ${STEP_TITLE[prev] || "ابزار قبلی"} بررسی می‌شوند.`}</div>` : "")
      + (it.src === "db" ? `<div class="hint">همه‌ی IPهای غیرمخرب و بلاک‌نشده‌ی دیتابیس.</div>` : "")
      + `<div class="hint ${srcs.length ? "" : "warn"}">منابع: ${srcs.length ? srcs.join(" + ") : "هیچ منبعی روشن نیست"} (تنظیمات ← بررسی تکمیلی). اگر فید دانلود نشود یا لیست داخلی خوانده نشود، ابزار خطا می‌دهد و هیچ IPای پاک حساب نمی‌شود.</div>`;
  } else if (it.tool === "redmine") {
    const rt = ((S.settings && S.settings.redmine) || {}), tps = rt.templates || [];
    inner = (tps.length ? `<label class="field"><span>قالب تیکت</span><select data-rf="${u}.template_id"><option value="">پیش‌فرض (${esc((tps.find((x) => x.id === rt.default_template) || tps[0] || {}).name || "")})</option>${tps.map((x) => `<option value="${esc(x.id)}" ${x.id === it.template_id ? "selected" : ""}>${esc(x.name)}</option>`).join("")}</select></label>` : "")
      + segHtml(u, [["run", "خروجی Splunk این اجرا", !before.includes("splunk")], ["csv", "فایل CSV"]], it.src)
      + (it.src === "csv" ? csvPicker(u, it.path) + `<div class="hint">CSV با ستون‌های خروجی Splunk.</div>` : `<div class="hint">آخرین CSV اسپلانک این اجرا + گزارش AbuseIPDB و FortiGate پیوست می‌شوند.</div>`);
  } else if (it.tool === "dns") {
    const conc = S.settings && S.settings.dns ? S.settings.dns.concurrency : 20;
    inner = `<div class="row" style="gap:8px;align-items:center"><span class="muted">نوع ورودی</span>${`<div class="seg" data-mode="${u}">${[["ip", "IP / رنج"], ["url", "URL / دامنه"]].map(([v, t]) => `<button data-v="${v}" class="${it.mode === v ? "on" : ""}">${t}</button>`).join("")}</div>`}</div>`
      + segHtml(u, [["prev", "خروجی ابزار قبلی", !prev || prev === "redmine" || prev === "ssh"], ["list", it.mode === "ip" ? "رنج / لیست" : "لیست"], ["csv", "فایل CSV"]], it.src)
      + (it.src === "list" ? list(it.mode === "ip" ? "10.10.0.1-10.10.0.254\n10.10.1.0/24\n10.10.2.5" : "https://example.com/path\nexample.org") : "")
      + (it.src === "csv" ? csvPicker(u, it.path) : "")
      + (it.src !== "list" ? `<label class="field"><span>ستون ورودی</span><input type="text" class="ltr" data-rf="${u}.column" value="${esc(it.column)}" placeholder="${it.mode === "ip" ? "خودکار: src_ip، src، dest_ip، ip" : "خودکار: url، http_url، domain"}"></label>` : "")
      + `<div class="field"><span>رکوردهای خروجی</span><div class="chks">${DNS_TYPES[it.mode].map((t) => `<label class="chk"><input type="checkbox" data-dt="${u}" value="${t}" ${it.types.includes(t) ? "checked" : ""}>${t}${t === "PTR" && it.mode === "url" ? " (آدرس‌ها)" : ""}</label>`).join("")}</div></div>`
      + `<label class="field"><span>درخواست هم‌زمان</span><input type="number" min="1" max="100" data-rf="${u}.concurrency" value="${esc(it.concurrency)}" placeholder="${esc(conc)}"></label>`
      + `<div class="hint">${it.mode === "ip" ? "برای هر IP اول PTR گرفته می‌شود و بقیه‌ی رکوردها روی نام به‌دست‌آمده؛ ستون Match یعنی A همان IP است." : "نام میزبان از URL جدا و رکوردهایش گرفته می‌شود."} حداکثر ۴۰۹۶ ورودی. سرور DNS در «تنظیمات ← DNS».</div>`;
  }
  else if (it.tool === "scan") {
    const sc = (S.settings && S.settings.scan) || {};
    inner = segHtml(u, [["prev", "خروجی ابزار قبلی", !prev || prev === "redmine" || prev === "ssh"], ["list", "رنج / لیست"], ["csv", "فایل CSV"]], it.src)
      + (it.src === "list" ? list("192.168.1.0/24\n10.10.0.1-10.10.0.50\n10.10.2.5") : "")
      + (it.src === "csv" ? csvPicker(u, it.path) : "")
      + (it.src !== "list" ? `<label class="field"><span>ستون ورودی</span><input type="text" class="ltr" data-rf="${u}.column" value="${esc(it.column)}" placeholder="خودکار: src_ip، src، dest_ip، dest، ip"></label>` : "")
      + `<label class="chk"><input type="checkbox" data-sf="${u}.ping" ${it.ping ? "checked" : ""}>Ping (پیدا کردن هاست‌های روشن)</label>`
      + `<label class="field"><span>پورت‌های TCP (خالی = بدون اسکن پورت)</span><input type="text" class="ltr" data-rf="${u}.ports" value="${esc(it.ports)}" placeholder="common"></label>
          <div class="hint">common = ${num(55)} پورت رایج؛ یا بازه و فهرست، مثل 1-1024 یا 22,80,443,3389. هاست روشن = پاسخ ping یا حداقل یک پورت باز.</div>
          <div class="row" style="gap:12px;flex-wrap:wrap">${it.ping ? `<label class="chk" title="سریع‌تر؛ ولی هاستی که ping را بسته از قلم می‌افتد"><input type="checkbox" data-sf="${u}.only_alive" ${it.only_alive ? "checked" : ""}>پورت‌ها فقط روی هاست‌های پاسخ‌دهنده به ping</label>` : ""}
          <label class="chk"><input type="checkbox" data-sf="${u}.banners" ${it.banners ? "checked" : ""}>گرفتن بنر سرویس</label>
          <label class="chk"><input type="checkbox" data-sf="${u}.http" ${it.http ? "checked" : ""}>بررسی HTTP/HTTPS پورت‌های وب</label></div>`
      + `<div class="row"><label class="field"><span>اتصال هم‌زمان</span><input type="number" min="1" max="300" data-rf="${u}.workers" value="${esc(it.workers)}" placeholder="${esc(sc.workers || 100)}"></label>
          <label class="field"><span>Timeout (ثانیه)</span><input type="number" min="0.2" max="10" step="0.1" data-rf="${u}.timeout" value="${esc(it.timeout)}" placeholder="${esc(sc.timeout || 1)}"></label></div>`
      + `<label class="chk"><input type="checkbox" data-sf="${u}.baseline" ${it.baseline ? "checked" : ""}>مقایسه با اجرای قبلی (در کارهای ذخیره‌شده؛ ${String(it.ports || "").trim() ? "پورت" : "هاست"} تازه ← هشدار و ایمیل)</label>`
      + `<div class="hint">فقط آدرس‌های داخل رنج‌های مجاز اسکن می‌شوند؛ بقیه رد می‌شوند. سقف ${num(sc.max_hosts || 1024)} آدرس در هر اجرا. تنظیمات در «تنظیمات ← اسکن شبکه». خروجی (ستون ip) ورودی ابزار بعدی است.</div>`;
  }
  else if (it.tool === "ssh") {
    const sc = RF.ssh.scripts, dv = RF.ssh.devices;
    inner = segHtml(u, [["prev", "خروجی ابزار قبلی", !prev || prev === "redmine"], ["list", "لیست"], ["csv", "فایل CSV"], ["none", "بدون ورودی"]], it.src)
      + (it.src === "list" ? `<label class="field"><span>نام متغیر</span><input type="text" class="ltr" data-rf="${u}.var" value="${esc(it.var)}" placeholder="src_ip"></label>` + list("هر مقدار در یک خط یا جدا با ویرگول") : "")
      + (it.src === "csv" ? csvPicker(u, it.path) + `<div class="hint">هر ستون فایل یک متغیر است.</div>` : "")
      + `<label class="field"><span>اسکریپت</span><select data-rf="${u}.script_id"><option value="">— متن دلخواه پایین —</option>${sc.map((x) => `<option value="${x.id}" ${String(x.id) === String(it.script_id) ? "selected" : ""}>${esc(x.name)}</option>`).join("")}</select></label>`
      + (it.script_id ? `<div class="hint">حالت، sudo و ذخیره‌ی کانفیگ از تنظیمات همان اسکریپت در کتابخانه‌ی SSH خوانده می‌شود.</div>`
        : `<textarea class="ltr" data-rf="${u}.body" spellcheck="false" style="min-height:130px" placeholder="ip access-list extended test&#10;{% for src in src_ip %}&#10; permit tcp host 10.10.10.1 host {{src}} eq 443&#10;{% endfor %}">${esc(it.body)}</textarea>
        <div class="row" style="gap:12px;flex-wrap:wrap"><select data-rf="${u}.mode">${[["config", "config (حالت پیکربندی)"], ["exec", "exec (دستور عادی)"]].map(([v, t]) => `<option value="${v}" ${it.mode === v ? "selected" : ""}>${t}</option>`).join("")}</select>
          <label class="chk"><input type="checkbox" data-sf="${u}.use_sudo" ${it.use_sudo ? "checked" : ""}>sudo (لینوکس)</label><label class="chk"><input type="checkbox" data-sf="${u}.save_config" ${it.save_config ? "checked" : ""}>ذخیره‌ی کانفیگ</label></div>`)
      + `<div class="field"><span>دستگاه‌ها</span>${dv.length ? `<div class="chks" style="max-height:140px;overflow:auto">${dv.map((d) => `<label class="chk"><input type="checkbox" data-dev="${u}" value="${d.id}" ${it.devs.includes(d.id) ? "checked" : ""}>${esc(d.name || d.host)} <small class="muted ltr">${esc(d.host)}</small></label>`).join("")}</div>` : `<div class="hint warn">دستگاهی در صفحه‌ی SSH تعریف نشده است.</div>`}</div>`
      + `<label class="chk"><input type="checkbox" data-sf="${u}.dry_run" ${it.dry_run ? "checked" : ""}>اجرای آزمایشی (فقط ساخت متن، بدون اتصال)</label>`
      + `<label class="chk"><input type="checkbox" data-sf="${u}.last_csv" ${it.last_csv ? "checked" : ""}>خروجی آخرین دستور به‌صورت CSV برای ابزار بعدی</label>`
      + (it.last_csv ? `<div class="hint">خروجی آخرین دستور هر دستگاه (مثلاً cat /tmp/out.csv) با خط اول نام ستون‌ها، جدول ورودی ابزار بعدی می‌شود؛ ستون‌های Device و Host اضافه می‌شوند. دستگاه شبکه: فقط حالت exec.</div>` : "")
      + `<div class="hint">${SSH_TPL_HINT} پیش از اجرا متن نهایی را می‌بینید و تأیید می‌کنید. حداکثر ۵۰۰ مقدار؛ اگر ورودی خالی باشد اجرا نمی‌شود.</div>`;
  }
  return `<div class="stage on"><div class="stage-top"><span class="stage-num">${i + 1}</span><span class="stage-title">${STEP_TITLE[it.tool]}</span>
      <button class="iconbtn x" data-rm="${u}" title="حذف از ترتیب" aria-label="حذف"><svg><use href="#i-x"/></svg></button></div>
    <div class="hint">${TOOL_DESC[it.tool]}</div>${inner}</div>`;
}
function renderStageForm() {
  const cnt = (t) => RF.seq.filter((x) => x.tool === t).length;
  if (S.state && S.state.me && S.state.me.role === "readonly") {
    $("#stageForm").innerHTML = `<div class="empty" style="grid-column:1/-1">دسترسی شما فقط‌خواندنی است؛ نتیجه‌ی آخرین اجرا را پایین صفحه می‌بینید.</div>`; return;
  }
  $("#stageForm").innerHTML = `<div class="toolbox" style="grid-column:1/-1"><span class="muted">به ترتیب کلیک اضافه می‌شوند:</span>
      ${Object.keys(STEP_TITLE).filter(showTool).map((t) => `<button class="btn sm" data-add="${t}">+ ${STEP_TITLE[t]}${cnt(t) ? `<span class="n">×${num(cnt(t))}</span>` : ""}</button>`).join("")}
      <span style="flex:1"></span>${["splunk", "abuse", "fortigate", "redmine"].every(showTool) ? `<button class="btn sm ghost" data-preset="full">روال کامل</button>` : ""}${RF.seq.length ? `<button class="btn sm ghost" data-preset="clear">پاک کردن</button>` : ""}</div>
    <div class="toolbox" style="grid-column:1/-1"><span class="muted">کار ذخیره‌شده:</span>
      <select id="rfJob" style="width:auto;min-width:220px"><option value="">— انتخاب —</option>${RF.jobs.map((j) => `<option value="${esc(j.id)}" ${RF.job === j.id ? "selected" : ""}>${esc(j.name)}</option>`).join("")}</select>
      <button class="btn sm" data-job="open">باز کردن</button>${isAdmin() ? `<button class="btn sm" data-job="save" ${RF.seq.length ? "" : "disabled"}>ذخیره به‌عنوان کار…</button>` : ""}
      ${RF.job ? `<span class="hint">ویرایش کار «${esc((RF.jobs.find((j) => j.id === RF.job) || {}).name || "")}»</span>` : ""}
      <span class="hint">زمان‌بندی کارها در «کارهای خودکار».</span></div>`
    + (RF.seq.length ? RF.seq.map(toolCard).join("") : `<div class="empty" style="grid-column:1/-1">ابزاری انتخاب نشده است. با کلیک روی ابزارها ترتیب اجرا را بسازید.</div>`);
}
const rfItem = (uid) => RF.seq.find((x) => String(x.uid) === String(uid));
function rfFromItem(item) {
  const it = rfNew(item.tool), o = item.opts || {}, inp = o.input || {};
  RF.seq.push(it);
  if (inp.source) it.src = inp.source === "splunk" ? "prev" : inp.source === "abuse" ? "prev" : inp.source;
  Object.assign(it, { text: inp.text || "", path: inp.path || "", column: inp.column && inp.column !== "auto" ? inp.column : "" });
  if (item.tool === "splunk") Object.assign(it, { query_id: o.query_id || "default", earliest: o.earliest || "", latest: o.latest || "" });
  if (item.tool === "redmine") it.template_id = o.template_id || "";
  if (item.tool === "fortigate") Object.assign(it, { device: o.device || "fortigate", scenario: o.scenario || "" });
  if (item.tool === "dns") Object.assign(it, { mode: o.mode || "ip", types: o.types || [...DNS_DEF[o.mode || "ip"]], concurrency: o.concurrency || "" });
  if (item.tool === "scan") Object.assign(it, ("ping" in o ? { ping: !!o.ping, ports: o.ports || "", only_alive: !!o.only_alive }
      : o.mode === "ports" ? { ping: false, ports: o.ports || "common", only_alive: false } : { ping: true, ports: "443,80,22,445,3389", only_alive: false }),
    { banners: !!o.banners, http: !!o.http,
    baseline: !!o.baseline, workers: o.workers || "", timeout: o.timeout || "" });
  if (item.tool === "ssh") Object.assign(it, { var: o.var || "src_ip", script_id: o.script_id ? String(o.script_id) : "", body: o.body || "", mode: o.mode || "config",
    use_sudo: !!o.use_sudo, save_config: !!o.save_config, dry_run: !!o.dry_run, last_csv: !!o.last_csv, devs: (o.device_ids || []).map(Number) });
}
async function rfJob(act) {
  if (act === "open") {
    const id = $("#rfJob").value, j = RF.jobs.find((x) => x.id === id);
    if (!j) return toast("یک کار انتخاب کنید.", "warn");
    RF.seq = []; j.items.forEach(rfFromItem); RF.job = j.id; renderStageForm(); toast(`کار «${j.name}» باز شد`, "ok"); return;
  }
  const { items, err } = rfItems();
  if (err.length) return toast(err[0], "warn");
  const cur = RF.jobs.find((x) => x.id === RF.job);
  const res = await openModal({ title: "ذخیره به‌عنوان کار", body: `<label class="field"><span>نام کار</span><input type="text" id="jbName" value="${esc(cur ? cur.name : "")}" autofocus></label>
      ${cur ? `<label class="chk" style="margin-top:10px"><input type="checkbox" id="jbOver" checked>جایگزین کار «${esc(cur.name)}» (زمان‌بندی‌اش حفظ می‌شود)</label>` : ""}
      <p class="hint">همه‌ی ورودی‌ها، کوئری‌ها، لیست‌ها و مسیر فایل‌ها همان‌طور که هست ذخیره می‌شوند و هر بار همین‌ها اجرا می‌شوند.</p>`,
    foot: `<button class="btn ghost" data-r="0">انصراف</button><button class="btn primary" data-r="1">ذخیره</button>`,
    onOpen: (m, close) => $$("[data-r]", m).forEach((b) => (b.onclick = () => close(b.dataset.r === "1" ? { name: $("#jbName", m).value.trim(), over: !!($("#jbOver", m) || {}).checked } : null))) });
  if (!res) return;
  const base = res.over && cur ? { ...cur } : { schedule: { type: "none" }, enabled: false };
  delete base.next_at;
  const r = await api("job_save", { ...base, id: res.over && cur ? cur.id : "", name: res.name, items });
  if (!r.ok) return toast(r.error, "error");
  RF.job = r.job.id; toast(`کار «${r.job.name}» ذخیره شد`, "ok"); loadToolsData();
}
$("#stageForm").addEventListener("change", (e) => {
  const sf = e.target.closest("[data-sf]");
  if (sf) { const [u, k] = sf.dataset.sf.split("."); rfItem(u)[k] = sf.checked; if (k === "ping" || k === "last_csv") renderStageForm(); return; }
  const dv = e.target.closest("[data-dev]");
  if (dv) { const it = rfItem(dv.dataset.dev); it.devs = $$(`[data-dev="${dv.dataset.dev}"]`).filter((x) => x.checked).map((x) => Number(x.value)); return; }
  const d = e.target.closest("[data-dt]");
  if (d) { const it = rfItem(d.dataset.dt); it.types = $$(`[data-dt="${d.dataset.dt}"]`).filter((x) => x.checked).map((x) => x.value); return; }
  const sel = e.target.closest("select[data-rf]"); if (sel) { const [u, k] = sel.dataset.rf.split("."); rfItem(u)[k] = sel.value; if (k === "script_id" || k === "scenario") renderStageForm(); }
});
$("#stageForm").addEventListener("input", (e) => {
  const el = e.target.closest("[data-rf]"); if (!el) return;
  const [u, k] = el.dataset.rf.split("."); rfItem(u)[k] = el.value;
});
$("#stageForm").addEventListener("click", async (e) => {
  const jb = e.target.closest("[data-job]"); if (jb) { rfJob(jb.dataset.job); return; }
  const ad = e.target.closest("[data-add]"); if (ad) { RF.seq.push(rfNew(ad.dataset.add)); renderStageForm(); return; }
  const pr = e.target.closest("[data-preset]");
  if (pr) { RF.seq = []; RF.job = null; if (pr.dataset.preset === "full") ["splunk", "abuse", "fortigate", "redmine"].forEach((t) => RF.seq.push(rfNew(t))); renderStageForm(); return; }
  const rm = e.target.closest("[data-rm]"); if (rm) { RF.seq = RF.seq.filter((x) => String(x.uid) !== rm.dataset.rm); renderStageForm(); return; }
  const md = e.target.closest("[data-mode] button");
  if (md) { const it = rfItem(md.parentElement.dataset.mode); if (it.mode !== md.dataset.v) { it.mode = md.dataset.v; it.types = [...DNS_DEF[it.mode]]; it.column = ""; } renderStageForm(); return; }
  const sb = e.target.closest("[data-seg] button");
  if (sb && !sb.disabled) { rfItem(sb.parentElement.dataset.seg).src = sb.dataset.v; renderStageForm(); return; }
  const pk = e.target.closest("[data-pick]");
  if (pk) {
    const r = await api("pick_csv");
    if (!r.ok) { toast(r.error, "warn"); return; }
    if (r.path) { rfItem(pk.dataset.pick).path = r.path; renderStageForm(); }
  }
});
function rfItems() {
  const err = [];
  const items = RF.seq.map((it, i) => {
    const n = `${STEP_TITLE[it.tool]} (شماره ${i + 1})`;
    if (it.src === "list" && it.tool !== "splunk" && !it.text.trim()) err.push(`${n}: لیست خالی است.`);
    if (it.tool === "ssh") {
      if (!it.devs.length) err.push(`${n}: هیچ دستگاهی انتخاب نشده است.`);
      if (!it.script_id && !it.body.trim()) err.push(`${n}: متن اسکریپت خالی است.`);
      return { tool: "ssh", opts: { input: { source: it.src, text: it.text, path: it.path }, var: (it.var || "").trim() || "src_ip", script_id: it.script_id ? Number(it.script_id) : 0,
        body: it.body, mode: it.mode, use_sudo: it.use_sudo, save_config: it.save_config, dry_run: it.dry_run, last_csv: !!it.last_csv, device_ids: it.devs } };
    }
    if (it.src === "csv" && !it.path.trim()) err.push(`${n}: فایل CSV انتخاب نشده است.`);
    if (it.tool === "splunk") return { tool: "splunk", opts: { query_id: it.query_id, earliest: it.earliest.trim(), latest: it.latest.trim() } };
    const input = { source: it.src, text: it.text, path: it.path, column: it.column.trim() };
    if (it.tool === "abuse" && it.src === "csv") input.column = input.column || "auto";
    if (it.tool === "scan") {
      if (!it.ping && !String(it.ports || "").trim()) err.push(`${n}: Ping یا پورت‌ها را انتخاب کنید.`);
      return { tool: "scan", opts: { ping: !!it.ping, only_alive: !!it.only_alive, input, ports: String(it.ports || "").trim(), banners: !!it.banners, http: !!it.http,
        baseline: !!it.baseline, workers: Number(it.workers) || 0, timeout: Number(it.timeout) || 0 } };
    }
    if (it.tool === "dns") {
      if (!it.types.length) err.push(`${n}: هیچ رکوردی انتخاب نشده است.`);
      return { tool: "dns", opts: { mode: it.mode, types: it.types, input, concurrency: Number(it.concurrency) || 0 } };
    }
    if (it.tool === "redmine") return { tool: "redmine", opts: { input, template_id: it.template_id || "" } };
    if (it.tool === "fortigate") return { tool: "fortigate", opts: { input, device: it.device || "fortigate", scenario: it.scenario || "" } };
    return { tool: it.tool, opts: { input } };
  });
  return { items, err };
}
$("#btnStart").addEventListener("click", (e) => withSpin(e.currentTarget, async () => {
  if (!RF.seq.length) return toast("هیچ ابزاری انتخاب نشده است.", "warn");
  const { items, err } = rfItems();
  if (err.length) return toast(err[0], "warn");
  const r = await api("start_run", { items });
  if (!r.ok) return toast(r.error, "error");
  toast("اجرا شروع شد", "ok"); S.resultTab = "summary"; S.approvalKey = "";
  await pollRun(true); refreshState();
}));
$("#btnCancel").addEventListener("click", async () => {
  if (!(await confirm2({ title: "توقف اجرا", body: "<p>اجرای جاری متوقف شود؟ کارهای انجام‌شده برنمی‌گردند.</p>", confirm: "توقف", danger: true }))) return;
  const r = await api("cancel_run"); toast(r.ok ? "درخواست توقف ارسال شد" : r.error, r.ok ? "warn" : "error");
});
function exportDone(r) { if (!r.ok) return toast(r.error, "error"); if (r.path) toast(`${num(r.count)} فایل در ${r.path} ذخیره شد`, "ok"); }
$("#btnRunFolder").addEventListener("click", () => S.run && api("export_run_files", S.run.dir).then(exportDone));

async function pollRun(force) {
  const prev = S.run;
  const r = await api("get_run", null, force ? null : (prev && prev.lists_sig) || null);
  if (!r.ok) return;
  if (r.run && r.run.lists_same && prev && prev.id === r.run.id) {     // فهرست‌ها و پیش‌نمایش تأیید تغییری نکرده‌اند
    r.run.lists = prev.lists;
    if (r.run.approval && r.run.approval.same) r.run.approval = prev.approval && prev.approval.id === r.run.approval.id ? prev.approval : null;
  }
  S.run = r.run;
  const run = r.run;
  $("#runArea").hidden = !run;
  const active = run && (run.status === "running" || run.status === "awaiting");
  $("#btnCancel").hidden = !active; $("#btnStart").disabled = !!active;
  $("#btnRunFolder").hidden = !active;     // 1.37: پس از پایان اجرا فقط گزارش (در تاریخچه) می‌ماند؛ فایل‌های CSV پاک می‌شوند
  if (!run) return;
  const sig = JSON.stringify([run.status, run.stages, run.lines.length, run.approval && run.approval.step, S.resultTab, run.summary]);
  if (!force && sig === S.runSig) return;
  S.runSig = sig;
  $("#runTitle").textContent = active ? "اجرای جاری" : "آخرین اجرا";
  $("#runMeta").textContent = `${run.id} — ${STATE_TXT[run.status] || { done: "کامل شد", failed: "ناموفق" }[run.status] || run.status}`;
  renderRail($("#runRail"), run.stages, run.summary, run.order);
  renderApproval(run);
  renderResults(run);
}

/* ---------------------------------------------------------------- approval */
function originTag(o) {
  return { intel: `<span class="tag err">بررسی تکمیلی</span>`, abuse: `<span class="tag err">مخرب</span>`, clean_foreign: `<span class="tag warn">غیرمخرب خارجی</span>`, manual: `<span class="tag mute">دستی</span>` }[o] || "—";
}
function policyHint() {
  return "فقط IPهای مخرب بلاک می‌شوند؛ غیرمخرب‌ها (از هر کشوری) بلاک نمی‌شوند.";
}
const DEC = { ban: ["warn", "بلاک"], convert: ["warn", "تبدیل به Administrative"], address: ["info", "Address Object"], banned: ["mute", "از قبل Banned"], ignored: ["mute", "داخلی / مستثنا"], invalid: ["err", "نامعتبر"] };
function renderApproval(run) {
  const box = $("#approvalBox");
  const ap = run.approval;
  const key = ap ? run.id + ":" + (ap.id || ap.key || ap.step) : "";
  if (key === S.approvalKey) return;
  S.approvalKey = key; S.approvalId = ap ? ap.id || "" : "";
  if (!ap) { box.innerHTML = ""; return; }
  if (!canTool(ap.step)) {
    box.innerHTML = `<div class="approval"><p class="hint warn">این اجرا منتظر تأیید «${esc(STEP_TITLE[ap.step] || ap.step)}» است؛ فقط کاربری که به این ابزار دسترسی دارد می‌تواند تأیید کند.</p></div>`;
    return;
  }
  const pv = ap.preview;
  if (ap.step === "fortigate" && pv.task) { approvalTask(run, pv, box); return; }
  if (ap.step === "fortigate") {
    const c = pv.counts;
    const isAct = (p) => p.decision === "ban" || p.decision === "convert";
    box.innerHTML = `<div class="approval"><h2>تأیید بلاک در FortiGate${pv.multi ? ` — <span>${esc(pv.device)}</span>` : ""}</h2>
      <p class="hint">${num(c.to_ban)}‏ IP در هیچ رنج داخلی، Address Object یا لیست Banned نیستند و بلاک می‌شوند.${c.to_convert ? ` ${num(c.to_convert)}‏ IP در Banned هست ولی بلاک خودکار (IPS، Application Control، ...) یا با انقضاست؛ از Banned پاک و بلافاصله به‌صورت Administrative دوباره بلاک می‌شود.` : ""} تیک هر IP را که نمی‌خواهید بردارید.
      ${pv.test_mode ? "<br><b class='hint warn'>حالت تست روشن است: هیچ درخواست بلاکی ارسال نمی‌شود و فقط فایل JSON نوشته می‌شود.</b>" : ""}</p>
      <div class="sum-grid">${[["warn", c.to_ban, "برای بلاک"], ...(c.to_convert ? [["warn", c.to_convert, "تبدیل به Administrative"]] : []), ["", c.already, "از قبل Banned"], ["", c.address, "تطابق Address"], ["", c.ignored, "داخلی / مستثنا"]]
        .map(([k, v, t]) => `<div class="sum ${k}"><b>${num(v)}</b><span>${t}</span></div>`).join("")}</div>
      <div class="row" style="gap:10px;margin:8px 0;flex-wrap:wrap;align-items:center"><input type="text" class="ltr" id="apQ" placeholder="جستجوی IP یا جزئیات" style="max-width:280px">
        <label class="chk"><input type="checkbox" id="apOthers">نمایش ردیف‌های غیرقابل بلاک هم</label><span class="muted" id="apInfo"></span></div>
      <div class="table-wrap inner" id="apTbl"></div>
      <div class="actions"><button class="btn" id="apReject">بلاک نکن</button><button class="btn warn" id="apOk">بلاک <span id="apN">${num(c.to_ban + (c.to_convert || 0))}</span> آدرس…</button></div></div>`;
    // 1.27.9: انتخاب در حافظه (Set)، نه چک‌باکس هزاران ردیف؛ حداکثر AP_SHOW ردیف در DOM
    const AP_SHOW = 500, act = pv.plan.filter(isAct);
    const sel = new Set(act.map((p) => p.ip));
    const draw = () => {
      const q = ($("#apQ").value || "").trim().toLowerCase(), oth = $("#apOthers").checked;
      const rows = pv.plan.filter((p) => (oth || isAct(p)) && (!q || p.ip.includes(q) || String(p.detail || "").toLowerCase().includes(q)));
      const shown = rows.slice(0, AP_SHOW), fa = rows.filter((p) => sel.has(p.ip) || isAct(p));
      const allOn = fa.length && fa.filter(isAct).every((p) => sel.has(p.ip));
      $("#apTbl").innerHTML = `<table class="grid"><thead><tr><th class="chk nosort"><input type="checkbox" id="apAll" ${allOn ? "checked" : ""} title="همه‌ی ردیف‌های فیلترشده"></th><th class="nosort">IP</th><th class="nosort">منشأ</th><th class="nosort">تصمیم</th><th class="nosort">جزئیات</th></tr></thead><tbody>
        ${shown.map((p) => `<tr><td class="chk">${isAct(p) ? `<input type="checkbox" class="apIp" value="${esc(p.ip)}" ${sel.has(p.ip) ? "checked" : ""}>` : ""}</td>
          <td class="ltr">${esc(p.ip)}</td><td>${originTag(p.origin)}</td><td><span class="tag ${DEC[p.decision][0]}">${DEC[p.decision][1]}</span></td><td class="wrap">${esc(p.detail)}</td></tr>`).join("")}</tbody></table>`;
      $("#apInfo").textContent = [rows.length > AP_SHOW ? I18N.t(`${num(AP_SHOW)} ردیف اول از ${num(rows.length)}؛ برای دیدن بقیه جستجو کنید`) : "",
        oth && pv.others_total > pv.plan.length - act.length ? I18N.t(`از ${num(pv.others_total)} ردیف غیرقابل بلاک فقط ${num(pv.plan.length - act.length)} نمونه آمده است`) : ""].filter(Boolean).join(" · ");
      $("#apN").textContent = num(sel.size);
      $("#apAll").onchange = (e) => { rows.filter(isAct).forEach((p) => (e.target.checked ? sel.add(p.ip) : sel.delete(p.ip))); draw(); };
      $$(".apIp").forEach((x) => (x.onchange = () => { x.checked ? sel.add(x.value) : sel.delete(x.value); $("#apN").textContent = num(sel.size); }));
    };
    let apT = null;
    $("#apQ").oninput = () => { clearTimeout(apT); apT = setTimeout(draw, 200); };
    $("#apOthers").onchange = draw;
    draw();
    $("#apReject").onclick = () => decide(run.id, false);
    $("#apOk").onclick = async () => {
      const ips = act.map((p) => p.ip).filter((ip) => sel.has(ip));
      if (!ips.length) return toast("هیچ IPای انتخاب نشده است. برای ادامه «بلاک نکن» را بزنید.", "warn");
      const ok = await confirm2({
        title: "تأیید نهایی بلاک", danger: !pv.test_mode, confirm: pv.test_mode ? "ثبت در فایل تست" : `بلاک ${ips.length} آدرس`,
        body: `<p>${pv.test_mode ? "در حالت تست فقط فایل نوشته می‌شود." : `این ${ips.length}‏ IP با expiry تنظیم‌شده به لیست Banned فورتی‌گیت اضافه می‌شوند.`}</p>
          <div class="path ltr" style="max-height:160px;overflow:auto">${ips.slice(0, 300).map(esc).join("<br>")}${ips.length > 300 ? `<br>… ${I18N.t(`و ${num(ips.length - 300)} آدرس دیگر`)}` : ""}</div>`,
        ack: pv.test_mode ? null : "لیست را بررسی کردم و بلاک این آدرس‌ها را تأیید می‌کنم",
      });
      if (ok) decide(run.id, true, { ips });
    };
  } else if (ap.step === "ssh") {
    box.innerHTML = `<div class="approval"><h2>تأیید اجرای SSH</h2>
      <p class="hint">اسکریپت «${esc(pv.name)}» در حالت <span class="tech">${esc(pv.mode || "exec")}</span>${pv.save_config ? " با ذخیره‌ی کانفیگ" : ""}${pv.use_sudo ? " با sudo" : ""} روی ${num(pv.devices.length)} دستگاه اجرا می‌شود.
      ${Object.keys(pv.counts || {}).length ? "<br>ورودی: " + Object.entries(pv.counts).map(([k, v]) => `<span class="tech">${esc(k)}</span>=${num(v)}`).join("، ") : ""}</p>
      <div class="chks" style="margin:6px 0">${pv.devices.map((d) => `<span class="tag mute">${esc(d.name)} <span class="ltr">${esc(d.host)}</span></span>`).join("")}</div>
      <div class="codebox ltr" data-no-i18n style="max-height:320px;overflow:auto;white-space:pre">${esc(pv.script)}</div>
      <div class="actions"><button class="btn" id="apReject">اجرا نکن</button><button class="btn warn" id="apOk">اجرا روی ${num(pv.devices.length)} دستگاه…</button></div></div>`;
    $("#apReject").onclick = () => decide(run.id, false);
    $("#apOk").onclick = async () => {
      const ok = await confirm2({ title: "تأیید نهایی SSH", danger: true, confirm: "اجرا", body: `<p>متن بالا روی ${num(pv.devices.length)} دستگاه ارسال می‌شود.</p>`,
        ack: "متن نهایی و دستگاه‌ها را بررسی کردم" });
      if (ok) decide(run.id, true, {});
    };
  } else {
    const dup = pv.duplicate;
    box.innerHTML = `<div class="approval"><h2>تأیید ساخت تیکت Redmine</h2>
      ${(pv.templates || []).length > 1 ? `<label class="field" style="max-width:360px"><span>قالب تیکت</span><select id="apTpl">${pv.templates.map((x) => `<option value="${esc(x.id)}" ${pv.template && x.id === pv.template.id ? "selected" : ""}>${esc(x.name)}${x.tracker ? ` — ${esc(x.tracker)}` : ""}</option>`).join("")}</select></label>` : ""}
      ${pv.note ? `<p class="hint warn">⚠ ${esc(pv.note)}</p>` : ""}
      <p class="hint">${pv.template ? `قالب: <b>${esc(pv.template.name)}</b> — Tracker: <span class="ltr">${esc(pv.tracker || "—")}</span> — ` : ""}پروژه: <span class="ltr">${esc(pv.project)}</span> — پیوست‌ها: <span class="ltr">${pv.attachments.map(esc).join("، ") || "—"}</span>
      ${pv.test_mode ? "<br><b class='hint warn'>حالت تست روشن است: تیکت ساخته نمی‌شود و فقط payload در فایل نوشته می‌شود.</b>" : ""}</p>
      ${dup ? `<p class="hint warn">برای همین فایل داده قبلاً تیکت ساخته شده است (${esc(dup.info)} در ${fmtDate(dup.ts)}).</p><label class="chk"><input type="checkbox" id="apForce">با وجود تکرار دوباره بساز</label>` : ""}
      <h3 style="margin:12px 0 6px">${esc(pv.subject)}</h3>
      <div class="pv-desc" data-no-i18n>${esc(pv.description)}</div>
      <details style="margin-top:10px"><summary class="muted" style="cursor:pointer">فیلدهای سفارشی (${pv.fields.length})</summary>
        <dl class="kv" style="margin-top:8px">${pv.fields.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join("")}</dl></details>
      <div class="actions"><button class="btn" id="apReject">تیکت نساز</button><button class="btn primary" id="apOk">ساخت تیکت…</button></div></div>`;
    $("#apReject").onclick = () => decide(run.id, false);
    const ts = $("#apTpl");
    if (ts) ts.onchange = async () => {
      const r = await api("decide", run.id, false, { switch_template: ts.value, approval_id: S.approvalId || "" });
      if (!r.ok) return toast(r.error, "error");
      S.approvalKey = "__"; toast("پیش‌نمایش با قالب تازه ساخته می‌شود…", "info"); setTimeout(() => pollRun(true), 600);
    };
    $("#apOk").onclick = async () => {
      const force = !!($("#apForce") && $("#apForce").checked);
      if (dup && !force) return toast("تیکت تکراری است. اگر می‌خواهید دوباره بسازید تیک «با وجود تکرار» را بزنید.", "warn");
      const ok = await confirm2({ title: "تأیید نهایی", confirm: pv.test_mode ? "ثبت در فایل تست" : "ساخت تیکت",
        body: `<p>${pv.test_mode ? "payload در فایل test_redmine_payload.json نوشته می‌شود." : `تیکت «${esc(pv.subject)}» با ${pv.attachments.length} پیوست ساخته شود؟`}</p>` });
      if (ok) decide(run.id, true, { force });
    };
  }
}
/* 1.29: تأیید کارهای تسک پایتونی */
function approvalTask(run, pv, box) {
  const T = pv.task, acts = pv.actions, AP_SHOW = 500, sel = new Set(acts.map((a) => a.i));
  box.innerHTML = `<div class="approval"><h2>تأیید تسک «<span>${esc(T.name)}</span>» در FortiGate${pv.multi ? ` — <span>${esc(pv.device)}</span>` : ""}</h2>
    <p class="hint">${I18N.t(`تسک برای ${num(pv.rows_total)} ردیف ورودی ${num(pv.actions_total)} کار پیشنهاد کرده است.`)} فقط کارهای تیک‌خورده، به همین ترتیب، به دستگاه فرستاده می‌شوند.
      ${T.on_error === "continue" ? "اگر یک کار خطا بدهد، بقیه ادامه پیدا می‌کند." : "اولین خطا بقیه‌ی کارها را متوقف می‌کند."}
      <span class="muted">sha <span class="ltr">${esc(T.sha)}</span></span>
      ${pv.test_mode ? "<br><b class='hint warn'>حالت تست روشن است: هیچ درخواستی ارسال نمی‌شود و فقط درخواست‌ها در گزارش اجرا نوشته می‌شود.</b>" : ""}
      ${pv.actions_total > acts.length ? `<br><b class="hint warn">${I18N.t(`فقط ${num(acts.length)} کار اول از ${num(pv.actions_total)} قابل بررسی است؛ تأیید فقط همین‌ها را می‌فرستد.`)}</b>` : ""}</p>
    <div class="row" style="gap:10px;margin:8px 0;flex-wrap:wrap;align-items:center"><input type="text" class="ltr" id="apQ" placeholder="جستجوی مسیر، توضیح یا مقدار" style="max-width:300px"><span class="muted" id="apInfo"></span></div>
    <div id="apTbl"></div>
    <div class="actions"><button class="btn" id="apReject">اجرا نکن</button><button class="btn warn" id="apOk">ارسال <span id="apN">${num(sel.size)}</span> کار…</button></div></div>`;
  const draw = () => {
    const q = ($("#apQ").value || "").trim().toLowerCase();
    const rows = acts.filter((a) => !q || `${a.method} ${a.path} ${a.note} ${JSON.stringify(a.row)} ${JSON.stringify(a.body)}`.toLowerCase().includes(q));
    $("#apTbl").innerHTML = fgActionsTable(rows.slice(0, AP_SHOW), sel);
    const all = $("#apAll"); if (all) { all.checked = rows.length > 0 && rows.every((a) => sel.has(a.i)); all.onchange = (e) => { rows.forEach((a) => (e.target.checked ? sel.add(a.i) : sel.delete(a.i))); draw(); }; }
    $("#apInfo").textContent = rows.length > AP_SHOW ? I18N.t(`${num(AP_SHOW)} ردیف اول از ${num(rows.length)}؛ برای دیدن بقیه جستجو کنید`) : "";
    $("#apN").textContent = num(sel.size);
    $$(".apAct").forEach((x) => (x.onchange = () => { const i = Number(x.value); x.checked ? sel.add(i) : sel.delete(i); $("#apN").textContent = num(sel.size); }));
  };
  let t = null; $("#apQ").oninput = () => { clearTimeout(t); t = setTimeout(draw, 200); };
  draw();
  $("#apReject").onclick = () => decide(run.id, false);
  $("#apOk").onclick = async () => {
    const ids = acts.filter((a) => sel.has(a.i)).map((a) => a.i);
    if (!ids.length) return toast("هیچ کاری انتخاب نشده است. برای ادامه «اجرا نکن» را بزنید.", "warn");
    const ok = await confirm2({ title: "تأیید نهایی تسک", danger: !pv.test_mode, confirm: pv.test_mode ? "ثبت در گزارش (تست)" : `ارسال ${ids.length} کار`,
      body: `<p>${pv.test_mode ? "در حالت تست هیچ درخواستی ارسال نمی‌شود." : I18N.t(`${num(ids.length)} کار تسک «${T.name}» روی «${pv.device}» ارسال می‌شود.`)}</p>`,
      ack: pv.test_mode ? null : "کارها را بررسی کردم و ارسالشان را تأیید می‌کنم" });
    if (ok) decide(run.id, true, { acts: ids });
  };
}
async function decide(id, approve, payload) {
  const r = await api("decide", id, approve, { ...(payload || {}), approval_id: S.approvalId || "" });
  if (!r.ok) return toast(r.error, "error");
  S.approvalKey = "__"; toast(approve ? "تأیید ثبت شد" : "رد شد", approve ? "ok" : "warn");
  setTimeout(() => pollRun(true), 300);
}

/* ---------------------------------------------------------------- results */
function scoreHtml(v) {
  if (v === null || v === undefined || v === "") return "—";
  const n = Number(v), col = n >= 75 ? "var(--err)" : n >= 25 ? "var(--warn)" : n > 0 ? "var(--info)" : "var(--ok)";
  return `<span class="score"><i><b style="width:${Math.min(100, n)}%;background:${col}"></b></i>${n}</span>`;
}
function statusTag(s) {
  return { ABUSE: `<span class="tag err">مخرب</span>`, CLEAN: `<span class="tag ok">غیرمخرب</span>`, ERROR: `<span class="tag warn">خطا</span>` }[s] || `<span class="tag mute">${esc(s || "—")}</span>`;
}
const REC_SHOW = 500;     // ساختن هزاران ردیف DOM (اجرا با ده‌ها هزار IP) رابط را کند و حافظه را پر می‌کرد
function recTable(recs, total) {
  if (!recs.length) return `<div class="empty">موردی نیست.</div>`;
  const all = Math.max(recs.length, total || 0);
  recs = recs.slice(0, REC_SHOW);
  const ROUTE = { block: ["err", "بلاک"], review: ["ok", "بلاک نمی‌شود"], error: ["mute", "ارسال نشد"] };
  return `<div class="table-wrap inner"><table class="grid"><thead><tr>${["IP", "وضعیت", "مسیر", "امتیاز", "گزارش‌ها", "کشور", "ISP", "نوع کاربری", "دسته‌ها", ""].map((t) => `<th class="nosort">${t}</th>`).join("")}</tr></thead><tbody>
    ${recs.map((r) => `<tr><td class="ltr"><span class="link ip" data-ipd="${esc(r.ip)}">${esc(r.ip)}</span></td><td>${statusTag(r.abuse_status)}</td>
      <td>${r.route ? `<span class="tag ${ROUTE[r.route][0]}" title="${esc(r.note || "")}">${ROUTE[r.route][1]}</span>` : "—"}</td><td>${scoreHtml(r.score)}</td>
      <td class="num">${num(r.reports)}</td><td>${esc(r.country_code || "—")}</td><td class="wrap">${esc(r.isp || "—")}</td><td class="wrap">${esc(r.usage_type || "—")}</td>
      <td class="wrap">${esc(r.error || r.categories || "—")}</td><td>${r.cached ? `<span class="tag mute">از کش</span>` : ""}${r.note ? `<span class="tag info">${esc(r.note)}</span>` : ""}</td></tr>`).join("")}</tbody></table></div>`
    + (all > recs.length ? `<p class="hint">${num(recs.length)} ردیف اول از ${num(all)}؛ همه در «خروجی فایل‌ها» و صفحه‌ی «آدرس‌ها».</p>` : "");
}
function renderResults(run) {
  const recs = (run.lists && run.lists.abuse_records) || [];
  const mal = recs.filter((r) => r.abuse_status === "ABUSE"), cln = recs.filter((r) => r.abuse_status === "CLEAN"), err = recs.filter((r) => r.abuse_status === "ERROR");
  const fw = (run.lists && (run.lists.fw_results || run.lists.fw_plan)) || [], fwa = (run.lists && run.lists.fw_actions) || null;
  // 1.27.9: سرور از فهرست‌های بزرگ فقط ۵۰۰ ردیف می‌فرستد؛ شمار کل جدا
  const L = run.lists || {}, ac = L.abuse_counts || {};
  const nMal = ac.ABUSE ?? mal.length, nCln = ac.CLEAN ?? cln.length, nErr = ac.ERROR ?? err.length;
  const nFw = fwa ? (L.fw_actions_total ?? fwa.length) : (L.fw_results ? L.fw_results_total : L.fw_plan_total) ?? fw.length;
  const tabs = [["summary", "خلاصه"], ["mal", "مخرب", nMal], ["clean", "غیرمخرب", nCln], ["err", "خطا", nErr], ["fw", "FortiGate", nFw]];
  const dnsL = (run.lists && run.lists.dns) || {};
  Object.keys(dnsL).forEach((k) => tabs.push(["dns:" + k, keyTitle(k), dnsL[k].total]));
  const scanL = (run.lists && run.lists.scan) || {};
  Object.keys(scanL).forEach((k) => tabs.push(["scan:" + k, keyTitle(k), scanL[k].total]));
  const sshL = (run.lists && run.lists.ssh) || {};
  Object.keys(sshL).forEach((k) => tabs.push(["ssh:" + k, keyTitle(k), sshL[k].rows.length]));
  const intL = (run.lists && run.lists.intel) || {};
  Object.keys(intL).forEach((k) => tabs.push(["intel:" + k, keyTitle(k), intL[k].total]));
  tabs.push(["log", "گزارش اجرا", run.lines.length]);
  $("#resultTabs").innerHTML = tabs.map(([k, t, n]) => `<button data-rt="${k}" class="${S.resultTab === k ? "on" : ""}">${t}${n !== undefined ? `<span class="n">${num(n)}</span>` : ""}</button>`).join("");
  const body = $("#resultBody");
  const sm = run.summary;
  if (S.resultTab === "summary") {
    const blocks = [];
    if (sm.splunk) blocks.push(["Splunk", [["", sm.splunk.rows, "ردیف خروجی"], ["", sm.splunk.src, "IP مبدأ یکتا"]]]);
    if (sm.abuse) { const a = sm.abuse; blocks.push(["AbuseIPDB", [["", a.total, "IP ورودی"], ["", a.checked, "بررسی آنلاین"], ["", a.cached, "از کش"], ["err", a.abuse, "مخرب"], ["ok", a.clean, "غیرمخرب"], ["warn", a.repeat || undefined, "تکراری ← بررسی مجدد"], ["warn", a.error, "خطا"], ["", a.private + a.ignored, "خصوصی / داخلی (رد شد)"]]]); }
    if (sm.fortigate && sm.fortigate.actions !== undefined) { const f = sm.fortigate; blocks.push(["FortiGate", [["", f.rows, "ردیف ورودی"], ["", f.actions, "کار پیشنهادی"], ["ok", f.done, "انجام شد"], ["warn", f.test || undefined, "تست"], ["err", f.failed, "ناموفق"], ["", f.skipped || undefined, "ارسال نشد"], ["", f.rejected, "رد شده توسط شما"]]]); }
    else if (sm.fortigate) { const f = sm.fortigate; blocks.push(["FortiGate", [["", f.targets, "IP ورودی"], ["ok", f.banned, "بلاک‌شده"], ["ok", f.done || undefined, "تسک انجام شد"], ["ok", f.converted || undefined, "تبدیل به Administrative"], ["warn", f.test, "بلاک (تست)"], ["", f.already, "از قبل Banned"], ["", f.address, "تطابق Address"], ["", f.ignored, "داخلی"], ["err", f.failed, "ناموفق"], ["", f.rejected, "رد شده توسط شما"]]]); }
    if (sm.redmine) blocks.push(["Redmine", [["", sm.redmine.issue ? "#" + sm.redmine.issue : "تست", "تیکت"]]]);
    Object.keys(run.stages || {}).filter((k) => (run.stages[k].tool || k.split("_")[0]) === "ssh" && run.stages[k].summary).forEach((k) => {
      const d = run.stages[k].summary;
      blocks.push([keyTitle(k), [["", d.devices, "دستگاه"], ["ok", d.ok, d.dry ? "آزمایشی" : "موفق"], ["err", d.failed, "ناموفق"]]]);
    });
    Object.keys(run.stages || {}).filter((k) => (run.stages[k].tool || k.split("_")[0]) === "scan" && run.stages[k].summary).forEach((k) => {
      const d = run.stages[k].summary;
      blocks.push([keyTitle(k), [["", d.targets, "آدرس اسکن‌شده"], ["ok", d.hosts, "هاست روشن"],
        ...(d.mode === "ports" ? [["", d.open, "پورت باز"]] : []), ["warn", d.new || undefined, "تازه نسبت به قبل"], ["", d.gone || undefined, "دیده نشد نسبت به قبل"],
        ["", d.denied || undefined, "خارج از رنج مجاز (رد شد)"]]]);
    });
    Object.keys(run.stages || {}).filter((k) => (run.stages[k].tool || k.split("_")[0]) === "dns" && run.stages[k].summary).forEach((k) => {
      const d = run.stages[k].summary;
      blocks.push([keyTitle(k), [["", d.total, d.mode === "url" ? "میزبان" : "IP"], ["ok", d.found, d.mode === "url" ? "resolve شد" : "PTR داشت"],
        ...Object.entries(d.statuses || {}).filter(([x]) => !["PTR_FOUND", "RESOLVED"].includes(x)).map(([x, v]) => [x === "TIMEOUT" || x === "ERROR" ? "warn" : "", v, x])]]);
    });
    Object.keys(run.stages || {}).filter((k) => (run.stages[k].tool || k.split("_")[0]) === "intel" && run.stages[k].summary).forEach((k) => {
      const d = run.stages[k].summary;
      blocks.push([keyTitle(k), [["", d.total, "IP بررسی‌شده"], ["err", d.malicious, "مخرب"], ["", d.feed, "از فید FFraud"], ["", d.local, "از لیست داخلی"], ["ok", d.clean, "پاک"],
        ["", d.skipped || undefined, "خصوصی / مستثنا (رد شد)"]]]);
    });
    const rate = sm.abuse_rate && sm.abuse_rate.remaining ? `<p class="hint">سهمیه‌ی باقی‌مانده‌ی AbuseIPDB: ${num(sm.abuse_rate.remaining)} از ${num(sm.abuse_rate.limit)}</p>` : "";
    body.innerHTML = blocks.length ? blocks.map(([t, items]) => `<h3 style="margin:4px 0 8px">${t}</h3><div class="sum-grid">${items.filter(([, v]) => v !== undefined)
      .map(([k, v, l]) => `<div class="sum ${k}"><b>${typeof v === "number" ? num(v) : esc(v)}</b><span>${l}</span></div>`).join("")}</div>`).join("") + rate
      : `<div class="empty">نتیجه‌ای هنوز آماده نیست.</div>`;
  } else if (S.resultTab === "mal") body.innerHTML = recTable(mal, nMal);
  else if (S.resultTab === "clean") body.innerHTML = (cln.length ? `<p class="hint">${policyHint()} ستون «مسیر» نشان می‌دهد هر IP کجا رفت. همه در صفحه‌ی «آدرس‌ها» با فیلتر «غیرمخرب» هم هستند.</p>` : "") + recTable(cln, nCln);
  else if (S.resultTab === "err") body.innerHTML = (err.length ? `<p class="hint">این IPها به FortiGate ارسال نشدند. از صفحه‌ی «آدرس‌ها» می‌توانید دوباره بررسی‌شان کنید.</p>` : "") + recTable(err, nErr);
  else if (S.resultTab.startsWith("ssh:")) {
    const d = sshL[S.resultTab.slice(4)];
    body.innerHTML = !d ? `<div class="empty">نتیجه‌ای نیست.</div>` : (d.dry ? `<p class="hint warn">اجرای آزمایشی: به دستگاه‌ها وصل نشد؛ متن نهایی هر دستگاه در خروجی است.</p>` : "")
      + d.rows.map((r) => `<details class="sec" ${d.rows.length === 1 ? "open" : ""}><summary style="cursor:pointer"><span class="tag ${r.Status === "ok" ? "ok" : "err"}">${esc(r.Status)}</span> <b>${esc(r.Device)}</b> <span class="ltr muted">${esc(r.Host)}</span> — ${esc(r.Message)}</summary>
        <div class="codebox ltr" data-no-i18n style="max-height:360px;overflow:auto;white-space:pre;margin-top:6px">${esc(r.Output || "—")}</div></details>`).join("");
  }
  else if (S.resultTab.startsWith("intel:")) {
    const d = intL[S.resultTab.slice(6)];
    body.innerHTML = !d ? `<div class="empty">نتیجه‌ای نیست.</div>` : (d.total > d.rows.length ? `<p class="hint">${num(d.rows.length)} ردیف اول از ${num(d.total)} (مخرب‌ها اول)؛ همه در «خروجی فایل‌ها».</p>` : "")
      + (d.rows.length ? `<div class="table-wrap inner"><table class="grid"><thead><tr><th>IP</th><th>نتیجه</th><th>منبع</th><th>امتیاز</th><th>تأییدها</th><th>دسته</th><th>نوع</th><th>جزئیات</th></tr></thead><tbody>
      ${d.rows.map((r) => `<tr><td class="ltr"><span class="link ip" data-ipd="${esc(r.ip)}">${esc(r.ip)}</span></td><td>${r.result === "ABUSE" ? `<span class="tag err">مخرب</span>` : `<span class="tag ok">پاک</span>`}</td>
        <td>${esc(r.source || "—")}</td><td class="num">${r.score === "" ? "—" : num(r.score)}</td><td class="num">${r.confirmations === "" ? "—" : num(r.confirmations)}</td><td class="ltr">${esc(r.category || "—")}</td><td class="ltr">${esc(r.type || "—")}</td><td class="wrap">${esc(String(r.source || "").startsWith("FFraud") ? (String(r.detail).split("؛ ")[1] || "") : r.detail || "")}</td></tr>`).join("")}</tbody></table></div>` : `<div class="empty">موردی نیست.</div>`);
  }
  else if (S.resultTab.startsWith("scan:")) {
    const d = scanL[S.resultTab.slice(5)];
    if (!d) { body.innerHTML = `<div class="empty">نتیجه‌ای نیست.</div>`; return; }
    const cols = d.columns.filter((c) => d.rows.some((r) => r[c] !== "" && r[c] !== undefined && r[c] !== null));
    body.innerHTML = (d.gone && d.gone.length ? `<p class="hint warn">نسبت به اجرای قبلی دیده نشد: <span class="ltr">${esc(d.gone.join(", "))}</span></p>` : "")
      + (d.total > d.rows.length ? `<p class="hint">${num(d.rows.length)} ردیف اول از ${num(d.total)} نمایش داده شده است؛ همه در «خروجی فایل‌ها».</p>` : "")
      + (d.rows.length ? `<div class="table-wrap inner"><table class="grid"><thead><tr>${cols.map((c) => `<th class="nosort ltr">${esc(c)}</th>`).join("")}</tr></thead><tbody>
      ${d.rows.map((r) => `<tr>${cols.map((c) => `<td class="ltr wrap">${c === "new" ? (r.new ? `<span class="tag warn">تازه</span>` : "") : esc(r[c])}</td>`).join("")}</tr>`).join("")}</tbody></table></div>`
        : `<div class="empty">هاست روشنی پیدا نشد.</div>`);
  }
  else if (S.resultTab.startsWith("dns:")) {
    const d = dnsL[S.resultTab.slice(4)];
    if (!d) { body.innerHTML = `<div class="empty">نتیجه‌ای نیست.</div>`; return; }
    const cols = d.columns.filter((c) => c !== "DNS_Server" && d.rows.some((r) => r[c] !== "" && r[c] !== undefined));
    body.innerHTML = (d.total > d.rows.length ? `<p class="hint">${num(d.rows.length)} ردیف اول از ${num(d.total)} نمایش داده شده است؛ همه در «خروجی فایل‌ها».</p>` : "")
      + `<div class="table-wrap inner"><table class="grid"><thead><tr>${cols.map((c) => `<th class="nosort ltr">${esc(c)}</th>`).join("")}</tr></thead><tbody>
      ${d.rows.map((r) => `<tr>${cols.map((c) => `<td class="ltr wrap">${c === "Status" ? `<span class="tag ${["PTR_FOUND", "RESOLVED"].includes(r[c]) ? "ok" : ["TIMEOUT", "ERROR"].includes(r[c]) ? "warn" : "mute"}">${esc(r[c])}</span>` : esc(r[c])}</td>`).join("")}</tr>`).join("")}</tbody></table></div>`;
  }
  else if (S.resultTab === "fw" && fwa) {
    body.innerHTML = fgActionsTable(fwa.slice(0, REC_SHOW), null, true) + (nFw > Math.min(REC_SHOW, fwa.length) ? `<p class="hint">${num(Math.min(REC_SHOW, fwa.length))} ردیف اول از ${num(nFw)}؛ همه در «خروجی فایل‌ها».</p>` : "");
  }
  else if (S.resultTab === "fw") {
    const RES = { done: ["ok", "انجام شد"], converted: ["ok", "تبدیل شد"], banned: ["ok", "بلاک شد"], failed: ["err", "ناموفق"], test: ["warn", "تست"], rejected: ["mute", "رد شد"], address: ["info", "Address"], banned_: ["mute", "از قبل"], ignored: ["mute", "داخلی"], invalid: ["err", "نامعتبر"] };
    body.innerHTML = fw.length ? `<div class="table-wrap inner"><table class="grid"><thead><tr><th class="nosort">IP</th><th class="nosort">منشأ</th><th class="nosort">تصمیم</th><th class="nosort">نتیجه</th><th class="nosort">جزئیات</th></tr></thead><tbody>
      ${fw.slice(0, REC_SHOW).map((p) => { const r = p.result === "banned" && p.decision === "banned" ? "banned_" : p.result; const rr = RES[r] || ["mute", r || "—"];
        return `<tr><td class="ltr">${esc(p.ip)}</td><td>${originTag(p.origin)}</td><td><span class="tag ${DEC[p.decision][0]}">${DEC[p.decision][1]}</span></td><td>${p.result ? `<span class="tag ${rr[0]}">${rr[1]}</span>` : "—"}</td><td class="wrap">${esc(p.response && p.result === "failed" ? p.response : p.detail)}</td></tr>`; }).join("")}
      </tbody></table></div>${nFw > Math.min(REC_SHOW, fw.length) ? `<p class="hint">${num(Math.min(REC_SHOW, fw.length))} ردیف اول از ${num(nFw)}؛ همه در «خروجی فایل‌ها».</p>` : ""}` : `<div class="empty">مرحله‌ی FortiGate در این اجرا نتیجه‌ای ندارد.</div>`;
  } else {
    body.innerHTML = `<div class="log">${run.lines.slice().reverse().map((e) => `<div class="ev ${esc(e.level)}"><time>${fmtTime(e.ts)}</time><span class="dot"></span><span class="msg">${esc(e.msg)}</span></div>`).join("")}</div>`;
  }
}
$("#resultTabs").addEventListener("click", (e) => { const b = e.target.closest("[data-rt]"); if (b) { S.resultTab = b.dataset.rt; S.runSig = ""; pollRun(true); } });
document.addEventListener("click", (e) => {
  const b = e.target.closest("[data-ipd]"); if (!b) return;
  if (String(window.getSelection() || "").trim()) return;   // کاربر در حال انتخاب متن برای کپی است
  showIp(b.dataset.ipd);
});
document.addEventListener("click", (e) => { const c = e.target.closest("[data-copy]"); if (c) copyText(c.dataset.copy, c.dataset.copyLabel || "IP"); });
async function copyText(text, what = "") {
  try { await navigator.clipboard.writeText(text); }
  catch (e) {
    const ta = document.createElement("textarea"); ta.value = text; ta.style.position = "fixed"; ta.style.opacity = "0";
    document.body.appendChild(ta); ta.select(); const ok = document.execCommand("copy"); ta.remove();
    if (!ok) return toast("کپی ممکن نشد؛ متن را انتخاب کنید و Ctrl+C بزنید", "warn");
  }
  toast(`${what || "متن"} کپی شد`, "ok");
}

/* ================================================================ automation page */
function sw(path, val, label, extra = "") {
  return `<label class="switch"><input type="checkbox" data-type="bool" data-path="${path}" ${val ? "checked" : ""} ${extra}><span class="track"><span class="thumb"></span></span>${label}</label>`;
}
function nextDaily(d) {
  if (!d.enabled) return "اجرای روزانه غیرفعال است.";
  const [h, m] = (d.time || "08:00").split(":").map(Number); const now = new Date(); const t = new Date(); t.setHours(h, m, 0, 0);
  if (t <= now) t.setDate(t.getDate() + 1);
  return `اجرای بعدی: ${fmtDate(t.getTime() / 1000)}${S.draft.automation.master ? "" : " — کلید اصلی کار خودکار خاموش است"}`;
}
function renderAuto() {
  if (!isAdmin()) S.autoTab = "daily";
  $$("#autoTabs button").forEach((b) => { b.classList.toggle("on", b.dataset.t === S.autoTab); b.hidden = !isAdmin() && b.dataset.t !== "daily"; });
  if (S.autoTab === "daily") { $("#btnSaveAuto").hidden = $("#btnUndoAuto").hidden = true; renderJobs($("#autoBody")); return; }
  if (!S.draft) return;
  const A = S.draft.automation, body = $("#autoBody");
  $("#btnSaveAuto").hidden = $("#btnUndoAuto").hidden = S.autoTab === "daily";
  if (S.autoTab === "daily") {
    renderJobs(body); return;
  } else if (S.autoTab === "sshsched") {
    renderSshSched(body); return;
  } else if (S.autoTab === "backup") {
    const bk = A.backup || { enabled: false, time: "02:00" };
    body.innerHTML = `<div class="form"><div class="row" style="justify-content:space-between">${sw("automation.backup.enabled", bk.enabled, "<b>پشتیبان‌گیری روزانه‌ی کانفیگ</b>")}
        <button class="btn" id="btnBkNow">پشتیبان‌گیری الان</button></div>
      <p class="hint">هر روز در ساعت تعیین‌شده کانفیگ همه‌ی دستگاه‌هایی که «پشتیبان‌گیری کانفیگ» برایشان روشن است گرفته و رمزشده ذخیره می‌شود. اگر کانفیگ تغییر نکرده باشد نسخه‌ی تازه ذخیره نمی‌شود؛ اگر تغییر کرده باشد در رویدادها اعلام می‌شود و (اگر روشن باشد) ایمیل ارسال می‌شود. دستگاه‌ها، نسخه‌ها و دستورها در «SSH ← پشتیبان کانفیگ».</p>
      <div class="form-grid" style="margin-top:12px"><label class="field"><span>ساعت اجرا</span><input type="time" data-path="automation.backup.time" value="${esc(bk.time || "02:00")}"></label></div></div>`;
    $("#btnBkNow").onclick = async () => { const r = await api("backup_now"); if (!r.ok) return toast(r.error, "error"); toast("پشتیبان‌گیری شروع شد", "ok"); };
  } else if (S.autoTab === "retry") {
    const r = A.retry_errors;
    body.innerHTML = `<div class="form"><div class="row" style="justify-content:space-between">${sw("automation.retry_errors.enabled", r.enabled, "<b>چک مجدد IPهای خطادار</b>")}<button class="btn" id="btnRetryNow">اجرای الان</button></div>
      <p class="hint">IPهایی که بررسی AbuseIPDB برایشان خطا داده (مثلاً rate limit) هر چند دقیقه یک بار دوباره بررسی می‌شوند. این کار فقط بررسی است و بلاکی انجام نمی‌دهد.</p>
      <div class="form-grid" style="margin-top:12px"><label class="field"><span>هر چند دقیقه</span><input type="number" min="5" data-type="num" data-path="automation.retry_errors.every_minutes" value="${esc(r.every_minutes)}"></label></div></div>`;
    $("#btnRetryNow").onclick = (e) => withSpin(e.currentTarget, async () => {
      const l = await api("list_ips", true); const ips = ipRows(l).filter((x) => x.abuse_status === "ERROR").map((x) => x.ip);
      if (!ips.length) return toast("IP خطاداری وجود ندارد.", "info");
      const r2 = await api("ips_action", "recheck", ips); toast(r2.ok ? r2.message : r2.error, r2.ok ? "ok" : "error");
    });
  } else {
    renderTplTab(body);
  }
  bindInputs(body);
  const dt = $("#dailyTime"); if (dt) dt.addEventListener("input", () => ($("#nextRun").textContent = nextDaily(S.draft.automation.daily)));
}
/* ===== زمان‌بندی SSH ===== */
const WDAYS = [[5, "شنبه"], [6, "یکشنبه"], [0, "دوشنبه"], [1, "سه‌شنبه"], [2, "چهارشنبه"], [3, "پنجشنبه"], [4, "جمعه"]];   // شماره‌ها مثل Python: دوشنبه=0
const SS = { list: [], fgu: {}, devs: [], scripts: [] };
function schedDays(d) { return !d || !d.length || d.length === 7 ? "هر روز" : WDAYS.filter(([n]) => d.includes(n)).map(([, t]) => t).join("، "); }
function nextSched(x) {
  if (!x.enabled) return "غیرفعال";
  const [hh, mm] = String(x.time || "00:00").split(":").map(Number), now = new Date();
  for (let i = 0; i < 8; i++) {
    const d = new Date(now); d.setDate(now.getDate() + i); d.setHours(hh, mm, 0, 0);
    const wd = (d.getDay() + 6) % 7;
    if (d > now && (!x.days || !x.days.length || x.days.includes(wd))) return "اجرای بعدی: " + fmtDate(d.getTime() / 1000);
  }
  return "—";
}
async function renderSshSched(body) {
  body.innerHTML = `<p class="hint">در حال بارگذاری…</p>`;
  const [a, b] = await Promise.all([api("ssh_sched_list"), api("ssh_list")]);
  if (S.page !== "auto" || S.autoTab !== "sshsched") return;      // در این فاصله تب عوض شد
  if (!a.ok || !b.ok) { body.innerHTML = `<p class="hint warn">${esc((a.ok ? b : a).error)}</p>`; return; }
  Object.assign(SS, { list: a.schedules, fgu: a.fgu_current, devs: b.devices, scripts: b.scripts });
  const master = S.settings.automation.master;
  body.innerHTML = `<div class="form"><div class="row" style="justify-content:space-between"><b>زمان‌بندی اجرای اسکریپت و به‌روزرسانی FortiGate</b>
      <button class="btn primary" id="ssNew">زمان‌بندی جدید</button></div>
    <p class="hint">اسکریپت ذخیره‌شده یا به‌روزرسانی آفلاین FortiGate در ساعت و روزهای تعیین‌شده روی دستگاه‌های انتخابی اجرا می‌شود. قواعد مثل اجرای روزانه است: اولین اجرا از همین لحظه، و اگر برنامه بسته بوده و بیش از «حداکثر قدمت» گذشته باشد، آن نوبت رد می‌شود. اگر کار SSH دیگری در جریان باشد، اجرا تا تمام شدن آن صبر می‌کند. تغییرات این تب بلافاصله ذخیره می‌شوند.</p>
    ${master ? "" : `<p class="hint warn">کلید اصلی کار خودکار خاموش است؛ زمان‌بندی‌ها اجرا نمی‌شوند.</p>`}
    ${SS.list.length ? `<div class="table-wrap" style="margin-top:12px"><table class="grid"><thead><tr>${["فعال", "نام", "نوع", "زمان", "دستگاه‌ها", "آخرین اجرا", ""].map((t) => `<th class="nosort">${t}</th>`).join("")}</tr></thead><tbody>
      ${SS.list.map((x) => `<tr><td><label class="switch"><input type="checkbox" data-sstog="${esc(x.id)}" ${x.enabled ? "checked" : ""}><span class="track"><span class="thumb"></span></span></label></td>
        <td><b>${esc(x.name)}</b><div class="muted" style="font-size:12px">${esc(nextSched(x))}</div></td>
        <td>${x.kind === "fgupdate" ? "به‌روزرسانی FortiGate" : "اسکریپت: " + esc((SS.scripts.find((c) => c.id === x.script_id) || { name: "(حذف شده)" }).name)}</td>
        <td><span class="ltr">${esc(x.time)}</span> — ${esc(schedDays(x.days))}</td>
        <td>${num(x.device_ids.length)}</td>
        <td>${x.last_at ? `${fmtDate(x.last_at)}<div class="muted" style="font-size:12px">${esc(x.last_message || "")}</div>` : "—"}</td>
        <td><div class="row" style="gap:6px;flex-wrap:nowrap"><button class="btn sm" data-ssed="${esc(x.id)}">ویرایش</button><button class="btn sm ghost" data-ssdel="${esc(x.id)}">حذف</button></div></td></tr>`).join("")}
      </tbody></table></div>` : `<div class="empty" style="margin-top:12px">هنوز زمان‌بندی‌ای ساخته نشده است.</div>`}</div>`;
  $("#ssNew").onclick = () => editSshSched(null);
  $$("[data-ssed]", body).forEach((b) => (b.onclick = () => editSshSched(SS.list.find((x) => x.id === b.dataset.ssed))));
  $$("[data-ssdel]", body).forEach((b) => (b.onclick = async () => {
    const x = SS.list.find((y) => y.id === b.dataset.ssdel);
    if (!(await confirm2({ title: "حذف زمان‌بندی", body: `<p>«${esc(x.name)}» حذف شود؟</p>`, confirm: "حذف", danger: true }))) return;
    const r = await api("ssh_sched_delete", x.id); if (!r.ok) return toast(r.error, "error");
    toast("حذف شد", "ok"); renderSshSched(body);
  }));
  $$("[data-sstog]", body).forEach((c) => (c.onchange = async () => {
    const r = await api("ssh_sched_toggle", c.dataset.sstog, c.checked); if (!r.ok) return toast(r.error, "error");
    renderSshSched(body);
  }));
}
function editSshSched(x) {
  const isNew = !x;
  x = x || { name: "", kind: "script", time: "03:00", days: [], device_ids: [], enabled: true, options: { concurrency: 5, timeout: 120 } };
  const sel = new Set(x.device_ids), o = x.options || { concurrency: 5, timeout: 120 };
  const fg = SS.fgu || {};
  const devList = (kind) => SS.devs.filter((d) => kind !== "fgupdate" || d.device_type === "fortinet");
  const devHtml = (kind) => devList(kind).length ? devList(kind).map((d) => `<label class="chk" style="display:flex;gap:8px"><input type="checkbox" class="ssDev" value="${d.id}" ${sel.has(d.id) ? "checked" : ""}>
      <span>${esc(d.name || d.host)} <span class="muted ltr">${esc(d.host)}</span> <span class="tag mute">${esc(d.device_type)}</span>${d.grp ? ` <span class="tag info">${esc(d.grp)}</span>` : ""}</span></label>`).join("")
    : `<p class="hint">${kind === "fgupdate" ? "هیچ دستگاه FortiGate (fortinet) در «SSH ← دستگاه‌ها» نیست." : "هنوز دستگاهی در «SSH ← دستگاه‌ها» تعریف نشده است."}</p>`;
  const kindPart = (kind) => kind === "fgupdate"
    ? `<div class="field wide"><span>تنظیمات به‌روزرسانی</span><div class="hint">از تب «SSH ← به‌روزرسانی FortiGate» برداشته می‌شود و هنگام ذخیره‌ی این زمان‌بندی ثابت می‌ماند:
        <div class="ltr" style="margin-top:4px">${fg.source === "remote" ? "TFTP دیگر: " + esc(fg.tftp_ip || "—") : "پوشه: " + esc(fg.folder || "—")}</div>
        <div>پکیج‌ها: ${fg.package_names && fg.package_names.length ? esc(fg.package_names.join("، ")) : "<b>انتخاب نشده</b>"}</div></div></div>`
    : `<label class="field"><span>اسکریپت ذخیره‌شده</span><select id="ssScript">${SS.scripts.length ? SS.scripts.map((c) => `<option value="${c.id}" ${c.id === x.script_id ? "selected" : ""}>${esc(c.name)}</option>`).join("") : `<option value="">— اسکریپتی ذخیره نشده —</option>`}</select></label>
       <label class="field"><span>تعداد اجرای هم‌زمان</span><input type="number" id="ssConc" value="${esc(o.concurrency)}"></label>
       <label class="field"><span>Timeout هر دستگاه (ثانیه)</span><input type="number" id="ssTo" value="${esc(o.timeout)}"></label>`;
  openModal({ title: isNew ? "زمان‌بندی جدید" : `ویرایش «${x.name}»`, wide: true,
    body: `<div class="form-grid">
      <label class="field"><span>نام</span><input type="text" id="ssName" value="${esc(x.name)}" autofocus></label>
      <label class="field"><span>نوع کار</span><select id="ssKind"><option value="script" ${x.kind === "script" ? "selected" : ""}>اجرای اسکریپت</option><option value="fgupdate" ${x.kind === "fgupdate" ? "selected" : ""}>به‌روزرسانی آفلاین FortiGate</option></select></label>
      <label class="field"><span>ساعت اجرا</span><input type="time" id="ssTime" value="${esc(x.time)}"></label>
      <div class="field wide"><span>روزها (هیچ‌کدام = هر روز)</span><div class="row" style="flex-wrap:wrap;gap:14px">${WDAYS.map(([n, t]) => `<label class="chk"><input type="checkbox" class="ssDay" value="${n}" ${x.days.includes(n) ? "checked" : ""}>${t}</label>`).join("")}</div></div>
      <div id="ssKindPart" style="display:contents">${kindPart(x.kind)}</div>
      <div class="field wide"><span>دستگاه‌ها</span><div id="ssDevs" style="max-height:240px;overflow:auto;display:flex;flex-direction:column;gap:6px">${devHtml(x.kind)}</div></div>
      <div class="field"><span>&nbsp;</span><label class="switch"><input type="checkbox" id="ssOn" ${x.enabled ? "checked" : ""}><span class="track"><span class="thumb"></span></span>فعال</label></div>
    </div>`,
    foot: `<button class="btn ghost" data-x="0">انصراف</button><button class="btn primary" data-x="1">ذخیره</button>`,
    onOpen: (m, close) => {
      $("#ssKind", m).onchange = (e) => { $("#ssKindPart", m).innerHTML = kindPart(e.target.value); $("#ssDevs", m).innerHTML = devHtml(e.target.value); };
      $("[data-x='0']", m).onclick = () => close();
      $("[data-x='1']", m).onclick = (e) => withSpin(e.currentTarget, async () => {
        const kind = $("#ssKind", m).value;
        const payload = { id: isNew ? "" : x.id, name: $("#ssName", m).value, kind, time: $("#ssTime", m).value,
          days: $$(".ssDay", m).filter((c) => c.checked).map((c) => Number(c.value)),
          device_ids: $$(".ssDev", m).filter((c) => c.checked).map((c) => Number(c.value)), enabled: $("#ssOn", m).checked };
        if (kind === "script") { payload.script_id = Number($("#ssScript", m).value || 0); payload.options = { concurrency: Number($("#ssConc", m).value || 5), timeout: Number($("#ssTo", m).value || 120) }; }
        const r = await api("ssh_sched_save", payload);
        if (!r.ok) return toast(r.error, "error");
        close(); toast("ذخیره شد", "ok"); renderSshSched($("#autoBody"));
      });
    } });
}
$("#autoTabs").addEventListener("click", (e) => { const b = e.target.closest("button[data-t]"); if (b) { S.autoTab = b.dataset.t; renderAuto(); } });
$("#btnSaveAuto").addEventListener("click", (e) => saveDraft(e.currentTarget));

/* ================================================================ IPs page */
const IP_COLS = [
  ["ip", "IP", 1], ["abuse_status", "وضعیت", 1], ["score", "امتیاز", 1], ["reports", "گزارش‌ها", 1], ["country_code", "کشور", 1],
  ["isp", "ISP", 1], ["usage_type", "نوع کاربری", 0], ["domain", "دامنه", 0], ["asn", "ASN", 0], ["categories", "دسته‌ها", 1],
  ["is_tor", "Tor", 0], ["is_whitelisted", "Whitelist", 0], ["fw_status", "FortiGate", 1],
  ["attack_count", "تعداد حمله", 1], ["signatures", "Signatureها", 0], ["dest_ports", "پورت‌های مقصد", 0],
  ["checked_at", "زمان بررسی", 1], ["last_seen", "آخرین مشاهده", 0], ["first_seen", "اولین مشاهده", 0],
  ["seen_days", "روزهای بررسی", 1], ["intel_status", "بررسی تکمیلی", 1],
];
const FW = { banned: ["ok", "بلاک شد"], already: ["mute", "از قبل Banned"], address: ["info", "Address"], ignored: ["mute", "داخلی"], failed: ["err", "ناموفق"], test: ["warn", "تست"], unbanned: ["warn", "از بلاک خارج شد"] };
function visibleCols() {
  const saved = S.settings && S.settings.ui && S.settings.ui.ip_columns, known = new Set(IP_COLS.map((c) => c[0]));
  const ok = Array.isArray(saved) ? saved.filter((k) => known.has(k)) : [];   // ستون‌های حذف‌شده (مثل «بررسی دستی») نادیده
  return ok.length ? ok : IP_COLS.filter((c) => c[2]).map((c) => c[0]);
}
const IP_PAGE = 500;
/** list_ips فشرده: نام ستون‌ها یک بار + آرایه‌ی مقدارها برای هر ردیف ← همان شیءهای قبلی */
function ipRows(r) {
  if (r.rows) return r.rows;
  const c = r.cols || [];
  return (r.data || []).map((a) => { const o = {}; for (let i = 0; i < c.length; i++) o[c[i]] = a[i]; return o; });
}
async function loadIps() {
  const r = await api("list_ips", true);
  if (!r.ok) return toast(r.error, "error");
  S.ips = ipRows(r); S.repeatDays = r.repeat_days || 0; renderIps();
}
function cell(k, r) {
  const v = r[k];
  if (k === "ip") return `<td class="ltr"><span class="link ip" data-ipd="${esc(v)}">${esc(v)}</span></td>`;
  if (k === "abuse_status") return `<td>${statusTag(v)}</td>`;
  if (k === "score") return `<td>${scoreHtml(v)}</td>`;
  if (k === "fw_status") return `<td>${v ? `<span class="tag ${(FW[v] || ["mute"])[0]}" title="${esc(r.fw_detail || "")}">${esc((FW[v] || [0, v])[1])}</span>` : "—"}</td>`;
  if (k === "seen_days") return `<td class="num">${v ? (isRepeat(r) ? `<span class="tag warn" title="IP غیرمخربی که بارها تکرار شده؛ بررسی مجدد">${num(v)}</span>` : num(v)) : "—"}</td>`;
  if (k === "intel_status") return `<td>${intelTag(r)}</td>`;
  if (["reports", "attack_count"].includes(k)) return `<td class="num">${num(v)}</td>`;
  if (["asn", "domain", "dest_ports", "checked_at", "last_seen", "first_seen"].includes(k)) return `<td class="ltr">${esc(v ?? "—")}</td>`;
  return `<td class="wrap">${esc(v === null || v === undefined || v === "" ? "—" : v)}</td>`;
}
function isRepeat(r) { const n = S.repeatDays || 0; return n > 0 && r.abuse_status === "CLEAN" && (r.seen_days || 0) >= n && !["banned", "already"].includes(r.fw_status); }
function intelTag(r) {
  if (!r.intel_status) return "—";
  return `<span class="tag ${r.intel_status === "ABUSE" ? "err" : "ok"}" title="${esc([r.intel_source, r.intel_detail, r.intel_at].filter(Boolean).join(" — "))}">${r.intel_status === "ABUSE" ? "مخرب" : "پاک"}</span>`;
}
function filteredIps() {
  const q = $("#ipSearch").value.trim().toLowerCase(), f = S.ipFilter;
  const cc = $("#ipCountry").value, dmin = Number($("#ipDays").value || 0);     // 1.37: فیلتر دقیق کشور و روزهای بررسی
  let rows = S.ips.filter((r) => {
    if (cc && (cc === "-" ? r.country_code : String(r.country_code || "").toUpperCase() !== cc)) return false;
    if (dmin > 0 && (r.seen_days || 0) < dmin) return false;
    if (f === "ABUSE" && r.abuse_status !== "ABUSE") return false;
    if (f === "CLEAN" && r.abuse_status !== "CLEAN") return false;
    if (f === "unchecked" && r.abuse_status && r.abuse_status !== "ERROR") return false;
    if (f === "fw_pending" && !r.fw_pending) return false;
    if (f === "intel" && r.intel_status !== "ABUSE") return false;
    if (!q) return true;
    return ["ip", "country", "country_code", "isp", "domain", "categories", "signatures", "usage_type"].some((k) => String(r[k] || "").toLowerCase().includes(q));
  });
  const { k, d } = S.ipSort;
  rows.sort((a, b) => {
    let x = a[k], y = b[k];
    if (k === "ip") { const p = (s) => String(s).split(".").map((n) => n.padStart(3, "0")).join("."); x = p(x); y = p(y); }
    const nx = Number(x), ny = Number(y);
    if (x !== null && y !== null && x !== "" && y !== "" && !isNaN(nx) && !isNaN(ny)) return (nx - ny) * d;
    return String(x ?? "").localeCompare(String(y ?? "")) * d;
  });
  return rows;
}
function ipCountryOpts() {
  const sel = $("#ipCountry"), cur = sel.value, n = {};
  S.ips.forEach((r) => { const c = String(r.country_code || "").toUpperCase() || "-"; n[c] = (n[c] || 0) + 1; });
  const sig = Object.keys(n).sort().map((k) => k + n[k]).join(",");
  if (sel._sig === sig) return;
  sel._sig = sig;
  const keys = Object.keys(n).filter((k) => k !== "-").sort((a, b) => n[b] - n[a] || a.localeCompare(b));
  sel.innerHTML = `<option value="">${esc(I18N.t("همه‌ی کشورها"))}</option>` + keys.map((k) => `<option value="${esc(k)}">${esc(k)} (${num(n[k])})</option>`).join("")
    + (n["-"] ? `<option value="-">${esc(I18N.t("بدون کشور"))} (${num(n["-"])})</option>` : "");
  sel.value = n[cur] || (cur === "-" && n["-"]) ? cur : "";
}
function renderIps() {
  ipCountryOpts();
  const unchecked = S.ips.filter((r) => !r.abuse_status).length, bu = $("#btnCheckUnchecked");
  bu.hidden = !unchecked; bu.textContent = `بررسی ${num(unchecked)} آدرس بررسی‌نشده در AbuseIPDB`;
  const cols = visibleCols(), allRows = filteredIps();
  S.ipShow = S.ipShow || IP_PAGE;
  const rows = allRows.slice(0, S.ipShow);   // ساختن هزاران ردیف یکجا رابط را کند می‌کرد
  const colDef = Object.fromEntries(IP_COLS.map((c) => [c[0], c[1]]));
  const allSel = rows.length && rows.every((r) => S.ipSel.has(r.ip));
  $("#ipTable").innerHTML = `<thead><tr><th class="chk nosort"><input type="checkbox" id="ipAll" ${allSel ? "checked" : ""}></th>${cols.map((c) =>
    `<th data-sort="${c}">${esc(colDef[c] || c)}${S.ipSort.k === c ? `<span class="arr">${S.ipSort.d > 0 ? "▲" : "▼"}</span>` : ""}</th>`).join("")}</tr></thead>
    <tbody>${rows.length ? rows.map((r) => `<tr class="${S.ipSel.has(r.ip) ? "sel" : ""}"><td class="chk"><input type="checkbox" class="ipChk" value="${esc(r.ip)}" ${S.ipSel.has(r.ip) ? "checked" : ""}></td>${cols.map((c) => cell(c, r)).join("")}</tr>`).join("")
      : `<tr><td colspan="${cols.length + 1}"><div class="empty">${S.ips.length ? "با این فیلتر موردی پیدا نشد." : "هنوز IPای بررسی نشده است. یک اجرا از صفحه‌ی «ابزارها» انجام دهید."}</div></td></tr>`}</tbody>`;
  if (allRows.length > rows.length) {
    $("#ipTable tbody").insertAdjacentHTML("beforeend", `<tr><td colspan="${cols.length + 1}" style="text-align:center"><button class="btn sm" id="ipMore">نمایش ${num(Math.min(IP_PAGE, allRows.length - rows.length))} ردیف بیشتر (${num(rows.length)} از ${num(allRows.length)})</button></td></tr>`);
    $("#ipMore").onclick = () => { S.ipShow += IP_PAGE; renderIps(); };
  }
  $("#ipCount").textContent = `${num(allRows.length)} مورد`;
  updateSelBar();
}
function updateSelBar() {
  $("#selBar").hidden = !S.ipSel.size;
  $("#selCount").textContent = `${num(S.ipSel.size)} مورد انتخاب شده`;
}
["#ipCountry", "#ipDays"].forEach((id) => $(id).addEventListener(id === "#ipDays" ? "input" : "change", () => { S.ipShow = 0; renderIps(); }));
$("#ipTable").addEventListener("click", (e) => {
  const th = e.target.closest("th[data-sort]");
  if (th) { const k = th.dataset.sort; S.ipSort = { k, d: S.ipSort.k === k ? -S.ipSort.d : 1 }; renderIps(); }
});
$("#ipTable").addEventListener("change", (e) => {
  if (e.target.id === "ipAll") { filteredIps().forEach((r) => (e.target.checked ? S.ipSel.add(r.ip) : S.ipSel.delete(r.ip))); renderIps(); }
});
/* انتخاب مثل ویندوز: کلیک روی تیک یا هر جای ردیف؛ Shift+کلیک همه‌ی ردیف‌های بین آخرین کلیک و این ردیف را انتخاب می‌کند */
let ipLastClick = null;
function ipSelectRange(ip, checked, shift) {
  const boxes = [...document.querySelectorAll("#ipTable .ipChk")];
  const idx = boxes.findIndex((x) => x.value === ip);
  if (idx < 0) return;
  let from = idx, to = idx;
  const li = shift && ipLastClick ? boxes.findIndex((x) => x.value === ipLastClick) : -1;
  if (li >= 0) { from = Math.min(li, idx); to = Math.max(li, idx); }
  for (let i = from; i <= to; i++) {
    const x = boxes[i]; x.checked = checked;
    checked ? S.ipSel.add(x.value) : S.ipSel.delete(x.value);
    x.closest("tr").classList.toggle("sel", checked);
  }
  ipLastClick = ip;
  const all = $("#ipAll"); if (all) all.checked = boxes.length && boxes.every((x) => x.checked);
  updateSelBar();
}
$("#ipTable").addEventListener("mousedown", (e) => {
  // Shift+کلیک روی ردیف نباید متن صفحه را انتخاب کند
  if (e.shiftKey && e.target.closest("tbody tr")) e.preventDefault();
});
$("#ipTable").addEventListener("click", (e) => {
  const tr = e.target.closest("tbody tr"); if (!tr) return;
  const box = tr.querySelector(".ipChk"); if (!box) return;
  if (e.target === box) { ipSelectRange(box.value, box.checked, e.shiftKey); return; }
  if (e.target.closest("a, button, .link, input, select")) return;
  if (!e.shiftKey && String(window.getSelection() || "").trim()) return;   // کاربر در حال انتخاب متن برای کپی است
  ipSelectRange(box.value, !box.checked, e.shiftKey);
});
$("#ipSearch").addEventListener("input", () => { S.ipShow = IP_PAGE; renderIps(); });
$("#ipFilter").addEventListener("click", (e) => {
  const b = e.target.closest("button"); if (!b) return;
  S.ipShow = IP_PAGE; S.ipFilter = b.dataset.f; $$("#ipFilter button").forEach((x) => x.classList.toggle("on", x === b)); renderIps();
});
$("#btnReloadIps").addEventListener("click", (e) => withSpin(e.currentTarget, loadIps));
$("#btnCols").addEventListener("click", (e) => {
  e.stopPropagation(); const m = $("#colsMenu"); const cur = visibleCols();
  m.innerHTML = IP_COLS.map(([k, t]) => `<label class="chk"><input type="checkbox" value="${k}" ${cur.includes(k) ? "checked" : ""} ${k === "ip" ? "disabled" : ""}>${esc(t)}</label>`).join("")
    + `<button class="btn sm ghost" id="colsReset" style="margin-top:6px">پیش‌فرض</button>`;
  m.hidden = !m.hidden;
});
$("#colsMenu").addEventListener("click", (e) => e.stopPropagation());
$("#colsMenu").addEventListener("change", async () => {
  const cols = ["ip", ...$$("#colsMenu input:checked").map((x) => x.value).filter((x) => x !== "ip")];
  const ordered = IP_COLS.map((c) => c[0]).filter((c) => cols.includes(c));
  S.settings.ui = S.settings.ui || {}; S.settings.ui.ip_columns = ordered; if (S.draft) { S.draft.ui = S.draft.ui || {}; S.draft.ui.ip_columns = ordered; }
  renderIps(); api("save_ui", "ip_columns", ordered);
});
document.addEventListener("click", (e) => {
  if (e.target.id === "colsReset") { S.settings.ui.ip_columns = null; if (S.draft) S.draft.ui.ip_columns = null; api("save_ui", "ip_columns", null); $("#colsMenu").hidden = true; renderIps(); return; }
  if (!e.target.closest(".colmenu")) $("#colsMenu").hidden = true;
});
$("#selBar").addEventListener("click", async (e) => {
  const b = e.target.closest("[data-act]"); if (!b) return;
  const act = b.dataset.act, ips = Array.from(S.ipSel);
  if (act === "clear") { S.ipSel.clear(); renderIps(); return; }
  if (act === "copy") { copyText(ips.join("\n"), `${num(ips.length)} IP`); return; }
  const list = `<div class="path ltr" style="max-height:180px;overflow:auto">${ips.map(esc).join("<br>")}</div>`;
  const cfg = {
    recheck: { title: "چک مجدد در AbuseIPDB", body: `<p>${ips.length}‏ IP دوباره بررسی می‌شوند (سهمیه مصرف می‌شود).</p>${list}`, confirm: "بررسی" },
    ban: { title: "بلاک در FortiGate", body: `<p>برای ${ips.length}‏ IP پیش‌نمایش ساخته می‌شود: رنج داخلی، Address و Banned بررسی می‌شوند و در صفحه‌ی «ابزارها» لیست نهایی را تأیید می‌کنید.</p>${list}`, confirm: "ساخت پیش‌نمایش" },
    ignore: { title: "افزودن به رنج‌های مستثنا", body: `<p>این IPها به‌صورت /32 به فهرست مستثنای FortiGate اضافه می‌شوند و از این پس بررسی و بلاک نمی‌شوند.</p>${list}`, confirm: "افزودن" },
  }[act];
  if (!(await confirm2(cfg))) return;
  const r = await api("ips_action", act, ips);
  if (!r.ok) return toast(r.error, "error");
  toast(r.message || "انجام شد", "ok"); S.ipSel.clear();
  if ((act === "ban" || act === "recheck") && r.run_id) { S.resultTab = act === "ban" ? "fw" : "summary"; go("run"); }
  else if (act === "recheck") loadIps();
  else { if (act === "ignore") await loadSettings(); loadIps(); }
});
/* بررسی همه‌ی IPهای بررسی‌نشده (از Splunk یا ورود داده) با همان پنجره‌ی تأیید «چک مجدد» */
$("#btnCheckUnchecked").addEventListener("click", () => {
  S.ipFilter = "unchecked";
  $$("#ipFilter button").forEach((b) => b.classList.toggle("on", b.dataset.f === "unchecked"));
  S.ipSel = new Set(S.ips.filter((r) => !r.abuse_status).map((r) => r.ip));
  renderIps();
  $("#selBar [data-act=recheck]").click();
});
/* ---------------------------------------------------------------- full sync */
$("#btnFullSync").addEventListener("click", async () => {
  if (!S.ips.length) await loadIps();
  const cand = S.ips.filter((r) => r.should_block), pend = cand.filter((r) => r.fw_pending);
  const ok = await confirm2({ title: "بررسی کامل با FortiGate", confirm: "شروع بررسی",
    body: `<p>همه‌ی IPهای دیتابیس که طبق قانون فعلی باید بلاک باشند (${num(cand.length)} IP مخرب) با لیست Banned و Address Objectهای FortiGate مقایسه می‌شوند.</p>
      <p class="hint">طبق اطلاعات دیتابیس حدود ${num(pend.length)} مورد هنوز بلاک نشده است؛ عدد دقیق را خود FortiGate مشخص می‌کند. قبل از هر بلاک، لیست نهایی را در صفحه‌ی «ابزارها» می‌بینید و تأیید می‌کنید. هیچ درخواستی به AbuseIPDB ارسال نمی‌شود.</p>` });
  if (!ok) return;
  const r = await api("start_full_sync");
  if (!r.ok) return toast(r.error, "error");
  toast("بررسی کامل شروع شد", "ok"); S.resultTab = "fw"; go("run");
});

/* ---------------------------------------------------------------- export */
$("#btnExport").addEventListener("click", async () => {
  if (!S.ips.length) await loadIps();
  const filt = filteredIps().map((r) => r.ip), sel = Array.from(S.ipSel);
  const st = { scope: "all", fmt: "script" };
  openModal({ title: "خروجی CSV", body: `
    <div class="field"><span>کدام IPها</span><div class="seg" id="exScope">
      <button data-v="all" class="on">همه (${num(S.ips.length)})</button>
      <button data-v="filter" ${filt.length === S.ips.length ? "disabled" : ""}>فیلتر و جستجوی فعلی (${num(filt.length)})</button>
      <button data-v="sel" ${sel.length ? "" : "disabled"}>انتخاب‌شده‌ها (${num(sel.length)})</button></div></div>
    <div class="field" style="margin-top:14px"><span>فرمت</span>
      <label class="chk"><input type="radio" name="exFmt" value="script" checked>فرمت اسکریپت (<span class="ltr">ipabuse_report.csv</span>، ۱۷ ستون)</label>
      <small class="hint" style="margin:0 0 8px;margin-inline-start:24px">قابل ورود دوباره در همین برنامه و سازگار با اسکریپت‌هایی که ipabuse_report.csv می‌خوانند.</small>
      <label class="chk"><input type="radio" name="exFmt" value="full">کامل (برای انتقال به سیستم دیگر)</label>
      <small class="hint" style="margin:0;margin-inline-start:24px">۱۷ ستون بالا + وضعیت FortiGate، منبع و داده‌ی Splunk. با «ورود از فایل» همه‌ی این‌ها برمی‌گردند.</small></div>`,
    foot: `<button class="btn ghost" data-x="0">انصراف</button><button class="btn primary" data-x="1">ذخیره‌ی فایل</button>`,
    onOpen: (m, close) => {
      $$("#exScope button", m).forEach((b) => (b.onclick = () => { if (b.disabled) return; st.scope = b.dataset.v; $$("#exScope button", m).forEach((x) => x.classList.toggle("on", x === b)); }));
      $$("[name=exFmt]", m).forEach((x) => (x.onchange = () => (st.fmt = x.value)));
      $("[data-x='0']", m).onclick = () => close();
      $("[data-x='1']", m).onclick = (e) => withSpin(e.currentTarget, async () => {
        const ips = st.scope === "all" ? null : st.scope === "filter" ? filt : sel;
        const r = await api("export_ips", ips, st.fmt);
        if (!r.ok) return toast(r.error, "error");
        if (r.cancelled) return;
        close(); toast(`${num(r.count)} IP ذخیره شد: ${r.path}`, "ok");
      });
    } });
});

/* ---------------------------------------------------------------- import / manual add */
$("#btnAddData").addEventListener("click", () => openAddData());
function openAddData(tab = "import") {
  const st = { path: "", tab };
  const body = () => `<div class="tabs" style="margin-bottom:14px"><button data-dt="import" class="${st.tab === "import" ? "on" : ""}">ورود از فایل CSV</button><button data-dt="manual" class="${st.tab === "manual" ? "on" : ""}">افزودن دستی</button></div>
    ${st.tab === "import" ? `<p class="hint">فایل <span class="ltr">ipabuse_report.csv</span> اسکریپت قبلی (یا <span class="ltr">abuse_report.csv</span> همین برنامه). ستون‌ها از روی سرستون شناخته می‌شوند؛ اگر یک IP چند بار آمده باشد، جدیدترین «Checked At» ملاک است.</p>
      <div class="row" style="margin:10px 0"><input type="text" class="ltr" id="impPath" placeholder="C:\\scripts\\ipabuse_report.csv" value="${esc(st.path)}"><button class="btn sm" id="impPick">انتخاب…</button><button class="btn sm" id="impPrev">پیش‌نمایش</button></div>
      <div id="impOut"></div>`
    : `<p class="hint">برای IPهایی که از قبل وضعیتشان را می‌دانید. با اعتبار نامحدود، این IPها دوباره در AbuseIPDB بررسی نمی‌شوند.</p>
      <div class="form-grid" style="margin-top:10px"><label class="field wide"><span>IPها (هر خط یک مورد یا جدا با ویرگول)</span><textarea class="ltr" id="manIps"></textarea></label>
      <label class="field"><span>وضعیت</span><select id="manSt"><option value="ABUSE">مخرب</option><option value="CLEAN">غیرمخرب</option></select></label>
      <label class="field"><span>کد کشور (اختیاری)</span><input type="text" class="ltr" id="manCc" placeholder="IR"></label>
      <label class="field wide"><span>توضیح (اختیاری)</span><input type="text" id="manNote"></label></div>
      <div class="form-foot"><button class="btn primary" id="manSave">افزودن</button></div>`}`;
  openModal({ title: "ورود و افزودن داده", wide: true, body: body(), onOpen: (m, close) => {
    const wire = () => {
      $$("[data-dt]", m).forEach((b) => (b.onclick = () => { st.tab = b.dataset.dt; $(".m-body", m).innerHTML = body(); wire(); }));
      if (st.tab === "import") {
        $("#impPath", m).oninput = (e) => (st.path = e.target.value);
        $("#impPick", m).onclick = async () => { const r = await api("pick_csv"); if (!r.ok) return toast(r.error, "warn"); if (r.path) { st.path = r.path; $("#impPath", m).value = r.path; } };
        $("#impPrev", m).onclick = (e) => withSpin(e.currentTarget, async () => {
          const r = await api("import_preview", st.path); const out = $("#impOut", m);
          if (!r.ok) { out.innerHTML = `<p class="test-res err">${esc(r.error)}</p>`; return; }
          const p = r.preview;
          out.innerHTML = `<div class="sum-grid">${[["", p.total, "IP یکتا در فایل"], ["ok", p.new, "جدید"], ["", p.update, "به‌روزرسانی (داده‌ی فایل جدیدتر)"], ["", p.older, "داده‌ی دیتابیس جدیدتر"], ["err", p.status.ABUSE, "مخرب"], ["ok", p.status.CLEAN, "غیرمخرب"], ["warn", p.status.ERROR, "خطا"]]
              .map(([k, v, t]) => `<div class="sum ${k}"><b>${num(v)}</b><span>${t}</span></div>`).join("")}</div>
            <p class="hint">ساختار ستون‌ها برای هر سطر جدا تشخیص داده شد${p.header ? "" : " (فایل سطر عنوان ندارد)"} — جداکننده: ${esc(p.delimiter)} — encoding: ${esc(p.encoding)}</p>
            ${p.merged || p.no_time || p.dup ? `<p class="hint">${p.merged ? `${num(p.merged)} سطر شامل دو رکورد چسبیده بود و جدا شد. ` : ""}${p.no_time ? `${num(p.no_time)} ردیف «Checked At» نداشت؛ زمان ذخیره‌ی فایل برایشان ثبت می‌شود. ` : ""}${p.dup ? `${num(p.dup)} ردیف تکراری بود (جدیدترین نگه داشته شد).` : ""}</p>` : ""}
            ${p.bad ? `<details class="hint warn"><summary style="cursor:pointer">${num(p.bad)} ردیف خوانده نشد</summary>${p.bad_rows.map(([n, m]) => `<div>سطر ${num(n)}: ${esc(m)}</div>`).join("")}</details>` : ""}
            <div class="table-wrap inner"><table class="grid"><thead><tr><th class="nosort">IP</th><th class="nosort">وضعیت</th><th class="nosort">امتیاز</th><th class="nosort">کشور</th><th class="nosort">ISP</th><th class="nosort">زمان بررسی</th></tr></thead><tbody>
            ${p.sample.map((x) => `<tr><td class="ltr">${esc(x.ip)}</td><td>${statusTag(x.abuse_status)}</td><td>${scoreHtml(x.score)}</td><td>${esc(x.country_code || "—")}</td><td class="wrap">${esc(x.isp || "—")}</td><td class="ltr">${esc(x.checked_at)}</td></tr>`).join("")}</tbody></table></div>
            <p class="hint">${p.total > 8 ? `نمایش ۸ ردیف از ${num(p.total)}. ` : ""}خطاها در اولین اجرا دوباره بررسی می‌شوند.</p>
            <div class="form-foot"><label class="chk"><input type="checkbox" id="impOver">داده‌ی فایل حتی اگر قدیمی‌تر است جایگزین شود</label>
            <button class="btn primary" id="impGo" style="margin-inline-start:auto">ورود ${num(p.new + p.update)} مورد</button></div>`;
          $("#impOver", m).onchange = (e) => ($("#impGo", m).textContent = `ورود ${num(e.target.checked ? p.total : p.new + p.update)} مورد`);
          $("#impGo", m).onclick = (ev) => withSpin(ev.currentTarget, async () => {
            const r2 = await api("import_commit", st.path, $("#impOver", m).checked);
            if (!r2.ok) return toast(r2.error, "error");
            toast(`${num(r2.result.written)} IP وارد شد${r2.result.skipped ? `، ${num(r2.result.skipped)} مورد رد شد` : ""}`, "ok");
            close(); loadIps();
          });
        });
      } else {
        $("#manSave", m).onclick = (e) => withSpin(e.currentTarget, async () => {
          const r = await api("add_manual", $("#manIps", m).value, $("#manSt", m).value, $("#manCc", m).value, $("#manNote", m).value);
          if (!r.ok) return toast(r.error, "error");
          toast(`${num(r.result.written)} IP اضافه شد`, "ok"); close(); loadIps();
        });
      }
    };
    wire();
  } });
}
async function showIp(ip) {
  const r = await api("ip_detail", ip);
  if (!r.ok) return toast(r.error, "error");
  const d = r.ip;
  const rows = [["وضعیت AbuseIPDB", statusTag(d.abuse_status), 1], ["امتیاز", scoreHtml(d.score), 1], ["تعداد گزارش", num(d.reports)], ["آخرین گزارش", d.last_reported],
    ["کشور", `${d.country || "—"} (${d.country_code || "—"})`], ["شهر", d.city], ["ISP", d.isp], ["نوع کاربری", d.usage_type], ["دامنه", d.domain], ["ASN", d.asn],
    ["Tor", d.is_tor], ["Whitelisted", d.is_whitelisted], ["دسته‌ها", d.categories], ["خطا", d.error],
    ["FortiGate", d.fw_status ? `${esc((FW[d.fw_status] || [0, d.fw_status])[1])} — ${esc(d.fw_detail || "")}` : "—", 1],
    ["تعداد حمله (Splunk)", num(d.attack_count)], ["Signatureها", d.signatures], ["پورت‌های مقصد", d.dest_ports],
    ["زمان بررسی", d.checked_at], ["اولین / آخرین مشاهده", `${d.first_seen || "—"} / ${d.last_seen || "—"}`], ["آخرین اجرا", d.last_run],
    ["روزهای بررسی در AbuseIPDB", d.seen_days ? `${num(d.seen_days)} روز مختلف` : "—"],
    ["بررسی تکمیلی", d.intel_status ? `${intelTag(d)} ${esc(d.intel_source || "")} — ${esc(d.intel_detail || "")} <span class="muted ltr">${esc(d.intel_at || "")}</span>` : "—", 1]];
  const hist = r.history.length ? `<h3 style="margin:16px 0 8px">تاریخچه</h3>${r.history.map((h) => `<div class="ev ${h.status === "ok" ? "ok" : h.status === "error" ? "error" : "warn"}"><time>${fmtDate(h.ts).slice(5)}</time><span class="dot"></span><span class="msg">${esc(h.kind)}: ${esc(h.detail)}</span></div>`).join("")}` : "";
  openModal({
    title: `⁦${ip}⁩`, wide: true,
    body: `<dl class="kv">${rows.map(([k, v, raw]) => `<dt>${k}</dt><dd>${raw ? v : esc(v === null || v === undefined || v === "" ? "—" : v)}</dd>`).join("")}</dl>${hist}`,
    foot: `<button class="btn ghost" data-copy="${esc(ip)}">کپی IP</button><button class="btn no-ro" data-a="recheck">چک مجدد</button><button class="btn no-ro" data-a="reviewed">بررسی شد</button><button class="btn warn no-ro" data-a="ban">بلاک…</button><button class="btn ghost" data-a="close">بستن</button>`,
    onOpen: (m, close) => $$("[data-a]", m).forEach((b) => (b.onclick = async () => {
      if (b.dataset.a === "close") return close();
      close(); S.ipSel = new Set([ip]); renderIps(); $("#selBar [data-act='" + b.dataset.a + "']").click();
    })),
  });
}

/* ================================================================ history */
async function loadHist(more = false) {
  // 1.37: صفحه‌بندی، فیلتر و جستجو سمت سرور (همه‌ی تاریخچه، نه فقط ۳۰۰۰ ردیف آخر)
  const off = more ? (S.hist || []).length : 0;
  const r = await api("list_history", S.histFilter || "all", $("#histSearch").value.trim(), $("#histRange").value, off, 200);
  if (!r.ok) return toast(r.error, "error");
  if (more) { S.hist = S.hist.concat(r.rows); S.runs = S.runs.concat(r.runs.filter((x) => !S.runs.some((y) => y.id === x.id))); }
  else { S.hist = r.rows; S.runs = r.runs; }
  S.histTotal = r.total; renderHist();
}
function isRunDir(p) {
  const r = (S.paths && S.paths.runs) || "";
  if (r) return String(p).startsWith(r);
  return /[\\/]runs[\\/]\d{8}_\d{6}_/.test(String(p));   // غیرادمین مسیرها را ندارد: الگوی پوشه‌ی اجرا
}
function renderHist() {
  const runDir = Object.fromEntries(S.runs.map((x) => [x.id, x.dir]));
  const KIND = { nettools: "ابزارهای شبکه", terminal: "ترمینال", transfer: "انتقال فایل", fgupdate: "به‌روزرسانی FortiGate", approval: "تأیید", dns: "DNS", ssh: "SSH", scan: "اسکن شبکه", intel: "بررسی تکمیلی", security: "امنیت", splunk: "Splunk", abuse: "AbuseIPDB", fortigate: "FortiGate", ban: "بلاک", ticket: "تیکت", redmine: "Redmine", import: "ورود داده", export: "خروجی" };
  const ST = { ok: ["ok", "موفق"], error: ["err", "خطا"], warn: ["warn", "با هشدار"], test: ["warn", "تست"] };
  const rows = S.hist || [], allN = S.histTotal || 0, more = allN > rows.length;
  $("#histTable").innerHTML = `<thead><tr>${["زمان", "کاربر", "نوع", "هدف", "وضعیت", "جزئیات", "اجرا", ""].map((t) => `<th class="nosort">${t}</th>`).join("")}</tr></thead><tbody>
    ${rows.length ? rows.map((h) => { const st = ST[h.status] || ["mute", h.status]; const dir = h.file || runDir[h.run_id];
      return `<tr><td class="ltr">${fmtDate(h.ts)}</td><td class="ltr">${esc(h.user || "—")}</td><td>${KIND[h.kind] || esc(h.kind)}</td><td class="bidi">${esc(h.target)}</td><td><span class="tag ${st[0]}">${st[1]}</span></td>
        <td class="wrap">${esc(h.detail)}</td><td class="ltr muted">${esc(h.run_id)}</td><td class="nowrap">${histViewable(h, dir) ? `<button class="btn sm ghost" data-hv="${h.id}" title="نمایش داده‌ها و گزارش">نمایش</button>` : ""}${dir && h.kind !== "terminal" && h.kind !== "transfer" && isAdmin() && !WEB && !isRunDir(dir) ? `<button class="btn sm ghost no-ro" data-open="${esc(dir)}" title="${isRunDir(dir) ? "خروجی فایل‌های اجرا" : "باز کردن پوشه"}"><svg><use href="#i-folder"/></svg></button>` : ""}</td></tr>`; }).join("")
      : `<tr><td colspan="8"><div class="empty">موردی در تاریخچه نیست.</div></td></tr>`}</tbody>`;
  if (more) {
    $("#histTable tbody").insertAdjacentHTML("beforeend", `<tr><td colspan="8" style="text-align:center"><button class="btn sm" id="histMore">نمایش ${num(Math.min(200, allN - rows.length))} ردیف بیشتر (${num(rows.length)} از ${num(allN)})</button></td></tr>`);
    $("#histMore").onclick = (e) => withSpin(e.currentTarget, () => loadHist(true));
  }
  $("#histCount").textContent = `${num(allN)} مورد`;
}
function histViewable(h, dir) {
  if (h.kind === "terminal" || h.kind === "transfer") return !!h.file && (isAdmin() || (S.state && S.state.me && String(h.user || "").toLowerCase() === S.state.me.username.toLowerCase()));
  if (h.kind === "ssh") return !!h.file;
  const run = h.run_id && (S.runs || []).find((x) => x.id === h.run_id);
  return (!!dir && isRunDir(dir)) || !!(run && run.has_log);      // 1.37: گزارش اجرا در پایگاه داده
}
document.addEventListener("click", (e) => { const b = e.target.closest("[data-hv]"); if (b) histView(Number(b.dataset.hv)); });
let _histT = null;
$("#histSearch").addEventListener("input", () => { clearTimeout(_histT); _histT = setTimeout(() => loadHist(), 350); });
$("#histRange").addEventListener("change", () => loadHist());
$("#histFilter").addEventListener("click", (e) => { const b = e.target.closest("button"); if (!b) return; S.histFilter = b.dataset.f; $$("#histFilter button").forEach((x) => x.classList.toggle("on", x === b)); loadHist(); });
$("#btnReloadHist").addEventListener("click", (e) => withSpin(e.currentTarget, loadHist));
$("#btnRunsFolder").addEventListener("click", () => api("export_logs").then(exportDone));
document.addEventListener("click", (e) => { const b = e.target.closest("[data-open]"); if (b) api("open_folder", b.dataset.open).then(exportDone); });

/* ================================================================ settings page */
const AUTH_OPTS = {
  splunk: [["bearer", "توکن (Bearer)"], ["basic", "نام کاربری و رمز"]],
  abuseipdb: [["header", "کلید API در هدر"]],
  fortigate: [["bearer", "توکن (Bearer)"], ["header", "کلید در هدر سفارشی"]],
  redmine: [["header", "کلید API در هدر"], ["basic", "نام کاربری و رمز"]],
};
const ADDR_PH = { splunk: "https://10.0.0.10", abuseipdb: "https://api.abuseipdb.com", fortigate: "https://10.0.0.1", redmine: "https://redmine.example.local" };
const PORT_PH = { splunk: "مثلاً 8089", abuseipdb: "خالی = پیش‌فرض پروتکل", fortigate: "مثلاً 443", redmine: "خالی = پیش‌فرض پروتکل" };
function inp(path, label, { type = "text", ltr = false, ph = "", wide = false, hint = "" } = {}) {
  const v = getPath(S.draft, path);
  return `<label class="field ${wide ? "wide" : ""}"><span>${label}</span><input type="${type === "num" ? "number" : "text"}" ${type === "num" ? "data-type='num'" : ""} class="${ltr ? "ltr" : ""}" data-path="${path}" value="${esc(v ?? "")}" placeholder="${esc(ph)}">${hint ? `<small class="hint">${hint}</small>` : ""}</label>`;
}
function secretInp(c, key, label) {
  const has = S.draft[c][`has_${key}`], cur = S.draft[c][key];
  return `<label class="field"><span>${label}</span><div class="row"><input type="password" class="ltr" data-path="${c}.${key}" value="${cur && cur !== "__clear__" ? esc(cur) : ""}"
    placeholder="${cur === "__clear__" ? "پس از ذخیره پاک می‌شود" : has ? "ذخیره شده — برای تغییر مقدار جدید وارد کنید" : "وارد نشده"}" autocomplete="off">
    ${has ? `<button class="btn sm ghost" data-clear="${c}.${key}" title="پاک کردن مقدار ذخیره‌شده">پاک</button>` : ""}</div></label>`;
}
function extraKeysInp(d) {
  // کلیدهای اضافه‌ی AbuseIPDB: هرگز نمایش داده نمی‌شوند؛ فقط تعداد. مقدار تازه همه‌ی فهرست قبلی را جایگزین می‌کند
  const n = d.extra_tokens_count || 0, cur = d.extra_tokens, clr = cur === "__clear__";
  return `<label class="field wide"><span>کلیدهای API اضافه — هر کلید در یک خط، به ترتیب استفاده</span>
    <div class="row" style="align-items:flex-start"><textarea class="ltr" data-path="abuseipdb.extra_tokens" style="min-height:70px;-webkit-text-security:disc" autocomplete="off" spellcheck="false"
      placeholder="${clr ? "پس از ذخیره پاک می‌شود" : n ? `${num(n)} کلید ذخیره شده — برای جایگزینی همه، فهرست تازه را وارد کنید` : "اختیاری"}">${cur && !clr ? esc(cur) : ""}</textarea>
    ${d.has_extra_tokens ? `<button class="btn sm ghost" data-clear="abuseipdb.extra_tokens" title="پاک کردن کلیدهای اضافه">پاک</button>` : ""}</div>
    <small class="hint">اول کلید بالا استفاده می‌شود؛ وقتی سهمیه‌ی روزانه‌اش تمام شد، همان IP با کلید بعدی همین فهرست بررسی می‌شود و به همین ترتیب. کلیدی که سهمیه‌اش تمام شده تا ریست روزانه کنار گذاشته می‌شود.</small></label>`;
}
function pairsEditor(path, h1, h2, ltr2 = false) {
  const list = getPath(S.draft, path) || [];
  return `<div class="pairs" data-pairs="${path}">
    <div class="pair muted" style="font-size:12.5px"><span>${h1}</span><span>${h2}</span><span></span></div>
    ${list.map(([a, b], i) => `<div class="pair"><input type="text" class="ltr" data-pi="${i}" data-pj="0" value="${esc(a)}"><textarea class="${ltr2 ? "ltr" : "ltr"}" data-pi="${i}" data-pj="1">${esc(b)}</textarea><button class="iconbtn" data-pdel="${i}" title="حذف"><svg><use href="#i-x"/></svg></button></div>`).join("")}
    <div><button class="btn sm" data-padd="${path}">افزودن ردیف</button></div></div>`;
}
function connSection(c) {
  const d = S.draft[c], at = d.auth_type, k = /^fortigate\d+$/.test(c) ? "fortigate" : c;
  return `<div class="form"><h3>اتصال ${k === "fortigate" ? `<span>${esc(fgDraftName(c))}</span>` : CONN_TITLE[c]}</h3><div class="form-grid">
    ${k === "fortigate" ? inp(`${c}.name`, "نام دستگاه", { ph: c === "fortigate" ? "FortiGate 1" : "" }) : ""}
    ${inp(`${c}.address`, "آدرس", { ltr: true, ph: ADDR_PH[k], hint: c === "abuseipdb" ? "دامنه کافی است (https://api.abuseipdb.com)؛ مسیر /api/v2/check خودکار اضافه می‌شود" : "با http:// یا https://؛ اگر نباشد https فرض می‌شود" })}
    ${inp(`${c}.port`, "پورت", { ltr: true, ph: PORT_PH[k] })}
    <label class="field"><span>روش احراز هویت</span><select data-path="${c}.auth_type" data-rerender="settings">${AUTH_OPTS[k].map(([v, t]) => `<option value="${v}" ${v === at ? "selected" : ""}>${t}</option>`).join("")}</select></label>
    ${at === "basic" ? inp(`${c}.username`, "نام کاربری", { ltr: true }) + secretInp(c, "password", "رمز عبور") : ""}
    ${at === "header" ? inp(`${c}.header_name`, "نام هدر", { ltr: true }) : ""}
    ${at !== "basic" ? secretInp(c, "token", c === "abuseipdb" || c === "redmine" ? (c === "abuseipdb" ? "کلید API (اول)" : "کلید API") : "توکن API") : ""}
    ${c === "abuseipdb" ? extraKeysInp(d) : ""}
    <div class="field"><span>&nbsp;</span>${sw(`${c}.verify_ssl`, d.verify_ssl, "بررسی گواهی SSL", "data-rerender='settings'")}</div>
    ${d.verify_ssl ? "" : pinRow(c, d)}
  </div><div class="form-foot"><button class="btn" data-test="${c}">تست اتصال (بدون ذخیره)</button><span class="test-res" id="tr-${c}"></span>
    ${c === "abuseipdb" ? `<span class="hint">تست یک درخواست از سهمیه‌ی روزانه مصرف می‌کند.</span>` : ""}</div></div>`;
}
/* ---------- Redmine: فیلدهای هر Tracker ---------- */
const RM_VARS = [["static", "مقدار ثابت"], ["src_ips", "IPهای مبدأ"], ["dest_ips", "IPهای مقصد"], ["dest_ports", "پورت‌های مقصد"], ["detected_date", "تاریخ تشخیص"]];
const RM_TEXTY = ["string", "text", "link", "int", "float"];
function rmLegacy(R, name) {
  const st = (R.static_fields || []).find(([n]) => String(n).trim().toLowerCase() === name.toLowerCase());
  if (st) return { src: "static", value: st[1] };
  const dy = (R.dynamic_fields || []).find(([n]) => String(n).trim().toLowerCase() === name.toLowerCase());
  if (dy && RM_VARS.some(([k]) => k === dy[1])) return { src: dy[1], value: "" };
  return null;
}
/* ---------------------------------------------------------------- Redmine: فیلدها و قالب‌های تیکت
 * هر قالب: نام، عنوان (با متغیر)، Tracker، اولویت، دسته، واگذاری، متن، مقدار فیلدهای همان Tracker و پیوست‌ها.
 * فرم فیلدها از فیلدهای واقعی خوانده‌شده از Redmine ساخته می‌شود؛ با تغییر Redmine، «به‌روزرسانی فیلدها». */
function rmMeta(R) { return R && R.meta && R.meta.project === R.project ? R.meta : null; }
function rmTracker(M, name) { return M ? M.trackers.find((x) => x.name.toLowerCase() === String(name || "").trim().toLowerCase()) : null; }
function rmMetaSection(R, M) {
  const loadBtn = `<button class="btn" id="btnRmMeta">${M ? "به‌روزرسانی فیلدها از Redmine…" : "خواندن Trackerها و فیلدها از Redmine…"}</button>`;
  return `<div class="sec"><h3>Trackerها و فیلدها</h3>
    ${M ? `<p class="hint">خوانده‌شده در ${fmtDate(M.fetched_at)} با کاربر <span class="ltr">${esc(M.by)}</span>: ${num(M.trackers.length)} Tracker${M.project_fields_known ? "" : " — نسخه‌ی Redmine فهرست فیلدهای پروژه را نمی‌دهد؛ همه‌ی فیلدهای Tracker نمایش داده شده‌اند"}. هر وقت فیلدها یا گزینه‌هایشان در Redmine عوض شد، دوباره بخوانید؛ قالب‌ها خودشان با فیلدهای تازه هماهنگ می‌شوند.</p>`
      : `<p class="hint">با خواندن اطلاعات از Redmine، فرم هر قالب از فیلدهای واقعی همان Tracker (اجباری بودن، پیش‌فرض و گزینه‌ها) ساخته می‌شود. یک بار کلید API ادمین لازم است و ذخیره نمی‌شود.</p>`}
    <div class="form-foot">${loadBtn}${M ? "" : `<button class="btn ghost" id="btnDiscover">کشف Tracker و فیلدها (روش قدیمی)</button>`}</div></div>`;
}
function rmMetaModal(after) {
  return openModal({ title: "خواندن فیلدها از Redmine",
    body: `<p class="hint">خواندن اجباری بودن فیلدها و Trackerهایشان (custom_fields.json) فقط با کلید API <b>ادمین</b> ممکن است. اگر کلید ذخیره‌شده ادمین است، این خانه را خالی بگذارید؛ وگرنه کلید ادمین را وارد کنید. این کلید فقط برای همین خواندن استفاده و <b>ذخیره نمی‌شود</b>؛ ساخت تیکت با کلید ذخیره‌شده (کاربر عادی) انجام می‌شود. اگر فیلدها در Redmine تغییر کرد، دوباره بخوانید.</p>
      <div class="form-grid"><label class="field"><span>کلید API ادمین (اختیاری)</span><input type="password" id="rmAdminKey" autocomplete="off" class="ltr"></label></div>`,
    foot: `<button class="btn ghost" data-x="0">انصراف</button><button class="btn primary" data-x="1">خواندن</button>`,
    onOpen: (m, close) => {
      $("[data-x='0']", m).onclick = () => close();
      $("[data-x='1']", m).onclick = (e) => withSpin(e.currentTarget, async () => {
        const r = await api("redmine_load_meta", draftPatch().redmine, $("#rmAdminKey", m).value);
        if (!r.ok) return toast(r.error, "error");
        S.settings.redmine.meta = r.settings.redmine.meta; S.draft.redmine.meta = r.settings.redmine.meta;
        close(); toast(r.message, "ok"); after && after();
      });
    } });
}
function wireRmFields(body) {
  const btn = $("#btnRmMeta", body);
  if (btn) btn.onclick = () => rmMetaModal(renderSettings);
}
/* بررسی یک قالب با فیلدهای فعلی Redmine؛ خروجی: فهرست هشدارها */
function rmTplCheck(t, M) {
  const out = [];
  if (!String(t.tracker || "").trim()) return ["Tracker انتخاب نشده است"];
  if (!M) return out;
  const tr = rmTracker(M, t.tracker);
  if (!tr) return [`Tracker «${t.tracker}» در فیلدهای خوانده‌شده نیست`];
  const fields = M.fields[String(tr.id)] || [], tv = (t.tracker_values || {})[String(tr.id)] || {};
  fields.forEach((f) => {
    if (f.format === "date") return;
    const ent = tv[String(f.id)] || { src: "static", value: f.default ?? "" };   // مثل سرور: مقدار تنظیم‌نشده = پیش‌فرض Redmine
    const v = ent.src === "static" ? ent.value : ent.src;
    const empty = v === undefined || v === null || v === "" || (Array.isArray(v) && !v.length);
    if (f.required && empty) out.push(`فیلد اجباری «${f.name}» مقدار ندارد`);
    if (f.options && ent.src === "static" && !empty) {
      const ok = new Set(f.options.map((o) => String(o.value)));
      const bad = [].concat(v).map(String).filter((x) => !ok.has(x));
      if (bad.length) out.push(`مقدار «${bad.join("، ")}» دیگر جزو گزینه‌های «${f.name}» نیست`);
    }
  });
  const gone = Object.keys(tv).filter((id) => !fields.some((f) => String(f.id) === id));
  if (gone.length) out.push(`${num(gone.length)} فیلد ذخیره‌شده دیگر در این Tracker نیست (نادیده گرفته می‌شود)`);
  return out;
}
function rmTplFields(t, M) {
  if (!M) return `<p class="hint">فیلدهای Redmine هنوز خوانده نشده‌اند؛ تا آن موقع «روش قدیمی» (تنظیمات ← Redmine) استفاده می‌شود.</p>`;
  const tr = rmTracker(M, t.tracker);
  if (!tr) return `<p class="hint warn">یک Tracker انتخاب کنید.</p>`;
  const fields = M.fields[String(tr.id)] || [], tv = (t.tracker_values || {})[String(tr.id)] || {};
  if (!fields.length) return `<p class="hint">Tracker «${esc(tr.name)}» فیلد سفارشی ندارد.</p>`;
  const rows = fields.map((f) => {
    const ent = tv[String(f.id)] || rmLegacy(S.draft.redmine, f.name) || { src: "static", value: f.default ?? "" };
    const texty = !f.options && RM_TEXTY.includes(f.format) && f.format !== "date";
    const srcSel = texty ? `<select class="tfSrc" data-f="${esc(f.id)}">${RM_VARS.map(([k, l]) => `<option value="${k}" ${ent.src === k ? "selected" : ""}>${l}</option>`).join("")}</select>` : "";
    let ctl, stale = "";
    if (f.options) {
      const cur = [].concat(ent.value ?? []).map(String), ok = new Set(f.options.map((o) => String(o.value)));
      const lost = cur.filter((x) => x && !ok.has(x));
      if (lost.length) stale = `<div class="hint warn">«${esc(lost.join("، "))}» دیگر در Redmine نیست؛ دوباره انتخاب کنید</div>`;
      ctl = `<select class="tfVal" data-f="${esc(f.id)}" ${f.multiple ? "multiple size='4'" : ""}>${f.multiple ? "" : `<option value="">—</option>`}${f.options.map((o) => `<option value="${esc(o.value)}" ${cur.includes(String(o.value)) ? "selected" : ""}>${esc(o.label)}</option>`).join("")}</select>`;
    } else if (f.format === "date") ctl = `<span class="muted">تاریخ روز ساخت تیکت (خودکار)</span>`;
    else ctl = `<input type="${["int", "float"].includes(f.format) ? "number" : "text"}" class="tfVal" data-f="${esc(f.id)}" value="${esc(ent.src === "static" ? ent.value ?? "" : "")}" ${ent.src !== "static" ? "hidden" : ""}>`;
    return `<tr><td><b>${esc(f.name)}</b>${f.required ? ` <span class="tag err">اجباری</span>` : ""}<div class="muted ltr" style="font-size:11.5px">${esc(f.format)}${f.multiple ? " · multiple" : ""}${f.default !== "" && f.default != null ? ` · default: ${esc(f.default)}` : ""}</div></td>
      <td>${srcSel}</td><td>${ctl}${stale}</td></tr>`;
  }).join("");
  return `<div class="table-wrap inner"><table class="grid"><thead><tr><th class="nosort">فیلد</th><th class="nosort">منبع مقدار</th><th class="nosort">مقدار</th></tr></thead><tbody>${rows}</tbody></table></div>`;
}
function rmTplCollect(m, t, M) {
  const tr = rmTracker(M, t.tracker); if (!tr) return;
  t.tracker_values = t.tracker_values || {};
  const prev = t.tracker_values[String(tr.id)] || {}, tv = {};
  (M.fields[String(tr.id)] || []).forEach((f) => {
    if (f.format === "date") return;
    const src = $(`.tfSrc[data-f="${f.id}"]`, m), val = $(`.tfVal[data-f="${f.id}"]`, m);
    if (!val && !src) { if (prev[String(f.id)]) tv[String(f.id)] = prev[String(f.id)]; return; }
    const s2 = src ? src.value : "static";
    const v = val ? (val.multiple ? Array.from(val.selectedOptions).map((o) => o.value) : val.value) : "";
    tv[String(f.id)] = { src: s2, value: s2 === "static" ? v : "" };
  });
  t.tracker_values[String(tr.id)] = tv;   // فیلدهایی که دیگر در Tracker نیستند حذف می‌شوند
}
const TPL_ATT = [["attach_splunk_csv", "CSV اسپلانک"], ["attach_abuse_report", "گزارش AbuseIPDB"], ["attach_fortigate_report", "گزارش FortiGate"]];
async function rmTplSaveAll(list, def) {
  const r = await api("save_settings", { redmine: { templates: list, default_template: def } });
  if (!r.ok) { toast(r.error, "error"); return false; }
  S.settings = r.settings;
  S.draft.redmine.templates = JSON.parse(JSON.stringify(r.settings.redmine.templates));
  S.draft.redmine.default_template = r.settings.redmine.default_template;
  return true;
}
function renderTplTab(body) {
  const R = S.draft.redmine, M = rmMeta(R), tl = R.templates || [];
  body.innerHTML = `<div class="form"><div class="row" style="justify-content:space-between;align-items:flex-start;gap:12px">
      <div><h3 style="margin:0 0 4px">قالب‌های تیکت Redmine</h3><p class="hint" style="margin:0">هر قالب عنوان، Tracker، اولویت، دسته، متن توضیحات، مقدار فیلدها و پیوست‌های خودش را دارد. قالب هر تیکت را در ابزار Redmine صفحه‌ی «ابزارها» (و کارهای ذخیره‌شده) یا در پیش‌نمایش تأیید انتخاب کنید.</p></div>
      <button class="btn primary no-ro" id="tplAdd">+ قالب تازه</button></div>
    ${M ? `<p class="hint">فیلدهای Redmine: خوانده‌شده در ${fmtDate(M.fetched_at)} <button class="btn sm ghost" id="tplMeta">به‌روزرسانی فیلدها از Redmine…</button></p>`
      : `<p class="hint warn">Trackerها و فیلدها هنوز از Redmine خوانده نشده‌اند؛ برای فرم پویای فیلدها <button class="btn sm" id="tplMeta">خواندن از Redmine…</button> (پروژه و اتصال در «تنظیمات ← Redmine»).</p>`}
    <div class="tpl-cards">${tl.map((t, i) => {
      const warn = rmTplCheck(t, M), def = t.id === R.default_template;
      return `<div class="tpl-card ${warn.length ? "has-warn" : ""}"><div class="row" style="justify-content:space-between;gap:8px"><b>${esc(t.name)}</b>${def ? `<span class="tag ok">پیش‌فرض</span>` : ""}</div>
        <div class="muted" style="font-size:12.5px">Tracker: <span class="ltr">${esc(t.tracker || "—")}</span>${t.priority ? ` · ${esc(t.priority)}` : ""}${t.category ? ` · ${esc(t.category)}` : ""}</div>
        <div class="wrap" style="margin:6px 0">${esc(t.subject || "—")}</div>
        ${warn.map((w) => `<div class="hint warn">⚠ <span>${esc(w)}</span></div>`).join("")}
        <div class="row" style="gap:6px;flex-wrap:wrap;margin-top:8px"><button class="btn sm no-ro" data-te="${i}">ویرایش</button><button class="btn sm ghost no-ro" data-tc="${i}">کپی</button>
          ${def ? "" : `<button class="btn sm ghost no-ro" data-td="${i}">پیش‌فرض شود</button><button class="btn sm danger-ghost no-ro" data-tx="${i}">حذف</button>`}</div></div>`;
    }).join("")}</div>
    <div class="form-grid" style="margin-top:14px"><label class="field"><span>فرمت تاریخ ({date})</span><input type="text" class="ltr" data-path="redmine.date_format" value="${esc(R.date_format)}"></label></div>
    <p class="hint">فرمت تاریخ و قالب‌بندی لیست IPها برای همه‌ی قالب‌ها مشترک است (تنظیمات ← Redmine). برای ذخیره‌ی فرمت تاریخ «ذخیره» را بزنید؛ قالب‌ها همان لحظه ذخیره می‌شوند.</p></div>`;
  $("#tplMeta").onclick = () => rmMetaModal(() => renderAuto());
  $("#tplAdd").onclick = () => rmTplEdit(null);
  $$("[data-te]", body).forEach((b) => (b.onclick = () => rmTplEdit(Number(b.dataset.te))));
  $$("[data-tc]", body).forEach((b) => (b.onclick = () => { const s = JSON.parse(JSON.stringify(tl[Number(b.dataset.tc)])); s.id = ""; s.name = s.name + " (کپی)"; rmTplEdit(null, s); }));
  $$("[data-td]", body).forEach((b) => (b.onclick = async () => { if (await rmTplSaveAll(tl, tl[Number(b.dataset.td)].id)) { toast("قالب پیش‌فرض عوض شد", "ok"); renderAuto(); } }));
  $$("[data-tx]", body).forEach((b) => (b.onclick = async () => {
    const t = tl[Number(b.dataset.tx)];
    if (!(await confirm2({ title: "حذف قالب", body: `<p>قالب «${esc(t.name)}» حذف شود؟ کارهایی که این قالب را دارند با قالب پیش‌فرض اجرا می‌شوند.</p>`, confirm: "حذف", danger: true }))) return;
    if (await rmTplSaveAll(tl.filter((x) => x !== t), R.default_template)) { toast("حذف شد", "ok"); renderAuto(); }
  }));
}
async function rmTplEdit(idx, seed) {
  const R = S.draft.redmine, M = rmMeta(R), tl = R.templates || [];
  const t = JSON.parse(JSON.stringify(seed || (idx === null ? { id: "", name: "", subject: R.subject || "گزارش IPهای مخرب", tracker: "", priority: "", category: "", assign_to_me: true,
    description_template: (tl[0] || {}).description_template || "", tracker_values: {}, attach_splunk_csv: true, attach_abuse_report: true, attach_fortigate_report: true } : tl[idx])));
  const sel = (id, list, cur, empty) => `<select id="${id}">${empty !== null ? `<option value="">${empty}</option>` : ""}${(cur && !list.includes(cur) ? [cur, ...list] : list).map((x) => `<option value="${esc(x)}" ${x === cur ? "selected" : ""}>${esc(x)}</option>`).join("")}</select>`;
  let lastTxt = "teDesc";
  await openModal({ title: idx === null ? "قالب تیکت تازه" : `ویرایش قالب «${t.name}»`, wide: true,
    body: `<div class="form-grid">
      <label class="field"><span>نام قالب</span><input type="text" id="teName" value="${esc(t.name)}" autofocus></label>
      <label class="field wide"><span>عنوان تیکت (متغیرها مجازند، مثل {date})</span><input type="text" id="teSubj" value="${esc(t.subject || "")}"></label>
      <label class="field"><span>Tracker</span>${M ? sel("teTr", M.trackers.map((x) => x.name), t.tracker, "— انتخاب کنید —") : `<input type="text" class="ltr" id="teTr" value="${esc(t.tracker || "")}">`}</label>
      <label class="field"><span>اولویت</span>${M ? sel("tePr", M.priorities, t.priority, "پیش‌فرض Redmine") : `<input type="text" id="tePr" value="${esc(t.priority || "")}">`}</label>
      <label class="field"><span>دسته</span>${M ? sel("teCa", M.categories, t.category, "بدون دسته") : `<input type="text" id="teCa" value="${esc(t.category || "")}">`}</label>
      <div class="field"><span>&nbsp;</span><label class="chk"><input type="checkbox" id="teMe" ${t.assign_to_me ? "checked" : ""}>واگذاری به خودم</label></div></div>
      <div class="sec"><h3>پیوست‌ها</h3><div class="row" style="gap:18px;flex-wrap:wrap">${TPL_ATT.map(([k, l]) => `<label class="chk"><input type="checkbox" class="teAt" data-k="${k}" ${t[k] !== false ? "checked" : ""}>${l}</label>`).join("")}</div></div>
      <div class="sec"><h3>فیلدهای Tracker</h3><div id="teFields">${rmTplFields(t, M)}</div></div>
      <div class="sec"><h3>متن توضیحات</h3><p class="hint">متغیرها هنگام ساخت تیکت جایگزین می‌شوند؛ با کلیک، در عنوان یا متن (هر کدام آخر انتخاب شده) درج می‌شوند.</p>
        <div class="varbtns">${Object.entries(S.tplVars || {}).map(([k, x]) => `<button data-var="${k}" title="${esc(x)}">${esc(x)}</button>`).join("")}</div>
        <div class="tpl-grid"><label class="field"><span>قالب</span><textarea id="teDesc">${esc(t.description_template || "")}</textarea></label>
        <div class="field"><span>پیش‌نمایش با داده‌ی نمونه</span><div class="pv-desc" data-no-i18n id="tePrev" style="max-height:none;min-height:300px"></div></div></div></div>`,
    foot: `<button class="btn ghost" data-r="0">انصراف</button><button class="btn primary" data-r="1">ذخیره‌ی قالب</button>`,
    onOpen: (m, close) => {
      const ta = $("#teDesc", m); let tm;
      const prev = () => { clearTimeout(tm); tm = setTimeout(async () => { const sj = $("#teSubj", m); if (!sj) return; const r = await api("preview_template", sj.value + "\n────\n" + ta.value); const el = $("#tePrev", m); if (el) el.textContent = r.ok ? r.text : r.error; }, 200); };
      ta.addEventListener("input", prev); $("#teSubj", m).addEventListener("input", prev); prev();
      ["teSubj", "teDesc"].forEach((id) => $("#" + id, m).addEventListener("focus", () => (lastTxt = id)));
      $$("[data-var]", m).forEach((b) => (b.onclick = () => {
        const el = $("#" + lastTxt, m), ins = `{${b.dataset.var}}`, s = el.selectionStart ?? el.value.length;
        el.value = el.value.slice(0, s) + ins + el.value.slice(el.selectionEnd ?? s); el.focus(); el.selectionStart = el.selectionEnd = s + ins.length;
        el.dispatchEvent(new Event("input"));
      }));
      const wireF = () => $$(".tfSrc", m).forEach((s) => (s.onchange = () => { const v = $(`.tfVal[data-f="${s.dataset.f}"]`, m); if (v) v.hidden = s.value !== "static"; }));
      wireF();
      const tr = $("#teTr", m);
      if (M) tr.onchange = () => { rmTplCollect(m, t, M); t.tracker = tr.value; $("#teFields", m).innerHTML = rmTplFields(t, M); wireF(); };
      $("[data-r='0']", m).onclick = () => close(null);
      $("[data-r='1']", m).onclick = (e) => withSpin(e.currentTarget, async () => {
        if (M) rmTplCollect(m, t, M);
        Object.assign(t, { name: $("#teName", m).value.trim(), subject: $("#teSubj", m).value.trim(), tracker: tr.value.trim(), priority: $("#tePr", m).value.trim(),
          category: $("#teCa", m).value.trim(), assign_to_me: $("#teMe", m).checked, description_template: ta.value });
        $$(".teAt", m).forEach((c) => (t[c.dataset.k] = c.checked));
        if (!t.name) return toast("نام قالب را وارد کنید.", "warn");
        if (!t.tracker) return toast("Tracker را انتخاب کنید.", "warn");
        const list = JSON.parse(JSON.stringify(tl));
        if (idx === null) list.push(t); else list[idx] = t;
        if (!(await rmTplSaveAll(list, R.default_template))) return;
        const w = rmTplCheck(S.draft.redmine.templates.find((x) => x.name === t.name) || t, M);
        toast(w.length ? `قالب ذخیره شد؛ ${w[0]}` : "قالب ذخیره شد", w.length ? "warn" : "ok");
        close(true);
      });
    } });
  renderAuto();
}
function fmtFp(fp) { return String(fp || "").toUpperCase().match(/.{1,2}/g)?.join(":") || ""; }
function pinRow(c, d) {
  const p = d.cert_pin;
  return `<div class="field wide"><span>&nbsp;</span>${sw(`${c}.pin_cert`, d.pin_cert, "پین گواهی (اختیاری)", "data-rerender='settings'")}
    <small class="hint">وقتی «بررسی گواهی SSL» خاموش است، با روشن کردن این گزینه اثر انگشت گواهی سرور با «تست اتصال» به شما نشان داده می‌شود و فقط پس از تأیید شما ذخیره می‌شود؛ اگر بعداً گواهی دیگری برگردد، اتصال رد می‌شود.</small>
    ${d.pin_cert ? (p && p.sha256 ? `<div class="row" style="gap:8px;margin-top:6px;flex-wrap:wrap"><span class="muted">گواهی پین‌شده برای <span class="ltr">${esc(p.host)}</span>:</span>
      <code class="ltr" style="font-size:11.5px;word-break:break-all">${esc(fmtFp(p.sha256))}</code>
      <button class="btn sm ghost" data-unpin="${c}">فراموش کردن گواهی</button></div>`
      : `<small class="hint warn">هنوز گواهی‌ای پین نشده؛ «تست اتصال» را بزنید و اثر انگشت را تأیید کنید. تا آن موقع اتصال برقرار نمی‌شود.</small>`) : ""}</div>`;
}
/* ---------------------------------------------------------------- 1.28: چند FortiGate و تسک‌ها (سناریوها) */
function fgDraftConns() { return ["fortigate", ...Object.keys(S.draft || {}).filter((x) => /^fortigate\d+$/.test(x)).sort((a, b) => Number(a.slice(9)) - Number(b.slice(9)))]; }
function fgDraftName(c) { const d = (S.draft || {})[c] || {}; return String(d.name || "").trim() || (c === "fortigate" ? "FortiGate 1" : `FortiGate ${c.slice(9)}`); }
function fgTaskCard(t, si) {
  const pre = `fg_scenarios.${si}`;
  return `<details class="sec form" ${S.fgOpen === si ? "open" : ""} data-scn="${si}"><summary style="cursor:pointer"><b data-no-i18n>${esc(t.name || "")}</b>${t.note ? ` <span class="muted" data-no-i18n>— ${esc(t.note)}</span>` : ""}</summary>
    <div class="form-grid" style="margin-top:10px">${inp(`${pre}.name`, "نام تسک")}${inp(`${pre}.note`, "توضیح")}
      <label class="field"><span>اگر یک کار خطا داد</span><select data-path="${pre}.on_error">${[["stop", "بقیه ارسال نشود"], ["continue", "بقیه ادامه پیدا کند"]].map(([v, l]) => `<option value="${v}" ${(t.on_error || "stop") === v ? "selected" : ""}>${l}</option>`).join("")}</select></label>
      ${inp(`${pre}.timeout`, "سقف زمان plan (ثانیه)", { type: "num", hint: "بین ۱۰ و ۶۰۰" })}
      <label class="field wide"><span>کد پایتون — تابع plan(fg, rows, ctx)</span><textarea class="ltr code-edit fg-code" data-path="${pre}.code" spellcheck="false" style="min-height:340px;font-family:monospace;white-space:pre;tab-size:4">${esc(t.code || "")}</textarea></label></div>
    <div class="form-foot"><button class="btn sm" data-scdry="${si}">اجرای آزمایشی plan…</button><span style="flex:1"></span>
      <button class="btn sm ghost" data-scdup="${si}">کپی این تسک</button><button class="btn sm danger-ghost" data-scrm="${si}">حذف تسک</button></div></details>`;
}
const FG_API_HELP = `rows: فهرست ردیف‌های جدول ورودی (dict با نام ستون‌ها) — ctx: device، vdom، run، columns، test، ignore_networks
fg.get(path, params) ← JSON پاسخ یا None (404) — fg.results(path) ← فقط results
fg.post(path, body, note, row) / fg.put(...) / fg.delete(path, note, row) ← فقط پیشنهاد کار؛ ارسال بعد از تأیید
q(name) ← نام برای مسیر URL — log(...) یا print(...) ← گزارش اجرا — raise TaskError("…") ← توقف با پیام`;
const FG_API_HELP_EN = `rows: rows of the input table (dicts keyed by column name) — ctx: device, vdom, run, columns, test, ignore_networks
fg.get(path, params) → response JSON or None (404) — fg.results(path) → results only
fg.post(path, body, note, row) / fg.put(...) / fg.delete(path, note, row) → only proposes an action; sent after approval
q(name) → name for a URL path — log(...) or print(...) → run log — raise TaskError("…") → stop with a message`;
async function fgDryRun(t) {
  const devs = fgDevices();
  openModal({ title: `اجرای آزمایشی — ${t.name || ""}`, wide: true,
    body: `<p class="hint">plan روی دستگاه انتخاب‌شده اجرا می‌شود: فقط خواندن (GET)؛ هیچ کاری ارسال نمی‌شود. کد فعلی فرم (حتی ذخیره‌نشده) اجرا می‌شود.</p>
      <div class="form-grid"><label class="field"><span>دستگاه</span><select id="dryDev">${devs.map((d) => `<option value="${esc(d.conn)}">${esc(d.name)}</option>`).join("")}</select></label>
      <label class="field wide"><span>ردیف‌های نمونه — خط اول نام ستون‌ها</span><textarea class="ltr" id="dryRows" style="min-height:110px" spellcheck="false">${esc(S.fgDryRows || "src,name,group\n45.1.2.3,AKRP_45.1.2.3,Blocked-IPs")}</textarea></label></div>
      <div id="dryOut"></div>`,
    foot: `<button class="btn ghost" data-x="0">بستن</button><button class="btn primary" id="dryGo">اجرا</button>`,
    onOpen: (m, close) => {
      $("[data-x='0']", m).onclick = () => close();
      $("#dryGo", m).onclick = (e) => withSpin(e.currentTarget, async () => {
        S.fgDryRows = $("#dryRows", m).value;
        const r = await api("fg_task_dryrun", { name: t.name, code: t.code, timeout: t.timeout, on_error: t.on_error }, $("#dryDev", m).value, S.fgDryRows);
        const out = $("#dryOut", m);
        if (!r.ok) { out.innerHTML = `<p class="hint err">خطا</p><div class="codebox ltr" data-no-i18n style="white-space:pre-wrap;max-height:300px;overflow:auto">${esc(r.error)}</div>`; return; }
        out.innerHTML = `<p class="hint">${I18N.t(`${num(r.rows)} ردیف، ${num(r.total)} کار پیشنهادی، ${r.seconds} ثانیه`)}</p>
          ${r.logs.length ? `<details open><summary class="muted">پیام‌های کد</summary><div class="codebox ltr" data-no-i18n style="white-space:pre-wrap;max-height:180px;overflow:auto">${esc(r.logs.join("\n"))}</div></details>` : ""}
          ${fgActionsTable(r.actions, null)}`;
      });
    } });
}
function fgActionsTable(acts, sel, res) {
  if (!acts.length) return `<div class="empty">کاری پیشنهاد نشد.</div>`;
  const RES = { done: ["ok", "انجام شد"], failed: ["err", "ناموفق"], skipped: ["mute", "ارسال نشد"], rejected: ["mute", "رد شد"], test: ["warn", "تست"] };
  return `<div class="table-wrap inner"><table class="grid"><thead><tr>${sel ? `<th class="chk nosort"><input type="checkbox" id="apAll" title="همه‌ی ردیف‌های فیلترشده"></th>` : ""}<th>#</th><th>متد</th><th>مسیر API</th><th>توضیح</th><th>مقادیر ردیف</th>${res ? "<th>نتیجه</th>" : ""}</tr></thead><tbody>
    ${acts.map((a) => `<tr>${sel ? `<td class="chk"><input type="checkbox" class="apAct" value="${a.i}" ${sel.has(a.i) ? "checked" : ""}></td>` : ""}<td class="num">${num(a.i + 1)}</td>
      <td class="ltr"><span class="tag ${a.method === "DELETE" ? "err" : a.method === "PUT" ? "info" : "warn"}">${esc(a.method)}</span></td>
      <td class="ltr wrap" title="${esc(a.body ? JSON.stringify(a.body) : "")}"><span class="tech">${esc(a.path)}</span>${a.body ? `<details><summary class="muted">body</summary><div class="codebox ltr" data-no-i18n style="white-space:pre;max-height:160px;overflow:auto">${esc(JSON.stringify(a.body, null, 2))}</div></details>` : ""}</td>
      <td class="wrap fnote" data-no-i18n>${esc(a.note || "")}</td><td class="ltr wrap tech">${esc(Object.entries(a.row || {}).slice(0, 4).map(([k, v]) => `${k}=${v}`).join(" · "))}</td>
      ${res ? `<td>${a.result ? `<span class="tag ${(RES[a.result] || ["mute"])[0]}">${(RES[a.result] || ["", a.result])[1]}</span>${a.detail && a.result !== "done" ? `<div class="muted wrap" style="font-size:12px">${esc(a.detail)}</div>` : ""}` : "—"}</td>` : ""}</tr>`).join("")}</tbody></table></div>`;
}
function renderFgSettings(body, D) {
  const conns = fgDraftConns();
  if (!conns.includes(S.fgDev)) S.fgDev = "fortigate";
  const c = S.fgDev, d = D[c];
  D.fg_scenarios = D.fg_scenarios || [];
  body.innerHTML = `<div class="form"><h3>دستگاه‌ها</h3><div class="row" style="gap:6px;flex-wrap:wrap" id="fgDevBar">
      ${conns.map((x) => `<button class="btn sm ${x === c ? "primary" : "ghost"}" data-fgdev="${x}"><span>${esc(fgDraftName(x))}</span></button>`).join("")}
      ${conns.length < 8 ? `<button class="btn sm" id="fgAdd">افزودن دستگاه…</button>` : ""}</div>
      <p class="hint">هر دستگاه اتصال، توکن و پین گواهی جدا دارد. در ابزار FortiGate برای هر گام، دستگاه و تسک انتخاب می‌شود. وضعیت بلاک فهرست «آدرس‌ها» فقط با دستگاه اول (تسک پیش‌فرض) هماهنگ است؛ بقیه در گزارش اجرا و تاریخچه ثبت می‌شوند.</p></div>
    ${connSection(c)}
    <div class="form"><h3>بلاک (تسک پیش‌فرض) — <span>${esc(fgDraftName(c))}</span></h3><div class="form-grid">
      ${inp(`${c}.vdom`, "VDOM", { ltr: true })}${inp(`${c}.ban_expiry`, "expiry بلاک (۰ = بدون انقضا)", { type: "num" })}
      <div class="field wide">${sw(`${c}.convert_auto_bans`, d.convert_auto_bans !== false, "تبدیل بلاک‌های خودکار به Administrative")}<small class="hint">IPی که باید بلاک شود ولی در Banned با منبعی جز Administrative (IPS، Application Control، DoS، ...) یا با انقضا هست، با تأیید شما از Banned پاک و بلافاصله با همین expiry دوباره به‌صورت Administrative بلاک می‌شود؛ بعد نتیجه دوباره از FortiGate خوانده و بررسی می‌شود.</small></div>
      ${inp(`${c}.address_count`, "تعداد Address در هر صفحه", { type: "num" })}
      ${inp(`${c}.timeout`, "Timeout (ثانیه)", { type: "num" })}
      <div class="field"><span>&nbsp;</span>${sw(`${c}.check_json_status`, d.check_json_status, "موفقیت فقط وقتی status=success باشد")}</div></div>
      ${c !== "fortigate" ? `<div class="form-foot"><button class="btn sm danger-ghost" id="fgDel">حذف این دستگاه…</button></div>` : ""}</div>
    <div class="form"><h3>مشترک همه‌ی دستگاه‌ها</h3><div class="form-grid">
      ${inp("fortigate.max_cidr_expand", "سقف بسط CIDR در ورودی دستی", { type: "num" })}
      <label class="field wide"><span>رنج‌های مستثنا (هرگز بلاک نمی‌شوند) — هر مورد در یک خط؛ متن بعد از # توضیح است</span><textarea class="ltr" data-type="lines" data-path="fortigate.ignore_networks" style="min-height:200px">${esc((D.fortigate.ignore_networks || []).join("\n"))}</textarea>
      <small class="hint">IPهای داخل این رنج‌ها نه در AbuseIPDB بررسی می‌شوند نه بلاک. خطوط شروع‌شده با # نادیده گرفته می‌شوند.</small></label></div></div>
    <div class="form"><h3>تسک‌ها</h3>
      <p class="hint">تسک = کد پایتون با تابع plan(fg, rows, ctx). کد فقط می‌خواند و «کار» پیشنهاد می‌کند؛ برنامه فهرست کارها را نشان می‌دهد و فقط کارهای تأییدشده را به همان دستگاه می‌فرستد (حالت تست: هیچ). در کارهای خودکار، با تیک «FortiGate بدون تأیید» بدون پنجره‌ی تأیید اجرا می‌شود.</p>
      <p class="hint warn">${WEB ? "کد پایتون روی همین سرور اجرا می‌شود و قابل محصورسازی کامل نیست؛ فقط ادمین تسک می‌سازد و هر تغییر کد با diff در تاریخچه ثبت می‌شود. کدی را که نمی‌شناسید اجرا نکنید."
        : "کد پایتون روی همین کامپیوتر اجرا می‌شود و قابل محصورسازی کامل نیست؛ فقط ادمین تسک می‌سازد و هر تغییر کد با diff در تاریخچه ثبت می‌شود. کدی را که نمی‌شناسید اجرا نکنید."}</p>
      <details class="sec"><summary style="cursor:pointer"><b>راهنمای fg، rows و ctx</b></summary><div class="codebox ltr" data-no-i18n style="white-space:pre-wrap">${esc(I18N.lang === "en" ? FG_API_HELP_EN : FG_API_HELP)}</div></details>
      <details class="sec"><summary style="cursor:pointer"><b>پیش‌فرض: Ban IP (لیست Banned)</b> <span class="muted">— داخلی، فقط خواندنی</span></summary><ol class="steps-ol">${FG_DEFAULT_DESC.map((x) => `<li>${esc(x)}</li>`).join("")}</ol></details>
      ${D.fg_scenarios.map(fgTaskCard).join("")}
      <div class="form-foot"><button class="btn" id="scNew">افزودن تسک…</button><span class="hint">تغییرها با «ذخیره‌ی تنظیمات» ذخیره می‌شوند.</span></div></div>`;
  $$("[data-fgdev]", body).forEach((b) => (b.onclick = () => { S.fgDev = b.dataset.fgdev; renderSettings(); }));
  const add = $("#fgAdd", body);
  if (add) add.onclick = async () => {
    const r = await api("fg_device_add", ""); if (!r.ok) return toast(r.error, "error");
    S.settings[r.conn] = r.settings[r.conn]; S.draft[r.conn] = clone(r.settings[r.conn]); S.fgDev = r.conn;
    toast("دستگاه اضافه شد؛ اتصالش را تنظیم و ذخیره کنید", "ok"); renderSettings(); refreshState();
  };
  const del = $("#fgDel", body);
  if (del) del.onclick = async () => {
    const ok = await confirm2({ title: "حذف دستگاه FortiGate", danger: true, confirm: "حذف",
      body: `<p>دستگاه «${esc(fgDraftName(c))}» با توکن و پین گواهی‌اش حذف می‌شود. گام‌های کارهای ذخیره‌شده که این دستگاه را دارند تا ویرایش اجرا نمی‌شوند.</p>` });
    if (!ok) return;
    const r = await api("fg_device_delete", c); if (!r.ok) return toast(r.error, "error");
    delete S.settings[c]; delete S.draft[c]; S.fgDev = "fortigate"; toast("حذف شد", "ok"); renderSettings(); refreshState();
  };
  const scs = D.fg_scenarios;
  const keepOpen = (si) => { S.fgOpen = si; renderSettings(); };
  $("#scNew", body).onclick = async () => {
    const r = await api("fg_task_templates"); if (!r.ok) return toast(r.error, "error");
    openModal({ title: "تسک تازه", body: `<p class="hint">از یک قالب شروع کنید؛ بعد کد را مطابق نیاز خودتان تغییر دهید.</p>
      <div class="chks" style="display:grid;gap:8px">${r.templates.map((t, i) => `<button class="btn" data-tpl="${i}" style="justify-content:flex-start;text-align:start"><b>${esc(t.name)}</b>${t.note ? ` <span class="muted">— ${esc(t.note)}</span>` : ""}</button>`).join("")}</div>`,
      foot: `<button class="btn ghost" data-x="0">انصراف</button>`,
      onOpen: (m, close) => {
        $("[data-x='0']", m).onclick = () => close();
        $$("[data-tpl]", m).forEach((b) => (b.onclick = () => {
          const t = r.templates[Number(b.dataset.tpl)];
          let nm = t.name, k = 2; while (scs.some((x) => x.name === nm)) nm = `${t.name} ${k++}`;
          scs.push({ name: nm, note: t.note || "", code: t.code, on_error: "stop", timeout: 120 }); close(); keepOpen(scs.length - 1);
        }));
      } });
  };
  $$("[data-scdry]", body).forEach((b) => (b.onclick = () => fgDryRun(scs[Number(b.dataset.scdry)])));
  $$("[data-scdup]", body).forEach((b) => (b.onclick = () => { const si = Number(b.dataset.scdup); const cp = clone(scs[si]); delete cp.id; cp.name += " (کپی)"; scs.push(cp); keepOpen(scs.length - 1); }));
  $$("[data-scrm]", body).forEach((b) => (b.onclick = async () => {
    const si = Number(b.dataset.scrm);
    if (!(await confirm2({ title: "حذف تسک", danger: true, confirm: "حذف", body: `<p>تسک «${esc(scs[si].name)}» پس از «ذخیره‌ی تنظیمات» حذف می‌شود. گام‌هایی که آن را انتخاب کرده‌اند تا ویرایش اجرا نمی‌شوند.</p>` }))) return;
    scs.splice(si, 1); S.fgOpen = -1; renderSettings();
  }));
  $$(".fg-code", body).forEach((ta) => ta.addEventListener("keydown", (e) => {     // Tab = چهار فاصله
    if (e.key !== "Tab" || e.shiftKey || e.ctrlKey || e.altKey) return;
    e.preventDefault(); const a = ta.selectionStart, b2 = ta.selectionEnd;
    ta.value = ta.value.slice(0, a) + "    " + ta.value.slice(b2); ta.selectionStart = ta.selectionEnd = a + 4;
    ta.dispatchEvent(new Event("input"));
  }));
  $$("details[data-scn]", body).forEach((x) => x.addEventListener("toggle", () => { if (x.open) S.fgOpen = Number(x.dataset.scn); }));
}
function renderSettings() {
  if (!S.draft) return;
  $$("#setTabs button").forEach((b) => b.classList.toggle("on", b.dataset.t === S.setTab));
  const body = $("#setBody"), D = S.draft, t = S.setTab;
  if (t === "security") { renderSecurityTab(body); return; }
  if (t === "users") { renderUsersTab(body); return; }
  if (t === "database") { renderDatabaseTab(body); return; }
  if (t === "notify") {
    const N = D.notify || {}, ev = N.events || {};
    const EV = [["approval", "اجرا منتظر تأیید است"], ["run_error", "مرحله‌ای از اجرا خطا داد"], ["ban_failed", "بلاک در FortiGate ناموفق بود"],
      ["ssh_failed", "اجرای SSH روی دستگاهی ناموفق بود"], ["backup_failed", "پشتیبان‌گیری کانفیگ ناموفق بود"], ["config_changed", "کانفیگ دستگاهی تغییر کرد"], ["abuse_quota", "سهمیه‌ی روزانه‌ی AbuseIPDB تمام شد و IPهایی بررسی نشدند"], ["scan_new", "اسکن شبکه هاست یا پورت تازه پیدا کرد"], ["mon_down", "هدف مانیتورینگ قطع شد"], ["mon_up", "هدف مانیتورینگ دوباره وصل شد"], ["mon_alarm", "هشدار آستانه‌ی SNMP (CPU، حافظه، دما، پورت، OID دستی) یا راه‌اندازی دوباره‌ی دستگاه"], ["mon_cert", "گواهی HTTPS هدف مانیتورینگ نزدیک انقضاست"], ["security_update", "به‌روزرسانی و امنیت: نسخه‌ی تازه‌ی برنامه یا آسیب‌پذیری تازه در کتابخانه‌ها"], ["abuse_repeat", "IP غیرمخربی بارها تکرار شد و نیاز به بررسی مجدد دارد"], ["health", "سلامت سرور: فضای دیسک کم، RAM یا CPU برنامه بالا"], ["dev_event", "رخداد بحرانی دستگاه (Trap یا Syslog)"]];
    body.innerHTML = `<div class="form"><div class="row" style="justify-content:space-between">${sw("notify.enabled", N.enabled, "<b>ارسال اعلان با ایمیل</b>")}</div>
      <h3 style="margin:16px 0 10px">سرور ایمیل (SMTP)</h3><div class="form-grid">
        ${inp("notify.host", "سرور", { ltr: true, ph: "mail.example.com" })}${inp("notify.port", "پورت", { type: "num" })}
        <label class="field"><span>امنیت اتصال</span><select data-path="notify.security">
          ${[["starttls", "STARTTLS (معمولاً پورت 587)"], ["ssl", "SSL/TLS (معمولاً پورت 465)"], ["none", "بدون رمزنگاری — relay داخلی (معمولاً پورت 25)"]].map(([v, t2]) => `<option value="${v}" ${N.security === v ? "selected" : ""}>${t2}</option>`).join("")}</select></label>
        <div class="field"><span>&nbsp;</span>${sw("notify.verify_ssl", N.verify_ssl !== false, "بررسی گواهی SSL")}</div>
        ${inp("notify.username", "یوزر (خالی = بدون احراز هویت)", { ltr: true })}${secretInp("notify", "password", "پسورد")}
        ${inp("notify.from_addr", "نشانی فرستنده", { ltr: true, ph: "autokrp@example.com" })}
        <label class="field"><span>گیرنده‌ها (هر خط یک نشانی)</span><textarea class="ltr" data-type="lines" data-path="notify.to" style="min-height:70px">${esc((N.to || []).join("\n"))}</textarea></label>
      </div>
      <div class="form-foot"><button class="btn" id="btnMailTest">ارسال ایمیل آزمایشی (بدون ذخیره)</button><span class="test-res" id="trMail"></span></div></div>
    <div class="form"><h3>برای کدام رویدادها ایمیل ارسال شود</h3>
      <div class="row" style="flex-direction:column;align-items:flex-start;gap:10px;margin-top:8px">${EV.map(([k, t2]) => `<label class="chk"><input type="checkbox" data-type="bool" data-path="notify.events.${k}" ${ev[k] ? "checked" : ""}>${t2}</label>`).join("")}</div>
      <div class="form-grid" style="margin-top:14px">${inp("notify.throttle_minutes", "جمع کردن رویدادهای تکراری (دقیقه)", { type: "num", hint: "اولین رخداد هر نوع فوری ارسال می‌شود؛ رخدادهای بعدی همان نوع در این بازه در یک ایمیل خلاصه می‌شوند." })}</div>
      <p class="hint">متن ایمیل به زبان فعلی برنامه است و هیچ توکن یا پسوردی در آن نوشته نمی‌شود. خطای ارسال ایمیل کار اصلی را متوقف نمی‌کند و فقط در رویدادها ثبت می‌شود.</p></div>`;
    bindInputs(body);
    $("#btnMailTest").onclick = (e) => withSpin(e.currentTarget, async () => {
      const out = $("#trMail"); out.className = "test-res"; out.textContent = "";
      const r = await api("notify_test", draftPatch().notify);
      if (!r.ok) { out.className = "test-res err"; out.textContent = r.error; return; }
      out.className = "test-res " + (r.sent ? "ok" : "err");
      out.innerHTML = `<div>${esc(r.message)}</div>${(r.trace || []).length ? `<div class="term" data-no-i18n style="margin-top:8px;max-height:260px;font-size:12px">${r.trace.map((s) => `<div dir="auto" style="color:${s.ok ? "inherit" : "var(--err, #e5484d)"}">${s.ok ? "✓" : "✗"} ${esc(s.text)}</div>`).join("")}</div>` : ""}`;
    });
    return;
  }
  if (t === "general") {
    body.innerHTML = brandingSection() + `<div class="form"><h3>رفتار</h3><div class="form-grid">
        <div class="field wide">${sw("test_mode", D.test_mode, "<b>حالت تست</b>")}<small class="hint">در حالت تست، Splunk و AbuseIPDB و خواندن از FortiGate واقعی انجام می‌شوند ولی بلاک و ساخت تیکت فقط در فایل JSON پوشه‌ی اجرا نوشته می‌شوند.</small></div>
        ${inp("poll_minutes", "فاصله‌ی بررسی وضعیت اتصال‌ها (دقیقه)", { type: "num" })}
        ${inp("max_age_hours", "حداکثر قدمت اجرای زمان‌بندی‌شده (ساعت)", { type: "num", hint: "اگر برنامه بسته بوده و نوبت اجرا بیش از این عقب افتاده باشد، آن نوبت رد می‌شود." })}
      </div></div>
      <div class="form"><h3>بخش‌ها و ابزارهای فعال برنامه</h3><p class="hint">خاموش = برای همه‌ی کاربران پنهان و <b>واقعاً متوقف</b> (کار پس‌زمینه‌اش هم قطع می‌شود). زیرمجموعه‌ها جدا خاموش می‌شوند؛ بخش اصلی خاموش = همه‌ی زیرمجموعه‌ها خاموش. داده‌ها و تنظیمات پاک نمی‌شوند.</p>
        <div class="row" style="gap:6px;margin:8px 0;flex-wrap:wrap"><button class="btn sm ghost" id="teAll">همه روشن</button><button class="btn sm" id="teMonOnly" title="همه‌ی بخش‌ها جز مانیتورینگ خاموش">فقط مانیتورینگ</button>
          <button class="btn sm" id="teDevOnly">فقط ارتباط با دستگاه‌ها</button><button class="btn sm" id="teSecOnly">فقط امنیت</button></div>
        ${teTreeHtml(D)}
        <p class="hint">هر کاربر هم می‌تواند ابزارهایی را که لازم ندارد فقط برای خودش پنهان کند: دکمه‌ی «ابزارهای من» پایین منو. دسترسی هر کاربر یا گروه: تنظیمات ← کاربران ← دسترسی‌ها (چیزی را متوقف نمی‌کند).</p></div>
      <div class="form"><h3>ظاهر و برند</h3><div class="form-grid">
        ${inp("branding.app_name", "نام برنامه")}${inp("branding.subtitle", "زیرعنوان")}${inp("branding.logo_text", "حرف لوگو، وقتی تصویر نیست (حداکثر ۲ نویسه)")}
        <label class="field"><span>پوسته</span><select data-path="theme"><option value="dark" ${D.theme !== "light" ? "selected" : ""}>تیره</option><option value="light" ${D.theme === "light" ? "selected" : ""}>روشن</option></select></label>
      </div></div>
      <div class="form"><h3>پوشه‌ی داده</h3>
        ${[["data", "داده و تنظیمات"], ["runs", "فایل‌های هر اجرا"], ["logs", "لاگ برنامه"]].map(([k, l]) => `<div class="row" style="margin-bottom:8px"><span style="width:130px" class="muted">${l}</span><div class="path ltr" style="flex:1">${esc(S.paths[k])}</div>${WEB ? "" : `<button class="btn sm" data-open="${esc(S.paths[k])}"><svg><use href="#i-folder"/></svg>باز کردن</button>`}</div>`).join("")}
        <p class="hint">اسرار (توکن و رمز) در فایل رمزنگاری‌شده نگهداری می‌شوند؛ «تنظیمات ← امنیت».</p></div>`;
    const preset = (keep) => {
      TE_TREE.forEach(([k, , kids]) => { setPath(D, "tools_enabled." + teKey(k), keep ? keep.includes(k) : true); kids.forEach(([c]) => setPath(D, "tools_enabled." + teKey(c), true)); });
      renderSettings();
      toast(I18N.t("تغییر کرد؛ برای اعمال «ذخیره» را بزنید."), "info"); };
    $("#teMonOnly", body).onclick = () => preset(["monitor"]);
    $("#teAll", body).onclick = () => preset(null);
    $("#teDevOnly", body).onclick = () => preset(["dev"]);
    $("#teSecOnly", body).onclick = () => preset(["sec"]);
  } else if (t === "splunk") {
    renderSplunkTab(body, D);
    bindInputs(body);
    return;
  } else if (t === "abuseipdb") {
    body.innerHTML = connSection("abuseipdb") + `<div class="form"><h3>بررسی</h3><div class="form-grid">
      ${inp("abuseipdb.threshold", "آستانه‌ی مخرب بودن (امتیاز بیشتر از)", { type: "num", hint: "۰ یعنی هر امتیاز بالای صفر مخرب است (رفتار اسکریپت اصلی)." })}
      ${inp("abuseipdb.max_age_days", "maxAgeInDays", { type: "num" })}
      <label class="field"><span>اعتبار نتیجه‌ی قبلی</span><select data-path="abuseipdb.cache_mode" data-rerender="settings">
        ${[["forever", "نامحدود — IP بررسی‌شده دوباره چک نشود"], ["days", "محدود به چند روز"], ["never", "هر بار دوباره بررسی شود"]].map(([v, t]) => `<option value="${v}" ${D.abuseipdb.cache_mode === v ? "selected" : ""}>${t}</option>`).join("")}</select>
        <small class="hint">خطاها همیشه دوباره بررسی می‌شوند. «چک مجدد» در صفحه‌ی آدرس‌ها همیشه آنلاین بررسی می‌کند. نتیجه‌ی کش‌شده هم به FortiGate می‌رود.</small></label>
      ${D.abuseipdb.cache_mode === "days" ? inp("abuseipdb.cache_days", "تعداد روز اعتبار", { type: "num" }) : ""}
      ${inp("abuseipdb.delay", "فاصله بین درخواست‌ها (ثانیه)", { type: "num" })}${inp("abuseipdb.retries", "تعداد تلاش مجدد", { type: "num" })}
      ${inp("abuseipdb.retry_delay", "زمان اولیه‌ی تلاش مجدد (ثانیه)", { type: "num" })}${inp("abuseipdb.timeout", "Timeout (ثانیه)", { type: "num" })}
      ${inp("abuseipdb.repeat_days", "هشدار تکرار IP غیرمخرب پس از (روز)", { type: "num", hint: "۰ = خاموش. IP غیرمخرب و بلاک‌نشده‌ای که در این تعداد روزِ مختلف دوباره به AbuseIPDB رسیده (آنلاین یا از کش) هشدار و ایمیل می‌دهد؛ بعد از آن هر همین تعداد روز دیگر. فهرست: آمار ← IPهای تکراری." })}
      ${inp("abuseipdb.purge_clean_days", "حذف IPهای غیرمخرب از فهرست پس از (روز)", { type: "num", hint: "۰ = خاموش. روزی یک بار، IPهای غیرمخربی که آخرین بررسی‌شان قدیمی‌تر است حذف می‌شوند تا اگر دوباره دیده شدند، از نو بررسی شوند. ثبت‌های دستی و IPهای بلاک‌شده حذف نمی‌شوند؛ صفحه‌ی آمار دست نمی‌خورد." })}
      <div class="field wide">${sw("abuseipdb.skip_whitelisted", D.abuseipdb.skip_whitelisted, "IPهای Whitelisted در AbuseIPDB بلاک نشوند")}</div></div></div>
    <div class="form"><h3>خروجی بی‌رمز آخرین اسکن</h3><div class="form-grid">
      <div class="field wide">${sw("abuseipdb.export_enabled", D.abuseipdb.export_enabled, "بعد از هر اسکن، نتیجه در یک پوشه ذخیره شود", "data-rerender='settings'")}
        <small class="hint">علاوه بر «آدرس‌ها» (مثل قبل)، نتیجه‌ی همان اسکن در فایل abuse_latest.csv این پوشه نوشته و هر بار بازنویسی می‌شود تا برنامه یا اسکریپت دیگری از آن استفاده کند. ستون‌ها مثل گزارش AbuseIPDB به‌علاوه‌ی شماره‌ی اجرا.</small></div>
      ${D.abuseipdb.export_enabled ? `<label class="field wide"><span>${WEB ? "پوشه روی سرور" : "پوشه"}</span><div class="row"><input type="text" class="ltr" data-path="abuseipdb.export_dir" value="${esc(D.abuseipdb.export_dir || "")}" placeholder="D:\\SOC\\abuse">${WEB ? "" : `<button class="btn sm" id="abExpPick">انتخاب…</button>`}</div></label>
        <p class="hint warn wide">این فایل رمز ندارد و هر کس به آن پوشه دسترسی داشته باشد آن را می‌خواند (فهرست IPها، امتیاز، ISP و …). پوشه را با دسترسی محدود انتخاب کنید.</p>` : ""}</div></div>
`;
    const ep = $("#abExpPick", body);
    if (ep) ep.onclick = async () => { const x = await api("pick_folder"); if (!x.ok) return toast(x.error, "warn"); if (x.path) { setPath(S.draft, "abuseipdb.export_dir", x.path); renderSettings(); } };
  } else if (t === "dns") {
    if (!D.dns) D.dns = { server: "", timeout: 5, max_records: 3, concurrency: 20 };
    body.innerHTML = `<div class="form"><h3>ابزار DNS</h3><div class="form-grid">
      ${inp("dns.server", "سرور DNS (خالی = سرور سیستم)", { ltr: true, ph: "10.0.0.53", hint: "چند سرور را با ویرگول جدا کنید." })}
      ${inp("dns.timeout", "Timeout هر درخواست (ثانیه)", { type: "num" })}
      ${inp("dns.max_records", "حداکثر رکورد از هر نوع (ستون‌های _1، _2 ...)", { type: "num", hint: "بین ۱ و ۱۰" })}
      ${inp("dns.concurrency", "درخواست هم‌زمان پیش‌فرض", { type: "num", hint: "بین ۱ و ۱۰۰؛ در هر ابزار DNS قابل تغییر است." })}</div>
      <p class="hint">رنج‌های مستثنای FortiGate در DNS اعمال نمی‌شوند. حداکثر ۴۰۹۶ ورودی در هر اجرا.</p></div>`;
  } else if (t === "monitor") {
    if (!D.health) D.health = { enabled: true, disk_min_gb: 10, disk_min_pct: 10, ram_max_mb: 2048, cpu_max_pct: 90 };
    if (!D.monitor) D.monitor = { repeat: 3, sound_on_up: true, quiet: { enabled: false, from: "23:00", to: "07:00" }, close_action: "ask", show_window: true, server_sound: false };
    const M = D.monitor; if (!M.quiet) M.quiet = { enabled: false, from: "23:00", to: "07:00" };
    if (M.keep_detail_days === undefined) M.keep_detail_days = 0;
    if (M.keep_hour_days === undefined) M.keep_hour_days = 0;
    const snd = (w, title) => `<div class="field"><span>${title}</span><div class="row" style="gap:6px;flex-wrap:wrap">
        <span class="tag ${M["sound_" + w] ? "info" : "mute"}">${M["sound_" + w] ? "سفارشی (" + esc(String(M["sound_" + w]).replace("custom:", "").toUpperCase()) + ")" : "پیش‌فرض"}</span>
        <button class="btn sm" data-snd-play="${w}">پخش</button><button class="btn sm" data-snd-up="${w}">انتخاب فایل…</button>
        ${M["sound_" + w] ? `<button class="btn sm ghost" data-snd-reset="${w}">برگشت به پیش‌فرض</button>` : ""}<input type="file" accept=".mp3,.wav,.ogg,audio/*" hidden data-snd-file="${w}"></div></div>`;
    body.innerHTML = `<div class="form"><h3>صدای هشدار</h3><div class="form-grid">
      ${snd("down", "صدای قطعی")}${snd("up", "صدای وصل شدن دوباره")}
      ${inp("monitor.repeat", "تکرار صدای قطعی (بار)", { type: "num", hint: "تا وقتی «تأیید» نزنید، هر ۳۰ ثانیه یک بار دیگر هم پخش می‌شود." })}
      <div class="field"><span>&nbsp;</span>${sw("monitor.sound_on_up", M.sound_on_up !== false, "پخش صدا وقتی دوباره وصل شد")}</div></div>
      <p class="hint">فایل MP3، WAV یا OGG تا ۲ مگابایت (رمزشده ذخیره می‌شود). در پس‌زمینه‌ی ویندوز فقط WAV و MP3 پخش می‌شوند؛ برای OGG صدای پیش‌فرض پخش می‌شود. هر کاربر می‌تواند در صفحه‌ی مانیتورینگ صدا را برای مرورگر خودش بی‌صدا کند.</p></div>
    <div class="form"><h3>نگهداری داده‌ی مانیتورینگ</h3><div class="form-grid">
      ${inp("monitor.keep_detail_days", "داده‌ی دقیق: دقیقه‌ای (Ping/TCP/HTTP) و ۱ یا ۵ دقیقه‌ای SNMP (روز)", { type: "num", hint: "۰ = بدون محدودیت (پیش‌فرض)؛ وگرنه دست‌کم ۷ روز. هدف‌های SNMP با «سیاست پایش» نگهداری خود سیاست را دارند." })}
      ${inp("monitor.keep_hour_days", "داده‌ی ساعتی و سابقه‌ی قطعی‌ها (روز)", { type: "num", hint: "۰ = بدون محدودیت (پیش‌فرض)؛ وگرنه دست‌کم ۳۰ روز" })}</div>
      <p class="hint">به‌طور پیش‌فرض هیچ داده‌ای پاک نمی‌شود. همه رمزشده (SNMP فشرده) در پوشه‌ی داده‌ی برنامه، فایل جدا برای هر روز یا ماه؛ نمودار فقط فایل‌های همان بازه را می‌خواند، پس حجم زیاد برنامه را کند نمی‌کند. پورت‌های خاموش SNMP ذخیره نمی‌شوند (مگر پیگیری شوند).</p>
      <div id="monStore" class="sum" style="margin-top:8px"><span class="muted">در حال خواندن حجم…</span></div></div>
    ${isAdmin() ? `<div class="form"><h3>کارایی و محل ذخیره‌ی مانیتورینگ</h3><div class="form-grid">
      <label class="field"><span>کارگرهای SNMP (فرایند جدا، هر کدام یک هسته)</span><select data-path="monitor.snmp_workers">
        ${[["auto", "خودکار (هسته‌ها منهای یک، حداکثر ۸)"], ["0", "خاموش (درون خود برنامه، یک هسته)"], ...Array.from({ length: 16 }, (_, i) => [String(i + 1), `${num(i + 1)} کارگر`])]
          .map(([v, n]) => `<option value="${v}" ${String(M.snmp_workers === undefined ? "auto" : M.snmp_workers) === v ? "selected" : ""}>${n}</option>`).join("")}</select>
        <small class="hint">فقط وقتی هدف SNMP فعالی هست اجرا می‌شوند. هر کارگر حدود ۵۰ مگابایت RAM می‌گیرد؛ با بسته شدن برنامه بسته می‌شوند.</small></label>
      <label class="field"><span>محل ذخیره‌ی داده‌ی نمودارها و Trap/Syslog</span><select data-path="monitor.ts_backend">
        <option value="file" ${(M.ts_backend || "file") === "file" ? "selected" : ""}>فایل‌های رمزشده در پوشه‌ی داده (پیش‌فرض)</option>
        <option value="mysql" ${M.ts_backend === "mysql" ? "selected" : ""}>MySQL / MariaDB (همان پایگاه داده‌ی برنامه)</option></select>
        <small class="hint">فقط وقتی پایگاه داده‌ی برنامه MySQL است. داده‌ی قبلی خودکار و در پس‌زمینه به MySQL منتقل می‌شود؛ اگر MySQL در دسترس نباشد داده موقتاً در فایل نوشته و بعداً منتقل می‌شود. قالب مثل حالت پایگاه داده: «خوانا» = JSON خوانا، «رمز ستون‌ها» و «رمز کامل» = فشرده و رمزشده.</small></label></div>
      <div id="monCap" class="sum" style="margin-top:8px"><span class="muted">در حال خواندن…</span></div></div>` : ""}
    <div class="form" id="evSetBox"></div>
    <div class="form" id="mibSetBox"></div>
    <div class="form"><h3>سلامت سرور</h3><div class="form-grid">
      <div class="field"><span>&nbsp;</span>${sw("health.enabled", (D.health || {}).enabled !== false, "هشدار سلامت سرور (رویداد، تاریخچه و ایمیل)")}</div>
      ${inp("health.disk_min_gb", "حداقل فضای آزاد دیسک (گیگ)", { type: "num" })}${inp("health.disk_min_pct", "حداقل فضای آزاد (درصد)", { type: "num" })}
      ${inp("health.ram_max_mb", "حداکثر RAM برنامه (مگ)", { type: "num" })}${inp("health.cpu_max_pct", "حداکثر CPU برنامه (٪ یک هسته، میانگین ۵ دقیقه)", { type: "num" })}</div>
      <p class="hint">هر ۵ دقیقه بررسی می‌شود؛ برای هر مشکل حداکثر روزی یک ایمیل («سلامت سرور» در رویدادهای اعلان ایمیلی). وضعیت در داشبورد.</p></div>
    <div class="form"><h3>ساعات سکوت</h3><div class="form-grid">
      <div class="field"><span>&nbsp;</span>${sw("monitor.quiet.enabled", M.quiet.enabled, "در این ساعت‌ها صدا پخش نشود")}</div>
      ${inp("monitor.quiet.from", "از ساعت", { ltr: true, ph: "23:00" })}${inp("monitor.quiet.to", "تا ساعت", { ltr: true, ph: "07:00" })}</div>
      <p class="hint">بنر، اعلان و ایمیل در ساعات سکوت هم ارسال می‌شوند؛ فقط صدا خاموش است.</p></div>
    <div class="form"><h3>اجرا در پس‌زمینه</h3><div class="row" style="flex-direction:column;align-items:flex-start;gap:12px">
      ${WEB ? `${sw("monitor.server_sound", M.server_sound, "پخش صدای هشدار روی خود سیستم سرور هم")}<small class="hint">در مرورگرهای باز همیشه صدا پخش می‌شود. اجرای خودکار با روشن شدن ویندوز (بدون ورود) صدا ندارد.</small>`
        : `<label class="field" style="max-width:420px"><span>با بستن پنجره وقتی مانیتورینگ فعال است</span><select data-path="monitor.close_action">
             ${[["ask", "هر بار بپرس"], ["background", "در پس‌زمینه بماند (بررسی و صدای هشدار ادامه دارد)"], ["quit", "کامل بسته شود"]].map(([v, t2]) => `<option value="${v}" ${(M.close_action || "ask") === v ? "selected" : ""}>${t2}</option>`).join("")}</select></label>
           ${sw("monitor.show_window", M.show_window !== false, "هنگام قطعی، پنجره دوباره باز شود")}
           <small class="hint">در پس‌زمینه بررسی‌ها ادامه دارند و هنگام قطعی صدا پخش می‌شود. آیکن برنامه کنار ساعت ویندوز (Show hidden icons) است: کلیک = باز کردن پنجره، کلیک راست = خروج کامل.</small>`}</div></div>`;
    if ($("#evSetBox", body)) { if (isAdmin()) monEventsSettings($("#evSetBox", body)); else $("#evSetBox", body).remove(); }
    if ($("#mibSetBox", body)) { if (isAdmin()) monMibSettings($("#mibSetBox", body)); else $("#mibSetBox", body).remove(); }
    api("mon_storage").then((r) => {
      const el = $("#monStore"); if (!el || !r.ok) { if (el) el.hidden = true; return; }
      const tot = r.minute + r.hour + r.snmp_detail + r.snmp_hour;
      const F = (n) => fmtBytes(n);     // هر خط یک جمله‌ی کامل بدون تگ (ترجمه‌ی رابط الگوی کامل می‌خواهد)
      const pols = Object.entries(r.by_policy || {}).map(([k, v]) => {
        const p = (MON.policies || []).find((x) => String(x.id) === k);
        return `${k === "custom" ? "سفارشی" : p ? p.name : "سیاست " + k}: ${F(v.bytes)} (${num(v.targets)} هدف)`;
      });
      el.innerHTML = `<div>${esc(`حجم داده‌های مانیتورینگ: ${F(tot)} (دقیقه‌ای ${F(r.minute)} · ساعتی ${F(r.hour)} · SNMP دقیق ${F(r.snmp_detail)} · SNMP ساعتی ${F(r.snmp_hour)})`)}</div>
        ${pols.length ? `<div>${esc(`حجم SNMP به تفکیک سیاست پایش: ${pols.join(" · ")}`)}</div>` : ""}
        ${r.per_day ? `<div>${esc(`رشد روز گذشته: ${F(r.per_day)} در روز (حدود ${F(r.per_day * 365)} در سال با همین تعداد هدف)`)}</div>` : ""}
        <div>${esc(`پایگاه داده: ${F(r.db)} · پوشه‌ی اجراها: ${F(r.runs)}`)}</div>${r.oldest ? `<div>${esc(`قدیمی‌ترین داده‌ی مانیتورینگ: ${r.oldest}`)}</div>` : ""}`;
    });
    if ($("#monCap", body)) monCapacityBox($("#monCap", body));
    $$("[data-snd-play]", body).forEach((b) => (b.onclick = () => { const m = MON.muted; MON.muted = false; monPlay(b.dataset.sndPlay, 1).finally(() => (MON.muted = m)); }));
    $$("[data-snd-up]", body).forEach((b) => (b.onclick = () => $(`[data-snd-file="${b.dataset.sndUp}"]`, body).click()));
    $$("[data-snd-file]", body).forEach((f) => (f.onchange = () => monSoundUpload(f.dataset.sndFile, f)));
    $$("[data-snd-reset]", body).forEach((b) => (b.onclick = () => monSoundReset(b.dataset.sndReset)));
  } else if (t === "terminal") {
    if (!D.terminal) D.terminal = { idle_minutes: 30, record: false };
    if (!D.transfer) D.transfer = { max_mb: 0 };
    body.innerHTML = `<div class="form"><h3>ترمینال SSH زنده</h3><div class="form-grid">
      ${inp("terminal.idle_minutes", "بستن ترمینال پس از بی‌کاری (دقیقه)", { type: "num", hint: "۰ = خاموش. ترمینالی که پنجره‌اش بسته شود پس از ۲ دقیقه قطع می‌شود." })}
      <div class="field"><span>&nbsp;</span>${sw("terminal.record", D.terminal.record, "ضبط متن نشست‌ها")}<small class="hint">خروجی ترمینال (شامل دستورهایی که دستگاه نمایش می‌دهد) رمزشده ذخیره و از «تاریخچه» قابل مشاهده است؛ فقط برای همان کاربر و ادمین. رمزهایی که دستگاه نمایش نمی‌دهد ضبط نمی‌شوند.</small></div></div></div>
    <div class="form"><h3>انتقال فایل (SFTP، SCP، FTP، TFTP)</h3><div class="form-grid">
      ${inp("transfer.max_mb", "سقف حجم هر فایل (مگابایت)", { type: "num", hint: "۰ = بدون محدودیت. برای آپلود، دانلود و فایل‌هایی که دستگاه با TFTP می‌فرستد." })}</div>
      <p class="hint">همه‌ی اتصال‌ها و انتقال‌ها با نام کاربر در تاریخچه ثبت می‌شوند. اتصال‌های بی‌کار پس از ۳۰ دقیقه بسته می‌شوند.</p></div>`;
  } else if (t === "intel") {
    if (!D.intel) D.intel = {};
    const I = D.intel;
    body.innerHTML = `<div class="form"><h3>فید آنلاین FFraud</h3>
      <div class="row" style="justify-content:space-between">${sw("intel.feed_enabled", I.feed_enabled !== false, "<b>استفاده از فید آنلاین</b>")}<button class="btn sm no-ro" id="btnIntelFeed">دریافت الان</button></div>
      <div id="intelFeedSt" class="hint" style="margin:8px 0">…</div>
      <div class="form-grid">
      ${inp("intel.feed_url", "آدرس فید (CSV با ستون ip)", { ltr: true, wide: true })}
      ${inp("intel.min_score", "حداقل امتیاز ffraud_score", { type: "num", hint: "۰ تا ۱۰۰. خود فید فقط IPهای با امتیاز ۵۰ و بیشتر را دارد." })}
      ${inp("intel.refresh_minutes", "دانلود دوباره حداکثر هر (دقیقه)", { type: "num", hint: "تا این مدت نسخه‌ی ذخیره‌شده استفاده می‌شود؛ بعد از آن فقط اگر فید تغییر کرده باشد دانلود می‌شود (ETag). فید هر ۳۰ دقیقه به‌روز می‌شود." })}
      ${inp("intel.max_age_hours", "استفاده از نسخه‌ی ذخیره‌شده هنگام خطای دانلود تا (ساعت)", { type: "num", hint: "قدیمی‌تر از این ← ابزار خطا می‌دهد و هیچ IPای پاک حساب نمی‌شود." })}
      ${inp("intel.timeout", "Timeout دانلود (ثانیه)", { type: "num" })}
      <div class="field"><span>&nbsp;</span>${sw("intel.verify_ssl", I.verify_ssl !== false, "بررسی گواهی SSL")}</div></div></div>
    <div class="form"><h3>لیست داخلی</h3>
      <div class="row" style="justify-content:space-between">${sw("intel.local_enabled", !!I.local_enabled, "<b>استفاده از لیست داخلی</b>")}
        <span class="row" style="gap:8px"><button class="btn sm no-ro" id="btnIntelUp">بارگذاری فایل…</button><button class="btn sm danger-ghost no-ro" id="btnIntelClr">حذف</button></span></div>
      <div id="intelLocalSt" class="hint" style="margin:8px 0">…</div>
      ${WEB ? "" : `<div class="form-grid">${inp("intel.local_path", "یا مسیر فایل (هر اجرا خوانده می‌شود)", { ltr: true, wide: true, ph: "C:\\lists\\malicious.csv", hint: "اگر پر باشد همین فایل در هر اجرا خوانده می‌شود و فایل آپلودشده استفاده نمی‌شود؛ وقتی فایل را به‌روز می‌کنید لازم نیست دوباره بارگذاری کنید. فایل در همان مسیر رمزنشده می‌ماند." })}</div>`}
      <p class="hint">قالب: هر خط یک IP یا رنج CIDR در ستون اول (مثل malicious.csv)؛ سرستون‌هایی مثل ip و src_ip و خطوط # نادیده گرفته می‌شوند. فایل آپلودشده رمزشده نگه داشته می‌شود؛ وقتی فایل شما به‌روز شد دوباره بارگذاری کنید.</p></div>
    <div class="form"><h3>بلاک</h3>
      ${sw("intel.auto_ban", !!I.auto_ban, "بلاک مخرب‌های بررسی تکمیلی در FortiGate بدون تأیید")}
      <p class="hint">فقط در کار زمان‌بندی‌شده‌ای که «بلاک بدون تأیید» آن روشن است اثر دارد (با همان سقف بلاک). پیش‌فرض خاموش: پیش از بلاک، فهرست را می‌بینید و تأیید می‌کنید.</p></div>`;
    const showSt = async () => {
      const r = await api("intel_status"); if (!r.ok) return;
      const f = r.feed || {}, l = r.local || {};
      $("#intelFeedSt").innerHTML = f.fetched ? `نسخه‌ی ذخیره‌شده: <span class="ltr">${fmtDate(f.fetched)}</span> — ${num(f.rows)}‏ IP، ${num(Math.round((f.size || 0) / 1024))}KB${f.last_error ? `<br><span class="warn">آخرین خطا: ${esc(f.last_error)}</span>` : ""}`
        : (f.last_error ? `<span class="warn">${esc(f.last_error)}</span>` : "هنوز دانلود نشده است (اولین اجرای ابزار یا «دریافت الان»).");
      $("#intelLocalSt").innerHTML = l.uploaded ? `فایل آپلودشده: <b class="ltr">${esc(l.name)}</b> — <span class="ltr">${fmtDate(l.uploaded)}</span> — ${num(l.ips)}‏ IP و ${num(l.nets)} رنج${l.invalid ? `، <span class="warn">${num(l.invalid)} خط نامعتبر</span>` : ""}` : "فایلی آپلود نشده است.";
    };
    showSt();
    $("#btnIntelFeed").onclick = (e) => withSpin(e.currentTarget, async () => { const r = await api("intel_feed_update"); toast(r.ok ? r.message : r.error, r.ok ? "ok" : "error"); showSt(); });
    $("#btnIntelUp").onclick = (e) => withSpin(e.currentTarget, async () => {
      const p = await api("pick_csv"); if (!p.ok) return toast(p.error, "warn"); if (!p.path) return;
      const r = await api("intel_local_upload", p.path); if (!r.ok) return toast(r.error, "error");
      S.settings = r.settings; setPath(S.draft, "intel.local_enabled", true);
      toast(`لیست داخلی بارگذاری شد: ${num(r.local.ips)}‏ IP و ${num(r.local.nets)} رنج`, "ok"); renderSettings();
    });
    $("#btnIntelClr").onclick = async () => {
      if (!(await confirm2({ title: "حذف لیست داخلی", body: "<p>فایل آپلودشده‌ی لیست داخلی حذف شود؟</p>", confirm: "حذف", danger: true }))) return;
      const r = await api("intel_local_clear"); if (!r.ok) return toast(r.error, "error");
      S.settings = r.settings; setPath(S.draft, "intel.local_enabled", !!r.settings.intel.local_enabled); toast("حذف شد", "ok"); renderSettings();
    };
  } else if (t === "scan") {
    if (!D.scan) D.scan = { allowed_networks: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"], max_hosts: 1024, max_probes: 200000, workers: 100, timeout: 1 };
    body.innerHTML = `<div class="form"><h3>ابزار اسکن شبکه</h3><div class="form-grid">
      <label class="field wide"><span>رنج‌های مجاز اسکن — هر مورد در یک خط؛ متن بعد از # توضیح است</span><textarea class="ltr" data-type="lines" data-path="scan.allowed_networks" style="min-height:140px">${esc((D.scan.allowed_networks || []).join("\n"))}</textarea>
        <small class="hint">فقط آدرس‌های داخل این رنج‌ها اسکن می‌شوند و بقیه رد و در گزارش اجرا ثبت می‌شوند. خالی = هیچ اسکنی انجام نمی‌شود. فقط شبکه‌هایی را اضافه کنید که اجازه‌ی اسکنشان را دارید.</small></label>
      ${inp("scan.max_hosts", "حداکثر آدرس در هر اجرا", { type: "num" })}
      ${inp("scan.max_probes", "حداکثر اتصال در هر اسکن پورت (هاست × پورت)", { type: "num" })}
      ${inp("scan.workers", "اتصال هم‌زمان پیش‌فرض", { type: "num", hint: "بین ۱ و ۳۰۰؛ در هر ابزار قابل تغییر است." })}
      ${inp("scan.timeout", "Timeout پیش‌فرض (ثانیه)", { type: "num", hint: "بین 0.2 و 10" })}</div>
      <p class="hint">اسکن با اتصال TCP عادی و ping سیستم انجام می‌شود (بدون Nmap). همه‌ی اسکن‌ها با نام کاربر در تاریخچه ثبت می‌شوند.</p></div>`;
  } else if (t === "fortigate") {
    renderFgSettings(body, D);
  } else {
    const R = D.redmine, M = (R.meta && R.meta.project === R.project) ? R.meta : null;
    body.innerHTML = connSection("redmine") + `<div class="form"><h3>تیکت</h3><div class="form-grid">
      ${inp("redmine.project", "شناسه‌ی پروژه", { ltr: true })}
      ${inp("redmine.src_ips_per_line", "تعداد IP مبدأ در هر خط (۰ = همه در یک خط)", { type: "num" })}${inp("redmine.dest_sample_count", "تعداد نمونه‌ی مقصد و پورت", { type: "num" })}
      ${inp("redmine.more_suffix", "پسوند ادامه")}</div>
      <p class="hint">عنوان، Tracker، اولویت، دسته، متن، مقدار فیلدها و پیوست‌ها برای هر قالب جداست: «کارهای خودکار ← قالب‌های تیکت Redmine» (${num((R.templates || []).length)} قالب). <button class="btn sm ghost" id="goTpl">باز کردن قالب‌ها</button></p>
      ${rmMetaSection(R, M)}
      ${M ? `<details class="sec"><summary class="muted">روش قدیمی (تعریف دستی فیلدها با نام) — فقط وقتی اطلاعات فیلدها خوانده نشده استفاده می‌شود</summary>` : ""}
      <div class="sec"><h3>فیلدهای ثابت</h3><p class="hint">نام دقیق Custom Field در Redmine و مقدار آن. برای فیلدهای لیستی مقدار باید یکی از گزینه‌های مجاز باشد.</p>${pairsEditor("redmine.static_fields", "نام فیلد", "مقدار")}</div>
      <div class="sec"><h3>فیلدهای پویا</h3><p class="hint">کلیدهای مجاز: src_ips، dest_ips، dest_ports، detected_date</p>${pairsEditor("redmine.dynamic_fields", "نام فیلد", "کلید داده")}</div>
      <div class="sec"><h3>شناسه‌ی دستی فیلدها</h3><p class="hint">فقط اگر پیدا کردن خودکار ID جواب نداد.</p>${pairsEditor("redmine.field_id_overrides", "نام فیلد", "ID")}</div>
      ${M ? `</details>` : ""}
      </div>`;
    wireRmFields(body);
    $("#goTpl").onclick = () => { S.autoTab = "tpl"; go("auto"); };
    if ($("#btnDiscover")) $("#btnDiscover").onclick = (e) => withSpin(e.currentTarget, async () => {
      const p = draftPatch().redmine; const r = await api("redmine_discover", p);
      if (!r.ok) return toast(r.error, "error");
      const d = r.discover;
      openModal({ title: "کشف Redmine", wide: true, body: `<p class="hint">کاربر: <span class="ltr">${esc(d.user.login)}</span> — منبع فیلدها: ${d.fields_source === "admin" ? "custom_fields.json (ادمین)" : d.fields_source === "sample-issue" ? "آخرین Issue پروژه" : "پیدا نشد"}</p>
        <div class="row" style="align-items:flex-start;gap:24px;margin:10px 0">${[["Trackerها", d.trackers], ["اولویت‌ها", d.priorities], ["دسته‌ها", d.categories]].map(([t, l]) => `<div><h3>${t}</h3>${l.map((x) => `<div class="ltr" style="font-size:13px">${esc(x.id)} — ${esc(x.name)}</div>`).join("")}</div>`).join("")}</div>
        <h3>فیلدهای سفارشی</h3><div class="table-wrap inner"><table class="grid"><thead><tr><th class="nosort">ID</th><th class="nosort">نام</th><th class="nosort">نوع</th><th class="nosort">گزینه‌ها</th></tr></thead><tbody>
        ${d.fields.map((f) => `<tr><td class="ltr">${esc(f.id)}</td><td class="ltr">${esc(f.name)}</td><td class="ltr">${esc(f.format)}</td><td class="wrap ltr">${esc((f.options || []).join(" | "))}</td></tr>`).join("")}</tbody></table></div>` });
    });
  }
  bindInputs(body);
}
$("#setTabs").addEventListener("click", (e) => { const b = e.target.closest("button[data-t]"); if (b) { S.setTab = b.dataset.t; renderSettings(); } });
$("#btnSaveSettings").addEventListener("click", (e) => saveDraft(e.currentTarget));
$("#setBody").addEventListener("click", async (e) => {
  const up = e.target.closest("[data-unpin]");
  if (up) {
    const ok = await confirm2({ title: "فراموش کردن گواهی", body: "<p>اتصال بعدی، گواهی فعلی سرور را دوباره پین می‌کند. فقط وقتی این کار را بکنید که از تعویض گواهی سرور مطمئن هستید.</p>", confirm: "فراموش کن", danger: true });
    if (!ok) return;
    const r = await api("forget_cert_pin", up.dataset.unpin);
    if (r.ok) { S.settings = r.settings; setPath(S.draft, `${up.dataset.unpin}.cert_pin`, r.settings[up.dataset.unpin].cert_pin); renderSettings(); toast("گواهی فراموش شد", "ok"); }
    else toast(r.error, "error");
    return;
  }
  const cl = e.target.closest("[data-clear]");
  if (cl) { setPath(S.draft, cl.dataset.clear, "__clear__"); renderSettings(); toast("پس از «ذخیره‌ی تنظیمات» پاک می‌شود", "warn"); return; }
  const tb = e.target.closest("[data-test]");
  if (tb) {
    const c = tb.dataset.test, out = $(`#tr-${c}`);
    await withSpin(tb, async () => {
      out.className = "test-res"; out.textContent = "";
      let r = await api("test_connection", c, draftPatch()[c]);
      if (!r.ok && r.pin_confirm) {     // گواهی ناشناخته: فقط با تأیید آگاهانه‌ی کاربر پین می‌شود
        const pc = r.pin_confirm;
        const ok = await confirm2({ title: "تأیید گواهی سرور", confirm: "اعتماد و پین گواهی",
          body: `<p>«بررسی گواهی SSL» خاموش است و گواهی <b class="ltr">${esc(pc.host)}</b> هنوز تأیید نشده است. اثر انگشت SHA-256 را با گواهی خود سرور مقایسه کنید (مثلاً در FortiGate: System ← Certificates):</p>
            <p class="ltr tech" style="font-size:12.5px;word-break:break-all">${esc(pc.fmt)}</p>
            <p class="hint">با تأیید، از این به بعد فقط همین گواهی پذیرفته می‌شود. اگر مطمئن نیستید، تأیید نکنید.</p>`,
          ack: "اثر انگشت را با گواهی سرور مقایسه کردم" });
        if (ok) {
          r = await api("test_connection", c, draftPatch()[c], { host: pc.host, sha256: pc.sha256 });
          const g = await api("get_settings");
          if (g.ok && g.settings[c]) { S.settings[c].cert_pin = g.settings[c].cert_pin; S.draft[c].cert_pin = g.settings[c].cert_pin; }
          if (r.ok) setTimeout(renderSettings, 1200);
        }
      }
      out.className = "test-res " + (r.ok ? "ok" : "err"); out.textContent = r.ok ? r.message : r.error;
    });
    return;
  }
  const add = e.target.closest("[data-padd]");
  if (add) { const l = getPath(S.draft, add.dataset.padd) || []; l.push(["", ""]); setPath(S.draft, add.dataset.padd, l); renderSettings(); return; }
  const del = e.target.closest("[data-pdel]");
  if (del) { const path = del.closest("[data-pairs]").dataset.pairs; const l = getPath(S.draft, path); l.splice(Number(del.dataset.pdel), 1); renderSettings(); }
});
$("#setBody").addEventListener("input", (e) => {
  const el = e.target.closest("[data-pi]"); if (!el) return;
  const path = el.closest("[data-pairs]").dataset.pairs; const l = getPath(S.draft, path);
  l[Number(el.dataset.pi)][Number(el.dataset.pj)] = el.value;
});

/* ================================================================ boot */
window.addEventListener("blur", clearTips);
document.addEventListener("scroll", clearTips, true);
setTimeout(() => document.body.classList.remove("booting"), 8000);      // اگر وضعیت هرگز نرسید، صفحه خالی نماند
/* 1.39: متن پذیرش پیش از استفاده — تا پذیرفته نشود برنامه بالا نمی‌آید (دسکتاپ یک بار؛ سرور هر کاربر؛ با نسخه‌ی تازه‌ی متن دوباره) */
const TERMS_UI = {
  fa: { chk: "متن بالا را خواندم", yes: "می‌پذیرم", no: "نمی‌پذیرم (خروج)", sw: "English", bye: "بدون پذیرش این متن نمی‌توان از برنامه استفاده کرد. برنامه را ببندید." },
  en: { chk: "I have read the text above", yes: "I accept", no: "I do not accept (exit)", sw: "فارسی", bye: "The program cannot be used without accepting this text. Please close it." },
};
function termsHtml(r, lang, gate) {
  const u = TERMS_UI[lang];
  return `<div class="terms-card" dir="${lang === "en" ? "ltr" : "rtl"}" lang="${lang}"><div class="terms-head"><h2>${esc(r.title[lang])}</h2>
      <button class="btn sm ghost" data-tl="${lang === "en" ? "fa" : "en"}">${u.sw}</button></div>
    <div class="terms-body">${r.text[lang].map((p) => `<p>${esc(p)}</p>`).join("")}</div>
    ${gate ? `<label class="chk"><input type="checkbox" id="trmChk">${u.chk}</label>
    <div class="terms-foot"><button class="btn ghost" id="trmNo">${u.no}</button><button class="btn primary" id="trmYes" disabled>${u.yes}</button></div>
    <div class="terms-bye" id="trmBye" hidden>${u.bye}</div>` : ""}</div>`;
}
async function termsGate() {
  let r;
  try { r = await api("terms_status"); } catch (_) { return; }
  if (!r || !r.ok || !r.need) return;
  await new Promise((done) => {
    const el = document.createElement("div");
    el.id = "terms"; el.className = "terms-back"; el.setAttribute("data-no-i18n", "");
    let lang = I18N.lang === "en" ? "en" : "fa";
    const draw = () => {
      el.innerHTML = termsHtml(r, lang, true);
      $("[data-tl]", el).onclick = (e) => { lang = e.currentTarget.dataset.tl; draw(); };
      $("#trmChk", el).onchange = (e) => ($("#trmYes", el).disabled = !e.target.checked);
      $("#trmYes", el).onclick = async () => {
        const x = await api("terms_accept", r.v);
        if (!x.ok) return toast(x.error, "error");
        el.remove(); done();
      };
      $("#trmNo", el).onclick = async () => {
        $("#trmBye", el).hidden = false;
        if (WEB) return webLogout();
        try { await api("app_close_choice", "quit", false); } catch (_) { /* پیام بالا */ }
      };
    };
    draw();
    document.body.appendChild(el);
  });
}
async function termsShowAgain() {
  const r = await api("terms_status"); if (!r.ok) return toast(r.error, "error");
  let lang = I18N.lang === "en" ? "en" : "fa";
  openModal({ title: r.title[lang], wide: true, body: `<div data-no-i18n id="trmView">${termsHtml(r, lang, false)}</div>`,
    onOpen: (m) => { const bind = () => { $("[data-tl]", m).onclick = (e) => { lang = e.currentTarget.dataset.tl; $("#trmView", m).innerHTML = termsHtml(r, lang, false); bind(); }; }; bind(); } });
}

(async function boot() {
  await termsGate();
  await loadSettings();
  await refreshState();
  renderFeed();
  renderStageForm();
})();

/* ================================================================ Splunk: کوئری و دستیار نگاشت ستون‌ها */
const SP_ROLES = [["src", "IP مبدأ", true], ["dest", "IP مقصد"], ["dest_port", "پورت مقصد"], ["signature", "نام حمله"],
  ["count", "تعداد"], ["first", "زمان اولین رخداد"], ["last", "زمان آخرین رخداد"]];
const SP = { diag: null, map: null };
function spMappingState(D) {
  const saved = S.settings && S.settings.splunk ? S.settings.splunk : {};
  const changed = (D.splunk.query || "") !== (saved.query || "");
  const hasMap = !!saved.fields_hash;
  return { changed, hasMap, confirmed: hasMap && !changed && SP.confirmedSaved !== false };
}
function renderSplunkTab(body, D) {
  const st = spMappingState(D);
  body.innerHTML = connSection("splunk") + `<div class="form"><h3>کوئری اصلی (پیش‌فرض — اجرای روزانه)</h3><div class="form-grid">
      <label class="field"><span>اپ Splunk</span><input type="text" class="ltr" data-path="splunk.app" value="${esc(D.splunk.app || "search")}" placeholder="search">
        <small class="hint">همان اپی که کوئری در وب Splunk در آن جواب می‌دهد؛ در آدرس صفحه‌ی جستجو: <span class="ltr">…/app/<b>search</b>/search</span>. اپ تعیین می‌کند ماکروها و استخراج فیلدها دیده شوند یا نه.</small></label>
      <div class="field"><span>بازه‌ی پیش‌فرض (earliest)</span><input type="text" class="ltr" data-path="splunk.earliest" id="spEarliest" value="${esc(D.splunk.earliest || "")}">
        <div class="row" style="gap:4px;margin-top:6px;flex-wrap:wrap">${["-30m", "-24h", "-72h", "-7d", "-30d"].map((x) => `<button class="btn sm ghost" data-er="${x}" type="button">${x}</button>`).join("")}</div></div>
      ${inp("splunk.latest", "latest پیش‌فرض", { ltr: true })}${inp("splunk.timeout", "حداکثر زمان انتظار (ثانیه)", { type: "num" })}
      <label class="field wide"><span>کوئری SPL</span><textarea class="ltr" data-path="splunk.query" id="spQuery" style="min-height:230px" spellcheck="false">${esc(D.splunk.query)}</textarea></label></div>
      <div class="form-foot"><button class="btn primary" id="btnSpPrev">اجرا و پیش‌نمایش</button><button class="btn" id="btnSpOpt" type="button">بهینه‌سازی برای API…</button><span id="spState">${spStateHtml(st)}</span></div>
      <p class="hint">بعد از هر تغییر کوئری: «اجرا و پیش‌نمایش» را بزنید، در جدول ببینید کدام ستون کدام اطلاعات است، و نگاشت را تأیید کنید. کوئری و نگاشت با هم ذخیره می‌شوند.</p></div>
    <div id="spPrev">${SP.diag ? "" : ""}</div>
    <div class="form" id="spQueries"></div>`;
  renderSpQueries();
  $$("[data-er]", body).forEach((x) => (x.onclick = () => { const i = $("#spEarliest", body); i.value = x.dataset.er; i.dispatchEvent(new Event("input")); }));
  $("#spQuery", body).addEventListener("input", (e) => {
    S.draft.splunk.query = e.target.value;   // پیش از محاسبه‌ی وضعیت (ترتیب شنونده‌ها مهم نیست)
    SP.diag = null; $("#spPrev").innerHTML = ""; $("#spState").innerHTML = spStateHtml(spMappingState(S.draft));
  });
  $("#btnSpOpt", body).onclick = () => splOptimizer($("#spQuery", body), S.draft.splunk.earliest, S.draft.splunk.latest);
  $("#btnSpPrev", body).onclick = (e) => withSpin(e.currentTarget, async () => {
    const r = await api("splunk_diagnose", draftPatch().splunk); if (!r.ok) return toast(r.error, "error");
    SP.diag = r.diag; SP.map = { ...r.diag.suggest }; renderSplunkPreview();
  });
  if (SP.diag) renderSplunkPreview();
}
const SP_STD = [["src_ip", "IP مبدأ", ["src_ip", "src"]], ["dest_ip", "IP مقصد", ["dest_ip", "dest"]], ["dest_port", "پورت مقصد", ["dest_port"]],
  ["signature", "نام حمله", ["signature", "signatures", "attack_name"]], ["count", "تعداد", ["count", "attack_count"]],
  ["first_time", "اولین زمان", ["first_time", "firstTime"]], ["last_time", "آخرین زمان", ["last_time", "lastTime"]],
  ["url", "URL", ["url", "http_url"]], ["domain", "دامنه", ["domain", "dest_host", "query"]]];
const SPQ = { open: null, diag: {} };
function renderSpQueries() {
  const box = $("#spQueries"); if (!box) return;
  const Q = S.draft.splunk.queries || (S.draft.splunk.queries = []);
  box.innerHTML = `<h3>کوئری‌های ذخیره‌شده</h3>
    <p class="hint">این کوئری‌ها در کارت Splunk صفحه‌ی «ابزارها» قابل انتخاب‌اند. نقش ستون‌ها از نام ستون تشخیص داده می‌شود؛ در کوئری با <span class="tech">rename … as …</span> خروجی را به این نام‌ها برگردانید:
    ${SP_STD.map(([n, t]) => `<span class="tech">${n}</span> (${t})`).join("، ")}.</p>
    ${Q.map((q, i) => `<div class="sec" style="border-top:1px solid var(--line2);padding-top:12px;margin-top:12px">
      <div class="row" style="gap:10px;align-items:end;flex-wrap:wrap">
        <label class="field" style="flex:1;min-width:200px"><span>نام</span><input type="text" data-path="splunk.queries.${i}.name" value="${esc(q.name || "")}" placeholder="مثلاً پورت اسکن"></label>
        <label class="field"><span>earliest (خالی = پیش‌فرض)</span><input type="text" class="ltr" data-path="splunk.queries.${i}.earliest" value="${esc(q.earliest || "")}" placeholder="${esc(S.draft.splunk.earliest || "-24h")}"></label>
        <label class="field"><span>latest</span><input type="text" class="ltr" data-path="splunk.queries.${i}.latest" value="${esc(q.latest || "")}" placeholder="${esc(S.draft.splunk.latest || "now")}"></label>
        <button class="btn sm" data-qo="${i}" type="button">بهینه‌سازی…</button><button class="btn sm" data-qt="${i}">اجرای آزمایشی</button><button class="btn sm danger-ghost" data-qd="${i}">حذف</button></div>
      <label class="field wide"><span>کوئری SPL</span><textarea class="ltr" data-path="splunk.queries.${i}.query" style="min-height:120px" spellcheck="false">${esc(q.query || "")}</textarea></label>
      <div id="spqPrev${i}">${spqPreview(i)}</div></div>`).join("")}
    <div class="form-foot"><button class="btn" id="spqAdd">+ افزودن کوئری</button><span class="hint">بعد از تغییر، «ذخیره» بالای صفحه را بزنید.</span></div>`;
  bindInputs(box);
  $("#spqAdd").onclick = () => { Q.push({ id: "", name: "", query: "", earliest: "", latest: "" }); renderSpQueries(); };
  $$("[data-qd]", box).forEach((b) => (b.onclick = async () => {
    const q = Q[Number(b.dataset.qd)];
    if (q.name && !(await confirm2({ title: "حذف کوئری", body: `<p>کوئری «${esc(q.name)}» حذف شود؟ بعد از «ذخیره» اعمال می‌شود.</p>`, confirm: "حذف", danger: true }))) return;
    Q.splice(Number(b.dataset.qd), 1); SPQ.diag = {}; renderSpQueries();
  }));
  $$("[data-qo]", box).forEach((b) => (b.onclick = () => {
    const i = Number(b.dataset.qo), q = Q[i];
    splOptimizer($(`textarea[data-path="splunk.queries.${i}.query"]`, box), q.earliest || S.draft.splunk.earliest, q.latest || S.draft.splunk.latest);
  }));
  $$("[data-qt]", box).forEach((b) => (b.onclick = (e) => withSpin(e.currentTarget, async () => {
    const i = Number(b.dataset.qt), q = Q[i];
    if (!(q.query || "").trim()) return toast("متن کوئری خالی است.", "warn");
    const patch = { ...draftPatch().splunk, query: q.query, fields: {}, fields_hash: "" };
    const r = await api("splunk_diagnose", patch, q.earliest || null, q.latest || null);
    if (!r.ok) return toast(r.error, "error");
    SPQ.diag[i] = r.diag; $(`#spqPrev${i}`).innerHTML = spqPreview(i);
  })));
}
/* ---------- دستیار کوئری: کوئری خام وب Splunk ← کوئری مناسب API (همه‌ی تحلیل محلی؛ فقط «بررسی فیلدها» به Splunk وصل می‌شود) */
async function splOptimizer(target, earliest, latest) {
  const st = { raw: target.value || "", opt: null, accept: null, check: null };
  const KIND = { fix: ["ok", "اصلاح شد"], warn: ["warn", "هشدار"] };
  // متن کوئری داخل «…» چپ‌به‌راست (وگرنه | و پرانتزها در متن فارسی جابه‌جا دیده می‌شوند)
  const bt = (t) => esc(t).replace(/«([^»]*[A-Za-z|][^»]*)»/g, (_, x) => `<span class="tech" dir="ltr">${x}</span>`);
  const draw = (m) => {
    const o = st.opt;
    $("#soOut", m).innerHTML = !o ? "" : `
      ${o.notes.length ? `<div style="margin:8px 0">${o.notes.map((n) => `<div class="row" style="gap:8px;align-items:flex-start;margin-bottom:4px"><span class="tag ${KIND[n.kind][0]}">${KIND[n.kind][1]}</span><span>${bt(n.text)}</span></div>`).join("")}</div>`
        : `<p class="hint">مورد قابل اصلاحی پیدا نشد.</p>`}
      ${o.suggestions.length ? `<h3 style="margin:12px 0 6px">پیشنهادها</h3>${o.suggestions.map((g) => `<label class="chk" style="display:flex;margin-bottom:6px"><input type="checkbox" class="soSug" value="${esc(g.id)}" ${g.on ? "checked" : ""}><span>${bt(g.text)}</span></label>`).join("")}` : ""}
      <label class="field wide" style="margin-top:10px"><span>کوئری نهایی (قابل ویرایش)</span><textarea class="ltr" id="soRes" style="min-height:220px" spellcheck="false">${esc(o.query)}</textarea></label>
      <div class="row" style="gap:8px;margin-top:6px"><button class="btn" id="soCheck" type="button">بررسی فیلدها روی Splunk</button><span class="hint">فقط برای تنظیم کوئری: حداکثر ۵٬۰۰۰ رخداد جستجوی پایه با fieldsummary</span></div>
      <div id="soChk">${chkHtml()}</div>`;
    $$(".soSug", m).forEach((x) => (x.onchange = () => { st.accept = $$(".soSug:checked", m).map((y) => y.value); run(m); }));
    const btn = $("#soCheck", m);
    if (btn) btn.onclick = (e) => withSpin(e.currentTarget, async () => {
      const r = await api("splunk_check_fields", draftPatch().splunk, $("#soRes", m).value, earliest || null, latest || null);
      if (!r.ok) return toast(r.error, "error");
      st.check = r.check; $("#soChk", m).innerHTML = chkHtml();
    });
  };
  const chkHtml = () => {
    const c = st.check; if (!c) return "";
    const bad = (c.messages || []).filter((x) => ["ERROR", "FATAL", "RAW"].includes(x.type));
    if (!c.present.length) return `<p class="hint warn">از جستجوی پایه هیچ رخدادی در این بازه برنگشت؛ index، sourcetype و بازه‌ی زمانی را بررسی کنید.</p>${bad.map((x) => `<div class="hint warn ltr">${esc(x.type)}: ${esc(x.text)}</div>`).join("")}`;
    return `${c.note ? `<p class="hint warn">${esc(c.note)}</p>` : ""}
      ${c.missing.length ? `<p class="hint">این فیلدها در رخدادها پیدا نشدند (${num(c.present.length)} فیلد موجود):</p>
        <div class="table-wrap inner"><table class="grid"><thead><tr><th class="nosort">فیلد در کوئری</th><th class="nosort">فیلدهای مشابه موجود</th></tr></thead><tbody>
        ${c.missing.map((x) => `<tr><td class="ltr">${esc(x.field)}</td><td class="ltr">${x.similar.length ? x.similar.map(esc).join("، ") : "—"}</td></tr>`).join("")}</tbody></table></div>
        <p class="hint">اگر فیلد مشابه درست است، در کوئری نهایی جایگزینش کنید و برای ستون خروجی <span class="tech">rename … as …</span> بگذارید.</p>`
        : `<p class="hint"><span class="tag ok">درست</span> همه‌ی ${num(c.need.length)} فیلدی که کوئری لازم دارد در رخدادها هست.</p>`}
      <details style="margin-top:6px"><summary class="hint" style="cursor:pointer">فیلدهای موجود (${num(c.present.length)})</summary><div class="ltr tech" style="white-space:normal">${c.present.map(esc).join("  ")}</div></details>`;
  };
  const run = async (m) => {
    const r = await api("splunk_optimize", $("#soRaw", m).value, st.accept);
    if (!r.ok) return toast(r.error, "error");
    st.opt = r.opt; st.check = null; draw(m);
  };
  const v = await openModal({ title: "بهینه‌سازی کوئری برای API", wide: true,
    body: `<p class="hint">کوئری را همان‌طور که در وب Splunk کار می‌کند بچسبانید. اصلاح‌ها خودکار انجام می‌شوند، پیشنهادها با تیک شما، و چیزی تا «جایگزینی» ذخیره نمی‌شود.</p>
      <label class="field wide"><span>کوئری خام</span><textarea class="ltr" id="soRaw" style="min-height:140px" spellcheck="false">${esc(st.raw)}</textarea></label>
      <div class="row" style="gap:8px"><button class="btn primary" id="soGo" type="button">تحلیل</button></div><div id="soOut"></div>`,
    foot: `<button class="btn ghost" data-r="0">انصراف</button><button class="btn primary" data-r="1">جایگزینی در کوئری</button>`,
    onOpen: (m, close) => {
      $("#soGo", m).onclick = (e) => withSpin(e.currentTarget, () => { st.accept = null; return run(m); });
      $("[data-r='0']", m).onclick = () => close(null);
      $("[data-r='1']", m).onclick = () => { const r = $("#soRes", m); if (!r) return toast("ابتدا «تحلیل» را بزنید.", "warn"); close(r.value); };
      if (st.raw.trim()) run(m);
    } });
  if (v == null) return;
  target.value = v; target.dispatchEvent(new Event("input", { bubbles: true }));
  toast("کوئری جایگزین شد؛ «اجرا و پیش‌نمایش» و بعد «ذخیره» را بزنید.", "ok");
}
function spqPreview(i) {
  const d = SPQ.diag[i]; if (!d) return "";
  const low = d.columns.map((c) => c.toLowerCase());
  const found = SP_STD.map(([n, t, al]) => [t, d.columns[low.findIndex((c) => al.map((x) => x.toLowerCase()).includes(c))]]).filter(([, c]) => c);
  const rows = d.rows.slice(0, 5);
  return `<p class="hint">${num(d.rows.length)} ردیف — ستون‌های شناخته‌شده: ${found.length ? found.map(([t, c]) => `${t}=<span class="tech">${esc(c)}</span>`).join("، ") : "هیچ"}</p>
    ${d.messages.length ? d.messages.slice(0, 3).map((m) => `<div class="hint warn ltr">${esc(m.type)}: ${esc(m.text)}</div>`).join("") : ""}
    ${rows.length ? `<div class="table-wrap inner" style="max-height:220px"><table class="grid"><thead><tr>${d.columns.map((c) => `<th class="nosort ltr">${esc(c)}</th>`).join("")}</tr></thead><tbody>
      ${rows.map((rw) => `<tr>${d.columns.map((c) => `<td class="ltr">${esc(Array.isArray(rw[c]) ? rw[c].join(", ") : rw[c] ?? "")}</td>`).join("")}</tr>`).join("")}</tbody></table></div>` : ""}`;
}
function spStateHtml(st) {
  if (st.changed) return `<span class="tag warn">کوئری تغییر کرده؛ اجرا و پیش‌نمایش کنید و نگاشت را تأیید کنید</span>`;
  if (st.hasMap) return `<span class="tag ok">نگاشت ستون‌ها برای این کوئری تأیید شده است</span>`;
  return `<span class="tag warn">نگاشت ستون‌ها هنوز تأیید نشده است</span>`;
}
function renderSplunkPreview() {
  const d = SP.diag, box = $("#spPrev"); if (!d || !box) return;
  const cols = d.columns, rows = d.rows.slice(0, 10);
  const msgCls = (t2) => (["ERROR", "FATAL", "RAW"].includes(t2) ? "err" : t2 === "WARN" || t2 === "AUTOKRP" ? "warn" : "info");
  const opts = (role, req) => (req ? `<option value="" ${!SP.map[role] ? "selected" : ""}>— انتخاب کنید —</option>` : `<option value="-" ${SP.map[role] === "-" ? "selected" : ""}>— ندارد —</option>`)
    + cols.map((c) => `<option value="${esc(c)}" ${SP.map[role] === c ? "selected" : ""}>${esc(c)}</option>`).join("");
  box.innerHTML = `<div class="form"><h3>پیش‌نمایش خروجی</h3>
    <p class="hint">یوزر توکن: <span class="tech">${d.user ? `${esc(d.user.username)} (${esc((d.user.roles || []).join("، "))})` : "—"}</span> — اپ: <span class="tech">${esc(d.app)}</span>
      — بازه: <span class="tech">${esc(d.earliest)} → ${esc(d.latest)}</span> — <span class="tech">HTTP ${esc(d.http)}</span> — <b>${num(d.rows.length)}</b> ردیف</p>
    ${d.messages.length ? `<div style="margin:8px 0">${d.messages.map((m) => `<div class="row" style="gap:8px;align-items:flex-start;margin-bottom:4px"><span class="tag ${msgCls(m.type)}">${esc(m.type)}</span><span class="tech" style="unicode-bidi:plaintext">${esc(m.text)}</span></div>`).join("")}</div>` : ""}
    ${rows.length ? `<div class="table-wrap inner" style="max-height:320px"><table class="grid"><thead><tr>${cols.map((c) => `<th class="nosort ltr">${esc(c)}</th>`).join("")}</tr></thead><tbody>
        ${rows.map((rw) => `<tr>${cols.map((c) => `<td class="ltr">${esc(Array.isArray(rw[c]) ? rw[c].join(", ") : rw[c] ?? "")}</td>`).join("")}</tr>`).join("")}</tbody></table></div>
      <h3 style="margin:16px 0 8px">کدام ستون کدام اطلاعات است؟</h3>
      <div class="form-grid">${SP_ROLES.map(([k, t2, req]) => `<label class="field"><span>${t2}${req ? " (الزامی)" : ""}</span><select class="ltr spMap" data-role="${k}">${opts(k, req)}</select></label>`).join("")}</div>
      <div class="form-foot"><button class="btn primary" id="btnSpSave">تأیید نگاشت و ذخیره‌ی کوئری</button>
        <span class="hint">فقط «IP مبدأ» الزامی است؛ بقیه برای تیکت Redmine و آمار استفاده می‌شوند.</span></div>`
    : `<p class="hint warn">کوئری هیچ ردیفی برنگرداند، پس ستونی برای انتخاب نیست. پیام‌های بالا، اپ و بازه را بررسی کنید؛ ستون‌ها باید همان چیزی باشند که در وب Splunk (اپ ${esc(d.app)}) می‌بینید.</p>`}
    <details style="margin-top:10px"><summary class="muted" style="cursor:pointer">کوئری ارسال‌شده</summary><div class="codebox" data-no-i18n style="margin-top:6px">${esc(d.query)}\n| head 20</div></details></div>`;
  $$(".spMap", box).forEach((x) => (x.onchange = () => (SP.map[x.dataset.role] = x.value)));
  const sv = $("#btnSpSave", box);
  if (sv) sv.onclick = (e) => withSpin(e.currentTarget, async () => {
    if (!SP.map.src || SP.map.src === "-") return toast("ستون IP مبدأ باید انتخاب شود.", "error");
    const r = await api("splunk_save_mapping", S.draft.splunk.query, SP.map, S.draft.splunk.app);
    if (!r.ok) return toast(r.error, "error");
    S.settings = r.settings; S.draft.splunk.query = r.settings.splunk.query; S.draft.splunk.fields = r.settings.splunk.fields;
    S.draft.splunk.fields_hash = r.settings.splunk.fields_hash; S.draft.splunk.app = r.settings.splunk.app;
    $("#spState").innerHTML = spStateHtml(spMappingState(S.draft));
    toast("کوئری و نگاشت ستون‌ها ذخیره شد", "ok");
  });
}

/* ================================================================ security: lock screen */
const MODE_INFO = {
  simple: ["ساده (بدون رمز)", "کلید با Windows DPAPI روی همین کاربر ویندوز محافظت می‌شود. فایل کپی‌شده جای دیگر باز نمی‌شود، ولی هر برنامه‌ای که با همین کاربر اجرا شود می‌تواند آن را باز کند."],
  password: ["رمز اصلی", "با هر بار باز کردن برنامه رمز را وارد می‌کنید. کلید با scrypt از رمز ساخته می‌شود و ذخیره نمی‌شود. امن‌ترین حالت."],
};
const LS = { mode: "simple", pw: "", pw2: "", remember: false, sig: "", errs: [], generated: "" };
/** اگر رمز با «ساخت رمز تصادفی» ساخته شده، قبل از پاک شدن از حافظه یک بار نمایش داده می‌شود. */
/* ---------------------------------------------------------------- کد بازیابی رمز (1.27.8) */
function recoveryHtml(sec) {
  const r = (sec && sec.recovery) || {};
  return `<div class="form" id="recBox"><h3>کد بازیابی رمز</h3>
    <p class="hint">اگر رمز ${sec && sec.server ? "ادمین" : sec && sec.users_enabled ? "ادمین" : "اصلی"} فراموش شود، با این کد در صفحه‌ی ${sec && sec.server ? "ورود" : "قفل"} ← «رمز را فراموش کرده‌ام» رمز تازه می‌گذارید و هیچ داده‌ای پاک نمی‌شود. کد فقط یک بار نشان داده می‌شود؛ فایلش را جای امن و جدا از این ${sec && sec.server ? "سرور" : "کامپیوتر"} نگه دارید. بدون رمز و بدون کد، تنها راه پاک کردن پوشه‌ی داده‌ی برنامه است.</p>
    <p>${r.has ? `<span class="tag ok">ساخته شده</span> <span class="muted">${r.created ? fmtDate(r.created) : ""}</span>` : `<span class="tag warn">کد بازیابی ندارید</span>`}</p>
    <button class="btn ${r.has ? "" : "primary"}" id="recNew">${r.has ? "ساخت کد تازه (کد قبلی باطل می‌شود)" : "ساخت کد بازیابی"}</button></div>`;
}
function wireRecovery(root, sec) {
  const b = $("#recNew", root); if (!b) return;
  b.onclick = () => recoveryCreate(sec);
}
async function recoveryCreate(sec, pw) {
  let cur = pw;
  if (cur === undefined) {
    cur = await openModal({ title: "کد بازیابی", body: `<p class="hint">برای ساخت کد بازیابی رمز خودتان را وارد کنید.${sec && sec.recovery && sec.recovery.has ? " کد قبلی دیگر کار نمی‌کند." : ""}</p>
        <input type="password" class="ltr" id="rcCur" autocomplete="current-password" style="width:100%">`,
      foot: `<button class="btn ghost" data-r="0">انصراف</button><button class="btn primary" data-r="1">ساخت کد</button>`,
      onOpen: (m, close) => {
        const go = () => close($("#rcCur", m).value);
        $("[data-r='0']", m).onclick = () => close(null); $("[data-r='1']", m).onclick = go;
        $("#rcCur", m).onkeydown = (e) => { if (e.key === "Enter") go(); }; setTimeout(() => $("#rcCur", m).focus(), 50);
      } });
    if (cur === null || cur === undefined) return false;
  }
  const r = await api("security_recovery_create", cur);
  if (!r.ok) { toast(r.error, "error"); return false; }
  await recoveryShow(r);
  if (S.state && r.security) S.state.security = r.security;
  recoveryNag();
  if (S.page === "settings") renderSettings();
  return true;
}
async function recoveryShow(r, note) {
  await openModal({ title: "کد بازیابی را ذخیره کنید", body: `${note ? `<p class="hint ok">${esc(note)}</p>` : ""}
      <p class="hint warn">این کد فقط همین یک بار نمایش داده می‌شود. فایلش را ذخیره کنید یا چاپ کنید و جای امن، جدا از این کامپیوتر، نگه دارید. هر کس آن را داشته باشد می‌تواند رمز را عوض کند.</p>
      <div class="codebox ltr" data-no-i18n style="font-size:17px;letter-spacing:1px;text-align:center;margin-top:10px">${esc(r.code)}</div>
      <label class="chk" style="margin-top:12px"><input type="checkbox" id="rcAck">کد را ذخیره کردم</label>`,
    foot: `<button class="btn" id="rcCopy">کپی</button><button class="btn" id="rcSave">ذخیره‌ی فایل کد…</button><button class="btn primary" id="rcOk" disabled>بستن</button>`,
    onOpen: (m, close) => {
      $("#rcCopy", m).onclick = async () => { try { await navigator.clipboard.writeText(r.code); toast("کپی شد", "ok"); } catch (e) { toast("کپی ممکن نشد؛ دستی انتخاب کنید", "warn"); } };
      $("#rcSave", m).onclick = async () => { const x = await api("save_export", r.filename || "AutoKRP-recovery-code.txt", r.file, false);
        if (!x.ok) return toast(x.error, "error"); if (!x.cancelled) { toast("ذخیره شد" + (x.path ? ": " + x.path : ""), "ok"); $("#rcAck", m).checked = true; $("#rcOk", m).disabled = false; } };
      $("#rcAck", m).onchange = (e) => ($("#rcOk", m).disabled = !e.target.checked);
      $("#rcOk", m).onclick = () => close(true);
    } });
}
function recoverFormHtml(sec) {
  const r = (sec && sec.recovery) || {}, usr = !!sec.users_enabled;
  const wipe = `<p class="hint">اگر کد بازیابی هم ندارید، تنها راه: برنامه را کامل ببندید و پوشه‌ی داده‌ی برنامه را پاک کنید؛ همه‌چیز پاک می‌شود و برنامه از اول شروع می‌شود.</p>
    ${sec.data_dir ? `<div class="codebox ltr" data-no-i18n style="margin-top:6px">${esc(sec.data_dir)}</div>` : ""}`;
  if (!r.has) return `<p class="hint warn">برای این برنامه کد بازیابی ساخته نشده است.</p>${wipe}`;
  return `<p class="hint">کد بازیابی (یا فایل آن) را بدهید و رمز تازه بگذارید؛ هیچ داده‌ای پاک نمی‌شود.</p>
    ${usr ? `<label class="field"><span>نام کاربری ادمین</span><input type="text" class="ltr" id="rvUser" value="admin" autocomplete="username"></label>` : ""}
    <label class="field"><span>کد بازیابی</span><textarea class="ltr" id="rvCode" rows="2" placeholder="XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX"></textarea></label>
    <label class="field"><span>یا فایل کد</span><input type="file" id="rvFile" accept=".txt,text/plain"></label>
    <label class="field"><span>رمز تازه</span><input type="password" class="ltr" id="rvPw" autocomplete="new-password"></label>
    <label class="field"><span>تکرار رمز تازه</span><input type="password" class="ltr" id="rvPw2" autocomplete="new-password"></label>
    <div class="form-foot"><button class="btn primary" id="rvGo">عوض کردن رمز</button></div><p class="test-res err" id="rvErr"></p>
    <details style="margin-top:8px"><summary class="muted" style="cursor:pointer">کد بازیابی را هم ندارم</summary>${wipe}</details>`;
}
function wireRecover(root) {
  const f = $("#rvFile", root);
  if (f) f.onchange = () => { const x = f.files[0]; if (!x) return; if (x.size > 65536) return toast("فایل کد بازیابی نیست.", "error");
    const rd = new FileReader(); rd.onload = () => { $("#rvCode", root).value = String(rd.result || ""); }; rd.readAsText(x); };
  const go = $("#rvGo", root); if (!go) return;
  go.onclick = (e) => withSpin(e.currentTarget, async () => {
    const pw = $("#rvPw", root).value, er = $("#rvErr", root); er.textContent = "";
    if (pw !== $("#rvPw2", root).value) { er.textContent = I18N.t("رمز و تکرار آن یکی نیستند."); return; }
    const u = $("#rvUser", root);
    const r = await api("security_recover", $("#rvCode", root).value, pw, u ? u.value.trim() : "");
    if (!r.ok) { er.textContent = r.error; return; }
    await recoveryShow(r, "رمز عوض شد و برنامه باز شد. کد بازیابی قبلی دیگر کار نمی‌کند؛ این کد تازه را ذخیره کنید.");
    roleSig = ""; LS.sig = ""; await refreshState(); loadSettings();
  });
}
function recoveryNag() {   // 1.27.8: یادآوری غیرمزاحم (نه پنجره): ادمینِ حالت رمز بدون کد بازیابی
  const st = S.state || {}, sec = st.security || {}, b = $("#recBadge");
  if (!b) return;
  const need = !!sec.recovery && !sec.recovery.has && (sec.server || sec.mode === "password") && (!st.me || st.me.role === "admin");
  b.hidden = !need;
  b.onclick = () => recoveryCreate(sec);
}
async function showGenerated(pw) {
  if (!pw || pw !== LS.generated) return;
  LS.generated = "";
  await openModal({ title: "رمز اصلی را ذخیره کنید", body: `<p class="hint warn">این رمز فقط همین یک بار نمایش داده می‌شود. اگر گم شود، اسرار قابل بازیابی نیستند.</p>
    <div class="codebox" style="font-size:15px;margin-top:10px">${esc(pw)}</div>`,
    foot: `<button class="btn" id="gpCopy">کپی</button><button class="btn primary" id="gpOk">ذخیره کردم</button>`,
    onOpen: (m, close) => {
      $("#gpCopy", m).onclick = async () => { try { await navigator.clipboard.writeText(pw); toast("کپی شد", "ok"); } catch (e) { toast("کپی ممکن نشد؛ دستی انتخاب کنید", "warn"); } };
      $("#gpOk", m).onclick = () => close(true);
    } });
}
function pwRulesHtml(errs, pw, strong) {
  if (!strong) return `<div class="pw-rules"><span class="tag mute">الزامات رمز قوی خاموش است</span></div>`;
  const rules = ["حداقل ۱۲ نویسه", "حداقل یک حرف", "حداقل یک عدد", "حداقل یک علامت (مثل ! @ # -)"];
  return `<div class="pw-rules">${rules.map((r) => `<span class="tag ${!pw ? "mute" : errs.includes(r) ? "err" : "ok"}">${r}</span>`).join("")}</div>`;
}
function pwFields(sec, withRemember = true) {
  return `<div class="form-grid" style="margin-top:6px">
      <label class="field"><span>رمز اصلی</span><div class="row"><input type="password" class="ltr" id="lsPw" value="${esc(LS.pw)}" autocomplete="new-password"><button class="btn" id="lsGen" type="button">ساخت رمز تصادفی</button></div></label>
      <label class="field"><span>تکرار رمز</span><input type="password" class="ltr" id="lsPw2" value="${esc(LS.pw2)}" autocomplete="new-password"></label></div>
    <div id="lsRules">${pwRulesHtml(LS.errs, LS.pw, sec.strong_policy)}</div>
    <div class="row" style="gap:20px;margin-top:10px;flex-wrap:wrap">
      <label class="chk"><input type="checkbox" id="lsStrong" ${sec.strong_policy ? "checked" : ""}>الزامات رمز قوی (حرف، عدد، علامت، ۱۲ نویسه)</label>
      ${withRemember ? `<label class="chk"><input type="checkbox" id="lsRemember" ${LS.remember ? "checked" : ""}>باز شدن خودکار در این کامپیوتر</label>` : ""}</div>
    ${withRemember ? `<p class="hint">«باز شدن خودکار» برای کار خودکار بعد از ری‌استارت لازم است. کلید با DPAPI روی همین کاربر ویندوز نگه داشته می‌شود؛ امنیتش مثل حالت ساده است ولی رمز اصلی هم دارید.</p>` : ""}`;
}
function wirePwFields(root, sec) {
  const upd = async () => {
    const r = await api("security_check_password", LS.pw); LS.errs = r.errors || [];
    $("#lsRules", root).innerHTML = pwRulesHtml(LS.errs, LS.pw, sec.strong_policy);
  };
  $("#lsPw", root).oninput = (e) => { LS.pw = e.target.value; upd(); };
  $("#lsPw2", root).oninput = (e) => (LS.pw2 = e.target.value);
  $("#lsGen", root).onclick = async () => {
    const r = await api("security_generate"); if (!r.ok) return toast(r.error, "error");
    LS.pw = LS.pw2 = LS.generated = r.password; $("#lsPw", root).value = $("#lsPw2", root).value = r.password;
    $("#lsPw", root).type = "text"; upd();
    toast("رمز ساخته شد؛ آن را کپی و در password manager ذخیره کنید", "warn");
  };
  $("#lsStrong", root).onchange = async (e) => {
    const r = await api("security_policy", e.target.checked); if (!r.ok) return toast(r.error, "error");
    sec.strong_policy = e.target.checked; upd();
  };
  const rem = $("#lsRemember", root); if (rem) rem.onchange = (e) => (LS.remember = e.target.checked);
  upd();
}
function pwValid(sec) {
  if (LS.pw !== LS.pw2) { toast("رمز و تکرار آن یکسان نیستند", "error"); return false; }
  if (!LS.pw || (sec.strong_policy && LS.errs.length)) { toast("رمز شرایط لازم را ندارد", "error"); return false; }
  return true;
}
function renderLock(sec) {
  const scr = $("#lockScreen");
  // تا اولین وضعیت امنیتی نرسیده، برنامه پنهان است (قبلاً داشبورد یک لحظه پیش از صفحه‌ی قفل دیده می‌شد)
  document.body.classList.remove("booting");
  if (S.wiped) return;
  const open = sec && sec.unlocked && !sec.ui_locked;
  const needLogin = sec && sec.users_enabled && sec.unlocked && !sec.ui_locked && S.state && !S.state.me;
  if (sec && open && !needLogin) recoveryNag();
  if (!sec || (open && !needLogin)) { if (!scr.hidden) { scr.hidden = true; LS.sig = ""; loadSettings().then(() => { if (S.page === "settings") renderSettings(); }); } return; }
  const sig = JSON.stringify([sec.initialized, sec.mode, sec.unlocked, sec.ui_locked, sec.unsupported, sec.users_enabled, I18N.lang]);
  if (!scr.hidden && sig === LS.sig) return;
  LS.sig = sig; scr.hidden = false;
  const b = (S.state && S.state.branding) || {};
  const head = `<div class="lc-head"><div class="logo ${b.logo_data ? "has-img" : ""}">${logoHtml(b)}</div><div><h1>${esc(b.app_name || "AutoKRP")}</h1><p class="muted" style="margin:0">${esc(b.subtitle || "")}</p></div>
    <button class="btn sm ghost lang-btn lang-toggle" style="margin-inline-start:auto" title="English / فارسی" data-no-i18n><svg><use href="#i-globe"/></svg>${I18N.lang === "en" ? "فارسی" : "English"}</button></div>`;
  const card = $("#lockCard");
  if (!sec.initialized && !sec.unsupported) {
    if (!MODE_INFO[LS.mode]) LS.mode = "simple";
    card.innerHTML = head + `<h2>محافظت از اسرار</h2><p class="hint">توکن‌های API و یوزر/پسوردها در یک فایل رمزنگاری‌شده (AES-256-GCM) نگهداری می‌شوند. روش محافظت از کلید را انتخاب کنید؛ بعداً از «تنظیمات ← امنیت» قابل تغییر است.</p>
      <div class="mode-cards" style="grid-template-columns:repeat(2,1fr)">${Object.entries(MODE_INFO).map(([k, [t, d]]) => `<button class="mode-card ${LS.mode === k ? "on" : ""}" data-m="${k}"><b>${t}</b><span>${d}</span></button>`).join("")}</div>
      <div id="lsBody"></div><div class="form-foot"><button class="btn primary" id="lsGo" style="margin-inline-start:auto">ادامه</button></div>`;
    const body = () => {
      $$(".mode-card", card).forEach((x) => x.classList.toggle("on", x.dataset.m === LS.mode));
      $("#lsBody", card).innerHTML = LS.mode === "password" ? pwFields(sec) : `<p class="hint">در این حالت رمزی لازم نیست و برنامه همیشه خودکار باز می‌شود.</p>`;
      if (LS.mode === "password") wirePwFields(card, sec);
    };
    $$(".mode-card", card).forEach((x) => (x.onclick = () => { LS.mode = x.dataset.m; body(); }));
    $("#lsGo", card).onclick = (e) => withSpin(e.currentTarget, async () => {
      if (LS.mode === "password" && !pwValid(sec)) return;
      const r = await api("security_setup", LS.mode, LS.mode === "password" ? LS.pw : "", LS.remember);
      if (!r.ok) return toast(r.error, "error");
      const used = LS.pw; LS.pw = LS.pw2 = ""; toast("تنظیم امنیت انجام شد", "ok"); await refreshState();
      if (LS.mode === "password") { S.recNagged = true; await showGenerated(used); await recoveryCreate((S.state || {}).security, used); }
    });
    body();
  } else if (sec.mode === "password") {
    const soft = sec.unlocked && sec.ui_locked;
    const usr = !!sec.users_enabled;
    card.innerHTML = head + `<h2>${usr ? "ورود" : "برنامه قفل است"}</h2>
      <p class="hint">${soft ? `رابط قفل است؛ کارهای زمان‌بندی‌شده در پس‌زمینه ادامه دارند. ${usr ? "با نام کاربری و رمز خود وارد شوید." : "برای دیدن یا تغییر چیزی رمز اصلی را وارد کنید."}`
        : "قفل کامل: کلید در حافظه نیست و هیچ کار خودکاری تا وارد کردن رمز اجرا نمی‌شود."}</p>
      ${usr ? `<label class="field" style="margin-top:10px"><span>نام کاربری</span><input type="text" class="ltr" id="lsUser" autocomplete="username" value="${esc(LS.user || "")}"></label>` : ""}
      <div class="row" style="margin-top:10px"><input type="password" class="ltr" id="lsUnlock" ${usr ? `placeholder="رمز"` : ""} autofocus><button class="btn primary" id="lsOpen">${usr ? "ورود" : "باز کردن"}</button></div>
      <p class="test-res err" id="lsErr"></p>
      <details style="margin-top:14px"><summary class="muted" style="cursor:pointer">رمز را فراموش کرده‌ام</summary>${recoverFormHtml(sec)}</details>`;
    const go = () => withSpin($("#lsOpen", card), async () => {
      const u = $("#lsUser", card); if (u) LS.user = u.value.trim();
      const r = await api("security_unlock", $("#lsUnlock", card).value, u ? u.value.trim() : "");
      if (!r.ok) { $("#lsErr", card).textContent = r.error; $("#lsUnlock", card).select(); return; }
      $("#lsUnlock", card).value = ""; roleSig = ""; LS.sig = ""; await refreshState(); loadSettings();
    });
    $("#lsOpen", card).onclick = go;
    $("#lsUnlock", card).onkeydown = (e) => { if (e.key === "Enter") go(); };
    wireRecover(card); setTimeout(() => (($("#lsUser", card) && !LS.user) ? $("#lsUser", card) : $("#lsUnlock", card)).focus(), 50);
  } else {
    card.innerHTML = head + `<h2>باز کردن فایل اسرار ممکن نشد</h2>
      <p class="hint">${sec.unsupported ? "فایل اسرار با «متغیر محیطی» ساخته شده است. این حالت به دلایل امنیتی حذف شده است؛ برای ادامه همه‌ی داده‌ها را پاک کنید و حالت جدید را انتخاب کنید."
        : "کلید حالت ساده با DPAPI روی کاربر ویندوز دیگری ساخته شده یا فایل آسیب دیده است."}</p>
      ${sec.unsupported ? "" : `<div class="form-foot"><button class="btn" id="lsRetry">تلاش دوباره</button></div>`}
      <p class="hint" style="margin-top:12px">برای شروع از نو: برنامه را کامل ببندید و پوشه‌ی داده‌ی برنامه را پاک کنید (همه‌چیز پاک می‌شود).</p>
      ${sec.data_dir ? `<div class="codebox ltr" data-no-i18n style="margin-top:6px">${esc(sec.data_dir)}</div>` : ""}`;
    const rt = $("#lsRetry", card); if (rt) rt.onclick = () => { LS.sig = ""; api("security_status").then(() => refreshState()); };
  }
}
function resetHtml(withPw) {   // withPw: از داخل برنامه (نه صفحه‌ی قفل) رمز خود ادمین هم لازم است
  return `<div class="sec"><h3 style="color:var(--err)">پاک کردن کامل برنامه</h3>
    <p class="hint warn">همه‌چیز برای همیشه پاک می‌شود و برنامه به حالت نصب اول برمی‌گردد:</p>
    <ul class="hint" style="margin:6px 0 10px;padding-inline-start:20px;line-height:1.9">
      <li>همه‌ی توکن‌ها، پسوردها، یوزر و پسورد دستگاه‌ها و پسورد ایمیل</li>
      <li>همه‌ی تنظیمات، زمان‌بندی‌ها، قالب تیکت، لوگو و آیکون</li>
      <li>دیتابیس IPها، تاریخچه، آمار، فهرست دستگاه‌ها و اسکریپت‌ها</li>
      <li>همه‌ی نسخه‌های پشتیبان کانفیگ، خروجی‌های SSH و کلیدهای میزبان</li>
      <li>فایل‌های اجراها، خروجی‌های داخل پوشه‌ی برنامه و لاگ‌ها</li></ul>
    <p class="hint">فایل‌های اسرار و داده‌های رمزشده پیش از حذف با داده‌ی تصادفی بازنویسی می‌شوند. فایل‌هایی که خودتان در مسیر دیگری ذخیره کرده‌اید پاک نمی‌شوند. پس از پاک‌سازی، برنامه بسته می‌شود.</p>
    <div class="row" style="flex-wrap:wrap">${withPw ? `<input type="password" class="ltr" id="lsResetPw" autocomplete="current-password" placeholder="رمز خودتان">` : ""}<input type="text" class="ltr" id="lsReset" placeholder="برای تأیید RESET را تایپ کنید"><button class="btn danger" id="lsResetGo">پاک کردن همه‌چیز</button></div></div>`;
}
function wireReset(root) {
  $("#lsResetGo", root).onclick = async (e) => {
    if (($("#lsReset", root).value || "").trim().toUpperCase() !== "RESET") return toast("برای پاک کردن، کلمه‌ی RESET را دقیق تایپ کنید.", "error");
    await withSpin(e.currentTarget, async () => {
      const pw = $("#lsResetPw", root);
      const r = await api("security_reset", $("#lsReset", root).value, pw ? pw.value : "");
      if (!r.ok) return toast(r.error, "error");
      showWiped(r);
    });
  };
}
function showWiped(r) {
  S.wiped = true;
  const scr = $("#lockScreen"); scr.hidden = false;
  $("#lockCard").innerHTML = `<h2>همه‌ی داده‌ها پاک شد</h2>
    <p class="hint">برنامه به حالت نصب اول برگشت. ${r.closing ? "پنجره تا چند لحظه‌ی دیگر بسته می‌شود؛" : ""} برای استفاده‌ی دوباره، برنامه را باز کنید.</p>
    ${r.task_left ? `<p class="hint warn">تسک «اجرای خودکار با روشن شدن ویندوز» به دسترسی Administrator نیاز داشت و حذف نشد (داده‌ای ندارد و دیگر کاری نمی‌کند). برای حذف: <span class="ltr">AutoKRP.exe --remove-service</span></p>` : ""}
    ${r.left && r.left.length ? `<p class="hint warn">این مسیرها حذف نشدند (احتمالاً در حال استفاده بودند):</p><div class="codebox">${r.left.map(esc).join("<br>")}</div>` : ""}`;
}
$("#btnLock").addEventListener("click", async () => {
  if (WEB) return webLogout();
  const r = await api("security_lock", false); if (!r.ok) return toast(r.error, "error"); refreshState();
});

/* ================================================================ security: settings tab */
function renderSecurityTab(body) {
  const sec = (S.state && S.state.security) || {};
  if (sec.server) return renderServerSecurity(body, sec);
  const cur = MODE_INFO[sec.mode] || ["—", ""];
  LS.pw = LS.pw2 = ""; LS.mode = LS.mode || sec.mode;
  body.innerHTML = `<div class="form"><h3>وضعیت</h3>
      <dl class="kv"><dt>حالت فعلی</dt><dd>${cur[0]}</dd><dt>تعداد اسرار ذخیره‌شده</dt><dd>${num(sec.count)}</dd>
      <dt>رمزنگاری</dt><dd class="ltr">AES-256-GCM · scrypt (n=2^15, r=8, p=1) · padded binary file</dd>
      ${sec.mode === "password" ? `<dt>باز شدن خودکار</dt><dd>${sec.remember ? "روشن" : "خاموش"}</dd>` : ""}</dl>
      <p class="hint">${cur[1]}</p>
      <div class="row" style="gap:20px;margin-top:10px;flex-wrap:wrap">
        <label class="switch"><input type="checkbox" id="secStrong" ${sec.strong_policy ? "checked" : ""}><span class="track"><span class="thumb"></span></span>الزامات رمز قوی</label>
        ${sec.mode === "password" && (sec.user_count || 0) <= 1 ? `<label class="switch"><input type="checkbox" id="secRemember" ${sec.remember ? "checked" : ""}><span class="track"><span class="thumb"></span></span>باز شدن خودکار در این کامپیوتر</label>` : ""}
        ${sec.mode === "password" ? `<button class="btn sm" id="secLockNow"><svg><use href="#i-lock"/></svg>قفل رابط</button><button class="btn sm danger-ghost" id="secLockFull">قفل کامل (توقف کارهای خودکار)</button>` : ""}</div>
      ${sec.mode === "password" ? `<p class="hint" style="margin-top:8px">«قفل رابط»: بدون رمز نمی‌توان چیزی دید یا تغییر داد، ولی کارهای زمان‌بندی‌شده ادامه دارند (کلید در حافظه می‌ماند). «قفل کامل»: کلید از حافظه پاک می‌شود و هیچ کار خودکاری تا وارد کردن رمز اجرا نمی‌شود.</p>` : ""}</div>
    ${sec.mode === "password" ? `<div class="form"><h3>قفل خودکار</h3><div class="row" style="gap:10px;align-items:end;flex-wrap:wrap">
      <label class="field"><span>قفل رابط بعد از بی‌کاری (دقیقه، ۰ = خاموش)</span><input type="number" min="0" max="1440" id="secAuto" value="${esc(sec.auto_lock_minutes || 0)}"></label>
      <button class="btn" id="secAutoSave">ذخیره</button></div><p class="hint">کارهای زمان‌بندی‌شده بعد از قفل ادامه دارند.</p></div>` : ""}
    <div class="form" id="secUsers"><h3>کاربران</h3><p class="hint">مدیریت کاربران و دسترسی هر کاربر به ابزارها حالا در تب «کاربران و دسترسی‌ها» است. <button class="btn sm" type="button" data-goset="users">رفتن به کاربران</button></p></div>
    <div class="form" ${sec.users_enabled ? "hidden" : ""}><h3>تغییر حالت یا رمز</h3><p class="hint">همه‌ی اسرار با کلید جدید دوباره رمز می‌شوند.</p>
      <div class="mode-cards">${Object.entries(MODE_INFO).map(([k, [t, d]]) => `<button class="mode-card ${LS.mode === k ? "on" : ""}" data-m="${k}"><b>${t}${k === sec.mode ? " (فعلی)" : ""}</b><span>${d}</span></button>`).join("")}</div>
      <div id="secBody"></div>
      ${sec.mode === "password" ? `<label class="field" style="margin-top:12px;max-width:420px"><span>رمز فعلی (برای تأیید)</span><input type="password" class="ltr" id="secCur"></label>` : ""}
      <div class="form-foot"><button class="btn primary" id="secApply">اعمال</button></div></div>
    ${sec.mode === "password" ? recoveryHtml(sec) : ""}
    <div class="form"><h3>پاک کردن اسرار</h3>${resetHtml(sec.mode === "password")}</div>`;
  const draw = () => {
    $$(".mode-card", body).forEach((x) => x.classList.toggle("on", x.dataset.m === LS.mode));
    const sb = $("#secBody", body);
    sb.innerHTML = LS.mode === "password" ? pwFields(sec) : `<p class="hint">بدون رمز؛ کلید با DPAPI محافظت می‌شود.</p>`;
    if (LS.mode === "password") wirePwFields(body, sec);
  };
  $$(".mode-card", body).forEach((x) => (x.onclick = () => { LS.mode = x.dataset.m; draw(); }));
  draw();
  const sa = $("#secAutoSave", body);
  if (sa) sa.onclick = async () => { const r = await api("security_auto_lock", Number($("#secAuto", body).value || 0)); toast(r.ok ? "ذخیره شد" : r.error, r.ok ? "ok" : "error"); refreshState(); };
  $$("[data-goset]", body).forEach((b) => (b.onclick = () => { S.setTab = b.dataset.goset; renderSettings(); }));
  $("#secStrong", body).onchange = async (e) => { const r = await api("security_policy", e.target.checked); toast(r.ok ? "ذخیره شد" : r.error, r.ok ? "ok" : "error"); refreshState(); };
  const rem = $("#secRemember", body);
  if (rem) rem.onchange = async (e) => {
    let current = "";
    if (e.target.checked) {
      current = await openModal({ title: "تأیید با رمز فعلی", body: `<input type="password" class="ltr" id="rmCur" autofocus>`,
        foot: `<button class="btn primary" id="rmOk">تأیید</button>`, onOpen: (m, close) => ($("#rmOk", m).onclick = () => close($("#rmCur", m).value)) });
      if (!current) { e.target.checked = false; return; }
    }
    const r = await api("security_set_remember", e.target.checked, current);
    if (!r.ok) { e.target.checked = !e.target.checked; return toast(r.error, "error"); }
    toast("ذخیره شد", "ok"); refreshState();
  };
  const ln = $("#secLockNow", body); if (ln) ln.onclick = () => $("#btnLock").click();
  const lf = $("#secLockFull", body);
  if (lf) lf.onclick = async () => {
    const ok = await confirm2({ title: "قفل کامل", confirm: "قفل کامل", danger: true, body: "<p>کلید از حافظه پاک می‌شود، اجرای در جریان متوقف می‌شود و هیچ کار زمان‌بندی‌شده‌ای تا وارد کردن رمز اجرا نمی‌شود.</p>" });
    if (!ok) return;
    const r = await api("security_lock", true); if (!r.ok) return toast(r.error, "error"); refreshState();
  };
  $("#secApply", body).onclick = (e) => withSpin(e.currentTarget, async () => {
    if (LS.mode === "password" && !pwValid(sec)) return;
    const ok = await confirm2({ title: "تغییر حالت امنیتی", confirm: "اعمال", body: `<p>حالت به «${MODE_INFO[LS.mode][0]}» تغییر می‌کند و همه‌ی اسرار دوباره رمز می‌شوند.</p>` });
    if (!ok) return;
    const r = await api("security_change", LS.mode, LS.pw, LS.remember, ($("#secCur", body) || {}).value || "");
    if (!r.ok) return toast(r.error, "error");
    const used = LS.pw;
    toast("تغییر اعمال شد", "ok"); await refreshState(); renderSettings();
    if (LS.mode === "password") await showGenerated(used);
  });
  wireReset(body); wireRecovery(body, sec);
}

/* ================================================================ امنیت حالت سرور */
async function renderServerSecurity(body, sec) {
  body.innerHTML = `<div class="form" id="srvUsers"><h3>کاربران</h3><p class="hint">مدیریت کاربران و دسترسی هر کاربر به ابزارها در تب «کاربران و دسترسی‌ها» است. <button class="btn sm" type="button" data-goset="users">رفتن به کاربران</button></p></div><div class="form" id="srvCfg"><div class="empty">…</div></div>
    <div class="form"><h3>رمزها</h3><div class="row" style="gap:20px;flex-wrap:wrap;align-items:center">
      <label class="switch"><input type="checkbox" id="secStrong" ${sec.strong_policy ? "checked" : ""}><span class="track"><span class="thumb"></span></span>الزامات رمز قوی برای کاربران</label>
      <button class="btn sm danger-ghost" id="srvFull">قفل کامل (توقف کارها و پاک کردن کلید از حافظه)</button></div>
      <p class="hint">«قفل کامل»: همه‌ی نشست‌ها بسته، کارهای زمان‌بندی‌شده متوقف و کلید از حافظه پاک می‌شود؛ با ورود بعدی یک کاربر دوباره راه می‌افتد.</p></div>
    ${recoveryHtml(sec)}
    <div class="form"><h3>پاک کردن کامل</h3><p class="hint warn">فقط ادمین و فقط از مرورگرِ خود سیستم سرور (localhost) ممکن است. سرور بعد از پاک‌سازی بسته می‌شود.</p>${resetHtml(true)}</div>`;
  $$("[data-goset]", body).forEach((b) => (b.onclick = () => { S.setTab = b.dataset.goset; renderSettings(); }));
  $("#secStrong", body).onchange = async (e) => { const r = await api("security_policy", e.target.checked); toast(r.ok ? "ذخیره شد" : r.error, r.ok ? "ok" : "error"); };
  $("#srvFull", body).onclick = async () => {
    if (!(await confirm2({ title: "قفل کامل سرور", danger: true, confirm: "قفل کامل", body: "<p>همه‌ی کاربران خارج می‌شوند، کارها متوقف می‌شوند و کلید از حافظه پاک می‌شود.</p>" }))) return;
    await api("security_lock", true);
  };
  wireReset(body); wireRecovery(body, sec);
  const r = await api("server_config"); if (!r.ok) { $("#srvCfg", body).innerHTML = `<p class="hint err">${esc(r.error)}</p>`; return; }
  drawServerCfg($("#srvCfg", body), r.server);
}
async function certUpload(box) {
  const st = { files: [] };
  await openModal({ title: "بارگذاری گواهی HTTPS شرکت",
    body: `<p class="hint">یکی از این دو را انتخاب کنید:</p><ul class="hint" style="margin:4px 0 0;padding-inline-start:20px"><li>فایل PFX/P12 (گواهی، کلید و زنجیره در یک فایل)</li><li>فایل گواهی PEM (crt/cer/pem، ترجیحاً با گواهی‌های میانی) به‌همراه فایل کلید (key)</li></ul>
      <div class="row" style="gap:8px;margin:10px 0"><button class="btn" id="cuPick">انتخاب فایل…</button><span class="muted" id="cuList">فایلی انتخاب نشده است.</span></div>
      <label class="field"><span>رمز PFX یا کلید (اگر دارد)</span><input type="password" id="cuPw" autocomplete="off" class="ltr"></label>
      <p class="hint">رمز فقط برای باز کردن همین یک بار استفاده و ذخیره نمی‌شود. کلید بدون رمز و با دسترسی محدود روی سرور نگه داشته می‌شود (برای HTTPS پیش از ورود کاربران لازم است). فایل‌های آپلودشده بعد از نصب پاک می‌شوند.</p>`,
    foot: `<button class="btn ghost" data-x="0">انصراف</button><button class="btn primary" data-x="1">بررسی و نصب</button>`,
    onOpen: (m, close) => {
      const list = () => { $("#cuList", m).textContent = st.files.length ? st.files.map((f) => f.name).join("، ") : "فایلی انتخاب نشده است."; };
      $("#cuPick", m).onclick = async () => {
        if (st.files.length >= 2) st.files = [];
        const up = await webPickFile(".pfx,.p12,.pem,.crt,.cer,.key");
        if (!up.ok) return toast(up.error, "error");
        if (up.path) { st.files.push(up); list(); }
      };
      $("[data-x='0']", m).onclick = () => close();
      $("[data-x='1']", m).onclick = (e) => withSpin(e.currentTarget, async () => {
        if (!st.files.length) return toast("فایل گواهی را انتخاب کنید.", "warn");
        const r = await api("server_cert_upload", st.files.map((f) => f.path), $("#cuPw", m).value);
        $("#cuPw", m).value = ""; st.files = []; list();
        if (!r.ok) return toast(r.error, "error");
        close(); toast("گواهی شرکت نصب شد", "ok");
        (r.warnings || []).forEach((w) => toast(w, "warn"));
        drawServerCfg(box, r.server);
      });
    } });
}
function drawServerCfg(box, c) {
  const me = (S.state && S.state.me && S.state.me.username) || "";
  box.innerHTML = `<h3>سرور وب</h3><div class="form-grid">
      <label class="field"><span>پورت HTTPS</span><input type="number" min="1" max="65535" id="scPort" value="${esc(c.port)}"></label>
      <label class="field"><span>آدرس bind (0.0.0.0 = همه‌ی کارت‌های شبکه)</span><input type="text" class="ltr" id="scBind" value="${esc(c.bind || "0.0.0.0")}"></label>
      <label class="field"><span>پایان نشست بعد از بی‌کاری (دقیقه)</span><input type="number" min="1" max="1440" id="scIdle" value="${esc(c.session_timeout_minutes)}"></label>
      <label class="field"><span>حداکثر عمر نشست کاربران AD (ساعت، ۰ = بدون سقف)</span><input type="number" min="0" max="168" id="scAdH" value="${esc(c.ad_session_hours ?? 12)}"></label>
      <label class="field"><span>قفل پس از چند ورود ناموفق (۰ = خاموش)</span><input type="number" min="0" max="50" id="scTh" value="${esc(c.lockout_threshold)}"></label>
      <label class="field"><span>مدت قفل (دقیقه)</span><input type="number" min="1" max="1440" id="scLm" value="${esc(c.lockout_minutes)}"></label>
      <label class="field"><span>حداکثر اتصال هم‌زمان (کل)</span><input type="number" min="10" max="5000" id="scMx" value="${esc(c.max_connections || 200)}"></label>
      <label class="field"><span>حداکثر اتصال هم‌زمان هر IP</span><input type="number" min="4" max="1000" id="scMxIp" value="${esc(c.max_connections_per_ip || 40)}"></label>
      <label class="field wide"><span>شبکه‌های مجاز (هر خط یک IP یا رنج؛ خالی = همه). خود سیستم سرور همیشه مجاز است.</span>
        <textarea class="ltr" id="scNets" style="min-height:90px" placeholder="10.10.0.0/16&#10;192.168.1.20">${esc((c.allowed_networks || []).join("\n"))}</textarea></label></div>
    <div class="form-foot"><button class="btn primary" id="scSave">ذخیره</button><span class="hint">تغییر پورت و bind بعد از اجرای دوباره‌ی سرور اعمال می‌شود. پورت را در فایروال ویندوز باز کنید. اجرای خودکار با روشن شدن ویندوز: از پنجره‌ی وضعیت سرور روی خود سیستم.</span></div>
    <div class="sec"><h3>گواهی HTTPS</h3>${c.cert ? `<dl class="kv"><dt>نوع</dt><dd>${c.cert.self_signed ? "ساخته‌شده توسط برنامه (self-signed) — مرورگر بار اول هشدار می‌دهد" : "صادرشده (گواهی شرکت)"}</dd>
      <dt>موضوع</dt><dd class="ltr" style="text-align:start">${esc(c.cert.subject)}</dd>
      ${c.cert.self_signed ? "" : `<dt>صادرکننده</dt><dd class="ltr" style="text-align:start">${esc(c.cert.issuer)}</dd>`}
      <dt>نام‌ها</dt><dd class="ltr" style="text-align:start">${esc((c.cert.names || []).join(", ") || "—")}</dd>
      <dt>اعتبار تا</dt><dd class="ltr" style="text-align:start">${fmtDate(c.cert.not_after)} ${c.cert.days_left < 30 ? `<span class="tag ${c.cert.days_left < 7 ? "err" : "warn"}">${num(c.cert.days_left)} روز مانده</span>` : ""}</dd>
      ${c.cert.chain ? `<dt>گواهی میانی</dt><dd>${num(c.cert.chain)}</dd>` : ""}
      <dt>اثر انگشت SHA-256</dt><dd class="ltr tech" style="text-align:start;word-break:break-all">${esc(c.cert.sha256)}</dd></dl>` : `<p class="hint warn">گواهی خوانده نشد.</p>`}
      <div class="row" style="gap:8px;margin-top:10px;flex-wrap:wrap"><button class="btn" id="scCertUp">بارگذاری گواهی شرکت…</button>
        ${c.cert && !c.cert.self_signed ? `<button class="btn ghost" id="scCertSelf">برگشت به گواهی خودساخته</button>` : ""}</div>
      <p class="hint">گواهی تازه بلافاصله برای اتصال‌های بعدی اعمال می‌شود (بدون اجرای دوباره). کاربران پیش از قبول هشدار مرورگر، اثر انگشت را با همین مقدار مقایسه کنند.</p></div>
    <div class="sec"><h3>نشست‌های فعال</h3><div class="table-wrap inner"><table class="grid"><thead><tr><th class="nosort">کاربر</th><th class="nosort">نقش</th><th class="nosort">IP</th><th class="nosort">ورود</th><th class="nosort">آخرین فعالیت</th><th class="nosort"></th></tr></thead><tbody>
      ${(c.sessions || []).map((x) => `<tr><td class="ltr">${esc(x.username)}${x.username === me ? ` <span class="tag info">شما</span>` : ""}</td><td>${esc(ROLE_FA[x.role] || x.role)}</td><td class="ltr">${esc(x.ip)}</td>
        <td class="ltr">${fmtDate(x.since)}</td><td class="ltr">${fmtDate(x.seen)}</td><td><button class="btn sm danger-ghost" data-kill="${esc(x.id)}">بستن</button></td></tr>`).join("") || `<tr><td colspan="6"><div class="empty">نشستی نیست.</div></td></tr>`}</tbody></table></div></div>`;
  $("#scSave", box).onclick = (e) => withSpin(e.currentTarget, async () => {
    const r = await api("server_save", { port: Number($("#scPort", box).value), bind: $("#scBind", box).value.trim(), session_timeout_minutes: Number($("#scIdle", box).value),
      ad_session_hours: Number($("#scAdH", box).value), lockout_threshold: Number($("#scTh", box).value), lockout_minutes: Number($("#scLm", box).value),
      max_connections: Number($("#scMx", box).value), max_connections_per_ip: Number($("#scMxIp", box).value),
      allowed_networks: $("#scNets", box).value.split(/\r?\n/).map((x) => x.trim()).filter(Boolean) });
    if (!r.ok) return toast(r.error, "error");
    toast(r.restart ? "ذخیره شد؛ پورت/bind بعد از اجرای دوباره‌ی سرور اعمال می‌شود" : "ذخیره شد", "ok"); drawServerCfg(box, r.server);
  });
  $("#scCertUp", box).onclick = () => certUpload(box);
  if ($("#scCertSelf", box)) $("#scCertSelf", box).onclick = async () => {
    if (!(await confirm2({ title: "برگشت به گواهی خودساخته", body: "<p>یک گواهی self-signed تازه ساخته و جایگزین می‌شود؛ گواهی فعلی پشتیبان گرفته می‌شود. مرورگرها دوباره هشدار می‌دهند.</p>", confirm: "جایگزین کن" }))) return;
    const r = await api("server_cert_selfsigned"); if (!r.ok) return toast(r.error, "error");
    toast("گواهی خودساخته جایگزین شد", "ok"); drawServerCfg(box, r.server);
  };
  $$("[data-kill]", box).forEach((b) => (b.onclick = async () => {
    const r = await api("server_kill_session", b.dataset.kill); if (!r.ok) return toast(r.error, "error");
    if (!r.server.sessions.some((x) => x.username === me)) return webLogout();
    drawServerCfg(box, r.server);
  }));
}

/* ================================================================ کاربران */
const UPERMS = [["monitor", "مانیتورینگ: افزودن و ویرایش هدف و پروفایل SNMP شخصی"], ["term", "ترمینال و انتقال فایل"]];
const UTOOLS = [["splunk", "Splunk"], ["abuse", "AbuseIPDB"], ["fortigate", "FortiGate"], ["redmine", "Redmine"], ["dns", "DNS"], ["ssh", "SSH"], ["scan", "اسکن شبکه"], ["intel", "بررسی تکمیلی"], ["asset", "مدیریت دارایی"]];
/* ---------------------------------------------------------------- کاربران و دسترسی‌ها (تب جدا، 1.22) */
async function renderUsersTab(body) {
  const sec = (S.state && S.state.security) || {};
  body.innerHTML = `<div class="form"><h3>نقش‌ها</h3><dl class="kv"><dt>ادمین</dt><dd>همه‌چیز، از جمله تنظیمات و کاربران</dd>
      <dt>اپراتور</dt><dd>ابزارها و بخش‌هایی که گروه‌هایش اجازه می‌دهند (دیدن یا اجرا)؛ بدون تنظیمات</dd>
      <dt>فقط‌خواندنی</dt><dd>حداکثر «دیدن» در ابزارهایی که گروه‌هایش اجازه می‌دهند؛ بدون اجرا، تأیید، خروجی و تنظیمات</dd></dl>
      <p class="hint">خاموش کردن یک ابزار یا بخش برای همه در «تنظیمات ← عمومی» است؛ دسترسی هر گروه و کاربر در جدول «دسترسی‌ها» پایین همین صفحه.</p></div>
    <div class="form" id="usrBox"></div><div class="form" id="usrMatrix"></div>${WEB ? `<div class="form" id="usrAd"></div><div class="form" id="usrUnseal"></div>` : ""}`;
  await renderUsers($("#usrBox", body), sec, () => renderUsersTab(body));
  if (WEB) adRender(body);
  const r = await api("users_list");
  const box = $("#usrMatrix", body);
  if (!r.ok || !r.enabled || !r.users.length) { box.remove(); return; }
  if (!(S.state && S.state.superuser)) { box.innerHTML = `<h3>دسترسی‌ها</h3><p class="hint">فقط «ادمین اصلی» کاربران، گروه‌ها و دسترسی‌ها را تغییر می‌دهد.</p>`; return; }
  await renderAccess(box);                                   // 1.32: ui/access.js
}
async function renderUsers(box, sec, after) {
  if (!box) return;
  if (!sec.server && sec.mode !== "password" && !sec.users_enabled) { box.innerHTML = `<h3>کاربران</h3><p class="hint">برنامه در حالت «کلاینت» یک‌کاربره است. برای چند کاربر با نقش‌ها و دسترسی از مرورگر، برنامه را در حالت «سرور» نصب کنید.</p>`; return; }
  const r = await api("users_list"); if (!r.ok) { box.innerHTML = ""; return; }
  if (!r.enabled && !r.server) {
    box.innerHTML = `<h3>کاربران</h3><p class="hint">برنامه در حالت «کلاینت» یک‌کاربره است. برای چند کاربر با نقش‌های ادمین، اپراتور و فقط‌خواندنی و دسترسی از مرورگر، برنامه را در حالت «سرور» نصب کنید.</p>`;
    return;
  }
  if (!r.enabled) {
    box.innerHTML = `<h3>کاربران</h3><p class="hint">با فعال کردن کاربران، هر نفر با نام کاربری و رمز خودش وارد می‌شود: ادمین (همه‌چیز)، اپراتور (اجرای ابزارهای مجاز) و فقط‌خواندنی (فقط دیدن داده‌ها، بدون اجرا و خروجی).
      شما اولین ادمین هستید و رمزتان همان رمز اصلی فعلی است. کلید اسرار عوض می‌شود و رمز اصلی فعلی فقط به‌عنوان رمز همین حساب کار می‌کند. «باز شدن خودکار» با بیش از یک کاربر خاموش می‌شود.</p>
      <div class="row" style="gap:10px;align-items:end;flex-wrap:wrap"><label class="field"><span>نام کاربری ادمین</span><input type="text" class="ltr" id="uaName" value="admin"></label>
      <label class="field"><span>رمز اصلی فعلی</span><input type="password" class="ltr" id="uaPw"></label><button class="btn primary" id="uaGo">فعال کردن کاربران</button></div>`;
    $("#uaGo", box).onclick = (e) => withSpin(e.currentTarget, async () => {
      const x = await api("users_enable", $("#uaName", box).value.trim(), $("#uaPw", box).value);
      if (!x.ok) return toast(x.error, "error");
      toast("کاربران فعال شد", "ok"); await refreshState(); renderSettings();
    });
    return;
  }
  const tl = (u) => (u.role === "operator" ? (u.tools.length ? u.tools.map((t) => (UTOOLS.find(([k]) => k === t) || [t, { monitor: "مانیتورینگ", term: "ترمینال" }[t] || t])[1]).join("، ") : "هیچ ابزاری") : "—");
  box.innerHTML = `<h3>کاربران</h3>
    <div class="table-wrap inner"><table class="grid"><thead><tr><th class="nosort">نام کاربری</th><th class="nosort">نقش</th><th class="nosort">ابزارها</th><th class="nosort">وضعیت</th><th class="nosort">آخرین ورود</th><th class="nosort"></th></tr></thead><tbody>
    ${r.users.map((u) => `<tr><td class="ltr"><b>${esc(u.username)}</b>${u.username === r.me ? ` <span class="tag info">شما</span>` : ""}${u.source === "ad" ? ` <span class="tag mnt" title="کاربر Active Directory؛ نقش از گروه‌های AD">AD</span>` : ""}</td><td>${esc(r.roles[u.role] || u.role)}</td><td>${esc(tl(u))}</td>
      <td>${u.disabled ? `<span class="tag mute">غیرفعال</span>` : `<span class="tag ok">فعال</span>`}</td><td class="ltr">${u.last_login ? fmtDate(u.last_login) : "—"}</td>
      <td><button class="btn sm" data-ue="${esc(u.username)}">ویرایش</button>${u.username === r.me ? "" : ` <button class="btn sm danger-ghost" data-ud="${esc(u.username)}">حذف</button>`}</td></tr>`).join("")}</tbody></table></div>
    <div class="form-foot"><button class="btn primary" id="uAdd">+ کاربر تازه</button><span style="flex:1"></span>${r.server ? "" : `<button class="btn ghost" id="uOff">غیرفعال کردن کاربران</button>`}</div>`;
  const reload = () => (after ? after() : renderUsers(box, sec));
  $("#uAdd", box).onclick = () => userModal(null, reload);
  $$("[data-ue]", box).forEach((b) => (b.onclick = () => userModal(r.users.find((u) => u.username === b.dataset.ue), reload)));
  $$("[data-ud]", box).forEach((b) => (b.onclick = async () => {
    if (!(await confirm2({ title: "حذف کاربر", danger: true, confirm: "حذف", body: `<p>کاربر «${esc(b.dataset.ud)}» حذف شود؟</p>` }))) return;
    const x = await api("user_delete", b.dataset.ud); if (!x.ok) return toast(x.error, "error"); reload();
  }));
  if ($("#uOff", box)) $("#uOff", box).onclick = async () => {
    const pw = await openModal({ title: "غیرفعال کردن کاربران", body: `<p class="hint">همه‌ی کاربران حذف می‌شوند و برنامه به حالت یک رمز اصلی برمی‌گردد. رمز اصلی تازه = رمز فعلی شما.</p>
      <label class="field"><span>رمز فعلی شما</span><input type="password" class="ltr" id="uoPw" autofocus></label>`,
      foot: `<button class="btn ghost" data-r="0">انصراف</button><button class="btn danger" data-r="1">غیرفعال کن</button>`,
      onOpen: (m, close) => $$("[data-r]", m).forEach((x) => (x.onclick = () => close(x.dataset.r === "1" ? $("#uoPw", m).value : null))) });
    if (!pw) return;
    const x = await api("users_disable", pw); if (!x.ok) return toast(x.error, "error");
    toast("کاربران غیرفعال شد", "ok"); await refreshState(); renderSettings();
  };
}
/* 1.24: ورود با Active Directory و «باز شدن خودکار» (حالت سرور، ادمین) */
async function adRender(body) {
  const r = await api("server_ad_get");
  const box = $("#usrAd", body), ub = $("#usrUnseal", body);
  if (!box) return;
  if (!r.ok) { box.remove(); ub.remove(); return; }
  const a = r.ad, us = r.unseal;
  const f = (k, label, o = {}) => `<label class="field ${o.wide ? "wide" : ""}"><span>${label}</span>${o.area ? `<textarea id="ad_${k}" class="ltr" rows="${o.rows || 4}" spellcheck="false" placeholder="${esc(o.ph || "")}">${esc(a[k] || "")}</textarea>`
    : `<input id="ad_${k}" class="ltr" value="${esc(a[k] ?? "")}" placeholder="${esc(o.ph || "")}" spellcheck="false">`}${o.hint ? `<small class="hint">${o.hint}</small>` : ""}</label>`;
  box.innerHTML = `<h3>ورود با Active Directory</h3>
    <p class="hint">کاربر دامنه با نام کاربری و رمز دامنه وارد می‌شود. نقش او از عضویت در گروه‌های زیر (به این ترتیب: ادمین، اپراتور، فقط‌خواندنی) تعیین می‌شود و ابزارهای اپراتور را این‌جا در «کاربران» تیک می‌زنید. فقط LDAPS یا StartTLS با بررسی کامل گواهی؛ رمز کاربر فقط به DC می‌رود و ذخیره نمی‌شود. کاربر محلی هم‌نام همیشه مقدم است. ادمین محلی را نگه دارید (برای وقتی AD در دسترس نیست).</p>
    <div class="form-grid">
      <div class="field wide"><span>&nbsp;</span><label class="chk"><input type="checkbox" id="ad_enabled" ${a.enabled ? "checked" : ""}>ورود با AD روشن باشد</label></div>
      ${f("urls", "آدرس Domain Controllerها", { wide: true, ph: "ldaps://dc1.corp.local:636 ldaps://dc2.corp.local:636", hint: "چند آدرس با فاصله؛ اگر اولی جواب ندهد بعدی. نام باید با گواهی DC یکی باشد." })}
      <div class="field"><span>&nbsp;</span><label class="chk"><input type="checkbox" id="ad_starttls" ${a.starttls ? "checked" : ""}>StartTLS (برای آدرس ldap:// روی پورت 389)</label></div>
      ${f("domain", "دامنه (برای UPN)", { ph: "corp.local" })}
      ${f("base_dn", "Base DN", { ph: "DC=corp,DC=local" })}
      ${f("bind_format", "قالب نام ورود", { hint: "پیش‌فرض {user}@{domain} (UPN)؛ یا CORP\\{user}" })}
      ${f("user_filter", "فیلتر پیدا کردن کاربر", { wide: true })}
      ${f("group_admin", "گروه ادمین (DN)", { wide: true, ph: "CN=AutoKRP-Admins,OU=Groups,DC=corp,DC=local" })}
      ${f("group_operator", "گروه اپراتور (DN)", { wide: true, ph: "CN=AutoKRP-Operators,OU=Groups,DC=corp,DC=local" })}
      ${f("group_readonly", "گروه فقط‌خواندنی (DN)", { wide: true, ph: "CN=AutoKRP-Viewers,OU=Groups,DC=corp,DC=local" })}
      ${f("ca_pem", "گواهی CA شرکت (PEM؛ خالی = گواهی‌های مورد اعتماد ویندوز)", { wide: true, area: true, ph: "-----BEGIN CERTIFICATE-----" })}
      ${f("timeout", "Timeout (ثانیه)")}</div>
    <div class="form-foot"><input id="adTu" class="ltr" placeholder="کاربر آزمایشی" style="max-width:180px"><input id="adTp" type="password" class="ltr" placeholder="رمز" style="max-width:160px" data-nodirty>
      <button class="btn" id="adTest">آزمایش اتصال</button><span style="flex:1"></span><button class="btn primary" id="adSave">ذخیره</button></div>
    <div id="adOut"></div>`;
  const collect = () => { const c = { enabled: $("#ad_enabled", box).checked, starttls: $("#ad_starttls", box).checked };
    ["urls", "domain", "base_dn", "bind_format", "user_filter", "group_admin", "group_operator", "group_readonly", "ca_pem", "timeout"].forEach((k) => (c[k] = $("#ad_" + k, box).value)); return c; };
  $("#adTest", box).onclick = (e) => withSpin(e.currentTarget, async () => {
    const x = await api("server_ad_test", collect(), $("#adTu", box).value.trim(), $("#adTp", box).value);
    $("#adTp", box).value = "";
    if (!x.ok) return toast(x.error, "error");
    $("#adOut", box).innerHTML = x.good ? `<div class="sum" style="margin-top:8px"><b style="color:var(--ok)">موفق — نقش: ${esc((ROLE_FA || {})[x.role] || x.role)}</b><ul>${x.steps.map((t) => `<li class="bidi">${esc(t)}</li>`).join("")}</ul></div>`
      : `<div class="sum" style="margin-top:8px;color:var(--err)">${esc(x.error)}</div>`;
  });
  $("#adSave", box).onclick = (e) => withSpin(e.currentTarget, async () => {
    const x = await api("server_ad_save", collect()); if (!x.ok) return toast(x.error, "error"); toast("ذخیره شد", "ok");
  });
  ub.innerHTML = `<h3>باز شدن خودکار پس از ری‌استارت</h3>
    <p class="hint">بدون این گزینه، بعد از روشن شدن دوباره‌ی سرور همه‌ی داده‌ها قفل‌اند تا یک کاربر محلی وارد شود: مانیتورینگ، کارهای زمان‌بندی‌شده و ورود کاربران AD تا آن موقع کار نمی‌کنند.
      با روشن کردن، کلید اصلی با DPAPI ویندوز (حوزه‌ی همین سیستم، لازم برای اجرای خودکار بدون ذخیره‌ی رمز ویندوز) روی دیسک می‌ماند: هر کس کنترل ویندوز سرور (حساب سرویس یا ادمین ویندوز) را داشته باشد می‌تواند داده‌ها را باز کند.
      دیسک و دسترسی ادمین ویندوز را محافظت کنید. «قفل کامل» این گزینه را خاموش نمی‌کند (بعد از ری‌استارت دوباره باز می‌شود)؛ RESET همه‌چیز از جمله آن را پاک می‌کند.</p>
    ${us.available ? `<div class="row" style="gap:10px;align-items:end;flex-wrap:wrap"><span class="tag ${us.enabled ? "ok" : "mute"}">${us.enabled ? "روشن است" : "خاموش است"}</span>
      <label class="field"><span>رمز فعلی شما (ادمین محلی)</span><input type="password" class="ltr" id="usPw" data-nodirty></label>
      <button class="btn ${us.enabled ? "danger-ghost" : "primary"}" id="usGo">${us.enabled ? "خاموش کن" : "روشن کن"}</button></div>`
      : `<p class="muted">فقط روی ویندوز (DPAPI) در دسترس است.</p>`}`;
  if ($("#usGo", ub)) $("#usGo", ub).onclick = (e) => withSpin(e.currentTarget, async () => {
    const x = await api("server_unseal_set", !us.enabled, $("#usPw", ub).value);
    if (!x.ok) return toast(x.error, "error");
    toast(x.enabled ? "باز شدن خودکار روشن شد" : "باز شدن خودکار خاموش شد", "ok"); adRender(body);
  });
}
function userModal(u, done) {
  const isNew = !u; u = u || { username: "", role: "readonly", tools: [], disabled: false };
  openModal({ title: isNew ? "کاربر تازه" : `ویرایش ${u.username}`, body: `<div class="form-grid">
      <label class="field"><span>نام کاربری</span><input type="text" class="ltr" id="umName" value="${esc(u.username)}" ${isNew ? "autofocus" : "disabled"}></label>
      <label class="field"><span>نقش</span><select id="umRole">${[["admin", "ادمین — همه‌چیز"], ["operator", "اپراتور — اجرای ابزارهای مجاز"], ["readonly", "فقط‌خواندنی — فقط دیدن"]].map(([k, t]) => `<option value="${k}" ${u.role === k ? "selected" : ""}>${t}</option>`).join("")}</select></label>
      <label class="field"><span>${isNew ? "رمز" : "رمز تازه (خالی = بدون تغییر)"}</span><input type="password" class="ltr" id="umPw" autocomplete="new-password"></label>
      <label class="field"><span>تکرار رمز</span><input type="password" class="ltr" id="umPw2" autocomplete="new-password"></label></div>
    <div class="field" id="umGroups"><span>گروه‌های دسترسی</span><div class="chks" id="umGrpList"><span class="muted">…</span></div>
      <small class="hint">ابزارها، سطح دسترسی (دیدن یا اجرا) و دستگاه‌های مجاز از گروه‌ها می‌آید؛ استثنای هر کاربر در جدول «دسترسی‌ها».</small></div>
    <label class="chk" style="margin-top:8px"><input type="checkbox" id="umDis" ${u.disabled ? "checked" : ""}>غیرفعال (نمی‌تواند وارد شود)</label>`,
    foot: `<button class="btn ghost" data-r="0">انصراف</button><button class="btn primary" data-r="1">ذخیره</button>`,
    onOpen: (m, close) => {
      if (u.source === "ad") {          // کاربر AD: نقش از گروه‌ها و رمز در خود AD
        $("#umRole", m).disabled = true; $("#umPw", m).closest(".field").hidden = true; $("#umPw2", m).closest(".field").hidden = true;
        $("#umRole", m).insertAdjacentHTML("afterend", `<small class="hint">کاربر AD: نقش در هر ورود از گروه‌های AD تعیین می‌شود؛ رمز در خود AD.</small>`);
      }
      api("access_get").then((g) => {
        const bx = $("#umGrpList", m); if (!bx) return;
        if (!g.ok) { $("#umGroups", m).hidden = true; return; }
        const mine = new Set(isNew ? [] : u.groups || []);
        bx.innerHTML = g.groups.length ? g.groups.map((x) => `<label class="chk"><input type="checkbox" class="umG" value="${esc(x.id)}" ${mine.has(String(x.id)) ? "checked" : ""}>${esc(x.name)}</label>`).join("")
          : `<span class="muted">هنوز گروهی نیست؛ پایین همین صفحه در «دسترسی‌ها» بسازید.</span>`;
      });
      $("[data-r='0']", m).onclick = () => close(null);
      $("[data-r='1']", m).onclick = async () => {
        const pw = $("#umPw", m).value;
        if (pw !== $("#umPw2", m).value) return toast("رمز و تکرار آن یکی نیستند.", "error");
        const body = { username: $("#umName", m).value.trim(), role: $("#umRole", m).value, disabled: $("#umDis", m).checked };
        if ($("#umGrpList input", m)) body.groups = $$(".umG", m).filter((c) => c.checked).map((c) => c.value);
        const x = await api("user_save", body, pw);
        if (!x.ok) return toast(x.error, "error");
        toast("ذخیره شد", "ok"); close(true); done();
      };
    } });
}
$("#userChip").addEventListener("click", async () => {
  const me = S.state && S.state.me; if (!me || me.single) return;
  const res = await openModal({ title: `حساب ${me.username}`, body: `<p class="hint">نقش: ${ROLE_FA[me.role] || me.role}${me.source === "ad" ? " · کاربر Active Directory (رمز در خود AD تغییر می‌کند)" : ""}</p><div ${me.source === "ad" ? "hidden" : ""}><h3 style="margin:12px 0 6px">تغییر رمز</h3><div class="form-grid">
      <label class="field"><span>رمز فعلی</span><input type="password" class="ltr" id="cpCur"></label><label class="field"><span>رمز تازه</span><input type="password" class="ltr" id="cpNew"></label>
      <label class="field"><span>تکرار رمز تازه</span><input type="password" class="ltr" id="cpNew2"></label></div></div>`,
    foot: `<button class="btn ghost" data-r="out">خروج از حساب</button><span style="flex:1"></span>${me.source === "ad" ? "" : `<button class="btn primary" data-r="pw">تغییر رمز</button>`}`,
    onOpen: (m, close) => {
      $("[data-r='out']", m).onclick = () => close("out");
      if ($("[data-r='pw']", m)) $("[data-r='pw']", m).onclick = async () => {
        if ($("#cpNew", m).value !== $("#cpNew2", m).value) return toast("رمز تازه و تکرار آن یکی نیستند.", "error");
        const x = await api("security_change_own", $("#cpCur", m).value, $("#cpNew", m).value);
        if (!x.ok) return toast(x.error, "error");
        toast("رمز تغییر کرد", "ok"); close(null);
      };
    } });
  if (res === "out") { if (WEB) webLogout(); else $("#btnLock").click(); }
});

/* ================================================================ about */
document.addEventListener("click", (e) => {
  const a = e.target.closest("[data-contact]"); if (!a) return;
  e.preventDefault(); api("open_contact", a.dataset.contact).then((r) => { if (!r.ok) toast(r.error, "error"); });
});
async function renderAbout() {
  const r = await api("get_about"); if (!r.ok) return toast(r.error, "error");
  const b = (S.state && S.state.branding) || {};
  $("#aboutBody").innerHTML = `<div class="form"><div class="about-hero"><div class="logo ${b.logo_data ? "has-img" : ""}">${logoHtml(b)}</div>
      <div><h1 class="ltr" style="text-align:start">${esc(r.name)} <span class="muted">v${esc(r.version)}</span></h1><p class="muted" style="margin:2px 0 0">ابزار متن‌باز خودکارسازی پاسخ امنیتی: <span class="ltr">Splunk → AbuseIPDB → FortiGate → Redmine</span></p></div></div>
      <div class="sec"><dl class="kv"><dt>سازنده</dt><dd class="ltr" style="text-align:start"><b>${esc(r.author)}</b></dd><dt>همکاری</dt><dd>${esc(r.credit)}</dd>
      <dt>مجوز</dt><dd>${esc(r.license)} — استفاده، تغییر و انتشار آزاد با حفظ نام سازنده</dd></dl></div>
      <div class="sec"><h3>ارتباط با سازنده</h3><dl class="kv">${(r.contacts || []).map((c) => `<dt>${{ email: "ایمیل", telegram: "تلگرام", github: "GitHub", issues: "گزارش مشکل / پیشنهاد" }[c.kind] || esc(c.kind)}</dt>
        <dd>${WEB && /^(https:|mailto:)/.test(c.url || "") ? `<a href="${esc(c.url)}" class="ltr" target="_blank" rel="noopener noreferrer">${esc(c.text)}</a>` : `<a href="#" class="ltr" data-contact="${esc(c.kind)}">${esc(c.text)}</a>`}</dd>`).join("")}</dl></div>
      <div class="sec"><h3>محیط اجرا</h3><dl class="kv"><dt>Python</dt><dd class="ltr" style="text-align:start">${esc(r.python)}</dd><dt>سیستم‌عامل</dt><dd class="ltr" style="text-align:start">${esc(r.os)}</dd>
      ${Object.entries(r.libs).map(([k, v]) => `<dt>${esc(k)}</dt><dd class="ltr" style="text-align:start">${esc(v)}</dd>`).join("")}
      <dt>پوشه‌ی داده</dt><dd class="ltr" style="text-align:start">${esc(r.data_dir)}</dd></dl></div>
      <div class="sec"><h3>متن پذیرش</h3><div class="row" style="gap:10px"><button class="btn sm" id="aboutTerms">نمایش متن پذیرش و سلب مسئولیت</button>
        <span class="muted" id="aboutTermsAt"></span></div></div>
      ${isAdmin() ? `<div class="sec" id="aboutSec"></div>` : ""}</div>`;
  $("#aboutTerms").onclick = termsShowAgain;
  api("terms_status").then((t) => { if (t.ok && t.accepted && $("#aboutTermsAt")) $("#aboutTermsAt").innerHTML = `پذیرفته‌شده: <span class="ltr">${esc(trFmt(t.accepted.at))}</span>`; });
  if (isAdmin()) aboutSec();
}

/* 1.33: نسخه‌ی تازه در GitHub + آسیب‌پذیری کتابخانه‌های برنامه (OSV) — دستی یا خودکار روزانه */
let _aboutPoll = null;
async function aboutSec() {
  const box = $("#aboutSec"); if (!box) return;
  const r = await api("about_security"); if (!r.ok) { box.innerHTML = ""; return; }
  const st = r.state || {}, rel = st.release || {}, vu = st.vulns || {};
  const items = vu.items || [], bad = items.filter((x) => !x.accepted);
  const relHtml = r.running && !st.at ? `<span class="muted">در حال بررسی…</span>`
    : !st.at ? `<span class="muted">هنوز بررسی نشده است.</span>`
    : rel.error ? `<span class="tag err">خطا</span> <span class="muted">${esc(rel.error)}</span>`
    : rel.newer ? `<span class="tag warn">نسخه‌ی تازه</span> <b class="ltr">${esc(rel.latest)}</b> <span class="muted">${rel.published ? esc(fmtDate(Date.parse(rel.published) / 1000)) : ""}</span>
        ${WEB ? `<a class="btn sm primary" href="${esc(rel.url)}" target="_blank" rel="noopener noreferrer">صفحه‌ی دانلود</a>` : `<button class="btn sm primary" id="abRel">صفحه‌ی دانلود</button>`}`
    : rel.latest ? `<span class="tag ok">به‌روز است</span> <span class="muted">آخرین انتشار:</span> <span class="ltr">${esc(rel.latest)}</span>` : `<span class="muted">هنوز انتشاری در GitHub نیست.</span>`;
  const vulnHtml = !st.at ? "" : vu.error ? `<p><span class="tag err">خطا</span> <span class="muted">${esc(vu.error)}</span></p>`
    : !items.length ? `<p><span class="tag ok">بدون آسیب‌پذیری شناخته‌شده</span> <span class="muted"><span>${num(vu.checked || 0)}</span> <span>کتابخانه بررسی شد.</span></span></p>`
    : `<p>${bad.length ? `<span class="tag err"><span>${num(bad.length)}</span> <span>آسیب‌پذیری</span></span>` : `<span class="tag ok">فقط موارد پذیرفته‌شده</span>`} <span class="muted"><span>${num(vu.checked || 0)}</span> <span>کتابخانه بررسی شد.</span></span></p>
      <div class="table-wrap inner"><table class="grid"><thead><tr><th>کتابخانه</th><th>نسخه</th><th>شناسه</th><th>شدت</th><th>رفع در نسخه</th><th>توضیح</th></tr></thead><tbody>
      ${items.map((x) => `<tr class="${x.accepted ? "muted" : ""}"><td class="ltr">${esc(x.package)}</td><td class="ltr">${esc(x.version)}</td>
        <td class="ltr" data-no-i18n>${esc(x.id)}${x.aliases.length ? `<br><small class="muted">${esc(x.aliases.join(", "))}</small>` : ""}</td><td class="ltr">${esc(x.severity || "—")}</td>
        <td class="ltr">${esc((x.fixed || []).join(", ") || "—")}</td>
        <td>${x.accepted ? `<span class="tag mute">ریسک پذیرفته‌شده</span> <small>${esc(x.accepted)}</small>` : `<small class="ltr" data-no-i18n>${esc(x.summary)}</small>`}</td></tr>`).join("")}</tbody></table></div>
      ${bad.length ? `<p class="hint">کتابخانه را در requirements.txt به نسخه‌ی «رفع در نسخه» برسانید و دوباره بیلد کنید، یا نسخه‌ی تازه‌ی برنامه را از GitHub بگیرید.</p>` : ""}`;
  box.innerHTML = `<h3>به‌روزرسانی و امنیت</h3>
    <dl class="kv"><dt>نسخه‌ی تازه در GitHub</dt><dd>${relHtml}</dd>
      <dt>آخرین بررسی</dt><dd>${st.at ? esc(fmtDate(st.at)) : "—"}${r.running ? ` <span class="tag info">در حال بررسی…</span>` : ""}</dd></dl>
    <h4 style="margin:12px 0 6px">آسیب‌پذیری کتابخانه‌های برنامه</h4>${vulnHtml}
    <div class="row" style="gap:10px;flex-wrap:wrap;align-items:center;margin-top:10px"><button class="btn" id="abChk" ${r.running ? "disabled" : ""}>بررسی الان</button>
      <label class="switch"><input type="checkbox" id="abAuto" ${r.auto ? "checked" : ""}><span class="track"><span class="thumb"></span></span>بررسی خودکار هر روز</label></div>
    <p class="hint">فقط نسخه‌ی برنامه و نام و نسخه‌ی کتابخانه‌ها به GitHub و پایگاه آسیب‌پذیری OSV (osv.dev، همان منبع pip-audit) فرستاده می‌شود؛ هیچ داده‌ی سازمانی فرستاده نمی‌شود. مورد تازه با اعلان برنامه و ایمیل (رویداد «به‌روزرسانی و امنیت») خبر داده می‌شود.</p>`;
  const rb = $("#abRel", box); if (rb) rb.onclick = () => api("open_release");
  $("#abChk", box).onclick = async () => { const x = await api("about_check"); if (!x.ok) return toast(x.error, "error"); aboutSec(); };
  $("#abAuto", box).onchange = async (e) => { const x = await api("about_auto_set", e.target.checked); if (!x.ok) { e.target.checked = !e.target.checked; toast(x.error, "error"); } };
  clearTimeout(_aboutPoll);
  if (r.running) _aboutPoll = setTimeout(() => { if (S.page === "about") aboutSec(); }, 1500);   // فقط تا پایان بررسی
}

/* ================================================================ branding in general tab */
function brandingSection() {
  const b = (S.state && S.state.branding) || {};
  return `<div class="form"><h3>لوگو و آیکون</h3><div class="form-grid">
    <div class="field"><span>لوگوی برنامه (PNG، SVG، JPG یا ICO — حداکثر ۱ مگابایت)</span><div class="row"><div class="logo-preview">${b.logo_data ? `<img src="${b.logo_data}" alt="">` : esc(b.logo_text || "A")}</div>
      <button class="btn sm" data-logo="logo">انتخاب فایل…</button>${b.logo_file ? `<button class="btn sm ghost" data-logoclr="logo">حذف</button>` : ""}</div>
      <small class="hint">در نوار کناری، صفحه‌ی قفل و «درباره» نمایش داده می‌شود. بدون لوگو، «حرف لوگو» نمایش داده می‌شود.</small></div>
    <div class="field"><span>آیکون پنجره و نوار وظیفه (فقط ICO)</span><div class="row"><span class="path ltr" style="flex:1">${esc(b.icon_file || "پیش‌فرض")}</span>
      <button class="btn sm" data-logo="icon">انتخاب فایل…</button>${b.icon_file ? `<button class="btn sm ghost" data-logoclr="icon">حذف</button>` : ""}</div>
      <small class="hint">آیکون خود فایل exe موقع ساخت از assets\\app.ico برداشته می‌شود؛ فایل خودتان را جایگزین کنید و build.bat را اجرا کنید.</small></div></div></div>
  <div class="form"><h3>خروجی و ورود تنظیمات</h3><p class="hint">همه‌ی تنظیمات بدون توکن و رمزها در یک فایل JSON. برای پشتیبان‌گیری یا انتقال تنظیمات سازمان خود به نسخه‌ی تازه.</p>
    <div class="form-foot"><button class="btn" id="btnSetExport">خروجی تنظیمات</button><button class="btn" id="btnSetImport">ورود تنظیمات…</button></div></div>`;
}
document.addEventListener("click", async (e) => {
  const lg = e.target.closest("[data-logo]"), lc = e.target.closest("[data-logoclr]");
  if (lg || lc) {
    let r;
    if (lg && WEB) {   // مرورگر: فایل اول آپلود می‌شود
      const up = await webPickFile(lg.dataset.logo === "icon" ? ".ico" : ".png,.svg,.jpg,.jpeg,.webp,.ico");
      if (!up.ok) return toast(up.error, "error"); if (!up.path) return;
      r = await api("set_logo", lg.dataset.logo, up.path);
    } else r = lg ? await api("set_logo", lg.dataset.logo) : await api("clear_logo", lc.dataset.logoclr);
    if (!r.ok) return toast(r.error, "error");
    if (r.cancelled) return;
    S.state.branding = r.branding; applyLogo(r.branding); toast("ذخیره شد", "ok"); renderSettings(); return;
  }
  if (e.target.closest("#btnSetExport")) { const r = await api("export_settings"); if (r.ok && !r.cancelled) toast("ذخیره شد: " + r.path, "ok"); else if (!r.ok) toast(r.error, "error"); }
  if (e.target.closest("#btnSetImport")) {
    let r;
    if (WEB) { const up = await webPickFile(".json,application/json"); if (!up.ok) return toast(up.error, "error"); if (!up.path) return; r = await api("import_settings", up.path); }
    else r = await api("import_settings");
    if (!r.ok) return toast(r.error, "error"); if (r.cancelled) return;
    await loadSettings(); renderSettings(); toast("تنظیمات وارد شد", "ok");
  }
});

/* ================================================================ stats page */
const ST = { range: "30d", cal: "jalali", data: null };
const cssVar = (n) => getComputedStyle(document.documentElement).getPropertyValue(n).trim();
const COLORS = () => ({ ok: cssVar("--ok"), err: cssVar("--err"), warn: cssVar("--warn"), info: cssVar("--info"),
  acc: cssVar("--accent"), faint: cssVar("--faint"), text: cssVar("--muted"), line: cssVar("--line2"), panel: cssVar("--panel") });

/** بیشینه‌ی محور با ۴ گام رُند و صحیح (حداقل گام ۱). */
function niceMax(v) {
  const raw = Math.max(1, v / 4), p = Math.pow(10, Math.floor(Math.log10(raw))), m = raw / p;
  let step = [1, 1.5, 2, 2.5, 3, 4, 5, 6, 8, 10].find((x) => m <= x) * p;
  if (step < 1) step = 1;
  if (!Number.isInteger(step)) step = Math.ceil(step);
  return step * 4;
}
/** نمودار میله‌ای انباشته یا خطی. series: [{name, color, values}] */
/* 1.23: گزینه‌های اضافه‌ی نمودار خطی زمانی:
 *  tips: برچسب کامل هر نقطه برای راهنما؛ zoom(i0, i1): کشیدن موس روی نمودار یک تکه را انتخاب می‌کند (دوبار کلیک = zoomOut)؛
 *  stats: جدول کمینه/میانگین/بیشینه/آخرین زیر نمودار؛ sync + times: خط راهنمای هم‌زمان بین نمودارهای یک گروه */
const CH_SYNC = new Map();      // گروه ← Set(el)
let CH_DRAG_END = null;
document.addEventListener("mouseup", () => { const f = CH_DRAG_END; CH_DRAG_END = null; if (f) f(); });
function drawChart(el, labels, series, { type = "bar", height = 220, fmt = null, yMax = null, dots = null, tips = null, zoom = null, zoomOut = null, stats = false, sync = null, times = null } = {}) {
  const F = fmt || ((v) => num(Math.round(v)));
  if (el.querySelector(".hit")) clearTips();          // 1.37: رسم دوباره (به‌روزرسانی خودکار) ← راهنمای قبلی پاک شود
  if (dots === null) dots = labels.length <= 120;
  const W = Math.max(360, Math.round(el.clientWidth || 680)), H = height, L = fmt ? 66 : 40, R = 10, T = 12, B = 34, n = labels.length;
  const c = COLORS();
  const totals = labels.map((_, i) => type === "bar" ? series.reduce((a, s) => a + (s.values[i] || 0), 0) : Math.max(0, ...series.map((s) => s.values[i] || 0)));
  const max = yMax || niceMax(Math.max(1, ...totals.filter((x) => Number.isFinite(x))));
  const cw = (W - L - R) / Math.max(1, n), y = (v) => T + (H - T - B) * (1 - v / max);
  let g = "";
  for (let k = 0; k <= 4; k++) {
    const v = (max / 4) * k, yy = y(v);
    g += `<line x1="${L}" x2="${W - R}" y1="${yy}" y2="${yy}" stroke="${c.line}"/><text x="${L - 6}" y="${yy + 4}" text-anchor="end" fill="${c.text}">${esc(F(v))}</text>`;
  }
  const maxLen = Math.max(1, ...labels.map((x) => String(x).length));
  const every = Math.max(1, Math.ceil((n * (maxLen * 6.5 + 10)) / (W - L - R)));
  const show = labels.map((_, i) => i % every === 0);
  if (n && !show[n - 1]) {           // آخرین بازه همیشه برچسب دارد؛ برچسب نزدیک قبلی حذف می‌شود
    const prevI = show.lastIndexOf(true);
    if (prevI >= 0 && n - 1 - prevI < every) show[prevI] = false;
    show[n - 1] = true;
  }
  labels.forEach((lb, i) => { if (show[i]) g += `<text x="${L + cw * i + cw / 2}" y="${H - 12}" text-anchor="middle" fill="${c.text}">${esc(lb)}</text>`; });
  let marks = "";
  if (type === "bar") {
    const bw = Math.max(2, Math.min(34, cw * 0.66));
    labels.forEach((_, i) => {
      let acc = 0;
      series.forEach((s) => {
        const v = s.values[i] || 0; if (!v) return;
        const y1 = y(acc + v), y0 = y(acc); acc += v;
        marks += `<rect x="${L + cw * i + (cw - bw) / 2}" y="${y1}" width="${bw}" height="${Math.max(0.5, y0 - y1)}" rx="2" fill="${s.color}"/>`;
      });
    });
  } else {
    series.forEach((s) => {
      let d = "", pen = false;
      s.values.forEach((v, i) => {
        if (v === null || v === undefined) { pen = false; return; }
        const x = L + cw * i + cw / 2; d += `${pen ? "L" : "M"}${x},${y(v)} `; pen = true;
        const lone = (i === 0 || s.values[i - 1] == null) && (i === s.values.length - 1 || s.values[i + 1] == null);   // نقطه‌ی تنها بدون خط
        if (dots || lone) marks += `<circle cx="${x}" cy="${y(v)}" r="2.6" fill="${s.color}"/>`;
      });
      marks = `<path d="${d}" fill="none" stroke="${s.color}" stroke-width="2"/>` + marks;
    });
  }
  const hits = labels.map((_, i) => `<rect class="hit" data-i="${i}" x="${L + cw * i}" y="${T}" width="${cw}" height="${H - T - B}" fill="transparent"/>`).join("");
  const line = type === "line";
  const xh = line ? `<line class="xh" x1="0" x2="0" y1="${T}" y2="${H - B}" stroke="${c.text}" stroke-dasharray="3 3" visibility="hidden"/><rect class="zsel" x="0" y="${T}" width="0" height="${H - T - B}" fill="${c.info}" fill-opacity=".15" visibility="hidden"/>` : "";
  const fv = (v) => (v === null || v === undefined ? "—" : fmt ? fmt(v) : num(Math.round(v * 100) / 100));
  let st = "";
  if (stats && line) {
    st = `<table class="ch-stats"><thead><tr><th></th><th>${esc(I18N.t("کمینه"))}</th><th>${esc(I18N.t("میانگین"))}</th><th>${esc(I18N.t("بیشینه"))}</th><th>${esc(I18N.t("آخرین"))}</th></tr></thead><tbody>${series.map((s) => {
      const v = s.values.filter((x) => x !== null && x !== undefined && Number.isFinite(x));
      const last = [...s.values].reverse().find((x) => x !== null && x !== undefined);
      return `<tr><td><i style="background:${s.color}"></i>${esc(s.name)}</td><td class="ltr">${v.length ? esc(fv(Math.min(...v))) : "—"}</td><td class="ltr">${v.length ? esc(fv(v.reduce((a, b) => a + b, 0) / v.length)) : "—"}</td><td class="ltr">${v.length ? esc(fv(Math.max(...v))) : "—"}</td><td class="ltr">${esc(fv(last))}</td></tr>`;
    }).join("")}</tbody></table>`;
  }
  el.innerHTML = `${stats && line ? "" : `<div class="legend">${series.map((s) => `<span><i style="background:${s.color}"></i>${esc(s.name)}</span>`).join("")}</div>`}
    <svg viewBox="0 0 ${W} ${H}" direction="ltr" xmlns="http://www.w3.org/2000/svg" font-family="VazirUI, Tahoma, sans-serif" font-size="11" class="${zoom ? "zoomable" : ""}">${g}${marks}${xh}${hits}</svg>${st}`;
  const svg = el.querySelector("svg"), xhl = svg.querySelector(".xh"), zr = svg.querySelector(".zsel");
  el._xh = (i) => { if (!xhl) return; if (i === null || i < 0 || i >= n) { xhl.setAttribute("visibility", "hidden"); return; } const x = L + cw * i + cw / 2; xhl.setAttribute("x1", x); xhl.setAttribute("x2", x); xhl.setAttribute("visibility", "visible"); };
  el._times = times;
  if (sync && times) { if (!CH_SYNC.has(sync)) CH_SYNC.set(sync, new Set()); CH_SYNC.get(sync).add(el); }
  const syncTo = (i) => {
    if (!sync || !times || !CH_SYNC.has(sync)) return;
    const t0 = i === null ? null : times[i];
    for (const o of [...CH_SYNC.get(sync)]) {
      if (!o.isConnected) { CH_SYNC.get(sync).delete(o); continue; }
      if (o === el || !o._xh) continue;
      if (t0 === null || !o._times) { o._xh(null); continue; }
      let best = -1, bd = Infinity; o._times.forEach((t, j) => { const d = Math.abs(t - t0); if (d < bd) { bd = d; best = j; } });
      o._xh(best);
    }
  };
  let drag = null;
  if (zoom && line) {
    const idxAt = (ev) => { const b = svg.getBoundingClientRect(), x = ((ev.clientX - b.left) / b.width) * W; return Math.max(0, Math.min(n - 1, Math.floor((x - L) / cw))); };
    svg.addEventListener("mousedown", (ev) => { if (ev.button !== 0) return; ev.preventDefault(); drag = { a: idxAt(ev), b: idxAt(ev) }; CH_DRAG_END = up; });
    svg.addEventListener("mousemove", (ev) => {
      if (!drag) return; drag.b = idxAt(ev);
      const a = Math.min(drag.a, drag.b), b = Math.max(drag.a, drag.b);
      zr.setAttribute("x", L + cw * a); zr.setAttribute("width", cw * (b - a + 1)); zr.setAttribute("visibility", a === b ? "hidden" : "visible");
    });
    // یک شنونده‌ی سراسری mouseup (CH_DRAG_END)؛ هر نمودار شنونده‌ی جدا نمی‌گذارد (نشت حافظه با به‌روزرسانی خودکار)
    function up() {
      if (!drag) return; const a = Math.min(drag.a, drag.b), b = Math.max(drag.a, drag.b); drag = null;
      if (!svg.isConnected) return;
      zr.setAttribute("visibility", "hidden");
      if (b > a) { clearTips(); zoom(a, b); }
    }
    if (zoomOut) svg.addEventListener("dblclick", () => { clearTips(); zoomOut(); });
  }
  let tip = null;
  svg.addEventListener("mouseleave", () => { el._xh(null); syncTo(null); });
  el.querySelectorAll(".hit").forEach((h) => {
    h.addEventListener("mousemove", (ev) => {
      const i = Number(h.dataset.i);
      if (line) { el._xh(i); syncTo(i); }
      if (!tip || !tip.isConnected) { clearTips(); tip = document.createElement("div"); tip.className = "hover-tip"; document.body.appendChild(tip); }
      tip.innerHTML = `<b>${esc(tips ? tips[i] : labels[i])}</b><br>${series.map((s) => `<span style="color:${s.color}">●</span> ${esc(s.name)}: ${s.values[i] === null || s.values[i] === undefined ? "—" : esc(fmt ? fmt(s.values[i]) : num(s.values[i]))}`).join("<br>")}`;
      // داخل پنجره نگه داشته می‌شود تا نوار اسکرول ظاهر نشود و صفحه جابه‌جا نشود
      const tw = tip.offsetWidth, th = tip.offsetHeight;
      let x = ev.clientX + 14, y = ev.clientY + 12;
      if (x + tw > window.innerWidth - 8) x = ev.clientX - tw - 14;
      if (y + th > window.innerHeight - 8) y = ev.clientY - th - 12;
      tip.style.left = Math.max(8, x) + "px"; tip.style.top = Math.max(8, y) + "px";
    });
    h.addEventListener("mouseleave", () => { if (tip) { tip.remove(); tip = null; } });
  });
}
function deltaHtml(cur, prev, { pct = false, bad = false } = {}) {
  if (cur === null || cur === undefined || prev === null || prev === undefined) return `<span class="delta flat">دوره‌ی قبل: —</span>`;
  const d = cur - prev;
  if (Math.abs(d) < (pct ? 0.05 : 0.5)) return `<span class="delta flat">بدون تغییر نسبت به دوره‌ی قبل</span>`;
  const cls = `${bad ? "bad " : ""}${d > 0 ? "up" : "down"}`;
  const txt = pct ? `${num(Math.abs(Math.round(d * 10) / 10))} واحد درصد` : prev ? `${num(Math.abs(Math.round((100 * d) / prev)))}٪` : `${num(Math.abs(d))} مورد`;
  return `<span class="delta ${cls}">${d > 0 ? "▲" : "▼"} ${txt} ${d > 0 ? "بیشتر" : "کمتر"} از دوره‌ی قبل</span>`;
}
async function loadStats() {
  const r = await api("get_stats", ST.range, ST.cal);
  if (!r.ok) return toast(r.error, "error");
  ST.data = r.stats;
  if (!ST.tab || ST.tab === "general") renderStats();
}
function stTabApply() {
  const mon = ST.tab === "monitor", other = ST.tab && ST.tab !== "general";
  ["#stCal", "#stRange", "#btnStatsPngAll", "#btnStatsCsv"].forEach((s) => { const e = $(s); if (e) e.hidden = !!other; });
  $$("#stTab button").forEach((x) => x.classList.toggle("on", x.dataset.v === (ST.tab || "general")));
  if (mon) $("#statsSub").textContent = I18N.t("در دسترس بودن، قطعی‌ها و زمان پاسخ هدف‌های مانیتورینگ");
  if (ST.tab === "repeat") $("#statsSub").textContent = I18N.t("IPهایی که در چند روز مختلف دوباره برای بررسی آمده‌اند");
}
$("#stTab").addEventListener("click", (e) => {
  const b = e.target.closest("button"); if (!b) return;
  ST.tab = b.dataset.v; stTabApply();
  if (ST.tab === "monitor") renderMonStats(); else if (ST.tab === "repeat") { renderRepeat(); loadRepeat(); } else if (ST.data) renderStats(); else loadStats();
});
function renderStats() {
  const d = ST.data, c = COLORS(), k = d.kpi, p = d.prev, S2 = d.series;
  const iso = (x) => `\u2066${x}\u2069`;
  $("#statsSub").textContent = `بازه: ${iso(d.period[0])} تا ${iso(d.period[1])} — ${d.gran === "day" ? "روزانه" : "ماهانه"}${d.first_event ? ` — اولین داده‌ی ثبت‌شده: ${iso(d.first_event)}` : ""}`;
  const pctTxt = (v) => (v === null || v === undefined ? "—" : `${num(v)}٪`);
  const kpis = [
    [num(k.checked), "IP یکتای بررسی‌شده", deltaHtml(k.checked, p.checked)],
    [num(k.malicious), `مخرب (${pctTxt(k.malicious_pct)})`, deltaHtml(k.malicious, p.malicious, { bad: true })],
    [num(k.banned), "بلاک موفق", deltaHtml(k.banned, p.banned)],
    [pctTxt(k.ban_fail_pct), `بلاک ناموفق (${num(k.ban_failed)} مورد)`, deltaHtml(k.ban_fail_pct, p.ban_fail_pct, { pct: true, bad: true })],
    [pctTxt(k.cache_pct), "نتیجه از کش (صرفه‌جویی سهمیه)", deltaHtml(k.cache_pct, p.cache_pct, { pct: true })],
    [num(k.tickets), "تیکت Redmine", deltaHtml(k.tickets, p.tickets)],
    [pctTxt(k.run_success_pct), `اجرای موفق (از ${num(k.runs)} اجرا)`, deltaHtml(k.run_success_pct, p.run_success_pct, { pct: true })],
  ];
  const card = (id, title, wide = false, hint = "") => `<div class="chart-card ${wide ? "wide" : ""}"><div class="chart-head"><h3>${title}</h3><button class="btn-img no-ro" data-png="${id}" data-title="${esc(title)}" title="ذخیره‌ی نمودار به‌صورت تصویر PNG"><svg><use href="#i-img"/></svg>ذخیره‌ی تصویر</button></div>${hint ? `<p class="hint" style="margin:0 0 4px">${hint}</p>` : ""}<div class="chart" id="${id}"></div></div>`;
  const hbars = (rows, name) => rows.length ? rows.map(([n2, v]) => `<div class="hbar"><span class="nm ${name === "cc" ? "ltr" : "bidi"}" title="${esc(n2)}">${esc(n2)}</span><span class="track"><i style="width:${Math.round((100 * v) / rows[0][1])}%"></i></span><span class="num">${num(v)}</span></div>`).join("") : `<div class="empty">داده‌ای نیست.</div>`;
  $("#statsBody").innerHTML = (d.has_data ? "" : `<div class="panel"><div class="empty">در این بازه داده‌ای ثبت نشده است. داده‌ی IPهای واردشده از روی «Checked At» در آمار دیده می‌شود.</div></div>`)
    + `<div class="kpis">${kpis.map(([v, t, dl]) => `<div class="kpi"><b>${v}</b><span>${t}</span>${dl}</div>`).join("")}</div>
    <div class="chart-grid">
      ${card("chAbuse", "بررسی IP در AbuseIPDB", true, "IP یکتا در هر بازه، با آخرین وضعیت")}
      ${card("chSource", "منبع نتیجه‌ها", false, "آنلاین = مصرف سهمیه؛ کش = بدون درخواست")}
      ${card("chBan", "بلاک در FortiGate")}
      ${card("chOrigin", "منشأ بلاک‌های موفق")}
      ${card("chTicket", "تیکت‌های Redmine")}
      ${card("chSnap", "روند جامانده از بلاک", true, "عکس روزانه (ساعتی به‌روز می‌شود)؛ از نسخه‌ی 0.5 ثبت می‌شود")}
      ${card("chRuns", "اجراها")}
      <div class="chart-card"><div class="chart-head"><h3>کشورهای پرتکرار (مخرب)</h3></div>${hbars(d.top_countries, "cc")}</div>
      <div class="chart-card wide"><div class="chart-head"><h3>ISPهای پرتکرار (مخرب)</h3></div>${hbars(d.top_isps, "isp")}</div>
    </div>`;
  const L2 = d.labels;
  drawChart($("#chAbuse"), L2, [{ name: "مخرب", color: c.err, values: S2.abuse.ABUSE }, { name: "غیرمخرب", color: c.ok, values: S2.abuse.CLEAN }, { name: "خطا", color: c.warn, values: S2.abuse.ERROR }]);
  drawChart($("#chSource"), L2, [{ name: "آنلاین", color: c.info, values: S2.source.online }, { name: "کش", color: c.acc, values: S2.source.cache }, { name: "ورود داده / دستی", color: c.faint, values: S2.source.import }]);
  drawChart($("#chBan"), L2, [{ name: "موفق", color: c.ok, values: S2.ban.ok }, { name: "ناموفق", color: c.err, values: S2.ban.failed }, { name: "حالت تست", color: c.warn, values: S2.ban.test }]);
  drawChart($("#chOrigin"), L2, [{ name: "مخرب", color: c.err, values: S2.ban_origin.abuse }, { name: "غیرمخرب خارجی", color: c.warn, values: S2.ban_origin.clean_foreign }, { name: "دستی / دیتابیس", color: c.faint, values: S2.ban_origin.manual }, { name: "بررسی تکمیلی", color: c.info, values: S2.ban_origin.intel || [] }]);
  drawChart($("#chTicket"), L2, [{ name: "ساخته شد", color: c.acc, values: S2.ticket.ok }, { name: "حالت تست", color: c.warn, values: S2.ticket.test }]);
  drawChart($("#chSnap"), L2, [{ name: "جامانده از بلاک", color: c.err, values: S2.snapshot.fw_pending }], { type: "line" });
  drawChart($("#chRuns"), L2, [{ name: "موفق", color: c.ok, values: S2.runs.done }, { name: "ناموفق", color: c.err, values: S2.runs.failed }, { name: "متوقف", color: c.faint, values: S2.runs.cancelled }]);
}
/* ---------------------------------------------------------------- آمار ← IPهای تکراری
 * هر روزی که IP به مرحله‌ی AbuseIPDB رسیده (آنلاین یا از کش) یک روز حساب می‌شود؛ چند بار در یک روز = یک روز. */
const RP = { min: 0, only: true, q: "", data: null, sel: new Set() };
async function loadRepeat() {
  const r = await api("repeat_ips", RP.min || 0, RP.only);
  if (!r.ok) return toast(r.error, "error");
  RP.data = r; RP.min = r.min_days;
  if (ST.tab === "repeat" && $("#page-stats").classList.contains("active")) renderRepeat();
}
function repeatRows() {
  const q = RP.q.trim().toLowerCase();
  return (RP.data ? RP.data.rows : []).filter((r) => !q || [r.ip, r.country_code, r.isp].some((x) => String(x || "").toLowerCase().includes(q)));
}
function renderRepeat() {
  const d = RP.data, body = $("#statsBody");
  if (!d) { body.innerHTML = `<div class="panel"><div class="empty">در حال بارگذاری…</div></div>`; return; }
  const rows = repeatRows(), act = canTool("abuse");
  RP.sel = new Set([...RP.sel].filter((ip) => rows.some((r) => r.ip === ip)));
  const fwT = (v) => (v ? `<span class="tag ${(FW[v] || ["mute"])[0]}">${esc((FW[v] || [0, v])[1])}</span>` : "—");
  const focus = document.activeElement && document.activeElement.id === "rpQ";
  body.innerHTML = `<div class="panel">
    <div class="toolbar" style="flex-wrap:wrap;gap:10px">
      <label class="field" style="margin:0"><span>حداقل روز</span><input type="number" min="1" max="365" id="rpMin" value="${esc(RP.min)}" style="width:90px"></label>
      <label class="chk"><input type="checkbox" id="rpOnly" ${RP.only ? "checked" : ""}>فقط غیرمخرب و بلاک‌نشده</label>
      <input type="search" class="search" id="rpQ" placeholder="جستجو در IP، کشور، ISP…" value="${esc(RP.q)}" style="max-width:260px">
      <span style="flex:1"></span>
      ${act ? `<button class="btn sm no-ro" id="rpRecheck" ${RP.sel.size ? "" : "disabled"}>بررسی مجدد در AbuseIPDB (${num(RP.sel.size)})</button>` : ""}
      <button class="btn sm no-ro" id="rpCsv" ${rows.length ? "" : "disabled"}>خروجی CSV</button>
    </div>
    <p class="hint">هر روزی که IP به مرحله‌ی AbuseIPDB رسیده (آنلاین یا از کش) یک روز حساب می‌شود؛ چند بار در یک روز = یک روز. ورود فایل و ثبت دستی حساب نمی‌شوند.
      ${d.threshold ? `هشدار و ایمیل وقتی IP غیرمخرب و بلاک‌نشده به ${num(d.threshold)} روز برسد و بعد از آن هر ${num(d.threshold)} روز دیگر (تنظیمات ← AbuseIPDB).` : "هشدار تکرار خاموش است (تنظیمات ← AbuseIPDB)."}
      ${d.total > d.rows.length ? `<br>${num(d.rows.length)} مورد اول از ${num(d.total)} نمایش داده شده است.` : ""}</p>
    ${rows.length ? `<div class="table-wrap inner"><table class="grid" id="rpTable"><thead><tr>${act ? `<th class="chk nosort"><input type="checkbox" id="rpAll" ${RP.sel.size && RP.sel.size === rows.length ? "checked" : ""}></th>` : ""}
      <th>IP</th><th>روزها</th><th>اولین</th><th>آخرین</th><th>وضعیت</th><th>امتیاز</th><th>کشور</th><th>ISP</th><th>FortiGate</th><th>بررسی تکمیلی</th><th>آخرین هشدار</th></tr></thead><tbody>
      ${rows.map((r) => `<tr>${act ? `<td class="chk"><input type="checkbox" class="rpIp" value="${esc(r.ip)}" ${RP.sel.has(r.ip) ? "checked" : ""}></td>` : ""}
        <td class="ltr"><span class="link ip" data-ipd="${esc(r.ip)}">${esc(r.ip)}</span></td><td class="num"><b>${num(r.days)}</b></td>
        <td class="ltr nowrap">${fmtDate(r.first)}</td><td class="ltr nowrap">${fmtDate(r.last)}</td><td>${r.abuse_status === "REMOVED" ? `<span class="tag mute" title="IP غیرمخرب پس از مدت تنظیم‌شده از فهرست آدرس‌ها حذف شده؛ سابقه‌ی آماری‌اش می‌ماند">حذف‌شده از فهرست</span>` : statusTag(r.abuse_status)}</td>
        <td>${scoreHtml(r.score)}</td><td>${esc(r.country_code || "—")}</td><td class="wrap" style="min-width:150px">${esc(r.isp || "—")}</td><td>${fwT(r.fw_status)}</td>
        <td>${intelTag(r)}</td><td class="num">${r.alerted ? `${num(r.alerted)} روز` : "—"}</td></tr>`).join("")}</tbody></table></div>`
      : `<div class="empty">موردی با این شرایط نیست.</div>`}</div>`;
  const q = $("#rpQ"); q.oninput = () => { RP.q = q.value; renderRepeat(); };
  if (focus) { q.focus(); q.setSelectionRange(q.value.length, q.value.length); }
  $("#rpMin").onchange = (e) => { RP.min = Math.max(1, Number(e.target.value) || 1); loadRepeat(); };
  $("#rpOnly").onchange = (e) => { RP.only = e.target.checked; loadRepeat(); };
  const all = $("#rpAll"); if (all) all.onchange = () => { RP.sel = all.checked ? new Set(rows.map((r) => r.ip)) : new Set(); renderRepeat(); };
  $$(".rpIp").forEach((c) => (c.onchange = () => { c.checked ? RP.sel.add(c.value) : RP.sel.delete(c.value); renderRepeat(); }));
  const act2 = async (a) => {
    const ips = [...RP.sel]; if (!ips.length) return;
    const r = await api("ips_action", a, ips);
    if (!r.ok) return toast(r.error, "error");
    toast(r.message || "انجام شد", "ok"); RP.sel.clear(); loadRepeat();
  };
  if ($("#rpRecheck")) $("#rpRecheck").onclick = () => act2("recheck");
  $("#rpCsv").onclick = async () => {
    const qv = (v) => `"${String(v ?? "").replace(/"/g, '""')}"`;
    const head = ["IP", "روزها", "اولین", "آخرین", "وضعیت", "امتیاز", "کشور", "ISP", "FortiGate", "بررسی تکمیلی", "آخرین هشدار (روز)"].map((x) => I18N.t(x));
    const lines = [head.map(qv).join(","), ...rows.map((r) => [r.ip, r.days, fmtDate(r.first), fmtDate(r.last), r.abuse_status, r.score, r.country_code, r.isp, r.fw_status,
      [r.intel_status, r.intel_source].filter(Boolean).join(" "), r.alerted || ""].map(qv).join(","))];
    const x = await api("save_export", "autokrp_repeat_ips.csv", lines.join("\r\n"), false);
    if (!x.ok) return toast(x.error, "error"); if (!x.cancelled) toast("ذخیره شد: " + x.path, "ok");
  };
}
$("#stRange").addEventListener("click", (e) => { const b = e.target.closest("button"); if (!b) return; ST.range = b.dataset.v; $$("#stRange button").forEach((x) => x.classList.toggle("on", x === b)); loadStats(); });
$("#stCal").addEventListener("click", (e) => {
  const b = e.target.closest("button"); if (!b) return; ST.cal = b.dataset.v;
  $$("#stCal button").forEach((x) => x.classList.toggle("on", x === b)); api("save_ui", "calendar", ST.cal); loadStats();
});
$("#btnStatsCsv").addEventListener("click", async () => {
  const d = ST.data; if (!d) return;
  const cols = [["abuse", "ABUSE", "مخرب"], ["abuse", "CLEAN", "غیرمخرب"], ["abuse", "ERROR", "خطا"], ["source", "online", "آنلاین"], ["source", "cache", "کش"],
    ["source", "import", "ورود داده"], ["ban", "ok", "بلاک موفق"], ["ban", "failed", "بلاک ناموفق"], ["ban", "test", "بلاک تست"],
    ["ban_origin", "abuse", "منشأ مخرب"], ["ban_origin", "clean_foreign", "منشأ غیرمخرب خارجی"], ["ban_origin", "intel", "منشأ بررسی تکمیلی"], ["ticket", "ok", "تیکت"],
    ["runs", "done", "اجرای موفق"], ["runs", "failed", "اجرای ناموفق"], ["snapshot", "fw_pending", "جامانده"]];
  const q = (v) => `"${String(v ?? "").replace(/"/g, '""')}"`;
  const lines = [[I18N.t("بازه"), ...cols.map((x) => I18N.t(x[2]))].map(q).join(",")];
  d.keys.forEach((key, i) => lines.push([key, ...cols.map(([a, b]) => d.series[a][b][i] ?? "")].map(q).join(",")));
  const r = await api("save_export", `autokrp_stats_${d.range}_${d.calendar}.csv`, lines.join("\r\n"), false);
  if (!r.ok) return toast(r.error, "error"); if (!r.cancelled) toast("ذخیره شد: " + r.path, "ok");
});
document.addEventListener("click", async (e) => {
  const b = e.target.closest("[data-png]"); if (!b) return;
  const r = await chartPng(b.dataset.png, b.dataset.title);
  if (!r) return;
  const s2 = await api("save_export", `autokrp_${b.dataset.png}_${ST.data.range}.png`, r, true);
  if (!s2.ok) return toast(s2.error, "error"); if (!s2.cancelled) toast("ذخیره شد: " + s2.path, "ok");
});
$("#btnStatsPngAll").addEventListener("click", (e) => withSpin(e.currentTarget, async () => {
  const items = [];
  for (const b of $$("[data-png]")) {
    const png = await chartPng(b.dataset.png, b.dataset.title);
    if (png) items.push([`autokrp_${b.dataset.png}_${ST.data.range}.png`, png]);
  }
  const r = await api("save_export_many", items);
  if (!r.ok) return toast(r.error, "error");
  if (!r.cancelled) toast(`${num(r.count)} تصویر ذخیره شد: ${r.path}`, "ok");
}));
/** نمودار را با عنوان، بازه و راهنما به PNG (base64) تبدیل می‌کند. */
function chartPng(id, title) { return new Promise((resolve) => {
  const svg = $(`#${id} svg`), leg = $(`#${id} .legend`); if (!svg) return resolve(null);
  const b = { dataset: { title } };
  const c = COLORS(), W = 1360, H = Math.round((W * svg.viewBox.baseVal.height) / svg.viewBox.baseVal.width) + 90;
  const canvas = document.createElement("canvas"); canvas.width = W; canvas.height = H;
  const ctx = canvas.getContext("2d");
  ctx.fillStyle = c.panel; ctx.fillRect(0, 0, W, H);
  ctx.fillStyle = cssVar("--text"); ctx.font = I18N.lang === "en" ? "600 26px Vazir, Segoe UI, Tahoma" : "600 26px VazirUI, Tahoma";
  const rtl = I18N.lang !== "en";
  ctx.textAlign = rtl ? "right" : "left"; ctx.direction = rtl ? "rtl" : "ltr";
  ctx.fillText(`${I18N.t(b.dataset.title)} — \u2066${ST.data.period[0]}\u2069 ${rtl ? "تا" : "to"} \u2066${ST.data.period[1]}\u2069`, rtl ? W - 24 : 24, 38);
  const fnt = rtl ? "VazirUI, Tahoma" : "Vazir, Segoe UI, Tahoma";
  ctx.font = "18px " + fnt; let x = rtl ? W - 24 : 24;
  $$("span", leg).forEach((sp) => {
    const col = sp.querySelector("i").style.background, t = sp.textContent, w = ctx.measureText(t).width;
    ctx.fillStyle = col; ctx.fillRect(rtl ? x - 14 : x, 56, 14, 14); ctx.fillStyle = c.text;
    ctx.fillText(t, rtl ? x - 22 : x + 22, 69); x += (rtl ? -1 : 1) * (w + 50);
  });
  const clone = svg.cloneNode(true); clone.querySelectorAll(".hit").forEach((h) => h.remove());
  clone.setAttribute("width", W); clone.setAttribute("height", H - 90);
  const img = new Image();
  img.onload = () => { ctx.drawImage(img, 0, 84, W, H - 90); resolve(canvas.toDataURL("image/png").split(",")[1]); };
  img.onerror = () => resolve(null);
  img.src = "data:image/svg+xml;charset=utf-8," + encodeURIComponent(new XMLSerializer().serializeToString(clone));
}); }

let _rsz;
window.addEventListener("resize", () => { clearTimeout(_rsz); _rsz = setTimeout(() => { if (S.page === "stats" && ST.data && ST.tab !== "monitor") renderStats(); }, 200); });

/* ================================================================ SSH */
const SSH = { tab: "devices", devices: [], scripts: [], types: [], groups: [], vars: [], sel: new Set(), q: "", grp: "",
  run: { scriptId: "", name: "", body: "", mode: "exec", use_sudo: false, save_config: false, devs: new Set(), concurrency: 5, timeout: 60 },
  job: null, jobSig: "", bk: { dev: null, pick: [] } };
const SSH_ST = { ok: ["ok", "موفق"], failed: ["err", "ناموفق"], running: ["info", "در حال اجرا"], pending: ["mute", "در صف"], cancelled: ["mute", "متوقف"], skipped: ["mute", "اجرا نشد"] };
const typeName = (t) => (SSH.types.find((x) => x[0] === t) || [t, t])[1];
const isLinux = (id) => (SSH.devices.find((d) => d.id === id) || {}).device_type === "linux";
async function loadSsh() {
  const lv = ((S.state || {}).access || {}).ssh;
  if (lv === "none") {                       // 1.32: فقط ترمینال یا ابزارهای شبکه (بدون دسترسی به فهرست دستگاه‌های SSH)
    Object.assign(SSH, { devices: [], scripts: [], creds: [], groups: [] });
    return renderSsh();
  }
  const [r, c] = await Promise.all([api("ssh_list"), isRO() || lv === "view" ? Promise.resolve({ ok: false }) : api("cred_list")]);
  if (!r.ok) return toast(r.error, "error");
  Object.assign(SSH, { devices: r.devices, scripts: r.scripts, types: r.types, telnetTypes: r.telnet_types || [], groups: r.groups, vars: r.vars, creds: c.ok ? c.profiles : [] });
  const ids = new Set(r.devices.map((d) => d.id));
  SSH.sel = new Set([...SSH.sel].filter((i) => ids.has(i))); SSH.run.devs = new Set([...SSH.run.devs].filter((i) => ids.has(i)));
  renderSsh();
}
function renderSsh() {
  if (!isAdmin() && SSH.tab === "fgu") SSH.tab = "run";
  if (S.state && S.state.me && S.state.me.role === "readonly" && ["term", "xfer", "creds", "net"].includes(SSH.tab)) SSH.tab = "devices";
  const tb = $(`#sshTabs button[data-t="${SSH.tab}"]`);
  if (tb && (tb.classList.contains("tool-off") || getComputedStyle(tb).display === "none")) {   // 1.32: تب پنهان برای این کاربر
    const first = $$("#sshTabs button").find((b) => !b.classList.contains("tool-off") && getComputedStyle(b).display !== "none");
    if (first) SSH.tab = first.dataset.t;
  }
  $$("#sshTabs button").forEach((b) => b.classList.toggle("on", b.dataset.t === SSH.tab));
  if (SSH.tab !== "term") termHide();
  ({ devices: sshDevices, creds: sshCreds, run: sshRun, term: sshTerm, xfer: sshXfer, net: sshNet, backups: sshBackups, fgu: sshFgu, jobs: sshJobs, api: sshApi })[SSH.tab]();
}
$("#sshTabs").addEventListener("click", (e) => { const b = e.target.closest("button[data-t]"); if (b) { SSH.tab = b.dataset.t; renderSsh(); } });
function typeOptions(cur, withAny = false) {
  return (withAny ? `<option value="any" ${cur === "any" ? "selected" : ""}>همه‌ی انواع</option>` : "") + SSH.types.map(([v, t]) => `<option value="${v}" ${v === cur ? "selected" : ""}>${esc(t)}</option>`).join("");
}
const stTag = (s) => { const st = SSH_ST[s] || ["mute", "—"]; return `<span class="tag ${st[0]}">${st[1]}</span>`; };

/* ---------- devices ---------- */
function sshDevices() {
  const canTerm = shown("term") && !(S.state && S.state.me && S.state.me.role === "readonly");   // دکمه‌ی «ترمینال» هر دستگاه
  $("#sshActions").innerHTML = `<button class="btn ghost adm-only" id="sshKeys" data-need-run="ssh">کلیدهای میزبان</button><button class="btn adm-only" id="sshBulk" data-need-run="ssh">افزودن گروهی</button><button class="btn primary" id="sshAdd" data-need-run="ssh">${isAdmin() ? "افزودن دستگاه" : "افزودن دستگاه شخصی"}</button>`;
  const q = SSH.q.toLowerCase();
  const rows = SSH.devices.filter((d) => (!SSH.grp || d.grp === SSH.grp) && (!q || [d.name, d.host, d.grp, d.username, typeName(d.device_type)].some((x) => String(x || "").toLowerCase().includes(q))));
  const allSel = rows.length && rows.every((d) => SSH.sel.has(d.id));
  $("#sshBody").innerHTML = `<div class="toolbar"><input type="search" class="search" id="sshQ" placeholder="جستجو در نام، آدرس، گروه…" value="${esc(SSH.q)}">
      <select id="sshGrp" style="width:auto"><option value="">همه‌ی گروه‌ها</option>${SSH.groups.map((g) => `<option ${g === SSH.grp ? "selected" : ""}>${esc(g)}</option>`).join("")}</select>
      <span class="muted">${num(rows.length)} دستگاه</span></div>
    <div class="table-wrap"><table class="grid"><thead><tr><th class="chk nosort"><input type="checkbox" id="sshAll" ${allSel ? "checked" : ""}></th>
      ${["نام", "آدرس", "نوع", "گروه", "آخرین وضعیت", "پشتیبان"].map((t) => `<th class="nosort">${t}</th>`).join("")}${canTerm ? `<th class="nosort"></th>` : ""}</tr></thead><tbody>
      ${rows.length ? rows.map((d) => `<tr class="${SSH.sel.has(d.id) ? "sel" : ""}"><td class="chk"><input type="checkbox" class="sshChk" value="${d.id}" ${SSH.sel.has(d.id) ? "checked" : ""}></td>
        <td><span class="link tech" data-edit="${d.id}">${esc(d.name)}</span>${d.personal ? ` <span class="tag info" title="فقط شما این دستگاه را می‌بینید">شخصی</span>` : ""}${d.has_password ? "" : ` <span class="tag warn">بدون پسورد</span>`}${d.cred_id ? ` <span class="tag mute" title="اعتبارنامه از پروفایل">🔑 ${esc(d.cred_name || "")}</span>` : ""}</td>
        <td class="ltr">${esc(d.host)}${Number(d.port) !== (d.protocol === "telnet" ? 23 : 22) ? ":" + esc(d.port) : ""}${d.protocol === "telnet" ? ` <span class="tag warn" title="Telnet بدون رمزنگاری است">Telnet</span>` : ""}</td><td>${esc(typeName(d.device_type))}</td><td>${esc(d.grp || "—")}</td>
        <td class="wrap" title="${esc(d.last_message || "")}">${d.last_status ? `${stTag(d.last_status)} <span class="muted">${fmtDate(d.last_at)}</span>` : "—"}</td>
        <td>${d.backup_on ? `<span class="tag ok" title="${esc(d.backup_message || "")}">✓</span>` : `<span class="muted">—</span>`}</td>
        ${canTerm ? `<td class="nowrap"><button class="btn sm ghost" data-term="${d.id}" title="${esc(d.has_password ? "اتصال مستقیم در ترمینال" : "یوزر یا پسورد این دستگاه ذخیره نشده است")}"${d.has_password ? "" : " disabled"}><svg style="width:15px;height:15px"><use href="#i-term"/></svg>ترمینال</button></td>` : ""}</tr>`).join("")
      : `<tr><td colspan="${canTerm ? 8 : 7}"><div class="empty">${SSH.devices.length ? "موردی با این فیلتر نیست." : "هنوز دستگاهی اضافه نشده است."}</div></td></tr>`}</tbody></table></div>
    <p class="hint" style="margin-top:10px">یوزر، پسورد و رمز enable/sudo فقط در فایل رمزنگاری‌شده نگهداری می‌شوند. کلید میزبان هر دستگاه بار اول ثبت می‌شود (TOFU) و اگر عوض شود اتصال قبل از ارسال پسورد قطع می‌شود.</p>
    <div class="selbar" id="sshSelBar" ${SSH.sel.size ? "" : "hidden"}><b>${num(SSH.sel.size)} مورد انتخاب شده</b>
      <button class="btn sm" data-sa="test" data-need-run="ssh">تست اتصال</button><button class="btn sm" data-sa="run" data-need-run="ssh">اجرای اسکریپت</button>
      <button class="btn sm" data-sa="backup" data-need-run="ssh">پشتیبان‌گیری الان</button><button class="btn sm danger-ghost" data-sa="del" data-need-run="ssh">حذف</button>
      <button class="btn sm ghost" data-sa="clear">لغو انتخاب</button></div>`;
  $("#sshQ").oninput = (e) => { SSH.q = e.target.value; const p = e.target.selectionStart; sshDevices(); const i = $("#sshQ"); i.focus(); i.selectionStart = i.selectionEnd = p; };
  $("#sshGrp").onchange = (e) => { SSH.grp = e.target.value; sshDevices(); };
  $("#sshAll").onchange = (e) => { rows.forEach((d) => (e.target.checked ? SSH.sel.add(d.id) : SSH.sel.delete(d.id))); sshDevices(); };
  $$(".sshChk").forEach((c) => (c.onchange = () => { const id = Number(c.value); c.checked ? SSH.sel.add(id) : SSH.sel.delete(id); sshDevices(); }));
  $$("[data-edit]").forEach((b) => (b.onclick = () => { if (!String(window.getSelection() || "").trim()) deviceModal(SSH.devices.find((d) => d.id === Number(b.dataset.edit))); }));
  // اتصال مستقیم: رفتن به تب ترمینال و باز کردن نشست همین دستگاه (با یوزر/پسورد ذخیره‌شده؛ مثل «اتصال تازه»)
  $$("[data-term]").forEach((b) => (b.onclick = () => { SSH.tab = "term"; renderSsh(); setTimeout(() => termOpen({ device_id: Number(b.dataset.term) }), 60); }));
  $("#sshAdd").onclick = () => deviceModal(null);
  $("#sshBulk").onclick = () => bulkModal();
  $("#sshKeys").onclick = () => keysModal();
  $$("[data-sa]").forEach((b) => (b.onclick = async () => {
    const ids = [...SSH.sel], a = b.dataset.sa;
    if (a === "clear") { SSH.sel.clear(); return sshDevices(); }
    if (a === "run") { SSH.run.devs = new Set(ids); SSH.tab = "run"; return renderSsh(); }
    if (a === "test") { const r = await api("ssh_test", ids); if (!r.ok) return toast(r.error, "error"); toast("تست اتصال شروع شد", "ok"); SSH.tab = "run"; return renderSsh(); }
    if (a === "backup") { const r = await api("backup_now", ids); if (!r.ok) return toast(r.error, "error"); toast("پشتیبان‌گیری شروع شد", "ok"); SSH.tab = "backups"; return renderSsh(); }
    if (a === "del") {
      const ok = await confirm2({ title: "حذف دستگاه‌ها", danger: true, confirm: `حذف ${ids.length} دستگاه`,
        body: `<p>دستگاه‌ها و یوزر/پسوردهایشان از فایل رمزشده حذف می‌شوند. سابقه‌ی اجراها می‌ماند.</p>` });
      if (!ok) return;
      const r = await api("ssh_delete_devices", ids); if (!r.ok) return toast(r.error, "error");
      SSH.sel.clear(); toast("حذف شد", "ok"); loadSsh();
    }
  }));
}
/* ---------- پروفایل‌های اعتبارنامه: یک یوزر/پسورد برای چند دستگاه ---------- */
function sshCreds() {
  $("#sshActions").innerHTML = `<button class="btn primary" id="crAdd">پروفایل تازه</button>`;
  const L = SSH.creds || [];
  $("#sshBody").innerHTML = `<p class="hint">یک بار یوزر، پسورد و رمز enable/sudo را اینجا تعریف کنید و در «ویرایش دستگاه» یا «افزودن گروهی» به‌جای یوزر و پسورد اختصاصی، پروفایل را انتخاب کنید. با عوض کردن پسورد پروفایل، همه‌ی دستگاه‌هایش همان لحظه رمز تازه را استفاده می‌کنند.
      <span>${isAdmin() ? "پروفایل مشترک فقط برای دستگاه‌های مشترک و پروفایل شخصی فقط برای دستگاه‌های شخصی خودتان است." : "پروفایل‌های شما شخصی‌اند و فقط برای دستگاه‌های شخصی خودتان قابل انتخاب‌اند."}</span></p>
    <div class="table-wrap"><table class="grid"><thead><tr>${["نام", "یوزر", "پسورد", "enable / sudo", "دستگاه‌ها", "یادداشت", ""].map((t) => `<th class="nosort">${t}</th>`).join("")}</tr></thead><tbody>
    ${L.length ? L.map((p) => `<tr><td><b>${esc(p.name)}</b>${p.personal ? ` <span class="tag info">شخصی</span>` : ""}</td><td class="ltr">${esc(p.username || "—")}</td>
      <td>${p.has_password ? `<span class="tag ok">✓</span>` : `<span class="tag warn">ندارد</span>`}</td><td>${p.has_secret ? "✓" : "—"}</td>
      <td>${num(p.devices || 0)}</td><td class="wrap">${esc(p.notes || "")}</td>
      <td class="nowrap">${!p.personal && !isAdmin() ? "" : `<button class="btn sm" data-cre="${p.id}">ویرایش</button> <button class="btn sm danger-ghost" data-crd="${p.id}">حذف</button>`}</td></tr>`).join("")
      : `<tr><td colspan="7"><div class="empty">هنوز پروفایلی ساخته نشده است.</div></td></tr>`}</tbody></table></div>`;
  $("#crAdd").onclick = () => credModal(null);
  $$("[data-cre]").forEach((b) => (b.onclick = () => credModal(L.find((p) => p.id === Number(b.dataset.cre)))));
  $$("[data-crd]").forEach((b) => (b.onclick = async () => {
    const p = L.find((x) => x.id === Number(b.dataset.crd));
    if (!(await confirm2({ title: "حذف پروفایل", danger: true, confirm: "حذف", body: `<p>پروفایل «${esc(p.name)}» و یوزر/پسوردش حذف شود؟</p>` }))) return;
    const r = await api("cred_delete", p.id); if (!r.ok) return toast(r.error, "error");
    toast("حذف شد", "ok"); loadSsh();
  }));
}
function credModal(p) {
  const isNew = !p; p = p || { name: "", username: "", notes: "", kind: "ssh" };
  openModal({ title: isNew ? "پروفایل اعتبارنامه‌ی تازه" : `ویرایش ${p.name}`, body: `<div class="form-grid">
      <label class="field"><span>نام پروفایل</span><input type="text" id="crName" value="${esc(p.name)}" placeholder="مثلاً روترهای شعبه"></label>
      <label class="field"><span>یوزر</span><input type="text" class="ltr" id="crUser" value="${esc(p.username || "")}" autocomplete="off"></label>
      <label class="field"><span>پسورد</span><input type="password" class="ltr" id="crPw" placeholder="${p.has_password ? "ذخیره شده — برای تغییر مقدار جدید وارد کنید" : ""}" autocomplete="new-password"></label>
      <label class="field"><span>رمز enable / sudo (اختیاری)</span><input type="password" class="ltr" id="crSec" placeholder="${p.has_secret ? "ذخیره شده" : ""}" autocomplete="new-password"></label>
      ${isNew && isAdmin() && S.state && S.state.me && !S.state.me.single ? `<div class="field"><span>&nbsp;</span><label class="switch"><input type="checkbox" id="crPersonal"><span class="track"><span class="thumb"></span></span>پروفایل شخصی (فقط من)</label></div>` : ""}
      <label class="field wide"><span>یادداشت</span><input type="text" id="crNotes" value="${esc(p.notes || "")}"></label></div>
      ${!isNew && p.devices ? `<p class="hint warn">${num(p.devices)} دستگاه از این پروفایل استفاده می‌کنند؛ تغییر پسورد روی همه‌ی آن‌ها اثر دارد.</p>` : ""}`,
    foot: `${!isNew && p.has_secret ? `<button class="btn ghost" id="crClrSec" style="margin-inline-end:auto">پاک کردن رمز enable</button>` : ""}<button class="btn ghost" data-x="0">انصراف</button><button class="btn primary" id="crSave">ذخیره</button>`,
    onOpen: (m, close) => {
      $("[data-x]", m).onclick = () => close();
      const save = async (clrSec) => {
        const prof = { id: isNew ? null : p.id, name: $("#crName", m).value, username: $("#crUser", m).value, notes: $("#crNotes", m).value, kind: "ssh",
          personal: !!($("#crPersonal", m) && $("#crPersonal", m).checked) };
        const r = await api("cred_save", prof, $("#crPw", m).value, clrSec ? "__clear__" : $("#crSec", m).value);
        if (!r.ok) return toast(r.error, "error");
        toast("ذخیره شد", "ok"); close(); loadSsh();
      };
      $("#crSave", m).onclick = () => save(false);
      const c = $("#crClrSec", m); if (c) c.onclick = () => save(true);
    } });
}
function deviceModal(d) {
  const isNew = !d; d = d || { name: "", host: "", port: 22, device_type: "cisco_ios", grp: "", username: "", use_enable: 0, notes: "", backup: null, protocol: "ssh" };
  const secretLabel = (t) => (t === "linux" ? "رمز sudo (خالی = همان پسورد ورود)" : "رمز enable (secret)");
  const bkOn = d.backup === null || d.backup === undefined ? d.device_type !== "linux" : !!d.backup;
  openModal({ title: isNew ? "افزودن دستگاه" : `ویرایش ${d.name}`, wide: true, body: `<div class="form-grid">
      <label class="field"><span>نام</span><input type="text" id="dvName" value="${esc(d.name)}"></label>
      <label class="field"><span>آدرس (IP یا نام میزبان)</span><input type="text" class="ltr" id="dvHost" value="${esc(d.host)}"></label>
      <label class="field"><span>پروتکل</span><select id="dvProto"><option value="ssh">SSH</option><option value="telnet" ${d.protocol === "telnet" ? "selected" : ""}>Telnet</option></select></label>
      <label class="field"><span>پورت</span><input type="number" class="ltr" id="dvPort" value="${esc(d.port || 22)}"></label>
      <label class="field"><span>نوع دستگاه</span><select id="dvType">${typeOptions(d.device_type)}</select></label>
      <label class="field"><span>گروه</span><input type="text" id="dvGrp" list="dvGroups" value="${esc(d.grp || "")}"><datalist id="dvGroups">${SSH.groups.map((g) => `<option>${esc(g)}</option>`).join("")}</datalist></label>
      <label class="field"><span>اعتبارنامه</span><select id="dvCred"></select></label>
      <label class="field dvOwn"><span>یوزر</span><input type="text" class="ltr" id="dvUser" value="${esc(d.cred_id ? "" : d.username || "")}" autocomplete="off"></label>
      <label class="field dvOwn"><span>پسورد</span><input type="password" class="ltr" id="dvPw" placeholder="${d.has_password ? "ذخیره شده — برای تغییر مقدار جدید وارد کنید" : ""}" autocomplete="new-password"></label>
      <label class="field dvOwn"><span id="dvSecL">${secretLabel(d.device_type)}</span><input type="password" class="ltr" id="dvSec" placeholder="${d.has_secret ? "ذخیره شده" : ""}" autocomplete="new-password"></label>
      <div class="field wide"><div class="row" style="gap:24px;flex-wrap:wrap">
        <label class="switch"><input type="checkbox" id="dvEn" ${d.use_enable ? "checked" : ""}><span class="track"><span class="thumb"></span></span><span id="dvEnL">${d.device_type === "linux" ? "اجازه‌ی sudo" : "ورود به حالت enable"}</span></label>
        ${isAdmin() && !d.personal ? `<label class="switch"><input type="checkbox" id="dvBk" ${bkOn ? "checked" : ""}><span class="track"><span class="thumb"></span></span>پشتیبان‌گیری کانفیگ</label>` : ""}
        ${isNew && isAdmin() && S.state && S.state.me && !S.state.me.single ? `<label class="switch" title="فقط شما این دستگاه را می‌بینید و استفاده می‌کنید"><input type="checkbox" id="dvPersonal"><span class="track"><span class="thumb"></span></span>دستگاه شخصی (فقط من)</label>` : ""}
        <label class="switch dvSshOnly" title="فقط برای دستگاه‌هایی که الگوریتم امروزی ندارند (خطای no acceptable kex)"><input type="checkbox" id="dvLeg" ${d.legacy ? "checked" : ""}><span class="track"><span class="thumb"></span></span>سازگاری با دستگاه قدیمی (SHA1)</label></div>
        <small class="hint warn-text" id="dvTelHint" hidden>Telnet رمزنگاری ندارد: یوزر، رمز و کانفیگ روی شبکه خوانا منتقل می‌شوند. فقط برای دستگاه‌هایی که SSH ندارند و در شبکه‌ی مدیریتی امن. Telnet فقط برای تجهیزات شبکه (نه لینوکس، ASA، MikroTik و FortiGate) در دسترس است.</small>
        <small class="hint dvSshOnly">«سازگاری با دستگاه قدیمی» الگوریتم‌های ضعیف‌تر (diffie-hellman-group1/14-sha1 و ssh-rsa) را فقط برای همین دستگاه مجاز می‌کند؛ فقط وقتی روشن کنید که اتصال با خطای الگوریتم رد می‌شود.</small></div>
      <label class="field wide"><span>یادداشت</span><input type="text" id="dvNotes" value="${esc(d.notes || "")}"></label></div>`,
    foot: `${isNew ? "" : `<button class="btn ghost" id="dvClear" style="margin-inline-end:auto">پاک کردن رمزهای ذخیره‌شده</button>`}<button class="btn ghost" data-x="0">انصراف</button><button class="btn primary" id="dvSave">ذخیره</button>`,
    onOpen: (m, close) => {
      const protoUi = () => {
        const tel = $("#dvProto", m).value === "telnet", okType = (SSH.telnetTypes || []).includes($("#dvType", m).value);
        $$(".dvSshOnly", m).forEach((x) => (x.hidden = tel));
        $("#dvTelHint", m).hidden = !tel;
        $("#dvProto option[value='telnet']", m).disabled = !okType;
        if (tel && !okType) { $("#dvProto", m).value = "ssh"; protoUi(); }
      };
      $("#dvProto", m).onchange = () => { const p = $("#dvPort", m); if (["22", "23", ""].includes(p.value)) p.value = $("#dvProto", m).value === "telnet" ? 23 : 22; protoUi(); };
      $("#dvType", m).onchange = (e) => { $("#dvSecL", m).textContent = secretLabel(e.target.value); $("#dvEnL", m).textContent = e.target.value === "linux" ? "اجازه‌ی sudo" : "ورود به حالت enable"; protoUi(); };
      protoUi();
      $("[data-x]", m).onclick = () => close();
      // دستگاه مشترک فقط پروفایل مشترک؛ دستگاه شخصی فقط پروفایل شخصی (رمز مشترک به دستگاهی با آدرس دلخواه اپراتور نرسد)
      const personal = () => (isNew ? !isAdmin() || !!($("#dvPersonal", m) && $("#dvPersonal", m).checked) : !!d.personal);
      const fillCred = () => {
        const cur = $("#dvCred", m).value || String(d.cred_id || ""), pl = (SSH.creds || []).filter((p) => p.kind === "ssh" && p.personal === personal());
        $("#dvCred", m).innerHTML = `<option value="">اختصاصی همین دستگاه</option>` + pl.map((p) => `<option value="${p.id}" ${String(p.id) === cur ? "selected" : ""}>🔑 ${esc(p.name)} (${esc(p.username)})</option>`).join("");
        const own = !$("#dvCred", m).value;
        $$(".dvOwn", m).forEach((x) => (x.hidden = !own));
        const cl = $("#dvClear", m); if (cl) cl.hidden = !own;
      };
      fillCred();
      $("#dvCred", m).onchange = fillCred;
      if ($("#dvPersonal", m)) $("#dvPersonal", m).onchange = fillCred;
      const save = async (clear) => {
        const dev = { id: isNew ? null : d.id, cred_id: $("#dvCred", m).value || null, name: $("#dvName", m).value, host: $("#dvHost", m).value, port: $("#dvPort", m).value, device_type: $("#dvType", m).value,
          grp: $("#dvGrp", m).value, username: $("#dvUser", m).value, use_enable: $("#dvEn", m).checked, notes: $("#dvNotes", m).value, backup: $("#dvBk", m) ? $("#dvBk", m).checked : false, legacy: $("#dvLeg", m).checked, protocol: $("#dvProto", m).value,
          personal: !isAdmin() || !!($("#dvPersonal", m) && $("#dvPersonal", m).checked) };
        const r = await api("ssh_save_device", dev, clear ? "__clear__" : $("#dvPw", m).value, clear ? "__clear__" : $("#dvSec", m).value);
        if (!r.ok) return toast(r.error, "error");
        toast("ذخیره شد", "ok"); close(); loadSsh();
      };
      $("#dvSave", m).onclick = () => save(false);
      const cl = $("#dvClear", m); if (cl) cl.onclick = () => save(true);
    } });
}
function bulkModal() {
  openModal({ title: "افزودن گروهی دستگاه", wide: true, body: `
    <p class="hint">هر خط یک دستگاه. فقط آدرس (مثل <span class="ltr">10.0.0.1</span> یا <span class="ltr">10.0.0.1:2222</span>) یا CSV با این ترتیب:</p>
    <div class="codebox">host,port,username,password,device_type,secret,name,group</div>
    <p class="hint">ستون‌های خالی از «مقادیر مشترک» پایین پر می‌شوند. خطوطی که با # شروع شوند نادیده گرفته می‌شوند.</p>
    <textarea class="ltr code-edit" id="bkText" style="min-height:160px" placeholder="10.0.0.1&#10;10.0.0.2:2222&#10;10.0.0.3,22,admin,P@ss,cisco_ios,En@ble,core-sw,Core"></textarea>
    <h3 style="margin:14px 0 8px">مقادیر مشترک</h3><div class="form-grid">
      <label class="field"><span>نوع دستگاه</span><select id="bkType">${typeOptions("cisco_ios")}</select></label>
      <label class="field"><span>پروتکل</span><select id="bkProto"><option value="ssh">SSH</option><option value="telnet">Telnet</option></select></label>
      <label class="field"><span>پورت</span><input type="number" class="ltr" id="bkPort" value="22"></label>
      <label class="field"><span>گروه</span><input type="text" id="bkGrp" list="dvGroups2"><datalist id="dvGroups2">${SSH.groups.map((g) => `<option>${esc(g)}</option>`).join("")}</datalist></label>
      <label class="field"><span>اعتبارنامه</span><select id="bkCred"><option value="">یوزر و پسورد همین فرم / ستون‌های CSV</option>${(SSH.creds || []).filter((p) => p.kind === "ssh" && !p.personal).map((p) => `<option value="${p.id}">🔑 ${esc(p.name)} (${esc(p.username)})</option>`).join("")}</select></label>
      <label class="field bkOwn"><span>یوزر</span><input type="text" class="ltr" id="bkUser" autocomplete="off"></label>
      <label class="field bkOwn"><span>پسورد</span><input type="password" class="ltr" id="bkPw" autocomplete="new-password"></label>
      <label class="field bkOwn"><span>رمز enable / sudo</span><input type="password" class="ltr" id="bkSec" autocomplete="new-password"></label>
      <div class="field"><span>&nbsp;</span><label class="switch"><input type="checkbox" id="bkEn"><span class="track"><span class="thumb"></span></span>enable / sudo</label></div></div>
    <div id="bkOut" style="margin-top:12px"></div>`,
    foot: `<button class="btn" id="bkPrev">پیش‌نمایش</button><button class="btn primary" id="bkGo" disabled>افزودن</button>`,
    onOpen: (m, close) => {
      $("#bkCred", m).onchange = () => $$(".bkOwn", m).forEach((x) => (x.hidden = !!$("#bkCred", m).value));
      $("#bkProto", m).onchange = (e) => { const p = $("#bkPort", m); if (["22", "23", ""].includes(p.value)) p.value = e.target.value === "telnet" ? 23 : 22; };
      const dfl = () => ({ protocol: $("#bkProto", m).value, device_type: $("#bkType", m).value, port: $("#bkPort", m).value, grp: $("#bkGrp", m).value, username: $("#bkUser", m).value,
        password: $("#bkPw", m).value, secret: $("#bkSec", m).value, use_enable: $("#bkEn", m).checked, cred_id: $("#bkCred", m).value || null });
      $("#bkPrev", m).onclick = (e) => withSpin(e.currentTarget, async () => {
        const r = await api("ssh_bulk_add", $("#bkText", m).value, dfl(), true); if (!r.ok) return toast(r.error, "error");
        $("#bkOut", m).innerHTML = `<p><b>${num(r.count)}</b> دستگاه آماده‌ی افزودن.</p>${r.errors.length ? `<div class="hint warn">${r.errors.map(esc).join("<br>")}</div>` : ""}
          <div class="table-wrap inner"><table class="grid"><thead><tr>${["نام", "آدرس", "نوع", "گروه", "یوزر", "پسورد"].map((t) => `<th class="nosort">${t}</th>`).join("")}</tr></thead><tbody>
          ${r.sample.map((d) => `<tr><td class="tech">${esc(d.name)}</td><td class="ltr">${esc(d.host)}:${esc(d.port)}</td><td>${esc(typeName(d.device_type))}</td><td>${esc(d.grp || "—")}</td><td class="ltr">${esc(d.username || "—")}</td><td>${d.has_password ? "✓" : "—"}</td></tr>`).join("")}</tbody></table></div>`;
        $("#bkGo", m).disabled = !r.count;
      });
      $("#bkGo", m).onclick = (e) => withSpin(e.currentTarget, async () => {
        const r = await api("ssh_bulk_add", $("#bkText", m).value, dfl(), false); if (!r.ok) return toast(r.error, "error");
        toast(`${num(r.count)} دستگاه اضافه شد`, "ok"); close(); loadSsh();
      });
    } });
}
async function keysModal() {
  const r = await api("ssh_hostkeys"); if (!r.ok) return toast(r.error, "error");
  openModal({ title: "کلیدهای میزبان", wide: true, body: `<p class="hint">کلید میزبان هر دستگاه در اولین اتصال ثبت می‌شود. اگر کلید عوض شود، اتصال قبل از ارسال پسورد قطع می‌شود. فقط وقتی مطمئن هستید دستگاه عوض شده (نصب دوباره، تعویض سخت‌افزار) کلید قبلی را حذف کنید تا کلید جدید ثبت شود.</p>
    <div class="table-wrap inner"><table class="grid"><thead><tr>${["میزبان", "نوع کلید", "اثر انگشت", ""].map((t) => `<th class="nosort">${t}</th>`).join("")}</tr></thead><tbody>
    ${r.keys.length ? r.keys.map((k) => `<tr><td class="ltr">${esc(k.host)}</td><td class="ltr">${esc(k.type)}</td><td class="ltr">${esc(k.fingerprint)}</td><td><button class="btn sm danger-ghost" data-fk="${esc(k.host)}">حذف</button></td></tr>`).join("")
      : `<tr><td colspan="4"><div class="empty">هنوز کلیدی ثبت نشده است.</div></td></tr>`}</tbody></table></div>`,
    onOpen: (m, close) => $$("[data-fk]", m).forEach((b) => (b.onclick = async () => {
      close();
      if (!(await confirm2({ title: "حذف کلید میزبان", danger: true, confirm: "حذف", body: `<p>کلید <span class="ltr">${esc(b.dataset.fk)}</span> حذف شود؟ اتصال بعدی کلید جدید را بدون هشدار ثبت می‌کند.</p>`, ack: "مطمئنم دستگاه واقعاً عوض شده است" }))) return keysModal();
      const x = await api("ssh_forget_hostkey", b.dataset.fk); if (!x.ok) return toast(x.error, "error"); toast("حذف شد", "ok"); keysModal();
    })) });
}

/* ---------- run: ۱) دستگاه‌ها ۲) اسکریپت ۳) پیش‌نمایش و اجرا ---------- */
function sshRun() {
  const R = SSH.run, job = SSH.job, running = job && job.status === "running";
  $("#sshActions").innerHTML = running ? `<button class="btn danger-ghost" id="sshStop">توقف اجرا</button>` : "";
  const sel = SSH.devices.filter((d) => R.devs.has(d.id));
  const hasLinux = sel.some((d) => d.device_type === "linux"), hasNet = sel.some((d) => d.device_type !== "linux");
  const sc = SSH.scripts.find((x) => String(x.id) === R.scriptId);
  $("#sshBody").innerHTML = `
    <div class="form"><div class="row" style="justify-content:space-between;flex-wrap:wrap;gap:10px"><h3><span class="stage-num" style="display:inline-grid;margin-inline-end:8px">1</span>دستگاه‌ها</h3>
        <button class="btn" id="rnPick">انتخاب دستگاه‌ها…</button></div>
      <div class="row" style="flex-wrap:wrap;gap:6px;margin-top:10px">${sel.length ? sel.slice(0, 14).map((d) => `<span class="chip tech">${esc(d.name)}</span>`).join("") + (sel.length > 14 ? `<span class="chip">+${num(sel.length - 14)}</span>` : "")
        : `<span class="muted">هنوز دستگاهی انتخاب نشده است.</span>`}</div></div>
    <div class="form"><div class="row" style="justify-content:space-between;flex-wrap:wrap;gap:10px"><h3><span class="stage-num" style="display:inline-grid;margin-inline-end:8px">2</span>اسکریپت</h3>
        <div class="row"><select id="rnScript" style="width:auto;min-width:220px"><option value="">— متن آزاد —</option>${SSH.scripts.map((x) => `<option value="${x.id}" ${String(x.id) === R.scriptId ? "selected" : ""}>${esc(x.name)}</option>`).join("")}</select>
        ${sc ? `<button class="btn sm adm-only" id="rnSaveSc">ذخیره</button><button class="btn sm ghost adm-only" id="rnDelSc">حذف</button>` : ""}<button class="btn sm adm-only" id="rnSaveAs">ذخیره به‌عنوان اسکریپت…</button></div></div>
      ${hasNet || hasLinux ? `<div class="row" style="gap:20px;margin:10px 0;flex-wrap:wrap">
        ${hasNet ? `<label class="chk"><input type="radio" name="rnMode" value="exec" ${R.mode !== "config" ? "checked" : ""}>exec — هر خط یک دستور (show و ...)</label>
          <label class="chk"><input type="radio" name="rnMode" value="config" ${R.mode === "config" ? "checked" : ""}>config — همه‌ی خطوط در حالت پیکربندی</label>
          <label class="chk"><input type="checkbox" id="rnSave" ${R.save_config ? "checked" : ""}>ذخیره‌ی کانفیگ بعد از اجرا (write memory / commit)</label>` : ""}
        ${hasLinux ? `<label class="chk"><input type="checkbox" id="rnSudo" ${R.use_sudo ? "checked" : ""}>اجرا با sudo (لینوکس)</label>` : ""}</div>` : ""}
      <div class="varbtns">${SSH.vars.map((v) => `<button data-v="${v}">{${v}}</button>`).join("")}</div>
      <textarea class="code-edit" id="rnBody" spellcheck="false" style="min-height:200px">${esc(R.body)}</textarea>
      <p class="hint">لینوکس: کل متن به‌صورت یک اسکریپت bash اجرا می‌شود. تجهیزات شبکه: هر خط یک دستور؛ خطوطی که با <span class="ltr">!#</span> شروع شوند توضیح هستند. متغیرها برای هر دستگاه جایگزین می‌شوند.</p>
      <details style="margin-top:6px"><summary class="muted" style="cursor:pointer">پیشرفته</summary><div class="form-grid" style="margin-top:10px">
        <label class="field"><span>اتصال همزمان</span><input type="number" min="1" max="20" id="rnConc" value="${R.concurrency}"></label>
        <label class="field"><span>Timeout هر دستگاه (ثانیه)</span><input type="number" min="5" max="3600" id="rnTo" value="${R.timeout}"></label></div></details></div>
    <div class="form"><div class="row" style="justify-content:space-between;flex-wrap:wrap;gap:10px"><h3><span class="stage-num" style="display:inline-grid;margin-inline-end:8px">3</span>پیش‌نمایش و اجرا</h3>
      <button class="btn warn" id="rnGo" ${running ? "disabled" : ""}>پیش‌نمایش و اجرا روی ${num(sel.length)} دستگاه…</button></div></div>
    <div id="rnJob"></div>`;
  const b = $("#sshBody");
  const pull = () => Object.assign(R, { body: $("#rnBody", b).value, mode: ($("[name=rnMode]:checked", b) || {}).value || R.mode || "exec",
    use_sudo: $("#rnSudo", b) ? $("#rnSudo", b).checked : R.use_sudo, save_config: $("#rnSave", b) ? $("#rnSave", b).checked : R.save_config,
    concurrency: Number($("#rnConc", b).value) || 5, timeout: Number($("#rnTo", b).value) || 60 });
  $("#rnPick", b).onclick = () => { pull(); pickDevices(); };
  $$("[data-v]", b).forEach((x) => (x.onclick = () => {
    const ta = $("#rnBody", b), ins = `{${x.dataset.v}}`, s0 = ta.selectionStart ?? ta.value.length;
    ta.value = ta.value.slice(0, s0) + ins + ta.value.slice(ta.selectionEnd ?? s0); ta.focus(); ta.selectionStart = ta.selectionEnd = s0 + ins.length;
  }));
  $("#rnBody", b).addEventListener("keydown", (e) => {
    if (e.key === "Tab") { e.preventDefault(); const ta = e.target, s0 = ta.selectionStart; ta.value = ta.value.slice(0, s0) + "    " + ta.value.slice(ta.selectionEnd); ta.selectionStart = ta.selectionEnd = s0 + 4; }
  });
  $("#rnScript", b).onchange = (e) => {
    pull(); const s2 = SSH.scripts.find((x) => String(x.id) === e.target.value);
    if (s2) Object.assign(R, { scriptId: String(s2.id), name: s2.name, body: s2.body, mode: s2.mode, use_sudo: !!s2.use_sudo, save_config: !!s2.save_config });
    else Object.assign(R, { scriptId: "", name: "" });
    sshRun();
  };
  const saveScript = async (asNew) => {
    pull();
    let name = R.name;
    if (asNew || !R.scriptId) {
      name = await openModal({ title: "ذخیره به‌عنوان اسکریپت", body: `<label class="field"><span>نام اسکریپت</span><input type="text" id="scNm" value="${esc(R.name || "")}" autofocus></label>`,
        foot: `<button class="btn primary" id="scNmOk">ذخیره</button>`, onOpen: (m, close) => { $("#scNmOk", m).onclick = () => close($("#scNm", m).value.trim()); $("#scNm", m).onkeydown = (e) => { if (e.key === "Enter") close(e.target.value.trim()); }; } });
      if (!name) return;
    }
    const types = [...new Set(sel.map((d) => d.device_type))];
    const r = await api("ssh_save_script", { id: asNew ? null : (R.scriptId ? Number(R.scriptId) : null), name, device_type: types.length === 1 ? types[0] : "any",
      mode: R.mode, body: R.body, use_sudo: R.use_sudo, save_config: R.save_config });
    if (!r.ok) return toast(r.error, "error");
    Object.assign(R, { scriptId: String(r.id), name }); toast("ذخیره شد", "ok"); loadSsh();
  };
  $("#rnSaveAs", b).onclick = () => saveScript(true);
  const ss = $("#rnSaveSc", b); if (ss) ss.onclick = () => saveScript(false);
  const ds = $("#rnDelSc", b);
  if (ds) ds.onclick = async () => {
    if (!(await confirm2({ title: "حذف اسکریپت", danger: true, confirm: "حذف", body: `<p>اسکریپت «${esc(sc.name)}» حذف شود؟</p>` }))) return;
    const r = await api("ssh_delete_script", sc.id); if (!r.ok) return toast(r.error, "error");
    Object.assign(R, { scriptId: "", name: "" }); toast("حذف شد", "ok"); loadSsh();
  };
  $("#rnGo", b).onclick = async () => {
    pull(); if (!R.devs.size) return toast("دستگاهی انتخاب نشده است", "warn"); if (!R.body.trim()) return toast("متن اسکریپت خالی است", "warn");
    const pv = await api("ssh_preview", [...R.devs], R.body); if (!pv.ok) return toast(pv.error, "error");
    const noPw = sel.filter((d) => !d.has_password);
    const choice = await openModal({ title: "پیش‌نمایش و تأیید اجرا", wide: true,
      body: `<p>${R.name ? `«${esc(R.name)}» — ` : ""}${num(sel.length)} دستگاه${hasNet ? ` — ${R.mode === "config" ? "config" : "exec"}${R.save_config ? " + ذخیره‌ی کانفیگ" : ""}` : ""}${hasLinux && R.use_sudo ? " — sudo" : ""}</p>
        ${noPw.length ? `<p class="hint warn">${num(noPw.length)} دستگاه پسورد ذخیره‌شده ندارند و ناموفق می‌شوند.</p>` : ""}
        ${pv.items.slice(0, 20).map((it) => `<h3 style="margin:10px 0 6px">${esc(it.name)} <span class="muted ltr">${esc(it.host)}</span></h3><div class="term" data-no-i18n style="max-height:160px">${esc(it.text)}</div>`).join("")}
        ${sel.length > 20 ? `<p class="hint">فقط ۲۰ دستگاه اول نمایش داده شد.</p>` : ""}
        <label class="chk" style="margin-top:14px"><input type="checkbox" id="rnAck">دستورها و لیست دستگاه‌ها را بررسی کردم</label>`,
      foot: `<button class="btn ghost" data-c="">انصراف</button><button class="btn" data-c="dry">اجرای آزمایشی (بدون اتصال)</button><button class="btn danger" data-c="run" disabled>اجرا روی ${num(sel.length)} دستگاه</button>`,
      onOpen: (m, close) => {
        $("#rnAck", m).onchange = (e) => ($("[data-c=run]", m).disabled = !e.target.checked);
        $$("[data-c]", m).forEach((x) => (x.onclick = () => close(x.dataset.c)));
      } });
    if (!choice) return;
    const dry = choice === "dry";
    const r = await api("ssh_start", [...R.devs], { name: R.name || "متن آزاد", body: R.body, mode: R.mode, use_sudo: R.use_sudo, save_config: R.save_config },
      { concurrency: R.concurrency, timeout: R.timeout, dry_run: dry });
    if (!r.ok) return toast(r.error, "error");
    toast(dry ? "اجرای آزمایشی شروع شد" : "اجرا شروع شد", "ok"); SSH.jobSig = ""; pollSsh(true);
  };
  const stop = $("#sshStop"); if (stop) stop.onclick = async () => { const r = await api("ssh_cancel"); toast(r.ok ? "درخواست توقف ارسال شد" : r.error, r.ok ? "warn" : "error"); };
  renderJob();
}
function pickDevices() {
  const R = SSH.run, tmp = new Set(R.devs);
  const types = [...new Set(SSH.devices.map((d) => d.device_type))];
  const body = () => `<div class="row" style="flex-wrap:wrap;gap:6px;margin-bottom:10px"><button class="btn sm" data-g="__all">همه</button><button class="btn sm" data-g="__none">هیچ</button>
      ${SSH.groups.map((g) => `<button class="btn sm" data-g="${esc(g)}">${esc(g)}</button>`).join("")}${types.map((t) => `<button class="btn sm" data-tp="${t}">${esc(typeName(t))}</button>`).join("")}</div>
    <div class="dev-picker">${SSH.devices.length ? SSH.devices.map((d) => `<label class="list-item chk" style="display:flex;gap:8px"><input type="checkbox" class="pkDev" value="${d.id}" ${tmp.has(d.id) ? "checked" : ""}>
      <span class="tech">${esc(d.name)}<small class="ltr" style="text-align:start">${esc(d.host)} · ${esc(typeName(d.device_type))}${d.grp ? " · " + esc(d.grp) : ""}</small></span></label>`).join("") : `<div class="empty">دستگاهی نیست؛ از تب «دستگاه‌ها» اضافه کنید.</div>`}</div>`;
  openModal({ title: "انتخاب دستگاه‌ها", wide: true, body: body(), foot: `<span class="muted" id="pkN" style="margin-inline-end:auto"></span><button class="btn primary" id="pkOk">تأیید</button>`,
    onOpen: (m, close) => {
      const wire = () => {
        $("#pkN", m).textContent = I18N.t(`${num(tmp.size)} مورد انتخاب شده`);
        $$(".pkDev", m).forEach((c) => (c.onchange = () => { const id = Number(c.value); c.checked ? tmp.add(id) : tmp.delete(id); $("#pkN", m).textContent = I18N.t(`${num(tmp.size)} مورد انتخاب شده`); }));
        $$("[data-g],[data-tp]", m).forEach((x) => (x.onclick = () => {
          const g = x.dataset.g, tp = x.dataset.tp;
          if (g === "__all") SSH.devices.forEach((d) => tmp.add(d.id)); else if (g === "__none") tmp.clear();
          else SSH.devices.filter((d) => (tp ? d.device_type === tp : d.grp === g)).forEach((d) => tmp.add(d.id));
          $(".m-body", m).innerHTML = body(); wire();
        }));
      };
      wire();
      $("#pkOk", m).onclick = () => { R.devs = new Set(tmp); close(); sshRun(); };
    } });
}
function renderJob() {
  const box = $("#rnJob") || $("#bkJob"); if (!box) return;
  const j = SSH.job;
  // تب پشتیبان فقط اجرای پشتیبان‌گیری را نشان می‌دهد؛ تب اجرا بقیه را
  if (!j || (box.id === "bkJob") !== (j.kind === "backup")) { box.innerHTML = ""; return; }
  const done = j.results.filter((r) => !["pending", "running"].includes(r.status)).length;
  box.innerHTML = `<div class="panel"><div class="panel-head"><h3>${esc(j.script_name)} ${j.dry ? `<span class="tag warn">آزمایشی</span>` : ""} ${j.kind === "test" ? `<span class="tag info">تست اتصال</span>` : ""}</h3>
      <span class="muted">${num(done)} از ${num(j.total)} — ${num(j.ok)} موفق، ${num(j.failed)} ناموفق${j.status === "running" ? "" : j.status === "cancelled" ? " — متوقف شد" : " — تمام شد"}</span>
      ${j.status !== "running" && j.kind !== "backup" ? `<button class="btn sm" id="jbExport">خروجی متنی همه</button>` : ""}</div>
    <div class="progress"><i style="width:${Math.round((100 * done) / Math.max(1, j.total))}%"></i></div>
    <div class="table-wrap inner"><table class="grid"><thead><tr>${["دستگاه", "آدرس", "وضعیت", "نتیجه", ""].map((t) => `<th class="nosort">${t}</th>`).join("")}</tr></thead><tbody>
    ${j.results.map((r) => `<tr><td class="tech">${esc(r.name)}</td><td class="ltr">${esc(r.host)}</td><td>${stTag(r.status)}</td><td class="wrap tech">${esc(r.message || "")}</td>
      <td>${r.out_file ? `<button class="btn sm" data-out="${esc(j.id)}|${r.device_id}|${esc(r.name)}">خروجی</button>` : ""}</td></tr>`).join("")}</tbody></table></div></div>`;
  const ex = $("#jbExport", box); if (ex) ex.onclick = async () => { const r = await api("ssh_export_output", j.id); if (!r.ok) return toast(r.error, "error"); if (!r.cancelled) toast("ذخیره شد: " + r.path, "ok"); };
}
/** نمایش متن بزرگ رمزشده (خروجی SSH، نسخه‌ی کانفیگ) با بارگذاری تکه‌تکه. */
function openTextModal(title, kind, a, b) {
  let text = "";
  openModal({ title, wide: true,
    // textarea: کنترل بومی سیستم برای متن خیلی بزرگ؛ div بزرگ روی WebView2 گاهی رسم نمی‌شد و پنجره غیب می‌شد
    body: `<p class="hint" id="txProg">در حال بارگذاری…</p><textarea class="term tx-view" data-no-i18n id="txBody" readonly wrap="off" spellcheck="false"></textarea>`,
    foot: `<button class="btn" id="txCopy" disabled>کپی</button><button class="btn primary" data-x="1">بستن</button>`,
    onOpen: async (m, close) => {
      let alive = true;
      $("[data-x]", m).onclick = () => { alive = false; close(); };
      $("#txCopy", m).onclick = () => copyText(text, I18N.t("متن"));
      const body = $("#txBody", m), prog = $("#txProg", m);
      let off = 0;
      for (;;) {
        const r = await api("text_chunk", kind, a, b ?? null, off);
        if (!alive || !body.isConnected) return;
        if (!r.ok) { prog.className = "hint warn"; prog.textContent = "بارگذاری ناموفق بود: " + r.error; return; }
        text += r.chunk; off = r.next;
        const kb = (n) => (n < 1024 ? `${num(n)} نویسه` : `${num(Math.round(n / 1024))} کیلوبایت`);
        prog.textContent = r.done ? kb(r.total) : `در حال بارگذاری… ${kb(off)} از ${kb(r.total)}`;
        if (r.done) break;
      }
      body.value = text; body.scrollTop = 0;
      $("#txCopy", m).disabled = false;
    } });
}
document.addEventListener("click", (e) => {
  const b = e.target.closest("[data-out]"); if (!b) return;
  const [jid, did, name] = b.dataset.out.split("|");
  openTextModal(`خروجی \u2066${name}\u2069`, "ssh", jid, Number(did));
});
async function pollSsh(force) {
  const r = await api("ssh_job"); if (!r.ok) return;
  const j = r.job, sig = JSON.stringify(j && [j.status, j.ok, j.failed, j.results.map((x) => x.status + x.message)]);
  $("#navSshDot").hidden = !(j && j.status === "running");
  if (!force && sig === SSH.jobSig) return;
  const wasRunning = SSH.job && SSH.job.status === "running";
  SSH.jobSig = sig; SSH.job = j;
  if (S.page === "ssh" && (SSH.tab === "run" || SSH.tab === "backups")) {
    if (SSH.tab === "run" && wasRunning !== (j && j.status === "running")) sshRun(); else renderJob();
  }
  if (wasRunning && j && j.status !== "running") {
    toast(`SSH تمام شد: ${num(j.ok)} موفق، ${num(j.failed)} ناموفق`, j.failed ? "warn" : "ok");
    await loadSsh();
  }
}
// هر ثانیه فقط وقتی کار SSH در جریان است یا تبی که نتیجه را نشان می‌دهد باز است؛ در تب ترمینال/انتقال فایل هر ۱۰ ثانیه
// (برای دیدن شروع کار زمان‌بندی‌شده)؛ پنجره‌ی پنهان هیچ (هر فراخوانی در دسکتاپ از پل pywebview می‌گذرد)
let sshTick = 0;
setInterval(() => {
  if (document.hidden) return;
  const busy = SSH.job && SSH.job.status === "running";
  const shows = S.page === "ssh" && ["devices", "run", "backups"].includes(SSH.tab);
  if (busy || shows || (S.page === "ssh" && ++sshTick % 10 === 0)) pollSsh();
}, 1000);

/* ---------- config backups ---------- */
async function sshBackups() {
  $("#sshActions").innerHTML = `<button class="btn" id="bkLatest">دانلود آخرین نسخه‌ها…</button><button class="btn primary" id="bkNow" data-need-run="ssh">پشتیبان‌گیری الان</button>`;
  const r = await api("backup_overview"); if (SSH.tab !== "backups" || S.page !== "ssh") return; if (!r.ok) return toast(r.error, "error");
  const devs = r.devices, auto = (S.settings && S.settings.automation && S.settings.automation.backup) || {};
  if (SSH.bk.dev && !devs.some((d) => d.id === SSH.bk.dev)) SSH.bk.dev = null;
  if (!SSH.bk.dev) { const f = devs.find((d) => d.backup_on && d.versions) || devs.find((d) => d.backup_on); SSH.bk.dev = f ? f.id : null; }
  const cur = devs.find((d) => d.id === SSH.bk.dev);
  const vr = cur ? await api("backup_versions", cur.id) : { ok: true, versions: [] };
  if (SSH.tab !== "backups" || S.page !== "ssh") return;
  const vs = (vr.ok && vr.versions) || [];
  SSH.bk.pick = SSH.bk.pick.filter((id) => vs.some((v) => v.id === id));
  $("#sshBody").innerHTML = `<p class="hint">زمان‌بندی: ${auto.enabled && S.settings.automation.master ? `هر روز ساعت <b class="ltr">${esc(auto.time || "02:00")}</b>` : "خاموش"} — تنظیم در «کارهای خودکار ← پشتیبان کانفیگ». نسخه‌ها رمزشده ذخیره می‌شوند و نسخه‌ی تکراری ذخیره نمی‌شود.</p>
    <div id="bkJob"></div>
    <div class="split"><div class="list-pane">${devs.length ? devs.map((d) => `<div class="list-item ${d.id === SSH.bk.dev ? "on" : ""}" data-bd="${d.id}" style="display:flex;gap:8px;align-items:center">
        ${isAdmin() ? `<input type="checkbox" class="bkOn" value="${d.id}" ${d.backup_on ? "checked" : ""} title="پشتیبان‌گیری کانفیگ">` : ""}
        <span style="flex:1;min-width:0"><span class="tech">${esc(d.name)}</span><small><span>${esc(typeName(d.device_type))}</span> · <span>${num(d.versions)} نسخه</span>${d.backup_status ? ` · <span>${esc(d.backup_message || "")}</span>` : ""}</small></span></div>`).join("")
      : `<div class="empty">هنوز دستگاهی اضافه نشده است.</div>`}</div>
      <div>${cur ? `<div class="panel"><div class="panel-head"><h3>${esc(cur.name)} <span class="muted ltr">${esc(cur.host)}</span></h3>
          <div class="row"><button class="btn sm" id="bkCmp" ${SSH.bk.pick.length === 2 ? "" : "disabled"}>مقایسه‌ی دو نسخه‌ی انتخاب‌شده</button>
            <button class="btn sm danger-ghost adm-only" id="bkDelSel" ${SSH.bk.pick.length ? "" : "disabled"}>حذف انتخاب‌شده‌ها (${num(SSH.bk.pick.length)})</button></div></div>
        ${cur.backup_status ? `<p class="hint">آخرین پشتیبان‌گیری: ${stTag(cur.backup_status)} ${fmtDate(cur.backup_at)} — <span class="tech">${esc(cur.backup_message || "")}</span></p>` : ""}
        <div class="table-wrap inner"><table class="grid"><thead><tr><th class="chk nosort"></th>${["زمان", "خطوط", "تغییر", "حجم", ""].map((t) => `<th class="nosort">${t}</th>`).join("")}</tr></thead><tbody>
        ${vs.length ? vs.map((v, i) => `<tr><td class="chk"><input type="checkbox" class="bkPick" value="${v.id}" ${SSH.bk.pick.includes(v.id) ? "checked" : ""}></td>
          <td class="ltr">${fmtDate(v.ts)}</td><td class="num">${num(v.lines)}</td>
          <td>${v.first ? `<span class="tag mute">اولین نسخه</span>` : `<span class="tag ok">+${num(v.added)}</span> <span class="tag err">−${num(v.removed)}</span>`}</td>
          <td class="num ltr">${(v.size / 1024).toFixed(1)} KB</td>
          <td><div class="row" style="gap:4px"><button class="btn sm" data-bv="${v.id}">نمایش</button>${vs[i + 1] ? `<button class="btn sm" data-bdf="${vs[i + 1].id}|${v.id}">تفاوت با قبلی</button>` : ""}<button class="btn sm ghost" data-bx="${v.id}">ذخیره‌ی فایل</button><button class="btn sm danger-ghost adm-only" data-bdel="${v.id}">حذف</button></div></td></tr>`).join("")
          : `<tr><td colspan="6"><div class="empty">${cur.backup_on ? "هنوز نسخه‌ای ذخیره نشده است. «پشتیبان‌گیری الان» را بزنید." : "پشتیبان‌گیری برای این دستگاه خاموش است."}</div></td></tr>`}</tbody></table></div></div>`
      : `<div class="panel"><div class="empty">یک دستگاه انتخاب کنید.</div></div>`}
      ${isAdmin() ? `<details class="form" style="margin-top:12px"><summary style="cursor:pointer"><b>تنظیمات پشتیبان</b></summary>${backupSettingsForm(r)}</details>` : ""}</div></div>`;
  renderJob();
  $("#bkLatest").onclick = () => backupLatestDialog(devs);
  $("#bkNow").onclick = async () => { const x = await api("backup_now"); if (!x.ok) return toast(x.error, "error"); toast("پشتیبان‌گیری شروع شد", "ok"); SSH.jobSig = ""; pollSsh(true); };
  $$("[data-bd]").forEach((x) => (x.onclick = (e) => { if (e.target.classList.contains("bkOn")) return; SSH.bk.dev = Number(x.dataset.bd); SSH.bk.pick = []; sshBackups(); }));
  $$(".bkOn").forEach((c) => (c.onchange = async () => { const x = await api("ssh_set_backup", [Number(c.value)], c.checked); if (!x.ok) { c.checked = !c.checked; return toast(x.error, "error"); } await loadSsh(); }));
  $$(".bkPick").forEach((c) => (c.onchange = () => {
    const id = Number(c.value);
    SSH.bk.pick = c.checked ? [...SSH.bk.pick.filter((x) => x !== id), id] : SSH.bk.pick.filter((x) => x !== id);
    $("#bkCmp").disabled = SSH.bk.pick.length !== 2;
    const bd2 = $("#bkDelSel"); bd2.disabled = !SSH.bk.pick.length; bd2.textContent = I18N.t(`حذف انتخاب‌شده‌ها (${num(SSH.bk.pick.length)})`);
  }));
  const cmp = $("#bkCmp"); if (cmp) cmp.onclick = () => { const [a, b2] = [...SSH.bk.pick].sort((x, y) => x - y); showDiff(a, b2); };
  $$("[data-bv]").forEach((x) => (x.onclick = () => {
    const v = vs.find((y) => y.id === Number(x.dataset.bv));
    openTextModal(`${cur.name} — ${fmtDate(v && v.ts)}`, "backup", Number(x.dataset.bv));
  }));
  $$("[data-bdel]").forEach((x) => (x.onclick = () => deleteVersions([Number(x.dataset.bdel)])));
  const bd = $("#bkDelSel"); if (bd) bd.onclick = () => deleteVersions([...SSH.bk.pick]);
  async function deleteVersions(ids) {
    if (!ids.length) return;
    const ok = await confirm2({ title: "حذف نسخه‌ی پشتیبان", danger: true, confirm: `حذف ${num(ids.length)} نسخه`,
      body: `<p>${num(ids.length)} نسخه از پشتیبان‌های «${esc(cur.name)}» برای همیشه حذف می‌شود. فایل رمزشده پیش از حذف بازنویسی می‌شود.</p>` });
    if (!ok) return;
    const r = await api("backup_delete", ids); if (!r.ok) return toast(r.error, "error");
    SSH.bk.pick = SSH.bk.pick.filter((i) => !ids.includes(i)); toast(`${num(r.deleted)} نسخه حذف شد`, "ok"); sshBackups();
  }
  $$("[data-bdf]").forEach((x) => (x.onclick = () => { const [a, b2] = x.dataset.bdf.split("|").map(Number); showDiff(a, b2); }));
  $$("[data-bx]").forEach((x) => (x.onclick = async () => { const v = await api("backup_export", Number(x.dataset.bx)); if (!v.ok) return toast(v.error, "error"); if (!v.cancelled) toast("ذخیره شد: " + v.path, "ok"); }));
  wireBackupSettings();
}
/** 1.27.10: آخرین نسخه‌ی پشتیبان چند دستگاه با هم، در یک فایل zip */
function backupLatestDialog(devs) {
  const list = devs.filter((d) => d.versions > 0);
  if (!list.length) return toast("هیچ دستگاهی هنوز نسخه‌ی پشتیبان ندارد.", "warn");
  const sel = new Set(list.map((d) => d.id));
  openModal({ title: "دانلود آخرین نسخه‌ی پشتیبان", wide: true,
    body: `<p class="hint">آخرین نسخه‌ی هر دستگاه تیک‌خورده، هر کدام یک فایل متنی، در یک فایل zip ذخیره می‌شود. فقط دستگاه‌هایی که نسخه دارند نمایش داده می‌شوند.</p>
      <div class="row" style="gap:8px;margin-bottom:8px"><input type="search" id="blQ" placeholder="جستجوی نام یا آدرس…" style="flex:1"><span class="muted" id="blInfo"></span></div>
      <div class="table-wrap inner" style="max-height:420px"><table class="grid"><thead><tr><th class="chk nosort"><input type="checkbox" id="blAll" checked title="همه‌ی ردیف‌های فیلترشده"></th><th>نام</th><th>آدرس</th><th>نوع</th><th>نسخه‌ها</th><th>آخرین پشتیبان</th></tr></thead>
      <tbody id="blBody">${list.map((d) => `<tr data-bl="${d.id}"><td class="chk"><input type="checkbox" class="blPick" value="${d.id}" checked></td><td class="tech">${esc(d.name)}</td><td class="ltr">${esc(d.host)}</td>
        <td>${esc(typeName(d.device_type))}</td><td class="num">${num(d.versions)}</td><td class="ltr" >${fmtDate(d.last_version)}</td></tr>`).join("")}</tbody></table></div>`,
    foot: `<button class="btn ghost" data-r="0">انصراف</button><button class="btn primary" id="blGo">دانلود zip</button>`,
    onOpen: (m, close) => {
      const rows = () => $$("#blBody tr", m), shown = () => rows().filter((r) => !r.hidden);
      const upd = () => {
        const n = sel.size; $("#blGo", m).disabled = !n;
        $("#blInfo", m).textContent = I18N.t(`${num(n)} از ${num(list.length)} دستگاه انتخاب شده`);
        const sh = shown(); $("#blAll", m).checked = sh.length > 0 && sh.every((r) => sel.has(Number(r.dataset.bl)));
      };
      $("#blQ", m).oninput = (e) => { const q = e.target.value.trim().toLowerCase();
        rows().forEach((r) => { const d = list.find((x) => x.id === Number(r.dataset.bl)); r.hidden = !!q && !`${d.name} ${d.host}`.toLowerCase().includes(q); }); upd(); };
      $("#blAll", m).onchange = (e) => { shown().forEach((r) => { const id = Number(r.dataset.bl); e.target.checked ? sel.add(id) : sel.delete(id); $(".blPick", r).checked = e.target.checked; }); upd(); };
      $$(".blPick", m).forEach((c) => (c.onchange = () => { const id = Number(c.value); c.checked ? sel.add(id) : sel.delete(id); upd(); }));
      $("[data-r='0']", m).onclick = () => close(null);
      $("#blGo", m).onclick = (e) => withSpin(e.currentTarget, async () => {
        const r = await api("backup_export_latest", [...sel]); if (!r.ok) return toast(r.error, "error");
        if (r.cancelled) return;
        close(true);
        toast(`آخرین نسخه‌ی ${num(r.count)} دستگاه ذخیره شد: ${r.path || ""}`, "ok");
        if (r.skipped && r.skipped.length) toast(`${num(r.skipped.length)} دستگاه نسخه نداشت`, "warn");
      });
      upd();
    } });
}
async function showDiff(oldId, newId) {
  const r = await api("backup_diff", oldId, newId); if (!r.ok) return toast(r.error, "error");
  const d = r.diff;
  const rows = d.rows.length ? d.rows.map(([t, a, b2, txt]) => t === "gap" ? `<div class="df gap">⋯</div>`
    : `<div class="df ${t}"><span class="ln">${a ?? ""}</span><span class="ln">${b2 ?? ""}</span><span class="sg">${t === "add" ? "+" : t === "del" ? "−" : " "}</span><span class="tx">${esc(txt)}</span></div>`).join("")
    : `<div class="empty">تفاوتی نیست (پس از نادیده گرفتن خطوط متغیر).</div>`;
  openModal({ title: `${fmtDate(d.old.ts)}${I18N.lang === "en" ? " → " : ARW}${fmtDate(d.new.ts)}`, wide: true,
    body: `<p><span class="tag ok">+${num(d.added)}</span> <span class="tag err">−${num(d.removed)}</span> <span class="muted">خطوط متغیر (مثل زمان آخرین تغییر و ENC) در مقایسه نادیده گرفته می‌شوند.</span></p>
      <div class="diff" data-no-i18n>${rows}</div>` });
}
function backupSettingsForm(r) {
  const b = (S.settings && S.settings.backup) || {};
  const cmds = b.commands || {};
  return `<div class="form-grid" style="margin-top:12px">
      <label class="field"><span>تعداد نسخه‌های نگه‌داشته‌شده برای هر دستگاه</span><input type="number" min="1" max="500" id="bsKeep" value="${esc(b.keep ?? 10)}"></label>
      <label class="field"><span>Timeout دریافت کانفیگ (ثانیه)</span><input type="number" min="30" max="3600" id="bsTo" value="${esc(b.timeout ?? 180)}"></label></div>
    <h3 style="margin:14px 0 8px">دستور پشتیبان هر نوع دستگاه</h3><div class="form-grid">
      ${r.types.map(([t, nm]) => `<label class="field"><span>${esc(nm)}</span><input type="text" class="ltr bsCmd" data-t="${t}" value="${esc(cmds[t] || "")}" placeholder="${t === "linux" ? "مثلاً cat /etc/nginx/nginx.conf" : ""}"></label>`).join("")}</div>
    <p class="hint">دستور خالی یعنی برای آن نوع پشتیبان گرفته نمی‌شود.</p>
    <div class="form-grid" style="margin-top:10px">
      <label class="field"><span>خطوط نادیده در مقایسه (regex، هر خط یک الگو)</span><textarea class="ltr code-edit" id="bsIgn" style="min-height:140px">${esc((b.ignore_lines || []).join("\n"))}</textarea></label>
      <label class="field"><span>مقدارهای ماسک‌شده در مقایسه (regex)</span><textarea class="ltr code-edit" id="bsMask" style="min-height:140px">${esc((b.mask || []).join("\n"))}</textarea>
        <small class="hint">مثل ENC در FortiGate که هر بار با مقدار تازه رمز می‌شود. متن ذخیره‌شده دست نمی‌خورد.</small></label></div>
    <div class="form-foot"><button class="btn primary" id="bsSave">ذخیره‌ی تنظیمات پشتیبان</button></div>`;
}
function wireBackupSettings() {
  const sv = $("#bsSave"); if (!sv) return;
  sv.onclick = (e) => withSpin(e.currentTarget, async () => {
    const commands = {}; $$(".bsCmd").forEach((i) => (commands[i.dataset.t] = i.value.trim()));
    const lines = (id) => $(id).value.split(/\r?\n/).map((x) => x.trim()).filter(Boolean);
    const r = await api("save_settings", { backup: { keep: Number($("#bsKeep").value) || 10, timeout: Number($("#bsTo").value) || 180,
      commands, ignore_lines: lines("#bsIgn"), mask: lines("#bsMask") } });
    if (!r.ok) return toast(r.error, "error");
    S.settings = r.settings; S.draft = clone(r.settings); toast("ذخیره شد", "ok");
  });
}

/* ---------- jobs ---------- */
async function sshJobs() {
  $("#sshActions").innerHTML = "";
  const r = await api("ssh_jobs"); if (SSH.tab !== "jobs" || S.page !== "ssh") return; if (!r.ok) return toast(r.error, "error");
  const kind = (j) => j.kind === "test" ? "تست اتصال" : j.kind === "backup" ? "پشتیبان کانفیگ" : j.dry ? "آزمایشی" : "اجرا";
  $("#sshBody").innerHTML = `<div class="table-wrap"><table class="grid"><thead><tr>${["زمان", "اسکریپت", "نوع", "دستگاه‌ها", "موفق", "ناموفق", "وضعیت", ""].map((t) => `<th class="nosort">${t}</th>`).join("")}</tr></thead><tbody>
    ${r.jobs.length ? r.jobs.map((j) => `<tr><td class="ltr">${fmtDate(j.started)}</td><td>${esc(j.script_name)}</td><td>${kind(j)}</td>
      <td class="num">${num(j.total)}</td><td class="num">${num(j.ok)}</td><td class="num">${num(j.failed)}</td><td>${{ done: "تمام شد", cancelled: "متوقف شد", running: "در حال اجرا" }[j.status] || esc(j.status)}</td>
      <td><button class="btn sm" data-jb="${esc(j.id)}">جزئیات</button></td></tr>`).join("") : `<tr><td colspan="8"><div class="empty">هنوز اجرایی نبوده است.</div></td></tr>`}</tbody></table></div>`;
  $$("[data-jb]").forEach((b) => (b.onclick = async () => {
    const jr = await api("ssh_job_results", b.dataset.jb); if (!jr.ok) return toast(jr.error, "error");
    openModal({ title: `اجرای ${b.dataset.jb}`, wide: true, body: `<div class="table-wrap inner"><table class="grid"><thead><tr>${["دستگاه", "آدرس", "وضعیت", "نتیجه", ""].map((t) => `<th class="nosort">${t}</th>`).join("")}</tr></thead><tbody>
      ${jr.results.map((x) => `<tr><td class="tech">${esc(x.name)}</td><td class="ltr">${esc(x.host)}</td><td>${stTag(x.status)}</td><td class="wrap tech">${esc(x.message || "")}</td>
        <td>${x.out_file ? `<button class="btn sm" data-out="${esc(b.dataset.jb)}|${x.device_id}|${esc(x.name)}">خروجی</button>` : ""}</td></tr>`).join("")}</tbody></table></div>`,
      foot: `<button class="btn" id="jbExp2">خروجی متنی همه</button>`,
      onOpen: (m) => ($("#jbExp2", m).onclick = async () => { const x = await api("ssh_export_output", b.dataset.jb); if (!x.ok) return toast(x.error, "error"); if (!x.cancelled) toast("ذخیره شد: " + x.path, "ok"); }) });
  }));
}


/* ---------- به‌روزرسانی آفلاین FortiGate (TFTP) ---------- */
const FGU = { info: null, sel: new Set(), pkgs: null, job: null, sig: "", check: null };
const FGU_ST = { ok: ["ok", "موفق"], failed: ["err", "ناموفق"], unknown: ["warn", "نامشخص"], running: ["info", "در حال اجرا"],
  pending: ["mute", "در صف"], cancelled: ["mute", "متوقف"] };
const fguTag = (s2) => { const t = FGU_ST[s2] || ["mute", s2]; return `<span class="tag ${t[0]}">${t[1]}</span>`; };
async function sshFgu() {
  const r = await api("fgu_info"); if (SSH.tab !== "fgu" || S.page !== "ssh") return; if (!r.ok) return toast(r.error, "error");
  FGU.info = r;
  const o = r.opts || {};
  if (!FGU.pkgs) FGU.pkgs = new Set(o.packages && o.packages.length ? o.packages : r.packages.map((p) => p.file));
  FGU.sel = new Set([...FGU.sel].filter((id) => r.devices.some((d) => d.id === id)));
  if (!FGU.sel.size && r.devices.length === 1) FGU.sel.add(r.devices[0].id);
  const running = FGU.job && FGU.job.status === "running";
  $("#sshActions").innerHTML = running ? `<button class="btn danger-ghost" id="fguStop">توقف</button>` : "";
  const src = o.source || "local";
  $("#sshBody").innerHTML = `
    <div class="form"><h3>۱. دستگاه‌ها</h3>
      ${r.devices.length ? `<div class="dev-picker" style="max-height:220px">${r.devices.map((d) => `<label class="list-item chk" style="display:flex;gap:8px">
        <input type="checkbox" class="fguDev" value="${d.id}" ${FGU.sel.has(d.id) ? "checked" : ""}>
        <span class="tech">${esc(d.name)}<small class="ltr" style="text-align:start">${esc(d.host)}${d.local_ip ? ` · <span>IP این کامپیوتر به سمت دستگاه:</span> ${esc(d.local_ip)}` : ""}${d.has_password ? "" : " · بدون پسورد"}</small></span></label>`).join("")}</div>`
        : `<p class="hint warn">هیچ دستگاهی با نوع «FortiGate (CLI)» ثبت نشده است. از تب «دستگاه‌ها» اضافه کنید.</p>`}</div>
    <div class="form"><div class="row" style="justify-content:space-between"><h3>۲. پکیج‌ها</h3>
        <div class="row" style="gap:4px"><button class="btn sm ghost" id="fguAll">همه</button><button class="btn sm ghost" id="fguNone">هیچ</button></div></div>
      <p class="hint">به همین ترتیب، یکی‌یکی اجرا می‌شوند؛ تا نتیجه‌ی هر دستور مشخص نشده، دستور بعدی زده نمی‌شود. اگر یکی ناموفق شود، بقیه انجام می‌شوند.</p>
      <div class="form-grid" style="margin-top:8px">${r.packages.map((p, i) => `<label class="chk"><input type="checkbox" class="fguPkg" value="${esc(p.file)}" ${FGU.pkgs.has(p.file) ? "checked" : ""}>
        <span><span class="muted">${i + 1}.</span> <span class="tech">${esc(p.file)}</span> <small class="muted ltr">(${esc(p.kind)})</small></span></label>`).join("")}</div></div>
    <div class="form"><h3>۳. منبع فایل‌ها (TFTP)</h3>
      <div class="row" style="gap:20px;flex-wrap:wrap;margin-bottom:10px">
        <label class="chk"><input type="radio" name="fguSrc" value="local" ${src === "local" ? "checked" : ""}>همین کامپیوتر (سرور TFTP داخلی)</label>
        <label class="chk"><input type="radio" name="fguSrc" value="remote" ${src === "remote" ? "checked" : ""}>سرور TFTP دیگر</label></div>
      <div id="fguSrcBody"></div></div>
    <div class="form"><h3>۴. VDOM</h3><div class="row" style="gap:20px;flex-wrap:wrap">
      <label class="switch"><input type="checkbox" id="fguMulti" ${o.multi_vdom !== false ? "checked" : ""}><span class="track"><span class="thumb"></span></span>دستگاه چند-VDOM است</label>
      <label class="field" style="max-width:240px"><span>نام VDOM</span><input type="text" class="ltr" id="fguVdom" value="${esc(o.vdom || "root")}"></label></div>
      <p class="hint">در حالت چند-VDOM: <span class="ltr">config vdom → edit &lt;vdom&gt;</span> قبل از دستورها، و <span class="ltr">config global → diagnose autoupdate versions</span> برای نسخه‌ها (قبل و بعد).</p>
      <details style="margin-top:8px"><summary class="muted" style="cursor:pointer">پیشرفته</summary><div class="form-grid" style="margin-top:10px">
        <label class="field"><span>مکث بین دستورها (ثانیه)</span><input type="number" min="0" max="120" id="fguDelay" value="${esc(o.delay ?? 5)}"></label>
        <label class="field"><span>حداکثر زمان هر پکیج (ثانیه)</span><input type="number" min="30" max="3600" id="fguTo" value="${esc(o.timeout ?? 600)}"></label>
        <label class="field"><span>پورت TFTP داخلی</span><input type="number" min="1" max="65535" id="fguPort" value="${esc(o.tftp_port ?? 69)}"></label></div></details>
      <div class="form-foot"><button class="btn warn" id="fguGo" ${running || !r.devices.length ? "disabled" : ""}>شروع به‌روزرسانی…</button></div></div>
    <div id="fguJob"></div>`;
  const drawSrc = () => {
    const v = ($("[name=fguSrc]:checked") || {}).value || "local";
    $("#fguSrcBody").innerHTML = v === "local" ? `
      ${WEB ? `<p class="hint">حالت سرور: فایل‌های بسته را روی خود سیستم سرور در پوشه‌ی <span class="tech ltr">fgupdate</span> داخل پوشه‌ی داده‌ی برنامه کپی کنید (به‌خاطر امنیت، مسیر دیگری پذیرفته نمی‌شود).</p>
      <div class="row"><input type="hidden" id="fguFolder" value=""><button class="btn sm" id="fguChk">بررسی فایل‌ها</button></div>`
      : `<div class="row"><input type="text" class="ltr" id="fguFolder" placeholder="C:\\FortiGate\\packages" value="${esc(o.folder || "")}">
        <button class="btn sm" id="fguPick">انتخاب پوشه…</button><button class="btn sm" id="fguChk">بررسی فایل‌ها</button></div>`}
      <div id="fguChkOut" style="margin-top:8px"></div>
      <p class="hint">برنامه فقط در مدت اجرا روی UDP پورت ${esc(o.tftp_port ?? 69)} سرور TFTP روشن می‌کند و فقط به دستگاه‌های انتخاب‌شده فایل می‌دهد. <b>فایروال ویندوز بار اول اجازه می‌خواهد؛ «Allow» را بزنید.</b> آدرس <span class="ltr">dest_ip</span> برای هر دستگاه خودکار تشخیص داده می‌شود.</p>`
      : `<label class="field" style="max-width:320px"><span>آدرس سرور TFTP</span><input type="text" class="ltr" id="fguIp" value="${esc(o.tftp_ip || "")}" placeholder="10.0.0.20"></label>
         <p class="hint">فایل‌ها باید با همین نام‌ها روی آن سرور باشند؛ برنامه نمی‌تواند وجودشان را از قبل بررسی کند.</p>`;
    const pk = $("#fguPick"); if (pk) pk.onclick = async () => { const x = await api("pick_folder"); if (!x.ok) return toast(x.error, "warn"); if (x.path) { $("#fguFolder").value = x.path; checkFolder(); } };
    const ck = $("#fguChk"); if (ck) ck.onclick = () => checkFolder();
  };
  const checkFolder = async () => {
    const f = ($("#fguFolder") || {}).value || ""; const out = $("#fguChkOut"); if (!out) return;
    const x = await api("fgu_check_folder", f, [...FGU.pkgs]); if (!x.ok) return toast(x.error, "error");
    const c = x.check;
    out.innerHTML = !c.exists ? `<span class="tag err">پوشه پیدا نشد</span>`
      : c.missing.length ? `<span class="tag err">نیست: <span class="ltr">${c.missing.map(esc).join(", ")}</span></span>`
        : `<span class="tag ok">همه‌ی ${num(Object.keys(c.files).length)} فایل انتخاب‌شده موجود است</span>`;
  };
  $$("[name=fguSrc]").forEach((x) => (x.onchange = drawSrc)); drawSrc();
  $$(".fguDev").forEach((c) => (c.onchange = () => { const id = Number(c.value); c.checked ? FGU.sel.add(id) : FGU.sel.delete(id); }));
  $$(".fguPkg").forEach((c) => (c.onchange = () => { c.checked ? FGU.pkgs.add(c.value) : FGU.pkgs.delete(c.value); }));
  $("#fguAll").onclick = () => { r.packages.forEach((p) => FGU.pkgs.add(p.file)); $$(".fguPkg").forEach((c) => (c.checked = true)); };
  $("#fguNone").onclick = () => { FGU.pkgs.clear(); $$(".fguPkg").forEach((c) => (c.checked = false)); };
  const stop = $("#fguStop"); if (stop) stop.onclick = async () => { const x = await api("fgu_cancel"); toast(x.ok ? "پکیج در حال اجرا تمام می‌شود و بعد متوقف می‌شود" : x.error, x.ok ? "warn" : "error"); };
  $("#fguGo").onclick = async () => {
    const opts = { source: ($("[name=fguSrc]:checked") || {}).value || "local", folder: ($("#fguFolder") || {}).value || o.folder || "",
      tftp_ip: ($("#fguIp") || {}).value || o.tftp_ip || "", multi_vdom: $("#fguMulti").checked, vdom: $("#fguVdom").value.trim() || "root",
      delay: Number($("#fguDelay").value) || 0, timeout: Number($("#fguTo").value) || 600, tftp_port: Number($("#fguPort").value) || 69,
      packages: r.packages.map((p) => p.file).filter((f) => FGU.pkgs.has(f)) };
    if (!FGU.sel.size) return toast("دستگاهی انتخاب نشده است", "warn");
    if (!opts.packages.length) return toast("هیچ پکیجی انتخاب نشده است", "warn");
    const names = r.devices.filter((d) => FGU.sel.has(d.id)).map((d) => d.name);
    const ok = await confirm2({ title: "شروع به‌روزرسانی FortiGate", danger: true, confirm: "شروع",
      body: `<p>${num(opts.packages.length)} پکیج روی ${num(names.length)} دستگاه (<span class="tech">${names.map(esc).join("، ")}</span>) بازنویسی می‌شود.</p>
        <p class="hint">منبع: ${opts.source === "local" ? `همین کامپیوتر — <span class="ltr">${esc(opts.folder)}</span>` : `سرور TFTP <span class="ltr">${esc(opts.tftp_ip)}</span>`}
        ${opts.multi_vdom ? ` — VDOM: <span class="ltr">${esc(opts.vdom)}</span>` : ""}</p>
        <div class="codebox" data-no-i18n>${opts.packages.map((f) => esc(`execute restore ${(r.packages.find((p) => p.file === f) || {}).kind} tftp ${f} <dest_ip>`)).join("\n")}</div>`,
      ack: "می‌دانم پکیج‌های فعلی دستگاه بازنویسی می‌شوند" });
    if (!ok) return;
    const x = await api("fgu_start", [...FGU.sel], opts); if (!x.ok) return toast(x.error, "error");
    toast("به‌روزرسانی شروع شد", "ok"); FGU.sig = ""; pollFgu(true);
  };
  renderFguJob();
}
function renderFguJob() {
  const box = $("#fguJob"); if (!box) return;
  const j = FGU.job; if (!j) { box.innerHTML = ""; return; }
  box.innerHTML = j.devices.map((d) => {
    const comps = [...new Set([...Object.keys(d.before || {}), ...Object.keys(d.after || {})])];
    const verRows = comps.map((k) => {
      const b = (d.before[k] || {}).version || "—", a = (d.after[k] || {}).version || "—";
      const changed = Object.keys(d.after || {}).length && b !== a;
      return `<tr><td class="tech">${esc(k)}</td><td class="ltr">${esc(b)}</td><td class="ltr">${esc(a)}</td><td>${!Object.keys(d.after || {}).length ? "—" : changed ? `<span class="tag ok">به‌روز شد</span>` : `<span class="tag mute">بدون تغییر</span>`}</td></tr>`;
    }).join("");
    const done = d.packages.filter((p) => !["pending", "running"].includes(p.status)).length;
    return `<div class="panel"><div class="panel-head"><h3><span class="tech">${esc(d.name)}</span> <span class="muted ltr">${esc(d.host)}</span> ${fguTag(d.status)}</h3>
        <span class="muted">${d.dest_ip ? `dest_ip: <span class="ltr">${esc(d.dest_ip)}</span> — ` : ""}${num(done)} از ${num(d.packages.length)}${d.message ? ` — ${esc(d.message)}` : ""}</span>
        ${d.out_file ? `<button class="btn sm" data-out="${esc(j.id)}|${d.id}|${esc(d.name)}">خروجی کامل</button>` : ""}</div>
      <div class="progress"><i style="width:${Math.round((100 * done) / Math.max(1, d.packages.length))}%"></i></div>
      <div class="table-wrap inner"><table class="grid"><thead><tr>${["پکیج", "وضعیت", "نتیجه", "زمان"].map((t) => `<th class="nosort">${t}</th>`).join("")}</tr></thead><tbody>
        ${d.packages.map((p) => `<tr><td class="tech">${esc(p.file)}</td><td>${fguTag(p.status)}</td><td class="wrap tech">${esc(p.message || "")}</td><td class="num">${p.secs == null ? "—" : num(p.secs) + " ث"}</td></tr>`).join("")}</tbody></table></div>
      ${comps.length ? `<h3 style="margin:14px 0 8px">نسخه‌ها (diagnose autoupdate versions)</h3><div class="table-wrap inner"><table class="grid"><thead><tr>${["بخش", "قبل", "بعد", ""].map((t) => `<th class="nosort">${t}</th>`).join("")}</tr></thead><tbody>${verRows}</tbody></table></div>` : ""}</div>`;
  }).join("") + (j.tftp && j.tftp.length ? `<details class="panel"><summary class="muted" style="cursor:pointer">گزارش سرور TFTP (${num(j.tftp.length)})</summary>
      <div class="log" style="margin-top:8px">${j.tftp.slice(-60).reverse().map((e) => `<div class="ev ${esc(e.level)}"><time>${fmtTime(e.ts)}</time><span class="dot"></span><span class="msg">${esc(e.msg)}</span></div>`).join("")}</div></details>` : "");
}
async function pollFgu(force) {
  const r = await api("fgu_job"); if (!r.ok) return;
  const j = r.job, sig = JSON.stringify(j && [j.status, j.devices.map((d) => [d.status, d.packages.map((p) => p.status + p.message), Object.keys(d.after || {}).length]), (j.tftp || []).length]);
  if (!force && sig === FGU.sig) return;
  const was = FGU.job && FGU.job.status === "running";
  FGU.sig = sig; FGU.job = j;
  if (S.page === "ssh" && SSH.tab === "fgu") { if (was !== (j && j.status === "running")) sshFgu(); else renderFguJob(); }
  if (was && j && j.status !== "running") {
    const bad = j.devices.reduce((n, d) => n + d.packages.filter((p) => p.status !== "ok").length, 0);
    toast(bad ? `به‌روزرسانی تمام شد؛ ${num(bad)} پکیج ناموفق` : "به‌روزرسانی FortiGate با موفقیت تمام شد", bad ? "warn" : "ok");
  }
}
setInterval(() => { if (!document.hidden && ((S.page === "ssh" && SSH.tab === "fgu") || (FGU.job && FGU.job.status === "running"))) pollFgu(); }, 1000);

/* ================================================================ کارهای زمان‌بندی‌شده */
const JB = { list: [], sel: null, edit: null, master: false };
const JB_DAYS = [[5, "شنبه"], [6, "یکشنبه"], [0, "دوشنبه"], [1, "سه‌شنبه"], [2, "چهارشنبه"], [3, "پنجشنبه"], [4, "جمعه"]];
const JB_ST = { done: ["ok", "کامل"], failed: ["err", "ناموفق"], cancelled: ["warn", "متوقف"], started: ["info", "در حال اجرا"], skipped: ["mute", "رد شد"], error: ["err", "شروع نشد"], awaiting: ["warn", "منتظر تأیید"] };
function jbSched(j) {
  const s = j.schedule || {};
  if (s.type === "interval") return `هر ${num(s.every_minutes)} دقیقه`;
  if (s.type === "daily") return `ساعت ${s.time}` + ((s.days || []).length === 7 ? " هر روز" : " — " + JB_DAYS.filter(([k]) => s.days.includes(k)).map(([, n]) => n).join("، "));
  return "بدون زمان‌بندی";
}
async function renderJobs(body) {
  const r = await api("jobs_list");
  if (body.id === "autoBody" && (S.page !== "auto" || S.autoTab !== "daily")) return;
  if (!r.ok) return toast(r.error, "error");
  JB.list = r.jobs; JB.master = r.master;
  if (!JB.list.some((j) => j.id === JB.sel)) JB.sel = (JB.list[0] || {}).id || null;
  if (!JB.edit || JB.edit.id !== JB.sel) JB.edit = JB.sel ? clone(JB.list.find((j) => j.id === JB.sel)) : null;
  drawJobs(body);
}
function drawJobs(body) {
  const j = JB.edit;
  body.innerHTML = (JB.master ? "" : `<p class="hint warn">کلید اصلی کار خودکار خاموش است؛ کارها فقط با «اجرای الان» اجرا می‌شوند.</p>`)
    + `<div class="split"><div class="list-pane">${JB.list.length ? JB.list.map((x) => `<button class="list-item ${x.id === JB.sel ? "on" : ""}" data-jb="${esc(x.id)}">${esc(x.name)}
        ${x.enabled ? "" : `<span class="tag mute">خاموش</span>`} ${x.last_status && JB_ST[x.last_status] ? `<span class="tag ${JB_ST[x.last_status][0]}">${JB_ST[x.last_status][1]}</span>` : ""}
        <small>${esc(jbSched(x))} — ${x.items.map((i) => STEP_TITLE[i.tool]).join(ARW)}</small></button>`).join("")
      : `<div class="empty">کاری نیست. در صفحه‌ی «ابزارها» ترتیب ابزارها را بچینید و «ذخیره به‌عنوان کار» را بزنید.</div>`}</div>
    <div style="min-width:0">${j ? jobForm(j) : `<div class="form"><div class="empty">یک کار انتخاب کنید.</div></div>`}</div></div>`;
  $$("[data-jb]", body).forEach((b) => (b.onclick = () => { JB.sel = b.dataset.jb; JB.edit = clone(JB.list.find((x) => x.id === JB.sel)); drawJobs(body); }));
  if (!j) return;
  const s = j.schedule || (j.schedule = { type: "none" });
  const on = (sel, ev, fn) => { const el = $(sel, body); if (el) el.addEventListener(ev, fn); };
  on("#jbEn", "change", (e) => (j.enabled = e.target.checked));
  on("#jbType", "change", (e) => { s.type = e.target.value; if (s.type === "daily") { s.time = s.time || "08:00"; s.days = s.days || [0, 1, 2, 3, 4, 5, 6]; } if (s.type === "interval") s.every_minutes = s.every_minutes || 60; drawJobs(body); });
  on("#jbTime", "input", (e) => (s.time = e.target.value));
  on("#jbEvery", "input", (e) => (s.every_minutes = Number(e.target.value || 60)));
  $$("[data-jday]", body).forEach((x) => (x.onchange = () => (s.days = $$("[data-jday]", body).filter((y) => y.checked).map((y) => Number(y.dataset.jday)))));
  on("#jbBusy", "change", (e) => (j.when_busy = e.target.value));
  ["auto_ban", "auto_ticket", "auto_ssh"].forEach((k) => on(`#jb_${k}`, "change", (e) => { j[k] = e.target.checked; if (k === "auto_ban") drawJobs(body); }));
  on("#jbCap", "input", (e) => (j.max_auto_ban = Number(e.target.value || 0)));
  on("#jbSave", "click", (e) => withSpin(e.currentTarget, async () => {
    if (j.enabled && (j.auto_ban || j.auto_ssh) && !(await confirm2({ title: "اجرای بدون تأیید", danger: true, confirm: "ذخیره", ack: "می‌دانم و می‌خواهم",
      body: `<p>در اجرای زمان‌بندی‌شده‌ی این کار ${[j.auto_ban && "بلاک IPهای مخرب (تا سقف تعیین‌شده)", j.auto_ssh && "اجرای اسکریپت SSH روی دستگاه‌ها"].filter(Boolean).join(" و ")} بدون تأیید شما انجام می‌شود.</p>` }))) return;
    const p = clone(j); delete p.next_at;
    const r = await api("job_save", p); if (!r.ok) return toast(r.error, "error");
    JB.sel = r.job.id; JB.edit = null; toast("کار ذخیره شد", "ok"); renderJobs(body);
  }));
  on("#jbRun", "click", async () => {
    if (!(await confirm2({ title: "اجرای الان", confirm: "اجرا", body: `<p>کار «${esc(j.name)}» با آخرین نسخه‌ی ذخیره‌شده اجرا می‌شود. در اجرای دستی پیش از بلاک، تیکت و SSH از شما تأیید گرفته می‌شود (صفحه‌ی «ابزارها»).</p>` }))) return;
    const r = await api("job_run", j.id); if (!r.ok) return toast(r.error, "error");
    toast("اجرا شروع شد", "ok"); go("run");
  });
  on("#jbOpen", "click", () => { RF.seq = []; j.items.forEach(rfFromItem); RF.job = j.id; go("run"); });
  on("#jbDel", "click", async () => {
    if (!(await confirm2({ title: "حذف کار", danger: true, confirm: "حذف", body: `<p>کار «${esc(j.name)}» و زمان‌بندی‌اش حذف شود؟</p>` }))) return;
    const r = await api("job_delete", j.id); if (!r.ok) return toast(r.error, "error");
    JB.sel = null; JB.edit = null; renderJobs(body);
  });
}
function jobForm(j) {
  const s = j.schedule, has = (t) => j.items.some((i) => i.tool === t);
  const adm = isAdmin(), canRun = !(S.state && S.state.me && S.state.me.role === "readonly") && j.items.every((i) => canTool(i.tool));
  return `<fieldset ${adm ? "" : "disabled"} style="border:0;padding:0;margin:0;min-width:0"><div class="form"><div class="row" style="justify-content:space-between;align-items:center"><h3 style="margin:0">${esc(j.name)}</h3>
      <label class="chk"><input type="checkbox" id="jbEn" ${j.enabled ? "checked" : ""}><b>زمان‌بندی روشن</b></label></div>
    <p class="hint"><span>ابزارها:</span> ${j.items.map((i, n) => `${n + 1}. <span>${STEP_TITLE[i.tool]}</span>`).join(ARW)} — <span>برای تغییر ابزارها یا ورودی‌ها «باز کردن در ابزارها» را بزنید و دوباره ذخیره کنید.</span></p>
    <div class="sec"><h3>زمان‌بندی</h3><div class="row" style="gap:12px;flex-wrap:wrap">
      <label class="field"><span>نوع</span><select id="jbType">${[["daily", "روزانه در ساعت مشخص"], ["interval", "هر N دقیقه"], ["none", "بدون زمان‌بندی"]].map(([k, v]) => `<option value="${k}" ${s.type === k ? "selected" : ""}>${v}</option>`).join("")}</select></label>
      ${s.type === "daily" ? `<label class="field"><span>ساعت</span><input type="time" id="jbTime" value="${esc(s.time || "08:00")}"></label>` : ""}
      ${s.type === "interval" ? `<label class="field"><span>هر چند دقیقه (حداقل ۵)</span><input type="number" min="5" id="jbEvery" value="${esc(s.every_minutes || 60)}"></label>` : ""}
      <label class="field"><span>اگر اجرای دیگری در جریان بود</span><select id="jbBusy"><option value="wait" ${j.when_busy !== "skip" ? "selected" : ""}>صبر کند</option><option value="skip" ${j.when_busy === "skip" ? "selected" : ""}>این نوبت رد شود</option></select></label></div>
      ${s.type === "daily" ? `<div class="chks" style="margin-top:6px">${JB_DAYS.map(([k, n]) => `<label class="chk"><input type="checkbox" data-jday="${k}" ${(s.days || []).includes(k) ? "checked" : ""}>${n}</label>`).join("")}</div>` : ""}
      <p class="hint">اولین اجرا از همین لحظه است؛ نوبت‌های گذشته اجرا نمی‌شوند. اگر برنامه بسته بوده و بیش از «حداکثر قدمت» گذشته باشد، آن نوبت رد می‌شود.</p></div>
    <div class="sec"><h3>تأیید در اجرای زمان‌بندی‌شده</h3>
      <p class="hint">پیش‌فرض: پیش از بلاک، تیکت و SSH اجرا منتظر شما می‌ماند و اعلان «منتظر تأیید» فرستاده می‌شود. اجرای دستی همیشه تأیید می‌خواهد.</p>
      <div class="chks">${has("fortigate") ? `<label class="chk"><input type="checkbox" id="jb_auto_ban" ${j.auto_ban ? "checked" : ""}>FortiGate بدون تأیید (بلاک یا تسک)</label>` : ""}
        ${has("redmine") ? `<label class="chk"><input type="checkbox" id="jb_auto_ticket" ${j.auto_ticket ? "checked" : ""}>تیکت بدون تأیید</label>` : ""}
        ${has("ssh") ? `<label class="chk"><input type="checkbox" id="jb_auto_ssh" ${j.auto_ssh ? "checked" : ""}>SSH بدون تأیید</label>` : ""}
        ${!has("fortigate") && !has("redmine") && !has("ssh") ? `<span class="muted">این کار ابزاری که تأیید بخواهد ندارد.</span>` : ""}</div>
      ${j.auto_ban && has("fortigate") ? `<label class="field" style="margin-top:8px"><span>سقف بلاک/کار تسک بدون تأیید در هر اجرا (۰ = بی‌سقف)</span><input type="number" min="0" id="jbCap" value="${esc(j.max_auto_ban ?? 50)}"></label>` : ""}</div>
    <div class="sec"><p class="muted">آخرین اجرا: ${j.last_at ? `${fmtDate(j.last_at)} ${JB_ST[j.last_status] ? `<span class="tag ${JB_ST[j.last_status][0]}">${JB_ST[j.last_status][1]}</span>` : ""} ${esc(j.last_message || "")}` : "—"}</p>
      <p class="muted">اجرای بعدی: ${j.next_at ? fmtDate(j.next_at) + (JB.master ? "" : ` <span>(کلید اصلی خاموش است)</span>`) : "—"}</p></div>
    </div></fieldset><div class="form-foot" style="display:flex;gap:8px;flex-wrap:wrap">${adm ? `<button class="btn primary" id="jbSave">ذخیره</button>` : ""}${canRun ? `<button class="btn" id="jbRun">اجرای الان</button><button class="btn ghost" id="jbOpen">باز کردن در ابزارها</button>` : ""}
      <span style="flex:1"></span>${adm ? `<button class="btn danger-ghost" id="jbDel">حذف کار</button>` : ""}${adm ? "" : `<span class="hint">ویرایش کارها فقط برای ادمین است.</span>`}</div>`;
}
