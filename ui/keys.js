"use strict";
/* ================================================================ کار با کیبورد (1.23)
 *  Esc: بستن انتخاب‌گر بازه، منو و پنجره (پنجره‌ی فرمی که تغییر کرده اول می‌پرسد).
 *  Enter در پنجره‌ی یک‌فیلدی = دکمه‌ی اصلی. Ctrl+F = جستجوی صفحه/پنجره.
 *  ↑↓ در جدول‌ها (Enter = جزئیات، Space = تیک ردیف). انتقال فایل: کلیدهای WinSCP. */

const KB = { t: null, i: -1, typed: "", typedAt: 0 };
const kbTyping = (el) => el && el.closest && el.closest("input:not([type=checkbox]):not([type=radio]):not([type=button]), textarea, select, [contenteditable=''], [contenteditable=true], .xterm");
const kbModalOpen = () => typeof modalClose === "function" && modalClose && !$("#modalBack").hidden;
const kbRoot = () => (kbModalOpen() ? $("#modal") : $(".page.active"));
const kbVisible = (el) => !!(el && el.offsetParent !== null && el.getClientRects().length);

/* ---------------------------------------------------------------- تغییر فرم پنجره */
["input", "change"].forEach((ev) => document.addEventListener(ev, (e) => {
  const m = $("#modal"), t = e.target;
  if (!e.isTrusted || !m || !m.contains(t) || !t.matches || !t.matches("input, textarea, select")) return;
  if (t.matches("[type=search], [data-nodirty]") || t.closest(".trbar, .trpop, [data-nodirty]")) return;
  m._dirty = true;
}, true));
function kbDirtyAsk(m) {
  const foot = $(".m-foot", m); if (!foot) return modalClose(null);
  let bar = $(".m-dirty", foot);
  if (bar) return modalClose(null);              // Esc دوم = بستن بدون ذخیره
  bar = document.createElement("div"); bar.className = "m-dirty";
  bar.innerHTML = `<span>${esc(I18N.t("تغییرات ذخیره نشده‌اند. بسته شود؟"))}</span><button class="btn sm danger-ghost" data-kd="close">${esc(I18N.t("بستن بدون ذخیره"))}</button><button class="btn sm ghost" data-kd="stay">${esc(I18N.t("ادامه‌ی ویرایش"))}</button>`;
  foot.prepend(bar);
  $("[data-kd='close']", bar).onclick = () => modalClose(null);
  $("[data-kd='stay']", bar).onclick = () => bar.remove();
  $("[data-kd='stay']", bar).focus();
}

/* ---------------------------------------------------------------- جدول‌ها */
function kbTables() {
  const root = kbRoot(); if (!root) return [];
  return $$("table.grid", root).filter((t) => kbVisible(t) && kbRows(t).length);
}
function kbRows(t) { return t.tBodies[0] ? [...t.tBodies[0].rows].filter((r) => r.cells.length > 1 && kbVisible(r)) : []; }
function kbMark(t, i, scroll = true) {
  document.querySelectorAll("table.grid tr.kcur").forEach((r) => r.classList.remove("kcur"));
  KB.t = t; KB.i = i; KB.key = t ? tsKey(t) : null;
  if (!t) return;
  const r = kbRows(t)[i]; if (!r) return;
  r.classList.add("kcur");
  if (scroll) r.scrollIntoView({ block: "nearest" });
}
function kbClear() { const had = !!$("table.grid tr.kcur"); kbMark(null, -1); return had; }
document.addEventListener("mousedown", (e) => {
  if (!$("table.grid tr.kcur")) return;            // فقط وقتی مکان‌نمای کیبورد فعال است، با کلیک جابه‌جا می‌شود
  const r = e.target.closest && e.target.closest("table.grid tbody tr"); if (!r) return;
  const t = r.closest("table.grid"), i = kbRows(t).indexOf(r);
  if (i >= 0) kbMark(t, i, false);
}, true);
/** Enter روی ردیف: فقط عمل «نمایش/جزئیات» (هرگز دکمه‌ی حذف یا تغییر) */
function kbOpenRow(r) {
  if (r.onclick || r.classList.contains("clickable")) { r.click(); return true; }
  const a = r.querySelector("[data-ipd], [data-hv], [data-pc], [data-mid], [data-aid], a.link, span.link");
  if (a) { a.click(); return true; }
  return false;
}
function kbTableKey(e) {
  const k = e.key;
  if (!["ArrowDown", "ArrowUp", "Home", "End", "PageDown", "PageUp", "Enter", " "].includes(k)) return false;
  const tabs = kbTables(); if (!tabs.length) return false;
  let t = KB.t && KB.t.isConnected && tabs.includes(KB.t) ? KB.t : null;
  if (!t) {
    if (k === "Enter" || k === " ") return false;
    t = tabs[0]; KB.i = -1;
  }
  const rows = kbRows(t);
  const has = $("tr.kcur", t) && KB.i >= 0;
  if (k === "Enter" || k === " ") {
    if (!has) return false;
    const r = rows[Math.min(KB.i, rows.length - 1)];
    if (k === " ") { const c = r.querySelector("td.chk input[type=checkbox], input[type=checkbox]"); if (!c || c.disabled) return false; c.click(); return true; }
    return kbOpenRow(r);
  }
  const page = Math.max(1, Math.floor((t.closest(".table-wrap, .m-body, .main") || document.documentElement).clientHeight / 34) - 1);
  let i = has ? Math.min(KB.i, rows.length - 1) : -1;
  if (k === "ArrowDown") i = i < 0 ? 0 : Math.min(rows.length - 1, i + 1);
  else if (k === "ArrowUp") i = i < 0 ? 0 : Math.max(0, i - 1);
  else if (k === "Home") i = 0;
  else if (k === "End") i = rows.length - 1;
  else if (k === "PageDown") i = Math.min(rows.length - 1, Math.max(0, i) + page);
  else if (k === "PageUp") i = Math.max(0, i - page);
  kbMark(t, i);
  return true;
}
// بعد از به‌روزرسانی خودکار جدول، ردیف مکان‌نما دوباره علامت می‌خورد (همان شماره‌ی ردیف)
let kbRaf = 0;
new MutationObserver(() => {
  if (KB.i < 0 || !KB.t || kbRaf) return;           // فقط در حالت کیبورد؛ حداکثر یک بار در هر فریم (بدون layout پشت‌سرهم)
  kbRaf = requestAnimationFrame(kbRestore);
}).observe(document.body, { childList: true, subtree: true });
function kbRestore() {
  kbRaf = 0;
  if (KB.i < 0 || !KB.t) return;
  if (KB.t.isConnected && $("tr.kcur", KB.t)) return;
  const tabs = kbTables(); const t = KB.t.isConnected && tabs.includes(KB.t) ? KB.t : tabs.find((x) => KB.key && tsKey(x) === KB.key);
  if (!t) return;
  const rows = kbRows(t); if (!rows.length) return;
  const i = Math.min(KB.i, rows.length - 1);
  if (!rows[i].classList.contains("kcur")) { KB.t = t; rows[i].classList.add("kcur"); }
}

/* ---------------------------------------------------------------- انتقال فایل (مثل WinSCP) */
function xfKActive() {
  return typeof XF !== "undefined" && S.page === "ssh" && typeof SSH !== "undefined" && SSH.tab === "xfer" && XF.sub === "files" && $("#xfMain");
}
function xfKSide() {
  const rOk = XF.cur && XF.cur.browse && $("#xrList tbody tr[data-n]"), lOk = XF.desktop && $("#xlList");
  if (XF.focus === "l" && lOk) return "l";
  if (rOk || $("#xrList")) return "r";
  return lOk ? "l" : null;
}
const xfKList = (side) => $(side === "l" ? "#xlList" : "#xrList");
const xfKSel = (side) => (side === "l" ? XF.local.sel : XF.rsel);
const xfKItems = (side) => (side === "l" ? XF.local.items : (XF.cur && XF.cur.items) || []);
function xfKPaint(side, scroll = true) {
  const box = xfKList(side); if (!box) return;
  const sel = xfKSel(side);
  $$("tbody tr[data-n]", box).forEach((r) => {
    r.classList.toggle("sel", sel.has(r.dataset.n));
    const on = r.dataset.n === XF.kc[side];
    r.classList.toggle("kcur", on);
    if (on && scroll) r.scrollIntoView({ block: "nearest" });
  });
  xfButtons();
}
function xfKFocus(side) {
  XF.focus = side;
  $$(".xf-pane").forEach((x) => x.classList.toggle("act", x.id === (side === "l" ? "xfLocal" : "xfRemote")));
  const rows = $$("tbody tr[data-n]", xfKList(side) || document.createElement("div"));
  if (rows.length && !rows.some((r) => r.dataset.n === XF.kc[side])) XF.kc[side] = rows[0].dataset.n;
  xfKPaint(side);
}
async function xfKOpen(side, name, dir) {
  if (!dir) {                                    // فایل: مثل دوبار کلیک
    if (side === "r") return xfDownload([name]);
    if (XF.cur) return xfUploadLocal([name]);
    return toast("ابتدا به دستگاه وصل شوید", "warn");
  }
  const ok = side === "l" ? await xfLocalGo(xfJoinL(name)) : await xfRemoteGo(xfJoinR(name));
  if (ok) xfKFocus(side);
}
async function xfKUp(side) {
  if (side === "l") {
    if (!XF.local.loaded) return;
    const cwd = XF.local.cwd || "", sep = XF.local.sep || "/";
    const base = cwd.replace(/[\\/]+$/, "").split(/[\\/]/).pop() || cwd.replace(/[\\/]+$/, "");
    const ok = await xfLocalGo(XF.local.parent ?? "");
    if (ok) { const hit = XF.local.items.find((i) => i.name === base || i.name === base + sep || i.name.replace(/[\\/]+$/, "") === base); XF.kc.l = XF.ka.l = hit ? hit.name : null; xfKFocus("l"); }
    return;
  }
  if (XF.cur && XF.cur.browse) { await xfRemoteUp(); xfKFocus("r"); }
}
function xfKey(e) {
  if (!xfKActive()) return false;
  const k = e.key, ctrl = e.ctrlKey || e.metaKey;
  if ((k === "Enter" || k === " ") && e.target && e.target.closest && e.target.closest("button, a")) return false;   // دکمه‌ی فوکوس‌شده
  const side = xfKSide(); if (!side) return false;
  const box = xfKList(side); if (!box) return false;
  const rows = $$("tbody tr[data-n]", box);
  const names = rows.map((r) => r.dataset.n);
  const sel = xfKSel(side);
  let i = names.indexOf(XF.kc[side]);
  const pageN = Math.max(1, Math.floor(box.clientHeight / 30) - 1);
  const move = (j) => {
    if (!names.length) return;
    j = Math.max(0, Math.min(names.length - 1, j));
    XF.kc[side] = names[j];
    if (e.shiftKey) {
      const a = Math.max(0, names.indexOf(XF.ka[side] ?? names[Math.max(0, i)]));
      if (XF.ka[side] == null) XF.ka[side] = names[Math.max(0, i)];
      sel.clear(); names.slice(Math.min(a, j), Math.max(a, j) + 1).forEach((n) => sel.add(n));
    } else if (!ctrl) { sel.clear(); sel.add(names[j]); XF.ka[side] = names[j]; }
    xfKPaint(side);
  };
  const target = () => (sel.size ? [...sel] : XF.kc[side] ? [XF.kc[side]] : []);
  switch (k) {
    case "ArrowDown": move(i < 0 ? 0 : i + 1); return true;
    case "ArrowUp": move(i < 0 ? 0 : i - 1); return true;
    case "Home": move(0); return true;
    case "End": move(names.length - 1); return true;
    case "PageDown": move(Math.max(0, i) + pageN); return true;
    case "PageUp": move(Math.max(0, i) - pageN); return true;
    case "Enter": {
      if (i < 0) return false;
      const r = rows[i]; xfKOpen(side, r.dataset.n, r.dataset.dir === "1"); return true;
    }
    case "Backspace": xfKUp(side); return true;
    case "Tab": {
      if (!XF.desktop || !(XF.cur && XF.cur.browse)) return false;
      xfKFocus(side === "l" ? "r" : "l"); return true;
    }
    case " ": {
      if (i < 0) { move(0); return true; }
      const n = names[i]; sel.has(n) ? sel.delete(n) : sel.add(n); XF.ka[side] = n; xfKPaint(side, false); return true;
    }
    case "F5": {
      const t = target(); if (!t.length) { toast("فایلی انتخاب نشده است", "warn"); return true; }
      if (side === "r") xfDownload(t); else xfUploadLocal(t);
      return true;
    }
    case "F2": {
      if (side === "l") { toast("تغییر نام فقط در پنل دستگاه", "warn"); return true; }
      const n = XF.kc.r || [...XF.rsel][0]; if (!n) return true;
      XF.rsel.clear(); XF.rsel.add(n); xfRename(); return true;
    }
    case "F7": {
      if (side === "l") { toast("ساختن پوشه فقط در پنل دستگاه", "warn"); return true; }
      xfMkdir(); return true;
    }
    case "Delete": {
      if (side === "l") { toast("حذف فقط در پنل دستگاه (فایل‌های این کامپیوتر دست نمی‌خورند)", "warn"); return true; }
      if (!XF.rsel.size && XF.kc.r) XF.rsel.add(XF.kc.r);
      xfDelete(); return true;
    }
  }
  if (ctrl && (k === "a" || k === "A" || k === "ش")) { names.forEach((n) => sel.add(n)); xfKPaint(side, false); return true; }
  if (ctrl && (k === "r" || k === "R" || k === "ق")) { if (side === "l") xfLocalGo(XF.local.cwd); else xfRemoteGo(XF.cur.cwd); return true; }
  // تایپ حروف = پرش به اولین نامی که با آن شروع می‌شود
  if (k.length === 1 && !ctrl && !e.altKey && k !== " ") {
    const now = Date.now();
    KB.typed = (now - KB.typedAt < 900 ? KB.typed : "") + k.toLowerCase(); KB.typedAt = now;
    let j = names.findIndex((n) => n.toLowerCase().startsWith(KB.typed));
    if (j < 0 && KB.typed.length > 1) { KB.typed = k.toLowerCase(); j = names.findIndex((n) => n.toLowerCase().startsWith(KB.typed)); }
    if (j >= 0) move(j);
    return true;
  }
  return false;
}

/* ---------------------------------------------------------------- مسیریاب کلیدها */
document.addEventListener("keydown", (e) => {
  if (e.defaultPrevented) return;
  const k = e.key;
  if ($("#noc") && !kbModalOpen()) {               // نمای NOC: Esc = بستن، F = تمام‌صفحه
    if (k === "Escape") { e.preventDefault(); nocClose(); return; }
    if ((k === "f" || k === "F" || k === "ب") && !e.ctrlKey && !e.altKey && !kbTyping(e.target)) { e.preventDefault(); nocFull(); return; }
    return;
  }
  if (k === "Escape") {
    if (typeof trPopClose === "function" && trPopClose()) { e.preventDefault(); return; }
    const cm = $("#colsMenu"); if (cm && !cm.hidden) { cm.hidden = true; return; }
    if (e.target && e.target.closest && e.target.closest(".xterm") && !kbModalOpen()) return;   // Esc برای دستگاه
    if (kbModalOpen()) {
      e.preventDefault();
      const m = $("#modal");
      if (m._dirty && $(".m-foot .btn.primary", m)) kbDirtyAsk(m); else modalClose(null);
      return;
    }
    kbClear();
    return;
  }
  // Ctrl+F = جستجوی همین صفحه یا پنجره
  if ((e.ctrlKey || e.metaKey) && !e.altKey && !e.shiftKey && (k === "f" || k === "F" || k === "ب")) {
    const root = kbRoot();
    const q = root && $$("input[type=search], input.search", root).find(kbVisible);
    if (q) { e.preventDefault(); q.focus(); q.select(); }
    return;
  }
  // Enter در پنجره‌ای که فقط یک فیلد متنی دارد = دکمه‌ی اصلی
  if (k === "Enter" && kbModalOpen() && !e.shiftKey && !e.ctrlKey && !e.altKey) {
    const t = e.target, m = $("#modal");
    if (t && t.matches && t.matches("input") && !t.matches("[type=checkbox], [type=radio], [type=file], [type=button], [type=search]") && m.contains(t) && !t.onkeydown) {
      const fields = $$("input, textarea, select", m).filter((x) => kbVisible(x) && !x.matches("[type=checkbox], [type=radio], [type=hidden], [type=search]"));
      const p = $(".m-foot .btn.primary", m);
      if (fields.length === 1 && p && !p.disabled) { e.preventDefault(); p.click(); }
    }
    return;
  }
  if (kbTyping(e.target) || e.altKey) return;
  if (kbModalOpen() || $(".trpop")) {
    if (!e.ctrlKey && !e.metaKey && kbModalOpen() && kbTableKey(e)) e.preventDefault();
    return;
  }
  if (xfKey(e)) { e.preventDefault(); return; }
  if (e.ctrlKey || e.metaKey) return;
  if (e.target && e.target.closest && e.target.closest("button, a, [tabindex]") && (k === "Enter" || k === " ")) return;   // دکمه‌ی فوکوس‌شده کار خودش را بکند
  if (kbTableKey(e)) e.preventDefault();
});
