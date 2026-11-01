"use strict";
/* ================================================================ نقشه‌های دستی شبکه (1.38)
 * فهرست نقشه‌ها، نمایش زنده (وضعیت دستگاه و پورت از همان پایش عادی)، ویرایشگر (کشیدن دستگاه، لینک پورت‌به‌پورت،
 * ناحیه، متن، زیرنقشه، پس‌زمینه) و تمام‌صفحه با چرخش. وابسته به app.js، monitor.js و snmp.js. */

const NM = { list: null, groups: [], canEdit: false, filt: { grp: "", q: "", prob: false }, cur: null, st: null, devs: new Map(), maps: new Map(),
  el: null, timer: 0, edit: false, dirty: false, sel: null, tool: "sel", linkA: null, hist: [], fut: [], vb: null, drag: null, q: "",
  prob: false, full: false, rot: 0, rotTimer: 0, bg: "", bgNew: undefined, stack: [] };
const NM_UC = (p) => (p >= 90 ? "#c63e33" : p >= 75 ? "#e0702e" : p >= 50 ? "#d9a520" : "#2e9e5b");
const NM_NCLS = { up: "ok", slow: "ok", down: "err", unreachable: "unr", warn: "warn" };
const NM_STN = { up: "وصل", slow: "کند", down: "قطع", unreachable: "در دسترس نیست (بالادستی قطع)", warn: "هشدار", unknown: "در حال بررسی",
  paused: "متوقف", hidden: "بدون دسترسی", gone: "حذف‌شده" };
const NM_LSTN = { up: "وصل", down: "پورت پایین", dev: "دستگاه قطع", unk: "نامعلوم", off: "خاموش (Admin down)" };
const NM_KIND = { cable: "کابلی", fiber: "فیبر", vpn: "VPN", wifi: "بی‌سیم", none: "بدون پورت" };
const NM_NLAB = { name: "نام", ip: "نام و IP", load: "نام و بار", none: "بدون برچسب" };
const NM_LLAB = { util: "درصد ترافیک", bps: "In/Out", ports: "نام پورت‌ها", none: "بدون برچسب" };
const NM_ICONS = ["router", "switch", "core", "firewall", "server", "wifi", "storage", "pc", "printer", "camera", "phone", "internet", "other"];
const NM_CORE = '<rect x="2.5" y="6" width="19" height="12" rx="1.5"/><path d="M2.5 10h19M6 13.5v2M9 13.5v2M12 13.5v2M15 13.5v2M18 13.5v2"/>';
const NM_MAPIC = '<rect x="3" y="4" width="18" height="16" rx="2"/><rect x="6" y="7" width="5" height="4" rx=".6" fill="currentColor"/><rect x="13" y="7" width="5" height="4" rx=".6" fill="currentColor"/><rect x="9.5" y="13.5" width="5" height="4" rx=".6" fill="currentColor"/>';
const NM_AREA_C = { blue: "#2f6fc3", teal: "#178f84", green: "#238a52", orange: "#c86a1a", red: "#c63e33", purple: "#8a5cc7", gray: "#6b7a8c" };
const NM_SZ = { s: 34, m: 44, l: 58 };
const NM_TSZ = { s: 13, m: 17, l: 24 };

function nmIconName(k) { return k === "core" ? "سوییچ هسته" : (MON_ICON_NAME[k] || k); }
function nmDur(sec) {
  sec = Math.max(0, Math.round(sec));
  if (sec < 90) return `${num(sec)} ثانیه`;
  if (sec < 5400) return `${num(Math.round(sec / 60))} دقیقه`;
  if (sec < 172800) return `${num(Math.round(sec / 3600))} ساعت`;
  return `${num(Math.round(sec / 86400))} روز`;
}
function nmBps(v) { return typeof fmtBps === "function" ? fmtBps(v) : `${num(v)} bps`; }
/** نام لاتین (مثل Core-Cisco-9300) با رقم لاتین و جهت درست؛ نام فارسی همان‌طور */
function nmN(t) { t = String(t || ""); return /^[\x20-\x7e]+$/.test(t) ? `<span class="ltr">${esc(t)}</span>` : `<span class="bidi">${esc(t)}</span>`; }
function nmUid(p) { return p + Math.random().toString(36).slice(2, 9); }

/* ---------------------------------------------------------------- ورود از سربرگ مانیتورینگ */
async function netmapRender(el) {
  NM.el = el;
  if (NM.cur) return nmOpen(NM.cur.id, NM.edit);
  return nmListRender();
}
/** ترک ویرایش بدون ذخیره ← پرسش (سربرگ‌ها، بازگشت، نقشه‌ی دیگر) */
async function nmCanLeave() {
  if (!NM.edit || !NM.dirty) return true;
  const ok = await confirm2({ title: "تغییرات ذخیره نشده", body: `<p>${esc("تغییرات این نقشه ذخیره نشده‌اند. بدون ذخیره خارج می‌شوید؟")}</p>`, confirm: "خروج بدون ذخیره", danger: true });
  if (ok) { NM.dirty = false; NM.edit = false; }
  return ok;
}
function nmStop() { clearTimeout(NM.timer); NM.timer = 0; clearInterval(NM.rotTimer); NM.rotTimer = 0; }
function nmAlive() { return NM.el && NM.el.isConnected && (NM.full || (MON.tab === "maps" && S.page === "monitor")); }

/* ---------------------------------------------------------------- فهرست نقشه‌ها */
async function nmListRender() {
  nmStop(); nmFullOff();
  NM.cur = null; NM.edit = false; NM.stack = [];
  const el = NM.el;
  const r = await api("mon_map_list");
  if (!el.isConnected) return;
  if (!r.ok) { el.innerHTML = `<div class="panel"><div class="empty">${esc(r.error)}</div></div>`; return; }
  NM.list = r.maps; NM.groups = r.groups; NM.canEdit = r.can_edit;
  const F = NM.filt;
  const grps = [...new Set([...r.groups, ...r.maps.map((m) => m.grp).filter(Boolean)])].sort();
  el.innerHTML = `<div class="toolbar">${NM.canEdit ? `<button class="btn primary" id="nmNew">+ نقشه‌ی جدید</button>` : ""}
      <select id="nmGrp" style="width:auto;min-width:150px"><option value="">همه‌ی گروه‌ها</option>${grps.map((g) => `<option value="${esc(g)}" ${F.grp === g ? "selected" : ""}>${esc(g)}</option>`).join("")}</select>
      <input id="nmQ" placeholder="جستجوی نقشه یا دستگاه…" style="width:230px" value="${esc(F.q)}">
      <div class="seg" id="nmProb"><button data-v="0" class="${F.prob ? "" : "on"}">همه</button><button data-v="1" class="${F.prob ? "on" : ""}">فقط دارای مشکل</button></div>
      <span style="flex:1"></span>${r.maps.length ? `<button class="btn" id="nmFullAll" title="تمام‌صفحه با چرخش بین نقشه‌ها (برای مانیتور دیواری)">⛶ نمایش دیواری</button>` : ""}</div>
    <div id="nmCards"></div>`;
  const draw = () => {
    const q = F.q.trim().toLowerCase();
    const show = r.maps.filter((m) => (!F.grp || m.grp === F.grp) && (!F.prob || m.counts.down || m.counts.warn || m.counts.unk)
      && (!q || m.name.toLowerCase().includes(q)));
    $("#nmCards", el).innerHTML = !r.maps.length
      ? `<div class="panel"><div class="empty">${esc("هنوز نقشه‌ای ساخته نشده است.")}${NM.canEdit ? `<br><span class="muted">${esc("با «نقشه‌ی جدید» دستگاه‌های مانیتورینگ را روی نقشه بکشید و پورت‌به‌پورت به هم وصل کنید؛ نیازی به LLDP یا CDP نیست.")}</span>` : ""}</div></div>`
      : !show.length ? `<div class="panel"><div class="empty">موردی پیدا نشد.</div></div>`
      : `<div class="nm-cards">${show.map(nmCard).join("")}</div>`;
    $$("[data-mo]", el).forEach((c) => (c.onclick = (e) => { if (e.target.closest("[data-me],[data-md]")) return; nmOpen(Number(c.dataset.mo)); }));
    $$("[data-me]", el).forEach((b) => (b.onclick = () => nmOpen(Number(b.dataset.me), true)));
    $$("[data-md]", el).forEach((b) => (b.onclick = async () => {
      const m = r.maps.find((x) => x.id === Number(b.dataset.md));
      if (!(await confirm2({ title: "حذف نقشه", body: `<p>${esc(`نقشه‌ی «${m.name}» حذف شود؟ دستگاه‌ها و پایش آن‌ها تغییری نمی‌کنند.`)}</p>`, confirm: "حذف", danger: true }))) return;
      const x = await api("mon_map_delete", m.id); if (!x.ok) return toast(x.error, "error");
      toast("نقشه حذف شد", "ok"); nmListRender();
    }));
  };
  draw();
  $("#nmGrp", el).onchange = (e) => { F.grp = e.target.value; draw(); };
  let tq = 0; $("#nmQ", el).oninput = (e) => { F.q = e.target.value; clearTimeout(tq); tq = setTimeout(draw, 200); };
  $$("#nmProb button", el).forEach((b) => (b.onclick = () => { F.prob = b.dataset.v === "1"; $$("#nmProb button", el).forEach((x) => x.classList.toggle("on", x === b)); draw(); }));
  if ($("#nmNew", el)) $("#nmNew", el).onclick = nmNew;
  if ($("#nmFullAll", el)) $("#nmFullAll", el).onclick = async () => { const first = r.maps[0]; await nmOpen(first.id); nmFullOn(60); };
  NM.timer = setTimeout(() => { if (nmAlive() && !NM.cur) nmListRender(); }, 30000);
}
function nmCard(m) {
  const c = m.counts;
  const W = m.w || 1600, H = m.h || 900, pos = new Map(m.nodes.map((n) => [n.id, n]));
  const thumb = `<svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="xMidYMid meet" class="nm-thumb">${m.nodes.filter((n) => n.t === "area")
    .map((n) => `<rect x="${n.x}" y="${n.y}" width="${n.w}" height="${n.h}" rx="16" class="nm-th-area"/>`).join("")}${m.links
    .map(([a, b]) => { const A = pos.get(a), B = pos.get(b); return A && B ? `<line x1="${A.x}" y1="${A.y}" x2="${B.x}" y2="${B.y}" class="nm-th-l"/>` : ""; }).join("")}${m.nodes
    .filter((n) => n.t !== "area").map((n) => `<circle cx="${n.x}" cy="${n.y}" r="${Math.max(W, H) / 90}" class="nm-th-n"/>`).join("")}</svg>`;
  return `<div class="nm-card ${m.worst === "down" ? "bad" : m.worst === "warn" ? "warnc" : ""}" data-mo="${m.id}" tabindex="0">${thumb}
    <div class="nm-cb"><div class="row" style="gap:8px"><b class="bidi" style="flex:1">${esc(m.name)}</b>${m.grp ? `<span class="tag mute">${esc(m.grp)}</span>` : ""}</div>
      <div class="nm-cnt"><span class="ok">● ${num(c.up)} <span>وصل</span></span>${c.down ? `<span class="err">● ${num(c.down)} <span>قطع</span></span>` : ""}${c.warn ? `<span class="warn">● ${num(c.warn)} <span>هشدار</span></span>` : ""}${c.unk ? `<span class="muted">● ${num(c.unk)} <span>نامعلوم</span></span>` : ""}<span class="muted">${num(m.n_links)} <span>لینک</span></span></div>
      <div class="row muted" style="gap:6px"><span style="flex:1">آخرین تغییر: <span class="ltr">${m.updated ? esc(trFmt(m.updated)) : "—"}</span></span>
      ${NM.canEdit ? `<button class="btn sm ghost" data-me="${m.id}">ویرایش</button><button class="btn sm danger-ghost" data-md="${m.id}">حذف</button>` : ""}</div></div></div>`;
}
async function nmNew() {
  const grps = NM.groups || [];
  const v = await openModal({ title: "نقشه‌ی جدید",
    body: `<label>نام نقشه</label><input id="nnName" autofocus placeholder="مثلاً: شبکه‌ی اصلی">
      <label style="margin-top:10px">گروه (برای فیلتر و انتخاب دستگاه‌ها)</label><select id="nnGrp"><option value="">بدون گروه</option>${grps.map((g) => `<option>${esc(g)}</option>`).join("")}</select>
      <label class="chk" style="margin-top:10px"><input type="checkbox" id="nnAdd" ${grps.length ? "" : "disabled"}>همه‌ی دستگاه‌های این گروه روی نقشه گذاشته شوند (بعد جابه‌جا و وصل کنید)</label>
      <label style="margin-top:10px">اندازه‌ی صفحه</label><select id="nnSize"><option value="1600x900">معمولی (۱۶۰۰×۹۰۰)</option><option value="2400x1350">بزرگ (۲۴۰۰×۱۳۵۰)</option><option value="3600x2000">خیلی بزرگ (۳۶۰۰×۲۰۰۰)</option></select>`,
    foot: `<button class="btn ghost" data-r="0">انصراف</button><button class="btn primary" data-r="1">ساخت و ویرایش</button>`,
    onOpen: (m, close) => {
      $$("[data-r]", m).forEach((b) => (b.onclick = () => {
        if (b.dataset.r !== "1") return close(null);
        const name = $("#nnName", m).value.trim(); if (!name) return toast("نام نقشه را وارد کنید.", "error");
        const [w, h] = $("#nnSize", m).value.split("x").map(Number);
        close({ name, grp: $("#nnGrp", m).value, add: $("#nnAdd", m).checked, w, h });
      }));
    } });
  if (!v) return;
  const data = { w: v.w, h: v.h, nodes: [], links: [], opt: { node: "name", link: "util", grid: true } };
  if (v.add && v.grp) {
    const L = await api("mon_list");
    const ts = ((L.ok && L.targets) || []).filter((t) => (t.grp || "") === v.grp).slice(0, 300);
    const cols = Math.max(1, Math.ceil(Math.sqrt(ts.length * 1.8)));
    ts.forEach((t, i) => data.nodes.push({ id: nmUid("n"), t: "dev", tid: t.id, x: 120 + (i % cols) * Math.min(220, (v.w - 240) / Math.max(1, cols - 1)),
      y: 120 + Math.floor(i / cols) * 160, label: "", icon: "", size: "m" }));
  }
  const r = await api("mon_map_save", { name: v.name, grp: v.grp, data });
  if (!r.ok) return toast(r.error, "error");
  nmOpen(r.id, true);
}

/* ---------------------------------------------------------------- باز کردن نقشه */
async function nmOpen(id, edit = false) {
  nmStop();
  const r = await api("mon_map_get", id);
  if (!NM.el || !NM.el.isConnected) return;
  if (!r.ok) { toast(r.error, "error"); NM.cur = null; return nmListRender(); }
  const keepView = NM.cur && NM.cur.id === r.id && NM.vb;
  NM.cur = { id: r.id, name: r.name, data: r.data, grp: r.data.grp || "" };
  NM.canEdit = r.can_edit;
  NM.devs = new Map(r.devices.map((d) => [d.id, d]));
  NM.maps = new Map(r.maps.map((m) => [m.id, m]));
  NM.edit = !!(edit && r.can_edit); NM.dirty = false; NM.sel = null; NM.tool = "sel"; NM.linkA = null; NM.hist = []; NM.fut = [];
  NM.bg = ""; NM.bgNew = undefined;
  if (!keepView) NM.vb = nmFitBox(r.data);
  if (!NM.list) { const L = await api("mon_map_list"); if (L.ok) { NM.list = L.maps; NM.groups = L.groups; } }
  if (r.data.bg) api("mon_map_bg", r.id).then((b) => { if (b.ok && NM.cur && NM.cur.id === r.id) { NM.bg = b.img; nmDraw(); } });
  nmShell();
  await nmStatus();
}
function nmShell() {
  const el = NM.el, D = NM.cur.data, E = NM.edit;
  const opt = D.opt || { node: "name", link: "util" };
  const others = (NM.list || []).filter((m) => m.id !== NM.cur.id);
  const crumbs = NM.stack.length ? NM.stack.map((s) => `<button class="linkbtn" data-crumb="${s.id}">${esc(s.name)}</button> ← `).join("") : "";
  el.innerHTML = `<div class="nm-wrap ${NM.full ? "nm-full" : ""}" id="nmWrap">
    ${E ? `<div class="toolbar nm-etop"><b class="bidi">${esc("ویرایش نقشه: ")}${esc(NM.cur.name)}</b><span style="flex:1"></span>
        <button class="btn sm" id="nmUndo" title="برگرداندن (Ctrl+Z)">↶</button><button class="btn sm" id="nmRedo" title="انجام دوباره (Ctrl+Y)">↷</button>
        <button class="btn sm" id="nmAuto" title="چیدن خودکار دستگاه‌ها بر اساس لینک‌ها">چیدمان خودکار</button>
        <button class="btn sm" id="nmLldp" title="اگر اسکن LLDP/CDP انجام شده باشد، لینک بین دستگاه‌های همین نقشه پیشنهاد می‌شود (اختیاری)">پیشنهاد لینک از LLDP</button>
        <button class="btn sm" id="nmSet">تنظیمات نقشه</button><button class="btn sm ghost" id="nmCancel">انصراف</button><button class="btn sm primary" id="nmSave">ذخیره</button></div>
      <div class="toolbar nm-tools"><div class="seg" id="nmTool">${[["sel", "⬚ انتخاب و جابه‌جایی"], ["link", "⟋ کشیدن لینک"], ["area", "▭ ناحیه"], ["text", "T متن"]]
        .map(([k, n]) => `<button data-tool="${k}" class="${NM.tool === k ? "on" : ""}">${n}</button>`).join("")}</div>
        <span class="muted" id="nmHint"></span></div>`
    : `<div class="toolbar nm-vtop">${NM.full ? `<b class="bidi nm-ftitle">${esc(NM.cur.name)}</b><span class="nm-fsum" id="nmFsum"></span><span class="ltr muted" id="nmClock"></span>` : `<button class="btn sm ghost" id="nmBack">→ نقشه‌ها</button>`}
        ${crumbs ? `<span class="muted">${crumbs}<b>${esc(NM.cur.name)}</b></span>` : ""}
        <select id="nmPick" style="width:auto;min-width:170px" title="نقشه"><option value="${NM.cur.id}">${esc(NM.cur.name)}</option>${others.map((m) => `<option value="${m.id}">${esc(m.name)}</option>`).join("")}</select>
        <span style="flex:1"></span>
        <input id="nmFind" placeholder="یافتن دستگاه…" style="width:160px" value="${esc(NM.q)}">
        <select id="nmNl" title="برچسب دستگاه" style="width:auto">${Object.entries(NM_NLAB).map(([k, n]) => `<option value="${k}" ${opt.node === k ? "selected" : ""}>${esc("دستگاه: ")}${n}</option>`).join("")}</select>
        <select id="nmLl" title="برچسب لینک" style="width:auto">${Object.entries(NM_LLAB).map(([k, n]) => `<option value="${k}" ${opt.link === k ? "selected" : ""}>${esc("لینک: ")}${n}</option>`).join("")}</select>
        <button class="btn sm ${NM.prob ? "on" : ""}" id="nmProbB" title="بخش‌های سالم کم‌رنگ و فهرست مشکل‌ها نمایش داده می‌شود">فقط مشکل‌ها</button>
        ${NM.full ? `<select id="nmRot" style="width:auto" title="چرخش خودکار بین نقشه‌ها"><option value="0">بدون چرخش</option>${[30, 60, 120, 300].map((s) => `<option value="${s}" ${NM.rot === s ? "selected" : ""}>${esc(`چرخش هر ${num(s)} ثانیه`)}</option>`).join("")}</select>` : ""}
        ${NM.canEdit && !NM.full ? `<button class="btn sm" id="nmEdit">✎ ویرایش</button>` : ""}
        <button class="btn sm" id="nmFullB" title="${NM.full ? "خروج از تمام‌صفحه (Esc)" : "تمام‌صفحه"}">${NM.full ? "✕" : "⛶ تمام‌صفحه"}</button></div>`}
    <div class="nm-main">${E ? `<div class="nm-pal" id="nmPal"></div>` : ""}
      <div class="nm-stage" id="nmStage"><svg id="nmSvg" class="nm-svg ${E ? "edit" : ""}" xmlns="http://www.w3.org/2000/svg"></svg>
        <div class="nm-zoom"><button class="btn sm" data-z="in" title="بزرگ‌نمایی">+</button><button class="btn sm" data-z="out" title="کوچک‌نمایی">−</button><button class="btn sm" data-z="fit" title="کل نقشه">⤢</button></div>
        ${E ? "" : nmLegend()}<div class="nm-tip" id="nmTip" hidden></div><div class="nm-probs" id="nmProbs" hidden></div></div>
      ${E ? `<div class="nm-prop" id="nmProp"></div>` : ""}</div></div>`;
  nmBindShell();
  nmDraw();
  if (E) { nmPalette(); nmProps(); nmHint(); }
}
function nmLegend() {
  const sw = (bg, t) => `<div><i style="background:${bg}"></i><span>${t}</span></div>`;
  return `<details class="nm-legend" open><summary>راهنما</summary>${sw("#2e9e5b", "کمتر از ۵۰٪")}${sw("#d9a520", "۵۰ تا ۷۵٪")}${sw("#e0702e", "۷۵ تا ۹۰٪")}${sw("#c63e33", "بیش از ۹۰٪")}
    ${sw("repeating-linear-gradient(90deg,var(--err) 0 6px,transparent 6px 9px)", "لینک یا دستگاه قطع")}${sw("repeating-linear-gradient(90deg,#a77bdb 0 3px,transparent 3px 6px)", "نامعلوم یا بالادستی قطع")}
    ${sw("var(--faint)", "ترافیک نامعلوم")}${sw("repeating-linear-gradient(90deg,var(--muted) 0 8px,transparent 8px 11px)", "VPN یا بی‌سیم")}</details>`;
}
function nmBindShell() {
  const el = NM.el;
  const on = (id, f) => { const x = $(id, el); if (x) x.onclick = f; };
  on("#nmBack", async () => { if (await nmCanLeave()) { NM.cur = null; NM.stack = []; nmListRender(); } });
  $$("[data-crumb]", el).forEach((b) => (b.onclick = () => { const i = NM.stack.findIndex((s) => String(s.id) === b.dataset.crumb); NM.stack = NM.stack.slice(0, i); nmOpen(Number(b.dataset.crumb)); }));
  if ($("#nmPick", el)) $("#nmPick", el).onchange = (e) => { NM.stack = []; NM.vb = null; nmOpen(Number(e.target.value)); };
  let tq = 0; if ($("#nmFind", el)) $("#nmFind", el).oninput = (e) => { NM.q = e.target.value; clearTimeout(tq); tq = setTimeout(nmDraw, 150); };
  if ($("#nmNl", el)) $("#nmNl", el).onchange = (e) => { NM.cur.data.opt.node = e.target.value; nmDraw(); nmSaveOpt(); };
  if ($("#nmLl", el)) $("#nmLl", el).onchange = (e) => { NM.cur.data.opt.link = e.target.value; nmDraw(); nmSaveOpt(); };
  on("#nmProbB", (e) => { NM.prob = !NM.prob; e.currentTarget.classList.toggle("on", NM.prob); nmDraw(); nmProbList(); });
  on("#nmEdit", () => nmOpen(NM.cur.id, true));
  on("#nmFullB", () => (NM.full ? nmFullOff(true) : nmFullOn(0)));
  if ($("#nmRot", el)) $("#nmRot", el).onchange = (e) => nmFullOn(Number(e.target.value));
  $$("[data-z]", el).forEach((b) => (b.onclick = () => nmZoom(b.dataset.z)));
  if (NM.edit) {
    on("#nmUndo", nmUndo); on("#nmRedo", nmRedo); on("#nmAuto", nmAutoLayout); on("#nmLldp", nmLldp); on("#nmSet", nmSettings);
    on("#nmSave", nmSave);
    on("#nmCancel", async () => { if (await nmCanLeave()) { NM.edit = false; nmOpen(NM.cur.id); } });
    $$("#nmTool [data-tool]", el).forEach((b) => (b.onclick = () => nmSetTool(b.dataset.tool)));
  }
  nmBindSvg();
}
/** انتخاب برچسب در حالت نمایش: برای کسی که اجازه‌ی ویرایش دارد در خود نقشه ذخیره می‌شود؛ بقیه فقط همین مرورگر */
let _nmOptT = 0;
function nmSaveOpt() {
  if (!NM.canEdit) return;
  clearTimeout(_nmOptT);
  _nmOptT = setTimeout(async () => {
    const r = await api("mon_map_get", NM.cur.id); if (!r.ok) return;
    const d = r.data; d.opt = { ...(d.opt || {}), node: NM.cur.data.opt.node, link: NM.cur.data.opt.link }; delete d.bg;
    await api("mon_map_save", { id: NM.cur.id, name: r.name, grp: d.grp || "", data: d });
  }, 800);
}

/* ---------------------------------------------------------------- وضعیت زنده */
async function nmStatus() {
  clearTimeout(NM.timer);
  if (!NM.cur) return;
  const id = NM.cur.id;
  const r = await api("mon_map_status", id);
  if (!NM.cur || NM.cur.id !== id || !NM.el.isConnected) return;
  if (r.ok) { NM.st = r; if (!NM.drag) nmDraw(); nmProbList(); nmFsum(); }
  NM.timer = setTimeout(() => { if (nmAlive() && NM.cur && NM.cur.id === id) nmStatus(); }, 15000);
}
function nmNS(n) { return (NM.st && NM.st.nodes[n.id]) || { st: n.t === "dev" || n.t === "map" ? "unknown" : "x" }; }
function nmLS(l) { return (NM.st && NM.st.links[l.id]) || { st: "unk" }; }
function nmNodeName(n) {
  if (n.label) return n.label;
  if (n.t === "dev") { const d = NM.devs.get(n.tid); return (d && d.name) || nmNS(n).name || "?"; }
  if (n.t === "map") { const m = NM.maps.get(n.map); return m ? m.name : "?"; }
  if (n.t === "cloud") return I18N.t("اینترنت");
  return "";
}
function nmNodeIcon(n) {
  if (n.t === "cloud") return n.icon || "internet";
  if (n.icon) return n.icon;
  if (n.t === "dev") { const d = NM.devs.get(n.tid); const ic = d && d.icon; return ic && MON_ICON_SVG[ic] ? ic : "other"; }
  return "other";
}
function nmProblems() {
  const D = NM.cur.data, out = [];
  for (const n of D.nodes) {
    const s = nmNS(n);
    if (n.t === "dev" && ["down", "unreachable", "warn"].includes(s.st)) out.push({ k: "n", id: n.id, cls: NM_NCLS[s.st], txt: nmNodeName(n), why: NM_STN[s.st], since: s.st === "down" ? s.since : null });
    if (n.t === "map" && (s.st === "down" || s.st === "warn")) out.push({ k: "n", id: n.id, cls: NM_NCLS[s.st], txt: nmNodeName(n), why: s.counts ? `${num(s.counts.down)} قطع · ${num(s.counts.warn)} هشدار` : NM_STN[s.st] });
  }
  const nn = new Map(D.nodes.map((n) => [n.id, n]));
  for (const l of D.links) {
    const s = nmLS(l);
    const nm = `${nmNodeName(nn.get(l.a))} ⇄ ${nmNodeName(nn.get(l.b))}`;
    if (s.st === "down") out.push({ k: "l", id: l.id, cls: "err", txt: nm, why: NM_LSTN.down, since: s.since });
    else if (s.st === "up" && s.util >= 75) out.push({ k: "l", id: l.id, cls: "warn", txt: nm, why: `${num(Math.round(s.util))}٪` });
  }
  return out;
}
function nmProbList() {
  const box = $("#nmProbs", NM.el); if (!box) return;
  if (!NM.prob || NM.edit) { box.hidden = true; return; }
  const P = nmProblems(), now = (NM.st && NM.st.now) || Date.now() / 1000;
  box.hidden = false;
  box.innerHTML = `<b>${esc(P.length ? `${num(P.length)} مشکل در این نقشه` : "مشکلی در این نقشه نیست")}</b>${P.map((p, i) => `<button class="nm-pi" data-pi="${i}"><i class="dot ${p.cls}"></i><span>${p.txt.split(" ⇄ ").map(nmN).join(" ⇄ ")}</span><span class="muted">— ${esc(p.why)}${p.since && now - p.since > 5 ? ` (${nmDur(now - p.since)})` : ""}</span></button>`).join("")}
    ${P.length ? `<div class="muted">کلیک = بزرگ‌نمایی روی همان مورد</div>` : ""}`;
  $$("[data-pi]", box).forEach((b) => (b.onclick = () => {
    const p = P[Number(b.dataset.pi)], D = NM.cur.data, nn = new Map(D.nodes.map((n) => [n.id, n]));
    let x, y;
    if (p.k === "n") ({ x, y } = nn.get(p.id)); else { const l = D.links.find((q) => q.id === p.id); const A = nn.get(l.a), B = nn.get(l.b); x = (A.x + B.x) / 2; y = (A.y + B.y) / 2; }
    const w = Math.min(D.w, 700), h = w * D.h / D.w; NM.vb = { x: x - w / 2, y: y - h / 2, w, h }; nmDraw();
  }));
}
function nmFsum() {
  const b = $("#nmFsum", NM.el); if (!b) return;
  let d = 0, w = 0;
  for (const n of NM.cur.data.nodes) { const s = nmNS(n).st; if (n.t === "dev") { if (s === "down") d++; else if (s === "warn") w++; } }
  const ld = Object.values((NM.st && NM.st.links) || {}).filter((s) => s.st === "down").length;
  b.innerHTML = `${d ? `<span class="tag err">${esc(`${num(d)} دستگاه قطع`)}</span>` : ""}${ld ? `<span class="tag err">${esc(`${num(ld)} لینک قطع`)}</span>` : ""}${w ? `<span class="tag warn">${esc(`${num(w)} هشدار`)}</span>` : ""}${!d && !ld && !w ? `<span class="tag ok">همه وصل</span>` : ""}`;
}

/* ---------------------------------------------------------------- رسم */
function nmLinkGeom(D) {
  const nn = new Map(D.nodes.map((n) => [n.id, n])), grp = new Map(), out = [];
  for (const l of D.links) { const k = [l.a, l.b].sort().join("|"); if (!grp.has(k)) grp.set(k, []); grp.get(k).push(l); }
  for (const ls of grp.values()) {
    ls.forEach((l, i) => {
      const A = nn.get(l.a), B = nn.get(l.b); if (!A || !B) return;
      const dx = B.x - A.x, dy = B.y - A.y, d = Math.hypot(dx, dy) || 1, s = l.a < l.b ? 1 : -1;
      const off = (i - (ls.length - 1) / 2) * 9 * s, ox = (-dy / d) * off, oy = (dx / d) * off;
      out.push({ l, A, B, x1: A.x + ox, y1: A.y + oy, x2: B.x + ox, y2: B.y + oy, d });
    });
  }
  return out;
}
function nmDraw() {
  const svg = $("#nmSvg", NM.el); if (!svg || !NM.cur) return;
  const D = NM.cur.data, E = NM.edit, opt = D.opt || {};
  const vb = NM.vb || { x: 0, y: 0, w: D.w, h: D.h };
  svg.setAttribute("viewBox", `${vb.x} ${vb.y} ${vb.w} ${vb.h}`);
  const q = NM.q.trim().toLowerCase();
  const hit = q ? new Set(D.nodes.filter((n) => { const d = n.t === "dev" ? NM.devs.get(n.tid) : null; return (nmNodeName(n) + " " + (d ? d.host : n.host || "")).toLowerCase().includes(q); }).map((n) => n.id)) : null;
  const bad = NM.prob ? new Set() : null;
  if (bad) {
    for (const p of nmProblems()) { if (p.k === "n") bad.add(p.id); else { const l = D.links.find((x) => x.id === p.id); bad.add(l.id); bad.add(l.a); bad.add(l.b); } }
  }
  const dimN = (n) => (hit && !hit.has(n.id)) || (bad && !bad.has(n.id));
  let s = `<rect x="0" y="0" width="${D.w}" height="${D.h}" class="nm-page"/>`;
  if (NM.bgNew !== undefined ? NM.bgNew : NM.bg) s += `<image href="${esc(NM.bgNew !== undefined ? NM.bgNew : NM.bg)}" x="0" y="0" width="${D.w}" height="${D.h}" preserveAspectRatio="xMidYMid meet" class="nm-bgimg"/>`;
  if (E && opt.grid !== false) s += `<defs><pattern id="nmGrid" width="20" height="20" patternUnits="userSpaceOnUse"><circle cx="1" cy="1" r="1.1" class="nm-gd"/></pattern></defs><rect width="${D.w}" height="${D.h}" fill="url(#nmGrid)"/>`;
  // ناحیه‌ها
  for (const n of D.nodes.filter((x) => x.t === "area")) {
    const c = NM_AREA_C[n.color] || NM_AREA_C.blue, sel = E && NM.sel === n.id;
    s += `<g data-n="${n.id}" class="nm-area${sel ? " sel" : ""}"><rect x="${n.x}" y="${n.y}" width="${n.w}" height="${n.h}" rx="14" style="fill:${c};fill-opacity:.06;stroke:${c};stroke-opacity:.45" stroke-dasharray="7 5" stroke-width="${sel ? 2.5 : 1.5}"/>
      ${n.label ? `<text x="${n.x + n.w - 12}" y="${n.y + 22}" class="nm-alab" style="fill:${c}" text-anchor="start">${esc(n.label)}</text>` : ""}
      ${sel ? `<rect data-h="${n.id}" x="${n.x - 7}" y="${n.y + n.h - 7}" width="14" height="14" rx="3" class="nm-handle"/>` : ""}</g>`;
  }
  // لینک‌ها
  for (const g of nmLinkGeom(D)) {
    const { l, x1, y1, x2, y2, d } = g, st = nmLS(l);
    let col = "", cls = "nm-l", dash = "", w = 4;
    if (st.st === "down" || st.st === "dev") { cls += " err"; dash = st.st === "dev" ? "8 6" : ""; }
    else if (st.st === "unk") { cls += " unr"; dash = "3 5"; w = 3; }
    else if (st.st === "off") { cls += " mute"; dash = "2 5"; w = 3; }
    else if (st.util != null) col = NM_UC(st.util);
    else cls += " nodata";
    if (l.kind === "vpn" && !dash) dash = "10 6";
    if (l.kind === "wifi" && !dash) dash = "2 6";
    if (l.kind === "fiber") w += 1;
    if (l.kind === "none") w = 2.5;
    if (bad && st.st === "up" && !(st.util >= 75)) cls += " nm-dim";
    else if ((hit && !(hit.has(l.a) || hit.has(l.b)))) cls += " nm-dim";
    const sel = E && NM.sel === l.id;
    s += `<g data-l="${l.id}" class="nm-lg${sel ? " sel" : ""}"><line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" class="nm-lhit"/>
      ${sel ? `<line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" class="nm-lsel"/>` : ""}
      <line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" class="${cls}" stroke-width="${w}" ${dash ? `stroke-dasharray="${dash}"` : ""} ${col ? `style="stroke:${col}"` : ""}/>`;
    const mx = (x1 + x2) / 2, my = (y1 + y2) / 2;
    if (st.st === "down") s += `<circle cx="${mx}" cy="${my}" r="10" class="nm-x"/><path d="M${mx - 4},${my - 4}l8,8m0,-8l-8,8" class="nm-xm"/>`;
    else if (!(bad && cls.includes("nm-dim")) && d > 90) {
      if (opt.link === "util" && st.util != null && st.st === "up") {
        s += `<rect x="${mx - 20}" y="${my - 10}" width="40" height="20" rx="10" class="nm-pill" style="stroke:${col}"/><text x="${mx}" y="${my + 4.5}" class="nm-pt" style="fill:${col}" text-anchor="middle">${num(Math.round(st.util))}٪</text>`;
      } else if (opt.link === "bps" && st.in_bps != null && st.st === "up") {
        s += `<text x="${mx}" y="${my - 7}" class="nm-bps ltr" text-anchor="middle">↓${esc(nmBps(st.in_bps))} ↑${esc(nmBps(st.out_bps))}</text>`;
      }
    }
    if ((opt.link === "ports" || E) && d > 110) {
      const lab = (P, Q, t) => { if (!t) return ""; const dx = Q.x - P.x, dy = Q.y - P.y, k = Math.min(0.42, 52 / d); return `<text x="${P.x + dx * k + (dy / d) * 10}" y="${P.y + dy * k - (dx / d) * 10 + 4}" class="nm-port ltr" text-anchor="middle">${esc(t)}</text>`; };
      s += lab({ x: x1, y: y1 }, { x: x2, y: y2 }, l.pa) + lab({ x: x2, y: y2 }, { x: x1, y: y1 }, l.pb);
    }
    s += `</g>`;
  }
  // گره‌ها
  for (const n of D.nodes.filter((x) => x.t !== "area")) {
    const sel = E && NM.sel === n.id, a = E && NM.linkA === n.id;
    if (n.t === "text") {
      s += `<g data-n="${n.id}" class="nm-node${dimN(n) ? " nm-dim" : ""}${sel ? " sel" : ""}"><text x="${n.x}" y="${n.y}" class="nm-text" style="font-size:${NM_TSZ[n.size] || 17}px" text-anchor="middle" dominant-baseline="middle">${esc(n.label)}</text>
        ${sel ? `<rect x="${n.x - 40}" y="${n.y - 16}" width="80" height="32" class="nm-selbox"/>` : ""}</g>`;
      continue;
    }
    const st = nmNS(n), z = NM_SZ[n.size] || 44, h = z / 2;
    const cls = n.t === "dev" || n.t === "map" ? NM_NCLS[st.st] || "mute" : "ext";
    const ic = n.t === "map" ? NM_MAPIC : nmNodeIcon(n) === "core" ? NM_CORE : MON_ICON_SVG[nmNodeIcon(n)] || MON_ICON_SVG.other;
    const name = nmNodeName(n), ltr = /^[\x20-\x7e]+$/.test(name);
    let sub = "";
    if (n.t === "map" && st.counts) sub = `${num(st.counts.up + st.counts.down + st.counts.warn + st.counts.unk)} دستگاه${st.counts.down ? ` · ${num(st.counts.down)} قطع` : st.counts.warn ? ` · ${num(st.counts.warn)} هشدار` : ""}`;
    else if (opt.node === "ip") { const d = n.t === "dev" ? NM.devs.get(n.tid) : null; sub = d ? d.host : n.host || ""; }
    else if (opt.node === "load" && n.t === "dev") sub = st.cpu != null ? `CPU ${Math.round(st.cpu)}% · RAM ${st.mem != null ? Math.round(st.mem) : "—"}%` : st.rtt != null ? `${st.rtt} ms` : "";
    s += `<g data-n="${n.id}" class="nm-node ${cls}${dimN(n) ? " nm-dim" : ""}${sel ? " sel" : ""}${a ? " la" : ""}">
      ${st.st === "down" ? `<circle cx="${n.x}" cy="${n.y}" r="${h + 13}" class="nm-halo"/>` : ""}
      ${sel || a ? `<rect x="${n.x - h - 7}" y="${n.y - h - 7}" width="${z + 14}" height="${z + 14}" rx="10" class="nm-selbox"/>` : ""}
      <rect x="${n.x - h}" y="${n.y - h}" width="${z}" height="${z}" rx="${n.t === "cloud" ? h : 9}" class="nm-nb"/>
      <svg x="${n.x - h * 0.72}" y="${n.y - h * 0.72}" width="${z * 0.72}" height="${z * 0.72}" viewBox="0 0 24 24" class="nm-ic" fill="none" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">${ic}</svg>
      ${n.t === "dev" && st.st === "warn" ? `<circle cx="${n.x + h}" cy="${n.y - h}" r="8" class="nm-wb"/><text x="${n.x + h}" y="${n.y - h + 4}" class="nm-wbt" text-anchor="middle">!</text>` : ""}
      ${opt.node !== "none" || E || n.t === "map" ? `<text x="${n.x}" y="${n.y + h + 16}" class="nm-name${ltr ? " ltr" : ""}" text-anchor="middle">${esc(name)}</text>` : ""}
      ${sub && (opt.node !== "none" || n.t === "map") ? `<text x="${n.x}" y="${n.y + h + 31}" class="nm-sub${/^[\x20-\x7e]+$/.test(sub) ? " ltr" : ""}" text-anchor="middle">${esc(sub)}</text>` : ""}</g>`;
  }
  svg.innerHTML = s;
}

/* ---------------------------------------------------------------- بزرگ‌نمایی، جابه‌جایی صفحه، راهنما */
function nmPt(e) {
  const svg = $("#nmSvg", NM.el), p = svg.createSVGPoint(); p.x = e.clientX; p.y = e.clientY;
  const m = svg.getScreenCTM(); return m ? p.matrixTransform(m.inverse()) : { x: 0, y: 0 };
}
/** کادر محتوای نقشه (نه کل صفحه) تا گره‌ها و نوشته‌ها بزرگ‌تر دیده شوند؛ نقشه‌ی خالی = کل صفحه */
function nmFitBox(D) {
  let x0 = Infinity, y0 = Infinity, x1 = -Infinity, y1 = -Infinity;
  for (const n of D.nodes || []) {
    if (n.t === "area") { x0 = Math.min(x0, n.x); y0 = Math.min(y0, n.y); x1 = Math.max(x1, n.x + n.w); y1 = Math.max(y1, n.y + n.h); continue; }
    const h = n.t === "text" ? 60 : (NM_SZ[n.size] || 44) / 2 + 12;
    x0 = Math.min(x0, n.x - h - 30); x1 = Math.max(x1, n.x + h + 30); y0 = Math.min(y0, n.y - h); y1 = Math.max(y1, n.y + h + 40);
  }
  if (!isFinite(x0)) return { x: 0, y: 0, w: D.w, h: D.h };
  const m = 30, w = Math.max(400, x1 - x0 + 2 * m), h = Math.max(260, y1 - y0 + 2 * m);
  return { x: (x0 + x1) / 2 - w / 2, y: (y0 + y1) / 2 - h / 2, w, h };
}
function nmZoom(how, at) {
  const D = NM.cur.data, vb = NM.vb || { x: 0, y: 0, w: D.w, h: D.h };
  if (how === "fit") { NM.vb = nmFitBox(D); return nmDraw(); }
  const f = how === "in" ? 1.25 : how === "out" ? 0.8 : how;
  const w = Math.max(D.w / 10, Math.min(D.w * 2.5, vb.w / f)), k = w / vb.w;
  const c = at || { x: vb.x + vb.w / 2, y: vb.y + vb.h / 2 };
  NM.vb = { x: c.x - (c.x - vb.x) * k, y: c.y - (c.y - vb.y) * k, w, h: vb.h * k };
  nmDraw();
}
function nmTip(e, html) {
  const t = $("#nmTip", NM.el); if (!t) return;
  if (!html) { t.hidden = true; return; }
  t.innerHTML = html; t.hidden = false;
  const st = $("#nmStage", NM.el).getBoundingClientRect();
  let x = e.clientX - st.left + 16, y = e.clientY - st.top + 16;
  if (x + 280 > st.width) x = e.clientX - st.left - 290;
  if (y + t.offsetHeight > st.height) y = Math.max(4, st.height - t.offsetHeight - 6);
  t.style.left = `${Math.max(4, x)}px`; t.style.top = `${y}px`;
}
function nmNodeTip(n) {
  const s = nmNS(n), now = (NM.st && NM.st.now) || Date.now() / 1000;
  if (n.t === "map") return `<b>${esc(nmNodeName(n))}</b><div class="muted">${esc("زیرنقشه — کلیک برای باز کردن")}</div>${s.counts ? `<div>${esc(`${num(s.counts.up)} وصل · ${num(s.counts.down)} قطع · ${num(s.counts.warn)} هشدار`)}</div>` : ""}`;
  if (n.t !== "dev") return `<b>${esc(nmNodeName(n))}</b>${n.host ? `<div class="ltr">${esc(n.host)}</div>` : ""}<div class="muted">${esc(n.t === "box" ? "دستگاه بدون مانیتور" : "شیء نقشه")}</div>`;
  const d = NM.devs.get(n.tid) || {};
  if (s.st === "hidden") return `<b>${esc(nmNodeName(n))}</b><div class="muted">${esc("دسترسی دیدن این دستگاه را ندارید.")}</div>`;
  if (s.st === "gone") return `<b>${esc(nmNodeName(n))}</b><div class="muted">${esc("این دستگاه از مانیتورینگ حذف شده است.")}</div>`;
  return `<b>${nmN(nmNodeName(n))}</b><div class="ltr muted">${esc(d.host || s.host || "")}</div>
    <div class="nm-tst ${NM_NCLS[s.st] || "mute"}">● ${esc(NM_STN[s.st] || s.st)}${s.since && ["down", "unreachable"].includes(s.st) ? ` — ${esc(nmDur(now - s.since))}` : ""}</div>
    ${s.cause ? `<div class="muted">${esc(s.cause)}</div>` : ""}
    ${s.cpu != null ? `<div class="kv"><span>CPU</span><span>${num(Math.round(s.cpu))}٪</span></div>` : ""}${s.mem != null ? `<div class="kv"><span>حافظه</span><span>${num(Math.round(s.mem))}٪</span></div>` : ""}
    ${s.rtt != null ? `<div class="kv"><span>تأخیر</span><span class="ltr">${esc(String(s.rtt))} ms</span></div>` : ""}
    ${(s.alarms || []).map((a) => `<div class="warn">⚠ ${esc(a)}</div>`).join("")}
    <div class="muted nm-th">${esc(NM.edit ? "کشیدن = جابه‌جایی" : "کلیک: جزئیات دستگاه")}</div>`;
}
function nmLinkTip(l) {
  const D = NM.cur.data, nn = new Map(D.nodes.map((n) => [n.id, n])), s = nmLS(l), now = (NM.st && NM.st.now) || Date.now() / 1000;
  const A = nmNodeName(nn.get(l.a)), B = nmNodeName(nn.get(l.b));
  const cls = { up: "ok", down: "err", dev: "err", unk: "unr", off: "mute" }[s.st] || "mute";
  return `<b>${nmN(A)} ⇄ ${nmN(B)}</b>
    <div class="nm-tst ${cls}">● ${esc(NM_LSTN[s.st] || s.st)}${s.since && now - s.since > 5 ? ` — ${esc(`از ${nmDur(now - s.since)} پیش`)}` : ""}</div>
    ${l.pa || l.pb ? `<div class="kv"><span>پورت</span><span class="ltr">${esc(l.pa || "—")} ⇄ ${esc(l.pb || "—")}</span></div>` : ""}
    <div class="kv"><span>نوع</span><span>${esc(NM_KIND[l.kind] || l.kind)}</span></div>
    ${s.speed ? `<div class="kv"><span>سرعت</span><span class="ltr">${esc(nmBps(s.speed))}</span></div>` : ""}
    ${s.util != null ? `<div class="kv"><span>بار</span><span>${num(Math.round(s.util))}٪</span></div><div class="kv"><span>In / Out</span><span class="ltr">${esc(nmBps(s.in_bps))} / ${esc(nmBps(s.out_bps))}</span></div>` : ""}
    ${s.st === "up" && s.util == null && (l.pa || l.pb) && l.kind !== "none" ? `<div class="muted">${esc("ترافیک هنوز خوانده نشده یا پورت در دستگاه پیدا نشد.")}</div>` : ""}
    ${!NM.edit && (s.pn || []).some(Boolean) ? `<div class="muted nm-th">${esc("کلیک: نمودار پورت")}</div>` : ""}`;
}
function nmBindSvg() {
  const svg = $("#nmSvg", NM.el); if (!svg) return;
  svg.onwheel = (e) => { e.preventDefault(); nmZoom(e.deltaY < 0 ? 1.15 : 1 / 1.15, nmPt(e)); };
  svg.onmouseleave = () => nmTip(null, "");
  svg.onmousemove = (e) => {
    if (NM.drag) return nmDragMove(e);
    const g = e.target.closest("[data-n],[data-l]");
    if (!g) return nmTip(e, "");
    if (g.dataset.n) { const n = NM.cur.data.nodes.find((x) => x.id === g.dataset.n); if (n && n.t !== "area" && n.t !== "text") return nmTip(e, nmNodeTip(n)); return nmTip(e, ""); }
    const l = NM.cur.data.links.find((x) => x.id === g.dataset.l); if (l) nmTip(e, nmLinkTip(l));
  };
  svg.onmousedown = (e) => {
    if (e.button !== 0) return;
    const p = nmPt(e), h = e.target.closest("[data-h]"), g = e.target.closest("[data-n],[data-l]");
    if (NM.edit) {
      if (h) { nmPush(); NM.drag = { k: "rs", id: h.dataset.h, p0: p, moved: false }; return e.preventDefault(); }
      if (NM.tool === "area" && !g) { nmAddNode({ t: "area", x: nmSnap(p.x), y: nmSnap(p.y), w: 300, h: 200, label: "", color: "blue" }); nmSetTool("sel"); return; }
      if (NM.tool === "text" && !g) { nmAddNode({ t: "text", x: nmSnap(p.x), y: nmSnap(p.y), label: I18N.t("متن"), size: "m" }); nmSetTool("sel"); setTimeout(() => { const i = $("#npLabel", NM.el); if (i) { i.focus(); i.select(); } }, 30); return; }
      if (NM.tool === "link") {
        const n = g && g.dataset.n ? NM.cur.data.nodes.find((x) => x.id === g.dataset.n) : null;
        if (!n || ["area", "text"].includes(n.t)) { NM.linkA = null; nmHint(); return nmDraw(); }
        if (!NM.linkA) { NM.linkA = n.id; nmHint(); return nmDraw(); }
        if (NM.linkA === n.id) return;
        const a = NM.linkA; NM.linkA = null; nmHint(); nmDraw();
        return nmLinkDialog({ a, b: n.id });
      }
      if (g && g.dataset.n) {
        const n = NM.cur.data.nodes.find((x) => x.id === g.dataset.n);
        NM.sel = n.id; nmProps(); nmDraw();
        NM.drag = { k: "node", id: n.id, dx: p.x - n.x, dy: p.y - n.y, moved: false, pushed: false };
        return e.preventDefault();
      }
      if (g && g.dataset.l) { NM.sel = g.dataset.l; nmProps(); nmDraw(); return; }
      if (NM.sel) { NM.sel = null; nmProps(); nmDraw(); }
    } else if (g) return;
    NM.drag = { k: "pan", c0: { x: e.clientX, y: e.clientY }, vb0: { ...(NM.vb || { x: 0, y: 0, w: NM.cur.data.w, h: NM.cur.data.h }) }, moved: false };
    e.preventDefault();
  };
  svg.onclick = (e) => {
    if (NM.edit || (NM.dragEnd && Date.now() - NM.dragEnd < 200)) return;
    const g = e.target.closest("[data-n],[data-l]"); if (!g) return;
    if (g.dataset.n) {
      const n = NM.cur.data.nodes.find((x) => x.id === g.dataset.n); if (!n) return;
      if (n.t === "dev") { const s = nmNS(n); if (["hidden", "gone"].includes(s.st)) return; nmTip(null, ""); return nmOpenDev(n.tid); }
      if (n.t === "map" && NM.maps.has(n.map)) { NM.stack.push({ id: NM.cur.id, name: NM.cur.name }); NM.vb = null; return nmOpen(n.map); }
      return;
    }
    const l = NM.cur.data.links.find((x) => x.id === g.dataset.l); if (!l) return;
    const s = nmLS(l), nn = new Map(NM.cur.data.nodes.map((n) => [n.id, n]));
    for (const [i, end] of [[0, l.a], [1, l.b]]) {
      const n = nn.get(end);
      if (n && n.t === "dev" && s.pn && s.pn[i]) { nmTip(null, ""); return nmOpenDev(n.tid, s.pn[i]); }
    }
  };
  svg.ondragover = (e) => { if (NM.edit) e.preventDefault(); };
  svg.ondrop = (e) => {
    if (!NM.edit) return; e.preventDefault();
    const v = e.dataTransfer.getData("text/plain"); if (!v) return;
    nmPaletteAdd(v, nmPt(e));
  };
}
const _nmUp = () => {
  if (!NM.drag) return;
  const d = NM.drag; NM.drag = null;
  if (d.moved) NM.dragEnd = Date.now();
  if (d.k !== "pan" && d.moved) { NM.dirty = true; nmProps(); }
  nmDraw();
};
window.addEventListener("mouseup", _nmUp);
function nmDragMove(e) {
  const d = NM.drag;
  if (d.k === "pan") {
    const svg = $("#nmSvg", NM.el), r = svg.getBoundingClientRect(), k = Math.max(d.vb0.w / r.width, d.vb0.h / r.height);
    const dx = (e.clientX - d.c0.x) * k, dy = (e.clientY - d.c0.y) * k;
    if (Math.abs(dx) + Math.abs(dy) > 2) d.moved = true;
    NM.vb = { ...d.vb0, x: d.vb0.x - dx, y: d.vb0.y - dy };
  } else {
    const p = nmPt(e), D = NM.cur.data, n = D.nodes.find((x) => x.id === d.id); if (!n) return;
    if (!d.pushed && d.k === "node") { nmPush(); d.pushed = true; }
    d.moved = true;
    if (d.k === "node") { n.x = Math.max(0, Math.min(D.w, nmSnap(p.x - d.dx))); n.y = Math.max(0, Math.min(D.h, nmSnap(p.y - d.dy))); }
    else { n.w = Math.max(60, nmSnap(p.x - n.x)); n.h = Math.max(40, nmSnap(p.y - n.y)); }
  }
  if (!NM._raf) NM._raf = requestAnimationFrame(() => { NM._raf = 0; nmDraw(); });
}
function nmSnap(v) { return NM.cur.data.opt && NM.cur.data.opt.grid === false ? Math.round(v) : Math.round(v / 20) * 20; }
async function nmOpenDev(tid, port) {
  if (!MON.targets || !MON.targets.find((t) => t.id === tid)) { const L = await api("mon_list"); if (L.ok) MON.targets = L.targets; }
  const t = MON.targets.find((x) => x.id === tid); if (!t) return toast("دستگاه پیدا نشد.", "error");
  if (t.kind === "snmp") return snmpDetail(t, port ? { port } : {});
  return monDetail(tid);
}

/* ---------------------------------------------------------------- تمام‌صفحه و چرخش */
function nmFullOn(rot) {
  NM.full = true; NM.rot = rot || 0;
  document.body.classList.add("nm-full-on");
  clearInterval(NM.rotTimer); NM.rotTimer = 0;
  if (NM.rot && (NM.list || []).length > 1) {
    NM.rotTimer = setInterval(() => {
      if (!NM.full || !NM.cur) return;
      const L = NM.list, i = L.findIndex((m) => m.id === NM.cur.id), nx = L[(i + 1) % L.length];
      NM.vb = null; NM.stack = []; nmOpen(nx.id);
    }, NM.rot * 1000);
  }
  try { if (!document.fullscreenElement && document.documentElement.requestFullscreen) document.documentElement.requestFullscreen().catch(() => {}); } catch (_) { /* پنجره‌ی برنامه */ }
  nmShell(); nmStatus(); nmClock();
}
function nmFullOff(redraw) {
  if (!NM.full) return;
  NM.full = false; NM.rot = 0; clearInterval(NM.rotTimer); NM.rotTimer = 0;
  document.body.classList.remove("nm-full-on");
  try { if (document.fullscreenElement) document.exitFullscreen().catch(() => {}); } catch (_) { /* */ }
  if (redraw && NM.cur) { nmShell(); nmStatus(); }
}
function nmClock() {
  const c = $("#nmClock", NM.el); if (!c || !NM.full) return;
  c.textContent = new Date().toTimeString().slice(0, 5);
  setTimeout(nmClock, 15000);
}
document.addEventListener("keydown", (e) => {
  if (!NM.el || !NM.el.isConnected || !NM.cur) return;
  if (e.key === "Escape" && NM.full && !$("#modal").innerHTML) { nmFullOff(true); return; }
  if (!NM.edit || $("#modal").innerHTML) return;
  const inInput = e.target && /^(INPUT|TEXTAREA|SELECT)$/.test(e.target.tagName);
  if ((e.ctrlKey || e.metaKey) && !inInput && (e.key === "z" || e.key === "Z")) { e.preventDefault(); return e.shiftKey ? nmRedo() : nmUndo(); }
  if ((e.ctrlKey || e.metaKey) && !inInput && (e.key === "y" || e.key === "Y")) { e.preventDefault(); return nmRedo(); }
  if (inInput) return;
  if ((e.key === "Delete" || e.key === "Backspace") && NM.sel) { e.preventDefault(); nmDelSel(); }
  if (e.key === "Escape" && (NM.linkA || NM.tool !== "sel")) { NM.linkA = null; nmSetTool("sel"); }
});

/* ---------------------------------------------------------------- ویرایش: تاریخچه، افزودن، حذف */
function nmPush() { NM.hist.push(JSON.stringify(NM.cur.data)); if (NM.hist.length > 60) NM.hist.shift(); NM.fut = []; NM.dirty = true; }
function nmUndo() { if (!NM.hist.length) return; NM.fut.push(JSON.stringify(NM.cur.data)); NM.cur.data = JSON.parse(NM.hist.pop()); nmAfterChange(); }
function nmRedo() { if (!NM.fut.length) return; NM.hist.push(JSON.stringify(NM.cur.data)); NM.cur.data = JSON.parse(NM.fut.pop()); nmAfterChange(); }
function nmAfterChange() {
  if (NM.sel && !NM.cur.data.nodes.some((n) => n.id === NM.sel) && !NM.cur.data.links.some((l) => l.id === NM.sel)) NM.sel = null;
  NM.dirty = true; nmDraw(); nmProps(); nmPalette();
}
function nmAddNode(o) {
  nmPush();
  const n = { id: nmUid("n"), label: "", ...o };
  if (["dev", "box", "cloud", "map"].includes(n.t)) { n.icon = n.icon || ""; n.size = n.size || "m"; }
  NM.cur.data.nodes.push(n); NM.sel = n.id;
  nmDraw(); nmProps(); nmPalette();
  return n;
}
function nmDelSel() {
  const D = NM.cur.data, id = NM.sel; if (!id) return;
  nmPush();
  if (D.links.some((l) => l.id === id)) D.links = D.links.filter((l) => l.id !== id);
  else { D.nodes = D.nodes.filter((n) => n.id !== id); D.links = D.links.filter((l) => l.a !== id && l.b !== id); }
  NM.sel = null; nmDraw(); nmProps(); nmPalette();
}
function nmSetTool(t) {
  NM.tool = t; NM.linkA = null;
  $$("#nmTool [data-tool]", NM.el).forEach((b) => b.classList.toggle("on", b.dataset.tool === t));
  const svg = $("#nmSvg", NM.el); if (svg) svg.dataset.tool = t;
  nmHint(); nmDraw();
}
function nmHint() {
  const h = $("#nmHint", NM.el); if (!h) return;
  h.textContent = I18N.t({
    sel: "دستگاه‌ها را از فهرست کنار بکشید یا کلیک کنید · کشیدن روی صفحه = جابه‌جایی نما · Del = حذف · Ctrl+Z = برگرداندن",
    link: NM.linkA ? "حالا روی دستگاه دوم کلیک کنید (Esc = لغو)" : "روی دستگاه اول کلیک کنید، بعد روی دستگاه دوم؛ سپس پورت هر طرف را انتخاب کنید",
    area: "روی نقشه کلیک کنید تا ناحیه (اتاق، طبقه، ساختمان) گذاشته شود؛ اندازه را با گوشه‌ی پایین تغییر دهید",
    text: "روی نقشه کلیک کنید تا برچسب متنی گذاشته شود",
  }[NM.tool] || "");
}
function nmViewCenter(i = 0) {
  const vb = NM.vb || { x: 0, y: 0, w: NM.cur.data.w, h: NM.cur.data.h };
  return { x: nmSnap(vb.x + vb.w / 2 + (i % 5) * 40 - 80), y: nmSnap(vb.y + vb.h / 2 + Math.floor(i / 5) * 40 - 40) };
}
function nmPaletteAdd(v, p) {
  const used = NM.cur.data.nodes.length;
  p = p ? { x: nmSnap(p.x), y: nmSnap(p.y) } : nmViewCenter(used);
  if (v.startsWith("dev:")) {
    const tid = Number(v.slice(4));
    if (NM.cur.data.nodes.some((n) => n.t === "dev" && n.tid === tid)) return toast("این دستگاه روی نقشه هست.", "warn");
    return nmAddNode({ t: "dev", tid, ...p });
  }
  if (v === "cloud") return nmAddNode({ t: "cloud", ...p, label: "" });
  if (v === "box") return nmAddNode({ t: "box", ...p, label: I18N.t("دستگاه"), host: "" });
  if (v === "area") return nmAddNode({ t: "area", x: p.x - 150, y: p.y - 100, w: 300, h: 200, label: "", color: "blue" });
  if (v === "text") return nmAddNode({ t: "text", ...p, label: I18N.t("متن"), size: "m" });
  if (v === "map") {
    const m = [...NM.maps.values()][0];
    if (!m) return toast("نقشه‌ی دیگری برای زیرنقشه نیست؛ ابتدا نقشه‌ی دیگری بسازید.", "warn");
    return nmAddNode({ t: "map", map: m.id, ...p });
  }
}
function nmPalette() {
  const P = $("#nmPal", NM.el); if (!P) return;
  const on = new Set(NM.cur.data.nodes.filter((n) => n.t === "dev").map((n) => n.tid));
  const F = NM.palF || (NM.palF = { q: "", grp: NM.cur.grp || "" });
  const grps = [...new Set([...NM.devs.values()].map((d) => d.grp).filter(Boolean))].sort();
  const q = F.q.trim().toLowerCase();
  const devs = [...NM.devs.values()].filter((d) => (!F.grp || d.grp === F.grp) && (!q || (d.name + " " + d.host).toLowerCase().includes(q)))
    .sort((a, b) => (on.has(a.id) - on.has(b.id)) || a.name.localeCompare(b.name));
  const keep = document.activeElement && document.activeElement.id === "npQ" ? document.activeElement.selectionStart : null;
  P.innerHTML = `<input id="npQ" placeholder="جستجوی دستگاه…" value="${esc(F.q)}">
    <select id="npGrp"><option value="">همه‌ی گروه‌ها</option>${grps.map((g) => `<option ${F.grp === g ? "selected" : ""}>${esc(g)}</option>`).join("")}</select>
    <div class="nm-sec">دستگاه‌های مانیتورینگ <span class="muted">(بکشید یا کلیک کنید)</span></div>
    <div class="nm-devs">${devs.slice(0, 400).map((d) => `<div class="nm-it${on.has(d.id) ? " used" : ""}" draggable="${on.has(d.id) ? "false" : "true"}" data-add="dev:${d.id}" title="${esc(d.host)}">
      ${monIcon(d.icon)}<span class="nm-itn">${nmN(d.name)}</span><span class="muted ltr">${esc(d.host)}</span>${on.has(d.id) ? "<span>✓</span>" : ""}</div>`).join("") || `<div class="muted">موردی نیست.</div>`}</div>
    ${F.grp && devs.some((d) => !on.has(d.id)) ? `<button class="btn sm" id="npAll">${esc(`افزودن همه‌ی دستگاه‌های ${F.grp}`)}</button>` : ""}
    <div class="nm-sec">شیء‌های دیگر</div>
    ${[["cloud", "internet", "ابر / اینترنت / ISP"], ["box", "other", "دستگاه بدون مانیتور"], ["map", "", "زیرنقشه (نقشه‌ی دیگر)"], ["area", "", "ناحیه / اتاق / طبقه"], ["text", "", "برچسب متنی"]]
      .map(([k, ic, n]) => `<div class="nm-it" draggable="true" data-add="${k}">${ic ? monIcon(ic) : `<span class="nm-gl">${{ map: "▣", area: "▭", text: "T" }[k]}</span>`}<span class="nm-itn">${n}</span></div>`).join("")}`;
  const qi = $("#npQ", P);
  if (keep !== null) { qi.focus(); qi.setSelectionRange(keep, keep); }
  qi.oninput = (e) => { F.q = e.target.value; nmPalette(); };
  $("#npGrp", P).onchange = (e) => { F.grp = e.target.value; nmPalette(); };
  $$("[data-add]", P).forEach((it) => {
    it.onclick = () => { if (!it.classList.contains("used")) nmPaletteAdd(it.dataset.add); };
    it.ondragstart = (e) => { e.dataTransfer.setData("text/plain", it.dataset.add); e.dataTransfer.effectAllowed = "copy"; };
  });
  if ($("#npAll", P)) $("#npAll", P).onclick = () => {
    const add = devs.filter((d) => !on.has(d.id)).slice(0, 200);
    nmPush();
    const c = nmViewCenter(0), cols = Math.ceil(Math.sqrt(add.length * 1.8));
    add.forEach((d, i) => NM.cur.data.nodes.push({ id: nmUid("n"), t: "dev", tid: d.id, label: "", icon: "", size: "m",
      x: Math.min(NM.cur.data.w - 40, Math.max(40, nmSnap(c.x - cols * 70 + (i % cols) * 140))), y: Math.min(NM.cur.data.h - 40, Math.max(40, nmSnap(c.y - 100 + Math.floor(i / cols) * 120))) }));
    nmDraw(); nmPalette(); toast(`${num(add.length)} دستگاه اضافه شد`, "ok");
  };
}

/* ---------------------------------------------------------------- پنل ویژگی‌ها */
function nmProps() {
  const P = $("#nmProp", NM.el); if (!P) return;
  const D = NM.cur.data, id = NM.sel;
  const n = id && D.nodes.find((x) => x.id === id), l = !n && id && D.links.find((x) => x.id === id);
  const chips = (key, vals, cur, names) => `<div class="nm-chips" data-k="${key}">${vals.map((v) => `<button class="chip${cur === v ? " on" : ""}" data-v="${v}">${esc(names(v))}</button>`).join("")}</div>`;
  if (!n && !l) {
    P.innerHTML = `<b>${esc(NM.cur.name)}</b><div class="muted">${esc(`${num(D.nodes.filter((x) => x.t === "dev").length)} دستگاه · ${num(D.links.length)} لینک`)}</div>
      <div class="nm-help"><b>راهنمای سریع</b><ol><li>دستگاه‌ها را از فهرست سمت راست روی نقشه بکشید.</li><li>«کشیدن لینک»: روی دو دستگاه کلیک کنید و پورت هر طرف را انتخاب کنید.</li>
      <li>با «ناحیه» اتاق یا طبقه را مشخص کنید.</li><li>«ذخیره» را بزنید.</li></ol><span class="muted">${esc("وضعیت پورت‌ها از همان پایش عادی می‌آید؛ نیازی به LLDP نیست.")}</span></div>`;
    return;
  }
  const nn = new Map(D.nodes.map((x) => [x.id, x]));
  if (l) {
    P.innerHTML = `<b>لینک</b><div>${nmN(nmNodeName(nn.get(l.a)))} ⇄ ${nmN(nmNodeName(nn.get(l.b)))}</div>
      <label>پورت‌ها</label><div class="ltr">${esc(l.pa || "—")} ⇄ ${esc(l.pb || "—")}</div>
      <label>نوع</label>${chips("kind", Object.keys(NM_KIND), l.kind, (v) => NM_KIND[v])}
      <button class="btn sm" id="npEditL">ویرایش پورت‌ها</button><button class="btn sm danger-ghost" id="npDel">حذف لینک</button>`;
    $$(".nm-chips[data-k=kind] [data-v]", P).forEach((b) => (b.onclick = () => { nmPush(); l.kind = b.dataset.v; if (l.kind === "none") { l.pa = ""; l.pb = ""; } nmDraw(); nmProps(); }));
    $("#npEditL", P).onclick = () => nmLinkDialog(l);
    $("#npDel", P).onclick = nmDelSel;
    return;
  }
  const d = n.t === "dev" ? NM.devs.get(n.tid) : null, my = D.links.filter((x) => x.a === n.id || x.b === n.id);
  const title = { dev: "دستگاه", box: "دستگاه بدون مانیتور", cloud: "ابر / اینترنت", map: "زیرنقشه", area: "ناحیه", text: "برچسب متنی" }[n.t];
  P.innerHTML = `<b>${esc(title)}</b>${d ? `<div class="ltr muted">${esc(d.name)} · ${esc(d.host)}</div>` : ""}
    ${n.t === "map" ? `<label>نقشه</label><select id="npMap">${[...NM.maps.values()].map((m) => `<option value="${m.id}" ${m.id === n.map ? "selected" : ""}>${esc(m.name)}</option>`).join("")}</select>` : ""}
    <label>${esc(n.t === "dev" ? "برچسب روی نقشه (خالی = نام دستگاه)" : "برچسب")}</label><input id="npLabel" value="${esc(n.label)}" maxlength="80">
    ${n.t === "box" ? `<label>آدرس (اختیاری، فقط برای نمایش)</label><input id="npHost" class="ltr" value="${esc(n.host || "")}" maxlength="80">` : ""}
    ${["dev", "box", "cloud"].includes(n.t) ? `<label>آیکون</label>${chips("icon", ["", ...NM_ICONS], n.icon || "", (v) => (v ? nmIconName(v) : n.t === "dev" ? "مثل دستگاه" : "پیش‌فرض"))}` : ""}
    ${n.t !== "area" ? `<label>اندازه</label>${chips("size", ["s", "m", "l"], n.size || "m", (v) => ({ s: "کوچک", m: "معمولی", l: "بزرگ" })[v])}` : ""}
    ${n.t === "area" ? `<label>رنگ</label><div class="nm-chips" data-k="color">${Object.entries(NM_AREA_C).map(([k, c]) => `<button class="nm-cdot${n.color === k ? " on" : ""}" data-v="${k}" style="background:${c}" title="${k}"></button>`).join("")}</div>
      <div class="row" style="gap:6px"><label>پهنا</label><input id="npW" type="number" min="60" step="20" value="${Math.round(n.w)}" style="width:80px"><label>ارتفاع</label><input id="npH" type="number" min="40" step="20" value="${Math.round(n.h)}" style="width:80px"></div>` : ""}
    ${my.length ? `<label>${esc(`لینک‌های این گره (${num(my.length)})`)}</label><div class="nm-lls">${my.map((x) => { const o = nn.get(x.a === n.id ? x.b : x.a); const mp = x.a === n.id ? x.pa : x.pb, op = x.a === n.id ? x.pb : x.pa; return `<button class="linkbtn" data-sl="${x.id}">${nmN(nmNodeName(o))} <span class="ltr muted">${esc(mp || "—")} ⇄ ${esc(op || "—")}</span></button>`; }).join("")}</div>` : ""}
    ${["dev", "box", "cloud", "map"].includes(n.t) ? `<button class="btn sm" id="npLink">⟋ لینک از این گره</button>` : ""}
    <button class="btn sm danger-ghost" id="npDel">حذف از نقشه</button>`;
  const lab = $("#npLabel", P);
  let pushed = false;
  lab.oninput = () => { if (!pushed) { nmPush(); pushed = true; } n.label = lab.value; nmDraw(); };
  if ($("#npHost", P)) $("#npHost", P).oninput = (e) => { if (!pushed) { nmPush(); pushed = true; } n.host = e.target.value; };
  if ($("#npMap", P)) $("#npMap", P).onchange = (e) => { nmPush(); n.map = Number(e.target.value); nmDraw(); };
  $$(".nm-chips[data-k]", P).forEach((g) => $$("[data-v]", g).forEach((b) => (b.onclick = () => { nmPush(); n[g.dataset.k] = b.dataset.v; nmDraw(); nmProps(); })));
  const wh = () => { nmPush(); n.w = Math.max(60, Number($("#npW", P).value) || 60); n.h = Math.max(40, Number($("#npH", P).value) || 40); nmDraw(); };
  if ($("#npW", P)) { $("#npW", P).onchange = wh; $("#npH", P).onchange = wh; }
  $$("[data-sl]", P).forEach((b) => (b.onclick = () => { NM.sel = b.dataset.sl; nmProps(); nmDraw(); }));
  if ($("#npLink", P)) $("#npLink", P).onclick = () => { nmSetTool("link"); NM.linkA = n.id; nmHint(); nmDraw(); };
  $("#npDel", P).onclick = nmDelSel;
}

/* ---------------------------------------------------------------- پنجره‌ی لینک (پورت هر طرف) */
async function nmLinkDialog(init) {
  const D = NM.cur.data, nn = new Map(D.nodes.map((x) => [x.id, x]));
  const A = nn.get(init.a), B = nn.get(init.b); if (!A || !B) return;
  const isNew = !init.id;
  const side = async (n) => {
    if (n.t !== "dev") return { ports: null };
    const r = await api("mon_map_ports", n.tid);
    if (r.ok && r.kind !== "snmp") return { ports: null };
    return r.ok ? r : { ports: null, err: r.error };
  };
  const [PA, PB] = await Promise.all([side(A), side(B)]);
  const usedOn = (nid, skip) => new Set(D.links.filter((x) => x.id !== skip).flatMap((x) => [x.a === nid ? x.pa : null, x.b === nid ? x.pb : null]).filter(Boolean));
  const st = { pa: init.pa || "", pb: init.pb || "", kind: init.kind || "cable" };
  // پیشنهاد از LLDP: پورتی از A که همسایه‌اش همان دستگاه B است (اگر اسکن شده)
  if (isNew && PA.ports && B.t === "dev") {
    const m = PA.ports.find((p) => p.nb && p.nb.tid === B.tid && !usedOn(A.id).has(p.name));
    if (m) { st.pa = m.name; if (m.nb.port && PB.ports && PB.ports.some((p) => p.name === m.nb.port)) st.pb = m.nb.port; }
  }
  const col = (n, P, key) => {
    const head = `<div class="nm-lc"><div class="muted">${esc("پورت سمت ")}<b>${nmN(nmNodeName(n))}</b></div>
      <input data-pf="${key}" class="ltr" placeholder="${P.ports ? "جستجو یا نام پورت…" : "نام پورت (اختیاری)"}" value="${esc(st[key])}">`;
    if (!P.ports) return head + `<div class="muted nm-pnote">${esc(n.t === "dev" ? (P.err || "این دستگاه SNMP نیست؛ وضعیت لینک از وضعیت خود دستگاه گرفته می‌شود.") : "برای این شیء پورتی خوانده نمی‌شود؛ نام پورت فقط برای نمایش است.")}</div></div>`;
    if (!P.ports.length) return head + `<div class="muted nm-pnote">${esc(P.polled ? "پورتی در آخرین بررسی نبود." : "دستگاه هنوز بررسی نشده؛ نام پورت را بنویسید (بعد از اولین بررسی وصل می‌شود).")}</div></div>`;
    return head + `<div class="nm-plist" data-pl="${key}"></div></div>`;
  };
  const fill = (m, key, P, n, other) => {
    const box = $(`[data-pl=${key}]`, m); if (!box) return;
    const q = st[key].trim().toLowerCase(), used = usedOn(n.id, init.id);
    const ps = P.ports.filter((p) => !q || (p.name + " " + p.alias + " " + p.descr).toLowerCase().includes(q) || p.name === st[key]).slice(0, 300);
    box.innerHTML = ps.map((p) => {
      const nb = p.nb && other.t === "dev" && p.nb.tid === other.tid;
      const ocls = p.admin === 2 ? "mute" : p.oper === 1 ? "ok" : "err";
      return `<button class="nm-prow${p.name === st[key] ? " on" : ""}" data-pp="${esc(p.name)}"><i class="dot ${ocls}"></i><span class="ltr">${esc(p.name)}</span>
        <span class="muted">${p.speed ? `<span class="ltr">${esc(nmBps(p.speed))}</span>` : ""}${p.alias ? ` · ${esc(p.alias)}` : ""}${used.has(p.name) ? ` · ${esc("در لینک دیگر")}` : ""}${p.oper !== 1 && p.admin !== 2 ? ` · ${esc("پایین")}` : ""}${nb ? ` · LLDP ← <span class="ltr">${esc(p.nb.port)}</span>` : ""}</span></button>`;
    }).join("") || `<div class="muted">موردی نیست.</div>`;
    $$("[data-pp]", box).forEach((b) => (b.onclick = () => { st[key] = b.dataset.pp; $(`[data-pf=${key}]`, m).value = st[key]; fill(m, key, P, n, other); }));
  };
  const v = await openModal({ title: isNew ? "لینک جدید" : "ویرایش لینک", wide: true,
    body: `<div style="margin-bottom:8px"><b>${nmN(nmNodeName(A))}</b> ⇄ <b>${nmN(nmNodeName(B))}</b></div>
      <div class="nm-lcols">${col(A, PA, "pa")}${col(B, PB, "pb")}</div>
      <label style="margin-top:10px">نوع خط</label><div class="nm-chips" id="nlKind">${Object.entries(NM_KIND).map(([k, n]) => `<button class="chip${st.kind === k ? " on" : ""}" data-v="${k}">${esc(n)}</button>`).join("")}</div>
      <div class="hint">${esc("«بدون پورت»: لینک فقط با وضعیت دو دستگاه قرمز یا سبز می‌شود (مثلاً وقتی پورت معلوم نیست). اگر پورت را انتخاب کنید، قطع شدن همان پورت هم دیده می‌شود.")}</div>`,
    foot: `<button class="btn ghost" data-r="0">انصراف</button><button class="btn primary" data-r="1">${isNew ? "افزودن لینک" : "ذخیره‌ی لینک"}</button>`,
    onOpen: (m, close) => {
      fill(m, "pa", PA, A, B); fill(m, "pb", PB, B, A);
      $$("[data-pf]", m).forEach((i) => (i.oninput = () => { const k = i.dataset.pf; st[k] = i.value; fill(m, k, k === "pa" ? PA : PB, k === "pa" ? A : B, k === "pa" ? B : A); }));
      $$("#nlKind [data-v]", m).forEach((b) => (b.onclick = () => { st.kind = b.dataset.v; $$("#nlKind [data-v]", m).forEach((x) => x.classList.toggle("on", x === b)); }));
      $$("[data-r]", m).forEach((b) => (b.onclick = () => close(b.dataset.r === "1" ? { ...st } : null)));
    } });
  if (!v) return;
  nmPush();
  const pa = v.kind === "none" ? "" : v.pa.trim().slice(0, 80), pb = v.kind === "none" ? "" : v.pb.trim().slice(0, 80);
  if (isNew) { const l = { id: nmUid("l"), a: A.id, b: B.id, pa, pb, kind: v.kind }; D.links.push(l); NM.sel = l.id; }
  else Object.assign(init, { pa, pb, kind: v.kind });
  nmDraw(); nmProps();
}

/* ---------------------------------------------------------------- تنظیمات، ذخیره، چیدمان، LLDP */
async function nmSettings() {
  const D = NM.cur.data, grps = [...new Set([...(NM.groups || []), ...[...NM.devs.values()].map((d) => d.grp).filter(Boolean)])].sort();
  let bg = NM.bgNew !== undefined ? NM.bgNew : NM.bg;
  const v = await openModal({ title: "تنظیمات نقشه",
    body: `<label>نام</label><input id="nsName" value="${esc(NM.cur.name)}" maxlength="60">
      <label style="margin-top:8px">گروه</label><select id="nsGrp"><option value="">بدون گروه</option>${grps.map((g) => `<option ${NM.cur.grp === g ? "selected" : ""}>${esc(g)}</option>`).join("")}</select>
      <div class="row" style="gap:8px;margin-top:8px"><label>اندازه‌ی صفحه</label><input id="nsW" type="number" min="600" max="6000" step="100" value="${D.w}" style="width:100px" class="ltr"> × <input id="nsH" type="number" min="400" max="6000" step="100" value="${D.h}" style="width:100px" class="ltr"></div>
      <label class="chk" style="margin-top:8px"><input type="checkbox" id="nsGrid" ${D.opt.grid !== false ? "checked" : ""}>شبکه‌ی جاذب (چیدن مرتب روی خانه‌های ۲۰ پیکسلی)</label>
      <div class="row" style="gap:8px;margin-top:8px"><label>برچسب پیش‌فرض دستگاه</label><select id="nsNl" style="width:auto">${Object.entries(NM_NLAB).map(([k, n]) => `<option value="${k}" ${D.opt.node === k ? "selected" : ""}>${n}</option>`).join("")}</select>
        <label>برچسب پیش‌فرض لینک</label><select id="nsLl" style="width:auto">${Object.entries(NM_LLAB).map(([k, n]) => `<option value="${k}" ${D.opt.link === k ? "selected" : ""}>${n}</option>`).join("")}</select></div>
      <label style="margin-top:10px">تصویر پس‌زمینه (نقشه‌ی ساختمان یا طبقه؛ PNG یا JPG تا ۲ مگابایت)</label>
      <div class="row" style="gap:8px"><input type="file" id="nsBg" accept="image/png,image/jpeg"><button class="btn sm danger-ghost" id="nsBgX" ${bg ? "" : "hidden"}>حذف تصویر</button><span class="muted" id="nsBgN">${bg ? esc("تصویر دارد") : ""}</span></div>`,
    foot: `<button class="btn ghost" data-r="0">انصراف</button><button class="btn primary" data-r="1">اعمال</button>`,
    onOpen: (m, close) => {
      $("#nsBg", m).onchange = (e) => {
        const f = e.target.files[0]; if (!f) return;
        if (!/^image\/(png|jpeg)$/.test(f.type)) { e.target.value = ""; return toast("فقط تصویر PNG یا JPG.", "error"); }
        if (f.size > 2 * 1024 * 1024) { e.target.value = ""; return toast("حداکثر حجم تصویر ۲ مگابایت است.", "error"); }
        const rd = new FileReader(); rd.onload = () => { bg = rd.result; $("#nsBgN", m).textContent = I18N.t("تصویر انتخاب شد"); $("#nsBgX", m).hidden = false; }; rd.readAsDataURL(f);
      };
      $("#nsBgX", m).onclick = () => { bg = ""; $("#nsBg", m).value = ""; $("#nsBgN", m).textContent = ""; $("#nsBgX", m).hidden = true; };
      $$("[data-r]", m).forEach((b) => (b.onclick = () => {
        if (b.dataset.r !== "1") return close(null);
        const name = $("#nsName", m).value.trim(); if (!name) return toast("نام نقشه را وارد کنید.", "error");
        close({ name, grp: $("#nsGrp", m).value, w: Math.max(600, Math.min(6000, Number($("#nsW", m).value) || D.w)), h: Math.max(400, Math.min(6000, Number($("#nsH", m).value) || D.h)),
          grid: $("#nsGrid", m).checked, node: $("#nsNl", m).value, link: $("#nsLl", m).value });
      }));
    } });
  if (!v) return;
  nmPush();
  NM.cur.name = v.name; NM.cur.grp = v.grp; D.w = v.w; D.h = v.h; D.opt = { ...D.opt, grid: v.grid, node: v.node, link: v.link };
  for (const n of D.nodes) { n.x = Math.min(n.x, D.w); n.y = Math.min(n.y, D.h); }
  if (bg !== (NM.bgNew !== undefined ? NM.bgNew : NM.bg)) NM.bgNew = bg;
  NM.vb = { x: 0, y: 0, w: D.w, h: D.h };
  nmShell();
}
async function nmSave() {
  const D = NM.cur.data, body = { id: NM.cur.id, name: NM.cur.name, grp: NM.cur.grp, data: { ...D } };
  delete body.data.bg;
  if (NM.bgNew !== undefined) body.bg = NM.bgNew;
  const b = $("#nmSave", NM.el); if (b) b.disabled = true;
  const r = await api("mon_map_save", body);
  if (b) b.disabled = false;
  if (!r.ok) return toast(r.error, "error");
  NM.dirty = false; NM.edit = false; NM.list = null;
  toast("نقشه ذخیره شد", "ok");
  nmOpen(NM.cur.id);
}
function nmAutoLayout() {
  const D = NM.cur.data, ns = D.nodes.filter((n) => ["dev", "box", "cloud", "map"].includes(n.t));
  if (ns.length < 2) return;
  nmPush();
  const idx = new Map(ns.map((n, i) => [n.id, i])), E = D.links.filter((l) => idx.has(l.a) && idx.has(l.b)).map((l) => [idx.get(l.a), idx.get(l.b)]);
  // لایه‌ها: از گره با بیشترین لینک (معمولاً هسته یا فایروال) با BFS؛ گره‌های بی‌لینک در ردیف آخر
  const deg = ns.map((_, i) => E.filter(([a, b]) => a === i || b === i).length), adj = ns.map(() => []);
  E.forEach(([a, b]) => { adj[a].push(b); adj[b].push(a); });
  const lv = ns.map(() => -1), order = [...ns.keys()].sort((a, b) => deg[b] - deg[a]);
  const cloud = ns.findIndex((n) => n.t === "cloud");
  for (const s of cloud >= 0 ? [cloud, ...order] : order) {
    if (lv[s] >= 0 || !deg[s]) continue;
    const base = Math.max(0, ...lv) + (lv.some((x) => x >= 0) ? 1 : 0);
    lv[s] = base; const qq = [s];
    while (qq.length) { const u = qq.shift(); for (const w of adj[u]) if (lv[w] < 0) { lv[w] = lv[u] + 1; qq.push(w); } }
  }
  const maxL = Math.max(0, ...lv);
  ns.forEach((_, i) => { if (lv[i] < 0) lv[i] = maxL + 1; });
  const rows = new Map(); ns.forEach((n, i) => { if (!rows.has(lv[i])) rows.set(lv[i], []); rows.get(lv[i]).push(i); });
  const keys = [...rows.keys()].sort((a, b) => a - b), dy = Math.min(170, (D.h - 120) / Math.max(1, keys.length - 1));
  // ترتیب هر ردیف با میانگین جای همسایه‌های ردیف قبل (کم شدن خط‌های متقاطع)
  const xs = ns.map(() => 0);
  keys.forEach((k, r) => {
    const row = rows.get(k);
    if (r) row.sort((a, b) => { const m = (i) => { const p = adj[i].filter((w) => lv[w] < k); return p.length ? p.reduce((s, w) => s + xs[w], 0) / p.length : D.w / 2; }; return m(a) - m(b); });
    const gap = Math.min(220, (D.w - 160) / Math.max(1, row.length));
    row.forEach((i, j) => { xs[i] = D.w / 2 + (j - (row.length - 1) / 2) * gap; });
    row.forEach((i) => { ns[i].x = nmSnap(Math.max(60, Math.min(D.w - 60, xs[i]))); ns[i].y = nmSnap(80 + r * dy); });
  });
  nmDraw();
  toast("چیدمان انجام شد؛ با Ctrl+Z برمی‌گردد", "info");
}
async function nmLldp() {
  const D = NM.cur.data, tids = D.nodes.filter((n) => n.t === "dev").map((n) => n.tid);
  const r = await api("mon_map_lldp", NM.cur.id, tids); if (!r.ok) return toast(r.error, "error");
  if (!r.scanned) return toast("اسکن LLDP/CDP انجام نشده است (اختیاری؛ از سربرگ «نقشه‌ی خودکار»). لینک‌ها را دستی بکشید.", "info");
  const byT = new Map(D.nodes.filter((n) => n.t === "dev").map((n) => [n.tid, n]));
  const has = new Set(D.links.map((l) => `${l.a}|${l.pa}`).concat(D.links.map((l) => `${l.b}|${l.pb}`)));
  const sug = r.links.map((x) => ({ ...x, na: byT.get(x.a), nb: byT.get(x.b) })).filter((x) => x.na && x.nb && !has.has(`${x.na.id}|${x.pa}`) && !has.has(`${x.nb.id}|${x.pb}`));
  if (!sug.length) return toast("لینک تازه‌ای در اسکن LLDP بین دستگاه‌های این نقشه نیست.", "info");
  const v = await openModal({ title: "پیشنهاد لینک از LLDP/CDP",
    body: `<p class="hint">${esc("این لینک‌ها در آخرین اسکن همسایه‌ها دیده شده‌اند. هر کدام را می‌خواهید تیک بزنید.")}</p>
      <div class="nm-sug">${sug.map((x, i) => `<label class="chk"><input type="checkbox" data-sg="${i}" checked>${nmN(nmNodeName(x.na))} <span class="ltr muted">${esc(x.pa)}</span> ⇄ ${nmN(nmNodeName(x.nb))} <span class="ltr muted">${esc(x.pb)}</span></label>`).join("")}</div>`,
    foot: `<button class="btn ghost" data-r="0">انصراف</button><button class="btn primary" data-r="1">افزودن لینک‌های انتخاب‌شده</button>`,
    onOpen: (m, close) => $$("[data-r]", m).forEach((b) => (b.onclick = () => close(b.dataset.r === "1" ? $$("[data-sg]", m).filter((c) => c.checked).map((c) => Number(c.dataset.sg)) : null))) });
  if (!v || !v.length) return;
  nmPush();
  v.forEach((i) => { const x = sug[i]; D.links.push({ id: nmUid("l"), a: x.na.id, b: x.nb.id, pa: x.pa.slice(0, 80), pb: x.pb.slice(0, 80), kind: "cable" }); });
  nmDraw(); toast(`${num(v.length)} لینک اضافه شد`, "ok");
}
