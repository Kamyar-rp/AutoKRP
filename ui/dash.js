"use strict";
/* ================================================================ داشبوردهای ویجتی (1.42؛ شبیه OpManager و Zabbix)
 * صفحه‌ی مستقل «داشبوردها». هر داشبورد چند صفحه؛ هر صفحه شبکه‌ی ۱۲ ستونی از ویجت‌ها (کشیدن، تغییر اندازه، تنظیم).
 * مشترک (ادمین یا «اجرا»ی مانیتورینگ) و شخصی (هر کاربر). فقط ویجت‌های مانیتورینگ؛ داده فقط از همان بررسی عادی
 * (mon_list و mon_rows؛ نمودارها از mon_snmp_series، دسترس‌پذیری از mon_report، رخدادها از mon_events_query، نقشه از mon_map_*).
 * نمایش خودکار صفحه‌ها (چرخش) و تمام‌صفحه. ویرایش روی یک کپی؛ «ذخیره» یا «انصراف». */
const DB = { list: [], canShared: false, personalOk: false, cur: null, page: 0, edit: false, draft: null, dirty: false,
  tg: new Map(), rows: {}, rev: 0, cfgRev: null, range: "", rangeFor: 0, timer: 0, clock: 0, rot: false, rotAt: 0, cache: new Map(), maps: new Map(),
  loading: false, drag: null };
const DB_COLS = 12, DB_ROW = 62, DB_GAP = 10;
const DB_RANGES = { "1h": "۱ ساعت", "6h": "۶ ساعت", "24h": "۲۴ ساعت", "7d": "۷ روز", "30d": "۳۰ روز" };
const DB_KEYS = { cpu: ["CPU", "%"], mem: ["حافظه", "%"], temp: ["دما", "°C"], disk: ["دیسک", "%"], rtt: ["زمان پاسخ", "ms"] };
const DB_VKEYS = { ...DB_KEYS, ses: ["نشست‌های فعال", ""], avail: ["دسترس‌پذیری ۲۴ ساعت", "%"], ports: ["پورت‌های وصل", ""] };
const DB_TOPK = { cpu: "CPU", mem: "حافظه", temp: "دما", rtt: "زمان پاسخ", traffic: "ترافیک پورت", avail: "کمترین دسترس‌پذیری ۲۴ ساعت" };
/* نوع ← [عنوان، نماد، عرض، ارتفاع پیش‌فرض، توضیح] */
const DB_TYPES = {
  status: ["وضعیت دستگاه‌ها", "▦", 4, 2, "شمار وصل، قطع، هشدار و…"],
  severity: ["مشکلات بر اساس شدت", "▤", 4, 2, "بحرانی، زیاد، هشدار، نگهداری"],
  problems: ["مشکلات جاری", "⚠", 6, 4, "فهرست قطع‌ها و هشدارهای جاری"],
  traffic: ["نمودار ترافیک پورت", "〰", 6, 4, "In/Out یک یا چند پورت"],
  metric: ["نمودار مقدار", "📈", 6, 4, "CPU، حافظه، دما، دیسک، زمان پاسخ"],
  gauge: ["عقربه (Gauge)", "◔", 3, 3, "مقدار لحظه‌ای با رنگ آستانه"],
  value: ["عدد تکی + روند", "#", 3, 2, "یک مقدار بزرگ با نمودار کوچک"],
  topn: ["Top-N", "☰", 4, 4, "بیشترین CPU، حافظه، ترافیک، …"],
  avail: ["جدول دسترس‌پذیری", "✓", 4, 4, "کمترین دسترس‌پذیری در بازه"],
  map: ["نقشه", "⌖", 6, 5, "یکی از نقشه‌های شبکه"],
  clock: ["ساعت", "◷", 3, 2, "ساعت و تاریخ"],
  events: ["آخرین Trap و Syslog", "✉", 6, 4, "رخدادهای اخیر دستگاه‌ها"],
  text: ["متن / عنوان", "T", 4, 1, "نوشته‌ی دلخواه"],
};
const DB_TOPT = { cpu: "بیشترین CPU", mem: "بیشترین مصرف حافظه", temp: "بیشترین دما", rtt: "بیشترین زمان پاسخ", traffic: "بیشترین ترافیک پورت", avail: "کمترین دسترس‌پذیری (۲۴ ساعت)" };
const dbAscii = (t) => /^[\x20-\x7e·]+$/.test(String(t || ""));
/** نام دستگاه/پورت لاتین با ارقام لاتین (قلم رابط ارقام را فارسی نشان می‌دهد) */
const dbN = (t, cls = "") => `<span class="${dbAscii(t) ? "ltr" : "bidi"}${cls ? " " + cls : ""}" data-no-i18n title="${esc(t)}">${esc(t)}</span>`;
const dbUid = (p) => p + Math.random().toString(36).slice(2, 9);
const dbRtl = () => document.documentElement.dir !== "ltr";
function dbLs(k, v) { try { if (v === undefined) return localStorage.getItem("akrp.dash." + k); localStorage.setItem("akrp.dash." + k, v); } catch (_) { /* */ } return null; }

/* ---------------------------------------------------------------- ورود به صفحه */
async function dashRender() {
  const el = $("#dashBody");
  if (!el) return;
  if (!DB.cur) el.innerHTML = `<div class="empty">در حال بارگذاری…</div>`;
  const r = await api("dash_list");
  if (!r.ok) { el.innerHTML = `<div class="empty">${esc(r.error || "")}</div>`; return; }
  DB.list = r.dashboards; DB.canShared = r.can_shared; DB.personalOk = r.personal_ok;
  if (DB.edit) return;           // ویرایش در جریان است؛ فهرست تازه شد ولی کپی دست نمی‌خورد
  const want = DB.cur ? DB.cur.id : Number(dbLs("cur")) || 0;
  DB.cur = DB.list.find((d) => d.id === want) || DB.list[0] || null;
  if (DB.cur && DB.page >= DB.cur.data.pages.length) DB.page = 0;
  if (DB.cur && DB.rangeFor !== DB.cur.id) { DB.range = DB.cur.data.range; DB.rangeFor = DB.cur.id; }
  dbShell();
  await dbData(true);
  dbDraw();
  dbStart();
}
function dbAlive() { return S.page === "dash" && $("#dbGrid"); }
function dbStop() { clearTimeout(DB.timer); DB.timer = 0; clearInterval(DB.clock); DB.clock = 0; }
function dbStart() {
  dbStop();
  DB.clock = setInterval(dbSecond, 1000);
  const sec = DB.cur ? DB.cur.data.refresh || 30 : 30;
  const tick = async () => {
    if (!dbAlive()) { dbStop(); return; }
    if (!DB.drag && !(document.querySelector("#modalBack") && !$("#modalBack").hidden && DB.edit)) { await dbData(false); dbDraw(true); }
    DB.timer = setTimeout(tick, sec * 1000);
  };
  DB.timer = setTimeout(tick, sec * 1000);
}
function dbSecond() {
  if (!dbAlive()) { dbStop(); return; }
  const now = new Date();
  $$(".db-clock").forEach((c) => {
    $("b", c).textContent = now.toLocaleTimeString("en-GB", c.dataset.sec === "1" ? {} : { hour: "2-digit", minute: "2-digit" });
    $("span", c).textContent = trFmtDay(now.getTime() / 1000);
  });
  if (DB.rot && !DB.edit && DB.cur && DB.cur.data.pages.length > 1) {
    const sec = DB.cur.data.rotate || 30, p = Math.min(1, (Date.now() - DB.rotAt) / (sec * 1000));
    const bar = $("#dbRot i"); if (bar) bar.style.width = `${(p * 100).toFixed(1)}%`;
    if (p >= 1) dbPage((DB.page + 1) % DB.cur.data.pages.length, true);
  }
}

/* ---------------------------------------------------------------- داده: هدف‌ها و ردیف‌های زنده (همان poll صفحه‌ی مانیتورینگ) */
async function dbData(full) {
  if (full || !DB.tg.size) {
    const L = await api("mon_list");
    if (L.ok) { DB.tg = new Map(L.targets.map((t) => [t.id, t])); DB.cfgRev = L.cfg_rev; DB.rev = 0; DB.rows = {}; }
  }
  const r = await api("mon_rows", DB.rev);
  if (!r.ok) return;
  if (DB.cfgRev !== null && r.cfg_rev !== DB.cfgRev && !full) { await dbData(true); return; }
  DB.rev = r.rev;
  r.rows.forEach((x) => (DB.rows[x.id] = x));
  const ids = new Set(r.ids);
  for (const k of Object.keys(DB.rows)) if (!ids.has(Number(k))) delete DB.rows[k];
  for (const k of [...DB.tg.keys()]) if (!ids.has(k)) DB.tg.delete(k);
}
function dbT(id) {
  const t = DB.tg.get(Number(id)); if (!t) return null;
  const r = DB.rows[t.id] || {};
  return { ...t, st: r.st || t.status, since: r.since ?? t.since, rtt: r.rtt ?? t.rtt, err: r.err ?? t.err, maint: r.maint || "", cause: r.cause || "",
    lvl: r.lvl || "", alm: r.alm || [], cpu: r.cpu, mem: r.mem, temp: r.temp, disk: r.disk, ses: r.ses, avail: r.avail, spark: r.spark || [],
    ports: r.ports || [], pu: r.pu, pn: r.pn };
}
/** وضعیت خلاصه: up | warn | down | unr | maint | unknown | paused */
function dbState(t) {
  if (t.st === "paused") return "paused";
  if (t.maint && t.st !== "up") return "maint";
  if (t.st === "down") return "down";
  if (t.st === "unreachable") return "unr";
  if (t.st === "unknown") return "unknown";
  if (t.lvl === "crit" || t.lvl === "warn" || t.st === "slow") return "warn";
  return "up";
}
function dbScope(c) {
  const ids = Array.isArray(c.tids) && c.tids.length ? new Set(c.tids.map(Number)) : null;
  return [...DB.tg.keys()].map(dbT).filter((t) => t && (!ids || ids.has(t.id)) && (!c.grp || (t.grp || "") === c.grp));
}
function dbRange(w) { return (w.cfg && w.cfg.range) || (DB.edit ? DB.draft.data.range : DB.range) || "1h"; }
/** درخواست سنگین (نمودار، گزارش، رخداد) با کش: همان درخواست تا maxAge دوباره فرستاده نمی‌شود */
async function dbFetch(key, maxAge, fn) {
  const c = DB.cache.get(key);
  if (c && Date.now() - c.at < maxAge) return c.r;
  if (c && c.p) return c.p;
  const p = fn().then((r) => { DB.cache.set(key, { at: Date.now(), r }); return r; });
  DB.cache.set(key, { at: c ? c.at : 0, r: c ? c.r : null, p });
  return p;
}

/* ---------------------------------------------------------------- پوسته: نوار بالا، سربرگ صفحه‌ها */
function dbD() { return DB.edit ? DB.draft : DB.cur; }
function dbShell() {
  const el = $("#dashBody"), D = dbD();
  const canEdit = D && (DB.edit || D.can_edit);
  el.innerHTML = `<div class="db-wrap${DB.edit ? " editing" : ""}" id="dbWrap">
    <div class="db-top">
      <h1 class="db-h">داشبوردها</h1>
      ${DB.list.length || DB.edit ? `<select id="dbSel" title="داشبورد" ${DB.edit ? "disabled" : ""}>${(DB.edit && !DB.list.some((d) => d.id === D.id) ? [D] : []).concat(DB.list).map((d) => `<option value="${d.id || ""}" data-no-i18n>${esc(d.name)}${d.personal ? " · " + esc(I18N.t("شخصی")) : ""}</option>`).join("")}</select>` : ""}
      <div class="db-tabs" id="dbTabs"></div>
      <div class="db-acts">
        ${D ? `<span class="muted db-rl">بازه:</span><select id="dbRange" title="بازه‌ی نمودارها">${Object.entries(DB_RANGES).map(([k, v]) => `<option value="${k}">${esc(I18N.t(v))}</option>`).join("")}</select>` : ""}
        ${D && !DB.edit ? `${D.data.pages.length > 1 ? `<button class="btn sm" id="dbRotB" title="نمایش خودکار صفحه‌ها">${DB.rot ? "⏸ توقف نمایش" : "▶ نمایش خودکار"}</button>` : ""}
          <button class="btn sm" id="dbFs" title="تمام‌صفحه (F)">⛶ تمام‌صفحه</button>
          ${canEdit ? `<button class="btn sm" id="dbEdit">✎ ویرایش</button>` : ""}` : ""}
        ${DB.edit ? `<button class="btn sm" id="dbSet">⚙ تنظیمات داشبورد</button><button class="btn sm ghost" id="dbCancel">انصراف</button><button class="btn sm primary" id="dbSave">ذخیره</button>`
          : `<button class="btn sm" id="dbNew" title="داشبورد تازه">+ داشبورد</button>`}
      </div>
    </div>
    <div class="db-rot" id="dbRot" ${DB.rot && !DB.edit ? "" : "hidden"}><i></i></div>
    <div class="db-main"><div class="db-grid" id="dbGrid"></div>${DB.edit ? dbLibHtml() : ""}</div>
  </div>`;
  if (!D) {
    $("#dbGrid").outerHTML = `<div class="db-empty"><h3>هنوز داشبوردی ساخته نشده است</h3>
      <p class="muted">داشبورد مجموعه‌ای از ویجت‌های مانیتورینگ است (وضعیت دستگاه‌ها، مشکلات، نمودار ترافیک، عقربه، نقشه، …) که می‌توانید بچینید، اندازه‌شان را عوض کنید و چند صفحه داشته باشید.</p>
      <button class="btn primary" id="dbNew2">+ ساخت داشبورد</button></div>`;
    $("#dbNew2").onclick = dbNew;
  }
  if ($("#dbSel")) { $("#dbSel").value = String(D ? D.id || "" : ""); $("#dbSel").onchange = (e) => dbOpen(Number(e.target.value)); }
  if ($("#dbRange")) {
    $("#dbRange").value = DB.edit ? D.data.range : DB.range || D.data.range;
    $("#dbRange").onchange = (e) => {
      if (DB.edit) { DB.draft.data.range = e.target.value; DB.dirty = true; }
      else { DB.range = e.target.value; DB.rangeFor = D.id; }
      dbDraw();
    };
  }
  const on = (id, f) => { const b = $("#" + id); if (b) b.onclick = f; };
  on("dbNew", dbNew); on("dbEdit", dbEditOn); on("dbCancel", dbEditCancel); on("dbSave", dbEditSave); on("dbSet", dbSettings); on("dbFs", dbFull);
  on("dbRotB", () => { DB.rot = !DB.rot; DB.rotAt = Date.now(); dbShell(); dbDraw(); });
  if (DB.edit) dbLibBind();
  dbTabs();
}
function dbTabs() {
  const el = $("#dbTabs"), D = dbD(); if (!el || !D) return;
  const P = D.data.pages;
  el.innerHTML = P.map((p, i) => `<button class="db-tab${i === DB.page ? " on" : ""}" data-pg="${i}" data-no-i18n>${esc(p.name)}${DB.edit && P.length > 1 ? `<span class="db-tx" data-pdel="${i}" title="${esc(I18N.t("حذف صفحه"))}">×</span>` : ""}</button>`).join("")
    + (DB.edit ? `<button class="db-tab add" id="dbPgAdd" title="صفحه‌ی تازه">+</button>` : "");
  $$("[data-pg]", el).forEach((b) => {
    b.onclick = (e) => { if (e.target.closest("[data-pdel]")) return; dbPage(Number(b.dataset.pg)); };
    if (DB.edit) b.ondblclick = () => dbPageRename(Number(b.dataset.pg));
  });
  $$("[data-pdel]", el).forEach((x) => (x.onclick = async () => {
    const i = Number(x.dataset.pdel), p = P[i];
    if (p.widgets.length && !(await confirm2({ title: "حذف صفحه", body: `<p>صفحه‌ی «<span class="bidi">${esc(p.name)}</span>» با ${num(p.widgets.length)} ویجت حذف شود؟</p>`, confirm: "حذف", danger: true }))) return;
    P.splice(i, 1); DB.dirty = true; DB.page = Math.min(DB.page, P.length - 1); dbTabs(); dbDraw();
  }));
  if ($("#dbPgAdd")) $("#dbPgAdd").onclick = () => {
    if (P.length >= 20) { toast("حداکثر ۲۰ صفحه.", "warn"); return; }
    P.push({ id: dbUid("p"), name: `${I18N.t("صفحه")} ${num(P.length + 1)}`, widgets: [] }); DB.dirty = true; DB.page = P.length - 1; dbTabs(); dbDraw();
  };
}
async function dbPageRename(i) {
  const p = DB.draft.data.pages[i];
  const v = await openModal({ title: "نام صفحه", body: `<div class="field"><label>نام</label><input class="input" id="dbPn" maxlength="40" value="${esc(p.name)}" autofocus></div>`,
    foot: `<button class="btn ghost" data-r="0">انصراف</button><button class="btn primary" data-r="1">تأیید</button>`,
    onOpen: (m, close) => { $$("[data-r]", m).forEach((b) => (b.onclick = () => close(b.dataset.r === "1" ? $("#dbPn", m).value.trim() : null))); $("#dbPn", m).onkeydown = (e) => { if (e.key === "Enter") close($("#dbPn", m).value.trim()); }; } });
  if (v) { p.name = v; DB.dirty = true; dbTabs(); }
}
function dbPage(i, auto) {
  DB.page = i; if (!auto) DB.rotAt = Date.now(); else DB.rotAt = Date.now();
  $$("#dbTabs [data-pg]").forEach((b) => b.classList.toggle("on", Number(b.dataset.pg) === i));
  dbDraw();
}
function dbOpen(id) {
  const d = DB.list.find((x) => x.id === id); if (!d) return;
  DB.cur = d; DB.page = 0; DB.rot = false; DB.range = d.data.range; DB.rangeFor = d.id; dbLs("cur", String(id));
  dbShell(); dbDraw(); dbStart();
}
function dbFull() {
  const w = $("#dbWrap");
  if (document.fullscreenElement) document.exitFullscreen().catch(() => {});
  else if (w) w.requestFullscreen().then(() => setTimeout(() => dbDraw(), 250)).catch(() => {});
}
let dbRsT = 0;
window.addEventListener("resize", () => { clearTimeout(dbRsT); dbRsT = setTimeout(() => { if (S.page === "dash" && $("#dbGrid") && !DB.drag) dbDraw(); }, 300); });   // اندازه‌ی نمودارها با پنجره و منوی جمع
document.addEventListener("fullscreenchange", () => { if (S.page === "dash" && $("#dbGrid")) setTimeout(() => dbDraw(), 200); });
document.addEventListener("keydown", (e) => {
  if (S.page !== "dash" || DB.edit || e.ctrlKey || e.altKey || e.metaKey) return;
  if (e.target.closest && e.target.closest("input,textarea,select,[contenteditable]")) return;
  if (!$("#modalBack").hidden) return;
  if (e.key === "f" || e.key === "F") { e.preventDefault(); dbFull(); }
});

/* ---------------------------------------------------------------- شبکه‌ی ویجت‌ها */
function dbWs() { const D = dbD(); return D ? (D.data.pages[DB.page] || D.data.pages[0]).widgets : []; }
function dbPos(el, w) { el.style.gridColumn = `${w.x + 1} / span ${w.w}`; el.style.gridRow = `${w.y + 1} / span ${w.h}`; }
function dbRowsUsed(ws) { return ws.reduce((m, w) => Math.max(m, w.y + w.h), 0); }
function dbDraw(light) {
  const g = $("#dbGrid"); if (!g) return;
  const ws = dbWs();
  g.classList.toggle("edit", DB.edit);
  g.style.gridTemplateRows = `repeat(${Math.max(dbRowsUsed(ws) + (DB.edit ? 4 : 0), 1)}, ${DB_ROW}px)`;
  const have = new Map($$(".db-w", g).map((e) => [e.dataset.w, e]));
  if (!light) { g.innerHTML = ""; have.clear(); }
  if (!ws.length && !DB.edit) {
    g.innerHTML = `<div class="db-none">این صفحه ویجتی ندارد.${dbD().can_edit !== false ? ` <a href="#" id="dbNoneEdit">ویرایش</a>` : ""}</div>`;
    const a = $("#dbNoneEdit"); if (a) a.onclick = (e) => { e.preventDefault(); dbEditOn(); };
    return;
  }
  if (!ws.length && DB.edit) {
    g.innerHTML = `<div class="db-none" style="grid-column:1/-1;grid-row:1/span 3">ویجت‌ها را از فهرست کنار اضافه کنید (کلیک یا کشیدن روی صفحه).</div>`;
    return;
  }
  for (const w of ws) {
    let el = have.get(w.id);
    if (!el) {
      el = document.createElement("div");
      el.className = "db-w"; el.dataset.w = w.id; el.dataset.type = w.type;
      el.innerHTML = `<div class="db-wh"><h3>${dbTitleHtml(w)}</h3>${DB.edit ? `<div class="db-wbar"><button data-wa="cfg" title="تنظیم ویجت">⚙</button><button data-wa="dup" title="کپی ویجت">⧉</button><button data-wa="del" title="حذف ویجت">×</button></div>` : ""}</div>
        <div class="db-wb"></div>${DB.edit ? `<span class="db-rs" title="تغییر اندازه"></span>` : ""}`;
      g.appendChild(el);
    } else { $(".db-wh h3", el).innerHTML = dbTitleHtml(w); }
    dbPos(el, w);
    have.delete(w.id);
    dbBody(w, $(".db-wb", el), light);
  }
  for (const el of have.values()) el.remove();
  if (DB.edit) dbBindEdit(g);
}
function dbDefTitle(w) {
  const c = w.cfg || {};
  if (w.type === "topn") return DB_TOPT[c.key] || DB_TOPT.cpu;
  if (w.type === "gauge") return (DB_KEYS[c.key] || DB_KEYS.cpu)[0];
  if (w.type === "value") return (DB_VKEYS[c.key] || DB_VKEYS.cpu)[0];
  if (w.type === "metric") return (c.keys || ["cpu"]).filter((k) => DB_KEYS[k]).map((k) => DB_KEYS[k][0]).join(" · ") || DB_TYPES.metric[0];
  if (w.type === "traffic") return "ترافیک";
  if (w.type === "avail") return "کمترین دسترس‌پذیری";
  return DB_TYPES[w.type][0];
}
function dbTitleHtml(w) {
  const t = w.cfg && w.cfg.tid ? DB.tg.get(Number(w.cfg.tid)) : null;
  const def = w.type === "metric" ? dbDefTitle(w).split(" · ").map((x) => I18N.t(x)).join(" · ") : I18N.t(dbDefTitle(w));
  if (w.type === "text" && !w.title) return "";
  if (w.type === "clock" && !w.title) return "";
  const sub = t ? [t.name, ...(w.type === "traffic" ? w.cfg.ports || [] : [])].join(" · ") : "";
  return `<span data-no-i18n>${esc(w.title || def)}</span>${sub ? ` <small class="muted">${dbN(sub)}</small>` : ""}`;
}

/* ---------------------------------------------------------------- محتوای ویجت‌ها */
const DB_STC = { up: ["ok", "وصل"], down: ["err", "قطع"], unr: ["unr", "در دسترس نیست"], warn: ["warn", "هشدار"], maint: ["info", "نگهداری"], unknown: ["mute", "نامعلوم"], paused: ["mute", "متوقف"] };
function dbBody(w, el, light) {
  try {
    const c = w.cfg || {};
    const need = ["traffic", "metric", "gauge", "value"].includes(w.type);
    if (need && !c.tid) { el.innerHTML = `<div class="db-hint">${DB.edit ? "با ⚙ دستگاه را انتخاب کنید." : "دستگاهی انتخاب نشده است."}</div>`; return; }
    if (need && !DB.tg.get(Number(c.tid))) { el.innerHTML = `<div class="db-hint">دستگاه پیدا نشد (حذف شده یا به آن دسترسی ندارید).</div>`; return; }
    if (w.type === "map" && !c.map) { el.innerHTML = `<div class="db-hint">${DB.edit ? "با ⚙ نقشه را انتخاب کنید." : "نقشه‌ای انتخاب نشده است."}</div>`; return; }
    (DB_RENDER[w.type] || (() => {}))(w, el, c, light);
  } catch (e) { el.innerHTML = `<div class="db-hint">${esc(String(e && e.message || e))}</div>`; }
}
const DB_RENDER = {
  status(w, el, c) {
    const ts = dbScope(c), n = {};
    ts.forEach((t) => { const s = dbState(t); n[s] = (n[s] || 0) + 1; });
    const keys = ["up", "down", "unr", "warn", "maint", "unknown"].filter((k) => k === "up" || k === "down" || n[k]);
    el.innerHTML = `<div class="db-cnt">${keys.map((k) => `<div class="c-${DB_STC[k][0]}${k === "down" && n.down ? " blink" : ""}"><b class="ltr">${num(n[k] || 0)}</b><span>${DB_STC[k][1]}</span></div>`).join("")}</div>`;
  },
  severity(w, el, c) {
    const ts = dbScope(c), n = { crit: 0, high: 0, warn: 0, maint: 0 };
    ts.forEach((t) => {
      const s = dbState(t);
      if (s === "down") n.crit++; else if (s === "unr" || (s === "warn" && t.lvl === "crit")) n.high++; else if (s === "warn") n.warn++; else if (s === "maint") n.maint++;
    });
    const L = [["crit", "err", "بحرانی"], ["high", "high", "زیاد"], ["warn", "warn", "هشدار"], ["maint", "info", "نگهداری"]];
    el.innerHTML = `<div class="db-cnt">${L.map(([k, cl, t]) => `<div class="c-${cl}${n[k] ? "" : " zero"}"><b class="ltr">${num(n[k])}</b><span>${t}</span></div>`).join("")}</div>`;
  },
  problems(w, el, c) {
    const R = { down: 0, unr: 1, warn: 2, maint: 3 }, now = Date.now() / 1000;
    const L = dbScope(c).map((t) => [t, dbState(t)]).filter(([, s]) => s in R && (s !== "maint" || c.maint))
      .sort((a, b) => R[a[1]] - R[b[1]] || (a[0].since || 0) - (b[0].since || 0)).slice(0, c.n || 50);
    if (!L.length) { el.innerHTML = `<div class="db-allok">همه سالم‌اند ✓</div>`; return; }
    el.innerHTML = `<table class="db-tbl"><thead><tr><th>زمان</th><th>دستگاه</th><th>مشکل</th><th>مدت</th></tr></thead><tbody>${L.map(([t, s]) => {
      const why = s === "down" ? (t.err || I18N.t("قطع")) : s === "unr" ? `${I18N.t("به‌خاطر قطع")} «${t.cause}»` : s === "maint" ? I18N.t("نگهداری")
        : t.alm.length ? t.alm.join(" · ") : t.st === "slow" ? `${num(t.rtt)} ms` : I18N.t("هشدار");
      const cls = s === "down" ? "err" : s === "unr" ? "unr" : s === "maint" ? "info" : t.lvl === "crit" ? "high" : "warn";
      return `<tr><td class="ltr">${t.since ? fmtTime(t.since).slice(0, 5) : "—"}</td><td>${monIcon(t.icon, "db-ic")}${dbN(t.name)}</td>
        <td><span class="db-tag ${cls}" data-no-i18n>${esc(why)}</span></td><td>${t.since && s !== "warn" ? monDur(now - t.since) : ""}</td></tr>`;
    }).join("")}</tbody></table>`;
  },
  async traffic(w, el, c, light) {
    const t = DB.tg.get(Number(c.tid)), ports = (c.ports || []).slice(0, 4);
    if (t.kind !== "snmp") { el.innerHTML = `<div class="db-hint">فقط برای هدف SNMP.</div>`; return; }
    if (!ports.length) { el.innerHTML = `<div class="db-hint">${DB.edit ? "با ⚙ پورت را انتخاب کنید." : "پورتی انتخاب نشده است."}</div>`; return; }
    const keys = ports.flatMap((p) => [`if:${p}:in`, `if:${p}:out`]);
    await dbChart(w, el, light, t.id, keys, ports.flatMap((p, i) => [[`if:${p}:in`, (ports.length > 1 ? p + " " : "") + "In", ["info", "acc", "ok", "warn"][i % 4]],
      [`if:${p}:out`, (ports.length > 1 ? p + " " : "") + "Out", ["ok", "warn", "info", "acc"][i % 4]]]), { bps: true });
  },
  async metric(w, el, c, light) {
    const t = DB.tg.get(Number(c.tid));
    if (t.kind !== "snmp") { el.innerHTML = `<div class="db-hint">فقط برای هدف SNMP.</div>`; return; }
    const ks = (c.keys || ["cpu"]).filter((k) => DB_KEYS[k]);
    const cols = ["info", "acc", "warn", "ok", "err"];
    await dbChart(w, el, light, t.id, ks, ks.map((k, i) => [k, I18N.t(DB_KEYS[k][0]), cols[i % cols.length]]), { pct: ks.every((k) => DB_KEYS[k][1] === "%") });
  },
  gauge(w, el, c) {
    const t = dbT(c.tid), k = DB_KEYS[c.key] ? c.key : "cpu", v = t[k];
    const pct = DB_KEYS[k][1] === "%", max = pct ? 100 : Number(c.max) || (k === "temp" ? 100 : 500);
    const wn = Number(c.warn) || (k === "temp" ? 60 : pct ? 75 : max * 0.5), cr = Number(c.crit) || (k === "temp" ? 75 : pct ? 90 : max * 0.8);
    el.innerHTML = dbGaugeSvg(v, max, wn, cr, DB_KEYS[k][1], I18N.t(DB_KEYS[k][0]));
  },
  async value(w, el, c, light) {
    const t = dbT(c.tid), k = DB_VKEYS[c.key] ? c.key : "cpu";
    let v = k === "ports" ? (t.pn ? `${num(t.pu)}/${num(t.pn)}` : null) : t[k];
    const unit = DB_VKEYS[k][1];
    const shown = v === null || v === undefined ? "—" : typeof v === "number" ? num(Math.round(v * 10) / 10) + (unit ? (unit === "%" ? "%" : " " + unit) : "") : v;
    const lvl = DB_KEYS[k] && DB_KEYS[k][1] === "%" && typeof v === "number" ? (v >= 90 ? "err" : v >= 75 ? "warn" : "") : k === "avail" && typeof v === "number" ? (v < 95 ? "err" : v < 99.9 ? "warn" : "") : "";
    const old = $(".db-spk", el) ? $(".db-spk", el).outerHTML : "";
    el.innerHTML = `<div class="db-val ${lvl}"><b class="ltr">${esc(shown)}</b><span class="muted">${esc(I18N.t(DB_VKEYS[k][0]))}</span></div>${old}`;
    let vals = null;
    if (k === "avail") vals = (t.spark || []).map((x) => (x && x[0] ? (100 * x[1]) / x[0] : null));
    else if (DB_KEYS[k] && t.kind === "snmp") {
      const r = await dbFetch(`s|${t.id}|1h|${k}`, 60000, () => api("mon_snmp_series", t.id, "1h", [k]));
      if (r && r.ok && r.data[k]) vals = r.data[k].avg;
    }
    if (!el.isConnected) return;
    const sp = $(".db-spk", el); if (sp) sp.remove();
    if (vals && vals.some((x) => x !== null && x !== undefined)) el.insertAdjacentHTML("beforeend", dbSpark(vals));
  },
  topn(w, el, c) {
    const k = DB_TOPK[c.key] ? c.key : "cpu", n = Number(c.n) || 5;
    const val = (t) => k === "traffic" ? (t.ports.length ? Math.max(...t.ports.map((p) => Math.max(p.in || 0, p.out || 0))) : null) : k === "rtt" ? (t.st === "down" ? null : t.rtt) : t[k];
    let L = dbScope(c).map((t) => [t, val(t)]).filter(([, v]) => v !== null && v !== undefined);
    L.sort((a, b) => (k === "avail" ? a[1] - b[1] : b[1] - a[1]));
    L = L.slice(0, n);
    if (!L.length) { el.innerHTML = `<div class="db-hint">داده‌ای نیست.</div>`; return; }
    const mx = k === "traffic" || k === "rtt" ? Math.max(...L.map((x) => x[1]), 1) : 100;
    const fmt = (v) => k === "traffic" ? fmtBps(v) : k === "rtt" ? `${num(v)} ms` : k === "temp" ? `${num(Math.round(v))}°C` : `${num(Math.round(v * 10) / 10)}%`;
    const col = (v) => k === "avail" ? (v < 95 ? "err" : v < 99.9 ? "warn" : "ok") : k === "traffic" || k === "rtt" ? "info" : v >= 90 ? "err" : v >= 75 ? "warn" : "ok";
    el.innerHTML = `<div class="db-bars">${L.map(([t, v]) => `<div class="db-bar">${dbN(t.name, "db-bn")}
      <span class="db-bt"><i class="c-${col(v)}" style="width:${Math.max(2, Math.min(100, (v / mx) * 100)).toFixed(1)}%"></i></span><b class="ltr">${esc(fmt(v))}</b></div>`).join("")}</div>`;
  },
  async avail(w, el, c, light) {
    const rng = dbRange(w), ids = dbScope(c).map((t) => t.id);
    if (!ids.length) { el.innerHTML = `<div class="db-hint">هدفی نیست.</div>`; return; }
    const key = `a|${rng}|${ids.join(",")}`;
    if (!light || !$(".db-bars", el)) el.innerHTML = el.innerHTML || `<div class="db-hint">…</div>`;
    const r = await dbFetch(key, 120000, () => api("mon_report", rng, ids));
    if (!el.isConnected) return;
    if (!r || !r.ok) { el.innerHTML = `<div class="db-hint">${esc((r && r.error) || "")}</div>`; return; }
    const L = (r.rows || []).filter((x) => x.avail !== null).sort((a, b) => a.avail - b.avail).slice(0, Number(c.n) || 10);
    if (!L.length) { el.innerHTML = `<div class="db-hint">هنوز داده‌ای برای این بازه نیست.</div>`; return; }
    const col = (v) => (v < 95 ? "err" : v < 99.9 ? "warn" : "ok");
    el.innerHTML = `<div class="db-bars">${L.map((x) => `<div class="db-bar">${dbN(x.name, "db-bn")}
      <span class="db-bt"><i class="c-${col(x.avail)}" style="width:${Math.max(2, x.avail).toFixed(1)}%"></i></span><b class="ltr">${x.avail >= 99.995 ? "100" : x.avail.toFixed(2)}%</b>${x.outages ? `<small class="muted" title="${esc(I18N.t("تعداد قطعی"))}">${num(x.outages)}×</small>` : ""}</div>`).join("")}</div>`;
  },
  async map(w, el, c, light) {
    const mid = Number(c.map);
    const g = await dbFetch(`mg|${mid}`, 300000, () => api("mon_map_get", mid));
    if (!el.isConnected) return;
    if (!g || !g.ok) { el.innerHTML = `<div class="db-hint">${esc((g && g.error) || "")}</div>`; return; }
    const st = await dbFetch(`ms|${mid}`, 14000, () => api("mon_map_status", mid));
    if (!el.isConnected) return;
    el.innerHTML = dbMapSvg(g, st && st.ok ? st : null);
  },
  clock(w, el, c) {
    const now = new Date();
    el.innerHTML = `<div class="db-clock" data-sec="${c.sec ? 1 : 0}"><b class="ltr">${now.toLocaleTimeString("en-GB", c.sec ? {} : { hour: "2-digit", minute: "2-digit" })}</b><span class="ltr">${trFmtDay(now.getTime() / 1000)}</span></div>`;
  },
  async events(w, el, c, light) {
    const rng = dbRange(w), kinds = (c.kinds || []).filter((k) => ["trap", "syslog"].includes(k)), sev = (c.sev || []).filter((k) => ["crit", "warn", "info", "ok"].includes(k));
    const r = await dbFetch(`e|${rng}|${kinds}|${sev}`, 30000, () => api("mon_events_query", rng, kinds, sev, "", null));
    if (!el.isConnected) return;
    if (!r || !r.ok) { el.innerHTML = `<div class="db-hint">${esc((r && r.error) || "")}</div>`; return; }
    const L = (r.rows || []).slice(0, Number(c.n) || 20);
    if (!L.length) { el.innerHTML = `<div class="db-hint">رخدادی در این بازه نیست.</div>`; return; }
    const SV = { crit: ["err", "بحرانی"], warn: ["warn", "هشدار"], info: ["info", "اطلاع"], ok: ["ok", "برطرف"] };
    el.innerHTML = `<table class="db-tbl"><tbody>${L.map((x) => { const s = SV[x.sev] || SV.info; return `<tr><td class="ltr">${fmtTime(x.t).slice(0, 5)}</td>
      <td>${dbN(x.tname || x.src || "")}</td><td><span class="db-tag ${s[0]}">${s[1]}</span></td>
      <td class="ltr db-msg" data-no-i18n title="${esc((x.msg || "").slice(0, 300))}">${esc(x.name ? x.name + " — " : "")}${esc((x.msg || "").slice(0, 160))}</td></tr>`; }).join("")}</tbody></table>`;
  },
  text(w, el, c) {
    el.innerHTML = `<div class="db-text s-${["s", "m", "l"].includes(c.size) ? c.size : "m"} a-${["start", "center"].includes(c.align) ? c.align : "start"}" data-no-i18n>${esc(c.text || "").replace(/\n/g, "<br>")}</div>`;
  },
};
/** نمودار سری زمانی داخل ویجت (کش ۶۰ ثانیه؛ در به‌روزرسانی سبک فقط وقتی داده‌ی تازه آمد دوباره رسم می‌شود) */
async function dbChart(w, el, light, tid, keys, defs, opt) {
  const rng = dbRange(w), key = `s|${tid}|${rng}|${keys.join(",")}`;
  const c = DB.cache.get(key), fresh = c && c.r && Date.now() - c.at < 60000;
  if (light && fresh && el.dataset.k === key && el.dataset.at === String(c.at)) return;
  if (!el.innerHTML) el.innerHTML = `<div class="db-hint">…</div>`;
  const r = await dbFetch(key, 60000, () => api("mon_snmp_series", tid, rng, keys));
  if (!el.isConnected) return;
  if (!r || !r.ok) { el.innerHTML = `<div class="db-hint">${esc((r && r.error) || "")}</div>`; return; }
  el.dataset.k = key; el.dataset.at = String((DB.cache.get(key) || {}).at || 0);
  dbFitChart(el, (hh) => snDraw(el, r, defs, { ...opt, height: hh }));
}
/** 1.50: نمودار + جدول کمینه/میانگین/بیشینه/آخرین همیشه بدون اسکرول در ویجت:
 *  ۱) نمودار کوتاه‌تر (≥ ۶۰px)  ۲) جدول فشرده و نمودار ≥ ۴۰px  ۳) جدول کوچک‌نمایی‌شده  ۴) فقط جدول (نمودار برای جا نبود) */
function dbFitChart(el, draw) {
  el.classList.remove("db-cmp", "db-nochart");
  el.removeAttribute("title");
  const H = Math.max(96, el.clientHeight - 6), MIN = 96;   // کمتر از ~۹۶px محور و برچسب‌ها خوانا نیستند
  const wide = () => { const t = el.querySelector(".ch-stats"); return !!t && t.scrollWidth > el.clientWidth + 1; };
  const over = () => el.scrollHeight - el.clientHeight;
  const svgH = () => { const v = el.querySelector("svg"); return v ? v.getBoundingClientRect().height : 0; };
  const shrink = (h) => {        // ارتفاع نمودار تا جای خالی؛ کوچک‌نمایی SVG (عرض کمتر از ۳۶۰px) حساب می‌شود
    const o = over(); if (o <= 0) return h;
    const k = (svgH() || h) / h || 1, nh = Math.max(MIN, Math.floor(h - o / k) - 2);
    if (nh < h) draw(nh);
    return nh;
  };
  draw(H);
  if (over() <= 0 && !wide()) return;
  let h = shrink(H);
  if (over() <= 0 && !wide()) return;
  el.classList.add("db-cmp"); draw(h); h = shrink(h);
  if (over() <= 0 && !wide()) return;
  const st = el.querySelector(".ch-stats"); if (!st) return;
  // کوچک‌نمایی جدول تا هم ارتفاع و هم عرض جا شود (نام پورت‌ها و همه‌ی ستون‌ها دیده شوند)
  const fitZoom = (min) => {
    st.style.zoom = "";
    const ov = over(), wz = st.scrollWidth > el.clientWidth ? (el.clientWidth - 2) / st.scrollWidth : 1;
    const hz = ov > 0 ? (st.offsetHeight - ov - 1) / st.offsetHeight : 1;
    const z = Math.min(1, wz, hz);
    if (z < 1) st.style.zoom = Math.max(min, z).toFixed(3);
    return over() <= 0 && st.getBoundingClientRect().width <= el.clientWidth + 1;
  };
  if (fitZoom(0.8)) return;
  // جا برای نمودار خوانا نیست: فقط عددها (ویجت را بزرگ‌تر کنید تا نمودار هم دیده شود)
  el.classList.add("db-nochart"); el.title = I18N.t("برای دیدن نمودار، ویجت را بزرگ‌تر کنید.");
  fitZoom(0.55);
}
function dbGaugeSvg(v, max, wn, cr, unit, label) {
  const f = v === null || v === undefined ? 0 : Math.max(0, Math.min(1, v / max));
  const cls = v === null || v === undefined ? "mute" : v >= cr ? "err" : v >= wn ? "warn" : "ok";
  const R = 40, cx = 50, cy = 52, a = Math.PI * (1 - f), x = cx + R * Math.cos(a), y = cy - R * Math.sin(a);
  const mark = (t) => { const b = Math.PI * (1 - Math.min(1, t / max)); return `<line x1="${cx + 33 * Math.cos(b)}" y1="${cy - 33 * Math.sin(b)}" x2="${cx + 47 * Math.cos(b)}" y2="${cy - 47 * Math.sin(b)}" class="db-gm"/>`; };
  const txt = v === null || v === undefined ? "—" : `${num(Math.round(v * 10) / 10)}${unit === "%" ? "%" : unit ? " " + unit : ""}`;
  return `<svg class="db-gauge" viewBox="0 0 100 62"><path d="M${cx - R} ${cy} A${R} ${R} 0 0 1 ${cx + R} ${cy}" class="db-gb"/>
    ${f > 0.002 ? `<path d="M${cx - R} ${cy} A${R} ${R} 0 0 1 ${x.toFixed(2)} ${y.toFixed(2)}" class="db-gv c-${cls}"/>` : ""}${mark(wn)}${mark(cr)}
    <text x="${cx}" y="${cy - 4}" text-anchor="middle" class="db-gt">${esc(txt)}</text><text x="${cx}" y="${cy + 9}" text-anchor="middle" class="db-gl">${esc(label)}</text></svg>`;
}
function dbSpark(vals) {
  const pts = vals.map((v, i) => [i, v]).filter((p) => p[1] !== null && p[1] !== undefined);
  if (pts.length < 2) return "";
  const W = 200, H = 40, mn = Math.min(...pts.map((p) => p[1])), mx = Math.max(...pts.map((p) => p[1])), sp = mx - mn || 1, n = vals.length - 1 || 1;
  const line = pts.map(([i, v]) => `${((i / n) * W).toFixed(1)},${(H - 2 - ((v - mn) / sp) * (H - 6)).toFixed(1)}`).join(" ");
  return `<svg class="db-spk" viewBox="0 0 ${W} ${H}" preserveAspectRatio="none"><polyline points="${line}"/></svg>`;
}
/** نمای سبک یک نقشه (بدون ویرایش): لینک‌ها با رنگ وضعیت/بار، گره‌ها با رنگ وضعیت */
function dbMapSvg(g, st) {
  const D = g.data, devs = new Map((g.devices || []).map((d) => [d.id, d])), maps = new Map((g.maps || []).map((m) => [m.id, m]));
  const NS = (n) => (st && st.nodes[n.id]) || { st: n.t === "dev" || n.t === "map" ? "unknown" : "x" };
  const name = (n) => n.label || (n.t === "dev" ? ((devs.get(n.tid) || {}).name || NS(n).name || "?") : n.t === "map" ? ((maps.get(n.map) || {}).name || "?") : n.t === "cloud" ? I18N.t("اینترنت") : "");
  const icon = (n) => n.t === "cloud" ? n.icon || "internet" : n.icon || (n.t === "dev" && (devs.get(n.tid) || {}).icon) || "other";
  const vb = nmFitBox(D);
  let s = "";
  for (const n of D.nodes.filter((x) => x.t === "area")) {
    const c = NM_AREA_C[n.color] || NM_AREA_C.blue;
    s += `<rect x="${n.x}" y="${n.y}" width="${n.w}" height="${n.h}" rx="14" style="fill:${c};fill-opacity:.06;stroke:${c};stroke-opacity:.45" stroke-dasharray="7 5" stroke-width="1.5"/>
      ${n.label ? `<text x="${n.x + n.w - 12}" y="${n.y + 22}" class="nm-alab" style="fill:${c}">${esc(n.label)}</text>` : ""}`;
  }
  for (const L of nmLinkGeom(D)) {
    const ls = (st && st.links[L.l.id]) || { st: "unk" };
    let cls = "nm-l", col = "", dash = "";
    if (ls.st === "down" || ls.st === "dev") { cls += " err"; dash = ls.st === "dev" ? "8 6" : ""; }
    else if (ls.st === "unk") { cls += " unr"; dash = "3 5"; }
    else if (ls.st === "off") { cls += " mute"; dash = "2 5"; }
    else if (ls.util != null) col = NM_UC(ls.util);
    else cls += " nodata";
    s += `<line x1="${L.x1}" y1="${L.y1}" x2="${L.x2}" y2="${L.y2}" class="${cls}" stroke-width="4" ${dash ? `stroke-dasharray="${dash}"` : ""} ${col ? `style="stroke:${col}"` : ""}><title>${esc((L.l.pa || "") + " ⇄ " + (L.l.pb || ""))}</title></line>`;
  }
  for (const n of D.nodes.filter((x) => x.t !== "area")) {
    if (n.t === "text") { s += `<text x="${n.x}" y="${n.y}" class="nm-text" style="font-size:${NM_TSZ[n.size] || 17}px" text-anchor="middle" dominant-baseline="middle">${esc(n.label)}</text>`; continue; }
    const ns = NS(n), z = NM_SZ[n.size] || 44, h = z / 2, cls = n.t === "dev" || n.t === "map" ? NM_NCLS[ns.st] || "mute" : "ext";
    const ic = n.t === "map" ? NM_MAPIC : icon(n) === "core" ? NM_CORE : MON_ICON_SVG[icon(n)] || MON_ICON_SVG.other;
    const nm = name(n);
    s += `<g class="nm-node ${cls}"><title>${esc(nm)}</title>${ns.st === "down" ? `<circle cx="${n.x}" cy="${n.y}" r="${h + 13}" class="nm-halo"/>` : ""}
      <rect x="${n.x - h}" y="${n.y - h}" width="${z}" height="${z}" rx="${n.t === "cloud" ? h : 9}" class="nm-nb"/>
      <svg x="${n.x - h * 0.72}" y="${n.y - h * 0.72}" width="${z * 0.72}" height="${z * 0.72}" viewBox="0 0 24 24" class="nm-ic" fill="none" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">${ic}</svg>
      <text x="${n.x}" y="${n.y + h + 16}" class="nm-name${/^[\x20-\x7e]+$/.test(nm) ? " ltr" : ""}" text-anchor="middle">${esc(nm)}</text></g>`;
  }
  return `<svg class="db-map" viewBox="${vb.x} ${vb.y} ${vb.w} ${vb.h}" preserveAspectRatio="xMidYMid meet" data-no-i18n>${s}</svg>`;
}

/* ---------------------------------------------------------------- ساخت، ویرایش، ذخیره */
function dbSample() {
  const W = (type, x, y, w, h, cfg = {}) => ({ id: dbUid("w"), type, x, y, w, h, title: "", cfg });
  return { range: "1h", rotate: 30, refresh: 30, pages: [{ id: dbUid("p"), name: I18N.t("نمای کلی"), widgets: [
    W("status", 0, 0, 5, 2), W("severity", 5, 0, 4, 2), W("clock", 9, 0, 3, 2),
    W("problems", 0, 2, 7, 4), W("topn", 7, 2, 5, 4, { key: "cpu", n: 6 }),
    W("avail", 0, 6, 6, 4, { n: 8 }), W("topn", 6, 6, 6, 4, { key: "traffic", n: 6 }),
  ] }] };
}
async function dbNew() {
  if (DB.edit) return;
  const both = DB.canShared && DB.personalOk;
  const v = await openModal({ title: "داشبورد تازه", body: `<div class="field"><label>نام</label><input class="input" id="dbNn" maxlength="60" autofocus></div>
    ${both ? `<div class="field"><label>نوع</label><div class="seg" id="dbNk"><button data-v="0" class="on">مشترک (همه می‌بینند)</button><button data-v="1">شخصی (فقط خودم)</button></div></div>`
      : !DB.canShared ? `<p class="hint">این داشبورد شخصی است و فقط خودتان آن را می‌بینید.</p>` : ""}
    <div class="field"><label>شروع با</label><div class="seg" id="dbNt"><button data-v="sample" class="on">چیدمان نمونه</button><button data-v="empty">صفحه‌ی خالی</button></div></div>`,
    foot: `<button class="btn ghost" data-r="0">انصراف</button><button class="btn primary" data-r="1">ساخت و ویرایش</button>`,
    onOpen: (m, close) => {
      $$(".seg", m).forEach((sg) => sg.addEventListener("click", (e) => { const b = e.target.closest("button"); if (!b) return; $$("button", sg).forEach((x) => x.classList.toggle("on", x === b)); }));
      const ok = () => { const n = $("#dbNn", m).value.trim(); if (!n) { $("#dbNn", m).focus(); return; }
        close({ name: n, personal: both ? $("#dbNk .on", m).dataset.v === "1" : !DB.canShared, tpl: $("#dbNt .on", m).dataset.v }); };
      $$("[data-r]", m).forEach((b) => (b.onclick = () => (b.dataset.r === "1" ? ok() : close(null))));
      $("#dbNn", m).onkeydown = (e) => { if (e.key === "Enter") ok(); };
    } });
  if (!v) return;
  const data = v.tpl === "sample" ? dbSample() : { range: "1h", rotate: 30, refresh: 30, pages: [{ id: dbUid("p"), name: I18N.t("صفحه ۱"), widgets: [] }] };
  const r = await api("dash_save", { name: v.name, personal: v.personal, data });
  if (!r.ok) { toast(r.error, "error"); return; }
  DB.cur = { id: r.id }; DB.page = 0; dbLs("cur", String(r.id));
  await dashRender();
  dbEditOn();
}
function dbEditOn() {
  if (!DB.cur || DB.edit) return;
  DB.edit = true; DB.rot = false; DB.dirty = false;
  DB.draft = JSON.parse(JSON.stringify(DB.cur));
  dbShell(); dbDraw();
}
async function dbEditCancel() {
  if (DB.dirty && !(await confirm2({ title: "لغو تغییرها", body: "<p>تغییرهای ذخیره‌نشده‌ی این داشبورد لغو شود؟</p>", confirm: "لغو تغییرها", danger: true }))) return;
  DB.edit = false; DB.draft = null; DB.dirty = false;
  if (DB.page >= DB.cur.data.pages.length) DB.page = 0;
  dbShell(); dbDraw();
}
async function dbEditSave() {
  const D = DB.draft;
  const r = await api("dash_save", { id: D.id, name: D.name, data: D.data });
  if (!r.ok) { toast(r.error, "error"); return; }
  toast("داشبورد ذخیره شد", "ok");
  DB.edit = false; DB.draft = null; DB.dirty = false; DB.cache.clear();
  await dashRender();
}
/** پیش از رفتن به صفحه‌ی دیگر (go) در حالت ویرایش */
async function dbCanLeave() {
  if (!DB.edit || !DB.dirty) { DB.edit = false; return true; }
  const ok = await confirm2({ title: "تغییرهای ذخیره‌نشده", body: "<p>تغییرهای داشبورد ذخیره نشده است. بدون ذخیره خارج شوید؟</p>", confirm: "خروج بدون ذخیره", danger: true });
  if (ok) { DB.edit = false; DB.draft = null; DB.dirty = false; }
  return ok;
}
async function dbSettings() {
  const D = DB.draft;
  const v = await openModal({ title: "تنظیمات داشبورد", body: `<div class="field"><label>نام</label><input class="input" id="dsN" maxlength="60" value="${esc(D.name)}" data-no-i18n></div>
    <div class="row" style="gap:12px"><div class="field" style="flex:1"><label>بازه‌ی پیش‌فرض نمودارها</label><select class="input" id="dsR">${Object.entries(DB_RANGES).map(([k, t]) => `<option value="${k}" ${k === D.data.range ? "selected" : ""}>${esc(I18N.t(t))}</option>`).join("")}</select></div>
      <div class="field" style="flex:1"><label>به‌روزرسانی (ثانیه)</label><input class="input ltr" id="dsF" type="number" min="10" max="600" value="${D.data.refresh || 30}"></div>
      <div class="field" style="flex:1"><label>نمایش خودکار: هر صفحه (ثانیه)</label><input class="input ltr" id="dsT" type="number" min="5" max="3600" value="${D.data.rotate || 30}"></div></div>
    <p class="hint">داده‌ی ویجت‌ها از همان بررسی عادی مانیتورینگ است و ساختن داشبورد بار تازه‌ای روی دستگاه‌ها نمی‌گذارد.</p>
    ${D.personal ? `<p class="hint">این داشبورد شخصی است.</p>` : ""}
    <hr><button class="btn danger sm" id="dsDel">حذف این داشبورد</button>`,
    foot: `<button class="btn ghost" data-r="0">انصراف</button><button class="btn primary" data-r="1">تأیید</button>`,
    onOpen: (m, close) => {
      $$("[data-r]", m).forEach((b) => (b.onclick = () => close(b.dataset.r === "1" ? { name: $("#dsN", m).value.trim(), range: $("#dsR", m).value,
        refresh: Number($("#dsF", m).value) || 30, rotate: Number($("#dsT", m).value) || 30 } : null)));
      $("#dsDel", m).onclick = () => close("del");
    } });
  if (v === "del") {
    if (!(await confirm2({ title: "حذف داشبورد", body: `<p>داشبورد «<span class="bidi">${esc(D.name)}</span>» حذف شود؟ این کار برگشت ندارد.</p>`, confirm: "حذف", danger: true }))) return;
    const r = await api("dash_delete", D.id);
    if (!r.ok) { toast(r.error, "error"); return; }
    DB.edit = false; DB.draft = null; DB.dirty = false; DB.cur = null; DB.page = 0; dbLs("cur", "");
    toast("داشبورد حذف شد", "ok");
    await dashRender();
    return;
  }
  if (!v) return;
  if (v.name) D.name = v.name;
  D.data.range = v.range; D.data.refresh = Math.max(10, Math.min(600, v.refresh)); D.data.rotate = Math.max(5, Math.min(3600, v.rotate));
  DB.dirty = true; dbShell(); dbDraw();
}

/* ---------------------------------------------------------------- فهرست ویجت‌ها (حالت ویرایش) */
function dbLibHtml() {
  return `<aside class="db-lib"><h3>افزودن ویجت</h3><p class="muted">کلیک کنید یا روی صفحه بکشید</p>
    ${Object.entries(DB_TYPES).map(([k, [t, ic, , , d]]) => `<div class="db-li" draggable="true" data-add="${k}" title="${esc(I18N.t(d))}"><span class="db-lic">${ic}</span><span><b>${esc(I18N.t(t))}</b><small>${esc(I18N.t(d))}</small></span></div>`).join("")}</aside>`;
}
function dbLibBind() {
  $$("[data-add]").forEach((it) => {
    it.onclick = () => dbAdd(it.dataset.add);
    it.ondragstart = (e) => { e.dataTransfer.setData("text/akrp-w", it.dataset.add); e.dataTransfer.effectAllowed = "copy"; };
  });
  const g = $("#dbGrid");
  g.ondragover = (e) => { if ([...e.dataTransfer.types].includes("text/akrp-w")) { e.preventDefault(); e.dataTransfer.dropEffect = "copy"; } };
  g.ondrop = (e) => {
    const k = e.dataTransfer.getData("text/akrp-w"); if (!DB_TYPES[k]) return;
    e.preventDefault();
    const c = dbCell(e.clientX, e.clientY);
    dbAdd(k, c.x, c.y);
  };
}
function dbCell(cx, cy) {
  const g = $("#dbGrid"), b = g.getBoundingClientRect(), cw = (b.width + DB_GAP) / DB_COLS;
  const px = dbRtl() ? b.right - cx : cx - b.left;
  return { x: Math.max(0, Math.min(DB_COLS - 1, Math.floor(px / cw))), y: Math.max(0, Math.floor((cy - b.top) / (DB_ROW + DB_GAP))) };
}
function dbAdd(type, x, y) {
  const ws = dbWs();
  if (ws.length >= 60) { toast("حداکثر ۶۰ ویجت در هر صفحه.", "warn"); return; }
  const [, , w, h] = DB_TYPES[type];
  const it = { id: dbUid("w"), type, x: x === undefined ? 0 : Math.min(x, DB_COLS - w), y: y === undefined ? dbRowsUsed(ws) : y, w, h, title: "", cfg: dbDefCfg(type) };
  ws.push(it); dbLayout(ws, it.id); dbLayout(ws, null); DB.dirty = true;
  dbDraw();
  const el = $(`.db-w[data-w="${it.id}"]`); if (el) { el.scrollIntoView({ block: "nearest", behavior: "smooth" }); el.classList.add("flash"); }
  if (["traffic", "metric", "gauge", "value", "map", "text"].includes(type)) dbCfg(it.id);
}
function dbDefCfg(type) {
  const first = [...DB.tg.values()].find((t) => t.kind === "snmp");
  switch (type) {
    case "metric": return { tid: first ? first.id : 0, keys: ["cpu", "mem"], range: "" };
    case "traffic": return { tid: first ? first.id : 0, ports: [], range: "" };
    case "gauge": return { tid: first ? first.id : 0, key: "cpu" };
    case "value": return { tid: first ? first.id : 0, key: "cpu" };
    case "topn": return { key: "cpu", n: 5 };
    case "avail": return { n: 8, range: "24h" };
    case "events": return { n: 20, kinds: [], sev: [], range: "" };
    case "problems": return { n: 50 };
    case "text": return { text: "", size: "m", align: "start" };
    default: return {};
  }
}
/* چیدمان: برخورد ← ویجت‌های دیگر پایین می‌روند؛ سپس همه تا جای ممکن بالا می‌آیند (مثل Grafana و Zabbix) */
function dbHit(a, b) { return a !== b && a.x < b.x + b.w && b.x < a.x + a.w && a.y < b.y + b.h && b.y < a.y + a.h; }
function dbLayout(ws, fixedId) {
  const fixed = fixedId ? ws.find((w) => w.id === fixedId) : null;
  const rest = ws.filter((w) => w !== fixed).sort((a, b) => a.y - b.y || a.x - b.x);
  const placed = fixed ? [fixed] : [];
  for (const w of rest) {
    w.x = Math.max(0, Math.min(DB_COLS - w.w, w.x)); w.y = Math.max(0, w.y);
    while (w.y > 0 && !placed.some((p) => dbHit({ ...w, y: w.y - 1 }, p))) w.y--;
    while (placed.some((p) => dbHit(w, p))) w.y++;
    placed.push(w);
  }
}
function dbBindEdit(g) {
  $$(".db-w", g).forEach((el) => {
    const id = el.dataset.w;
    $$("[data-wa]", el).forEach((b) => (b.onclick = (e) => {
      e.stopPropagation();
      const ws = dbWs(), i = ws.findIndex((w) => w.id === id); if (i < 0) return;
      if (b.dataset.wa === "cfg") dbCfg(id);
      else if (b.dataset.wa === "del") { ws.splice(i, 1); dbLayout(ws, null); DB.dirty = true; dbDraw(); }
      else if (b.dataset.wa === "dup") {
        if (ws.length >= 60) { toast("حداکثر ۶۰ ویجت در هر صفحه.", "warn"); return; }
        const c = { ...JSON.parse(JSON.stringify(ws[i])), id: dbUid("w"), y: ws[i].y + ws[i].h };
        ws.push(c); dbLayout(ws, c.id); dbLayout(ws, null); DB.dirty = true; dbDraw();
      }
    }));
    el.onpointerdown = (e) => {
      if (e.button !== 0 || e.target.closest("[data-wa]")) return;
      const rs = !!e.target.closest(".db-rs");
      const w = dbWs().find((x) => x.id === id); if (!w) return;
      e.preventDefault();
      const b = g.getBoundingClientRect();
      DB.drag = { id, rs, sx: e.clientX, sy: e.clientY, o: { x: w.x, y: w.y, w: w.w, h: w.h }, cw: (b.width + DB_GAP) / DB_COLS, snap: JSON.stringify(dbWs().map((x) => [x.id, x.x, x.y])) };
      el.classList.add(rs ? "resizing" : "dragging");
      el.setPointerCapture(e.pointerId);
    };
    el.onpointermove = (e) => {
      const d = DB.drag; if (!d || d.id !== id) return;
      const ws = dbWs(), w = ws.find((x) => x.id === id);
      const dxp = (e.clientX - d.sx) * (dbRtl() ? -1 : 1), dc = Math.round(dxp / d.cw), dr = Math.round((e.clientY - d.sy) / (DB_ROW + DB_GAP));
      const pos = JSON.parse(d.snap); ws.forEach((x) => { const p = pos.find((q) => q[0] === x.id); if (p) { x.x = p[1]; x.y = p[2]; } });
      if (d.rs) { w.w = Math.max(1, Math.min(DB_COLS - w.x, d.o.w + dc)); w.h = Math.max(1, Math.min(24, d.o.h + dr)); }
      else { w.x = Math.max(0, Math.min(DB_COLS - w.w, d.o.x + dc)); w.y = Math.max(0, d.o.y + dr); }
      dbLayout(ws, id);
      g.style.gridTemplateRows = `repeat(${dbRowsUsed(ws) + 4}, ${DB_ROW}px)`;
      ws.forEach((x) => { const e2 = $(`.db-w[data-w="${x.id}"]`, g); if (e2) dbPos(e2, x); });
    };
    const end = () => {
      const d = DB.drag; if (!d || d.id !== id) return;
      DB.drag = null; el.classList.remove("dragging", "resizing");
      const ws = dbWs(), w = ws.find((x) => x.id === id);
      dbLayout(ws, null);
      if (w && (w.x !== d.o.x || w.y !== d.o.y || w.w !== d.o.w || w.h !== d.o.h)) DB.dirty = true;
      ws.forEach((x) => { const e2 = $(`.db-w[data-w="${x.id}"]`, g); if (e2) dbPos(e2, x); });
      g.style.gridTemplateRows = `repeat(${dbRowsUsed(ws) + 4}, ${DB_ROW}px)`;
      if (d.rs && w) { const b2 = $(`.db-w[data-w="${id}"] .db-wb`, g); if (b2) { b2.innerHTML = ""; dbBody(w, b2, false); } }
    };
    el.onpointerup = end; el.onpointercancel = end;
  });
}

/* ---------------------------------------------------------------- تنظیم یک ویجت */
function dbTgOpts(sel, snmpOnly) {
  const L = [...DB.tg.values()].filter((t) => !snmpOnly || t.kind === "snmp").sort((a, b) => (a.grp || "").localeCompare(b.grp || "", "fa") || a.name.localeCompare(b.name, "fa"));
  return `<option value="">—</option>` + L.map((t) => `<option value="${t.id}" ${Number(sel) === t.id ? "selected" : ""} data-no-i18n>${esc(t.name)}${t.grp ? " · " + esc(t.grp) : ""}</option>`).join("");
}
function dbGroups() { return [...new Set([...DB.tg.values()].map((t) => t.grp || "").filter(Boolean))].sort((a, b) => a.localeCompare(b, "fa")); }
function dbChips(id, opts, cur, multi) {
  return `<div class="db-chips" id="${id}" data-multi="${multi ? 1 : 0}">${opts.map(([v, t]) => `<button type="button" data-v="${esc(v)}" class="${(multi ? cur.includes(v) : cur === v) ? "on" : ""}">${esc(I18N.t(t))}</button>`).join("")}</div>`;
}
function dbChipVal(m, id) { const el = $("#" + id, m); if (!el) return null; const on = $$("button.on", el).map((b) => b.dataset.v); return el.dataset.multi === "1" ? on : on[0] || ""; }
async function dbCfg(wid) {
  const ws = dbWs(), w = ws.find((x) => x.id === wid); if (!w) return;
  const c = w.cfg || {}, T = w.type;
  const rangeF = ["traffic", "metric", "avail", "events"].includes(T)
    ? `<div class="field"><label>بازه</label>${dbChips("dcR", [["", "مثل داشبورد"], ...Object.entries(DB_RANGES)], c.range || "", false)}</div>` : "";
  const scopeF = ["status", "severity", "problems", "topn", "avail"].includes(T)
    ? `<div class="row" style="gap:12px"><div class="field" style="flex:1"><label>گروه</label><select class="input" id="dcG"><option value="">همه‌ی گروه‌ها</option>${dbGroups().map((g) => `<option ${g === c.grp ? "selected" : ""} data-no-i18n>${esc(g)}</option>`).join("")}</select></div>
        <div class="field" style="flex:2"><label>یا فقط این هدف‌ها (خالی = همه)</label><select class="input" id="dcTs" multiple size="4">${[...DB.tg.values()].sort((a, b) => a.name.localeCompare(b.name, "fa")).map((t) => `<option value="${t.id}" ${(c.tids || []).map(Number).includes(t.id) ? "selected" : ""} data-no-i18n>${esc(t.name)}</option>`).join("")}</select></div></div>` : "";
  const nF = (def, mx) => `<div class="field"><label>تعداد ردیف</label><input class="input ltr" id="dcN" type="number" min="1" max="${mx}" value="${c.n || def}" style="max-width:110px"></div>`;
  let extra = "";
  if (["traffic", "metric", "gauge", "value"].includes(T)) extra += `<div class="field"><label>دستگاه</label><select class="input" id="dcT">${dbTgOpts(c.tid, T !== "value")}</select></div>`;
  if (T === "traffic") extra += `<div class="field"><label>پورت (یک یا چند؛ حداکثر ۴)</label><div id="dcP" class="db-chips" data-multi="1"><span class="muted">…</span></div><p class="hint">نمودار فقط برای پورت‌هایی است که تاریخچه‌ی ترافیک‌شان ثبت می‌شود (تنظیم SNMP هدف).</p></div>`;
  if (T === "metric") extra += `<div class="field"><label>مقدارها</label>${dbChips("dcK", Object.entries(DB_KEYS).map(([k, v]) => [k, v[0]]), c.keys || ["cpu"], true)}</div>`;
  if (T === "gauge") extra += `<div class="field"><label>مقدار</label>${dbChips("dcK", Object.entries(DB_KEYS).filter(([k]) => k !== "rtt").map(([k, v]) => [k, v[0]]), c.key || "cpu", false)}</div>
    <div class="row" style="gap:12px"><div class="field"><label>هشدار از</label><input class="input ltr" id="dcW" type="number" value="${c.warn || ""}" placeholder="75"></div><div class="field"><label>بحرانی از</label><input class="input ltr" id="dcC" type="number" value="${c.crit || ""}" placeholder="90"></div></div>`;
  if (T === "value") extra += `<div class="field"><label>مقدار</label>${dbChips("dcK", Object.entries(DB_VKEYS).map(([k, v]) => [k, v[0]]), c.key || "cpu", false)}</div>`;
  if (T === "topn") extra += `<div class="field"><label>بر اساس</label>${dbChips("dcK", Object.entries(DB_TOPK), c.key || "cpu", false)}</div>${nF(5, 30)}`;
  if (T === "avail" || T === "problems") extra += nF(T === "avail" ? 8 : 50, 100);
  if (T === "problems") extra += `<label class="chk"><input type="checkbox" id="dcM" ${c.maint ? "checked" : ""}>هدف‌های در حال نگهداری هم نمایش داده شوند</label>`;
  if (T === "events") extra += `<div class="field"><label>نوع</label>${dbChips("dcEk", [["trap", "Trap"], ["syslog", "Syslog"]], c.kinds || [], true)}</div>
    <div class="field"><label>سطح (هیچ = همه)</label>${dbChips("dcEs", [["crit", "بحرانی"], ["warn", "هشدار"], ["info", "اطلاع"], ["ok", "برطرف"]], c.sev || [], true)}</div>${nF(20, 100)}`;
  if (T === "map") extra += `<div class="field"><label>نقشه</label><select class="input" id="dcMp"><option value="">…</option></select></div>`;
  if (T === "clock") extra += `<label class="chk"><input type="checkbox" id="dcS" ${c.sec ? "checked" : ""}>نمایش ثانیه</label>`;
  if (T === "text") extra += `<div class="field"><label>متن</label><textarea class="input" id="dcX" rows="4" maxlength="300">${esc(c.text || "")}</textarea></div>
    <div class="row" style="gap:12px"><div class="field"><label>اندازه</label>${dbChips("dcZ", [["s", "کوچک"], ["m", "متوسط"], ["l", "بزرگ"]], c.size || "m", false)}</div>
    <div class="field"><label>چینش</label>${dbChips("dcA", [["start", "کنار"], ["center", "وسط"]], c.align || "start", false)}</div></div>`;
  const v = await openModal({ title: `${I18N.t("تنظیم ویجت")}: ${I18N.t(DB_TYPES[T][0])}`, body: `<div class="field"><label>عنوان (خالی = پیش‌فرض)</label><input class="input" id="dcTi" maxlength="80" value="${esc(w.title || "")}" placeholder="${esc(I18N.t(dbDefTitle(w)))}"></div>
      ${extra}${scopeF}${rangeF}`,
    foot: `<button class="btn ghost" data-r="0">انصراف</button><button class="btn primary" data-r="1">اعمال</button>`,
    onOpen: (m, close) => {
      $$(".db-chips", m).forEach((el) => el.addEventListener("click", (e) => {
        const b = e.target.closest("button[data-v]"); if (!b) return;
        if (el.dataset.multi === "1") { if (!b.classList.contains("on") && el.id === "dcP" && $$("button.on", el).length >= 4) { toast("حداکثر ۴ پورت.", "warn"); return; } b.classList.toggle("on"); }
        else $$("button", el).forEach((x) => x.classList.toggle("on", x === b));
      }));
      const loadPorts = async () => {
        const P = $("#dcP", m); if (!P) return;
        const tid = Number($("#dcT", m).value);
        if (!tid) { P.innerHTML = `<span class="muted">${esc(I18N.t("اول دستگاه را انتخاب کنید."))}</span>`; return; }
        const r = await api("mon_snmp_live", tid, 0, true);
        if (!P.isConnected) return;
        const ifs = r.ok && !r.none ? (r.ifs || []).filter((x) => x.type !== 24) : [];
        const cur = tid === Number(c.tid) ? c.ports || [] : [];
        P.innerHTML = ifs.length ? ifs.slice(0, 400).map((x) => `<button type="button" data-v="${esc(x.name)}" class="ltr${cur.includes(x.name) ? " on" : ""}${x.oper === 1 ? "" : " off"}" title="${esc(x.alias || "")}" data-no-i18n>${esc(x.name)}</button>`).join("")
          : `<span class="muted">${esc(I18N.t("هنوز داده‌ی زنده‌ای از این دستگاه نیامده است."))}</span>`;
      };
      if ($("#dcT", m)) $("#dcT", m).onchange = loadPorts;
      loadPorts();
      if ($("#dcMp", m)) api("mon_map_list").then((r) => {
        const s = $("#dcMp", m); if (!s) return;
        const L = r.ok ? r.maps || [] : [];
        s.innerHTML = L.length ? `<option value="">—</option>` + L.map((x) => `<option value="${x.id}" ${x.id === Number(c.map) ? "selected" : ""} data-no-i18n>${esc(x.name)}</option>`).join("")
          : `<option value="">${esc(I18N.t(r.ok ? "هنوز نقشه‌ای ساخته نشده است." : r.error || ""))}</option>`;
      });
      $$("[data-r]", m).forEach((b) => (b.onclick = () => {
        if (b.dataset.r !== "1") { close(null); return; }
        const o = {}, g = (id) => $("#" + id, m);
        if (g("dcT")) o.tid = Number(g("dcT").value) || 0;
        if (g("dcP")) o.ports = dbChipVal(m, "dcP").slice(0, 4);
        if (T === "metric") { o.keys = dbChipVal(m, "dcK"); if (!o.keys.length) o.keys = ["cpu"]; }
        if (["gauge", "value", "topn"].includes(T)) o.key = dbChipVal(m, "dcK");
        if (g("dcW")) { o.warn = Number(g("dcW").value) || 0; o.crit = Number(g("dcC").value) || 0; }
        if (g("dcN")) o.n = Math.max(1, Math.min(100, Number(g("dcN").value) || 0)) || undefined;
        if (g("dcM")) o.maint = g("dcM").checked;
        if (g("dcEk")) { o.kinds = dbChipVal(m, "dcEk"); o.sev = dbChipVal(m, "dcEs"); }
        if (g("dcMp")) o.map = Number(g("dcMp").value) || 0;
        if (g("dcS")) o.sec = g("dcS").checked;
        if (g("dcX")) { o.text = g("dcX").value; o.size = dbChipVal(m, "dcZ"); o.align = dbChipVal(m, "dcA"); }
        if (g("dcG")) { o.grp = g("dcG").value; o.tids = [...g("dcTs").selectedOptions].map((x) => Number(x.value)); }
        if (g("dcR")) o.range = dbChipVal(m, "dcR");
        close({ title: g("dcTi").value.trim(), cfg: o });
      }));
    } });
  if (!v) return;
  w.title = v.title; w.cfg = v.cfg; DB.dirty = true;
  const el = $(`.db-w[data-w="${wid}"]`);
  if (el) { $(".db-wh h3", el).innerHTML = dbTitleHtml(w); const b = $(".db-wb", el); b.innerHTML = ""; delete b.dataset.k; dbBody(w, b, false); }
}
