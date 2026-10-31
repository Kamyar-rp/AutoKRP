"use strict";
/* ================================================================ صفحه‌ی مانیتورینگ: نمای کارت و جدول (1.35)
 * نماهای ذخیره‌شده برای هر کاربر (save_ui «mon_views»)، «حالت ویرایش» (ستون‌ها و ترتیب، اندازه‌ی صفحه، قالب نمایش و
 * پورت‌های نمایشی هر دستگاه؛ همه پیش‌نویس تا «اعمال»)، فیلتر/جستجو/مرتب‌سازی/صفحه‌بندی سمت رابط، و فقط تغییرات
 * (mon_rows با rev) به‌جای فهرست کامل هر ۵ ثانیه. قالب‌های نمایش (فقط ادمین) در همین فایل. از app.js، monitor.js و snmp.js. */
const MV_COLS = { status: "وضعیت", name: "نام", host: "آدرس", grp: "گروه", policy: "سیاست پایش", rtt: "زمان پاسخ", avail: "در دسترس بودن ۲۴ ساعت",
  cpu: "CPU", mem: "حافظه", temp: "دما", disk: "دیسک", uptime: "Uptime", ports_up: "پورت‌های وصل", traffic: "ترافیک", alarms: "هشدارها",
  last: "آخرین بررسی", interval: "بازه", kind: "روش" };
const MV_DEF_COLS = ["status", "name", "host", "rtt", "avail", "cpu", "mem", "traffic", "alarms"];
const MV_CARD = { rtt: "زمان پاسخ", avail: "در دسترس بودن", cpu: "CPU", mem: "حافظه", temp: "دما", disk: "دیسک", uptime: "Uptime",
  ports_up: "پورت‌های وصل", traffic: "ترافیک", alarms: "هشدارها", sessions: "نشست‌ها", hw: "سلامت سخت‌افزار", err_ports: "پورت‌های دارای خطا" };
const MV_TABS = { sum: "خلاصه", ports: "پورت‌ها", hw: "سخت‌افزار", oids: "OIDها و وضعیت‌ها", charts: "نمودارها" };
const MV_CHARTS = { cpu_mem: "CPU و حافظه", traffic: "ترافیک پورت‌های نمایشی", temp: "دما", rtt: "زمان پاسخ", sessions: "نشست‌های فعال" };
const MV_FILTER = [["", "همه"], ["prob", "مشکل‌دار"], ["down", "قطع"], ["alarm", "هشدار"], ["maint", "در نگهداری"], ["paused", "متوقف"]];
const MV_RANK = { down: 0, unreachable: 1, alarm: 2, slow: 3, unknown: 4, up: 5, paused: 6 };
const MV = { rev: 0, rows: {}, page: 0, edit: null, view: null, sel: new Set(), filter: "", q: "", grp: "" };

/* ---------------------------------------------------------------- نماها */
function mvViews() { return (S.settings && S.settings.ui && S.settings.ui.mon_views) || { cur: "", list: [] }; }
function mvDefault() { return { name: "", mode: "cards", cols: [...MV_DEF_COLS], sort: "status", dir: 1, status: [], q: "", grp: "", size: 100 }; }
function mvCurrent() {
  if (MV.view) return MV.view;
  const v = mvViews(), x = v.list.find((o) => o.name === v.cur);
  MV.view = x ? JSON.parse(JSON.stringify(x)) : mvDefault();
  MV.filter = (MV.view.status || [])[0] || ""; MV.q = MV.view.q || ""; MV.grp = MV.view.grp || "";
  return MV.view;
}
async function mvSaveViews(v) {
  const r = await api("save_ui", "mon_views", v);
  if (!r.ok) { toast(r.error, "error"); return false; }
  if (S.settings) { S.settings.ui = S.settings.ui || {}; S.settings.ui.mon_views = v; }
  return true;
}

/* ---------------------------------------------------------------- داده (فقط تغییرات) */
function mvMerge(rows) {
  rows.forEach((r) => {
    MV.rows[r.id] = r;
    const t = MON.targets.find((x) => x.id === r.id);
    if (!t) return;
    if (t.enabled || r.st !== "paused") t.status = r.st;
    Object.assign(t, { since: r.since, rtt: r.rtt, err: r.err, maint: r.maint, cause: r.cause, last: r.last, spark: r.spark });
  });
}
async function mvTick() {
  if (S.page !== "monitor" || document.hidden || modalClose || monLoading || (MON.tab || "targets") !== "targets") return;
  const r = await api("mon_rows", MV.rev);
  if (!r.ok) return;
  if (r.cfg_rev !== MON.cfgRev || r.ids.length !== MON.targets.length || r.ids.some((i) => !MON.targets.find((t) => t.id === i))) return loadMon();
  MV.rev = r.rev;
  if (!r.rows.length) return;
  mvMerge(r.rows);
  monChips(); monBannerCap();
  mvRenderBody();
}
async function mvFirstRows() { MV.rev = 0; const r = await api("mon_rows", 0); if (r.ok) { MV.rev = r.rev; mvMerge(r.rows); } }

/* ---------------------------------------------------------------- مقدارها */
function mvState(t) {
  const r = MV.rows[t.id] || {};
  if (!t.enabled) return "paused";
  if (t.status === "up" && (r.lvl === "crit" || r.lvl === "warn")) return "alarm";
  return t.status || "unknown";
}
function mvVal(t, k) {
  const r = MV.rows[t.id] || {};
  switch (k) {
    case "status": return MV_RANK[mvState(t)] ?? 9;
    case "name": return (t.name || "").toLowerCase();
    case "host": return monWhere(t);
    case "grp": return t.grp || "";
    case "policy": return t.policy || "";
    case "rtt": return t.rtt ?? null;
    case "avail": return r.avail ?? null;
    case "cpu": return r.cpu ?? null;
    case "mem": return r.mem ?? null;
    case "temp": return r.temp ?? null;
    case "disk": return r.disk ?? null;
    case "uptime": return r.up ?? null;
    case "ports_up": return r.pn ? r.pu / r.pn : null;
    case "traffic": return (r.ports || []).reduce((s, p) => s + (p.in || 0) + (p.out || 0), 0) || null;
    case "alarms": return r.al || 0;
    case "last": return t.last || 0;
    case "interval": return t.eff_interval || t.interval;
    case "kind": return t.kind;
  }
  return null;
}
function mvSpark(h) {
  if (!h || h.length < 2) return "";
  const vals = h.flatMap((x) => [x[0] || 0, x[1] || 0]), mx = Math.max(1, ...vals), W = 90, H = 22, n = h.length - 1;
  const line = (i) => h.map((x, j) => `${(j * W / n).toFixed(1)},${(H - 1 - (x[i] || 0) / mx * (H - 2)).toFixed(1)}`).join(" ");
  return `<svg class="mv-spark" viewBox="0 0 ${W} ${H}" preserveAspectRatio="none"><polyline points="${line(0)}" class="in"/><polyline points="${line(1)}" class="out"/></svg>`;
}
function mvTraffic(t, withSpark) {
  const r = MV.rows[t.id] || {};
  const ps = r.ports || [];
  if (!ps.length) return t.kind === "snmp" ? `<span class="muted">—</span>` : "";
  return ps.map((p) => `<div class="mv-port"><span class="ltr mv-pn" title="${esc(p.a || p.n)}">${esc(p.n)}</span>
    <span class="ltr">↓${esc(fmtBps(p.in))} ↑${esc(fmtBps(p.out))}</span>${withSpark ? mvSpark(p.h) : ""}</div>`).join("");
}
function mvBar(v, warn = 80, crit = 95) {
  if (v === null || v === undefined) return `<span class="muted">—</span>`;
  const c = v >= crit ? "err" : v >= warn ? "warn" : "ok";
  return `<span class="mv-pct"><i class="${c}" style="width:${Math.max(2, Math.min(100, v))}%"></i></span><span class="ltr">${snPct(v)}</span>`;
}
function mvCell(t, k) {
  const r = MV.rows[t.id] || {}, now = Date.now() / 1000;
  switch (k) {
    case "status": {
      const s = mvState(t), st = s === "alarm" ? ["warn", "هشدار"] : MON_ST[s] || MON_ST.unknown;
      return `<span class="tag ${st[0]}">${st[1]}</span>${t.maint ? ` <span class="tag mnt">نگهداری</span>` : ""}${t.since && s !== "paused" ? `<div class="muted">${monDur(now - t.since)}</div>` : ""}`;
    }
    case "name": return `<span class="mv-nm">${monIcon(t.icon)}<b class="${snNameCls(t.name)}">${esc(t.name)}</b></span>${r.sys && r.sys !== t.name ? `<div class="muted ltr">${esc(r.sys)}</div>` : ""}`;
    case "host": return `<span class="ltr">${esc(monWhere(t))}</span>`;
    case "grp": return esc(t.grp || "—");
    case "policy": return esc(t.policy || "سفارشی");
    case "rtt": return t.rtt != null && t.status !== "down" ? `<span class="ltr">${num(t.rtt)} ms</span>` : `<span class="muted">—</span>`;
    case "avail": return r.avail == null ? `<span class="muted">—</span>` : `<span class="ltr ${r.avail >= 99.9 ? "" : r.avail >= 90 ? "c-warn" : "c-err"}">${num(r.avail)}٪</span>`;
    case "cpu": return mvBar(r.cpu);
    case "mem": return mvBar(r.mem, 85, 95);
    case "disk": return mvBar(r.disk, 85, 95);
    case "temp": return r.temp == null ? `<span class="muted">—</span>` : `<span class="ltr">${num(r.temp)}°C</span>`;
    case "uptime": return r.up == null ? `<span class="muted">—</span>` : esc(snUp(r.up));
    case "ports_up": return r.pn ? `<span class="ltr">${num(r.pu)} / ${num(r.pn)}</span>` : `<span class="muted">—</span>`;
    case "traffic": return mvTraffic(t, true) + (MV.edit && t.kind === "snmp" && t.can_edit ? `<button class="btn sm" data-mvports="${t.id}">پورت‌ها…</button>${MV.edit.ports[t.id] ? ` <span class="tag info">تغییر</span>` : ""}` : "");
    case "alarms": return r.al ? `<span class="tag ${r.lvl === "crit" ? "err" : "warn"}" title="${esc((r.alm || []).join(" · "))}">${num(r.al)}</span>` : `<span class="muted">—</span>`;
    case "last": return t.last ? `<span class="muted">${monDur(now - t.last)}</span>` : `<span class="muted">—</span>`;
    case "interval": return esc(monDur(t.eff_interval || t.interval));
    case "kind": return esc({ ping: "Ping", tcp: "TCP", http: "HTTP", snmp: "SNMP" }[t.kind] || t.kind);
  }
  return "";
}
function mvCardFields(t) {
  const r = MV.rows[t.id] || {}, tp = t.tpl_eff || {};
  const keys = t.kind === "snmp" ? (tp.card && tp.card.length ? tp.card : ["rtt", "cpu", "mem"]) : ["rtt", "avail"];
  const out = keys.map((k) => {
    switch (k) {
      case "rtt": return t.rtt != null && t.status !== "down" && t.status !== "paused" ? `<span class="ltr">${num(t.rtt)} ms</span>` : "";
      case "avail": return r.avail != null ? `<span>${num(r.avail)}٪</span>` : "";
      case "cpu": return r.cpu != null ? `<span class="ltr">CPU ${snPct(r.cpu)}</span>` : "";
      case "mem": return r.mem != null ? `<span class="ltr">RAM ${snPct(r.mem)}</span>` : "";
      case "temp": return r.temp != null ? `<span class="ltr">${num(r.temp)}°C</span>` : "";
      case "disk": return r.disk != null ? `<span>دیسک ${snPct(r.disk)}</span>` : "";
      case "uptime": return r.up != null ? `<span>${esc(snUp(r.up))}</span>` : "";
      case "ports_up": return r.pn ? `<span>${I18N.t("پورت")} ${num(r.pu)}/${num(r.pn)}</span>` : "";
      case "sessions": return r.ses != null ? `<span>${I18N.t("نشست")} ${num(r.ses)}</span>` : "";
      case "alarms": return "";
      case "hw": return r.hwn ? (r.hwb ? `<span class="tag ${r.hwc ? "err" : "warn"}">${I18N.t("سخت‌افزار")} ${num(r.hwb)}/${num(r.hwn)}</span>` : `<span class="tag ok">${I18N.t("سخت‌افزار سالم")}</span>`) : "";
      case "err_ports": return r.pe ? `<span class="tag warn">${num(r.pe)} ${I18N.t("پورت با خطا")}</span>` : "";
      case "traffic": return (r.ports || []).slice(0, 1).map((p) => `<span class="ltr" title="${esc(p.n)}">↓${esc(fmtBps(p.in))} ↑${esc(fmtBps(p.out))}</span>`).join("");
    }
    return "";
  }).filter(Boolean);
  const al = r.al && t.status !== "down" && t.status !== "paused" ? `<span class="tag ${r.lvl === "crit" ? "err" : "warn"}">${num(r.al)} هشدار</span>` : "";
  // 1.36: هر مقدار یک تکه‌ی جدا و بدون شکستن خط (به‌جای یک جمله‌ی به‌هم‌ریخته‌ی راست‌به‌چپ و چپ‌به‌راست)
  return (out.length ? `<span class="mon-snmp">${out.map((x) => `<span class="mv-f">${x}</span>`).join("")}</span>` : "") + al;
}

/* ---------------------------------------------------------------- فیلتر، مرتب‌سازی، صفحه */
function mvList() {
  const V = mvCurrent(), q = MV.q.trim().toLowerCase();
  let L = MON.targets.filter((t) => {
    const s = mvState(t);
    if (MV.filter === "prob" && !["down", "unreachable", "alarm", "slow"].includes(s)) return false;
    if (MV.filter === "down" && s !== "down") return false;
    if (MV.filter === "alarm" && s !== "alarm") return false;
    if (MV.filter === "maint" && !t.maint) return false;
    if (MV.filter === "paused" && s !== "paused") return false;
    if (MV.grp && (t.grp || "") !== MV.grp) return false;
    if (q && ![t.name, t.host, t.url, t.grp, (MV.rows[t.id] || {}).sys].some((x) => String(x || "").toLowerCase().includes(q))) return false;
    return true;
  });
  const k = V.sort || "status", d = V.dir || 1;
  L = L.slice().sort((a, b) => {
    const x = mvVal(a, k), y = mvVal(b, k);
    if (x === y) return (a.name || "").localeCompare(b.name || "", "fa");
    if (x === null) return 1;
    if (y === null) return -1;
    return (typeof x === "string" ? x.localeCompare(y, "fa") : x - y) * d;
  });
  return L;
}

/* ---------------------------------------------------------------- رسم */
function mvRenderAll() {
  const host = $("#mvWrap"); if (!host) return;
  mvRenderBar(); mvRenderEdit(); mvRenderBody();
}
function mvRenderBar() {
  const el = $("#mvBar"); if (!el) return;
  const V = mvCurrent(), vs = mvViews(), groups = [...new Set(MON.targets.map((t) => t.grp).filter(Boolean))].sort((a, b) => a.localeCompare(b, "fa"));
  el.innerHTML = `<div class="mv-bar">
      <div class="seg" id="mvMode"><button data-m="cards" class="${V.mode !== "table" ? "on" : ""}">کارت‌ها</button><button data-m="table" class="${V.mode === "table" ? "on" : ""}">جدول</button></div>
      <select id="mvView" title="نماهای ذخیره‌شده"><option value="">نمای پیش‌فرض</option>${vs.list.map((o) => `<option value="${esc(o.name)}" ${o.name === V.name ? "selected" : ""}>${esc(o.name)}</option>`).join("")}</select>
      <div class="seg" id="mvFilter">${MV_FILTER.map(([k, n]) => `<button data-f="${k}" class="${MV.filter === k ? "on" : ""}">${n}</button>`).join("")}</div>
      ${groups.length ? `<select id="mvGrp"><option value="">همه‌ی گروه‌ها</option>${groups.map((g) => `<option ${g === MV.grp ? "selected" : ""}>${esc(g)}</option>`).join("")}</select>` : ""}
      <input id="mvQ" type="search" placeholder="جستجو: نام، آدرس، گروه" value="${esc(MV.q)}">
      <button class="btn ${MV.edit ? "primary" : ""}" id="mvEditBtn" title="ستون‌ها، ترتیب، قالب و پورت‌های نمایشی؛ تغییرات بعد از «اعمال»">${MV.edit ? "در حال ویرایش…" : "✎ شخصی‌سازی"}</button></div>`;
  $$("#mvMode button", el).forEach((b) => (b.onclick = () => { V.mode = b.dataset.m; MV.page = 0; mvRenderAll(); }));
  $$("#mvFilter button", el).forEach((b) => (b.onclick = () => { MV.filter = b.dataset.f; MV.page = 0; mvRenderBar(); mvRenderBody(); }));
  if ($("#mvGrp", el)) $("#mvGrp", el).onchange = (e) => { MV.grp = e.target.value; MV.page = 0; mvRenderBody(); };
  $("#mvQ", el).oninput = (e) => { MV.q = e.target.value; MV.page = 0; mvRenderBody(); };
  $("#mvView", el).onchange = (e) => {
    const v = mvViews(); v.cur = e.target.value; MV.view = null; MV.page = 0; mvCurrent(); mvSaveViews(v); mvRenderAll();
  };
  $("#mvEditBtn", el).onclick = () => { if (MV.edit) return; mvEditStart(); };
}
function mvRenderBody() {
  const el = $("#mvBody"); if (!el) return;
  const V = mvCurrent(), L = mvList(), size = MV.edit ? MV.edit.view.size : V.size || 100;
  const pages = Math.max(1, Math.ceil(L.length / size));
  MV.page = Math.min(MV.page, pages - 1);
  const P = L.slice(MV.page * size, (MV.page + 1) * size);
  if (!MON.targets.length) { el.innerHTML = `<div class="panel"><div class="empty">هنوز هدفی برای مانیتورینگ نیست. «+ هدف تازه» را بزنید و IP سرور، روتر یا یک آدرس اینترنتی (مثلاً 8.8.8.8) اضافه کنید.</div></div>`; $("#mvPager").innerHTML = ""; return; }
  if (!L.length) { el.innerHTML = `<div class="empty">هدفی با این فیلتر نیست.</div>`; $("#mvPager").innerHTML = ""; return; }
  el.innerHTML = (MV.edit ? MV.edit.view.mode : V.mode) === "table" ? mvTable(P) : mvCards(P);
  $("#mvPager").innerHTML = pages > 1 ? `<div class="mv-pager"><button class="btn sm" data-pg="-1" ${MV.page ? "" : "disabled"}>قبلی</button>
    <span>${esc(`صفحه‌ی ${num(MV.page + 1)} از ${num(pages)} (${num(L.length)} هدف)`)}</span><button class="btn sm" data-pg="1" ${MV.page < pages - 1 ? "" : "disabled"}>بعدی</button></div>` : "";
  $$("[data-pg]", $("#mvPager")).forEach((b) => (b.onclick = () => { MV.page += Number(b.dataset.pg); mvRenderBody(); }));
  $$("[data-mid]", el).forEach((c) => (c.onclick = (e) => { if (e.target.closest("button,input,select,label")) return; monDetail(Number(c.dataset.mid)); }));
  $$("[data-sort]", el).forEach((h) => (h.onclick = () => {
    const W = MV.edit ? MV.edit.view : V;
    if (W.sort === h.dataset.sort) W.dir = -(W.dir || 1); else { W.sort = h.dataset.sort; W.dir = 1; }
    mvRenderBody();
  }));
  $$("[data-mvports]", el).forEach((b) => (b.onclick = () => mvPickPorts(Number(b.dataset.mvports))));
  $$("[data-mvsel]", el).forEach((c) => (c.onchange = () => { const i = Number(c.dataset.mvsel); if (c.checked) MV.sel.add(i); else MV.sel.delete(i); mvRenderEdit(); }));
  const all = $("#mvSelAll", el);
  if (all) all.onchange = () => { P.filter((t) => t.can_edit).forEach((t) => (all.checked ? MV.sel.add(t.id) : MV.sel.delete(t.id))); mvRenderBody(); mvRenderEdit(); };
}
function mvTable(P) {
  const W = MV.edit ? MV.edit.view : mvCurrent(), cols = W.cols && W.cols.length ? W.cols : MV_DEF_COLS, ed = !!MV.edit;
  const tplName = (t) => { const x = MV.edit && MV.edit.tpl[t.id] !== undefined ? MV.edit.tpl[t.id] : t.tpl || ""; const o = (MON.templates || []).find((z) => z.id === x); return x ? (o ? o.name : x) : "خودکار"; };
  return `<div class="table-wrap"><table class="grid mv-tbl"><thead><tr>${ed ? `<th class="nosort"><input type="checkbox" id="mvSelAll"></th>` : ""}
    ${cols.map((k) => `<th data-sort="${k}" class="${W.sort === k ? "sorted" : ""}">${esc(MV_COLS[k] || k)}${W.sort === k ? (W.dir === -1 ? " ▼" : " ▲") : ""}</th>`).join("")}
    ${ed ? `<th class="nosort">قالب نمایش</th>` : ""}</tr></thead><tbody>
    ${P.map((t) => `<tr data-mid="${t.id}" class="mv-r st-${mvState(t)}">${ed ? `<td>${t.can_edit ? `<input type="checkbox" data-mvsel="${t.id}" ${MV.sel.has(t.id) ? "checked" : ""}>` : ""}</td>` : ""}
      ${cols.map((k) => `<td class="c-${k}">${mvCell(t, k)}</td>`).join("")}
      ${ed ? `<td>${esc(tplName(t))}${MV.edit.tpl[t.id] !== undefined ? ` <span class="tag info">تغییر</span>` : ""}</td>` : ""}</tr>`).join("")}</tbody></table></div>`;
}
function mvCards(P) {
  const groups = {};
  P.forEach((t) => (groups[t.grp || ""] = groups[t.grp || ""] || []).push(t));
  const order = Object.keys(groups).sort((a, b) => (a === "") - (b === "") || a.localeCompare(b, "fa"));
  const now = Date.now() / 1000;
  return order.map((g) => `<div class="mon-group"><h3>${esc(g || "بدون گروه")}</h3><div class="mon-grid">${groups[g].map((t) => {
    const st = MON_ST[t.status] || MON_ST.unknown, r = MV.rows[t.id] || {};
    const lv = t.kind === "snmp" && t.status !== "down" && t.status !== "paused" ? r.lvl : "";
    const why = t.status === "unreachable" && t.cause ? `به‌خاطر قطع «${t.cause}»` : "";
    return `<div class="mon-card st-${t.status}${t.maint ? " maint" : ""}${lv && lv !== "ok" ? " lv-" + lv : ""}" data-mid="${t.id}" title="${esc([why, t.err, t.maint ? "پنجره‌ی نگهداری: " + t.maint : ""].filter(Boolean).join(" — "))}">
      <div class="mon-ic">${monIcon(t.icon)}<span class="mon-dot"></span></div>
      <div class="mon-main"><b class="${snNameCls(t.name)}">${esc(t.name)}</b><span class="ltr muted">${esc(monWhere(t))}</span>${monCertTag(t)}
        <span class="mon-meta"><span class="tag ${st[0]}">${st[1]}</span>
        ${t.since && t.status !== "unknown" ? `<span class="muted">${monDur(now - t.since)}</span>` : ""}${t.owner ? `<span class="tag mute" title="فقط شما و ادمین می‌بینید">شخصی</span>` : ""}${t.maint ? `<span class="tag mnt" title="${esc(t.maint)}">نگهداری</span>` : ""}${why ? `<span class="muted bidi">${esc(why)}</span>` : ""}${t.status !== "paused" ? mvCardFields(t) : ""}</span></div>
      <div class="mon-spark" title="۲۴ ساعت گذشته">${(t.spark || []).map((v) => `<i class="${v == null ? "n" : v >= 99.9 ? "g" : v >= 90 ? "y" : "r"}"></i>`).join("")}</div></div>`;
  }).join("")}</div></div>`).join("");
}

/* ---------------------------------------------------------------- حالت ویرایش (پیش‌نویس؛ «اعمال» = ذخیره) */
function mvEditStart() {
  MV.edit = { view: JSON.parse(JSON.stringify(mvCurrent())), tpl: {}, ports: {} };
  MV.sel = new Set();
  if (!MV.edit.view.cols || !MV.edit.view.cols.length) MV.edit.view.cols = [...MV_DEF_COLS];
  mvRenderAll();
}
function mvRenderEdit() {
  const el = $("#mvEdit"); if (!el) return;
  if (!MV.edit) { el.innerHTML = ""; return; }
  const E = MV.edit, V = E.view, cols = V.cols, rest = Object.keys(MV_COLS).filter((k) => !cols.includes(k));
  const nT = Object.keys(E.tpl).length, nP = Object.keys(E.ports).length;
  el.innerHTML = `<div class="mv-edit panel">
    <div class="mv-edit-grid">
      <div><h4>ستون‌های جدول (به همین ترتیب)</h4><div class="mv-cols">${cols.map((k, i) => `<div class="mv-col"><span>${esc(MV_COLS[k])}</span>
          <button class="btn sm ghost" data-cu="${i}" ${i ? "" : "disabled"} title="بالاتر">▲</button><button class="btn sm ghost" data-cd="${i}" ${i < cols.length - 1 ? "" : "disabled"} title="پایین‌تر">▼</button>
          <button class="btn sm ghost" data-cx="${k}" ${cols.length > 1 ? "" : "disabled"} title="حذف ستون">✕</button></div>`).join("")}</div>
        ${rest.length ? `<div class="row" style="gap:6px;margin-top:6px"><select id="mvAddCol">${rest.map((k) => `<option value="${k}">${esc(MV_COLS[k])}</option>`).join("")}</select><button class="btn sm" id="mvAddColB">+ ستون</button></div>` : ""}</div>
      <div><h4>نما</h4>
        <label class="field"><span>هدف در هر صفحه</span><select id="mvSize">${[25, 50, 100, 200].map((n) => `<option ${V.size === n ? "selected" : ""}>${n}</option>`).join("")}</select></label>
        <label class="field"><span>نام نما (برای ذخیره)</span><input id="mvName" value="${esc(V.name || "")}" placeholder="مثلاً فقط uplinkها"></label>
        <small class="hint">حالت نمایش، فیلتر، جستجو، گروه و مرتب‌سازی فعلی هم در نما ذخیره می‌شوند. نماها مخصوص خود شما هستند.</small>
        ${V.name ? `<button class="btn sm danger-ghost" id="mvDelView" style="margin-top:6px">حذف نمای «${esc(V.name)}»</button>` : ""}</div>
      <div><h4>دستگاه‌های انتخاب‌شده (${num(MV.sel.size)})</h4>
        <label class="field"><span>قالب نمایش</span><select id="mvTpl"><option value="">خودکار (از روی آیکن)</option>${(MON.templates || []).map((o) => `<option value="${esc(o.id)}">${esc(o.name)}</option>`).join("")}</select></label>
        <button class="btn sm" id="mvTplSet" ${MV.sel.size ? "" : "disabled"}>اعمال قالب روی انتخاب‌شده‌ها</button>
        <small class="hint">در جدول تیک بزنید. پورت‌های نمایشی هر دستگاه SNMP از دکمه‌ی «پورت‌ها…» در ستون ترافیک.</small>
        ${MON.admin ? `<div style="margin-top:8px"><button class="btn sm ghost" id="mvTplMgr">مدیریت قالب‌های نمایش…</button></div>` : ""}</div>
    </div>
    <div class="row mv-edit-foot"><span class="muted">${esc(nT || nP ? `تغییرهای در انتظار: قالب ${num(nT)} دستگاه، پورت‌های نمایشی ${num(nP)} دستگاه` : "تغییرات تا «اعمال» ذخیره نمی‌شوند.")}</span>
      <span style="flex:1"></span><button class="btn ghost" id="mvCancel">انصراف</button><button class="btn" id="mvApply">اعمال</button><button class="btn primary" id="mvApplySave">اعمال و ذخیره‌ی نما</button></div></div>`;
  const re = () => { mvRenderEdit(); mvRenderBody(); };
  $$("[data-cu]", el).forEach((b) => (b.onclick = () => { const i = Number(b.dataset.cu); [cols[i - 1], cols[i]] = [cols[i], cols[i - 1]]; re(); }));
  $$("[data-cd]", el).forEach((b) => (b.onclick = () => { const i = Number(b.dataset.cd); [cols[i + 1], cols[i]] = [cols[i], cols[i + 1]]; re(); }));
  $$("[data-cx]", el).forEach((b) => (b.onclick = () => { V.cols = cols.filter((k) => k !== b.dataset.cx); re(); }));
  if ($("#mvAddColB", el)) $("#mvAddColB", el).onclick = () => { cols.push($("#mvAddCol", el).value); V.mode = "table"; mvRenderAll(); };
  $("#mvSize", el).onchange = (e) => { V.size = Number(e.target.value); MV.page = 0; mvRenderBody(); };
  $("#mvName", el).oninput = (e) => { V.name_new = e.target.value; };
  $("#mvTplSet", el).onclick = () => { const v = $("#mvTpl", el).value; MV.sel.forEach((i) => (E.tpl[i] = v)); MV.sel = new Set(); re(); };
  if ($("#mvTplMgr", el)) $("#mvTplMgr", el).onclick = () => monTemplates();
  if ($("#mvDelView", el)) $("#mvDelView", el).onclick = async () => {
    if (!(await confirm2({ title: "حذف نما", body: `<p>نمای «${esc(V.name)}» حذف شود؟</p>`, confirm: "حذف", danger: true }))) return;
    const v = mvViews(); v.list = v.list.filter((o) => o.name !== V.name); if (v.cur === V.name) v.cur = "";
    if (await mvSaveViews(v)) { MV.edit = null; MV.view = null; mvRenderAll(); }
  };
  $("#mvCancel", el).onclick = () => { MV.edit = null; MV.sel = new Set(); mvRenderAll(); };
  $("#mvApply", el).onclick = () => mvApply(false);
  $("#mvApplySave", el).onclick = () => mvApply(true);
}
async function mvApply(saveView) {
  const E = MV.edit, V = E.view;
  const name = (V.name_new !== undefined ? V.name_new : V.name || "").trim();
  if (saveView && !name) return toast("برای ذخیره‌ی نما یک نام بنویسید.", "warn");
  // دستگاه‌ها: قالب (گروهی) و پورت‌های نمایشی
  const byTpl = {};
  Object.entries(E.tpl).forEach(([id, v]) => (byTpl[v] = byTpl[v] || []).push(Number(id)));
  for (const [v, ids] of Object.entries(byTpl)) { const r = await api("mon_tpl_set", ids, v); if (!r.ok) return toast(r.error, "error"); }
  for (const [id, names] of Object.entries(E.ports)) { const r = await api("mon_show_ports", Number(id), names); if (!r.ok) return toast(r.error, "error"); }
  delete V.name_new;
  const W = { ...V, status: MV.filter ? [MV.filter] : [], q: MV.q, grp: MV.grp };
  if (saveView) {
    const v = mvViews(); W.name = name;
    v.list = v.list.filter((o) => o.name !== name).concat([W]); v.cur = name;
    if (!(await mvSaveViews(v))) return;
  }
  MV.view = W; MV.edit = null; MV.sel = new Set();
  toast(saveView ? "اعمال و ذخیره شد" : "اعمال شد", "ok");
  if (Object.keys(byTpl).length || Object.keys(E.ports).length) await loadMon(); else mvRenderAll();
}
async function mvPickPorts(tid) {
  const t = MON.targets.find((x) => x.id === tid); if (!t) return;
  const r = await api("mon_snmp_live", tid, 0, true);
  if (!r.ok) return toast(r.error, "error");
  if (r.none) return toast("هنوز داده‌ای از این دستگاه خوانده نشده است.", "warn");
  const cur = MV.edit.ports[tid] || ((t.snmp_cfg || {}).show_ports || []);
  const ifs = (r.ifs || []).filter((x) => x.type !== 24);
  const res = await openModal({ title: `پورت‌های نمایشی «${t.name}»`, wide: true,
    body: `<p class="hint">حداکثر ۴ پورت؛ ترافیکشان در جدول، کارت و NOC نمایش داده می‌شود. هیچ = خودکار (پورت‌های پیگیری‌شده، وگرنه سریع‌ترین پورت‌های وصل).</p>
      <input id="ppQ" type="search" placeholder="جستجوی پورت" style="margin-bottom:8px">
      <div class="table-wrap inner" style="max-height:50vh"><table class="grid"><thead><tr><th></th><th>پورت</th><th>توضیح</th><th>وضعیت</th><th>ترافیک</th></tr></thead><tbody>
      ${ifs.map((x) => `<tr data-pn="${esc(x.name.toLowerCase() + " " + (x.alias || "").toLowerCase())}"><td><input type="checkbox" data-pp="${esc(x.name)}" ${cur.includes(x.name) ? "checked" : ""}></td>
        <td class="ltr">${esc(x.name)}</td><td class="bidi">${esc(x.alias || "")}</td><td>${esc(I18N.t(SN_OPER[x.oper] || String(x.oper)))}</td>
        <td class="ltr">↓${esc(fmtBps(x.in_bps))} ↑${esc(fmtBps(x.out_bps))}</td></tr>`).join("")}</tbody></table></div>`,
    foot: `<button class="btn ghost" data-r="auto">خودکار</button><span style="flex:1"></span><button class="btn ghost" data-r="0">انصراف</button><button class="btn primary" data-r="1">تأیید</button>`,
    onOpen: (m, close) => {
      $("#ppQ", m).oninput = (e) => { const q = e.target.value.toLowerCase(); $$("[data-pn]", m).forEach((tr) => (tr.hidden = q && !tr.dataset.pn.includes(q))); };
      $$("[data-pp]", m).forEach((c) => (c.onchange = () => { if ($$("[data-pp]:checked", m).length > 4) { c.checked = false; toast("حداکثر ۴ پورت", "warn"); } }));
      $("[data-r='0']", m).onclick = () => close(null);
      $("[data-r='auto']", m).onclick = () => close([]);
      $("[data-r='1']", m).onclick = () => close($$("[data-pp]:checked", m).map((c) => c.dataset.pp));
    } });
  if (res === null || res === undefined || !MV.edit) return;
  MV.edit.ports[tid] = res;
  mvRenderEdit(); mvRenderBody();
}

/* ---------------------------------------------------------------- قالب‌های نمایش (ادمین) */
async function monTemplates() {
  const r = await api("mon_tpl_list");
  if (!r.ok) return toast(r.error, "error");
  const res = await openModal({ title: "قالب‌های نمایش دستگاه", wide: true,
    body: `<p class="hint">قالب تعیین می‌کند در کارت و صفحه‌ی جزئیات دستگاه SNMP چه چیزی و به چه ترتیبی دیده شود (چه چیزی خوانده شود با «سیاست پایش» است). دستگاه بدون قالب، اگر سازنده‌اش تشخیص داده شود قالب همان سازنده (Cisco، Juniper، Extreme، FortiGate) و وگرنه قالب آیکنش را می‌گیرد.</p>
      <div class="table-wrap inner"><table class="grid"><thead><tr><th>نام</th><th>کارت</th><th>بخش‌ها</th><th>دستگاه‌ها</th><th class="nosort"></th></tr></thead><tbody>
      ${r.templates.map((x) => `<tr><td><b>${esc(x.name)}</b>${x.builtin ? ` <span class="tag mute">آماده</span>` : ""}</td><td>${esc(x.data.card.map((k) => I18N.t(MV_CARD[k] || k)).join("، ") || "—")}</td>
        <td>${esc(x.data.tabs.map((k) => I18N.t(MV_TABS[k] || k)).join("، "))}</td><td>${num(x.used)}</td>
        <td class="row" style="gap:4px">${x.builtin ? `<button class="btn sm" data-tc="${esc(x.id)}">کپی و ویرایش</button>` : `<button class="btn sm" data-te="${esc(x.id)}">ویرایش</button><button class="btn sm danger-ghost" data-td="${esc(x.id)}">حذف</button>`}</td></tr>`).join("")}</tbody></table></div>`,
    foot: `<button class="btn ghost" data-r="0">بستن</button>${r.can_edit ? `<button class="btn primary" id="tplAdd">+ قالب تازه</button>` : ""}`,
    onOpen: (m, close) => {
      $("[data-r='0']", m).onclick = () => close(null);
      if ($("#tplAdd", m)) $("#tplAdd", m).onclick = () => close({ edit: { name: "", data: r.templates[0].data } });
      const find = (id) => r.templates.find((x) => x.id === id);
      $$("[data-tc]", m).forEach((b) => (b.onclick = () => { const x = find(b.dataset.tc); close({ edit: { name: `${x.name} (کپی)`, data: x.data } }); }));
      $$("[data-te]", m).forEach((b) => (b.onclick = () => close({ edit: find(b.dataset.te) })));
      $$("[data-td]", m).forEach((b) => (b.onclick = () => close({ del: find(b.dataset.td) })));
    } });
  if (!res) return;
  if (res.del) {
    if (await confirm2({ title: "حذف قالب", body: `<p>قالب «${esc(res.del.name)}» حذف شود؟ دستگاه‌هایش قالب خودکار می‌گیرند.</p>`, confirm: "حذف", danger: true })) {
      const x = await api("mon_tpl_delete", res.del.id); if (!x.ok) toast(x.error, "error"); else { toast("حذف شد", "ok"); await loadMon(); }
    }
    return monTemplates();
  }
  if (await monTplEdit(res.edit)) await loadMon();
  monTemplates();
}
async function monTplEdit(x) {
  const d = JSON.parse(JSON.stringify(x.data)), tabs = [...d.tabs, ...Object.keys(MV_TABS).filter((k) => !d.tabs.includes(k))];
  const on = new Set(d.tabs);
  const bl = d.blocks || ["kpi", "alarms", "info"], blocks = [...bl, ...Object.keys(SN_BLOCKS).filter((k) => !bl.includes(k))], bon = new Set(bl);
  return openModal({ title: x.id ? `ویرایش قالب «${x.name}»` : "قالب نمایش تازه", wide: true,
    body: `<div class="form-grid"><label class="field"><span>نام</span><input id="teName" value="${esc(x.name || "")}" placeholder="مثلاً سوییچ‌های دسترسی"></label>
      <label class="field"><span>تعداد پورت نمایشی خودکار</span><select id="tePorts">${[0, 1, 2, 3, 4].map((n) => `<option ${d.ports === n ? "selected" : ""}>${n}</option>`).join("")}</select>
        <small class="hint">وقتی برای دستگاه پورت انتخاب نشده است.</small></label></div>
      <div class="field"><span>روی کارت (حداکثر ۴، به همین ترتیب)</span><div class="row" style="gap:6px;flex-wrap:wrap">${[0, 1, 2, 3].map((i) => `<select data-tcard="${i}"><option value="">—</option>${Object.entries(MV_CARD).map(([k, n]) => `<option value="${k}" ${d.card[i] === k ? "selected" : ""}>${esc(n)}</option>`).join("")}</select>`).join("")}</div></div>
      <div class="field"><span>بخش‌های صفحه‌ی جزئیات (ترتیب و نمایش)</span><div class="mv-cols" id="teTabs"></div></div>
      <div class="field"><span>بلوک‌های بخش «خلاصه» (ترتیب و نمایش)</span><div class="mv-cols" id="teBlocks"></div></div>
      <div class="field"><span>نمودارهای بخش «خلاصه»</span><div class="row" style="gap:14px;flex-wrap:wrap">${Object.entries(MV_CHARTS).map(([k, n]) => `<label class="chk"><input type="checkbox" data-tch="${k}" ${d.sum_charts.includes(k) ? "checked" : ""}>${esc(n)}</label>`).join("")}</div></div>`,
    foot: `<button class="btn ghost" data-r="0">انصراف</button><button class="btn primary" data-r="1">ذخیره</button>`,
    onOpen: (m, close) => {
      const draw = () => {
        $("#teTabs", m).innerHTML = tabs.map((k, i) => `<div class="mv-col"><label class="chk"><input type="checkbox" data-ton="${k}" ${on.has(k) ? "checked" : ""}>${esc(MV_TABS[k])}</label>
          <button class="btn sm ghost" data-tu="${i}" ${i ? "" : "disabled"}>▲</button><button class="btn sm ghost" data-tdn="${i}" ${i < tabs.length - 1 ? "" : "disabled"}>▼</button></div>`).join("");
        $$("[data-ton]", m).forEach((c) => (c.onchange = () => { if (c.checked) on.add(c.dataset.ton); else on.delete(c.dataset.ton); }));
        $$("[data-tu]", m).forEach((b) => (b.onclick = () => { const i = Number(b.dataset.tu); [tabs[i - 1], tabs[i]] = [tabs[i], tabs[i - 1]]; draw(); }));
        $$("[data-tdn]", m).forEach((b) => (b.onclick = () => { const i = Number(b.dataset.tdn); [tabs[i + 1], tabs[i]] = [tabs[i], tabs[i + 1]]; draw(); }));
      };
      draw();
      const drawB = () => {
        $("#teBlocks", m).innerHTML = blocks.map((k, i) => `<div class="mv-col"><label class="chk"><input type="checkbox" data-bon="${k}" ${bon.has(k) ? "checked" : ""}>${esc(SN_BLOCKS[k])}</label>
          <button class="btn sm ghost" data-bu="${i}" ${i ? "" : "disabled"}>▲</button><button class="btn sm ghost" data-bdn="${i}" ${i < blocks.length - 1 ? "" : "disabled"}>▼</button></div>`).join("");
        $$("[data-bon]", m).forEach((c) => (c.onchange = () => { if (c.checked) bon.add(c.dataset.bon); else bon.delete(c.dataset.bon); }));
        $$("[data-bu]", m).forEach((b) => (b.onclick = () => { const i = Number(b.dataset.bu); [blocks[i - 1], blocks[i]] = [blocks[i], blocks[i - 1]]; drawB(); }));
        $$("[data-bdn]", m).forEach((b) => (b.onclick = () => { const i = Number(b.dataset.bdn); [blocks[i + 1], blocks[i]] = [blocks[i], blocks[i + 1]]; drawB(); }));
      };
      drawB();
      $("[data-r='0']", m).onclick = () => close(false);
      $("[data-r='1']", m).onclick = async () => {
        const data = { card: $$("[data-tcard]", m).map((s) => s.value).filter(Boolean), tabs: tabs.filter((k) => on.has(k)),
          sum_charts: $$("[data-tch]:checked", m).map((c) => c.dataset.tch), ports: Number($("#tePorts", m).value), blocks: blocks.filter((k) => bon.has(k)) };
        const r = await api("mon_tpl_save", { id: x.id && !x.builtin ? x.id : null, name: $("#teName", m).value.trim(), data });
        if (!r.ok) return toast(r.error, "error");
        toast("ذخیره شد", "ok"); close(true);
      };
    } });
}
