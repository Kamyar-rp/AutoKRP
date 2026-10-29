"use strict";
/* ================================================================ رخدادهای دستگاه (1.25) و نقشه‌ی شبکه (1.26)
 * سربرگ‌های صفحه‌ی مانیتورینگ؛ تنظیمات گیرنده‌ها در «تنظیمات ← مانیتورینگ» (monEventsSettings). */
const EVS = { kinds: "", sev: "", q: "", tid: "", data: null };
const EV_SEV = { crit: ["err", "بحرانی"], warn: ["warn", "هشدار"], info: ["info", "اطلاع"], ok: ["ok", "برطرف"] };

async function monEventsRender(el) {
  const tsel = MON.targets.map((t) => `<option value="${t.id}" ${String(t.id) === String(EVS.tid) ? "selected" : ""}>${esc(t.name)}</option>`).join("");
  el.innerHTML = `<div class="toolbar"><div id="evTr"></div>
      <div class="seg" id="evK">${[["", "همه"], ["trap", "Trap"], ["syslog", "Syslog"]].map(([v, n]) => `<button data-v="${v}" class="${EVS.kinds === v ? "on" : ""}">${n}</button>`).join("")}</div>
      <div class="seg" id="evS">${[["", "همه‌ی سطح‌ها"], ["crit", "بحرانی"], ["warn", "هشدار"], ["info", "اطلاع"], ["ok", "برطرف"]].map(([v, n]) => `<button data-v="${v}" class="${EVS.sev === v ? "on" : ""}">${n}</button>`).join("")}</div>
      <select id="evT" style="width:auto;min-width:180px"><option value="">همه‌ی منبع‌ها</option>${tsel}</select>
      <input type="search" class="search" id="evQ" placeholder="جستجو در نام و متن…" value="${esc(EVS.q)}" style="max-width:220px">
      <button class="btn no-ro" id="evCsv">خروجی CSV</button></div>
    <div class="tr-note" id="evNote"></div><div id="evBody"><div class="empty">در حال خواندن…</div></div>`;
  const bar = { get: () => MON.tr, set: (R) => { monTrSet(R); trBar($("#evTr", el), bar); evLoad(el); }, refresh: () => evLoad(el, true) };
  trBar($("#evTr", el), bar);
  $$("#evK button", el).forEach((b) => (b.onclick = () => { EVS.kinds = b.dataset.v; $$("#evK button", el).forEach((x) => x.classList.toggle("on", x === b)); evLoad(el); }));
  $$("#evS button", el).forEach((b) => (b.onclick = () => { EVS.sev = b.dataset.v; $$("#evS button", el).forEach((x) => x.classList.toggle("on", x === b)); evLoad(el); }));
  $("#evT", el).onchange = (e) => { EVS.tid = e.target.value; evLoad(el); };
  let qt = null;
  $("#evQ", el).oninput = (e) => { EVS.q = e.target.value; clearTimeout(qt); qt = setTimeout(() => evLoad(el), 400); };
  $("#evCsv", el).onclick = evCsv;
  evLoad(el);
}
async function evLoad(el, silent) {
  const r = await api("mon_events_query", trApi(MON.tr), EVS.kinds ? [EVS.kinds] : null, EVS.sev ? [EVS.sev] : null, EVS.q, EVS.tid ? Number(EVS.tid) : null);
  const body = $("#evBody", el); if (!body) return;
  if (!r.ok) { body.innerHTML = `<div class="empty">${esc(r.error)}</div>`; return; }
  EVS.data = r;
  const c = r.counts || {};
  $("#evNote", el).innerHTML = `<span class="ltr">${esc(trFmt(r.since) + " — " + trFmt(r.until))}</span> · Trap: ${num(c.trap || 0)} · Syslog: ${num(c.syslog || 0)} ·
    <span style="color:var(--err)">بحرانی ${num(c.crit || 0)}</span> · هشدار ${num(c.warn || 0)}${r.partial ? ` · <span style="color:var(--warn)">${esc(I18N.t("بازه خیلی بزرگ است؛ فقط بخشی خوانده شد. بازه را کوچک کنید."))}</span>` : ""}${r.total > r.rows.length ? ` · فقط ${num(r.rows.length)} مورد آخر از ${num(r.total)} نمایش داده می‌شود؛ بازه یا فیلتر را کوچک کنید` : ""}`;
  if (!r.rows.length) {
    body.innerHTML = `<div class="panel"><div class="empty">رخدادی در این بازه نیست.${MON.admin ? ` گیرنده‌ی Trap و Syslog را در «تنظیمات ← مانیتورینگ» روشن کنید و دستگاه‌ها را برای ارسال به آدرس این سیستم تنظیم کنید.` : ""}</div></div>`;
    return;
  }
  const keep = silent ? body.querySelector(".table-wrap") && body.querySelector(".table-wrap").scrollTop : 0;
  body.innerHTML = `<div class="table-wrap" style="max-height:calc(100vh - 290px)"><table class="grid" id="evTable"><thead><tr><th>زمان</th><th>منبع</th><th>نوع</th><th>سطح</th><th>رخداد</th><th>متن</th></tr></thead><tbody>
    ${r.rows.slice(0, 500).map((x, i) => { const s = EV_SEV[x.sev] || EV_SEV.info; return `<tr data-ev="${i}" class="clickable">
      <td class="ltr" data-sv="${x.t}">${fmtDate(x.t)}:${String(new Date(x.t * 1000).getSeconds()).padStart(2, "0")}</td>
      <td><span class="bidi">${esc(x.tname || "")}</span> <span class="muted ltr">${esc(x.src)}</span></td><td>${x.k === "trap" ? "Trap" : "Syslog"}</td>
      <td><span class="tag ${s[0]}">${s[1]}</span></td><td class="ltr">${esc(x.name || "")}</td><td class="wrap ltr" style="max-width:520px">${esc((x.msg || "").slice(0, 300))}</td></tr>`; }).join("")}</tbody></table></div>
    ${r.rows.length > 500 ? `<div class="hint">۵۰۰ ردیف اول نمایش داده می‌شود (CSV همه‌ی ${num(r.rows.length)} ردیف).</div>` : ""}`;
  if (silent && keep) body.querySelector(".table-wrap").scrollTop = keep;
  $$("[data-ev]", body).forEach((tr) => (tr.onclick = () => evDetail(r.rows[Number(tr.dataset.ev)])));
}
function evDetail(x) {
  const s = EV_SEV[x.sev] || EV_SEV.info;
  const kv = x.k === "trap" ? (x.vbs || []).map(([o, v]) => `<tr><td class="ltr">${esc(o)}</td><td class="ltr wrap">${esc(String(v))}</td></tr>`).join("") : "";
  openModal({ title: `${x.k === "trap" ? "Trap" : "Syslog"} — ${x.name || ""}`, wide: true,
    body: `<dl class="kv"><dt>زمان</dt><dd class="ltr">${esc(trFmt(x.t))}</dd><dt>منبع</dt><dd>${esc(x.tname || "")} <span class="ltr">${esc(x.src)}</span>${x.agent ? ` (agent ${esc(x.agent)})` : ""}</dd>
      <dt>سطح</dt><dd><span class="tag ${s[0]}">${s[1]}</span>${x.pri != null ? ` <span class="muted">syslog ${esc(String(x.pri))}</span>` : ""}</dd>
      ${x.oid ? `<dt>OID</dt><dd class="ltr">${esc(x.oid)} (SNMP v${esc(x.ver || "")})</dd>` : ""}${x.vendor ? `<dt>سازنده</dt><dd>${esc(x.vendor)}</dd>` : ""}
      ${x.host ? `<dt>نام میزبان</dt><dd class="ltr">${esc(x.host)}</dd>` : ""}${x.app ? `<dt>برنامه</dt><dd class="ltr">${esc(x.app)}</dd>` : ""}</dl>
      <pre class="ltr paste-prev" data-no-i18n style="white-space:pre-wrap">${esc(x.msg || "")}</pre>
      ${kv ? `<h3 style="margin:10px 0 6px">Varbindها</h3><div class="table-wrap inner"><table class="grid"><tbody>${kv}</tbody></table></div>` : ""}`,
    foot: `<button class="btn ghost" data-r="0">بستن</button>`, onOpen: (m, close) => ($("[data-r='0']", m).onclick = () => close()) });
}
async function evCsv() {
  const r = EVS.data; if (!r) return;
  const q = (v) => `"${String(v ?? "").replace(/"/g, '""')}"`;
  const lines = [["زمان", "منبع", "IP", "نوع", "سطح", "رخداد", "متن"].map((h) => q(I18N.t(h))).join(",")];
  r.rows.forEach((x) => lines.push([trFmt(x.t), x.tname || "", x.src, x.k, x.sev, x.name || "", x.msg || ""].map(q).join(",")));
  const res = await api("save_export", `autokrp_events_${Math.floor(r.since)}-${Math.floor(r.until)}.csv`, "﻿" + lines.join("\r\n"), false);
  if (!res.ok) return toast(res.error, "error"); if (!res.cancelled) toast("ذخیره شد: " + res.path, "ok");
}

/* ---------------------------------------------------------------- تنظیمات ← مانیتورینگ: Trap و Syslog (ادمین) */
async function monEventsSettings(box) {
  const r = await api("mon_events_status");
  if (!r.ok || !box.isConnected) { box.remove(); return; }
  const c = r.cfg, st = r.stats;
  box.innerHTML = `<h3>دریافت Trap و Syslog از دستگاه‌ها</h3>
    <p class="hint">پیام‌ها فقط از آدرس هدف‌های مانیتورینگ (یا رنج‌های زیر) پذیرفته می‌شوند و رمزشده ذخیره می‌شوند. نام و سطح ${num(r.trapdb.traps)} Trap سیسکو، فورتی‌گیت، جونیپر، میکروتیک، HP و اکستریم از فایل‌های MIB رسمی؛ Syslog سیسکو (%FAC-SEV-MNEMONIC)، فورتی‌گیت (key=value) و RFC 3164/5424.
      SNMPv3 Trap هنوز پشتیبانی نمی‌شود (فقط v1، v2c و Inform). روی ویندوز فایروال پورت‌ها را باز کنید؛ روی لینوکس پورت زیر ۱۰۲۴ دسترسی root می‌خواهد.</p>
    <div class="form-grid">
      <div class="field"><span>&nbsp;</span><label class="chk"><input type="checkbox" id="ev_trap_enabled" ${c.trap_enabled ? "checked" : ""}>دریافت Trap (UDP)</label></div>
      <label class="field"><span>پورت Trap</span><input id="ev_trap_port" type="number" value="${esc(c.trap_port)}"></label>
      <div class="field"><span>&nbsp;</span><label class="chk"><input type="checkbox" id="ev_syslog_enabled" ${c.syslog_enabled ? "checked" : ""}>دریافت Syslog (UDP)</label></div>
      <label class="field"><span>پورت Syslog</span><input id="ev_syslog_port" type="number" value="${esc(c.syslog_port)}"></label>
      <div class="field"><span>&nbsp;</span><label class="chk"><input type="checkbox" id="ev_syslog_tcp" ${c.syslog_tcp ? "checked" : ""}>Syslog روی TCP هم (همان پورت)</label></div>
      <label class="field"><span>آدرس شنیدن</span><input id="ev_bind" class="ltr" value="${esc(c.bind)}"></label>
      <label class="field wide"><span>community‌های مجاز Trap (هر خط یکی)</span><textarea id="ev_communities" class="ltr" rows="2" data-nodirty>${esc((c.communities || []).join("\n"))}</textarea>
        <small class="hint">community پروفایل SNMP هر هدف خودکار مجاز است. خالی و بدون پروفایل = هر community از منبع شناخته.</small></label>
      <label class="field wide"><span>رنج‌های مجاز دیگر (CIDR، با فاصله)</span><input id="ev_sources" class="ltr" value="${esc((c.sources || []).join(" "))}" placeholder="10.10.0.0/16"></label>
      <div class="field"><span>&nbsp;</span><label class="chk"><input type="checkbox" id="ev_allow_unknown" ${c.allow_unknown ? "checked" : ""}>پذیرش از هر منبع (پیشنهاد نمی‌شود)</label></div>
      <label class="field"><span>کمترین شدت ذخیره‌ی Syslog</span><select id="ev_min_store">${[[3, "خطا (۳)"], [4, "هشدار (۴)"], [5, "notice (۵)"], [6, "اطلاع (۶)"], [7, "همه (debug)"]].map(([v, n]) => `<option value="${v}" ${Number(c.min_store) === v ? "selected" : ""}>${n}</option>`).join("")}</select></label>
      <div class="field"><span>&nbsp;</span><label class="chk"><input type="checkbox" id="ev_forti_traffic" ${c.forti_traffic ? "checked" : ""}>لاگ ترافیک و UTM فورتی‌گیت هم ذخیره شود (حجم بسیار زیاد)</label></div>
      <label class="field"><span>هشدار (بنر، صدا، ایمیل) از سطح</span><select id="ev_alert_level">${[["crit", "بحرانی"], ["warn", "هشدار و بحرانی"], ["none", "هیچ (فقط ثبت)"]].map(([v, n]) => `<option value="${v}" ${c.alert_level === v ? "selected" : ""}>${n}</option>`).join("")}</select></label>
      <label class="field"><span>نگهداری (روز، ۰ = بدون محدودیت)</span><input id="ev_keep_days" type="number" value="${esc(c.keep_days)}"></label>
      <div class="field wide"><span>قاعده‌ها (اولین قاعده‌ای که با نام یا متن جور شود سطح را تعیین می‌کند؛ regex، بدون حساسیت به حروف)</span>
        <div id="evRules">${(c.rules || []).map((x) => evRuleRow(x)).join("")}</div><button class="btn sm" id="evRuleAdd" type="button">+ قاعده</button></div></div>
    <div class="form-foot"><span class="muted">${esc(r.status.trap === "off" ? "Trap: خاموش" : "Trap: " + r.status.trap)} · ${esc(r.status.syslog === "off" ? "Syslog: خاموش" : "Syslog: " + r.status.syslog)}
      · دریافت‌شده: Trap ${num(st.trap)}، Syslog ${num(st.syslog)} · رد: منبع ناشناخته ${num(st.dropped_unknown)}، community ${num(st.dropped_auth)}، سقف سرعت ${num(st.dropped_rate)}</span>
      <span style="flex:1"></span><button class="btn primary" id="evSave">ذخیره و راه‌اندازی دوباره</button></div>`;
  const bindRules = () => $$("[data-evdel]", box).forEach((b) => (b.onclick = () => b.closest(".ev-rule").remove()));
  bindRules();
  $("#evRuleAdd", box).onclick = () => { $("#evRules", box).insertAdjacentHTML("beforeend", evRuleRow({ match: "", level: "crit" })); bindRules(); };
  $("#evSave", box).onclick = (e) => withSpin(e.currentTarget, async () => {
    const v = (id) => $("#ev_" + id, box);
    const cfg = { trap_enabled: v("trap_enabled").checked, trap_port: v("trap_port").value, syslog_enabled: v("syslog_enabled").checked, syslog_port: v("syslog_port").value,
      syslog_tcp: v("syslog_tcp").checked, bind: v("bind").value, communities: v("communities").value.split("\n"), sources: v("sources").value.trim().split(/\s+/).filter(Boolean),
      allow_unknown: v("allow_unknown").checked, min_store: Number(v("min_store").value), forti_traffic: v("forti_traffic").checked, alert_level: v("alert_level").value,
      keep_days: v("keep_days").value, rules: $$(".ev-rule", box).map((x) => ({ match: $("[data-k='m']", x).value, level: $("[data-k='l']", x).value })).filter((x) => x.match.trim()) };
    const x = await api("mon_events_cfg_save", cfg); if (!x.ok) return toast(x.error, "error");
    toast("ذخیره شد؛ گیرنده‌ها تا چند ثانیه دوباره راه‌اندازی می‌شوند", "ok"); setTimeout(() => monEventsSettings(box), 2500);
  });
}
function evRuleRow(x) {
  return `<div class="row ev-rule" style="gap:6px;margin-bottom:6px"><input data-k="m" class="ltr" style="flex:1" value="${esc(x.match || "")}" placeholder="مثلاً %SEC_LOGIN-4-LOGIN_FAILED یا fgTrapIpsSignature" data-nodirty>
    <select data-k="l" style="width:auto">${[["crit", "بحرانی"], ["warn", "هشدار"], ["info", "اطلاع"], ["ignore", "نادیده (ذخیره نشود)"]].map(([v, n]) => `<option value="${v}" ${x.level === v ? "selected" : ""}>${n}</option>`).join("")}</select>
    <button class="btn sm danger-ghost" type="button" data-evdel>حذف</button></div>`;
}

/* ---------------------------------------------------------------- نقشه‌ی شبکه */
const TOPO = { root: "", data: null, pos: (() => { try { return JSON.parse(localStorage.getItem("akrp_topo_pos") || "{}"); } catch (_) { return {}; } })() };
async function topoRender(el, setup = false) {
  const r = await api("mon_topo");
  if (!el.isConnected) return;
  if (!r.ok) { el.innerHTML = `<div class="panel"><div class="empty">${esc(r.error)}</div></div>`; return; }
  TOPO.data = r;
  // 1.27.1: بدون راه‌اندازی ادمین هیچ نقشه و اسکنی نیست؛ ادمین دستگاه‌ها را انتخاب و تأیید می‌کند
  if (!r.at || setup) {
    if (!MON.admin) { el.innerHTML = `<div class="panel"><div class="empty">نقشه‌ی شبکه هنوز راه‌اندازی نشده است؛ ادمین باید دستگاه‌ها را انتخاب و اسکن را تأیید کند.</div></div>`; return; }
    const sel = new Set(r.ids);
    el.innerHTML = `<div class="panel"><h3 style="margin-top:0">راه‌اندازی نقشه‌ی شبکه</h3>
      <p class="hint">فقط دستگاه‌هایی که تیک می‌زنید با SNMP خوانده می‌شوند (جدول همسایه‌های LLDP، CDP و MikroTik)؛ هیچ دستگاه دیگری اسکن نمی‌شود و اسکن هرگز خودکار اجرا نمی‌شود. نقشه فقط همین دستگاه‌ها و همسایه‌هایشان را نشان می‌دهد.</p>
      ${r.candidates.length ? `<div class="row" style="gap:6px;margin-bottom:6px"><button class="btn sm ghost" id="tpAll">همه</button><button class="btn sm ghost" id="tpNone">هیچ‌کدام</button></div>
        <div class="sn-pick">${r.candidates.map((c) => `<label class="chk"><input type="checkbox" data-tpi="${c.id}" ${sel.has(c.id) ? "checked" : ""}><span class="bidi">${esc(c.name)}</span> <small class="muted ltr">${esc(c.host)}</small></label>`).join("")}</div>
        <div class="row" style="gap:6px;margin-top:10px"><button class="btn primary" id="tpGo" ${r.scanning ? "disabled" : ""}>${r.scanning ? `در حال اسکن… ${num(r.progress[0])}/${num(r.progress[1])}` : "تأیید و اسکن دستگاه‌های انتخاب‌شده"}</button>${r.at ? `<button class="btn ghost" id="tpBack">انصراف</button>` : ""}</div>`
        : `<div class="empty">هیچ دستگاه SNMPی در مانیتورینگ نیست؛ ابتدا سوییچ‌ها و روترها را با روش SNMP اضافه کنید و LLDP یا CDP را روی آن‌ها روشن نگه دارید.</div>`}</div>`;
    if ($("#tpAll", el)) $("#tpAll", el).onclick = () => $$("[data-tpi]", el).forEach((c) => (c.checked = true));
    if ($("#tpNone", el)) $("#tpNone", el).onclick = () => $$("[data-tpi]", el).forEach((c) => (c.checked = false));
    if ($("#tpBack", el)) $("#tpBack", el).onclick = () => topoRender(el);
    if ($("#tpGo", el)) $("#tpGo", el).onclick = async () => {
      const ids = $$("[data-tpi]", el).filter((c) => c.checked).map((c) => Number(c.dataset.tpi));
      if (!ids.length) return toast("دست‌کم یک دستگاه انتخاب کنید.", "error");
      if (!(await confirm2({ title: "اسکن همسایه‌ها", body: `<p>${esc(`${num(ids.length)} دستگاه با SNMP خوانده می‌شود (فقط خواندن جدول همسایه‌ها).`)}</p>`, confirm: "تأیید و اسکن" }))) return;
      const x = await api("mon_topo_scan", ids); if (!x.ok) return toast(x.error, "error"); topoPoll(el);
    };
    if (r.scanning) topoPoll(el);
    return;
  }
  el.innerHTML = `<div class="toolbar">${MON.admin ? `<button class="btn primary" id="tpScan" ${r.scanning ? "disabled" : ""}>${r.scanning ? `در حال اسکن… ${num(r.progress[0])}/${num(r.progress[1])}` : "اسکن دوباره"}</button><button class="btn" id="tpSet">انتخاب دستگاه‌ها</button>` : ""}
      <span class="muted">آخرین اسکن: <span class="ltr">${esc(trFmt(r.at))}</span> · ${esc(`${num(r.scanned)} دستگاه SNMP · ${num(r.links.length)} لینک`)}</span><span style="flex:1"></span>
      ${MON.admin ? `<select id="tpRoot" style="width:auto;min-width:180px"><option value="">ریشه (مثلاً سوییچ هسته)…</option>${r.nodes.map((n) => `<option value="${n.id}" ${String(n.id) === String(TOPO.root) ? "selected" : ""}>${esc(n.name)}</option>`).join("")}</select>
      <button class="btn" id="tpSug" ${r.links.length ? "" : "disabled"}>پیشنهاد «وابسته به» از نقشه</button>` : ""}<button class="btn ghost" id="tpReset" title="چیدمان خودکار دوباره">چیدمان دوباره</button></div>
    ${Object.keys(r.errors || {}).length ? `<div class="hint" style="color:var(--warn)">بدون پاسخ: ${Object.entries(r.errors).map(([k, v]) => esc(((r.nodes.find((n) => String(n.id) === k) || {}).name || k) + " (" + v[0] + ")")).join(" · ")}</div>` : ""}
    <div class="panel topo-panel"><svg id="tpSvg" class="topo-svg"></svg><div class="topo-legend">${Object.entries({ up: "وصل", down: "قطع", unreachable: "در دسترس نیست", unknown: "نامعلوم", ext: "خارج از مانیتورینگ" }).map(([k, n]) => `<span><i class="tp-${k}"></i>${n}</span>`).join("")}<span class="muted">کشیدن = جابه‌جایی گره · کلیک = جزئیات</span></div></div>`;
  if ($("#tpScan", el)) $("#tpScan", el).onclick = async () => {
    if (!(await confirm2({ title: "اسکن همسایه‌ها", body: `<p>${esc(`${num(r.ids.length)} دستگاه انتخاب‌شده دوباره با SNMP خوانده می‌شود.`)}</p>`, confirm: "تأیید و اسکن" }))) return;
    const x = await api("mon_topo_scan"); if (!x.ok) return toast(x.error, "error"); topoPoll(el);
  };
  if ($("#tpSet", el)) $("#tpSet", el).onclick = () => topoRender(el, true);
  if ($("#tpRoot", el)) $("#tpRoot", el).onchange = (e) => { TOPO.root = e.target.value; };
  if ($("#tpSug", el)) $("#tpSug", el).onclick = () => topoSuggest(el);
  $("#tpReset", el).onclick = () => { TOPO.pos = {}; try { localStorage.removeItem("akrp_topo_pos"); } catch (_) { /* */ } topoDraw(el); };
  if (r.scanning) topoPoll(el);
  topoDraw(el);
}
function topoPoll(el) {
  setTimeout(async () => { if (!el.isConnected || (MON.tab || "") !== "topo") return; const r = await api("mon_topo"); if (r.ok && r.scanning) { const b = $("#tpScan", el) || $("#tpGo", el); if (b) b.textContent = `در حال اسکن… ${num(r.progress[0])}/${num(r.progress[1])}`; topoPoll(el); } else topoRender(el); }, 1500);
}
function topoGraph() {
  const r = TOPO.data, nodes = new Map(), edges = [];
  const add = (key, o) => { if (!nodes.has(key)) nodes.set(key, o); return key; };
  for (const lk of r.links) {
    const a = r.nodes.find((n) => n.id === lk.a); if (!a) continue;
    const ka = add("t" + a.id, { key: "t" + a.id, id: a.id, name: a.name, status: a.status });
    let kb;
    if (lk.b) { const b = r.nodes.find((n) => n.id === lk.b); if (!b) continue; kb = add("t" + b.id, { key: "t" + b.id, id: b.id, name: b.name, status: b.status }); }
    else kb = add("x" + (lk.b_name || lk.b_ip), { key: "x" + (lk.b_name || lk.b_ip), name: lk.b_name || lk.b_ip, status: "ext", plat: lk.plat, ip: lk.b_ip });
    edges.push({ a: ka, b: kb, lk });
  }
  r.nodes.filter((n) => n.kind === "snmp").forEach((n) => add("t" + n.id, { key: "t" + n.id, id: n.id, name: n.name, status: n.status }));
  return { nodes: [...nodes.values()], edges };
}
function topoLayout(g, W, H) {
  // Fruchterman–Reingold ساده با بذر ثابت؛ موقعیت ذخیره‌شده‌ی کاربر ثابت می‌ماند
  let seed = 7; const rnd = () => ((seed = (seed * 16807) % 2147483647) / 2147483647);
  const P = {}; g.nodes.forEach((n) => { const s = TOPO.pos[n.key]; P[n.key] = s ? { x: s.x * W, y: s.y * H, fixed: true } : { x: W * (0.15 + 0.7 * rnd()), y: H * (0.15 + 0.7 * rnd()) }; });
  const k = Math.sqrt((W * H) / Math.max(1, g.nodes.length)) * 0.75;
  for (let it = 0, t = W / 8; it < 300; it++, t *= 0.985) {
    const D = {}; g.nodes.forEach((n) => (D[n.key] = { x: 0, y: 0 }));
    for (let i = 0; i < g.nodes.length; i++) for (let j = i + 1; j < g.nodes.length; j++) {
      const a = P[g.nodes[i].key], b = P[g.nodes[j].key]; let dx = a.x - b.x, dy = a.y - b.y; const d = Math.max(0.01, Math.hypot(dx, dy)), f = (k * k) / d;
      dx /= d; dy /= d; D[g.nodes[i].key].x += dx * f; D[g.nodes[i].key].y += dy * f; D[g.nodes[j].key].x -= dx * f; D[g.nodes[j].key].y -= dy * f;
    }
    g.edges.forEach((e) => { const a = P[e.a], b = P[e.b]; let dx = a.x - b.x, dy = a.y - b.y; const d = Math.max(0.01, Math.hypot(dx, dy)), f = (d * d) / k;
      dx /= d; dy /= d; D[e.a].x -= dx * f; D[e.a].y -= dy * f; D[e.b].x += dx * f; D[e.b].y += dy * f; });
    g.nodes.forEach((n) => { const p = P[n.key]; if (p.fixed) return; const d = D[n.key], l = Math.max(0.01, Math.hypot(d.x, d.y));
      p.x = Math.min(W - 40, Math.max(40, p.x + (d.x / l) * Math.min(l, t))); p.y = Math.min(H - 30, Math.max(30, p.y + (d.y / l) * Math.min(l, t))); });
  }
  return P;
}
function topoDraw(el) {
  const svg = $("#tpSvg", el); if (!svg) return;
  const W = Math.max(600, svg.clientWidth || 1000), H = Math.max(420, Math.round(window.innerHeight - 300));
  svg.setAttribute("viewBox", `0 0 ${W} ${H}`); svg.style.height = H + "px";
  const g = topoGraph(), P = topoLayout(g, W, H);
  const lines = g.edges.map((e, i) => `<line data-e="${i}" x1="${P[e.a].x}" y1="${P[e.a].y}" x2="${P[e.b].x}" y2="${P[e.b].y}" class="tp-edge"><title>${esc(`${e.lk.a_port} ↔ ${e.lk.b_port || "?"} (${e.lk.proto})${e.lk.plat ? " — " + e.lk.plat : ""}`)}</title></line>`).join("");
  const dots = g.nodes.map((n) => `<g class="tp-node" data-k="${esc(n.key)}" transform="translate(${P[n.key].x},${P[n.key].y})"><circle r="${n.status === "ext" ? 7 : 11}" class="tp-${n.status === "paused" ? "unknown" : n.status}"></circle>
      <text y="${n.status === "ext" ? 20 : 25}" text-anchor="middle">${esc(n.name.length > 22 ? n.name.slice(0, 21) + "…" : n.name)}</text><title>${esc(n.name + (n.ip ? " — " + n.ip : "") + (n.plat ? " — " + n.plat : ""))}</title></g>`).join("");
  svg.innerHTML = `<g>${lines}</g><g>${dots}</g>`;
  // کشیدن گره‌ها
  let drag = null, moved = false;
  $$(".tp-node", svg).forEach((nd) => nd.addEventListener("mousedown", (ev) => { ev.preventDefault(); drag = nd; moved = false; }));
  svg.onmousemove = (ev) => {
    if (!drag) return; moved = true;
    const b = svg.getBoundingClientRect(), x = ((ev.clientX - b.left) / b.width) * W, y = ((ev.clientY - b.top) / b.height) * H, k = drag.dataset.k;
    P[k] = { x, y }; drag.setAttribute("transform", `translate(${x},${y})`);
    g.edges.forEach((e, i) => { if (e.a === k || e.b === k) { const l = svg.querySelector(`[data-e="${i}"]`); l.setAttribute(e.a === k ? "x1" : "x2", x); l.setAttribute(e.a === k ? "y1" : "y2", y); } });
  };
  svg.onmouseup = () => {
    if (!drag) return; const k = drag.dataset.k, n = g.nodes.find((x) => x.key === k);
    if (moved) { TOPO.pos[k] = { x: P[k].x / W, y: P[k].y / H }; try { localStorage.setItem("akrp_topo_pos", JSON.stringify(TOPO.pos)); } catch (_) { /* */ } }
    else if (n && n.id) monDetail(n.id);
    drag = null;
  };
}
async function topoSuggest(el) {
  if (!TOPO.root) return toast("ابتدا ریشه (مثلاً سوییچ هسته یا فایروال) را انتخاب کنید", "warn");
  const r = await api("mon_topo", Number(TOPO.root)); if (!r.ok) return toast(r.error, "error");
  const nm = (id) => (r.nodes.find((n) => n.id === id) || {}).name || "—";
  const rows = (r.suggest || []).filter((x) => x.parent !== x.current);
  const res = await openModal({ title: "پیشنهاد وابستگی از نقشه", wide: true,
    body: rows.length ? `<p class="hint">از «${esc(nm(Number(TOPO.root)))}» روی لینک‌های بین هدف‌ها پیمایش شد؛ پدر هر هدف دستگاه یک قدم نزدیک‌تر به ریشه است. فقط تفاوت‌ها نمایش داده می‌شوند.</p>
      <div class="table-wrap inner"><table class="grid"><thead><tr><th class="chk nosort"><input type="checkbox" id="tsAll" checked></th><th>هدف</th><th>پدر فعلی</th><th>پدر پیشنهادی</th></tr></thead><tbody>
      ${rows.map((x) => `<tr><td class="chk"><input type="checkbox" class="tsC" value="${x.id}" checked></td><td>${esc(nm(x.id))}</td><td>${esc(x.current ? nm(x.current) : "—")}</td><td><b>${esc(nm(x.parent))}</b></td></tr>`).join("")}</tbody></table></div>`
      : `<div class="empty">وابستگی‌ها با نقشه یکی است (یا لینکی بین هدف‌ها پیدا نشد).</div>`,
    foot: `<button class="btn ghost" data-r="0">انصراف</button>${rows.length ? `<button class="btn primary" data-r="1">اعمال انتخاب‌شده‌ها</button>` : ""}`,
    onOpen: (m, close) => {
      $("[data-r='0']", m).onclick = () => close(null);
      if (!rows.length) return;
      $("#tsAll", m).onchange = (e) => $$(".tsC", m).forEach((c) => (c.checked = e.target.checked));
      $("[data-r='1']", m).onclick = () => close($$(".tsC:checked", m).map((c) => Number(c.value)));
    } });
  if (!res || !res.length) return;
  const x = await api("mon_topo_apply", Number(TOPO.root), res);
  if (!x.ok) return toast(x.error, "error");
  toast(`وابستگی ${num(x.count)} هدف تنظیم شد`, "ok"); loadMon();
}

/* ---------------------------------------------------------------- تنظیمات ← مانیتورینگ: MIB سازنده‌ها (1.27.1، ادمین) */
async function monMibSettings(box) {
  const r = await api("mib_list");
  if (!box.isConnected) return;
  if (!r.ok) { box.remove(); return; }
  const ST = { ok: ["ok", "آماده"], failed: ["err", "ناموفق"], pending: ["info", "در صف"] };
  box.innerHTML = `<h3>دستگاه تازه با فایل MIB سازنده</h3>
    <p class="hint">فایل MIB دستگاهی را که برنامه نمی‌شناسد از سایت سازنده بگیرید و بارگذاری کنید (متن یا zip). برنامه خودکار سازنده را از روی MIB می‌شناسد، آن را به «نوع دستگاه» در مانیتورینگ اضافه می‌کند و «وضعیت‌های سلامت» آن (مثل green/yellow/red یا ok/failed) را روی همه‌ی دستگاه‌های همان سازنده می‌خواند و هشدار می‌دهد؛ کار دستی لازم نیست. Trapهای همان سازنده هم با نام MIB نمایش داده می‌شوند.</p>
    <div class="row" style="gap:6px;margin-bottom:8px"><button class="btn" id="mbUp">بارگذاری MIB…</button>${r.compiling ? `<span class="tag info">در حال پردازش…</span>` : ""}</div>
    ${r.types.length ? `<div class="sum" style="margin-bottom:8px">${r.types.map((x) => `<div><b>${esc(x.name)}</b> · <span class="ltr">${esc(x.match.join(", "))}</span> · ${esc(`${num(x.count)} وضعیت`)}${x.items.length ? ` <span class="muted ltr">(${esc(x.items.slice(0, 8).join(", "))}${x.items.length > 8 ? "…" : ""})</span>` : ""}</div>`).join("")}</div>` : ""}
    ${r.modules.length ? `<div class="table-wrap inner"><table class="grid"><thead><tr><th>ماژول</th><th>وضعیت</th><th>اشیا</th><th>زمان</th><th class="nosort"></th></tr></thead><tbody>
      ${r.modules.map((x) => { const t = ST[x.status] || ["mute", x.status]; return `<tr><td class="ltr">${esc(x.name)}</td>
        <td><span class="tag ${t[0]}">${esc(t[1])}</span>${x.missing.length ? `<div class="muted">لازم: <span class="ltr">${x.missing.map(esc).join("، ")}</span></div>` : x.error && x.status !== "ok" ? `<div class="muted ltr" style="white-space:normal">${esc(x.error)}</div>` : ""}</td>
        <td data-sv="${x.objects}">${num(x.objects)}</td><td class="ltr" data-sv="${x.ts}">${esc(trFmt(x.ts))}</td>
        <td><button class="btn sm danger-ghost" data-md="${esc(x.name)}">حذف</button></td></tr>`; }).join("")}</tbody></table></div>` : ""}`;
  $("#mbUp", box).onclick = async () => {
    let path = null;
    if (WEB) { const up = await webPickFile(".mib,.my,.txt,.zip"); if (!up.ok) return toast(up.error, "error"); if (!up.path) return; path = up.path; }
    const x = await api("mib_upload", path);
    if (!x.ok) return toast(x.error, "error");
    if (x.cancelled) return;
    if (x.errors.length) toast(x.errors.join(" · "), "error");
    if (x.added.length) toast(`${num(x.added.length)} ماژول بارگذاری شد؛ پردازش در پس‌زمینه`, "ok");
    monMibSettings(box);
  };
  $$("[data-md]", box).forEach((b) => (b.onclick = async () => {
    if (!(await confirm2({ title: "حذف MIB", body: `<p class="ltr">${esc(b.dataset.md)}</p>`, confirm: "حذف", danger: true }))) return;
    const x = await api("mib_delete", [b.dataset.md]); if (!x.ok) return toast(x.error, "error"); monMibSettings(box);
  }));
  if (r.compiling) setTimeout(() => { if (box.isConnected) monMibSettings(box); }, 2000);
}
