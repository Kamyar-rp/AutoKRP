"use strict";
/* ================================================================ مانیتورینگ
 * صفحه‌ی کارت‌ها، هشدار سراسری (بنر + صدا + اعلان مرورگر)، و بخش «مانیتورینگ» در آمار. از app.js استفاده می‌کند. */

const MON_ICON_SVG = {
  server: '<rect x="4" y="3.5" width="16" height="7" rx="1.5"/><rect x="4" y="13.5" width="16" height="7" rx="1.5"/><circle cx="8" cy="7" r=".9" fill="currentColor"/><circle cx="8" cy="17" r=".9" fill="currentColor"/><path d="M12 7h5M12 17h5"/>',
  router: '<rect x="3" y="13" width="18" height="7" rx="2"/><path d="M7 13l-2-7M17 13l2-7"/><circle cx="7.5" cy="16.5" r=".9" fill="currentColor"/><circle cx="11" cy="16.5" r=".9" fill="currentColor"/><path d="M15 16.5h3"/>',
  switch: '<rect x="2.5" y="8" width="19" height="8" rx="1.5"/><path d="M6 11v2M9 11v2M12 11v2M15 11v2M18 11v2"/>',
  firewall: '<rect x="3" y="4" width="18" height="16" rx="1.5"/><path d="M3 9h18M3 14.5h18M9 4v5M15 9v5.5M9 14.5V20"/>',
  internet: '<circle cx="12" cy="12" r="8.5"/><path d="M3.5 12h17M12 3.5c2.5 2.6 3.7 5.4 3.7 8.5s-1.2 5.9-3.7 8.5c-2.5-2.6-3.7-5.4-3.7-8.5S9.5 6.1 12 3.5z"/>',
  pc: '<rect x="3" y="4" width="18" height="12" rx="1.5"/><path d="M9 20h6M12 16v4"/>',
  camera: '<path d="M3 8l12-3 2 6-12 3z"/><path d="M17 9.5l3.5-1v5L17 12.5M8 14l1 5H6"/>',
  printer: '<path d="M7 9V4h10v5"/><rect x="3.5" y="9" width="17" height="7" rx="1.5"/><path d="M7 14h10v6H7z"/>',
  wifi: '<path d="M2.5 9a14 14 0 0 1 19 0M5.5 12.5a9.5 9.5 0 0 1 13 0M8.5 16a5 5 0 0 1 7 0"/><circle cx="12" cy="19" r="1.1" fill="currentColor"/>',
  storage: '<ellipse cx="12" cy="6" rx="7.5" ry="2.5"/><path d="M4.5 6v12c0 1.4 3.4 2.5 7.5 2.5s7.5-1.1 7.5-2.5V6M4.5 12c0 1.4 3.4 2.5 7.5 2.5s7.5-1.1 7.5-2.5"/>',
  phone: '<rect x="7" y="2.5" width="10" height="19" rx="2"/><path d="M11 18.5h2"/>',
  other: '<circle cx="12" cy="12" r="8.5"/><circle cx="12" cy="12" r="2.5" fill="currentColor"/>',
};
const MON_ICON_NAME = { server: "سرور", router: "روتر", switch: "سوییچ", firewall: "فایروال", internet: "اینترنت", pc: "کامپیوتر", camera: "دوربین",
  printer: "چاپگر", wifi: "وای‌فای", storage: "ذخیره‌ساز", phone: "تلفن", other: "سایر" };
const MON_ST = { up: ["ok", "وصل"], down: ["err", "قطع"], slow: ["warn", "کند"], unknown: ["mute", "در حال بررسی"], paused: ["mute", "متوقف"],
  unreachable: ["unr", "در دسترس نیست"] };
const MON_WD = [[6, "ش"], [0, "ی"], [1, "د"], [2, "س"], [3, "چ"], [4, "پ"], [5, "ج"]];   // ترتیب هفته‌ی ایرانی؛ مقدار = Date.getDay
const MON = { targets: [], icons: {}, cfg: {}, seq: null, alerts: [], down: [], timer: null, sounds: {}, audio: null, lastPlay: 0,
  muted: (() => { try { return localStorage.getItem("akrp_mon_mute") === "1"; } catch (_) { return false; } })(),
  rep: { id: "" },
  // 1.23: بازه‌ی زمانی مشترک همه‌ی نمودارهای مانیتورینگ (گزارش، جزئیات هدف، SNMP)؛ در همین مرورگر به خاطر سپرده می‌شود
  tr: (() => { try { const v = JSON.parse(localStorage.getItem("akrp_mon_tr") || "null"); if (v && (v.p || (v.from && v.to))) return v; } catch (_) { /* پیش‌فرض */ } return { p: "24h" }; })() };
function monTrSet(R) { MON.tr = R; try { localStorage.setItem("akrp_mon_tr", JSON.stringify(R)); } catch (_) { /* فقط همین مرورگر */ } }
/** داده‌ی یک گزارش برای نمودار: برچسب محور، راهنما، زمان‌ها */
function monAxis(keys, step) {
  const span = keys.length ? keys[keys.length - 1] - keys[0] + step : 0;
  return { lab: keys.map((k) => trTick(k, step, span)), tips: keys.map((k) => trTip(k, step)), times: keys };
}
/** کشیدن موس روی نمودار ← بازه‌ی همان تکه */
function monZoomTo(keys, step, i0, i1, set) { set(trCustom(keys[i0], keys[i1] + step)); }
function monZoomOut(R, set) { const r = trResolve(R), span = r.to - r.from; set(trCustom(r.from - span / 2, r.to + span / 2)); }

function monIcon(icon, cls = "") {
  if (String(icon || "").startsWith("custom:")) {
    const u = MON.icons[icon.slice(7)];
    if (u) return `<img class="mon-img ${cls}" src="${esc(u)}" alt="">`;
    icon = "other";
  }
  return `<svg class="mon-svg ${cls}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">${MON_ICON_SVG[icon] || MON_ICON_SVG.other}</svg>`;
}
function monDur(s) {
  s = Math.max(0, Math.floor(s || 0));
  if (s < 60) return `${num(s)} ثانیه`;
  if (s < 3600) return `${num(Math.floor(s / 60))} دقیقه`;
  if (s < 86400) return `${num(Math.floor(s / 3600))} ساعت و ${num(Math.floor((s % 3600) / 60))} دقیقه`;
  return `${num(Math.floor(s / 86400))} روز و ${num(Math.floor((s % 86400) / 3600))} ساعت`;
}
/* 1.31: روزهای باقی‌مانده‌ی گواهی HTTPS (فقط وقتی هشدار روشن است و به آستانه رسیده یا خطا داشته) */
function monCertTag(t) {
  const c = t.cert; if (!c || !t.cert_days) return "";
  if (c.err && c.days == null) return ` <span class="tag mute" title="${esc(c.err)}">گواهی: خطا</span>`;
  if (c.days == null || c.days > t.cert_days) return "";
  return ` <span class="tag ${c.days < 0 ? "err" : "warn"}" title="${esc(c.cn || "")}">${c.days < 0 ? "گواهی منقضی شده" : `<span>گواهی:</span> <span>${num(c.days)}</span> <span>روز</span>`}</span>`;
}
const monWhere = (t) => (t.kind === "http" ? t.url : t.kind === "tcp" ? `${t.host}:${t.port}` : t.kind === "snmp" ? `${t.host} (SNMP)` : t.host);

/* ---------------------------------------------------------------- هشدار سراسری */
function monQuiet(cfg) {
  const q = (cfg && cfg.quiet) || {};
  if (!q.enabled) return false;
  const toM = (s) => { const [h, m] = String(s || "0:0").split(":").map(Number); return h * 60 + (m || 0); };
  const a = toM(q.from || "23:00"), b = toM(q.to || "07:00"), d = new Date(), n = d.getHours() * 60 + d.getMinutes();
  return a <= b ? n >= a && n < b : n >= a || n < b;
}
async function monSoundUrl(which) {
  if (MON.sounds[which]) return MON.sounds[which];
  const r = await api("mon_sound_get", which);
  if (!r.ok) return "sounds/" + which + ".wav";
  if (r.default) return (MON.sounds[which] = r.url);
  const bin = atob(r.b64), u = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
  return (MON.sounds[which] = URL.createObjectURL(new Blob([u], { type: r.mime })));
}
async function monPlay(which, times = 1) {
  if (MON.muted || monQuiet(MON.cfg)) return;
  try {
    const url = await monSoundUrl(which);
    if (MON.audio) { MON.audio.pause(); MON.audio = null; }
    let left = Math.max(1, times);
    const a = new Audio(url); MON.audio = a;
    a.onended = () => { if (--left > 0 && MON.audio === a) { a.currentTime = 0; a.play().catch(() => {}); } };
    await a.play();
    MON.lastPlay = Date.now();
  } catch (_) {
    // مرورگر بدون کلیک کاربر اجازه‌ی پخش نمی‌دهد
    const b = $("#monBanner");
    if (b && !b.hidden && !b.classList.contains("need-click")) {
      b.classList.add("need-click");
      const t = b.querySelector(".mb-txt"); if (t) t.insertAdjacentHTML("beforeend", `<small>برای پخش صدا روی این نوار کلیک کنید</small>`);
    }
  }
}
function monStopSound() { if (MON.audio) { MON.audio.pause(); MON.audio = null; } }
function monBanner() {
  let b = $("#monBanner");
  if (!b) {
    b = document.createElement("div"); b.id = "monBanner"; b.className = "mon-banner"; b.hidden = true;
    document.body.appendChild(b);
  }
  const al = MON.alerts.filter((a) => a.state === "down" || a.state === "alarm");
  if (!al.length) { b.hidden = true; monStopSound(); return; }
  b.hidden = false;
  const allDown = al.every((a) => a.state === "down");
  b.innerHTML = `<span class="mon-pulse"></span><div class="mb-txt"><b>${al.length > 1 ? (allDown ? `${num(al.length)} هدف قطع شد` : `${num(al.length)} هشدار مانیتورینگ`)
      : al[0].state === "down" ? `«${esc(al[0].name)}» قطع شد` : esc(al[0].msg)}</b>
      <small>${al.slice(0, 4).map((a) => `${esc(a.state === "down" ? a.name : a.msg)} — ${fmtTime(a.ts)}`).join(" · ")}</small></div>
    <button class="btn sm" id="mbOpen">نمایش</button><button class="btn sm" id="mbMute">${MON.muted ? "صدا روشن" : "بی‌صدا"}</button><button class="btn sm primary" id="mbAck">تأیید</button>`;
  $("#mbAck").onclick = () => { MON.alerts = []; monStopSound(); monBanner(); };
  $("#mbOpen").onclick = () => { go("monitor"); };
  $("#mbMute").onclick = () => { monSetMute(!MON.muted); monBanner(); };
  b.onclick = (e) => { if (b.classList.contains("need-click") && !e.target.closest("button")) { b.classList.remove("need-click"); monPlay("down", MON.cfg.repeat || 1); } };
}
function monSetMute(v) {
  MON.muted = v; try { localStorage.setItem("akrp_mon_mute", v ? "1" : "0"); } catch (_) { /* */ }
  if (v) monStopSound();
  const m = $("#monMute"); if (m) m.textContent = I18N.t(v ? "صدا: خاموش" : "صدا: روشن");
}
function monNotifyBrowser(a) {
  try {
    if (!("Notification" in window) || Notification.permission !== "granted" || !document.hidden) return;
    new Notification(a.state === "down" ? I18N.t("قطعی در مانیتورینگ") : a.state === "alarm" ? I18N.t("هشدار مانیتورینگ") : a.state === "clear" ? I18N.t("هشدار برطرف شد") : I18N.t("دوباره وصل شد"),
      { body: a.msg, tag: "akrp-mon-" + a.target + (a.key || "") });
  } catch (_) { /* */ }
}
let monPolling = false;   // 1.26.2: درخواست هم‌پوشان نه (پاسخ کند ← صف درخواست‌ها)
async function monPoll() {
  if (monPolling || !S.state || (S.state.security && S.state.security.locked) || !window.pywebview) return;
  monPolling = true;
  let r;
  try { r = await api("mon_state", MON.seq || 0); } finally { monPolling = false; }
  if (!r.ok) return;
  MON.cfg = r.cfg || {};
  const fresh = MON.seq === null ? [] : r.alerts;     // بار اول: هشدارهای قدیمی دوباره پخش نمی‌شوند
  MON.seq = r.seq; MON.down = r.down; MON.total = r.disabled ? 0 : (r.total || 0);
  const nBad = r.down.length + (r.alarm || []).length;
  const nav = $("#navMonDot"); if (nav) { nav.hidden = !nBad; nav.textContent = nBad ? num(nBad) : ""; }
  if (!fresh.length) { if (MON.alerts.length && Date.now() - MON.lastPlay > 30000 && !MON.audio) monPlay("down", 1); return; }
  let downNew = false, upNew = false;
  for (const a of fresh) {
    monNotifyBrowser(a);
    if (a.state === "down" || a.state === "alarm") { MON.alerts.push(a); downNew = true; }
    else if (a.state === "clear") { MON.alerts = MON.alerts.filter((x) => !(x.target === a.target && x.key === a.key)); upNew = true; toast(a.msg, "ok"); }
    else { MON.alerts = MON.alerts.filter((x) => !(x.target === a.target && x.state === "down")); upNew = true; toast(a.msg, "ok"); }
  }
  monBanner();
  if (downNew) monPlay("down", MON.cfg.repeat || 3);
  else if (upNew && MON.cfg.sound_on_up !== false) monPlay("up", 1);
  if (S.page === "monitor") loadMon();
}
// بدون هدف مانیتورینگ (یا مانیتورینگ خاموش): هر ۳۰ ثانیه به‌جای ۴ ثانیه (هشدار پس‌زمینه را پایتون خودش پخش می‌کند)
let monTick = 0;
setInterval(() => { if (MON.total || S.page === "monitor" || ++monTick % 8 === 0) monPoll(); }, 4000);
setTimeout(monPoll, 1500);

/* ---------------------------------------------------------------- صفحه‌ی مانیتورینگ */
// 1.26.2: یک درخواست mon_list در هر لحظه؛ فراخوانی هم‌زمان (مثلاً هشدار تازه + بازه‌ی ۵ ثانیه) فقط یک بار دیگر بعد از آن
let monLoading = null, monLoadAgain = false, monLoadedAt = 0;
function loadMon() {
  if (monLoading) { monLoadAgain = true; return monLoading; }
  monLoading = (async () => {
    try {
      do {
        monLoadAgain = false;
        const [r, ic] = await Promise.all([api("mon_list"), Object.keys(MON.icons).length ? null : api("mon_icons")]);
        if (ic && ic.ok) MON.icons = ic.icons;
        if (!r.ok) { toast(r.error, "error"); return; }
        monLoadedAt = Date.now();
        Object.assign(MON, { targets: r.targets, cfg: r.cfg, canAdd: r.can_add, admin: r.admin, desktop: r.desktop, max: r.max });
        if ((MON.tab || "targets") === "targets") renderMon(); else if (!$("#monTabs")) monTabsRender();
      } while (monLoadAgain);
    } finally { monLoading = null; }
  })();
  return monLoading;
}
/* 1.25/1.26: سربرگ‌های صفحه‌ی مانیتورینگ */
function monTabsHtml() {
  const tab = MON.tab || "targets";
  return `<div class="tabs" id="monTabs" style="margin-bottom:12px">${[["targets", "هدف‌ها"], ["events", "رخدادهای دستگاه (Trap و Syslog)"], ["topo", "نقشه‌ی شبکه"]]
    .map(([k, n]) => `<button data-mt="${k}" class="${tab === k ? "on" : ""}">${n}</button>`).join("")}</div>`;
}
function monTabsBind() {
  $$("#monTabs [data-mt]").forEach((b) => (b.onclick = () => { MON.tab = b.dataset.mt; monTabsRender(); }));
}
function monTabsRender() {
  const tab = MON.tab || "targets";
  renderMon();                          // دکمه‌های بالای صفحه
  if (tab === "targets") return;
  $("#monBody").innerHTML = monTabsHtml() + `<div id="monSub"></div>`;
  monTabsBind();
  if (tab === "events") monEventsRender($("#monSub")); else topoRender($("#monSub"));
}
function renderMon() {
  const ts = MON.targets, cnt = (s) => ts.filter((t) => t.status === s).length;
  $("#monActions").innerHTML = `${MON.canAdd ? `<button class="btn primary" id="monAdd">+ هدف تازه</button><button class="btn" id="monSnmpP">اعتبارنامه‌های SNMP</button>` : ""}
    <button class="btn" id="monMaint">پنجره‌های نگهداری</button><button class="btn" id="monNoc" title="نمای تمام‌صفحه برای مانیتور دیواری">نمای NOC</button>
    <button class="btn ghost" id="monMute">${MON.muted ? "صدا: خاموش" : "صدا: روشن"}</button>
    <button class="btn ghost" id="monTest" title="پخش صدای قطعی برای امتحان">امتحان صدا</button>
    ${WEB && "Notification" in window && Notification.permission === "default" ? `<button class="btn ghost" id="monNotif">اعلان مرورگر</button>` : ""}
    ${MON.desktop && MON.admin ? `<button class="btn danger-ghost" id="monQuit" title="بستن کامل برنامه؛ با بستن پنجره، برنامه برای مانیتورینگ در پس‌زمینه می‌ماند">خروج کامل</button>` : ""}`;
  const groups = {};
  ts.forEach((t) => (groups[t.grp || ""] = groups[t.grp || ""] || []).push(t));
  const order = Object.keys(groups).sort((a, b) => (a === "") - (b === "") || a.localeCompare(b, "fa"));
  const now = Date.now() / 1000;
  $("#monBody").innerHTML = monTabsHtml() + `<div class="mon-sum">
      <span class="mon-chip"><b>${num(ts.length)}</b> هدف</span><span class="mon-chip ok"><b>${num(cnt("up"))}</b> وصل</span>
      <span class="mon-chip err"><b>${num(cnt("down"))}</b> قطع</span><span class="mon-chip warn"><b>${num(cnt("slow"))}</b> کند</span>
      ${cnt("unreachable") ? `<span class="mon-chip unr"><b>${num(cnt("unreachable"))}</b> در دسترس نیست (به‌خاطر قطع پدر)</span>` : ""}
      ${ts.some((t) => t.maint) ? `<span class="mon-chip mnt"><b>${num(ts.filter((t) => t.maint).length)}</b> در نگهداری</span>` : ""}
      <span class="mon-chip"><b>${num(cnt("paused") + cnt("unknown"))}</b> متوقف یا در حال بررسی</span></div>
    ${ts.length ? order.map((g) => `<div class="mon-group"><h3>${esc(g || "بدون گروه")}</h3><div class="mon-grid">${groups[g].map((t) => {
      const st = MON_ST[t.status] || MON_ST.unknown;
      const lv = t.snmp_sum && t.status !== "down" && t.status !== "paused" ? t.snmp_sum.level : "";
      const why = t.status === "unreachable" && t.cause ? `به‌خاطر قطع «${t.cause}»` : "";
      return `<div class="mon-card st-${t.status}${t.maint ? " maint" : ""}${lv && lv !== "ok" ? " lv-" + lv : ""}" data-mid="${t.id}" title="${esc([why, t.err, t.maint ? "پنجره‌ی نگهداری: " + t.maint : ""].filter(Boolean).join(" — "))}">
        <div class="mon-ic">${monIcon(t.icon)}<span class="mon-dot"></span></div>
        <div class="mon-main"><b class="bidi">${esc(t.name)}</b><span class="ltr muted">${esc(monWhere(t))}</span>${monCertTag(t)}
          <span class="mon-meta"><span class="tag ${st[0]}">${st[1]}</span>${t.rtt != null && t.status !== "down" && t.status !== "paused" ? `<span class="ltr">${num(t.rtt)} ms</span>` : ""}
          ${t.since && t.status !== "unknown" ? `<span class="muted">${monDur(now - t.since)}</span>` : ""}${t.owner ? `<span class="tag mute" title="فقط شما و ادمین می‌بینید">شخصی</span>` : ""}${t.maint ? `<span class="tag mnt" title="${esc(t.maint)}">نگهداری</span>` : ""}${why ? `<span class="muted bidi">${esc(why)}</span>` : ""}${t.kind === "snmp" && t.status !== "paused" ? snCardLine(t) : ""}</span></div>
        <div class="mon-spark" title="۲۴ ساعت گذشته">${t.spark.map((v) => `<i class="${v == null ? "n" : v >= 99.9 ? "g" : v >= 90 ? "y" : "r"}"></i>`).join("")}</div>
      </div>`; }).join("")}</div></div>`).join("")
      : `<div class="panel"><div class="empty">هنوز هدفی برای مانیتورینگ نیست. «+ هدف تازه» را بزنید و IP سرور، روتر یا یک آدرس اینترنتی (مثلاً 8.8.8.8) اضافه کنید.</div></div>`}`;
  if ($("#monAdd")) $("#monAdd").onclick = () => monEdit();
  if ($("#monSnmpP")) $("#monSnmpP").onclick = () => snmpProfiles();
  $("#monMaint").onclick = () => monMaintList();
  $("#monNoc").onclick = () => nocOpen();
  $("#monMute").onclick = () => monSetMute(!MON.muted);
  $("#monTest").onclick = () => { const m = MON.muted; MON.muted = false; monPlay("down", 1).finally(() => (MON.muted = m)); };
  if ($("#monNotif")) $("#monNotif").onclick = async () => { await Notification.requestPermission(); renderMon(); };
  if ($("#monQuit")) $("#monQuit").onclick = async () => {
    if (await confirm2({ title: "خروج کامل", body: "<p>برنامه کامل بسته می‌شود و مانیتورینگ تا اجرای دوباره متوقف می‌ماند.</p>", confirm: "خروج", danger: true })) api("app_quit");
  };
  $$("[data-mid]").forEach((c) => (c.onclick = () => monDetail(Number(c.dataset.mid))));
  monTabsBind();
}
// پنجره‌ی پنهان یا تازه بارشده (کمتر از ۴ ثانیه پیش) نه
setInterval(() => { if (S.page === "monitor" && !modalClose && !document.hidden && Date.now() - monLoadedAt > 4000) loadMon(); }, 5000);

async function monDetail(id) {
  const t = MON.targets.find((x) => x.id === id); if (!t) return;
  if (t.kind === "snmp") return snmpDetail(t);
  const st = MON_ST[t.status] || MON_ST.unknown;
  openModal({ title: t.name, wide: true,
    body: `<div class="mon-dhead">${monIcon(t.icon, "big")}<div><div class="ltr">${esc(monWhere(t))}</div>
        <div class="row" style="gap:8px;margin-top:4px"><span class="tag ${st[0]}">${st[1]}</span>${t.rtt != null ? `<span class="ltr">${num(t.rtt)} ms</span>` : ""}
        <span class="muted">${{ ping: "Ping", tcp: "پورت TCP", http: "HTTP", snmp: "SNMP" }[t.kind]} · هر ${num(t.interval)} ثانیه · قطع پس از ${num(t.threshold)} شکست</span></div>
        ${monRelLine(t)}
        ${t.err ? `<div class="muted" style="color:var(--err)">${esc(t.err)}</div>` : ""}</div></div>
      <div class="toolbar" style="margin-top:12px"><div id="mdTr"></div><span class="muted" id="mdSum"></span></div><div class="tr-note" id="mdNote"></div>
      <div class="chart-grid"><div class="chart-card wide"><div class="chart-head"><h3>در دسترس بودن (٪)</h3></div><div class="chart" id="mdAv"></div></div>
      <div class="chart-card wide"><div class="chart-head"><h3>زمان پاسخ (ms)</h3></div><div class="chart" id="mdRtt"></div></div></div>
      <h3 style="margin:12px 0 6px">قطعی‌های این بازه</h3><div id="mdEv"><div class="empty">در حال خواندن…</div></div>`,
    foot: `${t.can_edit ? `<button class="btn danger-ghost" data-a="del">حذف</button><button class="btn" data-a="toggle">${t.enabled ? "توقف بررسی" : "ادامه‌ی بررسی"}</button><button class="btn" data-a="edit">ویرایش</button>` : ""}
      <button class="btn" data-a="now">بررسی همین حالا</button><button class="btn ghost" data-a="close">بستن</button>`,
    onOpen: async (m, close) => {
      $$("[data-a]", m).forEach((b) => (b.onclick = async () => {
        const a = b.dataset.a;
        if (a === "close") return close();
        if (a === "edit") { close(); return monEdit(t); }
        if (a === "now") { await api("mon_check_now", id); toast("بررسی انجام می‌شود…", "info"); return; }
        if (a === "toggle") { const r = await api("mon_toggle", id, !t.enabled); if (!r.ok) return toast(r.error, "error"); close(); return loadMon(); }
        if (a === "del") {
          if (!(await confirm2({ title: "حذف هدف", body: `<p>«${esc(t.name)}» و سابقه‌ی قطعی‌هایش حذف شود؟</p>`, confirm: "حذف", danger: true }))) return;
          const r = await api("mon_delete", id); if (!r.ok) return toast(r.error, "error"); return loadMon();
        }
      }));
      const draw = async () => {
        const r = await api("mon_report", trApi(MON.tr), [id]);
        if (!$("#mdAv", m)) return;
        if (!r.ok) { $("#mdNote", m).textContent = r.error; return; }
        if (!r.rows.length) return;
        const row = r.rows[0], c = COLORS(), ax = monAxis(r.keys, r.step);
        const z = { zoom: (a, b) => monZoomTo(r.keys, r.step, a, b, setR), zoomOut: () => monZoomOut(MON.tr, setR), sync: "md", times: ax.times, tips: ax.tips, stats: true };
        drawChart($("#mdAv", m), ax.lab, [{ name: "در دسترس بودن", color: c.ok, values: row.avail_series }], { type: "line", height: 170, fmt: (v) => Math.round(v * 100) / 100 + "%", ...z });
        drawChart($("#mdRtt", m), ax.lab, [{ name: "میانگین زمان پاسخ", color: c.info, values: row.rtt_series }], { type: "line", height: 170, fmt: (v) => Math.round(v * 10) / 10 + " ms", ...z });
        $("#mdSum", m).textContent = `${I18N.t("در دسترس بودن")}: ${row.avail == null ? "—" : num(row.avail) + "٪"} · ${I18N.t("قطعی")}: ${num(row.outages)} · ${I18N.t("زمان قطعی")}: ${row.downtime ? monDur(row.downtime) : "—"}`;
        $("#mdNote", m).textContent = trResNote(r);
        $("#mdEv", m).innerHTML = monEvTable(r.events.slice(0, 50));
      };
      const setR = (R) => { monTrSet(R); trBar($("#mdTr", m), bar); draw(); };
      const bar = { get: () => MON.tr, set: setR, refresh: draw };
      trBar($("#mdTr", m), bar);
      draw();
    } });
}
function monLabel(ts, step) { return trTick(ts, step, 0); }
const MON_EVK = { down: ["err", "قطعی"], unreach: ["unr", "به‌خاطر پدر"], maint: ["mnt", "در نگهداری"] };
function monEvTable(evs, withName = false) {
  if (!evs.length) return `<div class="empty">قطعی‌ای ثبت نشده است.</div>`;
  return `<div class="table-wrap inner"><table class="grid"><thead><tr>${withName ? "<th>هدف</th>" : ""}<th>نوع</th><th>شروع</th><th>پایان</th><th>مدت</th><th>علت</th></tr></thead><tbody>
    ${evs.map((e) => { const k = MON_EVK[e.kind || "down"] || MON_EVK.down; return `<tr>${withName ? `<td class="bidi">${esc(e.name)}</td>` : ""}<td><span class="tag ${k[0]}">${k[1]}</span></td><td class="ltr">${fmtDate(e.start)}</td><td class="ltr">${e.end ? fmtDate(e.end) : `<span class="tag err">ادامه دارد</span>`}</td>
      <td data-sv="${e.dur}">${monDur(e.dur)}</td><td class="wrap">${esc(e.reason || "")}</td></tr>`; }).join("")}</tbody></table></div>`;
}

async function monEdit(t0) {
  const t = Object.assign({ kind: "ping", interval: 30, threshold: 3, timeout: 2, slow_ms: 0, icon: "server", enabled: 1, notify: 1 }, t0 || {});
  const groups = [...new Set(MON.targets.map((x) => x.grp).filter(Boolean))];
  let icon = t.icon;
  const iconGrid = () => Object.keys(MON_ICON_SVG).map((k) => `<button type="button" class="mon-pick ${icon === k ? "on" : ""}" data-ic="${k}" title="${MON_ICON_NAME[k]}">${monIcon(k)}<span>${MON_ICON_NAME[k]}</span></button>`).join("")
    + Object.keys(MON.icons).map((k) => `<button type="button" class="mon-pick ${icon === "custom:" + k ? "on" : ""}" data-ic="custom:${k}">${monIcon("custom:" + k)}<span>سفارشی</span></button>`).join("")
    + `<button type="button" class="mon-pick up" id="meUp" title="PNG، JPG یا SVG تا ۲۰۰ کیلوبایت"><svg class="mon-svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><path d="M12 16V5M7 10l5-5 5 5M5 19h14"/></svg><span>آیکن دلخواه…</span></button><input type="file" id="meFile" accept=".png,.jpg,.jpeg,.svg" hidden>`;
  const res = await openModal({ title: t0 ? "ویرایش هدف" : "هدف تازه برای مانیتورینگ", wide: true,
    body: `<div class="form-grid">
      <label class="field"><span>نام</span><input id="meName" value="${esc(t.name || "")}" placeholder="مثلاً روتر مرکزی"></label>
      <div class="field"><span>روش بررسی</span><div class="seg" id="meKind">${[["ping", "Ping"], ["tcp", "پورت TCP"], ["http", "HTTP(S)"], ["snmp", "SNMP"]].map(([v, n]) => `<button type="button" data-v="${v}" class="${t.kind === v ? "on" : ""}">${n}</button>`).join("")}</div></div>
      <label class="field" id="meHostW"><span>IP یا نام میزبان</span><input id="meHost" class="ltr" value="${esc(t.kind === "http" ? "" : t.host || "")}" placeholder="192.168.1.1"></label>
      <label class="field" id="mePortW"><span>پورت</span><input id="mePort" class="ltr" value="${esc(t.port || "")}" placeholder="22, 443, 3389…"></label>
      <div class="field wide" id="meSnmpW">${snEditHtml(t)}</div>
      <label class="field wide" id="meUrlW"><span>آدرس</span><input id="meUrl" class="ltr" value="${esc(t.url || "")}" placeholder="https://portal.example.local"><small class="hint">کد ۵۰۰ به بالا یا بدون پاسخ = قطع. گواهی بررسی نمی‌شود و ریدایرکت دنبال نمی‌شود.</small></label>
      <label class="field" id="meCertW"><span>هشدار انقضای گواهی HTTPS (روز قبل)</span><input id="meCert" type="number" min="0" max="365" value="${esc(t.cert_days || 0)}"><small class="hint">۰ = خاموش. گواهی هر ساعت خوانده می‌شود؛ هشدار روزی یک بار تا تمدید (قطع حساب نمی‌شود).</small></label>
      <label class="field"><span>هر چند ثانیه بررسی شود</span><input id="meInt" type="number" min="10" value="${esc(t.interval)}"></label>
      <label class="field"><span>قطع پس از چند شکست پشت‌سرهم</span><input id="meThr" type="number" min="1" max="20" value="${esc(t.threshold)}"></label>
      <label class="field"><span>Timeout (ثانیه)</span><input id="meTo" type="number" step="0.5" min="0.5" value="${esc(t.timeout)}"></label>
      <label class="field"><span>«کند» اگر پاسخ بیشتر از (ms)</span><input id="meSlow" type="number" min="0" value="${esc(t.slow_ms || 0)}"><small class="hint">۰ = خاموش</small></label>
      <label class="field"><span>گروه</span><input id="meGrp" list="meGrps" value="${esc(t.grp || "")}" placeholder="مثلاً دیتاسنتر"><datalist id="meGrps">${groups.map((g) => `<option value="${esc(g)}">`).join("")}</datalist></label>
      <label class="field"><span>وابسته به (پدر)</span><select id="meParent"><option value="">— بدون وابستگی —</option>${monParentOpts(t)}</select>
        <small class="hint">اگر پدر (مثلاً سوییچ یا لینک بالادست) قطع باشد، این هدف «در دسترس نیست» علامت می‌خورد و هشدار جدا نمی‌دهد.</small></label>
      <div class="field"><span>&nbsp;</span><label class="chk"><input type="checkbox" id="meParentGrp">همین پدر برای همه‌ی هدف‌های این گروه</label></div>
      <div class="field"><span>&nbsp;</span><label class="chk"><input type="checkbox" id="meNotify" ${t.notify ? "checked" : ""}>ایمیل هنگام قطع و وصل و هشدار بحرانی (اگر اعلان ایمیلی روشن باشد)</label></div>
      <div class="field wide"><span>نوع و آیکن</span><div class="mon-picks" id="mePicks">${iconGrid()}</div></div></div>`,
    foot: `<button class="btn ghost" data-r="0">انصراف</button><button class="btn primary" data-r="1">ذخیره</button>`,
    onOpen: (m, close) => {
      const kind = () => $("#meKind button.on", m).dataset.v;
      const vis = () => {
        const k = kind(); $("#meHostW", m).hidden = k === "http"; $("#mePortW", m).hidden = k !== "tcp" && k !== "snmp"; $("#meUrlW", m).hidden = k !== "http"; $("#meCertW", m).hidden = k !== "http";
        $("#meSnmpW", m).hidden = k !== "snmp"; $("#mePort", m).placeholder = k === "snmp" ? "161" : "22, 443, 3389…";
      };
      $$("#meKind button", m).forEach((b) => (b.onclick = () => {
        $$("#meKind button", m).forEach((x) => x.classList.toggle("on", x === b)); vis();
        if (!t0 && b.dataset.v === "snmp") { if ($("#meInt", m).value === "30") $("#meInt", m).value = 60; if ($("#meTo", m).value === "2") $("#meTo", m).value = 3; if (icon === "server") { icon = "switch"; $$("[data-ic]", m).forEach((x) => x.classList.toggle("on", x.dataset.ic === "switch")); } }
      }));
      vis();
      snEditBind(m, t);
      const bindPicks = () => {
        $$("[data-ic]", m).forEach((b) => (b.onclick = () => { icon = b.dataset.ic; $$("[data-ic]", m).forEach((x) => x.classList.toggle("on", x === b)); }));
        $("#meUp", m).onclick = () => $("#meFile", m).click();
        $("#meFile", m).onchange = async (e) => {
          const f = e.target.files[0]; e.target.value = ""; if (!f) return;
          if (f.size > 200 * 1024) return toast("آیکن باید کمتر از ۲۰۰ کیلوبایت باشد.", "error");
          const r = await api("mon_icon_upload", f.name, await blobB64(f));
          if (!r.ok) return toast(r.error, "error");
          const ic = await api("mon_icons"); if (ic.ok) MON.icons = ic.icons;
          icon = r.icon; $("#mePicks", m).innerHTML = iconGrid(); bindPicks();
        };
      };
      bindPicks();
      $("[data-r='0']", m).onclick = () => close(null);
      $("[data-r='1']", m).onclick = async () => {
        const k = kind();
        const body = { id: t.id, name: $("#meName", m).value.trim(), kind: k, host: $("#meHost", m).value.trim(), port: $("#mePort", m).value.trim(),
          url: $("#meUrl", m).value.trim(), cert_days: $("#meCert", m).value || 0, interval: $("#meInt", m).value, threshold: $("#meThr", m).value, timeout: $("#meTo", m).value,
          slow_ms: $("#meSlow", m).value, grp: $("#meGrp", m).value.trim(), icon, notify: $("#meNotify", m).checked, enabled: t.enabled !== 0, notes: t.notes || "",
          parent_id: $("#meParent", m).value || null };
        if (k === "snmp") { body.snmp = snEditCollect(m); body.cred_id = $("#snCred", m).value; }
        const r = await api("mon_save", body);
        if (!r.ok) return toast(r.error, "error");
        if ($("#meParentGrp", m).checked && body.grp) {
          const g = await api("mon_parent_group", body.grp, body.parent_id ? Number(body.parent_id) : null);
          if (!g.ok) toast(g.error, "error"); else toast(`وابستگی ${num(g.count)} هدف گروه «${body.grp}» تنظیم شد`, "ok");
        }
        close(true);
      };
    } });
  if (res) { toast("ذخیره شد", "ok"); loadMon(); }
}

/* ---------------------------------------------------------------- آمار ← مانیتورینگ */
async function renderMonStats() {
  const body = $("#statsBody");
  if (!MON.targets.length) { const r = await api("mon_list"); if (r.ok) MON.targets = r.targets; }
  if (!Object.keys(MON.icons).length) { const ic = await api("mon_icons"); if (ic.ok) MON.icons = ic.icons; }
  const R = MON.rep;
  const r = await api("mon_report", trApi(MON.tr), R.id ? [Number(R.id)] : null);
  if (S.page !== "stats" || ST.tab !== "monitor") return;
  if (!r.ok) { body.innerHTML = `<div class="toolbar"><div id="mrTr"></div></div><div class="panel"><div class="empty">${esc(r.error)}</div></div>`; trBar($("#mrTr"), monRepBar); return; }
  MON.repData = r;
  const rows = r.rows, c = COLORS();
  const checks = rows.reduce((a, x) => a + x.checks, 0);
  const avail = checks ? rows.reduce((a, x) => a + (x.avail == null ? 0 : x.avail * x.checks), 0) / checks : null;
  const outages = rows.reduce((a, x) => a + x.outages, 0), down = rows.reduce((a, x) => a + x.downtime, 0);
  const rn = rows.filter((x) => x.rtt_avg != null), rtt = rn.length ? rn.reduce((a, x) => a + x.rtt_avg, 0) / rn.length : null;
  const ax = monAxis(r.keys, r.step), lab = ax.lab;
  const keepY = $(".main").scrollTop;
  body.innerHTML = `<div class="toolbar"><div id="mrTr"></div>
      <select id="mrTarget" style="width:auto;min-width:220px"><option value="">همه‌ی هدف‌ها</option>${MON.targets.map((t) => `<option value="${t.id}" ${String(t.id) === String(R.id) ? "selected" : ""}>${esc(t.name)}</option>`).join("")}</select>
      <button class="btn no-ro" id="mrCsv">خروجی CSV</button></div>
    <div class="tr-note"><span class="ltr">${esc(trFmt(r.since) + " — " + trFmt(r.until))}</span> · ${esc(trResNote(r))} · ${esc(I18N.t("برای زوم، روی نمودار بکشید؛ دوبار کلیک = بازه‌ی بزرگ‌تر"))}</div>
    ${rows.length ? `<div class="kpis">
      <div class="kpi"><b>${avail == null ? "—" : num(Math.round(avail * 100) / 100) + "٪"}</b><span>در دسترس بودن</span></div>
      <div class="kpi"><b>${num(outages)}</b><span>قطعی${rows.some((x) => x.unreach) ? ` (+${num(rows.reduce((a, x) => a + (x.unreach || 0), 0))} به‌خاطر پدر)` : ""}</span></div>
      <div class="kpi"><b>${down ? monDur(down) : "—"}</b><span>مجموع زمان قطعی</span></div>
      <div class="kpi"><b>${rtt == null ? "—" : num(Math.round(rtt * 10) / 10) + " ms"}</b><span>میانگین زمان پاسخ</span></div>
      <div class="kpi"><b>${num(checks)}</b><span>بررسی انجام‌شده</span></div></div>
    <div class="chart-grid">
      <div class="chart-card wide"><div class="chart-head"><h3>${R.id ? "در دسترس بودن (٪)" : "میانگین در دسترس بودن همه‌ی هدف‌ها (٪)"}</h3><button class="btn-img no-ro" data-png="mrAv" data-title="در دسترس بودن"><svg><use href="#i-img"/></svg>ذخیره‌ی تصویر</button></div><div class="chart" id="mrAv"></div></div>
      <div class="chart-card wide"><div class="chart-head"><h3>${R.id ? "زمان پاسخ (ms)" : "هدف‌های دارای قطعی در هر بازه"}</h3><button class="btn-img no-ro" data-png="mrSec" data-title="مانیتورینگ"><svg><use href="#i-img"/></svg>ذخیره‌ی تصویر</button></div><div class="chart" id="mrSec"></div></div>
      <div class="chart-card wide"><div class="chart-head"><h3>نوار وضعیت</h3><span class="muted">سبز = کامل · زرد = کمتر از ۱۰۰٪ · قرمز = کمتر از ۹۰٪</span></div>
        <div class="mon-tl">${rows.map((x) => `<div class="mon-tl-row"><span class="nm bidi" title="${esc(x.name)}">${esc(x.name)}</span><span class="bar">${x.avail_series.map((v, i) => `<i class="${v == null ? "n" : v >= 99.9 ? "g" : v >= 90 ? "y" : "r"}" title="${esc(ax.tips[i])}: ${v == null ? "—" : v + "%"}"></i>`).join("")}</span></div>`).join("")}</div></div>
    </div>
    <div class="panel"><div class="panel-head"><h3>هدف‌ها</h3></div><div class="table-wrap inner"><table class="grid"><thead><tr><th></th><th>هدف</th><th>آدرس</th><th>در دسترس بودن</th><th>قطعی</th><th>زمان قطعی</th><th>میانگین پاسخ</th><th>بیشترین پاسخ</th><th>بررسی</th></tr></thead><tbody>
      ${rows.map((x) => `<tr><td>${monIcon(x.icon, "sm")}</td><td class="bidi">${esc(x.name)}</td><td class="ltr">${esc(x.host)}</td><td data-sv="${x.avail ?? ""}">${x.avail == null ? "—" : num(x.avail) + "٪"}</td><td>${num(x.outages)}</td>
        <td data-sv="${x.downtime}">${x.downtime ? monDur(x.downtime) : "—"}</td><td class="ltr">${x.rtt_avg == null ? "—" : num(x.rtt_avg) + " ms"}</td><td class="ltr">${x.rtt_max == null ? "—" : num(x.rtt_max) + " ms"}</td><td>${num(x.checks)}</td></tr>`).join("")}</tbody></table></div></div>
    <div class="panel"><div class="panel-head"><h3>قطعی‌ها</h3></div>${monEvTable(r.events, true)}</div>`
    : `<div class="panel"><div class="empty">هدفی برای گزارش نیست. هدف‌ها را در صفحه‌ی «مانیتورینگ» اضافه کنید.</div></div>`}`;
  trBar($("#mrTr"), monRepBar);
  $("#mrTarget").onchange = (e) => { R.id = e.target.value; renderMonStats(); };
  $("#mrCsv").onclick = monCsv;
  $(".main").scrollTop = keepY;
  if (!rows.length) return;
  const set = (x) => monRepBar.set(x);
  const z = { zoom: (a, b) => monZoomTo(r.keys, r.step, a, b, set), zoomOut: () => monZoomOut(MON.tr, set), sync: "mr", times: ax.times, tips: ax.tips };
  const pf = (v) => Math.round(v * 100) / 100 + "%";
  if (R.id) {
    drawChart($("#mrAv"), lab, [{ name: "در دسترس بودن", color: c.ok, values: rows[0].avail_series }], { type: "line", fmt: pf, stats: true, ...z });
    drawChart($("#mrSec"), lab, [{ name: "میانگین", color: c.info, values: rows[0].rtt_series }], { type: "line", fmt: (v) => Math.round(v * 10) / 10 + " ms", stats: true, ...z });
  } else {
    const avg = lab.map((_, i) => { const v = rows.map((x) => x.avail_series[i]).filter((x) => x != null); return v.length ? Math.round((v.reduce((a, b) => a + b, 0) / v.length) * 100) / 100 : null; });
    const bad = lab.map((_, i) => rows.filter((x) => x.avail_series[i] != null && x.avail_series[i] < 100).length);
    drawChart($("#mrAv"), lab, [{ name: "میانگین در دسترس بودن", color: c.ok, values: avg }], { type: "line", fmt: pf, stats: true, ...z });
    drawChart($("#mrSec"), lab, [{ name: "هدف دارای قطعی", color: c.err, values: bad }], { tips: ax.tips });
  }
}
const monRepBar = { get: () => MON.tr, set: (R) => { monTrSet(R); renderMonStats(); }, refresh: () => renderMonStats() };
async function monCsv() {
  const r = MON.repData; if (!r) return;
  const q = (v) => `"${String(v ?? "").replace(/"/g, '""')}"`;
  const lines = [[I18N.t("زمان"), ...r.rows.flatMap((x) => [x.name + " %", x.name + " ms"])].map(q).join(",")];
  r.keys.forEach((k, i) => lines.push([trFmt(k), ...r.rows.flatMap((x) => [x.avail_series[i], x.rtt_series[i]])].map(q).join(",")));
  lines.push("");
  lines.push([I18N.t("هدف"), I18N.t("شروع قطعی"), I18N.t("پایان"), I18N.t("مدت (ثانیه)"), I18N.t("علت")].map(q).join(","));
  r.events.forEach((e) => lines.push([e.name, trFmt(e.start), e.end ? trFmt(e.end) : "", e.dur, e.reason].map(q).join(",")));
  const res = await api("save_export", `autokrp_monitor_${r.range}.csv`, "﻿" + lines.join("\r\n"), false);
  if (!res.ok) return toast(res.error, "error"); if (!res.cancelled) toast("ذخیره شد: " + res.path, "ok");
}

/* ---------------------------------------------------------------- تنظیمات ← مانیتورینگ (صدا) */
async function monSoundUpload(which, inputEl) {
  const f = inputEl.files[0]; inputEl.value = ""; if (!f) return;
  if (f.size > 2 * 1024 * 1024) return toast("فایل صدا باید کمتر از ۲ مگابایت باشد.", "error");
  const r = await api("mon_sound_set", which, f.name, await blobB64(f));
  if (!r.ok) return toast(r.error, "error");
  delete MON.sounds[which];
  if (S.draft && S.draft.monitor) S.draft.monitor["sound_" + which] = "custom:" + r.ext;
  if (S.settings && S.settings.monitor) S.settings.monitor["sound_" + which] = "custom:" + r.ext;
  toast("صدا ذخیره شد", "ok"); renderSettings();
}
async function monSoundReset(which) {
  const r = await api("mon_sound_set", which, "", "");
  if (!r.ok) return toast(r.error, "error");
  delete MON.sounds[which];
  if (S.draft && S.draft.monitor) S.draft.monitor["sound_" + which] = "";
  if (S.settings && S.settings.monitor) S.settings.monitor["sound_" + which] = "";
  renderSettings();
}

/* ---------------------------------------------------------------- بستن پنجره در دسکتاپ وقتی مانیتورینگ فعال است */
window.monCloseAsk = async function () {
  if (modalClose) modalClose(null);
  const r = await openModal({ title: "بستن برنامه",
    body: `<p>مانیتورینگ فعال است. اگر برنامه کامل بسته شود، بررسی‌ها و هشدار قطعی متوقف می‌شوند.</p>
      <p class="hint">در پس‌زمینه: پنجره پنهان می‌شود، بررسی‌ها ادامه دارند و هنگام قطعی صدا پخش و پنجره باز می‌شود. برای باز کردن دوباره روی آیکن AutoKRP کنار ساعت ویندوز (Show hidden icons) کلیک کنید.</p>
      <label class="chk" style="margin-top:10px"><input type="checkbox" id="mcRem">انتخابم را به خاطر بسپار (قابل تغییر در تنظیمات ← مانیتورینگ)</label>`,
    foot: `<button class="btn ghost" data-r="cancel">انصراف</button><button class="btn danger-ghost" data-r="quit">بستن کامل</button><button class="btn primary" data-r="background">ادامه در پس‌زمینه</button>`,
    onOpen: (m, close) => $$("[data-r]", m).forEach((b) => (b.onclick = () => close({ a: b.dataset.r, rem: $("#mcRem", m).checked }))) });
  if (!r || r.a === "cancel") return;
  const x = await api("app_close_choice", r.a, r.rem);
  if (!x.ok) toast(x.error, "error");
};

/* ---------------------------------------------------------------- 1.24: وابستگی و پنجره‌ی نگهداری */
function monParentOpts(t) {
  // هدف مشترک فقط به هدف مشترک؛ هدف شخصی به مشترک یا شخصی همان کاربر؛ نه خودش و نه فرزندانش
  const kids = new Set(); let grew = true;
  if (t.id) kids.add(t.id);
  while (grew) { grew = false; MON.targets.forEach((x) => { if (x.parent_id && kids.has(x.parent_id) && !kids.has(x.id)) { kids.add(x.id); grew = true; } }); }
  const owner = t.id ? (t.owner || "") : MON.admin ? "" : null;      // null = هدف تازه‌ی اپراتور (شخصی خودش)
  return MON.targets.filter((x) => !kids.has(x.id) && (!x.owner || (owner === null ? x.mine : x.owner === owner)))
    .map((x) => `<option value="${x.id}" ${x.id === t.parent_id ? "selected" : ""}>${esc(x.name)}${x.grp ? " — " + esc(x.grp) : ""}</option>`).join("");
}
function monRelLine(t) {
  const p = t.parent_id && MON.targets.find((x) => x.id === t.parent_id);
  const kids = MON.targets.filter((x) => x.parent_id === t.id);
  const parts = [];
  if (p) parts.push(`وابسته به: <b class="bidi">${esc(p.name)}</b>`);
  if (kids.length) parts.push(`${num(kids.length)} هدف وابسته`);
  if (t.status === "unreachable" && t.cause) parts.push(`<span class="tag unr">در دسترس نیست به‌خاطر قطع «${esc(t.cause)}»</span>`);
  if (t.maint) parts.push(`<span class="tag mnt">پنجره‌ی نگهداری: ${esc(t.maint)}</span>`);
  return parts.length ? `<div class="row muted" style="gap:10px;flex-wrap:wrap;margin-top:4px">${parts.join(" · ")}</div>` : "";
}
function monMaintWhen(w) {
  if (w.kind === "once") return `<span class="ltr">${esc(trFmt(w.start))} — ${esc(trFmt(w.end))}</span>`;
  const ds = String(w.days || "").split(",").map(Number);
  return `هر ${MON_WD.filter(([v]) => ds.includes(v)).map(([, n]) => n).join("، ")} <span class="ltr">${esc(w.t_from)}–${esc(w.t_to)}</span>`;
}
async function monMaintList() {
  if (!MON.targets.length) await loadMon();
  const r = await api("mon_maint_list"); if (!r.ok) return toast(r.error, "error");
  const name = (id) => (MON.targets.find((x) => x.id === id) || {}).name || "#" + id;
  const res = await openModal({ title: "پنجره‌های نگهداری", wide: true,
    body: `<p class="hint">در این بازه‌ها بررسی ادامه دارد ولی قطعی هشدار، صدا و ایمیل ندارد و در «در دسترس بودن» حساب نمی‌شود. اگر بعد از پایان پنجره هنوز قطع باشد، هشدار عادی می‌آید.</p>
      ${r.windows.length ? `<div class="table-wrap inner"><table class="grid"><thead><tr><th>نام</th><th>زمان</th><th>هدف‌ها و گروه‌ها</th><th>وضعیت</th><th class="nosort"></th></tr></thead><tbody>
      ${r.windows.map((w) => `<tr><td><b>${esc(w.name)}</b>${w.owner ? ` <span class="tag mute">شخصی</span>` : ""}${w.note ? `<div class="muted">${esc(w.note)}</div>` : ""}</td><td>${monMaintWhen(w)}</td>
        <td class="wrap">${[...w.groups.map((g) => `گروه «${esc(g)}»`), ...w.ids.map((i) => esc(name(i)))].join("، ")}</td>
        <td>${!w.enabled ? `<span class="tag mute">خاموش</span>` : w.active ? `<span class="tag mnt">فعال است</span>` : `<span class="tag info">منتظر</span>`}</td>
        <td>${w.can_edit ? `<button class="btn sm" data-me="${w.id}">ویرایش</button> <button class="btn sm danger-ghost" data-md="${w.id}">حذف</button>` : ""}</td></tr>`).join("")}</tbody></table></div>`
      : `<div class="empty">پنجره‌ای تعریف نشده است.</div>`}`,
    foot: `<button class="btn ghost" data-r="0">بستن</button>${r.can_add ? `<button class="btn primary" data-r="new">+ پنجره‌ی تازه</button>` : ""}`,
    onOpen: (m, close) => {
      $("[data-r='0']", m).onclick = () => close(null);
      if ($("[data-r='new']", m)) $("[data-r='new']", m).onclick = () => close({ edit: {} });
      $$("[data-me]", m).forEach((b) => (b.onclick = () => close({ edit: r.windows.find((w) => w.id === Number(b.dataset.me)) })));
      $$("[data-md]", m).forEach((b) => (b.onclick = () => close({ del: Number(b.dataset.md) })));
    } });
  if (!res) return;
  if (res.del) {
    if (await confirm2({ title: "حذف پنجره", body: "<p>این پنجره‌ی نگهداری حذف شود؟</p>", confirm: "حذف", danger: true })) {
      const x = await api("mon_maint_delete", res.del); if (!x.ok) toast(x.error, "error");
    }
    return monMaintList();
  }
  if (await monMaintEdit(res.edit)) loadMon();
  monMaintList();
}
async function monMaintEdit(w0) {
  const w = Object.assign({ kind: "once", enabled: 1, ids: [], groups: [], days: "", t_from: "22:00", t_to: "02:00" }, w0 || {});
  const now = Date.now() / 1000, st = w.start || Math.ceil(now / 3600) * 3600, en = w.end || st + 2 * 3600;
  const groups = [...new Set(MON.targets.map((x) => x.grp).filter(Boolean))].sort((a, b) => a.localeCompare(b, "fa"));
  const days = String(w.days || "").split(",").filter(Boolean).map(Number);
  return openModal({ title: w.id ? "ویرایش پنجره‌ی نگهداری" : "پنجره‌ی نگهداری تازه", wide: true,
    body: `<div class="form-grid">
      <label class="field"><span>نام</span><input id="mwName" value="${esc(w.name || "")}" placeholder="مثلاً ارتقای فایروال"></label>
      <div class="field"><span>نوع</span><div class="seg" id="mwKind"><button type="button" data-v="once" class="${w.kind === "once" ? "on" : ""}">یک‌باره</button><button type="button" data-v="weekly" class="${w.kind === "weekly" ? "on" : ""}">هفتگی</button></div></div>
      <div class="field wide" id="mwOnce"><span>از … تا … <span class="muted">(${esc(trCal() === "j" ? "شمسی" : "میلادی")})</span></span>
        <div class="row" style="gap:6px;flex-wrap:wrap"><input id="mwFd" class="ltr" style="width:120px" value="${trFmtDay(st)}"><input id="mwFt" class="ltr" style="width:80px" value="${trFmtTime(st)}">
        <span>تا</span><input id="mwTd" class="ltr" style="width:120px" value="${trFmtDay(en)}"><input id="mwTt" class="ltr" style="width:80px" value="${trFmtTime(en)}"></div></div>
      <div class="field wide" id="mwWeek"><span>روزها و ساعت (پنجره‌ی شبانه مثل 22:00 تا 02:00 از روز انتخاب‌شده شروع می‌شود)</span>
        <div class="row" style="gap:6px;flex-wrap:wrap">${MON_WD.map(([v, n]) => `<label class="chk"><input type="checkbox" class="mwD" value="${v}" ${days.includes(v) ? "checked" : ""}>${n}</label>`).join("")}
        <span style="margin-inline-start:12px">از</span><input id="mwHf" class="ltr" style="width:80px" value="${esc(w.t_from)}"><span>تا</span><input id="mwHt" class="ltr" style="width:80px" value="${esc(w.t_to)}"></div></div>
      <div class="field wide"><span>گروه‌ها</span><div class="row" style="gap:10px;flex-wrap:wrap">${groups.length ? groups.map((g) => `<label class="chk"><input type="checkbox" class="mwG" value="${esc(g)}" ${w.groups.includes(g) ? "checked" : ""}>${esc(g)}</label>`).join("") : `<span class="muted">گروهی تعریف نشده است.</span>`}</div></div>
      <div class="field wide"><span>هدف‌ها</span><input type="search" class="search" id="mwQ" placeholder="جستجو…" style="max-width:260px;margin-bottom:6px">
        <div class="mw-list">${MON.targets.filter((x) => x.can_edit || MON.admin).map((x) => `<label class="chk" data-n="${esc((x.name + " " + (x.grp || "") + " " + monWhere(x)).toLowerCase())}"><input type="checkbox" class="mwT" value="${x.id}" ${w.ids.includes(x.id) ? "checked" : ""}>${esc(x.name)} <span class="muted ltr">${esc(monWhere(x))}</span></label>`).join("")}</div></div>
      <label class="field wide"><span>یادداشت</span><input id="mwNote" value="${esc(w.note || "")}"></label>
      <div class="field"><span>&nbsp;</span><label class="chk"><input type="checkbox" id="mwOn" ${w.enabled ? "checked" : ""}>فعال</label></div></div>`,
    foot: `<button class="btn ghost" data-r="0">انصراف</button><button class="btn primary" data-r="1">ذخیره</button>`,
    onOpen: (m, close) => {
      const kind = () => $("#mwKind button.on", m).dataset.v;
      const vis = () => { $("#mwOnce", m).hidden = kind() !== "once"; $("#mwWeek", m).hidden = kind() !== "weekly"; };
      $$("#mwKind button", m).forEach((b) => (b.onclick = () => { $$("#mwKind button", m).forEach((x) => x.classList.toggle("on", x === b)); vis(); }));
      vis();
      $("#mwQ", m).oninput = (e) => { const q = e.target.value.toLowerCase(); $$(".mw-list label", m).forEach((l) => (l.hidden = q && !l.dataset.n.includes(q))); };
      $("[data-r='0']", m).onclick = () => close(null);
      $("[data-r='1']", m).onclick = async () => {
        const body = { id: w.id, name: $("#mwName", m).value.trim(), kind: kind(), enabled: $("#mwOn", m).checked, note: $("#mwNote", m).value.trim(),
          scope: { ids: $$(".mwT:checked", m).map((x) => Number(x.value)), groups: $$(".mwG:checked", m).map((x) => x.value) } };
        if (body.kind === "once") {
          body.start = trParse($("#mwFd", m).value, $("#mwFt", m).value); body.end = trParse($("#mwTd", m).value, $("#mwTt", m).value);
          if (!body.start || !body.end) return toast("تاریخ یا ساعت نامعتبر است", "error");
        } else { body.days = $$(".mwD:checked", m).map((x) => Number(x.value)); body.t_from = trDigits($("#mwHf", m).value); body.t_to = trDigits($("#mwHt", m).value); }
        const r = await api("mon_maint_save", body);
        if (!r.ok) return toast(r.error, "error");
        toast("ذخیره شد", "ok"); close(true);
      };
    } });
}
