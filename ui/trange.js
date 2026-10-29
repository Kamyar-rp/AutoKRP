"use strict";
/* ================================================================ بازه‌ی زمانی نمودارها (1.23)
 * انتخاب‌گر مشترک مانیتورینگ: بازه‌های آماده، «از … تا …» دلخواه با تقویم شمسی یا میلادی (طبق تنظیم برنامه)،
 * جابه‌جایی بازه (◀ ▶)، بزرگ‌تر کردن، به‌روزرسانی خودکار، و زوم با کشیدن موس روی نمودار (drawChart با zoom).
 * R (وضعیت بازه) = {p: "24h"} یا {from, to} (ثانیه). */

/* ---------------------------------------------------------------- تقویم شمسی (الگوریتم ۳۳ ساله؛ با Intl برای ۱۹۵۰ تا ۲۱۰۰ بررسی شد) */
function g2j(gy, gm, gd) {
  const gdm = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
  const gy2 = gm > 2 ? gy + 1 : gy;
  let days = 355666 + 365 * gy + Math.floor((gy2 + 3) / 4) - Math.floor((gy2 + 99) / 100) + Math.floor((gy2 + 399) / 400) + gd + gdm[gm - 1];
  let jy = -1595 + 33 * Math.floor(days / 12053); days %= 12053;
  jy += 4 * Math.floor(days / 1461); days %= 1461;
  if (days > 365) { jy += Math.floor((days - 1) / 365); days = (days - 1) % 365; }
  return days < 186 ? [jy, 1 + Math.floor(days / 31), 1 + (days % 31)] : [jy, 7 + Math.floor((days - 186) / 30), 1 + ((days - 186) % 30)];
}
function j2g(jy, jm, jd) {
  jy += 1595;
  let days = -355668 + 365 * jy + Math.floor(jy / 33) * 8 + Math.floor(((jy % 33) + 3) / 4) + jd + (jm < 7 ? (jm - 1) * 31 : (jm - 7) * 30 + 186);
  let gy = 400 * Math.floor(days / 146097); days %= 146097;
  if (days > 36524) { gy += 100 * Math.floor(--days / 36524); days %= 36524; if (days >= 365) days++; }
  gy += 4 * Math.floor(days / 1461); days %= 1461;
  if (days > 365) { gy += Math.floor((days - 1) / 365); days = (days - 1) % 365; }
  let gd = days + 1;
  const ml = [0, 31, (gy % 4 === 0 && gy % 100 !== 0) || gy % 400 === 0 ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  let gm = 0; for (gm = 0; gm < 13 && gd > ml[gm]; gm++) gd -= ml[gm];
  return [gy, gm, gd];
}
const TR_JMON = ["فروردین", "اردیبهشت", "خرداد", "تیر", "مرداد", "شهریور", "مهر", "آبان", "آذر", "دی", "بهمن", "اسفند"];
const TR_GMON = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"];
const trCal = () => ((typeof S !== "undefined" && S.settings && S.settings.ui && S.settings.ui.calendar) || (typeof ST !== "undefined" && ST.cal) || "jalali") === "gregorian" ? "g" : "j";
const p2 = (n) => String(n).padStart(2, "0");
const trDigits = (s) => String(s || "").replace(/[۰-۹]/g, (d) => "۰۱۲۳۴۵۶۷۸۹".indexOf(d)).replace(/[٠-٩]/g, (d) => "٠١٢٣٤٥٦٧٨٩".indexOf(d));

/** {y, m, d} در تقویم فعلی برای یک Date محلی */
function trYmd(dt, cal = trCal()) {
  if (cal === "g") return { y: dt.getFullYear(), m: dt.getMonth() + 1, d: dt.getDate() };
  const [y, m, d] = g2j(dt.getFullYear(), dt.getMonth() + 1, dt.getDate());
  return { y, m, d };
}
/** Date محلی ساعت ۰ برای y/m/d تقویم فعلی */
function trDay(y, m, d, cal = trCal()) {
  if (cal === "g") return new Date(y, m - 1, d);
  const [gy, gm, gd] = j2g(y, m, d);
  return new Date(gy, gm - 1, gd);
}
function trMonthLen(y, m, cal = trCal()) {
  if (cal === "g") return new Date(y, m, 0).getDate();
  if (m <= 6) return 31; if (m <= 11) return 30;
  const n = trDay(y + 1, 1, 1, "j"); n.setDate(n.getDate() - 1); return trYmd(n, "j").d;
}
function trFmtDay(ts, cal = trCal()) { const o = trYmd(new Date(ts * 1000), cal); return `${o.y}/${p2(o.m)}/${p2(o.d)}`; }
function trFmtTime(ts) { const d = new Date(ts * 1000); return `${p2(d.getHours())}:${p2(d.getMinutes())}`; }
function trFmt(ts) { return `${trFmtDay(ts)} ${trFmtTime(ts)}`; }
/** «1405/07/29» + «14:30» ← ثانیه؛ نامعتبر ← null */
function trParse(day, time) {
  const m = trDigits(day).trim().match(/^(\d{4})[/\-.](\d{1,2})[/\-.](\d{1,2})$/);
  const t = trDigits(time || "00:00").trim().match(/^(\d{1,2}):(\d{2})$/);
  if (!m || !t) return null;
  const y = +m[1], mo = +m[2], d = +m[3], H = +t[1], M = +t[2];
  if (mo < 1 || mo > 12 || d < 1 || d > trMonthLen(y, mo) || H > 23 || M > 59) return null;
  const dt = trDay(y, mo, d); dt.setHours(H, M, 0, 0);
  return Math.floor(dt.getTime() / 1000);
}
/** برچسب محور: کوتاه، بسته به دقت و طول بازه */
function trTick(ts, step, span) {
  const d = new Date(ts * 1000), o = trYmd(d), md = `${p2(o.m)}/${p2(o.d)}`;
  if (step < 3600) return span > 86400 ? `${md} ${p2(d.getHours())}:${p2(d.getMinutes())}` : `${p2(d.getHours())}:${p2(d.getMinutes())}`;
  if (step < 86400) return `${md} ${p2(d.getHours())}h`;
  return span > 300 * 86400 ? `${o.y}/${md}` : md;
}
/** برچسب کامل راهنمای نمودار: «شروع تا پایان خانه» */
function trTip(ts, step) {
  const e = ts + step;
  if (step >= 86400) return step === 86400 ? trFmtDay(ts) : `${trFmtDay(ts)} — ${trFmtDay(e - 1)}`;
  return `${trFmt(ts)}${step > 60 ? " — " + trFmtTime(e) : ""}`;
}

/* ---------------------------------------------------------------- بازه‌ها */
const TR_PRE = [["15m", "۱۵ دقیقه‌ی گذشته", 900], ["1h", "۱ ساعت گذشته", 3600], ["6h", "۶ ساعت گذشته", 21600], ["12h", "۱۲ ساعت گذشته", 43200],
  ["24h", "۲۴ ساعت گذشته", 86400], ["7d", "۷ روز گذشته", 7 * 86400], ["30d", "۳۰ روز گذشته", 30 * 86400], ["90d", "۹۰ روز گذشته", 90 * 86400], ["365d", "یک سال گذشته", 365 * 86400], ["730d", "دو سال گذشته", 730 * 86400]];
const TR_CAL_PRE = [["today", "امروز"], ["yday", "دیروز"], ["week", "این هفته"], ["pweek", "هفته‌ی قبل"], ["month", "این ماه"], ["pmonth", "ماه قبل"]];
const TR_AUTO = [[0, "خاموش"], [30, "۳۰ ثانیه"], [60, "۱ دقیقه"], [300, "۵ دقیقه"]];
const TR_MIN_FROM = 946684800;     // 2000-01-01 (داده‌ها بدون محدودیت نگه داشته می‌شوند)

function trStartOfWeek(dt) {
  const d = new Date(dt.getFullYear(), dt.getMonth(), dt.getDate());
  const first = trCal() === "j" ? 6 : 1;                     // شمسی: شنبه؛ میلادی: دوشنبه
  d.setDate(d.getDate() - ((d.getDay() - first + 7) % 7));
  return d;
}
/** {from, to, live}: live یعنی پایان بازه «اکنون» است (به‌روزرسانی خودکار معنی دارد) */
function trResolve(R) {
  const now = Date.now() / 1000, nd = new Date(), s = (d) => Math.floor(d.getTime() / 1000);
  if (R && R.p) {
    const pr = TR_PRE.find((x) => x[0] === R.p);
    if (pr) return { from: now - pr[2], to: now, live: true };
    const today = new Date(nd.getFullYear(), nd.getMonth(), nd.getDate());
    if (R.p === "today") return { from: s(today), to: now, live: true };
    if (R.p === "yday") { const y = new Date(today); y.setDate(y.getDate() - 1); return { from: s(y), to: s(today), live: false }; }
    if (R.p === "week" || R.p === "pweek") {
      const w = trStartOfWeek(nd);
      if (R.p === "week") return { from: s(w), to: now, live: true };
      const pw = new Date(w); pw.setDate(pw.getDate() - 7); return { from: s(pw), to: s(w), live: false };
    }
    if (R.p === "month" || R.p === "pmonth") {
      const o = trYmd(nd), m0 = trDay(o.y, o.m, 1);
      if (R.p === "month") return { from: s(m0), to: now, live: true };
      const py = o.m === 1 ? o.y - 1 : o.y, pm = o.m === 1 ? 12 : o.m - 1;
      return { from: s(trDay(py, pm, 1)), to: s(m0), live: false };
    }
  }
  if (R && R.from && R.to) return { from: R.from, to: Math.min(R.to, now), live: false };
  return { from: now - 86400, to: now, live: true };
}
/** آنچه به API فرستاده می‌شود: بازه‌ی آماده‌ی نسبی با ساعت سرور، بقیه {from, to} */
function trApi(R) {
  if (R && R.p && TR_PRE.some((x) => x[0] === R.p)) return R.p;
  const r = trResolve(R); return { from: Math.floor(r.from), to: Math.ceil(r.to) };
}
function trLabel(R) {
  if (R && R.p) { const x = TR_PRE.find((y) => y[0] === R.p) || TR_CAL_PRE.find((y) => y[0] === R.p); if (x) return I18N.t(x[1]); }
  const r = trResolve(R);
  return trFmtDay(r.from) === trFmtDay(r.to) ? `${trFmtDay(r.from)} ${trFmtTime(r.from)} — ${trFmtTime(r.to)}` : `${trFmt(r.from)} — ${trFmt(r.to)}`;
}
function trCustom(from, to) {
  const now = Date.now() / 1000;
  to = Math.min(to, now); from = Math.max(from, TR_MIN_FROM);
  if (to - from < 60) from = to - 60;
  return { from: Math.floor(from), to: Math.ceil(to) };
}
/** نوشته‌ی کوچک زیر نمودار درباره‌ی دقت داده */
function trResNote(r) {
  if (!r || !r.step) return "";
  // جمله‌ی کامل با جای مقدار تا ترجمه‌ی رابط الگو را پیدا کند
  const st = r.step < 3600 ? I18N.t(`هر نقطه = ${num(r.step / 60)} دقیقه`) : r.step < 86400 ? I18N.t(`هر نقطه = ${num(r.step / 3600)} ساعت`) : I18N.t(`هر نقطه = ${num(r.step / 86400)} روز`);
  const old = r.res === "hour" && r.step < 86400 && (r.until - r.since) <= 8 * 86400 ? " · " + I18N.t("داده‌ی دقیق‌تر برای این بازه نگه داشته نشده است (فقط چند روز اخیر)") : "";
  return st + old;
}

/* ---------------------------------------------------------------- نوار انتخاب بازه
 * trBar(el, {get, set, refresh}) — get() وضعیت فعلی، set(R) تغییر بازه (رسم دوباره)، refresh() به‌روزرسانی خودکار بی‌صدا */
const TR_STATE = { auto: (() => { try { return Number(localStorage.getItem("akrp_tr_auto") || 0); } catch (_) { return 0; } })() };
function trBar(el, o) {
  const R = o.get();
  el.classList.add("trbar");
  el.innerHTML = `<button class="iconbtn" data-tr="prev" title="${esc(I18N.t("بازه‌ی قبل"))}">◀</button>
    <button class="trbtn" data-tr="open" title="${esc(I18N.t("انتخاب بازه‌ی زمانی"))}"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="12" cy="12" r="8.5"/><path d="M12 7.5V12l3 2"/></svg><span class="bidi">${esc(trLabel(R))}</span><b>▾</b></button>
    <button class="iconbtn" data-tr="next" title="${esc(I18N.t("بازه‌ی بعد"))}" ${trResolve(R).live ? "disabled" : ""}>▶</button>
    <button class="iconbtn" data-tr="out" title="${esc(I18N.t("بازه‌ی بزرگ‌تر (دو برابر)"))}">⊖</button>
    <label class="trauto" title="${esc(I18N.t("به‌روزرسانی خودکار وقتی پایان بازه «اکنون» است"))}"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M20 11a8 8 0 1 0-2.3 5.7M20 5v6h-6"/></svg>
      <select data-tr="auto">${TR_AUTO.map(([v, t]) => `<option value="${v}" ${TR_STATE.auto === v ? "selected" : ""}>${esc(I18N.t(t))}</option>`).join("")}</select></label>`;
  const shift = (dir) => {
    const r = trResolve(o.get()), span = r.to - r.from;
    o.set(trCustom(r.from + dir * span, r.to + dir * span));
  };
  $("[data-tr='prev']", el).onclick = () => shift(-1);
  $("[data-tr='next']", el).onclick = () => shift(1);
  $("[data-tr='out']", el).onclick = () => {
    const r = trResolve(o.get()), span = r.to - r.from;
    if (r.live) { const pr = TR_PRE.find((x) => x[2] >= span * 2 - 1); return o.set(pr ? { p: pr[0] } : { p: "365d" }); }
    o.set(trCustom(r.from - span / 2, r.to + span / 2));
  };
  $("[data-tr='open']", el).onclick = (e) => { e.stopPropagation(); trPop(el, o); };
  $("[data-tr='auto']", el).onchange = (e) => { TR_STATE.auto = Number(e.target.value); try { localStorage.setItem("akrp_tr_auto", String(TR_STATE.auto)); } catch (_) { /* فقط همین مرورگر */ } trAutoArm(el, o); };
  trAutoArm(el, o);
}
function trAutoArm(el, o) {
  clearInterval(el._trAuto);
  if (!TR_STATE.auto) return;
  el._trAuto = setInterval(() => {
    if (!el.isConnected) return clearInterval(el._trAuto);
    if (document.hidden || $(".trpop")) return;
    if (trResolve(o.get()).live) o.refresh();
  }, TR_STATE.auto * 1000);
}
function trPopClose() { const p = $(".trpop"); if (p) { p.remove(); return true; } return false; }
document.addEventListener("mousedown", (e) => { const p = $(".trpop"); if (p && !p.contains(e.target) && !e.target.closest("[data-tr='open']")) p.remove(); }, true);

function trPop(bar, o) {
  if (trPopClose()) return;
  const R = o.get(), r = trResolve(R), cal = trCal();
  const now = new Date();
  const C = { f: { day: trFmtDay(r.from), time: trFmtTime(r.from) }, t: { day: trFmtDay(r.to), time: trFmtTime(r.to) }, act: "f",
    view: trYmd(new Date(r.to * 1000)) };
  const pop = document.createElement("div");
  pop.className = "trpop";
  const preBtn = (k, t) => `<button data-p="${k}" class="${R.p === k ? "on" : ""}">${esc(I18N.t(t))}</button>`;
  pop.innerHTML = `<div class="trpre"><div class="trh">${esc(I18N.t("بازه‌های آماده"))}</div>${TR_PRE.map(([k, t]) => preBtn(k, t)).join("")}
      <div class="trh">${esc(I18N.t("بر اساس تقویم"))}</div>${TR_CAL_PRE.map(([k, t]) => preBtn(k, t)).join("")}</div>
    <div class="trcus"><div class="trh">${esc(I18N.t("بازه‌ی دلخواه"))} <span class="muted">(${esc(I18N.t(cal === "j" ? "شمسی" : "میلادی"))})</span></div>
      <div class="trrow" data-side="f"><span>${esc(I18N.t("از"))}</span><input class="ltr trd" data-k="day" value="${C.f.day}" placeholder="${cal === "j" ? "1405/07/29" : "2026-10-21"}" spellcheck="false"><input class="ltr trt" data-k="time" value="${C.f.time}" placeholder="00:00" spellcheck="false"></div>
      <div class="trrow" data-side="t"><span>${esc(I18N.t("تا"))}</span><input class="ltr trd" data-k="day" value="${C.t.day}" spellcheck="false"><input class="ltr trt" data-k="time" value="${C.t.time}" placeholder="23:59" spellcheck="false"></div>
      <div class="trcal"></div>
      <div class="trerr" hidden></div>
      <div class="row" style="gap:6px;justify-content:flex-end"><button class="btn sm ghost" data-a="now">${esc(I18N.t("تا اکنون"))}</button><button class="btn sm primary" data-a="ok">${esc(I18N.t("اعمال"))}</button></div>
      <p class="hint">${esc(I18N.t("روی تقویم روز شروع و بعد روز پایان را بزنید، یا تاریخ و ساعت را بنویسید. Enter = اعمال، Esc = بستن."))}</p></div>`;
  document.body.appendChild(pop);
  // جای پنجره زیر دکمه، داخل صفحه
  const bb = $("[data-tr='open']", bar).getBoundingClientRect(), pw = pop.offsetWidth, ph = pop.offsetHeight;
  let x = bb.left, y = bb.bottom + 6;
  if (x + pw > window.innerWidth - 8) x = window.innerWidth - pw - 8;
  if (y + ph > window.innerHeight - 8) y = Math.max(8, bb.top - ph - 6);
  pop.style.left = Math.max(8, x) + "px"; pop.style.top = y + "px";

  const inp = (side, k) => $(`.trrow[data-side='${side}'] [data-k='${k}']`, pop);
  const err = (m) => { const e = $(".trerr", pop); e.hidden = !m; e.textContent = m || ""; };
  const sel = () => [trParse(inp("f", "day").value, inp("f", "time").value), trParse(inp("t", "day").value, inp("t", "time").value)];
  const drawCal = () => {
    const v = C.view, n = trMonthLen(v.y, v.m), first = trDay(v.y, v.m, 1);
    const wd0 = cal === "j" ? (first.getDay() + 1) % 7 : (first.getDay() + 6) % 7;     // ستون اول: شنبه (شمسی) یا دوشنبه
    const heads = cal === "j" ? ["ش", "ی", "د", "س", "چ", "پ", "ج"] : ["Mo", "Tu", "We", "Th", "Fr", "Sa", "Su"];
    const [a, b] = sel(), da = a && trFmtDay(a), db = b && trFmtDay(b), today = trFmtDay(Date.now() / 1000);
    let cells = "";
    for (let i = 0; i < wd0; i++) cells += `<i></i>`;
    for (let d = 1; d <= n; d++) {
      const dt = trDay(v.y, v.m, d), ts = dt.getTime() / 1000, key = trFmtDay(ts), future = dt > now;
      const inR = a && b && ts >= a - 86399 && ts <= b;
      cells += `<button type="button" data-d="${d}" class="${key === da || key === db ? "end" : inR ? "in" : ""} ${key === today ? "today" : ""}" ${future ? "disabled" : ""}>${d}</button>`;
    }
    $(".trcal", pop).innerHTML = `<div class="trcalh"><button type="button" class="iconbtn" data-m="-1">‹</button><b>${esc(cal === "j" ? I18N.t(TR_JMON[v.m - 1]) : TR_GMON[v.m - 1])} ${v.y}</b><button type="button" class="iconbtn" data-m="1">›</button></div>
      <div class="trgrid ${cal === "j" ? "" : "ltrcal"}">${heads.map((h) => `<s>${esc(I18N.t(h))}</s>`).join("")}${cells}</div>`;
    $$("[data-m]", pop).forEach((b2) => (b2.onclick = () => {
      let { y, m } = C.view; m += Number(b2.dataset.m); if (m < 1) { m = 12; y--; } if (m > 12) { m = 1; y++; }
      C.view = { y, m, d: 1 }; drawCal();
    }));
    $$("[data-d]", pop).forEach((b2) => (b2.onclick = () => {
      const key = trFmtDay(trDay(v.y, v.m, Number(b2.dataset.d)).getTime() / 1000);
      if (C.act === "f") { inp("f", "day").value = key; inp("f", "time").value = "00:00"; inp("t", "day").value = key; inp("t", "time").value = "23:59"; C.act = "t"; }
      else {
        const [fa] = sel(), tb = trParse(key, "23:59");
        if (fa && tb && tb < fa) { inp("t", "day").value = inp("f", "day").value; inp("f", "day").value = key; inp("f", "time").value = "00:00"; }
        else inp("t", "day").value = key;
        inp("t", "time").value = "23:59"; C.act = "f";
      }
      err(""); drawCal();
    }));
  };
  drawCal();
  $$(".trpre [data-p]", pop).forEach((b2) => (b2.onclick = () => { pop.remove(); o.set({ p: b2.dataset.p }); }));
  const apply = () => {
    const [a, b] = sel();
    if (!a || !b) return err(I18N.t(cal === "j" ? "تاریخ را به شکل 1405/07/29 و ساعت را به شکل 14:30 بنویسید." : "تاریخ را به شکل 2026-10-21 و ساعت را به شکل 14:30 بنویسید."));
    if (b - a < 60) return err(I18N.t("پایان بازه باید بعد از شروع آن باشد."));
    if (a > Date.now() / 1000) return err(I18N.t("شروع بازه در آینده است."));
    pop.remove(); o.set(trCustom(a, b + (inp("t", "time").value.trim() === "23:59" ? 59 : 0)));
  };
  $("[data-a='ok']", pop).onclick = apply;
  $("[data-a='now']", pop).onclick = () => { const t = Date.now() / 1000; inp("t", "day").value = trFmtDay(t); inp("t", "time").value = trFmtTime(t); drawCal(); };
  $$("input", pop).forEach((i) => {
    i.onfocus = () => { C.act = i.closest(".trrow").dataset.side; };
    i.oninput = () => { err(""); if (i.dataset.k === "day") { const ts = trParse(i.value, "00:00"); if (ts) { C.view = trYmd(new Date(ts * 1000)); drawCal(); } } };
    i.onkeydown = (e) => { if (e.key === "Enter") { e.preventDefault(); apply(); } };
  });
  $(".trpre", pop).addEventListener("keydown", (e) => {          // ↑↓ بین بازه‌های آماده
    if (e.key !== "ArrowDown" && e.key !== "ArrowUp") return;
    const bs = $$(".trpre button", pop), i = bs.indexOf(document.activeElement);
    e.preventDefault(); bs[Math.max(0, Math.min(bs.length - 1, i + (e.key === "ArrowDown" ? 1 : -1)))].focus();
  });
  pop.addEventListener("keydown", (e) => { if (e.key === "Escape") { e.preventDefault(); e.stopPropagation(); pop.remove(); $("[data-tr='open']", bar).focus(); } });
  const f = $(".trpre button.on", pop) || $(".trpre button", pop); if (f) f.focus();
}
