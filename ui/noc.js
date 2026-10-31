"use strict";
/* ================================================================ نمای NOC (1.24؛ داشبوردها 1.35)
 * تمام‌صفحه برای مانیتور دیواری. بدون داشبورد: مشکل‌ها، همه‌ی هدف‌ها به تفکیک گروه، رخدادهای اخیر و ساعت.
 * داشبورد (1.35): نام، دامنه (همه / گروه‌ها / هدف‌ها)، چیدمان کاشی/جدول/ترکیبی، کاشی بزرگ برای دستگاه‌های مهم، نمودار
 * ترافیک uplinkها، زمان چرخش. آدرس ثابت: ‎#noc‎ (همه)، ‎#noc/<شناسه>‎، ‎#noc/rotate‎ (چرخش بین داشبوردهایی که زمان چرخش دارند).
 * هر ۵ ثانیه mon_noc (فعالیت حساب می‌شود؛ نشست مانیتور دیواری منقضی نمی‌شود)، نمودارها هر ۶۰ ثانیه.
 * بستن: Esc یا ✕. F = تمام‌صفحه. ویرایش داشبورد (ادمین): ✎ (NOC بسته و پنجره‌ی ویرایش باز می‌شود). */
const NOC = { timer: null, data: null, dash: null, rotate: false, list: [], rotAt: 0, chartAt: 0 };
const NOC_RANK = { down: 0, unreachable: 2, slow: 3, unknown: 5, up: 6, paused: 7 };

function nocHash() { return NOC.rotate ? "#noc/rotate" : NOC.dash ? `#noc/${NOC.dash}` : "#noc"; }
function nocParse(h) {
  const m = /^#noc(?:\/(rotate|\d+))?$/.exec(h || "");
  if (!m) return null;
  return m[1] === "rotate" ? { rotate: true, dash: null } : { rotate: false, dash: m[1] ? Number(m[1]) : null };
}
async function nocOpen(dash, rotate) {
  if ($("#noc") || NOC.opening) return;
  NOC.opening = true;
  try { await nocOpen2(dash, rotate); } finally { NOC.opening = false; }
}
async function nocOpen2(dash, rotate) {
  NOC.dash = dash || null; NOC.rotate = !!rotate; NOC.chartAt = 0;
  const L = await api("mon_noc_list");
  NOC.list = L.ok ? L.dashboards : [];
  NOC.canEdit = L.ok && L.can_edit;
  if (NOC.rotate) {
    const rot = NOC.list.filter((d) => d.data.rotate_sec > 0);
    if (!rot.length) { NOC.rotate = false; toast("هیچ داشبوردی زمان چرخش ندارد.", "warn"); }
    else { NOC.dash = rot[0].id; NOC.rotAt = Date.now(); }
  }
  if (NOC.dash && !NOC.list.find((d) => d.id === NOC.dash)) NOC.dash = null;
  if ($("#noc")) return;
  const el = document.createElement("div");
  el.id = "noc";
  el.innerHTML = `<div class="noc-top"><div class="noc-title"><b>AutoKRP</b><span>NOC</span></div>
      <select id="nocDash" title="داشبورد"><option value="">همه‌ی هدف‌ها</option>${NOC.list.map((d) => `<option value="${d.id}">${esc(d.name)}</option>`).join("")}
        ${NOC.list.some((d) => d.data.rotate_sec > 0) ? `<option value="rotate">↻ چرخش خودکار</option>` : ""}</select>
      <div class="noc-sum" id="nocSum"></div><div class="noc-clock ltr" id="nocClock"></div>
      ${NOC.canEdit ? `<button class="iconbtn" id="nocEdit" title="ویرایش داشبوردها">✎</button>` : ""}
      <button class="iconbtn" id="nocLink" title="کپی آدرس ثابت همین نما (برای مانیتور دیواری)">🔗</button>
      <button class="iconbtn" id="nocFs" title="تمام‌صفحه (F)">⛶</button><button class="iconbtn" id="nocX" title="بستن (Esc)"><svg><use href="#i-x"/></svg></button></div>
    <div class="noc-rot" id="nocRot" hidden><i></i></div>
    <div class="noc-body" id="nocBody"></div>`;
  document.body.appendChild(el);
  document.body.classList.add("noc-on");
  $("#nocDash").value = NOC.rotate ? "rotate" : NOC.dash ? String(NOC.dash) : "";
  $("#nocDash").onchange = (e) => {
    const v = e.target.value;
    NOC.rotate = v === "rotate"; NOC.dash = NOC.rotate ? (NOC.list.find((d) => d.data.rotate_sec > 0) || {}).id : v ? Number(v) : null;
    NOC.rotAt = Date.now(); NOC.chartAt = 0; NOC.data = null;
    try { history.replaceState(null, "", nocHash()); } catch (_) { /* */ }
    nocTick();
  };
  $("#nocX").onclick = nocClose;
  $("#nocFs").onclick = nocFull;
  $("#nocLink").onclick = async () => {
    const url = location.origin + location.pathname + nocHash();
    try { await navigator.clipboard.writeText(url); toast("آدرس کپی شد: " + url, "ok"); } catch (_) { toast(url, "info"); }
  };
  if ($("#nocEdit")) $("#nocEdit").onclick = () => { const d = NOC.dash; nocClose(); nocDashboards(d); };
  try { if (location.hash !== nocHash()) history.replaceState(null, "", nocHash()); } catch (_) { /* */ }
  NOC.timer = setInterval(nocTick, 5000);
  NOC.rtimer = setInterval(() => { if (nocRotate()) nocTick(); }, 1000);      // نوار پیشرفت و تعویض داشبورد در چرخش
  nocRotate();
  nocTick();
}
function nocClose() {
  clearInterval(NOC.timer); NOC.timer = null; clearInterval(NOC.rtimer); NOC.rtimer = null;
  const el = $("#noc"); if (el) el.remove();
  document.body.classList.remove("noc-on");
  if (document.fullscreenElement) document.exitFullscreen().catch(() => {});
  try { if (/^#noc/.test(location.hash)) history.replaceState(null, "", location.pathname + location.search); } catch (_) { /* */ }
}
function nocFull() {
  if (document.fullscreenElement) document.exitFullscreen().catch(() => {});
  else ($("#noc") || document.documentElement).requestFullscreen().catch(() => {});
}
function nocRotate() {
  const rot = NOC.list.filter((d) => d.data.rotate_sec > 0);
  if (!$("#nocRot")) return false;
  if (!NOC.rotate || !rot.length) { $("#nocRot").hidden = true; return false; }
  const cur = rot.find((d) => d.id === NOC.dash) || rot[0], sec = cur.data.rotate_sec, el = $("#nocRot");
  el.hidden = false;
  const p = Math.min(1, (Date.now() - NOC.rotAt) / (sec * 1000));
  $("i", el).style.width = `${(p * 100).toFixed(1)}%`;
  if (p >= 1) {
    const nx = rot[(rot.indexOf(cur) + 1) % rot.length];
    NOC.dash = nx.id; NOC.rotAt = Date.now(); NOC.chartAt = 0; NOC.data = null;
    return true;
  }
  return false;
}
async function nocTick() {
  const c = $("#nocClock");
  if (c) { const t = Date.now() / 1000; c.textContent = `${trFmtDay(t)}  ${new Date().toLocaleTimeString("en-GB")}`; }
  if (!$("#noc")) return;
  const r = await api("mon_noc", NOC.dash);
  if (!$("#noc")) return;
  if (!r.ok) { $("#nocBody").innerHTML = `<div class="empty">${esc(r.error || "")}</div>`; return; }
  if ((NOC.dash || null) !== ((r.dash && r.dash.id) || null)) return;      // پاسخ داشبورد قبلی (چرخش وسط درخواست)
  NOC.data = r;
  if (r.rows) r.rows.forEach((x) => (MV.rows[x.id] = x));
  nocRender();
}
function nocSt(t) { return t.maint && t.status !== "up" ? "maint" : t.status === "up" && t.level === "crit" ? "crit" : t.status === "up" && t.level === "warn" ? "warn" : t.status; }
function nocT(t) {         // هدف NOC ← شکل هدف رابط برای mvCell و mvCardFields
  const r = MV.rows[t.id] || {};
  return { ...t, enabled: t.status !== "paused", tpl_eff: { card: t.tpl || [] }, can_edit: false, last: r.last, eff_interval: r.iv, policy: r.pol };
}
function nocSummary(ts) {
  const cnt = (f) => ts.filter(f).length;
  const nDown = cnt((t) => t.status === "down" && !t.maint);
  $("#nocSum").innerHTML = `<span class="ok"><b>${num(cnt((t) => t.status === "up" || t.status === "slow"))}</b> وصل</span>
    <span class="${nDown ? "err blink" : "err"}"><b>${num(nDown)}</b> قطع</span>
    <span class="unr"><b>${num(cnt((t) => t.status === "unreachable"))}</b> در دسترس نیست</span>
    <span class="warn"><b>${num(cnt((t) => t.level === "crit" || t.level === "warn"))}</b> هشدار</span>
    <span class="mnt"><b>${num(cnt((t) => t.maint))}</b> نگهداری</span><span><b>${num(ts.length)}</b> کل</span>`;
}
function nocProblems(ts) {
  const now = Date.now() / 1000;
  const prob = ts.filter((t) => ["down", "unreachable"].includes(t.status) || ["crit", "warn"].includes(t.level) || t.status === "slow")
    .sort((a, b) => (a.maint ? 1 : 0) - (b.maint ? 1 : 0) || (NOC_RANK[a.status] ?? 9) - (NOC_RANK[b.status] ?? 9) || (a.level === "crit" ? -1 : 0) - (b.level === "crit" ? -1 : 0) || (a.since || 0) - (b.since || 0));
  return prob.length ? prob.map((t) => {
    const s = nocSt(t);
    const why = t.status === "unreachable" ? `به‌خاطر قطع «${t.cause}»` : t.status === "down" ? t.err : t.alarms.length ? t.alarms.join(" · ") : t.status === "slow" ? `${num(t.rtt)} ms` : "";
    return `<div class="noc-p s-${s}">${monIcon(t.icon)}<div><b class="bidi">${esc(t.name)}</b><span class="bidi">${esc(why || "")}</span></div>
      <div class="noc-dur">${t.since && (t.status === "down" || t.status === "unreachable") ? monDur(now - t.since) : ""}${t.maint ? `<small>نگهداری</small>` : ""}</div></div>`;
  }).join("") : `<div class="noc-allok">همه‌ی هدف‌ها سالم‌اند ✓</div>`;
}
function nocFeed(r) {
  return `<h3>رخدادهای اخیر</h3>${r.alerts.length ? r.alerts.map((a) => `<div class="noc-ev e-${a.state}"><span class="ltr">${fmtTime(a.ts)}</span><span class="bidi">${esc(a.msg)}</span></div>`).join("")
    : `<div class="muted">رخدادی نیست.</div>`}`;
}
function nocGroups(ts) {
  const groups = {};
  ts.forEach((t) => (groups[t.grp || "بدون گروه"] = groups[t.grp || "بدون گروه"] || []).push(t));
  const order = Object.keys(groups).sort((a, b) => {
    const bad = (g) => groups[g].some((t) => t.status === "down" && !t.maint) ? 0 : groups[g].some((t) => t.status === "unreachable" || t.level === "crit") ? 1 : 2;
    return bad(a) - bad(b) || a.localeCompare(b, "fa");
  });
  return order.map((g) => {
    const L = groups[g].sort((a, b) => (NOC_RANK[a.status] ?? 9) - (NOC_RANK[b.status] ?? 9) || a.name.localeCompare(b.name, "fa"));
    const okN = L.filter((t) => t.status === "up" || t.status === "slow").length;
    return `<div class="noc-g"><h3><span class="bidi">${esc(g)}</span><small>${num(okN)}/${num(L.length)}</small></h3>
      <div class="noc-tiles">${L.map((t) => `<div class="noc-t s-${nocSt(t)}" title="${esc(t.name + (t.err ? " — " + t.err : ""))}"><span class="bidi">${esc(t.name)}</span></div>`).join("")}</div></div>`;
  }).join("") || `<div class="empty">هدفی برای نمایش نیست.</div>`;
}
function nocTiles(ts, big) {
  const L = ts.slice().sort((a, b) => (big.includes(b.id) ? 1 : 0) - (big.includes(a.id) ? 1 : 0) || (NOC_RANK[a.status] ?? 9) - (NOC_RANK[b.status] ?? 9) || a.name.localeCompare(b.name, "fa"));
  return `<div class="noc-bt">${L.map((t) => {
    const T = nocT(t), isBig = big.includes(t.id), now = Date.now() / 1000;
    return `<div class="noc-tile s-${nocSt(t)}${isBig ? " big" : ""}"><div class="noc-th">${monIcon(t.icon)}<b class="bidi">${esc(t.name)}</b></div>
      <div class="noc-tm">${t.status === "down" || t.status === "unreachable" ? `<span>${esc(t.status === "down" ? (t.err || "قطع") : `به‌خاطر قطع «${t.cause}»`)}</span>${t.since ? `<b>${monDur(now - t.since)}</b>` : ""}` : mvCardFields(T)}</div>
      ${isBig && t.kind === "snmp" ? `<div class="noc-tp">${mvTraffic(T, true)}</div>` : ""}</div>`;
  }).join("")}</div>`;
}
function nocTable(ts, cols) {
  const L = ts.slice().sort((a, b) => (NOC_RANK[a.status] ?? 9) - (NOC_RANK[b.status] ?? 9) || a.name.localeCompare(b.name, "fa"));
  return `<table class="grid mv-tbl noc-tbl"><thead><tr>${cols.map((k) => `<th>${esc(MV_COLS[k] || k)}</th>`).join("")}</tr></thead><tbody>
    ${L.map((t) => { const T = nocT(t); return `<tr class="st-${t.level === "crit" || t.level === "warn" ? "alarm" : t.status}">${cols.map((k) => `<td class="c-${k}">${mvCell(T, k)}</td>`).join("")}</tr>`; }).join("")}</tbody></table>`;
}
function nocRender() {
  const r = NOC.data, ts = r.targets, D = r.dash;
  nocSummary(ts);
  const body = $("#nocBody");
  if (!D) {        // بدون داشبورد: همان نمای قبلی
    body.className = "noc-body";
    body.innerHTML = `<section class="noc-prob">${nocProblems(ts)}</section><section class="noc-groups">${nocGroups(ts)}</section><aside class="noc-feed">${nocFeed(r)}</aside>`;
    return;
  }
  const main = D.layout === "table" ? nocTable(ts, D.cols) : nocTiles(ts, D.big);
  const charts = D.charts.length ? `<section class="noc-charts">${D.charts.map((c, i) => {
    const t = ts.find((x) => x.id === c.tid);
    return `<div class="chart-card"><div class="chart-head"><h3 class="bidi">${esc(c.title || `${t ? t.name : "#" + c.tid} — ${c.port}`)}</h3></div><div class="chart" id="nocC${i}"></div></div>`;
  }).join("")}</section>` : "";
  const keep = $("#nocCharts") && NOC.chartAt && Date.now() - NOC.chartAt < 60000 && body.dataset.dash === String(D.id);
  const old = keep ? $("#nocCharts").innerHTML : null;
  body.className = `noc-body noc-d noc-${D.layout}${D.problems ? " w-prob" : ""}${D.feed ? " w-feed" : ""}${charts ? " w-charts" : ""}`;
  body.dataset.dash = String(D.id);
  body.innerHTML = `${D.problems ? `<section class="noc-prob">${nocProblems(ts)}</section>` : ""}
    <section class="noc-main">${ts.length ? main : `<div class="empty">هدفی در این داشبورد نیست.</div>`}</section>
    ${charts || D.feed ? `<aside class="noc-side">${charts ? `<div id="nocCharts">${old !== null ? old : charts}</div>` : ""}${D.feed ? `<div class="noc-feed">${nocFeed(r)}</div>` : ""}</aside>` : ""}`;
  if (charts && !keep) nocCharts(D);
}
async function nocCharts(D) {
  NOC.chartAt = Date.now();
  for (let i = 0; i < D.charts.length; i++) {
    const c = D.charts[i];
    const r = await api("mon_snmp_series", c.tid, D.range, [`if:${c.port}:in`, `if:${c.port}:out`]);
    const el = $(`#nocC${i}`);
    if (!el) return;
    if (!r.ok) { el.innerHTML = `<div class="empty">${esc(r.error)}</div>`; continue; }
    snDraw(el, r, [[`if:${c.port}:in`, "ورودی", "info"], [`if:${c.port}:out`, "خروجی", "ok"]], { bps: true, height: 150 });
  }
}

/* ---------------------------------------------------------------- مدیریت داشبوردها (ادمین؛ یک پنجره در هر لحظه) */
async function nocDashboards(reopen) {
  const r = await api("mon_noc_list");
  if (!r.ok) return toast(r.error, "error");
  if (!MON.targets.length) await loadMon();
  const LAY = { tiles: "کاشی", table: "جدول", mixed: "ترکیبی" };
  const res = await openModal({ title: "داشبوردهای NOC", wide: true,
    body: `<p class="hint">هر داشبورد آدرس ثابت خودش را دارد (‎#noc/شناسه‎) و برای مانیتور دیواری بعد از ورود مستقیم باز می‌شود. داشبوردهایی که «زمان چرخش» دارند در ‎#noc/rotate‎ پشت‌سرهم نمایش داده می‌شوند.</p>
      ${r.dashboards.length ? `<div class="table-wrap inner"><table class="grid"><thead><tr><th>نام</th><th>چیدمان</th><th>هدف‌ها</th><th>چرخش</th><th class="nosort"></th></tr></thead><tbody>
      ${r.dashboards.map((d) => `<tr><td><b>${esc(d.name)}</b> <span class="muted ltr">#noc/${d.id}</span></td><td>${esc(LAY[d.data.layout])}</td>
        <td>${esc(d.data.scope.all ? "همه" : [...d.data.scope.groups.map((g) => `گروه «${g}»`), d.data.scope.ids.length ? `${num(d.data.scope.ids.length)} هدف` : ""].filter(Boolean).join("، "))}</td>
        <td>${d.data.rotate_sec ? `${num(d.data.rotate_sec)} ثانیه` : "—"}</td>
        <td class="row" style="gap:4px"><button class="btn sm" data-dopen="${d.id}">باز کردن</button>${r.can_edit ? `<button class="btn sm" data-de="${d.id}">ویرایش</button><button class="btn sm danger-ghost" data-dd="${d.id}">حذف</button>` : ""}</td></tr>`).join("")}</tbody></table></div>`
      : `<div class="empty">هنوز داشبوردی ساخته نشده است.</div>`}`,
    foot: `<button class="btn ghost" data-r="0">بستن</button>${r.can_edit ? `<button class="btn primary" id="ndAdd">+ داشبورد تازه</button>` : ""}`,
    onOpen: (m, close) => {
      $("[data-r='0']", m).onclick = () => close(null);
      if ($("#ndAdd", m)) $("#ndAdd", m).onclick = () => close({ edit: { name: "", data: {} } });
      const find = (id) => r.dashboards.find((d) => d.id === Number(id));
      $$("[data-dopen]", m).forEach((b) => (b.onclick = () => close({ open: Number(b.dataset.dopen) })));
      $$("[data-de]", m).forEach((b) => (b.onclick = () => close({ edit: find(b.dataset.de) })));
      $$("[data-dd]", m).forEach((b) => (b.onclick = () => close({ del: find(b.dataset.dd) })));
    } });
  if (!res) { if (reopen !== undefined) nocOpen(reopen || null); return; }
  if (res.open) return nocOpen(res.open);
  if (res.del) {
    if (await confirm2({ title: "حذف داشبورد", body: `<p>داشبورد «${esc(res.del.name)}» حذف شود؟</p>`, confirm: "حذف", danger: true })) {
      const x = await api("mon_noc_delete", res.del.id); if (!x.ok) toast(x.error, "error"); else toast("حذف شد", "ok");
    }
    return nocDashboards(reopen);
  }
  const id = await nocDashEdit(res.edit);
  if (id) return nocOpen(id);
  nocDashboards(reopen);
}
async function nocDashEdit(x) {
  const d = Object.assign({ scope: { all: true, groups: [], ids: [] }, layout: "tiles", big: [], charts: [], cols: [...MV_DEF_COLS], rotate_sec: 0,
    feed: true, problems: true, range: "6h" }, x.data || {});
  const ts = MON.targets.slice().sort((a, b) => (a.grp || "").localeCompare(b.grp || "", "fa") || a.name.localeCompare(b.name, "fa"));
  const groups = [...new Set(ts.map((t) => t.grp).filter(Boolean))];
  const snmp = ts.filter((t) => t.kind === "snmp");
  const LAY = [["tiles", "کاشی (وضعیت و مقدارهای قالب هر دستگاه)"], ["table", "جدول (ستون‌های انتخابی)"], ["mixed", "ترکیبی (کاشی + نمودارها کنار هم)"]];
  return openModal({ title: x.id ? `ویرایش داشبورد «${x.name}»` : "داشبورد NOC تازه", wide: true,
    body: `<div class="form-grid">
        <label class="field"><span>نام</span><input id="ndName" value="${esc(x.name || "")}" placeholder="مثلاً هسته‌ی شبکه"></label>
        <label class="field"><span>چیدمان</span><select id="ndLay">${LAY.map(([k, n]) => `<option value="${k}" ${d.layout === k ? "selected" : ""}>${n}</option>`).join("")}</select></label>
        <label class="field"><span>زمان نمایش در چرخش خودکار (ثانیه)</span><input id="ndRot" type="number" min="0" max="3600" value="${esc(d.rotate_sec)}"><small class="hint">۰ = بیرون از چرخش؛ وگرنه ۱۰ تا ۳۶۰۰</small></label>
        <label class="field"><span>بازه‌ی نمودارها</span><select id="ndRange">${[["1h", "۱ ساعت"], ["6h", "۶ ساعت"], ["24h", "۲۴ ساعت"]].map(([k, n]) => `<option value="${k}" ${d.range === k ? "selected" : ""}>${n}</option>`).join("")}</select></label></div>
      <div class="row" style="gap:14px;flex-wrap:wrap;margin:6px 0"><label class="chk"><input type="checkbox" id="ndProb" ${d.problems ? "checked" : ""}>ستون مشکل‌ها</label>
        <label class="chk"><input type="checkbox" id="ndFeed" ${d.feed ? "checked" : ""}>رخدادهای اخیر</label></div>
      <details class="sn-det" open><summary>هدف‌ها</summary>
        <label class="chk"><input type="checkbox" id="ndAll" ${d.scope.all ? "checked" : ""}>همه‌ی هدف‌ها</label>
        <div id="ndScope" ${d.scope.all ? "hidden" : ""}>
          ${groups.length ? `<div class="field"><span>گروه‌ها (همه‌ی هدف‌های گروه، از جمله هدف‌های بعدی)</span><div class="row" style="gap:12px;flex-wrap:wrap">${groups.map((g) => `<label class="chk"><input type="checkbox" data-ndg="${esc(g)}" ${d.scope.groups.includes(g) ? "checked" : ""}>${esc(g)}</label>`).join("")}</div></div>` : ""}
          <div class="field"><span>هدف‌های تکی</span><input id="ndQ" type="search" placeholder="جستجو"><div class="table-wrap inner" style="max-height:220px"><table class="grid"><tbody>
            ${ts.map((t) => `<tr data-ndn="${esc((t.name + " " + (t.grp || "")).toLowerCase())}"><td><input type="checkbox" data-ndi="${t.id}" ${d.scope.ids.includes(t.id) ? "checked" : ""}></td><td class="bidi">${esc(t.name)}</td><td class="muted">${esc(t.grp || "")}</td></tr>`).join("")}</tbody></table></div></div></div></details>
      <details class="sn-det"><summary>کاشی بزرگ (دستگاه‌های مهم، با ترافیک پورت‌های نمایشی)</summary><div class="row" style="gap:12px;flex-wrap:wrap">
        ${ts.map((t) => `<label class="chk"><input type="checkbox" data-ndb="${t.id}" ${d.big.includes(t.id) ? "checked" : ""}>${esc(t.name)}</label>`).join("")}</div></details>
      <details class="sn-det"><summary>ستون‌های چیدمان جدول</summary><div class="row" style="gap:12px;flex-wrap:wrap">
        ${Object.entries(MV_COLS).map(([k, n]) => `<label class="chk"><input type="checkbox" data-ndc="${k}" ${d.cols.includes(k) ? "checked" : ""}>${esc(n)}</label>`).join("")}</div></details>
      <details class="sn-det" ${d.charts.length ? "open" : ""}><summary>نمودار ترافیک uplinkها (حداکثر ۱۲)</summary>
        <div id="ndCharts"></div>
        ${snmp.length ? `<div class="row" style="gap:6px;margin-top:6px"><select id="ndCT">${snmp.map((t) => `<option value="${t.id}">${esc(t.name)}</option>`).join("")}</select>
          <input id="ndCP" class="ltr" placeholder="نام پورت، مثلاً Te1/1/1" list="ndCPL"><datalist id="ndCPL"></datalist><input id="ndCN" placeholder="عنوان (اختیاری)"><button class="btn sm" id="ndCAdd">+ نمودار</button></div>`
          : `<div class="muted">هدف SNMP ندارید.</div>`}</details>`,
    foot: `<button class="btn ghost" data-r="0">انصراف</button><button class="btn primary" data-r="1">ذخیره و باز کردن</button>`,
    onOpen: (m, close) => {
      const charts = d.charts.map((c) => ({ ...c }));
      const drawCharts = () => {
        $("#ndCharts", m).innerHTML = charts.length ? charts.map((c, i) => `<div class="mv-col"><span class="bidi">${esc((MON.targets.find((t) => t.id === c.tid) || {}).name || "#" + c.tid)} — <span class="ltr">${esc(c.port)}</span>${c.title ? ` (${esc(c.title)})` : ""}</span>
          <button class="btn sm ghost" data-ndcx="${i}">✕</button></div>`).join("") : `<div class="muted">نموداری اضافه نشده است.</div>`;
        $$("[data-ndcx]", m).forEach((b) => (b.onclick = () => { charts.splice(Number(b.dataset.ndcx), 1); drawCharts(); }));
      };
      drawCharts();
      const fillPorts = async () => {
        if (!$("#ndCT", m)) return;
        const r = await api("mon_snmp_live", Number($("#ndCT", m).value), 0, true);
        $("#ndCPL", m).innerHTML = r.ok && !r.none ? (r.ifs || []).filter((x) => x.type !== 24).map((x) => `<option value="${esc(x.name)}">${esc(x.alias || "")}</option>`).join("") : "";
      };
      if ($("#ndCT", m)) { $("#ndCT", m).onchange = fillPorts; fillPorts(); }
      if ($("#ndCAdd", m)) $("#ndCAdd", m).onclick = () => {
        const port = $("#ndCP", m).value.trim(); if (!port) return toast("نام پورت را بنویسید.", "warn");
        if (charts.length >= 12) return toast("حداکثر ۱۲ نمودار", "warn");
        charts.push({ tid: Number($("#ndCT", m).value), port, title: $("#ndCN", m).value.trim() }); $("#ndCP", m).value = ""; $("#ndCN", m).value = ""; drawCharts();
      };
      $("#ndAll", m).onchange = (e) => ($("#ndScope", m).hidden = e.target.checked);
      $("#ndQ", m).oninput = (e) => { const q = e.target.value.toLowerCase(); $$("[data-ndn]", m).forEach((tr) => (tr.hidden = q && !tr.dataset.ndn.includes(q))); };
      $("[data-r='0']", m).onclick = () => close(null);
      $("[data-r='1']", m).onclick = async () => {
        const data = { layout: $("#ndLay", m).value, rotate_sec: Number($("#ndRot", m).value || 0), range: $("#ndRange", m).value,
          problems: $("#ndProb", m).checked, feed: $("#ndFeed", m).checked,
          scope: { all: $("#ndAll", m).checked, groups: $$("[data-ndg]:checked", m).map((c) => c.dataset.ndg), ids: $$("[data-ndi]:checked", m).map((c) => Number(c.dataset.ndi)) },
          big: $$("[data-ndb]:checked", m).map((c) => Number(c.dataset.ndb)), cols: $$("[data-ndc]:checked", m).map((c) => c.dataset.ndc), charts };
        const r = await api("mon_noc_save", { id: x.id, name: $("#ndName", m).value.trim(), data });
        if (!r.ok) return toast(r.error, "error");
        toast("ذخیره شد", "ok"); close(r.id);
      };
    } });
}

window.addEventListener("hashchange", () => {
  const p = nocParse(location.hash);
  if (p && S.state && !$("#noc")) nocOpen(p.dash, p.rotate);
});
// ‎#noc…‎ در آدرس: بعد از ورود خودکار باز می‌شود؛ با قفل شدن برنامه بسته می‌شود (و بعد از باز شدن قفل دوباره باز)
setInterval(() => {
  const locked = !S.state || (S.state.security && S.state.security.locked);
  if ($("#noc") && locked) { const h = location.hash; nocClose(); try { history.replaceState(null, "", h); } catch (_) { /* */ } return; }
  const p = nocParse(location.hash);
  if (!locked && p && !$("#noc") && !modalClose) nocOpen(p.dash, p.rotate);
}, 2000);
