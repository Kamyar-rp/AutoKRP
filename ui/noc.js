"use strict";
/* ================================================================ نمای NOC (1.24)
 * تمام‌صفحه برای مانیتور دیواری: مشکل‌ها بالا (قطع، در دسترس نیست، هشدار SNMP)، همه‌ی هدف‌ها به تفکیک گروه،
 * رخدادهای اخیر و ساعت. هر ۵ ثانیه mon_noc (فعالیت حساب می‌شود؛ نشست مانیتور دیواری منقضی نمی‌شود).
 * باز کردن: دکمه‌ی «نمای NOC» یا آدرس ‎#noc‎. بستن: Esc یا ✕. F = تمام‌صفحه. */
const NOC = { timer: null, data: null };
const NOC_RANK = { down: 0, unreachable: 2, slow: 3, unknown: 5, up: 6, paused: 7 };

function nocOpen() {
  if ($("#noc")) return;
  const el = document.createElement("div");
  el.id = "noc";
  el.innerHTML = `<div class="noc-top"><div class="noc-title"><b>AutoKRP</b><span>NOC</span></div><div class="noc-sum" id="nocSum"></div>
      <div class="noc-clock ltr" id="nocClock"></div>
      <button class="iconbtn" id="nocFs" title="تمام‌صفحه (F)">⛶</button><button class="iconbtn" id="nocX" title="بستن (Esc)"><svg><use href="#i-x"/></svg></button></div>
    <div class="noc-body"><section class="noc-prob" id="nocProb"></section><section class="noc-groups" id="nocGroups"></section><aside class="noc-feed" id="nocFeed"></aside></div>`;
  document.body.appendChild(el);
  document.body.classList.add("noc-on");
  $("#nocX").onclick = nocClose;
  $("#nocFs").onclick = nocFull;
  try { if (location.hash !== "#noc") history.replaceState(null, "", "#noc"); } catch (_) { /* */ }
  nocTick();
  NOC.timer = setInterval(nocTick, 5000);
  nocFull();
}
function nocClose() {
  clearInterval(NOC.timer); NOC.timer = null;
  const el = $("#noc"); if (el) el.remove();
  document.body.classList.remove("noc-on");
  try { if (document.fullscreenElement) document.exitFullscreen(); } catch (_) { /* */ }
  try { if (location.hash === "#noc") history.replaceState(null, "", location.pathname + location.search); } catch (_) { /* */ }
}
function nocFull() {
  try {
    if (document.fullscreenElement) document.exitFullscreen();
    else if (document.documentElement.requestFullscreen) document.documentElement.requestFullscreen().catch(() => {});
  } catch (_) { /* بدون اجازه‌ی کاربر یا در پنجره‌ی دسکتاپ */ }
}
async function nocTick() {
  const c = $("#nocClock");
  if (c) { const t = Date.now() / 1000; c.textContent = `${trFmtDay(t)}  ${new Date().toLocaleTimeString("en-GB")}`; }
  if (!$("#noc")) return;
  const r = await api("mon_noc");
  if (!$("#noc")) return;
  if (!r.ok) { $("#nocGroups").innerHTML = `<div class="empty">${esc(r.error || "")}</div>`; return; }
  NOC.data = r; nocRender();
}
function nocSt(t) { return t.maint && t.status !== "up" ? "maint" : t.status === "up" && t.level === "crit" ? "crit" : t.status === "up" && t.level === "warn" ? "warn" : t.status; }
function nocRender() {
  const r = NOC.data, ts = r.targets, now = Date.now() / 1000;
  const cnt = (f) => ts.filter(f).length;
  const nDown = cnt((t) => t.status === "down" && !t.maint);
  $("#nocSum").innerHTML = `<span class="ok"><b>${num(cnt((t) => t.status === "up" || t.status === "slow"))}</b> وصل</span>
    <span class="${nDown ? "err blink" : "err"}"><b>${num(nDown)}</b> قطع</span>
    <span class="unr"><b>${num(cnt((t) => t.status === "unreachable"))}</b> در دسترس نیست</span>
    <span class="warn"><b>${num(cnt((t) => t.level === "crit" || t.level === "warn"))}</b> هشدار</span>
    <span class="mnt"><b>${num(cnt((t) => t.maint))}</b> نگهداری</span><span><b>${num(ts.length)}</b> کل</span>`;
  const prob = ts.filter((t) => ["down", "unreachable"].includes(t.status) || ["crit", "warn"].includes(t.level) || t.status === "slow")
    .sort((a, b) => (a.maint ? 1 : 0) - (b.maint ? 1 : 0) || (NOC_RANK[a.status] ?? 9) - (NOC_RANK[b.status] ?? 9) || (a.level === "crit" ? -1 : 0) - (b.level === "crit" ? -1 : 0) || (a.since || 0) - (b.since || 0));
  $("#nocProb").innerHTML = prob.length ? prob.map((t) => {
    const s = nocSt(t);
    const why = t.status === "unreachable" ? `به‌خاطر قطع «${t.cause}»` : t.status === "down" ? t.err : t.alarms.length ? t.alarms.join(" · ") : t.status === "slow" ? `${num(t.rtt)} ms` : "";
    return `<div class="noc-p s-${s}">${monIcon(t.icon)}<div><b class="bidi">${esc(t.name)}</b><span class="bidi">${esc(why || "")}</span></div>
      <div class="noc-dur">${t.since && (t.status === "down" || t.status === "unreachable") ? monDur(now - t.since) : ""}${t.maint ? `<small>نگهداری</small>` : ""}</div></div>`;
  }).join("") : `<div class="noc-allok">همه‌ی هدف‌ها سالم‌اند ✓</div>`;
  const groups = {};
  ts.forEach((t) => (groups[t.grp || "بدون گروه"] = groups[t.grp || "بدون گروه"] || []).push(t));
  const order = Object.keys(groups).sort((a, b) => {
    const bad = (g) => groups[g].some((t) => t.status === "down" && !t.maint) ? 0 : groups[g].some((t) => t.status === "unreachable" || t.level === "crit") ? 1 : 2;
    return bad(a) - bad(b) || a.localeCompare(b, "fa");
  });
  $("#nocGroups").innerHTML = order.map((g) => {
    const L = groups[g].sort((a, b) => (NOC_RANK[a.status] ?? 9) - (NOC_RANK[b.status] ?? 9) || a.name.localeCompare(b.name, "fa"));
    const okN = L.filter((t) => t.status === "up" || t.status === "slow").length;
    return `<div class="noc-g"><h3><span class="bidi">${esc(g)}</span><small>${num(okN)}/${num(L.length)}</small></h3>
      <div class="noc-tiles">${L.map((t) => `<div class="noc-t s-${nocSt(t)}" title="${esc(t.name + (t.err ? " — " + t.err : ""))}"><span class="bidi">${esc(t.name)}</span></div>`).join("")}</div></div>`;
  }).join("") || `<div class="empty">هدفی برای نمایش نیست.</div>`;
  $("#nocFeed").innerHTML = `<h3>رخدادهای اخیر</h3>${r.alerts.length ? r.alerts.map((a) => `<div class="noc-ev e-${a.state}"><span class="ltr">${fmtTime(a.ts)}</span><span class="bidi">${esc(a.msg)}</span></div>`).join("")
    : `<div class="muted">رخدادی نیست.</div>`}`;
}
window.addEventListener("hashchange", () => { if (location.hash === "#noc" && S.state && !$("#noc")) nocOpen(); });
// ‎#noc‎ در آدرس: بعد از ورود خودکار باز می‌شود؛ با قفل شدن برنامه بسته می‌شود (و بعد از باز شدن قفل دوباره باز)
setInterval(() => {
  const locked = !S.state || (S.state.security && S.state.security.locked);
  if ($("#noc") && locked) { const h = location.hash; nocClose(); try { history.replaceState(null, "", h); } catch (_) { /* */ } return; }
  if (!locked && location.hash === "#noc" && !$("#noc") && !modalClose) nocOpen();
}, 2000);
