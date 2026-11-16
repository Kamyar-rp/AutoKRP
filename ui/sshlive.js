"use strict";
/* ================================================================ SSH زنده: ترمینال و انتقال فایل
 * از app.js استفاده می‌کند ($، api، openModal، SSH، toast، ...). xterm.js فقط با اولین باز شدن ترمینال بارگذاری می‌شود. */

/* ---------- بارگذاری تنبل xterm.js ---------- */
let _xtermReady = null;
function loadXterm() {
  if (_xtermReady) return _xtermReady;
  // حالت وب: تگ‌های <style> خود xterm فقط با nonce همین صفحه مجازند (CSP)
  const nm = document.querySelector('meta[name="akrp-style-nonce"]');
  if (nm && !document.__akrpNonce) {
    const nonce = nm.content, orig = document.createElement.bind(document);
    document.createElement = function (tag, opts) { const el = orig(tag, opts); if (String(tag).toLowerCase() === "style") el.nonce = nonce; return el; };
    document.__akrpNonce = true;
  }
  const add = (tag, attrs) => new Promise((res, rej) => { const e = document.createElement(tag); Object.assign(e, attrs); e.onload = res; e.onerror = () => rej(new Error("load " + (attrs.src || attrs.href))); document.head.appendChild(e); });
  _xtermReady = Promise.all([add("link", { rel: "stylesheet", href: "vendor/xterm.css" }), add("script", { src: "vendor/xterm.js" })])
    .then(() => Promise.all([add("script", { src: "vendor/addon-fit.js" }), add("script", { src: "vendor/addon-search.js" }).catch(() => null)]));
  _xtermReady.catch(() => { _xtermReady = null; });
  return _xtermReady;
}

// فایلی که بیرون از ناحیه‌ی رها کردن انداخته شود نباید پنجره را به آن فایل ببرد
document.addEventListener("dragover", (e) => { if (e.dataTransfer && [...e.dataTransfer.types].includes("Files")) e.preventDefault(); });
document.addEventListener("drop", (e) => { if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length) e.preventDefault(); });

/* ---------- ترجیحات هر مرورگر ---------- */
const TPREF_KEY = "akrp_term";
const TP = Object.assign({ font: 14, highlight: true, copySel: true, theme: "dark", stats: true }, (() => { try { return JSON.parse(localStorage.getItem(TPREF_KEY) || "{}"); } catch (_) { return {}; } })());
function saveTP() { try { localStorage.setItem(TPREF_KEY, JSON.stringify(TP)); } catch (_) { /* */ } }

const TCOLORS = ["#4fc1b4", "#e7ae45", "#6fa8f0", "#ec6a5e", "#b58cf0", "#5cc48d", "#f08cc6", "#9fb3c8"];
const XTHEME = { background: "#0c141d", foreground: "#d8e2ec", cursor: "#4fc1b4", cursorAccent: "#0c141d", selectionBackground: "#2c4a6a",
  black: "#1b2633", red: "#ec6a5e", green: "#5cc48d", yellow: "#e7ae45", blue: "#6fa8f0", magenta: "#c38cf0", cyan: "#4fc1b4", white: "#d8e2ec",
  brightBlack: "#5f7590", brightRed: "#ff8a7f", brightGreen: "#7fe0a9", brightYellow: "#ffd27a", brightBlue: "#94c1ff", brightMagenta: "#dcb0ff", brightCyan: "#7fe3d7", brightWhite: "#ffffff" };

const TERM = { tabs: [], active: null, seq: 0 };

/* ---------- رنگ‌آمیزی کلمه‌های مهم (بدون دست زدن به رنگ‌های خود دستگاه) ---------- */
const HL_RULES = [
  [/\b(error|errors|failed|failure|fail|denied|invalid|down|unreachable|refused|critical|err-disabled|timeout|timed out|not found|incomplete|rejected)\b/gi, "1;31"],
  [/\b(warning|warn|deprecated|notice|flapping|retrying)\b/gi, "1;33"],
  [/\b(up|ok|success|successful|succeeded|connected|established|enabled|active|running|full|accepted|passed)\b/gi, "1;32"],
  [/\b(?:\d{1,3}\.){3}\d{1,3}(?:\/\d{1,2})?\b/g, "36"],
  [/\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b|\b(?:[0-9a-f]{4}\.){2}[0-9a-f]{4}\b/gi, "35"],
  [/\b(?:(?:Gi|Te|Fa|Eth|Ethernet|GigabitEthernet|TenGigabitEthernet|FastEthernet|Po|Port-channel|Vlan|Lo|Loopback|Tu|Tunnel|port|wan|lan|internal|ens|eth|enp)\d+(?:\/\d+)*(?:\.\d+)?)\b/g, "34"],
];
const ESC_RE = /\x1b(?:\[[0-9;?<>=!]*[ -\/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)|[PX^_][^\x1b]*\x1b\\|[()][0-9A-Za-z]|[@-Z\\-_])/g;
function hlSegment(txt) {
  const marks = [];
  for (const [re, c] of HL_RULES) { re.lastIndex = 0; let m; while ((m = re.exec(txt))) { if (!m[0]) { re.lastIndex++; continue; } marks.push([m.index, m.index + m[0].length, c]); } }
  if (!marks.length) return txt;
  marks.sort((a, b) => a[0] - b[0] || b[1] - a[1]);
  let out = "", pos = 0;
  for (const [s, e, c] of marks) { if (s < pos) continue; out += txt.slice(pos, s) + `\x1b[${c}m` + txt.slice(s, e) + "\x1b[22;39m"; pos = e; }
  return out + txt.slice(pos);
}
function highlight(t, s) {
  // دنباله‌ی ESC ناقص انتهای تکه برای تکه‌ی بعد نگه داشته می‌شود
  s = t.pend + s; t.pend = "";
  const li = s.lastIndexOf("\x1b");
  if (li >= 0 && li > s.length - 64) { const tail = s.slice(li); ESC_RE.lastIndex = 0; const m = ESC_RE.exec(tail); if (!m || m.index !== 0) { t.pend = tail; s = s.slice(0, li); } }
  let out = "", pos = 0, m;
  ESC_RE.lastIndex = 0;
  while ((m = ESC_RE.exec(s))) {
    const seg = s.slice(pos, m.index);
    out += t.fg ? seg : hlSegment(seg);
    const q = m[0];
    if (q.endsWith("m") && q.startsWith("\x1b[")) {            // وضعیت رنگ متن خود دستگاه
      const ps = q.slice(2, -1).split(";");
      for (let i = 0; i < ps.length; i++) {
        const n = Number(ps[i] || 0);
        if (n === 0 || n === 39) t.fg = false;
        else if ((n >= 30 && n <= 37) || (n >= 90 && n <= 97)) t.fg = true;
        else if (n === 38) { t.fg = true; i += ps[i + 1] === "5" ? 2 : 4; }
        else if (n === 48) i += ps[i + 1] === "5" ? 2 : 4;
      }
    }
    out += q; pos = m.index + q.length;
  }
  const rest = s.slice(pos);
  return out + (t.fg ? rest : hlSegment(rest));
}

/* ---------- صفحه‌ی ترمینال ---------- */
function termRoot() {
  let r = $("#termRoot");
  if (!r) {
    r = document.createElement("div"); r.id = "termRoot"; r.hidden = true;
    r.innerHTML = `<div class="term-bar"><div class="term-tabs" id="termTabs" data-no-i18n></div>
      <button class="btn sm primary" id="termNew"><svg><use href="#i-term"/></svg>اتصال تازه</button>
      <button class="btn sm ghost" id="termSnipBtn" title="دستورهای ذخیره‌شده: با یک کلیک به ترمینال فعال (یا همه، در حالت MultiExec) فرستاده می‌شوند">دستورها ▾</button>
      <button class="btn sm ghost" id="termMulti" title="MultiExec: هر چه تایپ یا ارسال کنید هم‌زمان به همه‌ی ترمینال‌های تیک‌خورده می‌رود">MultiExec</button>
      <div class="term-tools">
        <button class="btn sm ghost" id="termFindBtn" title="جست‌وجو در متن همین ترمینال (Ctrl+Shift+F)">جست‌وجو</button>
        <button class="btn sm ghost" id="termLogBtn" title="ذخیره‌ی متن کل این نشست، از اول تا الان، در یک فایل txt. لاگ فقط در حافظه است و با بستن ترمینال پاک می‌شود.">ذخیره‌ی لاگ</button>
        <button class="btn sm ghost" id="termFontM" title="کوچک کردن متن">A−</button><button class="btn sm ghost" id="termFontP" title="بزرگ کردن متن">A+</button>
        <label class="chk" title="رنگی کردن کلمه‌های مهم مثل error، up/down، IP و نام اینترفیس‌ها"><input type="checkbox" id="termHl" ${TP.highlight ? "checked" : ""}>رنگ کلمه‌ها</label>
        <label class="chk" title="متن انتخاب‌شده خودکار کپی شود (کلیک راست = چسباندن)"><input type="checkbox" id="termCs" ${TP.copySel ? "checked" : ""}>کپی با انتخاب</label>
        <label class="chk" title="مصرف CPU، RAM، دیسک و شبکه‌ی سرورهای لینوکس، هر ۳ ثانیه (از یک کانال جدا روی همان اتصال؛ ترمینال دست نمی‌خورد)"><input type="checkbox" id="termSt" ${TP.stats ? "checked" : ""}>نوار منابع</label>
      </div></div>
      <div class="term-snips" id="termSnips" hidden></div>
      <div class="term-multi" id="termMultiBar" hidden></div>
      <div class="term-find" id="termFind" hidden>
        <input type="text" class="ltr" id="termFindQ" placeholder="جست‌وجو در این ترمینال…" autocomplete="off" spellcheck="false">
        <span class="muted" id="termFindN"></span>
        <button class="btn sm ghost" id="termFindPrev" title="قبلی (Shift+Enter)">↑</button><button class="btn sm ghost" id="termFindNext" title="بعدی (Enter)">↓</button>
        <label class="chk" title="حساس به بزرگی و کوچکی حروف"><input type="checkbox" id="termFindCase">Aa</label>
        <button class="btn sm ghost" id="termFindX" title="بستن (Esc)">✕</button>
      </div>
      <div class="term-stage" id="termStage"></div>
      <div class="term-stats" id="termStats" hidden></div>
      <div class="term-status" id="termStatus"></div>`;
    $("#sshBody").after(r);
    $("#termNew").onclick = () => termConnectDlg();
    $("#termMulti").onclick = () => termMultiToggle();
    $("#termSnipBtn").onclick = () => { const b = $("#termSnips"); b.hidden = !b.hidden; if (!b.hidden) termSnipsRender(); };
    $("#termFindBtn").onclick = () => termFindOpen();
    $("#termLogBtn").onclick = (e) => termSaveLog(e.currentTarget);
    $("#termFindQ").oninput = () => termFindGo(1, true);
    $("#termFindQ").onkeydown = (e) => {
      if (e.key === "Enter") { e.preventDefault(); termFindGo(e.shiftKey ? -1 : 1); }
      else if (e.key === "Escape") { e.preventDefault(); termFindClose(); }
    };
    $("#termFindPrev").onclick = () => termFindGo(-1);
    $("#termFindNext").onclick = () => termFindGo(1);
    $("#termFindCase").onchange = () => termFindGo(1, true);
    $("#termFindX").onclick = () => termFindClose();
    $("#termFontM").onclick = () => termFont(-1);
    $("#termFontP").onclick = () => termFont(1);
    $("#termHl").onchange = (e) => { TP.highlight = e.target.checked; saveTP(); };
    $("#termCs").onchange = (e) => { TP.copySel = e.target.checked; saveTP(); };
    $("#termSt").onchange = (e) => { TP.stats = e.target.checked; saveTP(); termStatsRender(); termStatsTick(); };
    window.addEventListener("resize", () => { clearTimeout(TERM._rz); TERM._rz = setTimeout(termFitActive, 120); });
  }
  return r;
}
/* --- جست‌وجو در متن ترمینال فعال (افزونه‌ی رسمی xterm) و ذخیره‌ی لاگ نشست (1.54) --- */
const TFIND_DECO = { matchBackground: "#7c5a00", matchOverviewRuler: "#c9a227", activeMatchBackground: "#d97706", activeMatchColorOverviewRuler: "#f59e0b" };
function termCur() { return TERM.tabs.find((x) => x.id === TERM.active); }
function termFindOpen() {
  const t = termCur(), bar = $("#termFind"); if (!t || !bar) return;
  if (!t.search) return toast("جست‌وجو در این ترمینال در دسترس نیست.", "warn");
  bar.hidden = false; termFitActive();
  const q = $("#termFindQ"), sel = t.term.hasSelection() ? t.term.getSelection() : "";
  if (sel && !sel.includes("\n") && sel.length <= 200) q.value = sel;
  q.focus(); q.select(); if (q.value) termFindGo(1, true);
}
function termFindClose() {
  const bar = $("#termFind"); if (!bar || bar.hidden) return;
  bar.hidden = true; $("#termFindN").textContent = "";
  TERM.tabs.forEach((t) => { if (t.search) t.search.clearDecorations(); });
  termFitActive(); const t = termCur(); if (t) t.term.focus();
}
function termFindGo(dir, incremental) {
  const t = termCur(), q = $("#termFindQ").value; if (!t || !t.search) return;
  if (!q) { t.search.clearDecorations(); t.term.clearSelection(); $("#termFindN").textContent = ""; return; }
  const opts = { caseSensitive: $("#termFindCase").checked, incremental: !!incremental, decorations: TFIND_DECO };
  const found = dir < 0 ? t.search.findPrevious(q, opts) : t.search.findNext(q, opts);
  if (!found) $("#termFindN").textContent = tt("پیدا نشد");
}
function termFindCount(t, e) {
  if (t.id !== TERM.active || !$("#termFind") || $("#termFind").hidden) return;
  const n = e && e.resultCount || 0;
  $("#termFindN").textContent = !$("#termFindQ").value ? "" : !n ? tt("پیدا نشد") : e.resultIndex >= 0 ? `${num(e.resultIndex + 1)} / ${num(n)}` : `${num(n)}${n >= 1000 ? "+" : ""}`;
}
async function termSaveLog(btn) {
  const t = termCur(); if (!t) return toast("ترمینالی باز نیست.", "warn");
  const r = await withSpin(btn, () => api("term_log", t.id));
  if (!r.ok) return toast(r.error, "error");
  if (!r.cancelled) { toast("ذخیره شد: " + r.path, "ok"); t.logWarned = false; }
}
function termFont(d) {
  TP.font = Math.max(9, Math.min(28, TP.font + d)); saveTP();
  TERM.tabs.forEach((t) => { t.term.options.fontSize = TP.font; });
  termFitActive();
}

async function sshTerm() {
  $("#sshActions").innerHTML = "";
  $("#sshBody").innerHTML = "";
  const r = termRoot(); r.hidden = false;
  if (!TERM.loaded) {
    TERM.loaded = true;
    const l = await api("term_list");
    if (l.ok) for (const s of l.sessions) if (!TERM.tabs.find((t) => t.id === s.id)) await termAttach(s);
  }
  if (!TERM.tabs.length) $("#termStage").innerHTML = `<div class="empty term-empty">هنوز ترمینالی باز نیست. «اتصال تازه» را بزنید؛ می‌توانید چند ترمینال هم‌زمان در تب‌های جدا داشته باشید.<br><small class="muted">Ctrl+Shift+C کپی · Ctrl+Shift+V یا کلیک راست چسباندن · متن چندخطی پیش از ارسال تأیید می‌خواهد</small></div>`;
  termRenderTabs(); setTimeout(termFitActive, 30);
}
function termHide() { const r = $("#termRoot"); if (r) r.hidden = true; }

function termRenderTabs() {
  const box = $("#termTabs"); if (!box) return;
  box.innerHTML = TERM.tabs.map((t) => `<div class="term-tab ${t.id === TERM.active ? "on" : ""} ${t.closed ? "dead" : ""}" data-tid="${t.id}" title="${esc(t.host + ":" + t.port)}">
    ${TERM.multi ? `<input type="checkbox" class="tm-chk" data-tm="${t.id}" ${TERM.multiSel.has(t.id) ? "checked" : ""} ${t.closed ? "disabled" : ""} title="در MultiExec">` : ""}<span class="dot" style="background:${t.color}"></span><span class="tt">${esc(t.title)}</span>${t.proto && t.proto !== "ssh" ? `<span class="tag ${t.proto === "telnet" ? "warn" : "info"} tp">${t.proto === "telnet" ? "Telnet" : "COM"}</span>` : ""}${t.recording ? `<span class="rec" title="متن این نشست ضبط می‌شود">●</span>` : ""}
    <button class="x" data-tclose="${t.id}" title="بستن"><svg><use href="#i-x"/></svg></button></div>`).join("");
  $$("[data-tid]", box).forEach((el) => (el.onclick = (e) => { if (!e.target.closest("[data-tclose]") && !e.target.closest("[data-tm]")) termActivate(el.dataset.tid); }));
  $$("[data-tm]", box).forEach((c) => (c.onchange = () => { c.checked ? TERM.multiSel.add(c.dataset.tm) : TERM.multiSel.delete(c.dataset.tm); termMultiBar(); }));
  termMultiBar();
  $$("[data-tclose]", box).forEach((b) => (b.onclick = () => termCloseTab(b.dataset.tclose)));
  termStatus(); termStatsRender();
}
function termStatus() {
  const t = TERM.tabs.find((x) => x.id === TERM.active), el = $("#termStatus"); if (!el) return;
  el.innerHTML = t ? `<span class="dot" style="background:${t.color}"></span>${t.proto === "serial"
      ? `<span class="ltr">${esc(t.host)} · ${esc(t.info || "")}</span><span class="tag info">کابل کنسول</span>${t.closed ? "" : `<button class="btn sm" id="termBrk" title="ارسال سیگنال Break (مثلاً برای Password Recovery روتر Cisco در ۶۰ ثانیه‌ی اول روشن شدن)">Break</button>`}`
      : `<span class="ltr">${esc(t.user ? t.user + "@" : "")}${esc(t.host)}:${t.port}</span>${t.proto === "telnet" ? `<span class="tag warn" title="یوزر، رمز و همه‌ی متن‌ها روی شبکه خوانا منتقل می‌شوند">Telnet — بدون رمزنگاری</span>` : ""}`}
    ${t.kind === "adhoc" ? `<span class="tag mute">موقت</span>` : ""}${t.recording ? `<span class="tag warn">ضبط روشن</span>` : ""}${t.logcut ? `<span class="tag warn" title="لاگ نشست به سقف حافظه رسید و ابتدای آن پاک شد. «ذخیره‌ی لاگ» فقط بخش باقی‌مانده را ذخیره می‌کند.">ابتدای لاگ پاک شد</span>` : (t.logp || 0) >= 80 ? `<span class="tag warn" title="لاگ نشست فقط در حافظه است. اگر لازم دارید با «ذخیره‌ی لاگ» ذخیره کنید؛ با پر شدن، قسمت‌های قدیمی‌تر پاک می‌شوند.">لاگ نشست ${num(t.logp)}٪ پر</span>` : ""}
    ${t.closed ? `<span class="tag err">قطع: ${esc(t.reason || "")}</span><button class="btn sm" id="termRe">اتصال دوباره</button>` : `<span class="tag ok">وصل</span>`}
    <span class="muted ltr" style="margin-inline-start:auto">${t.cols}×${t.rows}</span>` : "";
  const re = $("#termRe"); if (re) re.onclick = () => termReconnect(t);
  const bk = $("#termBrk"); if (bk) bk.onclick = async () => { const r = await api("term_break", t.id); if (!r.ok) toast(r.error, "error"); else toast("Break فرستاده شد", "ok"); t.term.focus(); };
}
function termActivate(id) {
  TERM.active = id;
  TERM.tabs.forEach((t) => (t.el.hidden = t.id !== id));
  const emp = $(".term-empty"); if (emp) emp.remove();
  termRenderTabs();
  const t = TERM.tabs.find((x) => x.id === id);
  termStatsRender();
  if ($("#termFind") && !$("#termFind").hidden) { TERM.tabs.forEach((x) => { if (x !== t && x.search) x.search.clearDecorations(); }); $("#termFindN").textContent = ""; if (t && t.search && $("#termFindQ").value) setTimeout(() => termFindGo(1, true), 60); }
  if (t) setTimeout(() => { termFit(t); t.term.focus(); termStatsTick(); }, 20);
}
function termFit(t) {
  if (!t || t.el.hidden || !t.el.offsetWidth) return;
  try { t.fit.fit(); } catch (_) { /* */ }
}
function termFitActive() { termFit(TERM.tabs.find((x) => x.id === TERM.active)); }

async function termConnectDlg(preset) {
  const devs = SSH.devices.filter((d) => d.has_password && d.username);
  const p = preset || {};
  const serialOk = !(S.state && (S.state.hidden_modes || []).includes("serial")) && axOk("term.serial", "run");
  const mode0 = p.serial ? "serial" : p.adhoc ? "adhoc" : "dev";
  const tel = p.protocol === "telnet";
  const res = await openModal({
    title: "اتصال ترمینال", wide: false,
    body: `<div class="seg" id="tcMode" style="margin-bottom:12px"><button data-v="dev" class="${mode0 === "dev" ? "on" : ""}">دستگاه ذخیره‌شده</button><button data-v="adhoc" class="${mode0 === "adhoc" ? "on" : ""}">اتصال موقت (SSH / Telnet)</button>${serialOk ? `<button data-v="serial" class="${mode0 === "serial" ? "on" : ""}">کابل کنسول (COM)</button>` : ""}</div>
      <div id="tcDev" ${mode0 === "dev" ? "" : "hidden"}>${devs.length ? `<label class="field"><span>دستگاه</span><select id="tcDevSel">${devs.map((d) => `<option value="${d.id}" ${d.id === p.device_id ? "selected" : ""}>${esc(d.name)} — ${esc(d.host)}${d.protocol === "telnet" ? " (Telnet)" : ""}${d.personal ? " (شخصی)" : ""}</option>`).join("")}</select></label>
        <p class="hint">یوزر و رمز ذخیره‌شده‌ی دستگاه استفاده می‌شود و به مرورگر نمی‌آید. برای تجهیزات Cisco با «ورود به enable»، enable خودکار زده می‌شود.</p>`
        : `<div class="empty">دستگاهی با یوزر و رمز ذخیره‌شده ندارید؛ از «اتصال موقت» استفاده کنید یا در تب «دستگاه‌ها» دستگاه بسازید.</div>`}</div>
      <div id="tcAd" ${mode0 === "adhoc" ? "" : "hidden"}><div class="form-grid">
        <label class="field"><span>پروتکل</span><select id="tcProto"><option value="ssh">SSH</option><option value="telnet" ${tel ? "selected" : ""}>Telnet</option></select></label>
        <label class="field"><span>آدرس</span><input id="tcHost" class="ltr" value="${esc(p.host || "")}" placeholder="10.0.0.1"></label>
        <label class="field"><span>پورت</span><input id="tcPort" class="ltr" value="${esc(p.port || (tel ? 23 : 22))}"></label>
        <label class="field"><span>یوزر</span><input id="tcUser" class="ltr" value="${esc(p.username || "")}" autocomplete="off"></label>
        <label class="field"><span>رمز</span><input id="tcPass" type="password" class="ltr" autocomplete="off"></label>
        <label class="field"><span>نوع دستگاه</span><select id="tcType">${typeOptions(p.device_type || "linux")}</select></label>
        <label class="chk tcSsh" style="align-self:end"><input type="checkbox" id="tcLegacy" ${p.legacy ? "checked" : ""}>الگوریتم‌های قدیمی (دستگاه‌های قدیمی)</label>
      </div><p class="hint tcSsh">اتصال موقت ذخیره نمی‌شود؛ فقط در تاریخچه ثبت می‌شود. بار اول اثر انگشت کلید دستگاه برای تأیید نشان داده می‌شود.</p>
      <p class="hint warn-text tcTel">Telnet رمزنگاری ندارد و یوزر و رمز روی شبکه خوانا می‌روند. یوزر و رمز اختیاری است: اگر وارد کنید، وقتی دستگاه «Username:» و «Password:» بپرسد خودکار وارد می‌شود.</p></div>
      <div id="tcSer" ${mode0 === "serial" ? "" : "hidden"}><div class="form-grid">
        <label class="field wide"><span>پورت</span><div class="row" style="gap:6px"><select id="tcCom" class="ltr" style="flex:1"></select><button class="btn sm ghost" id="tcComRe" type="button" title="تازه کردن فهرست">↻</button></div></label>
        <label class="field"><span>سرعت (Baud)</span><select id="tcBaud" class="ltr"></select></label>
        <label class="field"><span>بیت داده</span><select id="tcBits" class="ltr">${[8, 7, 6, 5].map((x) => `<option ${x === (p.bits || 8) ? "selected" : ""}>${x}</option>`).join("")}</select></label>
        <label class="field"><span>Parity</span><select id="tcPar" class="ltr">${[["N", "None"], ["E", "Even"], ["O", "Odd"], ["M", "Mark"], ["S", "Space"]].map(([v, t]) => `<option value="${v}" ${v === (p.parity || "N") ? "selected" : ""}>${t}</option>`).join("")}</select></label>
        <label class="field"><span>Stop bits</span><select id="tcStop" class="ltr">${["1", "1.5", "2"].map((x) => `<option ${x === String(p.stop || "1") ? "selected" : ""}>${x}</option>`).join("")}</select></label>
        <label class="field"><span>Flow control</span><select id="tcFlow" class="ltr">${[["none", "None"], ["xonxoff", "XON/XOFF"], ["rtscts", "RTS/CTS"], ["dsrdtr", "DSR/DTR"]].map(([v, t]) => `<option value="${v}" ${v === (p.flow || "none") ? "selected" : ""}>${t}</option>`).join("")}</select></label>
      </div><p class="hint">کابل کنسول (USB یا RJ45-DB9) را وصل کنید؛ بعد از نصب درایور، پورت آن در «Ports (COM &amp; LPT)» ویندوز و همین فهرست دیده می‌شود. تنظیم رایج Cisco و بیشتر روترها و مودم‌ها: 9600 8N1 بدون Flow control.</p>
      <div id="tcComNone" class="empty" hidden>هیچ پورت سریالی پیدا نشد. کابل را وصل کنید و درایور آن را نصب کنید؛ فهرست خودکار تازه می‌شود.</div></div>`,
    foot: `<button class="btn ghost" data-r="0">انصراف</button><button class="btn primary" data-r="1">اتصال</button>`,
    onOpen: (m, close) => {
      let timer = null, ports = null;
      const loadPorts = async () => {
        const r = await api("serial_ports"); if (!r.ok || !m.isConnected) return;
        if (!$("#tcBaud", m).options.length) $("#tcBaud", m).innerHTML = r.bauds.map((b) => `<option ${b === (p.baud || 9600) ? "selected" : ""}>${b}</option>`).join("");
        const sig = JSON.stringify(r.ports); if (sig === ports) return; ports = sig;
        const cur = $("#tcCom", m).value || p.port;
        $("#tcCom", m).innerHTML = r.ports.map((x) => `<option value="${esc(x.port)}" ${x.port === cur ? "selected" : ""}>${esc(x.port)}${x.desc ? " — " + esc(x.desc) : ""}</option>`).join("");
        $("#tcComNone", m).hidden = !!r.ports.length;
        if (!r.available) { $("#tcComNone", m).hidden = false; $("#tcComNone", m).textContent = tt("کتابخانه‌ی pyserial نصب نیست."); }
      };
      const setMode = (v) => {
        $$("#tcMode button", m).forEach((x) => x.classList.toggle("on", x.dataset.v === v));
        $("#tcDev", m).hidden = v !== "dev"; $("#tcAd", m).hidden = v !== "adhoc"; $("#tcSer", m).hidden = v !== "serial";
        clearTimeout(timer); timer = null;
        if (v === "serial") {        // کابل تازه وصل‌شده خودکار دیده شود؛ درخواست بعدی فقط بعد از پاسخ قبلی (شمارش پورت در ویندوز کند است)
          const loop = async () => { if (!m.isConnected || $("#tcSer", m).hidden) return; await loadPorts(); timer = setTimeout(loop, 3000); };
          loop();
        }
      };
      const protoUi = () => { const t = $("#tcProto", m).value === "telnet"; $$(".tcSsh", m).forEach((x) => (x.hidden = t)); $$(".tcTel", m).forEach((x) => (x.hidden = !t)); };
      $("#tcProto", m).onchange = () => { const pp = $("#tcPort", m); if (["22", "23", ""].includes(pp.value.trim())) pp.value = $("#tcProto", m).value === "telnet" ? 23 : 22; protoUi(); };
      protoUi();
      $$("#tcMode button", m).forEach((b) => (b.onclick = () => setMode(b.dataset.v)));
      $("#tcComRe", m).onclick = () => { ports = null; loadPorts(); };
      setMode(mode0);
      $("[data-r='0']", m).onclick = () => { clearTimeout(timer); close(null); };
      $("[data-r='1']", m).onclick = () => {
        if (!$("#tcSer", m).hidden) {
          const port = $("#tcCom", m).value; if (!port) return toast("پورت سریال انتخاب نشده است", "error");
          clearTimeout(timer);
          return close({ serial: { port, baud: Number($("#tcBaud", m).value) || 9600, bits: Number($("#tcBits", m).value), parity: $("#tcPar", m).value, stop: $("#tcStop", m).value, flow: $("#tcFlow", m).value } });
        }
        clearTimeout(timer);
        if (!$("#tcAd", m).hidden) {
          const host = $("#tcHost", m).value.trim(); if (!host) return toast("آدرس را وارد کنید", "error");
          const proto = $("#tcProto", m).value;
          close({ adhoc: { protocol: proto, host, port: Number($("#tcPort", m).value) || (proto === "telnet" ? 23 : 22), username: $("#tcUser", m).value.trim(), password: $("#tcPass", m).value, device_type: $("#tcType", m).value, legacy: $("#tcLegacy", m).checked } });
        } else { const sel = $("#tcDevSel", m); if (!sel) return; close({ device_id: Number(sel.value) }); }
      };
      const pw = $("#tcPass", m); if (pw) pw.onkeydown = (e) => { if (e.key === "Enter") $("[data-r='1']", m).click(); };
    },
  });
  if (res) await termOpen(res);
}
async function hostKeyConfirm(c) {
  return confirm2({ title: "تأیید کلید دستگاه", confirm: "اعتماد و اتصال",
    body: `<p>این اولین اتصال به <b class="ltr">${esc(c.host)}</b> است. اثر انگشت کلید را با خود دستگاه مقایسه کنید:</p>
      <p class="ltr tech" style="font-size:13px;word-break:break-all">${esc(c.type)} ${esc(c.fingerprint)}</p>
      <p class="hint">با تأیید، کلید ثبت می‌شود و از این به بعد اگر عوض شود اتصال رد می‌شود.</p>` });
}
/* اتصال قابل لغو: نوار «در حال اتصال… [لغو]» (Esc هم لغو می‌کند)؛ شناسه‌ی تلاش را رابط می‌سازد */
function connLabel(target) {
  if (target.serial) return target.serial.port + " (" + target.serial.baud + ")";
  if (target.adhoc) return target.adhoc.host + (target.adhoc.port ? ":" + target.adhoc.port : "");
  const d = (SSH.devices || []).find((x) => x.id === target.device_id); return d ? (d.name || d.host) : "";
}
async function connTry(btn, label, call) {
  const aid = (window.crypto && crypto.randomUUID ? crypto.randomUUID() : String(Date.now()) + Math.random().toString(36).slice(2)).replace(/[^A-Za-z0-9]/g, "");
  const bar = document.createElement("div"); bar.className = "conn-wait";
  bar.innerHTML = `<span class="cw-spin"></span><span>در حال اتصال به <b class="ltr">${esc(label)}</b>…</span><button class="btn sm" title="Esc">لغو</button>`;
  document.body.appendChild(bar);
  let cancelled = false;
  const cancel = () => { if (cancelled) return; cancelled = true; const b = bar.querySelector("button"); b.disabled = true; b.textContent = "در حال لغو…"; api("conn_cancel", aid); };
  bar.querySelector("button").onclick = cancel;
  const key = (e) => { if (e.key === "Escape") { e.preventDefault(); e.stopPropagation(); cancel(); } };
  document.addEventListener("keydown", key, true);
  try { return await withSpin(btn, () => call(aid)); }
  finally { document.removeEventListener("keydown", key, true); bar.remove(); }
}
async function termOpen(target, accept) {
  await loadXterm().catch(() => null);
  if (!window.Terminal) return toast("بارگذاری ترمینال ناموفق بود", "error");
  const t0 = termTemp();
  const r = await connTry($("#termNew"), connLabel(target), (aid) => api("term_open", target, t0.cols, t0.rows, accept || null, aid));
  if (!r.ok) return toast(r.error, r.cancelled ? "warn" : "error");
  if (r.confirm) { if (await hostKeyConfirm(r.confirm)) return termOpen(target, r.confirm.fingerprint); return; }
  const s = r.session;
  s.user = target.serial ? "" : target.adhoc ? target.adhoc.username : ((SSH.devices.find((d) => d.id === target.device_id) || {}).username || "");
  s.target = target.adhoc ? { adhoc: { ...target.adhoc, password: "" } } : target;
  await termAttach(s);
}
function termTemp() {
  // اندازه‌ی تقریبی پیش از ساخت ترمینال (بعد با fit دقیق می‌شود)
  const st = $("#termStage"), w = (st && st.clientWidth) || 900, h = (st && st.clientHeight) || 500;
  return { cols: Math.max(40, Math.floor(w / (TP.font * 0.6))), rows: Math.max(10, Math.floor(h / (TP.font * 1.2))) };
}
async function termAttach(s) {
  await loadXterm();
  const el = document.createElement("div"); el.className = "term-pane"; el.hidden = true; el.setAttribute("data-no-i18n", "");   // خروجی دستگاه ترجمه نشود
  $("#termStage").appendChild(el);
  const term = new window.Terminal({ fontFamily: 'Consolas, "Cascadia Mono", "DejaVu Sans Mono", monospace', fontSize: TP.font, cursorBlink: true,
    scrollback: 5000, theme: XTHEME, allowProposedApi: true, rightClickSelectsWord: false, convertEol: false });
  const fit = new window.FitAddon.FitAddon(); term.loadAddon(fit); term.open(el);
  let search = null;
  try { if (window.SearchAddon) { search = new window.SearchAddon.SearchAddon({ highlightLimit: 1000 }); term.loadAddon(search); } } catch (_) { search = null; }
  const t = { ...s, el, term, fit, search, next: 0, dec: new TextDecoder("utf-8"), fg: false, pend: "", color: TCOLORS[TERM.seq++ % TCOLORS.length], cols: term.cols, rows: term.rows, out: "", sending: false };
  TERM.tabs.push(t);
  // ورودی: تجمیع و ارسال ترتیبی
  term.onData((d) => termInput(t, d));
  term.onResize(({ cols, rows }) => { t.cols = cols; t.rows = rows; termStatus(); clearTimeout(t._rz); t._rz = setTimeout(() => !t.closed && api("term_resize", t.id, cols, rows), 150); });
  term.onSelectionChange(() => { if (TP.copySel && term.hasSelection() && document.activeElement !== $("#termFindQ")) termCopy(term.getSelection()); });
  if (search) search.onDidChangeResults((e) => termFindCount(t, e));
  term.attachCustomKeyEventHandler((e) => {
    if (e.type !== "keydown") return true;
    if (e.ctrlKey && e.shiftKey && (e.key === "C" || e.key === "c")) { if (term.hasSelection()) termCopy(term.getSelection()); return false; }
    if (e.ctrlKey && e.shiftKey && (e.key === "V" || e.key === "v")) { termPaste(t); return false; }
    if (e.ctrlKey && e.shiftKey && (e.key === "F" || e.key === "f")) { e.preventDefault(); termFindOpen(); return false; }
    if (e.key === "Escape" && $("#termFind") && !$("#termFind").hidden) { termFindClose(); return false; }
    return true;
  });
  el.addEventListener("contextmenu", (e) => { e.preventDefault(); termPaste(t); });
  el.addEventListener("paste", (e) => {           // Ctrl+V معمولی
    const txt = (e.clipboardData && e.clipboardData.getData("text")) || "";
    e.preventDefault(); e.stopPropagation(); termPasteText(t, txt);
  }, true);
  termActivate(t.id);
  termPoll(t);
}
/* ورودی کاربر؛ در MultiExec به همه‌ی ترمینال‌های تیک‌خورده‌ی باز هم می‌رود */
function termInput(t, d) {
  if (t.closed) return;
  const targets = TERM.multi && TERM.multiSel.has(t.id) ? TERM.tabs.filter((x) => !x.closed && TERM.multiSel.has(x.id)) : [t];
  for (const x of targets) { x.out += d; termFlush(x); }
}
function termMultiToggle() {
  TERM.multi = !TERM.multi;
  if (TERM.multi) TERM.multiSel = new Set(TERM.tabs.filter((x) => !x.closed).map((x) => x.id));
  $("#termMulti").classList.toggle("warn", TERM.multi);
  termRenderTabs();
  const t = TERM.tabs.find((x) => x.id === TERM.active); if (t) t.term.focus();
}
function termMultiBar() {
  const b = $("#termMultiBar"); if (!b) return;
  if (!TERM.multi) { b.hidden = true; return; }
  const n = TERM.tabs.filter((x) => !x.closed && TERM.multiSel.has(x.id)).length;
  b.hidden = false;
  b.innerHTML = `<b>MultiExec روشن است</b><span>هر چه در یکی از ترمینال‌های تیک‌خورده تایپ کنید هم‌زمان به ${num(n)} ترمینال می‌رود.</span><button class="btn sm" id="tmOff">خاموش</button>`;
  $("#tmOff").onclick = termMultiToggle;
}
TERM.multi = false; TERM.multiSel = new Set();
function termSnips() { return (S.settings && S.settings.ui && S.settings.ui.term_snips) || []; }
function termSnipsRender() {
  const box = $("#termSnips"); if (!box) return;
  const list = termSnips();
  box.innerHTML = `<div class="row" style="gap:6px;flex-wrap:wrap;align-items:center">${list.length ? list.map((x, i) => `<button class="btn sm ghost ltr" data-sn="${i}" title="${esc(x.text.slice(0, 300))}">${esc(x.name)}</button>`).join("")
      : `<span class="muted">هنوز دستوری ذخیره نشده است.</span>`}<button class="btn sm" id="snEdit" style="margin-inline-start:auto">ویرایش دستورها…</button></div>`;
  $$("[data-sn]", box).forEach((b) => (b.onclick = () => termSnipSend(list[Number(b.dataset.sn)])));
  $("#snEdit").onclick = termSnipsEdit;
}
async function termSnipSend(x) {
  const t = TERM.tabs.find((y) => y.id === TERM.active);
  if (!t || t.closed) return toast("ترمینال فعالی باز نیست", "warn");
  let txt = x.text.replace(/\r\n/g, "\n");
  const lines = txt.split("\n");
  const many = TERM.multi && TERM.multiSel.has(t.id) ? TERM.tabs.filter((y) => !y.closed && TERM.multiSel.has(y.id)).length : 1;
  if (lines.length > 1 || many > 1) {
    const ok = await confirm2({ title: "ارسال دستور", confirm: "ارسال",
      body: `<p>${many > 1 ? `به ${num(many)} ترمینال (MultiExec)` : "به ترمینال فعال"} فرستاده می‌شود:</p><pre class="ltr paste-prev" data-no-i18n>${esc(txt.slice(0, 3000))}</pre>` });
    t.term.focus(); if (!ok) return;
  }
  txt = lines.join("\r") + (x.enter !== false ? "\r" : "");
  termInput(t, txt);
  t.term.focus();
}
function termSnipsEdit() {
  const list = termSnips().map((x) => ({ ...x }));
  openModal({ title: "دستورهای ذخیره‌شده‌ی ترمینال", wide: true,
    body: `<p class="hint">هر دستور یک دکمه در نوار ترمینال می‌شود. متن چندخطی خط‌به‌خط فرستاده می‌شود. این فهرست فقط برای حساب شماست.</p><div id="snList"></div>
      <button class="btn sm" id="snAdd" style="margin-top:8px">+ دستور تازه</button>`,
    foot: `<button class="btn ghost" data-x="0">انصراف</button><button class="btn primary" id="snSave">ذخیره</button>`,
    onOpen: (m, close) => {
      const draw = () => {
        $("#snList", m).innerHTML = list.map((x, i) => `<div class="form-grid" style="border-bottom:1px solid var(--line);padding-bottom:8px;margin-bottom:8px">
          <label class="field"><span>نام دکمه</span><input data-k="name" data-i="${i}" value="${esc(x.name || "")}" maxlength="60"></label>
          <label class="chk" style="align-self:end"><input type="checkbox" data-k="enter" data-i="${i}" ${x.enter !== false ? "checked" : ""}>Enter در پایان</label>
          <label class="field wide"><span>متن</span><textarea class="ltr code-edit" data-k="text" data-i="${i}" style="min-height:54px">${esc(x.text || "")}</textarea></label>
          <div class="row" style="gap:6px"><button class="btn sm ghost" data-up="${i}" ${i ? "" : "disabled"}>↑</button><button class="btn sm danger-ghost" data-del="${i}">حذف</button></div></div>`).join("") || `<div class="empty">خالی</div>`;
        $$("[data-k]", m).forEach((el) => (el.oninput = el.onchange = () => { const x = list[Number(el.dataset.i)]; x[el.dataset.k] = el.type === "checkbox" ? el.checked : el.value; }));
        $$("[data-del]", m).forEach((b) => (b.onclick = () => { list.splice(Number(b.dataset.del), 1); draw(); }));
        $$("[data-up]", m).forEach((b) => (b.onclick = () => { const i = Number(b.dataset.up); [list[i - 1], list[i]] = [list[i], list[i - 1]]; draw(); }));
      };
      draw();
      $("#snAdd", m).onclick = () => { list.push({ name: "", text: "", enter: true }); draw(); const ts = $$("textarea", m); if (ts.length) ts[ts.length - 1].focus(); };
      $("[data-x]", m).onclick = () => close();
      $("#snSave", m).onclick = async () => {
        const items = list.filter((x) => String(x.text || "").trim());
        const r = await api("term_snips_save", items); if (!r.ok) return toast(r.error, "error");
        S.settings.ui = S.settings.ui || {}; S.settings.ui.term_snips = r.items; close(); toast("ذخیره شد", "ok"); termSnipsRender();
      };
    } });
}
async function termCopy(s) { try { await navigator.clipboard.writeText(s); } catch (_) { /* بدون دسترسی clipboard */ } }
async function termPaste(t) {
  let txt = "";
  try { txt = await navigator.clipboard.readText(); } catch (_) { return toast("دسترسی به کلیپ‌بورد نیست؛ از Ctrl+V استفاده کنید", "warn"); }
  termPasteText(t, txt);
}
async function termPasteText(t, txt) {
  if (!txt || t.closed) return;
  txt = txt.replace(/\r\n/g, "\n");
  const lines = txt.split("\n").filter((x, i, a) => x || i < a.length - 1);
  if (lines.length > 1 || txt.length > 2000) {
    const ok = await confirm2({ title: "چسباندن چندخطی", confirm: "ارسال به دستگاه",
      body: `<p>این متن ${num(lines.length)} خط دارد و هر خط مثل یک دستور اجرا می‌شود:</p><pre class="ltr paste-prev" data-no-i18n>${esc(txt.slice(0, 3000))}${txt.length > 3000 ? "\n…" : ""}</pre>` });
    t.term.focus();
    if (!ok) return;
  }
  t.term.paste(txt);
}
async function termFlush(t) {
  if (t.sending) return;
  t.sending = true;
  try {
    while (t.out && !t.closed) {
      const d = t.out; t.out = "";
      const r = await api("term_write", t.id, d);
      if (!r.ok) { termDead(t, r.error); break; }
    }
  } finally { t.sending = false; }
}
async function termPoll(t) {
  t.polling = true;
  while (!t.closed && TERM.tabs.includes(t)) {
    const r = await api("term_read", t.id, t.next);
    if (!TERM.tabs.includes(t)) break;
    if (!r.ok) { termDead(t, r.error); break; }
    if (r.lost) t.term.write("\r\n\x1b[33m" + tt("[بخشی از خروجی قدیمی‌تر از حافظه حذف شده است]") + "\x1b[0m\r\n");
    if (r.data) {
      const bin = atob(r.data), u = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
      let s = t.dec.decode(u, { stream: true });
      if (TP.highlight) s = highlight(t, s); else if (t.pend) { s = t.pend + s; t.pend = ""; }
      t.term.write(s);
    }
    t.next = r.next;
    if ((r.logp || 0) !== t.logp || !!r.logcut !== !!t.logcut) {      // لاگ نشست فقط در حافظه است؛ نزدیک سقف هشدار بده
      t.logp = r.logp || 0; t.logcut = !!r.logcut;
      if (t.logp >= 80 && !t.logWarned) { t.logWarned = true; toast(`${tt("لاگ نشست")} «${t.title}» ${tt("نزدیک سقف حافظه است؛ اگر لازم دارید با «ذخیره‌ی لاگ» ذخیره کنید، وگرنه قسمت‌های قدیمی‌تر پاک می‌شوند.")}`, "warn"); }
      if (t.id === TERM.active) termStatus();
    }
    if (r.closed) { termDead(t, r.reason); break; }
  }
  t.polling = false;
}
function termDead(t, reason) {
  if (t.closed) return;
  t.closed = true; t.reason = reason || "";
  const msg = tt(reason ? `[اتصال بسته شد: ${reason}]` : "[اتصال بسته شد]");
  t.term.write("\r\n\x1b[1;33m" + msg + "\x1b[0m\r\n");
  termRenderTabs();
}
async function termCloseTab(id) {
  const t = TERM.tabs.find((x) => x.id === id); if (!t) return;
  if (!t.closed && !(await confirm2({ title: "بستن ترمینال", body: `<p>اتصال به <b>${esc(t.title)}</b> قطع شود؟</p>`, confirm: "قطع اتصال", danger: true }))) return;
  t.closed = true;
  api("term_close", t.id);
  TERM.tabs = TERM.tabs.filter((x) => x !== t);
  t.term.dispose(); t.el.remove();
  if (TERM.active === id) TERM.active = TERM.tabs.length ? TERM.tabs[TERM.tabs.length - 1].id : null;
  if (TERM.active) termActivate(TERM.active); else { termRenderTabs(); sshTerm(); }
}
async function termReconnect(t) {
  api("term_close", t.id);
  if (t.target && t.target.adhoc) return termConnectDlg({ ...t.target.adhoc, adhoc: true });
  if (t.target && t.target.serial) return termOpen(t.target);
  if (t.target) return termOpen(t.target);
  termConnectDlg();
}

/* ================================================================ انتقال فایل (شبیه WinSCP) */
const XF = { conns: [], cur: null, desktop: !WEB, limit: 0, limitH: "", local: { cwd: "", items: [], sel: new Set() }, rsel: new Set(),
  sub: "files", jobs: [], polling: false, sort: { k: "name", d: 1 }, tftp: null, tftpSel: new Set(),
  focus: "r", files: new Map(), kc: { l: null, r: null }, ka: { l: null, r: null } };   // kc: ردیف مکان‌نما (کیبورد)، ka: لنگر Shift   // focus: پنل فعال برای Backspace؛ files: فایل‌های مرورگر برای «تلاش مجدد»

/* پنل فعال (برای کلیدها، keys.js) = آخرین پنلی که رویش کلیک شده (مثل WinSCP) */
document.addEventListener("mousedown", (e) => {
  const p = e.target.closest && e.target.closest("#xfLocal, #xfRemote"); if (!p) return;
  XF.focus = p.id === "xfLocal" ? "l" : "r";
  $$(".xf-pane").forEach((x) => x.classList.toggle("act", x === p));
}, true);

async function sshXfer() {
  termHide();
  $("#sshActions").innerHTML = "";
  const canF = axOk("term.xfer"), canT = axOk("term.tftp");          // 1.39: هر کدام جدا خاموش یا پنهان می‌شود
  if (!canF) XF.sub = "tftp"; else if (!canT) XF.sub = "files";
  const c = canF ? await api("xfer_conns") : { ok: false };
  if (c.ok) { XF.conns = c.conns; XF.limit = c.limit; XF.limitH = c.limit_h; XF.desktop = c.desktop; }
  if (XF.cur && !XF.conns.find((x) => x.id === XF.cur.id)) XF.cur = null;
  if (!XF.cur && XF.conns.length) XF.cur = XF.conns[0];
  $("#sshBody").innerHTML = `<div class="xf-top"><div class="seg" id="xfSub">${canF ? `<button data-v="files" class="${XF.sub === "files" ? "on" : ""}">SFTP / SCP / FTP</button>` : ""}${canT ? `<button data-v="tftp" class="${XF.sub === "tftp" ? "on" : ""}">سرور TFTP</button>` : ""}</div>
      <span class="muted">${XF.limit ? `سقف حجم هر فایل: <b class="ltr">${esc(XF.limitH)}</b>` : "بدون محدودیت حجم"}</span></div>
    <div id="xfMain"></div>
    <div class="panel xf-queue" ${canF ? "" : "hidden"}><div class="panel-head"><h3>انتقال‌ها</h3><button class="btn sm ghost" id="xfClear">پاک کردن تمام‌شده‌ها</button></div><div id="xfJobs"></div></div>`;
  $$("#xfSub button").forEach((b) => (b.onclick = () => { XF.sub = b.dataset.v; sshXfer(); }));
  $("#xfClear").onclick = async () => { await api("xfer_clear"); xfPollJobs(true); };
  if (XF.sub === "tftp") await tftpRender(); else xfRenderFiles();
  xfPollJobs(true);
}

function xfRenderFiles() {
  const conns = XF.conns;
  $("#xfMain").innerHTML = `<div class="xf-conns">${conns.map((c) => `<div class="term-tab ${XF.cur && c.id === XF.cur.id ? "on" : ""}" data-xc="${c.id}"><span class="tag info">${c.proto.toUpperCase()}</span><span class="tt">${esc(c.title)}</span><button class="x" data-xclose="${c.id}" title="قطع اتصال"><svg><use href="#i-x"/></svg></button></div>`).join("")}
      <button class="btn sm primary" id="xfNew">اتصال تازه</button></div>
    <div class="xf-panes ${XF.desktop ? "" : "web"}">
      <div class="xf-pane ${XF.focus === "l" ? "act" : ""}" id="xfLocal"></div>
      <div class="xf-pane ${XF.focus === "r" ? "act" : ""}" id="xfRemote"></div>
    </div>
    <div class="kbd-hint">${XF.desktop ? `<kbd>Tab</kbd> پنل دیگر · ` : ""}<kbd>↑</kbd><kbd>↓</kbd> حرکت · <kbd>Enter</kbd> باز کردن · <kbd>Backspace</kbd> پوشه‌ی بالاتر · <kbd>Space</kbd>/<kbd>Shift</kbd> انتخاب · <kbd>Ctrl+A</kbd> همه · <kbd>F5</kbd> کپی به پنل دیگر · <kbd>F2</kbd> تغییر نام · <kbd>F7</kbd> پوشه‌ی تازه · <kbd>Delete</kbd> حذف · <kbd>Ctrl+R</kbd> تازه کردن · تایپ حروف = پرش به نام</div>`;
  $$("[data-xc]").forEach((el) => (el.onclick = (e) => { if (e.target.closest("[data-xclose]")) return; XF.cur = XF.conns.find((c) => c.id === el.dataset.xc); XF.rsel.clear(); xfRenderFiles(); }));
  $$("[data-xclose]").forEach((b) => (b.onclick = async () => { await api("xfer_close", b.dataset.xclose); if (XF.cur && XF.cur.id === b.dataset.xclose) XF.cur = null; sshXfer(); }));
  $("#xfNew").onclick = () => xfConnectDlg();
  xfRenderLocal(); xfRenderRemote();
}

function xfSorted(items) {
  const { k, d } = XF.sort;
  return [...items].sort((a, b) => (b.dir - a.dir) || (k === "name" ? a.name.localeCompare(b.name, "en", { numeric: true }) : (a[k] || 0) - (b[k] || 0)) * d);
}
function xfTable(items, side, sel) {
  const head = [["name", "نام"], ["size", "حجم"], ["mtime", "تغییر"]].map(([k, t]) => `<th data-xs="${k}" class="nosort">${t}${XF.sort.k === k ? (XF.sort.d > 0 ? " ▲" : " ▼") : ""}</th>`).join("");
  return `<table class="xf-list"><thead><tr>${head}</tr></thead><tbody>${items.length ? xfSorted(items).map((it) => `<tr data-n="${esc(it.name)}" data-dir="${it.dir ? 1 : 0}" draggable="${XF.desktop || side === "r" ? "true" : "false"}" class="${sel.has(it.name) ? "sel" : ""}${XF.kc[side] === it.name ? " kcur" : ""}">
      <td class="ltr nm"><span class="fi ${it.dir ? "d" : "f"}"></span>${esc(it.name)}</td><td class="ltr num">${it.dir ? "" : fsize(it.size)}</td><td class="ltr muted">${it.mtime ? fmtDate(it.mtime) : esc(it.when || "")}</td></tr>`).join("")
    : `<tr><td colspan="3"><div class="empty">پوشه خالی است.</div></td></tr>`}</tbody></table>`;
}
function xfBindList(box, side) {
  const sel = side === "l" ? XF.local.sel : XF.rsel;
  $$("th[data-xs]", box).forEach((th) => (th.onclick = () => { const k = th.dataset.xs; XF.sort = { k, d: XF.sort.k === k ? -XF.sort.d : 1 }; side === "l" ? xfRenderLocal() : xfRenderRemote(); }));
  let last = null;
  $$("tbody tr[data-n]", box).forEach((tr) => {
    tr.onclick = (e) => {
      const n = tr.dataset.n;
      if (e.shiftKey && last) {
        const rows = $$("tbody tr[data-n]", box), a = rows.indexOf(last), b = rows.indexOf(tr);
        rows.slice(Math.min(a, b), Math.max(a, b) + 1).forEach((r) => sel.add(r.dataset.n));
      } else if (e.ctrlKey || e.metaKey) { sel.has(n) ? sel.delete(n) : sel.add(n); last = tr; }
      else { sel.clear(); sel.add(n); last = tr; }
      XF.kc[side] = n; if (!e.shiftKey) XF.ka[side] = n;
      $$("tbody tr[data-n]", box).forEach((r) => { r.classList.toggle("sel", sel.has(r.dataset.n)); r.classList.toggle("kcur", r === tr); });
      xfButtons();
    };
    tr.ondblclick = () => {
      if (tr.dataset.dir === "1") { side === "l" ? xfLocalGo(xfJoinL(tr.dataset.n)) : xfRemoteGo(xfJoinR(tr.dataset.n)); }
      else if (side === "r") { const it = (XF.cur.items || []).find((i) => i.name === tr.dataset.n); if (it && teIsText(it)) xfEdit(it.name); else xfDownload([tr.dataset.n]); }
      else if (XF.cur) xfUploadLocal([tr.dataset.n]);
    };
    tr.ondragstart = (e) => {
      if (!sel.has(tr.dataset.n)) { sel.clear(); sel.add(tr.dataset.n); }
      e.dataTransfer.setData("application/x-akrp-" + side, JSON.stringify([...sel]));
      e.dataTransfer.effectAllowed = "copy";
    };
  });
}
function xfJoinL(n) { const c = XF.local.cwd; if (!c) return n; const sep = XF.local.sep || "/"; return c.endsWith(sep) ? c + n : c + sep + n; }
function xfJoinR(n) { const c = (XF.cur && XF.cur.cwd) || "/"; return c.endsWith("/") ? c + n : c + "/" + n; }
function xfButtons() {
  const b = (id, on) => { const e = $("#" + id); if (e) e.disabled = !on; };
  const rfiles = XF.cur && XF.cur.items ? XF.cur.items.filter((i) => XF.rsel.has(i.name)) : [];
  b("xrDown", rfiles.some((i) => !i.dir)); b("xrDel", rfiles.length); b("xrRen", rfiles.length === 1); b("xrEdit", rfiles.length === 1 && !rfiles[0].dir);
  const lf = XF.local.items.filter((i) => XF.local.sel.has(i.name) && !i.dir);
  b("xlUp", lf.length && XF.cur);
}

/* --- پنل محلی --- */
async function xfRenderLocal() {
  const box = $("#xfLocal"); if (!box) return;
  if (!XF.desktop) {
    box.innerHTML = `<div class="xf-head"><b>این مرورگر</b></div>
      <div class="xf-drop" id="xfDrop"><svg><use href="#i-folder"/></svg><div>فایل‌ها را اینجا یا روی پنل دستگاه بکشید و رها کنید</div>
        <button class="btn sm" id="xfPick">انتخاب فایل…</button><input type="file" id="xfFile" multiple hidden></div>
      <p class="hint">برای دانلود، روی فایل دستگاه دوبار کلیک کنید یا «دانلود» را بزنید؛ فایل مستقیم از دستگاه به مرورگر می‌آید و روی سرور نمی‌ماند.</p>`;
    $("#xfPick").onclick = () => $("#xfFile").click();
    $("#xfFile").onchange = (e) => { xfUploadFiles([...e.target.files]); e.target.value = ""; };
    xfDropZone($("#xfDrop"));
    return;
  }
  if (!XF.local.loaded) { XF.local.loaded = true; await xfLocalGo(""); return; }
  const L = XF.local;
  box.innerHTML = `<div class="xf-head"><b>این کامپیوتر</b><div class="xf-path"><button class="iconbtn" id="xlUpDir" title="پوشه‌ی بالاتر">↑</button><button class="iconbtn" id="xlHome" title="پوشه‌ی کاربر">⌂</button>
      <input class="ltr" id="xlPath" value="${esc(L.cwd)}" placeholder="${navigator.platform.startsWith("Win") ? "درایوها" : "/"}"><button class="iconbtn" id="xlRef" title="تازه کردن">⟳</button></div></div>
    <div class="xf-act"><button class="btn sm" id="xlUp" disabled>آپلود به دستگاه</button></div>
    <div class="xf-scroll" id="xlList">${xfTable(L.items, "l", L.sel)}</div>`;
  $("#xlUpDir").onclick = () => xfLocalGo(L.parent ?? "");
  $("#xlHome").onclick = () => xfLocalGo(L.home || "");
  $("#xlRef").onclick = () => xfLocalGo(L.cwd);
  $("#xlPath").onkeydown = (e) => { if (e.key === "Enter") xfLocalGo(e.target.value.trim()); };
  $("#xlUp").onclick = () => xfUploadLocal([...L.sel]);
  xfBindList($("#xlList"), "l");
  const lst = $("#xlList");
  lst.ondragover = (e) => { if (e.dataTransfer.types.includes("application/x-akrp-r")) { e.preventDefault(); xfDropMark(lst, e); } };
  lst.ondragleave = (e) => { if (!lst.contains(e.relatedTarget)) xfDropMark(lst, null); };
  lst.ondrop = (e) => {
    const row = xfDropRow(lst, e); xfDropMark(lst, null);
    const d = e.dataTransfer.getData("application/x-akrp-r");
    if (d) { e.preventDefault(); xfDownload(JSON.parse(d), false, row ? xfJoinL(row.dataset.n) : null); }   // روی ردیف پوشه ← داخل همان پوشه
  };
  xfButtons();
}
async function xfLocalGo(p) {
  const r = await api("local_ls", p);
  if (!r.ok) return toast(r.error, "error");
  if (r.cwd !== XF.local.cwd) XF.kc.l = XF.ka.l = null;
  Object.assign(XF.local, { cwd: r.cwd, items: r.items, parent: r.parent, home: r.home || XF.local.home, sep: r.sep || XF.local.sep });
  XF.local.sel.clear(); xfRenderLocal();
  return true;
}
async function xfUploadLocal(names, destDir) {
  if (!XF.cur) return toast("ابتدا به دستگاه وصل شوید", "warn");
  const files = XF.local.items.filter((i) => names.includes(i.name) && !i.dir).map((i) => xfJoinL(i.name));
  if (!files.length) return toast("فقط فایل قابل انتقال است (پوشه نه)", "warn");
  const dest = destDir || (XF.cur.browse ? XF.cur.cwd : await xfScpDest());
  if (dest == null) return;
  let r = await api("xfer_local", XF.cur.id, "up", files, dest, false);
  if (r.ok && r.exists) { if (!(await xfOverwrite(r.remote))) return; r = await api("xfer_local", XF.cur.id, "up", files, dest, true); }
  if (!r.ok) return toast(r.error, "error");
  xfPollJobs(true);
}

/* --- پنل دستگاه --- */
function xfRenderRemote() {
  const box = $("#xfRemote"); if (!box) return;
  const c = XF.cur;
  if (!c) { box.innerHTML = `<div class="empty">به دستگاهی وصل نیستید. «اتصال تازه» را بزنید (SFTP، SCP، FTP یا FTPS).</div>`; return; }
  if (!c.browse) {
    box.innerHTML = `<div class="xf-head"><b class="ltr">${esc(c.user)}@${esc(c.host)}</b> <span class="tag info">SCP</span></div>
      <p class="hint">SCP فهرست پوشه ندارد. برای دانلود مسیر کامل فایل را بنویسید (مثلاً <span class="ltr">/var/log/syslog</span> یا <span class="ltr">flash:config.text</span>). برای آپلود فایل‌ها را اینجا بکشید؛ مقصد پرسیده می‌شود.</p>
      <div class="row"><input id="xsPath" class="ltr" placeholder="/path/to/file" style="flex:1"><button class="btn primary" id="xsGet">دانلود</button></div>
      <div class="xf-drop" id="xfDropR" style="margin-top:12px"><div>فایل‌ها را برای آپلود اینجا رها کنید</div></div>`;
    $("#xsGet").onclick = () => { const p = $("#xsPath").value.trim(); if (p) xfDownload([p], true); };
    xfDropZone($("#xfDropR"));
    return;
  }
  box.innerHTML = `<div class="xf-head"><b class="ltr">${esc(c.user)}@${esc(c.host)}</b> <span class="tag info">${c.proto.toUpperCase()}</span>
      <div class="xf-path"><button class="iconbtn" id="xrUpDir" title="پوشه‌ی بالاتر">↑</button><button class="iconbtn" id="xrHome" title="پوشه‌ی خانه">⌂</button>
      <input class="ltr" id="xrPath" value="${esc(c.cwd || c.home)}"><button class="iconbtn" id="xrRef" title="تازه کردن">⟳</button></div></div>
    <div class="xf-act"><button class="btn sm" id="xrDown" disabled>${XF.desktop ? "دانلود به این کامپیوتر" : "دانلود"}</button><button class="btn sm ghost" id="xrEdit" disabled title="باز کردن فایل متنی در ویرایشگر (دوبار کلیک روی فایل متنی)">ویرایش</button><button class="btn sm ghost" id="xrMk">پوشه‌ی تازه</button>
      <button class="btn sm ghost" id="xrRen" disabled>تغییر نام</button><button class="btn sm danger-ghost" id="xrDel" disabled>حذف</button>
      ${XF.desktop ? "" : `<button class="btn sm" id="xrUpB">آپلود…</button><input type="file" id="xrFile" multiple hidden>`}</div>
    <div class="xf-scroll" id="xrList">${c.items ? xfTable(c.items, "r", XF.rsel) : `<div class="empty">در حال خواندن…</div>`}</div>`;
  $("#xrUpDir").onclick = xfRemoteUp;
  $("#xrHome").onclick = () => xfRemoteGo(c.home);
  $("#xrRef").onclick = () => xfRemoteGo(c.cwd);
  $("#xrPath").onkeydown = (e) => { if (e.key === "Enter") xfRemoteGo(e.target.value.trim()); };
  $("#xrDown").onclick = () => xfDownload([...XF.rsel]);
  $("#xrEdit").onclick = () => xfEdit();
  $("#xrMk").onclick = xfMkdir; $("#xrRen").onclick = xfRename; $("#xrDel").onclick = xfDelete;
  if ($("#xrUpB")) { $("#xrUpB").onclick = () => $("#xrFile").click(); $("#xrFile").onchange = (e) => { xfUploadFiles([...e.target.files]); e.target.value = ""; }; }
  if (c.items) xfBindList($("#xrList"), "r"); else xfRemoteGo(c.cwd || c.home);
  const lst = $("#xrList");
  xfDropZone(lst, (e, row) => {
    const dest = row ? xfJoinR(row.dataset.n) : null;          // روی ردیف پوشه ← داخل همان پوشه؛ جای خالی ← پوشه‌ی باز
    const d = e.dataTransfer.getData("application/x-akrp-l");
    if (d) { xfUploadLocal(JSON.parse(d), dest); return true; }
    const files = [...(e.dataTransfer.files || [])];
    if (files.length) { xfUploadFiles(files, false, dest); return true; }
    return false;
  });
  xfButtons();
}
function xfRemoteUp() {
  const c = XF.cur; if (!c) return;
  const p = (c.cwd || "/").replace(/\/+$/, "");
  if (!p || p === "/") return;
  const base = p.slice(p.lastIndexOf("/") + 1);
  return xfRemoteGo(p.lastIndexOf("/") > 0 ? p.slice(0, p.lastIndexOf("/")) : "/").then((ok) => { if (ok && base) { XF.kc.r = XF.ka.r = base; xfRenderRemote(); } });
}
async function xfRemoteGo(p) {
  const c = XF.cur; if (!c) return;
  const r = await api("xfer_ls", c.id, p || c.home);
  if (!r.ok) { toast(r.error, "error"); if (!c.items) { c.items = []; c.cwd = c.home; xfRenderRemote(); } return; }
  if (r.cwd !== c.cwd) XF.kc.r = XF.ka.r = null;
  c.cwd = r.cwd; c.items = r.items; XF.rsel.clear(); xfRenderRemote();
  return true;
}
function xfDropRow(el, e) {
  const tr = e && e.target && e.target.closest ? e.target.closest("tr[data-dir='1']") : null;
  return tr && el.contains(tr) ? tr : null;
}
function xfDropMark(el, e) {
  const row = e ? xfDropRow(el, e) : null;
  el.classList.toggle("over", !!e && !row);
  $$("tr.drop", el).forEach((r) => r !== row && r.classList.remove("drop"));
  if (row) row.classList.add("drop");
}
function xfDropZone(el, custom) {
  if (!el) return;
  el.addEventListener("dragover", (e) => { if ([...e.dataTransfer.types].some((t) => t === "Files" || t.startsWith("application/x-akrp-l"))) { e.preventDefault(); xfDropMark(el, e); } });
  el.addEventListener("dragleave", (e) => { if (!el.contains(e.relatedTarget)) xfDropMark(el, null); });
  el.addEventListener("drop", (e) => {
    const row = xfDropRow(el, e); xfDropMark(el, null); e.preventDefault();
    if (custom && custom(e, row)) return;
    const files = [...(e.dataTransfer.files || [])];
    if (files.length) xfUploadFiles(files);
  });
}
async function xfScpDest() {
  const v = await openModal({ title: "مقصد روی دستگاه (SCP)",
    body: `<label class="field"><span>پوشه یا مسیر مقصد</span><input id="xsDest" class="ltr" value="${esc(XF.scpDest || "/tmp/")}" autofocus></label><p class="hint">مثلاً <span class="ltr">/tmp/</span> یا <span class="ltr">flash:</span> — نام فایل خودکار اضافه می‌شود.</p>`,
    foot: `<button class="btn ghost" data-r="0">انصراف</button><button class="btn primary" data-r="1">ادامه</button>`,
    onOpen: (m, close) => { $("[data-r='0']", m).onclick = () => close(null); $("[data-r='1']", m).onclick = () => close($("#xsDest", m).value.trim()); } });
  if (v) XF.scpDest = v;
  return v || null;
}
async function xfOverwrite(name) {
  return confirm2({ title: "فایل وجود دارد", body: `<p><span class="ltr">${esc(name)}</span> از قبل وجود دارد. جایگزین شود؟</p>`, confirm: "جایگزین کن", danger: true });
}

/* --- آپلود تکه‌ای از مرورگر/پنجره (فایل‌های کشیده‌شده یا انتخاب‌شده) --- */
const XCHUNK = 4 * 1024 * 1024;
async function xfUploadFiles(files, toTftp = false, destDir = null, overwrite = false) {
  if (!toTftp && !XF.cur) return toast("ابتدا به دستگاه وصل شوید", "warn");
  const big = XF.limit ? files.filter((f) => f.size > XF.limit) : [];
  if (big.length) toast(`${big.length} فایل بیشتر از سقف حجم (${XF.limitH}) است و ارسال نمی‌شود`, "error");
  files = files.filter((f) => !big.includes(f));
  if (!files.length) return;
  let dest = "";
  if (!toTftp) dest = destDir != null ? destDir : XF.cur.browse ? XF.cur.cwd : await xfScpDest();
  if (dest == null) return;
  const cid = toTftp ? "tftp" : XF.cur.id;
  await xfPutFiles(cid, dest, files, overwrite);
  if (toTftp) tftpRender(); else if (XF.cur && XF.cur.browse) xfRemoteGo(XF.cur.cwd);
}
async function xfPutFiles(cid, dest, files, overwrite) {
  for (const f of files) {
    let r = await api("xfer_put_begin", cid, dest, f.name, f.size, overwrite);
    if (r.ok && r.exists) { if (!(await xfOverwrite(r.remote))) continue; r = await api("xfer_put_begin", cid, dest, f.name, f.size, true); }
    if (!r.ok) { toast(`${f.name}: ${r.error}`, "error"); continue; }
    const jid = r.job.id; XF.files.set(jid, { file: f, cid, dest }); xfPollJobs(true);
    for (let off = 0; off < f.size; off += XCHUNK) {
      const b64 = await blobB64(f.slice(off, off + XCHUNK));
      const w = await api("xfer_put", jid, off, b64);
      if (!w.ok) { toast(`${f.name}: ${w.error}`, "error"); break; }
      xfJobUpdate(w.job);
    }
  }
  xfPollJobs(true);
}
async function xfDownload(names, raw = false, localDir = null) {
  const c = XF.cur; if (!c) return;
  const paths = raw ? names : (c.items || []).filter((i) => names.includes(i.name) && !i.dir).map((i) => xfJoinR(i.name));
  if (!paths.length) return toast("فقط فایل قابل دانلود است (پوشه نه)", "warn");
  if (XF.desktop) {
    const to = localDir || XF.local.cwd;
    if (!to) return toast("در پنل «این کامپیوتر» یک پوشه باز کنید", "warn");
    let r = await api("xfer_local", c.id, "down", paths, to, false);
    if (r.ok && r.exists) { if (!(await xfOverwrite(r.local))) return; r = await api("xfer_local", c.id, "down", paths, to, true); }
    if (!r.ok) return toast(r.error, "error");
    xfPollJobs(true);
    return;
  }
  for (const p of paths) {
    const r = await api("xfer_get", c.id, p);
    if (!r.ok) { toast(r.error, "error"); continue; }
    webDownload(r.url, p.split(/[/:]/).pop());
    await new Promise((res) => setTimeout(res, 400));
  }
  xfPollJobs(true);
}
async function xfMkdir() {
  const v = await openModal({ title: "پوشه‌ی تازه", body: `<label class="field"><span>نام</span><input id="xmN" class="ltr" autofocus></label>`,
    foot: `<button class="btn ghost" data-r="0">انصراف</button><button class="btn primary" data-r="1">ساختن</button>`,
    onOpen: (m, close) => { $("[data-r='0']", m).onclick = () => close(null); $("[data-r='1']", m).onclick = () => close($("#xmN", m).value.trim()); } });
  if (!v) return;
  const r = await api("xfer_mkdir", XF.cur.id, xfJoinR(v)); if (!r.ok) return toast(r.error, "error");
  xfRemoteGo(XF.cur.cwd);
}
async function xfRename() {
  const old = [...XF.rsel][0]; if (!old) return;
  const v = await openModal({ title: "تغییر نام", body: `<label class="field"><span>نام تازه</span><input id="xrN" class="ltr" value="${esc(old)}" autofocus></label>`,
    foot: `<button class="btn ghost" data-r="0">انصراف</button><button class="btn primary" data-r="1">ذخیره</button>`,
    onOpen: (m, close) => { $("[data-r='0']", m).onclick = () => close(null); $("[data-r='1']", m).onclick = () => close($("#xrN", m).value.trim()); } });
  if (!v || v === old) return;
  const r = await api("xfer_rename", XF.cur.id, xfJoinR(old), xfJoinR(v)); if (!r.ok) return toast(r.error, "error");
  xfRemoteGo(XF.cur.cwd);
}
async function xfDelete() {
  const items = (XF.cur.items || []).filter((i) => XF.rsel.has(i.name));
  if (!items.length) return;
  if (!(await confirm2({ title: "حذف روی دستگاه", danger: true, confirm: "حذف",
    body: `<p>${num(items.length)} مورد از دستگاه حذف شود؟ این کار برگشت ندارد. (پوشه فقط اگر خالی باشد حذف می‌شود.)</p><pre class="ltr paste-prev" data-no-i18n>${esc(items.map((i) => i.name + (i.dir ? "/" : "")).join("\n"))}</pre>` }))) return;
  const r = await api("xfer_delete", XF.cur.id, items.map((i) => ({ path: xfJoinR(i.name), dir: i.dir })));
  if (!r.ok) toast(r.error, "error");
  xfRemoteGo(XF.cur.cwd);
}
async function xfConnectDlg(preset) {
  const devs = SSH.devices.filter((d) => d.has_password && d.username);
  const p = preset || {};
  const res = await openModal({
    title: "اتصال انتقال فایل",
    body: `<div class="row" style="gap:10px;margin-bottom:12px;flex-wrap:wrap"><div class="seg" id="xcProto">${["sftp", "scp", "ftp", "ftps"].map((x) => `<button data-v="${x}" class="${(p.proto || "sftp") === x ? "on" : ""}">${x.toUpperCase()}</button>`).join("")}</div>
      <div class="seg" id="xcMode"><button data-v="dev" class="${p.adhoc ? "" : "on"}">دستگاه ذخیره‌شده</button><button data-v="adhoc" class="${p.adhoc ? "on" : ""}">اتصال موقت</button></div></div>
      <div id="xcDev" ${p.adhoc ? "hidden" : ""}>${devs.length ? `<label class="field"><span>دستگاه</span><select id="xcDevSel">${devs.map((d) => `<option value="${d.id}">${esc(d.name)} — ${esc(d.host)}${d.personal ? " (شخصی)" : ""}</option>`).join("")}</select></label>` : `<div class="empty">دستگاهی با یوزر و رمز ذخیره‌شده ندارید؛ از «اتصال موقت» استفاده کنید.</div>`}</div>
      <div id="xcAd" ${p.adhoc ? "" : "hidden"}><div class="form-grid">
        <label class="field"><span>آدرس</span><input id="xcHost" class="ltr" placeholder="10.0.0.1"></label>
        <label class="field"><span>یوزر</span><input id="xcUser" class="ltr" autocomplete="off"></label>
        <label class="field"><span>رمز</span><input id="xcPass" type="password" class="ltr" autocomplete="off"></label>
        <label class="chk" style="align-self:end"><input type="checkbox" id="xcLegacy">الگوریتم‌های قدیمی SSH</label></div></div>
      <div class="form-grid" style="margin-top:10px"><label class="field"><span>پورت (خالی = پیش‌فرض)</span><input id="xcPort" class="ltr" placeholder="SFTP/SCP: 22 · FTP: 21"></label>
        <label class="chk" style="align-self:end" id="xcActW" hidden><input type="checkbox" id="xcActive">FTP فعال (Active)</label></div>
      <p class="hint" id="xcHint"></p>`,
    foot: `<button class="btn ghost" data-r="0">انصراف</button><button class="btn primary" data-r="1">اتصال</button>`,
    onOpen: (m, close) => {
      const proto = () => $("#xcProto button.on", m).dataset.v;
      const hint = () => {
        const pr = proto();
        $("#xcActW", m).hidden = !pr.startsWith("ftp");
        $("#xcHint", m).textContent = { sftp: "SFTP: مرور پوشه‌ها، آپلود، دانلود، ساخت پوشه، تغییر نام و حذف.", scp: "SCP: برای تجهیزاتی که SFTP ندارند (مثل بعضی روترها)؛ فقط آپلود و دانلود با مسیر کامل.",
          ftp: "FTP: رمز و داده بدون رمزنگاری در شبکه می‌روند؛ فقط در شبکه‌ی امن استفاده کنید.", ftps: "FTPS: FTP با TLS صریح." }[pr];
      };
      $$("#xcProto button", m).forEach((b) => (b.onclick = () => { $$("#xcProto button", m).forEach((x) => x.classList.toggle("on", x === b)); hint(); }));
      $$("#xcMode button", m).forEach((b) => (b.onclick = () => { $$("#xcMode button", m).forEach((x) => x.classList.toggle("on", x === b)); $("#xcDev", m).hidden = b.dataset.v !== "dev"; $("#xcAd", m).hidden = b.dataset.v === "dev"; }));
      hint();
      $("[data-r='0']", m).onclick = () => close(null);
      $("[data-r='1']", m).onclick = () => {
        const opts = { port: $("#xcPort", m).value.trim(), active: $("#xcActive", m).checked };
        if (!$("#xcAd", m).hidden) {
          const host = $("#xcHost", m).value.trim(); if (!host) return toast("آدرس را وارد کنید", "error");
          close({ proto: proto(), opts, target: { adhoc: { host, port: Number(opts.port) || 22, username: $("#xcUser", m).value.trim(), password: $("#xcPass", m).value, legacy: $("#xcLegacy", m).checked } } });
        } else { const s = $("#xcDevSel", m); if (!s) return; close({ proto: proto(), opts, target: { device_id: Number(s.value) } }); }
      };
    },
  });
  if (res) await xfOpen(res);
}
async function xfOpen(o, accept) {
  const r = await connTry($("#xfNew"), `${o.proto.toUpperCase()} ${connLabel(o.target)}`, (aid) => api("xfer_open", o.target, o.proto, accept || null, o.opts, aid));
  if (!r.ok) return toast(r.error, r.cancelled ? "warn" : "error");
  if (r.confirm) { if (await hostKeyConfirm(r.confirm)) return xfOpen(o, r.confirm.fingerprint); return; }
  XF.conns.push(r.conn); XF.cur = r.conn; XF.rsel.clear(); xfRenderFiles();
}

/* --- صف انتقال‌ها --- */
function xfJobUpdate(j) { const i = XF.jobs.findIndex((x) => x.id === j.id); if (i >= 0) XF.jobs[i] = j; else XF.jobs.unshift(j); xfRenderJobs(); }
const XJ_ST = { running: ["info", "در حال انتقال"], queued: ["mute", "در صف"], waiting: ["mute", "در انتظار"], ok: ["ok", "کامل"], error: ["err", "خطا"], cancelled: ["mute", "لغو شد"] };
function xfRenderJobs() {
  const box = $("#xfJobs"); if (!box) return;
  if (!XF.jobs.length) { box.innerHTML = `<div class="empty">انتقالی نیست.</div>`; return; }
  box.innerHTML = `<table class="grid"><thead><tr><th>جهت</th><th>فایل</th><th>دستگاه</th><th>پیشرفت</th><th>سرعت</th><th>وضعیت</th><th class="nosort"></th></tr></thead><tbody>${XF.jobs.map((j) => {
    const st = XJ_ST[j.state] || ["mute", j.state], pct = j.size ? Math.min(100, Math.round((j.done / j.size) * 100)) : (j.state === "ok" ? 100 : 0);
    return `<tr><td>${j.dir === "up" ? "↑ آپلود" : j.dir === "stage" ? "↑ TFTP" : "↓ دانلود"}</td><td class="ltr wrap">${esc(j.remote || j.name)}</td><td class="ltr">${esc(j.proto.toUpperCase())} ${esc(j.host)}</td>
      <td><div class="xf-prog"><span style="width:${pct}%"></span></div><small class="muted ltr">${fsize(j.done)}${j.size != null ? " / " + fsize(j.size) : ""}</small></td>
      <td class="ltr">${j.state === "running" ? fsize(j.speed) + "/s" : ""}</td><td><span class="tag ${st[0]}">${st[1]}</span>${j.error ? `<div class="muted wrap">${esc(j.error)}</div>` : ""}</td>
      <td>${["running", "waiting", "queued"].includes(j.state) ? `<button class="btn sm ghost" data-xjc="${j.id}">لغو</button>`
        : ["error", "cancelled"].includes(j.state) && xfCanRetry(j) ? `<button class="btn sm" data-xjr="${j.id}">تلاش مجدد</button>` : ""}</td></tr>`; }).join("")}</tbody></table>`;
  $$("[data-xjc]", box).forEach((b) => (b.onclick = () => api("xfer_cancel", b.dataset.xjc).then(() => xfPollJobs(true))));
  $$("[data-xjr]", box).forEach((b) => (b.onclick = () => withSpin(b, () => xfRetry(XF.jobs.find((x) => x.id === b.dataset.xjr)))));
}
const xfDirOf = (p, seps) => { const i = Math.max(...seps.map((x) => String(p).lastIndexOf(x))); return i >= 0 ? String(p).slice(0, i + 1) : ""; };
function xfCanRetry(j) {
  if (j.dir === "stage") return XF.files.has(j.id);
  if (!j.local && j.dir === "up") return XF.files.has(j.id);          // آپلود از مرورگر: فایل باید هنوز در این صفحه باشد
  return true;
}
/* همان انتقال دوباره، با همان مبدأ و مقصد (فایل نیمه‌کاره جایگزین می‌شود) */
async function xfRetry(j) {
  if (!j) return;
  if (j.dir !== "stage" && !XF.conns.some((c) => c.id === j.conn)) return toast("اتصال این انتقال بسته شده است؛ دوباره وصل شوید و انتقال را از نو شروع کنید", "warn");
  let r = { ok: true };
  if (j.local) {
    r = j.dir === "up" ? await api("xfer_local", j.conn, "up", [j.local], xfDirOf(j.remote, ["/", ":"]), true)
      : await api("xfer_local", j.conn, "down", [j.remote], xfDirOf(j.local, ["/", "\\"]), true);
  } else if (j.dir === "down") {
    r = await api("xfer_get", j.conn, j.remote);
    if (r.ok) webDownload(r.url, j.name);
  } else {
    const x = XF.files.get(j.id);
    if (!x) return toast("فایل اصلی دیگر در دسترس نیست؛ دوباره انتخاب کنید", "warn");
    XF.files.delete(j.id);
    await xfPutFiles(x.cid, x.dest, [x.file], true);
  }
  if (!r.ok) return toast(r.error, "error");
  await api("xfer_clear_one", j.id);
  xfPollJobs(true);
}
async function xfPollJobs(once) {
  if (!axOk("term.xfer")) return;
  const r = await api("xfer_jobs");
  if (r.ok) {
    const before = XF.jobs.filter((j) => j.state === "running" || j.state === "queued").map((j) => j.id);
    XF.jobs = r.jobs; xfRenderJobs();
    const finished = before.filter((id) => { const j = XF.jobs.find((x) => x.id === id); return j && j.state !== "running" && j.state !== "queued"; });
    if (finished.length && XF.desktop && XF.local.loaded && $("#xfLocal")) xfLocalGo(XF.local.cwd);
    if (finished.length && XF.cur && XF.cur.browse && $("#xrList")) xfRemoteGo(XF.cur.cwd);
  }
  if (XF.polling) return;
  if (XF.jobs.some((j) => ["running", "waiting", "queued"].includes(j.state)) && SSH.tab === "xfer" && S.page === "ssh") {
    XF.polling = true; setTimeout(() => { XF.polling = false; xfPollJobs(); }, 1000);
  }
}

/* --- سرور TFTP --- */
async function tftpRender() {
  const r = await api("tftp_status"); if (!r.ok) return toast(r.error, "error");
  XF.tftp = r;
  const box = $("#xfMain"); if (!box) return;
  if (r.running && r.other) { box.innerHTML = `<div class="panel"><div class="empty">سرور TFTP الان توسط کاربر «${esc(r.other)}» روشن است. (هم‌زمان فقط یک سرور TFTP روی این سیستم ممکن است.)</div></div>`; return; }
  if (!r.running) {
    const devs = SSH.devices;
    box.innerHTML = `<div class="panel"><div class="panel-head"><h3>سرور TFTP موقت</h3></div>
      <p class="hint">برای تجهیزاتی که فقط TFTP دارند (کپی کانفیگ، فریم‌ور). سرور فقط به IP دستگاه‌های انتخاب‌شده جواب می‌دهد و پس از ۳۰ دقیقه بی‌کاری خودکار خاموش می‌شود.</p>
      <div class="form-grid"><div class="field wide"><span>دستگاه‌های مجاز</span><div class="chks" style="max-height:160px;overflow:auto">${devs.length ? devs.map((d) => `<label class="chk"><input type="checkbox" class="tfDev" value="${d.id}" ${XF.tftpSel.has(d.id) ? "checked" : ""}>${esc(d.name)} <small class="muted ltr">${esc(d.host)}</small></label>`).join("") : `<span class="muted">دستگاهی تعریف نشده است.</span>`}</div></div>
        <label class="field"><span>IPهای دیگر (اختیاری، با کاما)</span><input id="tfHosts" class="ltr" placeholder="10.0.0.5, 10.0.0.6"></label>
        <label class="field"><span>پورت UDP</span><input id="tfPort" class="ltr" value="69"></label>
        <label class="chk" style="align-self:end"><input type="checkbox" id="tfWrite" checked>اجازه‌ی دریافت فایل از دستگاه (مثلاً پشتیبان کانفیگ)</label></div>
      <div style="margin-top:12px"><button class="btn primary" id="tfStart">روشن کردن سرور</button></div></div>`;
    $("#tfStart").onclick = (e) => withSpin(e.currentTarget, async () => {
      const ids = $$(".tfDev:checked").map((x) => Number(x.value)); XF.tftpSel = new Set(ids);
      const hosts = $("#tfHosts").value.split(/[,\s]+/).filter(Boolean);
      const s = await api("tftp_start", ids, hosts, Number($("#tfPort").value) || 69, $("#tfWrite").checked);
      if (!s.ok) return toast(s.error, "error");
      tftpRender(); xfPollJobs(true);
    });
    return;
  }
  const cmds = r.commands || {};
  box.innerHTML = `<div class="panel"><div class="panel-head"><h3>سرور TFTP <span class="tag ok">روشن</span></h3><button class="btn danger-ghost sm" id="tfStop">خاموش کردن</button></div>
    <div class="kv-row"><span>آدرس این سیستم (به سمت دستگاه):</span> <b class="ltr">${esc(r.local_ip || "—")}</b> · <span>پورت:</span> <b class="ltr">${r.port}</b> · <span>مجاز:</span> <span class="ltr">${esc(r.allowed.join(", "))}</span> · ${r.write ? `<span class="tag info">دریافت فعال</span>` : `<span class="tag mute">فقط ارسال</span>`}</div>
    <div class="xf-panes" style="margin-top:12px"><div class="xf-pane"><div class="xf-head"><b>فایل‌های قابل دریافت توسط دستگاه</b>${XF.desktop ? `<button class="btn sm" id="tfAddL">افزودن از پنل محلی…</button>` : ""}</div>
      <div class="xf-drop" id="tfDrop"><div>فایل (مثلاً فریم‌ور) را اینجا رها کنید</div><button class="btn sm" id="tfPick">انتخاب فایل…</button><input type="file" id="tfFile" multiple hidden></div>
      <table class="grid"><tbody>${r.files.length ? r.files.map((f) => `<tr><td class="ltr">${esc(f.name)}</td><td class="ltr num">${fsize(f.size)}</td><td><button class="btn sm ghost" data-tfrm="${esc(f.name)}">برداشتن</button></td></tr>`).join("") : `<tr><td><div class="empty">فایلی اضافه نشده است.</div></td></tr>`}</tbody></table></div>
      <div class="xf-pane"><div class="xf-head"><b>فایل‌های دریافتی از دستگاه</b></div>
      <table class="grid"><tbody>${r.received.length ? r.received.slice().reverse().map((f) => `<tr><td class="ltr">${esc(f.name)}</td><td class="ltr">${esc(f.client)}</td><td class="ltr num">${fsize(f.size)}</td><td class="ltr muted">${fmtTime(f.ts)}</td><td><button class="btn sm" data-tfget="${esc(f.id)}">دانلود</button></td></tr>`).join("") : `<tr><td><div class="empty">هنوز فایلی دریافت نشده است.${r.write ? "" : " (دریافت خاموش است)"}</div></td></tr>`}</tbody></table>
      <p class="hint">فایل‌های دریافتی رمزشده نگه داشته می‌شوند و از «تاریخچه» هم قابل دانلودند.</p></div></div></div>
    ${Object.keys(cmds).length ? `<div class="panel"><div class="panel-head"><h3>دستورهای آماده</h3><span class="muted">FILE را با نام فایل عوض کنید</span></div>${Object.entries(cmds).map(([t, list]) => `<div class="tf-cmds"><b>${esc(typeName(t))}</b>${list.map((c) => `<div class="tf-cmd"><code class="ltr" data-no-i18n>${esc(c)}</code><button class="btn sm ghost" data-copy="${esc(c)}">کپی</button></div>`).join("")}</div>`).join("")}</div>` : ""}
    <div class="panel"><div class="panel-head"><h3>رویدادهای TFTP</h3><button class="btn sm ghost" id="tfRef">تازه کردن</button></div>
      <table class="grid"><thead><tr><th>فایل</th><th>دستگاه</th><th>جهت</th><th>حجم</th><th>وضعیت</th></tr></thead><tbody>${r.transfers.length ? r.transfers.slice().reverse().map((t) => `<tr><td class="ltr">${esc(t.file)}</td><td class="ltr">${esc(t.client)}</td><td>${t.dir === "in" ? "↓ دریافت" : "↑ ارسال"}</td><td class="ltr num">${fsize(t.bytes)}</td><td>${t.ok ? `<span class="tag ok">کامل</span>` : t.error ? `<span class="tag err">${esc(t.error)}</span>` : `<span class="tag info">در حال انتقال</span>`}</td></tr>`).join("") : `<tr><td colspan="5"><div class="empty">هنوز انتقالی نبوده است.</div></td></tr>`}</tbody></table></div>`;
  $("#tfStop").onclick = async () => { await api("tftp_stop"); tftpRender(); };
  $("#tfRef").onclick = () => tftpRender();
  $("#tfPick").onclick = () => $("#tfFile").click();
  $("#tfFile").onchange = (e) => { xfUploadFiles([...e.target.files], true); e.target.value = ""; };
  xfDropZone($("#tfDrop"), (e) => { const f = [...(e.dataTransfer.files || [])]; if (f.length) xfUploadFiles(f, true); return true; });
  if ($("#tfAddL")) $("#tfAddL").onclick = tftpAddLocal;
  $$("[data-tfrm]").forEach((b) => (b.onclick = async () => { await api("tftp_remove", b.dataset.tfrm); tftpRender(); }));
  $$("[data-tfget]").forEach((b) => (b.onclick = () => receivedGet(b.dataset.tfget)));
  clearTimeout(XF._tft);
  XF._tft = setTimeout(() => { if (XF.sub === "tftp" && SSH.tab === "xfer" && S.page === "ssh" && !modalClose) tftpRender(); }, 5000);
}
async function receivedGet(rid) {
  const r = await api("tftp_received_get", rid);
  if (!r.ok) return toast(r.error, "error");
  if (r.url) webDownload(r.url, "");
  else if (r.saved) toast("ذخیره شد: " + r.saved, "ok");
}
async function tftpAddLocal() {
  if (!XF.local.loaded) await xfLocalGo("");
  const L = XF.local;
  const pick = await openModal({ title: "افزودن فایل به سرور TFTP", wide: true,
    body: `<div class="xf-path" style="margin-bottom:8px"><input class="ltr" id="taPath" value="${esc(L.cwd)}" style="flex:1"><button class="btn sm" id="taGo">برو</button></div><div class="xf-scroll" style="max-height:360px" id="taList"></div>`,
    foot: `<button class="btn ghost" data-r="0">انصراف</button><button class="btn primary" data-r="1">افزودن انتخاب‌شده‌ها</button>`,
    onOpen: (m, close) => {
      const sel = new Set();
      const draw = () => {
        $("#taList", m).innerHTML = xfTable(XF.local.items, "t", sel);
        $$("tbody tr[data-n]", m).forEach((tr) => {
          tr.onclick = () => { if (tr.dataset.dir === "1") return; sel.has(tr.dataset.n) ? sel.delete(tr.dataset.n) : sel.add(tr.dataset.n); tr.classList.toggle("sel"); };
          tr.ondblclick = async () => { if (tr.dataset.dir === "1") { await xfLocalGo(xfJoinL(tr.dataset.n)); $("#taPath", m).value = XF.local.cwd; sel.clear(); draw(); } };
        });
      };
      draw();
      $("#taGo", m).onclick = async () => { await xfLocalGo($("#taPath", m).value.trim()); sel.clear(); draw(); };
      $("[data-r='0']", m).onclick = () => close(null);
      $("[data-r='1']", m).onclick = () => close([...sel].map(xfJoinL));
    } });
  if (!pick || !pick.length) return;
  const r = await api("tftp_add_local", pick); if (!r.ok) toast(r.error, "error");
  tftpRender();
}

/* ================================================================ نمایش داده‌ی تاریخچه */
/* نمایش داده‌ی یک ردیف تاریخچه با جستجو: CSV در کل فایل (سمت برنامه)، متن و ترمینال خط‌به‌خط */
function hvMark(text, q) {
  if (!q) return esc(text);
  const lo = text.toLowerCase(), ql = q.toLowerCase();
  let out = "", i = 0, k;
  while ((k = lo.indexOf(ql, i)) >= 0) { out += esc(text.slice(i, k)) + "<mark>" + esc(text.slice(k, k + q.length)) + "</mark>"; i = k + q.length; }
  return out + esc(text.slice(i));
}
function hvCsv(r, q) {
  const info = q ? `${num(r.matched)} ردیف از ${num(r.total)} ردیف شامل «${esc(q)}»${r.matched > r.rows.length ? ` — ${num(r.rows.length)} ردیف اول` : ""}`
    : `${num(r.total)} ردیف${r.total > r.rows.length ? ` — ${num(r.rows.length)} ردیف اول نمایش داده شده است` : ""}`;
  return `<div class="muted" style="margin-bottom:6px">${info}</div>
    <div class="table-wrap inner" data-no-i18n><table class="grid"><thead><tr>${r.columns.map((c) => `<th>${esc(c)}</th>`).join("")}</tr></thead><tbody>${r.rows.map((row) => `<tr>${row.map((c) => `<td class="wrap">${hvMark(String(c), q)}</td>`).join("")}</tr>`).join("")}</tbody></table></div>`;
}
function hvLines(text, q) {
  const lines = text.split(/\r?\n/);
  if (!q) return `<pre class="ltr hv-text" data-no-i18n>${esc(text)}</pre>`;
  const ql = q.toLowerCase(), hit = lines.filter((l) => l.toLowerCase().includes(ql));
  return `<div class="muted" style="margin-bottom:6px">${num(hit.length)} خط از ${num(lines.length)} خط شامل «${esc(q)}»</div>
    <pre class="ltr hv-text" data-no-i18n>${hit.length ? hit.map((l) => hvMark(l, q)).join("\n") : esc("—")}</pre>`;
}
async function histView(id, fname) {
  const r = await api("history_view", id, fname || null);
  if (!r.ok) return toast(r.error, "error");
  const files = r.files && r.files.length > 1 ? `<div class="seg" id="hvFiles" style="margin-bottom:10px;flex-wrap:wrap">${r.files.map((f) => `<button data-f="${esc(f)}" class="${f === r.file ? "on" : ""}">${esc(f)}</button>`).join("")}</div>` : "";
  const searchable = ["csv", "text", "term"].includes(r.type);
  const search = searchable ? `<div class="row" style="gap:8px;margin-bottom:8px"><input type="search" class="search" id="hvQ" placeholder="جستجو در ${r.type === "csv" ? "همه‌ی ردیف‌های این فایل" : "متن"}…" style="max-width:360px"><span class="muted" id="hvQs"></span></div>` : "";
  let body = "";
  if (r.type === "csv") body = `${files}${search}<div id="hvBody">${hvCsv(r, "")}</div>`;
  else if (r.type === "text") body = `${files}${search}<div id="hvBody">${hvLines(r.text, "")}</div>`;
  else if (r.type === "term") {
    body = `${search}${r.cut ? `<p class="hint">نشست طولانی بود؛ فقط بخش پایانی نمایش داده می‌شود.</p>` : ""}<div class="hv-term" id="hvTerm" data-no-i18n></div><div id="hvBody" hidden></div>`;
  } else if (r.type === "received") {
    body = `<p>فایل دریافتی (${fsize(r.size)}). فایل رمزشده نگه داشته شده است.</p><button class="btn primary" id="hvGet">دانلود</button>`;
  }
  openModal({ title: r.title || "نمایش", wide: true, body,
    onOpen: async (m) => {
      $$("#hvFiles button", m).forEach((b) => (b.onclick = () => { modalClose(null); histView(id, b.dataset.f); }));
      if ($("#hvGet", m)) $("#hvGet", m).onclick = () => receivedGet(r.rid);
      const qi = $("#hvQ", m);
      if (qi) {
        let tm, seq = 0;
        qi.focus();
        qi.oninput = () => {
          clearTimeout(tm);
          tm = setTimeout(async () => {
            const q = qi.value.trim(), box = $("#hvBody", m); if (!box) return;
            if (r.type === "csv") {
              const my = ++seq; $("#hvQs", m).textContent = q ? "…" : "";
              const x = await api("history_view", id, r.file, q || null);
              if (my !== seq || !$("#hvBody", m)) return;
              $("#hvQs", m).textContent = "";
              box.innerHTML = x.ok ? hvCsv(x, q) : `<div class="empty">${esc(x.error)}</div>`;
            } else if (r.type === "text") box.innerHTML = hvLines(r.text, q);
            else {   // ترمینال: با جستجو، خط‌های پیداشده به‌صورت متن ساده (بدون کد رنگ)
              box.hidden = !q; $("#hvTerm", m).hidden = !!q;
              if (q) box.innerHTML = hvLines(r.text.replace(ESC_RE, "").replace(/\r/g, ""), q);
            }
          }, r.type === "csv" ? 350 : 150);
        };
      }
      if (r.type === "term") {
        try { await loadXterm(); } catch (_) { $("#hvTerm", m).textContent = r.text.replace(ESC_RE, ""); return; }
        const t = new window.Terminal({ fontFamily: 'Consolas, "DejaVu Sans Mono", monospace', fontSize: 13, theme: XTHEME, scrollback: 100000, disableStdin: true, convertEol: false, cols: 140, rows: 32 });
        t.open($("#hvTerm", m));
        const st = { fg: false, pend: "" };
        t.write(TP.highlight ? highlight(st, r.text) : r.text);
        const obs = new MutationObserver(() => { if (!document.body.contains($("#hvTerm") || null) || !$("#hvTerm")) { t.dispose(); obs.disconnect(); } });
        obs.observe($("#modal"), { childList: true });
      }
    } });
}

/* ---------- نوار منابع سرور لینوکس (مثل MobaXterm) ---------- */
const STATS_MS = 3000;
function tsBar(p) { const v = Math.max(0, Math.min(100, Number(p || 0))); return `<span class="ts-bar ${v >= 90 ? "hot" : v >= 75 ? "warm" : ""}"><i style="width:${v}%"></i></span>`; }
function tsSpark(arr) {
  if (!arr || arr.length < 2) return "";
  const w = 60, h = 16, n = arr.length, pts = arr.map((v, i) => `${((i / (n - 1)) * w).toFixed(1)},${(h - (Math.max(0, Math.min(100, v)) / 100) * h).toFixed(1)}`).join(" ");
  return `<svg class="ts-spark" viewBox="0 0 ${w} ${h}" width="${w}" height="${h}"><polyline points="${pts}"/></svg>`;
}
function termStatsActive() {
  const r = $("#termRoot"), t = TERM.tabs.find((x) => x.id === TERM.active);
  if (!TP.stats || !r || r.hidden || S.page !== "ssh" || SSH.tab !== "term" || !t || t.closed || t.noStats) return null;
  return t;
}
function termStatsRender() {
  const el = $("#termStats"); if (!el) return;
  const t = termStatsActive(), st = t && t.st;
  const show = !!(t && st && st.supported);
  if (el.hidden === show) { el.hidden = !show; setTimeout(termFitActive, 30); }
  if (!show) return;
  const m = st.mem || {}, sw = st.swap || {}, dk = st.disk, n = st.net || {};
  const hot = (v) => (v != null && v >= 90 ? " hot" : "");
  el.innerHTML = `<span class="ts${hot(st.cpu)}" title="مصرف CPU — ${st.ncpu || "?"} هسته"><b>CPU</b>${tsBar(st.cpu)}<span class="v">${st.cpu == null ? "…" : st.cpu.toFixed(0) + "%"}</span>${tsSpark(t.cpuHist)}</span>
    ${st.load && st.load.length ? `<span class="ts" title="Load average (۱، ۵ و ۱۵ دقیقه)"><b>Load</b><span class="v">${st.load.map((x) => x.toFixed(2)).join(" ")}</span></span>` : ""}
    <span class="ts${hot(m.pct)}" title="RAM: ${fmtBytes(m.used)} از ${fmtBytes(m.total)}"><b>RAM</b>${tsBar(m.pct)}<span class="v">${fmtBytes(m.used)} / ${fmtBytes(m.total)}</span></span>
    ${sw.total && sw.used ? `<span class="ts${hot(sw.pct)}" title="Swap"><b>Swap</b>${tsBar(sw.pct)}<span class="v">${fmtBytes(sw.used)}</span></span>` : ""}
    ${dk ? `<span class="ts${hot(dk.pct)}" title="${esc((st.disks || []).map((d) => `${d.mount}  ${d.pct}%  ${fmtBytes(d.used)} / ${fmtBytes(d.size)}`).join("\n"))}"><b>Disk</b><span class="v">${esc(dk.mount)}</span>${tsBar(dk.pct)}<span class="v">${dk.pct.toFixed(0)}%  ${fmtBytes(dk.used)} / ${fmtBytes(dk.size)}</span>${(st.disks || []).some((d) => d !== dk && d.pct >= 90) ? `<span class="v hot">⚠</span>` : ""}</span>` : ""}
    <span class="ts" title="${esc((n.ifs || []).map((i) => `${i.name}  ↓ ${fmtBytes(i.rx)}/s  ↑ ${fmtBytes(i.tx)}/s`).join("\n"))}"><b>Net</b><span class="v">↓ ${fmtBytes(n.rx)}/s</span><span class="v">↑ ${fmtBytes(n.tx)}/s</span></span>
    ${st.uptime ? `<span class="ts" title="مدت روشن بودن سرور"><b>Up</b><span class="v">${fmtUp(st.uptime)}</span></span>` : ""}
    ${st.users != null ? `<span class="ts" title="کاربران وارد شده (who)"><b>Users</b><span class="v">${st.users}</span></span>` : ""}`;
}
async function termStatsTick() {
  const t = termStatsActive();
  if (!t || t.statsBusy || document.visibilityState === "hidden") return;
  t.statsBusy = true;
  try {
    const r = await api("term_stats", t.id);
    if (!r.ok) return;
    if (r.supported === false) { t.noStats = true; t.st = null; return; }
    if (r.error) return;            // خطای گذرا؛ آخرین مقدار می‌ماند
    t.st = r;
    if (r.cpu != null) { (t.cpuHist = t.cpuHist || []).push(r.cpu); if (t.cpuHist.length > 40) t.cpuHist.shift(); }
  } finally { t.statsBusy = false; termStatsRender(); }
}
setInterval(termStatsTick, STATS_MS);

/* ================================================================ ویرایشگر متن (1.58) — CodeMirror 5، بارگذاری تنبل */
let _cmReady = null;
function loadCM() {
  if (_cmReady) return _cmReady;
  const add = (tag, attrs) => new Promise((res, rej) => { const e = document.createElement(tag); Object.assign(e, attrs); e.onload = res; e.onerror = () => rej(new Error("load " + (attrs.src || attrs.href))); document.head.appendChild(e); });
  _cmReady = Promise.all([add("link", { rel: "stylesheet", href: "vendor/codemirror.css" }), add("script", { src: "vendor/codemirror.js" })]);
  _cmReady.catch(() => { _cmReady = null; });
  return _cmReady;
}
const TE_TEXT = /\.(txt|log|conf|cfg|cnf|ini|env|properties|ya?ml|json|js|mjs|ts|xml|html?|css|sh|bash|zsh|ksh|py|pl|pm|rb|lua|php|go|c|h|cc|cpp|hpp|java|sql|toml|md|csv|tsv|service|timer|socket|rules|list|repo|pem|crt|key|pub|ps1|psm1|bat|cmd|diff|patch|j2|tmpl|tpl|vhost|lst|out|err)$/i;
const TE_NAMES = /^(dockerfile|makefile|hosts|fstab|crontab|passwd|group|sudoers|resolv\.conf|authorized_keys|known_hosts|\.?bashrc|\.?profile|\.?vimrc|\.gitignore|\.htaccess|readme|license|config|interfaces)$/i;
function teIsText(it) { return !it.dir && (TE_TEXT.test(it.name) || TE_NAMES.test(it.name) || (!/\.[a-z0-9]{1,5}$/i.test(it.name) && (it.size || 0) < 1048576)); }
const TE_MODES = [["", "متن ساده"], ["shell", "Shell"], ["nginx", "nginx"], ["yaml", "YAML"], ["properties", "INI / properties"], ["application/json", "JSON"],
  ["javascript", "JavaScript"], ["xml", "XML"], ["htmlmixed", "HTML"], ["css", "CSS"], ["python", "Python"], ["text/x-sql", "SQL"], ["toml", "TOML"],
  ["dockerfile", "Dockerfile"], ["diff", "Diff"], ["perl", "Perl"], ["lua", "Lua"], ["powershell", "PowerShell"], ["text/x-csrc", "C"], ["text/x-c++src", "C++"],
  ["text/x-java", "Java"], ["go", "Go"], ["php", "PHP"], ["markdown", "Markdown"]];
function teModeFor(name) {
  const n = String(name).toLowerCase(), ext = n.includes(".") ? n.slice(n.lastIndexOf(".") + 1) : "";
  if (/nginx|\.vhost$/.test(n)) return "nginx";
  if (n === "dockerfile" || n.startsWith("dockerfile.")) return "dockerfile";
  const m = { sh: "shell", bash: "shell", zsh: "shell", ksh: "shell", bashrc: "shell", profile: "shell", yml: "yaml", yaml: "yaml", ini: "properties", conf: "properties",
    cfg: "properties", cnf: "properties", env: "properties", properties: "properties", service: "properties", timer: "properties", socket: "properties", repo: "properties",
    json: "application/json", js: "javascript", mjs: "javascript", ts: "javascript", xml: "xml", html: "htmlmixed", htm: "htmlmixed", css: "css", py: "python",
    sql: "text/x-sql", toml: "toml", diff: "diff", patch: "diff", pl: "perl", pm: "perl", lua: "lua", ps1: "powershell", psm1: "powershell", c: "text/x-csrc",
    h: "text/x-csrc", cc: "text/x-c++src", cpp: "text/x-c++src", hpp: "text/x-c++src", java: "text/x-java", go: "go", php: "php", md: "markdown" };
  if (m[ext]) return m[ext];
  if (/^\.?(bashrc|profile|bash_profile|zshrc)$/.test(n)) return "shell";
  return "";
}
async function xfEdit(name) {
  const c = XF.cur; if (!c || !c.browse) return;
  name = name || [...XF.rsel][0]; if (!name) return;
  const path = xfJoinR(name);
  try { await loadCM(); } catch (_) { return toast("ویرایشگر بارگذاری نشد.", "error"); }
  const r = await api("xfer_read_text", c.id, path);
  if (!r.ok) return toast(r.error, "error");
  teOpen(c, path, name, r);
}
function teOpen(conn, path, name, doc) {
  let cm = null, st = { hash: doc.hash, enc: doc.enc, eol: doc.eol, versions: doc.versions || 0, saving: false }, clean = 0, marks = [];
  const modeSel = TE_MODES.map(([v, t]) => `<option value="${esc(v)}">${esc(t)}</option>`).join("");
  const body = `<div class="te-top">
      <span class="ltr te-path" title="${esc(path)}">${esc(conn.user)}@${esc(conn.host)}:${esc(path)}</span>
      <span class="te-sp"></span>
      <select id="teMode" class="sm" title="رنگ‌آمیزی نحو" data-nodirty>${modeSel}</select>
      <select id="teEnc" class="sm ltr" title="کدگذاری" data-nodirty><option value="utf-8">UTF-8</option><option value="utf-8-sig">UTF-8 BOM</option><option value="latin-1">Latin-1</option></select>
      <select id="teEol" class="sm ltr" title="پایان خط" data-nodirty><option value="LF">LF (Linux)</option><option value="CRLF">CRLF (Windows)</option></select>
      <button class="btn sm ghost" id="teFindB" title="Ctrl+F / Ctrl+H">جستجو و جایگزینی</button>
      <button class="btn sm ghost" id="teVerB">نسخه‌های قبلی <span id="teVerN"></span></button>
    </div>
    ${doc.mixed ? `<div class="te-note warn">این فایل پایان خط مخلوط (LF و CRLF) داشت؛ هنگام ذخیره همه با «${esc(doc.eol)}» یکی می‌شوند.</div>` : ""}
    <div class="te-note warn" id="teConflict" hidden></div>
    <div class="te-vers" id="teVers" hidden></div>
    <div class="te-find" id="teFind" hidden data-nodirty>
      <input type="search" id="teQ" class="ltr" placeholder="جستجو" data-nodirty><input type="text" id="teR" class="ltr" placeholder="جایگزین با" data-nodirty>
      <label class="chk" title="عبارت باقاعده"><input type="checkbox" id="teRx" data-nodirty>.*</label>
      <label class="chk" title="حساس به حروف بزرگ و کوچک"><input type="checkbox" id="teCase" data-nodirty>Aa</label>
      <span class="muted" id="teCnt"></span>
      <button class="btn sm ghost" id="tePrev" title="Shift+Enter">قبلی</button><button class="btn sm ghost" id="teNext" title="Enter">بعدی</button>
      <button class="btn sm ghost" id="teRep">جایگزینی</button><button class="btn sm ghost" id="teRepAll">جایگزینی همه</button>
      <button class="iconbtn" id="teFindX" title="بستن">✕</button>
    </div>
    <div class="te-ed" id="teEd" dir="ltr"></div>
    <div class="te-stat" dir="ltr"><span id="teLC"></span><span id="teLines"></span><span id="teGo">Ctrl+G</span><input id="teGoIn" class="ltr" placeholder="Line" hidden data-nodirty><span id="teMod"></span></div>`;
  const foot = `<label class="chk te-keep" title="قبل از هر ذخیره، محتوای فعلی سرور رمزشده داخل برنامه نگه داشته می‌شود (۵ نسخه‌ی آخر)"><input type="checkbox" id="teKeep" data-nodirty>نگه داشتن نسخه‌ی قبلی داخل برنامه</label>
    <span class="te-sp"></span><button class="btn ghost" data-r="0">بستن</button><button class="btn primary" id="teSave">ذخیره (Ctrl+S)</button>`;
  return openModal({ title: "ویرایش " + name, body, foot, wide: true, onOpen: (m, close) => {
    m.classList.add("te-modal");
    const ed = $("#teEd", m);
    cm = CodeMirror(ed, { value: doc.text, lineNumbers: true, lineWrapping: false, matchBrackets: true, styleActiveLine: true, indentUnit: 2, tabSize: 4,
      direction: "ltr", mode: teModeFor(name) || null, theme: "akrp", inputStyle: "contenteditable", spellcheck: false, autofocus: true });
    m._cm = cm;
    $("#teMode", m).value = teModeFor(name);
    $("#teEnc", m).value = doc.enc; $("#teEol", m).value = doc.eol;
    $("#teKeep", m).checked = !!TP.teKeep;
    clean = cm.changeGeneration(true);
    const dirty = () => !cm.isClean(clean) || $("#teEnc", m).value !== st.enc || $("#teEol", m).value !== st.eol;
    const stat = () => {
      const p = cm.getCursor(), sel = cm.getSelection();
      $("#teLC", m).textContent = `Ln ${p.line + 1}, Col ${p.ch + 1}` + (sel ? ` (${sel.length} sel)` : "");
      $("#teLines", m).textContent = `${cm.lineCount()} lines`;
      const d = dirty(); m._dirty = d;
      $("#teMod", m).textContent = d ? "● " + I18N.t("ذخیره نشده") : "";
      $("#teVerN", m).textContent = st.versions ? `(${num(st.versions)})` : "";
    };
    cm.on("cursorActivity", stat); cm.on("change", () => { stat(); if (!$("#teFind", m).hidden) teMark(); });
    $("#teMode", m).onchange = (e) => cm.setOption("mode", e.target.value || null);
    $("#teEnc", m).onchange = stat; $("#teEol", m).onchange = stat;
    $("#teKeep", m).onchange = (e) => { TP.teKeep = e.target.checked; saveTP(); };
    stat();
    // ---- جستجو و جایگزینی
    const q = () => {
      const s = $("#teQ", m).value; if (!s) return null;
      if ($("#teRx", m).checked) { try { return new RegExp(s, $("#teCase", m).checked ? "g" : "gi"); } catch (_) { return null; } }
      return $("#teCase", m).checked ? s : new RegExp(s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "gi");
    };
    function teMark() {
      marks.forEach((x) => x.clear()); marks = [];
      const qq = q(); if (!qq) { $("#teCnt", m).textContent = ""; return; }
      const cur = cm.getSearchCursor(qq, { line: 0, ch: 0 }); let n = 0;
      while (cur.findNext()) { if (cur.from().line === cur.to().line && cur.from().ch === cur.to().ch) break; if (n < 2000) marks.push(cm.markText(cur.from(), cur.to(), { className: "te-hit" })); n++; }
      $("#teCnt", m).textContent = n ? num(n) : I18N.t("پیدا نشد");
    }
    const find = (back) => {
      const qq = q(); if (!qq) return false;
      let cur = cm.getSearchCursor(qq, back ? cm.getCursor("from") : cm.getCursor("to"));
      if (!(back ? cur.findPrevious() : cur.findNext())) {
        cur = cm.getSearchCursor(qq, back ? { line: cm.lastLine() + 1, ch: 0 } : { line: 0, ch: 0 });
        if (!(back ? cur.findPrevious() : cur.findNext())) return false;
      }
      cm.setSelection(cur.from(), cur.to()); cm.scrollIntoView({ from: cur.from(), to: cur.to() }, 60);
      return true;
    };
    const repText = (matched) => {
      const r = $("#teR", m).value, qq = q();
      if (qq instanceof RegExp && $("#teRx", m).checked) return matched.replace(new RegExp(qq.source, qq.flags.replace("g", "")), r);
      return r;
    };
    const replaceOne = () => {
      const qq = q(); if (!qq) return;
      const sel = cm.getSelection(), c0 = cm.getSearchCursor(qq, cm.getCursor("from"));
      if (sel && c0.findNext() && c0.from().line === cm.getCursor("from").line && c0.from().ch === cm.getCursor("from").ch) cm.replaceSelection(repText(sel), "end");
      find(false);
    };
    const replaceAll = () => {
      const qq = q(); if (!qq) return;
      let n = 0;
      cm.operation(() => { const cur = cm.getSearchCursor(qq, { line: 0, ch: 0 }); while (cur.findNext()) { const t = cm.getRange(cur.from(), cur.to()); if (!t && !$("#teRx", m).checked) break; cur.replace(repText(t)); n++; if (n > 100000) break; } });
      toast(n ? `${num(n)} مورد جایگزین شد.` : "موردی پیدا نشد.", n ? "ok" : "info");
    };
    const openFind = (rep) => {
      $("#teFind", m).hidden = false;
      const s = cm.getSelection(); if (s && !s.includes("\n")) $("#teQ", m).value = s;
      (rep && $("#teQ", m).value ? $("#teR", m) : $("#teQ", m)).focus(); $("#teQ", m).select(); teMark();
    };
    const closeFind = () => { $("#teFind", m).hidden = true; marks.forEach((x) => x.clear()); marks = []; cm.focus(); };
    $("#teFindB", m).onclick = () => openFind(false);
    $("#teFindX", m).onclick = closeFind;
    ["#teQ", "#teRx", "#teCase"].forEach((s) => $(s, m).addEventListener(s === "#teQ" ? "input" : "change", teMark));
    $("#teNext", m).onclick = () => find(false); $("#tePrev", m).onclick = () => find(true);
    $("#teRep", m).onclick = replaceOne; $("#teRepAll", m).onclick = replaceAll;
    $("#teFind", m).addEventListener("keydown", (e) => {
      if (e.key === "Escape") { e.preventDefault(); e.stopPropagation(); closeFind(); }
      else if (e.key === "Enter") { e.preventDefault(); e.stopPropagation(); if (e.target.id === "teR") replaceOne(); else find(e.shiftKey); }
    });
    // ---- رفتن به خط
    const goOpen = () => { const g = $("#teGoIn", m); g.hidden = false; g.value = ""; g.focus(); };
    $("#teGo", m).onclick = goOpen;
    $("#teGoIn", m).addEventListener("keydown", (e) => {
      if (e.key === "Escape" || e.key === "Enter") {
        e.preventDefault(); e.stopPropagation();
        const n = parseInt(String(e.target.value).replace(/[\u06F0-\u06F9]/g, (d) => d.charCodeAt(0) - 0x6F0), 10);
        e.target.hidden = true;
        if (e.key === "Enter" && n > 0) { const l = Math.min(n, cm.lineCount()) - 1; cm.setCursor({ line: l, ch: 0 }); cm.scrollIntoView({ line: l, ch: 0 }, 120); }
        cm.focus();
      }
    });
    // ---- ذخیره
    const save = async (force) => {
      if (st.saving) return; st.saving = true;
      const b = $("#teSave", m); b.disabled = true;
      try {
        const enc = $("#teEnc", m).value, eol = $("#teEol", m).value, gen = cm.changeGeneration(true);
        const r = await api("xfer_write_text", conn.id, path, cm.getValue(), enc, eol, st.hash, $("#teKeep", m).checked, !!force);
        if (!r.ok) return toast(r.error, "error");
        if (r.conflict) {
          const n = $("#teConflict", m); n.hidden = false;
          n.innerHTML = `<span>${esc(r.gone ? I18N.t("فایل روی سرور حذف شده یا خواندنی نیست.") : I18N.t("فایل روی سرور از زمان باز کردن تغییر کرده است."))}</span>
            <button class="btn sm danger-ghost" id="teForce">${esc(I18N.t("ذخیره‌ی من جایگزین شود"))}</button><button class="btn sm ghost" id="teReload">${esc(I18N.t("بارگذاری دوباره از سرور"))}</button>`;
          $("#teForce", m).onclick = () => { n.hidden = true; save(true); };
          $("#teReload", m).onclick = async () => {
            const x = await api("xfer_read_text", conn.id, path); if (!x.ok) return toast(x.error, "error");
            n.hidden = true; st.hash = x.hash; cm.setValue(x.text); clean = cm.changeGeneration(true); stat();
          };
          return;
        }
        st.hash = r.hash; st.enc = enc; st.eol = eol; st.versions = r.versions || 0; clean = gen;
        $("#teConflict", m).hidden = true; stat();
        toast(`ذخیره شد: ${path}`, "ok");
      } finally { st.saving = false; b.disabled = false; }
    };
    $("#teSave", m).onclick = () => save(false);
    $("[data-r='0']", m).onclick = () => { if (dirty()) kbDirtyAsk(m); else close(null); };
    m.addEventListener("keydown", (e) => {
      const k = e.key.toLowerCase();
      if (k === "escape" && e.target.closest && e.target.closest(".te-ed")) {     // CodeMirror خودش Esc را مصرف می‌کند
        e.preventDefault(); e.stopPropagation();
        if (!$("#teFind", m).hidden) closeFind(); else if (dirty()) kbDirtyAsk(m); else close(null);
        return;
      }
      if (!(e.ctrlKey || e.metaKey) || e.altKey) return;
      if (k === "s" || k === "\u0633") { e.preventDefault(); e.stopPropagation(); save(false); }
      else if ((k === "f" || k === "\u0628") && !e.shiftKey) { e.preventDefault(); e.stopPropagation(); openFind(false); }
      else if (k === "h" || k === "\u0627") { e.preventDefault(); e.stopPropagation(); openFind(true); }
      else if (k === "g" || k === "\u0644") { e.preventDefault(); e.stopPropagation(); goOpen(); }
    }, true);
    // ---- نسخه‌های قبلی
    $("#teVerB", m).onclick = async () => {
      const box = $("#teVers", m);
      if (!box.hidden) { box.hidden = true; return; }
      const r = await api("xfer_text_versions", conn.id, path); if (!r.ok) return toast(r.error, "error");
      const v = r.versions || [];
      box.innerHTML = v.length ? `<div class="hint">${esc(I18N.t("نسخه‌ای که انتخاب کنید در ویرایشگر بار می‌شود (با Ctrl+Z برمی‌گردد) و تا «ذخیره» نزنید روی سرور نمی‌رود."))}</div>
        <table class="grid nosort"><tbody>${v.map((x) => `<tr><td>${esc(fmtDate(x.ts))}</td><td class="ltr">${esc(fmtBytes(x.size))}</td>
        <td><button class="btn sm ghost" data-v="${esc(x.id)}">${esc(I18N.t("بارگذاری در ویرایشگر"))}</button></td></tr>`).join("")}</tbody></table>`
        : `<div class="hint">${esc(I18N.t("هنوز نسخه‌ی قبلی نگه داشته نشده است. گزینه‌ی «نگه داشتن نسخه‌ی قبلی داخل برنامه» را روشن کنید تا از ذخیره‌ی بعدی نگه داشته شود."))}</div>`;
      box.hidden = false;
      $$("[data-v]", box).forEach((b) => (b.onclick = async () => {
        const x = await api("xfer_text_version", conn.id, path, b.dataset.v); if (!x.ok) return toast(x.error, "error");
        cm.setValue(x.text); box.hidden = true; stat(); cm.focus();
      }));
    };
    setTimeout(() => { cm.refresh(); cm.focus(); }, 30);
  } });
}

/* ================================================================ پشتیبان پوشه‌ی لینوکس (1.58) */
const FBK = { jobs: [], running: {}, devices: [], desktop: true, master: false, timer: null };
const FBK_ST = { ok: ["ok", "موفق"], warn: ["warn", "با هشدار"], error: ["err", "ناموفق"], cancelled: ["mute", "متوقف شد"] };
async function sshFbackup() {
  $("#sshActions").innerHTML = `<button class="btn primary" id="fbNew">کار پشتیبان تازه</button>`;
  $("#fbNew").onclick = () => fbEdit(null);
  const r = await api("fbk_list"); if (SSH.tab !== "fbackup" || S.page !== "ssh") return;
  if (!r.ok) { $("#sshBody").innerHTML = `<p class="hint warn">${esc(r.error)}</p>`; return; }
  Object.assign(FBK, { jobs: r.jobs, running: r.running, devices: r.devices, desktop: r.desktop, master: r.master });
  fbRender();
  fbPoll();
}
function fbDev(id) { const d = FBK.devices.find((x) => x.id === id); return d ? d.name : "(حذف شده)"; }
function fbRender() {
  const box = $("#sshBody"); if (!box || SSH.tab !== "fbackup") return;
  const run = FBK.running;
  box.innerHTML = `<p class="hint">پوشه‌ها یا فایل‌های سرور لینوکس با <span class="ltr">tar.gz</span> از راه SSH مستقیم در پوشه‌ی مقصد ذخیره می‌شوند (بدون فایل موقت روی سرور). اگر فقط یک مسیر باشد و آن مسیر یک فایل باشد (مثلاً خودش آرشیو است)، همان فایل بدون tar دوباره ذخیره می‌شود. زمان‌بندی: «کارهای خودکار ← زمان‌بندی SSH».</p>
    <div class="table-wrap"><table class="grid"><thead><tr><th>نام</th><th>دستگاه</th><th>مسیرها</th><th>sudo</th><th>نگه‌داری</th><th>آخرین اجرا</th><th class="nosort"></th></tr></thead><tbody>
    ${FBK.jobs.length ? FBK.jobs.map((j) => {
      const rr = run[j.id], st = FBK_ST[j.last_status];
      return `<tr><td><b>${esc(j.name)}</b><div class="muted ltr" style="font-size:12px">${esc(j.dest)}</div></td><td>${esc(fbDev(j.device_id))}</td>
        <td class="wrap w-md ltr">${j.paths.map(esc).join("<br>")}${j.excludes.length ? `<div class="muted" style="font-size:12px">− ${j.excludes.map(esc).join("، ")}</div>` : ""}</td>
        <td>${j.sudo ? `<span class="tag warn">sudo</span>` : "—"}</td><td data-sort="${j.keep}">${j.keep ? `${num(j.keep)} نسخه` : "همه"}</td>
        <td class="wrap w-md" data-sort="${rr ? 9e12 : j.last_at || 0}">${rr ? `<span class="tag info">در حال اجرا</span> <span class="ltr">${esc(fmtBytes(rr.bytes))}</span> · ${num(rr.files)} فایل`
          : j.last_at ? `${st ? `<span class="tag ${st[0]}">${st[1]}</span>` : ""} ${fmtDate(j.last_at)}<div class="muted" style="font-size:12px">${esc(j.last_message || "")}</div>` : "—"}</td>
        <td><div class="row" style="gap:6px;flex-wrap:nowrap">${rr ? `<button class="btn sm danger-ghost" data-fbx="${esc(j.id)}">توقف</button>` : `<button class="btn sm" data-fbr="${esc(j.id)}">اجرا</button>`}
          <button class="btn sm ghost" data-fbh="${esc(j.id)}">سابقه</button><button class="btn sm ghost" data-fbe="${esc(j.id)}">ویرایش</button><button class="btn sm ghost" data-fbd="${esc(j.id)}">حذف</button></div></td></tr>`;
    }).join("") : `<tr><td colspan="7"><div class="empty">هنوز کار پشتیبان پوشه‌ای نیست. «کار پشتیبان تازه» را بزنید.</div></td></tr>`}</tbody></table></div>`;
  const J = (id) => FBK.jobs.find((x) => x.id === id);
  $$("[data-fbr]", box).forEach((b) => (b.onclick = () => withSpin(b, async () => { const r = await api("fbk_run", b.dataset.fbr); if (!r.ok) return toast(r.error, "error"); toast("پشتیبان‌گیری شروع شد", "ok"); await fbRefresh(); })));
  $$("[data-fbx]", box).forEach((b) => (b.onclick = async () => { const r = await api("fbk_cancel", b.dataset.fbx); if (!r.ok) toast(r.error, "error"); }));
  $$("[data-fbe]", box).forEach((b) => (b.onclick = () => fbEdit(J(b.dataset.fbe))));
  $$("[data-fbh]", box).forEach((b) => (b.onclick = () => fbHist(J(b.dataset.fbh))));
  $$("[data-fbd]", box).forEach((b) => (b.onclick = async () => {
    const j = J(b.dataset.fbd);
    if (!(await confirm2({ title: "حذف کار پشتیبان", danger: true, confirm: "حذف", body: `<p>«${esc(j.name)}» و زمان‌بندی‌هایش حذف شود؟ فایل‌های پشتیبانِ ساخته‌شده در پوشه‌ی مقصد می‌مانند.</p>` }))) return;
    const r = await api("fbk_delete", j.id); if (!r.ok) return toast(r.error, "error");
    toast("حذف شد", "ok"); fbRefresh();
  }));
}
async function fbRefresh() {
  const r = await api("fbk_list"); if (!r.ok) return;
  Object.assign(FBK, { jobs: r.jobs, running: r.running, devices: r.devices });
  if (!$("#modalBack") || $("#modalBack").hidden) fbRender();
  fbPoll();
}
function fbPoll() {
  clearTimeout(FBK.timer);
  if (Object.keys(FBK.running).length && S.page === "ssh" && SSH.tab === "fbackup") FBK.timer = setTimeout(fbRefresh, 2000);
}
function fbEdit(j) {
  const isNew = !j;
  j = j || { name: "", device_id: (FBK.devices[0] || {}).id, paths: [], excludes: [], sudo: false, dest: "", keep: 7 };
  if (!FBK.devices.length) return toast("هیچ دستگاه لینوکس مشترکی (SSH) در «دستگاه‌ها» نیست.", "warn");
  const payload = (m) => ({ id: isNew ? "" : j.id, name: $("#fbName", m).value, device_id: Number($("#fbDev", m).value),
    paths: $("#fbPaths", m).value.split("\n"), excludes: $("#fbEx", m).value.split("\n"), sudo: $("#fbSudo", m).checked,
    dest: $("#fbDest", m).value, keep: $("#fbKeep", m).value });
  openModal({ title: isNew ? "کار پشتیبان پوشه‌ی تازه" : `ویرایش «${j.name}»`, wide: true,
    body: `<div class="form-grid">
      <label class="field"><span>نام</span><input type="text" id="fbName" value="${esc(j.name)}" autofocus></label>
      <label class="field"><span>دستگاه لینوکس</span><select id="fbDev">${FBK.devices.map((d) => `<option value="${d.id}" ${d.id === j.device_id ? "selected" : ""}>${esc(d.name)} — ${esc(d.host)}</option>`).join("")}</select></label>
      <label class="field wide"><span>مسیرها (هر خط یک مسیر کامل؛ پوشه یا فایل)</span><textarea id="fbPaths" class="ltr" rows="4" placeholder="/etc/nginx&#10;/var/www/site&#10;/opt/app/backup.tar.gz">${esc(j.paths.join("\n"))}</textarea></label>
      <label class="field wide"><span>استثناها (اختیاری، هر خط یک الگو)</span><textarea id="fbEx" class="ltr" rows="2" placeholder="*.log&#10;node_modules&#10;cache/*">${esc(j.excludes.join("\n"))}</textarea></label>
      <label class="field wide"><span>پوشه‌ی مقصد ${FBK.desktop ? "(روی همین کامپیوتر)" : "(روی سرور برنامه)"}</span><div class="row" style="gap:6px"><input type="text" id="fbDest" class="ltr" style="flex:1" value="${esc(j.dest)}" placeholder="${FBK.desktop ? "D:\\Backups\\linux" : "/srv/backups"}">${FBK.desktop ? `<button class="btn ghost" id="fbPick" type="button">انتخاب…</button>` : ""}</div>
        <span class="hint">فایل‌ها در زیرپوشه‌ی نام دستگاه با نام <span class="ltr">کار_YYYY-MM-DD_HHMM.tar.gz</span> ذخیره می‌شوند (فشرده، رمزنگاری‌نشده).</span></label>
      <label class="field"><span>نگه داشتن نسخه‌های آخر (۰ = همه)</span><input type="number" id="fbKeep" min="0" max="365" value="${esc(j.keep)}"></label>
      <div class="field"><span>&nbsp;</span><label class="chk"><input type="checkbox" id="fbSudo" ${j.sudo ? "checked" : ""}>با sudo (برای فایل‌هایی که فقط root می‌خواند؛ پسورد همان یوزر دستگاه)</label></div>
      <div class="field wide" id="fbTestOut" hidden></div>
    </div>`,
    foot: `<button class="btn ghost" id="fbTest">بررسی مسیرها</button><span style="flex:1"></span><button class="btn ghost" data-x="0">انصراف</button><button class="btn primary" data-x="1">ذخیره</button>`,
    onOpen: (m, close) => {
      if ($("#fbPick", m)) $("#fbPick", m).onclick = async () => { const r = await api("fbk_pick_dir"); if (r.ok && r.path) { $("#fbDest", m).value = r.path; m._dirty = true; } };
      $("#fbTest", m).onclick = (e) => withSpin(e.currentTarget, async () => {
        const r = await api("fbk_test", payload(m)), out = $("#fbTestOut", m); out.hidden = false;
        if (!r.ok) { out.innerHTML = `<p class="hint warn">${esc(r.error)}</p>`; return; }
        const T = { dir: ["ok", "پوشه"], file: ["info", "فایل (بدون tar)"], missing: ["err", "پیدا نشد"], other: ["warn", "نوع دیگر"] };
        const one = Object.keys(r.types).length === 1;
        out.innerHTML = `<table class="grid nosort"><tbody>${Object.entries(r.types).map(([p, t]) => `<tr><td class="ltr">${esc(p)}</td><td><span class="tag ${T[t][0]}">${t === "file" && !one ? "فایل" : T[t][1]}</span></td></tr>`).join("")}</tbody></table>
          <p class="hint ${r.tar ? "" : "warn"}">${r.tar ? "tar روی سرور هست." : "tar روی سرور پیدا نشد؛ روش جایگزین SFTP (بدون sudo) به کار می‌رود."}</p>
          ${r.errors.length ? `<pre class="ltr paste-prev" data-no-i18n>${esc(r.errors.join("\n"))}</pre>` : ""}`;
      });
      $("[data-x='0']", m).onclick = () => close();
      $("[data-x='1']", m).onclick = (e) => withSpin(e.currentTarget, async () => {
        const r = await api("fbk_save", payload(m)); if (!r.ok) return toast(r.error, "error");
        close(); toast("ذخیره شد", "ok"); fbRefresh();
      });
    } });
}
function fbHist(j) {
  const runs = j.runs || [];
  openModal({ title: `سابقه‌ی «${j.name}»`, wide: true,
    body: runs.length ? `<div class="table-wrap inner"><table class="grid"><thead><tr><th>زمان</th><th>وضعیت</th><th>حجم</th><th>فایل‌ها</th><th>مدت</th><th>نوع اجرا</th><th>فایل</th></tr></thead><tbody>
      ${runs.map((x, i) => { const st = FBK_ST[x.status] || ["mute", x.status]; return `<tr><td class="ltr" data-sort="${x.at}">${fmtDate(x.at)}</td><td><span class="tag ${st[0]}">${st[1]}</span>${x.errors && x.errors.length ? ` <button class="btn sm ghost" data-er="${i}">${num(x.errors.length)} هشدار</button>` : ""}</td>
        <td class="ltr" data-sort="${x.size}">${x.size ? esc(fmtBytes(x.size)) : "—"}</td><td data-sort="${x.files}">${num(x.files)}</td><td data-sort="${x.secs}">${num(x.secs)} ثانیه</td>
        <td>${x.trigger === "schedule" ? "زمان‌بندی" : "دستی"}</td><td class="wrap w-lg">${x.file ? `<span class="ltr">${esc(x.file)}</span>` : esc(x.message || "")}</td></tr>`; }).join("")}</tbody></table></div><pre class="ltr paste-prev" id="fbErr" hidden data-no-i18n></pre>`
      : `<div class="empty">هنوز اجرا نشده است.</div>`,
    foot: `<button class="btn primary" data-x="0">بستن</button>`,
    onOpen: (m, close) => {
      $("[data-x='0']", m).onclick = () => close();
      $$("[data-er]", m).forEach((b) => (b.onclick = () => { const p = $("#fbErr", m); p.hidden = false; p.textContent = runs[Number(b.dataset.er)].errors.join("\n"); }));
    } });
}
