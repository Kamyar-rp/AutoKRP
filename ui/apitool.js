"use strict";
/* ================================================================ ابزار API (1.40)
 * ارتباط با دستگاه‌ها ← API. فهرست اتصال‌ها (آدرس پایه + احراز؛ رمز و توکن در vault سمت سرور) و درخواست‌های ذخیره‌شده‌ی هر کدام،
 * سازنده‌ی درخواست (متد، مسیر، پارامتر، هدر، Body)، پاسخ مرتب (کپی، ذخیره‌ی فایل) و لاگ درخواست‌ها. ساده، شبیه Bruno/Insomnia. */

const AT = { conns: [], reqs: {}, admin: false, cur: null, req: null, tab: "params", rtab: "body", resp: null, sending: false,
  view: "req", noAsk: false, open: new Set(), log: { q: "", offset: 0 } };
const AT_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"];
const AT_MUT = new Set(["POST", "PUT", "PATCH", "DELETE"]);
const AT_AUTH = { none: "بدون احراز", basic: "Basic (نام کاربری و رمز)", bearer: "Bearer Token", header: "API Key در هدر", query: "API Key در آدرس" };

function atNewReq(conn) { return { id: null, conn_id: conn ? conn.id : null, name: "", method: "GET", path: "", params: [], headers: [], body: "", body_type: "json" }; }
function atConn() { return AT.conns.find((c) => c.id === AT.cur) || null; }
function atCanRun() { return axOk("apitool", "run"); }

async function sshApi() {
  $("#sshActions").innerHTML = atCanRun() ? `<button class="btn primary" id="atAddConn">+ اتصال تازه</button>` : "";
  if ($("#atAddConn")) $("#atAddConn").onclick = () => atConnModal(null);
  const r = await api("api_conn_list");
  if (!r.ok) { $("#sshBody").innerHTML = `<div class="panel"><div class="empty">${esc(r.error)}</div></div>`; return; }
  AT.conns = r.conns; AT.reqs = r.reqs || {}; AT.admin = r.admin;
  if (AT.cur && !atConn()) AT.cur = null;
  if (!AT.cur && AT.conns.length) AT.cur = AT.conns[0].id;
  if (AT.cur) AT.open.add(AT.cur);
  if (!AT.req || AT.req.conn_id !== AT.cur) AT.req = atNewReq(atConn());
  atRender();
}
function atRender() {
  const body = $("#sshBody");
  body.innerHTML = `<div class="at-wrap"><aside class="at-side">
      <div class="seg at-viewsel"><button data-av="req" class="${AT.view === "req" ? "on" : ""}">درخواست</button><button data-av="log" class="${AT.view === "log" ? "on" : ""}">لاگ درخواست‌ها</button></div>
      <div class="at-conns">${AT.conns.length ? AT.conns.map((c) => `<div class="at-conn${c.id === AT.cur ? " on" : ""}">
        <button class="at-ch" data-ac="${c.id}"><span class="at-arrow">${AT.open.has(c.id) ? "▾" : "▸"}</span><span class="at-cn"><b class="bidi">${esc(c.name)}</b>
          <span class="ltr muted">${esc(c.base_url)}</span></span>${c.personal ? `<span class="tag mute" title="فقط برای خودتان">شخصی</span>` : ""}</button>
        ${AT.open.has(c.id) ? `<div class="at-reqs">${(AT.reqs[c.id] || []).map((q) => `<button class="at-rq${AT.req && AT.req.id === q.id ? " on" : ""}" data-arq="${q.id}" data-acn="${c.id}">
          <span class="at-m m-${q.method}">${q.method}</span><span class="bidi">${esc(q.name)}</span></button>`).join("")}
          <button class="at-rq at-new" data-anew="${c.id}">+ درخواست تازه</button></div>` : ""}</div>`).join("")
        : `<div class="empty">${esc("هنوز اتصالی نیست.")}${atCanRun() ? `<br><span class="muted">${esc("با «اتصال تازه» آدرس API دستگاه (مثلاً FortiGate) و روش احراز هویتش را وارد کنید.")}</span>` : ""}</div>`}</div>
    </aside><section class="at-main" id="atMain"></section></div>`;
  $$("[data-av]", body).forEach((b) => (b.onclick = () => { AT.view = b.dataset.av; atRender(); }));
  $$("[data-ac]", body).forEach((b) => (b.onclick = () => {
    const id = Number(b.dataset.ac);
    if (AT.cur === id) { if (AT.open.has(id)) AT.open.delete(id); else AT.open.add(id); }
    else { AT.cur = id; AT.open.add(id); AT.req = atNewReq(atConn()); AT.resp = null; }
    AT.view = "req"; atRender();
  }));
  $$("[data-arq]", body).forEach((b) => (b.onclick = () => {
    AT.cur = Number(b.dataset.acn);
    const q = (AT.reqs[AT.cur] || []).find((x) => x.id === Number(b.dataset.arq));
    AT.req = JSON.parse(JSON.stringify(q)); AT.resp = null; AT.view = "req"; atRender();
  }));
  $$("[data-anew]", body).forEach((b) => (b.onclick = () => { AT.cur = Number(b.dataset.anew); AT.req = atNewReq(atConn()); AT.resp = null; AT.view = "req"; atRender(); }));
  if (AT.view === "log") return atLog();
  atMain();
}

/* ---------------------------------------------------------------- سازنده‌ی درخواست */
function atKv(rows, key) {
  return `<table class="at-kv"><tbody>${rows.map((r, i) => `<tr><td><input type="checkbox" data-kon="${key}:${i}" ${r[2] !== false ? "checked" : ""}></td>
      <td><input class="ltr" data-kk="${key}:${i}" value="${esc(r[0])}" placeholder="${key === "headers" ? "Header" : "key"}"></td>
      <td><input class="ltr" data-kvv="${key}:${i}" value="${esc(r[1])}" placeholder="value"></td><td><button class="iconbtn" data-kdel="${key}:${i}" title="حذف">×</button></td></tr>`).join("")}</tbody></table>
    <button class="btn sm ghost" data-kadd="${key}">+ افزودن</button>`;
}
function atMain() {
  const m = $("#atMain"), c = atConn(), q = AT.req;
  if (!c) { m.innerHTML = `<div class="panel"><div class="empty">${esc("یک اتصال انتخاب کنید یا بسازید.")}</div></div>`; return; }
  const run = atCanRun();
  m.innerHTML = `<div class="at-chead"><div><b class="bidi">${esc(c.name)}</b> <span class="muted">${esc(I18N.t(AT_AUTH[c.auth] || c.auth))}${c.verify ? "" : ` · ${esc("بدون بررسی گواهی TLS")}`}</span>
      <div class="ltr muted at-base">${esc(c.base_url)}</div></div><span style="flex:1"></span>
      ${c.can_edit && run ? `<button class="btn sm" id="atEditConn">ویرایش اتصال</button>` : ""}</div>
    <div class="at-bar"><select id="atMethod" class="at-msel m-${q.method}">${AT_METHODS.map((x) => `<option ${x === q.method ? "selected" : ""}>${x}</option>`).join("")}</select>
      <div class="at-url"><span class="ltr muted at-urlbase" title="${esc(c.base_url)}">${esc(c.base_url.replace(/^https?:\/\//, ""))}</span><input id="atPath" class="ltr" value="${esc(q.path)}" placeholder="/api/v2/monitor/system/status" spellcheck="false"></div>
      <button class="btn primary" id="atSend" ${run ? "" : `disabled title="${esc(I18N.t("دسترسی اجرا ندارید"))}"`}>${AT.sending ? "در حال ارسال…" : "ارسال"}</button>
      ${c.can_edit && run ? `<button class="btn" id="atSave" title="ذخیره در فهرست همین اتصال">${q.id ? "ذخیره" : "ذخیره…"}</button>` : ""}</div>
    <div class="tabs at-tabs" id="atTabs">${[["params", "پارامترها", q.params.length], ["headers", "هدرها", q.headers.length], ["body", "Body", q.body ? 1 : 0]]
      .map(([k, t, n]) => `<button data-at="${k}" class="${AT.tab === k ? "on" : ""}">${t}${n ? ` <span class="at-n">${num(n)}</span>` : ""}</button>`).join("")}
      ${q.id ? `<span style="flex:1"></span><span class="muted">${esc("درخواست ذخیره‌شده: ")}<b class="bidi">${esc(q.name)}</b></span>${c.can_edit && run ? `<button class="btn sm danger-ghost" id="atDelReq">حذف</button>` : ""}` : ""}</div>
    <div class="at-pane" id="atPane"></div>
    <div class="at-resp" id="atResp"></div>`;
  atPane(); atRespRender();
  $("#atMethod").onchange = (e) => { q.method = e.target.value; e.target.className = `at-msel m-${q.method}`; };
  $("#atPath").oninput = (e) => {
    // آدرس کامل paste شد: پارامترها جدا شوند
    const v = e.target.value, i = v.indexOf("?");
    if (i >= 0 && v.length - i > 1 && /[=&]/.test(v.slice(i))) {
      q.path = v.slice(0, i);
      for (const part of v.slice(i + 1).split("&")) { if (!part) continue; const [k, ...rest] = part.split("="); try { q.params.push([decodeURIComponent(k), decodeURIComponent(rest.join("=")), true]); } catch (_) { q.params.push([k, rest.join("="), true]); } }
      e.target.value = q.path; AT.tab = "params"; atMain(); $("#atPath").focus(); return;
    }
    q.path = v;
  };
  $("#atPath").onkeydown = (e) => { if (e.key === "Enter") { e.preventDefault(); atSend(); } };
  $("#atSend").onclick = atSend;
  if ($("#atSave")) $("#atSave").onclick = atSaveReq;
  if ($("#atEditConn")) $("#atEditConn").onclick = () => atConnModal(c);
  if ($("#atDelReq")) $("#atDelReq").onclick = async () => {
    if (!(await confirm2({ title: "حذف درخواست", body: `<p>${esc(`درخواست «${q.name}» حذف شود؟`)}</p>`, confirm: "حذف", danger: true }))) return;
    const x = await api("api_req_delete", q.id); if (!x.ok) return toast(x.error, "error");
    AT.req = atNewReq(c); sshApi();
  };
  $$("#atTabs [data-at]").forEach((b) => (b.onclick = () => { AT.tab = b.dataset.at; $$("#atTabs [data-at]").forEach((x) => x.classList.toggle("on", x === b)); atPane(); }));
}
function atPane() {
  const p = $("#atPane"), q = AT.req;
  if (AT.tab === "body") {
    const dis = !AT_MUT.has(q.method);
    p.innerHTML = `<div class="row" style="gap:8px;margin-bottom:6px"><div class="seg" id="atBt">${[["json", "JSON"], ["text", "متن"], ["form", "Form"], ["none", "بدون Body"]]
        .map(([k, t]) => `<button data-bt="${k}" class="${q.body_type === k ? "on" : ""}">${t}</button>`).join("")}</div>
      ${q.body_type === "json" ? `<button class="btn sm ghost" id="atFmt">مرتب کردن JSON</button>` : ""}${dis ? `<span class="muted">${esc("درخواست GET بدنه نمی‌فرستد.")}</span>` : ""}</div>
      ${q.body_type === "none" ? "" : `<textarea id="atBody" class="ltr at-body" spellcheck="false" placeholder="${q.body_type === "json" ? '{ "name": "value" }' : q.body_type === "form" ? "a=1&b=2" : ""}">${esc(q.body)}</textarea>`}`;
    $$("#atBt [data-bt]", p).forEach((b) => (b.onclick = () => { q.body_type = b.dataset.bt; atPane(); }));
    if ($("#atBody", p)) $("#atBody", p).oninput = (e) => { q.body = e.target.value; };
    if ($("#atFmt", p)) $("#atFmt", p).onclick = () => { try { q.body = JSON.stringify(JSON.parse(q.body), null, 2); $("#atBody", p).value = q.body; } catch (e) { toast(I18N.t("JSON معتبر نیست: ") + e.message, "error"); } };
    return;
  }
  const key = AT.tab, rows = q[key];
  p.innerHTML = atKv(rows, key) + (key === "headers" ? `<p class="hint">${esc("هدرهای پیش‌فرض اتصال و احراز هویت (رمز، توکن یا کلید) خودکار اضافه می‌شوند و این‌جا لازم نیست.")}</p>` : "");
  $$("[data-kk]", p).forEach((i) => (i.oninput = () => { const [, n] = i.dataset.kk.split(":"); rows[n][0] = i.value; }));
  $$("[data-kvv]", p).forEach((i) => (i.oninput = () => { const [, n] = i.dataset.kvv.split(":"); rows[n][1] = i.value; }));
  $$("[data-kon]", p).forEach((i) => (i.onchange = () => { const [, n] = i.dataset.kon.split(":"); rows[n][2] = i.checked; }));
  $$("[data-kdel]", p).forEach((b) => (b.onclick = () => { const [, n] = b.dataset.kdel.split(":"); rows.splice(Number(n), 1); atPane(); atTabCounts(); }));
  $("[data-kadd]", p).onclick = () => { rows.push(["", "", true]); atPane(); atTabCounts(); const ins = $$("[data-kk]", p); if (ins.length) ins[ins.length - 1].focus(); };
}
function atTabCounts() {
  const q = AT.req;
  $$("#atTabs [data-at]").forEach((b) => { const n = { params: q.params.length, headers: q.headers.length, body: q.body ? 1 : 0 }[b.dataset.at]; const s = $(".at-n", b);
    if (n && !s) b.insertAdjacentHTML("beforeend", ` <span class="at-n">${num(n)}</span>`); else if (s) { if (n) s.textContent = num(n); else s.remove(); } });
}
async function atSend() {
  const c = atConn(), q = AT.req;
  if (!c || AT.sending || !atCanRun()) return;
  if (AT_MUT.has(q.method) && !AT.noAsk) {
    const v = await openModal({ title: `${q.method} — ${I18N.t("تأیید ارسال")}`,
      body: `<p>${esc("این درخواست ممکن است روی دستگاه چیزی را بسازد، تغییر دهد یا حذف کند:")}</p><p class="ltr"><b>${esc(q.method)}</b> ${esc(c.base_url)}${esc(q.path ? (q.path.startsWith("/") ? "" : "/") + q.path : "")}</p>
        <label class="chk"><input type="checkbox" id="atNoAsk">تا بسته شدن برنامه دیگر نپرس</label>`,
      foot: `<button class="btn ghost" data-r="0">انصراف</button><button class="btn danger" data-r="1">ارسال</button>`,
      onOpen: (m, close) => $$("[data-r]", m).forEach((b) => (b.onclick = () => close(b.dataset.r === "1" ? { noAsk: $("#atNoAsk", m).checked } : null))) });
    if (!v) return;
    if (v.noAsk) AT.noAsk = true;
  }
  AT.sending = true; const b = $("#atSend"); if (b) { b.disabled = true; b.textContent = I18N.t("در حال ارسال…"); }
  const r = await api("api_send", c.id, { method: q.method, path: q.path, params: q.params, headers: q.headers, body: q.body, body_type: q.body_type });
  AT.sending = false; if (b && b.isConnected) { b.disabled = false; b.textContent = I18N.t("ارسال"); }
  if (!r.ok) { AT.resp = { error: r.error }; } else AT.resp = r;
  atRespRender();
}
function atJsonHtml(text) {
  let pretty;
  try { pretty = JSON.stringify(JSON.parse(text), null, 2); } catch (_) { return esc(text); }
  return esc(pretty).replace(/(&quot;(?:[^&]|&(?!quot;))*?&quot;)(\s*:)?|\b(true|false|null)\b|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)/g,
    (m, str, colon, lit, n) => str ? `<span class="${colon ? "j-k" : "j-s"}">${str}</span>${colon || ""}` : lit ? `<span class="j-l">${lit}</span>` : `<span class="j-n">${n}</span>`);
}
function atRespRender() {
  const el = $("#atResp"); if (!el) return;
  const r = AT.resp;
  if (!r) { el.innerHTML = `<div class="at-empty muted">${esc("پاسخ این‌جا نمایش داده می‌شود. Ctrl+Enter یا Enter در مسیر = ارسال.")}</div>`; return; }
  if (r.error && !r.status) { el.innerHTML = `<div class="at-rhead"><span class="tag err">${esc("خطا")}</span>${r.ms != null ? `<span class="muted ltr">${num(r.ms)} ms</span>` : ""}</div><div class="at-err">${esc(r.error)}</div>`; return; }
  const cls = r.status < 300 ? "ok" : r.status < 400 ? "info" : r.status < 500 ? "warn" : "err";
  el.innerHTML = `<div class="at-rhead"><span class="tag ${cls} ltr">${num(r.status)} ${esc(r.reason || "")}</span><span class="muted ltr">${num(r.ms)} ms</span>
      <span class="muted ltr">${esc(typeof fmtBytes === "function" ? fmtBytes(r.size || 0) : `${num(r.size || 0)} B`)}</span>${r.truncated ? `<span class="tag warn">${esc("بریده شد (بیش از ۵ مگابایت)")}</span>` : ""}
      <div class="seg" id="atRt"><button data-rt="body" class="${AT.rtab === "body" ? "on" : ""}">پاسخ</button><button data-rt="headers" class="${AT.rtab === "headers" ? "on" : ""}">هدرها <span class="at-n">${num(r.headers.length)}</span></button>${r.json ? `<button data-rt="raw" class="${AT.rtab === "raw" ? "on" : ""}">متن خام</button>` : ""}</div>
      <span style="flex:1"></span><button class="btn sm" id="atCopy">کپی</button><button class="btn sm" id="atFile">ذخیره‌ی فایل</button></div>
    ${r.final_url ? `<div class="muted">${esc("پس از redirect: ")}<span class="ltr">${esc(r.final_url)}</span></div>` : ""}
    <pre class="at-pre ltr" id="atPre" data-no-i18n></pre>`;
  const pre = $("#atPre");
  const show = () => {
    if (AT.rtab === "headers") pre.innerHTML = r.headers.map(([k, v]) => `<span class="j-k">${esc(k)}</span>: ${esc(v)}`).join("\n");
    else if (AT.rtab === "raw" || !r.json) pre.textContent = r.body || "";
    else pre.innerHTML = atJsonHtml(r.body);
  };
  show();
  $$("#atRt [data-rt]").forEach((b) => (b.onclick = () => { AT.rtab = b.dataset.rt; $$("#atRt [data-rt]").forEach((x) => x.classList.toggle("on", x === b)); show(); }));
  const text = () => (AT.rtab === "headers" ? r.headers.map(([k, v]) => `${k}: ${v}`).join("\n") : r.json && AT.rtab !== "raw" ? JSON.stringify(JSON.parse(r.body), null, 2) : r.body || "");
  $("#atCopy").onclick = async () => { try { await navigator.clipboard.writeText(text()); toast("کپی شد", "ok"); } catch (_) { toast("کپی انجام نشد.", "error"); } };
  $("#atFile").onclick = async () => {
    const ext = AT.rtab === "headers" ? "txt" : r.json ? "json" : /xml/i.test(r.content_type || "") ? "xml" : "txt";
    const x = await api("save_export", `api-${(atConn() || {}).name || "response"}-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, "")}.${ext}`.replace(/[^\w.\-]+/g, "_"), text());
    if (x.ok && !x.cancelled) toast("ذخیره شد", "ok"); else if (!x.ok) toast(x.error, "error");
  };
}
async function atSaveReq() {
  const c = atConn(), q = AT.req;
  let name = q.name;
  if (!q.id) {
    name = await openModal({ title: "ذخیره‌ی درخواست", body: `<label>نام</label><input id="arName" autofocus maxlength="100" placeholder="${esc(I18N.t("مثلاً: وضعیت سیستم"))}" value="${esc(`${q.method} ${q.path}`.trim())}">`,
      foot: `<button class="btn ghost" data-r="0">انصراف</button><button class="btn primary" data-r="1">ذخیره</button>`,
      onOpen: (m, close) => { $$("[data-r]", m).forEach((b) => (b.onclick = () => close(b.dataset.r === "1" ? $("#arName", m).value.trim() : null))); $("#arName", m).onkeydown = (e) => { if (e.key === "Enter") close($("#arName", m).value.trim()); }; } });
    if (!name) return;
  }
  const x = await api("api_req_save", { ...q, name, conn_id: c.id });
  if (!x.ok) return toast(x.error, "error");
  q.id = x.id; q.name = name; toast("درخواست ذخیره شد", "ok");
  const keepResp = AT.resp; await sshApi(); AT.resp = keepResp; atRespRender();
}

/* ---------------------------------------------------------------- پنجره‌ی اتصال */
async function atConnModal(c) {
  const isNew = !c; c = c || { name: "", base_url: "https://", auth: "none", key_name: "", verify: true, timeout: 30, headers: [], notes: "", personal: !AT.admin, username: "", has_secret: false };
  const hdr = JSON.parse(JSON.stringify(c.headers || []));
  const v = await openModal({ title: isNew ? "اتصال تازه" : `ویرایش اتصال: ${c.name}`, wide: true,
    body: `<div class="form-grid"><label class="field"><span>نام</span><input id="acName" value="${esc(c.name)}" maxlength="80" placeholder="${esc(I18N.t("مثلاً: FortiGate مرکز"))}"></label>
      <label class="field"><span>آدرس پایه</span><input id="acBase" class="ltr" value="${esc(c.base_url)}" placeholder="https://10.0.0.1/api/v2"></label>
      <label class="field"><span>احراز هویت</span><select id="acAuth">${Object.entries(AT_AUTH).map(([k, t]) => `<option value="${k}" ${c.auth === k ? "selected" : ""}>${t}</option>`).join("")}</select></label>
      <label class="field" id="acKeyF"><span>نام هدر یا پارامتر کلید</span><input id="acKey" class="ltr" value="${esc(c.key_name)}" placeholder="X-API-Key / access_token"></label>
      <label class="field" id="acUserF"><span>نام کاربری</span><input id="acUser" class="ltr" value="${esc(c.username || "")}" autocomplete="off"></label>
      <label class="field" id="acSecF"><span id="acSecL"></span><input id="acSec" class="ltr" type="password" autocomplete="new-password" placeholder="${c.has_secret ? esc(I18N.t("بدون تغییر (ذخیره شده)")) : ""}"></label>
      <label class="field"><span>مهلت (ثانیه)</span><input id="acTo" type="number" min="2" max="300" value="${esc(String(c.timeout || 30))}"></label>
      <label class="field"><span>&nbsp;</span><label class="chk"><input type="checkbox" id="acVerify" ${c.verify ? "checked" : ""}>بررسی گواهی TLS (برای گواهی خودامضا خاموش کنید)</label></label></div>
    <h3 style="margin:12px 0 6px">هدرهای پیش‌فرض این اتصال</h3><div id="acHdr"></div>
    <label class="field" style="margin-top:10px"><span>یادداشت</span><input id="acNotes" value="${esc(c.notes || "")}" maxlength="500"></label>
    ${isNew && AT.admin ? `<label class="chk" style="margin-top:8px"><input type="checkbox" id="acPers" ${c.personal ? "checked" : ""}>شخصی (فقط برای خودم؛ وگرنه برای همه‌ی کسانی که دسترسی دارند)</label>` : ""}
    <p class="hint">${esc("رمز، توکن و کلید رمزنگاری‌شده در صندوق اسرار برنامه ذخیره می‌شوند، به رابط برنمی‌گردند و در لاگ ماسک می‌شوند.")}</p>`,
    foot: `${!isNew ? `<button class="btn danger-ghost" data-r="del">حذف اتصال</button>` : ""}<span style="flex:1"></span><button class="btn ghost" data-r="0">انصراف</button><button class="btn primary" data-r="1">ذخیره</button>`,
    onOpen: (m, close) => {
      const sync = () => {
        const a = $("#acAuth", m).value;
        $("#acKeyF", m).hidden = !["header", "query"].includes(a); $("#acUserF", m).hidden = a !== "basic"; $("#acSecF", m).hidden = a === "none";
        $("#acSecL", m).textContent = I18N.t({ basic: "رمز", bearer: "توکن", header: "مقدار کلید", query: "مقدار کلید" }[a] || "");
      };
      $("#acAuth", m).onchange = sync; sync();
      const hdrDraw = () => { const box = $("#acHdr", m); box.innerHTML = atKv(hdr, "hdr");
        $$("[data-kk]", box).forEach((i) => (i.oninput = () => (hdr[i.dataset.kk.split(":")[1]][0] = i.value)));
        $$("[data-kvv]", box).forEach((i) => (i.oninput = () => (hdr[i.dataset.kvv.split(":")[1]][1] = i.value)));
        $$("[data-kon]", box).forEach((i) => (i.onchange = () => (hdr[i.dataset.kon.split(":")[1]][2] = i.checked)));
        $$("[data-kdel]", box).forEach((b) => (b.onclick = () => { hdr.splice(Number(b.dataset.kdel.split(":")[1]), 1); hdrDraw(); }));
        $("[data-kadd]", box).onclick = () => { hdr.push(["", "", true]); hdrDraw(); }; };
      hdrDraw();
      $$("[data-r]", m).forEach((b) => (b.onclick = async () => {
        if (b.dataset.r === "0") return close(null);
        if (b.dataset.r === "del") {
          if (!(await confirm2({ title: "حذف اتصال", body: `<p>${esc(`اتصال «${c.name}» و درخواست‌های ذخیره‌شده‌اش حذف شوند؟ لاگ درخواست‌ها می‌ماند.`)}</p>`, confirm: "حذف", danger: true }))) return;
          const x = await api("api_conn_delete", c.id); if (!x.ok) return toast(x.error, "error");
          AT.cur = null; close(null); toast("اتصال حذف شد", "ok"); return sshApi();
        }
        const auth = $("#acAuth", m).value;
        const p = { id: c.id || null, name: $("#acName", m).value.trim(), base_url: $("#acBase", m).value.trim(), auth, key_name: $("#acKey", m).value.trim(),
          verify: $("#acVerify", m).checked, timeout: Number($("#acTo", m).value) || 30, headers: hdr.filter((h) => h[0].trim()), notes: $("#acNotes", m).value,
          personal: $("#acPers", m) ? $("#acPers", m).checked : !AT.admin };
        const sec = $("#acSec", m).value;
        if (isNew && auth !== "none" && !sec) return toast(I18N.t("رمز، توکن یا کلید را وارد کنید."), "error");
        const x = await api("api_conn_save", p, sec, auth === "basic" ? $("#acUser", m).value : null);
        if (!x.ok) return toast(x.error, "error");
        close(x.id);
      }));
    } });
  if (v) { AT.cur = v; AT.open.add(v); toast("اتصال ذخیره شد", "ok"); sshApi(); }
}

/* ---------------------------------------------------------------- لاگ */
async function atLog() {
  const m = $("#atMain"), L = AT.log;
  const r = await api("api_log_list", L.q, null, L.offset, 100);
  if (!m.isConnected) return;
  if (!r.ok) { m.innerHTML = `<div class="panel"><div class="empty">${esc(r.error)}</div></div>`; return; }
  m.innerHTML = `<div class="toolbar"><input type="search" class="search" id="alQ" placeholder="${esc(I18N.t("جستجو در آدرس، کاربر، اتصال، کد…"))}" value="${esc(L.q)}">
      <span class="muted">${esc(r.all_users ? "همه‌ی کاربران" : "فقط درخواست‌های خودتان")} · ${num(r.total)}</span></div>
    <div class="table-wrap"><table class="grid"><thead><tr><th>زمان</th>${r.all_users ? "<th>کاربر</th>" : ""}<th>اتصال</th><th>متد</th><th>آدرس</th><th>نتیجه</th><th>زمان پاسخ</th></tr></thead><tbody>
      ${r.rows.map((x) => `<tr class="clickable" data-al="${x.id}"><td class="ltr">${esc(trFmt(x.ts))}</td>${r.all_users ? `<td class="ltr">${esc(x.user || "—")}</td>` : ""}<td class="bidi">${esc(x.conn_name)}</td>
        <td><span class="at-m m-${esc(x.method)}">${esc(x.method)}</span></td><td class="ltr at-lurl" title="${esc(x.url)}">${esc(x.url)}</td>
        <td>${x.status ? `<span class="tag ${x.status < 400 ? "ok" : "err"} ltr">${num(x.status)}</span>` : `<span class="tag err">${esc("خطا")}</span>`}</td><td class="ltr">${num(x.ms)} ms</td></tr>`).join("")
        || `<tr><td colspan="7"><div class="empty">${esc("هنوز درخواستی ثبت نشده است.")}</div></td></tr>`}</tbody></table></div>
    <div class="row" style="gap:8px;margin-top:8px">${L.offset ? `<button class="btn sm" id="alPrev">قبلی</button>` : ""}${L.offset + r.rows.length < r.total ? `<button class="btn sm" id="alNext">بعدی</button>` : ""}</div>`;
  let t = 0; $("#alQ").oninput = (e) => { clearTimeout(t); t = setTimeout(() => { L.q = e.target.value; L.offset = 0; atLog(); }, 350); };
  if ($("#alPrev")) $("#alPrev").onclick = () => { L.offset = Math.max(0, L.offset - 100); atLog(); };
  if ($("#alNext")) $("#alNext").onclick = () => { L.offset += 100; atLog(); };
  $$("[data-al]", m).forEach((tr) => (tr.onclick = async () => {
    const x = await api("api_log_get", Number(tr.dataset.al)); if (!x.ok) return toast(x.error, "error");
    const g = x.row; let hs = []; try { hs = JSON.parse(g.req_headers || "[]"); } catch (_) { /* */ }
    openModal({ title: `${g.method} — ${g.conn_name}`, wide: true,
      body: `<dl class="kv"><dt>زمان</dt><dd class="ltr">${esc(trFmt(g.ts))}</dd><dt>کاربر</dt><dd class="ltr">${esc(g.user || "—")}</dd><dt>آدرس</dt><dd class="ltr">${esc(g.url)}</dd>
          <dt>نتیجه</dt><dd class="ltr">${g.status ? esc(String(g.status)) : esc(g.error || "")} · ${num(g.ms)} ms · ${num(g.size || 0)} B</dd></dl>
        <h3>هدرهای درخواست</h3><pre class="at-pre ltr" data-no-i18n>${hs.map(([k, v]) => `${esc(k)}: ${esc(v)}`).join("\n")}</pre>
        ${g.req_body ? `<h3>Body درخواست</h3><pre class="at-pre ltr" data-no-i18n>${atJsonHtml(g.req_body)}</pre>` : ""}
        <h3>ابتدای پاسخ (۴ کیلوبایت)</h3><pre class="at-pre ltr" data-no-i18n>${g.resp_head ? atJsonHtml(g.resp_head) : "—"}</pre>
        <p class="hint">${esc("رمز، توکن، کلید و مقدار فیلدهای حساس در لاگ ماسک شده‌اند.")}</p>` });
  }));
}
document.addEventListener("keydown", (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key === "Enter" && S.page === "ssh" && typeof SSH !== "undefined" && SSH.tab === "api" && AT.view === "req" && !$("#modal").innerHTML) { e.preventDefault(); atSend(); }
});
