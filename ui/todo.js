"use strict";
/* ================================================================ کارهای من (1.47)
 * چک‌لیست کارهای تکراری: روزانه (روزهای کاری شرکت)، هفتگی (روزهای دلخواه)، ماهانه (شمسی یا میلادی)، یک‌بار.
 * «امروز»: کارهای امروز + جا مانده‌ها (تا تیک یا «رد کردن» می‌مانند) + نوبت‌های پیش رو. «چک‌لیست‌ها»: تعریف کارها و سابقه.
 * تاریخ‌ها در API میلادی ISO (YYYY-MM-DD، وقت محلی سرور)؛ نمایش با تقویم برنامه (trange.js). */
const TD = { tab: "today", data: null, seen: new Set(), busy: false, cal: null, day: null, month: null };
// شماره‌ی روز مثل Python: دوشنبه=۰ … یکشنبه=۶. ترتیب نمایش هفته از شنبه (شمسی) یا دوشنبه (میلادی).
const TD_WD = ["دوشنبه", "سه‌شنبه", "چهارشنبه", "پنجشنبه", "جمعه", "شنبه", "یکشنبه"];
const tdOrder = () => (trCal() === "j" ? [5, 6, 0, 1, 2, 3, 4] : [0, 1, 2, 3, 4, 5, 6]);
const tdDate = (iso) => { const [y, m, d] = String(iso).split("-").map(Number); return new Date(y, m - 1, d); };
const tdIso = (dt) => `${dt.getFullYear()}-${p2(dt.getMonth() + 1)}-${p2(dt.getDate())}`;
const tdWd = (iso) => (tdDate(iso).getDay() + 6) % 7;
/** «پنجشنبه ۱۴ آبان» (همین سال) یا با سال */
function tdFmt(iso, opt = {}) {
  if (!iso) return "—";
  const dt = tdDate(iso), o = trYmd(dt), cal = trCal();
  const mon = cal === "j" ? I18N.t(TR_JMON[o.m - 1]) : TR_GMON[o.m - 1];
  const yr = opt.year || o.y !== trYmd(new Date()).y ? ` ${o.y}` : "";
  const day = cal === "j" ? `${o.d} ${mon}${yr}` : `${mon} ${o.d}${yr}`;
  return opt.wd === false ? day : `${I18N.t(TD_WD[tdWd(iso)])} ${day}`;
}
function tdRel(iso) {
  const n = Math.round((tdDate(iso) - tdDate(TD.data.today)) / 86400000);
  if (n === 0) return I18N.t("امروز");
  if (n === 1) return I18N.t("فردا");
  return tdFmt(iso);
}
function tdRule(r) {
  const days = (ds) => tdOrder().filter((d) => ds.includes(d)).map((d) => I18N.t(TD_WD[d])).join(I18N.t("، "));
  if (r.type === "daily") return I18N.t("روزانه (روزهای کاری)");
  if (r.type === "weekly") return `${I18N.t("هفتگی")}: ${days(r.days || [])}`;
  if (r.type === "monthly") return `${I18N.t(r.cal === "g" ? "ماهانه (میلادی)" : "ماهانه")}: ${r.day ? I18N.t("روز {0}").replace("{0}", r.day) : I18N.t("آخرین روز ماه")}`;
  if (r.type === "once") return `${I18N.t("یک‌بار")}: ${tdFmt(r.date, { wd: false })}`;
  return "";
}
const tdItem = (id) => (TD.data.items || []).find((x) => x.id === id) || {};

async function todoRender() {
  const body = $("#todoBody"); if (!body) return;
  if (!TD.data) body.innerHTML = `<div class="empty">${esc(I18N.t("در حال بارگذاری…"))}</div>`;
  const r = await api("todo_state");
  if (!r.ok) { body.innerHTML = `<div class="empty">${esc(r.error)}</div>`; return; }
  tdSet(r);
}
function tdBadge(n) { const b = $("#navTodo"); if (b) { b.hidden = !n; b.textContent = n; } }

function tdDraw() {
  const D = TD.data, body = $("#todoBody"), open = (D.tasks || []).filter((t) => !t.done).length;
  const chk = D.badge - (D.tbadge || 0);
  body.innerHTML = `<header class="ph"><div><h1>کارهای من</h1><p>چک‌لیست، To-do و تقویم</p></div>
      <div class="ph-actions">${D.can_cfg && TD.tab !== "tasks" ? `<button class="btn" id="tdWork">روزهای کاری</button>` : ""}${TD.tab === "tasks"
        ? `<button class="btn primary" id="tdNewT">+ کار تازه</button>` : `<button class="btn primary" id="tdNew">+ کار تکراری تازه</button>`}</div></header>
    <div class="tabs big" id="tdTabs"><button data-t="today" class="${TD.tab === "today" ? "on" : ""}">امروز${chk ? `<span class="n">${chk}</span>` : ""}</button><button data-t="tasks" class="${TD.tab === "tasks" ? "on" : ""}">To-do${open ? `<span class="n ${D.tbadge ? "w" : ""}">${open}</span>` : ""}</button><button data-t="defs" class="${TD.tab === "defs" ? "on" : ""}">چک‌لیست‌ها<span class="n">${(D.items || []).length}</span></button>${(D.people || []).length ? `<button data-t="chat" class="${TD.tab === "chat" ? "on" : ""}">پیام‌ها${D.unread ? `<span class="n w">${D.unread}</span>` : ""}</button>` : ""}</div>
    <div id="tdPane"></div>`;
  $$("#tdTabs [data-t]").forEach((b) => (b.onclick = () => { TD.tab = b.dataset.t; tdDraw(); }));
  if (TD.tab === "chat") { $(".ph-actions", body).innerHTML = ""; return tdChat(); }
  if ($("#tdNew")) $("#tdNew").onclick = () => tdEdit(null);
  if ($("#tdNewT")) $("#tdNewT").onclick = () => tdTaskEdit(null, TD.day);
  if ($("#tdWork")) $("#tdWork").onclick = tdWorkdays;
  if (TD.tab === "defs") tdDefs(); else if (TD.tab === "tasks") tdTasks(); else tdToday();
}
function tdSet(r) { TD.data = r; tdBadge(r.badge + (r.unread || 0)); TD.month = null; tdDraw(); }
const tdTeam = () => (TD.data.people || []).length > 0;
const tdShareTag = (it) => (it.share && it.share.mode ? `<span class="td-tag i" title="${esc(I18N.t(it.share.mode === "one" ? "تیم: یک نفر برای همه" : "تیم: هر نفر جدا"))}">👥 ${esc(it.share.users && it.share.users.length ? it.share.users.length + 1 : I18N.t("همه"))}</span>` : "")
  + (it.mine === false ? `<span class="td-tag" title="${esc(I18N.t("سازنده"))}">${esc(I18N.t("از"))} <span class="ltr">${esc(it.owner)}</span></span>` : "");
const tdRemBtn = (kind) => (tdTeam() ? `<button class="btn sm ghost" data-rem="${kind}" title="${esc(I18N.t("یادآوری به کاربر دیگر"))}">یادآوری…</button>` : "");

function tdToday() {
  const D = TD.data, pane = $("#tdPane");
  if (!(D.items || []).length && !(D.tasks || []).length) {
    pane.innerHTML = `<div class="td-card td-empty"><p>هنوز کاری تعریف نکرده‌اید.</p><p class="hint">مثلاً «بررسی مانیتورینگ و تجهیزات» هر روز، «بکاپ از تجهیزات» هر چهارشنبه یا «لیست اضافه‌کاری» روز ۳۰ هر ماه.</p>
      <button class="btn primary" id="tdNew2">+ کار تکراری تازه</button> <button class="btn" id="tdNew3">+ کار تازه (To-do)</button></div>`;
    $("#tdNew2").onclick = () => tdEdit(null); $("#tdNew3").onclick = () => tdTaskEdit(null); return;
  }
  const rows = D.items_today, done = rows.filter((x) => x.status).length;
  const row = (x) => {
    const it = tdItem(x.id), st = x.status;
    const by = x.by && x.by !== TD.data.me ? ` <span>${esc(I18N.t("توسط"))}</span> <span class="ltr">${esc(x.by)}</span>` : "";
    const sub = st === "done" ? `<small><span>${esc(I18N.t("انجام شد"))}</span> <span class="ltr">${fmtTime(x.at).slice(0, 5)}</span>${by}${x.mnote ? ` — <span dir="auto" data-no-i18n>${esc(x.mnote)}</span>` : ""}</small>`
      : st === "skip" ? `<small>${esc(I18N.t("رد شد"))}${by}${x.mnote ? ` — <span dir="auto" data-no-i18n>${esc(x.mnote)}</span>` : ""}</small>`
      : it.time ? `<small><span>${esc(I18N.t("ساعت یادآوری"))}</span> <span class="ltr">${esc(it.time)}</span>${it.email ? ` <span>${esc(I18N.t("+ ایمیل"))}</span>` : ""}</small>`
      : it.note ? `<small dir="auto" data-no-i18n>${esc(it.note)}</small>` : "";
    return `<div class="td-row ${st} ${x.remind ? "due" : ""}" data-id="${x.id}" data-due="${x.due}">
      <button class="td-box" data-a="${st ? "undo" : "done"}" title="${esc(I18N.t(st ? "برداشتن تیک" : "انجام شد"))}">${st === "done" ? "✓" : st === "skip" ? "–" : ""}</button>
      <span class="t"><span class="tt" dir="auto" data-no-i18n>${esc(it.title)}</span>${sub}</span>
      ${tdShareTag(it)}<span class="td-tag">${esc(tdRule(it.rule))}</span>
      <span class="td-acts">${st ? `<button class="btn sm ghost" data-a="note">یادداشت</button>` : `<button class="btn sm ghost" data-a="skip">رد کردن</button>${tdRemBtn("item")}`}</span></div>`;
  };
  const lateRow = (x) => {
    const it = tdItem(x.id), n = x.dues.length;
    const when = n === 1 ? I18N.t("نوبت {0} — انجام نشد").replace("{0}", tdFmt(x.dues[0]))
      : I18N.t("{0} نوبت از {1}").replace("{0}", n).replace("{1}", tdFmt(x.dues[0]));
    const days = Math.round((tdDate(D.today) - tdDate(x.dues[0])) / 86400000);
    return `<div class="td-row late" data-id="${x.id}" data-late="1">
      <button class="td-box" data-a="done" title="${esc(I18N.t("انجام شد"))}"></button>
      <span class="t"><span class="tt" dir="auto" data-no-i18n>${esc(it.title)}</span><small>${esc(when)}</small></span>
      ${tdShareTag(it)}<span class="td-tag w">${esc(I18N.t(days === 1 ? "۱ روز دیر" : "{0} روز دیر").replace("{0}", days))}</span>
      <span class="td-acts"><button class="btn sm" data-a="skip">رد کردن</button>${tdRemBtn("item")}</span></div>`;
  };
  const ups = D.upcoming.length ? D.upcoming.map((u) => `<div class="r"><span>${esc(tdRel(u.due))}</span><span dir="auto" data-no-i18n>${esc(tdItem(u.id).title)}</span></div>`).join("")
    : `<p class="muted">${esc(I18N.t("نوبتی در پیش نیست."))}</p>`;
  pane.innerHTML = `<div class="td-grid"><div class="td-card">
      <h3><span>${esc(tdFmt(D.today, { year: true }))}</span><span class="muted td-cnt">${esc(I18N.t("{0} از {1} انجام شده").replace("{0}", done).replace("{1}", rows.length))}</span></h3>
      <div class="td-prog"><i style="width:${rows.length ? Math.round((done / rows.length) * 100) : 0}%"></i></div>
      ${D.late.length ? `<div class="td-sec w">⚠ ${esc(I18N.t("جا مانده"))}</div>${D.late.map(lateRow).join("")}` : ""}
      <div class="td-sec">${esc(I18N.t("امروز"))}</div>
      ${rows.length ? rows.map(row).join("") : `<p class="muted">${esc(I18N.t("امروز کاری ندارید."))}</p>`}
      ${tdTodayTasks()}
    </div>
    <div class="td-card td-up"><h3>پیش رو</h3>${ups}
      <p class="hint">با «یادداشت» می‌توانید برای هر تیک توضیح کوتاه بنویسید. سابقه‌ی هر کار در «چک‌لیست‌ها» دیده می‌شود.</p></div></div>`;
  $$("#tdPane .td-row:not(.tk) [data-a]").forEach((b) => (b.onclick = () => tdAct(b)));
  tdTaskBind();
  tdRemBind();
}

async function tdAct(b) {
  if (TD.busy) return;
  const row = b.closest(".td-row"), id = Number(row.dataset.id), a = b.dataset.a;
  const late = row.dataset.late ? (TD.data.late.find((x) => x.id === id) || {}).dues || [] : null;
  const dues = late || [row.dataset.due];
  let status = a === "done" ? "done" : a === "skip" ? "skip" : a === "undo" ? "" : null, note = "";
  if (a === "skip" && late && late.length > 1) {
    if (!(await confirm2({ title: I18N.t("رد کردن"), body: `<p>${esc(I18N.t("همه‌ی {0} نوبت جامانده‌ی این کار رد شوند؟").replace("{0}", late.length))}</p>`, confirm: I18N.t("رد کردن") }))) return;
  }
  if (a === "note") {
    const cur = TD.data.items_today.find((x) => x.id === id) || {};
    const v = await openModal({ title: I18N.t("یادداشت"), body: `<label class="field wide"><span>${esc(tdItem(id).title)}</span><input id="tdNote" maxlength="300" value="${esc(cur.mnote || "")}" autofocus></label>`,
      foot: `<button class="btn ghost" data-r="0">لغو</button><button class="btn primary" data-r="1">ذخیره</button>`,
      onOpen: (m, close) => { $$("[data-r]", m).forEach((x) => (x.onclick = () => close(x.dataset.r === "1" ? $("#tdNote").value : null)));
        $("#tdNote", m).onkeydown = (e) => { if (e.key === "Enter") close($("#tdNote").value); }; } });
    if (v === null) return;
    status = cur.status; note = v;
  }
  TD.busy = true;
  try {
    const r = await api("todo_mark", id, dues, status, note);
    if (!r.ok) return toast(r.error, "error");
    tdSet(r);
  } finally { TD.busy = false; }
}

function tdDefs() {
  const D = TD.data, pane = $("#tdPane"), st = {};
  D.defs.forEach((x) => (st[x.id] = x));
  if (!(D.items || []).length) { TD.tab = "today"; return tdToday(); }
  pane.innerHTML = `<div class="td-card"><div class="td-scroll"><table class="td-tbl"><thead><tr><th>کار</th><th>تکرار</th><th>نوبت بعد</th><th>۳۰ روز اخیر</th><th></th></tr></thead><tbody>
    ${D.items.map((it) => { const s = st[it.id] || {}, late = D.late.some((x) => x.id === it.id);
      return `<tr class="${it.active ? "" : "off"}" data-id="${it.id}"><td><b dir="auto" data-no-i18n>${esc(it.title)}</b>${it.note ? `<small class="muted" dir="auto" data-no-i18n>${esc(it.note)}</small>` : ""}${it.active ? "" : `<small class="muted">${esc(I18N.t("غیرفعال"))}</small>`}<div class="td-tags">${tdShareTag(it)}</div></td>
        <td>${esc(tdRule(it.rule))}${it.time ? `<small class="muted"><span class="ltr">${esc(it.time)}</span>${it.email ? ` <span>${esc(I18N.t("+ ایمیل"))}</span>` : ""}</small>` : ""}</td>
        <td>${late ? `<span class="td-tag w">${esc(I18N.t("جا مانده"))}</span>` : s.next ? esc(tdRel(s.next)) : "—"}</td>
        <td>${s.n30 ? `<span class="td-tag ${s.done30 === s.n30 ? "ok" : ""}">${esc(I18N.t("{0} از {1}").replace("{0}", s.done30).replace("{1}", s.n30))}</span>` : "—"}</td>
        <td class="td-btns">${it.mine !== false ? `<button class="btn sm" data-a="edit">ویرایش</button>` : ""}<button class="btn sm ghost" data-a="hist">سابقه</button>${it.mine !== false ? `<button class="btn sm danger-ghost" data-a="del">حذف</button>` : ""}</td></tr>`; }).join("")}
    </tbody></table></div></div>`;
  $$("#tdPane [data-a]").forEach((b) => (b.onclick = async () => {
    const id = Number(b.closest("tr").dataset.id), it = tdItem(id);
    if (b.dataset.a === "edit") return tdEdit(it);
    if (b.dataset.a === "hist") return tdHist(it);
    if (!(await confirm2({ title: I18N.t("حذف کار"), body: `<p>${esc(I18N.t("«{0}» و همه‌ی سابقه‌ی تیک‌هایش حذف شود؟").replace("{0}", it.title))}</p>`, confirm: I18N.t("حذف"), danger: true }))) return;
    const r = await api("todo_delete", id); if (!r.ok) return toast(r.error, "error");
    tdSet(r);
  }));
}

async function tdHist(it) {
  const r = await api("todo_history", it.id); if (!r.ok) return toast(r.error, "error");
  const rows = r.rows.length ? r.rows.map((x) => `<tr><td>${esc(tdFmt(x.due, { year: true }))}</td><td><span class="td-tag ${x.status === "done" ? "ok" : ""}">${esc(I18N.t(x.status === "done" ? "انجام شد" : "رد شد"))}</span></td>
      <td class="ltr">${fmtDate(x.at)}</td>${tdTeam() ? `<td class="ltr">${esc(x.user || "")}</td>` : ""}<td dir="auto" data-no-i18n>${esc(x.note || "")}</td></tr>`).join("")
    : `<tr><td colspan="5" class="muted">${esc(I18N.t("هنوز تیکی ثبت نشده است."))}</td></tr>`;
  openModal({ title: `${I18N.t("سابقه")}: ${it.title}`, wide: true, body: `<div class="td-scroll"><table class="td-tbl"><tbody>${rows}</tbody></table></div>
    <p class="hint">${esc(I18N.t("نوبت‌هایی که نه تیک خورده‌اند و نه رد شده‌اند اینجا نیستند؛ تا ۶۰ روز در «امروز» به‌عنوان جا مانده دیده می‌شوند."))}</p>` });
}

/* ---------------------------------------------------------------- انتخاب تاریخ با تقویم (یک روز) */
function tdPick(input) {
  if (trPopClose()) return;
  const cal = trCal(), cur = trParse(input.value, "00:00");
  const C = { view: trYmd(cur ? new Date(cur * 1000) : new Date()) };
  const pop = document.createElement("div");
  pop.className = "trpop td-pop";
  pop.innerHTML = `<div class="trcus"><div class="trcal"></div></div>`;
  document.body.appendChild(pop);
  const bb = input.getBoundingClientRect(), pw = pop.offsetWidth, ph = pop.offsetHeight;
  let x = bb.left, y = bb.bottom + 4;
  if (x + pw > window.innerWidth - 8) x = window.innerWidth - pw - 8;
  if (y + ph > window.innerHeight - 8) y = Math.max(8, bb.top - ph - 4);
  pop.style.left = Math.max(8, x) + "px"; pop.style.top = y + "px";
  const draw = () => {
    const v = C.view, n = trMonthLen(v.y, v.m), first = trDay(v.y, v.m, 1);
    const wd0 = cal === "j" ? (first.getDay() + 1) % 7 : (first.getDay() + 6) % 7;
    const heads = cal === "j" ? ["ش", "ی", "د", "س", "چ", "پ", "ج"] : ["Mo", "Tu", "We", "Th", "Fr", "Sa", "Su"];
    const sel = trParse(input.value, "00:00"), sk = sel && trFmtDay(sel), today = trFmtDay(Date.now() / 1000);
    let cells = "";
    for (let i = 0; i < wd0; i++) cells += `<i></i>`;
    for (let d = 1; d <= n; d++) { const k = trFmtDay(trDay(v.y, v.m, d).getTime() / 1000); cells += `<button type="button" data-d="${d}" class="${k === sk ? "end" : ""} ${k === today ? "today" : ""}">${d}</button>`; }
    $(".trcal", pop).innerHTML = `<div class="trcalh"><button type="button" class="iconbtn" data-m="-1">‹</button><b>${esc(cal === "j" ? I18N.t(TR_JMON[v.m - 1]) : TR_GMON[v.m - 1])} ${v.y}</b><button type="button" class="iconbtn" data-m="1">›</button></div>
      <div class="trgrid ${cal === "j" ? "" : "ltrcal"}">${heads.map((h) => `<s>${esc(I18N.t(h))}</s>`).join("")}${cells}</div>`;
    $$("[data-m]", pop).forEach((b) => (b.onclick = () => { let { y, m } = C.view; m += Number(b.dataset.m); if (m < 1) { m = 12; y--; } if (m > 12) { m = 1; y++; } C.view = { y, m, d: 1 }; draw(); }));
    $$("[data-d]", pop).forEach((b) => (b.onclick = () => { input.value = trFmtDay(trDay(v.y, v.m, Number(b.dataset.d)).getTime() / 1000); input.dispatchEvent(new Event("input")); pop.remove(); input.focus(); }));
  };
  draw();
  pop.addEventListener("keydown", (e) => { if (e.key === "Escape") { e.preventDefault(); e.stopPropagation(); pop.remove(); input.focus(); } });
}
const tdDateField = (id, label, iso, attrs = "") => `<div class="field" ${attrs}><span>${esc(I18N.t(label))}</span><div class="td-dt"><input id="${id}" class="ltr" spellcheck="false" value="${iso ? trFmtDay(tdDate(iso).getTime() / 1000) : ""}" placeholder="${trCal() === "j" ? "1405/08/15" : "2026-11-06"}"><button type="button" class="btn sm" data-tr="open" data-pick="${id}" title="${esc(I18N.t("تقویم"))}">📅</button></div></div>`;
const tdReadDate = (id) => { const ts = trParse($("#" + id).value, "00:00"); return ts ? tdIso(new Date(ts * 1000)) : null; };

/* ---------------------------------------------------------------- تعریف و ویرایش کار */
function tdEdit(it) {
  const D = TD.data, r = (it && it.rule) || { type: "daily" };
  const E = { type: r.type, days: [...(r.days || [])], day: r.day ?? 30, share: (it && it.share && it.share.mode) || "", mem: [...((it && it.share && it.share.users) || [])] };
  const chips = (sel, attr) => tdOrder().map((d) => `<button type="button" class="${sel.includes(d) ? "on" : ""}" ${attr}="${d}">${esc(I18N.t(TD_WD[d]))}</button>`).join("");
  const dayOpts = [`<option value="0" ${E.day === 0 ? "selected" : ""}>${esc(I18N.t("آخرین روز ماه"))}</option>`]
    .concat(Array.from({ length: 31 }, (_, i) => `<option value="${i + 1}" ${E.day === i + 1 ? "selected" : ""}>${i + 1}</option>`)).join("");
  const body = `<div class="form-grid">
    <label class="field wide"><span>عنوان</span><input id="tdTitle" maxlength="120" value="${esc((it && it.title) || "")}" autofocus></label>
    <label class="field wide"><span>توضیح (اختیاری)</span><input id="tdNoteF" maxlength="500" value="${esc((it && it.note) || "")}"></label>
    <div class="field wide"><span>تکرار</span><div class="seg" id="tdType">${[["daily", "روزانه"], ["weekly", "هفتگی"], ["monthly", "ماهانه"], ["once", "یک‌بار"]].map(([k, t]) => `<button type="button" data-v="${k}" class="${E.type === k ? "on" : ""}">${esc(I18N.t(t))}</button>`).join("")}</div></div>
    <div class="field wide" data-for="daily"><span>روزهای کاری</span><div class="muted td-wdnote">${esc(tdOrder().filter((d) => D.workdays.includes(d)).map((d) => I18N.t(TD_WD[d])).join(I18N.t("، ")))}</div></div>
    <div class="field wide" data-for="weekly"><span>روزهای هفته</span><div class="td-days" id="tdDays">${chips(E.days, "data-wd")}</div></div>
    <label class="field" data-for="monthly"><span>روز ماه</span><select id="tdDay">${dayOpts}</select></label>
    <div class="field" data-for="monthly"><span>تقویم</span><div class="muted td-wdnote">${esc(I18N.t(((it && it.rule.cal) || trCal()) === "g" ? "میلادی" : "شمسی"))}</div></div>
    ${tdDateField("tdOnce", "تاریخ", r.date || D.today, 'data-for="once"')}
    ${tdDateField("tdStart", "از تاریخ", (it && it.start) || D.today)}
    <label class="field"><span>ساعت یادآوری (اختیاری)</span><input id="tdTime" class="ltr" placeholder="09:30" value="${esc((it && it.time) || "")}"></label>
    <div class="field wide"><label class="switch"><input type="checkbox" id="tdEmail" ${it && it.email ? "checked" : ""}><span class="track"><span class="thumb"></span></span><span>ایمیل یادآوری هم فرستاده شود</span></label></div>
    <label class="field wide" data-email><span>ایمیل به (خالی = گیرندگان تنظیمات «اعلان‌ها»)</span><input id="tdTo" class="ltr" placeholder="name@example.com" value="${esc((it && it.email_to) || "")}"></label>
    ${D.mail_ok ? "" : `<p class="hint warn wide" data-email>${esc(I18N.t("سرور ایمیل یا گیرنده در تنظیمات «اعلان‌ها» تعریف نشده است؛ ایمیل فرستاده نمی‌شود."))}</p>`}
    ${tdTeam() ? `<div class="field wide"><span>اشتراک</span><div class="seg" id="tdShare">${[["", "شخصی"], ["one", "تیم: یک نفر برای همه"], ["each", "تیم: هر نفر جدا"]].map(([k, t]) => `<button type="button" data-v="${k}">${esc(I18N.t(t))}</button>`).join("")}</div></div>
    <div class="field wide" data-share><span>اعضا (هیچ‌کدام = همه‌ی کاربران)</span><div class="td-days" id="tdMem">${TD.data.people.map((u) => `<button type="button" data-u="${esc(u.username)}" class="ltr">${esc(u.username)}</button>`).join("")}</div></div>` : ""}
    ${it ? `<div class="field wide"><label class="switch"><input type="checkbox" id="tdActive" ${it.active ? "checked" : ""}><span class="track"><span class="thumb"></span></span><span>فعال</span></label></div>` : ""}
  </div>
  <p class="hint" data-for="monthly">اگر ماه آن روز را نداشت (مثل ۳۱ مهر یا ۳۰ اسفند)، آخرین روز همان ماه.</p>
  <p class="hint">کاری که انجام نشود روزهای بعد با برچسب «جا مانده» بالای فهرست می‌آید تا تیک بزنید یا «رد کردن» را بزنید. ساعت یادآوری: اعلان داخل برنامه (و ایمیل اگر روشن باشد) اگر تا آن ساعت تیک نخورده باشد.</p>`;
  openModal({ title: I18N.t(it ? "ویرایش کار" : "کار تکراری تازه"), body,
    foot: `<button class="btn ghost" data-r="0">لغو</button><button class="btn primary" data-r="1">ذخیره</button>`,
    onOpen: (m, close) => {
      const sync = () => {
        $$("#tdType button", m).forEach((b) => b.classList.toggle("on", b.dataset.v === E.type));
        $$("[data-for]", m).forEach((x) => (x.hidden = x.dataset.for !== E.type));
        const em = $("#tdEmail", m).checked; $$("[data-email]", m).forEach((x) => (x.hidden = !em));
        $$("#tdShare button", m).forEach((b) => b.classList.toggle("on", b.dataset.v === E.share));
        $$("[data-share]", m).forEach((x) => (x.hidden = !E.share));
        $$("#tdMem [data-u]", m).forEach((b) => b.classList.toggle("on", E.mem.includes(b.dataset.u)));
      };
      sync();
      $$("#tdType button", m).forEach((b) => (b.onclick = () => { E.type = b.dataset.v; m._dirty = true; sync(); }));
      $$("#tdDays [data-wd]", m).forEach((b) => (b.onclick = () => { const d = Number(b.dataset.wd); E.days = E.days.includes(d) ? E.days.filter((x) => x !== d) : [...E.days, d]; b.classList.toggle("on"); m._dirty = true; }));
      $("#tdEmail", m).onchange = sync;
      $$("#tdShare button", m).forEach((b) => (b.onclick = () => { E.share = b.dataset.v; m._dirty = true; sync(); }));
      $$("#tdMem [data-u]", m).forEach((b) => (b.onclick = () => { const u = b.dataset.u; E.mem = E.mem.includes(u) ? E.mem.filter((x) => x !== u) : [...E.mem, u]; m._dirty = true; sync(); }));
      $$("[data-pick]", m).forEach((b) => (b.onclick = () => tdPick($("#" + b.dataset.pick))));
      $("[data-r='0']", m).onclick = () => close(null);
      $("[data-r='1']", m).onclick = (e) => withSpin(e.currentTarget, async () => {
        const start = tdReadDate("tdStart"), once = tdReadDate("tdOnce");
        if (!start) return toast(I18N.t("«از تاریخ» معتبر نیست."), "warn");
        if (E.type === "once" && !once) return toast(I18N.t("تاریخ کار یک‌باره معتبر نیست."), "warn");
        const rule = { type: E.type, cal: (it && it.rule.cal) || trCal() };
        if (E.type === "weekly") rule.days = E.days;
        if (E.type === "monthly") rule.day = Number($("#tdDay", m).value);
        if (E.type === "once") rule.date = once;
        const p = { id: it ? it.id : null, title: $("#tdTitle", m).value, note: $("#tdNoteF", m).value, rule, start: E.type === "once" ? (once < start ? once : start) : start,
          time: trDigits($("#tdTime", m).value).trim(), email: $("#tdEmail", m).checked, email_to: $("#tdTo", m).value, active: it ? $("#tdActive", m).checked : true,
          share: E.share ? { mode: E.share, users: E.mem } : {} };
        const r2 = await api("todo_save", p); if (!r2.ok) return toast(r2.error, "error");
        close(true); tdSet(r2); toast(I18N.t("ذخیره شد"), "ok");
      });
    } });
}

async function tdWorkdays() {
  const D = TD.data; let sel = [...D.workdays];
  openModal({ title: I18N.t("روزهای کاری"), body: `<p class="muted">${esc(I18N.t("کارهای «روزانه» فقط در این روزها نوبت دارند (برای همه‌ی کاربران)."))}</p>
      <div class="td-days" id="tdWD">${tdOrder().map((d) => `<button type="button" class="${sel.includes(d) ? "on" : ""}" data-wd="${d}">${esc(I18N.t(TD_WD[d]))}</button>`).join("")}</div>`,
    foot: `<button class="btn ghost" data-r="0">لغو</button><button class="btn primary" data-r="1">ذخیره</button>`,
    onOpen: (m, close) => {
      $$("[data-wd]", m).forEach((b) => (b.onclick = () => { const d = Number(b.dataset.wd); sel = sel.includes(d) ? sel.filter((x) => x !== d) : [...sel, d]; b.classList.toggle("on"); }));
      $("[data-r='0']", m).onclick = () => close(null);
      $("[data-r='1']", m).onclick = async () => { const r = await api("todo_cfg_save", sel); if (!r.ok) return toast(r.error, "error"); close(true); tdSet(r); };
    } });
}

/* ---------------------------------------------------------------- 1.48: To-do (کار یک‌باره با سررسید) و تقویم */
const tdTask = (id) => (TD.data.tasks || []).find((x) => x.id === id);
const tdDays = (iso) => Math.round((tdDate(iso) - tdDate(TD.data.today)) / 86400000);
function tdTaskRow(t, opt = {}) {
  const late = !t.done && t.due && t.due < TD.data.today;
  const due = t.due ? `<span class="td-tag ${late ? "e" : t.due === TD.data.today ? "w" : ""}">${esc(tdRel(t.due))}${t.time ? ` <span class="ltr">${esc(t.time)}</span>` : ""}</span>` : "";
  const sub = t.done ? `<small><span>${esc(I18N.t("انجام شد"))}</span> <span class="ltr">${fmtDate(t.done_at)}</span></small>`
    : t.note ? `<small dir="auto" data-no-i18n>${esc(t.note.split("\n")[0])}</small>` : "";
  return `<div class="td-row tk ${t.done ? "done" : ""} ${t.remind ? "due" : ""} ${late ? "late2" : ""}" data-tid="${t.id}">
    <button class="td-box" data-ta="${t.done ? "undo" : "done"}" title="${esc(I18N.t(t.done ? "برداشتن تیک" : "انجام شد"))}">${t.done ? "✓" : ""}</button>
    <span class="t"><span class="tt" dir="auto" data-no-i18n>${t.prio ? `<b class="td-star" title="${esc(I18N.t("مهم"))}">★</b> ` : ""}${esc(t.title)}</span>${sub}</span>
    ${t.assignee && t.mine ? `<span class="td-tag i" title="${esc(I18N.t("سپرده به"))}">→ <span class="ltr">${esc(t.assignee)}</span></span>` : ""}${!t.mine ? `<span class="td-tag i" title="${esc(I18N.t("سپرده‌شده به شما"))}">${esc(I18N.t("از"))} <span class="ltr">${esc(t.owner)}</span></span>` : ""}
    ${opt.nodue ? "" : due}${t.email && !t.done ? `<span class="td-tag" title="${esc(I18N.t("ایمیل یادآوری"))}">✉</span>` : ""}
    <span class="td-acts">${t.done ? "" : tdRemBtn("task")}${t.mine ? `<button class="btn sm ghost" data-ta="edit">ویرایش</button><button class="btn sm danger-ghost" data-ta="del">حذف</button>` : ""}</span></div>`;
}
function tdTodayTasks() {
  const ts = (TD.data.tasks || []).filter((t) => !t.done && t.due && t.due <= TD.data.today).sort(tdTaskSort);
  if (!ts.length) return "";
  return `<div class="td-sec">${esc(I18N.t("To-do امروز و گذشته"))}</div>${ts.map((t) => tdTaskRow(t)).join("")}`;
}
const tdTaskSort = (a, b) => (b.prio - a.prio) || (a.due || "9999").localeCompare(b.due || "9999") || (a.time || "99").localeCompare(b.time || "99") || a.id - b.id;
function tdTaskBind() {
  $$("#tdPane .td-row.tk [data-ta]").forEach((b) => (b.onclick = async () => {
    const id = Number(b.closest(".td-row").dataset.tid), a = b.dataset.ta, t = tdTask(id) || { id, title: "" };
    if (a === "edit") return tdTaskEdit(t);
    if (a === "del" && !(await confirm2({ title: I18N.t("حذف کار"), body: `<p>${esc(I18N.t("«{0}» حذف شود؟").replace("{0}", t.title))}</p>`, confirm: I18N.t("حذف"), danger: true }))) return;
    if (TD.busy) return; TD.busy = true;
    try {
      const r = a === "del" ? await api("task_delete", id) : await api("task_done", id, a === "done");
      if (!r.ok) return toast(r.error, "error");
      tdSet(r);
    } finally { TD.busy = false; }
  }));
}
function tdTasks() {
  const D = TD.data, pane = $("#tdPane"), T = D.today, ts = (D.tasks || []).slice().sort(tdTaskSort);
  const open = ts.filter((t) => !t.done), done = ts.filter((t) => t.done).sort((a, b) => b.done_at - a.done_at);
  const pick = TD.day;
  const groups = pick ? [[I18N.t("کارهای {0}").replace("{0}", tdFmt(pick)), open.filter((t) => t.due === pick)]] : [
    ["سررسید گذشته", open.filter((t) => t.due && t.due < T), "e"],
    ["امروز", open.filter((t) => t.due === T), "w"],
    ["فردا", open.filter((t) => t.due && tdDays(t.due) === 1)],
    ["تا ۷ روز آینده", open.filter((t) => t.due && tdDays(t.due) > 1 && tdDays(t.due) <= 7)],
    ["بعداً", open.filter((t) => t.due && tdDays(t.due) > 7)],
    ["بدون تاریخ", open.filter((t) => !t.due)]];
  const list = groups.filter((g) => g[1].length).map(([h, xs, c]) => `<div class="td-sec ${c || ""}">${esc(I18N.t(h))} <span class="muted">(${xs.length})</span></div>${xs.map((t) => tdTaskRow(t, { nodue: !!pick })).join("")}`).join("")
    || `<p class="muted td-none">${esc(I18N.t(pick ? "برای این روز کار To-do ندارید." : "کار بازی ندارید."))}</p>`;
  const doneH = done.length && !pick ? `<details class="td-done"><summary>${esc(I18N.t("انجام‌شده‌ها (۳۰ روز اخیر)"))} <span class="muted">(${done.length})</span></summary>${done.map((t) => tdTaskRow(t)).join("")}</details>` : "";
  pane.innerHTML = `<div class="td-grid"><div class="td-card">
      <div class="td-quick"><input id="tdQ" maxlength="200" placeholder="${esc(I18N.t("کار تازه… (Enter)"))}" dir="auto"><input id="tdQd" class="ltr" spellcheck="false" value="${pick ? trFmtDay(tdDate(pick).getTime() / 1000) : ""}" placeholder="${esc(I18N.t("بدون تاریخ"))}" title="${esc(I18N.t("سررسید"))}"><button type="button" class="btn sm" data-tr="open" id="tdQp" title="${esc(I18N.t("تقویم"))}">📅</button><button type="button" class="btn sm ghost td-star-btn" id="tdQs" title="${esc(I18N.t("مهم"))}">☆</button><button class="btn sm primary" id="tdQa">افزودن</button></div>
      ${pick ? `<div class="td-filter"><span class="chip">${esc(tdFmt(pick, { year: true }))}<button class="iconbtn sm" id="tdDayX" title="${esc(I18N.t("همه‌ی روزها"))}">×</button></span></div>` : ""}
      ${list}${doneH}</div>
    <div><div class="td-card" id="tdCal"></div><div class="td-card td-dayp" id="tdDayP" ${pick ? "" : "hidden"}></div></div></div>`;
  let star = 0;
  $("#tdQs").onclick = (e) => { star = 1 - star; e.currentTarget.textContent = star ? "★" : "☆"; e.currentTarget.classList.toggle("on", !!star); };
  $("#tdQp").onclick = () => tdPick($("#tdQd"));
  const add = (e) => withSpin($("#tdQa"), async () => {
    const title = $("#tdQ").value.trim(); if (!title) return $("#tdQ").focus();
    let due = "";
    if ($("#tdQd").value.trim()) { due = tdReadDate("tdQd"); if (!due) return toast(I18N.t("تاریخ سررسید معتبر نیست."), "warn"); }
    const r = await api("task_save", { title, due, prio: star }); if (!r.ok) return toast(r.error, "error");
    tdSet(r); setTimeout(() => $("#tdQ") && $("#tdQ").focus(), 50);
  });
  $("#tdQa").onclick = add;
  $("#tdQ").onkeydown = (e) => { if (e.key === "Enter") { e.preventDefault(); add(); } };
  if ($("#tdDayX")) $("#tdDayX").onclick = () => { TD.day = null; tdDraw(); };
  tdTaskBind();
  tdRemBind();
  tdCalDraw();
}

/* تقویم ماه: نقطه برای روزهای دارای To-do (قرمز: گذشته و باز) و چک‌لیست؛ کلیک ← کارهای همان روز */
async function tdCalDraw() {
  const box = $("#tdCal"); if (!box) return;
  const cal = trCal();
  if (!TD.cal) { const o = trYmd(tdDate(TD.data.today)); TD.cal = { y: o.y, m: o.m }; }
  const v = TD.cal, n = trMonthLen(v.y, v.m), first = trDay(v.y, v.m, 1), last = trDay(v.y, v.m, n);
  const key = `${v.y}-${v.m}-${cal}`;
  if (!TD.month || TD.month.key !== key) {
    const r = await api("todo_month", tdIso(first), tdIso(last)); if (!r.ok) return;
    TD.month = { key, ...r };
    if (!$("#tdCal")) return;
  }
  const M = TD.month, wd0 = cal === "j" ? (first.getDay() + 1) % 7 : (first.getDay() + 6) % 7;
  const heads = cal === "j" ? ["ش", "ی", "د", "س", "چ", "پ", "ج"] : ["Mo", "Tu", "We", "Th", "Fr", "Sa", "Su"];
  let cells = "";
  for (let i = 0; i < wd0; i++) cells += `<i></i>`;
  for (let d = 1; d <= n; d++) {
    const iso = tdIso(trDay(v.y, v.m, d)), x = M.days[iso] || { t: [], td: [], c: [] };
    const dots = (x.t.length ? `<b class="${iso < M.today ? "e" : "a"}"></b>` : "") + (x.td.length && !x.t.length ? `<b class="d"></b>` : "") + (x.c.length ? `<b class="c"></b>` : "");
    cells += `<button type="button" data-iso="${iso}" class="${iso === TD.day ? "end" : ""} ${iso === M.today ? "today" : ""}">${d}<span class="td-dots">${dots}</span></button>`;
  }
  box.innerHTML = `<div class="trcalh"><button type="button" class="iconbtn" data-m="-1">‹</button><b>${esc(cal === "j" ? I18N.t(TR_JMON[v.m - 1]) : TR_GMON[v.m - 1])} ${v.y}</b><button type="button" class="iconbtn" data-m="1">›</button></div>
    <div class="trgrid td-calg ${cal === "j" ? "" : "ltrcal"}">${heads.map((h) => `<s>${esc(I18N.t(h))}</s>`).join("")}${cells}</div>
    <div class="td-legend"><span><b class="a"></b>${esc(I18N.t("To-do"))}</span><span><b class="e"></b>${esc(I18N.t("گذشته"))}</span><span><b class="c"></b>${esc(I18N.t("چک‌لیست"))}</span></div>`;
  $$("[data-m]", box).forEach((b) => (b.onclick = () => { let { y, m } = TD.cal; m += Number(b.dataset.m); if (m < 1) { m = 12; y--; } if (m > 12) { m = 1; y++; } TD.cal = { y, m }; tdCalDraw(); }));
  $$("[data-iso]", box).forEach((b) => (b.onclick = () => { TD.day = TD.day === b.dataset.iso ? null : b.dataset.iso; tdDraw(); }));
  tdDayPanel();
}
function tdDayPanel() {
  const P = $("#tdDayP"); if (!P || !TD.day) return;
  const x = (TD.month && TD.month.days[TD.day]) || { t: [], td: [], c: [] };
  const name = (id) => (tdTask(id) || (TD.month.tasks || {})[id] || {}).title || "";
  const items = x.c.map((id) => `<div class="r"><span class="td-tag">${esc(I18N.t("چک‌لیست"))}</span><span dir="auto" data-no-i18n>${esc(tdItem(id).title || "")}</span></div>`).join("")
    + x.td.map((id) => `<div class="r done"><span class="td-tag ok">✓</span><span dir="auto" data-no-i18n>${esc(name(id))}</span></div>`).join("");
  P.innerHTML = `<h3><span>${esc(tdFmt(TD.day, { year: true }))}</span></h3>${items || `<p class="muted">${esc(I18N.t("کار چک‌لیست یا انجام‌شده‌ای در این روز نیست."))}</p>`}
    <button class="btn sm" id="tdDayAdd">+ کار برای این روز</button>`;
  $("#tdDayAdd").onclick = () => tdTaskEdit(null, TD.day);
}

function tdTaskEdit(t, due) {
  const D = TD.data;
  const body = `<div class="form-grid">
    <label class="field wide"><span>عنوان</span><input id="tkTitle" maxlength="200" dir="auto" value="${esc((t && t.title) || "")}" autofocus></label>
    <label class="field wide"><span>توضیح (اختیاری)</span><textarea id="tkNote" rows="3" maxlength="1000" dir="auto">${esc((t && t.note) || "")}</textarea></label>
    ${tdDateField("tkDue", "سررسید (اختیاری)", (t && t.due) || due || "")}
    <label class="field"><span>ساعت (اختیاری)</span><input id="tkTime" class="ltr" placeholder="14:00" value="${esc((t && t.time) || "")}"></label>
    ${tdTeam() ? `<label class="field wide"><span>سپردن به</span><select id="tkAs"><option value="">${esc(I18N.t("— خودم —"))}</option>${TD.data.people.map((u) => `<option value="${esc(u.username)}" ${t && t.assignee === u.username ? "selected" : ""}>${esc(u.username)}</option>`).join("")}</select></label>` : ""}
    <div class="field wide"><label class="switch"><input type="checkbox" id="tkPrio" ${t && t.prio ? "checked" : ""}><span class="track"><span class="thumb"></span></span><span>مهم ★</span></label></div>
    <div class="field wide"><label class="switch"><input type="checkbox" id="tkEmail" ${t && t.email ? "checked" : ""}><span class="track"><span class="thumb"></span></span><span>ایمیل یادآوری روز سررسید</span></label></div>
    <label class="field wide" data-email><span>ایمیل به (خالی = گیرندگان تنظیمات «اعلان‌ها»)</span><input id="tkTo" class="ltr" placeholder="name@example.com" value="${esc((t && t.email_to) || "")}"></label>
    ${D.mail_ok ? "" : `<p class="hint warn wide" data-email>${esc(I18N.t("سرور ایمیل یا گیرنده در تنظیمات «اعلان‌ها» تعریف نشده است؛ ایمیل فرستاده نمی‌شود."))}</p>`}
  </div>
  <p class="hint">یادآوری: روز سررسید، از ساعت تعیین‌شده (بدون ساعت از اول روز) اعلان داخل برنامه؛ ایمیل در همان ساعت (بدون ساعت ۰۹:۰۰). کاری که سررسیدش بگذرد با رنگ قرمز در «سررسید گذشته» می‌ماند تا انجام شود.</p>`;
  openModal({ title: I18N.t(t ? "ویرایش کار" : "کار تازه"), body,
    foot: `<button class="btn ghost" data-r="0">لغو</button><button class="btn primary" data-r="1">ذخیره</button>`,
    onOpen: (m, close) => {
      const sync = () => { const em = $("#tkEmail", m).checked; $$("[data-email]", m).forEach((x) => (x.hidden = !em)); };
      sync(); $("#tkEmail", m).onchange = sync;
      $$("[data-pick]", m).forEach((b) => (b.onclick = () => tdPick($("#" + b.dataset.pick))));
      $("[data-r='0']", m).onclick = () => close(null);
      $("[data-r='1']", m).onclick = (e) => withSpin(e.currentTarget, async () => {
        let d = "";
        if ($("#tkDue", m).value.trim()) { d = tdReadDate("tkDue"); if (!d) return toast(I18N.t("تاریخ سررسید معتبر نیست."), "warn"); }
        const p = { id: t ? t.id : null, title: $("#tkTitle", m).value, note: $("#tkNote", m).value, due: d, time: trDigits($("#tkTime", m).value).trim(),
          prio: $("#tkPrio", m).checked ? 1 : 0, email: $("#tkEmail", m).checked, email_to: $("#tkTo", m).value, assignee: $("#tkAs", m) ? $("#tkAs", m).value : "" };
        const r = await api("task_save", p); if (!r.ok) return toast(r.error, "error");
        close(true); tdSet(r); toast(I18N.t("ذخیره شد"), "ok");
      });
    } });
}

/* ---------------------------------------------------------------- 1.49: یادآوری به کاربر دیگر و پیام‌ها */
const TD_SYS = new Set(["این کار به شما سپرده شد.", "این کار انجام شد."]);
function tdRemBind() {
  $$("#tdPane [data-rem]").forEach((b) => (b.onclick = () => {
    const row = b.closest(".td-row"), kind = b.dataset.rem, id = Number(kind === "task" ? row.dataset.tid : row.dataset.id);
    const title = kind === "task" ? (tdTask(id) || {}).title : tdItem(id).title;
    tdRemind(kind, id, title);
  }));
}
function tdRemind(kind, id, title) {
  const P = TD.data.people || [];
  const it = kind === "item" ? tdItem(id) : tdTask(id) || {};
  const pre = kind === "task" ? (it.mine ? it.assignee : it.owner) : ((it.share && it.share.users) || [])[0];
  openModal({ title: I18N.t("یادآوری به کاربر دیگر"), body: `<p class="td-ref">📌 <span dir="auto" data-no-i18n>${esc(title || "")}</span></p>
      <div class="form-grid"><label class="field wide"><span>به</span><select id="rmTo">${P.map((u) => `<option value="${esc(u.username)}" ${u.username === pre ? "selected" : ""}>${esc(u.username)}</option>`).join("")}</select></label>
      <label class="field wide"><span>پیام (اختیاری)</span><textarea id="rmTxt" rows="3" maxlength="2000" dir="auto" placeholder="${esc(I18N.t("مثلاً: لطفاً تا آخر وقت انجام بده"))}"></textarea></label></div>`,
    foot: `<button class="btn ghost" data-r="0">لغو</button><button class="btn primary" data-r="1">ارسال</button>`,
    onOpen: (m, close) => {
      $("[data-r='0']", m).onclick = () => close(null);
      $("[data-r='1']", m).onclick = (e) => withSpin(e.currentTarget, async () => {
        const r = await api("chat_send", $("#rmTo", m).value, $("#rmTxt", m).value, { kind, id }); if (!r.ok) return toast(r.error, "error");
        close(true); toast(I18N.t("یادآوری فرستاده شد"), "ok");
      });
    } });
}
const tdMsgText = (t) => (TD_SYS.has(t) ? esc(I18N.t(t)) : `<span dir="auto" data-no-i18n>${esc(t)}</span>`);
function tdMsgTime(ts) {
  const d = new Date(ts * 1000), hm = `${p2(d.getHours())}:${p2(d.getMinutes())}`;
  return tdIso(d) === tdIso(new Date()) ? hm : `${trFmtDay(ts)} ${hm}`;
}
function tdBubble(m, me) {
  const ref = m.ref_kind ? `<div class="td-ref">📌 <span class="muted">${esc(I18N.t(m.ref_kind === "task" ? "To-do" : "چک‌لیست"))}:</span> <span dir="auto" data-no-i18n>${esc(m.ref_title || "")}</span></div>` : "";
  return `<div class="td-msg ${m.sender === me ? "me" : ""}" data-mid="${m.id}">${ref}${m.text ? `<div class="tx">${tdMsgText(m.text)}</div>` : ""}<div class="tm ltr">${tdMsgTime(m.ts)}${m.sender === me && m.read_at ? " ✓✓" : ""}</div></div>`;
}
async function tdChat() {
  const pane = $("#tdPane");
  const r = await api("chat_list"); if (!r.ok) { pane.innerHTML = `<div class="empty">${esc(r.error)}</div>`; return; }
  if (!TD.peer || !r.peers.some((p) => p.username === TD.peer)) TD.peer = (r.peers[0] || {}).username || null;
  pane.innerHTML = `<div class="td-chat"><div class="td-card td-peers">${r.peers.map((p) => `<button class="td-peer ${p.username === TD.peer ? "on" : ""}" data-p="${esc(p.username)}">
      <span class="pn ltr">${esc(p.username)}</span>${p.unread ? `<span class="nav-count">${p.unread}</span>` : ""}
      <small class="muted">${p.last ? (p.last.ref_kind && !p.last.text ? "📌 " + esc(p.last.ref_title || "") : tdMsgText(p.last.text)) : esc(I18N.t("هنوز پیامی نیست"))}</small></button>`).join("")}</div>
    <div class="td-card td-thread"><div class="td-th-h ltr">${esc(TD.peer || "")}</div><div class="td-msgs" id="tdMsgs"></div>
      <div class="td-send"><textarea id="tdMsgIn" rows="2" maxlength="2000" dir="auto" placeholder="${esc(I18N.t("پیام… (Enter = ارسال، Shift+Enter = خط تازه)"))}"></textarea><button class="btn primary" id="tdMsgGo">ارسال</button></div></div></div>`;
  $$(".td-peer").forEach((b) => (b.onclick = () => { TD.peer = b.dataset.p; tdChat(); }));
  if (!TD.peer) return;
  const t = await api("chat_thread", TD.peer); if (!t.ok) return toast(t.error, "error");
  TD.chatLast = t.msgs.length ? t.msgs[t.msgs.length - 1].id : 0;
  const box = $("#tdMsgs");
  box.innerHTML = t.msgs.length ? t.msgs.map((m) => tdBubble(m, t.me)).join("") : `<p class="muted td-none">${esc(I18N.t("هنوز پیامی نیست"))}</p>`;
  box.scrollTop = box.scrollHeight;
  const pc = $(".td-peer.on .nav-count"); if (pc) pc.remove();
  const send = () => withSpin($("#tdMsgGo"), async () => {
    const v = $("#tdMsgIn").value; if (!v.trim()) return;
    const r2 = await api("chat_send", TD.peer, v); if (!r2.ok) return toast(r2.error, "error");
    $("#tdMsgIn").value = ""; await tdChatPoll(); $("#tdMsgIn").focus();
  });
  $("#tdMsgGo").onclick = send;
  $("#tdMsgIn").onkeydown = (e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); send(); } };
  // badge: پیام‌های این هم‌صحبت خوانده شد
  todoPoll();
}
async function tdChatPoll() {
  if (S.page !== "todo" || TD.tab !== "chat" || !TD.peer || !$("#tdMsgs")) return;
  const r = await api("chat_poll", TD.peer, TD.chatLast || 0); if (!r.ok || !r.msgs.length) return;
  const box = $("#tdMsgs"), atEnd = box.scrollHeight - box.scrollTop - box.clientHeight < 40;
  if (!TD.chatLast) box.innerHTML = "";
  box.insertAdjacentHTML("beforeend", r.msgs.map((m) => tdBubble(m, TD.data.me)).join(""));
  TD.chatLast = r.msgs[r.msgs.length - 1].id;
  if (atEnd || r.msgs.some((m) => m.sender === TD.data.me)) box.scrollTop = box.scrollHeight;
}
setInterval(() => { if (!document.hidden) tdChatPoll(); }, 4000);

/* ---------------------------------------------------------------- عدد نوار کناری و اعلان یادآوری (هر دقیقه) */
async function todoPoll() {
  if (typeof S === "undefined" || !S.state) return;
  const r = await api("todo_badge"); if (!r.ok) return;
  tdBadge(r.badge + (r.unread || 0));
  if (TD.data) TD.data.unread = r.unread || 0;
  const tb = $("#tdTabs [data-t=chat]");
  if (tb) { const n = $(".n", tb); if (r.unread) { if (n) n.textContent = r.unread; else tb.insertAdjacentHTML("beforeend", `<span class="n w">${r.unread}</span>`); } else if (n) n.remove(); }
  const lm = r.last_msg;
  if (lm && lm.id > (TD.lastMsg || 0)) {
    let seenId = 0; try { seenId = Number(sessionStorage.getItem("akrp_td_msg") || 0); } catch (e) { /* نادیده */ }
    if (lm.id > seenId && !(S.page === "todo" && TD.tab === "chat" && TD.peer === lm.sender))
      toast(`${I18N.t("پیام از {0}").replace("{0}", lm.sender)}: ${TD_SYS.has(lm.text) ? I18N.t(lm.text) : lm.text || "📌 " + (lm.ref_title || "")}`, "info");
    TD.lastMsg = lm.id; try { sessionStorage.setItem("akrp_td_msg", String(lm.id)); } catch (e) { /* نادیده */ }
  }
  let seen = TD.seen;
  try { seen = new Set(JSON.parse(sessionStorage.getItem("akrp_td_seen") || "[]")); } catch (e) { /* بدون sessionStorage ← فقط حافظه */ }
  for (const x of r.due || []) {
    const k = `${x.id}@${r.today}`;
    if (seen.has(k) || TD.seen.has(k)) continue;
    TD.seen.add(k); seen.add(k);
    toast(`${I18N.t("یادآوری")}: ${x.title}`, "warn");
  }
  try { sessionStorage.setItem("akrp_td_seen", JSON.stringify([...seen].slice(-200))); } catch (e) { /* نادیده */ }
  if (S.page === "todo" && TD.data && TD.tab !== "chat" && (r.badge !== TD.data.badge || r.today !== TD.data.today) && !$("#modalBack:not([hidden])")) todoRender();
}
setInterval(() => { if (!document.hidden) todoPoll(); }, 60000);
setTimeout(todoPoll, 4000);
