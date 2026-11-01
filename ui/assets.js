"use strict";
/* ================================================================ مدیریت دارایی (1.21)
 * فهرست دارایی‌ها (شناسه = سریال)، جزئیات با قطعه‌ها و تاریخچه، صف «در انتظار تأیید»، تاریخچه‌ی کل، اسکن و تنظیمات.
 * همه‌ی جدول‌ها table.grid هستند و با کلیک سرستون مرتب می‌شوند (TSORT در app.js). */

const AS = { tab: "list", list: [], status: "active", q: "", chStatus: "pending", changes: [], hist: [], hq: "", titles: {}, admin: false,
  canEdit: false, pendN: 0, timer: null, sel: new Set() };
const AS_CLS = { chassis: "شاسی", member: "عضو استک", stack: "استک", psu: "منبع تغذیه", fan: "فن", module: "ماژول", port: "ماژول پورت / SFP",
  cpu: "پردازنده", storage: "ذخیره‌ساز", other: "سایر" };
const AS_KIND = { new: "دارایی تازه", update: "تغییر از اسکن", edit: "ویرایش دستی" };
const AS_ST = { pending: ["warn", "در انتظار"], approved: ["ok", "تأیید شد"], rejected: ["err", "رد شد"], obsolete: ["mute", "کهنه"] };
const AS_HF = { created: "ایجاد دارایی", "part+": "قطعه‌ی تازه", "part-": "قطعه برداشته شد", "part→": "جابه‌جایی قطعه", rejected: "پیشنهاد رد شد", deleted: "حذف دارایی" };
const asT = (f) => AS_HF[f] || AS.titles[f] || f;
const asStatus = (s) => (s === "retired" ? `<span class="tag mute">بازنشسته</span>` : `<span class="tag ok">فعال</span>`);
const asVal = (f, v) => (f === "loc_from_dev" ? (String(v) === "1" || v === true ? I18N.t("بله") : I18N.t("خیر")) : f === "status" ? (v === "retired" ? I18N.t("بازنشسته") : v === "active" ? I18N.t("فعال") : v) : v);

$("#asTabs").addEventListener("click", (e) => {
  const b = e.target.closest("button[data-t]"); if (!b) return;
  AS.tab = b.dataset.t; $$("#asTabs button").forEach((x) => x.classList.toggle("on", x === b)); loadAssets();
});
function asPendBadge() { const n = $("#asPendN"); if (n) { n.hidden = !AS.pendN; n.textContent = AS.pendN ? num(AS.pendN) : ""; } }

async function loadAssets() {
  clearInterval(AS.timer); AS.timer = null;
  const r = await api("asset_list");
  if (!r.ok) { $("#asBody").innerHTML = `<div class="panel"><div class="empty">${esc(r.error)}</div></div>`; $("#asActions").innerHTML = ""; return; }
  Object.assign(AS, { list: r.assets, titles: r.titles, admin: r.admin, canEdit: r.can_edit, pendN: r.pending });
  asPendBadge();
  $("#asActions").innerHTML = `${AS.canEdit ? `<button class="btn" id="asNew">+ دارایی دستی</button>` : ""}
    <button class="btn no-ro" id="asCsv">خروجی CSV</button>${AS.admin && axOk("asset.scan", "run") ? `<button class="btn primary" id="asScanNow">اسکن الان</button>` : ""}`;
  if ($("#asNew")) $("#asNew").onclick = () => asEdit(null);
  $("#asCsv").onclick = asCsv;
  if ($("#asScanNow")) $("#asScanNow").onclick = () => asScan(null);
  if (AS.tab === "pending") return asPending();
  if (AS.tab === "hist") return asHist();
  if (AS.tab === "scan" && AS.admin) return asScanTab();
  if (AS.tab === "scan") { AS.tab = "list"; $$("#asTabs button").forEach((x) => x.classList.toggle("on", x.dataset.t === "list")); }
  asList();
}

/* ---------------------------------------------------------------- فهرست */
function asList() {
  const q = AS.q.toLowerCase();
  const rows = AS.list.filter((a) => (AS.status === "all" || (a.status || "active") === AS.status)
    && (!q || [a.serial, a.name, a.hostname, a.label, a.model, a.vendor, a.ip, a.location, a.asset_tag, a.sw].join(" ").toLowerCase().includes(q)));
  $("#asBody").innerHTML = `<div class="toolbar"><input type="search" class="search" id="asQ" placeholder="جستجو در سریال، نام، مدل، IP، محل، شماره اموال…" value="${esc(AS.q)}">
      <div class="seg" id="asStatus">${[["active", "فعال"], ["retired", "بازنشسته"], ["all", "همه"]].map(([k, n]) => `<button data-v="${k}" class="${AS.status === k ? "on" : ""}">${n}</button>`).join("")}</div>
      <span class="muted">${num(rows.length)} دارایی</span></div>
    ${AS.list.length ? `<div class="table-wrap"><table class="grid" id="asTable"><thead><tr><th>سریال</th><th>نام</th><th>مدل</th><th>سازنده</th><th>IP</th><th>محل نصب</th><th>نسخه</th><th>قطعه</th><th>شماره اموال</th><th>آخرین مشاهده</th><th>وضعیت</th></tr></thead><tbody>
      ${rows.map((a) => `<tr data-aid="${a.id}" class="clickable"><td class="ltr"><b>${esc(a.serial)}</b>${a.pending ? ` <span class="tag warn" title="تغییر در انتظار تأیید">●</span>` : ""}</td>
        <td class="ltr">${esc(a.name || "—")}</td><td class="ltr">${esc(a.model || "—")}</td><td class="bidi">${esc(a.vendor || "—")}</td><td class="ltr">${esc(a.ip || "—")}</td>
        <td class="bidi">${esc(a.location || "—")}</td><td class="ltr">${esc(a.sw || "—")}</td><td>${num(a.parts_n)}</td><td class="ltr">${esc(a.asset_tag || "—")}</td>
        <td class="ltr" data-sv="${a.last_seen || 0}">${a.last_seen ? fmtDate(a.last_seen) : "—"}</td><td>${asStatus(a.status)}</td></tr>`).join("")}</tbody></table></div>`
      : `<div class="panel"><div class="empty">هنوز دارایی‌ای ثبت نشده است. ${AS.admin ? "در تب «اسکن و تنظیمات» منابع را ببینید و «اسکن الان» را بزنید؛ دستگاه‌های پیدا شده بعد از تأیید شما در این فهرست می‌آیند." : ""}</div></div>`}`;
  $("#asQ").oninput = (e) => { AS.q = e.target.value; const p = e.target.selectionStart; asList(); const i = $("#asQ"); i.focus(); i.setSelectionRange(p, p); };
  $$("#asStatus button").forEach((b) => (b.onclick = () => { AS.status = b.dataset.v; asList(); }));
  $$("[data-aid]").forEach((tr) => (tr.onclick = () => asDetail(Number(tr.dataset.aid))));
}

/* ---------------------------------------------------------------- جزئیات */
async function asDetail(id) {
  const r = await api("asset_get", id);
  if (!r.ok) return toast(r.error, "error");
  const a = r.asset;
  const kv = (k, v, cls = "") => `<div class="kv-row"><span>${esc(asT(k))}</span><b class="${cls}">${v === null || v === undefined || v === "" ? "—" : esc(String(v))}</b></div>`;
  const pend = r.changes.filter((c) => c.status === "pending");
  await openModal({ title: `${a.name || a.serial}`, wide: true,
    body: `<div class="row" style="gap:8px;flex-wrap:wrap;margin-bottom:8px"><b class="ltr">SN ${esc(a.serial)}</b>${asStatus(a.status)}
        ${a.serial_kind === "machine-id" ? `<span class="tag mute" title="سرور سریال سخت‌افزاری نداد (یا دسترسی root نبود)؛ شناسه‌ی سیستم‌عامل استفاده شد">machine-id</span>` : ""}
        ${a.serial_kind === "chassisId" ? `<span class="tag mute" title="سوییچ/روتر قدیمی Cisco بدون ENTITY-MIB؛ سریال از chassisId خوانده شد که قابل‌تغییر است — با برچسب دستگاه مقایسه کنید">chassisId</span>` : ""}
        ${pend.length ? `<span class="tag warn">${num(pend.length)} تغییر در انتظار تأیید</span>` : ""}</div>
      <div class="kv-grid">${kv("hostname", a.hostname, "ltr")}${kv("ip", a.ip, "ltr")}${kv("model", a.model, "ltr")}${kv("vendor", a.vendor)}${kv("sw", a.sw, "ltr")}${kv("mac", a.mac, "ltr")}
        ${kv("location_dev", a.location_dev)}<div class="kv-row"><span>${esc(I18N.t("اولین / آخرین مشاهده"))}</span><b class="ltr">${a.first_seen ? fmtDate(a.first_seen) : "—"} / ${a.last_seen ? fmtDate(a.last_seen) : "—"}</b></div></div>
      ${a.descr ? `<div class="hint ltr" style="white-space:normal;margin-top:6px">${esc(a.descr)}</div>` : ""}
      <h3 style="margin:14px 0 6px">اطلاعات دستی</h3>
      <div class="form-grid">
        <label class="field"><span>${esc(asT("label"))}</span><input id="adLabel" value="${esc(a.label || "")}" ${AS.canEdit ? "" : "disabled"}></label>
        <label class="field"><span>${esc(asT("location"))}</span><input id="adLoc" value="${esc(a.location || "")}" placeholder="مثلاً طبقه ۲، رک B" ${AS.canEdit ? "" : "disabled"}></label>
        <label class="field"><span>${esc(asT("asset_tag"))}</span><input id="adTag" class="ltr" value="${esc(a.asset_tag || "")}" ${AS.canEdit ? "" : "disabled"}></label>
        <label class="field"><span>${esc(asT("status"))}</span><select id="adStatus" ${AS.canEdit ? "" : "disabled"}><option value="active" ${a.status !== "retired" ? "selected" : ""}>فعال</option><option value="retired" ${a.status === "retired" ? "selected" : ""}>بازنشسته</option></select></label>
        <label class="field wide"><span>${esc(asT("notes"))}</span><textarea id="adNotes" rows="2" ${AS.canEdit ? "" : "disabled"}>${esc(a.notes || "")}</textarea></label>
        <div class="field wide"><label class="chk"><input type="checkbox" id="adLocDev" ${a.loc_from_dev ? "checked" : ""} ${AS.canEdit ? "" : "disabled"}>محل نصب از دستگاه (sysLocation) خوانده شود؛ تغییرش مثل بقیه‌ی تغییرها منتظر تأیید می‌ماند</label></div>
      </div>
      ${AS.canEdit && !AS.admin ? `<p class="hint">تغییر شما بعد از تأیید ادمین اعمال می‌شود.</p>` : ""}
      <h3 style="margin:14px 0 6px">قطعه‌ها (${num(r.parts.length)})</h3>
      ${r.parts.length ? `<div class="table-wrap inner"><table class="grid"><thead><tr><th>نوع</th><th>نام</th><th>مدل</th><th>سریال</th><th>نسخه‌ی سخت‌افزار</th><th>منبع</th><th>آخرین مشاهده</th></tr></thead><tbody>
        ${r.parts.map((p) => `<tr><td>${esc(AS_CLS[p.cls] || p.cls || "—")}</td><td class="ltr">${esc(p.name || p.descr || "—")}</td><td class="ltr">${esc(p.model || "—")}</td>
          <td class="ltr">${esc(p.serial)}</td><td class="ltr">${esc(p.hw || "—")}</td><td>${esc((p.src || "").toUpperCase())}</td><td class="ltr" data-sv="${p.last_seen || 0}">${p.last_seen ? fmtDate(p.last_seen) : "—"}</td></tr>`).join("")}</tbody></table></div>`
        : `<div class="empty">قطعه‌ای با سریال ثبت نشده است.</div>`}
      <h3 style="margin:14px 0 6px">تاریخچه</h3>${asHistTable(r.history, false)}`,
    foot: `${AS.admin ? `<button class="btn danger-ghost" data-a="del">حذف</button>` : ""}${AS.canEdit ? `<button class="btn primary" data-a="save">${AS.admin ? "ذخیره" : "پیشنهاد تغییر"}</button>` : ""}<button class="btn ghost" data-a="close">بستن</button>`,
    onOpen: (m, close) => {
      $$("[data-a]", m).forEach((b) => (b.onclick = async () => {
        const act = b.dataset.a;
        if (act === "close") return close();
        if (act === "del") {
          if (!(await confirm2({ title: "حذف دارایی", body: `<p>دارایی <b class="ltr">${esc(a.serial)}</b> با قطعه‌هایش حذف شود؟ برای دستگاهی که دیگر استفاده نمی‌شود «بازنشسته» بهتر است (تاریخچه می‌ماند).</p>`, confirm: "حذف", danger: true, ack: "می‌دانم حذف برگشت ندارد" }))) return;
          const x = await api("asset_delete", a.id); if (!x.ok) return toast(x.error, "error"); toast("حذف شد", "ok"); return loadAssets();
        }
        const fields = { label: $("#adLabel", m).value.trim(), location: $("#adLoc", m).value.trim(), asset_tag: $("#adTag", m).value.trim(),
          status: $("#adStatus", m).value, notes: $("#adNotes", m).value, loc_from_dev: $("#adLocDev", m).checked };
        const x = await api("asset_save", a.id, fields);
        if (!x.ok) return toast(x.error, "error");
        toast(x.unchanged ? "تغییری نبود" : x.pending ? "پیشنهاد ثبت شد؛ منتظر تأیید ادمین" : "ذخیره شد", x.pending ? "info" : "ok");
        close(); loadAssets();
      }));
    } });
}
/** مقدار «ایجاد دارایی» JSON است (برچسب‌ها جدا تا ترجمه شوند). */
function asCreated(h) { try { const o = JSON.parse(h.new); return o && typeof o === "object" ? o : null; } catch (_) { return null; } }
function asHistNew(h) {
  const o = h.field === "created" ? asCreated(h) : null;
  if (!o) return esc(asVal(h.field, h.new) || "—");
  return Object.entries(o).map(([k, v]) => `<div><span>${esc(asT(k))}</span>: <span class="bidi">${esc(asVal(k, v))}</span></div>`).join("");
}
function asHistNewText(h) {
  const o = h.field === "created" ? asCreated(h) : null;
  return o ? Object.entries(o).map(([k, v]) => `${I18N.t(asT(k))}: ${asVal(k, v)}`).join(" | ") : asVal(h.field, h.new);
}
function asHistTable(rows, withAsset) {
  if (!rows.length) return `<div class="empty">سابقه‌ای نیست.</div>`;
  return `<div class="table-wrap inner"><table class="grid"><thead><tr><th>زمان</th>${withAsset ? "<th>سریال</th><th>دارایی</th>" : ""}<th>مورد</th><th>قبلی</th><th>جدید</th><th>کاربر</th><th>منبع</th></tr></thead><tbody>
    ${rows.map((h) => `<tr><td class="ltr" data-sv="${h.ts}">${fmtDate(h.ts)}</td>${withAsset ? `<td class="ltr">${h.asset_id ? `<a href="#" class="link" data-ha="${h.asset_id}">${esc(h.serial)}</a>` : esc(h.serial)}</td><td class="ltr">${esc(h.asset_name || "")}</td>` : ""}
      <td>${esc(asT(h.field))}</td><td class="bidi wrap">${esc(asVal(h.field, h.old) || "—")}</td><td class="bidi wrap">${asHistNew(h)}</td>
      <td class="ltr">${esc(h.user || "—")}</td><td class="bidi wrap">${esc(h.source || "")}</td></tr>`).join("")}</tbody></table></div>`;
}

/* ---------------------------------------------------------------- دارایی دستی */
async function asEdit() {
  const f = (id, label, ph = "", ltr = false) => `<label class="field"><span>${esc(label)}</span><input id="${id}" ${ltr ? 'class="ltr"' : ""} placeholder="${esc(ph)}"></label>`;
  await openModal({ title: "دارایی دستی", wide: true,
    body: `<p class="hint">${AS.admin ? "برای دستگاهی که SNMP یا SSH ندارد (چاپگر، لپ‌تاپ، …)." : "برای دستگاهی که SNMP یا SSH ندارد (چاپگر، لپ‌تاپ، …). بعد از تأیید ادمین ثبت می‌شود."}</p><div class="form-grid">
      ${f("anSerial", I18N.t("سریال"), "مثلاً FCW2117G00C", true)}${f("anHost", asT("hostname"))}${f("anModel", asT("model"), "", true)}${f("anVendor", asT("vendor"))}
      ${f("anIp", "IP", "", true)}${f("anLoc", asT("location"))}${f("anTag", asT("asset_tag"), "", true)}${f("anLabel", asT("label"))}
      <label class="field wide"><span>${esc(asT("notes"))}</span><textarea id="anNotes" rows="2"></textarea></label></div>`,
    foot: `<button class="btn ghost" data-r="0">انصراف</button><button class="btn primary" data-r="1">${AS.admin ? "ثبت" : "پیشنهاد"}</button>`,
    onOpen: (m, close) => {
      $("[data-r='0']", m).onclick = () => close();
      $("[data-r='1']", m).onclick = async () => {
        const g = (id) => $("#" + id, m).value.trim();
        const x = await api("asset_save", null, { location: g("anLoc"), asset_tag: g("anTag"), label: g("anLabel"), notes: $("#anNotes", m).value },
          g("anSerial"), { hostname: g("anHost"), model: g("anModel"), vendor: g("anVendor"), ip: g("anIp") });
        if (!x.ok) return toast(x.error, "error");
        toast(x.pending ? "پیشنهاد ثبت شد؛ منتظر تأیید ادمین" : "ثبت شد", x.pending ? "info" : "ok"); close(); loadAssets();
      };
    } });
}

/* ---------------------------------------------------------------- در انتظار تأیید */
/** خلاصه‌ی خوانای یک پیشنهاد از داده‌ی ساخت‌یافته (هر برچسب در گره‌ی جدا تا ترجمه شود). */
function asChgHtml(c) {
  const d = c.data || {}, out = [];
  const lab = (f) => `<span>${esc(asT(f))}</span>`;
  const pt = (p) => `<span>${esc(AS_CLS[p.cls] || p.cls || "")}</span> <span class="ltr">${esc([p.name, p.model].filter(Boolean).join(" · "))} SN ${esc(p.serial)}</span>`;
  if (c.kind === "new") {
    Object.entries(d.fields || {}).filter(([k, v]) => v && AS.titles[k] && k !== "descr").forEach(([k, v]) => out.push(`${lab(k)}: <span class="ltr">${esc(v)}</span>`));
    Object.entries(d.manual || {}).filter(([, v]) => v !== "" && v !== null && v !== undefined).forEach(([k, v]) => out.push(`${lab(k)}: ${esc(asVal(k, v))}`));
  } else {
    Object.entries({ ...(d.fields || {}), ...(d.manual || {}) }).forEach(([k, v]) => {
      const [o, n] = Array.isArray(v) ? v : ["", v];
      out.push(`${lab(k)}: <s class="muted">${esc(asVal(k, o) || "—")}</s> ← <b>${esc(asVal(k, n) || "—")}</b>`);
    });
  }
  (d.parts_added || []).forEach((p) => out.push(`<span class="tag ok">+</span> ${pt(p)}`));
  (d.parts_removed || []).forEach((p) => out.push(`<span class="tag err">−</span> ${pt(p)}`));
  (d.parts_moved || []).forEach((p) => out.push(`<span class="tag warn">⇄</span> ${pt(p)} <span class="muted"><span>${esc(I18N.t("از"))}</span> ${esc(p.from || "")}</span>`));
  return out.map((x) => `<div>${x}</div>`).join("");
}
async function asPending() {
  const r = await api("asset_changes", AS.chStatus);
  if (!r.ok) { $("#asBody").innerHTML = `<div class="panel"><div class="empty">${esc(r.error)}</div></div>`; return; }
  AS.changes = r.changes; AS.sel = new Set([...AS.sel].filter((id) => r.changes.some((c) => c.id === id && c.status === "pending")));
  const pending = AS.chStatus === "pending";
  $("#asBody").innerHTML = `<div class="toolbar"><div class="seg" id="asChS">${[["pending", "در انتظار"], ["rejected", "رد شده"], ["approved", "تأیید شده"], ["obsolete", "کهنه"]].map(([k, n]) => `<button data-v="${k}" class="${AS.chStatus === k ? "on" : ""}">${n}</button>`).join("")}</div>
      <span class="muted">${num(r.changes.length)} مورد</span>
      ${AS.admin && pending && r.changes.length ? `<span style="margin-inline-start:auto" class="row"><button class="btn sm" id="asSelAll">انتخاب همه</button><button class="btn sm primary" id="asOk">تأیید انتخاب‌شده‌ها</button><button class="btn sm danger-ghost" id="asNo">رد انتخاب‌شده‌ها</button></span>` : ""}</div>
    ${pending ? `<p class="hint">هر تغییری که اسکن یا اپراتور پیشنهاد می‌دهد تا تأیید ادمین اعمال نمی‌شود. مقدار ردشده تا وقتی دوباره عوض نشود دوباره پیشنهاد نمی‌شود (از «رد شده» قابل بازگردانی است).</p>` : ""}
    ${r.changes.length ? `<div class="table-wrap"><table class="grid"><thead><tr>${AS.admin && pending ? `<th class="chk"></th>` : ""}<th>زمان</th><th>نوع</th><th>سریال</th><th>دستگاه</th><th>تغییرها</th><th>منبع</th><th>پیشنهاد</th>${pending ? "" : "<th>تصمیم</th>"}<th></th></tr></thead><tbody>
      ${r.changes.map((c) => `<tr>${AS.admin && pending ? `<td><input type="checkbox" data-cs="${c.id}" ${AS.sel.has(c.id) ? "checked" : ""}></td>` : ""}
        <td class="ltr" data-sv="${c.ts}">${fmtDate(c.ts)}</td><td><span class="tag ${c.kind === "new" ? "info" : c.kind === "edit" ? "mute" : "warn"}">${esc(AS_KIND[c.kind] || c.kind)}</span></td>
        <td class="ltr">${c.asset_id ? `<a href="#" class="link" data-ca="${c.asset_id}">${esc(c.serial)}</a>` : esc(c.serial)}</td><td class="ltr" style="white-space:nowrap">${esc(c.asset_name || "—")}</td>
        <td class="bidi wrap sn-chg">${asChgHtml(c)}${c.data && c.data.was_part_of ? `<div class="muted">${esc(I18N.t("قبلاً قطعه‌ی"))} ${esc(c.data.was_part_of)}</div>` : ""}</td>
        <td class="bidi wrap">${esc(c.source || "")}</td><td class="ltr">${esc(c.by_user || "—")}</td>
        ${pending ? "" : `<td><span class="tag ${AS_ST[c.status][0]}">${AS_ST[c.status][1]}</span><div class="muted ltr">${esc(c.decided_by || "")} ${c.decided ? fmtDate(c.decided) : ""}</div>${c.note ? `<div class="muted">${esc(c.note)}</div>` : ""}</td>`}
        <td class="row" style="gap:4px">${AS.admin && pending ? `<button class="btn sm primary" data-ok="${c.id}">تأیید</button><button class="btn sm danger-ghost" data-no="${c.id}">رد</button>`
          : AS.admin && c.status === "rejected" ? `<button class="btn sm" data-rs="${c.id}">بازگرداندن به صف</button>` : ""}</td></tr>`).join("")}</tbody></table></div>`
      : `<div class="panel"><div class="empty">${pending ? "تغییری در انتظار تأیید نیست." : "موردی نیست."}</div></div>`}`;
  $$("#asChS button").forEach((b) => (b.onclick = () => { AS.chStatus = b.dataset.v; asPending(); }));
  $$("[data-cs]").forEach((c) => (c.onchange = () => { const id = Number(c.dataset.cs); if (c.checked) AS.sel.add(id); else AS.sel.delete(id); }));
  $$("[data-ca]").forEach((x) => (x.onclick = (e) => { e.preventDefault(); asDetail(Number(x.dataset.ca)); }));
  const decide = async (ids, ok) => {
    if (!ids.length) return toast("موردی انتخاب نشده است.", "error");
    let note = "";
    if (!ok) {
      const v = await openModal({ title: "رد تغییر", body: `<p>${num(ids.length)} تغییر رد شود؟ همین مقدارها در اسکن‌های بعدی دوباره پیشنهاد نمی‌شوند.</p><label class="field"><span>علت (اختیاری)</span><input id="rjNote"></label>`,
        foot: `<button class="btn ghost" data-r="0">انصراف</button><button class="btn danger" data-r="1">رد</button>`,
        onOpen: (m, close) => { $("[data-r='0']", m).onclick = () => close(null); $("[data-r='1']", m).onclick = () => close($("#rjNote", m).value); } });
      if (v === null) return;
      note = v;
    } else if (ids.length > 1 && !(await confirm2({ title: "تأیید تغییرها", body: `<p>${num(ids.length)} تغییر روی دارایی‌ها اعمال شود؟</p>`, confirm: "تأیید" }))) return;
    const x = await api("asset_decide", ids, ok, note);
    if (!x.ok) return toast(x.error, "error");
    if (x.errors.length) toast(x.errors.join("\n"), "error"); else toast(ok ? `${num(x.done)} تغییر اعمال شد` : `${num(x.done)} تغییر رد شد`, "ok");
    AS.sel.clear(); loadAssets();
  };
  $$("[data-ok]").forEach((b) => (b.onclick = () => decide([Number(b.dataset.ok)], true)));
  $$("[data-no]").forEach((b) => (b.onclick = () => decide([Number(b.dataset.no)], false)));
  $$("[data-rs]").forEach((b) => (b.onclick = async () => { const x = await api("asset_restore", [Number(b.dataset.rs)]); if (!x.ok) return toast(x.error, "error"); toast("به صف تأیید برگشت", "ok"); loadAssets(); }));
  if ($("#asSelAll")) $("#asSelAll").onclick = () => { r.changes.forEach((c) => AS.sel.add(c.id)); asPending(); };
  if ($("#asOk")) $("#asOk").onclick = () => decide([...AS.sel], true);
  if ($("#asNo")) $("#asNo").onclick = () => decide([...AS.sel], false);
}

/* ---------------------------------------------------------------- تاریخچه‌ی کل */
async function asHist() {
  const r = await api("asset_history");
  if (!r.ok) { $("#asBody").innerHTML = `<div class="panel"><div class="empty">${esc(r.error)}</div></div>`; return; }
  AS.hist = r.rows; asHistRender();
}
function asHistRender() {
  const q = AS.hq.toLowerCase();
  const rows = AS.hist.filter((h) => !q || [h.serial, h.asset_name, asT(h.field), h.old, h.new, h.user, h.source].join(" ").toLowerCase().includes(q)).slice(0, 2000);
  $("#asBody").innerHTML = `<div class="toolbar"><input type="search" class="search" id="asHq" placeholder="جستجو…" value="${esc(AS.hq)}"><span class="muted">${num(rows.length)} ردیف</span>
      <button class="btn no-ro" id="asHcsv" style="margin-inline-start:auto">خروجی CSV</button></div>${asHistTable(rows, true)}`;
  $("#asHq").oninput = (e) => { AS.hq = e.target.value; const p = e.target.selectionStart; asHistRender(); const i = $("#asHq"); i.focus(); i.setSelectionRange(p, p); };
  $$("[data-ha]").forEach((x) => (x.onclick = (e) => { e.preventDefault(); asDetail(Number(x.dataset.ha)); }));
  $("#asHcsv").onclick = () => asSaveCsv("autokrp_asset_history.csv", [I18N.t("زمان"), I18N.t("سریال"), I18N.t("دارایی"), I18N.t("مورد"), I18N.t("قبلی"), I18N.t("جدید"), I18N.t("کاربر"), I18N.t("منبع")],
    rows.map((h) => [new Date(h.ts * 1000).toISOString().slice(0, 19).replace("T", " "), h.serial, h.asset_name, I18N.t(asT(h.field)), asVal(h.field, h.old), asHistNewText(h), h.user, h.source]));
}

/* ---------------------------------------------------------------- اسکن و تنظیمات (ادمین) */
async function asScanTab() {
  const r = await api("asset_sources");
  if (!r.ok) { $("#asBody").innerHTML = `<div class="panel"><div class="empty">${esc(r.error)}</div></div>`; return; }
  const c = r.cfg, all = c.sources === null || c.sources === undefined;
  $("#asBody").innerHTML = `<div class="form"><h3>اسکن خودکار</h3><div class="form-grid">
      <div class="field"><span>&nbsp;</span><label class="chk"><input type="checkbox" id="asSchOn" ${c.scan_enabled ? "checked" : ""}>اسکن روزانه</label></div>
      <label class="field"><span>ساعت</span><input id="asSchT" class="ltr" value="${esc(c.scan_time)}" placeholder="03:00"></label>
      <label class="field"><span>اتصال هم‌زمان</span><input id="asConc" type="number" min="1" max="10" value="${esc(c.concurrency)}"></label>
      <div class="field wide"><label class="chk"><input type="checkbox" id="asLocDef" ${c.loc_default ? "checked" : ""}>برای دارایی‌های تازه «محل نصب از دستگاه (sysLocation)» روشن باشد</label></div></div>
      <p class="hint">اسکن روزانه فقط وقتی «کار خودکار» در داشبورد روشن است و فقط سر همان ساعت (تا ۱۵ دقیقه بعد) اجرا می‌شود؛ اگر برنامه آن موقع باز نبود، با باز شدن برنامه جبران نمی‌شود. باز کردن این صفحه هیچ اسکنی اجرا نمی‌کند. نتیجه‌ی اسکن هیچ تغییری را مستقیم اعمال نمی‌کند؛ همه به «در انتظار تأیید» می‌روند و ایمیل «مدیریت دارایی: تغییر منتظر تأیید» فرستاده می‌شود (اگر اعلان ایمیلی روشن باشد).</p></div>
    <div class="form"><h3>منابع اسکن</h3>
      <label class="chk"><input type="checkbox" id="asAll" ${all ? "checked" : ""}>همه‌ی منابع مشترک (هدف یا دستگاه تازه هم خودکار اضافه شود)</label>
      <div class="table-wrap inner" style="margin-top:8px"><table class="grid"><thead><tr><th class="chk"></th><th>نوع</th><th>نام</th><th>آدرس</th><th>توضیح</th></tr></thead><tbody>
      ${r.sources.length ? r.sources.map((s) => `<tr><td><input type="checkbox" data-src="${esc(s.id)}" ${s.selected ? "checked" : ""} ${s.ok && !all ? "" : "disabled"}></td>
        <td>${s.type === "snmp" ? "SNMP" : "SSH" + (s.dtype ? ` <small class="muted ltr">${esc(s.dtype)}</small>` : "")}</td><td class="bidi">${esc(s.name)}</td><td class="ltr">${esc(s.host)}</td>
        <td class="wrap">${s.ok ? "" : `<span class="muted">${esc(s.why)}</span>`}</td></tr>`).join("")
        : `<tr><td colspan="5"><div class="empty">منبعی نیست: یک هدف SNMP در «مانیتورینگ» یا دستگاه SSH (Cisco یا لینوکس) مشترک اضافه کنید.</div></td></tr>`}</tbody></table></div>
      <p class="hint">SNMP: جدول استاندارد ENTITY-MIB (سریال، مدل و قطعه‌ها؛ Cisco از جمله Firepower/ASA، سوییچ‌های HP/Aruba و بیشتر تجهیزات) و MIB خود سازنده برای FortiGate، Juniper (با قطعه‌ها)، MikroTik و سرور HP ProLiant (iLO یا عامل HP). SSH: Cisco با show inventory و show version، لینوکس با فایل‌های DMI (بدون دسترسی root شناسه‌ی machine-id). فقط هدف‌ها و دستگاه‌های مشترک (ادمین) اسکن می‌شوند.</p>
      <div class="row" style="gap:6px"><button class="btn primary" id="asSave">ذخیره‌ی تنظیمات</button>${axOk("asset.scan", "run") ? `<button class="btn" id="asScanSel">اسکن الان</button>` : ""}</div></div>
    <div id="asJob"></div>`;
  $("#asAll").onchange = (e) => $$("[data-src]").forEach((x) => { const s = r.sources.find((y) => y.id === x.dataset.src); x.disabled = e.target.checked || !s.ok; if (e.target.checked && s.ok) x.checked = true; });
  const collect = () => ({ scan_enabled: $("#asSchOn").checked, scan_time: $("#asSchT").value.trim(), concurrency: $("#asConc").value, loc_default: $("#asLocDef").checked,
    sources: $("#asAll").checked ? null : { ids: $$("[data-src]").filter((x) => x.checked).map((x) => x.dataset.src) } });
  $("#asSave").onclick = async () => { const x = await api("asset_settings_save", collect()); if (!x.ok) return toast(x.error, "error"); toast("ذخیره شد", "ok"); };
  if ($("#asScanSel")) $("#asScanSel").onclick = () => asScan($("#asAll").checked ? null : $$("[data-src]").filter((x) => x.checked).map((x) => x.dataset.src));
  asJobRender(r.job);
  if (r.job && r.job.status === "running") asJobPoll();
}
async function asScan(ids) {
  const x = await api("asset_scan_start", ids);
  if (!x.ok) return toast(x.error, "error");
  toast("اسکن دارایی شروع شد", "info");
  if (AS.tab !== "scan") { AS.tab = "scan"; $$("#asTabs button").forEach((b) => b.classList.toggle("on", b.dataset.t === "scan")); await asScanTab(); }
  asJobRender(x.job); asJobPoll();
}
function asJobPoll() {
  clearInterval(AS.timer);
  AS.timer = setInterval(async () => {
    if (S.page !== "assets" || AS.tab !== "scan") { clearInterval(AS.timer); return; }
    const r = await api("asset_scan_status"); if (!r.ok) return;
    asJobRender(r.job);
    if (!r.job || r.job.status !== "running") { clearInterval(AS.timer); const s = await api("asset_list"); if (s.ok) { AS.pendN = s.pending; asPendBadge(); } }
  }, 1500);
}
function asJobRender(j) {
  const el = $("#asJob"); if (!el) return;
  if (!j) { el.innerHTML = ""; return; }
  const run = j.status === "running";
  el.innerHTML = `<div class="panel"><div class="panel-head"><h3>آخرین اسکن <span class="muted ltr">${fmtDate(j.started)}</span> <span class="tag mute">${j.trigger === "schedule" ? "زمان‌بندی روزانه" : "دستی" + (j.user ? " — " + esc(j.user) : "")}</span></h3>
      <span>${run ? `${num(j.done)} / ${num(j.total)} <button class="btn sm danger-ghost" id="asCancel">توقف</button>` : `<span class="tag ${j.status === "done" ? "ok" : "mute"}">${j.status === "done" ? "تمام شد" : "متوقف شد"}</span> · ${num(j.proposed)} تغییر در انتظار تأیید`}</span></div>
    <div class="table-wrap inner"><table class="grid"><thead><tr><th>منبع</th><th>آدرس</th><th>وضعیت</th><th>سریال</th><th>پیام</th></tr></thead><tbody>
    ${j.results.map((x) => `<tr><td class="bidi">${esc(x.name)}</td><td class="ltr">${esc(x.host || "")}</td><td><span class="tag ${x.status === "ok" ? "ok" : x.status === "error" ? "err" : "mute"}">${x.status === "ok" ? "موفق" : x.status === "error" ? "ناموفق" : "رد شد"}</span></td>
      <td class="ltr">${esc(x.serial || "—")}</td><td class="wrap">${esc(x.message || "")}</td></tr>`).join("")}</tbody></table></div>
    ${!run && j.proposed ? `<button class="btn primary sm" id="asGoPend" style="margin-top:8px">مشاهده‌ی تغییرهای در انتظار تأیید</button>` : ""}</div>`;
  if ($("#asCancel")) $("#asCancel").onclick = async () => { await api("asset_scan_cancel"); toast("توقف درخواست شد", "info"); };
  if ($("#asGoPend")) $("#asGoPend").onclick = () => { AS.tab = "pending"; AS.chStatus = "pending"; $$("#asTabs button").forEach((b) => b.classList.toggle("on", b.dataset.t === "pending")); loadAssets(); };
}

/* ---------------------------------------------------------------- CSV */
async function asSaveCsv(name, head, rows) {
  const q = (v) => `"${String(v ?? "").replace(/"/g, '""')}"`;
  const text = "﻿" + [head, ...rows].map((r) => r.map(q).join(",")).join("\r\n");
  const res = await api("save_export", name, text, false);
  if (!res.ok) return toast(res.error, "error"); if (!res.cancelled) toast("ذخیره شد: " + res.path, "ok");
}
function asCsv() {
  const f = ["serial", "label", "hostname", "model", "vendor", "ip", "location", "sw", "mac", "asset_tag", "status", "notes"];
  asSaveCsv("autokrp_assets.csv", [...f.map((k) => (k === "serial" ? I18N.t("سریال") : I18N.t(asT(k)))), I18N.t("قطعه"), I18N.t("اولین مشاهده"), I18N.t("آخرین مشاهده")],
    AS.list.map((a) => [...f.map((k) => asVal(k, a[k])), a.parts_n, a.first_seen ? new Date(a.first_seen * 1000).toISOString().slice(0, 10) : "", a.last_seen ? new Date(a.last_seen * 1000).toISOString().slice(0, 10) : ""]));
}
