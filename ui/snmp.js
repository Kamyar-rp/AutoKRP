"use strict";
/* ================================================================ SNMP در مانیتورینگ
 * فرم هدف SNMP، پروفایل‌های اعتبارنامه (v2c / v3)، مرورگر OID، صفحه‌ی جزئیات زنده (پورت‌ها، سخت‌افزار، OID دستی) و نمودارها.
 * از app.js (api، openModal، drawChart، …) و monitor.js (MON، monIcon، loadMon) استفاده می‌کند. */

const SN = { profiles: [], auth: [], priv: [], loaded: false, admin: true };
const SN_VENDORS = [["auto", "تشخیص خودکار"], ["cisco", "Cisco"], ["fortinet", "FortiGate"], ["linux", "Linux (net-snmp)"], ["extreme", "Extreme"], ["juniper", "Juniper"], ["mikrotik", "MikroTik"], ["hp", "HP ProLiant (iLO)"], ["generic", "عمومی (استانداردها)"]];
const SN_TH = [["cpu", "CPU (٪)"], ["mem", "حافظه (٪)"], ["disk", "دیسک (٪)"], ["temp", "دما (°C)"], ["util", "مصرف پورت‌های پیگیری‌شده (٪ سرعت)"], ["err", "خطای پورت‌های پیگیری‌شده (در دقیقه)"]];
const SN_TH_DEF = { cpu: [80, 95], mem: [85, 95], disk: [85, 95], temp: [null, null], util: [80, 95], err: [10, 100] };
const SN_SECT = [["cpu", "CPU"], ["mem", "حافظه"], ["disk", "دیسک"], ["env", "دما، فن و منبع تغذیه"], ["if", "پورت‌ها"]];
/* 1.34: سیاست پایش و تنظیم دقت/ذخیره‌ی داده (مشترک بین فرم هدف و ویرایش سیاست) */
const POL_PORTS = [["all", "همه‌ی پورت‌های فعال"], ["up", "فقط پورت‌های وصل"], ["watch", "فقط پورت‌های پیگیری‌شده"], ["none", "هیچ پورتی"]];
const POL_CNT = [["traffic", "ترافیک (ورودی/خروجی)"], ["err", "خطا"], ["disc", "Discard"]];
const POL_HIST = [["sys", "CPU، حافظه، دیسک، دما و زمان پاسخ"], ["if", "ترافیک و خطای پورت‌ها"], ["oid", "OIDهای دستی و قالب دستگاه"]];
function polKeep(v) { return v === null || v === undefined ? "" : v; }
function polDataHtml(c, pfx) {
  const cnt = c.counters || {}, hist = c.hist || {};
  const on = (o, k) => (o[k] === undefined ? true : !!o[k]);
  return `<div class="form-grid">
      <label class="field"><span>دقت داده‌ی دقیق (نمودار)</span><select id="${pfx}Res"><option value="300" ${Number(c.res || 300) === 300 ? "selected" : ""}>هر ۵ دقیقه</option><option value="60" ${Number(c.res) === 60 ? "selected" : ""}>هر ۱ دقیقه (حجم ۵ برابر)</option></select>
        <small class="hint">بازه‌های طولانی همیشه از داده‌ی ساعتی خوانده می‌شوند.</small></label>
      <label class="field"><span>تاریخچه‌ی کدام پورت‌ها</span><select id="${pfx}Ports">${POL_PORTS.map(([k, n]) => `<option value="${k}" ${(c.ports || "all") === k ? "selected" : ""}>${n}</option>`).join("")}</select>
        <small class="hint">جدول زنده‌ی پورت‌ها همیشه همه را نشان می‌دهد.</small></label>
      <label class="field"><span>نگهداری داده‌ی دقیق (روز)</span><input id="${pfx}KeepD" type="number" min="0" value="${esc(polKeep(c.keep_d))}" placeholder="مثل تنظیمات کلی">
        <small class="hint">خالی = مثل تنظیمات کلی · ۰ = بدون محدودیت · وگرنه دست‌کم ۷</small></label>
      <label class="field"><span>نگهداری داده‌ی ساعتی (روز)</span><input id="${pfx}KeepH" type="number" min="0" value="${esc(polKeep(c.keep_h))}" placeholder="مثل تنظیمات کلی">
        <small class="hint">خالی = مثل تنظیمات کلی · ۰ = بدون محدودیت · وگرنه دست‌کم ۳۰</small></label></div>
    <div class="field"><span>شمارنده‌های پورت که خوانده شوند</span><div class="row" style="gap:14px;flex-wrap:wrap">${POL_CNT.map(([k, n]) => `<label class="chk"><input type="checkbox" data-${pfx}cnt="${k}" ${on(cnt, k) ? "checked" : ""}>${n}</label>`).join("")}</div>
      <small class="hint">وضعیت وصل/قطع پورت‌ها همیشه خوانده می‌شود. هر شمارنده‌ی کمتر = درخواست کمتر به دستگاه.</small></div>
    <div class="field"><span>ذخیره‌ی تاریخچه (نمودار)</span><div class="row" style="gap:14px;flex-wrap:wrap">${POL_HIST.map(([k, n]) => `<label class="chk"><input type="checkbox" data-${pfx}hist="${k}" ${on(hist, k) ? "checked" : ""}>${n}</label>`).join("")}</div>
      <small class="hint">بدون تیک = فقط نمایش زنده و هشدار، بدون نمودار و حجم دیسک.</small></div>`;
}
function polDataCollect(m, pfx) {
  const keep = (id) => { const v = $(`#${pfx}${id}`, m).value.trim(); return v === "" ? null : Number(v); };
  const counters = {}, hist = {};
  $$(`[data-${pfx}cnt]`, m).forEach((c) => (counters[c.getAttribute(`data-${pfx}cnt`)] = c.checked ? 1 : 0));
  $$(`[data-${pfx}hist]`, m).forEach((c) => (hist[c.getAttribute(`data-${pfx}hist`)] = c.checked ? 1 : 0));
  return { res: Number($(`#${pfx}Res`, m).value), ports: $(`#${pfx}Ports`, m).value, keep_d: keep("KeepD"), keep_h: keep("KeepH"), counters, hist };
}
const SN_OPER = { 1: "وصل", 2: "قطع", 3: "تست", 4: "نامعلوم", 5: "خواب", 6: "نیست", 7: "قطع (لایه‌ی پایین)" };
const SN_LV = { ok: ["ok", "سالم"], warn: ["warn", "هشدار"], crit: ["err", "بحرانی"], absent: ["mute", "نیست"] };

function fmtBps(v) {
  if (v === null || v === undefined) return "—";
  v = Number(v);
  for (const [u, d] of [["Gbps", 1e9], ["Mbps", 1e6], ["Kbps", 1e3]]) if (v >= d) return (v / d).toFixed(v / d < 10 ? 2 : 1) + " " + u;
  return Math.round(v) + " bps";
}
function fmtSpeed(v) { if (!v) return "—"; return v >= 1e9 ? `${v / 1e9}G` : v >= 1e6 ? `${v / 1e6}M` : `${v}`; }
function snUp(s) {
  if (s === null || s === undefined) return "—";
  const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
  return d ? `${num(d)} روز و ${num(h)} ساعت` : `${num(h)} ساعت و ${num(m)} دقیقه`;
}
const snLv = (lv) => { const x = SN_LV[lv] || SN_LV.ok; return `<span class="tag ${x[0]}">${x[1]}</span>`; };
const snPct = (v) => (v === null || v === undefined ? "—" : num(Math.round(v * 10) / 10) + "٪");

async function snLoadProfiles(force) {
  if (SN.loaded && !force) return;
  const r = await api("snmp_cred_list");
  if (r.ok) Object.assign(SN, { profiles: r.profiles, auth: r.auth, priv: r.priv, admin: r.admin, canAdd: r.can_add, loaded: true });
}
/** پروفایل‌های قابل انتخاب برای هدفی با صاحب owner ('' = مشترک). */
function snUsable(owner) { return SN.profiles.filter((p) => (owner ? p.personal : !p.personal)); }
function snTargetOwner(t) { return t && t.id ? t.owner || "" : SN.admin ? "" : "me"; }

/* ---------------------------------------------------------------- فرم پروفایل */
function snProfHtml(p, x) {
  p = Object.assign({ version: "2c", auth: "SHA", priv: "AES128" }, p || {});
  const sel = (id, list, v) => `<select id="${x}${id}">${list.map(([k, n]) => `<option value="${k}" ${k === v ? "selected" : ""}>${esc(n)}</option>`).join("")}</select>`;
  const keep = p.id ? `placeholder="${esc(I18N.t("خالی = بدون تغییر"))}"` : "";
  return `<div class="form-grid">
    <label class="field"><span>نام پروفایل</span><input id="${x}Name" value="${esc(p.name || "")}" placeholder="مثلاً سوییچ‌های دسترسی"></label>
    <div class="field"><span>نسخه</span><div class="seg" id="${x}Ver"><button type="button" data-v="2c" class="${p.version !== "3" ? "on" : ""}">v2c</button><button type="button" data-v="3" class="${p.version === "3" ? "on" : ""}">v3</button></div></div>
    <label class="field ${x}v2"><span>Community</span><input id="${x}Comm" type="password" autocomplete="new-password" ${keep}></label>
    <label class="field ${x}v3"><span>نام کاربر (USM)</span><input id="${x}User" class="ltr" value="${esc(p.username || "")}"></label>
    <label class="field ${x}v3"><span>احراز هویت (auth)</span>${sel("Auth", SN.auth, p.auth || "SHA")}</label>
    <label class="field ${x}v3 ${x}a"><span>رمز auth</span><input id="${x}AKey" type="password" autocomplete="new-password" ${keep}></label>
    <label class="field ${x}v3"><span>رمزنگاری (priv)</span>${sel("Priv", SN.priv, p.priv || "AES128")}</label>
    <label class="field ${x}v3 ${x}p"><span>رمز priv</span><input id="${x}PKey" type="password" autocomplete="new-password" ${keep}></label>
    <label class="field ${x}v3"><span>Context (اختیاری)</span><input id="${x}Ctx" class="ltr" value="${esc(p.ctx || "")}"></label>
    ${!p.id && SN.admin && S.state && S.state.me && S.state.me.username ? `<div class="field"><span>&nbsp;</span><label class="chk"><input type="checkbox" id="${x}Pers">پروفایل شخصی (فقط من)</label></div>` : ""}
    </div>
    <p class="hint ${x}v3">رمزها ۸ تا ۱۲۸ نویسه. برای AES-192/256 روی Cisco معمولاً نوع «Cisco» درست است؛ اگر پاسخ نیامد نوع «استاندارد» را امتحان کنید.</p>
    <p class="hint">اسرار رمزشده در برنامه می‌مانند و هرگز به رابط برنمی‌گردند. پروفایل مشترک فقط برای هدف‌های مشترک (ادمین) و پروفایل شخصی فقط برای هدف‌های شخصی خودتان است.</p>`;
}
function snProfBind(root, x) {
  const vis = () => {
    const v3 = $(`#${x}Ver button.on`, root).dataset.v === "3";
    $$(`.${x}v2`, root).forEach((e) => (e.hidden = v3));
    $$(`.${x}v3`, root).forEach((e) => (e.hidden = !v3));
    if (v3) {
      const a = $(`#${x}Auth`, root).value, p = $(`#${x}Priv`, root).value;
      $$(`.${x}a`, root).forEach((e) => (e.hidden = a === "none"));
      $$(`.${x}p`, root).forEach((e) => (e.hidden = p === "none"));
    }
  };
  $$(`#${x}Ver button`, root).forEach((b) => (b.onclick = () => { $$(`#${x}Ver button`, root).forEach((y) => y.classList.toggle("on", y === b)); vis(); }));
  $(`#${x}Auth`, root).onchange = vis; $(`#${x}Priv`, root).onchange = vis;
  vis();
}
function snProfCollect(root, x, p) {
  const v3 = $(`#${x}Ver button.on`, root).dataset.v === "3";
  const pers = $(`#${x}Pers`, root);
  return { profile: { id: p && p.id, name: $(`#${x}Name`, root).value.trim(), version: v3 ? "3" : "2c", username: $(`#${x}User`, root).value.trim(),
      auth: $(`#${x}Auth`, root).value, priv: $(`#${x}Priv`, root).value, ctx: $(`#${x}Ctx`, root).value.trim(), personal: pers ? pers.checked : false },
    pw: v3 ? $(`#${x}AKey`, root).value : $(`#${x}Comm`, root).value, sec: v3 ? $(`#${x}PKey`, root).value : "" };
}

/* ---------------------------------------------------------------- مدیریت پروفایل‌ها (صفحه‌ی مانیتورینگ) */
async function snmpProfiles() {
  await snLoadProfiles(true);
  let edit = null;
  await openModal({ title: "اعتبارنامه‌های SNMP", wide: true, body: `<div id="spBody"></div>`, foot: `<button class="btn ghost" data-r="close">بستن</button>`,
    onOpen: (m, close) => {
      $("[data-r='close']", m).onclick = () => close(null);
      const list = () => {
        edit = null;
        $("#spBody", m).innerHTML = `<p class="hint">یک بار community یا کاربر SNMPv3 را تعریف کنید و در هدف‌های مانیتورینگ انتخاب کنید. تغییر رمز پروفایل همان لحظه برای همه‌ی هدف‌هایش اعمال می‌شود.</p>
          ${SN.canAdd ? `<button class="btn primary sm" id="spAdd">+ پروفایل تازه</button>` : ""}
          <div class="table-wrap inner" style="margin-top:10px"><table class="grid"><thead><tr><th>نام</th><th>نسخه</th><th>کاربر / امنیت</th><th>هدف‌ها</th><th></th></tr></thead><tbody>
          ${SN.profiles.length ? SN.profiles.map((p) => `<tr><td><b>${esc(p.name)}</b>${p.personal ? ` <span class="tag info">شخصی</span>` : ""}</td><td>v${esc(p.version)}</td>
            <td class="ltr">${p.version === "3" ? `${esc(p.username)} · ${esc(p.auth)}/${esc(p.priv)}` : "community"}</td><td>${num(p.targets)}</td>
            <td class="row" style="gap:4px">${p.personal || SN.admin ? `<button class="btn sm" data-ed="${p.id}">ویرایش</button><button class="btn sm danger-ghost" data-del="${p.id}">حذف</button>` : ""}</td></tr>`).join("")
            : `<tr><td colspan="5"><div class="empty">هنوز پروفایل SNMP ساخته نشده است.</div></td></tr>`}</tbody></table></div>`;
        if ($("#spAdd", m)) $("#spAdd", m).onclick = () => form(null);
        $$("[data-ed]", m).forEach((b) => (b.onclick = () => form(SN.profiles.find((p) => p.id === Number(b.dataset.ed)))));
        $$("[data-del]", m).forEach((b) => (b.onclick = async () => {
          const p = SN.profiles.find((x) => x.id === Number(b.dataset.del));
          if (!(await confirm2({ title: "حذف پروفایل", body: `<p>پروفایل «${esc(p.name)}» و رمزهایش حذف شود؟</p>`, confirm: "حذف", danger: true }))) return snmpProfiles();
          const r = await api("snmp_cred_delete", p.id);
          if (!r.ok) toast(r.error, "error"); else toast("حذف شد", "ok");
          snmpProfiles();
        }));
      };
      const form = (p) => {
        edit = p;
        $("#spBody", m).innerHTML = `<h3 style="margin:0 0 10px">${p ? esc(p.name) : esc(I18N.t("پروفایل SNMP تازه"))}</h3>${snProfHtml(p, "sp")}
          <div class="row" style="gap:6px;margin-top:12px"><button class="btn ghost" id="spBack">بازگشت</button><button class="btn primary" id="spSave">ذخیره</button></div>`;
        snProfBind(m, "sp");
        $("#spBack", m).onclick = list;
        $("#spSave", m).onclick = async () => {
          const c = snProfCollect(m, "sp", p);
          const r = await api("snmp_cred_save", c.profile, c.pw, c.sec);
          if (!r.ok) return toast(r.error, "error");
          toast("ذخیره شد", "ok"); await snLoadProfiles(true); list();
        };
      };
      list();
    } });
}

/* ---------------------------------------------------------------- بخش SNMP فرم هدف */
function snEditHtml(t) {
  const c = Object.assign({ vendor: "auto", collect: {}, th: SN_TH_DEF, after: 2, retries: 1, watch: [], oids: [], if_hist: 1 }, t.snmp_cfg || {});
  const col = (k) => (c.collect[k] === undefined ? true : !!c.collect[k]);
  const th = (k) => (c.th && c.th[k]) || [null, null];
  const v = (x) => (x === null || x === undefined ? "" : x);
  return `<div class="sn-edit">
    <div class="form-grid">
      <label class="field"><span>پروفایل اعتبارنامه</span><div class="row" style="gap:6px"><select id="snCred" style="flex:1"></select><button type="button" class="btn sm" id="snNewP">+ تازه</button></div></label>
      <label class="field"><span>نوع دستگاه</span><select id="snVendor" data-cur="${esc(c.profile && c.profile !== "auto" && c.profile !== "none" ? "prof:" + c.profile : c.vendor)}">${SN_VENDORS.map(([k, n]) => `<option value="${k}" ${c.vendor === k ? "selected" : ""}>${esc(n)}</option>`).join("")}</select></label>
    </div>
    <div id="snNewPW" hidden class="sn-sub"></div>
    <div class="row" style="gap:6px;margin:8px 0"><button type="button" class="btn" id="snTest">تست اتصال و کشف</button><button type="button" class="btn ghost" id="snBrowse">مرورگر OID…</button></div>
    <div id="snTestOut"></div>
    <div id="snBrowseW" hidden class="sn-sub"></div>
    <div id="snPolNote" class="sn-polnote" hidden></div>
    <details class="sn-det sn-polpart" open><summary>چه چیزهایی خوانده شود</summary>
      <div class="row" style="gap:14px;flex-wrap:wrap">${SN_SECT.map(([k, n]) => `<label class="chk"><input type="checkbox" data-col="${k}" ${col(k) ? "checked" : ""}>${esc(n)}</label>`).join("")}</div></details>
    <details class="sn-det sn-polpart"><summary>دقت و ذخیره‌ی داده</summary>${polDataHtml(c, "sn")}</details>
    <details class="sn-det"><summary>آستانه‌های هشدار</summary>
      <table class="grid sn-th"><thead><tr><th>مورد</th><th>هشدار (زرد)</th><th>بحرانی (قرمز، صدا و ایمیل)</th></tr></thead><tbody>
      ${SN_TH.map(([k, n]) => `<tr><td>${esc(n)}</td><td><input type="number" step="any" data-thw="${k}" value="${v(th(k)[0])}"></td><td><input type="number" step="any" data-thc="${k}" value="${v(th(k)[1])}"></td></tr>`).join("")}</tbody></table>
      <div class="form-grid" style="margin-top:8px">
        <label class="field"><span>هشدار پس از چند بار پشت‌سرهم</span><input id="snAfter" type="number" min="1" max="20" value="${esc(c.after)}"></label>
        <label class="field sn-polpart"><span>تلاش دوباره‌ی هر درخواست</span><input id="snRetries" type="number" min="0" max="5" value="${esc(c.retries)}"></label></div>
      <p class="hint">خالی = خاموش. وضعیت خود دستگاه (مثلاً منبع تغذیه‌ی خراب یا دمای بحرانی گزارش‌شده) همیشه هشدار می‌دهد. دما به‌طور پیش‌فرض فقط با وضعیت خود دستگاه هشدار می‌دهد (سنسورهای CPU/Hotspot ذاتاً داغ‌اند)؛ اگر عدد بدهید روی همه‌ی سنسورهای دما اعمال می‌شود. پورت‌ها فقط وقتی «پیگیری» شوند هشدار قطع، مصرف و خطا دارند.</p></details>
    <details class="sn-det" ${c.watch.length ? "open" : ""}><summary>پورت‌هایی که هشدار بدهند (${num(c.watch.length)})</summary>
      <textarea id="snWatch" rows="3" class="ltr" placeholder="Gi1/0/1&#10;Te1/1/1">${esc(c.watch.join("\n"))}</textarea>
      <p class="hint">همه‌ی پورت‌ها همیشه خوانده و با ترافیک نشان داده می‌شوند؛ تیک فقط یعنی این پورت «پیگیری» شود: اگر قطع شد یا مصرف و خطایش از آستانه گذشت، هشدار (صدا، اعلان و ایمیل) بدهد. بدون تیک هیچ هشداری برای پورت نیست. هر خط نام یک پورت (ifName، مثل Gi1/0/1)؛ بعد از «تست اتصال» از فهرست تیک بزنید. در صفحه‌ی جزئیات هدف هم قابل تغییر است.</p><div id="snWatchPick"></div></details>
    <details class="sn-det" ${c.oids.length ? "open" : ""}><summary>OIDهای دستی (${num(c.oids.length)})</summary>
      <div class="table-wrap inner"><table class="grid sn-oids"><thead><tr><th>نام</th><th>OID</th><th>نوع</th><th>واحد</th><th>ضریب</th><th>هشدار</th><th>بحرانی</th><th>جهت</th><th>مقدار مورد انتظار (متن)</th><th>نمودار</th><th></th></tr></thead><tbody id="snOidRows"></tbody></table></div>
      <button type="button" class="btn sm" id="snOidAdd" style="margin-top:6px">+ OID</button>
      <p class="hint">«شمارنده» = نرخ در ثانیه (تفاضل دو خواندن). «متن» فقط نمایش داده می‌شود و اگر «مقدار مورد انتظار» داشته باشد، تفاوت بحرانی است. جهت «کمتر» یعنی مقدار پایین بد است.</p></details>
  </div>`;
}
function snOidRow(o) {
  o = Object.assign({ name: "", oid: "", type: "gauge", unit: "", mult: 1, warn: "", crit: "", dir: "above", expect: "", chart: 1 }, o || {});
  const v = (x) => (x === null || x === undefined ? "" : x);
  return `<tr class="sn-oid"><td><input data-k="name" value="${esc(o.name)}"></td><td><input data-k="oid" class="ltr" value="${esc(o.oid)}" placeholder="1.3.6.1…"></td>
    <td><select data-k="type">${[["gauge", "عدد"], ["counter", "شمارنده"], ["text", "متن"]].map(([k, n]) => `<option value="${k}" ${o.type === k ? "selected" : ""}>${esc(n)}</option>`).join("")}</select></td>
    <td><input data-k="unit" value="${esc(o.unit)}" style="width:60px"></td><td><input data-k="mult" type="number" step="any" value="${esc(v(o.mult))}" style="width:70px"></td>
    <td><input data-k="warn" type="number" step="any" value="${esc(v(o.warn))}" style="width:70px"></td><td><input data-k="crit" type="number" step="any" value="${esc(v(o.crit))}" style="width:70px"></td>
    <td><select data-k="dir"><option value="above" ${o.dir !== "below" ? "selected" : ""}>بیشتر</option><option value="below" ${o.dir === "below" ? "selected" : ""}>کمتر</option></select></td>
    <td><input data-k="expect" value="${esc(o.expect)}"></td><td><input type="checkbox" data-k="chart" ${o.chart ? "checked" : ""}></td>
    <td><button type="button" class="btn sm ghost" data-oid-del title="حذف">×</button></td></tr>`;
}
async function snEditBind(m, t) {
  await snLoadProfiles(true);
  const owner = snTargetOwner(t);
  const fillCred = (sel) => {
    const L = snUsable(owner);
    $("#snCred", m).innerHTML = (L.length ? "" : `<option value="">${esc(I18N.t("— اول یک پروفایل بسازید —"))}</option>`)
      + L.map((p) => `<option value="${p.id}" ${String(p.id) === String(sel) ? "selected" : ""}>${esc(p.name)} (v${esc(p.version)})</option>`).join("");
  };
  fillCred(t.cred_id);
  api("mib_types").then((r) => {                           // 1.27.1: نوع‌های دستگاه ساخته‌شده از MIB سازنده‌ها
    const sel = $("#snVendor", m); if (!sel || !r.ok || !r.types.length) return;
    sel.insertAdjacentHTML("beforeend", r.types.map((p) => `<option value="prof:${esc(p.id)}">${esc(p.name)} (MIB)</option>`).join(""));
    if (sel.dataset.cur.startsWith("prof:")) sel.value = sel.dataset.cur;
  });
  const rows = $("#snOidRows", m);
  const bindRows = () => $$("[data-oid-del]", rows).forEach((b) => (b.onclick = () => b.closest("tr").remove()));
  rows.innerHTML = ((t.snmp_cfg && t.snmp_cfg.oids) || []).map(snOidRow).join(""); bindRows();
  $("#snOidAdd", m).onclick = () => { rows.insertAdjacentHTML("beforeend", snOidRow()); bindRows(); };
  // پروفایل تازه داخل همین فرم
  $("#snNewP", m).onclick = () => {
    const w = $("#snNewPW", m);
    if (!w.hidden) { w.hidden = true; return; }
    w.hidden = false;
    w.innerHTML = snProfHtml(null, "np") + `<div class="row" style="gap:6px"><button type="button" class="btn primary sm" id="npSave">ذخیره‌ی پروفایل</button><button type="button" class="btn ghost sm" id="npCancel">انصراف</button></div>`;
    snProfBind(w, "np");
    const pers = $("#npPers", w); if (pers) pers.closest(".field").hidden = true;   // پروفایل این هدف باید با صاحب هدف جور باشد
    $("#npCancel", w).onclick = () => (w.hidden = true);
    $("#npSave", w).onclick = async () => {
      const c = snProfCollect(w, "np", null);
      c.profile.personal = !!owner;
      const r = await api("snmp_cred_save", c.profile, c.pw, c.sec);
      if (!r.ok) return toast(r.error, "error");
      await snLoadProfiles(true); fillCred(r.id); w.hidden = true; toast("پروفایل ذخیره شد", "ok");
    };
  };
  const form = () => ({ id: t.id, host: $("#meHost", m).value.trim(), port: $("#mePort", m).value.trim() || 161, cred_id: $("#snCred", m).value,
    timeout: $("#meTo", m).value, snmp: snEditCollect(m) });
  // تست اتصال
  $("#snTest", m).onclick = async (e) => {
    const b = e.currentTarget; b.disabled = true;
    $("#snTestOut", m).innerHTML = `<div class="hint">در حال خواندن دستگاه…</div>`;
    const r = await api("snmp_test", form());
    b.disabled = false;
    if (!r.ok) { $("#snTestOut", m).innerHTML = `<div class="sn-test err">${esc(r.error)}</div>`; return; }
    const s = r.sys || {};
    $("#snTestOut", m).innerHTML = `<div class="sn-test ok"><b class="ltr">${esc(s.name || "—")}</b> · ${esc(r.vendor_name)} · <span class="ltr">${num(r.rtt)} ms</span>
      <div class="muted ltr" style="white-space:normal">${esc((s.descr || "").slice(0, 220))}</div>
      <div class="row" style="gap:10px;flex-wrap:wrap;margin-top:4px">
        <span>CPU: ${r.cpu === null ? "—" : snPct(r.cpu)}${r.cpu_src ? ` <small class="muted">(${esc(r.cpu_src)})</small>` : ""}</span>
        <span>حافظه: ${r.mem === null ? "—" : snPct(r.mem)}${r.mem_src ? ` <small class="muted">(${esc(r.mem_src)})</small>` : ""}</span>
        <span>دما: ${num(r.temps)}</span><span>فن: ${num(r.fans)}</span><span>منبع تغذیه: ${num(r.psus)}</span><span>سنسور: ${num(r.sensors)}</span>
        <span>دیسک: ${num(r.disks)}</span><span>پورت: ${num(r.if_count)}</span></div>
      ${r.profile ? `<div class="hint">نوع دستگاه از MIB: <b>${esc(r.profile.name)}</b> (${num(r.profile.count)} وضعیت)</div>` : ""}
      ${r.errors.length ? `<div class="hint" style="color:var(--warn)">${r.errors.map(esc).join("<br>")}</div>` : ""}
      ${r.oids.length ? `<div class="hint ltr">${r.oids.map((o) => `${esc(o.oid)} = ${esc(o.value === null ? "(none)" : String(o.value))}`).join("<br>")}</div>` : ""}</div>`;
    // انتخاب پورت‌های پیگیری‌شده از فهرست
    const cur = new Set($("#snWatch", m).value.split("\n").map((x) => x.trim()).filter(Boolean));
    $("#snWatchPick", m).innerHTML = r.ifs.length ? `<div class="sn-pick">${r.ifs.map((x) => `<label class="chk" title="${esc(x.alias)}"><input type="checkbox" data-wp="${esc(x.name)}" ${cur.has(x.name) ? "checked" : ""}>
      <span class="ltr">${esc(x.name)}</span>${x.alias ? ` <small class="muted bidi">${esc(x.alias)}</small>` : ""} <span class="tag ${x.oper === 1 ? "ok" : x.admin === 2 ? "mute" : "err"}">${x.admin === 2 ? esc(I18N.t("خاموش")) : esc(SN_OPER[x.oper] || x.oper)}</span></label>`).join("")}</div>` : "";
    if (r.ifs.length) $("#snWatchPick", m).closest("details").open = true;
    $$("[data-wp]", m).forEach((c) => (c.onchange = () => {
      const s2 = new Set($("#snWatch", m).value.split("\n").map((x) => x.trim()).filter(Boolean));
      if (c.checked) s2.add(c.dataset.wp); else s2.delete(c.dataset.wp);
      $("#snWatch", m).value = [...s2].join("\n");
    }));
  };
  // مرورگر OID
  $("#snBrowse", m).onclick = () => {
    const w = $("#snBrowseW", m);
    if (!w.hidden) { w.hidden = true; return; }
    w.hidden = false;
    w.innerHTML = `<div class="row" style="gap:6px;flex-wrap:wrap"><input id="sbOid" class="ltr" value="1.3.6.1.2.1.1" style="flex:1;min-width:220px">
      <select id="sbMax" style="width:auto"><option>200</option><option selected>500</option><option>2000</option></select><button type="button" class="btn sm primary" id="sbGo">گشتن</button></div>
      <div class="row" style="gap:4px;flex-wrap:wrap;margin-top:6px">${[["1.3.6.1.2.1.1", "system"], ["1.3.6.1.2.1.2.2.1", "ifTable"], ["1.3.6.1.2.1.31.1.1.1", "ifXTable"], ["1.3.6.1.2.1.47.1.1.1.1", "ENTITY"], ["1.3.6.1.2.1.25", "HOST-RESOURCES"], ["1.3.6.1.4.1.9.9.109.1.1.1", "Cisco CPU"], ["1.3.6.1.4.1.9.9.13", "Cisco ENVMON"], ["1.3.6.1.4.1.12356.101.4", "FortiGate"], ["1.3.6.1.4.1", "enterprises"]].map(([o, n]) => `<button type="button" class="btn sm ghost" data-sbq="${o}">${n}</button>`).join("")}</div>
      <div id="sbOut" style="margin-top:6px"></div>`;
    $$("[data-sbq]", w).forEach((b) => (b.onclick = () => { $("#sbOid", w).value = b.dataset.sbq; $("#sbGo", w).click(); }));
    $("#sbGo", w).onclick = async (e) => {
      const b = e.currentTarget; b.disabled = true; $("#sbOut", w).innerHTML = `<div class="hint">در حال خواندن…</div>`;
      const r = await api("snmp_walk", form(), $("#sbOid", w).value.trim(), Number($("#sbMax", w).value));
      b.disabled = false;
      if (!r.ok) { $("#sbOut", w).innerHTML = `<div class="sn-test err">${esc(r.error)}</div>`; return; }
      $("#sbOut", w).innerHTML = r.rows.length ? `<div class="table-wrap inner sn-walk"><table class="grid"><thead><tr><th>OID</th><th>نوع</th><th>مقدار</th><th></th></tr></thead><tbody>
        ${r.rows.map(([o, ty, val], i) => `<tr><td class="ltr">${esc(o)}</td><td class="ltr">${esc(ty)}</td><td class="ltr wrap">${esc(val === null ? "" : String(val))}</td>
          <td><button type="button" class="btn sm" data-sba="${i}">افزودن</button></td></tr>`).join("")}</tbody></table></div>
        ${r.more ? `<div class="hint">ردیف‌های بیشتری هست؛ OID دقیق‌تری بدهید.</div>` : ""}` : `<div class="empty">چیزی برنگشت.</div>`;
      $$("[data-sba]", w).forEach((bb) => (bb.onclick = () => {
        const [o, ty, val] = r.rows[Number(bb.dataset.sba)];
        const typ = /Counter/.test(ty) ? "counter" : /Integer|Gauge|Unsigned|TimeTicks/.test(ty) ? "gauge" : "text";
        rows.insertAdjacentHTML("beforeend", snOidRow({ name: o.split(".").slice(-2).join("."), oid: o, type: typ, chart: typ !== "text" ? 1 : 0 }));
        bindRows(); rows.closest("details").open = true; toast("به OIDهای دستی اضافه شد", "ok");
      }));
    };
  };
}
function snEditCollect(m) {
  const th = {};
  SN_TH.forEach(([k]) => {
    const w = $(`[data-thw="${k}"]`, m).value, c = $(`[data-thc="${k}"]`, m).value;
    th[k] = [w === "" ? null : Number(w), c === "" ? null : Number(c)];
  });
  const collect = {}; $$("[data-col]", m).forEach((c) => (collect[c.dataset.col] = c.checked ? 1 : 0));
  const oids = $$("#snOidRows tr", m).map((tr) => {
    const g = (k) => $(`[data-k="${k}"]`, tr);
    return { name: g("name").value.trim(), oid: g("oid").value.trim(), type: g("type").value, unit: g("unit").value.trim(), mult: g("mult").value,
      warn: g("warn").value, crit: g("crit").value, dir: g("dir").value, expect: g("expect").value.trim(), chart: g("chart").checked };
  }).filter((o) => o.oid);
  const vsel = $("#snVendor", m).value;               // «نوع دستگاه» از MIB = عمومی + همان نوع (بدون تشخیص خودکار)
  return { vendor: vsel.startsWith("prof:") ? "generic" : vsel, profile: vsel.startsWith("prof:") ? vsel.slice(5) : "auto", collect, th, after: $("#snAfter", m).value, retries: $("#snRetries", m).value,
    watch: $("#snWatch", m).value.split("\n").map((x) => x.trim()).filter(Boolean), oids, ...polDataCollect(m, "sn") };
}

/* ---------------------------------------------------------------- کارت */
function snCardLine(t) {
  const s = t.snmp_sum;
  if (!s) return "";
  const parts = [];
  if (s.cpu !== null && s.cpu !== undefined) parts.push(`CPU ${snPct(s.cpu)}`);
  if (s.mem !== null && s.mem !== undefined) parts.push(`RAM ${snPct(s.mem)}`);
  if (s.temp !== null && s.temp !== undefined) parts.push(`${num(s.temp)}°C`);
  if (s.if_n) parts.push(`${I18N.t("پورت")} ${num(s.if_up)}/${num(s.if_n)}`);
  return `<span class="mon-snmp ltr">${parts.map(esc).join(" · ")}</span>${s.alarms ? `<span class="tag ${s.level === "crit" ? "err" : "warn"}">${num(s.alarms)} هشدار</span>` : ""}`;
}

/* ---------------------------------------------------------------- جزئیات زنده */
async function snmpDetail(t) {
  const D = { t, live: null, tab: "sum", port: null, filter: "", pf: "all", timer: null };
  const st = MON_ST[t.status] || MON_ST.unknown;
  const done = openModal({ title: t.name, wide: true,
    body: `<div class="mon-dhead">${monIcon(t.icon, "big")}<div style="flex:1"><div class="ltr">${esc(t.host)}:${esc(String(t.port || 161))} (SNMP)</div>
        <div class="row" style="gap:8px;margin-top:4px;flex-wrap:wrap"><span class="tag ${st[0]}">${st[1]}</span><span id="snHead" class="row" style="gap:8px;flex-wrap:wrap"></span></div>
        ${t.err ? `<div class="muted" style="color:var(--err)">${esc(t.err)}</div>` : ""}</div></div>
      <div class="tabs" id="snTabs" style="margin-top:10px">${[["sum", "خلاصه"], ["ports", "پورت‌ها"], ["hw", "سخت‌افزار"], ["oids", "OIDها و وضعیت‌ها"], ["charts", "نمودارها"]]
        .map(([k, n]) => `<button data-t="${k}" class="${k === "sum" ? "on" : ""}">${n}</button>`).join("")}</div>
      <div id="snBody" style="margin-top:12px"><div class="empty">در حال خواندن…</div></div>`,
    foot: `${t.can_edit ? `<button class="btn danger-ghost" data-a="del">حذف</button><button class="btn" data-a="toggle">${t.enabled ? "توقف بررسی" : "ادامه‌ی بررسی"}</button><button class="btn" data-a="edit">ویرایش</button>` : ""}
      <button class="btn" data-a="now">بررسی همین حالا</button><button class="btn ghost" data-a="close">بستن</button>`,
    onOpen: (m, close) => {
      D.m = m;
      $$("[data-a]", m).forEach((b) => (b.onclick = async () => {
        const a = b.dataset.a;
        if (a === "close") return close();
        if (a === "edit") { close(); return monEdit(t); }
        if (a === "now") { await api("mon_check_now", t.id); toast("بررسی انجام می‌شود…", "info"); setTimeout(() => snRefresh(D, true), 2500); return; }
        if (a === "toggle") { const r = await api("mon_toggle", t.id, !t.enabled); if (!r.ok) return toast(r.error, "error"); close(); return loadMon(); }
        if (a === "del") {
          if (!(await confirm2({ title: "حذف هدف", body: `<p>«${esc(t.name)}» و سابقه و نمودارهایش حذف شود؟</p>`, confirm: "حذف", danger: true }))) return;
          const r = await api("mon_delete", t.id); if (!r.ok) return toast(r.error, "error"); return loadMon();
        }
      }));
      $$("#snTabs button", m).forEach((b) => (b.onclick = () => { $$("#snTabs button", m).forEach((x) => x.classList.toggle("on", x === b)); D.tab = b.dataset.t; snRender(D); if (D.tab === "ports") snRefresh(D, true); }));
      snRefresh(D, true);
      D.timer = setInterval(() => { if ($("#snBody", m)) snRefresh(D, false); }, 10000);
    } });
  done.then(() => clearInterval(D.timer));
}
async function snRefresh(D, force) {
  const r = await api("mon_snmp_live", D.t.id, force ? 0 : D.live ? D.live.t : 0, true);
  if (!r.ok || !D.m || !$("#snBody", D.m)) return;
  if (r.same) return;
  D.live = r.none ? null : r;
  snHead(D);
  if (D.tab !== "charts" || !D.chartsDone) snRender(D);
}
function snHead(D) {
  const L = D.live, h = $("#snHead", D.m);
  if (!h) return;
  if (!L) { h.innerHTML = `<span class="muted">هنوز خوانده نشده است.</span>`; return; }
  const s = L.sys || {};
  h.innerHTML = `${snLv(L.level)}<b class="ltr">${esc(s.name || "")}</b><span class="muted">${esc(L.profile ? L.profile.name : (SN_VENDORS.find((v) => v[0] === L.vendor) || [0, L.vendor])[1])}</span>
    <span class="muted">uptime: ${snUp(L.uptime_s)}</span><span class="muted ltr">${num(L.rtt)} ms</span><span class="muted">آخرین خواندن: ${fmtTime(L.t)}</span>`;
}
function snRender(D) {
  const b = $("#snBody", D.m); if (!b) return;
  const L = D.live;
  if (!L) { b.innerHTML = `<div class="empty">هنوز داده‌ای نیست؛ بعد از اولین بررسی (حداکثر ${num(D.t.interval)} ثانیه) نمایش داده می‌شود. اگر دستگاه پاسخ نمی‌دهد، علت بالای صفحه است.</div>`; return; }
  D.chartsDone = false;
  if (D.tab === "sum") return snSum(D, b, L);
  if (D.tab === "ports") return snPorts(D, b, L);
  if (D.tab === "hw") return snHw(D, b, L);
  if (D.tab === "oids") return snOids(D, b, L);
  return snCharts(D, b);
}
function snSum(D, b, L) {
  const ifs = L.ifs || [];
  const ex = L.extra || {};
  b.innerHTML = `<div class="kpis">
      <div class="kpi"><b>${L.cpu ? snPct(L.cpu.value) : "—"}</b><span>CPU</span></div>
      <div class="kpi"><b>${L.mem ? snPct(L.mem.pct) : "—"}</b><span>حافظه${L.mem && L.mem.total ? ` (${esc(fmtBytes(L.mem.used))} / ${esc(fmtBytes(L.mem.total))})` : ""}</span></div>
      <div class="kpi"><b>${L.temp_max === null || L.temp_max === undefined ? "—" : num(L.temp_max) + "°C"}</b><span>بیشترین دما</span></div>
      ${L.disk_max !== null && L.disk_max !== undefined ? `<div class="kpi"><b>${snPct(L.disk_max)}</b><span>بیشترین مصرف دیسک</span></div>` : ""}
      <div class="kpi"><b>${num(ifs.filter((x) => x.oper === 1).length)} / ${num(L.if_count || ifs.length)}</b><span>پورت وصل</span></div>
      ${ex.sessions !== undefined ? `<div class="kpi"><b>${num(ex.sessions)}</b><span>نشست‌های فعال</span></div>` : ""}
      ${ex.load1 !== undefined ? `<div class="kpi"><b>${num(ex.load1)}</b><span>Load (۱ دقیقه)</span></div>` : ""}</div>
    <h3 style="margin:4px 0 6px">هشدارها</h3>
    ${L.alarms.length ? `<div class="table-wrap inner"><table class="grid"><thead><tr><th>سطح</th><th>مورد</th><th>از</th></tr></thead><tbody>
      ${L.alarms.map((a) => `<tr><td>${snLv(a.level)}</td><td class="wrap">${esc(a.msg)}</td><td class="ltr">${fmtDate(a.since)}</td></tr>`).join("")}</tbody></table></div>`
      : `<div class="empty">هشدار فعالی نیست.</div>`}
    ${L.errors.length ? `<div class="hint" style="color:var(--warn);margin-top:8px">بخش‌هایی که خوانده نشدند: ${L.errors.map(esc).join(" · ")}</div>` : ""}
    <div class="hint ltr" style="margin-top:10px;white-space:normal">${esc(L.sys.descr || "")}${L.sys.location ? ` · ${esc(L.sys.location)}` : ""}${ex.version ? ` · ${esc(ex.version)}` : ""}</div>
    <div class="chart-grid" style="margin-top:12px"><div class="chart-card wide"><div class="chart-head"><h3>CPU و حافظه (٪) — ۲۴ ساعت</h3></div><div class="chart" id="snc1"></div></div></div>`;
  snChart(D, $("#snc1", b), "24h", [["cpu", "CPU", "info"], ["mem", "حافظه", "acc"]], { pct: true, height: 170 });
}
function snPorts(D, b, L) {
  const ae = document.activeElement, keep = ae && ae.id === "snPf" ? ae.selectionStart : null;   // نوشتن در جستجو با به‌روزرسانی زنده قطع نشود
  const all = L.ifs || [];
  const f = D.filter.toLowerCase();
  const rows = all.filter((x) => (D.pf === "all" || (D.pf === "up" && x.oper === 1) || (D.pf === "down" && x.admin === 1 && x.oper !== 1) || (D.pf === "watch" && x.watch))
    && (!f || `${x.name} ${x.alias} ${x.descr}`.toLowerCase().includes(f)));
  const show = rows.slice(0, 500);
  b.innerHTML = `<div class="toolbar"><input type="search" id="snPf" class="search" placeholder="جستجوی پورت…" value="${esc(D.filter)}">
      <div class="seg" id="snPs">${[["all", "همه"], ["up", "وصل"], ["down", "قطع"], ["watch", "پیگیری‌شده"]].map(([k, n]) => `<button data-v="${k}" class="${D.pf === k ? "on" : ""}">${n}</button>`).join("")}</div>
      <span class="muted">${num(rows.length)} پورت</span></div>
    <div id="snPortChart"></div>
    <div class="table-wrap inner"><table class="grid"><thead><tr><th title="پیگیری: هشدار قطع، مصرف و خطا">پیگیری</th><th>پورت</th><th>توضیح</th><th>وضعیت</th><th>سرعت</th><th>ورودی</th><th>خروجی</th><th>مصرف</th><th>خطا/دقیقه</th></tr></thead><tbody>
    ${show.map((x) => `<tr><td><input type="checkbox" data-w="${esc(x.name)}" ${x.watch ? "checked" : ""} ${D.t.can_edit ? "" : "disabled"}></td>
      <td class="ltr"><a href="#" class="link" data-pc="${esc(x.name)}" title="نمودار ترافیک">${esc(x.name)}</a></td><td class="bidi wrap">${esc(x.alias || "")}</td>
      <td><span class="tag ${x.admin !== 1 ? "mute" : x.oper === 1 ? "ok" : "err"}">${x.admin !== 1 ? esc(I18N.t("خاموش")) : esc(SN_OPER[x.oper] || x.oper)}</span></td>
      <td class="ltr" data-sv="${x.speed || 0}">${fmtSpeed(x.speed)}</td><td class="ltr" data-sv="${x.in_bps ?? -1}">${fmtBps(x.in_bps)}</td><td class="ltr" data-sv="${x.out_bps ?? -1}">${fmtBps(x.out_bps)}</td>
      <td data-sv="${x.util ?? -1}">${x.util === null || x.util === undefined ? "—" : `<span class="sn-bar"><i style="width:${Math.min(100, x.util)}%"></i></span> ${snPct(x.util)}`}</td>
      <td class="ltr" data-sv="${x.err_min ?? -1}">${x.err_min ? num(x.err_min) : x.err_min === 0 ? "0" : "—"}</td></tr>`).join("")}</tbody></table></div>
    ${rows.length > show.length ? `<div class="hint">فقط ۵۰۰ پورت نمایش داده می‌شود؛ جستجو کنید.</div>` : ""}`;
  if (keep !== null) { const i = $("#snPf", b); i.focus(); i.setSelectionRange(keep, keep); }
  $("#snPf", b).oninput = (e) => { D.filter = e.target.value; snPorts(D, b, L); };
  $$("#snPs button", b).forEach((x) => (x.onclick = () => { D.pf = x.dataset.v; snPorts(D, b, L); }));
  $$("[data-w]", b).forEach((c) => (c.onchange = async () => {
    const r = await api("mon_snmp_watch", D.t.id, [c.dataset.w], c.checked);
    if (!r.ok) { c.checked = !c.checked; return toast(r.error, "error"); }
    const it = all.find((x) => x.name === c.dataset.w); if (it) it.watch = c.checked;
    toast(c.checked ? "پورت پیگیری می‌شود" : "پیگیری پورت برداشته شد", "ok");
  }));
  $$("[data-pc]", b).forEach((a) => (a.onclick = (e) => { e.preventDefault(); D.port = a.dataset.pc; snPortChart(D, $("#snPortChart", b)); }));
  if (D.port) snPortChart(D, $("#snPortChart", b));
}
function snPortChart(D, el) {
  const p = D.port;
  el.innerHTML = `<div class="chart-card wide" style="margin-bottom:10px"><div class="chart-head"><h3 class="ltr">${esc(p)}</h3>
      <div id="snPr"></div>
      <button class="btn sm ghost" id="snPx">بستن</button></div><div class="tr-note" id="snPn"></div><div class="chart" id="snPcc"></div><div class="chart" id="snPce"></div></div>`;
  const draw = () => {
    snChart(D, $("#snPcc", el), MON.tr, [[`if:${p}:in`, "ورودی", "info"], [`if:${p}:out`, "خروجی", "acc"]], { bps: true, height: 190, withMax: true, sync: "snp", zoomTo: set, note: $("#snPn", el) });
    snChart(D, $("#snPce", el), MON.tr, [[`if:${p}:err`, "خطا در دقیقه", "err"]], { height: 120, hideEmpty: true, sync: "snp", zoomTo: set });
  };
  const set = (R) => { monTrSet(R); trBar($("#snPr", el), bar); draw(); };
  const bar = { get: () => MON.tr, set, refresh: draw };
  trBar($("#snPr", el), bar);
  $("#snPx", el).onclick = () => { D.port = null; el.innerHTML = ""; };
  draw();
}
function snHw(D, b, L) {
  const tbl = (title, head, rows) => rows.length ? `<h3 style="margin:10px 0 6px">${title}</h3><div class="table-wrap inner"><table class="grid"><thead><tr>${head.map((h) => `<th>${h}</th>`).join("")}</tr></thead><tbody>${rows.join("")}</tbody></table></div>` : "";
  const html = [
    tbl("دما", ["سنسور", "مقدار", "آستانه‌ی دستگاه", "وضعیت"], L.temps.map((x) => `<tr><td class="bidi">${esc(x.name)}</td><td class="ltr">${x.value === null ? "—" : num(x.value) + "°C"}</td><td class="ltr">${x.thr ? num(x.thr) + "°C" : "—"}</td><td>${snLv(x.state)}</td></tr>`)),
    tbl("فن", ["فن", "وضعیت"], L.fans.map((x) => `<tr><td class="bidi">${esc(x.name)}</td><td>${snLv(x.state)}</td></tr>`)),
    tbl("منبع تغذیه", ["منبع", "وضعیت"], L.psus.map((x) => `<tr><td class="bidi">${esc(x.name)}</td><td>${snLv(x.state)}</td></tr>`)),
    tbl("سنسورهای دستگاه", ["سنسور", "مقدار", "وضعیت"], L.sensors.map((x) => `<tr><td class="bidi">${esc(x.name)}</td><td class="ltr">${esc(x.value ?? "")}</td><td>${snLv(x.state)}</td></tr>`)),
    tbl("CPU", ["پردازنده", "۵ ثانیه", "۱ دقیقه", "۵ دقیقه"], (L.cpu && L.cpu.items || []).map((x) => `<tr><td class="bidi">${esc(x.name)}</td><td>${snPct(x.s5)}</td><td>${snPct(x.m1)}</td><td>${snPct(x.m5)}</td></tr>`)),
    tbl("حافظه", ["بخش", "مصرف", "کل", "٪"], (L.mem && L.mem.items || []).map((x) => `<tr><td class="bidi">${esc(x.name)}</td><td class="ltr">${esc(fmtBytes(x.used))}</td><td class="ltr">${esc(fmtBytes(x.total))}</td><td>${snPct(x.pct)}</td></tr>`)),
    tbl("دیسک", ["دیسک", "مصرف", "کل", "٪"], L.disks.map((x) => `<tr><td class="ltr">${esc(x.name)}</td><td class="ltr">${esc(fmtBytes(x.used))}</td><td class="ltr">${esc(fmtBytes(x.total))}</td><td>${snPct(x.pct)}</td></tr>`)),
  ].join("");
  b.innerHTML = (html || `<div class="empty">دستگاه اطلاعات سخت‌افزاری برنگرداند (یا این بخش‌ها در تنظیمات هدف خاموش‌اند).</div>`)
    + `<p class="hint">منبع داده: ${esc([L.cpu && L.cpu.src, L.mem && L.mem.src].filter(Boolean).join("، ") || "—")}</p>`;
}
function snOids(D, b, L) {
  if (!L.oids.length) { b.innerHTML = `<div class="empty">OID دستی یا وضعیتی از MIB سازنده برای این هدف نیست. در «ویرایش» ← «OIDهای دستی» اضافه کنید، یا MIB سازنده را در «تنظیمات ← مانیتورینگ» بارگذاری کنید.</div>`; return; }
  const al = {}; L.alarms.forEach((a) => (al[a.key] = a.level));
  b.innerHTML = `<div class="table-wrap inner"><table class="grid"><thead><tr><th>نام</th><th>OID</th><th>مقدار</th><th>وضعیت</th><th></th></tr></thead><tbody>
    ${L.oids.map((o) => `<tr><td>${esc(o.name)}${o.prof ? ` <span class="tag info" title="${esc(I18N.t("از MIB سازنده"))}">${esc(o.prof)}</span>` : ""}</td><td class="ltr">${esc(o.oid)}</td><td class="ltr">${o.missing ? `<span class="tag mute">${esc(I18N.t("روی دستگاه نیست"))}</span>` : o.value === null ? "—" : esc(String(o.value)) + (o.unit ? " " + esc(o.unit) : "") + (o.type === "counter" ? "/s" : "")}</td>
      <td>${snLv(al["oid:" + o.oid] || "ok")}</td><td>${o.chart ? `<button class="btn sm" data-oc="${esc(o.oid)}">نمودار</button>` : ""}</td></tr>`).join("")}</tbody></table></div><div id="snOc" style="margin-top:10px"></div>`;
  $$("[data-oc]", b).forEach((x) => (x.onclick = () => {
    const o = L.oids.find((y) => y.oid === x.dataset.oc);
    $("#snOc", b).innerHTML = `<div class="chart-card wide"><div class="chart-head"><h3>${esc(o.name)}${o.unit ? " (" + esc(o.unit) + ")" : ""}</h3><div id="snOr"></div></div><div class="tr-note" id="snOn"></div><div class="chart" id="snOcc"></div></div>`;
    const draw = () => snChart(D, $("#snOcc", b), MON.tr, [["oid:" + o.oid, o.name, "info"]], { withMax: true, zoomTo: set, note: $("#snOn", b) });
    const set = (R) => { monTrSet(R); trBar($("#snOr", b), bar); draw(); };
    const bar = { get: () => MON.tr, set, refresh: draw };
    trBar($("#snOr", b), bar); draw();
  }));
}
async function snCharts(D, b, silent) {
  D.chartsDone = true;
  const L = D.live;
  const oids = (L.oids || []).filter((o) => o.chart && o.type !== "text");
  if (!silent || !$("#sncCpu", b)) {
    b.innerHTML = `<div class="toolbar"><div id="snCr"></div>
      <button class="btn no-ro" id="snCsv">خروجی CSV</button></div><div class="tr-note" id="snCn"></div>
    <div class="chart-grid">
      <div class="chart-card wide"><div class="chart-head"><h3>CPU (٪)</h3></div><div class="chart" id="sncCpu"></div></div>
      <div class="chart-card wide"><div class="chart-head"><h3>حافظه (٪)</h3></div><div class="chart" id="sncMem"></div></div>
      <div class="chart-card wide"><div class="chart-head"><h3>بیشترین دما (°C)</h3></div><div class="chart" id="sncTemp"></div></div>
      ${L.disk_max !== null && L.disk_max !== undefined ? `<div class="chart-card wide"><div class="chart-head"><h3>بیشترین مصرف دیسک (٪)</h3></div><div class="chart" id="sncDisk"></div></div>` : ""}
      <div class="chart-card wide"><div class="chart-head"><h3>زمان پاسخ SNMP (ms)</h3></div><div class="chart" id="sncRtt"></div></div>
      ${oids.map((o, i) => `<div class="chart-card wide"><div class="chart-head"><h3>${esc(o.name)}${o.unit ? " (" + esc(o.unit) + ")" : ""}</h3></div><div class="chart" id="sncO${i}"></div></div>`).join("")}
    </div><p class="hint">خط پررنگ = میانگین، خط کم‌رنگ = بیشینه‌ی هر بازه. داده‌ی ۵ دقیقه‌ای برای روزهای اخیر (طبق تنظیمات نگهداری)، بازه‌های بلندتر یا قدیمی‌تر از داده‌ی ساعتی. برای زوم روی نمودار بکشید؛ دوبار کلیک = بازه‌ی بزرگ‌تر.</p>`;
  }
  const set = (R) => { monTrSet(R); snCharts(D, b); };
  trBar($("#snCr", b), { get: () => MON.tr, set, refresh: () => snCharts(D, b, true) });
  const keys = ["cpu", "mem", "temp", "disk", "rtt", ...oids.map((o) => "oid:" + o.oid)];
  const r = await api("mon_snmp_series", D.t.id, trApi(MON.tr), keys);
  if (!$("#sncCpu", b)) return;
  if (!r.ok) { $("#snCn", b).textContent = r.error; return; }
  D.series = r;
  $("#snCn", b).innerHTML = `<span class="ltr">${esc(trFmt(r.since) + " — " + trFmt(r.until))}</span> · ${esc(trResNote(r))}`;
  const draw = (id, key, name, color, opt) => { const el = $("#" + id, b); if (el) snDraw(el, r, [[key, name, color]], Object.assign({ withMax: true, sync: "snc", zoomTo: set }, opt)); };
  draw("sncCpu", "cpu", "CPU", "info", { pct: true }); draw("sncMem", "mem", "حافظه", "acc", { pct: true });
  draw("sncTemp", "temp", "دما", "warn", {}); draw("sncDisk", "disk", "دیسک", "info", { pct: true }); draw("sncRtt", "rtt", "زمان پاسخ", "ok", {});
  oids.forEach((o, i) => draw("sncO" + i, "oid:" + o.oid, o.name, "info", {}));
  $("#snCsv", b).onclick = async () => {
    const q = (v) => `"${String(v ?? "").replace(/"/g, '""')}"`;
    const ks = Object.keys(r.data);
    const lines = [[I18N.t("زمان"), ...ks.flatMap((k) => [k + " avg", k + " max"])].map(q).join(",")];
    r.times.forEach((t0, i) => lines.push([trFmt(t0), ...ks.flatMap((k) => [r.data[k].avg[i], r.data[k].max[i]])].map(q).join(",")));
    const res = await api("save_export", `autokrp_snmp_${D.t.id}_${typeof trApi(MON.tr) === "string" ? trApi(MON.tr) : Math.floor(r.since) + "-" + Math.floor(r.until)}.csv`, "\ufeff" + lines.join("\r\n"), false);
    if (!res.ok) return toast(res.error, "error"); if (!res.cancelled) toast("ذخیره شد: " + res.path, "ok");
  };
}
async function snChart(D, el, R, defs, opt) {
  const r = await api("mon_snmp_series", D.t.id, typeof R === "string" ? R : trApi(R), defs.map((d) => d[0]));
  if (!el.isConnected) return;
  if (!r.ok) { el.innerHTML = `<div class="empty">${esc(r.error)}</div>`; return; }
  if (opt && opt.note && opt.note.isConnected) opt.note.innerHTML = `<span class="ltr">${esc(trFmt(r.since) + " — " + trFmt(r.until))}</span> · ${esc(trResNote(r))}`;
  snDraw(el, r, defs, opt);
}
function snDraw(el, r, defs, { pct = false, bps = false, height = 200, withMax = false, hideEmpty = false, sync = null, zoomTo = null } = {}) {
  const c = COLORS();
  const series = [];
  defs.forEach(([k, name, color]) => {
    const d = r.data[k]; if (!d) return;
    series.push({ name, color: c[color] || c.info, values: d.avg });
    if (withMax && defs.length === 1) series.push({ name: name + " (" + I18N.t("بیشینه") + ")", color: c.faint, values: d.max });
  });
  const has = series.some((s) => s.values.some((v) => v !== null && v !== undefined));
  if (!has) { el.innerHTML = hideEmpty ? "" : `<div class="empty">هنوز داده‌ای برای این بازه ثبت نشده است.</div>`; return; }
  const ax = monAxis(r.times, r.step);
  const z = zoomTo ? { zoom: (a, b) => monZoomTo(r.times, r.step, a, b, zoomTo), zoomOut: () => monZoomOut(MON.tr, zoomTo) } : {};
  drawChart(el, ax.lab, series, { type: "line", height, fmt: bps ? fmtBps : pct ? (v) => Math.round(v * 10) / 10 + "%" : null, yMax: pct ? 100 : null,
    tips: ax.tips, times: ax.times, sync, stats: true, ...z });
}
