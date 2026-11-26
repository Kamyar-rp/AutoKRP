/* ================================================================ پایگاه داده (محلی / MySQL / PostgreSQL) — فقط ادمین */
"use strict";
const DB_SSL = [["off", "پیش‌فرض (بدون اجبار)"], ["required", "TLS اجباری (بدون بررسی گواهی)"], ["verify_ca", "TLS با بررسی CA"], ["verify_identity", "TLS با بررسی CA و نام سرور"]];
const DB_MODES = [
  ["cols", "رمز ستون‌های حساس (پیشنهادی)", "متن‌ها و جزئیات (تاریخچه، امضاها، خطاها، آدرس و یوزر دستگاه‌ها، اسکریپت‌ها) با AES-256-GCM رمز می‌شوند؛ IP، وضعیت، امتیاز، کشور و زمان‌ها برای گزارش‌گیری خوانا می‌مانند."],
  ["plain", "خوانا", "همه‌ی جدول‌ها و ستون‌ها برای کوئری و گزارش‌گیری با ابزارهای دیگر خوانا هستند. امنیت فقط با TLS، دسترسی‌ها و رمزنگاری دیسک خود سرور پایگاه داده."],
  ["blob", "کاملاً رمزشده", "کل پایگاه داده یک تصویر رمزشده است (مثل فایل محلی)؛ گزارش‌گیری بیرونی ممکن نیست. ذخیره هر ۳۰ ثانیه."]];
const DB_STATE = { mode: "cols", ssl: "off", choice: "local", engine: "mysql" };
// 1.53: PostgreSQL 16+ کنار MySQL / MariaDB
const DB_ENG = { mysql: { name: "MySQL / MariaDB", port: 3306 }, postgres: { name: "PostgreSQL", port: 5432 } };
const dbExt = (d) => !!d && (d.backend === "mysql" || d.backend === "postgres");

function dbStatusHtml(d) {
  if (!dbExt(d)) return `<dl class="kv"><dt>محل داده‌ها</dt><dd>${d && d.engine === "cipher" ? "فایل رمزشده‌ی محلی SQLCipher (state.sdb؛ هر صفحه AES-256 با امضای HMAC)" : "فایل رمزشده‌ی محلی (state.dat)"}</dd>${d && d.data_dir ? `<dt>پوشه</dt><dd class="dpath" dir="ltr" data-no-i18n>${esc(d.data_dir)}</dd>` : ""}</dl>`;
  const mode = (DB_MODES.find((m) => m[0] === d.mode) || [, d.mode])[1], ssl = (DB_SSL.find((m) => m[0] === d.ssl) || [, d.ssl])[1];
  return `<dl class="kv"><dt>محل داده‌ها</dt><dd>${DB_ENG[d.backend].name}</dd>
    <dt>سرور</dt><dd class="ltr">${esc(d.user)}@${esc(d.host)}:${esc(d.port)} / ${esc(d.database)}</dd>
    <dt>نحوه‌ی ذخیره</dt><dd>${esc(mode)}</dd><dt>TLS</dt><dd>${esc(ssl)}</dd>
    <dt>وضعیت</dt><dd>${d.ok === false ? `<span class="tag err">خطا</span> <span class="tech">${esc(d.error || "")}</span>` : `<span class="tag ok">متصل</span>`}</dd>
    <dt>آخرین ذخیره</dt><dd>${d.last_flush ? fmtDate(d.last_flush) : "—"}${d.pending ? ` — ${num(d.pending)} تغییر در صف` : ""}</dd></dl>`;
}

function renderDatabaseTab(body) {
  const d = (S.state && S.state.db) || { backend: "local" };
  body.innerHTML = `<div class="form"><h3>پایگاه داده</h3>${dbStatusHtml(d)}
      <p class="hint">داده‌های برنامه (IPها، اجراها، تاریخچه، آمار، دستگاه‌ها، مانیتورینگ) در حافظه کار می‌کنند و هر چند ثانیه در محل انتخاب‌شده ذخیره می‌شوند. تنظیمات، اسرار، فایل‌های هر اجرا و متن پشتیبان‌های کانفیگ همیشه محلی و رمزشده‌اند.</p>
      <div class="row" style="gap:8px;margin-top:10px;flex-wrap:wrap">
        <button class="btn primary" id="dbMy">${dbExt(d) ? "تغییر تنظیمات پایگاه داده…" : "انتقال به MySQL یا PostgreSQL…"}</button>
        ${dbExt(d) ? `<button class="btn" id="dbLocal">برگشت به پایگاه داده‌ی محلی</button>` : ""}</div></div>`;
  $("#dbMy", body).onclick = async () => { await dbDialog(false); renderDatabaseTab(body); };
  const bl = $("#dbLocal", body);
  if (bl) bl.onclick = async () => {
    if (!(await confirm2({ title: "برگشت به پایگاه داده‌ی محلی", confirm: "برگشت به محلی",
      body: `<p>داده‌های فعلی در فایل رمزشده‌ی محلی نوشته می‌شوند و از این به بعد آنجا ذخیره می‌شوند. داده‌های سرور پایگاه داده <b>دست نمی‌خورند</b> (پاک کردنشان با خودتان).</p>` }))) return;
    const r = await api("db_use_local"); if (!r.ok) return toast(r.error, "error");
    S.state.db = r.db; toast("پایگاه داده: محلی", "ok"); renderDatabaseTab(body);
  };
}

/* first = پرسش اولین اجرا (محلی، MySQL یا PostgreSQL) */
async function dbDialog(first) {
  const cur = (S.state && S.state.db) || {};
  const c = dbExt(cur) ? cur : {};
  DB_STATE.mode = c.mode || "cols"; DB_STATE.ssl = c.ssl || "off"; DB_STATE.engine = c.backend || "mysql"; DB_STATE.choice = first ? "local" : DB_STATE.engine;
  return openModal({ title: first ? "محل نگهداری داده‌ها" : "اتصال پایگاه داده‌ی بیرونی", wide: true,
    body: `${first ? `<p>داده‌های برنامه (IPها، اجراها، تاریخچه، آمار) کجا نگهداری شوند؟ بعداً هم از «تنظیمات ← پایگاه داده» قابل تغییر است.</p>
      <div class="mode-cards" id="dbChoice"><button class="mode-card on" data-v="local"><b>محلی (پیشنهادی)</b><span>فایل رمزشده روی همین سیستم؛ بدون نیاز به سرور.</span>${cur.data_dir ? `<span class="dpath" dir="ltr" data-no-i18n>${esc(cur.data_dir)}</span>` : ""}</button>
        <button class="mode-card" data-v="mysql"><b>MySQL / MariaDB</b><span>یوزر و پسورد را بدهید؛ برنامه پایگاه داده و جدول‌ها را خودش می‌سازد و با به‌روزرسانی برنامه ساختارشان را به‌روز می‌کند.</span></button>
        <button class="mode-card" data-v="postgres"><b>PostgreSQL</b><span>نسخه‌ی ۱۶ یا بالاتر؛ مثل MySQL، پایگاه داده و جدول‌ها خودکار ساخته و به‌روز می‌شوند.</span></button></div>` : ""}
      <div id="dbForm" ${first ? "hidden" : ""} style="margin-top:12px">
        ${first ? "" : `<div class="row" style="gap:10px;align-items:center;margin-bottom:10px"><span>نوع پایگاه داده</span><div class="seg" id="dbEng">${Object.entries(DB_ENG).map(([k, e]) => `<button type="button" class="${DB_STATE.engine === k ? "on" : ""}" data-v="${k}">${e.name}</button>`).join("")}</div></div>`}
        <div class="form-grid">
        <label class="field"><span>آدرس سرور</span><input id="dbHost" class="ltr" value="${esc(c.host || "")}" placeholder="10.0.0.20"></label>
        <label class="field"><span>پورت</span><input id="dbPort" class="ltr" value="${esc(c.port || DB_ENG[DB_STATE.engine].port)}"></label>
        <label class="field"><span>نام کاربری</span><input id="dbUser" class="ltr" autocomplete="off" value="${esc(c.user || "")}"></label>
        <label class="field"><span>رمز</span><input id="dbPass" type="password" class="ltr" autocomplete="new-password" placeholder="${c.host ? "خالی = همان رمز قبلی" : ""}"></label>
        <label class="field"><span>نام پایگاه داده (اگر نباشد ساخته می‌شود)</span><input id="dbName" class="ltr" value="${esc(c.database || "autokrp")}"></label>
        <label class="field"><span>TLS</span><select id="dbSsl">${DB_SSL.map(([k, t]) => `<option value="${k}" ${DB_STATE.ssl === k ? "selected" : ""}>${t}</option>`).join("")}</select></label>
        <label class="field wide" id="dbCaW" hidden><span>گواهی CA سرور پایگاه داده (PEM)</span><textarea id="dbCa" class="ltr code-edit" style="min-height:90px" placeholder="-----BEGIN CERTIFICATE-----"></textarea>
          <small class="hint">${c.has_ca ? "گواهی قبلی ذخیره است؛ خالی = همان. " : ""}برای گواهی خودساخته‌ی سرور «بررسی CA» کافی است (نام سرور در آن نیست).</small></label></div>
        <h3 style="margin:14px 0 8px">نحوه‌ی ذخیره</h3>
        <div class="mode-cards" id="dbModes">${DB_MODES.map(([k, t, dsc]) => `<button class="mode-card ${DB_STATE.mode === k ? "on" : ""}" data-v="${k}" ${c.mode && c.mode !== k ? "" : ""}><b>${t}</b><span>${dsc}</span></button>`).join("")}</div>
        <p class="hint warn" id="dbWarn"></p>
        <p class="hint" id="dbPerm"></p>
        <div id="dbProbe" style="margin-top:10px"></div></div>`,
    foot: `<span class="muted" id="dbBusy"></span><span style="flex:1"></span>${first ? `<button class="btn primary" id="dbLocalGo">ادامه با محلی</button>` : `<button class="btn ghost" data-r="0">انصراف</button>`}
      <button class="btn" id="dbTest" ${first ? "hidden" : ""}>تست اتصال</button><button class="btn primary" id="dbGo" ${first ? "hidden" : ""}>استفاده از این پایگاه داده</button>`,
    onOpen: (m, close) => {
      const x = (s) => $(s, m);
      const cancel = x("[data-r='0']"); if (cancel) cancel.onclick = () => close(null);
      const warn = () => {
        x("#dbWarn").textContent = I18N.t(DB_STATE.mode === "plain"
          ? "در این حالت داده‌ها در سرور پایگاه داده رمز نمی‌شوند؛ TLS را روشن و دسترسی به سرور پایگاه داده را محدود کنید."
          : "کلید رمز همان کلید داده‌های همین نصب است؛ اگر این سیستم (یا کاربر ویندوز در حالت کلاینت) از دست برود، داده‌های رمزشده در سرور پایگاه داده قابل بازیابی نیستند.");
        x("#dbCaW").hidden = !x("#dbSsl").value.startsWith("verify");
        x("#dbPerm").textContent = I18N.t(DB_STATE.engine === "postgres"
          ? "دسترسی لازم برای این کاربر: CREATEDB (اگر پایگاه داده هنوز نیست؛ وگرنه آن را خودتان با ENCODING 'UTF8' بسازید)، و مالکیت یا CREATE روی schema پیش‌فرض (public) همان پایگاه داده. اتصال باید در pg_hba.conf مجاز باشد. هم‌زمان فقط یک AutoKRP از یک پایگاه داده استفاده می‌کند."
          : "دسترسی لازم برای این کاربر: ساخت پایگاه داده (اگر هنوز نیست) و CREATE، ALTER، DROP، SELECT، INSERT، UPDATE، DELETE روی همان پایگاه داده. هم‌زمان فقط یک AutoKRP از یک پایگاه داده استفاده می‌کند.");
      };
      const setEng = (e) => {         // پورت پیش‌فرض با نوع پایگاه داده عوض شود (اگر کاربر چیز دیگری ننوشته)
        const p = x("#dbPort"), old = DB_ENG[DB_STATE.engine].port;
        DB_STATE.engine = e;
        if (!p.value || Number(p.value) === old) p.value = DB_ENG[e].port;
        $$("#dbEng button", m).forEach((y) => y.classList.toggle("on", y.dataset.v === e));
        warn();
      };
      $$("#dbEng button", m).forEach((b) => (b.onclick = () => setEng(b.dataset.v)));
      if (first) $$("#dbChoice .mode-card", m).forEach((b) => (b.onclick = () => {
        DB_STATE.choice = b.dataset.v; $$("#dbChoice .mode-card", m).forEach((y) => y.classList.toggle("on", y === b));
        const my = DB_STATE.choice !== "local";
        if (my) setEng(DB_STATE.choice);
        x("#dbForm").hidden = !my; x("#dbTest").hidden = !my; x("#dbGo").hidden = !my; x("#dbLocalGo").hidden = my;
      }));
      $$("#dbModes .mode-card", m).forEach((b) => (b.onclick = () => { DB_STATE.mode = b.dataset.v; $$("#dbModes .mode-card", m).forEach((y) => y.classList.toggle("on", y === b)); warn(); }));
      x("#dbSsl").onchange = warn; warn();
      const conf = () => ({ backend: DB_STATE.engine, host: x("#dbHost").value.trim(), port: Number(x("#dbPort").value) || DB_ENG[DB_STATE.engine].port, user: x("#dbUser").value.trim(),
        password: x("#dbPass").value, database: x("#dbName").value.trim(), ssl: x("#dbSsl").value, ca_pem: x("#dbCa").value.trim(), mode: DB_STATE.mode });
      const busy = (t) => { x("#dbBusy").textContent = t ? I18N.t(t) : ""; ["#dbTest", "#dbGo"].forEach((s) => (x(s).disabled = !!t)); };
      const showProbe = (i) => {
        const data = i.has_data ? `<span class="tag warn">داده‌ی AutoKRP دارد</span> (حالت ${esc((DB_MODES.find((q) => q[0] === i.mode) || [, i.mode])[1])}${i.key_ok === false ? `، <b>با کلید نصب دیگری رمز شده</b>` : ""})`
          : i.db_exists ? `<span class="tag ok">خالی</span>` : `<span class="tag ok">وجود ندارد؛ ساخته می‌شود</span>`;
        x("#dbProbe").innerHTML = `<div class="panel inner"><dl class="kv"><dt>سرور</dt><dd class="ltr">${esc(i.version)}</dd>
          <dt>TLS</dt><dd>${i.tls ? `<span class="tag ok">رمزشده</span> <span class="ltr">${esc(i.tls)}</span>` : `<span class="tag warn">بدون رمزنگاری</span>`}</dd>
          <dt>پایگاه داده</dt><dd>${data}</dd></dl></div>`;
      };
      x("#dbTest").onclick = async () => {
        busy("در حال اتصال…"); const r = await api("db_test", conf()); busy("");
        if (!r.ok) { x("#dbProbe").innerHTML = `<p class="hint warn">${esc(r.error)}</p>`; return; }
        showProbe(r.info);
      };
      const go = async (useExisting) => {
        busy("در حال انتقال داده‌ها…"); const r = await api("db_use_mysql", conf(), !!useExisting); busy("");
        if (!r.ok) { x("#dbProbe").innerHTML = `<p class="hint warn">${esc(r.error)}</p>`; return; }
        if (r.exists) {
          x("#dbProbe").innerHTML = `<div class="panel inner"><p><b>این پایگاه داده از قبل داده‌ی AutoKRP دارد.</b> با ادامه، داده‌های فعلی این برنامه کنار گذاشته و داده‌های همان پایگاه داده بارگذاری می‌شوند. برای انتقال داده‌های فعلی، نام پایگاه داده‌ی دیگری بدهید.</p>
            <button class="btn danger" id="dbUseEx">استفاده از داده‌های موجود در این پایگاه داده</button></div>`;
          x("#dbUseEx").onclick = () => go(true); return;
        }
        S.state.db = r.db; toast(r.reconnected ? "تنظیمات اتصال ذخیره شد" : r.loaded ? "داده‌های پایگاه داده بارگذاری شد" : "داده‌ها به پایگاه داده‌ی بیرونی منتقل شد", "ok");
        close(true); refreshState(); if (S.page !== "settings") go2(S.page);
      };
      x("#dbGo").onclick = () => go(false);
      const lg = x("#dbLocalGo");
      if (lg) lg.onclick = async () => { const r = await api("db_use_local"); if (!r.ok) return toast(r.error, "error"); S.state.db = r.db; close(false); };
    } });
}
function go2(p) { if (typeof go === "function") go(p); }
function dbMaybePrompt(r) {
  // اولین اجرا، فقط ادمین، وقتی پنجره‌ی دیگری باز نیست
  if (r && r.db && r.db.prompt && !S.dbPrompted && $("#modalBack").hidden) { S.dbPrompted = true; dbDialog(true); }
}
