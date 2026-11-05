"use strict";
/* ================================================================ لاگ ممیزی (1.46)
 * تنظیمات ← لاگ ممیزی (فقط ادمین اصلی): وضعیت زنجیره، بررسی یکپارچگی، ارسال به Syslog/SIEM (RFC 5424 یا CEF؛ UDP/TCP/TLS). */
async function renderAuditTab(body) {
  body.innerHTML = `<div class="empty">…</div>`;
  const r = await api("audit_status");
  if (S.setTab !== "audit") return;
  if (!r.ok) { body.innerHTML = `<div class="empty">${esc(r.error)}</div>`; return; }
  const c = r.cfg, st = r.stats, s2 = r.status || {};
  body.innerHTML = `<div class="form"><h3>لاگ ممیزی</h3>
      <p class="hint">هر رخداد «تاریخچه» (ورود و خروج و ورود ناموفق، تغییر کاربران و دسترسی‌ها و تنظیمات، اجرای ابزارها، بلاک، ترمینال، انتقال فایل، …) در لاگ ممیزی هم نوشته می‌شود. ردیف‌ها با امضای زنجیره‌ای (HMAC-SHA256) به هم وصل‌اند: هر تغییر، حذف یا جابه‌جایی با «بررسی یکپارچگی» معلوم می‌شود. از داخل برنامه هیچ راهی برای حذف یا ویرایش آن نیست. برای اینکه حتی کسی که به سرور برنامه دسترسی دارد نتواند ردی را پاک کند، آن را به Syslog/SIEM بفرستید.</p>
      <div class="kpis" style="margin:10px 0">
        <div class="kpi"><b>${num(st.rows)}</b><span>ردیف</span></div>
        <div class="kpi"><b class="ltr">${st.first ? fmtDate(st.first) : "—"}</b><span>از</span></div>
        <div class="kpi"><b>${num(st.unsealed)}</b><span>منتظر امضا</span></div>
        <div class="kpi"><b>${c.enabled ? num(r.pending) : "—"}</b><span>منتظر ارسال</span></div></div>
      <div class="row" style="gap:8px"><button class="btn" id="auVerify">بررسی یکپارچگی</button><span id="auVres" class="muted"></span></div>
      <p class="hint">حجم: هر رخداد حدود ۳۰۰ بایت؛ امضا چند میکروثانیه و ارسال در پس‌زمینه است و برنامه را کند نمی‌کند.</p></div>
    <div class="form"><h3>ارسال به Syslog / SIEM</h3>
      <div class="row" style="justify-content:space-between"><label class="switch"><input type="checkbox" id="auOn" ${c.enabled ? "checked" : ""}><span class="track"><span class="thumb"></span></span><b>ارسال روشن</b></label>
        <span class="muted">${s2.last_ok ? `${esc(I18N.t("آخرین ارسال موفق"))}: <span class="ltr">${fmtDate(s2.last_ok)}</span>` : ""}${s2.last_error ? ` <span class="warn">· ${esc(I18N.t("آخرین خطا"))}: ${esc(s2.last_error)}</span>` : ""}</span></div>
      <div class="form-grid" style="margin-top:10px">
        <label class="field"><span>آدرس سرور</span><input id="auHost" class="ltr" value="${esc(c.host)}" placeholder="siem.example.local"></label>
        <label class="field"><span>پورت</span><input id="auPort" class="ltr" type="number" min="1" max="65535" value="${c.port}"></label>
        <label class="field"><span>پروتکل</span><select id="auProto"><option value="udp">UDP</option><option value="tcp">TCP</option><option value="tls">TLS (TCP رمزشده)</option></select></label>
        <label class="field"><span>قالب</span><select id="auFmt"><option value="syslog">Syslog (RFC 5424)</option><option value="cef">CEF</option></select></label>
        <label class="field"><span>Facility</span><input id="auFac" class="ltr" type="number" min="0" max="23" value="${c.facility}"></label>
        <label class="field"><span>نام میزبان در پیام (خالی = نام همین کامپیوتر)</span><input id="auHn" class="ltr" value="${esc(c.hostname)}"></label>
        <div class="field"><span>&nbsp;</span><label class="chk"><input type="checkbox" id="auVer" ${c.verify_tls ? "checked" : ""}>بررسی گواهی TLS</label></div></div>
      <h4 style="margin:12px 0 6px">دسته‌ها</h4>
      <div class="chks">${Object.entries(r.cats).map(([k, t]) => `<label class="chk"><input type="checkbox" data-auc="${k}" ${c.cats.includes(k) ? "checked" : ""}>${esc(I18N.t(t))}</label>`).join("")}</div>
      <label class="chk" style="margin-top:10px"><input type="checkbox" id="auAll">${esc(I18N.t("با روشن کردن، ردیف‌های قبلی هم فرستاده شوند (وگرنه از همین حالا)"))}</label>
      <p class="hint">UDP ساده است ولی رسیدن پیام تضمین نمی‌شود؛ TCP و TLS اگر مقصد در دسترس نباشد، ردیف‌ها را نگه می‌دارند و بعد می‌فرستند. Splunk: یک ورودی UDP/TCP (مثلاً sourcetype=syslog یا cef) بسازید.</p>
      <div class="form-foot"><button class="btn" id="auTest">ارسال پیام آزمایشی</button><button class="btn primary" id="auSave">ذخیره</button></div></div>`;
  $("#auProto", body).value = c.proto; $("#auFmt", body).value = c.format;
  $("#auProto", body).onchange = (e) => { const p = $("#auPort", body); if (e.target.value === "tls" && p.value === "514") p.value = 6514; if (e.target.value !== "tls" && p.value === "6514") p.value = 514; };
  const read = () => ({ enabled: $("#auOn", body).checked, host: $("#auHost", body).value.trim(), port: Number($("#auPort", body).value) || 514,
    proto: $("#auProto", body).value, format: $("#auFmt", body).value, facility: Number($("#auFac", body).value) || 13, hostname: $("#auHn", body).value.trim(),
    verify_tls: $("#auVer", body).checked, cats: $$("[data-auc]", body).filter((x) => x.checked).map((x) => x.dataset.auc) });
  $("#auSave", body).onclick = (e) => withSpin(e.currentTarget, async () => {
    const x = await api("audit_cfg_save", read(), $("#auAll", body).checked); if (!x.ok) return toast(x.error, "error");
    toast("ذخیره شد", "ok"); renderAuditTab(body);
  });
  $("#auTest", body).onclick = (e) => withSpin(e.currentTarget, async () => { const x = await api("audit_test", read()); toast(x.ok ? x.message : x.error, x.ok ? "ok" : "error"); });
  $("#auVerify", body).onclick = (e) => withSpin(e.currentTarget, async () => {
    const x = await api("audit_verify"); if (!x.ok) return toast(x.error, "error");
    const v = x.result;
    $("#auVres", body).innerHTML = v.ok ? `<span class="tag ok">${esc(I18N.t("سالم"))}</span> ${num(v.checked)} ${esc(I18N.t("ردیف بررسی شد"))}${v.unsealed ? ` · ${num(v.unsealed)} ${esc(I18N.t("منتظر امضا"))}` : ""}`
      : `<span class="tag err">${esc(I18N.t("دست‌کاری شده"))}</span> <span>${esc(v.reason || "")}</span>`;
  });
}
