/* ================================================================ ابزارهای شبکه (1.31)
   محل IP/MAC روی سوییچ‌ها (SNMP)، Traceroute، مالک IP (RDAP) و سازنده‌ی MAC (IEEE).
   در تب «ابزارهای شبکه» صفحه‌ی «ارتباط با دستگاه‌ها». */
const NT = { tab: "locate", job: null, jobSince: 0, targets: null, off: new Set(), last: {}, locRes: null, traceRes: null, rdapRes: null, ouiRes: null };
const ntT = (s) => (window.I18N ? window.I18N.t(s) : s);

function sshNet() {
  $("#sshActions").innerHTML = "";
  const tabs = [["locate", "محل IP / MAC"], ["trace", "Traceroute"], ["rdap", "مالک IP (RDAP)"], ["oui", "سازنده‌ی MAC"]];
  $("#sshBody").innerHTML = `<div class="seg" id="ntTabs" style="margin-bottom:14px">${tabs.map(([k, t]) => `<button data-v="${k}" class="${NT.tab === k ? "on" : ""}">${t}</button>`).join("")}</div><div id="ntBody"></div>`;
  $$("#ntTabs button").forEach((b) => (b.onclick = () => { NT.tab = b.dataset.v; sshNet(); }));
  ({ locate: ntLocate, trace: ntTrace, rdap: ntRdap, oui: ntOui })[NT.tab]();
}

/* ---------- کار پس‌زمینه (Traceroute و جستجوی محل) */
async function ntRunJob(start, onLine, onDone, btn) {
  if (NT.job) await api("net_job_cancel", NT.job);
  const r = await withSpin(btn, () => start());
  if (!r.ok) return toast(r.error, "error");
  NT.job = r.id; let since = 0; const jid = r.id;
  ntJobBar(r);
  while (NT.job === jid) {
    await new Promise((res) => setTimeout(res, 800));
    if (NT.job !== jid) return;
    const j = await api("net_job", jid, since);
    if (!j.ok) { NT.job = null; ntJobBar(null); return toast(j.error, "error"); }
    since = j.next;
    if (j.lines.length && onLine) onLine(j.lines);
    ntJobBar(j);
    if (j.status !== "running") {
      NT.job = null; ntJobBar(null);
      if (j.status === "error") return toast(j.error, "error");
      if (j.status === "cancelled") toast("متوقف شد", "warn");
      return onDone(j.result, j);
    }
  }
}
function ntJobBar(j) {
  const b = $("#ntJob"); if (!b) return;
  if (!j || j.status !== "running") { b.hidden = true; return; }
  const [a, n] = j.progress || [0, 0];
  b.hidden = false;
  b.innerHTML = `<span class="cw-spin"></span><span>${esc(ntT("در حال اجرا"))}${n ? ` — <b>${num(a)}</b> / ${num(n)}` : ""}</span><button class="btn sm" id="ntStop">توقف</button>`;
  $("#ntStop").onclick = () => api("net_job_cancel", j.id);
}

/* ---------- محل IP / MAC */
async function ntLocate() {
  const box = $("#ntBody");
  box.innerHTML = `<div class="panel"><div class="form-grid">
      <label class="field"><span>آدرس IP یا MAC</span><input id="nlQ" class="ltr" value="${esc(NT.last.loc || "")}" placeholder="10.1.2.3 / aa:bb:cc:dd:ee:ff / aabb.ccdd.eeff"></label>
      <div class="field" style="align-self:end"><button class="btn primary" id="nlGo">جستجو</button></div></div>
    <p class="hint">جدول ARP (روترها و سوییچ‌های لایه ۳) و جدول MAC سوییچ‌ها با SNMP خوانده می‌شود؛ هیچ تغییری روی دستگاه داده نمی‌شود. دستگاه‌ها همان هدف‌های SNMP مانیتورینگ هستند. پورتی که MAC روی آن دیده شده و فقط چند MAC دارد (و همسایه‌ی LLDP/CDP در «نقشه» نیست) محتمل‌ترین محل است. در Cisco جدول MAC هر VLAN جدا (community@VLAN یا context vlan-N در SNMPv3) خوانده می‌شود.</p>
    <details id="nlDevs"><summary>دستگاه‌ها: <span id="nlDevSum">…</span></summary><div id="nlDevList" style="margin-top:8px"></div></details></div>
    <div class="nt-job" id="ntJob" hidden></div><div id="nlRes"></div>`;
  $("#nlQ").onkeydown = (e) => { if (e.key === "Enter") $("#nlGo").click(); };
  $("#nlGo").onclick = () => {
    const q = $("#nlQ").value.trim(); if (!q) return toast("آدرس را وارد کنید", "error");
    NT.last.loc = q; $("#nlRes").innerHTML = "";
    const L = NT.targets || [], picked = L.filter((t) => !NT.off.has(t.id)).map((t) => t.id);
    if (L.length && !picked.length) return toast("هیچ دستگاهی انتخاب نشده است", "error");
    const ids = picked.length === L.length ? null : picked;          // null = همه (هدف تازه هم خودکار)
    ntRunJob(() => api("net_locate_start", q, ids), null, (res) => { NT.locRes = res; ntLocRender(res); }, $("#nlGo"));
  };
  const r = await api("net_locate_targets");
  if (!r.ok) return toast(r.error, "error");
  NT.targets = r.targets;
  ntDevList();
  if (NT.locRes) ntLocRender(NT.locRes);
}
function ntDevList() {
  const L = NT.targets || [], nsel = () => L.filter((t) => !NT.off.has(t.id)).length;
  $("#nlDevSum").textContent = L.length ? `${num(nsel())} / ${num(L.length)}` : ntT("هیچ هدف SNMP فعالی در مانیتورینگ نیست");
  if (!L.length) { $("#nlDevList").innerHTML = `<div class="empty">ابتدا سوییچ‌ها و روترها را در «مانیتورینگ» با روش SNMP اضافه کنید.</div>`; return; }
  $("#nlDevList").innerHTML = `<div class="row" style="gap:8px;margin-bottom:6px"><button class="btn sm ghost" id="nlAll">همه</button><button class="btn sm ghost" id="nlNone">هیچ</button></div>
    <div class="chks">${L.map((t) => `<label class="chk" title="${esc(t.host)}"><input type="checkbox" data-nl="${t.id}" ${NT.off.has(t.id) ? "" : "checked"}>${esc(t.name)}${t.grp ? ` <span class="muted">(${esc(t.grp)})</span>` : ""}</label>`).join("")}</div>`;
  $$("[data-nl]").forEach((c) => (c.onchange = () => { const id = Number(c.dataset.nl); c.checked ? NT.off.delete(id) : NT.off.add(id); $("#nlDevSum").textContent = `${num(nsel())} / ${num(L.length)}`; }));
  $("#nlAll").onclick = () => { NT.off = new Set(); ntDevList(); };
  $("#nlNone").onclick = () => { NT.off = new Set(L.map((t) => t.id)); ntDevList(); };
}
function ntLocRender(r) {
  const box = $("#nlRes"); if (!box) return;
  const errs = Object.entries(r.errors || {});
  const macs = (r.macs || []).map((m) => `<span class="tag mute ltr" data-no-i18n>${esc(m.mac)}</span>${m.vendor && m.vendor !== "@local" ? ` <span class="muted" data-no-i18n>${esc(m.vendor)}</span>` : ""}`).join(" &nbsp; ");
  let best = "";
  if (r.best) {
    const b = r.best;
    best = `<div class="panel ok-card"><div class="muted">محتمل‌ترین محل</div><div style="font-size:16px;margin-top:4px"><b>${esc(b.device)}</b> — پورت <b class="ltr">${esc(b.port)}</b>${b.vlan != null ? ` — VLAN <b>${esc(b.vlan)}</b>` : ""}${b.alias ? ` — <span class="muted">${esc(b.alias)}</span>` : ""}</div>
      <div class="hint">${num(b.macs_on_port)} MAC روی این پورت دیده شده است.</div></div>`;
  } else if ((r.fdb || []).length) {
    best = `<div class="panel"><div class="hint">MAC فقط روی پورت‌های پرترافیک (uplink یا ترانک) دیده شد؛ سوییچ لبه‌ای که دستگاه به آن وصل است احتمالاً در فهرست دستگاه‌ها نیست.</div></div>`;
  }
  const notFound = r.kind === "ip" && !(r.arp || []).length ? `<div class="empty">این IP در جدول ARP هیچ‌کدام از ${num(r.scanned)} دستگاه نیست (روتر/فایروال آن شبکه را هم به هدف‌های SNMP اضافه کنید، یا دستگاه مدتی است ترافیکی نداشته).</div>`
    : (r.macs || []).length && !(r.fdb || []).length ? `<div class="empty">این MAC در جدول MAC هیچ سوییچی دیده نشد.</div>` : "";
  box.innerHTML = `${r.cancelled ? `<div class="hint warn">جستجو نیمه‌کاره متوقف شد؛ نتیجه ناقص است.</div>` : ""}
    ${macs ? `<div class="panel"><div class="muted" style="margin-bottom:4px">MAC</div>${macs}</div>` : ""}${best}${notFound}
    ${(r.arp || []).length ? `<h3 style="margin:14px 0 6px">جدول ARP</h3><div class="table-wrap inner"><table class="grid"><thead><tr><th>دستگاه</th><th>IP</th><th>MAC</th><th>اینترفیس</th></tr></thead><tbody>
      ${r.arp.map((a) => `<tr><td>${esc(a.device)}</td><td class="ltr">${esc(a.ip)}</td><td class="ltr" data-no-i18n>${esc(a.mac)}</td><td class="ltr">${esc(a.port)}</td></tr>`).join("")}</tbody></table></div>` : ""}
    ${(r.fdb || []).length ? `<h3 style="margin:14px 0 6px">جدول MAC سوییچ‌ها</h3><div class="table-wrap inner"><table class="grid"><thead><tr><th>دستگاه</th><th>پورت</th><th>VLAN</th><th>توضیح پورت</th><th>MACهای پورت</th><th>نوع پورت</th></tr></thead><tbody>
      ${r.fdb.map((f) => `<tr><td>${esc(f.device)}</td><td class="ltr">${esc(f.port)}</td><td>${f.vlan == null ? "—" : esc(f.vlan)}</td><td>${esc(f.alias || "—")}</td><td>${num(f.macs_on_port)}</td>
        <td>${f.edge ? `<span class="tag ok">لبه</span>` : f.uplink ? `<span class="tag mute">لینک به دستگاه دیگر</span>` : `<span class="tag mute">ترانک / پرترافیک</span>`}</td></tr>`).join("")}</tbody></table></div>` : ""}
    ${errs.length ? `<details style="margin-top:12px"><summary class="warn-text">${num(errs.length)} دستگاه خطا داشت</summary><ul class="hint">${errs.map(([k, v]) => `<li><b>${esc(k)}</b>: ${esc(v.join(" — "))}</li>`).join("")}</ul></details>` : ""}`;
}

/* ---------- Traceroute */
function ntTrace() {
  const L = NT.last;
  $("#ntBody").innerHTML = `<div class="panel"><div class="form-grid">
      <label class="field"><span>مقصد (IP یا نام)</span><input id="ntH" class="ltr" value="${esc(L.trH || "")}" placeholder="8.8.8.8"></label>
      <label class="field"><span>حداکثر گام</span><input id="ntHops" type="number" class="ltr" min="1" max="64" value="${esc(L.trHops || 30)}"></label>
      <label class="field"><span>انتظار هر گام (ثانیه)</span><input id="ntW" type="number" class="ltr" min="1" max="10" value="${esc(L.trW || 2)}"></label>
      <label class="chk" style="align-self:end"><input type="checkbox" id="ntRes" ${L.trRes ? "checked" : ""}>نمایش نام میزبان‌ها (کندتر)</label>
      <div class="field" style="align-self:end"><button class="btn primary" id="ntGo">شروع</button></div></div>
    <p class="hint">با برنامه‌ی خود سیستم‌عامل (tracert ویندوز) اجرا می‌شود؛ در حالت سرور مسیر از خود سرور سنجیده می‌شود.</p></div>
    <div class="nt-job" id="ntJob" hidden></div><div id="ntOut"></div>`;
  $("#ntH").onkeydown = (e) => { if (e.key === "Enter") $("#ntGo").click(); };
  $("#ntGo").onclick = () => {
    const h = $("#ntH").value.trim(); if (!h) return toast("مقصد را وارد کنید", "error");
    Object.assign(L, { trH: h, trHops: $("#ntHops").value, trW: $("#ntW").value, trRes: $("#ntRes").checked });
    const out = []; NT.traceRes = { host: h, lines: out, hops: null };
    ntTraceRender();
    ntRunJob(() => api("net_trace_start", h, Number(L.trHops), Number(L.trW), L.trRes),
      (lines) => { out.push(...lines); ntTraceRender(); }, (res) => { NT.traceRes.hops = res.hops; ntTraceRender(); }, $("#ntGo"));
  };
  if (NT.traceRes) ntTraceRender();
}
function ntIsPublic(ip) {
  if (ip.includes(":")) return !/^(fe8|fc|fd|::1$|::$)/i.test(ip);
  const p = ip.split(".").map(Number);
  return !(p[0] === 10 || p[0] === 127 || (p[0] === 172 && p[1] >= 16 && p[1] < 32) || (p[0] === 192 && p[1] === 168) || (p[0] === 100 && p[1] >= 64 && p[1] < 128) || (p[0] === 169 && p[1] === 254) || p[0] >= 224 || p[0] === 0);
}
function ntTraceRender() {
  const r = NT.traceRes, box = $("#ntOut"); if (!r || !box) return;
  const hops = r.hops;
  box.innerHTML = `${hops && hops.length ? `<div class="table-wrap inner"><table class="grid"><thead><tr><th>گام</th><th>آدرس</th><th>کمترین (ms)</th><th>میانگین (ms)</th><th>بی‌پاسخ</th><th></th></tr></thead><tbody>
      ${hops.map((h) => { const avg = h.rtt.length ? h.rtt.reduce((a, b) => a + b, 0) / h.rtt.length : null;
        return `<tr><td>${h.hop}</td><td class="ltr">${h.ips.length ? h.ips.map(esc).join(", ") : "*"}</td><td>${h.rtt.length ? Math.min(...h.rtt) : "—"}</td><td>${avg == null ? "—" : avg.toFixed(1)}</td><td>${h.lost || "—"}</td>
        <td>${h.ips.filter(ntIsPublic).slice(0, 1).map((ip) => `<button class="btn sm ghost" data-rd="${esc(ip)}">مالک IP</button>`).join("")}</td></tr>`; }).join("")}</tbody></table></div>` : ""}
    <pre class="ltr paste-prev" data-no-i18n style="margin-top:10px">${esc(r.lines.join("\n")) || "…"}</pre>`;
  $$("[data-rd]", box).forEach((b) => (b.onclick = () => { NT.tab = "rdap"; NT.last.rdIp = b.dataset.rd; sshNet(); $("#rdGo").click(); }));
}

/* ---------- RDAP */
function ntRdap() {
  $("#ntBody").innerHTML = `<div class="panel"><div class="form-grid">
      <label class="field"><span>آدرس IP</span><input id="rdIp" class="ltr" value="${esc(NT.last.rdIp || "")}" placeholder="203.0.113.10"></label>
      <div class="field" style="align-self:end"><button class="btn primary" id="rdGo">جستجو</button></div></div>
    <p class="hint">RDAP جایگزین استاندارد WHOIS است: مالک رنج IP، کشور، ایمیل abuse و تاریخ ثبت از سرور ثبت منطقه‌ای (RIPE، ARIN، …). سرور مناسب از فهرست IANA پیدا می‌شود؛ به اینترنت نیاز دارد.</p></div><div id="rdOut"></div>`;
  $("#rdIp").onkeydown = (e) => { if (e.key === "Enter") $("#rdGo").click(); };
  $("#rdGo").onclick = async () => {
    const ip = $("#rdIp").value.trim(); if (!ip) return toast("آدرس را وارد کنید", "error");
    NT.last.rdIp = ip;
    const r = await withSpin($("#rdGo"), () => api("net_rdap", ip));
    if (!r.ok) { $("#rdOut").innerHTML = ""; return toast(r.error, "error"); }
    NT.rdapRes = r; ntRdapRender();
  };
  if (NT.rdapRes) ntRdapRender();
}
function ntRdapRender() {
  const r = NT.rdapRes, box = $("#rdOut"); if (!r || !box) return;
  const row = (k, v) => (v ? `<dt>${k}</dt><dd class="ltr" data-no-i18n>${esc(v)}</dd>` : "");
  box.innerHTML = `<div class="panel"><dl class="kv">
      ${row("IP", r.ip, 1)}${row("نام شبکه", r.name, 1)}${row("مالک", r.owner, 1)}${row("کشور", r.country, 1)}
      ${row("رنج", r.start && r.end ? `${r.start} – ${r.end}` : "", 1)}${row("CIDR", (r.cidrs || []).join(", "), 1)}
      ${row("ایمیل abuse", r.abuse, 1)}${row("شناسه", r.handle, 1)}${row("شبکه‌ی بالادست", r.parent, 1)}${row("نوع", r.type, 1)}
      ${row("ثبت", r.registered, 1)}${row("آخرین تغییر", r.changed, 1)}${row("سرور", r.server, 1)}</dl>
    ${(r.entities || []).length ? `<h3 style="margin:12px 0 6px">نهادها</h3><div class="table-wrap inner"><table class="grid"><thead><tr><th>شناسه</th><th>نقش</th><th>نام</th><th>ایمیل</th></tr></thead><tbody>
      ${r.entities.map((e) => `<tr><td class="ltr">${esc(e.handle)}</td><td class="ltr">${esc((e.roles || []).join(", "))}</td><td class="ltr" data-no-i18n>${esc(e.name || "")}</td><td class="ltr" data-no-i18n>${esc(e.email || "")}</td></tr>`).join("")}</tbody></table></div>` : ""}
    ${(r.remarks || []).length ? `<ul class="hint ltr" data-no-i18n style="margin-top:10px">${r.remarks.map((x) => `<li>${esc(x)}</li>`).join("")}</ul>` : ""}
    <details style="margin-top:10px"><summary>پاسخ کامل (JSON)</summary><pre class="ltr paste-prev" data-no-i18n>${esc(r.raw || "")}</pre></details></div>`;
}

/* ---------- سازنده‌ی MAC */
function ntOui() {
  $("#ntBody").innerHTML = `<div class="panel">
    <label class="field"><span>MAC یا متن شامل MAC (مثلاً خروجی show mac address-table یا arp -a)</span>
      <textarea id="ouiT" class="ltr code-edit" style="min-height:120px" placeholder="aa:bb:cc:dd:ee:ff&#10;0011.2233.4455">${esc(NT.last.oui || "")}</textarea></label>
    <div class="row" style="gap:8px;margin-top:8px;flex-wrap:wrap"><button class="btn primary" id="ouiGo">جستجو</button><span class="muted" id="ouiInfo"></span>
      <button class="btn sm ghost adm-only" id="ouiUpd" style="margin-inline-start:auto" title="دریافت آخرین فهرست از standards-oui.ieee.org">به‌روزرسانی از IEEE</button></div></div><div id="ouiOut"></div>`;
  $("#ouiGo").onclick = async () => {
    NT.last.oui = $("#ouiT").value;
    const r = await withSpin($("#ouiGo"), () => api("net_oui", NT.last.oui));
    if (!r.ok) return toast(r.error, "error");
    NT.ouiRes = r; ntOuiRender();
  };
  $("#ouiUpd").onclick = async () => {
    const r = await withSpin($("#ouiUpd"), () => api("net_oui_update"));
    if (!r.ok) return toast(r.error, "error");
    toast("به‌روز شد", "ok"); if (NT.ouiRes) { NT.ouiRes.info = r; ntOuiRender(); } else ntOuiInfo(r);
  };
  if (NT.ouiRes) ntOuiRender();
}
function ntOuiInfo(i) {
  const el = $("#ouiInfo"); if (!el || !i) return;
  el.textContent = `${ntT("جدول IEEE")}: ${num(i.entries)} — ${i.source === "ieee" ? ntT("به‌روزشده") : ntT("همراه برنامه")}${i.updated ? " (" + fmtDate(i.updated) + ")" : ""}`;
}
function ntOuiRender() {
  const r = NT.ouiRes, box = $("#ouiOut"); if (!r || !box) return;
  ntOuiInfo(r.info);
  box.innerHTML = r.items.length ? `<div class="row" style="gap:8px;margin:10px 0"><b>${num(r.items.length)} MAC</b><button class="btn sm ghost" id="ouiCsv">CSV</button></div>
    <div class="table-wrap inner"><table class="grid"><thead><tr><th>MAC</th><th>سازنده</th></tr></thead><tbody>
    ${r.items.slice(0, 500).map((x) => `<tr><td class="ltr" data-no-i18n>${esc(x.mac)}</td>${x.vendor === "@local" ? `<td class="muted">آدرس محلی یا تصادفی (بدون سازنده)</td>` : `<td class="ltr" data-no-i18n>${esc(x.vendor || "—")}</td>`}</tr>`).join("")}</tbody></table></div>
    ${r.items.length > 500 ? `<p class="hint">۵۰۰ ردیف اول نمایش داده شد؛ همه در CSV هستند.</p>` : ""}` : `<div class="empty">هیچ MAC معتبری در متن پیدا نشد.</div>`;
  const c = $("#ouiCsv"); if (c) c.onclick = () => offSaveCsv("mac_vendors.csv", ["MAC", "Vendor"], r.items.map((x) => [x.mac, x.vendor]));
}
