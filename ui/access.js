/* ================================================================ دسترسی‌ها (1.32، شبیه پنل ادمین جنگو)
   گروه‌ها با سطح هر ابزار (پنهان / دیدن / اجرا) و دستگاه‌های مجاز؛ هر کاربر عضو چند گروه + استثنای خودش.
   فقط «ادمین اصلی» این بخش را می‌بیند و تغییر می‌دهد؛ اجرای واقعی همیشه سمت سرور (perms.levels) بررسی می‌شود. */
const AC = { data: null };
const AC_LV = [["none", "پنهان"], ["view", "دیدن"], ["run", "اجرا"]];
const acT = (s) => (window.I18N ? window.I18N.t(s) : s);
function acTitle(k) { return (AC.data && AC.data.titles[k]) || k; }
function acBadge(lv) {
  return lv === "run" ? `<span class="tag ok" data-sv="2" title="اجرا">✓</span>` : lv === "view" ? `<span class="tag info" data-sv="1" title="دیدن">👁</span>` : `<span class="muted" data-sv="0" title="پنهان">—</span>`;
}
/* 1.39: درخت بخش‌ها در پنجره‌ی گروه و کاربر. mode: group (بدون سطح: کلید پایه = پنهان، والد = بدون سقف، زیرمجموعه = مثل بخش)
   یا user (بدون سطح = از گروه‌ها). فقط سطح‌های تعیین‌شده ذخیره می‌شوند. */
function acKind(k) { const D = AC.data; return D.pure.includes(k) ? "pure" : D.subs.includes(k) ? "sub" : "base"; }
function acTreeSel(k, cur, mode, hint) {
  const nv = (AC.data.no_view || []).includes(k.split(".")[0]);
  const kind = acKind(k);
  const def = mode === "user" ? ["", acT("از گروه‌ها") + (hint ? ` (${hint})` : "")] : kind === "sub" ? ["", acT("مثل بخش")] : kind === "pure" ? ["", acT("بدون محدودیت")] : null;
  const v = cur == null ? "" : cur;
  return `<select data-ack="${k}" class="ac-sel">${def ? `<option value="" ${v === "" ? "selected" : ""}>${esc(def[1])}</option>` : ""}${AC_LV.filter(([x]) => !(nv && x === "view"))
    .map(([x, t]) => `<option value="${x}" ${v === x || (!def && v === "" && x === "none") ? "selected" : ""}>${t}</option>`).join("")}</select>`;
}
function acTree(vals, mode, hintOf) {
  const D = AC.data, off = (k) => !D.enabled.includes(k);
  const row = (k, cls) => `<div class="ac-row ${cls}"><span>${esc(acTitle(k))}${off(k) ? ` <small class="tag err">${esc(acT("خاموش در تنظیمات"))}</small>` : ""}</span>${acTreeSel(k, vals[k], mode, hintOf && hintOf(k))}</div>`;
  return `<div class="ac-tree">${D.tree.map(([sec, kids]) => `<details class="ac-sec" ${kids.some((k) => vals[k] != null) ? "open" : ""}><summary>${row(sec, "top")}</summary>
    ${kids.map((k) => row(k, k.includes(".") ? "sub2" : "sub")).join("")}</details>`).join("")}</div>`;
}
function acTreeBind(m) { $$(".ac-sec summary select", m).forEach((x) => (x.onclick = (e) => e.preventDefault())); }
function acTreeRead(m) {
  const out = {};
  $$("[data-ack]", m).forEach((s) => { if (s.value !== "" && !(acKind(s.dataset.ack) === "base" && s.value === "none" && !s.querySelector("option[value='']"))) out[s.dataset.ack] = s.value; });
  return out;
}
function acDevSummary(d) {
  if (!d) return `<span class="muted">از گروه‌ها</span>`;
  if (d.all) return `<span class="tag ok">همه‌ی مشترک‌ها</span>`;
  const n = (d.grps || []).length, m = (d.ids || []).length;
  return n || m ? `${n ? `<span>${num(n)}</span> <span>گروه دستگاه</span>` : ""}${n && m ? "، " : ""}${m ? `<span>${num(m)}</span> <span>دستگاه</span>` : ""}` : `<span class="muted">هیچ</span>`;
}

async function renderAccess(box) {
  if (!box) return;
  const r = await api("access_get");
  if (!r.ok) { box.innerHTML = `<h3>دسترسی‌ها</h3><p class="hint">${esc(r.error)}</p>`; return; }
  AC.data = r;
  const off = (k) => !r.enabled.includes(k);
  const keys = r.keys;
  box.innerHTML = `<h3>گروه‌های دسترسی</h3>
    <p class="hint">هر کاربر عضو یک یا چند گروه است و بیشترین سطح گروه‌هایش را می‌گیرد. سطح‌ها: پنهان (دیده نمی‌شود)، دیدن (فقط نتیجه و اطلاعات)، اجرا (اجرا و تغییر).</p>
    <p class="hint">استثنای هر کاربر جای گروه‌ها را می‌گیرد. «فقط‌خواندنی» حداکثر «دیدن» می‌گیرد. «ادمین اصلی» همه‌چیز را دارد و فقط او این بخش را تغییر می‌دهد. ابزاری که در «تنظیمات ← عمومی» خاموش است برای همه پنهان است.</p>
    <div class="table-wrap inner"><table class="grid"><thead><tr><th>گروه</th>${keys.map((k) => `<th class="${off(k) ? "muted" : ""}" title="${off(k) ? esc(acT("خاموش در تنظیمات")) : ""}">${esc(acTitle(k))}</th>`).join("")}<th>دستگاه‌ها</th><th>اعضا</th><th class="nosort"></th></tr></thead><tbody>
      ${r.groups.length ? r.groups.map((g) => `<tr><td><b>${esc(g.name)}</b>${g.notes ? `<br><small class="muted">${esc(g.notes)}</small>` : ""}</td>
        ${keys.map((k) => `<td>${acBadge((g.tools || {})[k] || "none")}</td>`).join("")}<td>${acDevSummary(g.devices)}</td>
        <td>${num(r.users.filter((u) => (u.groups || []).includes(String(g.id))).length)}</td>
        <td class="nowrap"><button class="btn sm" data-ge="${esc(g.id)}">ویرایش</button> <button class="btn sm danger-ghost" data-gd="${esc(g.id)}">حذف</button></td></tr>`).join("")
        : `<tr><td colspan="${keys.length + 4}"><div class="empty">هنوز گروهی نساخته‌اید.</div></td></tr>`}</tbody></table></div>
    <div class="form-foot"><button class="btn primary" id="acAddG">+ گروه تازه</button></div>
    <h3 style="margin-top:18px">دسترسی مؤثر هر کاربر</h3>
    <div class="table-wrap inner"><table class="grid"><thead><tr><th>کاربر</th><th>نقش</th><th>گروه‌ها</th>${keys.map((k) => `<th class="${off(k) ? "muted" : ""}">${esc(acTitle(k))}</th>`).join("")}<th>دستگاه‌ها</th><th class="nosort"></th></tr></thead><tbody>
      ${r.users.map((u) => `<tr class="${u.disabled ? "muted" : ""}"><td class="ltr"><b>${esc(u.username)}</b>${u.is_super ? ` <span class="tag warn" title="همه‌چیز؛ تغییر دسترسی‌ها">ادمین اصلی</span>` : ""}${u.access_v < 3 && !u.is_super ? ` <span class="tag mute" title="هنوز دسترسی نسخه‌های قبل (نقش + تیک ابزارها)؛ با «ویرایش» به گروه‌ها منتقل می‌شود">قدیمی</span>` : ""}</td>
        <td>${esc(ROLE_FA[u.role] || u.role)}</td><td>${(u.groups || []).map((id) => esc((r.groups.find((g) => String(g.id) === id) || {}).name || "?")).join("، ") || "—"}</td>
        ${keys.map((k) => `<td title="${(u.access || {})[k] ? esc(acT("استثنای کاربر")) : ""}">${acBadge(u.effective[k])}${(u.access || {})[k] ? "<sup>*</sup>" : ""}</td>`).join("")}
        <td>${u.is_super || u.dev_scope.all ? `<span class="tag ok">همه</span>` : acDevSummary(u.dev_scope)}</td>
        <td>${u.is_super && u.username === r.me ? "" : `<button class="btn sm" data-ua="${esc(u.username)}">ویرایش</button>`}</td></tr>`).join("")}</tbody></table></div>
    <p class="hint">* = استثنای همان کاربر. دستگاه‌های شخصی هر کاربر همیشه فقط برای خودش است.</p>`;
  const reload = () => renderAccess(box);
  $("#acAddG", box).onclick = () => acGroupModal(null, reload);
  $$("[data-ge]", box).forEach((b) => (b.onclick = () => acGroupModal(r.groups.find((g) => String(g.id) === b.dataset.ge), reload)));
  $$("[data-gd]", box).forEach((b) => (b.onclick = async () => {
    const g = r.groups.find((x) => String(x.id) === b.dataset.gd);
    if (!(await confirm2({ title: "حذف گروه", danger: true, confirm: "حذف", body: `<p>گروه «${esc(g.name)}» حذف شود؟ اعضا دسترسی‌های این گروه را از دست می‌دهند.</p>` }))) return;
    const x = await api("access_group_delete", g.id); if (!x.ok) return toast(x.error, "error"); reload();
  }));
  $$("[data-ua]", box).forEach((b) => (b.onclick = () => acUserModal(r.users.find((u) => u.username === b.dataset.ua), reload)));
}

/* بخش انتخاب دستگاه‌ها (گروه دستگاه و دستگاه تکی، با جستجو) */
function acDevPicker(d, withInherit) {
  const D = AC.data, mode = withInherit && !d ? "inherit" : d && d.all ? "all" : "pick";
  const dd = d || { all: false, grps: [], ids: [] };
  return `<div class="seg" data-acdm style="margin-bottom:8px">${withInherit ? `<button type="button" data-v="inherit" class="${mode === "inherit" ? "on" : ""}">از گروه‌ها</button>` : ""}
      <button type="button" data-v="all" class="${mode === "all" ? "on" : ""}">همه‌ی دستگاه‌های مشترک</button><button type="button" data-v="pick" class="${mode === "pick" ? "on" : ""}">فقط انتخاب‌شده‌ها</button></div>
    <div data-acdp ${mode === "pick" ? "" : "hidden"}>
      ${D.dev_groups.length ? `<div class="um-grp"><b>گروه دستگاه</b><div class="chks">${D.dev_groups.map((g) => `<label class="chk"><input type="checkbox" data-acg value="${esc(g)}" ${dd.grps.includes(g) ? "checked" : ""}>${esc(g)}</label>`).join("")}</div></div>` : ""}
      <div class="um-grp"><b>دستگاه</b> <input type="search" class="search" data-acq placeholder="${esc(acT("جستجو در نام یا آدرس…"))}" style="max-width:240px">
        <div class="chks" style="max-height:200px;overflow:auto">${D.devices.map((x) => `<label class="chk" data-acrow="${esc((x.name + " " + x.host).toLowerCase())}"><input type="checkbox" data-aci value="${x.id}" ${dd.ids.includes(x.id) ? "checked" : ""}><span data-no-i18n>${esc(x.name)}</span> <span class="muted ltr">${esc(x.host)}</span></label>`).join("") || `<span class="muted">دستگاه مشترکی نیست.</span>`}</div></div>
      <small class="hint">کاربر دستگاه‌هایی را می‌بیند که در یکی از گروه‌های دستگاه انتخاب‌شده باشند یا خودشان تیک خورده باشند.</small></div>`;
}
function acDevBind(m) {
  $$("[data-acdm] button", m).forEach((b) => (b.onclick = () => { $$("[data-acdm] button", m).forEach((x) => x.classList.toggle("on", x === b)); $("[data-acdp]", m).hidden = b.dataset.v !== "pick"; }));
  const q = $("[data-acq]", m); if (q) q.oninput = () => { const v = q.value.toLowerCase().trim(); $$("[data-acrow]", m).forEach((r) => (r.hidden = v && !r.dataset.acrow.includes(v))); };
}
function acDevRead(m) {
  const v = ($("[data-acdm] button.on", m) || {}).dataset.v;
  if (v === "inherit") return null;
  if (v === "all") return { all: true, grps: [], ids: [] };
  return { all: false, grps: $$("[data-acg]", m).filter((c) => c.checked).map((c) => c.value), ids: $$("[data-aci]", m).filter((c) => c.checked).map((c) => Number(c.value)) };
}

function acGroupModal(g, done) {
  const D = AC.data, isNew = !g; g = g || { name: "", notes: "", tools: {}, devices: { all: false, grps: [], ids: [] } };
  const members = new Set(D.users.filter((u) => (u.groups || []).includes(String(g.id))).map((u) => u.username));
  openModal({ title: isNew ? "گروه تازه" : `ویرایش گروه ${g.name}`, wide: true, body: `<div class="form-grid">
      <label class="field"><span>نام گروه</span><input id="agName" value="${esc(g.name)}" maxlength="60" placeholder="${esc(acT("مثلاً تیم شبکه"))}"></label>
      <label class="field"><span>توضیح</span><input id="agNotes" value="${esc(g.notes || "")}" maxlength="300"></label></div>
    <h3 style="margin:12px 0 6px">ابزارها و بخش‌ها</h3><p class="hint">سطح هر زیرمجموعه حداکثر به اندازه‌ی بخش بالای آن است. دسترسی هیچ سرویسی را متوقف نمی‌کند؛ فقط اعضای همین گروه را محدود می‌کند.</p>
    ${acTree(g.tools || {}, "group")}
    <h3 style="margin:12px 0 6px">دستگاه‌های مشترک</h3>${acDevPicker(g.devices, false)}
    <h3 style="margin:12px 0 6px">اعضا</h3><div class="chks">${D.users.map((u) => `<label class="chk"><input type="checkbox" data-agm value="${esc(u.username)}" ${members.has(u.username) ? "checked" : ""}><span class="ltr">${esc(u.username)}</span> <span class="muted">(${esc(ROLE_FA[u.role] || u.role)})</span></label>`).join("")}</div>
    <small class="hint">کاربری که هنوز دسترسی نسخه‌های قبل را دارد با عضویت به مدل گروه‌ها منتقل می‌شود و همان دسترسی قبلی‌اش به‌صورت «استثنای کاربر» می‌ماند تا چیزی ناگهان عوض نشود؛ برای این‌که فقط گروه‌ها اعمال شوند، در «ویرایش» همان کاربر استثناها را پاک کنید.</small>`,
    foot: `<button class="btn ghost" data-r="0">انصراف</button><button class="btn primary" data-r="1">ذخیره</button>`,
    onOpen: (m, close) => {
      acDevBind(m); acTreeBind(m);
      $("[data-r='0']", m).onclick = () => close();
      $("[data-r='1']", m).onclick = async () => {
        const tools = acTreeRead(m);
        const x = await api("access_group_save", { id: g.id || null, name: $("#agName", m).value.trim(), notes: $("#agNotes", m).value, tools,
          devices: acDevRead(m), members: $$("[data-agm]", m).filter((c) => c.checked).map((c) => c.value) });
        if (!x.ok) return toast(x.error, "error");
        toast("ذخیره شد", "ok"); close(); done();
      };
    } });
}

function acUserModal(u, done) {
  const D = AC.data;
  const legacy = u.access_v < 3;
  const ov = legacy ? Object.fromEntries(D.keys.map((k) => [k, u.effective[k]])) : { ...(u.access || {}) };          // کاربر قدیمی: همان دسترسی فعلی به‌صورت استثنا
  const devs = legacy ? { all: u.dev_scope.all, grps: [], ids: [] } : u.devices;
  openModal({ title: `دسترسی ${u.username}`, wide: true, body: `${legacy ? `<p class="hint warn-text">این کاربر هنوز دسترسی نسخه‌های قبل را دارد. با ذخیره به مدل گروه‌ها منتقل می‌شود؛ دسترسی فعلی‌اش به‌صورت استثنا پر شده است.</p>` : ""}
    <h3 style="margin:4px 0 6px">گروه‌ها</h3><div class="chks">${D.groups.map((g) => `<label class="chk"><input type="checkbox" data-aug value="${esc(g.id)}" ${(u.groups || []).includes(String(g.id)) ? "checked" : ""}>${esc(g.name)}</label>`).join("") || `<span class="muted">هنوز گروهی نیست.</span>`}</div>
    <h3 style="margin:12px 0 6px">استثنای این کاربر <button type="button" class="btn sm ghost" id="auClr">همه «از گروه‌ها»</button></h3>
      ${acTree(ov, "user", (k) => acT((AC_LV.find(([v]) => v === u.effective[k]) || [])[1] || ""))}
    ${u.role === "readonly" ? `<small class="hint">نقش «فقط‌خواندنی»: «اجرا» برای او «دیدن» حساب می‌شود.</small>` : ""}
    <h3 style="margin:12px 0 6px">دستگاه‌های مشترک</h3>${acDevPicker(devs, true)}
    ${u.role === "admin" && u.source !== "ad" ? `<label class="chk" style="margin-top:12px"><input type="checkbox" id="auSup" ${u.superuser ? "checked" : ""}>ادمین اصلی (همه‌ی ابزارها و دستگاه‌ها؛ تغییر کاربران و دسترسی‌ها)</label>` : ""}`,
    foot: `<button class="btn ghost" data-r="0">انصراف</button><button class="btn primary" data-r="1">ذخیره</button>`,
    onOpen: (m, close) => {
      acDevBind(m); acTreeBind(m);
      $("#auClr", m).onclick = () => $$("[data-ack]", m).forEach((s) => (s.value = ""));
      $("[data-r='0']", m).onclick = () => close();
      $("[data-r='1']", m).onclick = async () => {
        const access = acTreeRead(m);
        const data = { groups: $$("[data-aug]", m).filter((c) => c.checked).map((c) => c.value), access, devices: acDevRead(m) };
        if ($("#auSup", m)) data.superuser = $("#auSup", m).checked;
        const x = await api("access_user_save", u.username, data);
        if (!x.ok) return toast(x.error, "error");
        toast("ذخیره شد", "ok"); close(); done();
      };
    } });
}
