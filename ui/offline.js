/* ================================================================ ابزارهای آفلاین (صفحه‌ی «ابزارها»)
   همه‌چیز در همین صفحه محاسبه می‌شود؛ هیچ داده یا فایلی به سرور یا اینترنت فرستاده نمی‌شود. */
"use strict";
const OFF = { tool: "ip", hash: null, last: {} };
const OFF_TOOLS = [["ip", "تبدیل IP"], ["subnet", "ماشین‌حساب ساب‌نت"], ["hash", "هش فایل"], ["enc", "کدگذاری و رمزگشایی"], ["time", "تبدیل زمان"], ["ioc", "استخراج IOC"], ["fgcli", "جستجوی لاگ FortiGate (CLI)"], ["ports", "فهرست پورت‌ها"]];

/* ---------------------------------------------------------------- IP (BigInt) */
const IP = (() => {
  const B = BigInt, M32 = (1n << 32n) - 1n, M128 = (1n << 128n) - 1n;
  function v4(s) {
    const p = String(s).trim().split(".");
    if (p.length !== 4 || !p.every((x) => /^\d{1,3}$/.test(x) && Number(x) <= 255)) return null;
    return p.reduce((a, x) => (a << 8n) | B(Number(x)), 0n);
  }
  function v6(s) {
    s = String(s).trim().replace(/^\[|\]$/g, "").replace(/%[\w.\-]+$/, "");
    if (!/^[0-9a-fA-F:.]+$/.test(s) || !s.includes(":")) return null;
    let tail = [];
    const m4 = s.match(/^(.*:)(\d+\.\d+\.\d+\.\d+)$/);
    if (m4) {           // IPv4 در انتهای IPv6 (مثل ::ffff:1.2.3.4)
      const x = v4(m4[2]); if (x == null) return null;
      tail = [Number(x >> 16n), Number(x & 0xffffn)];
      s = m4[1].endsWith("::") ? m4[1] : m4[1].slice(0, -1);
    }
    const dbl = s.split("::"); if (dbl.length > 2) return null;
    const part = (x) => (x === "" ? [] : x.split(":"));
    const head = part(dbl[0]), rest = dbl.length === 2 ? part(dbl[1]) : [];
    if (![...head, ...rest].every((h) => /^[0-9a-fA-F]{1,4}$/.test(h))) return null;
    const words = [...head.map((h) => parseInt(h, 16))];
    const after = [...rest.map((h) => parseInt(h, 16)), ...tail];
    const total = words.length + after.length;
    if (dbl.length === 2) { if (total > 7) return null; while (words.length + after.length < 8) words.push(0); }
    else if (total !== 8) return null;
    return [...words, ...after].reduce((a, w) => (a << 16n) | B(w), 0n);
  }
  /* هر شکلی: نقطه‌دار، IPv6، عدد دهدهی، 0x هگز، 0b یا باینری نقطه‌دار */
  function any(s) {
    s = String(s).trim().replace(/\s+/g, "");
    if (!s) return null;
    let n = v4(s); if (n != null) return { v: 4, n };
    n = v6(s); if (n != null) return { v: 6, n };
    let num = null;
    if (/^\d+$/.test(s)) num = B(s);
    else if (/^0x[0-9a-f]+$/i.test(s)) num = B(s);
    else if (/^[0-9a-f]{8}$/i.test(s) && /[a-f]/i.test(s)) num = B("0x" + s);
    else if (/^0b[01]+$/i.test(s)) num = B(s);
    else if (/^[01]{8}(\.[01]{8}){3}$/.test(s) || /^[01]{32}$/.test(s)) num = B("0b" + s.replace(/\./g, ""));
    if (num == null) return null;
    if (num <= M32) return { v: 4, n: num };
    if (num <= M128) return { v: 6, n: num };
    return null;
  }
  const s4 = (n) => [24n, 16n, 8n, 0n].map((k) => String((n >> k) & 255n)).join(".");
  function words(n) { return Array.from({ length: 8 }, (_, i) => Number((n >> B(112 - i * 16)) & 0xffffn)); }
  function s6(n) {
    const w = words(n);
    let best = -1, bl = 0;
    for (let i = 0; i < 8;) { if (w[i] !== 0) { i++; continue; } let j = i; while (j < 8 && w[j] === 0) j++; if (j - i > bl && j - i >= 2) { best = i; bl = j - i; } i = j; }
    const h = w.map((x) => x.toString(16));
    if (best < 0) return h.join(":");
    return h.slice(0, best).join(":") + "::" + h.slice(best + bl).join(":");
  }
  const full6 = (n) => words(n).map((x) => x.toString(16).padStart(4, "0")).join(":");
  const str = (v, n) => (v === 4 ? s4(n) : s6(n));
  const bits = (v) => (v === 4 ? 32 : 128);
  const mask = (v, p) => (p === 0 ? 0n : (((1n << B(p)) - 1n) << B(bits(v) - p)));
  const inNet = (n, net, p, v) => (n & mask(v, p)) === net;
  const TYPES4 = [["0.0.0.0", 8, "این شبکه (نامعتبر برای مقصد)"], ["10.0.0.0", 8, "خصوصی (RFC 1918)"], ["100.64.0.0", 10, "CGNAT مشترک (RFC 6598)"],
    ["127.0.0.0", 8, "Loopback"], ["169.254.0.0", 16, "Link-local"], ["172.16.0.0", 12, "خصوصی (RFC 1918)"], ["192.0.0.0", 24, "رزرو IETF"],
    ["192.0.2.0", 24, "مستندات (TEST-NET-1)"], ["192.168.0.0", 16, "خصوصی (RFC 1918)"], ["198.18.0.0", 15, "تست کارایی (RFC 2544)"],
    ["198.51.100.0", 24, "مستندات (TEST-NET-2)"], ["203.0.113.0", 24, "مستندات (TEST-NET-3)"], ["255.255.255.255", 32, "Broadcast"],
    ["224.0.0.0", 4, "Multicast"], ["240.0.0.0", 4, "رزرو (Class E)"]];
  const TYPES6 = [["::", 128, "نامشخص (Unspecified)"], ["::1", 128, "Loopback"], ["::ffff:0:0", 96, "IPv4-mapped"], ["64:ff9b::", 96, "NAT64"],
    ["2001:db8::", 32, "مستندات"], ["2001::", 32, "Teredo"], ["2002::", 16, "6to4"], ["fc00::", 7, "خصوصی (ULA)"], ["fe80::", 10, "Link-local"],
    ["ff00::", 8, "Multicast"], ["2000::", 3, "عمومی (Global unicast)"]];
  function type(v, n) {
    for (const [a, p, t] of v === 4 ? TYPES4 : TYPES6) if (inNet(n, v === 4 ? v4(a) : v6(a), p, v)) return t;
    return v === 4 ? "عمومی" : "رزرو";
  }
  const isPublic = (v, n) => /^عمومی/.test(type(v, n));
  function ptr(v, n) {
    if (v === 4) return s4(n).split(".").reverse().join(".") + ".in-addr.arpa";
    return n.toString(16).padStart(32, "0").split("").reverse().join(".") + ".ip6.arpa";
  }
  const bin = (v, n) => (v === 4 ? [24n, 16n, 8n, 0n].map((k) => ((n >> k) & 255n).toString(2).padStart(8, "0")).join(".")
    : words(n).map((w) => w.toString(2).padStart(16, "0")).join(":"));
  const hex = (v, n) => "0x" + n.toString(16).toUpperCase().padStart(v === 4 ? 8 : 32, "0");
  /* IPv4 داخل IPv6: mapped (::ffff:a.b.c.d)، 6to4 (2002:WWXX:YYZZ::)، NAT64 (64:ff9b::a.b.c.d) */
  function embedded4(n) {
    if (inNet(n, v6("::ffff:0:0"), 96, 6) || inNet(n, v6("64:ff9b::"), 96, 6)) return s4(n & M32);
    if (inNet(n, v6("2002::"), 16, 6)) return s4((n >> 80n) & M32);
    return "";
  }
  return { v4, v6, any, s4, s6, full6, str, bits, mask, inNet, type, isPublic, ptr, bin, hex, embedded4, M32 };
})();

/* شبکه: «IP/prefix»، «IP mask»، «IP/mask» */
function offParseNet(s) {
  s = String(s || "").trim();
  if (!s) return { err: "آدرس شبکه را وارد کنید." };
  let ip = s, pre = null, note = "";
  const m = s.match(/^(\S+?)\s*(?:\/\s*|\s+)(\S+)$/);
  if (m) { ip = m[1]; pre = m[2]; }
  const a = IP.v4(ip) != null ? { v: 4, n: IP.v4(ip) } : IP.v6(ip) != null ? { v: 6, n: IP.v6(ip) } : null;
  if (!a) return { err: "آدرس IP معتبر نیست." };
  const bits = IP.bits(a.v);
  let p;
  if (pre == null) { p = a.v === 4 ? 24 : 64; note = `پیشوند وارد نشده بود؛ /${p} در نظر گرفته شد.`; }
  else if (/^\d{1,3}$/.test(pre)) { p = Number(pre); if (p > bits) return { err: `پیشوند باید بین 0 و ${bits} باشد.` }; }
  else if (a.v === 4 && IP.v4(pre) != null) {
    const mk = IP.v4(pre);
    const s2 = mk.toString(2).padStart(32, "0");
    const ones = (x) => x.split("").filter((c) => c === "1").length;
    if (/01/.test(s2)) {           // شاید wildcard باشد (مثل ACL سیسکو: 0.0.0.255)
      const s3 = ((~mk) & IP.M32).toString(2).padStart(32, "0");
      if (/01/.test(s3)) return { err: "ماسک پیوسته نیست." };
      p = ones(s3); note = "ورودی wildcard بود و به ماسک تبدیل شد.";
    } else p = ones(s2);
  } else return { err: "پیشوند یا ماسک معتبر نیست." };
  const mk = IP.mask(a.v, p), net = a.n & mk, last = net | (mk ^ ((1n << BigInt(bits)) - 1n));
  return { v: a.v, ip: a.n, p, net, last, mask: mk, bits, note };
}
/* بازه ← کمترین CIDRها */
function offRangeToCidrs(v, lo, hi) {
  const out = [], bits = BigInt(IP.bits(v));
  while (lo <= hi) {
    let size = 0n;
    while (size < bits) {
      const blk = 1n << (size + 1n);
      if (lo % blk !== 0n || lo + blk - 1n > hi) break;
      size++;
    }
    out.push([lo, Number(bits - size)]);
    lo += 1n << size;
    if (out.length > 4096) break;
  }
  return out;
}
const offCount = (n) => n < 10n ** 15n ? Number(n).toLocaleString("en-US") : n.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
function offPow(n) { return n.toString(2).length - 1; }

/* ---------------------------------------------------------------- رابط */
function offRender() {
  const box = $("#offBody"); if (!box) return;
  box.innerHTML = `<div class="seg off-seg" id="offSeg">${OFF_TOOLS.map(([k, t]) => `<button data-v="${k}" class="${OFF.tool === k ? "on" : ""}">${t}</button>`).join("")}</div>
    <p class="hint">همه‌ی محاسبه‌ها همین‌جا انجام می‌شوند؛ هیچ داده یا فایلی به سرور یا اینترنت فرستاده نمی‌شود.</p>
    <div id="offTool"></div>`;
  $$("#offSeg button").forEach((b) => (b.onclick = () => { if (OFF.hash && OFF.hash.running) OFF.hash.cancel = true; OFF.tool = b.dataset.v; offRender(); }));
  ({ ip: offIp, subnet: offSubnet, hash: offHash, enc: offEnc, time: offTime, ioc: offIoc, fgcli: offFgCli, ports: offPorts })[OFF.tool]();
}
const offKv = (rows) => `<table class="grid off-kv"><tbody>${rows.filter(Boolean).map(([k, v, raw]) => `<tr><th${/[0-9]/.test(k) && !/[\u0600-\u06ff]/.test(k) ? ` class="en-num"` : ""}>${k}</th><td class="ltr tech"><span class="off-v">${raw ? v : esc(v)}</span>${raw || v === "" ? "" : `<button class="iconbtn off-cp" data-cp="${esc(v)}" title="کپی">⧉</button>`}</td></tr>`).join("")}</tbody></table>`;
function offBindCopy(root) {
  $$("[data-cp]", root).forEach((b) => (b.onclick = () => offCopy(b.dataset.cp)));
}
async function offCopy(t) {
  try { await navigator.clipboard.writeText(t); toast("کپی شد", "ok"); }
  catch (e) {
    const ta = document.createElement("textarea"); ta.value = t; document.body.appendChild(ta); ta.select();
    try { document.execCommand("copy"); toast("کپی شد", "ok"); } catch (e2) { toast("کپی نشد", "error"); }
    ta.remove();
  }
}
async function offSaveCsv(name, head, rows) {
  const q = (v) => `"${String(v ?? "").replace(/"/g, '""')}"`;
  const text = [head.map((x) => q(I18N.t(x))).join(","), ...rows.map((r) => r.map(q).join(","))].join("\r\n");
  const r = await api("save_export", name, text, false);   // در Python از csvsafe می‌گذرد
  if (!r.ok) return toast(r.error, "error"); if (!r.cancelled) toast("ذخیره شد: " + r.path, "ok");
}
function offRemember(id, key) { const el = $(id); if (!el) return; el.value = OFF.last[key] ?? el.value; el.addEventListener("input", () => (OFF.last[key] = el.value)); }

/* ---------- ۱. تبدیل IP */
function offIp() {
  $("#offTool").innerHTML = `<div class="panel"><div class="form-grid">
      <label class="field wide"><span>آدرس (IPv4 یا IPv6، یا عدد دهدهی، <span class="ltr">0x</span> هگز، باینری)</span><input id="oiIn" class="ltr" placeholder="192.168.1.10 · 2001:db8::1 · 3232235786 · 0xC0A8010A" autofocus></label></div>
      <div id="oiOut" style="margin-top:12px"></div></div>
    <div class="panel"><div class="panel-head"><h3>تبدیل گروهی</h3><div class="row" style="gap:6px"><button class="btn sm" id="oiBulkCp">کپی CSV</button><button class="btn sm no-ro" id="oiBulkSave">ذخیره‌ی CSV</button></div></div>
      <label class="field"><span>هر خط یک آدرس</span><textarea id="oiBulk" class="ltr code-edit" style="min-height:110px" placeholder="8.8.8.8&#10;2606:4700:4700::1111&#10;167772161"></textarea></label>
      <div id="oiBulkOut" class="table-wrap inner" style="margin-top:10px"></div></div>`;
  offRemember("#oiIn", "ip"); offRemember("#oiBulk", "ipbulk");
  const one = () => {
    const v = $("#oiIn").value.trim(), out = $("#oiOut");
    if (!v) { out.innerHTML = ""; return; }
    const a = IP.any(v);
    if (!a) { out.innerHTML = `<p class="hint warn">آدرس قابل تشخیص نیست.</p>`; return; }
    const { n } = a;
    const f = Number(n >> 24n), cls = f < 128 ? "A" : f < 192 ? "B" : f < 224 ? "C" : f < 240 ? "D" : "E";
    const rows = a.v === 4 ? [["نسخه", "IPv4"], ["نقطه‌دار", IP.s4(n)], ["نوع", I18N.t(IP.type(4, n))], ["کلاس", cls],
      ["دهدهی", n.toString()], ["هگز", IP.hex(4, n)], ["باینری", IP.bin(4, n)], ["IPv6 (mapped)", "::ffff:" + IP.s4(n)],
      ["IPv6 (mapped، هگز)", IP.s6((0xffffn << 32n) | n)], ["6to4", IP.s6((0x2002n << 112n) | (n << 80n)) + "/48"], ["PTR", IP.ptr(4, n)]]
      : [["نسخه", "IPv6"], ["کوتاه", IP.s6(n)], ["کامل", IP.full6(n)], ["نوع", I18N.t(IP.type(6, n))], IP.embedded4(n) ? ["IPv4 داخل آن", IP.embedded4(n)] : null,
        ["دهدهی", n.toString()], ["هگز", IP.hex(6, n)], ["باینری", IP.bin(6, n)], ["PTR", IP.ptr(6, n)]];
    out.innerHTML = offKv(rows); offBindCopy(out);
  };
  let bulkRows = [];
  const bulk = () => {
    const lines = $("#oiBulk").value.split(/\r?\n/).map((x) => x.trim()).filter(Boolean).slice(0, 5000);
    bulkRows = lines.map((l) => { const a = IP.any(l); return a ? [l, "IPv" + a.v, IP.str(a.v, a.n), a.n.toString(), IP.hex(a.v, a.n), I18N.t(IP.type(a.v, a.n)), IP.ptr(a.v, a.n)] : [l, "", "", "", "", I18N.t("نامعتبر"), ""]; });
    $("#oiBulkOut").innerHTML = bulkRows.length ? `<table class="grid"><thead><tr>${["ورودی", "نسخه", "آدرس", "دهدهی", "هگز", "نوع"].map((t) => `<th class="nosort">${t}</th>`).join("")}</tr></thead><tbody>
      ${bulkRows.slice(0, 500).map((r) => `<tr>${r.slice(0, 6).map((c, i) => `<td class="${i === 5 ? "" : "ltr tech"}">${esc(c)}</td>`).join("")}</tr>`).join("")}</tbody></table>${bulkRows.length > 500 ? `<p class="hint">${num(bulkRows.length)} ردیف؛ ۵۰۰ ردیف اول نمایش داده شد (خروجی همه را دارد).</p>` : ""}` : "";
  };
  const HEAD = ["ورودی", "نسخه", "آدرس", "دهدهی", "هگز", "نوع", "PTR"];
  $("#oiIn").oninput = one; $("#oiBulk").oninput = bulk; one(); bulk();
  $("#oiBulkCp").onclick = () => offCopy([HEAD.map((x) => I18N.t(x)), ...bulkRows].map((r) => r.join(",")).join("\n"));
  $("#oiBulkSave").onclick = () => bulkRows.length ? offSaveCsv("autokrp_ip_convert.csv", HEAD, bulkRows) : toast("ورودی خالی است", "warn");
}

/* ---------- ۲. ساب‌نت */
function offSubnet() {
  $("#offTool").innerHTML = `<div class="panel"><div class="form-grid">
      <label class="field wide"><span>شبکه: <span class="ltr">IP/prefix</span> یا IP و ماسک</span><input id="osIn" class="ltr" placeholder="192.168.10.77/26 · 10.0.0.1 255.255.0.0 · 2001:db8:abcd::/48" autofocus></label></div>
      <div id="osOut" style="margin-top:12px"></div></div>
    <div class="off-grid">
      <div class="panel"><h3>تقسیم به ساب‌نت‌های کوچک‌تر</h3><div class="row" style="gap:8px;margin:8px 0"><span>پیشوند تازه</span><select id="osSplit" class="ltr" style="width:auto"></select><button class="btn sm" id="osSplitCp">کپی فهرست</button></div><div id="osSplitOut" class="table-wrap inner off-scroll"></div></div>
      <div class="panel"><h3>بازه ← CIDR</h3><input id="osRange" class="ltr" placeholder="10.0.0.5 - 10.0.0.20" style="margin-top:8px"><div id="osRangeOut" style="margin-top:8px"></div></div></div>`;
  offRemember("#osIn", "net"); offRemember("#osRange", "range");
  let N = null;
  const calc = () => {
    const r = offParseNet($("#osIn").value), out = $("#osOut");
    N = r.err ? null : r;
    if (!$("#osIn").value.trim()) { out.innerHTML = ""; splitOpts(); return; }
    if (r.err) { out.innerHTML = `<p class="hint warn">${esc(r.err)}</p>`; splitOpts(); return; }
    const total = 1n << BigInt(r.bits - r.p), S = (n) => IP.str(r.v, n);
    let rows;
    if (r.v === 4) {
      const usable = r.p >= 31 ? total : total - 2n;
      const first = r.p >= 31 ? r.net : r.net + 1n, lastH = r.p >= 31 ? r.last : r.last - 1n;
      const mb = IP.bin(4, r.mask), ib = IP.bin(4, r.ip);
      let k = 0; const hl = ib.split("").map((c) => { if (c === ".") return c; const on = k++ < r.p; return on ? `<b class="off-netbit">${c}</b>` : c; }).join("");
      rows = [["آدرس", S(r.ip)], ["شبکه", `${S(r.net)}/${r.p}`], ["ماسک", S(r.mask)], ["Wildcard (ACL)", S(r.mask ^ IP.M32)],
        ["Broadcast", r.p >= 31 ? "—" : S(r.last)], ["اولین هاست", S(first)], ["آخرین هاست", S(lastH)], ["بازه", `${S(r.net)} - ${S(r.last)}`],
        ["تعداد آدرس", offCount(total)], ["هاست قابل استفاده", offCount(usable) + (r.p === 31 ? " (RFC 3021)" : "")],
        ["نوع", I18N.t(IP.type(4, r.net))], ["ماسک باینری", mb], ["آدرس باینری (بخش شبکه پررنگ)", hl, true], ["ماسک هگز", IP.hex(4, r.mask)]];
    } else {
      rows = [["آدرس", IP.s6(r.ip)], ["شبکه", `${IP.s6(r.net)}/${r.p}`], ["اولین آدرس", IP.s6(r.net)], ["آخرین آدرس", IP.s6(r.last)],
        ["شبکه (کامل)", IP.full6(r.net)], ["تعداد آدرس", `${offCount(total)}  (2^${r.bits - r.p})`],
        r.p <= 64 ? ["تعداد /64", `${offCount(1n << BigInt(64 - r.p))}`] : null, ["نوع", I18N.t(IP.type(6, r.net))]];
    }
    out.innerHTML = (r.note ? `<p class="hint">${esc(r.note)}</p>` : "") + offKv(rows); offBindCopy(out);
    splitOpts();
  };
  const splitOpts = () => {
    const sel = $("#osSplit"), keep = Number(sel.value);
    if (!N || N.p >= N.bits) { sel.innerHTML = ""; $("#osSplitOut").innerHTML = `<div class="empty">ابتدا یک شبکه وارد کنید.</div>`; return; }
    const opts = []; for (let p = N.p + 1; p <= Math.min(N.bits, N.p + 24); p++) opts.push(p);
    sel.innerHTML = opts.map((p) => `<option value="${p}" ${p === keep ? "selected" : ""}>/${p} (${offCount(1n << BigInt(p - N.p))} ${I18N.t("ساب‌نت")})</option>`).join("");
    split();
  };
  let splitList = [];
  const split = () => {
    if (!N) return;
    const p = Number($("#osSplit").value), cnt = 1n << BigInt(p - N.p), step = 1n << BigInt(N.bits - p), lim = cnt > 1024n ? 1024n : cnt;
    splitList = [];
    for (let i = 0n; i < lim; i++) { const a = N.net + i * step; splitList.push([`${IP.str(N.v, a)}/${p}`, IP.str(N.v, a), IP.str(N.v, a + step - 1n)]); }
    $("#osSplitOut").innerHTML = `<table class="grid"><thead><tr><th class="nosort">#</th><th class="nosort">${I18N.t("ساب‌نت")}</th><th class="nosort">${I18N.t("از")}</th><th class="nosort">${I18N.t("تا")}</th></tr></thead><tbody>
      ${splitList.map((r, i) => `<tr><td class="num">${i + 1}</td>${r.map((c) => `<td class="ltr tech">${esc(c)}</td>`).join("")}</tr>`).join("")}</tbody></table>
      ${cnt > lim ? `<p class="hint">${offCount(cnt)} ساب‌نت؛ ${num(Number(lim))} مورد اول نمایش داده شد.</p>` : ""}`;
  };
  const range = () => {
    const v = $("#osRange").value.trim(), out = $("#osRangeOut");
    if (!v) { out.innerHTML = ""; return; }
    const m = v.split(/\s*[-–]\s*|\s+/).filter(Boolean);
    const a = m[0] && IP.any(m[0]), b = m[1] && IP.any(m[1]);
    if (!a || !b || a.v !== b.v || a.n > b.n) { out.innerHTML = `<span class="tag warn">بازه‌ی معتبر: «شروع - پایان» از یک نسخه و شروع ≤ پایان</span>`; return; }
    const c = offRangeToCidrs(a.v, a.n, b.n).map(([n, p]) => `${IP.str(a.v, n)}/${p}`);
    out.innerHTML = `<pre class="ltr paste-prev" data-no-i18n>${esc(c.join("\n"))}</pre><button class="btn sm" data-cp="${esc(c.join("\n"))}">کپی (${num(c.length)} CIDR)</button>`; offBindCopy(out);
  };
  $("#osIn").oninput = calc; $("#osSplit").onchange = split; $("#osRange").oninput = range;
  $("#osSplitCp").onclick = () => splitList.length && offCopy(splitList.map((r) => r[0]).join("\n"));
  calc(); range();
}

/* ---------- ۳. هش فایل */
function offHash() {
  const H = OFF.hash;
  const algos = OFF.last.algos || ["MD5", "SHA-1", "SHA-256"];
  $("#offTool").innerHTML = `<div class="panel">
      <div class="xf-drop off-drop" id="ohDrop"><svg><use href="#i-folder"/></svg><div>فایل را اینجا بکشید و رها کنید</div><button class="btn sm" id="ohPick">انتخاب فایل…</button><input type="file" id="ohFile" hidden></div>
      <div class="row" style="gap:16px;flex-wrap:wrap;margin-top:10px">${OffHash.ALGOS.map(([n]) => `<label class="chk"><input type="checkbox" class="ohA" value="${n}" ${algos.includes(n) ? "checked" : ""}><span class="en-num">${n}</span></label>`).join("")}</div>
      <label class="field" style="margin-top:10px"><span>مقایسه با هش مورد انتظار (اختیاری؛ الگوریتم از طولش تشخیص داده می‌شود)</span><input id="ohExp" class="ltr" placeholder="مثلاً SHA-256 منتشرشده‌ی سازنده"></label>
      <div id="ohOut" style="margin-top:12px"></div></div>
    <div class="panel"><h3>هش متن</h3><textarea id="ohText" class="ltr code-edit" style="min-height:80px;margin-top:8px" placeholder="متن (UTF-8)"></textarea><div id="ohTextOut" style="margin-top:8px"></div></div>`;
  offRemember("#ohExp", "exp"); offRemember("#ohText", "htext");
  $("#ohPick").onclick = () => $("#ohFile").click();
  $("#ohFile").onchange = (e) => { if (e.target.files[0]) offHashFile(e.target.files[0]); e.target.value = ""; };
  const dz = $("#ohDrop");
  dz.addEventListener("dragover", (e) => { if ([...e.dataTransfer.types].includes("Files")) { e.preventDefault(); dz.classList.add("over"); } });
  dz.addEventListener("dragleave", () => dz.classList.remove("over"));
  dz.addEventListener("drop", (e) => { dz.classList.remove("over"); e.preventDefault(); const f = e.dataTransfer.files && e.dataTransfer.files[0]; if (f) offHashFile(f); });
  $$(".ohA").forEach((c) => (c.onchange = () => { OFF.last.algos = $$(".ohA:checked").map((x) => x.value); textHash(); }));
  $("#ohExp").oninput = () => offHashShow();
  const textHash = () => {
    const t = $("#ohText").value, out = $("#ohTextOut");
    if (!t) { out.innerHTML = ""; return; }
    const d = new TextEncoder().encode(t), sel = $$(".ohA:checked").map((x) => x.value);
    out.innerHTML = offKv(OffHash.ALGOS.filter(([n]) => sel.includes(n)).map(([n, C]) => [n, new C().update(d).hex()])); offBindCopy(out);
  };
  $("#ohText").oninput = textHash; textHash();
  offHashShow();
}
async function offHashFile(f) {
  if (OFF.hash && OFF.hash.running) OFF.hash.cancel = true;
  const sel = $$(".ohA:checked").map((x) => x.value);
  if (!sel.length) return toast("حداقل یک الگوریتم انتخاب کنید", "warn");
  const job = OFF.hash = { name: f.name, size: f.size, done: 0, running: true, cancel: false, res: null, t0: performance.now(), algos: sel };
  const hs = OffHash.ALGOS.filter(([n]) => sel.includes(n)).map(([n, C]) => [n, new C()]);
  offHashShow();
  const CH = 4 * 1024 * 1024;
  let p = 0;
  try {
    while (p < f.size) {
      if (job.cancel) break;
      const buf = new Uint8Array(await f.slice(p, p + CH).arrayBuffer());
      for (const [, h] of hs) h.update(buf);
      p += buf.length; job.done = p;
      offHashProgress(job);
      await new Promise((r) => setTimeout(r, 0));     // صفحه قفل نشود
    }
    if (!job.cancel) job.res = hs.map(([n, h]) => [n, h.hex()]);
  } catch (e) { job.error = String(e && e.message || e); }
  job.running = false; job.sec = (performance.now() - job.t0) / 1000;
  if (OFF.hash === job) offHashShow();
}
function offHashProgress(j) {
  const pct = j.size ? Math.round((j.done / j.size) * 100) : 100, b = $("#ohProg");
  if (b) { b.style.width = pct + "%"; const t = $("#ohProgT"); if (t) t.textContent = `${pct}% — ${fsize(j.done)} / ${fsize(j.size)}`; }
}
function offHashShow() {
  const out = $("#ohOut"), j = OFF.hash; if (!out) return;
  if (!j) { out.innerHTML = ""; return; }
  const head = `<p><b class="ltr">${esc(j.name)}</b> <span class="muted ltr">${fsize(j.size)} (${num(j.size)} B)</span></p>`;
  if (j.running) {
    out.innerHTML = `${head}<div class="row" style="gap:10px"><div class="xf-prog" style="flex:1"><span id="ohProg" style="width:0%"></span></div><small class="muted ltr" id="ohProgT"></small><button class="btn sm ghost" id="ohStop">لغو</button></div>`;
    $("#ohStop").onclick = () => (j.cancel = true); offHashProgress(j); return;
  }
  if (j.error) { out.innerHTML = head + `<p class="hint warn">${esc(j.error)}</p>`; return; }
  if (!j.res) { out.innerHTML = head + `<p class="hint">لغو شد.</p>`; return; }
  const exp = ($("#ohExp") && $("#ohExp").value || "").trim().toLowerCase().replace(/[^0-9a-f]/g, "");
  const len = { 32: "MD5", 40: "SHA-1", 64: "SHA-256", 128: "SHA-512", 8: "CRC32" }[exp.length];
  let verdict = "";
  if (exp) {
    const hit = j.res.find(([, h]) => h === exp);
    verdict = hit ? `<p><span class="tag ok">✓ با ${esc(hit[0])} یکسان است</span></p>`
      : len && !j.res.some(([n]) => n === len) ? `<p><span class="tag warn">هش وارد‌شده ${esc(len)} است؛ این الگوریتم را تیک بزنید و فایل را دوباره بدهید</span></p>`
      : `<p><span class="tag err">✗ هیچ‌کدام از هش‌ها یکسان نیست</span></p>`;
  }
  out.innerHTML = head + verdict + offKv(j.res.map(([n, h]) => [n + (exp && h === exp ? " ✓" : ""), h])) + `<p class="hint">${j.sec.toFixed(1)} ثانیه</p>`;
  offBindCopy(out);
}

/* ---------- ۴. کدگذاری / رمزگشایی */
const OFF_ENC = [["b64e", "متن ← Base64"], ["b64d", "Base64 ← متن"], ["b64ue", "متن ← Base64URL"], ["urle", "URL encode"], ["urld", "URL decode"],
  ["hexe", "متن ← Hex"], ["hexd", "Hex ← متن"], ["htmle", "HTML entity encode"], ["htmld", "HTML entity decode"], ["defang", "Defang (ایمن برای گزارش)"], ["refang", "Refang"]];
function offB64e(s) { let b = ""; new TextEncoder().encode(s).forEach((x) => (b += String.fromCharCode(x))); return btoa(b); }
function offB64d(s) {
  s = s.replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/"); while (s.length % 4) s += "=";
  const bin = atob(s), u = Uint8Array.from(bin, (c) => c.charCodeAt(0));
  return new TextDecoder("utf-8", { fatal: false }).decode(u);
}
function offDefang(s) { return s.replace(/\bhttp(s?):\/\//gi, "hxxp$1[://]").replace(/\bftp:\/\//gi, "fxp[://]").replace(/@/g, "[@]").replace(/\.(?=[^\s.\[\]]+)/g, "[.]"); }
function offRefang(s) {
  return s.replace(/\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}|\[dot\]|\(dot\)/gi, ".").replace(/\[\s*:\s*\]/g, ":").replace(/\[:\/\/\]/g, "://")
    .replace(/\[\s*@\s*\]|\[at\]|\(at\)/gi, "@").replace(/\bhxxp/gi, "http").replace(/\bfxp/gi, "ftp");
}
function offEnc() {
  const op = OFF.last.encOp || "b64d";
  $("#offTool").innerHTML = `<div class="panel"><div class="row" style="gap:8px;flex-wrap:wrap;margin-bottom:10px"><span>عملیات</span><select id="oeOp" class="en-num" style="width:auto">${OFF_ENC.map(([k, t]) => `<option value="${k}" ${k === op ? "selected" : ""}>${t}</option>`).join("")}</select>
      <button class="btn sm ghost" id="oeSwap" title="خروجی به‌عنوان ورودی">⇅ جابه‌جایی</button></div>
    <div class="off-grid2"><label class="field"><span>ورودی</span><textarea id="oeIn" class="ltr code-edit" style="min-height:220px"></textarea></label>
      <label class="field"><span>خروجی</span><textarea id="oeOut" class="ltr code-edit" style="min-height:220px" readonly></textarea></label></div>
    <div class="row" style="margin-top:8px"><span id="oeErr" class="muted"></span><button class="btn sm" id="oeCp" style="margin-inline-start:auto">کپی خروجی</button></div></div>`;
  offRemember("#oeIn", "encIn");
  const run = () => {
    const o = $("#oeOp").value, s = $("#oeIn").value; OFF.last.encOp = o;
    let r = "", err = "";
    try {
      r = { b64e: () => offB64e(s), b64d: () => offB64d(s), b64ue: () => offB64e(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""),
        urle: () => encodeURIComponent(s), urld: () => decodeURIComponent(s.replace(/\+/g, " ")),
        hexe: () => Array.from(new TextEncoder().encode(s), (b) => b.toString(16).padStart(2, "0")).join(""),
        hexd: () => { const h = s.replace(/0x|\\x|[\s:,-]/gi, ""); if (!/^([0-9a-f]{2})*$/i.test(h)) throw new Error(I18N.t("Hex نامعتبر است")); return new TextDecoder().decode(Uint8Array.from(h.match(/../g) || [], (x) => parseInt(x, 16))); },
        htmle: () => s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])),
        htmld: () => { const d = new DOMParser().parseFromString(`<!doctype html><body><textarea>${s.replace(/</g, "&lt;")}</textarea>`, "text/html"); return d.querySelector("textarea").value; },
        defang: () => offDefang(s), refang: () => offRefang(s) }[o]();
    } catch (e) { err = I18N.t("ورودی برای این عملیات معتبر نیست") + (e && e.message ? `: ${e.message}` : ""); }
    $("#oeOut").value = r; $("#oeErr").textContent = err;
  };
  $("#oeOp").onchange = run; $("#oeIn").oninput = run;
  $("#oeSwap").onclick = () => { $("#oeIn").value = $("#oeOut").value; OFF.last.encIn = $("#oeIn").value; run(); };
  $("#oeCp").onclick = () => offCopy($("#oeOut").value);
  run();
}

/* ---------- ۵. تبدیل زمان */
function offTime() {
  $("#offTool").innerHTML = `<div class="panel"><div class="form-grid">
      <label class="field wide"><span>Epoch (ثانیه یا میلی‌ثانیه) یا تاریخ (<span class="ltr">2026-10-15 16:30</span>، ISO، RFC 2822)</span><input id="otIn" class="ltr" placeholder="1792065684"></label>
      <label class="field"><span>تاریخ بدون منطقه‌ی زمانی</span><select id="otTz"><option value="local">زمان همین کامپیوتر</option><option value="utc">UTC</option></select></label></div>
      <div class="row" style="margin-top:8px"><button class="btn sm" id="otNow">الان</button></div>
      <div id="otOut" style="margin-top:12px"></div></div>`;
  offRemember("#otIn", "time");
  const run = () => {
    const v = $("#otIn").value.trim(), out = $("#otOut");
    if (!v) { out.innerHTML = ""; return; }
    let ms = null, kind = "";
    if (/^-?\d{1,11}(\.\d+)?$/.test(v)) { ms = Number(v) * 1000; kind = "Epoch ثانیه"; }
    else if (/^-?\d{12,14}$/.test(v)) { ms = Number(v); kind = "Epoch میلی‌ثانیه"; }
    else if (/^\d{15,17}$/.test(v)) { ms = Number(v) / 1000; kind = "Epoch میکروثانیه"; }
    else {
      const m = v.match(/^(\d{4})[-/](\d{1,2})[-/](\d{1,2})(?:[ T](\d{1,2}):(\d{2})(?::(\d{2}))?)?$/);
      if (m) { const a = m.slice(1).map((x) => Number(x || 0)); ms = $("#otTz").value === "utc" ? Date.UTC(a[0], a[1] - 1, a[2], a[3], a[4], a[5]) : new Date(a[0], a[1] - 1, a[2], a[3], a[4], a[5]).getTime(); kind = "تاریخ"; }
      else { const t = Date.parse(v); if (!isNaN(t)) { ms = t; kind = "تاریخ"; } }
    }
    if (ms == null || !isFinite(ms)) { out.innerHTML = `<p class="hint warn">قابل تشخیص نیست.</p>`; return; }
    const d = new Date(ms), f = (o) => { try { return new Intl.DateTimeFormat("en-GB", { dateStyle: "medium", timeStyle: "medium", ...o }).format(d); } catch (e) { return ""; } };
    const fa = (tz) => { try { return new Intl.DateTimeFormat("fa-IR-u-ca-persian", { dateStyle: "full", timeStyle: "medium", timeZone: tz }).format(d); } catch (e) { return ""; } };
    const diff = (Date.now() - ms) / 1000, ad = Math.abs(diff);
    const rel = ad < 60 ? `${Math.round(ad)} s` : ad < 3600 ? `${Math.round(ad / 60)} min` : ad < 86400 ? `${(ad / 3600).toFixed(1)} h` : `${(ad / 86400).toFixed(1)} d`;
    out.innerHTML = offKv([["ورودی", I18N.t(kind)], ["Epoch (ثانیه)", String(Math.floor(ms / 1000))], ["Epoch (میلی‌ثانیه)", String(Math.round(ms))],
      ["UTC", f({ timeZone: "UTC" })], ["ISO 8601", d.toISOString()], ["زمان همین کامپیوتر", f({})], ["تهران", f({ timeZone: "Asia/Tehran" })],
      ["شمسی (تهران)", fa("Asia/Tehran")], ["فاصله تا الان", (diff >= 0 ? I18N.t("گذشته: ") : I18N.t("آینده: ")) + rel]]);
    offBindCopy(out);
  };
  $("#otIn").oninput = run; $("#otTz").onchange = run;
  $("#otNow").onclick = () => { $("#otIn").value = String(Math.floor(Date.now() / 1000)); OFF.last.time = $("#otIn").value; run(); };
  run();
}

/* ---------- ۶. استخراج IOC */
function offIocExtract(raw, pubOnly) {
  const t = offRefang(raw);
  const uniq = (a) => [...new Set(a)];
  const urls = uniq((t.match(/\b(?:https?|ftp):\/\/[^\s"'<>()\[\]{}]+/gi) || []).map((u) => u.replace(/[.,;:!?]+$/, "")));
  const emails = uniq((t.match(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}\b/g) || []).map((x) => x.toLowerCase()));
  let ip4 = uniq((t.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || []).filter((x) => IP.v4(x) != null));
  let ip6 = uniq((t.match(/(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?:\d+\.\d+\.\d+\.\d+)?/g) || []).filter((x) => x.length > 2 && /[0-9a-f]/i.test(x) && IP.v6(x) != null).map((x) => IP.s6(IP.v6(x))));
  if (pubOnly) { ip4 = ip4.filter((x) => IP.isPublic(4, IP.v4(x))); ip6 = ip6.filter((x) => IP.isPublic(6, IP.v6(x))); }
  const FILEEXT = /\.(exe|dll|bat|ps1|vbs|js|jar|zip|rar|7z|doc|docx|xls|xlsx|pdf|txt|log|csv|png|jpg|jpeg|gif|py|sh|php|html?|aspx?|json|xml|tmp|dat|bin|iso|msi|lnk|scr)$/i;
  const domains = uniq((t.match(/\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,23}\b/gi) || []).map((x) => x.toLowerCase())
    .filter((x) => !/^\d+(\.\d+)+$/.test(x) && !FILEEXT.test(x)));
  const hashes = (re) => uniq((t.match(re) || []).map((x) => x.toLowerCase()));
  const sha256 = hashes(/\b[a-f0-9]{64}\b/gi), sha1 = hashes(/\b[a-f0-9]{40}\b/gi), md5 = hashes(/\b[a-f0-9]{32}\b/gi);
  const cve = uniq((t.match(/\bCVE-\d{4}-\d{4,7}\b/gi) || []).map((x) => x.toUpperCase()));
  return [["IPv4", ip4], ["IPv6", ip6], ["دامنه", domains], ["URL", urls], ["ایمیل", emails], ["SHA-256", sha256], ["SHA-1", sha1], ["MD5", md5], ["CVE", cve]];
}
function offIoc() {
  $("#offTool").innerHTML = `<div class="panel"><label class="field"><span>متن (لاگ، ایمیل، گزارش؛ شکل defang مثل <span class="ltr">hxxp://evil[.]com</span> هم شناخته می‌شود)</span>
      <textarea id="oxIn" class="ltr code-edit" style="min-height:160px"></textarea></label>
      <div class="row" style="gap:16px;margin-top:8px;flex-wrap:wrap"><label class="chk"><input type="checkbox" id="oxPub" ${OFF.last.pub ? "checked" : ""}>فقط IPهای عمومی</label>
        <label class="chk"><input type="checkbox" id="oxDef" ${OFF.last.def ? "checked" : ""}>خروجی defang</label>
        <span style="margin-inline-start:auto" class="row"><button class="btn sm" id="oxCp">کپی همه</button><button class="btn sm no-ro" id="oxSave">ذخیره‌ی CSV</button></span></div>
      <div id="oxOut" class="off-ioc" style="margin-top:12px"></div></div>`;
  offRemember("#oxIn", "ioc");
  let groups = [];
  const run = () => {
    OFF.last.pub = $("#oxPub").checked; OFF.last.def = $("#oxDef").checked;
    groups = offIocExtract($("#oxIn").value.slice(0, 5 * 1024 * 1024), OFF.last.pub).filter(([, xs]) => xs.length);
    const show = (x) => (OFF.last.def ? offDefang(x) : x);
    $("#oxOut").innerHTML = groups.length ? groups.map(([g, xs]) => `<div class="panel inner"><div class="panel-head"><h3>${g} <span class="tag mute">${num(xs.length)}</span></h3><button class="btn sm ghost" data-cp="${esc(xs.map(show).join("\n"))}">کپی</button></div>
        <pre class="ltr paste-prev" data-no-i18n>${esc(xs.slice(0, 2000).map(show).join("\n"))}</pre></div>`).join("") : ($("#oxIn").value.trim() ? `<div class="empty">موردی پیدا نشد.</div>` : "");
    offBindCopy($("#oxOut"));
  };
  $("#oxIn").oninput = run; $("#oxPub").onchange = run; $("#oxDef").onchange = run;
  const rows = () => groups.flatMap(([g, xs]) => xs.map((x) => [I18N.t(g), OFF.last.def ? offDefang(x) : x]));
  $("#oxCp").onclick = () => offCopy(groups.map(([g, xs]) => `# ${I18N.t(g)}\n` + xs.map((x) => (OFF.last.def ? offDefang(x) : x)).join("\n")).join("\n\n"));
  $("#oxSave").onclick = () => groups.length ? offSaveCsv("autokrp_ioc.csv", ["نوع", "مقدار"], rows()) : toast("موردی نیست", "warn");
  run();
}

/* ---------- ۷. جستجوی لاگ FortiGate با CLI (1.27.2)
   فقط دستور می‌سازد؛ به دستگاه وصل نمی‌شود. مرجع: Fortinet «Technical Tip: Displaying logs via FortiGate's CLI»
   (شماره‌ی device و category به تفکیک نسخه، field تا ۵ مقدار با not و بازه با «-»، free-style، view-lines بین ۵ و ۱۰۰۰). */
const FGL_VERS = ["6.0", "6.2", "6.4", "7.0", "7.2", "7.4", "7.6", "8.0"];
const fglV = (v) => { const [a, b] = String(v).split(".").map(Number); return a * 100 + b; };
const FGL_DEV = (ver) => fglV(ver) >= 602 ? [["0", "Memory"], ["1", "Disk"], ["2", "FortiAnalyzer"], ["3", "FortiAnalyzer Cloud"], ["4", "FortiGate Cloud"]]
  : [["0", "Memory"], ["1", "Disk"], ["2", "FortiAnalyzer"], ["3", "FortiGate Cloud"]];
// [شماره، نام CLI، عنوان، از نسخه، تا پیش از نسخه]
const FGL_CAT = [["0", "traffic", "Traffic"], ["1", "event", "Event"], ["2", "utm-virus", "Antivirus"], ["3", "utm-webfilter", "Web filter"],
  ["4", "utm-ips", "IPS"], ["5", "utm-emailfilter", "Email filter"], ["7", "utm-anomaly", "Anomaly (DoS)"], ["8", "utm-voip", "VoIP"],
  ["9", "utm-dlp", "DLP"], ["10", "utm-app-ctrl", "Application control"], ["12", "utm-waf", "WAF"], ["15", "utm-dns", "DNS filter"],
  ["16", "utm-ssh", "SSH inspection"], ["17", "utm-ssl", "SSL inspection", "6.2"], ["18", "utm-cifs", "CIFS", "6.2", "6.4"],
  ["19", "utm-file-filter", "File filter", "6.2"], ["20", "utm-icap", "ICAP", "6.4"], ["22", "utm-sctp-filter", "SCTP filter", "7.0"],
  ["23", "forti-switch", "FortiSwitch", "7.2"], ["24", "utm-virtual-patch", "Virtual patching", "7.4"], ["25", "utm-casb", "Inline CASB", "7.4"],
  ["26", "debug", "Debug", "7.6"], ["27", "utm-llm", "LLM", "8.0"]];
const FGL_FIELDS = [["srcip", "IP مبدأ", "ip"], ["dstip", "IP مقصد", "ip"], ["srcport", "پورت مبدأ", "port"], ["dstport", "پورت مقصد", "port"],
  ["action", "Action (نتیجه)", "text"], ["policyid", "شماره‌ی Policy", "num"], ["service", "سرویس", "text"], ["subtype", "Subtype", "text"],
  ["srcintf", "اینترفیس مبدأ", "text"], ["dstintf", "اینترفیس مقصد", "text"], ["proto", "شماره‌ی پروتکل (6=TCP، 17=UDP، 1=ICMP)", "num"],
  ["app", "اپلیکیشن", "text"], ["user", "نام کاربری", "text"], ["group", "گروه کاربر", "text"], ["hostname", "Hostname / دامنه", "text"],
  ["srccountry", "کشور مبدأ", "text"], ["dstcountry", "کشور مقصد", "text"], ["logid", "Log ID", "num"], ["level", "سطح (Severity)", "text"],
  ["sessionid", "Session ID", "num"], ["srcmac", "MAC مبدأ", "text"], ["msg", "پیام لاگ", "text"], ["logdesc", "شرح لاگ (Event)", "text"],
  ["attack", "نام حمله (IPS)", "text"], ["virus", "نام ویروس", "text"], ["catdesc", "دسته‌ی وب‌فیلتر", "text"], ["url", "URL", "text"]];
const FGL_HINTS = { action: ["deny", "accept", "close", "timeout", "client-rst", "server-rst", "blocked", "passthrough", "login", "perf-stats"],
  subtype: ["forward", "local", "multicast", "system", "vpn", "user", "router", "ha", "wireless", "endpoint", "sdwan", "security-rating", "connector"],
  level: ["emergency", "alert", "critical", "error", "warning", "notice", "information", "debug"] };
const FGL_PRESETS = [["ip", "همه‌ی ترافیک یک IP", { cat: "0", either: true }], ["deny", "ترافیک رد شده", { cat: "0", rows: [["action", "deny"]] }],
  ["vpn", "رویدادهای VPN", { cat: "1", rows: [["subtype", "vpn"]] }], ["admin", "ورود ادمین‌ها", { cat: "1", rows: [["action", "login"]] }],
  ["cfg", "تغییرات کانفیگ", { cat: "1", rows: [["logdesc", "Object\\ attribute\\ configured"]] }], ["sdwan", "رویدادهای SD-WAN", { cat: "1", rows: [["subtype", "sdwan"]] }],
  ["ips", "حمله‌های IPS", { cat: "4" }], ["web", "وب‌فیلتر", { cat: "3" }], ["app", "کنترل اپلیکیشن", { cat: "10" }]];
const FGL_SAFE = /^[\p{L}\p{N}._:@\/\\*+-]+$/u;
function fglValues(raw, kind) {
  // تا ۵ مقدار با فاصله یا ویرگول؛ بازه با «-». خروجی: {vals, err}
  // «\ » (فاصله‌ی escape‌شده) جزو همان مقدار است؛ مثل logdesc Object\ attribute\ configured
  const vals = String(raw || "").trim().match(/(?:\\ |[^\s,،])+/g) || [];
  if (!vals.length) return { vals };
  if (vals.length > 5) return { err: "حداکثر ۵ مقدار برای هر فیلد" };
  for (const v of vals) {
    if (!FGL_SAFE.test(v.replace(/\\ /g, "x"))) return { err: `مقدار نامعتبر: ${v}` };
    const parts = v.includes("-") && kind !== "text" && kind !== "ip6" ? v.split("-") : [v];
    if (parts.length > 2 || parts.some((x) => !x)) return { err: `بازه‌ی نامعتبر: ${v}` };
    for (const x of parts) {
      if (kind === "ip" && IP.v4(x) == null && IP.v6(x) == null) return { err: `IP نامعتبر: ${x}` };
      if (kind === "port" && !(/^\d+$/.test(x) && +x >= 0 && +x <= 65535)) return { err: `پورت نامعتبر: ${x}` };
      if (kind === "num" && !/^\d+$/.test(x)) return { err: `عدد نامعتبر: ${x}` };
    }
  }
  return { vals };
}
function fglBuild(o) {
  // o: {ver, vdom, dev, cat, date, t1, t2, lines, either, ip, rows:[[field, value, not]]}
  const err = [], conds = [];
  if (o.vdom && !/^[A-Za-z0-9_.-]{1,31}$/.test(o.vdom)) err.push("نام VDOM نامعتبر است.");
  if (o.date && !/^\d{4}-\d{2}-\d{2}$/.test(o.date)) err.push("تاریخ باید YYYY-MM-DD باشد.");
  const tm = (x) => !x || /^\d{2}:\d{2}(:\d{2})?$/.test(x);
  if (!tm(o.t1) || !tm(o.t2)) err.push("ساعت باید HH:MM یا HH:MM:SS باشد.");
  const sec = (x) => (x.length === 5 ? x + ":00" : x);
  let time = "";
  if (o.t1 || o.t2) {
    const a = sec(o.t1 || "00:00:00"), b = sec(o.t2 || "23:59:59");
    if (a > b) err.push("ساعت پایان پیش از شروع است؛ برای بازه‌ی شبانه دو جستجو بسازید.");
    time = `${a}-${b}`;
  }
  const lines = Math.max(5, Math.min(1000, Number(o.lines) || 100));
  if (o.either) {
    const r = fglValues(o.ip, "ip");
    if (r.err) err.push(r.err); else if (!r.vals.length) err.push("IP را برای «هر دو جهت» وارد کنید.");
    else conds.push({ either: r.vals });
  }
  const seen = new Set();
  for (const [f, v, not] of o.rows || []) {
    if (!f || !String(v || "").trim()) continue;
    const def = FGL_FIELDS.find((x) => x[0] === f), kind = def ? def[2] : "text";
    if (!/^[a-z][a-z0-9_-]{0,30}$/.test(f)) { err.push(`نام فیلد نامعتبر: ${f}`); continue; }
    if (seen.has(f)) { err.push(`فیلد ${f} دو بار آمده است؛ مقدارها را در یک ردیف بنویسید (تا ۵ مقدار).`); continue; }
    seen.add(f);
    const r = fglValues(v, kind);
    if (r.err) { err.push(`${f}: ${r.err}`); continue; }
    conds.push({ f, vals: r.vals, not: !!not });
  }
  if (err.length) return { err };
  const free = conds.some((c) => c.either);
  const cmds = [];
  if (o.vdom) cmds.push("config vdom", `edit ${o.vdom}`);
  cmds.push("execute log filter reset", `execute log filter device ${o.dev}`, `execute log filter category ${o.cat}`);
  if (free) {
    const parts = [];
    if (o.date) parts.push(`(date ${o.date})`);
    if (time) parts.push(`(time ${time})`);
    for (const c of conds) parts.push(c.either ? `((srcip ${c.either.join(" ")}) or (dstip ${c.either.join(" ")}))` : `(${c.f} ${c.vals.join(" ")}${c.not ? " not" : ""})`);
    cmds.push(`execute log filter free-style "${parts.join(" and ")}"`);
  } else {
    if (o.date) cmds.push(`execute log filter field date ${o.date}`);
    if (time) cmds.push(`execute log filter field time ${time}`);
    for (const c of conds) cmds.push(`execute log filter field ${c.f} ${c.vals.join(" ")}${c.not ? " not" : ""}`);
  }
  cmds.push(`execute log filter view-lines ${lines}`, "execute log filter dump", "execute log display");
  if (o.vdom) cmds.push("end");
  return { cmds, free };
}
function offFgCli() {
  const L = OFF.last.fgl = OFF.last.fgl || { ver: "7.2", vdom: "", dev: "1", cat: "0", date: "", t1: "", t2: "", lines: "100", either: false, ip: "",
    rows: [["srcip", "", false], ["dstip", "", false], ["dstport", "", false], ["action", "", false]] };
  const cats = () => FGL_CAT.filter((c) => (!c[3] || fglV(L.ver) >= fglV(c[3])) && (!c[4] || fglV(L.ver) < fglV(c[4])));
  const fieldOpts = (cur) => FGL_FIELDS.map(([k, t]) => `<option value="${k}" ${k === cur ? "selected" : ""}>${k} — ${t}</option>`).join("")
    + (cur && !FGL_FIELDS.some((x) => x[0] === cur) ? `<option value="${esc(cur)}" selected>${esc(cur)}</option>` : "");
  const draw = () => {
    if (!cats().some((c) => c[0] === L.cat)) L.cat = "0";
    if (!FGL_DEV(L.ver).some((d) => d[0] === L.dev)) L.dev = "0";
    $("#offTool").innerHTML = `<div class="panel"><p class="hint">فقط دستور می‌سازد و به فایروال وصل نمی‌شود. خروجی را در CLI فورتی‌گیت (SSH یا کنسول) کپی کنید؛ برای صفحه‌ی بعد <span class="ltr tech">execute log display</span> را دوباره بزنید.</p>
      <div class="row" style="gap:6px;flex-wrap:wrap;margin:6px 0 10px">${FGL_PRESETS.map(([k, t]) => `<button class="btn sm" data-fgp="${k}">${t}</button>`).join("")}</div>
      <div class="form-grid">
        <label class="field"><span>نسخه‌ی FortiOS</span><select id="fgVer" class="ltr">${FGL_VERS.map((v) => `<option ${v === L.ver ? "selected" : ""}>${v}</option>`).join("")}</select></label>
        <label class="field"><span>منبع لاگ (device)</span><select id="fgDev" class="ltr">${FGL_DEV(L.ver).map(([k, t]) => `<option value="${k}" ${k === L.dev ? "selected" : ""}>${k} — ${t}</option>`).join("")}</select></label>
        <label class="field"><span>دسته (category)</span><select id="fgCat" class="ltr">${cats().map(([k, n, t]) => `<option value="${k}" ${k === L.cat ? "selected" : ""}>${k} — ${n} (${t})</option>`).join("")}</select></label>
        <label class="field"><span>VDOM (فقط اگر VDOM فعال است)</span><input id="fgVdom" class="ltr" value="${esc(L.vdom)}" placeholder="root"></label>
        <label class="field"><span>تاریخ (ساعت خود فایروال)</span><input id="fgDate" type="date" class="ltr" value="${esc(L.date)}"></label>
        <label class="field"><span>از ساعت</span><input id="fgT1" type="time" step="1" class="ltr" value="${esc(L.t1)}"></label>
        <label class="field"><span>تا ساعت</span><input id="fgT2" type="time" step="1" class="ltr" value="${esc(L.t2)}"></label>
        <label class="field"><span>تعداد خط در هر نمایش (۵ تا ۱۰۰۰)</span><input id="fgLines" type="number" min="5" max="1000" class="ltr" value="${esc(L.lines)}"></label></div>
      <label class="chk" style="margin-top:8px"><input type="checkbox" id="fgEither" ${L.either ? "checked" : ""}>IP در هر دو جهت (مبدأ <b>یا</b> مقصد) — با free-style</label>
      ${L.either ? `<label class="field" style="max-width:520px"><span>IP (تا ۵ تا، با فاصله)</span><input id="fgIp" class="ltr" value="${esc(L.ip)}" placeholder="10.10.1.20 8.8.8.8"></label>` : ""}
      <h3 style="margin:14px 0 6px">فیلترها <small class="muted">(خالی = نادیده؛ تا ۵ مقدار با فاصله؛ بازه مثل <span class="ltr">1000-2000</span>؛ «not» = برعکس)</small></h3>
      <div id="fgRows">${L.rows.map(([f, v, n], i) => `<div class="row" style="gap:8px;margin-bottom:6px;flex-wrap:wrap">
          <select data-fgf="${i}" style="min-width:260px;font-family:Vazir,sans-serif">${fieldOpts(f)}</select>
          <input data-fgv="${i}" class="ltr" style="flex:1;min-width:200px" value="${esc(v)}" list="fgHint_${esc(f)}" placeholder="${esc((FGL_HINTS[f] || []).slice(0, 3).join(" · "))}">
          <label class="chk"><input type="checkbox" data-fgn="${i}" ${n ? "checked" : ""}>not</label>
          <button class="iconbtn" data-fgx="${i}" title="حذف">✕</button></div>`).join("")}</div>
      ${Object.entries(FGL_HINTS).map(([k, xs]) => `<datalist id="fgHint_${k}">${xs.map((x) => `<option value="${x}">`).join("")}</datalist>`).join("")}
      <button class="btn sm" id="fgAdd">+ فیلد</button>
      <div id="fgOut" style="margin-top:14px"></div>
      <details style="margin-top:10px"><summary class="muted" style="cursor:pointer">نکته‌ها</summary><ul class="hint">
        <li>شماره‌ی device و category به نسخه بستگی دارد؛ روی خود فایروال با <span class="ltr tech">execute log filter device ?</span> و <span class="ltr tech">execute log filter category ?</span> مطمئن شوید.</li>
        <li>همه‌ی فیلدها در همه‌ی دسته‌ها و نسخه‌ها نیستند؛ فهرست فیلدهای قابل استفاده: <span class="ltr tech">execute log filter field ?</span></li>
        <li>جستجو روی لاگ‌های ذخیره‌شده در همان منبع است؛ نتیجه‌ی صفر یعنی لاگی ذخیره نشده، نه لزوماً ترافیکی نبوده. Memory فقط لاگ‌های اخیر را دارد.</li>
        <li>فاصله داخل یک مقدار را با <span class="ltr tech">\ </span> بنویسید، مثل <span class="ltr tech">Object\ attribute\ configured</span>.</li>
        <li>با VDOM: دستورها داخل همان VDOM اجرا می‌شوند (<span class="ltr tech">config vdom → edit</span>).</li></ul></details></div>`;
    bind();
    out();
  };
  const out = () => {
    const r = fglBuild(L), box = $("#fgOut");
    if (r.err) { box.innerHTML = `<p class="hint warn" style="font-family:Vazir,sans-serif">${r.err.map(esc).join("<br>")}</p>`; return; }
    const txt = r.cmds.join("\n");
    box.innerHTML = `<div class="panel inner"><div class="panel-head"><h3>دستورها ${r.free ? `<span class="tag mute">free-style</span>` : ""}</h3>
        <span class="row"><button class="btn sm primary" id="fgCp">کپی</button><button class="btn sm ghost no-ro" id="fgSave">ذخیره‌ی TXT</button></span></div>
      <pre class="ltr paste-prev" data-no-i18n>${esc(txt)}</pre></div>`;
    $("#fgCp").onclick = () => offCopy(txt + "\n");
    $("#fgSave").onclick = async () => { const s = await api("save_export", "fortigate_log_search.txt", txt + "\n", false); if (!s.ok) return toast(s.error, "error"); if (!s.cancelled) toast("ذخیره شد: " + s.path, "ok"); };
  };
  const bind = () => {
    const sel = (id, k, redraw) => { const e = $(id); if (e) e.onchange = e.oninput = () => { L[k] = e.type === "checkbox" ? e.checked : e.value; redraw ? draw() : out(); }; };
    sel("#fgVer", "ver", true); sel("#fgDev", "dev"); sel("#fgCat", "cat"); sel("#fgVdom", "vdom"); sel("#fgDate", "date"); sel("#fgT1", "t1"); sel("#fgT2", "t2");
    sel("#fgLines", "lines"); sel("#fgEither", "either", true); sel("#fgIp", "ip");
    $$("[data-fgf]").forEach((e) => (e.onchange = () => { L.rows[+e.dataset.fgf][0] = e.value; draw(); }));
    $$("[data-fgv]").forEach((e) => (e.oninput = () => { L.rows[+e.dataset.fgv][1] = e.value; out(); }));
    $$("[data-fgn]").forEach((e) => (e.onchange = () => { L.rows[+e.dataset.fgn][2] = e.checked; out(); }));
    $$("[data-fgx]").forEach((e) => (e.onclick = () => { L.rows.splice(+e.dataset.fgx, 1); draw(); }));
    $("#fgAdd").onclick = () => { const used = new Set(L.rows.map((r) => r[0])); L.rows.push([(FGL_FIELDS.find((x) => !used.has(x[0])) || FGL_FIELDS[0])[0], "", false]); draw(); };
    $$("[data-fgp]").forEach((b) => (b.onclick = () => {
      const p = FGL_PRESETS.find((x) => x[0] === b.dataset.fgp)[2];
      Object.assign(L, { cat: p.cat, either: !!p.either, rows: (p.rows || []).map(([f, v]) => [f, v, false]) });
      if (!L.rows.length && !p.either) L.rows = [["srcip", "", false], ["dstip", "", false]];
      if (p.either) L.rows = [["dstport", "", false]];
      draw();
    }));
  };
  draw();
}

/* ---------- ۸. فهرست پورت‌ها: فهرست گزیده (ui/ports.js، توضیح فارسی و پرچم) + کل رجیستری IANA (ui/ports_iana.js، با اولین باز کردن) */
function portMatch(spec, n) {
  return String(spec).split(/,\s*/).some((x) => { const [a, b] = x.split("-").map(Number); return b ? n >= a && n <= b : n === a; });
}
const PORT_SHOW = 500;
function offLoadIana() {
  if (window.PORTS_IANA) return Promise.resolve(true);
  if (OFF.ianaP) return OFF.ianaP;
  OFF.ianaP = new Promise((res) => {
    const sc = document.createElement("script"); sc.src = "ports_iana.js";
    sc.onload = () => res(!!window.PORTS_IANA); sc.onerror = () => { OFF.ianaP = null; res(false); };
    document.head.appendChild(sc);
  });
  return OFF.ianaP;
}
function portFilter(q, cat, risky, iana) {
  // خروجی: [{p, proto, name, cat, fa, en, flag, src}] — گزیده اول، بعد IANA
  q = String(q || "").trim().toLowerCase();
  const rng = q.match(/^(\d{1,5})\s*-\s*(\d{1,5})$/), one = /^\d{1,5}$/.test(q) ? +q : null;
  const inRange = (spec) => String(spec).split(/,\s*/).some((x) => { const [a, b] = x.split("-").map(Number); return (b || a) >= +rng[1] && a <= +rng[2]; });
  const catT = Object.fromEntries(PORT_CATS.map((c) => [c[0], c]));
  const cur = PORTS.filter((p) => (!cat || p[3] === cat) && (!risky || p[6]) && (!q || (one !== null ? portMatch(p[0], one) : rng ? inRange(p[0])
    : [p[0], p[1], p[2], p[4], p[5], catT[p[3]][1], catT[p[3]][2]].some((x) => String(x).toLowerCase().includes(q)))))
    .map((p) => ({ p: p[0], proto: p[1], name: p[2], cat: p[3], fa: p[4], en: p[5], flag: p[6], src: "" }));
  if (cat || risky || !q || !iana) return cur;
  const ia = iana.filter((r) => one !== null ? r[0] === one : rng ? r[0] >= +rng[1] && r[0] <= +rng[2]
    : String(r[2]).toLowerCase().includes(q) || String(r[3]).toLowerCase().includes(q))
    .map((r) => ({ p: String(r[0]), proto: r[1], name: r[2], cat: "", fa: "", en: r[3], flag: "", src: "iana" }));
  return cur.concat(ia);
}
function offPorts() {
  const L = OFF.last.ports = OFF.last.ports || { q: "", cat: "", risky: false };
  $("#offTool").innerHTML = `<div class="panel"><div class="row" style="gap:10px;flex-wrap:wrap;align-items:flex-end">
      <label class="field" style="flex:1;min-width:240px"><span>جستجو (شماره، بازه مثل <span class="ltr">8000-9000</span>، نام سرویس یا توضیح)</span><input id="opQ" class="ltr" value="${esc(L.q)}" placeholder="3389 · smb · 5000-6000"></label>
      <label class="field"><span>دسته</span><select id="opCat"><option value="">همه</option>${PORT_CATS.map(([k, t]) => `<option value="${k}" ${k === L.cat ? "selected" : ""}>${t}</option>`).join("")}</select></label>
      <label class="chk"><input type="checkbox" id="opRisk" ${L.risky ? "checked" : ""}>فقط پرخطر / مشکوک</label>
      <button class="btn sm no-ro" id="opSave">ذخیره‌ی CSV</button></div>
    <p class="hint"><span class="tag warn">پرخطر</span> = نباید بی‌محافظ رو به اینترنت باز باشد. <span class="tag err">مشکوک</span> = پیش‌فرض بدافزار یا ابزار نفوذ؛ دیدنش در ترافیک ارزش بررسی دارد (قطعی نیست، هر برنامه‌ای می‌تواند از هر پورتی استفاده کند).
      <span id="opIana"></span></p>
    <div id="opOut"></div></div>`;
  const catT = Object.fromEntries(PORT_CATS.map(([k, t]) => [k, t]));
  let rows = [];
  const run = () => {
    L.q = $("#opQ").value; L.cat = $("#opCat").value; L.risky = $("#opRisk").checked;
    rows = portFilter(L.q, L.cat, L.risky, window.PORTS_IANA);
    const shown = rows.slice(0, PORT_SHOW), nC = rows.filter((r) => !r.src).length;
    const desc = (r) => r.src ? `<span data-no-i18n>${esc(r.en || "—")}</span>` : esc(r.fa);
    $("#opOut").innerHTML = rows.length ? `<div class="table-wrap inner"><table class="grid"><thead><tr><th>پورت</th><th>پروتکل</th><th>سرویس</th><th>دسته</th><th>توضیح</th><th></th></tr></thead><tbody>
      ${shown.map((r) => `<tr><td class="ltr tech num">${esc(r.p)}</td><td class="ltr">${esc(r.proto.toUpperCase())}</td><td class="ltr tech">${esc(r.name)}</td>
        <td>${r.src ? `<span class="tag mute">IANA</span>` : esc(catT[r.cat])}</td><td class="wrap">${desc(r)}</td>
        <td>${r.flag === "m" ? `<span class="tag err">مشکوک</span>` : r.flag === "x" ? `<span class="tag warn">پرخطر</span>` : ""}</td></tr>`).join("")}</tbody></table></div>
      <p class="hint">${rows.length > PORT_SHOW ? `${num(PORT_SHOW)} ردیف اول از ${num(rows.length)} نمایش داده شد؛ جستجو را دقیق‌تر کنید یا CSV بگیرید. ` : ""}${num(nC)} از فهرست گزیده، ${num(rows.length - nC)} از رجیستری IANA</p>`
      : `<div class="empty">موردی پیدا نشد.</div>`;
  };
  const st = (ok) => { const e = $("#opIana"); if (e) e.innerHTML = ok ? `جستجو در کل رجیستری رسمی IANA هم انجام می‌شود (${num(window.PORTS_IANA.length)} سرویس؛ نام رسمی ممکن است با کاربرد واقعی فرق کند، مثل 541 که فورتی‌گیت برای FGFM استفاده می‌کند). ردیف‌های IANA دسته و برچسب «پرخطر» ندارند و فقط با جستجو نمایش داده می‌شوند.` : "رجیستری IANA بارگذاری نشد؛ فقط فهرست گزیده."; };
  $("#opQ").oninput = run; $("#opCat").onchange = run; $("#opRisk").onchange = run;
  $("#opSave").onclick = () => offSaveCsv("autokrp_ports.csv", ["پورت", "پروتکل", "سرویس", "دسته", "توضیح", "پرخطر / مشکوک"],
    rows.map((r) => [r.p, r.proto, r.name, r.src ? "IANA" : I18N.t(catT[r.cat]), r.src || I18N.lang === "en" ? r.en : r.fa, r.flag === "m" ? I18N.t("مشکوک") : r.flag === "x" ? I18N.t("پرخطر") : ""]));
  run();
  offLoadIana().then((ok) => { st(ok); if (ok && OFF.tool === "ports" && $("#opOut")) run(); });
}
if (typeof module !== "undefined") module.exports = { IP, offParseNet, offRangeToCidrs, offIocExtract, offDefang, offRefang, offB64d, offB64e, fglBuild, fglValues, portMatch, portFilter };
