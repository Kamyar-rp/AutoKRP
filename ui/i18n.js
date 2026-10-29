"use strict";
/*
 * AutoKRP i18n — ترجمه‌ی زمان اجرا.
 * رابط به فارسی نوشته شده است. در حالت انگلیسی هر متن فارسی (text node و title/placeholder)
 * هنگام نمایش با واژه‌نامه‌ی window.I18N_EN جایگزین می‌شود. {0} {1} ... جای مقادیر متغیر است؛
 * مقدارهای گرفته‌شده هم (اگر فارسی باشند) دوباره ترجمه می‌شوند.
 * هرگز ترجمه نمی‌شوند: مقدار input و textarea، و هر عنصر داخل [data-no-i18n]
 * (placeholder و title فیلدها ترجمه می‌شوند)
 * (داده‌ی کاربر مثل قالب تیکت، پیش‌نمایش تیکت و خروجی SSH).
 */
const I18N = (() => {
  const FA = /[\u0600-\u06FF]/;
  const INVIS = /[\u200e\u200f\u2066-\u2069]/g;
  const SKIP = new Set(["SCRIPT", "STYLE", "TEXTAREA", "INPUT", "CODE"]);
  const ATTRS = ["title", "placeholder", "aria-label", "data-title"];
  const PDIG = "۰۱۲۳۴۵۶۷۸۹", ADIG = "٠١٢٣٤٥٦٧٨٩";
  const SEPS = [[" — ", " — "], [" | ", " | "], ["؛ ", "; "], ["، ", ", "], [": ", ": "], [" + ", " + "], [" ← ", " → "], [" → ", " → "], [" · ", " · "]];
  let lang = "fa";
  const exact = new Map(), pats = [], cache = new Map();
  const orig = new WeakMap();        // text node → متن فارسی اصلی
  const origAttr = new WeakMap();    // element → {attr: متن اصلی}

  const norm = (s) => s.replace(INVIS, "").replace(/\s+/g, " ").trim();
  const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const latinDigits = (s) => s.replace(/[۰-۹]/g, (d) => PDIG.indexOf(d)).replace(/[٠-٩]/g, (d) => ADIG.indexOf(d));

  const memo = new Map();
  function load(dict) {
    memo.clear();
    for (const [fa, en] of Object.entries(dict || {})) {
      const key = norm(fa);
      if (!/\{\d+\}/.test(key)) { exact.set(key, en); exact.set(latinDigits(key), en); continue; }
      const parts = key.split(/(\{\d+\})/), idx = [];
      let re = "^";
      for (const p of parts) {
        const m = p.match(/^\{(\d+)\}$/);
        if (m) { re += "([\\s\\S]*?)"; idx.push(+m[1]); } else re += esc(p);
      }
      pats.push({ re: new RegExp(re + "$"), en, idx, fixed: key.replace(/\{\d+\}/g, "").length });
    }
    pats.sort((a, b) => b.fixed - a.fixed);   // الگوی دقیق‌تر اول
  }

  const faCount = (x) => (x.match(/[\u0600-\u06FF]/g) || []).length;
  const keepWs = (src, out) => src.match(/^\s*/)[0] + out + src.match(/\s*$/)[0];
  const SENT = /(?<=[.!؟?])\s+(?=\S)/;

  // 1.24: حافظه‌ی نتیجه؛ متن بلند چندجمله‌ای بی‌ترجمه بدون آن چند ده ثانیه طول می‌کشید (بازگشت روی همه‌ی ترکیب جمله‌ها)
  function core(s, depth = 0) {
    if (!FA.test(s) || depth > 6) return s;
    const k = norm(s);
    if (exact.has(k)) return exact.get(k);
    const mk = memo.get(k);
    if (mk !== undefined) return keepWs(s, mk);
    const out = core2(s, k, depth);
    if (memo.size > 20000) memo.clear();
    memo.set(k, out.trim());
    return out;
  }
  function core2(s, k, depth) {
    // الگو با جای مقدار؛ مقدار نباید مرز جمله‌ی فارسی را بپوشاند
    for (const p of pats) {
      const m = k.match(p.re);
      if (!m) continue;
      const caps = m.slice(1);
      if (caps.some((v) => FA.test(v) && /[.!؟?]\s+\S/.test(v))) continue;
      // الگوی کوتاه (مثل «ستون {0}») نباید یک جمله‌ی فارسی کامل را به‌عنوان مقدار بگیرد
      if (p.fixed < 9 && caps.some((v) => (v.match(/[\u0600-\u06FF]+/g) || []).length > 2)) continue;
      return p.en.replace(/\{(\d+)\}/g, (_, n) => {
        const v = caps[p.idx.indexOf(+n)] ?? "";
        return FA.test(v) ? keepWs(v, core(v, depth + 1)) : v;
      });
    }
    const cands = [];
    // فقط علامت‌های فارسی مانده (، ؛ ؟)
    if (!/[\u0621-\u064A\u067E-\u06D3]/.test(k)) return k.replace(/،\s*/g, ", ").replace(/؛\s*/g, "; ").replace(/؟/g, "?").replace(/٪/g, "%");
    // چند جمله در یک متن
    const sents = k.split(SENT);
    if (sents.length > 1) {
      // بلندترین گروه جمله‌های پشت‌سرهم که کامل ترجمه می‌شود
      const out = [];
      for (let i = 0; i < sents.length;) {
        let j = sents.length, got = null;
        for (; j > i; j--) {
          const chunk = sents.slice(i, j).join(" "), tr = core(chunk, depth + 1);
          if (!FA.test(tr) || j === i + 1) { got = tr; break; }
        }
        out.push(got); i = j;
      }
      cands.push(out.join(" "));
    }
    // پرانتز انتهایی: «X (Y)»
    const tp = k.match(/^([\s\S]*\S)\s*\(([^()]*)\)([.:]?)$/);
    if (tp) {
      const h = core(tp[1], depth + 1), i = FA.test(tp[2]) ? core(tp[2], depth + 1) : tp[2];
      cands.push(`${h} (${i})${tp[3]}`);
    }
    // جداکننده‌ها
    for (const [sep, rep] of SEPS) {
      if (!k.includes(sep)) continue;
      const parts = k.split(sep);
      if (parts.length < 2) continue;
      cands.push(parts.map((x) => (FA.test(x) ? keepWs(x, core(x, depth + 1)) : x)).join(rep));
    }
    // همه‌ی پرانتزها جدا
    if (/\([^()]*\)/.test(k)) {
      cands.push(k.split(/(\([^()]*\))/).map((x) => {
        if (!FA.test(x)) return x;
        const pm = x.match(/^\(([^()]*)\)$/);
        return pm ? `(${core(pm[1], depth + 1)})` : keepWs(x, core(x.trim(), depth + 1));
      }).join(""));
    }
    // گیومه و علامت اطراف
    const wrap = k.match(/^([(«“"\[]*)([\s\S]*?)([)»”"\].:!؟?]*)$/);
    if (wrap && (wrap[1] || wrap[3]) && wrap[2]) {
      cands.push(wrap[1].replace("«", "“") + core(wrap[2], depth + 1) + wrap[3].replace("»", "”").replace("؟", "?"));
    }
    // کلمه‌به‌کلمه، فقط اگر همه‌ی کلمه‌های فارسی ترجمه‌ی دقیق دارند (مثل «آبان 1404»)
    const toks = k.split(" ");
    if (toks.length > 1 && toks.every((x) => !FA.test(x) || exact.has(x))) cands.push(toks.map((x) => (FA.test(x) ? exact.get(x) : x)).join(" "));
    if (!cands.length) return s;
    // بهترین: کمترین حرف فارسی باقی‌مانده
    let best = s, score = faCount(s);
    for (const c of cands) { const sc = faCount(c); if (sc < score) { best = c; score = sc; } }
    return best;
  }

  function t(s) {
    if (lang !== "en" || s == null) return s;
    s = String(s);
    if (!FA.test(s)) return s;
    if (cache.has(s)) return cache.get(s);
    const lead = s.match(/^\s*/)[0], trail = s.match(/\s*$/)[0];
    let out = core(s);
    if (out === s && s.includes("\n")) {         // چندخطی: هر خط جدا (خط‌ها حفظ می‌شوند)
      out = s.split("\n").map((ln) => (FA.test(ln) ? keepWs(ln, core(ln)) : ln)).join("\n");
    }
    // در رابط راست‌به‌چپ «←» یعنی «بعدی»؛ در انگلیسی همان معنا «→» است
    out = out === s ? s : (lead + out + trail).replace(/←/g, "→");
    if (cache.size > 5000) cache.clear();
    cache.set(s, out);
    return out;
  }

  const skipped = (el) => {
    for (let e = el; e && e.nodeType === 1; e = e.parentElement) {
      if (SKIP.has(e.tagName) || e.isContentEditable || e.hasAttribute("data-no-i18n")) return true;
    }
    return false;
  };

  const done = new WeakMap();   // node → متنی که خودمان گذاشتیم (جلوگیری از ترجمه‌ی دوباره و حلقه)
  function doText(n) {
    const v = n.nodeValue;
    if (lang === "en") {
      if (!v || !FA.test(v) || done.get(n) === v || skipped(n.parentElement)) return;
      const tr = t(v);
      if (tr !== v) { orig.set(n, v); done.set(n, tr); n.nodeValue = tr; } else done.set(n, v);
    } else if (orig.has(n)) {
      n.nodeValue = orig.get(n); orig.delete(n);
    }
  }
  // برای ویژگی‌ها (placeholder/title) فقط [data-no-i18n] مانع است؛ مقدار فیلدها هرگز دست نمی‌خورد
  const skippedAttr = (el) => {
    for (let e = el; e && e.nodeType === 1; e = e.parentElement) {
      if (e.hasAttribute("data-no-i18n") || e.isContentEditable) return true;
    }
    return false;
  };
  function doAttrs(el) {
    if (skippedAttr(el)) return;
    for (const a of ATTRS) {
      const v = el.getAttribute(a);
      if (lang === "en") {
        if (v && FA.test(v)) {
          const o = origAttr.get(el) || {};
          if (o["_" + a] === v) continue;          // قبلاً پردازش شده (ترجمه‌ی ناقص)
          const tr = t(v);
          o[a] = v; o["_" + a] = tr; origAttr.set(el, o);
          if (tr !== v) el.setAttribute(a, tr);
        }
      } else {
        const o = origAttr.get(el);
        if (o && o[a] !== undefined) { el.setAttribute(a, o[a]); delete o[a]; delete o["_" + a]; }
      }
    }
  }
  function walk(root) {
    if (!root) return;
    if (root.nodeType === 3) return doText(root);
    if (root.nodeType !== 1) return;
    doAttrs(root);
    const tw = document.createTreeWalker(root, NodeFilter.SHOW_ELEMENT | NodeFilter.SHOW_TEXT);
    for (let n = tw.nextNode(); n; n = tw.nextNode()) n.nodeType === 3 ? doText(n) : doAttrs(n);
  }

  const obs = new MutationObserver((muts) => {
    if (lang !== "en") return;
    for (const m of muts) {
      if (m.type === "characterData") doText(m.target);
      else if (m.type === "attributes") doAttrs(m.target);
      else m.addedNodes.forEach(walk);
    }
  });

  function apply(l) {
    lang = l === "en" ? "en" : "fa";
    const html = document.documentElement;
    html.lang = lang;
    html.dir = lang === "en" ? "ltr" : "rtl";
    cache.clear();
    walk(document.body);
    if (lang === "en") document.title = t(document.title);
  }

  load(window.I18N_EN);
  obs.observe(document.documentElement, { childList: true, subtree: true, characterData: true,
    attributes: true, attributeFilter: ATTRS });
  // 1.30: زبان پیش‌فرض بار اول انگلیسی؛ بعد همان انتخاب کاربر (localStorage و تنظیمات برنامه)
  let saved = null;
  try { saved = localStorage.getItem("akrp_lang"); } catch (e) { saved = null; }
  if (saved !== "fa" && document.body) apply("en");
  return { t, apply, get lang() { return lang; } };
})();
window.I18N = I18N;
