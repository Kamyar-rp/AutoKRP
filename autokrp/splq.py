"""دستیار بهینه‌سازی کوئری Splunk برای اجرای API (search/jobs/export).

فقط متن کوئری را تحلیل می‌کند؛ به Splunk وصل نمی‌شود (بررسی فیلدها جداست: fields_probe_query/compare_fields).
قاعده‌ها از کوئری‌های واقعی کاربر استخراج شده‌اند (نسخه‌ی خام از وب Splunk ← نسخه‌ای که در برنامه کار کرد):
  اصلاح خودکار (fix):    sort بدون عدد، search … IN (رنج‌ها)، IN داخل where، ماکروی security_content_ctime،
                          ادغام eval‌های مستقل پشت‌سرهم، یک دستور در هر خط.
  پیشنهاد (suggest):     | fields پس از جستجوی پایه، سقف ستون‌های چندمقداری، نام ستون‌های شناخته‌شده‌ی برنامه،
                          زمان خوانا برای firstTime/lastTime.
  هشدار (warn):          مرتب‌سازی الفبایی روی ستون متنی case()، ماکروهای دیگر، دستورهایی که بررسی فیلد را ناممکن می‌کنند.
هیچ قاعده‌ای معنای کوئری را بی‌صدا عوض نمی‌کند؛ پیشنهادها فقط با تیک کاربر اعمال می‌شوند.
"""
import difflib
import re

from .connectors.splunk import FIELD_CANDIDATES, clean_query

TRANSFORMING = {"stats", "chart", "timechart", "top", "rare", "tstats", "table", "transaction", "geostats", "sistats", "mstats"}
SAFE_PRE = {"eval", "where", "search", "fields", "rename"}       # دستورهایی که فیلدهای ورودی‌شان را می‌توان شمرد
KEYWORDS = {"and", "or", "not", "xor", "in", "like", "as", "by", "over", "true", "false", "null", "output", "outputnew"}
STATS_FUNCS = {"count", "dc", "distinct_count", "values", "list", "min", "max", "sum", "avg", "mean", "median", "mode", "range",
               "stdev", "var", "first", "last", "earliest", "latest", "estdc", "perc", "p", "sumsq", "rate"}
IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*")
CIDR = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?$")
TIME_FMT = "%Y-%m-%d %H:%M:%S"
MV_CAP = 50
MERGE_FUNCS = {"mvjoin", "strftime", "round", "tostring", "trim", "lower", "upper"}   # eval‌های قالب‌بندی که ادغامشان خواناتر است
# نام‌های رایجی که برای یک نقش برنامه به‌کار می‌روند ولی برنامه نمی‌شناسد ← نام استاندارد
RENAME_HINTS = {"count": ["attempts", "hits", "total", "events", "event_count"], "dest": ["targets", "target", "dst", "dstip"],
                "dest_port": ["ports", "dport", "dstport"], "signature": ["sig", "alert", "rule", "rule_name"]}


# ---------------------------------------------------------------- تجزیه
def split_pipes(q):
    """جدا کردن دستورها روی | سطح بالا (نه داخل "…"، `…`، […] یا (…))."""
    out, cur, depth, quote = [], [], 0, None
    i = 0
    while i < len(q):
        c = q[i]
        if quote:
            cur.append(c)
            if c == "\\" and quote == '"' and i + 1 < len(q):
                cur.append(q[i + 1]); i += 2; continue
            if c == quote:
                quote = None
        elif c in "\"`":
            quote = c; cur.append(c)
        elif c in "[(":
            depth += 1; cur.append(c)
        elif c in "])":
            depth = max(0, depth - 1); cur.append(c)
        elif c == "|" and depth == 0:
            out.append("".join(cur)); cur = []
        else:
            cur.append(c)
        i += 1
    out.append("".join(cur))
    return [x for x in (s.strip() for s in out)]


def squash(s):
    """فاصله‌های پشت‌سرهم (بیرون از "…") ← یک فاصله؛ فاصله‌ی پیش از , و بعد از ( و پیش از ) حذف."""
    out, quote = [], None
    for c in s:
        if quote:
            out.append(c)
            if c == quote:
                quote = None
            continue
        if c in "\"`":
            quote = c; out.append(c); continue
        if c.isspace():
            if out and out[-1] != " ":
                out.append(" ")
            continue
        if c in ",)" and out and out[-1] == " ":
            out.pop()
        if out and out[-1] == " " and len(out) > 1 and out[-2] == "(":
            out.pop()
        out.append(c)
    return "".join(out).strip()


def split_top(s, sep=","):
    """جدا کردن روی جداکننده‌ی سطح بالا (نه داخل پرانتز یا رشته)."""
    out, cur, depth, quote = [], [], 0, None
    for c in s:
        if quote:
            cur.append(c)
            if c == quote:
                quote = None
        elif c == '"':
            quote = c; cur.append(c)
        elif c == "(":
            depth += 1; cur.append(c)
        elif c == ")":
            depth -= 1; cur.append(c)
        elif c == sep and depth == 0:
            out.append("".join(cur)); cur = []
        else:
            cur.append(c)
    out.append("".join(cur))
    return [x.strip() for x in out if x.strip()]


def strip_strings(s):
    return re.sub(r'"(?:[^"\\]|\\.)*"', '""', s)


def cmd_name(c):
    m = re.match(r"\s*([A-Za-z_]+)", c)
    return m.group(1).lower() if m else ""


def idents(expr):
    """نام فیلدهای ارجاع‌شده در یک عبارت (بدون رشته‌ها، نام تابع‌ها، کلیدواژه‌ها و اعداد)."""
    e = strip_strings(expr)
    out = []
    for m in IDENT.finditer(e):
        name = m.group(0)
        rest = e[m.end():].lstrip()
        if rest.startswith("("):
            continue                                   # تابع
        if name.lower() in KEYWORDS:
            continue
        if m.start() > 0 and (e[m.start() - 1].isdigit() or e[m.start() - 1] == "."):
            continue                                   # 1e5 یا عدد اعشاری
        out.append(name)
    return out


def eval_assignments(body):
    """eval a=…, b=… ← [(نام، عبارت)]"""
    out = []
    for part in split_top(body):
        m = re.match(r"\s*([A-Za-z_][\w.]*)\s*=(?!=)(.*)$", part, re.S)
        if m:
            out.append((m.group(1), m.group(2).strip()))
    return out


def stats_parts(body):
    """stats … by f1, f2 ← (عبارت توابع، فیلدهای by، نام‌های خروجی)"""
    b = strip_strings(body)
    m = re.search(r"\bby\b(.*)$", b, re.I | re.S)
    by = [x for x in re.split(r"[\s,]+", m.group(1).strip()) if x] if m else []
    funcs = body[:m.start()] if m else body
    outs = re.findall(r"\bas\s+([A-Za-z_][\w.]*)", strip_strings(funcs), re.I)
    return funcs, by, outs


# ---------------------------------------------------------------- قاعده‌ها
def _fix_sort(cmds, notes):
    for i, c in enumerate(cmds):
        if cmd_name(c) == "sort":
            rest = c[4:].strip()
            if not re.match(r"^(\d+|limit\s*=)", rest, re.I):
                cmds[i] = "sort 0 " + rest
                notes.append(("fix", "sort0", f"«{c}» بدون عدد فقط ۱۰٬۰۰۰ ردیف اول را برمی‌گرداند (بقیه بی‌صدا حذف می‌شوند) ← sort 0"))


def _fix_search_in(cmds, notes):
    """search NOT f IN ("10.0.0.0/8", …) ← where NOT (cidrmatch(…) OR …)"""
    for i, c in enumerate(cmds):
        if i == 0 or cmd_name(c) != "search":
            continue
        m = re.match(r"^search\s+(NOT\s+)?([A-Za-z_][\w.]*)\s+IN\s*\((.*)\)\s*$", c, re.I | re.S)
        if not m:
            continue
        vals = [v.strip().strip('"') for v in split_top(m.group(3))]
        if not vals or not all(CIDR.match(v) for v in vals):
            continue
        f = m.group(2)
        conds = [f'cidrmatch("{v}", {f})' if "/" in v else f'{f}="{v}"' for v in vals]
        expr = " OR ".join(conds)
        cmds[i] = f"where NOT ({expr})" if m.group(1) else f"where ({expr})"
        notes.append(("fix", "cidr", f"«search … {f} IN (رنج‌ها)» ← where با cidrmatch (مقایسه‌ی درست رنج‌های IP)"))


_IN_RE = re.compile(r"(?<![\w.])([A-Za-z_][\w.]*)\s+IN\s*\(", re.I)


def _fix_where_in(cmds, notes):
    for i, c in enumerate(cmds):
        if cmd_name(c) != "where":
            continue
        # فقط بیرون از رشته‌ها
        parts = re.split(r'("(?:[^"\\]|\\.)*")', c)
        changed = False
        for j in range(0, len(parts), 2):
            new = _IN_RE.sub(lambda m: f"in({m.group(1)}, ", parts[j])
            if new != parts[j]:
                parts[j], changed = new, True
        if changed:
            new_c = "".join(parts)
            new_c = re.sub(r"in\(([^,]+), \s*", r"in(\1, ", new_c)
            cmds[i] = new_c
            notes.append(("fix", "wherein", "«field IN (…)» داخل where ← تابع in(field, …)"))


def _fix_macros(cmds, notes):
    out = []
    for c in cmds:
        m = re.match(r"^`security_content_ctime\(\s*([A-Za-z_][\w.]*)\s*\)`$", c.strip())
        if m:
            f = m.group(1)
            out.append(f'eval {f}=strftime({f}, "%Y-%m-%dT%H:%M:%S")')
            notes.append(("fix", "macro", f"ماکروی security_content_ctime({f}) ← eval strftime (ماکرو ممکن است برای کاربر API یا app دیده نشود)"))
            continue
        for mm in re.finditer(r"`([^`(]+)", c):
            notes.append(("warn", "macro", f"ماکروی «{mm.group(1)}»: باید در app تنظیم‌شده و برای کاربر توکن قابل دسترسی باشد؛ "
                                           "وگرنه کوئری در API خطا می‌دهد (پیش‌نمایش را ببینید)"))
        out.append(c)
    cmds[:] = out


def _head(expr):
    m = re.match(r"\s*([A-Za-z_]\w*)\(", expr)
    return m.group(1).lower() if m else None


def _merge_evals(cmds, notes):
    out, merged = [], 0
    for c in cmds:
        if out and cmd_name(c) == "eval" and cmd_name(out[-1]) == "eval":
            prev = eval_assignments(out[-1][4:])
            cur = eval_assignments(c[4:])
            made = {n for n, _ in prev}
            uses = {x for _, e in cur for x in idents(e)}
            heads = {_head(e) for _, e in prev + cur}
            # فقط تبدیل‌های هم‌نوع (مثل چند mvjoin یا چند strftime)؛ eval‌های منطقی جدا خواناتر می‌مانند
            if prev and cur and len(heads) == 1 and heads <= MERGE_FUNCS and not (made & uses) and not (made & {n for n, _ in cur}):
                out[-1] = out[-1] + ", " + c[4:].strip()
                merged += 1
                continue
        out.append(c)
    if merged:
        notes.append(("fix", "evals", f"{merged} دستور eval مستقل پشت‌سرهم در یک eval ادغام شد"))
    cmds[:] = out


def _first_transform(cmds):
    for i, c in enumerate(cmds[1:], 1):
        if cmd_name(c) in TRANSFORMING:
            return i
    return None


def base_fields(base):
    """فیلدهای جستجوی پایه (مثل category=* یا src!=…) — بدون index/sourcetype/source/host."""
    b = strip_strings(base)
    out = []
    for m in re.finditer(r"(?<![\w.])([A-Za-z_][\w.]*)\s*(?:!=|=|<=|>=|<|>)", b):
        n = m.group(1)
        if n.lower() not in ("index", "sourcetype", "source", "host", "earliest", "latest", "eventtype", "tag", "search"):
            out.append(n)
    return list(dict.fromkeys(out))


def referenced_fields(cmds):
    """فیلدهای خامی که تا (و شامل) اولین دستور تبدیلی لازم‌اند. None اگر دستوری ناشناخته پیش از آن هست."""
    t = _first_transform(cmds)
    if t is None:
        return None, None
    used, made = [], set()

    def use(names):
        for n in names:
            if n not in made and n not in used:
                used.append(n)
    for c in cmds[1:t]:
        n = cmd_name(c)
        if n not in SAFE_PRE:
            return None, n
        body = c[len(n):]
        if n == "eval":
            for name, expr in eval_assignments(body):
                use(idents(expr))
                made.add(name)
        elif n == "rename":
            for a, b in re.findall(r"([\w.*]+)\s+as\s+([\w.*]+)", body, re.I):
                use([a]); made.add(b)
        elif n == "fields":
            return None, "fields"                      # کاربر خودش fields گذاشته
        else:
            use(idents(body))
    n = cmd_name(cmds[t])
    body = cmds[t][len(n):]
    if n in ("stats", "chart", "timechart"):
        funcs, by, _ = stats_parts(body)
        funcs = re.sub(r"\bas\s+[A-Za-z_][\w.]*", " ", strip_strings(funcs), flags=re.I)
        names = [x for x in idents(funcs) if x.lower() not in STATS_FUNCS]
        use(names + by)
        if n == "timechart" and "_time" not in used:
            used.insert(0, "_time")
    elif n in ("top", "rare", "table"):
        use([x for x in re.split(r"[\s,]+", strip_strings(body)) if IDENT.fullmatch(x or "") and x.lower() not in KEYWORDS
             and "=" not in x])
    else:
        return None, n
    if "_time" in used:
        used.remove("_time"); used.insert(0, "_time")
    return used, None


def _suggest_fields(cmds, notes, sugg):
    if not cmds[0]:
        return                                          # بدون جستجوی پایه (| tstats …): fields معنا ندارد
    names, why = referenced_fields(cmds)
    if names is None:
        if why and why != "fields":
            notes.append(("warn", "fields", f"به‌خاطر دستور «{why}» پیش از stats، فهرست فیلدهای لازم خودکار تعیین نمی‌شود"))
        return
    if not names:
        return
    sugg.append({"id": "fields", "on": True, "text": f"افزودن «| fields {' '.join(names)}» بعد از جستجوی پایه: Splunk فقط همین "
                 f"{len(names)} فیلد را می‌خواند (کوئری سریع‌تر و سبک‌تر)", "apply": ("insert", 1, "fields " + " ".join(names))})


def _final_table(cmds):
    for i in range(len(cmds) - 1, 0, -1):
        if cmd_name(cmds[i]) == "table":
            return i
    return None


def output_columns(cmds):
    """ستون‌های خروجی نهایی اگر قابل تعیین است (از آخرین table)."""
    t = _final_table(cmds)
    if t is None:
        return None
    return [x for x in re.split(r"[\s,]+", cmds[t][5:].strip()) if x]


def _suggest_mvcap(cmds, notes, sugg):
    """mvjoin(values_field, …) بدون mvindex ← سقف ۵۰ مقدار"""
    vals = set()
    for c in cmds:
        if cmd_name(c) in ("stats", "eventstats", "streamstats"):
            for f in re.findall(r"\b(?:values|list)\([^)]*\)\s+as\s+([A-Za-z_][\w.]*)", c, re.I):
                vals.add(f)
    hits = []
    for i, c in enumerate(cmds):
        if cmd_name(c) != "eval":
            continue
        for m in re.finditer(r"mvjoin\(\s*([A-Za-z_][\w.]*)\s*,", c):
            if m.group(1) in vals:
                hits.append(m.group(1))
    if hits:
        sugg.append({"id": "mvcap", "on": False, "text": f"سقف {MV_CAP} مقدار برای ستون‌های چندمقداری ({', '.join(dict.fromkeys(hits))}) "
                     "تا فایل CSV برای IPهای پرتکرار بیش از حد بزرگ نشود (بقیه‌ی مقدارها حذف می‌شوند)", "apply": ("mvcap", hits)})


def _suggest_names(cmds, notes, sugg):
    cols = output_columns(cmds)
    if not cols:
        return
    have = set(cols)
    renames = []
    for role, cands in FIELD_CANDIDATES.items():
        if any(c in have for c in cands):
            continue
        for alt in RENAME_HINTS.get(role, []):
            if alt in have and cands[0] not in have:
                renames.append((alt, cands[0]))
                break
    if renames:
        sugg.append({"id": "names", "on": True, "text": "نام ستون‌ها به نامی که برنامه خودکار می‌شناسد: "
                     + "، ".join(f"{a} ← {b}" for a, b in renames), "apply": ("rename", renames)})
    if "src" not in have and "src_ip" not in have:
        notes.append(("warn", "nosrc", "ستون IP مبدأ (src یا src_ip) در خروجی نیست؛ در پیش‌نمایش ستونش را دستی انتخاب کنید"))


def _suggest_times(cmds, notes, sugg):
    """min(_time)/max(_time) بدون تبدیل ← زمان خوانا (اگر ستون در خروجی است)"""
    tf = []
    for c in cmds:
        if cmd_name(c) in ("stats", "eventstats"):
            tf += re.findall(r"\b(?:min|max|earliest|latest)\(\s*_time\s*\)\s+as\s+([A-Za-z_][\w.]*)", c, re.I)
    if not tf:
        return
    conv = set()
    for c in cmds:
        for f in tf:
            if re.search(rf"\b{re.escape(f)}\s*=\s*strftime\(\s*{re.escape(f)}\b", c) or re.search(rf"ctime\(\s*{re.escape(f)}\s*\)", c):
                conv.add(f)
    cols = output_columns(cmds)
    need = [f for f in dict.fromkeys(tf) if f not in conv and (cols is None or f in cols)]
    if need:
        sugg.append({"id": "times", "on": True, "text": f"ستون‌های زمان ({', '.join(need)}) عدد epoch هستند؛ تبدیل به «{TIME_FMT}» در انتهای کوئری",
                     "apply": ("times", need)})


def _warn_sort_text(cmds, notes):
    texty = set()
    for c in cmds:
        if cmd_name(c) == "eval":
            for name, expr in eval_assignments(c[4:]):
                if expr.lower().startswith("case(") and re.search(r',\s*"[^"]*"\s*[,)]', expr):
                    texty.add(name)
    for c in cmds:
        if cmd_name(c) == "sort":
            for f in re.findall(r"[-+]?\s*([A-Za-z_][\w.]*)", c[4:]):
                if f in texty:
                    notes.append(("warn", "sorttext", f"«sort … {f}»: {f} متن است (case با متن)، پس الفبایی مرتب می‌شود "
                                                      f"(مثلاً Critical، High، Low، Medium). یک ستون عددی رتبه بسازید، مثل {f}_rank"))


# ---------------------------------------------------------------- اعمال پیشنهادها
def apply_suggestion(cmds, s):
    kind = s["apply"][0]
    if kind == "insert":
        _, pos, text = s["apply"]
        cmds.insert(pos, text)
    elif kind == "mvcap":
        for i, c in enumerate(cmds):
            if cmd_name(c) == "eval":
                for f in s["apply"][1]:
                    c = re.sub(rf"mvjoin\(\s*{re.escape(f)}\s*,", f"mvjoin(mvindex({f}, 0, {MV_CAP - 1}),", c)
                cmds[i] = c
    elif kind == "rename":
        pairs = s["apply"][1]
        t = _final_table(cmds)
        if t is None:
            return
        cmds.insert(t, "rename " + ", ".join(f"{a} as {b}" for a, b in pairs))
        cols = [dict(pairs).get(x, x) for x in output_columns(cmds)]
        cmds[t + 1] = "table " + " ".join(cols)
    elif kind == "times":
        expr = ", ".join(f'{f}=strftime({f}, "{TIME_FMT}")' for f in s["apply"][1])
        t = _final_table(cmds)
        # پیش از sort/table پایانی (sort روی زمان عددی درست است؛ تبدیل بعد از آن هم بی‌خطر است)
        pos = t if t is not None else len(cmds)
        cmds.insert(pos, "eval " + expr)


def build(cmds):
    body = "\n| ".join(c for c in cmds[1:] if c)
    if not cmds[0]:                                     # کوئری با دستور تولیدکننده (| tstats، | inputlookup …)
        return "| " + body
    return cmds[0] + ("\n| " + body if body else "")


def optimize(query, accept=None):
    """کوئری خام ← {"query": نتیجه با اصلاح‌ها و پیشنهادهای پذیرفته، "notes": [...], "suggestions": [...]}
    accept: شناسه‌ی پیشنهادهایی که اعمال شوند (None = پیش‌فرض هر پیشنهاد)."""
    q, clean_notes = clean_query((query or "").replace("\r\n", "\n"))
    notes = [("fix", "chars", n) for n in clean_notes]
    cmds = [squash(c) for c in split_pipes(q.strip())]
    cmds = [c for c in cmds if c] if cmds and cmds[0] else [""] + [c for c in cmds[1:] if c]
    if not cmds or not any(cmds):
        return {"query": "", "notes": [], "suggestions": [], "base": ""}
    if cmds[0].lower().startswith("search "):
        cmds[0] = cmds[0][7:].strip()
    _fix_macros(cmds, notes)
    _fix_search_in(cmds, notes)
    _fix_where_in(cmds, notes)
    _fix_sort(cmds, notes)
    _merge_evals(cmds, notes)
    _warn_sort_text(cmds, notes)
    sugg = []
    _suggest_fields(cmds, notes, sugg)
    _suggest_mvcap(cmds, notes, sugg)
    _suggest_names(cmds, notes, sugg)
    _suggest_times(cmds, notes, sugg)
    order = {"names": 0, "times": 1, "mvcap": 2, "fields": 3}         # از انتها به ابتدا تا جای درج‌ها جابه‌جا نشود
    for s in sorted(sugg, key=lambda x: order.get(x["id"], 9)):
        on = s["on"] if accept is None else s["id"] in accept
        s["on"] = on
        if on:
            apply_suggestion(cmds, s)
    # ردیف‌های تکراری یادداشت‌ها
    seen, uniq = set(), []
    for n in notes:
        if (n[0], n[2]) not in seen:
            seen.add((n[0], n[2])); uniq.append({"kind": n[0], "id": n[1], "text": n[2]})
    return {"query": build(cmds), "notes": uniq,
            "suggestions": [{k: v for k, v in s.items() if k != "apply"} for s in sugg], "base": cmds[0]}


# ---------------------------------------------------------------- بررسی فیلدها (روی Splunk؛ فقط هنگام تنظیم کوئری)
PROBE_EVENTS = 5000


def fields_probe_query(query):
    """کوئری کوچک برای فهرست فیلدهای موجود در رخدادهای جستجوی پایه. (کوئری، فیلدهای لازم، جستجوی پایه)"""
    r = optimize(query, accept=[])
    cmds = [squash(c) for c in split_pipes(r["query"])]
    base = cmds[0]
    if not base:
        return "", [], ""
    need, _ = referenced_fields(cmds)
    need = list(dict.fromkeys(base_fields(base) + (need or [])))
    return f"search {base}\n| head {PROBE_EVENTS}\n| fieldsummary\n| fields field count", need, base


def index_only(base):
    """فقط index/sourcetype/source/host از جستجوی پایه (وقتی خود جستجوی پایه رخدادی نمی‌دهد)."""
    parts = re.findall(r'(?<![\w.])(?:index|sourcetype|source|host)\s*=\s*(?:"[^"]*"|\S+)', base, re.I)
    return " ".join(parts) or base


def compare_fields(need, present):
    """فیلدهای لازمِ ناموجود + نزدیک‌ترین نام‌های موجود (مثلاً category ← alert.category)."""
    present = [p for p in present if p]
    low = {p.lower(): p for p in present}
    out = []
    for f in need:
        if f.startswith("_") or f.lower() in low:
            continue
        fl = f.lower()
        cands = [p for p in present if p.lower().endswith("." + fl)]
        cands += [p for p in present if p.lower() in (fl + "_ip", fl + "ip", fl + "_port") and p not in cands]
        cands += [p for p in difflib.get_close_matches(f, present, n=3, cutoff=0.75) if p not in cands]
        out.append({"field": f, "similar": cands[:3]})
    return out
