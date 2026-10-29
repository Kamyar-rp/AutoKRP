"""
قالب داده در اسکریپت SSH ابزارها.

  {% for src in src_ip %}            حلقه روی مقدارهای یک ستون ورودی (هر مقدار یک بار)
   permit tcp host 10.10.10.1 host {{src}} eq 443
  {% endfor %}
  {{src_ip|join:, }}                 همه‌ی مقدارها با جداکننده (پیش‌فرض: فاصله)
  {{src_ip|count}}  {{src_ip|first}}

خطی که فقط یک تگ {% ... %} دارد در خروجی حذف می‌شود. متغیرهای دستگاه با یک آکولاد ({host}، {name} ...)
بعداً جداگانه جایگزین می‌شوند و این‌جا دست نمی‌خورند.
"""
import re

MAX_VALUES = 500
MAX_OUTPUT = 300_000
_TOKEN = re.compile(r"(\{%.*?%\}|\{\{.*?\}\})", re.S)
_FOR = re.compile(r"^\{%\s*for\s+([A-Za-z_]\w*)\s+in\s+([A-Za-z_][\w.-]*)\s*%\}$")
_END = re.compile(r"^\{%\s*endfor\s*%\}$")
_VAR = re.compile(r"^\{\{\s*([A-Za-z_][\w.-]*)\s*(?:\|\s*(\w+)\s*(?::(.*))?)?\}\}$", re.S)
_TAG_LINE = re.compile(r"^[ \t]*(\{%.*?%\})[ \t]*(?:\r?\n|\Z)", re.M)


class TemplateError(Exception):
    pass


def _parse(body):
    # خطی که فقط یک تگ دارد: خود خط حذف می‌شود
    body = _TAG_LINE.sub(lambda m: m.group(1), body)
    root, stack = [], []
    cur = root
    for part in _TOKEN.split(body):
        if not part:
            continue
        if part.startswith("{%"):
            m = _FOR.match(part)
            if m:
                node = ("for", m.group(1), m.group(2), [])
                cur.append(node)
                stack.append(cur)
                cur = node[3]
                continue
            if _END.match(part):
                if not stack:
                    raise TemplateError("«{% endfor %}» بدون «{% for %}».")
                cur = stack.pop()
                continue
            raise TemplateError(f"تگ نامعتبر: {part}  (فقط for و endfor پشتیبانی می‌شود)")
        if part.startswith("{{"):
            m = _VAR.match(part)
            if not m:
                raise TemplateError(f"عبارت نامعتبر: {part}")
            cur.append(("var", m.group(1), (m.group(2) or "").lower(), m.group(3)))
            continue
        cur.append(("text", part))
    if stack:
        raise TemplateError("یک «{% for %}» بدون «{% endfor %}» مانده است.")
    return root


def used_lists(body):
    """نام متغیرهای فهرستی که قالب استفاده می‌کند (برای بررسی خالی بودن ورودی)."""
    out, loops = [], set()

    def walk(nodes):
        for n in nodes:
            if n[0] == "for":
                if n[2] not in loops and n[2] not in out:
                    out.append(n[2])
                loops.add(n[1])
                walk(n[3])
                loops.discard(n[1])
            elif n[0] == "var" and n[1] not in loops and n[1] not in out:
                out.append(n[1])
    walk(_parse(body or ""))
    return out


def render(body, lists):
    """lists: {نام: [مقدارها]}. خروجی: متن نهایی."""
    tree = _parse(body or "")
    out, size = [], [0]

    def val(name, scope):
        if name in scope:
            return scope[name]
        if name in lists:
            return lists[name]
        low = name.lower()
        for k, v in lists.items():
            if k.lower() == low:
                return v
        raise TemplateError(f"متغیر «{name}» در ورودی نیست. متغیرهای موجود: {', '.join(sorted(lists)) or '—'}")

    def emit(s):
        size[0] += len(s)
        if size[0] > MAX_OUTPUT:
            raise TemplateError("متن اسکریپت نهایی بیش از حد بزرگ شد.")
        out.append(s)

    def walk(nodes, scope):
        for n in nodes:
            if n[0] == "text":
                emit(n[1])
            elif n[0] == "var":
                v = val(n[1], scope)
                if isinstance(v, str):
                    if n[2] and n[2] not in ("first",):
                        raise TemplateError(f"فیلتر {n[2]} روی مقدار تکی «{n[1]}» معنا ندارد.")
                    emit(v)
                    continue
                f = n[2]
                if f in ("", "join"):
                    emit((n[3].replace("\\n", "\n").replace("\\t", "\t") if f == "join" and n[3] is not None else " ").join(v))
                elif f == "count":
                    emit(str(len(v)))
                elif f == "first":
                    emit(v[0] if v else "")
                else:
                    raise TemplateError(f"فیلتر ناشناخته «{f}»؛ مجاز: join، count، first")
            else:
                seq = val(n[2], scope)
                if isinstance(seq, str):
                    seq = [seq]
                for x in seq:
                    walk(n[3], {**scope, n[1]: x})
    walk(tree, {})
    return "".join(out)


# نام استاندارد ← نام‌های دیگری که از Splunk و ابزارها می‌آیند (اگر ستون استاندارد نبود)
ALIASES = {"src_ip": ["src", "ip"], "dest_ip": ["dest"], "signature": ["signatures", "attack_name"],
           "count": ["attack_count"], "first_time": ["firstTime"], "last_time": ["lastTime"],
           "url": ["http_url"], "domain": ["dest_host", "host", "query"]}


def add_aliases(lists):
    low = {k.lower(): k for k in lists}
    for std, alts in ALIASES.items():
        if std in low:
            continue
        for a in alts:
            if a.lower() in low:
                lists[std] = lists[low[a.lower()]]
                break
    return lists


def build_lists(columns, rows):
    """هر ستون جدول ورودی ← فهرست مقدارهای یکتا و غیرخالی به ترتیب دیده‌شدن."""
    lists = {}
    for c in columns:
        seen, vals = set(), []
        for r in rows:
            for x in str(r.get(c) or "").replace("\n", ",").split(","):
                x = x.strip()
                if x and x not in seen:
                    seen.add(x)
                    vals.append(x)
        lists[c] = vals
    return add_aliases(lists)
