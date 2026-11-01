#!/usr/bin/env python3
"""
استخراج همه‌ی متن‌های فارسی قابل نمایش از ui/app.js، ui/index.html و ماژول‌های Python.
خروجی: dev/i18n_strings.json  — فهرست الگوها؛ ‌{0} {1} ... جای مقادیر متغیر است.
الگوها همان شکلی را دارند که در DOM به صورت یک text node (یا مقدار title/placeholder) دیده می‌شوند.
"""
import ast
import json
import re
import sys
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FA = re.compile(r"[\u0600-\u06FF]")
TAG = re.compile(r"<[^<>]*>")
ATTR = re.compile(r'\b(?:title|placeholder|aria-label|alt|data-title)="([^"]*)"')
# توابعی که HTML برمی‌گردانند؛ جای آن‌ها در متن، text node را می‌شکند
HTMLISH = re.compile(r"`|<|Html\(|Tag\(|\b(?:inp|sw|secretInp|pairsEditor|connSection|card|hbars|recTable|segHtml|csvPicker|"
                     r"brandingSection|pwFields|envHelp|resetHtml|logoHtml|deltaHtml|scoreHtml|statusTag|originTag|pwRulesHtml|"
                     r"connChip|cell|kv|devRow|sshTypeSelect|resultRow|policyHint)\(")


# ------------------------------------------------------------------ JS tokenizer
def js_strings(src):
    """(نوع، بخش‌ها) برای هر رشته؛ بخش‌ها برای template: [('s', متن) | ('e', عبارت)]"""
    out, i, n = [], 0, len(src)
    prev = ""

    def read_quoted(i, q):
        j, buf = i + 1, []
        while j < n and src[j] != q:
            if src[j] == "\\":
                buf.append(src[j:j + 2])
                j += 2
                continue
            buf.append(src[j])
            j += 1
        return j + 1, "".join(buf)

    def read_template(i):
        """از ` تا ` متناظر؛ عبارت‌های ${} به صورت بازگشتی."""
        j, parts, buf = i + 1, [], []
        while j < n:
            c = src[j]
            if c == "\\":
                buf.append(src[j:j + 2])
                j += 2
                continue
            if c == "`":
                if buf:
                    parts.append(("s", "".join(buf)))
                return j + 1, parts
            if c == "$" and j + 1 < n and src[j + 1] == "{":
                if buf:
                    parts.append(("s", "".join(buf)))
                    buf = []
                j, expr = read_expr(j + 2)
                parts.append(("e", expr))
                continue
            buf.append(c)
            j += 1
        return j, parts

    def skip_regex(j):
        cls = False
        j += 1
        while j < n:
            if src[j] == "\\":
                j += 2
                continue
            if src[j] == "[":
                cls = True
            elif src[j] == "]":
                cls = False
            elif src[j] == "/" and not cls:
                return j + 1
            elif src[j] == "\n":
                return j
            j += 1
        return j

    def read_expr(j):
        depth, start, pv = 1, j, "("
        while j < n:
            c = src[j]
            if c == "/" and pv in "(,=:[!&|?{};+-*%<>~^":
                j = skip_regex(j)
                pv = "x"
                continue
            if not c.isspace():
                pv = c if not (c.isalnum() or c in "_$") else "x"
            if c in "'\"":
                j, s = read_quoted(j, c)
                out.append(("str", [("s", s)]))
                continue
            if c == "`":
                j, parts = read_template(j)
                out.append(("tpl", parts))
                continue
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    return j + 1, src[start:j]
            j += 1
        return j, src[start:j]

    while i < n:
        c = src[i]
        if src.startswith("//", i):
            i = src.find("\n", i)
            i = n if i < 0 else i
            continue
        if src.startswith("/*", i):
            i = src.find("*/", i) + 2
            continue
        if c in "'\"":
            i, s = read_quoted(i, c)
            out.append(("str", [("s", s)]))
            prev = "x"
            continue
        if c == "`":
            i, parts = read_template(i)
            out.append(("tpl", parts))
            prev = "x"
            continue
        if c == "/" and (prev in "(,=:[!&|?{};+-*%<>~^" or prev == ""):
            # regex literal
            j = i + 1
            cls = False
            while j < n:
                if src[j] == "\\":
                    j += 2
                    continue
                if src[j] == "[":
                    cls = True
                elif src[j] == "]":
                    cls = False
                elif src[j] == "/" and not cls:
                    break
                elif src[j] == "\n":
                    break
                j += 1
            i = j + 1
            prev = "x"
            continue
        if not c.isspace():
            prev = c if not (c.isalnum() or c in "_$") else "x"
            # «return /re/» نادر است؛ نادیده
        i += 1
    return out


def unescape(s):
    return s.replace("\\n", "\n").replace("\\'", "'").replace('\\"', '"').replace("\\\\", "\\").replace("\\u200f", "\u200f").replace("\\u2066", "").replace("\\u2069", "")


def segments_from_parts(parts):
    """اسکلت template را به تکه‌هایی که در DOM یک text node می‌شوند تبدیل می‌کند."""
    skel, k = [], 0
    for kind, v in parts:
        if kind == "s":
            skel.append(unescape(v))
        elif HTMLISH.search(v):
            skel.append("\x00")  # شکستن
        else:
            skel.append("{%d}" % k)
            k += 1
    text = "".join(skel)
    segs = []
    for m in ATTR.finditer(text):
        segs.append(m.group(1))
    for piece in re.split(TAG.pattern + "|\x00", text):
        segs.append(piece)
    res = []
    for sgm in segs:
        sgm = sgm.strip()
        if sgm and FA.search(sgm):
            res.append(renumber(sgm))
    return res


def renumber(s):
    """شماره‌ی placeholderها از ۰ پشت سر هم."""
    idx = {}

    def rep(m):
        idx.setdefault(m.group(0), len(idx))
        return "{%d}" % idx[m.group(0)]
    return re.sub(r"\{\d+\}", rep, s)


# ------------------------------------------------------------------ Python
def py_strings(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    docs = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.ClassDef, ast.AsyncFunctionDef)):
            if node.body and isinstance(node.body[0], ast.Expr) and isinstance(getattr(node.body[0], "value", None), ast.Constant):
                docs.add(id(node.body[0].value))
    inner = {id(v) for node in ast.walk(tree) if isinstance(node, ast.JoinedStr) for v in node.values}
    res = []
    for node in ast.walk(tree):
        if isinstance(node, ast.JoinedStr):
            k, skel = 0, []
            for v in node.values:
                if isinstance(v, ast.Constant):
                    skel.append(str(v.value))
                else:
                    skel.append("{%d}" % k)
                    k += 1
            t = "".join(skel).strip()
            if FA.search(t):
                res.append(t)
        elif isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in docs and id(node) not in inner:
            if FA.search(node.value):
                res.append(node.value.strip())
    # قسمت‌های ثابت داخل JoinedStr هم جدا به صورت Constant ظاهر می‌شوند؛ آن‌ها را نگه نمی‌داریم
    return res


class H(HTMLParser):
    def __init__(self):
        super().__init__()
        self.out = []
        self.skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self.skip += 1
        for k, v in attrs:
            if k in ("title", "placeholder", "aria-label", "alt") and v and FA.search(v):
                self.out.append(v.strip())

    def handle_endtag(self, tag):
        if tag in ("script", "style"):
            self.skip -= 1

    def handle_data(self, d):
        if not self.skip and FA.search(d):
            self.out.append(d.strip())


def main():
    items = {}

    def add(s, src):
        s = re.sub(r"[ \t]+", " ", s).strip()
        if re.search(r"[;=]\s*\w+\.\w+\(|\?\?|=>|\bapi\(|\bconst |\bfunction |\breturn ", s):   # تکه کد، نه متن
            return
        if s and FA.search(s):
            items.setdefault(s, set()).add(src)

    for kind, parts in (x for f in ("app.js", "trange.js", "keys.js", "noc.js", "monevents.js", "sshlive.js", "monitor.js", "snmp.js", "assets.js", "offline.js", "dbui.js", "nettools.js", "access.js", "monview.js", "netmap.js", "apitool.js") for x in js_strings((ROOT / "ui" / f).read_text(encoding="utf-8"))):
        if kind == "str":
            for sgm in segments_from_parts(parts):
                add(sgm, "js")
        else:
            for sgm in segments_from_parts(parts):
                add(sgm, "js")
    h = H()
    h.feed((ROOT / "ui" / "index.html").read_text(encoding="utf-8"))
    for s in h.out:
        add(s, "html")
    for p in sorted((ROOT / "autokrp").rglob("*.py")):
        for s in py_strings(p):
            add(s, "py:" + p.stem)
    # f-string: قسمت‌های Constant داخلی را که زیررشته‌ی یک الگوی کامل‌اند حذف نمی‌کنیم (ممکن است جدا هم استفاده شوند)
    data = [{"fa": k, "src": sorted(v)} for k, v in sorted(items.items())]
    out = ROOT / "dev" / "i18n_strings.json"
    out.write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
    print(len(data), "strings →", out)
    for src in ("js", "html"):
        print(src, sum(1 for d in data if src in d["src"]))
    print("py", sum(1 for d in data if any(x.startswith("py") for x in d["src"])))


if __name__ == "__main__":
    main()
