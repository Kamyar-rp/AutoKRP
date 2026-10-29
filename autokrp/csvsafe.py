"""جلوگیری از CSV/Formula Injection در فایل‌هایی که کاربر با Excel باز می‌کند.

داده‌ی بیرونی (ISP و دامنه از AbuseIPDB، signature و URL از Splunk، دسته از فید، نام فایل‌ها) ممکن است با = + - @
شروع شود و Excel آن را فرمول اجرا کند (مثلاً HYPERLINK یا DDE). در خروجی‌ها چنین خانه‌ای با ' شروع می‌شود (روش OWASP).
فایل‌های داخلی برنامه (ورودی ابزار بعدی) دست نمی‌خورند؛ فقط آنچه از برنامه بیرون می‌رود.
"""
import csv
import io
import re

_DANGER = ("=", "+", "@", "\t", "\r", "＝", "＋", "＠")   # با شکل تمام‌عرض یونیکد
_NUM = re.compile(r"-?\d+(\.\d+)?([eE][-+]?\d+)?")


def cell(v):
    s = "" if v is None else str(v)
    if not s:
        return s
    if s[0] in _DANGER or (s[0] == "-" and len(s) > 1 and not _NUM.fullmatch(s)):
        return "'" + s
    return s


def unquote(s):
    """برعکس cell هنگام ورود دوباره‌ی فایل خروجی خود برنامه."""
    if isinstance(s, str) and len(s) > 1 and s[0] == "'" and (s[1] in _DANGER or s[1] == "-"):
        return s[1:]
    return s


def row(values):
    return [cell(v) for v in values]


def sanitize_bytes(data: bytes) -> bytes:
    """کل یک فایل CSV. اگر CSV خوانا نبود همان داده برمی‌گردد."""
    bom = data.startswith(b"\xef\xbb\xbf")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return data
    try:
        sample = text[:4096]
        delim = ";" if sample.count(";") > sample.count(",") else ","
        rows = list(csv.reader(io.StringIO(text, newline=""), delimiter=delim))
    except csv.Error:
        return data
    out = io.StringIO(newline="")
    w = csv.writer(out, delimiter=delim, lineterminator="\r\n")
    for r in rows:
        w.writerow(row(r))
    return (b"\xef\xbb\xbf" if bom else b"") + out.getvalue().encode("utf-8")
