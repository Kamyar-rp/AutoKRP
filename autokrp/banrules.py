"""قاعده‌های مدت بلاک FortiGate (1.54).

هر قاعده: {"field", "op", "value", "days"}؛ از بالا بررسی می‌شوند و اولین قاعده‌ای که با IP جور باشد مدت را تعیین می‌کند
(days = ۰ یعنی دائم). اگر هیچ‌کدام جور نبود، مدت پیش‌فرض دستگاه (ban_days) به کار می‌رود.
اطلاعات IP از فهرست آدرس‌ها می‌آید؛ اگر فیلدی برای آن IP خالی باشد، قاعده‌ی آن فیلد جور نمی‌شود.
"""
import re

MAX_DAYS = 3650
MAX_RULES = 50
# field: (عملگرهای مجاز)
FIELDS = {
    "country": ("in", "not_in"),          # value: فهرست کد دوحرفی کشور
    "score": ("lt", "gte"),               # value: ۰ تا ۱۰۰ (امتیاز AbuseIPDB)
    "isp": ("contains", "not_contains"),  # value: متن
    "usage": ("contains", "not_contains"),
    "tor": ("is",),                       # value: True/False
    "source": ("is",),                    # value: یکی از SOURCES (چرا این IP برای بلاک آمده)
}
SOURCES = ("abuse", "intel", "manual")
_CC = re.compile(r"^[A-Z]{2}$")


class RuleError(ValueError):
    pass


def clean_days(v, what="مدت بلاک"):
    """روز (۰ = دائم). فقط عدد صحیح ۰ تا MAX_DAYS."""
    try:
        n = int(str(v if v not in (None, "") else 0).strip())
    except (TypeError, ValueError):
        raise RuleError(f"{what} باید عدد صحیح (روز) باشد.")
    if n < 0 or n > MAX_DAYS:
        raise RuleError(f"{what} باید بین ۰ (دائم) و {MAX_DAYS} روز باشد.")
    return n


def clean(rules):
    """اعتبارسنجی و یکدست‌سازی فهرست قاعده‌ها (برای ذخیره در تنظیمات)."""
    if rules in (None, ""):
        return []
    if not isinstance(rules, list):
        raise RuleError("قاعده‌های مدت بلاک نامعتبر است.")
    if len(rules) > MAX_RULES:
        raise RuleError(f"حداکثر {MAX_RULES} قاعده‌ی مدت بلاک.")
    out = []
    for i, r in enumerate(rules, 1):
        if not isinstance(r, dict):
            raise RuleError(f"قاعده‌ی {i} نامعتبر است.")
        field, op = str(r.get("field") or ""), str(r.get("op") or "")
        if field not in FIELDS or op not in FIELDS[field]:
            raise RuleError(f"قاعده‌ی {i}: شرط نامعتبر است.")
        v = r.get("value")
        if field == "country":
            if isinstance(v, str):
                v = re.split(r"[\s,\u060c]+", v)
            v = sorted({str(x).strip().upper() for x in (v or []) if str(x).strip()})
            if not v or any(not _CC.match(x) for x in v):
                raise RuleError(f"قاعده‌ی {i}: کد کشور باید دو حرف انگلیسی باشد (مثل IR).")
            if len(v) > 250:
                raise RuleError(f"قاعده‌ی {i}: تعداد کشورها زیاد است.")
        elif field == "score":
            try:
                v = int(v)
            except (TypeError, ValueError):
                raise RuleError(f"قاعده‌ی {i}: امتیاز باید عدد باشد.")
            if not 0 <= v <= 100:
                raise RuleError(f"قاعده‌ی {i}: امتیاز باید بین ۰ و ۱۰۰ باشد.")
        elif field in ("isp", "usage"):
            v = str(v or "").strip()[:100]
            if not v:
                raise RuleError(f"قاعده‌ی {i}: متن شرط خالی است.")
        elif field == "tor":
            v = bool(v) if not isinstance(v, str) else v.strip().lower() in ("1", "true", "yes")
        elif field == "source":
            v = str(v or "")
            if v not in SOURCES:
                raise RuleError(f"قاعده‌ی {i}: منبع نامعتبر است.")
        out.append({"field": field, "op": op, "value": v, "days": clean_days(r.get("days"), f"قاعده‌ی {i}: مدت بلاک")})
    return out


def _truthy(v):
    return str(v or "").strip().lower() in ("1", "true", "yes")


def matches(rule, rec, origin=""):
    """آیا این قاعده با ردیف IP (از فهرست آدرس‌ها؛ شاید خالی) جور است؟"""
    rec = rec or {}
    f, op, v = rule["field"], rule["op"], rule["value"]
    if f == "country":
        cc = str(rec.get("country_code") or "").strip().upper()
        if not cc:
            return False
        return (cc in v) if op == "in" else (cc not in v)
    if f == "score":
        s = rec.get("score")
        if s in (None, ""):
            return False
        try:
            s = int(s)
        except (TypeError, ValueError):
            return False
        return s < v if op == "lt" else s >= v
    if f in ("isp", "usage"):
        t = str(rec.get("isp" if f == "isp" else "usage_type") or "").strip().lower()
        if not t:
            return False
        hit = v.lower() in t
        return hit if op == "contains" else not hit
    if f == "tor":
        if rec.get("is_tor") in (None, ""):
            return False
        return _truthy(rec.get("is_tor")) == bool(v)
    if f == "source":
        return (origin or "manual") == v
    return False


def days_for(rules, rec, origin="", default=0):
    """(روز، شماره‌ی قاعده‌ی جورشده یا ۰ برای پیش‌فرض)."""
    for i, r in enumerate(rules or [], 1):
        try:
            if matches(r, rec, origin):
                return int(r["days"]), i
        except (KeyError, TypeError, ValueError):
            continue
    return int(default or 0), 0


def label(days):
    return "دائم" if not int(days or 0) else f"{int(days)} روز"
