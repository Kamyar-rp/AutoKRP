"""1.42: داشبوردهای ویجتی (شبیه OpManager و Zabbix) — صفحه‌ی مستقل «داشبوردها».
هر داشبورد چند صفحه دارد؛ هر صفحه شبکه‌ای ۱۲ ستونی از ویجت‌ها (x، y، w، h + تنظیمات هر ویجت). ذخیره در mon_layouts (kind="dash")؛
owner خالی = مشترک (ساخت و ویرایش با دسترسی «اجرا»ی مانیتورینگ)، وگرنه شخصی همان کاربر.
داده‌ی ویجت‌ها را رابط از همان APIهای موجود می‌گیرد (mon_list/mon_rows/series/report/events/map) با همان بررسی دسترسی."""
import re

DASH_MAX = 200
PAGE_MAX = 20
WIDGET_MAX = 60
COLS = 12
TYPES = ("status", "severity", "problems", "traffic", "metric", "gauge", "value", "topn", "avail", "map", "clock", "events", "text")
RANGES = ("1h", "6h", "24h", "7d", "30d")
_ID = re.compile(r"^[A-Za-z0-9_-]{1,24}$")


def _prim(v, depth=0):
    """تنظیمات ویجت: فقط مقدارهای ساده (رشته‌ی کوتاه، عدد، بولی، فهرست کوچک، دیکشنری کوچک)."""
    if isinstance(v, bool) or v is None:
        return v
    if isinstance(v, (int, float)):
        return v if abs(v) < 1e12 else 0
    if isinstance(v, str):
        return re.sub(r"[\x00-\x1f\x7f]", " ", v)[:300]
    if isinstance(v, list) and depth < 2:
        return [_prim(x, depth + 1) for x in v[:50]]
    if isinstance(v, dict) and depth < 2:
        return {str(k)[:40]: _prim(x, depth + 1) for k, x in list(v.items())[:40]}
    return None


def _int(v, lo, hi, d):
    try:
        return max(lo, min(hi, int(v)))
    except (TypeError, ValueError):
        return d


def clean(d):
    d = d if isinstance(d, dict) else {}
    pages = []
    for p in (d.get("pages") or [])[:PAGE_MAX]:
        if not isinstance(p, dict):
            continue
        pid = str(p.get("id") or "")
        if not _ID.match(pid) or any(x["id"] == pid for x in pages):
            continue
        ws = []
        for w in (p.get("widgets") or [])[:WIDGET_MAX]:
            if not isinstance(w, dict) or w.get("type") not in TYPES:
                continue
            wid = str(w.get("id") or "")
            if not _ID.match(wid) or any(x["id"] == wid for x in ws):
                continue
            ww = _int(w.get("w"), 1, COLS, 4)
            ws.append({"id": wid, "type": w["type"], "x": _int(w.get("x"), 0, COLS - ww, 0), "y": _int(w.get("y"), 0, 400, 0),
                       "w": ww, "h": _int(w.get("h"), 1, 24, 3), "title": re.sub(r"[\x00-\x1f\x7f]", " ", str(w.get("title") or ""))[:80],
                       "cfg": _prim(w.get("cfg") if isinstance(w.get("cfg"), dict) else {}) or {}})
        pages.append({"id": pid, "name": re.sub(r"[\x00-\x1f\x7f]", " ", str(p.get("name") or "")).strip()[:40] or "صفحه", "widgets": ws})
    if not pages:
        pages = [{"id": "p1", "name": "صفحه ۱", "widgets": []}]
    return {"pages": pages, "range": d.get("range") if d.get("range") in RANGES else "1h",
            "rotate": _int(d.get("rotate"), 0, 3600, 0), "refresh": _int(d.get("refresh"), 10, 600, 30)}
