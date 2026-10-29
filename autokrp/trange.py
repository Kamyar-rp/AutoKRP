"""بازه‌ی زمانی نمودارهای مانیتورینگ: بازه‌ی آماده («24h») یا دلخواه ({"from": ts, "to": ts}).

دقت نمودار (step) از روی طول بازه انتخاب می‌شود تا حدود ۳۰۰ نقطه باشد؛ کمترین step به داده‌ی موجود بستگی دارد
(از 1.23.1 همه‌ی داده‌ها بدون محدودیت نگه داشته می‌شوند مگر ادمین سقف بگذارد).
"""
import math
import time

PRESETS = {"15m": 900, "1h": 3600, "6h": 6 * 3600, "12h": 12 * 3600, "24h": 86400, "7d": 7 * 86400,
           "30d": 30 * 86400, "90d": 90 * 86400, "365d": 365 * 86400,
           "730d": 730 * 86400}
STEPS = (60, 120, 300, 600, 900, 1800, 3600, 7200, 3 * 3600, 6 * 3600, 12 * 3600, 86400, 2 * 86400, 7 * 86400,
         14 * 86400, 30 * 86400)
TARGET_POINTS = 300
MIN_FROM = 946684800            # 2000-01-01؛ داده‌ها بدون محدودیت نگه داشته می‌شوند (1.23.1)
MIN_SPAN = 60
MAX_BINS = 2000


def resolve(rng, now=None):
    """(since, until) — خطای ValueError برای ورودی نامعتبر."""
    now = time.time() if now is None else now
    if isinstance(rng, dict):
        try:
            a, b = float(rng.get("from")), float(rng.get("to"))
        except (TypeError, ValueError):
            raise ValueError("بازه‌ی زمانی نامعتبر است.") from None
        if not (math.isfinite(a) and math.isfinite(b)):
            raise ValueError("بازه‌ی زمانی نامعتبر است.")
        a, b = max(a, MIN_FROM), min(b, now)
        if b - a < MIN_SPAN:
            raise ValueError("شروع بازه باید دست‌کم یک دقیقه پیش از پایان آن و در گذشته باشد.")
        return a, b
    span = PRESETS.get(str(rng))
    if not span:
        raise ValueError("بازه‌ی زمانی نامعتبر است.")
    return now - span, now


def pick_step(span, min_step):
    for s in STEPS:
        if s >= min_step and span / s <= TARGET_POINTS:
            return s
    return STEPS[-1]


def grid(since, until, step):
    """(start, nb): شروع خانه‌ی اول و تعداد خانه‌ها. خانه‌های روزانه و بیشتر از نیمه‌شب محلی شروع می‌شوند."""
    if step >= 86400:
        off = time.localtime(since).tm_gmtoff
        start = int((since + off) // step) * step - off
    else:
        start = int(since // step) * step
    nb = min(MAX_BINS, int((until - start) // step) + 1)
    return start, nb


def label(since, until):
    f = "%Y%m%d-%H%M"
    return f"{time.strftime(f, time.localtime(since))}_{time.strftime(f, time.localtime(until))}"


def days(since, until, fmt):
    """نام‌های یکتای فایل روزانه/ماهانه (fmt = %Y%m%d یا %Y%m) که بازه را می‌پوشانند."""
    out, x = [], int(since)
    while x <= until + 86400:
        k = time.strftime(fmt, time.localtime(x))
        if k not in out:
            out.append(k)
        x += 86400
    return out
