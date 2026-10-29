"""
آمار عملکرد برای صفحه‌ی «آمار»: روند روزانه/ماهانه‌ی هر بخش، شاخص‌ها با مقایسه‌ی دوره‌ی قبل، و پرتکرارها.
منبع (1.22): جدول‌های خلاصه‌ی stat_day / stat_ip_day / stat_geo_day که هم‌زمان با هر رویداد به‌روز می‌شوند
(مثل trends در Zabbix)، به‌اضافه‌ی runs و daily_snapshot. رویدادهای خام فقط برای جزئیات نگه داشته می‌شوند.
"""
import time
from collections import Counter, defaultdict
from datetime import date, datetime, timedelta

JALALI_MONTHS = ["فروردین", "اردیبهشت", "خرداد", "تیر", "مرداد", "شهریور",
                 "مهر", "آبان", "آذر", "دی", "بهمن", "اسفند"]
RANGES = {"7d": ("day", 7), "30d": ("day", 30), "90d": ("day", 90), "12m": ("month", 12)}


def g2j(gy, gm, gd):
    """میلادی به شمسی (الگوریتم jalaali-js، معتبر برای سال‌های ۱۸۰۰ تا ۲۲۰۰ میلادی)."""
    g_d_m = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334]
    gy2 = gy + 1 if gm > 2 else gy
    days = 355666 + (365 * gy) + ((gy2 + 3) // 4) - ((gy2 + 99) // 100) + ((gy2 + 399) // 400) + gd + g_d_m[gm - 1]
    jy = -1595 + (33 * (days // 12053))
    days %= 12053
    jy += 4 * (days // 1461)
    days %= 1461
    if days > 365:
        jy += (days - 1) // 365
        days = (days - 1) % 365
    if days < 186:
        jm, jd = 1 + days // 31, 1 + days % 31
    else:
        jm, jd = 7 + (days - 186) // 30, 1 + (days - 186) % 30
    return jy, jm, jd


def day_key(d: date, gran, cal):
    if cal == "jalali":
        jy, jm, jd = g2j(d.year, d.month, d.day)
        return f"{jy}/{jm:02d}" if gran == "month" else f"{jy}/{jm:02d}/{jd:02d}"
    return d.strftime("%Y-%m") if gran == "month" else d.isoformat()


def key_label(key, gran, cal):
    if gran == "month":
        if cal == "jalali":
            y, m = key.split("/")
            return f"{JALALI_MONTHS[int(m) - 1]} {y}"
        return key
    return key[5:]  # MM-DD یا MM/DD


def build_buckets(range_key, cal, today=None):
    """(روزها از ابتدای دوره تا امروز، کلیدهای مرتب، نگاشت روز→کلید). ماه‌ها در هر تقویم کامل گرفته می‌شوند."""
    gran, n = RANGES.get(range_key, RANGES["30d"])
    today = today or date.today()
    if gran == "day":
        days = [today - timedelta(days=i) for i in range(n - 1, -1, -1)]
    else:
        pool = [today - timedelta(days=i) for i in range(400, -1, -1)]
        keys = list(dict.fromkeys(day_key(d, "month", cal) for d in pool))[-n:]
        keep = set(keys)
        days = [d for d in pool if day_key(d, "month", cal) in keep]
    mapping = {d: day_key(d, gran, cal) for d in days}
    keys = list(dict.fromkeys(mapping.values()))
    return gran, days, keys, mapping


def _ts(d: date):
    return time.mktime(datetime(d.year, d.month, d.day).timetuple())


def _kpis(events, runs):
    ab = [e for e in events if e["kind"] == "abuse"]
    ips = {e["ip"] for e in ab}
    mal = {e["ip"] for e in ab if e["sub"] == "ABUSE"}
    online = sum(1 for e in ab if e["src"] == "online")
    cache = sum(1 for e in ab if e["src"] == "cache")
    ban_ok = sum(1 for e in events if e["kind"] == "ban" and e["sub"] == "ok")
    ban_fail = sum(1 for e in events if e["kind"] == "ban" and e["sub"] == "failed")
    tickets = sum(1 for e in events if e["kind"] == "ticket" and e["sub"] == "ok")
    done = sum(1 for r in runs if r["status"] == "done")
    pct = lambda a, b: round(100.0 * a / b, 1) if b else None
    return {"checked": len(ips), "malicious": len(mal), "malicious_pct": pct(len(mal), len(ips)),
            "banned": ban_ok, "ban_failed": ban_fail, "ban_fail_pct": pct(ban_fail, ban_ok + ban_fail),
            "online": online, "cache": cache, "cache_pct": pct(cache, online + cache),
            "tickets": tickets, "runs": len(runs), "run_success_pct": pct(done, len(runs))}


def compute_raw(store, range_key="30d", cal="jalali"):
    """روش قبلی (پیش از 1.22) از رویدادهای خام؛ فقط برای تست هم‌ارزی با compute نگه داشته شده است."""
    gran, days, keys, mapping = build_buckets(range_key, cal)
    since, until = _ts(days[0]), _ts(days[-1] + timedelta(days=1))
    idx = {k: i for i, k in enumerate(keys)}
    n = len(keys)
    zero = lambda: [0] * n
    events = store.stat_events(since, until)
    runs = store.runs_between(since, until)

    qmemo = {}

    def bucket(ts):
        # ربع‌ساعت ← بازه (fromtimestamp برای هر رویداد روی ویندوز کند بود؛ ربع‌ساعت با هر منطقه‌ی زمانی درست است)
        q = int(ts // 900)
        b = qmemo.get(q, -1)
        if b == -1:
            b = qmemo[q] = idx.get(mapping.get(datetime.fromtimestamp(q * 900).date()))
        return b

    # AbuseIPDB: IP یکتا در هر بازه به تفکیک وضعیت (هر IP در هر بازه یک بار، با آخرین وضعیت)
    last = {}
    for e in events:
        if e["kind"] == "abuse":
            b = bucket(e["ts"])
            if b is not None:
                last[(b, e["ip"])] = e["sub"]
    abuse = {"ABUSE": zero(), "CLEAN": zero(), "ERROR": zero()}
    for (b, _ip), sub in last.items():
        if sub in abuse:
            abuse[sub][b] += 1
    source = {"online": zero(), "cache": zero(), "import": zero()}
    ban = {"ok": zero(), "failed": zero(), "test": zero()}
    ban_origin = {"abuse": zero(), "clean_foreign": zero(), "manual": zero(), "intel": zero()}
    ticket = {"ok": zero(), "test": zero()}
    countries, isps = Counter(), Counter()
    for e in events:
        b = bucket(e["ts"])
        if b is None:
            continue
        if e["kind"] == "abuse":
            source["online" if e["src"] == "online" else "cache" if e["src"] == "cache" else "import"][b] += 1
            if e["sub"] == "ABUSE":
                if e["cc"] and e["cc"] != "-":
                    countries[e["cc"]] += 1
                if e["isp"] and e["isp"] not in ("-", "ERROR"):
                    isps[e["isp"]] += 1
        elif e["kind"] == "ban" and e["sub"] in ban:
            ban[e["sub"]][b] += 1
            if e["sub"] == "ok" and e["src"] in ban_origin:
                ban_origin[e["src"]][b] += 1
        elif e["kind"] == "ticket" and e["sub"] in ticket:
            ticket[e["sub"]][b] += 1
    run_s = {"done": zero(), "failed": zero(), "cancelled": zero()}
    for r in runs:
        b = bucket(r["started"])
        if b is not None and r["status"] in run_s:
            run_s[r["status"]][b] += 1

    # روند جامانده/بررسی دستی: آخرین عکس هر بازه
    snap = {"fw_pending": [None] * n, "review_pending": [None] * n}
    for s in store.snapshots(days[0].isoformat()):
        try:
            d = date.fromisoformat(s["day"])
        except ValueError:
            continue
        b = idx.get(mapping.get(d))
        if b is not None:
            snap["fw_pending"][b] = s["fw_pending"]
            snap["review_pending"][b] = s["review_pending"]

    # دوره‌ی قبل با همان طول برای مقایسه
    span = until - since
    prev = _kpis(store.stat_events(since - span, since), store.runs_between(since - span, since))
    cur = _kpis(events, runs)
    first = store.first_stat_event(until)
    return {
        "range": range_key, "gran": gran, "calendar": cal,
        "keys": keys, "labels": [key_label(k, gran, cal) for k in keys],
        "period": [day_key(days[0], "day", cal), day_key(days[-1], "day", cal)],
        "series": {"abuse": abuse, "source": source, "ban": ban, "ban_origin": ban_origin,
                   "ticket": ticket, "runs": run_s, "snapshot": snap},
        "kpi": cur, "prev": prev,
        "top_countries": countries.most_common(10), "top_isps": isps.most_common(10),
        "has_data": bool(events or runs),
        "first_event": day_key(datetime.fromtimestamp(first[0]["ts"]).date(), "day", cal) if first else None,
    }


def _kpi_out(k, runs):
    done = sum(1 for r in runs if r["status"] == "done")
    pct = lambda a, b: round(100.0 * a / b, 1) if b else None
    return {"checked": k["checked"], "malicious": k["malicious"], "malicious_pct": pct(k["malicious"], k["checked"]),
            "banned": k["ban_ok"], "ban_failed": k["ban_fail"], "ban_fail_pct": pct(k["ban_fail"], k["ban_ok"] + k["ban_fail"]),
            "online": k["online"], "cache": k["cache"], "cache_pct": pct(k["cache"], k["online"] + k["cache"]),
            "tickets": k["tickets"], "runs": len(runs), "run_success_pct": pct(done, len(runs))}


def compute(store, range_key="30d", cal="jalali"):
    """همان خروجی compute_raw، از جدول‌های خلاصه (چند هزار ردیف به‌جای همه‌ی رویدادها)."""
    gran, days, keys, mapping = build_buckets(range_key, cal)
    since, until = _ts(days[0]), _ts(days[-1] + timedelta(days=1))
    idx = {k: i for i, k in enumerate(keys)}
    n = len(keys)
    zero = lambda: [0] * n
    day_b = {d.isoformat(): idx[mapping[d]] for d in days}
    span_days = (days[-1] - days[0]).days + 1
    p_last = days[0] - timedelta(days=1)
    p_first = p_last - timedelta(days=span_days - 1)
    R = store.stats_rollup(day_b, (days[0].isoformat(), days[-1].isoformat()), (p_first.isoformat(), p_last.isoformat()))
    abuse = {"ABUSE": zero(), "CLEAN": zero(), "ERROR": zero()}
    for b, sub, cnt in R["abuse"]:
        if sub in abuse:
            abuse[sub][b] += cnt
    source = {"online": zero(), "cache": zero(), "import": zero()}
    ban = {"ok": zero(), "failed": zero(), "test": zero()}
    ban_origin = {"abuse": zero(), "clean_foreign": zero(), "manual": zero(), "intel": zero()}
    ticket = {"ok": zero(), "test": zero()}
    for b, kind, sub, src, cnt in R["daily"]:
        if kind == "abuse":
            source["online" if src == "online" else "cache" if src == "cache" else "import"][b] += cnt
        elif kind == "ban" and sub in ban:
            ban[sub][b] += cnt
            if sub == "ok" and src in ban_origin:
                ban_origin[src][b] += cnt
        elif kind == "ticket" and sub in ticket:
            ticket[sub][b] += cnt
    runs = store.runs_between(since, until)
    run_s = {"done": zero(), "failed": zero(), "cancelled": zero()}
    for r in runs:
        d = datetime.fromtimestamp(r["started"]).date()
        b = idx.get(mapping.get(d))
        if b is not None and r["status"] in run_s:
            run_s[r["status"]][b] += 1
    snap = {"fw_pending": [None] * n, "review_pending": [None] * n}
    for s_ in store.snapshots(days[0].isoformat()):
        try:
            d = date.fromisoformat(s_["day"])
        except ValueError:
            continue
        b = idx.get(mapping.get(d))
        if b is not None:
            snap["fw_pending"][b] = s_["fw_pending"]
            snap["review_pending"][b] = s_["review_pending"]
    span = until - since
    prev_runs = store.runs_between(since - span, since)
    has = any(cnt for _, _, cnt in R["abuse"]) or any(r[4] for r in R["daily"]) or bool(runs)
    return {
        "range": range_key, "gran": gran, "calendar": cal,
        "keys": keys, "labels": [key_label(k, gran, cal) for k in keys],
        "period": [day_key(days[0], "day", cal), day_key(days[-1], "day", cal)],
        "series": {"abuse": abuse, "source": source, "ban": ban, "ban_origin": ban_origin,
                   "ticket": ticket, "runs": run_s, "snapshot": snap},
        "kpi": _kpi_out(R["kpi"], runs), "prev": _kpi_out(R["prev"], prev_runs),
        "top_countries": [list(x) for x in R["geo"]["cc"]], "top_isps": [list(x) for x in R["geo"]["isp"]],
        "has_data": has,
        "first_event": day_key(date.fromisoformat(R["first"]), "day", cal) if R["first"] else None,
    }
