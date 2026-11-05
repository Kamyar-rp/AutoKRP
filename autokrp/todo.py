"""1.47: «کارهای من» — چک‌لیست کارهای تکراری (روزانه، هفتگی، ماهانه، یک‌بار).

- هر کار مال یک کاربر است (owner = نام کاربر در حالت سرور؛ خالی در حالت کلاینت). اشتراک بین کاربران در 1.49.
- «روزانه» یعنی روزهای کاری شرکت (تنظیم todo.workdays، انتخاب ادمین؛ شماره‌ی روز مثل Python: دوشنبه=۰ … یکشنبه=۶).
- ماهانه بر اساس تقویمی که کار با آن ساخته شده (شمسی یا میلادی)؛ روزی که ماه ندارد (۳۱ مهر، ۳۰ اسفند) ← آخرین روز همان ماه.
- تیک هر نوبت یک ردیف todo_marks (due = تاریخ میلادی نوبت، done یا skip). نوبتی که گذشته و ردیفی ندارد «جا مانده» است
  و تا تیک یا «رد کردن» می‌ماند (حداکثر LOOKBACK روز به عقب).
- همه‌ی محاسبه در همین ماژول و بدون وابستگی به رابط؛ تاریخ‌ها به وقت محلی همین کامپیوتر یا سرور.
"""
import json
import re
from datetime import date, datetime, timedelta

from .stats import g2j

TYPES = ("daily", "weekly", "monthly", "once")
DEFAULT_WORKDAYS = [5, 6, 0, 1, 2, 3]          # شنبه تا پنجشنبه
LOOKBACK = 60                                   # جا مانده‌ها حداکثر این چند روز به عقب
ITEM_MAX = 300
_DAY = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_TIME = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")
_EMAIL = re.compile(r"^[^@\s,;<>]+@[^@\s,;<>]+\.[^@\s,;<>]+$")


class TodoError(Exception):
    pass


def pday(s):
    """«2026-11-05» ← date؛ نامعتبر ← None."""
    if not isinstance(s, str) or not _DAY.match(s):
        return None
    try:
        return date.fromisoformat(s)
    except ValueError:
        return None


def _ctl(s, n):
    return re.sub(r"[\x00-\x1f\x7f]", " ", str(s or "")).strip()[:n]


def clean_workdays(v):
    try:
        out = sorted({int(x) for x in (v or []) if 0 <= int(x) <= 6})
    except (TypeError, ValueError):
        out = []
    return out or list(DEFAULT_WORKDAYS)


def clean_item(p, today=None):
    """داده‌ی فرم ← کار معتبر (یا TodoError با پیام فارسی)."""
    p = p if isinstance(p, dict) else {}
    today = today or date.today()
    title = _ctl(p.get("title"), 120)
    if not title:
        raise TodoError("عنوان کار را وارد کنید.")
    r = p.get("rule") if isinstance(p.get("rule"), dict) else {}
    t = r.get("type") if r.get("type") in TYPES else "daily"
    rule = {"type": t, "cal": "g" if r.get("cal") == "g" else "j"}
    if t == "weekly":
        rule["days"] = clean_workdays(r.get("days")) if r.get("days") else []
        if not rule["days"]:
            raise TodoError("دست‌کم یک روز هفته را انتخاب کنید.")
    elif t == "monthly":
        try:
            d = int(r.get("day"))
        except (TypeError, ValueError):
            d = -1
        if not 0 <= d <= 31:
            raise TodoError("روز ماه باید بین ۱ و ۳۱ (یا «آخرین روز») باشد.")
        rule["day"] = d                            # ۰ = آخرین روز ماه
    elif t == "once":
        d = pday(r.get("date"))
        if not d:
            raise TodoError("تاریخ کار یک‌باره معتبر نیست.")
        rule["date"] = d.isoformat()
    start = pday(p.get("start")) or today
    tm = str(p.get("time") or "").strip()
    if tm and not _TIME.match(tm):
        raise TodoError("ساعت یادآوری را به شکل 09:30 بنویسید.")
    email = bool(p.get("email"))
    to = [x.strip() for x in re.split(r"[,;\s]+", str(p.get("email_to") or "")) if x.strip()][:5]
    for x in to:
        if not _EMAIL.match(x):
            raise TodoError(f"نشانی ایمیل معتبر نیست: {x[:60]}")
    if email and not tm:
        tm = "09:00"                               # ایمیل یادآوری بدون ساعت ← اول وقت
    sh = p.get("share") if isinstance(p.get("share"), dict) else {}
    mode = sh.get("mode") if sh.get("mode") in ("one", "each") else ""
    share = {"mode": mode, "users": sorted({_ctl(u, 64).lower() for u in (sh.get("users") or [])[:200] if _ctl(u, 64)})} if mode else {}
    return {"title": title, "note": _ctl(p.get("note"), 500), "rule": rule, "start": start.isoformat(), "time": tm,
            "email": email, "email_to": ",".join(to), "active": p.get("active") is not False, "share": share}


def _month_info(d, cal):
    """(روز ماه، آخرین روز ماه است؟) در تقویم کار."""
    n = d + timedelta(days=1)
    if cal == "g":
        return d.day, n.day == 1
    return g2j(d.year, d.month, d.day)[2], g2j(n.year, n.month, n.day)[2] == 1


def occurs(item, d, workdays):
    """آیا این کار در روز d نوبت دارد؟"""
    r = item["rule"]
    if d < (pday(item.get("start")) or d):
        return False
    t = r.get("type")
    if t == "daily":
        return d.weekday() in workdays
    if t == "weekly":
        return d.weekday() in (r.get("days") or [])
    if t == "monthly":
        md, last = _month_info(d, r.get("cal"))
        want = int(r.get("day") or 0)
        return (want == 0 and last) or md == want or (last and want > md)
    if t == "once":
        return d.isoformat() == r.get("date")
    return False


def occurrences(item, a, b, workdays):
    out, d = [], a
    while d <= b:
        if occurs(item, d, workdays):
            out.append(d)
        d += timedelta(days=1)
    return out


def next_due(item, after, workdays, horizon=400):
    """اولین نوبت از روز after به بعد (خود after هم) یا None."""
    d = after
    for _ in range(horizon):
        if occurs(item, d, workdays):
            return d
        d += timedelta(days=1)
    return None


def mkey(it, iso, me=""):
    """کلید ثبت تیک: «هر نفر جدا» ← تاریخ@کاربر؛ بقیه ← فقط تاریخ (تیک یک نفر برای همه)."""
    return f"{iso}@{me}" if (it.get("share") or {}).get("mode") == "each" else iso


def visible(it, me):
    """1.49: کار چک‌لیست برای این کاربر دیده می‌شود؟ (مال خودش، یا مشترک با همه یا با او)."""
    if (it.get("owner") or "") == me:
        return True
    sh = it.get("share") or {}
    return sh.get("mode") in ("one", "each") and (not sh.get("users") or me in sh["users"])


def view(items, marks, workdays, today=None, now=None, me=""):
    """صفحه‌ی «امروز»: today (کارهای امروز با وضعیت)، late (جا مانده‌ها، هر کار یک ردیف با همه‌ی نوبت‌های جامانده)،
    upcoming (نوبت‌های بعدی)، defs (فهرست کارها با نوبت بعد و آمار ۳۰ روز)، badge."""
    today = today or date.today()
    now = now or datetime.now()
    mk = {}
    for m in marks:
        mk[(m["item_id"], m["due"])] = m
    out_today, late, upcoming, defs = [], [], [], []
    for it in items:
        iid = it["id"]
        created = datetime.fromtimestamp(float(it.get("created") or 0)).date() if it.get("created") else today
        first = max(pday(it["start"]) or today, created, today - timedelta(days=LOOKBACK))
        K = lambda d, i=iid, x=it: (i, mkey(x, d.isoformat(), me))
        if it.get("active"):
            if occurs(it, today, workdays):
                m = mk.get(K(today))
                out_today.append({"id": iid, "due": today.isoformat(), "status": m["status"] if m else "", "by": (m or {}).get("user") or "",
                                  "at": (m or {}).get("at"), "mnote": (m or {}).get("note") or "",
                                  "remind": bool(it.get("time")) and not m and now.strftime("%H:%M") >= it["time"]})
            miss = [d.isoformat() for d in occurrences(it, first, today - timedelta(days=1), workdays) if K(d) not in mk]
            if miss:
                late.append({"id": iid, "dues": miss})
            nd = next_due(it, today + timedelta(days=1), workdays)
            if nd:
                upcoming.append({"id": iid, "due": nd.isoformat()})
        a30 = max(pday(it["start"]) or today, created, today - timedelta(days=29))
        occ = occurrences(it, a30, today, workdays)
        done = sum(1 for d in occ if (mk.get(K(d)) or {}).get("status") == "done")
        nxt = next_due(it, today, workdays) if it.get("active") else None
        defs.append({"id": iid, "next": nxt.isoformat() if nxt else "", "n30": len(occ) - (0 if K(today) in mk else
                     (1 if occ and occ[-1] == today else 0)), "done30": done})
    upcoming.sort(key=lambda x: x["due"])
    left = sum(1 for x in out_today if not x["status"])
    return {"today": today.isoformat(), "items_today": out_today, "late": late, "upcoming": upcoming[:12], "defs": defs,
            "badge": left + len(late)}


def item_row(r):
    """ردیف پایگاه داده ← دیکشنری کار."""
    d = dict(r)
    try:
        d["rule"] = json.loads(d.get("rule") or "{}")
    except ValueError:
        d["rule"] = {"type": "daily"}
    d["email"] = bool(d.get("email"))
    d["active"] = bool(d.get("active"))
    try:
        d["share"] = json.loads(d.get("share") or "{}") or {}
    except ValueError:
        d["share"] = {}
    return d


def email_due(store, workdays, now=None):
    """کارهای ساعت‌دار با «ایمیل هم» که نوبت امروزشان رسیده، تیک نخورده و ایمیلشان هنوز فرستاده نشده:
    [(کار، تاریخ)]. ثبت در todo_rem همین‌جا (هر نوبت حداکثر یک ایمیل، حتی اگر ارسال خطا بدهد)."""
    now = now or datetime.now()
    today = now.date().isoformat()
    hm = now.strftime("%H:%M")
    items = [item_row(r) for r in store.todo_items()]
    cand = [it for it in items if it["active"] and it["email"] and it.get("time") and hm >= it["time"] and occurs(it, now.date(), workdays)]
    if not cand:
        return []
    marked = {(m["item_id"], m["due"]) for m in store.todo_marks([x["id"] for x in cand], today)}
    return [(it, today) for it in cand if (it["id"], today) not in marked and store.todo_rem_add(it["id"], today)]


# ================================================================ 1.48: To-do (کار یک‌باره با سررسید)
TASK_MAX = 2000
DONE_KEEP_DAYS = 30            # انجام‌شده‌ها در فهرست تا این چند روز دیده می‌شوند (در پایگاه داده می‌مانند)


def clean_task(p):
    p = p if isinstance(p, dict) else {}
    title = _ctl(p.get("title"), 200)
    if not title:
        raise TodoError("عنوان کار را وارد کنید.")
    due = ""
    if p.get("due"):
        d = pday(p.get("due"))
        if not d:
            raise TodoError("تاریخ سررسید معتبر نیست.")
        due = d.isoformat()
    tm = str(p.get("time") or "").strip()
    if tm and not _TIME.match(tm):
        raise TodoError("ساعت یادآوری را به شکل 09:30 بنویسید.")
    if tm and not due:
        raise TodoError("برای ساعت یادآوری، تاریخ سررسید هم لازم است.")
    to = [x.strip() for x in re.split(r"[,;\s]+", str(p.get("email_to") or "")) if x.strip()][:5]
    for x in to:
        if not _EMAIL.match(x):
            raise TodoError(f"نشانی ایمیل معتبر نیست: {x[:60]}")
    email = bool(p.get("email"))
    if email and not due:
        raise TodoError("برای ایمیل یادآوری، تاریخ سررسید لازم است.")
    try:
        prio = 1 if int(p.get("prio") or 0) else 0
    except (TypeError, ValueError):
        prio = 0
    note = re.sub(r"[\x00-\x09\x0b-\x1f\x7f]", " ", str(p.get("note") or "").replace("\r\n", "\n")).strip()[:1000]     # چندخطی مجاز
    return {"assignee": _ctl(p.get("assignee"), 64).lower(), "title": title, "note": note, "due": due, "time": tm, "prio": prio, "email": email, "email_to": ",".join(to)}


def task_row(r):
    d = dict(r)
    d["email"] = bool(d.get("email"))
    d["prio"] = int(d.get("prio") or 0)
    d["done"] = d.get("done_at") is not None
    return d


def task_remind(t, now):
    """یادآوری داخل برنامه: باز، سررسید امروز و ساعت رسیده (بدون ساعت ← از اول روز)."""
    return not t["done"] and t.get("due") == now.date().isoformat() and now.strftime("%H:%M") >= (t.get("time") or "00:00")


def task_badge(tasks, today):
    """باز و سررسید امروز یا گذشته."""
    ti = today.isoformat()
    return sum(1 for t in tasks if not t["done"] and t.get("due") and t["due"] <= ti)


def month(items, tasks, workdays, a, b):
    """کارهای هر روز بین a و b: {iso: {"t": [To-do باز]، "td": [انجام‌شده]، "c": [کارهای چک‌لیست با نوبت]}} (شناسه‌ها)."""
    out = {}
    for t in tasks:
        d = pday(t.get("due") or "")
        if d and a <= d <= b:
            out.setdefault(d.isoformat(), {"t": [], "td": [], "c": []})["td" if t["done"] else "t"].append(t["id"])
    for it in items:
        if not it.get("active"):
            continue
        for d in occurrences(it, a, b, workdays):
            out.setdefault(d.isoformat(), {"t": [], "td": [], "c": []})["c"].append(it["id"])
    return out


def task_email_due(store, now=None):
    """کارهای To-do با «ایمیل هم»، باز، سررسید امروز و ساعت رسیده (بدون ساعت ← ۰۹:۰۰)؛ هر کار یک بار (todo_rem با -id)."""
    now = now or datetime.now()
    today, hm = now.date().isoformat(), now.strftime("%H:%M")
    out = []
    for t in (task_row(r) for r in store.task_list(done_since=time_floor())):
        if t["email"] and not t["done"] and t.get("due") == today and hm >= (t.get("time") or "09:00") and store.todo_rem_add(-t["id"], today):
            out.append(t)
    return out


def time_floor():
    """done_since برای جست‌وجوهایی که فقط کارهای باز را لازم دارند (انجام‌شده‌ی قدیمی لازم نیست)."""
    return datetime.now().timestamp() + 1
