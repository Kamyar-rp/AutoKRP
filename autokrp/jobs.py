"""
کارهای ذخیره‌شده: یک ترتیب ثابت از ابزارها (با همه‌ی ورودی‌ها، کوئری‌ها و فایل‌هایش) به‌علاوه‌ی زمان‌بندی.
اجرای زمان‌بندی‌شده همان Pipeline با trigger="schedule" و job_id است.
"""
import re
import time
import uuid
from datetime import datetime, timedelta

from .connectors import ConnectorError

DAYS = list(range(7))   # weekday() پایتون: دوشنبه=0 ... یکشنبه=6


def normalize(job, old=None):
    from .pipeline import TOOLS, Pipeline
    name = (job.get("name") or "").strip()
    if not name:
        raise ConnectorError("نام کار خالی است.")
    items = []
    for it in job.get("items") or []:
        if it.get("tool") not in TOOLS:
            raise ConnectorError(f"ابزار ناشناخته در کار: {it.get('tool')}")
        items.append({"tool": it["tool"], "opts": dict(it.get("opts") or {})})
    if not items:
        raise ConnectorError("کار هیچ ابزاری ندارد.")
    Pipeline.validate(items)
    sch = job.get("schedule") or {}
    typ = sch.get("type") if sch.get("type") in ("daily", "interval", "none") else "none"
    out = {"type": typ}
    if typ == "daily":
        tm = str(sch.get("time") or "08:00").strip()
        if not re.match(r"^\d{1,2}:\d{2}$", tm) or int(tm.split(":")[0]) > 23 or int(tm.split(":")[1]) > 59:
            raise ConnectorError("ساعت اجرا نامعتبر است.")
        out["time"] = tm
        days = sorted({int(d) for d in (sch.get("days") if sch.get("days") is not None else DAYS) if int(d) in DAYS})
        if not days:
            raise ConnectorError("حداقل یک روز هفته را انتخاب کنید.")
        out["days"] = days
    elif typ == "interval":
        try:
            out["every_minutes"] = int(sch.get("every_minutes") or 60)
        except (TypeError, ValueError):
            raise ConnectorError("فاصله‌ی اجرا باید عدد باشد.")
        if out["every_minutes"] < 5:
            raise ConnectorError("فاصله‌ی اجرا حداقل ۵ دقیقه است.")
    old = old or {}
    jid = str(job.get("id") or "") or uuid.uuid4().hex[:10]
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", jid):        # در نام فایل‌ها (jobfiles، مبنای اسکن) به کار می‌رود
        raise ConnectorError("شناسه‌ی کار نامعتبر است.")
    j = {"id": jid, "name": name, "items": items, "schedule": out,
         "enabled": bool(job.get("enabled")) and typ != "none",
         "auto_ban": bool(job.get("auto_ban")), "auto_ticket": bool(job.get("auto_ticket")), "auto_ssh": bool(job.get("auto_ssh")),
         "max_auto_ban": max(0, int(job.get("max_auto_ban") if job.get("max_auto_ban") not in (None, "") else 50)),
         "when_busy": "skip" if job.get("when_busy") == "skip" else "wait"}
    for k in ("last_at", "last_status", "last_message", "last_run"):
        if k in old:
            j[k] = old[k]
    # «اولین اجرا از همین لحظه»: روشن شدن یا تغییر زمان‌بندی، نوبت‌های گذشته را اجرا نمی‌کند
    same = old.get("enabled") and old.get("schedule") == out
    j["enabled_at"] = old.get("enabled_at", 0) if same else time.time()
    return j


def next_due(job, now=None):
    sch = job.get("schedule") or {}
    now = now or datetime.now()
    if not job.get("enabled") or sch.get("type") not in ("daily", "interval"):
        return None
    if sch["type"] == "interval":
        every = int(sch["every_minutes"]) * 60
        return (int(now.timestamp() // every) + 1) * every
    hh, mm = [int(x) for x in sch["time"].split(":")]
    for add in range(8):
        d = (now + timedelta(days=add)).replace(hour=hh, minute=mm, second=0, microsecond=0)
        if d > now and d.weekday() in sch.get("days", DAYS):
            return d.timestamp()
    return None


def run_options(job):
    return {"items": job["items"], "job_id": job["id"], "baseline_job": job["id"], "job_name": job["name"], "auto_ban": job.get("auto_ban"),
            "auto_ticket": job.get("auto_ticket"), "auto_ssh": job.get("auto_ssh"), "max_auto_ban": job.get("max_auto_ban", 50)}


def tick(worker, now, max_age):
    """هر ۲۰ ثانیه از Worker؛ فقط وقتی کلید اصلی کار خودکار روشن است."""
    st, pl = worker.store, worker.pipeline
    busy = bool(pl.current and pl.current.status in ("running", "awaiting"))
    for job in worker.settings.get("jobs", default=[]) or []:
        if not job.get("enabled"):
            continue
        sch = job.get("schedule") or {}
        name = job.get("name") or "بدون نام"
        if sch.get("type") == "interval":
            every = int(sch.get("every_minutes") or 60) * 60
            slot = int(time.time() // every)
            key = f"sched:job:{job['id']}:i{slot}"
            if st.is_processed(key) or slot * every < float(job.get("enabled_at") or 0):
                continue
        elif sch.get("type") == "daily":
            hh, mm = [int(x) for x in str(sch.get("time", "08:00")).split(":")[:2]]
            key = None
            # نوبت امروز، یا نوبت دیروز که از نیمه‌شب گذشت (مثلاً ۲۳:۵۵ که به‌خاطر اجرای دیگر یا قفل عقب افتاد)
            for back in (0, 1):
                day = now - timedelta(days=back)
                if day.weekday() not in (sch.get("days") or DAYS):
                    continue
                target = day.replace(hour=hh, minute=mm, second=0, microsecond=0)
                k = f"sched:job:{job['id']}:{target:%Y-%m-%d}"
                if now < target or st.is_processed(k):
                    continue
                if target.timestamp() < float(job.get("enabled_at") or 0):
                    st.mark_processed(k, "skipped:before-enable")
                    continue
                if (now - target).total_seconds() > max_age:
                    st.mark_processed(k, "skipped:too-old")
                    if back == 0:
                        worker.emit("warn", f"کار «{name}» ({target:%H:%M}) رد شد؛ بیش از حداکثر قدمت گذشته بود", "schedule")
                    continue
                key = k
                break
            if key is None:
                continue
        else:
            continue
        if busy:
            if job.get("when_busy") == "skip":
                st.mark_processed(key, "skipped:busy")
                worker.emit("warn", f"نوبت کار «{name}» رد شد؛ اجرای دیگری در جریان بود", "schedule")
                worker.settings.update_job(job["id"], last_at=time.time(), last_status="skipped",
                                           last_message="رد شد؛ اجرای دیگری در جریان بود")
            continue   # «صبر»: در دور بعدی دوباره تلاش می‌شود
        from .perms import TOOL_TITLES, enabled_tools
        off = [i["tool"] for i in job.get("items") or [] if i["tool"] not in enabled_tools(worker.settings)]
        if off:
            st.mark_processed(key, "skipped:tool-off")
            msg = f"ابزار {TOOL_TITLES.get(off[0], off[0])} در تنظیمات خاموش است؛ اجرا نشد"
            worker.emit("warn", f"کار «{name}»: {msg}", "schedule")
            worker.settings.update_job(job["id"], last_at=time.time(), last_status="skipped", last_message=msg)
            continue
        st.mark_processed(key, "started")
        try:
            run = pl.start(run_options(job), "schedule")
            busy = True
            worker.emit("info", f"کار زمان‌بندی‌شده‌ی «{name}» شروع شد", "schedule")
            worker.settings.update_job(job["id"], last_at=time.time(), last_status="started", last_message="شروع شد",
                                       last_run=run.id)
        except Exception as e:
            from .connectors import friendly_error
            msg = str(e) if isinstance(e, ConnectorError) else friendly_error(e)
            worker.emit("error", f"کار «{name}» شروع نشد: {msg}", "schedule")
            worker.notifier.notify("run_error", f"کار زمان‌بندی‌شده‌ی «{name}» شروع نشد: {msg}")
            worker.settings.update_job(job["id"], last_at=time.time(), last_status="error", last_message=msg)


def migrate_daily(settings):
    """اجرای روزانه‌ی قبلی ← کار «روال روزانه» با همان ساعت و کلیدها. یک بار."""
    if settings.get("jobs_migrated"):
        return
    d = settings.get("automation", "daily", default={}) or {}
    steps = dict(d.get("steps") or {})
    if not steps.get("splunk"):
        steps["abuse"] = steps["redmine"] = False
    if not steps.get("abuse"):
        steps["fortigate"] = False
    items = []
    for t, src in (("splunk", None), ("abuse", "prev"), ("fortigate", "prev"), ("redmine", "run")):
        if steps.get(t):
            items.append({"tool": t, "opts": {"input": {"source": src}} if src else {}})
    jobs = list(settings.get("jobs", default=[]) or [])
    if items:
        jobs.append({"id": uuid.uuid4().hex[:10], "name": "روال روزانه", "items": items,
                     "schedule": {"type": "daily", "time": d.get("time", "08:00"), "days": DAYS},
                     "enabled": bool(d.get("enabled")), "auto_ban": bool(d.get("auto_ban")), "auto_ticket": bool(d.get("auto_ticket")),
                     "auto_ssh": False, "max_auto_ban": int(d.get("max_auto_ban", 50) or 0), "when_busy": "wait",
                     "enabled_at": time.time()})
    settings.set_jobs(jobs, migrated=True)
    if d.get("enabled"):
        settings.update({"automation": {"daily": {"enabled": False}}})
