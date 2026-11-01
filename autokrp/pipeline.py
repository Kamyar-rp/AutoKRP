"""
زنجیره‌ی اجرا: Splunk → AbuseIPDB → FortiGate → Redmine
هر مرحله جدا یا پشت سر هم قابل اجراست. قبل از بلاک و قبل از ساخت تیکت پیش‌نمایش و تأیید لازم است
(مگر در اجرای زمان‌بندی‌شده با کلید «بدون تأیید»).
"""
import csv
import hashlib
import json
import logging
import re
import shutil
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path

from . import atrest, paths
from .connectors import Cancelled, ConnectorError, friendly_error, make
from .connectors import abuseipdb as ab
from .connectors import fortigate as fg
from .connectors import redmine as rm
from .connectors import splunk as sp
from .settings import TEMPLATE_KEYS

log = logging.getLogger(__name__)

STEPS = ["splunk", "abuse", "fortigate", "redmine"]
TOOLS = STEPS + ["dns", "ssh", "scan", "intel"]   # ابزارهای صفحه‌ی «ابزارها»؛ ترتیب اجرا را کاربر تعیین می‌کند
STEP_TITLES = {"splunk": "Splunk", "abuse": "AbuseIPDB", "fortigate": "FortiGate", "redmine": "Redmine", "dns": "DNS", "ssh": "SSH", "scan": "اسکن شبکه",
               "intel": "بررسی تکمیلی"}
RUN_LISTS = ("abuse_records", "fw_plan", "fw_results", "fw_actions", "dns", "ssh", "scan", "intel")   # تب‌های نتیجه‌ی اجرا
LEGACY_INPUT = {"abuse": "abuse_input", "fortigate": "fortigate_input", "redmine": "redmine_input"}


def legacy_items(options):
    """گزینه‌های قدیمی ({"steps": {...}, "abuse_input": ...}) ← فهرست ابزارها به ترتیب ثابت قبلی."""
    items = []
    for s in STEPS:
        if not (options.get("steps") or {}).get(s):
            continue
        o = {}
        if s == "splunk":
            o = {"earliest": options.get("earliest") or "", "latest": options.get("latest") or ""}
        elif options.get(LEGACY_INPUT[s]):
            o = {"input": dict(options[LEGACY_INPUT[s]])}
        items.append({"tool": s, "opts": o})
    return items
CONN = {"splunk": "splunk", "abuse": "abuseipdb", "fortigate": "fortigate", "redmine": "redmine"}


def block_reason(rec, cfg):
    """
    قانون واحد تصمیم (هم در اجرای روزانه و هم در بررسی کامل دیتابیس):
      فقط IPهای مخرب (ABUSE) بلاک می‌شوند → "abuse"
      Whitelisted با کلید skip_whitelisted → None (بررسی دستی)
      غیرمخرب (از هر کشوری) و خطا           → None — هرگز بلاک نمی‌شوند
    """
    return block_reason_v(rec.get("abuse_status"), rec.get("score"), rec.get("is_whitelisted"), cfg)


def block_reason_v(status, score, whitelisted, cfg):
    """همان قانون block_reason روی مقدارهای جدا (شمارش سریع بدون ساختن dict برای هر ردیف)."""
    st = str(status or "").upper()
    if st in ("ABUSE", "CLEAN") and score not in (None, "", "-"):
        try:      # با آستانه‌ی فعلی؛ نه وضعیتی که با آستانه‌ی قبلی ذخیره شده بود (ثبت دستی امتیاز ندارد)
            st = "ABUSE" if int(float(score)) > int(cfg.get("threshold") or 0) else "CLEAN"
        except (TypeError, ValueError):
            pass
    if cfg.get("skip_whitelisted") and str(whitelisted) == "True":
        return None
    return "abuse" if st == "ABUSE" else None


def _quota_fp(cfg, key=None):
    """اثر انگشت لینک و یک کلید AbuseIPDB؛ با عوض شدن هر کدام، علامت سهمیه بی‌اثر می‌شود."""
    raw = f"{cfg.get('address', '')}|{cfg.get('port', '')}|{cfg.get('token', '') if key is None else key}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _quota_map(raw):
    """meta abuse_quota_until: {"keys": {fp: until}} (قالب قدیمی {"until", "fp"} هم خوانده می‌شود)."""
    try:
        q = json.loads(raw or "{}")
    except ValueError:
        return {}
    if not isinstance(q, dict):
        return {}
    if isinstance(q.get("keys"), dict):
        return {str(k): float(v or 0) for k, v in q["keys"].items()}
    return {str(q["fp"]): float(q.get("until") or 0)} if q.get("fp") else {}


CACHED_KEYS = ("ip", "isp", "usage_type", "asn", "domain", "country_code", "country", "city", "score", "reports",
               "last_reported", "is_whitelisted", "is_tor", "categories", "error", "checked_at")
APPROVED_TXT = {"auto": "تأیید خودکار", "manual": "تأیید دستی"}
FW_DONE = ("banned", "already", "address", "ignored")


class Run:
    def __init__(self, options, trigger="manual"):
        self.id = datetime.now().strftime("%Y%m%d_%H%M%S") + "_" + trigger
        self.trigger = trigger
        self.options = options
        self.items, n = [], {}
        for it in options.get("items") or legacy_items(options):
            t = it.get("tool")
            if t not in TOOLS:
                raise ConnectorError(f"ابزار ناشناخته: {t}")
            n[t] = n.get(t, 0) + 1
            key = t if n[t] == 1 else f"{t}_{n[t]}"
            self.items.append({"key": key, "tool": t, "opts": dict(it.get("opts") or {})})
        self.selected = {s: any(i["tool"] == s for i in self.items) for s in TOOLS}
        self.cur = None
        self.status = "running"
        self.started = time.time()
        self.finished = None
        self.stages = {i["key"]: {"state": "pending", "tool": i["tool"], "message": "", "progress": None,
                                  "title": STEP_TITLES[i["tool"]] + (f" {i['key'].rsplit('_', 1)[1]}" if "_" in i["key"] else "")}
                       for i in self.items}
        self.summary = {}
        self.approval = None
        self._decision = None
        self._decision_ev = threading.Event()
        self.cancel = threading.Event()
        self.lines = []
        self.data = {}
        self.dir = paths.runs_dir() / self.id
        self.dir.mkdir(parents=True, exist_ok=True)
        self._logf = None                 # 1.26.2: run.log در طول اجرا باز می‌ماند (نه باز و بسته برای هر خط)
        self._loglock = threading.Lock()

    def log_line(self, text):
        with self._loglock:
            if self.finished is not None:          # پیام دیرهنگام پس از پایان اجرا: مثل قبل
                with open(self.dir / "run.log", "a", encoding="utf-8") as f:
                    f.write(text + "\n")
                return
            if self._logf is None:
                self._logf = open(self.dir / "run.log", "a", encoding="utf-8")  # noqa: SIM115 — در close_log بسته می‌شود
            self._logf.write(text + "\n")
            self._logf.flush()                   # تاریخچه و «نمایش» در همان لحظه ببینند

    def close_log(self):
        with self._loglock:
            if self._logf is not None:
                try:
                    self._logf.close()
                finally:
                    self._logf = None

    def to_dict(self, full=True):
        d = {"id": self.id, "trigger": self.trigger, "status": self.status, "started": self.started,
             "finished": self.finished, "stages": self.stages, "summary": self.summary, "dir": str(self.dir),
             "selected": self.selected, "order": [i["key"] for i in self.items], "user": self.options.get("user") or ""}
        if full:
            d["approval"] = self.approval
            d["lines"] = self.lines[-400:]
            d["lists"] = _trim_lists({k: self.data.get(k) for k in RUN_LISTS if self.data.get(k)})
        return d


LIST_SHOW = 500       # 1.27.9: رابط از هر فهرست بزرگ فقط این‌قدر ردیف می‌گیرد (+ شمار کل)؛ همه در CSV خروجی


def _trim_lists(lists):
    """فهرست‌های اجرا برای رابط: رکوردهای AbuseIPDB (هر وضعیت ۵۰۰ اول) و FortiGate (۵۰۰ اول) + شمار کل.
    قبلاً کل فهرست (ده‌ها هزار IP) هر بار به WebView می‌رفت: اوج حافظه‌ی WebView تا ۳GB در memdiag."""
    recs = lists.get("abuse_records")
    if recs and len(recs) > LIST_SHOW:
        out, cnt = [], {}
        for r in recs:
            st = r.get("abuse_status") or ""
            cnt[st] = cnt.get(st, 0) + 1
            if cnt[st] <= LIST_SHOW:
                out.append(r)
        lists["abuse_records"], lists["abuse_counts"] = out, cnt
    for k in ("fw_results", "fw_plan", "fw_actions"):
        v = lists.get(k)
        if v and len(v) > LIST_SHOW:
            lists[k], lists[k + "_total"] = v[:LIST_SHOW], len(v)
    return lists


def purge_run_dir(d):
    """حذف هر فایلی جز *.csv و run.log در یک پوشه‌ی اجرا (و پوشه‌ی خالی)."""
    try:
        if not d or not Path(d).is_dir():
            return 0
        n = 0
        for f in Path(d).iterdir():
            if f.is_file() and not (f.suffix.lower() == ".csv" or f.name == "run.log"):
                f.unlink()
                n += 1
        if not any(Path(d).iterdir()):
            Path(d).rmdir()
        return n
    except OSError:
        log.exception("run cleanup")
        return 0


def archive_run_dir(store, d, run_id=None):
    """1.37: متن run.log در پایگاه داده (runs.log) و حذف کل پوشه‌ی اجرا (CSVها هم؛ خواسته‌ی کاربر).
    خروجی: True اگر پوشه پاک شد."""
    d = Path(d)
    if not d.is_dir():
        return False
    lf = d / "run.log"
    try:
        if lf.is_file():
            text = "\n".join(atrest.read_log_lines(lf))
            if text.strip():
                store.run_set_log(run_id or d.name, text, started=lf.stat().st_mtime)
    except Exception:  # noqa — گزارش خوانده نشد: پوشه نگه داشته می‌شود
        log.exception("run archive %s", d.name)
        return False
    shutil.rmtree(d, ignore_errors=True)
    return not d.exists()


def purge_old_runs(store=None, skip=()):
    """یک‌بار در شروع. با store (1.37): گزارش اجراهای قبلی به پایگاه داده و حذف پوشه‌ها؛
    بدون store (نسخه‌های قبل): فقط فایل‌های نمایش‌داده‌نشده."""
    try:
        dirs = [d for d in paths.runs_dir().iterdir() if d.is_dir() and d.name not in skip]
    except OSError:
        return 0
    if store is None:
        return sum(purge_run_dir(d) for d in dirs)
    return sum(1 for d in dirs if archive_run_dir(store, d))


class Pipeline:
    def __init__(self, settings, store, demo=False, emit=None):
        self.settings = settings
        self.store = store
        self.demo = demo
        self._emit = emit or (lambda *a, **k: None)
        self.notify = lambda *a, **k: None   # worker مقداردهی می‌کند
        self.ssh = None                       # SshRunner؛ worker مقداردهی می‌کند
        self.fw_reconcile = None              # هماهنگی وضعیت بلاک دیتابیس با لیست Banned (worker)
        self.current: Run | None = None
        self._lock = threading.Lock()

    # ------------------------------------------------------------ API
    def start(self, options, trigger="manual"):
        with self._lock:
            if self.current and self.current.status in ("running", "awaiting"):
                raise ConnectorError("یک اجرای دیگر در جریان است. صبر کنید یا آن را متوقف کنید.")
            v = self.settings.vault
            if v is not None and not v.unlocked():
                raise ConnectorError("برنامه قفل است. ابتدا رمز اصلی را وارد کنید.")
            run = Run(options, trigger)
            if not run.items:
                raise ConnectorError("هیچ ابزاری انتخاب نشده است.")
            from .perms import TOOL_TITLES, enabled_tools
            off = [i["tool"] for i in run.items if i["tool"] not in enabled_tools(self.settings)]
            if off:
                raise ConnectorError(f"ابزار {TOOL_TITLES.get(off[0], off[0])} در تنظیمات خاموش است.")
            self.validate(run.items)
            self.current = run
        threading.Thread(target=self._run, args=(run,), name=f"run-{run.id}", daemon=True).start()
        return run

    @staticmethod
    def validate(items):
        """سازگاری ورودی هر ابزار با ابزارهای قبل از آن؛ پیش از شروع اجرا."""
        for k, it in enumerate(items):
            t, src = it["tool"], ((it.get("opts") or {}).get("input") or {}).get("source")
            before = [x["tool"] for x in items[:k]]
            prev = before[-1] if before else None
            title = STEP_TITLES[t]
            if t == "abuse" and src in (None, "prev", "splunk"):
                if src == "splunk" and "splunk" not in before:
                    raise ConnectorError(f"{title}: ورودی «خروجی Splunk» انتخاب شده ولی Splunk پیش از آن نیست.")
                if src in (None, "prev") and prev not in ("splunk", "dns", "scan"):
                    raise ConnectorError(f"{title} (شماره {k + 1}): «خروجی ابزار قبلی» فقط بعد از Splunk، DNS یا اسکن شبکه ممکن است.")
            if t == "fortigate" and src == "abuse" and prev != "abuse":
                raise ConnectorError(f"{title} (شماره {k + 1}): «مخرب‌های AbuseIPDB» فقط بلافاصله بعد از AbuseIPDB ممکن است.")
            if t == "fortigate" and (it.get("opts") or {}).get("scenario"):
                if src in (None, "prev") and (not prev or prev == "redmine"):
                    raise ConnectorError(f"{title} (شماره {k + 1}): «خروجی ابزار قبلی» ابزاری با خروجی جدول پیش از این گام لازم دارد.")
            elif t == "fortigate" and src in (None, "prev") and prev not in ("abuse", "intel"):
                raise ConnectorError(f"{title} (شماره {k + 1}): «خروجی ابزار قبلی» فقط بلافاصله بعد از AbuseIPDB یا بررسی تکمیلی "
                                     "ممکن است (فقط IPهای مخرب بلاک می‌شوند).")
            if t == "intel" and src in (None, "prev") and prev not in ("abuse", "splunk", "dns", "scan"):
                raise ConnectorError(f"{title} (شماره {k + 1}): «خروجی ابزار قبلی» فقط بعد از AbuseIPDB، Splunk، DNS یا اسکن شبکه "
                                     "ممکن است.")
            if t == "redmine" and src in (None, "run") and "splunk" not in before:
                raise ConnectorError(f"{title} (شماره {k + 1}): ورودی «خروجی Splunk این اجرا» انتخاب شده ولی Splunk پیش از آن نیست.")
            if t == "dns" and src in (None, "prev") and not prev:
                raise ConnectorError(f"{title} (شماره {k + 1}): «خروجی ابزار قبلی» انتخاب شده ولی ابزاری پیش از آن نیست.")
            if t == "ssh" and src in (None, "prev") and not prev:
                raise ConnectorError(f"{title} (شماره {k + 1}): «خروجی ابزار قبلی» انتخاب شده ولی ابزاری پیش از آن نیست.")
            if t == "ssh" and src in (None, "prev") and prev == "redmine":
                raise ConnectorError(f"{title} (شماره {k + 1}): خروجی Redmine ورودی مناسبی برای SSH نیست.")
            if t in ("dns", "scan") and src in (None, "prev") and prev == "ssh":
                raise ConnectorError(f"{title} (شماره {k + 1}): خروجی SSH ستون IP ندارد؛ ورودی مناسبی نیست.")
            if t == "scan" and src in (None, "prev") and (not prev or prev == "redmine"):
                raise ConnectorError(f"{title} (شماره {k + 1}): «خروجی ابزار قبلی» انتخاب شده ولی ابزار مناسبی پیش از آن نیست.")
            if t == "dns" and src in (None, "prev") and prev == "redmine":
                raise ConnectorError(f"{title} (شماره {k + 1}): خروجی Redmine ورودی مناسبی برای DNS نیست.")

    def cancel(self):
        run = self.current
        if run and run.status in ("running", "awaiting"):
            run.cancel.set()
            run._decision_ev.set()
            return True
        return False

    def decide(self, run_id, approve: bool, payload=None):
        run = self.current
        if not run or run.id != run_id or not run.approval:
            raise ConnectorError("درخواست تأییدی برای این اجرا در انتظار نیست.")
        aid = (payload or {}).get("approval_id")
        if aid and aid != run.approval.get("id"):  # پاسخ دیرهنگام به درخواست قبلی (پنجره یا کاربر دیگر)
            raise ConnectorError("این درخواست تأیید دیگر معتبر نیست؛ صفحه را تازه کنید.")
        run._decision = {"approve": bool(approve), "payload": payload or {}}
        run._decision_ev.set()

    # ------------------------------------------------------------ helpers
    def _log(self, run, msg, level="info", kind=None):
        run.lines.append({"ts": time.time(), "level": level, "msg": msg})
        self._emit(level, msg, kind or "run", run.id)
        try:      # گزارش هر اجرا کنار خروجی‌هایش (رمزشده) برای نمایش در تاریخچه
            if run.dir and run.dir.exists():
                run.log_line(atrest._enc_line(f"{time.strftime('%H:%M:%S')} [{level}] {msg}"))
        except Exception:
            pass

    @staticmethod
    def _f(run, name):
        """مسیر فایل ابزار جاری؛ برای تکرار دوم به بعد یک ابزار پسوند _2، _3 ... می‌گیرد."""
        key = (run.cur or {}).get("key", "")
        if "_" in key:
            stem, ext = name.rsplit(".", 1)
            name = f"{stem}_{key.rsplit('_', 1)[1]}.{ext}"
        return run.dir / name

    def _query(self, qid):
        """کوئری ذخیره‌شده‌ی Splunk؛ خالی یا «default» = کوئری اصلی تنظیمات."""
        sp_cfg = self.settings.get("splunk") or {}
        if qid and qid != "default":
            for q in sp_cfg.get("queries") or []:
                if q.get("id") == qid:
                    return q
            raise ConnectorError("کوئری انتخاب‌شده‌ی Splunk در تنظیمات پیدا نشد (شاید حذف شده باشد).")
        return {"id": "default", "name": "پیش‌فرض", "query": sp_cfg.get("query", "")}

    @staticmethod
    def _user_path(inp):
        try:
            return paths.user_file(inp.get("path"))
        except PermissionError as e:
            raise ConnectorError(str(e))

    @staticmethod
    def _st(run):
        return run.stages[run.cur["key"]]

    @staticmethod
    def _inp(run, default):
        return (run.cur or {}).get("opts", {}).get("input") or default

    def _client(self, step, run):
        cfg = self.settings.conn_config(CONN[step])
        return make(CONN[step], cfg, run.cancel, self.demo)

    def _test_mode(self):
        return bool(self.settings.get("test_mode", default=True))

    def _auto_allowed(self, run, key):
        """
        «بدون تأیید» فقط وقتی مجاز است که اجرا زمان‌بندی‌شده باشد و کلید آن همین الان هم روشن باشد.
        اگر کاربر وسط اجرا کلید را خاموش کرده باشد، اجرا منتظر تأیید می‌ماند.
        """
        if run.trigger != "schedule" or not run.options.get(key):
            return False
        if run.options.get("job_id"):   # کار زمان‌بندی‌شده: کلید همان کار، همین الان هم روشن باشد
            job = next((j for j in self.settings.get("jobs", default=[]) or [] if j.get("id") == run.options["job_id"]), None)
            return bool(job and job.get(key) and self.settings.get("automation", "master", default=False))
        return bool(self.settings.get("automation", "master", default=False)
                    and self.settings.get("automation", "daily", key, default=False))

    def _wait_approval(self, run, step, preview, auto):
        if auto:
            self._log(run, f"{STEP_TITLES[step]}: تأیید خودکار (کلید «بدون تأیید» روشن است)", "warn")
            run.data.setdefault("approved_by", {})[step] = "auto"
            return {"approve": True, "payload": {}}
        run._decision = None
        run._decision_ev.clear()                 # پیش از انتشار درخواست؛ تصمیمی که بلافاصله برسد گم نشود
        run.approval = {"step": step, "key": run.cur["key"], "preview": preview, "since": time.time(),
                        "id": hashlib.sha256(f"{run.id}|{run.cur['key']}|{time.time()}".encode()).hexdigest()[:16]}
        what = {"fortigate": f"بلاک {preview.get('counts', {}).get('to_ban', 0)} آدرس در FortiGate",
                "redmine": f"ساخت تیکت Redmine «{preview.get('subject', '')}»",
                "ssh": f"اجرای اسکریپت SSH روی {len(preview.get('devices') or [])} دستگاه"}.get(step, step)
        self.notify("approval", f"اجرای {run.id} منتظر تأیید شماست: {what}\nبرای تأیید، برنامه را باز کنید ← «ابزارها».")
        run.status = "awaiting"
        self._st(run)["state"] = "awaiting"
        self._log(run, f"{STEP_TITLES[step]}: منتظر تأیید شما", "warn", "approval")
        while not run._decision_ev.wait(0.5):
            if run.cancel.is_set():
                break
        if run.cancel.is_set():
            raise Cancelled()
        decision = run._decision or {"approve": False}
        run.data.setdefault("approved_by", {})[step] = "manual" if decision.get("approve") else "rejected"
        run.approval = None
        run._decision = None
        run.status = "running"
        self._st(run)["state"] = "running"
        return decision

    # ------------------------------------------------------------ main
    def _run(self, run: Run):
        from .store import ACTOR
        ACTOR.name = run.options.get("user") or ("زمان‌بندی" if run.trigger in ("schedule", "retry") else "")
        self._log(run, f"اجرا شروع شد ({'آزمایشی' if self._test_mode() else 'واقعی'}) — ابزارها به ترتیب: "
                       + "\u200f ← \u200f".join(run.stages[i["key"]]["title"] for i in run.items))   # RLM: ترتیب درست در متن فارسی
        self.store.save_run(self._run_row(run))
        try:
            for idx, item in enumerate(run.items):
                step = item["tool"]
                run.cur = item
                if run.cancel.is_set():
                    raise Cancelled()
                st = run.stages[item["key"]]
                st["state"] = "running"
                st["started"] = time.time()
                try:
                    run.data.pop("out_path", None)
                    run.data.pop("out_ips", None)
                    getattr(self, f"_step_{step}")(run)
                    if st["state"] == "running":
                        st["state"] = "done"
                    if isinstance(run.summary.get(step), dict):
                        st["summary"] = dict(run.summary[step])
                    run.data["prev"] = {"tool": step, "key": item["key"], "title": st["title"],
                                        "path": run.data.pop("out_path", None), "ips": run.data.pop("out_ips", [])}
                except Cancelled:
                    st["state"] = "cancelled"
                    raise
                except Exception as e:
                    st["state"] = "error"
                    st["message"] = friendly_error(e)
                    self._log(run, f"{st['title']}: {st['message']}", "error")
                    self.notify("run_error", f"اجرای {run.id} — {st['title']}: {st['message']}")
                    self.store.add_history(step, "-", "error", st["message"], run.id, str(run.dir))
                    log.exception("step %s failed", step)
                    for later in run.items[idx + 1:]:
                        run.stages[later["key"]]["state"] = "skipped"
                        run.stages[later["key"]]["message"] = "به‌خاطر خطای مرحله‌ی قبل اجرا نشد"
                    run.status = "failed"
                    break
                finally:
                    st["finished"] = time.time()
                    self.store.save_run(self._run_row(run))
            if run.status == "running":
                run.status = "done"
                self._log(run, "اجرا کامل شد", "ok")
        except Cancelled:
            run.status = "cancelled"
            for s in run.stages:
                if run.stages[s]["state"] in ("pending", "running", "awaiting"):
                    run.stages[s]["state"] = "cancelled"
            self._log(run, "اجرا توسط کاربر متوقف شد", "warn")
        except Exception as e:  # نباید رخ دهد
            run.status = "failed"
            self._log(run, friendly_error(e), "error")
            log.exception("run failed")
        finally:
            run.approval = None
            run.finished = time.time()
            self.store.save_run(self._run_row(run))
            if run.options.get("job_id"):
                try:
                    msg = {"done": "کامل شد", "cancelled": "متوقف شد"}.get(run.status) or next(
                        (f"{x['title']}: {x['message']}" for x in run.stages.values() if x["state"] == "error"), "ناموفق")
                    self.settings.update_job(run.options["job_id"], last_status=run.status, last_message=msg[:300], last_run=run.id)
                except Exception:
                    log.exception("job status")
            # run.json دیگر نوشته نمی‌شود: جایی خوانده نمی‌شد و تکرار run.log و CSVها بود
            self._cleanup_run(run)

    def _cleanup_run(self, run):
        """1.23.1: پس از اجرا فقط آنچه در برنامه نمایش داده می‌شود (CSVها و run.log) در پوشه‌ی اجرا می‌ماند؛
        داده‌ی کمکی اجرا (در حافظه و فایل) پاک می‌شود."""
        # 1.28: فهرست‌های نمایشی (تب‌های نتیجه) می‌مانند؛ قبلاً با پاک شدن کل run.data نتیجه‌ی ابزارها
        # (اسکن، DNS، SSH، AbuseIPDB، …) بلافاصله بعد از پایان اجرا از صفحه‌ی ابزارها پاک می‌شد
        run.data = {k: run.data[k] for k in RUN_LISTS if run.data.get(k)}
        run.close_log()               # ویندوز: فایل باز حذف/جابه‌جا نمی‌شود
        # 1.37: فقط متن گزارش (در پایگاه داده) می‌ماند؛ CSVها پس از پایان کار لازم نیستند (پیوست تیکت پیش از این فرستاده شده)
        if not archive_run_dir(self.store, run.dir, run.id):
            purge_run_dir(run.dir)

    def _run_row(self, run):
        return {"id": run.id, "started": run.started, "finished": run.finished, "trigger": run.trigger,
                "steps": {s: run.stages[s]["state"] for s in run.stages}, "status": run.status,
                "summary": run.summary, "dir": str(run.dir)}

    # ------------------------------------------------------------ step 1: Splunk
    def _step_splunk(self, run):
        cli = self._client("splunk", run)
        q0 = self._query(run.cur["opts"].get("query_id"))
        if q0["id"] != "default":
            # کوئری ذخیره‌شده: نقش ستون‌ها از نام‌های استاندارد (نگاشت دستی مخصوص کوئری اصلی است)
            if not (q0.get("query") or "").strip():
                raise ConnectorError(f"متن کوئری «{q0.get('name')}» خالی است.")
            cli.cfg.update(query=q0["query"], fields={}, fields_hash="", src_field="")
            self._log(run, f"Splunk: کوئری ذخیره‌شده «{q0.get('name')}»")
        out = self._f(run, "splunk.csv")
        o = run.cur["opts"]
        q = self._query(o.get("query_id"))
        earliest = o.get("earliest") or q.get("earliest") or None
        latest = o.get("latest") or q.get("latest") or None
        url, query, e, l = cli.prepared(earliest, latest)
        first_line = query.splitlines()[0][:120]
        for note in cli.query_notes:
            self._log(run, f"Splunk: در متن کوئری {note}", "warn")
        self._log(run, f"Splunk: اجرای کوئری در اپ {url.split('/servicesNS/-/')[1].split('/')[0]} — بازه {e} تا {l} — «{first_line}»")
        n = cli.export_csv(out, earliest, latest, progress=lambda m: self._st(run).update(message=m))
        rows = sp.read_rows(out)
        if not rows:
            self._splunk_zero(run, cli, earliest, latest, out)
        cols = list(rows[0].keys()) if rows else []
        fields = sp.resolve_fields(cols, cli.cfg)
        if q0["id"] == "default" and cli.cfg.get("fields_hash") and cli.cfg["fields_hash"] != sp.query_hash(cli.cfg.get("query")):
            self._log(run, "Splunk: کوئری بعد از تعیین نگاشت ستون‌ها تغییر کرده است؛ در تنظیمات Splunk «اجرا و پیش‌نمایش» را بزنید و نگاشت را دوباره تأیید کنید", "warn")
        if rows:
            if fields["src"] not in cols:
                # ممکن است کوئری برای ابزار دیگری باشد (مثلاً URL برای DNS)؛ ابزاری که IP مبدأ لازم دارد خطا می‌دهد
                self._log(run, f"Splunk: ستون IP مبدأ «{fields['src'] or 'src_ip'}» در خروجی نیست؛ IPها به فهرست آدرس‌ها اضافه نمی‌شوند. "
                               f"ستون‌های خروجی: {', '.join(cols)}", "warn")
                fields["src"] = ""
            for role, col in list(fields.items()):
                if col and col not in cols:
                    self._log(run, f"Splunk: ستون «{col}» ({role}) در خروجی نیست؛ نادیده گرفته شد", "warn")
                    fields[role] = ""
            self._log(run, "Splunk: ستون‌ها — " + "، ".join(f"{k}={v or '—'}" for k, v in fields.items()))
        run.data["splunk_fields"] = fields
        sources = sp.extract_sources(rows, fields) if rows and fields["src"] else {}
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        nets, _ = fg.parse_ignore(self.settings.get("fortigate", "ignore_networks", default=[]))
        excluded = {ip for ip in sources if fg.is_excluded(ip, nets)}
        if excluded:
            self._log(run, f"Splunk: {len(excluded)}\u200f IP خصوصی یا داخل رنج‌های مستثنا به فهرست آدرس‌ها اضافه نشد "
                           "(در فایل خروجی و تیکت می‌مانند)")
        with self.store.batch():   # یک تراکنش برای همه‌ی IPها
            for ip, d in sources.items():
                if ip in excluded:
                    continue
                self.store.upsert_ip(ip, source="splunk", last_seen=now, attack_count=d["attack_count"],
                                     signatures=", ".join(d["signatures"][:20]), dest_ports=", ".join(d["dest_ports"][:30]),
                                     last_run=run.id)
        run.data["splunk_csv"] = str(out)
        run.data["splunk_sources"] = sources
        run.data["splunk_has_src"] = bool(fields["src"]) or not rows
        run.data["out_path"], run.data["out_ips"] = str(out), list(sources)
        run.summary["splunk"] = {"rows": n, "src": len(sources)}
        self._st(run)["message"] = f"{n} ردیف، {len(sources)}\u200f IP مبدأ یکتا"
        self._log(run, f"Splunk: {n} ردیف در splunk.csv ذخیره شد؛ {len(sources)}\u200f IP مبدأ یکتا", "ok")
        self.store.add_history("splunk", f"{n} ردیف", "ok", f"{len(sources)}\u200f IP مبدأ", run.id, str(out))

    def _splunk_zero(self, run, cli, earliest, latest, out):
        """صفر ردیف: اجرای تشخیصی با خروجی JSON تا پیام‌های خود Splunk دیده شوند."""
        try:
            full = atrest.read_bytes(out)
            raw = full[:300].decode("utf-8", "replace").strip()
            self._log(run, f"Splunk: فایل CSV دریافتی {len(full)} بایت است" + (f"؛ ابتدای آن: «{raw[:200]}»" if raw else "؛ خالی"), "warn")
            d = cli.diagnose(earliest, latest, limit=5)
            if d.get("user"):
                self._log(run, f"Splunk: یوزر توکن {d['user']['username']} (نقش‌ها: {', '.join(d['user']['roles'])})", "warn")
            self._log(run, f"Splunk: اجرای تشخیصی (JSON) {len(d['rows'])} ردیف برگرداند؛ HTTP {d['http']}", "warn")
            for m in d["messages"][:10]:
                self._log(run, f"Splunk [{m['type']}]: {m['text'][:400]}", "error" if m["type"] in ("ERROR", "FATAL", "RAW") else "warn")
            if d["rows"] and not d["messages"]:
                self._log(run, "Splunk: خروجی JSON ردیف دارد ولی CSV خالی است؛ این را با «اجرای آزمایشی کوئری» در تنظیمات Splunk بررسی کنید", "error")
        except Exception as ex:
            self._log(run, f"Splunk: اجرای تشخیصی ناموفق بود: {friendly_error(ex)}", "warn")

    # ------------------------------------------------------------ ابزار DNS
    def _step_dns(self, run):
        from . import dnstool as dn
        o = run.cur["opts"]
        mode = "url" if o.get("mode") == "url" else "ip"
        inp = o.get("input") or {"source": "prev"}
        src = inp.get("source", "prev")
        values, label = [], ""
        try:
            if src == "list":
                values, label = [inp.get("text") or ""], "لیست دستی"
            elif src in ("csv", "prev"):
                if src == "prev":
                    prev = run.data.get("prev") or {}
                    path = prev.get("path")
                    if prev.get("tool") == "dns" and mode == "ip" and not inp.get("column"):
                        path = None   # خروجی DNS قبلی در حالت IP: آدرس‌های به‌دست‌آمده
                    if not path:
                        if prev.get("ips"):
                            values, label = ["\n".join(prev["ips"])], f"خروجی {prev.get('title')}"
                        elif prev.get("tool") in ("scan", "dns", "splunk", "abuse", "fortigate"):
                            st0 = self._st(run)            # ابزار قبلی نتیجه‌ای نداشت: کاری نیست (خطا نیست)
                            st0["message"] = "ورودی از ابزار قبلی خالی بود؛ اجرا نشد"
                            self._log(run, "DNS: " + st0["message"], "warn")
                            run.summary["dns"] = {"total": 0, "found": 0, "mode": mode, "statuses": {}, "server": ""}
                            return
                        else:
                            raise ConnectorError(f"ابزار قبلی ({prev.get('title', '—')}) خروجی قابل استفاده ندارد.")
                    label = label or f"خروجی {prev.get('title')}"
                else:
                    path = self._user_path(inp)
                    if not path or not Path(path).is_file():
                        raise ConnectorError(f"فایل CSV پیدا نشد: {path or '(خالی)'}")
                    label = f"فایل {Path(path).name}"
                if path and not values:
                    with atrest.open_read(path) as f:
                        rd = csv.DictReader(f)
                        cols = [(c or "").strip() for c in (rd.fieldnames or [])]
                        rows = list(rd)
                    col = dn.pick_column(cols, mode, inp.get("column") or "")
                    orig = next(c for c in (rd.fieldnames or []) if (c or "").strip() == col)
                    values = [r.get(orig) or "" for r in rows]
                    label += f" (ستون {col})"
            else:
                raise ConnectorError("منبع ورودی DNS نامعتبر است.")
            first = None
            if mode == "ip":
                targets, bad = dn.parse_ips("\n".join(values))
            else:
                targets, bad, first = dn.parse_hosts(values)
        except dn.DnsError as e:
            raise ConnectorError(str(e))
        if bad:
            self._log(run, f"DNS: {len(bad)} مقدار نامعتبر رد شد: {', '.join(bad[:10])}{' …' if len(bad) > 10 else ''}", "warn")
        if not targets:
            raise ConnectorError(f"DNS: هیچ {'IP' if mode == 'ip' else 'دامنه یا URL'} معتبری در ورودی ({label}) نیست.")
        cfg = dict(self.settings.get("dns") or {})
        if o.get("concurrency"):
            cfg["concurrency"] = o["concurrency"]
        st = self._st(run)
        self._log(run, f"DNS: {len(targets)} {'IP' if mode == 'ip' else 'میزبان'} از {label}؛ رکوردها: {', '.join(o.get('types') or dn.DEFAULT_TYPES[mode])}")

        def prog(i, n, t):
            st["progress"] = [i, n]
            st["message"] = f"{i} از {n}: {t}"
        try:
            cols, rows, ips, sm = dn.run_lookup(mode, targets, o.get("types"), cfg, run.cancel, prog, first)
        except InterruptedError:
            raise Cancelled()
        except dn.DnsError as e:
            raise ConnectorError(str(e))
        out = self._f(run, "dns.csv")
        with atrest.open_write(out) as f:
            w = csv.DictWriter(f, fieldnames=cols)
            w.writeheader()
            w.writerows(rows)
        run.summary["dns"] = sm
        run.data.setdefault("dns", {})[run.cur["key"]] = {"columns": cols, "rows": rows[:500], "total": len(rows), "mode": mode}
        run.data["out_path"], run.data["out_ips"] = str(out), ips
        st["progress"] = None
        st["message"] = f"{sm['found']} از {sm['total']} {'PTR داشت' if mode == 'ip' else 'resolve شد'}"
        self._log(run, f"DNS: {st['message']} (سرور {sm['server']})", "ok")
        self.store.add_history("dns", f"{sm['total']} {'IP' if mode == 'ip' else 'میزبان'}", "ok", st["message"], run.id, str(out))

    # ------------------------------------------------------------ ابزار SSH
    def _ssh_lists(self, run, o):
        """متغیرهای قالب: هر ستون ورودی یک فهرست؛ برای لیست دستی، نام متغیر را کاربر تعیین می‌کند."""
        from . import sshtemplate as tp
        inp = o.get("input") or {"source": "prev"}
        src = inp.get("source", "prev")
        if src == "list":
            name = (o.get("var") or "src_ip").strip() or "src_ip"
            vals = []
            for x in re.split(r"[\s,;]+", inp.get("text") or ""):
                if x and x not in vals:
                    vals.append(x)
            return {name: vals}, "لیست دستی"
        if src == "csv":
            path = self._user_path(inp)
            if not path or not Path(path).is_file():
                raise ConnectorError(f"فایل CSV پیدا نشد: {path or '(خالی)'}")
            label = f"فایل {Path(path).name}"
        elif src == "prev":
            prev = run.data.get("prev") or {}
            path, label = prev.get("path"), f"خروجی {prev.get('title', '—')}"
            if not prev:
                raise ConnectorError("ابزاری پیش از SSH نیست.")
            if not path and prev.get("tool") in ("redmine", "ssh"):
                raise ConnectorError(f"ابزار قبلی ({prev.get('title', '—')}) خروجی قابل استفاده ندارد.")
        elif src == "none":
            return {}, "بدون ورودی"
        else:
            raise ConnectorError("منبع ورودی SSH نامعتبر است.")
        lists = {}
        if path:
            with atrest.open_read(path) as f:
                rd = csv.DictReader(f)
                cols = [(c or "").strip() for c in (rd.fieldnames or [])]
                rows = [{(k or "").strip(): v for k, v in r.items()} for r in rd]
            lists = tp.build_lists(cols, rows)
        if src == "prev":                    # خالی هم باشد تعریف می‌شود تا قالب «داده‌ای نیست» بگوید، نه خطا
            lists.setdefault("ips", list((run.data.get("prev") or {}).get("ips") or []))
        return lists, label

    def _step_ssh(self, run):
        from . import sshtemplate as tp
        from .ssh import SshError
        if self.ssh is None:
            raise ConnectorError("ابزار SSH در دسترس نیست.")
        o = run.cur["opts"]
        st = self._st(run)
        ids = [int(x) for x in o.get("device_ids") or []]
        devs = [d for d in (self.store.ssh_device(i) for i in ids) if d and not d.get("owner")]   # کارها: فقط دستگاه‌های مشترک
        if not devs:
            raise ConnectorError("SSH: هیچ دستگاهی انتخاب نشده است (یا دستگاه‌های انتخابی حذف شده‌اند).")
        if o.get("script_id"):
            sc = self.store.ssh_script(int(o["script_id"]))
            if not sc:
                raise ConnectorError("SSH: اسکریپت انتخاب‌شده در کتابخانه پیدا نشد.")
            script = {k: sc.get(k) for k in ("body", "mode", "use_sudo", "save_config")}
            name = sc.get("name") or "اسکریپت"
        else:
            script = {"body": o.get("body") or "", "mode": o.get("mode") or "exec",
                      "use_sudo": bool(o.get("use_sudo")), "save_config": bool(o.get("save_config"))}
            name = "اسکریپت ابزارها"
        if not (script.get("body") or "").strip():
            raise ConnectorError("SSH: متن اسکریپت خالی است.")
        try:
            lists, label = self._ssh_lists(run, o)
            if (o.get("input") or {}).get("source", "prev") == "prev" and not any(lists.values()):
                st["message"] = "ورودی از ابزار قبلی خالی بود؛ اجرا نشد"
                self._log(run, "SSH: " + st["message"], "warn")
                run.summary["ssh"] = {"devices": len(devs), "ok": 0, "failed": 0, "skipped": True}
                return
            used = tp.used_lists(script["body"])
            for u in used:
                v = next((lists[k] for k in lists if k.lower() == u.lower()), None)
                if v is not None and len(v) > tp.MAX_VALUES:
                    raise tp.TemplateError(f"«{u}» {len(v)} مقدار دارد؛ سقف {tp.MAX_VALUES} است.")
            empty = [u for u in used if not next((lists[k] for k in lists if k.lower() == u.lower()), [1])]
            body = tp.render(script["body"], lists)
        except tp.TemplateError as e:
            raise ConnectorError(f"SSH: {e}")
        counts = {u: len(next((lists[k] for k in lists if k.lower() == u.lower()), [])) for u in used}
        self._log(run, f"SSH: «{name}» روی {len(devs)} دستگاه؛ ورودی {label}"
                       + ("؛ " + "، ".join(f"{k}={v}" for k, v in counts.items()) if counts else ""))
        if used and empty:
            st["message"] = f"داده‌ای برای {', '.join(empty)} نیست؛ اجرا نشد"
            self._log(run, "SSH: " + st["message"], "warn")
            run.summary["ssh"] = {"devices": len(devs), "ok": 0, "failed": 0, "skipped": True}
            return
        dry = bool(o.get("dry_run"))
        if not dry and self._test_mode():
            dry = True
            self._log(run, "SSH: حالت تست روشن است؛ فقط متن ساخته می‌شود و به دستگاه‌ها ارسال نمی‌شود", "warn")
        script = {**script, "body": body, "name": f"{name} — ابزارها ({run.id})", "last_csv": bool(o.get("last_csv"))}
        if not dry:
            preview = {"devices": [{"name": d.get("name") or d["host"], "host": d["host"], "type": d["device_type"]} for d in devs],
                       "script": body[:20000], "counts": counts, "mode": script.get("mode"), "name": name,
                       "save_config": bool(script.get("save_config")), "use_sudo": bool(script.get("use_sudo"))}
            st["message"] = "پیش‌نمایش اسکریپت آماده است"
            dec = self._wait_approval(run, "ssh", preview, self._auto_allowed(run, "auto_ssh"))
            if not dec.get("approve"):
                st["message"] = "اجرای SSH توسط کاربر رد شد"
                self._log(run, "SSH: " + st["message"], "warn")
                run.summary["ssh"] = {"devices": len(devs), "ok": 0, "failed": 0, "rejected": True}
                return
            if self._test_mode():          # در فاصله‌ی تأیید حالت تست روشن شد
                dry = True
                self._log(run, "SSH: حالت تست روشن است؛ فقط متن ساخته می‌شود و به دستگاه‌ها ارسال نمی‌شود", "warn")
        try:
            job = self.ssh.start([d["id"] for d in devs], script,
                                 {"concurrency": int(o.get("concurrency") or 5), "dry_run": dry}, "run")
        except SshError as e:
            raise ConnectorError(f"SSH: {e}")
        while job["status"] == "running":
            if run.cancel.is_set():
                self.ssh.cancel()
            done = sum(1 for r in job["results"].values() if r["status"] not in ("pending", "running"))
            st["progress"] = [done, job["total"]]
            st["message"] = f"{done} از {job['total']} دستگاه"
            time.sleep(0.5)
        st["progress"] = None
        if run.cancel.is_set():
            raise Cancelled()
        rows = []
        for r in job["results"].values():
            out = ""
            if r.get("out_file"):
                try:
                    out = self.ssh.output(job["id"], r["device_id"])
                except Exception:
                    out = ""
            rows.append({"Device": r["name"], "Host": r["host"], "Status": r["status"], "Message": r.get("message", ""), "Output": out})
        csvf = self._f(run, "ssh.csv")
        with atrest.open_write(csvf) as fh:
            w = csv.DictWriter(fh, fieldnames=["Device", "Host", "Status", "Message", "Output"])
            w.writeheader()
            w.writerows(rows)
        ok = sum(1 for r in rows if r["Status"] == "ok")
        failed = len(rows) - ok
        run.summary["ssh"] = {"devices": len(rows), "ok": ok, "failed": failed, "dry": dry, "job": job["id"]}
        run.data.setdefault("ssh", {})[run.cur["key"]] = {"rows": [{**r, "Output": r["Output"][-6000:]} for r in rows], "dry": dry}
        run.data["out_path"] = str(csvf)
        if o.get("last_csv"):
            self._ssh_last_table(run, job, dry)
        st["message"] = f"{ok} از {len(rows)} دستگاه موفق" + (" (آزمایشی)" if dry else "")
        self._log(run, "SSH: " + st["message"], "ok" if not failed else "warn")
        if failed:
            raise ConnectorError(f"SSH روی {failed} دستگاه ناموفق بود: " + "؛ ".join(
                f"{r['Device']}: {r['Message']}" for r in rows if r["Status"] != "ok")[:500])

    def _ssh_last_table(self, run, job, dry):
        """1.29: خروجی آخرین دستور هر دستگاه = CSV (خط اول نام ستون‌ها) ← یک جدول با ستون‌های Device و Host برای ابزار بعدی."""
        cols, rows = ["Device", "Host"], []
        for r in job["results"].values():
            if r["status"] != "ok":
                continue
            txt = self.ssh.last_output(job["id"], r["device_id"]) if not dry else None
            if txt is None:
                continue
            try:
                part, pc = self._parse_table(txt.lstrip("\ufeff").splitlines(), f"SSH {r['name']}")
            except ConnectorError as e:
                self._log(run, f"SSH: {e}", "warn")
                continue
            if not part:
                self._log(run, f"SSH: خروجی آخرین دستور «{r['name']}» ردیفی نداشت", "warn")
            for c in pc:
                if c not in cols:
                    cols.append(c)
            rows += [{"Device": r["name"], "Host": r["host"], **x} for x in part]
        f = self._f(run, "ssh_last.csv")
        with atrest.open_write(f) as fh:
            w = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
            w.writeheader()
            w.writerows(rows)
        run.data["out_path"] = str(f)
        ips = []
        for x in rows:
            ip = x.get("ip") or x.get("IP") or x.get("src") or x.get("src_ip")
            if ip and ip not in ips:
                ips.append(ip)
        run.data["out_ips"] = ips
        if dry:
            self._log(run, "SSH: اجرای آزمایشی؛ خروجی آخرین دستور (CSV) برای ابزار بعدی خالی است", "warn")
        else:
            self._log(run, f"SSH: خروجی آخرین دستور به‌صورت CSV: {len(rows)} ردیف، ستون‌ها: {', '.join(cols[:20])}")

    # ------------------------------------------------------------ ابزار اسکن شبکه
    def _scan_targets(self, run, inp, limit):
        from . import dnstool as dn
        src = inp.get("source", "prev")
        if src == "list":
            text, label = inp.get("text") or "", "لیست دستی"
        elif src in ("csv", "prev"):
            path, ips = None, []
            if src == "prev":
                prev = run.data.get("prev") or {}
                path, label = prev.get("path"), f"خروجی {prev.get('title', '—')}"
                if prev.get("ips") and not inp.get("column"):
                    path, ips = None, list(prev["ips"])
                if not path and not ips:
                    if prev.get("tool") in ("scan", "dns", "splunk", "abuse"):
                        return [], [], label     # ابزار قبلی نتیجه‌ای نداشت؛ اسکن انجام نمی‌شود (خطا نیست)
                    raise ConnectorError(f"ابزار قبلی ({prev.get('title', '—')}) خروجی قابل استفاده ندارد.")
            else:
                path = self._user_path(inp)
                if not path or not Path(path).is_file():
                    raise ConnectorError(f"فایل CSV پیدا نشد: {path or '(خالی)'}")
                label = f"فایل {Path(path).name}"
            if path:
                with atrest.open_read(path) as f:
                    rd = csv.DictReader(f)
                    cols = [(c or "").strip() for c in (rd.fieldnames or [])]
                    rows = list(rd)
                try:
                    col = dn.pick_column(cols, "ip", inp.get("column") or "")
                except dn.DnsError as e:
                    raise ConnectorError(f"اسکن: {e}")
                orig = next(c for c in (rd.fieldnames or []) if (c or "").strip() == col)
                ips = [r.get(orig) or "" for r in rows]
                label += f" (ستون {col})"
            if src == "prev" and not [x for x in ips if str(x).strip()]:
                return [], [], label
            text = "\n".join(ips)
        else:
            raise ConnectorError("منبع ورودی اسکن نامعتبر است.")
        try:
            targets, bad = dn.parse_ips(text, limit)
        except dn.DnsError as e:
            raise ConnectorError(f"اسکن: {e}")
        return targets, bad, label

    def _scan_baseline(self, run, mode, keys, scope=""):
        """مقایسه با نتیجه‌ی اجرای قبلی همین کار (فقط کارهای ذخیره‌شده). خروجی: (تازه، حذف‌شده، اولین بار؟)"""
        job = run.options.get("baseline_job")      # کار ذخیره‌شده (زمان‌بندی یا «اجرای الان»)
        if not job:
            return [], [], False
        d = paths.data_dir() / "scan_baselines"
        d.mkdir(exist_ok=True)
        safe = re.sub(r"[^A-Za-z0-9_-]", "", str(job))[:64] or "job"
        # مبنا به همان هدف‌ها و پورت‌ها بسته است؛ تغییر رنج یا پورت در کار، مبنای تازه می‌سازد (نه سیلی از «تازه»)
        f = d / (safe + "_" + hashlib.sha256(f"{job}|{run.cur['key']}|{mode}|{scope}".encode()).hexdigest()[:24] + ".dat")
        old = None
        if f.exists():
            try:
                old = set(json.loads(atrest.read_text(f)).get("keys") or [])
            except Exception:
                old = None
        atrest.write_text(f, json.dumps({"keys": sorted(keys), "at": time.time(), "job": job}))
        if old is None:
            return [], [], True
        return sorted(set(keys) - old), sorted(old - set(keys)), False

    @staticmethod
    def scan_opts(o):
        """گزینه‌های اسکن؛ کارهای ذخیره‌شده‌ی قبل از ادغام (mode کشف/پورت) به گزینه‌های تازه تبدیل می‌شوند."""
        if "ping" not in o and o.get("mode"):
            if o.get("mode") == "ports":
                return False, str(o.get("ports") or "common"), False
            return True, "443,80,22,445,3389", False      # کشف هاست قبلی = ping + چند پورت رایج
        return bool(o.get("ping")), str(o.get("ports") or "").strip(), bool(o.get("only_alive"))

    def _step_scan(self, run):
        from . import netscan as ns
        o = run.cur["opts"]
        st = self._st(run)
        cfg = dict(self.settings.get("scan") or {})
        do_ping, pspec, only_alive = self.scan_opts(o)
        if not do_ping and not pspec:
            raise ConnectorError("اسکن: Ping یا پورت‌ها را انتخاب کنید (هیچ‌کدام انتخاب نشده).")
        mode = "ports" if pspec else "discover"      # برای خلاصه و مبنا
        max_hosts = max(1, min(int(cfg.get("max_hosts") or 1024), ns.HARD_MAX_HOSTS))
        targets, bad, label = self._scan_targets(run, o.get("input") or {"source": "prev"}, max_hosts)
        if not targets and not bad and (o.get("input") or {}).get("source", "prev") == "prev":
            st["message"] = "ورودی از ابزار قبلی خالی بود؛ اسکن نشد"
            self._log(run, "اسکن: " + st["message"], "warn")
            run.summary["scan"] = {"mode": mode, "targets": 0, "denied": 0, "hosts": 0, "open": 0 if pspec else None,
                                   "new": 0, "gone": 0, "seconds": 0}
            run.data["out_ips"] = []
            return
        if bad:
            self._log(run, f"اسکن: {len(bad)} مقدار نامعتبر رد شد: {', '.join(bad[:10])}{' …' if len(bad) > 10 else ''}", "warn")
        nets, _ = ns.parse_networks(cfg.get("allowed_networks") if cfg.get("allowed_networks") is not None else ns.PRIVATE_DEFAULT)
        targets, denied = ns.split_allowed(targets, nets)
        if denied:
            self._log(run, f"اسکن: {len(denied)} آدرس خارج از رنج‌های مجاز اسکن است و رد شد: {', '.join(denied[:10])}"
                           f"{' …' if len(denied) > 10 else ''} (تنظیمات ← اسکن شبکه)", "warn")
        if not targets:
            raise ConnectorError(f"اسکن: هیچ آدرس مجازی در ورودی ({label}) نیست. رنج‌های مجاز در «تنظیمات ← اسکن شبکه».")
        timeout = float(o.get("timeout") or cfg.get("timeout") or 1.0)
        timeout = max(0.2, min(timeout, 10.0))
        workers = max(1, min(int(o.get("workers") or cfg.get("workers") or 100), ns.MAX_WORKERS))
        ports = []
        if pspec:
            try:
                ports = ns.parse_ports(pspec)
            except ns.ScanError as e:
                raise ConnectorError(f"اسکن: {e}")
            probes = len(targets) * len(ports)
            mx = max(1, min(int(cfg.get("max_probes") or 200000), ns.HARD_MAX_PROBES))
            if probes > mx:
                raise ConnectorError(f"اسکن: {len(targets)} هاست × {len(ports)} پورت = {probes} اتصال؛ سقف {mx} است. "
                                     "رنج یا پورت‌ها را کم کنید یا سقف را در تنظیمات بالا ببرید.")
        what = " + ".join((["Ping"] if do_ping else []) + ([f"{len(ports)} پورت"] if ports else []))
        self._log(run, f"اسکن: {what} روی {len(targets)} آدرس از {label}؛ هم‌زمان {workers}، timeout {timeout} ثانیه"
                       + ("؛ پورت‌ها فقط روی هاست‌های پاسخ‌دهنده به ping" if do_ping and only_alive and ports else ""))

        def prog(i, n, lbl):
            st["progress"] = [i, n]
            st["message"] = f"{lbl}: {i} از {n}"
        t0 = time.time()
        banners, http = bool(o.get("banners")) and bool(ports), bool(o.get("http")) and bool(ports)
        try:
            rows = (ns.demo_scan(targets, do_ping, ports, only_alive, banners, http) if self.demo
                    else ns.scan(targets, do_ping, ports, only_alive, timeout, workers, banners, http, run.cancel, prog))
        except InterruptedError:
            raise Cancelled()
        st["progress"] = None
        cols = [c for c in ns.SCAN_COLUMNS if (do_ping or c not in ("ping", "ping_ms"))
                and (ports or c in ("ip", "hostname", "ping", "ping_ms"))]
        cols += list(ns.HTTP_COLUMNS) if http else []
        ips = list(dict.fromkeys(r["ip"] for r in rows))
        open_rows = [r for r in rows if r.get("port") not in ("", None)]
        keys = [f"{r['ip']}:{r['port']}" for r in open_rows] if ports else ips
        inp0 = o.get("input") or {}
        scope = hashlib.sha256(json.dumps([inp0.get("source", "prev"), inp0.get("text", "") if inp0.get("source") == "list" else "",
                                           inp0.get("column", ""), ports, do_ping, only_alive], default=str).encode()).hexdigest()
        new, gone, first = self._scan_baseline(run, mode, keys, scope) if o.get("baseline") else ([], [], False)
        newset = set(new)
        for r in rows:
            k = f"{r['ip']}:{r['port']}" if ports else r["ip"]
            r["new"] = "yes" if k in newset else ""
        if o.get("baseline") and run.options.get("baseline_job"):
            cols.append("new")
        out = self._f(run, "scan.csv")
        with atrest.open_write(out) as f:
            w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
            w.writeheader()
            w.writerows(rows)
        sm = {"mode": mode, "targets": len(targets), "denied": len(denied), "hosts": len(ips),
              "open": len(open_rows) if ports else None, "new": len(new), "gone": len(gone), "seconds": round(time.time() - t0, 1)}
        run.summary["scan"] = sm
        run.data.setdefault("scan", {})[run.cur["key"]] = {"columns": cols, "rows": rows[:500], "total": len(rows), "mode": mode,
                                                         "new": new[:200], "gone": gone[:200]}
        run.data["out_path"], run.data["out_ips"] = str(out), ips
        st["message"] = f"{len(ips)} هاست روشن از {len(targets)}" + (f"، {len(open_rows)} پورت باز" if ports else "")
        self._log(run, f"اسکن: {st['message']} ({sm['seconds']} ثانیه)", "ok")
        if first:
            self._log(run, "اسکن: اولین اجرای این کار؛ نتیجه به‌عنوان مبنا (baseline) ذخیره شد", "info")
        if new or gone:
            kind = "پورت" if ports else "هاست"
            msg = (f"{len(new)} {kind} تازه: {', '.join(new[:20])}{' …' if len(new) > 20 else ''}" if new else "")
            if gone:
                msg += ("؛ " if msg else "") + f"{len(gone)} {kind} نسبت به قبل دیده نشد: {', '.join(gone[:20])}{' …' if len(gone) > 20 else ''}"
            self._log(run, "اسکن: " + msg, "warn")
            if new:
                self.notify("scan_new", f"کار «{run.options.get('job_name') or ''}» — اسکن شبکه: {msg}")
        self.store.add_history("scan", f"{len(targets)} آدرس", "ok", st["message"] + (f"؛ {len(new)} تازه" if new else ""),
                               run.id, str(out))

    # ------------------------------------------------------------ step 2: AbuseIPDB
    def _abuse_input(self, run):
        inp = self._inp(run, {"source": "prev"})
        src = inp.get("source", "prev")
        prev = run.data.get("prev") or {}
        if src == "prev" and prev.get("tool") in ("dns", "scan"):
            return list(prev.get("ips") or []), f"خروجی {prev.get('title')} (آدرس‌ها)"
        if src in ("prev", "splunk"):
            if "splunk_sources" not in run.data:
                raise ConnectorError("ورودی «خروجی Splunk» انتخاب شده ولی مرحله‌ی Splunk در این اجرا نیست.")
            if not run.data.get("splunk_has_src"):
                raise ConnectorError("خروجی Splunk ستون IP مبدأ (src_ip یا src) ندارد.")
            return list(run.data["splunk_sources"].keys()), "خروجی Splunk (ستون src)"
        if src == "list":
            ips = ab.extract_ips_from_text(inp.get("text", ""))
            return ips, "لیست دستی"
        if src == "csv":
            path = self._user_path(inp)
            if not path or not Path(path).is_file():
                raise ConnectorError(f"فایل CSV پیدا نشد: {path or '(خالی)'}")
            col = (inp.get("column") or "auto").strip()
            with atrest.open_read(path) as f:
                rows = list(csv.reader(f))
            header = [h.strip() for h in rows[0]] if rows else []
            if col == "auto":
                col = "src" if "src" in header else "all"
            ips, seen = [], set()
            if col == "all":
                cells = [c for r in rows for c in r]
                label = "همه‌ی ستون‌ها"
            else:
                if col not in header:
                    raise ConnectorError(f"ستون «{col}» در فایل نیست. ستون‌ها: {', '.join(header)}")
                i = header.index(col)
                cells = [r[i] for r in rows[1:] if len(r) > i]
                label = f"ستون {col}"
            for c in cells:
                for ip in ab.extract_ips_from_text(c):
                    if ip not in seen:
                        seen.add(ip)
                        ips.append(ip)
            return ips, f"فایل {Path(path).name} ({label})"
        raise ConnectorError("منبع ورودی AbuseIPDB نامعتبر است.")

    def _step_abuse(self, run):
        cfg_all = self.settings.conn_config("abuseipdb")
        threshold = int(cfg_all.get("threshold") or 0)
        cache_mode = cfg_all.get("cache_mode") or "forever"
        cache_days = float(cfg_all.get("cache_days") or 0)
        skip_wl = bool(cfg_all.get("skip_whitelisted"))
        force = bool(self._inp(run, {}).get("force"))
        use_cache = cache_mode != "never" and not force
        ignore_nets, _ = fg.parse_ignore(self.settings.get("fortigate", "ignore_networks", default=[]))
        ips, label = self._abuse_input(run)
        self._log(run, f"AbuseIPDB: {len(ips)}\u200f IP یکتا از {label}")
        stats = {"total": len(ips), "private": 0, "ignored": 0, "cached": 0, "checked": 0,
                 "abuse": 0, "clean": 0, "error": 0, "whitelisted": 0}
        todo, records = [], []
        cutoff = datetime.min if cache_mode == "forever" else datetime.now() - timedelta(days=cache_days)
        for ip in ips:
            if ab.should_skip_ip(ip):
                stats["private"] += 1
                continue
            if fg.is_ignored(ip, ignore_nets):
                stats["ignored"] += 1
                continue
            cached = self.store.get_ip(ip) if use_cache else None
            if cached and cached.get("abuse_status") in ("ABUSE", "CLEAN") and cached.get("checked_at"):
                try:
                    if datetime.strptime(cached["checked_at"], "%Y-%m-%d %H:%M:%S") >= cutoff:
                        rec = {k: cached.get(k) for k in CACHED_KEYS}
                        if rec.get("score") not in (None, "", "-"):
                            rec["abuse_status"] = "ABUSE" if int(rec["score"]) > threshold else "CLEAN"
                        else:  # ثبت دستی: وضعیت ذخیره‌شده ملاک است
                            rec["abuse_status"] = cached["abuse_status"]
                        rec["cached"] = True
                        records.append(rec)
                        stats["cached"] += 1
                        continue
                except ValueError:
                    pass
            todo.append(ip)
        cli = self._client("abuse", run) if todo else None
        if cli:
            cli.require_credentials()
            cli.base_url()
            # علامت «سهمیه تمام شده» برای هر کلید جداست (همان لینک)؛ چک مجدد دستی (force) همه را از اول امتحان می‌کند.
            # چند کلید: به ترتیب؛ اولین کلیدی که سهمیه‌اش تمام نشده استفاده می‌شود و با تمام شدنش، بعدی
            qmap = {} if force else _quota_map(self.store.meta("abuse_quota_until"))
            keys = cli.keys or [""]
            kfp = [_quota_fp(cfg_all, k) for k in keys]
            first = next((i for i, f in enumerate(kfp) if qmap.get(f, 0) <= time.time()), None)
            if first is None:
                cli.quota_reset_at = min(qmap.get(f, 0) for f in kfp)
                self._log(run, f"AbuseIPDB: سهمیه‌ی {'همه‌ی ' + str(len(keys)) + ' کلید' if len(keys) > 1 else 'این کلید'} "
                               f"تا حدود {datetime.fromtimestamp(cli.quota_reset_at):%H:%M} تمام است؛ درخواستی فرستاده نمی‌شود", "warn")
            elif cli.keys:
                if first:
                    self._log(run, f"AbuseIPDB: سهمیه‌ی {first} کلید اول تمام است؛ از کلید {first + 1} از {len(keys)} شروع می‌شود")
                cli.use_key(first)
            elif len(keys) > 1:
                self._log(run, f"AbuseIPDB: {len(keys)} کلید API به ترتیب استفاده می‌شوند")
            # اگر سهمیه کمتر از تعداد IPها باشد، IPهای پرحمله‌تر زودتر بررسی شوند
            counts = {ip: (d or {}).get("attack_count") or 0 for ip, d in (run.data.get("splunk_sources") or {}).items()}
            if counts:
                todo.sort(key=lambda x: -int(counts.get(x) or 0))
        quota_left = []

        def next_key():
            """سهمیه‌ی کلید فعلی تمام شد: ثبت، و رفتن به کلید بعدی که سهمیه دارد. False اگر نماند."""
            k = cli.key_idx if cli.keys else 0
            qmap[kfp[k]] = max(cli.quota_reset_at, time.time() + 60)
            self.store.set_meta("abuse_quota_until", json.dumps({"keys": qmap}))
            for j in range(k + 1, len(kfp)):
                if qmap.get(kfp[j], 0) <= time.time():
                    self._log(run, f"AbuseIPDB: سهمیه‌ی کلید {k + 1} تمام شد؛ ادامه با کلید {j + 1} از {len(kfp)}", "warn")
                    cli.use_key(j)
                    return True
            return False
        try:
            i = 0
            while i < len(todo):
                ip = todo[i]
                if cli.quota_exhausted():
                    quota_left = todo[i:]
                    break
                self._st(run)["progress"] = [i + 1, len(todo)]
                self._st(run)["message"] = f"بررسی {i + 1} از {len(todo)}: {ip}" + (
                    f" (کلید {cli.key_idx + 1})" if len(cli.keys) > 1 else "")
                res = cli.check_ip(ip, log=lambda m, lv="warn": self._log(run, "AbuseIPDB: " + m, lv))
                if res.get("quota"):
                    if next_key():
                        continue          # همین IP با کلید بعدی
                    quota_left = todo[i:]
                    break
                i += 1
                rec = ab.result_to_record(ip, res, threshold)
                records.append(rec)
                stats["checked"] += 1
                if rec["abuse_status"] == "ERROR":
                    self._log(run, f"{ip} → خطا: {rec['error']}", "error")
                elif rec["abuse_status"] == "ABUSE":
                    self._log(run, f"{ip} → مخرب | امتیاز {rec['score']} | {rec['reports']} گزارش | {rec['country_code']}", "warn")
                else:
                    self._log(run, f"{ip} → غیرمخرب | امتیاز {rec['score']}", "info")
                if i < len(todo):
                    cli.pause_between()
        except BaseException:
            # لغو یا خطای پیش‌بینی‌نشده: نتیجه‌هایی که تا این لحظه گرفته شده از دست نروند
            with self.store.batch():
                for rec in records:
                    if not rec.get("cached"):
                        self.store.upsert_ip(rec["ip"], last_run=run.id,
                                             **{k: v for k, v in rec.items() if k not in ("cached", "note", "ip", "route")})
            raise
        if quota_left:
            until = max(cli.quota_reset_at, time.time() + 60)
            if cli.keys:
                qmap[kfp[cli.key_idx]] = until
                until = min(qmap.get(f, until) for f in kfp)   # زودترین ریست بین همه‌ی کلیدها
            self.store.set_meta("abuse_quota_until", json.dumps({"keys": qmap}))
            kept = 0
            for ip in quota_left:
                cur = self.store.get_ip(ip)
                if cur and cur.get("abuse_status") in ("ABUSE", "CLEAN"):
                    # نتیجه‌ی قبلی (حتی اگر از اعتبار کش گذشته باشد) دست نمی‌خورد و مثل قبل استفاده می‌شود
                    rec = {k: cur.get(k) for k in CACHED_KEYS}
                    rec["abuse_status"], rec["cached"] = cur["abuse_status"], True
                    kept += 1
                else:
                    rec = ab.result_to_record(ip, {"success": False, "data": {}, "error": ab.QUOTA_ERR}, threshold)
                records.append(rec)
            if kept:
                self._log(run, f"AbuseIPDB: برای {kept}\u200f IP از آن‌ها نتیجه‌ی قبلی در دیتابیس بود و همان استفاده شد", "info")
            stats["quota_skipped"] = len(quota_left)
            run.summary["abuse_quota_skipped"] = len(quota_left)
            self._log(run, f"AbuseIPDB: سهمیه‌ی روزانه تمام شد؛ {len(quota_left)}\u200f IP بررسی نشد و با وضعیت خطا "
                           f"(«{ab.QUOTA_ERR}») ذخیره شد. چک مجدد خودکار آن‌ها را برنمی‌دارد؛ بعد از ریست سهمیه "
                           f"(حدود {datetime.fromtimestamp(until):%Y-%m-%d %H:%M}) از صفحه‌ی آدرس‌ها دستی بررسی کنید. "
                           "بقیه‌ی مراحل با IPهای بررسی‌شده ادامه پیدا می‌کند.", "warn")
            self.notify("abuse_quota", f"سهمیه‌ی روزانه‌ی AbuseIPDB تمام شد؛ {len(quota_left)} IP بررسی نشد (اجرای {run.id}).")
        if cli and cli.rate:
            run.summary["abuse_rate"] = cli.rate
            self.store.set_meta("abuse_rate", json.dumps(cli.rate))

        malicious, clean, errors = [], [], []
        clean_foreign, clean_review = [], []
        stats.update(clean_foreign=0, clean_home=0, clean_unknown=0)
        with self.store.batch():   # یک تراکنش برای همه‌ی نتیجه‌ها (بعد از پایان درخواست‌های شبکه)
            for rec in records:
                st = rec["abuse_status"]
                wl = str(rec.get("is_whitelisted")) == "True"
                if wl:
                    stats["whitelisted"] += 1
                if st == "ABUSE" and skip_wl and wl:
                    rec["note"] = "Whitelisted در AbuseIPDB؛ بلاک نمی‌شود"
                    st = "CLEAN"
                if st == "ABUSE":
                    malicious.append(rec["ip"])
                    stats["abuse"] += 1
                elif st == "CLEAN":
                    clean.append(rec["ip"])
                    stats["clean"] += 1
                    # غیرمخرب‌ها (از هر کشوری) هرگز بلاک نمی‌شوند؛ فقط برای بررسی دستی
                    rec["route"] = "review"
                    clean_review.append(rec["ip"])
                else:
                    errors.append(rec["ip"])
                    stats["error"] += 1
                fields = {k: v for k, v in rec.items() if k not in ("cached", "note", "ip")}
                fields.update(last_run=run.id)
                if st == "ABUSE":
                    rec["route"] = "block"
                elif st == "ERROR":
                    rec["route"] = "error"
                prev = self.store.get_ip(rec["ip"]) or {}
                if rec.get("route") == "review":
                    if prev.get("review") != "reviewed":
                        fields["review"] = "pending"
                elif prev.get("review") == "pending":
                    fields["review"] = ""
                self.store.upsert_ip(rec["ip"], **fields)

        now_ts = time.time()
        self.store.add_stats([(now_ts, "abuse", r["abuse_status"], r["ip"], r.get("country_code") or "",
                               r.get("isp") or "", "cache" if r.get("cached") else "online") for r in records])
        stats["repeat"] = self._repeat_check(run, records)
        stats["clean_to_block"] = len(clean_foreign)
        stats["clean_to_review"] = len(clean_review)
        report = self._f(run, "abuse_report.csv")
        with atrest.open_write(report) as f:
            w = csv.writer(f)
            w.writerow(ab.REPORT_HEADERS)
            w.writerows(ab.record_to_report_row(r) for r in records)
        with atrest.open_write(self._f(run, "malicious.csv")) as f:
            w = csv.writer(f)
            w.writerow(["IP", "Reason"])
            w.writerows([[ip, "ABUSE"] for ip in malicious] + [[ip, "CLEAN-FOREIGN"] for ip in clean_foreign])
        run.data.update(abuse_records=records, malicious=malicious, clean=clean, abuse_errors=errors,
                        clean_foreign=clean_foreign, clean_review=clean_review, abuse_report=str(report))
        # خروجی برای ابزار بعدی (SSH، DNS، اسکن، ...): فقط IPهای مخرب؛ غیرمخرب و خطا هرگز به ابزار بعدی نمی‌روند
        mal_report = self._f(run, "malicious_report.csv")
        with atrest.open_write(mal_report) as f:
            w = csv.writer(f)
            w.writerow(ab.REPORT_HEADERS)
            w.writerows(ab.record_to_report_row(r) for r in records if r.get("abuse_status") == "ABUSE")
        run.data["out_path"], run.data["out_ips"] = str(mal_report), list(run.data.get("malicious") or [])
        self._abuse_export(run, records)
        run.summary["abuse"] = stats
        self._st(run)["progress"] = None
        self._st(run)["message"] = (f"{stats['abuse']} مخرب، {stats['clean']} غیرمخرب، "
                                          f"{stats['error']} خطا، از کش: {stats['cached']}")
        self._log(run, "AbuseIPDB: " + self._st(run)["message"], "ok")
        self.store.add_history("abuse", f"{stats['total']}\u200f IP", "ok" if not stats["error"] else "warn",
                               self._st(run)["message"], run.id, str(report))

    def _abuse_export(self, run, records):
        """1.28: نتیجه‌ی همین اسکن، بدون رمز، در پوشه‌ی انتخابی کاربر (abuse_latest.csv؛ هر بار بازنویسی، اتمی).
        خطا اجرا را متوقف نمی‌کند؛ فقط هشدار در گزارش."""
        import os
        import tempfile
        from . import csvsafe
        cfg = self.settings.get("abuseipdb") or {}
        d = str(cfg.get("export_dir") or "").strip()
        if not cfg.get("export_enabled") or not d:
            return
        target = Path(d) / "abuse_latest.csv"
        tmp = None
        try:
            if not Path(d).is_dir():
                raise OSError(f"پوشه‌ی «{d}» وجود ندارد")
            if target.is_symlink():
                raise OSError("abuse_latest.csv یک لینک (symlink) است؛ بازنویسی نمی‌شود")
            fd, tmp = tempfile.mkstemp(prefix=".abuse_latest_", suffix=".tmp", dir=d)
            with os.fdopen(fd, "w", encoding="utf-8-sig", newline="") as f:     # BOM برای Excel
                w = csv.writer(f)
                w.writerow(ab.REPORT_HEADERS + ["Run"])
                w.writerows(csvsafe.row(ab.record_to_report_row(r) + [run.id]) for r in records)
            os.replace(tmp, target)
            tmp = None
            self._log(run, f"AbuseIPDB: نتیجه‌ی {len(records)}\u200f IP بدون رمز در {target} ذخیره شد")
        except OSError as e:
            self._log(run, f"AbuseIPDB: ذخیره‌ی خروجی بی‌رمز در «{d}» ناموفق بود: {e}", "warn")
        finally:
            if tmp:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass

    def _repeat_check(self, run, records):
        """هشدار تکرار: IP غیرمخرب و بلاک‌نشده‌ای که در N روزِ مختلف به AbuseIPDB رسیده (آنلاین یا از کش)،
        و بعد از آن هر N روز دیگر. خروجی: تعداد هشدارها."""
        n = int(self.settings.get("abuseipdb", "repeat_days", default=5) or 0)
        clean = [r["ip"] for r in records if r.get("abuse_status") == "CLEAN"]
        if n <= 0 or not clean:
            return 0
        days = self.store.seen_days(clean)
        done = self.store.repeat_alerts(clean)
        hits = []
        for ip in clean:
            d = (days.get(ip) or (0,))[0]
            if d < n or d < (done.get(ip) or 0) + n:
                continue
            cur = self.store.get_ip(ip) or {}
            if cur.get("fw_status") in ("banned", "already"):
                continue
            hits.append((ip, d))
        if not hits:
            return 0
        self.store.set_repeat_alerts(hits)
        for ip, d in hits[:200]:
            self.store.add_history("abuse", ip, "warn", f"IP غیرمخرب در {d} روز مختلف دوباره دیده شد؛ نیاز به بررسی مجدد", run.id)
        sample = "، ".join(f"{ip} ({d} روز)" for ip, d in hits[:20]) + (" …" if len(hits) > 20 else "")
        self._log(run, f"AbuseIPDB: {len(hits)}\u200f IP غیرمخرب در {n} روز یا بیشتر تکرار شده‌اند و نیاز به بررسی مجدد دارند (آمار ← IPهای تکراری): {sample}",
                  "warn", "repeat")
        self.notify("abuse_repeat", f"اجرای {run.id}: {len(hits)} IP غیرمخرب و بلاک‌نشده در {n} روز یا بیشتر دوباره دیده شده‌اند "
                                    "و نیاز به بررسی مجدد دارند (آمار ← IPهای تکراری):\n"
                    + "\n".join(f"- {ip}: {d} روز" for ip, d in hits[:50]))
        return len(hits)

    # ------------------------------------------------------------ ابزار «بررسی تکمیلی»
    INTEL_COLS = ["ip", "result", "source", "score", "confirmations", "category", "type", "detail"]

    def _intel_input(self, run):
        inp = self._inp(run, {"source": "prev"})
        src = inp.get("source", "prev")
        prev = run.data.get("prev") or {}
        if src == "prev" and prev.get("tool") == "abuse":
            return list(run.data.get("clean") or []), "غیرمخرب‌های AbuseIPDB"
        if src == "db":
            rows = self.store.ips_by_status(("CLEAN",), "ip, fw_status")
            return [r["ip"] for r in rows if r.get("fw_status") not in ("banned", "already")], "غیرمخرب‌های دیتابیس"
        return self._abuse_input(run)      # Splunk/DNS/اسکن قبلی، لیست یا CSV: همان خواندن ورودی AbuseIPDB

    def _step_intel(self, run):
        from . import intel
        cfg = dict(self.settings.get("intel") or {})
        use_feed, use_local = bool(cfg.get("feed_enabled", True)), bool(cfg.get("local_enabled"))
        if not use_feed and not use_local:
            raise ConnectorError("بررسی تکمیلی: هیچ منبعی (فید آنلاین یا لیست داخلی) روشن نیست (تنظیمات ← بررسی تکمیلی).")
        ips, label = self._intel_input(run)
        st = self._st(run)
        nets, _ = fg.parse_ignore(self.settings.get("fortigate", "ignore_networks", default=[]))
        targets, skipped = [], 0
        for ip in dict.fromkeys(ips):
            if fg.is_excluded(ip, nets):
                skipped += 1
            else:
                targets.append(ip)
        self._log(run, f"بررسی تکمیلی: {len(targets)}\u200f IP از {label}" + (f" ({skipped} خصوصی/مستثنا رد شد)" if skipped else ""))
        sm = {"total": len(targets), "skipped": skipped, "malicious": 0, "feed": 0, "local": 0, "clean": 0}
        if not targets:
            st["message"] = "ورودی خالی بود؛ بررسی‌ای انجام نشد"
            self._log(run, "بررسی تکمیلی: " + st["message"], "warn")
            run.summary["intel"] = sm
            run.data["out_path"], run.data["out_ips"] = None, []
            return
        feed_hits, local_hits, sources = {}, {}, []
        try:
            if use_feed:
                st["message"] = "دریافت فید آنلاین"
                if self.demo:
                    feed_hits = {ip: {"ip": ip, "score": 90, "confirmations": 12, "category": "brute_force", "type": "datacenter"}
                                 for ip in targets if sum(int(x) for x in ip.split(".") if x.isdigit()) % 5 == 0}
                    self._log(run, "بررسی تکمیلی (Demo): فید نمایشی؛ چیزی دانلود نشد", "warn")
                else:
                    meta, note = intel.update_feed(cfg, run.cancel, logf=lambda m, lv="info": self._log(run, "بررسی تکمیلی: " + m, lv))
                    self._log(run, f"بررسی تکمیلی: {note}")
                    feed_hits = intel.feed_lookup(targets, int(cfg.get("min_score") or 0))
                sources.append("FFraud")
            if use_local:
                lips, lnets, ldesc, bad = intel.load_local(cfg)
                if bad:
                    self._log(run, f"بررسی تکمیلی: {len(bad)} خط نامعتبر در لیست داخلی نادیده گرفته شد (مثلاً {bad[0]})", "warn")
                self._log(run, f"بررسی تکمیلی: لیست داخلی — {ldesc}: {len(lips)}\u200f IP و {len(lnets)} رنج")
                for ip in targets:
                    m = intel.local_match(ip, lips, lnets)
                    if m:
                        local_hits[ip] = m
                sources.append("لیست داخلی")
        except InterruptedError:
            raise Cancelled()
        except intel.IntelError as e:
            raise ConnectorError(f"بررسی تکمیلی: {e}")
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        rows, mal = [], []
        with self.store.batch():
            for ip in targets:
                f, lo = feed_hits.get(ip), local_hits.get(ip)
                if f:
                    det = f"امتیاز {f['score']}، {f['confirmations']} تأیید" + (f"، {f['category']}" if f["category"] else "") \
                          + (f"/{f['type']}" if f["type"] else "") + (f"؛ لیست داخلی: {lo}" if lo else "")
                    row = {"ip": ip, "result": "ABUSE", "source": "FFraud" + (" + لیست داخلی" if lo else ""), "score": f["score"],
                           "confirmations": f["confirmations"], "category": f["category"], "type": f["type"], "detail": det}
                    sm["feed"] += 1
                elif lo:
                    det = "در لیست داخلی" + (f" (رنج {lo})" if lo != ip else "")
                    row = {"ip": ip, "result": "ABUSE", "source": "لیست داخلی", "score": "", "confirmations": "",
                           "category": "", "type": "", "detail": det}
                    sm["local"] += 1
                else:
                    row = {"ip": ip, "result": "CLEAN", "source": "", "score": "", "confirmations": "", "category": "", "type": "",
                           "detail": "در " + " و ".join(sources) + " نبود"}
                    sm["clean"] += 1
                if row["result"] == "ABUSE":
                    mal.append(ip)
                rows.append(row)
                fields = {"intel_status": row["result"], "intel_source": row["source"] or "+".join(sources),
                          "intel_detail": row["detail"], "intel_at": now, "last_run": run.id}
                if not self.store.get_ip(ip):
                    fields["source"] = "intel"
                self.store.upsert_ip(ip, **fields)
        sm["malicious"] = len(mal)
        self.store.add_stats([(time.time(), "intel", r["result"], r["ip"], "", "", r["source"] or "clean") for r in rows])
        report = self._f(run, "intel_report.csv")
        with atrest.open_write(report) as fh:
            w = csv.DictWriter(fh, fieldnames=self.INTEL_COLS)
            w.writeheader()
            w.writerows(rows)
        mal_f = self._f(run, "intel_malicious.csv")
        with atrest.open_write(mal_f) as fh:
            w = csv.DictWriter(fh, fieldnames=self.INTEL_COLS)
            w.writeheader()
            w.writerows(r for r in rows if r["result"] == "ABUSE")
        run.data.setdefault("intel", {})[run.cur["key"]] = {"rows": sorted(rows, key=lambda r: r["result"] != "ABUSE")[:500],
                                                           "total": len(rows), "sources": sources}
        # خروجی برای ابزار بعدی (FortiGate، SSH، ...): فقط مخرب‌ها
        run.data["out_path"], run.data["out_ips"] = str(mal_f), mal
        run.summary["intel"] = sm
        st["message"] = f"{sm['malicious']} مخرب (فید {sm['feed']}، لیست داخلی {sm['local']})، {sm['clean']} پاک"
        self._log(run, "بررسی تکمیلی: " + st["message"], "warn" if mal else "ok")
        if mal:
            self._log(run, "بررسی تکمیلی: مخرب‌ها — " + "، ".join(mal[:30]) + (" …" if len(mal) > 30 else ""), "warn")
        self.store.add_history("intel", f"{len(targets)}\u200f IP", "warn" if mal else "ok", st["message"], run.id, str(report))

    # ------------------------------------------------------------ step 3: FortiGate
    def _fw_input(self, run, max_expand):
        inp = self._inp(run, {"source": "prev"})
        src = inp.get("source", "prev")
        prev = run.data.get("prev") or {}
        if src == "prev" and prev.get("tool") == "intel":
            ips = list(prev.get("ips") or [])
            run.data["fw_origin"] = {ip: "intel" for ip in ips}
            return ips, [], "مخرب‌های بررسی تکمیلی"
        if src in ("prev", "abuse"):
            if "malicious" not in run.data:
                raise ConnectorError("ورودی «IPهای مخرب» انتخاب شده ولی مرحله‌ی AbuseIPDB در این اجرا نیست.")
            if run.data.get("abuse_errors"):
                self._log(run, f"FortiGate: {len(run.data['abuse_errors'])}\u200f IP که بررسی‌شان خطا داد ارسال نمی‌شوند", "warn")
            run.data["fw_origin"] = {ip: "abuse" for ip in run.data["malicious"]}
            return list(run.data["malicious"]), [], "IPهای مخرب AbuseIPDB"
        if src == "db":
            cfg = self.settings.conn_config("abuseipdb")
            origin, skipped = {}, 0
            for r in self.store.ips_by_status(("ABUSE", "CLEAN"), "ip, abuse_status, is_whitelisted, score"):
                why = block_reason(r, cfg)
                if why:
                    origin[r["ip"]] = why
                elif r.get("abuse_status") in ("ABUSE", "CLEAN"):
                    skipped += 1
            run.data["fw_origin"] = origin
            self._log(run, f"FortiGate: از کل دیتابیس {len(origin)}\u200f IP مخرب انتخاب شد؛ "
                           f"{skipped} مورد طبق قانون فعلی بلاک‌شدنی نیست (غیرمخرب/Whitelisted)")
            return list(origin), [], "کل دیتابیس"
        if src == "list":
            values = [v for line in (inp.get("text") or "").splitlines() for v in line.replace(",", " ").split()]
            t, notes = fg.expand_targets(values, max_expand)
            return t, notes, "لیست دستی"
        if src == "csv":
            path = self._user_path(inp)
            if not path or not Path(path).is_file():
                raise ConnectorError(f"فایل CSV پیدا نشد: {path or '(خالی)'}")
            with atrest.open_read(path) as f:
                values = [row[0].strip() for row in csv.reader(f) if row]
            t, notes = fg.expand_targets(values, max_expand)
            return t, notes, f"فایل {Path(path).name} (ستون اول)"
        raise ConnectorError("منبع ورودی FortiGate نامعتبر است.")

    def _fw_target(self, run):
        """1.28: دستگاه و تسک انتخاب‌شده در گام FortiGate. خروجی: (conn, نام دستگاه, تسک یا None, چند دستگاهی؟)"""
        from . import fgtask
        opts = (run.cur or {}).get("opts", {}) or {}
        devs = {d["conn"]: d["name"] for d in self.settings.fg_devices()}
        conn = str(opts.get("device") or "fortigate")
        if conn not in devs:
            raise ConnectorError("دستگاه FortiGate انتخاب‌شده برای این گام دیگر وجود ندارد؛ گام را ویرایش و دستگاه دیگری انتخاب کنید.")
        sid = str(opts.get("scenario") or "")
        sc = None
        if sid:
            sc = next((x for x in self.settings.get("fg_scenarios", default=[]) or [] if x.get("id") == sid), None)
            if not sc:
                raise ConnectorError("تسک (سناریوی) انتخاب‌شده برای گام FortiGate حذف شده است؛ گام را ویرایش کنید.")
            sc = fgtask.validate(sc)
        return conn, devs[conn], sc, len(devs) > 1

    # ------------------------------------------------------------ 1.29: جدول ورودی (خط اول = نام ستون‌ها)
    @staticmethod
    def _looks_ip(v):
        import ipaddress
        try:
            ipaddress.ip_network(str(v).strip(), strict=False)
            return True
        except ValueError:
            return False

    def _parse_table(self, lines, label):
        """متن CSV (خط اول نام ستون‌ها). اگر خانه‌ی اول خط اول IP/CIDR باشد، جدول بدون سرتیتر فرض و ستون اول «ip» می‌شود."""
        lines = [l for l in lines if l.strip()]
        if not lines:
            return [], []
        head = lines[0]
        delim = "\t" if "\t" in head else (";" if head.count(";") > head.count(",") else ",")
        rd = list(csv.reader(lines, delimiter=delim))
        if self._looks_ip(rd[0][0]):
            n = max(len(r) for r in rd)
            cols = ["ip"] + [f"col{i}" for i in range(2, n + 1)]
            body = rd
        else:
            cols = [(c or "").strip() or f"col{i}" for i, c in enumerate(rd[0], 1)]
            seen = set()
            for i, c in enumerate(cols):            # نام تکراری ← c_2
                k, j = c, 2
                while k in seen:
                    k, j = f"{c}_{j}", j + 1
                cols[i] = k
                seen.add(k)
            body = rd[1:]
        rows = [{c: (r[i].strip() if i < len(r) else "") for i, c in enumerate(cols)} for r in body if any(x.strip() for x in r)]
        if len(rows) > 50000:
            raise ConnectorError(f"{label}: بیش از ۵۰ هزار ردیف.")
        return rows, cols

    def _table_input(self, run, inp):
        """ردیف‌های جدول ورودی تسک: خروجی ابزار قبلی، لیست (خط اول نام ستون‌ها) یا CSV. خروجی: (rows, columns, label)"""
        src = inp.get("source", "prev")
        if src == "list":
            rows, cols = self._parse_table((inp.get("text") or "").splitlines(), "لیست")
            return rows, cols, "لیست دستی"
        if src == "csv":
            path = self._user_path(inp)
            if not path or not Path(path).is_file():
                raise ConnectorError(f"فایل CSV پیدا نشد: {path or '(خالی)'}")
            with atrest.open_read(path) as f:
                text = f.read()
            rows, cols = self._parse_table(text.lstrip("\ufeff").splitlines(), "CSV")
            return rows, cols, f"فایل {Path(path).name}"
        if src == "prev":
            prev = run.data.get("prev") or {}
            if not prev:
                raise ConnectorError("ابزاری پیش از این گام نیست؛ ورودی را «لیست» یا «CSV» انتخاب کنید.")
            label = f"خروجی {prev.get('title', '—')}"
            if prev.get("path") and Path(prev["path"]).is_file():
                with atrest.open_read(prev["path"]) as f:
                    rd = csv.DictReader(f)
                    cols = [(c or "").strip().lstrip("\ufeff") for c in (rd.fieldnames or [])]
                    rows = [{(k or "").strip().lstrip("\ufeff"): ("" if v is None else str(v)) for k, v in r.items() if k is not None}
                            for r in rd]
                if len(rows) > 50000:
                    raise ConnectorError(f"{label}: بیش از ۵۰ هزار ردیف.")
                return rows, cols, label
            ips = list(prev.get("ips") or [])
            return [{"ip": ip} for ip in ips], ["ip"], label
        if src == "db":
            cfg = self.settings.conn_config("abuseipdb")
            rows = [{"ip": r["ip"], "abuse_status": r.get("abuse_status") or "", "score": str(r.get("score") or "")}
                    for r in self.store.ips_by_status(("ABUSE", "CLEAN"), "ip, abuse_status, is_whitelisted, score")
                    if block_reason(r, cfg)]
            return rows, ["ip", "abuse_status", "score"], "IPهای مخرب دیتابیس"
        raise ConnectorError("منبع ورودی نامعتبر است.")

    def _fw_task(self, run, cli, task, devname, multi, tag):
        """1.29: تسک پایتونی: plan در فرایند جدا ← تأیید کارها ← ارسال فقط کارهای تأییدشده (حالت تست: هیچ)."""
        from . import fgtask
        st = self._st(run)
        inp = self._inp(run, {"source": "prev"})
        rows, cols, label = self._table_input(run, inp)
        code_sha = fgtask.sha(task["code"])
        self._log(run, f"FortiGate: تسک «{task['name']}» (sha {code_sha[:12]})؛ {len(rows)} ردیف از {label}"
                       + (f"؛ ستون‌ها: {', '.join(cols[:20])}" if cols else ""))
        st["message"] = "اجرای plan تسک"
        ctx = {"device": devname, "vdom": cli.vdom, "run": run.id, "columns": cols, "test": self._test_mode(),
               "ignore_networks": list(cli.cfg.get("ignore_networks") or [])}
        try:
            actions, _logs = fgtask.plan(cli, task, rows, ctx, cancel=run.cancel,
                                         log=lambda m: self._log(run, f"FortiGate (تسک): {m[:1000]}"))
        except fgtask.TaskError as e:
            if run.cancel.is_set():
                raise Cancelled()
            raise ConnectorError(f"تسک «{task['name']}»: {e}")
        self._log(run, f"FortiGate: تسک {len(actions)} کار پیشنهاد کرد")
        summary = {"rows": len(rows), "actions": len(actions), "done": 0, "failed": 0, "skipped": 0, "rejected": 0, "test": 0,
                   "device": devname if multi else "", "task": task["name"]}
        approved = []
        test = False
        if actions:
            auto = self._auto_allowed(run, "auto_ban")
            cap = int(run.options["max_auto_ban"] if "max_auto_ban" in run.options
                      else self.settings.get("automation", "daily", "max_auto_ban", default=50) or 0)
            if auto and cap and len(actions) > cap:
                auto = False
                self._log(run, f"FortiGate: {len(actions)} کار، بیشتر از سقف اجرای بدون تأیید ({cap})؛ منتظر تأیید دستی", "warn")
            test_pv = self._test_mode()
            st["message"] = f"پیش‌نمایش آماده است: {len(actions)} کار"
            pv = {"task": {"name": task["name"], "note": task.get("note", ""), "sha": code_sha[:12], "on_error": task["on_error"]},
                  "actions": actions[:2000], "actions_total": len(actions), "rows_total": len(rows), "columns": cols[:50],
                  "device": devname, "multi": multi, "test_mode": test_pv}
            dec = self._wait_approval(run, "fortigate", pv, auto)
            if dec["approve"]:
                sel = dec["payload"].get("acts")
                sel = set(int(i) for i in sel) if isinstance(sel, list) else None
                approved = [a for a in actions if sel is None or a["i"] in sel]
            else:
                self._log(run, "FortiGate: اجرای تسک توسط کاربر رد شد", "warn")
            test = self._test_mode() or test_pv
        approved_i = {a["i"] for a in approved}
        results = []
        if test and approved:
            body = json.dumps([{k: a[k] for k in ("method", "path", "body")} for a in approved[:200]], ensure_ascii=False)
            self._log(run, f"FortiGate (حالت تست): {len(approved)} کار ارسال نشد؛ درخواست‌ها ({min(200, len(approved))} اول): {body[:20000]}", "warn")
            self.store.add_history("fortigate", f"{len(approved)} کار", "test", f"حالت تست — تسک «{task['name']}»{tag}", run.id, str(run.dir))
            done_map = {a["i"]: {**a, "result": "test", "detail": "حالت تست"} for a in approved}
            summary["test"] = len(approved)
        elif approved:
            st["message"] = f"ارسال {len(approved)} کار"
            n = [0]

            def prog(r):
                n[0] += 1
                st["progress"] = [n[0], len(approved)]
                lvl = {"done": "ok", "failed": "error"}.get(r["result"], "warn")
                if r["result"] != "done" or n[0] <= 200:
                    self._log(run, f"{r['method']} {r['path']} → {r['result']}" + (f": {r['detail'][:300]}" if r["result"] != "done" else ""),
                              lvl, "ban")
            res = fgtask.apply(cli, approved, task["on_error"], run.cancel, prog)
            st["progress"] = None
            done_map = {r["i"]: r for r in res}
        else:
            done_map = {}
        for a in actions:
            r = done_map.get(a["i"]) or {**a, "result": "rejected" if a["i"] not in approved_i else "skipped", "detail": ""}
            results.append(r)
        for k in ("done", "failed", "skipped", "rejected"):
            summary[k] = sum(1 for r in results if r["result"] == k)
        by = APPROVED_TXT.get(run.data.get("approved_by", {}).get("fortigate"), "تأیید دستی")
        if summary["done"] or summary["failed"]:
            self.store.add_history("fortigate", f"{summary['done']} کار", "ok" if not summary["failed"] else "warn",
                                   f"تسک «{task['name']}» (sha {code_sha[:12]}، {by}){tag}: انجام {summary['done']}، ناموفق {summary['failed']}",
                                   run.id, str(run.dir))
            for r in [x for x in results if x["result"] == "failed"][:100]:
                self.store.add_history("fortigate", f"{r['method']} {r['path']}"[:200], "error", f"{r['detail']}{tag}"[:1000], run.id)
        if summary["failed"]:
            bad = [f"- {r['method']} {r['path']}: {r['detail'][:150]}" for r in results if r["result"] == "failed"][:30]
            self.notify("ban_failed", f"اجرای {run.id}: تسک «{task['name']}» در FortiGate — {summary['failed']} کار ناموفق\n" + "\n".join(bad))
        # گزارش و خروجی برای ابزار بعدی: هر کار یک ردیف (+ ستون‌های ردیف ورودی همان کار)
        rcols = []
        for r in results:
            for k in (r.get("row") or {}):
                if k not in rcols and k not in ("Method", "Path", "Note", "Result", "Detail"):
                    rcols.append(k)
        f = self._f(run, "fortigate_actions.csv")
        with atrest.open_write(f) as fh:
            w = csv.writer(fh)
            w.writerow(["Method", "Path", "Note", "Result", "Detail"] + rcols)
            w.writerows([r["method"], r["path"], r.get("note", ""), r["result"], r.get("detail", "")]
                        + [(r.get("row") or {}).get(c, "") for c in rcols] for r in results)
        run.data["fw_report"] = str(f)
        run.data["fw_actions"] = [{k: r.get(k) for k in ("i", "method", "path", "note", "result", "detail", "row")} for r in results]
        ok_rows = [r for r in results if r["result"] in ("done", "test")]
        later = run.items[run.items.index(run.cur) + 1:] if run.cur in run.items else []
        if later:
            fo = self._f(run, "fortigate_done.csv")
            with atrest.open_write(fo) as fh:
                w = csv.writer(fh)
                w.writerow(["Method", "Path", "Note", "Result"] + rcols)
                w.writerows([r["method"], r["path"], r.get("note", ""), r["result"]] + [(r.get("row") or {}).get(c, "") for c in rcols]
                            for r in ok_rows)
            run.data["out_path"] = str(fo)
        ips = []
        for r in ok_rows:
            ip = (r.get("row") or {}).get("ip") or (r.get("row") or {}).get("IP") or (r.get("row") or {}).get("src")
            if ip and ip not in ips:
                ips.append(ip)
        run.data["out_ips"] = ips
        run.summary["fortigate"] = summary
        msg = (f"تسک «{task['name']}»: {len(actions)} کار، انجام‌شده {summary['done']}"
               + (f" (تست: {summary['test']})" if summary["test"] else "")
               + (f"، ناموفق {summary['failed']}" if summary["failed"] else "")
               + (f"، رد/ارسال‌نشده {summary['rejected'] + summary['skipped']}" if summary["rejected"] + summary["skipped"] else "") + tag)
        st["message"] = msg
        self._log(run, "FortiGate: " + msg, "ok" if not summary["failed"] else "warn")

    def _step_fortigate(self, run):
        conn, devname, sc, multi = self._fw_target(run)
        cli = make(conn, self.settings.conn_config(conn), run.cancel, self.demo)
        # وضعیت بلاک دیتابیس آدرس‌ها فقط با دستگاه اول و تسک پیش‌فرض (Banned) هماهنگ است؛ بقیه فقط در گزارش و تاریخچه
        db = conn == "fortigate" and not sc
        run.data["fw_db"] = db
        tag = f" — {devname}" if multi else ""
        run.data["fw_device"] = devname
        run.data["fw_task"] = sc["name"] if sc else ""
        up = self.store.upsert_ip if db else (lambda *a, **k: None)
        if multi or sc:
            self._log(run, f"FortiGate: دستگاه «{devname}»، تسک «{sc['name'] if sc else 'پیش‌فرض (لیست Banned)'}»")
        if sc:
            return self._fw_task(run, cli, sc, devname, multi, tag)
        max_expand = int(cli.cfg.get("max_cidr_expand") or 256)
        targets, notes, label = self._fw_input(run, max_expand)
        for kind, v in notes:
            lvl = "error" if kind in ("invalid", "too_big") else "info"
            txt = {"invalid": "نامعتبر", "ipv6_net": "شبکه IPv6 نادیده گرفته شد", "too_big": "بزرگ‌تر از سقف بسط؛ رد شد",
                   "expanded": "بسط داده شد"}[kind]
            self._log(run, f"FortiGate: {txt}: {v}", lvl)
        self._log(run, f"FortiGate: {len(targets)}\u200f IP از {label}")
        if not targets:
            self._st(run)["message"] = "هیچ IPای برای بررسی نیست"
            run.summary["fortigate"] = {"targets": 0}
            self._write_fw_report(run, [])
            return
        ignore_nets, bad = fg.parse_ignore(cli.cfg.get("ignore_networks"))
        for b in bad:
            self._log(run, f"FortiGate: رنج مستثنای نامعتبر در تنظیمات: {b}", "warn")
        addresses, banned = [], []
        if not sc or sc.get("skip_address", True):
            self._st(run)["message"] = "دریافت Address Objectها"
            addresses, raw_n = cli.get_addresses(log=lambda m, lv="info": self._log(run, "FortiGate: " + m, lv))
            self._log(run, f"FortiGate: {raw_n} Address Object دریافت شد ({len(addresses)} قابل مقایسه)")
        if not sc:
            self._st(run)["message"] = "دریافت لیست Banned"
            banned = cli.get_banned()
            self._log(run, f"FortiGate: {len(banned)}\u200f IP در لیست Banned")
            # IPهایی که در دیتابیس بلاک‌شده‌اند ولی در FortiGate برداشته یا منقضی شده‌اند (و برعکس)
            if not db:
                pass
            elif self.fw_reconcile:
                self.fw_reconcile(banned, run_log=lambda m, lv: self._log(run, m, lv, "ban"))
            else:
                self.store.fw_reconcile(banned)
        want_exp = int(cli.cfg.get("ban_expiry") or 0)
        conv = bool(cli.cfg.get("convert_auto_bans", True)) and not sc
        plan = fg.classify(targets, addresses, banned, ignore_nets, want_exp, conv)

        origin = run.data.get("fw_origin", {})
        for p in plan:
            p["origin"] = origin.get(p["ip"], "manual")
        run.data["fw_plan"] = plan
        # تبدیل بلاک خودکار (IPS/...) یا موقت به Administrative هم مثل بلاک تأیید می‌خواهد و در همان سقف حساب می‌شود
        to_ban = [p["ip"] for p in plan if p["decision"] in ("ban", "convert", "task")]
        counts = {k: sum(1 for p in plan if p["decision"] == d)
                  for k, d in (("to_ban", "task" if sc else "ban"), ("to_convert", "convert"), ("address", "address"), ("already", "banned"),
                               ("ignored", "ignored"), ("invalid", "invalid"))}
        if counts["to_convert"]:
            self._log(run, f"FortiGate: {counts['to_convert']}\u200f IP در Banned هست ولی بلاک خودکار (IPS، Application Control، ...) "
                           "یا با انقضاست؛ پس از تأیید پاک و دوباره به‌صورت Administrative دائمی بلاک می‌شود", "warn")
        self._st(run)["message"] = f"{counts['to_ban'] + counts['to_convert']}\u200f IP برای بلاک"

        approved = []
        if to_ban:
            auto = self._auto_allowed(run, "auto_ban")
            src = self._inp(run, {"source": "prev"}).get("source", "prev")
            if auto and (run.data.get("prev") or {}).get("tool") == "intel" and src in (None, "prev") \
                    and not self.settings.get("intel", "auto_ban", default=False):
                auto = False
                self._log(run, "FortiGate: ورودی از «بررسی تکمیلی» است و بلاک بدون تأیید برای آن خاموش است "
                               "(تنظیمات ← بررسی تکمیلی)؛ اجرا منتظر تأیید دستی می‌ماند", "warn")
            if auto and src not in (None, "prev", "abuse", "db"):
                # لیست یا CSV دستی در AbuseIPDB بررسی نشده؛ بلاک بدون تأیید فقط برای IPهای مخرب AbuseIPDB
                auto = False
                self._log(run, "FortiGate: ورودی لیست/CSV است و در AbuseIPDB بررسی نشده؛ اجرا منتظر تأیید دستی می‌ماند", "warn")
            cap = int(run.options["max_auto_ban"] if "max_auto_ban" in run.options
                      else self.settings.get("automation", "daily", "max_auto_ban", default=50) or 0)
            if auto and cap and len(to_ban) > cap:
                auto = False
                self._log(run, f"FortiGate: {len(to_ban)} آدرس برای بلاک/تبدیل، بیشتر از سقف بلاک بدون تأیید ({cap})؛ "
                               "اجرا منتظر تأیید دستی می‌ماند", "warn")
            self._st(run)["message"] = f"پیش‌نمایش آماده است: {len(to_ban)} آدرس برای بلاک"
            test_pv = self._test_mode()
            run.data["fw_test_pv"] = test_pv
            # 1.27.9: پیش‌نمایش فقط ردیف‌های قابل انتخاب (بلاک/تبدیل) کامل؛ بقیه (از قبل Banned، Address، داخلی) فقط
            # ۳۰۰ نمونه + شمار. قبلاً کل plan (ده‌ها هزار IP) به رابط می‌رفت: ۲۶۰ هزار گره‌ی DOM و WebView تا ۲٫۶GB (memdiag)
            act = [p for p in plan if p["decision"] in ("ban", "convert", "task")]
            rest = [p for p in plan if p["decision"] not in ("ban", "convert", "task")]
            pv = {"plan": act + rest[:300], "others_total": len(rest), "counts": counts, "test_mode": test_pv,
                  "device": devname, "multi": multi}
            dec = self._wait_approval(run, "fortigate", pv, auto)
            if dec["approve"]:
                chosen = dec["payload"].get("ips")
                chosen_set = set(chosen) if chosen is not None else None     # قبلاً set برای هر IP دوباره ساخته می‌شد
                approved = [ip for ip in to_ban if chosen_set is None or ip in chosen_set]
            else:
                self._log(run, "FortiGate: بلاک توسط کاربر رد شد", "warn")

        results = []
        # اگر هنگام پیش‌نمایش حالت تست بود، تأیید همان «فقط فایل» است؛ خاموش کردن حالت تست در این فاصله بلاک واقعی نمی‌کند
        test = self._test_mode() or bool(run.data.pop("fw_test_pv", False))
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        fw_counts = {"banned": 0, "failed": 0, "rejected": 0, "converted": 0}
        approved_set = set(approved)
        converted = []
        for p in plan:
            ip, d = p["ip"], p["decision"]
            if d == "convert":
                if ip not in approved_set:
                    results.append({**p, "result": "rejected"})
                    fw_counts["rejected"] += 1
                    continue
                self.check_cancel(run)
                if test:
                    results.append({**p, "result": "test"})
                    up(ip, fw_status="test", fw_detail="حالت تست: تبدیل به Administrative ارسال نشد", fw_at=now)
                    continue
                ok, detail = cli.convert_ip(ip)
                if ok:
                    fw_counts["converted"] += 1
                    converted.append(ip)
                    msg = f"بلاک {p.get('source') or 'خودکار'} به Administrative" + (" دائمی" if not want_exp else "") + " تبدیل شد"
                    self._log(run, f"{ip} → {msg}", "ok", "ban")
                    up(ip, fw_status="banned", fw_detail=msg, fw_at=now)
                    self.store.add_history("ban", ip, "ok", f"{msg} ({APPROVED_TXT.get(run.data.get('approved_by', {}).get('fortigate'), 'تأیید دستی')}){tag}", run.id)
                    self.store.add_stat("ban", "ok", ip, src=p.get("origin", ""))
                else:
                    fw_counts["failed"] += 1
                    self._log(run, f"{ip} → تبدیل ناموفق: {detail}", "error", "ban")
                    up(ip, fw_status="failed", fw_detail=detail, fw_at=now)
                    self.store.add_history("ban", ip, "error", detail + tag, run.id)
                    self.store.add_stat("ban", "failed", ip, src=p.get("origin", ""))
                results.append({**p, "result": "converted" if ok else "failed", "response": detail})
                continue
            if d == "ban":
                if ip not in approved_set:
                    results.append({**p, "result": "rejected"})
                    fw_counts["rejected"] += 1
                    continue
                self.check_cancel(run)
                if test:
                    results.append({**p, "result": "test"})
                    self.store.add_stat("ban", "test", ip, src=p.get("origin", ""))
                    up(ip, fw_status="test", fw_detail="حالت تست: بلاک ارسال نشد", fw_at=now)
                    continue
                ok, detail = cli.ban_ip(ip)
                if ok:
                    fw_counts["banned"] += 1
                    db and self.store.mark_processed(f"ban:{ip}", run.id)
                    self._log(run, f"{ip} → بلاک شد", "ok", "ban")
                    up(ip, fw_status="banned", fw_detail="در این اجرا بلاک شد", fw_at=now)
                    self.store.add_history("ban", ip, "ok", f"افزوده شد به Banned IP ({APPROVED_TXT.get(run.data.get('approved_by', {}).get('fortigate'), 'تأیید دستی')}){tag}", run.id)
                    self.store.add_stat("ban", "ok", ip, src=p.get("origin", ""))
                else:
                    fw_counts["failed"] += 1
                    self._log(run, f"{ip} → بلاک ناموفق: {detail}", "error", "ban")
                    up(ip, fw_status="failed", fw_detail=detail, fw_at=now)
                    self.store.add_history("ban", ip, "error", detail + tag, run.id)
                    self.store.add_stat("ban", "failed", ip, src=p.get("origin", ""))
                results.append({**p, "result": "banned" if ok else "failed", "response": detail})
            else:
                results.append({**p, "result": d})
                if d != "invalid":
                    up(ip, fw_status={"address": "address", "banned": "already",
                                                        "ignored": "ignored"}[d], fw_detail=p["detail"], fw_at=now)
        if converted:
            self._fw_verify(run, cli, converted, want_exp, results, fw_counts)
        conv_set = {p["ip"] for p in plan if p["decision"] == "convert"}
        if test and approved and not sc:
            # 1.23.1: به‌جای فایل json جدا (که در برنامه نمایش داده نمی‌شد) در گزارش اجرا (run.log، قابل نمایش در تاریخچه)
            body = json.dumps({"endpoint": "/api/v2/monitor/user/banned/add_users",
                               "vdom": cli.vdom, "expiry": int(cli.cfg.get("ban_expiry") or 0),
                               "ip_addresses": [ip for ip in approved if ip not in conv_set],
                               "convert_to_admin (clear_users + add_users)": [ip for ip in approved if ip in conv_set]},
                              ensure_ascii=False)
            self._log(run, f"FortiGate (حالت تست): {len(approved)}\u200f IP ارسال نشد؛ درخواستی که ارسال می‌شد: {body[:20000]}", "warn")
            self.store.add_history("ban", f"{len(approved)}\u200f IP", "test", "حالت تست", run.id, str(run.dir))
        run.data["fw_results"] = results
        if fw_counts["failed"]:
            bad = [f"- {r['ip']}: {r.get('response', '')[:150]}" for r in results if r.get("result") == "failed"][:30]
            self.notify("ban_failed", f"اجرای {run.id}: بلاک {fw_counts['failed']} آدرس در FortiGate ناموفق بود\n" + "\n".join(bad))
        self._write_fw_report(run, results)
        run.summary["fortigate"] = {"targets": len(targets), **counts, **fw_counts, "test": len(approved) if test else 0,
                                    "device": devname if multi else "", "task": sc["name"] if sc else ""}
        msg = (f"بلاک: {fw_counts['banned']}" + (f" (تست: {len(approved)})" if test and approved else "")
               + (f"، تبدیل به Administrative: {fw_counts['converted']}" if fw_counts["converted"] else "")
               + f"، از قبل: {counts['already']}، Address: {counts['address']}، داخلی: {counts['ignored']}"
               + (f"، ناموفق: {fw_counts['failed']}" if fw_counts["failed"] else ""))
        self._st(run)["message"] = msg
        self._log(run, "FortiGate: " + msg, "ok")

    def _fw_verify(self, run, cli, ips, want_exp, results, fw_counts):
        """پس از تبدیل، لیست Banned دوباره خوانده می‌شود: هر IP باید Administrative (و بدون انقضا اگر خواسته‌ایم) باشد."""
        try:
            now_b = {b["ip"]: b for b in cli.get_banned()}
        except Exception as e:
            self._log(run, f"FortiGate: بررسی نتیجه‌ی تبدیل ممکن نشد ({friendly_error(e)})", "warn")
            return
        for ip in ips:
            b = now_b.get(ip)
            why = "در لیست Banned نیست" if not b else fg.needs_convert(b, want_exp)
            if not why:
                continue
            msg = f"پس از تبدیل هنوز درست نیست: {why}"
            self._log(run, f"{ip} → {msg}", "error", "ban")
            if run.data.get("fw_db", True):
                self.store.upsert_ip(ip, fw_status="failed", fw_detail=msg)
            self.store.add_history("ban", ip, "error", msg, run.id)
            fw_counts["converted"] -= 1
            fw_counts["failed"] += 1
            for r in results:
                if r.get("ip") == ip:
                    r.update(result="failed", response=msg)

    def check_cancel(self, run):
        if run.cancel.is_set():
            raise Cancelled()

    def _write_fw_report(self, run, results):
        f = self._f(run, "fortigate_report.csv")
        src = {"abuse": "ABUSE", "clean_foreign": "CLEAN-FOREIGN", "manual": "MANUAL", "intel": "INTEL"}
        row = lambda r: [r["ip"], src.get(r.get("origin"), ""), r["decision"], r.get("result", ""),  # noqa: E731
                         r.get("response") if r.get("result") == "failed" else r.get("detail", "")]
        with atrest.open_write(f) as fh:
            w = csv.writer(fh)
            w.writerow(["IP", "Source", "Decision", "Result", "Detail"])
            w.writerows(row(r) for r in results)
        run.data["fw_report"] = str(f)
        # خروجی برای ابزار بعدی: فقط آدرس‌هایی که واقعاً بلاک/تبدیل شدند (یا در حالت تست بلاک‌شدنی بودند).
        # فایل جدا فقط وقتی ابزاری بعد از FortiGate هست (وگرنه همان ردیف‌های گزارش بالا تکرار می‌شد)
        done = [r for r in results if r.get("result") in ("banned", "converted", "test", "done") and r.get("ip")]
        out_path = None
        later = [i for i in run.items[run.items.index(run.cur) + 1:]] if run.cur in run.items else []
        if later:
            fb = self._f(run, "fortigate_blocked.csv")
            with atrest.open_write(fb) as fh:
                w = csv.writer(fh)
                w.writerow(["IP", "Source", "Decision", "Result", "Detail"])
                w.writerows(row(r) for r in done)
            out_path = str(fb)
        run.data["out_path"], run.data["out_ips"] = out_path, [r["ip"] for r in done]

    # ------------------------------------------------------------ step 4: Redmine
    def _variables(self, run, data):
        a = run.summary.get("abuse", {})
        f = run.summary.get("fortigate", {})
        pf = data["pipe_format"]
        banned_list = [r["ip"] for r in run.data.get("fw_results", []) if r.get("result") in ("banned", "converted", "test", "done")]
        return {
            "date": data["first_time"].strftime(self.settings.get("redmine", "date_format") or "%d/%m/%Y"),
            "src_count": data["counts"]["src"], "dest_count": data["counts"]["dest"],
            "checked_count": a.get("checked", 0) + a.get("cached", 0), "abuse_count": a.get("abuse", 0),
            "clean_count": a.get("clean", 0), "error_count": a.get("error", 0),
            "banned_count": f.get("banned", 0) + f.get("converted", 0) + f.get("test", 0) + f.get("done", 0), "already_banned_count": f.get("already", 0),
            "address_match_count": f.get("address", 0), "ignored_count": f.get("ignored", 0),
            "ban_failed_count": f.get("failed", 0),
            "abuse_list": pf(run.data.get("malicious", [])), "banned_list": pf(banned_list),
            "clean_list": pf(run.data.get("clean", [])),
            "clean_foreign_count": len(run.data.get("clean_foreign", [])),
            "clean_review_count": len(run.data.get("clean_review", [])),
            "clean_review_list": pf(run.data.get("clean_review", [])),
        }

    def _step_redmine(self, run):
        inp = self._inp(run, {"source": "run"})
        if inp.get("source", "run") == "run":
            path = run.data.get("splunk_csv")
            if not path:
                raise ConnectorError("ورودی «خروجی این اجرا» انتخاب شده ولی مرحله‌ی Splunk در این اجرا نیست.")
        else:
            path = self._user_path(inp)
            if not path or not Path(path).is_file():
                raise ConnectorError(f"فایل CSV پیدا نشد: {path or '(خالی)'}")
        cli = self._client("redmine", run)
        cfg = cli.cfg
        tid = run.cur["opts"].get("template_id") or ""
        tpl, lost = self.settings.redmine_template(tid)
        if lost:
            self._log(run, "Redmine: قالب انتخاب‌شده‌ی این کار دیگر وجود ندارد؛ قالب پیش‌فرض استفاده شد", "warn")
        with atrest.open_read(path) as fh:
            header = next(csv.reader(fh), [])
        scfg = self.settings.get("splunk") or {}
        if inp.get("source", "run") == "run" and run.data.get("splunk_fields"):
            fields = dict(run.data["splunk_fields"])      # نگاشتی که همین اجرا (با همان کوئری ذخیره‌شده) به کار برد
        else:
            fields = sp.resolve_fields([h.strip() for h in header], scfg)
        data = rm.summarize_csv(path, cfg, fields)
        variables = self._variables(run, data)
        prev_tpl, note = None, ""
        while True:   # در پیش‌نمایش می‌شود قالب را عوض کرد؛ تیکت با قالب تازه دوباره ساخته می‌شود
            try:
                dec, issue, attach, key, dup, test_pv = self._redmine_prepare(run, cli, tpl, data, variables, path, note)
            except ConnectorError as e:
                if prev_tpl is None:
                    raise
                # قالب تازه ایراد دارد (مثلاً فیلد اجباری بی‌مقدار): اجرا خراب نمی‌شود، به قالب قبلی برمی‌گردد
                note = f"قالب «{tpl.get('name')}» قابل استفاده نیست: {e}"
                self._log(run, "Redmine: " + note, "error")
                tpl, prev_tpl = prev_tpl, None
                continue
            note = ""
            nxt = (dec or {}).get("payload", {}).get("switch_template") if dec else None
            if dec is None or dec.get("approve") or not nxt:
                break
            prev_tpl = tpl
            tpl, _ = self.settings.redmine_template(nxt)
            self._log(run, f"Redmine: قالب «{tpl.get('name')}» انتخاب شد؛ پیش‌نمایش دوباره ساخته می‌شود")
        if dec is None:
            return
        if not dec["approve"]:
            self._st(run)["state"] = "done"
            self._st(run)["message"] = "ساخت تیکت توسط کاربر رد شد"
            self._log(run, "Redmine: ساخت تیکت رد شد", "warn")
            return
        self._redmine_create(run, cli, dec, issue, attach, key, dup, test_pv)

    def _redmine_prepare(self, run, cli, tpl, data, variables, path, note=""):
        """تیکت با یک قالب: ساخت، پیش‌نمایش و تأیید. خروجی (تصمیم یا None اگر تکراری رد شد، issue، پیوست‌ها، ...)."""
        cfg = cli.cfg
        for k in TEMPLATE_KEYS:              # قالب روی تنظیمات مشترک (اتصال، پروژه، قالب‌بندی لیست‌ها)
            if k in tpl:
                cfg[k] = tpl[k]
        cfg["_tpl_name"] = tpl.get("name") or ""
        self._st(run)["message"] = "دریافت Tracker و فیلدها"
        ctx = cli.build_context()
        issue, values = rm.build_issue(cfg, ctx, data, variables)
        self._log(run, f"Redmine: قالب «{tpl.get('name')}» — Tracker {cfg.get('tracker')}، عنوان «{issue['subject']}»")
        attach = []
        if cfg.get("attach_splunk_csv", True):
            attach.append(path)
        if cfg.get("attach_abuse_report", True) and run.data.get("abuse_report"):
            attach.append(run.data["abuse_report"])
        if cfg.get("attach_fortigate_report", True) and run.data.get("fw_report"):
            attach.append(run.data["fw_report"])
        digest = hashlib.sha1(atrest.read_bytes(path), usedforsecurity=False).hexdigest()[:16]
        key = f"ticket:{digest}"
        dup = self.store.processed_info(key)
        test_pv = self._test_mode()
        tpls = (self.settings.get("redmine", "templates", default=[]) or [])
        preview = {"subject": issue["subject"], "description": issue["description"],
                   "fields": [[k, str(v)] for k, v in values.items()],
                   "attachments": [Path(p).name for p in attach], "duplicate": dup,
                   "test_mode": test_pv, "project": cfg.get("project"), "tracker": cfg.get("tracker"),
                   "template": {"id": tpl.get("id"), "name": tpl.get("name")}, "note": note,
                   "templates": [{"id": t.get("id"), "name": t.get("name"), "tracker": t.get("tracker")} for t in tpls]}
        auto = self._auto_allowed(run, "auto_ticket")
        self._st(run)["message"] = "پیش‌نمایش تیکت آماده است"
        if dup and auto:
            self._log(run, f"Redmine: برای همین داده قبلاً تیکت ساخته شده ({dup.get('info')})؛ رد شد", "warn")
            self._st(run)["message"] = "تکراری؛ رد شد"
            return None, issue, attach, key, dup, test_pv
        dec = self._wait_approval(run, "redmine", preview, auto)
        return dec, issue, attach, key, dup, test_pv

    def _redmine_create(self, run, cli, dec, issue, attach, key, dup, test_pv):
        if dup and not dec["payload"].get("force"):
            raise ConnectorError("تیکت تکراری است و تأیید «ساخت دوباره» داده نشد.")
        if test_pv or self._test_mode():
            body = json.dumps({"issue": issue, "attachments": [Path(p).name for p in attach]}, ensure_ascii=False)
            self._st(run)["message"] = "حالت تست: payload در گزارش اجرا نوشته شد"
            self._log(run, f"Redmine (حالت تست): تیکت ساخته نشد؛ payload: {body[:20000]}", "warn")
            self.store.add_history("ticket", issue["subject"], "test", "حالت تست", run.id, str(run.dir))
            self.store.add_stat("ticket", "test", run.id)
            run.summary["redmine"] = {"issue": None, "test": True}
            return
        issue["uploads"] = [cli.upload(p) for p in attach]
        created = cli.create_issue(issue)
        url = cli.issue_url(created["id"])
        self.store.mark_processed(key, f"#{created['id']}")
        run.summary["redmine"] = {"issue": created["id"], "url": url}
        self._st(run)["message"] = f"تیکت #{created['id']} ساخته شد"
        self._log(run, f"Redmine: تیکت #{created['id']} ساخته شد", "ok", "ticket")
        self.store.add_history("ticket", f"#{created['id']}", "ok",
                               f"{url} ({APPROVED_TXT.get(run.data.get('approved_by', {}).get('redmine'), 'تأیید دستی')})", run.id, str(run.dir))
        self.store.add_stat("ticket", "ok", f"#{created['id']}")
