"""ترد پس‌زمینه: صف رویداد داشبورد، بررسی دوره‌ای اتصال‌ها، و زمان‌بندی (روزانه + چک مجدد خطاها)."""
import itertools
import logging
import threading
import time
from collections import deque
from datetime import datetime, timedelta

from .connectors import friendly_error, make
from .pipeline import CONN, Pipeline

log = logging.getLogger(__name__)
CONNS = ["splunk", "abuseipdb", "fortigate", "redmine"]


ASSET_SCAN_WINDOW = 15 * 60      # اسکن دارایی فقط تا ۱۵ دقیقه بعد از ساعت تعیین‌شده؛ بعد از آن جبرانی اجرا نمی‌شود


class Worker:
    def __init__(self, settings, store, demo=False):
        self.settings = settings
        self.store = store
        self.demo = demo
        self._seq = itertools.count(1)
        self.events = deque(maxlen=600)
        self._elock = threading.Lock()
        self.conn_status = {c: {"state": "unknown", "message": "هنوز بررسی نشده", "at": None} for c in CONNS}
        self.last_check = None
        self.pipeline = Pipeline(settings, store, demo, emit=self.emit)
        from .backup import Backups
        from .notify import Notifier
        from .ssh import SshRunner
        self.notifier = Notifier(settings, settings.vault, emit=self.emit)
        self.pipeline.notify = self.notifier.notify
        self.backups = Backups(settings, store, settings.vault)
        self.ssh = SshRunner(settings, store, settings.vault, emit=self.emit, backups=self.backups,
                             notify=self.notifier.notify)
        self.pipeline.ssh = self.ssh
        self.pipeline.fw_reconcile = self.fw_reconcile
        try:
            from .jobs import migrate_daily
            migrate_daily(settings)
        except Exception:
            log.exception("انتقال اجرای روزانه به کارها")
        from .fgupdate import FgUpdater
        from .monitor import Monitor
        self.monitor = Monitor(settings, store, emit=self.emit, notify=self.notifier.notify, demo=demo)
        self.monitor.history = lambda kind, target, status, detail, owner: store.add_history(kind, target, status, detail, user="")
        from .health import Health
        self.health = Health(settings, notify=self.notifier.notify, emit=self.emit,
                             history=lambda kind, target, status, detail: store.add_history(kind, target, status, detail, user=""))
        self._next_health = time.time() + 60
        self._health_busy = threading.Event()
        self.fgu = FgUpdater(settings, store, settings.vault, self.ssh, emit=self.emit, notify=self.notifier.notify)
        from .assets import AssetManager
        self.assets = AssetManager(settings, store, settings.vault, self.monitor.snmp.client, self.ssh.hostkeys, emit=self.emit,
                                   notify=self.notifier.notify, demo=demo)
        self._stop = threading.Event()
        self._force_check = threading.Event()
        self._thread = None

    # ------------------------------------------------------------ events
    def emit(self, level, msg, kind="app", run_id=""):
        with self._elock:
            self.events.append({"seq": next(self._seq), "ts": time.time(), "level": level, "msg": msg,
                                "kind": kind, "run_id": run_id})
        getattr(log, {"error": "error", "warn": "warning"}.get(level, "info"))("[%s] %s", kind, msg)

    def events_since(self, seq):
        with self._elock:
            return [e for e in self.events if e["seq"] > seq]

    # ------------------------------------------------------------ lifecycle
    def start(self):
        self._thread = threading.Thread(target=self._loop, name="worker", daemon=True)
        self._thread.start()
        self.monitor.start()
        from .pipeline import purge_old_runs     # 1.23.1: فایل‌های نمایش‌داده‌نشده‌ی اجراهای قبلی
        threading.Thread(target=purge_old_runs, name="runs-cleanup", daemon=True).start()
        self.emit("info", "برنامه اجرا شد" + (" (نسخه‌ی Demo)" if self.demo else ""))

    def stop(self, wait=0.0):
        self._stop.set()
        self.monitor.stop()
        self.pipeline.cancel()
        self.ssh.cancel()
        if wait:
            end = time.time() + wait
            if self._thread:
                self._thread.join(max(0.1, end - time.time()))
            while time.time() < end and ((self.pipeline.current and self.pipeline.current.status in ("running", "awaiting"))
                                         or (self.ssh.current and self.ssh.current.get("status") == "running")):
                time.sleep(0.2)

    def request_check(self):
        self._force_check.set()

    # ------------------------------------------------------------ connections
    def test_conn(self, name, cfg):
        cli = make(name, cfg, None, self.demo)
        res = cli.test()
        if getattr(cli, "last_banned", None) is not None:
            res["_banned"] = cli.last_banned
        if getattr(cli, "pin_note", ""):
            res["message"] = res.get("message", "") + " — " + cli.pin_note
        return res

    def all_conns(self):
        """۴ اتصال اصلی + FortiGateهای اضافه (1.28)."""
        return CONNS + [d["conn"] for d in self.settings.fg_devices()[1:]]

    def conn_view(self):
        """وضعیت اتصال‌ها برای رابط؛ دستگاه حذف‌شده نمایش داده نمی‌شود."""
        out = {}
        for c in self.all_conns():
            out[c] = self.conn_status.get(c) or {"state": "unknown", "message": "هنوز بررسی نشده", "at": None}
        return out

    def check_connections(self):
        for c in self.all_conns():
            cfg = self.settings.conn_config(c)
            if not self.demo and not (cfg.get("address") or "").strip():
                self.conn_status[c] = {"state": "unset", "message": "تنظیم نشده", "at": time.time()}
                continue
            try:
                res = self.test_conn(c, cfg)
                self.conn_status[c] = {"state": "ok", "message": res.get("message", ""), "at": time.time()}
            except Exception as e:
                self.conn_status[c] = {"state": "error", "message": friendly_error(e), "at": time.time()}
        self.last_check = time.time()

    # ------------------------------------------------------------ loop
    def _loop(self):
        next_conn = 0.0
        next_sched = 0.0
        locked_noted = False
        while not self._stop.is_set():
            now = time.time()
            v = self.settings.vault
            if v is not None and not v.unlocked():
                # بدون کلید، اسرار در دسترس نیست: نه بررسی اتصال، نه اجرای زمان‌بندی‌شده
                if not locked_noted and v.initialized():
                    self.emit("warn", "برنامه قفل است؛ کارهای خودکار تا وارد کردن رمز اصلی اجرا نمی‌شوند", "security")
                locked_noted = True
                self._stop.wait(1.0)
                continue
            if locked_noted:
                locked_noted = False
                next_conn = 0.0
            try:
                if self._force_check.is_set() or now >= next_conn:
                    self._force_check.clear()
                    # بررسی اتصال AbuseIPDB سهمیه مصرف می‌کند؛ در بررسی دوره‌ای فقط سه اتصال دیگر
                    self._periodic_check()
                    next_conn = now + max(1, int(self.settings.get("poll_minutes", default=5) or 5)) * 60
                if now >= next_sched:
                    self._scheduler_tick()
                    next_sched = now + 20
                if now >= self._next_flush:
                    self.notifier.flush()
                    self._next_flush = now + 30
                if now >= self._next_snap:
                    self.snapshot()
                    self._next_snap = now + 3600
                if now >= self._next_health and not self._health_busy.is_set():
                    self._next_health = now + 300
                    self._health_busy.set()       # 1.26.2: بررسی قبلی هنوز تمام نشده (مثلاً دیسک کند) ← ترد تازه نه
                    threading.Thread(target=self._health_check, name="health", daemon=True).start()
            except Exception:
                log.exception("worker loop")
            self._stop.wait(1.0)

    def _health_check(self):
        try:
            self.health.check()
        except Exception:
            log.exception("health check")
        finally:
            self._health_busy.clear()

    def _periodic_check(self):
        for c in ["splunk", "fortigate", "redmine"] + self.all_conns()[len(CONNS):]:
            cfg = self.settings.conn_config(c)
            if not self.demo and not (cfg.get("address") or "").strip():
                self.conn_status[c] = {"state": "unset", "message": "تنظیم نشده", "at": time.time()}
                continue
            try:
                res = self.test_conn(c, cfg)
                self.conn_status[c] = {"state": "ok", "message": res.get("message", ""), "at": time.time()}
                if c == "fortigate" and res.get("_banned") is not None:
                    self.fw_reconcile(res["_banned"])
            except Exception as e:
                prev = (self.conn_status.get(c) or {}).get("state")
                self.conn_status[c] = {"state": "error", "message": friendly_error(e), "at": time.time()}
                if prev != "error":
                    nm = next((d["name"] for d in self.settings.fg_devices() if d["conn"] == c), c) if c.startswith("fortigate") else c
                    self.emit("error", f"اتصال {nm}: {friendly_error(e)}", "conn")
        a = self.conn_status["abuseipdb"]
        cfg = self.settings.conn_config("abuseipdb")
        if not self.demo and not (cfg.get("address") or "").strip():
            self.conn_status["abuseipdb"] = {"state": "unset", "message": "تنظیم نشده", "at": time.time()}
        elif a["state"] in ("unknown", "unset"):
            self.conn_status["abuseipdb"] = {"state": "idle", "message": "برای حفظ سهمیه خودکار بررسی نمی‌شود",
                                             "at": time.time()}
        self.last_check = time.time()

    def fw_reconcile(self, banned, run_log=None):
        """وضعیت بلاک IPهای دیتابیس با لیست فعلی Banned فورتی‌گیت هماهنگ می‌شود (برداشته/منقضی‌شده و تازه‌دیده‌ها)."""
        from .perms import enabled_tools
        if "fortigate" not in enabled_tools(self.settings):
            return [], []
        try:
            gone, found = self.store.fw_reconcile(banned)
        except Exception:
            log.exception("fw reconcile")
            return [], []
        if gone:
            sample = "، ".join(gone[:15]) + (" …" if len(gone) > 15 else "")
            msg = f"FortiGate: {len(gone)}\u200f IP دیگر در لیست Banned نیست (برداشته یا منقضی شد) و وضعیتشان به‌روز شد: {sample}"
            (run_log or (lambda m, lv: self.emit(lv, m, "ban")))(msg, "warn")
            for ip in gone[:200]:
                self.store.add_history("ban", ip, "warn", "دیگر در لیست Banned فورتی‌گیت نیست (برداشته یا منقضی شد)", user="")
        if found:
            msg = f"FortiGate: {len(found)}\u200f IP در لیست Banned هست که دیتابیس بلاک‌شده نمی‌دانست؛ به‌روز شد"
            (run_log or (lambda m, lv: self.emit(lv, m, "ban")))(msg, "info")
        return gone, found

    # ------------------------------------------------------------ scheduler
    def _maintenance(self):
        """روزی یک بار، مستقل از کلید اصلی کار خودکار: حذف IPهای غیرمخرب قدیمی از فهرست."""
        key = f"maint:purge_clean:{datetime.now():%Y-%m-%d}"
        if self.store.is_processed(key):
            return
        self.store.mark_processed(key, "done")
        try:
            raw = int(self.settings.get("stats", "raw_days", default=180) or 0)
            if raw > 0:
                n = self.store.purge_stat_events(max(30, raw))
                if n:
                    log.info("%d رویداد آماری خام قدیمی‌تر از %d روز پاک شد (خلاصه‌ها می‌مانند)", n, raw)
        except Exception:
            log.exception("پاک کردن رویدادهای آماری قدیمی")
        days = int(self.settings.get("abuseipdb", "purge_clean_days", default=30) or 0)
        if days <= 0:
            return
        before = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
        n = self.store.purge_clean(before)
        if n:
            self.store.add_history("import", f"{n} IP", "ok", f"حذف خودکار IPهای غیرمخربی که بیش از {days} روز پیش بررسی شده بودند")
            self.emit("info", f"{n}\u200f IP غیرمخربِ قدیمی‌تر از {days} روز از فهرست حذف شد؛ اگر دوباره بیایند از نو بررسی می‌شوند", "maint")

    def _scheduler_tick(self):
        if not self.demo:
            try:
                self._maintenance()
            except Exception:
                log.exception("maintenance")
        auto = self.settings.get("automation") or {}
        if not auto.get("master"):
            return
        installed = float(self.store.meta("installed_at") or time.time())
        max_age = float(self.settings.get("max_age_hours", default=6) or 6) * 3600
        now = datetime.now()

        try:
            from . import jobs
            jobs.tick(self, now, max_age)
        except Exception:
            log.exception("jobs tick")

        daily = auto.get("daily") or {}
        if daily.get("enabled"):
            try:
                hh, mm = [int(x) for x in str(daily.get("time", "08:00")).split(":")[:2]]
            except ValueError:
                hh, mm = 8, 0
            target = now.replace(hour=hh, minute=mm, second=0, microsecond=0)
            key = f"sched:daily:{target:%Y-%m-%d}"
            enabled_at = float(self.store.meta("daily_enabled_at") or installed)
            if now >= target and not self.store.is_processed(key):
                if target.timestamp() < enabled_at:
                    # اولین اجرا از «همین لحظه»: زمانِ گذشته‌ی امروز اجرا نمی‌شود
                    self.store.mark_processed(key, "skipped:before-enable")
                elif (now - target).total_seconds() > max_age:
                    self.store.mark_processed(key, "skipped:too-old")
                    self.emit("warn", f"اجرای روزانه‌ی {target:%H:%M} رد شد؛ بیش از حداکثر قدمت گذشته بود", "schedule")
                elif self.pipeline.current and self.pipeline.current.status in ("running", "awaiting"):
                    pass  # بعداً دوباره تلاش می‌شود
                else:
                    self.store.mark_processed(key, "started")
                    opts = {"steps": dict(daily.get("steps") or {}),
                            "abuse_input": {"source": "splunk"}, "fortigate_input": {"source": "abuse"},
                            "redmine_input": {"source": "run"},
                            "auto_ban": bool(daily.get("auto_ban")), "auto_ticket": bool(daily.get("auto_ticket"))}
                    self._fix_inputs(opts)
                    try:
                        self.pipeline.start(opts, "schedule")
                        self.emit("info", "اجرای زمان‌بندی‌شده‌ی روزانه شروع شد", "schedule")
                    except Exception as e:
                        self.emit("error", f"اجرای روزانه شروع نشد: {friendly_error(e)}", "schedule")

        bk = auto.get("backup") or {}
        if bk.get("enabled"):
            try:
                hh, mm = [int(x) for x in str(bk.get("time", "02:00")).split(":")[:2]]
            except ValueError:
                hh, mm = 2, 0
            target = now.replace(hour=hh, minute=mm, second=0, microsecond=0)
            key = f"sched:backup:{target:%Y-%m-%d}"
            enabled_at = float(self.store.meta("backup_enabled_at") or installed)
            if now >= target and not self.store.is_processed(key):
                if target.timestamp() < enabled_at:
                    self.store.mark_processed(key, "skipped:before-enable")
                elif (now - target).total_seconds() > max_age:
                    self.store.mark_processed(key, "skipped:too-old")
                    self.emit("warn", f"پشتیبان‌گیری روزانه‌ی {target:%H:%M} رد شد؛ بیش از حداکثر قدمت گذشته بود", "schedule")
                elif self.ssh.current and self.ssh.current.get("status") == "running":
                    pass
                else:
                    self.store.mark_processed(key, "started")
                    try:
                        self.start_backup()
                        self.emit("info", "پشتیبان‌گیری زمان‌بندی‌شده‌ی کانفیگ شروع شد", "schedule")
                    except Exception as e:
                        self.emit("error", f"پشتیبان‌گیری روزانه شروع نشد: {friendly_error(e) if not isinstance(e, RuntimeError) else e}", "schedule")
                        self.notifier.notify("backup_failed", f"پشتیبان‌گیری روزانه شروع نشد: {e}")

        ac = self.settings.get("assets") or {}
        if ac.get("scan_enabled"):
            try:
                hh, mm = [int(x) for x in str(ac.get("scan_time", "03:00")).split(":")[:2]]
            except ValueError:
                hh, mm = 3, 0
            target = now.replace(hour=hh, minute=mm, second=0, microsecond=0)
            key = f"sched:assets:{target:%Y-%m-%d}"
            enabled_at = float(self.store.meta("assets_enabled_at") or installed)
            if now >= target and not self.store.is_processed(key):
                if target.timestamp() < enabled_at:
                    self.store.mark_processed(key, "skipped:before-enable")
                elif (now - target).total_seconds() > ASSET_SCAN_WINDOW:
                    # جبران نمی‌شود: اگر برنامه سر ساعت باز نبود، با باز شدن برنامه اسکن نمی‌کند (خواسته‌ی کاربر)
                    self.store.mark_processed(key, "skipped:missed")
                    self.emit("info", f"اسکن روزانه‌ی دارایی ساعت {target:%H:%M} انجام نشد چون برنامه آن موقع باز نبود؛ اسکن بعدی سر ساعت فردا (یا دستی)", "schedule")
                elif self.assets.job and self.assets.job["status"] == "running":
                    pass
                else:
                    self.store.mark_processed(key, "started")
                    try:
                        self.assets.scan_start(None, "", "schedule")
                        self.emit("info", "اسکن زمان‌بندی‌شده‌ی دارایی شروع شد", "schedule")
                    except Exception as e:
                        self.emit("error", f"اسکن روزانه‌ی دارایی شروع نشد: {e}", "schedule")

        for sch in self.settings.get("ssh_schedules", default=[]) or []:
            if sch.get("enabled"):
                try:
                    self._ssh_schedule_tick(sch, now, max_age)
                except Exception as e:
                    log.exception("ssh schedule")
                    self.emit("error", f"زمان‌بندی SSH «{sch.get('name')}»: {e}", "schedule")

        retry = auto.get("retry_errors") or {}
        if retry.get("enabled"):
            every = max(5, int(retry.get("every_minutes") or 60)) * 60
            slot = int(time.time() // every)
            key = f"sched:retry:{slot}"
            if not self.store.is_processed(key) and not (self.pipeline.current and
                                                         self.pipeline.current.status in ("running", "awaiting")):
                self.store.mark_processed(key, "tick")
                from .connectors.abuseipdb import QUOTA_ERR
                errs = [r["ip"] for r in self.store.ips_by_status(("ERROR",), "ip, error") if r.get("error") != QUOTA_ERR]
                if errs:
                    try:
                        self.pipeline.start({"steps": {"abuse": True},
                                             "abuse_input": {"source": "list", "text": "\n".join(errs)}}, "retry")
                        self.emit("info", f"چک مجدد {len(errs)}\u200f IP با خطای قبلی", "schedule")
                    except Exception as e:
                        self.emit("error", friendly_error(e), "schedule")

    def _ssh_schedule_tick(self, sch, now, max_age):
        """یک زمان‌بندی SSH (اسکریپت یا به‌روزرسانی FortiGate)؛ همان قواعد اجرای روزانه."""
        try:
            hh, mm = [int(x) for x in str(sch.get("time", "03:00")).split(":")[:2]]
        except ValueError:
            return
        days = sch.get("days") or []
        if days and now.weekday() not in days:
            return
        target = now.replace(hour=hh, minute=mm, second=0, microsecond=0)
        key = f"sched:ssh:{sch['id']}:{target:%Y-%m-%d}"
        if now < target or self.store.is_processed(key):
            return
        name = sch.get("name") or "بدون نام"
        if target.timestamp() < float(sch.get("enabled_at") or 0):
            self.store.mark_processed(key, "skipped:before-enable")
            return
        if (now - target).total_seconds() > max_age:
            self.store.mark_processed(key, "skipped:too-old")
            self.emit("warn", f"زمان‌بندی SSH «{name}» ({target:%H:%M}) رد شد؛ بیش از حداکثر قدمت گذشته بود", "schedule")
            self.settings.update_ssh_schedule(sch["id"], last_at=time.time(), last_status="skipped",
                                              last_message="رد شد؛ بیش از حداکثر قدمت گذشته بود")
            return
        if (self.ssh.current and self.ssh.current.get("status") == "running") or \
                (self.fgu.current and self.fgu.current.get("status") == "running"):
            return   # کار SSH دیگری در جریان است؛ در دور بعدی دوباره تلاش می‌شود
        self.store.mark_processed(key, "started")
        ids = [int(i) for i in sch.get("device_ids") or []]
        try:
            if sch.get("kind") == "fgupdate":
                job = self.fgu.start(ids, dict(sch.get("fgu") or {}))
            else:
                sc = self.store.ssh_script(int(sch.get("script_id") or 0))
                if not sc:
                    raise RuntimeError("اسکریپت این زمان‌بندی حذف شده است")
                script = {k: sc.get(k) for k in ("body", "mode", "use_sudo", "save_config")}
                script["name"] = f"{sc.get('name')} — زمان‌بندی «{name}»"
                job = self.ssh.start(ids, script, dict(sch.get("options") or {}), "run")
            self.emit("info", f"زمان‌بندی SSH «{name}» شروع شد", "schedule")
            self.settings.update_ssh_schedule(sch["id"], last_at=time.time(), last_status="started",
                                              last_message=f"شروع شد (اجرای {job.get('id', '')})")
        except Exception as e:
            from .ssh import SshError
            msg = str(e) if isinstance(e, (RuntimeError, SshError)) else friendly_error(e)
            self.emit("error", f"زمان‌بندی SSH «{name}» شروع نشد: {msg}", "schedule")
            self.notifier.notify("ssh_failed", f"زمان‌بندی SSH «{name}» شروع نشد: {msg}")
            self.settings.update_ssh_schedule(sch["id"], last_at=time.time(), last_status="error", last_message=msg)

    _next_snap = 0.0
    _next_flush = 0.0

    def backup_devices(self):
        """دستگاه‌هایی که پشتیبان‌گیری دارند (پیش‌فرض: همه‌ی تجهیزات شبکه؛ لینوکس فقط اگر روشن شده باشد)."""
        return [d["id"] for d in self.store.ssh_devices() if not d.get("owner")
                and (d.get("backup") if d.get("backup") is not None else d["device_type"] != "linux")]

    def start_backup(self, ids=None):
        ids = ids or self.backup_devices()
        if not ids:
            raise RuntimeError("هیچ دستگاهی برای پشتیبان‌گیری انتخاب نشده است.")
        return self.ssh.start(ids, {"name": "پشتیبان‌گیری کانفیگ"}, {"concurrency": 5}, "backup")

    def snapshot(self):
        """عکس روزانه از «جامانده از بلاک» و «منتظر بررسی دستی» برای نمودار روند (هر ساعت به‌روز می‌شود)."""
        from .pipeline import FW_DONE, block_reason_v
        rows = self.store.ip_count_rows()       # (status, score, whitelisted, fw, checked, review) — بدون dict
        cfg = self.settings.get("abuseipdb") or {}
        pend = sum(1 for st, sc, wl, fw, _c, _r in rows if fw not in FW_DONE and block_reason_v(st, sc, wl, cfg))
        rev = sum(1 for r in rows if r[5] == "pending")
        self.store.set_snapshot(datetime.now().strftime("%Y-%m-%d"), pend, rev, len(rows))

    @staticmethod
    def _fix_inputs(opts):
        """اگر مرحله‌ی قبلی خاموش است، ورودی مرحله‌ی بعد معنا ندارد."""
        s = opts["steps"]
        if not s.get("splunk"):
            s["abuse"] = False
            s["redmine"] = False
        if not s.get("abuse"):
            s["fortigate"] = False
