"""Bridge برای pywebview js_api. همه‌ی متدها {"ok": bool, ...} برمی‌گردانند؛ پیام خطا فارسی است."""
import collections
import functools
import hashlib
import hmac
import logging
import os
import re
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

import base64
import json
import platform
import secrets as pysecrets
import shutil

from . import AUTHOR, APP_NAME, CONTACTS, __version__, atrest, paths
from .vault import VaultError, check_password, derive_key
from .connectors import ConnectorError, friendly_error
from .connectors import redmine as rm
from . import importer, perms, ssh as sshmod, stats
import contextvars
from .store import ACTOR

WEB_USER = contextvars.ContextVar("web_user", default=None)   # کاربر هر درخواست در حالت سرور
WEB_IP = contextvars.ContextVar("web_ip", default="")
WEB_SID = contextvars.ContextVar("web_sid", default="")
from .pipeline import CONN, FW_DONE

log = logging.getLogger(__name__)


# در «قفل رابط» فقط این متدها مجازند (کارهای خودکار در پس‌زمینه ادامه دارند)
STATS_TTL = 20            # ثانیه
IPC_TTL = 10              # ثانیه: کمترین فاصله‌ی شمارش دوباره‌ی IPها برای داشبورد وقتی پایگاه داده مدام تغییر می‌کند
UNLOCK_FREE_TRIES = 5     # بعد از این تعداد رمز اشتباه، مکث تصاعدی: 30، 60، 120 … ثانیه
UNLOCK_MAX_WAIT = 900
UI_LOCK_ALLOW = {"get_state", "get_settings", "security_status", "security_unlock", "security_check_password",
                 "security_recover", "save_ui", "js_error", "ui_perf", "ui_touch"}   # 1.27.8: RESET از صفحه‌ی قفل نه


# متدهای مخصوص حالت کلاینت؛ در حالت سرور کلید/کاربران از serverauth مدیریت می‌شوند و پنجره‌ی دسکتاپ نیست
SERVER_BLOCK = {"security_setup", "security_change", "security_set_remember", "security_unlock", "users_enable",
                "users_disable", "security_auto_lock", "open_contact", "pick_folder"}


def server_path(path, sub=("uploads", "jobfiles")):
    """حالت سرور: هر مسیر فایلی که از مرورگر می‌آید باید داخل پوشه‌ی مجاز (آپلودها) باشد؛
    وگرنه کاربر وب می‌توانست هر فایلی روی دیسک سرور را بخواند. حالت کلاینت: بدون تغییر."""
    if not paths.is_server() or not path:
        return path
    p = paths.inside(path, [paths.data_dir() / x for x in ((sub,) if isinstance(sub, str) else sub)], allow_root=True)
    if p is None:
        raise ConnectorError("در حالت سرور فقط فایل‌های آپلودشده قابل استفاده‌اند.")
    return str(p)


def server_items(items):
    """مسیر CSV ورودی ابزارها (اجرا یا کار ذخیره‌شده) در حالت سرور."""
    for it in items or []:
        inp = ((it or {}).get("opts") or {}).get("input") or {}
        if inp.get("path"):
            inp["path"] = server_path(inp["path"])
    return items


RUN_LISTS_SECS = 5


def _lists_sig(d):
    """امضای ارزان فهرست‌های یک اجرا: تعداد هر فهرست + وضعیت اجرا و مرحله‌ها + تأیید فعلی."""
    parts = [d.get("status"), str((d.get("approval") or {}).get("id") or "")]
    for k, v in sorted((d.get("lists") or {}).items()):
        if isinstance(v, dict) and k == "abuse_counts":
            parts.append(f"{k}:{sorted(v.items())}")
        elif isinstance(v, dict):
            n = sum(len(x.get("rows") or []) + int(x.get("total") or 0) for x in v.values() if isinstance(x, dict))
            parts.append(f"{k}:{len(v)}:{n}")
        elif isinstance(v, (int, float)):
            parts.append(f"{k}={v}")                    # شمار کل فهرست‌های کوتاه‌شده (1.27.9)
        else:
            parts.append(f"{k}:{len(v) if hasattr(v, '__len__') else 0}")
    for k, st in sorted((d.get("stages") or {}).items()):
        parts.append(f"{k}={st.get('state') if isinstance(st, dict) else st}")
    return hashlib.sha1("|".join(parts).encode(), usedforsecurity=False).hexdigest()[:16]


SLOW_API_SECS = 1.5
SLOW_CALLS = collections.deque(maxlen=200)      # (زمان، نام متد، ثانیه) — فقط نام، بدون پارامتر یا داده


def _safe(fn):
    @functools.wraps(fn)
    def wrap(self, *a, **k):
        if getattr(self, "_wiped", False):
            return {"ok": False, "wiped": True, "error": "همه‌ی داده‌ها پاک شد. برنامه را ببندید و دوباره باز کنید."}
        name = fn.__name__
        v = getattr(self, "_vault", None)
        srv = paths.is_server()
        if v is not None and not srv:
            self._auto_lock_check(name)
        if v is not None and not srv and v.ui_locked and name not in UI_LOCK_ALLOW:
            return {"ok": False, "error": "برنامه قفل است.", "locked": True}
        user = self._current_user()
        if srv and user is None:   # حالت سرور: هر فراخوانی باید از نشست یک کاربر باشد
            return {"ok": False, "error": "ابتدا وارد شوید.", "locked": True}
        if v is not None and not srv and v.users_enabled() and user is None and name not in perms.PUBLIC:
            return {"ok": False, "error": "ابتدا وارد شوید.", "locked": True}
        if srv and name in SERVER_BLOCK:
            return {"ok": False, "error": "این بخش در حالت سرور در دسترس نیست.", "denied": True}
        deny = perms.can_call(user, name, self._settings) if v is not None else None
        if deny:
            return {"ok": False, "error": deny, "denied": True}
        ACTOR.name = user["username"] if user else ""
        t0 = time.perf_counter()
        try:
            out = fn(self, *a, **k)
            if srv and isinstance(out, dict) and out.get("path") and self._server is not None:
                out = self._webfile(out)
            if isinstance(out, dict) and "ok" in out:
                return out
            return {"ok": True, **(out or {})} if isinstance(out, dict) or out is None else {"ok": True, "data": out}
        except (ConnectorError, VaultError, sshmod.SshError) as e:
            return {"ok": False, "error": str(e), "locked": e.__class__.__name__ == "VaultLocked"}
        except TypeError as e:
            log.exception("api %s", fn.__name__)
            # امضای متد (نام پارامترها) به رابط برنگردد
            return {"ok": False, "error": "پارامترهای نامعتبر" if "argument" in str(e) else friendly_error(e)}
        except Exception as e:
            log.exception("api %s", fn.__name__)
            return {"ok": False, "error": friendly_error(e)}
        finally:
            ACTOR.name = ""
            dt = time.perf_counter() - t0
            if dt >= SLOW_API_SECS:        # عیب‌یابی کندی (memdiag هم این‌ها را ثبت می‌کند)
                SLOW_CALLS.append((time.time(), name, round(dt, 2)))
                log.warning("slow api %s %.2fs", name, dt)
    return wrap


class Api:
    def __init__(self, settings, store, worker, demo=False, vault=None):
        self._vault = vault
        self._logo_cache = {}
        self._settings = settings
        self._backup_was = bool(settings.get("automation", "master", default=False)
                                and settings.get("automation", "backup", "enabled", default=False))
        self._store = store
        self._worker = worker
        self._demo = demo
        self._window = None
        self._stats_cache = {}
        self._stats_lock = threading.Lock()
        self._snap_at = 0.0
        self._unlock_fails = 0
        self._unlock_until = 0.0
        self._user = None              # کاربر واردشده (فقط وقتی کاربران فعال‌اند)
        self._last_act = time.time()   # آخرین فعالیت کاربر (قفل خودکار)
        self._server = None            # نمونه‌ی سرور (حالت وب)
        from .abort import Registry
        from .term import TermManager
        from .xfer import XferManager
        self._attempts = Registry()    # اتصال‌های در حال برقراری (لغو فوری از رابط)
        hk = getattr(getattr(worker, "ssh", None), "hostkeys", None)
        self._term = TermManager(store, vault, settings, emit=worker.emit if worker else None, hostkeys=hk)
        self._term._on_close = self._term_closed
        self._xfer = XferManager(settings, self._term.hostkeys, emit=worker.emit if worker else None)
        self._xfer.on_history = self._xfer_history
        self._hidden = False           # دسکتاپ: پنجره بسته و برنامه در پس‌زمینه
        self._quitting = False
        if worker is not None and getattr(worker, "monitor", None):
            worker.monitor.on_alert = self._mon_alert
        if vault is not None and vault.users_enabled() and vault.unlocked():
            us = vault.users()
            if len(us) == 1 and not us[0].get("disabled"):
                self._user = us[0]     # تنها کاربر با «باز شدن خودکار»
            else:
                vault.ui_locked = True
        if not demo:
            from .connectors import base as cbase
            cbase.PIN_HOOK = self._on_cert_pin
            self._protect_bg()
        if not self._settings.get("database", "asked", default=False) and not self._store_fresh():
            self._settings.update({"database": {"asked": True}})   # نصب قبلی با داده: پرسش اولین اجرا لازم نیست

    def _store_fresh(self):
        try:
            return self._store.is_fresh()
        except Exception:
            return False

    # ------------------------------------------------------------ پایگاه داده (محلی / MySQL) — فقط ادمین
    def _db_state(self):
        st = self._store.db_status()
        me = self._current_user()
        admin = me is None or me.get("role") == "admin"
        st["prompt"] = bool(admin and st["backend"] == "local" and not self._settings.get("database", "asked", default=False))
        return st if admin else {"backend": st["backend"], "ok": st.get("ok"), "prompt": False}

    @_safe
    def db_info(self):
        return {"db": self._db_state()}

    def _db_conf(self, conf):
        from . import dbmysql
        old = dbmysql.load_conf() or (self._store.backend.conf if self._store.backend else None)
        return dbmysql.clean_conf(conf, old)

    @_safe
    def db_test(self, conf):
        from . import dbmysql
        try:
            c = self._db_conf(conf)
            info = dbmysql.MySQLBackend(c).probe()
        except dbmysql.DbError as e:
            raise ConnectorError(str(e))
        cur = self._store.backend
        info["current"] = bool(cur and cur.conf.get("host") == c["host"] and int(cur.conf.get("port")) == c["port"]
                               and cur.conf.get("database") == c["database"])
        return {"info": info}

    @_safe
    def db_use_mysql(self, conf, use_existing=False):
        from . import dbmysql
        try:
            c = self._db_conf(conf)
            r = self._store.use_mysql(c, bool(use_existing))
        except dbmysql.DbError as e:
            if str(e) == "EXISTS":
                return {"exists": True}
            raise ConnectorError(str(e))
        self._settings.update({"database": {"asked": True}})
        what = ("تنظیمات اتصال عوض شد" if r.get("reconnected") else
                "داده‌های موجود در MySQL بارگذاری شد" if r["loaded"] else "داده‌های فعلی به MySQL منتقل شد")
        self._store.add_history("security", "پایگاه داده", "ok",
                                f"پایگاه داده: MySQL {c['host']}:{c['port']}/{c['database']} (حالت {c['mode']}، TLS {c['ssl']}) — {what}")
        self._stats_cache = {}
        return {"db": self._db_state(), "loaded": r["loaded"], "reconnected": bool(r.get("reconnected"))}

    @_safe
    def db_use_local(self):
        was = self._store.db_status()
        self._store.use_local()
        self._settings.update({"database": {"asked": True}})
        if was["backend"] != "local":
            self._store.add_history("security", "پایگاه داده", "ok",
                                    f"پایگاه داده: برگشت به فایل محلی (داده‌های MySQL {was.get('host')}/{was.get('database')} دست نخورد)")
        return {"db": self._db_state()}

    def _excluded_fn(self):
        from .connectors import fortigate as fgc
        nets, _ = fgc.parse_ignore(self._settings.get("fortigate", "ignore_networks", default=[]))
        return lambda ip: fgc.is_excluded(ip, nets)

    def _cleanup_excluded(self, only=None):
        """
        IPهای خصوصی یا داخل رنج‌های مستثنا از فهرست آدرس‌ها حذف می‌شوند (رنج‌ها همه‌جا اعمال می‌شوند).
        IPی که در FortiGate بلاک شده باقی می‌ماند تا از دید کاربر پنهان نشود.
        """
        ex = self._excluded_fn()
        rows = self._store.ips_brief()
        if only is not None:
            only = set(only)
            rows = [r for r in rows if r["ip"] in only]
        dels = [r["ip"] for r in rows if ex(r["ip"]) and (r.get("fw_status") or "") not in ("banned", "already")]
        if dels:
            self._store.delete_ips(dels)
            self._store.add_history("import", f"{len(dels)} IP", "ok", "حذف از فهرست: خصوصی یا داخل رنج‌های مستثنا", "", "")
        return len(dels)

    def _protect_bg(self):
        """IP سرورهای معرفی‌شده در برنامه (Splunk، FortiGate، Redmine، SMTP، دستگاه‌های SSH) به رنج‌های مستثنا."""
        if self._demo:
            return

        def job():
            try:
                self._cleanup_excluded()
            except Exception:
                log.exception("cleanup excluded")
            try:
                added = self._settings.protect_servers()
                for d in self._store.ssh_devices():
                    added += self._settings.protect_host(d.get("host") or "", f"SSH: {d.get('name') or d.get('host')}")
                if added:
                    self._store.add_history("security", "رنج‌های مستثنا", "ok",
                                            "IP سرورهای برنامه اضافه شد: " + "، ".join(added))
            except Exception:
                log.exception("protect servers")
        threading.Thread(target=job, daemon=True).start()

    def _on_cert_pin(self, conn, hostport, fp):
        """TOFU: اولین اتصال به سرور با «بررسی گواهی» خاموش؛ اثر انگشت ذخیره و در تاریخچه ثبت می‌شود."""
        from .connectors.base import fmt_fp
        self._settings.set_cert_pin(conn, {"host": hostport, "sha256": fp})
        self._store.add_history("security", conn, "ok", f"گواهی {hostport} پین شد — SHA-256 {fmt_fp(fp)}")

    def _set_window(self, w):
        self._window = w

    # ------------------------------------------------------------ کاربر جاری و قفل خودکار
    def _current_user(self):
        if paths.is_server():
            return WEB_USER.get()
        v = self._vault
        if v is None or not v.users_enabled() or self._user is None:
            return None
        rec = v.find_user(self._user["username"])
        if rec is None or rec.get("disabled"):   # حذف یا غیرفعال شد: خروج
            self._user = None
            v.ui_locked = True
            return None
        self._user = rec
        return rec

    def _auto_lock_check(self, name):
        v, now = self._vault, time.time()
        mins = int(self._settings.get("security", "auto_lock_minutes", default=0) or 0)
        if v.mode == "password" and mins > 0 and v.unlocked() and not v.ui_locked and now - self._last_act > mins * 60:
            v.lock(False)
            who = self._user["username"] if self._user else ""
            self._user = None
            self._worker.emit("info", f"رابط پس از {mins} دقیقه بی‌کاری خودکار قفل شد" + (f" ({who})" if who else ""), "security")
            self._term.close_all()
            self._xfer.close_all()
        if name not in perms.POLL:
            self._last_act = now

    @_safe
    def ui_touch(self):
        if not self._vault.ui_locked:
            self._last_act = time.time()
        return {}

    @_safe
    def whoami(self):
        return self._me()

    def _me(self):
        u = self._current_user()
        feats = perms.enabled_features(self._settings)
        if paths.is_server():
            return {"me": perms.public_user(u), "tools": perms.allowed_tools(u, self._settings),
                    "tools_enabled": perms.enabled_tools(self._settings), "features": feats}
        if self._vault is not None and self._vault.users_enabled() and u is None:
            return {"me": None, "tools": [], "tools_enabled": perms.enabled_tools(self._settings), "features": feats}
        return {"me": perms.public_user(u), "tools": perms.allowed_tools(u, self._settings),
                "tools_enabled": perms.enabled_tools(self._settings), "features": feats}

    # ------------------------------------------------------------ کاربران (ادمین)
    def _save_users(self, items):
        self._settings.set_users(items)
        if len(items) > 1 and self._settings.get("security", "remember", default=False):
            self._vault.set_remember(False)
            self._worker.emit("warn", "«باز شدن خودکار» خاموش شد؛ با چند کاربر ممکن نیست", "security")

    @_safe
    def users_list(self):
        if paths.is_server():
            from . import serverauth
            data = serverauth.load()
            return {"enabled": True, "available": True, "server": True,
                    "users": [perms.public_user(u) for u in data.get("users", [])], "roles": perms.ROLE_TITLES,
                    "tools": perms.TOOL_TITLES, "perms": perms.USER_PERM_TITLES, "me": (self._current_user() or {}).get("username", "")}
        v = self._vault
        return {"enabled": v.users_enabled(), "available": v.mode == "password",
                "users": [perms.public_user(u) for u in v.users()], "roles": perms.ROLE_TITLES,
                "tools": perms.TOOL_TITLES, "perms": perms.USER_PERM_TITLES, "me": (self._user or {}).get("username", "")}

    @_safe
    def users_enable(self, username, current):
        """حالت تک‌رمزی ← کاربران. کلید vault تصادفی می‌شود تا رمز اصلی قبلی دیگر به اسرار راه نداشته باشد."""
        v = self._vault
        if v.mode != "password":
            raise VaultError("کاربران فقط در حالت رمز اصلی فعال می‌شوند (تنظیمات ← امنیت).")
        if v.users_enabled():
            raise VaultError("کاربران از قبل فعال‌اند.")
        self._verify_current(current)
        rec = {**v.make_user((username or "").strip(), current, "admin", [], False), "created": time.time()}
        v.rekey_random()
        rec = {**rec, **v._wrap(rec["username"], current)}
        self._save_users([rec])
        self._user = rec
        self._store.add_history("security", "کاربران", "ok", f"کاربران فعال شد؛ ادمین: {rec['username']}")
        return self.users_list()

    @_safe
    def users_disable(self, current):
        """برگشت به حالت تک‌رمزی با رمز ادمین جاری."""
        v, me = self._vault, self._user
        if not v.users_enabled() or not me:
            raise VaultError("کاربران فعال نیستند.")
        if not v.verify_user(me["username"], current):
            raise VaultError("رمز فعلی اشتباه است.")
        self._settings.set_users([])
        v.change("password", current, False)
        self._user = None
        self._store.add_history("security", "کاربران", "ok", "کاربران غیرفعال شد؛ رمز اصلی = رمز " + me["username"])
        return self.users_list()

    @_safe
    def user_save(self, user, password=""):
        if paths.is_server():
            return self._server_user_save(user, password)
        v = self._vault
        if not v.users_enabled():
            raise VaultError("ابتدا کاربران را فعال کنید.")
        u = dict(user or {})
        name = (u.get("username") or "").strip()
        role = u.get("role") or "readonly"
        tools = [t for t in (u.get("tools") or []) if t in perms.USER_TOOLS] if role == "operator" else []
        items = v.users()
        old = v.find_user(name)
        if old is None:
            if not password:
                raise VaultError("برای کاربر تازه رمز لازم است.")
            rec = {**v.make_user(name, password, role, tools, bool(u.get("disabled"))), "created": time.time(),
                   "shared_devices": u.get("shared_devices", True) is not False, "perms_v": perms.PERMS_V}
            items.append(rec)
            msg = f"کاربر {name} ({perms.ROLE_TITLES.get(role)}) ساخته شد"
        else:
            rec = {**old, "role": role, "tools": tools, "disabled": bool(u.get("disabled")),
                   "shared_devices": u.get("shared_devices", True) is not False, "perms_v": perms.PERMS_V}
            if role not in v.ROLES:
                raise VaultError("نقش نامعتبر است.")
            if password:
                rec = v.rewrap(rec, password)
            items = [rec if x["username"] == old["username"] else x for x in items]
            msg = f"کاربر {old['username']} به‌روز شد" + ("؛ رمز تغییر کرد" if password else "")
        if not any(x["role"] == "admin" and not x.get("disabled") for x in items):
            raise VaultError("حداقل یک ادمین فعال لازم است.")
        self._save_users(items)
        self._store.add_history("security", "کاربران", "ok", msg)
        return self.users_list()

    @_safe
    def user_delete(self, username):
        if paths.is_server():
            return self._server_user_delete(username)
        v = self._vault
        rec = v.find_user(username)
        if not rec:
            raise VaultError("کاربر پیدا نشد.")
        if self._user and rec["username"] == self._user["username"]:
            raise VaultError("نمی‌توانید حساب خودتان را حذف کنید.")
        items = [x for x in v.users() if x["username"] != rec["username"]]
        if not any(x["role"] == "admin" and not x.get("disabled") for x in items):
            raise VaultError("حداقل یک ادمین فعال لازم است.")
        self._save_users(items)
        self._store.add_history("security", "کاربران", "ok", f"کاربر {rec['username']} حذف شد")
        return self.users_list()

    @_safe
    def security_change_own(self, current, new):
        """تغییر رمز کاربر جاری (هر نقش)."""
        if paths.is_server():
            from . import serverauth
            me = self._current_user()
            rec = serverauth.find(serverauth.load(), me["username"]) or {}
            if rec.get("source") == "ad":
                raise VaultError("رمز کاربر AD در خود Active Directory تغییر می‌کند.")
            self._pw_attempt(lambda: serverauth.verify(me["username"], current or ""))
            serverauth.change_password(me["username"], self._server.master, new,
                                       self._settings.get("security", "strong_policy", default=True))
            self._server.drop_session(username=me["username"], keep=WEB_SID.get())   # نشست‌های دیگر همین کاربر بسته شوند
            self._store.add_history("security", "کاربران", "ok", f"{me['username']} رمز خود را تغییر داد")
            return {}
        v, me = self._vault, self._user
        if not v.users_enabled() or not me:
            raise VaultError("این گزینه فقط با کاربران فعال است.")
        self._pw_attempt(lambda: v.verify_user(me["username"], current or ""))
        rec = v.rewrap(me, new)
        self._save_users([rec if x["username"] == me["username"] else x for x in v.users()])
        self._store.add_history("security", "کاربران", "ok", f"{me['username']} رمز خود را تغییر داد")
        return {}

    # ------------------------------------------------------------ کاربران حالت سرور
    def _server_user_save(self, user, password=""):
        from . import serverauth
        with serverauth.LOCK:      # خواندن/تغییر/نوشتن فایل کاربران بدون تداخل با ورودها
            return self._server_user_save_locked(user, password)

    def _server_user_save_locked(self, user, password=""):
        from . import serverauth
        master = self._server.master
        u = dict(user or {})
        name = (u.get("username") or "").strip()
        role = u.get("role") or "readonly"
        tools = [t for t in (u.get("tools") or []) if t in perms.USER_TOOLS] if role == "operator" else []
        strong = self._settings.get("security", "strong_policy", default=True)
        data = serverauth.load()
        old = serverauth.find(data, name)
        if old is None:
            if not password:
                raise VaultError("برای کاربر تازه رمز لازم است.")
            rec = serverauth.new_user_record(master, name, password, role, tools, bool(u.get("disabled")), strong)
            rec["shared_devices"] = u.get("shared_devices", True) is not False
            rec["perms_v"] = perms.PERMS_V
            data["users"].append(rec)
            msg = f"کاربر {name} ({perms.ROLE_TITLES.get(role)}) ساخته شد"
        else:
            if role not in serverauth.ROLES:
                raise VaultError("نقش نامعتبر است.")
            if old.get("source") == "ad":
                if password:
                    raise VaultError("رمز کاربر AD در خود Active Directory تغییر می‌کند.")
                role = old["role"]            # نقش کاربر AD از گروه‌هایش در هر ورود
                tools = [t for t in (u.get("tools") or []) if t in perms.USER_TOOLS] if role == "operator" else []
            old.update(role=role, tools=tools, disabled=bool(u.get("disabled")), shared_devices=u.get("shared_devices", True) is not False,
                       perms_v=perms.PERMS_V)
            if password:
                from .vault import check_password as _cp
                errs = _cp(password, strong)
                if errs:
                    raise VaultError("رمز شرایط لازم را ندارد: " + "، ".join(errs))
                old.update(serverauth._wrap(master, password))
            data["users"] = [old if x["username"].lower() == old["username"].lower() else x for x in data["users"]]
            msg = f"کاربر {old['username']} به‌روز شد" + ("؛ رمز تغییر کرد" if password else "")
        if not any(x["role"] == "admin" and not x.get("disabled") and x.get("source") != "ad" for x in data["users"]):
            raise VaultError("حداقل یک ادمین محلی فعال لازم است (کاربر AD کافی نیست؛ اگر AD در دسترس نباشد کسی وارد نمی‌شود).")
        serverauth.save(data)
        if old is not None and (old.get("disabled") or password):   # غیرفعال یا رمز ریست شد: نشست‌هایش بسته شود
            me = (self._current_user() or {}).get("username", "")
            self._server.drop_session(username=old["username"],
                                      keep=WEB_SID.get() if old["username"].lower() == me.lower() else None)
        self._store.add_history("security", "کاربران", "ok", msg)
        return self.users_list()

    def _server_user_delete(self, username):
        from . import serverauth
        with serverauth.LOCK:
            return self._server_user_delete_locked(username)

    def _server_user_delete_locked(self, username):
        from . import serverauth
        data = serverauth.load()
        rec = serverauth.find(data, username)
        if not rec:
            raise VaultError("کاربر پیدا نشد.")
        me = self._current_user()
        if me and rec["username"].lower() == me["username"].lower():
            raise VaultError("نمی‌توانید حساب خودتان را حذف کنید.")
        items = [x for x in data["users"] if x["username"].lower() != rec["username"].lower()]
        if not any(x["role"] == "admin" and not x.get("disabled") and x.get("source") != "ad" for x in items):
            raise VaultError("حداقل یک ادمین محلی فعال لازم است.")
        data["users"] = items
        serverauth.save(data)
        self._server.drop_session(username=rec["username"])
        self._store.add_history("security", "کاربران", "ok", f"کاربر {rec['username']} حذف شد")
        return self.users_list()

    # ------------------------------------------------------------ Active Directory و باز شدن خودکار (1.24، ادمین، حالت سرور)
    def _need_server(self):
        if not paths.is_server():
            raise ConnectorError("فقط در حالت سرور.")

    @_safe
    def server_ad_get(self):
        from . import adauth, autounseal
        self._need_server()
        return {"ad": adauth.cfg_of(self._settings), "unseal": {"available": autounseal.available(), "enabled": autounseal.enabled()}}

    @_safe
    def server_ad_save(self, cfg):
        from . import adauth
        self._need_server()
        try:
            c = adauth.clean(cfg if isinstance(cfg, dict) else {})
        except adauth.ADError as e:
            raise ConnectorError(str(e))
        self._settings.set_ad(c)
        self._store.add_history("security", "Active Directory", "ok",
                                ("ورود با AD روشن شد" if c["enabled"] else "ورود با AD خاموش است") + (f" — {c['urls']}" if c["urls"] else ""))
        return {"ad": c}

    @_safe
    def server_ad_test(self, cfg, username, password):
        """آزمایش تنظیمات (ذخیره‌نشده) با یک کاربر؛ رمز ذخیره نمی‌شود. گزارش مرحله‌به‌مرحله."""
        from . import adauth
        self._need_server()
        now = time.time()                    # حداکثر ۱۰ آزمایش در دقیقه (حدس رمز حساب‌های دامنه از این مسیر نه)
        self._ad_tests = [x for x in getattr(self, "_ad_tests", []) if now - x < 60]
        if len(self._ad_tests) >= 10:
            raise ConnectorError("آزمایش‌های زیاد؛ یک دقیقه صبر کنید.")
        self._ad_tests.append(now)
        c = dict(cfg if isinstance(cfg, dict) else {}, enabled=True)
        try:
            role, user, steps = adauth.authenticate(c, username, password, detail=True)
            return {"good": True, "role": role, "user": user, "steps": steps}
        except adauth.ADError as e:
            return {"good": False, "error": str(e)}

    @_safe
    def server_unseal_set(self, on, current):
        """روشن/خاموش کردن باز شدن خودکار؛ با رمز ادمین جاری (کاربر محلی)."""
        from . import autounseal, serverauth
        self._need_server()
        me = self._current_user() or {}
        if not serverauth.verify(me.get("username", ""), current or ""):
            raise VaultError("رمز فعلی اشتباه است (فقط ادمین محلی).")
        if on:
            try:
                autounseal.enable(self._server.master)
            except OSError as e:
                raise ConnectorError(str(e))
        else:
            autounseal.disable()
        self._store.add_history("security", "باز شدن خودکار", "ok",
                                "روشن شد (کلید اصلی با DPAPI ماشین)" if on else "خاموش شد", user=me.get("username"))
        return {"enabled": autounseal.enabled()}

    # ------------------------------------------------------------ پیکربندی سرور (ادمین)
    @_safe
    def server_config(self):
        if not paths.is_server():
            raise ConnectorError("فقط در حالت سرور.")
        from . import serverauth
        cfg = serverauth.config()
        cfg["sessions"] = self._server.active_sessions() if self._server else []
        cfg["me"] = (self._current_user() or {}).get("username", "")
        cfg["cert"] = self._cert_info()
        return {"server": cfg}

    def _cert_info(self):
        from . import certs
        return certs.info()

    @_safe
    def server_cert_upload(self, files, password=""):
        """گواهی HTTPS شرکت (PFX/P12، یا PEM گواهی + کلید). فقط ادمین؛ بدون اجرای دوباره اعمال می‌شود.
        رمز کلید/PFX فقط برای باز کردن همین یک بار است و ذخیره نمی‌شود."""
        if not paths.is_server():
            raise ConnectorError("فقط در حالت سرور.")
        from . import certs
        from .wipe import overwrite
        if not isinstance(files, list) or not 1 <= len(files) <= 3:
            raise ConnectorError("یک یا دو فایل گواهی انتخاب کنید.")
        srcs = [Path(server_path(f)) for f in files]
        try:
            blobs = []
            for p in srcs:
                if not p.is_file() or p.stat().st_size > 1024 * 1024:
                    raise ConnectorError("فایل گواهی پیدا نشد یا بیش از حد بزرگ است.")
                blobs.append(atrest.read_bytes(p))
            try:
                inf, warns = certs.install(blobs, str(password or ""))
            except certs.CertError as e:
                raise ConnectorError(str(e))
        finally:
            for p in srcs:                 # فایل‌های آپلودشده (شامل کلید خصوصی) پاک می‌شوند
                try:
                    if p.exists():
                        overwrite(p)
                        p.unlink()
                except OSError:
                    pass
        if self._server is not None:
            self._server.reload_tls()
        self._store.add_history("security", "گواهی HTTPS", "ok", f"گواهی شرکت نصب شد: {inf['subject']} (تا {time.strftime('%Y-%m-%d', time.localtime(inf['not_after']))})")
        return {**self.server_config(), "warnings": warns}

    @_safe
    def server_cert_selfsigned(self):
        if not paths.is_server():
            raise ConnectorError("فقط در حالت سرور.")
        from . import certs
        certs.self_signed()
        if self._server is not None:
            self._server.reload_tls()
        self._store.add_history("security", "گواهی HTTPS", "ok", "گواهی خودساخته‌ی تازه جایگزین شد")
        return self.server_config()

    @_safe
    def server_save(self, cfg):
        if not paths.is_server():
            raise ConnectorError("فقط در حالت سرور.")
        import ipaddress as _ip
        from . import serverauth
        c, out = dict(cfg or {}), {}

        def num(k, lo, hi):
            try:
                v = int(c[k])
            except (TypeError, ValueError):
                raise ConnectorError(f"مقدار «{k}» باید عدد باشد.")
            if not lo <= v <= hi:
                raise ConnectorError(f"مقدار «{k}» باید بین {lo} و {hi} باشد.")
            return v
        if "session_timeout_minutes" in c:
            out["session_timeout_minutes"] = num("session_timeout_minutes", 1, 1440)
        if "ad_session_hours" in c:
            out["ad_session_hours"] = num("ad_session_hours", 0, 168)
        if "lockout_threshold" in c:
            out["lockout_threshold"] = num("lockout_threshold", 0, 50)
        if "lockout_minutes" in c:
            out["lockout_minutes"] = num("lockout_minutes", 1, 1440)
        if "port" in c:
            out["port"] = num("port", 1, 65535)
        if "max_connections" in c:
            out["max_connections"] = num("max_connections", 10, 5000)
        if "max_connections_per_ip" in c:
            out["max_connections_per_ip"] = num("max_connections_per_ip", 4, 1000)
        if "bind" in c:
            b = str(c["bind"] or "").strip() or "0.0.0.0"  # nosec B104 — فقط مقدار پیش‌فرض فیلد bind؛ کاربر در تنظیمات تغییر می‌دهد
            try:
                if _ip.ip_address(b).version != 4:
                    raise ValueError
            except ValueError:
                raise ConnectorError("آدرس bind باید یک IPv4 باشد (0.0.0.0 = همه‌ی کارت‌های شبکه).")
            if b not in ("0.0.0.0", "127.0.0.1"):  # nosec B104 — مقایسه، نه bind
                import socket as _so
                t = _so.socket(_so.AF_INET, _so.SOCK_STREAM)
                try:
                    t.bind((b, 0))                 # آدرس باید روی همین سیستم باشد؛ وگرنه سرور دیگر بالا نمی‌آید
                except OSError:
                    raise ConnectorError(f"آدرس {b} روی کارت‌های شبکه‌ی این سیستم نیست.")
                finally:
                    t.close()
            out["bind"] = b
        if "allowed_networks" in c:
            nets = []
            for n in c["allowed_networks"] or []:
                n = str(n).split("#", 1)[0].strip()
                if not n:
                    continue
                try:
                    nets.append(str(_ip.ip_network(n, strict=False)))
                except ValueError:
                    raise ConnectorError(f"رنج نامعتبر: {n}")
            ip = WEB_IP.get()
            if nets and ip and not _ip.ip_address(ip).is_loopback and not any(_ip.ip_address(ip) in _ip.ip_network(n) for n in nets):
                raise ConnectorError(f"IP فعلی شما ({ip}) در رنج‌های مجاز نیست؛ با ذخیره‌ی این فهرست دسترسی خودتان قطع می‌شود.")
            out["allowed_networks"] = nets
        before = serverauth.config()
        serverauth.set_config(out)
        if self._server is not None:
            self._server.reload_cfg()
        restart = any(k in out and out[k] != before.get(k) for k in ("port", "bind"))
        self._store.add_history("security", "سرور", "ok", "تنظیمات سرور تغییر کرد" + ("؛ پورت/bind بعد از اجرای دوباره" if restart else ""))
        return {**self.server_config(), "restart": restart}

    @_safe
    def server_kill_session(self, session_id):
        if not paths.is_server():
            raise ConnectorError("فقط در حالت سرور.")
        if self._server is not None:
            self._server.drop_session(pid=str(session_id or ""))
        self._store.add_history("security", "سرور", "ok", "یک نشست توسط ادمین بسته شد")
        return self.server_config()

    @_safe
    def security_auto_lock(self, minutes):
        m = int(minutes or 0)
        if not 0 <= m <= 1440:
            raise ConnectorError("زمان قفل خودکار باید بین ۰ و ۱۴۴۰ دقیقه باشد.")
        self._settings.update({"security": {"auto_lock_minutes": m}})
        return {"security": self._sec_status()}

    def _sec_status(self):
        st = self._vault.status()
        if paths.is_server():
            from . import serverauth
            st.update(server=True, users_enabled=True, user_count=0, auto_lock_minutes=0, recovery=serverauth.recovery_status())
            return st
        st.update(users_enabled=self._vault.users_enabled(), user_count=len(self._vault.users()),
                  auto_lock_minutes=int(self._settings.get("security", "auto_lock_minutes", default=0) or 0),
                  recovery=self._vault.recovery_status(), data_dir=str(paths.data_dir()))
        return st

    # ------------------------------------------------------------ state
    @_safe
    def get_state(self, since=0):
        v = self._vault
        if v is not None and (v.ui_locked or not v.unlocked() or (v.users_enabled() and self._current_user() is None)):
            # صفحه‌ی قفل/ورود: فقط آنچه برای نمایش آن لازم است
            return {"events": [], "conn": {}, "last_check": None, "run": None, "last_run": None,
                    "counts": {}, "test_mode": True, "master": False, "jobs_on": 0, "demo": self._demo,
                    "version": __version__, "author": AUTHOR, "branding": self._branding(),
                    "security": self._sec_status(), "lang": self._settings.get("ui", "lang") or "en",
                    "me": None, "tools": [], "tools_enabled": []}
        run = self._worker.pipeline.current
        midnight = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0).timestamp()
        counts = {"splunk": 0, "abuse": 0, "ban": 0, "ban_error": 0, "ticket": 0}
        for r in self._store.counts_since(midnight):
            if r["kind"] == "ban":
                if r["status"] == "ok":
                    counts["ban"] += r["n"]
                elif r["status"] == "error":
                    counts["ban_error"] += r["n"]
            elif r["kind"] in counts and r["status"] in ("ok", "warn"):
                counts[r["kind"]] += r["n"]
        counts.update(self._ip_counts())
        last = self._store.last_run()
        return {
            "events": self._worker.events_since(int(since or 0)),
            "conn": self._worker.conn_view(), "fg_devices": self._settings.fg_devices(), "last_check": self._worker.last_check,
            "run": run.to_dict(full=False) | {"approval": run.approval is not None} if run else None,
            "last_run": last, "counts": counts,
            "test_mode": self._settings.get("test_mode", default=True),
            "master": self._settings.get("automation", "master", default=False),
            "jobs_on": sum(1 for j in self._settings.get("jobs", default=[]) or [] if j.get("enabled")),
            "demo": self._demo, "version": __version__, "author": AUTHOR,
            "branding": self._branding(),
            "security": self._sec_status() if self._vault else None,
            "lang": self._settings.get("ui", "lang") or "en",
            "db": self._db_state(),
            "assets_pending": self._store.asset_pending_count() if self._asset_can_view() else 0,
            **self._me(),
        }

    def _ip_counts(self):
        """شمارش‌های آدرس‌ها برای داشبورد. get_state هر ۱ تا ۲.۵ ثانیه صدا زده می‌شود؛ قبلاً هر بار کل جدول ips
        به dict تبدیل و قانون بلاک روی همه اجرا می‌شد (با ۵۰ هزار IP حدود ۰.۸ ثانیه CPU و قفل پایگاه داده).
        حالا فقط وقتی پایگاه داده، روز یا تنظیمات AbuseIPDB عوض شده دوباره حساب می‌شود."""
        from .pipeline import block_reason_v
        acfg = self._settings.get("abuseipdb") or {}
        today = datetime.now().strftime("%Y-%m-%d")
        key = (self._store.change_mark(), today, acfg.get("threshold"), bool(acfg.get("skip_whitelisted")))
        c = self._ipc_cache
        # هنگام اجرا پایگاه داده هر چند ثانیه تغییر می‌کند؛ آن موقع شمارش‌ها حداکثر هر ۱۰ ثانیه دوباره حساب می‌شوند (نه هر poll)
        cur = getattr(self._worker.pipeline, "current", None)
        busy = bool(cur and getattr(cur, "status", "") in ("running", "awaiting"))
        if c and (c[0] == key or (busy and c[0][1:] == key[1:] and time.time() - c[2] < IPC_TTL)):
            return dict(c[1])
        out = {"abuse_today": 0, "review_pending": 0, "unchecked": 0, "fw_pending": 0}
        for status, score, wl, fw, checked, review in self._store.ip_count_rows():
            if not status:
                out["unchecked"] += 1
            elif status == "ABUSE" and str(checked or "").startswith(today):
                out["abuse_today"] += 1
            if review == "pending":
                out["review_pending"] += 1
            if fw not in FW_DONE and block_reason_v(status, score, wl, acfg):
                out["fw_pending"] += 1
        self._ipc_cache = (key, out, time.time())
        return dict(out)

    _ipc_cache = None

    # ------------------------------------------------------------ branding / logo
    def _branding(self):
        b = self._settings.get("branding") or {}
        f = b.get("logo_file")
        b["logo_data"] = ""
        if f and (Path(str(f)).name != str(f) or str(f).startswith(".")):   # فقط نام فایل داخل پوشه‌ی branding
            f = ""
        if f:
            p = paths.data_dir() / "branding" / f
            if p.is_file():
                key = (str(p), p.stat().st_mtime)
                if key not in self._logo_cache:
                    mime = {".png": "image/png", ".svg": "image/svg+xml", ".ico": "image/x-icon",
                            ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".webp": "image/webp"}.get(p.suffix.lower(), "image/png")
                    self._logo_cache = {key: f"data:{mime};base64," + base64.b64encode(p.read_bytes()).decode()}
                b["logo_data"] = self._logo_cache[key]
        return b

    @_safe
    def set_logo(self, kind="logo", path=None):
        """kind: logo (نوار کناری، PNG/SVG/JPG/ICO) یا icon (آیکون پنجره، فقط ICO)."""
        if kind not in ("logo", "icon"):
            raise ConnectorError("نوع نامعتبر است.")
        path = server_path(path)
        if not path:
            if not self._window:
                raise ConnectorError("انتخاب فایل در این محیط در دسترس نیست.")
            import webview
            types = ("Icon (*.ico)",) if kind == "icon" else ("Images (*.png;*.svg;*.jpg;*.jpeg;*.webp;*.ico)",)
            res = self._window.create_file_dialog(webview.OPEN_DIALOG, allow_multiple=False, file_types=types)
            if not res:
                return {"cancelled": True}
            path = res[0] if isinstance(res, (list, tuple)) else res
        src = Path(path)
        ext = src.suffix.lower()
        allowed = (".ico",) if kind == "icon" else (".png", ".svg", ".jpg", ".jpeg", ".webp", ".ico")
        if ext not in allowed:
            raise ConnectorError("فرمت فایل مجاز نیست: " + "، ".join(allowed))
        if not src.is_file() or src.stat().st_size > 1024 * 1024:
            raise ConnectorError("فایل پیدا نشد یا بزرگ‌تر از ۱ مگابایت است.")
        d = paths.data_dir() / "branding"
        d.mkdir(exist_ok=True)
        for old in d.glob(f"{kind}.*"):
            old.unlink()
        dst = d / f"{kind}{ext}"
        from . import atrest
        dst.write_bytes(atrest.read_bytes(src))   # آپلود سرور رمزشده است؛ فایل ساده هم همان‌طور خوانده می‌شود
        self._settings.update({"branding": {f"{kind}_file": dst.name}})
        if kind == "icon" and self._window:
            from .winicon import apply_icon
            apply_icon(self._window, str(dst))
        return {"branding": self._branding()}

    @_safe
    def clear_logo(self, kind="logo"):
        if kind not in ("logo", "icon"):
            raise ConnectorError("نوع نامعتبر است.")
        d = paths.data_dir() / "branding"
        for old in d.glob(f"{kind}.*") if d.exists() else []:
            old.unlink()
        self._settings.update({"branding": {f"{kind}_file": ""}})
        return {"branding": self._branding()}

    # ------------------------------------------------------------ about
    @_safe
    def get_about(self):
        def ver(mod):
            try:
                return __import__(mod).__version__
            except Exception:
                return "—"
        return {"name": APP_NAME, "version": __version__, "author": AUTHOR, "license": "MIT",
                "contacts": [{"kind": k, "text": t, "url": u} for k, t, u in CONTACTS],
                "credit": "با کمک Claude (Anthropic) نوشته شده است",
                "python": platform.python_version(), "os": platform.platform(),
                "libs": {"pywebview": ver("webview"), "requests": ver("requests"), "cryptography": ver("cryptography")},
                "data_dir": str(paths.data_dir())}

    # ------------------------------------------------------------ security
    @_safe
    def security_status(self):
        return {"security": self._sec_status()}

    @_safe
    def security_check_password(self, pw):
        return {"errors": check_password(pw or "", self._settings.get("security", "strong_policy", default=True))}

    @_safe
    def security_generate(self):
        strong = self._settings.get("security", "strong_policy", default=True)
        while True:
            pw = pysecrets.token_urlsafe(36)
            if not check_password(pw, strong):
                return {"password": pw}
            pw = pw[:-2] + "7!"
            if not check_password(pw, strong):
                return {"password": pw}

    @_safe
    def security_setup(self, mode, password="", remember=False):
        self._vault.setup(mode, password or "", bool(remember))
        self._worker.emit("ok", {"simple": "حالت ساده فعال شد", "password": "رمز اصلی تنظیم شد"}.get(mode, mode), "security")
        self._worker.request_check()
        return {"security": self._sec_status()}

    @_safe
    def security_unlock(self, password, username=""):
        t0 = time.time()
        wait = int(self._unlock_until - t0)
        if wait > 0:
            raise VaultError(f"به‌خاطر تلاش‌های ناموفق پشت‌سرهم، {wait} ثانیه‌ی دیگر دوباره امتحان کنید.")
        try:
            if self._vault.users_enabled():
                rec = self._vault.unlock_user(username, password or "")
                items = [{**x, "last_login": time.time()} if x["username"] == rec["username"] else x for x in self._vault.users()]
                self._settings.set_users(items)
                self._user = self._vault.find_user(rec["username"])
            else:
                self._vault.unlock(password or "")
        except VaultError:
            time.sleep(max(0.0, 1.0 - (time.time() - t0)))  # کند کردن حدس زدن
            self._unlock_fails += 1
            n = self._unlock_fails
            self._store.add_history("security", "باز کردن قفل", "error", f"رمز اشتباه ({n} بار پشت‌سرهم)"
                                    + (f" — نام کاربری: {str(username)[:40]}" if username else ""))
            if n >= UNLOCK_FREE_TRIES:
                secs = min(UNLOCK_MAX_WAIT, 30 * 2 ** (n - UNLOCK_FREE_TRIES))
                self._unlock_until = time.time() + secs
                raise VaultError(f"رمز اشتباه است. به‌خاطر {n} تلاش ناموفق پشت‌سرهم، {secs} ثانیه صبر کنید.")
            raise
        if self._unlock_fails:
            self._store.add_history("security", "باز کردن قفل", "ok", f"باز شد، پس از {self._unlock_fails} تلاش ناموفق")
        self._unlock_fails, self._unlock_until = 0, 0.0
        self._last_act = time.time()
        self._worker.emit("ok", "قفل برنامه باز شد" + (f" ({self._user['username']})" if self._user else ""), "security")
        if self._user:
            self._store.add_history("security", "ورود", "ok", f"{self._user['username']} وارد شد", user=self._user["username"])
        self._worker.request_check()
        return {"security": self._sec_status()}

    @_safe
    def security_lock(self, full=False):
        if paths.is_server():
            if not full:   # خروج از حساب: فقط همین نشست
                self._term.close_all(self._uname())
                self._xfer.close_all(self._uname())
                if self._server is not None:
                    self._server.drop_session(sid=WEB_SID.get())
                return {"logout": True}
            if (self._current_user() or {}).get("role") != "admin":
                raise VaultError("قفل کامل فقط برای ادمین است.")
            self._store.add_history("security", "سرور", "warn", "قفل کامل: کارها متوقف و کلیدها از حافظه پاک شد")
            self._term.close_all()
            self._xfer.close_all()
            srv = self._server
            threading.Thread(target=lambda: (time.sleep(0.5), srv.tear_down()), daemon=True).start()
            return {"logout": True}
        if full and self._user and self._user.get("role") != "admin":
            raise VaultError("قفل کامل فقط برای ادمین است.")
        self._vault.lock(bool(full))
        self._term.close_all()
        self._xfer.close_all()
        self._user = None
        if full:
            self._worker.pipeline.cancel()
            self._worker.emit("warn", "برنامه کامل قفل شد؛ کارهای خودکار تا وارد کردن رمز اجرا نمی‌شوند", "security")
        else:
            self._worker.emit("info", "رابط برنامه قفل شد؛ کارهای خودکار در پس‌زمینه ادامه دارند", "security")
        return {"security": self._sec_status()}

    def _verify_current(self, current):
        if self._vault.users_enabled():
            self._pw_attempt(lambda: bool(self._user) and self._vault.verify_user(self._user["username"], current or ""))
            return
        if self._vault.mode == "password":
            self._pw_attempt(lambda: bool(current) and hmac.compare_digest(derive_key(current, self._vault._salt), self._vault._key))

    @_safe
    def security_change(self, mode, password="", remember=False, current=""):
        self._verify_current(current)
        self._vault.change(mode, password or "", bool(remember))
        self._worker.emit("ok", "تنظیمات امنیتی تغییر کرد؛ همه‌ی اسرار با کلید جدید دوباره رمز شدند", "security")
        return {"security": self._sec_status()}

    @_safe
    def security_set_remember(self, on, current=""):
        if on:
            self._verify_current(current)
        self._vault.set_remember(bool(on))
        return {"security": self._sec_status()}

    @_safe
    def security_policy(self, strong):
        self._settings.update({"security": {"strong_policy": bool(strong)}})
        return {"security": self._sec_status()}

    # ------------------------------------------------------------ کد بازیابی رمز (1.27.8)
    @_safe
    def security_recovery_create(self, current=""):
        """کد بازیابی تازه (کد قبلی باطل). فقط ادمین، با رمز خودش. کد فقط در همین پاسخ است."""
        import socket
        from . import recovery as rc
        if paths.is_server():
            from . import serverauth
            me = self._current_user() or {}
            if me.get("role") != "admin":
                raise VaultError("ساخت کد بازیابی فقط برای ادمین است.")
            rec = serverauth.find(serverauth.load(), me.get("username", "")) or {}
            if rec.get("source") != "ad":
                self._pw_attempt(lambda: serverauth.verify(me["username"], current or ""))
            code = serverauth.recovery_create(self._server.master)
            where = f"سرور AutoKRP ({socket.gethostname()}) — رمز ادمین‌های محلی"
        else:
            if self._vault.mode != "password":
                raise VaultError("کد بازیابی فقط در حالت «رمز اصلی» معنا دارد.")
            self._verify_current(current)
            code = self._vault.recovery_create()
            where = f"AutoKRP روی {socket.gethostname()}" + (" — رمز ادمین‌ها" if self._vault.users_enabled() else " — رمز اصلی")
        self._store.add_history("security", "کد بازیابی", "ok", "کد بازیابی تازه ساخته شد (کد قبلی دیگر کار نمی‌کند)")
        return {"code": code, "file": rc.file_text(code, where), "filename": "AutoKRP-recovery-code.txt", "security": self._sec_status()}

    @_safe
    def security_recover(self, code, new_password, username=""):
        """کلاینت، صفحه‌ی قفل/ورود: کد بازیابی ← رمز تازه (حالت تک‌رمزی: رمز اصلی؛ با کاربران: رمز یک ادمین) و کد تازه.
        حالت سرور از /auth/recover (پیش از ورود)."""
        import socket
        from . import recovery as rc
        if paths.is_server():
            raise VaultError("در حالت سرور از صفحه‌ی ورود ← «رمز را فراموش کرده‌ام» استفاده کنید.")
        v = self._vault
        if v.mode != "password" or not v.recovery_status()["has"]:
            raise VaultError("برای این برنامه کد بازیابی ساخته نشده است.")
        t0 = time.time()
        wait = int(self._unlock_until - t0)
        if wait > 0:
            raise VaultError(f"به‌خاطر تلاش‌های ناموفق پشت‌سرهم، {wait} ثانیه‌ی دیگر دوباره امتحان کنید.")
        strong = self._settings.get("security", "strong_policy", default=True)
        errs = check_password(new_password or "", strong)
        if errs:
            raise VaultError("رمز تازه شرایط لازم را ندارد: " + "، ".join(errs))
        target = None
        if v.users_enabled():
            target = v.find_user(username)
            if target is None or target.get("role") != "admin" or target.get("disabled"):
                target = False
        try:
            key = v.recovery_open(code)
            if target is False:
                raise VaultError("کد بازیابی یا نام کاربری ادمین درست نیست.")
        except VaultError:
            time.sleep(max(0.0, 1.0 - (time.time() - t0)))
            self._unlock_fails += 1
            n = self._unlock_fails
            self._store.add_history("security", "کد بازیابی", "error", f"کد بازیابی اشتباه ({n} بار پشت‌سرهم)")
            if n >= UNLOCK_FREE_TRIES:
                secs = min(UNLOCK_MAX_WAIT, 30 * 2 ** (n - UNLOCK_FREE_TRIES))
                self._unlock_until = time.time() + secs
            raise VaultError("کد بازیابی یا نام کاربری ادمین درست نیست." if v.users_enabled() else "کد بازیابی درست نیست.")
        self._unlock_fails = 0
        with v._lock:
            if v._key is not None:
                if not hmac.compare_digest(key, v._key):
                    raise VaultError("کد بازیابی با فایل اسرار نمی‌خواند.")
                v.ui_locked = False
            else:
                v._open(key)
            if target:
                rec = v.rewrap(target, new_password)
                self._save_users([rec if x["username"] == target["username"] else x for x in v.users()])
                self._user = v.find_user(target["username"])
                who = f"رمز ادمین «{target['username']}»"
            else:
                v.change("password", new_password, bool(self._settings.get("security", "remember", default=False)))
                who = "رمز اصلی"
        new_code = v.recovery_create()                  # کد استفاده‌شده باطل
        self._store.add_history("security", "کد بازیابی", "warn", f"{who} با کد بازیابی عوض شد؛ کد بازیابی تازه ساخته شد")
        self._worker.emit("warn", f"{who} با کد بازیابی عوض شد", "security")
        self._worker.request_check()
        where = f"AutoKRP روی {socket.gethostname()}" + (" — رمز ادمین‌ها" if v.users_enabled() else " — رمز اصلی")
        return {"code": new_code, "file": rc.file_text(new_code, where), "filename": "AutoKRP-recovery-code.txt",
                "security": self._sec_status()}

    def _pw_attempt(self, ok_fn, msg="رمز فعلی اشتباه است."):
        """بررسی رمز فعلی در کارهای حساس (پاک‌سازی کامل، تغییر رمز/حالت): حداکثر ۵ اشتباه در ۱۵ دقیقه برای هر کاربر.
        1.27.7: قبلاً بدون سقف بود و با نشست دزدیده‌شده می‌شد رمز فعلی را حدس زد."""
        key, now = (self._current_user() or {}).get("username", "") or "-", time.time()
        allf = getattr(self, "_pw_fails", {})
        fails = [t for t in allf.get(key, []) if now - t < 900]
        if len(fails) >= 5:
            raise VaultError("تلاش‌های اشتباه زیاد بود؛ ۱۵ دقیقه‌ی دیگر دوباره امتحان کنید.")
        if not ok_fn():
            allf[key] = fails + [now]
            self._pw_fails = allf
            if len(fails) >= 2:
                self._store.add_history("security", "رمز", "warn", "رمز فعلی چند بار اشتباه وارد شد")
            raise VaultError(msg)
        allf.pop(key, None)
        self._pw_fails = allf

    @_safe
    def security_reset(self, confirm, password=""):
        """پاک‌سازی کامل: همه‌ی داده‌ها، تنظیمات، اسرار، نسخه‌های کانفیگ، تاریخچه و لاگ‌ها. سپس برنامه بسته می‌شود.
        1.27.7: از داخل برنامه (کاربر وارد شده) فقط ادمین و با رمز خودش؛ از صفحه‌ی قفل (رمز فراموش‌شده) مثل قبل."""
        if (confirm or "").strip().upper() != "RESET":
            raise VaultError("برای پاک کردن، کلمه‌ی RESET را دقیق تایپ کنید.")
        if paths.is_server():
            from .server import is_local
            from . import serverauth
            me = self._current_user() or {}
            if me.get("role") != "admin" or not is_local(WEB_IP.get()):
                raise VaultError("در حالت سرور، پاک‌سازی کامل فقط برای ادمین و فقط از خود سیستم سرور (localhost) ممکن است.")
            rec = serverauth.find(serverauth.load(), me.get("username", "")) or {}
            if rec.get("source") != "ad":            # رمز کاربر AD را خود AD بررسی می‌کند (ورود همین نشست)
                self._pw_attempt(lambda: serverauth.verify(me["username"], password or ""), "برای پاک‌سازی کامل، رمز خودتان را درست وارد کنید.")
        else:
            # 1.27.8 (تصمیم کاربر): RESET فقط از داخل برنامه؛ از صفحه‌ی قفل/ورود هرگز (تا کسی بدون رمز خراب‌کاری نکند).
            # رمز فراموش‌شده ← کد بازیابی؛ اگر آن هم نیست ← بستن برنامه و پاک کردن دستی پوشه‌ی داده.
            v = self._vault
            if v is None or not v.unlocked() or v.ui_locked:
                raise VaultError("پاک‌سازی کامل فقط از داخل برنامه (پس از ورود) ممکن است.")
            msg = "برای پاک‌سازی کامل، رمز خودتان را درست وارد کنید."
            if v.users_enabled():
                u = self._current_user()
                if u is None:
                    raise VaultError("پاک‌سازی کامل فقط از داخل برنامه (پس از ورود) ممکن است.")
                if u.get("role") != "admin":
                    raise VaultError("پاک‌سازی کامل فقط برای ادمین است.")
                self._pw_attempt(lambda: v.verify_user(u["username"], password or ""), msg)
            elif v.mode == "password":
                self._pw_attempt(lambda: v.verify_master(password or ""), msg)
        import logging as _lg
        import threading as _th
        from . import wipe
        root = paths.data_dir()   # در حالت Demo فقط داده‌ی Demo؛ در حالت عادی کل پوشه (شامل Demo)
        log.warning("factory reset requested")
        self._worker.stop(wait=10)
        try:
            n = self._store.wipe_backend()      # MySQL: جدول‌های AutoKRP حذف می‌شوند
            if n:
                log.warning("factory reset: %d MySQL tables dropped", n)
        except Exception as e:
            log.error("factory reset: dropping MySQL tables failed: %s", e)
        self._vault.forget()
        self._store.close()
        from . import atrest
        atrest.forget()
        for h in list(_lg.getLogger().handlers):
            if isinstance(h, _lg.FileHandler):
                h.close()
                _lg.getLogger().removeHandler(h)
        if paths.is_server() and self._server is not None:
            self._server.sessions.clear()
        task_left = False
        if paths.is_server() and not paths.is_demo():
            # 1.26.2: تسک «اجرای خودکار با روشن شدن ویندوز» هم حذف شود (داده‌ای ندارد و بعد از RESET کاری نمی‌کند،
            # ولی نباید باقی بماند). حذف آن دسترسی Administrator می‌خواهد؛ بدون آن فقط به کاربر گفته می‌شود.
            try:
                from . import winsvc
                if winsvc.supported() and winsvc.installed():
                    if winsvc.is_admin():
                        winsvc.remove()
                    else:
                        task_left = True
            except Exception as e:  # noqa — پاک‌سازی داده نباید به‌خاطر تسک متوقف شود
                log.error("factory reset: removing autostart task failed: %s", e)
                task_left = True
        left = wipe.wipe_dir(root)
        if not paths.is_demo():
            paths.clear_location()          # 1.26.2: اجرای بعدی دوباره پوشه‌ی داده را می‌پرسد
        self._wiped = True
        if paths.is_server():   # سرور بعد از پاک‌سازی بسته می‌شود؛ اجرای بعدی از صفر
            def _exit():
                time.sleep(3)
                os._exit(0)
            _th.Thread(target=_exit, daemon=True).start()
            return {"wiped": True, "left": left[:20], "closing": True, "task_left": task_left}
        if self._window:
            def _close():
                time.sleep(4)
                try:
                    self._window.destroy()
                except Exception:
                    pass
            _th.Thread(target=_close, daemon=True).start()
        return {"wiped": True, "left": left[:20], "closing": bool(self._window)}

    # ------------------------------------------------------------ settings export / import (بدون اسرار)
    @_safe
    def export_settings(self):
        data = self._settings.public()
        for c in ("splunk", "abuseipdb", "fortigate", "redmine"):
            for k in list(data.get(c, {})):
                if k.startswith("has_"):
                    del data[c][k]
        data.pop("security", None)
        data = {"autokrp_settings": 1, "version": __version__, "settings": data}
        name = f"autokrp_settings_{datetime.now():%Y%m%d_%H%M}.json"
        if self._window:
            import webview
            res = self._window.create_file_dialog(webview.SAVE_DIALOG, save_filename=name, file_types=("JSON (*.json)",))
            if not res:
                return {"cancelled": True}
            path = res[0] if isinstance(res, (list, tuple)) else res
        else:
            d = paths.data_dir() / "exports"
            d.mkdir(exist_ok=True)
            path = str(d / name)
        Path(path).write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        return {"path": path}

    @_safe
    def import_settings(self, path=None):
        path = server_path(path)
        if not path:
            if not self._window:
                raise ConnectorError("انتخاب فایل در این محیط در دسترس نیست.")
            import webview
            res = self._window.create_file_dialog(webview.OPEN_DIALOG, file_types=("JSON (*.json)",))
            if not res:
                return {"cancelled": True}
            path = res[0] if isinstance(res, (list, tuple)) else res
        try:
            from . import atrest
            raw = json.loads(atrest.read_text(path, "utf-8-sig"))
        except (OSError, ValueError) as e:
            raise ConnectorError(f"فایل تنظیمات خوانده نشد: {e}")
        if not isinstance(raw, dict) or raw.get("autokrp_settings") != 1 or not isinstance(raw.get("settings"), dict):
            raise ConnectorError("این فایل خروجی تنظیمات AutoKRP نیست.")
        patch = raw["settings"]
        # 1.27.7: همان کلیدهایی که «ذخیره‌ی تنظیمات» هم نمی‌پذیرد (ad و events فقط از متدهای خودشان با اعتبارسنجی)
        for k in ("security", "secrets", "has_password", "users", "server", "ui_users", "jobs", "ssh_schedules", "ad", "events"):
            patch.pop(k, None)
        from .settings import SECRET_KEYS
        for c, keys in SECRET_KEYS.items():          # هیچ رازی از فایل وارد نمی‌شود (notify هم)
            for k in keys:
                (patch.get(c) or {}).pop(k, None) if isinstance(patch.get(c), dict) else None
        if isinstance(patch.get("branding"), dict):  # نام فایل لوگو/آیکون فقط از set_logo (جلوگیری از خواندن فایل دلخواه)
            for k in ("logo_file", "icon_file", "logo_data"):
                patch["branding"].pop(k, None)
        self._validate(patch)                        # همان بررسی‌های «ذخیره‌ی تنظیمات»
        self._check_secret_dest(patch)               # تغییر مقصد اتصال بدون وارد کردن دوباره‌ی راز رد می‌شود
        self._settings.update(patch)
        self._store.add_history("security", "تنظیمات", "ok", f"ورود تنظیمات از فایل {Path(str(path)).name}")
        return {"settings": self._settings.public()}

    @_safe
    def get_run(self, run_id=None, have=None):
        """have: امضای فهرست‌هایی که رابط از قبل دارد. فهرست‌ها (رکوردهای AbuseIPDB، برنامه‌ی FortiGate، …) با هزاران IP
        چند مگابایت‌اند و رابط هر ثانیه poll می‌کند؛ قبلاً هر بار کامل فرستاده می‌شدند (در دسکتاپ هر بار به‌صورت متن
        اسکریپت به WebView2، که حافظه‌ی آن را تا چند گیگابایت بالا برد). حالا فقط وقتی عوض شده‌اند، و در حین اجرا حداکثر
        هر RUN_LISTS_SECS ثانیه یک بار."""
        run = self._worker.pipeline.current
        if not run or (run_id and run.id != run_id):
            return {"run": None}
        d = run.to_dict()
        sig = _lists_sig(d)
        d["lists_sig"] = sig
        key = (run.id, self._uname())
        now = time.monotonic()
        if have and (have == sig or (run.status == "running" and now - self._run_sent.get(key, 0) < RUN_LISTS_SECS)):
            d.pop("lists", None)
            d["lists_same"] = True
            d["lists_sig"] = have                 # همان نسخه‌ی رابط (در حین اجرا چند ثانیه بعد نسخه‌ی تازه)
            if d.get("approval"):                 # پیش‌نمایش تأیید (برنامه‌ی هزاران IP) هم همان قبلی است؛ id در امضاست
                d["approval"] = {k: v for k, v in d["approval"].items() if k != "preview"} | {"same": True}
        else:
            self._run_sent = {k: v for k, v in self._run_sent.items() if k[0] == run.id}
            self._run_sent[key] = now
        return {"run": d}

    _run_sent = {}

    # ------------------------------------------------------------ settings
    @_safe
    def get_settings(self):
        v = self._vault
        if v is not None and (v.ui_locked or not v.unlocked() or (v.users_enabled() and self._current_user() is None)):
            pub = self._settings.public()   # پیش از ورود: فقط ظاهر برنامه
            return {"settings": {k: pub.get(k) for k in ("ui", "branding", "theme")}, "paths": {}, "template_vars": [], "limited": True}
        pub = self._settings.public()
        u = self._current_user()
        mine = (pub.get("ui_users") or {}).get((u or {}).get("username", "").lower()) if u else None
        pub.pop("ui_users", None)
        if mine:                                      # ترجیحات نمایش همین کاربر (زبان، ستون‌ها، تقویم)
            pub["ui"] = {**(pub.get("ui") or {}), **mine}
        if u and u.get("role") != "admin":
            return {"settings": self._limited_settings(pub), "paths": {}, "template_vars": [], "limited": True}
        return {"settings": pub, "paths": {"data": str(paths.data_dir()),
                                           "logs": str(paths.logs_dir()),
                                           "runs": str(paths.runs_dir())},
                "template_vars": rm.TEMPLATE_VARS}

    @staticmethod
    def _limited_settings(pub):
        """غیرادمین: فقط آنچه صفحه‌های غیرتنظیمات لازم دارند؛ نه آدرس سرورها، یوزرها، گیرنده‌های ایمیل،
        متن کوئری‌ها، اسکریپت‌ها و کارها."""
        a = pub.get("automation") or {}
        sp = pub.get("splunk") or {}
        sc = pub.get("scan") or {}
        return {
            "ui": pub.get("ui") or {}, "branding": pub.get("branding") or {}, "theme": pub.get("theme"),
            "test_mode": pub.get("test_mode"), "tools_enabled": pub.get("tools_enabled") or {},
            "automation": {"master": bool(a.get("master")),
                           "retry_errors": {"enabled": bool((a.get("retry_errors") or {}).get("enabled"))},
                           "backup": {"enabled": bool((a.get("backup") or {}).get("enabled"))}},
            "splunk": {"earliest": sp.get("earliest", ""), "latest": sp.get("latest", ""),
                       "queries": [{k: q.get(k) for k in ("id", "name", "earliest", "latest")} for q in sp.get("queries") or []]},
            "dns": {"concurrency": (pub.get("dns") or {}).get("concurrency", 20)},
            "scan": {k: sc.get(k) for k in ("allowed_networks", "max_hosts", "workers", "timeout")},
            "intel": {k: bool((pub.get("intel") or {}).get(k, k == "feed_enabled")) for k in ("feed_enabled", "local_enabled")},
            "backup": {}, "notify": {}, "fortigate": {}, "abuseipdb": {},
            # 1.28: تسک‌های FortiGate (گام‌ها قابل دیدن برای اپراتور؛ رازی در آن‌ها نیست)
            "fg_scenarios": pub.get("fg_scenarios") or [],
            "redmine": {"templates": [{"id": t.get("id"), "name": t.get("name")} for t in (pub.get("redmine") or {}).get("templates") or []],
                        "default_template": (pub.get("redmine") or {}).get("default_template", "")},
        }

    @_safe
    def save_settings(self, patch):
        before_master = self._settings.get("automation", "master", default=False)
        before_daily = self._settings.get("automation", "daily", "enabled", default=False)
        patch = dict(patch or {})
        patch.pop("security", None)   # فقط از متدهای security_* تغییر می‌کند
        patch.pop("ad", None)         # فقط از server_ad_save (با اعتبارسنجی)
        patch.pop("events", None)     # فقط از mon_events_cfg_save
        if isinstance(patch.get("branding"), dict):
            for k in ("logo_file", "icon_file", "logo_data"):
                patch["branding"].pop(k, None)
        self._validate(patch or {})
        self._check_secret_dest(patch)
        before_ign = self._settings.get("fortigate", "ignore_networks", default=[])
        added = self._settings.update(patch or {})
        if added or self._settings.get("fortigate", "ignore_networks", default=[]) != before_ign:
            self._cleanup_excluded()
        if added:
            self._store.add_history("security", "رنج‌های مستثنا", "ok", "IP سرورهای برنامه اضافه شد: " + "، ".join(added))
        self._after_auto_change(before_master, before_daily)
        self._worker.request_check()
        return {"settings": self._settings.public()}

    def _check_secret_dest(self, patch):
        """تغییر مقصد اتصال (آدرس/هاست/پورت) بدون وارد کردن دوباره‌ی توکن/رمز ذخیره‌شده پذیرفته نمی‌شود؛
        وگرنه با عوض کردن آدرس، راز ذخیره‌شده به سرور دیگری فرستاده می‌شد."""
        from .settings import SECRET_KEYS
        for conn, keys in SECRET_KEYS.items():
            sub = patch.get(conn)
            if not isinstance(sub, dict):
                continue
            saved = self._settings.get(conn) or {}
            moved = [k for k in ("address", "host", "port") if k in sub and str(saved.get(k) or "").strip()
                     and str(sub.get(k) or "").strip() != str(saved.get(k) or "").strip()]
            if not moved:
                continue
            stored = [k for k in keys if self._settings.secret(conn, k)]
            missing = [k for k in stored if not sub.get(k)]
            if missing:
                title = {"splunk": "Splunk", "abuseipdb": "AbuseIPDB", "fortigate": "FortiGate", "redmine": "Redmine",
                         "notify": "SMTP"}.get(conn, conn)
                raise ConnectorError(f"{title}: مقصد اتصال عوض شده است؛ "
                                     f"{'، '.join({'token': 'توکن', 'extra_tokens': 'کلیدهای اضافه'}.get(k, 'پسورد') for k in missing)} را دوباره وارد کنید "
                                     "(یا با «پاک» حذفش کنید).")

    def _validate(self, p):
        for k in ("poll_minutes", "max_age_hours"):
            if k in p:
                try:
                    if float(p[k]) <= 0:
                        raise ValueError
                except (TypeError, ValueError):
                    raise ConnectorError("فاصله‌ی بررسی و حداکثر قدمت باید عدد مثبت باشند.")
        ab = p.get("abuseipdb")
        if isinstance(ab, dict) and ("export_dir" in ab or "export_enabled" in ab):   # 1.28: خروجی بی‌رمز AbuseIPDB
            cur = self._settings.get("abuseipdb") or {}
            on = bool(ab.get("export_enabled", cur.get("export_enabled")))
            d = str(ab.get("export_dir", cur.get("export_dir")) or "").strip()
            ab["export_dir"] = d
            if on:
                if not d or not os.path.isabs(d):
                    raise ConnectorError("AbuseIPDB: مسیر کامل پوشه‌ی خروجی بی‌رمز را وارد کنید (مثلاً D:\\SOC\\abuse).")
                if not os.path.isdir(d):
                    raise ConnectorError(f"AbuseIPDB: پوشه‌ی «{d}» وجود ندارد.")
                if Path(d).resolve() == paths.data_dir().resolve() or paths.data_dir().resolve() in Path(d).resolve().parents:
                    raise ConnectorError("AbuseIPDB: پوشه‌ی خروجی بی‌رمز نباید داخل پوشه‌ی داده‌های برنامه باشد.")
        if "fg_scenarios" in p:           # 1.29: تسک‌های پایتونی FortiGate (فقط ادمین؛ هر تغییر کد در تاریخچه)
            from . import fgtask
            try:
                p["fg_scenarios"] = fgtask.validate_all(p["fg_scenarios"])
            except fgtask.TaskError as e:
                raise ConnectorError(str(e))
            for line in fgtask.changes(self._settings.get("fg_scenarios", default=[]) or [], p["fg_scenarios"]):
                self._store.add_history("security", "تسک FortiGate", "ok", line)
        sq = (p.get("splunk") or {}).get("queries")
        if sq is not None:
            if not isinstance(sq, list):
                raise ConnectorError("فهرست کوئری‌های Splunk نامعتبر است.")
            names = set()
            for q in sq:
                n = str(q.get("name") or "").strip()
                if not n:
                    raise ConnectorError("نام هر کوئری ذخیره‌شده‌ی Splunk لازم است.")
                if n in names or n == "پیش‌فرض":
                    raise ConnectorError(f"نام کوئری تکراری است: {n}")
                names.add(n)
                if not str(q.get("id") or "").strip():
                    q["id"] = os.urandom(6).hex()
        d = p.get("dns")
        if isinstance(d, dict):
            from . import dnstool
            try:
                if d.get("server"):
                    dnstool.Lookup(d["server"], 1, 1)
                for k, lo, hi in (("timeout", 1, 60), ("max_records", 1, 10), ("concurrency", 1, dnstool.MAX_CONCURRENCY)):
                    if k in d and not lo <= int(d[k] or 0) <= hi:
                        raise ConnectorError(f"مقدار DNS «{k}» باید بین {lo} و {hi} باشد.")
            except dnstool.DnsError as e:
                raise ConnectorError(str(e))
            except (TypeError, ValueError):
                raise ConnectorError("تنظیمات DNS باید عدد باشند.")
        rp = p.get("redmine")
        if isinstance(rp, dict) and "templates" in rp:
            from .settings import TEMPLATE_KEYS
            tl = rp["templates"]
            if not isinstance(tl, list) or not tl or len(tl) > 100:
                raise ConnectorError("حداقل یک قالب تیکت لازم است.")
            names, clean = set(), []
            for t in tl:
                if not isinstance(t, dict):
                    raise ConnectorError("قالب تیکت نامعتبر است.")
                n = str(t.get("name") or "").strip()[:80]
                if not n:
                    raise ConnectorError("نام هر قالب تیکت لازم است.")
                if n.lower() in names:
                    raise ConnectorError(f"نام قالب تکراری است: {n}")
                names.add(n.lower())
                tid = str(t.get("id") or "").strip()
                if not re.fullmatch(r"[A-Za-z0-9_-]{1,40}", tid):
                    tid = os.urandom(6).hex()
                c = {"id": tid, "name": n}
                for k in TEMPLATE_KEYS:
                    if k in t:
                        c[k] = t[k]
                if not isinstance(c.get("tracker_values", {}), dict):
                    c["tracker_values"] = {}
                c["subject"] = str(c.get("subject") or "")[:255]
                clean.append(c)
            if len({c["id"] for c in clean}) != len(clean):
                raise ConnectorError("شناسه‌ی قالب‌ها تکراری است.")
            rp["templates"] = clean
            if rp.get("default_template") not in {c["id"] for c in clean}:
                rp["default_template"] = clean[0]["id"]
        it = p.get("intel")
        if isinstance(it, dict):
            if it.get("local_path") and paths.is_server():
                raise ConnectorError("در حالت سرور مسیر فایل لیست داخلی پذیرفته نیست؛ فایل را آپلود کنید.")
            if "feed_url" in it and not str(it.get("feed_url") or "").strip().lower().startswith(("https://", "http://")):
                raise ConnectorError("آدرس فید بررسی تکمیلی باید با https:// شروع شود.")
            try:
                for k, lo, hi in (("min_score", 0, 100), ("refresh_minutes", 0, 1440), ("max_age_hours", 1, 720), ("timeout", 10, 600)):
                    if k in it and not lo <= float(it[k] or 0) <= hi:
                        raise ConnectorError(f"مقدار بررسی تکمیلی «{k}» باید بین {lo} و {hi} باشد.")
            except (TypeError, ValueError):
                raise ConnectorError("تنظیمات بررسی تکمیلی باید عدد باشند.")
        sc = p.get("scan")
        if isinstance(sc, dict):
            from . import netscan
            if "allowed_networks" in sc:
                if not isinstance(sc["allowed_networks"], list):
                    raise ConnectorError("رنج‌های مجاز اسکن باید فهرست باشند.")
                _, bad = netscan.parse_networks(sc["allowed_networks"])
                if bad:
                    raise ConnectorError(f"رنج نامعتبر در اسکن شبکه: {', '.join(bad[:5])}")
            try:
                for k, lo, hi in (("max_hosts", 1, netscan.HARD_MAX_HOSTS), ("max_probes", 1, netscan.HARD_MAX_PROBES),
                                  ("workers", 1, netscan.MAX_WORKERS)):
                    if k in sc and not lo <= int(sc[k] or 0) <= hi:
                        raise ConnectorError(f"مقدار اسکن «{k}» باید بین {lo} و {hi} باشد.")
                if "timeout" in sc and not 0.2 <= float(sc["timeout"] or 0) <= 10:
                    raise ConnectorError("Timeout اسکن باید بین 0.2 و 10 ثانیه باشد.")
            except (TypeError, ValueError):
                raise ConnectorError("تنظیمات اسکن شبکه باید عدد باشند.")
        mo = p.get("monitor")
        if isinstance(mo, dict):
            mo.pop("sound_down", None)        # فقط با mon_sound_set
            mo.pop("sound_up", None)
            try:
                if "repeat" in mo and not 1 <= int(mo["repeat"] or 0) <= 20:
                    raise ValueError
            except (TypeError, ValueError):
                raise ConnectorError("تکرار صدا باید بین 1 و 20 باشد.")
            q = mo.get("quiet")
            if isinstance(q, dict):
                for k in ("from", "to"):
                    if k in q:
                        try:
                            datetime.strptime(str(q[k]), "%H:%M")
                        except ValueError:
                            raise ConnectorError("ساعت سکوت باید به شکل HH:MM باشد.")
        tm = p.get("terminal")
        if isinstance(tm, dict):
            try:
                if "idle_minutes" in tm and not 0 <= int(tm["idle_minutes"] or 0) <= 1440:
                    raise ValueError
            except (TypeError, ValueError):
                raise ConnectorError("زمان بی‌کاری ترمینال باید بین 0 و 1440 دقیقه باشد.")
        mo = p.get("monitor")
        if isinstance(mo, dict):
            for k, lo in (("keep_detail_days", 7), ("keep_hour_days", 30)):
                if k in mo:
                    try:
                        v = int(mo[k] or 0)
                        if v and not lo <= v <= 36500:
                            raise ValueError
                    except (TypeError, ValueError):
                        raise ConnectorError(f"نگهداری داده‌ی مانیتورینگ باید ۰ (بدون محدودیت) یا دست‌کم {lo} روز باشد.")
        he = p.get("health")
        if isinstance(he, dict):
            for k, lo, hi in (("disk_min_gb", 0, 100000), ("disk_min_pct", 0, 90), ("ram_max_mb", 64, 1048576), ("cpu_max_pct", 1, 100)):
                if k in he:
                    try:
                        if not lo <= float(he[k]) <= hi:
                            raise ValueError
                    except (TypeError, ValueError):
                        raise ConnectorError(f"مقدار سلامت سرور «{k}» باید بین {lo} و {hi} باشد.")
        tr = p.get("transfer")
        if isinstance(tr, dict) and "max_mb" in tr:
            try:
                if not 0 <= float(tr["max_mb"] or 0) <= 1024 * 1024:
                    raise ValueError
            except (TypeError, ValueError):
                raise ConnectorError("سقف حجم انتقال فایل باید عدد (مگابایت) باشد؛ 0 یعنی بدون محدودیت.")
        for c in CONN.values():
            port = str((p.get(c) or {}).get("port", "") or "").strip()
            if port and (not port.isdigit() or not 0 < int(port) < 65536):
                raise ConnectorError(f"پورت {c} معتبر نیست: {port}")
        t = ((p.get("automation") or {}).get("daily") or {}).get("time")
        if t is not None:
            try:
                datetime.strptime(str(t), "%H:%M")
            except ValueError:
                raise ConnectorError("ساعت اجرای روزانه باید به شکل HH:MM باشد.")

    def _after_auto_change(self, before_master, before_daily):
        m = self._settings.get("automation", "master", default=False)
        d = self._settings.get("automation", "daily", "enabled", default=False)
        if m and d and not (before_master and before_daily):
            self._store.set_meta("daily_enabled_at", str(time.time()))
        b_now = self._settings.get("automation", "backup", "enabled", default=False)
        if m and b_now and not getattr(self, "_backup_was", False):
            self._store.set_meta("backup_enabled_at", str(time.time()))
        self._backup_was = bool(m and b_now)
        if m and not before_master:   # کلید اصلی روشن شد: نوبت‌های گذشته‌ی کارها اجرا نمی‌شوند
            items = self._settings.get("jobs", default=[]) or []
            for j in items:
                j["enabled_at"] = time.time()
            self._settings.set_jobs(items)
        if m != before_master:
            self._worker.emit("info" if m else "warn", "کار خودکار " + ("روشن شد" if m else "خاموش شد"), "schedule")

    # ------------------------------------------------------------ کارهای ذخیره‌شده
    @_safe
    def jobs_list(self):
        from . import jobs
        items = self._settings.get("jobs", default=[]) or []
        for j in items:
            j["next_at"] = jobs.next_due(j)
        return {"jobs": items, "master": bool(self._settings.get("automation", "master", default=False))}

    @_safe
    def job_save(self, job):
        from . import jobs
        items = self._settings.get("jobs", default=[]) or []
        old = next((j for j in items if j.get("id") == (job or {}).get("id")), None)
        j = jobs.normalize(job or {}, old)
        self._ssh_items_ok(j["items"])
        if paths.is_server():   # فایل‌های CSV کار از آپلودهای موقت به پوشه‌ی ماندگار jobfiles منتقل می‌شوند
            import shutil
            jf = paths.data_dir() / "jobfiles"
            jf.mkdir(exist_ok=True)
            for it in server_items(j["items"]):
                inp = (it.get("opts") or {}).get("input") or {}
                src = Path(inp["path"]) if inp.get("path") else None
                in_jf = bool(src) and src.parent.resolve() == jf.resolve()
                # فایل خود همین کار می‌ماند؛ آپلود تازه یا فایلِ کار دیگری (ذخیره به‌عنوان کار تازه) کپی می‌شود،
                # تا حذف کار قبلی فایل این کار را از بین نبرد
                if src and not (in_jf and src.name.startswith(f"{j['id']}_")):
                    if not src.is_file():
                        raise ConnectorError("فایل آپلودشده‌ی این کار پیدا نشد (شاید منقضی شده)؛ دوباره آپلود کنید.")
                    base = src.name.split("_", 1)[1] if in_jf and "_" in src.name else src.name
                    dst = jf / f"{j['id']}_{base}"
                    shutil.copyfile(src, dst)   # همان بایت‌های رمزشده
                    inp["path"] = str(dst)
        if any(x.get("name") == j["name"] and x.get("id") != j["id"] for x in items):
            raise ConnectorError(f"کاری با نام «{j['name']}» از قبل هست.")
        items = [x for x in items if x.get("id") != j["id"]]
        items.append(j)
        items.sort(key=lambda x: x.get("name") or "")
        self._settings.set_jobs(items)
        return {"job": j}

    @_safe
    def job_delete(self, job_id):
        job_id = str(job_id or "")
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", job_id):
            raise ConnectorError("شناسه‌ی کار نامعتبر است.")
        items = [x for x in self._settings.get("jobs", default=[]) or [] if x.get("id") != job_id]
        self._settings.set_jobs(items)
        from . import wipe
        for sub in ("jobfiles", "scan_baselines"):   # CSVهای همین کار (حالت سرور) و مبنای اسکن
            jf = paths.data_dir() / sub
            if jf.exists():
                for f in jf.glob(f"{job_id}_*"):
                    wipe.overwrite(f)
                    f.unlink(missing_ok=True)
        return {}

    @_safe
    def job_run(self, job_id):
        j = next((x for x in self._settings.get("jobs", default=[]) or [] if x.get("id") == job_id), None)
        if not j:
            raise ConnectorError("کار پیدا نشد.")
        self._need_tools([i["tool"] for i in j["items"]])
        self._ssh_items_ok(j["items"])      # 1.26.2: مثل start_run؛ اپراتور بدون دسترسی دستگاه مشترک، کار SSH را اجرا نمی‌کند
        run = self._worker.pipeline.start({"items": j["items"], "job_name": j["name"], "baseline_job": j["id"], "user": self._who()}, "manual")
        return {"run_id": run.id}

    @_safe
    def set_master(self, on):
        bm = self._settings.get("automation", "master", default=False)
        bd = self._settings.get("automation", "daily", "enabled", default=False)
        self._settings.update({"automation": {"master": bool(on)}})
        self._after_auto_change(bm, bd)
        return {"master": bool(on)}

    @_safe
    def test_connection(self, name, data=None, accept_pin=None):
        """تست بدون ذخیره: مقادیر فرم روی مقادیر ذخیره‌شده اعمال می‌شود.
        accept_pin: {"host", "sha256"} اثر انگشتی که کاربر همین الان دیده و تأیید کرده (پین گواهی)."""
        from .connectors.base import PinUnconfirmed, fmt_fp
        if name not in ("splunk", "abuseipdb", "fortigate", "redmine") and name not in [d["conn"] for d in self._settings.fg_devices()]:
            raise ConnectorError("اتصال ناشناخته")
        data = {k: v for k, v in (data or {}).items() if not str(k).startswith("_")} if isinstance(data, dict) else {}
        cfg = self._settings.conn_config(name, data)
        if isinstance(accept_pin, dict) and accept_pin.get("host") and re.fullmatch(r"[0-9a-f]{64}", str(accept_pin.get("sha256"))):
            cfg["_pin_accept"] = {"host": str(accept_pin["host"]), "sha256": str(accept_pin["sha256"])}
        if not self._demo and not (cfg.get("address") or "").strip():
            raise ConnectorError("آدرس وارد نشده است.")
        t0 = time.time()
        try:
            res = self._worker.test_conn(name, cfg)
        except PinUnconfirmed as e:
            return {"ok": False, "error": str(e), "pin_confirm": {"host": e.hostport, "sha256": e.fp, "fmt": fmt_fp(e.fp)}}
        self._worker.conn_status[name] = {"state": "ok", "message": res.get("message", ""), "at": time.time()}
        return {"message": res.get("message", "") + f" ({time.time() - t0:.1f} ثانیه)"}

    def js_error(self, msg):
        """خطای JavaScript رابط → لاگ برنامه (بدون _safe تا خودش خطا تولید نکند)."""
        try:
            log.error("UI JS error: %s", str(msg)[:2000])
        except Exception:
            pass
        return {"ok": True}

    @_safe
    def open_contact(self, kind):
        """فقط نشانی‌های ثابت سازنده در مرورگر یا برنامه‌ی ایمیل پیش‌فرض باز می‌شوند."""
        import webbrowser
        url = next((u for k, _, u in CONTACTS if k == kind), None)
        if not url:
            raise ConnectorError("نشانی نامعتبر")
        webbrowser.open(url)
        return {}

    # ------------------------------------------------------------ چند FortiGate (1.28)
    @_safe
    def fg_device_add(self, name=""):
        try:
            conn = self._settings.fg_add_device(str(name or ""))
        except ValueError:
            raise ConnectorError("حداکثر ۸ دستگاه FortiGate می‌شود تعریف کرد.")
        nm = next(d["name"] for d in self._settings.fg_devices() if d["conn"] == conn)
        self._store.add_history("security", "FortiGate", "ok", f"دستگاه FortiGate «{nm}» اضافه شد")
        return {"conn": conn, "settings": self._settings.public()}

    @_safe
    def fg_device_delete(self, conn):
        from .settings import FG_EXTRA
        if conn not in FG_EXTRA or conn not in [d["conn"] for d in self._settings.fg_devices()]:
            raise ConnectorError("دستگاه اول را نمی‌شود حذف کرد؛ فقط تنظیماتش را عوض کنید." if conn == "fortigate" else "دستگاه پیدا نشد.")
        nm = next(d["name"] for d in self._settings.fg_devices() if d["conn"] == conn)
        self._settings.fg_delete_device(conn)
        self._worker.conn_status.pop(conn, None)
        self._store.add_history("security", "FortiGate", "ok", f"دستگاه FortiGate «{nm}» و اسرارش حذف شد")
        return {"settings": self._settings.public()}

    @_safe
    def fg_task_dryrun(self, task, device="fortigate", rows_text=""):
        """1.29: اجرای آزمایشی plan تسک (فقط ادمین): خواندن واقعی از دستگاه، هیچ ارسالی. خروجی: کارها و پیام‌ها."""
        from . import fgtask
        from .connectors import make
        try:
            t = fgtask.validate(dict(task or {}, name=(task or {}).get("name") or "آزمایشی"))
        except fgtask.TaskError as e:
            raise ConnectorError(str(e))
        devs = {d["conn"]: d["name"] for d in self._settings.fg_devices()}
        if device not in devs:
            raise ConnectorError("دستگاه پیدا نشد.")
        rows, cols = self._worker.pipeline._parse_table(str(rows_text or "").splitlines(), "ردیف‌های نمونه")
        cli = make(device, self._settings.conn_config(device), None, self._demo)
        ctx = {"device": devs[device], "vdom": cli.vdom, "run": "dryrun", "columns": cols, "test": True,
               "ignore_networks": list(cli.cfg.get("ignore_networks") or [])}
        t0 = time.time()
        try:
            acts, logs = fgtask.plan(cli, t, rows, ctx, timeout=min(t["timeout"], 120))
        except fgtask.TaskError as e:
            return {"ok": False, "error": str(e), "rows": len(rows), "columns": cols}
        return {"actions": acts[:500], "total": len(acts), "logs": logs[-200:], "rows": len(rows), "columns": cols,
                "seconds": round(time.time() - t0, 2)}

    @_safe
    def fg_task_templates(self):
        from . import fgtask
        return {"templates": fgtask.TEMPLATES}

    @_safe
    def forget_cert_pin(self, name):
        """حذف پین گواهی؛ اتصال بعدی گواهی فعلی سرور را دوباره پین می‌کند."""
        from .settings import PIN_CONNS
        if name not in PIN_CONNS:
            raise ConnectorError("اتصال ناشناخته")
        old = (self._settings.get(name, "cert_pin") or {}).get("host", "")
        self._settings.set_cert_pin(name, None)
        self._store.add_history("security", name, "ok", f"پین گواهی {old} به درخواست کاربر حذف شد")
        return {"settings": self._settings.public()}

    @_safe
    def splunk_diagnose(self, data=None, earliest=None, latest=None):
        """اجرای آزمایشی کوئری با تنظیمات فرم (بدون ذخیره)."""
        from .connectors import make
        from .connectors import splunk as sp
        cfg = self._settings.conn_config("splunk", data or {})
        d = make("splunk", cfg, None, self._demo).diagnose(earliest or None, latest or None, limit=20)
        d["fields"] = sp.resolve_fields(d["columns"], cfg)
        d["suggest"] = sp.suggest_fields(d["columns"], self._settings.get("splunk") or {})
        d["confirmed"] = bool(self._settings.get("splunk", "fields_hash")) and \
            self._settings.get("splunk", "fields_hash") == sp.query_hash(cfg.get("query"))
        return {"diag": d}

    @_safe
    def splunk_optimize(self, query, accept=None):
        """دستیار کوئری: تحلیل متن کوئری خام (محلی؛ بدون اتصال به Splunk)."""
        from . import splq
        q = str(query or "")
        if len(q) > 100_000:
            raise ConnectorError("کوئری بیش از حد طولانی است.")
        acc = [str(a) for a in accept] if isinstance(accept, list) else None
        return {"opt": splq.optimize(q, acc)}

    @_safe
    def splunk_check_fields(self, data=None, query="", earliest=None, latest=None):
        """«بررسی فیلدها» هنگام تنظیم کوئری: فهرست فیلدهای موجود در حداکثر ۵۰۰۰ رخداد جستجوی پایه (fieldsummary) و
        مقایسه با فیلدهایی که کوئری لازم دارد. فقط با دکمه اجرا می‌شود، نه در اجرای ابزار."""
        from . import splq
        from .connectors import make
        probe, need, base = splq.fields_probe_query(str(query or ""))
        if not base.strip():
            raise ConnectorError("بررسی فیلدها برای کوئری‌ای ممکن است که با جستجوی رخدادها (مثل index=…) شروع شود، "
                                 "نه با «|» (tstats، inputlookup …).")
        cfg = dict(self._settings.conn_config("splunk", data or {}))

        def run(q):
            c = dict(cfg, query=q)
            return make("splunk", c, None, self._demo).diagnose(earliest or None, latest or None, limit=5000)
        d = run(probe)
        note = ""
        if not d["rows"] and splq.index_only(base) != base:
            only = splq.index_only(base)
            d2 = run(probe.replace(base, only, 1))
            if d2["rows"]:
                note = (f"جستجوی پایه («{base}») هیچ رخدادی نداد، ولی «{only}» رخداد دارد؛ یکی از شرط‌های جستجوی پایه "
                        "روی فیلدی است که در داده نیست یا مقدارش فرق دارد. فیلدهای زیر از همان رخدادها خوانده شد.")
                d = d2
        present = [str(r.get("field") or "") for r in d["rows"]]
        return {"check": {"base": base, "need": need, "present": present, "missing": splq.compare_fields(need, present),
                          "note": note, "messages": d.get("messages") or [], "http": d.get("http"), "events": splq.PROBE_EVENTS}}

    @_safe
    def splunk_save_mapping(self, query, fields, app=None):
        """ذخیره‌ی کوئری همراه با نگاشت ستون‌هایی که کاربر در پیش‌نمایش تأیید کرده است."""
        from .connectors import splunk as sp
        fields = {k: str((fields or {}).get(k) or "").strip() for k in sp.FIELD_CANDIDATES}
        if not fields["src"] or fields["src"] == "-":
            raise ConnectorError("ستون IP مبدأ باید انتخاب شود.")
        patch = {"query": query or "", "fields": fields, "fields_hash": sp.query_hash(query), "src_field": fields["src"]}
        if app is not None:
            patch["app"] = (app or "search").strip()
        self._settings.update({"splunk": patch})
        return {"settings": self._settings.public()}

    @_safe
    def redmine_load_meta(self, data=None, admin_key=""):
        """خواندن Trackerها و فیلدها؛ کلید ادمین اختیاری فقط برای همین درخواست استفاده و ذخیره نمی‌شود."""
        from .connectors import make
        over = dict(data or {})
        if (admin_key or "").strip():
            over.update(auth_type="header", header_name="X-Redmine-API-Key", token=admin_key.strip())
        cfg = self._settings.conn_config("redmine", over)
        meta = make("redmine", cfg, None, self._demo).load_meta()
        self._settings.set_redmine_meta(meta)
        n = sum(len(v) for v in meta["fields"].values())
        self._store.add_history("redmine", "فیلدها", "ok", f"{len(meta['trackers'])} Tracker و فیلدها خوانده شد (کاربر {meta['by']})")
        return {"settings": self._settings.public(), "message": f"{len(meta['trackers'])} Tracker خوانده شد ({n} فیلد)."}

    @_safe
    def redmine_discover(self, data=None):
        from .connectors import make
        cfg = self._settings.conn_config("redmine", data or {})
        return {"discover": make("redmine", cfg, None, self._demo).discover()}

    @_safe
    def preview_template(self, template):
        sample = {k: v for k, v in {
            "date": datetime.now().strftime(self._settings.get("redmine", "date_format") or "%d/%m/%Y"),
            "src_count": 24, "dest_count": 5, "checked_count": 22, "abuse_count": 15, "clean_count": 6,
            "error_count": 1, "banned_count": 9, "already_banned_count": 3, "address_match_count": 2,
            "ignored_count": 1, "ban_failed_count": 0, "abuse_list": "| 45.155.205.12 | 89.248.165.3 |",
            "banned_list": "| 45.155.205.12 |", "clean_list": "| 162.142.125.9 | 5.160.1.20 |",
            "clean_foreign_count": 4, "clean_review_count": 2, "clean_review_list": "| 5.160.1.20 |"}.items()}
        return {"text": rm.render_template(template or "", sample)}

    # ------------------------------------------------------------ runs
    def _need_tools(self, tools):
        deny = perms.check_tools(self._current_user(), self._settings, tools)
        if deny:
            raise ConnectorError(deny)

    def _who(self):
        u = self._current_user()
        return u["username"] if u else ""

    @_safe
    def start_run(self, options):
        from .pipeline import legacy_items
        o = dict(options or {})
        self._need_tools([i.get("tool") for i in (o.get("items") or legacy_items(o))])
        self._ssh_items_ok(o.get("items") or [])
        for k in ("abuse_input", "fortigate_input", "redmine_input"):
            if isinstance(o.get(k), dict) and o[k].get("path"):
                o[k]["path"] = server_path(o[k]["path"])
        server_items(o.get("items"))
        o["user"] = self._who()
        run = self._worker.pipeline.start(o, "manual")
        return {"run_id": run.id}

    @_safe
    def start_full_sync(self):
        """کل IPهای دیتابیس که طبق قانون فعلی باید بلاک باشند، با FortiGate مقایسه و جامانده‌ها بلاک می‌شوند."""
        run = self._worker.pipeline.start({"steps": {"fortigate": True}, "fortigate_input": {"source": "db"}}, "sync")
        return {"run_id": run.id}

    @_safe
    def cancel_run(self):
        run = self._worker.pipeline.current
        if run is not None:                      # فقط کسی که همه‌ی ابزارهای این اجرا را دارد
            self._need_tools(sorted({i["tool"] for i in run.items}))
        return {"cancelled": self._worker.pipeline.cancel()}

    @_safe
    def decide(self, run_id, approve, payload=None):
        run = self._worker.pipeline.current
        step = (run.approval or {}).get("step", "") if run else ""
        if step:
            self._need_tools([step])
        if isinstance(payload, dict) and payload.get("switch_template") is not None:
            if step != "redmine" or not re.fullmatch(r"[A-Za-z0-9_-]{1,40}", str(payload["switch_template"])):
                raise ConnectorError("قالب نامعتبر است.")
        self._worker.pipeline.decide(run_id, approve, payload if isinstance(payload, dict) else {})
        from .pipeline import STEP_TITLES
        sw = (payload or {}).get("switch_template") if isinstance(payload, dict) else None
        if sw and not approve:
            self._store.add_history("approval", STEP_TITLES.get(step, step) or "-", "ok", f"قالب تیکت عوض شد ({sw})", run_id)
            return {}
        self._store.add_history("approval", STEP_TITLES.get(step, step) or "-", "ok" if approve else "warn",
                                "تأیید شد" if approve else "رد شد", run_id)
        return {}

    # ------------------------------------------------------------ data
    @_safe
    def list_ips(self, compact=False):
        """compact (رابط): {"cols": [...], "data": [[...], ...]} — نام ستون‌ها یک بار، نه برای هر ردیف (با ۵۰ هزار IP
        حدود یک‌سوم حجم؛ در دسکتاپ کل پاسخ به‌صورت متن از پل pywebview به WebView2 می‌رود)."""
        from .pipeline import block_reason_v
        cols, raw = self._store.list_ips_raw()
        acfg = self._settings.get("abuseipdb") or {}
        seen = self._store.seen_days()
        ix = {c: i for i, c in enumerate(cols)}
        i_ip, i_st, i_sc, i_wl, i_fw = ix["ip"], ix["abuse_status"], ix["score"], ix.get("is_whitelisted"), ix["fw_status"]
        data = []
        for t in raw:
            sb = bool(block_reason_v(t[i_st], t[i_sc], t[i_wl] if i_wl is not None else None, acfg))
            data.append(t + (sb, sb and t[i_fw] not in FW_DONE, (seen.get(t[i_ip]) or (0,))[0]))
        cols = cols + ["should_block", "fw_pending", "seen_days"]
        rd = int(acfg.get("repeat_days") or 0)
        if compact:
            return {"cols": cols, "data": data, "repeat_days": rd}
        return {"rows": [dict(zip(cols, t)) for t in data], "repeat_days": rd}

    # ------------------------------------------------------------ بررسی تکمیلی (فید و لیست داخلی؛ فقط ادمین)
    @_safe
    def intel_status(self):
        from . import intel
        return {"feed": intel.feed_meta(), "local": intel.local_meta(), "server": paths.is_server()}

    @_safe
    def intel_feed_update(self):
        from . import intel
        if self._demo:
            raise ConnectorError("در حالت Demo فید دانلود نمی‌شود.")
        try:
            meta, note = intel.update_feed(self._settings.get("intel") or {}, force=True)
        except intel.IntelError as e:
            self._store.add_history("intel", "فید آنلاین", "error", str(e))
            raise ConnectorError(str(e))
        self._store.add_history("intel", "فید آنلاین", "ok", note)
        return {"feed": meta, "message": note}

    @_safe
    def intel_local_upload(self, path):
        from . import intel
        try:
            p = paths.user_file(path)
        except PermissionError as e:
            raise ConnectorError(str(e))
        if not p:
            raise ConnectorError("فایلی انتخاب نشده است.")
        try:
            meta = intel.save_local(p, Path(p).name)
        except intel.IntelError as e:
            raise ConnectorError(str(e))
        self._settings.update({"intel": {"local_enabled": True}})
        self._store.add_history("intel", "لیست داخلی", "ok", f"لیست داخلی «{meta['name']}» بارگذاری شد: {meta['ips']}\u200f IP و "
                                f"{meta['nets']} رنج" + (f"؛ {meta['invalid']} خط نامعتبر" if meta["invalid"] else ""))
        return {"local": meta, "settings": self._settings.public()}

    @_safe
    def intel_local_clear(self):
        from . import intel
        intel.clear_local()
        self._settings.update({"intel": {"local_enabled": bool(self._settings.get("intel", "local_path", default=""))}})
        self._store.add_history("intel", "لیست داخلی", "ok", "لیست داخلی آپلودشده حذف شد")
        return {"settings": self._settings.public()}

    @_safe
    def repeat_ips(self, min_days=0, only_clean=True):
        """آمار ← IPهای تکراری: تعداد روزهای مختلفی که هر IP به AbuseIPDB رسیده، با وضعیت فعلی‌اش."""
        n = int(self._settings.get("abuseipdb", "repeat_days", default=5) or 0)
        try:
            min_days = max(1, int(min_days or 0) or n or 2)
        except (TypeError, ValueError):
            min_days = n or 2
        seen = self._store.seen_days()
        cand = [ip for ip, v in seen.items() if v[0] >= min_days]
        alerted = self._store.repeat_alerts(cand)
        rows = self._store.get_ips(cand)
        out = []
        for ip in cand:
            cur = rows.get(ip) or {}
            st = cur.get("abuse_status") or ""
            blocked = cur.get("fw_status") in ("banned", "already")
            if only_clean and (st != "CLEAN" or blocked):
                continue
            d, first, last = seen[ip]
            out.append({"ip": ip, "days": d, "first": first, "last": last, "abuse_status": st or ("REMOVED" if not cur else ""),
                        "score": cur.get("score"), "country_code": cur.get("country_code") or "", "isp": cur.get("isp") or "",
                        "fw_status": cur.get("fw_status") or "", "review": cur.get("review") or "", "alerted": alerted.get(ip) or 0,
                        "intel_status": cur.get("intel_status") or "", "intel_source": cur.get("intel_source") or "",
                        "checked_at": cur.get("checked_at") or ""})
        out.sort(key=lambda r: (-r["days"], -(r["last"] or 0)))
        return {"rows": out[:5000], "total": len(out), "min_days": min_days, "threshold": n}

    @_safe
    def ip_detail(self, ip):
        row = self._store.get_ip(ip)
        if not row:
            raise ConnectorError("این IP در داده‌ها نیست.")
        hist = [h for h in self._store.list_history(2000) if h["target"] == ip][:30]
        row["seen_days"] = (self._store.seen_days([ip]).get(ip) or (0,))[0]
        return {"ip": row, "history": hist}

    @_safe
    def ips_action(self, action, ips):
        ips = [str(i).strip() for i in (ips or []) if str(i).strip()]
        if not ips:
            raise ConnectorError("هیچ IPای انتخاب نشده است.")
        need = {"recheck": "abuse", "ban": "fortigate"}.get(action)
        if need:
            self._need_tools([need])
        elif action == "ignore" and self._current_user() and self._current_user().get("role") != "admin":
            raise ConnectorError("افزودن به رنج‌های مستثنا فقط برای ادمین است.")
        if action == "recheck":
            ex = self._excluded_fn()
            out = [ip for ip in ips if ex(ip)]
            ips = [ip for ip in ips if ip not in out]
            removed = self._cleanup_excluded(out) if out else 0
            note = f"؛ {len(out)}\u200f IP خصوصی یا داخل رنج‌های مستثنا بود و {removed} مورد از فهرست حذف شد" if out else ""
            if not ips:
                return {"message": "چیزی برای بررسی نماند" + note}
            run = self._worker.pipeline.start({"steps": {"abuse": True}, "user": self._who(),
                                               "abuse_input": {"source": "list", "text": "\n".join(ips), "force": True}}, "manual")
            return {"run_id": run.id, "message": f"چک مجدد {len(ips)}\u200f IP شروع شد" + note}
        if action == "ban":
            run = self._worker.pipeline.start({"steps": {"fortigate": True}, "user": self._who(),
                                               "fortigate_input": {"source": "list", "text": "\n".join(ips)}}, "manual")
            return {"run_id": run.id, "message": "پیش‌نمایش بلاک آماده می‌شود"}
        if action in ("reviewed", "pending"):
            for ip in ips:
                self._store.upsert_ip(ip, review=action)
            return {"message": f"{len(ips)}\u200f IP به‌روزرسانی شد"}
        if action == "ignore":
            cur = self._settings.get("fortigate", "ignore_networks", default=[]) or []
            add = [f"{ip}/32" for ip in ips if f"{ip}/32" not in cur and ip not in cur]
            self._settings.update({"fortigate": {"ignore_networks": cur + add}})
            removed = self._cleanup_excluded()
            return {"message": f"{len(add)}\u200f IP به رنج‌های مستثنا اضافه شد و {removed} مورد از فهرست حذف شد"}
        raise ConnectorError("عملیات ناشناخته")

    # ------------------------------------------------------------ import / manual add
    def _threshold(self):
        return int(self._settings.get("abuseipdb", "threshold", default=0) or 0)

    @_safe
    def import_preview(self, path):
        path = server_path(path)
        return {"preview": importer.preview(self._store, path, self._threshold())}

    @_safe
    def import_commit(self, path, overwrite=False):
        path = server_path(path)
        res = importer.commit(self._store, path, self._threshold(), bool(overwrite), self._excluded_fn())
        self._worker.emit("ok", f"ورود داده: {res['written']}\u200f IP از {Path(path.strip().strip(chr(34))).name}", "import")
        return {"result": res}

    @_safe
    def add_manual(self, text, status, country_code="", note=""):
        res = importer.add_manual(self._store, text, status, country_code, note, self._excluded_fn())
        self._worker.emit("ok", f"افزودن دستی: {res['written']}\u200f IP", "import")
        return {"result": res}

    @_safe
    def export_ips(self, ips=None, fmt="script"):
        rows = self._store.list_ips(limit=1_000_000)
        if ips is not None:
            want = set(ips)
            rows = [r for r in rows if r["ip"] in want]
        if not rows:
            raise ConnectorError("داده‌ای برای خروجی نیست.")
        name = f"{'ipabuse_report' if fmt == 'script' else 'autokrp_ips_full'}_{datetime.now():%Y%m%d_%H%M}.csv"
        path = None
        if self._window:
            import webview
            res = self._window.create_file_dialog(webview.SAVE_DIALOG, save_filename=name,
                                                  file_types=("CSV (*.csv)",))
            if not res:
                return {"cancelled": True}
            path = res[0] if isinstance(res, (list, tuple)) else res
            if not str(path).lower().endswith(".csv"):
                path = str(path) + ".csv"
        else:
            d = paths.data_dir() / "exports"
            d.mkdir(exist_ok=True)
            path = str(d / name)
        n = importer.export_rows(rows, path, fmt)
        self._store.add_history("export", Path(path).name, "ok", f"{n}\u200f IP ({'فرمت اسکریپت' if fmt == 'script' else 'کامل'})", "", path)
        return {"path": path, "count": n}

    # ------------------------------------------------------------ stats
    @_safe
    def get_stats(self, range_key="30d", calendar="jalali"):
        if range_key not in stats.RANGES:
            range_key = "30d"
        calendar = "gregorian" if calendar == "gregorian" else "jalali"
        key = (range_key, calendar)
        # نتیجه تا رویداد آماری تازه (یا روز تازه) معتبر است؛ STATS_TTL فقط برای اجرای فرایند و عکس روزانه
        mark = (self._store._stat_ver, datetime.now().strftime("%Y-%m-%d"))
        valid = lambda h: h and h[2] == mark and time.time() - h[0] < STATS_TTL * 30
        hit = self._stats_cache.get(key)
        if valid(hit):
            return {"stats": hit[1]}
        with self._stats_lock:                 # دو درخواست هم‌زمان (چند نمودار/تب) یک بار حساب شوند
            hit = self._stats_cache.get(key)
            if valid(hit):
                return {"stats": hit[1]}
            if time.time() - self._snap_at > 300:
                self._snap_at = time.time()
                self._worker.snapshot()
            res = stats.compute(self._store, range_key, calendar)
            self._stats_cache[key] = (time.time(), res, mark)
        return {"stats": res}

    def ui_perf(self, name, ms):
        try:
            log.info("UI slow call: %s %s ms", str(name)[:60], int(ms))
        except Exception:
            pass
        return {"ok": True}

    @_safe
    def save_export(self, name, content, is_base64=False):
        """ذخیره‌ی خروجی ساخته‌شده در رابط (PNG نمودار، CSV آمار) با پنجره‌ی ذخیره."""
        name = Path(str(name)).name or "export.txt"
        ext = Path(name).suffix.lower()
        if ext not in (".png", ".csv", ".svg", ".txt", ".json"):
            raise ConnectorError("نوع فایل مجاز نیست.")
        data = base64.b64decode(content) if is_base64 else str(content).encode("utf-8-sig" if ext == ".csv" else "utf-8")
        if len(data) > 20 * 1024 * 1024:
            raise ConnectorError("فایل بزرگ‌تر از حد مجاز است.")
        if ext == ".csv":
            from .csvsafe import sanitize_bytes
            data = sanitize_bytes(data)
        return self._save_bytes(name, ext, data)

    def _save_bytes(self, name, ext, data):
        """پنجره‌ی ذخیره (دسکتاپ) یا exports/ (سرور ← دانلود یک‌بارمصرف با _webfile). فقط برای داده‌ای که خود برنامه ساخته."""
        if self._window:
            import webview
            res = self._window.create_file_dialog(webview.SAVE_DIALOG, save_filename=name,
                                                  file_types=(f"{ext[1:].upper()} (*{ext})",))
            if not res:
                return {"cancelled": True}
            path = res[0] if isinstance(res, (list, tuple)) else res
            if not str(path).lower().endswith(ext):
                path = str(path) + ext
        else:
            d = paths.data_dir() / "exports"
            d.mkdir(exist_ok=True)
            path = str(d / name)
        Path(path).write_bytes(data)
        return {"path": path}

    # ------------------------------------------------------------ SSH
    @property
    def _ssh(self):
        return self._worker.ssh

    # ------------------------------------------------------------ دستگاه‌های مشترک و شخصی
    def _uname(self):
        u = self._current_user()
        return (u or {}).get("username", "").lower()

    def _can_shared(self):
        """دستگاه‌های مشترک (تعریف ادمین): ادمین همیشه؛ اپراتور اگر ادمین اجازه داده باشد."""
        u = self._current_user()
        return u is None or u.get("role") == "admin" or u.get("shared_devices", True) is not False

    def _dev_visible(self, d):
        owner = (d.get("owner") or "").lower()
        return self._can_shared() if not owner else owner == self._uname()

    def _check_devs(self, ids, shared_only=False):
        out = []
        for i in ids or []:
            d = self._store.ssh_device(int(i))
            if not d or not self._dev_visible(d):
                raise ConnectorError("دستگاه پیدا نشد یا دسترسی به آن ندارید.")
            if shared_only and d.get("owner"):
                raise ConnectorError(f"«{d.get('name') or d['host']}» دستگاه شخصی است؛ در پشتیبان‌گیری، کارها و به‌روزرسانی فقط دستگاه‌های مشترک مجازند.")
            out.append(d)
        return out

    # ------------------------------------------------------------ ترمینال زنده
    def _target(self, target):
        """دستگاه ذخیره‌شده (مشترک یا شخصی، با دسترسی) یا اتصال موقت. خروجی: (dev, creds, adhoc)"""
        t = target if isinstance(target, dict) else {}
        if t.get("device_id"):
            d = self._check_devs([t["device_id"]])[0]
            c = self._ssh.creds(d["id"])
            if not c.get("username") or not c.get("password"):
                raise ConnectorError("یوزر یا پسورد این دستگاه ذخیره نشده است.")
            return d, c, False
        a = t.get("adhoc") if isinstance(t.get("adhoc"), dict) else None
        if not a:
            raise ConnectorError("دستگاه یا اتصال موقت انتخاب نشده است.")
        d = self._clean_dev({"host": a.get("host"), "port": a.get("port") or 22, "device_type": a.get("device_type") or "linux",
                             "name": a.get("host"), "legacy": a.get("legacy")})
        return d, {"username": str(a.get("username") or "").strip(), "password": str(a.get("password") or ""), "secret": ""}, True

    def _term_closed(self, s):
        mins = int((time.time() - s.created) // 60)
        self._store.add_history("terminal", s.title, "ok", f"قطع اتصال ({s.host}:{s.port}) — {mins} دقیقه — {s.reason}"
                                + ("؛ متن نشست ضبط شد" if s.rec_path else ""), "", str(s.rec_path) if s.rec_path else "",
                                user=s.owner)

    @_safe
    def term_open(self, target, cols=120, rows=32, accept_fp=None, attempt=None):
        if not self._vault.unlocked():
            raise VaultError("برنامه قفل است.")
        from .term import TermError
        d, c, adhoc = self._target(target)
        att = self._attempt_begin(attempt)
        if isinstance(att, dict):
            return att
        try:
            res = self._term.open(self._uname(), d, c, cols, rows, accept_fp, adhoc, attempt=att)
        except TermError as e:
            if att.cancelled:
                return self._attempt_cancelled("terminal", d)
            raise ConnectorError(str(e))
        finally:
            self._attempts.end(self._uname(), attempt)
        if "session" in res:
            s = res["session"]
            self._store.add_history("terminal", s["title"], "ok", f"اتصال ترمینال به {s['host']}:{s['port']}"
                                    + (f" (موقت، یوزر {c['username']})" if adhoc else "")
                                    + ("؛ ضبط روشن" if s["recording"] else ""))
        return res

    # ------------------------------------------------------------ لغو اتصال در حال برقراری
    def _attempt_begin(self, aid):
        from .abort import Aborted
        try:
            return self._attempts.begin(self._uname(), aid)
        except Aborted as e:
            return {"ok": False, "error": str(e), "cancelled": True}

    def _attempt_cancelled(self, kind, dev):
        from .abort import CANCEL_MSG
        self._store.add_history(kind, dev.get("name") or dev.get("host") or "", "warn",
                                f"اتصال به {dev.get('host')} پیش از برقراری توسط کاربر لغو شد")
        return {"ok": False, "error": CANCEL_MSG, "cancelled": True}

    @_safe
    def conn_cancel(self, attempt):
        """لغو فوری اتصال ترمینال/انتقال فایلی که هنوز برقرار نشده (شناسه را خود رابط ساخته است)."""
        return {"cancelled": self._attempts.cancel(self._uname(), attempt)}

    def _term_call(self, fn, *a):
        from .term import TermError
        try:
            return fn(*a)
        except TermError as e:
            raise ConnectorError(str(e))

    @_safe
    def term_read(self, sid, since=0):
        return self._term_call(self._term.read, sid, self._uname(), since, 1.0)

    @_safe
    def term_write(self, sid, data):
        return self._term_call(self._term.write, sid, self._uname(), data)

    @_safe
    def term_resize(self, sid, cols, rows):
        return self._term_call(self._term.resize, sid, self._uname(), cols, rows)

    @_safe
    def term_stats(self, sid):
        return self._term_call(self._term.stats, sid, self._uname())

    @_safe
    def term_close(self, sid):
        return self._term_call(self._term.close, sid, self._uname())

    @_safe
    def term_list(self):
        return {"sessions": self._term.list(self._uname()), "settings": self._term.cfg()}

    # ------------------------------------------------------------ انتقال فایل
    def _xfer_history(self, owner, target, status, detail, file=""):
        self._store.add_history("transfer", target, status, detail, "", file, user=owner)

    def _xc(self, fn, *a):
        from .xfer import XferError
        try:
            return fn(*a)
        except XferError as e:
            raise ConnectorError(str(e))
        except OSError as e:
            raise ConnectorError(self._xfer._err(e))

    @_safe
    def xfer_open(self, target, proto="sftp", accept_fp=None, opts=None, attempt=None):
        if not self._vault.unlocked():
            raise VaultError("برنامه قفل است.")
        d, c, adhoc = self._target(target)
        o = opts if isinstance(opts, dict) else {}
        o = {"port": int(o["port"]) if str(o.get("port") or "").isdigit() and 0 < int(o["port"]) < 65536 else None,
             "active": bool(o.get("active"))}
        att = self._attempt_begin(attempt)
        if isinstance(att, dict):
            return att
        try:
            res = self._xc(self._xfer.connect, self._uname(), d, c, proto, adhoc, accept_fp, o, att)
        except ConnectorError:
            if att.cancelled:
                return self._attempt_cancelled("transfer", d)
            raise
        finally:
            self._attempts.end(self._uname(), attempt)
        if "conn" in res:
            x = res["conn"]
            self._store.add_history("transfer", x["title"], "ok", f"اتصال {x['proto'].upper()} به {x['host']}:{x['port']}"
                                    + (f" (موقت، یوزر {c['username']})" if adhoc else ""))
        return res

    @_safe
    def xfer_conns(self):
        from .xfer import human
        lim = self._xfer.limit()
        return {"conns": self._xfer.list(self._uname()), "limit": lim, "limit_h": human(lim) if lim else "",
                "desktop": not paths.is_server()}

    @_safe
    def xfer_ls(self, cid, path=""):
        r = self._xc(lambda: self._xfer.get(cid, self._uname()).ls(path))
        return {"cwd": r["path"], "items": r["items"]}

    @_safe
    def xfer_mkdir(self, cid, path):
        self._xc(lambda: self._xfer.get(cid, self._uname()).mkdir(path))
        return {}

    @_safe
    def xfer_delete(self, cid, items):
        c = self._xc(self._xfer.get, cid, self._uname())
        done = []
        for it in items or []:
            self._xc(c.delete, it.get("path"), bool(it.get("dir")))
            done.append(str(it.get("path")))
        if done:
            self._store.add_history("transfer", c.title, "ok", f"حذف روی {c.proto.upper()}: {', '.join(done[:10])}"
                                    + (f" و {len(done) - 10} مورد دیگر" if len(done) > 10 else ""))
        return {"deleted": len(done)}

    @_safe
    def xfer_rename(self, cid, src, dst):
        c = self._xc(self._xfer.get, cid, self._uname())
        self._xc(c.rename, src, dst)
        self._store.add_history("transfer", c.title, "ok", f"تغییر نام: {src} ← {dst}")
        return {}

    @_safe
    def xfer_close(self, cid):
        self._xc(self._xfer.close, cid, self._uname())
        return {}

    @_safe
    def xfer_put_begin(self, cid, remote_dir, name, size, overwrite=False):
        return self._xc(self._xfer.put_begin, self._uname(), cid, remote_dir, name, size, overwrite)

    @_safe
    def xfer_put(self, jid, off, b64):
        return self._xc(self._xfer.put_chunk, self._uname(), jid, off, b64)

    @_safe
    def xfer_get(self, cid, rpath):
        """حالت وب: آدرس دانلود جریانی یک‌بارمصرف."""
        if not paths.is_server():
            raise ConnectorError("در حالت دسکتاپ فایل را به پنل «این کامپیوتر» بکشید.")
        r = self._xc(self._xfer.get_begin, self._uname(), cid, rpath)
        return {"url": "/xfer/" + r["token"], "job": r["job"]}

    @_safe
    def xfer_local(self, cid, direction, items, target_dir, overwrite=False):
        if paths.is_server():
            raise ConnectorError("این بخش در حالت سرور در دسترس نیست.")
        return self._xc(self._xfer.local_transfer, self._uname(), cid, "up" if direction == "up" else "down",
                        items, target_dir, bool(overwrite))

    @_safe
    def local_ls(self, path=""):
        """پنل «این کامپیوتر» (فقط حالت دسکتاپ)."""
        if paths.is_server():
            raise ConnectorError("این بخش در حالت سرور در دسترس نیست.")
        p = str(path or "").strip()
        if not p:
            if os.name == "nt":
                import string
                drives = [f"{d}:\\" for d in string.ascii_uppercase if os.path.exists(f"{d}:\\")]
                return {"cwd": "", "items": [{"name": d, "dir": True, "size": 0, "mtime": 0} for d in drives],
                        "home": str(Path.home())}
            p = "/"
        base = Path(p).expanduser().resolve()
        if not base.is_dir():
            raise ConnectorError("پوشه پیدا نشد.")
        items = []
        try:
            with os.scandir(base) as it:
                for e in it:
                    try:
                        isdir = e.is_dir()
                        stt = e.stat()
                        items.append({"name": e.name, "dir": isdir, "size": 0 if isdir else stt.st_size, "mtime": stt.st_mtime})
                    except OSError:
                        continue
        except PermissionError:
            raise ConnectorError("دسترسی به این پوشه نیست.")
        parent = str(base.parent) if base.parent != base else ("" if os.name == "nt" else "/")
        return {"cwd": str(base), "items": items, "parent": parent, "home": str(Path.home()), "sep": os.sep}

    @_safe
    def xfer_jobs(self):
        return {"jobs": self._xfer.job_list(self._uname())}

    @_safe
    def xfer_cancel(self, jid):
        self._xc(self._xfer.cancel, self._uname(), jid)
        return {}

    @_safe
    def xfer_clear(self):
        self._xfer.clear_jobs(self._uname())
        return {}

    @_safe
    def xfer_clear_one(self, jid):
        self._xfer.clear_jobs(self._uname(), str(jid or ""))
        return {}

    @_safe
    def tftp_start(self, device_ids=None, hosts=None, port=69, write=True):
        devs = self._check_devs(device_ids or [])
        allowed = [d["host"] for d in devs] + [str(h).strip() for h in hosts or [] if str(h).strip()]
        try:
            port = int(port or 69)
            if not 0 < port < 65536:
                raise ValueError
        except ValueError:
            raise ConnectorError("پورت نامعتبر است.")
        st = self._xc(self._xfer.tftp_start, self._uname(), allowed, port, bool(write))
        return self._tftp_cmds(st, devs)

    def _tftp_cmds(self, st, devs=None):
        from .xfer import ready_commands
        if st.get("running") and st.get("local_ip"):
            types = {d.get("device_type") for d in devs or []} or {"cisco_ios", "fortinet", "linux"}
            st["commands"] = {t: ready_commands(t, st["local_ip"]) for t in sorted(types)}
            st["commands"] = {k: v for k, v in st["commands"].items() if v}
        return st

    @_safe
    def tftp_status(self):
        return self._tftp_cmds(self._xfer.tftp_status(self._uname()))

    @_safe
    def tftp_stop(self):
        self._xfer.tftp_stop(self._uname())
        return {}

    @_safe
    def tftp_add_local(self, files=None):
        if paths.is_server():
            raise ConnectorError("این بخش در حالت سرور در دسترس نیست.")
        return self._tftp_cmds(self._xc(self._xfer.tftp_add_local, self._uname(), files))

    @_safe
    def tftp_remove(self, name):
        return self._tftp_cmds(self._xfer.tftp_remove(self._uname(), str(name)))

    def _received_ok(self, rid):
        """فایل دریافتی TFTP فقط برای کسی که دریافتش کرده (یا ادمین)."""
        p = self._xfer.received_path(rid)
        if not p:
            raise ConnectorError("فایل پیدا نشد.")
        u = self._current_user()
        if u and u.get("role") != "admin":
            row = self._store.history_by_file(str(p))
            if not row or (row.get("user") or "").lower() != self._uname():
                raise ConnectorError("فایل پیدا نشد.")
        return p

    @_safe
    def tftp_received_get(self, rid):
        p = self._received_ok(rid)
        name = p.name.split("_", 3)[-1][:-5] if p.name.endswith(".akrp") else p.name
        if paths.is_server():
            return {"url": "/xfer/" + self._xfer.get_file_begin(self._uname(), p, name)}
        if not self._window:
            raise ConnectorError("پنجره در دسترس نیست.")
        import webview
        from .xfer import enc_iter
        res = self._window.create_file_dialog(webview.SAVE_DIALOG, save_filename=name)
        if not res:
            return {"cancelled": True}
        dest = res[0] if isinstance(res, (list, tuple)) else res
        with open(dest, "wb") as f:
            for c in enc_iter(p):
                f.write(c)
        return {"saved": str(dest)}

    # ------------------------------------------------------------ مانیتورینگ
    @property
    def _mon(self):
        return self._worker.monitor

    def _mon_admin(self):
        u = self._current_user()
        return u is None or u.get("role") == "admin"

    def _mon_can_add(self):
        u = self._current_user()
        return u is None or u.get("role") == "admin" or (u.get("role") == "operator" and "monitor" in perms.allowed_tools(u, self._settings))

    def _mon_visible(self, t):
        return self._mon_admin() or not t.get("owner") or t.get("owner") == self._uname()

    def _mon_get(self, tid, edit=False):
        t = self._store.mon_target(int(tid))
        if not t or not self._mon_visible(t):
            raise ConnectorError("هدف پیدا نشد.")
        if edit and not self._mon_admin() and t.get("owner") != self._uname():
            raise ConnectorError("هدف‌های مشترک را فقط ادمین تغییر می‌دهد.")
        return t

    def _mon_cfg(self):
        c = self._settings.get("monitor") or {}
        return {"repeat": int(c.get("repeat", 3) or 1), "sound_on_up": c.get("sound_on_up", True) is not False,
                "quiet": c.get("quiet") or {}, "sound_down": bool(c.get("sound_down")), "sound_up": bool(c.get("sound_up")),
                "background": c.get("background", True) is not False, "show_window": c.get("show_window", True) is not False}

    @_safe
    def mon_list(self):
        from .monitor import ICONS, MAX_TARGETS
        ts = [self._mon.public(t) for t in self._store.mon_targets() if self._mon_visible(t)]
        for t in ts:
            t["mine"] = bool(t.get("owner")) and t["owner"] == self._uname()
            t["can_edit"] = self._mon_admin() or (t["mine"] and self._mon_can_add())
        return {"targets": ts, "icons": list(ICONS), "max": MAX_TARGETS, "cfg": self._mon_cfg(), "seq": self._mon.seq,
                "can_add": self._mon_can_add(), "admin": self._mon_admin(), "desktop": not paths.is_server()}

    @_safe
    def mon_state(self, since=0):
        """poll سبک رابط (هر چند ثانیه): هشدارهای تازه و تعداد قطع‌ها."""
        if "monitor" not in perms.enabled_features(self._settings):
            return {"seq": self._mon.seq, "alerts": [], "down": [], "alarm": [], "total": 0, "cfg": self._mon_cfg(), "disabled": True}
        vis = {t["id"]: t for t in self._store.mon_targets() if self._mon_visible(t)}
        down = [vis[i].get("name") for i, st in self._mon.state.items() if i in vis and st.get("status") == "down"
                and vis[i].get("enabled") and not st.get("maint")]
        alarm = [vis[i].get("name") for i, lv in self._mon.snmp.live.items() if i in vis and vis[i].get("enabled")
                 and lv.get("level") == "crit" and vis[i].get("name") not in down]
        alerts = [a for a in list(self._mon.alerts) if a["seq"] > int(since or 0) and a["target"] in vis]
        return {"seq": self._mon.seq, "alerts": alerts, "down": down, "alarm": alarm, "total": len(vis), "cfg": self._mon_cfg()}

    @_safe
    def mon_save(self, target):
        from .monitor import MAX_TARGETS, MonitorError, clean_target
        t = target if isinstance(target, dict) else {}
        if t.get("id"):
            old = self._mon_get(t["id"], edit=True)
            owner = old.get("owner") or ""
        else:
            if len(self._store.mon_targets()) >= MAX_TARGETS:
                raise ConnectorError(f"حداکثر {MAX_TARGETS} هدف مانیتورینگ مجاز است.")
            owner = "" if self._mon_admin() else self._uname()
        try:
            c = clean_target(t, owner)
        except MonitorError as e:
            raise ConnectorError(str(e))
        if c["kind"] == "snmp":
            c["cred_id"] = self._snmp_cred(t.get("cred_id"), owner)
        c["parent_id"] = self._mon_parent_ok(c.get("parent_id"), owner, t.get("id"))
        tid = self._store.mon_save(c)
        self._mon.state.pop(tid, None)
        self._mon.reload()
        if c["kind"] != "snmp":
            self._mon.snmp.clear(tid)
        else:
            self._mon.snmp.prev.pop(tid, None)      # آدرس یا شمارنده‌ها ممکن است عوض شده باشند
        self._store.add_history("monitor", c["name"], "ok", ("ویرایش هدف" if t.get("id") else "هدف تازه") +
                                f" — {c['kind']} {c['url'] or c['host']}{':' + str(c['port']) if c['port'] else ''} — هر {c['interval']} ثانیه")
        return {"id": tid}

    def _mon_parent_ok(self, pid, owner, tid=None):
        """پدر باید هدفی باشد که صاحب فرزند هم می‌بیند (هدف مشترک فقط پدر مشترک)، و حلقه نسازد."""
        if not pid:
            return None
        p = self._store.mon_target(int(pid))
        if not p or (p.get("owner") and p["owner"] != owner) or not self._mon_visible(p):
            raise ConnectorError("هدف «وابسته به» پیدا نشد یا برای این هدف مجاز نیست (هدف مشترک فقط به هدف مشترک وابسته می‌شود).")
        if tid:
            ts = {t["id"]: t for t in self._store.mon_targets()}
            cur, seen = p, set()
            while cur and cur["id"] not in seen:
                if cur["id"] == int(tid):
                    raise ConnectorError("این وابستگی حلقه می‌سازد (هدف نمی‌تواند به فرزند خودش وابسته باشد).")
                seen.add(cur["id"])
                cur = ts.get(cur.get("parent_id"))
        return p["id"]

    @_safe
    def mon_parent_group(self, grp, parent_id):
        """«وابسته به» برای همه‌ی هدف‌های یک گروه که کاربر می‌تواند ویرایش کند (به‌جز خود پدر و پدرهایش)."""
        grp = str(grp or "").strip()
        if not grp:
            raise ConnectorError("گروه خالی است.")
        mine = [t for t in self._store.mon_targets() if (t.get("grp") or "") == grp and t["id"] != int(parent_id or 0)
                and (self._mon_admin() or t.get("owner") == self._uname())]
        done = []
        for t in mine:
            try:
                done.append((t["id"], self._mon_parent_ok(parent_id, t.get("owner") or "", t["id"])))
            except ConnectorError:
                continue
        for tid, pid in done:
            self._store.mon_set_parent([tid], pid)
        self._mon.reload()
        p = self._store.mon_target(int(parent_id)) if parent_id else None
        self._store.add_history("monitor", grp, "ok", f"وابستگی گروه: {len(done)} هدف ← {p['name'] if p else 'بدون پدر'}")
        return {"count": len(done), "skipped": len(mine) - len(done)}

    @_safe
    def mon_noc(self):
        """نمای NOC (هر چند ثانیه): وضعیت فشرده‌ی همه‌ی هدف‌های قابل دیدن + رخدادهای اخیر.
        عمداً در POLL نیست: صفحه‌ی NOC باز = فعالیت (نشست مانیتور دیواری منقضی نشود)."""
        if "monitor" not in perms.enabled_features(self._settings):
            return {"targets": [], "alerts": [], "disabled": True}
        now = time.time()
        out = []
        for t in self._store.mon_targets():
            if not self._mon_visible(t):
                continue
            st = self._mon.state.get(t["id"]) or {}
            lv = self._mon.snmp.live.get(t["id"]) if t.get("kind") == "snmp" else None
            out.append({"id": t["id"], "name": t.get("name") or t["host"], "grp": t.get("grp") or "", "icon": t.get("icon"),
                        "status": (st.get("status") or "unknown") if t.get("enabled") else "paused", "since": st.get("since"),
                        "rtt": st.get("rtt"), "maint": st.get("maint") or "", "cause": st.get("cause") or "", "err": st.get("err") or "",
                        "level": (lv or {}).get("level") or "", "alarms": [a.get("msg") for a in (lv or {}).get("alarms") or []][:3]})
        vis = {t["id"] for t in out}
        alerts = [a for a in list(self._mon.alerts) if a["target"] in vis][-30:]
        return {"targets": out, "alerts": alerts[::-1], "now": now}

    # ---- رخدادهای دستگاه: Trap و Syslog (1.25)
    @_safe
    def mon_events_query(self, rng="24h", kinds=None, sev=None, q="", tid=None):
        from . import trange
        try:
            since, until = trange.resolve(rng if isinstance(rng, dict) else str(rng))
        except ValueError as e:
            raise ConnectorError(str(e))
        kinds = [k for k in (kinds or []) if k in ("trap", "syslog")] or None
        sev = [x for x in (sev or []) if x in ("crit", "warn", "info", "ok")] or None
        vis = {t["id"] for t in self._store.mon_targets() if self._mon_visible(t)}
        tids = None
        if tid:
            if int(tid) not in vis:
                raise ConnectorError("هدف پیدا نشد.")
            tids = {int(tid)}
        elif not self._mon_admin():
            tids = vis                     # منبع ناشناخته (بدون هدف) فقط برای ادمین
        from .devevents import EventsError
        try:
            r = self._mon.events.query(since, until, kinds, sev, str(q or "")[:200], None, tids)
        except EventsError as e:
            raise ConnectorError(str(e))
        return {**r, "since": since, "until": until}

    @_safe
    def mon_events_status(self):
        from .devevents import trapdb
        ev = self._mon.events
        db = trapdb()
        return {"cfg": ev.cfg(), "status": ev.status, "stats": ev.stats, "recent": list(ev.recent)[:20],
                "trapdb": {"traps": len(db.get("traps") or {}), "source": db.get("source", "")}}

    @_safe
    def mon_events_cfg_save(self, cfg):
        from .devevents import EventsError, clean_cfg
        try:
            c = clean_cfg(cfg if isinstance(cfg, dict) else {})
        except EventsError as e:
            raise ConnectorError(str(e))
        self._settings.update({"events": c})
        self._mon._ev_sig = "restart"        # حلقه‌ی مانیتور با امضای تازه دوباره راه می‌اندازد
        self._store.add_history("monitor", "Trap و Syslog", "ok",
                                f"Trap: {'روشن، UDP ' + str(c['trap_port']) if c['trap_enabled'] else 'خاموش'} — "
                                f"Syslog: {'روشن، ' + str(c['syslog_port']) if c['syslog_enabled'] else 'خاموش'}")
        return {"cfg": c}

    # ---- توپولوژی (1.26)
    @_safe
    def mon_topo(self, root=None):
        from .topology import suggest
        vis = {t["id"]: t for t in self._store.mon_targets() if self._mon_visible(t)}
        d = self._mon.topo.load() or {}
        links = [lk for lk in d.get("links") or [] if lk["a"] in vis and (not lk.get("b") or lk["b"] in vis)]
        # 1.27.1: نقشه فقط پس از راه‌اندازی ادمین (انتخاب دستگاه‌ها و اسکن)؛ فقط همان دستگاه‌ها و همسایه‌هایشان رسم می‌شوند
        ids = [int(x) for x in (self._settings.get("topology", "ids", default=[]) or []) if str(x).isdigit()]
        if not ids or not d.get("at"):                  # راه‌اندازی نشده (یا نقشه‌ی نسخه‌های قبل بدون انتخاب ادمین): هیچ نقشه‌ای
            d, links = {}, []
        links = [lk for lk in links if lk["a"] in ids]
        show = (set(ids) | {lk["b"] for lk in links if lk.get("b")}) if d.get("at") else set()

        def node(t):
            return {"id": t["id"], "name": t["name"], "grp": t.get("grp") or "", "kind": t["kind"], "icon": t.get("icon"),
                    "parent_id": t.get("parent_id"), "status": (self._mon.state.get(t["id"]) or {}).get("status", "unknown")
                    if t.get("enabled") else "paused"}
        out = {"at": d.get("at"), "scanned": d.get("scanned", 0), "links": links, "scanning": self._mon.topo.scanning,
               "progress": self._mon.topo.progress, "errors": {k: v for k, v in (d.get("errors") or {}).items() if int(k) in vis},
               "ids": [i for i in ids if i in vis],
               "nodes": [node(t) for t in vis.values() if t["id"] in show],
               "candidates": [{"id": t["id"], "name": t["name"], "host": t.get("host") or "", "grp": t.get("grp") or ""}
                              for t in vis.values() if t["kind"] == "snmp"] if self._mon_admin() else []}
        if root and int(root) in vis:
            sg = suggest(links, int(root), set(vis))
            out["suggest"] = [{"id": k, "parent": v, "current": vis[k].get("parent_id")} for k, v in sorted(sg.items())]
        return out

    @_safe
    def mon_topo_scan(self, ids=None):
        """اسکن همسایه‌ها فقط روی دستگاه‌های SNMPی که ادمین انتخاب کرده (1.27.1؛ هرگز خودکار)."""
        u = self._current_user() or {}
        snmp_ids = {t["id"] for t in self._store.mon_targets() if t["kind"] == "snmp" and self._mon_visible(t)}
        if ids is None:
            ids = self._settings.get("topology", "ids", default=[]) or []
        ids = sorted({int(x) for x in ids if str(x).isdigit() and int(x) in snmp_ids})
        if not ids:
            raise ConnectorError("دست‌کم یک دستگاه SNMP برای نقشه انتخاب کنید.")
        self._settings.update({"topology": {"ids": ids}})
        if not self._mon.topo.scan_async(u.get("username") or "", ids):
            raise ConnectorError("اسکن توپولوژی در حال اجراست.")
        return {}

    @_safe
    def mon_topo_apply(self, root, ids):
        from .topology import suggest
        vis = {t["id"]: t for t in self._store.mon_targets() if self._mon_visible(t)}
        d = self._mon.topo.load() or {}
        sg = suggest(d.get("links") or [], int(root), set(vis))
        done = 0
        want = {int(x) for x in ids or [] if str(x).isdigit()}
        for i in [k for k in sg if k in want]:             # به ترتیب BFS از ریشه (بدون حلقه‌ی موقت)
            if i in vis:
                try:
                    pid = self._mon_parent_ok(sg[i], vis[i].get("owner") or "", i)
                except ConnectorError:
                    continue
                self._store.mon_set_parent([i], pid)
                done += 1
        self._mon.reload()
        self._store.add_history("monitor", "توپولوژی", "ok", f"وابستگی از نقشه برای {done} هدف (ریشه: {vis.get(int(root), {}).get('name', root)})")
        return {"count": done}

    # ---- پنجره‌های نگهداری
    def _maint_visible(self, w):
        return self._mon_admin() or not w.get("owner") or w.get("owner") == self._uname()

    @_safe
    def mon_maint_list(self):
        from .monitor import maint_on, maint_scope
        now = time.time()
        vis = {t["id"] for t in self._store.mon_targets() if self._mon_visible(t)}
        out = []
        for w in self._store.maint_list():
            if not self._maint_visible(w):
                continue
            ids, groups = maint_scope(w)
            w = {k: v for k, v in w.items() if k != "scope"}       # شناسه‌ی هدف‌هایی که کاربر نمی‌بیند فرستاده نمی‌شود
            out.append({**w, "ids": sorted(ids & vis), "groups": sorted(groups), "active": maint_on(w | {"scope": "{}"}, now),
                        "can_edit": self._mon_admin() or (w.get("owner") == self._uname() and self._mon_can_add())})
        return {"windows": out, "can_add": self._mon_can_add()}

    @_safe
    def mon_maint_save(self, w):
        from .monitor import MonitorError, clean_maint
        w = w if isinstance(w, dict) else {}
        if w.get("id"):
            old = self._store.maint_get(int(w["id"]))
            if not old or not (self._mon_admin() or old.get("owner") == self._uname()):
                raise ConnectorError("پنجره پیدا نشد یا اجازه‌ی تغییرش را ندارید.")
            owner = old.get("owner") or ""
        else:
            if len(self._store.maint_list()) >= 500:
                raise ConnectorError("حداکثر ۵۰۰ پنجره‌ی نگهداری.")
            owner = "" if self._mon_admin() else self._uname()
        sc = w.get("scope") if isinstance(w.get("scope"), dict) else {}
        vis = {t["id"] for t in self._store.mon_targets() if self._mon_visible(t)}
        w["scope"] = {"ids": [i for i in (sc.get("ids") or []) if str(i).isdigit() and int(i) in vis], "groups": sc.get("groups") or []}
        try:
            c = clean_maint(w, owner)
        except MonitorError as e:
            raise ConnectorError(str(e))
        mid = self._store.maint_save(c)
        self._mon.reload()
        when = (f"{time.strftime('%Y-%m-%d %H:%M', time.localtime(c['start']))} تا {time.strftime('%Y-%m-%d %H:%M', time.localtime(c['end']))}"
                if c["kind"] == "once" else f"هفتگی {c['t_from']}–{c['t_to']}")
        self._store.add_history("monitor", c["name"], "ok", ("ویرایش" if w.get("id") else "تعریف") + f" پنجره‌ی نگهداری — {when}")
        return {"id": mid}

    @_safe
    def mon_maint_delete(self, mid):
        w = self._store.maint_get(int(mid))
        if not w or not (self._mon_admin() or w.get("owner") == self._uname()):
            raise ConnectorError("پنجره پیدا نشد یا اجازه‌ی حذفش را ندارید.")
        self._store.maint_delete(w["id"])
        self._mon.reload()
        self._store.add_history("monitor", w["name"], "ok", "پنجره‌ی نگهداری حذف شد")
        return {}

    @_safe
    def mon_delete(self, tid):
        t = self._mon_get(tid, edit=True)
        self._store.mon_delete(t["id"])
        self._mon.state.pop(t["id"], None)
        self._mon.minutes.pop(t["id"], None)
        self._mon.snmp.clear(t["id"])
        self._mon.snmp.remove_files(t["id"])
        self._mon.reload()
        self._store.add_history("monitor", t["name"], "ok", "هدف حذف شد")
        return {}

    @_safe
    def mon_toggle(self, tid, enabled):
        t = self._mon_get(tid, edit=True)
        t["enabled"] = 1 if enabled else 0
        self._store.mon_save(t)
        self._mon.state.pop(t["id"], None)
        self._mon.reload()
        self._store.add_history("monitor", t["name"], "ok", "بررسی از سر گرفته شد" if enabled else "بررسی متوقف شد")
        return {}

    @_safe
    def mon_check_now(self, tid):
        t = self._mon_get(tid)
        st = self._mon.state.get(t["id"])
        if st:
            st["next"] = 0
        return {}

    @_safe
    def mon_report(self, rng="24h", ids=None):
        """rng: بازه‌ی آماده («24h»، «7d»…) یا {"from": ts, "to": ts}."""
        vis = {t["id"]: t for t in self._store.mon_targets() if self._mon_visible(t)}
        want = [int(i) for i in ids or [] if int(i) in vis] or list(vis)
        try:
            S = self._mon.series(rng if isinstance(rng, dict) else str(rng), set(want))
        except ValueError as e:
            return {"ok": False, "error": str(e)}
        step, since, until, data = S["step"], S["since"], S["until"], S["data"]
        now = time.time()
        evs = self._store.mon_events(since, until, set(want))
        rows = []
        for tid in want:
            b = data.get(tid) or []
            n, ok = sum(x[1] for x in b), sum(x[2] for x in b)
            rs, rn = sum(x[3] for x in b), sum(x[4] for x in b)
            mine = [e for e in evs if e["target_id"] == tid]
            real = [e for e in mine if (e.get("kind") or "down") == "down"]
            dur = lambda es: sum(max(0, min(e["end"] or now, until) - max(e["start"], since)) for e in es)  # noqa: E731
            down = dur([e for e in mine if (e.get("kind") or "down") != "maint"])
            rows.append({"id": tid, "name": vis[tid]["name"], "host": vis[tid]["url"] or vis[tid]["host"], "kind": vis[tid]["kind"],
                         "icon": vis[tid]["icon"], "grp": vis[tid]["grp"], "checks": n,
                         "avail": round(100 * ok / n, 3) if n else None, "outages": len(real), "downtime": int(max(0, down)),
                         "unreach": len([e for e in mine if e.get("kind") == "unreach"]),
                         "maint_time": int(dur([e for e in mine if e.get("kind") == "maint"])),
                         "rtt_avg": round(rs / rn, 1) if rn else None, "rtt_max": round(max((x[5] for x in b), default=0), 1) if rn else None,
                         "avail_series": [None if x[1] == 0 else round(100 * x[2] / x[1], 2) for x in b],
                         "rtt_series": [None if x[4] == 0 else round(x[3] / x[4], 1) for x in b]})
        keys = [x[0] for x in next(iter(data.values()), [])]
        from .trange import label
        return {"range": rng if isinstance(rng, str) else label(since, until), "step": step, "since": since, "until": until,
                "res": S["res"], "keys": keys, "rows": rows,
                "events": [{**e, "dur": int((e["end"] or now) - e["start"])} for e in evs[:500]]}

    @_safe
    def srv_health(self):
        """سلامت سرور و برنامه (فقط ادمین): دیسک، RAM، CPU، حجم داده‌ها، مشکل‌های فعلی."""
        return self._worker.health.view()

    @_safe
    def mon_storage(self):
        """حجم داده‌های مانیتورینگ و پایگاه داده (فقط ادمین؛ تنظیمات)."""
        out = self._mon.storage()
        db = 0
        for f in paths.data_dir().glob("state.*"):
            try:
                db += f.stat().st_size
            except OSError:
                pass
        out["db"] = db
        runs = 0
        for f in paths.runs_dir().rglob("*"):
            try:
                runs += f.stat().st_size if f.is_file() else 0
            except OSError:
                pass
        out["runs"] = runs
        return out

    @_safe
    def mon_icons(self):
        d = paths.data_dir() / "monitor" / "icons"
        out = {}
        if d.exists():
            for f in sorted(d.glob("*.bin")):
                try:
                    raw = atrest.read_bytes(f)
                    mime = "image/svg+xml" if raw.lstrip()[:5] in (b"<svg ", b"<?xml") or b"<svg" in raw[:200] else \
                        "image/png" if raw[:8] == b"\x89PNG\r\n\x1a\n" else "image/jpeg"
                    out[f.stem] = f"data:{mime};base64," + base64.b64encode(raw).decode("ascii")
                except Exception:
                    continue
        return {"icons": out}

    @_safe
    def mon_icon_upload(self, name, b64):
        u = self._current_user()
        if u and u.get("role") == "readonly":
            raise ConnectorError("دسترسی ندارید.")
        try:
            raw = base64.b64decode(str(b64 or ""), validate=True)
        except ValueError:
            raise ConnectorError("فایل نامعتبر است.")
        if not raw or len(raw) > 200 * 1024:
            raise ConnectorError("آیکن باید کمتر از ۲۰۰ کیلوبایت باشد.")
        if not (raw[:8] == b"\x89PNG\r\n\x1a\n" or raw[:3] == b"\xff\xd8\xff" or b"<svg" in raw[:400]):
            raise ConnectorError("فقط PNG، JPG یا SVG.")
        d = paths.data_dir() / "monitor" / "icons"
        d.mkdir(parents=True, exist_ok=True)
        if len(list(d.glob("*.bin"))) >= 60:
            raise ConnectorError("حداکثر ۶۰ آیکن سفارشی.")
        iid = os.urandom(6).hex()
        (d / f"{iid}.bin").write_bytes(raw)        # 1.22: آیکن داده‌ی حساس نیست؛ ساده (خواندن هر دو قالب را می‌فهمد)
        return {"icon": "custom:" + iid}

    def _sound_bytes(self, which):
        """(bytes, ext) صدای قطع/وصل: سفارشی (رمزشده) یا پیش‌فرض."""
        which = "up" if which == "up" else "down"
        ext = (self._settings.get("monitor", f"sound_{which}") or "").replace("custom:", "")
        p = paths.data_dir() / "monitor" / "sounds" / f"{which}.bin"
        if ext and p.exists():
            try:
                return atrest.read_bytes(p), ext
            except Exception:
                log.exception("sound")
        return (paths.ui_dir() / "sounds" / f"{which}.wav").read_bytes(), "wav"

    @_safe
    def mon_sound_get(self, which="down"):
        c = self._settings.get("monitor", f"sound_{'up' if which == 'up' else 'down'}") or ""
        if not c:
            return {"default": True, "url": f"sounds/{'up' if which == 'up' else 'down'}.wav"}
        data, ext = self._sound_bytes(which)
        mime = {"mp3": "audio/mpeg", "wav": "audio/wav", "ogg": "audio/ogg"}.get(ext, "audio/wav")
        return {"default": False, "mime": mime, "b64": base64.b64encode(data).decode("ascii")}

    @_safe
    def mon_sound_set(self, which, name, b64):
        which = "up" if which == "up" else "down"
        if not b64:
            self._settings.update({"monitor": {f"sound_{which}": ""}})
            p = paths.data_dir() / "monitor" / "sounds" / f"{which}.bin"
            if p.exists():
                p.unlink()
            return {}
        try:
            raw = base64.b64decode(str(b64), validate=True)
        except ValueError:
            raise ConnectorError("فایل نامعتبر است.")
        if len(raw) > 2 * 1024 * 1024:
            raise ConnectorError("فایل صدا باید کمتر از ۲ مگابایت باشد.")
        if raw[:4] == b"RIFF" and raw[8:12] == b"WAVE":
            ext = "wav"
        elif raw[:3] == b"ID3" or raw[:2] in (b"\xff\xfb", b"\xff\xf3", b"\xff\xf2"):
            ext = "mp3"
        elif raw[:4] == b"OggS":
            ext = "ogg"
        else:
            raise ConnectorError("فقط فایل WAV، MP3 یا OGG.")
        d = paths.data_dir() / "monitor" / "sounds"
        d.mkdir(parents=True, exist_ok=True)
        (d / f"{which}.bin").write_bytes(raw)      # 1.22: صدا داده‌ی حساس نیست؛ ساده
        self._settings.update({"monitor": {f"sound_{which}": "custom:" + ext}})
        self._store.add_history("monitor", "صدا", "ok", f"صدای {'وصل' if which == 'up' else 'قطع'} عوض شد ({str(name)[:60]})")
        return {"ext": ext}

    # ------------------------------------------------------------ SNMP (پروفایل‌ها، تست، مرورگر OID، داده‌ی زنده)
    # قاعده‌ی پروفایل همان SSH است: هدف مشترک (ادمین) فقط پروفایل مشترک، هدف شخصی فقط پروفایل شخصی صاحبش؛
    # وگرنه اپراتور با گذاشتن آدرس دستگاه خودش community/رمز مشترک را می‌گرفت (community در v2c رمزنشده می‌رود).
    def _snmp_profile_public(self, p, usage):
        from .snmp import cred_from_vault
        c = cred_from_vault(self._vault, p["id"])
        pfx = f"cred.{p['id']}."
        return {"id": p["id"], "name": p["name"], "notes": p.get("notes") or "", "personal": bool(p.get("owner")),
                "version": c["v"], "username": c.get("user", ""), "auth": c.get("auth", ""), "priv": c.get("priv", ""),
                "ctx": c.get("ctx", ""), "has_password": self._vault.has(pfx + "password"),
                "has_secret": self._vault.has(pfx + "secret"), "targets": usage.get(p["id"], 0)}

    @_safe
    def snmp_cred_list(self):
        from .snmp import AUTH_PROTOS, PRIV_PROTOS
        usage = {}
        for t in self._store.mon_targets():
            if t.get("cred_id"):
                usage[t["cred_id"]] = usage.get(t["cred_id"], 0) + 1
        return {"profiles": [self._snmp_profile_public(p, usage) for p in self._store.creds_list("snmp") if self._cred_visible(p)],
                "auth": AUTH_PROTOS, "priv": PRIV_PROTOS, "admin": self._mon_admin(),
                "can_add": self._mon_can_add()}

    @_safe
    def snmp_cred_save(self, profile, password="", secret=""):
        """profile: {id?, name, version 2c/3, username, auth, priv, ctx, notes, personal}.
        v2c: password = community. v3: password = رمز auth، secret = رمز priv. خالی در ویرایش = بدون تغییر."""
        from .snmp import SnmpError, clean_cred, cred_from_vault
        if not self._vault.unlocked():
            raise VaultError("برنامه قفل است.")
        u = self._current_user()
        if u and u.get("role") == "readonly":
            raise ConnectorError("دسترسی ندارید.")
        p = profile if isinstance(profile, dict) else {}
        name = str(p.get("name") or "").strip()[:80]
        if not name:
            raise ConnectorError("نام پروفایل خالی است.")
        admin = self._mon_admin()
        old = None
        if p.get("id"):
            old = self._cred_check(p["id"], edit=True)
            if old["kind"] != "snmp":
                raise ConnectorError("این پروفایل برای SNMP نیست.")
            oc = cred_from_vault(self._vault, old["id"])
            prev = {"community": oc.get("community"), "auth_key": oc.get("auth_key"), "priv_key": oc.get("priv_key")}
            if str(p.get("version") or "2c") != oc["v"] or (oc["v"] == "3" and str(p.get("username") or "").strip() != oc.get("user")):
                prev = {}          # نسخه یا کاربر عوض شد: رمزها دوباره لازم است
        else:
            prev = {}
        try:
            meta, sec = clean_cred(p, str(password or "") if str(p.get("version") or "2c") != "3" else "",
                                   str(password or "") if str(p.get("version") or "2c") == "3" else "", str(secret or ""), prev)
        except SnmpError as e:
            raise ConnectorError(str(e))
        if old:
            cid = self._store.cred_save({"id": old["id"], "name": name, "notes": str(p.get("notes") or "")[:500]})
        else:
            personal = bool(p.get("personal")) or not admin
            if personal and not self._uname():
                raise ConnectorError("پروفایل شخصی فقط با کاربران فعال (ورود با نام کاربری) معنا دارد.")
            cid = self._store.cred_save({"name": name, "kind": "snmp", "owner": self._uname() if personal else "",
                                         "notes": str(p.get("notes") or "")[:500]})
        pfx = f"cred.{cid}."
        ch = {pfx + "snmp": json.dumps({k: meta[k] for k in ("v", "auth", "priv", "ctx") if k in meta}),
              pfx + "username": meta.get("user", "")}
        if meta["v"] == "2c":
            ch[pfx + "secret"] = ""
            if sec.get("community"):
                ch[pfx + "password"] = sec["community"]
        else:
            if meta["auth"] == "none":
                ch[pfx + "password"] = ""
            elif sec.get("auth_key"):
                ch[pfx + "password"] = sec["auth_key"]
            if meta["priv"] == "none":
                ch[pfx + "secret"] = ""
            elif sec.get("priv_key"):
                ch[pfx + "secret"] = sec["priv_key"]
        self._vault.set_many(ch)
        self._mon.snmp.client.forget()
        n = len(self._store.cred_users(cid))
        self._store.add_history("monitor", name, "ok", f"پروفایل SNMP {'ساخته' if not old else 'به‌روز'} شد (v{meta['v']})"
                                + (f"؛ {n} هدف از آن استفاده می‌کنند" if n else ""))
        return {"id": cid}

    @_safe
    def snmp_cred_delete(self, cid):
        p = self._cred_check(cid, edit=True)
        if p["kind"] != "snmp":
            raise ConnectorError("این پروفایل برای SNMP نیست.")
        used = self._store.cred_users(p["id"])
        if used:
            names = "، ".join((d.get("name") or d["host"]) for d in used[:10]) + (" …" if len(used) > 10 else "")
            raise ConnectorError(f"{len(used)} هدف از این پروفایل استفاده می‌کنند ({names}); اول پروفایل آن‌ها را عوض کنید.")
        self._store.cred_delete(p["id"])
        self._vault.delete_prefix(f"cred.{p['id']}.")
        self._mon.snmp.client.forget()
        self._store.add_history("monitor", p["name"], "ok", "پروفایل SNMP حذف شد")
        return {}

    def _snmp_cred(self, cred_id, owner):
        if cred_id in (None, "", 0, "0"):
            raise ConnectorError("پروفایل اعتبارنامه‌ی SNMP را انتخاب کنید.")
        p = self._cred_check(cred_id)
        if p["kind"] != "snmp":
            raise ConnectorError("این پروفایل برای SNMP نیست.")
        if (p.get("owner") or "").lower() != (owner or "").lower():
            raise ConnectorError("هدف مشترک فقط از پروفایل مشترک و هدف شخصی فقط از پروفایل شخصی خودتان استفاده می‌کند.")
        return int(p["id"])

    def _snmp_adhoc(self, target):
        """هدف ذخیره‌شده یا فرم ذخیره‌نشده (تست / مرورگر OID) با همان قاعده‌ی دسترسی ذخیره."""
        from .monitor import MonitorError, clean_target
        from .snmp import cred_from_vault, load_cfg
        u = self._current_user()
        if u and u.get("role") == "readonly":
            raise ConnectorError("دسترسی ندارید.")
        t = target if isinstance(target, dict) else {"id": target}
        if t.get("id") and not t.get("host"):
            old = self._mon_get(t["id"], edit=True)
            if old["kind"] != "snmp":
                raise ConnectorError("این هدف SNMP نیست.")
            return old, load_cfg(old), cred_from_vault(self._vault, self._snmp_cred(old.get("cred_id"), old.get("owner")))
        owner = (self._mon_get(t["id"], edit=True).get("owner") or "") if t.get("id") else ("" if self._mon_admin() else self._uname())
        try:
            c = clean_target({**t, "kind": "snmp"}, owner)
        except MonitorError as e:
            raise ConnectorError(str(e))
        cid = self._snmp_cred(t.get("cred_id"), owner)
        c["cred_id"] = cid
        return c, json.loads(c["snmp"]), cred_from_vault(self._vault, cid)

    # ------------------------------------------------------------ کتابخانه‌ی SNMP (1.27): MIB، Walk، قالب دستگاه
    def _read_user_files(self, path, title, exts, multiple=False, limit=64 * 1024 * 1024):
        """[(نام، bytes)]: حالت سرور ← فایل آپلودشده (رمزشده در uploads)؛ دسکتاپ ← پنجره‌ی انتخاب فایل اگر path خالی است."""
        from . import atrest
        names = [path] if isinstance(path, str) and path else (list(path) if isinstance(path, (list, tuple)) else [])
        if paths.is_server():
            if not names:
                return []
            out = []
            for n in names[:200]:
                p = Path(server_path(str(n)))
                if not p.is_file():
                    raise ConnectorError("فایل آپلودشده پیدا نشد.")
                data = atrest.read_bytes(p)
                if len(data) > limit:
                    raise ConnectorError("فایل بیش از حد بزرگ است.")
                out.append((p.name.split("_", 1)[-1], data))
            return out
        if not names:
            if not self._window:
                raise ConnectorError("انتخاب فایل در این محیط در دسترس نیست.")
            import webview
            res = self._window.create_file_dialog(webview.OPEN_DIALOG, allow_multiple=multiple,
                                                  file_types=(f"{title} ({';'.join('*' + e for e in exts)})", "All files (*.*)"))
            if not res:
                return []
            names = list(res) if isinstance(res, (list, tuple)) else [res]
        out = []
        for n in names[:500]:
            p = Path(str(n))
            if str(n).startswith(("\\\\", "//")):
                raise ConnectorError("مسیر شبکه‌ای پشتیبانی نمی‌شود.")
            if not p.is_file():
                raise ConnectorError(f"فایل پیدا نشد: {p.name}")
            if p.stat().st_size > limit:
                raise ConnectorError(f"فایل {p.name} بیش از حد بزرگ است.")
            out.append((p.name, p.read_bytes()))
        return out

    # ---- MIB
    @_safe
    def mib_list(self):
        from .mibs import LIB
        out = LIB.modules()
        out["compiling"] = bool(getattr(self, "_mib_busy", False))
        out["can_edit"] = self._mon_admin()
        out["types"] = [{"name": p["name"], "match": p["match"], "modules": p["modules"], "count": len(p["metrics"]),
                         "items": [m["name"] for m in p["metrics"]]} for p in LIB.auto_profiles()]
        return out

    def _mib_compile_async(self):
        from .mibs import LIB
        if getattr(self, "_mib_busy", False):
            self._mib_again = True
            return

        def run():
            try:
                while True:
                    self._mib_again = False
                    LIB.compile_all()
                    if not self._mib_again:
                        break
            except Exception as e:  # noqa — نتیجه در وضعیت ماژول‌ها
                log.exception("mib compile")
                self._store.add_history("monitor", "MIB", "error", f"کامپایل MIB ناموفق: {e}", user=self._who())
            finally:
                self._mib_busy = False
        self._mib_busy = True
        threading.Thread(target=run, name="mib-compile", daemon=True).start()

    @_safe
    def mib_upload(self, path=None):
        """فایل‌های MIB (متن یا zip، از سایت سازنده). ماژول هم‌نام جایگزین می‌شود؛ سپس همه دوباره کامپایل می‌شوند."""
        import io
        import zipfile
        from .mibs import LIB, MibError
        files = self._read_user_files(path, "MIB", (".mib", ".my", ".txt", ".zip"), multiple=True)
        if not files:
            return {"cancelled": True}
        names, bad = [], []

        def add(fname, data):
            try:
                txt = data.decode("utf-8")
            except UnicodeDecodeError:
                txt = data.decode("latin-1")
            try:
                names.extend(LIB.add_text(txt))
            except MibError as e:
                bad.append(f"{fname}: {e}")
        for fname, data in files:
            if data[:4] == b"PK\x03\x04":
                try:
                    z = zipfile.ZipFile(io.BytesIO(data))
                except zipfile.BadZipFile:
                    bad.append(f"{fname}: zip خراب است")
                    continue
                total = 0
                for info in z.infolist()[:5000]:
                    if info.is_dir() or info.file_size > 4 * 1024 * 1024 or info.filename.startswith("__MACOSX"):
                        continue
                    total += info.file_size
                    if total > 200 * 1024 * 1024:
                        bad.append(f"{fname}: حجم بازشده بیش از ۲۰۰ مگابایت")
                        break
                    raw = z.read(info)
                    if b"DEFINITIONS" in raw[:200000]:
                        add(info.filename.rsplit("/", 1)[-1], raw)
            else:
                add(fname, data)
        if names:
            self._mib_compile_async()
            self._store.add_history("monitor", "MIB", "ok", f"{len(names)} ماژول MIB بارگذاری شد", user=self._who())
        return {"added": sorted(set(names)), "errors": bad[:30]}

    @_safe
    def mib_delete(self, names):
        from .mibs import LIB, MibError
        for n in (names if isinstance(names, list) else [names])[:500]:
            try:
                LIB.delete(n)
            except MibError as e:
                raise ConnectorError(str(e))
        self._mib_compile_async()
        return {}

    @_safe
    def mib_compile(self):
        self._mib_compile_async()
        return {}

    @_safe
    def mib_types(self):
        """انواع دستگاه که از MIBهای بارگذاری‌شده خودکار ساخته شده‌اند (برای «نوع دستگاه» در فرم هدف)."""
        from .mibs import LIB
        return {"types": [{"id": p["id"], "name": p["name"], "match": p["match"], "count": len(p["metrics"])} for p in LIB.auto_profiles()]}

    @_safe
    def snmp_test(self, target):
        """تست اتصال و کشف: system، سازنده، و این‌که کدام بخش‌ها روی دستگاه پاسخ دارند (بدون ذخیره)."""
        from .snmp import SnmpError, VENDOR_NAMES, collect
        t, cfg, cred = self._snmp_adhoc(target)
        from .mibs import LIB
        cfg = {**cfg, "_profiles": LIB.auto_profiles()}
        if self._demo and not str(t["host"]).startswith("127."):
            from .snmp import demo_raw
            raw = demo_raw({**t, "id": t.get("id") or 0}, cfg)
        else:
            try:
                raw = self._mon.snmp.client.run(collect(self._mon.snmp.client, cred, t["host"], t["port"], cfg,
                                                        float(t["timeout"]), cfg["retries"]), 120)
            except SnmpError as e:
                raise ConnectorError(str(e))
        return {"sys": raw["sys"], "vendor": raw["vendor"], "vendor_name": VENDOR_NAMES.get(raw["vendor"], raw["vendor"]),
                "rtt": raw["rtt"], "errors": raw["errors"], "cpu": raw["cpu"]["value"] if raw["cpu"] else None,
                "cpu_src": raw["cpu"]["src"] if raw["cpu"] else "", "mem": raw["mem"]["pct"] if raw["mem"] else None,
                "mem_src": raw["mem"]["src"] if raw["mem"] else "", "disks": len(raw["disks"]), "temps": len(raw["temps"]),
                "fans": len(raw["fans"]), "psus": len(raw["psus"]), "sensors": len(raw["sensors"]),
                "ifs": [{"name": x["name"], "alias": x["alias"], "oper": x["oper"], "admin": x["admin"]} for x in raw["ifs"][:1024]],
                "if_count": len(raw["ifs"]),
                "oids": [{"oid": o["oid"], "value": o["raw"], "type": o["tn"]} for o in raw["oids"]],
                "profile": {"name": raw["prof"]["name"], "count": len(raw["prof"]["items"])} if raw.get("prof") else None}

    @_safe
    def snmp_walk(self, target, oid, max_rows=500):
        """مرورگر OID: گشتن یک زیرشاخه روی دستگاه (حداکثر ۲۰۰۰ ردیف)."""
        from .snmp import SnmpError, norm_oid
        t, cfg, cred = self._snmp_adhoc(target)
        try:
            base = norm_oid(oid)
        except SnmpError as e:
            raise ConnectorError(str(e))
        n = max(1, min(2000, int(max_rows or 500)))
        if self._demo and not str(t["host"]).startswith("127."):
            return {"rows": [[base + ".0", "OctetString", "Demo"]], "more": False}
        try:
            rows = self._mon.snmp.client.run(self._mon.snmp.client.abrowse(cred, t["host"], t["port"], base, float(t["timeout"]),
                                                                           cfg["retries"], n + 1), 180)
        except SnmpError as e:
            raise ConnectorError(str(e))
        return {"rows": rows[:n], "more": len(rows) > n}

    @_safe
    def mon_snmp_live(self, tid, have=0, with_ifs=True):
        """داده‌ی زنده‌ی یک هدف SNMP (poll سبک: اگر از have تغییری نیست فقط same برمی‌گردد)."""
        t = self._mon_get(tid)
        lv = self._mon.snmp.live.get(t["id"])
        if not lv:
            return {"none": True}
        if have and float(have) == lv["t"]:
            return {"same": True, "t": lv["t"]}
        out = {k: v for k, v in lv.items() if k != "ifs"}
        if with_ifs:            # «پیگیری» از تنظیمات فعلی (تغییر از جدول، پیش از خواندن بعدی هم دیده شود)
            from .snmp import load_cfg
            w = set(load_cfg(t)["watch"])
            out["ifs"] = [{**x, "watch": x["name"] in w} for x in lv["ifs"]]
        out["if_count"] = len(lv["ifs"])
        return out

    @_safe
    def mon_snmp_series(self, tid, rng="24h", keys=None):
        t = self._mon_get(tid)
        keys = [str(k)[:120] for k in (keys or ["cpu", "mem", "temp", "rtt"])][:40]
        from .monitor import keep_days
        keep = keep_days(self._settings.get("monitor"))[0]
        try:
            return self._mon.snmp.series(t["id"], rng if isinstance(rng, dict) else str(rng), keys, keep)
        except ValueError as e:
            return {"ok": False, "error": str(e)}

    @_safe
    def mon_snmp_watch(self, tid, names, on):
        """پیگیری پورت (هشدار قطع، مصرف و خطا) از جدول پورت‌ها."""
        from .snmp import load_cfg
        t = self._mon_get(tid, edit=True)
        cfg = load_cfg(t)
        w = list(cfg["watch"])
        for n in [str(x)[:80] for x in (names or [])][:300]:
            if on and n not in w:
                w.append(n)
            elif not on and n in w:
                w.remove(n)
        cfg["watch"] = w[:300]
        t["snmp"] = json.dumps(cfg, ensure_ascii=False)
        self._store.mon_save(t)
        self._mon.reload()
        self._store.add_history("monitor", t["name"], "ok", f"پیگیری پورت: {'، '.join(str(x) for x in names[:10])}" if on else f"پایان پیگیری پورت: {'، '.join(str(x) for x in names[:10])}")
        return {"watch": w}

    # ------------------------------------------------------------ مدیریت دارایی (1.21)
    # هر تغییرِ پیدا شده با اسکن فقط پیشنهاد است و ادمین تأیید می‌کند؛ تغییر دستی اپراتور هم پیشنهاد است.
    @property
    def _assets(self):
        return self._worker.assets

    def _asset_can_view(self):
        if "asset" not in perms.enabled_tools(self._settings):
            return False
        u = self._current_user()
        return u is None or u.get("role") == "admin" or (u.get("role") == "operator" and "asset" in perms.allowed_tools(u, self._settings))

    def _asset_view(self):
        if "asset" not in perms.enabled_tools(self._settings):
            raise ConnectorError("ابزار «مدیریت دارایی» در تنظیمات خاموش است.")
        if not self._asset_can_view():
            raise ConnectorError("دسترسی به مدیریت دارایی ندارید.")

    def _asset_role(self):
        u = self._current_user()
        return "admin" if u is None else u.get("role")

    def _asset_public(self, a, parts_n=None, pend=None):
        return {**a, "parts_n": parts_n.get(a["id"], 0) if parts_n is not None else None,
                "pending": bool(pend and a["serial"] in pend), "name": a.get("label") or a.get("hostname") or ""}

    @_safe
    def asset_list(self):
        self._asset_view()
        parts_n = {}
        for p in self._store.asset_parts():
            parts_n[p["asset_id"]] = parts_n.get(p["asset_id"], 0) + 1
        pend = {c["serial"] for c in self._store.asset_changes("pending", None, 5000)}
        role = self._asset_role()
        return {"assets": [self._asset_public(a, parts_n, pend) for a in self._store.assets()], "pending": len(pend),
                "admin": role == "admin", "can_edit": role in ("admin", "operator"), "titles": __import__("autokrp.assets", fromlist=["x"]).TITLES}

    @_safe
    def asset_get(self, aid):
        self._asset_view()
        a = self._store.asset(int(aid))
        if not a:
            raise ConnectorError("دارایی پیدا نشد.")
        ch = self._store.asset_changes(None, a["serial"], 200)
        return {"asset": self._asset_public(a), "parts": self._store.asset_parts(a["id"]), "history": self._store.asset_history(a["id"], 2000),
                "changes": [self._chg_public(c) for c in ch]}

    def _chg_public(self, c):
        a = self._store.asset(c["asset_id"]) if c.get("asset_id") else self._store.asset_by_serial(c["serial"])
        f = (c["data"].get("fields") or {}) if c["kind"] == "new" else {}
        return {**c, "summary": self._assets.change_summary(c), "asset_name": (a and (a.get("label") or a.get("hostname"))) or f.get("hostname") or "",
                "asset_id": a["id"] if a else None}

    @_safe
    def asset_changes(self, status="pending"):
        self._asset_view()
        st = status if status in ("pending", "approved", "rejected", "obsolete") else None
        return {"changes": [self._chg_public(c) for c in self._store.asset_changes(st, None, 3000)], "admin": self._asset_role() == "admin"}

    @_safe
    def asset_history(self):
        self._asset_view()
        names = {a["id"]: a.get("label") or a.get("hostname") or "" for a in self._store.assets()}
        return {"rows": [{**h, "asset_name": names.get(h["asset_id"], "")} for h in self._store.asset_history(None, 5000)]}

    @_safe
    def asset_save(self, aid=None, fields=None, new_serial="", new_fields=None):
        """ادمین: مستقیم (با ثبت در تاریخچه). اپراتور با ابزار «مدیریت دارایی»: پیشنهاد در انتظار تأیید ادمین."""
        from .assets import AssetError
        self._asset_view()
        role = self._asset_role()
        if role not in ("admin", "operator"):
            raise ConnectorError("دسترسی ندارید.")
        try:
            r = self._assets.manual(int(aid) if aid else None, fields if isinstance(fields, dict) else {}, self._uname() or "admin",
                                    role == "admin", new_serial, new_fields if isinstance(new_fields, dict) else {})
        except AssetError as e:
            raise ConnectorError(str(e))
        if r.get("pending"):
            self._store.add_history("asset", str(new_serial or aid), "ok", "پیشنهاد تغییر دستی دارایی ثبت شد (در انتظار تأیید ادمین)")
            self._worker.notifier.notify("asset_change", f"کاربر {self._uname()} تغییر دستی دارایی را پیشنهاد داد؛ منتظر تأیید ادمین است.")
        return r

    @_safe
    def asset_decide(self, ids, approve, note=""):
        self._asset_view()
        ids = [int(i) for i in (ids or [])][:2000]
        return self._assets.decide(ids, bool(approve), self._uname() or "admin", str(note or "")[:300])

    @_safe
    def asset_restore(self, ids):
        self._asset_view()
        return {"restored": self._assets.restore([int(i) for i in (ids or [])][:2000], self._uname() or "admin")}

    @_safe
    def asset_delete(self, aid):
        self._asset_view()
        a = self._store.asset(int(aid))
        if not a:
            raise ConnectorError("دارایی پیدا نشد.")
        self._store.asset_delete(a["id"])
        self._store.asset_hist_add(None, a["serial"], "deleted", a.get("label") or a.get("hostname") or "", "", self._uname() or "admin", "دستی")
        self._store.add_history("asset", a["serial"], "ok", f"دارایی حذف شد ({a.get('label') or a.get('hostname') or ''})")
        return {}

    @_safe
    def asset_sources(self):
        self._asset_view()
        return {"sources": self._assets.sources(), "cfg": self._assets.cfg(), "job": self._assets.public_job()}

    @_safe
    def asset_settings_save(self, cfg):
        self._asset_view()
        c = cfg if isinstance(cfg, dict) else {}
        t = str(c.get("scan_time") or "03:00")
        if not re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d", t):
            raise ConnectorError("ساعت اسکن باید به شکل HH:MM باشد.")
        src = c.get("sources")
        if src is not None:
            known = {x["id"] for x in self._assets.sources()}
            src = {"ids": [str(i) for i in (src.get("ids") if isinstance(src, dict) else src) or [] if str(i) in known]}
        try:
            conc = max(1, min(10, int(c.get("concurrency") or 4)))
        except (TypeError, ValueError):
            conc = 4
        new = {"scan_enabled": bool(c.get("scan_enabled")), "scan_time": t, "sources": src, "loc_default": bool(c.get("loc_default")),
               "concurrency": conc}
        old = self._settings.get("assets") or {}
        if new["scan_enabled"] and (not old.get("scan_enabled") or old.get("scan_time") != new["scan_time"]):
            # روشن کردن یا عوض کردن ساعت: ساعتی که امروز گذشته فوراً اجرا نشود
            self._store.set_meta("assets_enabled_at", str(time.time()))
        self._settings.update({"assets": new})
        self._store.add_history("asset", "تنظیمات اسکن دارایی", "ok",
                                f"اسکن روزانه {'روشن' if new['scan_enabled'] else 'خاموش'} ({t})؛ منابع: {'همه' if src is None else len(src['ids'])}")
        return {"cfg": self._assets.cfg()}

    @_safe
    def asset_scan_start(self, ids=None):
        from .assets import AssetError
        self._asset_view()
        try:
            return {"job": self._assets.scan_start([str(i) for i in ids] if ids else None, self._uname() or "admin")}
        except AssetError as e:
            raise ConnectorError(str(e))

    @_safe
    def asset_scan_status(self):
        self._asset_view()
        return {"job": self._assets.public_job()}

    @_safe
    def asset_scan_cancel(self):
        self._asset_view()
        return {"cancelled": self._assets.scan_cancel()}

    def _mon_alert(self, a):
        """هشدار مانیتورینگ وقتی رابطی برای پخش صدا نیست (دسکتاپ در پس‌زمینه) یا «پخش روی سرور» روشن است."""
        from .monitor import play_sound, quiet_now
        c = self._settings.get("monitor") or {}
        srv = paths.is_server()
        if srv and not c.get("server_sound"):
            return
        locked = self._vault is not None and self._vault.ui_locked
        if not srv and not self._hidden and not locked:
            return                  # پنجره باز است: رابط خودش صدا را پخش می‌کند
        st = "up" if a["state"] in ("up", "clear") else "down"       # هشدار آستانه‌ی SNMP مثل قطعی
        if st == "up" and c.get("sound_on_up", True) is False:
            return
        if not srv and st == "down" and c.get("show_window", True) is not False and self._window:
            try:
                self._hidden = False
                self._window.show()
                self._window.restore()
            except Exception:
                log.exception("show window")
        if quiet_now(c):
            return
        data, ext = self._sound_bytes(st)
        if ext == "ogg":            # پخش‌کننده‌ی داخلی ویندوز OGG ندارد
            data, ext = (paths.ui_dir() / "sounds" / f"{st}.wav").read_bytes(), "wav"
        threading.Thread(target=play_sound, args=(data, ext, int(c.get("repeat", 3) or 1) if st == "down" else 1),
                         daemon=True).start()

    # ---- پنجره‌ی دسکتاپ: ماندن در پس‌زمینه
    def _on_closing(self):
        """True = واقعاً بسته شود؛ False = پنجره پنهان و برنامه برای مانیتورینگ در پس‌زمینه می‌ماند."""
        if self._quitting:
            return True
        c = self._settings.get("monitor") or {}
        action = c.get("close_action") or ("quit" if c.get("background") is False else "ask")
        try:
            active = "monitor" in perms.enabled_features(self._settings) and any(t.get("enabled") for t in self._store.mon_targets())
        except Exception:
            active = False
        if not active or action == "quit":
            return True
        locked = self._vault is not None and (self._vault.ui_locked or not self._vault.unlocked())
        if action == "background":
            self._go_background()
            return False
        if locked:                  # رابط قفل است و پرسیدن ممکن نیست: مثل قبل بسته می‌شود
            return True
        # پرسیدن در خود پنجره (پس از برگشتن از رویداد closing؛ صدا زدن پنجره داخل همین رویداد قفل می‌کند)
        w = self._window
        threading.Thread(target=lambda: (time.sleep(0.15), w and w.evaluate_js("window.monCloseAsk && window.monCloseAsk()")),
                         daemon=True).start()
        return False

    def _go_background(self):
        self._hidden = True
        self._worker.emit("info", "پنجره بسته شد؛ برنامه برای مانیتورینگ در پس‌زمینه باز است (برای باز کردن دوباره روی آیکن AutoKRP کنار ساعت ویندوز کلیک کنید)", "monitor")
        w = self._window
        threading.Thread(target=lambda: (time.sleep(0.15), w and w.hide()), daemon=True).start()

    @_safe
    def app_close_choice(self, action, remember=False):
        """پاسخ پنجره‌ی «بستن برنامه؟»: background = ادامه در پس‌زمینه، quit = بستن کامل."""
        if paths.is_server():
            raise ConnectorError("این بخش در حالت سرور در دسترس نیست.")
        action = "quit" if action == "quit" else "background"
        if remember:
            self._settings.update({"monitor": {"close_action": action}})
        if action == "background":
            self._go_background()
        else:
            self._quitting = True
            w = self._window
            threading.Thread(target=lambda: (time.sleep(0.2), w and w.destroy()), daemon=True).start()
        return {}

    def _show_window(self):
        if self._window:
            self._hidden = False
            self._window.show()
            self._window.restore()

    @_safe
    def app_quit(self):
        """خروج کامل (دسکتاپ)، حتی وقتی مانیتورینگ در پس‌زمینه می‌ماند."""
        if paths.is_server():
            raise ConnectorError("این بخش در حالت سرور در دسترس نیست.")
        u = self._current_user()
        if u and u.get("role") != "admin":
            raise ConnectorError("خروج کامل فقط برای ادمین است.")
        self._quitting = True
        w = self._window
        threading.Thread(target=lambda: (time.sleep(0.3), w and w.destroy()), daemon=True).start()
        return {}

    def _ssh_items_ok(self, items):
        """ابزار SSH در ابزارها و کارها: فقط دستگاه‌های مشترکی که کاربر به آن‌ها دسترسی دارد."""
        for it in items or []:
            if isinstance(it, dict) and it.get("tool") == "ssh":
                self._check_devs((it.get("opts") or {}).get("device_ids") or [], shared_only=True)

    def _dev_public(self, d, profiles=None):
        d = dict(d)
        d["backup_on"] = bool(d.get("backup")) if d.get("backup") is not None else d["device_type"] != "linux"
        pfx = sshmod.cred_prefix(d)
        d["username"] = self._vault.get(pfx + "username", "")   # یوزرنیم هم در vault است
        d["has_password"] = self._vault.has(pfx + "password")
        d["has_secret"] = self._vault.has(pfx + "secret")
        if d.get("cred_id"):
            p = (profiles or {}).get(d["cred_id"]) if profiles is not None else self._store.cred_get(d["cred_id"])
            d["cred_name"] = p["name"] if p else "(حذف شده)"
        return d

    # ------------------------------------------------------------ پروفایل اعتبارنامه
    # پروفایل مشترک (owner خالی، فقط ادمین می‌سازد) فقط برای دستگاه مشترک؛ پروفایل شخصی فقط برای دستگاه شخصی همان کاربر.
    # دلیل: اگر دستگاه شخصی می‌توانست از پروفایل مشترک استفاده کند، اپراتور با گذاشتن آدرس سرور خودش رمز ادمین را می‌گرفت.
    CRED_KINDS = ("ssh",)

    def _cred_visible(self, p):
        owner = (p.get("owner") or "").lower()
        return self._can_shared() if not owner else owner == self._uname()

    def _cred_check(self, cid, edit=False):
        p = self._store.cred_get(int(cid)) if str(cid or "").isdigit() else None
        if not p or not self._cred_visible(p):
            raise ConnectorError("پروفایل اعتبارنامه پیدا نشد یا دسترسی به آن ندارید.")
        if edit and not p.get("owner") and (self._current_user() or {"role": "admin"}).get("role") != "admin":
            raise ConnectorError("پروفایل‌های مشترک را فقط ادمین تغییر می‌دهد.")
        return p

    def _cred_public(self, p, usage=None):
        pfx = f"cred.{p['id']}."
        return {"id": p["id"], "name": p["name"], "kind": p["kind"], "notes": p.get("notes") or "", "personal": bool(p.get("owner")),
                "username": self._vault.get(pfx + "username", ""), "has_password": self._vault.has(pfx + "password"),
                "has_secret": self._vault.has(pfx + "secret"), "devices": usage.get(p["id"], 0) if usage is not None else None}

    @_safe
    def cred_list(self):
        usage = {}
        for d in self._store.ssh_devices():
            if d.get("cred_id"):
                usage[d["cred_id"]] = usage.get(d["cred_id"], 0) + 1
        return {"profiles": [self._cred_public(p, usage) for p in self._store.creds_list("ssh") if self._cred_visible(p)]}

    @_safe
    def cred_save(self, profile, password="", secret=""):
        """profile: {id?, name, kind, username, notes, personal}؛ password/secret خالی = بدون تغییر، "__clear__" = پاک."""
        if not self._vault.unlocked():
            raise VaultError("برنامه قفل است.")
        p = profile if isinstance(profile, dict) else {}
        name = str(p.get("name") or "").strip()[:80]
        if not name:
            raise ConnectorError("نام پروفایل خالی است.")
        admin = (self._current_user() or {"role": "admin"}).get("role") == "admin"
        if p.get("id"):
            old = self._cred_check(p["id"], edit=True)
            if old["kind"] != "ssh":
                raise ConnectorError("این پروفایل برای SSH نیست.")
            cid = self._store.cred_save({"id": old["id"], "name": name, "notes": str(p.get("notes") or "")[:500]})
            kind = old["kind"]
        else:
            kind = str(p.get("kind") or "ssh")
            if kind not in self.CRED_KINDS:
                raise ConnectorError("نوع پروفایل نامعتبر است.")
            personal = bool(p.get("personal")) or not admin
            if personal and not self._uname():
                raise ConnectorError("پروفایل شخصی فقط با کاربران فعال (ورود با نام کاربری) معنا دارد.")
            if not str(p.get("username") or "").strip() or not password:
                raise ConnectorError("برای پروفایل تازه یوزر و پسورد لازم است.")
            cid = self._store.cred_save({"name": name, "kind": kind, "owner": self._uname() if personal else "",
                                         "notes": str(p.get("notes") or "")[:500]})
        ch = {f"cred.{cid}.username": str(p.get("username") or "").strip()}
        for k, v in (("password", password), ("secret", secret)):
            if v == "__clear__":
                ch[f"cred.{cid}.{k}"] = ""
            elif v:
                ch[f"cred.{cid}.{k}"] = str(v)
        self._vault.set_many(ch)
        n = len(self._store.cred_users(cid))
        self._store.add_history("ssh", name, "ok", f"پروفایل اعتبارنامه {'ساخته' if not p.get('id') else 'به‌روز'} شد"
                                + (f"؛ {n} دستگاه از آن استفاده می‌کنند" if n else ""))
        self._protect_bg()
        return {"id": cid}

    @_safe
    def cred_delete(self, cid):
        p = self._cred_check(cid, edit=True)
        if p["kind"] != "ssh":
            raise ConnectorError("این پروفایل برای SSH نیست.")
        used = self._store.cred_users(p["id"])
        if used:
            names = "، ".join((d.get("name") or d["host"]) for d in used[:10]) + (" …" if len(used) > 10 else "")
            raise ConnectorError(f"{len(used)} دستگاه از این پروفایل استفاده می‌کنند ({names}); اول اعتبارنامه‌ی آن‌ها را عوض کنید.")
        self._store.cred_delete(p["id"])
        self._vault.delete_prefix(f"cred.{p['id']}.")
        self._store.add_history("ssh", p["name"], "ok", "پروفایل اعتبارنامه حذف شد")
        return {}

    def _dev_cred(self, cred_id, owner):
        """اعتبارسنجی پروفایل انتخاب‌شده برای دستگاهی با صاحب owner ('' = مشترک)."""
        if cred_id in (None, "", 0, "0"):
            return None
        p = self._cred_check(cred_id)
        if p["kind"] != "ssh":
            raise ConnectorError("این پروفایل برای SSH نیست.")
        if (p.get("owner") or "").lower() != (owner or "").lower():
            raise ConnectorError("دستگاه مشترک فقط از پروفایل مشترک و دستگاه شخصی فقط از پروفایل شخصی خودتان استفاده می‌کند.")
        return int(p["id"])

    @_safe
    def ssh_list(self):
        prof = {p["id"]: p for p in self._store.creds_list()}
        devs = [self._dev_public(d, prof) for d in self._store.ssh_devices() if self._dev_visible(d)]
        for d in devs:
            d["personal"] = bool(d.get("owner"))
        return {"devices": devs, "scripts": self._store.ssh_scripts(), "types": sshmod.DEVICE_TYPES,
                "groups": sorted({d["grp"] for d in devs if d.get("grp")}), "vars": list(sshmod.VARS)}

    def _clean_dev(self, d):
        host = str(d.get("host") or "").strip()
        if not host or any(c in host for c in " /\\@"):
            raise ConnectorError(f"آدرس دستگاه معتبر نیست: {host or '(خالی)'}")
        try:
            port = int(d.get("port") or 22)
            if not 0 < port < 65536:
                raise ValueError
        except ValueError:
            raise ConnectorError(f"پورت معتبر نیست: {d.get('port')}")
        dt = str(d.get("device_type") or "linux").strip()
        if not dt.replace("_", "").isalnum():
            raise ConnectorError(f"نوع دستگاه معتبر نیست: {dt}")
        cid = d.get("cred_id")
        return {"id": d.get("id"), "cred_id": int(cid) if str(cid or "").isdigit() and int(cid) > 0 else None,
                "name": str(d.get("name") or "").strip() or host, "host": host, "port": port,
                "device_type": dt, "username": str(d.get("username") or "").strip(), "grp": str(d.get("grp") or "").strip(),
                "use_enable": 1 if d.get("use_enable") else 0, "notes": str(d.get("notes") or ""),
                "legacy": 1 if d.get("legacy") else 0,
                "backup": None if d.get("backup") in (None, "", "default") else (1 if d.get("backup") else 0)}

    def _set_creds(self, dev_id, password=None, secret=None, username=None):
        ch = {}
        if username is not None:
            ch[f"ssh.{dev_id}.username"] = username
        for k, v in (("password", password), ("secret", secret)):
            if v == "__clear__":
                ch[f"ssh.{dev_id}.{k}"] = ""
            elif v:
                ch[f"ssh.{dev_id}.{k}"] = v
        if ch:
            self._vault.set_many(ch)

    @_safe
    def ssh_save_device(self, dev, password="", secret=""):
        if not self._vault.unlocked():
            raise VaultError("برنامه قفل است.")
        d = self._clean_dev(dev or {})
        username = d.pop("username")
        admin = (self._current_user() or {"role": "admin"}).get("role") == "admin"
        if d.get("id"):
            old = self._check_devs([d["id"]])[0]
            if not old.get("owner") and not admin:
                raise ConnectorError("دستگاه‌های مشترک را فقط ادمین ویرایش می‌کند.")
            d["owner"] = old.get("owner") or ""
        else:
            personal = bool((dev or {}).get("personal")) or not admin
            if personal and not self._uname():
                raise ConnectorError("دستگاه شخصی فقط با کاربران فعال (ورود با نام کاربری) معنا دارد.")
            d["owner"] = self._uname() if personal else ""
        if d["owner"]:
            d["backup"] = 0                       # پشتیبان خودکار فقط برای دستگاه‌های مشترک
        d["cred_id"] = self._dev_cred(d.get("cred_id"), d["owner"])
        dev_id = self._store.ssh_save_device(d)
        if d["cred_id"]:
            self._vault.delete_prefix(f"ssh.{dev_id}.")      # اعتبارنامه‌ی اختصاصی قبلی دیگر استفاده نمی‌شود
        else:
            self._set_creds(dev_id, password, secret, username)
        self._protect_bg()
        return {"id": dev_id}

    @_safe
    def ssh_delete_devices(self, ids):
        admin = (self._current_user() or {"role": "admin"}).get("role") == "admin"
        for d in self._check_devs(ids):
            if not d.get("owner") and not admin:
                raise ConnectorError("دستگاه‌های مشترک را فقط ادمین حذف می‌کند.")
        ids = [int(i) for i in ids or []]
        self._store.ssh_delete_devices(ids)
        for i in ids:
            self._vault.delete_prefix(f"ssh.{i}.")
        return {"deleted": len(ids)}

    @_safe
    def ssh_bulk_add(self, text, defaults=None, preview=False):
        """
        هر خط یک دستگاه:  host  یا  host:port  یا CSV:  host,port,username,password,device_type,secret,name,group
        ستون‌های خالی از «مقادیر مشترک» پر می‌شوند.
        """
        import csv as _csv
        dfl = defaults or {}
        rows, errors = [], []
        lines = [l for l in (text or "").splitlines() if l.strip() and not l.strip().startswith("#")]
        for n, row in enumerate(_csv.reader(lines), 1):
            row = [c.strip() for c in row]
            if len(row) == 1 and ":" in row[0] and row[0].count(":") == 1:
                row = row[0].split(":") 
            if row and row[0].lower() in ("host", "ip", "address"):
                continue
            g = lambda i, k: (row[i] if len(row) > i and row[i] else dfl.get(k, ""))
            d = {"host": g(0, "host"), "port": g(1, "port") or 22, "username": g(2, "username"), "device_type": g(4, "device_type") or "linux",
                 "name": g(6, "name"), "grp": g(7, "grp"), "use_enable": dfl.get("use_enable")}
            try:
                cd = self._clean_dev(d)
            except ConnectorError as e:
                errors.append(f"خط {n}: {e}")
                continue
            if dfl.get("cred_id"):
                cd["cred_id"] = dfl["cred_id"]
            rows.append((cd, g(3, "password"), g(5, "secret")))
        if preview:
            return {"count": len(rows), "errors": errors[:20],
                    "sample": [{**r[0], "has_password": bool(r[1]), "has_secret": bool(r[2])} for r in rows[:10]]}
        # یوزرنیم هم مثل پسورد فقط در vault ذخیره می‌شود
        if not self._vault.unlocked():
            raise VaultError("برنامه قفل است.")
        owner = self._uname() if dfl.get("personal") and self._uname() else ""     # افزودن گروهی فقط ادمین (perms)
        cid = self._dev_cred(dfl.get("cred_id"), owner) if dfl.get("cred_id") else None
        creds = {}
        for cd, pw, sec in rows:
            user = cd.pop("username")
            cd["owner"], cd["cred_id"] = owner, cid
            if owner:
                cd["backup"] = 0
            dev_id = self._store.ssh_save_device(cd)
            if cid:
                continue                                  # اعتبارنامه از پروفایل
            if user:
                creds[f"ssh.{dev_id}.username"] = user
            if pw:
                creds[f"ssh.{dev_id}.password"] = pw
            if sec:
                creds[f"ssh.{dev_id}.secret"] = sec
        if creds:
            self._vault.set_many(creds)
        self._worker.emit("ok", f"SSH: {len(rows)} دستگاه اضافه شد", "ssh")
        self._protect_bg()
        return {"count": len(rows), "errors": errors[:20]}

    @_safe
    def ssh_save_script(self, sc):
        sc = sc or {}
        if not str(sc.get("name") or "").strip():
            raise ConnectorError("نام اسکریپت خالی است.")
        clean = {"id": sc.get("id"), "name": str(sc["name"]).strip(), "device_type": sc.get("device_type") or "any",
                 "mode": "config" if sc.get("mode") == "config" else "exec", "body": str(sc.get("body") or ""),
                 "use_sudo": 1 if sc.get("use_sudo") else 0, "save_config": 1 if sc.get("save_config") else 0}
        return {"id": self._store.ssh_save_script(clean)}

    @_safe
    def ssh_delete_script(self, sid):
        self._store.ssh_delete_script(int(sid))
        return {}

    @_safe
    def ssh_preview(self, device_ids, body):
        self._check_devs(device_ids)
        out = []
        for i in device_ids or []:
            d = self._store.ssh_device(int(i))
            if d:
                d["username"] = self._vault.get(sshmod.cred_prefix(d) + "username", "")
                out.append({"name": d.get("name") or d["host"], "host": d["host"], "text": sshmod.render(body or "", d)})
        return {"items": out[:50]}

    @_safe
    def ssh_start(self, device_ids, script, options=None):
        self._check_devs(device_ids)
        job = self._ssh.start([int(i) for i in device_ids or []], script or {}, options or {}, "run")
        return {"job_id": job["id"]}

    @_safe
    def ssh_test(self, device_ids):
        self._check_devs(device_ids)
        job = self._ssh.start([int(i) for i in device_ids or []], {"name": "تست اتصال"}, {"concurrency": 10, "timeout": 30}, "test")
        return {"job_id": job["id"]}

    @_safe
    def ssh_job(self):
        j = self._ssh.public()
        if j:                                     # نتیجه‌ی دستگاه شخصی کاربر دیگر نمایش داده نمی‌شود
            vis = {d["id"] for d in self._store.ssh_devices() if self._dev_visible(d)}
            j["results"] = [r for r in j["results"] if r.get("device_id") in vis]
        return {"job": j}

    @_safe
    def ssh_cancel(self):
        return {"cancelled": self._ssh.cancel()}

    @_safe
    def ssh_jobs(self):
        return {"jobs": self._store.ssh_jobs()}

    @_safe
    def ssh_job_results(self, job_id):
        vis = {d["id"] for d in self._store.ssh_devices() if self._dev_visible(d)}
        return {"results": [r for r in self._store.ssh_results(job_id) if r.get("device_id") in vis]}

    @_safe
    def ssh_output(self, job_id, dev_id):
        self._out_check(dev_id)
        return {"text": self._ssh.output(str(job_id), int(dev_id))}

    @_safe
    def ssh_export_output(self, job_id):
        parts = []
        vis = {d["id"] for d in self._store.ssh_devices() if self._dev_visible(d)}   # 1.26.2: مثل ssh_job_results
        for r in self._store.ssh_results(job_id):
            if r.get("device_id") not in vis:
                continue
            try:
                txt = self._ssh.output(job_id, r["device_id"]) if r.get("out_file") else ""
            except Exception as e:
                txt = f"[خروجی خوانده نشد: {e}]"
            parts.append(f"===== {r['name']} ({r['host']}) — {r['status']} — {r['message']} =====\n{txt}\n")
        return self.save_export(f"autokrp_ssh_{job_id}.txt", "\n".join(parts), False)

    @_safe
    def ssh_hostkeys(self):
        return {"keys": self._ssh.hostkeys.list()}

    @_safe
    def ssh_forget_hostkey(self, entry):
        return {"removed": self._ssh.hostkeys.forget(str(entry))}

    @_safe
    def save_export_many(self, items):
        """چند فایل (مثلاً همه‌ی نمودارها) در یک پوشه‌ی انتخابی."""
        items = [(Path(str(n)).name, c) for n, c in (items or []) if n and c]
        if not items:
            raise ConnectorError("چیزی برای ذخیره نیست.")
        if self._window:
            import webview
            res = self._window.create_file_dialog(webview.FOLDER_DIALOG)
            if not res:
                return {"cancelled": True}
            folder = Path(res[0] if isinstance(res, (list, tuple)) else res)
        else:
            folder = paths.data_dir() / "exports"
            folder.mkdir(exist_ok=True)
        for name, content in items:
            if Path(name).suffix.lower() != ".png":
                continue
            (folder / name).write_bytes(base64.b64decode(content))
        return {"path": str(folder), "count": len(items)}

    # ------------------------------------------------------------ FortiGate offline update
    # ------------------------------------------------------------ زمان‌بندی SSH
    @_safe
    def ssh_sched_list(self):
        from .fgupdate import PKG_BY_FILE
        fgu = self._settings.get("fgupdate") or {}
        return {"schedules": self._settings.get("ssh_schedules", default=[]) or [],
                "fgu_current": {**fgu, "package_names": [PKG_BY_FILE[f][0] for f in (fgu.get("packages") or []) if f in PKG_BY_FILE]}}

    @_safe
    def ssh_sched_save(self, sch):
        """ذخیره‌ی یک زمان‌بندی. در نوع fgupdate، تنظیمات فعلی تب «به‌روزرسانی FortiGate» برداشته می‌شود."""
        import re
        from .fgupdate import PKG_BY_FILE
        sch = dict(sch or {})
        items = self._settings.get("ssh_schedules", default=[]) or []
        old = next((x for x in items if x.get("id") == sch.get("id")), None)
        name = str(sch.get("name") or "").strip()[:80]
        if not name:
            raise ConnectorError("نام زمان‌بندی را وارد کنید.")
        kind = sch.get("kind") if sch.get("kind") in ("script", "fgupdate") else "script"
        t = str(sch.get("time") or "")
        if not re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d", t):
            raise ConnectorError("ساعت اجرا معتبر نیست.")
        days = sorted({int(d) for d in sch.get("days") or [] if str(d).isdigit() and 0 <= int(d) <= 6})
        devs = {d["id"]: d for d in self._store.ssh_devices() if not d.get("owner")}   # زمان‌بندی فقط دستگاه‌های مشترک
        ids = [int(i) for i in sch.get("device_ids") or [] if int(i) in devs]
        if not ids:
            raise ConnectorError("حداقل یک دستگاه انتخاب کنید.")
        out = {"id": (old or {}).get("id") or pysecrets.token_hex(4), "name": name, "kind": kind, "time": t,
               "days": days, "device_ids": ids, "enabled": bool(sch.get("enabled", True))}
        if kind == "script":
            sid = int(sch.get("script_id") or 0)
            if not self._store.ssh_script(sid):
                raise ConnectorError("یک اسکریپت ذخیره‌شده انتخاب کنید.")
            o = sch.get("options") or {}
            out["script_id"] = sid
            out["options"] = {"concurrency": max(1, min(50, int(o.get("concurrency") or 5))),
                              "timeout": max(10, min(3600, int(o.get("timeout") or 120)))}
        else:
            bad = [devs[i].get("name") or devs[i]["host"] for i in ids if devs[i]["device_type"] != "fortinet"]
            if bad:
                raise ConnectorError("این دستگاه‌ها از نوع FortiGate نیستند: " + "، ".join(bad))
            fgu = dict(self._settings.get("fgupdate") or {})
            if not [f for f in fgu.get("packages") or [] if f in PKG_BY_FILE]:
                raise ConnectorError("در «SSH ← به‌روزرسانی FortiGate» ابتدا پوشه و پکیج‌ها را تنظیم و یک بار اجرا کنید؛ "
                                     "زمان‌بندی همان تنظیمات را برمی‌دارد.")
            out["fgu"] = fgu
        # «اولین اجرا از همین لحظه»: اگر تازه روشن شده، ساعتِ گذشته‌ی امروز اجرا نمی‌شود
        if out["enabled"] and not (old or {}).get("enabled"):
            out["enabled_at"] = time.time()
        else:
            out["enabled_at"] = (old or {}).get("enabled_at", time.time())
        for k in ("last_at", "last_status", "last_message"):
            if old and k in old:
                out[k] = old[k]
        items = [out if x.get("id") == out["id"] else x for x in items] if old else items + [out]
        self._settings.set_ssh_schedules(items)
        return {"schedules": items}

    @_safe
    def ssh_sched_toggle(self, sid, on):
        items = self._settings.get("ssh_schedules", default=[]) or []
        for x in items:
            if x.get("id") == sid:
                if on and not x.get("enabled"):
                    x["enabled_at"] = time.time()
                x["enabled"] = bool(on)
        self._settings.set_ssh_schedules(items)
        return {"schedules": items}

    @_safe
    def ssh_sched_delete(self, sid):
        items = [x for x in self._settings.get("ssh_schedules", default=[]) or [] if x.get("id") != sid]
        self._settings.set_ssh_schedules(items)
        return {"schedules": items}

    @_safe
    def fgu_info(self):
        from . import fgupdate
        devs = [self._dev_public(d) for d in self._store.ssh_devices()
                if d["device_type"] == "fortinet" and not d.get("owner") and self._can_shared()]
        for d in devs:
            try:
                d["local_ip"] = fgupdate.local_ip_for(d["host"], d.get("port") or 22)
            except OSError:
                d["local_ip"] = ""
        return {"devices": devs, "packages": [{"kind": k, "file": f, "title": t} for k, f, t in fgupdate.PACKAGES],
                "opts": self._settings.get("fgupdate") or {}}

    @_safe
    def fgu_check_folder(self, folder, packages):
        from . import fgupdate
        folder = self._fgu_folder(folder)
        return {"check": fgupdate.check_folder(folder, packages or [p[1] for p in fgupdate.PACKAGES])}

    def _fgu_folder(self, folder):
        """حالت سرور: بسته‌های FortiGate فقط از پوشه‌ی fgupdate داخل پوشه‌ی داده‌ی سرور (روی خود سیستم سرور کپی شوند)."""
        if not paths.is_server():
            return folder
        d = paths.data_dir() / "fgupdate"
        d.mkdir(exist_ok=True)
        return server_path(folder or str(d), "fgupdate")

    @_safe
    def pick_folder(self):
        if paths.is_server():
            return {"web_upload": True}
        if not self._window:
            raise ConnectorError("انتخاب پوشه در این محیط در دسترس نیست؛ مسیر را دستی وارد کنید.")
        import webview
        res = self._window.create_file_dialog(webview.FOLDER_DIALOG)
        if not res:
            return {"path": ""}
        return {"path": res[0] if isinstance(res, (list, tuple)) else res}

    @_safe
    def fgu_start(self, device_ids, opts):
        opts = dict(opts or {})
        if (opts.get("source") or "local") == "local":
            opts["folder"] = self._fgu_folder(opts.get("folder"))
        self._check_devs(device_ids, shared_only=True)
        keep = {k: opts.get(k) for k in ("source", "folder", "tftp_ip", "tftp_port", "multi_vdom", "vdom", "delay", "timeout", "packages")}
        self._settings.update({"fgupdate": keep})
        job = self._worker.fgu.start([int(i) for i in device_ids or []], opts)
        return {"job_id": job["id"]}

    @_safe
    def fgu_job(self):
        return {"job": self._worker.fgu.public()}

    @_safe
    def fgu_cancel(self):
        return {"cancelled": self._worker.fgu.cancel()}

    # ------------------------------------------------------------ config backups
    @_safe
    def backup_overview(self):
        devs = [self._dev_public(d) for d in self._store.ssh_devices() if not d.get("owner") and self._can_shared()]
        last = {}
        for b in self._store.backups(limit=100000):
            last.setdefault(b["device_id"], []).append(b)
        for d in devs:
            vs = last.get(d["id"], [])
            d["versions"] = len(vs)
            d["last_version"] = vs[0]["ts"] if vs else None
        cfg = self._settings.get("backup") or {}
        return {"devices": devs, "commands": cfg.get("commands") or {}, "keep": cfg.get("keep"),
                "types": sshmod.DEVICE_TYPES}

    @_safe
    def ssh_set_backup(self, ids, on):
        self._check_devs(ids, shared_only=True)
        ids = [int(i) for i in ids or []]
        self._store.ssh_set_backup_flag(ids, bool(on))
        return {"count": len(ids)}

    @_safe
    def backup_versions(self, dev_id):
        self._check_devs([dev_id], shared_only=True)
        return {"versions": self._store.backups(int(dev_id), limit=1000)}

    def _bk_check(self, bid):
        if not self._can_shared():
            raise ConnectorError("دسترسی به دستگاه‌های مشترک ندارید.")
        row = self._store.backup(int(bid))       # 1.26.2: دستگاه همین نسخه هم باید برای کاربر قابل‌دید باشد
        d = self._store.ssh_device(int(row["device_id"])) if row else None
        if d and not self._dev_visible(d):
            raise ConnectorError("دسترسی به این دستگاه ندارید.")

    def _out_check(self, dev_id):
        """خروجی SSH یک دستگاه: فقط اگر دستگاه برای کاربر قابل‌دید باشد؛ خروجی دستگاه حذف‌شده فقط برای ادمین."""
        d = self._store.ssh_device(int(dev_id))
        if d is None:
            u = self._current_user()
            if u is not None and u.get("role") != "admin":
                raise ConnectorError("دسترسی به خروجی این دستگاه ندارید.")
        elif not self._dev_visible(d):
            raise ConnectorError("دسترسی به خروجی این دستگاه ندارید.")

    @_safe
    def backup_view(self, bid):
        self._bk_check(bid)
        row, text = self._worker.backups.text(int(bid))
        return {"version": row, "text": text}

    @_safe
    def backup_delete(self, ids):
        for i in ids or []:
            self._bk_check(i)
        n = sum(1 for i in ids or [] if self._worker.backups.delete(int(i)))
        self._worker.emit("info", f"پشتیبان کانفیگ: {n} نسخه حذف شد", "backup")
        return {"deleted": n}

    # متن‌های بزرگ (کانفیگ کامل FortiGate چند مگابایت است) تکه‌تکه به رابط فرستاده می‌شوند؛
    # پل pywebview با پاسخ چندمگابایتی ممکن است بی‌صدا گیر کند.
    # تکه‌ی کوچک: پاسخ‌های خیلی بزرگ در پل pywebview روی WebView2 (ویندوز) ممکن است صفحه را از کار بیندازند
    CHUNK = 48 * 1024

    def _big_text(self, kind, a, b=None):
        # 1.26.2: بررسی دسترسی پیش از کش (قبلاً text_chunk بدون بررسی، پشتیبان و خروجی دستگاه دیگران را می‌داد)
        if kind == "backup":
            self._bk_check(a)
        else:
            self._out_check(b)
        key = (self._uname(), kind, str(a), str(b))
        cache = getattr(self, "_txt_cache", None)
        if cache and cache[0] == key and time.time() - cache[1] < 300:
            return cache[2], cache[3]
        meta = {}
        if kind == "backup":
            row, text = self._worker.backups.text(int(a))
            meta = {"version": row}
        else:
            text = self._ssh.output(str(a), int(b))
        self._txt_cache = (key, time.time(), text, meta)
        return text, meta

    @_safe
    def text_chunk(self, kind, a, b=None, offset=0):
        if kind not in ("backup", "ssh"):
            raise ConnectorError("نوع نامعتبر")
        if int(offset or 0) == 0:
            self._txt_cache = None   # بار اول همیشه تازه خوانده شود
        text, meta = self._big_text(kind, a, b)
        off = max(0, int(offset or 0))
        chunk = text[off:off + self.CHUNK]
        nxt = off + len(chunk)
        out = {"chunk": chunk, "next": nxt, "total": len(text), "done": nxt >= len(text)}
        if off == 0:
            out["meta"] = meta
        if out["done"]:
            self._txt_cache = None
        return out

    @_safe
    def backup_diff(self, old_id, new_id):
        self._bk_check(old_id)
        self._bk_check(new_id)
        return {"diff": self._worker.backups.diff(int(old_id), int(new_id))}

    @_safe
    def backup_export(self, bid):
        self._bk_check(bid)
        row, text = self._worker.backups.text(int(bid))
        d = self._store.ssh_device(row["device_id"]) or {"name": str(row["device_id"])}
        safe = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in (d.get("name") or "device"))
        return self.save_export(f"{safe}_{time.strftime('%Y%m%d_%H%M', time.localtime(row['ts']))}.txt", text, False)

    @_safe
    def backup_export_latest(self, ids):
        """1.27.10: آخرین نسخه‌ی پشتیبان چند دستگاه (انتخاب کاربر) در یک فایل zip؛ هر دستگاه یک فایل متنی."""
        import io
        import zipfile
        if not self._can_shared():
            raise ConnectorError("دسترسی به دستگاه‌های مشترک ندارید.")
        ids = list(dict.fromkeys(int(i) for i in (ids or [])))[:1000]
        if not ids:
            raise ConnectorError("هیچ دستگاهی انتخاب نشده است.")
        devs = self._check_devs(ids, shared_only=True)
        buf, used, n, skipped = io.BytesIO(), set(), 0, []
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            for d in devs:
                last = self._store.backups(int(d["id"]), limit=1)
                if not last:
                    skipped.append(d.get("name") or d["host"])
                    continue
                row, text = self._worker.backups.text(int(last[0]["id"]))
                safe = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in (d.get("name") or d["host"]))[:60] or "device"
                fn = f"{safe}_{time.strftime('%Y%m%d_%H%M', time.localtime(row['ts']))}.txt"
                k = 2
                while fn in used:
                    fn = f"{safe}_{k}_{time.strftime('%Y%m%d_%H%M', time.localtime(row['ts']))}.txt"
                    k += 1
                used.add(fn)
                z.writestr(fn, text)
                n += 1
            if skipped:
                z.writestr("_no_backup.txt", "\n".join(["دستگاه‌های بدون نسخه‌ی پشتیبان / Devices without a backup:", ""] + skipped) + "\n")
        if not n:
            raise ConnectorError("هیچ‌کدام از دستگاه‌های انتخاب‌شده نسخه‌ی پشتیبان ندارند.")
        data = buf.getvalue()
        if len(data) > 200 * 1024 * 1024:
            raise ConnectorError("حجم خروجی بیش از ۲۰۰ مگابایت است؛ دستگاه‌های کمتری انتخاب کنید.")
        out = self._save_bytes(f"autokrp_backups_{time.strftime('%Y%m%d_%H%M')}.zip", ".zip", data)
        if not out.get("cancelled"):
            self._store.add_history("export", "پشتیبان کانفیگ", "ok", f"آخرین نسخه‌ی {n} دستگاه در یک فایل zip"
                                    + (f"؛ {len(skipped)} دستگاه نسخه نداشت" if skipped else ""))
        return {**out, "count": n, "skipped": skipped}

    @_safe
    def backup_now(self, ids=None):
        if ids:
            self._check_devs(ids, shared_only=True)
        elif not self._can_shared():
            raise ConnectorError("دسترسی به دستگاه‌های مشترک ندارید.")
        try:
            job = self._worker.start_backup([int(i) for i in ids] if ids else None)
        except RuntimeError as e:
            raise ConnectorError(str(e))
        return {"job_id": job["id"]}

    # ------------------------------------------------------------ notifications
    @_safe
    def notify_test(self, data=None):
        from .notify import NotifyError, friendly as nfriendly
        trace = []
        try:
            self._worker.notifier.test(data or {}, trace)
        except NotifyError as e:
            return {"sent": False, "message": str(e), "trace": trace}
        except Exception as e:
            return {"sent": False, "message": nfriendly(e), "trace": trace}
        return {"sent": True, "message": "ایمیل آزمایشی ارسال شد.", "trace": trace}

    @_safe
    def list_history(self):
        return {"rows": self._store.list_history(), "runs": self._store.list_runs()}

    @_safe
    def history_view(self, hid, fname=None, q=None):
        """نمایش داده‌ی یک ردیف تاریخچه: جدول CSV و گزارش اجرا، خروجی SSH، متن ضبط‌شده‌ی ترمینال، فایل دریافتی."""
        import csv as csvmod
        import io
        row = self._store.history_get(int(hid))
        if not row:
            raise ConnectorError("ردیف پیدا نشد.")
        u = self._current_user()
        admin = u is None or u.get("role") == "admin"
        own = (row.get("user") or "").lower() == self._uname()
        f = row.get("file") or ""
        if not f and row.get("run_id"):
            rd = paths.runs_dir() / str(row["run_id"])
            f = str(rd) if rd.is_dir() else ""
        kind = row.get("kind")
        if kind in ("terminal", "transfer"):
            if not (admin or own):
                raise ConnectorError("فقط کاربری که این نشست را باز کرده (یا ادمین) می‌تواند آن را ببیند.")
            if kind == "terminal":
                p = paths.inside(f, [paths.data_dir() / "term_logs"]) if f else None
                if p is None or not p.is_file():
                    raise ConnectorError("متن این نشست ضبط نشده است (ضبط ترمینال در تنظیمات خاموش بود).")
                from .term import read_recording
                text = read_recording(p)
                cut = len(text) > 3_000_000
                return {"type": "term", "text": text[-3_000_000:], "cut": cut, "title": row["target"]}
            p = paths.inside(f, [paths.data_dir() / "received"]) if f else None
            if p is None or not p.is_file():
                raise ConnectorError("فایلی برای این ردیف نیست.")
            from .xfer import enc_size
            return {"type": "received", "rid": p.name, "size": enc_size(p), "title": row["target"]}
        if kind == "ssh" and f:
            if not admin and "ssh" not in perms.allowed_tools(u, self._settings):
                raise ConnectorError("دسترسی به خروجی SSH ندارید.")
            p = paths.inside(f, [paths.data_dir() / "ssh_runs"])
            if p is None or not p.is_dir():
                raise ConnectorError("خروجی پیدا نشد.")
            for b in sorted(p.glob("*.bin")):
                d = self._store.ssh_device(int(b.stem)) if b.stem.isdigit() else None
                if d and f"({d['host']})" in (row.get("target") or "") and self._dev_visible(d):
                    return {"type": "text", "text": self._ssh.output(p.name, int(b.stem)), "title": row["target"]}
            raise ConnectorError("خروجی این دستگاه پیدا نشد یا دسترسی ندارید.")
        p = paths.inside(f, [paths.runs_dir()]) if f else None
        if p is not None and not p.exists() and p.parent.is_dir() and p.parent != paths.runs_dir().resolve():
            p = p.parent          # فایل کمکی اجرا (مثلاً test_*.json نسخه‌های قبل) پاک شده؛ پوشه‌ی همان اجرا
        if p is None or not p.exists():
            raise ConnectorError("داده‌ای برای نمایش در این ردیف نیست.")
        base = p if p.is_dir() else p.parent
        files = sorted([x.name for x in base.iterdir() if x.suffix.lower() == ".csv"])
        if (base / "run.log").is_file():
            files.append("run.log")
        if not files:
            raise ConnectorError("فایلی برای نمایش نیست.")
        pick = fname if fname in files else (p.name if p.is_file() and p.name in files else files[0])
        fp = base / pick
        if pick == "run.log":
            return {"type": "text", "text": "\n".join(atrest.read_log_lines(fp)), "files": files, "file": pick, "title": row["target"]}
        rd = csvmod.reader(io.StringIO(atrest.read_text(fp)))
        head = next(rd, [])
        needle = str(q or "").strip().casefold()[:200]
        rows, total, matched = [], 0, 0
        for r in rd:            # جستجو روی همه‌ی ردیف‌های فایل (نه فقط ۲۰۰۰ ردیف نمایش‌داده‌شده)
            total += 1
            if needle and not any(needle in str(c).casefold() for c in r):
                continue
            matched += 1
            if len(rows) < 2000:
                rows.append(r)
        return {"type": "csv", "columns": head, "rows": rows, "total": total, "matched": matched, "q": needle,
                "files": files, "file": pick, "title": row["target"]}

    @_safe
    def save_ui(self, key, value):
        """ترجیحات نمایش. فقط کلیدهای مشخص با مقدار کوچک؛ با کاربران، برای هر کاربر جدا."""
        if key == "lang":
            if value not in ("fa", "en"):
                raise ConnectorError("زبان نامعتبر است.")
            if not paths.is_server():
                paths.set_ui_lang(value)       # پنجره‌های بومی (tray، پیام‌ها) هم همین زبان
        elif key == "calendar":
            if not isinstance(value, str) or len(value) > 20:
                raise ConnectorError("مقدار نامعتبر است.")
        elif key == "hidden_tools":     # «ابزارهای من»: فقط نمایش برای همین کاربر؛ دسترسی‌ها عوض نمی‌شوند
            if not isinstance(value, list) or not all(x in perms.TOOLS + perms.FEATURES for x in value):
                raise ConnectorError("مقدار نامعتبر است.")
        elif key == "ip_columns":
            if value is not None and (not isinstance(value, list) or len(value) > 60
                                      or not all(isinstance(x, str) and len(x) <= 40 for x in value)):
                raise ConnectorError("مقدار نامعتبر است.")
        else:
            raise ConnectorError("کلید نامعتبر است.")
        u = self._current_user()
        if u:
            self._settings.set_user_ui(u["username"].lower(), key, value)
        else:
            self._settings.update({"ui": {key: value}})
        return {}

    # ------------------------------------------------------------ files
    def _webfile(self, res):
        """حالت سرور: خروجی ساخته‌شده در پوشه‌ی exports/downloads به دانلود یک‌بارمصرف برای همین کاربر تبدیل می‌شود.
        فایل یا پوشه‌ی دیگری (داده‌های برنامه) هرگز از این راه دانلود نمی‌شود."""
        import zipfile
        p = Path(res["path"]).resolve()
        dl = paths.data_dir() / "downloads"
        dl.mkdir(exist_ok=True)
        roots = [dl.resolve(), (paths.data_dir() / "exports").resolve()]
        if not any(r == p.parent or r in p.parents for r in roots):
            return {k: v for k, v in res.items() if k != "path"}
        if p.is_dir():
            zp = dl / (p.name + ".zip")
            with zipfile.ZipFile(zp, "w", zipfile.ZIP_DEFLATED) as z:
                for f in p.rglob("*"):
                    if f.is_file():
                        z.write(f, f.relative_to(p))
            shutil.rmtree(p, ignore_errors=True)
            p = zp
        if not p.is_file():
            return {k: v for k, v in res.items() if k != "path"}
        if p.parent != dl.resolve():
            q = dl / f"{os.urandom(4).hex()}_{p.name}"
            os.replace(p, q)
            name, p = p.name, q
        else:
            name = p.name
        user = (self._current_user() or {}).get("username", "")
        tok = self._server.add_download(p, name, user)
        return {**{k: v for k, v in res.items() if k != "path"}, "download": "/download/" + tok, "filename": name}

    def _pick_folder(self):
        if paths.is_server():
            d = paths.data_dir() / "downloads"
            d.mkdir(exist_ok=True)
            return d
        if self._window:
            import webview
            res = self._window.create_file_dialog(webview.FOLDER_DIALOG)
            if not res:
                return None
            return Path(res[0] if isinstance(res, (list, tuple)) else res)
        d = paths.data_dir() / "exports"
        d.mkdir(exist_ok=True)
        return d

    def _export_plain(self, src, name):
        """فایل‌های رمزشده‌ی داده را در پوشه‌ی انتخابی کاربر به‌صورت ساده ذخیره می‌کند."""
        from . import atrest
        dest = self._pick_folder()
        if dest is None:
            return {"cancelled": True}
        dest = dest / name
        n = atrest.export_dir(src, dest)
        self._store.add_history("export", name, "ok", f"{n} فایل", "", str(dest))
        return {"path": str(dest), "count": n}

    @_safe
    def export_run_files(self, path):
        p = paths.inside(path, [paths.runs_dir()])
        if p is None:
            raise ConnectorError("پوشه‌ی اجرا پیدا نشد.")
        if p.is_file():
            p = p.parent
        if p == paths.runs_dir().resolve() or not p.is_dir():
            raise ConnectorError("پوشه‌ی اجرا پیدا نشد.")
        return self._export_plain(p, p.name)

    @_safe
    def export_logs(self):
        return self._export_plain(paths.logs_dir(), "AutoKRP-logs-" + time.strftime("%Y%m%d-%H%M%S"))

    @_safe
    def open_folder(self, path=None):
        if path and paths.inside(path, [paths.runs_dir()]) is not None:
            return self.export_run_files(str(path))   # فایل‌های اجرا رمزشده‌اند؛ خروجی ساده با انتخاب پوشه
        if paths.is_server():
            raise ConnectorError("در حالت سرور باز کردن پوشه‌ها روی دیسک سرور ممکن نیست.")
        u = self._current_user()
        if u and u.get("role") != "admin":
            raise ConnectorError("باز کردن پوشه‌های برنامه فقط برای ادمین است.")
        p = Path(path) if path else paths.data_dir()
        if str(path or "").startswith(("\\\\", "//")):
            raise ConnectorError("مسیر شبکه‌ای پشتیبانی نمی‌شود.")
        if p.is_file():
            p = p.parent
        if not p.exists():
            raise ConnectorError(f"پوشه پیدا نشد: {p}")
        if sys.platform == "win32":
            os.startfile(str(p))  # noqa
        else:
            subprocess.Popen(["xdg-open", str(p)])
        return {}

    @_safe
    def pick_csv(self):
        if paths.is_server():
            return {"web_upload": True}
        if not self._window:
            raise ConnectorError("انتخاب فایل در این محیط در دسترس نیست؛ مسیر را دستی وارد کنید.")
        import webview
        res = self._window.create_file_dialog(webview.OPEN_DIALOG, allow_multiple=False,
                                              file_types=("CSV (*.csv)", "All files (*.*)"))
        if not res:
            return {"path": ""}
        return {"path": res[0] if isinstance(res, (list, tuple)) else res}
