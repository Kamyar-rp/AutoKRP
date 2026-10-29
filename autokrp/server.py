"""
حالت سرور: وب چندکاربره روی HTTPS. بدون DPAPI.

- کلید اصلی تصادفی همه‌ی داده‌ها را رمز می‌کند و برای هر کاربر با رمز خودش wrap می‌شود (serverauth).
- Store/Settings/Vault/Worker/Api تنها پس از اولین ورود موفق ساخته می‌شوند (پیش از آن کلید در دست نیست).
- راه‌اندازی اولیه (ساخت اولین ادمین) و پاک‌سازی کامل فقط از خود سیستم سرور (localhost).
- نشست با کوکی امن (HttpOnly, Secure, SameSite=Strict) + توکن CSRF در هدر برای /api و /upload.
- فهرست شبکه‌های مجاز، قفل پس از چند تلاش ناموفق، پایان نشست پس از بی‌کاری؛ همه از لحظه‌ی روشن شدن.
- انتخاب فایل با آپلود (رمزشده روی دیسک)، گرفتن خروجی با دانلود یک‌بارمصرف و کوتاه‌عمر برای همان کاربر.
"""
import hashlib
import hmac
import html
import http.server
import ipaddress
import json
import logging
import os
import re
import secrets
import socket
import socketserver
import ssl
import threading
import time
import urllib.parse
from pathlib import Path

from . import atrest, certs, paths, serverauth

log = logging.getLogger(__name__)
COOKIE = "akrp_sid"
PRE_COOKIE = "akrp_pre"       # توکن پیش از ورود (CSRF صفحه‌ی ورود؛ double-submit)
CSRF_HEADER = "X-AKRP-CSRF"
TYPES = {".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8", ".js": "application/javascript; charset=utf-8",
         ".woff2": "font/woff2", ".woff": "font/woff", ".ttf": "font/ttf", ".svg": "image/svg+xml", ".png": "image/png",
         ".ico": "image/x-icon", ".txt": "text/plain; charset=utf-8", ".json": "application/json", ".wav": "audio/wav"}
MAX_JSON = 8 * 1024 * 1024
MAX_AUTH = 16 * 1024          # بدنه‌ی درخواست‌های پیش از ورود
MAX_UPLOAD = 64 * 1024 * 1024
# درخواست‌های بزرگ (آپلود، تکه‌ی انتقال فایل) کل بدنه را در حافظه نگه می‌دارند: سقف هم‌زمانی جدا تا چند آپلود
# هم‌زمان حافظه‌ی سرور را پر نکنند (بقیه منتظر می‌مانند یا 503 می‌گیرند)
BIG_BODY = 1024 * 1024
_BIG_SEM = threading.BoundedSemaphore(3)
DOWNLOAD_TTL = 600            # ثانیه
LOCAL_IPS = {"127.0.0.1", "::1", "::ffff:127.0.0.1"}
SEC_HEADERS = [
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "no-referrer"),
    ("Cache-Control", "no-store"),
    ("Strict-Transport-Security", "max-age=31536000"),
    ("Cross-Origin-Opener-Policy", "same-origin"),
    # بدون 'unsafe-inline' برای اسکریپت: هیچ اسکریپت درون‌خطی‌ای اجرا نمی‌شود (XSS تزریق‌شده بی‌اثر است).
    # استایل: فقط فایل‌های خود برنامه؛ ویژگی style روی عناصر (برای چیدمان) مجاز است، تگ <style> تزریق‌شده نه.
    ("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; style-src-elem 'self'; "
                                "style-src-attr 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; media-src 'self' blob:; "
                                "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'"),
]


def _eq(a, b):
    """مقایسه‌ی زمان‌ثابت توکن‌ها (هدر ممکن است کاراکتر غیر ASCII داشته باشد)."""
    return hmac.compare_digest(str(a or "").encode("utf-8", "replace"), str(b or "").encode("utf-8", "replace"))


def is_local(ip):
    return ip in LOCAL_IPS


_CTRL = re.compile(r"[\x00-\x1f\x7f-\x9f\u200b-\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069]")


def _log_safe(v, n=64):
    """متن ورودی کاربر برای لاگ و تاریخچه: بدون خط تازه و نویسه‌ی کنترلی/جهت (جعل خط لاگ)، کوتاه‌شده."""
    return _CTRL.sub("?", str(v or ""))[:n]


class _Ctx:
    """وضعیت مشترک سرور (یک نمونه)."""
    def __init__(self, demo=False):
        self.demo = demo
        self.lock = threading.RLock()
        self.sessions = {}            # sid -> {user, csrf, created, seen, ip, pid}
        self.fails = {}               # ip -> [count, until]
        self.api = None
        self.worker = None
        self.settings = None
        self.vault = None
        self.store = None
        self.downloads = {}           # token -> (path, filename, ts, username)
        self.master = None            # کلید اصلی (فقط در حافظه؛ برای ساخت کاربر و تغییر رمز)
        self.cfg = serverauth.config()
        self.started_at = time.time()

    def reload_cfg(self):
        self.cfg = serverauth.config()

    def reload_tls(self):
        """گواهی تازه بدون اجرای دوباره: اتصال‌های بعدی با گواهی جدید؛ نشست‌ها باز می‌مانند."""
        if getattr(self, "tls", None) is not None:
            certs.load_into(self.tls)

    # -------------------------------------------------- شبکه‌ی مجاز (از لحظه‌ی روشن شدن، بدون نیاز به کلید)
    def ip_allowed(self, ip):
        if is_local(ip):
            return True
        nets = self.cfg.get("allowed_networks") or []
        if not nets:
            return True
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False
        for n in nets:
            try:
                if a in ipaddress.ip_network(str(n).strip(), strict=False):
                    return True
            except ValueError:
                continue
        return False

    # -------------------------------------------------- قفل پس از تلاش ناموفق (بر اساس IP و نام کاربری)
    # هر تلاش پیش از بررسی رمز شمرده می‌شود (تلاش‌های هم‌زمان هم حساب می‌شوند) و ورود موفق فقط شمارنده‌ی
    # همان حساب را پاک می‌کند، نه شمارنده‌ی IP (ورود با حساب خود، حدس رمز حساب دیگر را آزاد نمی‌کند).
    # تلاش از خود سیستم سرور مشمول قفل حساب نیست تا ادمین همیشه از localhost وارد شود.
    def _win(self):
        return int(self.cfg.get("lockout_minutes") or 15) * 60

    def _locked(self, key, now):
        rec = self.fails.get(key)
        return int(rec[1] - now) + 1 if rec and rec[1] > now else 0

    # 1.27.7: قفل روی جفت «IP + نام کاربری» (رفتار عادی برای کاربر)، سقف بالاتر برای خود IP (حدس روی چند حساب)
    # و سقف خیلی بالاتر برای خود حساب (حمله‌ی پخش از چند IP). قبلاً شمارنده‌ی حساب با همان سقف عادی بود و هر کسی با
    # چند رمز غلط از هر جایی حساب ادمین را قفل می‌کرد.
    IP_FACTOR, USER_FACTOR = 3, 10

    def _keys(self, ip, name):
        n = (name or "").strip().lower()
        keys = [(f"ip:{ip}", self.IP_FACTOR)]
        if n:
            keys.append((f"pair:{ip}|{n}", 1))
            if not is_local(ip):
                keys.append((f"user:{n}", self.USER_FACTOR))
        return keys

    def begin_attempt(self, ip, name):
        """خروجی: ثانیه‌های انتظار (قفل است) یا ۰ (تلاش ثبت شد)."""
        th, now, win = int(self.cfg.get("lockout_threshold") or 0), time.time(), self._win()
        keys = self._keys(ip, name)
        locked_user = None
        with self.lock:
            wait = max(self._locked(k, now) for k, _ in keys)
            if wait:
                return wait
            for k, f in keys:
                rec = self.fails.get(k) or [0, 0.0, 0.0]          # [شمار، قفل تا، آخرین تلاش]
                if now - rec[2] > win:
                    rec[0] = 0
                rec[0] += 1
                rec[2] = now
                if th and rec[0] >= th * f:
                    rec[1], rec[0] = now + win, 0
                    if k.startswith("user:"):
                        locked_user = k[5:]
                self.fails[k] = rec
        if locked_user and self.api is not None:
            try:
                msg = f"حساب «{locked_user}» به‌خاطر تلاش‌های ناموفق زیاد از چند آدرس {win // 60} دقیقه قفل شد (آخرین: {ip})"
                self.api._worker.emit("warn", msg, "security")
                self.api._store.add_history("security", "ورود", "warn", msg, user="")
            except Exception:
                log.exception("lockout notify")
        return 0

    def end_attempt(self, ip, name, ok):
        if not ok:
            return
        n = (name or "").strip().lower()
        with self.lock:
            rec = self.fails.get(f"ip:{ip}")
            if rec and rec[0] > 0:
                rec[0] -= 1                                     # همین تلاش موفق بود
            self.fails.pop(f"pair:{ip}|{n}", None)
            rec = self.fails.get(f"user:{n}")
            if rec and rec[1] <= time.time():
                self.fails.pop(f"user:{n}", None)              # حساب قفل‌شده با ورود موفق از جای دیگر باز نمی‌شود

    def purge_fails(self):
        now, win = time.time(), self._win()
        with self.lock:
            for k, r in list(self.fails.items()):
                if r[1] < now and now - r[2] > win:
                    self.fails.pop(k, None)

    # -------------------------------------------------- نشست‌ها
    @staticmethod
    def _pid(sid):
        """شناسه‌ی عمومی نشست برای فهرست ادمین (خود توکن نشست هرگز نمایش داده نمی‌شود)."""
        return hashlib.sha256(sid.encode()).hexdigest()[:16]

    def new_session(self, user, ip):
        sid, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        with self.lock:
            self.sessions[sid] = {"user": user, "csrf": csrf, "created": time.time(), "seen": time.time(), "ip": ip,
                                  "pid": self._pid(sid)}
        return sid, csrf

    def get_session(self, sid, touch=True):
        with self.lock:
            s = self.sessions.get(sid)
            if not s:
                return None
            idle = int(self.cfg.get("session_timeout_minutes") or 0) * 60
            if idle and time.time() - s["seen"] > idle:
                self.sessions.pop(sid, None)
                return None
            try:
                rec = serverauth.find(serverauth.load(), s["user"]["username"])
            except serverauth.AuthError:
                # fail-closed: وقتی وضعیت فعلی حساب قابل تأیید نیست، نشست با دسترسی قبلی نمی‌ماند
                log.error("فایل کاربران سرور خوانده نشد؛ نشست %s بسته شد", s["user"].get("username"))
                rec = None
            if not rec or rec.get("disabled"):          # حذف یا غیرفعال شد: نشست بسته می‌شود
                self.sessions.pop(sid, None)
                return None
            if self._ad_expired(s, rec):
                self.sessions.pop(sid, None)
                return None
            s["user"] = {k: rec.get(k) for k in ("username", "role", "tools", "disabled", "shared_devices", "perms_v", "source")}
            if touch:
                s["seen"] = time.time()
            return s

    def _ad_expired(self, s, rec):
        """1.26.2: کاربر AD بدون رمزش دوباره با AD بررسی نمی‌شود (غیرفعال شدن یا حذف از گروه در AD دیده نمی‌شود)؛
        پس نشستش عمر مطلق دارد و بعد از آن باید دوباره وارد شود (۰ = بدون سقف)."""
        if (rec or {}).get("source") != "ad":
            return False
        try:
            hours = float(self.cfg.get("ad_session_hours", 12) or 0)
        except (TypeError, ValueError):
            hours = 12.0
        return bool(hours) and time.time() - s["created"] > hours * 3600

    def drop_session(self, sid=None, pid=None, username=None, keep=None):
        with self.lock:
            for k in list(self.sessions):
                s = self.sessions[k]
                if k == keep:
                    continue
                if k == sid or (pid and s["pid"] == pid) or (username and s["user"]["username"].lower() == username.lower()):
                    self.sessions.pop(k, None)

    def active_sessions(self):
        with self.lock:
            return [{"id": s["pid"], "username": s["user"]["username"], "role": s["user"]["role"], "ip": s["ip"],
                     "since": s["created"], "seen": s["seen"]} for s in self.sessions.values()]

    # -------------------------------------------------- راه‌اندازی پس از ورود / خاموش کردن
    def bring_up(self, master):
        """اولین ورود پس از روشن شدن سرور: کلیدها باز و اجزا ساخته می‌شوند."""
        with self.lock:
            if self.api is not None:
                return
            data_key, vault_key = serverauth.subkeys(master)
            atrest.set_key(data_key)
            from .settings import Settings
            from .store import Store
            from .vault import Vault
            from .worker import Worker
            from .api import Api
            self.settings = Settings()
            self.vault = Vault(self.settings)
            self.settings.attach_vault(self.vault)
            self.vault.open_server(vault_key)
            try:
                self.store = Store()
            except Exception:
                self.settings = self.vault = None   # ورود بعدی دوباره تلاش می‌کند
                atrest.forget()
                raise
            self.worker = Worker(self.settings, self.store, demo=self.demo)
            self.api = Api(self.settings, self.store, self.worker, demo=self.demo, vault=self.vault)
            self.api._server = self
            self.master = bytes(master)
            self.worker.start()
            from .atrest import flush_pending_logs
            flush_pending_logs()
            log.info("سرور پس از اولین ورود راه‌اندازی شد")

    def tear_down(self):
        """«قفل کامل»: کارها متوقف، کلیدها از حافظه پاک، همه‌ی نشست‌ها بسته. ورود بعدی دوباره راه‌اندازی می‌کند."""
        with self.lock:
            self.sessions.clear()
            if self.worker:
                try:
                    self.worker.stop(wait=10)
                except Exception:
                    pass
            if self.store:
                try:
                    self.store.close()
                except Exception:
                    pass
            if self.vault:
                self.vault.forget()
            self.api = self.worker = self.store = self.vault = self.settings = None
            self.master = None
            self._purge_downloads(all_=True)
            atrest.forget()

    # -------------------------------------------------- دانلود (یک‌بارمصرف، فقط برای همان کاربر)
    def add_download(self, path, filename, username):
        tok = secrets.token_urlsafe(24)
        with self.lock:
            self.downloads[tok] = (str(path), filename, time.time(), username)
        return tok

    def take_download(self, tok, username):
        with self.lock:
            rec = self.downloads.get(tok)
            if not rec or rec[3] != username or time.time() - rec[2] > DOWNLOAD_TTL:
                return None
            self.downloads.pop(tok, None)
            return rec

    def _purge_downloads(self, all_=False):
        with self.lock:
            for tok, rec in list(self.downloads.items()):
                if all_ or time.time() - rec[2] > DOWNLOAD_TTL:
                    self.downloads.pop(tok, None)
                    _remove(Path(rec[0]))
        d = paths.data_dir() / "downloads"
        if d.exists():
            live = {Path(r[0]).resolve() for r in self.downloads.values()}
            for f in d.iterdir():
                try:
                    if f.resolve() not in live and (all_ or time.time() - f.stat().st_mtime > DOWNLOAD_TTL):
                        _remove(f)
                except OSError:
                    pass

    def housekeeping(self):
        """هر دقیقه: دانلودها و نشست‌های منقضی، آپلودهای قدیمی (بیش از یک روز)."""
        while True:
            time.sleep(60)
            try:
                self._purge_downloads()
                self.purge_fails()
                idle = int(self.cfg.get("session_timeout_minutes") or 0) * 60
                with self.lock:
                    for k, s in list(self.sessions.items()):
                        if (idle and time.time() - s["seen"] > idle) or self._ad_expired(s, s["user"]):
                            self.sessions.pop(k, None)
                up = paths.data_dir() / "uploads"
                if up.exists():
                    for f in up.iterdir():
                        if time.time() - f.stat().st_mtime > 86400:
                            _remove(f)
            except Exception:
                log.exception("housekeeping")


def _remove(p):
    from . import wipe
    try:
        if p.is_dir():
            wipe.wipe_dir(p)
        elif p.exists():
            wipe.overwrite(p)
            p.unlink()
    except OSError:
        pass


CTX = None


def _ui_file(rel):
    # بررسی متنی پیش از هر دسترسی به دیسک: مسیر شبکه‌ای ویندوز (\\host\share)، درایو و «..» رد می‌شوند؛
    # وگرنه resolve روی مسیر UNC به سیستم دیگری وصل می‌شود (و ممکن است هش NTLM بفرستد)
    if not rel or "\\" in rel or ":" in rel or rel.startswith("/") or any(p in ("", ".", "..") for p in rel.split("/")):
        return None
    if not re.fullmatch(r"[A-Za-z0-9._/-]+", rel):
        return None
    root = paths.ui_dir().resolve()
    f = (root / rel).resolve()
    if root not in f.parents or not f.is_file():
        return None
    return f


LOGIN_HTML = """<!doctype html><html lang="fa" dir="rtl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><meta name="akrp-pre" content="__PRE__"><title>AutoKRP</title>
<link rel="stylesheet" href="/login.css"></head>
<body><form class="card" id="f"><h1 id="t">ورود</h1><p class="sub" id="s">AutoKRP — ابزار خودکارسازی پاسخ امنیتی</p>
<div id="fields"></div><button type="submit" id="btn">ورود</button><div class="err" id="e"></div><button type="button" class="link" id="fl" hidden>رمز را فراموش کرده‌ام</button>
<div class="lang"><button type="button" id="lang" data-no-i18n>English</button></div></form>
<script src="/i18n_en.js"></script><script src="/i18n.js"></script><script src="/login.js"></script></body></html>"""

LOGIN_CSS = """:root{color-scheme:dark}body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0b1622;color:#e6edf6;font-family:Tahoma,system-ui,sans-serif;padding:16px;box-sizing:border-box}
.card{background:#101c2a;border:1px solid #223040;border-radius:16px;padding:28px 30px;width:100%;max-width:360px;box-sizing:border-box;box-shadow:0 20px 60px #0007}
h1{margin:0 0 4px;font-size:22px}.sub{color:#8aa0b4;font-size:13px;margin:0 0 18px;line-height:1.8}
label{display:block;font-size:13px;margin:12px 0 5px;color:#b9c7d6}
input,textarea{width:100%;box-sizing:border-box;font-family:inherit;padding:10px;border-radius:9px;border:1px solid #2a3a4c;background:#0b1622;color:#e6edf6;direction:ltr;font-size:15px}
button{width:100%;margin-top:18px;padding:11px;border:0;border-radius:9px;background:#2f9e8f;color:#04120f;font-weight:700;cursor:pointer;font-size:15px}
button:disabled{opacity:.6}.lang{text-align:center;margin-top:10px}.lang button{width:auto;background:none;color:#8aa0b4;font-weight:400;font-size:13px;margin:0;padding:4px 10px}.err{color:#ff8080;font-size:13px;margin-top:12px;min-height:18px;line-height:1.7}
.link{display:block;text-align:center;margin-top:12px;color:#8aa0b4;font-size:13px;cursor:pointer;background:none;width:auto;padding:0;font-weight:400}
.code{direction:ltr;font-family:Consolas,monospace;font-size:17px;letter-spacing:1px;text-align:center;background:#0b1622;border:1px dashed #2f9e8f;border-radius:9px;padding:12px;word-break:break-all;margin:10px 0}
input[type=file]{padding:6px;font-size:13px}.ok{color:#7fd6c9;font-size:13px;line-height:1.8}"""

LOGIN_JS = """let MODE="login";
// زبان: همان انتخاب این مرورگر در برنامه (localStorage)؛ دکمه‌ی پایین صفحه عوضش می‌کند
const LANG=(()=>{try{return localStorage.getItem("akrp_lang")==="fa"?"fa":"en";}catch(e){return "en";}})();
if(window.I18N)I18N.apply(LANG);
document.getElementById("lang").textContent=LANG==="en"?"فارسی":"English";
document.getElementById("lang").addEventListener("click",()=>{try{localStorage.setItem("akrp_lang",LANG==="en"?"fa":"en");}catch(e){}location.reload();});
const PRE=(document.querySelector('meta[name="akrp-pre"]')||{}).content||"";
async function j(u,b){const r=await fetch(u,{method:"POST",headers:{"Content-Type":"application/json","%s":PRE},credentials:"same-origin",body:JSON.stringify(b||{})});
 try{return await r.json();}catch(e){return{ok:false,error:"پاسخ نامعتبر از سرور"};}}
function fields(){const F=document.getElementById("fields"),B=document.getElementById("btn");
 if(MODE==="remote"){F.innerHTML=`<p class="sub">سرور هنوز راه‌اندازی نشده است. اولین حساب ادمین فقط از خود سیستم سرور ساخته می‌شود: روی همان سیستم <b dir="ltr">https://localhost</b> را باز کنید.</p>`;B.hidden=true;return;}
 F.innerHTML=MODE==="setup"
 ?`<p class="sub">اولین راه‌اندازی سرور: حساب ادمین بسازید.</p><label>نام کاربری ادمین</label><input id="u" value="admin" autocomplete="username"><label>رمز</label><input id="p" type="password" autocomplete="new-password"><label>تکرار رمز</label><input id="p2" type="password" autocomplete="new-password">`
 :MODE==="recover"
 ?`<p class="sub">رمز ادمین را با کد بازیابی عوض کنید. اگر کد بازیابی ندارید، تنها راه پاک کردن پوشه‌ی داده‌ی سرور و راه‌اندازی دوباره است (همه‌چیز پاک می‌شود).</p><label>نام کاربری ادمین</label><input id="u" value="admin" autocomplete="username"><label>کد بازیابی (یا فایل آن)</label><textarea id="c" rows="2" dir="ltr" placeholder="XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX"></textarea><input type="file" id="cf" accept=".txt,text/plain"><label>رمز تازه</label><input id="p" type="password" autocomplete="new-password"><label>تکرار رمز تازه</label><input id="p2" type="password" autocomplete="new-password">`
 :`<label>نام کاربری</label><input id="u" autocomplete="username" autofocus><label>رمز</label><input id="p" type="password" autocomplete="current-password">`;
 document.getElementById("t").textContent=MODE==="setup"?"راه‌اندازی سرور":MODE==="recover"?"بازیابی رمز":"ورود";
 B.textContent=MODE==="setup"?"ساخت ادمین و ورود":MODE==="recover"?"عوض کردن رمز":"ورود";
 const cf=document.getElementById("cf");if(cf)cf.onchange=()=>{const f=cf.files[0];if(!f)return;if(f.size>65536){document.getElementById("e").textContent="فایل کد بازیابی نیست.";return;}
   const rd=new FileReader();rd.onload=()=>{document.getElementById("c").value=String(rd.result||"");};rd.readAsText(f);};
 const L=document.getElementById("fl");if(L){L.hidden=MODE!=="login"&&MODE!=="recover";L.textContent=MODE==="recover"?"بازگشت به ورود":"رمز را فراموش کرده‌ام";}}
function showCode(r){const F=document.getElementById("fields"),B=document.getElementById("btn");
 F.innerHTML=`<p class="ok">رمز عوض شد. کد بازیابی قبلی دیگر کار نمی‌کند؛ این کد تازه را همین حالا ذخیره کنید (دوباره نمایش داده نمی‌شود):</p><div class="code" id="cc"></div><button type="button" id="dl">ذخیره‌ی فایل کد</button>`;
 document.getElementById("cc").textContent=r.code;document.getElementById("t").textContent="کد بازیابی تازه";
 document.getElementById("dl").onclick=()=>{const a=document.createElement("a");a.href=URL.createObjectURL(new Blob([r.file],{type:"text/plain;charset=utf-8"}));a.download=r.filename||"AutoKRP-recovery-code.txt";document.body.appendChild(a);a.click();a.remove();};
 MODE="saved";B.textContent="ذخیره کردم؛ رفتن به ورود";const L=document.getElementById("fl");if(L)L.hidden=true;}
(async()=>{const st=await j("/auth/status");MODE=st.initialized?"login":(st.local?"setup":"remote");fields();})();
document.getElementById("fl").addEventListener("click",()=>{MODE=MODE==="recover"?"login":"recover";document.getElementById("e").textContent="";fields();});
document.getElementById("f").addEventListener("submit",async(ev)=>{ev.preventDefault();const e=document.getElementById("e"),B=document.getElementById("btn");e.textContent="";
 if(MODE==="saved"){location.href="/";return;}
 const u=document.getElementById("u").value.trim(),p=document.getElementById("p").value;B.disabled=true;
 try{if(MODE==="recover"){if(p!==document.getElementById("p2").value){e.textContent="رمز و تکرار آن یکی نیستند.";return;}
   const r=await j("/auth/recover",{username:u,code:document.getElementById("c").value,password:p});if(!r.ok){e.textContent=r.error;return;}showCode(r);return;}
  if(MODE==="setup"){if(p!==document.getElementById("p2").value){e.textContent="رمز و تکرار آن یکی نیستند.";return;}
   const r=await j("/auth/setup",{username:u,password:p});if(!r.ok){e.textContent=r.error;return;}location.href="/";return;}
 const r=await j("/auth/login",{username:u,password:p});if(!r.ok){e.textContent=r.error;document.getElementById("p").select();return;}location.href="/";}
 finally{B.disabled=false;}});
""" % CSRF_HEADER

# shim index.html: window.pywebview.api → POST /api/<m> با توکن CSRF (توکن و نام کاربر از meta؛ بدون اسکریپت درون‌خطی)
SHIM_JS = """(function(){var m=function(n){var e=document.querySelector('meta[name="'+n+'"]');return e?e.content:"";};
var CSRF=m("akrp-csrf");
window.__AKRP_WEB__={csrf:CSRF,user:m("akrp-user")};
window.pywebview={api:new Proxy({},{get:function(_,name){return function(){var args=[].slice.call(arguments);
 return fetch("/api/"+name,{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json","%s":CSRF},body:JSON.stringify(args)})
  .then(function(r){if(r.status===401){location.href="/login";return{ok:false,error:"نشست منقضی شد"};}return r.json();});};}})};
window.dispatchEvent(new Event("pywebviewready"));})();
""" % CSRF_HEADER


class _Deadlines:
    """سقف زمانی کل برای دریافت درخواست (نه هر بار خواندن). timeout سوکت برای هر recv جداست؛ کلاینتی که هر
    چند ثانیه یک بایت (از دست‌دادن TLS، هدر یا بدنه) بفرستد بدون این برای همیشه یک اتصال و یک ترد را نگه می‌دارد
    و با چند IP کل سقف اتصال‌ها پر می‌شود (slowloris). بعد از رسیدن مهلت، سوکت از ترد دیگری shutdown می‌شود تا
    خواندنِ در انتظار برگردد. هنگام پردازش و ارسال پاسخ (long-poll، دانلود بزرگ) مهلتی نیست."""

    def __init__(self):
        self._lk = threading.Lock()
        self._d = {}                       # id(handler) → (مهلت، سوکت)
        self._t = None

    def arm(self, h, secs):
        with self._lk:
            self._d[id(h)] = (time.monotonic() + secs, h.connection)
            if self._t is None:
                self._t = threading.Thread(target=self._reap, name="http-deadline", daemon=True)
                self._t.start()

    def disarm(self, h):
        with self._lk:
            self._d.pop(id(h), None)

    def _reap(self):
        while True:
            time.sleep(1)
            now = time.monotonic()
            with self._lk:
                late = [(k, sk) for k, (dl, sk) in self._d.items() if dl < now]
                for k, _ in late:
                    self._d.pop(k, None)
            for _, sk in late:
                try:
                    socket.socket.shutdown(sk, socket.SHUT_RDWR)   # سطح سیستم‌عامل؛ خواندن در ترد اتصال برمی‌گردد
                except OSError:
                    pass


DEADLINES = _Deadlines()
HEADER_SECS = 30                 # دست‌دادن TLS + خط درخواست + هدرها (و انتظار اتصال keep-alive بی‌کار)
BODY_SECS = 30                   # بدنه: این مقدار + زمان لازم با حداقل سرعت BODY_MIN_RATE
BODY_MIN_RATE = 32 * 1024


class Handler(http.server.BaseHTTPRequestHandler):
    timeout = 30                 # اتصال بی‌کار یا کند (هدر/بدنه‌ی ناقص) بعد از ۳۰ ثانیه بسته می‌شود (برای هر خواندن)

    def handle_one_request(self):
        DEADLINES.arm(self, HEADER_SECS)        # مهلت کل تا پایان هدرها (نه برای هر خواندن)
        try:
            super().handle_one_request()
        finally:
            DEADLINES.disarm(self)

    def parse_request(self):
        ok = super().parse_request()
        DEADLINES.disarm(self)                  # هدرها کامل رسید؛ بدنه مهلت جدا دارد، پاسخ مهلت ندارد
        return ok
    protocol_version = "HTTP/1.1"
    server_version = "AutoKRP"
    sys_version = ""

    def log_message(self, *a):
        pass

    # -------------------------------------------------- helpers
    def _ip(self):
        return self.client_address[0]

    def _cookies(self):
        out = {}
        for part in self.headers.get("Cookie", "").split(";"):
            if "=" in part:
                k, v = part.split("=", 1)
                out[k.strip()] = v.strip()
        return out

    def _read(self, limit):
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            n = -1
        if n < 0 or n > limit:
            self.close_connection = True
            return None
        if not n:
            return b""
        DEADLINES.arm(self, BODY_SECS + n / BODY_MIN_RATE)
        try:
            data = self.rfile.read(n)
        finally:
            DEADLINES.disarm(self)
        if len(data) != n:                      # اتصال قطع شد (یا مهلت تمام شد) پیش از رسیدن کل بدنه
            self.close_connection = True
            return None
        return data

    def _json_body(self):
        raw = getattr(self, "_body", None)
        if raw is None:
            return None
        try:
            return json.loads(raw.decode("utf-8")) if raw else {}
        except (ValueError, UnicodeDecodeError, RecursionError):   # RecursionError: JSON بیش از حد تودرتو
            return None

    def _send(self, code, body=b"", ctype="application/octet-stream", extra=None, style_nonce=None):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in SEC_HEADERS:
            if style_nonce and k == "Content-Security-Policy":
                # ترمینال (xterm.js) اندازه‌ی نویسه‌ها را با تگ <style> می‌سازد: فقط با nonce همین پاسخ
                v = v.replace("style-src-elem 'self'", f"style-src-elem 'self' 'nonce-{style_nonce}'")
            self.send_header(k, v)
        for k, v in (extra or []):
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, obj, code=200, extra=None):
        self._send(code, json.dumps(obj, ensure_ascii=False, default=str), "application/json; charset=utf-8", extra)

    def _session(self, touch=True):
        sid = self._cookies().get(COOKIE)
        return (sid, CTX.get_session(sid, touch)) if sid else (None, None)

    def _same_origin(self):
        """درخواست‌های POST فقط از همین سایت (کمکی، کنار SameSite و CSRF)."""
        origin = self.headers.get("Origin")
        if not origin:
            return True
        host = self.headers.get("Host", "")
        return urllib.parse.urlparse(origin).netloc == host

    def _cookie(self, sid):
        return [("Set-Cookie", f"{COOKIE}={sid}; HttpOnly; Secure; SameSite=Strict; Path=/")]

    # -------------------------------------------------- GET
    def do_GET(self):
        if not CTX.ip_allowed(self._ip()):
            return self._send(403, "دسترسی از این شبکه مجاز نیست.", "text/plain; charset=utf-8")
        path = urllib.parse.urlparse(self.path).path
        if path in ("/login", "/login/"):
            pre = secrets.token_urlsafe(32)
            return self._send(200, LOGIN_HTML.replace("__PRE__", pre), "text/html; charset=utf-8",
                              extra=[("Set-Cookie", f"{PRE_COOKIE}={pre}; HttpOnly; Secure; SameSite=Strict; Path=/auth; Max-Age=3600")])
        if path == "/login.css":
            return self._send(200, LOGIN_CSS, TYPES[".css"])
        if path == "/login.js":
            return self._send(200, LOGIN_JS, TYPES[".js"])
        if path == "/shim.js":
            return self._send(200, SHIM_JS, TYPES[".js"])
        sid, sess = self._session()
        if path in ("/", "/index.html"):
            if not sess or CTX.api is None:
                return self._send(302, b"", "text/plain", extra=[("Location", "/login")])
            data = _ui_file("index.html").read_bytes().decode("utf-8")
            nonce = secrets.token_urlsafe(18)
            meta = (f'<meta name="akrp-csrf" content="{html.escape(sess["csrf"])}">'
                    f'<meta name="akrp-user" content="{html.escape(sess["user"]["username"])}">'
                    f'<meta name="akrp-style-nonce" content="{nonce}">')
            data = data.replace("</head>", meta + "</head>", 1).replace('<script src="app.js">', '<script src="/shim.js"></script><script src="app.js">', 1)
            return self._send(200, data, "text/html; charset=utf-8", style_nonce=nonce)
        if path.startswith("/xfer/"):
            if self.command == "HEAD":
                return self._send(405, b"", "text/plain")
            if not sess or CTX.api is None:
                return self._send(302, b"", "text/plain", extra=[("Location", "/login")])
            return self._xfer_stream(path[len("/xfer/"):], sess["user"]["username"])
        if path.startswith("/download/"):
            if self.command == "HEAD":   # HEAD نباید توکن یک‌بارمصرف را مصرف کند
                return self._send(405, b"", "text/plain")
            if not sess:
                return self._send(302, b"", "text/plain", extra=[("Location", "/login")])
            rec = CTX.take_download(path[len("/download/"):], sess["user"]["username"])
            if not rec or not Path(rec[0]).is_file():
                return self._send(404, "فایل پیدا نشد یا منقضی شده است.", "text/plain; charset=utf-8")
            return self._send_file(Path(rec[0]), rec[1])
        rel = path.lstrip("/")
        f = _ui_file(rel) if rel else None
        if f and f.suffix in TYPES and f.name != "index.html":
            return self._send(200, f.read_bytes(), TYPES[f.suffix])
        return self._send(404, "", "text/plain")

    do_HEAD = do_GET

    def _send_file(self, fp, name):
        """1.26.2: فایل دانلود یک‌بارمصرف تکه‌تکه (نه کل فایل در حافظه)؛ بعد از ارسال (یا خطا) حذف می‌شود."""
        try:
            f = open(fp, "rb")
        except OSError:
            _remove(fp)
            return self._send(404, "فایل پیدا نشد یا منقضی شده است.", "text/plain; charset=utf-8")
        try:
            size = os.fstat(f.fileno()).st_size
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(size))
            for k, v in SEC_HEADERS:
                self.send_header(k, v)
            self.send_header("Content-Disposition", f"attachment; filename*=UTF-8''{urllib.parse.quote(name)}")
            self.end_headers()
            while True:
                chunk = f.read(256 * 1024)
                if not chunk:
                    break
                self.wfile.write(chunk)
        except OSError:
            self.close_connection = True
        finally:
            f.close()
            _remove(fp)

    def _xfer_stream(self, tok, username):
        """دانلود جریانی مستقیم از دستگاه (SFTP/SCP/FTP) یا فایل دریافتی TFTP؛ توکن یک‌بارمصرف همان کاربر."""
        res = CTX.api._xfer.stream(tok, username.lower()) if re.fullmatch(r"[0-9a-f]{64}", tok or "") else None
        if not res:
            return self._send(404, "فایل پیدا نشد، منقضی شده یا خواندنش ناموفق بود (جزئیات در فهرست انتقال‌ها).",
                              "text/plain; charset=utf-8")
        name, size, it = res
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        if size is not None:
            self.send_header("Content-Length", str(size))
        else:
            self.close_connection = True
        for k, v in SEC_HEADERS:
            self.send_header(k, v)
        self.send_header("Content-Disposition", f"attachment; filename*=UTF-8''{urllib.parse.quote(name)}")
        self.end_headers()
        try:
            for chunk in it:
                self.wfile.write(chunk)
        except OSError:
            self.close_connection = True
        finally:
            it.close()

    # -------------------------------------------------- POST
    def _reject(self, code, msg):
        """پاسخ بدون خواندن بدنه؛ اتصال بسته می‌شود (بدنه‌ی خوانده‌نشده درخواست بعدی را خراب نکند)."""
        self.close_connection = True
        return self._json({"ok": False, "error": msg}, code)

    def do_POST(self):
        ip = self._ip()
        path = urllib.parse.urlparse(self.path).path
        # همه‌ی بررسی‌های ارزان پیش از خواندن بدنه؛ بدنه‌ی بزرگ فقط از کاربر واردشده و با CSRF درست پذیرفته می‌شود
        if not CTX.ip_allowed(ip):
            return self._reject(403, "دسترسی از این شبکه مجاز نیست.")
        if not self._same_origin():
            return self._reject(403, "درخواست از مبدأ نامعتبر")
        ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        if ctype != ("application/octet-stream" if path == "/upload" else "application/json"):
            return self._reject(415, "نوع محتوای درخواست نامعتبر است")
        if self.headers.get("Transfer-Encoding"):      # فقط Content-Length؛ chunked یا طول متناقض پذیرفته نمی‌شود
            return self._reject(411, "Content-Length لازم است")
        if path == "/upload" or path.startswith("/api/"):
            _, sess = self._session(touch=False)
            if not sess or CTX.api is None:
                return self._reject(401, "نشست منقضی شد")
            if not _eq(self.headers.get(CSRF_HEADER, ""), sess["csrf"]):
                return self._reject(403, "درخواست نامعتبر (CSRF)")
            if path == "/upload" and sess["user"]["role"] == "readonly":
                return self._reject(403, "دسترسی ندارید")
            limit = MAX_UPLOAD if path == "/upload" else MAX_JSON
        else:
            limit = MAX_AUTH
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return self._reject(400, "Content-Length نامعتبر است")
        big = n > BIG_BODY
        if big and not _BIG_SEM.acquire(timeout=30):
            return self._reject(503, "سرور مشغول دریافت فایل‌های دیگر است؛ کمی بعد دوباره تلاش کنید")
        try:
            return self._post_body(path, ip, limit)
        finally:
            self._body = None
            if big:
                _BIG_SEM.release()

    def _post_body(self, path, ip, limit):
        self._body = self._read(limit)
        if self._body is None:
            return self._reject(413, "درخواست بیش از حد بزرگ است")
        if path == "/auth/status":
            return self._json({"mode": "server", "initialized": serverauth.exists(), "local": is_local(ip)})
        if path in ("/auth/setup", "/auth/login", "/auth/recover"):
            pre = self._cookies().get(PRE_COOKIE, "")
            if not pre or not _eq(pre, self.headers.get(CSRF_HEADER, "")):
                return self._json({"ok": False, "error": "صفحه‌ی ورود منقضی شده است؛ صفحه را دوباره باز کنید."}, 403)
            return {"/auth/setup": self._setup, "/auth/login": self._login, "/auth/recover": self._recover}[path]()
        if path == "/auth/logout":
            sid, sess = self._session(touch=False)
            if sess and not _eq(sess["csrf"], self.headers.get(CSRF_HEADER, "")):
                return self._json({"ok": False, "error": "درخواست نامعتبر (CSRF)"}, 403)
            if sid:
                if sess and CTX.api is not None:     # ترمینال‌ها و اتصال‌های انتقال فایل همین کاربر
                    u = sess["user"]["username"].lower()
                    CTX.api._term.close_all(u)
                    CTX.api._xfer.close_all(u)
                CTX.drop_session(sid=sid)
            return self._json({"ok": True}, extra=[("Set-Cookie", f"{COOKIE}=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0")])
        if path == "/upload":
            return self._upload()
        if path.startswith("/api/"):
            return self._api(path[len("/api/"):])
        return self._json({"ok": False, "error": "مسیر نامعتبر"}, 404)

    def _setup(self):
        if serverauth.exists():
            return self._json({"ok": False, "error": "سرور از قبل راه‌اندازی شده است."})
        if not is_local(self._ip()):
            return self._json({"ok": False, "error": "راه‌اندازی اولیه فقط از خود سیستم سرور ممکن است."}, 403)
        b = self._json_body()
        b = b if isinstance(b, dict) else {}
        name = str(b.get("username") or "").strip()
        try:
            master, data = serverauth.create_server(name, str(b.get("password") or ""))
        except serverauth.AuthError as e:
            return self._json({"ok": False, "error": str(e)})
        CTX.reload_cfg()
        try:
            CTX.bring_up(master)
        except Exception as e:  # noqa — مثلاً MySQL در دسترس نیست
            log.error("bring_up failed: %s", e)
            return self._json({"ok": False, "error": f"راه‌اندازی ناموفق: {e}"}, 503)
        CTX.api._store.add_history("security", "سرور", "ok", f"سرور راه‌اندازی شد؛ ادمین: {name}", user=name)
        rec = data["users"][0]
        sid, _ = CTX.new_session({k: rec.get(k) for k in ("username", "role", "tools", "disabled", "shared_devices", "perms_v", "source")}, self._ip())
        return self._json({"ok": True}, extra=self._cookie(sid))

    def _recover(self):
        """1.27.8: رمز فراموش‌شده‌ی ادمین محلی با کد بازیابی (پیش از ورود). همان قفل تلاش ناموفقِ ورود."""
        from . import recovery as rc
        ip = self._ip()
        b = self._json_body()
        b = b if isinstance(b, dict) else {}
        name = str(b.get("username") or "").strip()[:64]
        wait = CTX.begin_attempt(ip, "recovery:" + name.lower())
        if wait:
            return self._json({"ok": False, "error": f"به‌خاطر تلاش‌های ناموفق، {wait} ثانیه صبر کنید."}, 429)
        t0 = time.time()
        try:
            strong = True
            if CTX.settings is not None:
                strong = CTX.settings.get("security", "strong_policy", default=True)
            master, code = serverauth.recovery_use(str(b.get("code") or ""), name, str(b.get("password") or ""), strong)
        except serverauth.AuthError as e:
            time.sleep(max(0.0, 1.0 - (time.time() - t0)))
            log.warning("بازیابی رمز ناموفق از %s (نام کاربری: %s)", ip, _log_safe(name))
            if CTX.api:
                CTX.api._store.add_history("security", "کد بازیابی", "error", f"ناموفق از {ip} — نام کاربری: {_log_safe(name)}", user="")
            return self._json({"ok": False, "error": str(e)}, 400)
        CTX.end_attempt(ip, "recovery:" + name.lower(), True)
        CTX.drop_session(username=name.lower())                     # نشست‌های قبلی همین حساب بسته شوند
        if CTX.api:
            CTX.api._store.add_history("security", "کد بازیابی", "warn", f"رمز «{_log_safe(name)}» با کد بازیابی از {ip} عوض شد؛ کد تازه ساخته شد", user="")
        return self._json({"ok": True, "code": code, "filename": "AutoKRP-recovery-code.txt",
                           "file": rc.file_text(code, f"سرور AutoKRP ({socket.gethostname()}) — رمز ادمین‌های محلی")})

    def _login(self):
        ip = self._ip()
        b = self._json_body()
        b = b if isinstance(b, dict) else {}
        name = str(b.get("username") or "").strip()[:64]
        wait = CTX.begin_attempt(ip, name)
        if wait:
            return self._json({"ok": False, "error": f"به‌خاطر تلاش‌های ناموفق، {wait} ثانیه صبر کنید."}, 429)
        t0 = time.time()
        try:
            if not serverauth.is_local(name):
                master, rec = self._login_ad(name, str(b.get("password") or ""), ip)
            else:
                master, rec = serverauth.login(name, str(b.get("password") or ""))
        except serverauth.AuthError as e:
            time.sleep(max(0.0, 1.0 - (time.time() - t0)))
            shown = _log_safe(name)
            log.warning("ورود ناموفق از %s (نام کاربری: %s)", ip, shown)
            if CTX.api:
                CTX.api._store.add_history("security", "ورود", "error", f"ناموفق از {ip} — نام کاربری: {shown}", user="")
            return self._json({"ok": False, "error": str(e)}, 401)
        CTX.end_attempt(ip, name, True)
        try:
            CTX.bring_up(master)
        except Exception as e:  # noqa — مثلاً MySQL در دسترس نیست
            log.error("bring_up failed: %s", e)
            return self._json({"ok": False, "error": f"راه‌اندازی ناموفق: {e}"}, 503)
        CTX.api._store.add_history("security", "ورود", "ok", f"{rec['username']} از {ip} وارد شد", user=rec["username"])
        CTX.worker.request_check()
        sid, _ = CTX.new_session({k: rec.get(k) for k in ("username", "role", "tools", "disabled", "shared_devices", "perms_v", "source")}, ip)
        return self._json({"ok": True}, extra=self._cookie(sid))

    @staticmethod
    def _login_ad(name, pw, ip):
        """ورود کاربر دامنه (1.24). فقط وقتی سرور باز است (کلید اصلی در حافظه: ورود یک کاربر محلی یا «باز شدن خودکار»)."""
        from . import adauth
        if CTX.api is None or CTX.master is None:
            serverauth._derive("x", b"0" * 16)        # زمان پاسخ نزدیک به نام ناموجود
            raise serverauth.AuthError("نام کاربری یا رمز اشتباه است. (کاربر دامنه: سرور هنوز باز نشده است؛ یک ادمین محلی "
                                       "باید وارد شود یا «باز شدن خودکار» روشن باشد.)")
        cfg = adauth.cfg_of(CTX.settings)
        if not cfg.get("enabled"):
            serverauth._derive("x", b"0" * 16)
            raise serverauth.AuthError("نام کاربری یا رمز اشتباه است.")
        try:
            role, user = adauth.authenticate(cfg, name, pw)
        except adauth.ADBadCredentials as e:
            raise serverauth.AuthError(str(e))
        except adauth.ADError as e:
            log.error("ورود AD: %s", e)
            raise serverauth.AuthError("سرور Active Directory در دسترس نیست؛ با مدیر سیستم تماس بگیرید.")
        rec = serverauth.ad_upsert(user, role)
        return CTX.master, rec

    def _upload(self):
        sid, sess = self._session()
        if not sess or CTX.api is None:
            return self._json({"ok": False, "error": "نشست منقضی شد"}, 401)
        if not _eq(self.headers.get(CSRF_HEADER, ""), sess["csrf"]):
            return self._json({"ok": False, "error": "درخواست نامعتبر (CSRF)"}, 403)
        if sess["user"]["role"] == "readonly":
            return self._json({"ok": False, "error": "دسترسی ندارید"}, 403)
        data = self._body
        if not data:
            return self._json({"ok": False, "error": "فایل خالی یا بزرگ‌تر از حد مجاز (۶۴ مگابایت) است"}, 400)
        name = os.path.basename(urllib.parse.unquote(self.headers.get("X-Filename", "upload.csv")).replace("\\", "/"))
        name = "".join(c for c in name if c.isalnum() or c in "._- ")[:80].strip() or "upload.csv"
        up = paths.data_dir() / "uploads"
        up.mkdir(exist_ok=True)
        dest = up / f"{secrets.token_hex(6)}_{name}"
        atrest.write_bytes(dest, data)          # روی دیسک سرور رمزشده
        return self._json({"ok": True, "path": str(dest), "name": name})

    def _api(self, method):
        sid, sess = self._session(touch=method not in ("get_state", "get_run", "ssh_job", "fgu_job", "ui_perf", "js_error", "term_read", "xfer_jobs", "mon_state"))
        if not sess:
            return self._json({"ok": False, "error": "نشست منقضی شد", "locked": True}, 401)
        if not _eq(self.headers.get(CSRF_HEADER, ""), sess["csrf"]):
            return self._json({"ok": False, "error": "درخواست نامعتبر (CSRF)"}, 403)
        if CTX.api is None:
            return self._json({"ok": False, "error": "سرور آماده نیست"}, 503)
        fn = getattr(CTX.api, method, None)
        if method.startswith("_") or not callable(fn) or not getattr(fn, "__wrapped__", None):
            return self._json({"ok": False, "error": "متد ناشناخته"}, 404)
        args = self._json_body()
        if not isinstance(args, list):
            args = []
        from .api import WEB_IP, WEB_SID, WEB_USER
        tokens = (WEB_USER.set(sess["user"]), WEB_IP.set(self._ip()), WEB_SID.set(sid))
        try:
            out = fn(*args)
        except TypeError:
            out = {"ok": False, "error": "پارامترهای نامعتبر"}
        except Exception:
            log.exception("api %s", method)
            out = {"ok": False, "error": "خطای داخلی سرور"}
        finally:
            for v, t in zip((WEB_USER, WEB_IP, WEB_SID), tokens):
                v.reset(t)
        return self._json(out)


class _Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    # ویندوز: SO_REUSEADDR اجازه‌ی تصاحب پورت به برنامه‌ی دیگر می‌دهد؛ فقط روی POSIX (برای TIME_WAIT)
    allow_reuse_address = os.name != "nt"
    request_queue_size = 64

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self._conn_lock = threading.Lock()
        self._conns = {}              # ip -> تعداد اتصال باز
        self._conn_total = 0

    def process_request(self, request, client_address):
        """سقف اتصال هم‌زمان (کل و هر IP) تا یک کلاینت با اتصال‌های زیاد سرور را از کار نیندازد.
        اتصال از شبکه‌ی غیرمجاز همین‌جا (پیش از TLS) بسته می‌شود و سهمی نمی‌گیرد."""
        ip = client_address[0]
        if CTX is not None and not CTX.ip_allowed(ip):
            self.shutdown_request(request)
            return
        cfg = CTX.cfg if CTX else {}
        mx, per = int(cfg.get("max_connections") or 200), int(cfg.get("max_connections_per_ip") or 40)
        with self._conn_lock:
            if self._conn_total >= mx or self._conns.get(ip, 0) >= per:
                over = True
            else:
                over = False
                self._conn_total += 1
                self._conns[ip] = self._conns.get(ip, 0) + 1
        if over:
            log.warning("اتصال از %s رد شد (سقف اتصال هم‌زمان)", ip)
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._release(ip)
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._release(client_address[0])

    def _release(self, ip):
        with self._conn_lock:
            self._conn_total = max(0, self._conn_total - 1)
            n = self._conns.get(ip, 0) - 1
            if n > 0:
                self._conns[ip] = n
            else:
                self._conns.pop(ip, None)

    def handle_error(self, request, client_address):
        log.debug("خطای اتصال از %s", client_address, exc_info=True)


def _auto_unseal():
    """1.24: «باز شدن خودکار» روشن باشد ← کلید اصلی از DPAPI و راه‌اندازی بدون ورود (مانیتورینگ و کارها بعد از ری‌استارت)."""
    from . import autounseal
    if not autounseal.enabled():
        return
    master = autounseal.load()
    if not master:
        log.error("باز شدن خودکار: کلید باز نشد؛ تا ورود یک کاربر محلی قفل می‌ماند")
        return
    try:
        CTX.bring_up(master)
        CTX.api._store.add_history("security", "باز شدن خودکار", "ok", "سرور بدون ورود کاربر باز شد (DPAPI)", user="")
        log.info("سرور با «باز شدن خودکار» باز شد")
    except Exception as e:  # noqa — کلید نادرست (فایل از نصب دیگر) یا پایگاه داده در دسترس نیست
        log.error("باز شدن خودکار ناموفق: %s", e)
        try:
            CTX.tear_down()
        except Exception:  # noqa
            pass


def run(demo=False, on_ready=None, stop_event=None):
    """سرور HTTPS را اجرا می‌کند (مسدودکننده). on_ready(url, port) پس از آماده شدن صدا زده می‌شود."""
    global CTX
    CTX = _Ctx(demo=demo)
    cfg = CTX.cfg
    port, bind = int(cfg.get("port") or 8443), cfg.get("bind") or "0.0.0.0"  # nosec B104 — سرور باید روی کارت‌های شبکه بشنود تا کاربران وصل شوند؛ bind و شبکه‌های مجاز قابل تنظیم‌اند
    httpd = _Server((bind, port), Handler)
    # نکته: truststore (برای اتصال‌های خروجی) باید بعد از ساخت این context تزریق شود (on_ready)؛
    # SSLContext جایگزین‌شده‌ی truststore روی سوکت سرور گواهی کلاینت را بررسی می‌کند و خطا می‌دهد.
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.minimum_version = ssl.TLSVersion.TLSv1_2
    certs.load_into(tls)
    CTX.tls = tls
    # handshake در رشته‌ی هر اتصال انجام می‌شود، نه در حلقه‌ی accept؛ وگرنه یک کلاینت کند کل سرور را معطل می‌کرد
    httpd.socket = tls.wrap_socket(httpd.socket, server_side=True, do_handshake_on_connect=False)
    threading.Thread(target=CTX.housekeeping, name="server-housekeeping", daemon=True).start()
    threading.Thread(target=_auto_unseal, name="auto-unseal", daemon=True).start()
    url = f"https://localhost:{port}/"
    log.info("سرور AutoKRP روی %s (bind %s)", url, bind)
    if on_ready:
        try:
            on_ready(url, port)
        except Exception:
            pass
    if stop_event is not None:
        threading.Thread(target=lambda: (stop_event.wait(), httpd.shutdown()), daemon=True).start()
    try:
        httpd.serve_forever(poll_interval=0.5)
    finally:
        httpd.server_close()
        CTX.tear_down()
