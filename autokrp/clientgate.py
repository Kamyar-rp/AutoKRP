"""
کلاینت با رمز اصلی (1.50): هیچ داده‌ای پیش از وارد کردن رمز باز نمی‌شود.

پیش از 1.50 رمز اصلی کلاینت فقط اسرار (vault) را قفل می‌کرد و کلید بقیه‌ی داده‌ها (پایگاه داده، تنظیمات، پشتیبان‌ها،
لاگ‌ها …) با DPAPI روی همین کاربر ویندوز بود؛ پس برنامه‌ی دیگری با همین کاربر (مثلاً نسخه‌ی تغییر‌یافته از سورس)
بدون رمز آن‌ها را می‌خواند. حالا کلید داده با کلید vault رمز می‌شود (atrest.WRAP_FILE) و کلید vault فقط از رمز
اصلی، رمز یک کاربر یا کد بازیابی به دست می‌آید؛ مثل حالت سرور.

پیش از باز شدن فقط CLIENT_AUTH (ساده) خواناست: برای هر کاربر نام، salt و کلید vault رمز‌شده با رمز او؛ رکورد کد
بازیابی (رمز‌شده با کد). رمز هیچ کاربری ذخیره نمی‌شود.

Gate: شیء js_api پنجره. تا وقتی رمز وارد نشده فقط صفحه‌ی قفل را جواب می‌دهد؛ پس از باز شدن، تنظیمات، پایگاه داده،
worker و Api واقعی ساخته می‌شوند و همه‌ی فراخوانی‌ها به Api می‌روند.
"""
import json
import logging
import threading
import time

from cryptography.exceptions import InvalidTag

from . import atrest, paths
from .vault import SALT_LEN, VaultError, decrypt_blob, derive_key, split_blob, write_secure

log = logging.getLogger(__name__)

CLIENT_AUTH = ".client_auth.json"
USER_FIELDS = ("username", "salt", "wrap", "disabled")


def _path():
    return paths.data_dir() / CLIENT_AUTH


# ------------------------------------------------------------ فایل پیش از ورود
def sync(settings, vault=None):
    """هم‌سان کردن CLIENT_AUTH با تنظیمات (پس از هر تغییر کاربران، کد بازیابی یا حالت). فقط کلاینت مهرشده."""
    if paths.is_server():
        return
    try:
        if not atrest.sealed():
            if _path().exists():
                _path().unlink()
            return
        users = [{k: u.get(k) for k in USER_FIELDS} for u in (settings.get("users", default=[]) or [])
                 if u.get("username") and u.get("salt") and u.get("wrap")]
        r = settings.get("security", "recovery", default=None) or {}
        rec = {"rc": r.get("rc"), "rk": r.get("rk"), "created": r.get("created")} if r.get("rc") and r.get("rk") else None
        data = {"v": 1, "users": users, "recovery": rec,
                "strong_policy": bool(settings.get("security", "strong_policy", default=True))}
        raw = json.dumps(data, ensure_ascii=False, sort_keys=True).encode("utf-8")
        p = _path()
        if p.exists() and p.read_bytes() == raw:
            return
        write_secure(p, raw)
    except Exception:   # noqa — نبود فایل فقط ورود کاربران/کد بازیابی پیش از باز شدن را می‌بندد؛ رمز اصلی کار می‌کند
        log.exception("client auth sync")


def load():
    try:
        d = json.loads(_path().read_text("utf-8"))
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _vault_salt_blob():
    from .vault import Vault
    p = paths.data_dir() / Vault.VAULT_FILE
    blob = p.read_bytes()
    return split_blob(blob)[0], blob


def key_from_password(password, username=""):
    """کلید vault از رمز اصلی (بدون کاربران) یا رمز یک کاربر. خطا: VaultError با پیام یکسان."""
    from .vault import Vault
    auth = load()
    users = auth.get("users") or []
    if users:
        u = (username or "").strip().lower()
        rec = next((x for x in users if str(x.get("username", "")).lower() == u), None)
        k = None
        if rec is not None:
            try:
                uk = derive_key(password or "", bytes.fromhex(rec["salt"]))
                raw = bytes.fromhex(rec["wrap"])
                from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                k = AESGCM(uk).decrypt(raw[:12], raw[12:], Vault.USER_AAD + rec["username"].lower().encode("utf-8"))
            except (InvalidTag, ValueError, KeyError, TypeError):
                k = None
        else:
            derive_key(password or "x", b"0" * SALT_LEN)          # زمان پاسخ یکسان برای نام نامعتبر
        if k is None:
            raise VaultError("نام کاربری یا رمز اشتباه است.")
        if rec.get("disabled"):
            raise VaultError("این حساب غیرفعال است.")
        return k, rec["username"]
    if not password:
        raise VaultError("رمز اصلی وارد نشده است.")
    salt, blob = _vault_salt_blob()
    k = derive_key(password, salt)
    try:
        decrypt_blob(k, blob)
    except Exception:
        raise VaultError("رمز اشتباه یا فایل دست‌کاری شده")
    return k, ""


def key_from_recovery(code):
    from . import recovery as rc
    r = load().get("recovery") or {}
    R = rc.open_(r.get("rc"), code) if r.get("rc") else None
    k = rc._dec(R, r.get("rk", "")) if R else None
    if not k:
        if not R and not r.get("rc"):
            derive_key("x", b"0" * SALT_LEN)
        raise VaultError("کد بازیابی درست نیست.")
    return k


def remembered_key():
    """«باز شدن خودکار در این کامپیوتر» (کلید vault با DPAPI). None اگر نیست یا باز نشد."""
    from .vault import Vault
    p = paths.data_dir() / Vault.KEY_FILE
    if not p.exists():
        return None
    try:
        from . import dpapi
        raw = dpapi.unprotect(p.read_bytes())
        return raw[:32] if len(raw) >= 32 else None
    except OSError:
        return None


# ------------------------------------------------------------ ساخت اجزای کلاینت
def build(k=None, username="", via="", demo=False, open_store=None):
    """تنظیمات، vault، پایگاه داده، worker و Api. k: کلید vault (پس از رمز)؛ None = حالت ساده یا هنوز مهر نشده.
    خروجی: Api یا None (پایگاه داده باز نشد)."""
    from .api import Api
    from .settings import Settings
    from .store import Store
    from .vault import Vault
    from .worker import Worker
    settings = Settings()
    vault = Vault(settings)
    settings.attach_vault(vault)
    rec = None
    if k is not None:
        vault._open(k)
        if username:
            rec = vault.find_user(username)
            if rec is None or rec.get("disabled"):        # فایل پیش از ورود با تنظیمات واقعی نمی‌خواند
                vault.forget()
                raise VaultError("نام کاربری یا رمز اشتباه است." if rec is None else "این حساب غیرفعال است.")
        elif vault.users_enabled() and via == "password":
            vault.forget()
            raise VaultError("نام کاربری یا رمز اشتباه است.")
    else:
        vault.auto_unlock()
    store = (open_store or (lambda S: S()))(Store)
    if store is None:
        vault.forget()
        return None
    worker = Worker(settings, store, demo=demo)
    api = Api(settings, store, worker, demo=demo, vault=vault)
    if rec is not None:
        items = [{**x, "last_login": time.time()} if x["username"] == rec["username"] else x for x in vault.users()]
        settings.set_users(items)
        api._user = vault.find_user(rec["username"])
        vault.ui_locked = False
        store.add_history("security", "ورود", "ok", f"{rec['username']} وارد شد", user=rec["username"])
    api._last_act = time.time()
    worker.start()
    atrest.flush_pending_logs()
    marker = paths.data_dir() / ".atrest_v1"
    if not marker.exists():
        try:
            marker.write_bytes(b"")
        except OSError:
            pass
    if k is not None:
        worker.emit("ok", "قفل برنامه باز شد" + (f" ({rec['username']})" if rec else ""), "security")
        worker.request_check()
    return api


def start(demo=False, open_store=None, on_ready=None):
    """Gate آماده برای پنجره. حالت ساده/مهرنشده یا «باز شدن خودکار»: Api همین حالا ساخته می‌شود."""
    gate = Gate(lambda k, u, via: build(k, u, via, demo=demo, open_store=open_store), demo=demo, on_ready=on_ready)
    if not atrest.sealed():
        api = build(None, demo=demo, open_store=open_store)
        if api is None:
            return None
        gate._g_attach(api)
        return gate
    k = remembered_key()
    if k is not None:
        try:
            gate._bring_up(k, "", "remember")
        except VaultError as e:
            log.warning("باز شدن خودکار ناموفق: %s", e)
    return gate


# ------------------------------------------------------------ Gate (js_api)
GATE_OWN = {"_g_build", "_g_real", "_g_window", "_g_lock", "_g_demo", "_g_fails", "_g_until", "_g_on_ready", "_g_error"}
PRE = {"get_state", "security_status", "security_unlock", "security_recover", "security_check_password",
       "terms_status", "terms_accept", "save_ui", "js_error", "ui_perf", "ui_touch"}


class Gate:
    """build(k, username, via) ← Api واقعی (یا None). on_ready(api) پس از ساخت (آیکن، memdiag …)."""

    def __init__(self, build, demo=False, on_ready=None):
        object.__setattr__(self, "_g_build", build)
        object.__setattr__(self, "_g_real", None)
        object.__setattr__(self, "_g_window", None)
        object.__setattr__(self, "_g_lock", threading.Lock())
        object.__setattr__(self, "_g_demo", demo)
        object.__setattr__(self, "_g_fails", 0)
        object.__setattr__(self, "_g_until", 0.0)
        object.__setattr__(self, "_g_on_ready", on_ready)
        object.__setattr__(self, "_g_error", "")

    # Api واقعی آماده است (حالت ساده یا «باز شدن خودکار» از همان ابتدا)
    def _g_attach(self, api):
        object.__setattr__(self, "_g_real", api)
        if self._g_window is not None:
            api._set_window(self._g_window)
        if self._g_on_ready:
            try:
                self._g_on_ready(api)
            except Exception:
                log.exception("gate on_ready")

    # ویژگی‌های خصوصی (app.py و آیکن سینی) به Api واقعی؛ پیش از آن پیش‌فرض‌های بی‌خطر
    def __getattr__(self, name):
        real = object.__getattribute__(self, "_g_real")
        if real is not None:
            return getattr(real, name)
        if name == "_set_window":
            return lambda w: object.__setattr__(self, "_g_window", w)
        if name == "_on_closing":
            return lambda *a: True
        if name == "_show_window":
            def show():
                w = self._g_window
                if w is not None:
                    w.show()
                    w.restore()
            return show
        if name == "_window":
            return self._g_window
        if name in ("_quitting", "_hidden"):
            return False
        raise AttributeError(name)

    def __setattr__(self, name, value):
        if name in GATE_OWN:
            object.__setattr__(self, name, value)
            return
        real = self._g_real
        if real is not None:
            setattr(real, name, value)

    # ------------------------------------------------ پیش از باز شدن
    def _pre(self, name, *a, **k):
        if name in ("get_state", "security_status"):
            return self._pre_state(name)
        if name == "security_unlock":
            return self._pre_unlock(*a, **k)
        if name == "security_recover":
            return self._pre_recover(*a, **k)
        if name == "security_check_password":
            from .vault import check_password
            return {"ok": True, "errors": check_password((a[0] if a else "") or "", bool(load().get("strong_policy", True)))}
        if name == "terms_status":
            return {"ok": True, "need": False, "accepted": None}
        return {"ok": True}

    def _sec(self):
        auth = load()
        users = auth.get("users") or []
        r = auth.get("recovery") or {}
        return {"initialized": True, "unlocked": False, "ui_locked": False, "mode": "password", "unsupported": False,
                "remember": False, "strong_policy": bool(auth.get("strong_policy", True)), "dpapi": True, "count": 0,
                "users_enabled": bool(users), "user_count": len(users), "auto_lock_minutes": 0,
                "recovery": {"has": bool(r.get("rc")), "created": r.get("created")}, "data_dir": str(paths.data_dir()),
                "sealed": True}

    def _pre_state(self, name):
        from . import AUTHOR, __version__
        sec = self._sec()
        if name == "security_status":
            return {"ok": True, "security": sec}
        return {"ok": True, "events": [], "conn": {}, "last_check": None, "run": None, "last_run": None,
                "counts": {}, "test_mode": True, "master": False, "jobs_on": 0, "demo": self._g_demo,
                "version": __version__, "author": AUTHOR, "branding": {"app_name": "AutoKRP", "logo_data": ""},
                "security": sec, "lang": paths.ui_lang(), "me": None, "tools": [], "tools_enabled": []}

    def _throttle(self):
        from .api import UNLOCK_FREE_TRIES, UNLOCK_MAX_WAIT
        return UNLOCK_FREE_TRIES, UNLOCK_MAX_WAIT

    def _failed(self, t0, msg):
        free, mx = self._throttle()
        time.sleep(max(0.0, 1.0 - (time.time() - t0)))
        n = self._g_fails + 1
        object.__setattr__(self, "_g_fails", n)
        if n >= free:
            secs = min(mx, 30 * 2 ** (n - free))
            object.__setattr__(self, "_g_until", time.time() + secs)
            if msg.startswith("کد بازیابی"):
                return {"ok": False, "error": msg}
            return {"ok": False, "error": f"رمز اشتباه است. به‌خاطر {n} تلاش ناموفق پشت‌سرهم، {secs} ثانیه صبر کنید."}
        return {"ok": False, "error": msg}

    def _wait(self):
        w = int(self._g_until - time.time())
        if w > 0:
            return {"ok": False, "error": f"به‌خاطر تلاش‌های ناموفق پشت‌سرهم، {w} ثانیه‌ی دیگر دوباره امتحان کنید."}
        return None

    def _bring_up(self, k, username, via):
        """کلید داده با K؛ ساخت اجزا. خطا: VaultError."""
        if not atrest.open_sealed(k):
            raise VaultError("کلید داده‌ها با این رمز باز نشد (فایل کلید آسیب دیده است).")
        try:
            api = self._g_build(k, username, via)
        except Exception:
            atrest.forget()
            raise
        if api is None:
            atrest.forget()
            raise VaultError("پایگاه داده باز نشد.")
        if self._g_fails:
            api._store.add_history("security", "باز کردن قفل", "ok", f"باز شد، پس از {self._g_fails} تلاش ناموفق")
        object.__setattr__(self, "_g_fails", 0)
        object.__setattr__(self, "_g_until", 0.0)
        self._g_attach(api)
        return api

    def _pre_unlock(self, password="", username="", *_):
        t0 = time.time()
        with self._g_lock:
            if self._g_real is not None:
                return self._g_real.security_unlock(password, username)
            w = self._wait()
            if w:
                return w
            try:
                k, uname = key_from_password(password or "", username or "")
            except VaultError as e:
                return self._failed(t0, str(e))
            except OSError:
                return {"ok": False, "error": "فایل اسرار خوانده نشد."}
            try:
                api = self._bring_up(k, uname, "password")
            except VaultError as e:
                return {"ok": False, "error": str(e)}
            except Exception as e:   # noqa
                log.exception("gate bring-up")
                return {"ok": False, "error": f"باز کردن داده‌ها ناموفق بود: {e}"}
            return {"ok": True, "security": api._sec_status()}

    def _pre_recover(self, code="", new_password="", username="", *_):
        t0 = time.time()
        with self._g_lock:
            if self._g_real is not None:
                return self._g_real.security_recover(code, new_password, username)
            w = self._wait()
            if w:
                return w
            try:
                k = key_from_recovery(code)
            except VaultError:
                return self._failed(t0, "کد بازیابی درست نیست.")
            except Exception:  # noqa
                return self._failed(t0, "کد بازیابی درست نیست.")
            try:
                api = self._bring_up(k, "", "recovery")
            except VaultError as e:
                return {"ok": False, "error": str(e)}
            except Exception as e:   # noqa
                log.exception("gate bring-up (recovery)")
                return {"ok": False, "error": f"باز کردن داده‌ها ناموفق بود: {e}"}
        return api.security_recover(code, new_password, username)


def _make(name):
    def call(self, *a, **k):
        real = self._g_real
        if real is not None:
            return getattr(real, name)(*a, **k)
        if name in PRE:
            return self._pre(name, *a, **k)
        return {"ok": False, "error": "برنامه قفل است.", "locked": True}
    call.__name__ = name
    return call


def _install():
    from .api import Api
    for name in dir(Api):
        if name.startswith("_") or name in Gate.__dict__:
            continue
        if callable(getattr(Api, name, None)):
            setattr(Gate, name, _make(name))


_install()
