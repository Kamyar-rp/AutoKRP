"""
احراز هویت حالت سرور (وب، چندکاربره) — بدون DPAPI.

یک «کلید اصلی» تصادفی همه‌ی داده‌ها را رمز می‌کند (اسرار، تنظیمات، پایگاه داده، فایل‌ها، لاگ‌ها).
این کلید برای هر کاربر جداگانه با کلید مشتق از رمز خودش (scrypt + AES-256-GCM) wrap می‌شود و در
`.server_auth.json` نگهداری می‌شود. این فایل ساده است ولی فقط کلیدهای wrap‌شده را دارد؛ بدون رمزِ یکی
از کاربران هیچ داده‌ای باز نمی‌شود. رمز هیچ کاربری ذخیره نمی‌شود.

این فایل تنها چیزی است که در حالت سرور ساده روی دیسک می‌ماند؛ بقیه‌ی فایل‌ها با کلید اصلی رمز شده‌اند.
"""
import copy
import hashlib
import json
import os
import re
import threading
import time

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import paths
from .vault import SALT_LEN, NONCE_LEN, KEY_LEN, SCRYPT, check_password, write_secure

AUTH_FILE = ".server_auth.json"
# پیکربندی سرور که پیش از ورود لازم است (پورت، شبکه‌های مجاز، قفل حساب، زمان نشست). محرمانه نیست؛
# کنار کاربران در همین فایل ساده نگهداری می‌شود تا محدودیت‌ها از لحظه‌ی روشن شدن سرور اعمال شوند.
# bind پیش‌فرض روی همه‌ی کارت‌های شبکه تا کاربران LAN وصل شوند؛ در تنظیمات قابل محدود کردن است (nosec B104)
# شبکه‌های مجاز پیش‌فرض (نصب تازه): فقط شبکه‌های داخلی؛ خالی = همه (قابل تغییر در تنظیمات سرور)
DEFAULT_CONFIG = {"port": 8443, "bind": "0.0.0.0", "session_timeout_minutes": 30,  # nosec B104
                  "allowed_networks": ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
                  "lockout_threshold": 5, "lockout_minutes": 15, "max_connections": 200, "max_connections_per_ip": 40,
                  "ad_session_hours": 12}
AAD = b"autokrp-server-user:"
ROLES = ("admin", "operator", "readonly")
NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{2,32}$")


class AuthError(Exception):
    """پیام فارسی قابل نمایش."""


# هر «خواندن، تغییر، نوشتن» این فایل باید زیر همین قفل باشد؛ وگرنه نوشتن هم‌زمان (مثلاً ثبت آخرین ورود)
# تغییر ادمین (غیرفعال کردن، حذف، تغییر رمز) را با نسخه‌ی قدیمی بازنویسی می‌کند.
LOCK = threading.RLock()
_cache = None          # ((mtime_ns, size), data) — خواندن مکرر در هر درخواست


def _path():
    return paths.data_dir() / AUTH_FILE


def exists():
    return _path().exists()


def load():
    """نسخه‌ی مستقل (کپی) از فایل کاربران."""
    global _cache
    with LOCK:
        try:
            st = _path().stat()
            key = (st.st_mtime_ns, st.st_size)
            if _cache is not None and _cache[0] == key:
                return copy.deepcopy(_cache[1])
            d = json.loads(_path().read_text(encoding="utf-8"))
            if not isinstance(d, dict) or not isinstance(d.get("users"), list):
                raise ValueError
            _cache = (key, d)
            return copy.deepcopy(d)
        except (OSError, ValueError, json.JSONDecodeError):
            raise AuthError("فایل کاربران سرور خراب یا ناخواناست.")


def save(data):
    global _cache
    with LOCK:
        write_secure(_path(), json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8"))
        _cache = None


def config():
    """پیکربندی سرور (بدون نیاز به کلید). پیش از راه‌اندازی: پیش‌فرض.
    fail-closed: اگر فایل هست ولی خوانده یا اعتبارسنجی نشد، سرور فقط روی localhost و فقط برای localhost بالا می‌آید."""
    cfg = dict(DEFAULT_CONFIG)
    if exists():
        try:
            got = load().get("config") or {}
            if not isinstance(got, dict) or not isinstance(got.get("allowed_networks", []), list):
                raise AuthError("پیکربندی سرور نامعتبر است.")
            cfg.update(got)
        except AuthError as e:
            import logging
            logging.getLogger(__name__).error("پیکربندی سرور خوانده نشد (%s)؛ فقط دسترسی localhost", e)
            cfg.update(bind="127.0.0.1", allowed_networks=["127.0.0.0/8"], config_error=str(e)[:200])
    return cfg


def set_config(patch):
    with LOCK:
        data = load()
        data["config"] = {**config(), **(patch or {})}
        save(data)
        return data["config"]


def subkeys(master):
    """کلید داده (atrest) و کلید اسرار (vault) جدا از کلید اصلی، با HKDF-SHA256."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    def d(info):
        return HKDF(algorithm=hashes.SHA256(), length=KEY_LEN, salt=None, info=info).derive(master)
    return d(b"autokrp-server-data"), d(b"autokrp-server-vault")


# هر scrypt حدود ۳۲ مگابایت حافظه می‌گیرد؛ ورودهای هم‌زمان زیاد نباید حافظه‌ی سرور را تمام کنند
_KDF_SLOTS = threading.BoundedSemaphore(2)


def _derive(pw, salt):
    with _KDF_SLOTS:
        return _derive_raw(pw, salt)


def _derive_raw(pw, salt):
    return hashlib.scrypt(pw.encode("utf-8"), salt=bytes.fromhex(salt) if isinstance(salt, str) else salt, **SCRYPT)


def _wrap(master, pw):
    salt = os.urandom(SALT_LEN)
    uk = _derive(pw, salt)
    nonce = os.urandom(NONCE_LEN)
    return {"salt": salt.hex(), "wrap": (nonce + AESGCM(uk).encrypt(nonce, master, AAD)).hex()}


def _unwrap(rec, pw):
    try:
        uk = _derive(pw or "", rec["salt"])
        raw = bytes.fromhex(rec["wrap"])
        return AESGCM(uk).decrypt(raw[:NONCE_LEN], raw[NONCE_LEN:], AAD)
    except (InvalidTag, ValueError, KeyError):
        return None


def new_user_record(master, username, pw, role, tools=None, disabled=False, strong=True):
    if not NAME_RE.match(username or ""):
        raise AuthError("نام کاربری باید ۲ تا ۳۲ نویسه از حروف انگلیسی، عدد، نقطه، - یا _ باشد.")
    if role not in ROLES:
        raise AuthError("نقش نامعتبر است.")
    errs = check_password(pw or "", strong)
    if errs:
        raise AuthError("رمز شرایط لازم را ندارد: " + "، ".join(errs))
    return {"username": username, "role": role, "tools": list(tools or []) if role == "operator" else [],
            "disabled": bool(disabled), "created": time.time(), "last_login": None, **_wrap(master, pw)}


def create_server(username, pw, strong=True):
    """راه‌اندازی سرور: کلید اصلی تصادفی و اولین ادمین. خروجی: (master, data)"""
    if exists():
        raise AuthError("سرور از قبل راه‌اندازی شده است.")
    master = os.urandom(KEY_LEN)
    rec = new_user_record(master, username, pw, "admin", strong=strong)
    data = {"version": 1, "users": [rec], "config": dict(DEFAULT_CONFIG)}
    with LOCK:
        if exists():
            raise AuthError("سرور از قبل راه‌اندازی شده است.")
        save(data)
    return master, data


def find(data, username):
    u = (username or "").strip().lower()
    return next((x for x in data.get("users", []) if x.get("username", "").lower() == u), None)


def login(username, pw):
    """خروجی: (master, user_record). خطا: AuthError."""
    rec = find(load(), username)
    master = _unwrap(rec, pw) if rec else None      # کند (scrypt)؛ بیرون از قفل
    if rec is None or master is None:
        if rec is None:
            _derive("x", b"0" * SALT_LEN)   # زمان پاسخ نزدیک
        raise AuthError("نام کاربری یا رمز اشتباه است.")
    with LOCK:                                      # دوباره از فایل: شاید در این فاصله تغییر کرده باشد
        data = load()
        cur = find(data, username)
        if cur is None or cur.get("salt") != rec.get("salt"):
            raise AuthError("نام کاربری یا رمز اشتباه است.")
        if cur.get("disabled"):
            raise AuthError("این حساب غیرفعال است.")
        cur["last_login"] = time.time()
        save(data)
    return master, cur


def verify(username, pw):
    data = load()
    rec = find(data, username)
    return bool(rec and _unwrap(rec, pw) is not None)


def change_password(username, master, new_pw, strong=True):
    errs = check_password(new_pw or "", strong)
    if errs:
        raise AuthError("رمز شرایط لازم را ندارد: " + "، ".join(errs))
    wrapped = _wrap(master, new_pw)
    with LOCK:
        data = load()
        rec = find(data, username)
        if not rec:
            raise AuthError("کاربر پیدا نشد.")
        rec.update(wrapped)
        save(data)


def enabled():
    return paths.is_server() and exists()


# ---------------------------------------------------------------- کاربران Active Directory (1.24)
def is_local(username):
    """کاربر محلی (با کلید wrap‌شده) با این نام هست؟ کاربر محلی همیشه بر AD مقدم است."""
    try:
        rec = find(load(), username)
    except AuthError:
        return True               # fail-closed
    return bool(rec and rec.get("salt"))


def ad_upsert(username, role):
    """رکورد کاربر AD (بدون کلید و رمز): در اولین ورود ساخته می‌شود؛ نقش در هر ورود از گروه‌های AD.
    ابزارهای اپراتور و غیرفعال بودن را ادمین در برنامه تعیین می‌کند. خروجی: رکورد (یا AuthError اگر غیرفعال)."""
    if not NAME_RE.match(username or ""):
        raise AuthError("نام کاربری AD برای این برنامه مجاز نیست (۲ تا ۳۲ نویسه‌ی انگلیسی، عدد، . - _).")
    if role not in ROLES:
        raise AuthError("نقش نامعتبر است.")
    with LOCK:
        data = load()
        rec = find(data, username)
        if rec and rec.get("salt"):
            raise AuthError("نام کاربری یا رمز اشتباه است.")
        if rec is None:
            rec = {"username": username, "role": role, "tools": [], "disabled": False, "created": time.time(),
                   "last_login": None, "source": "ad", "shared_devices": True, "perms_v": 2}
            data["users"].append(rec)
        if rec.get("disabled"):
            raise AuthError("این حساب غیرفعال است.")
        if rec["role"] != role:
            rec["role"] = role
            if role != "operator":
                rec["tools"] = []
        rec["last_login"] = time.time()
        save(data)
        return dict(rec)


# ---------------------------------------------------------------- کد بازیابی (1.27.8؛ autokrp/recovery.py)
# کلید اصلی سرور ثابت است؛ مستقیم با کد رمز می‌شود و در همین فایل (data["recovery"]) می‌ماند. خود کد ذخیره نمی‌شود.
def recovery_status():
    try:
        r = load().get("recovery") or {}
    except AuthError:
        r = {}
    return {"has": bool(r.get("wrap")), "created": r.get("created")}


def recovery_create(master):
    from . import recovery as rc
    code = rc.new_code()
    with _KDF_SLOTS:
        rec = rc.seal(master, code)
    with LOCK:
        data = load()
        data["recovery"] = rec
        save(data)
    return code


def recovery_use(code, username, new_pw, strong=True):
    """کد درست ← رمز تازه برای یک ادمین محلی فعال + کد تازه. خروجی: (master, کد تازه). خطا: AuthError."""
    from . import recovery as rc
    errs = check_password(new_pw or "", strong)
    if errs:
        raise AuthError("رمز تازه شرایط لازم را ندارد: " + "، ".join(errs))
    data = load()
    with _KDF_SLOTS:
        master = rc.open_(data.get("recovery"), code) if data.get("recovery") else None
    if master is None:
        if not data.get("recovery"):
            _derive("x", b"0" * SALT_LEN)
        raise AuthError("کد بازیابی یا نام کاربری درست نیست.")
    rec = find(data, username)
    if not rec or rec.get("role") != "admin" or rec.get("disabled") or rec.get("source") == "ad":
        raise AuthError("کد بازیابی یا نام کاربری درست نیست. (فقط رمز یک ادمین محلی فعال بازیابی می‌شود.)")
    change_password(rec["username"], master, new_pw, strong)
    return master, recovery_create(master)
