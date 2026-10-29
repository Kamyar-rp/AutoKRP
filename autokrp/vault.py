"""
نگهداری امن اسرار (توکن‌های API، یوزر/پسورد SSH و ...).

دو حالت:
  simple    ← بدون رمز اصلی. کلید تصادفی ۲۵۶ بیتی با Windows DPAPI روی همین کاربر ویندوز محافظت می‌شود.
               فایل کپی‌شده روی کامپیوتر/کاربر دیگر باز نمی‌شود، ولی هر برنامه‌ای که با همین کاربر اجرا شود می‌تواند.
  password  ← رمز اصلی هنگام باز کردن برنامه. کلید با scrypt از رمز ساخته می‌شود و هیچ‌جا ذخیره نمی‌شود،
               مگر کاربر «باز شدن خودکار در این کامپیوتر» را بزند (کلید با DPAPI نگه داشته می‌شود).
(حالت متغیر محیطی در نسخه‌ی 0.9 حذف شد: کلید به‌صورت متن ساده در رجیستری کاربر و محیط همه‌ی برنامه‌ها بود.)

دو نوع قفل:
  قفل رابط  ← رابط بدون رمز قابل استفاده نیست، ولی کلید در حافظه می‌ماند تا کارهای زمان‌بندی‌شده ادامه یابند.
  قفل کامل  ← کلید و اسرار از حافظه پاک می‌شوند؛ هیچ کار خودکاری تا وارد کردن رمز اجرا نمی‌شود.

رمزنگاری (طبق مشخصات پروژه):
  کلید: hashlib.scrypt، salt تصادفی ۱۶ بایتی، n=2**15, r=8, p=1, maxmem=64MB, dklen=32
  AES-256-GCM (cryptography)، nonce تصادفی ۱۲ بایتی، AAD = b"autokrp-vault" + بایت نسخه
  داده: JSON، padding با طول ثابت: [۴ بایت طول ">I"][داده][بایت تصادفی] تا اندازه‌ی ثابت بعدی
  (به‌جای ۲۵۶ بایت ثابت، چون تعداد اسرار زیاد است: 4KB، 16KB، 64KB، ... تا طول فایل تعداد را لو ندهد)
  فایل باینری بدون برچسب: [۱ بایت نسخه][۱۶ بایت salt][۱۲ بایت nonce][متن رمزشده + تگ ۱۶ بایتی]
  همه‌ی مقادیر تصادفی با os.urandom. امنیت فقط به کلید وابسته است، نه مخفی بودن الگوریتم (کرکهوفس).
"""
import hashlib
import hmac
import json
import logging
import os
import re
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import dpapi, paths

log = logging.getLogger(__name__)

VERSION = 1
AAD = b"autokrp-vault" + bytes([VERSION])
SALT_LEN, NONCE_LEN, TAG_LEN, KEY_LEN = 16, 12, 16, 32
HEADER_LEN = 1 + SALT_LEN + NONCE_LEN
SCRYPT = dict(n=2 ** 15, r=8, p=1, maxmem=64 * 1024 * 1024, dklen=KEY_LEN)
BUCKET_BASE = 4096
MODES = ("simple", "password")


class VaultError(Exception):
    """پیام فارسی قابل نمایش."""


class VaultLocked(VaultError):
    pass


# ------------------------------------------------------------------ helpers
def derive_key(secret: str, salt: bytes) -> bytes:
    return hashlib.scrypt(secret.encode("utf-8"), salt=salt, **SCRYPT)


def check_password(pw: str, strong: bool) -> list:
    """فهرست خطاها (خالی = قابل قبول)."""
    errs = []
    if not pw:
        return ["رمز خالی است"]
    if strong:
        if len(pw) < 12:
            errs.append("حداقل ۱۲ نویسه")
        if not re.search(r"[A-Za-z\u0600-\u06FF]", pw):
            errs.append("حداقل یک حرف")
        if not re.search(r"\d", pw):
            errs.append("حداقل یک عدد")
        if not re.search(r"[^\w\s]|_", pw):
            errs.append("حداقل یک علامت (مثل ! @ # -)")
    return errs


def _bucket(n: int) -> int:
    size = BUCKET_BASE
    while size < n:
        size *= 4
    return size


def encrypt_blob(key: bytes, salt: bytes, data: dict) -> bytes:
    payload = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    frame = struct.pack(">I", len(payload)) + payload
    padded = frame + os.urandom(_bucket(len(frame) + TAG_LEN) - TAG_LEN - len(frame))
    nonce = os.urandom(NONCE_LEN)
    return bytes([VERSION]) + salt + nonce + AESGCM(key).encrypt(nonce, padded, AAD)


def split_blob(blob: bytes):
    if len(blob) < HEADER_LEN + TAG_LEN + 4:
        raise VaultError("فایل اسرار ناقص یا خراب است.")
    if blob[0] != VERSION:
        raise VaultError(f"نسخه‌ی فایل اسرار پشتیبانی نمی‌شود ({blob[0]}).")
    return blob[1:1 + SALT_LEN], blob[1 + SALT_LEN:HEADER_LEN], blob[HEADER_LEN:]


def decrypt_blob(key: bytes, blob: bytes) -> dict:
    _salt, nonce, ct = split_blob(blob)
    try:
        padded = AESGCM(key).decrypt(nonce, ct, AAD)
    except InvalidTag:
        raise VaultError("رمز اشتباه یا فایل دست‌کاری شده")
    (n,) = struct.unpack(">I", padded[:4])
    if n > len(padded) - 4:
        raise VaultError("رمز اشتباه یا فایل دست‌کاری شده")
    return json.loads(padded[4:4 + n].decode("utf-8"))


def _restrict(path):
    """دسترسی فقط برای کاربر جاری. در ویندوز 0600 کار نمی‌کند؛ ACL با icacls تنظیم می‌شود."""
    if sys.platform == "win32":
        user = os.environ.get("USERNAME") or ""
        if user:
            try:
                icacls = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "icacls.exe")
                subprocess.run([icacls, str(path), "/inheritance:r", "/grant:r", f"{user}:F"],
                               capture_output=True, timeout=15, creationflags=0x08000000)
            except Exception:
                log.warning("تنظیم ACL روی %s انجام نشد", path)
    else:
        os.chmod(path, 0o600)


def _set_hidden(path, hidden=True):
    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.kernel32.SetFileAttributesW(str(path), 0x02 if hidden else 0x80)
        except Exception:
            pass


def write_secure(path, data: bytes):
    """نوشتن اتمیک: فایل موقتِ یکتا (mkstemp، دسترسی 0600) و سپس جایگزینی. نوشتن‌های هم‌زمان با هم تداخل ندارند."""
    import tempfile
    path = Path(path)
    fd, tmpname = tempfile.mkstemp(dir=str(path.parent), prefix=path.name + ".", suffix=".tmp")
    tmp = Path(tmpname)
    try:
        try:
            os.write(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
        _restrict(tmp)
        if path.exists():
            _set_hidden(path, False)
        for i in range(20):          # ویندوز: اگر خواننده‌ی دیگری فایل را باز نگه داشته، کمی بعد دوباره
            try:
                os.replace(tmp, path)
                break
            except PermissionError:
                if i == 19:
                    raise
                time.sleep(0.05)
        _set_hidden(path, True)
    finally:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass


# ------------------------------------------------------------------ vault
class Vault:
    def __init__(self, settings):
        self.settings = settings
        self.path = paths.data_dir() / ".cfg_data.bin"
        self.key_path = paths.data_dir() / ".cfg_key.bin"
        self._lock = threading.RLock()
        self._key = None
        self._salt = None
        self._data = None
        self.ui_locked = False

    # ---------------------------------------------------------------- state
    @property
    def mode(self):
        if paths.is_server():
            return "server"
        return self.settings.get("security", "mode", default="") or ""

    # ---------------------------------------------------------------- server mode (کلید اصلی مشترک)
    def setup_server(self, master):
        """راه‌اندازی اولیه‌ی vault در حالت سرور: اسرار خالی با کلید اصلی."""
        with self._lock:
            self._key, self._salt, self._data = bytes(master), os.urandom(SALT_LEN), {}
            self._persist()
            self.ui_locked = False

    def open_server(self, master):
        """باز کردن اسرار با کلید اصلی (پس از ورود کاربر در حالت سرور)."""
        with self._lock:
            self._key = bytes(master)
            if self.path.exists():
                blob = self.path.read_bytes()
                self._salt, _n, _c = split_blob(blob)
                self._data = decrypt_blob(self._key, blob)
            else:
                self._salt, self._data = os.urandom(SALT_LEN), {}
                self._persist()
            self.ui_locked = False

    def initialized(self):
        if paths.is_server():
            from . import serverauth
            return serverauth.exists()
        return self.path.exists() and self.mode in MODES

    def unsupported(self):
        """فایل اسرار با حالتی ساخته شده که دیگر پشتیبانی نمی‌شود (متغیر محیطی)."""
        if paths.is_server():
            return False
        return self.path.exists() and bool(self.mode) and self.mode not in MODES

    def unlocked(self):
        return self._data is not None

    def status(self):
        return {"initialized": self.initialized(), "unlocked": self.unlocked(), "ui_locked": self.ui_locked,
                "mode": self.mode, "unsupported": self.unsupported(),
                "remember": bool(self.settings.get("security", "remember", default=False)),
                "strong_policy": bool(self.settings.get("security", "strong_policy", default=True)),
                "dpapi": dpapi.AVAILABLE, "count": len(self._data or {})}

    # ---------------------------------------------------------------- key sources
    def _key_for(self, mode, password, salt):
        if mode == "password":
            if not password:
                raise VaultError("رمز اصلی وارد نشده است.")
            return derive_key(password, salt)
        raise VaultError("حالت نامعتبر")

    def _store_key(self, key, salt):
        write_secure(self.key_path, dpapi.protect(key + salt))

    def _load_key(self):
        raw = dpapi.unprotect(self.key_path.read_bytes())
        return raw[:KEY_LEN], raw[KEY_LEN:KEY_LEN + SALT_LEN]

    def _drop_key_file(self):
        try:
            self.key_path.unlink()
        except FileNotFoundError:
            pass

    # ---------------------------------------------------------------- lifecycle
    def setup(self, mode, password="", remember=False, initial=None):
        """ساخت vault جدید. اگر فایل هست، باید اول reset شود."""
        with self._lock:
            if mode not in MODES:
                raise VaultError("حالت امنیتی نامعتبر است.")
            if self.path.exists():
                raise VaultError("فایل اسرار از قبل وجود دارد.")
            if mode == "password":
                errs = check_password(password, self.settings.get("security", "strong_policy", default=True))
                if errs:
                    raise VaultError("رمز اصلی شرایط لازم را ندارد: " + "، ".join(errs))
            salt = os.urandom(SALT_LEN)
            key = os.urandom(KEY_LEN) if mode == "simple" else self._key_for(mode, password, salt)
            self._key, self._salt, self._data = key, salt, dict(initial or {})
            self._persist(key, salt)
            if mode == "simple" or (mode == "password" and remember):
                self._store_key(key, salt)
            else:
                self._drop_key_file()
            self.settings.update({"security": {"mode": mode, "remember": bool(remember and mode == "password")}})

    def auto_unlock(self):
        """بدون دخالت کاربر: simple، یا password با «باز شدن خودکار». True اگر باز شد."""
        with self._lock:
            if paths.is_server():
                return False   # حالت سرور: فقط با ورود کاربر از وب باز می‌شود
            if not self.initialized() or self.unlocked():
                return self.unlocked()
            m = self.mode
            try:
                if m == "simple" or (m == "password" and self.settings.get("security", "remember", default=False)):
                    key, salt = self._load_key()
                else:
                    return False
                self._open(key)
                return True
            except (OSError, VaultError, ValueError) as e:
                log.warning("باز شدن خودکار vault ناموفق: %s", e)
                return False

    # ---------------------------------------------------------------- کاربران (فقط حالت رمز اصلی)
    # کلید vault (K) برای هر کاربر جداگانه با کلید مشتق از رمز خودش (scrypt + AES-GCM) رمز می‌شود.
    # رکوردها در settings.users هستند (settings.dat خودش رمزشده است). رمز هیچ کاربری ذخیره نمی‌شود.
    USER_AAD = b"autokrp-user:"
    ROLES = ("admin", "operator", "readonly")

    def users(self):
        return list(self.settings.get("users", default=[]) or [])

    def users_enabled(self):
        return self.mode == "password" and bool(self.users())

    def _wrap(self, username, password):
        salt = os.urandom(SALT_LEN)
        uk = derive_key(password, salt)
        nonce = os.urandom(NONCE_LEN)
        ct = AESGCM(uk).encrypt(nonce, self._key, self.USER_AAD + username.lower().encode("utf-8"))
        return {"salt": salt.hex(), "wrap": (nonce + ct).hex()}

    def _unwrap(self, rec, password):
        try:
            uk = derive_key(password or "", bytes.fromhex(rec["salt"]))
            raw = bytes.fromhex(rec["wrap"])
            return AESGCM(uk).decrypt(raw[:NONCE_LEN], raw[NONCE_LEN:], self.USER_AAD + rec["username"].lower().encode("utf-8"))
        except (InvalidTag, ValueError, KeyError):
            return None

    def find_user(self, username):
        u = (username or "").strip().lower()
        return next((x for x in self.users() if x.get("username", "").lower() == u), None)

    def make_user(self, username, password, role, tools=None, disabled=False):
        """رکورد کاربر تازه یا رمز تازه؛ کلید vault باید در حافظه باشد. ذخیره با فراخوان است."""
        with self._lock:
            self._require()
            if self.mode != "password":
                raise VaultError("کاربران فقط در حالت رمز اصلی فعال می‌شوند.")
            if not re.match(r"^[A-Za-z0-9_.-]{2,32}$", username or ""):
                raise VaultError("نام کاربری باید ۲ تا ۳۲ نویسه از حروف انگلیسی، عدد، نقطه، - یا _ باشد.")
            if role not in self.ROLES:
                raise VaultError("نقش نامعتبر است.")
            errs = check_password(password or "", self.settings.get("security", "strong_policy", default=True))
            if errs:
                raise VaultError("رمز شرایط لازم را ندارد: " + "، ".join(errs))
            return {"username": username, "role": role, "tools": list(tools or []), "disabled": bool(disabled),
                    **self._wrap(username, password)}

    def rewrap(self, rec, password):
        with self._lock:
            self._require()
            errs = check_password(password or "", self.settings.get("security", "strong_policy", default=True))
            if errs:
                raise VaultError("رمز شرایط لازم را ندارد: " + "، ".join(errs))
            return {**rec, **self._wrap(rec["username"], password)}

    def unlock_user(self, username, password):
        """ورود با نام کاربری و رمز. خروجی: رکورد کاربر."""
        with self._lock:
            rec = self.find_user(username)
            key = self._unwrap(rec, password) if rec else None
            if rec is None or key is None:
                if rec is None:
                    derive_key(password or "x", b"0" * SALT_LEN)   # زمان پاسخ یکسان برای نام کاربری نامعتبر
                raise VaultError("نام کاربری یا رمز اشتباه است.")
            if rec.get("disabled"):
                raise VaultError("این حساب غیرفعال است.")
            if self._key is not None:
                if not hmac.compare_digest(key, self._key):
                    raise VaultError("کلید این کاربر با فایل اسرار نمی‌خواند.")
                self.ui_locked = False
            else:
                self._open(key)
            return rec

    def verify_master(self, password):
        """رمز اصلی (حالت بدون کاربر) درست است؟ فقط وقتی کلید در حافظه است."""
        with self._lock:
            if self.mode != "password" or self._key is None or self._salt is None:
                return False
            return hmac.compare_digest(derive_key(password or "", self._salt), self._key)

    def verify_user(self, username, password):
        rec = self.find_user(username)
        return bool(rec and self._unwrap(rec, password) is not None)

    def unlock(self, password):
        with self._lock:
            if self.ui_locked and self._key is not None:
                # قفل رابط: کلید در حافظه است؛ فقط درستی رمز بررسی می‌شود
                if self.mode == "password" and not hmac.compare_digest(derive_key(password or "", self._salt), self._key):
                    raise VaultError("رمز اشتباه یا فایل دست‌کاری شده")
                self.ui_locked = False
                return
            if not self.initialized():
                raise VaultError("فایل اسرار هنوز ساخته نشده است.")
            blob = self.path.read_bytes()
            salt, _n, _c = split_blob(blob)
            key = self._key_for(self.mode if self.mode != "simple" else "password", password, salt)
            self._open(key, blob)

    def _open(self, key, blob=None):
        blob = blob or self.path.read_bytes()
        data = decrypt_blob(key, blob)
        self._key, self._salt, self._data = key, split_blob(blob)[0], data
        self.ui_locked = False

    def lock(self, full=False):
        """full=False: فقط رابط قفل می‌شود و کارهای خودکار ادامه دارند. full=True: کلید از حافظه پاک می‌شود."""
        with self._lock:
            if self.mode != "password":
                raise VaultError("قفل فقط در حالت رمز اصلی معنا دارد.")
            if full:
                self._key = self._salt = self._data = None
                self.ui_locked = False
            else:
                self.ui_locked = True

    def forget(self):
        """پاک کردن کلید و اسرار از حافظه (پیش از پاک کردن کامل داده‌ها)."""
        with self._lock:
            self._key = self._salt = self._data = None
            self.ui_locked = False

    def change(self, mode, password="", remember=False):
        """تغییر حالت یا رمز: همه‌ی اسرار با کلید جدید دوباره رمز می‌شوند."""
        with self._lock:
            self._require()
            if self.users_enabled():
                raise VaultError("با فعال بودن کاربران، حالت یا کلید عوض نمی‌شود. رمز هر کاربر در «کاربران» تغییر می‌کند؛ "
                                 "برای برگشت به حالت تک‌رمزی، کاربران را غیرفعال کنید.")
            if mode not in MODES:
                raise VaultError("حالت امنیتی نامعتبر است.")
            if mode == "password":
                errs = check_password(password, self.settings.get("security", "strong_policy", default=True))
                if errs:
                    raise VaultError("رمز اصلی شرایط لازم را ندارد: " + "، ".join(errs))
            salt = os.urandom(SALT_LEN)
            key = os.urandom(KEY_LEN) if mode == "simple" else self._key_for(mode, password, salt)
            self._persist(key, salt)
            self._recovery_rekey(key, drop=mode != "password")
            self._key, self._salt = key, salt
            if mode == "simple" or (mode == "password" and remember):
                self._store_key(key, salt)
            else:
                self._drop_key_file()
            self.settings.update({"security": {"mode": mode, "remember": bool(remember and mode == "password")}})

    def rekey_random(self):
        """کلید تصادفی تازه (حالت کاربران): همه‌ی اسرار دوباره رمز می‌شوند؛ رمز اصلی قبلی دیگر کار نمی‌کند."""
        with self._lock:
            self._require()
            key, salt = os.urandom(KEY_LEN), os.urandom(SALT_LEN)
            self._persist(key, salt)
            self._recovery_rekey(key)
            self._key, self._salt = key, salt
            if self.settings.get("security", "remember", default=False):
                self._store_key(key, salt)

    def set_remember(self, on):
        with self._lock:
            self._require()
            if self.mode != "password":
                raise VaultError("این گزینه فقط در حالت رمز اصلی است.")
            if on and len(self.users()) > 1:
                raise VaultError("با چند کاربر «باز شدن خودکار» ممکن نیست؛ معلوم نیست برنامه با کدام کاربر باز شود.")
            if on:
                self._store_key(self._key, self._salt)
            else:
                self._drop_key_file()
            self.settings.update({"security": {"remember": bool(on)}})

    # ---------------------------------------------------------------- کد بازیابی (1.27.8؛ autokrp/recovery.py)
    # settings.security.recovery = {rc: R با کد، rk: کلید vault با R، kr: R با کلید vault، created}
    def recovery_status(self):
        r = self.settings.get("security", "recovery", default=None) or {}
        return {"has": bool(r.get("rc") and r.get("rk")), "created": r.get("created")}

    def recovery_create(self):
        """کد تازه (کد قبلی باطل). خروجی: کد — فقط همین یک بار در دسترس است."""
        from . import recovery as rc
        with self._lock:
            self._require()
            if self.mode != "password":
                raise VaultError("کد بازیابی فقط در حالت رمز اصلی معنا دارد.")
            old = self.settings.get("security", "recovery", default=None) or {}
            R = rc._dec(self._key, old["kr"]) if old.get("kr") else None
            R = R or os.urandom(KEY_LEN)
            code = rc.new_code()
            rec = {"rc": rc.seal(R, code), "rk": rc._enc(R, self._key), "kr": rc._enc(self._key, R), "created": time.time()}
            self.settings.set_recovery(rec)
            return code

    def recovery_open(self, code):
        """کلید vault از کد بازیابی. خطا: VaultError (بدون گفتن این‌که کد یا رکورد مشکل دارد)."""
        from . import recovery as rc
        r = self.settings.get("security", "recovery", default=None) or {}
        R = rc.open_(r.get("rc"), code) if r.get("rc") else None
        key = rc._dec(R, r.get("rk", "")) if R else None
        if not key:
            if not R:
                derive_key("x", b"0" * SALT_LEN) if not r.get("rc") else None   # زمان پاسخ نزدیک
            raise VaultError("کد بازیابی درست نیست.")
        return key

    def _recovery_rekey(self, new_key, drop=False):
        """کلید vault عوض شد (تغییر رمز اصلی، فعال/غیرفعال کردن کاربران): کد بازیابی قبلی معتبر می‌ماند."""
        from . import recovery as rc
        r = self.settings.get("security", "recovery", default=None) or {}
        if not r.get("kr"):
            return
        if drop:                                     # حالت ساده: رمزی نیست که بازیابی شود
            self.settings.set_recovery(None)
            return
        R = rc._dec(self._key, r["kr"]) if self._key else None
        if not R:
            log.warning("کد بازیابی با کلید فعلی باز نشد؛ کد قبلی باطل شد")
            self.settings.set_recovery(None)
            return
        self.settings.set_recovery({**r, "rk": rc._enc(R, new_key), "kr": rc._enc(new_key, R)})

    # ---------------------------------------------------------------- data
    def _require(self):
        if self._data is None:
            raise VaultLocked("برنامه قفل است. ابتدا رمز اصلی را وارد کنید.")

    def _persist(self, key=None, salt=None):
        write_secure(self.path, encrypt_blob(key or self._key, salt or self._salt, self._data))

    def get(self, name, default=""):
        with self._lock:
            if self._data is None:
                return default
            return self._data.get(name, default)

    def has(self, name):
        with self._lock:
            return bool(self._data and self._data.get(name))

    def set(self, name, value):
        with self._lock:
            self._require()
            if value in (None, ""):
                self._data.pop(name, None)
            else:
                self._data[name] = value
            self._persist()

    def set_many(self, items: dict):
        with self._lock:
            self._require()
            for k, v in items.items():
                if v in (None, ""):
                    self._data.pop(k, None)
                else:
                    self._data[k] = v
            self._persist()

    def keys(self, prefix=""):
        with self._lock:
            return [k for k in (self._data or {}) if k.startswith(prefix)]

    def delete_prefix(self, prefix):
        with self._lock:
            self._require()
            for k in [k for k in self._data if k.startswith(prefix)]:
                del self._data[k]
            self._persist()

    # ---------------------------------------------------------------- خروجی‌های حساس (مثلاً خروجی SSH)
    OUT_AAD = b"autokrp-output" + bytes([VERSION])

    def _output_key(self):
        """کلید جدا که داخل خود vault نگهداری می‌شود؛ با تغییر رمز اصلی عوض نمی‌شود و خروجی‌های قبلی خوانا می‌مانند."""
        import base64
        with self._lock:
            self._require()
            k = self._data.get("sys.output_key")
            if not k:
                k = base64.b64encode(os.urandom(KEY_LEN)).decode()
                self.set("sys.output_key", k)
            return base64.b64decode(k)

    def encrypt_bytes(self, data: bytes) -> bytes:
        nonce = os.urandom(NONCE_LEN)
        return bytes([VERSION]) + nonce + AESGCM(self._output_key()).encrypt(nonce, data, self.OUT_AAD)

    def decrypt_bytes(self, blob: bytes) -> bytes:
        if len(blob) < 1 + NONCE_LEN + TAG_LEN or blob[0] != VERSION:
            raise VaultError("فایل خروجی ناقص یا نسخه‌ی آن ناشناخته است.")
        try:
            return AESGCM(self._output_key()).decrypt(blob[1:1 + NONCE_LEN], blob[1 + NONCE_LEN:], self.OUT_AAD)
        except InvalidTag:
            raise VaultError("فایل خروجی دست‌کاری شده یا با کلید دیگری رمز شده است.")
