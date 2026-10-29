"""
رمزنگاری داده‌ها روی دیسک (at-rest).

همه‌ی داده‌های برنامه (پایگاه داده، تنظیمات، فایل‌های اجرا، لاگ‌ها) با یک «کلید داده»ی جدا رمز می‌شوند.
این کلید با Windows DPAPI به همین کاربر ویندوز بسته است، در هر دو حالت vault. پس اگر فایل یا کل پوشه
روی سیستم یا کاربر دیگری کپی شود، خوانا نیست. اسرار (توکن و رمزها) جدا از این، داخل vault هستند.

فایل‌های قدیمیِ بدون رمز هنگام خواندن شناخته و همان‌طور خوانده می‌شوند (سازگاری و مهاجرت).
"""
import base64
import io
import logging
import os
import struct
import threading
from logging.handlers import RotatingFileHandler
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import dpapi, paths

log = logging.getLogger(__name__)

MAGIC = b"AKRPD1"
NONCE_LEN = 12
KEY_FILE = ".data_key.bin"
_key = None
_key_dir = None
_lock = threading.RLock()
_override = None       # کلید داده در حالت سرور (بعد از ورود کاربر؛ هیچ‌جا ساده ذخیره نمی‌شود)
_server = False        # حالت سرور: کلید فقط از ورود کاربر می‌آید، نه DPAPI


class AtRestError(Exception):
    pass


def set_server_mode(on: bool):
    global _server
    _server = bool(on)


def set_key(k):
    """حالت سرور: کلید داده را از کلید اصلی باز‌شده با رمز کاربر می‌گیرد."""
    global _override, _key_dir
    with _lock:
        if k is not None and len(k) != 32:
            raise AtRestError("کلید داده نامعتبر است.")
        _override = bytes(k) if k else None
        _key_dir = paths.data_dir() if k else None


def has_key() -> bool:
    with _lock:
        return _override is not None if _server else True


def _key_path() -> Path:
    return paths.data_dir() / KEY_FILE


def key() -> bytes:
    """کلید داده. حالت کلاینت: DPAPI. حالت سرور: کلید در حافظه پس از ورود."""
    global _key, _key_dir
    with _lock:
        if _server:
            if _override is None:
                raise AtRestError("برای دسترسی به داده‌ها باید وارد شوید.")
            return _override
        d = paths.data_dir()
        if _key is not None and _key_dir == d:
            return _key
        p = d / KEY_FILE
        if p.exists():
            try:
                raw = dpapi.unprotect(p.read_bytes())
            except OSError:
                raise AtRestError("کلید داده‌ها روی این کاربر ویندوز باز نمی‌شود؛ داده‌ها متعلق به کاربر یا سیستم دیگری است.")
            if len(raw) != 32:
                raise AtRestError("فایل کلید داده‌ها خراب است.")
            _key = raw
        else:
            if not dpapi.AVAILABLE:
                log.warning("DPAPI در دسترس نیست (غیرویندوز)؛ کلید داده‌ها محافظت واقعی ندارد.")
            from .vault import write_secure
            _key = os.urandom(32)
            write_secure(p, dpapi.protect(_key))
        _key_dir = d
        return _key


def forget():
    """پاک کردن کلید از حافظه (RESET یا قفل کامل سرور)."""
    global _key, _key_dir, _override
    with _lock:
        _key = None
        _key_dir = None
        _override = None


def is_encrypted(blob: bytes) -> bool:
    return blob[:len(MAGIC)] in (MAGIC, MAGIC2)


# قالب ۲ (فایل‌های بزرگ، مثل پایگاه داده): رمز تکه‌به‌تکه تا نه کل داده‌ی رمزشده در حافظه ساخته شود و نه کل فایل
# برای خواندن. MAGIC2 + پیشوند ۸ بایتی تصادفی، سپس تکه‌ها: [طول ۴ بایت][متن رمزشده + tag].
# nonce هر تکه = پیشوند + شماره‌ی تکه؛ AAD = MAGIC2 + شماره + پرچم «تکه‌ی آخر». پس جابه‌جا کردن، حذف، تکرار
# یا بریدن انتهای فایل (حتی دقیقاً در مرز تکه) با خطای اعتبارسنجی رد می‌شود.
MAGIC2 = b"AKRPD2"
CHUNK = 1024 * 1024
_PFX = 8


def _aad2(i, last):
    return MAGIC2 + struct.pack("!IB", i, 1 if last else 0)


def _enc_chunks(data, k):
    """تولیدکننده‌ی بایت‌های قالب ۲ (هر بار یک تکه)."""
    mv = memoryview(data)
    pfx = os.urandom(_PFX)
    yield MAGIC2 + pfx
    a = AESGCM(k)
    n = max(1, -(-len(mv) // CHUNK))
    for i in range(n):
        ct = a.encrypt(pfx + struct.pack("!I", i), mv[i * CHUNK:(i + 1) * CHUNK], _aad2(i, i == n - 1))
        yield struct.pack("!I", len(ct)) + ct


def _dec_stream(f, k, total=None):
    """خواندن قالب ۲ از فایل باز (بعد از MAGIC2) ← bytearray."""
    pfx = f.read(_PFX)
    if len(pfx) != _PFX:
        raise AtRestError("فایل رمزشده ناقص است.")
    a, out, i = AESGCM(k), bytearray(), 0
    h = f.read(4)
    while True:
        if len(h) < 4:
            raise AtRestError("فایل رمزشده ناقص است.")
        ln = struct.unpack("!I", h)[0]
        if ln > CHUNK + 16:
            raise AtRestError("فایل دست‌کاری شده است.")
        ct = f.read(ln)
        nxt = f.read(4)
        last = not nxt
        try:
            out += a.decrypt(pfx + struct.pack("!I", i), ct, _aad2(i, last))
        except InvalidTag:
            raise AtRestError("فایل دست‌کاری شده یا با کلید کاربر دیگری رمز شده است.")
        if last:
            return out
        h, i = nxt, i + 1


def encrypt(data: bytes) -> bytes:
    nonce = os.urandom(NONCE_LEN)
    return MAGIC + nonce + AESGCM(key()).encrypt(nonce, data, MAGIC)


def decrypt(blob: bytes) -> bytes:
    if not is_encrypted(blob):
        raise AtRestError("فایل رمزشده‌ی AutoKRP نیست.")
    if blob[:len(MAGIC2)] == MAGIC2:
        return bytes(_dec_stream(io.BytesIO(memoryview(blob)[len(MAGIC2):]), key()))
    n = len(MAGIC)
    try:
        return AESGCM(key()).decrypt(blob[n:n + NONCE_LEN], blob[n + NONCE_LEN:], MAGIC)
    except InvalidTag:
        raise AtRestError("فایل دست‌کاری شده یا با کلید کاربر دیگری رمز شده است.")


# ------------------------------------------------------------------ فایل‌ها
def write_bytes(path, data: bytes):
    """نوشتن اتمیک و رمزشده: فایل موقتِ یکتا در همان پوشه (mkstemp، 0600)، fsync، سپس جایگزینی.
    نوشتن‌های هم‌زمان روی یک مقصد فایل موقت مشترک ندارند؛ فایل نهایی همیشه یک blob کامل است."""
    import tempfile
    import time as _t
    path = Path(path)
    big = len(data) > CHUNK
    parts = _enc_chunks(data, key()) if big else (encrypt(data),)     # بزرگ: بدون کپی کامل رمزشده در حافظه
    fd, name = tempfile.mkstemp(dir=str(path.parent), prefix=path.name + ".", suffix=".tmp")
    tmp = Path(name)
    try:
        try:
            for b in parts:
                mv = memoryview(b)
                while mv:
                    mv = mv[os.write(fd, mv):]
            os.fsync(fd)
        finally:
            os.close(fd)
        for i in range(20):       # ویندوز: اگر خواننده‌ای فایل را باز نگه داشته، کمی بعد دوباره
            try:
                os.replace(tmp, path)
                break
            except PermissionError:
                if i == 19:
                    raise
                _t.sleep(0.05)
    finally:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass


def read_bytes(path, mutable=False) -> bytes:
    """خواندن شفاف: فایل رمزشده باز می‌شود، فایل ساده (قدیمی یا ورودی کاربر) همان‌طور برمی‌گردد."""
    with open(path, "rb") as f:
        if f.read(len(MAGIC2)) == MAGIC2:
            out = _dec_stream(f, key())
            return out if mutable else bytes(out)    # mutable: bytearray بدون کپی دوم (پایگاه داده‌ی بزرگ)
    raw = Path(path).read_bytes()
    return decrypt(raw) if is_encrypted(raw) else raw


def write_text(path, text: str, encoding="utf-8"):
    write_bytes(path, text.encode(encoding))


def read_text(path, encoding="utf-8-sig", errors="replace") -> str:
    return read_bytes(path).decode(encoding, errors)


class _Writer(io.StringIO):
    def __init__(self, path, encoding):
        super().__init__(newline="")
        self._path, self._enc = path, encoding

    def __exit__(self, *exc):
        if exc[0] is None:
            write_text(self._path, self.getvalue(), self._enc)
        return super().__exit__(*exc)


def open_write(path, encoding="utf-8-sig"):
    """جایگزین open(path, "w", newline="") برای فایل‌های داخل پوشه‌ی داده. محتوا هنگام بستن رمز و ذخیره می‌شود."""
    return _Writer(path, encoding)


def open_read(path, encoding="utf-8-sig", errors="replace"):
    """جایگزین open(path, "r", newline="")؛ برای فایل رمزشده و ساده هر دو."""
    return io.StringIO(read_text(path, encoding, errors), newline="")


def encrypt_file_inplace(path) -> bool:
    """مهاجرت: فایل ساده را رمز می‌کند و نسخه‌ی ساده را بازنویسی و حذف می‌کند. True اگر تغییر کرد."""
    from . import wipe
    path = Path(path)
    raw = path.read_bytes()
    if is_encrypted(raw):
        return False
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_bytes(encrypt(raw))
    wipe.overwrite(path)
    os.replace(tmp, path)
    return True


def export_dir(src, dest) -> int:
    """رمزگشایی فایل‌های یک پوشه (مثل یک اجرا) به مقصد انتخابی کاربر. خروجی: تعداد فایل‌ها."""
    src, dest = Path(src), Path(dest)
    files = [src] if src.is_file() else [p for p in sorted(src.rglob("*")) if p.is_file() and not p.name.endswith(".tmp")]
    n = 0
    for f in files:
        rel = f.name if src.is_file() else f.relative_to(src)
        out = dest / rel
        out.parent.mkdir(parents=True, exist_ok=True)
        if f.suffix.lower() == ".log" or ".log." in f.name:
            out.write_text("\n".join(read_log_lines(f)) + "\n", encoding="utf-8")
        elif f.suffix.lower() == ".csv":     # بیرون از برنامه با Excel باز می‌شود: بدون فرمول اجرایی
            from .csvsafe import sanitize_bytes
            out.write_bytes(sanitize_bytes(read_bytes(f)))
        else:
            out.write_bytes(read_bytes(f))
        n += 1
    return n


# ------------------------------------------------------------------ لاگ
LOG_PREFIX = "AKRP:"


def _enc_line(text: str) -> str:
    return LOG_PREFIX + base64.b64encode(encrypt(text.encode("utf-8"))).decode("ascii")


def iter_log_lines(path):
    """مثل read_log_lines ولی خط‌به‌خط از دیسک (فایل‌های بزرگ کامل در حافظه نمی‌آیند)."""
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\r\n")
            if line.startswith(LOG_PREFIX):
                try:
                    yield decrypt(base64.b64decode(line[len(LOG_PREFIX):])).decode("utf-8", "replace")
                except (AtRestError, ValueError):
                    yield "[خط لاگ قابل رمزگشایی نیست]"
            elif line:
                yield line


def read_log_lines(path):
    out = []
    for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith(LOG_PREFIX):
            try:
                out.append(decrypt(base64.b64decode(line[len(LOG_PREFIX):])).decode("utf-8", "replace"))
            except (AtRestError, ValueError):
                out.append("[خط لاگ قابل رمزگشایی نیست]")
        else:
            out.append(line)
    return out


_PENDING = []          # حالت سرور: لاگ‌های پیش از اولین ورود (کلید هنوز نیست) در حافظه
_PENDING_MAX = 2000
_HANDLERS = []


class EncryptedLogHandler(RotatingFileHandler):
    """هر رکورد لاگ جدا رمز می‌شود (یک خط base64)، تا افزودن به فایل و چرخش مثل قبل کار کند.
    در حالت سرور پیش از ورود، لاگ‌ها در حافظه می‌مانند و بعد از ورود رمزشده نوشته می‌شوند."""

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        _HANDLERS.append(self)

    def format(self, record):
        return _enc_line(super().format(record))

    def emit(self, record):
        if not has_key():
            with _lock:
                if len(_PENDING) < _PENDING_MAX:
                    _PENDING.append(record)
            return
        super().emit(record)


def flush_pending_logs():
    with _lock:
        items = list(_PENDING)
        _PENDING.clear()
    for h in _HANDLERS:
        for r in items:
            try:
                RotatingFileHandler.emit(h, r)
            except Exception:
                pass


def encrypt_log_inplace(path) -> bool:
    path = Path(path)
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    if all(l.startswith(LOG_PREFIX) or not l for l in lines):
        return False
    from . import wipe
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text("".join((l if l.startswith(LOG_PREFIX) else _enc_line(l)) + "\n" for l in lines if l), encoding="utf-8")
    wipe.overwrite(path)
    os.replace(tmp, path)
    return True


# ------------------------------------------------------------------ مهاجرت یک‌باره
def migrate_plain_files():
    """رمز کردن فایل‌های ساده‌ی قدیمی در runs و logs. خروجی: تعداد فایل‌های رمزشده."""
    n = 0
    for p in (paths.data_dir() / "runs").rglob("*") if (paths.data_dir() / "runs").exists() else []:
        if p.is_file() and not p.name.endswith(".tmp"):
            try:
                n += encrypt_file_inplace(p)
            except OSError as e:
                log.warning("رمز کردن %s انجام نشد: %s", p, e)
    logs = paths.data_dir() / "logs"
    if logs.exists():
        for p in logs.iterdir():
            if p.is_file() and (p.name == "app.log" or p.name.startswith("app.log.")):
                try:
                    n += encrypt_log_inplace(p)
                except OSError as e:
                    log.warning("رمز کردن %s انجام نشد: %s", p, e)
    return n
