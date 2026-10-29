"""باز شدن خودکار حالت سرور پس از ری‌استارت (1.24، اختیاری، فقط ادمین).

بدون این گزینه کلید اصلی فقط با رمز یک کاربر محلی باز می‌شود؛ یعنی بعد از ری‌استارت ویندوز، مانیتورینگ و کارهای
زمان‌بندی‌شده تا ورود یک کاربر اجرا نمی‌شوند و کاربران AD هم وارد نمی‌شوند.
با این گزینه کلید اصلی با DPAPI در حوزه‌ی «ماشین» (CRYPTPROTECT_LOCAL_MACHINE) رمز و در .server_unseal.bin
(ACL فقط کاربر جاری) ذخیره می‌شود. حوزه‌ی ماشین لازم است چون تسک S4U (اجرای خودکار بدون ذخیره‌ی رمز ویندوز) به کلید
DPAPI کاربر دسترسی ندارد. نتیجه: هر کس کنترل این ویندوز (حساب سرویس یا ادمین ویندوز) را داشته باشد داده‌ها را باز می‌کند.
"""
import logging

from . import dpapi, paths, wipe

log = logging.getLogger(__name__)
FILE = ".server_unseal.bin"
MAGIC = b"AKRPUS1"


def _path():
    return paths.data_dir() / FILE


def available():
    """ویندوز؛ یا تست صریح روی سیستم دیگر (AUTOKRP_INSECURE_TEST / Demo)."""
    if dpapi.AVAILABLE:
        return True
    try:
        dpapi._allowed()
        return True
    except OSError:
        return False


def enabled():
    return _path().exists()


def enable(master):
    from .vault import write_secure
    if not available():
        raise OSError("باز شدن خودکار فقط روی ویندوز (DPAPI) ممکن است.")
    write_secure(_path(), MAGIC + dpapi.protect(bytes(master), machine=True))


def disable():
    p = _path()
    if p.exists():
        try:
            wipe.overwrite(p)
        except Exception:  # noqa — بازنویسی ممکن نشد؛ دست‌کم حذف
            pass
        p.unlink(missing_ok=True)


def load():
    """کلید اصلی یا None."""
    p = _path()
    if not p.exists():
        return None
    try:
        raw = p.read_bytes()
        if not raw.startswith(MAGIC):
            raise ValueError("قالب نامعتبر")
        m = dpapi.unprotect(raw[len(MAGIC):])
        return m if len(m) == 32 else None
    except Exception as e:  # noqa — مثلاً فایل از سیستم دیگری کپی شده
        log.error("باز شدن خودکار ممکن نشد: %s", e)
        return None
