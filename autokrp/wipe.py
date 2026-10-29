"""
پاک‌سازی کامل (RESET): همه‌ی داده‌های برنامه در پوشه‌ی داده حذف می‌شوند.
فایل‌های حاوی اسرار و داده‌ی رمزشده پیش از حذف با بایت‌های تصادفی بازنویسی می‌شوند.
نکته: روی SSD به‌خاطر wear-leveling بازنویسی تضمین کامل نیست؛ چون این فایل‌ها از ابتدا رمزشده‌اند،
بدون کلید (که از حافظه و دیسک حذف می‌شود) بازیابی محتوایشان ممکن نیست.
"""
import logging
import os
import shutil
import stat
import sys
import time
from pathlib import Path

log = logging.getLogger(__name__)
SENSITIVE_SUFFIXES = (".bin", ".dat", ".db", ".db-wal", ".db-shm", ".sdb", ".sdb-wal", ".sdb-shm", ".pre122", ".json", ".csv", ".log", ".txt")


def _unhide(p):
    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.kernel32.SetFileAttributesW(str(p), 0x80)
        except Exception:
            pass
    try:
        os.chmod(p, stat.S_IWRITE | stat.S_IREAD)
    except OSError:
        pass


def overwrite(p: Path):
    if Path(p).is_symlink():
        return
    try:
        size = p.stat().st_size
        with open(p, "r+b", buffering=0) as f:
            left = size
            while left > 0:
                n = min(left, 1024 * 1024)
                f.write(os.urandom(n))
                left -= n
            f.flush()
            os.fsync(f.fileno())
    except OSError:
        pass


def wipe_dir(root: Path):
    """همه‌چیز زیر root را حذف می‌کند. خروجی: فهرست مسیرهایی که حذف نشدند."""
    root = Path(root)
    if not root.exists():
        return []
    for p in sorted(root.rglob("*"), key=lambda x: len(x.parts), reverse=True):
        if p.is_symlink():
            continue                       # 1.27.7: لینک فقط حذف می‌شود؛ فایلِ مقصد (شاید بیرون پوشه) هرگز بازنویسی نمی‌شود
        if p.is_file():
            _unhide(p)
            if p.suffix.lower() in SENSITIVE_SUFFIXES or p.name.startswith(".cfg_"):
                overwrite(p)
    left = []
    for attempt in range(5):
        try:
            retry = lambda f, path, exc: (_unhide(path), f(path))   # noqa: E731 — فایل فقط‌خواندنی/پنهان ویندوز
            if sys.version_info >= (3, 12):        # onerror از 3.12 منسوخ است
                shutil.rmtree(root, onexc=retry)
            else:
                shutil.rmtree(root, onerror=retry)
            return []
        except Exception:
            time.sleep(0.5)
    left = [str(p) for p in root.rglob("*")] or ([str(root)] if root.exists() else [])
    log.warning("wipe: %d مسیر حذف نشد", len(left))
    return left
