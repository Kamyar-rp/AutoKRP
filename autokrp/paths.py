"""مسیر منابع (سازگار با PyInstaller) و مسیر داده در %LOCALAPPDATA%"""
import os
import sys
from pathlib import Path

from . import APP_ID

_DEMO = False
_ROOT = None          # --data-root (اجرای پس‌زمینه با Task Scheduler)؛ پیش‌فرض %LOCALAPPDATA%
_MODE = "client"      # client (دسکتاپ، DPAPI) یا server (وب، چندکاربره)
MODE_FILE = ".mode"


def set_demo(flag: bool):
    global _DEMO
    _DEMO = bool(flag)


def is_demo() -> bool:
    return _DEMO


def set_mode(m: str):
    global _MODE
    _MODE = "server" if m == "server" else "client"


def mode() -> str:
    return _MODE


def is_server() -> bool:
    return _MODE == "server"


def saved_mode():
    """حالت ذخیره‌شده از اولین اجرا؛ None یعنی هنوز انتخاب نشده."""
    d = data_dir()
    p = d / MODE_FILE
    if p.exists():
        v = p.read_text(encoding="utf-8").strip()
        return "server" if v == "server" else "client"
    # نصب‌های قبل از 1.4 (داده‌ی کلاینت دارند): بدون پرسیدن، کلاینت
    if any((d / f).exists() for f in (".data_key.bin", "settings.dat", "settings.json", ".cfg_data.bin", "state.dat", "state.sdb")):
        save_mode("client")
        return "client"
    return None


def save_mode(m: str):
    (data_dir() / MODE_FILE).write_text("server" if m == "server" else "client", encoding="utf-8")


def resource_dir() -> Path:
    base = getattr(sys, "_MEIPASS", None)
    if base:
        return Path(base)
    return Path(__file__).resolve().parent.parent


def ui_dir() -> Path:
    return resource_dir() / "ui"


def set_root(p):
    global _ROOT
    _ROOT = Path(p) if p else None


def root() -> Path:
    return _root()


def _root() -> Path:
    if _ROOT is not None:
        return _ROOT
    return default_root()


def default_root() -> Path:
    return Path(os.environ.get("LOCALAPPDATA") or os.path.join(Path.home(), ".local", "share"))


# ---------------------------------------------------------------- پوشه‌ی داده‌ی دلخواه (1.26.2)
# در اولین اجرا کاربر پوشه‌ی داده را انتخاب می‌کند؛ داده‌ها در «<پوشه‌ی انتخابی>\AutoKRP» ذخیره می‌شوند
# (همیشه یک زیرپوشه‌ی جدا، تا RESET هرگز فایل‌های دیگر آن پوشه را پاک نکند). نشانی این پوشه در فایل کوچک
# «%LOCALAPPDATA%\AutoKRP\.location» است؛ بعداً فقط با RESET عوض می‌شود.
LOCATION_FILE = ".location"
_DATA_MARKERS = (MODE_FILE, ".data_key.bin", "settings.dat", "settings.json", ".cfg_data.bin", "state.dat", "state.sdb",
                 ".server_auth.json")


def location_file() -> Path:
    return default_root() / APP_ID / LOCATION_FILE


def saved_location():
    """ریشه‌ی انتخاب‌شده (پوشه‌ای که AutoKRP داخلش است) یا None (پیش‌فرض %LOCALAPPDATA%)."""
    f = location_file()
    try:
        import json
        v = json.loads(f.read_text(encoding="utf-8")).get("root")
    except (OSError, ValueError, AttributeError):
        return None
    return Path(v) if isinstance(v, str) and v.strip() else None


def save_location(root):
    """root = پوشه‌ی انتخابی کاربر. انتخاب همان پیش‌فرض = فایلی نوشته نمی‌شود."""
    import json
    root = Path(root)
    f = location_file()
    if os.path.normcase(os.path.abspath(str(root))) == os.path.normcase(os.path.abspath(str(default_root()))):
        clear_location()
        return
    f.parent.mkdir(parents=True, exist_ok=True)
    tmp = f.with_name(f.name + ".tmp")
    tmp.write_text(json.dumps({"root": str(root)}, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, f)


# ---------------------------------------------------------------- زبان پنجره‌های بومی (1.30)
# پنجره‌های پیش از باز شدن داده (انتخاب حالت، وضعیت سرور، پیام‌ها، منوی tray) زبان آخرین انتخاب کاربر را از این
# فایل کوچک می‌خوانند؛ پیش‌فرض انگلیسی. محتوای حساسی ندارد.
LANG_FILE = ".lang"


def ui_lang() -> str:
    try:
        v = (default_root() / APP_ID / LANG_FILE).read_text(encoding="ascii").strip()
    except (OSError, UnicodeDecodeError):
        return "en"
    return "fa" if v == "fa" else "en"


def set_ui_lang(lang: str):
    try:
        d = default_root() / APP_ID
        d.mkdir(parents=True, exist_ok=True)
        (d / LANG_FILE).write_text("fa" if lang == "fa" else "en", encoding="ascii")
    except OSError:
        pass


def L(fa: str, en: str) -> str:
    """متن پنجره‌های بومی به زبان انتخابی."""
    return fa if ui_lang() == "fa" else en


def clear_location():
    try:
        location_file().unlink()
    except OSError:
        pass


def has_app_data(d: Path) -> bool:
    return any((Path(d) / m).exists() for m in _DATA_MARKERS)


def _is_remote_drive(p: str) -> bool:
    """ویندوز: درایو شبکه‌ای (Map Network Drive). پایگاه داده‌ی SQLCipher با WAL روی اشتراک شبکه قابل اعتماد نیست."""
    if sys.platform != "win32":
        return False
    try:
        import ctypes
        drive = os.path.splitdrive(os.path.abspath(p))[0]
        return bool(drive) and ctypes.windll.kernel32.GetDriveTypeW(drive + "\\") == 4     # DRIVE_REMOTE
    except Exception:
        return False


def check_location(root):
    """بررسی پوشه‌ی انتخابی. خروجی dict: dir (پوشه‌ی داده)، existing (حالت داده‌ی قبلی یا None)، free_gb.
    خطا: ValueError با پیام فارسی."""
    raw = str(root or "").strip().strip('"')
    if not raw:
        raise ValueError("پوشه‌ای انتخاب نشده است.")
    if raw.startswith(("\\\\", "//")):
        raise ValueError("مسیر شبکه‌ای (\\\\server\\share) پشتیبانی نمی‌شود؛ یک پوشه روی دیسک همین سیستم انتخاب کنید.")
    if not os.path.isabs(raw):
        raise ValueError("مسیر کامل لازم است (مثلاً D:\\Data).")
    if _is_remote_drive(raw):
        raise ValueError("این درایو شبکه‌ای است؛ پایگاه داده روی درایو شبکه قابل اعتماد نیست. یک دیسک محلی انتخاب کنید.")
    base = Path(raw)
    if not base.is_dir():
        raise ValueError(f"پوشه پیدا نشد: {raw}")
    d = base / APP_ID
    existing = None
    if d.exists():
        if not d.is_dir():
            raise ValueError(f"در این مسیر فایلی به نام {APP_ID} هست؛ پوشه‌ی دیگری انتخاب کنید.")
        if any(x.name not in (LOCATION_FILE, ".write_test") for x in d.iterdir()) and not has_app_data(d):
            # RESET کل این زیرپوشه را پاک می‌کند؛ پس پوشه‌ی پر با داده‌ی ناشناخته هرگز پذیرفته نمی‌شود
            raise ValueError(f"پوشه‌ی {d} از قبل هست و داده‌ی AutoKRP نیست؛ پوشه‌ی دیگری انتخاب کنید.")
        mf = d / MODE_FILE
        if mf.exists():
            existing = "server" if mf.read_text(encoding="utf-8").strip() == "server" else "client"
        elif has_app_data(d):
            existing = "client"
    try:                                   # دسترسی نوشتن
        d.mkdir(exist_ok=True)
        t = d / ".write_test"
        t.write_bytes(b"ok")
        t.unlink()
    except OSError as e:
        raise ValueError(f"اجازه‌ی نوشتن در این پوشه نیست: {e.strerror or e}")
    try:
        import shutil
        free = shutil.disk_usage(str(d)).free / 1024 ** 3
    except OSError:
        free = None
    return {"dir": str(d), "existing": existing, "free_gb": round(free, 1) if free is not None else None}


def restrict_dir(d):
    """ویندوز: پوشه‌ی داده‌ی دلخواه فقط برای کاربر جاری (و SYSTEM)، با ارث‌بری به فایل‌ها و زیرپوشه‌ها؛
    مثل حفاظت پیش‌فرض %LOCALAPPDATA% (پوشه‌ای مثل D:\\ ممکن است برای همه‌ی کاربران خواندنی باشد)."""
    if sys.platform != "win32":
        try:
            os.chmod(d, 0o700)
        except OSError:
            pass
        return
    user = os.environ.get("USERNAME") or ""
    if not user:
        return
    import subprocess
    icacls = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "icacls.exe")
    try:
        subprocess.run([icacls, str(d), "/inheritance:r", "/grant:r", f"{user}:(OI)(CI)F", "*S-1-5-18:(OI)(CI)F"],  # nosec B603
                       capture_output=True, timeout=30, creationflags=0x08000000)
    except Exception:  # noqa — بدون ACL هم داده‌ها رمزشده‌اند
        pass


def data_dir() -> Path:
    p = _root() / APP_ID
    if _DEMO:
        p = p / "demo"
    p.mkdir(parents=True, exist_ok=True)
    return p


def logs_dir() -> Path:
    p = data_dir() / "logs"
    p.mkdir(parents=True, exist_ok=True)
    return p


def runs_dir() -> Path:
    p = data_dir() / "runs"
    p.mkdir(parents=True, exist_ok=True)
    return p


def inside(path, roots, allow_root=False):
    """آیا path داخل یکی از roots است؟ اول بدون دسترسی به دیسک (abspath/commonpath) بررسی می‌شود تا مسیر
    شبکه‌ای ویندوز (\\\\host\\share) هرگز باز نشود؛ بعد از resolve (پیوندها) دوباره. خروجی: مسیر resolve‌شده یا None."""
    p = str(path or "").strip().strip('"')
    if not p or p.startswith(("\\\\", "//")) or "\x00" in p:
        return None

    def ok(c, rs):
        for r in rs:
            try:
                common = os.path.commonpath([c, r])
            except ValueError:            # درایو یا نوع مسیر متفاوت
                continue
            if common == r and (allow_root or c != r):
                return True
        return False
    ap = os.path.normcase(os.path.abspath(p))
    rs = [os.path.normcase(os.path.abspath(str(r))) for r in roots]
    if not ok(ap, rs):
        return None
    try:
        rp = Path(p).resolve()
    except (OSError, ValueError):
        return None
    if not ok(os.path.normcase(str(rp)), [os.path.normcase(str(Path(r).resolve())) for r in roots]):
        return None
    return rp


def user_file(path) -> str:
    """مسیر فایلی که کاربر برای ورودی داده (CSV) وارد کرده است. در حالت سرور فقط فایل‌های آپلودشده‌ی
    همین برنامه مجازند تا کاربران وب نتوانند فایل‌های دلخواه سیستم سرور را بخوانند."""
    p = str(path or "").strip().strip('"')
    if not p or not is_server():
        return p
    rp = inside(p, [data_dir() / x for x in ("uploads", "jobfiles")])
    if rp is None:
        raise PermissionError("در حالت سرور فقط فایل‌های آپلودشده قابل استفاده‌اند؛ فایل را با «انتخاب…» آپلود کنید.")
    return str(rp)
