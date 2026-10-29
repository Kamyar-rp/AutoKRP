"""
اجرای خودکار سرور با روشن شدن ویندوز (بدون لاگین) با Task Scheduler.

- تسک با همان کاربر ویندوزی که نصب می‌کند و نوع ورود S4U اجرا می‌شود: رمز ویندوز ذخیره نمی‌شود و دسترسی
  اضافه‌ای (SYSTEM/Administrator) نمی‌گیرد؛ پوشه‌ی داده همان پوشه‌ی فعلی است (--data-root).
- نصب و حذف به دسترسی Administrator نیاز دارد؛ در صورت نیاز برنامه خودش با UAC دوباره اجرا می‌شود.
- قانون فایروال ورودی برای سرور هم‌زمان ساخته/حذف می‌شود.
- داده‌ها تا اولین ورود یک کاربر در وب قفل می‌مانند (کلید فقط از رمز کاربر می‌آید).
"""
import logging
import os
import subprocess  # nosec B404 — فقط ابزارهای خود ویندوز با مسیر کامل و آرگومان لیستی
import sys
import tempfile
from pathlib import Path
from xml.sax.saxutils import escape

log = logging.getLogger(__name__)

TASK = "AutoKRP Server"
FW_RULE = "AutoKRP Server"
NO_WINDOW = 0x08000000


class SvcError(Exception):
    pass


def supported() -> bool:
    return sys.platform == "win32"


def _sys32(name):
    # مسیر کامل؛ نه جست‌وجو در PATH
    return str(Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / name)


def _run(args, timeout=60):
    return subprocess.run(args, capture_output=True, timeout=timeout, creationflags=NO_WINDOW,  # nosec B603
                          stdin=subprocess.DEVNULL)


def _out(r):
    for enc in ("utf-8", "mbcs" if supported() else "latin-1", "latin-1"):
        try:
            return (r.stdout + r.stderr).decode(enc).strip()
        except (UnicodeDecodeError, LookupError):
            continue
    return ""


def is_admin() -> bool:
    if not supported():
        return False
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def current_user() -> str:
    dom, user = os.environ.get("USERDOMAIN", ""), os.environ.get("USERNAME", "")
    return f"{dom}\\{user}" if dom and user else user


def program():
    """(فایل اجرایی، آرگومان‌های پایه، پوشه‌ی کاری) همین برنامه."""
    if getattr(sys, "frozen", False):
        exe = Path(sys.executable).resolve()
        return str(exe), [], str(exe.parent)
    app = Path(__file__).resolve().parent.parent / "app.py"
    return str(Path(sys.executable).resolve()), [str(app)], str(app.parent)


def _cmdline(args):
    """نقل‌قول درست آرگومان‌ها طبق قواعد ویندوز (فاصله، " و \\ پایانی)."""
    return subprocess.list2cmdline([str(a) for a in args])


def installed() -> bool:
    if not supported():
        return False
    try:
        return _run([_sys32("schtasks.exe"), "/query", "/tn", TASK], timeout=20).returncode == 0
    except Exception:
        return False


def task_xml(user, data_root):
    exe, base, wd = program()
    args = _cmdline(base + ["--server", "--headless", "--data-root", str(data_root)])
    e = lambda v: escape(str(v))   # noqa: E731
    return f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Author>AutoKRP</Author><Description>AutoKRP server (HTTPS) — starts at Windows boot</Description></RegistrationInfo>
  <Triggers><BootTrigger><Enabled>true</Enabled><Delay>PT30S</Delay></BootTrigger></Triggers>
  <Principals><Principal id="Author"><UserId>{e(user)}</UserId><LogonType>S4U</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
    <RestartOnFailure><Interval>PT1M</Interval><Count>3</Count></RestartOnFailure>
  </Settings>
  <Actions Context="Author"><Exec><Command>{e(exe)}</Command><Arguments>{e(args)}</Arguments><WorkingDirectory>{e(wd)}</WorkingDirectory></Exec></Actions>
</Task>
"""


def _firewall_add(port):
    exe, base, _ = program()
    _run([_sys32("netsh.exe"), "advfirewall", "firewall", "delete", "rule", f"name={FW_RULE}"], timeout=30)
    args = [_sys32("netsh.exe"), "advfirewall", "firewall", "add", "rule", f"name={FW_RULE}", "dir=in", "action=allow",
            "protocol=TCP", "enable=yes"]
    # فایل اجرایی: قانون به برنامه بسته است (تغییر پورت بعداً هم کار می‌کند). حالت توسعه (python.exe): فقط پورت.
    args += [f"program={exe}"] if not base else [f"localport={int(port)}"]
    r = _run(args, timeout=30)
    if r.returncode != 0:
        log.warning("قانون فایروال ساخته نشد: %s", _out(r))
        return False
    return True


def install(user, data_root, port):
    if not supported():
        raise SvcError("فقط روی ویندوز.")
    if not is_admin():
        raise SvcError("برای نصب اجرای خودکار دسترسی Administrator لازم است.")
    user = (user or "").strip()
    if not user or any(c in user for c in '<>"|/'):
        raise SvcError("نام کاربر ویندوز نامعتبر است.")
    fd, tmp = tempfile.mkstemp(suffix=".xml", prefix="akrp_task_")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(task_xml(user, data_root).encode("utf-16"))
        r = _run([_sys32("schtasks.exe"), "/create", "/tn", TASK, "/xml", tmp, "/f"])
        if r.returncode != 0:
            raise SvcError("ساخت تسک ویندوز ناموفق بود: " + (_out(r) or f"کد {r.returncode}"))
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass
    fw = _firewall_add(port)
    log.info("اجرای خودکار سرور نصب شد (کاربر %s)", user)
    return {"firewall": fw}


def remove():
    if not supported():
        raise SvcError("فقط روی ویندوز.")
    if not is_admin():
        raise SvcError("برای حذف اجرای خودکار دسترسی Administrator لازم است.")
    sch = _sys32("schtasks.exe")
    _run([sch, "/end", "/tn", TASK], timeout=30)
    r = _run([sch, "/delete", "/tn", TASK, "/f"], timeout=30)
    _run([_sys32("netsh.exe"), "advfirewall", "firewall", "delete", "rule", f"name={FW_RULE}"], timeout=30)
    if r.returncode != 0 and installed():
        raise SvcError("حذف تسک ویندوز ناموفق بود: " + (_out(r) or f"کد {r.returncode}"))
    log.info("اجرای خودکار سرور حذف شد")


def run_now() -> bool:
    if not supported():
        return False
    r = _run([_sys32("schtasks.exe"), "/run", "/tn", TASK], timeout=30)
    return r.returncode == 0


def elevate(args) -> bool:
    """اجرای دوباره‌ی همین برنامه با UAC (runas) و آرگومان‌های داده‌شده؛ منتظر پایان می‌ماند."""
    if not supported():
        return False
    import ctypes
    from ctypes import wintypes
    exe, base, wd = program()
    params = _cmdline(base + list(args))

    class SEI(ctypes.Structure):
        _fields_ = [("cbSize", wintypes.DWORD), ("fMask", ctypes.c_ulong), ("hwnd", wintypes.HWND),
                    ("lpVerb", wintypes.LPCWSTR), ("lpFile", wintypes.LPCWSTR), ("lpParameters", wintypes.LPCWSTR),
                    ("lpDirectory", wintypes.LPCWSTR), ("nShow", ctypes.c_int), ("hInstApp", wintypes.HINSTANCE),
                    ("lpIDList", ctypes.c_void_p), ("lpClass", wintypes.LPCWSTR), ("hkeyClass", wintypes.HKEY),
                    ("dwHotKey", wintypes.DWORD), ("hIcon", wintypes.HANDLE), ("hProcess", wintypes.HANDLE)]
    sei = SEI(cbSize=ctypes.sizeof(SEI), fMask=0x40, lpVerb="runas", lpFile=exe, lpParameters=params,
              lpDirectory=wd, nShow=0)   # SEE_MASK_NOCLOSEPROCESS, پنجره‌ی پنهان
    if not ctypes.windll.shell32.ShellExecuteExW(ctypes.byref(sei)) or not sei.hProcess:
        return False                       # کاربر UAC را رد کرد
    ctypes.windll.kernel32.WaitForSingleObject(sei.hProcess, 120000)
    code = wintypes.DWORD()
    ctypes.windll.kernel32.GetExitCodeProcess(sei.hProcess, ctypes.byref(code))
    ctypes.windll.kernel32.CloseHandle(sei.hProcess)
    return code.value == 0
