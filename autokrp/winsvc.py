"""
اجرای خودکار سرور با روشن شدن ویندوز (بدون لاگین) با Task Scheduler.

- تسک با همان کاربر ویندوزی که نصب می‌کند و نوع ورود S4U اجرا می‌شود: رمز ویندوز ذخیره نمی‌شود و دسترسی
  اضافه‌ای (SYSTEM/Administrator) نمی‌گیرد؛ پوشه‌ی داده همان پوشه‌ی فعلی است (--data-root).
- نصب و حذف به دسترسی Administrator نیاز دارد؛ در صورت نیاز برنامه خودش با UAC دوباره اجرا می‌شود.
- قانون فایروال ورودی برای سرور هم‌زمان ساخته/حذف می‌شود (1.59.3: fw_apply؛ نام قانون برای هر نسخه جدا).
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
FW_LEGACY = "AutoKRP Server"       # نام قانون پیش از 1.59.3 (برای همه‌ی نسخه‌ها یکی بود)
FW_STATE = ".fw_applied"
FW_PARTIAL = "partial"      # 1.59.9: فقط قانون وب را نصب‌کننده ساخته؛ امضای کامل نیست (هرگز با fw_state برابر نمی‌شود)
FW_PORTS = ".fw_ports"       # 1.59.7: پورت‌های Trap/Syslog آخرین قانون (فقط عدد) برای به‌روزرسانی با نصب‌کننده
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


def task_program():
    """1.52: فایل اجرایی تسک اجرای خودکار (برای تشخیص تسکی که هنوز به exe قابل‌حمل قبلی اشاره می‌کند)."""
    if not supported():
        return None
    try:
        r = _run([_sys32("schtasks.exe"), "/query", "/tn", TASK, "/xml"], timeout=20)
    except Exception:
        return None
    if r.returncode != 0:
        return None
    raw = r.stdout or b""
    for enc in (("utf-16",) if raw[:2] in (b"\xff\xfe", b"\xfe\xff") else ()) + ("utf-8", "mbcs", "latin-1"):
        try:
            txt = raw.decode(enc)
            break
        except (UnicodeDecodeError, LookupError):
            continue
    else:
        return None
    import re
    from xml.sax.saxutils import unescape
    m = re.search(r"<Command>(.*?)</Command>", txt, re.S)
    return unescape(m.group(1).strip()) if m else None


def same_program(path) -> bool:
    exe = program()[0]
    try:
        return os.path.normcase(str(Path(path).resolve())) == os.path.normcase(str(Path(exe).resolve()))
    except OSError:
        return os.path.normcase(str(path)) == os.path.normcase(exe)


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


def fw_names():
    """نام قانون‌ها برای همین نسخه‌ی برنامه (کامل، مانیتورینگ، …) تا قانون نسخه‌ی دیگر را پاک نکند."""
    import ntpath            # مسیر ویندوز (\\ یا /)
    stem = ntpath.splitext(ntpath.basename(program()[0]))[0] if getattr(sys, "frozen", False) else "AutoKRP"
    return {"web": f"{stem} Server (web)", "udp": f"{stem} Server (Trap/Syslog UDP)", "tcp": f"{stem} Server (Syslog TCP)"}


def fw_clean_nets(nets):
    """شبکه‌های مجاز سرور ← فهرست مرتب برای remoteip (هر مورد نامعتبر کنار گذاشته می‌شود)."""
    import ipaddress
    out = set()
    for n in nets or []:
        t = str(n).split("#", 1)[0].strip()
        if not t:
            continue
        try:
            out.add(str(ipaddress.ip_network(t, strict=False)))
        except ValueError:
            continue
    return sorted(out)


def _ports(v):
    out = set()
    for x in v or []:
        try:
            n = int(x)
        except (TypeError, ValueError):
            continue
        if 1 <= n <= 65535:
            out.add(n)
    return sorted(out)


def fw_state(nets, udp=(), tcp=()):
    """امضای حالت مطلوب (پورت وب در آن نیست: قانون وب به خود برنامه بسته است و با عوض شدن پورت کار می‌کند)."""
    import hashlib
    import json
    d = {"nets": fw_clean_nets(nets), "udp": _ports(udp), "tcp": _ports(tcp)}
    return hashlib.sha256(json.dumps(d, sort_keys=True).encode()).hexdigest()


def fw_applied():
    """امضای آخرین قانون‌های ساخته‌شده یا None. فقط یک hash است (بدون آدرس) و بدون کلید خوانده می‌شود."""
    from . import paths
    try:
        return (paths.data_dir() / FW_STATE).read_text(encoding="ascii").strip() or None
    except OSError:
        return None


def _fw_delete_all(keep_events=False):
    exe, base, _ = program()
    ns = _sys32("netsh.exe")
    for k, n in fw_names().items():
        if keep_events and k != "web":
            continue
        _run([ns, "advfirewall", "firewall", "delete", "rule", f"name={n}"], timeout=30)
    if not base:     # قانون قدیمی هم‌نام فقط اگر مال همین فایل برنامه باشد
        _run([ns, "advfirewall", "firewall", "delete", "rule", f"name={FW_LEGACY}", f"program={exe}"], timeout=30)
    else:
        _run([ns, "advfirewall", "firewall", "delete", "rule", f"name={FW_LEGACY}"], timeout=30)


def fw_apply(nets=(), udp=(), tcp=(), port=8443, keep_events=False):
    """قانون‌های ورودی (به دسترسی Administrator نیاز دارد):
      وب: TCP، به خود فایل برنامه (هر پورتی که سرور گوش بدهد)، فقط از شبکه‌های مجاز (خالی = همه)؛
      Trap/Syslog: UDP (و TCP برای Syslog) روی همان پورت‌ها، از هر آدرسی (فیلتر منبع در خود برنامه است).
    حالت توسعه (python.exe): قانون وب فقط روی پورت."""
    if not supported():
        raise SvcError("فقط روی ویندوز.")
    if not is_admin():
        raise SvcError("برای تغییر فایروال ویندوز دسترسی Administrator لازم است.")
    exe, base, _ = program()
    ns, N = _sys32("netsh.exe"), fw_names()
    nl, up, tp = fw_clean_nets(nets), _ports(udp), _ports(tcp)
    _fw_delete_all(keep_events)
    add = [ns, "advfirewall", "firewall", "add", "rule", "dir=in", "action=allow", "enable=yes", "profile=any"]
    web = add + [f"name={N['web']}", "protocol=TCP"] + ([f"program={exe}"] if not base else [f"localport={int(port)}"])
    if nl:
        web.append("remoteip=" + ",".join(nl))
    errs = []
    r = _run(web, timeout=30)
    if r.returncode != 0:
        errs.append(_out(r) or f"code {r.returncode}")
    for key, proto, pp in (("udp", "UDP", up), ("tcp", "TCP", tp)):
        if pp and not keep_events:
            r = _run(add + [f"name={N[key]}", f"protocol={proto}", "localport=" + ",".join(map(str, pp))]
                     + ([f"program={exe}"] if not base else []), timeout=30)
            if r.returncode != 0:
                errs.append(_out(r) or f"code {r.returncode}")
    if errs:
        log.warning("قانون فایروال ساخته نشد: %s", "; ".join(errs))
        return {"ok": False, "error": "; ".join(errs)[:400]}
    if keep_events:          # قانون Trap/Syslog قبلی دست نخورد؛ پورت‌ها معلوم نیست پس هم‌خوان نمی‌شود اعلام کرد
        from . import paths
        try:   # 1.59.9: نشانه‌ی «قانون هست ولی هم‌خوانی معلوم نیست» (قبلاً فایل نبود و پنجره «قانونی ساخته نشده» می‌گفت)
            (paths.data_dir() / FW_STATE).write_text(FW_PARTIAL, encoding="ascii")   # nosec — ثابت، بدون داده
        except OSError:
            pass
        log.info("قانون وب فایروال ویندوز به‌روز شد (قانون‌های Trap/Syslog قبلی ماند)")
        return {"ok": True, "nets": nl, "udp": up, "tcp": tp, "kept": True}
    from . import paths
    try:
        (paths.data_dir() / FW_STATE).write_text(fw_state(nl, up, tp), encoding="ascii")   # nosec — فقط hash، بدون داده
    except OSError:
        pass
    try:
        import json
        (paths.data_dir() / FW_PORTS).write_text(json.dumps({"udp": up, "tcp": tp}), encoding="ascii")  # nosec — فقط شماره‌ی پورت
    except OSError:
        pass
    log.info("قانون‌های فایروال ویندوز ساخته شد (شبکه‌ها %d، UDP %s، TCP %s)", len(nl), up, tp)
    return {"ok": True, "nets": nl, "udp": up, "tcp": tp}


def fw_saved_ports():
    """پورت‌های Trap/Syslog آخرین قانون ساخته‌شده (برای نصب‌کننده که پورت‌ها را نمی‌داند)."""
    import json
    from . import paths
    try:
        d = json.loads((paths.data_dir() / FW_PORTS).read_text(encoding="ascii"))
        return {"udp": _ports(d.get("udp")), "tcp": _ports(d.get("tcp"))}
    except (OSError, ValueError, AttributeError):
        return None


def fw_live():
    """پورت‌های Trap/Syslog همین فرایند (اگر بخش مانیتورینگ در بیلد نیست: هیچ)."""
    try:
        from . import devevents
        L = getattr(devevents, "LISTEN", None)
    except Exception:  # noqa — بیلد بدون مانیتورینگ
        L = None
    if not isinstance(L, dict):
        return {"udp": [], "tcp": [], "known": True}
    return {"udp": _ports(L.get("udp")), "tcp": _ports(L.get("tcp")), "known": bool(L.get("known"))}


def fw_resolve(live):
    """1.59.10 (F1): پیش از اولین ورود وب پورت‌های Trap/Syslog معلوم نیست (known=False). آن وقت پورت‌های آخرین قانون
    (.fw_ports) به کار می‌رود، و اگر آن هم نیست قانون‌های Trap/Syslog موجود دست نمی‌خورد (keep). هرگز «پورت خالی» نه."""
    live = dict(live or {})
    if live.get("keep") or live.get("known", True):
        return live
    saved = fw_saved_ports()
    if saved is not None:
        return {"udp": saved["udp"], "tcp": saved["tcp"], "known": False, "saved": True}
    return {"udp": [], "tcp": [], "known": False, "keep": True}


def fw_status(nets, live=None):
    """آیا قانون‌های فایروال ویندوز با شبکه‌های مجاز و پورت‌های Trap/Syslog فعلی هم‌خوان‌اند؟
    1.59.10 (F2): پورت‌ها نامعلوم (پیش از اولین ورود) ← synced = None (نه «به‌روز» نه «هم‌خوان نیست»)."""
    live = live or fw_live()
    known = bool(live.get("known", True))
    applied = fw_applied()
    if not known:
        saved = fw_saved_ports() or {"udp": [], "tcp": []}
        return {"windows": supported(), "has": applied is not None, "nets": len(fw_clean_nets(nets)),
                "synced": None if applied is not None else False, "udp": saved["udp"], "tcp": saved["tcp"], "known": False}
    return {"windows": supported(), "has": applied is not None, "nets": len(fw_clean_nets(nets)),
            "synced": applied is not None and applied == fw_state(nets, live.get("udp"), live.get("tcp")),
            "udp": _ports(live.get("udp")), "tcp": _ports(live.get("tcp")), "known": True}


def fw_remove():
    if not supported() or not is_admin():
        return False
    _fw_delete_all()
    from . import paths
    try:
        (paths.data_dir() / FW_STATE).unlink()
    except OSError:
        pass
    try:
        (paths.data_dir() / FW_PORTS).unlink()
    except OSError:
        pass
    return True


def install(user, data_root, port, nets=(), udp=(), tcp=(), keep_events=False):
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
    fw = fw_apply(nets, udp, tcp, port, keep_events=keep_events).get("ok")
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
    # 1.59.3: قانون‌های فایروال جدا مدیریت می‌شوند (دکمه‌ی پنجره‌ی سرور، حذف برنامه)؛ سرور ممکن است بدون اجرای خودکار هم اجرا شود
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
