"""سلامت سرور و خود برنامه (1.24): فضای دیسک پوشه‌ی داده، RAM و CPU فرآیند، رشد داده‌ها؛ هشدار با عبور از آستانه.

بدون psutil (در exe نیست): لینوکس از /proc، ویندوز با GetProcessMemoryInfo (مثل memdiag)."""
import logging
import os
import shutil
import threading
import time

from . import paths

log = logging.getLogger(__name__)
DEFAULTS = {"enabled": True, "disk_min_gb": 10, "disk_min_pct": 10, "ram_max_mb": 2048, "cpu_max_pct": 90}
SIZE_EVERY = 1800           # حجم پوشه‌ها (پیمایش فایل‌ها) حداکثر هر ۳۰ دقیقه
CHECK_EVERY = 300
REPEAT_AFTER = 86400        # هشدار تکراری برای همان مشکل حداکثر روزی یک بار


def _rss():
    """RAM فرآیند (بایت)."""
    if os.name == "nt":
        try:
            import ctypes
            from ctypes import wintypes as W

            class PMC(ctypes.Structure):
                _fields_ = [("cb", W.DWORD), ("PageFaultCount", W.DWORD)] + [(n, ctypes.c_size_t) for n in (
                    "PeakWorkingSetSize", "WorkingSetSize", "QuotaPeakPagedPoolUsage", "QuotaPagedPoolUsage",
                    "QuotaPeakNonPagedPoolUsage", "QuotaNonPagedPoolUsage", "PagefileUsage", "PeakPagefileUsage", "PrivateUsage")]
            k32, psapi = ctypes.WinDLL("kernel32"), ctypes.WinDLL("psapi")
            k32.GetCurrentProcess.restype = W.HANDLE
            psapi.GetProcessMemoryInfo.argtypes = [W.HANDLE, ctypes.POINTER(PMC), W.DWORD]
            m = PMC()
            m.cb = ctypes.sizeof(PMC)
            if psapi.GetProcessMemoryInfo(k32.GetCurrentProcess(), ctypes.byref(m), m.cb):
                return int(m.WorkingSetSize)
        except Exception:  # noqa — فقط نمایش
            return None
        return None
    try:
        with open("/proc/self/status", encoding="ascii") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1]) * 1024
    except OSError:
        return None
    return None


def _dir_size(p):
    n = 0
    try:
        for root, _dirs, files in os.walk(p):
            for f in files:
                try:
                    n += os.path.getsize(os.path.join(root, f))
                except OSError:
                    continue
    except OSError:
        pass
    return n


class Health:
    def __init__(self, settings, notify=None, emit=None, history=None):
        self.settings = settings
        self.notify = notify or (lambda *a, **k: None)
        self.emit = emit or (lambda *a, **k: None)
        self.history = history
        self.started = time.time()
        self._cpu_prev = None
        self._sizes, self._sizes_at = {}, 0
        self._last = {}            # مشکل ← زمان آخرین هشدار
        self._lock = threading.Lock()
        self.last = None

    def cfg(self):
        c = dict(DEFAULTS)
        c.update({k: v for k, v in (self.settings.get("health") or {}).items() if k in DEFAULTS})
        return c

    def _cpu(self):
        """CPU فرآیند از نمونه‌ی قبلی: درصد کل سیستم و درصد یک هسته."""
        t = os.times()
        now, used = time.monotonic(), t.user + t.system
        prev, self._cpu_prev = self._cpu_prev, (now, used)
        if not prev or now - prev[0] < 1:
            return None, None
        one = 100 * (used - prev[1]) / (now - prev[0])
        return round(one / (os.cpu_count() or 1), 1), round(one, 1)

    def sizes(self, force=False):
        if force or time.time() - self._sizes_at > SIZE_EVERY:
            d = paths.data_dir()
            s = {"monitor": _dir_size(d / "monitor"), "runs": _dir_size(paths.runs_dir()), "backups": _dir_size(d / "backups"),
                 "logs": _dir_size(paths.logs_dir()), "db": sum(f.stat().st_size for f in d.glob("state.*") if f.is_file())}
            s["total"] = _dir_size(d)
            prev = self._sizes
            if prev.get("total") and self._sizes_at:
                s["growth_day"] = max(0, int((s["total"] - prev["total"]) * 86400 / max(60, time.time() - self._sizes_at)))
            else:
                s["growth_day"] = prev.get("growth_day")
            self._sizes, self._sizes_at = s, time.time()
        return dict(self._sizes)

    def view(self):
        """برای رابط: دیسک و RAM تازه، CPU از آخرین بررسی دوره‌ای (میانگین ۵ دقیقه)."""
        last = self.last or {}
        s = self.sample(cpu=False)
        s["cpu"], s["cpu_core"] = last.get("cpu"), last.get("cpu_core")
        s["problems"] = [{"key": k, "msg": m} for k, m in self.problems(s)]
        s["cfg"] = self.cfg()
        return s

    def sample(self, cpu=True):
        d = paths.data_dir()
        try:
            du = shutil.disk_usage(d)
            disk = {"total": du.total, "free": du.free, "pct_free": round(100 * du.free / du.total, 1) if du.total else None}
        except OSError:
            disk = {}
        cpu, cpu_core = self._cpu() if cpu else (None, None)
        out = {"t": time.time(), "disk": disk, "rss": _rss(), "cpu": cpu, "cpu_core": cpu_core, "cores": os.cpu_count(),
               "threads": threading.active_count(), "uptime": int(time.time() - self.started), "sizes": self.sizes(),
               "path": str(d)}
        g = (out["sizes"] or {}).get("growth_day")
        if g and disk.get("free"):
            out["days_left"] = int(disk["free"] / g)
        if cpu:
            self.last = out
        return out

    def problems(self, s):
        c, out = self.cfg(), []
        dk = s.get("disk") or {}
        if dk.get("free") is not None:
            gb = dk["free"] / 1024 ** 3
            if gb < float(c["disk_min_gb"]) or (dk.get("pct_free") is not None and dk["pct_free"] < float(c["disk_min_pct"])):
                out.append(("disk", f"فضای آزاد دیسک داده‌ها کم است: {gb:.1f} گیگ ({dk.get('pct_free')}٪) — {s['path']}"))
        if s.get("rss") and s["rss"] / 1024 ** 2 > float(c["ram_max_mb"]):
            out.append(("ram", f"مصرف RAM برنامه زیاد است: {s['rss'] / 1024 ** 2:.0f} مگ (حد {c['ram_max_mb']})"))
        if s.get("cpu_core") is not None and s["cpu_core"] > float(c["cpu_max_pct"]):
            out.append(("cpu", f"CPU برنامه بالاست: {s['cpu_core']:.0f}٪ یک هسته (میانگین ۵ دقیقه‌ی گذشته)"))
        if s.get("days_left") is not None and s["days_left"] < 30:
            out.append(("disk_trend", f"با رشد فعلی داده‌ها، دیسک حدود {s['days_left']} روز دیگر پر می‌شود"))
        return out

    def check(self):
        """هر ۵ دقیقه از worker: هشدار (رویداد، تاریخچه، ایمیل) با عبور از آستانه، و اعلام برطرف شدن."""
        c = self.cfg()
        s = self.sample()
        if not c["enabled"]:
            return s
        now = time.time()
        probs = dict(self.problems(s))
        with self._lock:
            for k, msg in probs.items():
                if now - self._last.get(k, 0) >= REPEAT_AFTER:
                    self._last[k] = now
                    self.emit("error", msg, "health")
                    if self.history:
                        self.history("health", "سلامت سرور", "error", msg)
                    self.notify("health", msg)
            for k in [k for k in self._last if k not in probs]:
                del self._last[k]
                self.emit("info", "سلامت سرور: مشکل برطرف شد", "health")
        s["problems"] = [{"key": k, "msg": m} for k, m in probs.items()]
        return s
