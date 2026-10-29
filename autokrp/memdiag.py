"""تشخیص مصرف حافظه در حالت کلاینت.

۱) patch_pywebview(): رفع نشت pywebview — Window.evaluate_js برای هر فراخوانی یک ورودی در window._callbacks
   می‌سازد و فقط برای حالت callback‌دار پاکش می‌کند؛ پاسخ هر فراخوانی API از رابط (js_bridge_call) بدون callback است،
   پس با هر کلیک/poll یک ورودی برای همیشه می‌ماند. ورودی‌های بدون callback هیچ‌جا دوباره خوانده نمی‌شوند.

۲) start(window): با سوییچ --memdiag هر دقیقه یک خط در logs/memdiag.txt:
   حافظه‌ی خود برنامه (پایتون)، هر پردازه‌ی WebView2 (msedgewebview2.exe زیرمجموعه‌ی برنامه)، handle و GDI/USER،
   تعداد ترد، heap جاوااسکریپت، تعداد گره‌های صفحه و چند شمارنده‌ی رابط. هر ۱۵ دقیقه بیشترین رشد tracemalloc.
   فایل فقط عدد و مسیر کد دارد (هیچ داده‌ی کاربر، IP یا متن ترمینال)؛ به همین دلیل رمز نمی‌شود تا مستقیم قابل ارسال باشد.
"""
import gc
import json
import logging
import os
import sys
import threading
import time

log = logging.getLogger(__name__)
_PATCHED = False


BOOT = {}          # زمان مرحله‌های بالا آمدن برنامه (app.py): ثانیه از شروع


def patch_pywebview():
    global _PATCHED
    if _PATCHED:
        return
    try:
        from webview.window import Window
    except Exception:
        return
    orig = Window.evaluate_js

    def evaluate_js(self, script, callback=None):
        try:
            return orig(self, script, callback)
        finally:
            if callback is None:
                cb = getattr(self, "_callbacks", None)
                if cb:
                    for k in [k for k, v in list(cb.items()) if v is None]:
                        cb.pop(k, None)

    evaluate_js.__wrapped__ = orig
    Window.evaluate_js = evaluate_js
    _PATCHED = True


# ---------------------------------------------------------------- اطلاعات پردازه‌ها
def _procs_psutil():
    import psutil
    me = psutil.Process()
    out = []
    for p in [me] + me.children(recursive=True):
        try:
            mi = p.memory_info()
            out.append({"pid": p.pid, "name": p.name(), "ws": mi.rss, "priv": getattr(mi, "private", 0) or getattr(mi, "uss", 0) or mi.rss,
                        "handles": p.num_handles() if hasattr(p, "num_handles") else p.num_fds(), "threads": p.num_threads(),
                        "type": _ptype(p.cmdline()) if p.pid != me.pid else "app"})
        except Exception:
            continue
    return out


def _ptype(cmd):
    for a in cmd or []:
        if a.startswith("--type="):
            return a[7:]
    return "browser" if any("webview" in str(a).lower() for a in cmd[:1]) else "?"


def _procs_win():
    """فقط Windows، بدون psutil (در exe نیست): درخت پردازه‌های زیرمجموعه‌ی همین برنامه."""
    import ctypes
    from ctypes import wintypes as W
    k32, u32, psapi = ctypes.WinDLL("kernel32", use_last_error=True), ctypes.WinDLL("user32"), ctypes.WinDLL("psapi")

    class PE(ctypes.Structure):
        _fields_ = [("dwSize", W.DWORD), ("cntUsage", W.DWORD), ("th32ProcessID", W.DWORD),
                    ("th32DefaultHeapID", ctypes.c_size_t), ("th32ModuleID", W.DWORD), ("cntThreads", W.DWORD),
                    ("th32ParentProcessID", W.DWORD), ("pcPriClassBase", ctypes.c_long), ("dwFlags", W.DWORD),
                    ("szExeFile", ctypes.c_wchar * 260)]

    class PMC(ctypes.Structure):
        _fields_ = [("cb", W.DWORD), ("PageFaultCount", W.DWORD)] + [(n, ctypes.c_size_t) for n in (
            "PeakWorkingSetSize", "WorkingSetSize", "QuotaPeakPagedPoolUsage", "QuotaPagedPoolUsage",
            "QuotaPeakNonPagedPoolUsage", "QuotaNonPagedPoolUsage", "PagefileUsage", "PeakPagefileUsage", "PrivateUsage")]

    k32.CreateToolhelp32Snapshot.restype = W.HANDLE
    k32.CreateToolhelp32Snapshot.argtypes = [W.DWORD, W.DWORD]
    k32.Process32FirstW.argtypes = k32.Process32NextW.argtypes = [W.HANDLE, ctypes.POINTER(PE)]
    k32.OpenProcess.restype = W.HANDLE
    k32.OpenProcess.argtypes = [W.DWORD, W.BOOL, W.DWORD]
    k32.CloseHandle.argtypes = [W.HANDLE]
    k32.GetProcessHandleCount.argtypes = [W.HANDLE, ctypes.POINTER(W.DWORD)]
    psapi.GetProcessMemoryInfo.argtypes = [W.HANDLE, ctypes.POINTER(PMC), W.DWORD]
    u32.GetGuiResources.argtypes = [W.HANDLE, W.DWORD]
    snap = k32.CreateToolhelp32Snapshot(0x2, 0)           # TH32CS_SNAPPROCESS
    if not snap or snap == W.HANDLE(-1).value:
        return []
    allp = {}
    try:
        e = PE(); e.dwSize = ctypes.sizeof(PE)
        ok = k32.Process32FirstW(snap, ctypes.byref(e))
        while ok:
            allp[e.th32ProcessID] = (e.th32ParentProcessID, e.szExeFile, e.cntThreads)
            ok = k32.Process32NextW(snap, ctypes.byref(e))
    finally:
        k32.CloseHandle(snap)
    me = os.getpid()
    tree, frontier = {me}, [me]
    while frontier:
        kids = [pid for pid, (pp, _, _) in allp.items() if pp in frontier and pid not in tree]
        tree.update(kids); frontier = kids
    out = []
    for pid in sorted(tree):
        pp, name, nthr = allp.get(pid, (0, "?", 0))
        h = k32.OpenProcess(0x1000, False, pid)             # PROCESS_QUERY_LIMITED_INFORMATION
        if not h:
            continue
        try:
            m = PMC(); m.cb = ctypes.sizeof(PMC)
            psapi.GetProcessMemoryInfo(h, ctypes.byref(m), m.cb)
            hc = W.DWORD(0); k32.GetProcessHandleCount(h, ctypes.byref(hc))
            out.append({"pid": pid, "name": name, "ws": m.WorkingSetSize, "priv": m.PrivateUsage, "handles": hc.value,
                        "threads": nthr, "gdi": u32.GetGuiResources(h, 0), "user": u32.GetGuiResources(h, 1),
                        "type": "app" if pid == me else ("browser" if pp == me else "child")})
        finally:
            k32.CloseHandle(h)
    return out


def procs():
    if sys.platform == "win32":
        try:
            return _procs_win()
        except Exception:
            log.debug("memdiag win", exc_info=True)
    try:
        return _procs_psutil()
    except Exception:
        return []


# ---------------------------------------------------------------- رابط (WebView2)
JS_PROBE = """(() => { const m = performance.memory || {};
  const T = typeof TERM !== 'undefined' ? TERM : null, X = typeof XF !== 'undefined' ? XF : null, S0 = typeof S !== 'undefined' ? S : null;
  let lines = 0; try { (T && T.tabs || []).forEach((t) => { lines += t.term.buffer.normal.length; }); } catch (_) {}
  return JSON.stringify({heap: m.usedJSHeapSize || 0, heapTotal: m.totalJSHeapSize || 0, nodes: document.getElementsByTagName('*').length,
    terms: T ? T.tabs.length : -1, termLines: lines, xfConns: X ? X.conns.length : -1, xfJobs: X ? X.jobs.length : -1,
    xfFiles: X && X.files ? X.files.size : -1, events: S0 && S0.events ? S0.events.length : -1, page: S0 ? S0.page : '',
    hidden: document.hidden, ips: S0 && S0.ips ? S0.ips.length : -1, hist: S0 && S0.hist ? S0.hist.length : -1,
    run: S0 && S0.run ? (S0.run.status + ':' + (S0.run.lists && S0.run.lists.abuse_records ? S0.run.lists.abuse_records.length : 0)) : '',
    tab: S0 ? (S0.resultTab || '') : ''}); })()"""


def _js(window):
    res = {}

    def run():
        try:
            r = window.evaluate_js(JS_PROBE)
            res.update(json.loads(r) if isinstance(r, str) else (r or {}))
        except Exception as e:
            res["err"] = type(e).__name__
    t = threading.Thread(target=run, daemon=True)
    t.start(); t.join(10)                                    # پنجره‌ی هنگ‌کرده نمونه‌برداری را متوقف نکند
    if t.is_alive():
        res["err"] = "timeout"
    return res


# ---------------------------------------------------------------- حلقه
def _mb(b):
    return f"{b / 1048576:.0f}"


class MemDiag:
    def __init__(self, window, path, every=60, tm_every=900, frames=12, store=None, trace=False):
        self.window, self.path, self.every, self.tm_every, self.frames = window, path, every, tm_every, frames
        self.store = store
        self.trace = trace     # tracemalloc: هر بار گرفتن حافظه ثبت می‌شود و برنامه را چند برابر کند می‌کند؛ فقط با --memdiag-trace
        self.t0 = time.time()
        self.base = None
        self.base0 = None          # عکس لحظه‌ی شروع: رشد حافظه در دقیقه‌های اول (کندی بالا آمدن برنامه)
        self.boot_done = set()
        self.slow_seen = 0

    def _w(self, line):
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(line + "\n")

    def start(self):
        import tracemalloc
        if self.trace:
            tracemalloc.start(self.frames)
            self.base0 = tracemalloc.take_snapshot()
        from . import __version__
        self._w(f"# AutoKRP {__version__} memdiag — {time.strftime('%Y-%m-%d %H:%M:%S')} — Python {sys.version.split()[0]} — pid {os.getpid()}"
                f" — {'tracemalloc روشن (کند)' if self.trace else 'سبک (بدون tracemalloc)'}")
        self._w("# min | app: ws/priv MB, handles, threads, gdi/user | webview: total priv MB [each type:priv] | py: traced MB, gc objs, "
                "bridge cb | db MB, last save s | js: heap MB, nodes, terms(lines), xf conns/jobs/files, events, page | ui: js reply ms, cpu%")
        self.tables()
        self._w("# boot: " + " ".join(f"{k}={v:.1f}s" for k, v in BOOT.items()))
        threading.Thread(target=self._loop, name="memdiag", daemon=True).start()

    def _loop(self):
        last_tm = time.time()
        while True:
            el = time.time() - self.t0
            time.sleep(10 if el < 300 else self.every)       # ۵ دقیقه‌ی اول هر ۱۰ ثانیه
            try:
                if "window shown" in BOOT and not getattr(self, "_shown_logged", False):
                    self._shown_logged = True
                    self._w("# boot: " + " ".join(f"{k}={v:.1f}s" for k, v in BOOT.items()))
                self.sample()
                self.slow()
                el = time.time() - self.t0
                for mark in ((60, 180) if self.trace else ()):
                    if el >= mark and mark not in self.boot_done:
                        self.boot_done.add(mark)
                        self.top(base=self.base0, title=f"--- tracemalloc: رشد از شروع برنامه تا ثانیه‌ی {el:.0f}")
                if self.trace and time.time() - last_tm >= self.tm_every:
                    last_tm = time.time()
                    self.top()
                    self.tables()
            except Exception as e:
                try:
                    self._w(f"! {type(e).__name__}: {e}")
                except Exception:
                    pass

    def sample(self):
        import tracemalloc
        ps = procs()
        app = next((p for p in ps if p["type"] == "app"), {})
        wv = [p for p in ps if p["type"] != "app"]
        cur, _peak = tracemalloc.get_traced_memory() if self.trace else (0, 0)
        cb = len(getattr(self.window, "_callbacks", {}) or {})
        tj = time.perf_counter()
        js = _js(self.window) if self.window is not None else {}
        js_ms = (time.perf_counter() - tj) * 1000
        db = self._db_size()
        wv_s = " ".join(f"{p['type']}:{_mb(p['priv'])}" for p in sorted(wv, key=lambda x: -x["priv"])[:6])
        el = time.time() - self.t0
        stamp = f"{el / 60:6.0f}" if el >= 300 else f"{el / 60:6.2f}"
        self._w(f"{stamp} | app {_mb(app.get('ws', 0))}/{_mb(app.get('priv', 0))} h{app.get('handles', 0)} "
                f"t{threading.active_count()}/{app.get('threads', 0)} g{app.get('gdi', '-')}/{app.get('user', '-')} | "
                f"webview {_mb(sum(p['priv'] for p in wv))} [{wv_s}] | py {cur / 1048576:.1f} gc{len(gc.get_objects())} cb{cb} | "
                f"db {db} | "
                f"js {js.get('heap', 0) / 1048576:.1f} n{js.get('nodes', '-')} term{js.get('terms', '-')}({js.get('termLines', '-')}) "
                f"xf{js.get('xfConns', '-')}/{js.get('xfJobs', '-')}/{js.get('xfFiles', '-')} ev{js.get('events', '-')} "
                f"{js.get('page', '')} ips{js.get('ips', '-')} hist{js.get('hist', '-')} run{js.get('run', '')}/{js.get('tab', '')}"
                f"{' hidden' if js.get('hidden') else ''}{' ERR ' + js['err'] if js.get('err') else ''} | ui {js_ms:.0f}ms cpu {self._cpu()}")
        if self.trace and self.base is None and time.time() - self.t0 > 300:
            self.base = tracemalloc.take_snapshot()

    def _cpu(self):
        """درصد CPU همین پروسه از نمونه‌ی قبلی (بدون psutil هم با process_time)."""
        now, pt = time.time(), time.process_time()
        prev = getattr(self, "_cpu_prev", None)
        self._cpu_prev = (now, pt)
        if not prev or now - prev[0] <= 0:
            return "-"
        return f"{100 * (pt - prev[1]) / (now - prev[0]):.0f}%"

    def slow(self):
        """فراخوانی‌های کند رابط (بیش از ۱.۵ ثانیه) از آخرین نمونه: فقط نام متد و زمان."""
        try:
            from .api import SLOW_CALLS
        except Exception:
            return
        lst = list(SLOW_CALLS)
        new = [x for x in lst if x[0] > self.slow_seen]
        if new:
            self.slow_seen = new[-1][0]
            self._w("  slow: " + " ".join(f"{n}={d}s@{x - self.t0:.0f}" for x, n, d in new[-30:]))

    def _db_size(self):
        st = self.store
        if st is None:
            return "-"
        try:
            with st._lock:
                pc = int(st.db.execute("PRAGMA page_count").fetchone()[0])
                ps = int(st.db.execute("PRAGMA page_size").fetchone()[0])
            return f"{pc * ps / 1048576:.0f} {getattr(st, 'last_flush_secs', 0):.1f}s"
        except Exception:
            return "?"

    def tables(self):
        """تعداد ردیف هر جدول (فقط عدد؛ محتوا نه) — کدام جدول پایگاه داده را بزرگ می‌کند."""
        st = self.store
        if st is None:
            return
        try:
            with st._lock:
                names = [r[0] for r in st.db.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
                cnt = {n: st.db.execute(f'SELECT COUNT(*) FROM "{n}"').fetchone()[0] for n in names if n.isidentifier()}  # nosec B608 — نام جدول از sqlite_master
            self._w("# tables: " + " ".join(f"{k}={v}" for k, v in sorted(cnt.items(), key=lambda x: -x[1]) if v))
        except Exception as e:
            self._w(f"! tables {type(e).__name__}")

    def top(self, n=12, base=None, title=None):
        import tracemalloc
        base = base or self.base
        if base is None:
            return
        snap = tracemalloc.take_snapshot()
        flt = [tracemalloc.Filter(False, tracemalloc.__file__), tracemalloc.Filter(False, "<frozen importlib._bootstrap>")]
        self._w(title or f"--- tracemalloc: بیشترین رشد از دقیقه‌ی ۵ تا دقیقه‌ی {(time.time() - self.t0) / 60:.0f}")
        for st in snap.filter_traces(flt).compare_to(base.filter_traces(flt), "traceback")[:n]:
            self._w(f"  {st.size_diff / 1024:+10.0f} KB {st.count_diff:+8d} obj")
            for line in st.traceback.format()[-8:]:
                self._w("     " + line.rstrip())


def start(window, logs_dir, store=None, trace=False):
    p = os.path.join(str(logs_dir), "memdiag.txt")
    d = MemDiag(window, p, store=store, trace=trace)
    d.start()
    return p
