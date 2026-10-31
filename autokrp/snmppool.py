"""
مدیریت کارگرهای SNMP (1.34): چند فرایند جدا تا خواندن SNMP از چند هسته‌ی CPU استفاده کند.

- هر کارگر یک بار دیگر خود برنامه است («--snmpworker PORT»)؛ اتصال فقط روی 127.0.0.1 با توکن یک‌بارمصرف.
- هر هدف همیشه به یک کارگر ثابت می‌رود (tid % n) تا کش موتور و داده‌ی ثابت پورت‌ها همان‌جا بماند.
- کارگر از کار افتاده: کارهای در جریانش در همین برنامه دوباره اجرا می‌شوند (دستگاه «قطع» اعلام نمی‌شود) و
  کارگر با تأخیر افزایشی دوباره اجرا می‌شود. بیش از حد خراب شدن ← کارگرها کنار گذاشته می‌شوند و همه درون برنامه.
- بازیافت: پس از RECYCLE_POLLS بار خواندن یا RAM بیش از RECYCLE_MB، کارگر تازه جایش را می‌گیرد.
- ویندوز: همه‌ی کارگرها در یک Job Object با KILL_ON_JOB_CLOSE (بسته یا کرش شدن برنامه = بسته شدن کارگرها)،
  بدون پنجره (CREATE_NO_WINDOW). در همه‌ی سیستم‌ها کارگر با بسته شدن اتصال خودش خارج می‌شود.
"""
import json
import logging
import os
import secrets
import socket
import subprocess  # nosec B404 — اجرای همین برنامه در حالت --snmpworker
import sys
import threading
import time

from .snmpworker import recv_msg, send_msg

log = logging.getLogger(__name__)

MAX_WORKERS = 16
RECYCLE_POLLS = 50000
RECYCLE_MB = 600
START_TIMEOUT = 40          # exe تک‌فایلی روی ویندوز کند باز می‌شود (آنتی‌ویروس)
HUNG_AFTER = 120            # کار در جریان + بدون هیچ پاسخی ← کارگر گیر کرده
FAIL_WINDOW, FAIL_MAX = 600, 6


def auto_count():
    n = os.cpu_count() or 2
    return max(1, min(8, n - 1))


def want_count(setting):
    """تنظیم «snmp_workers»: "auto" | 0 (خاموش) | ۱ تا ۱۶."""
    if setting in (None, "", "auto"):
        return auto_count()
    try:
        return max(0, min(MAX_WORKERS, int(setting)))
    except (TypeError, ValueError):
        return auto_count()


def child_cmd(port):
    if getattr(sys, "frozen", False):
        return [sys.executable, "--snmpworker", str(port)]
    app = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "app.py")
    return [sys.executable, app, "--snmpworker", str(port)]


class _WinJob:
    """Job Object ویندوز: کارگرها با بسته شدن برنامه (حتی کرش) بسته می‌شوند."""

    def __init__(self):
        self.h = None
        if os.name != "nt":
            return
        try:
            import ctypes
            from ctypes import wintypes as W

            class BASIC(ctypes.Structure):
                _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64), ("PerJobUserTimeLimit", ctypes.c_int64),
                            ("LimitFlags", W.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
                            ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", W.DWORD),
                            ("Affinity", ctypes.c_size_t), ("PriorityClass", W.DWORD), ("SchedulingClass", W.DWORD)]

            class IOC(ctypes.Structure):
                _fields_ = [(n, ctypes.c_uint64) for n in ("ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
                                                           "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]

            class EXT(ctypes.Structure):
                _fields_ = [("BasicLimitInformation", BASIC), ("IoInfo", IOC), ("ProcessMemoryLimit", ctypes.c_size_t),
                            ("JobMemoryLimit", ctypes.c_size_t), ("PeakProcessMemoryUsed", ctypes.c_size_t),
                            ("PeakJobMemoryUsed", ctypes.c_size_t)]
            k32 = ctypes.WinDLL("kernel32", use_last_error=True)
            k32.CreateJobObjectW.restype = W.HANDLE
            k32.CreateJobObjectW.argtypes = [ctypes.c_void_p, W.LPCWSTR]
            k32.SetInformationJobObject.argtypes = [W.HANDLE, ctypes.c_int, ctypes.c_void_p, W.DWORD]
            k32.AssignProcessToJobObject.argtypes = [W.HANDLE, W.HANDLE]
            h = k32.CreateJobObjectW(None, None)
            if not h:
                raise OSError(ctypes.get_last_error())
            info = EXT()
            info.BasicLimitInformation.LimitFlags = 0x2000          # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            if not k32.SetInformationJobObject(h, 9, ctypes.byref(info), ctypes.sizeof(info)):   # JobObjectExtendedLimitInformation
                raise OSError(ctypes.get_last_error())
            self.k32, self.h = k32, h
        except Exception as e:  # noqa — بدون Job هم کارگر با بسته شدن اتصال خارج می‌شود
            log.warning("snmp workers: job object unavailable: %s", e)
            self.h = None

    def add(self, proc):
        if self.h:
            try:
                if not self.k32.AssignProcessToJobObject(self.h, int(proc._handle)):
                    log.warning("snmp workers: AssignProcessToJobObject failed")
            except Exception as e:  # noqa
                log.warning("snmp workers: job assign: %s", e)


class _Worker:
    def __init__(self, slot, proc, token):
        self.slot, self.proc, self.token = slot, proc, token
        self.sock = None
        self.lock = threading.Lock()
        self.pending = {}           # id → (cb, fallback, deadline)
        self.polls = 0
        self.mem = 0
        self.started = time.time()
        self.last_rx = time.time()
        self.ready = threading.Event()
        self.dead = False
        self.draining = False
        self.pid = proc.pid


class WorkerPool:
    def __init__(self, n, on_status=None):
        self.n = n
        self.slots = [None] * n          # _Worker فعلی هر خانه
        self._next_id = 0
        self._ids = threading.Lock()
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._srv = None
        self._port = 0
        self._job = _WinJob()
        self._fails = []                 # زمان خرابی‌ها
        self._backoff = [0.0] * n
        self._restart_at = [0.0] * n
        self.degraded = ""
        self._profiles, self._prof_sig = [], None
        self.stats = {"done": 0, "fallback": 0, "restarts": 0, "timeouts": 0, "recycled": 0}
        self._waiting = {}               # token → _Worker (هنوز وصل نشده)
        self._old = []                   # کارگرهای بازیافتی که کارهای باقی‌مانده را تمام می‌کنند

    # ---- چرخه
    def start(self):
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.bind(("127.0.0.1", 0))
        self._srv.listen(16)
        self._srv.settimeout(1.0)
        self._port = self._srv.getsockname()[1]
        threading.Thread(target=self._accept, name="snmpw-accept", daemon=True).start()
        for i in range(self.n):
            self._spawn(i)
        threading.Thread(target=self._watch, name="snmpw-watch", daemon=True).start()
        return self

    def stop(self):
        self._stop.set()
        with self._lock:
            ws = [w for w in self.slots if w]
            ws += list(self._waiting.values()) + list(self._old)
        for w in ws:
            self._kill(w, quit_msg=True)
        try:
            self._srv.close()
        except Exception:  # noqa
            pass

    def _spawn(self, i, replace=False):
        token = secrets.token_hex(16)
        env = dict(os.environ)                # متغیرهای _PYI_ بمانند: کارگر از پوشه‌ی باز شده‌ی exe استفاده کند
        env["AKRP_SNMPW_TOKEN"] = token
        env.pop("PYINSTALLER_RESET_ENVIRONMENT", None)
        kw = {"creationflags": 0x08000000} if os.name == "nt" else {"start_new_session": False}   # CREATE_NO_WINDOW
        try:
            p = subprocess.Popen(child_cmd(self._port), env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,  # nosec B603 — همین برنامه، ورودی ثابت
                                 stderr=subprocess.DEVNULL, close_fds=True, **kw)
        except Exception as e:  # noqa
            log.error("snmp worker %d start failed: %s", i, e)
            self._failed(i)
            return None
        self._job.add(p)
        w = _Worker(i, p, token)
        with self._lock:
            self._waiting[token] = w
            if not replace:
                self.slots[i] = w
        return w

    def _accept(self):
        while not self._stop.is_set():
            try:
                c, addr = self._srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._hello, args=(c,), daemon=True).start()

    def _hello(self, c):
        try:
            c.settimeout(10)
            m = recv_msg(c)
            tok = (m or {}).get("token") or ""
            with self._lock:
                w = None
                for k in list(self._waiting):
                    if secrets.compare_digest(k, tok):
                        w = self._waiting.pop(k)
                        break
            if w is None:
                c.close()
                return
            c.settimeout(None)
            c.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            w.sock = c
            if self._profiles:
                send_msg(c, {"op": "profiles", "p": self._profiles}, w.lock)
            with self._lock:
                cur = self.slots[w.slot]
                old = None
                if cur is not w:              # جایگزین بازیافت: از حالا کارهای تازه به این یکی
                    if cur is not None:
                        cur.draining = True
                        old = cur
                    self.slots[w.slot] = w
            if old is not None:
                if old.pending:
                    self._old.append(old)
                else:
                    self._kill(old, quit_msg=True)
            w.last_rx = time.time()
            w.ready.set()
            self._read(w)
        except Exception as e:  # noqa
            log.warning("snmp worker hello: %s", e)
            try:
                c.close()
            except OSError:
                pass

    def _read(self, w):
        try:
            while True:
                m = recv_msg(w.sock)
                if m is None:
                    break
                w.last_rx = time.time()
                w.mem = m.get("m") or w.mem
                with self._lock:
                    ent = w.pending.pop(m.get("i"), None)
                if ent is None:
                    continue
                w.polls += 1
                self.stats["done"] += 1
                cb = ent[0]
                if "r" in m:
                    cb(m["r"])
                else:
                    from .snmp import SnmpError
                    e = SnmpError(m.get("e") or "خطای SNMP")
                    e.silent = bool(m.get("s"))
                    cb(e)
                if w.draining and not w.pending:
                    self._kill(w, quit_msg=True)
                    return
        except Exception as e:  # noqa
            if not self._stop.is_set():
                log.warning("snmp worker %d read: %s", w.slot, e)
        self._died(w)

    # ---- کار
    def usable(self):
        return not self.degraded and any(w is not None and w.ready.is_set() and not w.dead for w in self.slots)

    def set_profiles(self, profiles):
        sig = hash(json.dumps(profiles, sort_keys=True, default=str))
        if sig == self._prof_sig:
            return
        self._prof_sig, self._profiles = sig, profiles
        for w in list(self.slots):
            if w is not None and w.ready.is_set() and not w.dead:
                try:
                    send_msg(w.sock, {"op": "profiles", "p": profiles}, w.lock)
                except OSError:
                    pass

    def submit(self, tid, job, cb, fallback):
        """job: {cred, host, port, cfg, timeout, retries, budget}؛ cb(نتیجه یا SnmpError)؛ fallback() اگر کارگری نبود."""
        with self._lock:
            order = [(int(tid) + k) % self.n for k in range(self.n)]
            w = next((self.slots[i] for i in order if self.slots[i] is not None and self.slots[i].ready.is_set()
                      and not self.slots[i].dead and not self.slots[i].draining), None)
            if w is None:
                self.stats["fallback"] += 1
                fallback()
                return
            with self._ids:
                self._next_id += 1
                i = self._next_id
            w.pending[i] = (cb, fallback, time.time() + float(job["budget"]) + 30)
        try:
            send_msg(w.sock, {"op": "poll", "i": i, **job}, w.lock)
        except OSError:
            with self._lock:
                ent = w.pending.pop(i, None)
            if ent:
                self.stats["fallback"] += 1
                fallback()
            self._died(w)

    # ---- خرابی، گیر کردن، بازیافت
    def _kill(self, w, quit_msg=False):
        w.dead = True
        if quit_msg and w.sock is not None:
            try:
                send_msg(w.sock, {"op": "quit"}, w.lock)
            except OSError:
                pass
        try:
            if w.sock is not None:
                w.sock.close()
        except OSError:
            pass
        try:
            w.proc.wait(3)
        except subprocess.TimeoutExpired:
            try:
                w.proc.kill()
            except OSError:
                pass
        except Exception:  # noqa
            pass

    def _died(self, w):
        with self._lock:
            pend, w.pending = dict(w.pending), {}
            was_cur = self.slots[w.slot] is w
            already = w.dead
        if not already:
            self._kill(w)
        for cb, fallback, _ in pend.values():          # کارهای ناتمام: درون برنامه دوباره
            self.stats["fallback"] += 1
            try:
                fallback()
            except Exception:  # noqa
                log.exception("snmp fallback")
        if was_cur and not self._stop.is_set() and not w.draining:
            self._failed(w.slot)

    def _failed(self, i):
        now = time.time()
        self._fails = [t for t in self._fails if now - t < FAIL_WINDOW] + [now]
        if len(self._fails) >= FAIL_MAX:
            if not self.degraded:
                log.error("snmp workers keep failing; polling in-process")
            self.degraded = "کارگرهای SNMP پشت‌سرهم از کار افتادند؛ خواندن موقتاً درون خود برنامه انجام می‌شود."
        self._backoff[i] = min(300, max(5, self._backoff[i] * 2 or 5))
        self._restart_at[i] = now + self._backoff[i]
        with self._lock:
            if self.slots[i] is not None and self.slots[i].dead:
                self.slots[i] = None

    def _watch(self):
        while not self._stop.wait(1.0):
            now = time.time()
            for w in list(self._old):
                if w.dead or not w.pending or now - w.last_rx > HUNG_AFTER:
                    self._old.remove(w)
                    if not w.dead:
                        self._died(w) if w.pending else self._kill(w, quit_msg=True)
            if self.degraded and now - max(self._fails or [0]) > FAIL_WINDOW:
                self.degraded, self._fails = "", []
            for i in range(self.n):
                w = self.slots[i]
                if w is None:
                    if not self.degraded and now >= self._restart_at[i]:
                        self.stats["restarts"] += 1
                        self._spawn(i)
                    continue
                if not w.ready.is_set():
                    if w.proc.poll() is not None or now - w.started > START_TIMEOUT:
                        log.warning("snmp worker %d did not connect (exit %s)", i, w.proc.poll())
                        with self._lock:
                            self._waiting.pop(w.token, None)
                        self._kill(w)
                        self._failed(i)
                    continue
                # کار با زمان گذشته: مثل timeout دستگاه
                late = []
                with self._lock:
                    for jid, ent in list(w.pending.items()):
                        if now > ent[2]:
                            late.append(w.pending.pop(jid))
                for cb, _, _ in late:
                    self.stats["timeouts"] += 1
                    from .snmp import SnmpError
                    cb(SnmpError("خواندن SNMP بیش از حد طول کشید و متوقف شد"))
                if w.pending and now - w.last_rx > HUNG_AFTER:
                    log.warning("snmp worker %d hung; restarting", i)
                    self._died(w)
                    continue
                if w.proc.poll() is not None:
                    self._died(w)
                    continue
                if not w.draining and (w.polls >= RECYCLE_POLLS or w.mem > RECYCLE_MB * 1024 * 1024):
                    if not any(x.slot == i for x in self._waiting.values()):
                        self.stats["recycled"] += 1
                        self._spawn(i, replace=True)

    def status(self):
        out = []
        for i, w in enumerate(self.slots):
            if w is None:
                out.append({"slot": i, "state": "restart"})
            else:
                out.append({"slot": i, "pid": w.pid, "state": "ok" if w.ready.is_set() and not w.dead else "starting",
                            "pending": len(w.pending), "polls": w.polls, "mem": w.mem})
        return {"n": self.n, "workers": out, "degraded": self.degraded, **self.stats}
