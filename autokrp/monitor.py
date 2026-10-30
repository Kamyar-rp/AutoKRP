"""
مانیتورینگ در دسترس بودن (Ping / پورت TCP / HTTP) و SNMP (v2c/v3: CPU، حافظه، دما، پورت‌ها، OID دستی؛ autokrp/snmp.py).

- هر هدف در فاصله‌ی خودش بررسی می‌شود؛ پس از «threshold» شکست پشت‌سرهم «قطع» و با اولین موفقیت «وصل» می‌شود
  (یک بسته‌ی گم‌شده هشدار نمی‌دهد). وصل ولی کندتر از slow_ms = «کند».
- تغییر وضعیت: تاریخچه، رویداد، ایمیل (mon_down/mon_up)، هشدار رابط (صدا) و hook دسکتاپ.
- داده‌ی نمودار: خلاصه‌ی هر دقیقه (۷ روز) و هر ساعت (۴۰۰ روز) در فایل‌های رمزشده‌ی monitor/؛ هر خط یک رکورد
  رمزشده است (atrest) و رکوردهای هم‌زمان جمع زده می‌شوند. قطعی‌ها با شروع/پایان در پایگاه داده‌اند.
"""
import json
import logging
import os
import random
import re
import socket
import subprocess  # nosec B404 — فقط ping سیستم با مسیر کامل و آرگومان لیستی
import threading
import time
import urllib.parse
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

from . import atrest, netscan, paths, trange
from .snmp import SnmpError, SnmpRuntime

log = logging.getLogger(__name__)
KINDS = ("ping", "tcp", "http", "snmp")
ICONS = ("server", "router", "switch", "firewall", "internet", "pc", "camera", "printer", "wifi", "storage", "phone", "other")
MIN_INTERVAL = 10
MIN_INTERVAL_SNMP = 30      # سند Cisco و MikroTik: poll پرتکرار بار CPU دستگاه را بالا می‌برد
MAX_TARGETS = 200
# 1.23.1: نگهداری بی‌پایان به‌طور پیش‌فرض (خواسته‌ی کاربر: داده‌ی قبلی پاک نشود). ۰ = بدون محدودیت؛
# ادمین می‌تواند در تنظیمات ← مانیتورینگ سقف بگذارد (keep_detail_days برای دقیقه‌ای/۵ دقیقه‌ای، keep_hour_days برای ساعتی و قطعی‌ها)
DETAIL_MIN_DAYS, HOUR_MIN_DAYS, KEEP_MAX_DAYS = 7, 30, 36500


def keep_days(cfg):
    """(روزهای داده‌ی دقیق، روزهای داده‌ی ساعتی) — ۰ = بدون محدودیت."""
    c = cfg or {}
    def one(k, lo):
        try:
            v = int(c.get(k) or 0)
        except (TypeError, ValueError):
            return 0
        return 0 if v <= 0 else max(lo, min(KEEP_MAX_DAYS, v))
    return one("keep_detail_days", DETAIL_MIN_DAYS), one("keep_hour_days", HOUR_MIN_DAYS)
ALERT_KEEP = 200
_HOST_RE = re.compile(r"^[A-Za-z0-9._:\-\[\]%]+$")
_RTT_RE = re.compile(rb"[=<]\s*(\d+(?:[.,]\d+)?)\s*ms", re.I)


class MonitorError(Exception):
    pass


def clean_target(t, owner=None):
    """اعتبارسنجی هدف از رابط."""
    name = str(t.get("name") or "").strip()[:80]
    kind = str(t.get("kind") or "ping").lower()
    if kind not in KINDS:
        raise MonitorError("روش بررسی نامعتبر است.")
    host = str(t.get("host") or "").strip()
    url = str(t.get("url") or "").strip()
    port = None
    if kind == "http":
        if not re.match(r"^https?://", url, re.I) or len(url) > 500 or any(c in url for c in " \r\n\t"):
            raise MonitorError("آدرس HTTP باید با http:// یا https:// شروع شود.")
        host = urllib.parse.urlsplit(url).hostname or ""
    if not host or len(host) > 253 or host.startswith("-") or not _HOST_RE.match(host):
        raise MonitorError(f"آدرس نامعتبر است: {host or '(خالی)'}")
    if kind in ("tcp", "snmp"):
        try:
            port = int(t.get("port") or (161 if kind == "snmp" else 0))
            if not 0 < port < 65536:
                raise ValueError
        except (TypeError, ValueError):
            raise MonitorError("پورت نامعتبر است.")
    snmp_cfg = ""
    if kind == "snmp":
        from .snmp import clean_cfg
        try:
            snmp_cfg = json.dumps(clean_cfg(t.get("snmp") if isinstance(t.get("snmp"), dict) else {}), ensure_ascii=False)
        except SnmpError as e:
            raise MonitorError(str(e))

    def num(k, lo, hi, d, cast=int):
        try:
            v = cast(t.get(k) if t.get(k) not in (None, "") else d)
        except (TypeError, ValueError):
            raise MonitorError(f"مقدار «{k}» نامعتبر است.")
        if not lo <= v <= hi:
            raise MonitorError(f"مقدار «{k}» باید بین {lo} و {hi} باشد.")
        return v
    icon = str(t.get("icon") or "server")
    if icon not in ICONS and not re.fullmatch(r"custom:[0-9a-f]{12}", icon):
        icon = "other"
    return {"id": t.get("id"), "name": name or host, "host": host, "kind": kind, "port": port, "url": url if kind == "http" else "",
            "interval": num("interval", MIN_INTERVAL_SNMP if kind == "snmp" else MIN_INTERVAL, 86400, 60 if kind == "snmp" else 30), "threshold": num("threshold", 1, 20, 3),
            "timeout": num("timeout", 0.5, 30, 3 if kind == "snmp" else 2, float), "slow_ms": num("slow_ms", 0, 60000, 0),
            "snmp": snmp_cfg, "cred_id": None,       # cred_id را api بعد از بررسی دسترسی می‌گذارد
            "icon": icon, "grp": str(t.get("grp") or "").strip()[:60], "owner": owner if owner is not None else (t.get("owner") or ""),
            "enabled": 1 if t.get("enabled", True) else 0, "notify": 1 if t.get("notify", True) else 0,
            "notes": str(t.get("notes") or "")[:500], "parent_id": _int_or_none(t.get("parent_id")),
            "cert_days": num("cert_days", 0, 365, 0) if kind == "http" and url.lower().startswith("https://") else 0}


def _int_or_none(v):
    try:
        v = int(v)
        return v if v > 0 else None
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------- پنجره‌ی نگهداری (1.24)
DAYS = range(7)            # 0 = یکشنبه … 6 = شنبه (مثل Date.getDay در رابط)


def _hm(v):
    m = re.fullmatch(r"(\d{1,2}):(\d{2})", str(v or "").strip())
    if not m or int(m.group(1)) > 23 or int(m.group(2)) > 59:
        raise MonitorError("ساعت باید به شکل HH:MM باشد.")
    return f"{int(m.group(1)):02d}:{m.group(2)}"


def clean_maint(m, owner):
    """اعتبارسنجی پنجره‌ی نگهداری از رابط. scope = {"ids": [...], "groups": [...]}."""
    name = str(m.get("name") or "").strip()[:80] or "نگهداری"
    kind = m.get("kind") if m.get("kind") in ("once", "weekly") else "once"
    sc = m.get("scope") if isinstance(m.get("scope"), dict) else {}
    ids = sorted({int(x) for x in (sc.get("ids") or []) if str(x).isdigit()})[:500]
    groups = sorted({str(g).strip()[:60] for g in (sc.get("groups") or []) if str(g).strip()})[:100]
    if not ids and not groups:
        raise MonitorError("دست‌کم یک هدف یا گروه را انتخاب کنید.")
    out = {"id": m.get("id"), "name": name, "kind": kind, "scope": json.dumps({"ids": ids, "groups": groups}, ensure_ascii=False),
           "enabled": 1 if m.get("enabled", True) else 0, "owner": owner, "note": str(m.get("note") or "")[:300],
           "start": None, "end": None, "days": "", "t_from": "", "t_to": ""}
    if kind == "once":
        try:
            a, b = float(m.get("start")), float(m.get("end"))
        except (TypeError, ValueError):
            raise MonitorError("شروع و پایان پنجره را مشخص کنید.") from None
        if not b > a:
            raise MonitorError("پایان پنجره باید بعد از شروع آن باشد.")
        if b - a > 90 * 86400:
            raise MonitorError("پنجره‌ی یک‌باره حداکثر ۹۰ روز است.")
        out["start"], out["end"] = a, b
    else:
        days = sorted({int(d) for d in (m.get("days") or []) if str(d).isdigit() and int(d) in DAYS})
        if not days:
            raise MonitorError("دست‌کم یک روز هفته را انتخاب کنید.")
        out["days"], out["t_from"], out["t_to"] = ",".join(map(str, days)), _hm(m.get("t_from")), _hm(m.get("t_to"))
        if out["t_from"] == out["t_to"]:
            raise MonitorError("ساعت شروع و پایان یکسان است.")
    return out


def maint_scope(w):
    try:
        sc = json.loads(w.get("scope") or "{}")
    except ValueError:
        sc = {}
    return {int(x) for x in sc.get("ids") or []}, set(sc.get("groups") or [])


def maint_on(w, now=None):
    """آیا پنجره همین حالا فعال است؟ (هفتگی: پنجره‌ی شبانه مثل 23:00 تا 02:00 متعلق به روز شروع است)"""
    if not w.get("enabled"):
        return False
    now = time.time() if now is None else now
    if w.get("kind") == "once":
        return (w.get("start") or 0) <= now < (w.get("end") or 0)
    lt = time.localtime(now)
    days = {int(d) for d in str(w.get("days") or "").split(",") if d.strip().isdigit()}
    wd = (lt.tm_wday + 1) % 7                    # Python: دوشنبه=0 ← یکشنبه=0
    cur = lt.tm_hour * 60 + lt.tm_min
    a = int(w["t_from"][:2]) * 60 + int(w["t_from"][3:])
    b = int(w["t_to"][:2]) * 60 + int(w["t_to"][3:])
    if a < b:
        return wd in days and a <= cur < b
    return (wd in days and cur >= a) or (((wd - 1) % 7) in days and cur < b)


def maint_applies(w, t):
    """پنجره‌ی اپراتور فقط روی هدف‌های خود او؛ پنجره‌ی ادمین (owner خالی) روی همه."""
    if w.get("owner") and w["owner"] != (t.get("owner") or ""):
        return False
    ids, groups = maint_scope(w)
    return t["id"] in ids or (bool(t.get("grp")) and t["grp"] in groups)


# ---------------------------------------------------------------- بررسی‌ها
def check_ping(host, timeout):
    exe = netscan._ping_exe()
    if not exe:
        return False, None, "ping در دسترس نیست"
    if os.name == "nt":
        cmd = [exe, "-n", "1", "-w", str(max(1, int(timeout * 1000))), host]
    else:
        cmd = [exe, "-c", "1", "-W", str(max(1, int(round(timeout)))), host]
    t0 = time.perf_counter()
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL,  # nosec B603
                           timeout=timeout + 2, creationflags=0x08000000 if os.name == "nt" else 0)
    except subprocess.TimeoutExpired:
        return False, None, "timeout"
    except OSError as e:
        return False, None, str(e)
    out = p.stdout.upper()
    if os.name != "nt":
        ok = p.returncode == 0
    elif ":" in host:
        ok = p.returncode == 0 and b"UNREACHABLE" not in out and b"TIMED OUT" not in out
    else:
        ok = p.returncode == 0 and b"TTL=" in out
    if not ok:
        return False, None, "بدون پاسخ ping"
    m = _RTT_RE.search(p.stdout)
    rtt = float(m.group(1).replace(b",", b".")) if m else (time.perf_counter() - t0) * 1000
    return True, round(rtt, 1), ""


def check_tcp(host, port, timeout):
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError:
        return False, None, "نام پیدا نشد"
    fam, _, _, _, addr = infos[0]
    s = socket.socket(fam, socket.SOCK_STREAM)
    s.settimeout(timeout)
    t0 = time.perf_counter()
    try:
        rc = s.connect_ex(addr)
        if rc == 0:
            return True, round((time.perf_counter() - t0) * 1000, 1), ""
        return False, None, f"پورت {port} بسته است ({rc})"
    except socket.timeout:
        return False, None, "timeout"
    except OSError as e:
        return False, None, str(e)[:120]
    finally:
        s.close()


CERT_EVERY = 3600          # گواهی هر ساعت یک بار خوانده می‌شود (نه با هر بررسی)


def cert_expiry(url, timeout):
    """تاریخ انقضای گواهی سرور HTTPS. فقط گواهی خوانده می‌شود (بدون ارسال داده)؛ برای همین گواهی خودامضا هم خوانده می‌شود."""
    import ssl

    from cryptography import x509
    u = urllib.parse.urlsplit(url)
    host, port = u.hostname, u.port or 443
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # nosec B501 — فقط خواندن تاریخ انقضا؛ هیچ داده‌ای فرستاده نمی‌شود
    with socket.create_connection((host, port), timeout=timeout) as s:
        with ctx.wrap_socket(s, server_hostname=host) as ss:
            der = ss.getpeercert(binary_form=True)
    c = x509.load_der_x509_certificate(der)
    na = c.not_valid_after_utc.timestamp()
    cn = c.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
    return {"expires": na, "days": int((na - time.time()) // 86400), "cn": (cn[0].value if cn else "")[:120],
            "at": time.time(), "err": ""}


def check_http(url, timeout):
    r = netscan.http_check(url, timeout)
    st = r.get("status")
    if st == "" or st is None:
        return False, None, (r.get("error") or "بدون پاسخ")[:160]
    if int(st) >= 500:
        return False, r.get("latency_ms"), f"HTTP {st}"
    return True, r.get("latency_ms"), f"HTTP {st}"


# ---------------------------------------------------------------- مانیتور
class Monitor:
    def __init__(self, settings, store, emit=None, notify=None, demo=False):
        self.settings, self.store, self.demo = settings, store, demo
        self.emit = emit or (lambda *a, **k: None)
        self.notify = notify or (lambda *a, **k: None)
        self.on_alert = None                # hook دسکتاپ (صدای پس‌زمینه / نمایش پنجره)
        self.history = None                 # (kind, target, status, detail)
        self.state = {}
        self.minutes = {}                   # tid → deque[(minute_ts, n, ok, rtt_sum, rtt_n, rtt_max)]
        self._cur_min, self._min_acc = 0, {}
        self._cur_hour, self._hour_acc = 0, {}
        self.alerts = deque(maxlen=ALERT_KEEP)
        self.seq = 0
        self._targets = None
        self._busy = set()
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._pool = ThreadPoolExecutor(max_workers=24, thread_name_prefix="mon")
        self._thread = None
        self._last_purge = 0
        self._maint = None                  # کش پنجره‌های نگهداری
        self.snmp = SnmpRuntime(settings, store, demo)
        from .devevents import DevEvents
        self.events = DevEvents(self)       # Trap و Syslog (1.25)
        from .topology import Topology
        self.topo = Topology(self)          # نقشه‌ی همسایه‌ها (1.26)
        self._ev_sig = None

    # ---- چرخه
    def start(self):
        try:
            self._warm()
        except Exception:
            log.exception("monitor warm")
        self._thread = threading.Thread(target=self._loop, name="monitor", daemon=True)
        self._thread.start()

    def _events_tick(self):
        """گیرنده‌های Trap/Syslog فقط وقتی مانیتورینگ فعال است و با تغییر تنظیمات دوباره راه‌اندازی می‌شوند."""
        c = self.events.cfg()
        sig = json.dumps({k: c[k] for k in ("trap_enabled", "trap_port", "syslog_enabled", "syslog_port", "syslog_tcp", "bind")},
                         sort_keys=True) if (c["trap_enabled"] or c["syslog_enabled"]) else None
        if sig != self._ev_sig:
            self._ev_sig = sig
            if sig:
                self.events.start()
            else:
                self.events.stop()

    def stop(self):
        self._stop.set()
        try:
            self.events.stop()
            self._ev_sig = None
        except Exception:
            log.exception("events stop")
        try:
            self._flush(force=True)
            self.snmp.flush(self._active(), force=True)
        except Exception:
            log.exception("monitor flush")
        self._pool.shutdown(wait=False, cancel_futures=True)

    def reload(self):
        self._targets = None
        self._maint = None
        if hasattr(self, "events"):
            self.events.invalidate()

    def maint_windows(self):
        if self._maint is None:
            self._maint = self.store.maint_list()
        return self._maint

    def in_maint(self, t, now=None):
        """نام پنجره‌ی نگهداری فعال این هدف یا None."""
        for w in self.maint_windows():
            if maint_applies(w, t) and maint_on(w, now):
                return w.get("name") or "نگهداری"
        return None

    def ancestors(self, t):
        """زنجیره‌ی پدرها (بدون حلقه، حداکثر ۱۰ سطح)."""
        out, seen, cur, ts = [], {t["id"]}, t, self.targets()
        for _ in range(10):
            pid = cur.get("parent_id")
            if not pid or pid in seen or pid not in ts:
                break
            seen.add(pid)
            cur = ts[pid]
            out.append(cur)
        return out

    def _parent_block(self, t, now):
        """("down", نام) اگر یکی از پدرها قطع/در دسترس نیست؛ ("wait", نام) اگر پدر در حال شکست است و هنوز تصمیم نگرفته؛ None."""
        for p in self.ancestors(t):
            if not p.get("enabled"):
                continue
            ps = self.state.get(p["id"]) or {}
            if ps.get("status") in ("down", "unreachable"):
                return "down", p.get("name") or p["host"]
            if ps.get("fails", 0) > 0:
                return "wait", p.get("name") or p["host"]
        return None

    def targets(self):
        if self._targets is None:
            self._targets = {t["id"]: t for t in self.store.mon_targets()}
        return self._targets

    def _active(self):
        v = self.settings.vault
        if not (self.settings.get("tools_enabled", default={}) or {}).get("monitor", True):
            return False          # مانیتورینگ در تنظیمات خاموش است
        return v is None or v.unlocked()

    def _loop(self):
        while not self._stop.wait(1.0):
            try:
                if not self._active():
                    if self._ev_sig:
                        self.events.stop()
                        self._ev_sig = None
                    continue
                now = time.time()
                for tid, t in list(self.targets().items()):
                    if not t.get("enabled"):
                        continue
                    st = self.state.setdefault(tid, {"status": "unknown", "since": now, "fails": 0, "next": now, "rtt": None,
                                                     "err": "", "last": 0, "checks": 0})
                    mw = self.in_maint(t, now)
                    if bool(mw) != bool(st.get("maint")):
                        self._maint_change(t, st, mw, now)
                    if now >= st["next"] and tid not in self._busy:
                        self._busy.add(tid)
                        st["next"] = now + max(MIN_INTERVAL_SNMP if t.get("kind") == "snmp" else MIN_INTERVAL, int(t.get("interval") or 30))
                        self._pool.submit(self._run, dict(t))
                self._events_tick()
                self._flush()
                self.snmp.flush(True)
                if now - self._last_purge > 3600:
                    self._last_purge = now
                    self._purge()
            except Exception:
                log.exception("monitor loop")

    def _run(self, t):
        tid = t["id"]
        events = []
        try:
            if t["kind"] == "snmp":
                try:
                    ok, rtt, err, events = self.snmp.poll(t)
                except SnmpError as e:
                    ok, rtt, err = False, None, str(e)
            elif self.demo:
                time.sleep(random.uniform(0.05, 0.3))   # nosec B311 — داده‌ی نمایشی
                ok = random.random() > (0.35 if "down" in (t.get("name") or "").lower() else 0.03)  # nosec B311
                rtt, err = (round(random.uniform(1, 80), 1), "") if ok else (None, "بدون پاسخ (Demo)")  # nosec B311
            elif t["kind"] == "tcp":
                ok, rtt, err = check_tcp(t["host"], int(t["port"]), float(t.get("timeout") or 2))
            elif t["kind"] == "http":
                ok, rtt, err = check_http(t["url"], float(t.get("timeout") or 5))
                if ok and int(t.get("cert_days") or 0) > 0:
                    self._cert(t)
            else:
                ok, rtt, err = check_ping(t["host"], float(t.get("timeout") or 2))
            self._result(t, ok, rtt, err)
            if events:
                self._snmp_events(t, events)
        except Exception as e:
            log.exception("monitor check")
            self._result(t, False, None, str(e)[:120])
        finally:
            self._busy.discard(tid)

    def _cert(self, t):
        """1.31: هشدار نزدیک بودن انقضای گواهی HTTPS (روزی یک بار تا تمدید). قطع حساب نمی‌شود."""
        st = self.state.setdefault(t["id"], {"status": "unknown", "since": time.time(), "fails": 0, "next": time.time()})
        c = st.get("cert") or {}
        if c.get("url") == t["url"] and time.time() - c.get("at", 0) < CERT_EVERY:
            return
        try:
            c = {**cert_expiry(t["url"], float(t.get("timeout") or 5)), "url": t["url"], "warned": c.get("warned", 0)}
        except Exception as e:  # noqa — خطای خواندن گواهی؛ وضعیت HTTP دست نمی‌خورد
            c = {"url": t["url"], "at": time.time(), "err": str(e)[:150], "warned": c.get("warned", 0)}
        st["cert"] = c
        days, lim = c.get("days"), int(t.get("cert_days") or 0)
        if days is None or days > lim or st.get("maint") or time.time() - c.get("warned", 0) < 86400:
            return
        c["warned"] = time.time()
        when = time.strftime("%Y-%m-%d", time.localtime(c["expires"]))
        msg = (f"گواهی HTTPS «{t['name']}» منقضی شده است ({when})" if days < 0
               else f"گواهی HTTPS «{t['name']}» تا {days} روز دیگر منقضی می‌شود ({when})")
        self.emit("warn", msg, "monitor")
        if self.history:
            self.history("monitor", t["name"], "warn", msg, "")
        if t.get("notify"):
            self.notify("mon_cert", msg)

    def _result(self, t, ok, rtt, err):
        tid, now = t["id"], time.time()
        if tid not in self.targets():
            return
        with self._lock:
            st = self.state.setdefault(tid, {"status": "unknown", "since": now, "fails": 0, "next": now})
            st.update(last=now, checks=st.get("checks", 0) + 1, err="" if ok else err)
            if ok:
                st["rtt"] = rtt
            # خلاصه‌ی دقیقه و ساعت (بررسی‌های داخل پنجره‌ی نگهداری در در دسترس بودن حساب نمی‌شوند)
            for acc in (() if st.get("maint") else (self._min_acc, self._hour_acc)):
                a = acc.setdefault(tid, [0, 0, 0.0, 0, 0.0])
                a[0] += 1
                if ok:
                    a[1] += 1
                    if rtt is not None:
                        a[2] += rtt
                        a[3] += 1
                        a[4] = max(a[4], rtt)
            prev = st["status"]
            cause = None
            if ok:
                st["fails"] = 0
                st.pop("wait_since", None)
                slow = int(t.get("slow_ms") or 0)
                new = "slow" if slow and rtt is not None and rtt > slow else "up"
            else:
                st["fails"] = st.get("fails", 0) + 1
                new = "down" if st["fails"] >= int(t.get("threshold") or 3) else prev
                if new == "down" and prev != "down":
                    blk = self._parent_block(t, now)
                    if blk and blk[0] == "down":
                        new, cause = "unreachable", blk[1]
                    elif blk and blk[0] == "wait" and now - st.setdefault("wait_since", now) < 300:
                        new = prev            # پدر هم در حال شکست است: تا تصمیم پدر صبر (حداکثر ۵ دقیقه)
                        self._nudge_parents(t)
                    else:
                        st.pop("wait_since", None)
            if new != prev:
                st["status"] = new
                st["since"] = now
                st["cause"] = cause or ""
        if new != prev:
            self._transition(t, prev, new, err, rtt, cause, st.get("maint"))

    def _nudge_parents(self, t):
        for p in self.ancestors(t):
            ps = self.state.get(p["id"])
            if ps and ps.get("fails", 0) > 0 and ps.get("status") not in ("down", "unreachable"):
                ps["next"] = 0             # پدر زودتر بررسی شود تا وضعیت فرزند معلوم شود

    @staticmethod
    def _where(t):
        return t["url"] if t["kind"] == "http" else (f"{t['host']}:{t['port']}" if t["kind"] == "tcp"
                                                     else f"{t['host']} (SNMP)" if t["kind"] == "snmp" else t["host"])

    def _transition(self, t, prev, new, err, rtt, cause=None, maint=None):
        name, now = t.get("name") or t["host"], time.time()
        where = self._where(t)
        owner = t.get("owner") or ""
        if new in ("down", "unreachable"):
            if prev in ("down", "unreachable"):
                return
            if maint:
                self.store.mon_event_open(t["id"], name, now, f"{err} — در پنجره‌ی نگهداری «{maint}»", "maint")
                self.emit("info", f"«{name}» در پنجره‌ی نگهداری «{maint}» قطع است ({where})", "monitor")
                return
            if new == "unreachable":
                self.store.mon_event_open(t["id"], name, now, f"در دسترس نیست به‌خاطر قطع «{cause}» — {err}", "unreach")
                self.emit("warn", f"«{name}» در دسترس نیست به‌خاطر قطع «{cause}» ({where})", "monitor")
                if self.history:
                    self.history("monitor", name, "warn", f"در دسترس نیست به‌خاطر قطع «{cause}» — {where}", owner)
                return
            self.store.mon_event_open(t["id"], name, now, err)
            msg = f"«{name}» قطع شد ({where}) — {err}"
            self.emit("error", msg, "monitor")
            if self.history:
                self.history("monitor", name, "error", f"قطع شد — {where} — {err}", owner)
            if t.get("notify"):
                self.notify("mon_down", msg)
            self._alert(t, "down", msg)
        elif prev in ("down", "unreachable"):
            ev = self.store.mon_event_open_get(t["id"])
            self.store.mon_event_close(t["id"], now)
            dur = int(now - ev["start"]) if ev else 0
            kind = (ev or {}).get("kind") or "down"
            if kind != "down":           # قطعی به‌خاطر پدر یا در نگهداری: بدون هشدار
                self.emit("info", f"«{name}» دوباره در دسترس است ({where})", "monitor")
                if kind == "unreach" and self.history:
                    self.history("monitor", name, "ok", f"دوباره در دسترس — {where} — {fmt_dur(dur)}", owner)
            else:
                msg = f"«{name}» دوباره وصل شد ({where}) — قطعی {fmt_dur(dur)}"
                self.emit("info", msg, "monitor")
                if self.history:
                    self.history("monitor", name, "ok", f"دوباره وصل شد — {where} — قطعی {fmt_dur(dur)}", owner)
                if t.get("notify"):
                    self.notify("mon_up", msg)
                self._alert(t, "up", msg)
            if prev == "down":
                self._wake_children(t)
        elif new == "slow" and prev == "up":
            self.emit("warn", f"«{name}» کند است ({rtt} ms)", "monitor")
        if new in ("up", "slow") and prev == "unreachable":
            self._wake_children(t)

    def _wake_children(self, t):
        """پدر برگشت: فرزندانی که «در دسترس نیست» بودند فوراً دوباره بررسی شوند."""
        for c in self.targets().values():
            if any(p["id"] == t["id"] for p in self.ancestors(c)):
                cs = self.state.get(c["id"])
                if cs and cs.get("status") == "unreachable":
                    cs["next"] = 0

    def _maint_change(self, t, st, mw, now):
        """ورود/خروج از پنجره‌ی نگهداری."""
        name = t.get("name") or t["host"]
        with self._lock:
            st["maint"] = mw or ""
        if mw:
            self.emit("info", f"«{name}» وارد پنجره‌ی نگهداری «{mw}» شد", "monitor")
            if self.history:
                self.history("monitor", name, "ok", f"شروع نگهداری «{mw}»", t.get("owner") or "")
            return
        if self.history:
            self.history("monitor", name, "ok", "پایان نگهداری", t.get("owner") or "")
        ev = self.store.mon_event_open_get(t["id"])
        if ev and ev.get("kind") == "maint":
            # بعد از پایان نگهداری هنوز قطع است ← قطعی واقعی با هشدار
            self.store.mon_event_close(t["id"], now)
            with self._lock:
                st["status"] = "up"
            self._transition(t, "up", "down", st.get("err") or "بعد از پایان نگهداری هنوز قطع است", None)
            with self._lock:
                st["status"] = "down"
                st["since"] = now

    def _snmp_events(self, t, events):
        """تغییر سطح آستانه‌های SNMP: crit = هشدار کامل (بنر، صدا، ایمیل)؛ warn = رویداد و تاریخچه؛ برطرف شدن crit = اعلام.
        در پنجره‌ی نگهداری فقط رویداد ثبت می‌شود (بدون هشدار، صدا و ایمیل)."""
        name = t.get("name") or t["host"]
        if (self.state.get(t["id"]) or {}).get("maint"):
            for key, old, new, msg in events:
                self.emit("info", f"«{name}»: {msg} (در پنجره‌ی نگهداری)", "monitor")
            return
        for key, old, new, msg in events:
            full = f"«{name}»: {msg}"
            if key == "reboot":
                self.emit("warn", full, "monitor")
                if self.history:
                    self.history("monitor", name, "warn", msg, t.get("owner") or "")
                if t.get("notify"):
                    self.notify("mon_alarm", full)
                continue
            if new == "crit":
                self.emit("error", full, "monitor")
                if self.history:
                    self.history("monitor", name, "error", f"هشدار بحرانی — {msg}", t.get("owner") or "")
                if t.get("notify"):
                    self.notify("mon_alarm", f"هشدار بحرانی — {full}")
                self._alert(t, "alarm", full, key)
            elif new == "warn":
                self.emit("warn", full, "monitor")
                if self.history:
                    self.history("monitor", name, "warn", f"هشدار — {msg}", t.get("owner") or "")
                if old == "crit":
                    self._alert(t, "clear", full, key)
            else:
                self.emit("info", f"{full} — برطرف شد", "monitor")
                if self.history:
                    self.history("monitor", name, "ok", f"برطرف شد — {msg}", t.get("owner") or "")
                if old == "crit":
                    if t.get("notify"):
                        self.notify("mon_alarm", f"برطرف شد — {full}")
                    self._alert(t, "clear", f"{full} — برطرف شد", key)

    def _alert(self, t, state, msg, key=""):
        with self._lock:
            self.seq += 1
            a = {"seq": self.seq, "ts": time.time(), "target": t["id"], "name": t.get("name") or t["host"], "state": state,
                 "msg": msg, "owner": t.get("owner") or "", "key": key}
            self.alerts.append(a)
        if self.on_alert:
            try:
                self.on_alert(a)
            except Exception:
                log.exception("monitor alert hook")

    # ---- فایل‌ها
    def _dir(self):
        d = paths.data_dir() / "monitor"
        d.mkdir(exist_ok=True)
        return d

    def _append(self, name, rec):
        with open(self._dir() / name, "a", encoding="utf-8") as f:
            f.write(atrest._enc_line(json.dumps(rec, separators=(",", ":"))) + "\n")

    def _flush(self, force=False):
        now = time.time()
        minute, hour = int(now // 60) * 60, int(now // 3600) * 3600
        if not self._cur_min:
            self._cur_min, self._cur_hour = minute, hour
        if (minute != self._cur_min or force) and self._min_acc:
            with self._lock:
                acc, self._min_acc = self._min_acc, {}
            m = self._cur_min
            for tid, a in acc.items():
                dq = self.minutes.setdefault(tid, deque(maxlen=1440))
                if dq and dq[-1][0] == m:
                    o = dq.pop()
                    a = [o[1] + a[0], o[2] + a[1], o[3] + a[2], o[4] + a[3], max(o[5], a[4])]
                dq.append((m, *a))
            if self._active():
                try:
                    self._append(f"m_{time.strftime('%Y%m%d', time.localtime(m))}.log", {"t": m, "d": acc})
                except Exception:
                    log.exception("monitor minute write")
        if minute != self._cur_min:
            self._cur_min = minute
        if (hour != self._cur_hour or force) and self._hour_acc:
            with self._lock:
                acc, self._hour_acc = self._hour_acc, {}
            h = self._cur_hour
            if self._active():
                try:
                    self._append(f"h_{time.strftime('%Y%m', time.localtime(h))}.log", {"t": h, "d": acc})
                except Exception:
                    log.exception("monitor hour write")
        if hour != self._cur_hour:
            self._cur_hour = hour

    @staticmethod
    def _read(path):
        out = []
        try:
            for line in atrest.read_log_lines(path):
                try:
                    out.append(json.loads(line))
                except ValueError:
                    continue
        except OSError:
            pass
        return out

    def _warm(self):
        """۲۴ ساعت گذشته‌ی خلاصه‌ی دقیقه‌ای برای نمودار کوچک کارت‌ها."""
        since = time.time() - 86400
        for day in (since, time.time()):
            p = self._dir() / f"m_{time.strftime('%Y%m%d', time.localtime(day))}.log"
            if not p.exists():
                continue
            for rec in self._read(p):
                if rec.get("t", 0) < since:
                    continue
                for tid, a in (rec.get("d") or {}).items():
                    dq = self.minutes.setdefault(int(tid), deque(maxlen=1440))
                    if dq and dq[-1][0] == rec["t"]:
                        o = dq.pop()
                        a = [o[1] + a[0], o[2] + a[1], o[3] + a[2], o[4] + a[3], max(o[5], a[4])]
                    dq.append((rec["t"], *a))

    def _purge(self):
        """فقط اگر ادمین سقف گذاشته باشد؛ پیش‌فرض هیچ داده‌ای پاک نمی‌شود. پوشه‌ی SNMP هدف حذف‌شده همیشه پاک می‌شود."""
        now = time.time()
        kd, kh = keep_days(self.settings.get("monitor"))
        if kd:
            for f in self._dir().glob("m_*.log"):
                try:
                    if datetime.strptime(f.stem[2:], "%Y%m%d").timestamp() < now - (kd + 1) * 86400:
                        f.unlink()
                except (ValueError, OSError):
                    continue
        if kh:
            for f in self._dir().glob("h_*.log"):
                try:
                    if datetime.strptime(f.stem[2:], "%Y%m").timestamp() < now - (kh + 31) * 86400:
                        f.unlink()
                except (ValueError, OSError):
                    continue
            self.store.mon_purge_events(now - kh * 86400)
        try:
            self.events.purge()
        except Exception:
            log.exception("events purge")
        try:
            self.snmp.purge(kd, kh, set(self.targets()))
        except Exception:
            log.exception("snmp purge")

    def storage(self):
        """حجم داده‌های مانیتورینگ روی دیسک (بایت) و رشد روزانه‌ی تقریبی از روز کامل قبل."""
        d = self._dir()
        out = {"minute": 0, "hour": 0, "snmp_detail": 0, "snmp_hour": 0, "minute_days": 0, "oldest": None}
        y = time.strftime("%Y%m%d", time.localtime(time.time() - 86400))
        day_m = day_s = 0
        for f in d.glob("m_*.log"):
            sz = f.stat().st_size
            out["minute"] += sz
            out["minute_days"] += 1
            if f.stem[2:] == y:
                day_m = sz
        for f in d.glob("h_*.log"):
            out["hour"] += f.stat().st_size
        old = sorted(f.stem[2:] for f in d.glob("[mh]_*.log"))
        out["oldest"] = old[0] if old else None
        sd = d / "snmp"
        if sd.exists():
            for f in sd.glob("*/*.log"):
                sz = f.stat().st_size
                if f.name.startswith("f_"):
                    out["snmp_detail"] += sz
                    if f.stem[2:] == y:
                        day_s += sz
                else:
                    out["snmp_hour"] += sz
        out["per_day"] = day_m + day_s
        out["per_day_hour"] = round((out["hour"] + out["snmp_hour"]) / max(1, out["minute_days"])) if out["minute_days"] else 0
        return out

    # ---- خروجی برای رابط
    def public(self, t):
        st = self.state.get(t["id"]) or {}
        status = st.get("status", "unknown") if t.get("enabled") else "paused"
        dq = self.minutes.get(t["id"]) or ()
        # نمودار کوچک: ۴۸ خانه‌ی نیم‌ساعته در ۲۴ ساعت گذشته (درصد در دسترس بودن)
        now = time.time()
        start = int((now - 86400) // 1800) * 1800
        bins = [[0, 0] for _ in range(49)]
        for m, n, ok, *_ in dq:
            i = int((m - start) // 1800)
            if 0 <= i < len(bins):
                bins[i][0] += n
                bins[i][1] += ok
        out = {k: v for k, v in t.items() if k != "snmp"}
        if t.get("kind") == "snmp":
            from .snmp import load_cfg
            out["snmp_sum"] = self.snmp.summary(t["id"])
            out["snmp_cfg"] = load_cfg(t)
        cert = st.get("cert") or {}
        if cert:
            out["cert"] = {k: cert.get(k) for k in ("days", "expires", "cn", "err", "at")}
        return {**out, "status": status, "since": st.get("since"), "rtt": st.get("rtt"), "err": st.get("err", ""),
                "maint": st.get("maint") or "", "cause": st.get("cause") or "",
                "last": st.get("last"), "fails": st.get("fails", 0),
                "spark": [None if n == 0 else round(100 * ok / n, 1) for n, ok in bins]}

    def series(self, rng, ids):
        """داده‌ی گزارش: bins = [(شروع، n، ok، rtt_sum، rtt_n، rtt_max)] برای هر هدف.
        rng: بازه‌ی آماده («24h») یا {"from", "to"}؛ دقت از روی طول بازه (trange)."""
        now = time.time()
        since, until = trange.resolve(rng, now)
        kd = keep_days(self.settings.get("monitor"))[0]
        minute_ok = not kd or since >= now - kd * 86400 + 120
        step = trange.pick_step(until - since, 60 if minute_ok else 3600)
        start, nb = trange.grid(since, until, step)
        src = []
        if step < 3600 and since < now - 86400 - 120 and not any(
                (self._dir() / f"m_{day}.log").exists() for day in trange.days(since, until, "%Y%m%d")):
            step = trange.pick_step(until - since, 3600)     # داده‌ی دقیقه‌ای این روزها نیست (نسخه‌های قبل ۷ روز نگه می‌داشتند) ← ساعتی
            start, nb = trange.grid(since, until, step)
        if step < 3600:
            if since >= now - 86400 - 120:          # ۲۴ ساعت اخیر در حافظه است (۱۴۴۰ دقیقه)
                for tid in ids:
                    for m, *a in self.minutes.get(tid) or ():
                        src.append((m, tid, a))
            else:
                for day in trange.days(since, until, "%Y%m%d"):
                    p = self._dir() / f"m_{day}.log"
                    if p.exists():
                        for rec in self._read(p):
                            if start <= rec.get("t", 0) <= until:
                                for tid, a in (rec.get("d") or {}).items():
                                    if int(tid) in ids:
                                        src.append((rec["t"], int(tid), a))
            with self._lock:
                cur = [(self._cur_min, tid, list(a)) for tid, a in self._min_acc.items() if tid in ids]
            res = "minute"
        else:
            for mo in trange.days(since - 3600, until, "%Y%m"):
                p = self._dir() / f"h_{mo}.log"
                if p.exists():
                    for rec in self._read(p):
                        if start - 3600 < rec.get("t", 0) <= until:
                            for tid, a in (rec.get("d") or {}).items():
                                if int(tid) in ids:
                                    src.append((rec["t"], int(tid), a))
            with self._lock:
                cur = [(self._cur_hour, tid, list(a)) for tid, a in self._hour_acc.items() if tid in ids]
            res = "hour"
        src += [x for x in cur if x[0] and x[0] <= until]
        out = {tid: [[start + i * step, 0, 0, 0.0, 0, 0.0] for i in range(nb)] for tid in ids}
        for t0, tid, a in src:
            i = int((t0 - start) // step)
            if tid in out and 0 <= i < nb:
                b = out[tid][i]
                b[1] += a[0]
                b[2] += a[1]
                b[3] += a[2]
                b[4] += a[3]
                b[5] = max(b[5], a[4])
        return {"step": step, "since": since, "until": until, "data": out, "res": res}


def fmt_dur(s):
    s = int(s or 0)
    if s < 60:
        return f"{s} ثانیه"
    if s < 3600:
        return f"{s // 60} دقیقه"
    if s < 86400:
        return f"{s // 3600} ساعت و {s % 3600 // 60} دقیقه"
    return f"{s // 86400} روز و {s % 86400 // 3600} ساعت"


def quiet_now(cfg):
    q = (cfg or {}).get("quiet") or {}
    if not q.get("enabled"):
        return False
    try:
        a = datetime.strptime(q.get("from") or "23:00", "%H:%M").time()
        b = datetime.strptime(q.get("to") or "07:00", "%H:%M").time()
    except ValueError:
        return False
    n = datetime.now().time()
    return (a <= n < b) if a <= b else (n >= a or n < b)


# ---------------------------------------------------------------- صدا (پخش در خود برنامه، وقتی پنجره‌ای باز نیست)
def play_sound(data, ext, times=1):
    """ویندوز: WAV از حافظه (winsound)، MP3 با MCI از فایل موقت. جای دیگر: کاری نمی‌کند."""
    if os.name != "nt" or not data:
        return
    try:
        if ext == "wav":
            import winsound
            for _ in range(max(1, times)):
                winsound.PlaySound(data, winsound.SND_MEMORY)
            return
        if ext == "mp3":
            import ctypes
            tmp = paths.data_dir() / "monitor" / ".play.mp3"
            Path(tmp).write_bytes(data)
            mci = ctypes.windll.winmm.mciSendStringW
            try:
                for _ in range(max(1, times)):
                    mci(f'open "{tmp}" type mpegvideo alias akrp_snd', None, 0, None)
                    mci("play akrp_snd wait", None, 0, None)
                    mci("close akrp_snd", None, 0, None)
            finally:
                try:
                    os.remove(tmp)
                except OSError:
                    pass
    except Exception:
        log.exception("play sound")
