"""
ترمینال SSH زنده (مثل PuTTY): نشست تعاملی با PTY (xterm-256color) روی دستگاه ذخیره‌شده یا اتصال موقت.

- رابط با long-poll کار می‌کند (term_read تا ۱ ثانیه برای داده‌ی تازه صبر می‌کند)؛ هم در پنجره‌ی دسکتاپ و هم در وب.
- رمزها هرگز به مرورگر نمی‌روند؛ اتصال از خود برنامه برقرار می‌شود.
- کلید میزبان: دستگاه ذخیره‌شده TOFU مثل بقیه‌ی SSH؛ اتصال موقت: کلید تازه فقط با تأیید اثر انگشت توسط کاربر.
- هر نشست فقط برای کاربری که بازش کرده قابل استفاده است. بی‌کاری طولانی یا رها شدن (بدون poll) آن را می‌بندد.
- ضبط اختیاری: فقط خروجی (شامل echo دستورها؛ رمزهایی که دستگاه echo نمی‌کند ضبط نمی‌شوند)، رمزشده در term_logs.
"""
import base64
import logging
import shlex
import threading
import time
import uuid

import paramiko

from . import atrest, paths
from .abort import CANCEL_MSG
from .ssh import HostKeys, SshError, algorithms, fingerprint, friendly

log = logging.getLogger(__name__)
BUF_MAX = 2 * 1024 * 1024          # خروجی نگه‌داشته‌شده برای هر نشست (برای وصل شدن دوباره‌ی تب)
MAX_PER_USER = 8
MAX_TOTAL = 64
ABANDON_SECS = 120                  # بدون poll (پنجره بسته شد) ← بسته می‌شود


class TermError(Exception):
    pass


class Session:
    def __init__(self, owner, title, host, port, kind):
        self.id = uuid.uuid4().hex
        self.owner, self.title, self.host, self.port, self.kind = owner, title, host, int(port), kind
        self.client = None
        self.chan = None
        self.buf = bytearray()
        self.base = 0                  # آفست بایت اول buf در کل خروجی
        self.cond = threading.Condition()
        self.closed = False
        self.reason = ""
        self.created = self.last_input = self.last_poll = time.time()
        self.rec_path = None
        self.bytes_out = 0
        self.device_type = ""
        self.stats = None              # وضعیت نوار منابع (فقط لینوکس)

    @property
    def end(self):
        return self.base + len(self.buf)

    def public(self):
        return {"id": self.id, "title": self.title, "host": self.host, "port": self.port, "kind": self.kind,
                "created": self.created, "closed": self.closed, "reason": self.reason, "recording": bool(self.rec_path)}


def check_hostkey(hostkeys, host, port, legacy, adhoc, accept_fp, emit, attempt=None):
    """کلید میزبان پیش از اتصال تعاملی: ناهمخوان ← خطا؛ ناشناخته در اتصال موقت ← {"confirm": ...} تا کاربر تأیید کند؛
    ناشناخته برای دستگاه ذخیره‌شده ← TOFU و ثبت."""
    try:
        key = HostKeys.fetch(host, port, 10, legacy, attempt)
    except Exception as e:
        raise TermError(CANCEL_MSG if attempt and attempt.cancelled else friendly(e))
    fp = fingerprint(key)
    entry = HostKeys.entry(host, port)
    with hostkeys._lock:
        known = hostkeys._load().lookup(entry)
    if known:
        old = known.get(key.get_name())
        if old is None or old.asbytes() != key.asbytes():
            other = old or next(iter(known.values()))
            raise TermError(f"کلید میزبان عوض شده است! ثبت‌شده: {fingerprint(other)} — فعلی: {fp}. "
                            "اگر تغییر عمدی است، کلید قبلی را از «کلیدهای میزبان» حذف کنید.")
        return None
    if adhoc and accept_fp != fp:
        return {"confirm": {"fingerprint": fp, "type": key.get_name(), "host": entry}}
    with hostkeys._lock:
        hk = hostkeys._load()
        hk.add(entry, key.get_name(), key)
        hostkeys._save(hk)
    emit("info", f"SSH: کلید میزبان {host} برای اولین بار ثبت شد ({fp})", "ssh")
    return None


def ssh_connect(hostkeys, dev, creds, attempt=None):
    """SSHClient وصل‌شده با کلید میزبان ثبت‌شده (RejectPolicy). attempt: لغو فوری از رابط."""
    host, port = dev["host"], int(dev.get("port") or 22)
    cli = paramiko.SSHClient()
    hostkeys.load_into(cli, host, port)
    cli.set_missing_host_key_policy(paramiko.RejectPolicy())
    try:
        sock = attempt.connect(host, port, 15) if attempt else None
        cli.connect(host, port=port, username=creds["username"], password=creds.get("password") or "",
                    timeout=15, banner_timeout=15, auth_timeout=20, look_for_keys=False, allow_agent=False,
                    disabled_algorithms=algorithms(dev), sock=sock)
        if attempt:
            attempt.check()
    except Exception as e:
        cli.close()
        raise TermError(CANCEL_MSG if attempt and attempt.cancelled else friendly(e))
    return cli


class TermManager:
    def __init__(self, store, vault, settings, emit=None, hostkeys=None):
        self.store, self.vault, self.settings = store, vault, settings
        self.emit = emit or (lambda *a, **k: None)
        self.hostkeys = hostkeys or HostKeys()
        self.sessions = {}
        self._lock = threading.Lock()
        threading.Thread(target=self._watchdog, name="term-watchdog", daemon=True).start()

    # ------------------------------------------------------------------ تنظیمات
    def cfg(self):
        c = self.settings.get("terminal") or {}
        return {"idle_minutes": int(c.get("idle_minutes", 30) or 0), "record": bool(c.get("record", False))}

    # ------------------------------------------------------------------ باز کردن
    def open(self, owner, dev, creds, cols=120, rows=32, accept_fp=None, adhoc=False, add_history=None, attempt=None):
        """dev: {host, port, device_type, name, legacy, use_enable}؛ creds: {username, password, secret}"""
        with self._lock:
            mine = [s for s in self.sessions.values() if s.owner == owner and not s.closed]
            if len(mine) >= MAX_PER_USER:
                raise TermError(f"حداکثر {MAX_PER_USER} ترمینال باز برای هر کاربر.")
            if len([s for s in self.sessions.values() if not s.closed]) >= MAX_TOTAL:
                raise TermError("تعداد ترمینال‌های باز برنامه به سقف رسیده است.")
        host, port = dev["host"], int(dev.get("port") or 22)
        legacy = bool(dev.get("legacy"))
        if not creds.get("username"):
            raise TermError("یوزر وارد نشده است.")
        confirm = check_hostkey(self.hostkeys, host, port, legacy, adhoc, accept_fp, self.emit, attempt)
        if confirm:
            return confirm
        cli = ssh_connect(self.hostkeys, dev, creds, attempt)
        try:
            chan = cli.invoke_shell(term="xterm-256color", width=max(20, min(int(cols), 500)), height=max(5, min(int(rows), 200)))
            chan.settimeout(0.5)
            if attempt:
                attempt.check()     # لغو درست هم‌زمان با برقراری اتصال: نشست ساخته نمی‌شود
        except Exception as e:
            cli.close()
            raise TermError(CANCEL_MSG if attempt and attempt.cancelled else friendly(e))
        title = dev.get("name") or host
        s = Session(owner, title, host, port, "adhoc" if adhoc else "device")
        s.client, s.chan = cli, chan
        s.device_type = dev.get("device_type") or ""
        if self.cfg()["record"]:
            d = paths.data_dir() / "term_logs"
            d.mkdir(exist_ok=True)
            s.rec_path = d / f"{time.strftime('%Y%m%d_%H%M%S')}_{s.id[:8]}.log"
            self._rec(s, f"# {title} ({host}:{port}) — user {creds['username']} — {owner or '-'} — {time.strftime('%Y-%m-%d %H:%M:%S')}\r\n")
        with self._lock:
            self.sessions[s.id] = s
        threading.Thread(target=self._reader, args=(s,), name=f"term-{s.id[:6]}", daemon=True).start()
        if dev.get("use_enable") and dev.get("device_type") not in ("linux", None) and creds.get("secret"):
            threading.Thread(target=self._auto_enable, args=(s, creds["secret"]), daemon=True).start()
        if add_history:
            add_history(s, "open")
        return {"session": s.public()}

    def _auto_enable(self, s, secret):
        """دستگاه ذخیره‌شده با «ورود به حالت enable»: enable و رمزش از خود برنامه (رمز به مرورگر نمی‌رود)."""
        def wait_for(pred, secs):
            t = time.time() + secs
            with s.cond:
                while not s.closed and time.time() < t:
                    tail = bytes(s.buf[-200:]).decode("utf-8", "replace")
                    if pred(tail):
                        return tail
                    s.cond.wait(0.3)
            return None
        tail = wait_for(lambda x: x.rstrip().endswith((">", "#")), 8)
        if not tail or tail.rstrip().endswith("#"):
            return
        try:
            s.chan.send(b"enable\n")
            if wait_for(lambda x: "assword" in x[-40:], 6):
                s.chan.send(secret.encode("utf-8") + b"\n")
        except OSError:
            pass

    # ------------------------------------------------------------------ خواندن از دستگاه
    def _reader(self, s):
        try:
            while not s.closed:
                try:
                    data = s.chan.recv(65536)
                except (TimeoutError, OSError) as e:
                    if isinstance(e, TimeoutError) or "timed out" in str(e):
                        if s.chan.closed or s.chan.exit_status_ready():
                            break
                        continue
                    raise
                if not data:
                    break
                with s.cond:
                    s.buf += data
                    s.bytes_out += len(data)
                    if len(s.buf) > BUF_MAX:
                        cut = len(s.buf) - BUF_MAX
                        del s.buf[:cut]
                        s.base += cut
                    s.cond.notify_all()
                if s.rec_path:
                    self._rec(s, data.decode("utf-8", "replace"))
        except Exception as e:
            s.reason = friendly(e)
        finally:
            self._finish(s, s.reason or "اتصال از طرف دستگاه بسته شد")

    def _rec(self, s, text):
        try:
            with open(s.rec_path, "a", encoding="utf-8") as f:
                f.write(atrest._enc_line(text) + "\n")
        except Exception:
            log.exception("ضبط ترمینال")

    def _finish(self, s, reason):
        with s.cond:
            if s.closed:
                return
            s.closed = True
            s.reason = s.reason or reason
            s.cond.notify_all()
        try:
            s.client.close()
        except Exception:
            pass
        if self._on_close:
            try:
                self._on_close(s)
            except Exception:
                log.exception("term close hook")

    _on_close = None

    # ------------------------------------------------------------------ API
    def _get(self, sid, owner):
        s = self.sessions.get(str(sid))
        if not s or s.owner != owner:
            raise TermError("نشست ترمینال پیدا نشد.")
        return s

    def read(self, sid, owner, since=0, wait=1.0):
        s = self._get(sid, owner)
        s.last_poll = time.time()
        since = int(since or 0)
        with s.cond:
            if since >= s.end and not s.closed:
                s.cond.wait(max(0.0, min(float(wait), 2.0)))
            start = max(since, s.base)
            data = bytes(s.buf[start - s.base:])
            end = s.end
        return {"data": base64.b64encode(data).decode("ascii"), "next": end, "closed": s.closed, "reason": s.reason,
                "lost": since < s.base and since > 0}

    def write(self, sid, owner, data):
        s = self._get(sid, owner)
        if s.closed:
            raise TermError("نشست بسته شده است.")
        s.last_input = time.time()
        raw = str(data or "").encode("utf-8")
        if len(raw) > 256 * 1024:
            raise TermError("متن ارسالی بیش از حد بزرگ است.")
        try:
            s.chan.sendall(raw)
        except OSError as e:
            self._finish(s, friendly(e))
            raise TermError("ارسال به دستگاه ناموفق بود؛ اتصال بسته شد.")
        return {}

    def resize(self, sid, owner, cols, rows):
        s = self._get(sid, owner)
        if not s.closed:
            try:
                s.chan.resize_pty(width=max(20, min(int(cols), 500)), height=max(5, min(int(rows), 200)))
            except Exception:
                pass
        return {}

    def stats(self, sid, owner):
        """نوار منابع لینوکس (CPU، RAM، دیسک، شبکه) از یک کانال exec جدا روی همان اتصال SSH؛ ترمینال و ضبط دست نمی‌خورند."""
        s = self._get(sid, owner)
        if s.closed:
            raise TermError("نشست بسته شده است.")
        if s.device_type and s.device_type != "linux":
            return {"supported": False}
        if s.stats is None:
            s.stats = HostStats()
        return s.stats.poll(s.client)

    def close(self, sid, owner, reason="بسته شد توسط کاربر"):
        s = self._get(sid, owner)
        self._finish(s, reason)
        with self._lock:
            self.sessions.pop(s.id, None)
        return {}

    def list(self, owner):
        with self._lock:
            return [s.public() for s in self.sessions.values() if s.owner == owner]

    def close_all(self, owner=None):
        for s in list(self.sessions.values()):
            if owner is None or s.owner == owner:
                self._finish(s, "برنامه قفل یا بسته شد")
        with self._lock:
            for k in [k for k, s in self.sessions.items() if s.closed and (owner is None or s.owner == owner)]:
                self.sessions.pop(k, None)

    def _watchdog(self):
        while True:
            time.sleep(15)
            try:
                idle = self.cfg()["idle_minutes"] * 60
                now = time.time()
                for s in list(self.sessions.values()):
                    if s.closed:
                        if now - s.last_poll > ABANDON_SECS:
                            with self._lock:
                                self.sessions.pop(s.id, None)
                        continue
                    if idle and now - s.last_input > idle:
                        self._finish(s, f"بعد از {idle // 60} دقیقه بی‌کاری بسته شد")
                    elif now - s.last_poll > ABANDON_SECS:
                        self._finish(s, "پنجره‌ی ترمینال بسته شد")
            except Exception:
                log.exception("term watchdog")


def read_recording(path):
    """متن ضبط‌شده‌ی یک نشست (رمزگشایی‌شده)."""
    return "".join(atrest.read_log_lines(path))


__all__ = ["TermManager", "TermError", "SshError", "read_recording"]


# ---------------------------------------------------------------------- نوار منابع (مثل MobaXterm)
# فقط خواندن فایل‌های /proc و df؛ هیچ چیزی روی سرور نوشته یا نصب نمی‌شود. خروجی بخش‌ها با «@@» جدا می‌شود.
STATS_CMD = ("LC_ALL=C; export LC_ALL; head -n1 /proc/stat; echo @@; cat /proc/meminfo; echo @@; cat /proc/net/dev; echo @@; "
             "cat /proc/loadavg; echo @@; cat /proc/uptime; echo @@; "
             "(df -P -k -x tmpfs -x devtmpfs -x squashfs -x overlay 2>/dev/null || df -P -k 2>/dev/null); echo @@; "
             "(who 2>/dev/null | wc -l); echo @@; (nproc 2>/dev/null || grep -c ^processor /proc/cpuinfo)")
STATS_CMD = "sh -c " + shlex.quote(STATS_CMD)    # پوسته‌ی ورود کاربر ممکن است csh/fish باشد
STATS_MIN_GAP = 1.5          # درخواست‌های پشت‌سرهم (چند پنجره) سرور را شلوغ نکنند
STATS_TIMEOUT = 8


def _run_exec(client, cmd, timeout=STATS_TIMEOUT):
    tr = client.get_transport()
    if tr is None or not tr.is_active():
        raise TermError("اتصال SSH فعال نیست.")
    ch = tr.open_session(timeout=timeout)
    try:
        ch.settimeout(timeout)
        ch.exec_command(cmd)  # nosec B601 — فقط STATS_CMD ثابت؛ هیچ ورودی کاربر
        out = bytearray()
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                d = ch.recv(65536)
            except Exception:
                break
            if not d:
                break
            out += d
            if len(out) > 512 * 1024:
                break
        return out.decode("utf-8", "replace")
    finally:
        try:
            ch.close()
        except Exception:
            pass


def parse_stats(text):
    """خروجی STATS_CMD ← داده‌ی خام (بدون محاسبه‌ی نرخ)."""
    parts = text.split("@@")
    if len(parts) < 8 or not parts[0].strip().startswith("cpu"):
        return None
    cpu = [int(x) for x in parts[0].split()[1:] if x.isdigit()]
    mem = {}
    for line in parts[1].splitlines():
        k, _, v = line.partition(":")
        if v.strip():
            try:
                mem[k.strip()] = int(v.split()[0]) * 1024
            except ValueError:
                pass
    nets = {}
    for line in parts[2].splitlines():
        if ":" not in line:
            continue
        name, _, rest = line.partition(":")
        f = rest.split()
        name = name.strip()
        if len(f) >= 9 and name != "lo":
            nets[name] = (int(f[0]), int(f[8]))
    load = parts[3].split()[:3]
    up = parts[4].split()
    disks = []
    for line in parts[5].splitlines()[1:]:
        f = line.split()
        if len(f) >= 6 and f[1].isdigit() and int(f[1]) > 0:
            disks.append({"fs": f[0], "mount": " ".join(f[5:]), "size": int(f[1]) * 1024, "used": int(f[2]) * 1024,
                          "pct": round(int(f[2]) * 100 / max(1, int(f[2]) + int(f[3])), 1)})
    try:
        users = int(parts[6].strip() or 0)
    except ValueError:
        users = None
    try:
        ncpu = int(parts[7].strip().splitlines()[0])
    except (ValueError, IndexError):
        ncpu = None
    return {"cpu": cpu, "mem": mem, "net": nets, "load": [float(x) for x in load if x.replace(".", "", 1).isdigit()],
            "uptime": float(up[0]) if up else None, "disks": disks, "users": users, "ncpu": ncpu}


class HostStats:
    """نرخ CPU و شبکه از اختلاف دو نمونه. اولین بار دو نمونه با فاصله‌ی کوتاه گرفته می‌شود تا عدد فوراً آماده باشد."""

    def __init__(self):
        self.prev = None
        self.prev_t = 0.0
        self.last = None
        self.last_t = 0.0
        self.supported = None
        self.lock = threading.Lock()
        self.fails = 0

    def poll(self, client):
        with self.lock:
            now = time.time()
            if self.supported is False:
                return {"supported": False}
            if self.last and now - self.last_t < STATS_MIN_GAP:
                return self.last
            try:
                raw = parse_stats(_run_exec(client, STATS_CMD))
                if raw and self.prev is None:          # نمونه‌ی دوم برای نرخ لحظه‌ای
                    self.prev, self.prev_t = raw, time.time()
                    time.sleep(0.6)
                    raw = parse_stats(_run_exec(client, STATS_CMD))
            except TermError:
                raise
            except Exception as e:  # noqa — exec ممنوع، کانال بسته، ...
                self.fails += 1
                if self.fails >= 3:
                    self.supported = False
                return {"supported": self.supported is not False, "error": friendly(e)}
            if raw is None:
                self.supported = False        # /proc ندارد (لینوکس نیست)
                return {"supported": False}
            self.supported, self.fails = True, 0
            t = time.time()
            out = self._compute(raw, t)
            self.prev, self.prev_t = raw, t
            self.last, self.last_t = out, t
            return out

    def _compute(self, raw, t):
        p, dt = self.prev, max(0.001, t - self.prev_t)
        cpu = None
        if p and len(p["cpu"]) >= 4 and len(raw["cpu"]) >= 4:
            tot = sum(raw["cpu"][:8]) - sum(p["cpu"][:8])
            idle = (raw["cpu"][3] + (raw["cpu"][4] if len(raw["cpu"]) > 4 else 0)) - (p["cpu"][3] + (p["cpu"][4] if len(p["cpu"]) > 4 else 0))
            cpu = round(max(0.0, min(100.0, 100.0 * (tot - idle) / tot)), 1) if tot > 0 else 0.0
        m = raw["mem"]
        total = m.get("MemTotal", 0)
        avail = m.get("MemAvailable", m.get("MemFree", 0) + m.get("Buffers", 0) + m.get("Cached", 0))
        used = max(0, total - avail)
        swap_t, swap_f = m.get("SwapTotal", 0), m.get("SwapFree", 0)
        rx = tx = 0.0
        ifs = []
        if p:
            for name, (r, x) in raw["net"].items():
                if name in p["net"]:
                    dr = max(0, r - p["net"][name][0]) / dt
                    dx = max(0, x - p["net"][name][1]) / dt
                    rx += dr
                    tx += dx
                    ifs.append({"name": name, "rx": round(dr), "tx": round(dx)})
        disks = sorted(raw["disks"], key=lambda d: (d["mount"] != "/", d["mount"]))[:20]
        root = next((d for d in disks if d["mount"] == "/"), disks[0] if disks else None)
        return {"supported": True, "ts": t, "cpu": cpu, "ncpu": raw["ncpu"], "load": raw["load"],
                "mem": {"total": total, "used": used, "pct": round(used * 100 / total, 1) if total else None},
                "swap": {"total": swap_t, "used": max(0, swap_t - swap_f), "pct": round((swap_t - swap_f) * 100 / swap_t, 1) if swap_t else 0},
                "disk": root, "disks": disks, "net": {"rx": round(rx), "tx": round(tx), "ifs": sorted(ifs, key=lambda i: -(i["rx"] + i["tx"]))[:8]},
                "uptime": raw["uptime"], "users": raw["users"]}
