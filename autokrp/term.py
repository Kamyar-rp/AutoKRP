"""
ترمینال زنده (مثل PuTTY): نشست تعاملی SSH (PTY xterm-256color)، Telnet، یا پورت سریال (کابل کنسول؛ فقط حالت کلاینت)
روی دستگاه ذخیره‌شده یا اتصال موقت.

- رابط با long-poll کار می‌کند (term_read تا ۱ ثانیه برای داده‌ی تازه صبر می‌کند)؛ هم در پنجره‌ی دسکتاپ و هم در وب.
- رمزها هرگز به مرورگر نمی‌روند؛ اتصال از خود برنامه برقرار می‌شود.
- کلید میزبان: دستگاه ذخیره‌شده TOFU مثل بقیه‌ی SSH؛ اتصال موقت: کلید تازه فقط با تأیید اثر انگشت توسط کاربر.
- هر نشست فقط برای کاربری که بازش کرده قابل استفاده است. بی‌کاری طولانی یا رها شدن (بدون poll) آن را می‌بندد.
- ضبط اختیاری: فقط خروجی (شامل echo دستورها؛ رمزهایی که دستگاه echo نمی‌کند ضبط نمی‌شوند)، رمزشده در term_logs.
"""
import base64
import logging
import re
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


# ---------------------------------------------------------------------- لایه‌ی انتقال (SSH / Telnet / Serial)
class SshT:
    proto = "ssh"

    def __init__(self, client, chan):
        self.client, self.chan = client, chan

    def recv(self, n):
        try:
            return self.chan.recv(n)
        except (TimeoutError, OSError) as e:
            if isinstance(e, TimeoutError) or "timed out" in str(e):
                if self.chan.closed or self.chan.exit_status_ready():
                    return b""
                raise TimeoutError("timed out")
            raise

    def send(self, data):
        self.chan.sendall(data)

    def resize(self, cols, rows):
        self.chan.resize_pty(width=cols, height=rows)

    def brk(self):
        raise TermError("ارسال Break فقط برای پورت سریال است.")

    def close(self):
        self.client.close()


class TelnetT:
    proto = "telnet"

    def __init__(self, conn):
        self.conn = conn

    def recv(self, n):
        return self.conn.recv(n)

    def send(self, data):
        self.conn.send(data)

    def resize(self, cols, rows):
        self.conn.resize(cols, rows)

    def brk(self):
        raise TermError("ارسال Break فقط برای پورت سریال است.")

    def close(self):
        self.conn.close()


class SerialT:
    proto = "serial"

    def __init__(self, ser):
        self.ser = ser

    def recv(self, n):
        d = self.ser.read(1)          # تا timeout پورت (۰٫۵ ثانیه) صبر می‌کند
        if not d:
            raise TimeoutError("timed out")
        w = self.ser.in_waiting
        if w:
            d += self.ser.read(min(w, n))
        return d

    def send(self, data):
        self.ser.write(data)

    def resize(self, cols, rows):
        pass                           # کنسول سریال اندازه‌ی پنجره ندارد

    def brk(self):
        self.ser.send_break(duration=0.5)

    def close(self):
        try:
            self.ser.close()
        except Exception:
            pass


# ---------------------------------------------------------------------- پورت سریال
BAUDS = (300, 1200, 2400, 4800, 9600, 14400, 19200, 38400, 57600, 115200, 230400, 460800, 921600)
PARITY = {"N": "N", "E": "E", "O": "O", "M": "M", "S": "S"}
STOPS = {"1": 1, "1.5": 1.5, "2": 2}
FLOWS = ("none", "xonxoff", "rtscts", "dsrdtr")


def list_serial():
    """پورت‌های سریال این کامپیوتر (کابل کنسول USB بعد از نصب درایور در «Ports (COM & LPT)» ویندوز)."""
    try:
        from serial.tools import list_ports
    except ImportError:
        return []
    out = []
    for p in list_ports.comports():
        out.append({"port": p.device, "desc": p.description if p.description and p.description != "n/a" else "",
                    "hwid": p.hwid if p.hwid and p.hwid != "n/a" else "",
                    "vid": f"{p.vid:04X}" if p.vid is not None else "", "pid": f"{p.pid:04X}" if p.pid is not None else ""})
    def key(x):
        m = re.search(r"(\d+)$", x["port"])
        return (re.sub(r"\d+$", "", x["port"]), int(m.group(1)) if m else 0)
    return sorted(out, key=key)


def clean_serial(o):
    """تنظیمات اتصال سریال از رابط؛ پورت باید در فهرست پورت‌های واقعی همین کامپیوتر باشد (نه مسیر دلخواه دستگاه)."""
    o = o if isinstance(o, dict) else {}
    port = str(o.get("port") or "").strip()
    if not port or port not in {p["port"] for p in list_serial()}:
        raise TermError(f"پورت سریال «{port or '-'}» پیدا نشد؛ کابل را وصل کنید و فهرست را تازه کنید.")
    try:
        baud = int(o.get("baud") or 9600)
    except (TypeError, ValueError):
        baud = 0
    if baud not in BAUDS:
        raise TermError(f"سرعت {o.get('baud')} معتبر نیست.")
    bits = int(o.get("bits") or 8) if str(o.get("bits") or 8) in ("5", "6", "7", "8") else 0
    if not bits:
        raise TermError("تعداد بیت داده معتبر نیست.")
    parity = PARITY.get(str(o.get("parity") or "N").upper()[:1])
    stop = STOPS.get(str(o.get("stop") or "1"))
    flow = str(o.get("flow") or "none")
    if parity is None or stop is None or flow not in FLOWS:
        raise TermError("تنظیمات پورت سریال معتبر نیست.")
    return {"port": port, "baud": baud, "bits": bits, "parity": parity, "stop": stop, "flow": flow}


def serial_label(c):
    st = {1: "1", 1.5: "1.5", 2: "2"}[c["stop"]]
    return f"{c['baud']} {c['bits']}{c['parity']}{st}" + ("" if c["flow"] == "none" else f" {c['flow']}")


def serial_open(c):
    try:
        import serial
    except ImportError:
        raise TermError("کتابخانه‌ی pyserial نصب نیست (pip install pyserial).")
    kw = dict(port=c["port"], baudrate=c["baud"], bytesize=c["bits"], parity=c["parity"], stopbits=c["stop"],
              timeout=0.5, write_timeout=5, xonxoff=c["flow"] == "xonxoff", rtscts=c["flow"] == "rtscts",
              dsrdtr=c["flow"] == "dsrdtr")
    try:
        try:
            return serial.Serial(exclusive=True, **kw)
        except (TypeError, ValueError):          # exclusive روی ویندوز پیش‌فرض و در بعضی نسخه‌ها پارامتر ندارد
            return serial.Serial(**kw)
    except serial.SerialException as e:
        m = str(e)
        if "ermission" in m or "Access is denied" in m or "PermissionError" in m or "busy" in m.lower():
            raise TermError(f"پورت {c['port']} در دسترس نیست؛ احتمالاً برنامه‌ی دیگری (مثل PuTTY) آن را باز کرده است.")
        raise TermError(f"باز کردن پورت {c['port']} ناموفق بود: {m[:200]}")


class Session:
    def __init__(self, owner, title, host, port, kind, proto="ssh", info=""):
        self.id = uuid.uuid4().hex
        self.owner, self.title, self.host, self.port, self.kind = owner, title, host, int(port), kind
        self.proto, self.info = proto, info
        self.t = None                  # SshT / TelnetT / SerialT
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
                "proto": self.proto, "info": self.info, "created": self.created, "closed": self.closed, "reason": self.reason, "recording": bool(self.rec_path)}


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
    def _limits(self, owner):
        with self._lock:
            mine = [s for s in self.sessions.values() if s.owner == owner and not s.closed]
            if len(mine) >= MAX_PER_USER:
                raise TermError(f"حداکثر {MAX_PER_USER} ترمینال باز برای هر کاربر.")
            if len([s for s in self.sessions.values() if not s.closed]) >= MAX_TOTAL:
                raise TermError("تعداد ترمینال‌های باز برنامه به سقف رسیده است.")

    def open(self, owner, dev, creds, cols=120, rows=32, accept_fp=None, adhoc=False, add_history=None, attempt=None):
        """dev: {host, port, device_type, name, legacy, use_enable, protocol (ssh|telnet)}؛ creds: {username, password, secret}"""
        self._limits(owner)
        cols, rows = max(20, min(int(cols), 500)), max(5, min(int(rows), 200))
        proto = dev.get("protocol") or "ssh"
        host = dev["host"]
        port = int(dev.get("port") or (23 if proto == "telnet" else 22))
        if proto == "telnet":
            from .telnet import TelnetConn
            try:
                conn = TelnetConn.connect(host, port, 15, attempt, cols, rows)
                if attempt:
                    attempt.check()
            except Exception as e:
                raise TermError(CANCEL_MSG if attempt and attempt.cancelled else friendly(e))
            tr = TelnetT(conn)
        else:
            legacy = bool(dev.get("legacy"))
            if not creds.get("username"):
                raise TermError("یوزر وارد نشده است.")
            confirm = check_hostkey(self.hostkeys, host, port, legacy, adhoc, accept_fp, self.emit, attempt)
            if confirm:
                return confirm
            cli = ssh_connect(self.hostkeys, dev, creds, attempt)
            try:
                chan = cli.invoke_shell(term="xterm-256color", width=cols, height=rows)
                chan.settimeout(0.5)
                if attempt:
                    attempt.check()     # لغو درست هم‌زمان با برقراری اتصال: نشست ساخته نمی‌شود
            except Exception as e:
                cli.close()
                raise TermError(CANCEL_MSG if attempt and attempt.cancelled else friendly(e))
            tr = SshT(cli, chan)
        title = dev.get("name") or host
        s = Session(owner, title, host, port, "adhoc" if adhoc else "device", proto)
        s.t = tr
        s.device_type = dev.get("device_type") or ""
        self._start(s, f"{title} ({proto} {host}:{port}) — user {creds.get('username') or '-'}")
        if proto == "telnet" and (creds.get("username") or creds.get("password")):
            threading.Thread(target=self._auto_login, args=(s, creds, bool(dev.get("use_enable"))), daemon=True).start()
        elif dev.get("use_enable") and dev.get("device_type") not in ("linux", None) and creds.get("secret"):
            threading.Thread(target=self._auto_enable, args=(s, creds["secret"]), daemon=True).start()
        if add_history:
            add_history(s, "open")
        return {"session": s.public()}

    def open_serial(self, owner, cfg):
        """کابل کنسول: cfg از clean_serial. پورت انحصاری باز می‌شود (برنامه‌ی دیگری هم‌زمان نمی‌تواند)."""
        self._limits(owner)
        with self._lock:
            if any(not x.closed and x.proto == "serial" and x.host == cfg["port"] for x in self.sessions.values()):
                raise TermError(f"پورت {cfg['port']} همین حالا در یک ترمینال دیگر باز است.")
        ser = serial_open(cfg)
        info = serial_label(cfg)
        s = Session(owner, cfg["port"], cfg["port"], cfg["baud"], "serial", "serial", info)
        s.t = SerialT(ser)
        self._start(s, f"{cfg['port']} ({info})")
        try:
            s.t.send(b"\r")             # بیدار کردن کنسول تا prompt دیده شود
        except Exception:
            pass
        return {"session": s.public()}

    def _start(self, s, head):
        if self.cfg()["record"]:
            d = paths.data_dir() / "term_logs"
            d.mkdir(exist_ok=True)
            s.rec_path = d / f"{time.strftime('%Y%m%d_%H%M%S')}_{s.id[:8]}.log"
            self._rec(s, f"# {head} — {s.owner or '-'} — {time.strftime('%Y-%m-%d %H:%M:%S')}\r\n")
        with self._lock:
            self.sessions[s.id] = s
        threading.Thread(target=self._reader, args=(s,), name=f"term-{s.id[:6]}", daemon=True).start()

    def _wait_for(self, s, pred, secs, since=None):
        """متن خروجی از آفست since (یا ۲۰۰ بایت آخر) تا pred درست شود؛ None = نشد."""
        t = time.time() + secs
        with s.cond:
            while not s.closed and time.time() < t:
                if since is None:
                    tail = bytes(s.buf[-200:]).decode("utf-8", "replace")
                else:
                    tail = bytes(s.buf[max(0, since - s.base):][-400:]).decode("utf-8", "replace")
                if pred(tail):
                    return tail
                s.cond.wait(0.3)
        return None

    _USER_RE = re.compile(r"(user\s*name|username|login)\s*:\s*$", re.I)
    _PASS_RE = re.compile(r"pass(word|code)?\s*:\s*$", re.I)

    def _auto_login(self, s, creds, use_enable):
        """Telnet: یوزر و رمز ذخیره‌شده از خود برنامه (به مرورگر نمی‌رود). prompt ناشناخته = کاربر خودش وارد می‌کند."""
        user, pw = creds.get("username") or "", creds.get("password") or ""
        try:
            tail = self._wait_for(s, lambda x: bool(self._USER_RE.search(x.rstrip(" ")) or self._PASS_RE.search(x.rstrip(" "))), 15)
            if not tail:
                return
            if self._USER_RE.search(tail.rstrip(" ")):
                if not user:
                    return
                mark = s.end
                s.t.send(user.encode("utf-8") + b"\r")
                tail = self._wait_for(s, lambda x: bool(self._PASS_RE.search(x.rstrip(" "))), 10, mark)
                if not tail:
                    return
            if not pw:
                return
            mark = s.end
            s.t.send(pw.encode("utf-8") + b"\r")
            if use_enable and creds.get("secret") and s.device_type not in ("linux", ""):
                tail = self._wait_for(s, lambda x: x.rstrip().endswith((">", "#")) or bool(self._USER_RE.search(x.rstrip(" "))), 10, mark)
                if tail and tail.rstrip().endswith(">"):
                    s.t.send(b"enable\r")
                    if self._wait_for(s, lambda x: "assword" in x[-40:], 6):
                        s.t.send(creds["secret"].encode("utf-8") + b"\r")
        except Exception:
            log.debug("telnet auto-login", exc_info=True)

    def _auto_enable(self, s, secret):
        """دستگاه ذخیره‌شده با «ورود به حالت enable»: enable و رمزش از خود برنامه (رمز به مرورگر نمی‌رود)."""
        tail = self._wait_for(s, lambda x: x.rstrip().endswith((">", "#")), 8)
        if not tail or tail.rstrip().endswith("#"):
            return
        try:
            s.t.send(b"enable\n")
            if self._wait_for(s, lambda x: "assword" in x[-40:], 6):
                s.t.send(secret.encode("utf-8") + b"\n")
        except OSError:
            pass

    # ------------------------------------------------------------------ خواندن از دستگاه
    def _reader(self, s):
        try:
            while not s.closed:
                try:
                    data = s.t.recv(65536)
                except TimeoutError:
                    continue
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
            if s.closed:
                pass
            elif s.proto == "serial":
                s.reason = f"پورت سریال قطع شد (کابل جدا شد؟): {str(e)[:150]}"
            else:
                s.reason = friendly(e)
        finally:
            self._finish(s, s.reason or ("پورت سریال بسته شد" if s.proto == "serial" else "اتصال از طرف دستگاه بسته شد"))

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
            if s.t:
                s.t.close()
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
            s.t.send(raw)
        except Exception as e:
            self._finish(s, friendly(e))
            raise TermError("ارسال به دستگاه ناموفق بود؛ اتصال بسته شد.")
        return {}

    def resize(self, sid, owner, cols, rows):
        s = self._get(sid, owner)
        if not s.closed:
            try:
                s.t.resize(max(20, min(int(cols), 500)), max(5, min(int(rows), 200)))
            except Exception:
                pass
        return {}

    def send_break(self, sid, owner):
        s = self._get(sid, owner)
        if s.closed:
            raise TermError("نشست بسته شده است.")
        s.last_input = time.time()
        try:
            s.t.brk()
        except TermError:
            raise
        except Exception as e:
            raise TermError(f"ارسال Break ناموفق بود: {str(e)[:150]}")
        if s.rec_path:
            self._rec(s, "\r\n[BREAK]\r\n")
        return {}

    def stats(self, sid, owner):
        """نوار منابع لینوکس (CPU، RAM، دیسک، شبکه) از یک کانال exec جدا روی همان اتصال SSH؛ ترمینال و ضبط دست نمی‌خورند."""
        s = self._get(sid, owner)
        if s.closed:
            raise TermError("نشست بسته شده است.")
        if s.proto != "ssh" or (s.device_type and s.device_type != "linux"):
            return {"supported": False}
        if s.stats is None:
            s.stats = HostStats()
        return s.stats.poll(s.t.client)

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


__all__ = ["TermManager", "TermError", "SshError", "read_recording", "list_serial", "clean_serial"]


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
