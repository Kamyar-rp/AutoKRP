"""
انتقال فایل (مثل WinSCP): SFTP، SCP، FTP/FTPS و سرور TFTP موقت.

- اتصال‌ها مثل ترمینال مال همان کاربرند و با بی‌کاری بسته می‌شوند؛ رمزها به مرورگر نمی‌روند.
- آپلود از مرورگر تکه‌تکه (حداکثر ۴ مگابایت در هر درخواست) مستقیم روی دستگاه نوشته می‌شود؛ روی دیسک این سیستم چیزی نمی‌ماند.
- دانلود در حالت وب مستقیم از دستگاه به مرورگر جریان می‌یابد؛ در حالت دسکتاپ به پوشه‌ی انتخاب‌شده.
- سقف حجم اختیاری است (transfer.max_mb؛ ۰ = بدون محدودیت).
- TFTP: فقط به IP دستگاه‌های انتخاب‌شده پاسخ می‌دهد؛ فایل‌های دریافتی رمزشده نگه داشته می‌شوند.
"""
import base64
import ftplib  # nosec B402 — FTP به درخواست کاربر برای تجهیزات قدیمی؛ رابط هشدار عدم رمزنگاری می‌دهد و FTPS هم هست
import logging
import os
import posixpath
import re
import socket
import stat as stmod
import struct
import threading
import time
import uuid
from pathlib import Path

from . import atrest, paths
from .abort import CANCEL_MSG, Aborted, ftp_class
from .term import TermError, check_hostkey, ssh_connect
from .tftp import TftpServer, local_ip_for

log = logging.getLogger(__name__)
CHUNK = 256 * 1024
PUT_MAX_CHUNK = 4 * 1024 * 1024
MAX_CONN_PER_USER = 6
IDLE_SECS = 30 * 60
JOB_KEEP = 3600
PROTOS = ("sftp", "scp", "ftp", "ftps")
_BAD = re.compile(r"[\x00-\x1f\x7f]")


class XferError(Exception):
    pass


def clean_name(n):
    n = os.path.basename(str(n or "").replace("\\", "/")).strip()
    if not n or n in (".", "..") or _BAD.search(n) or len(n) > 255:
        raise XferError(f"نام فایل نامعتبر است: {n or '(خالی)'}")
    return n


def clean_rpath(p):
    p = str(p or "").strip()
    if not p or _BAD.search(p) or len(p) > 1024:
        raise XferError("مسیر نامعتبر است.")
    return p


def human(n):
    n = float(n or 0)
    for u in ("B", "KB", "MB", "GB"):
        if n < 1024 or u == "GB":
            return f"{n:.0f} {u}" if u == "B" else f"{n:.1f} {u}"
        n /= 1024


# ---------------------------------------------------------------- فایل رمزشده‌ی تکه‌ای (staging/دریافتی TFTP)
class EncWriter:
    """هر تکه جدا با atrest رمز می‌شود: [طول ۴ بایت][تکه‌ی رمزشده] — بدون نگه داشتن کل فایل در حافظه."""
    def __init__(self, path):
        self.path = Path(path)
        self.f = open(self.path, "wb")
        self.buf = bytearray()
        self.size = 0

    def write(self, data):
        self.buf += data
        self.size += len(data)
        if len(self.buf) >= 1024 * 1024:
            self._flush()

    def _flush(self):
        if self.buf:
            blob = atrest.encrypt(bytes(self.buf))
            self.f.write(struct.pack("!I", len(blob)) + blob)
            self.buf = bytearray()

    def close(self, ok=True):
        try:
            if ok:
                self._flush()
        finally:
            self.f.close()
            if not ok:
                try:
                    self.path.unlink()
                except OSError:
                    pass


def enc_iter(path):
    with open(path, "rb") as f:
        while True:
            h = f.read(4)
            if len(h) < 4:
                return
            yield atrest.decrypt(f.read(struct.unpack("!I", h)[0]))


def enc_size(path):
    return sum(len(c) for c in enc_iter(path))


# ---------------------------------------------------------------- SCP (پروتکل ساده‌ی یک فایل)
def _scp_path(p):
    p = clean_rpath(p)
    if re.search(r"[\s'\"`$;&|<>\\]", p):
        raise XferError("در SCP مسیر نباید فاصله یا نویسه‌ی خاص داشته باشد.")
    if p.startswith("-"):                  # 1.27.7: به scp -t/-f می‌رسد؛ «-» اول گزینه حساب می‌شود
        raise XferError("در SCP مسیر نباید با «-» شروع شود (مثلاً ./-file بنویسید).")
    return p


def _scp_ack(chan):
    c = chan.recv(1)
    if c == b"\0":
        return
    msg = b""
    while not msg.endswith(b"\n"):
        x = chan.recv(1)
        if not x:
            break
        msg += x
    raise XferError("SCP: " + (msg.decode("utf-8", "replace").strip() or "پاسخ نامعتبر از دستگاه"))


class _ScpWriter:
    def __init__(self, cli, path, size):
        d, name = posixpath.split(path)
        self.chan = cli.get_transport().open_session(timeout=20)
        self.chan.settimeout(60)
        self.chan.exec_command(f"scp -t {_scp_path(path)}")
        _scp_ack(self.chan)
        self.chan.sendall(f"C0644 {int(size)} {clean_name(name)}\n".encode())
        _scp_ack(self.chan)

    def write(self, data):
        self.chan.sendall(data)

    def close(self, ok=True):
        try:
            if ok:
                self.chan.sendall(b"\0")
                _scp_ack(self.chan)
        finally:
            self.chan.close()


class _ScpReader:
    def __init__(self, cli, path):
        self.chan = cli.get_transport().open_session(timeout=20)
        self.chan.settimeout(60)
        self.chan.exec_command(f"scp -f {_scp_path(path)}")
        self.chan.sendall(b"\0")
        line = b""
        while not line.endswith(b"\n"):
            x = self.chan.recv(1)
            if not x:
                break
            line += x
        if line[:1] in (b"\x01", b"\x02") or not line.startswith(b"C"):
            self.chan.close()
            raise XferError("SCP: " + (line[1:].decode("utf-8", "replace").strip() or "فایل خوانده نشد (شاید پوشه است یا وجود ندارد)"))
        try:
            self.size = int(line.split(b" ")[1])
        except (IndexError, ValueError):
            self.chan.close()
            raise XferError("SCP: سرآیند نامعتبر")
        self.left = self.size
        self.chan.sendall(b"\0")

    def read(self, n):
        if self.left <= 0:
            return b""
        d = self.chan.recv(min(n, self.left))
        if not d:
            raise XferError("SCP: اتصال پیش از پایان فایل قطع شد")
        self.left -= len(d)
        return d

    def close(self, ok=True):
        try:
            if ok and self.left == 0:
                _scp_ack(self.chan)
                self.chan.sendall(b"\0")
        except Exception:
            pass
        finally:
            self.chan.close()


# ---------------------------------------------------------------- FTP
class _FtpWriter:
    def __init__(self, ftp, path):
        self.ftp = ftp
        ftp.voidcmd("TYPE I")
        self.sock = ftp.transfercmd(f"STOR {path}")

    def write(self, data):
        self.sock.sendall(data)

    def close(self, ok=True):
        try:
            if isinstance(self.sock, socket.socket) and hasattr(self.sock, "unwrap"):
                try:
                    self.sock.unwrap()
                except Exception:
                    pass
            self.sock.close()
            if ok:
                self.ftp.voidresp()
        finally:
            try:
                self.ftp.quit()
            except Exception:
                self.ftp.close()


class _FtpReader:
    def __init__(self, ftp, path):
        self.ftp = ftp
        ftp.voidcmd("TYPE I")
        try:
            self.size = ftp.size(path)
        except ftplib.all_errors:
            self.size = None
        self.sock = ftp.transfercmd(f"RETR {path}")

    def read(self, n):
        return self.sock.recv(n)

    def close(self, ok=True):
        try:
            self.sock.close()
            if ok:
                self.ftp.voidresp()
        except Exception:
            pass
        finally:
            try:
                self.ftp.quit()
            except Exception:
                self.ftp.close()


_LIST_RE = re.compile(r"^([dl-])[rwxsStT-]{9}\S*\s+\d+\s+\S+\s+\S+\s+(\d+)\s+(\w{3}\s+\d+\s+[\d:]+)\s+(.+)$")


def _ftp_list(ftp, path):
    items = []
    try:
        for name, f in ftp.mlsd(path, facts=["type", "size", "modify"]):
            t = f.get("type", "")
            if t in ("cdir", "pdir") or name in (".", ".."):
                continue
            mt = 0
            try:
                mt = time.mktime(time.strptime(f.get("modify", "")[:14], "%Y%m%d%H%M%S"))
            except ValueError:
                pass
            items.append({"name": name, "dir": t == "dir", "size": int(f.get("size") or 0), "mtime": mt})
        return items
    except ftplib.error_perm:
        pass
    lines = []
    ftp.retrlines(f"LIST {path}" if path else "LIST", lines.append)
    for ln in lines:
        m = _LIST_RE.match(ln)
        if not m:
            continue
        name = m.group(4)
        if m.group(1) == "l" and " -> " in name:
            name = name.split(" -> ")[0]
        if name in (".", ".."):
            continue
        items.append({"name": name, "dir": m.group(1) == "d", "size": int(m.group(2)), "mtime": 0, "when": m.group(3)})
    return items


# ---------------------------------------------------------------- اتصال
class Conn:
    def __init__(self, owner, proto, dev, creds, opts):
        self.id = uuid.uuid4().hex
        self.owner, self.proto, self.dev, self.creds, self.opts = owner, proto, dev, creds, opts
        self.title = dev.get("name") or dev["host"]
        self.host = dev["host"]
        self.port = int(opts.get("port") or (21 if proto in ("ftp", "ftps") else dev.get("port") or 22))
        self.cli = self.sftp = self.ftp = None
        self.lock = threading.RLock()
        self.last = time.time()
        self.home = "/"
        self.closed = False

    def public(self):
        return {"id": self.id, "proto": self.proto, "title": self.title, "host": self.host, "port": self.port,
                "home": self.home, "browse": self.proto != "scp", "user": self.creds.get("username", "")}

    # ---- FTP
    def _ftp_new(self, attempt=None):
        tls = self.proto == "ftps"
        if attempt:
            f = ftp_class(attempt, tls)(timeout=20)
        else:
            f = ftplib.FTP_TLS(timeout=20) if tls else ftplib.FTP(timeout=20)  # nosec B321 — انتخاب صریح کاربر (هشدار در رابط)
        f.encoding = "utf-8"
        try:
            f.connect(self.host, self.port)
            f.login(self.creds.get("username") or "anonymous", self.creds.get("password") or "")
            if tls:
                f.prot_p()
            f.set_pasv(not self.opts.get("active"))
        except Exception:
            f.close()
            raise
        return f

    def open(self, hostkeys, attempt=None):
        if self.proto in ("ftp", "ftps"):
            self.ftp = self._ftp_new(attempt)
            try:
                self.home = self.ftp.pwd() or "/"
            except ftplib.all_errors:
                self.home = "/"
            return
        self.cli = ssh_connect(hostkeys, {**self.dev, "port": self.port}, self.creds, attempt)
        self.cli.get_transport().set_keepalive(30)
        if self.proto == "sftp":
            try:
                self.sftp = self.cli.open_sftp()
                self.home = self.sftp.normalize(".") or "/"
            except Exception as e:
                self.cli.close()
                if attempt and attempt.cancelled:
                    raise XferError(CANCEL_MSG)
                raise XferError(f"SFTP روی این دستگاه فعال نیست ({e}). SCP یا TFTP را امتحان کنید.")

    def close(self):
        self.closed = True
        for c in (self.sftp, self.cli):
            try:
                c and c.close()
            except Exception:
                pass
        if self.ftp:
            try:
                self.ftp.quit()
            except Exception:
                self.ftp.close()

    def _ftp_alive(self):
        try:
            self.ftp.voidcmd("NOOP")
        except Exception:
            try:
                self.ftp.close()
            except Exception:
                pass
            self.ftp = self._ftp_new()

    # ---- مرور
    def ls(self, path):
        path = clean_rpath(path or self.home)
        with self.lock:
            self.last = time.time()
            if self.proto == "sftp":
                path = self.sftp.normalize(path)
                items = []
                for a in self.sftp.listdir_attr(path):
                    isdir = stmod.S_ISDIR(a.st_mode or 0)
                    if stmod.S_ISLNK(a.st_mode or 0):
                        try:
                            isdir = stmod.S_ISDIR(self.sftp.stat(posixpath.join(path, a.filename)).st_mode)
                        except OSError:
                            pass
                    items.append({"name": a.filename, "dir": isdir, "size": a.st_size or 0, "mtime": a.st_mtime or 0,
                                  "perm": stmod.filemode(a.st_mode) if a.st_mode else ""})
                return {"path": path, "items": items}
            if self.proto in ("ftp", "ftps"):
                self._ftp_alive()
                self.ftp.cwd(path)
                path = self.ftp.pwd()
                return {"path": path, "items": _ftp_list(self.ftp, "")}
        raise XferError("در SCP فهرست پوشه وجود ندارد؛ مسیر کامل فایل را وارد کنید.")

    def mkdir(self, path):
        path = clean_rpath(path)
        with self.lock:
            self.last = time.time()
            if self.proto == "sftp":
                self.sftp.mkdir(path)
            elif self.proto in ("ftp", "ftps"):
                self._ftp_alive()
                self.ftp.mkd(path)
            else:
                raise XferError("در SCP پوشه ساخته نمی‌شود.")

    def delete(self, path, is_dir):
        path = clean_rpath(path)
        with self.lock:
            self.last = time.time()
            if self.proto == "sftp":
                (self.sftp.rmdir if is_dir else self.sftp.remove)(path)
            elif self.proto in ("ftp", "ftps"):
                self._ftp_alive()
                (self.ftp.rmd if is_dir else self.ftp.delete)(path)
            else:
                raise XferError("در SCP حذف ممکن نیست.")

    def rename(self, a, b):
        a, b = clean_rpath(a), clean_rpath(b)
        with self.lock:
            self.last = time.time()
            if self.proto == "sftp":
                self.sftp.rename(a, b)
            elif self.proto in ("ftp", "ftps"):
                self._ftp_alive()
                self.ftp.rename(a, b)
            else:
                raise XferError("در SCP تغییر نام ممکن نیست.")

    def exists(self, path):
        with self.lock:
            if self.proto == "sftp":
                try:
                    self.sftp.stat(path)
                    return True
                except OSError:
                    return False
            if self.proto in ("ftp", "ftps"):
                self._ftp_alive()
                try:
                    self.ftp.voidcmd("TYPE I")
                    self.ftp.size(path)
                    return True
                except ftplib.all_errors:
                    return False
        return False

    # ---- جریان داده (هر انتقال کانال یا اتصال جدای خودش را دارد تا مرور هم‌زمان کار کند)
    def writer(self, path, size):
        path = clean_rpath(path)
        if self.proto == "sftp":
            s = self.cli.open_sftp()
            f = s.open(path, "wb")
            f.set_pipelined(True)

            class W:
                def write(self, d):
                    f.write(d)

                def close(self, ok=True):
                    try:
                        f.close()
                        if not ok:
                            try:
                                s.remove(path)
                            except OSError:
                                pass
                    finally:
                        s.close()
            return W()
        if self.proto == "scp":
            return _ScpWriter(self.cli, path, size)
        return _FtpWriter(self._ftp_new(), path)

    def reader(self, path):
        path = clean_rpath(path)
        if self.proto == "sftp":
            s = self.cli.open_sftp()
            try:
                f = s.open(path, "rb")
                size = f.stat().st_size
                if stmod.S_ISDIR(f.stat().st_mode or 0):
                    raise XferError("این مسیر پوشه است.")
                f.prefetch(size)
            except Exception:
                s.close()
                raise

            class R:
                pass
            r = R()
            r.size, r.read = size, f.read

            def close(ok=True):
                try:
                    f.close()
                finally:
                    s.close()
            r.close = close
            return r
        if self.proto == "scp":
            return _ScpReader(self.cli, path)
        return _FtpReader(self._ftp_new(), path)


# ---------------------------------------------------------------- مدیر
class XferManager:
    def __init__(self, settings, hostkeys, emit=None):
        self.settings, self.hostkeys = settings, hostkeys
        self.emit = emit or (lambda *a, **k: None)
        self.on_history = None
        self.conns = {}
        self.jobs = {}
        self.tokens = {}
        self._lock = threading.Lock()
        self.tftp = None            # {"server", "owner", "allowed", "port", "write", "files": {name: (path, enc)}, "started", "last"}
        threading.Thread(target=self._watchdog, name="xfer-watchdog", daemon=True).start()

    def limit(self):
        try:
            mb = float((self.settings.get("transfer") or {}).get("max_mb") or 0)
        except (TypeError, ValueError):
            mb = 0
        return int(mb * 1024 * 1024) if mb > 0 else 0

    def _check_size(self, size):
        lim = self.limit()
        if lim and size is not None and int(size) > lim:
            raise XferError(f"حجم فایل ({human(size)}) بیشتر از سقف تنظیم‌شده ({human(lim)}) است.")

    def _hist(self, owner, target, status, detail, file=""):
        if self.on_history:
            try:
                self.on_history(owner, target, status, detail, file)
            except Exception:
                log.exception("xfer history")

    # ---- اتصال
    def connect(self, owner, dev, creds, proto, adhoc=False, accept_fp=None, opts=None, attempt=None):
        proto = str(proto or "sftp").lower()
        if proto not in PROTOS:
            raise XferError("پروتکل نامعتبر است.")
        opts = opts if isinstance(opts, dict) else {}
        with self._lock:
            if len([c for c in self.conns.values() if c.owner == owner]) >= MAX_CONN_PER_USER:
                raise XferError(f"حداکثر {MAX_CONN_PER_USER} اتصال انتقال فایل باز برای هر کاربر.")
        c = Conn(owner, proto, dev, creds, opts)
        if proto in ("sftp", "scp"):
            if not creds.get("username"):
                raise XferError("یوزر وارد نشده است.")
            try:
                confirm = check_hostkey(self.hostkeys, c.host, c.port, bool(dev.get("legacy")), adhoc, accept_fp, self.emit,
                                        attempt)
            except TermError as e:
                raise XferError(str(e))
            if confirm:
                return confirm
        try:
            c.open(self.hostkeys, attempt)
            if attempt:
                attempt.check()     # لغو هم‌زمان با برقراری: اتصال نگه داشته نمی‌شود
        except (TermError, XferError, Aborted) as e:
            c.close()
            raise XferError(str(e))
        except ftplib.all_errors as e:
            c.close()
            raise XferError(CANCEL_MSG if attempt and attempt.cancelled else f"اتصال FTP ناموفق: {e}")
        with self._lock:
            self.conns[c.id] = c
        return {"conn": c.public()}

    def get(self, cid, owner):
        c = self.conns.get(str(cid))
        if not c or c.owner != owner or c.closed:
            raise XferError("اتصال انتقال فایل پیدا نشد یا بسته شده است؛ دوباره وصل شوید.")
        c.last = time.time()
        return c

    def close(self, cid, owner):
        c = self.get(cid, owner)
        c.close()
        with self._lock:
            self.conns.pop(c.id, None)

    def close_all(self, owner=None):
        for c in list(self.conns.values()):
            if owner is None or c.owner == owner:
                c.close()
                self.conns.pop(c.id, None)
        for j in list(self.jobs.values()):
            if (owner is None or j["owner"] == owner) and j["state"] in ("running", "waiting"):
                j["cancel"].set()
        if owner is None or (self.tftp and self.tftp["owner"] == owner):
            self.tftp_stop(None)

    def list(self, owner):
        return [c.public() for c in self.conns.values() if c.owner == owner and not c.closed]

    # ---- کارها
    def _job(self, owner, conn, direction, name, remote, size, local=""):
        j = {"id": uuid.uuid4().hex, "owner": owner, "conn": conn.id if conn else "", "proto": conn.proto if conn else "tftp",
             "host": conn.host if conn else "", "dir": direction, "name": name, "remote": remote, "local": local,
             "size": size, "done": 0, "state": "running", "error": "", "started": time.time(), "ended": 0,
             "cancel": threading.Event()}
        with self._lock:
            self.jobs[j["id"]] = j
        return j

    @staticmethod
    def pub_job(j):
        el = max(0.001, (j["ended"] or time.time()) - j["started"])
        return {k: v for k, v in j.items() if k not in ("cancel", "_w", "_r", "token")} | {"speed": int(j["done"] / el)}

    def job_list(self, owner):
        return [self.pub_job(j) for j in sorted(self.jobs.values(), key=lambda x: -x["started"]) if j["owner"] == owner][:100]

    def _end(self, j, ok, err=""):
        if j["state"] not in ("running", "waiting"):
            return
        j["ended"] = time.time()
        j["state"] = "ok" if ok else ("cancelled" if j["cancel"].is_set() else "error")
        j["error"] = "" if ok else (err or "لغو شد")
        extra = (f" — {j['error']}" if not ok else "") + (f" — {j['local']}" if j.get("local") else "")
        size, pr = human(j["done"]), j["proto"].upper()
        if j["dir"] == "up":
            detail = f"آپلود {pr} — {j['remote']} — {size}{extra}"
        elif j["dir"] == "stage":
            detail = f"آماده‌سازی فایل برای TFTP — {j['name']} — {size}{extra}"
        else:
            detail = f"دانلود {pr} — {j['remote']} — {size}{extra}"
        self._hist(j["owner"], j["host"] or j["name"], "ok" if ok else "error", detail)

    def cancel(self, owner, jid):
        j = self.jobs.get(str(jid))
        if not j or j["owner"] != owner:
            raise XferError("کار پیدا نشد.")
        j["cancel"].set()
        if j["state"] == "running" and j.get("_w"):        # آپلود مرورگر که منتظر تکه‌ی بعدی است
            self._abort_put(j)
        elif j["state"] == "waiting":
            self._end(j, False, "لغو شد")

    def clear_jobs(self, owner, only=None):
        """پاک کردن کارهای تمام‌شده (یا فقط یکی، مثلاً کاری که «تلاش مجدد» جایش را گرفت)."""
        with self._lock:
            for k, j in list(self.jobs.items()):
                if only and k != only:
                    continue
                if j["owner"] == owner and j["state"] not in ("running", "waiting"):
                    self.jobs.pop(k, None)

    # ---- آپلود تکه‌ای از مرورگر
    def put_begin(self, owner, cid, remote_dir, name, size, overwrite=False):
        name = clean_name(name)
        size = int(size or 0)
        if size < 0:
            raise XferError("حجم نامعتبر")
        self._check_size(size)
        if cid == "tftp":
            return self._tftp_put_begin(owner, name, size)
        c = self.get(cid, owner)
        remote = posixpath.join(clean_rpath(remote_dir), name) if c.proto != "scp" or remote_dir else name
        if c.proto == "scp" and str(remote_dir or "").endswith(":"):
            remote = remote_dir + name           # flash: ← flash:name
        if not overwrite and c.proto != "scp" and c.exists(remote):
            return {"exists": True, "remote": remote}
        j = self._job(owner, c, "up", name, remote, size)
        try:
            j["_w"] = c.writer(remote, size)
        except Exception as e:
            self._end(j, False, self._err(e))
            raise XferError(self._err(e))
        if size == 0:
            self._finish_put(j)
        return {"job": self.pub_job(j)}

    def put_chunk(self, owner, jid, off, b64):
        j = self.jobs.get(str(jid))
        if not j or j["owner"] != owner or j["dir"] not in ("up", "stage"):
            raise XferError("کار آپلود پیدا نشد.")
        if j["state"] != "running":
            raise XferError(j["error"] or "آپلود متوقف شده است.")
        if j["cancel"].is_set():
            self._abort_put(j)
            raise XferError("لغو شد")
        data = base64.b64decode(str(b64 or ""), validate=True)
        if len(data) > PUT_MAX_CHUNK or int(off) != j["done"] or j["done"] + len(data) > j["size"]:
            self._abort_put(j, "تکه‌ی نامعتبر")
            raise XferError("ترتیب یا حجم تکه‌ها نامعتبر است؛ آپلود لغو شد.")
        j["_touch"] = time.time()
        try:
            j["_w"].write(data)
        except Exception as e:
            self._abort_put(j, self._err(e))
            raise XferError(self._err(e))
        j["done"] += len(data)
        if j["done"] >= j["size"]:
            self._finish_put(j)
        return {"job": self.pub_job(j)}

    def _finish_put(self, j):
        try:
            j.pop("_w").close(True)
        except Exception as e:
            self._end(j, False, self._err(e))
            raise XferError(self._err(e))
        if j["dir"] == "stage":
            self._tftp_staged(j)
        self._end(j, True)

    def _abort_put(self, j, err="لغو شد"):
        w = j.pop("_w", None)
        if w:
            try:
                w.close(False)
            except Exception:
                pass
        self._end(j, False, err)

    # ---- انتقال از/به مسیر محلی (حالت دسکتاپ)
    def local_transfer(self, owner, cid, direction, items, target_dir, overwrite=False):
        c = self.get(cid, owner)
        jobs = []
        for it in items or []:
            if direction == "up":
                lp = Path(str(it))
                if not lp.is_file():
                    raise XferError(f"فایل پیدا نشد (پوشه‌ها پشتیبانی نمی‌شوند): {lp}")
                self._check_size(lp.stat().st_size)
                remote = (target_dir + lp.name) if c.proto == "scp" and str(target_dir).endswith(":") else \
                    posixpath.join(clean_rpath(target_dir or c.home), clean_name(lp.name))
                if not overwrite and c.proto != "scp" and c.exists(remote):
                    return {"exists": True, "remote": remote}
                jobs.append(self._job(owner, c, "up", lp.name, remote, lp.stat().st_size, str(lp)))
            else:
                rp = clean_rpath(it)
                name = clean_name(posixpath.basename(rp.split(":")[-1]) if c.proto == "scp" else posixpath.basename(rp))
                lp = Path(str(target_dir)) / name
                if not Path(str(target_dir)).is_dir():
                    raise XferError("پوشه‌ی مقصد محلی پیدا نشد.")
                if lp.exists() and not overwrite:
                    return {"exists": True, "local": str(lp)}
                jobs.append(self._job(owner, c, "down", name, rp, None, str(lp)))
        threading.Thread(target=self._run_local, args=(c, jobs), name="xfer-local", daemon=True).start()
        return {"jobs": [self.pub_job(j) for j in jobs]}

    def _run_local(self, c, jobs):
        for j in jobs:
            if j["cancel"].is_set():
                self._end(j, False)
                continue
            src = dst = None
            ok = False
            try:
                if j["dir"] == "up":
                    src = open(j["local"], "rb")
                    dst = c.writer(j["remote"], j["size"])
                    rd = src.read
                else:
                    src = c.reader(j["remote"])
                    j["size"] = src.size
                    self._check_size(src.size)
                    dst = open(j["local"] + ".part", "wb")
                    rd = src.read
                lim = self.limit()
                while not j["cancel"].is_set():
                    d = rd(CHUNK)
                    if not d:
                        break
                    dst.write(d)
                    j["done"] += len(d)
                    if lim and j["done"] > lim:
                        raise XferError(f"از سقف حجم ({human(lim)}) بیشتر شد.")
                ok = not j["cancel"].is_set()
                err = ""
            except Exception as e:
                err = self._err(e)
            finally:
                for f in (src, dst):
                    if f is None:
                        continue
                    try:
                        try:
                            f.close(ok)
                        except TypeError:       # فایل محلی
                            f.close()
                    except Exception as e:
                        if ok:
                            ok, err = False, self._err(e)
            if j["dir"] == "down":
                part = Path(j["local"] + ".part")
                try:
                    if ok:
                        os.replace(part, j["local"])
                    elif part.exists():
                        part.unlink()
                except OSError as e:
                    ok, err = False, str(e)
            self._end(j, ok, err)

    # ---- دانلود جریانی در مرورگر (حالت وب)
    def get_begin(self, owner, cid, rpath):
        c = self.get(cid, owner)
        rp = clean_rpath(rpath)
        name = clean_name(rp.split(":")[-1].split("/")[-1])
        j = self._job(owner, c, "down", name, rp, None)
        j["state"] = "waiting"
        tok = uuid.uuid4().hex + uuid.uuid4().hex
        j["token"] = tok
        self.tokens[tok] = j["id"]
        return {"job": self.pub_job(j), "token": tok}

    def get_file_begin(self, owner, path, name):
        """فایل رمزشده‌ی محلی (دریافتی TFTP) برای دانلود در مرورگر."""
        j = self._job(owner, None, "down", name, name, None)
        j.update(state="waiting", local_enc=str(path))
        tok = uuid.uuid4().hex + uuid.uuid4().hex
        j["token"] = tok
        self.tokens[tok] = j["id"]
        return tok

    def stream(self, tok, owner):
        """(name, size, iterator) برای سرور وب؛ توکن یک‌بارمصرف و فقط برای همان کاربر."""
        jid = self.tokens.pop(str(tok), None)
        j = self.jobs.get(jid or "")
        if not j or j["owner"] != owner or j["state"] != "waiting":
            return None
        if j.get("local_enc"):
            j["state"] = "running"
            p = j.pop("local_enc")

            def gen_local():
                ok = False
                try:
                    for d in enc_iter(p):
                        j["done"] += len(d)
                        yield d
                    ok = True
                finally:
                    j["ended"] = time.time()
                    j["state"] = "ok" if ok else "error"
            j["size"] = enc_size(p)
            return j["name"], j["size"], gen_local()
        c = self.conns.get(j["conn"])
        if not c:
            self._end(j, False, "اتصال بسته شده است")
            return None
        try:
            r = c.reader(j["remote"])
            self._check_size(r.size)
        except Exception as e:
            j["state"] = "running"
            self._end(j, False, self._err(e))
            return None
        j["state"] = "running"
        j["size"] = r.size

        def gen():
            ok, err = False, ""
            lim = self.limit()
            try:
                while not j["cancel"].is_set():
                    d = r.read(CHUNK)
                    if not d:
                        break
                    j["done"] += len(d)
                    if lim and j["done"] > lim:
                        raise XferError(f"از سقف حجم ({human(lim)}) بیشتر شد.")
                    yield d
                ok = not j["cancel"].is_set()
            except GeneratorExit:
                err = "دانلود در مرورگر قطع شد"
                raise
            except Exception as e:
                err = self._err(e)
            finally:
                try:
                    r.close(ok)
                except Exception:
                    pass
                self._end(j, ok, err)
        return j["name"], r.size, gen()

    @staticmethod
    def _err(e):
        if isinstance(e, (XferError, TermError)):
            return str(e)
        if isinstance(e, PermissionError) or "ermission denied" in str(e):
            return "دسترسی روی دستگاه رد شد (Permission denied)."
        if isinstance(e, FileNotFoundError) or "No such file" in str(e):
            return "فایل یا پوشه پیدا نشد."
        if isinstance(e, ftplib.Error):
            return f"FTP: {e}"
        return f"{e.__class__.__name__}: {e}"

    # ---------------------------------------------------------------- TFTP
    def _tftp_dir(self, sub):
        d = paths.data_dir() / sub
        d.mkdir(exist_ok=True)
        return d

    def tftp_start(self, owner, allowed, port=69, write=True):
        if self.tftp:
            if self.tftp["owner"] != owner:
                raise XferError(f"سرور TFTP الان توسط «{self.tftp['owner'] or 'کاربر دیگر'}» روشن است.")
            self.tftp_stop(owner)
        ips = []
        for h in allowed or []:
            try:
                ips.append(socket.gethostbyname(str(h).strip()))
            except OSError:
                raise XferError(f"آدرس دستگاه پیدا نشد: {h}")
        if not ips:
            raise XferError("حداقل یک دستگاه مجاز لازم است (سرور فقط به IP همان دستگاه‌ها جواب می‌دهد).")
        st = {"owner": owner, "allowed": ips, "port": int(port or 69), "write": bool(write), "files": {},
              "received": [], "started": time.time(), "last": time.time()}
        srv = TftpServer(None, port=st["port"], allowed=ips, on_event=self._tftp_event,
                         files=lambda n: self._tftp_read(n), on_write=self._tftp_write if write else None)
        srv.start()
        st["server"] = srv
        self.tftp = st
        try:
            st["local_ip"] = local_ip_for(ips[0])
        except OSError:
            st["local_ip"] = ""
        allowed_txt = ", ".join(ips)
        self._hist(owner, "TFTP", "ok", f"سرور TFTP روشن شد (پورت {st['port']}، مجاز: {allowed_txt}، دریافت فایل فعال)" if write
                   else f"سرور TFTP روشن شد (پورت {st['port']}، مجاز: {allowed_txt})")
        return self.tftp_status(owner)

    def tftp_stop(self, owner):
        st = self.tftp
        if not st or (owner is not None and st["owner"] != owner):
            return {}
        self.tftp = None
        try:
            st["server"].stop()
        except Exception:
            pass
        for name, (p, staged, _) in st["files"].items():
            if staged:
                try:
                    Path(p).unlink()
                except OSError:
                    pass
        self._hist(st["owner"], "TFTP", "ok", "سرور TFTP خاموش شد")
        return {}

    def tftp_status(self, owner):
        st = self.tftp
        if not st:
            return {"running": False}
        if st["owner"] != owner:
            return {"running": True, "other": st["owner"] or "-"}
        srv = st["server"]
        return {"running": True, "port": st["port"], "allowed": st["allowed"], "write": st["write"], "local_ip": st.get("local_ip", ""),
                "files": [{"name": n, "size": sz, "staged": s} for n, (p, s, sz) in st["files"].items()],
                "transfers": [dict(t) for t in list(srv.transfers)[-50:]], "received": list(st["received"])}

    def tftp_add_local(self, owner, files):
        st = self.tftp
        if not st or st["owner"] != owner:
            raise XferError("سرور TFTP روشن نیست.")
        for f in files or []:
            p = Path(str(f))
            if not p.is_file():
                raise XferError(f"فایل پیدا نشد: {p}")
            self._check_size(p.stat().st_size)
            st["files"][clean_name(p.name)] = (str(p), False, p.stat().st_size)
        return self.tftp_status(owner)

    def tftp_remove(self, owner, name):
        st = self.tftp
        if st and st["owner"] == owner and name in st["files"]:
            p, staged, _ = st["files"].pop(name)
            if staged:
                try:
                    Path(p).unlink()
                except OSError:
                    pass
        return self.tftp_status(owner)

    def _tftp_put_begin(self, owner, name, size):
        st = self.tftp
        if not st or st["owner"] != owner:
            raise XferError("سرور TFTP روشن نیست.")
        j = self._job(owner, None, "stage", name, name, size)
        j["host"] = "TFTP"
        p = self._tftp_dir("xfer_stage") / f"{uuid.uuid4().hex[:10]}.bin"
        j["_w"] = EncWriter(p)
        j["_path"] = str(p)
        if size == 0:
            self._finish_put(j)
        return {"job": self.pub_job(j)}

    def _tftp_staged(self, j):
        st = self.tftp
        if not st or st["owner"] != j["owner"]:
            try:
                Path(j["_path"]).unlink()
            except OSError:
                pass
            raise XferError("سرور TFTP خاموش شد.")
        old = st["files"].get(j["name"])
        if old and old[1] and old[0] != j["_path"]:
            try:
                Path(old[0]).unlink()
            except OSError:
                pass
        st["files"][j["name"]] = (j["_path"], True, j["done"])

    def _tftp_read(self, name):
        st = self.tftp
        if not st:
            return None
        st["last"] = time.time()
        rec = st["files"].get(name)
        if not rec:
            return None
        p, staged, _ = rec
        if staged:
            return b"".join(enc_iter(p))
        return Path(p).read_bytes()

    def _tftp_write(self, name, client, tsize):
        st = self.tftp
        if not st or not st["write"]:
            raise XferError("Write not allowed")
        st["last"] = time.time()
        name = clean_name(name)
        if tsize is not None:
            self._check_size(tsize)
        p = self._tftp_dir("received") / f"{time.strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}_{name}.akrp"
        w = EncWriter(p)
        lim = self.limit()
        owner = st["owner"]
        mgr = self

        class Sink:
            size = 0

            def write(self, d):
                if lim and w.size + len(d) > lim:
                    raise XferError("over limit")
                w.write(d)

            def close(self, ok):
                w.close(ok)
                if ok:
                    rec = {"name": name, "client": client, "size": w.size, "ts": time.time(), "path": str(p)}
                    if mgr.tftp:
                        mgr.tftp["received"].append({k: v for k, v in rec.items() if k != "path"} | {"id": p.name})
                        del mgr.tftp["received"][:-500]     # فهرست حافظه محدود (فایل‌ها و تاریخچه می‌مانند)
                    mgr._hist(owner, client, "ok", f"دریافت TFTP — {name} — {human(w.size)}", str(p))
        return Sink()

    def received_path(self, rid):
        rid = clean_name(rid)
        p = paths.data_dir() / "received" / rid
        return p if p.is_file() else None

    def _tftp_event(self, level, msg):
        if level == "warn":       # 1.26.2: درخواست رد‌شده‌ی تکراری (مثلاً بسته‌های جعلی) هر پیام حداکثر یک بار در دقیقه
            seen = self.__dict__.setdefault("_tftp_warned", {})
            now = time.time()
            if now - seen.get(msg, 0) < 60:
                return
            if len(seen) > 1000:
                seen.clear()
            seen[msg] = now
        self.emit("info" if level == "ok" else level, msg, "ssh")

    # ---------------------------------------------------------------- نگهبان
    def _watchdog(self):
        while True:
            time.sleep(30)
            try:
                now = time.time()
                for c in list(self.conns.values()):
                    busy = any(j["conn"] == c.id and j["state"] == "running" for j in self.jobs.values())
                    if not busy and now - c.last > IDLE_SECS:
                        c.close()
                        self.conns.pop(c.id, None)
                for k, j in list(self.jobs.items()):
                    if j["state"] == "running" and j.get("_w") and now - j["started"] > 60 and \
                            now - j.get("_touch", j["started"]) > 600:
                        self._abort_put(j, "بدون ادامه از طرف مرورگر")
                    if j["state"] == "waiting" and now - j["started"] > 600:
                        self._end(j, False, "دانلود شروع نشد")
                    if j["state"] not in ("running", "waiting") and now - j["ended"] > JOB_KEEP:
                        self.jobs.pop(k, None)
                for t, jid in list(self.tokens.items()):
                    if jid not in self.jobs:
                        self.tokens.pop(t, None)
                st = self.tftp
                if st and now - st["last"] > IDLE_SECS and not any(
                        not t.get("secs") and not t.get("error") and not t.get("ok") for t in st["server"].transfers):
                    self.tftp_stop(None)
            except Exception:
                log.exception("xfer watchdog")


def ready_commands(device_type, ip, name="FILE"):
    """دستورهای آماده برای کپی (فقط نمایش)."""
    dt = str(device_type or "linux")
    if dt.startswith("cisco"):
        return [f"copy running-config tftp://{ip}/{name}", f"copy tftp://{ip}/{name} flash:{name}",
                f"copy startup-config tftp://{ip}/{name}"]
    if dt.startswith("fortinet"):
        return [f"execute backup config tftp {name} {ip}", f"execute restore image tftp {name} {ip}"]
    if dt != "linux":
        return []
    return [f"tftp {ip} -c get {name}", f"tftp {ip} -c put {name}", f"curl -T {name} tftp://{ip}/"]
