"""
سرور TFTP موقت (RFC 1350، به‌علاوه‌ی گزینه‌های blksize/tsize/timeout از RFC 2347-2349).
برای «به‌روزرسانی FortiGate» (فقط‌خواندنی، فایل‌های یک پوشه) و بخش انتقال فایل (فایل‌های انتخاب‌شده + دریافت اختیاری):
  - نوشتن (WRQ) فقط وقتی on_write داده شده باشد پذیرفته می‌شود؛
  - مسیر فایل فقط نام فایل است (بدون پوشه یا ..)؛
  - اختیاری: فقط به IPهای مجاز (دستگاه‌های در حال به‌روزرسانی) پاسخ داده می‌شود.
"""
import logging
import os
import socket
import struct
import threading
import time
from collections import deque
from pathlib import Path

log = logging.getLogger(__name__)
RRQ, WRQ, DATA, ACK, ERROR, OACK = 1, 2, 3, 4, 5, 6
MAX_ACTIVE = 16          # انتقال هم‌زمان (هر انتقال یک ترد و یک سوکت)
MAX_ACTIVE_PER_IP = 4
MAX_HISTORY = 200        # تاریخچه‌ی انتقال‌ها در حافظه


class TftpServer:
    def __init__(self, root, host="0.0.0.0", port=69, allowed=None, on_event=None, files=None, on_write=None):  # nosec B104 — دسترسی با فهرست IP دستگاه‌های مجاز کنترل می‌شود
        self.root = Path(root).resolve() if root else None
        self.files = files            # تابع name → bytes یا None (به‌جای پوشه)
        self.on_write = on_write      # تابع (name, client_ip, tsize) → sink با write/close(ok)
        self.host, self.port = host, int(port)
        self.allowed = set(allowed or [])
        self.on_event = on_event or (lambda *a: None)
        self._sock = None
        self._stop = threading.Event()
        self._thread = None
        self.transfers = deque(maxlen=MAX_HISTORY)
        self._active = {}             # ip → تعداد انتقال در جریان
        self._alock = threading.Lock()

    def start(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((self.host, self.port))
        except OSError as e:
            s.close()
            raise OSError(f"پورت UDP {self.port} برای سرور TFTP آزاد نیست ({e}). شاید سرور TFTP دیگری روی این کامپیوتر روشن است.")
        s.settimeout(0.5)
        self._sock = s
        self._thread = threading.Thread(target=self._loop, name="tftp", daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(2)
        if self._sock:
            self._sock.close()

    def _loop(self):
        while not self._stop.is_set():
            try:
                data, addr = self._sock.recvfrom(2048)
            except socket.timeout:
                continue
            except OSError:
                break
            if len(data) < 4:
                continue
            op = struct.unpack("!H", data[:2])[0]
            if self.allowed and addr[0] not in self.allowed:
                self.on_event("warn", f"TFTP: درخواست از {addr[0]} رد شد (جزو دستگاه‌های در حال به‌روزرسانی نیست)")
                self._error(addr, 2, "Access violation")
                continue
            if op == WRQ and not self.on_write:
                self._error(addr, 2, "Write not allowed")
                continue
            if op not in (RRQ, WRQ):
                continue
            if not self._acquire(addr[0]):
                self._error(addr, 0, "Server busy")
                continue
            target = self._receive if op == WRQ else self._serve
            threading.Thread(target=self._run, args=(target, data, addr), daemon=True).start()

    def _acquire(self, ip):
        """سقف انتقال هم‌زمان کل و هر IP؛ درخواست‌های زیاد ترد و سوکت نامحدود نمی‌سازند."""
        with self._alock:
            if sum(self._active.values()) >= MAX_ACTIVE or self._active.get(ip, 0) >= MAX_ACTIVE_PER_IP:
                self.on_event("warn", f"TFTP: درخواست {ip} رد شد (سقف انتقال هم‌زمان)")
                return False
            self._active[ip] = self._active.get(ip, 0) + 1
            return True

    def _run(self, fn, data, addr):
        try:
            fn(data, addr)
        finally:
            with self._alock:
                n = self._active.get(addr[0], 1) - 1
                if n > 0:
                    self._active[addr[0]] = n
                else:
                    self._active.pop(addr[0], None)

    def _error(self, addr, code, msg, sock=None):
        pkt = struct.pack("!HH", ERROR, code) + msg.encode() + b"\0"
        try:
            (sock or self._sock).sendto(pkt, addr)
        except OSError:
            pass

    @staticmethod
    def _parse(data):
        parts = data[2:].split(b"\0")
        name = parts[0].decode("utf-8", "replace")
        mode = (parts[1].decode("latin-1", "replace") if len(parts) > 1 else "octet").lower()
        opts = {}
        for i in range(2, len(parts) - 1, 2):
            if parts[i]:
                opts[parts[i].decode("latin-1").lower()] = parts[i + 1].decode("latin-1")
        return name, mode, opts

    @staticmethod
    def _opts(opts, tsize=None):
        blk, timeout, oack = 512, 3.0, {}
        if "blksize" in opts:
            try:
                blk = max(8, min(65464, int(opts["blksize"])))
                oack["blksize"] = str(blk)
            except ValueError:
                pass
        if "tsize" in opts:
            oack["tsize"] = str(tsize if tsize is not None else opts["tsize"])
        if "timeout" in opts:
            try:
                timeout = float(max(1, min(255, int(opts["timeout"]))))
                oack["timeout"] = opts["timeout"]
            except ValueError:
                pass
        return blk, timeout, oack

    def _receive(self, data, addr):
        """WRQ: دریافت فایل از دستگاه (مثلاً copy running-config tftp:)."""
        name, mode, opts = self._parse(data)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((self.host if self.host != "0.0.0.0" else "", 0))  # nosec B104 — دسترسی با فهرست IP دستگاه‌های مجاز کنترل می‌شود
        t0 = time.time()
        rec = {"file": name, "client": addr[0], "bytes": 0, "ok": False, "error": "", "secs": 0, "dir": "in"}
        self.transfers.append(rec)
        sink = None
        ok = False
        try:
            if mode not in ("octet", "netascii"):
                self._error(addr, 0, "Unsupported mode", sock)
                return
            try:
                ts = int(opts["tsize"]) if "tsize" in opts else None
            except ValueError:
                ts = None
            try:
                sink = self.on_write(name, addr[0], ts)
            except Exception as e:
                rec["error"] = str(e)
                self._error(addr, 3 if "حجم" in str(e) else 2, "Disk full or allocation exceeded" if "حجم" in str(e) else "Access violation", sock)
                self.on_event("error", f"TFTP: دریافت «{name}» از {addr[0]} رد شد ({e})")
                return
            blk, timeout, oack = self._opts(opts)
            sock.settimeout(timeout)
            self.on_event("info", f"TFTP: دریافت «{name}» از {addr[0]}")
            last = (struct.pack("!H", OACK) + b"".join(k.encode() + b"\0" + v.encode() + b"\0" for k, v in oack.items())) \
                if oack else struct.pack("!HH", ACK, 0)
            expect, tries = 1, 0
            sock.sendto(last, addr)
            last_good = time.monotonic()
            while not self._stop.is_set():
                if time.monotonic() - last_good > (sock.gettimeout() or 3.0) * 7:
                    rec["error"] = f"timeout at block {expect}"   # بسته‌های بی‌ربط انتقال را زنده نگه نمی‌دارند
                    return
                try:
                    d, a = sock.recvfrom(blk + 4)
                except socket.timeout:
                    tries += 1
                    if tries > 6:
                        rec["error"] = f"timeout at block {expect}"
                        return
                    sock.sendto(last, addr)
                    continue
                if a != addr or len(d) < 4:
                    continue
                op, n = struct.unpack("!HH", d[:4])
                if op == ERROR:
                    rec["error"] = d[4:].split(b"\0")[0].decode("utf-8", "replace") or "error from client"
                    return
                if op != DATA:
                    continue
                if n == (expect - 1) & 0xFFFF:          # تکراری: ACK قبلی دوباره
                    sock.sendto(last, addr)
                    continue
                if n != expect & 0xFFFF:
                    continue
                last_good = time.monotonic()
                payload = d[4:]
                try:
                    sink.write(payload)
                except Exception:
                    rec["error"] = "size limit"
                    self._error(addr, 3, "Disk full or allocation exceeded", sock)
                    self.on_event("error", f"TFTP: دریافت «{name}» از {addr[0]} به سقف حجم رسید و قطع شد")
                    return
                rec["bytes"] += len(payload)
                tries = 0
                last = struct.pack("!HH", ACK, n)
                sock.sendto(last, addr)
                expect += 1
                if len(payload) < blk:
                    ok = True
                    break
            rec["ok"] = ok
            if ok:
                self.on_event("ok", f"TFTP: «{name}» کامل از {addr[0]} دریافت شد ({rec['bytes']} بایت)")
        finally:
            if sink is not None:
                try:
                    sink.close(ok)
                except Exception:
                    pass
            rec["secs"] = round(time.time() - t0, 1)
            sock.close()

    def _serve(self, data, addr):
        name, mode, opts = self._parse(data)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((self.host if self.host != "0.0.0.0" else "", 0))  # nosec B104 — دسترسی با فهرست IP دستگاه‌های مجاز کنترل می‌شود
        t0 = time.time()
        rec = {"file": name, "client": addr[0], "bytes": 0, "ok": False, "error": "", "secs": 0}
        self.transfers.append(rec)
        try:
            base = os.path.basename(name.replace("\\", "/"))
            payload = None
            if base == name.replace("\\", "/").lstrip("/"):
                if self.files is not None:
                    payload = self.files(base)
                else:
                    path = (self.root / base).resolve()
                    if self.root in path.parents and path.is_file():
                        payload = path.read_bytes()
            if payload is None:
                rec["error"] = "File not found"
                self.on_event("error", f"TFTP: «{name}» برای {addr[0]} پیدا نشد")
                self._error(addr, 1, "File not found", sock)
                return
            if mode not in ("octet", "netascii"):
                self._error(addr, 0, "Unsupported mode", sock)
                return
            blk, timeout, oack = self._opts(opts, len(payload))
            sock.settimeout(timeout)
            self.on_event("info", f"TFTP: ارسال «{base}» ({len(payload)} بایت) به {addr[0]}")
            if oack:
                pkt = struct.pack("!H", OACK) + b"".join(k.encode() + b"\0" + v.encode() + b"\0" for k, v in oack.items())
                if not self._send_wait(sock, addr, pkt, 0):
                    rec["error"] = "no ACK for OACK"
                    return
            block, off = 1, 0
            while True:
                chunk = payload[off:off + blk]
                pkt = struct.pack("!HH", DATA, block & 0xFFFF) + chunk
                if not self._send_wait(sock, addr, pkt, block & 0xFFFF):
                    rec["error"] = f"timeout at block {block}"
                    self.on_event("error", f"TFTP: ارسال «{base}» به {addr[0]} در بلوک {block} قطع شد")
                    return
                off += len(chunk)
                rec["bytes"] = off
                if len(chunk) < blk:
                    break
                block += 1
            rec["ok"] = True
            self.on_event("ok", f"TFTP: «{base}» کامل به {addr[0]} ارسال شد")
        finally:
            rec["secs"] = round(time.time() - t0, 1)
            sock.close()

    def _send_wait(self, sock, addr, pkt, want, tries=6):
        base = sock.gettimeout() or 3.0
        for _ in range(tries):
            if self._stop.is_set():
                return False
            sock.sendto(pkt, addr)
            end = time.monotonic() + base      # بسته‌های بی‌ربط (آدرس دیگر/ACK اشتباه) مهلت را تمدید نمی‌کنند
            try:
                while True:
                    left = end - time.monotonic()
                    if left <= 0:
                        raise socket.timeout()
                    sock.settimeout(left)
                    d, a = sock.recvfrom(1024)
                    if a != addr or len(d) < 4:
                        continue
                    op, n = struct.unpack("!HH", d[:4])
                    if op == ACK and n == want:
                        return True
                    if op == ERROR:
                        return False
            except socket.timeout:
                continue
            finally:
                sock.settimeout(base)
        return False


def local_ip_for(host, port=22):
    """IP کارت شبکه‌ی این کامپیوتر که به سمت host مسیر دارد (بدون ارسال بسته)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((host, int(port)))
        return s.getsockname()[0]
    finally:
        s.close()
