"""اتصال قابل لغو: کاربر وسط «در حال اتصال» (آدرس اشتباه، دستگاه خاموش) می‌تواند فوراً لغو کند.

Attempt سوکت‌های TCP یک تلاش اتصال را خودش می‌سازد و نگه می‌دارد:
- اتصال TCP غیرمسدود با select در گام‌های کوتاه انجام می‌شود تا لغو در کمتر از ۰.۲ ثانیه اثر کند
  (بستن سوکت از ترد دیگر در لینوکس connect مسدود را قطع نمی‌کند).
- پس از وصل شدن، لغو سوکت را shutdown/close می‌کند؛ هر خواندن در جریان (handshake SSH، پاسخ FTP) فوراً خطا می‌دهد.
سوکت ساخته‌شده به paramiko (sock=)، netmiko (sock=) و ftplib (connect بازنویسی‌شده) داده می‌شود.
"""
import ftplib  # nosec B402 — FTP به درخواست کاربر برای تجهیزات قدیمی (مثل xfer.py)؛ FTPS هم هست
import os
import select
import socket
import threading
import errno
import time

_PENDING = {errno.EINPROGRESS, errno.EWOULDBLOCK, errno.EAGAIN, errno.EALREADY, 10035}   # 10035 = WSAEWOULDBLOCK
CANCEL_MSG = "اتصال توسط کاربر لغو شد."


class Aborted(Exception):
    pass


class Attempt:
    def __init__(self):
        self.cancelled = False
        self.created = time.time()
        self._socks = []
        self._lock = threading.Lock()

    def check(self):
        if self.cancelled:
            raise Aborted(CANCEL_MSG)

    def cancel(self):
        with self._lock:
            self.cancelled = True
            socks, self._socks = self._socks, []
        for s in socks:
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                s.close()
            except OSError:
                pass

    def track(self, s):
        """سوکت تازه‌ای که جای قبلی را گرفته (مثلاً پس از TLS) هم با لغو بسته شود."""
        with self._lock:
            if not self.cancelled:
                self._socks.append(s)
                return
        try:
            s.close()
        except OSError:
            pass
        raise Aborted(CANCEL_MSG)

    def release(self, s):
        """سوکتی که دیگر مال اتصال برقرارشده است (بعد از موفقیت) از فهرست لغو خارج می‌شود."""
        with self._lock:
            if s in self._socks:
                self._socks.remove(s)

    def connect(self, host, port, timeout=15):
        """مثل socket.create_connection ولی قابل لغو."""
        self.check()
        infos = socket.getaddrinfo(host, int(port), 0, socket.SOCK_STREAM)
        self.check()
        last = None
        for af, st, proto, _cn, sa in infos:
            s = socket.socket(af, st, proto)
            with self._lock:
                if self.cancelled:
                    s.close()
                    raise Aborted(CANCEL_MSG)
                self._socks.append(s)
            try:
                s.setblocking(False)
                err = s.connect_ex(sa)
                if err and err not in _PENDING:
                    raise OSError(err, os.strerror(err))
                deadline = time.monotonic() + float(timeout)
                while err:
                    if self.cancelled:
                        raise Aborted(CANCEL_MSG)
                    left = deadline - time.monotonic()
                    if left <= 0:
                        raise socket.timeout("timed out")
                    _r, w, x = select.select([], [s], [s], min(0.2, left))
                    if w or x:
                        err = s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                        if err:
                            raise OSError(err, os.strerror(err))
                        break
                self.check()
                s.setblocking(True)
                s.settimeout(timeout)
                return s
            except Aborted:
                self._drop(s)
                raise
            except OSError as e:
                self._drop(s)
                if self.cancelled:
                    raise Aborted(CANCEL_MSG)
                last = e
        raise last or OSError("آدرس پیدا نشد")

    def _drop(self, s):
        self.release(s)
        try:
            s.close()
        except OSError:
            pass


def ftp_class(attempt, tls=False):
    """کلاس FTP/FTP_TLS که سوکت کنترل را از Attempt می‌گیرد (همان کار connect اصلی ftplib)."""
    base = ftplib.FTP_TLS if tls else ftplib.FTP

    class _FTP(base):  # nosec B321 — پروتکل انتخاب صریح کاربر است (هشدار در رابط)
        def connect(self, host="", port=0, timeout=-999, source_address=None):
            if host:
                self.host = host
            if port > 0:
                self.port = port
            if timeout != -999:
                self.timeout = timeout
            self.sock = attempt.connect(self.host, self.port, self.timeout or 20)
            self.af = self.sock.family
            self.file = self.sock.makefile("r", encoding=self.encoding)
            self.welcome = self.getresp()
            return self.welcome

        if tls:
            def auth(self):
                r = super().auth()
                attempt.track(self.sock)
                return r
    return _FTP


class Registry:
    """تلاش‌های در جریان هر کاربر با شناسه‌ای که مرورگر می‌سازد. لغوِ پیش از رسیدن درخواست اتصال هم ثبت می‌شود."""

    def __init__(self):
        self._lock = threading.Lock()
        self._items = {}

    @staticmethod
    def _key(owner, aid):
        aid = str(aid or "")
        if not aid or len(aid) > 64 or not all(c.isalnum() or c in "-_" for c in aid):
            return None
        return (owner or "", aid)

    def _prune(self):
        now = time.time()
        for k in [k for k, a in self._items.items() if now - a.created > 600]:
            self._items.pop(k, None)

    def begin(self, owner, aid):
        k = self._key(owner, aid)
        if k is None:
            return Attempt()
        with self._lock:
            self._prune()
            a = self._items.get(k)
            if a is None:
                a = self._items[k] = Attempt()
        a.check()
        return a

    def end(self, owner, aid):
        k = self._key(owner, aid)
        if k is not None:
            with self._lock:
                a = self._items.get(k)
                if a is not None and not a.cancelled:
                    self._items.pop(k, None)

    def cancel(self, owner, aid):
        k = self._key(owner, aid)
        if k is None:
            return False
        with self._lock:
            self._prune()
            a = self._items.get(k)
            if a is None:
                a = self._items[k] = Attempt()
        a.cancel()
        return True
