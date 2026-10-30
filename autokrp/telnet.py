"""
کلاینت Telnet کوچک برای ترمینال زنده (telnetlib از پایتون 3.13 حذف شده است).

- فقط مذاکره‌ی گزینه‌های لازم (RFC 854/855): ECHO و SGA از سمت دستگاه، NAWS (اندازه‌ی پنجره، RFC 1073)
  و TTYPE (نوع ترمینال، RFC 1091) از سمت ما؛ بقیه رد می‌شوند.
- Telnet رمزنگاری ندارد؛ رمز و همه‌ی متن‌ها روی شبکه خوانا هستند (رابط هشدار می‌دهد).
"""
import socket
import struct
import threading

IAC, DONT, DO, WONT, WILL, SB, SE = 255, 254, 253, 252, 251, 250, 240
ECHO, SGA, TTYPE, NAWS = 1, 3, 24, 31
WE_DO = {NAWS, TTYPE, SGA}          # گزینه‌هایی که خودمان قبول می‌کنیم (WILL)
THEY_DO = {ECHO, SGA}               # گزینه‌هایی که از دستگاه می‌پذیریم (DO)
TERM_TYPE = b"XTERM-256COLOR"
MAX_SB = 4096


class TelnetConn:
    """سوکت Telnet: recv داده‌ی خالص (بدون فرمان‌های IAC) برمی‌گرداند؛ send داده را escape می‌کند."""

    def __init__(self, sock, cols=80, rows=24):
        self.sock = sock
        self.cols, self.rows = cols, rows
        self._pend = b""             # فرمان IAC نیمه‌کاره از تکه‌ی قبلی
        self._naws = False           # دستگاه NAWS را خواسته است
        self._sent = {}              # آخرین پاسخ ما به هر (نوع، گزینه) تا حلقه‌ی مذاکره نسازیم
        self._wlock = threading.Lock()
        self.sock.settimeout(0.5)

    @classmethod
    def connect(cls, host, port, timeout=15, attempt=None, cols=80, rows=24):
        sock = attempt.connect(host, port, timeout) if attempt else socket.create_connection((host, port), timeout)
        return cls(sock, cols, rows)

    # ------------------------------------------------------------------ نوشتن
    def _raw(self, data):
        with self._wlock:
            self.sock.sendall(data)

    def _reply(self, cmd, opt):
        if self._sent.get(opt, (None,))[0] == cmd:
            return                    # همین پاسخ قبلاً داده شده
        self._sent[opt] = (cmd,)
        self._raw(bytes([IAC, cmd, opt]))

    def send(self, data):
        """ورودی کاربر: 0xFF دوبار؛ Enter (CR تنها) ← CR LF مثل PuTTY (پیش‌فرض «Telnet New Line»)."""
        data = data.replace(b"\xff", b"\xff\xff")
        out, i = bytearray(), 0
        while i < len(data):
            b = data[i]
            out.append(b)
            if b == 13 and (i + 1 >= len(data) or data[i + 1] not in (10, 0)):
                out.append(10)
            i += 1
        self._raw(bytes(out))

    sendall = send

    def resize(self, cols, rows):
        self.cols, self.rows = int(cols), int(rows)
        if self._naws:
            self._send_naws()

    def _send_naws(self):
        body = struct.pack(">HH", max(1, min(self.cols, 65535)), max(1, min(self.rows, 65535))).replace(b"\xff", b"\xff\xff")
        self._raw(bytes([IAC, SB, NAWS]) + body + bytes([IAC, SE]))

    # ------------------------------------------------------------------ خواندن
    def recv(self, n=65536):
        """داده‌ی خالص؛ b"" = اتصال بسته شد؛ TimeoutError = داده‌ای نرسید."""
        try:
            chunk = self.sock.recv(n)
        except socket.timeout:
            raise TimeoutError("timed out")
        if not chunk:
            return b""
        return self._parse(self._pend + chunk)

    def _parse(self, buf):
        out = bytearray()
        i, L = 0, len(buf)
        self._pend = b""
        while i < L:
            b = buf[i]
            if b != IAC:
                out.append(b)
                i += 1
                continue
            if i + 1 >= L:
                self._pend = buf[i:]
                break
            c = buf[i + 1]
            if c == IAC:
                out.append(IAC)
                i += 2
            elif c in (DO, DONT, WILL, WONT):
                if i + 2 >= L:
                    self._pend = buf[i:]
                    break
                self._negotiate(c, buf[i + 2])
                i += 3
            elif c == SB:
                end = buf.find(bytes([IAC, SE]), i + 2)
                if end < 0:
                    if L - i > MAX_SB:            # زیرمذاکره‌ی بی‌پایان: دور ریخته می‌شود
                        i = L
                    else:
                        self._pend = buf[i:]
                    break
                self._sub(buf[i + 2:end])
                i = end + 2
            else:
                i += 2                            # NOP، GA، AYT و … نادیده
        return bytes(out)

    def _negotiate(self, cmd, opt):
        if cmd == DO:
            if opt in WE_DO:
                self._reply(WILL, opt)
                if opt == NAWS:
                    self._naws = True
                    self._send_naws()
            else:
                self._reply(WONT, opt)
        elif cmd == DONT:
            if opt == NAWS:
                self._naws = False
            self._reply(WONT, opt)
        elif cmd == WILL:
            self._reply(DO if opt in THEY_DO else DONT, opt)
        elif cmd == WONT:
            self._reply(DONT, opt)

    def _sub(self, body):
        body = body.replace(b"\xff\xff", b"\xff")
        if len(body) >= 2 and body[0] == TTYPE and body[1] == 1:          # SEND
            self._raw(bytes([IAC, SB, TTYPE, 0]) + TERM_TYPE + bytes([IAC, SE]))

    def close(self):
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass
