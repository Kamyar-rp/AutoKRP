#!/usr/bin/env python3
"""
سرور Telnet آزمایشی (فقط برای تست توسعه): مذاکره‌ی گزینه‌ها (ECHO، SGA، NAWS، TTYPE)، Username/Password و
همان shell شبیه Cisco IOS در fake_ssh.py.
اجرا: python dev/fake_telnet.py 2323     یوزر: admin  پسورد: P@ssw0rd  enable: En@ble1
"""
import socket
import struct
import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fake_ssh import PASSWORD, USER, cisco_shell  # noqa: E402

IAC, DONT, DO, WONT, WILL, SB, SE = 255, 254, 253, 252, 251, 250, 240
ECHO, SGA, TTYPE, NAWS = 1, 3, 24, 31
INFO = {}


class Chan:
    """سوکت با حذف فرمان‌های IAC کلاینت (برای cisco_shell)."""

    def __init__(self, sock):
        self.sock, self.pend = sock, b""

    def sendall(self, b):
        self.sock.sendall(b.replace(b"\xff", b"\xff\xff"))

    send = sendall

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass

    def recv(self, n):
        while True:
            d = self.sock.recv(n)
            if not d:
                return b""
            out = self._strip(self.pend + d)
            out = out.replace(b"\r\n", b"\r").replace(b"\r\x00", b"\r")
            if out:
                return out

    def _strip(self, buf):
        out, i = bytearray(), 0
        self.pend = b""
        while i < len(buf):
            if buf[i] != IAC:
                out.append(buf[i])
                i += 1
                continue
            if i + 1 >= len(buf):
                self.pend = buf[i:]
                break
            c = buf[i + 1]
            if c == IAC:
                out.append(IAC)
                i += 2
            elif c in (DO, DONT, WILL, WONT):
                if i + 2 >= len(buf):
                    self.pend = buf[i:]
                    break
                INFO.setdefault("neg", []).append((c, buf[i + 2]))
                i += 3
            elif c == SB:
                e = buf.find(bytes([IAC, SE]), i)
                if e < 0:
                    self.pend = buf[i:]
                    break
                body = buf[i + 2:e]
                if body[:1] == bytes([NAWS]) and len(body) >= 5:
                    INFO["naws"] = struct.unpack(">HH", body[1:5])
                    print("NAWS", INFO["naws"], flush=True)
                if body[:2] == bytes([TTYPE, 0]):
                    INFO["ttype"] = body[2:].decode()
                    print("TTYPE", INFO["ttype"], flush=True)
                i = e + 2
            else:
                i += 2
        return bytes(out)

    def readline(self, echo=True):
        line = b""
        while True:
            d = self.recv(1)
            if not d:
                return None
            if d in (b"\n", b"\x00") and not line:
                continue                   # باقی‌مانده‌ی CR LF / CR NUL خط قبل
            if d in (b"\r", b"\n"):
                if echo:
                    self.sendall(b"\r\n")
                return line.decode(errors="replace")
            line += d
            if echo:
                self.sendall(d)


def handle(sock):
    ch = Chan(sock)
    sock.sendall(bytes([IAC, WILL, ECHO, IAC, WILL, SGA, IAC, DO, NAWS, IAC, DO, TTYPE]))
    sock.sendall(bytes([IAC, SB, TTYPE, 1, IAC, SE]))
    sock.sendall(b"\r\nUser Access Verification\r\n\r\nUsername: ")
    u = ch.readline()
    sock.sendall(b"Password: ")
    p = ch.readline(echo=False)
    print("LOGIN", u, "ok" if (u, p) == (USER, PASSWORD) else "BAD", flush=True)
    if (u, p) != (USER, PASSWORD):
        sock.sendall(b"\r\n% Authentication failed\r\n")
        ch.close()
        return
    try:
        cisco_shell(ch)
    except Exception as e:
        print("ERR", e, flush=True)
    finally:
        ch.close()


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 2323
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port))
    s.listen(20)
    print(f"telnet listening {port}", flush=True)
    while True:
        c, _ = s.accept()
        threading.Thread(target=handle, args=(c,), daemon=True).start()


if __name__ == "__main__":
    main()
