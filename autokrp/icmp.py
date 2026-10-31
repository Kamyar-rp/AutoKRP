"""
Ping بومی ویندوز (1.34) با IcmpSendEcho از iphlpapi.dll: بدون اجرای ping.exe برای هر بررسی و بدون نیاز به دسترسی ادمین
(همان API که خود ping.exe استفاده می‌کند). فقط IPv4؛ IPv6 و هر خطا ← روش قبلی (ping.exe).
"""
import ctypes
import os
import socket
import threading

IP_SUCCESS = 0
_ERR_TEXT = {11002: "شبکه‌ی مقصد در دسترس نیست", 11003: "میزبان مقصد در دسترس نیست", 11010: "بدون پاسخ ping",
             11013: "TTL تمام شد (مسیر حلقه دارد؟)", 11050: "خطای کلی ICMP"}
_lib = None
_lib_lock = threading.Lock()


class _OPT(ctypes.Structure):
    _fields_ = [("Ttl", ctypes.c_ubyte), ("Tos", ctypes.c_ubyte), ("Flags", ctypes.c_ubyte), ("OptionsSize", ctypes.c_ubyte),
                ("OptionsData", ctypes.c_void_p)]


class ICMP_ECHO_REPLY(ctypes.Structure):
    _fields_ = [("Address", ctypes.c_uint32), ("Status", ctypes.c_uint32), ("RoundTripTime", ctypes.c_uint32),
                ("DataSize", ctypes.c_uint16), ("Reserved", ctypes.c_uint16), ("Data", ctypes.c_void_p), ("Options", _OPT)]


def available():
    return os.name == "nt" and _load() is not None


def _load():
    global _lib
    if os.name != "nt":
        return None
    with _lib_lock:
        if _lib is None:
            try:
                from ctypes import wintypes as W
                lib = ctypes.WinDLL("iphlpapi.dll", use_last_error=True)
                lib.IcmpCreateFile.restype = W.HANDLE
                lib.IcmpCreateFile.argtypes = []
                lib.IcmpCloseHandle.argtypes = [W.HANDLE]
                lib.IcmpCloseHandle.restype = W.BOOL
                lib.IcmpSendEcho.argtypes = [W.HANDLE, ctypes.c_uint32, ctypes.c_void_p, W.WORD, ctypes.c_void_p,
                                             ctypes.c_void_p, W.DWORD, W.DWORD]
                lib.IcmpSendEcho.restype = W.DWORD
                _lib = lib
            except Exception:  # noqa — نبود API: روش قبلی
                _lib = False
        return _lib or None


def ipv4(host):
    """آدرس IPv4 (رشته) یا None (IPv6، نام بدون IPv4، خطا)."""
    try:
        socket.inet_aton(host)
        if host.count(".") == 3:
            return host
    except OSError:
        pass
    if ":" in host:
        return None
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET)
        return infos[0][4][0] if infos else None
    except OSError:
        return None


def addr_value(ip):
    """IPAddr ویندوز: ترتیب بایت شبکه، خوانده‌شده به‌صورت ULONG (مثل inet_addr)."""
    return int.from_bytes(socket.inet_aton(ip), "little")


def ping(host, timeout):
    """(ok، rtt میلی‌ثانیه، خطا) یا None یعنی «با روش قبلی امتحان کن»."""
    lib = _load()
    if lib is None:
        return None
    ip = ipv4(host)
    if ip is None:
        return None
    h = lib.IcmpCreateFile()
    if not h or h == ctypes.c_void_p(-1).value:
        return None
    try:
        data = b"AutoKRP-ping-0123456789abcdef"[:32]
        size = ctypes.sizeof(ICMP_ECHO_REPLY) + len(data) + 8 + 16
        buf = ctypes.create_string_buffer(size)
        n = lib.IcmpSendEcho(h, addr_value(ip), data, len(data), None, buf, size, max(100, int(timeout * 1000)))
        if not n:
            err = ctypes.get_last_error()
            return False, None, _ERR_TEXT.get(err, "بدون پاسخ ping")
        r = ICMP_ECHO_REPLY.from_buffer_copy(buf)
        if r.Status != IP_SUCCESS:
            return False, None, _ERR_TEXT.get(r.Status, f"بدون پاسخ ping ({r.Status})")
        return True, float(r.RoundTripTime) if r.RoundTripTime else 1.0, ""     # مثل ping.exe: «<1ms» = ۱
    finally:
        lib.IcmpCloseHandle(h)
