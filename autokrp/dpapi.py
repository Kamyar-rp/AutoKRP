"""Windows DPAPI (CryptProtectData) با ctypes. خارج از ویندوز فقط برای Demo/تست صریح، بدون امنیت واقعی (b64)."""
import base64
import sys

AVAILABLE = sys.platform == "win32"

if AVAILABLE:
    import ctypes
    from ctypes import wintypes

    class _BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    _crypt32 = ctypes.windll.crypt32
    _kernel32 = ctypes.windll.kernel32

    def _blob(data: bytes):
        buf = ctypes.create_string_buffer(data, len(data))
        return _BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char))), buf

    def protect(data: bytes, machine=False) -> bytes:
        """machine=True: CRYPTPROTECT_LOCAL_MACHINE — هر فرآیندی روی همین سیستم باز می‌کند (فقط همراه ACL فایل)؛
        لازم برای تسک S4U که کلید DPAPI کاربر را ندارد (ورود بدون رمز)."""
        src, _keep = _blob(data)
        out = _BLOB()
        if not _crypt32.CryptProtectData(ctypes.byref(src), "AutoKRP", None, None, None, 0x01 | (0x04 if machine else 0), ctypes.byref(out)):
            raise OSError("CryptProtectData failed")
        try:
            return ctypes.string_at(out.pbData, out.cbData)
        finally:
            _kernel32.LocalFree(out.pbData)

    def unprotect(data: bytes) -> bytes:
        src, _keep = _blob(data)
        out = _BLOB()
        if not _crypt32.CryptUnprotectData(ctypes.byref(src), None, None, None, None, 0x01, ctypes.byref(out)):
            raise OSError("CryptUnprotectData failed")
        try:
            return ctypes.string_at(out.pbData, out.cbData)
        finally:
            _kernel32.LocalFree(out.pbData)
else:
    # خارج از ویندوز DPAPI نیست. این جایگزین (Base64) رمزنگاری نیست و فقط در Demo یا تست صریح
    # (متغیر محیطی AUTOKRP_INSECURE_TEST=1) مجاز است؛ وگرنه خطا، تا هیچ‌وقت داده‌ی واقعی بی‌حفاظت ذخیره نشود.
    _TAG = b"NODPAPI:"

    def _allowed():
        import os
        from . import paths
        if paths.is_demo() or os.environ.get("AUTOKRP_INSECURE_TEST") == "1":
            return
        raise OSError("DPAPI فقط در ویندوز وجود دارد؛ حالت کلاینت فقط روی ویندوز پشتیبانی می‌شود "
                      "(در سیستم‌های دیگر از حالت سرور استفاده کنید).")

    def protect(data: bytes, machine=False) -> bytes:
        _allowed()
        return _TAG + base64.b64encode(data)

    def unprotect(data: bytes) -> bytes:
        _allowed()
        if not data.startswith(_TAG):
            raise OSError("not a test blob")
        return base64.b64decode(data[len(_TAG):])
