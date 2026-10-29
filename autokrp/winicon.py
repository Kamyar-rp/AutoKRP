"""تغییر آیکون پنجره و نوار وظیفه در زمان اجرا (ویندوز، WM_SETICON). روی ویندوز تست نشده است."""
import logging
import sys

log = logging.getLogger(__name__)


def apply_icon(window, ico_path):
    if sys.platform != "win32" or not ico_path:
        return False
    try:
        import ctypes
        user32 = ctypes.windll.user32
        user32.FindWindowW.restype = ctypes.c_void_p
        user32.LoadImageW.restype = ctypes.c_void_p
        user32.SendMessageW.argtypes = [ctypes.c_void_p, ctypes.c_uint, ctypes.c_void_p, ctypes.c_void_p]
        hwnd = user32.FindWindowW(None, window.title)
        if not hwnd:
            return False
        IMAGE_ICON, LR_LOADFROMFILE, WM_SETICON = 1, 0x10, 0x80
        big = user32.LoadImageW(None, ico_path, IMAGE_ICON, 32, 32, LR_LOADFROMFILE)
        small = user32.LoadImageW(None, ico_path, IMAGE_ICON, 16, 16, LR_LOADFROMFILE)
        if big:
            user32.SendMessageW(hwnd, WM_SETICON, 1, big)
        if small:
            user32.SendMessageW(hwnd, WM_SETICON, 0, small)
        return bool(big or small)
    except Exception:
        log.exception("تغییر آیکون پنجره ناموفق بود")
        return False
