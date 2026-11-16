"""ویرایشگر متن انتقال فایل: خواندن/نوشتن فایل متنی روی سرور (SFTP/FTP/SCP) + نسخه‌های قبلی اختیاری.

- خواندن از همان reader/writer اتصال انتقال فایل (کانال جدا، مهلت‌دار).
- تشخیص باینری (بایت NUL در ۸KB اول)، کدگذاری (UTF-8 / UTF-8 BOM / Latin-1) و پایان خط غالب.
- تشخیص تغییر هم‌زمان: هنگام ذخیره، محتوای فعلی سرور دوباره خوانده و hash آن با hash زمان باز کردن مقایسه می‌شود.
- نسخه‌ی قبلی (فقط اگر کاربر بخواهد) رمزشده با کلید vault در data_dir/edit_versions؛ ۵ نسخه‌ی آخر هر فایل.
"""
import hashlib
import json
import time

from . import paths

MAX_TEXT = 5 * 1024 * 1024
KEEP = 5


class EditError(Exception):
    pass


def _slurp(conn, path, limit=MAX_TEXT):
    r = conn.reader(path)
    ok = False
    try:
        if getattr(r, "size", None) and r.size > limit:
            raise EditError(f"فایل بزرگ‌تر از {limit // (1024 * 1024)} مگابایت است و در ویرایشگر باز نمی‌شود.")
        buf = bytearray()
        while True:
            d = r.read(65536)
            if not d:
                break
            buf += d
            if len(buf) > limit:
                raise EditError(f"فایل بزرگ‌تر از {limit // (1024 * 1024)} مگابایت است و در ویرایشگر باز نمی‌شود.")
        ok = True
        return bytes(buf)
    finally:
        try:
            if ok:
                r.close(True)
            else:
                r.abort()
        except Exception:  # nosec B110 — بستن کانال خواندن؛ خطای بستن مهم نیست
            pass


def decode(data: bytes):
    if b"\x00" in data[:8192]:
        raise EditError("این فایل متنی نیست (باینری است) و در ویرایشگر باز نمی‌شود.")
    if data.startswith(b"\xef\xbb\xbf"):
        enc, text = "utf-8-sig", data[3:].decode("utf-8", "replace")
    else:
        try:
            enc, text = "utf-8", data.decode("utf-8")
        except UnicodeDecodeError:
            enc, text = "latin-1", data.decode("latin-1")
    crlf = text.count("\r\n")
    lf = text.count("\n") - crlf
    eol = "CRLF" if crlf > lf else "LF"
    return text.replace("\r\n", "\n"), enc, eol, (crlf > 0 and lf > 0)


def encode(text: str, enc: str, eol: str) -> bytes:
    text = str(text).replace("\r\n", "\n").replace("\r", "\n")
    if eol == "CRLF":
        text = text.replace("\n", "\r\n")
    if enc == "utf-8-sig":
        return b"\xef\xbb\xbf" + text.encode("utf-8")
    if enc == "latin-1":
        try:
            return text.encode("latin-1")
        except UnicodeEncodeError:
            raise EditError("متن نویسه‌هایی دارد که در کدگذاری Latin-1 نیست؛ کدگذاری را UTF-8 کنید.")
    return text.encode("utf-8")


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read(conn, path):
    data = _slurp(conn, path)
    text, enc, eol, mixed = decode(data)
    return {"path": path, "text": text, "enc": enc, "eol": eol, "mixed": mixed, "size": len(data), "hash": sha(data)}


def write(conn, path, text, enc, eol, expect_hash=None, force=False):
    """خروجی: (bytes قبلی یا None، bytes جدید)."""
    if enc not in ("utf-8", "utf-8-sig", "latin-1"):
        enc = "utf-8"
    eol = "CRLF" if eol == "CRLF" else "LF"
    new = encode(text, enc, eol)
    if len(new) > MAX_TEXT:
        raise EditError("متن بزرگ‌تر از ۵ مگابایت است.")
    old = None
    try:
        old = _slurp(conn, path)
    except EditError:
        raise
    except Exception:
        old = None          # فایل حذف شده یا خواندنی نیست
    if not force and expect_hash and (old is None or sha(old) != expect_hash):
        return {"conflict": True, "gone": old is None}, None, None
    w = conn.writer(path, len(new))
    ok = False
    try:
        w.write(new)
        ok = True
    except Exception:
        try:
            w.abort()
        except Exception:
            pass
        raise
    finally:
        if ok:
            w.close(True)
    return {"size": len(new), "hash": sha(new)}, old, new


class Versions:
    """نسخه‌های قبلی فایل‌های ویرایش‌شده؛ رمزشده با کلید vault."""

    def __init__(self, vault):
        self.vault = vault
        self.root = paths.data_dir() / "edit_versions"

    def _dir(self, owner, key, path):
        h = hashlib.sha256(f"{owner}\x00{key}\x00{path}".encode("utf-8")).hexdigest()[:32]
        return self.root / h

    def add(self, owner, key, path, data: bytes, title=""):
        d = self._dir(owner, key, path)
        d.mkdir(parents=True, exist_ok=True)
        ts = time.time()
        name = f"{int(ts * 1000)}.bin"
        (d / name).write_bytes(self.vault.encrypt_bytes(data))
        meta = self._meta(d)
        meta.insert(0, {"id": name, "ts": int(ts), "size": len(data), "path": path, "title": title})
        for m in meta[KEEP:]:
            try:
                (d / m["id"]).unlink()
            except OSError:
                pass
        self._save_meta(d, meta[:KEEP])

    def _meta(self, d):
        f = d / "index.bin"
        if not f.is_file():
            return []
        try:
            return json.loads(self.vault.decrypt_bytes(f.read_bytes()).decode("utf-8"))
        except Exception:
            return []

    def _save_meta(self, d, meta):
        (d / "index.bin").write_bytes(self.vault.encrypt_bytes(json.dumps(meta).encode("utf-8")))

    def list(self, owner, key, path):
        return [{k: m[k] for k in ("id", "ts", "size")} for m in self._meta(self._dir(owner, key, path))]

    def get(self, owner, key, path, vid):
        d = self._dir(owner, key, path)
        ids = {m["id"] for m in self._meta(d)}
        if str(vid) not in ids:
            raise EditError("نسخه پیدا نشد.")
        data = self.vault.decrypt_bytes((d / str(vid)).read_bytes())
        return decode(data)[0]


def conn_key(conn):
    return f"{conn.proto}://{conn.creds.get('username', '')}@{conn.host}:{conn.port}"
