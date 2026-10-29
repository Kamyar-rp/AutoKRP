"""پایه‌ی مشترک کانکتورها: ساخت URL از آدرس+پورت، احراز هویت، session و پیام خطای فارسی."""
import hashlib
import logging
import socket
import ssl
import threading
from urllib.parse import urlsplit, urlunsplit

import requests
import urllib3
from requests.adapters import HTTPAdapter

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
log = logging.getLogger(__name__)


class ConnectorError(Exception):
    """خطای قابل نمایش به کاربر (پیام فارسی)."""


class Cancelled(Exception):
    pass


def build_base_url(address: str, port) -> str:
    address = (address or "").strip()
    if not address:
        raise ConnectorError("آدرس تنظیم نشده است. در صفحه‌ی تنظیمات آدرس را وارد کنید.")
    if "://" not in address:
        address = "https://" + address
    parts = urlsplit(address)
    if not parts.hostname:
        raise ConnectorError(f"آدرس معتبر نیست: {address}")
    netloc = parts.netloc
    port = str(port or "").strip()
    if port:
        if not port.isdigit() or not (0 < int(port) < 65536):
            raise ConnectorError(f"پورت معتبر نیست: {port}")
        host = parts.hostname
        if ":" in host:  # IPv6
            host = f"[{host}]"
        userinfo = netloc.rsplit("@", 1)[0] + "@" if "@" in netloc else ""
        netloc = f"{userinfo}{host}:{port}"
    return urlunsplit((parts.scheme, netloc, parts.path.rstrip("/"), parts.query, ""))


# ---------------------------------------------------------------- پین گواهی
# وقتی «بررسی گواهی SSL» خاموش است (مثل گواهی self-signed فورتی‌گیت)، اثر انگشت SHA-256 گواهی پین می‌شود و
# از آن به بعد هر گواهی دیگری رد می‌شود (مثل known_hosts در SSH). از 1.12.2 گواهی ناشناخته خودکار پین نمی‌شود:
# اثر انگشت به کاربر نشان داده می‌شود و فقط با تأیید صریح او (در «تست اتصال») ذخیره می‌شود.
# PIN_HOOK را برنامه تنظیم می‌کند: PIN_HOOK(conn_name, "host:port", sha256_hex)
PIN_HOOK = None
PIN_MISMATCH = "Fingerprints did not match"


def fetch_cert_sha256(host: str, port: int, timeout: float = 10) -> str:
    """اثر انگشت SHA-256 گواهی سرور (بدون اعتبارسنجی؛ فقط برای پین اولیه)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # nosec B502 — عمداً: فقط خواندن گواهی برای پین
    with socket.create_connection((host, port), timeout=timeout) as raw:
        with ctx.wrap_socket(raw, server_hostname=host) as tls:
            der = tls.getpeercert(binary_form=True)
    if not der:
        raise ConnectorError(f"گواهی سرور {host}:{port} دریافت نشد.")
    return hashlib.sha256(der).hexdigest()


def fmt_fp(fp: str) -> str:
    fp = (fp or "").upper()
    return ":".join(fp[i:i + 2] for i in range(0, len(fp), 2))


class PinUnconfirmed(ConnectorError):
    """گواهی سرور هنوز پین نشده و کاربر اثر انگشتش را تأیید نکرده است."""

    def __init__(self, hostport, fp):
        self.hostport, self.fp = hostport, fp
        super().__init__(f"گواهی {hostport} هنوز تأیید نشده است (SHA-256: {fmt_fp(fp)}). در «تنظیمات» همین اتصال "
                         "«تست اتصال» را بزنید، اثر انگشت را با گواهی خود سرور مقایسه و تأیید کنید.")


class _PinAdapter(HTTPAdapter):
    def __init__(self, fp, **kw):
        self._fp = fp
        super().__init__(**kw)

    def init_poolmanager(self, *a, **kw):
        kw["assert_fingerprint"] = self._fp
        return super().init_poolmanager(*a, **kw)


class _PinnedSession(requests.Session):
    """
    پیش از اولین درخواست به هر host:port، آداپتور پین را نصب می‌کند.
    verify جلسه همیشه اعمال می‌شود؛ در requests متغیر محیطی REQUESTS_CA_BUNDLE در غیر این صورت
    مقدار verify=False جلسه را بی‌صدا نادیده می‌گیرد.
    """
    pin_check = None
    auth_header = ""

    def rebuild_auth(self, prepared_request, response):
        """ریدایرکت به میزبان دیگر: هیچ اعتبارنامه‌ای (Authorization، هدر کلید API، کوکی) همراهش نمی‌رود."""
        super().rebuild_auth(prepared_request, response)
        old, new = urlsplit(response.request.url), urlsplit(prepared_request.url)
        if (old.hostname, old.port, old.scheme) != (new.hostname, new.port, new.scheme):
            for h in ("Authorization", "Cookie", self.auth_header):
                if h:
                    prepared_request.headers.pop(h, None)

    cancel_event = None

    def request(self, method, url, *a, **kw):
        kw.setdefault("verify", self.verify)
        if self.pin_check:
            self.pin_check(url)
        if self.cancel_event is None or getattr(_TL, "inner", False):
            return super().request(method, url, *a, **kw)
        # درخواست در ترد جدا؛ با «لغو» منتظر پایان timeout (تا ۱۰ دقیقه برای Splunk) نمی‌مانیم
        return run_cancellable(self.cancel_event, lambda: super(_PinnedSession, self).request(method, url, *a, **kw),
                               self, name="http")


_TL = threading.local()


def _shutdown_resp(resp):
    """بستن سوکت یک پاسخ جریانی از ترد دیگر (recv مسدود فوراً برمی‌گردد)."""
    try:
        conn = getattr(resp.raw, "_connection", None) or getattr(resp.raw, "connection", None)
        sock = getattr(conn, "sock", None)
        if sock is None:    # http.client پس از پاسخ «Connection: close» سوکت را فقط در fp نگه می‌دارد
            fp = getattr(getattr(resp.raw, "_fp", None), "fp", None)
            sock = getattr(getattr(fp, "raw", None), "_sock", None)
        if sock is not None:
            sock.shutdown(socket.SHUT_RDWR)
    except (OSError, AttributeError, ValueError):
        pass
    try:
        resp.close()
    except Exception:  # nosec B110 — بستن بهترین‌تلاش پس از لغو
        pass


def run_cancellable(cancel_event, fn, holder=None, name="io"):
    """
    fn را در ترد جدا اجرا می‌کند و هر ۰.۲ ثانیه لغو را بررسی می‌کند. با لغو، پاسخ جریانی ثبت‌شده در
    holder.live_resp بسته می‌شود و Cancelled فوراً برمی‌گردد؛ ترد رها‌شده با بسته شدن سوکت یا timeout تمام می‌شود.
    """
    if cancel_event.is_set():
        raise Cancelled()
    box = {}

    def work():
        _TL.inner = True
        try:
            box["r"] = fn()
        except BaseException as e:  # noqa — به ترد اصلی منتقل می‌شود
            box["e"] = e

    t = threading.Thread(target=work, name=f"cancellable-{name}", daemon=True)
    t.start()
    while t.is_alive():
        t.join(0.2)
        if t.is_alive() and cancel_event.is_set():
            r = getattr(holder, "live_resp", None)
            if r is not None:
                _shutdown_resp(r)
            raise Cancelled()
    if "e" in box:
        raise box["e"]
    return box.get("r")


def friendly_error(e: Exception) -> str:
    if isinstance(e, ConnectorError):
        return str(e)
    if isinstance(e, requests.exceptions.SSLError):
        if PIN_MISMATCH in str(e):
            return ("گواهی سرور با گواهی ذخیره‌شده (پین) فرق دارد. ممکن است کسی بین شما و سرور باشد (MITM)، "
                    "یا گواهی سرور عمداً عوض شده باشد. اگر از تعویض گواهی مطمئنید، در تنظیمات همین اتصال "
                    "«فراموش کردن گواهی» را بزنید و دوباره تست کنید.")
        return ("خطای گواهی SSL. بهتر است گواهی معتبر یا CA سازمان را روی سرور/ویندوز نصب کنید. اگر گواهی self-signed است، "
                "«بررسی گواهی SSL» را خاموش و «پین گواهی» را روشن کنید و اثر انگشت را در «تست اتصال» تأیید کنید.")
    if isinstance(e, requests.exceptions.ConnectTimeout):
        return "اتصال به سرور در زمان مقرر برقرار نشد (Timeout)."
    if isinstance(e, requests.exceptions.ReadTimeout):
        return "سرور در زمان مقرر پاسخ نداد (Timeout)."
    if isinstance(e, requests.exceptions.ConnectionError):
        return "اتصال به سرور برقرار نشد. آدرس، پورت و دسترسی شبکه را بررسی کنید."
    if isinstance(e, requests.exceptions.HTTPError) and e.response is not None:
        code = e.response.status_code
        body = (e.response.text or "")[:300]
        if code in (401, 403):
            return f"احراز هویت رد شد (HTTP {code}). توکن/رمز یا دسترسی کاربر را بررسی کنید."
        if code == 404:
            return f"مسیر API پیدا نشد (HTTP 404). آدرس را بررسی کنید. {body}"
        return f"خطای HTTP {code}: {body}"
    return f"خطای غیرمنتظره: {e}"


class BaseConnector:
    NAME = ""

    def __init__(self, cfg: dict, cancel_event: threading.Event | None = None):
        self.cfg = cfg
        if cfg.get("_conn"):            # 1.28: چند FortiGate — نام اتصال (برای پین گواهی هر دستگاه)
            self.NAME = str(cfg["_conn"])
        self.cancel_event = cancel_event or threading.Event()
        self.s = _PinnedSession()
        if cancel_event is not None:          # فقط اجراهای قابل لغو (ابزارها)؛ تست اتصال مثل قبل
            self.s.cancel_event = cancel_event
        self.s.verify = bool(cfg.get("verify_ssl", True))
        self._pinned = set()
        self.pin_note = ""
        if not self.s.verify and cfg.get("pin_cert"):   # اختیاری: پین گواهی وقتی بررسی CA خاموش است
            self.s.pin_check = self._pin_check
        self._apply_auth()

    def _pin_check(self, url):
        parts = urlsplit(url)
        if parts.scheme != "https" or not parts.hostname:
            return
        port = parts.port or 443
        hp = f"{parts.hostname}:{port}"
        if hp in self._pinned:
            return
        saved = self.cfg.get("cert_pin") or {}
        if saved.get("host") == hp and saved.get("sha256"):
            fp = saved["sha256"]
        else:
            try:
                fp = fetch_cert_sha256(parts.hostname, port, timeout=10)
            except (OSError, ssl.SSLError) as e:
                raise requests.exceptions.ConnectionError(str(e)) from e
            acc = self.cfg.get("_pin_accept") or {}
            if acc.get("host") != hp or acc.get("sha256") != fp:
                raise PinUnconfirmed(hp, fp)    # بدون تأیید صریح کاربر هیچ گواهی ناشناخته‌ای مورد اعتماد نمی‌شود
            if PIN_HOOK:
                PIN_HOOK(self.NAME, hp, fp)
            self.cfg["cert_pin"] = {"host": hp, "sha256": fp}
            self.pin_note = f"گواهی {hp} با تأیید کاربر پین شد (SHA-256: {fmt_fp(fp)[:23]}…)"
            log.warning("%s: %s", self.NAME, self.pin_note)
        self.s.mount(f"https://{parts.netloc}", _PinAdapter(fp))
        self._pinned.add(hp)

    def _apply_auth(self):
        t = self.cfg.get("auth_type", "bearer")
        token = self.cfg.get("token", "")
        if t == "bearer":
            if token:
                self.s.headers["Authorization"] = f"Bearer {token}"
        elif t == "basic":
            self.s.auth = (self.cfg.get("username", ""), self.cfg.get("password", ""))
        elif t == "header":
            name = (self.cfg.get("header_name") or "").strip()
            if name and token:
                self.s.headers[name] = token
                self.s.auth_header = name

    def require_credentials(self):
        t = self.cfg.get("auth_type", "bearer")
        if t == "basic":
            if not self.cfg.get("username") or not self.cfg.get("password"):
                raise ConnectorError("نام کاربری یا رمز عبور تنظیم نشده است.")
        elif not self.cfg.get("token"):
            raise ConnectorError("توکن / کلید API تنظیم نشده است.")

    def base_url(self) -> str:
        return build_base_url(self.cfg.get("address"), self.cfg.get("port"))

    def cancellable(self, fn):
        """اجرای یک کار شبکه‌ای طولانی (مثل خواندن جریانی) که با لغو فوراً رها شود."""
        return run_cancellable(self.cancel_event, fn, self.s, name=self.NAME)

    def check_cancel(self):
        if self.cancel_event.is_set():
            raise Cancelled()

    def sleep(self, seconds: float):
        """خواب قابل توقف."""
        if self.cancel_event.wait(max(0.0, seconds)):
            raise Cancelled()
