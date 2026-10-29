"""
اعلان ایمیلی (SMTP).

امنیت اتصال: starttls (معمولاً پورت ۵۸۷)، ssl (معمولاً ۴۶۵) یا none (relay داخلی، معمولاً ۲۵).
پسورد در vault است. در ایمیل هیچ توکن یا پسوردی نوشته نمی‌شود.
جلوگیری از ایمیل پشت‌سرهم: اولین رخداد هر نوع فوری ارسال می‌شود؛ رخدادهای بعدی تا پایان بازه‌ی
throttle_minutes جمع و در یک ایمیل خلاصه ارسال می‌شوند.
ارسال در ترد جدا انجام می‌شود؛ خطای ایمیل هرگز کار اصلی را متوقف نمی‌کند.
"""
import json
import logging
import re
import smtplib
import socket
import ssl
import threading
import time
from email.message import EmailMessage
from email.utils import formataddr, formatdate, make_msgid

from . import APP_NAME, paths

log = logging.getLogger(__name__)

EVENTS = ("approval", "run_error", "ban_failed", "ssh_failed", "backup_failed", "config_changed", "abuse_quota", "scan_new",
          "mon_down", "mon_up", "mon_alarm", "asset_change", "abuse_repeat", "health", "dev_event")
TITLES = {
    "fa": {"approval": "اجرا منتظر تأیید شماست", "run_error": "خطا در اجرای زنجیره", "ban_failed": "بلاک ناموفق در FortiGate",
           "ssh_failed": "اجرای SSH ناموفق", "backup_failed": "پشتیبان‌گیری کانفیگ ناموفق", "config_changed": "کانفیگ دستگاه تغییر کرد",
           "abuse_quota": "سهمیه‌ی روزانه‌ی AbuseIPDB تمام شد", "scan_new": "اسکن شبکه: هاست یا پورت تازه", "mon_down": "مانیتورینگ: قطعی", "mon_up": "مانیتورینگ: وصل شد", "mon_alarm": "مانیتورینگ SNMP: هشدار آستانه", "asset_change": "مدیریت دارایی: تغییر منتظر تأیید", "abuse_repeat": "IP غیرمخرب تکراری: نیاز به بررسی مجدد", "health": "سلامت سرور: فضای دیسک، RAM یا CPU", "dev_event": "رخداد بحرانی دستگاه (Trap یا Syslog)", "test": "ایمیل آزمایشی", "summary": "رویداد", "more": "رویداد دیگر از همین نوع در {0} دقیقه‌ی گذشته",
           "footer": "این ایمیل خودکار از {0} روی {1} ارسال شده است."},
    "en": {"approval": "A run is waiting for your approval", "run_error": "Pipeline run error", "ban_failed": "FortiGate block failed",
           "ssh_failed": "SSH run failed", "backup_failed": "Config backup failed", "config_changed": "Device configuration changed",
           "abuse_quota": "AbuseIPDB daily quota exhausted", "scan_new": "Network scan: new host or port", "mon_down": "Monitoring: target down", "mon_up": "Monitoring: target back up", "mon_alarm": "SNMP monitoring: threshold alarm", "asset_change": "Asset management: change awaiting approval", "abuse_repeat": "Repeated clean IP: needs another review", "health": "Server health: disk space, RAM or CPU", "dev_event": "Critical device event (Trap or Syslog)", "test": "Test email", "summary": "events", "more": "more events of this type in the last {0} minutes",
           "footer": "This email was sent automatically by {0} on {1}."},
}


class NotifyError(Exception):
    pass


# ------------------------------------------------------------------ ترجمه‌ی جزئیات پیام برای ایمیل انگلیسی
_DICT = None


def _load_dict():
    global _DICT
    if _DICT is None:
        _DICT = {"exact": {}, "pats": []}
        try:
            raw = (paths.ui_dir() / "i18n_en.js").read_text(encoding="utf-8")
            d = json.loads(raw[raw.index("{"):raw.rindex("}") + 1])
            inv = re.compile(r"[\u200e\u200f\u2066-\u2069]")
            for fa, en in d.items():
                k = re.sub(r"\s+", " ", inv.sub("", fa)).strip()
                if "{" not in k:
                    _DICT["exact"][k] = en
                    continue
                parts, idx, rx = re.split(r"(\{\d+\})", k), [], "^"
                for p in parts:
                    m = re.fullmatch(r"\{(\d+)\}", p)
                    if m:
                        rx += r"(.*?)"
                        idx.append(int(m.group(1)))
                    else:
                        rx += re.escape(p)
                _DICT["pats"].append((re.compile(rx + "$", re.S), en, idx, len(re.sub(r"\{\d+\}", "", k))))
            _DICT["pats"].sort(key=lambda x: -x[3])
        except Exception:
            log.exception("واژه‌نامه‌ی انگلیسی برای ایمیل بارگذاری نشد")
    return _DICT


def tr(s, depth=0):
    if not s or not re.search(r"[\u0600-\u06FF]", s) or depth > 4:
        return s
    d = _load_dict()
    k = re.sub(r"\s+", " ", re.sub(r"[\u200e\u200f\u2066-\u2069]", "", s)).strip()
    if k in d["exact"]:
        return d["exact"][k]
    fa_word = re.compile(r"[\u0600-\u06FF]+")
    for rx, en, idx, fixed in d["pats"]:
        m = rx.match(k)
        if not m:
            continue
        caps = m.groups()
        # همان محافظ رابط: مقدار نباید مرز جمله را بپوشاند و الگوی کوتاه جمله‌ی کامل را نگیرد
        if any(fa_word.search(v) and re.search(r"[.!؟?]\s+\S", v) for v in caps):
            continue
        if fixed < 9 and any(len(fa_word.findall(v)) > 2 for v in caps):
            continue
        return re.sub(r"\{(\d+)\}", lambda g: tr(caps[idx.index(int(g.group(1)))], depth + 1), en)
    for sep in (" — ", "؛ ", "، ", ": "):
        if sep in k:
            parts = k.split(sep)
            out = [tr(p, depth + 1) for p in parts]
            if out != parts:
                return {"؛ ": "; ", "، ": ", "}.get(sep, sep).join(out)
    return s


# ------------------------------------------------------------------ notifier
class Notifier:
    def __init__(self, settings, vault, emit=None):
        self.settings = settings
        self.vault = vault
        self._emit = emit or (lambda *a, **k: None)
        self._lock = threading.Lock()
        self._last = {}       # event → زمان آخرین ارسال
        self._pending = {}    # event → [(ts, text)]

    def cfg(self, override=None):
        c = self.settings.conn_config("notify", override or {})
        if override and "events" in override:
            c["events"] = {**(c.get("events") or {}), **override["events"]}
        return c

    def lang(self):
        return "en" if (self.settings.get("ui", "lang") or "en") == "en" else "fa"

    # ---------------------------------------------------------------- API داخلی
    def notify(self, event, text):
        """از هر جای برنامه صدا زده می‌شود؛ هرگز استثنا بیرون نمی‌دهد."""
        try:
            c = self.cfg()
            if not c.get("enabled") or not (c.get("events") or {}).get(event) or not c.get("host") or not c.get("to"):
                return
            if self.vault is not None and not self.vault.unlocked() and c.get("username"):
                return
            now = time.time()
            win = max(1, int(c.get("throttle_minutes") or 15)) * 60
            with self._lock:
                last = self._last.get(event, 0)
                if now - last >= win and not self._pending.get(event):
                    self._last[event] = now
                    items = [(now, text)]
                else:
                    self._pending.setdefault(event, []).append((now, text))
                    return
            threading.Thread(target=self._send_safe, args=(event, items), daemon=True, name="notify").start()
        except Exception:
            log.exception("notify")

    def flush(self):
        """صدا زده‌شده از ترد پس‌زمینه: ارسال رخدادهای جمع‌شده که بازه‌شان تمام شده است."""
        try:
            c = self.cfg()
            win = max(1, int(c.get("throttle_minutes") or 15)) * 60
            now = time.time()
            due = []
            with self._lock:
                for ev, items in list(self._pending.items()):
                    if items and now - self._last.get(ev, 0) >= win:
                        due.append((ev, items))
                        self._pending[ev] = []
                        self._last[ev] = now
            ok = c.get("enabled") and c.get("host") and c.get("to")
            for ev, items in due:            # اگر در این فاصله اعلان یا همین رویداد خاموش شد، چیزی فرستاده نمی‌شود
                if ok and (c.get("events") or {}).get(ev):
                    self._send_safe(ev, items)
        except Exception:
            log.exception("notify flush")

    def _send_safe(self, event, items):
        try:
            self.send(event, items)
        except Exception as e:
            msg = e.args[0] if isinstance(e, NotifyError) else friendly(e)
            self._emit("error", f"ارسال ایمیل ناموفق بود: {msg}", "notify")

    # ---------------------------------------------------------------- ساخت و ارسال
    def compose(self, event, items, c):
        L = self.lang()
        T = TITLES[L]
        title = T.get(event, event)
        app = (self.settings.get("branding", "app_name") or APP_NAME)
        subject = f"[{app}] {title}" + (f" ({len(items)} {T['summary']})" if len(items) > 1 else "")
        lines = [title, "=" * min(60, max(10, len(title) * 2)), ""]
        for ts, text in items[:50]:
            t = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
            body = tr(text) if L == "en" else text
            lines.append(f"[{t}]")
            lines.append(body)
            lines.append("")
        if len(items) > 50:
            lines.append(f"+ {len(items) - 50} …")
        lines += ["--", T["footer"].format(app, socket.gethostname())]
        return subject, "\n".join(lines)

    def send(self, event, items, override=None, trace=None):
        """trace: اگر فهرست داده شود، هر مرحله‌ی اتصال (بدون رمز) در آن ثبت می‌شود — برای تست و عیب‌یابی."""
        def step(ok, text):
            log.info("SMTP %s %s", "OK " if ok else "ERR", text)
            if trace is not None:
                trace.append({"ok": ok, "text": text})
        c = self.cfg(override)
        host, port = (c.get("host") or "").strip(), int(c.get("port") or 0)
        to = [x.strip() for x in (c.get("to") or []) if str(x).strip()]
        sender = (c.get("from_addr") or c.get("username") or "").strip()
        if not host or not port:
            raise NotifyError("سرور یا پورت ایمیل تنظیم نشده است.")
        if not to:
            raise NotifyError("هیچ گیرنده‌ای برای ایمیل تعریف نشده است.")
        if not sender or "@" not in sender:
            raise NotifyError("نشانی فرستنده‌ی ایمیل معتبر نیست.")
        subject, body = self.compose(event, items, c)
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = formataddr((self.settings.get("branding", "app_name") or APP_NAME, sender))
        msg["To"] = ", ".join(to)
        msg["Date"] = formatdate(localtime=True)
        msg["Message-ID"] = make_msgid(domain=sender.split("@")[-1])
        msg.set_content(body, charset="utf-8")
        timeout = float(c.get("timeout") or 20)
        sec = c.get("security") or "starttls"
        ctx = ssl.create_default_context()
        if not c.get("verify_ssl", True):
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        step(True, f"تنظیمات: {host}:{port} — امنیت {sec} — "
                   f"{'با یوزر ' + c['username'] if c.get('username') else 'بدون احراز هویت (relay)'} — فرستنده {sender}")
        try:
            addrs = sorted({a[4][0] for a in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)})
            step(True, f"DNS: {host} → {', '.join(addrs)}")
        except OSError as e:
            step(False, f"DNS: نام {host} پیدا نشد ({e})")
            raise
        t0 = time.time()
        try:
            if sec == "ssl":
                smtp = smtplib.SMTP_SSL(timeout=timeout, context=ctx)
            else:
                smtp = smtplib.SMTP(timeout=timeout)
            smtp._host = host   # برای SNI و بررسی گواهی در TLS/STARTTLS (smtplib فقط در سازنده مقدار می‌دهد)
            code, banner = smtp.connect(host, port)
        except Exception as e:
            step(False, f"اتصال TCP{'/TLS' if sec == 'ssl' else ''} به {host}:{port} ناموفق: {e.__class__.__name__}: {e}"
                        + ("" if sec == "ssl" else " — اگر شبکه وصل است، فایروال یا آنتی‌ویروس ممکن است پورت را برای این برنامه ببندد"))
            raise
        step(True, f"اتصال برقرار شد ({(time.time() - t0) * 1000:.0f} ms) — پاسخ سرور: {code} {_txt(banner)}")
        try:
            code, resp = smtp.ehlo()
            step(code == 250, f"EHLO → {code}؛ قابلیت‌ها: {', '.join(sorted(smtp.esmtp_features)) or '—'}")
            if sec == "starttls":
                if not smtp.has_extn("starttls"):
                    step(False, "سرور در این پورت STARTTLS ارائه نمی‌کند")
                    raise NotifyError("سرور ایمیل از STARTTLS پشتیبانی نمی‌کند؛ روش امنیت را عوض کنید.")
                smtp.starttls(context=ctx)
                smtp.ehlo()
                step(True, f"STARTTLS انجام شد ({smtp.sock.version()})؛ قابلیت‌ها بعد از TLS: "
                           f"{', '.join(sorted(smtp.esmtp_features)) or '—'}")
            elif sec == "ssl":
                step(True, f"TLS مستقیم ({smtp.sock.version()})")
            auth = (smtp.esmtp_features.get("auth") or "").upper().split()
            if c.get("username"):
                if not auth:
                    step(False, "سرور در این اتصال هیچ روش احراز هویتی (AUTH) ارائه نمی‌کند")
                    raise NotifyError("سرور ایمیل در این پورت احراز هویت ارائه نمی‌کند. اگر Relay داخلی است یوزر را خالی بگذارید؛ "
                                      "در Exchange معمولاً احراز هویت روی پورت ۵۸۷ و بعد از STARTTLS فعال است.")
                usable = [m for m in auth if m in ("LOGIN", "PLAIN", "CRAM-MD5")]
                step(bool(usable), f"روش‌های احراز هویت سرور: {', '.join(auth)}")
                if not usable:
                    raise NotifyError(f"سرور فقط این روش‌ها را می‌پذیرد: {', '.join(auth)}. AutoKRP از LOGIN/PLAIN پشتیبانی می‌کند؛ "
                                      "در Exchange، Basic Authentication را روی Receive Connector فعال کنید یا از Relay داخلی استفاده کنید.")
                smtp.login(c["username"], c.get("password") or "")
                step(True, f"احراز هویت با {c['username']} موفق بود")
            smtp.send_message(msg)
            step(True, f"ایمیل پذیرفته شد؛ گیرنده‌ها: {', '.join(to)}")
        except smtplib.SMTPResponseException as e:
            step(False, f"پاسخ خطای سرور: {e.smtp_code} {_txt(e.smtp_error)}")
            raise
        except NotifyError:
            raise
        except Exception as e:
            step(False, f"{e.__class__.__name__}: {e}")
            raise
        finally:
            try:
                smtp.quit()
            except Exception:
                pass
        log.info("email sent: %s → %s", event, to)

    def test(self, override=None, trace=None):
        self.send("test", [(time.time(), "این یک ایمیل آزمایشی است. تنظیمات ایمیل درست کار می‌کند.")], override, trace)


def _txt(b):
    return (b.decode("utf-8", "replace") if isinstance(b, bytes) else str(b)).replace("\n", " | ")[:300]


def friendly(e):
    if isinstance(e, NotifyError):
        return str(e)
    if isinstance(e, smtplib.SMTPAuthenticationError):
        detail = _txt(e.smtp_error)
        if "5.7.139" in detail or "basic authentication is disabled" in detail.lower() or "5.7.57" in detail:
            return ("احراز هویت رد شد: ارسال SMTP با یوزر و رمز روی این سرور غیرفعال است "
                    f"(در Exchange Online/Microsoft 365 معمول است). پاسخ سرور: {detail}")
        return f"احراز هویت ایمیل رد شد؛ یوزر یا پسورد را بررسی کنید. پاسخ سرور: {e.smtp_code} {detail}"
    if isinstance(e, smtplib.SMTPRecipientsRefused):
        return "سرور ایمیل گیرنده‌ها را نپذیرفت."
    if isinstance(e, smtplib.SMTPSenderRefused):
        return "سرور ایمیل نشانی فرستنده را نپذیرفت."
    if isinstance(e, ssl.SSLCertVerificationError):
        return "گواهی SSL سرور ایمیل معتبر نیست. اگر گواهی داخلی است، «بررسی گواهی» را خاموش کنید."
    if isinstance(e, ssl.SSLError):
        return f"خطای SSL؛ روش امنیت یا پورت را بررسی کنید ({e.reason or e})."
    if isinstance(e, (socket.timeout, TimeoutError)):
        return "اتصال به سرور ایمیل در زمان مقرر برقرار نشد."
    if isinstance(e, ConnectionRefusedError):
        return "سرور ایمیل اتصال را رد کرد؛ آدرس و پورت را بررسی کنید."
    if isinstance(e, socket.gaierror):
        return "نام سرور ایمیل پیدا نشد."
    if isinstance(e, smtplib.SMTPException):
        return f"خطای SMTP: {e}"
    return f"{e.__class__.__name__}: {e}"
