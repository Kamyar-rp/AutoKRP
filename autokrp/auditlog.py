"""1.46: لاگ ممیزی ضد دست‌کاری و ارسال به Syslog/SIEM (پیش‌نیاز PAM کوچک).

- هر ردیف «تاریخچه» (و رخدادهای ورود) یک ردیف هم در audit_log می‌نویسد. ردیف‌ها با HMAC-SHA256 به هم زنجیر می‌شوند
  (mac = HMAC(کلید، mac ردیف قبلی + متن ثابت ردیف)). کلید از کلید داده‌ی برنامه (atrest) مشتق می‌شود و جایی ذخیره نمی‌شود.
  هر تغییر، حذف یا جابه‌جایی وسط زنجیره با «بررسی یکپارچگی» معلوم می‌شود؛ حذف از انتهای زنجیره هم با «سر زنجیره»ی امضاشده
  (meta: audit_head). از داخل برنامه هیچ راهی برای حذف یا ویرایش ردیف ممیزی نیست (فقط RESET کامل).
- ردیف‌ها اول بدون امضا نوشته می‌شوند و به ترتیب «مهر» می‌شوند (seal) — در حالت سرور تا ادمین وارد نشده کلید داده در حافظه نیست.
- ارسال: Syslog استاندارد (RFC 5424) یا CEF، روی UDP، TCP یا TLS. صف = شماره‌ی آخرین ردیف فرستاده‌شده (meta: audit_sent)؛
  قطع شدن مقصد ← بعداً همان‌ها فرستاده می‌شوند (حداقل یک بار).
"""
import hashlib
import hmac
import json
import logging
import socket
import ssl
import threading
import time
from datetime import datetime, timezone

log = logging.getLogger(__name__)

# دسته‌ها ← نوع‌های تاریخچه
CATS = {
    "auth": "ورود و خروج",
    "security": "کاربران، دسترسی و تنظیمات",
    "tools": "ابزارهای امنیتی (Splunk، AbuseIPDB، FortiGate، Redmine، …)",
    "devices": "ارتباط با دستگاه‌ها (SSH، ترمینال، انتقال فایل، API، پشتیبان)",
    "monitor": "مانیتورینگ و دارایی‌ها",
}
_KIND_CAT = {
    "splunk": "tools", "abuse": "tools", "fortigate": "tools", "ban": "tools", "redmine": "tools", "ticket": "tools", "intel": "tools",
    "dns": "tools", "scan": "tools", "import": "tools", "export": "tools", "approval": "tools",
    "ssh": "devices", "backup": "devices", "terminal": "devices", "transfer": "devices", "fgupdate": "devices", "api": "devices",
    "nettools": "devices", "monitor": "monitor", "asset": "monitor", "security": "security",
}
SEV = {"error": 3, "warn": 4, "ok": 6, "info": 6}          # شدت Syslog (RFC 5424: ۳ خطا، ۴ هشدار، ۶ اطلاع)
FIELDS = ("id", "ts", "kind", "cat", "user", "ip", "target", "status", "detail")
SEAL_BATCH = 2000


def category(kind, target=""):
    if kind == "security" and str(target or "") in ("ورود", "خروج", "قفل"):
        return "auth"
    return _KIND_CAT.get(kind, "tools")


def canon(r):
    """متن ثابت یک ردیف برای امضا (ترتیب و قالب هرگز عوض نشود)."""
    return json.dumps([int(r["id"]), round(float(r["ts"]), 3), r["kind"] or "", r["cat"] or "", r["user"] or "", r["ip"] or "",
                       r["target"] or "", r["status"] or "", r["detail"] or ""], ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def audit_key():
    """کلید HMAC از کلید داده؛ وقتی کلید در دسترس نیست None (ردیف‌ها بعداً مهر می‌شوند)."""
    from . import atrest
    try:
        if not atrest.has_key():
            return None
        return hmac.new(atrest.key(), b"autokrp-audit-chain-v1", hashlib.sha256).digest()
    except Exception:  # noqa
        return None


def mac_of(key, prev, r):
    return hmac.new(key, (prev or "").encode("ascii") + b"|" + canon(r), hashlib.sha256).hexdigest()


def head_mac(key, rid, mac):
    return hmac.new(key, f"head|{int(rid)}|{mac}".encode("ascii"), hashlib.sha256).hexdigest()


# ------------------------------------------------------------------ قالب‌ها
def _sd(v):
    return str(v or "").replace("\\", "\\\\").replace('"', '\\"').replace("]", "\\]")


def _clean(v, n=2000):
    return " ".join(str(v or "").split())[:n]


def fmt_syslog(r, host, facility=13, app="AutoKRP"):
    """RFC 5424 با Structured Data (enterprise 32473 = شماره‌ی نمونه‌ی مستندات، RFC 5612)."""
    pri = facility * 8 + SEV.get(r["status"], 5)
    ts = datetime.fromtimestamp(float(r["ts"]), timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    sd = (f'[autokrp@32473 id="{r["id"]}" cat="{_sd(r["cat"])}" kind="{_sd(r["kind"])}" user="{_sd(r["user"])}" ip="{_sd(r["ip"])}"'
          f' status="{_sd(r["status"])}" target="{_sd(_clean(r["target"], 200))}" mac="{r.get("mac") or ""}"]')
    return f"<{pri}>1 {ts} {host or '-'} {app} - {r['cat'] or '-'} {sd} ﻿{_clean(r['detail'])}"


def _cef_h(v):
    return str(v or "").replace("\\", "\\\\").replace("|", "\\|")


def _cef_e(v):
    return _clean(v).replace("\\", "\\\\").replace("=", "\\=")


def fmt_cef(r, host, version, facility=13):
    sev = {"error": 7, "warn": 5, "ok": 2, "info": 2}.get(r["status"], 3)
    ext = (f"rt={int(float(r['ts']) * 1000)} externalId={r['id']} cat={_cef_e(r['cat'])} act={_cef_e(r['kind'])} suser={_cef_e(r['user'])}"
           f" outcome={_cef_e(r['status'])} cs1Label=target cs1={_cef_e(_clean(r['target'], 200))} cs2Label=chainMac cs2={r.get('mac') or ''}"
           f" msg={_cef_e(r['detail'])}")
    if r.get("ip"):
        ext += f" src={_cef_e(r['ip'])}"
    body = f"CEF:0|AutoKRP|AutoKRP|{_cef_h(version)}|{_cef_h(r['cat'])}.{_cef_h(r['kind'])}|{_cef_h(_clean(r['target'], 120) or r['kind'])}|{sev}|{ext}"
    pri = facility * 8 + SEV.get(r["status"], 5)
    ts = datetime.fromtimestamp(float(r["ts"]), timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    return f"<{pri}>1 {ts} {host or '-'} AutoKRP - - - {body}"


def clean_cfg(c):
    c = c if isinstance(c, dict) else {}
    proto = c.get("proto") if c.get("proto") in ("udp", "tcp", "tls") else "udp"
    fmt = c.get("format") if c.get("format") in ("syslog", "cef") else "syslog"
    try:
        port = int(c.get("port") or (6514 if proto == "tls" else 514))
    except (TypeError, ValueError):
        port = 514
    cats = [x for x in (c.get("cats") or list(CATS)) if x in CATS]
    return {"enabled": bool(c.get("enabled")), "host": str(c.get("host") or "").strip()[:200], "port": max(1, min(65535, port)),
            "proto": proto, "format": fmt, "cats": cats, "verify_tls": c.get("verify_tls") is not False,
            "facility": max(0, min(23, int(c.get("facility") or 13))), "hostname": str(c.get("hostname") or "").strip()[:100]}


# ------------------------------------------------------------------ ارسال
class Sender:
    def __init__(self, cfg):
        self.cfg, self.sock = cfg, None

    def close(self):
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass
        self.sock = None

    def _open(self):
        c = self.cfg
        if c["proto"] == "udp":
            fam = socket.getaddrinfo(c["host"], c["port"], 0, socket.SOCK_DGRAM)[0]
            s = socket.socket(fam[0], socket.SOCK_DGRAM)
            s.connect(fam[4])
            return s
        s = socket.create_connection((c["host"], c["port"]), timeout=10)
        if c["proto"] == "tls":
            ctx = ssl.create_default_context()
            if not c["verify_tls"]:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE  # nosec B501 — فقط وقتی ادمین خودش «بررسی گواهی» را خاموش کرده (گواهی داخلی سازمان)
            s = ctx.wrap_socket(s, server_hostname=c["host"])
        s.settimeout(10)
        return s

    def send(self, lines):
        """هر خط یک پیام. UDP: هر پیام یک بسته (حداکثر ۸KB). TCP/TLS: جدا با LF (RFC 6587 non-transparent framing)."""
        if self.sock is None:
            self.sock = self._open()
        try:
            if self.cfg["proto"] == "udp":
                for x in lines:
                    self.sock.send(x.encode("utf-8")[:8000])
            else:
                self.sock.sendall("".join(x.replace("\n", " ") + "\n" for x in lines).encode("utf-8"))
        except OSError:
            self.close()
            raise


class Forwarder:
    """رشته‌ی پس‌زمینه: مهر کردن ردیف‌های تازه و فرستادن ردیف‌های مهرشده به مقصد."""

    def __init__(self, store, settings, version, hostname=""):
        self.store, self.settings, self.version = store, settings, version
        self.hostname = hostname or socket.gethostname()
        self.status = {"last_ok": None, "last_error": "", "last_error_at": None, "sent": 0}
        self._stop = threading.Event()
        self._thr = None
        self._sig = None
        self._sender = None

    def start(self):
        if self._thr and self._thr.is_alive():
            return
        self._stop.clear()
        self._thr = threading.Thread(target=self._loop, name="audit-fwd", daemon=True)
        self._thr.start()

    def stop(self):
        self._stop.set()
        if self._sender:
            self._sender.close()

    def cfg(self):
        return clean_cfg(self.settings.get("audit") or {})

    def _loop(self):
        delay = 2
        while not self._stop.wait(delay):
            try:
                self.store.audit_seal()
                c = self.cfg()
                if not c["enabled"] or not c["host"]:
                    delay = 5
                    continue
                sig = json.dumps(c, sort_keys=True)
                if sig != self._sig:
                    if self._sender:
                        self._sender.close()
                    self._sender, self._sig = Sender(c), sig
                n = self.flush(c)
                delay = 0.2 if n >= 500 else 2
            except Exception as e:  # noqa — مقصد در دسترس نیست؛ بعداً همان ردیف‌ها دوباره
                self.status.update(last_error=str(e)[:300], last_error_at=time.time())
                delay = min(60, max(5, delay * 2))

    def flush(self, c, limit=500):
        start = int(self.store.meta("audit_sent", 0) or 0)
        rows = self.store.audit_since(start, limit)
        if not rows:
            return 0
        host = c["hostname"] or self.hostname
        out = []
        for r in rows:
            if r["cat"] in c["cats"]:
                out.append(fmt_cef(r, host, self.version, c["facility"]) if c["format"] == "cef" else fmt_syslog(r, host, c["facility"]))
        if out:
            self._sender.send(out)
        self.store.set_meta("audit_sent", rows[-1]["id"])
        self.status.update(last_ok=time.time(), last_error="", sent=self.status["sent"] + len(out))
        return len(rows)

    def test(self, c):
        """پیام آزمایشی (بدون جابه‌جا کردن صف)."""
        r = {"id": 0, "ts": time.time(), "kind": "security", "cat": "security", "user": "", "ip": "", "target": "Audit test",
             "status": "info", "detail": "AutoKRP audit forwarding test message", "mac": ""}
        host = c["hostname"] or self.hostname
        s = Sender(c)
        try:
            s.send([fmt_cef(r, host, self.version, c["facility"]) if c["format"] == "cef" else fmt_syslog(r, host, c["facility"])])
        finally:
            s.close()
