"""AbuseIPDB: منطق abuseipdb.py اصلی (retry، backoff، verbose، CATEGORY_MAP) با requests."""
import ipaddress
import random
import time
from datetime import datetime

import requests

from .base import BaseConnector, ConnectorError

CATEGORY_MAP = {
    1: "DNS Compromise", 2: "DNS Poisoning", 3: "Fraud Orders", 4: "DDoS Attack",
    5: "FTP Brute-Force", 6: "Ping of Death", 7: "Phishing", 8: "Fraud VoIP",
    9: "Open Proxy", 10: "Web Spam", 11: "Email Spam", 12: "Blog Spam", 13: "VPN IP",
    14: "Port Scan", 15: "Hacking", 16: "SQL Injection", 17: "Spoofing", 18: "Brute Force",
    19: "Bad Web Bot", 20: "Exploited Host", 21: "Web App Attack", 22: "SSH", 23: "IoT Targeted",
}

REPORT_HEADERS = [
    "IP", "ISP", "Usage Type", "ASN", "Domain", "Country Code", "Country", "City",
    "Abuse Confidence Score", "Total Reports", "Last Reported At", "Is Whitelisted",
    "Is Tor", "Categories", "Status", "Error", "Checked At",
]


def is_valid_ipv4(value):
    try:
        return isinstance(ipaddress.ip_address(str(value).strip()), ipaddress.IPv4Address)
    except ValueError:
        return False


def should_skip_ip(ip):
    try:
        o = ipaddress.ip_address(ip)
        return o.is_private or o.is_loopback or o.is_link_local or o.is_multicast or o.is_reserved or o.is_unspecified
    except ValueError:
        return True


def extract_ips_from_text(text):
    """همان تابع اسکریپت: جداسازی با , ; فاصله tab و خط جدید، فقط IPv4، بدون تکرار."""
    if not text:
        return []
    values = [str(text)]
    for sep in [",", ";", " ", "\t", "\n", "\r"]:
        values = [p for v in values for p in v.split(sep)]
    ips = []
    for v in values:
        v = v.strip()
        if is_valid_ipv4(v) and v not in ips:
            ips.append(v)
    return ips


def extract_categories(reports):
    cats = set()
    if not isinstance(reports, list):
        return "-"
    for rep in reports:
        if not isinstance(rep, dict):
            continue
        for c in rep.get("categories", []):
            try:
                cid = int(c)
                if cid in CATEGORY_MAP:
                    cats.add(CATEGORY_MAP[cid])
            except (ValueError, TypeError):
                continue
    return " | ".join(sorted(cats)) if cats else "-"


def result_to_record(ip, result, threshold=0):
    """معادل create_result_row اسکریپت، به‌صورت dict. وضعیت: ABUSE اگر score > آستانه."""
    checked_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if not result["success"]:
        return {"ip": ip, "abuse_status": "ERROR", "error": result["error"], "checked_at": checked_at,
                "score": None, "reports": None}
    d = result["data"]
    score = d.get("abuseConfidenceScore", 0) or 0
    asn = d.get("asn")
    return {
        "ip": ip,
        "isp": d.get("isp", "-"), "usage_type": d.get("usageType", "-"),
        "asn": f"AS{asn}" if asn else "-", "domain": d.get("domain", "-"),
        "country_code": d.get("countryCode", "-"), "country": d.get("countryName", "-"),
        "city": d.get("city", "-"), "score": score, "reports": d.get("totalReports", 0) or 0,
        "last_reported": d.get("lastReportedAt", "-"),
        "is_whitelisted": d.get("isWhitelisted", "-"), "is_tor": d.get("isTor", "-"),
        "categories": extract_categories(d.get("reports", [])),
        "abuse_status": "ABUSE" if score > threshold else "CLEAN",
        "error": "", "checked_at": checked_at,
    }


def record_to_report_row(r):
    g = lambda k: "-" if r.get(k) in (None, "") else r.get(k)
    return [r["ip"], g("isp"), g("usage_type"), g("asn"), g("domain"), g("country_code"), g("country"),
            g("city"), g("score"), g("reports"), g("last_reported"), g("is_whitelisted"), g("is_tor"),
            g("categories"), r.get("abuse_status"), r.get("error", ""), r.get("checked_at")]


CHECK_PATH = "/api/v2/check"


def api_error(r):
    """متن خطای AbuseIPDB (JSON:API: errors[].detail) یا ابتدای پاسخ."""
    try:
        errs = r.json().get("errors") or []
        if errs and errs[0].get("detail"):
            return str(errs[0]["detail"])[:300]
    except ValueError:
        pass
    txt = (r.text or "").strip()
    if txt.lower().startswith("<!doctype") or txt.lower().startswith("<html"):
        return "پاسخ HTML به‌جای JSON (آدرس endpoint اشتباه است یا پراکسی/فایروال پاسخ داده است)"
    return txt[:200]


# پیام ثابت IPهایی که به‌خاطر تمام شدن سهمیه بررسی نشدند (چک مجدد خودکار این‌ها را برنمی‌دارد)
QUOTA_ERR = "بررسی نشد: سهمیه‌ی روزانه‌ی AbuseIPDB تمام شد"
QUOTA_WAIT_LIMIT = 120   # ثانیه؛ Retry-After بیشتر از این یعنی سهمیه‌ی روزانه، نه محدودیت لحظه‌ای


def split_keys(text):
    """کلیدهای اضافه: هر خط (یا جداشده با ویرگول/فاصله) یک کلید؛ بدون تکرار، به همان ترتیب."""
    import re
    return [k for k in dict.fromkeys(re.split(r"[\s,;]+", str(text or ""))) if k]


class AbuseClient(BaseConnector):
    NAME = "abuseipdb"

    def base_url(self):
        """آدرس کامل endpoint بررسی. اگر فقط دامنه یا /api/v2 وارد شده باشد، مسیر /api/v2/check اضافه می‌شود."""
        url = super().base_url()
        from urllib.parse import urlsplit, urlunsplit
        p = urlsplit(url)
        path = p.path.rstrip("/")
        if path in ("", "/api", "/api/v2"):
            path = CHECK_PATH
        return urlunsplit((p.scheme, p.netloc, path, p.query, ""))

    def __init__(self, cfg, cancel_event=None):
        super().__init__(cfg, cancel_event)
        self.quota_reset_at = 0.0
        self.rate = {}           # تا اولین پاسخ؛ بدون آن، اجرایی که همه‌ی درخواست‌هایش خطا بدهد AttributeError می‌گرفت
        # طبق مستندات APIv2 کلید فقط در هدر «Key» پذیرفته می‌شود (Bearer پشتیبانی نمی‌شود)
        self.s.headers.pop("Authorization", None)
        self.s.auth = None
        self.s.auth_header = "Key"
        # چند کلید به ترتیب: کلید اصلی، بعد «کلیدهای اضافه» (هر خط یکی)؛ با تمام شدن سهمیه‌ی یکی، بعدی
        self.keys = list(dict.fromkeys(k for k in [self.cfg.get("token") or ""] + split_keys(self.cfg.get("extra_tokens")) if k))
        self.key_idx = 0
        if self.keys:
            self.s.headers["Key"] = self.keys[0]

    def use_key(self, i):
        """کلید شماره‌ی i (از ۰) برای درخواست‌های بعدی؛ وضعیت سهمیه و rate برای کلید تازه از نو."""
        self.key_idx = i
        self.s.headers["Key"] = self.keys[i]
        self.quota_reset_at = 0.0
        self.rate = {}
        self.s.headers.update({"Accept": "application/json", "User-Agent": "AbuseIPDB-Python-Checker/3.0"})

    def require_credentials(self):
        if not self.keys:
            from .base import ConnectorError
            raise ConnectorError("کلید API تنظیم نشده است.")
        self.rate = {}

    def test(self) -> dict:
        self.require_credentials()
        res = self.check_ip("8.8.8.8", max_age=1, retries=1)
        if not res["success"]:
            err = res["error"]
            if err.startswith("HTTP 401"):
                k = self.cfg.get("token") or ""
                err += (f" | کلید ارسال‌شده در هدر Key: {len(k)} نویسه، پایان با «…{k[-4:]}». "
                        "آن را با کلید APIv2 در حساب AbuseIPDB (Account → API) مقایسه کنید؛ کلید APIv1 کار نمی‌کند.")
            raise ConnectorError(err)
        msg = f"اتصال برقرار است (یک درخواست از سهمیه مصرف شد). آدرس: {self.base_url()}"
        if self.rate.get("remaining") is not None:
            msg += f" سهمیه‌ی باقی‌مانده: {self.rate['remaining']} از {self.rate.get('limit', '?')}"
        return {"message": msg, "rate": self.rate}

    def check_ip(self, ip, max_age=None, retries=None, log=None):
        url = self.base_url()
        params = {"ipAddress": ip, "maxAgeInDays": max_age or int(self.cfg.get("max_age_days") or 90),
                  "verbose": "true"}
        timeout = float(self.cfg.get("timeout") or 15)
        max_retries = retries or int(self.cfg.get("retries") or 5)
        init_delay = float(self.cfg.get("retry_delay") or 5)
        for attempt in range(1, max_retries + 1):
            self.check_cancel()
            try:
                r = self.s.get(url, params=params, timeout=timeout)
                self._read_rate(r)
                if r.status_code in (429, 500, 502, 503, 504):
                    ra = r.headers.get("Retry-After")
                    try:
                        wait = float(ra) if ra else init_delay * (2 ** (attempt - 1))
                    except ValueError:
                        wait = init_delay * (2 ** (attempt - 1))
                    if r.status_code == 429 and (str(self.rate.get("remaining")) == "0" or wait > QUOTA_WAIT_LIMIT):
                        # سهمیه‌ی روزانه تمام شده: صبر کردن (گاهی چند ساعت) بی‌فایده است؛ اجرا ادامه پیدا می‌کند
                        self.quota_reset_at = time.time() + (wait if ra else 3600)
                        return {"success": False, "data": {}, "error": QUOTA_ERR, "quota": True}
                    wait += random.uniform(1, 3)  # nosec B311 — فقط jitter زمان انتظار، نه رمزنگاری
                    if attempt < max_retries:
                        if log:
                            log(f"{ip} → HTTP {r.status_code}؛ تلاش مجدد پس از {wait:.1f} ثانیه ({attempt}/{max_retries})", "warn")
                        self.sleep(wait)
                        continue
                    return {"success": False, "data": {}, "error": f"HTTP {r.status_code}"}
                if r.status_code >= 400:
                    hint = {401: " — کلید API اشتباه، منقضی یا خالی است", 403: " — دسترسی رد شد (کلید یا محدودیت شبکه)",
                            404: f" — آدرس endpoint اشتباه است؛ باید ‎{CHECK_PATH} باشد", 422: " — پارامتر نامعتبر"}.get(r.status_code, "")
                    return {"success": False, "data": {}, "error": f"HTTP {r.status_code}{hint}: {api_error(r)}"}
                try:
                    return {"success": True, "data": r.json().get("data", {}), "error": ""}
                except ValueError:
                    return {"success": False, "data": {}, "error": "پاسخ JSON نامعتبر: " + api_error(r)}
            except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
                wait = init_delay * (2 ** (attempt - 1)) + random.uniform(1, 3)  # nosec B311 — فقط jitter زمان انتظار، نه رمزنگاری
                if attempt < max_retries:
                    if log:
                        log(f"{ip} → خطای شبکه؛ تلاش مجدد پس از {wait:.1f} ثانیه", "warn")
                    self.sleep(wait)
                    continue
                return {"success": False, "data": {}, "error": f"Network error: {e}"}
            except ValueError as e:
                return {"success": False, "data": {}, "error": f"پاسخ JSON نامعتبر: {e}"}
        return {"success": False, "data": {}, "error": "Unknown error"}

    def quota_exhausted(self):
        """آیا از اجرای قبلی می‌دانیم سهمیه تمام است و هنوز ریست نشده؟"""
        return self.quota_reset_at > time.time()

    def _read_rate(self, r):
        for k, name in (("limit", "X-RateLimit-Limit"), ("remaining", "X-RateLimit-Remaining")):
            if r.headers.get(name) is not None:
                self.rate[k] = r.headers.get(name)
        self.rate["at"] = time.time()

    def pause_between(self):
        self.sleep(float(self.cfg.get("delay") or 1.5) + random.uniform(0.2, 0.8))  # nosec B311 — فقط jitter زمان انتظار، نه رمزنگاری
