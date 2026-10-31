"""
تنظیمات JSON با merge روی DEFAULTS و ذخیره‌ی اتمیک. اسرار (توکن/رمز) در settings.json نیستند؛
در vault رمزنگاری‌شده (vault.py) نگهداری می‌شوند.
هیچ آدرس یا پورتی به‌صورت پیش‌فرض در کد نیست؛ همه از صفحه‌ی تنظیمات وارد می‌شوند.
"""
import copy
import ipaddress
import json
import logging
import os
import socket
import threading
import time
from urllib.parse import urlsplit

from . import atrest, paths

log = logging.getLogger(__name__)

# ------------------------------------------------------------------ DEFAULTS
SPLUNK_QUERY = r"""| tstats  summariesonly=false
    count as attack_count
    dc(IDS_Attacks.dest) as dest_count
    values(IDS_Attacks.dest) as dest
    values(IDS_Attacks.signature) as signatures
    min(_time) as firstTime
    max(_time) as lastTime
  from datamodel=Intrusion_Detection.IDS_Attacks
  by IDS_Attacks.src IDS_Attacks.dest_port IDS_Attacks.signature IDS_Attacks.vendor_product IDS_Attacks.category IDS_Attacks.action
| rename IDS_Attacks.* as *
| eval dest=mvjoin(dest,", "), signatures=mvjoin(signatures,", ")
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| `vulnerability_scanner_detected`"""

REDMINE_DESCRIPTION = """اطلاعات کلی رویداد:
عنوان: گزارش IPهای مخرب شناسایی‌شده
تاریخ شناسایی: {date}
شدت: High

شرح رویداد:
در بررسی رویدادهای IDS در Splunk، از {src_count} آدرس IP مبدأ یکتا روی سرویس‌های سازمان اسکن یا حمله ثبت شده است.
نتیجه‌ی بررسی AbuseIPDB: {abuse_count} مخرب، {clean_count} غیرمخرب، {error_count} خطا.
در FortiGate {banned_count} آدرس بلاک شد، {already_banned_count} از قبل بلاک بود و {address_match_count} با Address Objectها تطابق داشت.
{clean_review_count} آدرس غیرمخرب برای بررسی دستی باقی ماند.
لیست کامل در فایل‌های پیوست است.

پیشنهادات:
آدرس‌های بررسی دستی کنترل شوند."""

# 1.30: نصب تازه با زبان انگلیسی ← قالب تیکت انگلیسی
REDMINE_SUBJECT_EN = "Malicious IP report"
REDMINE_DESCRIPTION_EN = """Event overview:
Title: Report of detected malicious IPs
Detected: {date}
Severity: High

Description:
Reviewing IDS events in Splunk, {src_count} unique source IP addresses were seen scanning or attacking the organisation's services.
AbuseIPDB result: {abuse_count} malicious, {clean_count} clean, {error_count} errors.
On FortiGate {banned_count} addresses were blocked, {already_banned_count} were already blocked and {address_match_count} matched Address Objects.
{clean_review_count} clean addresses are left for manual review.
The full lists are attached.

Recommendations:
Review the addresses left for manual review."""

# فقط شبکه‌های خصوصی؛ رنج‌های عمومی سازمان خود را در تنظیمات اضافه کنید
# 1.28: چند FortiGate — دستگاه اول همان «fortigate»؛ بقیه fortigate2 … fortigate8 (هر کدام اتصال جدا با اسرار و پین خودش).
# رنج‌های مستثنا، سقف بسط CIDR و سناریوها (fg_scenarios) مشترک‌اند و فقط در «fortigate» نگه داشته می‌شوند.
FG_EXTRA = tuple(f"fortigate{i}" for i in range(2, 9))
FG_DEV_FIELDS = ("name", "address", "port", "auth_type", "header_name", "username", "vdom", "verify_ssl", "pin_cert",
                 "ban_expiry", "address_count", "convert_auto_bans", "timeout", "check_json_status")
FG_SHARED = ("ignore_networks", "max_cidr_expand")
PIN_CONNS = ("splunk", "abuseipdb", "fortigate", "redmine") + FG_EXTRA
# رنج‌های غیرعمومی که بلاک کردنشان معنا ندارد. پیش‌فرض‌اند و کاربر می‌تواند از فیلد حذفشان کند.
NONPUBLIC_NETWORKS = [
    "0.0.0.0/8  # this network", "127.0.0.0/8  # loopback", "169.254.0.0/16  # link-local",
    "100.64.0.0/10  # CGNAT", "224.0.0.0/4  # multicast", "240.0.0.0/4  # reserved",
    "::1/128  # loopback", "fc00::/7  # IPv6 private", "fe80::/10  # IPv6 link-local",
]
IGNORE_NETWORKS = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"] + NONPUBLIC_NETWORKS
# سرورهایی که برنامه از آن‌ها استفاده می‌کند و IPشان خودکار به رنج‌های مستثنا اضافه می‌شود
PROTECT_CONNS = (("splunk", "address", "Splunk"), ("fortigate", "address", "FortiGate"),
                 ("redmine", "address", "Redmine"), ("notify", "host", "SMTP")) + tuple((c, "address", "FortiGate") for c in FG_EXTRA)

DEFAULTS = {
    "_pin_v1262": True,           # نشانه‌ی مهاجرت پیش‌فرض پین گواهی (بالا: load)
    "branding": {"app_name": "AutoKRP", "subtitle": "ابزار خودکار ساز", "logo_text": "A",
                 "logo_file": "", "icon_file": ""},
    # mode: "" (هنوز انتخاب نشده) | simple | password | env
    "security": {"mode": "", "remember": False, "strong_policy": True, "auto_lock_minutes": 0},
    # کاربران (فقط حالت رمز اصلی؛ از متدهای users تغییر می‌کند): [{"username","role","tools","disabled","salt","wrap"}]
    "users": [],
    # پایگاه داده: asked = انتخاب «محلی یا MySQL» در اولین اجرا انجام شده (تنظیمات اتصال در db.dat، نه اینجا)
    "database": {"asked": False},
    # ابزارهای فعال برنامه (ادمین)؛ ابزار خاموش برای همه پنهان و غیرقابل اجراست
    "tools_enabled": {"splunk": True, "abuse": True, "fortigate": True, "redmine": True, "dns": True, "ssh": True, "scan": True, "intel": True, "asset": True,
                      "monitor": True, "term": True, "offline": True},
    # حالت سرور (وب). از متدهای server_* تغییر می‌کند
    "server": {"port": 8443, "allowed_networks": [], "session_timeout_minutes": 30,
               "lockout_threshold": 5, "lockout_minutes": 15},
    "theme": "dark",
    "test_mode": True,
    "poll_minutes": 5,            # فاصله‌ی بررسی وضعیت اتصال‌ها
    "max_age_hours": 6,           # اگر اجرای زمان‌بندی‌شده بیش از این عقب افتاد، رد شود
    "splunk": {
        "address": "", "port": "", "auth_type": "bearer", "username": "",
        # همان اپی که کوئری در وب Splunk در آن جواب می‌دهد (…/app/search/search)
        "app": "search", "verify_ssl": False, "pin_cert": True,   # 1.26.2: بدون بررسی CA، پین گواهی پیش‌فرض روشن (نصب تازه)
        "query": SPLUNK_QUERY, "earliest": "-24h", "latest": "now", "timeout": 600,
        "src_field": "src",
        # نگاشت ستون‌های خروجی کوئری که کاربر در «اجرا و پیش‌نمایش» تأیید می‌کند.
        # مقدار: نام ستون | "-" = ندارد | "" = تشخیص خودکار. fields_hash = اثر انگشت کوئری‌ای که نگاشت برایش تأیید شد.
        "fields": {"src": "", "dest": "", "dest_port": "", "signature": "", "count": "", "first": "", "last": ""},
        "fields_hash": "",
        # کوئری‌های ذخیره‌شده‌ی دیگر: [{"id", "name", "query", "earliest", "latest"}]؛ نقش ستون‌ها از نام‌های استاندارد
        "queries": [],
    },
    # کارهای ذخیره‌شده‌ی صفحه‌ی ابزارها و زمان‌بندی‌شان (از متدهای jobs تغییر می‌کند، نه از فرم)
    "jobs": [], "jobs_migrated": False,
    # ابزار DNS
    "dns": {"server": "", "timeout": 5, "max_records": 3, "concurrency": 20},
    # ترمینال SSH زنده: بستن پس از بی‌کاری (دقیقه، ۰ = خاموش)؛ ضبط متن نشست‌ها (رمزشده، پیش‌فرض خاموش)
    "terminal": {"idle_minutes": 30, "record": False},
    # مانیتورینگ: صدای هشدار (خالی = صدای پیش‌فرض؛ فایل سفارشی رمزشده در monitor/sounds)، تکرار، ساعات سکوت،
    # ماندن در پس‌زمینه با بستن پنجره (دسکتاپ)، نمایش پنجره هنگام قطعی، پخش صدا روی خود سرور (حالت وب)
    "monitor": {"sound_down": "", "sound_up": "", "repeat": 3, "sound_on_up": True,
                "quiet": {"enabled": False, "from": "23:00", "to": "07:00"},
                "close_action": "ask", "show_window": True, "server_sound": False,
                # نگهداری داده (روز؛ ۰ = بدون محدودیت، پیش‌فرض از 1.23.1): دقیقه‌ای/۵ دقیقه‌ای SNMP، و ساعتی + قطعی‌ها
                "keep_detail_days": 0, "keep_hour_days": 0},
    # Trap و Syslog (1.25؛ پیش‌فرض خاموش؛ ادمین در تنظیمات ← مانیتورینگ)
    "events": {"trap_enabled": False, "trap_port": 162, "syslog_enabled": False, "syslog_port": 514, "syslog_tcp": True,
               "bind": "0.0.0.0", "allow_unknown": False, "sources": [], "communities": [], "min_store": 6,  # nosec B104 — گیرنده روی شبکه
               "forti_traffic": False, "alert_level": "crit", "rules": [], "keep_days": 0},
    # سلامت سرور (1.24): هشدار کمبود فضای دیسک پوشه‌ی داده، RAM و CPU خود برنامه
    "health": {"enabled": True, "disk_min_gb": 10, "disk_min_pct": 10, "ram_max_mb": 2048, "cpu_max_pct": 90},
    # ابزار «بررسی تکمیلی»: فید آنلاین FFraud و لیست داخلی (IP/CIDR)
    "intel": {"feed_enabled": True, "feed_url": "https://raw.githubusercontent.com/FFraud-com/ip-fraud-database/main/threat-ips/confirmed-abusive.csv",
              "min_score": 50, "refresh_minutes": 60, "max_age_hours": 24, "verify_ssl": True, "timeout": 120,
              # لیست داخلی: آپلود در تنظیمات (رمزشده) یا مسیر فایلی که هر اجرا خوانده می‌شود (فقط کلاینت؛ اولویت با مسیر)
              "local_enabled": False, "local_path": "",
              # بلاک مخرب‌های این ابزار در FortiGate بدون تأیید (فقط در کار زمان‌بندی‌شده با «بلاک بدون تأیید»)
              "auto_ban": False},
    # انتقال فایل: سقف حجم هر فایل به مگابایت (۰ = بدون محدودیت)
    "transfer": {"max_mb": 0},
    # مدیریت دارایی: اسکن روزانه (با «کار خودکار»)، منابع (None = همه‌ی منابع مشترک)، خواندن محل از دستگاه برای دارایی تازه
    "stats": {"raw_days": 180},     # 1.22: رویدادهای آماری خام بعد از این‌همه روز پاک می‌شوند؛ خلاصه‌ها (نمودارها) می‌مانند
    "assets": {"scan_enabled": False, "scan_time": "03:00", "sources": None, "loc_default": False, "concurrency": 4},
    # ابزار اسکن شبکه: فقط رنج‌های مجاز اسکن می‌شوند (پیش‌فرض: شبکه‌های داخلی)
    "scan": {"allowed_networks": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"], "max_hosts": 1024,
             "max_probes": 200000, "workers": 100, "timeout": 1.0},
    "abuseipdb": {
        "address": "", "port": "", "auth_type": "header", "header_name": "Key", "username": "",
        "verify_ssl": True, "max_age_days": 90, "timeout": 15, "delay": 1.5,
        "retries": 5, "retry_delay": 5, "threshold": 0,
        # forever = مثل اسکریپت اصلی، IP بررسی‌شده دوباره آنلاین چک نمی‌شود | days = تا cache_days روز | never = همیشه
        "cache_mode": "forever", "cache_days": 30,
        "skip_whitelisted": False,
        # IPهای غیرمخرب (نتیجه‌ی AbuseIPDB، نه ثبت دستی) پس از این تعداد روز از فهرست حذف می‌شوند (۰ = خاموش)
        "purge_clean_days": 30,
        # هشدار تکرار: IP غیرمخربی که در این تعداد روزِ مختلف دوباره به AbuseIPDB رسیده (و هر همین تعداد بعدی) (۰ = خاموش)
        "repeat_days": 5,
        # 1.28: آخرین نتیجه‌ی هر اسکن، بدون رمز، در یک پوشه‌ی دلخواه (abuse_latest.csv؛ هر بار بازنویسی)
        "export_enabled": False, "export_dir": "",
        # فقط IPهای مخرب بلاک می‌شوند؛ غیرمخرب‌ها (از هر کشوری) فقط برای بررسی دستی می‌مانند
    },
    "fortigate": {
        "name": "",
        "address": "", "port": "", "auth_type": "bearer", "username": "",
        "vdom": "root", "verify_ssl": False, "pin_cert": True, "ban_expiry": 0, "address_count": 10000,
        # IPی که در Banned هست ولی بلاک خودکار (IPS، Application Control، ...) یا با انقضاست ← Administrative دائمی (با تأیید)
        "convert_auto_bans": True,
        "timeout": 10, "max_cidr_expand": 256, "check_json_status": True,
        "ignore_networks": list(IGNORE_NETWORKS),
    },
    # 1.29: تسک‌های پایتونی FortiGate (fgtask) — [{id, name, note, code, on_error, timeout}]
    "fg_scenarios": [],
    "redmine": {
        "address": "", "port": "", "auth_type": "header", "header_name": "X-Redmine-API-Key", "username": "",
        "verify_ssl": True, "project": "",
        "tracker": "", "subject": "گزارش IPهای مخرب", "priority": "",
        "category": "", "assign_to_me": True,
        "src_ips_per_line": 0, "dest_sample_count": 2, "more_suffix": "و ...", "date_format": "%d/%m/%Y",
        "description_template": REDMINE_DESCRIPTION,
        # نام Custom Fieldهای Redmine هر سازمان فرق دارد؛ در تنظیمات تعریف کنید
        "static_fields": [],
        "dynamic_fields": [
            ["Src IP(s)", "src_ips"], ["Dest IP(s)", "dest_ips"],
            ["Dest-Port(s)", "dest_ports"], ["Detected Time", "detected_date"],
        ],
        "field_id_overrides": [],
        # روش جدید: مقدار فیلدهای هر Tracker — {tracker_id: {field_id: {"src": "static"|کلید داده, "value": ...}}}
        "tracker_values": {},
        "attach_splunk_csv": True, "attach_abuse_report": True, "attach_fortigate_report": True,
        # قالب‌های تیکت (1.12): هر قالب عنوان، Tracker، اولویت، دسته، متن، مقدار فیلدها و پیوست‌های خودش را دارد.
        # خالی ← از فیلدهای بالا (روش تک‌قالبی قبلی) قالب «پیش‌فرض» ساخته می‌شود.
        "templates": [], "default_template": "",
    },
    "automation": {
        "master": False,
        "daily": {
            "enabled": False, "time": "08:00",
            "steps": {"splunk": True, "abuse": True, "fortigate": True, "redmine": True},
            "auto_ban": False, "auto_ticket": False,
            # سقف بلاک بدون تأیید در هر اجرا؛ اگر بیشتر شد، اجرا منتظر تأیید دستی می‌ماند (۰ = بی‌سقف)
            "max_auto_ban": 50,
        },
        "retry_errors": {"enabled": False, "every_minutes": 60},
        "backup": {"enabled": False, "time": "02:00"},
    },
    "ui": {"ip_columns": None},
    # پشتیبان‌گیری کانفیگ تجهیزات (روی ابزار SSH)
    "backup": {
        "keep": 10, "timeout": 180,
        "commands": {
            "cisco_ios": "show running-config", "cisco_nxos": "show running-config", "cisco_asa": "show running-config",
            "cisco_xr": "show running-config", "hp_procurve": "show running-config", "mikrotik_routeros": "/export",
            "juniper_junos": "show configuration | display set", "fortinet": "show full-configuration",
            "huawei": "display current-configuration", "paloalto_panos": "show config running", "linux": "",
        },
        # خطوطی که هر بار عوض می‌شوند و در مقایسه نادیده گرفته می‌شوند (regex)
        "ignore_lines": [
            r"^! Last configuration change", r"^! NVRAM config last updated", r"^Current configuration\s*:",
            r"^Building configuration", r"^ntp clock-period", r"^!Time:", r"^!Running configuration last done",
            r"^#config-version=", r"^#conf_file_ver=", r"^#buildno=", r"^#global_vdom=",
            r"^# \w{3}/\d{2}/\d{4} \d", r"^# \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} by RouterOS", r"^## Last commit",
            r"^!Last configuration was updated", r"^!Software Version", r"^\s*$",
        ],
        # مقدارهایی که هر بار با مقدار تازه رمز می‌شوند (مثل ENC در FortiGate)؛ فقط برای مقایسه یکسان می‌شوند
        "mask": [r"\bENC \S+"],
    },
    # به‌روزرسانی آفلاین FortiGate (آخرین گزینه‌های استفاده‌شده)
    # زمان‌بندی اجرای اسکریپت SSH و به‌روزرسانی آفلاین FortiGate (فقط از متدهای ssh_sched_* تغییر می‌کند)
    "ssh_schedules": [],
    "fgupdate": {"source": "local", "folder": "", "tftp_ip": "", "tftp_port": 69, "multi_vdom": True, "vdom": "root",
                 "delay": 5, "timeout": 600, "packages": None},
    # اعلان ایمیلی
    "notify": {
        "enabled": False, "host": "", "port": 587, "security": "starttls", "verify_ssl": True,
        "username": "", "from_addr": "", "to": [], "throttle_minutes": 15, "timeout": 20,
        "events": {"approval": True, "run_error": True, "ban_failed": True, "ssh_failed": True,
                   "backup_failed": True, "config_changed": True, "abuse_quota": True, "scan_new": True,
                   "mon_down": True, "mon_up": True, "mon_alarm": True, "asset_change": True, "abuse_repeat": True,
                   "health": True, "dev_event": True, "mon_cert": True, "security_update": True},
    },
}

SECRET_KEYS = {
    "splunk": ["token", "password"],
    "abuseipdb": ["token", "password", "extra_tokens"],   # extra_tokens: کلیدهای اضافه، هر خط یکی
    "fortigate": ["token", "password"],
    "redmine": ["token", "password"],
    "notify": ["password"],
    **{c: ["token", "password"] for c in FG_EXTRA},
}


def _host_of(address: str) -> str:
    a = (address or "").strip()
    if not a:
        return ""
    if "://" not in a:
        a = "https://" + a
    try:
        return urlsplit(a).hostname or ""
    except ValueError:
        return ""


def _resolve(address: str) -> list:
    """آدرس (IP، نام، یا URL) → فهرست IPها. خطای DNS = فهرست خالی."""
    host = _host_of(address)
    if not host:
        return []
    try:
        return [ipaddress.ip_address(host)]
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None)
    except (OSError, UnicodeError):
        return []
    out = []
    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0].split("%")[0])
        except ValueError:
            continue
        if ip not in out:
            out.append(ip)
    return out


def _parse_net(line):
    s = str(line).split("#", 1)[0].strip()
    if not s:
        return None
    try:
        return ipaddress.ip_network(s, strict=False)
    except ValueError:
        return None


def _net_key(line):
    n = _parse_net(line)
    return str(n) if n else str(line).strip()


def _merge(base, over):
    if isinstance(base, dict) and isinstance(over, dict):
        out = dict(base)
        for k, v in over.items():
            out[k] = _merge(base.get(k), v) if k in base else v
        return out
    return copy.deepcopy(over) if over is not None else copy.deepcopy(base)


import re as _re
_INVISIBLE = _re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff\u00a0]")


def clean_secret(key, value):
    """
    توکن/کلید API: همه‌ی فاصله‌ها، خط‌های جدید و کاراکترهای نامرئی (RLM، ZWNJ، BOM و ...) حذف می‌شوند؛
    کلید API هیچ‌وقت فاصله ندارد و این کاراکترها هنگام کپی‌کردن، به‌خصوص در محیط فارسی، همراه متن می‌آیند.
    پسورد: فقط کاراکترهای نامرئی و خط جدید انتهایی حذف می‌شوند (فاصله در پسورد ممکن است عمدی باشد).
    """
    v = str(value or "")
    if key == "extra_tokens":     # چند کلید: هر کدام مثل token تمیز، هر خط یکی، بدون تکرار
        parts = _re.split(r"[\s,;]+", _INVISIBLE.sub("", v))
        return "\n".join(dict.fromkeys(p for p in parts if p))
    if key == "token":
        return _re.sub(r"\s+", "", _INVISIBLE.sub("", v))
    return _INVISIBLE.sub("", v).rstrip("\r\n")


TEMPLATE_KEYS = ("subject", "tracker", "priority", "category", "assign_to_me", "description_template", "tracker_values",
                 "attach_splunk_csv", "attach_abuse_report", "attach_fortigate_report")


def legacy_template(rcfg):
    """قالب «پیش‌فرض» از تنظیمات تک‌قالبی قبلی (مهاجرت 1.12)."""
    t = {"id": "default", "name": "پیش‌فرض"}
    for k in TEMPLATE_KEYS:
        t[k] = copy.deepcopy(rcfg.get(k, DEFAULTS["redmine"].get(k)))
    return t


class Settings:
    def __init__(self):
        self.path = paths.data_dir() / "settings.dat"          # رمزشده (atrest)
        self.legacy_path = paths.data_dir() / "settings.json"  # نسخه‌های قبل از 1.0.1، ساده
        self._lock = threading.RLock()
        self.data = copy.deepcopy(DEFAULTS)
        fresh = not self.path.exists() and not self.legacy_path.exists()
        self.load()
        if fresh and paths.ui_lang() == "en":
            self.data["redmine"].update(subject=REDMINE_SUBJECT_EN, description_template=REDMINE_DESCRIPTION_EN)
        self._ensure_templates()
        if fresh and paths.ui_lang() == "en":
            for t in self.data["redmine"]["templates"]:
                if t.get("id") == "default":
                    t["name"] = "Default"

    def _ensure_templates(self):
        """نصب تازه یا قدیمی بدون قالب: قالب «پیش‌فرض» از تنظیمات قبلی (روی دیسک با اولین ذخیره)."""
        with self._lock:
            r = self.data.setdefault("redmine", {})
            if not r.get("templates"):
                r["templates"] = [legacy_template(r)]
            ids = [t.get("id") for t in r["templates"]]
            if r.get("default_template") not in ids:
                r["default_template"] = ids[0]

    def redmine_template(self, tid=None):
        """(قالب، آیا قالب خواسته‌شده پیدا نشد). خالی/ناموجود ← قالب پیش‌فرض."""
        with self._lock:
            r = self.data.get("redmine") or {}
            tpls = r.get("templates") or [legacy_template(r)]
            by = {t.get("id"): t for t in tpls}
            if tid and tid in by:
                return copy.deepcopy(by[tid]), False
            return copy.deepcopy(by.get(r.get("default_template")) or tpls[0]), bool(tid)

    def load(self):
        with self._lock:
            legacy = not self.path.exists() and self.legacy_path.exists()
            src = self.legacy_path if legacy else self.path
            if src.exists():
                try:
                    raw = json.loads(atrest.read_text(src, "utf-8"))
                    self.data = _merge(copy.deepcopy(DEFAULTS), raw)
                    sp = self.data.get("splunk") or {}
                    # مهاجرت تنظیمات نصب‌های قدیمی: اپ پیش‌فرض Splunk به search
                    if sp.get("app") == "DA-ESS-ContentUpdate" and not sp.get("_app_v094"):
                        sp["app"] = "search"
                        sp["_app_v094"] = True
                        self.data["splunk"] = sp
                        self.save()
                    if isinstance(raw, dict) and not raw.get("_pin_v1262"):
                        # 1.26.2: پین گواهی پیش‌فرض روشن فقط برای نصب تازه؛ نصب‌های قبلی همان رفتار قبلی را نگه می‌دارند
                        # (وگرنه کارهای زمان‌بندی‌شده تا تأیید اثر انگشت متوقف می‌شدند)
                        for conn in ("splunk", "fortigate"):
                            if "pin_cert" not in (raw.get(conn) or {}):
                                self.data.setdefault(conn, {})["pin_cert"] = False
                        self.data["_pin_v1262"] = True
                        self.save()
                    if any(isinstance(t, dict) and "code" not in t for t in self.data.get("fg_scenarios") or []):
                        from . import fgtask       # 1.29: تسک‌های گام‌به‌گام 1.28 ← کد پایتون
                        self.data["fg_scenarios"] = [fgtask.from_steps(t) if isinstance(t, dict) and "code" not in t else t
                                                     for t in self.data["fg_scenarios"]]
                        self.save()
                    fgc = self.data.get("fortigate") or {}
                    # مهاجرت تنظیمات نصب‌های قدیمی: افزودن رنج‌های غیرعمومی (یک بار؛ بعد از آن انتخاب کاربر حفظ می‌شود)
                    if not fgc.get("_ignore_v098"):
                        cur = list(fgc.get("ignore_networks") or [])
                        have = {_net_key(x) for x in cur}
                        cur += [n for n in NONPUBLIC_NETWORKS if _net_key(n) not in have]
                        fgc.update(ignore_networks=cur, _ignore_v098=True)
                        self.data["fortigate"] = fgc
                        self.save()
                except Exception:
                    log.exception("فایل تنظیمات خراب است؛ از پیش‌فرض استفاده می‌شود")
                    bad = src.with_name(src.stem + ".bad" + src.suffix)
                    try:
                        os.replace(src, bad)
                    except OSError:
                        pass
                    self.data = copy.deepcopy(DEFAULTS)
                    legacy = False
            if legacy:
                self.save()
                from . import wipe
                wipe.overwrite(self.legacy_path)
                self.legacy_path.unlink()

    def save(self):
        with self._lock:
            atrest.write_text(self.path, json.dumps(self.data, ensure_ascii=False, indent=2))

    def get(self, *keys, default=None):
        with self._lock:
            cur = self.data
            for k in keys:
                if not isinstance(cur, dict) or k not in cur:
                    return default
                cur = cur[k]
            return copy.deepcopy(cur)

    # ---------------------------------------------------------------- secrets (در vault)
    vault = None

    def attach_vault(self, vault):
        self.vault = vault

    def secret(self, conn: str, key: str) -> str:
        return self.vault.get(f"{conn}.{key}", "") if self.vault else ""

    # ---------------------------------------------------------------- محافظت از سرورهای خود برنامه
    def protect_host(self, host: str, label: str) -> list:
        """
        IP(های) host را، اگر در رنج‌های مستثنا نباشد، با برچسب به فیلد اضافه می‌کند.
        هر IP فقط یک بار خودکار اضافه می‌شود؛ اگر کاربر بعداً حذفش کند، دوباره اضافه نمی‌شود.
        """
        ips = _resolve(host)
        if not ips:
            return []
        with self._lock:
            fgc = self.data.setdefault("fortigate", {})
            cur = list(fgc.get("ignore_networks") or [])
            done = list(fgc.get("ignore_auto") or [])
            nets = [n for n in (_parse_net(x) for x in cur) if n is not None]
            added = []
            for ip in ips:
                key = f"{ip}/{ip.max_prefixlen}"
                if key in done:
                    continue
                done.append(key)
                if any(ip.version == n.version and ip in n for n in nets):
                    continue
                cur.append(f"{key}  # {label}")
                added.append(key)
            fgc["ignore_networks"], fgc["ignore_auto"] = cur, done
            self.save()
        if added:
            log.info("رنج مستثنا برای %s اضافه شد: %s", label, added)
        return added

    def protect_servers(self) -> list:
        added = []
        for conn, key, label in PROTECT_CONNS:
            host = self.get(conn, key, default="") or ""
            if host.strip():
                added += self.protect_host(host, label)
        return added

    def set_recovery(self, rec: dict | None):
        """رکورد کد بازیابی (vault/recovery)؛ None = حذف. فقط از Vault (نه از فرم تنظیمات)."""
        with self._lock:
            sec = self.data.setdefault("security", {})
            if rec:
                sec["recovery"] = copy.deepcopy(rec)
            else:
                sec.pop("recovery", None)
            self.save()

    def set_redmine_meta(self, meta: dict | None):
        with self._lock:
            sub = self.data.setdefault("redmine", {})
            if meta:
                sub["meta"] = copy.deepcopy(meta)
            else:
                sub.pop("meta", None)
            self.save()

    def set_ssh_schedules(self, items: list):
        with self._lock:
            self.data["ssh_schedules"] = copy.deepcopy(items)
            self.save()

    def set_server(self, cfg: dict):
        with self._lock:
            self.data["server"] = {**(self.data.get("server") or {}), **copy.deepcopy(cfg)}
            self.save()

    def set_ad(self, cfg: dict):
        with self._lock:
            self.data["ad"] = copy.deepcopy(cfg)
            self.save()

    def set_users(self, items: list):
        with self._lock:
            self.data["users"] = copy.deepcopy(items)
            self.save()

    def set_jobs(self, items: list, migrated=None):
        with self._lock:
            self.data["jobs"] = copy.deepcopy(items)
            if migrated is not None:
                self.data["jobs_migrated"] = bool(migrated)
            self.save()

    def set_user_ui(self, username: str, key: str, value):
        """ترجیحات نمایش هر کاربر (زبان، ستون‌ها، تقویم) جدا از بقیه."""
        with self._lock:
            uu = self.data.setdefault("ui_users", {})
            uu.setdefault(username, {})[key] = value
            self.save()

    def update_job(self, jid: str, **fields):
        with self._lock:
            for j in self.data.get("jobs") or []:
                if j.get("id") == jid:
                    j.update(fields)
            self.save()

    def update_ssh_schedule(self, sid: str, **fields):
        with self._lock:
            for s in self.data.get("ssh_schedules") or []:
                if s.get("id") == sid:
                    s.update(fields)
            self.save()

    # ---------------------------------------------------------------- چند FortiGate (1.28)
    def fg_devices(self) -> list:
        """[{conn, name}] به ترتیب؛ اولی همیشه «fortigate»."""
        with self._lock:
            out = [{"conn": "fortigate", "name": str((self.data.get("fortigate") or {}).get("name") or "").strip() or "FortiGate 1"}]
            for i, c in enumerate(FG_EXTRA, 2):
                d = self.data.get(c)
                if isinstance(d, dict):
                    out.append({"conn": c, "name": str(d.get("name") or "").strip() or f"FortiGate {i}"})
            return out

    def fg_add_device(self, name: str = "") -> str:
        with self._lock:
            free = next((c for c in FG_EXTRA if not isinstance(self.data.get(c), dict)), None)
            if not free:
                raise ValueError("full")
            base = DEFAULTS["fortigate"]
            dev = {k: copy.deepcopy(base[k]) for k in FG_DEV_FIELDS if k in base}
            dev.update(name=str(name or "").strip()[:60] or f"FortiGate {FG_EXTRA.index(free) + 2}", pin_cert=True)
            self.data[free] = dev
            self.save()
            return free

    def fg_delete_device(self, conn: str):
        if conn not in FG_EXTRA:
            raise ValueError(conn)
        if self.vault:
            self.vault.set_many({f"{conn}.{k}": "" for k in SECRET_KEYS[conn]})
        with self._lock:
            self.data.pop(conn, None)
            self.save()

    def set_cert_pin(self, conn: str, pin: dict | None):
        """ذخیره یا حذف پین گواهی TLS یک اتصال ({"host": "h:p", "sha256": hex})."""
        if conn not in PIN_CONNS or (conn in FG_EXTRA and not isinstance(self.data.get(conn), dict)):
            raise ValueError(conn)
        with self._lock:
            sub = self.data.setdefault(conn, {})
            if pin:
                sub["cert_pin"] = {"host": pin["host"], "sha256": pin["sha256"], "at": time.time()}
            else:
                sub.pop("cert_pin", None)
            self.save()

    def conn_config(self, conn: str, override: dict | None = None) -> dict:
        """پیکربندی کامل یک اتصال به‌همراه اسرار رمزگشایی‌شده (فقط برای استفاده در بک‌اند)."""
        cfg = self.get(conn) or {}
        if conn in FG_EXTRA:
            main = self.get("fortigate") or {}
            cfg.update({k: main.get(k) for k in FG_SHARED})
        if conn == "fortigate" or conn in FG_EXTRA:
            cfg["_conn"] = conn
        for k in SECRET_KEYS.get(conn, []):
            cfg[k] = clean_secret(k, self.secret(conn, k))
        if override:
            # اگر مقصد (آدرس/هاست/پورت) با مقدار ذخیره‌شده فرق کند، اسرار ذخیره‌شده به مقصد تازه فرستاده نمی‌شوند؛
            # باید دوباره وارد شوند (اسرار در رابط فقط‌نوشتنی‌اند و نباید با عوض کردن آدرس به سرور دیگری لو بروند)
            dest = ("address", "host", "port")
            if any(k in override and str(override.get(k) or "").strip() != str(cfg.get(k) or "").strip()
                   for k in dest if str(cfg.get(k) or "").strip()):
                for k in SECRET_KEYS.get(conn, []):
                    cfg[k] = ""
            for k, v in override.items():
                if k in SECRET_KEYS.get(conn, []):
                    if v == "__clear__":
                        cfg[k] = ""
                        continue
                    if not v:
                        continue  # خالی = همان مقدار ذخیره‌شده
                    v = clean_secret(k, v)
                cfg[k] = v
        return cfg

    # ---------------------------------------------------------------- public
    def public(self) -> dict:
        with self._lock:
            d = copy.deepcopy(self.data)
        d.pop("secrets", None)
        d.pop("users", None)
        (d.get("security") or {}).pop("recovery", None)     # 1.27.8: فقط وضعیتش از security_status
        for conn, keys in SECRET_KEYS.items():
            if conn in FG_EXTRA and not isinstance(d.get(conn), dict):
                continue
            for k in keys:
                d.setdefault(conn, {})[f"has_{k}"] = bool(self.vault and self.vault.has(f"{conn}.{k}"))
        try:      # فقط تعداد کلیدهای اضافه (خود کلیدها هرگز به رابط نمی‌روند)
            extra = self.vault.get("abuseipdb.extra_tokens", "") if self.vault and d["abuseipdb"].get("has_extra_tokens") else ""
            d["abuseipdb"]["extra_tokens_count"] = len([x for x in str(extra or "").split("\n") if x.strip()])
        except Exception:
            d["abuseipdb"]["extra_tokens_count"] = 0
        return d

    def update(self, patch: dict):
        """به‌روزرسانی از UI. کلیدهای اسرار (token/password) جدا رمزنگاری می‌شوند."""
        with self._lock:
            patch = copy.deepcopy(patch or {})
            patch.pop("secrets", None)
            patch.pop("has_password", None)
            patch.pop("ssh_schedules", None)
            patch.pop("jobs", None)
            patch.pop("users", None)
            patch.pop("server", None)
            patch.pop("jobs_migrated", None)
            patch.pop("ui_users", None)
            for conn in PIN_CONNS:   # پین گواهی فقط از مسیر set_cert_pin عوض می‌شود، نه از فرم
                if isinstance(patch.get(conn), dict):
                    patch[conn].pop("cert_pin", None)
            for c in FG_EXTRA:     # دستگاه FortiGate تازه فقط از fg_add_device؛ از فرم فقط فیلدهای همان دستگاه
                if c in patch:
                    sub = patch.pop(c)
                    if isinstance(sub, dict) and isinstance(self.data.get(c), dict):
                        patch[c] = {k: v for k, v in sub.items() if k in FG_DEV_FIELDS or k in SECRET_KEYS[c]}
            if isinstance(patch.get("redmine"), dict):   # اطلاعات فیلدها فقط از set_redmine_meta
                patch["redmine"].pop("meta", None)
            changes = {}
            for conn, keys in SECRET_KEYS.items():
                sub = patch.get(conn)
                if not isinstance(sub, dict):
                    continue
                for k in keys:
                    sub.pop(f"has_{k}", None)
                    if k in sub:
                        v = sub.pop(k)
                        if v == "__clear__":
                            changes[f"{conn}.{k}"] = ""
                        elif v:
                            changes[f"{conn}.{k}"] = clean_secret(k, v)
            if changes:
                if not self.vault:
                    raise RuntimeError("vault وصل نیست")
                self.vault.set_many(changes)   # اگر قفل باشد VaultLocked می‌دهد و چیزی ذخیره نمی‌شود
            old_hosts = {(c, k): str((self.data.get(c) or {}).get(k) or "").strip() for c, k, _ in PROTECT_CONNS}
            self.data = _merge(self.data, patch)
            self._ensure_templates()
            self.save()
        # 1.27.3: فقط آدرسی که واقعاً عوض شده resolve می‌شود (قبلاً با هر ذخیره‌ی فرم همه‌ی نام‌ها DNS می‌شدند؛
        # نامی که resolve نمی‌شد ذخیره‌ی تنظیمات را چند ثانیه نگه می‌داشت — memdiag: save_settings=5.4s)
        added = []
        for c, k, label in PROTECT_CONNS:
            if isinstance(patch.get(c), dict) and k in patch[c]:
                host = str(self.get(c, k, default="") or "").strip()
                if host and host != old_hosts[(c, k)]:
                    added += self.protect_host(host, label)
        return added
