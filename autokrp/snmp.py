"""
SNMP v2c / v3 برای مانیتورینگ (کتابخانه‌ی pysnmp، پایتون خالص؛ داخل exe بسته‌بندی می‌شود).

- Client: یک حلقه‌ی asyncio در ترد جدا؛ برای هر پروفایل اعتبارنامه یک SnmpEngine جدا (کاربر v3 هم‌نام با رمز
  متفاوت روی دو پروفایل با هم قاطی نمی‌شود). همه‌ی OIDها عددی‌اند (lookupMib=False؛ هیچ فایل MIB لازم نیست).
- collect(): خواندن یک دستگاه: system، CPU، حافظه، دیسک، دما/فن/منبع تغذیه، پورت‌ها و OIDهای دستی.
  OIDها و مقدارهای enum از فایل‌های MIB واقعی (CISCO-PROCESS/ENHANCED-MEMPOOL/MEMORY-POOL/ENVMON/ENTITY-SENSOR،
  FORTINET-FORTIGATE، EXTREME-SYSTEM/SOFTWARE-MONITOR، UCD-SNMP، HOST-RESOURCES، IF-MIB، ENTITY-MIB) با snmptranslate
  استخراج شده‌اند، نه از حافظه.
- SnmpRuntime: نرخ ترافیک از تفاضل شمارنده‌ها، آستانه‌ها و هشدار (با چند بار تکرار پیش از هشدار)، داده‌ی زنده برای
  رابط و ذخیره‌ی سری زمانی رمزشده (۵ دقیقه‌ای و ساعتی) در monitor/snmp/<id>/.
"""
import asyncio
import base64
import concurrent.futures
import hashlib
import ipaddress
import json
import logging
import math
import random
import re
import threading
import time
import zlib
from collections import OrderedDict, deque

from . import atrest

log = logging.getLogger(__name__)


class SnmpError(Exception):
    """خطای قابل نمایش (فارسی)."""


# ---------------------------------------------------------------------------- OIDها (از MIB واقعی)
SYS = {"descr": "1.3.6.1.2.1.1.1.0", "objid": "1.3.6.1.2.1.1.2.0", "uptime": "1.3.6.1.2.1.1.3.0",
       "contact": "1.3.6.1.2.1.1.4.0", "name": "1.3.6.1.2.1.1.5.0", "location": "1.3.6.1.2.1.1.6.0"}
ENT_NAME = "1.3.6.1.2.1.47.1.1.1.1.7"                 # ENTITY-MIB::entPhysicalName
# IF-MIB
IF_T = {"descr": "1.3.6.1.2.1.2.2.1.2", "type": "1.3.6.1.2.1.2.2.1.3", "speed": "1.3.6.1.2.1.2.2.1.5",
        "admin": "1.3.6.1.2.1.2.2.1.7", "oper": "1.3.6.1.2.1.2.2.1.8", "in32": "1.3.6.1.2.1.2.2.1.10",
        "indisc": "1.3.6.1.2.1.2.2.1.13", "inerr": "1.3.6.1.2.1.2.2.1.14", "out32": "1.3.6.1.2.1.2.2.1.16",
        "outdisc": "1.3.6.1.2.1.2.2.1.19", "outerr": "1.3.6.1.2.1.2.2.1.20"}
IF_X = {"name": "1.3.6.1.2.1.31.1.1.1.1", "in64": "1.3.6.1.2.1.31.1.1.1.6", "out64": "1.3.6.1.2.1.31.1.1.1.10",
        "hspeed": "1.3.6.1.2.1.31.1.1.1.15", "alias": "1.3.6.1.2.1.31.1.1.1.18"}
# Cisco
CPM = {"phys": "1.3.6.1.4.1.9.9.109.1.1.1.1.2", "s5": "1.3.6.1.4.1.9.9.109.1.1.1.1.6",
       "m1": "1.3.6.1.4.1.9.9.109.1.1.1.1.7", "m5": "1.3.6.1.4.1.9.9.109.1.1.1.1.8"}
CEMP = {"type": "1.3.6.1.4.1.9.9.221.1.1.1.1.2", "name": "1.3.6.1.4.1.9.9.221.1.1.1.1.3",
        "used": "1.3.6.1.4.1.9.9.221.1.1.1.1.7", "free": "1.3.6.1.4.1.9.9.221.1.1.1.1.8",
        "hcused": "1.3.6.1.4.1.9.9.221.1.1.1.1.18", "hcfree": "1.3.6.1.4.1.9.9.221.1.1.1.1.20"}
CMP = {"name": "1.3.6.1.4.1.9.9.48.1.1.1.2", "used": "1.3.6.1.4.1.9.9.48.1.1.1.5", "free": "1.3.6.1.4.1.9.9.48.1.1.1.6"}
ENV_TEMP = {"descr": "1.3.6.1.4.1.9.9.13.1.3.1.2", "value": "1.3.6.1.4.1.9.9.13.1.3.1.3",
            "thr": "1.3.6.1.4.1.9.9.13.1.3.1.4", "state": "1.3.6.1.4.1.9.9.13.1.3.1.6"}
ENV_FAN = {"descr": "1.3.6.1.4.1.9.9.13.1.4.1.2", "state": "1.3.6.1.4.1.9.9.13.1.4.1.3"}
ENV_PSU = {"descr": "1.3.6.1.4.1.9.9.13.1.5.1.2", "state": "1.3.6.1.4.1.9.9.13.1.5.1.3"}
CSENS = {"type": "1.3.6.1.4.1.9.9.91.1.1.1.1.1", "scale": "1.3.6.1.4.1.9.9.91.1.1.1.1.2",
         "prec": "1.3.6.1.4.1.9.9.91.1.1.1.1.3", "value": "1.3.6.1.4.1.9.9.91.1.1.1.1.4",
         "status": "1.3.6.1.4.1.9.9.91.1.1.1.1.5"}
# ENTITY-SENSOR-MIB (استاندارد؛ برای دستگاه‌های دیگر)
ESENS = {"type": "1.3.6.1.2.1.99.1.1.1.1", "scale": "1.3.6.1.2.1.99.1.1.1.2", "prec": "1.3.6.1.2.1.99.1.1.1.3",
         "value": "1.3.6.1.2.1.99.1.1.1.4", "status": "1.3.6.1.2.1.99.1.1.1.5"}
# Cisco قدیمی: CISCO-PROCESS-MIB پیش از 12.2(3.5) (بدون Rev، طبق سند Cisco «Collect CPU Utilization on Cisco IOS Devices with SNMP»)
# و OLD-CISCO-CPU-MIB (avgBusy1/avgBusy5، اسکالر) برای دستگاه‌هایی که CISCO-PROCESS-MIB ندارند
CPM_OLD = {"s5": "1.3.6.1.4.1.9.9.109.1.1.1.1.3", "m1": "1.3.6.1.4.1.9.9.109.1.1.1.1.4", "m5": "1.3.6.1.4.1.9.9.109.1.1.1.1.5"}
OLD_BUSY = {"m1": "1.3.6.1.4.1.9.2.1.57.0", "m5": "1.3.6.1.4.1.9.2.1.58.0"}
# Juniper: JUNIPER-MIB::jnxOperatingTable («صفر یعنی نامعلوم یا نامربوط»؛ سند Juniper «Health monitoring with SNMP»: CPU و حافظه‌ی Routing Engine)
JNX_OP = {"descr": "1.3.6.1.4.1.2636.3.1.13.1.5", "state": "1.3.6.1.4.1.2636.3.1.13.1.6", "temp": "1.3.6.1.4.1.2636.3.1.13.1.7",
          "cpu": "1.3.6.1.4.1.2636.3.1.13.1.8", "buffer": "1.3.6.1.4.1.2636.3.1.13.1.11", "memory": "1.3.6.1.4.1.2636.3.1.13.1.15"}
# JUNIPER-MIB::jnxOperatingState: unknown(1) running(2) ready(3) reset(4) runningAtFullSpeed(5) down(6) standby(7)
JNX_STATE = {1: "unknown", 2: "running", 3: "ready", 4: "reset", 5: "runningAtFullSpeed", 6: "down", 7: "standby"}
JNX_LEVEL = {1: "unknown", 2: "ok", 3: "ok", 4: "warn", 5: "warn", 6: "down", 7: "ok"}
# MikroTik: MIKROTIK-MIB::mtxrGaugeTable (unit: celsius(1) rpm(2) dV(3) dA(4) dW(5) status(6)) و mtxrHl* قدیمی.
# طبق راهنمای رسمی MikroTik (Health) دما در SNMP «ضرب در ۱۰» است؛ ولتاژ dV.
MT_GAUGE = {"name": "1.3.6.1.4.1.14988.1.1.3.100.1.2", "value": "1.3.6.1.4.1.14988.1.1.3.100.1.3", "unit": "1.3.6.1.4.1.14988.1.1.3.100.1.4"}
MT_HL = {"temp": "1.3.6.1.4.1.14988.1.1.3.10.0", "cpu_temp": "1.3.6.1.4.1.14988.1.1.3.11.0"}
# HP ProLiant: CPQHLTH-MIB (condition: other(1) ok(2) degraded(3) failed(4)؛ present: other(1) absent(2) present(3))
HP_TEMP = {"locale": "1.3.6.1.4.1.232.6.2.6.8.1.3", "value": "1.3.6.1.4.1.232.6.2.6.8.1.4", "thr": "1.3.6.1.4.1.232.6.2.6.8.1.5",
           "cond": "1.3.6.1.4.1.232.6.2.6.8.1.6"}
HP_FAN = {"locale": "1.3.6.1.4.1.232.6.2.6.7.1.3", "present": "1.3.6.1.4.1.232.6.2.6.7.1.4", "cond": "1.3.6.1.4.1.232.6.2.6.7.1.9"}
HP_PSU = {"bay": "1.3.6.1.4.1.232.6.2.9.3.1.2", "present": "1.3.6.1.4.1.232.6.2.9.3.1.3", "cond": "1.3.6.1.4.1.232.6.2.9.3.1.4"}
HP_COND = {1: "ok", 2: "ok", 3: "warn", 4: "crit"}
HP_LOCALE = {1: "Other", 2: "Unknown", 3: "System", 4: "System board", 5: "I/O board", 6: "CPU", 7: "Memory", 8: "Storage",
             9: "Removable media", 10: "Power supply", 11: "Ambient", 12: "Chassis", 13: "Bridge card"}
# FortiGate (اسکالرها با .0)
FG = {"ver": "1.3.6.1.4.1.12356.101.4.1.1.0", "cpu": "1.3.6.1.4.1.12356.101.4.1.3.0", "mem": "1.3.6.1.4.1.12356.101.4.1.4.0",
      "memcap": "1.3.6.1.4.1.12356.101.4.1.5.0", "disk": "1.3.6.1.4.1.12356.101.4.1.6.0",
      "diskcap": "1.3.6.1.4.1.12356.101.4.1.7.0", "sess": "1.3.6.1.4.1.12356.101.4.1.8.0"}
FG_HW = {"name": "1.3.6.1.4.1.12356.101.4.3.2.1.2", "value": "1.3.6.1.4.1.12356.101.4.3.2.1.3",
         "alarm": "1.3.6.1.4.1.12356.101.4.3.2.1.4"}
# Extreme
EX = {"cpu": "1.3.6.1.4.1.1916.1.32.1.2.0", "temp": "1.3.6.1.4.1.1916.1.1.1.8.0", "overtemp": "1.3.6.1.4.1.1916.1.1.1.7.0"}
EX_MEM = {"total": "1.3.6.1.4.1.1916.1.32.2.2.1.2", "free": "1.3.6.1.4.1.1916.1.32.2.2.1.3"}   # رشته، کیلوبایت
EX_FAN = "1.3.6.1.4.1.1916.1.1.1.9.1.2"        # TruthValue: true(1) false(2)
EX_PSU = "1.3.6.1.4.1.1916.1.1.1.27.1.2"       # notPresent(1) presentOK(2) presentNotOK(3) presentPowerOff(4)
# Linux (net-snmp) / Windows / عمومی
UCD = {"idle": "1.3.6.1.4.1.2021.11.11.0", "total": "1.3.6.1.4.1.2021.4.5.0", "avail": "1.3.6.1.4.1.2021.4.6.0",
       "buffer": "1.3.6.1.4.1.2021.4.14.0", "cached": "1.3.6.1.4.1.2021.4.15.0", "load1": "1.3.6.1.4.1.2021.10.1.3.1"}
HR_CPU = "1.3.6.1.2.1.25.3.3.1.2"
HR_ST = {"type": "1.3.6.1.2.1.25.2.3.1.2", "descr": "1.3.6.1.2.1.25.2.3.1.3", "units": "1.3.6.1.2.1.25.2.3.1.4",
         "size": "1.3.6.1.2.1.25.2.3.1.5", "used": "1.3.6.1.2.1.25.2.3.1.6"}
HR_RAM, HR_DISK = "1.3.6.1.2.1.25.2.1.2", "1.3.6.1.2.1.25.2.1.4"

VENDORS = [("1.3.6.1.4.1.9.", "cisco"), ("1.3.6.1.4.1.12356.", "fortinet"), ("1.3.6.1.4.1.1916.", "extreme"),
           ("1.3.6.1.4.1.2636.", "juniper"), ("1.3.6.1.4.1.14988.", "mikrotik"), ("1.3.6.1.4.1.232.", "hp"),
           ("1.3.6.1.4.1.8072.", "linux")]
VENDOR_NAMES = {"auto": "تشخیص خودکار", "cisco": "Cisco", "fortinet": "FortiGate", "linux": "Linux (net-snmp)",
                "juniper": "Juniper", "mikrotik": "MikroTik", "hp": "HP ProLiant (iLO)",
                "extreme": "Extreme", "generic": "عمومی (استانداردها)"}
# CISCO-ENVMON-MIB CiscoEnvMonState
ENV_STATE = {1: "ok", 2: "warn", 3: "crit", 4: "crit", 5: "absent", 6: "crit"}
IF_OPER = {1: "up", 2: "down", 3: "testing", 4: "unknown", 5: "dormant", 6: "notPresent", 7: "lowerLayerDown"}

AUTH_PROTOS = [("none", "بدون احراز هویت (noAuth)"), ("MD5", "MD5"), ("SHA", "SHA-1"), ("SHA224", "SHA-224"),
               ("SHA256", "SHA-256"), ("SHA384", "SHA-384"), ("SHA512", "SHA-512")]
PRIV_PROTOS = [("none", "بدون رمزنگاری (noPriv)"), ("DES", "DES"), ("3DES", "3DES"), ("AES128", "AES-128"),
               ("AES192", "AES-192 (استاندارد)"), ("AES256", "AES-256 (استاندارد)"),
               ("AES192C", "AES-192 (Cisco)"), ("AES256C", "AES-256 (Cisco)")]
_OID_RE = re.compile(r"^\.?1(\.(0|[1-9]\d{0,9})){1,127}$")
MAX_OIDS = 40
MAX_IFS = 1024           # پورت‌های هر دستگاه در جدول زنده
MAX_IF_HIST = 256        # پورت‌هایی که سری زمانی ذخیره می‌کنند
TH_KEYS = ("cpu", "mem", "disk", "temp", "util", "err")
TH_DEFAULT = {"cpu": [80, 95], "mem": [85, 95], "disk": [85, 95], "temp": [None, None], "util": [80, 95], "err": [10, 100]}
LOCAL_CONCURRENCY = 64         # 1.34: خواندن هم‌زمان در حلقه‌ی درون برنامه (بدون کارگر)
MIN_INTERVAL_SNMP = 30         # سند Cisco: poll پرتکرار بار CPU دستگاه را بالا می‌برد
# مسیرهای مجازی لینوکس در hrStorage (snap همیشه ۱۰۰٪، tmpfs و …) هشدار کاذب دیسک می‌دادند
_PSEUDO_FS = re.compile(r"^/(snap|run|dev|sys|proc|var/lib/(docker|containers|kubelet)|var/snap)(/|$)")
TH_TITLES = {"cpu": "CPU (٪)", "mem": "حافظه (٪)", "disk": "دیسک (٪)", "temp": "دما (°C)",
             "util": "مصرف پورت (٪ سرعت)", "err": "خطای پورت (در دقیقه)"}


def norm_oid(s):
    s = str(s or "").strip()
    if not _OID_RE.match(s):
        raise SnmpError(f"OID نامعتبر است: {s[:60] or '(خالی)'} (فقط عدد و نقطه، مثل 1.3.6.1.2.1.1.3.0)")
    return s.lstrip(".")


def oid_t(s):
    return tuple(int(x) for x in s.split("."))


# ---------------------------------------------------------------------------- مقدارها و خطاها
_TXT_OK = re.compile(r"^[\t\r\n\x20-\x7e -￿]*$")


def conv(v):
    """(مقدار پایتون، نام نوع). None یعنی نبود مقدار."""
    tn = v.__class__.__name__
    if tn in ("NoSuchObject", "NoSuchInstance", "EndOfMibView", "Null"):
        return None, tn
    if tn in ("Integer", "Integer32", "Unsigned32", "Gauge32", "Counter32", "Counter64", "TimeTicks"):
        return int(v), tn
    if tn in ("ObjectIdentifier", "ObjectName"):
        return str(v), tn
    if tn == "IpAddress":
        return ".".join(str(b) for b in bytes(v.asOctets())), tn
    try:
        b = bytes(v.asOctets())
    except Exception:
        return str(v.prettyPrint()), tn
    try:
        s = b.decode("utf-8")
        if _TXT_OK.match(s):
            return s.rstrip("\x00"), tn
    except UnicodeDecodeError:
        pass
    return ":".join(f"{x:02x}" for x in b), tn


_ERRS = {
    "RequestTimedOut": "دستگاه به SNMP پاسخ نداد (آدرس، پورت UDP، community/کاربر، ACL یا فایروال را بررسی کنید)",
    "WrongDigest": "احراز هویت SNMPv3 رد شد (رمز auth یا الگوریتم auth اشتباه است)",
    "UnknownUserName": "این کاربر SNMPv3 روی دستگاه تعریف نشده است",
    "UnknownSecurityName": "این کاربر SNMPv3 روی دستگاه تعریف نشده است",
    "UnsupportedSecurityLevel": "سطح امنیتی (auth/priv) با تنظیم کاربر روی دستگاه جور نیست",
    "DecryptionError": "رمزگشایی پاسخ ناموفق بود (رمز priv یا الگوریتم رمزنگاری؛ برای AES-192/256 نوع Cisco را امتحان کنید)",
    "NotInTimeWindow": "زمان SNMPv3 دستگاه هماهنگ نشد؛ دوباره امتحان کنید",
    "UnknownEngineID": "شناسه‌ی موتور SNMPv3 دستگاه پیدا نشد",
}
_STATUS = {1: "پاسخ برای یک بسته‌ی UDP بزرگ است (tooBig)", 2: "OID پیدا نشد", 5: "خطای عمومی دستگاه (genErr)",
           6: "دسترسی به این OID مجاز نیست (noAccess)", 16: "این کاربر/community به این بخش دسترسی ندارد (view)"}


def _err(ei, cred=None):
    name = ei.__class__.__name__
    msg = _ERRS.get(name) or f"خطای SNMP: {ei}"
    if name == "RequestTimedOut" and cred and cred.get("v") == "3" and (cred.get("priv") or "none") != "none":
        msg += ". در v3 رمز یا الگوریتم priv اشتباه هم همین نتیجه را می‌دهد (برای AES-192/256 نوع «Cisco» و «استاندارد» را امتحان کنید)"
    return SnmpError(msg)


# ---------------------------------------------------------------------------- کلاینت
class Client:
    """حلقه‌ی asyncio اختصاصی SNMP؛ از هر ترد با run() صدا زده می‌شود."""
    ENGINE_MAX = 64

    STATIC_TTL = 1200          # 1.34: داده‌ی ثابت پورت‌ها/ENTITY (نام، alias، سرعت، نوع) هر ۲۰ دقیقه (± پخش) دوباره خوانده می‌شود

    def __init__(self):
        self._loop = None
        self._lock = threading.Lock()
        self._engines = OrderedDict()
        self.static = {}           # (host, port, fp) → {"t", "up", "rows", "has64"} — فقط داخل حلقه‌ی asyncio
        self.names = {}            # (host, port, fp) → {"t", "n": {idx: name}}

    def static_key(self, cred, host, port):
        return (str(host), str(port), self._fp(cred))

    def prune(self, now=None):
        """کش‌های کهنه (دستگاه حذف‌شده یا خاموش) پاک شوند."""
        now = now or time.time()
        for d in (self.static, self.names):
            for k in [k for k, v in d.items() if now - v["t"] > 3 * self.STATIC_TTL]:
                d.pop(k, None)

    def _ensure(self):
        with self._lock:
            if self._loop is None:
                loop = asyncio.new_event_loop()
                threading.Thread(target=loop.run_forever, name="snmp-loop", daemon=True).start()
                self._loop = loop
            return self._loop

    def run(self, coro, timeout):
        fut = asyncio.run_coroutine_threadsafe(coro, self._ensure())
        try:
            return fut.result(timeout)
        except (TimeoutError, concurrent.futures.TimeoutError):
            fut.cancel()
            raise SnmpError("خواندن SNMP بیش از حد طول کشید و متوقف شد")

    def forget(self):
        """تغییر/حذف پروفایل‌ها: موتورها از نو ساخته شوند."""
        loop = self._loop
        if loop is not None:
            loop.call_soon_threadsafe(self._engines.clear)

    # --- داخل حلقه
    @staticmethod
    def _fp(cred):
        return hashlib.sha256(json.dumps(cred, sort_keys=True).encode()).hexdigest()

    def _auth(self, cred):
        from pysnmp.hlapi.v3arch.asyncio import CommunityData, SnmpEngine, UsmUserData
        import pysnmp.hlapi.v3arch.asyncio as H
        fp = self._fp(cred)
        if fp in self._engines:
            self._engines.move_to_end(fp)
            return self._engines[fp]
        if cred.get("v") == "3":
            ap = {"none": H.USM_AUTH_NONE, "MD5": H.USM_AUTH_HMAC96_MD5, "SHA": H.USM_AUTH_HMAC96_SHA,
                  "SHA224": H.USM_AUTH_HMAC128_SHA224, "SHA256": H.USM_AUTH_HMAC192_SHA256,
                  "SHA384": H.USM_AUTH_HMAC256_SHA384, "SHA512": H.USM_AUTH_HMAC384_SHA512}[cred.get("auth") or "none"]
            pp = {"none": H.USM_PRIV_NONE, "DES": H.USM_PRIV_CBC56_DES, "3DES": H.USM_PRIV_CBC168_3DES,
                  "AES128": H.USM_PRIV_CFB128_AES, "AES192": H.USM_PRIV_CFB192_AES_BLUMENTHAL,
                  "AES256": H.USM_PRIV_CFB256_AES_BLUMENTHAL, "AES192C": H.USM_PRIV_CFB192_AES,
                  "AES256C": H.USM_PRIV_CFB256_AES}[cred.get("priv") or "none"]
            if (cred.get("auth") or "none") == "none":
                auth = UsmUserData(cred["user"])
            elif (cred.get("priv") or "none") == "none":
                auth = UsmUserData(cred["user"], cred.get("auth_key") or "", authProtocol=ap)
            else:
                auth = UsmUserData(cred["user"], cred.get("auth_key") or "", cred.get("priv_key") or "",
                                   authProtocol=ap, privProtocol=pp)
        else:
            auth = CommunityData(cred.get("community") or "", mpModel=1)
        ent = (SnmpEngine(), auth, cred.get("ctx") or "")
        self._engines[fp] = ent
        while len(self._engines) > self.ENGINE_MAX:
            self._engines.popitem(last=False)
        return ent

    @staticmethod
    async def _target(host, port, timeout, retries):
        from pysnmp.hlapi.v3arch.asyncio import Udp6TransportTarget, UdpTransportTarget
        try:
            v6 = ipaddress.ip_address(host.strip("[]")).version == 6
        except ValueError:
            v6 = False
        cls = Udp6TransportTarget if v6 else UdpTransportTarget
        try:
            return await cls.create((host.strip("[]"), int(port or 161)), timeout=float(timeout), retries=int(retries))
        except Exception as e:  # noqa — نام پیدا نشد و …
            raise SnmpError(f"آدرس پیدا نشد: {host} ({str(e)[:80]})")

    async def aget(self, cred, host, port, oids, timeout=3, retries=1, typed=False):
        from pysnmp.hlapi.v3arch.asyncio import ContextData, ObjectIdentity, ObjectType, get_cmd
        eng, auth, ctx = self._auth(cred)
        tgt = await self._target(host, port, timeout, retries)
        out = {}
        oids = list(dict.fromkeys(oids))
        for i in range(0, len(oids), 20):
            part = oids[i:i + 20]
            ei, es, ix, vbs = await get_cmd(eng, auth, tgt, ContextData(contextName=ctx),
                                            *[ObjectType(ObjectIdentity(o)) for o in part], lookupMib=False)
            if ei:
                raise _err(ei, cred)
            if es:
                if int(es) == 2 and len(part) > 1:          # SNMPv1-مانند: noSuchName؛ تک‌تک
                    for o in part:
                        out.update(await self.aget(cred, host, port, [o], timeout, retries, typed))
                    continue
                raise SnmpError("خطای SNMP: " + _STATUS.get(int(es), str(es)))
            for o, v in vbs:
                val, tn = conv(v)
                out[str(o)] = (val, tn) if typed else val
        return out

    async def awalk(self, cred, host, port, cols, timeout=3, retries=1, max_rows=MAX_IFS):
        """چند ستون جدول هم‌زمان با GETBULK؛ هر ستون مستقل پیش می‌رود (حفره‌ها و پاسخ بریده‌شده مشکلی ندارند).
        خروجی: {ستون: {اندیس: مقدار}}"""
        from pysnmp.hlapi.v3arch.asyncio import ContextData, ObjectIdentity, ObjectType, bulk_cmd
        eng, auth, ctx = self._auth(cred)
        tgt = await self._target(host, port, timeout, retries)
        cols = [c.strip(".") for c in cols]
        out = {c: {} for c in cols}
        cur = {c: c for c in cols}
        active = list(cols)
        rep = max(4, min(25, 60 // max(1, len(cols))))
        calls = 0
        while active and calls < 600:
            calls += 1
            ei, es, ix, vbs = await bulk_cmd(eng, auth, tgt, ContextData(contextName=ctx), 0, rep,
                                             *[ObjectType(ObjectIdentity(cur[c])) for c in active], lookupMib=False)
            if ei:
                raise _err(ei, cred)
            if es:
                if int(es) == 1 and rep > 1:
                    rep = max(1, rep // 2)
                    continue
                raise SnmpError("خطای SNMP: " + _STATUS.get(int(es), str(es)))
            if not vbs:
                break
            n, ended = len(active), set()
            for i, (o, v) in enumerate(vbs):
                c = active[i % n]
                if c in ended:
                    continue
                os_ = str(o)
                if v.__class__.__name__ == "EndOfMibView" or not os_.startswith(c + "."):
                    ended.add(c)
                    continue
                if oid_t(os_) <= oid_t(cur[c]):       # دستگاه معیوب: OID جلو نمی‌رود
                    ended.add(c)
                    continue
                out[c][os_[len(c) + 1:]] = conv(v)[0]
                cur[c] = os_
                if len(out[c]) >= max_rows:
                    ended.add(c)
            active = [c for c in active if c not in ended]
        return out

    async def abrowse(self, cred, host, port, base, timeout=3, retries=1, max_rows=500, start=None):
        """گشتن یک زیرشاخه برای «مرورگر OID»: [(oid، نوع، مقدار)].
        start (1.27، walk کامل تکه‌تکه): ادامه از بعد از این OID."""
        from pysnmp.hlapi.v3arch.asyncio import ContextData, ObjectIdentity, ObjectType, bulk_cmd
        eng, auth, ctx = self._auth(cred)
        tgt = await self._target(host, port, timeout, retries)
        base = base.strip(".")
        cur, rows, rep = (start.strip(".") if start else base), [], 25
        while len(rows) < max_rows:
            ei, es, ix, vbs = await bulk_cmd(eng, auth, tgt, ContextData(contextName=ctx), 0, rep,
                                             ObjectType(ObjectIdentity(cur)), lookupMib=False)
            if ei:
                raise _err(ei, cred)
            if es:
                if int(es) == 1 and rep > 1:
                    rep = max(1, rep // 2)
                    continue
                raise SnmpError("خطای SNMP: " + _STATUS.get(int(es), str(es)))
            if not vbs:
                break
            stop = False
            for o, v in vbs:
                os_ = str(o)
                if v.__class__.__name__ == "EndOfMibView" or not (os_ == base or os_.startswith(base + ".")) \
                        or oid_t(os_) <= oid_t(cur):
                    stop = True
                    break
                val, tn = conv(v)
                rows.append([os_, tn, val])
                cur = os_
                if len(rows) >= max_rows:
                    break
            if stop:
                break
        if not rows and not start:       # شاید خود OID یک مقدار تکی است
            g = await self.aget(cred, host, port, [base], timeout, retries, typed=True)
            val, tn = g.get(base, (None, ""))
            if val is not None:
                rows.append([base, tn, val])
        return rows


# ---------------------------------------------------------------------------- خواندن یک دستگاه
def _num(v):
    try:
        if v is None or v == "":
            return None
        return float(str(v).strip())
    except (TypeError, ValueError):
        return None


def _scaled(value, scale, prec):
    """CISCO-ENTITY-SENSOR / ENTITY-SENSOR: مقدار × ۱۰^(۳×(scale−9)) ÷ ۱۰^precision (units(9) = بدون ضریب)."""
    if value is None:
        return None
    try:
        return float(value) * (10 ** (3 * (int(scale or 9) - 9))) / (10 ** int(prec or 0))
    except (TypeError, ValueError, OverflowError):
        return None


def detect_vendor(objid):
    for pfx, v in VENDORS:
        if str(objid or "").startswith(pfx):
            return v
    return "generic"


async def _names(cl, cred, host, port, idx, timeout, retries):
    """entPhysicalName برای چند اندیس (حداکثر ۶۴). 1.34: نام‌ها تا STATIC_TTL در کش Client می‌مانند."""
    idx = [str(i) for i in dict.fromkeys(idx) if str(i) not in ("", "0")][:64]
    if not idx:
        return {}
    key = cl.static_key(cred, host, port) if hasattr(cl, "names") else None
    now = time.time()
    c = cl.names.get(key) if key else None
    if c and now - c["t"] > c.get("ttl", Client.STATIC_TTL):
        c = None
    have = c["n"] if c else {}
    miss = [i for i in idx if i not in have]
    if miss:
        g = await cl.aget(cred, host, port, [f"{ENT_NAME}.{i}" for i in miss], timeout, retries)
        have = {**have, **{i: (g.get(f"{ENT_NAME}.{i}") or "").strip() for i in miss}}
        if key:
            cl.names[key] = {"t": c["t"] if c else now, "ttl": c["ttl"] if c else Client.STATIC_TTL * random.uniform(0.85, 1.15),  # nosec B311 — پخش زمان
                             "n": dict(list(have.items())[-512:])}
    return {i: have.get(i, "") for i in idx}


async def collect(cl, cred, host, port, cfg, timeout=3, retries=1):
    """خروجی خام یک بار خواندن (نرخ‌ها در SnmpRuntime از تفاضل حساب می‌شوند)."""
    t0 = time.perf_counter()
    try:
        s = await cl.aget(cred, host, port, list(SYS.values()), timeout, retries)
    except SnmpError as e:
        e.silent = True            # 1.34: دستگاه به همان درخواست اول (system) جواب نداد؛ تلاش دوباره‌ی uptime بی‌فایده است
        raise
    rtt = round((time.perf_counter() - t0) * 1000, 1)
    vendor = cfg.get("vendor") or "auto"
    if vendor == "auto":
        vendor = detect_vendor(s.get(SYS["objid"]))
    out = {"sys": {k: s.get(o) for k, o in SYS.items()}, "vendor": vendor, "rtt": rtt, "errors": [],
           "cpu": None, "mem": None, "disks": [], "temps": [], "fans": [], "psus": [], "sensors": [], "ifs": [], "oids": [],
           "extra": {}, "prof": None}
    col = cfg.get("collect") or {}
    a = (cred, host, port)

    async def part(name, fn):
        try:
            await fn()
        except SnmpError as e:
            out["errors"].append(f"{name}: {e}")
        except Exception as e:  # noqa — داده‌ی غیرمنتظره‌ی یک دستگاه نباید کل خواندن را خراب کند
            log.exception("snmp %s %s", host, name)
            out["errors"].append(f"{name}: {e.__class__.__name__}")

    async def w(cols, rows=MAX_IFS):
        return await cl.awalk(*a, cols, timeout, retries, rows)

    async def g(oids):
        return await cl.aget(*a, oids, timeout, retries)

    # ---------------- CPU و حافظه و دیسک
    async def cpu_mem():
        if vendor == "cisco":
            r = await w(list(CPM.values()), 64)
            cpus = []
            if r[CPM["m1"]] or r[CPM["m5"]]:
                names = await _names(cl, *a, r[CPM["phys"]].values(), timeout, retries)
                for i in sorted(set(r[CPM["m1"]]) | set(r[CPM["m5"]]), key=lambda x: oid_t(x)):
                    ph = str(r[CPM["phys"]].get(i) or "")
                    cpus.append({"name": names.get(ph) or f"CPU {i}", "s5": r[CPM["s5"]].get(i),
                                 "m1": r[CPM["m1"]].get(i), "m5": r[CPM["m5"]].get(i)})
            src = "CISCO-PROCESS-MIB"
            if not cpus:            # IOS قدیمی‌تر از 12.2(3.5): ستون‌های بدون Rev
                o = await w(list(CPM_OLD.values()) + [CPM["phys"]], 64)
                if o[CPM_OLD["m1"]] or o[CPM_OLD["m5"]]:
                    names = await _names(cl, *a, o[CPM["phys"]].values(), timeout, retries)
                    for i in sorted(set(o[CPM_OLD["m1"]]) | set(o[CPM_OLD["m5"]]), key=lambda x: oid_t(x)):
                        ph = str(o[CPM["phys"]].get(i) or "")
                        cpus.append({"name": names.get(ph) or f"CPU {i}", "s5": o[CPM_OLD["s5"]].get(i),
                                     "m1": o[CPM_OLD["m1"]].get(i), "m5": o[CPM_OLD["m5"]].get(i)})
                    src = "CISCO-PROCESS-MIB (cpmCPUTotal5min)"
            if not cpus:            # خیلی قدیمی: OLD-CISCO-CPU-MIB
                o = await g(list(OLD_BUSY.values()))
                if o.get(OLD_BUSY["m1"]) is not None or o.get(OLD_BUSY["m5"]) is not None:
                    cpus.append({"name": "CPU", "s5": None, "m1": o.get(OLD_BUSY["m1"]), "m5": o.get(OLD_BUSY["m5"])})
                    src = "OLD-CISCO-CPU-MIB"
            if cpus:
                vals = [c["m1"] if c["m1"] is not None else c["m5"] for c in cpus]
                vals = [v for v in vals if v is not None]
                out["cpu"] = {"value": max(vals) if vals else None, "items": cpus, "src": src}
            if col.get("mem", True):
                m = await w(list(CEMP.values()), 128)
                pools = []
                for i in sorted(m[CEMP["name"]], key=lambda x: oid_t(x)):
                    used = m[CEMP["hcused"]].get(i)
                    free = m[CEMP["hcfree"]].get(i)
                    if used is None or free is None:
                        used, free = m[CEMP["used"]].get(i), m[CEMP["free"]].get(i)
                    if used is None or free is None or used + free <= 0:
                        continue
                    pools.append({"name": m[CEMP["name"]][i] or f"Pool {i}", "type": m[CEMP["type"]].get(i),
                                  "used": used, "total": used + free, "pct": round(100 * used / (used + free), 1)})
                src = "CISCO-ENHANCED-MEMPOOL-MIB"
                if not pools:
                    m = await w(list(CMP.values()), 64)
                    for i in sorted(m[CMP["name"]], key=lambda x: oid_t(x)):
                        used, free = m[CMP["used"]].get(i), m[CMP["free"]].get(i)
                        if used is None or free is None or used + free <= 0:
                            continue
                        nm = m[CMP["name"]][i] or f"Pool {i}"
                        pools.append({"name": nm, "type": 2 if nm.lower().startswith("processor") else 0,
                                      "used": used, "total": used + free, "pct": round(100 * used / (used + free), 1)})
                    src = "CISCO-MEMORY-POOL-MIB"
                if pools:
                    main = [p for p in pools if p["type"] == 2] or pools[:1]
                    top = max(main, key=lambda p: p["pct"])
                    out["mem"] = {"pct": top["pct"], "used": top["used"], "total": top["total"], "items": pools, "src": src}
        elif vendor == "fortinet":
            r = await g(list(FG.values()))
            if r.get(FG["cpu"]) is not None:
                out["cpu"] = {"value": r[FG["cpu"]], "items": [], "src": "FORTINET-FORTIGATE-MIB"}
            if r.get(FG["mem"]) is not None:
                cap = r.get(FG["memcap"])
                out["mem"] = {"pct": float(r[FG["mem"]]), "total": cap * 1024 if cap else None,
                              "used": cap * 1024 * r[FG["mem"]] / 100 if cap else None, "items": [], "src": "FORTINET-FORTIGATE-MIB"}
            if r.get(FG["diskcap"]):
                cap, used = r[FG["diskcap"]], r.get(FG["disk"]) or 0
                out["disks"].append({"name": "disk", "used": used * 1048576, "total": cap * 1048576,
                                     "pct": round(100 * used / cap, 1)})
            if r.get(FG["sess"]) is not None:
                out["extra"]["sessions"] = r[FG["sess"]]
            if r.get(FG["ver"]):
                out["extra"]["version"] = r[FG["ver"]]
        elif vendor == "juniper":
            r = await w(list(JNX_OP.values()), 512)
            re_rows = [i for i in r[JNX_OP["descr"]] if "routing engine" in str(r[JNX_OP["descr"]][i]).lower()]
            cpus, mems = [], []
            for i in sorted(re_rows, key=lambda x: oid_t(x)):
                if r[JNX_OP["state"]].get(i) in (6, 7):        # down / standby (RE پشتیبان)
                    continue
                nm = str(r[JNX_OP["descr"]][i])[:80]
                cpus.append({"name": nm, "s5": None, "m1": r[JNX_OP["cpu"]].get(i), "m5": None})
                if r[JNX_OP["memory"]].get(i):
                    mb, pct = r[JNX_OP["memory"]][i], r[JNX_OP["buffer"]].get(i)
                    if pct is not None:
                        mems.append({"name": nm, "type": 2, "used": mb * 1048576 * pct / 100, "total": mb * 1048576, "pct": float(pct)})
            vals = [c["m1"] for c in cpus if c["m1"] is not None]
            if vals:
                out["cpu"] = {"value": max(vals), "items": cpus, "src": "JUNIPER-MIB (jnxOperatingCPU)"}
            if mems and col.get("mem", True):
                top = max(mems, key=lambda p: p["pct"])
                out["mem"] = {"pct": top["pct"], "used": top["used"], "total": top["total"], "items": mems, "src": "JUNIPER-MIB (jnxOperatingBuffer)"}
            out["extra"]["_jnx"] = r                         # دما از همین جدول (بدون خواندن دوباره)
            comps = []                                       # 1.36: قطعه‌ها از همین جدول (فقط نمایش)
            for i in sorted(r[JNX_OP["descr"]], key=lambda x: oid_t(x))[:64]:
                stv = r[JNX_OP["state"]].get(i)
                comps.append({"name": str(r[JNX_OP["descr"]][i] or i)[:80], "state": JNX_STATE.get(stv, str(stv or "")),
                              "level": JNX_LEVEL.get(stv, "unknown"), "temp": r[JNX_OP["temp"]].get(i) or None,
                              "cpu": r[JNX_OP["cpu"]].get(i)})
            out["extra"]["components"] = comps
        elif vendor == "extreme":
            r = await g([EX["cpu"]])
            if r.get(EX["cpu"]) is not None:
                out["cpu"] = {"value": r[EX["cpu"]], "items": [], "src": "EXTREME-SOFTWARE-MONITOR-MIB"}
            m = await w(list(EX_MEM.values()), 16)
            pools = []
            for i in sorted(m[EX_MEM["total"]], key=lambda x: oid_t(x)):
                tot, fr = _num(m[EX_MEM["total"]][i]), _num(m[EX_MEM["free"]].get(i))
                if tot and fr is not None:
                    pools.append({"name": f"Slot {i}", "type": 2, "used": (tot - fr) * 1024, "total": tot * 1024,
                                  "pct": round(100 * (tot - fr) / tot, 1)})
            if pools:
                top = max(pools, key=lambda p: p["pct"])
                out["mem"] = {"pct": top["pct"], "used": top["used"], "total": top["total"], "items": pools,
                              "src": "EXTREME-SOFTWARE-MONITOR-MIB"}
        if out["cpu"] is None:          # لینوکس، ویندوز و هر دستگاه دارای HOST-RESOURCES
            r = await w([HR_CPU], 256)
            v = [x for x in r[HR_CPU].values() if x is not None]
            if v:
                out["cpu"] = {"value": round(sum(v) / len(v), 1), "items": [{"name": f"Core {i + 1}", "m1": x} for i, x in enumerate(v)][:64],
                              "src": "HOST-RESOURCES-MIB"}
            elif vendor in ("linux", "generic", "mikrotik", "hp"):
                u = await g([UCD["idle"]])
                if u.get(UCD["idle"]) is not None:
                    out["cpu"] = {"value": max(0, 100 - u[UCD["idle"]]), "items": [], "src": "UCD-SNMP-MIB"}
        if vendor in ("linux", "generic", "mikrotik", "hp") and (out["mem"] is None or col.get("disk", True)):
            hs = None
            if out["mem"] is None and col.get("mem", True):
                u = await g([UCD["total"], UCD["avail"], UCD["buffer"], UCD["cached"], UCD["load1"]])
                tot = u.get(UCD["total"])
                if tot:
                    used = max(0, tot - (u.get(UCD["avail"]) or 0) - (u.get(UCD["buffer"]) or 0) - (u.get(UCD["cached"]) or 0))
                    out["mem"] = {"pct": round(100 * used / tot, 1), "used": used * 1024, "total": tot * 1024, "items": [],
                                  "src": "UCD-SNMP-MIB"}
                if _num(u.get(UCD["load1"])) is not None:
                    out["extra"]["load1"] = _num(u.get(UCD["load1"]))
            if out["mem"] is None or col.get("disk", True):
                hs = await w(list(HR_ST.values()), 128)
                for i in sorted(hs[HR_ST["type"]], key=lambda x: oid_t(x)):
                    typ, un = str(hs[HR_ST["type"]][i] or ""), hs[HR_ST["units"]].get(i) or 0
                    size, used = hs[HR_ST["size"]].get(i), hs[HR_ST["used"]].get(i)
                    if not size or used is None or not un or size < 0 or used < 0 or used > size:
                        continue       # Integer32 دیسک خیلی بزرگ منفی/سرریز می‌شود
                    descr = str(hs[HR_ST["descr"]].get(i) or "")
                    if typ == HR_DISK and _PSEUDO_FS.match(descr):
                        continue
                    row = {"name": str(hs[HR_ST["descr"]].get(i) or i)[:80], "used": used * un, "total": size * un,
                           "pct": round(100 * used / size, 1)}
                    if typ == HR_RAM and out["mem"] is None and col.get("mem", True):
                        out["mem"] = {"pct": row["pct"], "used": row["used"], "total": row["total"], "items": [],
                                      "src": "HOST-RESOURCES-MIB"}
                    elif typ == HR_DISK and col.get("disk", True):
                        out["disks"].append(row)

    # ---------------- دما، فن، منبع تغذیه
    async def env():
        if vendor == "cisco":
            r = await w(list(ENV_TEMP.values()), 64)
            for i in sorted(r[ENV_TEMP["descr"]], key=lambda x: oid_t(x)):
                st = ENV_STATE.get(r[ENV_TEMP["state"]].get(i), "ok")
                if st == "absent":
                    continue
                out["temps"].append({"name": r[ENV_TEMP["descr"]][i] or f"Temp {i}", "value": r[ENV_TEMP["value"]].get(i),
                                     "thr": r[ENV_TEMP["thr"]].get(i), "state": st})
            if not out["temps"]:
                await sensors(CSENS, "CISCO-ENTITY-SENSOR-MIB")
            if not out["temps"]:        # ASA / Firepower: ENTITY-SENSOR-MIB استاندارد (سند Cisco Secure Firewall ASA، فصل SNMP)
                await sensors(ESENS, "ENTITY-SENSOR-MIB")
            for tbl, key in ((ENV_FAN, "fans"), (ENV_PSU, "psus")):
                r = await w(list(tbl.values()), 64)
                for i in sorted(r[tbl["descr"]], key=lambda x: oid_t(x)):
                    st = ENV_STATE.get(r[tbl["state"]].get(i), "ok")
                    if st != "absent":
                        out[key].append({"name": r[tbl["descr"]][i] or i, "state": st})
        elif vendor == "fortinet":
            r = await w(list(FG_HW.values()), 128)
            for i in sorted(r[FG_HW["name"]], key=lambda x: oid_t(x)):
                out["sensors"].append({"name": r[FG_HW["name"]][i] or i, "value": r[FG_HW["value"]].get(i),
                                       "state": "crit" if r[FG_HW["alarm"]].get(i) == 1 else "ok"})
        elif vendor == "extreme":
            r = await g([EX["temp"], EX["overtemp"]])
            if r.get(EX["temp"]) is not None:
                out["temps"].append({"name": "System", "value": r[EX["temp"]], "thr": None,
                                     "state": "crit" if r.get(EX["overtemp"]) == 1 else "ok"})
            r = await w([EX_FAN, EX_PSU], 32)
            for i in sorted(r[EX_FAN], key=lambda x: oid_t(x)):
                out["fans"].append({"name": f"Fan {i}", "state": "ok" if r[EX_FAN][i] == 1 else "crit"})
            for i in sorted(r[EX_PSU], key=lambda x: oid_t(x)):
                v = r[EX_PSU][i]
                if v != 1:
                    out["psus"].append({"name": f"PSU {i}", "state": {2: "ok", 3: "crit", 4: "warn"}.get(v, "ok")})
        elif vendor == "juniper":
            r = out["extra"].pop("_jnx", None) or await w(list(JNX_OP.values()), 512)
            for i in sorted(r[JNX_OP["temp"]], key=lambda x: oid_t(x)):
                v = r[JNX_OP["temp"]][i]
                if v and v > 0 and r[JNX_OP["state"]].get(i) not in (6,):       # صفر = نامعلوم
                    out["temps"].append({"name": str(r[JNX_OP["descr"]].get(i) or i)[:80], "value": v, "thr": None, "state": "ok"})
        elif vendor == "mikrotik":
            r = await w(list(MT_GAUGE.values()), 128)
            for i in sorted(r[MT_GAUGE["name"]], key=lambda x: oid_t(x)):
                nm, v, u = str(r[MT_GAUGE["name"]][i] or i)[:60], r[MT_GAUGE["value"]].get(i), r[MT_GAUGE["unit"]].get(i)
                if v is None:
                    continue
                if u == 1:
                    out["temps"].append({"name": nm, "value": round(v / 10, 1), "thr": None, "state": "ok"})
                elif u == 2:
                    out["sensors"].append({"name": nm, "value": f"{v} rpm", "state": "ok"})
                elif u in (3, 4, 5):
                    out["sensors"].append({"name": nm, "value": f"{v / 10:g} {'VAW'[u - 3]}", "state": "ok"})
                else:
                    out["sensors"].append({"name": nm, "value": str(v), "state": "ok"})
            if not r[MT_GAUGE["name"]]:          # RouterOS قدیمی (پیش از جدول gauge)
                o = await g(list(MT_HL.values()))
                for k, nm in (("temp", "Board"), ("cpu_temp", "CPU")):
                    v = o.get(MT_HL[k])
                    if v is not None and v > 0:
                        out["temps"].append({"name": nm, "value": round(v / 10, 1), "thr": None, "state": "ok"})
        elif vendor == "hp":
            await hp_env()
        else:
            await sensors(ESENS, "ENTITY-SENSOR-MIB")
            if not out["temps"] and vendor in ("linux", "generic"):     # سرور HP با عامل Insight روی ویندوز/لینوکس
                await hp_env()

    async def hp_env():
        r = await w(list(HP_TEMP.values()), 128)
        if not r[HP_TEMP["cond"]]:          # CPQHLTH-MIB نیست (Insight Agent/iLO نیست) ← بقیه هم خوانده نشود
            return
        for i in sorted(r[HP_TEMP["value"]], key=lambda x: oid_t(x)):
            v = r[HP_TEMP["value"]][i]
            if v is None or v <= 0:          # سنسور غایب (مقدار منفی یا صفر)
                continue
            thr = r[HP_TEMP["thr"]].get(i)
            out["temps"].append({"name": f"{HP_LOCALE.get(r[HP_TEMP['locale']].get(i), 'Sensor')} {i}", "value": v,
                                 "thr": thr if thr and thr > 0 else None, "state": HP_COND.get(r[HP_TEMP["cond"]].get(i), "ok")})
        r = await w(list(HP_FAN.values()), 64)
        for i in sorted(r[HP_FAN["cond"]], key=lambda x: oid_t(x)):
            if r[HP_FAN["present"]].get(i) == 3:
                out["fans"].append({"name": f"Fan {i} ({HP_LOCALE.get(r[HP_FAN['locale']].get(i), '')})".replace(" ()", ""),
                                    "state": HP_COND.get(r[HP_FAN["cond"]][i], "ok")})
        r = await w(list(HP_PSU.values()), 32)
        for i in sorted(r[HP_PSU["cond"]], key=lambda x: oid_t(x)):
            if r[HP_PSU["present"]].get(i) == 3:
                out["psus"].append({"name": f"PSU {r[HP_PSU['bay']].get(i) or i}", "state": HP_COND.get(r[HP_PSU["cond"]][i], "ok")})

    async def sensors(tbl, src):
        r = await w(list(tbl.values()), 256)
        rows = [i for i in r[tbl["type"]] if r[tbl["type"]][i] == 8]        # celsius(8)
        names = await _names(cl, *a, rows, timeout, retries) if rows else {}
        for i in sorted(rows, key=lambda x: oid_t(x))[:64]:
            stv = r[tbl["status"]].get(i)
            if stv in (2, 3):         # unavailable / nonoperational
                continue
            v = _scaled(r[tbl["value"]].get(i), r[tbl["scale"]].get(i), r[tbl["prec"]].get(i))
            if v is not None:
                out["temps"].append({"name": names.get(str(i)) or f"Sensor {i}", "value": round(v, 1), "thr": None, "state": "ok"})

    # ---------------- پورت‌ها
    # 1.34: ستون‌های ثابت (نام، توضیح، alias، نوع، سرعت) با کش STATIC_TTL؛ هر بار فقط وضعیت و شمارنده‌ها.
    # کش با راه‌اندازی دوباره‌ی دستگاه (uptime کمتر)، پایان زمان یا تغییر فهرست پورت‌ها دوباره خوانده می‌شود.
    cnt = cfg.get("counters") or {}
    want = {k: bool(cnt.get(k, 1)) for k in ("traffic", "err", "disc")}

    async def if_static():
        r = await w([IF_T["descr"], IF_T["type"], IF_T["speed"]])
        x = await w([IF_X["name"], IF_X["hspeed"], IF_X["alias"], IF_X["in64"]])
        rows = {}
        for i in r[IF_T["descr"]]:
            hs = x[IF_X["hspeed"]].get(i)
            sp = r[IF_T["speed"]].get(i)
            rows[i] = {"name": (x[IF_X["name"]].get(i) or r[IF_T["descr"]][i] or str(i))[:80], "descr": (r[IF_T["descr"]][i] or "")[:120],
                       "alias": (x[IF_X["alias"]].get(i) or "")[:120], "type": r[IF_T["type"]].get(i),
                       "speed": hs * 1_000_000 if hs else (sp if sp and sp != 4294967295 else None)}
        ent = {"t": time.time(), "ttl": Client.STATIC_TTL * random.uniform(0.85, 1.15), "up": out["sys"].get("uptime"),  # nosec B311 — پخش زمان
               "rows": rows, "has64": {i for i in rows if x[IF_X["in64"]].get(i) is not None}}
        if hasattr(cl, "static"):
            cl.static[cl.static_key(cred, host, port)] = ent
        return ent

    async def ifs():
        key = cl.static_key(cred, host, port) if hasattr(cl, "static") else None
        st = cl.static.get(key) if key else None
        up = out["sys"].get("uptime")
        if st and (time.time() - st["t"] > st["ttl"] or (up is not None and st["up"] is not None and up < st["up"])):
            st = None
        if st is None:
            st = await if_static()
        cols = [IF_T["admin"], IF_T["oper"]]
        if want["traffic"]:
            cols += [IF_X["in64"], IF_X["out64"]]
            if len(st["has64"]) < len(st["rows"]):
                cols += [IF_T["in32"], IF_T["out32"]]
        if want["err"]:
            cols += [IF_T["inerr"], IF_T["outerr"]]
        if want["disc"]:
            cols += [IF_T["indisc"], IF_T["outdisc"]]
        d = await w(cols)
        idx = set(d[IF_T["admin"]]) | set(d[IF_T["oper"]])
        if idx and idx != set(st["rows"]) and st["t"] < time.time() - 300:   # پورت تازه یا حذف‌شده (حداکثر هر ۵ دقیقه)
            st = await if_static()
        g = lambda c, i: d.get(c, {}).get(i)  # noqa: E731
        for i in sorted(st["rows"], key=lambda k: oid_t(k))[:MAX_IFS]:
            s0 = st["rows"][i]
            in64, out64 = g(IF_X["in64"], i), g(IF_X["out64"], i)
            b64 = in64 is not None
            err = (g(IF_T["inerr"], i) or 0) + (g(IF_T["outerr"], i) or 0) if want["err"] else None
            disc = (g(IF_T["indisc"], i) or 0) + (g(IF_T["outdisc"], i) or 0) if want["disc"] else None
            out["ifs"].append({
                "idx": int(i) if i.isdigit() else i, **s0, "admin": g(IF_T["admin"], i), "oper": g(IF_T["oper"], i),
                "in": in64 if b64 else g(IF_T["in32"], i), "out": out64 if b64 else g(IF_T["out32"], i),
                "bits": 64 if b64 else 32, "err": err, "disc": disc})

    # ---------------- OIDهای دستی
    async def oids():
        lst = cfg.get("oids") or []
        if not lst:
            return
        r = await cl.aget(*a, [o["oid"] for o in lst], timeout, retries, typed=True)
        for o in lst:
            val, tn = r.get(o["oid"], (None, ""))
            out["oids"].append({"oid": o["oid"], "raw": val, "tn": tn})

    if col.get("cpu", True) or col.get("mem", True) or col.get("disk", True):
        await part("CPU/حافظه", cpu_mem)
    if col.get("env", True):
        await part("سخت‌افزار", env)
    if col.get("if", True):
        await part("پورت‌ها", ifs)
    await part("OIDهای دستی", oids)

    # ---------------- نوع دستگاه از MIB سازنده (1.27.1)
    async def prof():
        from .devprof import collect as pcollect, select
        p = select(cfg.get("_profiles"), cfg.get("profile", "auto"), out["sys"].get("objid"))
        if p and p.get("metrics"):
            out["prof"] = {"id": p["id"], "name": p["name"], "items": []}
            out["prof"]["items"] = await pcollect(cl, cred, host, port, p, timeout, retries)
    await part("قالب دستگاه", prof)
    out["extra"].pop("_jnx", None)
    if not col.get("cpu", True):
        out["cpu"] = None
    if not col.get("mem", True):
        out["mem"] = None
    if not col.get("disk", True):
        out["disks"] = []
    return out


async def poll_raw(cl, cred, host, port, cfg, timeout, retries, budget):
    """یک بار خواندن کامل با سقف زمان (درون‌برنامه یا در کارگر SNMP). خروجی: {"raw": …} یا
    {"alive": پیام، "rtt"} وقتی خواندن کامل نشد ولی دستگاه پاسخ می‌دهد (قطع اعلام نشود). خطا: SnmpError."""
    try:
        return {"raw": await asyncio.wait_for(collect(cl, cred, host, port, cfg, timeout, retries), budget)}
    except asyncio.TimeoutError:
        err = SnmpError("خواندن SNMP بیش از حد طول کشید و متوقف شد")
    except SnmpError as e:
        if getattr(e, "silent", False):
            raise
        err = e
    t0 = time.perf_counter()
    try:
        r = await asyncio.wait_for(cl.aget(cred, host, port, [SYS["uptime"]], timeout, retries), timeout * (retries + 1) + 5)
    except (SnmpError, asyncio.TimeoutError):
        raise err
    if r.get(SYS["uptime"]) is None:
        raise err
    return {"alive": f"خواندن کامل ناموفق بود ولی دستگاه پاسخ می‌دهد: {err}", "rtt": round((time.perf_counter() - t0) * 1000, 1)}


def poll_budget(t, cfg):
    timeout = float(t.get("timeout") or 3)
    return min(300, max(120, 30 + timeout * (cfg["retries"] + 1) * 10))


# ---------------------------------------------------------------------------- پیکربندی هدف
def _thr(v):
    if v in (None, ""):
        return None
    try:
        f = float(v)
    except (TypeError, ValueError):
        raise SnmpError(f"آستانه‌ی «{v}» عدد نیست.")
    if not math.isfinite(f):
        raise SnmpError("آستانه نامعتبر است.")
    return f


def clean_cfg(c):
    """اعتبارسنجی تنظیمات SNMP هدف (از رابط)."""
    c = c if isinstance(c, dict) else {}
    vendor = str(c.get("vendor") or "auto")
    if vendor not in VENDOR_NAMES:
        vendor = "auto"
    col = c.get("collect") if isinstance(c.get("collect"), dict) else {}
    th_in = c.get("th") if isinstance(c.get("th"), dict) else {}
    th = {}
    for k in TH_KEYS:
        v = th_in.get(k, TH_DEFAULT[k])
        if not isinstance(v, (list, tuple)) or len(v) != 2:
            v = [None, None]
        w, cr = _thr(v[0]), _thr(v[1])
        if w is not None and cr is not None and w > cr:
            raise SnmpError(f"آستانه‌ی هشدار «{TH_TITLES[k]}» از آستانه‌ی بحرانی بیشتر است.")
        th[k] = [w, cr]
    try:
        after = int(c.get("after") if c.get("after") not in (None, "") else 2)
        retries = int(c.get("retries") if c.get("retries") not in (None, "") else 1)
    except (TypeError, ValueError):
        raise SnmpError("مقدار «تکرار» نامعتبر است.")
    if not 1 <= after <= 20 or not 0 <= retries <= 5:
        raise SnmpError("«هشدار پس از» باید ۱ تا ۲۰ و «تلاش دوباره» ۰ تا ۵ باشد.")
    watch = []
    for n in (c.get("watch") or [])[:300]:
        n = str(n or "").strip()[:80]
        if n and n not in watch:
            watch.append(n)
    oids = []
    raw = c.get("oids") or []
    if len(raw) > MAX_OIDS:
        raise SnmpError(f"حداکثر {MAX_OIDS} OID دستی.")
    for o in raw:
        if not isinstance(o, dict):
            continue
        oid = norm_oid(o.get("oid"))
        typ = str(o.get("type") or "gauge")
        if typ not in ("gauge", "counter", "text"):
            typ = "gauge"
        try:
            mult = float(o.get("mult") if o.get("mult") not in (None, "") else 1)
        except (TypeError, ValueError):
            raise SnmpError("ضریب OID دستی باید عدد باشد.")
        if not math.isfinite(mult) or mult == 0:
            raise SnmpError("ضریب OID دستی نامعتبر است.")
        w, cr = (None, None) if typ == "text" else (_thr(o.get("warn")), _thr(o.get("crit")))
        d = "below" if o.get("dir") == "below" else "above"
        if w is not None and cr is not None and ((d == "above" and w > cr) or (d == "below" and w < cr)):
            raise SnmpError(f"آستانه‌های «{o.get('name') or oid}» برعکس‌اند.")
        oids.append({"name": str(o.get("name") or oid).strip()[:60], "oid": oid, "type": typ,
                     "unit": str(o.get("unit") or "").strip()[:16], "mult": mult, "warn": w, "crit": cr, "dir": d,
                     "expect": str(o.get("expect") or "").strip()[:120] if typ == "text" else "",
                     "chart": 0 if typ == "text" else (1 if o.get("chart", True) else 0)})
    prof = str(c.get("profile") or "auto")              # 1.27.1: نوع دستگاه از MIB: auto (با sysObjectID) | none | mib<enterprise>
    if prof not in ("auto", "none") and not re.fullmatch(r"mib\d{1,10}", prof):
        prof = "auto"
    ext = clean_pol_fields(c)
    return {"vendor": vendor, "collect": {k: 1 if col.get(k, True) else 0 for k in ("cpu", "mem", "disk", "env", "if")},
            "th": th, "after": after, "retries": retries, "watch": watch, "oids": oids,
            "if_hist": ext["hist"]["if"], "profile": prof, **ext,
            "show_ports": [str(x).strip()[:80] for x in (c.get("show_ports") or [])[:4] if str(x).strip()]}


PORTS = ("all", "up", "watch", "none")       # تاریخچه‌ی کدام پورت‌ها: همه (فعال)، فقط وصل، فقط پیگیری‌شده، هیچ
RES = (60, 300)                              # دقت داده‌ی دقیق (ثانیه)
DETAIL_MIN_DAYS, HOUR_MIN_DAYS, KEEP_MAX_DAYS = 7, 30, 36500


def keep_val(v, lo):
    """None = مثل تنظیمات کلی؛ ۰ = بدون محدودیت؛ وگرنه lo تا KEEP_MAX_DAYS روز."""
    if v in (None, "", "inherit"):
        return None
    try:
        v = int(v)
    except (TypeError, ValueError):
        raise SnmpError("مدت نگهداری باید عدد (روز) باشد.")
    if v <= 0:
        return 0
    if v < lo:
        raise SnmpError(f"مدت نگهداری دست‌کم {lo} روز است (یا ۰ = بدون محدودیت).")
    return min(KEEP_MAX_DAYS, v)


def clean_pol_fields(c):
    """1.34: دقت، نگهداری، شمارنده‌ها، پورت‌ها و تاریخچه (هم برای هدف سفارشی و هم «سیاست پایش»)."""
    try:
        res = int(c.get("res") or 300)
    except (TypeError, ValueError):
        res = 300
    hist_in = c.get("hist") if isinstance(c.get("hist"), dict) else {}
    cnt = c.get("counters") if isinstance(c.get("counters"), dict) else {}
    return {"res": res if res in RES else 300,
            "keep_d": keep_val(c.get("keep_d"), DETAIL_MIN_DAYS), "keep_h": keep_val(c.get("keep_h"), HOUR_MIN_DAYS),
            "ports": c.get("ports") if c.get("ports") in PORTS else "all",
            "counters": {k: 1 if cnt.get(k, True) else 0 for k in ("traffic", "err", "disc")},
            "hist": {"sys": 1 if hist_in.get("sys", True) else 0,
                     "if": 1 if hist_in.get("if", c.get("if_hist", True)) else 0,
                     "oid": 1 if hist_in.get("oid", True) else 0}}


def load_cfg(t):
    try:
        c = json.loads(t.get("snmp") or "{}")
    except (TypeError, ValueError):
        c = {}
    try:
        return clean_cfg(c)
    except SnmpError:
        return clean_cfg({})


# ---------------------------------------------------------------------------- اعتبارنامه
def clean_cred(p, community="", auth_key="", priv_key="", old=None):
    """پارامترهای پروفایل SNMP: {v, user, auth, priv, ctx} + اسرار. خالی در ویرایش = بدون تغییر."""
    v = "3" if str(p.get("version") or "2c") == "3" else "2c"
    old = old or {}
    if v == "2c":
        if not community and not old.get("community"):
            raise SnmpError("community لازم است.")
        if community and (len(community) > 128 or any(ch in community for ch in "\r\n\0")):
            raise SnmpError("community نامعتبر است.")
        return {"v": "2c"}, {"community": community} if community else {}
    user = str(p.get("username") or "").strip()
    if not user or len(user) > 64 or any(ch in user for ch in " \r\n\t\0"):
        raise SnmpError("نام کاربر SNMPv3 لازم است (بدون فاصله).")
    auth = str(p.get("auth") or "SHA")
    priv = str(p.get("priv") or "AES128")
    if auth not in dict(AUTH_PROTOS) or priv not in dict(PRIV_PROTOS):
        raise SnmpError("الگوریتم auth یا priv نامعتبر است.")
    if auth == "none" and priv != "none":
        raise SnmpError("رمزنگاری (priv) بدون احراز هویت (auth) ممکن نیست.")
    sec = {}
    for k, val, need in (("auth_key", auth_key, auth != "none"), ("priv_key", priv_key, priv != "none")):
        if not need:
            continue
        if val:
            if len(val) < 8 or len(val) > 128:
                raise SnmpError("رمزهای SNMPv3 باید ۸ تا ۱۲۸ نویسه باشند.")
            sec[k] = val
        elif not old.get(k):
            raise SnmpError("رمز auth و priv برای این سطح امنیتی لازم است.")
    ctx = str(p.get("ctx") or "").strip()[:64]
    return {"v": "3", "user": user, "auth": auth, "priv": priv, "ctx": ctx}, sec


# ---------------------------------------------------------------------------- فایل‌های سری زمانی
ZPFX = "AKRZ:"


def _zline(obj):
    from .tsdb import zenc
    return zenc(obj)


def _zread(path):
    out = []
    try:
        text = path.read_text(encoding="ascii", errors="ignore")
    except OSError:
        return out
    for line in text.splitlines():
        if not line.startswith(ZPFX):
            continue
        try:
            out.append(json.loads(zlib.decompress(atrest.decrypt(base64.b64decode(line[len(ZPFX):])))))
        except Exception:  # noqa — خط خراب (قطع برق وسط نوشتن) نادیده گرفته می‌شود
            continue
    return out


def fmt_bps(v):
    v = float(v or 0)
    for u, d in (("Gbps", 1e9), ("Mbps", 1e6), ("Kbps", 1e3)):
        if v >= d:
            return f"{v / d:.1f} {u}"
    return f"{v:.0f} bps"


# ---------------------------------------------------------------------------- زمان اجرا (نرخ، هشدار، ذخیره)
class SnmpRuntime:
    BUCKET = 300

    def __init__(self, settings, store, demo=False):
        self.settings, self.store, self.demo = settings, store, demo
        self.client = Client()
        self.live = {}          # tid → داده‌ی زنده برای رابط
        self.prev = {}          # tid → شمارنده‌های قبلی
        self.alarms = {}        # tid → {key: {level, since, msg, value, n_bad, n_ok}}
        self._acc5, self._acch = {}, {}   # 1.34: tid → {"b": شروع بازه، "r": طول بازه، "a": {key: [جمع، تعداد، بیشینه]}}
        self._lock = threading.Lock()
        from . import tsdb
        self.ts = tsdb.store()
        self.pool = None        # کارگرهای SNMP (snmppool)؛ None = درون برنامه
        self.vendors = {}       # 1.36: tid → سازنده‌ی تشخیص‌داده‌شده (برای قالب نمایش خودکار)
        self.vendor_new = False
        self.phist = {}         # 1.35: tid → {پورت نمایشی: deque[(t، ورودی، خروجی)]} برای نمودار کوچک جدول و NOC
        self._prof_sig = None
        self._sem = None

    # ---- اعتبارنامه از vault
    def cred_for(self, t):
        cid = t.get("cred_id")
        p = self.store.cred_get(int(cid)) if cid else None
        if not p or p.get("kind") != "snmp" or (p.get("owner") or "").lower() != (t.get("owner") or "").lower():
            raise SnmpError("پروفایل اعتبارنامه‌ی SNMP این هدف پیدا نشد (یا با صاحب هدف جور نیست).")
        return cred_from_vault(self.settings.vault, p["id"])

    def profiles(self):
        """نوع‌های دستگاه ساخته‌شده از MIBهای بارگذاری‌شده (1.27.1)."""
        try:
            from .mibs import LIB
            return LIB.auto_profiles()
        except Exception:  # noqa
            return []

    def _cfg(self, t, cfg=None):
        cfg = dict(cfg or t.get("_cfg") or load_cfg(t))
        cfg["_profiles"] = self.profiles()
        return cfg

    def _demo(self, t):
        return self.demo and not str(t.get("host") or "").startswith("127.")

    def job(self, t, cfg):
        """پارامترهای یک بار خواندن (برای کارگر یا حلقه‌ی درون برنامه)."""
        return {"cred": self.cred_for(t), "host": t["host"], "port": t.get("port") or 161, "timeout": float(t.get("timeout") or 3),
                "retries": cfg["retries"], "budget": poll_budget(t, cfg)}

    def finish(self, t, cfg, res):
        """نتیجه‌ی poll_raw → (ok، rtt، err، رویدادها)."""
        if "alive" in res:
            self._note(t["id"], res["alive"])
            return True, res.get("rtt"), "", []
        raw = res["raw"]
        try:
            events = self.ingest(t, cfg, raw)
        except Exception as e:  # noqa — خطای پردازش نباید دستگاه سالم را «قطع» نشان دهد
            log.exception("snmp ingest %s", t.get("host"))
            self._note(t["id"], f"خطای پردازش داده: {e.__class__.__name__}")
            return True, raw.get("rtt"), "", []
        return True, raw["rtt"], "", events

    def poll(self, t, cfg=None):
        """یک بار خواندن کامل (همگام، درون برنامه)؛ خروجی (ok، rtt، err، رویدادها). خطای دستگاه: SnmpError."""
        cfg = self._cfg(t, cfg)
        if self._demo(t):
            return self.finish(t, cfg, {"raw": demo_raw(t, cfg)})
        j = self.job(t, cfg)
        res = self.client.run(poll_raw(self.client, j["cred"], j["host"], j["port"], cfg, j["timeout"], j["retries"], j["budget"]),
                              j["budget"] + 30)
        return self.finish(t, cfg, res)

    def submit(self, t, done):
        """1.34: خواندن بدون اشغال نخ؛ done(cfg, نتیجه یا SnmpError) از نخ دیگری صدا زده می‌شود.
        با کارگرهای SNMP (چند هسته) یا حلقه‌ی asyncio همین برنامه (اگر کارگری نیست یا از کار افتاد)."""
        cfg = self._cfg(t)
        if self._demo(t):
            done(cfg, {"raw": demo_raw(t, cfg)})
            return
        try:
            j = self.job(t, cfg)
        except SnmpError as e:
            done(cfg, e)
            return
        send = {k: v for k, v in cfg.items() if k != "_profiles"}
        pool = self.pool
        if pool is not None and pool.usable():
            pool.set_profiles(cfg["_profiles"])
            pool.submit(t["id"], {**j, "cfg": send}, lambda r: done(cfg, r),
                        fallback=lambda: self._local(j, cfg, lambda r: done(cfg, r)))
            return
        self._local(j, cfg, lambda r: done(cfg, r))

    def _local(self, j, cfg, cb):
        loop = self.client._ensure()

        async def run():
            if self._sem is None:
                self._sem = asyncio.Semaphore(LOCAL_CONCURRENCY)
            async with self._sem:
                return await poll_raw(self.client, j["cred"], j["host"], j["port"], cfg, j["timeout"], j["retries"], j["budget"])
        fut = asyncio.run_coroutine_threadsafe(run(), loop)

        def fin(f):
            try:
                cb(f.result())
            except SnmpError as e:
                cb(e)
            except BaseException as e:  # noqa — لغو یا خطای غیرمنتظره: مثل خطای دستگاه گزارش شود
                cb(SnmpError(f"خطای داخلی SNMP: {e.__class__.__name__}"))
        fut.add_done_callback(fin)

    def _note(self, tid, msg):
        with self._lock:
            lv = self.live.get(tid)
            if lv is not None:
                lv["errors"] = [msg]
                lv["stale"] = True

    def ingest(self, t, cfg, raw, now=None):
        """نرخ‌ها، زنده، هشدارها و سری زمانی. خروجی: رویدادهای هشدار [(key, old, new, msg)]."""
        tid = t["id"]
        now = now or time.time()
        up = raw["sys"].get("uptime")
        pv = self.prev.get(tid) or {}
        dt = now - pv.get("t", 0) if pv else 0
        reboot = bool(pv) and up is not None and pv.get("up") is not None and up < pv["up"]
        if reboot and pv["up"] + dt * 100 > 2 ** 32 - 60000:     # چرخش sysUpTime (TimeTicks ۳۲ بیتی، حدود ۴۹۷ روز)، راه‌اندازی نیست
            reboot = False
        rate_ok = bool(pv) and 0 < dt < 3600 and not reboot
        cnt = {}

        def rate(key, val, bits):
            if val is None:
                return None
            cnt[key] = val
            if not rate_ok or key not in pv.get("c", {}):
                return None
            d = val - pv["c"][key]
            if d < 0:
                if bits == 32 and pv["c"][key] > 2 ** 31:   # چرخش شمارنده‌ی ۳۲ بیتی
                    d += 2 ** 32
                else:
                    return None
            return d / dt

        ifs = []
        watch = set(cfg["watch"])
        for x in raw["ifs"]:
            k = f"if:{x['name']}"
            ib, ob = rate(k + ":in", x["in"], x["bits"]), rate(k + ":out", x["out"], x["bits"])
            er = rate(k + ":err", x["err"], 32)
            ds = rate(k + ":disc", x["disc"], 32)
            row = {k2: x[k2] for k2 in ("idx", "name", "descr", "alias", "type", "admin", "oper", "speed")}
            row.update(in_bps=round(ib * 8) if ib is not None else None, out_bps=round(ob * 8) if ob is not None else None,
                       err_min=round(er * 60, 1) if er is not None else None, disc_min=round(ds * 60, 1) if ds is not None else None,
                       watch=x["name"] in watch)
            if row["speed"] and ib is not None and ob is not None:
                row["util"] = round(100 * max(ib, ob) * 8 / row["speed"], 1)
            else:
                row["util"] = None
            ifs.append(row)
        oids = []
        for o, r in zip(cfg["oids"], raw["oids"] + [None] * (len(cfg["oids"]) - len(raw["oids"]))):
            r = r or {"raw": None, "tn": ""}
            if o["type"] == "text":
                val = None if r["raw"] is None else str(r["raw"])
            elif o["type"] == "counter":
                rv = _num(r["raw"])
                rr = rate(f"oid:{o['oid']}", rv, 64 if r["tn"] == "Counter64" else 32) if rv is not None else None
                val = round(rr * o["mult"], 3) if rr is not None else None
            else:
                rv = _num(r["raw"])
                val = round(rv * o["mult"], 3) if rv is not None else None
            oids.append({**o, "value": val, "missing": r["raw"] is None})
        pr = raw.get("prof")
        for it in (pr or {}).get("items") or []:                 # 1.27: مقدارهای قالب دستگاه، با همان نمایش و هشدار OIDهای دستی
            rv, lv, txt = it["raw"], "ok", None
            if it.get("auto") and rv is None:                    # شیء MIB که این دستگاه ندارد: نمایش داده نمی‌شود
                continue
            if it["type"] == "text":
                val = None if rv is None else str(rv)[:200]
            elif it["type"] == "enum":
                val = None
                if rv is not None:
                    k = str(rv)
                    txt = f"{it['enum'].get(k) or k} ({k})" if it["enum"].get(k) else k
                    lv = it["levels"].get(k) or "ok"
                    val = txt
            elif it["type"] == "counter":
                n = _num(rv)
                rr = rate(f"oid:{it['key']}", n, 64 if it.get("tn") == "Counter64" else 32) if n is not None else None
                val = round(rr * it["mult"], 3) if rr is not None else None
            else:
                n = _num(rv)
                val = round(n * it["mult"], 3) if n is not None else None
            oids.append({"name": it["name"], "oid": it["key"], "type": it["type"], "unit": it["unit"], "mult": it["mult"],
                         "warn": it["warn"], "crit": it["crit"], "dir": it["dir"], "expect": it["expect"], "chart": it["chart"],
                         "value": val, "missing": rv is None, "prof": pr["name"], "level": lv})
        self.prev[tid] = {"t": now, "up": up, "c": cnt}
        temps = [x["value"] for x in raw["temps"] if x.get("value") is not None]
        disks = [x["pct"] for x in raw["disks"] if x.get("pct") is not None]
        if raw.get("vendor") and self.vendors.get(tid) != raw["vendor"]:
            self.vendors[tid] = raw["vendor"]
            self.vendor_new = True
        live = {"t": now, "sys": raw["sys"], "vendor": raw["vendor"], "rtt": raw["rtt"], "errors": raw["errors"],
                "uptime_s": round(up / 100) if up is not None else None, "cpu": raw["cpu"], "mem": raw["mem"],
                "disks": raw["disks"], "temps": raw["temps"], "fans": raw["fans"], "psus": raw["psus"],
                "sensors": raw["sensors"], "extra": raw["extra"], "ifs": ifs, "oids": oids,
                "profile": {"id": pr["id"], "name": pr["name"]} if pr else None,
                "temp_max": max(temps) if temps else None, "disk_max": max(disks) if disks else None}
        events = self._alarms(t, cfg, live, now)
        if reboot:
            events.append(("reboot", None, "info", f"دستگاه یا عامل SNMP آن دوباره راه‌اندازی شد (uptime {fmt_up(live['uptime_s'])})"))
        live["alarms"] = [{"key": k, **v} for k, v in (self.alarms.get(tid) or {}).items() if v["level"] in ("warn", "crit")]
        live["level"] = "crit" if any(a["level"] == "crit" for a in live["alarms"]) else "warn" if live["alarms"] else "ok"
        self.live[tid] = live
        self._port_hist(tid, cfg, ifs, now)
        self._accumulate(tid, cfg, live, now)
        return events

    # ---- پورت‌های نمایشی (1.35): انتخاب کاربر، وگرنه پیگیری‌شده‌ها، وگرنه سریع‌ترین پورت‌های وصل
    PH_LEN = 60

    @staticmethod
    def show_names(cfg, ifs, n=2):
        pick = [x for x in (cfg.get("show_ports") or []) if any(i["name"] == x for i in ifs)][:4]
        if pick:
            return pick
        n = max(0, min(4, int(cfg.get("_tpl_ports", n) if cfg.get("_tpl_ports") is not None else n)))
        if not n:
            return []
        w = set(cfg.get("watch") or [])
        cand = [x for x in ifs if x["name"] in w and x["oper"] == 1]
        if len(cand) < n:
            rest = [x for x in ifs if x["oper"] == 1 and x["type"] not in (24, 1, 53, 135, 136) and x not in cand]
            rest.sort(key=lambda x: (-(x["speed"] or 0), -((x["in_bps"] or 0) + (x["out_bps"] or 0))))
            cand += rest
        return [x["name"] for x in cand[:n]]

    def _port_hist(self, tid, cfg, ifs, now):
        names = self.show_names(cfg, ifs)
        with self._lock:
            ring = self.phist.setdefault(tid, {})
            for k in [k for k in ring if k not in names]:
                del ring[k]
            for x in ifs:
                if x["name"] in names:
                    ring.setdefault(x["name"], deque(maxlen=self.PH_LEN)).append((round(now), x["in_bps"], x["out_bps"]))
            ring["_order"] = names

    def port_rows(self, tid):
        lv = self.live.get(tid)
        with self._lock:
            ring = dict(self.phist.get(tid) or {})
        if not lv:
            return []
        by = {x["name"]: x for x in lv["ifs"]}
        out = []
        for n in ring.get("_order") or []:
            x = by.get(n)
            if not x:
                continue
            out.append({"n": n, "a": (x.get("alias") or "")[:40], "in": x["in_bps"], "out": x["out_bps"], "sp": x["speed"],
                        "u": x["util"], "o": x["oper"], "h": [[a, b] for _, a, b in list(ring.get(n) or [])[-30:]]})
        return out

    # ---- هشدارها
    def _checks(self, cfg, live):
        """[(key, level ok/warn/crit, متن)] برای همین بار خواندن."""
        th, out = cfg["th"], []

        def lvl(v, pair, below=False):
            if v is None:
                return None
            w, c = pair
            if below:
                return "crit" if c is not None and v <= c else "warn" if w is not None and v <= w else "ok"
            return "crit" if c is not None and v >= c else "warn" if w is not None and v >= w else "ok"
        if live["cpu"] and live["cpu"].get("value") is not None:
            out.append(("cpu", lvl(live["cpu"]["value"], th["cpu"]), f"CPU {live['cpu']['value']}٪"))
        if live["mem"] and live["mem"].get("pct") is not None:
            out.append(("mem", lvl(live["mem"]["pct"], th["mem"]), f"حافظه {live['mem']['pct']}٪"))
        for d in live["disks"]:
            out.append((f"disk:{d['name']}", lvl(d["pct"], th["disk"]), f"دیسک {d['name']} {d['pct']}٪"))
        for x in live["temps"]:
            lv = lvl(x.get("value"), th["temp"]) or "ok"
            dev = x.get("state") or "ok"
            rank = {"ok": 0, "warn": 1, "crit": 2}
            lv = max(lv, dev, key=lambda z: rank.get(z, 0))
            tv = x.get("value") if x.get("value") is not None else "—"
            nm = x["name"]
            msg = (f"دمای {nm} {tv}°C (وضعیت دستگاه: بحرانی)" if dev == "crit" else
                   f"دمای {nm} {tv}°C (وضعیت دستگاه: هشدار)" if dev == "warn" else f"دمای {nm} {tv}°C")
            out.append((f"temp:{nm}", lv, msg))
        # متن کامل برای هر حالت (ترجمه‌ی رابط الگوی کامل جمله را می‌خواهد)
        for x in live["fans"]:
            sv, nm = x.get("state") or "ok", x["name"]
            out.append((f"fan:{nm}", sv, f"فن {nm}: خراب/بحرانی" if sv == "crit" else f"فن {nm}: هشدار" if sv == "warn" else f"فن {nm}: سالم"))
        for x in live["psus"]:
            sv, nm = x.get("state") or "ok", x["name"]
            out.append((f"psu:{nm}", sv, f"منبع تغذیه {nm}: خراب/بحرانی" if sv == "crit" else f"منبع تغذیه {nm}: هشدار" if sv == "warn"
                        else f"منبع تغذیه {nm}: سالم"))
        for x in live["sensors"]:
            sv, nm, val = x.get("state") or "ok", x["name"], x.get("value") if x.get("value") not in (None, "") else "—"
            out.append((f"sensor:{nm}", sv, f"سنسور {nm} ({val}): هشدار دستگاه" if sv in ("crit", "warn") else f"سنسور {nm} ({val}): سالم"))
        for x in live["ifs"]:
            if not x["watch"]:
                continue
            nm = x["name"]
            if x["admin"] == 1:
                down = x["oper"] not in (1, 5)
                al = f" ({x['alias']})" if x["alias"] else ""
                ost = IF_OPER.get(x["oper"], str(x["oper"]))
                out.append((f"if:{nm}:down", "crit" if down else "ok", f"پورت {nm}{al} قطع است ({ost})" if down else f"پورت {nm}{al} وصل است"))
            if x["util"] is not None:
                out.append((f"if:{nm}:util", lvl(x["util"], th["util"]),
                            f"مصرف پورت {nm} {x['util']}٪ (ورودی {fmt_bps(x['in_bps'])}، خروجی {fmt_bps(x['out_bps'])})"))
            if x["err_min"] is not None:
                out.append((f"if:{nm}:err", lvl(x["err_min"], th["err"]), f"خطای پورت {nm}: {x['err_min']} در دقیقه"))
        for o in live["oids"]:
            k = f"oid:{o['oid']}"
            if o["type"] == "enum":
                if o["value"] is not None:
                    out.append((k, "ok" if o.get("level") in ("ok", "info", None) else o["level"], f"{o['name']}: {o['value']}"))
                continue
            if o["type"] == "text":
                if o["expect"] and o["value"] is not None:
                    bad = o["value"].strip() != o["expect"]
                    out.append((k, "crit" if bad else "ok", f"{o['name']} = «{o['value'][:60]}»" + (f" (انتظار: «{o['expect']}»)" if bad else "")))
                continue
            if o["value"] is None:
                continue
            out.append((k, lvl(o["value"], (o["warn"], o["crit"]), o["dir"] == "below") or "ok",
                        f"{o['name']} = {o['value']:g}{(' ' + o['unit']) if o['unit'] else ''}"))
        return out

    def _alarms(self, t, cfg, live, now):
        tid, after = t["id"], cfg["after"]
        cur = self.alarms.setdefault(tid, {})
        seen, events = set(), []
        for key, lv, msg in self._checks(cfg, live):
            seen.add(key)
            a = cur.setdefault(key, {"level": "ok", "since": now, "msg": msg, "pend": "ok", "n": 0})
            a["msg"] = msg
            if lv == a["level"]:
                a["pend"], a["n"] = lv, 0
                continue
            if lv == a["pend"]:
                a["n"] += 1
            else:
                a["pend"], a["n"] = lv, 1
            # بدتر شدن بعد از «after» بار پشت‌سرهم؛ بهتر شدن بعد از ۲ بار (جلوگیری از نوسان)
            need = after if {"ok": 0, "warn": 1, "crit": 2}[lv] > {"ok": 0, "warn": 1, "crit": 2}[a["level"]] else min(2, after)
            if a["n"] >= need:
                old = a["level"]
                a.update(level=lv, since=now, pend=lv, n=0)
                events.append((key, old, lv, msg))
        if live.get("errors"):
            # بخشی از خواندن شکست خورد (timeout گذرا): هشدارهای دیده‌نشده دست‌نخورده بمانند تا «برطرف شد» کاذب و نوسان نداشته باشیم
            return events
        for key in [k for k in cur if k not in seen]:     # مورد حذف شد (پورت حذف، OID حذف، تیک برداشته شد)
            a = cur.pop(key)
            if a["level"] in ("warn", "crit"):
                events.append((key, a["level"], "ok", f"{a['msg']} — دیگر بررسی نمی‌شود"))
        return events

    def clear(self, tid):
        for d in (self.live, self.prev, self.alarms, self.phist):
            d.pop(tid, None)
        with self._lock:
            self._acc5.pop(tid, None)
            self._acch.pop(tid, None)

    # ---- سری زمانی
    def _series_vals(self, cfg, live):
        v = {}
        hist = cfg.get("hist") or {"sys": 1, "if": cfg.get("if_hist", 1), "oid": 1}
        if hist.get("sys", 1):
            if live["cpu"] and live["cpu"].get("value") is not None:
                v["cpu"] = live["cpu"]["value"]
            if live["mem"] and live["mem"].get("pct") is not None:
                v["mem"] = live["mem"]["pct"]
            if live["disk_max"] is not None:
                v["disk"] = live["disk_max"]
            if live["temp_max"] is not None:
                v["temp"] = live["temp_max"]
            if live["rtt"] is not None:
                v["rtt"] = live["rtt"]
            ses = (live.get("extra") or {}).get("sessions")
            if isinstance(ses, (int, float)):
                v["ses"] = ses                  # 1.36: نمودار نشست‌های فایروال
        ports = cfg.get("ports") or "all"
        if hist.get("if", 1) and ports != "none":
            n = 0
            for x in live["ifs"]:
                if x["in_bps"] is None and x["err_min"] is None:
                    continue
                if x["type"] == 24:              # loopback
                    continue
                if ports == "watch" and not x["watch"]:
                    continue
                if ports == "up" and x["oper"] != 1 and not x["watch"]:
                    continue
                if ports == "all" and x["admin"] != 1 and not x["watch"]:
                    continue
                n += 1
                if n > MAX_IF_HIST:
                    break
                if x["in_bps"] is not None:
                    v[f"if:{x['name']}:in"] = x["in_bps"]
                    v[f"if:{x['name']}:out"] = x["out_bps"]
                if x["err_min"]:
                    v[f"if:{x['name']}:err"] = x["err_min"]
        if hist.get("oid", 1):
            for o in live["oids"]:
                if o["chart"] and isinstance(o["value"], (int, float)):
                    v[f"oid:{o['oid']}"] = o["value"]
        return v

    def _accumulate(self, tid, cfg, live, now):
        vals = self._series_vals(cfg, live)
        res = cfg.get("res") or 300
        out = []
        with self._lock:
            for acc, r, kind in ((self._acc5, res, "sd"), (self._acch, 3600, "sh")):
                b = int(now // r) * r
                e = acc.get(tid)
                if e and (e["b"] != b or e["r"] != r):
                    if e["a"]:
                        out.append((kind, tid, {"t": e["b"], **self._pack(e["a"])}))
                    e = None
                if e is None:
                    e = acc[tid] = {"b": b, "r": r, "a": {}}
                for k, x in vals.items():
                    s_ = e["a"].setdefault(k, [0.0, 0, None])
                    s_[0] += x
                    s_[1] += 1
                    s_[2] = x if s_[2] is None else max(s_[2], x)
        if out:
            self.ts.put(out)

    @staticmethod
    def _pack(acc):
        return {"a": {k: round(s[0] / s[1], 3) for k, s in acc.items() if s[1]}, "x": {k: s[2] for k, s in acc.items() if s[1]}}

    def flush(self, active=True, force=False):
        """بازه‌های تمام‌شده (یا همه با force) نوشته شوند."""
        now = time.time()
        out = []
        with self._lock:
            for acc, kind in ((self._acc5, "sd"), (self._acch, "sh")):
                for tid in list(acc):
                    e = acc[tid]
                    if force or now >= e["b"] + e["r"]:
                        if e["a"]:
                            out.append((kind, tid, {"t": e["b"], **self._pack(e["a"])}))
                        del acc[tid]
        if out and active:
            try:
                self.ts.put(out)
            except Exception:
                log.exception("snmp series write")

    def purge(self, keep, alive_ids, glob):
        """keep: {tid: (روز دقیق، روز ساعتی)} نگهداری مؤثر هر هدف (۰ = بدون محدودیت)؛ glob: همان برای کلی.
        پوشه/ردیف‌های هدف حذف‌شده همیشه پاک می‌شوند."""
        now = time.time()
        self.ts.drop_missing(alive_ids)
        for tid, (kd, kh) in keep.items():
            if kd:
                self.ts.purge("sd", now - (kd + 1) * 86400, tid)
            if kh:
                self.ts.purge("sh", now - (kh + 31) * 86400, tid)

    def remove_files(self, tid):
        self.ts.drop(tid)

    def series(self, tid, rng, keys, keep_days=0, res=300):
        """{step, times, data: {key: {avg:[], max:[]}}} — rng: بازه‌ی آماده یا {"from", "to"} (trange).
        داده‌ی دقیق (۱ یا ۵ دقیقه) فقط keep_days روز اخیر؛ بازه‌ی بلندتر یا قدیمی‌تر از داده‌ی ساعتی."""
        from . import trange
        now = time.time()
        since, until = trange.resolve(rng, now)
        f_ok = not keep_days or since >= now - keep_days * 86400 + 600
        step = trange.pick_step(until - since, res if f_ok else 3600)
        if step < 3600 and since < now - 2 * 86400 and not any(self.ts.files.has_day(tid, x) for x in trange.days(since, until, "%Y%m%d")) \
                and self.ts.mysql is None:
            step = trange.pick_step(until - since, 3600)     # داده‌ی دقیق این روزها پاک شده بود (نسخه‌های قبل) ← ساعتی
        src = "sd" if step < 3600 else "sh"
        keys = [str(k) for k in keys][:40]
        start, nb = trange.grid(since, until, step)
        acc = {k: [[0.0, 0, None] for _ in range(nb)] for k in keys}

        def add(t0, rec):
            i = int((t0 - start) // step)
            if not 0 <= i < nb:
                return
            for k in keys:
                if k in rec["a"]:
                    s_ = acc[k][i]
                    s_[0] += rec["a"][k]
                    s_[1] += 1
                    mx = rec["x"].get(k, rec["a"][k])
                    s_[2] = mx if s_[2] is None else max(s_[2], mx)
        for rec in self.ts.get(src, int(tid), start - step + 1, until):
            add(rec["t"], rec)
        with self._lock:                 # بازه‌ی جاری که هنوز نوشته نشده
            cur = (self._acc5 if src == "sd" else self._acch).get(int(tid))
            if cur and cur["a"] and cur["b"] <= until:
                add(cur["b"], self._pack(cur["a"]))
        return {"step": step, "since": since, "until": until, "res": ("1min" if step < 300 else "5min") if src == "sd" else "hour",
                "times": [start + i * step for i in range(nb)],
                "data": {k: {"avg": [round(s_[0] / s_[1], 2) if s_[1] else None for s_ in v],
                             "max": [round(s_[2], 2) if s_[2] is not None else None for s_ in v]} for k, v in acc.items()}}

    def if_heat(self, tid, rng, keep_days=0, res=300, max_bins=144, max_ports=256):
        """1.37: «نقشه‌ی حرارتی» ترافیک همه‌ی پورت‌ها: برای هر پورت در هر خانه‌ی زمانی بیشینه‌ی ورودی/خروجی (bps).
        {step, times, ports: [{n, a, sp, avg: [], max: []}]} مرتب از پرترافیک‌ترین."""
        from . import trange
        now = time.time()
        since, until = trange.resolve(rng, now)
        f_ok = not keep_days or since >= now - keep_days * 86400 + 600
        lo = res if f_ok else 3600
        step = next((x for x in trange.STEPS if x >= lo and (until - since) / x <= max_bins), trange.STEPS[-1])
        src = "sd" if step < 3600 else "sh"
        start, nb = trange.grid(since, until, step)
        acc = {}

        def add(t0, rec):
            i = int((t0 - start) // step)
            if not 0 <= i < nb:
                return
            ports = {}
            for k, v in rec["a"].items():
                if k.startswith("if:") and (k.endswith(":in") or k.endswith(":out")):
                    n = k[3:].rsplit(":", 1)[0]
                    mx = rec["x"].get(k, v)
                    p = ports.setdefault(n, [0.0, 0.0])
                    p[0], p[1] = max(p[0], v or 0), max(p[1], mx or 0)
            for n, (av, mx) in ports.items():
                row = acc.setdefault(n, [[0.0, 0, 0.0] for _ in range(nb)])
                c = row[i]
                c[0] += av
                c[1] += 1
                c[2] = max(c[2], mx)
        for rec in self.ts.get(src, int(tid), start - step + 1, until):
            add(rec["t"], rec)
        with self._lock:
            cur = (self._acc5 if src == "sd" else self._acch).get(int(tid))
            if cur and cur["a"] and cur["b"] <= until:
                add(cur["b"], self._pack(cur["a"]))
        lv = self.live.get(int(tid)) or {}
        info = {x["name"]: x for x in lv.get("ifs") or []}
        ports = []
        for n, row in acc.items():
            mx = [round(c[2]) if c[1] else None for c in row]
            ports.append({"n": n, "a": (info.get(n) or {}).get("alias") or "", "sp": (info.get(n) or {}).get("speed"),
                          "avg": [round(c[0] / c[1]) if c[1] else None for c in row], "max": mx, "peak": max([x for x in mx if x is not None] or [0])})
        ports.sort(key=lambda p: -p["peak"])
        return {"step": step, "since": since, "until": until, "times": [start + i * step for i in range(nb)], "ports": ports[:max_ports],
                "total": len(ports)}

    # ---- خروجی برای رابط
    def summary(self, tid):
        lv = self.live.get(tid)
        if not lv:
            return None
        ifs = lv["ifs"]
        return {"cpu": lv["cpu"]["value"] if lv["cpu"] else None, "mem": lv["mem"]["pct"] if lv["mem"] else None,
                "temp": lv["temp_max"], "level": lv["level"], "alarms": len(lv["alarms"]),
                "if_up": sum(1 for x in ifs if x["oper"] == 1), "if_n": len(ifs), "vendor": lv["vendor"],
                "sysname": lv["sys"].get("name") or "", "errors": len(lv["errors"])}


def cred_from_vault(vault, cid):
    pfx = f"cred.{int(cid)}."
    try:
        meta = json.loads(vault.get(pfx + "snmp", "") or "{}")
    except ValueError:
        meta = {}
    if meta.get("v") == "3":
        return {"v": "3", "user": vault.get(pfx + "username", ""), "auth": meta.get("auth") or "none",
                "priv": meta.get("priv") or "none", "auth_key": vault.get(pfx + "password", ""),
                "priv_key": vault.get(pfx + "secret", ""), "ctx": meta.get("ctx") or ""}
    return {"v": "2c", "community": vault.get(pfx + "password", "")}


def fmt_up(s):
    if s is None:
        return "—"
    s = int(s)
    d, h, m = s // 86400, s % 86400 // 3600, s % 3600 // 60
    return f"{d} روز و {h} ساعت" if d else f"{h} ساعت و {m} دقیقه"


# ---------------------------------------------------------------------------- داده‌ی نمایشی (Demo)
_DEMO = {}


def _demo_vendor(t, cfg):
    v = cfg.get("vendor") or "auto"
    if v in ("juniper", "extreme", "fortinet"):
        return v
    n = (t.get("name") or "").lower()
    for k, ven in (("juniper", "juniper"), ("jnp", "juniper"), ("extreme", "extreme"), ("exos", "extreme"), ("forti", "fortinet"), ("fw", "fortinet")):
        if k in n:
            return ven
    return "cisco"


def _demo_ports(st, rnd, names, up_down=(), admin_off=(), err=(), uplinks=None, sp=1_000_000_000, fast=()):
    """پورت‌های ساختگی با شمارنده‌های پیوسته (Demo)."""
    ifs = []
    for i, name in enumerate(names, 1):
        oper = 2 if i in up_down or i in admin_off else 1
        speed = 10_000_000_000 if i in fast else sp
        o = st["oct"].setdefault(name, [rnd.randint(10 ** 9, 10 ** 11), rnd.randint(10 ** 9, 10 ** 11)])
        if oper == 1:
            base = (6e8 if i in fast else 4e7) if i in (uplinks or {}) else 2e6
            o[0] += int(base * rnd.uniform(0.3, 1.6) * 60 / 8)
            o[1] += int(base * rnd.uniform(0.3, 1.6) * 60 / 8)
        e = st["err"].setdefault(name, 0)
        if i in err:
            st["err"][name] = e + rnd.randint(0, 40)
        ifs.append({"idx": i, "name": name, "descr": name, "alias": (uplinks or {}).get(i, ""), "type": 6,
                    "admin": 2 if i in admin_off else 1, "oper": oper, "speed": speed, "in": o[0], "out": o[1], "bits": 64,
                    "err": st["err"][name], "disc": 0})
    return ifs


def demo_raw(t, cfg):
    """دستگاه ساختگی برای حالت Demo (مقدارها تصادفی ولی پیوسته): Cisco (پیش‌فرض)، Juniper، Extreme یا FortiGate
    از روی «نوع دستگاه» یا نام هدف."""
    ven = _demo_vendor(t, cfg)
    if ven != "cisco":
        return _demo_other(t, cfg, ven)
    st = _DEMO.setdefault(t["id"], {"t0": time.time() - 86400 * 12, "oct": {}, "err": {}})
    now = time.time()
    rnd = random.Random(int(now // 60) ^ int(t["id"]))  # nosec B311 — داده‌ی نمایشی
    ifs = []
    for i in range(1, 25):
        name = f"Gi1/0/{i}"
        oper = 2 if i in (7, 19) else 1
        sp = 1_000_000_000
        o = st["oct"].setdefault(name, [rnd.randint(10 ** 9, 10 ** 11), rnd.randint(10 ** 9, 10 ** 11)])
        if oper == 1:
            base = 4e7 if i in (1, 2) else 2e6
            o[0] += int(base * rnd.uniform(0.3, 1.6) * 60 / 8)
            o[1] += int(base * rnd.uniform(0.3, 1.6) * 60 / 8)
        e = st["err"].setdefault(name, 0)
        if i == 13:
            st["err"][name] = e + rnd.randint(0, 40)
        ifs.append({"idx": i, "name": name, "descr": f"GigabitEthernet1/0/{i}", "alias": {1: "Uplink-Core", 2: "Uplink-FW"}.get(i, ""),
                    "type": 6, "admin": 2 if i == 19 else 1, "oper": oper, "speed": sp, "in": o[0], "out": o[1], "bits": 64,
                    "err": st["err"][name], "disc": 0})
    ifs.append({"idx": 100, "name": "Vl1", "descr": "Vlan1", "alias": "", "type": 53, "admin": 1, "oper": 1, "speed": 1_000_000_000,
                "in": 0, "out": 0, "bits": 64, "err": 0, "disc": 0})
    cpu = round(rnd.uniform(8, 35) + (50 if "busy" in (t.get("name") or "").lower() else 0), 0)
    return {"sys": {"descr": "Cisco IOS Software [Cupertino], Catalyst L3 Switch Software (CAT9K_IOSXE), Version 17.9.5 (Demo)",
                    "objid": "1.3.6.1.4.1.9.1.2494", "uptime": int((now - st["t0"]) * 100), "contact": "noc@example.local",
                    "name": (t.get("name") or "switch").replace(" ", "-"), "location": "Demo rack"},
            "vendor": "cisco", "rtt": round(rnd.uniform(2, 15), 1), "errors": [],
            "cpu": {"value": cpu, "items": [{"name": "Switch 1", "s5": cpu, "m1": cpu, "m5": cpu - 2},
                                            {"name": "Switch 2", "s5": round(cpu * 0.6), "m1": round(cpu * 0.6), "m5": round(cpu * 0.55)}],
                    "src": "CISCO-PROCESS-MIB"},
            "mem": {"pct": 41.5, "used": 3.4e9, "total": 8.2e9, "items": [{"name": "Processor", "type": 2, "used": 3.4e9, "total": 8.2e9, "pct": 41.5},
                                                                     {"name": "lsmpi_io", "type": 3, "used": 6.2e6, "total": 6.3e6, "pct": 98.4}],
                    "src": "CISCO-ENHANCED-MEMPOOL-MIB"},
            "disks": [], "temps": [{"name": "Switch 1 - Inlet Temp Sensor", "value": round(rnd.uniform(30, 36), 0), "thr": 56, "state": "ok"},
                                   {"name": "Switch 1 - Hotspot Temp Sensor", "value": round(rnd.uniform(48, 55), 0), "thr": 125, "state": "ok"}],
            "fans": [{"name": "Switch 1 - FAN - T1 1", "state": "ok"}, {"name": "Switch 1 - FAN - T1 2", "state": "ok"},
                     {"name": "Switch 2 - FAN - T1 1", "state": "ok"}, {"name": "Switch 2 - FAN - T1 2", "state": "ok"}],
            "psus": [{"name": "Sw1, PS1 Normal, RPS NotExist", "state": "ok"}, {"name": "Sw2, PS1 Normal, RPS NotExist", "state": "ok"}], "sensors": [], "ifs": ifs, "extra": {},
            "oids": [{"oid": o["oid"], "raw": rnd.randint(0, 100) if o["type"] != "text" else "ok", "tn": "Gauge32"} for o in cfg["oids"]]}


def _demo_other(t, cfg, ven):
    st = _DEMO.setdefault(t["id"], {"t0": time.time() - 86400 * 37, "oct": {}, "err": {}})
    now = time.time()
    rnd = random.Random(int(now // 60) ^ int(t["id"]))  # nosec B311 — داده‌ی نمایشی
    busy = 45 if "busy" in (t.get("name") or "").lower() else 0
    nm = (t.get("name") or ven).replace(" ", "-")
    up = int((now - st["t0"]) * 100)
    base = {"rtt": round(rnd.uniform(2, 15), 1), "errors": [], "disks": [], "sensors": [], "extra": {}, "fans": [], "psus": [], "temps": [],
            "oids": [{"oid": o["oid"], "raw": rnd.randint(0, 100) if o["type"] != "text" else "ok", "tn": "Gauge32"} for o in cfg["oids"]]}
    if ven == "juniper":
        ifs = _demo_ports(st, rnd, [f"ge-0/0/{i}" for i in range(24)] + [f"xe-0/1/{i}" for i in range(4)],
                          up_down=(6, 18), admin_off=(20,), err=(11,), uplinks={25: "Core-Uplink-A", 26: "Core-Uplink-B"}, fast=(25, 26, 27, 28))
        cpu = round(rnd.uniform(6, 22) + busy)
        comps = [("Routing Engine 0", 2, 42, cpu), ("Routing Engine 1", 7, 39, 2), ("FPC: EX4300-48T @ 0/*/*", 2, 37, round(cpu * 0.8)),
                 ("PIC: 48x 10/100/1000 Base-T @ 0/0/*", 2, 0, 0), ("PIC: 4x 10G SFP+ @ 0/1/*", 2, 0, 0),
                 ("Fan Tray 0 Fan 0", 2, 0, 0), ("Fan Tray 0 Fan 1", 5, 0, 0), ("Power Supply 0", 2, 0, 0), ("Power Supply 1", 6, 0, 0)]
        temps = [{"name": n, "value": tv + rnd.randint(-1, 2), "thr": None, "state": "ok"} for n, s_, tv, c in comps if tv]
        return {**base, "sys": {"descr": "Juniper Networks, Inc. ex4300-48t Ethernet Switch, kernel JUNOS 21.4R3-S5 (Demo)",
                                "objid": "1.3.6.1.4.1.2636.1.1.1.2.63", "uptime": up, "contact": "noc@example.local", "name": nm, "location": "Demo rack"},
                "vendor": "juniper", "ifs": ifs, "temps": temps,
                "cpu": {"value": cpu, "items": [{"name": "Routing Engine 0", "s5": None, "m1": cpu, "m5": None}], "src": "JUNIPER-MIB (jnxOperatingCPU)"},
                "mem": {"pct": 54.0, "used": 1.1e9, "total": 2.0e9, "items": [{"name": "Routing Engine 0", "type": 2, "used": 1.1e9, "total": 2.0e9, "pct": 54.0}],
                        "src": "JUNIPER-MIB (jnxOperatingBuffer)"},
                "extra": {"components": [{"name": n, "state": JNX_STATE[s_], "level": JNX_LEVEL[s_], "temp": tv or None, "cpu": c}
                                         for n, s_, tv, c in comps]}}
    if ven == "extreme":
        ifs = _demo_ports(st, rnd, [f"1:{i}" for i in range(1, 49)] + [f"1:{i}" for i in range(49, 53)],
                          up_down=(9, 33, 40), admin_off=(41,), err=(22, 30), uplinks={49: "To-Core-1", 50: "To-Core-2"}, fast=(49, 50, 51, 52))
        cpu = round(rnd.uniform(4, 18) + busy)
        return {**base, "sys": {"descr": "ExtremeXOS (X465-48T) version 32.6.1.6 32.6.1.6 by release-manager (Demo)",
                                "objid": "1.3.6.1.4.1.1916.2.411", "uptime": up, "contact": "noc@example.local", "name": nm, "location": "Demo rack"},
                "vendor": "extreme", "ifs": ifs,
                "cpu": {"value": cpu, "items": [], "src": "EXTREME-SOFTWARE-MONITOR-MIB"},
                "mem": {"pct": 38.2, "used": 1.5e9, "total": 3.9e9, "items": [{"name": "Slot 1", "type": 2, "used": 1.5e9, "total": 3.9e9, "pct": 38.2}],
                        "src": "EXTREME-SOFTWARE-MONITOR-MIB"},
                "temps": [{"name": "System", "value": 38 + rnd.randint(0, 3), "thr": None, "state": "ok"}],
                "fans": [{"name": f"Fan {i}", "state": "ok"} for i in range(1, 7)],
                "psus": [{"name": "PSU 1", "state": "ok"}, {"name": "PSU 2", "state": "warn"}]}
    # FortiGate
    names = ["wan1", "wan2", "dmz", "internal1", "internal2", "internal3", "internal4", "port1", "port2", "port3", "port4", "x1", "x2", "ha"]
    ifs = _demo_ports(st, rnd, names, up_down=(2, 10), admin_off=(11,), err=(7,), uplinks={1: "ISP-A", 12: "Core-Trunk"}, fast=(12, 13))
    cpu = round(rnd.uniform(9, 30) + busy)
    ses = int(42000 + 15000 * abs(((now / 3600) % 24) - 12) / 12 + rnd.randint(-900, 900))
    return {**base, "sys": {"descr": "FortiGate-200F v7.4.4,build2662,240514 (GA.F) (Demo)", "objid": "1.3.6.1.4.1.12356.101.1.2006",
                            "uptime": up, "contact": "noc@example.local", "name": nm, "location": "Demo rack"},
            "vendor": "fortinet", "ifs": ifs,
            "cpu": {"value": cpu, "items": [], "src": "FORTINET-FORTIGATE-MIB"},
            "mem": {"pct": 47.0, "used": 3.7e9, "total": 7.9e9, "items": [], "src": "FORTINET-FORTIGATE-MIB"},
            "disks": [{"name": "disk", "used": 9.1e10, "total": 2.4e11, "pct": 37.9}],
            "sensors": [{"name": "PS1 Status", "value": "1", "state": "ok"}, {"name": "PS2 Status", "value": "0", "state": "crit"},
                        {"name": "Fan 1", "value": "5400", "state": "ok"}, {"name": "Fan 2", "value": "5520", "state": "ok"},
                        {"name": "CPU On-die Temperature", "value": str(52 + rnd.randint(0, 4)), "state": "ok"}],
            "extra": {"sessions": ses, "version": "v7.4.4,build2662,240514 (GA.F)"}}


# ---------------------------------------------------------------------------- 1.37: بررسی زنده‌ی موقت
class LiveProbe:
    """خواندن پرتکرار موقت (۵/۱۰/۳۰ ثانیه) فقط CPU و پورت‌ها برای عیب‌یابی، تا وقتی پنجره باز است.
    کاملاً جدا از بررسی عادی: شمارنده‌ها، هشدارها و سری زمانی دست نمی‌خورند و چیزی ذخیره نمی‌شود.
    هر جلسه با هر درخواست رابط تمدید می‌شود؛ بدون درخواست (پنجره بسته شد) پس از LEASE ثانیه و در هر حال پس از MAX_SEC تمام می‌شود."""
    INTERVALS = (5, 10, 30)
    LEASE = 45
    MAX_SEC = 900
    KEEP = 180

    def __init__(self, runtime):
        self.rt = runtime
        self.s = {}                 # tid → جلسه
        self._lock = threading.Lock()
        self._thr = None
        self._stop = threading.Event()

    def start(self, t, sec):
        sec = int(sec) if int(sec or 0) in self.INTERVALS else 10
        now = time.time()
        with self._lock:
            cur = self.s.get(t["id"])
            if cur and cur["iv"] == sec and now < cur["end"]:
                cur["lease"] = now + self.LEASE
                return cur
            self.s[t["id"]] = {"t": dict(t), "iv": sec, "start": now, "end": now + self.MAX_SEC, "lease": now + self.LEASE,
                               "next": now, "busy": False, "prev": None, "samples": deque(maxlen=self.KEEP), "err": "", "seq": 0}
            if self._thr is None or not self._thr.is_alive():
                self._stop.clear()
                self._thr = threading.Thread(target=self._loop, name="snmp-live", daemon=True)
                self._thr.start()
            return self.s[t["id"]]

    def stop(self, tid):
        with self._lock:
            self.s.pop(int(tid), None)

    def get(self, tid, since=0):
        now = time.time()
        with self._lock:
            x = self.s.get(int(tid))
            if not x:
                return None
            x["lease"] = now + self.LEASE
            return {"iv": x["iv"], "left": max(0, round(x["end"] - now)), "err": x["err"], "seq": x["seq"],
                    "samples": [y for y in list(x["samples"]) if y["seq"] > int(since or 0)]}

    def _loop(self):
        while not self._stop.wait(0.5):
            now = time.time()
            with self._lock:
                for tid in [k for k, v in self.s.items() if now > v["end"] or now > v["lease"]]:
                    self.s.pop(tid, None)
                if not self.s:
                    self._thr = None
                    return
                due = [v for v in self.s.values() if not v["busy"] and now >= v["next"]]
                for v in due:
                    v["busy"], v["next"] = True, now + v["iv"]
            for v in due:
                self._poll(v)

    def _poll(self, v):
        t = v["t"]
        cfg = dict(load_cfg(t))
        cfg.update(collect={"cpu": 1, "mem": 1, "disk": 0, "env": 0, "if": 1}, oids=[], profile="none",
                   counters={"traffic": 1, "err": 1, "disc": 0})
        cfg["_profiles"] = []
        rt = self.rt
        if rt._demo(t):
            try:
                self._done(v, demo_raw({**t, "id": -int(t["id"])}, cfg))     # حالت جدای Demo (شمارنده‌های بررسی عادی دست نخورند)
            finally:
                v["busy"] = False
            return
        try:
            cred = rt.cred_for(t)
        except SnmpError as e:
            v["err"], v["busy"] = str(e), False
            return
        timeout = float(t.get("timeout") or 3)
        fut = asyncio.run_coroutine_threadsafe(
            collect(rt.client, cred, t["host"], t.get("port") or 161, cfg, timeout, 0), rt.client._ensure())

        def fin(f):
            try:
                self._done(v, f.result())
            except SnmpError as e:
                v["err"] = str(e)
            except BaseException as e:  # noqa
                v["err"] = e.__class__.__name__
            finally:
                v["busy"] = False
        fut.add_done_callback(fin)

    def _done(self, v, raw):
        now = time.time()
        pv = v["prev"]
        ports = []
        for x in raw["ifs"]:
            ib = ob = None
            if pv and x["name"] in pv["c"] and now > pv["t"]:
                dt = now - pv["t"]
                pi, po = pv["c"][x["name"]]
                if x["in"] is not None and pi is not None and x["in"] >= pi:
                    ib = round((x["in"] - pi) * 8 / dt)
                if x["out"] is not None and po is not None and x["out"] >= po:
                    ob = round((x["out"] - po) * 8 / dt)
            ports.append({"n": x["name"], "a": (x.get("alias") or "")[:40], "o": x["oper"], "sp": x["speed"], "i": ib, "u": ob})
        v["prev"] = {"t": now, "c": {x["name"]: (x["in"], x["out"]) for x in raw["ifs"]}}
        v["err"] = "; ".join(raw.get("errors") or [])[:200]
        if pv is None:
            return                      # نمونه‌ی اول فقط پایه‌ی محاسبه‌ی نرخ است
        v["seq"] += 1
        v["samples"].append({"seq": v["seq"], "t": round(now, 1), "cpu": (raw.get("cpu") or {}).get("value"),
                             "mem": (raw.get("mem") or {}).get("pct"), "rtt": raw.get("rtt"), "ports": ports})
