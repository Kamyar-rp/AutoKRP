"""ابزار «بررسی تکمیلی»: بررسی دوباره‌ی IPها (معمولاً غیرمخرب‌های AbuseIPDB) با دو منبع:

1) فید آنلاین FFraud (confirmed-abusive.csv؛ ستون‌ها: ip,ffraud_score,confirmations,category,type؛ خطوط # توضیح‌اند؛
   هر ۳۰ دقیقه بازسازی می‌شود و ETag دارد). یک نسخه‌ی رمزشده در پوشه‌ی داده نگه داشته می‌شود و فقط وقتی تغییر کرده
   دوباره دانلود می‌شود (If-None-Match).
2) لیست داخلی کاربر (IP یا CIDR، ستون اول هر خط): آپلود در تنظیمات (رمزشده) یا مسیر فایلی که هر اجرا خوانده می‌شود
   (فقط حالت کلاینت).

ایمنی (مثل اسکریپت اصلی کاربر): اگر فید دانلود نشود و نسخه‌ی ذخیره‌شده‌ی معتبر (جوان‌تر از max_age_hours) نباشد،
یا لیست داخلی روشن باشد ولی خوانده نشود، خطا داده می‌شود و هیچ IPای «غیرمخرب» حساب نمی‌شود.
"""
import csv
import hashlib
import io
import ipaddress
import json
import logging
import os
import re
import time
import types
from pathlib import Path

import requests

from . import atrest, paths
from .connectors.base import Cancelled, run_cancellable

log = logging.getLogger(__name__)

FFRAUD_URL = ("https://raw.githubusercontent.com/FFraud-com/ip-fraud-database/main/"
              "threat-ips/confirmed-abusive.csv")
MAX_FEED_BYTES = 300 * 1024 * 1024
MAX_LOCAL_BYTES = 50 * 1024 * 1024
HEADER_WORDS = {"ip", "src_ip", "src", "ip_address", "ip address", "address", "source_ip", "source ip", "cidr", "network"}
USER_AGENT = "AutoKRP-intel/1.0"


class IntelError(Exception):
    pass


def _dir():
    d = paths.data_dir() / "intel"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _read_json(name):
    p = _dir() / name
    if not p.exists():
        return {}
    try:
        return json.loads(atrest.read_text(p))
    except Exception:
        return {}


def _write_json(name, data):
    atrest.write_text(_dir() / name, json.dumps(data, ensure_ascii=False))


# ------------------------------------------------------------------ فید آنلاین
# 1.22: فید داده‌ی عمومی اینترنت است و ساده ذخیره می‌شود (feed.csv؛ حذف ۴۰ مگ رمز و باز کردن)؛ ولی اثر انگشت SHA-256
# آن در feed_meta.dat (رمزشده) است و هر خواندن بررسی می‌شود: فایل دست‌کاری‌شده (مثلاً IP داخلی اضافه‌شده تا بلاک
# شود) خوانده نمی‌شود. feed.dat رمزشده‌ی نسخه‌های قبل همچنان خوانده می‌شود تا دانلود بعدی.
def _feed_path():
    p = _dir() / "feed.csv"
    return p if p.exists() else _dir() / "feed.dat"


def _feed_bytes():
    p = _feed_path()
    if not p.exists():
        raise IntelError("نسخه‌ای از فید ذخیره نشده است.")
    if p.name == "feed.dat":
        return atrest.read_bytes(p)
    raw = p.read_bytes()
    want = feed_meta().get("sha256")
    if not want or hashlib.sha256(raw).hexdigest() != want:
        raise IntelError("فایل فید ذخیره‌شده با اثر انگشت ثبت‌شده جور نیست (دست‌کاری یا ناقص)؛ فید را دوباره دانلود کنید.")
    return raw


def feed_meta():
    return _read_json("feed_meta.dat")


def _feed_header(text):
    """نام ستون‌های فید (اولین خط غیر #). بدون ستون ip ← خطا (قالب حدس زده نمی‌شود)."""
    for line in io.StringIO(text):
        if not line.strip() or line.startswith("#"):
            continue
        cols = [c.strip().lstrip("﻿").lower() for c in next(csv.reader([line]))]
        if "ip" not in cols:
            raise IntelError(f"فید ستون «ip» ندارد (ستون‌ها: {', '.join(cols[:10])}).")
        return cols
    raise IntelError("فید خالی است یا سطر عنوان ندارد.")


def update_feed(cfg, cancel=None, force=False, logf=None):
    """نسخه‌ی تازه‌ی فید (در صورت نیاز). خروجی: (meta، پیام وضعیت). خطا ← IntelError."""
    logf = logf or (lambda m, lv="info": None)
    url = str(cfg.get("feed_url") or FFRAUD_URL).strip()
    if not url.lower().startswith(("https://", "http://")):
        raise IntelError("آدرس فید باید با https:// شروع شود.")
    meta = feed_meta()
    have = _feed_path().exists() and meta.get("url") == url
    if have:
        try:
            _feed_bytes()                 # اثر انگشت جور نیست ← دوباره دانلود می‌شود
        except IntelError:
            have = False
            meta.pop("etag", None)
    age = time.time() - float(meta.get("fetched") or 0) if have else None
    refresh = max(0, int(cfg.get("refresh_minutes") or 0)) * 60
    if have and not force and age is not None and age < refresh:
        return meta, f"نسخه‌ی ذخیره‌شده‌ی فید ({_ago(age)} پیش) استفاده شد"
    headers = {"User-Agent": USER_AGENT}
    if have and meta.get("etag"):
        headers["If-None-Match"] = meta["etag"]
    meta["last_try"] = time.time()
    holder = types.SimpleNamespace(live_resp=None)

    def fetch():
        with requests.Session() as s:
            s.verify = bool(cfg.get("verify_ssl", True))
            r = s.get(url, headers=headers, timeout=(15, max(10, int(cfg.get("timeout") or 120))), stream=True,
                      allow_redirects=True, verify=s.verify)
            holder.live_resp = r
            if r.status_code == 304 and have:
                return None, None
            if r.status_code != 200:
                raise IntelError(f"دانلود فید ناموفق: HTTP {r.status_code}")
            buf, n = io.BytesIO(), 0
            for chunk in r.iter_content(1024 * 1024):
                if cancel is not None and cancel.is_set():
                    raise InterruptedError()
                n += len(chunk)
                if n > MAX_FEED_BYTES:
                    raise IntelError(f"حجم فید بیشتر از {MAX_FEED_BYTES // (1024 * 1024)}MB است.")
                buf.write(chunk)
            return buf.getvalue(), r.headers.get("ETag") or ""
    try:
        if cancel is not None:     # لغو فوری حتی وقتی سرور فید جواب نمی‌دهد
            try:
                data, etag = run_cancellable(cancel, fetch, holder, name="feed")
            except Cancelled:
                raise InterruptedError()
        else:
            data, etag = fetch()
        if data is None:
            meta.update(fetched=time.time(), last_error="")
            _write_json("feed_meta.dat", meta)
            return meta, "فید تغییری نکرده بود (304)؛ نسخه‌ی ذخیره‌شده استفاده شد"
    except InterruptedError:
        raise
    except (IntelError, requests.RequestException) as e:
        return _fail(meta, have, age, cfg, logf, e)
    text = data.decode("utf-8-sig", "replace")
    try:
        cols = _feed_header(text)
    except IntelError as e:
        return _fail(meta, have, age, cfg, logf, e)
    rows = sum(1 for line in text.splitlines() if line and not line.startswith("#")) - 1
    tmp = _dir() / "feed.csv.tmp"
    tmp.write_bytes(data)
    meta = {"url": url, "fetched": time.time(), "etag": etag, "size": len(data), "rows": max(0, rows), "columns": cols,
            "last_try": time.time(), "last_error": "", "sha256": hashlib.sha256(data).hexdigest()}
    _write_json("feed_meta.dat", meta)          # اول اثر انگشت، بعد فایل (هر دو حالت ناقص با بررسی رد می‌شود)
    os.replace(tmp, _dir() / "feed.csv")
    old = _dir() / "feed.dat"
    if old.exists():
        old.unlink()
    return meta, f"فید دانلود شد ({len(data) // 1024:,}KB، {max(0, rows):,} IP)"


def _fail(meta, have, age, cfg, logf, err):
    msg = str(err) if isinstance(err, IntelError) else f"دانلود فید ناموفق: {err.__class__.__name__}: {str(err)[:200]}"
    meta["last_error"] = msg
    if meta.get("url"):
        _write_json("feed_meta.dat", meta)
    max_age = float(cfg.get("max_age_hours") or 0) * 3600
    if have and age is not None and age <= max_age:
        logf(f"{msg}؛ نسخه‌ی ذخیره‌شده‌ی {_ago(age)} پیش استفاده می‌شود", "warn")
        return meta, f"نسخه‌ی ذخیره‌شده‌ی فید ({_ago(age)} پیش) به‌خاطر خطای دانلود استفاده شد"
    raise IntelError(msg + ("؛ نسخه‌ی ذخیره‌شده هم قدیمی‌تر از حد مجاز است" if have else "؛ نسخه‌ی ذخیره‌شده‌ای هم نیست")
                     + ". برای جلوگیری از غیرمخرب حساب کردن اشتباه IPها، بررسی انجام نشد.")


def _ago(sec):
    sec = int(sec or 0)
    if sec < 3600:
        return f"{max(1, sec // 60)} دقیقه"
    if sec < 86400:
        return f"{sec // 3600} ساعت"
    return f"{sec // 86400} روز"


def feed_lookup(targets, min_score=0):
    """رکورد فید برای IPهای خواسته‌شده (بالاترین امتیاز اگر تکراری باشد). {ip: {...}}"""
    text = _feed_bytes().decode("utf-8-sig", "replace")
    cols = None
    out = {}
    targets = set(targets)
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        if cols is None:
            cols = [c.strip().lstrip("﻿").lower() for c in next(csv.reader([line]))]
            if "ip" not in cols:
                raise IntelError("فید ذخیره‌شده ستون «ip» ندارد.")
            ip_i = cols.index("ip")
            continue
        if ip_i == 0:
            ip = line.split(",", 1)[0].strip()
            if ip not in targets:
                continue
        row = next(csv.reader([line]))
        if len(row) <= ip_i:
            continue
        ip = row[ip_i].strip()
        if ip not in targets:
            continue
        d = dict(zip(cols, (c.strip() for c in row)))
        score = _int(d.get("ffraud_score") or d.get("score"))
        if score < min_score:
            continue
        rec = {"ip": ip, "score": score, "confirmations": _int(d.get("confirmations")),
               "category": d.get("category") or "", "type": d.get("type") or ""}
        if ip not in out or score > out[ip]["score"]:
            out[ip] = rec
    return out


def _int(v):
    try:
        return int(float(v))
    except (TypeError, ValueError):
        return 0


# ------------------------------------------------------------------ لیست داخلی
def parse_list(text):
    """هر خط: IP یا CIDR در اولین خانه (جداکننده‌ی , ; tab فاصله). # = توضیح. خروجی: (ips:set, nets:list, invalid:list)"""
    ips, nets, bad = set(), [], []
    for n, line in enumerate(str(text or "").splitlines(), 1):
        line = line.split("#", 1)[0].strip().lstrip("﻿")
        if not line:
            continue
        cell = line.replace(";", ",").replace("\t", ",").split(",")[0].strip().strip('"').strip()
        cell = cell.split()[0] if cell.split() else ""
        if not cell:
            continue
        if cell.lower() in HEADER_WORDS:
            continue
        try:
            if "/" in cell:
                net = ipaddress.ip_network(cell, strict=False)
                if net.num_addresses == 1:
                    ips.add(str(net.network_address))
                else:
                    nets.append(net)
            else:
                ips.add(str(ipaddress.ip_address(cell)))
        except ValueError:
            bad.append(f"{n}: {cell[:60]}")
    return ips, nets, bad


def local_meta():
    return _read_json("local_meta.dat")


def save_local(src_path, name=None):
    """فایل لیست داخلی (ساده یا آپلودِ رمزشده) ← نسخه‌ی رمزشده‌ی برنامه. خروجی: meta"""
    p = Path(src_path)
    if not p.is_file():
        raise IntelError("فایل پیدا نشد.")
    if p.stat().st_size > MAX_LOCAL_BYTES + 1024:
        raise IntelError(f"حجم فایل بیشتر از {MAX_LOCAL_BYTES // (1024 * 1024)}MB است.")
    raw = atrest.read_bytes(p)
    text = _decode(raw)
    ips, nets, bad = parse_list(text)
    if not ips and not nets:
        raise IntelError("هیچ IP یا CIDR معتبری در فایل نیست (ستون اول هر خط خوانده می‌شود).")
    atrest.write_bytes(_dir() / "local.dat", text.encode("utf-8"))
    meta = {"name": name or p.name, "uploaded": time.time(), "ips": len(ips), "nets": len(nets), "invalid": len(bad),
            "invalid_sample": bad[:10]}
    _write_json("local_meta.dat", meta)
    return meta


def clear_local():
    for n in ("local.dat", "local_meta.dat"):
        f = _dir() / n
        if f.exists():
            atrest.write_bytes(f, b"")     # بازنویسی پیش از حذف
            f.unlink()


def _decode(raw):
    for enc in ("utf-8-sig", "cp1256"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", "replace")


def load_local(cfg):
    """(ips, nets, توضیح منبع). مسیر فایل (فقط کلاینت) هر بار خوانده می‌شود؛ وگرنه نسخه‌ی آپلودشده."""
    path = str(cfg.get("local_path") or "").strip().strip('"')
    if path and not paths.is_server():
        p = Path(path)
        if not p.is_file():
            raise IntelError(f"فایل لیست داخلی پیدا نشد: {path}")
        if p.stat().st_size > MAX_LOCAL_BYTES:
            raise IntelError("حجم فایل لیست داخلی بیش از حد است.")
        ips, nets, bad = parse_list(_decode(atrest.read_bytes(p)))
        mt = time.strftime("%Y-%m-%d %H:%M", time.localtime(p.stat().st_mtime))
        return ips, nets, f"فایل {p.name} (تغییر {mt})", bad
    f = _dir() / "local.dat"
    if not f.exists():
        raise IntelError("لیست داخلی بارگذاری نشده است (تنظیمات ← بررسی تکمیلی).")
    ips, nets, bad = parse_list(atrest.read_bytes(f).decode("utf-8", "replace"))
    m = local_meta()
    when = time.strftime("%Y-%m-%d %H:%M", time.localtime(m.get("uploaded") or 0)) if m.get("uploaded") else "—"
    return ips, nets, f"لیست آپلودشده‌ی {m.get('name') or '-'} ({when})", bad


def local_match(ip, ips, nets):
    if ip in ips:
        return ip
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for n in nets:
        if n.version == a.version and a in n:
            return str(n)
    return None


# ------------------------------------------------------------------ 1.44: فهرست‌های عمومی دانلودی (رایگان)
# هر دو فقط متن ساده‌اند (IP یا CIDR در هر خط) و فقط به‌عنوان داده خوانده می‌شوند: هیچ چیزی اجرا یا باز نمی‌شود، هر خطی که
# IP یا CIDR معتبر نیست کنار گذاشته می‌شود، حجم سقف دارد و رنج‌های داخلی/رزرو (مثل 10/8، 100.64/10، 0/8) هرگز
# «مخرب» حساب نمی‌شوند. اثر انگشت فایل در meta رمزشده است (مثل فید FFraud) تا فایل ذخیره‌شده دست‌کاری نشود.
# قالب‌ها از فایل واقعی بررسی شد (۱۴۰۵/۰۸/۱۴): firehol_level1.netset = خطوط # + یک IP/CIDR در هر خط؛
# ipsum.txt = خطوط # + «IP<tab>تعداد فهرست‌ها».
LISTS = {
    "firehol_l1": {"name": "FireHOL Level 1", "fmt": "net",
                   "url": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset"},
    "ipsum": {"name": "IPsum", "fmt": "ipsum", "url": "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"},
    # 1.44: فهرست IOC مرکز افتا (درخواست کاربر). قالب فایل از این محیط دیده نشد (دسترسی بسته بود)؛ با همان خواننده‌ی محتاط
    # خوانده می‌شود: اولین بخش هر خط (جداشده با فاصله، , یا ;) اگر IP یا CIDR عمومی باشد. بدون هیچ IP ← خطا، نه «پاک».
    # قالب (تأیید کاربر): هر خط یک IP. ممکن است کوتاه باشد، پس حداقل یک IP معتبر کافی است (صفحه‌ی خطای HTML هیچ IPی ندارد).
    "afta": {"name": "AFTA IOC", "fmt": "net", "min": 1, "url": "https://afta.gov.ir/uploads/IP/AFTA_IOC_IPs.txt"},
}
MAX_LIST_BYTES = 50 * 1024 * 1024
MIN_LIST_ENTRIES = 50          # کمتر از این ← احتمالاً صفحه‌ی خطا یا فایل ناقص؛ پذیرفته نمی‌شود


def _global(net):
    try:
        return net.is_global and not net.is_multicast
    except AttributeError:
        return False


def parse_feed_list(fmt, text, min_level=1):
    """(ips: {ip: سطح}, nets: [شبکه]) — فقط IP/CIDR معتبر و عمومی. سطح = تعداد فهرست‌ها (IPsum) یا None."""
    ips, nets = {}, []
    for line in str(text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        cell, lvl = re.split(r"[\s,;|]+", line)[0].strip().strip('"\''), None
        if fmt == "ipsum":
            if len(parts) < 2 or not parts[1].isdigit():
                continue
            lvl = int(parts[1])
            if lvl < min_level:
                continue
        try:
            if "/" in cell:
                n = ipaddress.ip_network(cell, strict=False)
                if not _global(n):
                    continue
                if n.num_addresses == 1:
                    ips[str(n.network_address)] = lvl
                else:
                    nets.append(n)
            else:
                a = ipaddress.ip_address(cell)
                if _global(ipaddress.ip_network(a)):
                    ips[str(a)] = lvl
        except ValueError:
            continue
    return ips, nets


def list_url(lid, cfg):
    """1.46.1: آدرس هر فهرست مثل فید FFraud قابل تغییر است (خالی = آدرس پیش‌فرض)."""
    u = str(((cfg or {}).get("list_urls") or {}).get(lid) or "").strip()
    return u or LISTS[lid]["url"]


def list_meta(lid):
    return _read_json(f"list_{lid}_meta.dat")


def _list_file(lid):
    return _dir() / f"list_{lid}.txt"


def update_list(lid, cfg, cancel=None, force=False, logf=None):
    """نسخه‌ی تازه‌ی یک فهرست عمومی (در صورت نیاز). خروجی: (meta، پیام). خطا ← IntelError."""
    logf = logf or (lambda m, lv="info": None)
    spec = LISTS[lid]
    url, name = list_url(lid, cfg), spec["name"]
    if not url.lower().startswith(("https://", "http://")):
        raise IntelError(f"{name}: آدرس باید با https:// شروع شود.")
    meta = list_meta(lid)
    f = _list_file(lid)
    have = f.exists() and meta.get("url") == url and hashlib.sha256(f.read_bytes()).hexdigest() == meta.get("sha256")
    age = time.time() - float(meta.get("fetched") or 0) if have else None
    refresh = max(30, int(cfg.get("refresh_minutes") or 60)) * 60
    if have and not force and age is not None and age < refresh:
        return meta, f"{name}: نسخه‌ی ذخیره‌شده ({_ago(age)} پیش)"
    headers = {"User-Agent": USER_AGENT}
    if have and meta.get("etag"):
        headers["If-None-Match"] = meta["etag"]
    holder = types.SimpleNamespace(live_resp=None)

    def fetch():
        with requests.Session() as s:
            s.verify = bool(cfg.get("verify_ssl", True))
            r = s.get(url, headers=headers, timeout=(15, max(10, int(cfg.get("timeout") or 120))), stream=True,
                      allow_redirects=True, verify=s.verify)
            holder.live_resp = r
            if r.status_code == 304 and have:
                return None, None
            if r.status_code != 200:
                raise IntelError(f"{name}: دانلود ناموفق (HTTP {r.status_code})")
            buf, n = io.BytesIO(), 0
            for chunk in r.iter_content(1024 * 1024):
                if cancel is not None and cancel.is_set():
                    raise InterruptedError()
                n += len(chunk)
                if n > MAX_LIST_BYTES:
                    raise IntelError(f"{name}: حجم بیشتر از {MAX_LIST_BYTES // (1024 * 1024)}MB است.")
                buf.write(chunk)
            return buf.getvalue(), r.headers.get("ETag") or ""

    def fail(e):
        msg = str(e) if isinstance(e, IntelError) else f"{name}: دانلود ناموفق: {e.__class__.__name__}: {str(e)[:200]}"
        meta["last_error"], meta["last_try"] = msg, time.time()
        _write_json(f"list_{lid}_meta.dat", meta)
        max_age = float(cfg.get("max_age_hours") or 24) * 3600
        if have and age is not None and age <= max_age:
            logf(f"{msg}؛ نسخه‌ی ذخیره‌شده‌ی {_ago(age)} پیش استفاده می‌شود", "warn")
            return meta, f"{name}: نسخه‌ی ذخیره‌شده ({_ago(age)} پیش) به‌خاطر خطای دانلود"
        raise IntelError(msg + ". برای جلوگیری از پاک حساب کردن اشتباه، بررسی انجام نشد.")
    try:
        if cancel is not None:
            try:
                data, etag = run_cancellable(cancel, fetch, holder, name="list")
            except Cancelled:
                raise InterruptedError()
        else:
            data, etag = fetch()
    except InterruptedError:
        raise
    except (IntelError, requests.RequestException) as e:
        return fail(e)
    if data is None:
        meta.update(fetched=time.time(), last_error="", last_try=time.time())
        _write_json(f"list_{lid}_meta.dat", meta)
        return meta, f"{name}: تغییری نکرده بود (304)"
    text = data.decode("utf-8", "replace")
    ips, nets = parse_feed_list(spec["fmt"], text, 1)
    if len(ips) + len(nets) < spec.get("min", MIN_LIST_ENTRIES):
        return fail(IntelError(f"{name}: فایل دریافتی فهرست معتبری نیست ({len(ips) + len(nets)} مورد)"))
    tmp = f.with_suffix(".tmp")
    tmp.write_bytes(data)
    meta = {"url": url, "fetched": time.time(), "etag": etag, "size": len(data), "ips": len(ips), "nets": len(nets),
            "last_try": time.time(), "last_error": "", "sha256": hashlib.sha256(data).hexdigest()}
    _write_json(f"list_{lid}_meta.dat", meta)
    os.replace(tmp, f)
    return meta, f"{name}: دانلود شد ({len(data) // 1024:,}KB، {len(ips):,}\u200f IP و {len(nets):,} رنج)"


def list_lookup(lid, targets, min_level=1, cfg=None):
    """{ip: توضیح} برای IPهایی که در فهرست هستند. فایل ذخیره‌شده با اثر انگشت بررسی می‌شود."""
    spec, f, meta = LISTS[lid], _list_file(lid), list_meta(lid)
    if not f.exists() or (cfg is not None and meta.get("url") != list_url(lid, cfg)):
        raise IntelError(f"{spec['name']}: نسخه‌ای ذخیره نشده است.")
    raw = f.read_bytes()
    if hashlib.sha256(raw).hexdigest() != meta.get("sha256"):
        raise IntelError(f"{spec['name']}: فایل ذخیره‌شده با اثر انگشت ثبت‌شده جور نیست؛ دوباره دانلود کنید.")
    ips, nets = parse_feed_list(spec["fmt"], raw.decode("utf-8", "replace"), min_level)
    out = {}
    for ip in targets:
        if ip in ips:
            out[ip] = f"در {ips[ip]} فهرست" if ips[ip] else ip
            continue
        m = local_match(ip, set(), nets)
        if m:
            out[ip] = f"رنج {m}"
    return out


# ------------------------------------------------------------------ 1.59: مدیر منابع (فهرست قابل ویرایش)
# هر منبع: {"id", "name", "enabled", "kind": url|path|upload, "url", "path", "fmt": lines|csv|ipsum, "ip_col", "score_col",
#            "min_score", "min_entries", "builtin"}. منابع پیش‌فرض هم مثل بقیه ویرایش و حذف می‌شوند؛ «بازگرداندن پیش‌فرض‌ها».
# ایمنی مثل قبل: منبع اینترنتی فقط IP/CIDR عمومی؛ خطای دانلود بدون نسخه‌ی معتبرِ جوان‌تر از max_age_hours ← خطا (نه «پاک»)؛
# اثر انگشت فایل ذخیره‌شده در meta رمزشده؛ فایل روی کامپیوتر/آپلود (داده‌ی خود کاربر) هر رنجی را می‌پذیرد.
KINDS = ("url", "path", "upload")
FMTS = ("lines", "csv", "ipsum")
MAX_SOURCES = 30
MAX_SRC_BYTES = MAX_FEED_BYTES
_SID = re.compile(r"^[a-z0-9_]{2,24}$")


def default_sources():
    return [
        {"id": "ffraud", "name": "FFraud", "enabled": True, "kind": "url", "url": FFRAUD_URL, "path": "", "fmt": "csv",
         "ip_col": "ip", "score_col": "ffraud_score", "min_score": 50, "min_entries": MIN_LIST_ENTRIES, "builtin": True},
        {"id": "firehol_l1", "name": "FireHOL Level 1", "enabled": False, "kind": "url", "url": LISTS["firehol_l1"]["url"], "path": "",
         "fmt": "lines", "ip_col": "", "score_col": "", "min_score": 0, "min_entries": MIN_LIST_ENTRIES, "builtin": True},
        {"id": "ipsum", "name": "IPsum", "enabled": False, "kind": "url", "url": LISTS["ipsum"]["url"], "path": "", "fmt": "ipsum",
         "ip_col": "", "score_col": "", "min_score": 3, "min_entries": MIN_LIST_ENTRIES, "builtin": True},
        {"id": "afta", "name": "AFTA IOC", "enabled": False, "kind": "url", "url": LISTS["afta"]["url"], "path": "", "fmt": "lines",
         "ip_col": "", "score_col": "", "min_score": 0, "min_entries": 1, "builtin": True},
        {"id": "local", "name": "لیست داخلی", "enabled": False, "kind": "upload", "url": "", "path": "", "fmt": "lines",
         "ip_col": "", "score_col": "", "min_score": 0, "min_entries": 1, "builtin": True},
    ]


def sources(cfg):
    """منابع مؤثر: فهرست ذخیره‌شده، یا (تنظیمات پیش از 1.59) ساخته‌شده از کلیدهای قدیمی."""
    cfg = cfg or {}
    if isinstance(cfg.get("sources"), list):
        return cfg["sources"]
    out = default_sources()
    by = {s["id"]: s for s in out}
    by["ffraud"].update(enabled=bool(cfg.get("feed_enabled", True)), url=str(cfg.get("feed_url") or FFRAUD_URL),
                        min_score=int(cfg.get("min_score") or 0))
    for lid in ("firehol_l1", "ipsum", "afta"):
        by[lid]["enabled"] = bool((cfg.get("lists") or {}).get(lid))
        u = str((cfg.get("list_urls") or {}).get(lid) or "").strip()
        if u:
            by[lid]["url"] = u
    by["ipsum"]["min_score"] = max(1, int(cfg.get("ipsum_min") or 3))
    lp = str(cfg.get("local_path") or "").strip()
    by["local"].update(enabled=bool(cfg.get("local_enabled")), kind="path" if lp else "upload", path=lp)
    return out


def clean_sources(items, server=False):
    if not isinstance(items, list):
        raise IntelError("فهرست منابع نامعتبر است.")
    if len(items) > MAX_SOURCES:
        raise IntelError(f"حداکثر {MAX_SOURCES} منبع.")
    out, ids, names = [], set(), set()
    for i, s in enumerate(items, 1):
        if not isinstance(s, dict):
            raise IntelError(f"منبع {i} نامعتبر است.")
        name = re.sub(r"[\x00-\x1f\x7f]", " ", str(s.get("name") or "")).strip()[:60]
        if not name:
            raise IntelError(f"منبع {i}: نام را وارد کنید.")
        if name.lower() in names:
            raise IntelError(f"نام منبع تکراری است: {name}")
        names.add(name.lower())
        sid = str(s.get("id") or "").strip().lower()
        if not _SID.match(sid) or sid in ids:
            sid = "s" + hashlib.sha256(f"{name}{time.time()}{i}".encode()).hexdigest()[:8]
        ids.add(sid)
        kind = s.get("kind") if s.get("kind") in KINDS else "url"
        fmt = s.get("fmt") if s.get("fmt") in FMTS else "lines"
        url = str(s.get("url") or "").strip()[:500]
        path = str(s.get("path") or "").strip().strip('"')[:400]
        p = f"منبع «{name}»: "
        if kind == "url" and not url.lower().startswith(("https://", "http://")):
            raise IntelError(p + "آدرس باید با https:// شروع شود.")
        if kind == "path":
            if server:
                raise IntelError(p + "در حالت سرور «فایل روی کامپیوتر» نیست؛ فایل را آپلود کنید.")
            if not path:
                raise IntelError(p + "مسیر فایل را وارد کنید.")
        ip_col = str(s.get("ip_col") or "").strip()[:60]
        if fmt == "csv" and not ip_col:
            raise IntelError(p + "نام ستون IP را برای CSV وارد کنید.")
        try:
            ms = int(s.get("min_score") or 0)
            me = int(s.get("min_entries") if s.get("min_entries") not in (None, "") else 1)
        except (TypeError, ValueError):
            raise IntelError(p + "حداقل امتیاز باید عدد باشد.")
        out.append({"id": sid, "name": name, "enabled": bool(s.get("enabled")), "kind": kind, "url": url if kind == "url" else "",
                    "path": path if kind == "path" else "", "fmt": fmt, "ip_col": ip_col if fmt == "csv" else "",
                    "score_col": str(s.get("score_col") or "").strip()[:60] if fmt == "csv" else "",
                    "min_score": max(0, min(1_000_000, ms)), "min_entries": max(1, min(100_000, me)), "builtin": bool(s.get("builtin"))})
    return out


def src_meta(sid):
    return _read_json(f"src_{sid}_meta.dat")


def _src_file(sid):
    return _dir() / f"src_{sid}.txt"


def _src_upload(sid):
    return _dir() / f"src_{sid}.dat"


def _csv_cols(text):
    for line in io.StringIO(text):
        if not line.strip() or line.startswith("#"):
            continue
        return [c.strip().lstrip("﻿") for c in next(csv.reader([line]))]
    return []


def parse_source(src, text, private_ok=False):
    """(ips: {ip: توضیح}، nets: [(شبکه، توضیح)]) — فقط ردیف‌های بالاتر از حداقل امتیاز."""
    ok = (lambda n: True) if private_ok else _global
    ips, nets = {}, []

    def add(cell, why):
        try:
            if "/" in cell:
                n = ipaddress.ip_network(cell, strict=False)
                if not ok(n):
                    return
                if n.num_addresses == 1:
                    ips[str(n.network_address)] = why
                else:
                    nets.append((n, why))
            else:
                a = ipaddress.ip_address(cell)
                if ok(ipaddress.ip_network(a)):
                    ips[str(a)] = why
        except ValueError:
            return
    if src["fmt"] == "csv":
        cols = None
        for line in text.splitlines():
            if not line.strip() or line.startswith("#"):
                continue
            row = next(csv.reader([line]))
            if cols is None:
                cols = [c.strip().lstrip("﻿").lower() for c in row]
                ic = src["ip_col"].lower()
                if ic not in cols:
                    raise IntelError(f"{src['name']}: ستون «{src['ip_col']}» در فایل نیست (ستون‌ها: {', '.join(cols[:12])}).")
                ii = cols.index(ic)
                si = cols.index(src["score_col"].lower()) if src.get("score_col") and src["score_col"].lower() in cols else None
                if src.get("score_col") and si is None:
                    raise IntelError(f"{src['name']}: ستون امتیاز «{src['score_col']}» در فایل نیست.")
                extra = [cols.index(c) for c in ("confirmations", "category", "type") if c in cols]
                continue
            if len(row) <= ii:
                continue
            why = ""
            if si is not None:
                sc = _int(row[si]) if si < len(row) else 0
                if sc < int(src.get("min_score") or 0):
                    continue
                why = f"امتیاز {sc}"
            more = [row[j].strip() for j in extra if j < len(row) and row[j].strip()]
            if more:
                why = "، ".join([why] + more if why else more)
            add(row[ii].strip(), why)
        return ips, nets
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip().lstrip("﻿")
        if not line:
            continue
        parts = re.split(r"[\s,;|]+", line)
        cell, why = parts[0].strip().strip('"\''), ""
        if cell.lower() in HEADER_WORDS:
            continue
        if src["fmt"] == "ipsum":
            if len(parts) < 2 or not parts[1].isdigit():
                continue
            if int(parts[1]) < max(1, int(src.get("min_score") or 1)):
                continue
            why = f"در {parts[1]} فهرست"
        add(cell, why)
    return ips, nets


def _fetch_url(src, cfg, have, meta, cancel):
    headers = {"User-Agent": USER_AGENT}
    if have and meta.get("etag"):
        headers["If-None-Match"] = meta["etag"]
    holder = types.SimpleNamespace(live_resp=None)

    def fetch():
        with requests.Session() as s:
            s.verify = bool(cfg.get("verify_ssl", True))
            r = s.get(src["url"], headers=headers, timeout=(15, max(10, int(cfg.get("timeout") or 120))), stream=True,
                      allow_redirects=True, verify=s.verify)
            holder.live_resp = r
            if r.status_code == 304 and have:
                return None, None
            if r.status_code != 200:
                raise IntelError(f"{src['name']}: دانلود ناموفق (HTTP {r.status_code})")
            buf, n = io.BytesIO(), 0
            for chunk in r.iter_content(1024 * 1024):
                if cancel is not None and cancel.is_set():
                    raise InterruptedError()
                n += len(chunk)
                if n > MAX_SRC_BYTES:
                    raise IntelError(f"{src['name']}: حجم بیشتر از {MAX_SRC_BYTES // (1024 * 1024)}MB است.")
                buf.write(chunk)
            return buf.getvalue(), r.headers.get("ETag") or ""
    if cancel is not None:
        try:
            return run_cancellable(cancel, fetch, holder, name="intel-src")
        except Cancelled:
            raise InterruptedError()
    return fetch()


def update_source(src, cfg, cancel=None, force=False, logf=None):
    """فقط منبع اینترنتی: نسخه‌ی تازه در صورت نیاز. خروجی: (meta، پیام)."""
    logf = logf or (lambda m, lv="info": None)
    name, sid = src["name"], src["id"]
    meta, f = src_meta(sid), _src_file(sid)
    have = f.exists() and meta.get("url") == src["url"] and hashlib.sha256(f.read_bytes()).hexdigest() == meta.get("sha256")
    age = time.time() - float(meta.get("fetched") or 0) if have else None
    refresh = max(5, int(cfg.get("refresh_minutes") or 60)) * 60
    if have and not force and age is not None and age < refresh:
        return meta, f"{name}: نسخه‌ی ذخیره‌شده ({_ago(age)} پیش)"

    def fail(e):
        msg = str(e) if isinstance(e, IntelError) else f"{name}: دانلود ناموفق: {e.__class__.__name__}: {str(e)[:200]}"
        meta["last_error"], meta["last_try"] = msg, time.time()
        _write_json(f"src_{sid}_meta.dat", meta)
        max_age = float(cfg.get("max_age_hours") or 24) * 3600
        if have and age is not None and age <= max_age:
            logf(f"{msg}؛ نسخه‌ی ذخیره‌شده‌ی {_ago(age)} پیش استفاده می‌شود", "warn")
            return meta, f"{name}: نسخه‌ی ذخیره‌شده ({_ago(age)} پیش) به‌خاطر خطای دانلود"
        raise IntelError(msg + ". برای جلوگیری از پاک حساب کردن اشتباه، بررسی انجام نشد.")
    try:
        data, etag = _fetch_url(src, cfg, have, meta, cancel)
    except InterruptedError:
        raise
    except (IntelError, requests.RequestException) as e:
        return fail(e)
    if data is None:
        meta.update(fetched=time.time(), last_error="", last_try=time.time())
        _write_json(f"src_{sid}_meta.dat", meta)
        return meta, f"{name}: تغییری نکرده بود (304)"
    text = data.decode("utf-8-sig", "replace")
    try:
        ips, nets = parse_source(src, text)
    except IntelError as e:
        return fail(e)
    if len(ips) + len(nets) < int(src.get("min_entries") or 1):
        return fail(IntelError(f"{name}: فایل دریافتی فهرست معتبری نیست ({len(ips) + len(nets)} مورد)"))
    tmp = f.with_suffix(".tmp")
    tmp.write_bytes(data)
    meta = {"url": src["url"], "fetched": time.time(), "etag": etag, "size": len(data), "ips": len(ips), "nets": len(nets),
            "last_try": time.time(), "last_error": "", "sha256": hashlib.sha256(data).hexdigest()}
    _write_json(f"src_{sid}_meta.dat", meta)
    os.replace(tmp, f)
    return meta, f"{name}: دانلود شد ({len(data) // 1024:,}KB، {len(ips):,}\u200f IP و {len(nets):,} رنج)"


def _src_text(src, cfg):
    """متن منبع (اینترنتی: نسخه‌ی ذخیره‌شده با اثر انگشت؛ فایل: هر بار خوانده می‌شود؛ آپلود: رمزشده). خروجی: (متن، توضیح، داخلی؟)"""
    sid = src["id"]
    if src["kind"] == "url":
        f, meta = _src_file(sid), src_meta(sid)
        if not f.exists() or meta.get("url") != src["url"]:
            raise IntelError(f"{src['name']}: نسخه‌ای ذخیره نشده است.")
        raw = f.read_bytes()
        if hashlib.sha256(raw).hexdigest() != meta.get("sha256"):
            raise IntelError(f"{src['name']}: فایل ذخیره‌شده با اثر انگشت ثبت‌شده جور نیست؛ دوباره دانلود کنید.")
        return raw.decode("utf-8-sig", "replace"), "", False
    if src["kind"] == "path":
        if paths.is_server():
            raise IntelError(f"{src['name']}: در حالت سرور «فایل روی کامپیوتر» خوانده نمی‌شود.")
        p = Path(src["path"])
        if not p.is_file():
            raise IntelError(f"{src['name']}: فایل پیدا نشد: {src['path']}")
        if p.stat().st_size > MAX_LOCAL_BYTES:
            raise IntelError(f"{src['name']}: حجم فایل بیش از حد است.")
        mt = time.strftime("%Y-%m-%d %H:%M", time.localtime(p.stat().st_mtime))
        return _decode(atrest.read_bytes(p)), f"فایل {p.name} (تغییر {mt})", True
    f = _src_upload(sid)
    if not f.exists() and sid == "local" and (_dir() / "local.dat").exists():
        f = _dir() / "local.dat"            # لیست داخلیِ آپلودشده در نسخه‌های پیش از 1.59
    if not f.exists():
        raise IntelError(f"{src['name']}: فایلی آپلود نشده است (تنظیمات ← بررسی تکمیلی ← منابع).")
    return atrest.read_bytes(f).decode("utf-8", "replace"), "فایل آپلودشده", True


def source_lookup(src, cfg, targets):
    """{ip: توضیح} برای IPهایی که در این منبع‌اند + توضیح منبع."""
    text, desc, private_ok = _src_text(src, cfg)
    ips, nets = parse_source(src, text, private_ok)
    if src["kind"] != "url" and not ips and not nets:
        raise IntelError(f"{src['name']}: هیچ IP یا رنج معتبری در فایل نیست.")
    out = {}
    for ip in targets:
        if ip in ips:
            out[ip] = ips[ip]
            continue
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            continue
        for n, why in nets:
            if n.version == a.version and a in n:
                out[ip] = f"رنج {n}" + (f"، {why}" if why else "")
                break
    return out, desc or f"{len(ips):,}\u200f IP و {len(nets):,} رنج"


def save_upload(sid, src_path):
    p = Path(src_path)
    if not p.is_file():
        raise IntelError("فایل پیدا نشد.")
    if p.stat().st_size > MAX_LOCAL_BYTES + 1024:
        raise IntelError(f"حجم فایل بیشتر از {MAX_LOCAL_BYTES // (1024 * 1024)}MB است.")
    text = _decode(atrest.read_bytes(p))
    atrest.write_bytes(_src_upload(sid), text.encode("utf-8"))
    meta = {"name": p.name, "uploaded": time.time(), "size": len(text)}
    _write_json(f"src_{sid}_meta.dat", meta)
    return meta


def test_source(src, cfg, cancel=None):
    """«آزمایش» در فرم: دانلود/خواندن بدون ذخیره؛ تعداد و ۵ نمونه."""
    if src["kind"] == "url":
        data, _ = _fetch_url(src, cfg, False, {}, cancel)
        text, private_ok = data.decode("utf-8-sig", "replace"), False
    else:
        text, _d, private_ok = _src_text(src, cfg)
    ips, nets = parse_source(src, text, private_ok)
    sample = [f"{ip}" + (f" — {why}" if why else "") for ip, why in list(ips.items())[:5]] + [str(n) for n, _ in nets[:max(0, 5 - len(ips))]]
    return {"ips": len(ips), "nets": len(nets), "sample": sample, "columns": _csv_cols(text)[:30] if src["fmt"] == "csv" else [],
            "ok": len(ips) + len(nets) >= int(src.get("min_entries") or 1)}
