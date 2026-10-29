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
