"""SQLite محلی: وضعیت، کلیدهای پردازش‌شده (idempotency)، IPها، اجراها و تاریخچه. با migration خودکار."""
import contextlib
import re
import json
import logging
import os
import sqlite3
import sys
import threading
import time
from datetime import datetime

from . import atrest, dbmysql, paths

log = logging.getLogger(__name__)

_COL = re.compile(r"^[a-z_][a-z0-9_]*$")

_IP_FIELDS_V2 = [   # ستون‌های جدول ips در مهاجرت _m2 (ثابت؛ ستون‌های بعدی با مهاجرت‌های بعدی اضافه می‌شوند)
    "ip", "source", "first_seen", "last_seen", "attack_count", "signatures", "dest_ports",
    "abuse_status", "score", "reports", "country_code", "country", "city", "isp", "usage_type",
    "domain", "asn", "categories", "is_tor", "is_whitelisted", "last_reported", "checked_at",
    "error", "fw_status", "fw_detail", "fw_at", "review", "last_run",
]
# ابزار «بررسی تکمیلی» (1.11): نتیجه‌ی فید/لیست داخلی جدا از AbuseIPDB
INTEL_FIELDS = ["intel_status", "intel_source", "intel_detail", "intel_at"]
IP_FIELDS = _IP_FIELDS_V2 + INTEL_FIELDS


def _m1(c):
    for sql in [
        "CREATE TABLE IF NOT EXISTS processed(key TEXT PRIMARY KEY, ts REAL, info TEXT)",
        "CREATE TABLE IF NOT EXISTS runs(id TEXT PRIMARY KEY, started REAL, finished REAL, trigger TEXT,"
        " steps TEXT, status TEXT, summary TEXT, dir TEXT)",
        "CREATE TABLE IF NOT EXISTS history(id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, run_id TEXT,"
        " kind TEXT, target TEXT, status TEXT, detail TEXT, file TEXT)",
        "CREATE INDEX IF NOT EXISTS ix_hist_ts ON history(ts)",
    ]:
        c.execute(sql)


def _m2(c):
    cols = ", ".join(f"{f} TEXT" if f not in ("attack_count", "score", "reports") else f"{f} INTEGER"
                     for f in _IP_FIELDS_V2 if f != "ip")
    c.execute(f"CREATE TABLE IF NOT EXISTS ips(ip TEXT PRIMARY KEY, {cols})")


def _parse_ts(v):
    try:
        return time.mktime(time.strptime(str(v)[:19], "%Y-%m-%d %H:%M:%S"))
    except (TypeError, ValueError):
        return None


def _m3(c):
    """رویدادهای آماری + عکس روزانه. از داده‌ی موجود (IPها و تاریخچه) پر می‌شود تا آمار گذشته هم دیده شود."""
    c.execute("CREATE TABLE IF NOT EXISTS stat_events(ts REAL, kind TEXT, sub TEXT, ip TEXT, cc TEXT, isp TEXT,"
              " src TEXT, UNIQUE(kind, ip, ts))")
    c.execute("CREATE INDEX IF NOT EXISTS ix_stat_ts ON stat_events(ts)")
    c.execute("CREATE TABLE IF NOT EXISTS daily_snapshot(day TEXT PRIMARY KEY, fw_pending INTEGER,"
              " review_pending INTEGER, total_ips INTEGER)")
    for r in c.execute("SELECT ip, abuse_status, checked_at, country_code, isp FROM ips").fetchall():
        ts = _parse_ts(r[2])
        if ts and r[1]:
            c.execute("INSERT OR IGNORE INTO stat_events VALUES(?,?,?,?,?,?,?)",
                      (ts, "abuse", r[1], r[0], r[3] or "", r[4] or "", "backfill"))
    for r in c.execute("SELECT ts, kind, status, target FROM history WHERE kind IN ('ban','ticket')").fetchall():
        sub = {"ok": "ok", "error": "failed", "test": "test"}.get(r[2], r[2])
        c.execute("INSERT OR IGNORE INTO stat_events VALUES(?,?,?,?,?,?,?)", (r[0], r[1], sub, r[3], "", "", "backfill"))


def _m4(c):
    """ابزار SSH: دستگاه‌ها، اسکریپت‌ها، اجراها و نتیجه‌ی هر دستگاه. یوزر/پسورد در vault است، نه اینجا."""
    c.execute("CREATE TABLE IF NOT EXISTS ssh_devices(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, host TEXT,"
              " port INTEGER, device_type TEXT, username TEXT, grp TEXT, use_enable INTEGER, notes TEXT,"
              " created REAL, last_status TEXT, last_at REAL, last_message TEXT)")
    c.execute("CREATE TABLE IF NOT EXISTS ssh_scripts(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, device_type TEXT,"
              " mode TEXT, body TEXT, use_sudo INTEGER, save_config INTEGER, updated REAL)")
    c.execute("CREATE TABLE IF NOT EXISTS ssh_jobs(id TEXT PRIMARY KEY, started REAL, finished REAL, script_name TEXT,"
              " status TEXT, total INTEGER, ok INTEGER, failed INTEGER, dry INTEGER, kind TEXT)")
    c.execute("CREATE TABLE IF NOT EXISTS ssh_results(job_id TEXT, device_id INTEGER, name TEXT, host TEXT, status TEXT,"
              " started REAL, finished REAL, message TEXT, out_file TEXT, PRIMARY KEY(job_id, device_id))")


def _m5(c):
    """پشتیبان کانفیگ: پرچم هر دستگاه، وضعیت آخرین پشتیبان، و نسخه‌های ذخیره‌شده (فایل‌ها رمزشده‌اند)."""
    for col, typ in (("backup", "INTEGER"), ("backup_status", "TEXT"), ("backup_at", "REAL"), ("backup_message", "TEXT")):
        c.execute(f"ALTER TABLE ssh_devices ADD COLUMN {col} {typ}")
    c.execute("CREATE TABLE IF NOT EXISTS config_backups(id INTEGER PRIMARY KEY AUTOINCREMENT, device_id INTEGER, ts REAL,"
              " hash TEXT, size INTEGER, lines INTEGER, added INTEGER, removed INTEGER, first INTEGER, file TEXT, job_id TEXT)")
    c.execute("CREATE INDEX IF NOT EXISTS ix_cb_dev ON config_backups(device_id, ts)")


def _m6(c):
    """کاربر انجام‌دهنده‌ی هر رویداد تاریخچه."""
    c.execute("ALTER TABLE history ADD COLUMN user TEXT")


def _m7(c):
    """سازگاری با دستگاه قدیمی (الگوریتم‌های SHA1 در SSH) برای هر دستگاه؛ پیش‌فرض خاموش."""
    c.execute("ALTER TABLE ssh_devices ADD COLUMN legacy INTEGER DEFAULT 0")


def _m8(c):
    """دستگاه‌های شخصی: owner خالی = مشترک (ادمین)؛ وگرنه نام کاربری صاحب (فقط خودش می‌بیند)."""
    c.execute("ALTER TABLE ssh_devices ADD COLUMN owner TEXT DEFAULT ''")


def _m9(c):
    """مانیتورینگ: هدف‌ها و رخدادهای قطعی. نتیجه‌ی تک‌تک بررسی‌ها در فایل‌های رمزشده‌ی monitor/ است، نه اینجا."""
    c.execute("CREATE TABLE IF NOT EXISTS mon_targets(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, host TEXT, kind TEXT,"
              " port INTEGER, url TEXT, interval INTEGER, threshold INTEGER, timeout REAL, slow_ms INTEGER, icon TEXT,"
              " grp TEXT, owner TEXT DEFAULT '', enabled INTEGER DEFAULT 1, notify INTEGER DEFAULT 1, notes TEXT, created REAL)")
    c.execute("CREATE TABLE IF NOT EXISTS mon_events(id INTEGER PRIMARY KEY AUTOINCREMENT, target_id INTEGER, name TEXT,"
              " start REAL, end REAL, reason TEXT)")
    c.execute("CREATE INDEX IF NOT EXISTS ix_mon_ev ON mon_events(target_id, start)")


def _m10(c):
    """1.11: ستون‌های «بررسی تکمیلی» در ips، هشدارهای تکرار IP و نمایه‌ی شمارش روزهای بررسی هر IP."""
    have = {r[1] for r in c.execute("PRAGMA table_info(ips)")}
    for col in INTEL_FIELDS:
        if col not in have:
            c.execute(f"ALTER TABLE ips ADD COLUMN {col} TEXT")
    c.execute("CREATE TABLE IF NOT EXISTS repeat_alerts(ip TEXT PRIMARY KEY, days INTEGER, ts REAL)")
    c.execute("CREATE INDEX IF NOT EXISTS ix_stat_ip ON stat_events(ip, kind)")


def _m11(c):
    """1.19: پروفایل اعتبارنامه (یوزر/پسورد مشترک چند دستگاه؛ اسرار در vault با کلید cred.<id>.*)."""
    c.execute("CREATE TABLE IF NOT EXISTS cred_profiles(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, kind TEXT,"
              " owner TEXT DEFAULT '', notes TEXT, created REAL)")
    have = {r[1] for r in c.execute("PRAGMA table_info(ssh_devices)")}
    if "cred_id" not in have:
        c.execute("ALTER TABLE ssh_devices ADD COLUMN cred_id INTEGER")


def _m12(c):
    """1.20: هدف مانیتورینگ SNMP: تنظیمات (JSON) و پروفایل اعتبارنامه‌ی SNMP (اسرار در vault با کلید cred.<id>.*)."""
    have = {r[1] for r in c.execute("PRAGMA table_info(mon_targets)")}
    for col, typ in (("snmp", "TEXT"), ("cred_id", "INTEGER")):
        if col not in have:
            c.execute(f"ALTER TABLE mon_targets ADD COLUMN {col} {typ}")


def _m13(c):
    """1.21: مدیریت دارایی. شناسه‌ی هر دارایی سریال است؛ تغییرها اول در asset_changes (در انتظار تأیید ادمین)."""
    c.execute("CREATE TABLE IF NOT EXISTS assets(id INTEGER PRIMARY KEY AUTOINCREMENT, serial TEXT UNIQUE, vendor TEXT, model TEXT,"
              " hostname TEXT, ip TEXT, sw TEXT, mac TEXT, descr TEXT, location TEXT, location_dev TEXT, loc_from_dev INTEGER DEFAULT 0,"
              " label TEXT, asset_tag TEXT, notes TEXT, status TEXT DEFAULT 'active', source TEXT, serial_kind TEXT,"
              " first_seen REAL, last_seen REAL, created REAL)")
    c.execute("CREATE TABLE IF NOT EXISTS asset_parts(id INTEGER PRIMARY KEY AUTOINCREMENT, asset_id INTEGER, serial TEXT, cls TEXT,"
              " name TEXT, descr TEXT, model TEXT, hw TEXT, src TEXT, first_seen REAL, last_seen REAL)")
    c.execute("CREATE INDEX IF NOT EXISTS ix_apart_a ON asset_parts(asset_id)")
    c.execute("CREATE INDEX IF NOT EXISTS ix_apart_s ON asset_parts(serial)")
    c.execute("CREATE TABLE IF NOT EXISTS asset_changes(id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, asset_id INTEGER, serial TEXT,"
              " kind TEXT, data TEXT, source TEXT, status TEXT, by_user TEXT, decided REAL, decided_by TEXT, note TEXT)")
    c.execute("CREATE INDEX IF NOT EXISTS ix_achg ON asset_changes(status, serial)")
    c.execute("CREATE TABLE IF NOT EXISTS asset_history(id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, asset_id INTEGER, serial TEXT,"
              " field TEXT, old TEXT, new TEXT, user TEXT, source TEXT, change_id INTEGER)")
    c.execute("CREATE INDEX IF NOT EXISTS ix_ahist ON asset_history(asset_id, ts)")


# ---------------------------------------------------------------- خلاصه‌های آماری (1.22، روش trends در Zabbix)
# هم‌زمان با ثبت هر رویداد به‌روز می‌شوند؛ صفحه‌ی آمار و «روزهای تکرار» فقط این‌ها را می‌خوانند، نه رویدادهای خام.
SEEN_SRC = ("online", "cache", "backfill")


def _local_day(ts, memo={}):     # noqa: B006 — کش عمدی: ربع‌ساعت ← تاریخ محلی (با هر منطقه‌ی زمانی و DST درست)
    q = int(ts // 900)
    d = memo.get(q)
    if d is None:
        if len(memo) > 300_000:
            memo.clear()
        from datetime import datetime as _dt
        d = memo[q] = _dt.fromtimestamp(q * 900).strftime("%Y-%m-%d")
    return d


def _roll(c, rows):
    """rows: رویدادهای تازه‌ی ثبت‌شده [(ts, kind, sub, ip, cc, isp, src)] ← جدول‌های خلاصه."""
    from collections import Counter
    day_n, geo_n, ipd = Counter(), Counter(), {}
    for ts, kind, sub, ip, cc, isp, src in rows:
        d = _local_day(ts)
        day_n[(d, kind or "", sub or "", src or "")] += 1
        if kind != "abuse":
            continue
        if sub == "ABUSE":
            if cc and cc != "-":
                geo_n[(d, "cc", cc)] += 1
            if isp and isp not in ("-", "ERROR"):
                geo_n[(d, "isp", isp)] += 1
        seen = src in SEEN_SRC
        o = ipd.get((d, ip))
        if o is None:
            ipd[(d, ip)] = [sub or "", ts, 1 if sub == "ABUSE" else 0, 1 if seen else 0, ts if seen else None, ts if seen else None]
        else:
            if ts >= o[1]:
                o[0], o[1] = sub or "", ts
            if sub == "ABUSE":
                o[2] = 1
            if seen:
                o[3] = 1
                o[4] = ts if o[4] is None else min(o[4], ts)
                o[5] = ts if o[5] is None else max(o[5], ts)
    if day_n:
        c.executemany("INSERT INTO stat_day VALUES(?,?,?,?,?) ON CONFLICT(day, kind, sub, src) DO UPDATE SET n = n + excluded.n",
                      [(*k, n) for k, n in day_n.items()])
    if geo_n:
        c.executemany("INSERT INTO stat_geo_day VALUES(?,?,?,?) ON CONFLICT(day, kind, name) DO UPDATE SET n = n + excluded.n",
                      [(*k, n) for k, n in geo_n.items()])
    if ipd:
        c.executemany(
            "INSERT INTO stat_ip_day VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(day, ip) DO UPDATE SET "
            "last_sub = CASE WHEN excluded.last_ts >= last_ts THEN excluded.last_sub ELSE last_sub END, "
            "last_ts = MAX(last_ts, excluded.last_ts), abuse = MAX(abuse, excluded.abuse), seen = MAX(seen, excluded.seen), "
            "seen_first = CASE WHEN excluded.seen_first IS NULL THEN seen_first WHEN seen_first IS NULL THEN excluded.seen_first "
            "ELSE MIN(seen_first, excluded.seen_first) END, "
            "seen_last = CASE WHEN excluded.seen_last IS NULL THEN seen_last WHEN seen_last IS NULL THEN excluded.seen_last "
            "ELSE MAX(seen_last, excluded.seen_last) END",
            [(d, ip, *v) for (d, ip), v in ipd.items()])


def _m14(c):
    """1.22: جدول‌های خلاصه‌ی آماری و پر کردن آن‌ها از همه‌ی رویدادهای فعلی."""
    c.execute("CREATE TABLE IF NOT EXISTS stat_day(day TEXT, kind TEXT, sub TEXT, src TEXT, n INTEGER, PRIMARY KEY(day, kind, sub, src))")
    c.execute("CREATE TABLE IF NOT EXISTS stat_ip_day(day TEXT, ip TEXT, last_sub TEXT, last_ts REAL, abuse INTEGER, seen INTEGER,"
              " seen_first REAL, seen_last REAL, PRIMARY KEY(day, ip))")
    c.execute("CREATE INDEX IF NOT EXISTS ix_sid_ip ON stat_ip_day(ip)")
    c.execute("CREATE TABLE IF NOT EXISTS stat_geo_day(day TEXT, kind TEXT, name TEXT, n INTEGER, PRIMARY KEY(day, kind, name))")
    cur = c.execute("SELECT ts, kind, sub, ip, cc, isp, src FROM stat_events ORDER BY ts, rowid")
    while True:
        rows = cur.fetchmany(20000)
        if not rows:
            break
        _roll(c, [tuple(r) for r in rows])


def _m15(c):
    """1.24: وابستگی هدف‌ها (parent_id)، نوع رخداد قطعی (down / unreach = به‌خاطر پدر / maint = در پنجره‌ی نگهداری)
    و پنجره‌های نگهداری."""
    have = {r[1] for r in c.execute("PRAGMA table_info(mon_targets)")}
    if "parent_id" not in have:
        c.execute("ALTER TABLE mon_targets ADD COLUMN parent_id INTEGER")
    have = {r[1] for r in c.execute("PRAGMA table_info(mon_events)")}
    if "kind" not in have:
        c.execute("ALTER TABLE mon_events ADD COLUMN kind TEXT DEFAULT 'down'")
    c.execute("CREATE TABLE IF NOT EXISTS mon_maint(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, scope TEXT, kind TEXT,"
              " start REAL, end REAL, days TEXT, t_from TEXT, t_to TEXT, enabled INTEGER DEFAULT 1, owner TEXT DEFAULT '',"
              " note TEXT, created REAL)")


def _m16(c):
    """1.31: پروتکل اتصال دستگاه (ssh یا telnet)؛ هشدار انقضای گواهی HTTPS در مانیتورینگ (روز؛ ۰ = خاموش)."""
    have = {r[1] for r in c.execute("PRAGMA table_info(ssh_devices)")}
    if "protocol" not in have:
        c.execute("ALTER TABLE ssh_devices ADD COLUMN protocol TEXT DEFAULT 'ssh'")
    have = {r[1] for r in c.execute("PRAGMA table_info(mon_targets)")}
    if "cert_days" not in have:
        c.execute("ALTER TABLE mon_targets ADD COLUMN cert_days INTEGER DEFAULT 0")


def _m17(c):
    """1.34: «سیاست پایش» (بازه، دقت داده، نگهداری، چه داده‌ای) و سیاست هر هدف (NULL = سفارشی، مثل قبل)."""
    c.execute("CREATE TABLE IF NOT EXISTS mon_policies(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, data TEXT, created REAL)")
    have = {r[1] for r in c.execute("PRAGMA table_info(mon_targets)")}
    if "policy_id" not in have:
        c.execute("ALTER TABLE mon_targets ADD COLUMN policy_id INTEGER")
    if not c.execute("SELECT COUNT(*) FROM mon_policies").fetchone()[0]:
        from .monitor import POLICY_PRESETS
        for name, data in POLICY_PRESETS:
            c.execute("INSERT INTO mon_policies(name, data, created) VALUES(?, ?, ?)",
                      (name, json.dumps(data, ensure_ascii=False), time.time()))


def _m18(c):
    """1.35: قالب‌های نمایش و داشبوردهای NOC (mon_layouts) و قالب هر هدف (tpl: خالی = خودکار از آیکن)."""
    c.execute("CREATE TABLE IF NOT EXISTS mon_layouts(id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT, name TEXT, data TEXT,"
              " owner TEXT DEFAULT '', created REAL)")
    have = {r[1] for r in c.execute("PRAGMA table_info(mon_targets)")}
    if "tpl" not in have:
        c.execute("ALTER TABLE mon_targets ADD COLUMN tpl TEXT DEFAULT ''")


def _m19(c):
    """1.37: متن گزارش اجرا در پایگاه داده (فشرده)؛ پوشه‌ی اجرا (CSV و run.log) بعد از پایان کار پاک می‌شود."""
    have = {r[1] for r in c.execute("PRAGMA table_info(runs)")}
    if "log" not in have:
        c.execute("ALTER TABLE runs ADD COLUMN log TEXT")
    c.execute("CREATE INDEX IF NOT EXISTS ix_hist_ts ON history(ts)")


def _m20(c):
    """1.40: ابزار API — اتصال‌ها (آدرس پایه و نوع احراز؛ رمز و توکن در vault)، درخواست‌های ذخیره‌شده، لاگ درخواست‌ها."""
    c.execute("CREATE TABLE IF NOT EXISTS api_conns(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, base_url TEXT, auth TEXT DEFAULT 'none',"
              " key_name TEXT DEFAULT '', verify INTEGER DEFAULT 1, timeout INTEGER DEFAULT 30, headers TEXT DEFAULT '{}', owner TEXT DEFAULT '',"
              " notes TEXT DEFAULT '', created REAL, updated REAL)")
    c.execute("CREATE TABLE IF NOT EXISTS api_requests(id INTEGER PRIMARY KEY AUTOINCREMENT, conn_id INTEGER, name TEXT, method TEXT, path TEXT,"
              " params TEXT DEFAULT '[]', headers TEXT DEFAULT '[]', body TEXT DEFAULT '', body_type TEXT DEFAULT 'json', created REAL, updated REAL)")
    c.execute("CREATE TABLE IF NOT EXISTS api_log(id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, user TEXT, conn_id INTEGER, conn_name TEXT, method TEXT,"
              " url TEXT, req_headers TEXT, req_body TEXT, status INTEGER, ms INTEGER, size INTEGER, resp_head TEXT, error TEXT)")
    c.execute("CREATE INDEX IF NOT EXISTS ix_api_log_ts ON api_log(ts)")


MIGRATIONS = [_m1, _m2, _m3, _m4, _m5, _m6, _m7, _m8, _m9, _m10, _m11, _m12, _m13, _m14, _m15, _m16, _m17, _m18, _m19, _m20]
# ستون‌هایی که مهاجرت‌ها اضافه می‌کنند؛ هر بار باز شدن بررسی می‌شود و اگر نباشد اضافه می‌شود
# (پایگاه داده‌ای که شماره‌ی نسخه‌اش جلوتر از ستون‌هایش است، مثلاً بازگردانی فایل قدیمی، دیگر خطا نمی‌دهد)
REQUIRED_COLUMNS = {
    "ssh_devices": {"backup": "INTEGER", "backup_status": "TEXT", "backup_at": "REAL", "backup_message": "TEXT",
                    "legacy": "INTEGER DEFAULT 0", "owner": "TEXT DEFAULT ''", "cred_id": "INTEGER",
                    "protocol": "TEXT DEFAULT 'ssh'"},
    "history": {"user": "TEXT"},
    "runs": {"log": "TEXT"},
    "ips": {c: "TEXT" for c in INTEL_FIELDS},
    "mon_targets": {"snmp": "TEXT", "cred_id": "INTEGER", "parent_id": "INTEGER", "cert_days": "INTEGER DEFAULT 0",
                    "policy_id": "INTEGER", "tpl": "TEXT DEFAULT ''"},
    "mon_events": {"kind": "TEXT DEFAULT 'down'"},
}
ACTOR = threading.local()   # نام کاربر جاری هر رشته (API یا اجرای ابزار)؛ برای ستون user تاریخچه


def _cipher_mod():
    """sqlcipher3 (SQLite با رمز صفحه‌به‌صفحه‌ی SQLCipher 4). None اگر نصب نیست."""
    try:
        import sqlcipher3
        return sqlcipher3
    except Exception:  # noqa — نبود کتابخانه‌ی بومی: برگشت به روش قبلی
        return None


def _db_key():
    """کلید پایگاه داده از کلید داده (جدا از کلید فایل‌ها با HMAC؛ فقط هگز، بدون ورودی کاربر در PRAGMA)."""
    import hashlib
    import hmac
    return hmac.new(atrest.key(), b"autokrp-sqlcipher-v1", hashlib.sha256).hexdigest()


def _plain_tables(src):
    return [(n, t, q) for n, t, q in src.execute(
        "SELECT name, type, sql FROM sqlite_master WHERE sql IS NOT NULL AND name NOT LIKE 'sqlite_%' "
        "ORDER BY CASE type WHEN 'table' THEN 0 WHEN 'index' THEN 1 WHEN 'view' THEN 2 ELSE 3 END, rowid").fetchall()]


def copy_db(src, dst):
    """همه‌ی جدول‌ها، نمایه‌ها و ردیف‌ها (با همان rowid) از یک اتصال SQLite به اتصال دیگر (حتی از sqlite3 به sqlcipher3).
    خروجی: {جدول: تعداد ردیف} برای مقایسه."""
    counts = {}
    items = _plain_tables(src)
    dst.execute("BEGIN")
    try:
        for name, typ, sql in items:
            if typ != "table":
                continue
            if not _COL.match(name.lower()) and not name.startswith("_akrp_"):
                raise RuntimeError(f"نام جدول نامعتبر: {name}")
            dst.execute(sql)
            info = src.execute(f'PRAGMA table_info("{name}")').fetchall()          # nosec B608 — نام از sqlite_master، بررسی‌شده
            cols = [r[1] for r in info]
            pk = [r for r in info if r[5]]
            alias = len(pk) == 1 and str(pk[0][2]).upper() == "INTEGER"         # ستون INTEGER PRIMARY KEY همان rowid است
            names = cols if alias else ["rowid"] + cols
            sel = ", ".join(f'"{c}"' for c in names)
            ins = f'INSERT INTO "{name}"({sel}) VALUES({", ".join("?" * len(names))})'  # nosec B608 — نام‌ها از sqlite_master
            cur = src.execute(f'SELECT {sel} FROM "{name}"')                                 # nosec B608
            n = 0
            while True:
                rows = cur.fetchmany(5000)
                if not rows:
                    break
                dst.executemany(ins, [tuple(r) for r in rows])
                n += len(rows)
            counts[name] = n
        for name, typ, sql in items:
            if typ != "table":
                dst.execute(sql)
        if src.execute("SELECT 1 FROM sqlite_master WHERE name='sqlite_sequence'").fetchone():
            for name, seq in src.execute("SELECT name, seq FROM sqlite_sequence").fetchall():
                dst.execute("UPDATE sqlite_sequence SET seq=? WHERE name=?", (seq, name))
        dst.execute("COMMIT")
    except BaseException:
        dst.execute("ROLLBACK")
        raise
    return counts


class Store:
    """
    1.22: پایگاه داده‌ی محلی یک فایل SQLCipher است (state.sdb): هر صفحه‌ی ۴ کیلوبایتی با AES-256 رمز و با HMAC-SHA512
    امضا می‌شود، فقط صفحه‌های تغییرکرده نوشته می‌شوند (WAL)، فایل‌های موقت فقط در حافظه. کلید از کلید داده (atrest).
    حالت MySQL: پایگاه داده‌ی موقت در حافظه (sqlite3) و ذخیره در MySQL مثل قبل.
    برگشت (بدون sqlcipher3): روش قبلی، کل پایگاه داده در حافظه و ذخیره‌ی رمزشده‌ی کامل در state.dat.
    """
    FLUSH_SECS = 5
    _seen_cache = None
    _stat_ver = 0
    FLUSH_SECS_MAX = 30       # سقف فاصله‌ی ذخیره‌ی خودکار برای پایگاه داده‌ی بزرگ (بیشترین داده‌ی ازدست‌رفته در قطع برق)
    last_flush_secs = 0.0
    FLUSH_SECS_BLOB = 30      # MySQL حالت blob: کل تصویر رمزشده هر بار نوشته می‌شود

    def __init__(self, path=None, use_conf=True):
        if sys.version_info < (3, 11):
            raise RuntimeError("AutoKRP به Python 3.11 یا بالاتر نیاز دارد.")
        self.path = path or (paths.data_dir() / "state.db")
        self.enc_path = self.path.with_name(self.path.stem + ".dat")
        self.sdb_path = self.path.with_name(self.path.stem + ".sdb")
        self.engine = "memory"
        self._lock = threading.RLock()
        # یک ذخیره در هر لحظه (رمز و نوشتن بیرون از self._lock). ترتیب قفل‌ها همیشه: _flush_lock ← _lock
        self._flush_lock = threading.RLock()
        self._closed = False
        self.backend = None
        self.db = self._new_db()
        legacy = False
        conf = dbmysql.load_conf() if use_conf else None
        if conf:
            self.backend = dbmysql.MySQLBackend(conf)
            self.backend.open()
            try:
                ver = self._load_backend(self.db, self.backend)
                self._migrate()
                self._backend_prepare(ver)
            except Exception:
                self.backend.close()
                raise
        else:
            cm = _cipher_mod()
            if cm is None and self.sdb_path.exists():
                raise RuntimeError("پایگاه داده با SQLCipher رمز شده ولی کتابخانه‌ی sqlcipher3 در این نصب نیست.")
            if cm is not None and self.sdb_path.exists():
                self.db.close()
                self.db = self._open_cipher(self.sdb_path)
                self.engine = "cipher"
                self._drop_old_copy()
            else:
                if self.enc_path.exists():
                    self.db.deserialize(atrest.read_bytes(self.enc_path, mutable=True))
                elif self.path.exists():
                    legacy = True
                    src = sqlite3.connect(str(self.path))
                    try:
                        src.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                        src.execute("PRAGMA journal_mode=DELETE")   # تصویر WAL در حافظه باز نمی‌شود
                        data = src.serialize()
                    finally:
                        src.close()
                    self.db.deserialize(data)
                if cm is not None:
                    self._migrate()             # ساختار به‌روز پیش از انتقال
                    self._to_cipher()
                else:
                    log.warning("sqlcipher3 نصب نیست؛ پایگاه داده به روش قبلی (کل فایل رمزشده در state.dat) ذخیره می‌شود")
            self._migrate()
        self._saved = -1
        self.flush()
        if legacy:
            from . import wipe
            for suf in ("", "-wal", "-shm"):
                f = self.path.with_name(self.path.name + suf)
                if f.exists():
                    wipe.overwrite(f)
                    f.unlink()
        self._stop = threading.Event()
        self._t = threading.Thread(target=self._flusher, name="store-flush", daemon=True)
        self._t.start()

    # ------------------------------------------------------------ SQLCipher
    def _open_cipher(self, path):
        cm = _cipher_mod()
        db = cm.connect(str(path), check_same_thread=False, isolation_level=None)
        db.row_factory = cm.Row
        try:
            db.execute("PRAGMA cipher_log_level = NONE")     # کلید نادرست را خودمان با پیام فارسی گزارش می‌کنیم
        except cm.DatabaseError:
            pass
        key = _db_key()
        if not re.fullmatch(r"[0-9a-f]{64}", key):
            raise RuntimeError("کلید پایگاه داده نامعتبر است.")
        db.execute(f"PRAGMA key = \"x'{key}'\"")
        db.execute("PRAGMA temp_store = MEMORY")         # هیچ فایل موقتِ رمزنشده‌ای روی دیسک
        try:
            db.execute("SELECT count(*) FROM sqlite_master").fetchone()
        except cm.DatabaseError:
            db.close()
            raise atrest.AtRestError("پایگاه داده باز نشد: با کلید این کاربر/سرور رمز نشده یا فایل خراب است.")
        db.execute("PRAGMA journal_mode = WAL")
        db.execute("PRAGMA synchronous = NORMAL")       # WAL: بعد از قطع برق پایگاه داده سالم است؛ حداکثر آخرین تراکنش‌ها
        db.execute("PRAGMA cache_size = -65536")        # تا ۶۴ مگ صفحه‌ی رمزگشایی‌شده در حافظه
        return db

    def _sdb_files(self, base=None):
        base = base or self.sdb_path
        return [base.with_name(base.name + suf) for suf in ("", "-wal", "-shm", "-journal")]

    def _wipe_files(self, files):
        from . import wipe
        for f in files:
            if f.exists():
                wipe.overwrite(f)
                f.unlink()

    def _to_cipher(self):
        """انتقال یک‌باره‌ی پایگاه داده‌ی حافظه (از state.dat یا MySQL) به فایل SQLCipher. نسخه‌ی قبلی state.dat
        با نام state.dat.pre122 می‌ماند تا اجرای بعدی که فایل تازه سالم باز شد."""
        tmp = self.sdb_path.with_name(self.sdb_path.name + ".new")
        self._wipe_files(self._sdb_files(tmp))
        t0 = time.monotonic()
        dst = self._open_cipher(tmp)
        try:
            dst.execute("PRAGMA journal_mode = DELETE")
            want = copy_db(self.db, dst)
            got = {t: dst.execute(f'SELECT COUNT(*) FROM "{t}"').fetchone()[0] for t in want}  # nosec B608 — نام از sqlite_master
            if got != want:
                raise RuntimeError(f"انتقال پایگاه داده ناقص بود: {want} ≠ {got}")
        except BaseException:
            dst.close()
            self._wipe_files(self._sdb_files(tmp))
            raise
        dst.close()
        os.replace(tmp, self.sdb_path)
        mem, self.db = self.db, self._open_cipher(self.sdb_path)
        mem.close()
        self.engine = "cipher"
        if self.enc_path.exists():
            os.replace(self.enc_path, self.enc_path.with_name(self.enc_path.name + ".pre122"))
        log.warning("پایگاه داده به SQLCipher منتقل شد (%d جدول، %.1f ثانیه)", len(want), time.monotonic() - t0)

    def _drop_old_copy(self):
        """فایل SQLCipher سالم باز شد: نسخه‌ی قبلی (state.dat.pre122) و state.dat جامانده (قطع برق بین انتقال و
        تغییر نام) دیگر لازم نیستند؛ بازنویسی و حذف می‌شوند."""
        self._wipe_files([self.enc_path.with_name(self.enc_path.name + ".pre122"), self.enc_path,
                          *self._sdb_files(self.sdb_path.with_name(self.sdb_path.name + ".new"))])

    @staticmethod
    def _new_db():
        db = sqlite3.connect(":memory:", check_same_thread=False, isolation_level=None)
        db.row_factory = sqlite3.Row
        return db

    # ------------------------------------------------------------ MySQL
    @staticmethod
    def _load_backend(db, be):
        """داده‌ی MySQL در db (خالی) بارگذاری می‌شود. خروجی: نسخه‌ی ساختار پیش از مهاجرت (None = پایگاه داده‌ی تازه)."""
        if be.mode == "blob":
            img = be.load_blob()
            if img is None:
                return None
            db.deserialize(img)
            row = db.execute("SELECT value FROM meta WHERE key='schema'").fetchone()
            return int(row[0]) if row else 0
        ver = be.schema_version()
        if ver is None:
            return None
        db.execute("CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT)")
        for m in MIGRATIONS[:ver]:          # همان ساختاری که داده‌ها با آن ذخیره شده‌اند؛ بقیه‌ی مهاجرت‌ها بعد از بارگذاری
            m(db)
        be.load_tables(db)
        return ver

    def _schema(self):
        row = self.db.execute("SELECT value FROM meta WHERE key='schema'").fetchone()
        return int(row[0]) if row else 0

    def _backend_prepare(self, ver_before):
        """پس از مهاجرت: ساختار MySQL هم‌سان می‌شود و در صورت نیاز همه‌ی داده دوباره نوشته می‌شود."""
        be = self.backend
        be.write_meta_base()
        if be.mode == "blob":
            return
        changed = be.sync_schema(self.db)
        be.install_triggers(self.db)
        if ver_before is None or ver_before != self._schema() or changed:
            be.push_all(self.db)          # پایگاه داده‌ی تازه یا ساختار تازه (مهاجرت‌های داده‌ای هم منتقل شوند)
        self.db.execute(f"DELETE FROM {dbmysql.CHG}")  # nosec B608 — نام ثابت

    def _drop_triggers(self):
        for (name,) in self.db.execute("SELECT name FROM sqlite_master WHERE type='trigger' AND name LIKE '_akrp_%'").fetchall():
            self.db.execute(f'DROP TRIGGER IF EXISTS "{name}"')
        self.db.execute(f"DROP TABLE IF EXISTS {dbmysql.CHG}")  # nosec B608 — نام ثابت

    def is_fresh(self):
        """نصب تازه (هنوز IP یا اجرایی ثبت نشده)."""
        with self._lock:
            return not self.db.execute("SELECT 1 FROM ips LIMIT 1").fetchone() and not self.db.execute("SELECT 1 FROM runs LIMIT 1").fetchone()

    def db_status(self):
        be = self.backend
        if not be:
            return {"backend": "local", "engine": self.engine}
        pend = 0
        if be.mode != "blob":
            try:
                pend = self.db.execute(f"SELECT COUNT(*) FROM {dbmysql.CHG}").fetchone()[0]  # nosec B608
            except sqlite3.Error:
                pass
        return dbmysql.public_conf(be.conf) | {"ok": be.ok, "error": be.error, "last_flush": be.last_flush, "pending": pend}

    def _flush_first(fn):
        """متدهایی که زیر self._lock ذخیره (flush) می‌کنند: اول قفل ذخیره، تا ترتیب قفل‌ها همه‌جا یکی باشد."""
        import functools

        @functools.wraps(fn)
        def wrap(self, *a, **k):
            with self._flush_lock:
                return fn(self, *a, **k)
        return wrap

    @_flush_first
    def use_mysql(self, conf, use_existing=False):
        """انتقال به MySQL در حال اجرا. پایگاه داده‌ی خالی ← داده‌ی فعلی منتقل می‌شود؛ دارای داده ← فقط با use_existing
        (داده‌ی فعلی کنار گذاشته و داده‌ی MySQL بارگذاری می‌شود)."""
        cur = self.backend
        if cur and (cur.conf["host"], int(cur.conf["port"]), cur.conf["database"]) == (conf["host"], int(conf["port"]), conf["database"]):
            return self._reconnect(conf)
        be = dbmysql.MySQLBackend(conf)
        meta = be.open()
        try:
            has = bool(meta.get("saved"))
            if has and not use_existing:
                raise dbmysql.DbError("EXISTS")
            with self._lock:
                old_be = self.backend
                if has:
                    db = self._new_db()
                    old_db, self.db = self.db, db
                    try:
                        ver = self._load_backend(db, be)
                        self._migrate()
                    except Exception:
                        self.db = old_db
                        raise
                    old_db.close()
                else:
                    ver = None
                    if old_be is None:
                        self.flush()
                    if self.engine == "cipher":        # MySQL با پایگاه داده‌ی موقت در حافظه کار می‌کند
                        mem = self._new_db()
                        copy_db(self.db, mem)
                        old_db, self.db = self.db, mem
                    self._drop_triggers()
                self.backend = be
                try:
                    self._backend_prepare(ver)
                    if be.mode == "blob":
                        be.save_blob(self.db.serialize())
                except Exception:
                    self.backend = old_be
                    if self.engine == "cipher" and not has:
                        self.db.close()
                        self.db = old_db
                    raise
                if self.engine == "cipher":
                    if not has:
                        old_db.close()
                    self.engine = "memory"
                    self._wipe_files(self._sdb_files())
                if old_be is not None:
                    old_be.close()
                dbmysql.save_conf(conf)
                self._saved = self.db.total_changes
                be.last_flush = time.time()
                if self.enc_path.exists():       # نسخه‌ی محلی دیگر استفاده نمی‌شود
                    from . import wipe
                    wipe.overwrite(self.enc_path)
                    self.enc_path.unlink()
            return {"loaded": has}
        except Exception:
            if self.backend is not be:
                be.close()
            raise

    @_flush_first
    def _reconnect(self, conf):
        """همان پایگاه داده با تنظیمات تازه (TLS، رمز، کاربر). حالت ذخیره عوض نمی‌شود؛ داده جابه‌جا نمی‌شود."""
        cur = self.backend
        if conf.get("mode") != cur.mode:
            raise dbmysql.DbError("حالت ذخیره‌ی یک پایگاه داده عوض نمی‌شود؛ برای حالت دیگر نام پایگاه داده‌ی تازه بدهید.")
        with self._lock:
            self.flush()
            cur.close()                       # قفل آزاد شود تا اتصال تازه بگیردش
            be = dbmysql.MySQLBackend(conf)
            try:
                be.open()
            except Exception:
                cur.open()                    # برگشت به تنظیمات قبلی
                raise
            if be.mode != "blob":
                be.install_triggers(self.db)
            self.backend = be
            be.last_flush = time.time()
            dbmysql.save_conf(conf)
        return {"loaded": False, "reconnected": True}

    @_flush_first
    def use_local(self):
        """برگشت به فایل محلی: داده‌ی فعلی در state.dat نوشته می‌شود؛ داده‌های MySQL دست نمی‌خورند."""
        with self._lock:
            be = self.backend
            if be is None:
                return
            try:
                self.flush()
            except Exception:
                log.exception("نوشتن آخرین تغییرات در MySQL پیش از برگشت به محلی ناموفق بود")
            self._drop_triggers()
            self.backend = None
            be.close()
            dbmysql.remove_conf()
            self._saved = -1
            if _cipher_mod() is not None:
                self._wipe_files(self._sdb_files())
                self._to_cipher()
            else:
                self.flush()

    def wipe_backend(self):
        """RESET: جدول‌های AutoKRP در MySQL حذف می‌شوند."""
        with self._lock:
            be = self.backend
            if not be:
                return 0
            n = be.drop_all()
            self._drop_triggers()
            self.backend = None
            be.close()
            self._saved = self.db.total_changes     # پس از پاک‌سازی چیزی جایی نوشته نشود
            return n

    def flush(self):
        """ذخیره (رمزشده در فایل محلی، یا MySQL) اگر از آخرین ذخیره تغییری بوده است.
        فایل محلی: فقط گرفتن تصویر (serialize) زیر قفل پایگاه داده است؛ رمز و نوشتن روی دیسک بیرون از آن (با قفل
        جدای ذخیره) تا در پایگاه داده‌ی بزرگ بقیه‌ی برنامه چند ثانیه منتظر نماند."""
        with self._flush_lock:
            with self._lock:
                if self._closed or self.db.in_transaction:
                    return False
                if self.backend is None and self.engine == "cipher":
                    return False                 # SQLCipher هر تراکنش را خودش (فقط صفحه‌های تغییرکرده) می‌نویسد
                if self.backend is None:
                    ch = self.db.total_changes
                    if ch == self._saved:
                        return False
                    img = self.db.serialize()
                else:
                    return self._flush_backend()
            t0 = time.monotonic()
            try:
                atrest.write_bytes(self.enc_path, img)
            finally:
                del img
            self.last_flush_secs = time.monotonic() - t0
            with self._lock:
                self._saved = ch
            return True

    def _flush_backend(self):
        be = self.backend
        try:
            if be.mode == "blob":
                ch = self.db.total_changes
                if ch == self._saved:
                    return False
                be.save_blob(self.db.serialize())
                self._saved = ch
            else:
                if not be.flush_changes(self.db):
                    if not be.ok:
                        be.ensure()
                        be.ok, be.error = True, ""
                    return False
            be.ok, be.error, be.last_flush = True, "", time.time()
            return True
        except Exception as e:  # noqa — اتصال قطع: تغییرات می‌مانند و دفعه‌ی بعد نوشته می‌شوند
            be._fail(dbmysql.DbError(str(e)) if not isinstance(e, dbmysql.DbError) else e)
            return False

    def _flusher(self):
        n = 0
        while not self._stop.wait(1):
            n += 1
            secs = self.FLUSH_SECS_BLOB if self.backend and self.backend.mode == "blob" else self.FLUSH_SECS
            # پایگاه داده‌ی بزرگ: فاصله‌ی ذخیره به نسبت زمان هر ذخیره (حداکثر FLUSH_SECS_MAX) تا CPU و دیسک
            # مدام درگیر بازنویسی کل فایل نباشند؛ بستن برنامه همیشه ذخیره‌ی کامل انجام می‌دهد.
            secs = max(secs, min(self.FLUSH_SECS_MAX, int(self.last_flush_secs * 10)))
            if n < secs:
                continue
            n = 0
            try:
                self.flush()
            except Exception:
                log.exception("ذخیره‌ی پایگاه داده ناموفق بود")

    @_flush_first
    def close(self):
        self._stop.set()
        with self._lock:
            if self._closed:
                return
            try:
                self.flush()
            except Exception:
                log.exception("ذخیره‌ی پایگاه داده هنگام بستن ناموفق بود")
            self._closed = True
            if self.backend:
                self.backend.close()
            try:
                self.db.close()
            except Exception:
                pass

    def _migrate(self):
        with self._lock:
            self.db.execute("CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT)")
            row = self.db.execute("SELECT value FROM meta WHERE key='schema'").fetchone()
            ver = int(row[0]) if row else 0
            for i, m in enumerate(MIGRATIONS[ver:], start=ver + 1):
                self.db.execute("BEGIN")
                try:
                    m(self.db)
                    self.db.execute("INSERT OR REPLACE INTO meta VALUES('schema', ?)", (str(i),))
                    self.db.execute("COMMIT")
                except Exception:
                    self.db.execute("ROLLBACK")
                    raise
            for table, cols in REQUIRED_COLUMNS.items():
                have = {r[1] for r in self.db.execute(f"PRAGMA table_info({table})")}  # nosec B608 — نام جدول از کد
                if not have:
                    continue
                for col, typ in cols.items():
                    if col not in have:
                        log.warning("ستون جاافتاده‌ی %s.%s اضافه شد", table, col)
                        self.db.execute(f"ALTER TABLE {table} ADD COLUMN {col} {typ}")  # nosec B608 — نام‌ها از کد
            if not self.meta("installed_at"):
                self.set_meta("installed_at", str(time.time()))

    # ------------------------------------------------------------ meta / keys
    def meta(self, key, default=None):
        with self._lock:
            r = self.db.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
            return r[0] if r else default

    def set_meta(self, key, value):
        with self._lock:
            self.db.execute("INSERT OR REPLACE INTO meta VALUES(?,?)", (key, str(value)))

    def is_processed(self, key) -> bool:
        with self._lock:
            return self.db.execute("SELECT 1 FROM processed WHERE key=?", (key,)).fetchone() is not None

    def processed_info(self, key):
        with self._lock:
            r = self.db.execute("SELECT ts, info FROM processed WHERE key=?", (key,)).fetchone()
            return dict(r) if r else None

    def mark_processed(self, key, info=""):
        """True اگر کلید تازه ثبت شد، False اگر از قبل بود."""
        with self._lock:
            cur = self.db.execute("INSERT OR IGNORE INTO processed VALUES(?,?,?)", (key, time.time(), info))
            return cur.rowcount == 1

    # ------------------------------------------------------------ IPs
    def upsert_ip(self, ip, **fields):
        bad = [k for k in fields if not _COL.match(k)]
        if bad:   # نام ستون‌ها از کد می‌آید؛ این فقط دفاع در عمق در برابر SQL injection است
            raise ValueError(f"نام ستون نامعتبر: {bad}")
        fields = {k: v for k, v in fields.items() if k in IP_FIELDS and k != "ip"}
        with self._lock:
            now = time.strftime("%Y-%m-%d %H:%M:%S")
            exists = self.db.execute("SELECT 1 FROM ips WHERE ip=?", (ip,)).fetchone()
            if not exists:
                fields.setdefault("first_seen", now)
                cols = ["ip"] + list(fields)
                self.db.execute(f"INSERT INTO ips({','.join(cols)}) VALUES({','.join('?' * len(cols))})",  # nosec B608 — نام ستون‌ها از کد است، مقادیر با ? پارامتری‌اند
                                [ip] + [self._v(v) for v in fields.values()])
            elif fields:
                sets = ",".join(f"{k}=?" for k in fields)
                self.db.execute(f"UPDATE ips SET {sets} WHERE ip=?", [self._v(v) for v in fields.values()] + [ip])  # nosec B608 — نام ستون‌ها از کد است، مقادیر با ? پارامتری‌اند
        self._breathe()

    @staticmethod
    def _v(v):
        if isinstance(v, (list, dict)):
            return json.dumps(v, ensure_ascii=False)
        if isinstance(v, bool):
            return "True" if v else "False"
        return v

    def get_ip(self, ip):
        with self._lock:
            r = self.db.execute("SELECT * FROM ips WHERE ip=?", (ip,)).fetchone()
            return dict(r) if r else None

    def get_ips(self, ips):
        """{ip: ردیف} برای چند IP با چند پرس‌وجوی IN (به‌جای یک پرس‌وجو و قفل برای هر IP)."""
        out, ips = {}, list(dict.fromkeys(ips))
        with self._lock:
            for i in range(0, len(ips), 500):
                part = ips[i:i + 500]
                for r in self.db.execute(f"SELECT * FROM ips WHERE ip IN ({','.join('?' * len(part))})", part):  # nosec B608 — فقط ? ها
                    out[r["ip"]] = dict(r)
        return out

    BATCH_BREATHE = 200       # 1.27.5: هر این‌قدر نوشتن در batch، commit و رها کردن کوتاه قفل

    @contextlib.contextmanager
    def batch(self):
        """چند نوشتن پشت‌سرهم در یک تراکنش (به‌جای یک تراکنش و fsync برای هر ردیف). بدون عملیات شبکه داخلش.
        1.27.5: هر BATCH_BREATHE نوشتن (upsert_ip) تراکنش commit و قفل چند میلی‌ثانیه رها می‌شود؛ قبلاً نتیجه‌ی
        هزاران IP (AbuseIPDB، بررسی تکمیلی، Splunk، ورود فایل) قفل پایگاه داده را یکسره ده‌ها ثانیه نگه می‌داشت و رابط
        (get_state، mon_state و …) همان‌قدر منتظر می‌ماند (memdiag کاربر: get_state=33.8s). هر تکه‌ی commit‌شده
        مستقل است؛ خطا فقط تکه‌ی جاری را برمی‌گرداند."""
        self._lock.acquire()
        mine = False
        try:
            if self.db.in_transaction:
                yield
                return
            self.db.execute("BEGIN")
            self._bt, mine = {"tid": threading.get_ident(), "n": 0}, True
            try:
                yield
            except BaseException:
                if self.db.in_transaction:
                    self.db.execute("ROLLBACK")
                raise
            if self.db.in_transaction:
                self.db.execute("COMMIT")
        finally:
            if mine:
                self._bt = None
            self._lock.release()

    def _breathe(self):
        """داخل batch همین thread (و فقط وقتی قفل را خود batch نگه داشته): commit، رها کردن کوتاه قفل، تراکنش تازه."""
        bt = getattr(self, "_bt", None)
        if not bt or bt["tid"] != threading.get_ident():
            return
        bt["n"] += 1
        if bt["n"] % self.BATCH_BREATHE:
            return
        if self.db.in_transaction:
            self.db.execute("COMMIT")
        self._lock.release()
        try:
            time.sleep(0.003)             # فرصت برای thread رابط
        finally:
            self._lock.acquire()
            if not self.db.in_transaction:
                self.db.execute("BEGIN")

    def delete_ips(self, ips):
        with self._lock:
            self.db.executemany("DELETE FROM ips WHERE ip=?", [(i,) for i in ips])
        return len(ips)

    def fw_reconcile(self, banned):
        """هماهنگی وضعیت FortiGate دیتابیس با لیست فعلی Banned فورتی‌گیت.
        banned: [{"ip", "source", "expires"}]. IPی که «بلاک شد/از قبل Banned» ثبت شده ولی دیگر در لیست نیست ← unbanned؛
        IPی که در لیست هست ولی دیتابیس بلاک‌شده نمی‌داند ← already. خروجی: (فهرست برداشته‌شده‌ها، فهرست تازه‌دیده‌ها)."""
        cur = {}
        for b in banned or []:
            ip = str(b.get("ip") or "").strip()
            if ip:
                cur[ip] = b
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        gone, found = [], []
        with self._lock:
            rows = self.db.execute("SELECT ip, fw_status FROM ips").fetchall()
            self.db.execute("BEGIN")
            try:
                for ip, st in rows:
                    if st in ("banned", "already") and ip not in cur:
                        self.db.execute("UPDATE ips SET fw_status='unbanned', fw_detail=?, fw_at=? WHERE ip=?",
                                        ("دیگر در لیست Banned فورتی‌گیت نیست (برداشته یا منقضی شد)", now, ip))
                        gone.append(ip)
                    elif ip in cur and st not in ("banned", "already"):
                        b = cur[ip]
                        src = str(b.get("source") or "").strip()
                        self.db.execute("UPDATE ips SET fw_status='already', fw_detail=?, fw_at=? WHERE ip=?",
                                        ("در لیست Banned فورتی‌گیت" + (f" (منبع: {src})" if src else ""), now, ip))
                        found.append(ip)
                self.db.execute("COMMIT")
            except BaseException:
                self.db.execute("ROLLBACK")
                raise
        return gone, found

    def ips_brief(self):
        with self._lock:
            return [dict(r) for r in self.db.execute("SELECT ip, fw_status FROM ips").fetchall()]

    def purge_clean(self, before: str):
        """IPهای غیرمخربِ بررسی‌شده با AbuseIPDB (نه ثبت دستی) که آخرین بررسی‌شان قبل از before است."""
        with self._lock:
            cur = self.db.execute("DELETE FROM ips WHERE abuse_status='CLEAN' AND score IS NOT NULL "
                                  "AND checked_at IS NOT NULL AND checked_at < ? "
                                  "AND COALESCE(fw_status, '') NOT IN ('banned', 'already')", (before,))
            return cur.rowcount

    def ips_by_status(self, statuses, cols="*"):
        """IPها با وضعیت‌های داده‌شده، با فیلتر در خود SQL (بدون بارگذاری کل جدول)."""
        statuses = list(statuses)
        q = ",".join("?" * len(statuses))
        with self._lock:
            rows = self.db.execute(f"SELECT {cols} FROM ips WHERE abuse_status IN ({q}) "  # nosec B608 — cols از کد است
                                   "ORDER BY COALESCE(checked_at, first_seen) DESC", statuses).fetchall()
            return [dict(r) for r in rows]

    def change_mark(self):
        """نشانه‌ی «تغییر کرده؟» برای کش: هر نوشتن total_changes را بالا می‌برد؛ id(db) برای وقتی پایگاه داده عوض می‌شود."""
        with self._lock:
            return id(self.db), self.db.total_changes

    def ip_count_rows(self):
        """ستون‌های لازم برای شمارش‌های داشبورد (تاپل، بدون dict)."""
        with self._lock:
            return self.db.execute("SELECT abuse_status, score, is_whitelisted, fw_status, checked_at, review FROM ips").fetchall()

    def list_ips_raw(self, limit=10_000_000):
        """(ستون‌ها، ردیف‌ها به‌صورت تاپل) — برای فهرست بزرگ بدون ساختن dict برای هر ردیف."""
        with self._lock:
            cur = self.db.execute("SELECT * FROM ips ORDER BY COALESCE(checked_at, first_seen) DESC LIMIT ?", (limit,))
            cols = [d[0] for d in cur.description]
            return cols, [tuple(r) for r in cur.fetchall()]

    def list_ips(self, limit=5000):
        with self._lock:
            rows = self.db.execute("SELECT * FROM ips ORDER BY COALESCE(checked_at, first_seen) DESC LIMIT ?",
                                   (limit,)).fetchall()
            return [dict(r) for r in rows]

    # ------------------------------------------------------------ runs
    def save_run(self, run: dict):
        with self._lock:
            # 1.37: ستون‌ها با نام (ستون log اضافه شد) و بدون پاک کردن log ذخیره‌شده (REPLACE ردیف را کامل عوض می‌کرد)
            self.db.execute(
                "INSERT INTO runs(id, started, finished, trigger, steps, status, summary, dir) VALUES(?,?,?,?,?,?,?,?) "
                "ON CONFLICT(id) DO UPDATE SET started=excluded.started, finished=excluded.finished, trigger=excluded.trigger, "
                "steps=excluded.steps, status=excluded.status, summary=excluded.summary, dir=excluded.dir",
                (run["id"], run.get("started"), run.get("finished"), run.get("trigger"),
                 json.dumps(run.get("steps", {}), ensure_ascii=False), run.get("status"),
                 json.dumps(run.get("summary", {}), ensure_ascii=False), run.get("dir")))

    def list_runs(self, limit=200):
        with self._lock:
            rows = self.db.execute("SELECT * FROM runs ORDER BY started DESC LIMIT ?", (limit,)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["has_log"] = bool(d.pop("log", None))       # 1.37: متن گزارش جدا خوانده می‌شود (حجم)
            d["steps"] = json.loads(d["steps"] or "{}")
            try:
                d["summary"] = json.loads(d["summary"] or "{}")
            except ValueError:
                d["summary"] = {}
            out.append(d)
        return out

    def last_run(self):
        runs = self.list_runs(1)
        return runs[0] if runs else None

    # ------------------------------------------------------------ history
    def add_history(self, kind, target, status, detail="", run_id="", file="", user=None):
        if user is None:
            user = getattr(ACTOR, "name", "") or ""
        with self._lock:
            self.db.execute("INSERT INTO history(ts,run_id,kind,target,status,detail,file,user) VALUES(?,?,?,?,?,?,?,?)",
                            (time.time(), run_id, kind, target, status, detail, file, user))

    def history_get(self, hid):
        with self._lock:
            r = self.db.execute("SELECT * FROM history WHERE id=?", (int(hid),)).fetchone()
            return dict(r) if r else None

    def history_by_file(self, file):
        with self._lock:
            r = self.db.execute("SELECT * FROM history WHERE file=? ORDER BY id DESC LIMIT 1", (str(file),)).fetchone()
            return dict(r) if r else None

    # ---- 1.37: تاریخچه با صفحه‌بندی و جستجوی سمت سرور (قبلاً فقط ۳۰۰۰ ردیف آخر به رابط می‌رسید)
    def history_query(self, kinds=None, status=None, q="", since=None, until=None, hide=(), offset=0, limit=200, target=None):
        where, args = [], []
        if kinds:
            where.append(f"kind IN ({','.join('?' * len(kinds))})")
            args += list(kinds)
        if hide:
            where.append(f"kind NOT IN ({','.join('?' * len(hide))})")
            args += list(hide)
        if status:
            where.append("status=?")
            args.append(status)
        if since:
            where.append("ts>=?")
            args.append(float(since))
        if until:
            where.append("ts<=?")
            args.append(float(until))
        if target:
            where.append("target=?")
            args.append(str(target))
        q = str(q or "").strip()[:200]
        if q:
            like = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
            where.append("(" + " OR ".join(f"COALESCE({c},'') LIKE ? ESCAPE '\\'" for c in ("target", "detail", "run_id", "kind", "user")) + ")")
            args += [like] * 5
        w = (" WHERE " + " AND ".join(where)) if where else ""
        with self._lock:
            total = self.db.execute(f"SELECT COUNT(*) FROM history{w}", args).fetchone()[0]  # nosec B608 — ستون‌ها از کد، مقدارها پارامتر
            rows = self.db.execute(f"SELECT * FROM history{w} ORDER BY id DESC LIMIT ? OFFSET ?",  # nosec B608
                                   args + [int(limit), int(offset)]).fetchall()
        return [dict(r) for r in rows], total

    def run_set_log(self, run_id, text, started=None):
        """متن گزارش اجرا (فشرده و base64)؛ اگر ردیف اجرا نیست (اجرای خیلی قدیمی) ردیف کوتاه ساخته می‌شود."""
        import base64
        import zlib
        z = "z:" + base64.b64encode(zlib.compress(text.encode("utf-8"), 6)).decode("ascii")
        with self._lock:
            n = self.db.execute("UPDATE runs SET log=? WHERE id=?", (z, str(run_id))).rowcount
            if not n:
                self.db.execute("INSERT INTO runs(id, started, finished, trigger, steps, status, summary, dir, log) VALUES(?,?,?,?,?,?,?,?,?)",
                                (str(run_id), started or time.time(), started or time.time(), "", "{}", "done", "", "", z))

    def run_get_log(self, run_id):
        import base64
        import zlib
        with self._lock:
            r = self.db.execute("SELECT log FROM runs WHERE id=?", (str(run_id),)).fetchone()
        v = r[0] if r else None
        if not v:
            return None
        if v.startswith("z:"):
            try:
                return zlib.decompress(base64.b64decode(v[2:])).decode("utf-8", "replace")
            except Exception:  # noqa
                return None
        return v

    def list_history(self, limit=3000):
        with self._lock:
            rows = self.db.execute("SELECT * FROM history ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
            return [dict(r) for r in rows]

    def counts_since(self, ts):
        with self._lock:
            rows = self.db.execute(
                "SELECT kind, status, COUNT(*) n FROM history WHERE ts>=? GROUP BY kind, status", (ts,)).fetchall()
            return [dict(r) for r in rows]

    # ------------------------------------------------------------ stats
    def add_stat(self, kind, sub, ip="", cc="", isp="", src="", ts=None):
        self.add_stats([(ts if ts is not None else time.time(), kind, sub, ip, cc or "", isp or "", src)])

    def add_stats(self, rows):
        """rows: [(ts, kind, sub, ip, cc, isp, src)] — رویداد خام و خلاصه‌ها در یک تراکنش."""
        rows = [tuple(r) for r in rows]
        if not rows:
            return
        if len(rows) > 1000 and not self.db.in_transaction:   # 1.27.5: تکه‌تکه تا قفل یکسره نگه داشته نشود
            for i in range(0, len(rows), 1000):
                self.add_stats(rows[i:i + 1000])
                time.sleep(0.002)
            return
        with self._lock:
            own = not self.db.in_transaction
            if own:
                self.db.execute("BEGIN")
            try:
                new = []
                for r in rows:
                    if self.db.execute("INSERT OR IGNORE INTO stat_events VALUES(?,?,?,?,?,?,?)", r).rowcount:
                        new.append(r)
                _roll(self.db, new)
                if own:
                    self.db.execute("COMMIT")
            except Exception:
                if own:
                    self.db.execute("ROLLBACK")
                raise
            self._stat_ver += 1

    def purge_stat_events(self, days):
        """رویدادهای خام قدیمی‌تر از days روز (خلاصه‌ها همیشه می‌مانند). خروجی: تعداد حذف‌شده."""
        if not days or days <= 0:
            return 0
        with self._lock:
            return self.db.execute("DELETE FROM stat_events WHERE ts < ?", (time.time() - days * 86400,)).rowcount

    def stats_rollup(self, day_bucket, cur_days, prev_days):
        """داده‌ی صفحه‌ی آمار از خلاصه‌ها. day_bucket: {'YYYY-MM-DD': شماره‌ی بازه}؛ cur_days/prev_days: (اولین، آخرین روز)."""
        with self._lock:
            db = self.db
            db.execute("CREATE TEMP TABLE IF NOT EXISTS _sb(day TEXT PRIMARY KEY, b INTEGER)")
            db.execute("DELETE FROM _sb")
            db.executemany("INSERT INTO _sb VALUES(?,?)", list(day_bucket.items()))
            abuse = db.execute(
                "SELECT b, last_sub, COUNT(*) FROM (SELECT m.b b, s.ip, s.last_sub last_sub, MAX(s.last_ts) "
                "FROM stat_ip_day s JOIN _sb m ON m.day = s.day GROUP BY m.b, s.ip) GROUP BY b, last_sub").fetchall()
            daily = db.execute("SELECT m.b, s.kind, s.sub, s.src, SUM(s.n) FROM stat_day s JOIN _sb m ON m.day = s.day "
                               "GROUP BY m.b, s.kind, s.sub, s.src").fetchall()
            geo = {k: db.execute("SELECT name, SUM(n) t FROM stat_geo_day WHERE kind = ? AND day BETWEEN ? AND ? "
                                 "GROUP BY name ORDER BY t DESC, name LIMIT 10", (k, *cur_days)).fetchall() for k in ("cc", "isp")}

            def kpi(d0, d1):
                ip = db.execute("SELECT COUNT(DISTINCT ip), COUNT(DISTINCT CASE WHEN abuse = 1 THEN ip END) FROM stat_ip_day "
                                "WHERE day BETWEEN ? AND ?", (d0, d1)).fetchone()
                n = {(k, sb, sr): t for k, sb, sr, t in db.execute(
                    "SELECT kind, sub, src, SUM(n) FROM stat_day WHERE day BETWEEN ? AND ? AND kind IN ('abuse', 'ban', 'ticket') "
                    "GROUP BY kind, sub, src", (d0, d1))}
                tot = lambda k, sub=None, src=None: sum(v for (a, b, c), v in n.items() if a == k and (sub is None or b == sub) and (src is None or c == src))
                return {"checked": ip[0], "malicious": ip[1], "online": tot("abuse", src="online"), "cache": tot("abuse", src="cache"),
                        "ban_ok": tot("ban", "ok"), "ban_fail": tot("ban", "failed"), "tickets": tot("ticket", "ok")}
            first = db.execute("SELECT MIN(day) FROM stat_day").fetchone()[0]
            db.execute("DELETE FROM _sb")
            return {"abuse": [tuple(r) for r in abuse], "daily": [tuple(r) for r in daily],
                    "geo": {k: [tuple(r) for r in v] for k, v in geo.items()},
                    "kpi": kpi(*cur_days), "prev": kpi(*prev_days), "first": first}

    # ------------------------------------------------------------ تکرار IP (روزهای بررسی)
    # هر روزی که IP به مرحله‌ی AbuseIPDB رسیده (آنلاین یا از کش، و داده‌ی قبلی backfill) یک روز حساب می‌شود؛
    # چند بار در یک روز = یک روز. ورود فایل و ثبت دستی حساب نمی‌شوند.
    def seen_days(self, ips=None):
        """{ip: (روزها، اولین، آخرین)} — روزهایی که IP به مرحله‌ی AbuseIPDB رسیده (آنلاین، کش یا داده‌ی قبلی).
        1.22: از جدول خلاصه‌ی stat_ip_day (یک ردیف برای هر IP در هر روز)؛ کش تا ثبت رویداد بعدی."""
        with self._lock:
            c = self._seen_cache
            if ips is None and c and c[0] == (id(self.db), self._stat_ver):
                return c[1]
            q = "SELECT ip, COUNT(*), MIN(seen_first), MAX(seen_last) FROM stat_ip_day WHERE seen = 1"
            if ips is None:
                out = {r[0]: (r[1], r[2], r[3]) for r in self.db.execute(q + " GROUP BY ip")}
                self._seen_cache = ((id(self.db), self._stat_ver), out)
                return out
            out, ips = {}, list(dict.fromkeys(ips))
            for i in range(0, len(ips), 500):
                part = ips[i:i + 500]
                for r in self.db.execute(q + f" AND ip IN ({','.join('?' * len(part))}) GROUP BY ip", part):  # nosec B608 — فقط ? ها
                    out[r[0]] = (r[1], r[2], r[3])
            return out

    def repeat_alerts(self, ips):
        out = {}
        ips = list(dict.fromkeys(ips))
        with self._lock:
            for i in range(0, len(ips), 500):
                part = ips[i:i + 500]
                for r in self.db.execute(f"SELECT ip, days FROM repeat_alerts WHERE ip IN ({','.join('?' * len(part))})",  # nosec B608 — فقط ? ها
                                         part):
                    out[r[0]] = r[1]
        return out

    def set_repeat_alerts(self, rows):
        """rows: [(ip, days)]"""
        now = time.time()
        with self._lock:
            self.db.executemany("INSERT OR REPLACE INTO repeat_alerts VALUES(?,?,?)", [(ip, d, now) for ip, d in rows])

    def stat_events(self, since, until):
        with self._lock:
            return [dict(r) for r in self.db.execute(
                "SELECT * FROM stat_events WHERE ts>=? AND ts<? ORDER BY ts", (since, until)).fetchall()]

    def first_stat_event(self, until):
        """فقط اولین رویداد (نه بارگذاری کل جدول)."""
        with self._lock:
            r = self.db.execute("SELECT * FROM stat_events WHERE ts<? ORDER BY ts LIMIT 1", (until,)).fetchone()
            return [dict(r)] if r else []

    def runs_between(self, since, until):
        with self._lock:
            return [dict(r) for r in self.db.execute(
                "SELECT id, started, status, trigger FROM runs WHERE started>=? AND started<?", (since, until)).fetchall()]

    def set_snapshot(self, day, fw_pending, review_pending, total):
        """فقط اگر مقدار عوض شده: هر نوشتن total_changes را بالا می‌برد (کش‌ها باطل و کل پایگاه داده دوباره ذخیره می‌شود)
        و صفحه‌ی آمار هر بار این را صدا می‌زند."""
        with self._lock:
            cur = self.db.execute("SELECT fw_pending, review_pending, total_ips FROM daily_snapshot WHERE day=?", (day,)).fetchone()
            if cur is not None and tuple(cur) == (fw_pending, review_pending, total):
                return
            self.db.execute("INSERT OR REPLACE INTO daily_snapshot VALUES(?,?,?,?)", (day, fw_pending, review_pending, total))

    def snapshots(self, since_day):
        with self._lock:
            return [dict(r) for r in self.db.execute(
                "SELECT * FROM daily_snapshot WHERE day>=? ORDER BY day", (since_day,)).fetchall()]

    # ------------------------------------------------------------ ssh
    SSH_DEV_FIELDS = ("name", "host", "port", "device_type", "grp", "use_enable", "notes", "backup", "legacy", "owner", "cred_id", "protocol")   # username در vault

    def ssh_devices(self):
        with self._lock:
            return [dict(r) for r in self.db.execute("SELECT * FROM ssh_devices ORDER BY grp, name, host").fetchall()]

    def ssh_device(self, dev_id):
        with self._lock:
            r = self.db.execute("SELECT * FROM ssh_devices WHERE id=?", (dev_id,)).fetchone()
            return dict(r) if r else None

    def ssh_save_device(self, dev):
        f = {k: dev.get(k) for k in self.SSH_DEV_FIELDS}
        with self._lock:
            if dev.get("id"):
                self.db.execute(f"UPDATE ssh_devices SET {','.join(k + '=?' for k in f)} WHERE id=?",  # nosec B608 — نام ستون‌ها از کد است، مقادیر با ? پارامتری‌اند
                                list(f.values()) + [dev["id"]])
                return int(dev["id"])
            cur = self.db.execute(f"INSERT INTO ssh_devices({','.join(f)}, created) VALUES({','.join('?' * len(f))}, ?)",  # nosec B608 — نام ستون‌ها از کد است، مقادیر با ? پارامتری‌اند
                                  list(f.values()) + [time.time()])
            return cur.lastrowid

    # ------------------------------------------------------------ مانیتورینگ
    MON_FIELDS = ("name", "host", "kind", "port", "url", "interval", "threshold", "timeout", "slow_ms", "icon", "grp",
                  "owner", "enabled", "notify", "notes", "snmp", "cred_id", "parent_id", "cert_days", "policy_id", "tpl")

    def mon_targets(self):
        with self._lock:
            return [dict(r) for r in self.db.execute("SELECT * FROM mon_targets ORDER BY grp, name").fetchall()]

    def mon_target(self, tid):
        with self._lock:
            r = self.db.execute("SELECT * FROM mon_targets WHERE id=?", (int(tid),)).fetchone()
            return dict(r) if r else None

    def mon_save(self, t):
        f = {k: t.get(k) for k in self.MON_FIELDS}
        with self._lock:
            if t.get("id"):
                self.db.execute(f"UPDATE mon_targets SET {','.join(k + '=?' for k in f)} WHERE id=?",  # nosec B608 — نام ستون‌ها از کد
                                list(f.values()) + [int(t["id"])])
                return int(t["id"])
            cur = self.db.execute(f"INSERT INTO mon_targets({','.join(f)}, created) VALUES({','.join('?' * len(f))}, ?)",  # nosec B608 — نام ستون‌ها از کد
                                  list(f.values()) + [time.time()])
            return cur.lastrowid

    def mon_delete(self, tid):
        with self._lock:
            self.db.execute("DELETE FROM mon_targets WHERE id=?", (int(tid),))
            self.db.execute("DELETE FROM mon_events WHERE target_id=?", (int(tid),))
            self.db.execute("UPDATE mon_targets SET parent_id=NULL WHERE parent_id=?", (int(tid),))

    def mon_event_open(self, tid, name, start, reason, kind="down"):
        with self._lock:
            return self.db.execute("INSERT INTO mon_events(target_id,name,start,end,reason,kind) VALUES(?,?,?,NULL,?,?)",
                                   (int(tid), name, start, reason, kind)).lastrowid

    def mon_event_open_get(self, tid):
        with self._lock:
            r = self.db.execute("SELECT * FROM mon_events WHERE target_id=? AND end IS NULL ORDER BY start DESC LIMIT 1", (int(tid),)).fetchone()
            return dict(r) if r else None

    def mon_set_parent(self, ids, parent_id):
        with self._lock:
            self.db.executemany("UPDATE mon_targets SET parent_id=? WHERE id=?", [(parent_id, int(i)) for i in ids])

    # پنجره‌های نگهداری
    MAINT_FIELDS = ("name", "scope", "kind", "start", "end", "days", "t_from", "t_to", "enabled", "owner", "note")

    # ---- قالب نمایش و داشبورد NOC (1.35)
    def lay_list(self, kind):
        with self._lock:
            out = []
            for r in self.db.execute("SELECT * FROM mon_layouts WHERE kind=? ORDER BY id", (kind,)).fetchall():
                d = dict(r)
                try:
                    d["data"] = json.loads(d.get("data") or "{}")
                except ValueError:
                    d["data"] = {}
                out.append(d)
            return out

    def lay_save(self, lid, kind, name, data, owner=""):
        with self._lock:
            js = json.dumps(data, ensure_ascii=False)
            if lid:
                self.db.execute("UPDATE mon_layouts SET name=?, data=? WHERE id=? AND kind=?", (name, js, int(lid), kind))
                return int(lid)
            return self.db.execute("INSERT INTO mon_layouts(kind, name, data, owner, created) VALUES(?, ?, ?, ?, ?)",
                                   (kind, name, js, owner, time.time())).lastrowid

    def lay_delete(self, lid, kind):
        with self._lock:
            if kind == "tpl":
                self.db.execute("UPDATE mon_targets SET tpl='' WHERE tpl=?", (str(int(lid)),))
            self.db.execute("DELETE FROM mon_layouts WHERE id=? AND kind=?", (int(lid), kind))

    # ---- ابزار API (1.40)
    API_CONN_COLS = ("name", "base_url", "auth", "key_name", "verify", "timeout", "headers", "owner", "notes")

    def api_conns(self):
        with self._lock:
            return [dict(r) for r in self.db.execute("SELECT * FROM api_conns ORDER BY name").fetchall()]

    def api_conn_get(self, cid):
        with self._lock:
            r = self.db.execute("SELECT * FROM api_conns WHERE id=?", (int(cid),)).fetchone()
            return dict(r) if r else None

    def api_conn_save(self, p):
        now = time.time()
        with self._lock:
            vals = [p.get(k) for k in self.API_CONN_COLS]
            if p.get("id"):
                self.db.execute("UPDATE api_conns SET " + ", ".join(f"{k}=?" for k in self.API_CONN_COLS) + ", updated=? WHERE id=?",  # nosec B608 — نام ستون‌ها ثابت
                                vals + [now, int(p["id"])])
                return int(p["id"])
            return self.db.execute("INSERT INTO api_conns(" + ", ".join(self.API_CONN_COLS) + ", created, updated) VALUES("  # nosec B608
                                   + ", ".join("?" * len(self.API_CONN_COLS)) + ", ?, ?)", vals + [now, now]).lastrowid

    def api_conn_delete(self, cid):
        with self._lock:
            self.db.execute("DELETE FROM api_requests WHERE conn_id=?", (int(cid),))
            self.db.execute("DELETE FROM api_conns WHERE id=?", (int(cid),))

    def api_reqs(self, cid=None):
        with self._lock:
            if cid is None:
                return [dict(r) for r in self.db.execute("SELECT * FROM api_requests ORDER BY name").fetchall()]
            return [dict(r) for r in self.db.execute("SELECT * FROM api_requests WHERE conn_id=? ORDER BY name", (int(cid),)).fetchall()]

    def api_req_get(self, rid):
        with self._lock:
            r = self.db.execute("SELECT * FROM api_requests WHERE id=?", (int(rid),)).fetchone()
            return dict(r) if r else None

    def api_req_save(self, p):
        now = time.time()
        cols = ("conn_id", "name", "method", "path", "params", "headers", "body", "body_type")
        with self._lock:
            vals = [p.get(k) for k in cols]
            if p.get("id"):
                self.db.execute("UPDATE api_requests SET " + ", ".join(f"{k}=?" for k in cols) + ", updated=? WHERE id=?",  # nosec B608
                                vals + [now, int(p["id"])])
                return int(p["id"])
            return self.db.execute("INSERT INTO api_requests(" + ", ".join(cols) + ", created, updated) VALUES("  # nosec B608
                                   + ", ".join("?" * len(cols)) + ", ?, ?)", vals + [now, now]).lastrowid

    def api_req_delete(self, rid):
        with self._lock:
            self.db.execute("DELETE FROM api_requests WHERE id=?", (int(rid),))

    API_LOG_KEEP = 20000

    def api_log_add(self, r):
        cols = ("ts", "user", "conn_id", "conn_name", "method", "url", "req_headers", "req_body", "status", "ms", "size", "resp_head", "error")
        with self._lock:
            lid = self.db.execute("INSERT INTO api_log(" + ", ".join(cols) + ") VALUES(" + ", ".join("?" * len(cols)) + ")",  # nosec B608
                                  [r.get(k) for k in cols]).lastrowid
            if lid % 500 == 0:                       # فقط آخرین ۲۰٬۰۰۰ درخواست
                self.db.execute("DELETE FROM api_log WHERE id<=?", (lid - self.API_LOG_KEEP,))
            return lid

    def api_log_list(self, user=None, conn_id=None, q="", offset=0, limit=100):
        w, a = [], []
        if user is not None:
            w.append("user=?"); a.append(user)
        if conn_id:
            w.append("conn_id=?"); a.append(int(conn_id))
        sql = " FROM api_log" + (" WHERE " + " AND ".join(w) if w else "")
        with self._lock:
            rows = [dict(r) for r in self.db.execute("SELECT id, ts, user, conn_id, conn_name, method, url, status, ms, size, error" + sql  # nosec B608
                                                     + " ORDER BY id DESC LIMIT 5000", a).fetchall()]
        q = str(q or "").strip().lower()
        if q:          # جستجو بعد از رمزگشایی (ستون‌های رمزشده در MySQL)
            rows = [r for r in rows if q in " ".join(str(r.get(k) or "") for k in ("user", "conn_name", "method", "url", "status", "error")).lower()]
        return rows[int(offset):int(offset) + int(limit)], len(rows)

    def api_log_get(self, lid):
        with self._lock:
            r = self.db.execute("SELECT * FROM api_log WHERE id=?", (int(lid),)).fetchone()
            return dict(r) if r else None

    def mon_set_tpl(self, ids, tpl):
        with self._lock:
            self.db.executemany("UPDATE mon_targets SET tpl=? WHERE id=?", [(tpl, int(i)) for i in ids])

    # ---- سیاست پایش (1.34)
    def pol_list(self):
        with self._lock:
            out = []
            for r in self.db.execute("SELECT * FROM mon_policies ORDER BY id").fetchall():
                d = dict(r)
                try:
                    d["data"] = json.loads(d.get("data") or "{}")
                except ValueError:
                    d["data"] = {}
                out.append(d)
            return out

    def pol_save(self, pid, name, data):
        with self._lock:
            js = json.dumps(data, ensure_ascii=False)
            if pid:
                self.db.execute("UPDATE mon_policies SET name=?, data=? WHERE id=?", (name, js, int(pid)))
                return int(pid)
            return self.db.execute("INSERT INTO mon_policies(name, data, created) VALUES(?, ?, ?)", (name, js, time.time())).lastrowid

    def pol_delete(self, pid):
        with self._lock:
            self.db.execute("UPDATE mon_targets SET policy_id=NULL WHERE policy_id=?", (int(pid),))
            self.db.execute("DELETE FROM mon_policies WHERE id=?", (int(pid),))

    def pol_usage(self):
        with self._lock:
            return {r[0]: r[1] for r in self.db.execute("SELECT policy_id, COUNT(*) FROM mon_targets WHERE policy_id IS NOT NULL GROUP BY policy_id")}

    def maint_list(self):
        with self._lock:
            return [dict(r) for r in self.db.execute("SELECT * FROM mon_maint ORDER BY id").fetchall()]

    def maint_get(self, mid):
        with self._lock:
            r = self.db.execute("SELECT * FROM mon_maint WHERE id=?", (int(mid),)).fetchone()
            return dict(r) if r else None

    def maint_save(self, m):
        f = {k: m.get(k) for k in self.MAINT_FIELDS}
        with self._lock:
            if m.get("id"):
                self.db.execute(f"UPDATE mon_maint SET {','.join(k + '=?' for k in f)} WHERE id=?",  # nosec B608 — نام ستون‌ها از کد
                                list(f.values()) + [int(m["id"])])
                return int(m["id"])
            return self.db.execute(f"INSERT INTO mon_maint({','.join(f)}, created) VALUES({','.join('?' * len(f))}, ?)",  # nosec B608 — نام ستون‌ها از کد
                                   list(f.values()) + [time.time()]).lastrowid

    def maint_delete(self, mid):
        with self._lock:
            self.db.execute("DELETE FROM mon_maint WHERE id=?", (int(mid),))

    def mon_event_close(self, tid, end):
        with self._lock:
            self.db.execute("UPDATE mon_events SET end=? WHERE target_id=? AND end IS NULL", (end, int(tid)))

    def mon_events(self, since, until=None, ids=None):
        q, a = "SELECT * FROM mon_events WHERE (end IS NULL OR end>=?)", [since]
        if until:
            q += " AND start<=?"
            a.append(until)
        with self._lock:
            rows = [dict(r) for r in self.db.execute(q + " ORDER BY start DESC LIMIT 5000", a).fetchall()]  # nosec B608 — شرط‌ها ثابت‌اند
        return [r for r in rows if ids is None or r["target_id"] in ids]

    def mon_purge_events(self, before):
        with self._lock:
            self.db.execute("DELETE FROM mon_events WHERE end IS NOT NULL AND end<?", (before,))

    # ------------------------------------------------------------ پروفایل اعتبارنامه
    def creds_list(self, kind=None):
        with self._lock:
            q, a = "SELECT * FROM cred_profiles", []
            if kind:
                q, a = q + " WHERE kind=?", [kind]
            return [dict(r) for r in self.db.execute(q + " ORDER BY name", a).fetchall()]

    def cred_get(self, cid):
        with self._lock:
            r = self.db.execute("SELECT * FROM cred_profiles WHERE id=?", (int(cid),)).fetchone()
            return dict(r) if r else None

    def cred_save(self, p):
        with self._lock:
            if p.get("id"):
                self.db.execute("UPDATE cred_profiles SET name=?, notes=? WHERE id=?", (p["name"], p.get("notes") or "", int(p["id"])))
                return int(p["id"])
            cur = self.db.execute("INSERT INTO cred_profiles(name, kind, owner, notes, created) VALUES(?,?,?,?,?)",
                                  (p["name"], p["kind"], p.get("owner") or "", p.get("notes") or "", time.time()))
            return cur.lastrowid

    def cred_delete(self, cid):
        with self._lock:
            self.db.execute("DELETE FROM cred_profiles WHERE id=?", (int(cid),))

    def cred_users(self, cid):
        """دستگاه‌های SSH و هدف‌های مانیتورینگ SNMP که از این پروفایل استفاده می‌کنند."""
        with self._lock:
            return [dict(r) for r in self.db.execute("SELECT id, name, host, owner FROM ssh_devices WHERE cred_id=?", (int(cid),)).fetchall()] + \
                [dict(r) for r in self.db.execute("SELECT id, name, host, owner FROM mon_targets WHERE cred_id=?", (int(cid),)).fetchall()]

    def ssh_delete_devices(self, ids):
        with self._lock:
            self.db.executemany("DELETE FROM ssh_devices WHERE id=?", [(i,) for i in ids])

    def ssh_set_status(self, dev_id, status, message):
        with self._lock:
            self.db.execute("UPDATE ssh_devices SET last_status=?, last_at=?, last_message=? WHERE id=?",
                            (status, time.time(), message[:300], dev_id))

    def ssh_scripts(self):
        with self._lock:
            return [dict(r) for r in self.db.execute("SELECT * FROM ssh_scripts ORDER BY name").fetchall()]

    def ssh_script(self, sid):
        with self._lock:
            r = self.db.execute("SELECT * FROM ssh_scripts WHERE id=?", (sid,)).fetchone()
            return dict(r) if r else None

    def ssh_save_script(self, sc):
        keys = ("name", "device_type", "mode", "body", "use_sudo", "save_config")
        f = {k: sc.get(k) for k in keys}
        with self._lock:
            if sc.get("id"):
                self.db.execute(f"UPDATE ssh_scripts SET {','.join(k + '=?' for k in f)}, updated=? WHERE id=?",  # nosec B608 — نام ستون‌ها از کد است، مقادیر با ? پارامتری‌اند
                                list(f.values()) + [time.time(), sc["id"]])
                return int(sc["id"])
            cur = self.db.execute(f"INSERT INTO ssh_scripts({','.join(f)}, updated) VALUES({','.join('?' * len(f))}, ?)",  # nosec B608 — نام ستون‌ها از کد است، مقادیر با ? پارامتری‌اند
                                  list(f.values()) + [time.time()])
            return cur.lastrowid

    def ssh_delete_script(self, sid):
        with self._lock:
            self.db.execute("DELETE FROM ssh_scripts WHERE id=?", (sid,))

    def ssh_save_job(self, job):
        with self._lock:
            self.db.execute("INSERT OR REPLACE INTO ssh_jobs VALUES(?,?,?,?,?,?,?,?,?,?)",
                            (job["id"], job["started"], job.get("finished"), job["script_name"], job["status"],
                             job["total"], job["ok"], job["failed"], 1 if job.get("dry") else 0, job.get("kind", "run")))

    def ssh_save_result(self, job_id, r):
        with self._lock:
            self.db.execute("INSERT OR REPLACE INTO ssh_results VALUES(?,?,?,?,?,?,?,?,?)",
                            (job_id, r["device_id"], r["name"], r["host"], r["status"], r.get("started"),
                             r.get("finished"), r.get("message", "")[:500], r.get("out_file", "")))

    def ssh_jobs(self, limit=300):
        with self._lock:
            return [dict(r) for r in self.db.execute("SELECT * FROM ssh_jobs ORDER BY started DESC LIMIT ?", (limit,)).fetchall()]

    def ssh_results(self, job_id):
        with self._lock:
            return [dict(r) for r in self.db.execute("SELECT * FROM ssh_results WHERE job_id=? ORDER BY name", (job_id,)).fetchall()]

    # ------------------------------------------------------------ دارایی‌ها
    ASSET_FIELDS = ("serial", "vendor", "model", "hostname", "ip", "sw", "mac", "descr", "location", "location_dev", "loc_from_dev",
                    "label", "asset_tag", "notes", "status", "source", "serial_kind", "first_seen", "last_seen")

    def assets(self):
        with self._lock:
            return [dict(r) for r in self.db.execute("SELECT * FROM assets ORDER BY serial").fetchall()]

    def asset(self, aid):
        with self._lock:
            r = self.db.execute("SELECT * FROM assets WHERE id=?", (int(aid),)).fetchone()
            return dict(r) if r else None

    def asset_by_serial(self, serial):
        with self._lock:
            r = self.db.execute("SELECT * FROM assets WHERE serial=?", (serial,)).fetchone()
            return dict(r) if r else None

    def asset_insert(self, f):
        f = {k: f.get(k) for k in self.ASSET_FIELDS if k in f}
        with self._lock:
            cur = self.db.execute(f"INSERT INTO assets({','.join(f)}, created) VALUES({','.join('?' * len(f))}, ?)",  # nosec B608 — نام ستون‌ها از کد
                                  list(f.values()) + [time.time()])
            return cur.lastrowid

    def asset_update(self, aid, f):
        f = {k: v for k, v in f.items() if k in self.ASSET_FIELDS and k != "serial"}
        if not f:
            return
        with self._lock:
            self.db.execute(f"UPDATE assets SET {','.join(k + '=?' for k in f)} WHERE id=?", list(f.values()) + [int(aid)])  # nosec B608 — نام ستون‌ها از کد

    def asset_delete(self, aid):
        with self._lock:
            self.db.execute("DELETE FROM asset_parts WHERE asset_id=?", (int(aid),))
            self.db.execute("DELETE FROM assets WHERE id=?", (int(aid),))

    def asset_parts(self, aid=None):
        with self._lock:
            if aid is None:
                return [dict(r) for r in self.db.execute("SELECT * FROM asset_parts").fetchall()]
            return [dict(r) for r in self.db.execute("SELECT * FROM asset_parts WHERE asset_id=? ORDER BY id", (int(aid),)).fetchall()]

    def part_by_serial(self, serial):
        with self._lock:
            r = self.db.execute("SELECT * FROM asset_parts WHERE serial=?", (serial,)).fetchone()
            return dict(r) if r else None

    def part_add(self, aid, p, now):
        with self._lock:
            self.db.execute("INSERT INTO asset_parts(asset_id, serial, cls, name, descr, model, hw, src, first_seen, last_seen)"
                            " VALUES(?,?,?,?,?,?,?,?,?,?)", (int(aid), p["serial"], p.get("cls") or "", p.get("name") or "", p.get("descr") or "",
                                                             p.get("model") or "", p.get("hw") or "", p.get("src") or "", now, now))

    def part_delete_serial(self, serial):
        with self._lock:
            self.db.execute("DELETE FROM asset_parts WHERE serial=?", (serial,))

    def part_refresh(self, aid, p, now):
        """توضیح قطعه‌ی موجود (نام، مدل، …) و آخرین مشاهده؛ هویت قطعه (سریال و دارایی) عوض نمی‌شود."""
        with self._lock:
            self.db.execute("UPDATE asset_parts SET cls=?, name=?, descr=?, model=?, hw=?, last_seen=? WHERE asset_id=? AND serial=?",
                            (p.get("cls") or "", p.get("name") or "", p.get("descr") or "", p.get("model") or "", p.get("hw") or "",
                             now, int(aid), p["serial"]))

    def asset_change_add(self, ch):
        with self._lock:
            cur = self.db.execute("INSERT INTO asset_changes(ts, asset_id, serial, kind, data, source, status, by_user, note)"
                                  " VALUES(?,?,?,?,?,?,?,?,?)", (time.time(), ch.get("asset_id"), ch["serial"], ch["kind"],
                                                                json.dumps(ch["data"], ensure_ascii=False), ch.get("source") or "",
                                                                "pending", ch.get("by_user") or "", ch.get("note") or ""))
            return cur.lastrowid

    def asset_change_set(self, cid, **f):
        if "data" in f:
            f["data"] = json.dumps(f["data"], ensure_ascii=False)
        f = {k: v for k, v in f.items() if k in ("ts", "data", "source", "status", "decided", "decided_by", "note", "by_user", "asset_id", "kind")}
        with self._lock:
            self.db.execute(f"UPDATE asset_changes SET {','.join(k + '=?' for k in f)} WHERE id=?", list(f.values()) + [int(cid)])  # nosec B608 — نام ستون‌ها از کد

    @staticmethod
    def _chg(r):
        d = dict(r)
        try:
            d["data"] = json.loads(d["data"] or "{}")
        except ValueError:
            d["data"] = {}
        return d

    def asset_changes(self, status=None, serial=None, limit=2000):
        q, a = "SELECT * FROM asset_changes WHERE 1=1", []
        if status:
            q += " AND status=?"
            a.append(status)
        if serial:
            q += " AND serial=?"
            a.append(serial)
        with self._lock:
            return [self._chg(r) for r in self.db.execute(q + " ORDER BY id DESC LIMIT ?", a + [int(limit)]).fetchall()]  # nosec B608 — شرط‌ها ثابت‌اند

    def asset_change(self, cid):
        with self._lock:
            r = self.db.execute("SELECT * FROM asset_changes WHERE id=?", (int(cid),)).fetchone()
            return self._chg(r) if r else None

    def asset_pending_count(self):
        with self._lock:
            return self.db.execute("SELECT COUNT(*) FROM asset_changes WHERE status='pending'").fetchone()[0]

    def asset_hist_add(self, aid, serial, field, old, new, user, source, change_id=None, ts=None):
        with self._lock:
            self.db.execute("INSERT INTO asset_history(ts, asset_id, serial, field, old, new, user, source, change_id) VALUES(?,?,?,?,?,?,?,?,?)",
                            (ts or time.time(), aid, serial, field, "" if old is None else str(old), "" if new is None else str(new),
                             user or "", source or "", change_id))

    def asset_history(self, aid=None, limit=5000):
        with self._lock:
            if aid is None:
                rows = self.db.execute("SELECT * FROM asset_history ORDER BY id DESC LIMIT ?", (int(limit),)).fetchall()
            else:
                rows = self.db.execute("SELECT * FROM asset_history WHERE asset_id=? ORDER BY id DESC LIMIT ?", (int(aid), int(limit))).fetchall()
            return [dict(r) for r in rows]

    # ------------------------------------------------------------ config backups
    def backup_add(self, row):
        with self._lock:
            cur = self.db.execute("INSERT INTO config_backups(device_id, ts, hash, size, lines, added, removed, first, file, job_id)"
                                  " VALUES(?,?,?,?,?,?,?,?,?,?)",
                                  (row["device_id"], row["ts"], row["hash"], row["size"], row["lines"], row["added"],
                                   row["removed"], row["first"], row["file"], row.get("job_id", "")))
            return cur.lastrowid

    def backups(self, device_id=None, limit=500):
        with self._lock:
            if device_id is None:
                rows = self.db.execute("SELECT * FROM config_backups ORDER BY ts DESC LIMIT ?", (limit,)).fetchall()
            else:
                rows = self.db.execute("SELECT * FROM config_backups WHERE device_id=? ORDER BY ts DESC LIMIT ?",
                                       (device_id, limit)).fetchall()
            return [dict(r) for r in rows]

    def backup(self, bid):
        with self._lock:
            r = self.db.execute("SELECT * FROM config_backups WHERE id=?", (bid,)).fetchone()
            return dict(r) if r else None

    def backup_delete(self, bid):
        with self._lock:
            self.db.execute("DELETE FROM config_backups WHERE id=?", (bid,))

    def ssh_set_backup_status(self, dev_id, status, message):
        with self._lock:
            self.db.execute("UPDATE ssh_devices SET backup_status=?, backup_at=?, backup_message=? WHERE id=?",
                            (status, time.time(), (message or "")[:300], dev_id))

    def ssh_set_backup_flag(self, ids, on):
        with self._lock:
            self.db.executemany("UPDATE ssh_devices SET backup=? WHERE id=?", [(1 if on else 0, int(i)) for i in ids])
