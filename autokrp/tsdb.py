"""
ذخیره‌ی سری زمانی مانیتورینگ (1.34): فایل محلی (روش قبلی) یا جدول‌های جدای MySQL/MariaDB.

نوع رکوردها:
  sd — SNMP دقیق (هر ۱ یا ۵ دقیقه، برای هر هدف)      sh — SNMP ساعتی (برای هر هدف)
  pm — Ping/TCP/HTTP دقیقه‌ای (همه‌ی هدف‌ها در یک رکورد)  ph — Ping/TCP/HTTP ساعتی                         ev — رخداد Trap/Syslog (1.35؛ monitor/events/e_*.log یا جدول akrp_ev)
هر رکورد یک dict با کلید «t» (شروع بازه) است.

فایل: همان قالب نسخه‌های قبل (monitor/m_*.log، monitor/h_*.log، monitor/snmp/<id>/f_*.log و h_*.log)، رمزشده.
MySQL: جدول akrp_ts_d (دقیق و دقیقه‌ای) و akrp_ts_h (ساعتی) با اتصال جدا (نه از مسیر همگام‌سازی پایگاه داده‌ی برنامه).
  - اگر سرور اجازه بدهد، پارتیشن RANGE روی زمان (روزانه / ماهانه)؛ پاک کردن داده‌ی قدیمی با DROP PARTITION.
  - قالب ستون d تابع حالت پایگاه داده: plain = JSON خوانا؛ cols و blob = فشرده و رمزشده با کلید همین نصب.
  - نوشتن در صف و دسته‌ای؛ اگر MySQL در دسترس نباشد رکوردها در فایل محلی نوشته می‌شوند و بعداً منتقل می‌شوند.
  - خواندن همیشه از هر دو (فایل‌های محلی باقی‌مانده + MySQL)، پس جابه‌جایی محل ذخیره چیزی را پنهان نمی‌کند.
"""
import base64
import json
import logging
import os
import queue
import secrets
import shutil
import threading
import time
import zlib
from datetime import datetime, timezone

from . import atrest, paths

log = logging.getLogger(__name__)

KINDS = ("sd", "sh", "pm", "ph", "ev")      # ev = رخداد Trap/Syslog (1.35)
ZPFX = "AKRZ:"
TABLE = {"sd": "akrp_ts_d", "pm": "akrp_ts_d", "sh": "akrp_ts_h", "ph": "akrp_ts_h", "ev": "akrp_ev"}
EV_K = {"trap": 1, "syslog": 2}
EV_SEV = {"crit": 1, "warn": 2, "info": 3, "ok": 4}
KCODE = {"sd": 1, "sh": 1, "pm": 2, "ph": 2}
DAY, MONTH = 86400, "month"
FUTURE_DAYS, FUTURE_MONTHS = 3, 2
BATCH = 500
DEL_BATCH = 5000
QUEUE_MAX = 200000


def zenc(obj):
    raw = zlib.compress(json.dumps(obj, separators=(",", ":")).encode("utf-8"), 6)
    return ZPFX + base64.b64encode(atrest.encrypt(raw)).decode("ascii")


def zdec(line):
    return json.loads(zlib.decompress(atrest.decrypt(base64.b64decode(line[len(ZPFX):]))))


def _day(ts):
    return time.strftime("%Y%m%d", time.localtime(ts))


def _month(ts):
    return time.strftime("%Y%m", time.localtime(ts))


def _days(since, until, fmt):
    out, t = [], since
    while t <= until + 86400:
        x = time.strftime(fmt, time.localtime(t))
        if not out or out[-1] != x:
            out.append(x)
        t += 86400 if fmt == "%Y%m%d" else 86400 * 27
    last = time.strftime(fmt, time.localtime(until))
    if last not in out:
        out.append(last)
    return out


# ============================================================================ فایل محلی
class FileTS:
    name = "file"

    def base(self):
        d = paths.data_dir() / "monitor"
        d.mkdir(exist_ok=True)
        return d

    def _tdir(self, tid, make=True):
        d = self.base() / "snmp" / str(int(tid))
        if make:
            d.mkdir(parents=True, exist_ok=True)
        return d

    def path(self, kind, tid, t):
        if kind == "sd":
            return self._tdir(tid) / f"f_{_day(t)}.log"
        if kind == "sh":
            return self._tdir(tid) / f"h_{_month(t)}.log"
        if kind == "pm":
            return self.base() / f"m_{_day(t)}.log"
        if kind == "ev":
            d = self.base() / "events"
            d.mkdir(exist_ok=True)
            return d / f"e_{_day(t)}.log"
        return self.base() / f"h_{_month(t)}.log"

    @staticmethod
    def encode(kind, rec):
        if kind in ("sd", "sh"):
            return zenc(rec)
        return atrest._enc_line(json.dumps(rec, separators=(",", ":"), ensure_ascii=kind != "ev"))

    def put(self, items):
        groups = {}
        for kind, tid, rec in items:
            groups.setdefault(self.path(kind, tid, rec["t"]), []).append(self.encode(kind, rec))
        for p, lines in groups.items():
            enc = "ascii" if p.parent.name.isdigit() else "utf-8"
            with open(p, "a", encoding=enc) as f:
                f.write("\n".join(lines) + "\n")

    @staticmethod
    def read_file(kind, p):
        out = []
        try:
            if kind in ("sd", "sh"):
                text = p.read_text(encoding="ascii", errors="ignore")
                for line in text.splitlines():
                    if line.startswith(ZPFX):
                        try:
                            out.append(zdec(line))
                        except Exception:  # noqa — خط خراب (قطع برق وسط نوشتن)
                            continue
            else:
                for line in atrest.read_log_lines(p):
                    try:
                        out.append(json.loads(line))
                    except ValueError:
                        continue
        except OSError:
            pass
        return out

    def get(self, kind, tid, since, until):
        if kind in ("sd", "pm"):
            names = _days(since, until, "%Y%m%d")
        else:
            names = _days(since - 3600, until, "%Y%m")
        d = self._tdir(tid, make=False) if kind in ("sd", "sh") else self.base()
        pfx = {"sd": "f_", "sh": "h_", "pm": "m_", "ph": "h_"}[kind]
        out = []
        for n in names:
            for p in (d / f"{pfx}{n}.log", d / f"{pfx}{n}.log.mig"):
                if p.exists():
                    out += [r for r in self.read_file(kind, p) if since <= r.get("t", 0) <= until]
        return out

    def has_day(self, tid, day):
        return (self._tdir(tid, make=False) / f"f_{day}.log").exists()

    def files(self):
        """[(kind, tid, path)] همه‌ی فایل‌ها (برای انتقال و حجم)."""
        b = self.base()
        out = [("pm", 0, f) for f in b.glob("m_*.log")] + [("ph", 0, f) for f in b.glob("h_*.log")]
        sd = b / "snmp"
        if sd.exists():
            for d in sd.iterdir():
                if d.is_dir() and d.name.isdigit():
                    out += [("sd", int(d.name), f) for f in d.glob("f_*.log")] + [("sh", int(d.name), f) for f in d.glob("h_*.log")]
        ev = b / "events"
        if ev.exists():
            out += [("ev", 0, f) for f in ev.glob("e_*.log")]
        return out

    def ev_days(self, since, until):
        """فایل‌های روزانه‌ی رخداد این بازه، جدیدترین روز اول."""
        d = self.base() / "events"
        out = []
        for n in reversed(_days(since, until, "%Y%m%d")):
            for p in (d / f"e_{n}.log", d / f"e_{n}.log.mig"):
                if p.exists():
                    out.append(p)
        return out

    @staticmethod
    def period_end(kind, p):
        """پایان بازه‌ی زمانی یک فایل (برای پاک کردن)."""
        stem = p.name.split(".")[0][2:]
        try:
            if kind in ("sd", "pm", "ev"):
                return datetime.strptime(stem, "%Y%m%d").timestamp() + 86400
            m = datetime.strptime(stem, "%Y%m")
            nxt = datetime(m.year + (m.month == 12), m.month % 12 + 1, 1)
            return nxt.timestamp()
        except ValueError:
            return None

    def purge(self, kind, before, tid=None):
        for k, t, p in self.files():
            if k != kind or (tid is not None and t != tid):
                continue
            end = self.period_end(k, p)
            if end is not None and end <= before:
                try:
                    p.unlink()
                except OSError:
                    continue

    def drop(self, tid):
        shutil.rmtree(self.base() / "snmp" / str(int(tid)), ignore_errors=True)

    def drop_missing(self, alive):
        sd = self.base() / "snmp"
        if not sd.exists():
            return
        for d in sd.iterdir():
            if d.is_dir() and (not d.name.isdigit() or int(d.name) not in alive):
                shutil.rmtree(d, ignore_errors=True)

    def sizes(self):
        """{kind: {tid: bytes}} و حجم روز کامل قبل."""
        out = {k: {} for k in KINDS}
        y = _day(time.time() - 86400)
        day = {"sd": 0, "pm": 0, "ev": 0}
        days_pm, names = 0, []
        for k, tid, p in self.files():
            try:
                sz = p.stat().st_size
            except OSError:
                continue
            out[k][tid] = out[k].get(tid, 0) + sz
            stem = p.name.split(".")[0][2:]
            if k in day and stem == y:
                day[k] += sz
            if k == "pm":
                days_pm += 1
            if k in ("pm", "ph"):
                names.append(stem)
        return {"by": out, "day": day, "days_pm": days_pm, "oldest": min(names) if names else None}


# ============================================================================ MySQL / MariaDB
class MySqlTS:
    name = "mysql"

    def __init__(self, conf, spill=None, create=True):
        from .dbmysql import MySQLBackend
        self.conf = dict(conf)
        self.create = create          # False: فقط خواندن داده‌ی موجود (محل نوشتن فایل است)؛ جدول ساخته نمی‌شود
        self.absent = False
        self.missing = set()          # جدول‌هایی که (در حالت فقط‌خواندنی) وجود ندارند
        self.down_until = 0.0         # پس از خطای اتصال، خواندن‌ها ۳۰ ثانیه منتظر MySQL نمی‌مانند (رابط کند نشود)
        self.mode = self.conf.get("mode", "cols")
        self._be = MySQLBackend(self.conf)
        self.spill = spill or FileTS()
        self.cn = None
        self._lock = threading.RLock()
        self.q = queue.Queue(QUEUE_MAX)
        self.error = ""
        self.partitioned = {}
        self.ready = False
        self.written = 0
        self.spilled = 0
        self._stop = threading.Event()
        self._sizes = (0, None)
        self._thr = threading.Thread(target=self._writer, name="tsdb-mysql", daemon=True)
        self._thr.start()

    # ---- اتصال
    def _conn(self):
        if self.cn is None:
            self.cn = self._be._connect()
            self.cn.autocommit(True)
            if not self.ready:
                self._ensure()
        return self.cn

    def _drop_conn(self):
        try:
            if self.cn is not None:
                self.cn.close()
        except Exception:  # noqa
            pass
        self.cn = None

    def _run(self, fn):
        """یک کار با یک بار تلاش دوباره (اتصال قطع‌شده)."""
        with self._lock:
            for attempt in (0, 1):
                try:
                    r = fn(self._conn())
                    self.error = ""
                    return r
                except Exception as e:  # noqa — هر خطای اتصال/کوئری
                    self._drop_conn()
                    if attempt:
                        self.error = str(e)[:300]
                        self.down_until = time.time() + 30
                        raise
        return None

    # ---- ساختار
    @staticmethod
    def _bound(name):
        """مرز بالای پارتیشن pYYYYMMDD / pYYYYMM (ثانیه‌ی یونیکس UTC)."""
        s = name[1:]
        if len(s) == 8:
            return int(datetime.strptime(s, "%Y%m%d").replace(tzinfo=timezone.utc).timestamp()) + DAY
        m = datetime.strptime(s, "%Y%m")
        return int(datetime(m.year + (m.month == 12), m.month % 12 + 1, 1, tzinfo=timezone.utc).timestamp())

    @staticmethod
    def _pname(ts, monthly):
        d = datetime.fromtimestamp(ts, timezone.utc)
        return d.strftime("p%Y%m" if monthly else "p%Y%m%d")

    def _ensure(self):
        c = self.cn.cursor()
        now = int(time.time())
        for table, monthly in (("akrp_ts_d", False), ("akrp_ts_h", True), ("akrp_ev", False)):
            c.execute("SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=%s", (table,))
            exists = c.fetchone()[0]
            if not exists and not self.create:
                self.missing.add(table)
                self.absent = len(self.missing) == 3
                continue
            if not exists:
                cols = ("(k TINYINT UNSIGNED NOT NULL, tid INT UNSIGNED NOT NULL, t INT UNSIGNED NOT NULL, h INT UNSIGNED NOT NULL,"
                        " d MEDIUMTEXT NOT NULL, PRIMARY KEY (k, tid, t, h)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4")
                if table == "akrp_ev":      # رخدادها: فیلتر نوع/سطح/هدف/منبع در SQL؛ متن کامل در d (تابع حالت)
                    cols = ("(t INT UNSIGNED NOT NULL, h INT UNSIGNED NOT NULL, k TINYINT UNSIGNED NOT NULL, sev TINYINT UNSIGNED NOT NULL,"
                            " tid INT UNSIGNED NULL, src VARCHAR(64) NOT NULL DEFAULT '', d MEDIUMTEXT NOT NULL,"
                            " PRIMARY KEY (t, h), KEY ix_tid (tid, t), KEY ix_src (src, t)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4")
                first = self._pname(now, monthly)
                part = (f" PARTITION BY RANGE (t) (PARTITION pold VALUES LESS THAN ({self._bound(first) - (0 if monthly else DAY)}),"
                        f" PARTITION pmax VALUES LESS THAN MAXVALUE)")
                if monthly:   # pold = پیش از ماه جاری
                    m = datetime.fromtimestamp(now, timezone.utc)
                    start = int(datetime(m.year, m.month, 1, tzinfo=timezone.utc).timestamp())
                    part = f" PARTITION BY RANGE (t) (PARTITION pold VALUES LESS THAN ({start}), PARTITION pmax VALUES LESS THAN MAXVALUE)"
                try:
                    c.execute(f"CREATE TABLE {table} {cols}{part}")  # nosec B608 — نام و ساختار ثابت در کد
                except Exception as e:  # noqa — سرور بدون پشتیبانی/اجازه‌ی پارتیشن: جدول ساده، پاک کردن با DELETE
                    log.warning("tsdb: partitioning unavailable (%s), plain table", e)
                    c.execute(f"CREATE TABLE IF NOT EXISTS {table} {cols}")  # nosec B608
            c.execute("SELECT PARTITION_NAME FROM information_schema.PARTITIONS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=%s"
                      " AND PARTITION_NAME IS NOT NULL", (table,))
            self.partitioned[table] = sorted(r[0] for r in c.fetchall())
        self.ready = True
        self._maintain(c)

    def _maintain(self, c=None):
        """پارتیشن‌های امروز و چند روز/ماه آینده ساخته شوند (از pmax جدا می‌شوند)."""
        c = c or self.cn.cursor()
        now = int(time.time())
        for table, monthly in (("akrp_ts_d", False), ("akrp_ts_h", True), ("akrp_ev", False)):
            have = self.partitioned.get(table) or []
            if "pmax" not in have:
                continue
            want = []
            for i in range(FUTURE_MONTHS + 1 if monthly else FUTURE_DAYS + 1):
                ts = now + i * (31 * DAY if monthly else DAY)
                n = self._pname(ts, monthly)
                if n not in have and n not in want:
                    want.append(n)
            last = max([self._bound(p) for p in have if p not in ("pold", "pmax")] or [0])
            want = [n for n in want if self._bound(n) > last]
            if not want:
                continue
            parts = ", ".join(f"PARTITION {n} VALUES LESS THAN ({self._bound(n)})" for n in want)
            c.execute(f"ALTER TABLE {table} REORGANIZE PARTITION pmax INTO ({parts}, PARTITION pmax VALUES LESS THAN MAXVALUE)")  # nosec B608 — نام‌ها از تاریخ
            self.partitioned[table] = sorted(have + want)

    def maintain(self):
        try:
            self._run(lambda cn: self._maintain(cn.cursor()))
        except Exception as e:  # noqa
            log.warning("tsdb maintain: %s", e)

    # ---- قالب
    def encode(self, rec):
        if self.mode == "plain":
            return json.dumps(rec, separators=(",", ":"), ensure_ascii=False)
        return zenc(rec)

    @staticmethod
    def decode(d):
        if d.startswith(ZPFX):
            return zdec(d)
        return json.loads(d)

    # ---- نوشتن (صف + نخ نویسنده)
    def put(self, items):
        for it in items:
            try:
                self.q.put_nowait(it)
            except queue.Full:
                self.spill.put([it])          # صف پر (MySQL کند/قطع): فایل محلی
                self.spilled += 1

    def _writer(self):
        while not self._stop.is_set():
            batch = []
            try:
                batch.append(self.q.get(timeout=1.0))
            except queue.Empty:
                continue
            t0 = time.time()
            while len(batch) < BATCH * 4 and time.time() - t0 < 1.0:
                try:
                    batch.append(self.q.get(timeout=0.2))
                except queue.Empty:
                    break
            try:
                self._write(batch)
            finally:
                for _ in batch:
                    self.q.task_done()

    def _write(self, batch, spill=True):
        rows = {"akrp_ts_d": [], "akrp_ts_h": [], "akrp_ev": []}
        for kind, tid, rec in batch:
            if kind == "ev":
                rows["akrp_ev"].append((int(rec["t"]), secrets.randbelow(2 ** 31), EV_K.get(rec.get("k"), 0), EV_SEV.get(rec.get("sev"), 3),
                                        rec.get("tid"), "" if self.mode == "blob" else str(rec.get("src") or "")[:64], self.encode(rec)))   # حالت «رمز کامل»: منبع هم فقط در متن رمزشده
                continue
            rows[TABLE[kind]].append((KCODE[kind], int(tid), int(rec["t"]), secrets.randbelow(2 ** 31), self.encode(rec)))

        def go(cn):
            c = cn.cursor()
            cn.begin()                    # همه یا هیچ (تلاش دوباره ردیف تکراری نمی‌سازد)
            try:
                for table, rs in rows.items():
                    sql = ("INSERT INTO akrp_ev (t, h, k, sev, tid, src, d) VALUES (%s, %s, %s, %s, %s, %s, %s)" if table == "akrp_ev"
                           else f"INSERT INTO {table} (k, tid, t, h, d) VALUES (%s, %s, %s, %s, %s)")  # nosec B608 — نام جدول ثابت
                    for i in range(0, len(rs), BATCH):
                        c.executemany(sql, rs[i:i + BATCH])
                cn.commit()
            except Exception:
                try:
                    cn.rollback()
                except Exception:  # noqa
                    pass
                raise
        try:
            self._run(go)
            self.written += len(batch)
        except Exception as e:  # noqa — MySQL در دسترس نیست: فایل محلی (بعداً منتقل می‌شود)
            if not spill:
                raise
            log.warning("tsdb write failed, spilling %d records: %s", len(batch), e)
            try:
                self.spill.put(batch)
                self.spilled += len(batch)
            except Exception:
                log.exception("tsdb spill")

    def flush(self, timeout=15):
        """منتظر نوشته شدن همه‌ی صف (توقف برنامه، تست‌ها)."""
        t0 = time.time()
        while self.q.unfinished_tasks and time.time() - t0 < timeout and self._thr.is_alive():
            time.sleep(0.05)
        rest = []
        while True:
            try:
                rest.append(self.q.get_nowait())
            except queue.Empty:
                break
        if rest:
            try:
                self._write(rest)
            finally:
                for _ in rest:
                    self.q.task_done()

    def close(self):
        self.flush()
        self._stop.set()
        with self._lock:
            self._drop_conn()

    def _skip(self):
        if time.time() < self.down_until:
            return True
        if not self.ready and not self.create:
            try:
                self._run(lambda cn: None)
            except Exception:  # noqa
                return True
        return self.absent

    # ---- خواندن
    def get(self, kind, tid, since, until):
        if self._skip() or TABLE[kind] in self.missing:
            return []

        def go(cn):
            c = cn.cursor()
            c.execute(f"SELECT d FROM {TABLE[kind]} WHERE k=%s AND tid=%s AND t BETWEEN %s AND %s ORDER BY t",  # nosec B608
                      (KCODE[kind], int(tid), int(since), int(until)))
            return [r[0] for r in c.fetchall()]
        out = []
        for d in self._run(go) or []:
            try:
                out.append(self.decode(d))
            except Exception:  # noqa — ردیف خراب/کلید دیگر
                continue
        return out

    def ev_iter(self, since, until, kinds=None, tids=None, src=None, page=2000):
        """رخدادها جدیدترین اول، صفحه‌به‌صفحه (keyset روی t و h؛ حافظه‌ی محدود). فیلتر نوع/هدف/منبع در SQL."""
        if self._skip() or "akrp_ev" in self.missing or (tids is not None and not tids):
            return
        where, args = ["t BETWEEN %s AND %s"], [int(since), int(until) + 1]
        if kinds:
            ks = [EV_K[k] for k in kinds if k in EV_K]
            if not ks:
                return
            where.append("k IN (" + ",".join(["%s"] * len(ks)) + ")")
            args += ks
        if tids is not None:
            ts = [int(x) for x in list(tids)[:5000]]
            where.append("tid IN (" + ",".join(["%s"] * len(ts)) + ")")
            args += ts
        if src and self.mode != "blob":        # در حالت blob منبع را devevents بعد از رمزگشایی فیلتر می‌کند
            where.append("src=%s")
            args.append(str(src)[:64])
        last = None
        while True:
            w, a = list(where), list(args)
            if last:
                w.append("(t < %s OR (t = %s AND h < %s))")
                a += [last[0], last[0], last[1]]

            def go(cn, w=w, a=a):
                c = cn.cursor()
                c.execute("SELECT t, h, d FROM akrp_ev WHERE " + " AND ".join(w) + " ORDER BY t DESC, h DESC LIMIT %s",  # nosec B608 — فقط نگه‌دارنده‌ها
                          (*a, int(page)))
                return c.fetchall()
            rows = self._run(go) or []
            for t, h, d in rows:
                try:
                    yield self.decode(d)
                except Exception:  # noqa
                    continue
            if len(rows) < page:
                return
            last = (rows[-1][0], rows[-1][1])

    # ---- پاک کردن
    def drop_before(self, table, before):
        """پارتیشن‌هایی که کامل پیش از before هستند حذف می‌شوند (همه‌ی هدف‌ها). خروجی: تعداد."""
        have = self.partitioned.get(table) or []
        old = [p for p in have if p not in ("pmax", "pold") and self._bound(p) <= before]
        if not old:
            return 0

        def go(cn):
            cn.cursor().execute(f"ALTER TABLE {table} DROP PARTITION {', '.join(old)}")  # nosec B608 — نام‌ها از information_schema
        self._run(go)
        self.partitioned[table] = [p for p in have if p not in old]
        return len(old)

    def purge(self, kind, before, tid=None):
        """DELETE دسته‌ای (هر بار حداکثر DEL_BATCH ردیف تا قفل طولانی نشود)."""
        if self._skip() or TABLE[kind] in self.missing:
            return
        if kind == "ev":
            sql, args = "DELETE FROM akrp_ev WHERE t < %s LIMIT %s", (int(before), DEL_BATCH)
        else:
            sql = f"DELETE FROM {TABLE[kind]} WHERE k=%s" + (" AND tid=%s" if tid is not None else "") + " AND t < %s LIMIT %s"  # nosec B608
            args = (KCODE[kind],) + ((int(tid),) if tid is not None else ()) + (int(before), DEL_BATCH)
        for _ in range(2000):
            n = self._run(lambda cn: cn.cursor().execute(sql, args))
            if not n or n < DEL_BATCH:
                break

    def drop(self, tid):
        for kind in ("sd", "sh"):
            self.purge(kind, 2 ** 32 - 1, tid)

    def drop_missing(self, alive):
        if self._skip() or "akrp_ts_h" in self.missing:
            return

        def go(cn):
            c = cn.cursor()
            c.execute("SELECT DISTINCT tid FROM akrp_ts_h WHERE k=1")
            return [r[0] for r in c.fetchall()]
        try:
            for tid in self._run(go) or []:
                if tid not in alive:
                    self.drop(tid)
        except Exception as e:  # noqa
            log.warning("tsdb drop_missing: %s", e)

    def sizes(self, max_age=600):
        """حجم داده (بایت) به تفکیک نوع و هدف؛ ۱۰ دقیقه کش (روی جدول بزرگ کوئری سنگینی است)."""
        if self._sizes[1] is not None and time.time() - self._sizes[0] < max_age:
            return self._sizes[1]
        if self._skip():
            return {"by": {k: {} for k in KINDS}, "day": {"sd": 0, "pm": 0, "ev": 0}, "days_pm": 0, "oldest": None}

        def go(cn):
            c = cn.cursor()
            out = {k: {} for k in KINDS}
            for table, kinds in (("akrp_ts_d", {1: "sd", 2: "pm"}), ("akrp_ts_h", {1: "sh", 2: "ph"})):
                if table in self.missing:
                    continue
                c.execute(f"SELECT k, tid, SUM(LENGTH(d)) + COUNT(*) * 24 FROM {table} GROUP BY k, tid")  # nosec B608
                for k, tid, n in c.fetchall():
                    if k in kinds:
                        out[kinds[k]][int(tid)] = int(n or 0)
            y0 = int(time.time() // DAY - 1) * DAY
            day = {"sd": 0, "pm": 0, "ev": 0}
            if "akrp_ts_d" not in self.missing:
                c.execute("SELECT k, SUM(LENGTH(d)) + COUNT(*) * 24 FROM akrp_ts_d WHERE t >= %s AND t < %s GROUP BY k", (y0, y0 + DAY))
                for k, n in c.fetchall():
                    day["sd" if k == 1 else "pm"] = int(n or 0)
            try:
                c.execute("SELECT SUM(LENGTH(d)) + COUNT(*) * 40 FROM akrp_ev")
                out["ev"][0] = int(c.fetchone()[0] or 0)
            except Exception:  # noqa — جدول هنوز ساخته نشده (نصب فقط‌خواندنی)
                pass
            mn = None
            if "akrp_ts_h" not in self.missing:
                c.execute("SELECT MIN(t) FROM akrp_ts_h")
                mn = c.fetchone()[0]
            return {"by": out, "day": day, "days_pm": 0, "oldest": _month(mn) if mn else None}
        r = self._run(go)
        self._sizes = (time.time(), r)
        return r

    def status(self):
        return {"backend": "mysql", "mode": self.mode, "error": self.error, "queue": self.q.qsize(), "written": self.written,
                "spilled": self.spilled, "partitioned": {k: len(v) > 0 for k, v in self.partitioned.items()}}


# ============================================================================ دسترسی یکپارچه
class Store:
    """نوشتن در محل انتخاب‌شده؛ خواندن و پاک کردن از هر دو."""

    def __init__(self):
        self.files = FileTS()
        self.mysql = None
        self.target = "file"
        self.mig = {"running": False, "done": 0, "files": 0, "error": "", "at": None}
        self._mig_lock = threading.Lock()

    def configure(self, target, conf):
        """target: «file» یا «mysql»؛ conf: تنظیمات MySQL برنامه (None = پایگاه داده‌ی محلی).
        با پایگاه داده‌ی MySQL و محل «file»، داده‌ی قبلی MySQL (اگر جدولش هست) همچنان خوانده می‌شود."""
        want = "mysql" if target == "mysql" and conf else "file"
        create = want == "mysql"
        if not conf:
            if self.mysql is not None:
                self.mysql.close()
            self.mysql = None
        elif self.mysql is None or self.mysql.conf != dict(conf) or (create and not self.mysql.create):
            if self.mysql is not None:
                self.mysql.close()
            self.mysql = MySqlTS(conf, spill=self.files, create=create)
        self.target = want

    def writer(self):
        return self.mysql if self.target == "mysql" and self.mysql else self.files

    def readers(self):
        out = [self.files]
        if self.mysql is not None:
            out.append(self.mysql)
        return out

    def put(self, items):
        if items:
            self.writer().put(items)

    def get(self, kind, tid, since, until):
        out = []
        for r in self.readers():
            try:
                out += r.get(kind, tid, since, until)
            except Exception as e:  # noqa — MySQL قطع: داده‌ی فایل‌ها نمایش داده شود
                log.warning("tsdb read %s: %s", r.name, e)
        return out

    def purge(self, kind, before, tid=None):
        for r in self.readers():
            try:
                r.purge(kind, before, tid)
            except Exception as e:  # noqa
                log.warning("tsdb purge %s: %s", r.name, e)

    def drop(self, tid):
        for r in self.readers():
            try:
                r.drop(tid)
            except Exception as e:  # noqa
                log.warning("tsdb drop %s: %s", r.name, e)

    def drop_missing(self, alive):
        for r in self.readers():
            r.drop_missing(alive)

    def ev_mysql(self, *a, **k):
        """رخدادهای MySQL (اگر هست)، جدیدترین اول؛ فایل‌ها را devevents خودش خط‌به‌خط می‌خواند."""
        if self.mysql is None:
            return
        try:
            yield from self.mysql.ev_iter(*a, **k)
        except Exception as e:  # noqa
            log.warning("tsdb events read: %s", e)

    def sizes(self):
        tot = self.files.sizes()
        if self.mysql is not None:
            try:
                m = self.mysql.sizes()
                for k in KINDS:
                    for tid, n in m["by"][k].items():
                        tot["by"][k][tid] = tot["by"][k].get(tid, 0) + n
                for k in ("sd", "pm", "ev"):
                    tot["day"][k] += m["day"].get(k, 0)
                if m["oldest"] and (not tot["oldest"] or m["oldest"] < tot["oldest"]):
                    tot["oldest"] = m["oldest"]
            except Exception as e:  # noqa
                log.warning("tsdb sizes: %s", e)
        return tot

    def flush(self):
        if self.mysql is not None:
            self.mysql.flush()

    def maintain(self):
        if self.mysql is not None:
            self.mysql.maintain()

    def status(self):
        out = {"target": self.target, "mysql": self.mysql.status() if self.mysql else None, "migrate": dict(self.mig)}
        out["local_files"] = len(self.files.files()) if self.target == "mysql" else None
        return out

    # ---- انتقال فایل‌های محلی به MySQL (داده‌ی قبلی و رکوردهای نوشته‌شده هنگام قطعی)
    def migrate(self, stop=None, min_age=120):
        """هر فایل: تغییر نام به .mig، خواندن، نوشتن در MySQL، حذف. فایلی که همین حالا نوشته می‌شود (کمتر از min_age ثانیه) بعداً."""
        if self.target != "mysql" or self.mysql is None or not self._mig_lock.acquire(blocking=False):
            return
        try:
            self.mig.update(running=True, error="")
            todo = [x for x in self.files.files()]
            b = self.files.base()
            todo += [(("sd" if p.name.startswith("f_") else "sh"), int(p.parent.name), p)
                     for p in (b / "snmp").glob("*/*.log.mig")] if (b / "snmp").exists() else []
            todo += [(("pm" if p.name.startswith("m_") else "ph"), 0, p) for p in b.glob("*.log.mig")]
            todo += [("ev", 0, p) for p in (b / "events").glob("*.log.mig")] if (b / "events").exists() else []
            self.mig["files"] = len(todo)
            now = time.time()
            for kind, tid, p in todo:
                if stop is not None and stop.is_set():
                    break
                try:
                    if not p.name.endswith(".mig"):
                        if now - p.stat().st_mtime < min_age:
                            continue
                        q = p.with_name(p.name + ".mig")
                        os.replace(p, q)
                        p = q
                    recs = self.files.read_file(kind, p)
                    self.mysql._write([(kind, tid, r) for r in recs if "t" in r], spill=False)
                    p.unlink()
                    self.mig["done"] += 1
                except OSError as e:         # فایل همین حالا باز است: دفعه‌ی بعد
                    self.mig["error"] = str(e)[:200]
                except Exception as e:  # noqa — MySQL قطع شد: فایل .mig می‌ماند و دفعه‌ی بعد منتقل می‌شود
                    self.mig["error"] = str(e)[:200]
                    break
            self.mig["at"] = time.time()
        finally:
            self.mig["running"] = False
            self._mig_lock.release()


STORE = None


def store():
    global STORE
    if STORE is None:
        STORE = Store()
    return STORE
