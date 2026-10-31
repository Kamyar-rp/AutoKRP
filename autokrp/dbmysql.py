"""پایگاه داده‌ی MySQL / MariaDB به‌جای فایل محلی state.dat.

موتور کاری برنامه همان SQLite درون حافظه می‌ماند (همه‌ی کوئری‌ها بدون تغییر)؛ MySQL محل ماندگاری است:
- هنگام باز شدن، داده از MySQL در حافظه بارگذاری می‌شود.
- هر تغییر با تریگرهای SQLite در جدول _akrp_chg ثبت و هر چند ثانیه همان ردیف‌ها در MySQL نوشته/حذف می‌شوند.
- ساختار جدول‌ها از SQLite ساخته می‌شود و با به‌روزرسانی برنامه (جدول یا ستون تازه) خودکار در MySQL اضافه می‌شود.

سه حالت ذخیره (انتخاب کاربر هنگام راه‌اندازی):
  plain — جدول‌ها و ستون‌ها خوانا (برای کوئری و گزارش‌گیری بیرونی). امنیت با TLS و دسترسی‌های خود MySQL.
  cols  — ستون‌های متنی حساس (جزئیات، متن‌ها، آدرس دستگاه‌ها، ...) با AES-GCM رمز می‌شوند؛ IP، وضعیت‌ها و زمان‌ها خوانا.
  blob  — کل پایگاه داده یک تصویر رمزشده (مثل state.dat) در جدول _akrp_blob. MySQL فقط نگه‌دارنده است.
در حالت‌های cols و blob کلید رمز همان کلید داده‌های همین نصب است؛ بدون آن (نصب دیگر، ویندوز دیگر) داده خوانا نیست.

فقط یک نصب هم‌زمان: قفل GET_LOCK روی یک اتصال جدا تا برنامه‌ی دوم با همان پایگاه داده باز نشود.
"""
import base64
import json
import logging
import re
import ssl
import time

from . import atrest, paths

log = logging.getLogger(__name__)

MODES = ("plain", "cols", "blob")
SSL_MODES = ("off", "required", "verify_ca", "verify_identity")   # مثل ssl-mode در MySQL
CHG = "_akrp_chg"                 # جدول تغییرات (فقط در SQLite)
META = "_akrp_meta"               # اطلاعات خود AutoKRP در MySQL (حالت، بررسی کلید، نسخه)
BLOB = "_akrp_blob"
SKIP_TABLES = {CHG, "sqlite_sequence"}
CHUNK = 1024 * 1024               # تکه‌های blob (زیر max_allowed_packet پیش‌فرض)
BATCH = 500
_NAME = re.compile(r"^[A-Za-z0-9_]{1,64}$")
CHECK_PLAIN = b"AutoKRP-key-check-v1"

# ستون‌های رمزشده در حالت cols (متن آزاد، مسیرها، آدرس و یوزر دستگاه‌ها). ستون‌های تازه پیش‌فرض خوانا هستند.
ENC_COLS = {
    "history": {"target", "detail", "file"},
    "runs": {"steps", "summary", "dir"},
    "processed": {"info"},
    "ips": {"signatures", "fw_detail", "error", "intel_detail", "dest_ports", "source"},   # 1.22: پورت‌های هدف و منبع هم (داده‌ی شبکه‌ی سازمان)
    "ssh_devices": {"host", "username", "notes", "backup_message"},
    "ssh_scripts": {"body"},
    "ssh_results": {"host", "message", "out_file"},
    "ssh_jobs": {"script_name"},
    "config_backups": {"file"},
    "mon_targets": {"host", "url", "notes", "snmp"},
    "mon_events": {"reason"},
    "mon_maint": {"name", "scope", "note"},
    "cred_profiles": {"notes"},
    "assets": {"notes", "descr"},
    "asset_changes": {"data", "note"},
}
ENC_PREFIX = "enc1:"


class DbError(Exception):
    """خطای قابل نمایش (فارسی)."""


def conf_path():
    return paths.data_dir() / "db.dat"


def load_conf():
    """تنظیمات MySQL از فایل رمزشده‌ی db.dat (یا None = پایگاه داده‌ی محلی)."""
    p = conf_path()
    if not p.exists():
        return None
    try:
        c = json.loads(atrest.read_bytes(p).decode("utf-8"))
    except Exception as e:
        raise DbError(f"فایل تنظیمات پایگاه داده (db.dat) خوانده نشد: {e}")
    return c if c.get("backend") == "mysql" else None


def save_conf(conf):
    atrest.write_bytes(conf_path(), json.dumps(conf, ensure_ascii=False).encode("utf-8"))


def remove_conf():
    p = conf_path()
    if p.exists():
        from . import wipe
        wipe.overwrite(p)
        p.unlink()


def clean_conf(c, old=None):
    """اعتبارسنجی ورودی رابط؛ رمز خالی = همان رمز قبلی (فقط اگر میزبان/یوزر عوض نشده باشد)."""
    c = dict(c or {})
    host = str(c.get("host") or "").strip()
    if not host or len(host) > 255 or any(ch in host for ch in " /\\@;'\"`"):
        raise DbError("آدرس سرور MySQL معتبر نیست.")
    try:
        port = int(c.get("port") or 3306)
        if not 0 < port < 65536:
            raise ValueError
    except (TypeError, ValueError):
        raise DbError("پورت معتبر نیست.")
    user = str(c.get("user") or "").strip()
    if not user or len(user) > 80:
        raise DbError("نام کاربری MySQL را وارد کنید.")
    db = str(c.get("database") or "autokrp").strip()
    if not _NAME.match(db):
        raise DbError("نام پایگاه داده فقط حروف انگلیسی، عدد و _ (حداکثر ۶۴).")
    sslm = c.get("ssl") or "off"
    if sslm not in SSL_MODES:
        raise DbError("حالت TLS نامعتبر است.")
    ca = str(c.get("ca_pem") or "").strip()
    if sslm.startswith("verify") and "BEGIN CERTIFICATE" not in ca:
        raise DbError("برای TLS با بررسی CA، گواهی CA (PEM) را وارد کنید.")
    mode = c.get("mode") or "cols"
    if mode not in MODES:
        raise DbError("حالت ذخیره نامعتبر است.")
    pw = c.get("password")
    if not pw:
        if old and old.get("host") == host and old.get("user") == user and int(old.get("port") or 0) == port:
            pw = old.get("password", "")
        else:
            raise DbError("رمز MySQL را وارد کنید.")
    return {"backend": "mysql", "host": host, "port": port, "user": user, "password": str(pw), "database": db,
            "ssl": sslm, "ca_pem": ca if sslm.startswith("verify") else "", "mode": mode}


def public_conf(c):
    if not c:
        return {"backend": "local"}
    return {k: c.get(k) for k in ("backend", "host", "port", "user", "database", "ssl", "mode")} | {"has_ca": bool(c.get("ca_pem"))}


def _q(name):
    if not _NAME.match(name):
        raise DbError(f"نام نامعتبر: {name}")
    return f"`{name}`"


def _mysql_type(sqlite_type, enc):
    t = (sqlite_type or "").upper()
    if enc:
        return "LONGTEXT"
    if "INT" in t:
        return "BIGINT"
    if any(x in t for x in ("REAL", "FLOA", "DOUB")):
        return "DOUBLE"
    if "BLOB" in t:
        return "LONGBLOB"
    return "LONGTEXT"


class MySQLBackend:
    def __init__(self, conf):
        self.conf = dict(conf)
        self.mode = self.conf.get("mode", "cols")
        self.cn = None            # اتصال داده
        self.lock_cn = None       # اتصال نگه‌دارنده‌ی قفل
        self.ok = None
        self.error = ""
        self.last_flush = 0.0
        self.pending = 0
        self._err_logged = ""
        self.lock_name = ""

    # ------------------------------------------------------------ اتصال
    def _ssl(self):
        m = self.conf.get("ssl", "off")
        if m == "off":
            return None
        if m == "required":         # رمز شده، بدون بررسی گواهی (مثل --ssl-mode=REQUIRED)
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE  # nosec B501 — انتخاب صریح کاربر («TLS بدون بررسی گواهی»)
            return ctx
        ctx = ssl.create_default_context(cadata=self.conf.get("ca_pem") or None)
        # گواهی‌های خودساخته‌ی MySQL (auto_generated) keyUsage ندارند؛ زنجیره و امضا همچنان بررسی می‌شود
        ctx.verify_flags &= ~getattr(ssl, "VERIFY_X509_STRICT", 0)
        ctx.check_hostname = m == "verify_identity"     # verify_ca: فقط CA (نام گواهی خودساخته‌ی MySQL با آدرس جور نیست)
        return ctx

    def _connect(self, with_db=True, timeout=10):
        import pymysql
        kw = dict(host=self.conf["host"], port=int(self.conf.get("port") or 3306), user=self.conf["user"],
                  password=self.conf.get("password", ""), charset="utf8mb4", autocommit=False,
                  connect_timeout=timeout, read_timeout=120, write_timeout=120)
        if with_db:
            kw["database"] = self.conf["database"]
        ctx = self._ssl()
        if ctx is not None:
            kw["ssl"] = ctx
        try:
            return pymysql.connect(**kw)
        except pymysql.err.OperationalError as e:
            code = e.args[0] if e.args else 0
            msg = {1045: "نام کاربری یا رمز MySQL درست نیست.", 1049: "پایگاه داده وجود ندارد.",
                   2003: "به سرور MySQL وصل نشد (آدرس، پورت یا فایروال را بررسی کنید).",
                   1044: "این کاربر به این پایگاه داده دسترسی ندارد."}.get(code)
            detail = str(e.args[-1] if e.args else e)
            if "SSL" in detail or "certificate" in detail.lower():
                msg = "خطای TLS: گواهی سرور MySQL تأیید نشد (CA، نام سرور یا تنظیم TLS را بررسی کنید)."
            raise DbError(f"{msg or 'اتصال به MySQL ناموفق بود'} ({detail})")
        except ssl.SSLError as e:
            raise DbError(f"خطای TLS در اتصال به MySQL: {e}")
        except Exception as e:  # noqa — هر خطای دیگر کتابخانه
            raise DbError(f"اتصال به MySQL ناموفق بود: {e}")

    def probe(self):
        """تست اتصال برای رابط: نسخه، TLS، وجود پایگاه داده و داده‌ی قبلی AutoKRP."""
        cn = self._connect(with_db=False)
        try:
            with cn.cursor() as c:
                c.execute("SELECT VERSION()")
                ver = c.fetchone()[0]
                c.execute("SHOW SESSION STATUS LIKE 'Ssl_cipher'")
                r = c.fetchone()
                cipher = r[1] if r else ""
                c.execute("SELECT SCHEMA_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME=%s", (self.conf["database"],))
                exists = bool(c.fetchone())
                info = {"version": ver, "tls": cipher or "", "db_exists": exists, "has_data": False, "mode": None, "key_ok": None}
                if exists:
                    c.execute("SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA=%s AND TABLE_NAME=%s",
                              (self.conf["database"], META))
                    if c.fetchone()[0]:
                        c.execute(f"SELECT k, v FROM {_q(self.conf['database'])}.{META}")  # nosec B608 — نام‌ها اعتبارسنجی‌شده
                        m = dict(c.fetchall())
                        info.update(has_data=True, mode=m.get("mode"), saved=m.get("saved"), version_app=m.get("app_version"))
                        info["key_ok"] = self._key_ok(m.get("key_check"))
                return info
        finally:
            cn.close()

    @staticmethod
    def _key_ok(chk):
        if not chk:
            return None
        try:
            return atrest.decrypt(base64.b64decode(chk)) == CHECK_PLAIN
        except Exception:
            return False

    def open(self):
        """اتصال، ساخت پایگاه داده در صورت نبود، گرفتن قفل تک‌نصبی. خروجی: اطلاعات _akrp_meta یا {} (خالی)."""
        db = self.conf["database"]
        cn = self._connect(with_db=False)
        try:
            with cn.cursor() as c:
                c.execute(f"CREATE DATABASE IF NOT EXISTS {_q(db)} CHARACTER SET utf8mb4 COLLATE utf8mb4_bin")
            cn.commit()
        except Exception as e:
            raise DbError(f"ساخت پایگاه داده‌ی «{db}» ناموفق بود (دسترسی CREATE لازم است): {e}")
        finally:
            cn.close()
        self.lock_cn = self._connect()
        self.lock_name = f"autokrp:{db}"[:64]
        with self.lock_cn.cursor() as c:
            c.execute("SELECT GET_LOCK(%s, 1)", (self.lock_name,))
            got = c.fetchone()[0]
        if got != 1:
            self.lock_cn.close()
            self.lock_cn = None
            raise DbError(f"پایگاه داده‌ی «{db}» الان در اختیار یک AutoKRP دیگر است؛ هم‌زمان فقط یک نصب می‌تواند از آن استفاده کند.")
        self.cn = self._connect()
        with self.cn.cursor() as c:
            c.execute(f"CREATE TABLE IF NOT EXISTS {META}(k VARCHAR(64) PRIMARY KEY, v LONGTEXT) CHARACTER SET utf8mb4")
            c.execute(f"SELECT k, v FROM {META}")  # nosec B608 — نام ثابت
            meta = dict(c.fetchall())
        self.cn.commit()
        if meta.get("mode") and meta["mode"] != self.mode:
            self.close()
            raise DbError(f"این پایگاه داده با حالت «{meta['mode']}» ساخته شده است؛ همان حالت را انتخاب کنید یا نام پایگاه داده‌ی دیگری بدهید.")
        if meta.get("mode") in ("cols", "blob") and self._key_ok(meta.get("key_check")) is False:
            self.close()
            raise DbError("داده‌های این پایگاه داده با کلید نصب دیگری رمز شده‌اند و در این سیستم خوانا نیستند.")
        self.ok, self.error = True, ""
        return meta

    def _set_meta(self, c, **kv):
        for k, v in kv.items():
            c.execute(f"REPLACE INTO {META}(k, v) VALUES(%s, %s)", (k, str(v)))  # nosec B608 — نام ثابت

    def write_meta_base(self):
        from . import __version__
        with self.cn.cursor() as c:
            self._set_meta(c, mode=self.mode, app_version=__version__,
                           key_check=base64.b64encode(atrest.encrypt(CHECK_PLAIN)).decode() if self.mode != "plain" else "")
        self.cn.commit()

    def ensure(self):
        """اتصال داده پس از قطع شدن دوباره برقرار می‌شود (و قفل اگر از دست رفته باشد)."""
        try:
            self.cn.ping(reconnect=True)
        except Exception:
            try:
                self.cn.close()
            except Exception:
                pass
            self.cn = self._connect()
        try:
            self.lock_cn.ping(reconnect=False)
        except Exception:
            try:
                self.lock_cn.close()
            except Exception:
                pass
            self.lock_cn = self._connect()
            with self.lock_cn.cursor() as c:
                c.execute("SELECT GET_LOCK(%s, 1)", (self.lock_name,))
                if c.fetchone()[0] != 1:
                    raise DbError("قفل پایگاه داده از دست رفت و نصب دیگری آن را گرفته است؛ نوشتن متوقف شد.")

    def close(self):
        for cn in (self.cn, self.lock_cn):
            if cn is not None:
                try:
                    cn.close()      # قفل GET_LOCK با بسته شدن اتصال آزاد می‌شود
                except Exception:
                    pass
        self.cn = self.lock_cn = None

    def _fail(self, e):
        self.ok, self.error = False, str(e)
        if self._err_logged != self.error:
            log.error("MySQL: %s", e)
            self._err_logged = self.error

    # ------------------------------------------------------------ رمز ستون‌ها
    def _enc_cols(self, table):
        return ENC_COLS.get(table, set()) if self.mode == "cols" else set()

    @staticmethod
    def _enc(v):
        if v is None:
            return None
        return ENC_PREFIX + base64.b64encode(atrest.encrypt(json.dumps(v, ensure_ascii=False).encode("utf-8"))).decode()

    @staticmethod
    def _dec(v):
        if isinstance(v, (bytes, bytearray)):
            v = v.decode("utf-8")
        if not isinstance(v, str) or not v.startswith(ENC_PREFIX):
            return v
        return json.loads(atrest.decrypt(base64.b64decode(v[len(ENC_PREFIX):])).decode("utf-8"))

    # ------------------------------------------------------------ حالت blob
    def load_blob(self):
        with self.cn.cursor() as c:
            c.execute(f"CREATE TABLE IF NOT EXISTS {BLOB}(n INT PRIMARY KEY, data LONGBLOB)")
            c.execute(f"SELECT data FROM {BLOB} ORDER BY n")  # nosec B608 — نام ثابت
            parts = [r[0] for r in c.fetchall()]
        self.cn.commit()
        return atrest.decrypt(b"".join(parts)) if parts else None

    def save_blob(self, image: bytes):
        data = atrest.encrypt(image)
        self.ensure()
        with self.cn.cursor() as c:
            c.execute(f"CREATE TABLE IF NOT EXISTS {BLOB}(n INT PRIMARY KEY, data LONGBLOB)")
            c.execute(f"DELETE FROM {BLOB}")  # nosec B608 — نام ثابت
            for i in range(0, max(1, len(data)), CHUNK):
                c.execute(f"INSERT INTO {BLOB}(n, data) VALUES(%s, %s)", (i // CHUNK, data[i:i + CHUNK]))  # nosec B608
            self._set_meta(c, saved=time.time())
        self.cn.commit()

    # ------------------------------------------------------------ حالت جدولی
    @staticmethod
    def sqlite_tables(db):
        return [r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
                if r[0] not in SKIP_TABLES and not r[0].startswith("sqlite_")]

    @staticmethod
    def sqlite_cols(db, t):
        return [(r[1], r[2], r[5]) for r in db.execute(f"PRAGMA table_info({_q(t)})")]   # (نام، نوع، pk)

    def mysql_tables(self):
        with self.cn.cursor() as c:
            c.execute("SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA=%s", (self.conf["database"],))
            return {r[0] for r in c.fetchall()}

    def mysql_cols(self, t):
        with self.cn.cursor() as c:
            c.execute("SELECT COLUMN_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=%s AND TABLE_NAME=%s",
                      (self.conf["database"], t))
            return {r[0] for r in c.fetchall()}

    def schema_version(self):
        """نسخه‌ی ساختار ذخیره‌شده در جدول meta همان MySQL (برای ساختن همان ساختار در حافظه پیش از بارگذاری)."""
        if "meta" not in self.mysql_tables():
            return None
        with self.cn.cursor() as c:
            c.execute("SELECT `value` FROM `meta` WHERE `key`='schema'")
            r = c.fetchone()
        v = self._dec(r[0]) if r else None
        return int(v) if v else None

    def load_tables(self, db):
        """همه‌ی ردیف‌ها از MySQL به SQLite (rowid ها حفظ می‌شوند). جدول‌های SQLite باید از قبل ساخته شده باشند."""
        have = self.mysql_tables()
        n = 0
        for t in self.sqlite_tables(db):
            if t not in have:
                continue
            cols = [c for c, _, _ in self.sqlite_cols(db, t)]
            mcols = self.mysql_cols(t)
            use = [c for c in cols if c in mcols]
            enc = self._enc_cols(t)
            db.execute(f"DELETE FROM {_q(t)}")  # nosec B608 — نام از sqlite_master
            with self.cn.cursor() as c:
                c.execute(f"SELECT `_rid`, {', '.join(_q(x) for x in use)} FROM {_q(t)}")  # nosec B608 — نام‌ها اعتبارسنجی‌شده
                while True:
                    rows = c.fetchmany(BATCH)
                    if not rows:
                        break
                    out = []
                    for r in rows:
                        vals = [self._dec(v) if use[i] in enc else v for i, v in enumerate(r[1:])]
                        out.append((r[0], *vals))
                    db.executemany(f"INSERT INTO {_q(t)}(rowid, {', '.join(_q(x) for x in use)}) VALUES({', '.join('?' * (len(use) + 1))})", out)  # nosec B608
                    n += len(out)
        self.cn.commit()
        return n

    def sync_schema(self, db):
        """جدول‌ها و ستون‌های تازه‌ی SQLite در MySQL ساخته/اضافه می‌شوند. خروجی: جدول‌هایی که تغییر کردند."""
        have = self.mysql_tables()
        changed = []
        with self.cn.cursor() as c:
            for t in self.sqlite_tables(db):
                cols = self.sqlite_cols(db, t)
                enc = self._enc_cols(t)
                if t not in have:
                    defs = ["`_rid` BIGINT NOT NULL PRIMARY KEY"] + [f"{_q(n)} {_mysql_type(ty, n in enc)} NULL" for n, ty, _ in cols]
                    pk = [n for n, ty, p in sorted(cols, key=lambda x: x[2]) if p]
                    if pk and not enc.intersection(pk):    # نمایه برای کوئری بیرونی روی کلید اصلی SQLite
                        defs.append("KEY `ix_pk` (" + ", ".join(f"{_q(x)}(191)" if _mysql_type(ty, False) == "LONGTEXT" else _q(x)
                                                           for x, ty, _ in [c2 for c2 in cols if c2[0] in pk]) + ")")
                    c.execute(f"CREATE TABLE {_q(t)}({', '.join(defs)}) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin")
                    changed.append(t)
                    continue
                mc = self.mysql_cols(t)
                for n, ty, _ in cols:
                    if n not in mc:
                        c.execute(f"ALTER TABLE {_q(t)} ADD COLUMN {_q(n)} {_mysql_type(ty, n in enc)} NULL")
                        changed.append(t)
        self.cn.commit()
        return sorted(set(changed))

    def install_triggers(self, db):
        db.execute("PRAGMA recursive_triggers = ON")   # REPLACE هم تریگر حذف را اجرا کند (ردیف قدیمی در MySQL نماند)
        db.execute(f"CREATE TABLE IF NOT EXISTS {CHG}(n INTEGER PRIMARY KEY AUTOINCREMENT, tbl TEXT, rid INTEGER)")
        for t in self.sqlite_tables(db):
            qt = _q(t)[1:-1]          # نام جدول از sqlite_master، فقط [A-Za-z0-9_] (وگرنه DbError)
            for ev, ref in (("INSERT", "NEW.rowid"), ("UPDATE", "NEW.rowid"), ("DELETE", "OLD.rowid")):
                name = _q(f"_akrp_{ev[0].lower()}_{t}"[:64])
                extra = f"INSERT INTO {CHG}(tbl, rid) VALUES('{qt}', OLD.rowid); " if ev == "UPDATE" else ""  # nosec B608 — نام اعتبارسنجی‌شده
                db.execute(f"CREATE TRIGGER IF NOT EXISTS {name} AFTER {ev} ON {_q(t)} BEGIN {extra}"  # nosec B608 — نام‌ها اعتبارسنجی‌شده
                           f"INSERT INTO {CHG}(tbl, rid) VALUES('{qt}', {ref}); END")

    def push_all(self, db, tables=None):
        """بارگذاری کامل جدول‌ها در MySQL (پایگاه داده‌ی تازه یا پس از تغییر ساختار)."""
        self.ensure()
        tables = tables or self.sqlite_tables(db)
        with self.cn.cursor() as c:
            for t in tables:
                c.execute(f"DELETE FROM {_q(t)}")  # nosec B608 — نام از sqlite_master
                cols = [x for x, _, _ in self.sqlite_cols(db, t)]
                cur = db.execute(f"SELECT rowid, * FROM {_q(t)}")  # nosec B608
                while True:
                    rows = cur.fetchmany(BATCH)
                    if not rows:
                        break
                    self._upsert(c, t, cols, rows)
            self._set_meta(c, saved=time.time())
        self.cn.commit()

    def _upsert(self, c, t, cols, rows):
        enc = self._enc_cols(t)
        names = ["_rid"] + cols
        vals = []
        for r in rows:
            r = tuple(r)
            vals.append((r[0], *[self._enc(v) if cols[i] in enc else v for i, v in enumerate(r[1:])]))
        upd = ", ".join(f"{_q(x)}=VALUES({_q(x)})" for x in cols) or "`_rid`=`_rid`"
        c.executemany(f"INSERT INTO {_q(t)}({', '.join(_q(x) for x in names)}) VALUES({', '.join(['%s'] * len(names))}) "  # nosec B608
                      f"ON DUPLICATE KEY UPDATE {upd}", vals)

    def flush_changes(self, db):
        """نوشتن تغییرات ثبت‌شده در _akrp_chg. اگر MySQL در دسترس نباشد تغییرات می‌مانند و بعداً نوشته می‌شوند."""
        top = db.execute(f"SELECT MAX(n) FROM {CHG}").fetchone()[0]  # nosec B608 — نام ثابت
        if top is None:
            return 0
        by = {}
        for t, rid in db.execute(f"SELECT DISTINCT tbl, rid FROM {CHG} WHERE n <= ?", (top,)):  # nosec B608
            by.setdefault(t, set()).add(rid)
        self.ensure()
        n = 0
        with self.cn.cursor() as c:
            for t, rids in by.items():
                cols = [x for x, _, _ in self.sqlite_cols(db, t)]
                if not cols:
                    continue
                ids = sorted(rids)
                for i in range(0, len(ids), BATCH):
                    part = ids[i:i + BATCH]
                    rows = db.execute(f"SELECT rowid, * FROM {_q(t)} WHERE rowid IN ({','.join('?' * len(part))})", part).fetchall()  # nosec B608
                    found = {r[0] for r in rows}
                    if rows:
                        self._upsert(c, t, cols, rows)
                    gone = [x for x in part if x not in found]
                    if gone:
                        c.execute(f"DELETE FROM {_q(t)} WHERE `_rid` IN ({','.join(['%s'] * len(gone))})", gone)  # nosec B608
                    n += len(part)
            self._set_meta(c, saved=time.time())
        self.cn.commit()
        db.execute(f"DELETE FROM {CHG} WHERE n <= ?", (top,))  # nosec B608 — فقط تغییرهایی که نوشته شدند
        return n

    def drop_all(self):
        """RESET: فقط جدول‌های AutoKRP (ستون _rid، یا _akrp_meta/_akrp_blob) حذف می‌شوند؛ جدول‌های دیگرِ همین پایگاه داده و خودش می‌مانند."""
        self.ensure()
        with self.cn.cursor() as c:
            c.execute("SELECT DISTINCT TABLE_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=%s AND COLUMN_NAME='_rid'",
                      (self.conf["database"],))
            names = {r[0] for r in c.fetchall()} | ({META, BLOB, "akrp_ts_d", "akrp_ts_h", "akrp_ev"} & self.mysql_tables())   # 1.34: سری زمانی مانیتورینگ
            for t in sorted(names):
                if _NAME.match(t):
                    c.execute(f"DROP TABLE IF EXISTS {_q(t)}")
        self.cn.commit()
        return len(names)
