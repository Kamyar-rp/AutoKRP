"""PostgreSQL (16 یا بالاتر) به‌جای فایل محلی — هم‌ارز dbmysql.MySQLBackend (1.53).

همان معماری MySQL: موتور کاری SQLite درون حافظه؛ PostgreSQL محل ماندگاری (بارگذاری هنگام باز شدن، نوشتن تغییرات
ثبت‌شده با تریگرهای SQLite هر چند ثانیه). همان سه حالت plain / cols / blob و همان ستون‌های رمزشده (dbmysql.ENC_COLS).

درایور: pg8000 (تمام پایتونی، BSD). قفل تک‌نصبی: pg_try_advisory_lock روی یک اتصال جدا.
تفاوت‌ها با MySQL:
- پایگاه داده اگر نباشد با CREATE DATABASE (نیاز به CREATEDB) ساخته می‌شود؛ جدول‌ها در schema جاری (معمولاً public).
- نوع ستون‌ها سخت‌گیرتر است؛ مقدار پیش از ارسال به نوع ستون تبدیل می‌شود (مثل رفتار MySQL؛ NUL در متن جایگزین می‌شود).
- TLS: off = اگر سرور TLS دارد رمزشده ولی بدون بررسی گواهی، وگرنه ساده (رفتار پیش‌فرض pg8000)؛ required = اجباری؛
  verify_ca / verify_identity = با گواهی CA (و نام سرور).
"""
import base64
import hashlib
import logging
import re
import ssl
import time

from . import atrest
from .dbmysql import BATCH, BLOB, CHECK_PLAIN, CHG, CHUNK, META, DbError, MySQLBackend

log = logging.getLogger(__name__)

_NAME = re.compile(r"^[A-Za-z0-9_]{1,63}$")
MIN_VERSION = 160000          # PostgreSQL 16
TS_TABLES = ("akrp_ts_d", "akrp_ts_h", "akrp_ev")
MAX_PARAMS = 60000            # سقف پروتکل ۶۵۵۳۵ پارامتر در هر دستور


def q(name):
    if not _NAME.match(name or ""):
        raise DbError(f"نام نامعتبر: {name}")
    return f'"{name}"'


def pg_kind(sqlite_type, enc=False):
    t = (sqlite_type or "").upper()
    if enc:
        return "text"
    if "INT" in t:
        return "int"
    if any(x in t for x in ("REAL", "FLOA", "DOUB")):
        return "float"
    if "BLOB" in t:
        return "bytea"
    return "text"


PG_TYPE = {"int": "BIGINT", "float": "DOUBLE PRECISION", "bytea": "BYTEA", "text": "TEXT"}


def _err_text(e):
    a = e.args[0] if getattr(e, "args", None) else None
    if isinstance(a, dict):
        return a.get("M") or str(a), a.get("C") or ""
    return str(e), ""


def lock_key(db):
    return int.from_bytes(hashlib.sha256(f"autokrp:{db}".encode()).digest()[:8], "big", signed=True)


class PgBackend(MySQLBackend):
    """رابط یکسان با MySQLBackend (store.Store و tsdb از آن استفاده می‌کنند)."""

    def __init__(self, conf):
        super().__init__(conf)
        self._warned = set()

    # ------------------------------------------------------------ اتصال
    def _ssl(self):
        m = self.conf.get("ssl", "off")
        if m == "off":
            return None                 # pg8000: اگر سرور TLS دارد رمزشده (بدون بررسی)، وگرنه ساده
        if m == "required":
            return True                 # TLS اجباری بدون بررسی گواهی (انتخاب صریح کاربر)
        ctx = ssl.create_default_context(cadata=self.conf.get("ca_pem") or None)
        ctx.verify_flags &= ~getattr(ssl, "VERIFY_X509_STRICT", 0)    # گواهی‌های خودساخته‌ی رایج (snakeoil) keyUsage ندارند
        ctx.check_hostname = m == "verify_identity"
        return ctx

    def _connect(self, with_db=True, timeout=10, database=None):
        import pg8000.dbapi as pg
        db = database or (self.conf["database"] if with_db else "postgres")
        try:
            cn = pg.connect(user=self.conf["user"], password=self.conf.get("password", ""), host=self.conf["host"],
                            port=int(self.conf.get("port") or 5432), database=db, ssl_context=self._ssl(),
                            timeout=max(timeout, 30), application_name="AutoKRP")
        except pg.DatabaseError as e:
            msg, code = _err_text(e)
            human = {"28P01": "نام کاربری یا رمز PostgreSQL درست نیست.", "28000": "این کاربر اجازه‌ی ورود ندارد (pg_hba.conf را بررسی کنید).",
                     "3D000": "پایگاه داده وجود ندارد.", "42501": "این کاربر به این پایگاه داده دسترسی ندارد."}.get(code)
            raise DbError(f"{human or 'اتصال به PostgreSQL ناموفق بود'} ({msg})")
        except ssl.SSLError as e:
            raise DbError(f"خطای TLS: گواهی سرور PostgreSQL تأیید نشد (CA، نام سرور یا تنظیم TLS را بررسی کنید). ({e})")
        except Exception as e:  # noqa — InterfaceError (اتصال/TLS) و هر خطای دیگر کتابخانه
            t = str(e)
            if "refuses SSL" in t:
                raise DbError("سرور PostgreSQL از TLS پشتیبانی نمی‌کند (ssl = on در postgresql.conf) یا TLS را خاموش کنید.")
            if "Can't create a connection" in t or isinstance(e, OSError):
                raise DbError(f"به سرور PostgreSQL وصل نشد (آدرس، پورت یا فایروال را بررسی کنید). ({t})")
            raise DbError(f"اتصال به PostgreSQL ناموفق بود: {t}")
        try:
            c = cn.cursor()
            c.execute("SHOW server_version_num")
            v = int(c.fetchone()[0])
            cn.rollback()
        except Exception:  # noqa
            v = MIN_VERSION
        if v < MIN_VERSION:
            cn.close()
            raise DbError(f"نسخه‌ی PostgreSQL باید ۱۶ یا بالاتر باشد (این سرور: {v // 10000}).")
        return cn

    def _db_exists(self):
        """(وجود دارد؟، اتصال به پایگاه داده‌ی postgres ممکن بود؟)"""
        try:
            cn = self._connect(with_db=False)
        except DbError:
            try:
                self._connect().close()
                return True, False
            except DbError:
                return False, False
        try:
            c = cn.cursor()
            c.execute("SELECT 1 FROM pg_database WHERE datname=%s", (self.conf["database"],))
            return bool(c.fetchone()), True
        finally:
            cn.close()

    def probe(self):
        exists, _ = self._db_exists()
        cn = self._connect(with_db=exists)
        try:
            c = cn.cursor()
            c.execute("SHOW server_version")
            ver = "PostgreSQL " + str(c.fetchone()[0])
            c.execute("SELECT ssl, version, cipher FROM pg_stat_ssl WHERE pid = pg_backend_pid()")
            r = c.fetchone()
            tls = f"{r[1]} {r[2]}" if r and r[0] else ""
            info = {"version": ver, "tls": tls, "db_exists": exists, "has_data": False, "mode": None, "key_ok": None}
            if exists:
                c.execute("SELECT to_regclass(%s)", (META,))
                if c.fetchone()[0]:
                    c.execute(f"SELECT k, v FROM {META}")  # nosec B608 — نام ثابت
                    m = dict(c.fetchall())
                    info.update(has_data=True, mode=m.get("mode"), saved=m.get("saved"), version_app=m.get("app_version"))
                    info["key_ok"] = self._key_ok(m.get("key_check"))
            cn.rollback()
            return info
        finally:
            cn.close()

    def open(self):
        db = self.conf["database"]
        if not _NAME.match(db):
            raise DbError("نام پایگاه داده فقط حروف انگلیسی، عدد و _ (حداکثر ۶۳).")
        exists, via_pg = self._db_exists()
        if not exists:
            if not via_pg:
                raise DbError(f"پایگاه داده‌ی «{db}» پیدا نشد و اتصال برای ساختن آن ممکن نبود؛ آن را در PostgreSQL بسازید "
                              f"(CREATE DATABASE {db} ENCODING 'UTF8' OWNER <user>) یا به کاربر اجازه‌ی CREATEDB بدهید.")
            cn = self._connect(with_db=False)
            try:
                cn.autocommit = True
                cn.cursor().execute(f"CREATE DATABASE {q(db)} ENCODING 'UTF8' TEMPLATE template0")
            except Exception as e:  # noqa
                raise DbError(f"ساخت پایگاه داده‌ی «{db}» ناموفق بود (دسترسی CREATEDB لازم است): {_err_text(e)[0]}")
            finally:
                cn.close()
        self.lock_cn = self._connect()
        self.lock_cn.autocommit = True
        c = self.lock_cn.cursor()
        c.execute("SELECT pg_try_advisory_lock(%s)", (lock_key(db),))
        if not c.fetchone()[0]:
            self.lock_cn.close()
            self.lock_cn = None
            raise DbError(f"پایگاه داده‌ی «{db}» الان در اختیار یک AutoKRP دیگر است؛ هم‌زمان فقط یک نصب می‌تواند از آن استفاده کند.")
        self.cn = self._connect()
        try:
            c = self.cn.cursor()
            c.execute(f"CREATE TABLE IF NOT EXISTS {META}(k VARCHAR(64) PRIMARY KEY, v TEXT)")
            c.execute(f"SELECT k, v FROM {META}")  # nosec B608 — نام ثابت
            meta = dict(c.fetchall())
            self.cn.commit()
        except Exception as e:  # noqa
            self.close()
            raise DbError(f"ساخت جدول در پایگاه داده‌ی «{db}» ناموفق بود (دسترسی CREATE روی schema لازم است): {_err_text(e)[0]}")
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
            c.execute(f"INSERT INTO {META}(k, v) VALUES(%s, %s) ON CONFLICT (k) DO UPDATE SET v = EXCLUDED.v", (k, str(v)))  # nosec B608

    def write_meta_base(self):
        from . import __version__
        c = self.cn.cursor()
        self._set_meta(c, mode=self.mode, app_version=__version__, engine="postgres",
                       key_check=base64.b64encode(atrest.encrypt(CHECK_PLAIN)).decode() if self.mode != "plain" else "")
        self.cn.commit()

    @staticmethod
    def _alive(cn):
        try:
            cn.rollback()
            cn.cursor().execute("SELECT 1")
            cn.rollback()
            return True
        except Exception:  # noqa
            return False

    def ensure(self):
        if self.cn is None or not self._alive(self.cn):
            try:
                if self.cn is not None:
                    self.cn.close()
            except Exception:  # noqa
                pass
            self.cn = self._connect()
        if self.lock_cn is None or not self._alive(self.lock_cn):
            try:
                if self.lock_cn is not None:
                    self.lock_cn.close()
            except Exception:  # noqa
                pass
            self.lock_cn = self._connect()
            self.lock_cn.autocommit = True
            c = self.lock_cn.cursor()
            c.execute("SELECT pg_try_advisory_lock(%s)", (lock_key(self.conf["database"]),))
            if not c.fetchone()[0]:
                raise DbError("قفل پایگاه داده از دست رفت و نصب دیگری آن را گرفته است؛ نوشتن متوقف شد.")

    def close(self):
        for cn in (self.cn, self.lock_cn):
            if cn is not None:
                try:
                    cn.close()          # قفل advisory با بسته شدن اتصال آزاد می‌شود
                except Exception:  # noqa
                    pass
        self.cn = self.lock_cn = None

    def _fail(self, e):
        self.ok, self.error = False, str(e)
        if self._err_logged != self.error:
            log.error("PostgreSQL: %s", e)
            self._err_logged = self.error

    # ------------------------------------------------------------ تبدیل نوع
    def _val(self, v, kind, where=""):
        if v is None:
            return None
        if kind == "text":
            if isinstance(v, str):
                return v.replace("\x00", "�") if "\x00" in v else v
            if isinstance(v, (bytes, bytearray)):
                return bytes(v).decode("utf-8", "replace").replace("\x00", "�")
            return str(v)
        if kind == "int":
            if isinstance(v, bool):
                return int(v)
            if isinstance(v, int):
                return v
            if isinstance(v, float):
                return int(round(v))
            try:
                return int(str(v).strip())
            except (TypeError, ValueError):
                try:
                    return int(round(float(str(v).strip())))
                except (TypeError, ValueError):
                    self._warn(where, v)
                    return None
        if kind == "float":
            if isinstance(v, (int, float)):
                return float(v)
            try:
                return float(str(v).strip())
            except (TypeError, ValueError):
                self._warn(where, v)
                return None
        if isinstance(v, str):
            return v.encode("utf-8")
        return bytes(v) if isinstance(v, (bytes, bytearray, memoryview)) else str(v).encode("utf-8")

    def _warn(self, where, v):
        if where not in self._warned:
            self._warned.add(where)
            log.warning("PostgreSQL: مقدار ناسازگار با نوع ستون %s ذخیره نشد (NULL): %r", where, str(v)[:40])

    # ------------------------------------------------------------ حالت blob
    def load_blob(self):
        c = self.cn.cursor()
        c.execute(f"CREATE TABLE IF NOT EXISTS {BLOB}(n INT PRIMARY KEY, data BYTEA)")
        c.execute(f"SELECT data FROM {BLOB} ORDER BY n")  # nosec B608 — نام ثابت
        parts = [bytes(r[0]) for r in c.fetchall()]
        self.cn.commit()
        return atrest.decrypt(b"".join(parts)) if parts else None

    def save_blob(self, image: bytes):
        data = atrest.encrypt(image)
        self.ensure()
        c = self.cn.cursor()
        try:
            c.execute(f"CREATE TABLE IF NOT EXISTS {BLOB}(n INT PRIMARY KEY, data BYTEA)")
            c.execute(f"DELETE FROM {BLOB}")  # nosec B608 — نام ثابت
            for i in range(0, max(1, len(data)), CHUNK):
                c.execute(f"INSERT INTO {BLOB}(n, data) VALUES(%s, %s)", (i // CHUNK, data[i:i + CHUNK]))  # nosec B608
            self._set_meta(c, saved=time.time())
            self.cn.commit()
        except Exception:
            self.cn.rollback()
            raise

    # ------------------------------------------------------------ حالت جدولی
    def mysql_tables(self):          # نام هم‌سان با MySQLBackend
        c = self.cn.cursor()
        c.execute("SELECT table_name FROM information_schema.tables WHERE table_schema = current_schema()")
        out = {r[0] for r in c.fetchall()}
        self.cn.rollback()
        return out

    def mysql_cols(self, t):
        c = self.cn.cursor()
        c.execute("SELECT column_name FROM information_schema.columns WHERE table_schema = current_schema() AND table_name=%s", (t,))
        out = {r[0] for r in c.fetchall()}
        self.cn.rollback()
        return out

    def schema_version(self):
        if "meta" not in self.mysql_tables():
            return None
        c = self.cn.cursor()
        c.execute('SELECT "value" FROM "meta" WHERE "key"=\'schema\'')
        r = c.fetchone()
        self.cn.rollback()
        v = self._dec(r[0]) if r else None
        return int(v) if v else None

    def load_tables(self, db):
        have = self.mysql_tables()
        n = 0
        c = self.cn.cursor()
        for t in self.sqlite_tables(db):
            if t not in have:
                continue
            cols = [x for x, _, _ in self.sqlite_cols(db, t)]
            mcols = self.mysql_cols(t)
            use = [x for x in cols if x in mcols]
            enc = self._enc_cols(t)
            db.execute(f"DELETE FROM {q(t)}")  # nosec B608 — نام از sqlite_master
            last = None
            while True:                       # صفحه‌به‌صفحه روی _rid (pg8000 کل نتیجه را در حافظه می‌آورد)
                sel = ", ".join(q(x) for x in use)
                if last is None:
                    c.execute(f'SELECT "_rid"{", " + sel if sel else ""} FROM {q(t)} ORDER BY "_rid" LIMIT %s', (BATCH * 10,))  # nosec B608
                else:
                    c.execute(f'SELECT "_rid"{", " + sel if sel else ""} FROM {q(t)} WHERE "_rid" > %s ORDER BY "_rid" LIMIT %s',  # nosec B608
                              (last, BATCH * 10))
                rows = c.fetchall()
                if not rows:
                    break
                out = []
                for r in rows:
                    vals = [self._dec(v) if use[i] in enc else (bytes(v) if isinstance(v, memoryview) else v) for i, v in enumerate(r[1:])]
                    out.append((r[0], *vals))
                db.executemany(f"INSERT INTO {q(t)}(rowid{', ' + ', '.join(q(x) for x in use) if use else ''}) "  # nosec B608
                               f"VALUES({', '.join('?' * (len(use) + 1))})", out)
                n += len(out)
                last = rows[-1][0]
                if len(rows) < BATCH * 10:
                    break
        self.cn.rollback()
        return n

    def sync_schema(self, db):
        have = self.mysql_tables()
        changed = []
        c = self.cn.cursor()
        try:
            for t in self.sqlite_tables(db):
                cols = self.sqlite_cols(db, t)
                enc = self._enc_cols(t)
                if t not in have:
                    defs = ['"_rid" BIGINT NOT NULL PRIMARY KEY'] + [f"{q(n)} {PG_TYPE[pg_kind(ty, n in enc)]} NULL" for n, ty, _ in cols]
                    c.execute(f"CREATE TABLE {q(t)}({', '.join(defs)})")
                    pk = [n for n, ty, p in sorted(cols, key=lambda x: x[2]) if p]
                    if pk and not enc.intersection(pk):    # نمایه برای کوئری بیرونی روی کلید اصلی SQLite
                        tys = {n: ty for n, ty, _ in cols}
                        parts = [f"left({q(x)}, 200)" if pg_kind(tys[x]) == "text" else q(x) for x in pk]
                        c.execute(f"CREATE INDEX IF NOT EXISTS {q(('ix_' + t)[:55] + '_pk')} ON {q(t)} ({', '.join(parts)})")
                    changed.append(t)
                    continue
                mc = self.mysql_cols(t)
                for n, ty, _ in cols:
                    if n not in mc:
                        c.execute(f"ALTER TABLE {q(t)} ADD COLUMN {q(n)} {PG_TYPE[pg_kind(ty, n in enc)]} NULL")
                        changed.append(t)
            self.cn.commit()
        except Exception:
            self.cn.rollback()
            raise
        return sorted(set(changed))

    def push_all(self, db, tables=None):
        self.ensure()
        tables = tables or self.sqlite_tables(db)
        c = self.cn.cursor()
        try:
            for t in tables:
                c.execute(f"DELETE FROM {q(t)}")  # nosec B608 — نام از sqlite_master
                cols = self.sqlite_cols(db, t)
                cur = db.execute(f"SELECT rowid, * FROM {q(t)}")  # nosec B608
                while True:
                    rows = cur.fetchmany(BATCH)
                    if not rows:
                        break
                    self._upsert(c, t, cols, rows)
            self._set_meta(c, saved=time.time())
            self.cn.commit()
        except Exception:
            self.cn.rollback()
            raise

    def _upsert(self, c, t, cols, rows):
        """INSERT … ON CONFLICT چندردیفی (هر دستور حداکثر MAX_PARAMS پارامتر). cols: [(نام، نوع SQLite، pk)]."""
        enc = self._enc_cols(t)
        names = [x for x, _, _ in cols]
        kinds = [pg_kind(ty, n in enc) for n, ty, _ in cols]
        allq = ", ".join(q(x) for x in ["_rid"] + names)
        upd = ", ".join(f"{q(x)} = EXCLUDED.{q(x)}" for x in names)
        tail = f' ON CONFLICT ("_rid") DO UPDATE SET {upd}' if names else ' ON CONFLICT ("_rid") DO NOTHING'  # nosec B608 — نام ستون‌ها با q() اعتبارسنجی‌شده
        per = max(1, min(BATCH, MAX_PARAMS // (len(names) + 1)))
        ph = "(" + ", ".join(["%s"] * (len(names) + 1)) + ")"
        rows = [tuple(r) for r in rows]
        for i in range(0, len(rows), per):
            part = rows[i:i + per]
            args = []
            for r in part:
                args.append(int(r[0]))
                for j, v in enumerate(r[1:]):
                    args.append(self._enc(v) if names[j] in enc else self._val(v, kinds[j], f"{t}.{names[j]}"))
            c.execute(f"INSERT INTO {q(t)}({allq}) VALUES {', '.join([ph] * len(part))}{tail}", args)  # nosec B608 — نام‌ها اعتبارسنجی‌شده

    def flush_changes(self, db):
        top = db.execute(f"SELECT MAX(n) FROM {CHG}").fetchone()[0]  # nosec B608 — نام ثابت
        if top is None:
            return 0
        by = {}
        for t, rid in db.execute(f"SELECT DISTINCT tbl, rid FROM {CHG} WHERE n <= ?", (top,)):  # nosec B608
            by.setdefault(t, set()).add(rid)
        self.ensure()
        n = 0
        c = self.cn.cursor()
        try:
            for t, rids in by.items():
                cols = self.sqlite_cols(db, t)
                if not cols:
                    continue
                ids = sorted(rids)
                for i in range(0, len(ids), BATCH):
                    part = ids[i:i + BATCH]
                    rows = db.execute(f"SELECT rowid, * FROM {q(t)} WHERE rowid IN ({','.join('?' * len(part))})", part).fetchall()  # nosec B608
                    found = {r[0] for r in rows}
                    if rows:
                        self._upsert(c, t, cols, rows)
                    gone = [x for x in part if x not in found]
                    if gone:
                        c.execute(f'DELETE FROM {q(t)} WHERE "_rid" IN ({",".join(["%s"] * len(gone))})', gone)  # nosec B608
                    n += len(part)
            self._set_meta(c, saved=time.time())
            self.cn.commit()
        except Exception:
            self.cn.rollback()
            raise
        db.execute(f"DELETE FROM {CHG} WHERE n <= ?", (top,))  # nosec B608 — فقط تغییرهایی که نوشته شدند
        return n

    def drop_all(self):
        """RESET: فقط جدول‌های AutoKRP (ستون _rid، جدول‌های meta/blob/سری زمانی) در schema جاری حذف می‌شوند."""
        self.ensure()
        c = self.cn.cursor()
        try:
            c.execute("SELECT DISTINCT table_name FROM information_schema.columns WHERE table_schema = current_schema() AND column_name='_rid'")
            names = {r[0] for r in c.fetchall()}
            have = self.mysql_tables()
            names |= ({META, BLOB, *TS_TABLES} & have)
            for t in sorted(names):
                if _NAME.match(t):
                    c.execute(f"DROP TABLE IF EXISTS {q(t)} CASCADE")
            self.cn.commit()
        except Exception:
            self.cn.rollback()
            raise
        return len(names)

