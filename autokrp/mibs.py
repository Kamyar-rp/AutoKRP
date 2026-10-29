"""
کتابخانه‌ی MIB (1.27): نام، نوع، واحد و مقدارهای enum هر OID از فایل‌های MIB واقعی.

- MIBهای استاندارد (IETF، Net-SNMP) همراه برنامه‌اند: assets/mibs/std.json (از dev/mibs_build.py) و منبع‌شان در
  assets/mibs/src برای حل وابستگی MIBهای سازنده.
- ادمین فایل MIB سازنده را (از سایت سازنده) در «مانیتورینگ ← کتابخانه‌ی SNMP ← فایل‌های MIB» بارگذاری می‌کند؛
  بدون تغییر سورس برنامه. فایل با pysmi به JSON تبدیل می‌شود (JsonCodeGen؛ هیچ کدی از فایل اجرا نمی‌شود) و فقط
  قالب فشرده‌ی خود برنامه نگه داشته می‌شود (بخش meta که نام میزبان/کاربر/مسیر دارد دور ریخته می‌شود).
- MIB داده‌ی عمومی سازنده است و رمز نمی‌شود (معیار رمزنگاری پروژه: داده‌ی شبکه‌ی سازمان رمز؛ داده‌ی عمومی نه).

قالب فشرده‌ی هر شیء (کلید = OID عددی):
  m ماژول، n نام، k نوع گره (s اسکالر، c ستون، t جدول، r ردیف، n نوتیفیکیشن، o گره)، t نوع پایه، e {عدد: برچسب}،
  u واحد، h display hint، d توضیح (کوتاه‌شده)، i نام ستون‌های اندیس (ردیف)، x اشیای نوتیفیکیشن.
"""
import json
import logging
import re
import threading
import time
from pathlib import Path

from . import paths

log = logging.getLogger(__name__)

MAX_FILE = 4 * 1024 * 1024          # هر فایل بارگذاری‌شده
MAX_MODULES = 3000
DESC_MAX = 400
_MOD_RE = re.compile(r"^\s*([A-Za-z][A-Za-z0-9-]{0,63})\s+DEFINITIONS\s*(?:IMPLICIT\s+TAGS\s*)?::=\s*BEGIN\b", re.M)
_NAME_OK = re.compile(r"^[A-Za-z][A-Za-z0-9-]{0,63}$")
ACCESS = {"read-only": "ro", "read-write": "rw", "read-create": "rw", "not-accessible": "na", "accessible-for-notify": "nf"}
KIND = {"scalar": "s", "column": "c", "table": "t", "row": "r", "notification": "n"}
BASE_TYPES = {"Integer32", "INTEGER", "Unsigned32", "Gauge32", "Counter32", "Counter64", "TimeTicks", "IpAddress",
              "OctetString", "OCTET STRING", "ObjectIdentifier", "OBJECT IDENTIFIER", "Bits", "BITS", "Opaque"}
# نوع پایه‌ی TCهای استاندارد SNMPv2-TC (pysmi آن را فقط stub می‌کند؛ مقدارها از RFC 2579)
SNMPV2_TC = {"DisplayString": ("OctetString", None), "PhysAddress": ("OctetString", None), "MacAddress": ("OctetString", None),
             "TruthValue": ("INTEGER", {1: "true", 2: "false"}), "TestAndIncr": ("Integer32", None),
             "AutonomousType": ("ObjectIdentifier", None), "InstancePointer": ("ObjectIdentifier", None),
             "VariablePointer": ("ObjectIdentifier", None), "RowPointer": ("ObjectIdentifier", None),
             "RowStatus": ("INTEGER", {1: "active", 2: "notInService", 3: "notReady", 4: "createAndGo", 5: "createAndWait", 6: "destroy"}),
             "TimeStamp": ("TimeTicks", None), "TimeInterval": ("Integer32", None), "DateAndTime": ("OctetString", None),
             "StorageType": ("INTEGER", {1: "other", 2: "volatile", 3: "nonVolatile", 4: "permanent", 5: "readOnly"}),
             "TDomain": ("ObjectIdentifier", None), "TAddress": ("OctetString", None)}


# سطح Trap از روی نام (همان قاعده‌ی dev/trapdb_build.py برای trapdb.json؛ برای Trap MIBهای بارگذاری‌شده‌ی کاربر)
OK = re.compile(r"(ok$|ok[A-Z]|okay|up$|Up$|poweron|recover|restore|clear|normal|inserted|established|linkup|online|resolved|cleared)", re.I)
CRIT = re.compile(r"(fail|fault|critical|shutdown|overtemp|overheat|temp|thermal|exception|degrad|lost|removed|removal|"
                  r"backwardtransition|down(?!grade)|alarm|error|outofrange|nonredundant|notpresent|exceed|full|abort|violation|"
                  r"errdisable|bad|offline|unavailable|power|supply|psu|fan|voltage|battery|high$|high[A-Z]|hot|dyinggasp)", re.I)
WARN = re.compile(r"(ha|switch(?:over)?|reboot|restart|statechange|newroot|topologychange|authentication|threshold|"
                  r"cpu|mem|disk|pool|usage|new[A-Z]|security|bypass|stack|member|hsrp|vrrp|bgp|ospf|ips|virus|av[A-Z]|anomaly|attack|intrusion)", re.I)


def trap_level(name):
    n = name.lower()
    if n in ("coldstart", "warmstart", "authenticationfailure", "linkdown"):
        return "warn"
    if n == "linkup":
        return "ok"
    if OK.search(name):
        return "ok"
    if CRIT.search(name):
        return "crit"
    if WARN.search(name):
        return "warn"
    return "info"



class MibError(Exception):
    """پیام فارسی قابل نمایش."""


# ---------------------------------------------------------------------------- تبدیل JSON pysmi به قالب فشرده
def _enum(syn):
    c = (syn or {}).get("constraints") or {}
    en = c.get("enumeration")
    if isinstance(en, dict) and en:
        try:
            return {int(v): str(k) for k, v in en.items()}
        except (TypeError, ValueError):
            return None
    return None


def compact(doc):
    """JSON یک ماژول (خروجی JsonCodeGen) ← {"module", "imports", "tcs", "objs"}."""
    mod = ((doc.get("meta") or {}).get("module")) or ""
    imports = sorted(str(k) for k in (doc.get("imports") or {}) if k != "class")
    tcs, objs, ident = {}, {}, {}
    for name, o in doc.items():
        if not isinstance(o, dict):
            continue
        cls = o.get("class")
        if cls == "textualconvention":
            ty = (o.get("type") or {})
            tcs[name] = {"t": ty.get("type") or "", "e": _enum(ty), "h": o.get("displayhint") or ""}
        elif cls in ("objecttype", "notificationtype", "objectidentity", "moduleidentity") or (cls == "" and o.get("oid")):
            oid = str(o.get("oid") or "")
            if not oid:
                continue
            syn = o.get("syntax") or {}
            e = {"m": mod, "n": name, "k": KIND.get(o.get("nodetype") or ("notification" if cls == "notificationtype" else ""), "o")}
            if syn.get("type"):
                e["t"] = syn["type"]
            en = _enum(syn)
            if en:
                e["e"] = en
            if o.get("units"):
                e["u"] = str(o["units"])[:40]
            d = " ".join(str(o.get("description") or "").split())
            if d:
                e["d"] = d[:DESC_MAX]
            if o.get("indices"):
                e["i"] = [str(x.get("object")) for x in o["indices"] if isinstance(x, dict)]
            if o.get("objects"):
                e["x"] = [str(x.get("object")) for x in o["objects"] if isinstance(x, dict)]
            if o.get("maxaccess"):
                e["a"] = ACCESS.get(o["maxaccess"], "")
            if cls == "moduleidentity":
                ident = {"oid": oid, "org": " ".join(str(o.get("organization") or "").split())[:120]}
            objs[oid] = e
        elif o.get("oid") and o.get("name"):            # OBJECT IDENTIFIER ساده (گره)
            objs.setdefault(str(o["oid"]), {"m": mod, "n": name, "k": "o"})
    return {"module": mod, "imports": imports, "tcs": tcs, "objs": objs, "ident": ident}


# ---------------------------------------------------------------------------- کامپایل
def split_modules(text):
    """یک فایل ممکن است چند ماژول داشته باشد: [(نام، متن ماژول)]."""
    ms = list(_MOD_RE.finditer(text))
    out = []
    for i, m in enumerate(ms):
        end = ms[i + 1].start() if i + 1 < len(ms) else len(text)
        out.append((m.group(1), text[m.start():end].strip() + "\n"))
    return out


def _compiler(sources, writer_cb):
    try:
        from pysmi.codegen import JsonCodeGen
        from pysmi.compiler import MibCompiler
        from pysmi.parser import SmiStarParser
        from pysmi.reader import FileReader
        from pysmi.searcher import StubSearcher
        from pysmi.writer import CallbackWriter
    except ImportError:
        raise MibError("کتابخانه‌ی pysmi نصب نیست؛ بارگذاری MIB ممکن نیست.")
    mc = MibCompiler(SmiStarParser(), JsonCodeGen(), CallbackWriter(lambda name, data, ctx: writer_cb(name, data)))
    for s in sources:
        mc.add_sources(FileReader(str(s), recursive=False))
    mc.add_searchers(StubSearcher(*JsonCodeGen.baseMibs))
    return mc


def compile_modules(names, sources):
    """{نام: (وضعیت، dict فشرده یا پیام)} برای ماژول‌های خواسته‌شده و وابستگی‌هایشان."""
    got = {}

    def cb(name, data):
        try:
            got[name] = compact(json.loads(data))
        except (ValueError, TypeError) as e:
            got[name] = str(e)
    mc = _compiler(sources, cb)
    try:
        st = mc.compile(*names, genTexts=True, ignoreErrors=True)
    except Exception as e:  # noqa — خطای pysmi (پیام انگلیسی کتابخانه)
        raise MibError(f"کامپایل MIB ناموفق: {e}")
    out = {}
    for n, s0 in st.items():
        s = str(s0)
        if n in got and isinstance(got[n], dict):
            out[n] = ("ok", got[n])
        elif s in ("untouched", "borrowed"):
            out[n] = ("base", None)
        elif s == "missing":
            out[n] = ("missing", "فایل این ماژول نیست")
        else:
            out[n] = ("failed", _short_err(getattr(s0, "error", None) or s))
    return out


def _short_err(e):
    t = " ".join(str(e).split())
    m = re.search(r"(no module \S+|no symbol \S+|Bad grammar[^,]*|line \d+[^,]*)", t, re.I)
    return (m.group(1) if m else t)[:200]


# ---------------------------------------------------------------------------- مخزن
def std_dir():
    return paths.resource_dir() / "assets" / "mibs"


def user_dir():
    d = paths.data_dir() / "mibs"
    (d / "src").mkdir(parents=True, exist_ok=True)
    (d / "json").mkdir(parents=True, exist_ok=True)
    return d


class Library:
    """MIBهای استاندارد + بارگذاری‌شده؛ نمایه‌ی OID ← شیء با کش در حافظه."""

    def __init__(self):
        self._lock = threading.RLock()
        self._idx = None          # oid ← entry
        self._names = None        # "MOD::name" و "name" ← oid
        self._std = None
        self._ver = 0

    # -------------------------------------------------- بارگذاری
    def _load_std(self):
        if self._std is None:
            try:
                self._std = json.loads((std_dir() / "std.json").read_text(encoding="utf-8"))
            except (OSError, ValueError):
                log.exception("std.json")
                self._std = {"modules": {}}
        return self._std

    def _user_mods(self):
        out = {}
        for f in sorted((user_dir() / "json").glob("*.json")):
            try:
                d = json.loads(f.read_text(encoding="utf-8"))
                if isinstance(d, dict) and isinstance(d.get("objs"), dict):
                    out[d.get("module") or f.stem] = d
            except (OSError, ValueError):
                continue
        return out

    def invalidate(self):
        with self._lock:
            self._idx = self._names = None
            self._ver += 1

    def _build(self):
        with self._lock:
            if self._idx is not None:
                return
            mods = dict(self._load_std().get("modules") or {})
            mods.update(self._user_mods())
            tcs = {}
            for d in mods.values():
                tcs.update(d.get("tcs") or {})
            idx, names = {}, {}
            for mname, d in mods.items():
                for oid, e in (d.get("objs") or {}).items():
                    e = dict(e)
                    t = e.get("t")
                    for _ in range(4):                   # TC تودرتو ← نوع پایه، enum و hint
                        if not t or t in BASE_TYPES:
                            break
                        if t in tcs:
                            tc = tcs[t]
                            if tc.get("e") and not e.get("e"):
                                e["e"] = {int(k): v for k, v in tc["e"].items()}
                            if tc.get("h") and not e.get("h"):
                                e["h"] = tc["h"]
                            e.setdefault("tc", t)
                            t = tc.get("t")
                        elif t in SNMPV2_TC:
                            b, en = SNMPV2_TC[t]
                            if en and not e.get("e"):
                                e["e"] = en
                            e.setdefault("tc", t)
                            t = b
                        else:
                            break
                    if t:
                        e["t"] = t
                    if e.get("e"):
                        e["e"] = {int(k): v for k, v in e["e"].items()}
                    idx[oid] = e
                    names[f"{e['m']}::{e['n']}"] = oid
                    names.setdefault(e["n"], oid)
            self._idx, self._names = idx, names

    # -------------------------------------------------- جستجو
    def lookup(self, oid):
        """(entry, پسوند اندیس) برای نزدیک‌ترین پدر شناخته‌شده؛ یا (None, "")."""
        self._build()
        parts = str(oid or "").strip(".").split(".")
        for n in range(len(parts), 0, -1):
            e = self._idx.get(".".join(parts[:n]))
            if e is not None:
                return e, ".".join(parts[n:])
        return None, ""

    def name_of(self, oid):
        e, rest = self.lookup(oid)
        if not e:
            return ""
        return f"{e['m']}::{e['n']}" + (f".{rest}" if rest else "")

    def oid_of(self, name):
        """«MOD::name.idx» یا «name.idx» ← OID عددی؛ None اگر شناخته نیست."""
        self._build()
        s = str(name or "").strip()
        m = re.match(r"^([A-Za-z][\w-]*::)?([A-Za-z][\w-]*)((?:\.\d+)*)$", s)
        if not m:
            return None
        key = (m.group(1) or "") + m.group(2)
        oid = self._names.get(key) or self._names.get(m.group(2))
        return (oid + (m.group(3) or "")) if oid else None

    def entry(self, oid):
        self._build()
        return self._idx.get(str(oid).strip("."))

    def children(self, oid):
        """ستون‌های یک جدول/ردیف (برای پیشنهاد ستون برچسب)."""
        self._build()
        p = str(oid).strip(".") + "."
        return {o: e for o, e in self._idx.items() if o.startswith(p) and e.get("k") == "c"}

    def describe(self, oid, value=None):
        """برای رابط: {name, module, kind, type, unit, enum_text, descr, index}."""
        e, rest = self.lookup(oid)
        if not e:
            return {}
        out = {"name": e["n"], "module": e["m"], "kind": e.get("k", "o"), "type": e.get("t", ""), "unit": e.get("u", ""),
               "descr": e.get("d", ""), "index": rest}
        if e.get("e"):
            out["enum"] = {str(k): v for k, v in e["e"].items()}
            try:
                if value is not None and int(value) in e["e"]:
                    out["enum_text"] = e["e"][int(value)]
            except (TypeError, ValueError):
                pass
        return out

    def trap(self, oid):
        """نام و اشیای یک NOTIFICATION-TYPE (برای رخدادهای دستگاه)."""
        self._build()
        e = self._idx.get(str(oid).strip("."))
        return e if e and e.get("k") == "n" else None

    # -------------------------------------------------- مدیریت (ادمین)
    def modules(self):
        """فهرست ماژول‌های بارگذاری‌شده با وضعیت."""
        d = user_dir()
        st = self._status()
        std = set((self._load_std().get("modules") or {}).keys())
        out = []
        for f in sorted((d / "src").iterdir()):
            if not f.is_file() or not _NAME_OK.match(f.name):
                continue
            s = st.get(f.name) or {}
            j = d / "json" / f"{f.name}.json"
            n = 0
            if j.exists():
                try:
                    n = len(json.loads(j.read_text(encoding="utf-8")).get("objs") or {})
                except (OSError, ValueError):
                    n = 0
            out.append({"name": f.name, "size": f.stat().st_size, "status": s.get("status") or ("ok" if j.exists() else "pending"),
                        "error": s.get("error", ""), "objects": n, "missing": s.get("missing", []), "ts": f.stat().st_mtime})
        return {"modules": out, "std": sorted(std), "std_count": len(std)}

    def _status(self):
        try:
            return json.loads((user_dir() / "status.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}

    def add_text(self, text):
        """متن یک فایل MIB ← ماژول‌های آن در src. خروجی: نام‌ها."""
        if len(text.encode("utf-8", "replace")) > MAX_FILE:
            raise MibError("فایل MIB بزرگ‌تر از ۴ مگابایت است.")
        mods = split_modules(text)
        if not mods:
            raise MibError("این فایل MIB نیست (عبارت «DEFINITIONS ::= BEGIN» پیدا نشد).")
        d = user_dir() / "src"
        if len(list(d.iterdir())) + len(mods) > MAX_MODULES:
            raise MibError(f"حداکثر {MAX_MODULES} ماژول MIB.")
        names = []
        for name, body in mods:
            if not _NAME_OK.match(name):
                continue
            (d / name).write_text(body, encoding="utf-8")
            names.append(name)
        return names

    def delete(self, name):
        if not _NAME_OK.match(str(name or "")):
            raise MibError("نام ماژول نامعتبر است.")
        d = user_dir()
        for p in (d / "src" / name, d / "json" / f"{name}.json"):
            try:
                p.unlink()
            except OSError:
                pass
        st = self._status()
        st.pop(name, None)
        (d / "status.json").write_text(json.dumps(st, ensure_ascii=False), encoding="utf-8")
        self.invalidate()

    def compile_all(self):
        """همه‌ی ماژول‌های بارگذاری‌شده دوباره کامپایل می‌شوند (وابستگی‌ها از همین فهرست یا MIBهای همراه برنامه)."""
        d = user_dir()
        names = sorted(f.name for f in (d / "src").iterdir() if f.is_file() and _NAME_OK.match(f.name))
        status = {}
        if names:
            res = compile_modules(names, [d / "src", std_dir() / "src"])
            std = set((self._load_std().get("modules") or {}).keys())
            for n in names:
                st, val = res.get(n, ("failed", "نتیجه‌ای نیامد"))
                j = d / "json" / f"{n}.json"
                if st == "ok":
                    j.write_text(json.dumps(val, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
                    status[n] = {"status": "ok"}
                else:
                    if j.exists():
                        j.unlink()
                    miss = sorted(k for k, (s2, _) in res.items() if s2 == "missing" and k not in std)
                    status[n] = {"status": st, "error": val if isinstance(val, str) else "", "missing": miss}
            # وابستگی‌ای که فقط از MIBهای همراه برنامه کامپایل شد دوباره ذخیره نمی‌شود (در std.json هست)
        for j in (d / "json").glob("*.json"):
            if j.stem not in names:
                j.unlink()
        (d / "status.json").write_text(json.dumps(status, ensure_ascii=False), encoding="utf-8")
        self.invalidate()
        self._build_auto()
        return status

    # -------------------------------------------------- نوع دستگاه خودکار از MIB (1.27.1)
    def _build_auto(self):
        """برای هر سازنده (شماره‌ی enterprise از MODULE-IDENTITY) یک «نوع دستگاه» خودکار: همه‌ی اشیای «وضعیت سلامت»
        MIB (enum با مقدار سالم و مقدار هشدار/خرابی، مثل green/yellow/red یا ok/failed) با سطح هر مقدار از نام آن.
        عدد و آستانه حدس زده نمی‌شود. سازنده‌هایی که برنامه خودش می‌شناسد (Cisco، FortiGate و …) نوع تازه نمی‌گیرند."""
        from .snmp import VENDORS
        d = user_dir()
        self._build()
        by_ent = {}
        for f in sorted((d / "json").glob("*.json")):
            try:
                m = json.loads(f.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            ident = m.get("ident") or {}
            oid = ident.get("oid") or ""
            if not oid.startswith("1.3.6.1.4.1."):            # SMIv1 بدون MODULE-IDENTITY: پرتکرارترین شاخه‌ی enterprise
                from collections import Counter
                c = Counter(".".join(o.split(".")[:7]) for o in (m.get("objs") or {}) if o.startswith("1.3.6.1.4.1."))
                oid = c.most_common(1)[0][0] if c else ""
            parts = oid.split(".")
            if not oid.startswith("1.3.6.1.4.1.") or len(parts) < 7:
                continue
            ent = ".".join(parts[:7])
            if any((ent + ".").startswith(pfx) for pfx, _ in VENDORS):
                continue
            g = by_ent.setdefault(ent, {"org": ident.get("org") or "", "modules": [], "objs": {}})
            g["modules"].append(m.get("module") or f.stem)
            g["objs"].update(m.get("objs") or {})
        out = []
        for ent, g in sorted(by_ent.items()):
            metrics = health_metrics(g["objs"], self._idx)
            vendor = vendor_short(g["org"]) or g["modules"][0]
            out.append({"id": "mib" + ent.rsplit(".", 1)[1], "name": vendor, "vendor": vendor, "match": [ent], "metrics": metrics,
                        "asset": {}, "modules": g["modules"], "source": "mib", "updated": time.time()})
        (d / "auto_profiles.json").write_text(json.dumps(out, ensure_ascii=False), encoding="utf-8")
        self._auto = out

    def auto_profiles(self):
        a = getattr(self, "_auto", None)
        if a is None:
            try:
                a = json.loads((user_dir() / "auto_profiles.json").read_text(encoding="utf-8"))
            except (OSError, ValueError):
                a = []
            self._auto = a
        return a


# ---------------------------------------------------------------------------- وضعیت سلامت از روی نام مقدارهای enum
_LV_OK = re.compile(r"^(green|ok|okay|normal|up|online|good|active|running|operational|nominal|cleared?|present|inservice|healthy)$", re.I)
_LV_CRIT = re.compile(r"(red|critical|major|fail|fault|alarm|down|offline|error|lost|broken|shutdown|nonrecoverable|bad)", re.I)
_LV_WARN = re.compile(r"(yellow|warn|minor|degrad|marginal|noncritical|attention|low|high)", re.I)
MAX_AUTO = 40


def level_of(label):
    """سطح یک مقدار enum از نامش؛ None = نامعلوم (بدون هشدار)."""
    t = str(label or "")
    if _LV_OK.match(t):
        return "ok"
    if _LV_CRIT.search(t):
        return "crit"
    if _LV_WARN.search(t):
        return "warn"
    return None


def health_metrics(objs, idx=None):
    """اشیای «وضعیت سلامت» یک سازنده ← مقدارهای قالب (enum با سطح هر مقدار؛ جدول با ستون برچسب)."""
    notif_parents = set()
    for o, e in objs.items():
        if e.get("k") == "n":
            ps = o.split(".")
            for n in range(7, len(ps)):
                notif_parents.add(".".join(ps[:n]))
    out = []
    for oid, e in sorted(objs.items(), key=lambda x: tuple(int(p) for p in x[0].split("."))):
        if e.get("k") not in ("s", "c") or not e.get("e") or e.get("a") in ("na", "nf", "rw"):
            continue
        if e["k"] == "s" and oid.rsplit(".", 1)[0] in notif_parents:      # متغیرهای شاخه‌ی Trap (فقط داخل Trap می‌آیند)
            continue
        levels = {str(k): level_of(v) for k, v in e["e"].items()}
        if "ok" not in levels.values() or not ({"warn", "crit"} & set(levels.values())):
            continue
        label = ""
        if e["k"] == "c":
            row = oid.rsplit(".", 1)[0]
            sib = [(o, x) for o, x in objs.items() if o.rsplit(".", 1)[0] == row and x.get("k") == "c" and o != oid
                   and not x.get("e") and re.search(r"(DisplayString|OctetString|OCTET STRING|SnmpAdminString)", str(x.get("t") or ""))]
            for pat in ("name$", "descr", "name", "label", "alias"):
                hit = next((o for o, x in sib if re.search(pat, x["n"], re.I)), "")
                if hit:
                    label = hit
                    break
        out.append({"id": "a" + str(len(out)), "name": e["n"], "oid": oid if e["k"] == "c" else oid + ".0", "table": 1 if e["k"] == "c" else 0,
                    "label_oid": label, "max_rows": 64, "type": "enum", "unit": "", "mult": 1.0, "warn": None, "crit": None,
                    "dir": "above", "expect": "", "enum": {str(k): v for k, v in e["e"].items()},
                    "levels": {k: (v or "info") for k, v in levels.items()}, "chart": 0, "bits": 32, "auto": 1})
        if len(out) >= MAX_AUTO:
            break
    return out


def vendor_short(org):
    t = re.split(r"[,(]", str(org or ""))[0]
    t = re.sub(r"\b(Inc|Ltd|LLC|Corp|Corporation|Co|GmbH|S\.?A|AG|Limited)\.?$", "", t.strip(), flags=re.I).strip(" .")
    return t[:60]


LIB = Library()
