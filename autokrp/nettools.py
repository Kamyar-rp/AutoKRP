"""
ابزارهای شبکه (1.31): پیدا کردن محل IP/MAC روی سوییچ‌ها (SNMP)، Traceroute (برنامه‌ی خود سیستم‌عامل)،
مالک IP (RDAP، جایگزین استاندارد WHOIS) و سازنده از روی MAC (جدول IEEE).

- همه‌ی OIDها از فایل‌های MIB واقعی با snmptranslate بررسی شده‌اند (BRIDGE-MIB، Q-BRIDGE-MIB، IP-MIB، IF-MIB،
  SNMPv2-MIB، CISCO-VTP-MIB).
- Cisco جدول MAC هر VLAN را فقط با «community@VLAN» (v2c) یا context «vlan-N» (v3) می‌دهد (Community String Indexing).
- کارها در پس‌زمینه اجرا می‌شوند و رابط با شناسه‌ی کار وضعیت را می‌خواند؛ هر کاربر فقط کارهای خودش را می‌بیند.
"""
import gzip
import ipaddress
import json
import logging
import os
import re
import shutil
import subprocess  # nosec B404 — فقط tracert/traceroute سیستم با مسیر کامل و آرگومان لیستی
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from . import paths

log = logging.getLogger(__name__)


class NetError(Exception):
    pass


# ============================================================== MAC و سازنده
_MAC_RE = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}([:\-])(?:[0-9A-Fa-f]{2}\1){4}[0-9A-Fa-f]{2}"
                     r"|[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}|[0-9A-Fa-f]{12})(?![0-9A-Fa-f])")


def norm_mac(s):
    """aa:bb:cc:dd:ee:ff از هر قالب رایج (aa-bb-…، aabb.ccdd.eeff، aabbccddeeff)؛ None اگر MAC نیست."""
    h = re.sub(r"[^0-9A-Fa-f]", "", str(s or ""))
    if len(h) != 12 or not _MAC_RE.fullmatch(str(s or "").strip()):
        return None
    h = h.lower()
    return ":".join(h[i:i + 2] for i in range(0, 12, 2))


def extract_macs(text, limit=5000):
    """همه‌ی MACهای یک متن (مثلاً خروجی show mac address-table یا arp -a)، بدون تکرار، به ترتیب."""
    seen, out = set(), []
    for m in _MAC_RE.finditer(str(text or "")):
        mac = norm_mac(m.group(0))
        if mac and mac not in seen:
            seen.add(mac)
            out.append(mac)
            if len(out) >= limit:
                break
    return out


class Oui:
    """جدول سازنده‌ها: نسخه‌ی همراه برنامه (autokrp/oui.dat) یا نسخه‌ی به‌روزشده از IEEE در پوشه‌ی داده."""

    def __init__(self):
        self._db, self._src, self._lock = None, None, threading.Lock()

    @staticmethod
    def user_path():
        return paths.data_dir() / "oui.dat"

    @staticmethod
    def builtin_path():
        return Path(__file__).with_name("oui.dat")

    def _load(self):
        with self._lock:
            if self._db is not None:
                return self._db
            db, src = {}, None
            for p in (self.user_path(), self.builtin_path()):
                try:
                    if p.exists():
                        with gzip.open(p, "rt", encoding="utf-8") as f:
                            for line in f:
                                k, _, v = line.rstrip("\n").partition("\t")
                                if k and v:
                                    db[k] = v
                        src = p
                        break
                except (OSError, EOFError, ValueError):
                    log.exception("oui load %s", p)
                    db = {}
            self._db, self._src = db, src
            return db

    def info(self):
        db = self._load()
        p = self._src
        return {"entries": len(db), "updated": p.stat().st_mtime if p and p.exists() else None,
                "source": "ieee" if p == self.user_path() else "builtin"}

    def lookup(self, mac):
        db = self._load()
        h = mac.replace(":", "").upper()
        for n in (9, 7, 6):                      # MA-S (۳۶ بیت)، MA-M (۲۸ بیت)، MA-L (۲۴ بیت)
            v = db.get(h[:n])
            if v:
                return v
        try:
            if int(h[1], 16) & 2:
                return "@local"            # بیت U/L: آدرس محلی یا تصادفی (رابط ترجمه‌شده نشان می‌دهد)
        except ValueError:
            pass
        return ""

    def reset(self):
        with self._lock:
            self._db = None

    def update_from_ieee(self, timeout=60):
        """دانلود فهرست‌های فعلی IEEE (MA-L، MA-M، MA-S) و ذخیره در پوشه‌ی داده. داده‌ی عمومی است."""
        import csv
        import io

        import requests
        urls = ("https://standards-oui.ieee.org/oui/oui.csv", "https://standards-oui.ieee.org/oui28/mam.csv",
                "https://standards-oui.ieee.org/oui36/oui36.csv")
        data = {}
        for u in urls:
            r = requests.get(u, timeout=(15, timeout), headers={"User-Agent": "AutoKRP"})
            if r.status_code != 200:
                raise NetError(f"دانلود {u} ناموفق بود (HTTP {r.status_code}).")
            rd = csv.DictReader(io.StringIO(r.content.decode("utf-8", "replace")))
            if not rd.fieldnames or "Assignment" not in rd.fieldnames or "Organization Name" not in rd.fieldnames:
                raise NetError(f"قالب فایل {u} شناخته نشد.")
            for row in rd:
                a = re.sub(r"[^0-9A-Fa-f]", "", row.get("Assignment") or "").upper()
                n = " ".join((row.get("Organization Name") or "").split())[:120]
                if len(a) in (6, 7, 9) and n:
                    data[a] = n
        if len(data) < 10000:
            raise NetError("فهرست دریافتی ناقص است؛ ذخیره نشد.")
        tmp = self.user_path().with_suffix(".tmp")
        with gzip.open(tmp, "wt", encoding="utf-8") as f:
            f.write("".join(f"{k}\t{v}\n" for k, v in sorted(data.items())))
        os.replace(tmp, self.user_path())
        self.reset()
        return self.info()


OUI = Oui()


# ============================================================== کارهای پس‌زمینه
class Jobs:
    MAX_PER_USER = 6
    KEEP = 1800

    def __init__(self):
        self.jobs, self._lock = {}, threading.Lock()

    def start(self, owner, kind, title, fn):
        with self._lock:
            now = time.time()
            for k in [k for k, j in self.jobs.items() if j["status"] != "running" and now - (j["finished"] or now) > self.KEEP]:
                self.jobs.pop(k, None)
            if len([j for j in self.jobs.values() if j["owner"] == owner and j["status"] == "running"]) >= self.MAX_PER_USER:
                raise NetError("تعداد کارهای در جریان ابزارهای شبکه زیاد است؛ کمی صبر کنید.")
            j = {"id": uuid.uuid4().hex, "owner": owner, "kind": kind, "title": title, "status": "running", "lines": [],
                 "result": None, "error": "", "progress": [0, 0], "started": time.time(), "finished": None,
                 "cancel": threading.Event(), "proc": None}
            self.jobs[j["id"]] = j

        def run():
            try:
                j["result"] = fn(j)
                j["status"] = "cancelled" if j["cancel"].is_set() else "done"
            except NetError as e:
                j["status"], j["error"] = "error", str(e)
            except Exception as e:  # noqa
                log.exception("net job %s", kind)
                j["status"], j["error"] = "error", str(e)[:300]
            finally:
                j["finished"] = time.time()
        threading.Thread(target=run, name=f"net-{kind}", daemon=True).start()
        return self.public(j)

    def get(self, jid, owner):
        j = self.jobs.get(str(jid))
        if not j or j["owner"] != owner:
            raise NetError("کار پیدا نشد.")
        return j

    def cancel(self, jid, owner):
        j = self.get(jid, owner)
        j["cancel"].set()
        p = j.get("proc")
        if p and p.poll() is None:
            try:
                p.kill()
            except OSError:
                pass
        return self.public(j)

    @staticmethod
    def public(j, since=0):
        return {"id": j["id"], "kind": j["kind"], "title": j["title"], "status": j["status"], "error": j["error"],
                "progress": j["progress"], "started": j["started"], "finished": j["finished"],
                "lines": j["lines"][since:], "next": len(j["lines"]),
                "result": j["result"] if j["status"] != "running" else None}


# ============================================================== Traceroute
_HOST_RE = re.compile(r"^[A-Za-z0-9._:\-\[\]%]+$")


def clean_host(h):
    h = str(h or "").strip()
    if not h or len(h) > 253 or h.startswith("-") or not _HOST_RE.match(h):
        raise NetError(f"آدرس نامعتبر است: {h[:60] or '(خالی)'}")
    return h.strip("[]")


def _trace_cmd(host, hops, wait, resolve):
    if os.name == "nt":
        exe = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "TRACERT.EXE")
        if not os.path.exists(exe):
            raise NetError("tracert.exe ویندوز پیدا نشد.")
        cmd = [exe] + ([] if resolve else ["-d"]) + ["-h", str(hops), "-w", str(int(wait * 1000))]
        if ":" in host:
            cmd.append("-6")
        return cmd + [host]
    exe = next((p for p in ("/usr/bin/traceroute", "/usr/sbin/traceroute", "/bin/traceroute") if os.path.exists(p)), None) \
        or shutil.which("traceroute")
    if not exe:
        raise NetError("برنامه‌ی traceroute روی این سیستم نصب نیست.")
    return [exe] + ([] if resolve else ["-n"]) + (["-6"] if ":" in host else []) + ["-m", str(hops), "-w", str(wait), host]


_IP_IN_LINE = re.compile(r"(?<![\w.:])((?:\d{1,3}\.){3}\d{1,3}|[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7})(?![\w.:])")
_RTT_RE = re.compile(r"[<]?\s*(\d+(?:\.\d+)?)\s*ms", re.I)


def parse_hop(line):
    """خط یک گام (مستقل از زبان ویندوز): شماره، IPها، زمان‌ها (ms) و تعداد پاسخ‌نداده‌ها (*)."""
    m = re.match(r"^\s*(\d{1,3})\s+(.*)$", line)
    if not m:
        return None
    rest = m.group(2)
    ips = []
    for x in _IP_IN_LINE.findall(rest):
        try:
            ipaddress.ip_address(x)
            if x not in ips:
                ips.append(x)
        except ValueError:
            pass
    return {"hop": int(m.group(1)), "ips": ips, "rtt": [float(x) for x in _RTT_RE.findall(rest)],
            "lost": rest.count("*")}


def traceroute(job, host, hops=30, wait=2, resolve=False):
    host = clean_host(host)
    cmd = _trace_cmd(host, max(1, min(int(hops), 64)), max(1, min(int(wait), 10)), resolve)
    enc = "oem" if os.name == "nt" else "utf-8"
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,  # nosec B603
                         creationflags=0x08000000 if os.name == "nt" else 0)
    job["proc"] = p
    hopl = []
    deadline = time.time() + 60 + hops * wait * 4
    try:
        for raw in iter(p.stdout.readline, b""):
            line = raw.decode(enc, "replace").rstrip("\r\n")
            if line.strip():
                job["lines"].append(line[:500])
                h = parse_hop(line)
                if h:
                    hopl.append(h)
                    job["progress"] = [h["hop"], hops]
            if job["cancel"].is_set() or time.time() > deadline or len(job["lines"]) > 500:
                p.kill()
                break
        p.wait(10)
    finally:
        if p.poll() is None:
            p.kill()
    return {"host": host, "hops": hopl, "code": p.returncode}


# ============================================================== RDAP (مالک IP)
BOOT_URLS = {4: "https://data.iana.org/rdap/ipv4.json", 6: "https://data.iana.org/rdap/ipv6.json"}
BOOT_MAX_AGE = 7 * 86400


def _http_get(url, timeout=20, accept="application/rdap+json, application/json"):
    import requests
    r = requests.get(url, timeout=(10, timeout), headers={"Accept": accept, "User-Agent": "AutoKRP"}, allow_redirects=True)
    return r


def _bootstrap(ver, getter=_http_get):
    f = paths.data_dir() / f"rdap_boot{ver}.json"
    try:
        if f.exists() and time.time() - f.stat().st_mtime < BOOT_MAX_AGE:
            return json.loads(f.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        pass
    try:
        r = getter(BOOT_URLS[ver])
        if r.status_code != 200:
            raise NetError(f"فهرست سرورهای RDAP (IANA) دریافت نشد: HTTP {r.status_code}")
        data = r.json()
        if not isinstance(data.get("services"), list):
            raise NetError("قالب فهرست سرورهای RDAP شناخته نشد.")
        f.write_text(json.dumps(data), encoding="utf-8")       # داده‌ی عمومی IANA
        return data
    except NetError:
        if f.exists():
            return json.loads(f.read_text(encoding="utf-8"))    # نسخه‌ی قدیمی بهتر از هیچ
        raise
    except Exception as e:
        if f.exists():
            return json.loads(f.read_text(encoding="utf-8"))
        raise NetError(f"دسترسی به data.iana.org ممکن نشد: {str(e)[:150]}")


def rdap_server(ip, boot):
    """طولانی‌ترین پیشوند منطبق در فهرست IANA (RFC 9224) ← نشانی سرور RDAP."""
    best, url = -1, None
    for svc in boot.get("services") or []:
        try:
            nets, urls = svc[0], svc[1]
        except (IndexError, TypeError):
            continue
        for n in nets:
            try:
                net = ipaddress.ip_network(n, strict=False)
            except ValueError:
                continue
            if ip in net and net.prefixlen > best:
                https = [u for u in urls if str(u).startswith("https://")]
                if https:
                    best, url = net.prefixlen, https[0]
    return url


def _vcard(ent):
    out = {}
    try:
        for item in (ent.get("vcardArray") or [None, []])[1]:
            k, v = item[0], item[3]
            if k in ("fn", "org") and v and "name" not in out:
                out["name"] = v if isinstance(v, str) else " ".join(map(str, v))
            elif k == "email" and v:
                out.setdefault("email", v)
            elif k == "tel" and v:
                out.setdefault("tel", str(v).replace("tel:", ""))
            elif k == "adr":
                lab = (item[1] or {}).get("label")
                if lab:
                    out.setdefault("address", " ".join(str(lab).split()))
    except (TypeError, IndexError, AttributeError):
        pass
    return out


def _entities(ents, depth=0, acc=None):
    acc = [] if acc is None else acc
    for e in ents or []:
        if not isinstance(e, dict):
            continue
        acc.append({"handle": e.get("handle") or "", "roles": e.get("roles") or [], **_vcard(e)})
        if depth < 3:
            _entities(e.get("entities"), depth + 1, acc)
    return acc


def parse_rdap(d):
    ents = _entities(d.get("entities"))
    abuse = next((e for e in ents if "abuse" in e["roles"] and e.get("email")), None)
    owner = next((e for e in ents if "registrant" in e["roles"] and e.get("name")), None)
    ev = {e.get("eventAction"): e.get("eventDate") for e in d.get("events") or [] if isinstance(e, dict)}
    cidrs = []
    for c in d.get("cidr0_cidrs") or []:
        pfx = c.get("v4prefix") or c.get("v6prefix")
        if pfx is not None and c.get("length") is not None:
            cidrs.append(f"{pfx}/{c['length']}")
    rem = []
    for r in d.get("remarks") or []:
        if isinstance(r, dict):
            txt = " ".join(str(x) for x in r.get("description") or [])
            if txt:
                rem.append(((r.get("title") + ": ") if r.get("title") else "") + txt[:400])
    return {"handle": d.get("handle") or "", "name": d.get("name") or "", "type": d.get("type") or "",
            "country": d.get("country") or "", "start": d.get("startAddress") or "", "end": d.get("endAddress") or "",
            "cidrs": cidrs, "parent": d.get("parentHandle") or "", "owner": (owner or {}).get("name", ""),
            "abuse": (abuse or {}).get("email", ""), "registered": ev.get("registration", ""),
            "changed": ev.get("last changed", ""), "entities": ents[:30], "remarks": rem[:8], "port43": d.get("port43") or ""}


def rdap_lookup(ip, getter=_http_get):
    try:
        a = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        raise NetError(f"«{str(ip)[:60]}» آدرس IP نیست.")
    if not a.is_global:
        raise NetError("این آدرس خصوصی یا رزرو است و مالک عمومی ندارد.")
    url = rdap_server(a, _bootstrap(a.version, getter))
    if not url:
        raise NetError("سرور RDAP این آدرس در فهرست IANA پیدا نشد.")
    q = url.rstrip("/") + "/ip/" + str(a)
    try:
        r = getter(q)
    except Exception as e:
        raise NetError(f"اتصال به سرور RDAP ناموفق بود: {str(e)[:150]}")
    if r.status_code == 404:
        raise NetError("سرور RDAP رکوردی برای این آدرس ندارد.")
    if r.status_code == 429:
        raise NetError("سرور RDAP درخواست‌ها را محدود کرده است؛ کمی بعد دوباره امتحان کنید.")
    if r.status_code != 200:
        raise NetError(f"پاسخ سرور RDAP: HTTP {r.status_code}")
    try:
        d = r.json()
    except ValueError:
        raise NetError("پاسخ سرور RDAP JSON نیست.")
    out = parse_rdap(d)
    out.update(ip=str(a), server=q, raw=json.dumps(d, ensure_ascii=False, indent=1)[:60000])
    return out


# ============================================================== محل IP/MAC روی سوییچ‌ها (SNMP)
OID = {
    "sysName": "1.3.6.1.2.1.1.5.0", "sysObjectID": "1.3.6.1.2.1.1.2.0",
    "arp": "1.3.6.1.2.1.4.22.1.2",            # IP-MIB::ipNetToMediaPhysAddress   (ifIndex.a.b.c.d)
    "arp_type": "1.3.6.1.2.1.4.22.1.4",       # IP-MIB::ipNetToMediaType          invalid(2)
    "arp2": "1.3.6.1.2.1.4.35.1.4",           # IP-MIB::ipNetToPhysicalPhysAddress (ifIndex.type.len.addr)
    "qfdb": "1.3.6.1.2.1.17.7.1.2.2.1.2",     # Q-BRIDGE-MIB::dot1qTpFdbPort       (fdbId.mac)
    "qfdb_st": "1.3.6.1.2.1.17.7.1.2.2.1.3",  # Q-BRIDGE-MIB::dot1qTpFdbStatus     self(4)
    "qvlan_fdb": "1.3.6.1.2.1.17.7.1.4.2.1.3",  # Q-BRIDGE-MIB::dot1qVlanFdbId     (timeMark.vlan → fdbId)
    "fdb": "1.3.6.1.2.1.17.4.3.1.2",          # BRIDGE-MIB::dot1dTpFdbPort        (mac)
    "fdb_st": "1.3.6.1.2.1.17.4.3.1.3",       # BRIDGE-MIB::dot1dTpFdbStatus      self(4)
    "bport": "1.3.6.1.2.1.17.1.4.1.2",        # BRIDGE-MIB::dot1dBasePortIfIndex
    "ifName": "1.3.6.1.2.1.31.1.1.1.1", "ifDescr": "1.3.6.1.2.1.2.2.1.2", "ifAlias": "1.3.6.1.2.1.31.1.1.1.18",
    "vtp_state": "1.3.6.1.4.1.9.9.46.1.3.1.1.2",  # CISCO-VTP-MIB::vtpVlanState   (domain.vlan) operational(1)
}
ROWS = 60000
MAX_VLANS = 256
EDGE_MACS = 4          # پورتی با این تعداد MAC یا کمتر «پورت لبه (دسترسی)» حساب می‌شود


def _mac_val(v):
    """مقدار PhysAddress از snmp.conv: معمولاً «aa:bb:…»؛ اگر همه‌ی بایت‌ها حرف چاپی بودند، رشته‌ی متنی."""
    if v is None:
        return None
    s = str(v)
    m = norm_mac(s) if len(s) == 17 else None
    if m:
        return m
    b = s.encode("utf-8")
    if len(b) <= 6:
        b = b.ljust(6, b"\0")
        return ":".join(f"{x:02x}" for x in b)
    return None


def _mac_from_idx(parts):
    if len(parts) != 6:
        return None
    try:
        return ":".join(f"{int(x):02x}" for x in parts)
    except ValueError:
        return None


def parse_arp(cols):
    """{ستون: {اندیس: مقدار}} ← [(ip، mac، ifIndex)]"""
    out = []
    bad = {k for k, v in (cols.get(OID["arp_type"]) or {}).items() if v == 2}
    for idx, v in (cols.get(OID["arp"]) or {}).items():
        p = idx.split(".")
        if len(p) != 5 or idx in bad:
            continue
        mac = _mac_val(v)
        if mac and mac != "00:00:00:00:00:00":
            out.append((".".join(p[1:]), mac, int(p[0])))
    for idx, v in (cols.get(OID["arp2"]) or {}).items():
        p = idx.split(".")
        try:
            ifx, typ, ln = int(p[0]), int(p[1]), int(p[2])
            raw = bytes(int(x) for x in p[3:3 + ln])
        except (ValueError, IndexError):
            continue
        if len(raw) != ln or typ not in (1, 2):
            continue
        try:
            ip = str(ipaddress.ip_address(raw))
        except ValueError:
            continue
        mac = _mac_val(v)
        if mac and mac != "00:00:00:00:00:00" and not any(o[0] == ip and o[1] == mac for o in out):
            out.append((ip, mac, ifx))
    return out


def parse_fdb(cols, vlan=None):
    """جدول MAC ← [(mac، vlan یا fdbId، bridgePort)]؛ رکوردهای self (MAC خود سوییچ) حذف."""
    out = []
    qst = cols.get(OID["qfdb_st"]) or {}
    fdb_vlan = {}
    for idx, fid in (cols.get(OID["qvlan_fdb"]) or {}).items():
        p = idx.split(".")
        if len(p) == 2:
            try:
                fdb_vlan.setdefault(int(fid), int(p[1]))
            except (TypeError, ValueError):
                pass
    for idx, port in (cols.get(OID["qfdb"]) or {}).items():
        p = idx.split(".")
        mac = _mac_from_idx(p[1:]) if len(p) == 7 else None
        if not mac or qst.get(idx) == 4 or not port:
            continue
        fid = int(p[0])
        out.append((mac, fdb_vlan.get(fid, fid), int(port)))
    st = cols.get(OID["fdb_st"]) or {}
    for idx, port in (cols.get(OID["fdb"]) or {}).items():
        mac = _mac_from_idx(idx.split("."))
        if not mac or st.get(idx) == 4 or not port:
            continue
        out.append((mac, vlan, int(port)))
    return out


def _vlans(cols):
    out = []
    for idx, stt in (cols.get(OID["vtp_state"]) or {}).items():
        p = idx.split(".")
        try:
            v = int(p[-1])
        except ValueError:
            continue
        if stt == 1 and not 1002 <= v <= 1005:
            out.append(v)
    return sorted(set(out))[:MAX_VLANS]


def vlan_cred(cred, vlan):
    """Cisco Community String Indexing: v2c «community@VLAN»، v3 context «vlan-VLAN»."""
    if cred.get("v") == "3":
        return {**cred, "ctx": f"vlan-{vlan}"}
    return {**cred, "community": f"{cred.get('community') or ''}@{vlan}"}


def collect_device(client, cred, host, port, timeout, need_arp, need_fdb):
    """یک دستگاه: (sys، arp، fdb، ifnames، errors). fdb = [(mac، vlan، ifIndex یا None، bridgePort)]"""
    errs = []
    run = lambda coro, t=120: client.run(coro, t)
    g = run(client.aget(cred, host, port, [OID["sysName"], OID["sysObjectID"]], timeout, 1), 30)
    sysn = {"name": g.get(OID["sysName"]) or "", "oid": g.get(OID["sysObjectID"]) or ""}
    arp, fdb = [], []
    if need_arp:
        try:
            arp = parse_arp(run(client.awalk(cred, host, port, [OID["arp"], OID["arp_type"], OID["arp2"]], timeout, 1, ROWS)))
        except Exception as e:  # noqa
            errs.append(f"ARP: {str(e)[:150]}")
    if need_fdb:
        try:
            cols = run(client.awalk(cred, host, port, [OID["qfdb"], OID["qfdb_st"], OID["qvlan_fdb"], OID["fdb"],
                                                       OID["fdb_st"], OID["bport"]], timeout, 1, ROWS), 240)
            bport = {int(k): v for k, v in (cols.get(OID["bport"]) or {}).items() if k.isdigit()}
            rows = parse_fdb(cols)
            fdb = [(m, v, bport.get(bp), bp) for m, v, bp in rows]
            if str(sysn["oid"]).startswith("1.3.6.1.4.1.9.") and not cols.get(OID["qfdb"]):
                vl = run(client.awalk(cred, host, port, [OID["vtp_state"]], timeout, 1, 4096))
                seen = {(m, bp) for m, _, _, bp in fdb}
                for v in _vlans(vl):
                    try:
                        c2 = run(client.awalk(vlan_cred(cred, v), host, port, [OID["fdb"], OID["fdb_st"], OID["bport"]],
                                              timeout, 0, ROWS), 120)
                    except Exception as e:  # noqa — VLAN بدون پورت یا بدون دسترسی
                        errs.append(f"VLAN {v}: {str(e)[:100]}")
                        continue
                    bp2 = {int(k): x for k, x in (c2.get(OID["bport"]) or {}).items() if k.isdigit()}
                    for m, _, bp in parse_fdb(c2, v):
                        if (m, bp) in seen and v == 1:
                            continue
                        fdb.append((m, v, bp2.get(bp), bp))
                fdb = _dedupe_fdb(fdb)
        except Exception as e:  # noqa
            errs.append(f"MAC: {str(e)[:150]}")
    names = {}
    try:
        c = run(client.awalk(cred, host, port, [OID["ifName"], OID["ifDescr"], OID["ifAlias"]], timeout, 1, 20000))
        for idx, v in (c.get(OID["ifDescr"]) or {}).items():
            names.setdefault(int(idx), {})["descr"] = str(v)
        for idx, v in (c.get(OID["ifName"]) or {}).items():
            names.setdefault(int(idx), {})["name"] = str(v)
        for idx, v in (c.get(OID["ifAlias"]) or {}).items():
            if v:
                names.setdefault(int(idx), {})["alias"] = str(v)
    except Exception as e:  # noqa
        errs.append(f"IF-MIB: {str(e)[:120]}")
    return sysn, arp, fdb, names, errs


def _dedupe_fdb(fdb):
    best = {}
    for m, v, ifx, bp in fdb:
        k = (m, ifx if ifx is not None else f"bp{bp}")
        if k not in best or (best[k][1] in (None, 1) and v not in (None, 1)):
            best[k] = (m, v, ifx, bp)
    return list(best.values())


def locate(job, query, targets, cred_for, client, uplinks=None, demo=False):
    """targets: [{id، name، host، port، timeout}]؛ uplinks: {target_id: {نام پورت‌های دارای همسایه‌ی LLDP/CDP}}"""
    q = str(query or "").strip()
    mac_q = norm_mac(q)
    ip_q = None
    if not mac_q:
        try:
            ip_q = str(ipaddress.ip_address(q))
        except ValueError:
            raise NetError("یک آدرس IP یا MAC وارد کنید (مثل 10.1.2.3 یا aa:bb:cc:dd:ee:ff یا aabb.ccdd.eeff).")
    if not targets:
        raise NetError("هیچ دستگاه SNMP برای جستجو انتخاب نشده است (هدف‌های SNMP مانیتورینگ).")
    uplinks = uplinks or {}
    job["progress"] = [0, len(targets)]
    data, errors = {}, {}

    def one(t):
        if job["cancel"].is_set():
            return
        try:
            if demo:
                data[t["id"]] = _demo_device(targets.index(t), len(targets), ip_q, mac_q)
            else:
                data[t["id"]] = collect_device(client, cred_for(t), t["host"], t.get("port") or 161,
                                               float(t.get("timeout") or 3), True, True)
            if data[t["id"]][4]:
                errors[t["name"]] = data[t["id"]][4][:4]
        except Exception as e:  # noqa
            errors[t["name"]] = [str(e)[:200]]
        finally:
            job["progress"][0] += 1
            job["lines"].append(f"{t['name']} ({t['host']})")
    with ThreadPoolExecutor(max_workers=4) as ex:
        list(ex.map(one, targets))
    byid = {t["id"]: t for t in targets}
    # ۱) IP ← MAC از جدول ARP همه‌ی دستگاه‌ها
    arp_hits = []
    for tid, (sysn, arp, fdb, names, _) in data.items():
        for ip, mac, ifx in arp:
            if (ip_q and ip == ip_q) or (mac_q and mac == mac_q):
                arp_hits.append({"device": byid[tid]["name"], "device_id": tid, "ip": ip, "mac": mac,
                                 "port": _ifname(names, ifx)})
    macs = [mac_q] if mac_q else sorted({h["mac"] for h in arp_hits})
    # ۲) MAC ← پورت از جدول MAC سوییچ‌ها
    fdb_hits = []
    for tid, (sysn, arp, fdb, names, _) in data.items():
        cnt = {}
        for m, v, ifx, bp in fdb:
            cnt[(ifx, bp)] = cnt.get((ifx, bp), 0) + 1
        for m, v, ifx, bp in fdb:
            if m in macs:
                pn = _ifname(names, ifx) if ifx is not None else f"bridge-port {bp}"
                up = pn in (uplinks.get(tid) or set())
                n = cnt[(ifx, bp)]
                fdb_hits.append({"device": byid[tid]["name"], "device_id": tid, "host": byid[tid]["host"], "mac": m,
                                 "vlan": v, "port": pn, "alias": (names.get(ifx) or {}).get("alias", "") if ifx is not None else "",
                                 "macs_on_port": n, "uplink": up, "edge": (not up) and n <= EDGE_MACS})
    fdb_hits.sort(key=lambda h: (not h["edge"], h["uplink"], h["macs_on_port"], h["device"]))
    best = fdb_hits[0] if fdb_hits and fdb_hits[0]["edge"] else None
    return {"query": q, "kind": "mac" if mac_q else "ip", "macs": [{"mac": m, "vendor": OUI.lookup(m)} for m in macs],
            "arp": arp_hits, "fdb": fdb_hits[:500], "best": best, "errors": errors, "scanned": len(targets),
            "cancelled": job["cancel"].is_set()}


def _ifname(names, ifx):
    n = names.get(ifx) or {}
    return n.get("name") or n.get("descr") or (f"ifIndex {ifx}" if ifx is not None else "")


def _demo_device(i, n, ip_q, mac_q):
    """داده‌ی ساختگی Demo: دستگاه اول ARP دارد، دستگاه دوم MAC را روی یک پورت دسترسی می‌بیند، بقیه روی uplink.
    با یک دستگاه، همان یکی هر دو را دارد."""
    mac = mac_q or "00:1b:54:3c:9a:10"
    ip = ip_q or "10.20.30.44"
    k = i % 3 if n > 1 else -1
    names = {1: {"name": "Gi1/0/1", "alias": "Uplink-Core"}, 7: {"name": "Gi1/0/7", "alias": "Room 204"}}
    arp = [(ip, mac, 1)] if k in (0, -1) else []
    fdb = [(mac, 30, 7, 7)] if k in (1, -1) else [(mac, 30, 1, 1)] + [(f"00:00:5e:00:01:{x:02x}", 30, 1, 1) for x in range(40)]
    return {"name": f"demo{i}"}, arp, fdb, names, []
