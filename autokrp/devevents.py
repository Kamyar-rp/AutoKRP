"""رخدادهای دستگاه (1.25): دریافت SNMP Trap (UDP، v1/v2c و Inform) و Syslog (UDP و TCP).

- فهرست Trapها، OID، اشیاء و enumها از trapdb.json (ساخته‌شده از فایل‌های MIB واقعی با dev/trapdb_build.py)؛ Trap ناشناخته
  با OID عددی ذخیره می‌شود.
- Syslog: سرآیند RFC 5424 و RFC 3164 (BSD)، پیام سیسکو «%FACILITY-SEVERITY-MNEMONIC:» (راهنمای System Message سیسکو)،
  لاگ key=value فورتی‌گیت (FortiOS Log Reference: logid، type، subtype، level، msg). قالب‌های دیگر خام ذخیره می‌شوند.
- فقط از منبع‌های شناخته (آدرس هدف‌های مانیتورینگ یا رنج‌های تعریف‌شده) پذیرفته می‌شود مگر «پذیرش منبع ناشناخته» روشن باشد.
- ذخیره: فایل روزانه‌ی رمزشده monitor/events/e_YYYYMMDD.log (بدون پاک شدن، مثل بقیه‌ی مانیتورینگ؛ سقف اختیاری).
- هشدار: سطح «بحرانی» (یا قاعده‌ی کاربر) برای منبعی که هدف مانیتورینگ است ← همان هشدار مانیتورینگ (بنر، صدا، ایمیل)،
  مگر هدف در پنجره‌ی نگهداری یا «در دسترس نیست» باشد. هر کلید حداکثر هر ۵ دقیقه یک هشدار.
"""
import ipaddress
import json
import logging
import re
import socket
import socketserver
import threading
import time
from collections import deque
from pathlib import Path

from . import atrest

log = logging.getLogger(__name__)
DEFAULTS = {"trap_enabled": False, "trap_port": 162, "syslog_enabled": False, "syslog_port": 514, "syslog_tcp": True,
            "bind": "0.0.0.0", "allow_unknown": False, "sources": [], "communities": [], "min_store": 6,  # nosec B104 — گیرنده باید روی شبکه بشنود
            "forti_traffic": False, "alert_level": "crit", "rules": [], "keep_days": 0}
SEV_RANK = {"crit": 0, "warn": 1, "info": 2, "ok": 3}
MAX_MSG = 8192
RATE = 200                      # حداکثر پیام در ثانیه از هر منبع (بقیه شمرده و دور ریخته می‌شود)
DAY_CAP = 500_000               # حداکثر رکورد ذخیره‌شده از هر منبع در روز (دیسک با یک دستگاه پرحرف یا جعل پر نشود)
TCP_MAX, TCP_PER_IP = 200, 20   # اتصال هم‌زمان Syslog/TCP
SCAN_CAP = 2_000_000            # حداکثر خطی که یک جستجو می‌خواند
ALERT_GAP = 300
TRAP_OID = "1.3.6.1.6.3.1.1.4.1.0"
UPTIME_OID = "1.3.6.1.2.1.1.3.0"
GENERIC = ["coldStart", "warmStart", "linkDown", "linkUp", "authenticationFailure", "egpNeighborLoss"]
_DB = None


def trapdb():
    global _DB
    if _DB is None:
        try:
            _DB = json.loads((Path(__file__).with_name("trapdb.json")).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            log.exception("trapdb.json")
            _DB = {"traps": {}, "objs": {}}
    return _DB


def cfg_of(settings):
    c = dict(DEFAULTS)
    c.update({k: v for k, v in (settings.get("events") or {}).items() if k in DEFAULTS})
    return c


class EventsError(Exception):
    pass


def clean_cfg(c):
    c = {**DEFAULTS, **{k: v for k, v in (c or {}).items() if k in DEFAULTS}}
    for k in ("trap_enabled", "syslog_enabled", "syslog_tcp", "allow_unknown", "forti_traffic"):
        c[k] = bool(c[k])
    for k in ("trap_port", "syslog_port"):
        try:
            c[k] = int(c[k])
            if not 0 < c[k] < 65536:
                raise ValueError
        except (TypeError, ValueError):
            raise EventsError("پورت نامعتبر است.") from None
    if c["trap_enabled"] and c["syslog_enabled"] and c["trap_port"] == c["syslog_port"]:
        raise EventsError("پورت Trap و Syslog یکی است.")
    try:
        ipaddress.ip_address(str(c["bind"]).strip())
    except ValueError:
        raise EventsError("آدرس bind نامعتبر است (مثلاً 0.0.0.0).") from None
    c["bind"] = str(c["bind"]).strip()
    src = []
    for x in c["sources"] if isinstance(c["sources"], list) else re.split(r"[\s,]+", str(c["sources"] or "")):
        x = str(x).strip()
        if not x:
            continue
        try:
            src.append(str(ipaddress.ip_network(x, strict=False)))
        except ValueError:
            raise EventsError(f"رنج نامعتبر: {x}") from None
    c["sources"] = src[:200]
    com = [str(x).strip() for x in (c["communities"] if isinstance(c["communities"], list) else str(c["communities"] or "").split("\n"))]
    c["communities"] = [x for x in com if x and len(x) <= 128][:50]
    try:
        c["min_store"] = max(0, min(7, int(c["min_store"])))
    except (TypeError, ValueError):
        c["min_store"] = 6
    c["alert_level"] = c["alert_level"] if c["alert_level"] in ("crit", "warn", "none") else "crit"
    rules = []
    for r in c["rules"] if isinstance(c["rules"], list) else []:
        pat, lv = str((r or {}).get("match") or "").strip(), (r or {}).get("level")
        if not pat:
            continue
        if len(pat) > 200 or lv not in ("crit", "warn", "info", "ignore"):
            raise EventsError(f"قاعده‌ی نامعتبر: {pat[:40]}")
        try:
            re.compile(pat, re.I)
        except re.error as e:
            raise EventsError(f"الگوی نامعتبر «{pat[:40]}»: {e}") from None
        rules.append({"match": pat, "level": lv})
    c["rules"] = rules[:100]
    try:
        c["keep_days"] = max(0, int(c["keep_days"] or 0))
        if c["keep_days"]:
            c["keep_days"] = max(30, c["keep_days"])
    except (TypeError, ValueError):
        c["keep_days"] = 0
    return c


# ---------------------------------------------------------------------------- Syslog
PRI_RE = re.compile(r"^<(\d{1,3})>")
R5424 = re.compile(r"^1 (\S+) (\S+) (\S+) (\S+) (\S+) (-|(?:\[(?:[^\]\\]|\\.)*\])+)\s?(.*)$", re.S)
R3164 = re.compile(r"^([A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+(\S+)\s+(.*)$", re.S)
CISCO = re.compile(r"%([A-Z0-9_]+(?:-[A-Z0-9_]+)*)-(\d)-([A-Z0-9_]+):\s*(.*)$", re.S)
KV = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|\S+)')
TAG = re.compile(r"^([A-Za-z0-9_./-]{1,48})(?:\[(\d+)\])?:\s*(.*)$", re.S)
SYS_SEV = ["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"]
FORTI_LEVEL = {"emergency": 0, "alert": 1, "critical": 2, "error": 3, "warning": 4, "notice": 5, "information": 6, "debug": 7}


def sev_of(n):
    """شدت syslog (۰ تا ۷) ← سطح برنامه."""
    return "crit" if n <= 2 else "warn" if n <= 4 else "info"


def parse_syslog(raw):
    """dict: sev (۰–۷)، fac، host، app، name (شناسه‌ی پیام)، msg، vendor، kv (فورتی‌گیت)."""
    s = raw.decode("utf-8", "replace") if isinstance(raw, (bytes, bytearray)) else str(raw)
    s = s.replace("\x00", "").strip()[:MAX_MSG]
    if s.startswith("﻿"):
        s = s[1:]
    out = {"sev": 5, "fac": 1, "host": "", "app": "", "name": "", "msg": s, "vendor": ""}
    m = PRI_RE.match(s)
    if m and int(m.group(1)) <= 191:
        pri = int(m.group(1))
        out["fac"], out["sev"] = pri >> 3, pri & 7
        s = s[m.end():]
    m = R5424.match(s)
    if m:
        out["host"] = "" if m.group(2) == "-" else m.group(2)
        out["app"] = "" if m.group(3) == "-" else m.group(3)
        out["name"] = "" if m.group(5) == "-" else m.group(5)
        body = m.group(7).lstrip("﻿")
        if m.group(6) != "-":
            out["sd"] = m.group(6)[:1000]
        s = body
    else:
        m = R3164.match(s)
        if m:
            out["host"], s = m.group(2), m.group(3)
        t = TAG.match(s)
        if t and not CISCO.match(s):
            out["app"], s = t.group(1), t.group(3)
    c = CISCO.search(s)
    if c:
        out.update(vendor="cisco", name=f"{c.group(1)}-{c.group(2)}-{c.group(3)}", sev=int(c.group(2)), msg=c.group(4).strip())
        return out
    if "logid=" in s and ("devname=" in s or "devid=" in s):
        kv = {k: v.strip('"') for k, v in KV.findall(s)}
        out.update(vendor="fortinet", kv={k: kv[k] for k in list(kv)[:60]},
                   name=f"{kv.get('type', '')}/{kv.get('subtype', '')} {kv.get('logid', '')}".strip(),
                   msg=kv.get("msg") or kv.get("logdesc") or s)
        if kv.get("level") in FORTI_LEVEL:
            out["sev"] = FORTI_LEVEL[kv["level"]]
        if kv.get("devname"):
            out["host"] = kv["devname"]
        return out
    out["msg"] = s.strip()
    return out


# ---------------------------------------------------------------------------- Trap
def _val(v):
    """مقدار pyasn1 ← متن قابل نمایش."""
    try:
        name = v.__class__.__name__
        if name in ("OctetString", "Opaque"):
            b = bytes(v)
            try:
                t = b.decode("utf-8")
                if t.isprintable():
                    return t
            except UnicodeDecodeError:
                pass
            return "0x" + b.hex()
        if name == "IpAddress":
            return ".".join(str(x) for x in bytes(v))
        if name == "ObjectIdentifier":
            return ".".join(str(x) for x in v)
        if name in ("Integer", "Integer32", "Counter32", "Counter64", "Gauge32", "Unsigned32", "TimeTicks"):
            return int(v)
        return v.prettyPrint()
    except Exception:  # noqa — مقدار عجیب
        return str(v)[:500]


def oid_name(oid):
    """نام شیء MIB از trapdb (با اندیس): 1.3.6.1.2.1.2.2.1.2.5 ← ifDescr.5"""
    objs = trapdb()["objs"]
    parts = oid.split(".")
    for i in range(len(parts), 6, -1):
        base = ".".join(parts[:i])
        if base in objs:
            suf = ".".join(parts[i:])
            return objs[base]["n"] + ("." + suf if suf else ""), objs[base]
    fixed = {"1.3.6.1.2.1.1.3.0": "sysUpTime.0", "1.3.6.1.6.3.1.1.4.1.0": "snmpTrapOID.0",
             "1.3.6.1.6.3.18.1.3.0": "snmpTrapAddress.0", "1.3.6.1.6.3.18.1.4.0": "snmpTrapCommunity.0"}
    if oid in fixed:
        return fixed[oid], None
    try:                                  # 1.27: MIBهای کتابخانه (استاندارد + بارگذاری‌شده‌ی کاربر)
        from .mibs import LIB
        e, rest = LIB.lookup(oid)
        if e and e.get("k") in ("s", "c"):
            return e["n"] + ("." + rest if rest else ""), {"e": {str(k): v for k, v in (e.get("e") or {}).items()}}
    except Exception:  # noqa — نام اختیاری است
        pass
    return oid, None


def decode_trap(data):
    """بسته‌ی UDP ← dict یا None (نه Trap). v3 پشتیبانی نمی‌شود (ProtocolError)."""
    from pyasn1.codec.ber import decoder
    from pysnmp.proto import api
    ver = int(api.decodeMessageVersion(data))
    if ver not in api.PROTOCOL_MODULES:
        raise ValueError("نسخه‌ی SNMP پشتیبانی نمی‌شود (فقط v1 و v2c)")
    pm = api.PROTOCOL_MODULES[ver]
    msg, _ = decoder.decode(data, asn1Spec=pm.Message())
    pdu = pm.apiMessage.get_pdu(msg)
    community = bytes(pm.apiMessage.get_community(msg)).decode("utf-8", "replace")
    inform = ver == 1 and pdu.isSameTypeWith(pm.InformRequestPDU())
    if not (pdu.isSameTypeWith(pm.TrapPDU()) or inform):
        return None
    vbs = []
    if ver == 0:
        ent = ".".join(str(x) for x in pm.apiTrapPDU.get_enterprise(pdu))
        gen, spec = int(pm.apiTrapPDU.get_generic_trap(pdu)), int(pm.apiTrapPDU.get_specific_trap(pdu))
        trap_oid = f"1.3.6.1.6.3.1.1.5.{gen + 1}" if gen < 6 else f"{ent}.0.{spec}"      # RFC 3584 بخش 3.1
        agent = ".".join(str(x) for x in bytes(pm.apiTrapPDU.get_agent_address(pdu)))
        for o, v in pm.apiTrapPDU.get_varbinds(pdu):
            vbs.append((".".join(str(x) for x in o), _val(v)))
    else:
        trap_oid, agent = "", ""
        for o, v in pm.apiPDU.get_varbinds(pdu):
            oid = ".".join(str(x) for x in o)
            if oid == TRAP_OID:
                trap_oid = _val(v)
            elif oid != UPTIME_OID:
                vbs.append((oid, _val(v)))
    resp = None
    if inform:
        r = pm.apiMessage.get_response(msg)
        from pyasn1.codec.ber import encoder
        resp = encoder.encode(r)
    return {"ver": "1" if ver == 0 else "2c", "community": community, "oid": trap_oid, "agent": agent, "vbs": vbs, "inform": inform,
            "resp": resp}


def describe_trap(t):
    """نام، سطح، سازنده و متن خوانا از trapdb."""
    db = trapdb()["traps"].get(t["oid"]) or {}
    if not db:
        try:                              # 1.27: Trap سازنده از MIB بارگذاری‌شده (NOTIFICATION-TYPE / TRAP-TYPE)
            from .mibs import LIB, trap_level
            e = LIB.trap(t["oid"])
            if e:
                db = {"n": e["n"], "m": e["m"], "d": e.get("d", ""), "s": trap_level(e["n"])}
        except Exception:  # noqa
            db = {}
    name = db.get("n") or {f"1.3.6.1.6.3.1.1.5.{i + 1}": g for i, g in enumerate(GENERIC)}.get(t["oid"]) or t["oid"]
    sev = db.get("s") or ("warn" if name in ("coldStart", "warmStart", "linkDown", "authenticationFailure") else
                          "ok" if name == "linkUp" else "info")
    parts = []
    for oid, v in t["vbs"][:20]:
        n, o = oid_name(oid)
        if o and o.get("e") and str(v) in o["e"]:
            v = f"{o['e'][str(v)]}({v})"
        parts.append(f"{n}={v}")
    msg = (db.get("d") or "") if not parts else "، ".join(str(x) for x in parts)
    return {"name": name, "sev": sev, "vendor": db.get("v") or "", "module": db.get("m") or "", "msg": msg[:2000],
            "descr": db.get("d") or ""}


# ---------------------------------------------------------------------------- مدیریت
class _TCPHandler(socketserver.StreamRequestHandler):
    timeout = 300

    def handle(self):
        mgr, ip = self.server.mgr, self.client_address[0]
        buf = b""
        while not mgr.stop_ev.is_set():
            try:
                chunk = self.request.recv(65536)
            except OSError:
                return
            if not chunk:
                return
            buf += chunk
            while buf:
                m = re.match(rb"^(\d{1,6}) (?=<)", buf)       # RFC 6587: octet counting (پیام syslog با «<» شروع می‌شود)
                if m:
                    n = int(m.group(1))
                    if n > MAX_MSG * 4:
                        return
                    if len(buf) < m.end() + n:
                        break
                    msg, buf = buf[m.end():m.end() + n], buf[m.end() + n:]
                else:
                    i = buf.find(b"\n")
                    if i < 0:
                        if len(buf) > MAX_MSG * 4:
                            return
                        break
                    msg, buf = buf[:i], buf[i + 1:]
                if msg.strip():
                    mgr.on_syslog(msg, ip)


class _TCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 64

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self._cl = threading.Lock()
        self._conns = {}

    def verify_request(self, request, client_address):
        """منبع ناشناخته همان لحظه رد؛ سقف اتصال کل و هر IP (بدون ترد برای هر اتصال اضافه)."""
        ip = client_address[0]
        if not self.mgr._accept(ip)[1]:
            self.mgr.stats["dropped_unknown"] += 1
            return False
        with self._cl:
            if sum(self._conns.values()) >= TCP_MAX or self._conns.get(ip, 0) >= TCP_PER_IP:
                self.mgr.stats["dropped_rate"] += 1
                return False
            self._conns[ip] = self._conns.get(ip, 0) + 1
        return True

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            with self._cl:
                ip = client_address[0]
                self._conns[ip] = self._conns.get(ip, 1) - 1
                if self._conns[ip] <= 0:
                    self._conns.pop(ip, None)


class DevEvents:
    def __init__(self, monitor):
        self.mon = monitor
        self.settings = monitor.settings
        self.stop_ev = threading.Event()
        self._threads, self._socks, self._tcp = [], [], None
        self._lock = threading.Lock()
        self._rate = {}                    # ip ← [ثانیه، تعداد]
        self._day = {}                     # ip ← [روز، تعداد ذخیره‌شده]
        self._wlock = threading.Lock()     # نوشتن هم‌زمان چند ترد (UDP/TCP) در یک فایل روزانه
        self._qlock = threading.Lock()     # یک جستجوی سنگین در هر لحظه
        self._last_alert = {}
        self._src_map, self._src_at = {}, 0
        self.stats = {"trap": 0, "syslog": 0, "dropped_unknown": 0, "dropped_rate": 0, "dropped_auth": 0, "errors": 0, "started": None}
        self.status = {"trap": "off", "syslog": "off"}
        self.recent = deque(maxlen=50)

    def cfg(self):
        return cfg_of(self.settings)

    # ---- چرخه
    def start(self):
        self.stop()
        self.stop_ev = threading.Event()
        c = self.cfg()
        if c["trap_enabled"]:
            self._udp("trap", c["bind"], c["trap_port"], self._on_trap_pkt)
        if c["syslog_enabled"]:
            self._udp("syslog", c["bind"], c["syslog_port"], lambda d, a, s: self.on_syslog(d, a[0]))
            if c["syslog_tcp"]:
                try:
                    srv = _TCPServer((c["bind"], c["syslog_port"]), _TCPHandler)
                    srv.mgr = self
                    self._tcp = srv
                    th = threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.5}, name="syslog-tcp", daemon=True)
                    th.start()
                    self._threads.append(th)
                except OSError as e:
                    self.status["syslog"] += f"؛ TCP: {e}"
        self.stats["started"] = time.time()

    def stop(self):
        self.stop_ev.set()
        for s in self._socks:
            try:
                s.close()
            except OSError:
                pass
        if self._tcp:
            try:
                self._tcp.shutdown()
                self._tcp.server_close()
            except OSError:
                pass
        self._socks, self._tcp, self._threads = [], None, []
        self.status = {"trap": "off", "syslog": "off"}

    def _udp(self, kind, bind, port, handler):
        try:
            fam = socket.AF_INET6 if ":" in bind else socket.AF_INET
            s = socket.socket(fam, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
            s.bind((bind, port))
            s.settimeout(0.5)
        except OSError as e:
            self.status[kind] = f"خطا در باز کردن پورت UDP {port}: {e}"
            log.error("%s: %s", kind, self.status[kind])
            return
        self._socks.append(s)
        self.status[kind] = f"در حال شنیدن روی UDP {bind}:{port}"
        stop = self.stop_ev

        def loop():
            while not stop.is_set():
                try:
                    data, addr = s.recvfrom(65535)
                except socket.timeout:
                    continue
                except OSError:
                    return
                try:
                    handler(data, addr, s)
                except Exception:  # noqa — یک بسته‌ی خراب گیرنده را متوقف نکند
                    self.stats["errors"] += 1
                    log.debug("event packet", exc_info=True)
        th = threading.Thread(target=loop, name=f"{kind}-udp", daemon=True)
        th.start()
        self._threads.append(th)

    # ---- منبع
    def _sources(self):
        """آدرس هدف‌های مانیتورینگ ← هدف (نام میزبان یک بار resolve، هر ۱۰ دقیقه تازه).
        تازه کردن در ترد جدا تا DNS کند ترد دریافت را معطل نکند (تا آماده شدن، نقشه‌ی قبلی)."""
        if (time.time() - self._src_at > 600 or not self._src_map) and not getattr(self, "_src_busy", False):
            if self._src_map:
                self._src_busy = True
                threading.Thread(target=self._sources_build, name="events-dns", daemon=True).start()
            else:
                self._sources_build()
        return self._src_map

    def _sources_build(self):
        try:
            m = {}
            for t in self.mon.targets().values():
                h = t.get("host") or ""
                try:
                    ips = {ipaddress.ip_address(h).compressed}
                except ValueError:
                    try:
                        ips = {ai[4][0] for ai in socket.getaddrinfo(h, None)} if h else set()
                    except OSError:
                        ips = set()
                for ip in ips:
                    m.setdefault(ip, []).append(t["id"])
            self._src_map, self._src_at = m, time.time()
        finally:
            self._src_busy = False

    def invalidate(self):
        self._src_at = 0

    def _accept(self, ip):
        """(target یا None، پذیرفته؟)"""
        ip = ip.split("%")[0]
        if ip.startswith("::ffff:"):
            ip = ip[7:]
        tids = self._sources().get(ip) or []
        t = self.mon.targets().get(tids[0]) if tids else None
        if t:
            return t, True
        c = self.cfg()
        try:
            a = ipaddress.ip_address(ip)
            if any(a in ipaddress.ip_network(n) for n in c["sources"]):
                return None, True
        except ValueError:
            return None, False
        return None, bool(c["allow_unknown"])

    def _rate_ok(self, ip):
        now = int(time.time())
        with self._lock:
            r = self._rate.get(ip)
            if not r or r[0] != now:
                if len(self._rate) > 5000:
                    self._rate.clear()
                self._rate[ip] = [now, 1]
                return True
            r[1] += 1
            return r[1] <= RATE

    # ---- ورودی‌ها
    def _on_trap_pkt(self, data, addr, sock):
        ip = addr[0]
        t, ok = self._accept(ip)
        if not ok:
            self.stats["dropped_unknown"] += 1
            return
        if not self._rate_ok(ip):
            self.stats["dropped_rate"] += 1
            return
        tr = decode_trap(data)
        if not tr:
            return
        if not self._community_ok(t, tr["community"]):
            self.stats["dropped_auth"] += 1
            return
        if tr["resp"]:
            try:
                sock.sendto(tr["resp"], addr)
            except OSError:
                pass
        d = describe_trap(tr)
        for r in self.cfg()["rules"]:                 # قاعده‌های کاربر برای Trap هم (روی نام و متن)
            if re.search(r["match"], f"{d['name']} {d['msg']}", re.I):
                d["sev"] = r["level"]
                break
        if d["sev"] == "ignore":
            return
        self.stats["trap"] += 1
        self._record({"k": "trap", "src": ip, "agent": tr["agent"] if tr["agent"] not in ("", "0.0.0.0", ip) else "",  # nosec B104 — مقایسه، نه bind
                      "ver": tr["ver"], "oid": tr["oid"], "name": d["name"], "sev": d["sev"], "vendor": d["vendor"], "msg": d["msg"],
                      "vbs": [[o, v] for o, v in tr["vbs"][:40]]}, t)

    def _community_ok(self, t, community):
        """اگر هدف پروفایل SNMP v2c دارد یا community سراسری تعریف شده، باید یکی باشد؛ وگرنه منبع شناخته کافی است."""
        allowed = set(self.cfg()["communities"])
        if t and t.get("cred_id"):
            try:
                from .snmp import cred_from_vault
                cr = cred_from_vault(self.settings.vault, t["cred_id"])
                if cr.get("v") == "2c" and cr.get("community"):
                    allowed.add(cr["community"])
            except Exception:  # noqa
                pass
        return not allowed or community in allowed

    def on_syslog(self, data, ip):
        t, ok = self._accept(ip)
        if not ok:
            self.stats["dropped_unknown"] += 1
            return
        if not self._rate_ok(ip):
            self.stats["dropped_rate"] += 1
            return
        p = parse_syslog(data)
        c = self.cfg()
        if p.get("vendor") == "fortinet" and not c["forti_traffic"] and (p.get("kv") or {}).get("type") in ("traffic", "utm"):
            return                    # لاگ ترافیک/UTM فورتی‌گیت حجم زیاد دارد؛ پیش‌فرض ذخیره نمی‌شود
        level = sev_of(p["sev"])
        for r in c["rules"]:
            if re.search(r["match"], f"{p['name']} {p['msg']}", re.I):
                level = r["level"]
                break
        if level == "ignore":
            return
        if p["sev"] > c["min_store"] and level not in ("crit", "warn"):
            return
        self.stats["syslog"] += 1
        self._record({"k": "syslog", "src": ip, "sev": level, "pri": p["sev"], "fac": p["fac"], "host": p["host"][:120],
                      "app": p["app"][:60], "name": p["name"][:120], "vendor": p["vendor"], "msg": p["msg"][:MAX_MSG]}, t)

    # ---- ذخیره و هشدار
    def _record(self, rec, t):
        now = time.time()
        day = int(now // 86400)
        with self._lock:
            c = self._day.get(rec["src"])
            if not c or c[0] != day:
                if len(self._day) > 5000:
                    self._day.clear()
                c = self._day[rec["src"]] = [day, 0]
            c[1] += 1
            if c[1] > DAY_CAP:
                self.stats["dropped_cap"] = self.stats.get("dropped_cap", 0) + 1
                return
        rec["t"] = round(now, 3)
        if t:
            rec["tid"], rec["tname"] = t["id"], t.get("name") or t["host"]
        try:
            from . import tsdb                  # 1.35: فایل روزانه‌ی رمزشده یا جدول akrp_ev در MySQL (محل ذخیره‌ی مانیتورینگ)
            with self._wlock:
                tsdb.store().put([("ev", 0, rec)])
        except Exception:  # noqa
            self.stats["errors"] += 1
            log.exception("event write")
        self.recent.appendleft({k: rec[k] for k in ("t", "k", "src", "sev", "name", "msg") if k in rec} | {"tname": rec.get("tname", "")})
        self._maybe_alert(rec, t)

    def _maybe_alert(self, rec, t):
        lvl = self.cfg()["alert_level"]
        if lvl == "none" or SEV_RANK.get(rec["sev"], 9) > SEV_RANK.get(lvl, 0):
            return
        src = rec.get("tname") or rec["src"]
        what = "Trap" if rec["k"] == "trap" else "Syslog"
        msg = f"«{src}» {what}: {rec.get('name') or ''} — {rec.get('msg', '')[:300]}"
        if not t:
            self.mon.emit("warn" if rec["sev"] == "warn" else "error", msg, "monitor")
            return
        st = self.mon.state.get(t["id"]) or {}
        if st.get("maint") or st.get("status") == "unreachable":
            self.mon.emit("info", msg + " (در نگهداری / به‌خاطر پدر؛ بدون هشدار)", "monitor")
            return
        key = f"{rec['k']}:{rec.get('name') or rec.get('oid') or ''}"
        now = time.time()
        with self._lock:
            if now - self._last_alert.get((t["id"], key), 0) < ALERT_GAP:
                return
            self._last_alert[(t["id"], key)] = now
        self.mon.emit("error" if rec["sev"] == "crit" else "warn", msg, "monitor")
        if self.mon.history:
            self.mon.history("monitor", t.get("name") or t["host"], "error" if rec["sev"] == "crit" else "warn", f"{what}: {rec.get('name')} — {rec.get('msg', '')[:300]}",
                             t.get("owner") or "")
        if rec["sev"] == "crit":
            if t.get("notify"):
                self.mon.notify("dev_event", msg)
            self.mon._alert(t, "alarm", msg, key)

    # ---- خواندن برای رابط
    def query(self, since, until, kinds=None, sev=None, q="", src=None, tids=None, limit=2000):
        """جدیدترین‌ها اول؛ فقط فایل‌های روزانه‌ی همان بازه، خط‌به‌خط (حافظه‌ی محدود: حداکثر limit ردیف)،
        حداکثر SCAN_CAP خط در هر جستجو و یک جستجو در هر لحظه (کاربر فقط‌خواندنی هم می‌تواند جستجو کند)."""
        from . import tsdb
        S = tsdb.store()
        out, counts, total, scanned, partial = [], {"trap": 0, "syslog": 0, "crit": 0, "warn": 0, "info": 0, "ok": 0}, 0, 0, False
        ql = (q or "").lower()
        if not self._qlock.acquire(timeout=30):
            raise EventsError("جستجوی دیگری در حال اجراست؛ کمی بعد دوباره امتحان کنید.")
        try:
            def keep(r, line_l):
                nonlocal total
                if not since <= r.get("t", 0) <= until:
                    return False
                if kinds and r.get("k") not in kinds:
                    return False
                if tids is not None and r.get("tid") not in tids:
                    return False
                if src and r.get("src") != src:
                    return False
                if ql and ql not in line_l:
                    return False
                counts[r.get("k")] = counts.get(r.get("k"), 0) + 1
                counts[r.get("sev")] = counts.get(r.get("sev"), 0) + 1
                if sev and r.get("sev") not in sev:
                    return False
                total += 1
                return True
            # MySQL (اگر داده آنجاست): فیلتر نوع/هدف/منبع در خود پایگاه داده
            for r in S.ev_mysql(since, until, kinds, tids, src):
                scanned += 1
                if scanned > SCAN_CAP:
                    partial = True
                    break
                if keep(r, json.dumps(r, ensure_ascii=False).lower() if ql else "") and len(out) < limit:
                    out.append(r)
            for f in ([] if partial else S.files.ev_days(since, until)):
                recs = deque(maxlen=max(0, limit - len(out)))     # جدیدترین‌های همین روز (فایل به ترتیب زمان است)
                for line in atrest.iter_log_lines(f):
                    scanned += 1
                    if scanned > SCAN_CAP:
                        partial = True
                        break
                    try:
                        r = json.loads(line)
                    except ValueError:
                        continue
                    if keep(r, line.lower() if ql else "") and recs.maxlen:
                        recs.append(r)
                out.extend(reversed(recs))
                if partial:
                    break
        finally:
            self._qlock.release()
        out.sort(key=lambda r: r.get("t", 0), reverse=True)
        return {"rows": out[:limit], "total": total, "counts": counts, "partial": partial}

    def purge(self):
        kd = self.cfg()["keep_days"]
        if not kd:
            return
        from . import tsdb
        S = tsdb.store()
        lim = time.time() - (kd + 1) * 86400
        S.purge("ev", lim)                       # فایل‌های روزانه و ردیف‌های MySQL
        if S.mysql is not None:
            try:
                S.mysql.drop_before("akrp_ev", lim)
            except Exception:  # noqa
                log.exception("events partitions")
