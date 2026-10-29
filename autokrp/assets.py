"""
مدیریت دارایی (1.21).

- شناسه‌ی هر دارایی «سریال» دستگاه است، نه IP یا نام؛ دستگاهی که جابه‌جا شود (IP و نام تازه) همان دارایی می‌ماند.
- قطعه‌ها (عضو استک، منبع تغذیه، ماژول، SFP، …) با سریال خودشان؛ جابه‌جایی قطعه بین دارایی‌ها هم دیده می‌شود.
- منابع اسکن: هدف‌های مانیتورینگ SNMP مشترک (ENTITY-MIB؛ FortiGate: fnSysSerial) و دستگاه‌های SSH مشترک
  (Cisco: show inventory + show version طبق نمونه‌ی واقعی کاربر، Linux: اسکریپت ثابت خود برنامه).
- هر تغییری که اسکن پیدا کند فقط «پیشنهاد» است (asset_changes، status=pending) و با تأیید ادمین اعمال می‌شود.
  مقدار ردشده تا وقتی دوباره عوض نشود دوباره پیشنهاد نمی‌شود. آخرین مشاهده (last_seen) بدون تأیید به‌روز می‌شود.
"""
import hashlib
import json
import logging
import re
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

from .snmp import SnmpError, cred_from_vault, oid_t

log = logging.getLogger(__name__)

# ENTITY-MIB::entPhysicalTable (از MIB واقعی با snmptranslate)
ENT = {"descr": "1.3.6.1.2.1.47.1.1.1.1.2", "cls": "1.3.6.1.2.1.47.1.1.1.1.5", "name": "1.3.6.1.2.1.47.1.1.1.1.7",
       "hw": "1.3.6.1.2.1.47.1.1.1.1.8", "fw": "1.3.6.1.2.1.47.1.1.1.1.9", "sw": "1.3.6.1.2.1.47.1.1.1.1.10",
       "serial": "1.3.6.1.2.1.47.1.1.1.1.11", "mfg": "1.3.6.1.2.1.47.1.1.1.1.12", "model": "1.3.6.1.2.1.47.1.1.1.1.13"}
FN_SERIAL = "1.3.6.1.4.1.12356.100.1.1.1.0"      # FORTINET-CORE-MIB::fnSysSerial.0
FG_VER = "1.3.6.1.4.1.12356.101.4.1.1.0"         # FORTINET-FORTIGATE-MIB::fgSysVersion.0
SYS = {"descr": "1.3.6.1.2.1.1.1.0", "objid": "1.3.6.1.2.1.1.2.0", "name": "1.3.6.1.2.1.1.5.0", "location": "1.3.6.1.2.1.1.6.0"}
# ENTITY-MIB PhysicalClass: other(1) unknown(2) chassis(3) backplane(4) container(5) powerSupply(6) fan(7) sensor(8)
# module(9) port(10) stack(11) cpu(12) energyObject(13) battery(14) storageDrive(15)
ENT_CLS = {3: "chassis", 4: "other", 5: "other", 6: "psu", 7: "fan", 8: "other", 9: "module", 10: "port", 11: "stack",
           12: "cpu", 14: "other", 15: "storage"}
SSH_TYPES = ("cisco_ios", "cisco_nxos", "cisco_asa", "cisco_xr", "linux")
FIELDS = ("hostname", "ip", "model", "vendor", "sw", "mac", "descr", "location_dev")       # از دستگاه
MANUAL = ("location", "label", "asset_tag", "notes", "status", "loc_from_dev")             # دستی
TITLES = {"hostname": "نام دستگاه", "ip": "IP", "model": "مدل", "vendor": "سازنده", "sw": "نسخه‌ی نرم‌افزار", "mac": "MAC",
          "descr": "توضیح دستگاه", "location_dev": "محل از دستگاه", "location": "محل نصب", "label": "نام دلخواه",
          "asset_tag": "شماره اموال", "notes": "یادداشت", "status": "وضعیت", "loc_from_dev": "محل از دستگاه خوانده شود"}
_JUNK = {"", "0", "00000000", "0123456789", "123456789", "N/A", "NA", "NONE", "NULL", "UNKNOWN", "DEFAULT STRING",
         "TO BE FILLED BY O.E.M.", "NOT SPECIFIED", "BUILTIN", "BUILT-IN", "SYSTEM SERIAL NUMBER", "CHASSIS SERIAL NUMBER", "NOT APPLICABLE", "XXXXXXXXXX"}
_SER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/\-]{1,79}$")


class AssetError(Exception):
    pass


def norm_serial(s):
    s = str(s or "").strip().strip('"').strip()
    if s.upper() in _JUNK or not _SER_RE.match(s):
        return ""
    return s.upper()


def _clean(v, n=200):
    return str(v or "").replace("\x00", "").strip()[:n]


# ---------------------------------------------------------------------------- Cisco (نمونه‌ی واقعی کاربر: C9300، IOS-XE 17.9.5)
_INV_RE = re.compile(r'NAME:\s*"(?P<name>[^"]*)"\s*,?\s*DESCR:\s*"(?P<descr>[^"]*)"\s*PID:\s*(?P<pid>[^,]*?)\s*,\s*VID:\s*(?P<vid>[^,]*?)\s*,\s*SN:\s*(?P<sn>\S*)',
                     re.S)


def parse_cisco_inventory(text):
    """«show inventory»: بلوک‌ها با خط خالی جدا می‌شوند؛ NAME/DESCR گاهی دو خطی است (مثل Power Supply)."""
    out = []
    for block in re.split(r"\r?\n\s*\r?\n", text or ""):
        m = _INV_RE.search(block)
        if m:
            out.append({k: m.group(k).strip() for k in ("name", "descr", "pid", "vid", "sn")})
    return out


def parse_cisco_version(text):
    t = text or ""
    r = {}
    m = re.search(r"^(?:Cisco IOS[^\n]*?|Cisco Nexus[^\n]*?|Cisco Adaptive Security[^\n]*?|[^\n]*Software[^\n]*?),\s*Version\s+([\w.()\-]+)", t, re.M | re.I)
    if not m:
        m = re.search(r"\bVersion\s+([0-9][\w.()\-]*)", t)
    if m:
        r["sw"] = m.group(1)
    m = re.search(r"^(\S+)\s+uptime is\b", t, re.M)
    if m:
        r["hostname"] = m.group(1)
    m = re.search(r"^Model [Nn]umber\s*:\s*(\S+)", t, re.M) or re.search(r"^[Cc]isco\s+(\S+)\s+\(.*?\)\s+processor", t, re.M)
    if m:
        r["model"] = m.group(1)
    m = re.search(r"^System [Ss]erial [Nn]umber\s*:\s*(\S+)", t, re.M) or re.search(r"Processor board ID\s+(\S+)", t)
    if m:
        r["serial"] = m.group(1)
    m = re.search(r"^Base [Ee]thernet MAC [Aa]ddress\s*:\s*(\S+)", t, re.M)
    if m:
        r["mac"] = m.group(1)
    return r


def cls_from_name(name, descr=""):
    n = f"{name} {descr}"
    if re.match(r"^(Switch|Chassis)\s*\d*$", name.strip(), re.I):
        return "chassis"
    if re.search(r"stack", name, re.I):
        return "stack"
    if re.search(r"power supply|\bPS\s?\d|\bPWR", n, re.I):
        return "psu"
    if re.search(r"\bfan", n, re.I):
        return "fan"
    if re.match(r"^(Te|Gi|Fo|Hu|Twe|Tw|Fa|Eth|Ethernet|TenGig|Gig|Fi)\S*\d", name.strip()) or re.search(r"SFP|QSFP|GBIC|XFP", n, re.I):
        return "port"
    if re.search(r"module|uplink|supervisor|linecard|slot|\bNM\b", n, re.I):
        return "module"
    return "other"


def obs_cisco(inv_text, ver_text, host):
    inv, ver = parse_cisco_inventory(inv_text), parse_cisco_version(ver_text)
    serials = [norm_serial(e["sn"]) for e in inv]
    primary = norm_serial(ver.get("serial"))
    if not primary or primary not in serials:
        primary = next((s for s in serials if s), primary)
    if not primary:
        raise AssetError("سریال دستگاه در خروجی show inventory / show version پیدا نشد")
    main = next((e for e in inv if norm_serial(e["sn"]) == primary), None)
    parts, seen = [], {primary}
    for e in inv:
        s = norm_serial(e["sn"])
        if not s or s in seen:
            continue
        seen.add(s)
        c = cls_from_name(e["name"], e["descr"])
        parts.append({"serial": s, "cls": "member" if c == "chassis" else c, "name": _clean(e["name"], 120), "descr": _clean(e["descr"], 200),
                      "model": _clean(e["pid"], 80), "hw": _clean(e["vid"], 40), "src": "ssh"})
    return {"serial": primary, "serial_kind": "chassis", "vendor": "Cisco", "model": _clean(ver.get("model") or (main and main["pid"]), 80),
            "hostname": _clean(ver.get("hostname"), 120), "ip": host, "sw": _clean(ver.get("sw"), 80), "mac": _clean(ver.get("mac"), 40),
            "descr": "", "location_dev": "", "parts": parts, "kind": "ssh"}


# ---------------------------------------------------------------------------- Linux (اسکریپت ثابت برنامه؛ خروجی برچسب‌دار خودمان)
LINUX_SCRIPT = r"""echo "AKRP_host=$(hostname 2>/dev/null)"
for f in product_serial product_name sys_vendor board_serial; do
  v=$(cat /sys/class/dmi/id/$f 2>/dev/null || sudo -n cat /sys/class/dmi/id/$f 2>/dev/null)
  echo "AKRP_$f=$v"
done
. /etc/os-release 2>/dev/null; echo "AKRP_os=$PRETTY_NAME"
echo "AKRP_kernel=$(uname -r 2>/dev/null)"
echo "AKRP_mid=$(cat /etc/machine-id 2>/dev/null)"
echo "AKRP_mac=$(cat /sys/class/net/$(ip route show default 2>/dev/null | awk '{print $5; exit}')/address 2>/dev/null)"
"""


def obs_linux(text, host):
    kv = {}
    for line in (text or "").splitlines():
        m = re.match(r"^AKRP_(\w+)=(.*)$", line.strip())
        if m:
            kv[m.group(1)] = m.group(2).strip()
    serial, kind = norm_serial(kv.get("product_serial")), "dmi"
    if not serial:
        serial, kind = norm_serial(kv.get("board_serial")), "board"
    if not serial and re.fullmatch(r"[0-9a-f]{32}", kv.get("mid", "")):
        serial, kind = "MID-" + kv["mid"].upper(), "machine-id"     # بدون دسترسی root یا ماشین مجازی بی‌سریال
    if not serial:
        raise AssetError("سریال سرور خوانده نشد (فایل‌های DMI بدون دسترسی root خوانا نیستند و machine-id هم نبود)")
    os_ = kv.get("os", "")
    return {"serial": serial, "serial_kind": kind, "vendor": _clean(kv.get("sys_vendor"), 80), "model": _clean(kv.get("product_name"), 80),
            "hostname": _clean(kv.get("host"), 120), "ip": host, "sw": _clean(f"{os_} ({kv.get('kernel', '')})" if os_ else kv.get("kernel"), 120),
            "mac": _clean(kv.get("mac"), 40), "descr": "", "location_dev": "", "parts": [], "kind": "ssh"}


# ---------------------------------------------------------------------------- SNMP
# اسکالرهای سریال سازنده‌ها (MIB واقعی، snmptranslate روی mibs مخزن LibreNMS):
# FORTINET-CORE-MIB / FORTINET-FORTIGATE-MIB، JUNIPER-MIB (jnxBox*)، MIKROTIK-MIB (mtxr*)، CPQSINFO-MIB (HP ProLiant: iLO یا عامل HP روی سیستم‌عامل)
VSCALAR = {
    "fortinet": {"serial": FN_SERIAL, "sw": FG_VER},
    "juniper": {"serial": "1.3.6.1.4.1.2636.3.1.3.0", "model": "1.3.6.1.4.1.2636.3.1.2.0"},
    "mikrotik": {"serial": "1.3.6.1.4.1.14988.1.1.7.3.0", "model": "1.3.6.1.4.1.14988.1.1.7.9.0", "sw": "1.3.6.1.4.1.14988.1.1.4.4.0",
                 "swid": "1.3.6.1.4.1.14988.1.1.4.1.0"},
    "hp": {"serial": "1.3.6.1.4.1.232.2.2.2.1.0", "model": "1.3.6.1.4.1.232.2.2.4.2.0"},
}
VNAME = {"cisco": "Cisco", "fortinet": "Fortinet", "juniper": "Juniper Networks", "mikrotik": "MikroTik", "hp": "HPE", "extreme": "Extreme"}
_VPFX = [("1.3.6.1.4.1.9.", "cisco"), ("1.3.6.1.4.1.12356.", "fortinet"), ("1.3.6.1.4.1.2636.", "juniper"), ("1.3.6.1.4.1.14988.", "mikrotik"),
         ("1.3.6.1.4.1.232.", "hp"), ("1.3.6.1.4.1.1916.", "extreme"), ("1.3.6.1.4.1.8072.", "linux")]
# JUNIPER-MIB::jnxContentsTable (قطعه‌ها؛ Junos معمولاً ENTITY-MIB ندارد)
JNX = {"descr": "1.3.6.1.4.1.2636.3.1.8.1.6", "serial": "1.3.6.1.4.1.2636.3.1.8.1.7", "rev": "1.3.6.1.4.1.2636.3.1.8.1.8",
       "part": "1.3.6.1.4.1.2636.3.1.8.1.10", "model": "1.3.6.1.4.1.2636.3.1.8.1.14"}


def vendor_of(objid):
    for pfx, v in _VPFX:
        if str(objid or "").startswith(pfx):
            return v
    return "generic"


CSTACK_SERIAL = "1.3.6.1.4.1.9.5.1.2.19.0"     # CISCO-STACK-MIB::chassisSerialNumberString.0
OLD_CHASSIS_ID = "1.3.6.1.4.1.9.3.6.3.0"      # OLD-CISCO-CHASSIS-MIB::chassisId.0


async def obs_snmp(cl, cred, host, port, timeout=3, retries=1, profiles=None):
    """سریال اصلی: اسکالر سازنده‌ی شناخته‌شده (از sysObjectID)، وگرنه ENTITY-MIB (شاسی، استک، هر سریال)، وگرنه هر اسکالر سازنده
    (مثلاً سرور HP که sysObjectID آن مال سیستم‌عامل است). قطعه‌ها: ENTITY-MIB و برای Juniper جدول jnxContents."""
    s = await cl.aget(cred, host, port, list(SYS.values()), timeout, retries)
    vk = vendor_of(s.get(SYS["objid"]))
    vs = await cl.aget(cred, host, port, [o for d in VSCALAR.values() for o in d.values()], timeout, retries)
    vval = {v: {k: _clean(vs.get(o), 200) for k, o in d.items()} for v, d in VSCALAR.items()}
    r = await cl.awalk(cred, host, port, list(ENT.values()), timeout, retries, 3000)
    rows = []
    for i in sorted(r[ENT["cls"]] or r[ENT["serial"]], key=lambda x: oid_t(x)):
        rows.append({"idx": i, "cls": r[ENT["cls"]].get(i), **{k: _clean(r[o].get(i), 200) for k, o in ENT.items() if k != "cls"}})
    primary, main, kind, src_v = "", None, "entity", ""
    if vk in VSCALAR and norm_serial(vval[vk]["serial"]):
        primary, kind, src_v = norm_serial(vval[vk]["serial"]), vk, vk
    if not primary:
        for want in (3, 11, None):              # شاسی، بعد استک، بعد هر سریالی
            main = next((x for x in rows if norm_serial(x["serial"]) and (want is None or x["cls"] == want)), None)
            if main:
                primary = norm_serial(main["serial"])
                break
    else:
        main = next((x for x in rows if norm_serial(x["serial"]) == primary), None)
    if not primary:
        for v in ("hp", "juniper", "mikrotik", "fortinet"):
            if norm_serial(vval[v]["serial"]):
                primary, kind, src_v = norm_serial(vval[v]["serial"]), v, v
                break
    if not primary and vk == "cisco":
        # Cisco قدیمی بدون ENTITY-MIB: CISCO-STACK-MIB (کاتالیست‌های CatOS/قدیمی) و OLD-CISCO-CHASSIS-MIB::chassisId
        # (chassisId قابل‌نوشتن است و «پیش‌فرض آن سریال شاسی است» — پس نوعش جدا ثبت می‌شود)
        o = await cl.aget(cred, host, port, [CSTACK_SERIAL, OLD_CHASSIS_ID], timeout, retries)
        if norm_serial(_clean(o.get(CSTACK_SERIAL), 200)):
            primary, kind, src_v = norm_serial(_clean(o.get(CSTACK_SERIAL), 200)), "chassis", "cisco"
        elif norm_serial(_clean(o.get(OLD_CHASSIS_ID), 200)):
            primary, kind, src_v = norm_serial(_clean(o.get(OLD_CHASSIS_ID), 200)), "chassisId", "cisco"
    if not primary and vk == "mikrotik" and norm_serial(vval["mikrotik"].get("swid")):
        primary, kind, src_v = "SWID-" + norm_serial(vval["mikrotik"]["swid"]), "software-id", "mikrotik"   # CHR (مجازی) سریال ندارد
    pa = {}                                        # 1.27: OIDهای مدل/سریال/نسخه از «قالب دستگاه»
    from .devprof import match as pmatch
    prof = pmatch(profiles, s.get(SYS["objid"]))
    if prof and prof.get("asset"):
        g = await cl.aget(cred, host, port, list(prof["asset"].values()), timeout, retries)
        pa = {k: _clean(g.get(o), 200) for k, o in prof["asset"].items()}
        if not primary and norm_serial(pa.get("serial")):
            primary, kind, src_v = norm_serial(pa["serial"]), "profile", ""
    if not primary:
        raise AssetError("دستگاه سریال برنگرداند (ENTITY-MIB و MIBهای سازنده‌ی شناخته‌شده پشتیبانی نمی‌شوند یا در view این community/کاربر نیستند)")
    parts, seen = [], {primary}
    for x in rows:
        sn = norm_serial(x["serial"])
        if not sn or sn in seen:
            continue
        seen.add(sn)
        c = ENT_CLS.get(x["cls"], "other")
        parts.append({"serial": sn, "cls": "member" if c == "chassis" else c, "name": x["name"][:120], "descr": x["descr"][:200],
                      "model": x["model"][:80], "hw": x["hw"][:40], "src": "snmp"})
    if src_v == "juniper" or vk == "juniper":
        j = await cl.awalk(cred, host, port, list(JNX.values()), timeout, retries, 1000)
        for i in sorted(j[JNX["serial"]], key=lambda x: oid_t(x)):
            sn = norm_serial(j[JNX["serial"]][i])
            if not sn or sn in seen:
                continue
            seen.add(sn)
            d = _clean(j[JNX["descr"]].get(i), 200)
            parts.append({"serial": sn, "cls": cls_from_name(d, d), "name": d[:120], "descr": d,
                          "model": _clean(j[JNX["model"]].get(i) or j[JNX["part"]].get(i), 80), "hw": _clean(j[JNX["rev"]].get(i), 40), "src": "snmp"})
    vv = vval.get(src_v) or {}
    sw = vv.get("sw") or (main or {}).get("sw")
    if not sw:
        m = re.search(r"(?:Version|JUNOS|RouterOS)\s+([0-9][\w.()\-]*)", s.get(SYS["descr"]) or "")
        sw = m.group(1) if m else ""
    if pa.get("firmware") and not vv.get("sw"):
        sw = pa["firmware"]
    vendor = (main or {}).get("mfg") or VNAME.get(src_v or vk, "") or (prof or {}).get("vendor") or ""
    model = vv.get("model") or pa.get("model") or (main or {}).get("model") or (main or {}).get("descr") or ""
    return {"serial": primary, "serial_kind": kind, "vendor": _clean(vendor, 80), "model": _clean(model, 80),
            "hostname": _clean(s.get(SYS["name"]), 120), "ip": host, "sw": _clean(sw, 120), "mac": "", "descr": _clean(s.get(SYS["descr"]), 300),
            "location_dev": _clean(s.get(SYS["location"]), 200), "parts": parts, "kind": "snmp"}


def demo_obs(host, name, kind):
    """Demo: دستگاه ساختگی با سریال ثابت (از روی آدرس)."""
    h = hashlib.sha256(host.encode()).hexdigest().upper()
    return {"serial": "FCW" + h[:8], "serial_kind": "chassis", "vendor": "Cisco", "model": "C9300-48UXM", "hostname": name.replace(" ", "-"),
            "ip": host, "sw": "17.09.05", "mac": "", "descr": "Cisco IOS XE Software, Version 17.09.05 (Demo)", "location_dev": "Demo rack",
            "kind": kind, "parts": [{"serial": "LIT" + h[8:16], "cls": "psu", "name": "Power Supply A", "descr": "PWR-C1-1100WAC", "model": "PWR-C1-1100WAC",
                                     "hw": "V02", "src": kind},
                                    {"serial": "TED" + h[16:24], "cls": "port", "name": "Te1/1/1", "descr": "SFP-10GBase-CX1", "model": "SFP-H10GB-CU2M",
                                     "hw": "V02", "src": kind}]}


def merge(obs_list):
    """مشاهده‌های یک سریال از چند منبع (SNMP و SSH) یکی می‌شوند."""
    by = {}
    for o in obs_list:
        cur = by.get(o["serial"])
        if cur is None:
            by[o["serial"]] = dict(o, parts=list(o["parts"]), kinds={o["kind"]}, sources=[o.get("source", "")])
            continue
        for k in FIELDS + ("serial_kind",):
            if not cur.get(k) and o.get(k):
                cur[k] = o[k]
        have = {p["serial"] for p in cur["parts"]}
        cur["parts"] += [p for p in o["parts"] if p["serial"] not in have]
        cur["kinds"].add(o["kind"])
        cur["sources"].append(o.get("source", ""))
    return list(by.values())


_VENDOR_ALIAS = [(r"^mikrotik", "mikrotik"), (r"^cisco", "cisco"), (r"^fortinet|^fortigate", "fortinet"), (r"^extreme", "extreme"), (r"^juniper", "juniper"),
                 (r"^(hewlett|hp\b|hpe\b|aruba)", "hp"), (r"^dell", "dell"), (r"^lenovo", "lenovo"), (r"^vmware", "vmware")]


def _vendor_key(v):
    v = str(v or "").strip().lower()
    for rx, k in _VENDOR_ALIAS:
        if re.match(rx, v):
            return k
    return re.sub(r"[\s,.]+(inc|ltd|corp|corporation|co|systems|networks|technologies|technology)\b\.?", "", v).strip(" ,.")


def same(field, a, b):
    """دو مقدار یک فیلد از دو منبع (SNMP و SSH) فقط در قالب فرق دارند؟ (Cisco Systems Inc = Cisco، SW1.corp = SW1، 17.09.05 = 17.9.5)"""
    a, b = str(a or "").strip(), str(b or "").strip()
    if a == b:
        return True
    if not a or not b:
        return False
    if field == "vendor":
        return _vendor_key(a) == _vendor_key(b)
    if field == "hostname":
        return a.lower().split(".")[0] == b.lower().split(".")[0]
    if field == "sw":
        na, nb = re.findall(r"\d+", a), re.findall(r"\d+", b)
        return bool(na) and [int(x) for x in na[:4]] == [int(x) for x in nb[:4]]
    if field in ("model", "mac"):
        return re.sub(r"[^0-9a-z]", "", a.lower()) == re.sub(r"[^0-9a-z]", "", b.lower())
    return False


def part_text(p):
    return f"{p.get('cls') or ''} {p.get('name') or ''} {p.get('model') or ''} SN {p['serial']}".strip()


# ---------------------------------------------------------------------------- مدیر دارایی
class AssetManager:
    def __init__(self, settings, store, vault, snmp_client, hostkeys, emit=None, notify=None, demo=False):
        self.settings, self.store, self.vault, self.client, self.hostkeys = settings, store, vault, snmp_client, hostkeys
        self.emit = emit or (lambda *a, **k: None)
        self.notify = notify or (lambda *a, **k: None)
        self.demo = demo
        self.job = None
        self._lock = threading.RLock()

    def cfg(self):
        c = self.settings.get("assets") or {}
        return {"scan_enabled": bool(c.get("scan_enabled")), "scan_time": c.get("scan_time") or "03:00",
                "sources": c.get("sources"), "loc_default": bool(c.get("loc_default")), "concurrency": int(c.get("concurrency") or 4)}

    # ---- منابع
    def sources(self):
        cfg = self.cfg()
        sel = cfg["sources"] if isinstance(cfg["sources"], dict) else None
        out = []
        for t in self.store.mon_targets():
            if t.get("kind") != "snmp" or t.get("owner"):
                continue
            out.append({"id": f"snmp:{t['id']}", "type": "snmp", "name": t["name"], "host": t["host"], "ok": bool(t.get("cred_id")),
                        "why": "" if t.get("cred_id") else "پروفایل SNMP ندارد", "selected": sel is None or f"snmp:{t['id']}" in sel.get("ids", [])})
        for d in self.store.ssh_devices():
            if d.get("owner"):
                continue
            ok = d.get("device_type") in SSH_TYPES
            out.append({"id": f"ssh:{d['id']}", "type": "ssh", "name": d.get("name") or d["host"], "host": d["host"], "dtype": d.get("device_type"),
                        "ok": ok, "why": "" if ok else "این نوع دستگاه با SSH پشتیبانی نمی‌شود؛ از SNMP استفاده کنید",
                        "selected": ok and (sel is None or f"ssh:{d['id']}" in sel.get("ids", []))})
        return out

    # ---- اسکن
    def scan_start(self, ids=None, user="", trigger="manual"):
        with self._lock:
            if self.job and self.job["status"] == "running":
                raise AssetError("یک اسکن دارایی در جریان است.")
            if self.vault is not None and not self.vault.unlocked():
                raise AssetError("برنامه قفل است.")
            src = [s for s in self.sources() if s["ok"] and (s["selected"] if ids is None else s["id"] in ids)]
            if not src:
                raise AssetError("هیچ منبعی برای اسکن انتخاب نشده است (هدف SNMP یا دستگاه SSH مشترک).")
            job = {"id": time.strftime("%Y%m%d_%H%M%S") + "_" + uuid.uuid4().hex[:4], "status": "running", "started": time.time(),
                   "finished": None, "total": len(src), "done": 0, "results": [], "trigger": trigger, "user": user, "proposed": 0,
                   "cancel": threading.Event()}
            self.job = job
        threading.Thread(target=self._run, args=(job, src), name="asset-scan", daemon=True).start()
        return self.public_job()

    def scan_cancel(self):
        j = self.job
        if j and j["status"] == "running":
            j["cancel"].set()
            return True
        return False

    def public_job(self):
        j = self.job
        return None if not j else {k: v for k, v in j.items() if k != "cancel"}

    def _run(self, job, src):
        self.emit("info", f"اسکن دارایی روی {len(src)} منبع شروع شد", "asset")
        obs = []
        with ThreadPoolExecutor(max_workers=max(1, min(10, self.cfg()["concurrency"]))) as ex:
            for res in ex.map(lambda s: self._one(job, s), src):
                job["results"].append(res)
                job["done"] += 1
                if res.get("obs"):
                    obs.append(res.pop("obs"))
        try:
            n = 0 if job["cancel"].is_set() else self.propose(merge(obs), job.get("user") or "", f"اسکن {job['id']}")
        except Exception as e:
            log.exception("asset propose")
            n = 0
            job["results"].append({"id": "", "name": "", "status": "error", "message": f"ثبت نتیجه ناموفق بود: {e}"})
        job["proposed"] = n
        job["finished"] = time.time()
        job["status"] = "cancelled" if job["cancel"].is_set() else "done"
        bad = sum(1 for r in job["results"] if r["status"] == "error")
        self.store.add_history("asset", "اسکن دارایی", "ok" if not bad else "warn",
                               f"{len(src)} منبع، {bad} ناموفق، {n} تغییر در انتظار تأیید", user=job.get("user") or "")
        self.emit("warn" if n or bad else "ok", f"اسکن دارایی تمام شد: {n} تغییر در انتظار تأیید، {bad} منبع ناموفق", "asset")
        if n:
            self.notify("asset_change", f"اسکن دارایی: {n} تغییر (دارایی تازه، جابه‌جایی، تغییر نام/IP/قطعه) منتظر تأیید ادمین است.")

    def _one(self, job, s):
        r = {"id": s["id"], "name": s["name"], "host": s["host"], "status": "error", "message": "", "serial": ""}
        if job["cancel"].is_set():
            r.update(status="skipped", message="به‌خاطر توقف اجرا نشد")
            return r
        typ, sid = s["id"].split(":", 1)
        try:
            if typ == "snmp":
                o = self._snmp(int(sid))
            else:
                o = self._ssh(int(sid), job)
            o["source"] = s["id"]
            r.update(status="ok", serial=o["serial"], message=f"{o.get('model') or ''} · {len(o['parts'])} قطعه".strip(" ·"), obs=o)
        except (AssetError, SnmpError) as e:
            r["message"] = str(e)
        except Exception as e:
            from .ssh import friendly
            log.info("asset scan %s: %s", s["id"], e)
            r["message"] = friendly(e)
        return r

    def _snmp(self, tid):
        t = self.store.mon_target(tid)
        if not t or t.get("kind") != "snmp" or t.get("owner"):
            raise AssetError("هدف SNMP پیدا نشد.")
        if self.demo and not str(t["host"]).startswith("127."):
            return demo_obs(t["host"], t["name"], "snmp")
        p = self.store.cred_get(int(t["cred_id"])) if t.get("cred_id") else None
        if not p or p.get("kind") != "snmp" or p.get("owner"):
            raise AssetError("پروفایل SNMP این هدف پیدا نشد.")
        from .snmp import load_cfg
        cfg = load_cfg(t)
        cred = cred_from_vault(self.vault, p["id"])
        timeout = float(t.get("timeout") or 3)
        return self.client.run(obs_snmp(self.client, cred, t["host"], t.get("port") or 161, timeout, cfg["retries"],
                                        []), 180)

    def _ssh(self, did, job):
        from . import ssh as sshmod
        from .abort import Attempt
        d = self.store.ssh_device(did)
        if not d or d.get("owner"):
            raise AssetError("دستگاه SSH پیدا نشد.")
        if d.get("device_type") not in SSH_TYPES:
            raise AssetError("این نوع دستگاه با SSH پشتیبانی نمی‌شود.")
        if self.demo and not str(d["host"]).startswith("127."):
            return demo_obs(d["host"], d.get("name") or d["host"], "ssh")
        pfx = sshmod.cred_prefix(d)
        creds = {"username": self.vault.get(pfx + "username", ""), "password": self.vault.get(pfx + "password", ""),
                 "secret": self.vault.get(pfx + "secret", "")}
        if not creds["username"] or not creds["password"]:
            raise AssetError("یوزر یا پسورد این دستگاه ذخیره نشده است")
        att = Attempt()
        state, fp, old = self.hostkeys.check(d["host"], d.get("port") or 22, legacy=bool(d.get("legacy")), attempt=att)
        if state == "mismatch":
            raise AssetError(f"کلید میزبان عوض شده است (ثبت‌شده {old}، فعلی {fp}); اتصال انجام نشد.")
        if state == "new":
            self.emit("warn", f"SSH: کلید میزبان {d['host']} برای اولین بار ثبت شد ({fp})", "asset")
        cancel = job["cancel"]
        if d["device_type"] == "linux":
            ok, text, msg = sshmod.run_linux(d, creds, LINUX_SCRIPT, False, 60, self.hostkeys, cancel, attempt=Attempt())
            return obs_linux(text, d["host"])
        ok, text, msg = sshmod.run_netmiko(d, creds, "show inventory\nshow version", "exec", False, 90, self.hostkeys, cancel,
                                           attempt=Attempt())
        inv, ver = split_cmds(text)
        return obs_cisco(inv, ver, d["host"])

    # ---- مقایسه و پیشنهاد
    def _rejected(self, serial):
        out = set()
        for c in self.store.asset_changes("rejected", serial, 500):
            d = c["data"]
            if c["kind"] == "new":
                out.add(("new",))
            for f, (o, n) in (d.get("fields") or {}).items():
                out.add(("f", f, str(n)))
            for p in d.get("parts_added") or []:
                out.add(("add", p["serial"]))
            for p in d.get("parts_moved") or []:
                out.add(("add", p["serial"]))
            for p in d.get("parts_removed") or []:
                out.add(("rm", p["serial"]))
        return out

    def propose(self, obs_list, user, source):
        """برای هر دستگاه دیده‌شده، تفاوت با وضعیت تأییدشده ← یک پیشنهاد در انتظار (یا به‌روز کردن پیشنهاد قبلی)."""
        n, now = 0, time.time()
        with self._lock:
            for o in obs_list:
                serial = o["serial"]
                a = self.store.asset_by_serial(serial)
                rej = self._rejected(serial)
                pend = self.store.asset_changes("pending", serial, 5)
                pend = [c for c in pend if c["kind"] in ("new", "update")]
                if a is None:
                    if ("new",) in rej:
                        continue
                    fields = {f: o.get(f) or "" for f in FIELDS}
                    fields["serial_kind"] = o.get("serial_kind") or ""
                    added, moved = self._parts_owner(o["parts"], None)
                    owner_part = self.store.part_by_serial(serial)
                    data = {"fields": fields, "parts_added": added, "parts_moved": moved, "parts_removed": [], "kinds": sorted(o["kinds"]),
                            "was_part_of": self._asset_label(owner_part["asset_id"]) if owner_part else ""}
                    kind = "new"
                else:
                    self.store.asset_update(a["id"], {"last_seen": now})
                    fields = {}
                    for f in FIELDS:
                        v = o.get(f) or ""
                        if v and not same(f, a.get(f), v) and ("f", f, v) not in rej:
                            fields[f] = [a.get(f) or "", v]
                    if a.get("loc_from_dev") and o.get("location_dev") and o["location_dev"] != (a.get("location") or "") \
                            and ("f", "location", o["location_dev"]) not in rej:
                        fields["location"] = [a.get("location") or "", o["location_dev"]]
                    cur = {p["serial"]: p for p in self.store.asset_parts(a["id"])}
                    seen = {p["serial"]: p for p in o["parts"]}
                    for sn, p in seen.items():
                        if sn in cur:
                            self.store.part_refresh(a["id"], p, now)
                    new_parts = [p for sn, p in seen.items() if sn not in cur and ("add", sn) not in rej]
                    added, moved = self._parts_owner(new_parts, a["id"])
                    removed = [cur[sn] for sn in cur if sn not in seen and (cur[sn].get("src") or "") in o["kinds"]
                               and ("rm", sn) not in rej]
                    removed = [{k: p.get(k) for k in ("serial", "cls", "name", "model")} for p in removed]
                    data = {"fields": fields, "parts_added": added, "parts_moved": moved, "parts_removed": removed, "kinds": sorted(o["kinds"])}
                    kind = "update"
                    if not (fields or added or moved or removed):
                        for c in pend:
                            self.store.asset_change_set(c["id"], status="obsolete", decided=now, note="دستگاه به وضعیت تأییدشده برگشت")
                        continue
                src = f"{source} ({'، '.join(s for s in o.get('sources', []) if s)})"
                if pend:
                    c = pend[0]
                    if c["data"] != data or c["kind"] != kind:
                        self.store.asset_change_set(c["id"], ts=now, data=data, source=src, kind=kind, asset_id=a["id"] if a else None)
                        n += 1
                    for extra in pend[1:]:
                        self.store.asset_change_set(extra["id"], status="obsolete", decided=now, note="پیشنهاد تازه‌تر جایش را گرفت")
                else:
                    self.store.asset_change_add({"asset_id": a["id"] if a else None, "serial": serial, "kind": kind, "data": data,
                                                 "source": src, "by_user": user})
                    n += 1
        return n

    def _parts_owner(self, parts, aid):
        added, moved = [], []
        for p in parts:
            q = self.store.part_by_serial(p["serial"])
            other = self.store.asset_by_serial(p["serial"])
            p = {k: p.get(k) or "" for k in ("serial", "cls", "name", "descr", "model", "hw", "src")}
            if q and q["asset_id"] != aid:
                moved.append({**p, "from_id": q["asset_id"], "from": self._asset_label(q["asset_id"])})
            elif other and other.get("id") != aid:
                moved.append({**p, "from_id": None, "from": f"دارایی مستقل {other.get('label') or other.get('hostname') or other['serial']}",
                              "was_asset": other["id"]})
            else:
                added.append(p)
        return added, moved

    def _asset_label(self, aid):
        a = self.store.asset(aid) if aid else None
        if not a:
            return ""
        return f"{a.get('label') or a.get('hostname') or ''} ({a['serial']})".strip()

    # ---- ویرایش دستی
    def clean_manual(self, f):
        out = {}
        for k in MANUAL:
            if k not in f:
                continue
            v = f[k]
            if k == "loc_from_dev":
                out[k] = 1 if v else 0
            elif k == "status":
                if v not in ("active", "retired"):
                    raise AssetError("وضعیت نامعتبر است.")
                out[k] = v
            else:
                out[k] = _clean(v, 1000 if k == "notes" else 200)
        return out

    def manual(self, aid, fields, user, admin, new_serial=None, new_fields=None):
        """ادمین: مستقیم اعمال و ثبت در تاریخچه. اپراتور: پیشنهاد در انتظار تأیید."""
        man = self.clean_manual(fields or {})
        with self._lock:
            if aid is None:
                serial = norm_serial(new_serial)
                if not serial:
                    raise AssetError("سریال معتبر لازم است (حروف انگلیسی، عدد و . _ - / :).")
                if self.store.asset_by_serial(serial):
                    raise AssetError("دارایی با این سریال از قبل هست.")
                nf = {k: _clean((new_fields or {}).get(k), 200) for k in ("hostname", "ip", "model", "vendor", "sw", "mac")}
                data = {"fields": {**nf, "descr": "", "location_dev": "", "serial_kind": "manual"}, "manual": man, "parts_added": [],
                        "parts_moved": [], "parts_removed": [], "kinds": ["manual"]}
                if not admin:
                    if self.store.asset_changes("pending", serial, 1):
                        raise AssetError("برای این سریال یک پیشنهاد در انتظار تأیید هست.")
                    return {"pending": self.store.asset_change_add({"serial": serial, "kind": "new", "data": data, "source": "دستی",
                                                                    "by_user": user})}
                cid = self.store.asset_change_add({"serial": serial, "kind": "new", "data": data, "source": "دستی", "by_user": user})
                self._apply(self.store.asset_change(cid), user)
                self.store.asset_change_set(cid, status="approved", decided=time.time(), decided_by=user, note="ثبت مستقیم ادمین")
                return {"id": self.store.asset_by_serial(serial)["id"]}
            a = self.store.asset(aid)
            if not a:
                raise AssetError("دارایی پیدا نشد.")
            diff = {k: [a.get(k) if a.get(k) is not None else "", v] for k, v in man.items() if str(v) != str(a.get(k) if a.get(k) is not None else "")}
            if not diff:
                return {"unchanged": True}
            data = {"manual": diff}
            cid = self.store.asset_change_add({"asset_id": aid, "serial": a["serial"], "kind": "edit", "data": data, "source": "دستی",
                                               "by_user": user})
            if not admin:
                return {"pending": cid}
            self._apply(self.store.asset_change(cid), user)
            self.store.asset_change_set(cid, status="approved", decided=time.time(), decided_by=user, note="ثبت مستقیم ادمین")
            return {"id": aid}

    # ---- تأیید و رد
    def decide(self, ids, approve, user, note=""):
        done, errs = 0, []
        with self._lock:
            for cid in ids:
                c = self.store.asset_change(int(cid))
                if not c or c["status"] != "pending":
                    continue
                if approve:
                    try:
                        self._apply(c, user)
                    except AssetError as e:
                        errs.append(f"{c['serial']}: {e}")
                        continue
                self.store.asset_change_set(c["id"], status="approved" if approve else "rejected", decided=time.time(), decided_by=user,
                                            note=str(note or "")[:300])
                if not approve:
                    a = self.store.asset_by_serial(c["serial"])
                    self.store.asset_hist_add(a["id"] if a else None, c["serial"], "rejected", "", self.change_summary(c)[:500], user,
                                              c["source"], c["id"])
                done += 1
        if done:
            self.store.add_history("asset", f"{done} تغییر", "ok", ("تأیید شد" if approve else "رد شد") + (f" — {note}" if note else ""), user=user)
        return {"done": done, "errors": errs}

    def restore(self, ids, user):
        """پیشنهاد ردشده دوباره به صف تأیید (تا اسکن بعدی دوباره پیشنهادش کند یا همین الان تأیید شود)."""
        n = 0
        with self._lock:
            for cid in ids:
                c = self.store.asset_change(int(cid))
                if c and c["status"] == "rejected":
                    if c["kind"] in ("new", "update") and self.store.asset_changes("pending", c["serial"], 1):
                        self.store.asset_change_set(c["id"], status="obsolete", note="بازگردانی؛ پیشنهاد دیگری در صف بود")
                    else:
                        self.store.asset_change_set(c["id"], status="pending", decided=None, decided_by="", note=f"بازگردانی توسط {user}")
                    n += 1
        return n

    def _apply(self, c, user):
        now, d, src, cid = time.time(), c["data"], c["source"], c["id"]
        hist = lambda aid, serial, f, o, n: self.store.asset_hist_add(aid, serial, f, o, n, user, src, cid, now)
        if c["kind"] == "new":
            if self.store.asset_by_serial(c["serial"]):
                raise AssetError("دارایی با این سریال در این فاصله ثبت شده است؛ دوباره اسکن کنید.")
            f = dict(d.get("fields") or {})
            rec = {k: f.get(k) or "" for k in FIELDS}
            rec.update(serial=c["serial"], serial_kind=f.get("serial_kind") or "", status="active", first_seen=c["ts"], last_seen=c["ts"],
                       loc_from_dev=1 if self.cfg()["loc_default"] else 0, source=src[:200])
            rec.setdefault("location", "")
            rec.update(d.get("manual") or {})
            if rec.get("loc_from_dev") and rec.get("location_dev") and not rec.get("location"):
                rec["location"] = rec["location_dev"]
            aid = self.store.asset_insert(rec)
            hist(aid, c["serial"], "created", "", json.dumps({k: v for k, v in rec.items() if k in FIELDS + MANUAL and k != "descr"
                                                              and v not in ("", None, 0)}, ensure_ascii=False))
            owner_part = self.store.part_by_serial(c["serial"])
            if owner_part:            # قبلاً قطعه‌ی دارایی دیگری بود (مثلاً عضو استک که جدا شد)
                self.store.part_delete_serial(c["serial"])
                hist(owner_part["asset_id"], self._serial_of(owner_part["asset_id"]), "part-", part_text(owner_part), f"دارایی مستقل شد ({c['serial']})")
        elif c["kind"] in ("update", "edit"):
            a = self.store.asset(c["asset_id"]) if c.get("asset_id") else self.store.asset_by_serial(c["serial"])
            if not a:
                raise AssetError("دارایی دیگر وجود ندارد.")
            aid = a["id"]
            ch = {}
            for f, (o, n) in {**(d.get("fields") or {}), **(d.get("manual") or {})}.items():
                if f in FIELDS + MANUAL:
                    ch[f] = n
                    hist(aid, a["serial"], f, a.get(f) if a.get(f) is not None else "", n)
            if ch:
                self.store.asset_update(aid, ch)
        else:
            raise AssetError("نوع تغییر نامعتبر است.")
        aid = self.store.asset_by_serial(c["serial"])["id"]
        for p in d.get("parts_removed") or []:
            q = self.store.part_by_serial(p["serial"])
            if q and q["asset_id"] == aid:
                self.store.part_delete_serial(p["serial"])
                hist(aid, c["serial"], "part-", part_text(p), "")
        for p in d.get("parts_moved") or []:
            q = self.store.part_by_serial(p["serial"])
            if q and q["asset_id"] != aid:
                self.store.part_delete_serial(p["serial"])
                hist(q["asset_id"], self._serial_of(q["asset_id"]), "part→", part_text(p), f"منتقل شد به {self._asset_label(aid)}")
            self.store.part_add(aid, p, now)
            hist(aid, c["serial"], "part→", p.get("from") or "", part_text(p))
        for p in d.get("parts_added") or []:
            if not self.store.part_by_serial(p["serial"]):
                self.store.part_add(aid, p, now)
                hist(aid, c["serial"], "part+", "", part_text(p))

    def _serial_of(self, aid):
        a = self.store.asset(aid) if aid else None
        return a["serial"] if a else ""

    @staticmethod
    def change_summary(c):
        d, out = c["data"], []
        if c["kind"] == "new":
            f = d.get("fields") or {}
            out.append("دارایی تازه: " + "، ".join(f"{TITLES.get(k, k)} {v}" for k, v in f.items() if v and k in FIELDS))
        items = (d.get("manual") or {}) if c["kind"] == "new" else {**(d.get("fields") or {}), **(d.get("manual") or {})}
        for f, v in items.items():
            o, n = v if isinstance(v, (list, tuple)) else ("", v)
            out.append(f"{TITLES.get(f, f)}: {o or '—'} ← {n or '—'}")
        out += [f"+ {part_text(p)}" for p in d.get("parts_added") or []]
        out += [f"− {part_text(p)}" for p in d.get("parts_removed") or []]
        out += [f"⇄ {part_text(p)} (از {p.get('from')})" for p in d.get("parts_moved") or []]
        return "؛ ".join(out)


def split_cmds(text):
    """خروجی run_netmiko برای چند دستور (هر کدام با «<prompt>دستور» شروع می‌شود) ← (inventory، version)."""
    parts = {"inventory": "", "version": ""}
    cur = None
    for line in (text or "").splitlines():
        m = re.search(r"show (inventory|version)\s*$", line)
        if m and not line.strip().startswith(("NAME", "PID")):
            cur = m.group(1)
            continue
        if cur:
            parts[cur] += line + "\n"
    return parts["inventory"], parts["version"]
