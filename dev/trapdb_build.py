"""ساخت autokrp/trapdb.json از فایل‌های MIB واقعی (LibreNMS) با snmptranslate (net-snmp).
  git clone --filter=blob:none --sparse https://github.com/librenms/librenms.git && git sparse-checkout set mibs
  python dev/trapdb_build.py /path/to/librenms/mibs
هیچ OID دستی نیست: فهرست Trapها، OID، OBJECTS، شرح و enumها همه از خود MIB. فقط «سطح» (s) با قاعده‌ی نام تعیین می‌شود."""
import json, re, subprocess, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
ROOT = Path(next((a for a in sys.argv[1:] if not a.startswith("--")), "mibs/librenms/mibs"))
DIRS = [ROOT] + [ROOT / d for d in ("cisco", "fortinet", "juniper", "juniper/junos", "mikrotik", "hp", "extreme")]
MP = ":".join(str(d) for d in DIRS)
MODULES = {  # ماژول ← سازنده (برچسب رابط)
    "SNMPv2-MIB": "std", "IF-MIB": "std", "ENTITY-MIB": "std", "BGP4-MIB": "std", "OSPF-TRAP-MIB": "std", "BRIDGE-MIB": "std",
    "CISCO-CONFIG-MAN-MIB": "cisco", "CISCO-ENVMON-MIB": "cisco", "CISCO-ENTITY-SENSOR-MIB": "cisco", "CISCO-ENTITY-FRU-CONTROL-MIB": "cisco",
    "CISCO-STACKWISE-MIB": "cisco", "CISCO-HSRP-MIB": "cisco", "CISCO-RF-MIB": "cisco", "CISCO-ERR-DISABLE-MIB": "cisco",
    "CISCO-PORT-SECURITY-MIB": "cisco", "CISCO-SYSLOG-MIB": "cisco", "CISCO-IPSEC-FLOW-MONITOR-MIB": "cisco", "CISCO-BGP4-MIB": "cisco",
    "FORTINET-FORTIGATE-MIB": "fortinet", "FORTINET-CORE-MIB": "fortinet",
    "JUNIPER-MIB": "juniper", "JUNIPER-CFGMGMT-MIB": "juniper",
    "MIKROTIK-MIB": "mikrotik",
    "CPQHLTH-MIB": "hp", "CPQIDA-MIB": "hp",
    "EXTREME-TRAP-MIB": "extreme", "EXTREME-V2TRAP-MIB": "extreme", "EXTREME-SYSTEM-MIB": "extreme", "EXTREME-STACKING-MIB": "extreme",
    "EXTREME-PORT-MIB": "extreme", "EXTREME-POE-MIB": "extreme",
}
from autokrp.mibs import CRIT, OK, WARN, trap_level as level  # noqa: E402,F401 — یک قاعده برای هر دو


def tr(*a):
    return subprocess.run(["snmptranslate", "-M", MP, *a], capture_output=True, text=True, errors="replace").stdout


def find(mod):
    for d in DIRS:
        f = d / mod
        if f.is_file():
            return f
    raise SystemExit(f"MIB {mod} پیدا نشد")


if "--relevel" in sys.argv:          # فقط سطح‌ها دوباره (بدون snmptranslate)
    out = Path(__file__).resolve().parents[1] / "autokrp" / "trapdb.json"
    db = json.loads(out.read_text(encoding="utf-8"))
    for v in db["traps"].values():
        v["s"] = level(v["n"])
    out.write_text(json.dumps(db, ensure_ascii=False, separators=(",", ":"), sort_keys=True), encoding="utf-8")
    raise SystemExit(0)
traps, objs = {}, {}
for mod, vendor in MODULES.items():
    text = find(mod).read_text(errors="ignore")
    names = sorted(set(re.findall(r"^\s*([a-z][A-Za-z0-9-]*)\s+(?:NOTIFICATION-TYPE|TRAP-TYPE)\b", text, re.M)))
    for nm in names:
        oid = tr("-m", "+" + mod, "-On", f"{mod}::{nm}").strip()
        if not oid.startswith("."):
            continue
        d = tr("-m", "+" + mod, "-Td", f"{mod}::{nm}")
        om = re.search(r"(?:OBJECTS|VARIABLES)\s*\{([^}]*)\}", d)
        ob = [x.strip() for x in om.group(1).split(",") if x.strip()] if om else []
        dm = re.search(r'DESCRIPTION\s*"([^"]*)"', d)
        desc = re.sub(r"\s+", " ", dm.group(1)).strip() if dm else ""
        first = re.split(r"(?<=[.])\s", desc, maxsplit=1)[0][:220]
        olist = []
        for o in ob:
            ooid = tr("-m", "+" + mod, "-IR", "-On", o).strip()      # -IR: نام بدون ماژول در خود MIB و importهایش
            if not ooid.startswith("."):
                continue
            olist.append(ooid[1:])
            if ooid[1:] not in objs:
                od = tr("-m", "+" + mod, "-Td", ooid)
                e = {}
                em = re.search(r"SYNTAX\s+\S+\s*\{([^}]*)\}", od)
                if em:
                    for lab, v in re.findall(r"([A-Za-z][\w-]*)\((-?\d+)\)", em.group(1)):
                        e[v] = lab
                objs[ooid[1:]] = {"n": o.split("::")[-1], **({"e": e} if e else {})}
        traps[oid[1:]] = {"n": nm, "m": mod, "v": vendor, "s": level(nm), "d": first, "o": olist}
    print(f"{mod}: {len(names)}", file=sys.stderr)
out = Path(__file__).resolve().parents[1] / "autokrp" / "trapdb.json"
out.write_text(json.dumps({"source": "LibreNMS mibs + net-snmp snmptranslate", "traps": traps, "objs": objs}, ensure_ascii=False,
                          separators=(",", ":"), sort_keys=True), encoding="utf-8")
print(f"{len(traps)} traps, {len(objs)} objects ← {out}", file=sys.stderr)
