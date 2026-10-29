"""ساخت assets/mibs (1.27): MIBهای استاندارد همراه برنامه.

  python dev/mibs_build.py <پوشه‌ی mibs مخزن LibreNMS>

- assets/mibs/std.json: قالب فشرده‌ی همه‌ی ماژول‌های زیر و وابستگی‌هایشان (autokrp.mibs.compact).
- assets/mibs/src/<MODULE>: منبع همان ماژول‌ها تا MIB سازنده‌ای که کاربر بارگذاری می‌کند وابستگی‌اش را پیدا کند.
فقط MIBهای استاندارد IETF/IANA و Net-SNMP (BSD)؛ MIB سازنده‌ها را کاربر خودش از سایت سازنده بارگذاری می‌کند.
"""
import json
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from autokrp.mibs import compile_modules  # noqa: E402

STD = ["SNMPv2-MIB", "IF-MIB", "IANAifType-MIB", "EtherLike-MIB", "HOST-RESOURCES-MIB",
       "HOST-RESOURCES-TYPES", "ENTITY-MIB", "ENTITY-SENSOR-MIB", "ENTITY-STATE-MIB", "IP-MIB", "IP-FORWARD-MIB", "TCP-MIB",
       "UDP-MIB", "BRIDGE-MIB", "Q-BRIDGE-MIB", "LLDP-MIB", "UPS-MIB", "POWER-ETHERNET-MIB", "DISMAN-EVENT-MIB",
       "SNMP-FRAMEWORK-MIB", "SNMP-TARGET-MIB", "NOTIFICATION-LOG-MIB", "UCD-SNMP-MIB", "NET-SNMP-MIB", "NET-SNMP-AGENT-MIB",
       "NET-SNMP-EXTEND-MIB", "SNMP-USER-BASED-SM-MIB", "OSPF-MIB", "BGP4-MIB", "RMON-MIB", "VRRP-MIB", "ENTITY-STATE-TC-MIB",
       "DOT3-OAM-MIB", "RADIUS-AUTH-CLIENT-MIB", "SNMP-COMMUNITY-MIB", "HCNUM-TC", "INET-ADDRESS-MIB"]


def main(src_dir):
    src = Path(src_dir)
    out = Path(__file__).resolve().parent.parent / "assets" / "mibs"
    res = compile_modules(STD, [src])
    mods = {}
    for n, (st, val) in sorted(res.items()):
        if st == "ok":
            mods[n] = val
        elif st != "base":
            print("SKIP", n, st, val)
    if (out / "src").exists():
        shutil.rmtree(out / "src")
    (out / "src").mkdir(parents=True)
    for n in mods:
        shutil.copy(src / n, out / "src" / n)
    # MIBهای پایه (SMI) را pysmi کامپایل نمی‌کند ولی برای جدول نمادها منبعشان لازم است
    from pysmi.codegen import JsonCodeGen
    for n in JsonCodeGen.baseMibs:
        if (src / n).is_file():
            shutil.copy(src / n, out / "src" / n)
    (out / "std.json").write_text(json.dumps({"modules": mods}, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    print(len(mods), "modules,", sum(len(m["objs"]) for m in mods.values()), "objects,",
          (out / "std.json").stat().st_size // 1024, "KB")


if __name__ == "__main__":
    main(sys.argv[1])
