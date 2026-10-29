"""نقشه‌ی توپولوژی (1.26): همسایه‌های هر هدف SNMP از LLDP-MIB (استاندارد)، CISCO-CDP-MIB و MIKROTIK-MIB (mtxrNeighborTable).
همه‌ی OIDها با snmptranslate از فایل MIB واقعی (LibreNMS) گرفته شد. همسایه با IP یا نام سیستم (sysName) به هدف مانیتورینگ
وصل می‌شود؛ همسایه‌ی ناشناخته هم نشان داده می‌شود. پیشنهاد «وابسته به» با پیمایش از ریشه (BFS) روی لینک‌های شناخته.
نتیجه‌ی آخرین اسکن رمزشده در monitor/topology.dat."""
import ipaddress
import json
import logging
import re
import threading
import time

from . import atrest, paths

log = logging.getLogger(__name__)
LLDP_REM = {"chassis": "1.0.8802.1.1.2.1.4.1.1.5", "port_id": "1.0.8802.1.1.2.1.4.1.1.7", "port_desc": "1.0.8802.1.1.2.1.4.1.1.8",
            "sysname": "1.0.8802.1.1.2.1.4.1.1.9"}
LLDP_LOC = {"id": "1.0.8802.1.1.2.1.3.7.1.3", "desc": "1.0.8802.1.1.2.1.3.7.1.4"}
LLDP_MAN = "1.0.8802.1.1.2.1.4.2.1.3"          # lldpRemManAddrIfSubtype؛ آدرس در اندیس جدول است
CDP = {"type": "1.3.6.1.4.1.9.9.23.1.2.1.1.3", "addr": "1.3.6.1.4.1.9.9.23.1.2.1.1.4", "dev": "1.3.6.1.4.1.9.9.23.1.2.1.1.6",
       "port": "1.3.6.1.4.1.9.9.23.1.2.1.1.7", "plat": "1.3.6.1.4.1.9.9.23.1.2.1.1.8"}
MTX = {"ip": "1.3.6.1.4.1.14988.1.1.11.1.1.2", "mac": "1.3.6.1.4.1.14988.1.1.11.1.1.3", "plat": "1.3.6.1.4.1.14988.1.1.11.1.1.5",
       "ident": "1.3.6.1.4.1.14988.1.1.11.1.1.6", "ifidx": "1.3.6.1.4.1.14988.1.1.11.1.1.8"}
IF_NAME = "1.3.6.1.2.1.31.1.1.1.1"


def _ip4(v):
    """آدرس ۴ بایتی CDP: «0a:00:00:01» (هگز) یا رشته‌ی ۴ نویسه‌ای (وقتی بایت‌ها چاپ‌شدنی بودند)."""
    if isinstance(v, str):
        if re.fullmatch(r"([0-9a-f]{2}:){3}[0-9a-f]{2}", v):
            return ".".join(str(int(x, 16)) for x in v.split(":"))
        if len(v) == 4:
            return ".".join(str(ord(c)) for c in v)
        try:
            return str(ipaddress.ip_address(v))
        except ValueError:
            return ""
    return ""


def norm_name(s):
    """«SW1.corp.local» / «SW1(FOC123)» / «sw1» ← «sw1»"""
    s = str(s or "").strip().lower()
    s = re.sub(r"\(.*\)$", "", s).strip()
    return s.split(".")[0] if s and not re.fullmatch(r"[\d.]+", s) else s


async def neighbors(client, cred, host, port, timeout=3, retries=1):
    """همسایه‌های یک دستگاه: [{proto, local, rname, rport, rip, plat}] — جدولی که دستگاه ندارد نادیده گرفته می‌شود."""
    out, errs = [], []
    ifn = {}
    try:
        w = await client.awalk(cred, host, port, [IF_NAME], timeout, retries, max_rows=2000)
        ifn = {k: v for k, v in w[IF_NAME].items()}
    except Exception as e:  # noqa
        errs.append(f"ifName: {e}")
    try:
        w = await client.awalk(cred, host, port, list(LLDP_REM.values()), timeout, retries, max_rows=2000)
        loc = await client.awalk(cred, host, port, list(LLDP_LOC.values()), timeout, retries, max_rows=2000)
        man = await client.awalk(cred, host, port, [LLDP_MAN], timeout, retries, max_rows=2000)
        mip = {}
        for idx in man[LLDP_MAN]:
            p = idx.split(".")
            if len(p) >= 9 and p[3] == "1" and p[4] == "4":            # ipv4(1)، طول ۴
                mip.setdefault(".".join(p[:3]), ".".join(p[5:9]))
        for idx, name in w[LLDP_REM["sysname"]].items():
            p = idx.split(".")
            lp = p[1] if len(p) >= 3 else ""
            out.append({"proto": "LLDP", "local": loc[LLDP_LOC["desc"]].get(lp) or loc[LLDP_LOC["id"]].get(lp) or ifn.get(lp) or lp,
                        "rname": name or w[LLDP_REM["chassis"]].get(idx, ""), "rport": w[LLDP_REM["port_desc"]].get(idx) or w[LLDP_REM["port_id"]].get(idx, ""),
                        "rip": mip.get(".".join(p[:3]), ""), "plat": ""})
    except Exception as e:  # noqa
        errs.append(f"LLDP: {e}")
    try:
        w = await client.awalk(cred, host, port, list(CDP.values()), timeout, retries, max_rows=2000)
        for idx, dev in w[CDP["dev"]].items():
            ifidx = idx.split(".")[0]
            ip = _ip4(w[CDP["addr"]].get(idx)) if w[CDP["type"]].get(idx) in (1, None) else ""
            out.append({"proto": "CDP", "local": ifn.get(ifidx) or ifidx, "rname": dev, "rport": w[CDP["port"]].get(idx, ""),
                        "rip": ip, "plat": w[CDP["plat"]].get(idx, "")})
    except Exception as e:  # noqa
        errs.append(f"CDP: {e}")
    try:
        w = await client.awalk(cred, host, port, list(MTX.values()), timeout, retries, max_rows=2000)
        for idx, ident in w[MTX["ident"]].items():
            ifidx = str(w[MTX["ifidx"]].get(idx, ""))
            out.append({"proto": "MNDP", "local": ifn.get(ifidx) or ifidx, "rname": ident, "rport": "",
                        "rip": w[MTX["ip"]].get(idx, ""), "plat": w[MTX["plat"]].get(idx, "")})
    except Exception as e:  # noqa
        errs.append(f"MikroTik: {e}")
    # یک همسایه با چند پروتکل (LLDP و CDP) یک بار
    seen, uniq = set(), []
    for n in out:
        k = (norm_name(n["rname"]) or n["rip"], str(n["local"]).lower())
        if k in seen:
            continue
        seen.add(k)
        uniq.append(n)
    return uniq, errs


def _demo(targets):
    """Demo: زنجیره‌ی ساختگی بین هدف‌های SNMP (اولی هسته)."""
    snmp = [t for t in targets if t.get("kind") == "snmp"]
    res = {}
    for i, t in enumerate(snmp):
        nb = []
        if i > 0:
            nb.append({"proto": "LLDP", "local": "Gi1/0/48", "rname": snmp[0]["name"], "rport": f"Te1/1/{i}", "rip": snmp[0]["host"], "plat": ""})
        else:
            nb += [{"proto": "CDP", "local": f"Te1/1/{j}", "rname": s["name"], "rport": "Gi1/0/48", "rip": s["host"], "plat": "C9200"}
                   for j, s in enumerate(snmp[1:], 1)]
            nb.append({"proto": "LLDP", "local": "Gi1/0/1", "rname": "unknown-ap-1", "rport": "eth0", "rip": "", "plat": ""})
        res[t["id"]] = (nb, [])
    return res


class Topology:
    def __init__(self, monitor):
        self.mon = monitor
        self.scanning = False
        self.progress = [0, 0]
        self._lock = threading.Lock()

    def _path(self):
        return paths.data_dir() / "monitor" / "topology.dat"

    def load(self):
        p = self._path()
        if not p.exists():
            return None
        try:
            return json.loads(atrest.read_text(p))
        except Exception:  # noqa
            log.exception("topology read")
            return None

    def scan_async(self, user="", ids=()):
        with self._lock:
            if self.scanning:
                return False
            self.scanning = True
        threading.Thread(target=self._scan, args=(user, set(ids)), name="topology", daemon=True).start()
        return True

    def _index(self, targets):
        by_ip, by_name = {}, {}
        for ip, tids in self.mon.events._sources().items():
            by_ip.setdefault(ip, tids[0])
        for t in targets:
            lv = self.mon.snmp.live.get(t["id"]) or {}
            for n in (lv.get("sys") or {}).get("name"), t.get("name"), t.get("host"):
                k = norm_name(n)
                if k:
                    by_name.setdefault(k, t["id"])
        return by_ip, by_name

    def _scan(self, user, ids):
        try:
            targets = [t for t in self.mon.targets().values() if t.get("enabled")]
            snmp_t = [t for t in targets if t.get("kind") == "snmp" and t["id"] in ids]     # فقط دستگاه‌های انتخاب ادمین
            self.progress = [0, len(snmp_t)]
            demo = self.mon.demo
            res = _demo(snmp_t) if demo else {}
            if not demo:
                for t in snmp_t:
                    try:
                        cred = self.mon.snmp.cred_for(t)
                        to = float(t.get("timeout") or 3)
                        res[t["id"]] = self.mon.snmp.client.run(
                            neighbors(self.mon.snmp.client, cred, t["host"], t.get("port") or 161, to, 1), 180)
                    except Exception as e:  # noqa
                        res[t["id"]] = ([], [str(e)[:200]])
                    self.progress[0] += 1
            by_ip, by_name = self._index(targets)
            links, errors = [], {}
            for tid, (nbs, errs) in res.items():
                if errs and not nbs:
                    errors[str(tid)] = errs[:3]
                for n in nbs:
                    other = by_ip.get(n["rip"]) or by_name.get(norm_name(n["rname"]))
                    if other == tid:
                        continue
                    links.append({"a": tid, "a_port": str(n["local"])[:60], "b": other, "b_name": str(n["rname"])[:120],
                                  "b_port": str(n["rport"])[:60], "b_ip": n["rip"], "plat": str(n["plat"])[:80], "proto": n["proto"]})
            # لینک دوطرفه (هر دو طرف همسایه‌ی هم را دیده‌اند) یک بار
            seen, uniq = set(), []
            for lk in links:
                k = (min(lk["a"], lk["b"]), max(lk["a"], lk["b"])) if lk["b"] else (lk["a"], lk["b_name"])
                if lk["b"] and k in seen:
                    continue
                seen.add(k)
                uniq.append(lk)
            data = {"at": time.time(), "by": user, "scanned": len(snmp_t), "links": uniq, "errors": errors}
            self._path().parent.mkdir(parents=True, exist_ok=True)
            atrest.write_text(self._path(), json.dumps(data, ensure_ascii=False))
            if self.mon.history:
                self.mon.history("monitor", "توپولوژی", "ok", f"اسکن همسایه‌ها: {len(snmp_t)} دستگاه SNMP، {len(uniq)} لینک", "")
        except Exception:  # noqa
            log.exception("topology scan")
        finally:
            self.scanning = False


def suggest(links, root, targets):
    """پدر پیشنهادی هر هدف با BFS از ریشه روی لینک‌های بین هدف‌ها: {tid: parent_tid}"""
    adj = {}
    for lk in links:
        if lk.get("b") and lk["a"] in targets and lk["b"] in targets:
            adj.setdefault(lk["a"], set()).add(lk["b"])
            adj.setdefault(lk["b"], set()).add(lk["a"])
    if root not in targets:
        return {}
    par, q = {root: None}, [root]
    while q:
        cur = q.pop(0)
        for n in sorted(adj.get(cur, ())):
            if n not in par:
                par[n] = cur
                q.append(n)
    return {k: v for k, v in par.items() if v is not None}
