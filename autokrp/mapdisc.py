"""1.45: کشف اتصال‌ها برای نقشه‌ی دستی از جدول ARP و MAC (بدون LLDP/CDP).

فقط با زدن دکمه و فقط برای دستگاه‌هایی که کاربر خواسته (یک دستگاه انتخاب‌شده یا همه‌ی دستگاه‌های نقشه) همان خواندنی انجام می‌شود که
ابزار «محل IP/MAC» می‌کند (nettools.collect_device: ARP، جدول MAC، نام پورت‌ها) به‌علاوه‌ی MAC اینترفیس‌های خود دستگاه
(IF-MIB::ifPhysAddress). نتیجه‌ی هر دستگاه ذخیره می‌شود (mon_layouts، kind="disc"، داخل پایگاه داده‌ی رمزشده) تا در نقشه‌های دیگر
بدون خواندن دوباره استفاده شود. هیچ خواندن دوره‌ای اضافه نمی‌شود و همه‌ی محاسبه داخل برنامه است.

قاعده‌ها (analyze):
- مالک هر MAC: MACهای خود دستگاه‌ها (ifPhysAddress) و IP هدف‌های مانیتورینگ در جدول ARP (IP ← MAC).
- پورت P از سوییچ S که فقط یک دستگاه شناخته‌شده‌ی T را می‌بیند ← لینک S:P ⇄ T. اگر T هم بررسی شده و S را روی پورت Q می‌بیند،
  پورت طرف دیگر Q است و اطمینان «زیاد».
- پورتی که چند دستگاه شناخته‌شده می‌بیند: اگر یکی از آن‌ها (T) بررسی شده و S را روی Q و بقیه را روی پورت‌های دیگر می‌بیند،
  T همسایه‌ی مستقیم است (زیاد)؛ وگرنه پیشنهاد «کم» با همه‌ی گزینه‌ها و پیش‌فرض بدون تیک.
- پورتی بدون دستگاه شناخته‌شده با حداکثر edge_max MAC ← دستگاه‌های ناشناس (یک MAC = یک دستگاه؛ چند MAC = سوییچ مدیریت‌نشده
  وسط). پرتعدادتر ← کنار گذاشته (uplink یا سرور مجازی).
"""
import time

from .nettools import OUI, collect_device, norm_mac

IF_PHYS = "1.3.6.1.2.1.2.2.1.6"     # IF-MIB::ifPhysAddress
ROWS = 20000
EDGE_MAX = 4
SKIP_MACS = {"00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"}


def _mac(v):
    m = norm_mac(v) if isinstance(v, str) else None
    if m is None and isinstance(v, (bytes, bytearray)) and len(v) == 6:
        m = ":".join(f"{b:02x}" for b in v)
    return m if m and m not in SKIP_MACS else None


def own_macs(client, cred, host, port, timeout):
    """MACهای اینترفیس‌های خود دستگاه."""
    c = client.run(client.awalk(cred, host, port, [IF_PHYS], timeout, 1, ROWS), 60)
    out = set()
    for v in (c.get(IF_PHYS) or {}).values():
        m = _mac(v)
        if m:
            out.add(m)
    return sorted(out)


def scan(client, cred, t):
    """یک دستگاه: {t، own، arp، fdb، names، errors}. همان خواندن ابزار «محل IP/MAC» + ifPhysAddress."""
    host, port, to = t["host"], int(t.get("port") or 161), float(t.get("timeout") or 3)
    sysn, arp, fdb, names, errs = collect_device(client, cred, host, port, to, True, True)
    try:
        own = own_macs(client, cred, host, port, to)
    except Exception as e:  # noqa
        own, errs = [], errs + [f"ifPhysAddress: {str(e)[:120]}"]
    nm = {}
    for ifx in {f[2] for f in fdb if f[2] is not None} | {a[2] for a in arp if a[2] is not None}:
        n = names.get(ifx) or {}
        nm[str(ifx)] = n.get("name") or n.get("descr") or f"ifIndex {ifx}"
    return {"t": time.time(), "sys": sysn.get("name") or "", "own": own, "arp": [list(x) for x in arp],
            "fdb": [list(x) for x in fdb], "names": nm, "errors": errs[:10]}


def _pname(d, ifx, bp):
    if ifx is not None:
        return d["names"].get(str(ifx)) or f"ifIndex {ifx}"
    return f"bridge-port {bp}"


def analyze(scope, discs, devs, edge_max=EDGE_MAX):
    """scope: شناسه‌ی دستگاه‌هایی که نتیجه برایشان خواسته شده؛ discs: {tid: نتیجه‌ی scan یا {"own": [...]} }؛
    devs: {tid: {"host"، "name"}} همه‌ی هدف‌های قابل‌دید. خروجی: links، endpoints، crowded."""
    owner = {}
    for tid, d in discs.items():
        for m in d.get("own") or []:
            owner.setdefault(m, tid)
    ip2t = {str(v.get("host") or ""): tid for tid, v in devs.items() if v.get("host")}
    arp_ip = {}
    for tid, d in discs.items():
        for ip, mac, _ifx in d.get("arp") or []:
            m = _mac(mac)
            if not m:
                continue
            arp_ip.setdefault(m, ip)
            if ip in ip2t:
                owner.setdefault(m, ip2t[ip])
    full = {tid for tid, d in discs.items() if d.get("fdb") is not None and "names" in d}

    def ports_of(tid):
        d = discs[tid]
        out = {}
        for m, _v, ifx, bp in d.get("fdb") or []:
            m = _mac(m)
            if m:
                out.setdefault(_pname(d, ifx, bp), set()).add(m)
        return out

    P = {tid: ports_of(tid) for tid in full}

    def sees(a, b):
        """پورت‌هایی از a که MAC دستگاه b را می‌بینند."""
        return [p for p, ms in P.get(a, {}).items() if any(owner.get(m) == b for m in ms)]

    links, endpoints, crowded, seen_pairs = [], [], [], set()
    for s in scope:
        if s not in full:
            continue
        for p, ms in sorted(P[s].items()):
            known = sorted({owner[m] for m in ms if m in owner and owner[m] != s})
            if known:
                best, conf, pb = None, "low", ""
                for t in known:
                    if t not in full:
                        continue
                    q = sees(t, s)
                    if len(q) != 1:
                        continue
                    others = [u for u in known if u != t]
                    if all(q[0] not in sees(t, u) for u in others):
                        best, conf, pb = t, "high", q[0]
                        break
                if best is None and len(known) == 1:
                    best, conf = known[0], "medium" if len(ms) <= edge_max + 2 else "low"
                    q = sees(best, s) if best in full else []
                    if len(q) == 1:
                        pb, conf = q[0], "high"
                key = tuple(sorted([(s, p), (best, pb)], key=str)) if best else None
                if key and key in seen_pairs:
                    continue
                if key:
                    seen_pairs.add(key)
                links.append({"a": s, "pa": p, "b": best, "pb": pb, "conf": conf, "cand": known if best is None else [],
                              "macs": len(ms)})
                continue
            if len(ms) > edge_max:
                crowded.append({"a": s, "port": p, "macs": len(ms)})
                continue
            items = [{"mac": m, "ip": arp_ip.get(m, ""), "vendor": OUI.lookup(m) or ""} for m in sorted(ms)]
            endpoints.append({"a": s, "port": p, "items": items})
    return {"links": links, "endpoints": endpoints, "crowded": crowded[:200]}


def demo_scan(t, peers, i):
    """داده‌ی ساختگی Demo: پورت Gi1/0/(۲۰+k) هر دستگاه دیگر نقشه را می‌بیند؛ یک پورت با یک دستگاه ناشناس و یک پورت با سه."""
    tid = t["id"]
    me = f"00:1a:00:00:{tid // 256 % 256:02x}:{tid % 256:02x}"
    fdb, names, arp = [], {}, []
    for k, p in enumerate(peers):
        ifx = 20 + k
        fdb.append([f"00:1a:00:00:{p // 256 % 256:02x}:{p % 256:02x}", 1, ifx, ifx])
        names[str(ifx)] = f"Gi1/0/{ifx}"
    names["5"], names["6"] = "Gi1/0/5", "Gi1/0/6"
    host = f"00:50:56:{i % 256:02x}:00:05"
    fdb.append([host, 10, 5, 5])
    arp.append([f"10.20.{i % 250}.41", host, 5])
    for x in range(3):
        m = f"3c:52:82:{i % 256:02x}:06:{x:02x}"
        fdb.append([m, 10, 6, 6])
        arp.append([f"10.20.{i % 250}.{60 + x}", m, 6])
    return {"t": time.time(), "sys": t.get("name") or "", "own": [me], "arp": arp, "fdb": fdb, "names": names, "errors": []}
