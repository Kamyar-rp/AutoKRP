"""نقشه‌های دستی شبکه (1.38): گره (دستگاه مانیتورینگ، ابر، دستگاه بدون مانیتور، زیرنقشه، ناحیه، متن) و لینک پورت‌به‌پورت.
ذخیره در mon_layouts (kind="map")؛ تصویر پس‌زمینه جدا (kind="mapbg"، name = شناسه‌ی نقشه).
وضعیت فقط از داده‌ی همان پایش عادی (state و snmp.live) ساخته می‌شود؛ هیچ درخواست SNMP اضافه‌ای نیست."""
import base64
import re
import time

MAP_MAX = 100
NODE_MAX = 500
LINK_MAX = 1000
BG_MAX = 2 * 1024 * 1024
W_MIN, W_MAX = 600, 6000
NODE_KINDS = ("dev", "cloud", "box", "map", "area", "text")
ICONS = ("router", "switch", "core", "firewall", "server", "wifi", "storage", "pc", "printer", "camera", "phone", "internet", "other")
SIZES = ("s", "m", "l")
LINK_KINDS = ("cable", "fiber", "vpn", "wifi", "none")
COLORS = ("blue", "teal", "green", "orange", "red", "purple", "gray")
NODE_LABELS = ("name", "ip", "load", "none")
LINK_LABELS = ("util", "bps", "ports", "none")
_ID = re.compile(r"^[A-Za-z0-9_-]{1,24}$")
# بدترین وضعیت اول: برای کارت نقشه و زیرنقشه
RANK = {"down": 5, "unreachable": 4, "warn": 3, "unknown": 2, "slow": 1, "up": 0, "paused": -1}


class MapError(ValueError):
    pass


def _num(v, lo, hi, d=0):
    try:
        x = float(v)
    except (TypeError, ValueError):
        return d
    if x != x:
        return d
    return round(max(lo, min(hi, x)), 1)


def _txt(v, n):
    return re.sub(r"[\x00-\x1f\x7f]", " ", str(v or "")).strip()[:n]


def clean_map(d):
    """داده‌ی نقشه از رابط ← ساختار مطمئن. شناسه‌ی گره/لینک فقط حروف و عدد؛ لینک بدون دو سر معتبر حذف می‌شود."""
    d = d if isinstance(d, dict) else {}
    w = int(_num(d.get("w"), W_MIN, W_MAX, 1600))
    h = int(_num(d.get("h"), 400, W_MAX, 900))
    nodes, ids = [], set()
    for n in (d.get("nodes") or [])[:NODE_MAX + 1]:
        if not isinstance(n, dict):
            continue
        nid, k = str(n.get("id") or ""), n.get("t")
        if not _ID.match(nid) or nid in ids or k not in NODE_KINDS:
            continue
        if len(nodes) >= NODE_MAX:
            raise MapError(f"حداکثر {NODE_MAX} شیء در یک نقشه.")
        o = {"id": nid, "t": k, "x": _num(n.get("x"), 0, w), "y": _num(n.get("y"), 0, h), "label": _txt(n.get("label"), 80)}
        if k == "dev":
            try:
                o["tid"] = int(n.get("tid"))
            except (TypeError, ValueError):
                continue
        if k == "map":
            try:
                o["map"] = int(n.get("map"))
            except (TypeError, ValueError):
                continue
        if k in ("dev", "box", "cloud", "map"):
            o["icon"] = n.get("icon") if n.get("icon") in ICONS else ""
            o["size"] = n.get("size") if n.get("size") in SIZES else "m"
        if k == "box":
            o["host"] = _txt(n.get("host"), 80)
        if k == "area":
            o["w"] = _num(n.get("w"), 40, w, 300)
            o["h"] = _num(n.get("h"), 30, h, 200)
            o["color"] = n.get("color") if n.get("color") in COLORS else "blue"
        if k == "text":
            o["size"] = n.get("size") if n.get("size") in SIZES else "m"
            if not o["label"]:
                continue
        ids.add(nid)
        nodes.append(o)
    ends = {n["id"] for n in nodes if n["t"] in ("dev", "cloud", "box", "map")}
    links, lids = [], set()
    for lk in (d.get("links") or [])[:LINK_MAX + 1]:
        if not isinstance(lk, dict):
            continue
        lid, a, b = str(lk.get("id") or ""), str(lk.get("a") or ""), str(lk.get("b") or "")
        if not _ID.match(lid) or lid in lids or a not in ends or b not in ends or a == b:
            continue
        if len(links) >= LINK_MAX:
            raise MapError(f"حداکثر {LINK_MAX} لینک در یک نقشه.")
        kind = lk.get("kind") if lk.get("kind") in LINK_KINDS else "cable"
        o = {"id": lid, "a": a, "b": b, "kind": kind,
             "pa": "" if kind == "none" else _txt(lk.get("pa"), 80), "pb": "" if kind == "none" else _txt(lk.get("pb"), 80)}
        lids.add(lid)
        links.append(o)
    opt = d.get("opt") if isinstance(d.get("opt"), dict) else {}
    return {"w": w, "h": h, "nodes": nodes, "links": links,
            "opt": {"node": opt.get("node") if opt.get("node") in NODE_LABELS else "name",
                    "link": opt.get("link") if opt.get("link") in LINK_LABELS else "util",
                    "grid": opt.get("grid") is not False}}


def clean_bg(data_url):
    """پس‌زمینه: فقط PNG یا JPEG تا ۲ مگابایت (بررسی امضای فایل، نه فقط پسوند). خالی = حذف."""
    if not data_url:
        return ""
    m = re.match(r"^data:image/(png|jpeg);base64,([A-Za-z0-9+/=\s]+)$", str(data_url))
    if not m:
        raise MapError("فقط تصویر PNG یا JPG.")
    try:
        raw = base64.b64decode(m.group(2), validate=False)
    except (ValueError, TypeError):
        raise MapError("تصویر خراب است.")
    if len(raw) > BG_MAX:
        raise MapError("حداکثر حجم تصویر ۲ مگابایت است.")
    if not (raw.startswith(b"\x89PNG\r\n\x1a\n") or raw.startswith(b"\xff\xd8\xff")):
        raise MapError("فقط تصویر PNG یا JPG.")
    kind = "png" if raw.startswith(b"\x89PNG") else "jpeg"
    return f"data:image/{kind};base64," + base64.b64encode(raw).decode()


def _norm(p):
    return re.sub(r"\s+", "", str(p or "")).lower()


def find_if(live, name):
    """پورت با نام، توضیح یا نام مستعار (همان چیزی که کاربر در ویرایشگر انتخاب کرده)."""
    if not live or not name:
        return None
    ifs = live.get("ifs") or []
    k = _norm(name)
    for f in ("name", "descr", "alias"):
        for x in ifs:
            if _norm(x.get(f)) == k:
                return x
    return None


class MapStatus:
    """وضعیت گره‌ها و لینک‌ها؛ زمان شروع قطعی لینک در حافظه (برای «از ۱۸ دقیقه پیش»)."""

    def __init__(self):
        self.down_since = {}

    def node(self, t, st, live):
        if not t:
            return {"st": "gone"}
        if not t.get("enabled"):
            s = "paused"
        else:
            s = st.get("status") or "unknown"
            if s in ("up", "slow") and live and live.get("level") in ("warn", "crit"):
                s = "warn"
        o = {"st": s, "since": st.get("since"), "cause": st.get("cause") or "", "rtt": st.get("rtt"),
             "name": t.get("name") or t.get("host"), "host": t.get("host") or "", "kind": t.get("kind")}
        if live:
            o["cpu"] = (live.get("cpu") or {}).get("value")
            o["mem"] = (live.get("mem") or {}).get("pct")
            o["alarms"] = [a.get("msg") for a in live.get("alarms") or []][:3]
        return o

    def link(self, lid, lk, na, nb, ia, ib, now):
        """na/nb = وضعیت دو سر (None برای ابر/دستگاه بدون مانیتور)؛ ia/ib = سطر پورت از live."""
        o = {"st": "up"}
        dev = [x for x in (na, nb) if x]
        if any(x["st"] in ("down", "unreachable") for x in dev):
            o["st"] = "dev" if any(x["st"] == "down" for x in dev) else "unk"
        elif lk.get("kind") != "none" and (lk.get("pa") or lk.get("pb")):
            ports = [p for p in ((ia, lk.get("pa"), na), (ib, lk.get("pb"), nb)) if p[1] and p[2]]
            rows = [p[0] for p in ports if p[0]]
            if any(r.get("admin") == 2 for r in rows):
                o["st"] = "off"
            elif any(r.get("oper") not in (1, None) for r in rows):
                o["st"] = "down"
            elif not rows:
                o["st"] = "unk" if ports else "up"
            src = next((r for r in rows if r.get("in_bps") is not None), None)
            if src:
                o.update(util=src.get("util"), in_bps=src.get("in_bps"), out_bps=src.get("out_bps"), speed=src.get("speed"))
            o["oper"] = [(r or {}).get("oper") for r in (ia, ib)]
            o["pn"] = [(r or {}).get("name") or "" for r in (ia, ib)]
        elif not dev or all(x["st"] in ("unknown", "paused") for x in dev):
            o["st"] = "unk"
        if o["st"] in ("down", "dev"):
            o["since"] = self.down_since.setdefault(lid, now)
        else:
            self.down_since.pop(lid, None)
        return o


def worst(states):
    """خلاصه‌ی وضعیت: بدترین + شمارش."""
    c = {"up": 0, "down": 0, "warn": 0, "unk": 0}
    w = "up"
    for s in states:
        if s in ("up", "slow"):
            c["up"] += 1
        elif s == "down":
            c["down"] += 1
        elif s == "warn":
            c["warn"] += 1
        elif s != "paused":
            c["unk"] += 1
        if RANK.get(s, 2) > RANK.get(w, 0):
            w = s
    return w, c


def now():
    return time.time()
