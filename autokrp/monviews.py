"""
نمایش مانیتورینگ (1.35): قالب‌های نمایش دستگاه، داشبوردهای NOC، نماهای ذخیره‌شده‌ی جدول و ردیف‌های فشرده (فقط تغییرات).

- قالب نمایش فقط «چه چیزی و به چه ترتیبی دیده شود» را تعیین می‌کند (کارت، صفحه‌ی جزئیات)؛ چه چیزی خوانده شود
  همچنان با «سیاست پایش» است. هدف بدون قالب = خودکار از روی آیکن.
- ردیف فشرده: وضعیت زنده‌ی هر هدف (~۲۰۰ بایت)؛ رابط هر چند ثانیه فقط ردیف‌های تغییرکرده را می‌گیرد (rev).
"""
import json
import threading
import time

# ---------------------------------------------------------------- قالب نمایش
CARD_FIELDS = ("rtt", "avail", "cpu", "mem", "temp", "disk", "uptime", "ports_up", "traffic", "alarms", "sessions", "hw", "err_ports")
TABS = ("sum", "ports", "hw", "oids", "charts")
SUM_CHARTS = ("cpu_mem", "traffic", "temp", "rtt", "sessions")
# 1.36: بلوک‌های بخش «خلاصه» (فقط نمایش داده‌ای که همین حالا خوانده می‌شود)
BLOCKS = ("kpi", "health", "modules", "top_ports", "err_ports", "alarms", "info")
DEFAULT_BLOCKS = ["kpi", "alarms", "info"]
BUILTIN_TPL = {
    # 1.36: قالب سازنده‌ها — دستگاهی که سازنده‌اش تشخیص داده شود (sysObjectID) خودکار همین را می‌گیرد
    "b:cisco": {"name": "Cisco (Catalyst / Nexus / ISR)", "vendor": "cisco", "card": ["ports_up", "traffic", "cpu", "hw"],
                "tabs": ["sum", "ports", "hw", "charts", "oids"], "sum_charts": ["traffic", "cpu_mem", "temp"], "ports": 2,
                "blocks": ["kpi", "health", "modules", "top_ports", "err_ports", "alarms", "info"]},
    "b:juniper": {"name": "Juniper (EX / MX / SRX)", "vendor": "juniper", "card": ["cpu", "mem", "temp", "hw"],
                  "tabs": ["sum", "ports", "hw", "charts", "oids"], "sum_charts": ["cpu_mem", "traffic", "temp"], "ports": 2,
                  "blocks": ["kpi", "modules", "health", "top_ports", "err_ports", "alarms", "info"]},
    "b:extreme": {"name": "Extreme (EXOS)", "vendor": "extreme", "card": ["ports_up", "traffic", "cpu", "hw"],
                  "tabs": ["sum", "ports", "hw", "charts", "oids"], "sum_charts": ["traffic", "cpu_mem", "temp"], "ports": 2,
                  "blocks": ["kpi", "health", "top_ports", "err_ports", "alarms", "info"]},
    "b:fortinet": {"name": "FortiGate", "vendor": "fortinet", "card": ["cpu", "mem", "sessions", "traffic"],
                   "tabs": ["sum", "charts", "ports", "hw", "oids"], "sum_charts": ["cpu_mem", "sessions", "traffic"], "ports": 2,
                   "blocks": ["kpi", "health", "top_ports", "err_ports", "alarms", "info"]},
    "b:switch": {"name": "سوییچ", "card": ["ports_up", "traffic", "cpu"], "tabs": ["sum", "ports", "charts", "hw", "oids"],
                 "sum_charts": ["traffic", "cpu_mem"], "ports": 2},
    "b:router": {"name": "روتر و لینک", "card": ["rtt", "traffic", "cpu"], "tabs": ["sum", "charts", "ports", "hw", "oids"],
                 "sum_charts": ["traffic", "rtt", "cpu_mem"], "ports": 2},
    "b:firewall": {"name": "فایروال", "card": ["cpu", "mem", "sessions", "traffic"], "tabs": ["sum", "charts", "ports", "hw", "oids"],
                   "sum_charts": ["cpu_mem", "traffic"], "ports": 2},
    "b:server": {"name": "سرور", "card": ["cpu", "mem", "disk", "uptime"], "tabs": ["sum", "charts", "hw", "ports", "oids"],
                 "sum_charts": ["cpu_mem", "temp"], "ports": 1},
    "b:generic": {"name": "عمومی", "card": ["rtt", "cpu", "mem"], "tabs": ["sum", "ports", "hw", "oids", "charts"],
                  "sum_charts": ["cpu_mem"], "ports": 1},
}
NON_NET_ICONS = ("server", "pc", "storage", "camera", "printer", "phone")
VENDOR_TPL = {"cisco": "b:cisco", "juniper": "b:juniper", "extreme": "b:extreme", "fortinet": "b:fortinet"}
ICON_TPL = {"switch": "b:switch", "router": "b:router", "internet": "b:router", "wifi": "b:router", "firewall": "b:firewall",
            "server": "b:server", "storage": "b:server", "pc": "b:server"}
TPL_MAX = 50
NOC_MAX = 30


class ViewError(Exception):
    pass


def auto_tpl(icon):
    return ICON_TPL.get(str(icon or ""), "b:generic")


def _pick(lst, allowed, n):
    out = []
    for x in lst if isinstance(lst, list) else []:
        if x in allowed and x not in out:
            out.append(x)
    return out[:n]


def clean_tpl(d):
    d = d if isinstance(d, dict) else {}
    tabs = _pick(d.get("tabs"), TABS, len(TABS))
    if not tabs:
        raise ViewError("دست‌کم یک بخش در صفحه‌ی جزئیات لازم است.")
    try:
        ports = max(0, min(4, int(d.get("ports", 2))))
    except (TypeError, ValueError):
        ports = 2
    blocks = _pick(d.get("blocks"), BLOCKS, len(BLOCKS)) if "blocks" in d else list(DEFAULT_BLOCKS)
    return {"card": _pick(d.get("card"), CARD_FIELDS, 4), "tabs": tabs, "sum_charts": _pick(d.get("sum_charts"), SUM_CHARTS, 5),
            "ports": ports, "blocks": blocks}


def _builtin(key):
    b = BUILTIN_TPL[key]
    return {**b, "blocks": list(b.get("blocks") or DEFAULT_BLOCKS)}


def resolve_tpl(t, custom, vendor=None):
    """قالب مؤثر هدف: {id, name, card, tabs, sum_charts, ports, blocks, auto}.
    ترتیب: قالب انتخاب‌شده ← قالب سازنده‌ی تشخیص‌داده‌شده (1.36) ← از روی آیکن."""
    key = str(t.get("tpl") or "")
    if key and key in BUILTIN_TPL:
        return {"id": key, "auto": False, **_builtin(key)}
    if key.isdigit() and int(key) in custom:
        c = custom[int(key)]
        return {"id": key, "auto": False, "name": c["name"], **c["data"]}
    # آیکن غیرشبکه‌ای (سرور، کامپیوتر، ذخیره‌ساز…) یعنی کاربر خودش نوع را گفته: قالب آیکن مقدم است
    a = VENDOR_TPL.get(vendor or "") if t.get("kind") == "snmp" and str(t.get("icon") or "") not in NON_NET_ICONS else None
    a = a or auto_tpl(t.get("icon"))
    return {"id": a, "auto": True, **_builtin(a)}


# ---------------------------------------------------------------- داشبورد NOC
NOC_LAYOUTS = ("tiles", "table", "mixed")
TABLE_COLS = ("status", "name", "host", "grp", "policy", "rtt", "avail", "cpu", "mem", "temp", "disk", "uptime", "ports_up",
              "traffic", "alarms", "last", "interval", "kind")
DEFAULT_COLS = ["status", "name", "host", "rtt", "avail", "cpu", "mem", "traffic", "alarms"]


def clean_noc(d):
    d = d if isinstance(d, dict) else {}
    sc = d.get("scope") if isinstance(d.get("scope"), dict) else {}
    groups = [str(g).strip()[:60] for g in (sc.get("groups") or [])[:100] if str(g).strip()]
    ids = []
    for i in (sc.get("ids") or [])[:2000]:
        try:
            ids.append(int(i))
        except (TypeError, ValueError):
            continue
    every = bool(sc.get("all", not groups and not ids))
    layout = d.get("layout") if d.get("layout") in NOC_LAYOUTS else "tiles"
    big = []
    for i in (d.get("big") or [])[:40]:
        try:
            big.append(int(i))
        except (TypeError, ValueError):
            continue
    charts = []
    for c in (d.get("charts") or [])[:12]:
        if not isinstance(c, dict):
            continue
        try:
            tid = int(c.get("tid"))
        except (TypeError, ValueError):
            continue
        port = str(c.get("port") or "").strip()[:80]
        if port:
            charts.append({"tid": tid, "port": port, "title": str(c.get("title") or "").strip()[:60]})
    try:
        sec = int(d.get("rotate_sec") or 0)
    except (TypeError, ValueError):
        sec = 0
    if sec and not 10 <= sec <= 3600:
        raise ViewError("زمان نمایش در چرخش باید بین ۱۰ ثانیه و ۱ ساعت باشد (یا ۰ = بیرون از چرخش).")
    rng = d.get("range") if d.get("range") in ("1h", "6h", "24h") else "6h"
    return {"scope": {"all": every, "groups": groups, "ids": ids}, "layout": layout, "big": big, "charts": charts,
            "cols": _pick(d.get("cols"), TABLE_COLS, len(TABLE_COLS)) or list(DEFAULT_COLS), "rotate_sec": sec,
            "feed": bool(d.get("feed", True)), "problems": bool(d.get("problems", True)), "range": rng}


def in_scope(t, d):
    sc = d["scope"]
    if sc["all"]:
        return True
    return t["id"] in sc["ids"] or (t.get("grp") or "") in sc["groups"]


# ---------------------------------------------------------------- نماهای جدول (هر کاربر، save_ui)
def clean_views(v):
    """{"cur": نام، "list": [{name, mode, cols, sort, dir, filter, q, grp, size}]}"""
    if v is None:
        return None
    if not isinstance(v, dict) or len(json.dumps(v, ensure_ascii=False)) > 20000:
        raise ViewError("مقدار نامعتبر است.")
    out = []
    for x in (v.get("list") or [])[:20]:
        if not isinstance(x, dict):
            continue
        name = str(x.get("name") or "").strip()[:40]
        if not name or any(o["name"] == name for o in out):
            continue
        try:
            size = int(x.get("size") or 100)
        except (TypeError, ValueError):
            size = 100
        st = [s for s in (x.get("status") or []) if s in ("up", "down", "slow", "unreachable", "unknown", "paused", "maint", "alarm")]
        out.append({"name": name, "mode": "table" if x.get("mode") == "table" else "cards",
                    "cols": _pick(x.get("cols"), TABLE_COLS, len(TABLE_COLS)) or list(DEFAULT_COLS),
                    "sort": x.get("sort") if x.get("sort") in TABLE_COLS else "status", "dir": -1 if x.get("dir") == -1 else 1,
                    "status": st, "q": str(x.get("q") or "")[:80], "grp": str(x.get("grp") or "")[:60],
                    "size": size if size in (25, 50, 100, 200) else 100})
    cur = str(v.get("cur") or "")[:40]
    return {"cur": cur if any(o["name"] == cur for o in out) else "", "list": out}


# ---------------------------------------------------------------- ردیف‌های فشرده و تغییرات
def _avail(spark):
    vals = [x for x in spark if x is not None]
    return round(sum(vals) / len(vals), 2) if vals else None


def row(mon, t):
    """وضعیت زنده‌ی فشرده‌ی یک هدف (t: هدف مؤثر از Monitor.targets())."""
    pub = mon.public(t)
    st = mon.state.get(t["id"]) or {}
    r = {"id": t["id"], "st": pub["status"], "since": pub.get("since"), "rtt": pub.get("rtt"), "err": (pub.get("err") or "")[:160],
         "maint": pub.get("maint") or "", "cause": pub.get("cause") or "", "last": pub.get("last"), "spark": pub["spark"],
         "avail": _avail(pub["spark"]), "iv": t.get("interval"), "pol": t.get("_policy") or "", "fails": st.get("fails", 0)}
    if pub.get("cert"):
        r["cert"] = pub["cert"]
    if t.get("kind") == "snmp":
        lv = mon.snmp.live.get(t["id"])
        if lv:
            ifs = lv["ifs"]
            r.update(cpu=lv["cpu"]["value"] if lv["cpu"] else None, mem=lv["mem"]["pct"] if lv["mem"] else None,
                     temp=lv["temp_max"], disk=lv["disk_max"], up=lv.get("uptime_s"), lvl=lv["level"], al=len(lv["alarms"]),
                     alm=[a["msg"] for a in lv["alarms"]][:3], pu=sum(1 for x in ifs if x["oper"] == 1), pn=len(ifs),
                     ses=(lv.get("extra") or {}).get("sessions"), sys=(lv["sys"].get("name") or "")[:60],
                     ports=mon.snmp.port_rows(t["id"]))
            # 1.36: سلامت سخت‌افزار (فن، منبع تغذیه، دما، سنسور) و پورت‌های دارای خطا
            hw = [x.get("state") or "ok" for k in ("fans", "psus", "temps", "sensors") for x in (lv.get(k) or [])]
            hw += [c["level"] for c in ((lv.get("extra") or {}).get("components") or []) if c.get("level") in ("ok", "warn")]   # Juniper
            r.update(hwn=len(hw), hwb=sum(1 for s in hw if s in ("warn", "crit")), hwc=sum(1 for s in hw if s == "crit"),
                     pe=sum(1 for x in ifs if x["admin"] == 1 and ((x.get("err_min") or 0) > 0 or (x.get("disc_min") or 0) > 0)))
    return r


class Rows:
    """شماره‌ی تغییر (rev) برای هر هدف: رابط فقط ردیف‌های تازه‌تر از rev خودش را می‌گیرد."""

    def __init__(self, mon):
        self.mon = mon
        self.rev = 0
        self._sig, self._rev, self._row = {}, {}, {}
        self._lock = threading.Lock()
        self._at = 0.0

    def refresh(self, min_gap=1.0):
        now = time.time()
        with self._lock:
            if now - self._at < min_gap:
                return
            self._at = now
            ts = self.mon.targets()
            for tid in [k for k in self._row if k not in ts]:
                self._row.pop(tid, None)
                self._sig.pop(tid, None)
                self._rev.pop(tid, None)
            for tid, t in ts.items():
                r = row(self.mon, t)
                sig = json.dumps(r, sort_keys=True, default=str)
                if sig != self._sig.get(tid):
                    self.rev += 1
                    self._sig[tid], self._rev[tid], self._row[tid] = sig, self.rev, r

    def changed(self, since, visible):
        self.refresh()
        with self._lock:
            since = int(since or 0)
            if since > self.rev:            # برنامه دوباره اجرا شده: همه
                since = 0
            return self.rev, [self._row[i] for i in visible if i in self._row and self._rev.get(i, 0) > since]
