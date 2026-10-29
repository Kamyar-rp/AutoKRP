"""نسخه‌ی Demo هر چهار سیستم با همان رابط؛ داده‌ی ساختگی و قطعی (بر اساس hash IP)."""
import csv
import hashlib
import random
import time
from datetime import datetime, timedelta

from .. import atrest
from .base import BaseConnector, ConnectorError
from .abuseipdb import AbuseClient
from .fortigate import FortiClient, parse_address_objects
from .redmine import RedmineClient
from .splunk import SplunkClient, read_rows

SIGS = ["ET SCAN Suspicious inbound to MSSQL port 1433", "ET SCAN NMAP -sS window 1024",
        "ET SCAN Potential SSH Scan", "ET DROP Dshield Block Listed Source",
        "ET SCAN Zmap User-Agent (Inbound)", "GPL SCAN Nessus probe"]
PORTS = ["22", "23", "80", "443", "445", "1433", "3389", "8080"]
DESTS = ["203.0.113.10", "203.0.113.44", "198.51.100.15", "198.51.100.20", "192.0.2.7"]  # رنج‌های مستندسازی RFC 5737
# چند IP داخل رنج‌های ignore و Address تا تصمیم‌های مختلف دیده شوند
SRC_POOL = ["45.155.205.%d", "193.163.125.%d", "167.94.138.%d", "162.142.125.%d", "71.6.199.%d",
            "89.248.165.%d", "185.224.128.%d", "198.235.24.%d", "205.210.31.%d"]


# IPهای ثابت تا همه‌ی حالت‌های تصمیم فورتی‌گیت در Demo دیده شوند
FIXED_SRCS = ["167.94.138.20", "198.235.24.30", "45.155.205.7", "10.20.30.40"]
FORCED_ABUSE = {"167.94.138.20", "198.235.24.30", "45.155.205.7"}


def _h(ip):
    return int(hashlib.md5(ip.encode(), usedforsecurity=False).hexdigest(), 16)


class _DemoMixin:
    def _lag(self, a=0.15, b=0.5):
        self.sleep(random.uniform(a, b))  # nosec B311 — داده‌ی نمایشی Demo

    def require_credentials(self):
        pass

    def base_url(self):
        return "https://demo.local"


class DemoSplunk(_DemoMixin, SplunkClient):
    def test(self):
        self._lag()
        return {"message": "اتصال Demo برقرار است. Splunk 9.2.1 روی demo-sh01"}

    def export_csv(self, out_path, earliest=None, latest=None, progress=None):
        self._lag(0.6, 1.2)
        rnd = random.Random(int(time.time() // 3600))  # nosec B311 — داده‌ی نمایشی Demo
        now = datetime.now()
        rows = []
        srcs = set()
        while len(srcs) < rnd.randint(14, 22):
            srcs.add(rnd.choice(SRC_POOL) % rnd.randint(1, 254))
        srcs = sorted(srcs) + FIXED_SRCS
        for src in srcs:
            for _ in range(rnd.randint(1, 3)):
                t1 = now - timedelta(hours=rnd.randint(2, 23), minutes=rnd.randint(0, 59))
                t2 = t1 + timedelta(minutes=rnd.randint(1, 90))
                sig = rnd.choice(SIGS)
                dest = rnd.sample(DESTS, rnd.randint(1, 3))
                rows.append({
                    "src": src, "dest_port": rnd.choice(PORTS), "signature": sig,
                    "vendor_product": rnd.choice(["Suricata", "Fortinet FortiGate"]),
                    "category": "Attempted Information Leak", "action": "allowed",
                    "attack_count": rnd.randint(3, 900), "dest_count": len(dest), "dest": ", ".join(dest),
                    "signatures": sig, "firstTime": t1.strftime("%m/%d/%Y %H:%M:%S"),
                    "lastTime": t2.strftime("%m/%d/%Y %H:%M:%S"),
                })
        with atrest.open_write(out_path, "utf-8") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            w.writeheader()
            w.writerows(rows)
        return len(read_rows(out_path))


DEMO_FIELDS = {   # فیلدهای ساختگی هر index برای «بررسی فیلدها» در Demo (شبیه eve.json سوریکاتا و ترافیک فورتی‌گیت)
    "suricata": ["_time", "index", "sourcetype", "host", "event_type", "src_ip", "src_port", "dest_ip", "dest_port", "proto",
                 "alert.signature", "alert.signature_id", "alert.action", "alert.category", "alert.severity"],
    "fortigate": ["_time", "index", "sourcetype", "host", "subtype", "src", "srcip", "dest", "dstip", "dest_port", "dstport", "action",
                  "service", "policyname", "srcintf", "dstintf", "app"],
}


def _demo_diag(self, earliest=None, latest=None, limit=20):
    url, query, e, l = self.prepared(earliest, latest)
    if "fieldsummary" in query:
        idx = "suricata" if "suricata" in query else "fortigate"
        base = query.split("|")[0]
        empty = "category=*" in base           # مثل داده‌ی واقعی: این فیلد در eve.json سوریکاتا نیست ← رخدادی نمی‌آید
        rows = [] if empty else [{"field": f, "count": "5000"} for f in DEMO_FIELDS[idx]]
        return {"url": url, "app": "search", "query": query, "earliest": e, "latest": l, "rows": rows, "columns": ["field", "count"],
                "messages": [], "user": {"username": "demo", "roles": ["user"]}, "http": 200}
    return {"url": url, "app": url.split("/servicesNS/-/")[1].split("/")[0], "query": query, "earliest": e, "latest": l,
            "rows": [{"src": "45.155.205.7", "action": "allowed", "count": "3", "dest_ip": "203.0.113.10", "dest_port": "22,443",
                      "attack_name": "ET SCAN Potential SSH Scan", "firstTime": "2026-10-01T08:59:11", "lastTime": "2026-10-01T16:11:32"}],
            "columns": ["src", "action", "count", "dest_ip", "dest_port", "attack_name", "firstTime", "lastTime"],
            "messages": [{"type": "INFO", "text": "Demo: no real connection"}], "user": {"username": "demo", "roles": ["user"]}, "http": 200}


DemoSplunk.diagnose = _demo_diag


class DemoAbuse(_DemoMixin, AbuseClient):
    def test(self):
        self._lag()
        self.rate = {"limit": "1000", "remaining": str(1000 - random.randint(10, 300))}  # nosec B311 — داده‌ی نمایشی Demo
        return {"message": f"اتصال Demo برقرار است. سهمیه‌ی باقی‌مانده: {self.rate['remaining']} از 1000",
                "rate": self.rate}

    def check_ip(self, ip, max_age=None, retries=None, log=None):
        self._lag(0.05, 0.2)
        h = _h(ip)
        if h % 17 == 0:
            return {"success": False, "data": {}, "error": "HTTP 429"}
        score = 0 if h % 4 == 0 else (h % 100)
        if ip in FORCED_ABUSE:
            score = 80
        cats = [c for c in (14, 18, 22, 15, 21) if (h >> c) & 1]
        self.rate = {"limit": "1000", "remaining": str(1000 - (int(time.time()) % 400))}
        return {"success": True, "error": "", "data": {
            "ipAddress": ip, "abuseConfidenceScore": score, "totalReports": 0 if score == 0 else h % 500,
            "countryCode": ["NL", "US", "DE", "RU", "CN", "BG", "IR"][h % 7],
            "countryName": ["Netherlands", "United States of America", "Germany", "Russia", "China", "Bulgaria",
                            "Iran"][h % 7],
            "city": "-", "isp": ["Censys, Inc.", "Shadowserver", "DigitalOcean", "Hetzner", "Unmanaged Ltd"][h % 5],
            "usageType": ["Data Center/Web Hosting/Transit", "Commercial", "Fixed Line ISP"][h % 3],
            "domain": ["censys.io", "shadowserver.org", "digitalocean.com", "hetzner.com", "-"][h % 5],
            "asn": 10000 + h % 50000, "isWhitelisted": h % 23 == 0, "isTor": h % 29 == 0,
            "lastReportedAt": (datetime.utcnow() - timedelta(hours=h % 72)).strftime("%Y-%m-%dT%H:%M:%S+00:00"),
            "reports": [{"categories": cats}] if score else [],
        }}

    def pause_between(self):
        self.sleep(0.05)


class DemoForti(_DemoMixin, FortiClient):
    _banned = {}

    def test(self):
        self._lag()
        self.last_banned = self.get_banned()
        return {"message": f"اتصال Demo برقرار است. {len(self.last_banned)} IP در لیست Banned (VDOM {self.vdom})."}

    def get_addresses(self, log=None):
        self._lag()
        raw = [
            {"name": "all", "type": "ipmask", "subnet": "0.0.0.0 0.0.0.0"},
            {"name": "Censys-Scanners", "type": "ipmask", "subnet": "167.94.138.0 255.255.255.0"},
            {"name": "Partner-Range", "type": "iprange", "start-ip": "198.235.24.1", "end-ip": "198.235.24.60"},
            {"name": "LAN", "type": "ipmask", "subnet": "10.0.0.0 255.0.0.0"},
        ]
        return parse_address_objects(raw), len(raw)

    # Demo: سه بلاک Administrative دائمی و یک بلاک خودکار IPS با انقضا (برای «تبدیل به Administrative»)
    _removed = set()

    def get_banned(self):
        self._lag()
        now = int(time.time())
        base = [{"ip": "45.155.205.%d" % i, "created": now - 86400, "source": "Administrative", "expires": 0, "ipv6": False}
                for i in (7, 99, 233)]
        base.append({"ip": "45.155.205.138", "created": now - 600, "source": "IPS", "expires": now + 3000, "ipv6": False})
        base = [b for b in base if b["ip"] not in DemoForti._removed and b["ip"] not in DemoForti._banned]
        return base + [{"ip": ip, "created": t, "source": "Administrative", "expires": 0, "ipv6": False}
                       for ip, t in DemoForti._banned.items()]

    def ban_ip(self, ip):
        self._lag(0.05, 0.25)
        if _h(ip) % 31 == 0:
            return False, "HTTP 500: demo failure"
        DemoForti._banned[ip] = int(time.time())
        DemoForti._removed.discard(ip)
        return True, '{"status": "success"}'

    # Demo سناریوها: Address و Address Group در حافظه (برای هر دستگاه جدا)
    _objs = {}

    def _db(self):
        return DemoForti._objs.setdefault(self.NAME, {"addr": {}, "grp": {"Blocked-IPs": [], "Deny-Inbound": []}})

    def api_request(self, method, path, body=None, params=None):
        from urllib.parse import unquote
        self._lag(0.02, 0.08)
        db, p = self._db(), path.split("/")
        if path.startswith("/api/v2/cmdb/firewall/address"):
            if method == "GET" and len(p) > 6:
                a = db["addr"].get(unquote(p[6]))
                return (200, {"status": "success", "results": [a]}) if a else (404, {"status": "error", "http_status": 404})
            if method == "POST":
                if body["name"] in db["addr"]:
                    return 500, {"status": "error", "error": -5}
                db["addr"][body["name"]] = dict(body)
                return 200, {"status": "success", "mkey": body["name"]}
        if path.startswith("/api/v2/cmdb/firewall/addrgrp/"):
            g = unquote(p[6])
            if g not in db["grp"]:
                return 404, {"status": "error", "http_status": 404}
            if method == "GET":
                return 200, {"status": "success", "results": [{"name": g, "member": [{"name": m} for m in db["grp"][g]]}]}
            if method == "POST" and len(p) > 7:
                if body["name"] not in db["addr"]:
                    return 500, {"status": "error", "error": -3}
                db["grp"][g].append(body["name"])
                return 200, {"status": "success"}
            if method == "DELETE" and len(p) > 8:
                m = unquote(p[8])
                if m in db["grp"][g]:
                    db["grp"][g].remove(m)
                    return 200, {"status": "success"}
                return 404, {"status": "error"}
        if path == "/api/v2/monitor/user/banned" and method == "GET":
            return 200, {"status": "success", "results": [{"ip_address": b["ip"], "source": b["source"]} for b in self.get_banned()]}
        if path == "/api/v2/cmdb/firewall/policy":
            pol = db.setdefault("policy", {})
            if method == "GET":
                return 200, {"status": "success", "results": [{"name": n} for n in pol]}
            if method == "POST":
                pol[body["name"]] = body
                return 200, {"status": "success", "mkey": len(pol)}
        if path == "/api/v2/monitor/user/banned/add_users":
            for ip in body.get("ip_addresses") or []:
                DemoForti._banned[ip] = int(time.time())
            return 200, {"status": "success"}
        if path == "/api/v2/monitor/user/banned/clear_users":
            for ip in body.get("ip_addresses") or []:
                DemoForti._banned.pop(ip, None)
            return 200, {"status": "success"}
        return 404, {"status": "error", "http_status": 404, "path": path}

    def unban_ip(self, ip):
        self._lag(0.05, 0.2)
        DemoForti._banned.pop(ip, None)
        DemoForti._removed.add(ip)
        return True, '{"status": "success"}'


class DemoRedmine(_DemoMixin, RedmineClient):
    _next = 4800

    def test(self):
        self._lag()
        return {"message": "اتصال Demo برقرار است. کاربر: soc.analyst (ادمین: خیر)"}

    def _cfs(self):
        names = [n for n, _ in self.cfg.get("static_fields") or []] + [n for n, _ in self.cfg.get("dynamic_fields") or []]
        return [{"id": 100 + i, "name": n, "field_format": "string"} for i, n in enumerate(names)]

    def discover(self):
        self._lag()
        return {"user": {"id": 42, "login": "soc.analyst", "admin": False},
                "trackers": [{"id": 1, "name": "Bug"}, {"id": 9, "name": "Security Events"}],
                "priorities": [{"id": 1, "name": "None"}, {"id": 2, "name": "Low"}, {"id": 4, "name": "high"}],
                "categories": [{"id": 3, "name": "Event"}, {"id": 4, "name": "Incident"}],
                "fields": [{"id": c["id"], "name": c["name"], "format": "string", "options": []} for c in self._cfs()],
                "fields_source": "sample-issue"}

    _TRACKERS = [{"id": 1, "name": "Bug"}, {"id": 9, "name": "Security Events"}, {"id": 12, "name": "Incident"}]

    def load_meta(self):
        """Demo: Trackerها و فیلدهای نمونه (فیلدهای Security Events شبیه Redmine واقعی کاربر)."""
        self._lag()
        sev = [{"value": v, "label": v} for v in ("Low", "Medium", "High", "Critical")]
        se = [{"id": 101, "name": "Src IP(s)", "format": "text", "required": True, "multiple": False, "default": "", "options": None},
              {"id": 102, "name": "Dest IP(s)", "format": "text", "required": False, "multiple": False, "default": "", "options": None},
              {"id": 103, "name": "Dest-Port(s)", "format": "string", "required": False, "multiple": False, "default": "", "options": None},
              {"id": 104, "name": "Detected Time", "format": "date", "required": True, "multiple": False, "default": "", "options": None},
              {"id": 105, "name": "Severity", "format": "list", "required": True, "multiple": False, "default": "Medium", "options": sev},
              {"id": 106, "name": "Source", "format": "list", "required": False, "multiple": True, "default": "",
               "options": [{"value": v, "label": v} for v in ("IDS", "Firewall", "AbuseIPDB", "FFraud")]}]
        inc = [{"id": 105, "name": "Severity", "format": "list", "required": True, "multiple": False, "default": "High", "options": sev},
               {"id": 107, "name": "Affected host", "format": "string", "required": True, "multiple": False, "default": "", "options": None}]
        return {"fetched_at": time.time(), "by": "admin", "project": self.project, "project_fields_known": True,
                "trackers": self._TRACKERS, "priorities": ["Low", "Normal", "High"], "categories": ["Event", "Incident"],
                "fields": {"1": [], "9": se, "12": inc}}

    def build_context(self):
        self._lag()
        t = next((x for x in self._TRACKERS if x["name"].lower() == str(self.cfg.get("tracker") or "").strip().lower()), None)
        if self.cfg.get("tracker") and not t:
            raise ConnectorError(f"Tracker «{self.cfg.get('tracker')}» در Redmine پیدا نشد")
        ctx = {"tracker_id": t["id"] if t else 9, "priority_id": 1, "category_id": 3, "me_id": 42, "cf_index": self._cfs()}
        meta = self.cfg.get("meta") or {}
        if meta.get("project") == self.project and str(ctx["tracker_id"]) in (meta.get("fields") or {}):
            ctx["meta_fields"] = meta["fields"][str(ctx["tracker_id"])]
        return ctx

    def upload(self, filepath):
        self._lag(0.1, 0.3)
        return {"token": "demo-" + hashlib.md5(filepath.encode(), usedforsecurity=False).hexdigest()[:10],
                "filename": filepath.replace("\\", "/").rsplit("/", 1)[-1], "content_type": "text/csv"}

    def create_issue(self, issue):
        self._lag(0.3, 0.6)
        DemoRedmine._next += 1
        return {"id": DemoRedmine._next}


REAL = {"splunk": SplunkClient, "abuseipdb": AbuseClient, "fortigate": FortiClient, "redmine": RedmineClient}
DEMO = {"splunk": DemoSplunk, "abuseipdb": DemoAbuse, "fortigate": DemoForti, "redmine": DemoRedmine}


def make(name, cfg, cancel_event=None, demo=False):
    cls = (DEMO if demo else REAL).get("fortigate" if str(name).startswith("fortigate") else name)   # 1.28: fortigate2…
    if not cls:
        raise ConnectorError(f"اتصال ناشناخته: {name}")
    return cls(cfg, cancel_event)
