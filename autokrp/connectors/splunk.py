"""Splunk: اجرای کوئری با /search/jobs/export و ذخیره‌ی خروجی CSV (منطق splunk.py اصلی)."""
import csv
import json
import ipaddress
import re

from .. import atrest
from .base import BaseConnector, ConnectorError

_SPLIT = re.compile(r"[\r\n,;\s]+")


# کاراکترهایی که هنگام کپی از تلگرام/Word/وب یا در ویندوز فارسی وارد متن کوئری می‌شوند و Splunk را بی‌صدا گمراه می‌کنند
_ODD_SPACES = re.compile(r"[\u00a0\u1680\u2000-\u200a\u202f\u205f\u3000]")
_INVISIBLE = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]")
_QUOTES = str.maketrans({"\u201c": '"', "\u201d": '"', "\u201e": '"', "\u00ab": '"', "\u00bb": '"',
                         "\u2018": "'", "\u2019": "'", "\u0060": "`"})


def clean_query(q):
    """(کوئری پاک‌شده، فهرست تغییرات). بک‌تیک ماکروها دست نمی‌خورد."""
    notes = []
    n = len(_ODD_SPACES.findall(q))
    if n:
        q = _ODD_SPACES.sub(" ", q)
        notes.append(f"{n} فاصله‌ی غیراستاندارد (مثل NBSP) به فاصله‌ی معمولی تبدیل شد")
    n = len(_INVISIBLE.findall(q))
    if n:
        q = _INVISIBLE.sub("", q)
        notes.append(f"{n} کاراکتر نامرئی (مثل RLM، ZWNJ یا BOM) حذف شد")
    smart = sum(q.count(c) for c in "\u201c\u201d\u201e\u00ab\u00bb\u2018\u2019")
    if smart:
        q = q.translate(_QUOTES)
        notes.append(f"{smart} گیومه‌ی غیراستاندارد (مثل “ ” یا « ») به \" یا ' تبدیل شد")
    return q, notes


class SplunkClient(BaseConnector):
    NAME = "splunk"
    query_notes = []

    def test(self) -> dict:
        self.require_credentials()
        url = f"{self.base_url()}/services/server/info"
        r = self.s.get(url, params={"output_mode": "json"}, timeout=(10, 30))
        r.raise_for_status()
        entry = (r.json().get("entry") or [{}])[0].get("content", {})
        return {"message": f"اتصال برقرار است. Splunk {entry.get('version', '?')} روی {entry.get('serverName', '?')}"}

    def prepared(self, earliest=None, latest=None):
        """(url، کوئری نهایی، earliest، latest) — همان چیزی که دقیقاً به Splunk فرستاده می‌شود."""
        app = (self.cfg.get("app") or "search").strip()
        url = f"{self.base_url()}/servicesNS/-/{app}/search/jobs/export"
        query, self.query_notes = clean_query((self.cfg.get("query") or "").replace("\r\n", "\n"))
        query = query.strip()
        if not query:
            raise ConnectorError("کوئری Splunk خالی است.")
        if not query.startswith("|") and not query.lower().startswith("search"):
            query = "search " + query
        return url, query, earliest or self.cfg.get("earliest") or "-24h", latest or self.cfg.get("latest") or "now"

    def whoami(self):
        r = self.s.get(f"{self.base_url()}/services/authentication/current-context", params={"output_mode": "json"}, timeout=(10, 30))
        r.raise_for_status()
        c = (r.json().get("entry") or [{}])[0].get("content", {})
        return {"username": c.get("username", "?"), "roles": c.get("roles", [])}

    def diagnose(self, earliest=None, latest=None, limit=20):
        """
        اجرای آزمایشی با خروجی JSON تا پیام‌های خطا و هشدار خود Splunk هم دیده شوند
        (در خروجی CSV این پیام‌ها نمی‌آیند). کوئری با «| head N» محدود می‌شود.
        """
        self.require_credentials()
        url, query, e, l = self.prepared(earliest, latest)
        info = {"url": url, "app": url.split("/servicesNS/-/")[1].split("/")[0], "query": query, "earliest": e, "latest": l,
                "rows": [], "columns": [], "messages": [], "user": None, "http": None}
        for n in getattr(self, "query_notes", []):
            info["messages"].append({"type": "AUTOKRP", "text": "در متن کوئری: " + n})
        try:
            info["user"] = self.whoami()
        except Exception as ex:  # noqa
            info["messages"].append({"type": "WARN", "text": f"current-context: {ex}"})
        data = {"search": f"{query}\n| head {int(limit)}", "earliest_time": e, "latest_time": l, "output_mode": "json"}
        r = self.s.post(url, data=data, timeout=(10, int(self.cfg.get("timeout") or 600)))
        info["http"] = r.status_code
        body = r.text or ""
        parsed = False
        for line in body.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except ValueError:
                continue
            parsed = True
            if isinstance(obj.get("result"), dict):
                info["rows"].append(obj["result"])
            for m in obj.get("messages") or []:
                info["messages"].append({"type": m.get("type", "INFO"), "text": m.get("text", "")})
        if not parsed and body.strip():
            info["messages"].append({"type": "RAW", "text": body.strip()[:800]})
        cols = []
        for row in info["rows"]:
            for k in row:
                if k not in cols and not k.startswith("_"):
                    cols.append(k)
        info["columns"] = cols
        return info

    def export_csv(self, out_path, earliest=None, latest=None, progress=None) -> int:
        self.require_credentials()
        url, query, e, l = self.prepared(earliest, latest)
        data = {"search": query, "earliest_time": e, "latest_time": l, "output_mode": "csv"}
        timeout = int(self.cfg.get("timeout") or 600)
        buf = bytearray()   # فایل فقط رمزشده روی دیسک نوشته می‌شود

        def download():
            # Splunk تا پایان جستجو چیزی نمی‌فرستد؛ کل دریافت در ترد قابل لغو است تا «لغو» منتظر timeout نماند
            written = 0
            with self.s.post(url, data=data, stream=True, timeout=(10, timeout)) as resp:
                self.s.live_resp = resp
                try:
                    if resp.status_code != 200:
                        raise ConnectorError(f"Splunk خطای {resp.status_code} برگرداند: {resp.text[:800]}")
                    for chunk in resp.iter_content(chunk_size=8192):
                        self.check_cancel()
                        if chunk:
                            buf.extend(chunk)
                            written += len(chunk)
                            if progress:
                                progress(f"{written // 1024} کیلوبایت دریافت شد")
                finally:
                    self.s.live_resp = None
        self.cancellable(download)
        atrest.write_bytes(out_path, bytes(buf))
        rows = read_rows(out_path)
        return len(rows)


def read_rows(path):
    with atrest.open_read(path) as f:
        return [{(k or "").strip(): (v or "").strip() for k, v in r.items()} for r in csv.DictReader(f)]


# نام ستون‌ها در کوئری‌های مختلف؛ به ترتیب اولویت. با تنظیمات splunk.fields قابل تعیین دستی است.
FIELD_CANDIDATES = {
    "src": ["src", "src_ip"],
    "dest": ["dest", "dest_ip"],
    "dest_port": ["dest_port"],
    "signature": ["signatures", "signature", "attack_name"],
    "count": ["attack_count", "count"],
    "first": ["firstTime", "first_time"],
    "last": ["lastTime", "last_time"],
}


def query_hash(query):
    import hashlib
    return hashlib.sha256(clean_query(query or "")[0].strip().encode("utf-8")).hexdigest()[:16]


def resolve_fields(columns, cfg=None):
    """
    نگاشت نقش → ستون. تنظیم کاربر مقدم است:
      نام ستون → همان (حتی اگر در خروجی نباشد، تا بتوان خطای روشن داد)
      "-"       → ندارد
      ""        → تشخیص خودکار از FIELD_CANDIDATES
    """
    cols = list(columns or [])
    manual = dict((cfg or {}).get("fields") or {})
    if not manual.get("src") and (cfg or {}).get("src_field"):
        manual["src"] = cfg["src_field"]
    out = {}
    for role, cands in FIELD_CANDIDATES.items():
        m = (manual.get(role) or "").strip()
        if m == "-":
            out[role] = ""
        elif m:
            out[role] = m
        else:
            out[role] = next((c for c in cands if c in cols), "")
    return out


def suggest_fields(columns, cfg=None):
    """پیشنهاد برای فرم پیش‌نمایش: انتخاب قبلی کاربر اگر در خروجی هست، وگرنه تشخیص خودکار."""
    cols = list(columns or [])
    manual = dict((cfg or {}).get("fields") or {})
    out = {}
    for role, cands in FIELD_CANDIDATES.items():
        m = (manual.get(role) or "").strip()
        if m == "-" and role != "src":
            out[role] = "-"
        elif m and m in cols:
            out[role] = m
        else:
            out[role] = next((c for c in cands if c in cols), "" if role == "src" else "-")
    return out


def _to_int(v):
    try:
        return int(float(v))
    except (TypeError, ValueError):
        return 0


def extract_sources(rows, fields):
    """
    IPهای یکتای ستون مبدأ به‌همراه خلاصه‌ی حمله برای هر IP.
    fields: خروجی resolve_fields (یا نام ستون مبدأ به‌صورت رشته، برای سازگاری).
    فقط IPv4 معتبر برگردانده می‌شود (مثل اسکریپت AbuseIPDB).
    """
    if isinstance(fields, str):
        fields = {"src": fields}
    src_f = fields.get("src") or "src"
    if rows and src_f not in rows[0]:
        cols = ", ".join(rows[0].keys())
        raise ConnectorError(f"ستون «{src_f}» در خروجی Splunk نیست. ستون‌های موجود: {cols}")
    sig_f, cnt_f, port_f = fields.get("signature"), fields.get("count"), fields.get("dest_port")
    first_f, last_f = fields.get("first"), fields.get("last")
    out = {}
    for r in rows:
        for ip in [x.strip() for x in _SPLIT.split(r.get(src_f, "")) if x.strip()]:
            try:
                if not isinstance(ipaddress.ip_address(ip), ipaddress.IPv4Address):
                    continue
            except ValueError:
                continue
            d = out.setdefault(ip, {"attack_count": 0, "signatures": set(), "dest_ports": set(),
                                    "first": "", "last": ""})
            d["attack_count"] += _to_int(r.get(cnt_f)) if cnt_f else 0
            for s in re.split(r",\s*|\n", r.get(sig_f, "") if sig_f else ""):
                if s.strip():
                    d["signatures"].add(s.strip())
            for p in re.split(r"[,\s]+", r.get(port_f, "") if port_f else ""):
                if p.strip():
                    d["dest_ports"].add(p.strip())
            if first_f and r.get(first_f) and (not d["first"] or r[first_f] < d["first"]):
                d["first"] = r[first_f]
            if last_f and r.get(last_f) and r[last_f] > d["last"]:
                d["last"] = r[last_f]
    for d in out.values():
        d["signatures"] = sorted(d["signatures"])
        d["dest_ports"] = sorted(d["dest_ports"], key=lambda x: (0, int(x)) if x.isdigit() else (1, x))
    return out
