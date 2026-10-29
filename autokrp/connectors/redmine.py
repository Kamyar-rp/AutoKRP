"""Redmine: منطق redmine.py اصلی (کشف ID ها، اعتبارسنجی فیلد لیستی، آپلود، ساخت Issue)."""
import csv
import datetime as dt
import ipaddress
import json
import os
import time
import re

import requests

from .. import atrest
from .base import BaseConnector, ConnectorError

SPLIT_RE = re.compile(r"[\r\n,;\s]+")
VAR_RE = re.compile(r"\{([a-z_]+)\}")

TEMPLATE_VARS = {
    "date": "تاریخ شناسایی (اولین firstTime)",
    "src_count": "تعداد IP مبدأ یکتا",
    "dest_count": "تعداد IP مقصد یکتا",
    "checked_count": "تعداد IP بررسی‌شده در AbuseIPDB",
    "abuse_count": "تعداد IP مخرب",
    "clean_count": "تعداد IP غیرمخرب",
    "error_count": "تعداد خطای بررسی",
    "banned_count": "تعداد بلاک‌شده در این اجرا",
    "already_banned_count": "تعداد از قبل Banned",
    "address_match_count": "تعداد تطابق با Address Object",
    "ignored_count": "تعداد IP داخلی مستثنا",
    "ban_failed_count": "تعداد بلاک ناموفق",
    "abuse_list": "لیست IPهای مخرب",
    "banned_list": "لیست IPهای بلاک‌شده",
    "clean_list": "لیست IPهای غیرمخرب",
    "clean_review_count": "تعداد غیرمخرب برای بررسی دستی",
    "clean_review_list": "لیست غیرمخرب‌های بررسی دستی",
}


def split_values(v):
    return [x.strip() for x in SPLIT_RE.split(v or "") if x.strip()]


def ip_key(x):
    try:
        return (0, ipaddress.ip_address(x))
    except ValueError:
        return (1, x)


def port_key(x):
    return (0, int(x)) if x.isdigit() else (1, x)


def parse_time(v):
    v = (v or "").strip()
    if not v:
        return None
    try:
        return dt.datetime.fromtimestamp(float(v))
    except ValueError:
        pass
    v = re.sub(r"(\.\d+)?([+-]\d{2}:?\d{2}|Z)?$", "", v)
    for fmt in ("%m/%d/%Y %H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S",
                "%m/%d/%Y %H:%M", "%Y/%m/%d %H:%M:%S", "%m/%d/%Y", "%Y-%m-%d"):
        try:
            return dt.datetime.strptime(v, fmt)
        except ValueError:
            continue
    return None


def summarize_csv(path, cfg, fields=None):
    """معادل read_csv اسکریپت. fields: نگاشت ستون‌ها (dest، dest_port، first، src)؛ پیش‌فرض نام‌های کوئری قبلی."""
    with atrest.open_read(path) as f:
        rows = [{(k or "").strip(): (v or "").strip() for k, v in r.items()} for r in csv.DictReader(f)]
    fields = fields or {}
    f_src, f_dest = fields.get("src") or "src", fields.get("dest") or "dest"
    f_port, f_first = fields.get("dest_port") or "dest_port", fields.get("first") or "firstTime"
    if not rows:
        raise ConnectorError(f"CSV خالی است: {os.path.basename(path)}")
    per_line = int(cfg.get("src_ips_per_line") or 0)
    sample_n = int(cfg.get("dest_sample_count") or 2)
    suffix = cfg.get("more_suffix", "و ...")

    def pipe_format(items):
        if not items:
            return ""
        n = per_line or len(items)
        return "\n".join("| " + " | ".join(items[i:i + n]) + " |" for i in range(0, len(items), n))

    def sample_format(items):
        out = "\n".join(items[:sample_n])
        if len(items) > sample_n:
            out += "\n" + suffix
        return out

    src, dest, ports, times = set(), set(), set(), []
    for r in rows:
        src.update(split_values(r.get(f_src)))
        dest.update(split_values(r.get(f_dest)))
        ports.update(split_values(r.get(f_port)))
        t = parse_time(r.get(f_first))
        if t:
            times.append(t)
    first = min(times) if times else dt.datetime.now()
    return {
        "src_ips": pipe_format(sorted(src, key=ip_key)),
        "dest_ips": sample_format(sorted(dest, key=ip_key)),
        "dest_ports": sample_format(sorted(ports, key=port_key)),
        "detected_date": first.strftime("%Y-%m-%d"),
        "first_time": first,
        "counts": {"src": len(src), "dest": len(dest), "ports": len(ports), "rows": len(rows)},
        "pipe_format": pipe_format,
    }


def render_template(template, variables):
    """فقط {متغیر}های شناخته‌شده جایگزین می‌شوند؛ آکولادهای دیگر دست نمی‌خورند."""
    return VAR_RE.sub(lambda m: str(variables[m.group(1)]) if m.group(1) in variables else m.group(0), template)


def find_by_name(items, name, key="name"):
    low = str(name).strip().lower()
    for it in items:
        if str(it.get(key, "")).strip().lower() == low:
            return it
    return None


def resolve_field_ids(cf_index, names, overrides):
    ids, missing = {}, []
    for name in names:
        if name in overrides:
            ids[name] = overrides[name]
            continue
        hit = find_by_name(cf_index, name)
        if not hit:
            prefix = name.strip().lower().rstrip(" .)")
            cand = [c for c in cf_index if c["name"].strip().lower().startswith(prefix)]
            hit = cand[0] if len(cand) == 1 else None
        if hit:
            ids[name] = hit["id"]
        else:
            missing.append(name)
    return ids, missing


def normalize_value(cf, name, value):
    pv = (cf or {}).get("possible_values") or []
    if not pv or value in (None, ""):
        return value
    values = [str(p.get("value")) for p in pv]
    if str(value) in values:
        return str(value)
    by_label = {str(p.get("label") or p.get("value")).strip().lower(): str(p.get("value")) for p in pv}
    hit = by_label.get(str(value).strip().lower())
    if hit is not None:
        return hit
    opts = [f"{p.get('label') or p.get('value')}" for p in pv]
    raise ConnectorError(f"مقدار «{value}» برای فیلد «{name}» معتبر نیست. گزینه‌های مجاز: {opts}")


class RedmineClient(BaseConnector):
    NAME = "redmine"

    def __init__(self, cfg, cancel_event=None):
        super().__init__(cfg, cancel_event)
        self.project = cfg.get("project") or ""

    def get(self, path, **params):
        self.require_credentials()
        r = self.s.get(f"{self.base_url()}{path}", params=params, timeout=30)
        r.raise_for_status()
        return r.json()

    def test(self):
        u = self.get("/users/current.json")["user"]
        return {"message": f"اتصال برقرار است. کاربر: {u.get('login')} (ادمین: {'بله' if u.get('admin') else 'خیر'})"}

    def upload(self, filepath):
        name = os.path.basename(filepath)
        data = atrest.read_bytes(filepath)   # فایل‌های اجرا رمزشده‌اند؛ نسخه‌ی ساده فقط برای ارسال
        if name.lower().endswith(".csv"):     # پیوست با Excel باز می‌شود: بدون فرمول اجرایی
            from ..csvsafe import sanitize_bytes
            data = sanitize_bytes(data)
        r = self.s.post(f"{self.base_url()}/uploads.json", params={"filename": name}, data=data,
                        headers={"Content-Type": "application/octet-stream"}, timeout=60)
        r.raise_for_status()
        return {"token": r.json()["upload"]["token"], "filename": name, "content_type": "text/csv"}

    def create_issue(self, issue):
        r = self.s.post(f"{self.base_url()}/issues.json", json={"issue": issue}, timeout=60)
        if r.status_code == 422:
            raise ConnectorError("خطای اعتبارسنجی Redmine: " + json.dumps(r.json(), ensure_ascii=False))
        r.raise_for_status()
        return r.json()["issue"]

    def issue_url(self, issue_id):
        return f"{self.base_url()}/issues/{issue_id}"

    def load_custom_fields(self, tracker_id):
        try:
            cfs = self.get("/custom_fields.json")["custom_fields"]
            return [c for c in cfs if c.get("customized_type") == "issue"], "admin"
        except requests.HTTPError:
            issues = self.get("/issues.json", project_id=self.project, tracker_id=tracker_id,
                              status_id="*", limit=1, sort="id:desc")["issues"]
            if not issues:
                return [], "none"
            return issues[0].get("custom_fields", []), "sample-issue"

    def _paged(self, path, key, **params):
        out, offset = [], 0
        while True:
            d = self.get(path, offset=offset, limit=100, **params)
            items = d.get(key) or []
            out += items
            offset += len(items)
            if not items or offset >= int(d.get("total_count") or 0):
                return out

    def load_meta(self):
        """
        Trackerها و فیلدهای سفارشی هر Tracker (اجباری بودن، مقدار پیش‌فرض، گزینه‌ها) از Redmine.
        /custom_fields.json فقط با کلید ادمین در دسترس است؛ نتیجه در تنظیمات ذخیره می‌شود تا
        ساخت تیکت با کلید کاربر عادی هم کار کند.
        """
        if not self.project:
            raise ConnectorError("شناسه‌ی پروژه‌ی Redmine در تنظیمات وارد نشده است.")
        user = self.get("/users/current.json")["user"]
        try:
            cfs = self.get("/custom_fields.json")["custom_fields"]
        except requests.HTTPError as e:
            if e.response is not None and e.response.status_code in (401, 403):
                raise ConnectorError(f"کاربر «{user.get('login')}» ادمین نیست؛ خواندن فیلدهای سفارشی (custom_fields.json) "
                                     "فقط با کلید API ادمین ممکن است. کلید ادمین را در همین پنجره وارد کنید.")
            raise
        trackers = self.get("/trackers.json")["trackers"]
        proj = self.get(f"/projects/{self.project}.json", include="trackers,issue_custom_fields")["project"]
        if proj.get("trackers") is not None:
            ids = {t["id"] for t in proj["trackers"]}
            trackers = [t for t in trackers if t["id"] in ids]
        pcf = proj.get("issue_custom_fields")
        pcf_ids = {c["id"] for c in pcf} if pcf is not None else None
        issue_cfs = [c for c in cfs if c.get("customized_type") == "issue" and (pcf_ids is None or c["id"] in pcf_ids)]
        users = versions = None
        if any(c.get("field_format") == "user" for c in issue_cfs):
            users = []
            for m in self._paged(f"/projects/{self.project}/memberships.json", "memberships"):
                who = m.get("user") or m.get("group")
                if who and all(str(who["id"]) != u["value"] for u in users):
                    users.append({"value": str(who["id"]), "label": who.get("name") or str(who["id"])})
        if any(c.get("field_format") == "version" for c in issue_cfs):
            versions = [{"value": str(v["id"]), "label": v.get("name") or str(v["id"])}
                        for v in self.get(f"/projects/{self.project}/versions.json").get("versions", [])
                        if v.get("status") != "closed"]

        def options(c):
            f = c.get("field_format")
            if f == "bool":
                return [{"value": "1", "label": "بله"}, {"value": "0", "label": "خیر"}]
            if f == "user":
                return users or []
            if f == "version":
                return versions or []
            pv = c.get("possible_values")
            if pv:
                return [{"value": str(p.get("value")), "label": str(p.get("label") or p.get("value"))} for p in pv]
            return None

        fields = {}
        for t in trackers:
            lst = []
            for c in issue_cfs:
                tr = c.get("trackers")
                if tr is not None and t["id"] not in {x["id"] for x in tr}:
                    continue
                lst.append({"id": c["id"], "name": c["name"], "format": c.get("field_format") or "string",
                            "required": bool(c.get("is_required")), "multiple": bool(c.get("multiple")),
                            "default": c.get("default_value") if c.get("default_value") is not None else "",
                            "options": options(c)})
            fields[str(t["id"])] = lst
        prios = self.get("/enumerations/issue_priorities.json")["issue_priorities"]
        try:
            cats = self.get(f"/projects/{self.project}/issue_categories.json")["issue_categories"]
        except requests.HTTPError:
            cats = []
        return {"fetched_at": time.time(), "by": user.get("login"), "project": self.project,
                "project_fields_known": pcf_ids is not None,
                "trackers": [{"id": t["id"], "name": t["name"]} for t in trackers],
                "priorities": [p["name"] for p in prios], "categories": [c["name"] for c in cats],
                "fields": fields}

    def discover(self):
        u = self.get("/users/current.json")["user"]
        trackers = self.get("/trackers.json")["trackers"]
        prios = self.get("/enumerations/issue_priorities.json")["issue_priorities"]
        cats = self.get(f"/projects/{self.project}/issue_categories.json")["issue_categories"]
        tracker = find_by_name(trackers, self.cfg.get("tracker", ""))
        cfs, src = self.load_custom_fields(tracker["id"] if tracker else None)
        fields = []
        for c in cfs:
            pv = [(p.get("label") if p.get("label") and p.get("label") != p.get("value") else p.get("value"))
                  for p in c.get("possible_values", []) or []]
            fields.append({"id": c["id"], "name": c["name"], "format": c.get("field_format", "?"), "options": pv})
        return {
            "user": {k: u.get(k) for k in ("id", "login", "admin")},
            "trackers": [{"id": t["id"], "name": t["name"]} for t in trackers],
            "priorities": [{"id": p["id"], "name": p["name"]} for p in prios],
            "categories": [{"id": c["id"], "name": c["name"]} for c in cats],
            "fields": fields, "fields_source": src,
        }

    def build_context(self):
        if not self.project:
            raise ConnectorError("شناسه‌ی پروژه‌ی Redmine در تنظیمات وارد نشده است.")
        trackers = self.get("/trackers.json")["trackers"]
        tracker = find_by_name(trackers, self.cfg.get("tracker", ""))
        if not tracker:
            where = f" (قالب «{self.cfg.get('_tpl_name')}»)" if self.cfg.get("_tpl_name") else ""
            raise ConnectorError(f"Tracker «{self.cfg.get('tracker')}» در Redmine پیدا نشد{where}")
        ctx = {"tracker_id": tracker["id"]}
        meta = self.cfg.get("meta") or {}
        if meta.get("project") == self.project and str(tracker["id"]) in (meta.get("fields") or {}):
            # فیلدهای خوانده‌شده با کلید ادمین (تنظیمات ← Redmine)
            ctx["meta_fields"] = meta["fields"][str(tracker["id"])]
        if self.cfg.get("priority"):
            p = find_by_name(self.get("/enumerations/issue_priorities.json")["issue_priorities"], self.cfg["priority"])
            ctx["priority_id"] = p["id"] if p else None
        if self.cfg.get("category"):
            c = find_by_name(self.get(f"/projects/{self.project}/issue_categories.json")["issue_categories"],
                             self.cfg["category"])
            ctx["category_id"] = c["id"] if c else None
        if self.cfg.get("assign_to_me"):
            ctx["me_id"] = self.get("/users/current.json")["user"]["id"]
        if "meta_fields" in ctx:
            ctx["cf_index"] = [{"id": f["id"], "name": f["name"], "possible_values": f.get("options") or []}
                               for f in ctx["meta_fields"]]
        else:
            ctx["cf_index"], _ = self.load_custom_fields(tracker["id"])
        return ctx


VAR_KEYS = ("src_ips", "dest_ips", "dest_ports", "detected_date")


def meta_custom_fields(cfg, ctx, data):
    """
    مقدار فیلدهای Tracker از «تنظیمات ← Redmine» (روش جدید، با اطلاعات فیلدها).
    مقدار تنظیم‌نشده = مقدار پیش‌فرض Redmine. فیلد اجباری خالی = خطا پیش از ساخت تیکت.
    """
    tv = (cfg.get("tracker_values") or {}).get(str(ctx["tracker_id"])) or {}
    custom, values, missing, gone = [], {}, [], []
    today = dt.date.today().isoformat()
    for f in ctx["meta_fields"]:
        ent = tv.get(str(f["id"]))
        if f.get("format") == "date":
            val = today   # فیلد تاریخ همیشه = روز ساخت تیکت (قابل تغییر نیست)
        elif ent is None:
            val = f.get("default")
        elif ent.get("src") in VAR_KEYS:
            val = data.get(ent["src"], "")
        else:
            val = ent.get("value")
        if f.get("multiple") and isinstance(val, str):
            val = [val] if val else []
        if f.get("options") and val not in (None, "", []) and (ent or {}).get("src", "static") == "static":
            allowed = {str(o.get("value")) for o in f["options"]}
            bad = [str(v) for v in (val if isinstance(val, list) else [val]) if str(v) not in allowed]
            if bad:      # گزینه در Redmine حذف یا عوض شده است
                gone.append(f"{f['name']}: {', '.join(bad)}")
                continue
        if val in (None, "", []):
            if f.get("required"):
                missing.append(f["name"])
            continue
        custom.append({"id": f["id"], "value": val})
        values[f["name"]] = ", ".join(val) if isinstance(val, list) else val
    where = f"قالب «{cfg.get('_tpl_name')}»" if cfg.get("_tpl_name") else "تنظیمات ← Redmine"
    if gone:
        raise ConnectorError(f"این مقدارها دیگر جزو گزینه‌های فیلد در Redmine نیستند ({where}؛ فیلدها را از Redmine "
                             "دوباره بخوانید و مقدار را انتخاب کنید): " + "؛ ".join(gone))
    if missing:
        raise ConnectorError(f"این فیلدهای اجباری Tracker مقدار ندارند ({where}): " + "، ".join(missing))
    return custom, values


def build_issue(cfg, ctx, data, variables):
    """معادل process_file اسکریپت (بدون ارسال)."""
    if "meta_fields" in ctx:
        custom, values = meta_custom_fields(cfg, ctx, data)
        return _issue(cfg, ctx, variables, custom), values
    static = [(str(n), str(v)) for n, v in cfg.get("static_fields") or [] if str(n).strip()]
    dynamic = [(str(n), str(k)) for n, k in cfg.get("dynamic_fields") or [] if str(n).strip()]
    overrides = {}
    for n, v in cfg.get("field_id_overrides") or []:
        try:
            overrides[str(n)] = int(v)
        except (TypeError, ValueError):
            pass
    names = [n for n, _ in static] + [n for n, _ in dynamic]
    ids, missing = resolve_field_ids(ctx["cf_index"], names, overrides)
    if missing:
        raise ConnectorError(f"ID این فیلدها پیدا نشد (در «شناسه‌ی دستی فیلدها» وارد کنید): {missing}")
    cf_by_id = {c["id"]: c for c in ctx["cf_index"]}
    values = dict(static)
    for n, k in dynamic:
        values[n] = data.get(k, "")
    today = dt.date.today().isoformat()
    dates = {n for n in values if (cf_by_id.get(ids[n]) or {}).get("field_format") == "date"}
    dates |= {n for n, k in dynamic if k == "detected_date"}
    for n in dates:
        values[n] = today   # فیلد تاریخ همیشه = روز ساخت تیکت
    custom = [{"id": ids[n], "value": v if n in dates else normalize_value(cf_by_id.get(ids[n]), n, v)} for n, v in values.items()]
    return _issue(cfg, ctx, variables, custom), values


def _issue(cfg, ctx, variables, custom):
    today = dt.date.today().isoformat()
    issue = {
        "project_id": cfg.get("project"),
        "tracker_id": ctx["tracker_id"],
        "subject": render_template(cfg.get("subject") or "گزارش آی پی مخرب", variables).strip()[:255] or "گزارش آی پی مخرب",
        "description": render_template(cfg.get("description_template") or "", variables),
        "start_date": today, "due_date": today, "custom_fields": custom,
    }
    for k, dst in (("priority_id", "priority_id"), ("category_id", "category_id"), ("me_id", "assigned_to_id")):
        if ctx.get(k):
            issue[dst] = ctx[k]
    return issue
