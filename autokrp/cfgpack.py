"""1.41: بسته‌ی پیکربندی کامل — خروجی و ورود همه‌ی تنظیمات کاری، بدون هیچ رمز، secret یا توکن.
محتوا: تنظیمات، پروفایل‌های اعتبارنامه (نام و نام کاربری، بدون رمز)، دستگاه‌ها، اسکریپت‌ها، هدف‌های مانیتورینگ، سیاست‌ها،
قالب‌ها، داشبوردهای NOC، نقشه‌ها (با پس‌زمینه)، پنجره‌های نگهداری، اتصال‌ها و درخواست‌های ابزار API، گروه‌های دسترسی،
کارهای خودکار و زمان‌بندی‌های SSH.
ورود: فقط افزودن؛ هیچ چیزی پاک یا بازنویسی نمی‌شود. موردی با همان نام (و همان نوع) از قبل باشد، رد می‌شود و ارجاع‌ها به
همان مورد موجود وصل می‌شوند (مثلاً دستگاه روی نقشه). هر مورد با «ref» (شناسه‌ی مبدأ) ارجاع داده می‌شود و در ورود به
شناسه‌ی تازه نگاشت می‌شود. زمان‌بندی‌ها خاموش وارد می‌شوند تا کاربر بازبینی کند. اعتبارسنجی همان متدهای عادی برنامه است."""
import json
import time

PKG_FORMAT = 1
MAX_BYTES = 50 * 1024 * 1024
CATS = ("cred_profiles", "mon_policies", "templates", "ssh_scripts", "ssh_devices", "mon_targets", "maint", "noc", "maps", "dashboards",
        "api_conns", "access_groups", "jobs", "ssh_schedules")
CAT_TITLES = {"cred_profiles": "پروفایل‌های اعتبارنامه", "mon_policies": "سیاست‌های پایش", "templates": "قالب‌های نمایش",
              "ssh_scripts": "اسکریپت‌ها", "ssh_devices": "دستگاه‌ها", "mon_targets": "هدف‌های مانیتورینگ",
              "maint": "پنجره‌های نگهداری", "noc": "داشبوردهای NOC", "maps": "نقشه‌ها", "dashboards": "داشبوردها", "api_conns": "اتصال‌های API",
              "access_groups": "گروه‌های دسترسی", "jobs": "کارهای خودکار", "ssh_schedules": "زمان‌بندی‌های SSH",
              "settings": "تنظیمات"}


class PackError(ValueError):
    pass


# 1.41.1: تنظیمات به تفکیک بخش (کاربر انتخاب می‌کند کدام بخش از فایل اعمال شود). conn = بخش اتصال (پیش‌فرض: فقط اگر این‌جا هنوز تنظیم نشده)
def _fg_keys():
    from .settings import FG_EXTRA
    return ["fortigate", *FG_EXTRA, "fg_scenarios"]


SET_SECTIONS = [("splunk", "Splunk (اتصال، کوئری‌ها و نگاشت ستون‌ها)", ["splunk"], True),
                ("abuseipdb", "AbuseIPDB", ["abuseipdb"], True),
                ("fortigate", "FortiGate (همه‌ی دستگاه‌ها و سناریوهای پایتون)", None, True),
                ("redmine", "Redmine (اتصال و قالب‌های تیکت)", ["redmine"], True),
                ("notify", "ایمیل و اعلان‌ها", ["notify"], False),
                ("tools", "DNS، اسکن شبکه، بررسی تکمیلی", ["dns", "scan", "intel"], False),
                ("monitor", "تنظیمات مانیتورینگ", ["monitor"], False),
                ("events", "دریافت Trap و Syslog (بدون community)", ["events"], False),
                ("ssh", "پشتیبان کانفیگ، ترمینال، انتقال فایل، به‌روزرسانی آفلاین", ["backup", "terminal", "transfer", "fgupdate"], False),
                ("assets", "دارایی‌ها", ["assets"], False),
                ("automation", "اجرای خودکار", ["automation"], False),
                ("general", "عمومی و ظاهر", ["test_mode", "poll_minutes", "max_age_hours", "theme", "branding", "health", "stats", "ui"], False),
                ("ad", "ورود با Active Directory (حالت سرور)", ["ad"], False)]


# 1.41.2: فهرست‌های نام‌دار داخل تنظیمات — مثل بقیه‌ی موارد فقط-افزودن (هم‌نام رد)؛ اعمال یک بخش تنظیمات آن‌ها را جایگزین نمی‌کند
LISTS = [("splunk_queries", "کوئری‌های ذخیره‌شده‌ی Splunk", ("splunk", "queries")),
         ("fg_tasks", "تسک‌های FortiGate (مثل بلاک IP یا ساخت Address)", ("fg_scenarios",)),
         ("redmine_templates", "قالب‌های تیکت Redmine", ("redmine", "templates"))]


def _list_get(st, path):
    cur = st
    for k in path:
        cur = cur.get(k) if isinstance(cur, dict) else None
    return [x for x in cur if isinstance(x, dict)] if isinstance(cur, list) else []


def _sec_keys(sid):
    for s, _, keys, _c in SET_SECTIONS:
        if s == sid:
            return keys if keys is not None else _fg_keys()
    return []


def settings_sections(A, st):
    """بخش‌های تنظیمات موجود در فایل + پیش‌فرض تیک (اتصالی که این‌جا هنوز آدرس ندارد)."""
    out = []
    for sid, title, _keys, conn in SET_SECTIONS:
        keys = [k for k in _sec_keys(sid) if k in st]
        if not keys or (sid == "ad" and not st.get("ad")):
            continue
        empty = conn and not str((A._settings.get(keys[0]) or {}).get("address") or "").strip() if conn else False
        out.append({"id": sid, "title": title, "default": bool(empty), "configured_here": bool(conn and not empty)})
    return out


def _j(v, d):
    try:
        return json.loads(v) if isinstance(v, str) else (v if v is not None else d)
    except ValueError:
        return d


# ============================================================== خروجی
def build(A):
    """A = نمونه‌ی Api (دسترسی‌ها را خود متد api بررسی کرده است: فقط ادمین اصلی)."""
    from . import __version__
    S, V = A._store, A._vault
    pkg = {"autokrp_package": PKG_FORMAT, "version": __version__, "created": time.time(), "by": A._uname() or ""}
    pkg["settings"] = A._export_settings_dict()
    pkg["cred_profiles"] = []
    for p in S.creds_list():
        pfx = f"cred.{p['id']}."
        pkg["cred_profiles"].append({"ref": p["id"], "name": p["name"], "kind": p["kind"], "owner": p.get("owner") or "", "notes": p.get("notes") or "",
                                     "username": V.get(pfx + "username", ""), "snmp": V.get(pfx + "snmp", "") if p["kind"] == "snmp" else ""})
    pkg["mon_policies"] = [{"ref": p["id"], "name": p["name"], "data": p["data"]} for p in S.pol_list()]
    pkg["templates"] = [{"ref": x["id"], "name": x["name"], "data": x["data"]} for x in S.lay_list("tpl")]
    pkg["ssh_scripts"] = [{"ref": s["id"], **{k: s.get(k) for k in ("name", "device_type", "mode", "body", "use_sudo", "save_config")}} for s in S.ssh_scripts()]
    pkg["ssh_devices"] = []
    for d in S.ssh_devices():
        x = {"ref": d["id"], **{k: d.get(k) for k in ("name", "host", "port", "device_type", "grp", "use_enable", "notes", "backup", "legacy", "owner", "protocol")},
             "cred": d.get("cred_id") or None}
        if not d.get("cred_id"):
            x["username"] = V.get(f"ssh.{d['id']}.username", "")
        pkg["ssh_devices"].append(x)
    pkg["mon_targets"] = []
    for t in S.mon_targets():
        x = {"ref": t["id"], **{k: t.get(k) for k in ("name", "host", "kind", "port", "url", "interval", "threshold", "timeout", "slow_ms", "icon", "grp",
                                                       "owner", "enabled", "notify", "notes", "cert_days")},
             "snmp": _j(t.get("snmp"), {}), "cred": t.get("cred_id") or None, "parent": t.get("parent_id") or None,
             "policy": t.get("policy_id") or None, "tpl": t.get("tpl") or ""}
        pkg["mon_targets"].append(x)
    pkg["maint"] = []
    for m in S.maint_list():
        sc = _j(m.get("scope"), {})
        pkg["maint"].append({"ref": m["id"], **{k: m.get(k) for k in ("name", "kind", "start", "end", "days", "t_from", "t_to", "enabled", "owner", "note")},
                             "scope": {"ids": sc.get("ids") or [], "groups": sc.get("groups") or []}})
    pkg["noc"] = [{"ref": x["id"], "name": x["name"], "data": x["data"]} for x in S.lay_list("noc")]
    bgs = {b["name"]: (b.get("data") or {}).get("img") or "" for b in S.lay_list("mapbg")}
    pkg["maps"] = [{"ref": x["id"], "name": x["name"], "data": x["data"], "bg": bgs.get(str(x["id"]), "")} for x in S.lay_list("map")]
    pkg["dashboards"] = [{"ref": x["id"], "name": x["name"], "data": x["data"]} for x in S.lay_list("dash") if not x.get("owner")]   # 1.42: فقط مشترک‌ها
    pkg["api_conns"] = []
    reqs = {}
    for r in S.api_reqs():
        reqs.setdefault(r["conn_id"], []).append({k: r.get(k) for k in ("name", "method", "path", "body", "body_type")}
                                                 | {"params": _j(r.get("params"), []), "headers": _j(r.get("headers"), [])})
    for c in S.api_conns():
        pkg["api_conns"].append({"ref": c["id"], **{k: c.get(k) for k in ("name", "base_url", "auth", "key_name", "verify", "timeout", "notes", "owner")},
                                 "headers": _j(c.get("headers"), []), "username": V.get(f"api.{c['id']}.username", "") if c.get("auth") == "basic" else "",
                                 "requests": reqs.get(c["id"], [])})
    pkg["access_groups"] = [{"ref": g.get("id"), "name": g.get("name"), "notes": g.get("notes") or "", "tools": g.get("tools") or {},
                             "devices": g.get("devices") or {"all": False, "grps": [], "ids": []}}
                            for g in (A._settings.get("access", "groups", default=[]) or []) if isinstance(g, dict)]
    pkg["jobs"] = [{k: v for k, v in j.items() if k not in ("last_at", "last_status", "last_message", "last_run")}
                   for j in (A._settings.get("jobs", default=[]) or [])]
    pkg["ssh_schedules"] = [{k: v for k, v in s.items() if k not in ("last_at", "last_status", "last_message", "enabled_at", "fgu")}
                            for s in (A._settings.get("ssh_schedules", default=[]) or [])]
    return pkg


# ============================================================== ورود
def load(raw):
    if not isinstance(raw, dict) or raw.get("autokrp_package") != PKG_FORMAT:
        raise PackError("این فایل بسته‌ی پیکربندی AutoKRP نیست.")
    for c in CATS:
        if not isinstance(raw.get(c, []), list):
            raise PackError(f"بخش «{CAT_TITLES[c]}» در فایل خراب است.")
    if raw.get("settings") is not None and not isinstance(raw.get("settings"), dict):
        raise PackError("بخش تنظیمات در فایل خراب است.")
    return raw


def _existing(A):
    """نام‌های موجود هر بخش (کلید رد شدن) ← شناسه‌ی موجود."""
    S = A._store
    low = lambda s: str(s or "").strip().lower()
    return {
        "cred_profiles": {(p["kind"], low(p["name"])): p["id"] for p in S.creds_list()},
        "mon_policies": {low(p["name"]): p["id"] for p in S.pol_list()},
        "templates": {low(x["name"]): x["id"] for x in S.lay_list("tpl")},
        "ssh_scripts": {low(s["name"]): s["id"] for s in S.ssh_scripts()},
        "ssh_devices": {low(d["name"]): d["id"] for d in S.ssh_devices()},
        "mon_targets": {low(t["name"]): t["id"] for t in S.mon_targets()},
        "maint": {low(m["name"]): m["id"] for m in S.maint_list()},
        "noc": {low(x["name"]): x["id"] for x in S.lay_list("noc")},
        "maps": {low(x["name"]): x["id"] for x in S.lay_list("map")},
        "dashboards": {low(x["name"]): x["id"] for x in S.lay_list("dash") if not x.get("owner")},
        "api_conns": {(low(c["name"]), c.get("owner") or ""): c["id"] for c in S.api_conns()},
        "access_groups": {low(g.get("name")): g.get("id") for g in (A._settings.get("access", "groups", default=[]) or []) if isinstance(g, dict)},
        "jobs": {low(j.get("name")): j.get("id") for j in (A._settings.get("jobs", default=[]) or [])},
        "ssh_schedules": {low(s.get("name")): s.get("id") for s in (A._settings.get("ssh_schedules", default=[]) or [])},
    }


def _key(cat, it):
    low = lambda s: str(s or "").strip().lower()
    if cat == "cred_profiles":
        return (it.get("kind"), low(it.get("name")))
    if cat == "api_conns":
        return (low(it.get("name")), it.get("owner") or "")
    return low(it.get("name"))


def preview(A, pkg):
    ex = _existing(A)
    out = []
    for c in CATS:
        items = pkg.get(c) or []
        same = [it.get("name") for it in items if isinstance(it, dict) and _key(c, it) in ex[c]]
        out.append({"cat": c, "title": CAT_TITLES[c], "total": len(items), "new": len(items) - len(same), "skip": len(same), "skip_names": same[:20]})
    st = pkg.get("settings") if isinstance(pkg.get("settings"), dict) else {}
    cur = A._settings.public()
    for lid, title, path in LISTS:
        items = _list_get(st, path)
        if not items:
            continue
        have = {str(x.get("name") or "").strip().lower() for x in _list_get(cur, path)}
        same = [x.get("name") for x in items if str(x.get("name") or "").strip().lower() in have]
        out.append({"cat": lid, "title": title, "total": len(items), "new": len(items) - len(same), "skip": len(same), "skip_names": same[:20]})
    return {"cats": out, "has_settings": bool(st), "settings": settings_sections(A, st), "version": pkg.get("version"),
            "created": pkg.get("created"), "by": pkg.get("by")}


def apply(A, pkg, cats=None, with_settings=False):
    """ورود فقط-افزودن. خروجی: شمارش هر بخش، خطاها، و فهرست مواردی که رمز/توکن لازم دارند.
    with_settings: True = همه‌ی بخش‌های تنظیمات، یا فهرست شناسه‌ی بخش‌ها (SET_SECTIONS)."""
    from . import netmap
    S, V = A._store, A._vault
    cats = set(cats or (list(CATS) + [x[0] for x in LISTS]))
    ex = _existing(A)
    M = {c: {} for c in CATS}           # ref ← شناسه‌ی تازه یا موجود
    res = {c: {"added": 0, "skipped": 0, "failed": 0} for c in CATS}
    added = {c: set() for c in CATS}    # refهایی که همین ورود ساخت (فقط این‌ها در دور دوم تغییر می‌کنند)
    errors, needs = [], []

    def ok(r):
        if not isinstance(r, dict) or not r.get("ok"):
            raise PackError((r or {}).get("error") or "نامعتبر")
        return r

    def run(cat, items, fn):
        for it in items:
            if not isinstance(it, dict):
                continue
            k = _key(cat, it)
            if k in ex[cat]:
                M[cat][it.get("ref")] = ex[cat][k]
                res[cat]["skipped"] += 1
                continue
            if cat not in cats:
                continue
            try:
                nid = fn(it)
                M[cat][it.get("ref")] = nid
                ex[cat][k] = nid
                added[cat].add(it.get("ref"))
                res[cat]["added"] += 1
            except Exception as e:  # noqa — یک مورد خراب بقیه را متوقف نمی‌کند
                res[cat]["failed"] += 1
                errors.append(f"{CAT_TITLES[cat]} «{str(it.get('name') or '')[:60]}»: {str(e)[:200]}")

    def owner_set(table, rid, owner):
        if owner:
            with S._lock:
                S.db.execute(f"UPDATE {table} SET owner=? WHERE id=?", (str(owner)[:80], int(rid)))  # nosec B608 — نام جدول از کد

    # پروفایل اعتبارنامه: مستقیم (متد عادی بدون رمز ساختن را نمی‌پذیرد)؛ رمز بعداً
    def f_cred(it):
        kind = it.get("kind")
        if kind not in A.CRED_KINDS and kind != "snmp":
            raise PackError("نوع نامعتبر")
        name = str(it.get("name") or "").strip()[:80]
        if not name:
            raise PackError("نام خالی")
        cid = S.cred_save({"name": name, "kind": kind, "owner": str(it.get("owner") or "")[:80], "notes": str(it.get("notes") or "")[:500]})
        ch = {f"cred.{cid}.username": str(it.get("username") or "")[:200]}
        if kind == "snmp" and it.get("snmp"):
            meta = _j(it.get("snmp"), {})
            if isinstance(meta, dict):
                ch[f"cred.{cid}.snmp"] = json.dumps({k: str(meta.get(k) or "")[:64] for k in ("v", "auth", "priv", "ctx")})
        V.set_many(ch)
        needs.append(f"{CAT_TITLES['cred_profiles']}: {name}")
        return cid
    run("cred_profiles", pkg.get("cred_profiles") or [], f_cred)
    run("mon_policies", pkg.get("mon_policies") or [], lambda it: ok(A.mon_pol_save({"name": it.get("name"), "data": it.get("data")}))["id"])
    run("templates", pkg.get("templates") or [], lambda it: int(ok(A.mon_tpl_save({"name": it.get("name"), "data": it.get("data")}))["id"]))
    run("ssh_scripts", pkg.get("ssh_scripts") or [], lambda it: ok(A.ssh_save_script({k: it.get(k) for k in ("name", "device_type", "mode", "body", "use_sudo", "save_config")}))["id"])

    def f_dev(it):
        cred = M["cred_profiles"].get(it.get("cred"))
        d = {k: it.get(k) for k in ("name", "host", "port", "device_type", "grp", "use_enable", "notes", "legacy", "protocol")}
        d["backup"] = it.get("backup")
        d["cred_id"] = cred
        d["username"] = it.get("username") or ""
        rid = ok(A.ssh_save_device(d, "", ""))["id"]
        owner_set("ssh_devices", rid, it.get("owner"))
        if not cred:
            needs.append(f"{CAT_TITLES['ssh_devices']}: {d.get('name') or d.get('host')}")
        return rid
    run("ssh_devices", pkg.get("ssh_devices") or [], f_dev)

    def tpl_ref(v):
        v = str(v or "")
        if v.isdigit():
            n = M["templates"].get(int(v))
            return str(n) if n else ""
        return v                                   # قالب داخلی (b:cisco، …) یا خالی

    def f_tgt(it):
        t = {k: it.get(k) for k in ("name", "host", "kind", "port", "url", "interval", "threshold", "timeout", "slow_ms", "icon", "grp",
                                    "enabled", "notify", "notes", "cert_days")}
        t["snmp"] = it.get("snmp") if isinstance(it.get("snmp"), dict) else {}
        t["cred_id"] = M["cred_profiles"].get(it.get("cred"))
        if t["kind"] == "snmp" and not t["cred_id"]:
            raise PackError("پروفایل SNMP آن در بسته نیست")
        t["policy_id"] = M["mon_policies"].get(it.get("policy"))
        t["tpl"] = tpl_ref(it.get("tpl"))
        if str(t.get("icon") or "").startswith("custom:"):
            t["icon"] = "other"                    # آیکون آپلودی جزو بسته نیست
        rid = ok(A.mon_save(t))["id"]
        owner_set("mon_targets", rid, it.get("owner"))
        return rid
    tg = pkg.get("mon_targets") or []
    run("mon_targets", tg, f_tgt)
    for it in tg:                                   # دور دوم: «وابسته به» (فقط هدف‌های تازه؛ حلقه را api.mon_save می‌گرفت، این‌جا هم بررسی)
        if not isinstance(it, dict) or not it.get("parent") or it.get("ref") not in added["mon_targets"]:
            continue
        a, p = M["mon_targets"].get(it.get("ref")), M["mon_targets"].get(it.get("parent"))
        if a and p and a != p:
            try:
                A._mon_parent_ok(p, (S.mon_target(a) or {}).get("owner") or "", a)
                S.mon_set_parent([a], p)
            except Exception as e:  # noqa
                errors.append(f"{CAT_TITLES['mon_targets']} «{it.get('name')}»: وابستگی وصل نشد ({str(e)[:120]})")

    def f_maint(it):
        sc = it.get("scope") or {}
        ids = [M["mon_targets"].get(i) for i in sc.get("ids") or []]
        w = {k: it.get(k) for k in ("name", "kind", "start", "end", "t_from", "t_to", "enabled", "note")}
        w["days"] = [int(x) for x in str(it.get("days") or "").split(",") if x.strip().isdigit()]
        w["scope"] = {"ids": [i for i in ids if i], "groups": sc.get("groups") or []}
        rid = ok(A.mon_maint_save(w))["id"]
        owner_set("mon_maint", rid, it.get("owner"))
        return rid
    run("maint", pkg.get("maint") or [], f_maint)

    def f_noc(it):
        d = dict(it.get("data") or {})
        sc = dict(d.get("scope") or {})
        sc["ids"] = [M["mon_targets"][i] for i in sc.get("ids") or [] if M["mon_targets"].get(i)]
        d["scope"] = sc
        d["big"] = [M["mon_targets"][i] for i in d.get("big") or [] if M["mon_targets"].get(i)]
        d["charts"] = [{**c, "tid": M["mon_targets"][c.get("tid")]} for c in d.get("charts") or [] if isinstance(c, dict) and M["mon_targets"].get(c.get("tid"))]
        return ok(A.mon_noc_save({"name": it.get("name"), "data": d}))["id"]
    run("noc", pkg.get("noc") or [], f_noc)

    maps = pkg.get("maps") or []
    new_maps = []

    def f_map(it):
        d = netmap.clean_map(it.get("data") or {})
        d["nodes"] = [{**n, "tid": M["mon_targets"].get(n.get("tid"))} if n["t"] == "dev" else n for n in d["nodes"]]
        gone = {n["id"] for n in d["nodes"] if n["t"] == "dev" and not n.get("tid")}
        d["nodes"] = [n for n in d["nodes"] if n["id"] not in gone]
        d["links"] = [lk for lk in d["links"] if lk["a"] not in gone and lk["b"] not in gone]
        body = {"name": it.get("name"), "grp": (it.get("data") or {}).get("grp") or "", "data": d}
        if it.get("bg"):
            body["bg"] = it["bg"]
        rid = ok(A.mon_map_save(body))["id"]
        new_maps.append((rid, it))
        return rid
    run("maps", maps, f_map)
    for rid, _it in new_maps:                       # دور دوم: زیرنقشه‌ها
        x = next((m for m in S.lay_list("map") if m["id"] == rid), None)
        if not x:
            continue
        d = x["data"]
        changed = False
        for n in d.get("nodes") or []:
            if n.get("t") == "map":
                n["map"] = M["maps"].get(n.get("map")) or 0
                changed = True
        if changed:
            S.lay_save(rid, "map", x["name"], d)

    def f_dash(it):
        from .dashboards import clean
        d = clean(it.get("data"))
        T = M["mon_targets"]
        for p in d["pages"]:
            for w in p["widgets"]:
                c = w["cfg"]
                if "tid" in c:
                    c["tid"] = T.get(c["tid"]) or 0
                if isinstance(c.get("tids"), list):
                    c["tids"] = [T[i] for i in c["tids"] if T.get(i)]
                if "map" in c:
                    c["map"] = M["maps"].get(c["map"]) or 0
        return ok(A.dash_save({"name": it.get("name"), "personal": False, "data": d}))["id"]
    run("dashboards", pkg.get("dashboards") or [], f_dash)

    def f_api(it):
        conn = {k: it.get(k) for k in ("name", "base_url", "auth", "key_name", "timeout", "notes")}
        conn["verify"] = bool(it.get("verify", 1))
        conn["headers"] = it.get("headers") or []
        conn["personal"] = False
        rid = ok(A.api_conn_save(conn, "", it.get("username") if conn.get("auth") == "basic" else None))["id"]
        owner_set("api_conns", rid, it.get("owner"))
        for q in it.get("requests") or []:
            if isinstance(q, dict):
                r = A.api_req_save({**q, "conn_id": rid})
                if not r.get("ok"):
                    errors.append(f"{CAT_TITLES['api_conns']} «{conn['name']}» / {q.get('name')}: {r.get('error')}")
        if (conn.get("auth") or "none") != "none":
            needs.append(f"{CAT_TITLES['api_conns']}: {conn['name']}")
        return rid
    run("api_conns", pkg.get("api_conns") or [], f_api)

    def f_group(it):
        dv = it.get("devices") or {}
        g = {"id": None, "name": it.get("name"), "notes": it.get("notes") or "", "tools": it.get("tools") or {},
             "devices": {"all": bool(dv.get("all")), "grps": dv.get("grps") or [],
                         "ids": [M["ssh_devices"][i] for i in dv.get("ids") or [] if M["ssh_devices"].get(i)]}, "members": []}
        r = ok(A.access_group_save(g))
        return r.get("id") or next((x.get("id") for x in (A._settings.get("access", "groups", default=[]) or []) if x.get("name") == g["name"]), None)
    run("access_groups", pkg.get("access_groups") or [], f_group)

    def f_job(it):
        items = []
        for x in it.get("items") or []:
            x = json.loads(json.dumps(x))
            o = x.get("opts") or {}
            if ((o.get("input") or {}).get("path")):
                raise PackError("ورودی فایل CSV دارد که جزو بسته نیست؛ دستی بسازید")
            if x.get("tool") == "ssh":
                o["device_ids"] = [M["ssh_devices"][i] for i in o.get("device_ids") or [] if M["ssh_devices"].get(i)]
                if o.get("script_id"):
                    o["script_id"] = M["ssh_scripts"].get(o["script_id"])
            items.append(x)
        j = {**{k: v for k, v in it.items() if k not in ("id", "items")}, "items": items, "enabled": False}
        return ok(A.job_save(j))["job"]["id"]
    run("jobs", pkg.get("jobs") or [], f_job)

    def f_sch(it):
        s = {k: v for k, v in it.items() if k not in ("id",)}
        s["device_ids"] = [M["ssh_devices"][i] for i in it.get("device_ids") or [] if M["ssh_devices"].get(i)]
        if it.get("script_id"):
            s["script_id"] = M["ssh_scripts"].get(it["script_id"])
        s["enabled"] = False
        r = ok(A.ssh_sched_save(s))
        return next((x["id"] for x in r["schedules"] if x.get("name") == s.get("name")), None)
    run("ssh_schedules", pkg.get("ssh_schedules") or [], f_sch)

    src = pkg.get("settings") if isinstance(pkg.get("settings"), dict) else {}
    lres = {}
    for lid, title, path in LISTS:                  # فهرست‌های نام‌دار تنظیمات: فقط افزودن
        items = _list_get(src, path)
        if not items:
            continue
        cur = _list_get(A._settings.public(), path)
        have = {str(x.get("name") or "").strip().lower() for x in cur}
        ids = {str(x.get("id")) for x in cur if x.get("id") is not None}
        new = [dict(x) for x in items if str(x.get("name") or "").strip().lower() not in have]
        lres[lid] = {"added": 0, "skipped": len(items) - len(new), "failed": 0}
        if lid not in cats or not new:
            continue
        import uuid
        for x in new:
            if "id" in x and (x.get("id") is None or str(x["id"]) in ids):
                x["id"] = uuid.uuid4().hex[:10]
            ids.add(str(x.get("id")))
        merged = cur + new
        patch = {path[0]: merged} if len(path) == 1 else {path[0]: {path[1]: merged}}
        try:
            A._import_settings_dict(patch)
            lres[lid]["added"] = len(new)
        except Exception as e:  # noqa
            lres[lid]["failed"] = len(new)
            errors.append(f"{title}: {str(e)[:200]}")
    res.update(lres)
    st = None
    if with_settings and src:
        secs = [s for s, *_ in SET_SECTIONS] if with_settings is True else [s for s in with_settings if any(s == x for x, *_ in SET_SECTIONS)]
        done, st = [], {}
        for sid in secs:
            keys = [k for k in _sec_keys(sid) if k in src and k != "fg_scenarios"]
            if not keys:
                continue
            try:
                if sid == "events":
                    ev = dict(src["events"]) if isinstance(src.get("events"), dict) else {}
                    ev["communities"] = (A._settings.get("events", default={}) or {}).get("communities") or []   # community جزو بسته نیست
                    ok(A.mon_events_cfg_save(ev))
                elif sid == "ad":
                    ok(A.server_ad_save(src["ad"]))
                else:
                    part = {k: src[k] for k in keys}
                    for _l, _t, path in LISTS:      # فهرست‌های نام‌دار جدا (فقط افزودن)، نه جایگزینی
                        if len(path) == 2 and isinstance(part.get(path[0]), dict):
                            part[path[0]] = {k: v for k, v in part[path[0]].items() if k != path[1]}
                    A._import_settings_dict(part)
                done.append(sid)
            except Exception as e:  # noqa — یک بخش خراب بقیه را متوقف نمی‌کند
                st[sid] = str(e)[:200]
                errors.append(f"{CAT_TITLES['settings']} / {dict((x, t) for x, t, *_ in SET_SECTIONS)[sid]}: {str(e)[:200]}")
        if any(s in done for s in ("splunk", "abuseipdb", "fortigate", "redmine")):
            needs.append("تنظیمات: توکن یا رمز اتصال‌های Splunk، AbuseIPDB، FortiGate و Redmine (و تأیید دوباره‌ی گواهی در اولین اتصال)")
        st = {"applied": done, "failed": st}
    return {"result": res, "errors": errors[:200], "needs": needs[:500], "settings": st}
