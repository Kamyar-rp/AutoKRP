"""
نقش‌ها و دسترسی‌ها. پیش‌فرض: هر متد API فقط برای ادمین است، مگر در فهرست‌های زیر باشد.

  admin     همه‌چیز
  operator  دیدن داده‌ها و گرفتن خروجی + اجرای ابزارهایی که ادمین برایش تیک زده (و تأیید همان‌ها)
  readonly  فقط دیدن داده‌ها؛ بدون اجرا، تأیید، خروجی و تنظیمات

بدون کاربران (حالت ساده یا تک‌رمزی) کاربر جاری همیشه ادمین است.
"""
TOOLS = ["splunk", "abuse", "fortigate", "redmine", "dns", "ssh", "scan", "intel", "asset"]
TOOL_TITLES = {"splunk": "Splunk", "abuse": "AbuseIPDB", "fortigate": "FortiGate", "redmine": "Redmine", "dns": "DNS", "ssh": "SSH", "scan": "اسکن شبکه",
               "intel": "بررسی تکمیلی", "asset": "مدیریت دارایی"}
# بخش‌هایی که ادمین می‌تواند برای همه خاموش کند (جدا از دسترسی ابزار اپراتورها)
FEATURES = ["monitor", "term", "offline", "nettools"]
FEATURE_TITLES = {"monitor": "مانیتورینگ", "term": "ترمینال و انتقال فایل", "offline": "ابزارهای آفلاین", "nettools": "ابزارهای شبکه"}
FEATURE_API = {
    "monitor": {"mon_list", "mon_report", "mon_icons", "mon_sound_get", "mon_sound_set", "mon_check_now", "mon_save",
                "mon_delete", "mon_toggle", "mon_icon_upload", "mon_snmp_live", "mon_snmp_series", "mon_snmp_watch",
                "snmp_cred_list", "snmp_cred_save", "snmp_cred_delete", "snmp_test", "snmp_walk",
                "mon_maint_list", "mon_maint_save", "mon_maint_delete", "mon_parent_group", "mon_noc",
                "mon_events_query", "mon_events_status", "mon_events_cfg_save", "mon_topo", "mon_topo_scan", "mon_topo_apply",
                "mon_pol_list", "mon_pol_save", "mon_pol_delete", "mon_capacity", "mon_ts_migrate",
                # 1.27.1: MIB سازنده‌ها ← نوع دستگاه خودکار
                "mib_list", "mib_upload", "mib_delete", "mib_compile", "mib_types"},
    "term": {"term_open", "term_break", "serial_ports", "term_snips_save", "term_read", "term_write", "term_resize", "term_close", "term_list", "term_stats", "conn_cancel",
             "xfer_open", "xfer_conns", "xfer_ls", "xfer_mkdir", "xfer_delete", "xfer_rename", "xfer_close", "xfer_put_begin",
             "xfer_put", "xfer_get", "xfer_local", "local_ls", "xfer_jobs", "xfer_cancel", "xfer_clear", "xfer_clear_one", "tftp_start",
             "tftp_status", "tftp_stop", "tftp_add_local", "tftp_remove", "tftp_received_get"},
}
FEATURE_API["nettools"] = {"net_oui", "net_oui_update", "net_rdap", "net_trace_start", "net_locate_targets", "net_locate_start",
                           "net_job", "net_job_cancel"}
FEATURE_API["offline"] = {"fgu_info", "fgu_check_folder", "fgu_start", "fgu_job", "fgu_cancel"}   # 1.22: خاموش بودن واقعاً اجرا نشود
ROLE_TITLES = {"admin": "ادمین", "operator": "اپراتور", "readonly": "فقط‌خواندنی"}
# 1.22: دسترسی به «بخش‌ها» برای هر اپراتور جدا (قبلاً مانیتورینگ برای همه‌ی اپراتورها باز بود و ترمینال همراه SSH)
USER_PERMS = ["monitor", "term"]
USER_PERM_TITLES = {"monitor": "مانیتورینگ: افزودن و ویرایش هدف‌ها و پروفایل‌های SNMP شخصی", "term": "ترمینال و انتقال فایل"}
USER_TOOLS = TOOLS + USER_PERMS
PERMS_V = 2


def user_tools(u):
    """ابزارها و بخش‌های اپراتور. کاربرهای ذخیره‌شده پیش از 1.22 (بدون perms_v) همان دسترسی قبلی را دارند:
    مانیتورینگ برای همه، ترمینال برای هر کسی که SSH داشت."""
    t = [x for x in (u.get("tools") or []) if x in USER_TOOLS]
    if int(u.get("perms_v") or 1) < PERMS_V:
        t += [x for x in ("monitor",) if x not in t]
        if "ssh" in t and "term" not in t:
            t.append("term")
    return t

# 1.31: جای کار هر بخش. «client» = فقط برنامه‌ی دسکتاپ (به سخت‌افزار همان کامپیوتر نیاز دارد، مثل کابل کنسول)؛
# در حالت سرور نه در رابط دیده می‌شود و نه API آن پاسخ می‌دهد. بخش تازه‌ی وابسته به کامپیوتر کاربر ← اینجا اضافه شود.
TOOL_MODES = {"serial": "client"}
MODE_API = {"serial": {"serial_ports"}}


def mode_block(name):
    """None = مجاز؛ وگرنه پیام خطا (متد مخصوص کلاینت در حالت سرور یا برعکس)."""
    from . import paths
    srv = paths.is_server()
    for tool, names in MODE_API.items():
        if name in names:
            m = TOOL_MODES.get(tool, "both")
            if m == "client" and srv:
                return "این بخش فقط در حالت کلاینت (برنامه‌ی دسکتاپ) در دسترس است."
            if m == "server" and not srv:
                return "این بخش فقط در حالت سرور در دسترس است."
    return None


def hidden_modes():
    """بخش‌هایی که در حالت فعلی برنامه نباید دیده شوند (برای رابط: data-mode)."""
    from . import paths
    srv = paths.is_server()
    return sorted(t for t, m in TOOL_MODES.items() if (m == "client" and srv) or (m == "server" and not srv))


# بدون ورود هم مجاز (صفحه‌ی قفل)
# 1.27.8: security_reset دیگر عمومی نیست (فقط ادمین، از داخل برنامه)؛ security_recover = کد بازیابی در صفحه‌ی قفل
PUBLIC = {"get_state", "security_status", "security_unlock", "security_check_password", "security_recover",
          "js_error", "ui_perf", "save_ui", "ui_touch", "get_settings"}
# همه‌ی نقش‌ها (دیدن)
READ = {"app_close_choice", "mon_list", "mon_state", "mon_report", "mon_snmp_live", "mon_snmp_series", "mon_icons", "mon_sound_get", "mon_check_now",
        "get_run", "list_ips", "repeat_ips", "ip_detail", "get_stats", "list_history", "history_view", "jobs_list", "get_about", "security_lock",
        "security_change_own", "whoami", "asset_list", "asset_get", "asset_changes", "asset_history",
        "mon_maint_list", "mon_noc", "mon_events_query", "mon_topo", "mon_pol_list"}
# اپراتور (به‌علاوه‌ی READ). چک ابزار داخل خود متدها یا در check_tools انجام می‌شود.
OPERATOR = {"net_oui", "net_rdap", "net_trace_start", "net_locate_targets", "net_locate_start", "net_job", "net_job_cancel",
            "start_run", "cancel_run", "decide", "job_run", "pick_csv", "ips_action",
            "export_ips", "export_run_files", "save_export", "save_export_many", "open_folder", "asset_save"}
# اپراتوری که دسترسی «مانیتورینگ» دارد (هدف‌ها و پروفایل‌های شخصی خودش؛ هدف مشترک فقط ادمین)
OPERATOR_MON = {"mon_save", "mon_delete", "mon_toggle", "mon_icon_upload", "mon_snmp_watch", "snmp_cred_list", "snmp_cred_save",
                "snmp_cred_delete", "snmp_test", "snmp_walk", "mon_maint_save", "mon_maint_delete", "mon_parent_group",
                # 1.27.1: فهرست نوع‌های دستگاه از MIB برای فرم هدف (بارگذاری MIB فقط ادمین)
                "mib_types"}
# اپراتوری که «ترمینال و انتقال فایل» دارد
OPERATOR_TERM = {"xfer_open", "xfer_conns", "xfer_ls", "xfer_mkdir", "xfer_delete", "xfer_rename", "xfer_close",
                 "xfer_put_begin", "xfer_put", "xfer_get", "xfer_local", "local_ls", "xfer_jobs", "xfer_cancel", "xfer_clear", "xfer_clear_one",
                 "tftp_start", "tftp_status", "tftp_stop", "tftp_add_local", "tftp_remove", "tftp_received_get",
                 "term_open", "term_read", "term_write", "term_resize", "term_close", "term_list", "term_stats",
                 "term_break", "serial_ports", "term_snips_save"}
# اپراتوری که ابزار SSH دارد
OPERATOR_SSH = {"ssh_save_device", "ssh_delete_devices", "ssh_list", "cred_list", "cred_save", "cred_delete", "ssh_preview", "ssh_start", "ssh_test", "ssh_job", "ssh_cancel", "ssh_jobs",
                "ssh_job_results", "ssh_output", "ssh_export_output", "text_chunk", "backup_overview",
                "backup_versions", "backup_view", "backup_diff", "backup_export", "backup_export_latest", "backup_now"}
# متدهای SSH که با خاموش بودن ابزار SSH برای همه بسته‌اند
SSH_RUN = {"ssh_start", "ssh_test", "ssh_preview", "backup_now", "fgu_start", "term_open", "xfer_open", "tftp_start"}
# درخواست‌های دوره‌ای رابط؛ «فعالیت کاربر» حساب نمی‌شوند (قفل خودکار)
POLL = {"net_job", "mon_state", "mon_snmp_live", "asset_scan_status", "term_read", "term_stats", "xfer_jobs", "get_state", "get_run", "ssh_job", "fgu_job", "js_error", "ui_perf", "security_status", "ui_touch", "whoami"}


def enabled_tools(settings):
    en = settings.get("tools_enabled", default={}) or {}
    return [t for t in TOOLS if en.get(t, True)]


def enabled_features(settings):
    en = settings.get("tools_enabled", default={}) or {}
    return [f for f in FEATURES if en.get(f, True)]


def allowed_tools(user, settings, lv=None):
    """ابزارها و بخش‌هایی که این کاربر اجازه‌ی «اجرا» دارد (روشن و مجاز)."""
    lv = lv or levels(user, settings)
    return [k for k in ACCESS_KEYS if lv.get(k) == "run"]


# ============================================================== 1.32: دسترسی با گروه‌ها (مثل پنل ادمین جنگو)
# سطح هر ابزار/بخش برای هر کاربر: none (پنهان) < view (دیدن) < run (اجرا و تغییر).
# سطح = بیشینه‌ی گروه‌های کاربر، سپس استثنای خود کاربر (جایگزین)، سپس سقف نقش (فقط‌خواندنی حداکثر view).
# ابزار خاموش در «ابزارهای فعال» برای همه none است. «ادمین اصلی» (superuser) همیشه run و همه‌ی دستگاه‌ها را دارد
# و فقط او دسترسی‌ها را تغییر می‌دهد. کاربر بدون access_v=3 (پیش از 1.32) همان دسترسی قبلی را دارد (legacy_levels).
ACCESS_V = 3
LEVELS = ("none", "view", "run")
RANK = {"none": 0, "view": 1, "run": 2}
ACCESS_KEYS = TOOLS + FEATURES                     # همه‌ی ابزارها و بخش‌ها
ACCESS_TITLES = {**TOOL_TITLES, **FEATURE_TITLES, "ssh": "ارتباط با دستگاه‌ها (SSH/Telnet)"}
NO_VIEW = {"term"}                                  # بخش‌هایی که «دیدن» ندارند (view = none)
_MON_VIEW = {"mon_list", "mon_report", "mon_snmp_live", "mon_snmp_series", "mon_icons", "mon_sound_get", "mon_check_now",
             "mon_maint_list", "mon_noc", "mon_events_query", "mon_topo", "mon_pol_list"}
_ASSET_VIEW = {"asset_list", "asset_get", "asset_changes", "asset_history", "asset_scan_status"}
_SSH_VIEW = {"ssh_list", "ssh_jobs", "ssh_job", "ssh_job_results", "ssh_output", "ssh_export_output", "text_chunk",
             "backup_overview", "backup_versions", "backup_view", "backup_diff", "backup_export", "backup_export_latest"}
# متد ← (ابزار، کمترین سطح لازم). متدی که اینجا نیست فقط با قاعده‌ی نقش بررسی می‌شود.
METHOD_ACCESS = {}
for _m in _MON_VIEW:
    METHOD_ACCESS[_m] = ("monitor", "view")
for _m in OPERATOR_MON | FEATURE_API["monitor"] - _MON_VIEW - {"mon_state"}:
    METHOD_ACCESS[_m] = ("monitor", "run")
for _m in _ASSET_VIEW:
    METHOD_ACCESS[_m] = ("asset", "view")
METHOD_ACCESS["asset_save"] = ("asset", "run")
for _m in _SSH_VIEW:
    METHOD_ACCESS[_m] = ("ssh", "view")
for _m in OPERATOR_SSH - _SSH_VIEW:
    METHOD_ACCESS[_m] = ("ssh", "run")
for _m in OPERATOR_TERM | (FEATURE_API["term"] - {"conn_cancel"}):
    METHOD_ACCESS[_m] = ("term", "run")
METHOD_ACCESS["net_oui"] = ("nettools", "view")
for _m in FEATURE_API["nettools"] - {"net_oui"}:
    METHOD_ACCESS[_m] = ("nettools", "run")
for _m in FEATURE_API["offline"]:
    METHOD_ACCESS[_m] = ("offline", "run")
# متدهای دیگر با همین پیشوندها (بیشترشان فقط ادمین) هم سطح «اجرا»ی همان ابزار را می‌خواهند،
# تا ادمینی که ادمین اصلی نیست و آن ابزار را ندارد از راه API هم به آن نرسد.
PREFIX_ACCESS = (("asset_", "asset"), ("ssh_", "ssh"), ("backup_", "ssh"), ("cred_", "ssh"), ("fgu_", "offline"),
                 ("mon_", "monitor"), ("snmp_", "monitor"), ("mib_", "monitor"), ("term_", "term"), ("xfer_", "term"),
                 ("tftp_", "term"), ("net_", "nettools"))
NO_ACCESS_CHECK = {"mon_state"}          # خودش برای سطح none پاسخ خالی می‌دهد (بنر هشدار سراسری)


def access_for(name):
    if name in NO_ACCESS_CHECK:
        return None
    if name in METHOD_ACCESS:
        return METHOD_ACCESS[name]
    for p, k in PREFIX_ACCESS:
        if name.startswith(p):
            return (k, "run")
    return None


# تاریخچه: نوع ردیف ← ابزار (ردیف ابزار پنهان برای کاربر نشان داده نمی‌شود)
HISTORY_KIND = {"ssh": "ssh", "backup": "ssh", "fgupdate": "offline", "terminal": "term", "transfer": "term",
                "monitor": "monitor", "asset": "asset", "nettools": "nettools", "dns": "dns", "scan": "scan",
                "intel": "intel", "splunk": "splunk", "abuse": "abuse", "fortigate": "fortigate", "ban": "fortigate",
                "redmine": "redmine", "ticket": "redmine"}


def _maxl(a, b):
    return a if RANK.get(a, 0) >= RANK.get(b, 0) else b


def legacy_levels(user):
    """سطح‌های معادل دسترسی پیش از 1.32 (نقش + تیک ابزارهای اپراتور)."""
    role = user.get("role")
    if role == "admin":
        return {k: "run" for k in ACCESS_KEYS}
    lv = {}
    ut = user_tools(user) if role == "operator" else []
    for k in ACCESS_KEYS:
        if k in ut:
            lv[k] = "run"
        elif k in ("ssh", "asset", "term"):
            lv[k] = "none"
        elif k == "nettools":
            lv[k] = "run" if role == "operator" else "none"
        else:
            lv[k] = "view"                         # نتیجه‌ها، مانیتورینگ و ابزارهای آفلاین را می‌دید
    return lv


def is_super(user, all_users):
    """ادمین اصلی: کاربر با پرچم superuser؛ اگر هیچ ادمین فعالی پرچم ندارد (پیش از 1.32)، هر ادمین."""
    if user is None:
        return True
    if user.get("role") != "admin" or user.get("disabled"):
        return False
    if user.get("superuser"):
        return True
    return not any(u.get("superuser") and u.get("role") == "admin" and not u.get("disabled") for u in all_users or [])


def groups_of(settings):
    g = settings.get("access", "groups", default=[]) or []
    return {str(x.get("id")): x for x in g if isinstance(x, dict) and x.get("id")}


def levels(user, settings, superuser=False):
    """{ابزار: none|view|run} برای این کاربر."""
    en = set(enabled_tools(settings)) | set(enabled_features(settings))
    if user is None or superuser:
        lv = {k: "run" for k in ACCESS_KEYS}
    elif int(user.get("access_v") or 0) < ACCESS_V:
        lv = legacy_levels(user)
    else:
        lv = {k: "none" for k in ACCESS_KEYS}
        gs = groups_of(settings)
        for gid in user.get("groups") or []:
            for k, v in ((gs.get(str(gid)) or {}).get("tools") or {}).items():
                if k in lv and v in RANK:
                    lv[k] = _maxl(lv[k], v)
        for k, v in (user.get("access") or {}).items():
            if k in lv and v in RANK:
                lv[k] = v
        if user.get("role") == "readonly":
            lv = {k: ("view" if v == "run" else v) for k, v in lv.items()}
    for k in NO_VIEW:
        if lv.get(k) == "view":
            lv[k] = "none"
    return {k: (v if k in en else "none") for k, v in lv.items()}


def device_scope(user, settings, superuser=False):
    """دستگاه‌های مشترکی که کاربر می‌بیند: {"all": bool, "grps": set, "ids": set}."""
    if user is None or superuser:
        return {"all": True, "grps": set(), "ids": set()}
    if int(user.get("access_v") or 0) < ACCESS_V:
        ok = user.get("role") == "admin" or user.get("shared_devices", True) is not False
        return {"all": ok, "grps": set(), "ids": set()}
    sc = {"all": False, "grps": set(), "ids": set()}
    specs = [(groups_of(settings).get(str(g)) or {}).get("devices") for g in user.get("groups") or []]
    if isinstance(user.get("devices"), dict):
        specs = [user["devices"]]                  # استثنای کاربر جای گروه‌ها را می‌گیرد
    for d in specs:
        if not isinstance(d, dict):
            continue
        sc["all"] = sc["all"] or bool(d.get("all"))
        sc["grps"] |= {str(x) for x in d.get("grps") or []}
        sc["ids"] |= {int(x) for x in d.get("ids") or [] if str(x).isdigit()}
    return sc


def device_ok(scope, dev):
    return bool(scope["all"] or (dev.get("grp") or "") in scope["grps"] or int(dev.get("id") or 0) in scope["ids"])


def clean_levels(d):
    return {k: v for k, v in (d or {}).items() if k in ACCESS_KEYS and v in RANK} if isinstance(d, dict) else {}


def clean_devices(d):
    if not isinstance(d, dict):
        return None
    return {"all": bool(d.get("all")), "grps": sorted({str(x).strip()[:60] for x in d.get("grps") or [] if str(x).strip()})[:500],
            "ids": sorted({int(x) for x in d.get("ids") or [] if str(x).isdigit()})[:5000]}


def can_call(user, name, settings, lv=None):
    """None = مجاز؛ وگرنه پیام خطا. lv = levels(...) همین کاربر (اگر نیامد از نقش و تیک‌ها حساب می‌شود)."""
    if name in PUBLIC:
        return None
    mb = mode_block(name)
    if mb:
        return mb
    for f, names in FEATURE_API.items():
        if name in names and f not in enabled_features(settings):
            return f"بخش «{FEATURE_TITLES[f]}» در تنظیمات خاموش است."
    if lv is None:
        lv = levels(user, settings)
    need = access_for(name)
    if need and RANK[lv.get(need[0], "none")] < RANK[need[1]]:
        return f"دسترسی به «{ACCESS_TITLES.get(need[0], need[0])}» ندارید." if lv.get(need[0], "none") == "none" \
            else f"فقط اجازه‌ی دیدن «{ACCESS_TITLES.get(need[0], need[0])}» را دارید."
    role = "admin" if user is None else user.get("role")
    if role == "admin":
        if name in SSH_RUN and "ssh" not in enabled_tools(settings):
            return "ابزار SSH در تنظیمات خاموش است."
        return None
    if name in READ:
        return None
    if role == "operator":
        if name in OPERATOR or name in OPERATOR_SSH or name in OPERATOR_TERM or name in OPERATOR_MON:
            return None
        if name == "conn_cancel":
            return None if (RANK[lv.get("ssh", "none")] == 2 or RANK[lv.get("term", "none")] == 2) else "دسترسی ندارید."
    if role == "readonly" and need and need[1] == "view":
        return None                                # فقط‌خواندنی با سطح «دیدن»
    return "دسترسی به این بخش ندارید."


def check_tools(user, settings, tools, lv=None):
    """ابزارهایی که اجرا می‌شوند باید فعال و برای کاربر مجاز (سطح اجرا) باشند."""
    en = enabled_tools(settings)
    ok = [k for k, v in (lv or levels(user, settings)).items() if v == "run"]
    for t in tools:
        if t not in en:
            return f"ابزار {TOOL_TITLES.get(t, t)} در تنظیمات خاموش است."
        if t not in ok:
            return f"دسترسی اجرای ابزار {TOOL_TITLES.get(t, t)} را ندارید."
    return None


def public_user(u):
    if not u:
        return {"username": "", "role": "admin", "single": True}
    return {"username": u["username"], "role": u["role"], "tools": user_tools(u) if u["role"] == "operator" else [],
            "disabled": bool(u.get("disabled")),
            "shared_devices": u.get("shared_devices", True) is not False,
            "groups": [str(g) for g in u.get("groups") or []], "access": clean_levels(u.get("access")),
            "devices": clean_devices(u.get("devices")), "superuser": bool(u.get("superuser")),
            "access_v": int(u.get("access_v") or 0),
            "last_login": u.get("last_login"), "created": u.get("created"), "source": u.get("source") or "local"}
