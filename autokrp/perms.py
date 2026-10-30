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
        "mon_maint_list", "mon_noc", "mon_events_query", "mon_topo"}
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


def allowed_tools(user, settings):
    """ابزارهای اجرایی + بخش‌ها (monitor، term) که برای این کاربر روشن و مجاز است."""
    en = enabled_tools(settings) + [p for p in USER_PERMS if p in enabled_features(settings)]
    if user is None or user.get("role") == "admin":
        return en
    if user.get("role") == "operator":
        ut = user_tools(user)
        return [t for t in en if t in ut]
    return []


def can_call(user, name, settings):
    """None = مجاز؛ وگرنه پیام خطا."""
    if name in PUBLIC:
        return None
    mb = mode_block(name)
    if mb:
        return mb
    for f, names in FEATURE_API.items():
        if name in names and f not in enabled_features(settings):
            return f"بخش «{FEATURE_TITLES[f]}» در تنظیمات خاموش است."
    role = "admin" if user is None else user.get("role")
    if role == "admin":
        if name in SSH_RUN and "ssh" not in enabled_tools(settings):
            return "ابزار SSH در تنظیمات خاموش است."
        return None
    if name in READ:
        return None
    if role == "operator":
        if name in OPERATOR:
            return None
        ok = allowed_tools(user, settings)
        if name in OPERATOR_SSH:
            return None if "ssh" in ok else "دسترسی به ابزار SSH ندارید."
        if name in OPERATOR_TERM:
            return None if "term" in ok else "دسترسی به ترمینال و انتقال فایل ندارید."
        if name in OPERATOR_MON:
            return None if "monitor" in ok else "دسترسی به تغییر مانیتورینگ ندارید."
        if name == "conn_cancel":
            return None if ("ssh" in ok or "term" in ok) else "دسترسی ندارید."
    return "دسترسی به این بخش ندارید."


def check_tools(user, settings, tools):
    """ابزارهایی که اجرا می‌شوند باید فعال و برای کاربر مجاز باشند."""
    en, ok = enabled_tools(settings), allowed_tools(user, settings)
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
            "last_login": u.get("last_login"), "created": u.get("created"), "source": u.get("source") or "local"}
