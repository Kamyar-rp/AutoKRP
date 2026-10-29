"""
تسک‌های پایتونی FortiGate (1.29) — جایگزین سناریوهای گام‌به‌گام 1.28.

هر تسک = کد پایتون با تابع plan(fg, rows, ctx):
  rows  ردیف‌های جدول ورودی (dict با نام ستون‌ها؛ از ابزار قبلی، لیست یا CSV که خط اولش نام ستون‌هاست)
  fg    fg.get(path) / fg.results(path) خواندن واقعی از دستگاه انتخاب‌شده (از راه برنامه؛ توکن دیده نمی‌شود)
        fg.post(path, body, note, row) / fg.put(...) / fg.delete(path, note, row) فقط «پیشنهاد» کار
  ctx   {device, vdom, run, columns, test, ignore_networks}
مدل دومرحله‌ای: plan در فرایند جدا (fgtask_child) با سقف زمان اجرا می‌شود و فهرست کارها را برمی‌گرداند؛ برنامه
آن را نشان می‌دهد و فقط کارهای تأییدشده را خودش می‌فرستد (حالت تست: هیچ). مسیرها فقط زیر /api/v2/ همان دستگاه.

هشدار: کد پایتون قابل محصورسازی کامل نیست؛ فقط ادمین تسک را می‌سازد/ویرایش می‌کند و هر تغییر در تاریخچه ثبت می‌شود.
"""
import ast
import difflib
import hashlib
import json
import os
import secrets
import socket
import subprocess  # nosec B404 — اجرای همین برنامه در حالت --fgtask
import sys
import time
import uuid

MAX_CODE = 200_000
MAX_TASKS = 30
MAX_ROWS = 50_000
METHODS = ("POST", "PUT", "DELETE")


class TaskError(ValueError):
    pass


def sha(code):
    return hashlib.sha256(str(code or "").encode("utf-8")).hexdigest()


def check_code(code, name="تسک"):
    code = str(code or "")
    if len(code) > MAX_CODE:
        raise TaskError(f"«{name}»: کد بیش از ۲۰۰ هزار نویسه است.")
    try:
        tree = ast.parse(code, filename="<task>")
    except SyntaxError as e:
        raise TaskError(f"«{name}»: خطای نحوی در خط {e.lineno}: {e.msg}")
    fn = next((n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "plan"), None)
    if not fn or len(fn.args.args) != 3:
        raise TaskError(f"«{name}»: کد باید تابع plan(fg, rows, ctx) داشته باشد.")
    return code


def validate(t: dict) -> dict:
    if not isinstance(t, dict):
        raise TaskError("تسک نامعتبر است.")
    if "code" not in t and t.get("steps"):
        t = from_steps(t)
    name = str(t.get("name") or "").strip()[:80]
    if not name:
        raise TaskError("نام تسک خالی است.")
    out = {"id": str(t.get("id") or "").strip()[:40], "name": name, "note": str(t.get("note") or "").strip()[:500],
           "code": check_code(t.get("code"), name),
           "on_error": "continue" if t.get("on_error") == "continue" else "stop"}
    try:
        out["timeout"] = max(10, min(600, int(t.get("timeout") or 120)))
    except (TypeError, ValueError):
        out["timeout"] = 120
    if not out["id"] or not all(c.isalnum() or c == "_" for c in out["id"]):
        out["id"] = uuid.uuid4().hex[:10]
    return out


def validate_all(lst) -> list:
    if not isinstance(lst, list):
        raise TaskError("فهرست تسک‌ها نامعتبر است.")
    if len(lst) > MAX_TASKS:
        raise TaskError(f"حداکثر {MAX_TASKS} تسک.")
    out, ids, names = [], set(), set()
    for t in lst:
        c = validate(t)
        while c["id"] in ids:
            c["id"] = uuid.uuid4().hex[:10]
        if c["name"].lower() in names:
            raise TaskError(f"نام تسک «{c['name']}» تکراری است.")
        ids.add(c["id"])
        names.add(c["name"].lower())
        out.append(c)
    return out


def changes(old, new) -> list:
    """متن تاریخچه برای تسک‌های ساخته/حذف/ویرایش‌شده (diff کد)."""
    o = {t.get("id"): t for t in old or []}
    n = {t.get("id"): t for t in new or []}
    out = []
    for i, t in n.items():
        if i not in o:
            out.append(f"تسک «{t['name']}» ساخته شد (sha {sha(t['code'])[:12]})")
        elif sha(o[i].get("code")) != sha(t["code"]) or o[i].get("name") != t["name"]:
            d = "\n".join(difflib.unified_diff(str(o[i].get("code") or "").splitlines(), t["code"].splitlines(),
                                               "قبل", "بعد", lineterm="", n=1))
            out.append(f"تسک «{t['name']}» ویرایش شد (sha {sha(o[i].get('code'))[:12]} → {sha(t['code'])[:12]})\n{d[:3000]}")
    for i, t in o.items():
        if i not in n:
            out.append(f"تسک «{t.get('name')}» حذف شد")
    return out


# ---------------------------------------------------------------- اجرای plan در فرایند جدا
def _child_cmd(port):
    if getattr(sys, "frozen", False):
        return [sys.executable, "--fgtask", str(port)]
    return [sys.executable, "-I", os.path.join(os.path.dirname(os.path.abspath(__file__)), "fgtask_child.py"), str(port)]


def _child_env(token):
    keep = ("SYSTEMROOT", "SystemRoot", "WINDIR", "TEMP", "TMP", "PATH", "LANG", "LC_ALL", "PYTHONIOENCODING")
    env = {k: v for k, v in os.environ.items() if k in keep}
    env["AKRP_TASK_TOKEN"] = token
    env["PYTHONIOENCODING"] = "utf-8"
    return env


def plan(cli, task, rows, ctx, cancel=None, log=None, timeout=None):
    """کد تسک را در فرایند جدا اجرا می‌کند. خروجی: (actions, logs)"""
    log = log or (lambda m: None)
    timeout = float(timeout or task.get("timeout") or 120)
    token = secrets.token_hex(16)
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    srv.settimeout(0.5)
    port = srv.getsockname()[1]
    kw = {"creationflags": 0x08000000} if os.name == "nt" else {}      # CREATE_NO_WINDOW
    p = subprocess.Popen(_child_cmd(port), env=_child_env(token), stdin=subprocess.DEVNULL,  # nosec B603 — همین برنامه، ورودی ثابت
                         stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, **kw)
    t0 = time.time()
    conn = None
    logs = []
    try:
        while conn is None:
            if cancel is not None and cancel.is_set():
                raise TaskError("متوقف شد")
            if time.time() - t0 > min(timeout, 60):
                raise TaskError("فرایند تسک شروع نشد.")
            if p.poll() is not None:
                err = (p.stderr.read() or b"").decode("utf-8", "replace")[-1500:]
                raise TaskError("فرایند تسک بسته شد: " + err)
            try:
                c, _ = srv.accept()
            except socket.timeout:
                continue
            c.settimeout(1.0)
            f = c.makefile("rwb")
            try:
                hello = json.loads(f.readline() or b"{}")
            except (ValueError, OSError):
                hello = {}
            if not secrets.compare_digest(str(hello.get("token") or ""), token):
                c.close()
                continue
            conn = (c, f)
        c, f = conn
        c.settimeout(None)
        why = {}
        finished = []

        def watchdog():       # سقف زمان و «توقف»: فرایند کشته و سوکت بسته می‌شود
            import threading as _t  # noqa
            while not finished:
                if cancel is not None and cancel.is_set():
                    why["m"] = "متوقف شد"
                elif time.time() - t0 > timeout:
                    why["m"] = f"تسک بیش از {int(timeout)} ثانیه طول کشید و متوقف شد."
                if why:
                    try:
                        p.kill()
                    except OSError:
                        pass
                    try:
                        c.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
                    return
                time.sleep(0.2)
        import threading
        threading.Thread(target=watchdog, daemon=True, name="fgtask-watchdog").start()

        def send(o):
            f.write(json.dumps(o, ensure_ascii=False, default=str).encode("utf-8") + b"\n")
            f.flush()
        try:
            send({"t": "start", "code": task["code"], "rows": rows, "ctx": ctx})
            while True:
                try:
                    line = f.readline()
                except OSError:
                    line = b""
                if not line or why:
                    if why:
                        raise TaskError(why["m"])
                    err = ""
                    try:
                        p.wait(timeout=2)
                        err = (p.stderr.read() or b"").decode("utf-8", "replace")[-1500:]
                    except subprocess.TimeoutExpired:
                        pass
                    raise TaskError("فرایند تسک بدون نتیجه بسته شد. " + err)
                msg = json.loads(line.decode("utf-8"))
                k = msg.get("t")
                if k == "log":
                    logs.append(str(msg.get("msg", "")))
                    log(str(msg.get("msg", "")))
                elif k == "get":
                    try:
                        st, data = cli.api_request("GET", msg["path"], None, params=msg.get("params") or None)
                        ok = st < 400
                        send({"t": "res", "ok": ok, "status": st, "data": data if ok else None,
                              "error": "" if ok else str(data)[:300]})
                    except Exception as e:     # خطای شبکه یا مسیر نامعتبر ← به کد تسک
                        from .connectors import friendly_error
                        send({"t": "res", "ok": False, "status": 0, "error": friendly_error(e)})
                elif k == "done":
                    return clean_actions(msg.get("actions") or []), logs
                elif k == "error":
                    raise TaskError(f"خطا در کد تسک: {msg.get('msg')}\n{msg.get('tb', '')}".strip())
        finally:
            finished.append(1)
    finally:
        try:
            srv.close()
        except OSError:
            pass
        if conn:
            try:
                conn[0].close()
            except OSError:
                pass
        try:
            p.wait(timeout=2)
        except subprocess.TimeoutExpired:
            p.kill()
            try:
                p.wait(timeout=3)
            except subprocess.TimeoutExpired:
                pass
        for s in (p.stderr,):
            try:
                s.close()
            except Exception:  # nosec B110
                pass


def clean_actions(acts):
    out = []
    for i, a in enumerate(acts):
        m = str(a.get("method") or "").upper()
        path = str(a.get("path") or "")
        if m not in METHODS or not path.startswith("/api/v2/") or ".." in path or "?" in path or "#" in path:
            raise TaskError(f"کار {i + 1} نامعتبر است: {m} {path}")
        out.append({"i": i, "method": m, "path": path, "body": a.get("body"), "note": str(a.get("note") or "")[:300],
                    "row": a.get("row") if isinstance(a.get("row"), dict) else {}})
    return out


def apply(cli, actions, on_error="stop", cancel=None, on_result=None):
    """ارسال کارهای تأییدشده به ترتیب. خروجی: نتیجه‌ی هر کار (done|failed|skipped)."""
    stop = False
    out = []
    for a in actions:
        if stop:
            r = {**a, "result": "skipped", "detail": "به‌خاطر خطای کار قبلی ارسال نشد"}
        else:
            if cancel is not None and cancel.is_set():
                from .connectors import Cancelled
                raise Cancelled()
            try:
                st, data = cli.api_request(a["method"], a["path"], a.get("body"))
                ok, detail = cli.api_ok(st, data)
            except Exception as e:
                from .connectors import Cancelled, friendly_error
                if isinstance(e, Cancelled):
                    raise
                ok, detail = False, friendly_error(e)
            r = {**a, "result": "done" if ok else "failed", "detail": detail}
            if not ok and on_error != "continue":
                stop = True
        out.append(r)
        if on_result:
            on_result(r)
    return out


# ---------------------------------------------------------------- تبدیل سناریوهای 1.28 به کد
def from_steps(sc: dict) -> dict:
    tpl = str(sc.get("name_tpl") or "AKRP_{ip}")
    cm = str(sc.get("comment_tpl") or "")
    lines = ["# تبدیل خودکار از تسک گام‌به‌گام نسخه‌ی 1.28", "def plan(fg, rows, ctx):", "    for r in rows:",
             "        ip = r.get('ip') or r.get('IP') or r.get('src') or next(iter(r.values()), '')",
             "        if not ip:", "            continue",
             f"        name = {tpl!r}.replace('{{ip}}', ip).replace('{{ip_}}', ip.replace('.', '_'))[:79]"]
    for st in sc.get("steps") or []:
        t = st.get("type")
        if t == "address":
            lines += ["        if not fg.get('/api/v2/cmdb/firewall/address/' + q(name)):",
                      f"            fg.post('/api/v2/cmdb/firewall/address', {{'name': name, 'type': 'ipmask', 'subnet': ip + ' 255.255.255.255', 'comment': 'AutoKRP: ' + {cm!r}}}, 'ساخت Address', r)"]
        elif t in ("group_add", "group_remove"):
            g = str(st.get("group") or "")
            lines += [f"        grp = fg.results('/api/v2/cmdb/firewall/addrgrp/' + q({g!r}))",
                      "        members = {m.get('name') for m in (grp[0].get('member') or [])} if grp else set()"]
            if t == "group_add":
                lines += ["        if name not in members:",
                          f"            fg.post('/api/v2/cmdb/firewall/addrgrp/' + q({g!r}) + '/member', {{'name': name}}, 'افزودن به گروه', r)"]
            else:
                lines += ["        if name in members:",
                          f"            fg.delete('/api/v2/cmdb/firewall/addrgrp/' + q({g!r}) + '/member/' + q(name), 'برداشتن از گروه', r)"]
        elif t == "ban":
            lines += [f"        fg.post('/api/v2/monitor/user/banned/add_users', {{'ip_addresses': [ip], 'expiry': {int(st.get('expiry') or 0)}}}, 'Banned', r)"]
        elif t == "unban":
            lines += ["        fg.post('/api/v2/monitor/user/banned/clear_users', {'ip_addresses': [ip]}, 'Unban', r)"]
        elif t == "rest":
            lines += [f"        # گام REST دستی نسخه‌ی قبل: {st.get('method')} {st.get('path')} — دوباره بنویسید"]
    return {"id": sc.get("id"), "name": sc.get("name") or "تسک", "note": sc.get("note") or "", "code": "\n".join(lines) + "\n",
            "on_error": "stop", "timeout": 120}


# ---------------------------------------------------------------- قالب‌های آماده
TEMPLATES = [
    {"key": "ban", "name": "Ban IP (code)", "note": "Like the default task but simpler: every IP not yet in Banned is added.",
     "code": '''"""
Ban IP — every IP of the input rows (column ip, IP or src) that is not in the Banned list is added to it.
plan() only proposes actions; AutoKRP sends them after your approval
(or, in an automated job, when "FortiGate without approval" is checked).
"""
import ipaddress

EXPIRY = 0          # seconds; 0 = never expires


def plan(fg, rows, ctx):
    banned = {b.get("ip_address") for b in fg.results("/api/v2/monitor/user/banned")}
    skip = [ipaddress.ip_network(n.split("#")[0].strip(), strict=False)
            for n in ctx.get("ignore_networks", []) if n.split("#")[0].strip()]
    for r in rows:
        ip = (r.get("ip") or r.get("IP") or r.get("src") or "").strip()
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            log("invalid:", ip)
            continue
        if any(a.version == n.version and a in n for n in skip) or ip in banned:
            continue
        fg.post("/api/v2/monitor/user/banned/add_users", {"ip_addresses": [ip], "expiry": EXPIRY},
                note="Ban " + ip, row=r)
'''},
    {"key": "group", "name": "Address + Group", "note": "Columns: src (IP or CIDR), name (optional), group",
     "code": '''"""
For each row, create an Address Object (if missing) and add it to the row's Address Group.
Columns: src (IP or CIDR), name (optional; default AKRP_<src>), group (empty = GROUP below).
"""
import ipaddress

GROUP = "Blocked-IPs"


def plan(fg, rows, ctx):
    groups = {}
    for r in rows:
        src = (r.get("src") or r.get("ip") or r.get("IP") or "").strip()
        try:
            net = ipaddress.ip_network(src, strict=False)
        except ValueError:
            log("invalid:", src)
            continue
        if net.version != 4:
            log("IPv6 is not handled by this template:", src)
            continue
        name = (r.get("name") or "AKRP_" + src.replace("/", "_"))[:79]
        group = (r.get("group") or GROUP).strip()
        if not fg.get("/api/v2/cmdb/firewall/address/" + q(name)):
            fg.post("/api/v2/cmdb/firewall/address",
                    {"name": name, "type": "ipmask", "subnet": f"{net.network_address} {net.netmask}",
                     "comment": "AutoKRP: " + ctx.get("run", "")},
                    note="Create address " + name, row=r)
        if group not in groups:
            g = fg.results("/api/v2/cmdb/firewall/addrgrp/" + q(group))
            if not g:
                raise TaskError(f"Address Group '{group}' does not exist on the device")
            groups[group] = {m.get("name") for m in g[0].get("member") or []}
        if name not in groups[group]:
            fg.post("/api/v2/cmdb/firewall/addrgrp/" + q(group) + "/member", {"name": name},
                    note=f"Add {name} to {group}", row=r)
            groups[group].add(name)
'''},
    {"key": "policy", "name": "Policies from a table", "note": "Columns: name, srcintf, dstintf, srcaddr, dstaddr, service, action",
     "code": '''"""
Create one Firewall Policy per row (unless a policy with the same name exists).
Columns: name, srcintf, dstintf, srcaddr, dstaddr, service (several values separated by ;),
action (accept/deny; default deny).
New policies are added at the end of the list; moving them is up to you. Run it in test mode first.
"""


def _names(v):
    return [{"name": x.strip()} for x in str(v or "").split(";") if x.strip()]


def plan(fg, rows, ctx):
    have = {p.get("name") for p in fg.results("/api/v2/cmdb/firewall/policy", {"format": "name"})}
    for r in rows:
        name = (r.get("name") or "").strip()[:35]
        if not name or name in have:
            continue
        body = {"name": name, "srcintf": _names(r.get("srcintf")), "dstintf": _names(r.get("dstintf")),
                "srcaddr": _names(r.get("srcaddr")), "dstaddr": _names(r.get("dstaddr")),
                "service": _names(r.get("service") or "ALL"), "schedule": "always",
                "action": (r.get("action") or "deny").strip().lower(), "logtraffic": "all",
                "comments": "AutoKRP " + ctx.get("run", "")}
        fg.post("/api/v2/cmdb/firewall/policy", body, note="Policy " + name, row=r)
'''},
    {"key": "empty", "name": "Empty", "note": "", "code": '''def plan(fg, rows, ctx):
    # rows: list of dicts keyed by column name (ctx["columns"])
    # fg.get(path) / fg.results(path): read from the device
    # fg.post(path, body, note, row) / fg.put(...) / fg.delete(path, note, row): propose an action
    for r in rows:
        log(r)
'''},
]
