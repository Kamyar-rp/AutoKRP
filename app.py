#!/usr/bin/env python3
"""
AutoKRP — نقطه‌ی شروع.  اجرا: python app.py  |  نسخه‌ی Demo: python app.py --demo
Copyright (c) 2026 Kamyar RP — MIT License. Built with the help of Claude (Anthropic).
"""
import argparse
import json
import logging
import os
import socket
import sys
from pathlib import Path

from autokrp import APP_ID, paths

LOCK_PORTS = {False: 47831, True: 47832}
_lock_sock = None


def single_instance(demo):
    global _lock_sock
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        if os.name == "nt":       # برنامه‌ی دیگری نتواند همین پورت را هم‌زمان bind کند (و فرمان‌ها را بگیرد)
            s.setsockopt(socket.SOL_SOCKET, getattr(socket, "SO_EXCLUSIVEADDRUSE", -5), 1)
        else:                     # POSIX: اتصال‌های TIME_WAIT قبلی مانع اجرای دوباره نشوند
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", LOCK_PORTS[demo]))
        s.listen(4)
    except OSError:
        s.close()
        return False
    _lock_sock = s
    return True


def release_instance():
    global _lock_sock
    if _lock_sock is not None:
        try:
            _lock_sock.close()
        except OSError:
            pass
        _lock_sock = None


# ---------------------------------------------------------------- کنترل نمونه‌ی در حال اجرای سرور
# روی همان سوکت قفل (فقط 127.0.0.1). هر فرمان باید توکن تصادفی همین اجرا را داشته باشد که در پوشه‌ی داده
# با دسترسی فقط همین کاربر ذخیره می‌شود؛ کاربر دیگر سیستم نمی‌تواند سرور را متوقف کند.
CTL_FILE = ".ctl_token"


def start_control(info, stop, on_show=None):
    import hmac
    import json
    import secrets
    import threading
    from autokrp.vault import write_secure
    tok = secrets.token_hex(24)
    write_secure(paths.data_dir() / CTL_FILE, tok.encode("ascii"))

    def loop():
        while not stop.is_set() and _lock_sock is not None:
            try:
                c, _ = _lock_sock.accept()
            except OSError:
                return
            with c:
                try:
                    c.settimeout(3)
                    cmd, _, t = c.recv(256).decode("ascii", "replace").strip().partition(" ")
                    if not hmac.compare_digest(t.encode("ascii", "replace"), tok.encode("ascii")):
                        continue
                    if cmd == "INFO":
                        c.sendall(json.dumps({"headless": bool(info.get("headless")), "url": info.get("url"),
                                              "port": info.get("port")}).encode("utf-8"))
                    elif cmd == "SHOW" and on_show:
                        c.sendall(b"OK")
                        on_show()
                    elif cmd == "STOP":
                        c.sendall(b"OK")
                        stop.set()
                except OSError:
                    continue
    threading.Thread(target=loop, name="instance-control", daemon=True).start()
    return tok


def control(cmd, demo=False, timeout=5):
    """فرمان به نمونه‌ی در حال اجرا (INFO/STOP). خروجی: bytes یا None."""
    try:
        tok = (paths.data_dir() / CTL_FILE).read_text(encoding="ascii").strip()
        with socket.create_connection(("127.0.0.1", LOCK_PORTS[demo]), timeout=timeout) as c:
            c.sendall(f"{cmd} {tok}".encode("ascii"))
            out = b""
            while True:
                d = c.recv(4096)
                if not d:
                    break
                out += d
            return out
    except (OSError, ValueError):
        return None


def message_box(text, title=APP_ID):
    if sys.platform == "win32":
        import ctypes
        ctypes.windll.user32.MessageBoxW(None, text, title, 0x40)
    else:
        print(text)


def retry_box(text, title=APP_ID):
    """True = «تلاش دوباره»، False = انصراف."""
    if sys.platform == "win32":
        import ctypes
        return ctypes.windll.user32.MessageBoxW(None, text, title, 0x5 | 0x10) == 4   # MB_RETRYCANCEL | MB_ICONERROR
    print(text)
    return False


def open_store(Store):
    """باز کردن پایگاه داده؛ اگر MySQL در دسترس نباشد کاربر می‌تواند دوباره تلاش کند یا خارج شود."""
    from autokrp.dbmysql import DbError
    while True:
        try:
            return Store()
        except DbError as e:
            logging.getLogger(__name__).error("database open failed: %s", e)
            if not retry_box(paths.L(f"پایگاه داده‌ی MySQL باز نشد:\n{e}\n\n«Retry» = تلاش دوباره، «Cancel» = خروج.\n"
                                     "برگشت به پایگاه داده‌ی محلی (خالی؛ داده‌های MySQL دست نمی‌خورند): اجرای برنامه با --local-db",
                                     f"Could not open the MySQL database:\n{e}\n\nRetry = try again, Cancel = quit.\n"
                                     "To fall back to the local database (empty; MySQL data is not touched), run the app with --local-db")):
                return None


def setup_logging():
    from autokrp.atrest import EncryptedLogHandler
    h = EncryptedLogHandler(paths.logs_dir() / "app.log", maxBytes=1_000_000, backupCount=5, encoding="utf-8")
    h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    root.addHandler(h)
    logging.getLogger("urllib3").setLevel(logging.WARNING)


_LOC_EN = [(r"^پوشه‌ای انتخاب نشده است", "No folder selected."),
           (r"^مسیر شبکه‌ای", "Network paths (\\\\server\\share) are not supported; choose a folder on a disk of this system."),
           (r"^مسیر کامل لازم است", "A full path is required (e.g. D:\\Data)."),
           (r"^این درایو شبکه‌ای است", "This is a network drive; the database is not reliable on a network drive. Choose a local disk."),
           (r"^پوشه پیدا نشد: (.*)$", "Folder not found: {0}"),
           (r"^در این مسیر فایلی به نام (\S+) هست", "There is a file named {0} in this location; choose another folder."),
           (r"^پوشه‌ی (.*) از قبل هست و داده‌ی AutoKRP نیست", "Folder {0} already exists and does not contain AutoKRP data; choose another folder."),
           (r"^اجازه‌ی نوشتن در این پوشه نیست: (.*)$", "No write permission in this folder: {0}")]


def _loc_err_en(msg):
    import re
    for pat, en in _LOC_EN:
        m = re.search(pat, msg)
        if m:
            return en.format(*m.groups())
    return msg


def _choose_mode(ask_location=False):
    """اولین اجرا: (۱.۲۶.۲) انتخاب پوشه‌ی داده و انتخاب کلاینت یا سرور. خروجی: "client" | "server" | None(انصراف).
    پوشه‌ی داده بعداً فقط با پاک‌سازی کامل (RESET) عوض می‌شود."""
    try:
        import webview
    except Exception:
        return "client"
    default = str(paths.default_root())
    from autokrp import terms
    need_terms = paths.terms_accepted_v() < terms.VERSION      # 1.39: پیش از انتخاب پوشه و حالت (پیش از ساختن سرور)
    html = """<!doctype html><html lang=fa dir=rtl><head><meta charset=utf-8>
<style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0b1622;color:#e6edf6;font-family:Tahoma,sans-serif}
.w{width:600px;text-align:center}.cards{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-top:14px}
.c{background:#101c2a;border:1px solid #223040;border-radius:14px;padding:20px;cursor:pointer}
.c:hover{border-color:#2f9e8f}.c b{font-size:17px}.c p{color:#8aa0b4;font-size:12.5px;line-height:1.8;margin:8px 0 0}
.dis .c{opacity:.4;pointer-events:none}
h1{font-size:22px;margin:0}.s{color:#8aa0b4;font-size:13px;line-height:1.8}h3{font-size:14px;margin:18px 0 6px;text-align:right}
.loc{background:#101c2a;border:1px solid #223040;border-radius:14px;padding:14px;text-align:right}
.row{display:flex;gap:8px}input{flex:1;background:#0b1622;color:#e6edf6;border:1px solid #2a3a4c;border-radius:8px;padding:8px;font:13px Consolas,monospace;direction:ltr}
button{background:#1d6f65;color:#fff;border:0;border-radius:8px;padding:8px 14px;font:13px Tahoma,sans-serif;cursor:pointer}
button.g{background:#223040}.m{font-size:12.5px;line-height:1.9;margin-top:8px;min-height:20px}.ok{color:#5fd3a7}.er{color:#ff8a8a}
.ltr{direction:ltr;unicode-bidi:embed;font-family:Consolas,monospace}#ex{display:none;margin-top:10px}
#terms{text-align:start}#terms h2{font-size:17px;margin:4px 0 8px}#tb{background:#101c2a;border:1px solid #223040;border-radius:14px;padding:12px 16px;
max-height:52vh;overflow:auto;font-size:12.8px;line-height:1.9;color:#cfd9e4}#tb p{margin:0 0 8px}.tf{display:flex;gap:8px;align-items:center;margin-top:12px}
.tf label{flex:1;font-size:13px;cursor:pointer}button:disabled{opacity:.45;cursor:default}#main{display:none}</style></head>
<body><div class=w><div id=terms><button class=g id=lang0 style="float:left;padding:4px 10px;font-size:12px">English</button><h2 id=tt></h2><div id=tb></div>
<div class=tf><label><input type=checkbox id=tc> <span id=tcl></span></label><button class=g id=tno></button><button id=tyes disabled></button></div></div>
<div id=main><button class=g id=lang style="float:right;padding:4px 10px;font-size:12px">English</button><h1>AutoKRP</h1><p class=s data-t=sub>راه‌اندازی اول (بعداً فقط با پاک‌سازی کامل، RESET، عوض می‌شود).</p>
<div id=locBox style="display:none"><h3 data-t=h1>۱. پوشه‌ی ذخیره‌ی داده‌ها</h3><div class=loc>
<div class=row><input id=p spellcheck=false><button class=g id=br data-t=br>انتخاب پوشه…</button></div>
<div class=m id=msg></div>
<p class=s style="margin:6px 0 0" data-t=note>پایگاه داده، تنظیمات، اسرار، لاگ‌ها، داده‌ی مانیتورینگ و پشتیبان‌ها همه داخل زیرپوشه‌ی <span class=ltr>AutoKRP</span> همین مسیر و رمزشده ذخیره می‌شوند. پیش‌فرض: پوشه‌ی کاربر ویندوز. درایو شبکه پشتیبانی نمی‌شود.</p>
<div id=ex><button id=useEx data-t=useEx>ادامه با داده‌ی موجود</button></div></div><h3 data-t=h2>۲. حالت اجرا</h3></div>
<div id=modes class=cards>
<div class=c data-m=client><b data-t=cT>کلاینت (دسکتاپ)</b><p data-t=cD>یک کاربر روی همین کامپیوتر، با پنجره‌ی برنامه. بدون رمز (DPAPI) یا یک رمز اصلی.</p></div>
<div class=c data-m=server><b data-t=sT>سرور (وب)</b><p data-t=sD>چند کاربر از طریق مرورگر و HTTPS، با نقش‌های ادمین/اپراتور/فقط‌خواندنی.</p></div>
</div></div></div>
<script>
const ASK=__ASK__, NEED=__NEED__, TERMS=__TERMS__, $=(x)=>document.getElementById(x);
const TU={fa:{c:"متن بالا را خواندم و می‌پذیرم",y:"می‌پذیرم و ادامه",n:"نمی‌پذیرم (خروج)",s:"English"},en:{c:"I have read and accept the text above",y:"Accept and continue",n:"I do not accept (exit)",s:"فارسی"}};
function drawTerms(){const l=LANG,u=TU[l],w=$("terms");w.dir=l==="fa"?"rtl":"ltr";$("tt").textContent=TERMS.title[l];
 $("tb").innerHTML="";TERMS.text[l].forEach((t)=>{const p=document.createElement("p");p.textContent=t;$("tb").appendChild(p);});
 $("tcl").textContent=u.c;$("tyes").textContent=u.y;$("tno").textContent=u.n;$("lang0").textContent=u.s;$("lang0").style.float=l==="fa"?"left":"right";}
const EN={sub:"First run (can be changed later only with a full reset, RESET).",h1:"1. Data folder",br:"Choose folder…",
 note:"The database, settings, secrets, logs, monitoring data and backups are all stored encrypted in the <span class=ltr>AutoKRP</span> subfolder of this location. Default: the Windows user folder. Network drives are not supported.",
 useEx:"Continue with existing data",h2:"2. Run mode",cT:"Client (desktop)",cD:"One user on this computer, with the app window. No password (DPAPI) or one master password.",
 sT:"Server (web)",sD:"Several users through a browser over HTTPS, with admin/operator/read-only roles."};
const FA={};document.querySelectorAll("[data-t]").forEach((e)=>FA[e.dataset.t]=e.innerHTML);
let EX=null, T=0, LANG=__LANG__, LAST=null;
function api(){return window.pywebview.api;}
function setLang(l){LANG=l;document.documentElement.lang=l;document.documentElement.dir=l==="fa"?"rtl":"ltr";
 document.querySelectorAll("h3,.loc").forEach((e)=>e.style.textAlign=l==="fa"?"right":"left");
 document.querySelectorAll("[data-t]").forEach((e)=>e.innerHTML=(l==="fa"?FA:EN)[e.dataset.t]);$("lang").textContent=l==="fa"?"English":"فارسی";if(LAST)show(LAST);}
function show(r){LAST=r;const m=$("msg");EX=null;$("ex").style.display="none";const en=LANG==="en";
 if(!r.ok){m.className="m er";m.textContent=en&&r.error_en?r.error_en:r.error;$("modes").className="cards dis";return;}
 m.className="m ok";m.innerHTML=(en?"Data in: ":"داده‌ها در: ")+"<span class=ltr></span>"+(r.free_gb!=null?(en?" — free space: ":" — فضای آزاد: ")+r.free_gb+" GB":"");
 m.querySelector(".ltr").textContent=r.dir;
 if(r.existing){EX=r.existing;const md=r.existing==="server"?(en?"server":"سرور"):(en?"client":"کلاینت");
  m.innerHTML+=en?"<br>Existing AutoKRP data ("+md+" mode) was found here; it will be used and the mode stays the same."
   :"<br>داده‌ی قبلی AutoKRP (حالت «"+md+"») در این مسیر پیدا شد؛ همان استفاده می‌شود و حالت عوض نمی‌شود.";
  $("ex").style.display="block";$("modes").className="cards dis";}
 else $("modes").className="cards";}
async function check(){const r=await api().check($("p").value);show(r);}
function initTerms(){if(!NEED){$("terms").style.display="none";$("main").style.display="block";return init();}
 drawTerms();$("lang0").onclick=()=>{LANG=LANG==="fa"?"en":"fa";api().lang(LANG);drawTerms();};
 $("tc").onchange=()=>{$("tyes").disabled=!$("tc").checked;};
 $("tno").onclick=()=>api().decline();
 $("tyes").onclick=async()=>{await api().accept(TERMS.v);$("terms").style.display="none";$("main").style.display="block";init();};}
function init(){setLang(LANG);$("lang").onclick=()=>{setLang(LANG==="fa"?"en":"fa");api().lang(LANG);};
 if(!ASK){$("modes").className="cards";return;}
 $("locBox").style.display="block";$("p").value=__DEF__;check();
 $("p").addEventListener("input",()=>{clearTimeout(T);T=setTimeout(check,400);});
 $("br").onclick=async()=>{const r=await api().browse();if(r){$("p").value=r;check();}};
 $("useEx").onclick=()=>api().pick(EX,$("p").value);}
document.querySelectorAll("[data-m]").forEach((c)=>c.onclick=()=>api().pick(c.dataset.m,ASK?$("p").value:""));
window.addEventListener("pywebviewready",initTerms);
</script></body></html>""".replace("__ASK__", "true" if ask_location else "false").replace("__DEF__", json.dumps(default)).replace("__LANG__", json.dumps(paths.ui_lang())).replace(
        "__NEED__", "true" if need_terms else "false").replace("__TERMS__", json.dumps(terms.payload(), ensure_ascii=False).replace("</", "<\\/"))
    chosen = {"m": None, "root": None}

    class ChooseApi:
        def accept(self, v):
            if int(v or 0) == terms.VERSION:
                paths.save_terms_accepted(terms.VERSION)
            return True

        def decline(self):
            for w in webview.windows:
                w.destroy()
            return True

        def lang(self, l):
            paths.set_ui_lang(l)
            return True

        def check(self, root):
            try:
                return {"ok": True, **paths.check_location(root)}
            except ValueError as e:
                return {"ok": False, "error": str(e), "error_en": _loc_err_en(str(e))}
            except Exception as e:  # noqa — نمایش خطا به کاربر
                return {"ok": False, "error": f"بررسی پوشه ناموفق: {e}", "error_en": f"Folder check failed: {e}"}

        def browse(self):
            try:
                res = webview.windows[0].create_file_dialog(webview.FOLDER_DIALOG)
            except Exception:
                return None
            if not res:
                return None
            return str(res[0] if isinstance(res, (list, tuple)) else res)

        def pick(self, m, root=""):
            if ask_location:
                try:
                    info = paths.check_location(root)       # دوباره (ممکن است در این فاصله عوض شده باشد)
                except ValueError:
                    return False
                if info["existing"]:
                    m = info["existing"]                    # حالت داده‌ی قبلی عوض نمی‌شود
                chosen["root"] = Path(str(root).strip().strip('"'))
            chosen["m"] = "server" if m == "server" else "client"
            for w in webview.windows:
                w.destroy()
            return True

    webview.create_window("AutoKRP", html=html, js_api=ChooseApi(), width=720, height=680 if (ask_location or need_terms) else 380,
                          background_color="#0b1622")
    webview.start(gui="edgechromium" if sys.platform == "win32" else None)
    if not chosen["m"]:
        return None
    if chosen["root"] is not None:
        paths.save_location(chosen["root"])
        paths.set_root(chosen["root"])
        if os.path.normcase(os.path.abspath(str(chosen["root"]))) != os.path.normcase(os.path.abspath(default)):
            paths.restrict_dir(paths.data_dir())
    if paths.saved_mode() is None:
        paths.save_mode(chosen["m"])
    return paths.saved_mode()


def _start_tray(api, title):
    """آیکن کوچک کنار ساعت ویندوز (Show hidden icons): کلیک = نمایش پنجره؛ منو: نمایش / خروج کامل.
    اگر pystray نصب نباشد یا کار نکند، برنامه بدون آن ادامه می‌دهد."""
    log = logging.getLogger("tray")
    try:
        import pystray
        from PIL import Image, ImageDraw
    except Exception as e:
        log.info("آیکن سینی سیستم در دسترس نیست: %s", e)
        return None
    img = None
    for base in (Path(getattr(sys, "_MEIPASS", "")), Path(__file__).resolve().parent):
        p = base / "assets" / "app.png"
        if p.is_file():
            try:
                img = Image.open(p).convert("RGBA")
                break
            except Exception:
                img = None
    if img is None:      # آیکن ساده‌ی جایگزین
        img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
        d = ImageDraw.Draw(img)
        d.rounded_rectangle((4, 4, 60, 60), radius=14, fill=(79, 193, 180, 255))
        d.line((16, 36, 26, 36, 31, 22, 38, 46, 43, 32, 50, 32), fill=(6, 38, 35, 255), width=5)

    def show(icon, item):
        api._show_window()

    def quit_all(icon, item):
        api._quitting = True
        try:
            if api._window:
                api._window.destroy()
        finally:
            icon.stop()

    try:
        icon = pystray.Icon("AutoKRP", img, title, menu=pystray.Menu(
            pystray.MenuItem(paths.L("نمایش AutoKRP", "Show AutoKRP"), show, default=True),
            pystray.MenuItem(paths.L("خروج کامل", "Quit"), quit_all)))
        icon.run_detached()        # ویندوز: حلقه‌ی پیام در ترد جدای خود pystray
        return icon
    except Exception:
        log.exception("tray")
        return None


def _lan_ips():
    ips = []
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if not ip.startswith("127.") and ip not in ips:
                ips.append(ip)
    except OSError:
        pass
    return ips


def _cert_fp():
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from autokrp import certs
        c = x509.load_pem_x509_certificate(open(certs.paths_for()[0], "rb").read())
        h = c.fingerprint(hashes.SHA256()).hex().upper()
        return ":".join(h[i:i + 2] for i in range(0, len(h), 2))
    except Exception:
        return ""


_STATUS_CSS = """body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0b1622;color:#e6edf6;font-family:Tahoma,sans-serif;text-align:center}
a{color:#2f9e8f;direction:ltr;display:inline-block;margin:3px 0}.b{background:#101c2a;border:1px solid #223040;border-radius:14px;padding:22px 30px;max-width:540px}
.fp{direction:ltr;font-family:Consolas,monospace;font-size:10.5px;color:#8aa0b4;word-break:break-all;margin-top:6px}
.h{color:#8aa0b4;font-size:12.5px;line-height:1.8}.sv{border-top:1px solid #223040;margin-top:14px;padding-top:12px}
button{background:#2f9e8f;color:#04120f;border:0;border-radius:8px;padding:7px 14px;font-family:inherit;font-weight:700;cursor:pointer;margin:4px}
button.g{background:#1b2a3a;color:#e6edf6}button:disabled{opacity:.55}.st{font-size:13px}.ok{color:#5fd1a0}.no{color:#e0b060}.err{color:#ff8080}"""

_STATUS_JS = r"""const A=()=>window.pywebview.api;
function busy(on){document.querySelectorAll("button").forEach(b=>b.disabled=on);}
async function call(n){busy(true);document.getElementById("msg").textContent="…";
 try{const r=await A()[n]();document.getElementById("msg").textContent=r.msg||"";document.getElementById("msg").className="h "+(r.ok?"ok":"err");draw(r.svc);}
 finally{busy(false);}}
function draw(s){const e=document.getElementById("svc");if(!e||!s)return;
 if(!s.supported){e.innerHTML="";return;}
 const T=(f,e)=>FA?f:e;
 e.innerHTML='<div class="st">'+T('اجرای خودکار با روشن شدن ویندوز (بدون لاگین): ','Auto-start with Windows (no login): ')+(s.installed?'<b class="ok">'+T('فعال','On')+'</b>':'<b class="no">'+T('غیرفعال','Off')+'</b>')+'</div>'+
  (s.installed?'<button class="g" onclick="call(\'svc_remove\')">'+T('حذف اجرای خودکار','Remove auto-start')+'</button>'+(s.background?'':'<button onclick="call(\'svc_background\')">'+T('انتقال به پس‌زمینه و بستن پنجره','Move to background and close')+'</button>')
   :'<button onclick="call(\'svc_install\')">'+T('فعال کردن','Enable')+'</button>')+
  '<p class="h">'+T('نیاز به دسترسی Administrator (پنجره‌ی UAC). سرور با همین کاربر ویندوز اجرا می‌شود و داده‌ها تا اولین ورود در وب قفل می‌مانند.','Requires Administrator access (UAC prompt). The server runs as this Windows user and data stays locked until the first web sign-in.')+'</p>';}
window.addEventListener("pywebviewready",async()=>draw(await A().svc_status()));"""


def _status_html(title, urls, fp, note):
    import html as _html
    links = "".join(f'<div><a href="#" onclick="window.pywebview.api.open({i});return false">{_html.escape(u)}</a></div>'
                    for i, u in enumerate(urls))
    fa = paths.ui_lang() == "fa"
    return f"""<!doctype html><html lang={'fa dir=rtl' if fa else 'en dir=ltr'}><head><meta charset=utf-8><style>{_STATUS_CSS}</style></head>
<body><div class=b><h2 style="margin-top:0">{_html.escape(title)}</h2>
<p class=h>{paths.L('از مرورگر یکی از این آدرس‌ها را باز کنید:', 'Open one of these addresses in a browser:')}</p>{links}
{'<p class=h style="margin-top:14px">' + paths.L('اثر انگشت گواهی (برای بررسی هشدار مرورگر):', 'Certificate fingerprint (to verify the browser warning):') + '</p><div class=fp>' + _html.escape(fp) + '</div>' if fp else ''}
<p class=h style="margin-top:14px">{note}</p>
<div class=sv id=svc></div><p class=h id=msg></p></div><script>const FA={'true' if fa else 'false'};{_STATUS_JS}</script></body></html>"""


class _SvcApi:
    """دکمه‌های اجرای خودکار در پنجره‌ی وضعیت سرور."""

    def __init__(self, urls, demo, background=False, on_background=None, on_stopped=None):
        self.urls, self.demo, self.background = urls, demo, background
        self.on_background, self.on_stopped = on_background, on_stopped

    def open(self, i=0):
        import webbrowser
        i = int(i)
        webbrowser.open(self.urls[i] if 0 <= i < len(self.urls) else self.urls[0])

    def svc_status(self):
        from autokrp import winsvc
        return {"supported": winsvc.supported() and not self.demo, "installed": winsvc.installed(),
                "background": self.background}

    def _r(self, ok, msg):
        return {"ok": ok, "msg": msg, "svc": self.svc_status()}

    def svc_install(self):
        ok, msg = _svc_elevated("install")
        return self._r(ok, msg)

    def svc_remove(self):
        if self.background:
            control("STOP", self.demo)
        ok, msg = _svc_elevated("remove")
        if ok and self.background and self.on_stopped:
            self.on_stopped()
        return self._r(ok, msg)

    def svc_stop_bg(self):
        ok = control("STOP", self.demo) == b"OK"
        if ok and self.on_stopped:
            self.on_stopped()
        return self._r(ok, paths.L("سرور پس‌زمینه متوقف شد؛ با روشن شدن بعدی ویندوز دوباره اجرا می‌شود.",
                                   "The background server stopped; it starts again at the next Windows start.") if ok
                       else paths.L("سرور پس‌زمینه پاسخ نداد.", "The background server did not respond."))

    def svc_background(self):
        if self.on_background:
            return self.on_background()
        return self._r(False, "")


def _svc_elevated(action):
    """نصب/حذف اجرای خودکار با UAC. خروجی: (موفق؟، پیام)."""
    from autokrp import winsvc
    res = paths.data_dir() / ".svc_result"
    try:
        res.unlink()
    except OSError:
        pass
    args = ["--install-service" if action == "install" else "--remove-service", "--quiet",
            "--svc-user", winsvc.current_user(), "--data-root", str(paths.root())]
    if winsvc.is_admin():
        code = _svc_do(action, winsvc.current_user())
        ok = code == 0
    else:
        ok = winsvc.elevate(args)
    try:
        msg = res.read_text(encoding="utf-8")
        res.unlink()
    except OSError:
        msg = "" if ok else paths.L("انجام نشد (دسترسی Administrator داده نشد؟)", "Failed (Administrator access not granted?)")
    return ok, msg


def _svc_do(action, user, quiet=True):
    """اجرای واقعی نصب/حذف (با دسترسی Administrator). نتیجه در .svc_result برای پنجره‌ی والد."""
    from autokrp import serverauth, winsvc
    try:
        if action == "install":
            if paths.saved_mode() != "server":
                raise winsvc.SvcError(paths.L("اجرای خودکار فقط برای حالت سرور است.", "Auto-start is only for server mode."))
            r = winsvc.install(user, paths.root(), serverauth.config().get("port") or 8443)
            msg = paths.L("اجرای خودکار فعال شد؛ سرور از روشن شدن بعدی ویندوز در پس‌زمینه اجرا می‌شود.",
                          "Auto-start enabled; from the next Windows start the server runs in the background.") + (
                "" if r.get("firewall") else paths.L(" (قانون فایروال ساخته نشد؛ پورت را دستی باز کنید.)",
                                                     " (No firewall rule was created; open the port manually.)"))
        else:
            winsvc.remove()
            msg = paths.L("اجرای خودکار حذف شد.", "Auto-start removed.")
        code = 0
    except Exception as e:
        msg, code = str(e) or "error", 1
    try:
        (paths.data_dir() / ".svc_result").write_text(msg, encoding="utf-8")
    except OSError:
        pass
    if not quiet:
        message_box(msg)
    return code


def _run_server(args):
    import threading
    import time as _t
    from autokrp import atrest, server
    headless = bool(args.headless)
    if not single_instance(args.demo):
        if headless:
            return 1
        return _background_window(args)
    atrest.set_server_mode(True)
    setup_logging()
    log = logging.getLogger("autokrp.app")
    log.info("شروع در حالت سرور%s", " (پس‌زمینه)" if headless else "")
    info = {"url": None, "port": None, "error": None, "headless": headless}
    stop = threading.Event()

    def ready(url, port):
        info["url"], info["port"] = url, port
        try:
            # پس از ساخت TLS سرور: اتصال‌های خروجی (Splunk/FortiGate/…) از مخزن گواهی ویندوز استفاده کنند
            import truststore
            truststore.inject_into_ssl()
        except Exception:
            pass

    def serve():
        try:
            server.run(demo=args.demo, on_ready=ready, stop_event=stop)
        except OSError as e:
            info["error"] = paths.L(f"سرور اجرا نشد: {e}", f"The server did not start: {e}")
            log.error("server: %s", e)

    t = threading.Thread(target=serve, name="https-server")
    t.start()
    for _ in range(200):
        if info["url"] or info["error"]:
            break
        _t.sleep(0.05)
    tok = start_control(info, stop)
    try:
        webview = None
        if not headless:
            try:
                import webview
            except Exception:
                webview = None
        if webview is None:            # پس‌زمینه یا بدون رابط گرافیکی: تا توقف (STOP یا Ctrl+C)
            print(info["error"] or f"AutoKRP server on {info['url']}")
            try:
                while t.is_alive():
                    t.join(1)
            except KeyboardInterrupt:
                stop.set()
                t.join(15)
            return 1 if info["error"] else 0
        if info["error"]:
            stop.set()
            message_box(info["error"] + paths.L("\nپورت در حال استفاده است یا دسترسی ندارد.", "\nThe port is in use or access is denied."))
            return 1
        urls = [info["url"]] + [f"https://{ip}:{info['port']}/" for ip in _lan_ips()]

        def to_background():
            from autokrp import winsvc
            stop.set()
            t.join(20)
            release_instance()
            if not winsvc.run_now():
                return {"ok": False, "msg": paths.L("اجرای تسک پس‌زمینه ناموفق بود؛ برنامه را دوباره باز کنید.", "Starting the background task failed; open the app again."), "svc": api.svc_status()}
            for w in webview.windows:
                w.destroy()
            return {"ok": True, "msg": "", "svc": api.svc_status()}

        api = _SvcApi(urls, args.demo, on_background=to_background)
        status = _status_html(paths.L("سرور AutoKRP در حال اجراست", "AutoKRP server is running"), urls, _cert_fp(),
                              paths.L("اولین حساب ادمین فقط از همین سیستم (localhost) ساخته می‌شود.<br>با بستن این پنجره سرور متوقف می‌شود.",
                                      "The first admin account can only be created from this machine (localhost).<br>Closing this window stops the server."))
        webview.create_window(paths.L("AutoKRP — سرور", "AutoKRP — Server"), html=status, js_api=api, width=620, height=560, background_color="#0b1622")
        webview.start(gui="edgechromium" if sys.platform == "win32" else None)
        return 0
    finally:
        stop.set()                 # بستن پنجره یا STOP: سرور، کارها و پایگاه داده به‌درستی بسته می‌شوند
        t.join(20)
        try:
            f = paths.data_dir() / CTL_FILE
            if f.read_text(encoding="ascii").strip() == tok:   # نه توکن نمونه‌ی پس‌زمینه‌ای که بعد از ما شروع شده
                f.unlink()
        except OSError:
            pass


def _background_window(args):
    """برنامه باز شد ولی نمونه‌ی دیگری از سرور در حال اجراست (معمولاً پس‌زمینه با Task Scheduler)."""
    import json
    raw = control("INFO", args.demo)
    try:
        info = json.loads(raw.decode("utf-8")) if raw else None
    except ValueError:
        info = None
    if not info or not info.get("headless"):
        message_box(paths.L("برنامه از قبل باز است.", "AutoKRP is already running."))
        return 0
    try:
        import webview
    except Exception:
        print(f"AutoKRP server is running in the background on {info.get('url')}.")
        return 0
    port = info.get("port") or 8443
    urls = [f"https://localhost:{port}/"] + [f"https://{ip}:{port}/" for ip in _lan_ips()]

    def stopped():
        for w in webview.windows:
            w.evaluate_js("document.getElementById('bgStop')&&document.getElementById('bgStop').remove()")

    api = _SvcApi(urls, args.demo, background=True, on_stopped=stopped)
    note = (paths.L('سرور در پس‌زمینه (اجرای خودکار ویندوز) در حال اجراست؛ بستن این پنجره آن را متوقف نمی‌کند.',
                    'The server is running in the background (Windows auto-start); closing this window does not stop it.')
            + '<br><button class="g" id="bgStop" onclick="call(\'svc_stop_bg\')">' + paths.L('توقف سرور پس‌زمینه', 'Stop background server') + '</button>')
    status = _status_html(paths.L("سرور AutoKRP در پس‌زمینه", "AutoKRP server in the background"), urls, _cert_fp(), note)
    webview.create_window(paths.L("AutoKRP — سرور (پس‌زمینه)", "AutoKRP — Server (background)"), html=status, js_api=api, width=620, height=560,
                          background_color="#0b1622")
    webview.start(gui="edgechromium" if sys.platform == "win32" else None)
    return 0


def _svc_cli(args):
    """--install-service / --remove-service از خط فرمان (یا فرزند بالابرده‌شده با --quiet)."""
    from autokrp import winsvc
    action = "install" if args.install_service else "remove"
    if not winsvc.supported():
        print("Windows only.")
        return 1
    if args.demo:
        message_box(paths.L("اجرای خودکار برای نسخه‌ی Demo نیست.", "Auto-start is not available for the Demo."))
        return 1
    if winsvc.is_admin():
        if action == "remove":
            control("STOP", False)
        return _svc_do(action, args.svc_user or winsvc.current_user(), quiet=args.quiet)
    if args.quiet:                 # فرزند بالابرده‌شده ولی هنوز بدون دسترسی
        return 1
    if action == "remove":
        control("STOP", False)
    ok, msg = _svc_elevated(action)
    message_box(msg or (paths.L("انجام شد.", "Done.") if ok else paths.L("انجام نشد.", "Failed.")))
    return 0 if ok else 1


def main():
    if len(sys.argv) == 3 and sys.argv[1] == "--fgtask":     # 1.29: اجرای plan تسک FortiGate در فرایند جدا
        from autokrp import fgtask_child
        sys.exit(fgtask_child.main(sys.argv[2]))
    if len(sys.argv) == 3 and sys.argv[1] == "--snmpworker":  # 1.34: کارگر SNMP (چند هسته)
        from autokrp import snmpworker
        sys.exit(snmpworker.main(sys.argv[2]))
    ap = argparse.ArgumentParser()
    ap.add_argument("--demo", action="store_true", help="run with sample data (no real connections)")
    ap.add_argument("--debug", action="store_true")
    ap.add_argument("--server", action="store_true", help="server (web) mode")
    ap.add_argument("--client", action="store_true", help="client (desktop) mode")
    ap.add_argument("--headless", action="store_true", help="server without a window (Windows auto-start)")
    ap.add_argument("--data-root", help=argparse.SUPPRESS)
    ap.add_argument("--install-service", action="store_true", help="start the server automatically with Windows")
    ap.add_argument("--remove-service", action="store_true", help="remove server auto-start")
    ap.add_argument("--svc-user", help=argparse.SUPPRESS)
    ap.add_argument("--quiet", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("--local-db", action="store_true", help="ignore the MySQL settings and use the local database")
    ap.add_argument("--memdiag", action="store_true", help="log memory use every minute to logs\\memdiag.txt (diagnostics)")
    ap.add_argument("--memdiag-trace", action="store_true", help="with --memdiag: trace Python allocations (tracemalloc); slows the app")
    args = ap.parse_args()

    paths.set_demo(args.demo)
    if args.data_root:
        paths.set_root(args.data_root)
    else:
        loc = paths.saved_location()          # 1.26.2: پوشه‌ی داده‌ای که در اولین اجرا انتخاب شد
        if loc is not None:
            if not (loc / APP_ID).is_dir():
                message_box(paths.L(f"پوشه‌ی داده‌ی AutoKRP پیدا نشد:\n{loc / APP_ID}\n\nاگر روی درایو جداست، آن را وصل کنید و "
                                    f"برنامه را دوباره باز کنید. برای شروع از صفر با پوشه‌ی دیگر، فایل زیر را حذف کنید:\n"
                                    f"{paths.location_file()}",
                                    f"AutoKRP data folder not found:\n{loc / APP_ID}\n\nIf it is on a separate drive, connect it and "
                                    f"open the app again. To start from scratch with another folder, delete this file:\n"
                                    f"{paths.location_file()}"))
                return 1
            paths.set_root(loc)
    if args.install_service or args.remove_service:
        return _svc_cli(args)
    if args.headless and paths.saved_mode() != "server":
        return 1               # پس از RESET یا نصب کلاینت: تسک قدیمی کاری نمی‌کند

    # انتخاب حالت: پرچم خط فرمان > فایل ذخیره‌شده > انتخاب اولین اجرا
    saved = paths.saved_mode()
    want = "server" if args.server else "client" if args.client else None
    if want and saved and want != saved:
        message_box(paths.L(f"داده‌های این نصب برای حالت «{saved}» است. حالت فقط با پاک‌سازی کامل (RESET) عوض می‌شود.",
                            f"This installation's data is for “{saved}” mode. The mode can only be changed with a full reset (RESET)."))
        return 1
    mode = want or saved
    if want and not saved:
        paths.save_mode(want)
    if mode is None:
        # پوشه‌ی داده فقط در اولین اجرای واقعی پرسیده می‌شود (نه Demo، نه وقتی از قبل انتخاب شده یا --data-root داده شده)
        mode = _choose_mode(ask_location=not args.demo and not args.data_root and paths.saved_location() is None)
        if mode is None:
            return 0
        # pywebview در یک فرایند فقط یک بار start می‌شود؛ برنامه با حالت انتخاب‌شده دوباره اجرا می‌شود
        import subprocess
        cmd = [sys.executable] + ([] if getattr(sys, "frozen", False) else [sys.argv[0]]) + sys.argv[1:]
        # نسخه‌ی exe (PyInstaller onefile): فرزند نباید پوشه‌ی موقت _MEI همین فرایند را به ارث ببرد؛ این پوشه با
        # بسته شدن ما پاک می‌شود و فرزند در بارگذاری DLLها (مثلاً ClrLoader برای پنجره) با خطای 0x7e شکست می‌خورد
        env = {k: v for k, v in os.environ.items() if not (k.startswith("_PYI_") or k == "_MEIPASS2")}
        env["PYINSTALLER_RESET_ENVIRONMENT"] = "1"
        subprocess.Popen(cmd, close_fds=True, env=env)  # nosec B603 — اجرای دوباره‌ی همین برنامه
        return 0
    paths.set_mode(mode)
    if args.local_db:            # MySQL در دسترس نیست و کاربر می‌خواهد با پایگاه داده‌ی محلی (خالی) ادامه دهد
        from autokrp import dbmysql
        dbmysql.remove_conf()
    if mode == "server":
        return _run_server(args)
    try:
        # requests به‌طور پیش‌فرض فقط به certifi اعتماد می‌کند؛ با truststore از مخزن گواهی ویندوز استفاده می‌شود
        # (گواهی‌های سازمانی/SSL inspection، مثل رفتار urllib در اسکریپت‌های قبلی)
        import truststore
        truststore.inject_into_ssl()
    except Exception:
        pass
    if not single_instance(args.demo):
        # برنامه (مثلاً در پس‌زمینه برای مانیتورینگ) باز است: همان پنجره نمایش داده می‌شود
        if control("SHOW", args.demo) != b"OK":
            message_box(paths.L("برنامه از قبل باز است.", "AutoKRP is already running."))
        return 0
    from autokrp import atrest
    try:
        atrest.key()
    except atrest.AtRestError as e:
        message_box(str(e))
        return 1
    marker = paths.data_dir() / ".atrest_v1"
    if not marker.exists():
        atrest.migrate_plain_files()   # داده‌های ساده‌ی نسخه‌های قبل؛ پیش از باز شدن فایل لاگ
        marker.write_bytes(b"")
    setup_logging()

    import webview
    from autokrp.api import Api
    from autokrp.settings import Settings
    from autokrp.store import Store
    from autokrp.worker import Worker

    from autokrp.vault import Vault

    import time as _t
    from autokrp import memdiag
    boot = memdiag.BOOT
    tb = _t.perf_counter()
    settings = Settings()
    vault = Vault(settings)
    settings.attach_vault(vault)
    vault.auto_unlock()          # حالت ساده، متغیر محیطی، یا رمز اصلی با «باز شدن خودکار»
    boot["settings+vault"] = _t.perf_counter() - tb
    store = open_store(Store)
    boot["store"] = _t.perf_counter() - tb
    if store is None:
        return 1
    worker = Worker(settings, store, demo=args.demo)
    api = Api(settings, store, worker, demo=args.demo, vault=vault)
    worker.start()
    boot["worker"] = _t.perf_counter() - tb

    name = (settings.get("branding", "app_name") or "AutoKRP") + (" — Demo" if args.demo else "")
    memdiag.patch_pywebview()           # رفع نشت pywebview (یک ورودی برای هر فراخوانی API)
    window = webview.create_window(name, str(paths.ui_dir() / "index.html"), js_api=api,
                                   width=1360, height=860, min_size=(1080, 680), background_color="#101c2a",
                                   text_select=True)   # انتخاب متن با ماوس و کپی با Ctrl+C
    api._set_window(window)
    if args.memdiag or args.memdiag_trace:
        logging.getLogger("autokrp.app").warning("memdiag on: %s", memdiag.start(window, paths.logs_dir(), store, trace=args.memdiag_trace))
    import threading as _th
    start_control({"headless": False}, _th.Event(), on_show=api._show_window)
    # بستن پنجره وقتی مانیتورینگ فعال است: برنامه در پس‌زمینه می‌ماند (خروج کامل از دکمه‌ی «خروج کامل»)
    window.events.closing += api._on_closing
    tray = _start_tray(api, name) if sys.platform == "win32" else None

    def on_shown():
        boot["window shown"] = _t.perf_counter() - tb
        logging.getLogger("autokrp.app").info("startup: %s", " ".join(f"{k}={v:.1f}s" for k, v in boot.items()))
        icon = settings.get("branding", "icon_file")
        if icon:
            from autokrp.winicon import apply_icon
            apply_icon(window, str(paths.data_dir() / "branding" / icon))
    window.events.shown += on_shown
    try:
        webview.start(debug=args.debug, gui="edgechromium" if sys.platform == "win32" else None)
    finally:
        if tray is not None:
            try:
                tray.stop()
            except Exception:
                pass
        worker.stop()
        store.close()   # ذخیره‌ی نهایی رمزشده‌ی پایگاه داده
    return 0


if __name__ == "__main__":
    sys.exit(main())
