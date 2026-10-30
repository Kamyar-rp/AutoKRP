"""
ابزار SSH: اجرای اسکریپت روی سرور لینوکس یا تجهیزات شبکه.

امنیت اتصال (طبق مشخصات پروژه):
  - look_for_keys=False و allow_agent=False (فقط یوزر/پسورد ذخیره‌شده در vault)
  - Trust-On-First-Use برای host key: بار اول کلید ثبت می‌شود (فایل known_hosts جدا با دسترسی محدود)،
    اتصال واقعی با RejectPolicy و همان فایل انجام می‌شود؛ اگر کلید عوض شده باشد اتصال قطع می‌شود
    (BadHostKeyException) و فقط با تأیید صریح کاربر کلید جدید پذیرفته می‌شود.
اجرا:
  - linux  ← paramiko: اسکریپت کامل با «bash -s» از stdin اجرا می‌شود؛ sudo با «sudo -S» (رمز فقط از stdin)
  - بقیه   ← netmiko: prompt، enable، صفحه‌بندی خروجی و حالت config هر برند را مدیریت می‌کند
"""
import base64
import contextlib
import hashlib
import logging
import os
import socket
import tempfile
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import paramiko

from . import atrest, paths
from .abort import Aborted, Attempt
from .vault import _restrict

log = logging.getLogger(__name__)

DEVICE_TYPES = [
    ("linux", "سرور لینوکس"),
    ("cisco_ios", "Cisco IOS / IOS-XE"),
    ("cisco_nxos", "Cisco NX-OS"),
    ("cisco_asa", "Cisco ASA"),
    ("cisco_xr", "Cisco IOS-XR"),
    ("mikrotik_routeros", "MikroTik RouterOS"),
    ("juniper_junos", "Juniper Junos"),
    ("fortinet", "FortiGate (CLI)"),
    ("huawei", "Huawei VRP"),
    ("hp_procurve", "HP ProCurve / Aruba"),
    ("paloalto_panos", "Palo Alto PAN-OS"),
]
TYPE_NAMES = dict(DEVICE_TYPES)
# 1.31: نوع‌هایی که netmiko برایشان «<نوع>_telnet» دارد (بررسی‌شده با netmiko.ssh_dispatcher.CLASS_MAPPER)
TELNET_TYPES = ("cisco_ios", "cisco_nxos", "cisco_xr", "juniper_junos", "huawei", "hp_procurve", "paloalto_panos")
TEST_COMMANDS = {"linux": "uname -a", "cisco_ios": "show version | include Version", "cisco_nxos": "show version | include version",
                 "cisco_asa": "show version | include Version", "cisco_xr": "show version | include Version",
                 "mikrotik_routeros": "/system resource print", "juniper_junos": "show version | match Junos",
                 "fortinet": "get system status", "huawei": "display version", "hp_procurve": "show version",
                 "paloalto_panos": "show system info"}
MAX_OUTPUT = 2 * 1024 * 1024
VARS = ("name", "host", "port", "username", "group")


class SshError(Exception):
    pass


def fingerprint(key) -> str:
    return "SHA256:" + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")


def render(body, dev):
    """جایگزینی {name} {host} {port} {username} {group}؛ آکولادهای دیگر (مثلاً در اسکریپت bash) دست نمی‌خورند."""
    vals = {"name": dev.get("name") or dev.get("host"), "host": dev.get("host"), "port": str(dev.get("port") or 22),
            "username": dev.get("username") or "", "group": dev.get("grp") or ""}   # username از vault پر می‌شود
    out = body or ""
    for k in VARS:
        out = out.replace("{" + k + "}", str(vals[k]))
    return out


# ------------------------------------------------------------------ الگوریتم‌ها
# پیش‌فرض: فقط الگوریتم‌های امروزی (بدون SHA1 در تبادل کلید و بدون ssh-rsa با SHA1).
# دستگاه‌های قدیمی (روتر/سوئیچ با IOS قدیمی) فقط diffie-hellman-group1/14-sha1 دارند؛ برای آن‌ها در تنظیمات
# همان دستگاه «سازگاری با دستگاه قدیمی» روشن می‌شود و این الگوریتم‌ها فقط برای همان دستگاه مجاز می‌شوند.
LEGACY_KEX = ["diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1", "diffie-hellman-group1-sha1"]
LEGACY_KEYS = ["ssh-rsa", "ssh-dss"]


def algorithms(dev):
    """disabled_algorithms برای paramiko/netmiko."""
    if dev and dev.get("legacy"):
        return {}
    return {"kex": list(LEGACY_KEX), "keys": list(LEGACY_KEYS), "pubkeys": list(LEGACY_KEYS)}


# ------------------------------------------------------------------ host keys (TOFU)
def cred_prefix(dev):
    """کلید vault اعتبارنامه‌ی یک دستگاه: cred.<پروفایل>. یا ssh.<دستگاه>."""
    if dev and dev.get("cred_id"):
        return f"cred.{int(dev['cred_id'])}."
    return f"ssh.{int(dev['id'])}." if dev else "ssh.0."


class HostKeys:
    def __init__(self):
        self.path = paths.data_dir() / "ssh_known_hosts"
        self._lock = threading.Lock()

    @staticmethod
    def entry(host, port):
        return host if int(port) == 22 else f"[{host}]:{port}"

    # فایل رمزشده (atrest) مثل بقیه‌ی داده‌ها؛ فایل ساده‌ی نسخه‌های قبل هم خوانده و در اولین ذخیره رمز می‌شود
    def _load(self):
        hk = paramiko.HostKeys()
        if self.path.exists():
            for line in atrest.read_text(self.path, "utf-8").splitlines():
                try:
                    e = paramiko.hostkeys.HostKeyEntry.from_line(line)
                except Exception:
                    e = None
                if e is not None and e.key is not None:
                    for h in e.hostnames:
                        hk.add(h, e.key.get_name(), e.key)
        return hk

    @staticmethod
    def _lines(hk, only=None):
        return "".join(f"{h} {k.get_name()} {k.get_base64()}\n" for h in hk.keys() if only is None or h == only
                       for k in hk[h].values())

    def _save(self, hk):
        atrest.write_text(self.path, self._lines(hk), "utf-8")

    def load_into(self, client, host, port):
        """کلیدهای همین میزبان مستقیم در حافظه‌ی کلاینت paramiko (بدون فایل ساده)."""
        with self._lock:
            hk = self._load()
        e = self.entry(host, port)
        for k in (hk.lookup(e) or {}).values():
            client.get_host_keys().add(e, k.get_name(), k)

    @contextlib.contextmanager
    def temp(self, host, port):
        """netmiko فقط مسیر فایل می‌گیرد: فایل موقت فقط با کلید همین میزبان، که بلافاصله پس از اتصال پاک می‌شود."""
        with self._lock:
            text = self._lines(self._load(), self.entry(host, port))
        fd, name = tempfile.mkstemp(dir=str(paths.data_dir()), prefix=".kh_", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(text)
            _restrict(Path(name))
            yield name
        finally:
            try:
                os.remove(name)
            except OSError:
                pass

    @staticmethod
    def fetch(host, port, timeout=10, legacy=False, attempt=None):
        """فقط کلید میزبان را می‌گیرد (بدون احراز هویت). attempt: abort.Attempt برای لغو فوری."""
        sock = attempt.connect(host, port, timeout) if attempt else socket.create_connection((host, int(port)), timeout=timeout)
        t = paramiko.Transport(sock, disabled_algorithms=algorithms({"legacy": legacy}))
        try:
            t.banner_timeout = timeout
            t.start_client(timeout=timeout)
            return t.get_remote_server_key()
        finally:
            t.close()

    def check(self, host, port, timeout=10, legacy=False, attempt=None):
        """('match'|'new'|'mismatch', fingerprint جدید، fingerprint قبلی)"""
        key = self.fetch(host, port, timeout, legacy, attempt)
        with self._lock:
            hk = self._load()
            known = hk.lookup(self.entry(host, port))
            if not known:
                hk.add(self.entry(host, port), key.get_name(), key)
                self._save(hk)
                return "new", fingerprint(key), None
            old = known.get(key.get_name())
            if old is None:
                other = next(iter(known.values()))
                return "mismatch", fingerprint(key), fingerprint(other)
            if old.asbytes() != key.asbytes():
                return "mismatch", fingerprint(key), fingerprint(old)
            return "match", fingerprint(key), None

    def list(self):
        with self._lock:
            hk = self._load()
            return [{"host": h, "type": t, "fingerprint": fingerprint(k)} for h in hk.keys() for t, k in hk[h].items()]

    def forget(self, host_entry):
        with self._lock:
            hk = self._load()
            if host_entry in hk:
                del hk[host_entry]
                self._save(hk)
                return True
            return False


# ------------------------------------------------------------------ connectors
def _read_channel(chan, cancel, timeout):
    out, deadline = bytearray(), time.time() + timeout
    while True:
        if cancel.is_set():
            raise SshError("متوقف شد")
        got = False
        while chan.recv_ready():
            out += chan.recv(65536)
            got = True
        while chan.recv_stderr_ready():
            out += chan.recv_stderr(65536)
            got = True
        if len(out) > MAX_OUTPUT:
            out = out[:MAX_OUTPUT] + "\n... [خروجی بیش از ۲ مگابایت؛ بقیه ذخیره نشد]".encode("utf-8")
            break
        if chan.exit_status_ready() and not chan.recv_ready() and not chan.recv_stderr_ready():
            break
        if time.time() > deadline:
            raise SshError(f"اجرای اسکریپت بیش از {timeout} ثانیه طول کشید (timeout)")
        if not got:
            time.sleep(0.05)
    return bytes(out), chan.recv_exit_status() if chan.exit_status_ready() else None


LAST_MARK = "__AKRP_LAST_OUTPUT_7f3c__"
_BLOCK_END = ("fi", "done", "esac", "}", "EOF", ")", ";;")


def mark_last(body):
    """1.29 «خروجی آخرین دستور»: پیش از آخرین دستور لینوکس یک نشانه چاپ می‌شود تا خروجی همان دستور جدا شود."""
    lines = body.replace("\r\n", "\n").split("\n")
    k = next((i for i in range(len(lines) - 1, -1, -1) if lines[i].strip() and not lines[i].strip().startswith("#")), None)
    if k is None:
        raise SshError("اسکریپت خالی است")
    last = lines[k].strip()
    if last in _BLOCK_END or last.endswith("\\") or (k and lines[k - 1].rstrip().endswith("\\")):
        raise SshError("برای «خروجی آخرین دستور به‌صورت CSV» آخرین خط اسکریپت باید یک دستور کامل باشد (مثلاً cat /tmp/out.csv)")
    return "\n".join(lines[:k] + [f"echo '{LAST_MARK}'"] + lines[k:])


def split_last(text):
    i = text.rfind(LAST_MARK)
    return text[i + len(LAST_MARK):].lstrip("\r\n") if i >= 0 else ""


def run_linux(dev, creds, body, use_sudo, timeout, known_hosts, cancel, on_client=None, attempt=None):
    cli = paramiko.SSHClient()
    if isinstance(known_hosts, HostKeys):
        known_hosts.load_into(cli, dev["host"], int(dev.get("port") or 22))
    else:
        cli.load_host_keys(str(known_hosts))
    cli.set_missing_host_key_policy(paramiko.RejectPolicy())
    try:
        sock = attempt.connect(dev["host"], int(dev.get("port") or 22), 15) if attempt else None
        cli.connect(dev["host"], port=int(dev.get("port") or 22), username=creds["username"], password=creds["password"],
                    timeout=15, banner_timeout=15, auth_timeout=20, look_for_keys=False, allow_agent=False,
                    disabled_algorithms=algorithms(dev), sock=sock)
        if on_client:
            on_client(cli)
        log_lines = []
        if use_sudo:
            # اول بدون رمز امتحان می‌شود (NOPASSWD)؛ وگرنه رمز فقط از stdin داده می‌شود و هیچ‌جا چاپ نمی‌شود
            _i, o, _e = cli.exec_command("sudo -n true", timeout=20)  # nosec B601 — اجرای اسکریپتی که خود کاربر برای دستگاه خودش نوشته، هدف همین ابزار است
            nopass = o.channel.recv_exit_status() == 0
            if nopass:
                cmd, prefix = "sudo -n bash -s", b""
            else:
                pw = creds.get("secret") or creds["password"]
                cmd, prefix = "sudo -S -p '' bash -s", (pw + "\n").encode()
            log_lines.append(f"[sudo {'بدون رمز' if nopass else 'با رمز'}]")
        else:
            cmd, prefix = "bash -s", b""
        chan = cli.get_transport().open_session()
        chan.exec_command(cmd)  # nosec B601 — اجرای اسکریپتی که خود کاربر برای دستگاه خودش نوشته، هدف همین ابزار است
        chan.sendall(prefix + body.replace("\r\n", "\n").encode("utf-8") + b"\n")
        chan.shutdown_write()
        out, code = _read_channel(chan, cancel, timeout)
        text = ("\n".join(log_lines) + "\n" if log_lines else "") + out.decode("utf-8", "replace")
        if code not in (0, None):
            return False, text, f"کد خروج {code}"
        return True, text, "کد خروج 0"
    finally:
        cli.close()


def run_netmiko(dev, creds, body, mode, save_config, timeout, known_hosts, cancel, on_client=None, raw=False, attempt=None,
                last_out=None):
    from netmiko import ConnectHandler
    lines = [l.rstrip() for l in body.replace("\r\n", "\n").split("\n") if l.strip() and not l.strip().startswith("!#")]
    if dev.get("protocol") == "telnet":
        if dev["device_type"] not in TELNET_TYPES:
            raise SshError("Telnet برای این نوع دستگاه پشتیبانی نمی‌شود")
        conn = ConnectHandler(device_type=dev["device_type"] + "_telnet", host=dev["host"], port=int(dev.get("port") or 23),
                              username=creds["username"], password=creds["password"], secret=creds.get("secret") or "",
                              conn_timeout=15, auth_timeout=20, timeout=timeout, fast_cli=False)
        return _netmiko_session(conn, dev, lines, mode, save_config, timeout, cancel, on_client, raw, last_out)
    params = dict(device_type=dev["device_type"], host=dev["host"], port=int(dev.get("port") or 22),
                  username=creds["username"], password=creds["password"], secret=creds.get("secret") or "",
                  conn_timeout=15, auth_timeout=20, banner_timeout=15, timeout=timeout, fast_cli=False,
                  use_keys=False, allow_agent=False, ssh_strict=True, system_host_keys=False,
                  alt_host_keys=True, disabled_algorithms=algorithms(dev))
    with (known_hosts.temp(dev["host"], int(dev.get("port") or 22)) if isinstance(known_hosts, HostKeys)
          else contextlib.nullcontext(str(known_hosts))) as kf:
        if attempt:
            params["sock"] = attempt.connect(dev["host"], int(dev.get("port") or 22), 15)
        conn = ConnectHandler(**params, alt_key_file=kf)
    return _netmiko_session(conn, dev, lines, mode, save_config, timeout, cancel, on_client, raw, last_out)


def _netmiko_session(conn, dev, lines, mode, save_config, timeout, cancel, on_client, raw, last_out):
    try:
        if on_client:
            on_client(conn)
        out = []
        if dev.get("use_enable"):
            conn.enable()
            out.append(f"[enable] {conn.find_prompt()}")
        if mode == "config":
            if cancel.is_set():
                raise SshError("متوقف شد")
            out.append(conn.send_config_set(lines, read_timeout=timeout))
        else:
            for line in lines:
                if cancel.is_set():
                    raise SshError("متوقف شد")
                res = conn.send_command(line, read_timeout=timeout)
                if raw:   # پشتیبان کانفیگ: فقط خروجی خام دستور
                    return True, res, "ok"
                if last_out is not None:      # 1.29: خروجی آخرین دستور برای CSV
                    last_out[:] = [res]
                out.append(f"{conn.find_prompt()}{line}\n{res}")
        if save_config:
            out.append("[save] " + conn.save_config())
        text = "\n".join(out)
        bad = [m for m in ("% Invalid input", "% Incomplete command", "% Ambiguous command", "% Unknown command",
                           "syntax error") if m in text]
        if bad:
            return False, text, "دستگاه خطا برگرداند: " + bad[0]
        return True, text, f"{len(lines)} خط اجرا شد"
    finally:
        conn.disconnect()


def friendly(e):
    name = e.__class__.__name__
    if isinstance(e, (SshError, Aborted)):
        return str(e)
    msg = str(e).lower()
    if "IncompatiblePeer" in name or "no acceptable" in msg or "incompatible ssh" in msg:
        return ("دستگاه فقط الگوریتم‌های قدیمی SSH را پشتیبانی می‌کند؛ در تنظیمات همین دستگاه "
                "«سازگاری با دستگاه قدیمی» را روشن کنید (یا SSH دستگاه را به‌روز کنید)")
    if isinstance(e, paramiko.BadHostKeyException) or "does not match" in msg or "not found in known_hosts" in msg \
            or ("host key" in msg and "ssh" in msg):
        return "کلید میزبان با کلید ثبت‌شده یکی نیست؛ اتصال قبل از ارسال پسورد قطع شد"
    if isinstance(e, paramiko.AuthenticationException) or "Authentication" in name:
        return "احراز هویت رد شد؛ یوزر یا پسورد را بررسی کنید"
    if isinstance(e, (socket.timeout, TimeoutError)) or "Timeout" in name:
        return "اتصال یا پاسخ در زمان مقرر برقرار نشد (timeout)"
    if isinstance(e, (ConnectionRefusedError, OSError)) and "refused" in str(e).lower():
        return "اتصال رد شد؛ پورت یا سرویس SSH را بررسی کنید"
    if isinstance(e, socket.gaierror):
        return "نام میزبان پیدا نشد"
    if "enable" in str(e).lower() or "privilege" in str(e).lower():
        return f"ورود به حالت enable ناموفق بود: {e}"
    return f"{name}: {str(e)[:300]}"


# ------------------------------------------------------------------ runner
class SshRunner:
    def __init__(self, settings, store, vault, emit=None, backups=None, notify=None):
        self.backups = backups
        self.notify = notify or (lambda *a, **k: None)
        self.settings = settings
        self.store = store
        self.vault = vault
        self.hostkeys = HostKeys()
        self._emit = emit or (lambda *a, **k: None)
        self.current = None
        self._lock = threading.Lock()

    def creds(self, dev_id):
        """اعتبارنامه‌ی دستگاه: از پروفایل (اگر دستگاه به پروفایل وصل است) وگرنه اختصاصی خود دستگاه."""
        d = self.store.ssh_device(int(dev_id)) if self.store is not None else None
        pfx = cred_prefix(d) if d else f"ssh.{int(dev_id)}."
        return {"username": self.vault.get(pfx + "username", ""), "password": self.vault.get(pfx + "password", ""),
                "secret": self.vault.get(pfx + "secret", "")}

    def start(self, device_ids, script, options, kind="run"):
        """script: {name, body, mode, use_sudo, save_config} ؛ options: {concurrency, timeout, dry_run}"""
        with self._lock:
            if self.current and self.current["status"] == "running":
                raise SshError("یک اجرای SSH در جریان است.")
            if not self.vault.unlocked():
                raise SshError("برنامه قفل است. ابتدا رمز اصلی را وارد کنید.")
            devs = [d for d in (self.store.ssh_device(i) for i in device_ids) if d]
            if not devs:
                raise SshError("هیچ دستگاهی انتخاب نشده است.")
            if kind == "run" and not (script.get("body") or "").strip():
                raise SshError("متن اسکریپت خالی است.")
            job = {"id": time.strftime("%Y%m%d_%H%M%S") + "_" + uuid.uuid4().hex[:4], "started": time.time(),
                   "finished": None, "script_name": script.get("name") or {"test": "تست اتصال", "backup": "پشتیبان‌گیری کانفیگ"}.get(kind, "بدون نام"),
                   "status": "running", "total": len(devs), "ok": 0, "failed": 0, "dry": bool(options.get("dry_run")),
                   "kind": kind, "results": {}, "cancel": threading.Event(), "clients": {}, "attempts": {}, "changed": []}
            for d in devs:
                job["results"][d["id"]] = {"device_id": d["id"], "name": d.get("name") or d["host"], "host": d["host"],
                                           "device_type": d["device_type"], "status": "pending", "message": ""}
            self.current = job
            self.store.ssh_save_job(job)
        threading.Thread(target=self._run, args=(job, devs, script, options), daemon=True, name="ssh-job").start()
        return job

    def cancel(self):
        job = self.current
        if job and job["status"] == "running":
            job["cancel"].set()
            for a in list(job["attempts"].values()):    # اتصال‌های در حال برقراری فوراً قطع شوند
                a.cancel()
            for c in list(job["clients"].values()):
                try:
                    c.disconnect() if hasattr(c, "disconnect") else c.close()
                except Exception:
                    pass
            return True
        return False

    def public(self, job=None):
        job = job or self.current
        if not job:
            return None
        return {k: v for k, v in job.items() if k not in ("cancel", "clients", "attempts")} | {"results": list(job["results"].values())}

    def _run(self, job, devs, script, options):
        conc = max(1, min(20, int(options.get("concurrency") or 5)))
        timeout = max(5, min(3600, int(options.get("timeout") or 60)))
        out_dir = paths.data_dir() / "ssh_runs" / job["id"]
        out_dir.mkdir(parents=True, exist_ok=True)
        self._emit("info", f"SSH: «{job['script_name']}» روی {len(devs)} دستگاه شروع شد"
                           + (" (پیش‌نمایش، بدون اتصال)" if job["dry"] else ""), "ssh")
        with ThreadPoolExecutor(max_workers=conc) as ex:
            for d in devs:
                ex.submit(self._one, job, d, script, timeout, out_dir)
        job["finished"] = time.time()
        job["status"] = "cancelled" if job["cancel"].is_set() else "done"
        self.store.ssh_save_job(job)
        lvl = "ok" if not job["failed"] else "warn"
        self._emit(lvl, f"SSH: پایان — {job['ok']} موفق، {job['failed']} ناموفق از {job['total']}", "ssh")
        failed = [r for r in job["results"].values() if r["status"] == "failed"]
        if failed and not job["dry"] and job["kind"] in ("run", "backup"):
            text = "\n".join(f"- {r['name']} ({r['host']}): {r.get('message', '')}" for r in failed)
            self.notify("backup_failed" if job["kind"] == "backup" else "ssh_failed",
                        f"«{job['script_name']}»: {len(failed)} از {job['total']} دستگاه ناموفق\n{text}")
        if job["changed"]:
            text = "\n".join(f"- {n} ({h}): +{a} / −{d}" for n, h, a, d in job["changed"])
            self._emit("warn", f"پشتیبان کانفیگ: {len(job['changed'])} دستگاه تغییر کرده است", "backup")
            self.notify("config_changed", f"کانفیگ {len(job['changed'])} دستگاه تغییر کرده است:\n{text}")

    def _one(self, job, dev, script, timeout, out_dir):
        r = job["results"][dev["id"]]
        if job["cancel"].is_set():
            r.update(status="skipped", message="به‌خاطر توقف اجرا نشد")
            self.store.ssh_save_result(job["id"], r)
            return
        r.update(status="running", started=time.time())
        text, ok, msg = "", False, ""
        last_text = None
        body = render(script.get("body") or "", {**dev, "username": self.vault.get(cred_prefix(dev) + "username", "")})
        try:
            if job["dry"]:
                ok, msg = True, "پیش‌نمایش: متصل نشد"
                text = f"# دستگاه: {r['name']} ({dev['host']}:{dev.get('port') or 22}) — {TYPE_NAMES.get(dev['device_type'], dev['device_type'])}\n" \
                       f"# حالت: {'config' if script.get('mode') == 'config' else 'exec'}" \
                       f"{' + sudo' if script.get('use_sudo') and dev['device_type'] == 'linux' else ''}" \
                       f"{' + enable' if dev.get('use_enable') and dev['device_type'] != 'linux' else ''}\n\n{body}"
            else:
                creds = self.creds(dev["id"])
                if not creds["username"] or not creds["password"]:
                    raise SshError("یوزر یا پسورد این دستگاه ذخیره نشده است")
                att = job["attempts"][dev["id"]] = Attempt()
                if job["cancel"].is_set():
                    att.cancel()
                if dev.get("protocol") == "telnet":
                    state, fp, old = "telnet", "", ""        # Telnet کلید میزبان ندارد
                else:
                    state, fp, old = self.hostkeys.check(dev["host"], dev.get("port") or 22, legacy=bool(dev.get("legacy")),
                                                         attempt=att)
                if state == "mismatch":
                    raise SshError(f"کلید میزبان عوض شده است! ثبت‌شده: {old} — فعلی: {fp}. "
                                   "اگر تغییر را تأیید می‌کنید از «کلیدهای میزبان» کلید قبلی را حذف کنید.")
                if state == "new":
                    self._emit("warn", f"SSH: کلید میزبان {dev['host']} برای اولین بار ثبت شد ({fp})", "ssh")
                keep = lambda c: job["clients"].__setitem__(dev["id"], c)
                if job["kind"] == "test":
                    body = TEST_COMMANDS.get(dev["device_type"], "")
                if job["kind"] == "backup":
                    bcfg = self.settings.get("backup") or {}
                    body = ((bcfg.get("commands") or {}).get(dev["device_type"]) or "").strip()
                    if not body:
                        raise SshError("دستور پشتیبان برای این نوع دستگاه تعریف نشده است")
                    btimeout = max(30, int(bcfg.get("timeout") or 180))
                    if dev["device_type"] == "linux":
                        ok, text, msg = run_linux(dev, creds, body, bool(dev.get("use_enable")), btimeout,
                                                  self.hostkeys, job["cancel"], keep, attempt=att)
                    else:
                        ok, text, msg = run_netmiko(dev, creds, body, "exec", False, btimeout, self.hostkeys,
                                                    job["cancel"], keep, raw=True, attempt=att)
                    if not ok:
                        raise SshError(msg)
                    res = self.backups.record(dev, text, job["id"])
                    msg = {"first": f"اولین نسخه ذخیره شد ({res.get('id')})", "unchanged": "بدون تغییر",
                           "changed": f"تغییر کرد: +{res['added']} / −{res['removed']} خط"}[res["state"]]
                    if res["state"] == "changed":
                        job["changed"].append((r["name"], dev["host"], res["added"], res["removed"]))
                    text = ""   # نسخه در پشتیبان‌ها ذخیره شد؛ خروجی تکراری نگه داشته نمی‌شود
                elif dev["device_type"] == "linux":
                    lastcsv = bool(script.get("last_csv")) and job["kind"] != "test"
                    ok, text, msg = run_linux(dev, creds, mark_last(body) if lastcsv else body,
                                              bool(script.get("use_sudo")) and job["kind"] != "test",
                                              timeout, self.hostkeys, job["cancel"], keep, attempt=att)
                    if lastcsv:
                        last_text = split_last(text)
                        text = text.replace(LAST_MARK + "\n", "").replace(LAST_MARK, "")
                else:
                    lastcsv = bool(script.get("last_csv")) and job["kind"] != "test"
                    if lastcsv and (script.get("mode") or "exec") == "config":
                        raise SshError("«خروجی آخرین دستور به‌صورت CSV» فقط در حالت exec ممکن است")
                    lo = [] if lastcsv else None
                    ok, text, msg = run_netmiko(dev, creds, body, "exec" if job["kind"] == "test" else script.get("mode") or "exec",
                                                bool(script.get("save_config")) and job["kind"] != "test",
                                                timeout, self.hostkeys, job["cancel"], keep, attempt=att, last_out=lo)
                    if lastcsv:
                        last_text = lo[0] if lo else ""
                if job["kind"] == "test" and ok:
                    msg = (text.strip().splitlines() or ["متصل شد"])[-1][:200]
        except Exception as e:
            ok, msg = False, friendly(e)
            text = text or msg
            log.info("ssh %s: %s", dev["host"], e)
        finally:
            job["clients"].pop(dev["id"], None)
            job["attempts"].pop(dev["id"], None)
        if job["cancel"].is_set() and not ok:
            r["status"] = "cancelled"
        else:
            r["status"] = "ok" if ok else "failed"
        r.update(message=msg, finished=time.time())
        if text:
            f = out_dir / f"{dev['id']}.bin"
            f.write_bytes(self.vault.encrypt_bytes(text.encode("utf-8")))
            r["out_file"] = str(f)
        if last_text is not None and ok:
            f = out_dir / f"{dev['id']}.last.bin"
            f.write_bytes(self.vault.encrypt_bytes(last_text.encode("utf-8")))
            r["last_file"] = str(f)
        with self._lock:
            job["ok" if r["status"] == "ok" else "failed"] += 1 if r["status"] in ("ok", "failed") else 0
        self.store.ssh_save_result(job["id"], r)
        if job["kind"] == "backup" and not job["dry"]:
            self.store.ssh_set_backup_status(dev["id"], r["status"], msg)
        if not job["dry"]:
            self.store.ssh_set_status(dev["id"], r["status"], msg)
            self.store.add_stat("ssh", "ok" if r["status"] == "ok" else "failed", dev["host"], src=job["kind"])
            self.store.add_history("ssh", f"{r['name']} ({dev['host']})", "ok" if r["status"] == "ok" else "error",
                                   f"{job['script_name']}: {msg}", job["id"], str(out_dir))

    def last_output(self, job_id, dev_id):
        base = (paths.data_dir() / "ssh_runs").resolve()
        f = (base / job_id / f"{int(dev_id)}.last.bin").resolve()
        if base not in f.parents or not f.is_file():
            return None
        return self.vault.decrypt_bytes(f.read_bytes()).decode("utf-8", "replace")

    def output(self, job_id, dev_id):
        base = (paths.data_dir() / "ssh_runs").resolve()
        f = (base / job_id / f"{int(dev_id)}.bin").resolve()
        if base not in f.parents or not f.is_file():
            raise SshError("خروجی پیدا نشد.")
        return self.vault.decrypt_bytes(f.read_bytes()).decode("utf-8", "replace")
