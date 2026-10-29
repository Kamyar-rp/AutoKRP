"""
به‌روزرسانی آفلاین امضاهای FortiGate (۷.۲) از TFTP با SSH.

ترتیب (همان اسکریپت کاربر):
  [config global → diagnose autoupdate versions → end]        ← نسخه‌ها قبل
  config vdom → edit <vdom>                                     ← فقط در حالت چند-VDOM
  execute restore <نوع> tftp <فایل> <dest_ip>  →  (y/n) → y     ← هر پکیج جدا؛ تا prompt برنگشته دستور بعد زده نمی‌شود
  end
  [config global → diagnose autoupdate versions → end]        ← نسخه‌ها بعد
تشخیص نتیجه از متن خروجی دستگاه:
  موفق:  «Get … from tftp server OK.»
  ناموفق: «Error code …» / «Can not get …» / «Failed to restore …» / «Command fail. Return code …»
اگر یک پکیج ناموفق شود، بقیه انجام می‌شوند و خطا گزارش می‌شود.
"""
import logging
import re
import socket
import threading
import time
import uuid

from . import paths
from .ssh import SshError, algorithms, friendly
from .tftp import TftpServer, local_ip_for

log = logging.getLogger(__name__)

# (نوع، فایل، عنوان) — به ترتیب اسکریپت کاربر
PACKAGES = [
    ("ips", "IPS.pkg", "IPS"),
    ("av", "Antivirus.pkg", "Antivirus"),
    ("ips", "Application-Control.pkg", "Application Control"),
    ("av", "AVAI.pkg", "AV AI"),
    ("av", "Mobile-Malware.pkg", "Mobile Malware"),
    ("other-objects", "Internet-Service.pkg", "Internet Service DB"),
    ("ips", "Industrial-DB.pkg", "Industrial DB"),
    ("av", "Botnet-Domain.pkg", "Botnet Domain"),
    ("ips", "IOT.pkg", "IoT"),
    ("av", "MCDB.pkg", "MCDB"),
]
PKG_BY_FILE = {p[1]: p for p in PACKAGES}
OK_RE = re.compile(r"from tftp server OK", re.I)
FAIL_RE = re.compile(r"Error code\s*\d+.*|Can not get .*|Failed to restore .*|Command fail\..*|Return code\s*-?\d+", re.I)


def parse_versions(text):
    """
    خروجی diagnose autoupdate versions:
        AV Engine
        ---------
        Version: 6.00303 signed
        Last Updated using manual update on Tue Jan 14 18:23:00 2025
        Result: ...
    → {عنوان: {"version", "updated", "result"}}
    """
    out, lines = {}, [l.rstrip() for l in (text or "").replace("\r", "").split("\n")]
    for i in range(len(lines) - 1):
        if lines[i].strip() and re.fullmatch(r"-{3,}", lines[i + 1].strip()):
            title = lines[i].strip()
            info = {"version": "", "updated": "", "result": ""}
            for l in lines[i + 2:]:
                if not l.strip():
                    if info["version"]:
                        break
                    continue
                if re.fullmatch(r"-{3,}", l.strip()):
                    break
                m = re.match(r"\s*Version\s*:\s*(.+)", l)
                if m:
                    info["version"] = m.group(1).strip()
                m = re.match(r"\s*Last Updated using (.+)", l)
                if m:
                    info["updated"] = m.group(1).strip()
                m = re.match(r"\s*Result\s*:\s*(.+)", l)
                if m:
                    info["result"] = m.group(1).strip()
            out[title] = info
    return out


def judge(output):
    """('ok'|'failed'|'unknown', پیام)"""
    fails = [m.group(0).strip() for m in FAIL_RE.finditer(output or "")]
    if fails:
        return "failed", " | ".join(dict.fromkeys(fails))[:300]
    if OK_RE.search(output or ""):
        line = next((l.strip() for l in output.splitlines() if OK_RE.search(l)), "OK")
        return "ok", line
    return "unknown", "نتیجه از خروجی دستگاه مشخص نشد"


class FgUpdater:
    def __init__(self, settings, store, vault, ssh_runner, emit=None, notify=None):
        self.settings = settings
        self.store = store
        self.vault = vault
        self.ssh = ssh_runner
        self._emit = emit or (lambda *a, **k: None)
        self.notify = notify or (lambda *a, **k: None)
        self.current = None
        self._lock = threading.Lock()

    # ---------------------------------------------------------------- API
    def start(self, device_ids, opts):
        with self._lock:
            if self.current and self.current["status"] == "running":
                raise SshError("یک به‌روزرسانی FortiGate در جریان است.")
            if self.ssh.current and self.ssh.current.get("status") == "running":
                raise SshError("یک اجرای SSH در جریان است؛ صبر کنید تمام شود.")
            if not self.vault.unlocked():
                raise SshError("برنامه قفل است.")
            devs = [d for d in (self.store.ssh_device(int(i)) for i in device_ids) if d]
            if not devs:
                raise SshError("هیچ FortiGateی انتخاب نشده است.")
            bad = [d["name"] or d["host"] for d in devs if d["device_type"] != "fortinet"]
            if bad:
                raise SshError("این دستگاه‌ها از نوع FortiGate نیستند: " + "، ".join(bad))
            pkgs = [f for f in opts.get("packages") or [] if f in PKG_BY_FILE]
            pkgs = [p[1] for p in PACKAGES if p[1] in pkgs]   # ترتیب ثابت اسکریپت
            if not pkgs:
                raise SshError("هیچ پکیجی انتخاب نشده است.")
            src = opts.get("source") or "local"
            if src == "local":
                folder = (opts.get("folder") or "").strip().strip('"')
                missing = check_folder(folder, pkgs)["missing"]
                if missing:
                    raise SshError("این فایل‌ها در پوشه نیستند: " + "، ".join(missing))
            else:
                if not (opts.get("tftp_ip") or "").strip():
                    raise SshError("آدرس سرور TFTP وارد نشده است.")
            job = {"id": time.strftime("%Y%m%d_%H%M%S") + "_" + uuid.uuid4().hex[:4], "kind": "fgupdate",
                   "started": time.time(), "finished": None, "status": "running", "opts": {**opts, "packages": pkgs},
                   "devices": [{"id": d["id"], "name": d["name"] or d["host"], "host": d["host"], "status": "pending",
                                "message": "", "dest_ip": "", "packages": [{"file": f, "title": PKG_BY_FILE[f][2], "status": "pending",
                                                                            "message": "", "secs": None} for f in pkgs],
                                "before": {}, "after": {}, "out_file": ""} for d in devs],
                   "tftp": [], "cancel": threading.Event()}
            self.current = job
        threading.Thread(target=self._run, args=(job, devs), daemon=True, name="fgupdate").start()
        return job

    def cancel(self):
        j = self.current
        if j and j["status"] == "running":
            j["cancel"].set()
            return True
        return False

    def public(self):
        j = self.current
        if not j:
            return None
        return {k: v for k, v in j.items() if k != "cancel" and not k.startswith("_")}

    TFTP_KEEP = 300

    def _tftp_event(self, job, lvl, msg):
        """1.26.2: رخدادهای TFTP با سقف (بسته‌های ردشده‌ی جعلی فهرست و حافظه را بی‌نهایت بزرگ نکنند)؛
        هر پیام هشدار یکسان حداکثر یک بار در دقیقه به رخدادهای برنامه می‌رود."""
        ev = job["tftp"]
        ev.append({"ts": time.time(), "level": lvl, "msg": msg})
        if len(ev) > self.TFTP_KEEP:
            del ev[:len(ev) - self.TFTP_KEEP]
        if lvl == "warn":
            seen = job.setdefault("_tftp_warned", {})
            now = time.time()
            if now - seen.get(msg, 0) < 60:
                return
            if len(seen) > 1000:
                seen.clear()
            seen[msg] = now
        self._emit(lvl, msg, "fgupdate")

    # ---------------------------------------------------------------- run
    def _run(self, job, devs):
        o = job["opts"]
        server = None
        out_dir = paths.data_dir() / "ssh_runs" / job["id"]
        out_dir.mkdir(parents=True, exist_ok=True)
        self._emit("info", f"به‌روزرسانی FortiGate روی {len(devs)} دستگاه شروع شد ({len(o['packages'])} پکیج)", "fgupdate")
        try:
            if o.get("source", "local") == "local":
                allowed = set()
                for d in devs:                  # دستگاهی که با نام تعریف شده: IPهایش هم مجاز است
                    allowed.add(d["host"])
                    try:
                        allowed.update(ai[4][0] for ai in socket.getaddrinfo(d["host"], None))
                    except OSError:
                        pass
                server = TftpServer(o["folder"], port=int(o.get("tftp_port") or 69), allowed=allowed,
                                    on_event=lambda lvl, msg: self._tftp_event(job, lvl, msg))
                server.start()
            for dev, rec in zip(devs, job["devices"]):
                if job["cancel"].is_set():
                    rec["status"], rec["message"] = "cancelled", "به‌خاطر توقف اجرا نشد"
                    continue
                self._one(job, dev, rec, out_dir)
        except Exception as e:
            log.exception("fgupdate")
            self._emit("error", f"به‌روزرسانی FortiGate: {friendly(e) if not isinstance(e, OSError) else e}", "fgupdate")
            for rec in job["devices"]:
                if rec["status"] in ("pending", "running"):
                    rec["status"], rec["message"] = "failed", str(e)[:300]
        finally:
            if server:
                server.stop()
            job["finished"] = time.time()
            job["status"] = "cancelled" if job["cancel"].is_set() else "done"
            ok = sum(1 for p in (x for r in job["devices"] for x in r["packages"]) if p["status"] == "ok")
            bad = [(r, p) for r in job["devices"] for p in r["packages"] if p["status"] in ("failed", "unknown")]
            self._emit("ok" if not bad else "warn", f"به‌روزرسانی FortiGate تمام شد: {ok} پکیج موفق، {len(bad)} ناموفق", "fgupdate")
            if bad:
                self.notify("ssh_failed", "به‌روزرسانی FortiGate: پکیج‌های ناموفق\n" +
                            "\n".join(f"- {r['name']}: {p['file']} — {p['message']}" for r, p in bad[:40]))

    @staticmethod
    def _prompt_re(conn):
        """prompt با عوض شدن VDOM عوض می‌شود: «FGT (root) #» ← «FGT (global) #»؛ فقط نام دستگاه ثابت است."""
        host = conn.base_prompt.split("(")[0].strip() or conn.base_prompt
        return re.escape(host) + r"[^\n]*[#$]\s*$"

    def _send(self, conn, cmd, transcript, expect=None, timeout=60):
        pattern = expect or self._prompt_re(conn)
        out = conn.send_command(cmd, expect_string=pattern, read_timeout=timeout, strip_prompt=False, strip_command=False,
                                cmd_verify=False)
        transcript.append(out)
        return out

    def _versions(self, conn, multi, transcript):
        if multi:
            self._send(conn, "config global", transcript)
        out = self._send(conn, "diagnose autoupdate versions", transcript, timeout=120)
        if multi:
            self._send(conn, "end", transcript)
        return parse_versions(out)

    def _one(self, job, dev, rec, out_dir):
        from netmiko import ConnectHandler
        o = job["opts"]
        rec["status"] = "running"
        transcript = []
        multi = bool(o.get("multi_vdom", True))
        vdom = (o.get("vdom") or "root").strip() or "root"
        delay = max(0.0, float(o.get("delay") or 5))
        timeout = max(30, int(o.get("timeout") or 600))
        try:
            creds = self.ssh.creds(dev["id"])
            if not creds["username"] or not creds["password"]:
                raise SshError("یوزر یا پسورد این دستگاه ذخیره نشده است")
            state, fp, old = self.ssh.hostkeys.check(dev["host"], dev.get("port") or 22, legacy=bool(dev.get("legacy")))
            if state == "mismatch":
                raise SshError(f"کلید میزبان عوض شده است! ثبت‌شده: {old} — فعلی: {fp}")
            dest = (o.get("tftp_ip") or "").strip() if o.get("source") == "remote" else local_ip_for(dev["host"], dev.get("port") or 22)
            rec["dest_ip"] = dest
            with self.ssh.hostkeys.temp(dev["host"], int(dev.get("port") or 22)) as kf:
                conn = ConnectHandler(device_type="fortinet", host=dev["host"], port=int(dev.get("port") or 22),
                                      username=creds["username"], password=creds["password"], conn_timeout=15, auth_timeout=20,
                                      banner_timeout=15, timeout=timeout, fast_cli=False, use_keys=False, allow_agent=False,
                                      ssh_strict=True, system_host_keys=False, alt_host_keys=True, alt_key_file=kf,
                                      disabled_algorithms=algorithms(dev))
            try:
                rec["before"] = self._versions(conn, multi, transcript)
                if multi:
                    self._send(conn, "config vdom", transcript)
                    self._send(conn, f"edit {vdom}", transcript)
                for p in rec["packages"]:
                    if job["cancel"].is_set():
                        p["status"], p["message"] = "cancelled", "متوقف شد"
                        continue
                    kind = PKG_BY_FILE[p["file"]][0]
                    cmd = f"execute restore {kind} tftp {p['file']} {dest}"
                    p["status"] = "running"
                    t0 = time.time()
                    try:
                        first = self._send(conn, cmd, transcript, expect=r"\(y/n\)|" + self._prompt_re(conn))
                        out = first
                        if "(y/n)" in first:
                            out += self._send(conn, "y", transcript, timeout=timeout)
                        p["status"], p["message"] = judge(out)
                    except Exception as e:
                        p["status"], p["message"] = "failed", friendly(e)
                        transcript.append(f"\n[AutoKRP] خطا در {p['file']}: {e}\n")
                        # اگر اتصال سالم است ادامه بده؛ وگرنه بقیه‌ی پکیج‌ها را ناموفق علامت بزن
                        if not _alive(conn):
                            for q in rec["packages"]:
                                if q["status"] == "pending":
                                    q["status"], q["message"] = "failed", "اتصال قطع شد"
                            break
                    p["secs"] = round(time.time() - t0, 1)
                    lvl = {"ok": "ok", "failed": "error"}.get(p["status"], "warn")
                    self._emit(lvl, f"{rec['name']}: {p['file']} — {p['message']}", "fgupdate")
                    self.store.add_history("fgupdate", f"{rec['name']} — {p['file']}", "ok" if p["status"] == "ok" else "error",
                                           p["message"], job["id"], str(out_dir))
                    if delay and p is not rec["packages"][-1]:
                        job["cancel"].wait(delay)
                if multi and _alive(conn):
                    self._send(conn, "end", transcript)
                if _alive(conn):
                    rec["after"] = self._versions(conn, multi, transcript)
            finally:
                try:
                    conn.disconnect()
                except Exception:
                    pass
            fails = sum(1 for p in rec["packages"] if p["status"] != "ok")
            rec["status"] = "ok" if not fails else "failed"
            rec["message"] = "همه‌ی پکیج‌ها موفق" if not fails else f"{fails} پکیج ناموفق"
        except Exception as e:
            rec["status"], rec["message"] = "failed", friendly(e)
            for p in rec["packages"]:
                if p["status"] in ("pending", "running"):
                    p["status"], p["message"] = "failed", "اجرا نشد: " + rec["message"]
            self._emit("error", f"{rec['name']}: {rec['message']}", "fgupdate")
        finally:
            if transcript:
                f = out_dir / f"{dev['id']}.bin"
                f.write_bytes(self.vault.encrypt_bytes("\n".join(transcript).encode("utf-8")))
                rec["out_file"] = str(f)
            self.store.add_stat("ssh", "ok" if rec["status"] == "ok" else "failed", dev["host"], src="fgupdate")


def _alive(conn):
    """
    وضعیت اتصال بدون ارسال چیزی به دستگاه. (is_alive() در netmiko یک کاراکتر NUL می‌فرستد که
    جلوی دستور بعدی می‌نشیند و آن را خراب می‌کند — مثلاً «\x00end».)
    """
    try:
        t = conn.remote_conn.get_transport() if conn.remote_conn else None
        return bool(t and t.is_active())
    except Exception:
        return False


def check_folder(folder, pkgs):
    from pathlib import Path
    p = Path(folder or "")
    if not folder or not p.is_dir():
        return {"exists": False, "missing": list(pkgs), "files": {}}
    files = {f: (p / f).stat().st_size for f in pkgs if (p / f).is_file()}
    return {"exists": True, "missing": [f for f in pkgs if f not in files], "files": files}
