"""1.58: پشتیبان پوشه‌ی سرور لینوکس.

هر «کار پشتیبان پوشه»: یک دستگاه لینوکس مشترک، یک یا چند مسیر، الگوهای استثنا، sudo اختیاری، پوشه‌ی مقصد، نگه داشتن N نسخه.
روش: روی سرور `tar -cz` اجرا و خروجی مستقیم (بدون فایل موقت روی سرور) از SSH به فایل محلی جریان می‌یابد.
- فقط یک مسیر و آن مسیر یک فایل است (مثلاً خودش یک .tar.gz): همان فایل بدون tar دوباره و با همان پسوند ذخیره می‌شود.
- tar روی سرور نیست (کد 127) و sudo خاموش است: SFTP فایل‌به‌فایل و ساخت tar.gz در همین برنامه.
فایل مقصد: <پوشه>/<دستگاه>/<کار>_YYYY-MM-DD_HHMM.tar.gz (فشرده، رمزنگاری‌نشده؛ انتخاب کاربر).
"""
import fnmatch
import logging
import os
import posixpath
import re
import shlex
import stat as stmod
import tarfile
import threading
import time
import zlib
from datetime import datetime
from pathlib import Path

from .term import TermError, check_hostkey, ssh_connect

log = logging.getLogger(__name__)
IDLE_TIMEOUT = 300          # بدون هیچ داده‌ای از سرور (نه خروجی، نه پیام) ← قطع
MAX_RUNS = 20
MAX_PATHS = 20
STAMP = "%Y-%m-%d_%H%M"


class FbError(Exception):
    pass


def slug(s):
    s = re.sub(r"[^\w.-]+", "_", str(s or "").strip(), flags=re.UNICODE).strip("._")
    return s[:60] or "backup"


def clean_paths(paths):
    out = []
    for p in paths or []:
        p = str(p or "").strip()
        if not p:
            continue
        if not p.startswith("/"):
            raise FbError(f"مسیر باید کامل باشد (با / شروع شود): {p}")
        if "\x00" in p or "\n" in p:
            raise FbError("مسیر نامعتبر است.")
        p = posixpath.normpath(p)
        if p == "/":
            raise FbError("پشتیبان از کل ریشه‌ی «/» مجاز نیست؛ پوشه‌های لازم را جدا بنویسید.")
        if p not in out:
            out.append(p)
    if not out:
        raise FbError("حداقل یک مسیر وارد کنید.")
    if len(out) > MAX_PATHS:
        raise FbError(f"حداکثر {MAX_PATHS} مسیر در هر کار.")
    return out


def clean_excludes(ex):
    out = []
    for x in ex or []:
        x = str(x or "").strip()
        if x and "\n" not in x and "\x00" not in x and x not in out:
            out.append(x[:200])
    return out[:50]


def human(n):
    n = float(n or 0)
    for u in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or u == "TB":
            return f"{n:.0f} {u}" if u == "B" else f"{n:.1f} {u}"
        n /= 1024
    return str(n)


class _Cancel(Exception):
    pass


class FolderBackup:
    def __init__(self, settings, store, ssh, hostkeys, emit=None):
        self.settings, self.store, self.ssh, self.hostkeys = settings, store, ssh, hostkeys
        self.emit = emit or (lambda *a, **k: None)
        self.running = {}           # job_id -> {"started", "bytes", "files", "cancel": Event, "by"}
        self._lock = threading.Lock()

    # ------------------------------------------------------------ کارها (در تنظیمات)
    def jobs(self):
        return list(self.settings.get("fbackup_jobs", default=[]) or [])

    def job(self, jid):
        j = next((x for x in self.jobs() if x.get("id") == jid), None)
        if not j:
            raise FbError("کار پشتیبان پیدا نشد.")
        return j

    def _update(self, jid, **f):
        items = self.jobs()
        for x in items:
            if x.get("id") == jid:
                x.update(f)
        self.settings.set_fbackup_jobs(items)

    def status(self):
        with self._lock:
            return {k: {"started": v["started"], "bytes": v["bytes"], "files": v["files"], "by": v["by"]} for k, v in self.running.items()}

    # ------------------------------------------------------------ اجرا
    def start(self, jid, by="", trigger="manual"):
        j = self.job(jid)
        with self._lock:
            if jid in self.running:
                raise FbError("این کار همین حالا در حال اجراست.")
            if len(self.running) >= 3:
                raise FbError("حداکثر ۳ پشتیبان پوشه هم‌زمان؛ کمی بعد دوباره امتحان کنید.")
            st = {"started": time.time(), "bytes": 0, "files": 0, "cancel": threading.Event(), "by": by}
            self.running[jid] = st
        threading.Thread(target=self._run, args=(j, st, by, trigger), name="fbackup", daemon=True).start()
        return {"started": True}

    def cancel(self, jid):
        with self._lock:
            st = self.running.get(jid)
        if not st:
            raise FbError("این کار در حال اجرا نیست.")
        st["cancel"].set()

    def _dev(self, j):
        d = self.store.ssh_device(int(j.get("device_id") or 0))
        if not d or d.get("owner"):
            raise FbError("دستگاه این کار حذف شده است.")
        c = self.ssh.creds(d["id"])
        if not c.get("username"):
            raise FbError("یوزر این دستگاه ذخیره نشده است.")
        return d, c

    def connect(self, d, c):
        port = int(d.get("port") or 22) if d.get("protocol") != "telnet" else 22
        dev = {**d, "port": port}
        check_hostkey(self.hostkeys, d["host"], port, bool(d.get("legacy")), False, None, self.emit)
        cli = ssh_connect(self.hostkeys, dev, c)
        cli.get_transport().set_keepalive(30)
        return cli

    @staticmethod
    def _cmd(inner, sudo):
        return f"sudo -S -p '' {inner}" if sudo else inner

    def _exec(self, cli, cmd, pw, sudo, out=None, st=None, on_err=None):
        """اجرای یک فرمان؛ stdout به out (فایل) یا برگشتی. خروجی: (کد خروج، stdout یا None، خطاها[])."""
        ch = cli.get_transport().open_session(timeout=20)
        ch.settimeout(1.0)
        ch.exec_command(cmd)
        if sudo:
            ch.sendall((pw or "") + "\n")
        ch.shutdown_write()
        buf, errs, ebuf = bytearray(), [], b""
        last = time.time()
        try:
            while True:
                if st and st["cancel"].is_set():
                    raise _Cancel()
                got = False
                if ch.recv_ready():
                    d = ch.recv(262144)
                    if d:
                        got = True
                        if out is not None:
                            out.write(d)
                            if st:
                                st["bytes"] += len(d)
                        else:
                            buf += d
                            if len(buf) > 1 << 20:
                                raise FbError("خروجی فرمان بیش از حد بزرگ است.")
                if ch.recv_stderr_ready():
                    e = ch.recv_stderr(65536)
                    if e:
                        got = True
                        ebuf += e
                        *lines, ebuf = ebuf.split(b"\n")
                        for ln in lines:
                            (on_err or errs.append)(ln.decode("utf-8", "replace").rstrip("\r"))
                if got:
                    last = time.time()
                    continue
                # 1.58.1: پایان = EOF کانال، نه exit-status. OpenSSH ممکن است exit-status را پیش از
                # آخرین تکه‌های stdout بفرستد (وقتی پنجره‌ی کانال پر است)؛ شکستن با exit-status آرشیو را ناقص می‌کرد.
                if (ch.eof_received or ch.closed) and not ch.recv_ready() and not ch.recv_stderr_ready():
                    break
                if time.time() - last > IDLE_TIMEOUT:
                    raise FbError(f"سرور {IDLE_TIMEOUT // 60} دقیقه هیچ داده‌ای نفرستاد؛ قطع شد.")
                time.sleep(0.05)
            if ebuf:
                (on_err or errs.append)(ebuf.decode("utf-8", "replace").rstrip("\r"))
            end = time.time() + 30
            while not ch.exit_status_ready() and time.time() < end:
                time.sleep(0.05)
            if not ch.exit_status_ready():
                raise FbError("سرور کد پایان فرمان را نفرستاد؛ نتیجه قابل اطمینان نیست.")
            return ch.recv_exit_status(), (None if out is not None else bytes(buf)), errs
        finally:
            ch.close()

    def probe(self, cli, paths, sudo, pw):
        """نوع هر مسیر: {path: "dir"|"file"|"missing"|"other"}"""
        q = " ".join(shlex.quote(p) for p in paths)
        code, out, errs = self._exec(cli, self._cmd(f"stat -L -c '%F|%s|%n' -- {q}", sudo), pw, sudo)
        if sudo and any("incorrect password" in e or "Sorry, try again" in e or "no password was provided" in e for e in errs):
            raise FbError("sudo پسورد را نپذیرفت (پسورد همان یوزر دستگاه استفاده می‌شود).")
        if sudo and any("not in the sudoers" in e or "may not run sudo" in e for e in errs):
            raise FbError("این یوزر اجازه‌ی sudo ندارد.")
        if code == 127:
            raise FbError("فرمان stat روی سرور نیست.")
        types = {p: "missing" for p in paths}
        self._sizes = {}
        for ln in (out or b"").decode("utf-8", "replace").splitlines():
            if ln.count("|") < 2:
                continue
            t, sz, n = ln.split("|", 2)
            if n in types:
                self._sizes[n] = int(sz) if sz.isdigit() else -1
                types[n] = "dir" if t == "directory" else ("file" if t.startswith("regular") else "other")
        return types, errs

    def test(self, j):
        d, c = self._dev(j)
        cli = self.connect(d, c)
        try:
            types, errs = self.probe(cli, j["paths"], j.get("sudo"), c.get("password"))
            code, out, _ = self._exec(cli, "command -v tar || which tar", None, False)
            return {"types": types, "tar": bool(out and out.strip()), "errors": [e for e in errs if e][:10]}
        finally:
            cli.close()

    def _target(self, j, d, ext):
        base = Path(str(j.get("dest") or "")).expanduser()
        if not str(j.get("dest") or "").strip() or not base.is_absolute():
            raise FbError("پوشه‌ی مقصد تنظیم نشده است.")
        folder = base / slug(d.get("name") or d["host"])
        folder.mkdir(parents=True, exist_ok=True)
        stem = f"{slug(j['name'])}_{datetime.now().strftime(STAMP)}"
        ext = ext if re.fullmatch(r"(\.[A-Za-z0-9_-]{1,12}){0,2}", ext or "") else ""
        p, i = folder / f"{stem}{ext}", 2
        while p.exists() or p.with_name(p.name + ".part").exists():
            p, i = folder / f"{stem}_{i}{ext}", i + 1
        return p

    def _rotate(self, j, folder):
        keep = int(j.get("keep") or 0)
        if keep <= 0:
            return 0
        pat = re.compile(re.escape(slug(j["name"])) + r"_\d{4}-\d{2}-\d{2}_\d{4}(_\d+)?(\..+)?$")
        files = sorted((f for f in folder.iterdir() if f.is_file() and pat.match(f.name) and not f.name.endswith(".part")),
                       key=lambda f: f.stat().st_mtime, reverse=True)
        n = 0
        for f in files[keep:]:
            try:
                f.unlink()
                n += 1
            except OSError:
                log.warning("fbackup rotate: %s", f)
        return n

    def _run(self, j, st, by, trigger):
        t0 = time.time()
        res = {"at": t0, "status": "error", "message": "", "size": 0, "files": 0, "file": "", "trigger": trigger, "errors": []}
        part = None
        cli = None
        try:
            d, c = self._dev(j)
            pw = c.get("password")
            sudo = bool(j.get("sudo"))
            cli = self.connect(d, c)
            types, perr = self.probe(cli, j["paths"], sudo, pw)
            missing = [p for p, t in types.items() if t == "missing"]
            if len(missing) == len(types):
                raise FbError("هیچ‌کدام از مسیرها روی سرور پیدا نشد: " + "، ".join(missing))
            paths = [p for p in j["paths"] if types[p] != "missing"]
            errors = [f"پیدا نشد: {p}" for p in missing]
            single = len(paths) == 1 and types[paths[0]] == "file"
            if single:
                # یک فایل (مثلاً خودش آرشیو است): همان فایل، بدون tar دوباره
                src = paths[0]
                bn = posixpath.basename(src)
                ext = "".join(Path(bn).suffixes[-2:]) if bn.lower().endswith((".tar.gz", ".tar.bz2", ".tar.xz")) else Path(bn).suffix
                target = self._target(j, d, ext)
                part = target.with_name(target.name + ".part")
                with open(part, "wb") as f:
                    code, _, errs = self._exec(cli, self._cmd(f"cat -- {shlex.quote(src)}", sudo), pw, sudo, out=f, st=st)
                if code != 0:
                    raise FbError("خواندن فایل ناموفق: " + ("؛ ".join(e for e in errs if e)[:300] or f"کد {code}"))
                want = self._sizes.get(src, -1)
                if want >= 0 and st["bytes"] != want:
                    raise FbError(f"فایل ناقص دریافت شد ({human(st['bytes'])} از {human(want)})؛ دوباره اجرا کنید.")
                st["files"] = 1
                method = "file"
            else:
                target = self._target(j, d, ".tar.gz")
                part = target.with_name(target.name + ".part")
                ex = " ".join(f"--exclude={shlex.quote(x)}" for x in j.get("excludes") or [])
                rel = " ".join(shlex.quote(p.lstrip("/")) for p in paths)
                terr = []

                def on_err(ln):
                    if not ln:
                        return
                    if ln.startswith("tar:") or "Permission denied" in ln or "Cannot" in ln:
                        if len(terr) < 200:
                            terr.append(ln)
                    elif not ln.endswith("/"):          # فهرست -v: پوشه‌ها با / تمام می‌شوند
                        st["files"] += 1
                with open(part, "wb") as f:
                    code, _, _ = self._exec(cli, self._cmd(f"tar -czvf - {ex} -C / -- {rel}", sudo), pw, sudo, out=f, st=st,
                                            on_err=on_err)
                method = "tar"
                if code == 127 and not sudo:
                    st["bytes"] = st["files"] = 0
                    with open(part, "wb") as f:
                        self._sftp_tar(cli, paths, j.get("excludes") or [], f, st, terr)
                    method, code = "sftp", 0
                elif code == 127:
                    raise FbError("tar روی سرور نیست (با sudo روش جایگزین SFTP ممکن نیست).")
                if sudo and any("incorrect password" in e or "Sorry, try again" in e for e in terr):
                    raise FbError("sudo پسورد را نپذیرفت.")
                errors += [e for e in terr if "Removing leading" not in e]
                if code == 2 and not st["files"]:
                    raise FbError("tar ناموفق: " + "؛ ".join(errors[:3])[:400])
                if code not in (0, 1, 2):
                    raise FbError(f"tar با کد {code} تمام شد: " + "؛ ".join(errors[:3])[:400])
            if method != "file":
                self._verify_gz(part, st)
            os.replace(part, target)
            part = None
            size = target.stat().st_size
            rot = self._rotate(j, target.parent)
            res.update(status="warn" if errors else "ok", size=size, files=st["files"], file=str(target), errors=errors[:50],
                       message=(f"{human(size)}، {st['files']} فایل" if method != "file" else f"{human(size)} (همان فایل، بدون tar)")
                       + (f"؛ {len(errors)} هشدار" if errors else "") + (f"؛ {rot} نسخه‌ی قدیمی حذف شد" if rot else "")
                       + ("؛ روش SFTP (tar روی سرور نبود)" if method == "sftp" else ""))
        except _Cancel:
            res.update(status="cancelled", message="به درخواست کاربر متوقف شد")
        except (FbError, TermError) as e:
            res["message"] = str(e)
        except Exception as e:
            log.exception("fbackup")
            try:
                from .ssh import friendly
                res["message"] = friendly(e)
            except Exception:
                res["message"] = str(e) or e.__class__.__name__
        finally:
            if cli:
                try:
                    cli.close()
                except Exception:  # nosec B110 — بستن اتصال پایان‌یافته
                    pass
            if part is not None:
                try:
                    part.unlink()
                except OSError:
                    pass
            with self._lock:
                self.running.pop(j["id"], None)
        res["secs"] = round(time.time() - t0, 1)
        try:
            cur = next((x for x in self.jobs() if x.get("id") == j["id"]), None)
            if cur is not None:
                runs = ([{k: res[k] for k in ("at", "status", "message", "size", "files", "file", "trigger", "secs", "errors")}]
                        + list(cur.get("runs") or []))[:MAX_RUNS]
                self._update(j["id"], last_at=res["at"], last_status=res["status"], last_message=res["message"], runs=runs)
            ok = res["status"] in ("ok", "warn")
            self.store.add_history("ssh", j["name"], "ok" if ok else "error", f"پشتیبان پوشه: {res['message']}", "", res["file"],
                                   user=by or "")
            lvl = {"ok": "info", "warn": "warn", "cancelled": "warn"}.get(res["status"], "error")
            self.emit(lvl, f"پشتیبان پوشه «{j['name']}»: {res['message']}", "backup")
        except Exception:
            log.exception("fbackup result")

    @staticmethod
    def _verify_gz(path, st):
        """1.58.1: آرشیو دریافت‌شده باید یک gzip کامل باشد (ته gzip و CRC)؛ وگرنه ذخیره نمی‌شود."""
        d = zlib.decompressobj(16 + zlib.MAX_WBITS)
        try:
            with open(path, "rb") as f:
                while True:
                    if st["cancel"].is_set():
                        raise _Cancel()
                    b = f.read(1 << 20)
                    if not b:
                        break
                    d.decompress(b, 1 << 16)
                    while d.unconsumed_tail:
                        d.decompress(d.unconsumed_tail, 1 << 16)
        except zlib.error as e:
            raise FbError(f"آرشیو دریافت‌شده خراب است ({e})؛ ذخیره نشد.")
        if not d.eof:
            raise FbError("آرشیو ناقص دریافت شد (اتصال پیش از پایان قطع شد)؛ ذخیره نشد، دوباره اجرا کنید.")

    def _sftp_tar(self, cli, paths, excludes, f, st, errs):
        """روش جایگزین: پیمایش با SFTP و ساخت tar.gz در همین برنامه."""
        sftp = cli.open_sftp()
        sftp.get_channel().settimeout(60)

        def skip(rel, name):
            return any(fnmatch.fnmatch(name, x) or fnmatch.fnmatch(rel, x) or fnmatch.fnmatch("/" + rel, x) for x in excludes)
        try:
            with tarfile.open(fileobj=f, mode="w:gz") as tar:
                def add(path, a):
                    if st["cancel"].is_set():
                        raise _Cancel()
                    rel = path.lstrip("/")
                    if skip(rel, posixpath.basename(path)):
                        return
                    ti = tarfile.TarInfo(rel)
                    ti.mtime, ti.mode = int(a.st_mtime or 0), (a.st_mode or 0) & 0o7777
                    if stmod.S_ISDIR(a.st_mode or 0):
                        ti.type = tarfile.DIRTYPE
                        tar.addfile(ti)
                        try:
                            kids = sftp.listdir_attr(path)
                        except OSError as e:
                            errs.append(f"{path}: {e}")
                            return
                        for k in kids:
                            add(posixpath.join(path, k.filename), k)
                    elif stmod.S_ISREG(a.st_mode or 0):
                        ti.size = a.st_size or 0
                        try:
                            with sftp.open(path, "rb") as rf:
                                rf.prefetch(ti.size)
                                tar.addfile(ti, _Counting(rf, st))
                            st["files"] += 1
                        except OSError as e:
                            errs.append(f"{path}: {e}")
                for p in paths:
                    try:
                        add(p, sftp.stat(p))
                    except OSError as e:
                        errs.append(f"{p}: {e}")
        finally:
            sftp.close()


class _Counting:
    def __init__(self, f, st):
        self.f, self.st = f, st

    def read(self, n=-1):
        d = self.f.read(n)
        self.st["bytes"] += len(d)
        if self.st["cancel"].is_set():
            raise _Cancel()
        return d


def normalize(job, old=None, devices=None):
    """ورودی فرم ← کار ذخیره‌شدنی."""
    import secrets as pysecrets
    name = str(job.get("name") or "").strip()[:80]
    if not name:
        raise FbError("نام کار را وارد کنید.")
    try:
        did = int(job.get("device_id") or 0)
    except (TypeError, ValueError):
        did = 0
    devs = {d["id"]: d for d in (devices or [])}
    if did not in devs:
        raise FbError("یک دستگاه لینوکس از فهرست دستگاه‌های مشترک انتخاب کنید.")
    if devs[did].get("device_type") != "linux":
        raise FbError("پشتیبان پوشه فقط برای دستگاه‌های لینوکس است.")
    if devs[did].get("protocol") == "telnet":
        raise FbError("این دستگاه با Telnet تعریف شده؛ پشتیبان پوشه SSH لازم دارد.")
    dest = str(job.get("dest") or "").strip()
    if not dest or not Path(dest).expanduser().is_absolute():
        raise FbError("پوشه‌ی مقصد (مسیر کامل) را انتخاب کنید.")
    try:
        keep = max(0, min(365, int(job.get("keep") if job.get("keep") not in (None, "") else 7)))
    except (TypeError, ValueError):
        raise FbError("تعداد نسخه‌های نگه‌داشتنی باید عدد باشد.")
    old = old or {}
    out = {"id": old.get("id") or pysecrets.token_hex(4), "name": name, "device_id": did, "paths": clean_paths(job.get("paths")),
           "excludes": clean_excludes(job.get("excludes")), "sudo": bool(job.get("sudo")), "dest": dest, "keep": keep}
    for k in ("last_at", "last_status", "last_message", "runs"):
        if k in old:
            out[k] = old[k]
    return out
