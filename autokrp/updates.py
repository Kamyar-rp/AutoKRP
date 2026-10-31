"""
1.33: بررسی امنیت و به‌روزرسانی (صفحه‌ی «درباره»).

- نسخه‌ی تازه: GET https://api.github.com/repos/kamyar-rp/AutoKRP/releases/latest (آخرین انتشار غیرپیش‌نویس و
  غیر pre-release؛ مستند GitHub REST «Get the latest release»: tag_name، html_url، published_at، body، assets[].name،
  assets[].browser_download_url).
- آسیب‌پذیری کتابخانه‌ها: پایگاه OSV (همان منبع pip-audit): POST https://api.osv.dev/v1/querybatch با
  {"queries":[{"package":{"ecosystem":"PyPI","name":..},"version":..}]} ← results[i].vulns[].id؛ جزئیات هر مورد با
  GET https://api.osv.dev/v1/vulns/{id} (summary، aliases، affected[].ranges[].events[].fixed).
- فهرست کتابخانه‌ها: در exe از autokrp/build_deps.txt (هنگام بیلد با dev/deps_snapshot.py ساخته می‌شود)، در اجرای
  از سورس از کتابخانه‌های نصب‌شده‌ای که requirements.txt (و وابستگی‌هایشان) لازم دارد.
- فقط نام و نسخه‌ی کتابخانه‌ها و نسخه‌ی برنامه به GitHub و OSV می‌رود؛ هیچ داده‌ی سازمانی فرستاده نمی‌شود.
"""
import json
import logging
import re
import threading
import time
from pathlib import Path

from . import __version__, atrest, paths

log = logging.getLogger(__name__)

GH_LATEST = "https://api.github.com/repos/kamyar-rp/AutoKRP/releases/latest"
RELEASES_PAGE = "https://github.com/kamyar-rp/AutoKRP/releases"
OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/{}"
EVERY = 86400
MAX_DETAILS = 80
# ریسک پذیرفته‌شده (در build.bat و CI هم نادیده گرفته می‌شود) — نمایش داده می‌شود ولی هشدار نمی‌دهد
ACCEPTED = {
    "GHSA-r374-rxx8-8654": "paramiko 4: الگوریتم SHA-1 فقط با سوییچ «سازگاری با دستگاه قدیمی» همان دستگاه روشن می‌شود؛ نسخه‌ی اصلاح‌شده هنوز منتشر نشده است.",
}
# فقط برای ساخت exe؛ داخل برنامه نیستند
BUILD_ONLY = {"pyinstaller", "pyinstaller-hooks-contrib", "altgraph", "pefile", "pywin32-ctypes", "macholib", "pip",
              "setuptools", "wheel", "pip-audit"}


class UpdateError(Exception):
    pass


def norm(name):
    return re.sub(r"[-_.]+", "-", str(name or "")).lower().strip()


def vtuple(v):
    """«v1.32.0» یا «1.32.0rc1» ← (1, 32, 0)؛ فقط بخش‌های عددی ابتدای هر جزء."""
    out = []
    for p in str(v or "").strip().lstrip("vV").split("."):
        m = re.match(r"\d+", p)
        if not m:
            break
        out.append(int(m.group(0)))
    return tuple(out) or (0,)


# ------------------------------------------------------------------ فهرست کتابخانه‌ها
def _req_names(text):
    names = []
    for line in str(text or "").splitlines():
        line = line.split("#", 1)[0].strip()
        m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)", line)
        if m and norm(m.group(1)) not in BUILD_ONLY:
            names.append(m.group(1))
    return names


def snapshot(req_file=None):
    """کتابخانه‌های لازم برنامه (requirements + وابستگی‌ها، بدون ابزارهای بیلد) با نسخه‌ی نصب‌شده: {نام: نسخه}."""
    from importlib import metadata
    req = Path(req_file) if req_file else Path(__file__).resolve().parent.parent / "requirements.txt"
    todo = _req_names(req.read_text(encoding="utf-8")) if req.exists() else []
    out = {}
    while todo:
        n = todo.pop()
        k = norm(n)
        if k in out or k in BUILD_ONLY:
            continue
        try:
            d = metadata.distribution(n)
        except metadata.PackageNotFoundError:
            continue
        out[k] = d.version
        for r in d.requires or []:
            if ";" in r and "extra" in r.split(";", 1)[1]:
                continue                           # وابستگی اختیاری (extra) نصب نشده است
            m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)", r.strip())
            if m:
                todo.append(m.group(1))
    return dict(sorted(out.items()))


def installed():
    """exe: فایل build_deps.txt همراه برنامه؛ سورس: snapshot از محیط فعلی."""
    f = Path(__file__).with_name("build_deps.txt")
    if f.exists():
        out = {}
        for line in f.read_text(encoding="utf-8").splitlines():
            if "==" in line and not line.startswith("#"):
                n, v = line.split("==", 1)
                if norm(n) not in BUILD_ONLY:
                    out[norm(n)] = v.strip()
        if out:
            return out, "build"
    return snapshot(), "source"


# ------------------------------------------------------------------ HTTP (قابل جایگزینی در تست)
def _get(url, timeout=20):
    import requests
    return requests.get(url, timeout=(10, timeout), headers={"User-Agent": f"AutoKRP/{__version__}",
                                                             "Accept": "application/vnd.github+json, application/json"})


def _post(url, body, timeout=30):
    import requests
    return requests.post(url, json=body, timeout=(10, timeout), headers={"User-Agent": f"AutoKRP/{__version__}"})


# ------------------------------------------------------------------ نسخه‌ی تازه
def check_release(get=_get, current=__version__):
    try:
        r = get(GH_LATEST)
    except Exception as e:
        raise UpdateError(f"اتصال به GitHub ممکن نشد: {str(e)[:150]}")
    if r.status_code == 404:
        return {"current": current, "latest": None, "newer": False, "url": RELEASES_PAGE}
    if r.status_code in (403, 429):
        raise UpdateError("GitHub درخواست‌ها را محدود کرده است؛ کمی بعد دوباره امتحان کنید.")
    if r.status_code != 200:
        raise UpdateError(f"پاسخ GitHub: HTTP {r.status_code}")
    try:
        d = r.json()
    except ValueError:
        raise UpdateError("پاسخ GitHub JSON نیست.")
    tag = str(d.get("tag_name") or "")
    url = str(d.get("html_url") or "")
    if not url.startswith(RELEASES_PAGE + "/"):
        url = RELEASES_PAGE
    exe = next((a for a in d.get("assets") or [] if str(a.get("name", "")).lower().endswith(".exe")), None)
    return {"current": current, "latest": tag.lstrip("vV") or None, "newer": vtuple(tag) > vtuple(current), "url": url,
            "published": d.get("published_at") or "", "notes": str(d.get("body") or "")[:6000],
            "exe": {"name": exe.get("name"), "size": exe.get("size")} if exe else None}


# ------------------------------------------------------------------ آسیب‌پذیری‌ها
def _fixed_for(vuln, pkg):
    fixed = []
    for a in vuln.get("affected") or []:
        p = a.get("package") or {}
        if norm(p.get("name")) != pkg or (p.get("ecosystem") or "").lower() != "pypi":
            continue
        for rg in a.get("ranges") or []:
            for ev in rg.get("events") or []:
                if ev.get("fixed"):
                    fixed.append(str(ev["fixed"]))
    return sorted(set(fixed), key=vtuple)


def _severity(v):
    ds = v.get("database_specific") or {}
    s = ds.get("severity") if isinstance(ds, dict) else None
    if isinstance(s, str) and s:
        return s.upper()
    for a in v.get("affected") or []:
        es = a.get("ecosystem_specific") or {}
        if isinstance(es, dict) and isinstance(es.get("severity"), str):
            return es["severity"].upper()
    return ""


def check_vulns(pkgs, post=_post, get=_get):
    """pkgs: {نام: نسخه} ← فهرست آسیب‌پذیری‌ها (هر کتابخانه/شناسه یک ردیف)."""
    names = list(pkgs)
    found = []
    for i in range(0, len(names), 100):
        part = names[i:i + 100]
        body = {"queries": [{"package": {"ecosystem": "PyPI", "name": n}, "version": pkgs[n]} for n in part]}
        try:
            r = post(OSV_BATCH, body)
        except Exception as e:
            raise UpdateError(f"اتصال به osv.dev ممکن نشد: {str(e)[:150]}")
        if r.status_code != 200:
            raise UpdateError(f"پاسخ osv.dev: HTTP {r.status_code}")
        try:
            res = r.json().get("results") or []
        except (ValueError, AttributeError):
            raise UpdateError("پاسخ osv.dev JSON نیست.")
        for n, rr in zip(part, res):
            for v in (rr or {}).get("vulns") or []:
                if v.get("id"):
                    found.append((n, str(v["id"])))
    items, seen = [], set()
    for n, vid in found[:MAX_DETAILS]:
        det = {}
        try:
            r = get(OSV_VULN.format(vid))
            if r.status_code == 200:
                det = r.json()
        except Exception:  # noqa — جزئیات اختیاری است؛ شناسه کافی است
            det = {}
        aliases = [str(a) for a in det.get("aliases") or []]
        acc = next((ACCEPTED[x] for x in [vid] + aliases if x in ACCEPTED), "")
        key = (n, tuple(sorted({vid, *aliases})))
        if key in seen:
            continue
        seen.add(key)
        items.append({"package": n, "version": pkgs[n], "id": vid, "aliases": aliases[:6],
                      "summary": str(det.get("summary") or det.get("details") or "")[:300],
                      "fixed": _fixed_for(det, n), "severity": _severity(det), "accepted": acc})
    # یک آسیب‌پذیری با چند شناسه (GHSA/PYSEC/CVE) یک بار
    uniq, ids = [], set()
    for it in items:
        allids = {it["id"], *it["aliases"]}
        if (it["package"], frozenset(allids)) in ids or any(it["package"] == p and allids & s for p, s in ids):
            continue
        ids.add((it["package"], frozenset(allids)))
        uniq.append(it)
    return {"items": uniq, "checked": len(names), "more": max(0, len(found) - MAX_DETAILS)}


# ------------------------------------------------------------------ بررسی دوره‌ای (worker)
class SecurityCheck:
    def __init__(self, settings, emit=None, notify=None, demo=False):
        self.settings, self.demo = settings, demo
        self.emit = emit or (lambda *a, **k: None)
        self.notify = notify or (lambda *a, **k: None)
        self.running = False
        self._lock = threading.Lock()
        self.get, self.post = _get, _post
        self.alerts = None                         # کش summary برای poll رابط (فایل هر ثانیه خوانده نشود)

    def _path(self):
        return paths.data_dir() / "security_check.dat"

    def load(self):
        p = self._path()
        try:
            return json.loads(atrest.read_text(p)) if p.exists() else {}
        except Exception:  # noqa
            log.exception("security_check read")
            return {}

    def _save(self, d):
        try:
            atrest.write_text(self._path(), json.dumps(d, ensure_ascii=False))
        except Exception:  # noqa
            log.exception("security_check write")

    def auto(self):
        return bool(self.settings.get("updates", "auto", default=True))

    def due(self, now=None):
        if not self.auto() or self.running:
            return False
        last = (self.load() or {}).get("at") or 0
        return (now or time.time()) - last >= EVERY

    def start(self, who="auto"):
        with self._lock:
            if self.running:
                return False
            self.running = True
        threading.Thread(target=self._run, args=(who,), name="seccheck", daemon=True).start()
        return True

    def _run(self, who):
        try:
            self.run_now(who)
        finally:
            self.running = False

    def run_now(self, who="auto"):
        old = self.load()
        d = {"at": time.time(), "by": who}
        if self.demo:
            d["release"] = {"current": __version__, "latest": __version__, "newer": False, "url": RELEASES_PAGE}
            d["vulns"] = {"items": [], "checked": 0, "source": "demo"}
        else:
            try:
                d["release"] = check_release(self.get)
            except UpdateError as e:
                d["release"] = {"error": str(e), "current": __version__}
            try:
                pk, src = installed()
                d["vulns"] = {**check_vulns(pk, self.post, self.get), "source": src}
            except UpdateError as e:
                d["vulns"] = {"error": str(e)}
            except Exception as e:  # noqa
                log.exception("vuln check")
                d["vulns"] = {"error": str(e)[:200]}
        # هشدار فقط برای موارد تازه (نه هر روز تکرار همان)
        d["notified"] = dict(old.get("notified") or {})
        rel = d.get("release") or {}
        if rel.get("newer") and d["notified"].get("release") != rel.get("latest"):
            msg = f"نسخه‌ی تازه‌ی AutoKRP منتشر شده است: {rel['latest']} (نسخه‌ی فعلی {rel['current']})"
            self.emit("warn", msg, "security")
            self.notify("security_update", f"{msg}\n{rel.get('url')}")
            d["notified"]["release"] = rel.get("latest")
        bad = [x for x in (d.get("vulns") or {}).get("items") or [] if not x.get("accepted")]
        keys = sorted(f"{x['package']}:{x['id']}" for x in bad)
        newk = [k for k in keys if k not in (old.get("notified") or {}).get("vulns", [])]
        if newk:
            lines = "\n".join(f"- {x['package']} {x['version']}: {x['id']}" + (f" (رفع در {x['fixed'][0]})" if x["fixed"] else "")
                              for x in bad if f"{x['package']}:{x['id']}" in newk)
            msg = f"آسیب‌پذیری تازه در {len(newk)} مورد از کتابخانه‌های برنامه پیدا شد"
            self.emit("warn", msg, "security")
            self.notify("security_update", f"{msg}:\n{lines}")
        d["notified"]["vulns"] = keys
        self._save(d)
        self.alerts = None
        return d

    def summary(self):
        """برای نوار کناری: تعداد هشدارهای باز (نسخه‌ی تازه + آسیب‌پذیری پذیرفته‌نشده)."""
        if self.alerts is not None:
            return self.alerts
        d = self.load()
        n = 1 if (d.get("release") or {}).get("newer") else 0
        n += len([x for x in (d.get("vulns") or {}).get("items") or [] if not x.get("accepted")])
        self.alerts = n
        return n
