"""
ابزار اسکن شبکه: کشف هاست‌ها و اسکن پورت TCP (connect)، با بنر و بررسی HTTP اختیاری.
بر پایه‌ی اسکریپت NetRecon کاربر (فقط کتابخانه‌ی استاندارد، بدون Nmap). منطق اصلی همان است؛
تغییرها: اجرای ping با مسیر کامل و بدون پنجره، قابل توقف، سقف‌ها، و فقط رنج‌های مجاز.

فقط ابزار شناسایی/عیب‌یابی است (اتصال TCP عادی و درخواست شناسایی)؛ هیچ بهره‌برداری‌ای انجام نمی‌شود.
"""
import ipaddress
import os
import platform
import re
import socket
import ssl
import subprocess  # nosec B404 — فقط ping سیستم با مسیر کامل و آرگومان لیستی
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from pathlib import Path

COMMON_PORTS = [
    20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 88, 110, 111, 119,
    123, 135, 137, 138, 139, 143, 161, 389, 443, 445, 465, 514,
    587, 636, 993, 995, 1433, 1521, 2049, 2375, 2376, 3000, 3306,
    3389, 5000, 5432, 5601, 5900, 5985, 5986, 6379, 6443, 8000,
    8080, 8081, 8443, 8888, 9090, 9200, 9300, 27017
]

SERVICE_NAMES = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP",
    88: "Kerberos", 110: "POP3", 111: "RPCBind", 119: "NNTP",
    123: "NTP", 135: "MSRPC", 137: "NetBIOS-NS", 138: "NetBIOS-DGM",
    139: "NetBIOS-SSN", 143: "IMAP", 161: "SNMP", 389: "LDAP",
    443: "HTTPS", 445: "SMB", 465: "SMTPS", 514: "Syslog",
    587: "SMTP-submit", 636: "LDAPS", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle", 2049: "NFS", 2375: "Docker",
    2376: "Docker-TLS", 3000: "HTTP-alt", 3306: "MySQL", 3389: "RDP",
    5000: "HTTP-alt", 5432: "PostgreSQL", 5601: "Kibana",
    5900: "VNC", 5985: "WinRM", 5986: "WinRM-HTTPS", 6379: "Redis",
    6443: "Kubernetes", 8000: "HTTP-alt", 8080: "HTTP-proxy",
    8081: "HTTP-alt", 8443: "HTTPS-alt", 8888: "HTTP-alt",
    9090: "HTTP-alt", 9200: "Elasticsearch", 9300: "Elasticsearch",
    27017: "MongoDB",
}

# درخواست‌های شناسایی (همان اسکریپت اصلی)
BANNER_PROBES = {
    21: b"\r\n", 22: b"\r\n",
    25: b"EHLO netrecon.local\r\n",
    80: b"HEAD / HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    110: b"\r\n", 143: b"a001 CAPABILITY\r\n",
    587: b"EHLO netrecon.local\r\n",
    8080: b"HEAD / HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    8000: b"HEAD / HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    8081: b"HEAD / HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    8888: b"HEAD / HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    9090: b"HEAD / HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n",
}
DISCOVERY_PORTS = [443, 80, 22, 445, 3389]
HTTP_PORTS = (80, 8000, 8080, 8081, 8888, 9090)
HTTPS_PORTS = (443, 8443)

PRIVATE_DEFAULT = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
MAX_WORKERS = 300
HARD_MAX_HOSTS = 65536
HARD_MAX_PROBES = 2_000_000


class ScanError(Exception):
    pass


# ------------------------------------------------------------------ ورودی و محدودیت‌ها
def parse_ports(spec):
    spec = str(spec or "").strip()
    if not spec or spec.lower() == "common":
        return COMMON_PORTS.copy()
    result = set()
    for part in re.split(r"[\s,;]+", spec):
        if not part:
            continue
        try:
            if "-" in part:
                a, b = part.split("-", 1)
                start, end = sorted((int(a), int(b)))
                if start < 1 or end > 65535:
                    raise ScanError("پورت باید بین ۱ و ۶۵۵۳۵ باشد.")
                result.update(range(start, end + 1))
            else:
                p = int(part)
                if not 1 <= p <= 65535:
                    raise ScanError("پورت باید بین ۱ و ۶۵۵۳۵ باشد.")
                result.add(p)
        except ValueError:
            raise ScanError(f"پورت نامعتبر: {part}")
    if not result:
        raise ScanError("هیچ پورت معتبری وارد نشده است.")
    return sorted(result)


def parse_networks(lines):
    """فهرست رنج‌های مجاز از تنظیمات (متن بعد از # توضیح است)."""
    nets, bad = [], []
    for line in lines or []:
        s = str(line).split("#", 1)[0].strip()
        if not s:
            continue
        try:
            nets.append(ipaddress.ip_network(s, strict=False))
        except ValueError:
            bad.append(s)
    return nets, bad


def split_allowed(ips, nets):
    """(مجاز، غیرمجاز) بر اساس رنج‌های مجاز. بدون رنج مجاز، هیچ اسکنی انجام نمی‌شود."""
    ok, no = [], []
    for ip in ips:
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            no.append(ip)
            continue
        (ok if any(a.version == n.version and a in n for n in nets) else no).append(ip)
    return ok, no


# ------------------------------------------------------------------ اتصال (منطق اسکریپت اصلی)
def tcp_connect(ip, port, timeout=1.0):
    start = time.perf_counter()
    fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
    sock = socket.socket(fam, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        rc = sock.connect_ex((ip, port))
        return rc == 0, (time.perf_counter() - start) * 1000, None
    except socket.timeout:
        return False, (time.perf_counter() - start) * 1000, "timeout"
    except OSError as e:
        return False, (time.perf_counter() - start) * 1000, str(e)
    finally:
        sock.close()


def _ping_exe():
    if os.name == "nt":
        p = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "PING.EXE"
        return str(p) if p.exists() else None
    for c in ("/bin/ping", "/usr/bin/ping", "/sbin/ping"):
        if os.path.exists(c):
            return c
    return None


def ping(host, timeout=1.5):
    exe = _ping_exe()
    if not exe:
        return {"available": False, "reachable": None, "latency_ms": None}
    if platform.system().lower() == "windows":
        cmd = [exe, "-n", "1", "-w", str(max(1, int(timeout * 1000))), host]
    else:
        cmd = [exe, "-c", "1", "-W", str(max(1, int(timeout))), host]
    start = time.perf_counter()
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL,  # nosec B603
                           timeout=timeout + 1, creationflags=0x08000000 if os.name == "nt" else 0)
        elapsed = (time.perf_counter() - start) * 1000
        # ویندوز برای «Destination host unreachable» هم کد ۰ برمی‌گرداند؛ پاسخ واقعی IPv4 «TTL=» دارد
        # (پاسخ IPv6 ویندوز TTL ندارد؛ آنجا «unreachable» بودن بررسی می‌شود)
        out = p.stdout.upper()
        if os.name != "nt":
            ok = p.returncode == 0
        elif ":" in host:
            ok = p.returncode == 0 and b"UNREACHABLE" not in out and b"TIMED OUT" not in out
        else:
            ok = p.returncode == 0 and b"TTL=" in out
        return {"available": True, "reachable": ok, "latency_ms": round(elapsed, 2) if ok else None}
    except Exception:
        return {"available": True, "reachable": False, "latency_ms": None}


def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def clean_banner(data, limit=300):
    if not data:
        return ""
    text = data.decode("utf-8", errors="replace")
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", " ", text)
    return " ".join(text.split())[:limit]


def grab_banner(ip, port, timeout=1.5):
    probe = BANNER_PROBES.get(port, b"\r\n")
    fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
    sock = socket.socket(fam, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((ip, port))
        if probe:
            try:
                sock.sendall(probe)
            except OSError:
                pass
        return clean_banner(sock.recv(1024))
    except Exception:
        return ""
    finally:
        sock.close()


def detect(banner):
    low = (banner or "").lower()
    if "ssh" in low:
        return "SSH"
    if "http/" in low or "server:" in low:
        return "HTTP"
    if "smtp" in low:
        return "SMTP"
    if "ftp" in low:
        return "FTP"
    return ""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """ریدایرکت دنبال نمی‌شود: درخواست نباید به آدرسی بیرون از رنج مجاز برود."""
    def redirect_request(self, *a, **k):
        return None


def _opener(https):
    hs = [urllib.request.ProxyHandler({}), _NoRedirect()]      # بدون پروکسی سیستم؛ مستقیم به همان هاست
    if https:
        hs.append(urllib.request.HTTPSHandler(context=ssl._create_unverified_context()))  # nosec B323 — شناسایی سرویس داخلی با گواهی self-signed
    return urllib.request.build_opener(*hs)


def http_check(url, timeout=5.0):
    """درخواست GET ساده (بدون بررسی گواهی، بدون پروکسی و ریدایرکت؛ فقط برای شناسایی سرویس)."""
    req = urllib.request.Request(url, headers={"User-Agent": "AutoKRP-NetScan/1.0", "Accept": "*/*", "Connection": "close"})
    start = time.perf_counter()
    try:
        with _opener(url.lower().startswith("https://")).open(req, timeout=timeout) as r:  # nosec B310 — فقط http/https ساخته‌شده در همین ماژول
            return {"status": r.status, "server": r.headers.get("Server") or "", "title": _title(r.read(4096)),
                    "latency_ms": round((time.perf_counter() - start) * 1000, 2)}
    except urllib.error.HTTPError as e:
        return {"status": e.code, "server": (e.headers.get("Server") if e.headers else "") or "", "title": "",
                "latency_ms": round((time.perf_counter() - start) * 1000, 2)}
    except Exception as e:
        return {"status": "", "server": "", "title": "", "error": str(e)[:200]}


def _title(body):
    m = re.search(rb"<title[^>]*>(.*?)</title>", body or b"", re.I | re.S)
    return clean_banner(m.group(1), 120) if m else ""


# ------------------------------------------------------------------ اجرای موازی و قابل توقف
def _pool(items, fn, workers, cancel, progress, label):
    """fn(item) روی همه با حداکثر workers هم‌زمان. با cancel فوراً برمی‌گردد (اتصال‌های در جریان با timeout
    خودشان در پس‌زمینه تمام می‌شوند و نتیجه‌شان دور ریخته می‌شود). خروجی: نتایج غیر None."""
    out, n, done = [], len(items), 0
    it = iter(items)
    w = max(1, min(int(workers), MAX_WORKERS))
    ex = ThreadPoolExecutor(max_workers=w)
    try:
        running = set()
        for _ in range(w * 2):
            x = next(it, None)
            if x is None:
                break
            running.add(ex.submit(fn, x))
        while running:
            fin, running = wait(running, timeout=0.3, return_when=FIRST_COMPLETED)
            if cancel is not None and cancel.is_set():
                raise InterruptedError()
            for f in fin:
                done += 1
                try:
                    r = f.result()
                except Exception:
                    r = None
                if r is not None:
                    out.append(r)
                x = next(it, None)
                if x is not None:
                    running.add(ex.submit(fn, x))
            if progress and fin:
                progress(done, n, label)
        return out
    finally:
        ex.shutdown(wait=not (cancel is not None and cancel.is_set()), cancel_futures=True)


def _ipkey(ip):
    a = ipaddress.ip_address(ip)
    return (a.version, int(a))


def discover(targets, timeout=0.7, workers=100, cancel=None, progress=None):
    """کشف هاست (همان host_check اسکریپت): ping + چند پورت TCP رایج. فقط هاست‌های روشن برمی‌گردند."""
    def one(ip):
        if cancel is not None and cancel.is_set():
            return None
        p = ping(ip, timeout + 0.5)
        tcp = []
        for port in DISCOVERY_PORTS:
            opened, lat, _ = tcp_connect(ip, port, timeout)
            if opened:
                tcp.append(port)
        if not (p.get("reachable") or tcp):
            return None
        return {"ip": ip, "hostname": reverse_dns(ip), "ping": "yes" if p.get("reachable") else ("no" if p.get("available") else "n/a"),
                "ping_ms": p.get("latency_ms") or "", "tcp_open": " ".join(map(str, tcp))}
    rows = _pool(targets, one, workers, cancel, progress, "کشف")
    return sorted(rows, key=lambda r: _ipkey(r["ip"]))


def port_scan(targets, ports, timeout=1.0, workers=100, banners=False, http=False, cancel=None, progress=None, names=True):
    """اسکن پورت TCP روی همه‌ی هدف‌ها. فقط پورت‌های باز برمی‌گردند."""
    pairs = [(ip, p) for ip in targets for p in ports]

    def one(pair):
        if cancel is not None and cancel.is_set():
            return None
        ip, port = pair
        opened, lat, _ = tcp_connect(ip, port, timeout)
        if not opened:
            return None
        r = {"ip": ip, "port": port, "service": SERVICE_NAMES.get(port, "unknown"), "latency_ms": round(lat, 2),
             "banner": "", "detected": ""}
        if banners:
            b = grab_banner(ip, port, max(timeout, 1.5))
            r["banner"], r["detected"] = b, detect(b)
        return r
    rows = _pool(pairs, one, workers, cancel, progress, "پورت")
    if names:
        hosts = list(dict.fromkeys(r["ip"] for r in rows))
        nm = dict(_pool(hosts, lambda ip: (ip, reverse_dns(ip)), min(int(workers), 50), cancel, progress, "نام"))
        for r in rows:
            r["hostname"] = nm.get(r["ip"], "")
    if http:
        web = [r for r in rows if r["port"] in HTTP_PORTS + HTTPS_PORTS]

        def hc(r):
            if cancel is not None and cancel.is_set():
                return None
            host = f"[{r['ip']}]" if ":" in r["ip"] else r["ip"]
            scheme = "https" if r["port"] in HTTPS_PORTS else "http"
            h = http_check(f"{scheme}://{host}:{r['port']}", timeout + 2)
            r.update({"http_status": h.get("status", ""), "http_server": h.get("server", ""), "http_title": h.get("title", "")})
            return r
        _pool(web, hc, min(int(workers), 20), cancel, progress, "HTTP")
    return sorted(rows, key=lambda r: (_ipkey(r["ip"]), r["port"]))


def scan(targets, do_ping=True, ports=None, only_alive=False, timeout=1.0, workers=100, banners=False, http=False,
         cancel=None, progress=None):
    """اسکن یکپارچه: ping (اختیاری) + اسکن پورت TCP (اختیاری).
    هاست «روشن» = پاسخ ping یا حداقل یک پورت باز. خروجی: یک ردیف برای هر پورت باز؛ هاست روشنِ بدون پورت باز
    یک ردیف با پورت خالی دارد. only_alive: پورت‌ها فقط روی هاست‌هایی که به ping جواب دادند (سریع‌تر؛ ولی هاستی
    که ping را بسته از قلم می‌افتد)."""
    ports = list(ports or [])
    pings = {}
    if do_ping:
        def pg(ip):
            if cancel is not None and cancel.is_set():
                return None
            return ip, ping(ip, timeout + 0.5)
        pings = dict(_pool(targets, pg, workers, cancel, progress, "ping"))
    port_targets = [ip for ip in targets if pings.get(ip, {}).get("reachable")] if (do_ping and only_alive) else list(targets)
    prow = port_scan(port_targets, ports, timeout, workers, banners, http, cancel, progress, names=False) if ports else []
    up = [ip for ip in targets if pings.get(ip, {}).get("reachable")]
    up = list(dict.fromkeys(up + [r["ip"] for r in prow]))
    names = dict(_pool(up, lambda ip: (ip, reverse_dns(ip)), min(int(workers), 50), cancel, progress, "نام")) if up else {}

    def pinfo(ip):
        p = pings.get(ip)
        if not do_ping:
            return {"ping": "", "ping_ms": ""}
        if not p or not p.get("available"):
            return {"ping": "n/a", "ping_ms": ""}
        return {"ping": "yes" if p.get("reachable") else "no", "ping_ms": p.get("latency_ms") or ""}
    rows = []
    by_ip = {}
    for r in prow:
        by_ip.setdefault(r["ip"], []).append(r)
    for ip in up:
        base = {"ip": ip, "hostname": names.get(ip, ""), **pinfo(ip)}
        if by_ip.get(ip):
            rows += [{**base, **r, "hostname": base["hostname"]} for r in sorted(by_ip[ip], key=lambda x: x["port"])]
        else:
            rows.append({**base, "port": "", "service": "", "detected": "", "latency_ms": "", "banner": ""})
    return sorted(rows, key=lambda r: (_ipkey(r["ip"]), r["port"] if r["port"] != "" else -1))


SCAN_COLUMNS = ["ip", "hostname", "ping", "ping_ms", "port", "service", "detected", "latency_ms", "banner"]
DISCOVER_COLUMNS = ["ip", "hostname", "ping", "ping_ms", "tcp_open"]
PORT_COLUMNS = ["ip", "hostname", "port", "service", "detected", "latency_ms", "banner"]
HTTP_COLUMNS = ["http_status", "http_server", "http_title"]


# ------------------------------------------------------------------ Demo (بدون اتصال واقعی)
def demo_discover(targets):
    import random
    rnd = random.Random(len(targets))  # nosec B311 — داده‌ی نمایشی
    rows = []
    for ip in targets:
        if rnd.random() < 0.3:
            tcp = [p for p in DISCOVERY_PORTS if rnd.random() < 0.4]
            rows.append({"ip": ip, "hostname": f"host-{ip.replace('.', '-').replace(':', '-')}.lab", "ping": "yes",
                         "ping_ms": round(rnd.uniform(0.5, 9), 2), "tcp_open": " ".join(map(str, tcp))})
    return rows


def demo_ports(targets, ports, banners=False, http=False):
    import random
    rows = []
    for ip in targets:
        rnd = random.Random(ip)  # nosec B311 — داده‌ی نمایشی
        for p in ports:
            if rnd.random() < (0.35 if p in (22, 80, 443, 3389, 445) else 0.03):
                r = {"ip": ip, "hostname": f"host-{ip.replace('.', '-')}.lab", "port": p, "service": SERVICE_NAMES.get(p, "unknown"),
                     "latency_ms": round(rnd.uniform(0.3, 5), 2), "banner": "", "detected": ""}
                if banners and p == 22:
                    r["banner"], r["detected"] = "SSH-2.0-OpenSSH_8.9", "SSH"
                if http and p in HTTP_PORTS + HTTPS_PORTS:
                    r.update({"http_status": 200, "http_server": "nginx", "http_title": "Demo"})
                rows.append(r)
    return rows


def demo_scan(targets, do_ping, ports, only_alive=False, banners=False, http=False):
    import random
    alive = {r["ip"]: r for r in demo_discover(targets)} if do_ping else {}
    pt = [ip for ip in targets if ip in alive] if (do_ping and only_alive) else list(targets)
    prow = demo_ports(pt, ports, banners, http) if ports else []
    up = list(dict.fromkeys([ip for ip in targets if ip in alive] + [r["ip"] for r in prow]))
    rows = []
    for ip in up:
        rnd = random.Random(ip)  # nosec B311 — داده‌ی نمایشی
        base = {"ip": ip, "hostname": f"host-{ip.replace('.', '-')}.lab",
                "ping": ("yes" if ip in alive else "no") if do_ping else "", "ping_ms": round(rnd.uniform(0.5, 9), 2) if ip in alive else ""}
        mine = [r for r in prow if r["ip"] == ip]
        rows += [{**r, **base} for r in mine] or [{**base, "port": "", "service": "", "detected": "", "latency_ms": "", "banner": ""}]
    return rows
