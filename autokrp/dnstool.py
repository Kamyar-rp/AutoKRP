"""
ابزار DNS: لوکاپ روی رنج/لیست IP (PTR و رکوردهای نام به‌دست‌آمده) یا روی URL/دامنه (A، AAAA، ... و PTR آدرس‌ها).
بر پایه‌ی اسکریپت DNS Lookup کاربر؛ اجرای موازی، قابل توقف، با سقف تعداد.
"""
import ipaddress
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlsplit

MAX_TARGETS = 4096
MAX_CONCURRENCY = 100
IP_TYPES = ["PTR", "A", "CNAME", "NS", "MX", "TXT"]
URL_TYPES = ["A", "AAAA", "CNAME", "NS", "MX", "TXT", "PTR"]
DEFAULT_TYPES = {"ip": ["PTR", "A", "CNAME"], "url": ["A", "AAAA", "CNAME"]}
# ستون‌های پیش‌فرض ورودی از خروجی ابزار قبلی یا CSV (نام‌های استاندارد، بدون حساسیت به حروف)
IP_COLUMNS = ["src_ip", "src", "dest_ip", "dest", "ip"]
URL_COLUMNS = ["url", "http_url", "domain", "dest_host", "query", "host"]
_HOST = re.compile(r"^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?)(?:\.[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?)*$")


class DnsError(Exception):
    pass


# ------------------------------------------------------------------ ورودی
def _norm_ranges(text):
    return re.sub(r"\s*-\s*", "-", text or "")


def parse_ips(text, limit=MAX_TARGETS):
    """IP، رنج a-b، CIDR؛ جدا با خط، فاصله، ویرگول یا ;. خروجی: (ips, invalid)"""
    out, seen, bad = [], set(), []

    def add(ip):
        s = str(ip)
        if s not in seen:
            seen.add(s)
            out.append(s)
            if len(out) > limit:
                raise DnsError(f"تعداد آدرس‌ها بیشتر از سقف {limit} است. رنج را کوچک‌تر کنید.")

    for tok in re.split(r"[\s,;]+", _norm_ranges(text)):
        tok = tok.strip().strip('"\'')
        if not tok:
            continue
        try:
            if "-" in tok and "/" not in tok:
                a, b = tok.split("-", 1)
                s, e = ipaddress.ip_address(a), ipaddress.ip_address(b)
                if s.version != e.version or int(s) > int(e):
                    raise ValueError
                if int(e) - int(s) + 1 > limit:
                    raise DnsError(f"رنج {tok} بیشتر از سقف {limit} آدرس است.")
                for n in range(int(s), int(e) + 1):
                    add(ipaddress.ip_address(n))
            elif "/" in tok:
                net = ipaddress.ip_network(tok, strict=False)
                if net.num_addresses > limit:
                    raise DnsError(f"شبکه‌ی {tok} بیشتر از سقف {limit} آدرس است.")
                hosts = list(net.hosts()) if net.num_addresses > 2 else list(net)
                for ip in hosts:
                    add(ip)
            else:
                add(ipaddress.ip_address(tok))
        except DnsError:
            raise
        except ValueError:
            bad.append(tok)
    return out, bad


def host_of(value):
    """نام میزبان از URL یا دامنه. اگر IP بود، خود IP. نامعتبر: ''"""
    v = (value or "").strip().strip('"\'').strip()
    if not v:
        return ""
    if "://" not in v:
        v = "http://" + v.lstrip("/")
    try:
        h = urlsplit(v).hostname or ""
    except ValueError:
        return ""
    h = h.strip().rstrip(".").lower()
    try:
        return str(ipaddress.ip_address(h))
    except ValueError:
        pass
    try:
        h = h.encode("idna").decode("ascii")
    except UnicodeError:
        return ""
    return h if _HOST.match(h) else ""


def parse_hosts(values, limit=MAX_TARGETS):
    """خروجی: (hosts, invalid, first_url) — first_url: اولین مقدار اصلی هر میزبان"""
    out, first, bad = [], {}, []
    for v in values:
        for tok in re.split(r"[\s,;]+", v or ""):
            if not tok.strip():
                continue
            h = host_of(tok)
            if not h:
                bad.append(tok)
                continue
            if h not in first:
                first[h] = tok
                out.append(h)
                if len(out) > limit:
                    raise DnsError(f"تعداد میزبان‌ها بیشتر از سقف {limit} است.")
    return out, bad, first


def pick_column(columns, mode, wanted=""):
    """ستون ورودی: انتخاب کاربر یا اولین نام استاندارد موجود (بدون حساسیت به حروف)."""
    low = {c.lower(): c for c in columns}
    if wanted:
        c = low.get(wanted.strip().lower())
        if not c:
            raise DnsError(f"ستون «{wanted}» در ورودی نیست. ستون‌ها: {', '.join(columns[:30])}")
        return c
    for c in (IP_COLUMNS if mode == "ip" else URL_COLUMNS):
        if c in low:
            return low[c]
    raise DnsError(f"ستونی با نام استاندارد ({', '.join(IP_COLUMNS if mode == 'ip' else URL_COLUMNS)}) در ورودی نیست. "
                   f"ستون‌ها: {', '.join(columns[:30])}. نام ستون را در ابزار وارد کنید یا در کوئری rename کنید.")


# ------------------------------------------------------------------ لوکاپ
class Lookup:
    def __init__(self, server="", timeout=5, max_records=3):
        import dns.resolver
        self.r = dns.resolver.Resolver()
        servers = [s.strip() for s in re.split(r"[\s,;]+", server or "") if s.strip()]
        if servers:
            for s in servers:
                try:
                    ipaddress.ip_address(s)
                except ValueError:
                    raise DnsError(f"آدرس سرور DNS نامعتبر است: {s}")
            self.r.nameservers = servers
        t = max(1.0, float(timeout or 5))
        self.r.timeout = t
        self.r.lifetime = t
        self.max = max(1, min(10, int(max_records or 3)))
        self.server_used = ", ".join(str(x) for x in self.r.nameservers)

    def query(self, name, rtype):
        """(records, status): status: OK | NXDOMAIN | NO_ANSWER | TIMEOUT | ERROR"""
        import dns.exception
        import dns.resolver
        import dns.reversename
        try:
            qname = dns.reversename.from_address(name) if rtype == "PTR" else name
            ans = self.r.resolve(qname, rtype)
        except dns.resolver.NXDOMAIN:
            return [], "NXDOMAIN"
        except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            return [], "NO_ANSWER"
        except (dns.exception.Timeout, dns.resolver.LifetimeTimeout):
            return [], "TIMEOUT"
        except Exception:
            return [], "ERROR"
        out = []
        for a in ans:
            if rtype == "TXT":
                v = b"".join(a.strings).decode("utf-8", "replace")
            else:
                v = a.to_text().strip().rstrip(".")
            if v not in out:
                out.append(v)
            if len(out) >= self.max:
                break
        return out, "OK"

    # -------------------------------------------------- یک ورودی
    def for_ip(self, ip, types):
        t0 = time.time()
        res = {t: [] for t in types}
        ptr, st = self.query(ip, "PTR")
        if "PTR" in res:
            res["PTR"] = ptr
        host = ptr[0] if ptr else ""
        if host:
            for t in types:
                if t != "PTR":
                    res[t], _ = self.query(host, t)
        match = ""
        if host:
            rt = "AAAA" if ":" in ip else "A"
            addrs = res.get(rt) if rt in res else self.query(host, rt)[0]

            def _n(x):
                try:
                    return str(ipaddress.ip_address(str(x).strip()))
                except ValueError:
                    return str(x).strip()
            match = "YES" if _n(ip) in {_n(a) for a in addrs or []} else "NO"
        status = "PTR_FOUND" if ptr else {"NXDOMAIN": "NO_PTR", "NO_ANSWER": "NO_PTR"}.get(st, st)
        return {"input": ip, "host": host, "res": res, "match": match, "status": status,
                "time": round(time.time() - t0, 3), "ips": [ip]}

    def for_host(self, host, types):
        t0 = time.time()
        res = {t: [] for t in types}
        try:
            ipaddress.ip_address(host)
            return self.for_ip(host, ["PTR"] + [t for t in types if t not in ("PTR", "AAAA")]) | {"kind": "ip"}
        except ValueError:
            pass
        a, st = self.query(host, "A")
        aaaa = self.query(host, "AAAA")[0] if ("AAAA" in res or not a) else []
        if "A" in res:
            res["A"] = a
        if "AAAA" in res:
            res["AAAA"] = aaaa
        for t in types:
            if t in ("A", "AAAA", "PTR"):
                continue
            res[t], s2 = self.query(host, t)
            if t == "CNAME" and st != "OK" and s2 == "OK":
                st = "OK"
        if "PTR" in res:
            ptrs = []
            for ip in (a + aaaa)[:self.max]:
                for p in self.query(ip, "PTR")[0]:
                    if p not in ptrs:
                        ptrs.append(p)
            res["PTR"] = ptrs[:self.max]
        ok = bool(a or aaaa)
        status = "RESOLVED" if ok else ({"OK": "NO_ADDRESS"}.get(st, st))
        return {"input": host, "host": host, "res": res, "match": "", "status": status,
                "time": round(time.time() - t0, 3), "ips": a + aaaa}


def run_lookup(mode, targets, types, cfg, cancel=None, progress=None, first_url=None):
    """
    mode: "ip" | "url". خروجی: (columns, rows, ips, summary)
    """
    types = [t for t in (IP_TYPES if mode == "ip" else URL_TYPES) if t in (types or DEFAULT_TYPES[mode])]
    if not types:
        raise DnsError("هیچ نوع رکوردی برای خروجی انتخاب نشده است.")
    lk = Lookup(cfg.get("server", ""), cfg.get("timeout", 5), cfg.get("max_records", 3))
    conc = max(1, min(MAX_CONCURRENCY, int(cfg.get("concurrency") or 20)))
    results = [None] * len(targets)
    done = 0
    lock = threading.Lock()
    fn = lk.for_ip if mode == "ip" else lk.for_host
    with ThreadPoolExecutor(max_workers=conc) as ex:
        futs = {ex.submit(fn, t, types): i for i, t in enumerate(targets)}
        for f in as_completed(futs):
            i = futs[f]
            try:
                results[i] = f.result()
            except Exception as e:  # نباید رخ دهد
                results[i] = {"input": targets[i], "host": "", "res": {t: [] for t in types}, "match": "",
                              "status": "ERROR", "time": 0, "ips": [], "error": str(e)}
            with lock:
                done += 1
                if progress:
                    progress(done, len(targets), targets[i])
            if cancel is not None and cancel.is_set():
                for x in futs:
                    x.cancel()
                break
    if cancel is not None and cancel.is_set():
        raise InterruptedError()
    n = lk.max
    cols = ["IP"] if mode == "ip" else ["URL", "Host"]
    for t in types:
        cols += [f"{t}_{k}" for k in range(1, n + 1)]
    if mode == "ip":
        cols.append("Match")
    cols += ["Status", "DNS_Server", "Response_Time"]
    rows, ips, found = [], [], 0
    for r in results:
        row = {"IP": r["input"]} if mode == "ip" else {"URL": (first_url or {}).get(r["input"], r["input"]), "Host": r["input"]}
        for t in types:
            vals = r["res"].get(t, [])
            for k in range(n):
                row[f"{t}_{k + 1}"] = vals[k] if k < len(vals) else ""
        if mode == "ip":
            row["Match"] = r["match"]
        row.update(Status=r["status"], DNS_Server=lk.server_used, Response_Time=r["time"])
        rows.append(row)
        if r["status"] in ("PTR_FOUND", "RESOLVED"):
            found += 1
        for ip in r["ips"]:
            if ip not in ips:
                ips.append(ip)
    statuses = {}
    for r in rows:
        statuses[r["Status"]] = statuses.get(r["Status"], 0) + 1
    summary = {"mode": mode, "total": len(rows), "found": found, "statuses": statuses, "server": lk.server_used}
    return cols, rows, ips, summary
