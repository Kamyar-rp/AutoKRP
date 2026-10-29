"""FortiGate: منطق fortigate.py اصلی (Address Objects، Banned list، ignore، ban با add_users)."""
import ipaddress
import time

from .base import BaseConnector, ConnectorError

TARGET_HEADERS = {"ip", "ip_address", "address", "network", "target"}


def parse_address_objects(results):
    """همان منطق get_firewall_addresses: subnet به network، start-ip/end-ip به range."""
    out = []
    for item in results:
        name = item.get("name", "")
        if str(item.get("comment") or "").startswith("AutoKRP"):
            continue        # 1.28: ساخته‌ی سناریوهای خود برنامه؛ «Address خودی» نیست
        subnet = item.get("subnet", "")
        atype = item.get("type", "")
        if subnet:
            parts = subnet.split()
            if len(parts) >= 2:
                try:
                    net = ipaddress.ip_network(f"{parts[0]}/{parts[1]}", strict=False)
                    out.append({"name": name, "type": atype, "object": "subnet", "value": subnet, "network": str(net)})
                    continue
                except ValueError:
                    pass
        start_ip, end_ip = item.get("start-ip"), item.get("end-ip")
        if start_ip:
            try:
                s = ipaddress.ip_address(start_ip)
                e = ipaddress.ip_address(end_ip) if end_ip else s
                out.append({"name": name, "type": atype, "object": "range", "value": f"{s} - {e}", "network": f"{s} - {e}"})
            except ValueError:
                pass
    return out


def ip_matches_address(target_ip, address):
    try:
        target = ipaddress.ip_address(target_ip)
    except ValueError:
        return False
    if address["object"] == "subnet":
        try:
            net = ipaddress.ip_network(address["network"], strict=False)
            if net.version == 4 and net.prefixlen == 0:   # 0.0.0.0/0 را تطابق حساب نکن
                return False
            return target in net
        except (ValueError, TypeError):
            return False
    if address["object"] == "range":
        try:
            a, b = address["network"].split("-")
            return ipaddress.ip_address(a.strip()) <= target <= ipaddress.ip_address(b.strip())
        except (ValueError, IndexError, TypeError):
            return False
    return False


def is_excluded(ip, nets) -> bool:
    """IP خصوصی/غیرعمومی یا داخل «رنج‌های مستثنا» — در هیچ بخشی (فهرست، بررسی، بلاک) استفاده نمی‌شود."""
    from .abuseipdb import should_skip_ip
    return should_skip_ip(str(ip)) or is_ignored(str(ip), nets)


def parse_ignore(networks):
    out, bad = [], []
    for n in networks or []:
        n = str(n).split("#", 1)[0].strip()   # توضیح بعد از # نادیده گرفته می‌شود
        if not n:
            continue
        try:
            out.append(ipaddress.ip_network(n, strict=False))
        except ValueError:
            bad.append(n)
    return out, bad


def is_ignored(ip, ignore_nets):
    try:
        t = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(t.version == n.version and t in n for n in ignore_nets)


def expand_targets(values, max_expand=256):
    """معادل read_target_ips: IP تکی یا CIDR (IPv4). IPv6 شبکه رد می‌شود. سقف بسط CIDR."""
    targets, notes = [], []
    for value in values:
        value = str(value).strip()
        if not value or value.lower() in TARGET_HEADERS:
            continue
        try:
            targets.append(str(ipaddress.ip_address(value)))
            continue
        except ValueError:
            pass
        try:
            net = ipaddress.ip_network(value, strict=False)
        except ValueError:
            notes.append(("invalid", value))
            continue
        if net.version != 4:
            notes.append(("ipv6_net", str(net)))
            continue
        hosts = list(net) if net.prefixlen >= 31 else list(net.hosts())
        if max_expand and len(hosts) > max_expand:
            notes.append(("too_big", f"{net} ({len(hosts)} آدرس)"))
            continue
        targets.extend(str(h) for h in hosts)
        notes.append(("expanded", f"{net} → {len(hosts)} آدرس"))
    return list(dict.fromkeys(targets)), notes


_BUCKET_SHIFT = {4: 16, 6: 96}   # IPv4: سطل‌های /16 — IPv6: سطل‌های /32
_MAX_BUCKETS = 256               # بازه‌ی بزرگ‌تر از این تعداد سطل، در فهرست «پهن» می‌رود و جدا بررسی می‌شود


class _AddrIndex:
    """
    نمایه‌ی Address Objectها برای جستجوی سریع: هر بازه در سطل‌های پیشوندی که پوشش می‌دهد ثبت می‌شود.
    خروجی دقیقاً مثل مقایسه‌ی خطی قبلی است (همان Addressها، به همان ترتیب)؛ فقط به‌جای
    مقایسه‌ی هر IP با همه‌ی Addressها، فقط چند Address هم‌سطل بررسی می‌شوند.
    """
    def __init__(self, nets, ranges):
        self.buckets, self.wide = {}, []
        items = [(0, i, n.version, int(n.network_address), int(n.broadcast_address), a) for i, (n, a) in enumerate(nets)]
        items += [(1, i, lo.version, int(lo), int(hi), a) for i, (lo, hi, a) in enumerate(ranges) if lo.version == hi.version]
        for it in items:
            v, lo, hi = it[2], it[3], it[4]
            sh = _BUCKET_SHIFT[v]
            b0, b1 = lo >> sh, hi >> sh
            if b1 - b0 >= _MAX_BUCKETS:
                self.wide.append(it)
            else:
                for b in range(b0, b1 + 1):
                    self.buckets.setdefault((v, b), []).append(it)

    def match(self, ip):
        x, v = int(ip), ip.version
        found = [it for it in self.buckets.get((v, x >> _BUCKET_SHIFT[v]), ()) if it[3] <= x <= it[4]]
        found += [it for it in self.wide if it[2] == v and it[3] <= x <= it[4]]
        found.sort(key=lambda it: (it[0], it[1]))
        return [it[5] for it in found]


def _compile_addresses(addresses):
    """Address Objectها یک بار parse می‌شوند (برای بررسی هزاران IP سریع باشد). همان قواعد ip_matches_address."""
    nets, ranges = [], []
    for a in addresses:
        try:
            if a["object"] == "subnet":
                n = ipaddress.ip_network(a["network"], strict=False)
                if n.version == 4 and n.prefixlen == 0:   # 0.0.0.0/0 تطابق حساب نمی‌شود
                    continue
                nets.append((n, a))
            elif a["object"] == "range":
                lo, hi = a["network"].split("-")
                ranges.append((ipaddress.ip_address(lo.strip()), ipaddress.ip_address(hi.strip()), a))
        except (ValueError, TypeError, KeyError):
            continue
    return nets, ranges


def is_admin_source(source) -> bool:
    """بلاک دستی/API (FortiGate: source = «Administrative»)؛ بقیه (IPS، DoS، Application Control، ...) خودکارند."""
    return str(source or "").strip().lower().startswith("admin")


def _expiry_val(v):
    """expires فیلد لیست Banned: ۰ یا خالی = بدون انقضا. None اگر فیلد نیست/قابل خواندن نیست."""
    if v in (None, ""):
        return None
    try:
        return int(float(v))
    except (TypeError, ValueError):
        return None


def needs_convert(item, want_expiry=0) -> str:
    """دلیل تبدیل بلاک موجود به بلاک Administrative (یا "" اگر لازم نیست).
    فقط وقتی خواسته‌ی ما بدون انقضاست، انقضای یک بلاک Administrative هم دلیل تبدیل است."""
    src = str(item.get("source") or "").strip()
    if src and not is_admin_source(src):
        return f"بلاک خودکار {src}"
    exp = _expiry_val(item.get("expires"))
    if int(want_expiry or 0) == 0 and exp:
        return "بلاک با انقضا"
    return ""


def classify(targets, addresses, banned, ignore_nets, want_expiry=0, convert=True):
    """
    تصمیم برای هر IP، دقیقاً به ترتیب اسکریپت:
      ignored  ← در رنج‌های exclude
      address  ← با یک یا چند Address Object تطابق دارد (بلاک نمی‌شود)
      convert  ← در Banned هست ولی بلاک خودکار (IPS، Application Control، ...) یا با انقضاست؛ دائمی و Administrative شود
      banned   ← از قبل در لیست Banned/Quarantine است
      ban      ← هیچ‌کدام؛ باید بلاک شود
    """
    banned_set, banned_item = set(), {}
    for b in banned:
        try:
            a = ipaddress.ip_address(str(b.get("ip", "")).strip())
            banned_set.add(a)
            banned_item[a] = b
        except ValueError:
            pass
    nets, ranges = _compile_addresses(addresses)
    index = _AddrIndex(nets, ranges)
    plan = []
    for t in targets:
        try:
            ip = ipaddress.ip_address(str(t).strip())
        except ValueError:
            plan.append({"ip": t, "decision": "invalid", "detail": "IP نامعتبر"})
            continue
        if is_ignored(ip, ignore_nets):
            plan.append({"ip": str(ip), "decision": "ignored", "detail": "در رنج‌های مستثنا (داخلی)"})
            continue
        matches = index.match(ip)
        in_banned = ip in banned_set
        why = needs_convert(banned_item.get(ip) or {}, want_expiry) if in_banned and convert and not matches else ""
        if why:
            plan.append({"ip": str(ip), "decision": "convert", "in_banned": True,
                         "detail": f"در Banned هست ولی {why}؛ پاک و دوباره به‌صورت Administrative بلاک می‌شود",
                         "source": (banned_item.get(ip) or {}).get("source", ""),
                         "expires": (banned_item.get(ip) or {}).get("expires", "")})
            continue
        if matches or in_banned:
            parts = []
            if matches:
                parts.append("Address: " + "، ".join(f"{m['name']} ({m['network']})" for m in matches))
            if in_banned:
                parts.append("از قبل در لیست Banned")
            plan.append({"ip": str(ip), "decision": "address" if matches else "banned", "detail": " | ".join(parts),
                         "in_banned": in_banned, "addresses": [m["name"] for m in matches]})
            continue
        plan.append({"ip": str(ip), "decision": "ban", "detail": "در Address و Banned نیست"})
    return plan


class FortiClient(BaseConnector):
    NAME = "fortigate"

    def __init__(self, cfg, cancel_event=None):
        super().__init__(cfg, cancel_event)
        self.s.headers.update({"Accept": "application/json", "Content-Type": "application/json"})
        self.timeout = float(cfg.get("timeout") or 10)
        self.vdom = cfg.get("vdom") or "root"

    def _get(self, endpoint, params=None):
        self.require_credentials()
        r = self.s.get(f"{self.base_url()}/{endpoint.lstrip('/')}", params=params, timeout=self.timeout)
        r.raise_for_status()
        try:
            return r.json()
        except ValueError:
            raise ConnectorError(f"FortiGate پاسخ JSON نامعتبر برگرداند: {r.text[:300]}")

    def test(self) -> dict:
        self.last_banned = self.get_banned()      # برای هماهنگ کردن وضعیت بلاک دیتابیس (worker)
        return {"message": f"اتصال برقرار است. {len(self.last_banned)} IP در لیست Banned (VDOM {self.vdom})."}

    def get_addresses(self, log=None):
        count = int(self.cfg.get("address_count") or 10000)
        results, start = [], 0
        while True:
            self.check_cancel()
            data = self._get("/api/v2/cmdb/firewall/address", {"vdom": self.vdom, "start": start, "count": count})
            page = data.get("results", []) or []
            results.extend(page)
            if len(page) < count:
                break
            start += count
            if log:
                log(f"Address Objectها بیش از {start} مورد است؛ صفحه‌ی بعد دریافت می‌شود", "info")
        return parse_address_objects(results), len(results)

    def get_banned(self):
        data = self._get("/api/v2/monitor/user/banned", {"vdom": self.vdom})
        out = []
        for item in data.get("results", []) or []:
            ip = item.get("ip_address", "")
            if ip:
                out.append({"ip": ip, "created": item.get("created", ""), "source": item.get("source", ""),
                            "expires": item.get("expires", ""), "ipv6": item.get("ipv6", "")})
        return out

    def _post(self, action, body):
        self.require_credentials()
        r = self.s.post(f"{self.base_url()}/api/v2/monitor/user/banned/{action}",
                        params={"vdom": self.vdom}, json=body, timeout=self.timeout)
        try:
            result = r.json()
        except ValueError:
            result = r.text
        if r.status_code >= 400:
            return False, f"HTTP {r.status_code}: {str(result)[:300]}"
        if self.cfg.get("check_json_status", True) and isinstance(result, dict) and "status" in result:
            if str(result.get("status")).lower() != "success":
                return False, f"FortiGate status={result.get('status')}: {str(result)[:300]}"
        return True, str(result)[:300]

    def api_request(self, method, path, body=None, params=None):
        """1.28 سناریوها: درخواست به API همین دستگاه (فقط زیر /api/v2/، با vdom). خروجی: (HTTP status, JSON یا متن)."""
        self.require_credentials()
        if not str(path).startswith("/api/v2/") or ".." in str(path):
            raise ConnectorError(f"مسیر نامعتبر: {path}")
        r = self.s.request(method, f"{self.base_url()}{path}", params={**(params or {}), "vdom": self.vdom},
                           json=body if body is not None and method != "GET" else None, timeout=self.timeout)
        try:
            return r.status_code, r.json()
        except ValueError:
            return r.status_code, r.text

    def api_ok(self, status, data):
        if status >= 400:
            return False, f"HTTP {status}: {str(data)[:300]}"
        if self.cfg.get("check_json_status", True) and isinstance(data, dict) and "status" in data:
            if str(data.get("status")).lower() != "success":
                return False, f"FortiGate status={data.get('status')}: {str(data)[:300]}"
        return True, str(data)[:300]

    def unban_ip(self, ip):
        """حذف از لیست Banned/Quarantine (clear_users)."""
        return self._post("clear_users", {"ip_addresses": [ip]})

    def convert_ip(self, ip):
        """بلاک خودکار (IPS/...) یا موقت ← بلاک Administrative با expiry تنظیم‌شده: پاک و دوباره اضافه.
        اگر افزودن دوباره ناموفق بود یک بار دیگر تلاش می‌شود تا IP بی‌بلاک نماند."""
        ok, detail = self.unban_ip(ip)
        if not ok:
            return False, "پاک کردن بلاک قبلی ناموفق: " + detail
        ok, detail = self.ban_ip(ip)
        if not ok:
            time.sleep(1)
            ok, detail2 = self.ban_ip(ip)
            if not ok:
                return False, f"بلاک قبلی پاک شد ولی بلاک دوباره ناموفق بود (IP الان بلاک نیست!): {detail2}"
            detail = detail2
        return True, detail

    def ban_ip(self, ip):
        """True/False و متن پاسخ. معادل ban_ip اسکریپت + بررسی status در JSON (اختیاری)."""
        return self._post("add_users", {"ip_addresses": [ip], "expiry": int(self.cfg.get("ban_expiry") or 0)})
