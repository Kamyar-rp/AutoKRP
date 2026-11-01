"""1.40: ابزار API (شبیه Bruno/Insomnia، ساده): اتصال = آدرس پایه + نوع احراز (رمز و توکن در vault)؛ درخواست با متد، مسیر،
پارامتر، هدر و Body؛ پاسخ مرتب برای رابط و لاگ در پایگاه داده (رمزها و توکن‌ها ماسک‌شده).
فقط http و https. دنبال کردن redirect به میزبان دیگر هدر Authorization را نمی‌برد (رفتار requests)."""
import json
import re
import time
from urllib.parse import urlencode, urlsplit

METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE")
AUTHS = ("none", "basic", "bearer", "header", "query")
BODY_TYPES = ("json", "text", "form", "none")
MAX_RESP = 5 * 1024 * 1024          # پاسخ برای رابط (بیشتر از این بریده می‌شود)
MAX_BODY = 2 * 1024 * 1024          # بدنه‌ی درخواست
LOG_HEAD = 4096                     # ابتدای پاسخ در لاگ
CONN_MAX = 300
REQ_MAX = 2000
SENSITIVE = re.compile(r"(pass|secret|token|key|auth|cookie|session|credential|signature)", re.I)
MASK = "••••"


class ApiError(ValueError):
    pass


def _txt(v, n):
    return re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", str(v or "")).strip()[:n]


def clean_base(url):
    u = _txt(url, 500).rstrip("/")
    p = urlsplit(u)
    if p.scheme not in ("http", "https") or not p.netloc:
        raise ApiError("آدرس پایه باید با http:// یا https:// شروع شود (مثلاً https://fw1.example/api/v2).")
    if p.username or p.password:
        raise ApiError("نام کاربری و رمز را در آدرس ننویسید؛ در «احراز هویت» وارد کنید.")
    if p.query or p.fragment:
        raise ApiError("آدرس پایه نباید پارامتر (?…) یا # داشته باشد؛ پارامترها را در درخواست وارد کنید.")
    return u


def clean_kv(rows, n=100):
    """[[نام، مقدار، روشن؟]…] ← فهرست تمیز (حداکثر ۱۰۰ ردیف)."""
    out = []
    for r in (rows if isinstance(rows, list) else [])[:n]:
        if isinstance(r, dict):
            r = [r.get("k"), r.get("v"), r.get("on", True)]
        if not isinstance(r, (list, tuple)) or not r:
            continue
        k = _txt(r[0], 200)
        if not k or "\r" in str(r[0]) or "\n" in str(r[0]):
            continue
        v = re.sub(r"[\r\n]", " ", str(r[1] if len(r) > 1 and r[1] is not None else ""))[:4000]
        out.append([k, v, bool(r[2]) if len(r) > 2 else True])
    return out


def clean_conn(p):
    p = p if isinstance(p, dict) else {}
    name = _txt(p.get("name"), 80)
    if not name:
        raise ApiError("نام اتصال را وارد کنید.")
    auth = p.get("auth") if p.get("auth") in AUTHS else "none"
    key_name = _txt(p.get("key_name"), 100)
    if auth in ("header", "query") and not re.match(r"^[A-Za-z0-9_.\-]{1,100}$", key_name or ""):
        raise ApiError("نام هدر یا پارامتر کلید را وارد کنید (مثلاً X-API-Key یا access_token).")
    try:
        timeout = max(2, min(300, int(p.get("timeout") or 30)))
    except (TypeError, ValueError):
        timeout = 30
    hdr = clean_kv(p.get("headers"), 50)
    return {"name": name, "base_url": clean_base(p.get("base_url")), "auth": auth, "key_name": key_name if auth in ("header", "query") else "",
            "verify": 0 if p.get("verify") is False else 1, "timeout": timeout, "headers": json.dumps(hdr, ensure_ascii=False),
            "notes": _txt(p.get("notes"), 500)}


def clean_req(p):
    p = p if isinstance(p, dict) else {}
    m = str(p.get("method") or "GET").upper()
    if m not in METHODS:
        raise ApiError("متد نامعتبر است.")
    path = _txt(p.get("path"), 2000)
    if re.match(r"^[a-z][a-z0-9+.\-]*://", path, re.I):
        raise ApiError("مسیر باید نسبت به آدرس پایه‌ی اتصال باشد (مثلاً /monitor/system/status)، نه آدرس کامل.")
    if "\r" in path or "\n" in path:
        raise ApiError("مسیر نامعتبر است.")
    body = str(p.get("body") or "")
    if len(body.encode("utf-8")) > MAX_BODY:
        raise ApiError("حداکثر حجم Body دو مگابایت است.")
    bt = p.get("body_type") if p.get("body_type") in BODY_TYPES else "json"
    return {"method": m, "path": path, "params": clean_kv(p.get("params")), "headers": clean_kv(p.get("headers")), "body": body, "body_type": bt}


def join_url(base, path):
    if not path:
        return base
    return base + ("" if path.startswith("/") or path.startswith("?") else "/") + path


def mask_value(k, v):
    return MASK if SENSITIVE.search(str(k)) else v


def mask_url(url, secret_keys=()):
    """پارامترهای حساس آدرس (token، key، …) و کلید احراز «query» ماسک می‌شوند."""
    def sub(m):
        k = m.group(2)
        return m.group(1) + k + "=" + (MASK if SENSITIVE.search(k) or k in secret_keys else m.group(3))
    return re.sub(r"([?&])([^=&#]+)=([^&#]*)", sub, url)


def mask_body(body, secrets=()):
    """بدنه‌ی JSON: مقدار کلیدهای حساس؛ هر متن: خود رمز و توکن اتصال اگر در متن آمده باشد."""
    s = str(body or "")
    try:
        d = json.loads(s)

        def walk(x):
            if isinstance(x, dict):
                return {k: (MASK if SENSITIVE.search(str(k)) and isinstance(v, (str, int, float)) else walk(v)) for k, v in x.items()}
            if isinstance(x, list):
                return [walk(v) for v in x]
            return x
        s = json.dumps(walk(d), ensure_ascii=False)
    except (ValueError, TypeError):
        s = re.sub(r'((?:password|passwd|secret|token|api[_-]?key)\s*[=:]\s*)[^&\s,;"]+', r"\1" + MASK, s, flags=re.I)
    for sec in secrets:
        if sec and len(sec) >= 4:
            s = s.replace(sec, MASK)
    return s


def build(conn, secret, username, req):
    """درخواست نهایی: (url, headers, data, auth_tuple, query_items). اسرار فقط اینجا اضافه می‌شوند."""
    url = join_url(conn["base_url"], req["path"])
    headers = {}
    for k, v, on in json.loads(conn.get("headers") or "[]"):
        if on:
            headers[k] = v
    for k, v, on in req["headers"]:
        if on:
            headers[k] = v
    params = [(k, v) for k, v, on in req["params"] if on]
    auth = None
    a = conn.get("auth") or "none"
    if a == "basic":
        auth = (username or "", secret or "")
    elif a == "bearer" and secret:
        headers["Authorization"] = "Bearer " + secret
    elif a == "header" and secret:
        headers[conn["key_name"]] = secret
    elif a == "query" and secret:
        params.append((conn["key_name"], secret))
    data = None
    if req["method"] in ("POST", "PUT", "PATCH", "DELETE") and req["body_type"] != "none" and req["body"]:
        if req["body_type"] == "json":
            try:
                json.loads(req["body"])
            except ValueError as e:
                raise ApiError(f"Body یک JSON معتبر نیست: {e}")
            headers.setdefault("Content-Type", "application/json")
        elif req["body_type"] == "form":
            headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
        else:
            headers.setdefault("Content-Type", "text/plain; charset=utf-8")
        data = req["body"].encode("utf-8")
    headers.setdefault("Accept", "application/json, */*;q=0.5")
    headers.setdefault("User-Agent", "AutoKRP-API")
    return url, headers, data, auth, params


def send(conn, secret, username, req, session_factory=None):
    """ارسال؛ خروجی: dict برای رابط (status، زمان، هدرها، متن پاسخ بریده‌شده، JSON بودن) + اطلاعات لاگ."""
    import requests
    url, headers, data, auth, params = build(conn, secret, username, req)
    full = url + (("&" if "?" in url else "?") + urlencode(params) if params else "")
    t0 = time.perf_counter()
    qkeys = (conn.get("key_name"),) if conn.get("auth") == "query" else ()
    out = {"url": mask_url(full, qkeys), "method": req["method"]}
    try:
        s = session_factory() if session_factory else requests.Session()
        s.trust_env = False              # پروکسی سیستم نه؛ مستقیم به دستگاه
        with s:
            r = s.request(req["method"], url, params=params, headers=headers, data=data, auth=auth, timeout=conn.get("timeout") or 30,
                          verify=bool(conn.get("verify", 1)), stream=True, allow_redirects=True)
            buf, size, trunc = bytearray(), 0, False
            for chunk in r.iter_content(65536):
                size += len(chunk)
                if len(buf) < MAX_RESP:
                    buf += chunk[:MAX_RESP - len(buf)]
                else:
                    trunc = True
                if size > 50 * MAX_RESP:      # بیش از ۲۵۰ مگابایت: ادامه نمی‌دهیم
                    trunc = True
                    break
            enc = r.encoding or "utf-8"
            try:
                text = bytes(buf).decode(enc, errors="replace")
            except LookupError:
                text = bytes(buf).decode("utf-8", errors="replace")
            ct = r.headers.get("Content-Type", "")
            is_json = False
            if "json" in ct.lower() or text[:1] in "{[":
                try:
                    json.loads(text)
                    is_json = True
                except ValueError:
                    pass
            out.update(status=r.status_code, reason=r.reason or "", headers=[[k, v] for k, v in r.headers.items()], body=text,
                       json=is_json, size=size, truncated=trunc, content_type=ct, final_url=mask_url(r.url, qkeys) if r.url != full else "")
    except requests.exceptions.SSLError as e:
        out.update(error="خطای گواهی TLS (اگر گواهی دستگاه خودامضاست، «بررسی گواهی» را در اتصال خاموش کنید): " + str(e)[:300])
    except requests.exceptions.ConnectTimeout:
        out.update(error="مهلت اتصال تمام شد (دستگاه پاسخ نداد).")
    except requests.exceptions.ReadTimeout:
        out.update(error="مهلت خواندن پاسخ تمام شد.")
    except requests.exceptions.ConnectionError as e:
        out.update(error="اتصال برقرار نشد: " + str(e)[:300])
    except requests.exceptions.RequestException as e:
        out.update(error="خطای درخواست: " + str(e)[:300])
    out["ms"] = int((time.perf_counter() - t0) * 1000)
    secrets = [secret] if secret else []
    out["log"] = {"url": out["url"],
                  "req_headers": json.dumps([[k, mask_value(k, v) if k.lower() != "content-type" else v] for k, v in headers.items()], ensure_ascii=False),
                  "req_body": mask_body(data.decode("utf-8", "replace"), secrets)[:65536] if data else "",
                  "resp_head": mask_body(out.get("body", "")[:LOG_HEAD], secrets)[:LOG_HEAD] if "body" in out else "",
                  "status": out.get("status"), "ms": out["ms"], "size": out.get("size"), "error": out.get("error", "")}
    # متن پاسخ در رابط همان پاسخ واقعی دستگاه است؛ فقط لاگ ماسک می‌شود
    return out
