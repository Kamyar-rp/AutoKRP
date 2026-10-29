"""ورود با Active Directory در حالت سرور (1.24) — LDAPS یا LDAP + StartTLS (LDAP ساده پشتیبانی نمی‌شود).

- رمز کاربر فقط برای bind به خود DC فرستاده می‌شود و هیچ‌جا ذخیره نمی‌شود.
- نقش از عضویت در سه گروه تنظیم‌شده: ادمین ← اپراتور ← فقط‌خواندنی (اولین گروهی که کاربر عضوش باشد).
  عضویت مستقیم از memberOf؛ عضویت تودرتو با قاعده‌ی LDAP_MATCHING_RULE_IN_CHAIN مایکروسافت (1.2.840.113556.1.4.1941)
  که فقط AD می‌شناسد (روی سرور دیگر نادیده گرفته می‌شود).
- چون کلید داده‌ها فقط از رمز کاربران محلی (یا «باز شدن خودکار») باز می‌شود، کاربر AD فقط وقتی سرور باز است وارد می‌شود.
- پیکربندی در تنظیمات رمزشده (settings «ad»)؛ چیزی در فایل ساده‌ی .server_auth.json جز نام کاربر و نقش نمی‌رود.
"""
import re
import ssl

DEFAULTS = {"enabled": False, "urls": "", "starttls": False, "domain": "", "bind_format": "{user}@{domain}", "base_dn": "",
            "user_filter": "(&(objectClass=user)(sAMAccountName={user}))",
            "group_admin": "", "group_operator": "", "group_readonly": "", "ca_pem": "", "timeout": 8}
ROLE_ORDER = (("admin", "group_admin"), ("operator", "group_operator"), ("readonly", "group_readonly"))
USER_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
IN_CHAIN = "1.2.840.113556.1.4.1941"
INVALID_CREDENTIALS = 49


class ADError(Exception):
    """پیام فارسی قابل نمایش."""


class ADBadCredentials(ADError):
    pass


def cfg_of(settings):
    c = dict(DEFAULTS)
    c.update({k: v for k, v in (settings.get("ad") or {}).items() if k in DEFAULTS})
    return c


def parse_urls(s):
    out = []
    for u in re.split(r"[\s,;]+", str(s or "").strip()):
        if not u:
            continue
        m = re.fullmatch(r"(ldaps?)://([A-Za-z0-9.\-]+|\[[0-9A-Fa-f:]+\])(?::(\d{1,5}))?/?", u)
        if not m:
            raise ADError(f"آدرس سرور نامعتبر است: {u} (مثلاً ldaps://dc1.corp.local:636)")
        tls = m.group(1) == "ldaps"
        port = int(m.group(3) or (636 if tls else 389))
        if not 0 < port < 65536:
            raise ADError(f"پورت نامعتبر: {u}")
        out.append((m.group(2).strip("[]"), port, tls))
    return out[:5]


def clean(c):
    """اعتبارسنجی تنظیمات از رابط."""
    c = {**DEFAULTS, **{k: v for k, v in (c or {}).items() if k in DEFAULTS}}
    c["enabled"] = bool(c["enabled"])
    c["starttls"] = bool(c["starttls"])
    for k in ("urls", "domain", "bind_format", "base_dn", "user_filter", "group_admin", "group_operator", "group_readonly"):
        c[k] = str(c[k] or "").strip()[:1000]
    c["ca_pem"] = str(c["ca_pem"] or "").strip()[:20000]
    try:
        c["timeout"] = max(2, min(30, int(c["timeout"] or 8)))
    except (TypeError, ValueError):
        c["timeout"] = 8
    if not c["enabled"]:
        return c
    urls = parse_urls(c["urls"])
    if not urls:
        raise ADError("دست‌کم یک آدرس سرور (Domain Controller) لازم است.")
    if any(not tls for _, _, tls in urls) and not c["starttls"]:
        raise ADError("LDAP بدون رمزنگاری مجاز نیست: ldaps:// یا StartTLS را روشن کنید.")
    if "{user}" not in c["bind_format"]:
        raise ADError("قالب نام ورود باید {user} داشته باشد.")
    if "{user}" not in c["user_filter"] or not (c["user_filter"].startswith("(") and c["user_filter"].endswith(")")):
        raise ADError("فیلتر کاربر باید داخل پرانتز باشد و {user} داشته باشد.")
    if not c["base_dn"]:
        raise ADError("Base DN لازم است (مثلاً DC=corp,DC=local).")
    if not any(c[k] for _, k in ROLE_ORDER):
        raise ADError("دست‌کم برای یکی از نقش‌ها گروه AD را مشخص کنید.")
    if c["ca_pem"] and "BEGIN CERTIFICATE" not in c["ca_pem"]:
        raise ADError("گواهی CA باید PEM باشد (-----BEGIN CERTIFICATE-----).")
    if c["ca_pem"]:
        try:
            ssl.create_default_context(cadata=c["ca_pem"])
        except (ssl.SSLError, ValueError) as e:
            raise ADError(f"گواهی CA خوانده نشد: {e}")
    return c


def split_user(name):
    """«DOMAIN\\user» یا «user@domain» یا «user» ← user (حروف کوچک)."""
    n = str(name or "").strip()
    if "\\" in n:
        n = n.split("\\", 1)[1]
    if "@" in n:
        n = n.split("@", 1)[0]
    if not USER_RE.match(n):
        raise ADBadCredentials("نام کاربری یا رمز اشتباه است.")
    return n.lower()


def _tls_class(Tls):
    """Tls کتابخانه‌ی ldap3 نام میزبان را با match_hostname قدیمی خودش بررسی می‌کند (IP در SAN را نمی‌شناسد).
    اینجا بررسی گواهی و نام میزبان با خود ssl پایتون (check_hostname، حداقل TLS 1.2) انجام می‌شود."""
    class StrictTls(Tls):
        def __init__(self, ca_pem):
            super().__init__(validate=ssl.CERT_REQUIRED)
            self._ca = ca_pem or None

        def wrap_socket(self, connection, do_handshake=False):
            ctx = ssl.create_default_context(cadata=self._ca) if self._ca else ssl.create_default_context()
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.check_hostname, ctx.verify_mode = True, ssl.CERT_REQUIRED
            connection.socket = ctx.wrap_socket(connection.socket, server_side=False, do_handshake_on_connect=True,
                                                server_hostname=connection.server.host)
    return StrictTls


def _norm_dn(dn):
    return re.sub(r"\s*([,=])\s*", r"\1", str(dn or "")).lower()


def authenticate(c, name, password, detail=False):
    """(نقش، نام کاربر). خطا: ADBadCredentials (رمز/نام یا بدون گروه) یا ADError (اتصال/تنظیم).
    detail=True: گزارش مرحله‌به‌مرحله برای «آزمایش اتصال»."""
    from ldap3 import BASE, SIMPLE, SUBTREE, Connection, Server, Tls
    from ldap3.core.exceptions import LDAPException
    from ldap3.utils.conv import escape_filter_chars
    log = []
    user = split_user(name)
    if not password:                                  # bind بدون رمز در LDAP «موفق» است (unauthenticated) — هرگز
        raise ADBadCredentials("نام کاربری یا رمز اشتباه است.")
    c = clean(c)
    if not c["enabled"]:
        raise ADError("ورود با Active Directory خاموش است.")
    tls = _tls_class(Tls)(c["ca_pem"])
    bind_name = c["bind_format"].replace("{user}", user).replace("{domain}", c["domain"])
    last_err = None
    for host, port, use_ssl in parse_urls(c["urls"]):
        srv = Server(host, port=port, use_ssl=use_ssl, tls=tls, connect_timeout=c["timeout"], get_info="NO_INFO")
        conn = Connection(srv, user=bind_name, password=password, authentication=SIMPLE, receive_timeout=c["timeout"],
                          raise_exceptions=False, auto_bind=False, read_only=True)
        try:
            conn.open()
            if conn.closed:
                raise LDAPException(conn.last_error or "اتصال برقرار نشد")
            if not use_ssl and not conn.start_tls():     # هرگز رمز روی اتصال بی‌رمز فرستاده نشود
                raise LDAPException(conn.last_error or "StartTLS ناموفق")
            log.append(f"اتصال امن به {host}:{port} ({'LDAPS' if use_ssl else 'StartTLS'}) و بررسی گواهی: موفق")
            if not conn.bind():
                if (conn.result or {}).get("result") == INVALID_CREDENTIALS:
                    raise ADBadCredentials("نام کاربری یا رمز اشتباه است.")
                raise ADError(f"ورود به AD ناموفق: {(conn.result or {}).get('description') or conn.last_error}")
            log.append(f"ورود {bind_name}: موفق")
            flt = c["user_filter"].replace("{user}", escape_filter_chars(user))
            conn.search(c["base_dn"], flt, SUBTREE, attributes=["memberOf"], size_limit=2)
            ents = [e for e in conn.response or [] if e.get("type") == "searchResEntry"]
            if len(ents) != 1:
                raise ADBadCredentials("کاربر در Base DN پیدا نشد." if detail else "نام کاربری یا رمز اشتباه است.")
            dn = ents[0]["dn"]
            groups = {_norm_dn(g) for g in (ents[0].get("attributes") or {}).get("memberOf") or []}
            log.append(f"کاربر: {dn} — {len(groups)} گروه مستقیم")
            role = None
            for r, key in ROLE_ORDER:
                g = c[key]
                if not g:
                    continue
                hit = _norm_dn(g) in groups
                if not hit:
                    try:
                        conn.search(dn, f"(memberOf:{IN_CHAIN}:={escape_filter_chars(g)})", BASE, attributes=["1.1"])
                        hit = any(e.get("type") == "searchResEntry" for e in conn.response or [])
                    except LDAPException:
                        hit = False
                log.append(f"گروه {r}: {'عضو' if hit else 'عضو نیست'}")
                if hit:
                    role = r
                    break
            if not role:
                raise ADBadCredentials("این کاربر عضو هیچ‌کدام از گروه‌های تعیین‌شده برای AutoKRP نیست."
                                       if detail else "نام کاربری یا رمز اشتباه است.")
            return (role, user, log) if detail else (role, user)
        except ADError:
            raise
        except (LDAPException, OSError, ssl.SSLError) as e:
            last_err = f"{host}:{port} — {e}"
            log.append(f"خطا: {last_err}")
            continue
        finally:
            try:
                conn.unbind()
            except Exception:  # noqa — بستن اتصال
                pass
    raise ADError(f"به هیچ Domain Controllerی وصل نشد: {last_err}")
