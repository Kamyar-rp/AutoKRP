"""
گواهی HTTPS برای حالت سرور. اگر کاربر گواهی خودش را ندهد، یک گواهی self-signed ساخته می‌شود.
کلید خصوصی باید پیش از ورود کاربر خوانا باشد (برای TLS)، پس با کلید داده رمز نمی‌شود.
1.22: روی ویندوز کلید به‌صورت PEM رمزدار (PKCS8) ذخیره می‌شود و رمزش با DPAPI به همان حساب ویندوزی بسته است که سرور
با آن اجرا می‌شود (server_key.pass). کپی پوشه روی سیستم یا حساب دیگر کلید را باز نمی‌کند. جای دیگر: ساده با دسترسی محدود.
"""
import datetime
import hashlib
import ipaddress
import logging
import re
import socket
import time

from . import dpapi, paths
from .vault import write_secure

log = logging.getLogger(__name__)
CERT_FILE = "server_cert.pem"
KEY_FILE = "server_key.pem"
PASS_FILE = "server_key.pass"


def _use_dpapi():
    return dpapi.AVAILABLE


def _write_key(key_path, key):
    """کلید خصوصی: ویندوز ← PEM رمزدار با رمز تصادفی که خودش با DPAPI بسته شده؛ جای دیگر ← PEM ساده."""
    import os
    from cryptography.hazmat.primitives import serialization
    pp = key_path.with_name(PASS_FILE)
    if _use_dpapi():
        pw = os.urandom(32).hex().encode()
        write_secure(pp, dpapi.protect(pw))
        enc = serialization.BestAvailableEncryption(pw)
    else:
        if pp.exists():
            pp.unlink()
        enc = serialization.NoEncryption()
    write_secure(key_path, key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, enc))


def _key_password(key_path):
    pp = key_path.with_name(PASS_FILE)
    if not pp.exists():
        return None
    return dpapi.unprotect(pp.read_bytes())


def _protect_existing(key_path):
    """کلید ساده‌ی نسخه‌های قبل روی ویندوز یک بار رمزدار می‌شود."""
    from cryptography.hazmat.primitives import serialization
    if not _use_dpapi() or key_path.with_name(PASS_FILE).exists():
        return
    raw = key_path.read_bytes()
    if b"ENCRYPTED" in raw:
        return
    _write_key(key_path, serialization.load_pem_private_key(raw, password=None))
    log.info("کلید خصوصی HTTPS با DPAPI محافظت شد")


def load_into(ctx):
    """گواهی و کلید را در SSLContext بار می‌کند. اگر رمز کلید روی این حساب ویندوز باز نشود (حساب سرویس عوض شده)،
    گواهی self-signed تازه ساخته می‌شود (قبلی پشتیبان می‌شود) و هشدار ثبت می‌شود."""
    cert, key = ensure()
    try:
        _protect_existing(paths_for()[1])
        ctx.load_cert_chain(cert, key, password=_key_password(paths_for()[1]))
    except (OSError, ValueError) as e:
        log.warning("کلید خصوصی HTTPS باز نشد (%s)؛ گواهی self-signed تازه ساخته شد — گواهی سفارشی را دوباره وارد کنید", e)
        self_signed()
        ctx.load_cert_chain(cert, key, password=_key_password(paths_for()[1]))


def paths_for():
    d = paths.data_dir()
    return d / CERT_FILE, d / KEY_FILE


def ensure(hostnames=None):
    """خروجی: (cert_path, key_path). اگر نبود، self-signed می‌سازد."""
    cert, key = paths_for()
    if cert.exists() and key.exists():
        return str(cert), str(key)
    _generate(cert, key, hostnames or [])
    return str(cert), str(key)


def _generate(cert_path, key_path, hostnames):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    host = socket.gethostname() or "autokrp"
    names = [host] + list(hostnames or [])
    alt = []
    seen = set()
    for n in names + ["localhost"]:
        n = (n or "").strip()
        if not n or n.lower() in seen:
            continue
        seen.add(n.lower())
        try:
            alt.append(x509.IPAddress(ipaddress.ip_address(n)))
        except ValueError:
            alt.append(x509.DNSName(n))
    for ip in ("127.0.0.1", "::1"):
        alt.append(x509.IPAddress(ipaddress.ip_address(ip)))
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host), x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AutoKRP")])
    now = datetime.datetime.utcnow()
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(x509.SubjectAlternativeName(alt), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    write_secure(cert_path, cert.public_bytes(serialization.Encoding.PEM))
    _write_key(key_path, key)
    log.info("گواهی self-signed ساخته شد: %s", cert_path)


# ------------------------------------------------------------------ گواهی شرکت (بارگذاری از تنظیمات)
class CertError(Exception):
    pass


BACKUP_DIR = "cert_backup"


def _load_parts(blobs, password):
    """از یک یا دو فایل (PFX/P12، PEM با گواهی و/یا کلید، یا DER) گواهی‌ها و کلید را بیرون می‌کشد."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.serialization import pkcs12
    pw = password.encode("utf-8") if password else None
    certs, key, need_pw = [], None, False
    for b in blobs:
        if b"-----BEGIN" in b:
            for m in re.finditer(rb"-----BEGIN ([A-Z0-9 ]+)-----.*?-----END \1-----", b, re.S):
                block, kind = m.group(0), m.group(1)
                if kind == b"CERTIFICATE":
                    certs.append(x509.load_pem_x509_certificate(block))
                elif kind.endswith(b"PRIVATE KEY"):
                    try:
                        key = serialization.load_pem_private_key(block, password=pw)
                    except TypeError:          # کلید رمزدار و رمز داده نشده (یا برعکس)
                        need_pw = True
                    except ValueError:
                        raise CertError("کلید خصوصی باز نشد؛ رمز کلید اشتباه است یا فایل خراب است.")
            continue
        try:                                   # PFX / P12
            k, c, extra = pkcs12.load_key_and_certificates(b, pw)
            key = key or k
            certs += ([c] if c else []) + list(extra or [])
            continue
        except ValueError as e:
            if "password" in str(e).lower() or "mac" in str(e).lower():
                raise CertError("فایل PFX رمز دارد؛ رمز را وارد کنید." if not pw else "فایل PFX باز نشد؛ رمز اشتباه است.")
        except TypeError:
            need_pw = True
            continue
        try:                                   # گواهی DER (.cer)
            certs.append(x509.load_der_x509_certificate(b))
        except ValueError:
            raise CertError("فرمت فایل شناخته نشد؛ PFX/P12 یا PEM (crt/cer/key) بدهید.")
    if key is None and need_pw:
        raise CertError("کلید خصوصی رمز دارد؛ رمز را وارد کنید.")
    return certs, key


def _host_names():
    names = {socket.gethostname().lower(), socket.getfqdn().lower(), "localhost"}
    ips = set()
    try:
        for ai in socket.getaddrinfo(socket.gethostname(), None):
            ips.add(ai[4][0])
    except OSError:
        pass
    return names, ips


def inspect(cert, chain=None):
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    fp = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest().upper()
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        dns = [n.lower() for n in san.get_values_for_type(x509.DNSName)]
        ips = [str(i) for i in san.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        dns, ips = [], []
    na = cert.not_valid_after_utc.timestamp()
    return {"subject": cert.subject.rfc4514_string(), "issuer": cert.issuer.rfc4514_string(),
            "self_signed": cert.subject == cert.issuer, "not_before": cert.not_valid_before_utc.timestamp(), "not_after": na,
            "days_left": int((na - time.time()) // 86400), "sha256": ":".join(fp[i:i + 2] for i in range(0, len(fp), 2)),
            "names": dns + ips, "chain": len(chain or [])}


def info():
    from cryptography import x509
    try:
        raw = paths_for()[0].read_bytes()
        cs = [x509.load_pem_x509_certificate(m.group(0)) for m in
              re.finditer(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", raw, re.S)]
        return inspect(cs[0], cs[1:]) if cs else None
    except Exception:
        return None


def install(blobs, password=""):
    """گواهی شرکت را بررسی و جایگزین می‌کند (نسخه‌ی قبلی پشتیبان می‌شود). خروجی: (info, warnings)"""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    certs, key = _load_parts(blobs, password)
    if key is None:
        raise CertError("کلید خصوصی پیدا نشد؛ فایل PFX یا فایل کلید (key) را هم بدهید.")
    if not isinstance(key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)):
        raise CertError("نوع کلید پشتیبانی نمی‌شود (فقط RSA یا EC).")
    pub = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    leaf = next((c for c in certs if c.public_key().public_bytes(serialization.Encoding.DER,
                                                                  serialization.PublicFormat.SubjectPublicKeyInfo) == pub), None)
    if leaf is None:
        raise CertError("گواهی با کلید خصوصی جور نیست (یا گواهی سرور در فایل‌ها نیست).")
    now = time.time()
    if leaf.not_valid_after_utc.timestamp() <= now:
        raise CertError("این گواهی منقضی شده است.")
    if leaf.not_valid_before_utc.timestamp() > now + 86400:
        raise CertError("تاریخ شروع اعتبار این گواهی هنوز نرسیده است.")
    if isinstance(key, rsa.RSAPrivateKey) and key.key_size < 2048:
        raise CertError("کلید RSA کمتر از ۲۰۴۸ بیت است.")
    chain = [c for c in certs if c is not leaf]
    # ترتیب زنجیره: از صادرکننده‌ی گواهی سرور به بالا (گواهی ریشه لازم نیست ولی اشکالی ندارد)
    ordered, cur = [], leaf
    for _ in range(10):
        nxt = next((c for c in chain if c not in ordered and c.subject == cur.issuer), None)
        if nxt is None:
            break
        ordered.append(nxt)
        if nxt.subject == nxt.issuer:
            break
        cur = nxt
    ordered += [c for c in chain if c not in ordered]
    warnings = []
    inf = inspect(leaf, ordered)
    names, ips = _host_names()
    if not any(n in names or n in ips for n in inf["names"]):
        shown = "، ".join(inf["names"][:6] or ["—"])
        warnings.append(f"نام یا IP این سرور در گواهی نیست ({shown})؛ کاربران باید با همان نامی که در گواهی است وصل شوند.")
    if inf["days_left"] < 30:
        warnings.append(f"این گواهی {inf['days_left']} روز دیگر منقضی می‌شود.")
    if leaf.subject != leaf.issuer and not ordered:
        warnings.append("گواهی میانی (chain) در فایل نیست؛ اگر مرورگرها خطای زنجیره دادند، فایل کامل (PFX یا PEM با chain) را بدهید.")
    _backup()
    cert_path, key_path = paths_for()
    pem = b"".join(c.public_bytes(serialization.Encoding.PEM) for c in [leaf] + ordered)
    _write_key(key_path, key)
    write_secure(cert_path, pem)
    log.info("گواهی HTTPS شرکت نصب شد: %s", inf["subject"])
    return inf, warnings


def _backup():
    cert_path, key_path = paths_for()
    if not (cert_path.exists() and key_path.exists()):
        return
    d = paths.data_dir() / BACKUP_DIR
    d.mkdir(exist_ok=True)
    write_secure(d / CERT_FILE, cert_path.read_bytes())       # فقط آخرین نسخه‌ی قبلی نگه داشته می‌شود
    write_secure(d / KEY_FILE, key_path.read_bytes())
    pp = key_path.with_name(PASS_FILE)
    if pp.exists():
        write_secure(d / PASS_FILE, pp.read_bytes())
    elif (d / PASS_FILE).exists():
        (d / PASS_FILE).unlink()


def self_signed():
    """برگشت به گواهی خودساخته‌ی تازه (گواهی فعلی پشتیبان می‌شود)."""
    _backup()
    cert_path, key_path = paths_for()
    _generate(cert_path, key_path, [])
    return info()
