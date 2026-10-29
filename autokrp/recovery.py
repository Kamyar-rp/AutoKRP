"""
کد بازیابی رمز (1.27.8) — به‌جای RESET برای «رمز را فراموش کرده‌ام».

کد ۱۶۰ بیتی تصادفی (۳۲ نویسه‌ی base32، هشت گروه ۴تایی) یک بار به کاربر نشان داده و به‌صورت فایل متنی ذخیره می‌شود؛
خود کد هیچ‌جا ذخیره نمی‌شود. فقط یک کلید با آن (scrypt + AES-256-GCM) رمز می‌شود:
  - کلاینت: کلید بازیابی R (تصادفی). R کلید vault را رمز می‌کند (rk) و کلید vault هم R را (kr)، تا با عوض شدن
    رمز اصلی (کلید vault تازه) کد قبلی معتبر بماند: Vault._recovery_rekey.
  - سرور: کلید اصلی سرور (ثابت) مستقیم با کد رمز می‌شود.
بعد از هر استفاده کد عوض می‌شود. RESET همه‌چیز (از جمله این رکورد) را پاک می‌کند.
"""
import base64
import os
import re
import time

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .vault import NONCE_LEN, SALT_LEN, derive_key

AAD = b"autokrp-recovery-v1"
_CODE_DASH = re.compile(r"(?<![A-Z2-7])[A-Z2-7]{4}(?:-[A-Z2-7]{4}){7}(?![A-Z2-7])")
_CODE_RE = re.compile(r"[A-Z2-7]{4}(?:[ \t-]*[A-Z2-7]{4}){7}")


def new_code():
    s = base64.b32encode(os.urandom(20)).decode("ascii")
    return "-".join(s[i:i + 4] for i in range(0, 32, 4))


def normalize(text):
    """کد از متن کاربر یا محتوای فایل کد (خطوط دیگر فایل نادیده). خروجی: ۳۲ نویسه یا ''."""
    t = str(text or "").upper().replace("‌", " ")
    m = _CODE_DASH.search(t) or _CODE_RE.search(t)
    raw = re.sub(r"[^A-Z2-7]", "", m.group(0) if m else t)
    return raw if len(raw) == 32 else ""


def _enc(key, data, aad=AAD):
    n = os.urandom(NONCE_LEN)
    return (n + AESGCM(key).encrypt(n, data, aad)).hex()


def _dec(key, hexblob, aad=AAD):
    try:
        raw = bytes.fromhex(hexblob)
        return AESGCM(key).decrypt(raw[:NONCE_LEN], raw[NONCE_LEN:], aad)
    except (InvalidTag, ValueError, TypeError):
        return None


def seal(secret, code):
    """secret با کد رمز می‌شود. خروجی رکورد {salt, wrap, created}."""
    c = normalize(code)
    salt = os.urandom(SALT_LEN)
    return {"salt": salt.hex(), "wrap": _enc(derive_key(c, salt), secret), "created": time.time()}


def open_(rec, code):
    """secret یا None (کد اشتباه / رکورد خراب)."""
    c = normalize(code)
    if not c or not isinstance(rec, dict) or not rec.get("salt") or not rec.get("wrap"):
        return None
    try:
        k = derive_key(c, bytes.fromhex(rec["salt"]))
    except ValueError:
        return None
    return _dec(k, rec["wrap"])


def file_text(code, where, app="AutoKRP"):
    return (f"{app} — کد بازیابی رمز / Password recovery code\n"
            f"{'=' * 52}\n\n    {code}\n\n"
            f"برای: {where}\nساخته‌شده: {time.strftime('%Y-%m-%d %H:%M')}\n\n"
            "در صفحه‌ی ورود ← «رمز را فراموش کرده‌ام» این کد (یا همین فایل) را بدهید و رمز تازه بگذارید.\n"
            "این فایل را جای امن و جدا از این کامپیوتر نگه دارید (مثلاً چاپ کنید). هر کس آن را داشته باشد می‌تواند رمز را عوض کند.\n"
            "بعد از هر استفاده کد عوض می‌شود و این کد دیگر کار نمی‌کند.\n\n"
            "On the sign-in screen choose “Forgot password”, give this code (or this file) and set a new password.\n"
            "Keep it somewhere safe, away from this computer. Anyone who has it can change the password.\n"
            "The code changes after each use.\n")
