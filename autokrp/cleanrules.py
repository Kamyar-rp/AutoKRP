"""1.59: قاعده‌های بلاک IPهای غیرمخرب (AbuseIPDB: CLEAN).

قانون اصلی برنامه عوض نمی‌شود: مخرب‌ها مثل قبل. این قاعده‌ها فقط وقتی کاربر خودش تعریف و روشن کرده باشد، IP غیرمخربی را که
شرط‌های قاعده را دارد هم برای بلاک پیشنهاد می‌کنند — با همان مسیر مخرب‌ها (بلاک خودکار روشن ← بلاک؛ خاموش ← فهرست تأیید)،
همان رنج‌های مستثنا و همان سقف‌ها.

هر قاعده (همه‌ی شرط‌ها با هم):
  runs_min در window روز اخیر = چند بار (چند اجرای Splunk) IP در گزارش‌ها آمده («۳ بار در ۳۰ روز»)
  days_min                    = تعداد روزهای مختلفی که IP در خروجی Splunk بوده (۰ = مهم نیست)
  (attacks_min — جمع حمله‌ها — از 1.59.1 در رابط نیست؛ عدد Splunk قابل اعتماد نبود)
  score_min..score_max        = امتیاز AbuseIPDB
  intel: any | ABUSE | CLEAN | none (بررسی تکمیلی)
  countries + countries_op (in / not_in)، text (ISP یا نوع استفاده شامل)
  ban_days: مدت بلاک (۰ = دائم)
پس از پایان بلاکی که قاعده زده، شمارش از صفر: فقط روزهای بعد از ips.attack_reset حساب می‌شوند.
اولین قاعده‌ی جورشده (به ترتیب فهرست) مدت را تعیین می‌کند.
"""
import re
import secrets
from datetime import datetime, timedelta

from . import banrules

MAX_RULES = 30
INTEL = ("any", "ABUSE", "CLEAN", "none")
_CC = re.compile(r"^[A-Z]{2}$")


class RuleError(ValueError):
    pass


def _int(v, lo, hi, what, default=None):
    if v in (None, ""):
        if default is None:
            raise RuleError(f"{what} را وارد کنید.")
        return default
    try:
        n = int(str(v).strip())
    except (TypeError, ValueError):
        raise RuleError(f"{what} باید عدد صحیح باشد.")
    if not lo <= n <= hi:
        raise RuleError(f"{what} باید بین {lo} و {hi} باشد.")
    return n


def clean_one(r, i=1):
    if not isinstance(r, dict):
        raise RuleError(f"قاعده‌ی {i} نامعتبر است.")
    name = re.sub(r"[\x00-\x1f\x7f]", " ", str(r.get("name") or "")).strip()[:60]
    if not name:
        raise RuleError(f"قاعده‌ی {i}: نام را وارد کنید.")
    p = f"قاعده‌ی «{name}»: "
    try:
        window = _int(r.get("window"), 1, 365, "بازه‌ی روزها", 30)
        days_min = _int(r.get("days_min"), 0, 365, "روز حمله", 0)
        runs_min = _int(r.get("runs_min"), 0, 100000, "حضور در گزارش‌ها", 0)
        if days_min > window:
            raise RuleError("روز حمله نمی‌تواند از بازه بیشتر باشد.")
        if not days_min and not runs_min:
            raise RuleError("حداقل یکی از «حضور در گزارش‌ها» یا «روز حمله» را بیشتر از صفر بگذارید.")
        attacks_min = _int(r.get("attacks_min"), 0, 10 ** 9, "جمع حمله", 0)
        smin = _int(r.get("score_min"), 0, 100, "کمترین امتیاز", 0)
        smax = _int(r.get("score_max"), 0, 100, "بیشترین امتیاز", 100)
        if smin > smax:
            raise RuleError("کمترین امتیاز از بیشترین بزرگ‌تر است.")
        ban_days = banrules.clean_days(r.get("ban_days") if r.get("ban_days") not in (None, "") else 30)
    except (RuleError, banrules.RuleError) as e:
        raise RuleError(p + str(e))
    intel = str(r.get("intel") or "any")
    if intel not in INTEL:
        raise RuleError(p + "شرط بررسی تکمیلی نامعتبر است.")
    cc = r.get("countries") or []
    if isinstance(cc, str):
        cc = re.split(r"[\s,\u060c]+", cc)
    cc = sorted({str(x).strip().upper() for x in cc if str(x).strip()})
    if any(not _CC.match(x) for x in cc) or len(cc) > 250:
        raise RuleError(p + "کد کشور باید دو حرف انگلیسی باشد (مثل RU).")
    op = "not_in" if r.get("countries_op") == "not_in" else "in"
    text = re.sub(r"[\x00-\x1f\x7f]", " ", str(r.get("text") or "")).strip()[:100]
    rid = str(r.get("id") or "")
    if not re.fullmatch(r"[a-f0-9]{8}", rid):
        rid = secrets.token_hex(4)
    return {"id": rid, "name": name, "enabled": bool(r.get("enabled", True)), "window": window, "days_min": days_min, "runs_min": runs_min,
            "attacks_min": attacks_min, "score_min": smin, "score_max": smax, "intel": intel, "countries": cc,
            "countries_op": op, "text": text, "ban_days": ban_days}


def clean(rules):
    if rules in (None, ""):
        return []
    if not isinstance(rules, list):
        raise RuleError("قاعده‌های بلاک غیرمخرب نامعتبر است.")
    if len(rules) > MAX_RULES:
        raise RuleError(f"حداکثر {MAX_RULES} قاعده‌ی بلاک غیرمخرب.")
    out = [clean_one(r, i) for i, r in enumerate(rules, 1)]
    names = [x["name"].lower() for x in out]
    if len(set(names)) != len(names):
        raise RuleError("نام قاعده‌ها باید یکتا باشد.")
    ids = set()
    for x in out:
        while x["id"] in ids:
            x["id"] = secrets.token_hex(4)
        ids.add(x["id"])
    return out


def summary(r):
    """متن کوتاه شرط‌ها برای جدول و تاریخچه."""
    parts = [f"در {r['window']} روز اخیر"]
    if r.get("runs_min"):
        parts.append(f"حضور در گزارش‌ها ≥ {r['runs_min']} بار")
    if r.get("days_min"):
        parts.append(f"روز حمله ≥ {r['days_min']}")
    if r.get("attacks_min"):
        parts.append(f"حمله ≥ {r['attacks_min']}")
    if (r.get("score_min"), r.get("score_max")) != (0, 100):
        parts.append(f"امتیاز {r['score_min']}–{r['score_max']}")
    if r.get("intel") and r["intel"] != "any":
        parts.append("بررسی تکمیلی: " + {"ABUSE": "مخرب", "CLEAN": "پاک", "none": "بررسی‌نشده"}[r["intel"]])
    if r.get("countries"):
        parts.append(("کشور: " if r.get("countries_op") != "not_in" else "کشور غیر از: ") + ", ".join(r["countries"]))
    if r.get("text"):
        parts.append(f"ISP/نوع شامل «{r['text']}»")
    return " · ".join(parts)


def _static_ok(r, rec):
    try:
        sc = int(float(rec.get("score")))
    except (TypeError, ValueError):
        return False
    if not r["score_min"] <= sc <= r["score_max"]:
        return False
    it = str(rec.get("intel_status") or "")
    if r["intel"] == "ABUSE" and it != "ABUSE":
        return False
    if r["intel"] == "CLEAN" and it != "CLEAN":
        return False
    if r["intel"] == "none" and it:
        return False
    if r["countries"]:
        cc = str(rec.get("country_code") or "").upper()
        if not cc:
            return False
        if (cc in r["countries"]) != (r["countries_op"] == "in"):
            return False
    if r["text"]:
        t = f"{rec.get('isp') or ''} {rec.get('usage_type') or ''}".lower()
        if r["text"].lower() not in t:
            return False
    return True


FW_DONE = ("banned", "already")


def evaluate(store, rules, cfg, only=None, include_banned=False):
    """IPهای غیرمخربی که قاعده‌ای (روشن) با آن‌ها جور است.
    خروجی: {ip: {"rule": نام، "rule_id"، "days": مدت بلاک، "atk_days"، "atk_total"}} — اولین قاعده‌ی جورشده.
    cfg: تنظیمات abuseipdb (برای تشخیص مخرب با آستانه‌ی فعلی؛ مخرب‌ها مال قانون اصلی‌اند).
    only: فقط این IPها (اختیاری). include_banned: IPهای از قبل بلاک‌شده هم (برای پیش‌نمایش «الان منطبق»)."""
    from .pipeline import block_reason_v
    rules = [r for r in (rules or []) if r.get("enabled")]
    if not rules:
        return {}
    today = datetime.now()
    wmax = max(r["window"] for r in rules)
    since = (today - timedelta(days=wmax - 1)).strftime("%Y-%m-%d")
    cand = store.attack_stats(since, only)
    if not cand:
        return {}
    info = store.ips_info(list(cand), "ip, abuse_status, score, is_whitelisted, country_code, isp, usage_type, intel_status, "
                                      "fw_status, attack_reset")
    out = {}
    per_rule_since = {r["id"]: (today - timedelta(days=r["window"] - 1)).strftime("%Y-%m-%d") for r in rules}
    exact = {}           # (ip, since) ← شمارش دقیق وقتی بازه‌ی قاعده یا attack_reset با بازه‌ی کلی فرق دارد
    for ip, rec in info.items():
        if str(rec.get("abuse_status") or "").upper() != "CLEAN":
            continue
        if block_reason_v(rec.get("abuse_status"), rec.get("score"), rec.get("is_whitelisted"), cfg):
            continue        # با آستانه‌ی فعلی مخرب است: قانون اصلی
        if not include_banned and rec.get("fw_status") in FW_DONE:
            continue
        reset = str(rec.get("attack_reset") or "")
        for r in rules:
            if not _static_ok(r, rec):
                continue
            s = per_rule_since[r["id"]]
            if reset and reset >= s:
                s = (datetime.strptime(reset[:10], "%Y-%m-%d") + timedelta(days=1)).strftime("%Y-%m-%d")
            if s == since:
                nd, tot, nr = cand[ip]
            else:
                if (ip, s) not in exact:
                    exact[(ip, s)] = store.attack_stats(s, [ip]).get(ip, (0, 0, 0))
                nd, tot, nr = exact[(ip, s)]
            if nd >= (r.get("days_min") or 0) and nr >= (r.get("runs_min") or 0) and tot >= (r.get("attacks_min") or 0):
                out[ip] = {"rule": r["name"], "rule_id": r["id"], "days": int(r["ban_days"]), "atk_days": nd, "atk_total": tot, "atk_runs": nr}
                break
    return out


def reset_day(days):
    """روزی که شمارش بعد از آن از نو شروع می‌شود: پایان بلاک (موقت) یا امروز (دائم)."""
    d = datetime.now() + timedelta(days=int(days or 0))
    return d.strftime("%Y-%m-%d")
