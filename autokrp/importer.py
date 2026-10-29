"""
ورود داده‌ی قبلی به دیتابیس:
  - فایل ipabuse_report.csv اسکریپت اصلی (۱۷ ستون) یا ip_temp.csv یا abuse_report.csv همین برنامه
  - افزودن دستی
"""
import csv
import time
from datetime import datetime
from pathlib import Path

from . import atrest, csvsafe
from .connectors import ConnectorError
from .connectors.abuseipdb import is_valid_ipv4, extract_ips_from_text

# نام ستون در فایل → نام فیلد در دیتابیس
COLUMN_MAP = {
    "ip": "ip", "isp": "isp", "usage type": "usage_type", "asn": "asn", "domain": "domain",
    "country code": "country_code", "country": "country", "city": "city",
    "abuse confidence score": "score", "total reports": "reports", "last reported at": "last_reported",
    "is whitelisted": "is_whitelisted", "is tor": "is_tor", "categories": "categories",
    "status": "abuse_status", "error": "error", "checked at": "checked_at",
}
TIME_FMT = "%Y-%m-%d %H:%M:%S"

# ستون‌های اضافه‌ی خروجی کامل همین برنامه (برای جابه‌جایی داده بین دو سیستم)
EXTRA_COLUMNS = [
    ("FortiGate Status", "fw_status"), ("FortiGate Detail", "fw_detail"), ("FortiGate At", "fw_at"),
    ("Review", "review"), ("Source", "source"), ("First Seen", "first_seen"), ("Last Seen", "last_seen"),
    ("Attack Count", "attack_count"), ("Signatures", "signatures"), ("Dest Ports", "dest_ports"),
]
HEADER_MAP = {**COLUMN_MAP, **{h.lower(): k for h, k in EXTRA_COLUMNS}}


def _int(v):
    try:
        return int(float(str(v).strip()))
    except (TypeError, ValueError):
        return None


def _ts(v):
    try:
        return datetime.strptime(str(v).strip(), TIME_FMT)
    except (TypeError, ValueError):
        return None


# ترتیب ستون‌های ipabuse_report.csv اسکریپت اصلی (برای فایل بدون سطر عنوان)
POSITIONAL = ["ip", "isp", "usage_type", "asn", "domain", "country_code", "country", "city", "score", "reports",
              "last_reported", "is_whitelisted", "is_tor", "categories", "abuse_status", "error", "checked_at"]


def _read_text(path):
    raw = atrest.read_bytes(path)
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16"), "UTF-16"
    try:
        return raw.decode("utf-8-sig"), "UTF-8"
    except UnicodeDecodeError:
        return raw.decode("cp1256", errors="replace"), "Windows-1256"


def _delimiter(first_line):
    counts = {d: first_line.count(d) for d in (",", ";", "\t")}
    return max(counts, key=counts.get) if max(counts.values()) else ","


STATUSES = ("ABUSE", "CLEAN", "ERROR")
S_IDX = POSITIONAL.index("abuse_status")  # 14


def _split_merged(r):
    """سطرهایی که خط جدیدشان جا افتاده (مثلاً ۳۲ ستون = ۱۵ + ۱۷) را به رکوردهای جدا می‌شکند."""
    out = []
    while len(r) > len(POSITIONAL):
        cut = next((k for k in range(S_IDX + 1, len(POSITIONAL) + 1)
                    if k < len(r) and is_valid_ipv4(r[k].strip()) and str(r[S_IDX]).strip().upper() in STATUSES), None)
        if cut is None:
            break
        out.append(r[:cut])
        r = r[cut:]
    out.append(r)
    return out


def _layout(r, header_idx, header_len):
    """برای هر سطر ترتیب ستون‌ها را پیدا می‌کند؛ None اگر هیچ ترتیبی معتبر نباشد."""
    # ۰) خروجی کامل همین برنامه: سطر عنوان با همه‌ی ستون‌ها
    if header_idx and len(header_idx) > len(POSITIONAL) and len(r) == header_len:
        return header_idx
    # ۱) ترتیب ستون‌های ipabuse_report.csv (۱۵، ۱۶ یا ۱۷ ستون: Error و Checked At ممکن است نباشند)
    if S_IDX < len(r) <= len(POSITIONAL) and r[S_IDX].strip().upper() in STATUSES:
        return {k: i for i, k in enumerate(POSITIONAL) if i < len(r)}
    # ۲) ترتیب سطر عنوان خود فایل (مثلاً خروجی کامل همین برنامه)
    if header_idx and len(r) == header_len:
        si = header_idx.get("abuse_status")
        if si is None or r[si].strip().upper() in STATUSES:
            return header_idx
    return None


def parse_file(path, threshold=0):
    """فایل را می‌خواند و رکوردهای آماده برای ورود برمی‌گرداند (بدون نوشتن)."""
    from . import paths
    try:
        path = paths.user_file(path)
    except PermissionError as e:
        raise ConnectorError(str(e))
    if not path or not Path(path).is_file():
        raise ConnectorError(f"فایل پیدا نشد: {path or '(خالی)'}")
    text, enc = _read_text(path)
    lines = text.splitlines()
    first = next((l for l in lines if l.strip()), "")
    delim = _delimiter(first)
    rows = [(n, [csvsafe.unquote(c) for c in r]) for n, r in enumerate(csv.reader(lines, delimiter=delim), 1)
            if r and any(c.strip() for c in r)]
    if not rows:
        raise ConnectorError("فایل خالی است.")
    clean = lambda v: v.replace("\ufeff", "").strip()
    head = [clean(h).lower() for h in rows[0][1]]
    header_idx, header_len, has_header = {}, 0, False
    if "ip" in head:
        has_header = True
        header_idx = {HEADER_MAP[h]: i for i, h in enumerate(head) if h in HEADER_MAP}
        header_len = len(head)
        rows = rows[1:]
    file_time = datetime.fromtimestamp(Path(path).stat().st_mtime).strftime(TIME_FMT)

    records, bad, dup, merged, no_time = {}, [], 0, 0, 0
    layouts = {"script": 0, "header": 0}
    for line_no, raw in rows:
        raw = [clean(c) for c in raw]
        if raw and raw[0].lower() == "ip":
            continue  # سطر عنوان تکراری
        parts = _split_merged(raw)
        if len(parts) > 1:
            merged += 1
        for r in parts:
            if not r or not is_valid_ipv4(r[0]):
                bad.append((line_no, "IP نامعتبر: " + (r[0][:40] if r else "")))
                continue
            idx = _layout(r, header_idx, header_len)
            if idx is None:
                bad.append((line_no, f"{len(r)} ستون؛ ستون Status پیدا نشد"))
                continue
            layouts["header" if idx is header_idx else "script"] += 1
            rec = {k: (r[i] if i < len(r) else "") for k, i in idx.items()}
            status = rec.get("abuse_status", "").upper()
            score = _int(rec.get("score"))
            if status not in STATUSES:
                status = "ERROR" if score is None else ("ABUSE" if score > threshold else "CLEAN")
            if status != "ERROR" and score is None:
                bad.append((line_no, f"امتیاز نامعتبر: {rec.get('score')}"))
                continue
            rec["abuse_status"] = status
            if status == "ERROR":
                # در اسکریپت اصلی ردیف خطا ستون ISP را هم ERROR می‌نویسد
                for k in ("isp", "usage_type", "asn", "domain", "country_code", "country", "city",
                          "last_reported", "is_whitelisted", "is_tor", "categories"):
                    rec[k] = "-"
                rec["score"] = None
                rec["reports"] = None
            else:
                rec["score"] = score
                rec["reports"] = _int(rec.get("reports")) or 0
            if not _ts(rec.get("checked_at")):
                rec["checked_at"] = file_time  # زمان ذخیره‌ی فایل، نه زمان ورود
                no_time += 1
            for k in list(rec):
                if k not in POSITIONAL:          # ستون‌های خروجی کامل: خالی = بدون تغییر
                    if rec[k] in ("", None):
                        del rec[k]
                    elif k == "attack_count":
                        rec[k] = _int(rec[k])
                elif rec[k] == "" and k != "error":
                    rec[k] = "-"
            ip = rec["ip"]
            prev = records.get(ip)
            if prev:
                dup += 1
                if (_ts(prev["checked_at"]) or datetime.min) > (_ts(rec["checked_at"]) or datetime.min):
                    continue
            records[ip] = rec
    if not records:
        raise ConnectorError("هیچ ردیف قابل خواندنی پیدا نشد. " +
                             ("نمونه: " + "؛ ".join(f"سطر {n}: {m}" for n, m in bad[:3]) if bad else ""))
    info = {"bad": len(bad), "bad_rows": bad[:15], "dup": dup, "merged": merged, "no_time": no_time,
            "header": has_header, "layouts": layouts,
            "delimiter": {",": "ویرگول", ";": "نقطه‌ویرگول", "\t": "Tab"}[delim], "encoding": enc}
    return list(records.values()), info


def preview(store, path, threshold=0):
    recs, info = parse_file(path, threshold)
    new = upd = older = 0
    for r in recs:
        cur = store.get_ip(r["ip"])
        if not cur or not cur.get("checked_at"):
            new += 1
        elif (_ts(cur["checked_at"]) or datetime.min) < (_ts(r["checked_at"]) or datetime.min):
            upd += 1
        else:
            older += 1
    by = {s: sum(1 for r in recs if r["abuse_status"] == s) for s in ("ABUSE", "CLEAN", "ERROR")}
    return {"total": len(recs), "new": new, "update": upd, "older": older, "status": by,
            "file": Path(path.strip().strip('"')).name, **info,
            "sample": recs[:8]}


def commit(store, path, threshold=0, overwrite=False, excluded=lambda ip: False):
    """
    ورود به دیتابیس. پیش‌فرض: اگر IP در دیتابیس نتیجه‌ی جدیدتری دارد، دست نمی‌خورد.
    overwrite=True یعنی داده‌ی فایل همیشه جایگزین شود.
    """
    recs, _ = parse_file(path, threshold)
    written = skipped = ignored = 0
    stat_rows = []
    with store.batch():   # یک تراکنش برای کل فایل
        for r in recs:
            if excluded(r["ip"]):
                ignored += 1
                continue
            cur = store.get_ip(r["ip"])
            if cur and cur.get("checked_at") and not overwrite:
                if (_ts(cur["checked_at"]) or datetime.min) >= (_ts(r["checked_at"]) or datetime.min):
                    skipped += 1
                    continue
            fields = {k: v for k, v in r.items() if k != "ip"}
            if not cur:
                fields["source"] = "import"
            store.upsert_ip(r["ip"], **fields)
            written += 1
            ts = _ts(r.get("checked_at"))
            if ts:
                stat_rows.append((ts.timestamp(), "abuse", r["abuse_status"], r["ip"], r.get("country_code") or "",
                                  r.get("isp") or "", "import"))
    if stat_rows:
        store.add_stats(stat_rows)
    store.add_history("import", Path(path.strip().strip('"')).name, "ok",
                      f"{written} IP وارد شد، {skipped} مورد به‌خاطر داده‌ی جدیدتر و {ignored} مورد به‌خاطر رنج مستثنا/خصوصی رد شد",
                      "", path)
    return {"written": written, "skipped": skipped, "ignored": ignored}


def add_manual(store, text, status, country_code="", note="", excluded=lambda ip: False):
    ips = extract_ips_from_text(text)
    if not ips:
        raise ConnectorError("هیچ IPv4 معتبری در متن پیدا نشد.")
    skipped = [ip for ip in ips if excluded(ip)]
    ips = [ip for ip in ips if ip not in skipped]
    if not ips:
        raise ConnectorError("همه‌ی IPها خصوصی یا داخل رنج‌های مستثنا (تنظیمات ← FortiGate) هستند؛ چیزی اضافه نشد.")
    status = status.upper()
    if status not in ("ABUSE", "CLEAN"):
        raise ConnectorError("وضعیت باید مخرب یا غیرمخرب باشد.")
    cc = (country_code or "").strip().upper() or "-"
    now = time.strftime(TIME_FMT)
    with store.batch():
        for ip in ips:
            cur = store.get_ip(ip)
            fields = {"abuse_status": status, "score": None, "reports": (cur or {}).get("reports"),
                      "country_code": cc if cc != "-" else (cur or {}).get("country_code") or "-",
                      "checked_at": now, "error": "", "categories": note.strip() or "ثبت دستی"}
            if not cur:
                fields["source"] = "manual"
            store.upsert_ip(ip, **fields)
            store.add_stat("abuse", status, ip, fields["country_code"], "", "manual")
    store.add_history("import", f"{len(ips)} IP", "ok", f"افزودن دستی با وضعیت {status}", "", "")
    return {"written": len(ips), "ignored": len(skipped)}


# ------------------------------------------------------------------ export
SCRIPT_HEADERS = ["IP", "ISP", "Usage Type", "ASN", "Domain", "Country Code", "Country", "City",
                  "Abuse Confidence Score", "Total Reports", "Last Reported At", "Is Whitelisted", "Is Tor",
                  "Categories", "Status", "Error", "Checked At"]


def _script_row(r):
    if (r.get("abuse_status") or "") == "ERROR":
        return [r["ip"], "ERROR"] + ["-"] * 12 + ["ERROR", r.get("error") or "", r.get("checked_at") or ""]
    g = lambda k: "-" if r.get(k) in (None, "") else r.get(k)
    return [r["ip"]] + [g(k) for k in POSITIONAL[1:14]] + [r.get("abuse_status") or "-", r.get("error") or "",
                                                           r.get("checked_at") or ""]


def export_rows(rows, path, fmt="script"):
    """
    script = دقیقاً ۱۷ ستون ipabuse_report.csv (سازگار با ipabuse_report.csv و قابل ورود دوباره)
    full   = همان ۱۷ ستون + وضعیت FortiGate، بررسی دستی، منبع و داده‌ی Splunk (برای انتقال کامل)
    """
    rows = [r for r in rows if r.get("abuse_status") in STATUSES or fmt == "full"]
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f)
        if fmt == "full":
            w.writerow(SCRIPT_HEADERS + [h for h, _ in EXTRA_COLUMNS])
            for r in rows:
                w.writerow(csvsafe.row(_script_row(r) + ["" if r.get(k) is None else r.get(k) for _, k in EXTRA_COLUMNS]))
        else:
            w.writerow(SCRIPT_HEADERS)
            w.writerows(csvsafe.row(_script_row(r)) for r in rows)
    return len(rows)
