#!/usr/bin/env python3
"""
ساخت autokrp/oui.dat (جدول سازنده از روی MAC) از فهرست‌های ثبت IEEE.
منبع: فایل‌های oui.txt (MA-L) و iab.txt بسته‌ی netaddr (BSD؛ داده‌ی عمومی IEEE Registration Authority)
یا CSVهای خود IEEE (standards-oui.ieee.org: oui.csv، mam.csv، oui36.csv).
اجرا: python dev/oui_build.py <پوشه‌ی netaddr/eui یا فایل‌های csv>...
خروجی: gzip، هر خط «پیشوند هگز<TAB>سازنده» (پیشوند ۶، ۷ یا ۹ رقم هگز)، مرتب.
"""
import csv
import gzip
import re
import sys
from pathlib import Path


def from_txt(path, iab=False):
    out, cur = {}, None
    for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
        m = re.match(r"^\s*([0-9A-F]{2})-([0-9A-F]{2})-([0-9A-F]{2})\s+\(hex\)\s+(.*?)\s*$", line)
        if m:
            cur = "".join(m.groups()[:3])
            if not iab:
                out[cur] = m.group(4)
            continue
        m = re.match(r"^\s*([0-9A-F]{6})-([0-9A-F]{6})\s+\(base 16\)\s+(.*?)\s*$", line)
        if m and iab and cur:
            out[cur + m.group(1)[:3]] = m.group(3)
    return out


def from_csv(path):
    out = {}
    with open(path, encoding="utf-8", errors="replace", newline="") as f:
        for row in csv.DictReader(f):
            a = re.sub(r"[^0-9A-Fa-f]", "", row.get("Assignment") or "").upper()
            n = (row.get("Organization Name") or "").strip()
            if len(a) in (6, 7, 9) and n:
                out[a] = n
    return out


def build(sources):
    data = {}
    for s in sources:
        p = Path(s)
        if p.is_dir():
            if (p / "oui.txt").exists():
                data.update(from_txt(p / "oui.txt"))
            if (p / "iab.txt").exists():
                data.update(from_txt(p / "iab.txt", iab=True))
        elif p.suffix.lower() == ".csv":
            data.update(from_csv(p))
    return data


def write(data, dest):
    lines = "".join(f"{k}\t{' '.join(v.split())[:120]}\n" for k, v in sorted(data.items()))
    with gzip.open(dest, "wt", encoding="utf-8", compresslevel=9) as f:
        f.write(lines)


if __name__ == "__main__":
    d = build(sys.argv[1:])
    dest = Path(__file__).resolve().parent.parent / "autokrp" / "oui.dat"
    write(d, dest)
    print(len(d), "entries ->", dest, dest.stat().st_size, "bytes")
