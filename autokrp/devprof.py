"""
نوع دستگاه از MIB سازنده (1.27.1): خواندن «وضعیت سلامت» دستگاه‌هایی که برنامه خودش نمی‌شناسد.

نوع‌ها را mibs.Library._build_auto از MIBهای بارگذاری‌شده می‌سازد (هر سازنده = شماره‌ی enterprise؛ تشخیص با
sysObjectID). هر مقدار: اسکالر یا ستون جدول (همه‌ی ردیف‌ها، نام از ستون برچسب) از نوع enum با سطح هر مقدار.
همه‌ی OIDها عددی‌اند؛ خواندن دستگاه به فایل MIB نیاز ندارد.
"""

MAX_INSTANCES = 300            # مجموع مقدارهای یک دستگاه در هر بار خواندن


def match(profiles, objid):
    """قالبی که sysObjectID دستگاه با آن می‌خواند (طولانی‌ترین تطابق)."""
    o = str(objid or "").strip().lstrip(".")
    if not o:
        return None
    best, blen = None, -1
    for p in profiles or []:
        for m in p.get("match") or []:
            if (o == m or o.startswith(m + ".")) and len(m) > blen:
                best, blen = p, len(m)
    return best


def select(profiles, sel, objid):
    """sel: auto | none | شناسه‌ی قالب."""
    if sel == "none":
        return None
    if sel and sel != "auto":
        return next((p for p in profiles or [] if p["id"] == sel), None)
    return match(profiles, objid)


async def collect(cl, cred, host, port, prof, timeout=3, retries=1):
    """خواندن مقدارهای قالب: [{key, mid, name, oid, inst, type, …, raw, tn}]"""
    items, scal, tabs = [], [m for m in prof["metrics"] if not m["table"]], [m for m in prof["metrics"] if m["table"]]
    if scal:
        r = await cl.aget(cred, host, port, [m["oid"] for m in scal], timeout, retries, typed=True)
        for m in scal:
            val, tn = r.get(m["oid"], (None, ""))
            items.append({**m, "inst": "", "raw": val, "tn": tn, "key": m["oid"]})
    for m in tabs:
        if len(items) >= MAX_INSTANCES:
            break
        cols = [m["oid"]] + ([m["label_oid"]] if m["label_oid"] and m["label_oid"] != m["oid"] else [])
        w = await cl.awalk(cred, host, port, cols, timeout, retries, m["max_rows"])
        lab = w.get(m["label_oid"]) or {} if m["label_oid"] else {}
        for idx in sorted(w.get(m["oid"]) or {}, key=lambda x: tuple(int(p) for p in x.split(".") if p.isdigit())):
            if len(items) >= MAX_INSTANCES:
                break
            val = w[m["oid"]][idx]
            label = str(lab.get(idx) or "").strip()[:60] or idx
            items.append({**m, "inst": label, "raw": val, "tn": "Counter64" if m["bits"] == 64 else "",
                          "key": f"{m['oid']}.{idx}", "name": f"{m['name']} — {label}"})
    return items
