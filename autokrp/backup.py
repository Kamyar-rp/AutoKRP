"""
پشتیبان‌گیری کانفیگ تجهیزات.

هر نسخه رمزشده (با کلید خروجی vault) در data_dir/config_backups/<device_id>/ ذخیره می‌شود.
برای تشخیص تغییر، متن «نرمال» می‌شود:
  - خطوطی که هر بار عوض می‌شوند (ignore_lines، مثل «! Last configuration change at ...») کنار گذاشته می‌شوند؛
  - مقدارهایی که هر بار با مقدار تازه رمز می‌شوند (mask، مثل «ENC ...» در FortiGate) یکسان در نظر گرفته می‌شوند.
متن ذخیره‌شده همیشه خروجی خام و دست‌نخورده‌ی دستگاه است.
اگر نسخه‌ی تازه با قبلی یکی باشد، نسخه‌ی تکراری ذخیره نمی‌شود.
"""
import difflib
import hashlib
import logging
import re
import time
from pathlib import Path

from . import paths

log = logging.getLogger(__name__)
MAX_DIFF_LINES = 6000


class BackupError(Exception):
    pass


def _rules(settings):
    cfg = settings.get("backup") or {}
    ign, msk = [], []
    for p in cfg.get("ignore_lines") or []:
        try:
            ign.append(re.compile(p))
        except re.error:
            log.warning("الگوی ignore_lines نامعتبر: %s", p)
    for p in cfg.get("mask") or []:
        try:
            msk.append(re.compile(p))
        except re.error:
            log.warning("الگوی mask نامعتبر: %s", p)
    return ign, msk


def normalize(text, settings):
    """[(خط نرمال، خط خام)] — خطوط نادیده‌گرفته‌شده حذف می‌شوند."""
    ign, msk = _rules(settings)
    out = []
    for raw in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        line = raw.rstrip()
        if any(r.search(line) for r in ign):
            continue
        norm = line
        for r in msk:
            norm = r.sub("«masked»", norm)
        out.append((norm, raw))
    return out


def digest(pairs):
    return hashlib.sha256("\n".join(n for n, _ in pairs).encode("utf-8")).hexdigest()


class Backups:
    def __init__(self, settings, store, vault):
        self.settings = settings
        self.store = store
        self.vault = vault
        self.root = paths.data_dir() / "config_backups"

    def _read(self, row):
        f = Path(row["file"])
        base = self.root.resolve()
        if base not in f.resolve().parents or not f.is_file():
            raise BackupError("فایل نسخه پیدا نشد.")
        return self.vault.decrypt_bytes(f.read_bytes()).decode("utf-8", "replace")

    def text(self, bid):
        row = self.store.backup(int(bid))
        if not row:
            raise BackupError("نسخه پیدا نشد.")
        return row, self._read(row)

    def record(self, dev, text, job_id=""):
        """
        ذخیره‌ی نتیجه‌ی پشتیبان‌گیری یک دستگاه.
        خروجی: {"state": "first"|"unchanged"|"changed", "added", "removed", "id"}
        """
        if not text or not text.strip():
            raise BackupError("خروجی دستگاه خالی بود.")
        pairs = normalize(text, self.settings)
        h = digest(pairs)
        prev = self.store.backups(dev["id"], limit=1)
        prev = prev[0] if prev else None
        if prev and prev["hash"] == h:
            return {"state": "unchanged", "added": 0, "removed": 0, "id": prev["id"]}
        added = removed = 0
        if prev:
            try:
                # شمارش با Counter: O(n) حتی برای کانفیگ کامل FortiGate (صدها هزار خط)
                from collections import Counter
                old = Counter(n for n, _ in normalize(self._read(prev), self.settings))
                new = Counter(n for n, _ in pairs)
                added = sum((new - old).values())
                removed = sum((old - new).values())
            except Exception:
                log.exception("مقایسه با نسخه‌ی قبل ناموفق بود")
        d = self.root / str(dev["id"])
        d.mkdir(parents=True, exist_ok=True)
        ts = time.time()
        f = d / f"{time.strftime('%Y%m%d_%H%M%S', time.localtime(ts))}_{h[:8]}.bin"
        data = text.encode("utf-8")
        f.write_bytes(self.vault.encrypt_bytes(data))
        bid = self.store.backup_add({"device_id": dev["id"], "ts": ts, "hash": h, "size": len(data), "lines": len(pairs),
                                     "added": added, "removed": removed, "first": 0 if prev else 1, "file": str(f),
                                     "job_id": job_id})
        self.prune(dev["id"])
        return {"state": "changed" if prev else "first", "added": added, "removed": removed, "id": bid}

    def delete(self, bid):
        """حذف یک نسخه: فایل رمزشده پیش از حذف با داده‌ی تصادفی بازنویسی می‌شود."""
        from . import wipe
        row = self.store.backup(int(bid))
        if not row:
            return False
        f = Path(row["file"])
        try:
            if self.root.resolve() in f.resolve().parents and f.is_file():
                wipe.overwrite(f)
                f.unlink()
        except FileNotFoundError:
            pass
        self.store.backup_delete(row["id"])
        return True

    def prune(self, dev_id):
        keep = max(1, int((self.settings.get("backup") or {}).get("keep") or 10))
        for row in self.store.backups(dev_id, limit=100000)[keep:]:
            try:
                Path(row["file"]).unlink()
            except FileNotFoundError:
                pass
            self.store.backup_delete(row["id"])

    def diff(self, old_id, new_id, context=3):
        """ردیف‌های مقایسه: [نوع، شماره‌ی خط قدیم، شماره‌ی خط جدید، متن خام] — نوع: eq|add|del|gap"""
        a_row, a_txt = self.text(old_id)
        b_row, b_txt = self.text(new_id)
        a, b = normalize(a_txt, self.settings), normalize(b_txt, self.settings)
        # autojunk=True (پیش‌فرض difflib): خطوط بسیار تکراری مثل «next» و «end» سرعت را روی کانفیگ‌های بزرگ نمی‌کُشند
        sm = difflib.SequenceMatcher(None, [n for n, _ in a], [n for n, _ in b], autojunk=True)
        rows, added, removed = [], 0, 0
        for group in sm.get_grouped_opcodes(context):
            if rows:
                rows.append(["gap", None, None, ""])
            for op, a1, a2, b1, b2 in group:
                if op == "equal":
                    rows += [["eq", a1 + i + 1, b1 + i + 1, b[b1 + i][1]] for i in range(a2 - a1)]
                    continue
                if op in ("replace", "delete"):
                    rows += [["del", i + 1, None, a[i][1]] for i in range(a1, a2)]
                    removed += a2 - a1
                if op in ("replace", "insert"):
                    rows += [["add", None, i + 1, b[i][1]] for i in range(b1, b2)]
                    added += b2 - b1
            if len(rows) > MAX_DIFF_LINES:
                rows.append(["gap", None, None, "…"])
                break
        return {"old": a_row, "new": b_row, "rows": rows, "added": added, "removed": removed}
