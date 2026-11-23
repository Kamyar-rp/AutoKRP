"""1.59.4: آیکن نصب‌کننده (Inno Setup) از assets/app.ico (یا app.png).

Inno Setup فقط فایل .ico واقعی و سالم می‌پذیرد؛ PyInstaller با Pillow هر تصویری را خودش تبدیل می‌کند، برای همین با آیکن کاربر
فایل پرتابل ساخته می‌شد ولی نصب‌کننده نه (خط SetupIconFile). این اسکریپت هر تصویری را که Pillow باز کند به یک .ico استاندارد
(۱۶ تا ۲۵۶ پیکسل) در build/setup.ico تبدیل می‌کند. خروجی: مسیر فایل روی stdout، یا هیچ (نصب‌کننده با آیکن پیش‌فرض ساخته می‌شود).
  python dev/mkicon.py [out]"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SIZES = [(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "build", "setup.ico")
    try:
        from PIL import Image
    except ImportError:
        print("[WARNING] Pillow is not installed; the installer uses the default icon.", file=sys.stderr)
        return 0
    adir = os.path.join(ROOT, "assets")
    extra = sorted(f for f in os.listdir(adir) if f.lower().endswith((".ico", ".png")) and f not in ("app.ico", "app.png")) if os.path.isdir(adir) else []
    for name in ["app.ico", "app.png"] + extra:      # آیکنی با نام دیگر هم (اگر app.ico نیست)
        src = os.path.join(adir, name)
        if not os.path.exists(src):
            continue
        try:
            with Image.open(src) as im:
                if getattr(im, "format", "") == "ICO" and getattr(im, "ico", None):
                    best = max(im.ico.sizes(), key=lambda s: s[0] * s[1])     # بزرگ‌ترین اندازه‌ی داخل ico
                    im.size = best
                im.load()
                img = im.convert("RGBA")
            w, h = img.size
            if w != h:            # مربع با حاشیه‌ی شفاف
                side = max(w, h)
                sq = Image.new("RGBA", (side, side), (0, 0, 0, 0))
                sq.paste(img, ((side - w) // 2, (side - h) // 2))
                img = sq
            if img.size[0] < 256:
                img = img.resize((256, 256), Image.LANCZOS)
            os.makedirs(os.path.dirname(out), exist_ok=True)
            img.save(out, format="ICO", sizes=SIZES)
            print(out)
            return 0
        except Exception as e:     # noqa — هر خطای تصویر: پیام و ادامه با آیکن پیش‌فرض
            print(f"[WARNING] assets\\{name} is not a usable image ({e}); trying the next one.", file=sys.stderr)
    print("[WARNING] No usable icon in assets (app.ico or app.png); the installer uses the default icon.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
