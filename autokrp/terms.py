"""1.39: متن پذیرش پیش از استفاده و سلب مسئولیت (دوزبانه). با تغییر محتوای متن VERSION را یکی بالا ببرید تا همه دوباره بپذیرند.
نمایش: پنجره‌ی اولین اجرا پیش از انتخاب حالت (app.py) و داخل برنامه پیش از هر کاری.
دسکتاپ: یک بار برای همین نصب؛ حالت سرور: هر کاربر جدا (settings → terms). این متن مکمل مجوز MIT است، نه جایگزین آن."""
VERSION = 1

TITLE = {"fa": "شرایط استفاده و سلب مسئولیت", "en": "Terms of use and disclaimer"}

TEXT = {
    "fa": [
        "۱. AutoKRP نرم‌افزاری رایگان و متن‌باز با مجوز MIT است که فقط برای ساده‌تر کردن کارهای روزمره‌ی امنیت و شبکه ساخته شده است. "
        "این نرم‌افزار محصول تجاری نیست و سازنده تعهدی به پشتیبانی، نگهداری یا ارائه‌ی به‌روزرسانی ندارد.",
        "۲. نرم‌افزار «همان‌گونه که هست» و «هر طور که در دسترس است» و بدون هیچ ضمانت صریح یا ضمنی ارائه می‌شود؛ از جمله ضمانت درستی، "
        "امنیت، کارکرد بی‌وقفه یا بی‌خطا، یا مناسب بودن برای هدفی خاص.",
        "۳. تا بیشترین حدی که قانون اجازه می‌دهد، سازنده و مشارکت‌کنندگان در برابر هیچ خسارت مستقیم یا غیرمستقیمی مسئول نیستند؛ از جمله از دست رفتن "
        "یا افشای داده، قطعی سرویس، تغییر یا خرابی تنظیمات دستگاه‌ها، مسدود شدن ترافیک یا کاربران مجاز، زیان مالی، یا ادعا و پیامد حقوقی؛ "
        "چه از استفاده، ناتوانی در استفاده، استفاده‌ی نادرست یا سوءاستفاده از نرم‌افزار ناشی شود و چه از ایراد نرم‌افزاری یا امنیتی آن.",
        "۴. مسئولیت هر کاری که با نرم‌افزار انجام می‌شود (مثل بلاک کردن آدرس، اجرای دستور یا تغییر تنظیمات دستگاه‌ها، اسکن شبکه، یا ارسال داده "
        "و درخواست به سرویس‌ها) فقط با کاربر و سازمان اوست. کاربر باید: فقط روی شبکه‌ها، دستگاه‌ها و حساب‌هایی کار کند که اجازه‌ی رسمی مدیریتشان را دارد؛ "
        "قوانین و مقررات کشور خود و سیاست‌های سازمانش را رعایت کند؛ نتیجه‌ی کارهای خودکار را بازبینی کند؛ پیش از استفاده در محیط واقعی آزمایش کند؛ "
        "و از داده‌ها و تنظیمات دستگاه‌ها پشتیبان داشته باشد.",
        "۵. سرویس‌های دیگری که به نرم‌افزار وصل می‌کنید (مثل Splunk، AbuseIPDB، FortiGate، Redmine و سرویس‌های اینترنتی) تابع شرایط خودشان هستند. "
        "نرم‌افزار ممکن است داده‌هایی مثل آدرس IP را به همان سرویس‌هایی که خودتان تنظیم کرده‌اید بفرستد؛ مسئولیت این کار و نگهداری امن کلیدها و رمزها با کاربر است.",
        "۶. سازنده با حسن نیت و در حد توان تلاش کرده نرم‌افزار امن و پایدار باشد و عمداً هیچ کد مخربی در آن قرار نداده است؛ با این حال هیچ نرم‌افزاری "
        "بی‌نقص نیست. سوءاستفاده‌ی دیگران از نرم‌افزار یا از ایرادهای آن بر عهده‌ی سازنده نیست. ایراد نرم‌افزاری را در GitHub (Issues) و ایراد امنیتی را "
        "به‌صورت خصوصی (Security) گزارش دهید تا رفع شود، و همیشه آخرین نسخه را به‌کار ببرید.",
        "۷. نسخه‌ی رسمی فقط از مخزن GitHub پروژه منتشر می‌شود. سازنده در برابر نسخه‌هایی که دیگران تغییر داده یا از جای دیگری منتشر کرده‌اند مسئولیتی ندارد.",
        "۸. این متن مکمل مجوز MIT است. اگر بخشی از آن طبق قانون قابل اجرا نباشد، بقیه‌ی بخش‌ها معتبر می‌مانند.",
        "با زدن «می‌پذیرم» تأیید می‌کنید که این متن و مجوز MIT را خوانده‌اید، فهمیده‌اید و پذیرفته‌اید. اگر نمی‌پذیرید، از نرم‌افزار استفاده نکنید.",
    ],
    "en": [
        "1. AutoKRP is free, open-source software under the MIT licence, made only to make everyday security and network work easier. "
        "It is not a commercial product, and the author has no obligation to provide support, maintenance or updates.",
        "2. The software is provided “as is” and “as available”, without warranty of any kind, express or implied, including any warranty of "
        "accuracy, security, uninterrupted or error-free operation, or fitness for a particular purpose.",
        "3. To the maximum extent permitted by law, the author and contributors are not liable for any direct or indirect damage, including loss or disclosure "
        "of data, service outages, changed or broken device configuration, blocking of legitimate traffic or users, financial loss, or legal claims and "
        "consequences, whether arising from the use, inability to use, misuse or abuse of the software, or from a software or security defect in it.",
        "4. The user and the user's organisation alone are responsible for everything done with the software (for example blocking addresses, running "
        "commands on or changing devices, scanning networks, or sending data and requests to services). The user must: work only on networks, devices and "
        "accounts they are formally authorised to manage; follow the laws and regulations of their country and their organisation's policies; review the "
        "results of automated actions; test before using it in production; and keep backups of data and device configurations.",
        "5. Other services you connect (such as Splunk, AbuseIPDB, FortiGate, Redmine and internet services) are subject to their own terms. The software may "
        "send data such as IP addresses to the services you configure; the user is responsible for this and for keeping keys and passwords safe.",
        "6. The author has tried in good faith, as far as possible, to make the software secure and stable, and has not knowingly included any malicious code; "
        "however, no software is free of defects. Misuse of the software or of its defects by others is not the author's responsibility. Report software "
        "problems on GitHub (Issues) and security problems privately (Security) so they can be fixed, and always use the latest version.",
        "7. Official releases are published only from the project's GitHub repository. The author is not responsible for versions modified by others or "
        "distributed from anywhere else.",
        "8. This text complements the MIT licence. If any part of it is unenforceable under law, the remaining parts stay in effect.",
        "By pressing “I accept” you confirm that you have read, understood and accepted this text and the MIT licence. If you do not accept, do not use the software.",
    ],
}


def payload():
    return {"v": VERSION, "title": TITLE, "text": TEXT}
