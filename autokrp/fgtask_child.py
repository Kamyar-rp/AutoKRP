"""
اجراکننده‌ی تسک پایتونی FortiGate در فرایند جدا (1.29) — فقط کتابخانه‌ی استاندارد.

برنامه این فرایند را با «--fgtask PORT» اجرا می‌کند؛ فرایند به 127.0.0.1:PORT وصل می‌شود، توکن یک‌بارمصرف را
(از متغیر محیطی AKRP_TASK_TOKEN) می‌فرستد و کد تسک، ردیف‌ها و ctx را می‌گیرد. تابع plan(fg, rows, ctx) فقط
می‌تواند بخواند (fg.get از راه برنامه، بدون دیدن توکن دستگاه) و کارها را پیشنهاد کند (fg.post/put/delete فقط ثبت
می‌کنند). ارسال واقعی را خود برنامه بعد از تأیید انجام می‌دهد. پیام‌ها: JSON یک‌خطی روی سوکت.
"""
import json
import os
import socket
import sys
import traceback

MAX_ACTIONS = 20000
MAX_GETS = 5000


class TaskError(Exception):
    pass


class _Conn:
    def __init__(self, port, token):
        self.s = socket.create_connection(("127.0.0.1", int(port)), timeout=30)
        self.s.settimeout(None)
        self.f = self.s.makefile("rwb")
        self.send({"t": "hello", "token": token})

    def send(self, obj):
        self.f.write(json.dumps(obj, ensure_ascii=False, default=str).encode("utf-8") + b"\n")
        self.f.flush()

    def recv(self):
        line = self.f.readline()
        if not line:
            raise SystemExit(3)
        return json.loads(line.decode("utf-8"))


def _check_path(path):
    p = str(path or "")
    if not p.startswith("/api/v2/") or ".." in p or "#" in p or "?" in p:
        raise TaskError(f"مسیر باید با /api/v2/ شروع شود (بدون ? # ..): {p}")
    return p


class FG:
    """رابط تسک با دستگاه: get خواندن واقعی (از راه برنامه)، post/put/delete فقط پیشنهاد."""

    def __init__(self, conn, ctx):
        self._c, self._n = conn, 0
        self.actions = []
        self.vdom = ctx.get("vdom", "")
        self.device = ctx.get("device", "")

    def get(self, path, params=None):
        """JSON پاسخ؛ برای 404 مقدار None. خطای دیگر ← TaskError."""
        self._n += 1
        if self._n > MAX_GETS:
            raise TaskError(f"بیش از {MAX_GETS} درخواست GET")
        self._c.send({"t": "get", "path": _check_path(path), "params": params or {}})
        r = self._c.recv()
        if r.get("t") == "abort":
            raise SystemExit(4)
        if r.get("status") == 404:
            return None
        if not r.get("ok"):
            raise TaskError(f"GET {path}: {r.get('error') or ('HTTP %s' % r.get('status'))}")
        return r.get("data")

    def results(self, path, params=None):
        """فقط فهرست results پاسخ (یا [] برای 404)."""
        d = self.get(path, params)
        return (d or {}).get("results") or [] if isinstance(d, dict) else []

    def _act(self, method, path, body, note, row):
        if len(self.actions) >= MAX_ACTIONS:
            raise TaskError(f"بیش از {MAX_ACTIONS} کار")
        if body is not None:
            json.dumps(body)        # باید JSON‌پذیر باشد
        a = {"method": method, "path": _check_path(path), "body": body, "note": str(note or "")[:300],
             "row": {str(k): ("" if v is None else str(v))[:200] for k, v in list((row or {}).items())[:12]} if isinstance(row, dict) else {}}
        self.actions.append(a)
        return a

    def post(self, path, body=None, note="", row=None):
        return self._act("POST", path, body, note, row)

    def put(self, path, body=None, note="", row=None):
        return self._act("PUT", path, body, note, row)

    def delete(self, path, note="", row=None):
        return self._act("DELETE", path, None, note, row)


def q(x):
    """نام برای مسیر URL (فاصله و / و …)."""
    from urllib.parse import quote
    return quote(str(x), safe="")


def main(port):
    token = os.environ.pop("AKRP_TASK_TOKEN", "")
    c = _Conn(port, token)
    start = c.recv()
    logs = []

    class _Out:
        buf = ""

        def write(self, s):
            s = str(s)
            self.buf += s
            while "\n" in self.buf:
                line, self.buf = self.buf.split("\n", 1)
                if line.strip():
                    c.send({"t": "log", "msg": line.rstrip()[:2000]})
            if len(self.buf) > 4000:
                self.flush()
            return len(s)

        def flush(self):
            if self.buf.strip():
                c.send({"t": "log", "msg": self.buf.rstrip()[:2000]})
            self.buf = ""

    out = _Out()
    sys.stdout = sys.stderr = out
    ctx = start.get("ctx") or {}
    fg = FG(c, ctx)
    try:
        ns = {"__name__": "akrp_task", "q": q, "TaskError": TaskError, "log": lambda *a: out.write(" ".join(map(str, a)) + "\n")}
        exec(compile(start["code"], "<task>", "exec"), ns)  # nosec B102 — کد تسکی که ادمین خودش نوشته؛ هدف همین قابلیت است (فرایند جدا، بدون اسرار)
        fn = ns.get("plan")
        if not callable(fn):
            raise TaskError("تابع plan(fg, rows, ctx) در کد نیست.")
        ret = fn(fg, start.get("rows") or [], ctx)
        if isinstance(ret, list) and ret and not fg.actions:      # اگر خودش فهرست ساخت
            for a in ret:
                if isinstance(a, dict):
                    fg._act(str(a.get("method", "POST")).upper(), a.get("path"), a.get("body"), a.get("note", ""), a.get("row"))
        out.flush()
        c.send({"t": "done", "actions": fg.actions, "logs": logs})
    except SystemExit:
        raise
    except BaseException as e:   # noqa — همه‌ی خطاهای کد کاربر به برنامه گزارش می‌شود
        out.flush()
        lines = traceback.format_exc(limit=12).splitlines()
        k = next((i for i, l in enumerate(lines) if '"<task>"' in l), None)
        tb = "\n".join(lines[k:] if k is not None else lines[-1:])
        if isinstance(e, TaskError):        # پیام عمدی خود تسک؛ traceback لازم نیست
            c.send({"t": "error", "msg": str(e), "tb": ""})
        else:
            c.send({"t": "error", "msg": f"{type(e).__name__}: {e}", "tb": tb[-4000:]})
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
