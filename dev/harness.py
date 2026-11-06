#!/usr/bin/env python3
"""
Harness تست: کلاس Api واقعی را با Demo اجرا می‌کند و UI را روی HTTP سرو می‌کند.
window.pywebview.api با یک shim به POST /api/<method> وصل می‌شود.
اجرا: python dev/harness.py [port]   سپس http://127.0.0.1:8765
"""
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("LOCALAPPDATA", str(ROOT / "dev" / "_data"))

from autokrp import paths  # noqa: E402
paths.set_demo(True)
from autokrp import clientgate  # noqa: E402

# مثل app.py (1.50): Gate — با رمز اصلی تا وارد کردن رمز هیچ داده‌ای باز نمی‌شود
api = clientgate.start(demo=True)

SHIM = """<script>
window.pywebview = { api: new Proxy({}, { get: (_, name) => (...args) =>
  fetch('/api/' + name, { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(args) }).then(r => r.json()) }) };
window.dispatchEvent(new Event('pywebviewready'));
</script>"""
TYPES = {".html": "text/html; charset=utf-8", ".css": "text/css", ".js": "application/javascript",
         ".woff2": "font/woff2", ".txt": "text/plain"}


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        rel = self.path.split("?")[0].lstrip("/") or "index.html"
        f = (ROOT / "ui" / rel).resolve()
        if not str(f).startswith(str(ROOT / "ui")) or not f.is_file():
            self.send_error(404)
            return
        data = f.read_bytes()
        if f.name == "index.html":
            data = data.replace(b'<script src="app.js">', SHIM.encode() + b'<script src="app.js">')
        self.send_response(200)
        self.send_header("Content-Type", TYPES.get(f.suffix, "application/octet-stream"))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        name = self.path.split("/api/", 1)[-1]
        args = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"[]")
        if name.startswith("_") or not callable(getattr(api, name, None)):
            out = {"ok": False, "error": "not allowed"}
        else:
            out = getattr(api, name)(*args)
        body = json.dumps(out, ensure_ascii=False, default=str).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8765
    print(f"http://127.0.0.1:{port}")
    ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()
