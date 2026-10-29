"""ساخت ui/ports_iana.js از رجیستری IANA (بسته‌ی npm «port-numbers»، مجوز BSD-2-Clause).

  npm pack port-numbers && tar xzf port-numbers-*.tgz
  python dev/ports_build.py package/index.json

خروجی: [[پورت، "tcp" | "udp" | "tcp/udp" | "sctp" | …، نام سرویس، توضیح]] — Reserved/Unassigned و بی‌نام حذف می‌شوند؛
tcp و udp با نام و توضیح یکسان یک ردیف می‌شوند. فایل فقط وقتی کاربر «فهرست پورت‌ها» را باز می‌کند بارگذاری می‌شود.
"""
import json
import sys
from collections import OrderedDict
from datetime import date
from pathlib import Path

NOTICE = """/* IANA Service Name and Transport Protocol Port Number Registry — https://www.iana.org/assignments/service-names-port-numbers/
   Data via the npm package "port-numbers" (https://github.com/silverwind/port-numbers):
   Copyright (c) silverwind. All rights reserved.
   Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following
   conditions are met: 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the
   following disclaimer. 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and
   the following disclaimer in the documentation and/or other materials provided with the distribution.
   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT
   NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
   COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
   (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
   INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
   OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. */
"""


def main(src, version=""):
    d = json.loads(Path(src).read_text(encoding="utf-8"))
    rows = OrderedDict()
    for key, (name, desc) in d.items():
        port, proto = key.split("/")
        name, desc = (name or "").strip(), " ".join((desc or "").split())
        if not name or desc.lower() in ("reserved", "unassigned"):
            continue
        k = (int(port), name, desc)
        rows.setdefault(k, []).append(proto)
    out = []
    for (port, name, desc), protos in sorted(rows.items(), key=lambda x: (x[0][0], x[0][1])):
        p = "tcp/udp" if set(protos) >= {"tcp", "udp"} else "/".join(sorted(set(protos)))
        out.append([port, p, name, desc if desc.lower() != name.lower() else ""])
    js = (NOTICE + f"/* {len(out)} entries; built {date.today()} from port-numbers {version} by dev/ports_build.py */\n"
          + "window.PORTS_IANA = " + json.dumps(out, ensure_ascii=False, separators=(",", ":")) + ";\n")
    dst = Path(__file__).resolve().parent.parent / "ui" / "ports_iana.js"
    dst.write_text(js, encoding="utf-8")
    print(len(out), "entries,", dst.stat().st_size // 1024, "KB")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else "")
