"""
کارگر SNMP (1.34) — فرایند جدا برای استفاده از چند هسته‌ی CPU.

برنامه این فرایند را با «--snmpworker PORT» اجرا می‌کند (exe: خود AutoKRP.exe؛ سورس: app.py). کارگر به 127.0.0.1:PORT
وصل می‌شود و توکن یک‌بارمصرف (متغیر محیطی AKRP_SNMPW_TOKEN) را می‌فرستد؛ همان روش تسک‌های FortiGate (1.29).
پیام‌ها: JSON با پیشوند طول ۴ بایتی.
  برنامه → کارگر: {"op": "poll", "i", "cred", "host", "port", "cfg", "timeout", "retries", "budget"} |
                   {"op": "profiles", "p": [...]} | {"op": "quit"}
  کارگر → برنامه: {"i", "r": {"raw"|"alive"...}} یا {"i", "e": پیام خطا}؛ همراه هر پاسخ «m» = RAM کارگر (بایت).
کار سنگین (درخواست‌ها و رمزگشایی BER) اینجاست؛ نرخ‌ها، هشدارها و ذخیره در خود برنامه می‌مانند.
با بسته شدن اتصال (برنامه بسته شد یا از کار افتاد) کارگر خودش خارج می‌شود.
"""
import asyncio
import json
import logging
import os
import socket
import struct
import sys
import threading
import time

CONCURRENCY = 64
MAX_MSG = 64 * 1024 * 1024
log = logging.getLogger("snmpworker")


def send_msg(sock, obj, lock=None):
    data = json.dumps(obj, separators=(",", ":"), ensure_ascii=False, default=str).encode("utf-8")
    pkt = struct.pack(">I", len(data)) + data
    if lock:
        with lock:
            sock.sendall(pkt)
    else:
        sock.sendall(pkt)


def recv_exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        b = sock.recv(n - len(buf))
        if not b:
            return None
        buf += b
    return bytes(buf)


def recv_msg(sock):
    h = recv_exact(sock, 4)
    if h is None:
        return None
    n = struct.unpack(">I", h)[0]
    if n > MAX_MSG:
        raise ValueError("message too large")
    data = recv_exact(sock, n)
    if data is None:
        return None
    return json.loads(data.decode("utf-8"))


def main(port):
    token = os.environ.pop("AKRP_SNMPW_TOKEN", "")
    logging.basicConfig(level=logging.WARNING)
    from autokrp.health import _rss
    from autokrp.snmp import Client, SnmpError, poll_raw
    sock = socket.create_connection(("127.0.0.1", int(port)), timeout=30)
    sock.settimeout(None)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    wlock = threading.Lock()
    send_msg(sock, {"t": "hello", "token": token, "pid": os.getpid()})
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    cl = Client()
    cl._loop = loop                       # درخواست‌ها روی حلقه‌ی همین نخ
    state = {"profiles": [], "mem": 0, "mem_t": 0}
    sem = asyncio.Semaphore(CONCURRENCY)

    def mem():
        now = time.time()
        if now - state["mem_t"] > 10:
            state["mem"], state["mem_t"] = _rss() or 0, now
        return state["mem"]

    def reply(obj):
        obj["m"] = mem()
        try:
            send_msg(sock, obj, wlock)
        except OSError:
            loop.call_soon_threadsafe(loop.stop)

    async def job(m):
        async with sem:
            cfg = dict(m["cfg"])
            cfg["_profiles"] = state["profiles"]
            try:
                r = await poll_raw(cl, m["cred"], m["host"], m["port"], cfg, float(m["timeout"]), int(m["retries"]), float(m["budget"]))
                out = {"i": m["i"], "r": r}
            except SnmpError as e:
                out = {"i": m["i"], "e": str(e), "s": 1 if getattr(e, "silent", False) else 0}
            except Exception as e:  # noqa — داده‌ی غیرمنتظره‌ی یک دستگاه نباید کارگر را از کار بیندازد
                log.exception("snmp worker job")
                out = {"i": m["i"], "e": f"خطای داخلی کارگر SNMP: {e.__class__.__name__}"}
        await loop.run_in_executor(None, reply, out)

    def handle(m):
        op = m.get("op")
        if op == "poll":
            loop.create_task(job(m))
        elif op == "profiles":
            state["profiles"] = m.get("p") or []
        elif op == "quit":
            loop.stop()

    def reader():
        try:
            while True:
                m = recv_msg(sock)
                if m is None:
                    break
                loop.call_soon_threadsafe(handle, m)
        except Exception:  # noqa — اتصال خراب
            pass
        loop.call_soon_threadsafe(loop.stop)

    async def housekeeping():
        while True:
            await asyncio.sleep(300)
            cl.prune()

    threading.Thread(target=reader, name="snmpw-reader", daemon=True).start()
    loop.create_task(housekeeping())
    try:
        loop.run_forever()
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
