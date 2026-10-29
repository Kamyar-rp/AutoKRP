#!/usr/bin/env python3
"""
سرور SSH آزمایشی که رفتار Cisco IOS را شبیه‌سازی می‌کند (فقط برای تست درایور netmiko در توسعه).
اجرا: python dev/fake_cisco.py [port]   یوزر admin / پسورد C1sco!pass / enable: En@ble
"""
import socket
import sys
import threading

import paramiko

USER, PASS, ENABLE = "admin", "C1sco!pass", "En@ble"
# AKRP_FAKE_SAMPLES=<پوشه>: پاسخ «show version» و «show inventory» از فایل نمونه‌ی واقعی (c9300_show_*.txt)
import os as _os
_SD = _os.environ.get("AKRP_FAKE_SAMPLES", "")
SAMPLE = {k: open(_os.path.join(_SD, f"c9300_show_{k}.txt"), encoding="utf-8").read().rstrip("\n")
          for k in ("version", "inventory")} if _SD else {}
HOSTKEY = paramiko.RSAKey.generate(2048)


class Server(paramiko.ServerInterface):
    def check_auth_password(self, username, password):
        return paramiko.AUTH_SUCCESSFUL if (username, password) == (USER, PASS) else paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, *a):
        return True

    def check_channel_shell_request(self, channel):
        return True


# کانفیگ مشترک بین همه‌ی اتصال‌ها (مثل یک دستگاه واقعی)
CFG = []
RUNNING = {"hostname": "hostname R1"}


def session(chan):
    host, mode, cfg = "R1", ">", CFG
    running = RUNNING
    prompt = lambda: {">": f"{host}>", "#": f"{host}#", "c": f"{host}(config)#", "i": f"{host}(config-if)#"}[mode]
    send = lambda s: chan.send(s.replace("\n", "\r\n"))
    def handle(line):
        nonlocal mode
        if not line:
            return ""
        low = line.lower()
        if low.startswith("terminal "):
            return ""
        if SAMPLE and "|" not in low and low.startswith(("show version", "show inventory")):
            return SAMPLE["version" if "version" in low else "inventory"]
        if mode == ">":
            if low in ("enable", "en"):
                return "__pw__"
            if low in ("exit", "logout"):
                return "__exit__"
            if low.startswith("show version"):
                return "Cisco IOS Software, C2900 Software (C2900-UNIVERSALK9-M), Version 15.2(4)M"
            return "% Invalid input detected at '^' marker."
        if mode == "#":
            if low in ("configure terminal", "conf t"):
                mode = "c"
                return "Enter configuration commands, one per line.  End with CNTL/Z."
            if low.startswith("show version"):
                return "Cisco IOS Software, C2900 Software (C2900-UNIVERSALK9-M), Version 15.2(4)M"
            if low.startswith("show run"):
                import random, time as _t
                head = ["Building configuration...", "", f"Current configuration : {1200 + len(cfg) * 40} bytes", "!",
                        f"! Last configuration change at {_t.strftime('%H:%M:%S')} UTC by admin",
                        f"ntp clock-period {random.randint(17179000, 17179999)}", "!"]
                return "\n".join(head + list(running.values()) + cfg + ["end"])
            if low.startswith("write") or low.startswith("copy run"):
                return "Building configuration...\n[OK]"
            if low in ("exit", "logout"):
                return "__exit__"
            if low == "disable":
                mode = ">"
                return ""
            return "% Invalid input detected at '^' marker."
        # config / config-if
        if low in ("end",):
            mode = "#"
            return ""
        if low == "exit":
            mode = "c" if mode == "i" else "#"
            return ""
        if low.startswith("interface "):
            mode = "i"
            cfg.append(line)
            return ""
        if low.startswith("hostname "):
            running["hostname"] = line
            return ""
        if low.startswith("bogus"):
            return "                ^\n% Invalid input detected at '^' marker."
        cfg.append((" " if mode == "i" else "") + line)
        return ""

    send("\nUser Access Verification\n\n" + prompt())
    buf, want_pw = "", False
    while True:
        try:
            data = chan.recv(1024)
        except Exception:
            return
        if not data:
            return
        for ch in data.decode("utf-8", "replace"):
            if ch in "\r\n":
                if ch == "\n" and buf == "" and getattr(session, "_last_cr", False):
                    session._last_cr = False
                    continue
                session._last_cr = ch == "\r"
                line, buf = buf.strip(), ""
                if want_pw:
                    want_pw = False
                    send("\n")
                    if line == ENABLE:
                        mode = "#"
                    else:
                        send("% Access denied\n")
                    send("\n" + prompt())
                    continue
                send("\n")
                out = handle(line)
                if out == "__exit__":
                    chan.close()
                    return
                if out == "__pw__":
                    send("Password: ")
                    want_pw = True
                    continue
                if out:
                    send(out + "\n")
                send(prompt())
            else:
                buf += ch
                if not want_pw:
                    chan.send(ch)

def serve(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", port))
    sock.listen(20)
    print(f"fake cisco on 127.0.0.1:{port}", flush=True)
    while True:
        client, _ = sock.accept()
        threading.Thread(target=conn, args=(client,), daemon=True).start()


def conn(client):
    t = paramiko.Transport(client)
    t.add_server_key(HOSTKEY)
    try:
        t.start_server(server=Server())
        chan = t.accept(20)
        if chan:
            session(chan)
    except Exception:
        pass
    finally:
        t.close()


if __name__ == "__main__":
    serve(int(sys.argv[1]) if len(sys.argv) > 1 else 2223)
