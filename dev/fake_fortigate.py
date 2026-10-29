#!/usr/bin/env python3
"""
سرور SSH آزمایشی که رفتار FortiGate 7.2 (چند-VDOM) را برای «به‌روزرسانی FortiGate» شبیه‌سازی می‌کند.
فایل‌ها را واقعاً از سرور TFTP دانلود می‌کند. خروجی‌ها مطابق نمونه‌ی واقعی کاربر است.
اجرا: python dev/fake_fortigate.py [port]   یوزر admin / پسورد F0rti!pass
"""
import hashlib
import socket
import struct
import sys
import threading

import paramiko

USER, PASS = "admin", "F0rti!pass"
DEBUG = "--debug" in sys.argv
HOST = "FGT-TEST"
HOSTKEY = paramiko.RSAKey.generate(2048)
VERS = {"AV Engine": "6.00303", "Virus Definitions": "92.08010", "IPS Attack Engine": "7.00341", "Attack Definitions": "28.00898",
        "Application Definitions": "28.00898", "Industrial Attack Definitions": "6.00741", "IoT Detect Definitions": "28.00898",
        "Internet-service Full Database": "7.03700", "Botnet Domain Database": "4.00895", "Mobile Malware Definitions": "92.08010",
        "AI/Machine Learning Malware Detection Model": "2.17360", "Malicious URL Database": "1.00001"}
PKG_TO_COMP = {"IPS.pkg": "Attack Definitions", "Antivirus.pkg": "Virus Definitions", "Application-Control.pkg": "Application Definitions",
               "AVAI.pkg": "AI/Machine Learning Malware Detection Model", "Mobile-Malware.pkg": "Mobile Malware Definitions",
               "Internet-Service.pkg": "Internet-service Full Database", "Industrial-DB.pkg": "Industrial Attack Definitions",
               "Botnet-Domain.pkg": "Botnet Domain Database", "IOT.pkg": "IoT Detect Definitions", "MCDB.pkg": "Malicious URL Database"}
NAMES = {"ips": "IPS", "av": "AV", "other-objects": "other objects"}


def tftp_get(server, name, timeout=3):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    s.sendto(struct.pack("!H", 1) + name.encode() + b"\0octet\0", (server, 69))
    data, want = b"", 1
    try:
        while True:
            d, addr = s.recvfrom(4096)
            op = struct.unpack("!H", d[:2])[0]
            if op == 5:
                code = struct.unpack("!H", d[2:4])[0]
                return None, f"Error code {code}: {d[4:-1].decode()}"
            blk = struct.unpack("!H", d[2:4])[0]
            if blk == want:
                data += d[4:]
                want += 1
            s.sendto(struct.pack("!HH", 4, blk), addr)
            if len(d) - 4 < 512:
                return data, ""
    except socket.timeout:
        return None, "Error code 0: Timeout"
    finally:
        s.close()


class Server(paramiko.ServerInterface):
    def check_auth_password(self, u, p):
        return paramiko.AUTH_SUCCESSFUL if (u, p) == (USER, PASS) else paramiko.AUTH_FAILED

    def get_allowed_auths(self, u):
        return "password"

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, *a):
        return True

    def check_channel_shell_request(self, c):
        return True


def session(chan):
    ctx = {"mode": "", "pending": None}
    prompt = lambda: f"{HOST} ({ctx['mode']}) # " if ctx["mode"] else f"{HOST} # "
    send = lambda t: chan.send(t.replace("\n", "\r\n"))

    def handle(line):
        if DEBUG:
            print("LINE:", repr(line), "mode:", ctx["mode"], flush=True)
        low = line.strip()
        if low == "":
            return ""
        if low.startswith("get system status | grep Virtual"):
            return "Virtual domain configuration: multiple"
        if low.startswith("get system status | grep Version"):
            return "Version: FortiGate-100D v7.2.8,build1639,240313 (GA.M)"
        if low == "config global":
            ctx["mode"] = "global"
            return ""
        if low == "config vdom":
            ctx["mode"] = "vdom"
            return ""
        if low.startswith("edit ") and ctx["mode"] == "vdom":
            ctx["mode"] = low.split()[1]
            return ""
        if low == "end":
            ctx["mode"] = ""
            return ""
        if low == "get system console" and ctx["mode"] == "global":
            return "output              : standard"
        if low == "diagnose autoupdate versions":
            if ctx["mode"] != "global":
                return "Unknown action 0\nCommand fail. Return code -1"
            return "\n".join(f"\n{k}\n{'-' * len(k)}\nVersion: {v} signed\nContract Expiry Date: n/a\n"
                             f"Last Updated using manual update on Tue Jan 14 18:23:00 2025\n"
                             f"Last Update Attempt: Sun Oct  4 10:59:50 2026\nResult: Connectivity failure" for k, v in VERS.items())
        if low.startswith("execute restore "):
            parts = low.split()
            if len(parts) != 6 or parts[3] != "tftp":
                return "Command fail. Return code -1"
            if ctx["mode"] in ("", "global", "vdom"):
                return "Command fail. Return code -1"
            ctx["pending"] = (parts[2], parts[4], parts[5])
            return "__yn__"
        if low == "exit":
            return "__exit__"
        return "Unknown action 0\nCommand fail. Return code -61"

    def restore(kind, fname, server):
        nm = NAMES.get(kind, kind)
        send(f"\nPlease wait...\n\nConnect to tftp server {server} ...\n")
        data, err = tftp_get(server, fname)
        if data is None:
            send(f"{err}\nInterrupted system call\nCan not get {nm} database from tftp server via vdom {ctx['mode']}.\n"
                 f"Failed to restore {nm} package file.\nCommand fail. Return code -39\n\n")
            return
        send("###\n\n")
        comp = PKG_TO_COMP.get(fname)
        if comp:
            major = VERS[comp].split(".")[0]
            VERS[comp] = f"{major}.{int(hashlib.md5(data).hexdigest(), 16) % 100000:05d}"
        send(f"Get {nm} database from tftp server OK.\n\n")

    send(prompt())
    buf = ""
    while True:
        try:
            data = chan.recv(1024)
        except Exception:
            return
        if not data:
            return
        for ch in data.decode("utf-8", "replace"):
            if ctx["pending"]:
                if ch in "\r\n":
                    continue
                chan.send(ch)
                kind, fname, server = ctx["pending"]
                ctx["pending"] = None
                if ch.lower() == "y":
                    restore(kind, fname, server)
                else:
                    send("\n")
                send(prompt())
                continue
            if ch in "\r\n":
                if ch == "\n" and buf == "" and getattr(session, "_cr", False):
                    session._cr = False
                    continue
                session._cr = ch == "\r"
                line, buf = buf, ""
                send("\n")
                out = handle(line)
                if out == "__exit__":
                    chan.close()
                    return
                if out == "__yn__":
                    send(f"This operation will overwrite the current {NAMES.get(ctx['pending'][0], '')} package!\n"
                         "Do you want to continue? (y/n)")
                    continue
                if out:
                    send(out + "\n")
                send("\n" + prompt() if out else prompt())
            else:
                buf += ch
                chan.send(ch)


def conn(client):
    t = paramiko.Transport(client)
    t.add_server_key(HOSTKEY)
    # درایور fortinet در netmiko فقط group14-sha1 / group-exchange را می‌پذیرد؛ GEX به فایل moduli نیاز دارد
    t.load_server_moduli()
    try:
        t.start_server(server=Server())
        ch = t.accept(20)
        if ch:
            session(ch)
    except Exception:
        pass
    finally:
        t.close()


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 and sys.argv[1].isdigit() else 2224
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port))
    s.listen(10)
    print(f"fake FortiGate on 127.0.0.1:{port}", flush=True)
    while True:
        c, _ = s.accept()
        threading.Thread(target=conn, args=(c,), daemon=True).start()
