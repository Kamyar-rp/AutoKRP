#!/usr/bin/env python3
"""
سرورهای SSH آزمایشی (فقط برای تست توسعه، نه برای استفاده‌ی واقعی):
  linux  ← exec: «bash -s» واقعاً با bash اجرا می‌شود؛ sudo با رمز شبیه‌سازی می‌شود
  cisco  ← shell تعاملی شبیه Cisco IOS: prompt، enable، configure terminal، write memory
اجرا: python dev/fake_ssh.py linux 2222 [keyfile]   |   python dev/fake_ssh.py cisco 2223 [keyfile]
یوزر: admin  پسورد: P@ssw0rd  enable/sudo: En@ble1
"""
import socket
import subprocess
import sys
import threading

import paramiko

USER, PASSWORD, SECRET = "admin", "P@ssw0rd", "En@ble1"
AUTH_LOG = []


class Server(paramiko.ServerInterface):
    def __init__(self):
        self.event = threading.Event()
        self.exec_cmd = None

    def check_auth_password(self, username, password):
        AUTH_LOG.append((username, password == PASSWORD))
        print("AUTH", username, "ok" if password == PASSWORD else "BAD", flush=True)
        return paramiko.AUTH_SUCCESSFUL if (username, password) == (USER, PASSWORD) else paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, *a):
        return True

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_exec_request(self, channel, command):
        self.exec_cmd = command.decode()
        self.event.set()
        return True


def read_all_stdin(chan):
    data = b""
    while True:
        d = chan.recv(65536)
        if not d:
            break
        data += d
    return data


def linux_exec(chan, cmd):
    if cmd == "sudo -n true":
        chan.send_exit_status(1)
        return
    stdin = read_all_stdin(chan)
    if cmd.startswith("sudo -S"):
        pw, _, stdin = stdin.partition(b"\n")
        if pw.decode() != SECRET:
            chan.sendall_stderr(b"sudo: 1 incorrect password attempt\n")
            chan.send_exit_status(1)
            return
        stdin = b"echo '[root]'\n" + stdin
    if cmd.endswith("bash -s"):
        p = subprocess.run(["bash", "-s"], input=stdin, capture_output=True, timeout=30)
        chan.sendall(p.stdout)
        chan.sendall_stderr(p.stderr)
        chan.send_exit_status(p.returncode)
    else:
        p = subprocess.run(["bash", "-c", cmd], capture_output=True, timeout=30)
        chan.sendall(p.stdout + p.stderr)
        chan.send_exit_status(p.returncode)


def cisco_shell(chan):
    state = {"mode": ">", "await_pw": False}
    hostname = "R1"
    running = ["hostname R1", "interface Gi0/1", " description uplink"]

    def prompt():
        return {">": f"{hostname}>", "#": f"{hostname}#", "cfg": f"{hostname}(config)#", "if": f"{hostname}(config-if)#"}[state["mode"]]

    chan.sendall(b"\r\n" + prompt().encode())
    buf = b""
    while True:
        d = chan.recv(1024)
        if not d:
            return
        buf += d
        while b"\n" in buf or b"\r" in buf:
            idx = min(i for i in (buf.find(b"\r"), buf.find(b"\n")) if i >= 0)
            line, buf = buf[:idx].decode(errors="replace"), buf[idx + 1:].lstrip(b"\n")
            if state["await_pw"]:
                state["await_pw"] = False
                if line == SECRET:
                    state["mode"] = "#"
                    chan.sendall(b"\r\n" + prompt().encode())
                else:
                    chan.sendall(b"\r\n% Access denied\r\n\r\n" + prompt().encode())
                continue
            chan.sendall(line.encode() + b"\r\n")   # echo
            cmd = line.strip()
            out = ""
            if not cmd:
                pass
            elif cmd.startswith("terminal"):
                pass
            elif cmd == "enable":
                if state["mode"] == ">":
                    state["await_pw"] = True
                    chan.sendall(b"Password: ")
                    continue
            elif cmd == "exit" and state["mode"] in (">", "#"):
                chan.close()
                return
            elif cmd.startswith("show version"):
                out = "Cisco IOS Software, C2960 Software, Version 15.2(7)E4, RELEASE SOFTWARE (fc2)"
            elif cmd == "show running-config" and state["mode"] == "#":
                out = "Building configuration...\r\n" + "\r\n".join(running) + "\r\nend"
            elif cmd in ("configure terminal", "conf t") and state["mode"] == "#":
                out = "Enter configuration commands, one per line.  End with CNTL/Z."
                state["mode"] = "cfg"
            elif cmd == "end" and state["mode"] in ("cfg", "if"):
                state["mode"] = "#"
            elif cmd == "exit" and state["mode"] == "if":
                state["mode"] = "cfg"
            elif cmd == "exit" and state["mode"] == "cfg":
                state["mode"] = "#"
            elif state["mode"] in ("cfg", "if"):
                if cmd.startswith("interface "):
                    state["mode"] = "if"
                if cmd.startswith("hostname "):
                    hostname = cmd.split()[1]
                if cmd.startswith("bogus"):
                    out = "                ^\r\n% Invalid input detected at '^' marker."
                else:
                    running.append(cmd)
            elif cmd in ("write memory", "write mem") and state["mode"] == "#":
                out = "Building configuration...\r\n[OK]"
            else:
                out = "                ^\r\n% Invalid input detected at '^' marker."
            chan.sendall((out + "\r\n" if out else "") .encode() + prompt().encode())


def handle(client, kind, key):
    t = paramiko.Transport(client)
    t.add_server_key(key)
    srv = Server()
    try:
        t.start_server(server=srv)
    except (paramiko.SSHException, EOFError):
        return
    chan = t.accept(20)
    if chan is None:
        t.close()
        return
    srv.event.wait(10)
    try:
        if kind == "linux" and srv.exec_cmd is not None:
            linux_exec(chan, srv.exec_cmd)
        elif kind == "cisco":
            cisco_shell(chan)
    except Exception as e:
        print("ERR", e, flush=True)
    finally:
        try:
            chan.close()
        except Exception:
            pass
        # بعد از exec اتصال را باز می‌گذاریم تا کلاینت کانال‌های بعدی را باز کند
        if kind == "linux":
            while t.is_active():
                c2 = t.accept(2)
                if c2 is None:
                    continue
                srv.event.clear()
                srv.exec_cmd = None
                srv.event.wait(10)
                try:
                    if srv.exec_cmd is not None:
                        linux_exec(c2, srv.exec_cmd)
                finally:
                    c2.close()


def main():
    kind, port = sys.argv[1], int(sys.argv[2])
    keyfile = sys.argv[3] if len(sys.argv) > 3 else None
    if keyfile:
        try:
            key = paramiko.RSAKey(filename=keyfile)
        except FileNotFoundError:
            key = paramiko.RSAKey.generate(2048)
            key.write_private_key_file(keyfile)
    else:
        key = paramiko.RSAKey.generate(2048)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port))
    s.listen(20)
    print(f"{kind} listening {port}", flush=True)
    while True:
        c, _ = s.accept()
        threading.Thread(target=handle, args=(c, kind, key), daemon=True).start()


if __name__ == "__main__":
    main()
