"""Modular build (1.56): choose which sections and which mode go into the exe.

Used by build.bat. The working tree is never changed: the source is copied to build/stage/<name>/ and the exe is
built from there.

  python dev/mkbuild.py                       ask (menu)
  python dev/mkbuild.py full                  everything (same as before 1.56)
  python dev/mkbuild.py monitor               monitoring only
  python dev/mkbuild.py monitor+asset server  several sections (sec, dev, monitor, asset, offline), server mode only
  extra words:  both | client | server   mode (default both = asked at first start)
                portable                 one-file exe only (no folder build for the installer)
                --ask                    only decide (menu if needed) and write build/build_choice.cmd for build.bat
                --stage-only             only create the staged source (for tests; no PyInstaller)
                --out DIR                stage directory (default build/stage/<name>)

What a section that is left out loses:
  * its engine modules are replaced by empty stubs (autokrp/absent.py), so their code is not in the exe;
  * its scripts are removed from ui/ and from index.html;
  * its API methods are removed from the Api class and blocked in perms (autokrp/buildcfg.py decides);
  * its third-party libraries are not bundled (PyInstaller --exclude-module).
Anything a kept section needs from another section stays (for example assets keeps the SSH and SNMP engines).
"""
import ast
import os
import re
import shutil
import subprocess  # nosec B404 — runs PyInstaller of the build venv with a fixed argument list
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SEP = os.pathsep            # PyInstaller --add-data separator (";" on Windows)
ALL = ("sec", "dev", "monitor", "asset", "offline")
TITLES = {"sec": "Security (Splunk, AbuseIPDB, FortiGate, Redmine, DNS, scan, addresses, automation)",
          "dev": "Device access (SSH/Telnet, backup, terminal, file transfer, TFTP, network tools, API tool)",
          "monitor": "Monitoring (targets, SNMP, traps/syslog, maps, dashboards, NOC)",
          "asset": "Assets", "offline": "Offline tools (FortiGate offline update)"}
SHORT = {"sec": "Sec", "dev": "Dev", "monitor": "Monitor", "asset": "Asset", "offline": "Offline"}

# Engine modules of each section (paths under autokrp/, without .py). A module listed for several sections stays when
# any of them is built. Everything not listed here is core and is always built.
ENGINES = {
    "sec": ["pipeline", "connectors/abuseipdb", "connectors/demo", "connectors/fortigate",
            "connectors/redmine", "connectors/splunk", "importer", "intel", "splq", "dnstool", "fgtask", "fgtask_child", "banrules",
            "jobs", "netscan"],
    "dev": ["ssh", "sshtemplate", "telnet", "term", "xfer", "tftp", "nettools", "apitool", "backup", "jobs"],
    "monitor": ["monitor", "snmp", "snmppool", "snmpworker", "monviews", "devevents", "topology", "tsdb", "netscan", "icmp", "mibs",
                "dashboards", "netmap", "mapdisc", "devprof", "nettools"],
    # assets are filled by SNMP and SSH scans: the engines stay, the Monitoring / Device access pages do not
    "asset": ["assets", "ssh", "sshtemplate", "telnet", "backup", "monitor", "snmp", "snmppool", "snmpworker", "monviews", "devevents",
              "topology", "tsdb", "netscan", "icmp", "mibs", "devprof", "nettools", "mapdisc"],
    "offline": ["fgupdate", "ssh", "sshtemplate", "telnet", "tftp", "backup"],
}
# UI scripts: shipped when any of the listed sections is built. app.js and the other shared scripts are always shipped.
UI = {
    "sshlive.js": ("dev",), "nettools.js": ("dev",), "apitool.js": ("dev",),
    "monitor.js": ("monitor",), "snmp.js": ("monitor",), "monview.js": ("monitor",), "noc.js": ("monitor",), "monevents.js": ("monitor",),
    "netmap.js": ("monitor",), "dash.js": ("monitor",),
    "assets.js": ("asset",),
    # offline tools page; nettools.js (dev) uses its CSV helper
    "offline.js": ("offline", "dev"), "offhash.js": ("offline", "dev"), "ports.js": ("offline", "dev"), "ports_iana.js": ("offline", "dev"),
}
UI_DIRS = {"dev": ["vendor"], "monitor": ["sounds"]}          # ui/vendor = xterm (terminal); ui/sounds = monitoring alarms
# Third-party libraries: needed when any of these sections (or mode) is built
LIBS = {
    "netmiko": ("dev", "asset", "offline"), "paramiko": ("dev", "asset", "offline"), "scp": ("dev", "asset", "offline"),
    "serial": ("dev",), "dns": ("sec",), "pysnmp": ("monitor", "asset"), "pysmi": ("monitor", "asset"),
    "lark": ("monitor", "asset"), "jinja2": ("monitor", "asset"),
}


def die(msg):
    print("[ERROR] " + msg)
    sys.exit(2)


def parse(argv):
    mods, mode, portable, stage_only, out, ask = None, "both", False, False, None, False
    it = iter(argv)
    for a in it:
        low = a.lower()
        if low == "--ask":
            ask = True
        elif low in ("both", "client", "server"):
            mode = low
        elif low == "portable":
            portable = True
        elif low == "all":
            pass                                   # old name of "exe + installer"
        elif low == "--stage-only":
            stage_only = True
        elif low == "--out":
            out = next(it, None) or die("--out needs a directory")
        elif low == "full":
            mods = list(ALL)
        else:
            parts = [p for p in re.split(r"[+,]", low) if p]
            bad = [p for p in parts if p not in ALL]
            if bad or not parts:
                die(f"unknown word: {a}   (sections: {', '.join(ALL)}; presets: full, monitor; modes: both, client, server)")
            mods = [m for m in ALL if m in parts]
    return mods, mode, portable, stage_only, out, ask


def ask(prompt, default):
    """input() that falls back to the default when there is no real input (1.57: on Windows "< nul" still looks like a
    console to isatty(), so the release script reached the menu and failed with EOFError)."""
    try:
        return input(prompt).strip() or default
    except (EOFError, KeyboardInterrupt, OSError):
        print(default)
        return default


def menu():
    """Interactive choice (only when no section word was given and a console is attached)."""
    print()
    print("=== AutoKRP build: what should be inside? ===")
    print("  1) Full        everything (default)")
    print("  2) Monitoring  monitoring only")
    print("  3) Custom      choose the sections")
    c = ask("Choice [1]: ", "1")
    if c == "2":
        mods = ["monitor"]
    elif c == "3":
        mods = []
        for m in ALL:
            if ask(f"  include {m:8} - {TITLES[m]} ? [y/N]: ", "n").lower().startswith("y"):
                mods.append(m)
        if not mods:
            die("nothing selected")
    else:
        mods = list(ALL)
    print()
    print("Mode:  1) Both (asked at first start, default)   2) Client only (desktop)   3) Server only (web)")
    mode = {"2": "client", "3": "server"}.get(ask("Choice [1]: ", "1"), "both")
    return mods, mode


def edition(mods, mode):
    full = tuple(mods) == ALL
    name = "" if full else "-".join(SHORT[m] for m in mods)
    if mode != "both":
        name = (name + "-" if name else "") + mode.capitalize()
    return name


def kept_engines(mods):
    keep = set()
    for m in mods:
        keep.update(ENGINES[m])
    return keep


def all_engines():
    out = set()
    for v in ENGINES.values():
        out.update(v)
    return out


# ------------------------------------------------------------------ stubs
def stub_source(path, rel):
    """A module with the same public names as the real one, but no code: classes and functions are Absent, exception
    classes are real exceptions (they appear in except clauses), simple constants keep their value."""
    tree = ast.parse(open(path, encoding="utf-8").read())
    depth = rel.count("/") + 1
    lines = [f'"""Not part of this build (generated by dev/mkbuild.py from {rel}.py)."""',
             f"from {'.' * depth}absent import ABSENT, Absent  # noqa: F401", ""]
    exc = set()
    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            bases = [getattr(b, "id", getattr(b, "attr", "")) for b in node.bases]
            if any(b.endswith(("Error", "Exception")) or b in exc for b in bases):
                base = next((b for b in bases if b in exc), "Exception")
                lines += [f"class {node.name}({base}):", "    pass", ""]
                exc.add(node.name)
            else:
                lines += [f"class {node.name}(Absent):", "    pass", ""]
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            lines += [f"def {node.name}(*a, **k):", "    return ABSENT", ""]
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            names = [t.id for t in targets if isinstance(t, ast.Name)]
            if not names or node.value is None:
                continue
            try:
                val = repr(ast.literal_eval(node.value))
            except Exception:
                val = "ABSENT"
            for n in names:
                if not (n.startswith("__") and n.endswith("__")):
                    lines.append(f"{n} = {val}")
    return "\n".join(lines) + "\n"


# ------------------------------------------------------------------ stage
SKIP_DIRS = {".git", "__pycache__", ".ruff_cache", "build", "dist", ".venv", ".venv-build", ".pybuild", ".innosetup", "kamyar", "vendor",
             ".github"}


def stage(mods, mode, out):
    name = edition(mods, mode)
    if os.path.isdir(out):
        shutil.rmtree(out)
    shutil.copytree(ROOT, out, ignore=lambda d, names: [n for n in names if n in SKIP_DIRS and os.path.join(d, n) != os.path.join(ROOT, "ui", "vendor")
                                                        or n.endswith((".pyc", ".zip"))])
    pkg = os.path.join(out, "autokrp")
    # 1) build profile
    src = open(os.path.join(pkg, "buildcfg.py"), encoding="utf-8").read()
    src = re.sub(r"^MODULES = .*$", f"MODULES = {tuple(mods)!r}", src, count=1, flags=re.M)
    src = re.sub(r"^MODE = .*$", f"MODE = {mode!r}", src, count=1, flags=re.M)
    src = re.sub(r"^EDITION = .*$", f"EDITION = {name!r}", src, count=1, flags=re.M)
    open(os.path.join(pkg, "buildcfg.py"), "w", encoding="utf-8", newline="\n").write(src)
    # 2) engines that are not needed -> stubs
    keep = kept_engines(mods)
    stubbed = sorted(all_engines() - keep)
    for rel in stubbed:
        p = os.path.join(pkg, *rel.split("/")) + ".py"
        if not os.path.isfile(p):
            die(f"engine module not found: {rel}.py (update ENGINES in dev/mkbuild.py)")
        open(p, "w", encoding="utf-8", newline="\n").write(stub_source(os.path.join(ROOT, "autokrp", *rel.split("/")) + ".py", rel))
    # 3) data files that only a missing section uses
    if "nettools" not in keep:
        _rm(os.path.join(pkg, "oui.dat"))
    if "snmp" not in keep:
        _rm(os.path.join(pkg, "trapdb.json"))
        _rm(os.path.join(out, "assets", "mibs"))
    # 4) UI scripts
    ui = os.path.join(out, "ui")
    gone = [f for f, need in UI.items() if not any(m in mods for m in need)]
    for f in gone:
        _rm(os.path.join(ui, f))
    for m in ALL:
        if m not in mods:
            for d in UI_DIRS.get(m, []):
                _rm(os.path.join(ui, d))
    idx = os.path.join(ui, "index.html")
    html = open(idx, encoding="utf-8").read()
    for f in gone:
        html, n = re.subn(rf'[ \t]*<script src="{re.escape(f)}"></script>\r?\n', "", html)
        if n > 1:
            die(f"more than one script tag of {f} in ui/index.html")          # 0 = loaded on demand (ports_iana.js)
    if "dev" not in mods:
        html = re.sub(r'[ \t]*<link[^>]+href="vendor/[^"]+"[^>]*>\r?\n', "", html)
    open(idx, "w", encoding="utf-8", newline="\n").write(html)
    return name, stubbed, gone


def _rm(p):
    if os.path.isdir(p):
        shutil.rmtree(p)
    elif os.path.exists(p):
        os.remove(p)


def pyi_args(mods, mode, name, stage_dir):
    """PyInstaller arguments for this profile (paths relative to the stage directory)."""
    exe = "AutoKRP" + ("-" + name if name else "")
    keep = kept_engines(mods)
    a = ["--windowed", "--name", exe, "--version-file", os.path.join("build", "version_info.txt"),
         "--add-data", "ui" + SEP + "ui", "--add-data", os.path.join("assets", "app.png") + SEP + "assets",
         "--add-data", os.path.join("autokrp", "build_deps.txt") + SEP + "autokrp",
         "--hidden-import", "pystray._win32", "--hidden-import", "pymysql", "--hidden-import", "pg8000",
         "--hidden-import", "sqlcipher3", "--collect-binaries", "sqlcipher3"]
    if os.path.exists(os.path.join(stage_dir, "assets", "app.ico")):
        a += ["--icon", os.path.join("assets", "app.ico")]
    for m in ("dbpg", "fgtask_child", "snmpworker", "snmppool", "tsdb", "icmp", "monviews", "netmap", "terms", "apitool", "cfgpack",
              "dashboards", "mapdisc", "auditlog", "todo", "clientgate", "absent", "buildcfg"):
        a += ["--hidden-import", "autokrp." + m]            # stubs included: tiny and harmless
    if "snmp" in keep:
        a += ["--add-data", os.path.join("assets", "mibs") + SEP + os.path.join("assets", "mibs"),
              "--add-data", os.path.join("autokrp", "trapdb.json") + SEP + "autokrp",
              "--collect-submodules", "pysnmp", "--collect-all", "pysmi", "--collect-data", "lark"]
    if "nettools" in keep:
        a += ["--add-data", os.path.join("autokrp", "oui.dat") + SEP + "autokrp"]
    if "ssh" in keep:
        a += ["--collect-submodules", "netmiko"]
    if "dev" in mods:
        a += ["--collect-submodules", "serial"]
    if "sec" in mods:
        a += ["--collect-submodules", "dns"]
    if mode != "client":
        a += ["--collect-submodules", "ldap3"]              # Active Directory sign-in exists only in server mode
    else:
        a += ["--exclude-module", "ldap3"]
    for lib, need in LIBS.items():
        if not any(m in mods for m in need):
            a += ["--exclude-module", lib]
    return exe, a


def main():
    mods, mode, portable, stage_only, out, ask = parse(sys.argv[1:])
    if mods is None and portable:
        mods = list(ALL)                           # "build.bat portable" = full build, portable exe only (release script)
    if mods is None:
        if sys.stdin is not None and sys.stdin.isatty():
            mods, mode = menu()
        else:
            mods = list(ALL)                       # no console (release script): the full build
    if ask:                                        # build.bat asks first, then prepares the tools, then builds
        os.makedirs(os.path.join(ROOT, "build"), exist_ok=True)
        words = ("full" if tuple(mods) == ALL else "+".join(mods)) + " " + mode + (" portable" if portable else "")
        open(os.path.join(ROOT, "build", "build_choice.cmd"), "w", encoding="ascii").write(f'set "BUILDARGS={words}"\n')
        print(f"Selected: {words}")
        return 0
    name = edition(mods, mode)
    exe = "AutoKRP" + ("-" + name if name else "")
    out = os.path.abspath(out or os.path.join(ROOT, "build", "stage", exe))
    print(f"Build: {exe}   sections: {', '.join(mods)}   mode: {mode}")
    name, stubbed, gone = stage(mods, mode, out)
    print(f"Stage: {out}")
    print(f"  left out: {len(stubbed)} engine modules, {len(gone)} UI scripts")
    exe, args = pyi_args(mods, mode, name, out)
    if stage_only:
        open(os.path.join(out, "pyinstaller-args.txt"), "w", encoding="utf-8").write("\n".join(args) + "\n")
        return 0
    py = sys.executable
    dist = os.path.join(ROOT, "dist")
    run = lambda extra: subprocess.run([py, "-m", "PyInstaller", "--noconfirm", "--clean"] + extra + args + ["app.py"], cwd=out)  # nosec B603  # noqa: E731
    subprocess.run([py, os.path.join("dev", "version_info.py"), os.path.join("build", "version_info.txt"), exe], cwd=out, check=True)  # nosec B603
    deps = os.path.join(out, "autokrp", "build_deps.txt")
    if not os.path.exists(deps):                   # normally written by dev/deps_snapshot.py (build.bat) before staging
        open(deps, "w", encoding="utf-8").close()
    r = run(["--onefile", "--distpath", dist, "--workpath", os.path.join(ROOT, "build", "onefile", exe)])
    if r.returncode or not os.path.exists(os.path.join(dist, exe + (".exe" if os.name == "nt" else ""))):
        die("PyInstaller (one-file) failed")
    folder = ""
    if not portable:
        r = run(["--onedir", "--distpath", os.path.join(dist, "installer"), "--workpath", os.path.join(ROOT, "build", "onedir", exe)])
        if r.returncode:
            die("PyInstaller (folder build for the installer) failed")
        folder = os.path.join(dist, "installer", exe)
    # values for build.bat (installer step, hashes, messages)
    with open(os.path.join(ROOT, "build", "last_build.cmd"), "w", encoding="ascii") as f:
        import uuid
        guid = "AD6B0823-5846-4C49-9730-7DAAD1702EE9" if not name else str(uuid.uuid5(uuid.UUID("AD6B0823-5846-4C49-9730-7DAAD1702EE9"), exe)).upper()
        f.write(f'set "EXENAME={exe}"\nset "EDITION={name}"\nset "BUILDMODS={"+".join(mods)}"\nset "BUILDMODE={mode}"\nset "INSTDIR={folder}"\n'
                f'set "APPGUID={guid}"\n')
    print(f"Built: dist{os.sep}{exe}{'.exe' if os.name == 'nt' else ''}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
