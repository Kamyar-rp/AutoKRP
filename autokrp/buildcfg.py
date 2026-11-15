"""Build profile (1.56). This file describes the FULL build and is what runs from source.

build.bat (dev/mkbuild.py) writes its own copy of this file into the staged source of a custom build, so the working
tree is never changed. Modules that are not in MODULES are not only switched off: their engines are replaced by empty
stubs (autokrp/absent.py), their pages and scripts are left out of the UI, their API methods are removed and their
libraries are not bundled.

  MODULES  sections that are part of this build:
             sec      security: Splunk, AbuseIPDB, FortiGate, Redmine, DNS, scan, extra check, addresses, automation
             dev      device access: SSH/Telnet, config backup, terminal, file transfer, TFTP, serial, network tools, API tool
             monitor  monitoring: targets, SNMP, traps/syslog, maps, dashboards, NOC
             asset    assets
             offline  offline tools (FortiGate offline update)
  MODE     both | client | server   ("both" = asked at first start)
  EDITION  "" for the full build; otherwise the name shown in About and used in the exe name (AutoKRP-<EDITION>.exe)

Always part of every build: sign-in, users and groups, encryption and security settings, database (local, MySQL,
PostgreSQL), general settings, history and audit log, tasks and messages, notifications, About, licence and author.
"""
ALL_MODULES = ("sec", "dev", "monitor", "asset", "offline")
MODULES = ALL_MODULES
MODE = "both"
EDITION = ""


def has(*sections):
    """True if any of these sections is part of this build."""
    return any(s in MODULES for s in sections)


def info():
    return {"modules": list(MODULES), "all": list(ALL_MODULES), "mode": MODE, "edition": EDITION, "full": tuple(MODULES) == ALL_MODULES and MODE == "both"}
