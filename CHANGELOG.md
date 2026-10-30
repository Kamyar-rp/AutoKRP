# Changelog

All notable changes are listed here. The project follows [Semantic Versioning](https://semver.org/) from the first public release.

## [1.31.0] — 2026-10-30

### Added
- **Device Access** (the former "SSH" page): the terminal can connect over **SSH, Telnet or a console cable** (USB/serial COM port).
  - Console cable: ports are detected automatically when the cable is plugged in; speed (9600 by default), data bits, parity, stop bits, flow control; **Break** button (e.g. Cisco password recovery). Desktop (client) mode only — hidden in server mode.
  - Telnet: temporary connections and saved devices, with optional automatic login and `enable` using stored credentials (never sent to the browser). Clear warning that Telnet is not encrypted.
  - **MultiExec**: type once, send to all ticked terminals; **saved command buttons** per user.
- Saved devices have a **protocol** (SSH or Telnet); Telnet devices work for runs, connection tests, config backups and asset scans (network device types that netmiko supports over Telnet).
- **Network tools** tab: locate an IP or MAC on the network (switch, port, VLAN from SNMP ARP and MAC tables of the monitoring SNMP targets; Cisco per-VLAN tables), traceroute (the OS's own tool), IP owner lookup with RDAP, and MAC vendor lookup from the IEEE registry (bundled, updatable by an admin).
- Monitoring: optional **HTTPS certificate expiry warning** for HTTP(S) targets (n days before; e-mail event "certificate about to expire").
- Sections can now be marked client-only or server-only; client-only parts are neither shown nor callable in server mode.

### Dependencies
- Added `pyserial` (BSD-3-Clause).

## [1.30.0] — 2026-10-29 — first public release

First release on GitHub. Highlights of the current version:

- **Default language is English** on first run (Persian is one click away); first-run window, tray menu, server status window and messages follow the chosen language.
- Response pipeline: Splunk → AbuseIPDB → FortiGate → Redmine, manual or scheduled, with preview, approval and test mode.
- Tools page with table (CSV) hand-off between tools; saved and scheduled jobs.
- Several FortiGate devices; **Python tasks** (`plan(fg, rows, ctx)`) with dry-run, approval of each proposed request and change history.
- SSH: script library, multi-device runs, last-command output as CSV, config backups with diff and multi-device download, live terminal, file transfer, offline FortiGate updates.
- Monitoring (Ping/TCP/HTTP, SNMP v2c/v3, traps, syslog), asset inventory, statistics, offline tools.
- Client (DPAPI or master password, recovery code) and multi-user HTTPS server mode; everything encrypted at rest.

Earlier versions (1.0–1.29) were developed privately.
