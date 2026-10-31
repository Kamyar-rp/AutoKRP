# Changelog

All notable changes are listed here. The project follows [Semantic Versioning](https://semver.org/) from the first public release.

## [1.33.0] — 2026-10-31

### Added
- **About → Updates and security** (admins): checks whether a newer AutoKRP release is published on GitHub (with a link to the download page) and checks every library bundled in the app against the OSV vulnerability database (the same source pip-audit uses), showing the package, installed version, advisory ID, severity and the fixed version.
- The check runs **automatically once a day** (can be turned off) or with **Check now**. New findings are shown as an app notification and a badge on "About", and can be e-mailed (new notification event "Updates and security"). Each finding is reported once, not every day. Accepted risks (paramiko SHA-1 advisory) are listed but do not raise alerts.
- `build.bat` and the release workflow now bundle the exact list of shipped libraries (`dev/deps_snapshot.py` → `autokrp/build_deps.txt`) so the check knows what is inside the exe.
- Only the app version and the library names/versions are sent to GitHub and osv.dev; no organisational data.

### Fixed
- Console-cable dialog: listing COM ports can take several seconds on Windows; the list is now cached briefly and refreshed without overlapping requests (found in a memory-diagnostics log).

## [1.32.0] — 2026-10-31

### Added
- **Access groups** (Settings → Users and access), similar to the Django admin: each group sets a level for every tool and section — **Hidden**, **View** (results and information only) or **Run** (run and change) — and which shared devices its members see (all, by device group, or individual devices).
- Users belong to one or more groups and get the highest level among them; a per-user exception can replace any tool level or the device list. The "Read-only" role is capped at View.
- **Main admin**: one local admin (the first one by default) always has everything and is the only one who can change users, groups and access. Other admins are limited by their groups like everyone else.
- The interface follows the levels: hidden tools disappear, view-only tools have no run/change buttons, and the "Device Access" page opens on whatever the user may use (e.g. terminal only). History rows of hidden tools are not shown.

### Changed
- Every API call checks the user's level for the tool it belongs to, in both server and multi-user client mode; a tool switched off in Settings → General stays off for everyone.
- Existing users keep exactly their previous access until the main admin edits them (old role + tool ticks become user exceptions).

### Security
- Includes the 1.31.1 fix: `pyasn1>=0.6.5` (CVE-2026-119194, CVE-2026-119195, CVE-2026-119196, CVE-2026-119197).

## [1.31.1] — 2026-10-31

### Security
- Require `pyasn1>=0.6.5` (dependency of pysnmp and ldap3) to fix CVE-2026-119194, CVE-2026-119195, CVE-2026-119196 and CVE-2026-119197 reported by pip-audit during the build.

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
