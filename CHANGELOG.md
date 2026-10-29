# Changelog

All notable changes are listed here. The project follows [Semantic Versioning](https://semver.org/) from the first public release.

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
