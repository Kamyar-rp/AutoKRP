# Changelog

All notable changes are listed here. The project follows [Semantic Versioning](https://semver.org/) from the first public release.

## [1.49.0] — 2026-11-05

### Added
- **Sharing tasks between users** (available when users are set up, in server mode or desktop multi-user mode).
  - **Checklist tasks** can be personal, or shared with the team in one of two ways:
    - **One tick for all**: one person ticks, and everyone sees it done, by whom and with the note.
    - **Each person ticks**: every member has their own tick, missed items and history.
  - A shared task can go to all users or only to chosen members. Only its creator can edit or delete it.
- **Assigning To-do tasks**: a To-do task can be assigned to another user.
  - The assignee sees it with "from …", can tick it and gets an automatic message.
  - When the assignee marks it done, the creator gets a message.
  - Only the creator can edit or delete the task.
- **Messages** (My tasks → Messages): short direct messages between users.
  - A list of people with unread counts, a conversation view that updates every few seconds, read marks (✓✓), and Enter to send.
  - Unread messages count in the sidebar, and a notice appears when a new message arrives.
- **Remind…** on any checklist or To-do task sends the task, with its title and an optional note, to another user as a message.
- Messages are kept for one year and are stored in the app database (encrypted columns in MySQL "cols" mode). Users can only read their own conversations.

## [1.48.0] — 2026-11-05

### Added
- **My tasks → To-do** (one-off tasks with an optional due date).
  - **Quick add**: type a title and press Enter. You can also pick the due date from the calendar and mark the task as important (★).
  - The list is grouped into **Overdue** (in red; stays until done), **Today**, **Tomorrow**, **Next 7 days**, **Later**, **No date** and **Done** (last 30 days, collapsed). Important tasks come first.
  - Each task has an optional time, a multi-line note, an in-app reminder on the due date and an optional **reminder email** on the due date (at the set time, or 09:00).
  - Overdue and today's To-do tasks also appear on the **Today** tab and in the sidebar count.
- **Month calendar** beside the To-do list (Persian or Gregorian, following the app setting). Days are marked with dots for open, overdue and checklist tasks.
  - Click a day to see that day's To-do tasks, checklist items and completed tasks, or to add a task for that day.
- Each user sees only their own tasks (all roles). Sharing between users and messages come in 1.49.

### Changed
- The reminder email subject is now "Reminder (My tasks)".

## [1.47.0] — 2026-11-05

### Added
- **My tasks: recurring checklist** (new page in the sidebar, with a count of what is left today).
  - Repeat a task **daily** (on the company's workdays), **weekly** on any days you pick, **monthly** on a day of the month or the last day (Persian or Gregorian calendar, following the app's calendar setting; a day the month doesn't have falls on the month's last day), or **one time** on a date.
  - **Today** lists what is due, with a progress bar. Tick a task when it's done, skip it, or add a short note to the tick.
  - A task that wasn't done shows at the top on the following days, marked **Missed**, until it is ticked or skipped (up to 60 days back). All missed occurrences of a task can be ticked or skipped at once.
  - **Coming up** shows the next occurrences. **Checklists** lists all tasks with their rule, next due date, the last 30 days (done of due) and the tick history.
  - Optional **reminder time**: an in-app notice if the task hasn't been ticked by then, and optionally a **reminder email** (to addresses set on the task, or to the recipients in Notifications settings). At most one email per occurrence.
  - **Workdays** (which days count as "daily") are chosen by an admin, because they differ between companies. The default is Saturday to Thursday.
  - Dates are picked from a calendar.
  - Each user sees and ticks only their own tasks (all roles, including read-only). Sharing between users and messages come in a later version.
  - Data is stored in the app database (encrypted columns in MySQL "cols" mode).

## [1.46.1] — 2026-11-05

### Changed
- **Extra check sources look and work the same.** FFraud, FireHOL Level 1, IPsum, AFTA IOC and the local list are now identical cards: on/off switch, short description, action button, status line (saved copy, IP and range counts, last error) and a collapsible **Settings** part.
  - Each online list's URL can now be changed (empty = default, https only), e.g. for an internal mirror. Changing the URL forces a fresh download before the list is used.
  - Download settings shared by all online sources (refresh interval, stale-copy limit, timeout, SSL check) are in one section below the cards.

### Fixed
- Web mode: the sidebar showed an unneeded scrollbar at 100% browser zoom on some screen heights. Compact spacing now starts earlier, so the sidebar fits from 700 to 1040 px height without scrolling.

## [1.46.0] — 2026-11-05

### Added
- **Tamper-evident audit log** (Settings → Audit log, main admin only).
  - Every History event (sign-in, sign-out and failed sign-in with the client IP, changes to users, access and settings, tool runs, blocks, terminal, file transfer, …) is also written to an audit log.
  - Records are chained with HMAC-SHA256 using a key derived from the app's data key. **Integrity check** reports any changed, deleted or reordered record, including records removed from the end (signed chain head).
  - There is no way inside the app to edit or delete audit records (only a full RESET).
  - Cost: about 160 bytes and under half a millisecond per event; checking 60,000 records takes about a second.
- **Audit log forwarding to Syslog/SIEM**: RFC 5424 Syslog (structured data) or **CEF**, over **UDP, TCP or TLS** (certificate check optional), with selectable categories (sign-in, users/access/settings, security tools, device access, monitoring). Each message carries its chain signature.
  - With TCP/TLS, records are queued while the destination is unreachable and sent when it is back.
  - Optionally send earlier records when turning it on. A test message button is included.
  - The destination can only be changed by the main admin and is not taken from imported settings files.

### Note
- The audit log starts when you upgrade; earlier History rows are not added to it.

## [1.45.1] — 2026-11-05

### Fixed
- Network tools → MAC vendor: the IEEE update now sends normal browser headers and retries once (the IEEE server sometimes drops other clients). If the main list still cannot be downloaded, the message explains what to do. Only the main list (MA-L) is required; MA-M and MA-S are added when they download.

### Added
- **Import IEEE file…**: for networks where the IEEE site does not open, download `oui.csv` (and optionally `mam.csv`, `oui36.csv`) in a browser from standards-oui.ieee.org and import them; they are merged into the current table.

## [1.45.0] — 2026-11-05

### Added
- Network map editor: **⇄ Discover connections (ARP/MAC)** — no LLDP/CDP needed.
  - Select one SNMP device on the map to check only that device, or select nothing to check all SNMP devices on the map.
  - Reads the same tables as the "IP/MAC location" tool (ARP, MAC table, port names) plus the device's own interface MACs. Read-only, only when you press the button; no periodic polling is added and all the work is done inside the app.
  - Optionally reads just the interface MACs of the other devices on the map (one small column) so it can tell which device is behind each port.
  - Finds links between monitored devices with the ports on both sides and a confidence level. A switch is not linked directly to a device that is reached through another monitored switch. When a port sees several known devices and the direct neighbour cannot be told, you can pick it yourself.
  - Devices behind access ports become new map objects, named by IP (from ARP) or MAC vendor. Several devices on one port are shown behind an "unmanaged switch". Ports with many MACs (uplinks, virtual servers) are skipped; the limit is adjustable.
  - Results are reviewed in a window before anything is added; new objects are placed in free space, and Undo removes them.
  - Each device's result is saved (encrypted) and reused in other maps without reading the device again, unless you choose "Read again". It is removed when the monitoring target is deleted.

## [1.44.1] — 2026-11-05

### Changed
- Extra check, AFTA IOC list: accepted even when it holds only a few IPs (one IP per line). The other lists still need at least 50 entries, so an error page is never taken as a list.

## [1.44.0] — 2026-11-05

### Added
- Extra check: two free **public downloadable lists** as extra sources, each with its own switch and "Download now" (Settings → Extra check):
  - **FireHOL Level 1** — DShield, Feodo Tracker (abuse.ch) and Spamhaus DROP combined; few false positives.
  - **IPsum** — IPs that appear on several public blocklists; an IP counts as malicious from a minimum number of lists (default 3).
  - **AFTA IOC** — the IOC IP list published by Iran's AFTA center (afta.gov.ir).
  
  The lists are plain text, read only as data: lines that are not a valid IP or CIDR are skipped, internal and reserved ranges are never counted as malicious, size is capped, and the saved copy is checked against a fingerprint. No IP from your network is sent out and there is no per-IP quota. A failed download falls back to the saved copy within the allowed age, otherwise the check stops instead of treating IPs as clean.

## [1.43.0] — 2026-11-05

### Added
- Addresses: **Remove from list** (admin only) for the selected IPs. They are checked again from scratch (AbuseIPDB and extra check) the next time they arrive from Splunk or another input. Past statistics and history are kept; an existing FortiGate block is not removed.
- Config backup: **several commands per device type** (one per line). All outputs are saved in one backup file, in order, each under a `##### command` heading. A single command is stored exactly as before, so comparisons with older versions are unaffected.
- A faint handle in the middle of the side menu's edge collapses or expands the menu (same as the button next to the logo).

### Changed
- Extra check results in a run now list only malicious IPs; the number checked and the number clean are shown above (the full report is still in the exported files).
- SNMPv3: the DES privacy option is now labelled "DES (DES-56, CBC)".

### Fixed
- Server health: "data growth per day" could show a huge value (for example 139 MB/day) because the difference between two samples 30 minutes apart was multiplied by 48, so a temporary file (backup zip, export, database save) looked like daily growth. It is now estimated from at least 6 hours (up to 24 hours) of samples, ignoring short spikes, and is shown only after 6 hours of running.

## [1.42.1] — 2026-11-02

### Fixed
- Desktop: clicking an export button again while its **Save as** window was still open opened a second file window, which could freeze or crash the app. Only one file open/save window can be open at a time now (a second request shows a message), and the configuration/settings export buttons are disabled while their window is open.

## [1.42.0] — 2026-11-02

### Added
- **Widget dashboards** (new **Dashboards** page in the side menu), similar to OpManager or Zabbix:
  - Each dashboard has **several pages**; each page is a 12-column grid of widgets you can **drag, resize, configure, duplicate and delete**. Add widgets by clicking them in the widget list or dragging them onto the page.
  - Widgets (monitoring only): device status counts, problems by severity, current problems, port traffic chart (up to 4 ports), value chart (CPU, memory, temperature, disk, response time), gauge with warning/critical thresholds, single value with trend, Top-N (CPU, memory, temperature, response time, port traffic, lowest availability), availability table, network map, clock, latest traps and syslog, and free text.
  - Each widget can be limited to a group or to selected targets, and chart widgets can use their own time range.
  - **Shared dashboards** are created and edited by an admin or a user with Monitoring "Run" access; **personal dashboards** can be made by any user and are visible only to their owner.
  - **Slideshow** of pages with a per-page time, **fullscreen** (F), and a sample layout for a quick start.
  - Widget data comes only from the normal monitoring checks; dashboards add no extra load on devices.
  - New access item and on/off switch: Monitoring → Dashboards.
  - Shared dashboards are included in the configuration package (targets and maps are matched to the new IDs on import).
- **Collapsible side menu**: the side menu can be collapsed to icons only for more room (names show as tooltips). The choice is remembered in this browser.
- Temporary live check: click a port in the port list to chart it live (up to 5 ports).

### Fixed
- Temporary live check: after **Stop**, or after the session ended, choosing an interval did not start it again; there is now also a **Start again** button. The first values now appear within a few seconds even with the 30-second interval, and the live tab works even before the first normal check of the target.
- Configuration package: importing several access groups on a fresh installation could fail with "only the main admin…" after the first group.

## [1.41.2] — 2026-11-02

### Changed
- Configuration package: **saved Splunk queries, FortiGate tasks** (for example block an IP or create an Address) **and Redmine ticket templates** are now their own import items, add-only like everything else. Existing queries, tasks and templates are kept, new ones are added and same-name ones are skipped. Applying the Splunk, FortiGate or Redmine settings section no longer replaces these lists.

## [1.41.1] — 2026-11-02

### Changed
- Configuration package import: the settings in the file can now be applied **per section**:
  - Splunk; AbuseIPDB; FortiGate (all devices and Python tasks); Redmine; email and notifications; DNS, scan and extra check
  - monitoring; Trap/Syslog; config backup, terminal, file transfer and offline updates
  - assets; automation; general and appearance; Active Directory
  
  Connections that are not yet set up on this installation are ticked by default. Sections that would overwrite an existing setup are marked. Trap/Syslog settings (previously skipped) and Active Directory settings (server mode) are now imported too.
- Settings exports and the configuration package no longer contain SNMP trap communities (treated as secrets, like tokens and passwords).

## [1.41.0] — 2026-11-02

### Added
- **Full configuration package** (Settings → General, main admin only): export and import the whole configuration in one JSON file, **without any passwords, secrets or tokens**.
  - **Included**: settings, credential profiles (name and username only), devices, scripts, monitoring targets (with dependencies, policies and display templates), monitoring policies, display templates, NOC dashboards, network maps (with background images and submaps), maintenance windows, API connections and their saved requests, access groups, automation jobs and SSH schedules.
  - **Not included**: users, uploaded icons and MIB files, and data (history, addresses, chart data, config backups).
  - **Import only adds**: nothing is deleted or overwritten.
    - An item whose name already exists is skipped, and references point to the existing item (for example, a device on an imported map links to the device you already have).
    - References between items are rebuilt with the new IDs.
    - Imported jobs and schedules arrive turned off for review.
    - Applying the file's settings is optional; passwords, users, access, accepted terms and active parts are never changed.
  - A preview shows new and same-name items per section. Afterwards a report lists what was added or skipped, any errors, and which devices, profiles and API connections still need a password or token.
  - Importing the same file twice adds nothing.

## [1.40.1] — 2026-11-02

### Changed
- The exe now carries Windows version information (Properties → Details): product name, version, description, author, copyright and the source link. Executables without it are more often flagged by antivirus heuristics. Generated from `autokrp/__init__.py` by `dev/version_info.py` in `build.bat` and the release workflow.

## [1.40.0] — 2026-11-01

### Added
- **API tool** (Device access → API), a simple request tool in the spirit of Bruno and Insomnia:
  - **Connections**: name, base URL and authentication (none, Basic, Bearer token, API key in a header or in the URL), TLS certificate check, timeout and default headers.
    - Passwords, tokens and keys are stored in the encrypted secret store and never sent back to the interface.
    - Admins create shared connections; operators create personal ones.
  - **Requests**: GET, POST, PUT, PATCH or DELETE with a path, parameters, headers and a body (JSON with "Format JSON", text or form).
    - Pasting a URL with `?a=1&b=2` splits it into parameters.
    - Enter or Ctrl+Enter sends. POST, PUT, PATCH and DELETE ask for confirmation first, unless switched off until the app closes.
    - Requests can be saved under their connection.
  - **Responses**: status, time and size; formatted, coloured JSON, the raw text and the response headers; copy, or save as a file.
    - Responses over 5 MB are truncated.
  - **Request log in the database**:
    - Records who, when, which connection, method, URL, status, duration, the request headers and body, and the first 4 KB of the response.
    - Passwords, tokens, keys and sensitive field values are masked.
    - Admins see everyone's requests; others see only their own. Each request is also recorded in History.
  - It appears in the parts tree ("API tool" under Device access): it can be turned off for everyone or limited per user and group (view = connections and log, run = send and edit).

### Fixed
- In server mode on short browser windows, the bottom of the side menu (language, version, user) was cut off. The menu is now more compact on short screens and scrolls when needed.

### Changed
- THIRD_PARTY_NOTICES lists `autokrp/trapdb.json` (trap names and descriptions extracted from vendor MIB files).
- The exe build explicitly includes the map, terms and API tool modules.

## [1.39.0] — 2026-11-01

### Added
- **Terms of use and disclaimer**:
  - Shown on the very first start, before the data folder and run mode (client or server) are chosen, and again inside the app before anything else.
  - The program cannot be used until the text is accepted. "I do not accept" closes the app (desktop) or signs out (server).
  - Acceptance is recorded with its time and text version. The desktop accepts once per installation; in server mode every user accepts once. Everyone is asked again only when the text changes.
  - The text can be read again under About.
- **Parts and tools as a tree** (Settings → General):
  - Each section (Security, Device access, Monitoring, Assets, Offline tools) has a switch, and its sub-items have tick boxes:
    - Device access: devices and commands, config backup, terminal, file transfer, TFTP server, serial console, network tools
    - Monitoring: Trap/Syslog, maps, automatic LLDP map, NOC, live check
    - Assets: asset scan
  - Turning something off **really stops it** for everyone, not only hides it:
    - Monitoring checks, SNMP workers and Trap/Syslog listeners stop.
    - Open terminal and file-transfer sessions are closed and the TFTP server is stopped.
    - Scheduled config backups and asset scans are skipped.
    - The matching API calls are refused.
  - Before saving, a confirmation lists what will be turned off. Presets: all on, monitoring only, device access only, security only.
- **Access per sub-item** (Settings → Users → Access):
  - Groups and per-user exceptions use the same tree with hidden / view / run.
  - A sub-item is "same as section" by default and can never have more access than its section.
  - Access only limits those users and never stops a service.
  - Existing groups and users keep exactly the access they had.

## [1.38.0] — 2026-11-01

### Added
- **Network maps** (Monitoring → Maps): hand-drawn maps of your network. They do not need LLDP or CDP, which are often turned off for security.
  - **Maps list**: one card per map with a preview, the number of devices that are up, down or warning, a group filter and "problems only".
  - **Live view**:
    - Devices are colored by state. A device that is down glows red. A device whose parent is down is purple. A device with an alert is orange.
    - Links connect port to port and are colored by load (green, yellow, orange, red). A port that goes down turns the link red with a ✕. A link to a device that is down is red and dashed. VPN and wireless links are drawn dashed.
    - Hover a device or link for details (ports, speed, in/out, how long it has been down). Click a device for its details, or a link for that port's chart.
  - **Labels** can be chosen per map and switched in the view:
    - device: name, name and IP, name and CPU/memory, or none
    - link: load %, in/out bps, port names, or none
  - **Problems only**: healthy parts are dimmed and a list of problems is shown. Click a problem to zoom to it.
  - **Submaps**: a map can contain another map, shown with the worst state inside it. Click it to open, with a path back.
  - **Editor**:
    - Drag (or click) monitored devices onto the map.
    - Draw a link by clicking two devices and choosing the port on each side from the device's port list, with up/down state, speed, ports already used, and the LLDP neighbour if a scan exists. Line types: cable, fiber, VPN, wireless, or no port (state from the two devices only).
    - Add areas (room, floor, building), text labels, clouds/ISPs, unmonitored devices and submaps.
    - Optional background image (PNG/JPG up to 2 MB, e.g. a floor plan), snap to grid, auto layout, undo/redo (Ctrl+Z / Ctrl+Y) and Delete. You are asked before leaving with unsaved changes.
    - "Suggest links from LLDP" is optional and only uses the last neighbour scan.
  - **Full screen / wall display**: full screen with a status summary and clock, rotating between maps every 30 s to 5 min.
  - Map state comes from normal monitoring data. **No extra SNMP requests** are sent to devices.
  - Anyone who can see Monitoring can view maps. Creating and editing needs "Run" access to Monitoring.
  - A device the viewer may not see is shown without its name or state, and other users cannot add it to their own maps.

### Changed
- The 1.26 neighbour map tab is now called "Automatic map (LLDP)" and comes after "Maps".

## [1.37.0] — 2026-11-01

### Fixed
- A chart tooltip could stay on screen after its window closed or the chart redrew. It now disappears when the chart redraws, the window closes, the page scrolls or the mouse leaves.
- The "close the app" question opened behind the NOC view. Windows opened over the NOC are now shown on top.
- History looked like it lost older entries. Only the latest 3,000 rows were loaded. History is now searched, filtered and paged on the server across all entries, with a time-range filter.
- The chart range controls were unclear. The buttons now have labels (Previous, Next, Wider range, Auto refresh). Auto refresh redraws immediately when switched on and shows the time of the last refresh. It explains that it only works for ranges ending "now".

### Added
- **Addresses**:
  - an exact **country filter** (a list of countries with counts, instead of a text search that also matched ISP/domain)
  - a **"days checked ≥ N"** filter, to select, for example, clean IPs of one country seen on many days and block them by hand
- **Temporary live check** (SNMP detail → "● Live"): CPU, memory and the traffic of every port every 5, 10 or 30 seconds, for troubleshooting.
  - Nothing is stored, and normal checks, counters, alerts and charts are untouched.
  - It stops when the window closes or after 15 minutes, and needs "Run" access to Monitoring.
- **Traffic of all ports** in one view (SNMP detail → Charts): a heatmap with one row per port over the chosen time range.
  - Colors show % of port capacity, or are relative to the busiest port when the speed is unknown.
  - Click a row to open that port's chart.
- **"Monitoring only"** preset (Settings → General): turns off every tool except Monitoring. When a user has no security tools, the menu hides the security pages and opens on Monitoring.
- An approximate data-size note next to the detailed-data resolution: 1-minute data is kept unmerged for the whole retention period, and retention 0 keeps it forever.

### Changed
- **Run files**: when a run ends, its log text is stored (compressed) in the database and the run folder, including its CSV files, is deleted. Existing run folders are converted the same way at startup. History "View" shows the log from the database. File export is only available while a run is in progress.

## [1.36.0] — 2026-10-31

### Added
- **Vendor display templates** for **Cisco** (Catalyst / Nexus / ISR), **Juniper** (EX / MX / SRX), **Extreme** (EXOS) and **FortiGate**. An SNMP device without a chosen template gets its vendor's template automatically once the vendor is detected (sysObjectID). A template picked by hand, or a server/PC/storage icon, still wins.
- **Summary blocks** for the SNMP detail page, ordered and switched on/off per template:
  - indicators, including a warning when the device restarted in the last 24 hours
  - hardware health tiles for temperature, fans, power supplies and sensors
  - CPU per stack member or module, and memory pools
  - Juniper component table (Routing Engines, FPC, PIC, fans, PSUs) with state, temperature and CPU, from the same `jnxOperatingTable` that was already read
  - busiest ports, with in/out bars
  - ports with errors or discards
  - alarms and device details
- New card fields: **hardware health** and **ports with errors**.
- FortiGate **active sessions** are now kept in history, with a 24-hour sessions chart.
- The demo mode includes Juniper, Extreme and FortiGate devices (by device type or name).

### Changed
- Card values are shown as separate chips, so mixed right-to-left and left-to-right text no longer wraps into one jumbled line. Latin device and component names keep Latin digits.
- No new SNMP OIDs are read; the new blocks only display data the app already collects.

## [1.35.0] — 2026-10-31

### Added
- **Table view** on the Monitoring page, next to cards (in the style of PRTG): one row per target, with these columns:
  - status, name, address, group, policy
  - response time, 24-hour availability, CPU, memory, temperature, disk, uptime
  - ports up, traffic of the display ports with a small chart, alerts, last check, interval, method

  The table can be sorted, filtered (problems / down / alerts / maintenance / paused), searched and filtered by group. It is paged at 25 to 200 per page.
- **Customize mode**: change columns and their order, page size, display templates of selected devices and the display ports of each SNMP device. Nothing is saved until **Apply**; **Cancel** discards everything.
- **Saved views** per user (layout, columns, filter, search, group, sort).
- **Device display templates**: what is shown, and in which order, on the card and on the SNMP detail page (sections and summary charts).
  - Five built-in templates: switch, router/link, firewall, server, generic. A device without a template gets one automatically from its icon.
  - Admins can copy and edit templates.
  - Templates only change the display; what is read is still set by the monitoring policy.
- **Display ports**: up to 4 ports per SNMP device whose traffic is shown in the table, the card and the NOC. By default these are the watched ports, otherwise the fastest ports that are up. A short in-memory history feeds the small charts.
- **NOC dashboards**: named dashboards (admins) with:
  - their own targets (all, groups or individual targets)
  - a tiles, table or mixed layout
  - large tiles for important devices
  - up to 12 uplink traffic charts
  - optional problems column and recent-events feed

  Each dashboard has a fixed address (`#noc/<id>`) that opens directly after sign-in. `#noc/rotate` cycles through dashboards that have a rotation time.
- **Trap/Syslog events in MySQL/MariaDB** (table `akrp_ev`, daily partitions), using the same "monitoring data location" setting as chart data.
  - Type, target and source are filtered in the database; message text follows the database mode (the source address is hidden too in "fully encrypted" mode).
  - Existing event files are moved in the background, and searches read both files and MySQL.

### Changed
- The Monitoring page now refreshes with `mon_rows` every 5 s: only changed targets are sent (about 24 KB instead of about 0.5 MB with 500 targets). The full list is reloaded only when targets, policies or templates change.
- New targets get their first check within 10 s (was up to 30 s).
- The 24-hour availability bar on cards is cached per minute (cheaper with many targets).
- MySQL reset also removes `akrp_ev`.

## [1.34.0] — 2026-10-31

### Added
- **SNMP worker processes (multi-core)**: SNMP polling now runs in separate worker processes (the same AutoKRP executable started with `--snmpworker`), so it uses several CPU cores. Default is automatic (CPU cores minus one, up to 8); it can be set from 0 (inside the app, as before) to 16 in Settings → Monitoring. Workers only run while there is an active SNMP target.
  - Workers talk to the app over 127.0.0.1 with a one-time token (the same method as FortiGate Python tasks). Credentials never leave the machine.
  - On Windows, workers are placed in a Job Object, so they close when the app closes or crashes. They have no window. A crashed or hung worker is restarted, and its in-flight polls are re-run inside the app, so devices are not falsely reported down. Workers are recycled after 50,000 polls or 600 MB of RAM.
  - Measured on a 2-core Linux test machine with net-snmp agents (54 interfaces each):
    - 500 devices every 60 s: kept up, about 0.8 core.
    - 1,000 devices every 60 s: kept up, using both cores.
    - SNMPv3 (SHA/AES) costs about the same as v2c.
    - Unresponsive devices do not delay healthy ones.
- **Monitoring policies**: named profiles that set the check interval, failures before "down", SNMP retries, what to read (CPU, memory, disk, hardware, ports), which port counters to read (traffic, errors, discards), whose port history to store (all enabled / only up / only watched / none), whether to store history for system values, ports and custom OIDs, detailed-data resolution (**1 or 5 minutes**) and retention for detailed and hourly data.
  - Each target uses a policy or stays "Custom" (its own settings, as before).
  - Three presets are included: Critical (1 min, 1-minute data), Standard (5 min) and Light (10 min, status and CPU only).
  - Settings → Monitoring shows disk usage per policy.
- **Chart data in MySQL/MariaDB** (optional, when the app database is MySQL): monitoring time series go to the tables `akrp_ts_d` and `akrp_ts_h` over a separate connection.
  - The tables are partitioned by day/month when the server allows it, and old data is removed with `DROP PARTITION`; otherwise batched `DELETE` is used.
  - The format follows the database mode: readable JSON in "plain", compressed and encrypted otherwise.
  - Existing local files are moved to MySQL in the background. If MySQL is unreachable, data is written to local files and moved later. Charts always read both.
- Monitoring page warns admins when targets fall behind schedule or workers keep failing.

### Changed
- The monitoring target limit is now 2,000 (was 200).
- Checks are spread evenly over each target's interval instead of starting together.
- Static SNMP data (port names, descriptions, aliases, speeds, entity names) is cached for about 20 minutes and refreshed on reboot or when ports change. This cuts the work per poll by about a quarter.
- A device that does not answer the first request is reported after one timeout, without a second "is it alive" query.
- Ping on Windows uses the system ICMP API (`IcmpSendEcho`) instead of starting `ping.exe` for every check (IPv6 still uses `ping.exe`).
- MySQL reset also removes the monitoring time-series tables.

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
