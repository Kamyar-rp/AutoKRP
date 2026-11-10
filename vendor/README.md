# vendor — build tools (not in the repository)

`build.bat` uses these files when they are present. They are **not** committed (see `.gitignore`); download them
yourself from the official sites and check their signatures/hashes before use.

| File | Used for | Where it goes |
|---|---|---|
| `python-3.14.x-amd64.exe` (Windows installer, python.org) | the build Python, when no Python 3.14 is found (`py -3.14`) | `.pybuild\` in this folder; current user only, no PATH change, no file associations |
| `innosetup-*.exe` (Inno Setup 6.3 or newer, jrsoftware.org) | compiling the installer (`installer\AutoKRP.iss`), when Inno Setup is not installed | `.innosetup\` in this folder, current user only |

Not needed by `build.bat` (you may keep them here): `python-3.14.x-embed-amd64.zip`, `WinSW-x64.exe`.

## Outputs

- `build.bat` → `dist\AutoKRP.exe` (portable) **and** `dist\AutoKRP-Setup-X.Y.Z.exe` (installer), each with a `.sha256.txt`.
- `build.bat portable` → only the portable exe. GitHub releases contain only the portable exe; build the installer
  from source when you want it.

## Installer behaviour

- Installs to `C:\Program Files\AutoKRP` (Administrator), Start menu shortcut, optional desktop shortcut.
- **Data is not moved or copied.** The installed app uses the same data folder as the portable exe
  (`%LOCALAPPDATA%\AutoKRP` or the folder chosen at first start) — open it with the same Windows user and you continue
  with the same data, mode and password.
- A running AutoKRP (also the portable exe in the tray) is closed before installing; the app starts as the user who
  ran the setup, not as Administrator.
- If server auto-start was set up from the portable exe, the server window shows
  "Auto-start still runs the previous copy" → **Update to this copy**.
- Uninstalling never deletes data (use RESET in the app for that).
