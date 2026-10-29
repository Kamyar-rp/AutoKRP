# Security Policy

## Supported versions

Only the latest release receives security fixes. Please update before reporting.

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

- Preferred: GitHub's private reporting — **Security → Report a vulnerability** on this repository.
- Or e-mail: kamyar.rp@gmail.com (subject starting with `[AutoKRP security]`).

Please include the version, mode (client/server), steps to reproduce and the impact. You can expect an acknowledgement within a few days; a fix and a new release follow as soon as practical, and reporters are credited unless they prefer otherwise.

## Security design (summary)

A full description in Persian is in [docs/security-design.fa.md](docs/security-design.fa.md).

### Secrets and data at rest
- API tokens and passwords are never stored in settings or the database; they live in an encrypted vault file (AES-256-GCM, random nonce, versioned AAD, padded to fixed size classes so the file size does not reveal the number of secrets).
- Settings, run files, SSH outputs, config backups and logs are encrypted as well; the local database is an **SQLCipher 4** file (every page encrypted and authenticated).
- Files are written atomically (unique temp file, fsync, replace). Exported CSV files are protected against formula injection.

### Key protection
- **Client mode:** a random key protected by Windows **DPAPI** (bound to the Windows user), or derived from a **master password** with scrypt and never stored. An optional **recovery code** (160-bit, shown once) can reset the master password without losing data.
- **Server mode:** a random master key is wrapped separately for every user with a key derived from that user's password; without a valid sign-in nothing can be decrypted. DPAPI is not used. The first admin account and a full reset are only possible from the server itself (localhost).
- Two lock levels: UI lock (key stays in memory for scheduled jobs) and full lock (keys removed from memory, jobs stop). Failed unlock attempts back off exponentially and are logged.

### Web (server mode)
- HTTPS only (TLS ≥ 1.2) with a self-signed or organisation certificate.
- `HttpOnly; Secure; SameSite=Strict` session cookie, CSRF tokens, Origin and Content-Type checks, strict CSP without inline scripts, HSTS, `X-Frame-Options: DENY`.
- Lockout after failed sign-ins (per IP+user, per IP and per account), idle session timeout, an allowed-networks list (private ranges by default), connection and body-size limits.
- Roles: admin / operator / read-only; operators only get the tools the admin grants. Non-admins never see server addresses, credentials, recipients, queries or scripts.

### Outbound connections
- TLS certificates are verified against the Windows store by default. If verification is turned off (e.g. a self-signed FortiGate), certificate **pinning** can be enabled: an unknown certificate is trusted only after the user compares and confirms its SHA-256 fingerprint.
- Stored secrets are never sent to a changed address/host/port; they must be entered again.
- No credentials are forwarded on cross-host redirects.
- SSH host keys are verified (known_hosts, encrypted); a changed key is always rejected.

### Protection against wrong blocks or changes
- Nothing is blocked, ticketed, sent over SSH or pushed to a FortiGate without approval, unless the admin explicitly enables "without approval" for a scheduled job — and even then a per-run cap applies.
- Only IPs that AbuseIPDB reports as malicious are blocked by the default FortiGate task; excluded ranges (private ranges and the app's own servers by default) are never blocked.
- Every block, ticket and change is recorded in the history together with whether it was approved manually or automatically.

### FortiGate Python tasks
- Task code runs in a **separate process** with a time limit and a minimal environment; it never receives the device token. It can read from the device only through the app and can only *propose* REST actions under `/api/v2/` of the selected device; the app sends the approved ones.
- Python code cannot be fully sandboxed: anyone who can edit a task can run code as the user that runs AutoKRP. Therefore **only admins** can create or edit tasks, every change is recorded in the history with a diff and a SHA-256, and the hash is shown in the approval window.

### Reset
- A full reset (type `RESET`) is only possible from inside the app by an admin with their own password — never from the lock or sign-in screen. Secret files are overwritten before deletion.

### Known limitations
- While the app is unlocked, keys are in memory; malware running as the same Windows user can read them or use that user's DPAPI. Encryption protects against **copied files**, not against malicious code on the same account.
- Python cannot guarantee that every copy of a key is wiped from RAM after a full lock.
- If both the master password and the recovery code are lost, the data cannot be recovered.
- The released exe is not code-signed yet; verify its SHA-256 against the value published with the release.

### Automated checks
- `.github/workflows/security.yml`: syntax, Bandit (Medium/High) and pip-audit on every push and weekly.
- `build.bat` builds in an isolated venv, runs pip-audit and writes the exact dependency versions and the exe's SHA-256 next to it.
