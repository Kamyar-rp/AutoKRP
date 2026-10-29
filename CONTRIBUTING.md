# Contributing to AutoKRP

Thanks for taking the time to help! Bug reports, ideas, translations and pull requests are all welcome.

## Reporting bugs and ideas
- Use the [issue templates](https://github.com/kamyar-rp/AutoKRP/issues/new/choose).
- Include the version (**About** page), the mode (client/server), what you did, what you expected and what happened.
- Remove tokens, passwords, internal IPs and hostnames from logs and screenshots.
- Performance problems: start the app with `--memdiag` and attach `logs\memdiag.txt` from the data folder (it only contains numbers).
- **Security issues must not be reported publicly** — see [SECURITY.md](SECURITY.md).

## Development setup
```bat
git clone https://github.com/kamyar-rp/AutoKRP.git
cd AutoKRP
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
run_demo.bat
```
The demo uses fake Splunk/AbuseIPDB/FortiGate/Redmine connectors, so you can work on almost everything without real servers. `dev/` contains local fake servers (SSH, FortiGate SSH, SMTP, …) and a browser harness (`dev/harness.py`) to run the UI in a normal browser.

## Project layout
| Path | Contents |
|---|---|
| `app.py` | Entry point, first-run window, tray, server status window |
| `autokrp/` | Backend: API (`api.py`), pipeline, connectors, vault and encryption, server, SSH, monitoring, … |
| `ui/` | Front end (plain HTML/CSS/JS, no build step); `i18n_en.js` is generated |
| `dev/` | Fake servers, i18n tools, data builders, security check scripts |
| `docs/` | Screenshots and design documents |

## Translations
The UI source strings are Persian; English comes from `ui/i18n_en.js`, which is generated:
1. Add the new English strings to a file in `dev/tr/` (e.g. `dev/tr/extra_<version>.json`, `{"persian text": "English text"}`; `{0}` placeholders are supported).
2. Run `python dev/i18n_extract.py && python dev/i18n_build.py` and check that the "untranslated" list did not grow.

New UI text should be written so that every visible text node is a complete sentence or label (variables in their own `<span>`), otherwise it cannot be translated.

## Pull requests
- One topic per pull request; describe what changed and how you tested it.
- Keep the security rules intact: no secret in plain text on disk or in the UI, every new API method is explicitly listed in `autokrp/perms.py` (default: admin only), nothing changes a device without approval.
- Run before submitting:
  ```bat
  python -m compileall -q app.py autokrp
  python -m bandit -r app.py autokrp -ll
  ```
- Code comments are mostly in Persian; English comments are welcome.

By contributing you agree that your contribution is licensed under the [MIT License](LICENSE).
