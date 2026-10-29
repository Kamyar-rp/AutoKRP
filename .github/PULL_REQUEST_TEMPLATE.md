## What does this change?

## How was it tested?
- [ ] `run_demo.bat` / demo mode
- [ ] Against real devices (which?):

## Checklist
- [ ] No secrets, internal IPs or hostnames in code, tests or screenshots
- [ ] New API methods are listed in `autokrp/perms.py`
- [ ] New UI text has English translations (`dev/tr/`, then `dev/i18n_extract.py` and `dev/i18n_build.py`)
- [ ] `python -m bandit -r app.py autokrp -ll` reports no Medium/High issues
