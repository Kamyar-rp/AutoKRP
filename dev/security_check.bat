@echo off
rem Security check: Bandit (static analysis) + pip-audit (dependency vulnerabilities)
cd /d "%~dp0\.."
python -m pip install --quiet bandit pip-audit
echo === Bandit (Medium/High) ===
python -m bandit -r app.py autokrp -ll
echo === pip-audit ===
python -m pip_audit -r requirements.txt
pause
