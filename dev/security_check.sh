#!/bin/sh
# بررسی امنیتی کد: Bandit (تحلیل ایستا) و pip-audit (آسیب‌پذیری وابستگی‌ها)
cd "$(dirname "$0")/.."
python3 -m pip install --quiet bandit pip-audit
echo "=== Bandit (Medium/High) ==="
python3 -m bandit -r app.py autokrp -ll
echo "=== pip-audit ==="
python3 -m pip_audit -r requirements.txt
