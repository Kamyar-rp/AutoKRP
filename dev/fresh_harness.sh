# harness تازه: harness قبلی را می‌بندد، dev/_data را پاک و دوباره روی 8765 اجرا می‌کند
cd "$(dirname "$0")/.."
python3 - <<'PY'
import os, signal, time
for pid in os.listdir('/proc'):
    if not pid.isdigit(): continue
    try: cmd=open(f'/proc/{pid}/cmdline','rb').read().split(b'\0')
    except Exception: continue
    if len(cmd)>1 and cmd[0].endswith(b'python3') and cmd[1].endswith(b'dev/harness.py'):
        os.kill(int(pid), signal.SIGTERM)
time.sleep(1)
PY
rm -rf dev/_data
nohup setsid python3 dev/harness.py 8765 > /tmp/harness.log 2>&1 < /dev/null &
sleep 3
