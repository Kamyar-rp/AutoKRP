#!/usr/bin/env python3
"""سرور وب (حالت سرور، Demo) برای تست: python dev/server_harness.py [port]   ← https://localhost:PORT"""
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("LOCALAPPDATA", str(ROOT / "dev" / "_sdata"))

from autokrp import atrest, paths, server, serverauth  # noqa: E402

paths.set_demo(True)
paths.set_mode("server")
atrest.set_server_mode(True)
if len(sys.argv) > 1 and not serverauth.exists():
    serverauth.DEFAULT_CONFIG["port"] = int(sys.argv[1])
server.run(demo=True, on_ready=lambda u, p: print(u, flush=True))
