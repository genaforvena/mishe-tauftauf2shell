#!/usr/bin/env python3
"""Loopback synthetic watchdog peer, NodeCount=3, delayed trigger send."""
import socket, struct, sys, time

PORT = 19005
DELAY = float(sys.argv[1]) if len(sys.argv) > 1 else 3.0
JSON = ('{"Function":"START_RECOVERY","Flags":0,"NodeCount":3,'
        '"NodeIdList":[1094795585,1111638594,11259375]}')

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", PORT))
s.listen(1)
print(f"peer listening {PORT}, delay={DELAY}, N=3", flush=True)
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
print(f"peer sleeping {DELAY}s before trigger", flush=True)
time.sleep(DELAY)
pkt = b'r' + struct.pack("!II", 1, len(JSON)) + JSON.encode()
conn.sendall(pkt)
print(f"peer sent trigger type=r len={len(JSON)} payload={JSON}", flush=True)
time.sleep(2)
conn.close(); s.close()
