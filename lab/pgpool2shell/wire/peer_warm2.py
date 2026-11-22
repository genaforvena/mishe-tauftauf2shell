#!/usr/bin/env python3
"""Loopback synthetic watchdog peer: one safe NodeCount=1 warm-up packet,
then one NodeCount=2 trigger packet on the same connection. Used to test
whether the -O2 adjacent slot tracks peer-controlled fields."""
import socket, struct, sys, time

PORT = 19005
WARM = sys.argv[1] if len(sys.argv) > 1 else (
    '{"Function":"START_RECOVERY","Flags":0,"NodeCount":1,"NodeIdList":[1094795585,0]}')
TRIGGER = sys.argv[2] if len(sys.argv) > 2 else (
    '{"Function":"START_RECOVERY","Flags":0,"NodeCount":2,"NodeIdList":[1094795585,1111638594]}')

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", PORT))
s.listen(1)
print(f"peer listening 127.0.0.1:{PORT}", flush=True)
conn, addr = s.accept()
print(f"peer accepted {addr}", flush=True)
conn.settimeout(1.0)
try:
    while True:
        d = conn.recv(4096)
        if not d:
            break
        print(f"peer recv {len(d)} bytes type={d[:1]!r}", flush=True)
except socket.timeout:
    pass

for label, payload in (("warm", WARM), ("trigger", TRIGGER)):
    pkt = b'r' + struct.pack("!II", 1, len(payload)) + payload.encode()
    print(f"peer sending {label} type=r len={len(payload)} payload={payload}", flush=True)
    conn.sendall(pkt)
    time.sleep(1.0)

conn.settimeout(2.0)
try:
    while True:
        d = conn.recv(4096)
        if not d:
            break
        print(f"peer recv after packets {len(d)} bytes type={d[:1]!r}", flush=True)
except socket.timeout:
    pass
conn.close(); s.close()
