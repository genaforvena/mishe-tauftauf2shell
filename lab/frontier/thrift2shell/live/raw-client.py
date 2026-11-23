#!/usr/bin/env python3
"""Send a crafted THeader/ZLIB wire frame to a loopback port. No Thrift lib."""
import socket
import sys
import time
from pathlib import Path

if len(sys.argv) not in (2, 3, 4):
    raise SystemExit("usage: raw-client.py PORT [FRAME_FILE] [HOLD_SECONDS]")

port = int(sys.argv[1])
frame_path = Path(sys.argv[2]) if len(sys.argv) >= 3 else Path(__file__).with_name("wire.bin")
hold = float(sys.argv[3]) if len(sys.argv) == 4 else 0.0
frame = frame_path.read_bytes()
assert int.from_bytes(frame[:4], "big") == len(frame) - 4
with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
    sock.sendall(frame)
    if hold:
        sock.settimeout(hold)
        try:
            reply = sock.recv(4096)
        except socket.timeout:
            reply = b""
        print(f"RAW_REPLY bytes={len(reply)}")
        time.sleep(hold)
print(f"RAW_SENT bytes={len(frame)} frame_len={int.from_bytes(frame[:4], 'big')}")
