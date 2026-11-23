#!/usr/bin/env python3
"""Send a captured THeader/ZLIB wire frame to a loopback port. No Thrift lib."""
import socket
import sys
from pathlib import Path

if len(sys.argv) != 2:
    raise SystemExit("usage: raw-client.py PORT")

port = int(sys.argv[1])
frame = Path(__file__).with_name("wire.bin").read_bytes()
assert int.from_bytes(frame[:4], "big") == len(frame) - 4
with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
    sock.sendall(frame)
print(f"RAW_SENT bytes={len(frame)} frame_len={int.from_bytes(frame[:4], 'big')}")
