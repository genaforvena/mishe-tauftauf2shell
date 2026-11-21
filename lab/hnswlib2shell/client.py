#!/usr/bin/env python3
"""Send one local file to the loopback-only index-loading service."""
import socket
import sys
import time


def main():
    port, path = int(sys.argv[1]), sys.argv[2]
    data = open(path, "rb").read()
    last = None
    for _ in range(50):
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=1)
            break
        except OSError as exc:
            last = exc
            time.sleep(0.1)
    else:
        raise SystemExit("client_connect_failed: %r" % (last,))
    s.sendall(data)
    s.shutdown(socket.SHUT_WR)
    s.close()
    print("client_sent bytes=%d" % len(data))


if __name__ == "__main__":
    main()
